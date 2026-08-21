from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import subprocess
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Sequence

from keeper.authority_service.codex_registration import (
    persist_public_response,
    verify_reviewed_executable,
)
from keeper.providers.codex_contract import (
    account_identity_probe_exchange,
    parse_codex_account_identity_probe,
    sanitized_codex_environment,
)


_MAX_STREAM_BYTES = 65_536


def discover_codex_account_identity(
    executable: Path,
    *,
    expected_sha256: str,
    expected_size: int,
    expected_version: str,
    predecessor_registration_id: str,
    predecessor_failure_digest: str,
    workspace: Path,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Read one sanitized ChatGPT account identity without running a model."""

    identity = verify_reviewed_executable(
        executable,
        expected_sha256=expected_sha256,
        expected_size=expected_size,
        expected_version=expected_version,
    )
    if (
        not predecessor_registration_id.startswith("keeper-provider:codex:v1:")
        or len(predecessor_registration_id)
        != len("keeper-provider:codex:v1:") + 32
        or len(predecessor_failure_digest) != 64
        or any(
            character not in "0123456789abcdef"
            for character in predecessor_failure_digest
        )
    ):
        raise PermissionError("Codex account discovery predecessor is invalid")
    canonical_workspace = workspace.resolve(strict=True)
    if not canonical_workspace.is_dir() or any(canonical_workspace.iterdir()):
        raise PermissionError("Codex account discovery workspace is not empty")
    profile = Path(os.environ.get("USERPROFILE", ""))
    if not profile.is_absolute():
        raise PermissionError("Codex account discovery profile is unavailable")
    environment = sanitized_codex_environment(
        dict(os.environ), codex_home=profile / ".codex"
    )
    response_lines, stream_evidence = _exchange_account_identity(
        Path(str(identity["path"])),
        canonical_workspace,
        environment,
        timeout_seconds=timeout_seconds,
    )
    account = parse_codex_account_identity_probe(response_lines)
    return {
        "schema_version": 1,
        "operation": "CODEX_ACCOUNT_IDENTITY_DISCOVERY",
        "observed_at": datetime.now(UTC).isoformat(),
        "predecessor_registration_id": predecessor_registration_id,
        "predecessor_failure_digest": predecessor_failure_digest,
        "verified_executable": identity,
        "account_binding": account,
        "stream_evidence": stream_evidence,
        "effect_accounting": {
            "account_request_count": 1,
            "model_request_count": 0,
            "provider_execution_count": 0,
            "qualification_count": 0,
            "registration_success_count": 0,
            "usage_observation_count": 0,
            "usage_reservation_count": 0,
        },
        "raw_account_identity_persisted": False,
    }


def _exchange_account_identity(
    executable: Path,
    workspace: Path,
    environment: dict[str, str],
    *,
    timeout_seconds: float,
) -> tuple[list[str], dict[str, Any]]:
    if not 1.0 <= timeout_seconds <= 60.0:
        raise ValueError("Codex account discovery timeout is invalid")
    process = subprocess.Popen(  # noqa: S603 - exact reviewed executable
        [str(executable), "app-server", "--listen", "stdio://"],
        cwd=str(workspace),
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _stop_process(process)
        raise RuntimeError("Codex account discovery pipes are unavailable")
    events: queue.Queue[tuple[str, bytes | BaseException | None]] = queue.Queue()
    stdout_worker = threading.Thread(
        target=_read_bounded_stream,
        args=("stdout", process.stdout, events),
        daemon=True,
    )
    stderr_worker = threading.Thread(
        target=_read_bounded_stream,
        args=("stderr", process.stderr, events),
        daemon=True,
    )
    stdout_worker.start()
    stderr_worker.start()
    deadline = time.monotonic() + timeout_seconds
    stdout_lines: list[str] = []
    stderr_digest = hashlib.sha256()
    stderr_bytes = 0
    stdout_digest = hashlib.sha256()
    stdout_bytes = 0
    try:
        for serialized, expected_id in account_identity_probe_exchange():
            process.stdin.write(serialized.encode("utf-8") + b"\n")
            process.stdin.flush()
            if expected_id is None:
                continue
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Codex account discovery timed out")
                try:
                    source, value = events.get(timeout=remaining)
                except queue.Empty as error:
                    raise TimeoutError("Codex account discovery timed out") from error
                if isinstance(value, BaseException):
                    raise RuntimeError(
                        f"Codex account discovery {source} reader failed"
                    ) from value
                if value is None:
                    raise PermissionError(
                        "Codex account discovery ended before its response"
                    )
                if source == "stderr":
                    stderr_bytes += len(value)
                    stderr_digest.update(value)
                    continue
                stdout_bytes += len(value)
                stdout_digest.update(value)
                line = value.decode("utf-8", errors="strict")
                stdout_lines.append(line)
                try:
                    response = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(response, dict) and response.get("id") == expected_id:
                    break
    finally:
        try:
            process.stdin.close()
        finally:
            _stop_process(process)
            stdout_worker.join(timeout=5)
            stderr_worker.join(timeout=5)
            if stdout_worker.is_alive() or stderr_worker.is_alive():
                raise RuntimeError("Codex account discovery cleanup is uncertain")
    while True:
        try:
            source, value = events.get_nowait()
        except queue.Empty:
            break
        if isinstance(value, BaseException):
            raise RuntimeError(
                f"Codex account discovery {source} reader failed"
            ) from value
        if value is None:
            continue
        if source == "stderr":
            stderr_bytes += len(value)
            stderr_digest.update(value)
        else:
            stdout_bytes += len(value)
            stdout_digest.update(value)
            stdout_lines.append(value.decode("utf-8", errors="strict"))
    return stdout_lines, {
        "stdout_bytes": stdout_bytes,
        "stdout_sha256": stdout_digest.hexdigest(),
        "stderr_bytes": stderr_bytes,
        "stderr_sha256": stderr_digest.hexdigest(),
    }


def _read_bounded_stream(
    name: str,
    stream: BinaryIO,
    events: queue.Queue[tuple[str, bytes | BaseException | None]],
) -> None:
    total = 0
    try:
        while True:
            value = stream.readline(_MAX_STREAM_BYTES + 1)
            if not value:
                events.put((name, None))
                return
            total += len(value)
            if total > _MAX_STREAM_BYTES or len(value) > _MAX_STREAM_BYTES:
                raise PermissionError(
                    f"Codex account discovery {name} exceeded its limit"
                )
            events.put((name, value))
    except BaseException as error:  # noqa: BLE001 - preserve reader failure
        events.put((name, error))


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keeper-authority codex-discover-account-identity"
    )
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-size", type=int, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--predecessor-registration-id", required=True)
    parser.add_argument("--predecessor-failure-digest", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    options = parser.parse_args(arguments)
    identity = verify_reviewed_executable(
        options.executable,
        expected_sha256=options.expected_sha256,
        expected_size=options.expected_size,
        expected_version=options.expected_version,
    )
    if not options.apply:
        print(
            json.dumps(
                {
                    "apply_required": True,
                    "operation": "CODEX_ACCOUNT_IDENTITY_DISCOVERY",
                    "verified_executable": identity,
                    "model_request_count": 0,
                },
                sort_keys=True,
            )
        )
        return 0
    result = discover_codex_account_identity(
        options.executable,
        expected_sha256=options.expected_sha256,
        expected_size=options.expected_size,
        expected_version=options.expected_version,
        predecessor_registration_id=options.predecessor_registration_id,
        predecessor_failure_digest=options.predecessor_failure_digest,
        workspace=options.workspace,
    )
    persist_public_response(options.output, result)
    print(json.dumps(result, sort_keys=True))
    return 0
