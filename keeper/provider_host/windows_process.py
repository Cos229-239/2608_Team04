from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import threading
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from keeper.authority_service.restricted_process import (
    RestrictedProcessCleanupUncertain,
    RestrictedProcessResult,
    current_process_token,
    profile_restricted_primary_token,
    run_restricted_process,
)
from keeper.authority_service.windows_signature import authenticode_identity
from keeper.providers.codex_contract import (
    CODEX_REQUIRED_SUBSCRIPTION_PLAN,
    app_server_probe_exchange,
    build_codex_exec_command,
    parse_codex_app_server_probe,
)
from keeper.providers.claude_contract import (
    CLAUDE_AUTHENTICATION_MODE,
    CLAUDE_PINNED_REVIEW_MODEL,
    CLAUDE_QUALIFICATION_NONCE,
    CLAUDE_QUALIFICATION_PROMPT,
    build_claude_exec_command,
    build_claude_qualification_command,
    claude_qualification_schema,
    parse_claude_auth_status,
)


_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_INVALID_HANDLE = ctypes.c_void_p(-1).value


class ProviderProcessLauncher:
    """Launch a measured provider under the user host's restricted token."""

    def __init__(self, output_root: Path) -> None:
        self.output_root = output_root.resolve()

    def launch(
        self,
        envelope: Mapping[str, Any],
        environment: Mapping[str, str],
        cancel_requested: threading.Event,
        *,
        on_started: Callable[[dict[str, object]], None],
        on_resumed: Callable[[dict[str, object]], None],
    ) -> dict[str, Any]:
        executable = Path(str(envelope["executable"]["path"]))
        workspace = Path(str(envelope["workspace"]["canonical_path"])).resolve(
            strict=True
        )
        limits = envelope["resource_limits"]
        launch_id = str(envelope["launch_id"])
        self.output_root.mkdir(parents=True, exist_ok=True)
        stdout_path = self.output_root / f"{launch_id}.stdout"
        stderr_path = self.output_root / f"{launch_id}.stderr"
        with locked_tls_root_bundle(
            environment, envelope["environment"]["tls_root_bundle"]
        ), locked_executable(executable, envelope["executable"]) as measurement:
            with current_process_token() as current_token:
                with profile_restricted_primary_token(current_token) as restricted:
                    result = run_restricted_process(
                        restricted,
                        [str(executable), *list(envelope["argv"])],
                        executable,
                        workspace,
                        dict(environment),
                        stdout_path,
                        stderr_path,
                        float(limits["timeout_seconds"]),
                        on_started,
                        cancel_requested,
                        on_resumed=on_resumed,
                        integrity_level="medium",
                        validated_executable_identity=measurement,
                        executable_provider_id=str(envelope["provider_id"]),
                        active_process_limit=int(limits["active_process_limit"]),
                        memory_bytes=int(limits["memory_bytes"]),
                        stdout_bytes=int(limits["stdout_bytes"]),
                        stderr_bytes=int(limits["stderr_bytes"]),
                    )
        public = _public_result(result, stdout_path, stderr_path)
        if envelope.get("provider_id") == "claude" and result.exit_code == 0:
            try:
                response = json.loads(stdout_path.read_text(encoding="utf-8"))
                structured = (
                    response.get("structured_output")
                    if isinstance(response, dict)
                    else None
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise PermissionError(
                    "Claude provider result envelope is invalid"
                ) from error
            if not isinstance(structured, dict):
                raise PermissionError(
                    "Claude provider result contains no structured output"
                )
            public["structured_output"] = structured
        return public


class CodexSetupRunner:
    """Host-side, Authority-bound subscription-provider setup executor."""

    def __init__(self, output_root: Path) -> None:
        self.output_root = output_root.resolve()

    def run_setup(
        self,
        envelope: Mapping[str, Any],
        environment: Mapping[str, str],
        cancel_requested: threading.Event,
        *,
        on_started: Callable[[dict[str, object]], None],
        on_resumed: Callable[[dict[str, object]], None],
    ) -> dict[str, Any]:
        executable = Path(str(envelope["executable"]["path"]))
        workspace = Path(str(envelope["workspace"]["canonical_path"])).resolve(
            strict=True
        )
        limits = envelope["resource_limits"]
        setup_id = str(envelope["setup_id"])
        expected_setup_root = self.output_root / hashlib.sha256(
            setup_id.encode("utf-8")
        ).hexdigest()
        if (
            workspace != expected_setup_root
            or not workspace.is_dir()
            or any(workspace.iterdir())
        ):
            raise PermissionError(
                "Provider Host setup output workspace differs"
            )
        setup_root = workspace
        model_id = str(envelope["model_id"])
        provider_id = str(envelope.get("provider_id", "codex"))
        account_binding = dict(envelope["account_binding"])
        version_stdout = setup_root / "version.stdout"
        version_stderr = setup_root / "version.stderr"
        probe_stdout = setup_root / "probe.stdout"
        probe_stderr = setup_root / "probe.stderr"
        failure_reason: str | None = None
        failure_stage = "SETUP_INITIALIZATION"
        failure_code: str | None = None
        version_text = ""
        authentication_probe: dict[str, Any] | None = None
        structured_output: dict[str, Any] | None = None
        usage_observation: dict[str, Any] | None = None
        production_command: tuple[str, ...] = ()
        process_result: dict[str, Any] | None = None
        prompt_digest: str | None = None
        schema_digest: str | None = None
        ownership: dict[str, Any] = {
            "job_confined": False,
            "restricted": False,
            "integrity_level": "unknown",
            "launch_nonce": str(envelope["challenge"]),
        }
        exit_status = 70
        try:
            failure_stage = "EXECUTABLE_LOCK"
            with locked_tls_root_bundle(
                environment, envelope["environment"]["tls_root_bundle"]
            ), locked_executable(executable, envelope["executable"]) as measurement:
                failure_stage = "SOURCE_TOKEN_OPEN"
                with current_process_token() as current_token:
                    failure_stage = "RESTRICTED_TOKEN_CREATE"
                    with profile_restricted_primary_token(current_token) as restricted:
                        failure_stage = "VERSION_LAUNCH"

                        def version_started(observation: dict[str, object]) -> None:
                            nonlocal failure_stage
                            failure_stage = "VERSION_STARTED_ACK"
                            on_started(observation)
                            failure_stage = "VERSION_RESUME"

                        def version_resumed(observation: dict[str, object]) -> None:
                            nonlocal failure_stage
                            on_resumed(observation)
                            failure_stage = "VERSION_WAIT"

                        def version_launch_stage(stage: str) -> None:
                            nonlocal failure_stage
                            failure_stage = "VERSION_" + stage

                        version = run_restricted_process(
                            restricted,
                            [str(executable), "--version"],
                            executable,
                            workspace,
                            dict(environment),
                            version_stdout,
                            version_stderr,
                            min(30, float(limits["timeout_seconds"])),
                            version_started,
                            cancel_requested,
                            on_resumed=version_resumed,
                            integrity_level="medium",
                            validated_executable_identity=measurement,
                            executable_provider_id=provider_id,
                            active_process_limit=int(limits["active_process_limit"]),
                            memory_bytes=int(limits["memory_bytes"]),
                            stdout_bytes=int(limits["stdout_bytes"]),
                            stderr_bytes=int(limits["stderr_bytes"]),
                            on_launch_stage=version_launch_stage,
                        )
                        process_result = _sanitized_setup_process_result(
                            version, version_stdout, version_stderr, "VERSION"
                        )
                        failure_stage = "VERSION_VALIDATE"
                        version_text = version.stdout.strip()
                        lines = version_text.splitlines()
                        if (
                            version.exit_code != 0
                            or not lines
                            or lines[0].strip() != envelope["executable"]["version"]
                        ):
                            raise PermissionError(
                                "Codex setup executable version differs"
                            )
                        failure_stage = "ACCOUNT_PROBE_LAUNCH"
                        process_result = None
                        probe_command = (
                            [str(executable), "app-server", "--listen", "stdio://"]
                            if provider_id == "codex"
                            else [
                                str(executable),
                                "--setting-sources=",
                                "auth",
                                "status",
                                "--json",
                            ]
                        )
                        probe = run_restricted_process(
                            restricted,
                            probe_command,
                            executable,
                            workspace,
                            dict(environment),
                            probe_stdout,
                            probe_stderr,
                            min(30, float(limits["timeout_seconds"])),
                            cancel_requested=cancel_requested,
                            jsonl_exchange=(
                                app_server_probe_exchange()
                                if provider_id == "codex"
                                else None
                            ),
                            integrity_level="medium",
                            validated_executable_identity=measurement,
                            executable_provider_id=provider_id,
                            active_process_limit=int(limits["active_process_limit"]),
                            memory_bytes=int(limits["memory_bytes"]),
                            stdout_bytes=int(limits["stdout_bytes"]),
                            stderr_bytes=int(limits["stderr_bytes"]),
                        )
                        process_result = _sanitized_setup_process_result(
                            probe, probe_stdout, probe_stderr, "ACCOUNT_PROBE"
                        )
                        failure_stage = "ACCOUNT_PROBE_VALIDATE"
                        if probe.timed_out:
                            raise TimeoutError("Codex setup account probe timed out")
                        if probe.exit_code != 0:
                            raise PermissionError("Codex setup account probe failed")
                        authentication_probe = (
                            parse_codex_app_server_probe(
                                probe.stdout.splitlines(),
                                model_allowlist=[model_id],
                            )
                            if provider_id == "codex"
                            else parse_claude_auth_status(probe.stdout)
                        )
                        if (
                            provider_id == "claude"
                            and (
                                model_id != CLAUDE_PINNED_REVIEW_MODEL
                                or authentication_probe.get("models") != [model_id]
                            )
                        ):
                            raise PermissionError(
                                "Claude setup model capability differs"
                            )
                        observed_binding = {
                            name: authentication_probe[name]
                            for name in (
                                "account_identity_digest",
                                "authentication_method",
                                "plan_type",
                            )
                        }
                        failure_stage = "ACCOUNT_BINDING_VALIDATE"
                        if (
                            account_binding["account_identity_digest"]
                            == "DISCOVER"
                        ):
                            expected_discovery = {
                                "account_identity_digest": "DISCOVER",
                                "authentication_method": (
                                    "chatgpt-subscription"
                                    if provider_id == "codex"
                                    else CLAUDE_AUTHENTICATION_MODE
                                ),
                                "plan_type": (
                                    CODEX_REQUIRED_SUBSCRIPTION_PLAN
                                    if provider_id == "codex"
                                    else account_binding["plan_type"]
                                ),
                            }
                            if account_binding != expected_discovery:
                                raise PermissionError(
                                    "Codex setup discovery policy is invalid"
                                )
                        elif observed_binding != account_binding:
                            raise PermissionError(
                                "Codex setup authenticated account differs"
                            )
                        usage_observation = dict(
                            authentication_probe["usage_observation"]
                        )
                        final = probe
                        if envelope["operation"] == "QUALIFY":
                            failure_stage = "QUALIFICATION_PREPARE"
                            process_result = None
                            qualification_nonce = (
                                "keeper-codex-qualification-v1"
                                if provider_id == "codex"
                                else CLAUDE_QUALIFICATION_NONCE
                            )
                            schema = claude_qualification_schema() if provider_id == "claude" else {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {
                                    "status": {"type": "string", "const": "ok"},
                                    "provider": {
                                        "type": "string",
                                        "const": provider_id,
                                    },
                                    "effort": {
                                        "type": "string",
                                        "const": "medium",
                                    },
                                    "nonce": {
                                        "type": "string",
                                        "const": qualification_nonce
                                    },
                                },
                                "required": [
                                    "status",
                                    "provider",
                                    "effort",
                                    "nonce",
                                ],
                            }
                            prompt = CLAUDE_QUALIFICATION_PROMPT if provider_id == "claude" else (
                                "Return only the JSON object required by the supplied "
                                "schema. This is a harmless Keeper provider qualification. "
                                "Do not read or write project files, use tools, access "
                                "credentials, or perform any operation beyond this response."
                            )
                            schema_path = setup_root / "qualification-schema.json"
                            output_path = setup_root / "qualification-output.json"
                            events_path = setup_root / "qualification-events.jsonl"
                            error_path = setup_root / "qualification.stderr"
                            schema_bytes = json.dumps(
                                schema, sort_keys=True, separators=(",", ":")
                            ).encode("utf-8")
                            with schema_path.open("xb") as stream:
                                stream.write(schema_bytes)
                                stream.flush()
                                os.fsync(stream.fileno())
                            command = (
                                build_codex_exec_command(
                                    executable,
                                    model_id=model_id,
                                    reasoning_level="medium",
                                    schema_path=schema_path,
                                    output_path=output_path,
                                    prompt=prompt,
                                )
                                if provider_id == "codex"
                                else build_claude_qualification_command(executable)
                            )
                            production_command = tuple(command)
                            prompt_digest = hashlib.sha256(
                                prompt.encode("utf-8")
                            ).hexdigest()
                            schema_digest = hashlib.sha256(schema_bytes).hexdigest()
                            failure_stage = "QUALIFICATION_LAUNCH"
                            final = run_restricted_process(
                                restricted,
                                command,
                                executable,
                                workspace,
                                dict(environment),
                                events_path,
                                error_path,
                                float(limits["timeout_seconds"]),
                                cancel_requested=cancel_requested,
                                integrity_level="medium",
                                validated_executable_identity=measurement,
                                executable_provider_id=provider_id,
                                active_process_limit=int(
                                    limits["active_process_limit"]
                                ),
                                memory_bytes=int(limits["memory_bytes"]),
                                stdout_bytes=int(limits["stdout_bytes"]),
                                stderr_bytes=int(limits["stderr_bytes"]),
                            )
                            process_result = _sanitized_setup_process_result(
                                final, events_path, error_path, "QUALIFICATION"
                            )
                            failure_stage = "QUALIFICATION_VALIDATE"
                            if final.timed_out:
                                raise TimeoutError(
                                    "Codex setup qualification request timed out"
                                )
                            if final.exit_code != 0:
                                raise PermissionError(
                                    "Codex setup qualification request failed"
                                )
                            try:
                                response = json.loads(
                                    output_path.read_text(encoding="utf-8")
                                    if provider_id == "codex"
                                    else final.stdout
                                )
                            except (OSError, json.JSONDecodeError) as error:
                                raise PermissionError(
                                    "Provider setup qualification output is invalid"
                                ) from error
                            expected_output = {
                                "status": "ok",
                                "provider": provider_id,
                                "effort": "medium",
                                "nonce": qualification_nonce,
                            }
                            parsed = (
                                response
                                if provider_id == "codex"
                                else (
                                    response.get("structured_output")
                                    if isinstance(response, dict)
                                    else None
                                )
                            )
                            if parsed != expected_output:
                                raise PermissionError(
                                    "Provider setup qualification output differs"
                                )
                            structured_output = expected_output
                        ownership = {
                            "pid": final.process_id,
                            "launch_nonce": str(envelope["challenge"]),
                            "restricted": final.restricted,
                            "integrity_level": final.integrity_level,
                            "job_confined": final.job_confined,
                            "executable": str(executable),
                            "executable_sha256": str(
                                envelope["executable"]["sha256"]
                            ),
                        }
                        exit_status = 0
        except RestrictedProcessCleanupUncertain:
            # The Host must retain durable UNCERTAIN state; converting this to
            # a normal failed observation would falsely assert termination.
            raise
        except (OSError, PermissionError, RuntimeError, ValueError) as error:
            failure_code = _setup_failure_code(error)
            failure_reason = f"{type(error).__name__}:{failure_code}"
        return {
            "authentication_probe": authentication_probe,
            "exit_status": exit_status,
            "failure_reason": failure_reason,
            "failure_stage": None if exit_status == 0 else failure_stage,
            "failure_code": failure_code,
            "process_ownership": ownership,
            "process_result": process_result,
            "production_command": list(production_command),
            "prompt_digest": prompt_digest,
            "provider_instance_id": (
                provider_id
                + "-session:"
                + str(envelope["provider_registration_id"])
                + ":"
                + str(envelope["user_binding"]["session_id"])
            ),
            "raw_version_output": version_text,
            "schema_digest": schema_digest,
            "structured_output": structured_output,
            "usage_observation": usage_observation,
        }


def _setup_failure_code(error: BaseException) -> str:
    """Return a bounded public error class without exception text or paths."""

    win32_error = getattr(error, "winerror", None)
    if not isinstance(win32_error, int):
        errno = getattr(error, "errno", None)
        win32_error = errno if isinstance(errno, int) else None
    if not isinstance(win32_error, int):
        match = re.search(r"\bwin32_error=(\d{1,5})\b", str(error))
        win32_error = int(match.group(1)) if match is not None else None
    if isinstance(win32_error, int) and 0 < win32_error <= 65_535:
        return f"WIN32_{win32_error}"
    if isinstance(error, TimeoutError):
        return "TIMEOUT"
    if isinstance(error, PermissionError):
        return "PERMISSION_REJECTED"
    if isinstance(error, OSError):
        return "OS_ERROR"
    if isinstance(error, ValueError):
        return "INVALID_RESULT"
    return "RUNTIME_FAILURE"


@contextmanager
def locked_executable(
    executable: Path, declared: Mapping[str, object]
) -> Iterator[dict[str, Any]]:
    """Deny executable write/delete sharing through suspended creation."""

    if os.name != "nt":
        raise RuntimeError("Provider Host process launch requires Windows")
    canonical = executable.resolve(strict=True)
    kernel32 = _kernel32()
    handle = kernel32.CreateFileW(
        str(canonical),
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle in {None, _INVALID_HANDLE}:
        raise PermissionError(
            "Provider Host executable cannot be locked: "
            f"{ctypes.get_last_error()}"
        )
    try:
        content = canonical.read_bytes()
        stat = canonical.stat()
        file_identity = {
            "device_id": int(stat.st_dev),
            "file_id": int(stat.st_ino),
            "modified_ns": int(stat.st_mtime_ns),
            "schema_version": 1,
            "size": int(stat.st_size),
        }
        observed = {
            "authenticode_binding": dict(authenticode_identity(canonical)),
            "canonical_path": str(canonical),
            "file_identity": file_identity,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
        expected = {
            "authenticode_binding": declared.get("authenticode_binding"),
            "canonical_path": declared.get("path"),
            "file_identity": declared.get("file_identity"),
            "sha256": declared.get("sha256"),
            "size": declared.get("size"),
        }
        if observed != expected:
            raise PermissionError("Provider Host executable identity changed")
        yield observed
        final = canonical.stat()
        if (
            int(final.st_dev),
            int(final.st_ino),
            int(final.st_mtime_ns),
            int(final.st_size),
        ) != (
            file_identity["device_id"],
            file_identity["file_id"],
            file_identity["modified_ns"],
            file_identity["size"],
        ):
            raise PermissionError("Provider Host executable changed during launch")
    finally:
        if not kernel32.CloseHandle(handle):
            raise PermissionError("Provider Host executable lock did not close")


@contextmanager
def locked_tls_root_bundle(
    environment: Mapping[str, str], declared: Mapping[str, object]
) -> Iterator[dict[str, object]]:
    """Hold the exact Windows-root PEM immutable for the restricted launch."""

    if os.name != "nt":
        raise RuntimeError("Provider Host TLS root bundle lock requires Windows")
    raw_path = declared.get("canonical_path")
    if not isinstance(raw_path, str) or not raw_path:
        raise PermissionError("Provider Host TLS root bundle path is invalid")
    canonical = Path(raw_path).resolve(strict=True)
    if os.path.normcase(str(canonical)) != os.path.normcase(raw_path):
        raise PermissionError("Provider Host TLS root bundle path is not canonical")
    if environment.get("SSL_CERT_FILE") != str(canonical):
        raise PermissionError("Provider Host TLS root environment differs")
    kernel32 = _kernel32()
    handle = kernel32.CreateFileW(
        str(canonical),
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle in {None, _INVALID_HANDLE}:
        raise PermissionError(
            "Provider Host TLS root bundle cannot be locked: "
            f"{ctypes.get_last_error()}"
        )
    try:
        content = canonical.read_bytes()
        stat = canonical.stat()
        identity = {
            "device_id": int(stat.st_dev),
            "file_id": int(stat.st_ino),
            "modified_ns": int(stat.st_mtime_ns),
            "schema_version": 1,
            "size": int(stat.st_size),
        }
        observed: dict[str, object] = {
            "canonical_path": str(canonical),
            "certificate_count": content.count(b"-----BEGIN CERTIFICATE-----"),
            "file_identity": identity,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
            "source": "windows-root-store",
        }
        if observed != dict(declared):
            raise PermissionError("Provider Host TLS root bundle identity changed")
        yield observed
        final = canonical.stat()
        if (
            int(final.st_dev), int(final.st_ino), int(final.st_mtime_ns),
            int(final.st_size),
        ) != (
            identity["device_id"], identity["file_id"],
            identity["modified_ns"], identity["size"],
        ):
            raise PermissionError("Provider Host TLS root bundle changed during launch")
    finally:
        if not kernel32.CloseHandle(handle):
            raise PermissionError("Provider Host TLS root bundle lock did not close")


def _public_result(
    result: RestrictedProcessResult, stdout_path: Path, stderr_path: Path
) -> dict[str, Any]:
    stdout = stdout_path.read_bytes() if stdout_path.exists() else b""
    stderr = stderr_path.read_bytes() if stderr_path.exists() else b""
    return {
        "exit_code": result.exit_code,
        "job_confined": result.job_confined,
        "pid": result.process_id,
        "restricted": result.restricted,
        "stderr_digest": hashlib.sha256(stderr).hexdigest(),
        "stdout_digest": hashlib.sha256(stdout).hexdigest(),
        "timed_out": result.timed_out,
    }


def _sanitized_setup_process_result(
    result: RestrictedProcessResult,
    stdout_path: Path,
    stderr_path: Path,
    operation: str,
) -> dict[str, Any]:
    """Return a closed, output-free process result for the signed setup record."""

    if operation not in {"VERSION", "ACCOUNT_PROBE", "QUALIFICATION"}:
        raise ValueError("setup process result operation is invalid")
    stdout = stdout_path.read_bytes() if stdout_path.exists() else b""
    stderr = stderr_path.read_bytes() if stderr_path.exists() else b""
    return {
        "operation": operation,
        "exit_code": int(result.exit_code),
        "timed_out": bool(result.timed_out),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stdout_bytes": len(stdout),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stderr_bytes": len(stderr),
        "restricted": result.restricted is True,
        "job_confined": result.job_confined is True,
        "started": True,
        "resumed": True,
    }


def _kernel32() -> Any:
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    api.CreateFileW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    return api
