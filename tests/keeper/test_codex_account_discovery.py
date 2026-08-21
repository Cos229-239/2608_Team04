from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any

import pytest

import keeper.authority_service.codex_account_discovery as discovery
from keeper.providers.codex_contract import (
    account_identity_probe_exchange,
    parse_codex_account_identity_probe,
)


ACCOUNT_EMAIL = "founder@example.invalid"
ACCOUNT_DIGEST = hashlib.sha256(
    f"chatgpt\0{ACCOUNT_EMAIL}".encode("utf-8")
).hexdigest()


def _probe_lines(
    *, email: str = ACCOUNT_EMAIL, plan_type: str = "plus"
) -> list[str]:
    return [
        json.dumps({"id": 1, "result": {"userAgent": "fixture"}}),
        json.dumps({"method": "account/updated", "params": {}}),
        json.dumps(
            {
                "id": 2,
                "result": {
                    "account": {
                        "type": "chatgpt",
                        "planType": plan_type,
                        "email": email,
                    }
                },
            }
        ),
    ]


def test_account_identity_probe_is_account_only_and_returns_digest() -> None:
    requests = [json.loads(value) for value, _ in account_identity_probe_exchange()]
    assert [request["method"] for request in requests] == [
        "initialize",
        "initialized",
        "account/read",
    ]
    assert all(
        request["method"]
        not in {"model/list", "account/rateLimits/read", "account/usage/read"}
        for request in requests
    )
    result = parse_codex_account_identity_probe(_probe_lines())
    assert result == {
        "authentication_method": "chatgpt-subscription",
        "plan_type": "plus",
        "account_identity_digest": ACCOUNT_DIGEST,
    }
    assert ACCOUNT_EMAIL not in json.dumps(result)


def test_account_identity_probe_accepts_chatgpt_pro_and_preserves_plan() -> None:
    result = parse_codex_account_identity_probe(_probe_lines(plan_type="pro"))
    assert result == {
        "authentication_method": "chatgpt-subscription",
        "plan_type": "pro",
        "account_identity_digest": ACCOUNT_DIGEST,
    }


@pytest.mark.parametrize("plan_type", ["free", "team", "business", "enterprise", ""])
def test_account_identity_probe_rejects_unapproved_plan(plan_type: str) -> None:
    with pytest.raises(PermissionError, match="plan"):
        parse_codex_account_identity_probe(_probe_lines(plan_type=plan_type))


@pytest.mark.parametrize(
    "lines",
    [
        _probe_lines()[:1],
        [
            _probe_lines()[0],
            json.dumps({"id": 2, "error": {"code": -1}}),
        ],
        [
            _probe_lines()[0],
            json.dumps(
                {
                    "id": 2,
                    "result": {
                        "account": {
                            "type": "chatgpt",
                            "planType": "plus",
                        }
                    },
                }
            ),
        ],
        _probe_lines(email="different-at-invalid"),
        [*_probe_lines(), json.dumps({"id": 2, "result": {}})],
        [*_probe_lines(), json.dumps({"id": 3, "result": {}})],
    ],
)
def test_account_identity_probe_rejects_incomplete_or_malformed_identity(
    lines: list[str],
) -> None:
    with pytest.raises(PermissionError):
        parse_codex_account_identity_probe(lines)


class _RecordingInput(io.BytesIO):
    def __init__(self) -> None:
        super().__init__()
        self.recorded = b""

    def close(self) -> None:
        self.recorded = self.getvalue()
        super().close()


class _FakeProcess:
    def __init__(self) -> None:
        self.stdin = _RecordingInput()
        self.stdout = io.BytesIO(
            ("\n".join(_probe_lines()) + "\n").encode("utf-8")
        )
        self.stderr = io.BytesIO(b"bounded fixture diagnostic\n")
        self.returncode: int | None = None
        self.terminated = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        assert self.returncode is not None
        return self.returncode


def test_account_identity_exchange_closes_process_and_sends_no_model_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeProcess()
    launched: list[list[str]] = []

    def popen(command: list[str], **kwargs: Any) -> _FakeProcess:
        del kwargs
        launched.append(command)
        return fake

    monkeypatch.setattr(discovery.subprocess, "Popen", popen)
    lines, evidence = discovery._exchange_account_identity(
        tmp_path / "codex.exe",
        tmp_path,
        {"CODEX_NON_INTERACTIVE": "1"},
        timeout_seconds=5,
    )
    result = parse_codex_account_identity_probe(lines)
    sent = [json.loads(line) for line in fake.stdin.recorded.decode().splitlines()]
    assert launched == [
        [str(tmp_path / "codex.exe"), "app-server", "--listen", "stdio://"]
    ]
    assert [value["method"] for value in sent] == [
        "initialize",
        "initialized",
        "account/read",
    ]
    assert result["account_identity_digest"] == ACCOUNT_DIGEST
    assert evidence["stdout_bytes"] > 0
    assert evidence["stderr_bytes"] > 0
    assert fake.terminated is True


def test_discovery_result_persists_only_sanitized_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "Founder"))
    monkeypatch.setattr(
        discovery,
        "verify_reviewed_executable",
        lambda *args, **kwargs: {
            "path": str(executable),
            "sha256": "a" * 64,
            "size": 7,
            "version": "codex-cli fixture",
            "authenticode_status": "Valid",
            "publisher_subject": 'CN="OpenAI OpCo, LLC"',
            "certificate_thumbprint": "b" * 40,
        },
    )
    monkeypatch.setattr(
        discovery,
        "_exchange_account_identity",
        lambda *args, **kwargs: (
            _probe_lines(),
            {
                "stdout_bytes": 1,
                "stdout_sha256": "c" * 64,
                "stderr_bytes": 0,
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            },
        ),
    )
    result = discovery.discover_codex_account_identity(
        executable,
        expected_sha256="a" * 64,
        expected_size=7,
        expected_version="codex-cli fixture",
        predecessor_registration_id=("keeper-provider:codex:v1:" + "1" * 32),
        predecessor_failure_digest="2" * 64,
        workspace=workspace,
    )
    serialized = json.dumps(result)
    assert result["account_binding"]["account_identity_digest"] == ACCOUNT_DIGEST
    assert result["predecessor_registration_id"] == (
        "keeper-provider:codex:v1:" + "1" * 32
    )
    assert result["predecessor_failure_digest"] == "2" * 64
    assert result["effect_accounting"]["account_request_count"] == 1
    assert result["effect_accounting"]["model_request_count"] == 0
    assert result["raw_account_identity_persisted"] is False
    assert ACCOUNT_EMAIL not in serialized
