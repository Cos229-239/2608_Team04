from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from keeper.app.git_safety import GitSafetyService
from keeper.app.notifications import SUPPORTED_EVENTS, deliver_local_notification
from keeper.app.security import (
    MAX_LOG_BYTES,
    redact_structure,
    redact_text,
    safe_repository_path,
    validate_archive_member,
)
from keeper.app.service import KeeperApplication
from keeper.app.verification_policy import VerificationSpec, environment_summary, validate_semantic_bindings


def test_environment_summary_never_contains_secret_names_or_values() -> None:
    summary = environment_summary({"PATH": "safe", "API_KEY": "secret", "TOKEN": "secret"})
    assert summary == {"available_keys": ["PATH"], "secret_values_included": False}


def test_generic_shell_cannot_be_a_registered_verification() -> None:
    with pytest.raises(ValueError, match="cannot satisfy"):
        validate_semantic_bindings(
            [
                VerificationSpec(
                    "task", ["powershell.exe", "-Command", "exit 0"], "registered-command"
                )
            ],
            ["task"],
        )


def test_authorization_rejects_malformed_naive_expired_and_revoked(tmp_path: Path) -> None:
    base: dict[str, object] = {
        "capability": "push",
        "repository": str(tmp_path.resolve()),
        "approving_authority": "founder",
        "consumed_at": None,
        "revoked_at": None,
    }
    for expires in (
        "zzzz",
        datetime.now().isoformat(),
        (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
    ):
        value = {**base, "expires_at": expires}
        with pytest.raises(PermissionError):
            GitSafetyService._require_authorization("push", tmp_path, value)
    value = {
        **base,
        "expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
        "revoked_at": datetime.now(UTC).isoformat(),
    }
    with pytest.raises(PermissionError):
        GitSafetyService._require_authorization("push", tmp_path, value)


def test_notifications_are_bounded_and_event_allowlisted() -> None:
    assert "blocking_finding" in SUPPORTED_EVENTS
    with pytest.raises(ValueError, match="unsupported"):
        deliver_local_notification("source_code", "title", "detail")


def test_service_redacts_notification_details(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    item = app.notify("provider_failure", "token=abc", "password: hunter2")
    assert "abc" not in item["title"]
    assert "hunter2" not in item["detail"]


def test_redaction_and_log_bounding() -> None:
    value = redact_text("api_key=abc " + ("x" * (MAX_LOG_BYTES + 10)))
    assert "abc" not in value and value.endswith("[OUTPUT TRUNCATED]")
    structured = redact_structure({"token": "abc", "nested": ["password=bad"]})
    assert structured == {"token": "[REDACTED]", "nested": ["password=[REDACTED]"]}


def test_safe_paths_and_archive_members_reject_traversal(tmp_path: Path) -> None:
    assert safe_repository_path(tmp_path, "keeper/file.py") == tmp_path / "keeper" / "file.py"
    for value in ("../secret", "/absolute", "keeper/../../secret"):
        with pytest.raises(PermissionError):
            safe_repository_path(tmp_path, value)
        with pytest.raises(ValueError):
            validate_archive_member(value, 10)
    with pytest.raises(ValueError, match="size"):
        validate_archive_member("safe.txt", 33 * 1024 * 1024)
