from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from tests.keeper.authority_testkit import provider_authority_kwargs

from keeper.app.lifecycle import RunStage
from keeper.app.service import KeeperApplication
from keeper.providers.adapters import (
    CodexCommandAdapter,
    ProviderDiscovery,
    create_provider_registration,
)


def _marker_provider(path: Path, marker: Path) -> None:
    path.write_text(
        f'@echo marker>"{marker}"\r\n'
        'if "%~1"=="--version" echo controlled 1.0\r\n',
        encoding="ascii",
    )


def test_discovery_never_executes_configured_unregistered_content(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "executed.txt"
    _marker_provider(executable, marker)
    diagnostic = next(
        item
        for item in ProviderDiscovery({"codex": str(executable)}).discover()
        if item.provider_id == "codex"
    )
    assert not diagnostic.available
    assert diagnostic.discovery_state == "blocked"
    assert "no immutable registration" in diagnostic.detail
    assert not marker.exists()


def test_diagnostics_and_first_run_do_not_execute_unknown_content(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "diagnostic-executed.txt"
    _marker_provider(executable, marker)
    app = KeeperApplication(tmp_path / "data")
    app.save_provider_paths({"codex": str(executable)})
    diagnostic = next(
        item for item in app.diagnostics()["providers"] if item["provider_id"] == "codex"
    )
    assert diagnostic["available"] is False
    assert diagnostic["discovery_state"] == "blocked"
    assert not marker.exists()


@pytest.mark.parametrize("mutation", ["stale", "malformed", "revoked"])
def test_discovery_registration_mismatch_fails_without_execution(
    tmp_path: Path, mutation: str
) -> None:
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / f"{mutation}-executed.txt"
    _marker_provider(executable, marker)
    registration = create_provider_registration(
        "codex", executable, authorized_by="test-authority"
    , **provider_authority_kwargs('codex'))
    if mutation == "stale":
        registration["script_sha256"] = "0" * 64
    elif mutation == "malformed":
        del registration["launcher_sha256"]
    else:
        registration["revoked_at"] = "2026-07-26T00:00:00+00:00"
    diagnostic = next(
        item
        for item in ProviderDiscovery(
            {"codex": str(executable)}, {"codex": registration}
        ).discover()
        if item.provider_id == "codex"
    )
    assert not diagnostic.available
    assert diagnostic.discovery_state == (
        "revoked" if mutation == "revoked" else "blocked"
    )
    assert not marker.exists()


def test_registration_remains_unqualified_without_execution(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "qualified-executed.txt"
    _marker_provider(executable, marker)
    registration = create_provider_registration(
        "codex",
        executable,
        authorized_by="test-authority",
     **provider_authority_kwargs('codex'))
    diagnostic = next(
        item
        for item in ProviderDiscovery(
            {"codex": str(executable)}, {"codex": registration}
        ).discover()
        if item.provider_id == "codex"
    )
    assert diagnostic.available
    assert diagnostic.version is None
    assert diagnostic.discovery_state == "registered-unqualified"
    assert not marker.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("launcher_sha256", "0" * 64),
        ("launcher_size", 1),
        ("script_sha256", "0" * 64),
        ("script_size", 1),
    ],
)
def test_batch_constructor_rejects_authoritative_component_mismatch(
    tmp_path: Path, field: str, value: object
) -> None:
    executable = tmp_path / "provider.cmd"
    _marker_provider(executable, tmp_path / "never.txt")
    registration = create_provider_registration(
        "codex", executable, authorized_by="test-authority"
    , **provider_authority_kwargs('codex'))
    registration[field] = value
    with pytest.raises(PermissionError):
        CodexCommandAdapter(str(executable), registration)
    assert registration[field] == value


def test_batch_constructor_does_not_rederive_changed_script_into_trust(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider.cmd"
    _marker_provider(executable, tmp_path / "original.txt")
    registration = create_provider_registration(
        "codex", executable, authorized_by="test-authority"
    , **provider_authority_kwargs('codex'))
    original_configuration = registration["configuration_digest"]
    content = executable.read_bytes()
    executable.write_bytes(b"X" + content[1:])
    assert executable.stat().st_size == registration["script_size"]
    with pytest.raises(PermissionError):
        CodexCommandAdapter(str(executable), registration)
    assert registration["configuration_digest"] == original_configuration


def _execution_started_run(
    app: KeeperApplication,
    *,
    evidence_kind: str,
) -> tuple[str, Path]:
    run_id = f"run-{evidence_kind}"
    app.lifecycle.create(run_id, "task")
    app.lifecycle.transition(run_id, RunStage.SCOPE_VALIDATION)
    evidence = app.data_directory / "evidence" / run_id
    provider = evidence / ".ai-workflow" / "runs" / "provider-run"
    provider.mkdir(parents=True)
    record = app.store.get("runs", run_id)
    assert record is not None
    record.update(
        {
            "status": "running",
            "evidence_root": str(evidence),
            "provider_execution_attempts": [
                {
                    "status": "EXECUTION_STARTED",
                    "provider_run_id": "provider-run",
                    "task_id": "task",
                    "stage_id": "author_execution",
                    "role": "builder",
                    "provider_instance_id": "instance",
                    "stable_registration_digest": "d" * 64,
                    "start_time": "2026-07-26T00:00:00+00:00",
                    "evidence_path": str(provider / "run.json"),
                    "process_id": None,
                }
            ],
        }
    )
    app.store.upsert("runs", run_id, record)
    return run_id, provider / "run.json"


@pytest.mark.parametrize(
    ("kind", "content", "expected_status"),
    [
        ("missing", None, "MISSING_EVIDENCE"),
        ("malformed", "{", "MALFORMED_EVIDENCE"),
        (
            "other-run",
            json.dumps(
                {
                    "run_id": "other",
                    "task_id": "task",
                    "role": "builder",
                    "status": "running",
                }
            ),
            "INDETERMINATE",
        ),
        (
            "other-task",
            json.dumps(
                {
                    "run_id": "provider-run",
                    "task_id": "other",
                    "role": "builder",
                    "status": "running",
                }
            ),
            "INDETERMINATE",
        ),
    ],
)
def test_unresolved_execution_started_is_blocked_and_not_retry_safe(
    tmp_path: Path,
    kind: str,
    content: str | None,
    expected_status: str,
) -> None:
    app = KeeperApplication(tmp_path / kind)
    run_id, evidence_path = _execution_started_run(app, evidence_kind=kind)
    if content is not None:
        evidence_path.write_text(content, encoding="utf-8")
    recovered = app.workflow.recover_interrupted_runs()[0]
    recovery = recovered["recovery"]
    assert recovery["classification"] == "uncertain"
    assert recovery["retry_safe"] is False
    assert recovery["provider_evidence_status"] == expected_status
    assert recovery["durable_execution_attempt"]["provider_run_id"] == "provider-run"
    assert recovery["termination_reason"]


def test_duplicate_provider_evidence_is_blocked(
    tmp_path: Path,
) -> None:
    app = KeeperApplication(tmp_path / "duplicate")
    _, first = _execution_started_run(app, evidence_kind="duplicate")
    value = {
        "run_id": "provider-run",
        "task_id": "task",
        "role": "builder",
        "status": "running",
    }
    first.write_text(json.dumps(value), encoding="utf-8")
    second = first.parents[1] / "duplicate-provider" / "run.json"
    second.parent.mkdir()
    second.write_text(json.dumps(value), encoding="utf-8")
    recovered = app.workflow.recover_interrupted_runs()[0]
    assert recovered["recovery"]["provider_evidence_status"] == "INDETERMINATE"
    assert recovered["recovery"]["retry_safe"] is False


def test_deleted_evidence_after_execution_start_remains_non_reusable(
    tmp_path: Path,
) -> None:
    app = KeeperApplication(tmp_path / "deleted")
    run_id, evidence = _execution_started_run(app, evidence_kind="deleted")
    evidence.write_text(
        json.dumps(
            {
                "run_id": "provider-run",
                "task_id": "task",
                "role": "builder",
                "status": "running",
            }
        ),
        encoding="utf-8",
    )
    evidence.unlink()
    recovered = app.workflow.recover_interrupted_runs()[0]
    assert recovered["id"] == run_id
    assert recovered["recovery"]["retry_safe"] is False
    assert recovered["recovery"]["provider_evidence_status"] == "MISSING_EVIDENCE"
