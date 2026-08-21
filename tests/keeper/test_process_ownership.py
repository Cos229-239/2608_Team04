from __future__ import annotations

from pathlib import Path

import pytest

from keeper.app.lifecycle import RunStage
from keeper.app.service import KeeperApplication
from keeper.recovery import ownership_records_match, process_identity_matches


def _ownership(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "pid": 4242,
        "creation_time": "20260726120000.000000-240",
        "executable": "C:\\trusted\\provider.exe",
        "command_line_hash": "a" * 64,
        "parent_pid": 101,
        "launch_nonce": "nonce",
        "ownership_token": "token",
        "keeper_run_id": "run-reused-pid",
        "task_id": "task",
        "stage_id": "BUILDING",
        "provider_run_id": "provider-run",
        "provider_name": "provider",
        "provider_instance_id": "provider-instance",
        "role": "builder",
        "evidence_path": "C:\\evidence",
        "job_or_group_identity": "windows-job:1",
        "started_at": "2026-07-26T12:00:00+00:00",
    }
    value.update(overrides)
    return value


class _RetainedHandle:
    def __init__(
        self,
        identities: list[dict[str, object] | None],
        *,
        terminate_result: bool = True,
    ) -> None:
        self.pid = 4242
        self.identities = list(identities)
        self.terminate_result = terminate_result
        self.terminate_calls = 0
        self.close_calls = 0

    def identity(self) -> dict[str, object] | None:
        if len(self.identities) > 1:
            return self.identities.pop(0)
        return self.identities[0] if self.identities else None

    def terminate_exact(self, exit_code: int = 1) -> bool:
        self.terminate_calls += 1
        return self.terminate_result

    def close(self) -> None:
        self.close_calls += 1


def test_process_identity_requires_creation_executable_command_and_parent() -> None:
    recorded = _ownership()
    current = {
        key: recorded[key]
        for key in (
            "pid",
            "creation_time",
            "executable",
            "command_line_hash",
            "parent_pid",
        )
    }
    assert process_identity_matches(recorded, current)
    for key, wrong in (
        ("creation_time", "different"),
        ("executable", "C:\\other.exe"),
        ("command_line_hash", "b" * 64),
        ("parent_pid", 202),
    ):
        assert not process_identity_matches(recorded, {**current, key: wrong})
    assert not process_identity_matches({"pid": 4242}, current)
    assert not process_identity_matches(recorded, None)
    assert ownership_records_match(recorded, dict(recorded))


def _recovery_fixture(data: Path, run_id: str = "run-race") -> dict[str, object]:
    first = KeeperApplication(data)
    first.lifecycle.create(run_id, "task")
    first.lifecycle.transition(run_id, RunStage.SCOPE_VALIDATION)
    evidence = data / "evidence" / run_id
    provider = evidence / ".ai-workflow" / "runs" / "provider-run"
    provider.mkdir(parents=True)
    ownership = _ownership(
        keeper_run_id=run_id,
        evidence_path=str(provider.resolve()),
    )
    (provider / "run.json").write_text(
        __import__("json").dumps(
            {
                "run_id": "provider-run",
                "task_id": "task",
                "role": "builder",
                "status": "running",
                "process_id": 4242,
                "process_ownership": ownership,
            }
        ),
        encoding="utf-8",
    )
    record = first.store.get("runs", run_id)
    assert record is not None
    record.update(
        {
            "status": "running",
            "evidence_root": str(evidence),
            "process_id": 4242,
        }
    )
    first.store.upsert("runs", run_id, record)
    first.store.insert_immutable(
        "artifacts",
        f"process-ownership:{run_id}:provider-run",
        {
            **ownership,
            "id": f"process-ownership:{run_id}:provider-run",
            "kind": "process_ownership",
        },
    )
    return ownership


def _live_identity(ownership: dict[str, object]) -> dict[str, object]:
    return {
        key: ownership[key]
        for key in (
            "pid",
            "creation_time",
            "executable",
            "command_line_hash",
            "parent_pid",
        )
    }


@pytest.mark.parametrize(
    "replacement",
    [
        None,
        {
            "pid": 4242,
            "creation_time": "replacement",
            "executable": "C:\\trusted\\provider.exe",
            "command_line_hash": "a" * 64,
            "parent_pid": 101,
        },
        {
            "pid": 4242,
            "creation_time": "20260726120000.000000-240",
            "executable": "C:\\trusted\\provider.exe",
            "command_line_hash": "a" * 64,
            "parent_pid": 202,
        },
    ],
)
def test_retained_handle_blocks_post_validation_pid_reuse_and_identity_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: dict[str, object] | None,
) -> None:
    data = tmp_path / "data"
    ownership = _recovery_fixture(data)
    retained = _RetainedHandle([_live_identity(ownership), replacement])
    monkeypatch.setattr("keeper.app.workflow.process_exists", lambda pid: True)
    monkeypatch.setattr(
        "keeper.app.workflow.retain_process_handle", lambda pid: retained
    )
    monkeypatch.setattr("keeper.app.workflow._windows_process_tree", lambda pid: [pid])
    recovered = KeeperApplication(data).workflow.startup_recovery[0]
    assert retained.terminate_calls == 0
    assert retained.close_calls == 1
    assert recovered["recovery"]["classification"] == "uncertain"
    assert recovered["recovery"]["retry_safe"] is False
    assert recovered["recovery"]["destructive_revalidation_verified"] is False


def test_recovery_blocks_when_handle_acquisition_or_descendants_are_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for scenario in ("handle", "descendants"):
        data = tmp_path / scenario
        ownership = _recovery_fixture(data, f"run-{scenario}")
        retained = _RetainedHandle([_live_identity(ownership)])
        monkeypatch.setattr("keeper.app.workflow.process_exists", lambda pid: True)
        monkeypatch.setattr(
            "keeper.app.workflow.retain_process_handle",
            (lambda pid: None)
            if scenario == "handle"
            else (lambda pid, value=retained: value),
        )
        monkeypatch.setattr(
            "keeper.app.workflow._windows_process_tree",
            lambda pid: [9001, pid],
        )
        recovered = KeeperApplication(data).workflow.startup_recovery[0]
        assert recovered["recovery"]["classification"] == "uncertain"
        assert recovered["recovery"]["retry_safe"] is False
        assert retained.terminate_calls == 0


def test_protected_job_or_ownership_change_blocks_destructive_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    ownership = _recovery_fixture(data)
    retained = _RetainedHandle(
        [_live_identity(ownership), _live_identity(ownership)]
    )
    matches = iter([True, False])
    monkeypatch.setattr("keeper.app.workflow.process_exists", lambda pid: True)
    monkeypatch.setattr(
        "keeper.app.workflow.retain_process_handle", lambda pid: retained
    )
    monkeypatch.setattr("keeper.app.workflow._windows_process_tree", lambda pid: [pid])
    monkeypatch.setattr(
        "keeper.app.workflow.ownership_records_match",
        lambda authority, evidence: next(matches),
    )
    recovered = KeeperApplication(data).workflow.startup_recovery[0]
    assert retained.terminate_calls == 0
    assert recovered["recovery"]["classification"] == "uncertain"


def test_exact_matching_retained_process_is_terminated_and_handle_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    ownership = _recovery_fixture(data)
    retained = _RetainedHandle(
        [_live_identity(ownership), _live_identity(ownership)]
    )
    monkeypatch.setattr("keeper.app.workflow.process_exists", lambda pid: True)
    monkeypatch.setattr(
        "keeper.app.workflow.retain_process_handle", lambda pid: retained
    )
    monkeypatch.setattr("keeper.app.workflow._windows_process_tree", lambda pid: [pid])
    recovered = KeeperApplication(data).workflow.startup_recovery[0]
    assert retained.terminate_calls == 1
    assert retained.close_calls == 1
    assert recovered["recovery"]["exact_root_process_terminated"] is True
    assert recovered["recovery"]["destructive_revalidation_verified"] is True
    assert recovered["recovery"]["retry_safe"] is True


def test_reused_pid_is_uncertain_and_never_terminated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    first = KeeperApplication(data)
    run_id = "run-reused-pid"
    first.lifecycle.create(run_id, "task")
    for stage in (
        RunStage.SCOPE_VALIDATION,
        RunStage.RISK_CLASSIFICATION,
        RunStage.AUTHORIZATION_RESOLUTION,
        RunStage.PROVIDER_SELECTION,
        RunStage.WORKTREE_PREPARATION,
        RunStage.AUTHOR_EXECUTION,
    ):
        first.lifecycle.transition(run_id, stage)
    evidence = data / "evidence" / run_id
    provider = evidence / ".ai-workflow" / "runs" / "provider-run"
    provider.mkdir(parents=True)
    ownership = _ownership(evidence_path=str(provider.resolve()))
    (provider / "run.json").write_text(
        __import__("json").dumps(
            {
                "run_id": "provider-run",
                "task_id": "task",
                "role": "builder",
                "status": "running",
                "process_id": 4242,
                "process_ownership": ownership,
            }
        ),
        encoding="utf-8",
    )
    record = first.store.get("runs", run_id)
    assert record is not None
    record.update(
        {
            "status": "running",
            "evidence_root": str(evidence),
            "process_id": 4242,
        }
    )
    first.store.upsert("runs", run_id, record)
    first.store.insert_immutable(
        "artifacts",
        "process-ownership:run-reused-pid:provider-run",
        {
            **ownership,
            "id": "process-ownership:run-reused-pid:provider-run",
            "kind": "process_ownership",
        },
    )
    monkeypatch.setattr("keeper.app.workflow.process_exists", lambda pid: True)
    retained = _RetainedHandle(
        [{
            "pid": 4242,
            "creation_time": "reused",
            "executable": "C:\\unrelated.exe",
            "command_line_hash": "b" * 64,
            "parent_pid": 999,
        }]
    )
    monkeypatch.setattr(
        "keeper.app.workflow.retain_process_handle", lambda pid: retained
    )
    monkeypatch.setattr("keeper.app.workflow._windows_process_tree", lambda pid: [pid])
    restarted = KeeperApplication(data)
    recovered = next(
        item for item in restarted.workflow.startup_recovery if item["id"] == run_id
    )
    assert retained.terminate_calls == 0
    assert retained.close_calls == 1
    assert recovered["recovery"]["classification"] == "uncertain"
    assert recovered["recovery"]["identity_verified"] is False
    assert recovered["recovery"]["retry_safe"] is False


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("ownership_token", "forged-token"),
        ("provider_run_id", "other-provider-run"),
        ("stage_id", "REVIEWING"),
        ("provider_name", "other-provider"),
        ("provider_instance_id", "other-instance"),
        ("evidence_path", "C:\\forged-evidence"),
        ("launch_nonce", "forged-nonce"),
        ("task_id", "other-task"),
        ("keeper_run_id", "other-run"),
    ],
)
def test_forged_provider_ownership_never_authorizes_termination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    forged: str,
) -> None:
    data = tmp_path / "data"
    first = KeeperApplication(data)
    run_id = "run-forged"
    first.lifecycle.create(run_id, "task")
    first.lifecycle.transition(run_id, RunStage.SCOPE_VALIDATION)
    evidence = data / "evidence" / run_id
    provider = evidence / ".ai-workflow" / "runs" / "provider-run"
    provider.mkdir(parents=True)
    authority = _ownership(
        keeper_run_id=run_id,
        evidence_path=str(provider.resolve()),
    )
    forged_ownership = {**authority, field: forged}
    (provider / "run.json").write_text(
        __import__("json").dumps(
            {
                "run_id": "provider-run",
                "status": "running",
                "process_id": 4242,
                "process_ownership": forged_ownership,
            }
        ),
        encoding="utf-8",
    )
    record = first.store.get("runs", run_id)
    assert record is not None
    record.update(
        {"status": "running", "evidence_root": str(evidence), "process_id": 4242}
    )
    first.store.upsert("runs", run_id, record)
    first.store.insert_immutable(
        "artifacts",
        f"process-ownership:{run_id}:provider-run",
        {
            **authority,
            "id": f"process-ownership:{run_id}:provider-run",
            "kind": "process_ownership",
        },
    )
    monkeypatch.setattr("keeper.app.workflow.process_exists", lambda pid: True)
    retained = _RetainedHandle(
        [{
            key: authority[key]
            for key in (
                "pid",
                "creation_time",
                "executable",
                "command_line_hash",
                "parent_pid",
            )
        }]
    )
    monkeypatch.setattr(
        "keeper.app.workflow.retain_process_handle", lambda pid: retained
    )
    monkeypatch.setattr("keeper.app.workflow._windows_process_tree", lambda pid: [pid])
    recovered = KeeperApplication(data).workflow.startup_recovery[0]
    assert retained.terminate_calls == 0
    assert recovered["recovery"]["classification"] == "uncertain"
    assert recovered["recovery"]["ownership_binding_verified"] is False
    assert recovered["recovery"]["retry_safe"] is False


@pytest.mark.parametrize("authority_count", [0, 2])
def test_missing_or_duplicate_protected_ownership_is_uncertain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority_count: int,
) -> None:
    data = tmp_path / "data"
    first = KeeperApplication(data)
    run_id = "run-authority-count"
    first.lifecycle.create(run_id, "task")
    first.lifecycle.transition(run_id, RunStage.SCOPE_VALIDATION)
    evidence = data / "evidence" / run_id
    provider = evidence / ".ai-workflow" / "runs" / "provider-run"
    provider.mkdir(parents=True)
    ownership = _ownership(
        keeper_run_id=run_id,
        evidence_path=str(provider.resolve()),
    )
    (provider / "run.json").write_text(
        __import__("json").dumps(
            {
                "run_id": "provider-run",
                "status": "running",
                "process_id": 4242,
                "process_ownership": ownership,
            }
        ),
        encoding="utf-8",
    )
    record = first.store.get("runs", run_id)
    assert record is not None
    record.update(
        {"status": "running", "evidence_root": str(evidence), "process_id": 4242}
    )
    first.store.upsert("runs", run_id, record)
    for index in range(authority_count):
        first.store.insert_immutable(
            "artifacts",
            f"process-ownership:{run_id}:provider-run:{index}",
            {
                **ownership,
                "id": f"process-ownership:{run_id}:provider-run:{index}",
                "kind": "process_ownership",
            },
        )
    monkeypatch.setattr("keeper.app.workflow.process_exists", lambda pid: True)
    retained = _RetainedHandle(
        [{
            key: ownership[key]
            for key in (
                "pid",
                "creation_time",
                "executable",
                "command_line_hash",
                "parent_pid",
            )
        }]
    )
    monkeypatch.setattr(
        "keeper.app.workflow.retain_process_handle", lambda pid: retained
    )
    monkeypatch.setattr("keeper.app.workflow._windows_process_tree", lambda pid: [pid])
    recovered = KeeperApplication(data).workflow.startup_recovery[0]
    assert retained.terminate_calls == 0
    assert recovered["recovery"]["classification"] == "uncertain"
    assert recovered["recovery"]["authoritative_ownership_record_count"] == (
        authority_count
    )


def test_missing_process_is_recoverable_without_termination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    first = KeeperApplication(data)
    first.lifecycle.create("run-missing", "task")
    first.lifecycle.transition("run-missing", RunStage.SCOPE_VALIDATION)
    record = first.store.get("runs", "run-missing")
    assert record is not None
    record.update({"status": "running", "process_id": 999999})
    first.store.upsert("runs", "run-missing", record)
    monkeypatch.setattr("keeper.app.workflow.process_exists", lambda pid: False)
    restarted = KeeperApplication(data)
    recovered = next(
        item
        for item in restarted.workflow.startup_recovery
        if item["id"] == "run-missing"
    )
    assert recovered["recovery"]["classification"] == "recoverable"
    assert recovered["recovery"]["retry_safe"] is True
