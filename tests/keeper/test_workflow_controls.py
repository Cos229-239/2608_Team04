from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

import pytest

from keeper.app.service import KeeperApplication
from keeper.desktop import FirstRunController, KeeperViewModel
from keeper.executive.service import KeeperExecutive


def repository(root: Path) -> tuple[Path, str]:
    root.mkdir()
    for args in (
        ("init",),
        ("config", "user.email", "keeper@example.invalid"),
        ("config", "user.name", "Keeper"),
    ):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    (root / "README.md").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=root, check=True, capture_output=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    return root, head


def manual_task(app: KeeperApplication, root: Path) -> str:
    repo, head = repository(root)
    app.add_project(repo)
    task = app.create_task(
        {
            "title": "Manual approval",
            "objective": "Exercise workflow controls",
            "baseline": head,
            "target_branch": "keeper/manual",
            "included_paths": [".keeper-workflow/"],
            "requires_manual_approval": True,
            "is_demo": True,
            "provider_policy": "mock",
            "mock_scenario": "no-repair",
        }
    )
    return str(task["id"])


def await_status(app: KeeperApplication, run_id: str, status: str) -> dict[str, object]:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        run = app.run_status(run_id)
        if run.get("status") == status:
            return run
        time.sleep(0.05)
    raise AssertionError(f"run never reached {status}: {app.run_status(run_id)}")


def test_manual_approval_control_completes_authoritative_run(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    run = app.start_task(manual_task(app, tmp_path / "repo"))
    run_id = str(run["id"])
    await_status(app, run_id, "awaiting_approval")
    app.approve_run(run_id, "Founder")
    completed = app.wait_for_run(run_id, 20)
    assert completed["status"] == "COMPLETED"
    assert completed["approval"]["decision"] == "approved"
    assert app.evidence_path(run_id, "markdown").is_file()


def test_pause_resume_then_reject_and_cancel_controls(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    run_id = str(app.start_task(manual_task(app, tmp_path / "repo"))["id"])
    await_status(app, run_id, "awaiting_approval")
    app.pause_run(run_id)
    assert app.run_status(run_id)["stage"] == "interrupted"
    app.resume_run(run_id)
    app.reject_run(run_id, "Founder", "Acceptance rejection")
    rejected = app.wait_for_run(run_id, 20)
    assert rejected["status"] == "REJECTED"

    second = str(app.start_task(manual_task(app, tmp_path / "repo-2"))["id"])
    await_status(app, second, "awaiting_approval")
    app.cancel_run(second)
    cancelled = app.wait_for_run(second, 20)
    assert cancelled["stage"] == "cancelled"


def test_task_cannot_start_while_a_live_run_already_exists(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    task_id = manual_task(app, tmp_path / "repo")
    app.store.upsert(
        "runs",
        "run-already-live",
        {
            "id": "run-already-live",
            "task_id": task_id,
            "stage": "author_execution",
            "status": "running",
        },
    )

    with pytest.raises(PermissionError, match="already launched"):
        app.start_task(task_id)


def test_task_launch_claim_is_atomic_across_application_instances(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = KeeperApplication(tmp_path / "data")
    task_id = manual_task(first, tmp_path / "repo")
    second = KeeperApplication(tmp_path / "data")
    monkeypatch.setattr(
        first.workflow, "start", lambda value, **kwargs: {"id": "run-first"}
    )
    monkeypatch.setattr(
        second.workflow, "start", lambda value, **kwargs: {"id": "run-second"}
    )

    assert first.start_task(task_id)["id"] == "run-first"
    with pytest.raises(PermissionError, match="immutable settings record"):
        second.start_task(task_id)


def test_terminal_task_requires_explicit_run_recovery_instead_of_relaunch(
    tmp_path: Path,
) -> None:
    app = KeeperApplication(tmp_path / "data")
    task_id = manual_task(app, tmp_path / "repo")
    app.store.upsert(
        "runs",
        "run-completed",
        {
            "id": "run-completed",
            "task_id": task_id,
            "stage": "closed",
            "status": "COMPLETED",
        },
    )

    with pytest.raises(PermissionError, match="explicit run recovery"):
        app.start_task(task_id)


def test_execute_task_uses_the_same_immutable_launch_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = KeeperApplication(tmp_path / "data")
    task_id = manual_task(app, tmp_path / "repo")
    monkeypatch.setattr(
        app.workflow, "start", lambda value, **kwargs: {"id": "run-first"}
    )
    assert app.start_task(task_id)["id"] == "run-first"

    with pytest.raises(PermissionError, match="immutable settings record"):
        app.execute_task(task_id)


def test_task_records_keep_their_keeper_project_binding(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    repo, head = repository(tmp_path / "repo")
    app.add_project(repo)
    task = app.create_task(
        {
            "title": "Bound task",
            "objective": "Remain attached to one Keeper project",
            "baseline": head,
            "target_branch": "keeper/bound-task",
            "keeper_project_id": "keeper-project-1",
            "keeper_charter_id": "charter-1",
            "keeper_charter_revision": 2,
            "keeper_founder_approval_record_id": "approval-1",
            "keeper_founder_approval_identity": "Founder",
        }
    )

    assert task["keeper_project_id"] == "keeper-project-1"
    assert task["keeper_charter_id"] == "charter-1"
    assert task["keeper_charter_revision"] == 2


def test_claimed_task_snapshot_cannot_be_replaced_before_workflow_consumes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = KeeperApplication(tmp_path / "data")
    task_id = manual_task(first, tmp_path / "repo")
    second = KeeperApplication(tmp_path / "data")
    claimed = threading.Event()
    release = threading.Event()
    result: list[dict[str, str]] = []

    def held_start(
        value: str, **kwargs: object
    ) -> dict[str, str]:
        assert value == task_id
        snapshot = kwargs["validated_task"]
        assert isinstance(snapshot, dict)
        assert snapshot["objective"] == "Exercise workflow controls"
        claimed.set()
        assert release.wait(5)
        return {"id": "run-held"}

    monkeypatch.setattr(first.workflow, "start", held_start)
    thread = threading.Thread(
        target=lambda: result.append(first.start_task(task_id)), daemon=True
    )
    thread.start()
    assert claimed.wait(5)
    replacement = second.store.get("tasks", task_id)
    assert replacement is not None
    replacement["objective"] = "MUTATED AFTER VALIDATION"
    with pytest.raises(PermissionError, match="claimed task is immutable"):
        second.store.upsert("tasks", task_id, replacement)
    release.set()
    thread.join(5)
    assert result == [{"id": "run-held"}]


def test_launch_claim_cannot_be_deleted_and_reclaimed_by_another_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = KeeperApplication(tmp_path / "data")
    task_id = manual_task(first, tmp_path / "repo")
    second = KeeperApplication(tmp_path / "data")
    claimed = threading.Event()
    release = threading.Event()

    def held_start(value: str, **kwargs: object) -> dict[str, str]:
        claimed.set()
        assert release.wait(5)
        return {"id": "run-held"}

    monkeypatch.setattr(first.workflow, "start", held_start)
    result: list[dict[str, str]] = []
    thread = threading.Thread(
        target=lambda: result.append(first.start_task(task_id)), daemon=True
    )
    thread.start()
    assert claimed.wait(5)
    with pytest.raises(PermissionError, match="launch claims are immutable"):
        second.store.delete("settings", f"task_launch_claim:{task_id}")
    with pytest.raises(PermissionError, match="claimed task is immutable"):
        second.store.delete("tasks", task_id)
    with pytest.raises(PermissionError, match="immutable settings record"):
        second.start_task(task_id)
    release.set()
    thread.join(5)
    assert result == [{"id": "run-held"}]


def test_direct_service_start_rejects_a_superseded_keeper_charter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = KeeperApplication(tmp_path / "data")
    repo, head = repository(tmp_path / "repo")
    app.add_project(repo)
    task = app.create_task(
        {
            "title": "Bound task",
            "objective": "Never run under a superseded charter",
            "baseline": head,
            "target_branch": "keeper/bound-task",
            "keeper_project_id": "keeper-project-1",
            "keeper_charter_id": "charter-old",
            "keeper_charter_revision": 1,
            "keeper_founder_approval_record_id": "approval-old",
            "keeper_founder_approval_identity": "Founder",
        }
    )

    class CurrentStatus:
        def to_dict(self) -> dict[str, object]:
            return {
                "active_charter": {
                    "charter_id": "charter-current",
                    "revision": 2,
                    "founder_approval_record_id": "approval-current",
                    "founder_approval_identity": "Founder",
                    "workspaces": [str(repo.resolve())],
                }
            }

    monkeypatch.setattr(
        KeeperExecutive, "status", lambda self, project_id: CurrentStatus()
    )
    called = False

    def forbidden_start(task_id: str) -> dict[str, str]:
        nonlocal called
        called = True
        return {"id": "forbidden"}

    monkeypatch.setattr(app.workflow, "start", forbidden_start)
    with pytest.raises(PermissionError, match="current approved Keeper charter"):
        app.start_task(str(task["id"]))
    assert called is False


def test_first_run_controller_navigation_validation_and_persistence(
    tmp_path: Path,
) -> None:
    app = KeeperApplication(tmp_path / "data")
    controller = FirstRunController(app)
    assert controller.step == "boundaries"
    assert controller.back() == "boundaries"
    for expected in controller.STEPS[1:]:
        assert controller.next() == expected
    controller.evidence_directory = str(tmp_path / "evidence")
    controller.provider_policy = "automatic"
    controller.finish()
    assert app.setup_complete()
    assert app.store.get("settings", "routing") == {
        "default_provider_policy": "automatic"
    }


def test_view_model_exposes_real_controls(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    model = KeeperViewModel(app)
    run_id = str(model.start_task(manual_task(app, tmp_path / "repo"))["id"])
    await_status(app, run_id, "awaiting_approval")
    model.approve(run_id, "Founder")
    assert app.wait_for_run(run_id, 20)["status"] == "COMPLETED"
