from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import Mock

import pytest

from keeper.app.service import KeeperApplication
from keeper.app.workflow import ActiveRun


def test_recovery_records_are_read_only_and_global(tmp_path: Path, monkeypatch) -> None:
    app = KeeperApplication(tmp_path)
    records = [
        {"id": "a", "task_id": "other-project", "status": "interrupted", "recovery": {"classification": "uncertain"}},
        {"id": "b", "status": "UNCERTAIN"},
        {"id": "c", "status": "running"},
        {"id": "d", "status": "COMPLETED"},
    ]
    for row in records:
        app.store.upsert("runs", row["id"], row)
    before = app.store.list("runs")
    monkeypatch.setattr(app.workflow, "recover_interrupted_runs", Mock(side_effect=AssertionError("must not recover")))
    for _ in range(2):
        assert {r["id"] for r in app.recovery_records()} == {"a", "b"}
    assert app.store.list("runs") == before


def test_recovery_skips_registered_worker_before_start(tmp_path: Path, monkeypatch) -> None:
    app = KeeperApplication(tmp_path)
    row = {"id": "active", "status": "running", "stage": "author_execution"}
    app.store.upsert("runs", "active", row)
    app.workflow._active["active"] = ActiveRun(threading.Thread(), threading.Event(), threading.Event(), threading.Event())
    monkeypatch.setattr(app.workflow, "_process_ownership_records", Mock(side_effect=AssertionError("must not probe active worker")))
    assert app.recover_runs() == []
    assert app.store.get("runs", "active") == row
    with pytest.raises(RuntimeError, match="already active"):
        app.retry_run("active", "duplicate")
    assert app.store.get("runs", "active") == row


def test_recovery_serializes_with_start_publication(tmp_path: Path, monkeypatch) -> None:
    app = KeeperApplication(tmp_path)
    entered = threading.Event()
    finished = threading.Event()
    original = app.store.list
    def observed(kind):
        if kind == "runs":
            entered.set()
        return original(kind)
    monkeypatch.setattr(app.store, "list", observed)
    def recover():
        app.recover_runs()
        finished.set()
    with app.workflow._recovery_lock:
        worker = threading.Thread(target=recover)
        worker.start()
        assert not entered.wait(0.1)
    worker.join(3)
    assert finished.is_set()


@pytest.mark.parametrize("classification,safe,running,stage,expected", [
    ("recoverable", True, False, "author_execution", "retry"),
    ("uncertain", True, False, "author_execution", ""),
    ("recoverable", False, False, "author_execution", ""),
    ("recoverable", True, True, "author_execution", ""),
    ("recoverable", True, False, "authorized_push", ""),
    ("recoverable", True, False, "scope_validation", ""),
    ("unknown", True, False, "author_execution", ""),
])
def test_recovery_action_fails_closed(tmp_path, classification, safe, running, stage, expected):
    app = KeeperApplication(tmp_path)
    row = {"id": "r", "status": "interrupted", "stage": "interrupted", "interrupted_from": stage,
           "recovery": {"classification": classification, "retry_safe": safe, "previous_process_running": running}}
    assert app.workflow.recovery_action(row) == expected


def test_paused_live_worker_resumes_not_retries(tmp_path):
    app = KeeperApplication(tmp_path)
    paused = threading.Event()
    paused.set()
    thread = Mock()
    thread.is_alive.return_value = True
    app.workflow._active["r"] = ActiveRun(thread, threading.Event(), paused, threading.Event())
    row = {"id": "r", "status": "interrupted", "stage": "interrupted"}
    assert app.workflow.recovery_action(row) == "resume"
    row["recovery"] = {"classification": "uncertain"}
    assert app.workflow.recovery_action(row) == ""


def test_worker_start_failure_removes_only_exact_registry_entry(tmp_path):
    app = KeeperApplication(tmp_path)
    thread = Mock()
    thread.start.side_effect = RuntimeError("cannot start thread")
    row = {"id": "r", "status": "running"}
    app.store.upsert("runs", "r", row)
    active = ActiveRun(thread, threading.Event(), threading.Event(), threading.Event())
    app.workflow._active["r"] = active
    with pytest.raises(RuntimeError, match="cannot start"):
        app.workflow._start_registered_worker("r", thread)
    assert "r" not in app.workflow._active
    assert app.store.get("runs", "r") == row
    replacement = ActiveRun(Mock(), threading.Event(), threading.Event(), threading.Event())
    app.workflow._active["r"] = replacement
    with pytest.raises(RuntimeError):
        app.workflow._start_registered_worker("r", thread)
    assert app.workflow._active["r"] is replacement


def test_retry_launch_failure_remains_available_for_recovery(tmp_path, monkeypatch):
    app = KeeperApplication(tmp_path)
    app.lifecycle.create("r", "task")
    row = app.store.get("runs", "r")
    row.update({"stage": "interrupted", "status": "interrupted", "interrupted_from": "author_execution",
                "recovery": {"classification": "recoverable", "retry_safe": True, "previous_process_running": False}})
    app.store.upsert("runs", "r", row)
    monkeypatch.setattr(app.workflow, "_task", lambda _: {})
    thread = Mock()
    thread.start.side_effect = RuntimeError("cannot start thread")
    monkeypatch.setattr("keeper.app.workflow.threading.Thread", Mock(return_value=thread))
    with pytest.raises(RuntimeError, match="cannot start"):
        app.retry_run("r", "explicit retry")
    assert "r" not in app.workflow._active
    assert app.store.get("runs", "r") is not None


def test_stale_retry_cannot_bypass_new_uncertainty(tmp_path):
    app = KeeperApplication(tmp_path)
    app.lifecycle.create("r", "task")
    row = app.store.get("runs", "r")
    row.update({"stage": "interrupted", "status": "interrupted", "interrupted_from": "author_execution",
                "recovery": {"classification": "uncertain", "retry_safe": True, "previous_process_running": False}})
    app.store.upsert("runs", "r", row)
    with pytest.raises(PermissionError, match="uncertain"):
        app.retry_run("r", "stale button")
    assert app.store.get("runs", "r") == row


def test_concurrent_retry_and_recovery_wait_for_worker_publication(tmp_path, monkeypatch):
    app = KeeperApplication(tmp_path)
    app.lifecycle.create("r", "task")
    row = app.store.get("runs", "r")
    row.update({"stage": "interrupted", "status": "interrupted", "interrupted_from": "author_execution",
                "recovery": {"classification": "recoverable", "retry_safe": True, "previous_process_running": False}})
    app.store.upsert("runs", "r", row)
    entered, publish, stop_worker = threading.Event(), threading.Event(), threading.Event()
    retry_stage = app.workflow.lifecycle.retry_stage
    calls = []
    def delayed_retry(*args, **kwargs):
        calls.append("transition")
        entered.set()
        assert publish.wait(3)
        return retry_stage(*args, **kwargs)
    monkeypatch.setattr(app.workflow.lifecycle, "retry_stage", delayed_retry)
    monkeypatch.setattr(app.workflow, "_task", lambda _: {})
    monkeypatch.setattr(app.workflow, "_execute_guarded", lambda *args: stop_worker.wait(5))
    outcomes = []
    def retry():
        try:
            app.retry_run("r", "explicit retry")
            outcomes.append("started")
        except RuntimeError as error:
            outcomes.append(str(error))
    first = threading.Thread(target=retry)
    second = threading.Thread(target=retry)
    recovered = []
    recovery = threading.Thread(target=lambda: recovered.append(app.recover_runs()))
    try:
        first.start()
        assert entered.wait(3)
        second.start()
        recovery.start()
        publish.set()
        for thread in (first, second, recovery):
            thread.join(3)
            assert not thread.is_alive()
        assert calls == ["transition"]
        assert sorted(outcomes) == ["stage retry is already active", "started"]
        assert recovered == [[]]
        assert app.store.get("runs", "r")["status"] == "running"
    finally:
        publish.set()
        stop_worker.set()
        for thread in (first, second, recovery):
            if thread.ident is not None:
                thread.join(3)
        active = app.workflow._active.get("r")
        if active is not None:
            active.thread.join(3)


def test_controller_refresh_does_not_recover_and_counts_global_uncertainty(tmp_path, monkeypatch):
    pytest.importorskip("PySide6")
    from keeper.ui_qml.controller import KeeperDesktopController
    app = KeeperApplication(tmp_path)
    controller = KeeperDesktopController(app, test_fixture=True)
    app.store.upsert("runs", "foreign-run", {"id": "foreign-run", "task_id": "foreign-task", "status": "interrupted", "recovery": {"classification": "uncertain"}})
    monkeypatch.setattr(app, "recover_runs", Mock(side_effect=AssertionError("refresh must be read-only")))
    for _ in range(2):
        controller.refresh()
        state = controller.state_snapshot()
        assert state["counts"]["uncertain"] == 1
        row = state["recoveries"][0]
        assert row["run_id"] == "foreign-run"
        assert row["status"] == "UNCERTAIN"
        assert row["recovery_action"] == ""
    controller.sendAssistantMessage("Create a local checklist project.")
    first = controller.state_snapshot()["project"]["id"]
    controller.startNewProject()
    controller.sendAssistantMessage("Create a local notes project.")
    second = controller.state_snapshot()["project"]["id"]
    assert first and second and first != second
    for selected in (first, second):
        controller.selectProject(selected)
        assert controller.state_snapshot()["counts"]["uncertain"] == 1
        assert controller.state_snapshot()["counts"]["projectUncertain"] == 0


def test_charter_summary_shows_recorded_request_and_missing_fields():
    pytest.importorskip("PySide6")
    from keeper.ui_qml.controller import _charter_summary
    result = _charter_summary({"problem_or_opportunity": "Do not push or deploy.", "deliverables": ["Checklist"], "success_criteria": ["Readable"], "constraints": []})
    assert "Do not push or deploy." in result
    assert "Deliverables: Checklist" in result
    assert "Success criteria: Readable" in result
    assert "Constraints: Not recorded" in result
    assert "not permission to act" in result
