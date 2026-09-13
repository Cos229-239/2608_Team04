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
