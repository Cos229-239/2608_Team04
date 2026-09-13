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
