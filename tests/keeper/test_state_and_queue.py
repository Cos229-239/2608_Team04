import json
from pathlib import Path

import pytest

from keeper.models.task import Task
from keeper.state_machine import TaskStatus, transition
from keeper.task_queue import TaskQueue


def task(identifier: str, status: TaskStatus = TaskStatus.BACKLOG, dependencies: list[str] | None = None) -> Task:
    return Task(identifier, identifier, "description", "one", 1, status=status, dependencies=dependencies or [])


def test_valid_state_transition() -> None:
    assert transition(TaskStatus.BACKLOG, TaskStatus.READY) is TaskStatus.READY


def test_invalid_state_transition() -> None:
    with pytest.raises(ValueError, match="invalid task transition"):
        transition(TaskStatus.BACKLOG, TaskStatus.COMPLETED)


def test_dependency_resolution_and_selection() -> None:
    tasks = [
        task("dependency", TaskStatus.COMPLETED),
        task("blocked", dependencies=["missing"]),
        task("eligible", dependencies=["dependency"]),
    ]
    assert [item.id for item in TaskQueue.eligible(tasks)] == ["eligible"]


def test_retry_limit_excludes_task() -> None:
    candidate = task("attempted")
    candidate.attempts = candidate.maximum_attempts
    assert TaskQueue.eligible([candidate]) == []


def test_failed_task_is_eligible_with_attempt_remaining() -> None:
    candidate = task("retry", TaskStatus.FAILED)
    candidate.attempts = 1
    assert TaskQueue.eligible([candidate]) == [candidate]


def test_load_rejects_duplicate_ids(tmp_path: Path) -> None:
    data = task("same").to_dict()
    (tmp_path / "one.json").write_text(json.dumps(data), encoding="utf-8")
    (tmp_path / "two.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="unique"):
        TaskQueue(tmp_path).load()
