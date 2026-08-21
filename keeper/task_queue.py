from __future__ import annotations

import json
from pathlib import Path

from keeper.models.task import Task
from keeper.state_machine import TaskStatus


class TaskQueue:
    def __init__(self, task_directory: Path) -> None:
        self.task_directory = task_directory

    def load(self) -> list[Task]:
        tasks: list[Task] = []
        if not self.task_directory.exists():
            return tasks
        for path in sorted(self.task_directory.glob("*.json")):
            with path.open(encoding="utf-8") as handle:
                tasks.append(Task.from_dict(json.load(handle)))
        ids = [task.id for task in tasks]
        if len(ids) != len(set(ids)):
            raise ValueError("task IDs must be unique")
        return tasks

    @staticmethod
    def eligible(tasks: list[Task]) -> list[Task]:
        completed = {task.id for task in tasks if task.status is TaskStatus.COMPLETED}
        return sorted(
            (
                task
                for task in tasks
                if task.status in {TaskStatus.BACKLOG, TaskStatus.READY, TaskStatus.FAILED}
                and set(task.dependencies) <= completed
                and task.attempts < task.maximum_attempts
            ),
            key=lambda item: (item.phase, item.sequence, item.priority, item.id),
        )

    def next(self) -> Task | None:
        tasks = self.load()
        eligible = self.eligible(tasks)
        return eligible[0] if eligible else None
