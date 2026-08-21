from enum import StrEnum


class TaskStatus(StrEnum):
    BACKLOG = "BACKLOG"
    READY = "READY"
    BUILDING = "BUILDING"
    SELF_VERIFYING = "SELF_VERIFYING"
    INDEPENDENT_AUDIT = "INDEPENDENT_AUDIT"
    REPAIRING = "REPAIRING"
    FINAL_VERIFY = "FINAL_VERIFY"
    APPROVED = "APPROVED"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    PAUSED = "PAUSED"
    CANCELLED = "CANCELLED"


_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.BACKLOG: frozenset({TaskStatus.READY, TaskStatus.BLOCKED, TaskStatus.CANCELLED}),
    TaskStatus.READY: frozenset({TaskStatus.BUILDING, TaskStatus.BLOCKED, TaskStatus.PAUSED, TaskStatus.CANCELLED}),
    TaskStatus.BUILDING: frozenset({TaskStatus.SELF_VERIFYING, TaskStatus.FAILED, TaskStatus.BLOCKED, TaskStatus.PAUSED}),
    TaskStatus.SELF_VERIFYING: frozenset({TaskStatus.INDEPENDENT_AUDIT, TaskStatus.REPAIRING, TaskStatus.FAILED, TaskStatus.BLOCKED}),
    TaskStatus.INDEPENDENT_AUDIT: frozenset({TaskStatus.REPAIRING, TaskStatus.FINAL_VERIFY, TaskStatus.FAILED, TaskStatus.BLOCKED}),
    TaskStatus.REPAIRING: frozenset({TaskStatus.FINAL_VERIFY, TaskStatus.FAILED, TaskStatus.BLOCKED}),
    TaskStatus.FINAL_VERIFY: frozenset({TaskStatus.APPROVED, TaskStatus.FAILED, TaskStatus.BLOCKED}),
    TaskStatus.APPROVED: frozenset({TaskStatus.COMPLETED}),
    TaskStatus.PAUSED: frozenset({TaskStatus.READY, TaskStatus.BUILDING, TaskStatus.BLOCKED, TaskStatus.CANCELLED}),
    TaskStatus.FAILED: frozenset(
        {
            TaskStatus.READY,
            TaskStatus.BUILDING,
            TaskStatus.SELF_VERIFYING,
            TaskStatus.INDEPENDENT_AUDIT,
            TaskStatus.REPAIRING,
            TaskStatus.FINAL_VERIFY,
            TaskStatus.BLOCKED,
        }
    ),
    TaskStatus.BLOCKED: frozenset(
        {
            TaskStatus.READY,
            TaskStatus.BUILDING,
            TaskStatus.SELF_VERIFYING,
            TaskStatus.INDEPENDENT_AUDIT,
            TaskStatus.REPAIRING,
            TaskStatus.FINAL_VERIFY,
            TaskStatus.CANCELLED,
        }
    ),
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}


def validate_transition(current: TaskStatus, target: TaskStatus) -> None:
    if target not in _TRANSITIONS[current]:
        raise ValueError(f"invalid task transition: {current.value} -> {target.value}")


def transition(current: TaskStatus, target: TaskStatus) -> TaskStatus:
    validate_transition(current, target)
    return target
