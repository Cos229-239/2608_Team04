from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from keeper.app.storage import KeeperStore


class RunStage(StrEnum):
    INTAKE = "intake"
    SCOPE_VALIDATION = "scope_validation"
    RISK_CLASSIFICATION = "risk_classification"
    AUTHORIZATION_RESOLUTION = "authorization_resolution"
    PROVIDER_SELECTION = "provider_selection"
    WORKTREE_PREPARATION = "worktree_preparation"
    AUTHOR_EXECUTION = "author_execution"
    AUTHOR_SELF_VERIFICATION = "author_self_verification"
    INDEPENDENT_AUDIT = "independent_audit"
    REPAIR_EXECUTION = "repair_execution"
    POST_REPAIR_VERIFICATION = "post_repair_verification"
    FINAL_VALIDATION = "final_validation"
    APPROVAL_DECISION = "approval_decision"
    AUTHORIZED_COMMIT = "authorized_commit"
    AUTHORIZED_PUSH = "authorized_push"
    EVIDENCE_FINALIZATION = "evidence_finalization"
    CLOSED = "closed"
    INTERRUPTED = "interrupted"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


TERMINAL_STAGES = frozenset(
    {RunStage.CLOSED, RunStage.CANCELLED, RunStage.BLOCKED}
)

RETRYABLE_STAGES = frozenset(
    {
        RunStage.AUTHOR_EXECUTION,
        RunStage.AUTHOR_SELF_VERIFICATION,
        RunStage.INDEPENDENT_AUDIT,
        RunStage.REPAIR_EXECUTION,
        RunStage.POST_REPAIR_VERIFICATION,
        RunStage.FINAL_VALIDATION,
    }
)

_FORWARD: dict[RunStage, frozenset[RunStage]] = {
    RunStage.INTAKE: frozenset({RunStage.SCOPE_VALIDATION}),
    RunStage.SCOPE_VALIDATION: frozenset({RunStage.RISK_CLASSIFICATION}),
    RunStage.RISK_CLASSIFICATION: frozenset({RunStage.AUTHORIZATION_RESOLUTION}),
    RunStage.AUTHORIZATION_RESOLUTION: frozenset({RunStage.PROVIDER_SELECTION}),
    RunStage.PROVIDER_SELECTION: frozenset({RunStage.WORKTREE_PREPARATION}),
    RunStage.WORKTREE_PREPARATION: frozenset({RunStage.AUTHOR_EXECUTION}),
    RunStage.AUTHOR_EXECUTION: frozenset({RunStage.AUTHOR_SELF_VERIFICATION}),
    RunStage.AUTHOR_SELF_VERIFICATION: frozenset({RunStage.INDEPENDENT_AUDIT}),
    RunStage.INDEPENDENT_AUDIT: frozenset(
        {RunStage.REPAIR_EXECUTION, RunStage.FINAL_VALIDATION}
    ),
    RunStage.REPAIR_EXECUTION: frozenset({RunStage.POST_REPAIR_VERIFICATION}),
    RunStage.POST_REPAIR_VERIFICATION: frozenset({RunStage.INDEPENDENT_AUDIT}),
    RunStage.FINAL_VALIDATION: frozenset({RunStage.APPROVAL_DECISION}),
    RunStage.APPROVAL_DECISION: frozenset(
        {RunStage.AUTHORIZED_COMMIT, RunStage.EVIDENCE_FINALIZATION}
    ),
    RunStage.AUTHORIZED_COMMIT: frozenset(
        {RunStage.AUTHORIZED_PUSH, RunStage.EVIDENCE_FINALIZATION}
    ),
    RunStage.AUTHORIZED_PUSH: frozenset({RunStage.EVIDENCE_FINALIZATION}),
    RunStage.EVIDENCE_FINALIZATION: frozenset({RunStage.CLOSED}),
}


@dataclass(frozen=True, slots=True)
class TransitionResult:
    run_id: str
    previous: RunStage
    current: RunStage
    sequence: int


class RunLifecycle:
    """Durable, fail-closed lifecycle controller with idempotent recovery."""

    def __init__(self, store: KeeperStore) -> None:
        self.store = store

    def create(self, run_id: str, task_id: str) -> dict[str, Any]:
        existing = self.store.get("runs", run_id)
        if existing is not None:
            if existing.get("task_id") != task_id:
                raise ValueError("run identifier is already bound to another task")
            return existing
        record: dict[str, Any] = {
            "id": run_id,
            "task_id": task_id,
            "stage": RunStage.INTAKE.value,
            "sequence": 0,
            "status": "running",
            "history": [],
            "interrupted_from": None,
        }
        self.store.upsert("runs", run_id, record)
        return record

    def transition(self, run_id: str, target: RunStage) -> TransitionResult:
        record = self._record(run_id)
        previous = RunStage(str(record["stage"]))
        if previous == target:
            return TransitionResult(run_id, previous, target, int(record["sequence"]))
        if target == RunStage.INTERRUPTED:
            if previous in TERMINAL_STAGES:
                raise ValueError("terminal run cannot be interrupted")
            record["interrupted_from"] = previous.value
        elif target in {RunStage.CANCELLED, RunStage.BLOCKED}:
            if previous in TERMINAL_STAGES:
                raise ValueError("terminal run cannot change state")
            record["stopped_from"] = previous.value
        elif previous == RunStage.INTERRUPTED:
            if target.value != record.get("interrupted_from"):
                raise ValueError("interrupted run may resume only at its recorded stage")
            record["interrupted_from"] = None
        elif target not in _FORWARD.get(previous, frozenset()):
            raise ValueError(f"forbidden Keeper transition: {previous} -> {target}")
        sequence = int(record["sequence"]) + 1
        history = list(record.get("history", []))
        history.append({"sequence": sequence, "from": previous.value, "to": target.value})
        if target in RETRYABLE_STAGES:
            attempts = dict(record.get("stage_attempt_counts", {}))
            count = int(attempts.get(target.value, 0)) + 1
            attempts[target.value] = count
            record["stage_attempt_counts"] = attempts
            record["active_stage_attempt_id"] = (
                f"{run_id}:{target.value}:{count}"
            )
        record.update(
            {
                "stage": target.value,
                "sequence": sequence,
                "history": history,
                "status": (
                    "completed"
                    if target == RunStage.CLOSED
                    else target.value
                    if target in TERMINAL_STAGES
                    else "running"
                ),
            }
        )
        self.store.upsert("runs", run_id, record)
        return TransitionResult(run_id, previous, target, sequence)

    def retry_stage(
        self,
        run_id: str,
        target: RunStage,
        *,
        reason: str,
        authorizer: str,
    ) -> dict[str, Any]:
        if target not in RETRYABLE_STAGES:
            raise PermissionError("selected stage is not retryable")
        if not reason.strip() or not authorizer.strip():
            raise ValueError("retry reason and authorizer are required")
        record = self._record(run_id)
        previous = RunStage(str(record["stage"]))
        if previous not in {
            RunStage.INTERRUPTED,
            RunStage.BLOCKED,
            RunStage.CANCELLED,
        }:
            raise PermissionError("run is not stopped at a retryable stage")
        expected = (
            record.get("interrupted_from")
            if previous == RunStage.INTERRUPTED
            else record.get("stopped_from")
        )
        if expected != target.value:
            raise PermissionError("retry authorization does not match the failed stage")
        recovery = record.get("recovery")
        if isinstance(recovery, dict):
            if not recovery.get("retry_safe", False):
                raise PermissionError("stage recovery is not safe to retry")
            if recovery.get("previous_process_running", False):
                raise PermissionError("provider process state is still uncertain")
        attempts = dict(record.get("stage_attempt_counts", {}))
        count = int(attempts.get(target.value, 1)) + 1
        attempts[target.value] = count
        stage_attempt_id = f"{run_id}:{target.value}:{count}"
        prior_attempt = record.get("active_stage_attempt_id")
        sequence = int(record["sequence"]) + 1
        history = list(record.get("history", []))
        history.append(
            {
                "sequence": sequence,
                "from": previous.value,
                "to": target.value,
                "retry": True,
                "stage_attempt_id": stage_attempt_id,
            }
        )
        retry_history = list(record.get("retry_history", []))
        retry_history.append(
            {
                "stage": target.value,
                "reason": reason,
                "authorizer": authorizer,
                "prior_attempt_id": prior_attempt,
                "stage_attempt_id": stage_attempt_id,
            }
        )
        record.update(
            {
                "stage": target.value,
                "sequence": sequence,
                "status": "running",
                "interrupted_from": None,
                "stopped_from": None,
                "stage_attempt_counts": attempts,
                "active_stage_attempt_id": stage_attempt_id,
                "retry_history": retry_history,
            }
        )
        self.store.upsert("runs", run_id, record)
        return record

    def _record(self, run_id: str) -> dict[str, Any]:
        record = self.store.get("runs", run_id)
        if record is None:
            raise LookupError("run not found")
        try:
            RunStage(str(record["stage"]))
            int(record["sequence"])
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError("run state is corrupt") from error
        return record
