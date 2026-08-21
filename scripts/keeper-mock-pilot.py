"""Run one isolated deterministic Keeper lifecycle and emit invocation-scoped evidence."""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from keeper.agent_runner import AgentRunner
from keeper.config import KeeperConfig
from keeper.models.task import Task, now_iso
from keeper.orchestrator import Keeper
from keeper.providers.base import AgentRequest, ProcessResult
from keeper.providers.mock import MockProvider
from keeper.providers.routing import ProviderRouter
from keeper.recovery import atomic_write_json
from keeper.state_machine import TaskStatus
from keeper.workspace import WorkspaceManager


class SequencedBuilder(MockProvider):
    def __init__(self) -> None:
        super().__init__(provider_name="mock-builder")
        self.calls = 0

    def run(self, request: AgentRequest) -> ProcessResult:
        self.calls += 1
        self.file_writes = {
            ".keeper-pilot/result.txt": "failed\n" if self.calls == 1 else "built\n"
        }
        self.output = {
            "status": "completed",
            "files_changed": [".keeper-pilot/result.txt"],
        }
        return super().run(request)


def main() -> int:
    invocation_id = f"mock-pilot-{uuid.uuid4().hex}"
    invocation_root = (
        REPOSITORY_ROOT / ".ai-workflow" / "pilot-invocations" / invocation_id
    )
    state_root = invocation_root / "state"
    workspace_root = REPOSITORY_ROOT / ".ai-workflow" / "pw" / invocation_id[-12:]
    task = Task(
        id=f"keeper-pilot-{uuid.uuid4().hex[:10]}",
        title="Invocation-scoped Keeper pilot",
        description="Exercise retry, review, repair, verification, recovery, and persistence.",
        phase="pilot",
        sequence=1,
        verification_commands=[
            ["keeper:file-equals", ".keeper-pilot/result.txt", "built\n"]
        ],
        final_verification_commands=[
            ["keeper:file-equals", ".keeper-pilot/result.txt", "repaired\n"]
        ],
        allowed_paths=[".keeper-pilot/"],
        capabilities=["repository_write", "run_verification"],
        maximum_attempts=2,
    )
    started_from = task.status.value
    task_path = state_root / "tasks" / f"{task.id}.json"
    atomic_write_json(task_path, task.to_dict())
    config = KeeperConfig(
        repository_root=REPOSITORY_ROOT.resolve(),
        state_root=state_root.resolve(),
        workspace_root=workspace_root.resolve(),
        provider_command=(),
        process_timeout_seconds=30,
        provider_routes=(
            ("builder", "builder"),
            ("reviewer", "reviewer"),
            ("repairer", "repairer"),
            ("post_repair_reviewer", "post-reviewer"),
        ),
    )
    builder = SequencedBuilder()
    reviewer = MockProvider(
        provider_name="mock-reviewer",
        output={
            "status": "completed",
            "files_changed": [],
            "findings": [
                {
                    "finding_id": "PILOT-H-1",
                    "severity": "High",
                    "title": "Pilot blocking fixture",
                    "description": "Require a repair and independent disposition.",
                    "file": ".keeper-pilot/result.txt",
                    "line": 1,
                },
                {
                    "finding_id": "PILOT-L-1",
                    "severity": "Low",
                    "title": "Pilot deferred fixture",
                    "description": "Demonstrate non-blocking cleanup registration.",
                    "file": ".keeper-pilot/result.txt",
                    "line": 1,
                },
            ],
        },
    )
    repairer = MockProvider(
        provider_name="mock-repairer",
        output={
            "status": "completed",
            "files_changed": [".keeper-pilot/result.txt"],
        },
        file_writes={".keeper-pilot/result.txt": "repaired\n"},
    )
    post_reviewer = MockProvider(
        provider_name="mock-post-reviewer",
        output={
            "status": "completed",
            "files_changed": [],
            "findings": [],
            "dispositions": [
                {
                    "finding_id": "PILOT-H-1",
                    "status": "resolved",
                    "justification": "Repaired content and diff were independently inspected.",
                }
            ],
        },
    )
    router = ProviderRouter(
        {
            "builder": builder,
            "reviewer": reviewer,
            "repairer": repairer,
            "post-reviewer": post_reviewer,
        },
        dict(config.provider_routes),
    )
    manager = WorkspaceManager(
        config.repository_root,
        config.workspace_root,
        state_root / "workspace-ownership",
    )
    keeper = Keeper(
        config,
        AgentRunner(builder, state_root / "runs", 30),
        manager,
        router,
    )
    first = keeper.run_task(task)
    if first.status is not TaskStatus.FAILED:
        raise RuntimeError("pilot first attempt did not exercise the required failure")
    second = keeper.run_task(first)

    recovery_task = Task(
        id=f"{task.id}-recovery",
        title="Recovery probe",
        description="Invocation-scoped interrupted run.",
        phase="pilot",
        sequence=2,
        status=TaskStatus.BUILDING,
        verification_commands=[["keeper:file-equals", "tracked.txt", "safe\n"]],
        active_attempt_id="recovery-attempt",
        active_run_stage="BUILDING",
    )
    atomic_write_json(
        state_root / "tasks" / f"{recovery_task.id}.json", recovery_task.to_dict()
    )
    atomic_write_json(
        state_root / "runs" / "recovery-probe" / "run.json",
        {
            "run_id": "recovery-probe",
            "task_id": recovery_task.id,
            "status": "running",
            "process_id": 99999999,
        },
    )
    recovery = keeper.recover()
    run_records = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((state_root / "runs").glob("*/run.json"))
        if path.parent.name != "recovery-probe"
    ]
    ownership = manager.ownership(task.id)
    evidence = {
        "pilot_invocation_id": invocation_id,
        "mock_providers": True,
        "task_id": task.id,
        "started_from": started_from,
        "final_status": second.status.value,
        "attempt_ids": (ownership or {}).get("attempt_ids", []),
        "run_ids": [record["run_id"] for record in run_records],
        "worktree_identity": ownership,
        "branch_identity": second.branch_name,
        "state_transitions": second.transition_history,
        "provider_context_identities": [
            {
                "role": record["role"],
                "provider_name": record["provider_name"],
                "provider_instance_id": record["provider_instance_id"],
            }
            for record in run_records
        ],
        "verification_evidence": [
            record["verification_result"]
            for record in run_records
            if record.get("verification_result")
        ],
        "high_finding": "PILOT-H-1",
        "repair_run_ids": [
            record["run_id"] for record in run_records if record["role"] == "repairer"
        ],
        "post_repair_review_run_ids": [
            record["run_id"]
            for record in run_records
            if record["role"] == "post_repair_reviewer"
        ],
        "bounded_retry": second.attempts == second.maximum_attempts == 2,
        "interruption_recovery": recovery,
        "cleanup_result": (
            "not performed: parent task explicitly prohibited worktree deletion; "
            "pilot worktree preserved"
        ),
        "recorded_at": now_iso(),
        "process_id": os.getpid(),
    }
    atomic_write_json(invocation_root / "mock-pilot-summary.json", evidence)
    print(json.dumps(evidence, indent=2))
    return 0 if second.status is TaskStatus.COMPLETED else 1


if __name__ == "__main__":
    raise SystemExit(main())
