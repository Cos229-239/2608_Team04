from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path
from typing import Any

from keeper.agent_runner import AgentRunner
from keeper.config import KeeperConfig
from keeper.models.task import Task
from keeper.orchestrator import Keeper
from keeper.providers.mock import MockProvider
from keeper.providers.routing import ProviderRouter
from keeper.workspace import WorkspaceManager


def run_mock_demonstration(data_root: Path) -> dict[str, Any]:
    invocation = f"demo-{uuid.uuid4().hex}"
    root = data_root / "demonstrations" / invocation
    repository = root / "repository"
    repository.mkdir(parents=True)
    _git(repository, "init")
    _git(repository, "config", "user.email", "keeper@example.invalid")
    _git(repository, "config", "user.name", "Keeper Demonstration")
    (repository / "README.md").write_text("Keeper demonstration\n", encoding="utf-8")
    _git(repository, "add", "README.md")
    _git(repository, "commit", "-m", "demonstration baseline")
    state = repository / ".ai-workflow"
    config = KeeperConfig(
        repository,
        state,
        root / "worktrees",
        (),
        provider_routes=(
            ("builder", "builder"),
            ("reviewer", "reviewer"),
            ("repairer", "repairer"),
            ("post_repair_reviewer", "post-reviewer"),
        ),
        process_timeout_seconds=30,
    )
    task = Task(
        f"demo-task-{uuid.uuid4().hex[:8]}",
        "Keeper deterministic demonstration",
        "Exercise author, verification, independent review, repair, and approval.",
        "demo",
        1,
        verification_commands=[
            ["keeper:file-equals", ".keeper-demo/result.txt", "built\n"]
        ],
        final_verification_commands=[
            ["keeper:file-equals", ".keeper-demo/result.txt", "repaired\n"]
        ],
        allowed_paths=[".keeper-demo/"],
        capabilities=["repository_write", "run_verification"],
    )
    builder = MockProvider(
        provider_name="mock-builder",
        output={"status": "completed", "files_changed": [".keeper-demo/result.txt"]},
        file_writes={".keeper-demo/result.txt": "built\n"},
    )
    reviewer = MockProvider(
        provider_name="mock-reviewer",
        output={
            "status": "completed",
            "files_changed": [],
            "findings": [
                {
                    "finding_id": "DEMO-H-1",
                    "severity": "High",
                    "title": "Demonstration repair",
                    "description": "Exercise the required repair path.",
                }
            ],
        },
    )
    repairer = MockProvider(
        provider_name="mock-repairer",
        output={"status": "completed", "files_changed": [".keeper-demo/result.txt"]},
        file_writes={".keeper-demo/result.txt": "repaired\n"},
    )
    post_reviewer = MockProvider(
        provider_name="mock-post-reviewer",
        output={
            "status": "completed",
            "files_changed": [],
            "findings": [],
            "dispositions": [
                {
                    "finding_id": "DEMO-H-1",
                    "status": "resolved",
                    "justification": "The repaired deterministic content was independently verified.",
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
    keeper = Keeper(
        config,
        AgentRunner(builder, state / "runs", 30),
        WorkspaceManager(repository, config.workspace_root, state / "ownership"),
        router,
    )
    result = keeper.run_task(task)
    summary = {
        "schema_version": 1,
        "invocation_id": invocation,
        "task_id": result.id,
        "status": result.status.value,
        "attempts": result.attempts,
        "branch": result.branch_name,
        "workspace": result.workspace_path,
        "transitions": result.transition_history,
        "providers": {
            "builder": builder.instance_id,
            "reviewer": reviewer.instance_id,
            "repairer": repairer.instance_id,
            "post_reviewer": post_reviewer.instance_id,
        },
        "evidence_root": str(state),
        "mock_providers": True,
    }
    (root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _git(repository: Path, *arguments: str) -> None:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        capture_output=True,
        text=True,
        shell=False,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "unable to prepare mock repository")
