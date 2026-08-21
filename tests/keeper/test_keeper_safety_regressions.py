from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import time
from pathlib import Path

import pytest

from keeper.models.task import Task
from keeper.models.finding import Finding, Severity
from keeper.config import KeeperConfig
from keeper.agent_runner import AgentRunner
from keeper.orchestrator import Keeper
from keeper.providers.mock import MockProvider
from keeper.recovery import atomic_write_json
from keeper.state_machine import TaskStatus
from keeper.policies import validate_capabilities
from keeper.provider_output import validate_provider_output
from keeper.reviewer import validate_post_repair_review
from keeper.providers.base import AgentRequest
from keeper.providers.codex_cli import CliProvider
from keeper.verifier import VerificationCommand, Verifier
from keeper.workspace import WorkspaceManager


def git(path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments], cwd=path, check=True, capture_output=True, text=True
    )


def repository(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "keeper@example.invalid")
    git(repo, "config", "user.name", "Keeper Test")
    (repo / "tracked.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-m", "fixture")
    return repo


def test_task_rejects_empty_required_categories() -> None:
    value = Task("id", "title", "description", "phase", 1).to_dict()
    value["required_verification_categories"] = []
    with pytest.raises(ValueError, match="categories"):
        Task.from_dict(value)


def test_verifier_rejects_empty_and_missing_tool(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least one"):
        Verifier().run(tmp_path, [])
    with pytest.raises(PermissionError, match="immutable registration"):
        Verifier().run(
            tmp_path, [VerificationCommand(["keeper-tool-that-does-not-exist"])]
        )


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "{",
        "prefix {}",
        '{"status":"unknown","files_changed":[]}',
        '{"status":"completed","files_changed":[],"error":"failed"}',
        '{"status":"completed"}',
    ],
)
def test_invalid_builder_output_fails_closed(raw: str) -> None:
    with pytest.raises(ValueError):
        validate_provider_output("builder", raw, 1024)


def test_oversized_provider_output_fails_closed() -> None:
    raw = json.dumps(
        {"status": "completed", "files_changed": [], "padding": "x" * 100}
    )
    with pytest.raises(ValueError, match="size"):
        validate_provider_output("builder", raw, 32)


def test_valid_role_specific_outputs() -> None:
    assert validate_provider_output(
        "builder", '{"status":"completed","files_changed":[]}', 1024
    )["status"] == "completed"
    assert validate_provider_output(
        "post_repair_reviewer",
        json.dumps(
            {
                "status": "completed",
                "files_changed": [],
                "findings": [],
                "dispositions": [
                    {
                        "finding_id": "H-1",
                        "status": "resolved",
                        "justification": "verified",
                    }
                ],
            }
        ),
        4096,
    )["dispositions"]


def test_protected_capability_requires_exact_scoped_authorization(
    tmp_path: Path,
) -> None:
    repo = tmp_path.resolve()
    authorization: dict[str, object] = {
        "capability": "deploy_production",
        "task_id": "task",
        "attempt_id": "attempt",
        "repository": str(repo),
        "approving_authority": "owner",
        "expires_at": "2999-01-01T00:00:00+00:00",
        "consumed_at": None,
    }
    with pytest.raises(PermissionError):
        validate_capabilities(
            ["deploy_production"],
            task_id="task",
            attempt_id="attempt",
            repository=repo,
            authorizations=[],
            now="2026-01-01T00:00:00+00:00",
        )
    assert validate_capabilities(
        ["deploy_production"],
        task_id="task",
        attempt_id="attempt",
        repository=repo,
        authorizations=[authorization],
        now="2026-01-01T00:00:00+00:00",
    ) == [authorization]
    for field, value in (
        ("task_id", "other"),
        ("attempt_id", "other"),
        ("repository", str(repo / "other")),
        ("expires_at", "2020-01-01T00:00:00+00:00"),
    ):
        invalid: dict[str, object] = dict(authorization)
        invalid[field] = value
        with pytest.raises(PermissionError):
            validate_capabilities(
                ["deploy_production"],
                task_id="task",
                attempt_id="attempt",
                repository=repo,
                authorizations=[invalid],
                now="2026-01-01T00:00:00+00:00",
            )


@pytest.mark.parametrize(
    "expires_at",
    [
        "zzzz",
        "2999-01-01T00:00:00",
        "2025-12-31T23:59:59Z",
        "2026-01-01T01:00:00+01:00",
    ],
)
def test_authorization_rejects_malformed_naive_and_expired_timestamps(
    tmp_path: Path, expires_at: str
) -> None:
    authorization: dict[str, object] = {
        "capability": "deploy_production",
        "task_id": "task",
        "attempt_id": "attempt",
        "repository": str(tmp_path.resolve()),
        "approving_authority": "owner",
        "expires_at": expires_at,
        "consumed_at": None,
    }
    with pytest.raises(PermissionError):
        validate_capabilities(
            ["deploy_production"],
            task_id="task",
            attempt_id="attempt",
            repository=tmp_path,
            authorizations=[authorization],
            now="2026-01-01T00:00:00Z",
        )


def test_authorization_accepts_timezone_equivalent_future_boundary(
    tmp_path: Path,
) -> None:
    authorization: dict[str, object] = {
        "capability": "deploy_production",
        "task_id": "task",
        "attempt_id": "attempt",
        "repository": str(tmp_path.resolve()),
        "approving_authority": "owner",
        "expires_at": "2025-12-31T20:00:01-05:00",
        "consumed_at": None,
    }
    assert validate_capabilities(
        ["deploy_production"],
        task_id="task",
        attempt_id="attempt",
        repository=tmp_path,
        authorizations=[authorization],
        now="2026-01-01T01:00:00Z",
    )


def test_post_repair_review_rejects_new_blocker_and_duplicate_dispositions() -> None:
    original = [Finding("H-1", Severity.HIGH, "original", "fix")]
    base = {
        "findings": [],
        "dispositions": [
            {"finding_id": "H-1", "status": "resolved", "justification": "fixed"}
        ],
    }
    new_blocker = dict(base)
    new_blocker["findings"] = [
        {
            "finding_id": "H-2",
            "severity": "High",
            "title": "regression",
            "description": "new blocker",
        }
    ]
    with pytest.raises(ValueError, match="new blocking"):
        validate_post_repair_review(new_blocker, original)
    duplicate = dict(base)
    duplicate["dispositions"] = base["dispositions"] * 2
    with pytest.raises(ValueError, match="exactly once"):
        validate_post_repair_review(duplicate, original)


def test_retry_reuses_exact_owned_worktree_and_rejects_mismatch(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)
    manager = WorkspaceManager(
        repo, tmp_path / "worktrees", tmp_path / "ownership"
    )
    first = manager.create("task", "attempt-1")
    second = manager.create("task", "attempt-2")
    assert first == second
    record_path = tmp_path / "ownership" / "task.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["branch"] = "keeper/forged"
    record_path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(PermissionError, match="ownership"):
        manager.create("task", "attempt-3")


@pytest.mark.parametrize(
    ("status", "stage"),
    [
        (TaskStatus.BUILDING, "BUILDING"),
        (TaskStatus.SELF_VERIFYING, "SELF_VERIFYING"),
        (TaskStatus.INDEPENDENT_AUDIT, "REVIEWING"),
        (TaskStatus.REPAIRING, "REPAIRING"),
        (TaskStatus.FINAL_VERIFY, "FINAL_VERIFYING"),
    ],
)
def test_recovery_reconciles_every_interrupted_active_stage(
    tmp_path: Path, status: TaskStatus, stage: str
) -> None:
    repo = repository(tmp_path)
    state = repo / ".ai-workflow"
    task = Task(
        "task",
        "title",
        "description",
        "phase",
        1,
        status=status,
        verification_commands=[["keeper:file-equals", "tracked.txt", "safe\n"]],
        active_attempt_id="task-attempt-1",
        active_run_stage=stage,
    )
    atomic_write_json(state / "tasks" / "task.json", task.to_dict())
    atomic_write_json(
        state / "runs" / "run" / "run.json",
        {
            "run_id": "run",
            "task_id": "task",
            "status": "running",
            "process_id": 99999999,
        },
    )
    config = KeeperConfig(repo, state, tmp_path / "worktrees", ())
    keeper = Keeper(
        config,
        AgentRunner(MockProvider(), state / "runs", 5),
        WorkspaceManager(repo, config.workspace_root, state / "ownership"),
    )
    keeper.recover()
    recovered = Task.from_dict(
        json.loads((state / "tasks" / "task.json").read_text(encoding="utf-8"))
    )
    assert recovered.status is TaskStatus.FAILED
    assert recovered.active_run_stage == stage


def test_cleanup_refuses_unregistered_and_primary_worktrees(tmp_path: Path) -> None:
    repo = repository(tmp_path)
    root = tmp_path / "worktrees"
    manager = WorkspaceManager(repo, root, tmp_path / "ownership")
    unrelated = tmp_path / "unrelated"
    git(repo, "worktree", "add", "-b", "unrelated", str(unrelated))
    with pytest.raises(PermissionError, match="outside"):
        manager.cleanup(unrelated)
    with pytest.raises(PermissionError, match="primary"):
        manager.cleanup(repo)


def test_cleanup_valid_owned_worktree_and_repeated_request(tmp_path: Path) -> None:
    repo = repository(tmp_path)
    manager = WorkspaceManager(
        repo, tmp_path / "worktrees", tmp_path / "ownership"
    )
    workspace = manager.create("task", "attempt")
    manager.cleanup(workspace.path)
    assert not workspace.path.exists()
    with pytest.raises((FileNotFoundError, PermissionError)):
        manager.cleanup(workspace.path)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows process-tree regression")
def test_timeout_terminates_child_before_it_can_write(tmp_path: Path) -> None:
    marker = tmp_path / "late.txt"
    child_code = (
        "import time,pathlib;time.sleep(3);"
        f"pathlib.Path({str(marker)!r}).write_text('late')"
    )
    parent_code = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable,'-c',{child_code!r}]);time.sleep(30)"
    )
    executable = Path(sys.executable)
    provider = CliProvider(
        (sys.executable, "-c", parent_code, "{prompt}"),
        expected_executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        expected_executable_size=executable.stat().st_size,
        registration_id="python-timeout-test",
        registration_version="1",
        configuration_digest="c" * 64,
    )
    prompt = tmp_path / "prompt.md"
    prompt.write_text("safe", encoding="utf-8")
    result = provider.run(
        AgentRequest(
            "builder",
            prompt,
            tmp_path,
            1,
            tmp_path / "stdout.log",
            tmp_path / "stderr.log",
        )
    )
    assert result.timed_out
    time.sleep(2.5)
    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows process-tree regression")
def test_successful_parent_exit_terminates_delayed_child(tmp_path: Path) -> None:
    marker = tmp_path / "late-success.txt"
    child_code = (
        "import time,pathlib;time.sleep(2);"
        f"pathlib.Path({str(marker)!r}).write_text('late')"
    )
    parent_code = (
        "import subprocess,sys;"
        f"subprocess.Popen([sys.executable,'-c',{child_code!r}])"
    )
    executable = Path(sys.executable)
    provider = CliProvider(
        (sys.executable, "-c", parent_code, "{prompt}"),
        expected_executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        expected_executable_size=executable.stat().st_size,
        registration_id="python-success-test",
        registration_version="1",
        configuration_digest="c" * 64,
    )
    prompt = tmp_path / "prompt.md"
    prompt.write_text("safe", encoding="utf-8")
    result = provider.run(
        AgentRequest(
            "builder",
            prompt,
            tmp_path,
            5,
            tmp_path / "success-stdout.log",
            tmp_path / "success-stderr.log",
        )
    )
    assert result.exit_code == 0
    time.sleep(2.5)
    assert not marker.exists()
