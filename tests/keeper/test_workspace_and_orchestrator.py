import subprocess
from pathlib import Path

from keeper.agent_runner import AgentRunner
from keeper.config import KeeperConfig
from keeper.orchestrator import Keeper
from keeper.providers.mock import MockProvider
from keeper.workspace import WorkspaceManager


def git(path: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True, text=True)


def repository(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "keeper@example.invalid")
    git(repo, "config", "user.name", "Keeper Test")
    (repo / "tracked.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-m", "test fixture")
    return repo


def test_dirty_worktree_detection(tmp_path: Path) -> None:
    repo = repository(tmp_path)
    manager = WorkspaceManager(repo, tmp_path / "worktrees")
    assert not manager.is_dirty()
    (repo / "tracked.txt").write_text("changed\n", encoding="utf-8")
    assert manager.is_dirty()


def test_deterministic_workspace_branch(tmp_path: Path) -> None:
    repo = repository(tmp_path)
    manager = WorkspaceManager(repo, tmp_path / "worktrees")
    workspace = manager.create("TASK 01")
    assert workspace.branch == "keeper/task-01"
    assert workspace.path.exists()


def test_recovery_marks_dead_run_interrupted(tmp_path: Path) -> None:
    repo = repository(tmp_path)
    state = repo / ".ai-workflow"
    run_dir = state / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        '{"run_id":"run-1","status":"running","process_id":99999999}',
        encoding="utf-8",
    )
    config = KeeperConfig(repo, state, tmp_path / "worktrees", ())
    provider = MockProvider()
    keeper = Keeper(config, AgentRunner(provider, state / "runs", 5), WorkspaceManager(repo, config.workspace_root))
    decisions = keeper.recover()
    assert decisions[0]["action"] == "mark_interrupted"
    assert '"interrupted"' in (run_dir / "run.json").read_text(encoding="utf-8")
