from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from keeper.models.task import now_iso
from keeper.recovery import atomic_write_json, load_json


@dataclass(frozen=True, slots=True)
class Workspace:
    path: Path
    branch: str


class WorkspaceManager:
    def __init__(self, repository: Path, workspace_root: Path, ownership_root: Path | None = None) -> None:
        self.repository = repository.resolve()
        self.workspace_root = workspace_root.resolve()
        self.ownership_root = (ownership_root or workspace_root.parent / "workspace-ownership").resolve()

    def _git(self, *arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={self.repository.as_posix()}",
                "-c",
                "core.longpaths=true",
                *arguments,
            ],
            cwd=cwd or self.repository,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def is_dirty(self, path: Path | None = None) -> bool:
        result = self._git("status", "--porcelain", cwd=path)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "unable to inspect working tree")
        return bool(result.stdout.strip())

    @staticmethod
    def branch_name(task_id: str) -> str:
        safe = re.sub(r"[^a-z0-9-]+", "-", task_id.lower()).strip("-")
        if not safe:
            raise ValueError("task ID cannot produce an empty branch name")
        return f"keeper/{safe}"

    def _ownership_path(self, task_id: str) -> Path:
        safe = self.branch_name(task_id).removeprefix("keeper/")
        return self.ownership_root / f"{safe}.json"

    def _registered_worktrees(self) -> dict[Path, str]:
        result = self._git("worktree", "list", "--porcelain")
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "unable to list worktrees")
        registered: dict[Path, str] = {}
        current: Path | None = None
        for line in result.stdout.splitlines():
            if line.startswith("worktree "):
                current = Path(line[9:]).resolve()
            elif current is not None and line.startswith("branch refs/heads/"):
                registered[current] = line.removeprefix("branch refs/heads/")
        return registered

    def ownership(self, task_id: str) -> dict[str, Any] | None:
        value = load_json(self._ownership_path(task_id), None)
        return value if isinstance(value, dict) else None

    def create(self, task_id: str, attempt_id: str = "legacy", base: str = "HEAD") -> Workspace:
        branch = self.branch_name(task_id)
        path = (self.workspace_root / branch.removeprefix("keeper/")).resolve()
        if not path.is_relative_to(self.workspace_root):
            raise ValueError("workspace path escapes configured Keeper workspace root")
        existing_ownership = self.ownership(task_id)
        if path.exists():
            if existing_ownership is None:
                raise FileExistsError(f"unowned workspace already exists: {path}")
            expected = {
                "repository": str(self.repository),
                "task_id": task_id,
                "branch": branch,
                "workspace_path": str(path),
            }
            if any(existing_ownership.get(key) != value for key, value in expected.items()):
                raise PermissionError("workspace ownership record does not match retry target")
            registered = self._registered_worktrees()
            if registered.get(path) != branch:
                raise PermissionError("registered worktree identity does not match ownership record")
            attempts = existing_ownership.setdefault("attempt_ids", [])
            if attempt_id not in attempts:
                attempts.append(attempt_id)
            existing_ownership["active_attempt_id"] = attempt_id
            atomic_write_json(self._ownership_path(task_id), existing_ownership)
            return Workspace(path, branch)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        if existing_ownership is not None:
            raise PermissionError("ownership record exists but its worktree is missing")
        existing = self._git("show-ref", "--verify", "--quiet", f"refs/heads/{branch}")
        arguments = (
            ("worktree", "add", str(path), branch)
            if existing.returncode == 0
            else ("worktree", "add", "-b", branch, str(path), base)
        )
        result = self._git(*arguments)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "unable to create worktree")
        workspace = Workspace(path, branch)
        atomic_write_json(
            self._ownership_path(task_id),
            {
                "repository": str(self.repository),
                "task_id": task_id,
                "attempt_ids": [attempt_id],
                "active_attempt_id": attempt_id,
                "branch": branch,
                "workspace_path": str(path),
                "created_at": now_iso(),
            },
        )
        return workspace

    def changed_files(self, workspace: Path) -> list[str]:
        result = self._git("status", "--porcelain", "--untracked-files=all", cwd=workspace)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "unable to list changed files")
        return [line[3:].replace("\\", "/") for line in result.stdout.splitlines() if len(line) > 3]

    def cleanup(self, workspace: Path) -> None:
        workspace = workspace.resolve()
        if workspace == self.repository:
            raise PermissionError("refusing to remove the primary repository worktree")
        if not workspace.is_relative_to(self.workspace_root):
            raise PermissionError("cleanup target is outside the Keeper workspace root")
        records = [
            value for path in self.ownership_root.glob("*.json")
            if isinstance((value := load_json(path, None)), dict)
            and value.get("workspace_path") == str(workspace)
        ]
        if len(records) != 1:
            raise PermissionError("cleanup target has no unique Keeper ownership record")
        record = records[0]
        if record.get("repository") != str(self.repository):
            raise PermissionError("cleanup ownership repository mismatch")
        registered = self._registered_worktrees()
        if registered.get(workspace) != record.get("branch"):
            raise PermissionError("cleanup worktree branch does not match ownership record")
        if not workspace.exists():
            raise FileNotFoundError(f"cleanup target does not exist: {workspace}")
        if self.is_dirty(workspace):
            raise RuntimeError("refusing to remove a dirty worktree")
        result = self._git("worktree", "remove", str(workspace))
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "unable to remove worktree")
