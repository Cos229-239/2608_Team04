from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
from pathlib import Path

from keeper.policies import enforce_path_scope


FORBIDDEN_GIT_ACTIONS = frozenset(
    {"merge", "rebase", "reset", "stash", "clean", "push-force", "branch-delete", "worktree-remove"}
)


@dataclass(frozen=True, slots=True)
class RepositoryInspection:
    root: str
    branch: str
    head: str
    dirty: bool
    detached: bool
    staged: list[str]
    unstaged: list[str]
    untracked: list[str]
    conflicts: list[str]
    worktrees: list[dict[str, str]]


class GitSafetyService:
    def inspect(self, repository: Path) -> RepositoryInspection:
        root = repository.resolve()
        head = self._git(root, "rev-parse", "HEAD").stdout.strip()
        branch_result = self._git(root, "branch", "--show-current")
        branch = branch_result.stdout.strip()
        status = self._git(root, "status", "--porcelain=v1", "--untracked-files=all")
        staged = self._lines(self._git(root, "diff", "--cached", "--name-only").stdout)
        unstaged = self._lines(self._git(root, "diff", "--name-only").stdout)
        untracked = self._lines(
            self._git(root, "ls-files", "--others", "--exclude-standard").stdout
        )
        conflicts = self._lines(
            self._git(root, "diff", "--name-only", "--diff-filter=U").stdout
        )
        worktrees = self._parse_worktrees(
            self._git(root, "worktree", "list", "--porcelain").stdout
        )
        return RepositoryInspection(
            str(root),
            branch,
            head,
            bool(status.stdout.strip()),
            not bool(branch),
            staged,
            unstaged,
            untracked,
            conflicts,
            worktrees,
        )

    def merge_base(self, repository: Path, baseline: str) -> str:
        self.validate_baseline(repository, baseline)
        return self._git(repository.resolve(), "merge-base", "HEAD", baseline).stdout.strip()

    def validate_baseline(self, repository: Path, baseline: str) -> None:
        if not baseline or self._git(
            repository.resolve(), "cat-file", "-e", f"{baseline}^{{commit}}", check=False
        ).returncode:
            raise ValueError("approved baseline commit does not exist")

    def stage_allowlisted(
        self, repository: Path, paths: list[str], allowed: list[str], blocked: list[str]
    ) -> None:
        if not paths:
            raise ValueError("no paths were authorized for staging")
        enforce_path_scope(paths, allowed, blocked)
        root = repository.resolve()
        for relative in paths:
            candidate = root / relative
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root):
                raise PermissionError("staging path escapes repository")
            if candidate.is_symlink():
                raise PermissionError("Keeper does not stage symbolic links")
        self._git(repository.resolve(), "add", "--", *paths)
        conflicts = self._git(
            repository.resolve(), "diff", "--cached", "--name-only", "--diff-filter=U"
        ).stdout
        if conflicts.strip():
            raise RuntimeError("staged changes contain unresolved conflicts")
        binary = self._git(
            root, "diff", "--cached", "--numstat", "--", *paths
        ).stdout.splitlines()
        if any(line.startswith("-\t-\t") for line in binary):
            raise PermissionError("unexpected binary addition requires separate authorization")
        inspection = self.inspect(root)
        enforce_path_scope(inspection.staged, allowed, blocked)
        if sorted(inspection.staged) != sorted(paths):
            raise PermissionError(
                "resulting staged path set differs from the authorized changes"
            )

    def staged_digest(self, worktree: Path) -> str:
        patch = self._git(
            worktree.resolve(), "diff", "--cached", "--binary", "--full-index"
        ).stdout.encode("utf-8")
        return hashlib.sha256(patch).hexdigest()

    def commit(
        self,
        repository: Path,
        message: str,
        authorization: dict[str, object],
        *,
        task_id: str,
        run_id: str,
        worktree: Path,
        branch: str,
    ) -> str:
        inspection = self.inspect(worktree)
        self._require_registered_worktree(repository, worktree, branch)
        context: dict[str, object] = {
            "task_id": task_id,
            "run_id": run_id,
            "worktree": str(worktree.resolve()),
            "branch": branch,
            "head": inspection.head,
            "staged_paths": sorted(inspection.staged),
            "staged_digest": self.staged_digest(worktree),
        }
        self._require_authorization("commit", repository, authorization, context)
        if inspection.root != str(worktree.resolve()) or inspection.branch != branch:
            raise PermissionError("commit worktree or branch identity changed")
        if not message.strip():
            raise ValueError("commit message cannot be empty")
        result = self._git(worktree.resolve(), "commit", "-m", message)
        authorization["consumed_at"] = datetime.now(UTC).isoformat()
        return result.stdout.strip()

    def push(
        self,
        repository: Path,
        remote: str,
        source_ref: str,
        destination_ref: str,
        authorization: dict[str, object],
        *,
        task_id: str,
        run_id: str,
        worktree: Path,
    ) -> str:
        if (
            not remote
            or not source_ref
            or not destination_ref
            or any(value.startswith("-") for value in (remote, source_ref, destination_ref))
            or any(marker in source_ref or marker in destination_ref for marker in ("+", ":"))
        ):
            raise ValueError("push target is invalid")
        inspection = self.inspect(worktree)
        self._require_registered_worktree(repository, worktree, inspection.branch)
        remote_url = self._git(
            worktree.resolve(), "remote", "get-url", remote
        ).stdout.strip()
        context: dict[str, object] = {
            "task_id": task_id,
            "run_id": run_id,
            "worktree": str(worktree.resolve()),
            "branch": inspection.branch,
            "head": inspection.head,
            "remote": remote,
            "remote_url": remote_url,
            "source_ref": source_ref,
            "destination_ref": destination_ref,
            "expected_commit": inspection.head,
            "force": False,
        }
        self._require_authorization("push", repository, authorization, context)
        result = self._git(
            worktree.resolve(),
            "push",
            "--",
            remote,
            f"{source_ref}:{destination_ref}",
        )
        authorization["consumed_at"] = datetime.now(UTC).isoformat()
        return result.stderr.strip() or result.stdout.strip()

    def remote_url(self, worktree: Path, remote: str) -> str:
        if not remote or remote.startswith("-"):
            raise ValueError("remote name is invalid")
        return self._git(
            worktree.resolve(), "remote", "get-url", remote
        ).stdout.strip()

    @staticmethod
    def reject_action(action: str) -> None:
        if action in FORBIDDEN_GIT_ACTIONS:
            raise PermissionError(f"Keeper never performs prohibited Git action: {action}")

    def _git(
        self, repository: Path, *arguments: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={repository.as_posix()}", *arguments],
            cwd=repository,
            capture_output=True,
            text=True,
            shell=False,
            timeout=60,
            check=False,
        )
        if check and result.returncode:
            raise RuntimeError(result.stderr.strip() or "Git operation failed")
        return result

    @staticmethod
    def _parse_worktrees(value: str) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for line in [*value.splitlines(), ""]:
            if not line:
                if current:
                    entries.append(current)
                    current = {}
            elif " " in line:
                key, content = line.split(" ", 1)
                current[key] = content
        return entries

    @staticmethod
    def _lines(value: str) -> list[str]:
        return [line for line in value.splitlines() if line]

    @staticmethod
    def _require_authorization(
        capability: str,
        repository: Path,
        authorization: dict[str, object],
        context: dict[str, object] | None = None,
    ) -> None:
        expires_at = authorization.get("expires_at")
        issued_at = authorization.get("issued_at")
        try:
            expires = datetime.fromisoformat(str(expires_at))
            issued = datetime.fromisoformat(str(issued_at))
        except (TypeError, ValueError) as error:
            raise PermissionError("authorization timestamps are malformed") from error
        if (
            expires.tzinfo is None
            or expires.utcoffset() is None
            or issued.tzinfo is None
            or issued.utcoffset() is None
        ):
            raise PermissionError("authorization timestamps must be timezone-aware")
        now = datetime.now(UTC)
        if (
            not authorization.get("id")
            or
            authorization.get("capability") != capability
            or authorization.get("repository") != str(repository.resolve())
            or authorization.get("consumed_at") is not None
            or authorization.get("revoked_at") is not None
            or not authorization.get("approving_authority")
            or authorization.get("reusable") not in {None, False}
            or issued > now
            or expires <= now
        ):
            raise PermissionError(f"explicit scoped {capability} authorization is required")
        for key, actual in (context or {}).items():
            expected = authorization.get(key)
            if key == "staged_paths":
                expected = sorted(str(item) for item in expected) if isinstance(expected, list) else expected
            if expected != actual:
                raise PermissionError(f"authorization scope mismatch: {key}")

    def _require_registered_worktree(
        self, repository: Path, worktree: Path, branch: str
    ) -> None:
        repository_root = repository.resolve()
        worktree_root = worktree.resolve()
        if worktree_root == repository_root:
            return
        registered = self._parse_worktrees(
            self._git(
                repository_root, "worktree", "list", "--porcelain"
            ).stdout
        )
        expected_ref = f"refs/heads/{branch}"
        if not any(
            Path(item.get("worktree", "")).resolve() == worktree_root
            and item.get("branch") == expected_ref
            for item in registered
        ):
            raise PermissionError("worktree is not registered to the authorized repository")
