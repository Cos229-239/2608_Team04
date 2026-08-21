from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from keeper.pass_b.enums import AssignmentState, ReservationMode
from keeper.pass_b.models import (
    AssignmentRecord,
    EvidenceBundleRecord,
    WorkspaceReservationRecord,
)
from keeper.pass_b.repository import (
    canonical_workspace_path,
    validate_protected_workspace_tree,
)


Runner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True, slots=True)
class WorkspacePolicy:
    implementation_root: Path
    prohibited_roots: tuple[Path, ...]
    prohibited_fragments: tuple[str, ...] = (".ai-workflow/pw",)

    def validate_target(self, target: Path) -> Path:
        try:
            resolved = validate_protected_workspace_tree(
                target, require_exists=os.path.lexists(target)
            )
        except PermissionError as error:
            raise PermissionError(
                "workspace target is in a protected scope"
            ) from error
        root = self.implementation_root.resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise PermissionError(
                "workspace must be inside the configured implementation root"
            ) from error
        for prohibited in self.prohibited_roots:
            protected = prohibited.resolve(strict=False)
            if _paths_overlap(resolved, protected):
                raise PermissionError("workspace target is in a protected scope")
        normalized_parts = tuple(item.casefold() for item in resolved.parts)
        for fragment in self.prohibited_fragments:
            fragment_parts = tuple(
                item.casefold()
                for item in fragment.replace("\\", "/").split("/")
                if item
            )
            if _contains_parts(normalized_parts, fragment_parts):
                raise PermissionError("workspace target is in a protected scope")
        return resolved


class GitWorktreeService:
    """Explicit worktree lifecycle; cleanup is never automatic."""

    def __init__(
        self,
        policy: WorkspacePolicy,
        *,
        runner: Runner = subprocess.run,
    ) -> None:
        self.policy = policy
        self.runner = runner

    def create_implementation_worktree(
        self,
        repository: Path,
        target: Path,
        branch: str,
        base_commit: str,
        assignment: AssignmentRecord,
    ) -> Path:
        if assignment.read_only:
            raise PermissionError("read-only reviewer cannot create writer worktree")
        destination = self.policy.validate_target(target)
        if destination.exists():
            raise FileExistsError("implementation worktree target already exists")
        repository_root = repository.resolve(strict=True)
        result = self.runner(
            [
                "git",
                "-c",
                f"safe.directory={repository_root.as_posix()}",
                "-C",
                str(repository_root),
                "worktree",
                "add",
                "-b",
                branch,
                str(destination),
                base_commit,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(
                f"isolated worktree creation failed: {result.stderr.strip()}"
            )
        return self.policy.validate_target(destination)

    def validate_reviewer_workspace(
        self,
        assignment: AssignmentRecord,
        reservation: WorkspaceReservationRecord,
    ) -> Path:
        if (
            assignment.read_only is not True
            or reservation.mode != ReservationMode.READ_ONLY
            or reservation.assignment_id != assignment.assignment_id
        ):
            raise PermissionError("review workspace is not read-only")
        path = self.policy.validate_target(Path(reservation.canonical_path))
        if canonical_workspace_path(path) != reservation.canonical_path:
            raise PermissionError("review workspace identity changed")
        if not (path / ".git").exists():
            raise PermissionError("review workspace is not a Git worktree")
        return path

    def cleanup_worktree(
        self,
        repository: Path,
        reservation: WorkspaceReservationRecord,
        assignment: AssignmentRecord,
        evidence: tuple[EvidenceBundleRecord, ...],
        *,
        explicitly_approved: bool,
    ) -> None:
        if not explicitly_approved:
            raise PermissionError("worktree cleanup requires explicit approval")
        if assignment.state in {
            AssignmentState.LAUNCH_CLAIMED,
            AssignmentState.RUNNING,
            AssignmentState.UNCERTAIN,
            AssignmentState.WAITING_FOR_USAGE_RESET,
        }:
            raise PermissionError("active or uncertain worktree cannot be removed")
        if not evidence:
            raise PermissionError("worktree evidence must be preserved first")
        target = self.policy.validate_target(Path(reservation.canonical_path))
        status = self.runner(
            [
                "git",
                "-c",
                f"safe.directory={target.as_posix()}",
                "-C",
                str(target),
                "status",
                "--porcelain",
                "--untracked-files=all",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if status.returncode or status.stdout.strip():
            raise PermissionError(
                "worktree with unresolved or untracked state cannot be removed"
            )
        repository_root = repository.resolve(strict=True)
        result = self.runner(
            [
                "git",
                "-c",
                f"safe.directory={repository_root.as_posix()}",
                "-C",
                str(repository_root),
                "worktree",
                "remove",
                str(target),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(
                f"explicit worktree cleanup failed: {result.stderr.strip()}"
            )


def workspace_identity(path: Path) -> str:
    import hashlib

    normalized = os.path.normcase(str(path.resolve()))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _contains_parts(
    parts: tuple[str, ...], fragment: tuple[str, ...]
) -> bool:
    return any(
        parts[index : index + len(fragment)] == fragment
        for index in range(max(0, len(parts) - len(fragment) + 1))
    )
