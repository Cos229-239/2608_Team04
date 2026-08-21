from __future__ import annotations

import subprocess
import hashlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from keeper.app.git_safety import GitSafetyService
from keeper.app.verification_policy import (
    VerificationSpec,
    VerificationWaiver,
    validate_semantic_bindings,
)


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def repository(root: Path) -> Path:
    root.mkdir()
    git(root, "init")
    git(root, "config", "user.email", "keeper@example.invalid")
    git(root, "config", "user.name", "Keeper")
    (root / "file.txt").write_text("baseline\n", encoding="utf-8")
    git(root, "add", "file.txt")
    git(root, "commit", "-m", "baseline")
    return root


def commit_authorization(root: Path) -> dict[str, object]:
    service = GitSafetyService()
    inspection = service.inspect(root)
    return {
        "id": "authorization-1",
        "capability": "commit",
        "repository": str(root.resolve()),
        "task_id": "task-1",
        "run_id": "run-1",
        "worktree": str(root.resolve()),
        "branch": inspection.branch,
        "head": inspection.head,
        "staged_paths": inspection.staged,
        "staged_digest": service.staged_digest(root),
        "approving_authority": "founder",
        "issued_at": datetime.now(UTC).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "consumed_at": None,
        "revoked_at": None,
    }


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("task_id", "wrong-task"),
        ("run_id", "wrong-run"),
        ("branch", "wrong-branch"),
        ("head", "0" * 40),
        ("staged_paths", ["wrong.txt"]),
        ("staged_digest", "0" * 64),
        ("worktree", "C:/wrong"),
    ],
)
def test_commit_rejects_every_scope_mismatch(
    tmp_path: Path, field: str, wrong: object
) -> None:
    root = repository(tmp_path / "repo")
    (root / "file.txt").write_text("changed\n", encoding="utf-8")
    git(root, "add", "file.txt")
    authorization = commit_authorization(root)
    authorization[field] = wrong
    with pytest.raises(PermissionError, match="mismatch"):
        GitSafetyService().commit(
            root,
            "commit",
            authorization,
            task_id="task-1",
            run_id="run-1",
            worktree=root,
            branch=git(root, "branch", "--show-current"),
        )


def test_commit_authorization_is_invalidated_by_same_path_content_change(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path / "repo")
    (root / "file.txt").write_text("first\n", encoding="utf-8")
    git(root, "add", "file.txt")
    authorization = commit_authorization(root)
    (root / "file.txt").write_text("second\n", encoding="utf-8")
    git(root, "add", "file.txt")
    with pytest.raises(PermissionError, match="staged_digest"):
        GitSafetyService().commit(
            root,
            "commit",
            authorization,
            task_id="task-1",
            run_id="run-1",
            worktree=root,
            branch=git(root, "branch", "--show-current"),
        )


def test_exact_push_to_local_bare_remote_succeeds_once(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    git(root, "remote", "add", "local", str(remote))
    branch = git(root, "branch", "--show-current")
    head = git(root, "rev-parse", "HEAD")
    authorization: dict[str, object] = {
        "id": "push-1",
        "capability": "push",
        "repository": str(root.resolve()),
        "task_id": "task-1",
        "run_id": "run-1",
        "worktree": str(root.resolve()),
        "branch": branch,
        "head": head,
        "remote": "local",
        "remote_url": str(remote),
        "source_ref": branch,
        "destination_ref": f"refs/heads/{branch}",
        "expected_commit": head,
        "force": False,
        "approving_authority": "founder",
        "issued_at": datetime.now(UTC).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "consumed_at": None,
        "revoked_at": None,
    }
    service = GitSafetyService()
    service.push(
        root,
        "local",
        branch,
        f"refs/heads/{branch}",
        authorization,
        task_id="task-1",
        run_id="run-1",
        worktree=root,
    )
    assert authorization["consumed_at"] is not None
    with pytest.raises(PermissionError):
        service.push(
            root,
            "local",
            branch,
            f"refs/heads/{branch}",
            authorization,
            task_id="task-1",
            run_id="run-1",
            worktree=root,
        )
    with pytest.raises(ValueError):
        service.push(
            root,
            "local",
            branch,
            f"+refs/heads/{branch}",
            {**authorization, "consumed_at": None},
            task_id="task-1",
            run_id="run-1",
            worktree=root,
        )


def test_verification_waiver_must_be_exact_current_and_unrevoked() -> None:
    spec = VerificationSpec(
        "tests",
        ["{python}", "-m", "pytest", "-q"],
        "pytest",
        waiver_id="waiver-1",
        registration_id="keeper:tests:v1",
        expected_executable_sha256=hashlib.sha256(
            Path(sys.executable).resolve().read_bytes()
        ).hexdigest(),
    )
    valid = VerificationWaiver(
        "waiver-1",
        "tests",
        "task-1",
        "founder",
        "temporarily unavailable platform",
        (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
    )
    validate_semantic_bindings([spec], ["tests"], [valid], "task-1")
    invalid = VerificationWaiver(
        valid.waiver_id,
        valid.category,
        "wrong",
        valid.approving_authority,
        valid.reason,
        valid.expires_at,
    )
    with pytest.raises(PermissionError):
        validate_semantic_bindings([spec], ["tests"], [invalid], "task-1")
    expired = VerificationWaiver(
        "waiver-1",
        "tests",
        "task-1",
        "founder",
        "reason",
        (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
    )
    with pytest.raises(PermissionError):
        validate_semantic_bindings([spec], ["tests"], [expired], "task-1")
