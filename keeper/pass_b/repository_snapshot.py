from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    canonical_repository_path: str
    commit_hash: str
    tree_hash: str
    manifest_digest: str
    entries: tuple[dict[str, object], ...]
    total_size_bytes: int


def capture_repository_snapshot(repository_root: Path) -> RepositorySnapshot:
    root = repository_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("repository snapshot root must be a directory")
    top_level = _git(root, "rev-parse", "--show-toplevel").strip()
    if Path(top_level).resolve(strict=True) != root:
        raise PermissionError("repository snapshot root is not the Git top level")
    if _git_bytes(root, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
        raise PermissionError("repository snapshot requires a clean worktree")

    commit_hash = _object_id(_git(root, "rev-parse", "--verify", "HEAD").strip())
    tree_hash = _object_id(
        _git(root, "rev-parse", "--verify", f"{commit_hash}^{{tree}}").strip()
    )
    raw_entries = _git_bytes(
        root, "ls-tree", "-r", "-z", "--full-tree", commit_hash
    )
    entries: list[dict[str, object]] = []
    seen_paths: set[str] = set()
    total_size = 0
    for raw_entry in raw_entries.split(b"\0"):
        if not raw_entry:
            continue
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        fields = metadata.decode("ascii").split(" ")
        if not separator or len(fields) != 3:
            raise RuntimeError("Git tree entry is malformed")
        mode, object_type, object_id = fields
        object_id = _object_id(object_id)
        try:
            relative_path = raw_path.decode("utf-8")
        except UnicodeDecodeError as error:
            raise PermissionError("repository path is not valid UTF-8") from error
        parsed = PurePosixPath(relative_path)
        if (
            parsed.is_absolute()
            or not parsed.parts
            or any(part in {"", ".", ".."} for part in parsed.parts)
            or relative_path in seen_paths
        ):
            raise PermissionError("repository snapshot path is unsafe or duplicated")
        seen_paths.add(relative_path)
        content = _git_bytes(root, "cat-file", object_type, object_id)
        total_size += len(content)
        entries.append(
            {
                "path": relative_path,
                "mode": mode,
                "object_type": object_type,
                "object_id": object_id,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
            }
        )
    if not entries:
        raise PermissionError("repository snapshot cannot be empty")
    if _git_bytes(root, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
        raise PermissionError("repository changed during snapshot capture")
    final_commit = _object_id(
        _git(root, "rev-parse", "--verify", "HEAD").strip()
    )
    final_tree = _object_id(
        _git(root, "rev-parse", "--verify", f"{final_commit}^{{tree}}").strip()
    )
    if final_commit != commit_hash or final_tree != tree_hash:
        raise PermissionError("repository changed during snapshot capture")
    entries.sort(key=lambda item: str(item["path"]))
    manifest = tuple(entries)
    manifest_digest = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return RepositorySnapshot(
        canonical_repository_path=str(root),
        commit_hash=commit_hash,
        tree_hash=tree_hash,
        manifest_digest=manifest_digest,
        entries=manifest,
        total_size_bytes=total_size,
    )


def _object_id(value: str) -> str:
    normalized = value.casefold()
    if len(normalized) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise RuntimeError("Git object identity is malformed")
    return normalized


def _git(root: Path, *arguments: str) -> str:
    return _git_bytes(root, *arguments).decode("utf-8")


def _git_bytes(root: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ("git", "-C", str(root), *arguments),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PermissionError("repository snapshot Git inspection failed") from error
    if result.returncode != 0:
        raise PermissionError("repository snapshot Git inspection was rejected")
    return result.stdout
