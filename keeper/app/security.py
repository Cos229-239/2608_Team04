from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any


MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_SECRET = re.compile(
    r"(?i)\b(token|secret|password|api[_-]?key|authorization)"
    r"(\s*[:=]\s*|:\s*bearer\s+)([^\s,;]+)"
)


def redact_text(value: str, limit: int = MAX_LOG_BYTES) -> str:
    encoded = value.encode("utf-8", errors="replace")
    bounded = encoded[:limit].decode("utf-8", errors="replace")
    suffix = "\n[OUTPUT TRUNCATED]" if len(encoded) > limit else ""
    return _SECRET.sub(r"\1\2[REDACTED]", bounded) + suffix


def redact_structure(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): (
                "[REDACTED]"
                if any(marker in str(key).lower() for marker in ("token", "secret", "password", "key"))
                else redact_structure(item)
            )
            for key, item in value.items()
        }
    return value


def safe_repository_path(root: Path, relative: str, *, allow_symlink: bool = False) -> Path:
    candidate_name = PurePosixPath(relative.replace("\\", "/"))
    if candidate_name.is_absolute() or ".." in candidate_name.parts:
        raise PermissionError("path traversal is prohibited")
    root = root.resolve()
    candidate = root.joinpath(*candidate_name.parts)
    if candidate.is_symlink() and not allow_symlink:
        raise PermissionError("symbolic link access is prohibited")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise PermissionError("path escapes repository")
    return resolved


def validate_archive_member(name: str, size: int) -> None:
    if size < 0 or size > MAX_ARTIFACT_BYTES:
        raise ValueError("archive member exceeds safe size limit")
    normalized = PurePosixPath(name.replace("\\", "/"))
    if normalized.is_absolute() or ".." in normalized.parts:
        raise ValueError("unsafe archive member path")
