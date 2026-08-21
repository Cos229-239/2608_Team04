from __future__ import annotations

import os
from pathlib import Path


WINDOWS_SAFE_PATH_BUDGET = 240


def windows_path_units(path: Path) -> int:
    return len(str(path).encode("utf-16-le")) // 2


def validate_path_budget(path: Path, *, purpose: str) -> Path:
    absolute = path.absolute()
    units = windows_path_units(absolute)
    if os.name == "nt" and units > WINDOWS_SAFE_PATH_BUDGET:
        raise ValueError(
            f"{purpose} exceeds Keeper's supported Windows path budget "
            f"({units} UTF-16 code units > {WINDOWS_SAFE_PATH_BUDGET}); "
            "choose a shorter Keeper data directory or repository path"
        )
    return absolute


def contained_path(root: Path, target: Path, *, purpose: str) -> Path:
    approved = root.resolve(strict=True)
    if target.is_symlink():
        raise PermissionError(f"{purpose} cannot be a symbolic link")
    resolved = target.resolve(strict=True)
    if not resolved.is_relative_to(approved):
        raise PermissionError(f"{purpose} escapes the approved root")
    return resolved
