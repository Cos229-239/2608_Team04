import json
from pathlib import Path

import pytest

from keeper.policies import (
    enforce_path_scope,
    filtered_environment,
    require_unprotected,
    resolve_within,
    select_reasoning_level,
    validate_provider_assignment,
)
from keeper.recovery import atomic_write_json, load_json


def test_protected_action_is_blocked() -> None:
    with pytest.raises(PermissionError, match="explicit authorization"):
        require_unprotected("force_push")


def test_provider_assignment_policy() -> None:
    validate_provider_assignment("qwen3-coder:30b", "high", "large", "risk")
    with pytest.raises(PermissionError, match="disabled"):
        validate_provider_assignment("qwen2.5-coder:14b", "low", "small", "documentation")


def test_reasoning_level_policy() -> None:
    assert select_reasoning_level() == "medium"
    assert select_reasoning_level(important_file_count=6) == "high"
    assert select_reasoning_level(test_failure_count=2) == "high"
    assert select_reasoning_level(live_or_brokerage=True) == "extra-high"


def test_environment_filters_secrets() -> None:
    assert filtered_environment({"PATH": "ok", "API_KEY": "secret"}) == {"PATH": "ok"}


def test_path_scope_enforcement() -> None:
    enforce_path_scope(["keeper/cli.py"], ["keeper/"], ["backend/"])
    enforce_path_scope([".keeper-pilot/result.txt"], [".keeper-pilot/"], [])
    with pytest.raises(PermissionError, match="outside allowed"):
        enforce_path_scope(["README.md"], ["keeper/"], [])
    with pytest.raises(PermissionError, match="blocked"):
        enforce_path_scope(["backend/app.py"], ["backend/"], ["backend/"])


def test_path_traversal_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsafe"):
        resolve_within(tmp_path, "../outside")


def test_atomic_state_persistence(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    atomic_write_json(path, {"state": "safe"})
    assert load_json(path, {}) == {"state": "safe"}
    assert not list(tmp_path.glob("*.tmp"))
