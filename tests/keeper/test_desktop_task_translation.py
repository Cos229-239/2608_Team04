from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from keeper.app.service import KeeperApplication
from keeper.app.workflow import _domain_task, _select_routes
from keeper.desktop import FirstRunController
from keeper.providers.adapters import ProviderCapabilities, ProviderDiagnostic


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repository(root: Path) -> tuple[Path, str]:
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.email", "keeper@example.invalid")
    _git(root, "config", "user.name", "Keeper")
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "src" / "one.py").write_text("value = 1\n", encoding="utf-8")
    (root / "tests" / "test_one.py").write_text(
        "def test_one():\n    assert True\n", encoding="utf-8"
    )
    _git(root, "add", ".")
    _git(root, "commit", "-m", "baseline")
    return root, _git(root, "rev-parse", "HEAD")


def _normal_values(head: str, included: str) -> dict[str, object]:
    return {
        "title": f"Task for {included}",
        "objective": "Preserve the requested scope",
        "baseline": head,
        "target_branch": "feature/scoped",
        "included_paths": [included],
        "excluded_paths": ["tests/fixtures/"],
        "required_validations": ["tests", "typing"],
        "completion_criteria": ["Requested tests pass", "No excluded paths change"],
        "provider_policy": "automatic",
    }


def test_desktop_tasks_preserve_distinct_scope_validations_and_completion(
    tmp_path: Path,
) -> None:
    repository, head = _repository(tmp_path / "repo")
    app = KeeperApplication(tmp_path / "data")
    app.add_project(repository)
    first = app.create_task(_normal_values(head, "src/"))
    second = app.create_task(_normal_values(head, "tests/"))
    first_domain = _domain_task(first, "run-one")
    second_domain = _domain_task(second, "run-two")
    assert first_domain.allowed_paths == ["src/"]
    assert second_domain.allowed_paths == ["tests/"]
    assert first_domain.blocked_paths == second_domain.blocked_paths == [
        "tests/fixtures/"
    ]
    assert first_domain.required_verification_categories == ["tests", "typing"]
    assert [item["category"] for item in first_domain.verification_specs] == [
        "tests",
        "typing",
    ]
    assert first_domain.acceptance_criteria == [
        "Requested tests pass",
        "No excluded paths change",
    ]
    assert all(
        ".keeper-workflow/result.txt" not in command
        for command in first_domain.verification_commands
    )


def test_task_scope_rejects_traversal_and_symlink_escape(tmp_path: Path) -> None:
    repository, head = _repository(tmp_path / "repo")
    app = KeeperApplication(tmp_path / "data")
    app.add_project(repository)
    with pytest.raises(PermissionError, match="traversal"):
        app.create_task(_normal_values(head, "../outside"))
    link = repository / "linked"
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable")
    with pytest.raises(PermissionError, match="symbolic"):
        app.create_task(_normal_values(head, "linked/"))


def test_desktop_rejects_caller_controlled_verification_specs(
    tmp_path: Path,
) -> None:
    repository, head = _repository(tmp_path / "repo")
    app = KeeperApplication(tmp_path / "data")
    app.add_project(repository)
    hostile = tmp_path / "zero.cmd"
    hostile.write_text("@exit /b 0\r\n", encoding="ascii")
    with pytest.raises(PermissionError, match="immutable registered"):
        app.create_task(
            {
                **_normal_values(head, "src/"),
                "verification_specs": [
                    {
                        "category": "task",
                        "validator": "registered-command",
                        "arguments": [str(hostile)],
                        "registration_id": "caller-controlled",
                    }
                ],
            }
        )


def test_first_run_default_and_task_override_are_applied(tmp_path: Path) -> None:
    repository, head = _repository(tmp_path / "repo")
    app = KeeperApplication(tmp_path / "data")
    app.add_project(repository)
    app.store.upsert(
        "settings", "routing", {"default_provider_policy": "local-only"}
    )
    controller = FirstRunController(app)
    assert controller.provider_policy == "local-only"
    defaulted = app.create_task({**_normal_values(head, "src/"), "provider_policy": ""})
    overridden = app.create_task(
        {**_normal_values(head, "tests/"), "provider_policy": "strongest"}
    )
    assert defaulted["provider_policy"] == "local-only"
    assert overridden["provider_policy"] == "strongest"


def test_mock_requires_explicit_demo_and_is_isolated(tmp_path: Path) -> None:
    repository, head = _repository(tmp_path / "repo")
    app = KeeperApplication(tmp_path / "data")
    app.add_project(repository)
    with pytest.raises(PermissionError, match="demonstration"):
        app.create_task(
            {**_normal_values(head, "src/"), "provider_policy": "mock"}
        )
    demo = app.create_task(
        {
            **_normal_values(head, ".keeper-workflow/"),
            "provider_policy": "mock",
            "is_demo": True,
            "required_validations": ["task"],
        }
    )
    domain = _domain_task(demo, "run-demo")
    assert domain.allowed_paths == [".keeper-workflow/"]
    assert domain.verification_commands == [
        ["keeper:file-equals", ".keeper-workflow/result.txt", "built\n"]
    ]


def test_unavailable_specific_provider_blocks_without_mock_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    diagnostics = [
        ProviderDiagnostic(
            "codex",
            "Codex",
            False,
            None,
            None,
            "unavailable",
            ProviderCapabilities(),
        ),
        ProviderDiagnostic(
            "mock",
            "Mock",
            True,
            None,
            "built-in",
            "verified",
            ProviderCapabilities(local_only=True),
        ),
    ]
    monkeypatch.setattr(
        "keeper.app.workflow.ProviderDiscovery.discover", lambda self: diagnostics
    )
    with pytest.raises(RuntimeError, match="no provider"):
        _select_routes(
            {
                "provider_policy": "codex",
                "risk": "low",
                "is_demo": False,
            },
            {},
        )
