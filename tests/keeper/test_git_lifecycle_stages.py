from __future__ import annotations

import json
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from keeper.app.git_safety import GitSafetyService
from keeper.app.service import KeeperApplication
from keeper.app.workflow import _routing_decision
from keeper.desktop import KeeperViewModel
from keeper.providers.adapters import ProviderCapabilities, ProviderDiagnostic
from keeper.providers.base import AgentProvider
from keeper.providers.mock import MockProvider


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def wait(app: KeeperApplication, run_id: str, status: str) -> dict[str, object]:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        value = app.run_status(run_id)
        if value.get("status") == status:
            return value
        time.sleep(0.05)
    raise AssertionError(f"run did not reach {status}: {app.run_status(run_id)}")


def test_authorized_commit_and_push_are_lifecycle_stages(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "keeper@example.invalid")
    git(repo, "config", "user.name", "Keeper")
    (repo / "README.md").write_text("baseline\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "baseline")
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    git(repo, "remote", "add", "local", str(remote))

    app = KeeperApplication(tmp_path / "data")
    model = KeeperViewModel(app)
    project = app.add_project(repo)
    task = app.create_task(
        {
            "title": "Authorized lifecycle Git",
            "objective": "Commit and push only with exact authority",
            "baseline": project["head"],
            "target_branch": "keeper/git",
            "included_paths": [".keeper-workflow/"],
            "is_demo": True,
            "provider_policy": "mock",
            "mock_scenario": "no-repair",
            "requires_manual_approval": True,
            "commit_requested": True,
            "push_requested": True,
            "push_remote": "local",
        }
    )
    run_id = str(app.start_task(str(task["id"]))["id"])
    ready = wait(app, run_id, "awaiting_approval")
    worktree = Path(str(ready["worktree"]))
    inspection = GitSafetyService().inspect(worktree)
    commit_authorization = model.create_authorization(
        {
            "capability": "commit",
            "run_id": run_id,
            "approving_authority": "Founder",
            "minutes": 5,
        }
    )
    assert commit_authorization["staged_paths"] == inspection.staged
    app.approve_run(run_id, "Founder")
    pushed = wait(app, run_id, "awaiting_push_authorization")
    commit_hash = str(pushed["commit_hash"])
    push_authorization = model.create_authorization(
        {
            "capability": "push",
            "run_id": run_id,
            "approving_authority": "Founder",
            "minutes": 5,
        }
    )
    assert push_authorization["expected_commit"] == commit_hash
    assert push_authorization["remote_url"] == str(remote)
    completed = app.wait_for_run(run_id, 30)
    assert completed["status"] == "COMPLETED"
    transitions = [item["to"] for item in completed["history"]]
    assert "authorized_commit" in transitions
    assert "authorized_push" in transitions
    assert git(remote, "rev-parse", f"refs/heads/{inspection.branch}") == commit_hash
    report = json.loads(
        (
            Path(str(completed["evidence_root"])) / "final-report.json"
        ).read_text(encoding="utf-8")
    )
    assert {item["capability"] for item in report["authorizations"]} == {
        "commit",
        "push",
    }
    assert report["commit_result"]["commit_hash"] == commit_hash
    assert report["push_result"]["remote"] == "local"


def _normal_routes(
    changed_path: str,
) -> tuple[
    dict[str, AgentProvider],
    dict[str, str],
    list[dict[str, object]],
]:
    providers: dict[str, AgentProvider] = {
        "builder": MockProvider(
            provider_name="controlled-builder",
            output={"status": "completed", "files_changed": [changed_path]},
            file_writes={changed_path: "value = 1\n"},
        ),
        "reviewer": MockProvider(
            provider_name="controlled-reviewer",
            output={"status": "completed", "files_changed": [], "findings": []},
        ),
        "repairer": MockProvider(provider_name="controlled-repairer"),
        "post-reviewer": MockProvider(provider_name="controlled-post-reviewer"),
    }
    routes = {
        "builder": "builder",
        "reviewer": "reviewer",
        "repairer": "repairer",
        "post_repair_reviewer": "post-reviewer",
    }
    decisions: list[dict[str, object]] = []
    for role, key in routes.items():
        provider = providers[key]
        decisions.append(
            _routing_decision(
                role=role,
                provider_id=provider.provider_name,
                provider=provider,
                diagnostic=ProviderDiagnostic(
                    provider.provider_name,
                    provider.provider_name,
                    True,
                    None,
                    "built-in",
                    "verified",
                    ProviderCapabilities(local_only=True, streaming=False),
                    "Controlled test provider.",
                ),
                capability=role,
                independence=(
                    "independent-review"
                    if role in {"reviewer", "post_repair_reviewer"}
                    else "authoring"
                ),
                reasons=["controlled routing"],
                policy="automatic",
                configured_paths={},
            )
        )
    return providers, routes, decisions


@pytest.mark.parametrize(
    ("scope", "changed_path"),
    [
        ("keeper/", "keeper/allowed_change.py"),
        ("backend/", "backend/allowed_change.py"),
    ],
)
def test_normal_desktop_commit_stages_authoritative_selected_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    changed_path: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "keeper@example.invalid")
    git(repo, "config", "user.name", "Keeper")
    (repo / "test_validation.py").write_text(
        "def test_validation():\n    assert True\n", encoding="utf-8"
    )
    (repo / ".gitignore").write_text(
        ".pytest_cache/\n__pycache__/\n", encoding="utf-8"
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "baseline")
    app = KeeperApplication(tmp_path / "data")
    model = KeeperViewModel(app)
    project = app.add_project(repo)
    monkeypatch.setattr(
        "keeper.app.workflow._select_routes",
        lambda stored, configured: _normal_routes(changed_path),
    )
    task = app.create_task(
        {
            "title": f"Stage {scope}",
            "objective": "Stage the authoritative desktop scope",
            "baseline": project["head"],
            "target_branch": f"keeper/{scope.rstrip('/')}",
            "included_paths": [scope],
            "excluded_paths": [f"{scope}excluded/"],
            "required_validations": ["tests"],
            "provider_policy": "automatic",
            "requires_manual_approval": True,
            "commit_requested": True,
        }
    )
    run_id = str(app.start_task(str(task["id"]))["id"])
    ready = wait(app, run_id, "awaiting_approval")
    assert ready["staged_paths"] == [changed_path]
    authorization = model.create_authorization(
        {
            "capability": "commit",
            "run_id": run_id,
            "approving_authority": "Founder",
            "minutes": 5,
        }
    )
    assert authorization["staged_paths"] == [changed_path]
    assert authorization["staged_digest"] == ready["staged_digest"]
    app.approve_run(run_id, "Founder")
    completed = app.wait_for_run(run_id, 30)
    assert completed["status"] == "COMPLETED"
    worktree = Path(str(completed["worktree"]))
    assert git(worktree, "show", "--name-only", "--format=", "HEAD") == changed_path
