from __future__ import annotations

import subprocess
from pathlib import Path

from keeper.app.service import KeeperApplication


def repository(root: Path) -> tuple[Path, str]:
    root.mkdir()
    for arguments in (
        ("init",),
        ("config", "user.email", "keeper@example.invalid"),
        ("config", "user.name", "Keeper Test"),
    ):
        subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True)
    (root / "README.md").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
    subprocess.run(
        ["git", "commit", "-m", "baseline"], cwd=root, check=True, capture_output=True
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return root, head


def create_task(app: KeeperApplication, root: Path, scenario: str = "repair") -> str:
    repo, head = repository(root)
    app.add_project(repo)
    task = app.create_task(
        {
            "title": f"{scenario} workflow",
            "objective": "Exercise the unified workflow",
            "baseline": head,
            "target_branch": f"keeper/{scenario}",
            "included_paths": [".keeper-workflow/"],
            "is_demo": True,
            "provider_policy": "mock",
            "mock_scenario": scenario,
        }
    )
    return str(task["id"])


def test_desktop_task_uses_authoritative_repair_lifecycle(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    run = app.execute_task(create_task(app, tmp_path / "repo"))
    assert run["status"] == "COMPLETED"
    transitions = [item["to"] for item in run["history"]]
    assert transitions == [
        "scope_validation",
        "risk_classification",
        "authorization_resolution",
        "provider_selection",
        "worktree_preparation",
        "author_execution",
        "author_self_verification",
        "independent_audit",
        "repair_execution",
        "post_repair_verification",
        "independent_audit",
        "final_validation",
        "approval_decision",
        "evidence_finalization",
        "closed",
    ]
    assert Path(run["report_json"]).is_file()
    identities = {
        item["provider_instance_id"] for item in run["routing_decisions"]
    }
    assert len(identities) == 4


def test_no_repair_workflow_skips_only_the_repair_branch(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    run = app.execute_task(create_task(app, tmp_path / "repo", "no-repair"))
    transitions = [item["to"] for item in run["history"]]
    assert run["status"] == "COMPLETED"
    assert "repair_execution" not in transitions
    assert "post_repair_verification" not in transitions
    assert transitions[-3:] == ["approval_decision", "evidence_finalization", "closed"]
