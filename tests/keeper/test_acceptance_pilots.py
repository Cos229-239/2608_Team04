from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from keeper.app.reporting import verify_evidence
from keeper.app.service import KeeperApplication


def repository(root: Path) -> tuple[Path, str]:
    root.mkdir()
    for args in (
        ("init",),
        ("config", "user.email", "keeper@example.invalid"),
        ("config", "user.name", "Keeper"),
    ):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    (root / "README.md").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=root, check=True, capture_output=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    return root, head


def task(app: KeeperApplication, root: Path, scenario: str) -> str:
    repo, head = repository(root)
    project = app.add_project(repo)
    created = app.create_task(
        {
            "title": scenario,
            "objective": f"Acceptance pilot: {scenario}",
            "repository": project["repository"],
            "baseline": head,
            "target_branch": f"keeper/{scenario}",
            "included_paths": [".keeper-workflow/"],
            "is_demo": True,
            "provider_policy": "mock",
            "mock_scenario": scenario,
        }
    )
    return str(created["id"])


def test_success_repair_and_no_repair_pilots_preserve_evidence(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    repair = app.execute_task(task(app, tmp_path / "repair", "repair"))
    no_repair = app.execute_task(task(app, tmp_path / "clean", "no-repair"))
    for run in (repair, no_repair):
        assert run["status"] == "COMPLETED"
        root = Path(str(run["evidence_root"]))
        verify_evidence(root)
        assert app.evidence_path(str(run["id"]), "json").is_file()
        records = [
            item
            for item in app.store.list("verification_records")
            if item.get("run_id") == run["id"]
        ]
        assert records
        assert all(item["result"] == "passed" for item in records)
        assert all(Path(str(item["output_path"])).is_file() for item in records)
    assert "repair_execution" in [item["to"] for item in repair["history"]]
    assert "repair_execution" not in [item["to"] for item in no_repair["history"]]
    repair_report = json.loads(
        (Path(str(repair["evidence_root"])) / "final-report.json").read_text(
            encoding="utf-8"
        )
    )
    clean_report = json.loads(
        (Path(str(no_repair["evidence_root"])) / "final-report.json").read_text(
            encoding="utf-8"
        )
    )
    required = {
        "schema_version",
        "scope",
        "provider_policy",
        "provider_identities",
        "routing_rationale",
        "lifecycle_stages",
        "authorizations",
        "waivers",
        "commands",
        "verification_results",
        "findings",
        "dispositions",
        "repairs",
        "post_repair_findings",
        "approval_result",
        "commit_result",
        "push_result",
        "logs",
        "artifacts",
        "evidence_paths",
        "evidence_hashes",
        "unresolved_observations",
        "terminal_status",
    }
    assert required <= repair_report.keys()
    assert repair_report["findings"]
    assert repair_report["dispositions"]
    assert repair_report["repairs"]
    assert clean_report["findings"] == []
    assert clean_report["dispositions"] == []
    assert clean_report["repairs"] == []
    markdown = (
        Path(str(repair["evidence_root"])) / "final-report.md"
    ).read_text(encoding="utf-8")
    assert "```json\nnull\n```" not in markdown
    assert "## Dispositions" in markdown
    exported = app.export_run_report(str(repair["id"]), tmp_path / "exported")
    verify_evidence(exported)
    exported_report = json.loads(
        (exported / "final-report.json").read_text(encoding="utf-8")
    )
    assert exported_report == repair_report


def test_same_identity_reviewer_pilot_blocks_without_approval(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    run = app.execute_task(task(app, tmp_path / "repo", "blocked-reviewer"))
    assert run["stage"] == "blocked"
    assert run.get("outcome") != "approved"
    report_path = Path(str(run["evidence_root"])) / "final-report.json"
    assert report_path.exists()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["terminal_status"] == "BLOCKED"
    assert report["approval_result"] == {}


def test_history_filters_use_persisted_authoritative_fields(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    run = app.execute_task(task(app, tmp_path / "repo", "no-repair"))
    matches = app.filtered_runs(
        repository=str(run["repository"]),
        branch=str(run["branch"]),
        task_id=str(run["task_id"]),
        outcome="COMPLETED",
    )
    assert [item["id"] for item in matches] == [run["id"]]
    assert app.filtered_runs(repository="C:/not-this-repository") == []


def test_scoped_waiver_is_persisted_executed_and_reported(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    repo, head = repository(tmp_path / "repo")
    app.add_project(repo)
    waiver = {
        "waiver_id": "waiver-task",
        "category": "task",
        "task_id": "placeholder",
        "approving_authority": "Founder",
        "reason": "Acceptance waiver pilot",
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
    }
    created = app.create_task(
        {
            "title": "Waived verification",
            "objective": "Persist a scoped waiver",
            "baseline": head,
            "target_branch": "keeper/waiver",
            "included_paths": [".keeper-workflow/"],
            "verification_waivers": [waiver],
            "is_demo": True,
            "provider_policy": "mock",
            "mock_scenario": "no-repair",
        }
    )
    # Task identity is assigned during creation, so update the scoped record before execution.
    waiver["task_id"] = created["id"]
    created["verification_waivers"] = [waiver]
    app.store.upsert("tasks", str(created["id"]), created)
    app.store.upsert(
        "authorizations",
        "waiver-task",
        {
            **waiver,
            "id": "waiver-task",
            "capability": "verification_waiver",
            "run_id": None,
            "issued_at": datetime.now(UTC).isoformat(),
            "consumed_at": None,
            "revoked_at": None,
        },
    )
    run = app.execute_task(str(created["id"]))
    records = [
        item
        for item in app.store.list("verification_records")
        if item.get("run_id") == run["id"]
    ]
    assert run["status"] == "COMPLETED"
    assert records and all(item["result"] == "waived" for item in records)
    report = (Path(str(run["evidence_root"])) / "final-report.json").read_text(
        encoding="utf-8"
    )
    assert "waiver-task" in report
    assert json.loads(report)["waivers"][0]["id"] == "waiver-task"
