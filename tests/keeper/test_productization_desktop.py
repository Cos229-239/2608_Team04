from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from keeper.app.service import KeeperApplication
from keeper.desktop import KeeperViewModel, main, parser


def _repo(root: Path) -> Path:
    root.mkdir()
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "keeper@example.invalid"], cwd=root, check=True
    )
    subprocess.run(["git", "config", "user.name", "Keeper"], cwd=root, check=True)
    (root / "file.txt").write_text("one\n", encoding="utf-8")
    subprocess.run(["git", "add", "file.txt"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=root, check=True, capture_output=True)
    return root


def test_view_model_first_run_project_task_authorization_and_demo(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    model = KeeperViewModel(app)
    assert not app.setup_complete()
    assert any(item["provider_id"] == "mock" for item in model.diagnostics()["providers"])
    model.complete_setup(str(tmp_path / "evidence"))
    project = model.add_project(str(_repo(tmp_path / "repo")))
    task = model.create_task(
        {
            "title": "Desktop task",
            "objective": "Test display-independent workflows",
            "baseline": project["head"],
            "target_branch": "test/desktop",
        }
    )
    assert task["provider_policy"] == "automatic"
    run = model.run_demo()
    assert run["status"] == "COMPLETED"
    routing = model.evidence_details(str(run["id"]), "routing")
    assert routing["details"]["provider_identities"]
    logs = model.evidence_details(str(run["id"]), "logs")
    assert logs["details"]
    hashes = model.evidence_details(str(run["id"]), "hashes")
    assert any(
        str(item["path"]).endswith("stdout.log")
        for item in hashes["details"]
    )


def test_view_model_revokes_active_waiver_without_rewriting_history(
    tmp_path: Path,
) -> None:
    app = KeeperApplication(tmp_path / "data")
    model = KeeperViewModel(app)
    project = model.add_project(str(_repo(tmp_path / "repo")))
    waiver = {
        "waiver_id": "waiver-visible",
        "category": "task",
        "task_id": "placeholder",
        "approving_authority": "release-owner",
        "reason": "controlled unavailable check",
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "scope": {"repository": project["repository"]},
    }
    task = model.create_task(
        {
            "title": "Waiver control",
            "objective": "Exercise visible waiver revocation",
            "baseline": project["head"],
            "target_branch": "keeper/waiver-control",
            "verification_waivers": [waiver],
        }
    )
    waiver["task_id"] = task["id"]
    task["verification_waivers"] = [waiver]
    app.store.upsert("tasks", str(task["id"]), task)
    app.store.upsert(
        "authorizations",
        "waiver-visible",
        {
            **waiver,
            "id": "waiver-visible",
            "capability": "verification_waiver",
            "issued_at": datetime.now(UTC).isoformat(),
            "consumed_at": None,
            "revoked_at": None,
        },
    )
    model.revoke_waiver("waiver-visible")
    revoked = app.store.get("authorizations", "waiver-visible")
    assert revoked is not None and revoked["revoked_at"] is not None
    updated = app.store.get("tasks", str(task["id"]))
    assert updated is not None
    assert updated["verification_waivers"][0]["revoked_at"] is not None
    with pytest.raises(PermissionError, match="active waiver"):
        model.revoke_waiver("waiver-visible")


def test_headless_diagnostics_entrypoint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert parser().parse_args(["--diagnostics"]).diagnostics
    assert main(["--data-dir", str(tmp_path / "data"), "--diagnostics"]) == 0
    assert '"local_only": true' in capsys.readouterr().out
