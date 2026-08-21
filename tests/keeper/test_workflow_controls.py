from __future__ import annotations

import subprocess
import time
from pathlib import Path

from keeper.app.service import KeeperApplication
from keeper.desktop import FirstRunController, KeeperViewModel


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


def manual_task(app: KeeperApplication, root: Path) -> str:
    repo, head = repository(root)
    app.add_project(repo)
    task = app.create_task(
        {
            "title": "Manual approval",
            "objective": "Exercise workflow controls",
            "baseline": head,
            "target_branch": "keeper/manual",
            "included_paths": [".keeper-workflow/"],
            "requires_manual_approval": True,
            "is_demo": True,
            "provider_policy": "mock",
            "mock_scenario": "no-repair",
        }
    )
    return str(task["id"])


def await_status(app: KeeperApplication, run_id: str, status: str) -> dict[str, object]:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        run = app.run_status(run_id)
        if run.get("status") == status:
            return run
        time.sleep(0.05)
    raise AssertionError(f"run never reached {status}: {app.run_status(run_id)}")


def test_manual_approval_control_completes_authoritative_run(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    run = app.start_task(manual_task(app, tmp_path / "repo"))
    run_id = str(run["id"])
    await_status(app, run_id, "awaiting_approval")
    app.approve_run(run_id, "Founder")
    completed = app.wait_for_run(run_id, 20)
    assert completed["status"] == "COMPLETED"
    assert completed["approval"]["decision"] == "approved"
    assert app.evidence_path(run_id, "markdown").is_file()


def test_pause_resume_then_reject_and_cancel_controls(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    run_id = str(app.start_task(manual_task(app, tmp_path / "repo"))["id"])
    await_status(app, run_id, "awaiting_approval")
    app.pause_run(run_id)
    assert app.run_status(run_id)["stage"] == "interrupted"
    app.resume_run(run_id)
    app.reject_run(run_id, "Founder", "Acceptance rejection")
    rejected = app.wait_for_run(run_id, 20)
    assert rejected["status"] == "REJECTED"

    second = str(app.start_task(manual_task(app, tmp_path / "repo-2"))["id"])
    await_status(app, second, "awaiting_approval")
    app.cancel_run(second)
    cancelled = app.wait_for_run(second, 20)
    assert cancelled["stage"] == "cancelled"


def test_first_run_controller_navigation_validation_and_persistence(
    tmp_path: Path,
) -> None:
    app = KeeperApplication(tmp_path / "data")
    controller = FirstRunController(app)
    assert controller.step == "boundaries"
    assert controller.back() == "boundaries"
    for expected in controller.STEPS[1:]:
        assert controller.next() == expected
    controller.evidence_directory = str(tmp_path / "evidence")
    controller.provider_policy = "automatic"
    controller.finish()
    assert app.setup_complete()
    assert app.store.get("settings", "routing") == {
        "default_provider_policy": "automatic"
    }


def test_view_model_exposes_real_controls(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    model = KeeperViewModel(app)
    run_id = str(model.start_task(manual_task(app, tmp_path / "repo"))["id"])
    await_status(app, run_id, "awaiting_approval")
    model.approve(run_id, "Founder")
    assert app.wait_for_run(run_id, 20)["status"] == "COMPLETED"
