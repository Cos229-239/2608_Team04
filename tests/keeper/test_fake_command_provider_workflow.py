from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from tests.keeper.authority_testkit import provider_authority_kwargs

from keeper.app.service import KeeperApplication
from keeper.orchestrator import Keeper


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def fake_provider(path: Path, envelope: bool) -> None:
    prefix = '{"result":' if envelope else ""
    suffix = "}" if envelope else ""
    script = f"""@echo off
if "%~1"=="--version" echo controlled-provider 1.0& exit /b 0
set role=%KEEPER_PROVIDER_ROLE%
set /a count=0
if exist "%~dp0%role%.count" set /p count=<"%~dp0%role%.count"
set /a count+=1
>"%~dp0%role%.count" echo %count%
if exist "%~dp0fail-%role%.once" (
  del "%~dp0fail-%role%.once"
  exit /b 9
)
if exist "%~dp0slow-%role%.once" (
  del "%~dp0slow-%role%.once"
  ping.exe 127.0.0.1 -n 20 >nul
)
set schema=
if "{str(envelope).lower()}"=="true" set schema=%~2
if "{str(envelope).lower()}"=="false" (
  :args
  if "%~1"=="" goto output
  if "%~1"=="--output-schema" set schema=%~2& goto output
  shift
  goto args
)
:output
if not exist .keeper-workflow mkdir .keeper-workflow
if "%KEEPER_PROVIDER_ROLE%"=="post_repair_reviewer" (
  echo {prefix}{{"status":"completed","files_changed":[],"findings":[],"dispositions":[{{"finding_id":"FAKE-H-1","status":"resolved","justification":"controlled repair verified"}}]}}{suffix}
  exit /b 0
)
if "%KEEPER_PROVIDER_ROLE%"=="reviewer" (
  echo {prefix}{{"status":"completed","files_changed":[],"findings":[{{"finding_id":"FAKE-H-1","severity":"High","title":"controlled repair","description":"exercise repair"}}]}}{suffix}
  exit /b 0
)
if "%KEEPER_PROVIDER_ROLE%"=="repairer" (
  >.keeper-workflow\\result.txt echo repaired
  echo {prefix}{{"status":"completed","files_changed":[".keeper-workflow/result.txt"]}}{suffix}
  exit /b 0
)
>.keeper-workflow\\result.txt echo built
echo {prefix}{{"status":"completed","files_changed":[".keeper-workflow/result.txt"]}}{suffix}
"""
    path.write_text(script, encoding="ascii")


def test_controlled_command_adapters_complete_full_repair_workflow(
    tmp_path: Path,
) -> None:
    codex = tmp_path / "controlled-codex.cmd"
    claude = tmp_path / "controlled-claude.cmd"
    fake_provider(codex, False)
    fake_provider(claude, True)
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "keeper@example.invalid")
    git(repo, "config", "user.name", "Keeper")
    (repo / "README.md").write_text("baseline\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "baseline")

    app = KeeperApplication(tmp_path / "data")
    app.save_provider_paths({"codex": str(codex), "claude": str(claude)})
    app.register_provider("codex", codex, "test-authority", **provider_authority_kwargs())
    app.register_provider("claude", claude, "test-authority", **provider_authority_kwargs("claude"))
    app.qualify_provider("codex", "test-authority")
    app.qualify_provider("claude", "test-authority")
    project = app.add_project(repo)
    task = app.create_task(
        {
            "title": "Controlled command workflow",
            "objective": "Exercise command adapters without credentials",
            "baseline": project["head"],
            "target_branch": "keeper/controlled",
            "included_paths": [".keeper-workflow/"],
            "provider_policy": "automatic",
            "is_demo": True,
        }
    )
    run = app.execute_task(str(task["id"]))
    assert run["status"] == "COMPLETED", run
    providers = {item["provider"] for item in run["routing_decisions"]}
    assert providers == {"codex-command", "claude-command"}
    assert "repair_execution" in [item["to"] for item in run["history"]]
    logs = list(Path(str(run["evidence_root"])).glob(".ai-workflow/runs/*/*"))
    assert any(path.name == "run.json" for path in logs)


@pytest.mark.parametrize(
    ("failed_role", "failed_stage", "unchanged_roles"),
    [
        ("builder", "author_execution", ()),
        ("reviewer", "independent_audit", ("builder",)),
        ("repairer", "repair_execution", ("builder", "reviewer")),
        (
            "post_repair_reviewer",
            "post_repair_verification",
            ("builder", "reviewer", "repairer"),
        ),
    ],
)
def test_selected_provider_stage_retry_does_not_repeat_verified_stages(
    tmp_path: Path,
    failed_role: str,
    failed_stage: str,
    unchanged_roles: tuple[str, ...],
) -> None:
    codex = tmp_path / "controlled-codex.cmd"
    claude = tmp_path / "controlled-claude.cmd"
    fake_provider(codex, False)
    fake_provider(claude, True)
    (tmp_path / f"fail-{failed_role}.once").write_text("", encoding="ascii")
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "keeper@example.invalid")
    git(repo, "config", "user.name", "Keeper")
    (repo / "README.md").write_text("baseline\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "baseline")
    app = KeeperApplication(tmp_path / "data")
    app.save_provider_paths({"codex": str(codex), "claude": str(claude)})
    app.register_provider("codex", codex, "test-authority", **provider_authority_kwargs())
    app.register_provider("claude", claude, "test-authority", **provider_authority_kwargs("claude"))
    app.qualify_provider("codex", "test-authority")
    app.qualify_provider("claude", "test-authority")
    project = app.add_project(repo)
    task = app.create_task(
        {
            "title": f"Retry {failed_role}",
            "objective": "Retry one selected provider stage",
            "baseline": project["head"],
            "target_branch": f"keeper/retry-{failed_role}",
            "included_paths": [".keeper-workflow/"],
            "provider_policy": "automatic",
            "is_demo": True,
        }
    )
    failed = app.execute_task(str(task["id"]))
    assert failed["status"] == "blocked", failed
    assert failed["stopped_from"] == failed_stage
    before = {
        role: int((tmp_path / f"{role}.count").read_text(encoding="ascii"))
        for role in unchanged_roles
    }

    retried = app.retry_run(
        str(failed["id"]),
        "authorized focused retry",
        failed_stage,
        "acceptance-operator",
    )
    assert retried["id"] == failed["id"]
    completed = app.wait_for_run(str(failed["id"]), 30)
    assert completed["status"] == "COMPLETED", completed
    for role, count in before.items():
        assert int(
            (tmp_path / f"{role}.count").read_text(encoding="ascii")
        ) == count
    history = completed["retry_history"][-1]
    assert history["stage"] == failed_stage
    assert history["authorizer"] == "acceptance-operator"
    assert history["stage_attempt_id"] != history["prior_attempt_id"]


@pytest.mark.parametrize(
    ("verification_name", "failed_stage", "prior_roles"),
    [
        ("self", "author_self_verification", ("builder",)),
        (
            "final",
            "final_validation",
            ("builder", "reviewer", "repairer", "post_repair_reviewer"),
        ),
    ],
)
def test_selected_verification_retry_does_not_repeat_provider_stages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    verification_name: str,
    failed_stage: str,
    prior_roles: tuple[str, ...],
) -> None:
    codex = tmp_path / "controlled-codex.cmd"
    claude = tmp_path / "controlled-claude.cmd"
    fake_provider(codex, False)
    fake_provider(claude, True)
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "keeper@example.invalid")
    git(repo, "config", "user.name", "Keeper")
    (repo / "README.md").write_text("baseline\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "baseline")
    original_verify = Keeper._verify
    failed_once = False

    def fail_selected_verification_once(
        self: Keeper,
        *args: object,
        **kwargs: object,
    ) -> tuple[bool, dict[str, object]]:
        nonlocal failed_once
        stage = str(args[3] if len(args) > 3 else kwargs["stage"])
        passed, evidence = original_verify(self, *args, **kwargs)  # type: ignore[arg-type]
        if stage == verification_name and not failed_once:
            failed_once = True
            evidence["passed"] = False
            return False, evidence
        return passed, evidence

    monkeypatch.setattr(Keeper, "_verify", fail_selected_verification_once)
    app = KeeperApplication(tmp_path / "data")
    app.save_provider_paths({"codex": str(codex), "claude": str(claude)})
    app.register_provider("codex", codex, "test-authority", **provider_authority_kwargs())
    app.register_provider("claude", claude, "test-authority", **provider_authority_kwargs("claude"))
    app.qualify_provider("codex", "test-authority")
    app.qualify_provider("claude", "test-authority")
    project = app.add_project(repo)
    task = app.create_task(
        {
            "title": f"Retry {verification_name} verification",
            "objective": "Retry only failed verification and downstream work",
            "baseline": project["head"],
            "target_branch": f"keeper/retry-{verification_name}",
            "included_paths": [".keeper-workflow/"],
            "provider_policy": "automatic",
            "is_demo": True,
        }
    )
    failed = app.execute_task(str(task["id"]))
    assert failed["stopped_from"] == failed_stage
    before = {
        role: int((tmp_path / f"{role}.count").read_text(encoding="ascii"))
        for role in prior_roles
    }
    app.retry_run(
        str(failed["id"]),
        "verification environment recovered",
        failed_stage,
        "acceptance-operator",
    )
    completed = app.wait_for_run(str(failed["id"]), 30)
    assert completed["status"] == "COMPLETED", completed
    for role, count in before.items():
        assert int(
            (tmp_path / f"{role}.count").read_text(encoding="ascii")
        ) == count


@pytest.mark.parametrize("stop_mode", ["timeout", "cancellation"])
def test_author_stage_retry_after_timeout_or_cancellation(
    tmp_path: Path,
    stop_mode: str,
) -> None:
    codex = tmp_path / "controlled-codex.cmd"
    claude = tmp_path / "controlled-claude.cmd"
    fake_provider(codex, False)
    fake_provider(claude, True)
    (tmp_path / "slow-builder.once").write_text("", encoding="ascii")
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "keeper@example.invalid")
    git(repo, "config", "user.name", "Keeper")
    (repo / "README.md").write_text("baseline\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "baseline")
    app = KeeperApplication(tmp_path / "data")
    app.save_provider_paths({"codex": str(codex), "claude": str(claude)})
    app.register_provider("codex", codex, "test-authority", **provider_authority_kwargs())
    app.register_provider("claude", claude, "test-authority", **provider_authority_kwargs("claude"))
    app.qualify_provider("codex", "test-authority")
    app.qualify_provider("claude", "test-authority")
    project = app.add_project(repo)
    task = app.create_task(
        {
            "title": f"Retry after {stop_mode}",
            "objective": "Retry a stopped author stage",
            "baseline": project["head"],
            "target_branch": f"keeper/retry-{stop_mode}",
            "included_paths": [".keeper-workflow/"],
            "provider_policy": "automatic",
            "is_demo": True,
        }
    )
    task["timeout_seconds"] = 1 if stop_mode == "timeout" else 30
    app.store.upsert("tasks", str(task["id"]), task)
    if stop_mode == "timeout":
        failed = app.execute_task(str(task["id"]))
    else:
        started = app.start_task(str(task["id"]))
        deadline = time.monotonic() + 10
        while (
            time.monotonic() < deadline
            and not (tmp_path / "builder.count").exists()
        ):
            time.sleep(0.05)
        app.cancel_run(str(started["id"]))
        failed = app.wait_for_run(str(started["id"]), 10)
    assert failed["stopped_from"] == "author_execution"
    app.retry_run(
        str(failed["id"]),
        f"{stop_mode} cleared",
        "author_execution",
        "acceptance-operator",
    )
    completed = app.wait_for_run(str(failed["id"]), 30)
    assert completed["status"] == "COMPLETED", completed
