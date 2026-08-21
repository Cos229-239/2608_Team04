from __future__ import annotations

import json
import hashlib
import subprocess
import threading
import time
from pathlib import Path

from keeper.app.service import KeeperApplication
from keeper.app.lifecycle import RunStage
from keeper.app.reporting import finalize_evidence, verify_evidence
from keeper.providers.base import AgentRequest, ProcessResult
from keeper.providers.codex_cli import CliProvider
from keeper.recovery import process_exists


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def test_running_command_tree_is_discovered_logged_and_terminated_on_restart(
    tmp_path: Path,
) -> None:
    slow = tmp_path / "slow-provider.cmd"
    child_pid_path = tmp_path / "child.pid"
    slow.write_text(
        "@echo off\n"
        "if \"%~1\"==\"--version\" echo slow-provider 1.0& exit /b 0\n"
        "echo token=super-secret provider-started\n"
        "ping.exe 127.0.0.1 -n 2 >nul\n"
        "echo provider-progress\n"
        "start \"\" /b powershell.exe -NoProfile -NonInteractive -Command "
        f"\"$PID | Set-Content -LiteralPath '{child_pid_path}'; "
        "Start-Sleep -Seconds 60\"\n"
        "ping.exe 127.0.0.1 -n 60 >nul\n",
        encoding="ascii",
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "keeper@example.invalid")
    git(repo, "config", "user.name", "Keeper")
    (repo / "README.md").write_text("baseline\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "baseline")
    data = tmp_path / "data"
    first = KeeperApplication(data)
    run_id = "run-real-interruption"
    evidence = data / "evidence" / run_id
    provider_directory = evidence / ".ai-workflow" / "runs" / "provider-active"
    provider_directory.mkdir(parents=True)
    stdout = provider_directory / "stdout.log"
    stderr = provider_directory / "stderr.log"
    prompt = provider_directory / "prompt.md"
    prompt.write_text("controlled interruption", encoding="utf-8")
    first.lifecycle.create(run_id, "task-interrupted")
    for stage in (
        RunStage.SCOPE_VALIDATION,
        RunStage.RISK_CLASSIFICATION,
        RunStage.AUTHORIZATION_RESOLUTION,
        RunStage.PROVIDER_SELECTION,
        RunStage.WORKTREE_PREPARATION,
        RunStage.AUTHOR_EXECUTION,
    ):
        first.lifecycle.transition(run_id, stage)
    record = first.store.get("runs", run_id)
    assert record is not None
    record.update(
        {
            "status": "running",
            "evidence_root": str(evidence),
            "provider": "controlled-command",
        }
    )
    first.store.upsert("runs", run_id, record)
    provider_record = provider_directory / "run.json"
    started = threading.Event()
    process_ids: list[int] = []
    ownership_records: list[dict[str, object]] = []
    results: list[ProcessResult] = []

    def process_started(pid: int) -> None:
        process_ids.append(pid)
        current = first.store.get("runs", run_id)
        assert current is not None
        current["process_id"] = pid
        first.store.upsert("runs", run_id, current)
        provider_record.write_text(
            json.dumps(
                {
                    "run_id": "provider-active",
                    "status": "running",
                    "process_id": pid,
                    "stdout_log_path": str(stdout),
                    "stderr_log_path": str(stderr),
                }
            ),
            encoding="utf-8",
        )
        started.set()

    def process_owned(ownership: dict[str, object]) -> None:
        ownership_records.append(
            {
                **ownership,
                "keeper_run_id": run_id,
                "task_id": "task-interrupted",
                "provider_run_id": "provider-active",
                "provider_name": "controlled-command",
                "provider_instance_id": provider.instance_id,
                "stage_id": "BUILDING",
                "role": "builder",
                "evidence_path": str(provider_directory.resolve()),
            }
        )
        value = json.loads(provider_record.read_text(encoding="utf-8"))
        value["process_ownership"] = ownership_records[-1]
        provider_record.write_text(json.dumps(value), encoding="utf-8")
        first.store.insert_immutable(
            "artifacts",
            f"process-ownership:{run_id}:provider-active",
            {
                **ownership_records[-1],
                "id": f"process-ownership:{run_id}:provider-active",
                "kind": "process_ownership",
            },
        )

    provider = CliProvider(
        (str(slow), "{prompt}"),
        "controlled-command",
        expected_executable_sha256=hashlib.sha256(
            Path(__import__("os").environ["COMSPEC"]).read_bytes()
        ).hexdigest(),
        expected_executable_size=Path(
            __import__("os").environ["COMSPEC"]
        ).stat().st_size,
        registration_id="controlled-command",
        registration_version="1",
        configuration_digest="c" * 64,
        expected_script_sha256=hashlib.sha256(slow.read_bytes()).hexdigest(),
        expected_script_size=slow.stat().st_size,
        script_registration_id="controlled-script",
        script_registration_version="1",
    )
    thread = threading.Thread(
        target=lambda: results.append(
            provider.run(
                AgentRequest(
                    "builder",
                    prompt,
                    repo,
                    60,
                    stdout,
                    stderr,
                    on_process_started=process_started,
                    on_process_owned=process_owned,
                )
            )
        ),
        daemon=True,
    )
    thread.start()
    assert started.wait(5)
    pid = process_ids[0]
    assert process_exists(pid)
    ownership_deadline = time.monotonic() + 5
    while time.monotonic() < ownership_deadline and not ownership_records:
        time.sleep(0.01)
    assert ownership_records
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and (
        not stdout.exists() or "provider-progress" not in stdout.read_text(encoding="utf-8")
    ):
        time.sleep(0.05)
    assert stdout.exists()
    live_output = stdout.read_text(encoding="utf-8")
    assert "provider-progress" in live_output
    assert "super-secret" not in live_output
    assert "[REDACTED]" in live_output
    child_pid: int | None = None
    while time.monotonic() < deadline and child_pid is None:
        try:
            child_pid = int(child_pid_path.read_text(encoding="utf-8").strip())
        except (FileNotFoundError, PermissionError, ValueError):
            time.sleep(0.05)
    assert child_pid is not None
    assert process_exists(child_pid)

    restarted = KeeperApplication(data)
    recovered = next(
        item for item in restarted.workflow.startup_recovery if item["id"] == run_id
    )
    recovery = recovered["recovery"]
    assert recovery["provider_process_id"] == pid
    assert recovery["attributable_tree_terminated"] is False
    assert recovery["identity_verified"] is True
    assert recovery["descendant_state"] == "ambiguous"
    assert recovery["classification"] == "uncertain"
    assert recovery["retry_safe"] is False
    assert process_exists(pid)
    assert process_exists(child_pid)
    provider.cancel()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert results and results[0].exit_code != 0
    assert not process_exists(pid)
    assert not process_exists(child_pid)
    status = restarted.run_status(run_id)
    assert "super-secret" not in status["latest_log"]
    assert len(status["latest_log"]) <= 20_000
    log_details = restarted.evidence_details(run_id, "logs")["details"]
    stdout_detail = next(
        item for item in log_details if str(item["path"]).endswith("stdout.log")
    )
    assert "provider-started" in stdout_detail["recent_output"]
    complete_digest = hashlib.sha256(stdout.read_bytes()).hexdigest()
    assert stdout_detail["sha256"] == complete_digest
    index = finalize_evidence(evidence, {"status": "interrupted"})
    indexed_stdout = next(
        item
        for item in index["files"]
        if str(item["path"]).endswith("stdout.log")
    )
    assert indexed_stdout["sha256"] == complete_digest
    verify_evidence(evidence)
