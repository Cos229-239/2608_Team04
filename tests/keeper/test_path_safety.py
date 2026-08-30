from __future__ import annotations

import os
from pathlib import Path

import pytest

from keeper.agent_runner import AgentRunner
from keeper.app.path_safety import (
    WINDOWS_SAFE_PATH_BUDGET,
    validate_path_budget,
    windows_path_units,
)
from keeper.app.service import KeeperApplication
from keeper.models.task import Task
from keeper.providers.base import AgentProvider, AgentRequest, ProcessResult


class NeverRunProvider(AgentProvider):
    provider_name = "never-run"

    def __init__(self) -> None:
        self.called = False

    def validate(self) -> None:
        self.called = True

    def run(self, request: AgentRequest) -> ProcessResult:
        self.called = True
        raise AssertionError("provider must not launch for an over-budget path")


@pytest.mark.skipif(os.name != "nt", reason="Windows path budget")
def test_supported_path_budget_boundary_and_early_over_budget_failure() -> None:
    prefix = "C:\\"
    boundary = Path(prefix + ("a" * (WINDOWS_SAFE_PATH_BUDGET - len(prefix))))
    assert len(str(validate_path_budget(boundary, purpose="boundary"))) == (
        WINDOWS_SAFE_PATH_BUDGET
    )
    too_long = Path(str(boundary) + "a")
    with pytest.raises(ValueError, match="supported Windows path budget"):
        validate_path_budget(too_long, purpose="over-budget")

    provider = NeverRunProvider()
    runner = AgentRunner(provider, Path("C:\\") / ("b" * 220), 1)
    with pytest.raises(ValueError, match="choose a shorter"):
        runner.run(
            Task("task-path", "path", "path", "test", 1),
            "post_repair_reviewer",
            Path("C:\\workspace"),
            "keeper/path",
            "prompt",
        )
    assert provider.called is False


@pytest.mark.skipif(os.name != "nt", reason="Windows path budget")
def test_windows_budget_counts_utf16_code_units() -> None:
    prefix = "C:\\"
    value = Path(
        prefix
        + ("a" * (WINDOWS_SAFE_PATH_BUDGET - len(prefix) - 1))
        + "\U0001f512"
    )
    assert len(str(value)) == WINDOWS_SAFE_PATH_BUDGET
    assert windows_path_units(value) == WINDOWS_SAFE_PATH_BUDGET + 1
    with pytest.raises(ValueError, match="UTF-16 code units"):
        validate_path_budget(value, purpose="Unicode boundary")


@pytest.mark.skipif(os.name != "nt", reason="Windows path budget")
def test_over_budget_demo_repository_fails_before_git_launch(tmp_path: Path) -> None:
    suffix = (
        "\\demonstrations\\demo-00000000000000000000000000000000"
        "\\repository\\.git\\objects\\00\\" + ("0" * 38)
    )
    base = str(tmp_path.resolve()) + "\\"
    target_length = WINDOWS_SAFE_PATH_BUDGET + 1 - len(suffix)
    if target_length <= len(base):
        pytest.skip("temporary test root is already beyond the target boundary")
    data = Path(base + ("d" * (target_length - len(base))))
    app = KeeperApplication(data)
    with pytest.raises(ValueError, match="demonstration repository path"):
        app.run_mock_demo()
    assert not (data / "demonstrations").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows path budget")
def test_filesystem_backed_near_limit_workflow_completes(
    tmp_path: Path,
) -> None:
    suffix = (
        "\\demonstrations\\demo-00000000000000000000000000000000"
        "\\repository\\.git\\objects\\00\\" + ("0" * 38)
    )
    base = str(tmp_path.resolve()) + "\\"
    target_data_units = 238 - len(suffix.encode("utf-16-le")) // 2
    filler = target_data_units - len(base.encode("utf-16-le")) // 2
    assert filler > 0, "test temporary root must leave a supported path budget"
    data = Path(base + ("n" * filler))
    assert windows_path_units(Path(str(data) + suffix)) == 238
    run = KeeperApplication(data).run_mock_demo()
    assert run["status"] == "COMPLETED"
    assert Path(str(run["report_json"])).is_file()


def test_child_report_symlink_escape_is_rejected(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    root = app.data_directory / "evidence" / "run-path"
    root.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    report = root / "final-report.json"
    try:
        report.symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are unavailable")
    app.store.upsert(
        "runs",
        "run-path",
        {
            "id": "run-path",
            "task_id": "task-path",
            "status": "COMPLETED",
            "evidence_root": str(root),
        },
    )
    with pytest.raises(PermissionError, match="symbolic link"):
        app.evidence_path("run-path", "json")


def test_authority_exchange_evidence_requires_the_exact_run_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = KeeperApplication(tmp_path / "data")
    exchange = tmp_path / "client-exchange"
    evidence = exchange / "evidence" / "run-authority"
    evidence.mkdir(parents=True)
    monkeypatch.setattr(
        app.authority,
        "diagnostics",
        lambda: {"client_exchange_root": str(exchange.resolve())},
    )
    app.store.upsert(
        "runs",
        "run-authority",
        {
            "id": "run-authority",
            "task_id": "task-authority",
            "status": "COMPLETED",
            "authority_execution_root": str(exchange.resolve()),
            "evidence_root": str(evidence.resolve()),
        },
    )

    assert app.evidence_details("run-authority", "logs")["details"] == []

    tampered = app.store.get("runs", "run-authority")
    assert tampered is not None
    sibling = exchange / "evidence" / "other-run"
    sibling.mkdir()
    tampered["evidence_root"] = str(sibling.resolve())
    app.store.upsert("runs", "run-authority", tampered)
    with pytest.raises(PermissionError, match="outside Keeper storage"):
        app.evidence_details("run-authority", "logs")

    redirected = app.store.get("runs", "run-authority")
    assert redirected is not None
    redirected["id"] = "other-run"
    redirected["evidence_root"] = str(sibling.resolve())
    app.store.upsert("runs", "run-authority", redirected)
    with pytest.raises(PermissionError, match="durable key"):
        app.evidence_details("run-authority", "logs")


def test_evidence_path_rejects_symlinked_ancestors(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    outside = tmp_path / "outside"
    (outside / "run-linked").mkdir(parents=True)
    evidence_parent = app.data_directory / "evidence"
    try:
        evidence_parent.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symbolic links are unavailable")
    app.store.upsert(
        "runs",
        "run-linked",
        {
            "id": "run-linked",
            "task_id": "task-linked",
            "status": "COMPLETED",
            "evidence_root": str(evidence_parent / "run-linked"),
        },
    )

    with pytest.raises(PermissionError, match="reparse point"):
        app.evidence_details("run-linked", "logs")


def test_run_status_rejects_outside_evidence_before_reading_logs(
    tmp_path: Path,
) -> None:
    app = KeeperApplication(tmp_path / "data")
    outside = tmp_path / "outside-run"
    log = outside / ".ai-workflow" / "runs" / "provider-run" / "stdout.log"
    log.parent.mkdir(parents=True)
    log.write_text("OUTSIDE_SECRET", encoding="utf-8")
    app.store.upsert(
        "runs",
        "run-outside",
        {
            "id": "run-outside",
            "task_id": "task-outside",
            "status": "COMPLETED",
            "evidence_root": str(outside.resolve()),
        },
    )

    with pytest.raises(PermissionError, match="outside Keeper storage"):
        app.run_status("run-outside")


def test_run_status_rejects_a_symlinked_child_log(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    root = app.data_directory / "evidence" / "run-child-link"
    log = root / ".ai-workflow" / "runs" / "provider-run" / "stdout.log"
    log.parent.mkdir(parents=True)
    outside = tmp_path / "outside-secret.log"
    outside.write_text("OUTSIDE_SECRET", encoding="utf-8")
    try:
        log.symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are unavailable")
    app.store.upsert(
        "runs",
        "run-child-link",
        {
            "id": "run-child-link",
            "task_id": "task-child-link",
            "status": "COMPLETED",
            "evidence_root": str(root.resolve()),
        },
    )

    with pytest.raises(PermissionError, match="reparse point"):
        app.run_status("run-child-link")
