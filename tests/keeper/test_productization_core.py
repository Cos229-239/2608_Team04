from __future__ import annotations

import json
import hashlib
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from keeper.app.git_safety import GitSafetyService
from keeper.app.lifecycle import RunLifecycle, RunStage
from keeper.app.reporting import finalize_evidence, verify_evidence
from keeper.app.service import KeeperApplication
from keeper.app.storage import (
    ENTITY_TABLES,
    EXECUTIVE_LIFECYCLE_TABLES,
    SCHEMA_VERSION,
    KeeperStore,
)
from keeper.app.verification_policy import VerificationSpec, validate_semantic_bindings
from keeper.providers.adapters import (
    ProviderCapabilities,
    ProviderDiagnostic,
    RoutingRequest,
    route_provider,
)
from tests.keeper.executive.fixture_store import insert_executive_fixture


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _repository(root: Path) -> Path:
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.email", "keeper@example.invalid")
    _git(root, "config", "user.name", "Keeper Test")
    (root / "readme.txt").write_text("baseline\n", encoding="utf-8")
    _git(root, "add", "readme.txt")
    _git(root, "commit", "-m", "baseline")
    return root


def test_store_migrates_all_entities_and_detects_tampering(tmp_path: Path) -> None:
    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    for table in ENTITY_TABLES:
        payload: dict[str, object] = {"id": "one", "table": table}
        if table in EXECUTIVE_LIFECYCLE_TABLES:
            insert_executive_fixture(store, table, "one", payload)
        else:
            store.upsert(table, "one", payload)
        assert store.get(table, "one") == {"id": "one", "table": table}
    with store.connect() as connection:
        connection.execute("UPDATE tasks SET payload='{}' WHERE id='one'")
    with pytest.raises(RuntimeError, match="integrity"):
        store.get("tasks", "one")


def test_store_backup_export_and_legacy_import(tmp_path: Path) -> None:
    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    legacy = tmp_path / "legacy" / "runs" / "run-1"
    legacy.mkdir(parents=True)
    (legacy / "run.json").write_text('{"run_id":"run-1"}', encoding="utf-8")
    assert store.import_legacy_evidence(tmp_path / "legacy") == 1
    assert store.backup(tmp_path / "backup.db").is_file()
    exported = store.export_json(tmp_path / "export.json")
    assert (
        json.loads(exported.read_text(encoding="utf-8"))["schema_version"]
        == SCHEMA_VERSION
    )


def test_lifecycle_is_deterministic_idempotent_and_recoverable(tmp_path: Path) -> None:
    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    lifecycle = RunLifecycle(store)
    assert lifecycle.create("run", "task")["stage"] == "intake"
    first = lifecycle.transition("run", RunStage.SCOPE_VALIDATION)
    repeated = lifecycle.transition("run", RunStage.SCOPE_VALIDATION)
    assert first.sequence == repeated.sequence == 1
    lifecycle.transition("run", RunStage.INTERRUPTED)
    with pytest.raises(ValueError, match="recorded stage"):
        lifecycle.transition("run", RunStage.RISK_CLASSIFICATION)
    lifecycle.transition("run", RunStage.SCOPE_VALIDATION)
    lifecycle.transition("run", RunStage.RISK_CLASSIFICATION)


def test_lifecycle_rejects_skips_and_corrupt_state(tmp_path: Path) -> None:
    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    lifecycle = RunLifecycle(store)
    lifecycle.create("run", "task")
    with pytest.raises(ValueError, match="forbidden"):
        lifecycle.transition("run", RunStage.FINAL_VALIDATION)
    store.upsert("runs", "bad", {"stage": "invented", "sequence": 0})
    with pytest.raises(RuntimeError, match="corrupt"):
        lifecycle.transition("bad", RunStage.CANCELLED)


def test_semantic_binding_rejects_forgery_duplicates_and_missing() -> None:
    valid = VerificationSpec(
        "tests",
        ["{python}", "-m", "pytest", "-q"],
        "pytest",
        registration_id="keeper:tests:v1",
        expected_executable_sha256=hashlib.sha256(
            Path(sys.executable).resolve().read_bytes()
        ).hexdigest(),
    )
    validate_semantic_bindings([valid], ["tests"])
    with pytest.raises(ValueError, match="cannot satisfy"):
        validate_semantic_bindings(
            [VerificationSpec("typing", valid.arguments, "pytest")], ["typing"]
        )
    with pytest.raises(ValueError, match="more than once"):
        validate_semantic_bindings([valid, valid], ["tests"])
    with pytest.raises(ValueError, match="unsatisfied"):
        validate_semantic_bindings([valid], ["tests", "typing"])


def test_routing_enforces_independence_and_qwen_review() -> None:
    providers = [
        ProviderDiagnostic(
            "ollama",
            "Ollama",
            True,
            "ollama",
            "1",
            "tested",
            ProviderCapabilities(local_only=True),
        ),
        ProviderDiagnostic(
            "codex", "Codex", True, "codex", "1", "tested", ProviderCapabilities()
        ),
    ]
    decision = route_provider(
        RoutingRequest("reviewer", "high", "security", frozenset({"ollama"}), True),
        providers,
    )
    assert decision.provider_id == "codex"
    with pytest.raises(RuntimeError, match="independent"):
        route_provider(
            RoutingRequest(
                "reviewer", "high", "security", frozenset({"ollama", "codex"}), True
            ),
            providers,
        )


def test_git_safety_inspects_and_stages_only_allowlisted_text(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repo")
    (repository / "keeper").mkdir()
    (repository / "keeper" / "change.txt").write_text("safe\n", encoding="utf-8")
    service = GitSafetyService()
    inspection = service.inspect(repository)
    assert "keeper/change.txt" in [value.replace("\\", "/") for value in inspection.untracked]
    assert service.merge_base(repository, inspection.head) == inspection.head
    service.stage_allowlisted(repository, ["keeper/change.txt"], ["keeper/"], [])
    assert service.inspect(repository).staged
    with pytest.raises(PermissionError):
        service.stage_allowlisted(repository, ["readme.txt"], ["keeper/"], [])


def test_staging_rejects_exclusions_malformed_paths_and_existing_out_of_scope_index(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    (repository / "keeper" / "excluded").mkdir(parents=True)
    (repository / "keeper" / "allowed.txt").write_text("allowed\n", encoding="utf-8")
    (repository / "keeper" / "excluded" / "blocked.txt").write_text(
        "blocked\n", encoding="utf-8"
    )
    (repository / "outside.txt").write_text("outside\n", encoding="utf-8")
    service = GitSafetyService()
    with pytest.raises(PermissionError, match="blocked"):
        service.stage_allowlisted(
            repository,
            ["keeper/excluded/blocked.txt"],
            ["keeper/"],
            ["keeper/excluded/"],
        )
    for unsafe in ("C:\\outside.txt", "keeper/file.txt:stream", "../outside.txt"):
        with pytest.raises((PermissionError, ValueError)):
            service.stage_allowlisted(repository, [unsafe], ["keeper/"], [])
    _git(repository, "add", "outside.txt")
    with pytest.raises(PermissionError, match="outside allowed"):
        service.stage_allowlisted(
            repository,
            ["keeper/allowed.txt"],
            ["keeper/"],
            [],
        )


def test_git_commit_authorization_is_scoped_expiring_and_one_time(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    (repository / "readme.txt").write_text("changed\n", encoding="utf-8")
    _git(repository, "add", "readme.txt")
    authorization: dict[str, object] = {
        "id": "authorization-1",
        "capability": "commit",
        "repository": str(repository.resolve()),
        "task_id": "task-1",
        "run_id": "run-1",
        "worktree": str(repository.resolve()),
        "branch": _git(repository, "branch", "--show-current"),
        "head": _git(repository, "rev-parse", "HEAD"),
        "staged_paths": ["readme.txt"],
        "staged_digest": GitSafetyService().staged_digest(repository),
        "approving_authority": "founder",
        "issued_at": datetime.now(UTC).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "consumed_at": None,
        "revoked_at": None,
    }
    GitSafetyService().commit(
        repository,
        "test commit",
        authorization,
        task_id="task-1",
        run_id="run-1",
        worktree=repository,
        branch=str(authorization["branch"]),
    )
    assert authorization["consumed_at"] is not None
    with pytest.raises(PermissionError):
        GitSafetyService().commit(
            repository,
            "replay",
            authorization,
            task_id="task-1",
            run_id="run-1",
            worktree=repository,
            branch=str(authorization["branch"]),
        )


def test_report_is_valid_json_and_tamper_evident(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    finalize_evidence(root, {"status": "completed", "findings": []})
    assert json.loads((root / "final-report.json").read_text(encoding="utf-8"))["status"] == "completed"
    verify_evidence(root)
    (root / "final-report.md").write_text("tampered", encoding="utf-8")
    with pytest.raises(RuntimeError, match="tampering"):
        verify_evidence(root)


def test_application_first_run_project_task_and_mock_workflow(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    diagnostics = app.diagnostics()
    assert any(item["provider_id"] == "mock" and item["available"] for item in diagnostics["providers"])
    app.finish_setup()
    repository = _repository(tmp_path / "repo")
    project = app.add_project(repository)
    task = app.create_task(
        {
            "title": "Safe change",
            "objective": "Exercise the application service",
            "baseline": project["head"],
            "target_branch": "test/task",
        }
    )
    assert app.setup_complete() and task["status"] == "INTAKE"
    result = app.run_mock_demo()
    assert result["status"] == "COMPLETED"
