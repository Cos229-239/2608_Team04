from __future__ import annotations

import ast
import sqlite3
from pathlib import Path

import pytest

from keeper.app.restore import prepare_test_restore_authorization
from keeper.app.storage import KeeperStore
from keeper.authority_service.client import TestAuthorityServiceClient
from keeper.authority_service.core import AuthorityServiceCore
from keeper.executive.founder_auth import TestFounderAuthenticator
from keeper.executive.models import utc_now
from tests.keeper.executive.fixture_store import insert_executive_fixture


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EXECUTIVE_ROOT = REPOSITORY_ROOT / "keeper" / "executive"


def _production_store(tmp_path: Path, name: str) -> KeeperStore:
    store = KeeperStore(tmp_path / f"{name}.db")
    store.migrate()
    store.bind_executive_repository_mode("PRODUCTION")
    return store


def _test_trust_boundaries(
    tmp_path: Path,
) -> tuple[TestFounderAuthenticator, TestAuthorityServiceClient]:
    founder = TestFounderAuthenticator()
    core = AuthorityServiceCore(tmp_path / "authority-service")
    authority = TestAuthorityServiceClient(
        lambda request: core.dispatch(request, "S-1-5-21-KEEPER-TEST")
    )
    return founder, authority


def _active_project(project_id: str) -> dict[str, object]:
    timestamp = utc_now()
    return {
        "project_id": project_id,
        "name": "Recovery fixture",
        "project_type": "software",
        "state": "ACTIVE",
        "active_charter_id": None,
        "active_charter_revision": None,
        "pause_reason": None,
        "created_at": timestamp,
        "updated_at": timestamp,
    }


def test_sqlite_is_the_only_live_executive_commit_boundary(
    tmp_path: Path,
) -> None:
    store = _production_store(tmp_path, "sqlite-authoritative")
    store.upsert("settings", "write", {"committed": True})

    assert store.get("settings", "write") == {"committed": True}
    assert store.executive_repository_binding()[4] == 0
    assert not (tmp_path / ".keeper-lineage").exists()


def test_backup_is_atomic_and_integrity_checked(tmp_path: Path) -> None:
    store = _production_store(tmp_path, "backup-source")
    store.upsert("settings", "backup-marker", {"value": 1})
    backup = store.backup(tmp_path / "backups" / "executive.db")

    assert backup.is_file()
    copied = KeeperStore(backup)
    copied.verify_integrity()
    assert copied.get("settings", "backup-marker") == {"value": 1}


def test_explicit_restore_pauses_projects_reconciles_and_advances_epoch(
    tmp_path: Path,
) -> None:
    store = _production_store(tmp_path, "restore-live")
    insert_executive_fixture(
        store,
        "executive_projects",
        "project-recovery",
        _active_project("project-recovery"),
    )
    backup = store.backup(tmp_path / "backup.db")
    store.upsert("settings", "post-backup", {"must_disappear": True})
    founder, authority = _test_trust_boundaries(tmp_path)
    authorization = prepare_test_restore_authorization(
        store.path,
        backup,
        reason="Founder requested recovery",
        authenticator=founder,
    )

    epoch = store.restore_backup_for_test(
        Path(authorization.request.backup_artifact_path),
        reason="Founder requested recovery",
        authorization=authorization,
        founder_authenticator=founder,
        authority=authority,
    )

    assert epoch == 1
    assert store.executive_repository_binding()[4] == 1
    assert store.get("settings", "post-backup") is None
    restored = store.get("executive_projects", "project-recovery")
    assert restored is not None
    assert restored["state"] == "PAUSED"


def test_failed_restore_reconciliation_leaves_live_state_unchanged(
    tmp_path: Path,
) -> None:
    store = _production_store(tmp_path, "restore-failure")
    store.upsert("settings", "state", {"generation": 1})
    backup = store.backup(tmp_path / "failure-backup.db")
    store.upsert("settings", "state", {"generation": 2})
    founder = TestFounderAuthenticator()
    authorization = prepare_test_restore_authorization(
        store.path, backup, reason="failure injection", authenticator=founder
    )
    no_op_authority = TestAuthorityServiceClient(lambda _request: {})

    with pytest.raises(PermissionError, match="Authority restore"):
        store.restore_backup_for_test(
            Path(authorization.request.backup_artifact_path),
            reason="failure injection",
            authorization=authorization,
            founder_authenticator=founder,
            authority=no_op_authority,
        )

    assert store.get("settings", "state") == {"generation": 2}
    assert store.executive_repository_binding()[4] == 0


def test_corrupt_database_fails_closed_on_startup(tmp_path: Path) -> None:
    database = tmp_path / "corrupt.db"
    database.write_bytes(b"not a SQLite database")

    with pytest.raises((RuntimeError, sqlite3.DatabaseError)):
        KeeperStore(database).migrate()


def test_trusted_executive_has_no_dynamic_provider_code_loader() -> None:
    forbidden_modules = {"importlib", "runpy"}
    forbidden_calls = {
        "__import__",
        "compile",
        "eval",
        "exec",
        "exec_module",
        "import_module",
        "load_module",
        "run_module",
        "run_path",
    }
    violations: list[str] = []

    for source in sorted(EXECUTIVE_ROOT.glob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in forbidden_modules:
                        violations.append(f"{source.name}:{node.lineno}:{alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if (
                    node.module is not None
                    and node.module.split(".", 1)[0] in forbidden_modules
                ):
                    violations.append(
                        f"{source.name}:{node.lineno}:{node.module}"
                    )
            elif isinstance(node, ast.Call):
                name = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else ""
                )
                if name in forbidden_calls:
                    violations.append(f"{source.name}:{node.lineno}:{name}")

    assert violations == []


def test_pass_a_uses_the_versioned_personal_use_threat_model() -> None:
    threat_model = (
        REPOSITORY_ROOT / "docs" / "keeper" / "THREAT_MODEL.md"
    ).read_text(encoding="utf-8")
    pass_a = (
        REPOSITORY_ROOT / "docs" / "keeper" / "EXECUTIVE_PASS_A.md"
    ).read_text(encoding="utf-8")

    assert "Version: 1.0" in threat_model
    assert "Authoritative for Keeper Completion Pass A" in threat_model
    assert "arbitrary code already executing inside the trusted" in threat_model
    assert "provider-generated code is never loaded" in threat_model.lower()
    assert "THREAT_MODEL.md" in pass_a
