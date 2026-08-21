from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from keeper.authority_service.client import TestAuthorityServiceClient
from keeper.authority_service.core import AuthorityServiceCore, TrustedObserver
from keeper.app.restore import (
    TestRestoreHooks,
    prepare_test_restore_authorization,
    restore_authorization_digest,
    sha256_file,
)
from keeper.app.restore_runtime import _validate_artifact_identity
from keeper.app.storage import KeeperStore
from keeper.executive.founder_auth import TestFounderAuthenticator
from keeper.executive.models import utc_now
from tests.keeper.executive.fixture_store import insert_executive_fixture
from tests.keeper.executive.test_restore_safety import (
    SID,
    _attempt_records,
    _authorization,
    _project,
    _raw_setting,
    _restore,
    _store,
)

class _CancellationObserver:
    def __init__(self) -> None:
        self.called = False

    def cancel_provider(self, attempt_id: str) -> None:
        del attempt_id
        self.called = True



def _seed_restore_parents(store: KeeperStore) -> None:
    insert_executive_fixture(
        store, "executive_projects", "project-restore", _project()
    )
    insert_executive_fixture(
        store,
        "project_charters",
        "charter-1",
        {"charter_id": "charter-1", "project_id": "project-restore", "revision": 1},
    )
    insert_executive_fixture(
        store,
        "executive_tasks",
        "task-restore",
        {
            "task_id": "task-restore",
            "project_id": "project-restore",
            "status": "EXECUTION_STARTED",
            "revision": 1,
            "updated_at": utc_now(),
        },
    )


def _approval(consumed_at: str | None) -> dict[str, Any]:
    return {
        "approval_id": "approval-restore",
        "project_id": "project-restore",
        "charter_id": "charter-1",
        "charter_revision": 1,
        "action_id": "action-restore",
        "task_id": "task-restore",
        "kind": "ONE_TIME",
        "consumed_at": consumed_at,
        "revoked_at": None,
    }


def _insert_safety(
    store: KeeperStore,
    *,
    budget_state: str = "CROSSED",
    amount_minor: int = 500,
    include_attempt: bool = False,
) -> str:
    consumed_at = utc_now()
    insert_executive_fixture(
        store,
        "executive_approvals",
        "approval-restore",
        _approval(consumed_at),
    )
    with store.connect() as connection:
        connection.execute(
            "INSERT INTO executive_approval_consumptions VALUES(?,?,?,?,?,?,?)",
            (
                "approval-restore",
                "project-restore",
                "charter-1",
                1,
                "action-restore",
                "task-restore",
                consumed_at,
            ),
        )
        connection.execute(
            "INSERT INTO executive_budget_reservations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "budget-restore",
                "project-restore",
                "charter-1",
                1,
                "approval-restore",
                "action-restore",
                "task-restore",
                amount_minor,
                "USD",
                budget_state,
                consumed_at,
            ),
        )
    if include_attempt:
        insert_executive_fixture(
            store,
            "executive_execution_attempts",
            "attempt-live-safety",
            {
                "id": "attempt-live-safety",
                "project_id": "project-restore",
                "charter_id": "charter-1",
                "charter_revision": 1,
                "task_id": "task-restore",
                "action_id": "action-restore",
                "approval_id": "approval-restore",
                "budget_reservation_id": "budget-restore",
                "authority_attempt_id": "authority-attempt-live-safety",
                "state": "UNCERTAIN",
                "created_at": consumed_at,
                "updated_at": consumed_at,
            },
        )
    return consumed_at


def _older_backup_fixture(
    tmp_path: Path, *, include_attempt: bool = False
) -> tuple[
    KeeperStore,
    Path,
    TestFounderAuthenticator,
    AuthorityServiceCore,
    TestAuthorityServiceClient,
    Any,
    str,
]:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "older.db")
    consumed_at = _insert_safety(store, include_attempt=include_attempt)
    core = AuthorityServiceCore(tmp_path / "authority")
    authority = TestAuthorityServiceClient(
        lambda request: core.dispatch(request, SID)
    )
    founder, authorization = _authorization(store, backup)
    return store, backup, founder, core, authority, authorization, consumed_at


def _fence_identity(authorization: Any) -> dict[str, Any]:
    request = authorization.request
    return {
        "restore_operation_id": request.operation_id,
        "backup_operation_id": request.backup_operation_id,
        "backup_artifact_path": request.backup_artifact_path,
        "backup_sha256": request.backup_sha256,
        "source_database_id": request.source_database_id,
        "source_recovery_epoch": request.source_recovery_epoch,
        "source_generation": request.source_generation,
        "target_database_id": request.target_database_id,
        "target_recovery_epoch": request.target_recovery_epoch,
        "target_generation": request.target_generation,
        "project_scope": list(request.project_scope),
        "authorization_digest": restore_authorization_digest(authorization),
    }


def _direct_fence(
    core: AuthorityServiceCore,
    authorization: Any,
) -> tuple[TestAuthorityServiceClient, dict[str, Any]]:
    client = TestAuthorityServiceClient(
        lambda request: core.dispatch(request, SID)
    )
    fence = client.begin_executive_restore_fence(
        **_fence_identity(authorization)
    )["fence"]
    return client, fence


def _business_snapshot(store: KeeperStore) -> tuple[Any, ...]:
    with sqlite3.connect(store.path) as connection:
        return (
            connection.execute(
                "SELECT recovery_epoch FROM executive_recovery_state WHERE singleton=1"
            ).fetchone(),
            connection.execute(
                "SELECT approval_id,consumed_at FROM executive_approval_consumptions"
            ).fetchall(),
            connection.execute(
                "SELECT reservation_id,amount_minor,state "
                "FROM executive_budget_reservations"
            ).fetchall(),
        )


def test_01_consumed_approval_remains_consumed_after_older_restore(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, authority, authorization, consumed_at = (
        _older_backup_fixture(tmp_path)
    )
    _restore(store, backup, founder, authorization, authority)
    approval = store.get("executive_approvals", "approval-restore")
    assert approval is not None and approval["consumed_at"] == consumed_at
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT consumed_at FROM executive_approval_consumptions "
            "WHERE approval_id='approval-restore'"
        ).fetchone()
    assert row == (consumed_at,)


def test_02_consumed_approval_cannot_be_reused_after_restore_restart(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, authority, authorization, _ = (
        _older_backup_fixture(tmp_path)
    )
    _restore(store, backup, founder, authorization, authority)
    restarted = KeeperStore(store.path)
    restarted.migrate()
    approval = restarted.get("executive_approvals", "approval-restore")
    assert approval is not None and approval["consumed_at"] is not None
    with pytest.raises(sqlite3.IntegrityError), restarted.connect() as connection:
        connection.execute(
            "INSERT INTO executive_approval_consumptions VALUES(?,?,?,?,?,?,?)",
            (
                "approval-restore",
                "project-restore",
                "charter-1",
                1,
                "other-action",
                "task-restore",
                utc_now(),
            ),
        )


def test_03_crossed_budget_remains_crossed_after_older_restore(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, authority, authorization, _ = (
        _older_backup_fixture(tmp_path)
    )
    _restore(store, backup, founder, authorization, authority)
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT amount_minor,state FROM executive_budget_reservations "
            "WHERE reservation_id='budget-restore'"
        ).fetchone()
    assert row == (500, "CROSSED")


def test_04_budget_amount_or_binding_cannot_be_weakened(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    _insert_safety(store, budget_state="RESERVED", amount_minor=100)
    backup = store.backup(tmp_path / "older.db")
    with store.connect() as connection:
        connection.execute(
            "UPDATE executive_budget_reservations SET amount_minor=500,state='CROSSED' "
            "WHERE reservation_id='budget-restore'"
        )
    core = AuthorityServiceCore(tmp_path / "authority")
    authority = TestAuthorityServiceClient(lambda request: core.dispatch(request, SID))
    founder, authorization = _authorization(store, backup)
    with pytest.raises(PermissionError, match="budget safety binding"):
        _restore(store, backup, founder, authorization, authority)
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT amount_minor,state FROM executive_budget_reservations"
        ).fetchone()
    assert row == (500, "CROSSED")


def test_05_executive_only_newer_safety_entry_is_preserved(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, authority, authorization, _ = (
        _older_backup_fixture(tmp_path, include_attempt=True)
    )
    _restore(store, backup, founder, authorization, authority)
    attempt = store.get("executive_execution_attempts", "attempt-live-safety")
    assert attempt is not None
    assert attempt["budget_reservation_id"] == "budget-restore"


def test_06_ambiguous_safety_conflict_rejects_restore(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    _insert_safety(store)
    backup = store.backup(tmp_path / "older.db")
    with store.connect() as connection:
        connection.execute(
            "UPDATE executive_approval_consumptions SET action_id='live-action' "
            "WHERE approval_id='approval-restore'"
        )
    core = AuthorityServiceCore(tmp_path / "authority")
    authority = TestAuthorityServiceClient(lambda request: core.dispatch(request, SID))
    founder, authorization = _authorization(store, backup)
    with pytest.raises(PermissionError, match="approval consumption conflicts"):
        _restore(store, backup, founder, authorization, authority)


def test_07_restore_failure_leaves_live_safety_unchanged(tmp_path: Path) -> None:
    store, backup, founder, _core, authority, authorization, _ = (
        _older_backup_fixture(tmp_path)
    )
    before = _business_snapshot(store)

    def fail() -> None:
        raise RuntimeError("deterministic pre-replacement failure")

    with pytest.raises(RuntimeError, match="deterministic"):
        _restore(
            store,
            backup,
            founder,
            authorization,
            authority,
            hooks=TestRestoreHooks(before_live_replacement=fail),
        )
    assert _business_snapshot(store) == before


def test_08_restore_request_includes_source_generation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "backup.db")
    founder = TestFounderAuthenticator()
    authorization = prepare_test_restore_authorization(
        store.path, backup, reason="Founder restore", authenticator=founder
    )
    with sqlite3.connect(authorization.request.backup_artifact_path) as connection:
        row = connection.execute(
            "SELECT generation FROM executive_write_state WHERE singleton=1"
        ).fetchone()
    assert row is not None
    assert row == (authorization.request.source_generation,)
    binding = authorization.challenge.approval_binding
    assert binding is not None and binding["source_generation"] == row[0]


def test_09_authorization_binds_immutable_backup_artifact(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "backup.db")
    founder, authorization = _authorization(store, backup)
    del founder
    artifact = Path(authorization.request.backup_artifact_path)
    assert artifact != backup.resolve()
    assert artifact.is_file()
    assert authorization.request.backup_operation_id in artifact.name
    assert authorization.request.backup_sha256 == sha256_file(artifact)
    binding = authorization.challenge.approval_binding
    assert binding is not None and binding["backup_artifact_path"] == str(artifact)


def test_10_supported_source_write_after_authorization_is_excluded(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "backup.db")
    core = AuthorityServiceCore(tmp_path / "authority")
    authority = TestAuthorityServiceClient(lambda request: core.dispatch(request, SID))
    founder, authorization = _authorization(store, backup)
    source_store = KeeperStore(backup)
    source_store.upsert("settings", "after-authorization", {"value": 1})
    _restore(store, backup, founder, authorization, authority)
    assert store.get("settings", "after-authorization") is None


def test_11_wal_backed_post_authorization_content_is_excluded(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "backup.db")
    core = AuthorityServiceCore(tmp_path / "authority")
    authority = TestAuthorityServiceClient(lambda request: core.dispatch(request, SID))
    founder, authorization = _authorization(store, backup)
    connection = sqlite3.connect(backup)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        connection.execute("BEGIN IMMEDIATE")
        _raw_setting(connection, "wal-after-authorization", 1)
        connection.commit()
        assert Path(f"{backup}-wal").is_file()
        _restore(store, backup, founder, authorization, authority)
    finally:
        connection.close()
    assert store.get("settings", "wal-after-authorization") is None


def test_12_artifact_mutation_after_authorization_is_rejected(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "backup.db")
    core = AuthorityServiceCore(tmp_path / "authority")
    authority = TestAuthorityServiceClient(lambda request: core.dispatch(request, SID))
    founder, authorization = _authorization(store, backup)
    Path(authorization.request.backup_artifact_path).write_bytes(b"mutated")
    with pytest.raises(PermissionError, match="backup identity"):
        _restore(store, backup, founder, authorization, authority)


def test_12b_application_payload_corruption_is_rejected_before_reconciliation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "backup.db")
    with sqlite3.connect(backup) as connection:
        connection.execute(
            'UPDATE "executive_projects" SET payload_hash=? WHERE id=?',
            ("0" * 64, "project-restore"),
        )
    core = AuthorityServiceCore(tmp_path / "authority")
    authority = TestAuthorityServiceClient(lambda request: core.dispatch(request, SID))
    founder, authorization = _authorization(store, backup)
    with pytest.raises(RuntimeError, match="integrity"):
        _restore(store, backup, founder, authorization, authority)


def test_13_source_generation_mismatch_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "backup.db")
    _founder, authorization = _authorization(store, backup)
    changed = replace(
        authorization.request,
        source_generation=authorization.request.source_generation + 1,
    )
    with pytest.raises(PermissionError, match="identity or generation"):
        _validate_artifact_identity(
            Path(authorization.request.backup_artifact_path), changed
        )


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("source_database_id", "wrong-database", "identity or generation"),
        ("source_recovery_epoch", 99, "identity or generation"),
    ],
)
def test_14_backup_identity_or_epoch_mismatch_is_rejected(
    tmp_path: Path, field: str, value: str | int, match: str
) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "backup.db")
    _founder, authorization = _authorization(store, backup)
    if field == "source_database_id":
        changed = replace(authorization.request, source_database_id=str(value))
    else:
        changed = replace(authorization.request, source_recovery_epoch=int(value))
    with pytest.raises(PermissionError, match=match):
        _validate_artifact_identity(
            Path(authorization.request.backup_artifact_path), changed
        )


def _attempt_restore_fixture(
    tmp_path: Path, state: str = "RESERVED"
) -> tuple[
    KeeperStore,
    Path,
    TestFounderAuthenticator,
    AuthorityServiceCore,
    TestAuthorityServiceClient,
    Any,
    str,
]:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    with store.connect() as connection:
        connection.execute(
            'DELETE FROM "executive_tasks" WHERE id=?', ("task-restore",)
        )
    core = AuthorityServiceCore(tmp_path / "authority")
    attempt_id, _ = _attempt_records(store, core, state=state)
    current = core.store.get("attempts", attempt_id)
    assert current is not None
    current_state = str(current.pop("service_state"))
    current["authorized_client_sid"] = SID
    core.store.transition(
        "attempts", attempt_id, current_state, current_state, current
    )
    backup = store.backup(tmp_path / "backup.db")
    store.upsert("settings", "live-only", {"generation": 2})
    authority = TestAuthorityServiceClient(lambda request: core.dispatch(request, SID))
    founder, authorization = _authorization(store, backup)
    return store, backup, founder, core, authority, authorization, attempt_id


def test_15_authority_cancellation_during_fence_aborts_restore(
    tmp_path: Path,
) -> None:
    store, backup, founder, core, authority, authorization, attempt_id = (
        _attempt_restore_fixture(tmp_path)
    )
    before = _business_snapshot(store)
    observer = _CancellationObserver()
    core.observer = cast(TrustedObserver, observer)

    def cancel() -> None:
        authority.cancel_attempt(attempt_id)

    with pytest.raises(PermissionError, match="fenced"):
        _restore(
            store,
            backup,
            founder,
            authorization,
            authority,
            hooks=TestRestoreHooks(before_live_replacement=cancel),
        )
    current = core.store.get("attempts", attempt_id)
    assert current is not None and current["service_state"] == "RESERVED"
    assert observer.called is False
    assert _business_snapshot(store) == before


def test_16_authority_completion_during_fence_aborts_restore(
    tmp_path: Path,
) -> None:
    store, backup, founder, core, authority, authorization, attempt_id = (
        _attempt_restore_fixture(tmp_path, state="EXECUTION_STARTED")
    )
    current = core.store.get("attempts", attempt_id)
    assert current is not None
    current.pop("service_state")
    completion = core.keys.sign(
        "provider-completion",
        {**current, "kind": "provider_completion", "normalized_result": "completed"},
    )

    def complete() -> None:
        core.store.transition(
            "attempts", attempt_id, "EXECUTION_STARTED", "COMPLETED", completion
        )

    with pytest.raises(PermissionError, match="fenced"):
        _restore(
            store,
            backup,
            founder,
            authorization,
            authority,
            hooks=TestRestoreHooks(before_live_replacement=complete),
        )
    after = core.store.get("attempts", attempt_id)
    assert after is not None and after["service_state"] == "EXECUTION_STARTED"


def test_17_authority_revocation_during_fence_aborts_restore(
    tmp_path: Path,
) -> None:
    store, backup, founder, core, authority, authorization, _ = (
        _attempt_restore_fixture(tmp_path)
    )
    prior = core.store.get("launch_authorizations", "launch-authorization-1")
    assert prior is not None
    prior.pop("service_state")
    revocation = core.keys.sign(
        "project-launch-revocation",
        {**prior, "kind": "project_launch_revocation", "revocation_epoch": 1},
    )

    def revoke() -> None:
        core.store.revoke_launch_authorization(
            "launch-authorization-1", 1, SID, revocation
        )

    with pytest.raises(PermissionError, match="fenced"):
        _restore(
            store,
            backup,
            founder,
            authorization,
            authority,
            hooks=TestRestoreHooks(before_live_replacement=revoke),
        )
    after = core.store.get("launch_authorizations", "launch-authorization-1")
    assert after is not None and after["service_state"] == "ACTIVE"


def test_18_approval_budget_authority_change_during_fence_aborts_restore(
    tmp_path: Path,
) -> None:
    store, backup, founder, core, authority, authorization, _ = (
        _attempt_restore_fixture(tmp_path)
    )

    def reserve_related_attempt() -> None:
        core.store.insert(
            "attempts",
            "attempt-budget-change",
            "RESERVED",
            {
                "id": "attempt-budget-change",
                "project_id": "project-restore",
                "approval_id": "approval-new",
                "budget_reservation_id": "budget-new",
            },
            registration_id="registration-1",
            run_id="run-new",
            attempt_number=2,
            challenge="challenge-new",
        )

    with pytest.raises(PermissionError, match="fenced"):
        _restore(
            store,
            backup,
            founder,
            authorization,
            authority,
            hooks=TestRestoreHooks(before_live_replacement=reserve_related_attempt),
        )
    assert core.store.get("attempts", "attempt-budget-change") is None


def test_19_successful_fenced_restore_preserves_terminal_truth(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, authority, authorization, attempt_id = (
        _attempt_restore_fixture(tmp_path, state="COMPLETED")
    )
    _restore(store, backup, founder, authorization, authority)
    attempt = store.get("executive_execution_attempts", attempt_id)
    assert attempt is not None and attempt["state"] == "UNCERTAIN"
    assert attempt["authority_terminal_state"] == "COMPLETED"


def test_20_fence_expiry_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "backup.db")
    _founder, authorization = _authorization(store, backup)
    core = AuthorityServiceCore(tmp_path / "authority")
    client, fence = _direct_fence(core, authorization)
    with core.store.connect() as connection:
        connection.execute(
            "UPDATE restore_reconciliation_fences SET expires_at=? WHERE fence_id=?",
            ("2000-01-01T00:00:00+00:00", fence["fence_id"]),
        )
    with pytest.raises(PermissionError, match="expired"):
        client.confirm_executive_restore_fence(
            fence["fence_id"], authorization.request.operation_id
        )


def test_21_crash_active_fence_is_conservatively_recoverable(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "backup.db")
    _founder, authorization = _authorization(store, backup)
    core = AuthorityServiceCore(tmp_path / "authority")
    client, fence = _direct_fence(core, authorization)
    assert fence["fence_id"] == (
        f"restore-fence:{authorization.request.operation_id}"
    )
    with core.store.connect() as connection:
        connection.execute(
            "UPDATE restore_reconciliation_fences SET expires_at=? WHERE fence_id=?",
            ("2000-01-01T00:00:00+00:00", fence["fence_id"]),
        )
    outcome = client.recover_executive_restore_fence(
        fence["fence_id"], authorization.request.operation_id
    )["outcome"]
    assert outcome["state"] == "EXPIRED"
    _founder2, authorization2 = _authorization(store, backup)
    replacement = client.begin_executive_restore_fence(
        **_fence_identity(authorization2)
    )["fence"]
    client.abort_executive_restore_fence(
        replacement["fence_id"], authorization2.request.operation_id
    )


def test_22_concurrent_restore_fences_have_one_winner(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "backup.db")
    _founder, authorization = _authorization(store, backup)
    core = AuthorityServiceCore(tmp_path / "authority")
    client = TestAuthorityServiceClient(lambda request: core.dispatch(request, SID))
    barrier = threading.Barrier(2)

    def begin() -> dict[str, Any] | type[BaseException]:
        barrier.wait()
        try:
            return client.begin_executive_restore_fence(
                **_fence_identity(authorization)
            )
        except BaseException as error:
            return type(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in [pool.submit(begin), pool.submit(begin)]]
    winners = [item for item in results if isinstance(item, dict)]
    losers = [item for item in results if item is PermissionError]
    assert len(winners) == 1 and len(losers) == 1
    fence = winners[0]["fence"]
    client.abort_executive_restore_fence(
        fence["fence_id"], authorization.request.operation_id
    )


def test_23_no_duplicate_launch_or_material_effect_after_restart(
    tmp_path: Path,
) -> None:
    store, backup, founder, core, authority, authorization, attempt_id = (
        _attempt_restore_fixture(tmp_path)
    )
    _restore(store, backup, founder, authorization, authority)
    restarted = KeeperStore(store.path)
    restarted.migrate()
    attempts = [
        item for item in restarted.list("executive_execution_attempts")
        if item["id"] == attempt_id
    ]
    assert len(attempts) == 1
    with pytest.raises(PermissionError, match="already reserved"):
        current = core.store.get("attempts", attempt_id)
        assert current is not None
        current.pop("service_state")
        core.store.insert(
            "attempts",
            attempt_id,
            "RESERVED",
            current,
            registration_id="registration-1",
            run_id="run-restore",
            attempt_number=1,
            challenge="challenge-restore",
        )


def test_24_normal_multiwriter_behavior_survives_restore(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed_restore_parents(store)
    backup = store.backup(tmp_path / "backup.db")
    core = AuthorityServiceCore(tmp_path / "authority")
    authority = TestAuthorityServiceClient(lambda request: core.dispatch(request, SID))
    founder, authorization = _authorization(store, backup)
    _restore(store, backup, founder, authorization, authority)
    barrier = threading.Barrier(2)

    def write(identifier: str) -> None:
        barrier.wait()
        store.upsert("settings", identifier, {"writer": identifier})

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(write, "writer-a"), pool.submit(write, "writer-b")]
        for future in futures:
            future.result()
    assert store.get("settings", "writer-a") == {"writer": "writer-a"}
    assert store.get("settings", "writer-b") == {"writer": "writer-b"}


def test_25_failed_restore_preserves_business_epoch_ledgers_and_authority(
    tmp_path: Path,
) -> None:
    store, backup, founder, core, authority, authorization, consumed_at = (
        _older_backup_fixture(tmp_path)
    )
    before = _business_snapshot(store)
    authority_before = core.store.list_records("attempts")

    def fail() -> None:
        raise RuntimeError("stop before replacement")

    with pytest.raises(RuntimeError, match="stop before replacement"):
        _restore(
            store,
            backup,
            founder,
            authorization,
            authority,
            hooks=TestRestoreHooks(before_live_replacement=fail),
        )
    assert _business_snapshot(store) == before
    assert core.store.list_records("attempts") == authority_before
    approval = store.get("executive_approvals", "approval-restore")
    assert approval is not None and approval["consumed_at"] == consumed_at
    with core.store.connect() as connection:
        fence_state = connection.execute(
            "SELECT state FROM restore_reconciliation_fences"
        ).fetchone()
    assert fence_state is not None and tuple(fence_state) == ("ABORTED",)
