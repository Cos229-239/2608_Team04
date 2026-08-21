from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

import pytest

from keeper.authority_service.client import TestAuthorityServiceClient
from keeper.authority_service.core import AuthorityServiceCore
from keeper.authority_service.protocol import Operation, Request
from keeper.app.database_lock import DatabaseMaintenanceBusyError
from keeper.app.restore import (
    TestRestoreAuthorization,
    TestRestoreHooks,
    prepare_test_restore_authorization,
)
from keeper.app.storage import KeeperStore
from keeper.executive.founder_auth import TestFounderAuthenticator
from keeper.executive.models import utc_now
from tests.keeper.executive.fixture_store import insert_executive_fixture


SID = "S-1-5-21-KEEPER-RESTORE-TEST"


def _store(tmp_path: Path, name: str = "live") -> KeeperStore:
    store = KeeperStore(tmp_path / f"{name}.db")
    store.migrate()
    store.bind_executive_repository_mode("PRODUCTION")
    return store


def _project(project_id: str = "project-restore") -> dict[str, Any]:
    timestamp = utc_now()
    return {
        "project_id": project_id,
        "name": "Restore safety",
        "project_type": "software",
        "state": "ACTIVE",
        "active_charter_id": None,
        "active_charter_revision": None,
        "pause_reason": None,
        "created_at": timestamp,
        "updated_at": timestamp,
    }


def _authority(
    tmp_path: Path,
    transform: Callable[[Request, dict[str, Any]], dict[str, Any]] | None = None,
) -> tuple[AuthorityServiceCore, TestAuthorityServiceClient]:
    core = AuthorityServiceCore(tmp_path / "authority")

    def transport(request: Request) -> dict[str, Any]:
        result = core.dispatch(request, SID)
        return transform(request, result) if transform is not None else result

    return core, TestAuthorityServiceClient(transport)


def _authorization(
    store: KeeperStore,
    backup: Path,
    reason: str = "Founder restore",
) -> tuple[TestFounderAuthenticator, TestRestoreAuthorization]:
    founder = TestFounderAuthenticator()
    return founder, prepare_test_restore_authorization(
        store.path, backup, reason=reason, authenticator=founder
    )


def _restore(
    store: KeeperStore,
    backup: Path,
    founder: TestFounderAuthenticator,
    authorization: TestRestoreAuthorization,
    authority: TestAuthorityServiceClient,
    *,
    reason: str = "Founder restore",
    hooks: TestRestoreHooks | None = None,
) -> int:
    del backup
    return store.restore_backup_for_test(
        Path(authorization.request.backup_artifact_path),
        reason=reason,
        authorization=authorization,
        founder_authenticator=founder,
        authority=authority,
        hooks=hooks,
    )


def _fixture(
    tmp_path: Path,
) -> tuple[
    KeeperStore,
    Path,
    TestFounderAuthenticator,
    AuthorityServiceCore,
    TestAuthorityServiceClient,
    TestRestoreAuthorization,
]:
    store = _store(tmp_path)
    insert_executive_fixture(
        store, "executive_projects", "project-restore", _project()
    )
    backup = store.backup(tmp_path / "backup.db")
    store.upsert("settings", "live-only", {"generation": 2})
    core, authority = _authority(tmp_path)
    founder, authorization = _authorization(store, backup)
    return store, backup, founder, core, authority, authorization


def _attempt_records(
    store: KeeperStore,
    core: AuthorityServiceCore,
    *,
    state: str,
    approval_id: str | None = None,
    budget_reservation_id: str | None = None,
) -> tuple[str, dict[str, Any]]:
    attempt_id = "provider-attempt:run-restore:provider-run-1"
    timestamp = utc_now()
    common: dict[str, Any] = {
        "id": attempt_id,
        "project_id": "project-restore",
        "charter_id": "charter-1",
        "charter_revision": 1,
        "task_id": "task-restore",
        "stage_id": "stage-restore",
        "role": "implementer",
        "registration_id": "registration-1",
        "provider_run_id": "provider-run-1",
        "provider_instance_id": "provider-instance-1",
        "launch_authorization_id": "launch-authorization-1",
        "authorization_generation": 1,
    }
    executive = {
        **common,
        "state": "EXECUTION_STARTED",
        "created_at": timestamp,
        "updated_at": timestamp,
        "completion_digest": None,
        "artifact_digest": None,
        "action_id": "action-restore",
        "approval_id": approval_id,
        "budget_reservation_id": budget_reservation_id,
    }
    task = {
        "task_id": "task-restore",
        "project_id": "project-restore",
        "authority_attempt_id": attempt_id,
        "status": "EXECUTION_STARTED",
        "revision": 1,
        "updated_at": timestamp,
    }
    insert_executive_fixture(
        store, "executive_execution_attempts", attempt_id, executive
    )
    insert_executive_fixture(store, "executive_tasks", "task-restore", task)
    purpose = (
        "provider-completion"
        if state in {"COMPLETED", "FAILED"}
        else "provider-launch-authorization"
    )
    if core.store.get("registrations", "registration-1") is None:
        registration = core.keys.sign(
            "provider-registration",
            {
                "id": "registration-1",
                "kind": "provider_registration",
                "configuration_digest": "0" * 64,
            },
        )
        core.store.insert(
            "registrations", "registration-1", "QUALIFIED", registration
        )
    if core.store.get("launch_authorizations", "launch-authorization-1") is None:
        launch_authorization = core.keys.sign(
            "project-launch-authorization",
            {
                "id": "launch-authorization-1",
                "kind": "project_launch_authorization",
                "schema_version": 2,
                "project_id": "project-restore",
                "charter_id": "charter-1",
                "charter_revision": 1,
                "authorization_generation": 1,
            },
        )
        core.store.insert(
            "launch_authorizations",
            "launch-authorization-1",
            "ACTIVE",
            launch_authorization,
            run_id=SID,
            attempt_number=1,
        )
    authority = core.keys.sign(
        purpose,
        {
            **common,
            "kind": (
                "provider_completion"
                if state in {"COMPLETED", "FAILED"}
                else "provider_launch_authorization"
            ),
            "schema_version": 2 if state in {"COMPLETED", "FAILED"} else 1,
            "normalized_result": (
                "completed"
                if state == "COMPLETED"
                else "failed"
                if state == "FAILED"
                else None
            ),
        },
    )
    core.store.insert(
        "attempts",
        attempt_id,
        state,
        authority,
        registration_id="registration-1",
        run_id="run-restore",
        attempt_number=1,
        challenge="challenge-restore",
    )
    return attempt_id, authority


def _raw_setting(connection: sqlite3.Connection, identifier: str, value: int) -> None:
    timestamp = utc_now()
    payload = json.dumps(
        {"value": value}, sort_keys=True, separators=(",", ":")
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    connection.execute(
        'INSERT INTO "settings" VALUES(?,?,?,?,?,?)',
        (identifier, 9, timestamp, timestamp, payload, digest),
    )


def test_noop_callbacks_and_test_proofs_are_rejected_by_production(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, authority, authorization = _fixture(tmp_path)
    production_restore: Any = store.restore_backup
    with pytest.raises(TypeError):
        production_restore(
            backup,
            reason="Founder restore",
            confirm_founder_restore=lambda *_args: None,
            reconcile_authority=lambda *_args: None,
        )
    with pytest.raises(TypeError, match="production trust boundaries"):
        production_restore(
            backup,
            reason="Founder restore",
            authorization=authorization,
            founder_authenticator=founder,
            authority=authority,
        )


def test_noop_authority_result_is_rejected_and_live_state_is_preserved(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, _authority_client, authorization = _fixture(
        tmp_path
    )
    no_op = TestAuthorityServiceClient(lambda _request: {})
    with pytest.raises(PermissionError, match="Authority restore"):
        _restore(store, backup, founder, authorization, no_op)
    assert store.get("settings", "live-only") == {"generation": 2}
    assert store.executive_repository_binding()[4] == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("operation_id", "0" * 32),
        ("backup_sha256", "0" * 64),
        ("target_database_id", "wrong-database"),
    ],
)
def test_restore_authorization_identity_mismatch_is_rejected(
    tmp_path: Path, field: str, value: str
) -> None:
    store, backup, founder, _core, authority, authorization = _fixture(tmp_path)
    if field == "operation_id":
        request = replace(authorization.request, operation_id=value)
    elif field == "backup_sha256":
        request = replace(authorization.request, backup_sha256=value)
    else:
        request = replace(authorization.request, target_database_id=value)
    changed = replace(authorization, request=request)
    with pytest.raises(PermissionError):
        _restore(store, backup, founder, changed, authority)
    assert store.get("settings", "live-only") == {"generation": 2}


def test_stale_and_replayed_restore_authorization_is_rejected(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, authority, authorization = _fixture(tmp_path)
    stale = replace(
        authorization,
        request=replace(
            authorization.request, expires_at="2000-01-01T00:00:00+00:00"
        ),
    )
    with pytest.raises(PermissionError):
        _restore(store, backup, founder, stale, authority)
    assert _restore(store, backup, founder, authorization, authority) == 1
    with pytest.raises(PermissionError):
        _restore(store, backup, founder, authorization, authority)


@pytest.mark.parametrize("state", ["RESERVED", "COMPLETED", "CANCELLED"])
def test_omitted_authority_attempt_or_terminal_state_is_rejected(
    tmp_path: Path, state: str
) -> None:
    store = _store(tmp_path)
    insert_executive_fixture(
        store, "executive_projects", "project-restore", _project()
    )
    core = AuthorityServiceCore(tmp_path / "authority")
    _attempt_records(store, core, state=state)
    backup = store.backup(tmp_path / "backup.db")
    store.upsert("settings", "live-only", {"generation": 2})

    def omit(
        request: Request, result: dict[str, Any]
    ) -> dict[str, Any]:
        if request.operation != Operation.BEGIN_EXECUTIVE_RESTORE_FENCE:
            return result
        receipt = dict(result["fence"])
        receipt["attempts"] = []
        receipt["state_digest"] = hashlib.sha256(
            json.dumps(
                {
                    "attempts": [],
                    "launch_authorizations": receipt[
                        "launch_authorizations"
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return {"fence": receipt}

    authority = TestAuthorityServiceClient(
        lambda request: omit(request, core.dispatch(request, SID))
    )
    founder, authorization = _authorization(store, backup)
    with pytest.raises(PermissionError, match="evidence is invalid"):
        _restore(store, backup, founder, authorization, authority)
    assert store.get("settings", "live-only") == {"generation": 2}


def test_omitted_authority_revocation_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    insert_executive_fixture(
        store, "executive_projects", "project-restore", _project()
    )
    core = AuthorityServiceCore(tmp_path / "authority")
    _attempt_records(store, core, state="RESERVED")
    prior = core.store.get("launch_authorizations", "launch-authorization-1")
    assert prior is not None
    revocation = core.keys.sign(
        "project-launch-revocation",
        {
            **{key: value for key, value in prior.items() if key != "service_state"},
            "kind": "project_launch_revocation",
            "revocation_epoch": 1,
            "revoked_at": utc_now(),
        },
    )
    core.store.revoke_launch_authorization(
        "launch-authorization-1", 1, SID, revocation
    )
    backup = store.backup(tmp_path / "backup.db")
    store.upsert("settings", "live-only", {"generation": 2})

    def omit(
        request: Request, result: dict[str, Any]
    ) -> dict[str, Any]:
        if request.operation != Operation.BEGIN_EXECUTIVE_RESTORE_FENCE:
            return result
        receipt = dict(result["fence"])
        receipt["launch_authorizations"] = []
        receipt["state_digest"] = hashlib.sha256(
            json.dumps(
                {
                    "attempts": receipt["attempts"],
                    "launch_authorizations": [],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return {
            "fence": core.keys.sign(
                "executive-restore-reconciliation-fence", receipt
            )
        }

    authority = TestAuthorityServiceClient(
        lambda request: omit(request, core.dispatch(request, SID))
    )
    founder, restore_authorization = _authorization(store, backup)
    with pytest.raises(
        PermissionError, match="omits its launch authorization state"
    ):
        _restore(
            store, backup, founder, restore_authorization, authority
        )
    assert store.get("settings", "live-only") == {"generation": 2}

def test_reconciliation_timestamp_only_follows_validated_evidence(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, authority, authorization = _fixture(tmp_path)
    with sqlite3.connect(store.path) as connection:
        before = connection.execute(
            "SELECT authority_reconciled_at FROM executive_recovery_state"
        ).fetchone()
    assert before == (None,)
    _restore(store, backup, founder, authorization, authority)
    with sqlite3.connect(store.path) as connection:
        after = connection.execute(
            "SELECT authority_reconciled_at,authority_receipt_digest "
            "FROM executive_recovery_state"
        ).fetchone()
    assert after is not None
    assert after[0] is not None
    assert isinstance(after[1], str) and len(after[1]) == 64


def test_newer_authority_completion_is_preserved_as_uncertain(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    insert_executive_fixture(
        store, "executive_projects", "project-restore", _project()
    )
    core = AuthorityServiceCore(tmp_path / "authority")
    attempt_id, _record = _attempt_records(store, core, state="COMPLETED")
    backup = store.backup(tmp_path / "backup.db")
    store.upsert("settings", "live-only", {"generation": 2})
    authority = TestAuthorityServiceClient(
        lambda request: core.dispatch(request, SID)
    )
    founder, authorization = _authorization(store, backup)
    _restore(store, backup, founder, authorization, authority)
    attempt = store.get("executive_execution_attempts", attempt_id)
    task = store.get("executive_tasks", "task-restore")
    assert attempt is not None and attempt["state"] == "UNCERTAIN"
    assert attempt["authority_terminal_state"] == "COMPLETED"
    assert isinstance(attempt["completion_digest"], str)
    assert task is not None and task["status"] == "UNCERTAIN"
    with sqlite3.connect(store.path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM executive_restore_reconciliations"
        ).fetchone()
    assert count == (1,)


def test_approval_consumption_and_crossed_budget_are_preserved(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    insert_executive_fixture(
        store, "executive_projects", "project-restore", _project()
    )
    insert_executive_fixture(
        store,
        "project_charters",
        "charter-1",
        {"charter_id": "charter-1", "project_id": "project-restore", "revision": 1},
    )
    approval: dict[str, object] = {
        "approval_id": "approval-restore",
        "project_id": "project-restore",
        "charter_id": "charter-1",
        "charter_revision": 1,
        "action_id": "action-restore",
        "task_id": "task-restore",
        "kind": "ONE_TIME",
        "consumed_at": utc_now(),
    }
    insert_executive_fixture(
        store, "executive_approvals", "approval-restore", approval
    )
    core = AuthorityServiceCore(tmp_path / "authority")
    _attempt_records(
        store,
        core,
        state="EXECUTION_STARTED",
        approval_id="approval-restore",
        budget_reservation_id="budget-restore",
    )
    with store.connect() as connection:
        connection.execute(
            "INSERT INTO executive_approval_consumptions "
            "VALUES(?,?,?,?,?,?,?)",
            (
                "approval-restore",
                "project-restore",
                "charter-1",
                1,
                "action-restore",
                "task-restore",
                utc_now(),
            ),
        )
        connection.execute(
            "INSERT INTO executive_budget_reservations "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "budget-restore",
                "project-restore",
                "charter-1",
                1,
                "approval-restore",
                "action-restore",
                "task-restore",
                500,
                "USD",
                "RESERVED",
                utc_now(),
            ),
        )
    backup = store.backup(tmp_path / "backup.db")
    store.upsert("settings", "live-only", {"generation": 2})
    authority = TestAuthorityServiceClient(
        lambda request: core.dispatch(request, SID)
    )
    founder, authorization = _authorization(store, backup)
    _restore(store, backup, founder, authorization, authority)
    with sqlite3.connect(store.path) as connection:
        consumption = connection.execute(
            "SELECT action_id FROM executive_approval_consumptions "
            "WHERE approval_id='approval-restore'"
        ).fetchone()
        budget = connection.execute(
            "SELECT state FROM executive_budget_reservations "
            "WHERE reservation_id='budget-restore'"
        ).fetchone()
    assert consumption == ("action-restore",)
    assert budget == ("CROSSED",)


def test_active_writer_commit_is_not_erased_and_stale_restore_aborts(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, authority, authorization = _fixture(tmp_path)
    started = threading.Event()
    release = threading.Event()

    def writer() -> None:
        with store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _raw_setting(connection, "acknowledged-writer", 1)
            started.set()
            assert release.wait(5)

    with ThreadPoolExecutor(max_workers=2) as pool:
        writer_future = pool.submit(writer)
        assert started.wait(5)
        restore_future = pool.submit(
            _restore,
            store,
            backup,
            founder,
            authorization,
            authority,
        )
        release.set()
        writer_future.result(timeout=5)
        with pytest.raises(PermissionError, match="target recovery identity"):
            restore_future.result(timeout=5)
    assert store.get("settings", "acknowledged-writer") == {"value": 1}


def test_writer_starting_during_restore_is_rejected_before_commit(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, authority, authorization = _fixture(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    def hold_restore() -> None:
        entered.set()
        assert release.wait(5)

    hooks = TestRestoreHooks(after_maintenance_acquired=hold_restore)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            _restore,
            store,
            backup,
            founder,
            authorization,
            authority,
            hooks=hooks,
        )
        assert entered.wait(5)
        with pytest.raises(DatabaseMaintenanceBusyError):
            store.upsert("settings", "forbidden-during-restore", {"value": 1})
        release.set()
        assert future.result(timeout=5) == 1
    assert store.get("settings", "forbidden-during-restore") is None
    store.upsert("settings", "writes-resumed", {"value": 1})
    assert store.get("settings", "writes-resumed") == {"value": 1}


def test_generation_change_immediately_before_replacement_aborts(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, authority, authorization = _fixture(tmp_path)

    def advance_generation() -> None:
        connection = sqlite3.connect(store.path)
        try:
            connection.execute(
                "UPDATE executive_write_state SET generation=generation+1"
            )
            connection.commit()
        finally:
            connection.close()

    hooks = TestRestoreHooks(before_live_replacement=advance_generation)
    with pytest.raises(PermissionError, match="target recovery identity"):
        _restore(
            store,
            backup,
            founder,
            authorization,
            authority,
            hooks=hooks,
        )
    assert store.get("settings", "live-only") == {"generation": 2}


def test_concurrent_restores_have_one_winner(tmp_path: Path) -> None:
    store, backup, founder_a, _core, authority, authorization_a = _fixture(
        tmp_path
    )
    founder_b, authorization_b = _authorization(store, backup)
    entered = threading.Event()
    release = threading.Event()
    def hold_restore() -> None:
        entered.set()
        assert release.wait(5)

    hooks = TestRestoreHooks(after_maintenance_acquired=hold_restore)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(
            _restore,
            store,
            backup,
            founder_a,
            authorization_a,
            authority,
            hooks=hooks,
        )
        assert entered.wait(5)
        second = pool.submit(
            _restore,
            store,
            backup,
            founder_b,
            authorization_b,
            authority,
        )
        release.set()
        outcomes: list[object] = []
        for future in (first, second):
            try:
                outcomes.append(future.result(timeout=5))
            except BaseException as error:
                outcomes.append(error)
    assert sum(value == 1 for value in outcomes) == 1
    assert sum(isinstance(value, PermissionError) for value in outcomes) == 1


def test_interrupted_maintenance_requires_explicit_conservative_recovery(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.path) as connection:
        generation = connection.execute(
            "SELECT generation FROM executive_write_state"
        ).fetchone()
        assert generation is not None
        connection.execute(
            "INSERT INTO executive_restore_maintenance "
            "(singleton,operation_id,state,source_backup_sha256,"
            "expected_generation,started_at,finished_at) "
            "VALUES(1,?,'ACTIVE',?,?,?,NULL) "
            "ON CONFLICT(singleton) DO UPDATE SET "
            "operation_id=excluded.operation_id,state='ACTIVE',"
            "source_backup_sha256=excluded.source_backup_sha256,"
            "expected_generation=excluded.expected_generation,"
            "started_at=excluded.started_at,finished_at=NULL",
            ("interrupted-op", "0" * 64, generation[0], utc_now()),
        )
    with pytest.raises(RuntimeError, match="active restore"):
        store.get("settings", "anything")
    with pytest.raises(PermissionError):
        store.recover_stale_restore("wrong-operation")
    store.recover_stale_restore("interrupted-op")
    store.upsert("settings", "after-recovery", {"value": 1})
    assert store.get("settings", "after-recovery") == {"value": 1}


def test_failed_restore_releases_maintenance_and_writes_resume(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, _authority_client, authorization = _fixture(
        tmp_path
    )
    authority = TestAuthorityServiceClient(lambda _request: {})
    with pytest.raises(PermissionError):
        _restore(store, backup, founder, authorization, authority)
    store.upsert("settings", "after-failure", {"value": 1})
    assert store.get("settings", "after-failure") == {"value": 1}


def test_normal_multiwriter_execution_remains_supported(tmp_path: Path) -> None:
    store = _store(tmp_path)
    barrier = threading.Barrier(3)

    def write(index: int) -> None:
        barrier.wait()
        store.upsert("settings", f"writer-{index}", {"value": index})

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(write, index) for index in range(2)]
        barrier.wait()
        for future in futures:
            future.result(timeout=5)
    assert store.get("settings", "writer-0") == {"value": 0}
    assert store.get("settings", "writer-1") == {"value": 1}


def test_restore_preserves_one_attempt_and_prevents_duplicate_launch_state(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    insert_executive_fixture(
        store, "executive_projects", "project-restore", _project()
    )
    core = AuthorityServiceCore(tmp_path / "authority")
    attempt_id, _record = _attempt_records(
        store, core, state="EXECUTION_STARTED"
    )
    backup = store.backup(tmp_path / "backup.db")
    store.upsert("settings", "live-only", {"generation": 2})
    authority = TestAuthorityServiceClient(
        lambda request: core.dispatch(request, SID)
    )
    founder, authorization = _authorization(store, backup)
    _restore(store, backup, founder, authorization, authority)
    project = store.get("executive_projects", "project-restore")
    attempts = [
        item
        for item in store.list("executive_execution_attempts")
        if item["id"] == attempt_id
    ]
    assert project is not None and project["state"] == "PAUSED"
    assert len(attempts) == 1
    assert attempts[0]["state"] == "EXECUTION_STARTED"


def test_corrupt_backup_after_authorization_preserves_live_state(
    tmp_path: Path,
) -> None:
    store, backup, founder, _core, authority, authorization = _fixture(tmp_path)
    artifact = Path(authorization.request.backup_artifact_path)
    connection = sqlite3.connect(artifact)
    connection.close()
    artifact.write_bytes(b"corrupt")
    with pytest.raises(PermissionError, match="backup"):
        _restore(store, backup, founder, authorization, authority)
    assert store.get("settings", "live-only") == {"generation": 2}
    assert store.executive_repository_binding()[4] == 0
