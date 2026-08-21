from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, cast

from keeper.authority_service.client import (
    ProductionAuthorityServiceClient,
    TestAuthorityServiceClient,
)
from keeper.authority_service.protocol import PROTOCOL_VERSION
from keeper.app.database_lock import DatabaseFileLock
from keeper.app.restore import (
    RESTORE_APPROVAL_ACTION,
    RESTORE_SCHEMA_VERSION,
    ProductionRestoreAuthorization,
    RestoreRequest,
    TestRestoreAuthorization,
    TestRestoreHooks,
    restore_authorization_digest,
    restore_request_digest,
    sha256_file,
)
from keeper.executive.founder_auth import (
    ProductionFounderAuthenticator,
    TestFounderAuthenticator,
)

if TYPE_CHECKING:
    from keeper.app.storage import KeeperStore


AUTHORITY_RECONCILIATION_PURPOSE = "executive-restore-reconciliation"
AUTHORITY_FENCE_PURPOSE = "executive-restore-reconciliation-fence"
AUTHORITY_FENCE_CONFIRMATION_PURPOSE = "executive-restore-fence-confirmation"
AUTHORITY_FENCE_OUTCOME_PURPOSE = "executive-restore-fence-outcome"
AUTHORITY_RECONCILIATION_SCHEMA_VERSION = 1
TERMINAL_AUTHORITY_STATES = frozenset({"COMPLETED", "FAILED", "CANCELLED"})


def restore_production_backup(
    store: KeeperStore,
    backup: Path,
    *,
    reason: str,
    authorization: ProductionRestoreAuthorization,
    founder_authenticator: ProductionFounderAuthenticator,
    authority: ProductionAuthorityServiceClient,
) -> int:
    if (
        type(authorization) is not ProductionRestoreAuthorization
        or type(founder_authenticator) is not ProductionFounderAuthenticator
        or type(authority) is not ProductionAuthorityServiceClient
    ):
        raise TypeError("production restore requires exact production trust boundaries")
    session = founder_authenticator.verify(
        authorization.challenge, authorization.confirmation
    )
    return _restore(
        store,
        backup,
        reason=reason,
        authorization=authorization,
        founder_identity=session.principal_sid,
        authority=authority,
        hooks=None,
        production=True,
    )


def restore_test_backup(
    store: KeeperStore,
    backup: Path,
    *,
    reason: str,
    authorization: TestRestoreAuthorization,
    founder_authenticator: TestFounderAuthenticator,
    authority: TestAuthorityServiceClient,
    hooks: TestRestoreHooks | None = None,
) -> int:
    if (
        type(authorization) is not TestRestoreAuthorization
        or type(founder_authenticator) is not TestFounderAuthenticator
        or type(authority) is not TestAuthorityServiceClient
        or (hooks is not None and type(hooks) is not TestRestoreHooks)
    ):
        raise TypeError("test restore requires exact test-only trust boundaries")
    session = founder_authenticator.verify(
        authorization.challenge, authorization.confirmation
    )
    return _restore(
        store,
        backup,
        reason=reason,
        authorization=authorization,
        founder_identity=session.principal_sid,
        authority=authority,
        hooks=hooks,
        production=False,
    )


def recover_stale_restore(store: KeeperStore, operation_id: str) -> None:
    if not operation_id:
        raise ValueError("restore operation ID is required")
    with DatabaseFileLock(store.path, "exclusive", timeout_seconds=5):
        store.verify_integrity()
        with _connection(store.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT operation_id,state,expected_generation "
                "FROM executive_restore_maintenance WHERE singleton=1"
            ).fetchone()
            generation = _generation(connection)
            if (
                row is None
                or row["state"] != "ACTIVE"
                or row["operation_id"] != operation_id
                or int(row["expected_generation"]) != generation
            ):
                raise PermissionError(
                    "stale restore recovery identity or generation is invalid"
                )
            connection.execute(
                "UPDATE executive_restore_maintenance "
                "SET state='FAILED',finished_at=? "
                "WHERE singleton=1 AND operation_id=? AND state='ACTIVE'",
                (_now(), operation_id),
            )


def _restore(
    store: KeeperStore,
    backup: Path,
    *,
    reason: str,
    authorization: ProductionRestoreAuthorization | TestRestoreAuthorization,
    founder_identity: str,
    authority: ProductionAuthorityServiceClient | TestAuthorityServiceClient,
    hooks: TestRestoreHooks | None,
    production: bool,
) -> int:
    source = backup.resolve()
    request = authorization.request
    if source == store.path:
        raise ValueError("restore source must differ from live database")
    if not source.is_file():
        raise FileNotFoundError(source)
    _validate_authorization_shape(
        store, source, reason, authorization, founder_identity
    )
    staged_path = store.path.with_name(
        f".{store.path.name}.{uuid.uuid4().hex}.restore"
    )
    staged = type(store)(staged_path)
    replaced = False
    maintenance_started = False
    fence: dict[str, Any] | None = None
    authorization_digest = restore_authorization_digest(authorization)
    with (
        DatabaseFileLock(store.path, "exclusive", timeout_seconds=5),
        DatabaseFileLock(source, "exclusive", timeout_seconds=5),
    ):
        try:
            with _connection(store.path) as live:
                live.execute("BEGIN IMMEDIATE")
                current = _live_identity(live)
                _validate_target_identity(request, store.path, current)
                if live.execute(
                    "SELECT 1 FROM executive_restore_authorizations "
                    "WHERE operation_id=? OR authorization_digest=?",
                    (request.operation_id, authorization_digest),
                ).fetchone():
                    raise PermissionError("restore authorization was already consumed")
                active = live.execute(
                    "SELECT operation_id,state FROM executive_restore_maintenance "
                    "WHERE singleton=1"
                ).fetchone()
                if active is not None and active["state"] == "ACTIVE":
                    raise RuntimeError(
                        "an active or interrupted restore requires explicit recovery"
                    )
                live_safety = _capture_live_safety_ledger(live, request)
                live.execute(
                    "INSERT INTO executive_restore_maintenance("
                    "singleton,operation_id,state,source_backup_sha256,"
                    "expected_generation,started_at,finished_at,"
                    "authority_fence_id,authority_fence_expires_at"
                    ") VALUES(1,?,'ACTIVE',?,?,?,NULL,NULL,NULL) "
                    "ON CONFLICT(singleton) DO UPDATE SET "
                    "operation_id=excluded.operation_id,state='ACTIVE',"
                    "source_backup_sha256=excluded.source_backup_sha256,"
                    "expected_generation=excluded.expected_generation,"
                    "started_at=excluded.started_at,finished_at=NULL,"
                    "authority_fence_id=NULL,authority_fence_expires_at=NULL",
                    (
                        request.operation_id,
                        request.backup_sha256,
                        request.target_generation,
                        _now(),
                    ),
                )
            maintenance_started = True
            if hooks is not None and hooks.after_maintenance_acquired is not None:
                hooks.after_maintenance_acquired()

            before_hash = sha256_file(source)
            if before_hash != request.backup_sha256:
                raise PermissionError("restore backup identity changed after authorization")
            _validate_artifact_identity(source, request)
            store._sqlite_backup(source, staged_path)
            if sha256_file(source) != before_hash:
                raise PermissionError("restore backup changed while it was staged")
            _validate_artifact_identity(source, request)
            staged.migrate()
            staged.verify_integrity()

            diagnostics = authority.diagnostics()
            if production:
                diagnostics = cast(
                    ProductionAuthorityServiceClient, authority
                ).require_live_identity()
            fence = _begin_authority_fence(
                authority, diagnostics, request, authorization_digest
            )
            with _connection(store.path) as live:
                live.execute("BEGIN IMMEDIATE")
                _validate_live_boundary(live, request)
                live.execute(
                    "UPDATE executive_restore_maintenance SET "
                    "authority_fence_id=?,authority_fence_expires_at=? "
                    "WHERE singleton=1 AND operation_id=? AND state='ACTIVE'",
                    (
                        fence["fence_id"],
                        fence["expires_at"],
                        request.operation_id,
                    ),
                )
            safety = _reconcile_staged(
                staged_path, request, fence, live_safety
            )

            if hooks is not None and hooks.before_final_generation_check is not None:
                hooks.before_final_generation_check()
            confirmation = _confirm_authority_fence(
                authority, diagnostics, request, fence
            )

            with _connection(store.path) as live:
                _validate_live_boundary(live, request)

            reconciled_at = str(confirmation["confirmed_at"])
            receipt = {"fence": fence, "confirmation": confirmation}
            receipt_digest = _digest(receipt)
            recovery_epoch = request.target_recovery_epoch + 1
            with _connection(staged_path) as connection:
                connection.execute("BEGIN IMMEDIATE")
                _validate_source_identity(connection, request)
                store._pause_projects_for_restore(connection, reconciled_at)
                reconciliation_payload = {
                    "authority_receipt": receipt,
                    "executive_safety": safety,
                }
                serialized = _serialized(reconciliation_payload)
                connection.execute(
                    "INSERT INTO executive_restore_reconciliations VALUES(?,?,?,?,?,?,?)",
                    (
                        request.operation_id,
                        receipt_digest,
                        fence["service_key_id"],
                        fence["service_key_version"],
                        reconciled_at,
                        serialized,
                        _sha256(serialized.encode("utf-8")),
                    ),
                )
                connection.execute(
                    "INSERT INTO executive_restore_authorizations VALUES(?,?,?,?)",
                    (
                        request.operation_id,
                        authorization_digest,
                        founder_identity,
                        reconciled_at,
                    ),
                )
                cursor = connection.execute(
                    "UPDATE executive_recovery_state SET "
                    "database_id=?,canonical_path=?,recovery_epoch=?,restored_at=?,"
                    "restore_reason=?,authority_reconciled_at=?,updated_at=?,"
                    "restore_operation_id=?,authority_receipt_digest=? "
                    "WHERE singleton=1",
                    (
                        request.target_database_id,
                        os.path.normcase(str(store.path.resolve())),
                        recovery_epoch,
                        reconciled_at,
                        request.reason,
                        reconciled_at,
                        reconciled_at,
                        request.operation_id,
                        receipt_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("staged recovery identity is missing")
                connection.execute(
                    "UPDATE executive_write_state SET generation=?,updated_at=? "
                    "WHERE singleton=1",
                    (request.target_generation + 1, reconciled_at),
                )
                connection.execute(
                    "INSERT INTO executive_restore_maintenance("
                    "singleton,operation_id,state,source_backup_sha256,"
                    "expected_generation,started_at,finished_at,"
                    "authority_fence_id,authority_fence_expires_at"
                    ") VALUES(1,?,'COMPLETED',?,?,?,?,?,?) "
                    "ON CONFLICT(singleton) DO UPDATE SET "
                    "operation_id=excluded.operation_id,state='COMPLETED',"
                    "source_backup_sha256=excluded.source_backup_sha256,"
                    "expected_generation=excluded.expected_generation,"
                    "started_at=excluded.started_at,"
                    "finished_at=excluded.finished_at,"
                    "authority_fence_id=excluded.authority_fence_id,"
                    "authority_fence_expires_at=excluded.authority_fence_expires_at",
                    (
                        request.operation_id,
                        request.backup_sha256,
                        request.target_generation,
                        request.requested_at,
                        reconciled_at,
                        fence["fence_id"],
                        fence["expires_at"],
                    ),
                )
            staged.verify_integrity()
            if hooks is not None and hooks.before_live_replacement is not None:
                hooks.before_live_replacement()
            with _connection(store.path) as live:
                _validate_live_boundary(live, request)
            store._sqlite_backup(staged_path, store.path)
            replaced = True
            store.verify_integrity()
            _finish_authority_fence(
                authority, diagnostics, request, fence, "COMPLETED"
            )
            return recovery_epoch
        except BaseException as error:
            cleanup_errors: list[BaseException] = []
            if fence is not None and not replaced:
                try:
                    _finish_authority_fence(
                        authority, diagnostics, request, fence, "ABORTED"
                    )
                except BaseException as fence_error:
                    cleanup_errors.append(fence_error)
            if maintenance_started and not replaced:
                try:
                    _mark_restore_failed(store.path, request.operation_id)
                except BaseException as maintenance_error:
                    cleanup_errors.append(maintenance_error)
            if cleanup_errors:
                raise BaseExceptionGroup(
                    "restore failed and conservative cleanup was incomplete",
                    [error, *cleanup_errors],
                )
            raise
        finally:
            for candidate in (
                staged_path,
                Path(f"{staged_path}-wal"),
                Path(f"{staged_path}-shm"),
                staged_path.with_name(f"{staged_path.name}.keeper-lock"),
                staged_path.with_suffix(".verified"),
            ):
                candidate.unlink(missing_ok=True)

def _validate_authorization_shape(
    store: KeeperStore,
    backup: Path,
    reason: str,
    authorization: ProductionRestoreAuthorization | TestRestoreAuthorization,
    founder_identity: str,
) -> None:
    request = authorization.request
    challenge = authorization.challenge
    now = datetime.now(UTC)
    if request.backup_sha256 != sha256_file(backup):
        raise PermissionError("restore backup identity changed after authorization")
    _validate_artifact_identity(backup, request)
    if (
        request.schema_version != RESTORE_SCHEMA_VERSION
        or len(request.operation_id) != 32
        or len(request.backup_operation_id) != 32
        or request.backup_artifact_path
        != os.path.normcase(str(backup.resolve()))
        or request.target_canonical_path
        != os.path.normcase(str(store.path.resolve()))
        or request.reason != reason.strip()
        or not request.reason
        or tuple(sorted(set(request.project_scope))) != request.project_scope
        or datetime.fromisoformat(request.requested_at) > now
        or datetime.fromisoformat(request.expires_at) <= now
        or challenge.approval_action != RESTORE_APPROVAL_ACTION
        or challenge.charter_digest != restore_request_digest(request)
        or challenge.approval_binding != request.to_dict()
        or authorization.confirmation.principal_sid != founder_identity
    ):
        raise PermissionError("restore authorization binding is invalid or stale")


def _validate_artifact_identity(path: Path, request: RestoreRequest) -> None:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT r.database_id,r.recovery_epoch,w.generation,m.mode "
            "FROM executive_recovery_state AS r "
            "JOIN executive_write_state AS w ON w.singleton=r.singleton "
            "JOIN executive_repository_mode AS m ON m.singleton=r.singleton "
            "WHERE r.singleton=1"
        ).fetchone()
        if (
            row is None
            or row["mode"] != "PRODUCTION"
            or row["database_id"] != request.source_database_id
            or int(row["recovery_epoch"]) != request.source_recovery_epoch
            or int(row["generation"]) != request.source_generation
        ):
            raise PermissionError("restore artifact identity or generation changed")
    except sqlite3.DatabaseError as error:
        raise RuntimeError("restore artifact identity is unreadable") from error
    finally:
        connection.close()


def _validate_target_identity(
    request: RestoreRequest,
    path: Path,
    current: tuple[str, int, int, str],
) -> None:
    if (
        current[0] != request.target_database_id
        or current[1] != request.target_recovery_epoch
        or current[2] != request.target_generation
        or current[3] != "PRODUCTION"
        or request.target_canonical_path
        != os.path.normcase(str(path.resolve()))
    ):
        raise PermissionError("restore target recovery identity is stale")


def _begin_authority_fence(
    authority: ProductionAuthorityServiceClient | TestAuthorityServiceClient,
    diagnostics: dict[str, Any],
    request: RestoreRequest,
    authorization_digest: str,
) -> dict[str, Any]:
    result = authority.begin_executive_restore_fence(
        restore_operation_id=request.operation_id,
        backup_operation_id=request.backup_operation_id,
        backup_artifact_path=request.backup_artifact_path,
        backup_sha256=request.backup_sha256,
        source_database_id=request.source_database_id,
        source_recovery_epoch=request.source_recovery_epoch,
        source_generation=request.source_generation,
        target_database_id=request.target_database_id,
        target_recovery_epoch=request.target_recovery_epoch,
        target_generation=request.target_generation,
        project_scope=list(request.project_scope),
        authorization_digest=authorization_digest,
    )
    fence = result.get("fence")
    fields = {
        "schema_version",
        "kind",
        "restore_operation_id",
        "backup_operation_id",
        "backup_artifact_path",
        "backup_sha256",
        "source_database_id",
        "source_recovery_epoch",
        "source_generation",
        "target_database_id",
        "target_recovery_epoch",
        "target_generation",
        "project_scope",
        "authorization_digest",
        "fence_id",
        "authorized_client_sid",
        "attempts",
        "launch_authorizations",
        "project_versions",
        "state_digest",
        "version_digest",
        "issued_at",
        "expires_at",
        "protocol_version",
        "service_key_id",
        "service_key_version",
        "authority_schema_version",
        "authority_key_id",
        "authenticated_writer_proof",
    }
    state = {
        "attempts": fence.get("attempts") if isinstance(fence, dict) else None,
        "launch_authorizations": (
            fence.get("launch_authorizations")
            if isinstance(fence, dict)
            else None
        ),
    }
    if (
        not isinstance(fence, dict)
        or set(fence) != fields
        or fence.get("schema_version") != AUTHORITY_RECONCILIATION_SCHEMA_VERSION
        or fence.get("kind") != AUTHORITY_FENCE_PURPOSE
        or fence.get("restore_operation_id") != request.operation_id
        or fence.get("backup_operation_id") != request.backup_operation_id
        or fence.get("backup_artifact_path") != request.backup_artifact_path
        or fence.get("backup_sha256") != request.backup_sha256
        or fence.get("source_database_id") != request.source_database_id
        or fence.get("source_recovery_epoch") != request.source_recovery_epoch
        or fence.get("source_generation") != request.source_generation
        or fence.get("target_database_id") != request.target_database_id
        or fence.get("target_recovery_epoch") != request.target_recovery_epoch
        or fence.get("target_generation") != request.target_generation
        or fence.get("project_scope") != list(request.project_scope)
        or fence.get("authorization_digest") != authorization_digest
        or fence.get("protocol_version") != PROTOCOL_VERSION
        or fence.get("service_key_id") != diagnostics.get("service_key_id")
        or fence.get("service_key_version")
        != diagnostics.get("service_key_version")
        or fence.get("authorized_client_sid") != diagnostics.get("client_sid")
        or not isinstance(fence.get("fence_id"), str)
        or not isinstance(fence.get("attempts"), list)
        or not isinstance(fence.get("launch_authorizations"), list)
        or not isinstance(fence.get("project_versions"), dict)
        or fence.get("state_digest") != _digest(state)
        or fence.get("version_digest") != _digest(fence.get("project_versions"))
        or datetime.fromisoformat(str(fence.get("issued_at"))) > datetime.now(UTC)
        or datetime.fromisoformat(str(fence.get("expires_at"))) <= datetime.now(UTC)
        or not authority.verify(AUTHORITY_FENCE_PURPOSE, fence)
    ):
        raise PermissionError("Authority restore fence evidence is invalid")
    return fence


def _confirm_authority_fence(
    authority: ProductionAuthorityServiceClient | TestAuthorityServiceClient,
    diagnostics: dict[str, Any],
    request: RestoreRequest,
    fence: dict[str, Any],
) -> dict[str, Any]:
    result = authority.confirm_executive_restore_fence(
        str(fence["fence_id"]), request.operation_id
    )
    confirmation = result.get("confirmation")
    fields = {
        "schema_version",
        "kind",
        "protocol_version",
        "service_key_id",
        "fence_id",
        "restore_operation_id",
        "authorized_client_sid",
        "state_digest",
        "version_digest",
        "authorization_digest",
        "backup_sha256",
        "project_scope",
        "issued_at",
        "expires_at",
        "confirmed_at",
        "service_key_version",
        "authority_schema_version",
        "authority_key_id",
        "authenticated_writer_proof",
    }
    if (
        not isinstance(confirmation, dict)
        or set(confirmation) != fields
        or confirmation.get("schema_version")
        != AUTHORITY_RECONCILIATION_SCHEMA_VERSION
        or confirmation.get("kind") != AUTHORITY_FENCE_CONFIRMATION_PURPOSE
        or confirmation.get("protocol_version") != PROTOCOL_VERSION
        or confirmation.get("service_key_id") != diagnostics.get("service_key_id")
        or confirmation.get("service_key_version")
        != diagnostics.get("service_key_version")
        or confirmation.get("authorized_client_sid")
        != diagnostics.get("client_sid")
        or confirmation.get("fence_id") != fence.get("fence_id")
        or confirmation.get("restore_operation_id") != request.operation_id
        or confirmation.get("state_digest") != fence.get("state_digest")
        or confirmation.get("version_digest") != fence.get("version_digest")
        or confirmation.get("authorization_digest")
        != fence.get("authorization_digest")
        or confirmation.get("backup_sha256") != request.backup_sha256
        or confirmation.get("project_scope") != list(request.project_scope)
        or confirmation.get("issued_at") != fence.get("issued_at")
        or confirmation.get("expires_at") != fence.get("expires_at")
        or datetime.fromisoformat(str(confirmation.get("confirmed_at")))
        > datetime.now(UTC)
        or datetime.fromisoformat(str(confirmation.get("expires_at")))
        <= datetime.now(UTC)
        or not authority.verify(
            AUTHORITY_FENCE_CONFIRMATION_PURPOSE, confirmation
        )
    ):
        raise PermissionError("Authority restore fence confirmation is invalid")
    return confirmation


def _finish_authority_fence(
    authority: ProductionAuthorityServiceClient | TestAuthorityServiceClient,
    diagnostics: dict[str, Any],
    request: RestoreRequest,
    fence: dict[str, Any],
    state: str,
) -> dict[str, Any]:
    if state == "COMPLETED":
        result = authority.complete_executive_restore_fence(
            str(fence["fence_id"]), request.operation_id
        )
    elif state == "ABORTED":
        result = authority.abort_executive_restore_fence(
            str(fence["fence_id"]), request.operation_id
        )
    else:
        raise ValueError("Authority restore fence outcome is invalid")
    outcome = result.get("outcome")
    fields = {
        "schema_version",
        "kind",
        "protocol_version",
        "service_key_id",
        "authorized_client_sid",
        "fence_id",
        "restore_operation_id",
        "state",
        "finished_at",
        "service_key_version",
        "authority_schema_version",
        "authority_key_id",
        "authenticated_writer_proof",
    }
    if (
        not isinstance(outcome, dict)
        or set(outcome) != fields
        or outcome.get("schema_version")
        != AUTHORITY_RECONCILIATION_SCHEMA_VERSION
        or outcome.get("kind") != AUTHORITY_FENCE_OUTCOME_PURPOSE
        or outcome.get("protocol_version") != PROTOCOL_VERSION
        or outcome.get("service_key_id") != diagnostics.get("service_key_id")
        or outcome.get("service_key_version")
        != diagnostics.get("service_key_version")
        or outcome.get("authorized_client_sid") != diagnostics.get("client_sid")
        or outcome.get("fence_id") != fence.get("fence_id")
        or outcome.get("restore_operation_id") != request.operation_id
        or outcome.get("state") != state
        or not authority.verify(AUTHORITY_FENCE_OUTCOME_PURPOSE, outcome)
    ):
        raise PermissionError("Authority restore fence outcome is invalid")
    return outcome

def _capture_live_safety_ledger(
    connection: sqlite3.Connection, request: RestoreRequest
) -> dict[str, Any]:
    return _read_safety_ledger(connection, set(request.project_scope))


def _read_safety_ledger(
    connection: sqlite3.Connection, project_scope: set[str]
) -> dict[str, Any]:
    consumptions = [
        dict(row)
        for row in connection.execute(
            "SELECT approval_id,project_id,charter_id,charter_revision,"
            "action_id,task_id,consumed_at "
            "FROM executive_approval_consumptions ORDER BY approval_id"
        ).fetchall()
        if row["project_id"] in project_scope
    ]
    budgets = [
        dict(row)
        for row in connection.execute(
            "SELECT reservation_id,project_id,charter_id,charter_revision,"
            "approval_id,action_id,task_id,amount_minor,currency,state,reserved_at "
            "FROM executive_budget_reservations ORDER BY reservation_id"
        ).fetchall()
        if row["project_id"] in project_scope
    ]
    required_approvals = {
        str(item["approval_id"]) for item in [*consumptions, *budgets]
    }
    approvals: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    for table, destination in (
        ("executive_approvals", approvals),
        ("executive_execution_attempts", attempts),
    ):
        rows = connection.execute(
            f'SELECT id,schema_version,created_at,updated_at,payload,payload_hash '
            f'FROM "{table}" ORDER BY id'
        ).fetchall()
        for row in rows:
            serialized = str(row["payload"])
            if _sha256(serialized.encode("utf-8")) != row["payload_hash"]:
                raise RuntimeError(f"{table} safety record integrity failed")
            payload = json.loads(serialized)
            if not isinstance(payload, dict):
                raise RuntimeError(f"{table} safety record is malformed")
            if payload.get("project_id") not in project_scope:
                continue
            if table == "executive_approvals":
                if (
                    row["id"] not in required_approvals
                    and payload.get("consumed_at") is None
                    and payload.get("revoked_at") is None
                ):
                    continue
            elif (
                payload.get("approval_id") not in required_approvals
                and payload.get("budget_reservation_id")
                not in {item["reservation_id"] for item in budgets}
            ):
                continue
            destination.append(
                {
                    "id": str(row["id"]),
                    "schema_version": int(row["schema_version"]),
                    "created_at": str(row["created_at"]),
                    "updated_at": str(row["updated_at"]),
                    "payload": payload,
                    "payload_hash": str(row["payload_hash"]),
                }
            )
    approval_by_id = {item["id"]: item["payload"] for item in approvals}
    for consumption in consumptions:
        approval = approval_by_id.get(consumption["approval_id"])
        if (
            approval is None
            or approval.get("kind") != "ONE_TIME"
            or approval.get("consumed_at") is None
            or approval.get("project_id") != consumption["project_id"]
            or approval.get("charter_id") != consumption["charter_id"]
            or approval.get("charter_revision")
            != consumption["charter_revision"]
        ):
            raise PermissionError("live approval consumption safety ledger is ambiguous")
    for budget in budgets:
        approval = approval_by_id.get(budget["approval_id"])
        if (
            approval is None
            or approval.get("project_id") != budget["project_id"]
            or approval.get("charter_id") != budget["charter_id"]
            or approval.get("charter_revision") != budget["charter_revision"]
            or budget["state"] not in {"RESERVED", "CROSSED", "RELEASED"}
        ):
            raise PermissionError("live budget safety ledger is ambiguous")
    value: dict[str, Any] = {
        "project_scope": sorted(project_scope),
        "approvals": approvals,
        "consumptions": consumptions,
        "budgets": budgets,
        "attempt_bindings": attempts,
    }
    value["digest"] = _digest(value)
    return value


def _merge_live_safety_ledger(
    connection: sqlite3.Connection, live: dict[str, Any]
) -> dict[str, Any]:
    unsigned = {key: value for key, value in live.items() if key != "digest"}
    if live.get("digest") != _digest(unsigned):
        raise PermissionError("live Executive safety ledger digest is invalid")
    scope_value = live.get("project_scope")
    approvals = live.get("approvals")
    consumptions = live.get("consumptions")
    budgets = live.get("budgets")
    attempts = live.get("attempt_bindings")
    if (
        not isinstance(scope_value, list)
        or not isinstance(approvals, list)
        or not isinstance(consumptions, list)
        or not isinstance(budgets, list)
        or not isinstance(attempts, list)
    ):
        raise PermissionError("live Executive safety ledger is malformed")
    try:
        for approval_row in approvals:
            if not isinstance(approval_row, dict):
                raise PermissionError("live approval safety row is malformed")
            _merge_approval_safety(connection, approval_row)
        for consumption in consumptions:
            if not isinstance(consumption, dict):
                raise PermissionError("live approval consumption is malformed")
            existing = connection.execute(
                "SELECT project_id,charter_id,charter_revision,action_id,task_id,"
                "consumed_at FROM executive_approval_consumptions "
                "WHERE approval_id=?",
                (consumption["approval_id"],),
            ).fetchone()
            expected = tuple(
                consumption[key]
                for key in (
                    "project_id",
                    "charter_id",
                    "charter_revision",
                    "action_id",
                    "task_id",
                    "consumed_at",
                )
            )
            if existing is None:
                connection.execute(
                    "INSERT INTO executive_approval_consumptions "
                    "VALUES(?,?,?,?,?,?,?)",
                    (consumption["approval_id"], *expected),
                )
            elif tuple(existing)[:5] != expected[:5]:
                raise PermissionError(
                    "approval consumption conflicts with restored safety state"
                )
            elif existing["consumed_at"] != consumption["consumed_at"]:
                connection.execute(
                    "UPDATE executive_approval_consumptions SET consumed_at=? "
                    "WHERE approval_id=?",
                    (consumption["consumed_at"], consumption["approval_id"]),
                )
        for budget in budgets:
            if not isinstance(budget, dict):
                raise PermissionError("live budget reservation is malformed")
            _merge_budget_safety(connection, budget)
        for attempt in attempts:
            if not isinstance(attempt, dict):
                raise PermissionError("live attempt safety binding is malformed")
            staged = _entity(
                connection, "executive_execution_attempts", str(attempt["id"])
            )
            live_payload = attempt.get("payload")
            if not isinstance(live_payload, dict):
                raise PermissionError("live attempt safety payload is malformed")
            if staged is None:
                for table, field in (
                    ("executive_projects", "project_id"),
                    ("project_charters", "charter_id"),
                    ("executive_tasks", "task_id"),
                ):
                    parent_id = live_payload.get(field)
                    if not isinstance(parent_id, str) or _entity(
                        connection, table, parent_id
                    ) is None:
                        raise PermissionError(
                            "restored state omits a live safety-attempt parent"
                        )
                serialized = _serialized(live_payload)
                connection.execute(
                    'INSERT INTO "executive_execution_attempts" VALUES(?,?,?,?,?,?)',
                    (
                        str(attempt["id"]),
                        int(attempt["schema_version"]),
                        str(attempt["created_at"]),
                        str(attempt["updated_at"]),
                        serialized,
                        _sha256(serialized.encode("utf-8")),
                    ),
                )
                staged = live_payload
            for field in (
                "project_id",
                "charter_id",
                "charter_revision",
                "task_id",
                "action_id",
                "approval_id",
                "budget_reservation_id",
                "authority_attempt_id",
            ):
                if staged.get(field) != live_payload.get(field):
                    raise PermissionError(
                        "execution attempt conflicts with live safety binding"
                    )
    except sqlite3.IntegrityError as error:
        raise PermissionError(
            "live Executive safety ledger cannot be merged unambiguously"
        ) from error
    merged = _read_safety_ledger(connection, set(scope_value))
    return {
        "captured_digest": live["digest"],
        "merged_digest": merged["digest"],
        "approval_count": len(merged["approvals"]),
        "consumption_count": len(merged["consumptions"]),
        "budget_count": len(merged["budgets"]),
        "attempt_binding_count": len(merged["attempt_bindings"]),
        "approval_ids": sorted(item["id"] for item in merged["approvals"]),
        "consumption_ids": sorted(
            item["approval_id"] for item in merged["consumptions"]
        ),
        "budget_ids": sorted(
            item["reservation_id"] for item in merged["budgets"]
        ),
        "attempt_ids": sorted(
            item["id"] for item in merged["attempt_bindings"]
        ),
    }


def _merge_approval_safety(
    connection: sqlite3.Connection, live_row: dict[str, Any]
) -> None:
    identifier = str(live_row["id"])
    live_payload = live_row.get("payload")
    if not isinstance(live_payload, dict):
        raise PermissionError("live approval safety payload is malformed")
    project = _entity(connection, "executive_projects", str(live_payload["project_id"]))
    charter = _entity(connection, "project_charters", str(live_payload["charter_id"]))
    if project is None or charter is None:
        raise PermissionError("restored state omits an approval safety parent")
    row = connection.execute(
        'SELECT schema_version,created_at,payload FROM "executive_approvals" '
        "WHERE id=?",
        (identifier,),
    ).fetchone()
    if row is None:
        serialized = _serialized(live_payload)
        connection.execute(
            'INSERT INTO "executive_approvals" VALUES(?,?,?,?,?,?)',
            (
                identifier,
                live_row["schema_version"],
                live_row["created_at"],
                live_row["updated_at"],
                serialized,
                _sha256(serialized.encode("utf-8")),
            ),
        )
        return
    staged_payload = json.loads(str(row["payload"]))
    if not isinstance(staged_payload, dict):
        raise PermissionError("restored approval safety payload is malformed")
    monotonic = {"consumed_at", "revoked_at"}
    if (
        int(row["schema_version"]) != int(live_row["schema_version"])
        or str(row["created_at"]) != str(live_row["created_at"])
        or {key: value for key, value in staged_payload.items() if key not in monotonic}
        != {key: value for key, value in live_payload.items() if key not in monotonic}
    ):
        raise PermissionError("approval safety binding conflicts with restored state")
    merged = dict(staged_payload)
    for field in monotonic:
        if live_payload.get(field) is not None:
            merged[field] = live_payload[field]
    _update_entity(connection, "executive_approvals", identifier, merged)


def _merge_budget_safety(
    connection: sqlite3.Connection, live: dict[str, Any]
) -> None:
    fields = (
        "project_id",
        "charter_id",
        "charter_revision",
        "approval_id",
        "action_id",
        "task_id",
        "amount_minor",
        "currency",
        "reserved_at",
    )
    row = connection.execute(
        "SELECT project_id,charter_id,charter_revision,approval_id,action_id,"
        "task_id,amount_minor,currency,state,reserved_at "
        "FROM executive_budget_reservations WHERE reservation_id=?",
        (live["reservation_id"],),
    ).fetchone()
    if row is None:
        connection.execute(
            "INSERT INTO executive_budget_reservations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                live["reservation_id"],
                *(live[field] for field in fields[:-1]),
                live["state"],
                live["reserved_at"],
            ),
        )
        return
    if tuple(row[field] for field in fields) != tuple(live[field] for field in fields):
        raise PermissionError("budget safety binding conflicts with restored state")
    state = "CROSSED" if "CROSSED" in {row["state"], live["state"]} else live["state"]
    connection.execute(
        "UPDATE executive_budget_reservations SET state=? WHERE reservation_id=?",
        (state, live["reservation_id"]),
    )


def _reconcile_staged(
    path: Path,
    request: RestoreRequest,
    receipt: dict[str, Any],
    live_safety: dict[str, Any],
) -> dict[str, Any]:
    checked_attempts: list[dict[str, Any]] = []
    with _connection(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _validate_source_identity(connection, request)
        projects = _project_scope(connection)
        if not projects.issubset(set(request.project_scope)):
            raise PermissionError("restored project scope exceeds Founder authorization")
        safety_ledger = _merge_live_safety_ledger(connection, live_safety)
        launch_authorizations = _authority_launch_authorizations(receipt, request)
        for authority_attempt in receipt["attempts"]:
            if not isinstance(authority_attempt, dict):
                raise PermissionError("Authority attempt evidence is malformed")
            attempt_id = authority_attempt.get("id")
            service_state = authority_attempt.get("service_state")
            project_id = authority_attempt.get("project_id")
            if (
                not isinstance(attempt_id, str)
                or service_state
                not in {
                    "RESERVED",
                    "LAUNCH_CLAIMED",
                    "EXECUTION_STARTED",
                    "PAUSED",
                    "COMPLETED",
                    "FAILED",
                    "CANCELLED",
                }
                or project_id not in request.project_scope
            ):
                raise PermissionError("Authority attempt reconciliation is invalid")
            launch_authorization_id = authority_attempt.get(
                "launch_authorization_id"
            )
            launch_authorization = launch_authorizations.get(
                launch_authorization_id
            ) if isinstance(launch_authorization_id, str) else None
            if (
                launch_authorization is None
                or launch_authorization.get("project_id") != project_id
                or launch_authorization.get("authorization_generation")
                != authority_attempt.get("authorization_generation")
            ):
                raise PermissionError(
                    "Authority attempt omits its launch authorization state"
                )
            executive = _entity(connection, "executive_execution_attempts", attempt_id)
            if executive is None:
                raise PermissionError(
                    "restored Executive state omits an Authority attempt"
                )
            for field in (
                "project_id",
                "charter_id",
                "charter_revision",
                "task_id",
                "stage_id",
                "role",
                "registration_id",
                "provider_run_id",
                "provider_instance_id",
                "launch_authorization_id",
                "authorization_generation",
            ):
                if executive.get(field) != authority_attempt.get(field):
                    raise PermissionError(
                        "restored attempt is misbound to Authority evidence"
                    )
            safety = _validate_attempt_safety(
                connection, executive, authority_attempt
            )
            authority_digest = _digest(
                {
                    key: value
                    for key, value in authority_attempt.items()
                    if key != "service_state"
                }
            )
            if service_state in TERMINAL_AUTHORITY_STATES:
                current_digest = executive.get("completion_digest")
                if current_digest not in {None, authority_digest}:
                    raise PermissionError(
                        "restored completion conflicts with newer Authority truth"
                    )
                if current_digest is None:
                    updated = {
                        **executive,
                        "state": "UNCERTAIN",
                        "completion_digest": authority_digest,
                        "authority_terminal_state": service_state,
                        "authority_reconciled_at": receipt["issued_at"],
                        "updated_at": receipt["issued_at"],
                    }
                    _update_entity(
                        connection,
                        "executive_execution_attempts",
                        attempt_id,
                        updated,
                    )
                    _mark_task_uncertain(
                        connection,
                        str(authority_attempt["task_id"]),
                        attempt_id,
                        receipt["issued_at"],
                    )
            checked_attempts.append(
                {
                    "attempt_id": attempt_id,
                    "authority_state": service_state,
                    **safety,
                }
            )
        return {
            "attempts": checked_attempts,
            "project_scope": list(request.project_scope),
            "launch_authorization_count": len(receipt["launch_authorizations"]),
            "live_safety_ledger": safety_ledger,
        }


def _authority_launch_authorizations(
    receipt: dict[str, Any], request: RestoreRequest
) -> dict[str, dict[str, Any]]:
    authorizations: dict[str, dict[str, Any]] = {}
    for value in receipt["launch_authorizations"]:
        if not isinstance(value, dict):
            raise PermissionError("Authority launch authorization is malformed")
        identifier = value.get("id")
        project_id = value.get("project_id")
        generation = value.get("authorization_generation")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in authorizations
            or project_id not in request.project_scope
            or type(generation) is not int
            or generation <= 0
            or value.get("service_state") not in {"ACTIVE", "REVOKED"}
        ):
            raise PermissionError(
                "Authority launch authorization reconciliation is invalid"
            )
        authorizations[identifier] = value
    return authorizations


def _validate_attempt_safety(
    connection: sqlite3.Connection,
    executive: dict[str, Any],
    authority: dict[str, Any],
) -> dict[str, Any]:
    approval_id = executive.get("approval_id")
    approval_state = "NOT_REQUIRED"
    if isinstance(approval_id, str):
        approval = _entity(connection, "executive_approvals", approval_id)
        if approval is None:
            raise PermissionError("restored attempt omits its approval")
        approval_state = "PRESERVED"
        if approval.get("kind") == "ONE_TIME":
            consumption = connection.execute(
                "SELECT project_id,action_id,task_id "
                "FROM executive_approval_consumptions WHERE approval_id=?",
                (approval_id,),
            ).fetchone()
            if (
                approval.get("consumed_at") is None
                or consumption is None
                or consumption["project_id"] != executive.get("project_id")
                or consumption["action_id"] != executive.get("action_id")
                or consumption["task_id"] != executive.get("task_id")
            ):
                raise PermissionError(
                    "restored one-time approval consumption is incomplete"
                )
            approval_state = "ONE_TIME_CONSUMED"

    reservation_id = executive.get("budget_reservation_id")
    budget_state = "NOT_REQUIRED"
    if isinstance(reservation_id, str):
        reservation = connection.execute(
            "SELECT project_id,approval_id,action_id,task_id,state "
            "FROM executive_budget_reservations WHERE reservation_id=?",
            (reservation_id,),
        ).fetchone()
        if (
            reservation is None
            or reservation["project_id"] != executive.get("project_id")
            or reservation["approval_id"] != approval_id
            or reservation["action_id"] != executive.get("action_id")
            or reservation["task_id"] != executive.get("task_id")
            or reservation["state"] not in {"RESERVED", "CROSSED"}
        ):
            raise PermissionError("restored budget reservation is incomplete")
        budget_state = str(reservation["state"])
        if authority.get("service_state") not in {"RESERVED", "LAUNCH_CLAIMED"}:
            connection.execute(
                "UPDATE executive_budget_reservations SET state='CROSSED' "
                "WHERE reservation_id=? AND state='RESERVED'",
                (reservation_id,),
            )
            budget_state = "CROSSED"
    return {
        "approval_state": approval_state,
        "budget_state": budget_state,
    }


def _mark_task_uncertain(
    connection: sqlite3.Connection,
    task_id: str,
    attempt_id: str,
    timestamp: str,
) -> None:
    task = _entity(connection, "executive_tasks", task_id)
    if task is None or task.get("authority_attempt_id") != attempt_id:
        raise PermissionError("restored Authority attempt has no bound task")
    if task.get("status") in {"COMPLETED", "FAILED", "CANCELED"}:
        return
    updated = {
        **task,
        "status": "UNCERTAIN",
        "revision": int(task.get("revision", 0)) + 1,
        "result_disposition": "RESTORE_AUTHORITY_RECONCILIATION_REQUIRED",
        "updated_at": timestamp,
    }
    _update_entity(connection, "executive_tasks", task_id, updated)


def _validate_source_identity(
    connection: sqlite3.Connection, request: RestoreRequest
) -> None:
    row = connection.execute(
        "SELECT r.database_id,r.recovery_epoch,w.generation "
        "FROM executive_recovery_state AS r "
        "JOIN executive_write_state AS w ON w.singleton=r.singleton "
        "WHERE r.singleton=1"
    ).fetchone()
    mode = connection.execute(
        "SELECT mode FROM executive_repository_mode WHERE singleton=1"
    ).fetchone()
    if (
        row is None
        or mode is None
        or mode["mode"] != "PRODUCTION"
        or row["database_id"] != request.source_database_id
        or int(row["recovery_epoch"]) != request.source_recovery_epoch
        or int(row["generation"]) != request.source_generation
    ):
        raise PermissionError("staged backup recovery identity is invalid")


def _validate_live_boundary(
    connection: sqlite3.Connection, request: RestoreRequest
) -> None:
    current = _live_identity(connection)
    _validate_target_identity(request, Path(request.target_canonical_path), current)
    lease = connection.execute(
        "SELECT operation_id,state,source_backup_sha256,expected_generation "
        "FROM executive_restore_maintenance WHERE singleton=1"
    ).fetchone()
    if (
        lease is None
        or lease["operation_id"] != request.operation_id
        or lease["state"] != "ACTIVE"
        or lease["source_backup_sha256"] != request.backup_sha256
        or int(lease["expected_generation"]) != request.target_generation
    ):
        raise RuntimeError("restore maintenance lease changed before replacement")


def _live_identity(connection: sqlite3.Connection) -> tuple[str, int, int, str]:
    row = connection.execute(
        "SELECT r.database_id,r.recovery_epoch,w.generation,m.mode "
        "FROM executive_recovery_state AS r "
        "JOIN executive_write_state AS w ON w.singleton=r.singleton "
        "JOIN executive_repository_mode AS m ON m.singleton=r.singleton "
        "WHERE r.singleton=1"
    ).fetchone()
    if row is None:
        raise PermissionError("live Executive recovery identity is missing")
    return (
        str(row["database_id"]),
        int(row["recovery_epoch"]),
        int(row["generation"]),
        str(row["mode"]),
    )


def _generation(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT generation FROM executive_write_state WHERE singleton=1"
    ).fetchone()
    if row is None:
        raise PermissionError("Executive write generation is missing")
    return int(row["generation"])


def _project_scope(connection: sqlite3.Connection) -> set[str]:
    values: set[str] = set()
    for row in connection.execute(
        'SELECT payload,payload_hash FROM "executive_projects"'
    ).fetchall():
        payload = str(row["payload"])
        if _sha256(payload.encode("utf-8")) != row["payload_hash"]:
            raise RuntimeError("restored project failed integrity validation")
        value = json.loads(payload)
        if not isinstance(value, dict) or not isinstance(
            value.get("project_id"), str
        ):
            raise RuntimeError("restored project scope is invalid")
        values.add(value["project_id"])
    return values


def _entity(
    connection: sqlite3.Connection, table: str, identifier: str
) -> dict[str, Any] | None:
    row = connection.execute(
        f'SELECT payload,payload_hash FROM "{table}" WHERE id=?',
        (identifier,),
    ).fetchone()
    if row is None:
        return None
    payload = str(row["payload"])
    if _sha256(payload.encode("utf-8")) != row["payload_hash"]:
        raise RuntimeError(f"restored {table} record failed integrity validation")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise RuntimeError(f"restored {table} record is malformed")
    return value


def _update_entity(
    connection: sqlite3.Connection,
    table: str,
    identifier: str,
    value: dict[str, Any],
) -> None:
    serialized = _serialized(value)
    cursor = connection.execute(
        f'UPDATE "{table}" SET updated_at=?,payload=?,payload_hash=? WHERE id=?',
        (
            str(value.get("updated_at", _now())),
            serialized,
            _sha256(serialized.encode("utf-8")),
            identifier,
        ),
    )
    if cursor.rowcount != 1:
        raise RuntimeError(f"restored {table} update was lost")


def _mark_restore_failed(path: Path, operation_id: str) -> None:
    with _connection(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE executive_restore_maintenance "
            "SET state='FAILED',finished_at=? "
            "WHERE singleton=1 AND operation_id=? AND state='ACTIVE'",
            (_now(), operation_id),
        )


@contextmanager
def _connection(path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    try:
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def _serialized(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return _sha256(_serialized(value).encode("utf-8"))


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
