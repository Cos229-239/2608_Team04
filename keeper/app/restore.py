from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from keeper.executive.founder_auth import (
    ProductionApprovalConfirmation,
    ProductionFounderAuthenticator,
    TestApprovalConfirmation,
    TestFounderAuthenticator,
)
from keeper.executive.models import FounderApprovalChallenge


RESTORE_SCHEMA_VERSION = 2
RESTORE_AUTHORIZATION_LIFETIME = timedelta(minutes=2)
RESTORE_APPROVAL_ACTION = "APPROVE_ACTION"


@dataclass(frozen=True, slots=True)
class RestoreRequest:
    schema_version: int
    operation_id: str
    backup_operation_id: str
    backup_artifact_path: str
    backup_sha256: str
    source_database_id: str
    source_recovery_epoch: int
    source_generation: int
    target_database_id: str
    target_canonical_path: str
    target_recovery_epoch: int
    target_generation: int
    project_scope: tuple[str, ...]
    reason: str
    requested_at: str
    expires_at: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["project_scope"] = list(self.project_scope)
        return value


@dataclass(frozen=True, slots=True)
class ProductionRestoreAuthorization:
    request: RestoreRequest
    challenge: FounderApprovalChallenge
    confirmation: ProductionApprovalConfirmation


@dataclass(frozen=True, slots=True)
class TestRestoreAuthorization:
    __test__ = False
    request: RestoreRequest
    challenge: FounderApprovalChallenge
    confirmation: TestApprovalConfirmation


@dataclass(frozen=True, slots=True)
class TestRestoreHooks:
    __test__ = False
    after_maintenance_acquired: Callable[[], None] | None = None
    before_final_generation_check: Callable[[], None] | None = None
    before_live_replacement: Callable[[], None] | None = None


def prepare_production_restore_authorization(
    store_path: Path,
    backup: Path,
    *,
    reason: str,
    authenticator: ProductionFounderAuthenticator,
) -> ProductionRestoreAuthorization:
    if type(authenticator) is not ProductionFounderAuthenticator:
        raise TypeError("production restore requires the production Founder authenticator")
    request = build_restore_request(store_path, backup, reason=reason)
    challenge = _challenge(request)
    return ProductionRestoreAuthorization(
        request, challenge, authenticator.authenticate(challenge)
    )


def prepare_test_restore_authorization(
    store_path: Path,
    backup: Path,
    *,
    reason: str,
    authenticator: TestFounderAuthenticator,
) -> TestRestoreAuthorization:
    if type(authenticator) is not TestFounderAuthenticator:
        raise TypeError("test restore requires the test Founder authenticator")
    request = build_restore_request(store_path, backup, reason=reason)
    challenge = _challenge(request)
    return TestRestoreAuthorization(
        request, challenge, authenticator.authenticate(challenge)
    )


def build_restore_request(
    store_path: Path,
    backup: Path,
    *,
    reason: str,
) -> RestoreRequest:
    target = store_path.resolve()
    source = backup.resolve()
    cleaned_reason = reason.strip()
    if not cleaned_reason:
        raise ValueError("restore reason is required")
    operation_id = uuid.uuid4().hex
    backup_operation_id = uuid.uuid4().hex
    artifact = _prepare_immutable_artifact(source, backup_operation_id)
    target_binding, target_projects = _database_restore_identity(target)
    source_binding, source_projects = _database_restore_identity(artifact)
    now = datetime.now(UTC)
    return RestoreRequest(
        RESTORE_SCHEMA_VERSION,
        operation_id,
        backup_operation_id,
        _canonical_path(artifact),
        sha256_file(artifact),
        source_binding[0],
        source_binding[1],
        source_binding[2],
        target_binding[0],
        _canonical_path(target),
        target_binding[1],
        target_binding[2],
        tuple(sorted(target_projects | source_projects)),
        cleaned_reason,
        now.isoformat(),
        (now + RESTORE_AUTHORIZATION_LIFETIME).isoformat(),
    )


def restore_request_digest(request: RestoreRequest) -> str:
    return hashlib.sha256(
        json.dumps(
            request.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def restore_authorization_digest(
    authorization: ProductionRestoreAuthorization | TestRestoreAuthorization,
) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "request": authorization.request.to_dict(),
                "challenge": authorization.challenge.to_dict(),
                "confirmation": asdict(authorization.confirmation),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _prepare_immutable_artifact(source: Path, operation_id: str) -> Path:
    if not source.is_file():
        raise FileNotFoundError(source)
    artifact = source.with_name(
        f".{source.name}.{operation_id}.keeper-restore.db"
    ).resolve()
    temporary = artifact.with_name(f".{artifact.name}.{uuid.uuid4().hex}.tmp")
    if artifact.exists():
        raise FileExistsError(artifact)
    try:
        _sqlite_backup(source, temporary)
        _verify_sqlite_integrity(temporary)
        os.replace(temporary, artifact)
        return artifact
    finally:
        temporary.unlink(missing_ok=True)
        Path(f"{temporary}-wal").unlink(missing_ok=True)
        Path(f"{temporary}-shm").unlink(missing_ok=True)


def _sqlite_backup(source: Path, destination: Path) -> None:
    source_connection = sqlite3.connect(source)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
        destination_connection.commit()
    finally:
        destination_connection.close()
        source_connection.close()


def _verify_sqlite_integrity(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        if [
            str(row[0])
            for row in connection.execute("PRAGMA integrity_check").fetchall()
        ] != ["ok"]:
            raise RuntimeError("restore artifact failed SQLite integrity validation")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise RuntimeError("restore artifact failed foreign-key validation")
    except sqlite3.DatabaseError as error:
        raise RuntimeError("restore artifact is corrupt or unreadable") from error
    finally:
        connection.close()


def _challenge(request: RestoreRequest) -> FounderApprovalChallenge:
    return FounderApprovalChallenge(
        challenge_id=f"restore-challenge-{uuid.uuid4().hex}",
        schema_version=2,
        project_id=f"restore-scope:{_scope_digest(request.project_scope)}",
        charter_id="keeper-executive-restore",
        charter_revision=request.target_recovery_epoch + 1,
        charter_digest=restore_request_digest(request),
        approval_action=RESTORE_APPROVAL_ACTION,
        approval_binding=request.to_dict(),
        nonce=secrets.token_hex(32),
        requested_at=request.requested_at,
        expires_at=request.expires_at,
        state="PENDING",
        consumed_event_id=None,
    )


def _database_restore_identity(path: Path) -> tuple[tuple[str, int, int], set[str]]:
    if not path.is_file():
        raise FileNotFoundError(path)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT database_id,recovery_epoch FROM executive_recovery_state "
            "WHERE singleton=1"
        ).fetchone()
        mode = connection.execute(
            "SELECT mode FROM executive_repository_mode WHERE singleton=1"
        ).fetchone()
        generation_row = connection.execute(
            "SELECT generation FROM executive_write_state WHERE singleton=1"
        ).fetchone()
        if (
            row is None
            or mode is None
            or mode["mode"] != "PRODUCTION"
            or generation_row is None
        ):
            raise PermissionError(
                "restore source and target require production recovery identities"
            )
        projects: set[str] = set()
        for project in connection.execute(
            'SELECT payload FROM "executive_projects"'
        ).fetchall():
            value = json.loads(str(project["payload"]))
            if not isinstance(value, dict) or not isinstance(
                value.get("project_id"), str
            ):
                raise RuntimeError("Executive project restore scope is invalid")
            projects.add(value["project_id"])
        return (
            str(row["database_id"]),
            int(row["recovery_epoch"]),
            int(generation_row["generation"]),
        ), projects
    except sqlite3.DatabaseError as error:
        raise RuntimeError("restore database identity is unreadable") from error
    finally:
        connection.close()


def _canonical_path(path: Path) -> str:
    return os.path.normcase(str(path.resolve()))


def _scope_digest(project_scope: tuple[str, ...]) -> str:
    return hashlib.sha256(
        json.dumps(list(project_scope), separators=(",", ":")).encode("utf-8")
    ).hexdigest()
