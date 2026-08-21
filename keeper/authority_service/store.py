from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterator


SERVICE_SCHEMA_VERSION = 6
_EXPECTED_TABLES = {
    "attempts",
    "audit_log",
    "qualifications",
    "registrations",
    "replay_guard",
    "service_meta",
    "launch_authorizations",
    "founder_capability_consumptions",
    "authority_project_versions",
    "restore_reconciliation_fences",
    "provider_host_enrollments",
}


class AuthorityStore:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
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

    def migrate(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS service_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS replay_guard(
                    request_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    nonce TEXT NOT NULL UNIQUE,
                    client_sid TEXT NOT NULL,
                    received_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS registrations(
                    id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS qualifications(
                    id TEXT PRIMARY KEY,
                    registration_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    challenge TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(registration_id) REFERENCES registrations(id)
                );
                CREATE TABLE IF NOT EXISTS attempts(
                    id TEXT PRIMARY KEY,
                    registration_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    challenge TEXT NOT NULL UNIQUE,
                    run_id TEXT NOT NULL,
                    attempt_number INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(registration_id) REFERENCES registrations(id)
                );
                CREATE TABLE IF NOT EXISTS launch_authorizations(
                    id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    client_sid TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS founder_capability_consumptions(
                    capability_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    approval_record_id TEXT NOT NULL,
                    approval_event_id TEXT NOT NULL,
                    founder_session_id TEXT NOT NULL,
                    challenge_id TEXT NOT NULL,
                    approval_digest TEXT NOT NULL,
                    challenge_proof_digest TEXT NOT NULL,
                    capability_digest TEXT NOT NULL UNIQUE,
                    signature_digest TEXT NOT NULL UNIQUE,
                    generation INTEGER NOT NULL,
                    authorization_id TEXT NOT NULL UNIQUE,
                    consumed_at TEXT NOT NULL,
                    UNIQUE(project_id, approval_record_id),
                    UNIQUE(project_id, approval_event_id),
                    UNIQUE(project_id, founder_session_id),
                    UNIQUE(project_id, challenge_id),
                    UNIQUE(project_id, approval_digest),
                    UNIQUE(project_id, challenge_proof_digest)
                );
                CREATE TABLE IF NOT EXISTS authority_project_versions(
                    project_id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL CHECK(version>=0),
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS restore_reconciliation_fences(
                    fence_id TEXT PRIMARY KEY,
                    restore_operation_id TEXT NOT NULL UNIQUE,
                    client_sid TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN
                        ('ACTIVE','COMPLETED','ABORTED','EXPIRED')),
                    project_scope TEXT NOT NULL,
                    state_digest TEXT NOT NULL,
                    version_digest TEXT NOT NULL,
                    authorization_digest TEXT NOT NULL,
                    backup_sha256 TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    client_sid TEXT NOT NULL,
                    object_id TEXT,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS provider_host_enrollments(
                    id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            row = connection.execute(
                "SELECT value FROM service_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO service_meta(key,value) VALUES('schema_version',?)",
                    (str(SERVICE_SCHEMA_VERSION),),
                )
            elif int(row["value"]) == 1:
                connection.executescript(
                    """
                    ALTER TABLE attempts RENAME TO attempts_v1;
                    CREATE TABLE attempts(
                        id TEXT PRIMARY KEY,
                        registration_id TEXT NOT NULL,
                        state TEXT NOT NULL,
                        challenge TEXT NOT NULL UNIQUE,
                        run_id TEXT NOT NULL,
                        attempt_number INTEGER NOT NULL,
                        payload TEXT NOT NULL,
                        payload_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY(registration_id) REFERENCES registrations(id)
                    );
                    INSERT INTO attempts SELECT * FROM attempts_v1;
                    DROP TABLE attempts_v1;
                    CREATE TABLE IF NOT EXISTS launch_authorizations(
                        id TEXT PRIMARY KEY,
                        state TEXT NOT NULL,
                        generation INTEGER NOT NULL,
                        client_sid TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        payload_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    UPDATE service_meta SET value='6' WHERE key='schema_version';
                    """
                )
            elif int(row["value"]) == 2:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS launch_authorizations(
                        id TEXT PRIMARY KEY,
                        state TEXT NOT NULL,
                        generation INTEGER NOT NULL,
                        client_sid TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        payload_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    UPDATE service_meta SET value='6' WHERE key='schema_version';
                    """
                )
            elif int(row["value"]) in {3, 4}:
                connection.execute(
                    "UPDATE service_meta SET value='6' WHERE key='schema_version'"
                )
            elif int(row["value"]) == 5:
                connection.execute(
                    "UPDATE service_meta SET value='6' WHERE key='schema_version'"
                )
            elif int(row["value"]) != SERVICE_SCHEMA_VERSION:
                raise RuntimeError("authority service schema is incompatible")
            self._backfill_founder_capability_consumptions(connection)

    @staticmethod
    def _backfill_founder_capability_consumptions(
        connection: sqlite3.Connection,
    ) -> None:
        rows = connection.execute(
            "SELECT id,generation,payload,payload_hash FROM launch_authorizations"
        ).fetchall()
        for row in rows:
            serialized = str(row["payload"])
            if hashlib.sha256(serialized.encode("utf-8")).hexdigest() != row["payload_hash"]:
                raise RuntimeError(
                    "stored launch authorization failed integrity validation"
                )
            payload = json.loads(serialized)
            if not isinstance(payload, dict):
                raise RuntimeError("stored launch authorization is malformed")
            authorization_id = str(row["id"])
            project_id = str(payload["project_id"])
            legacy = {
                "capability_id": str(
                    payload.get("founder_capability_id")
                    or f"legacy-capability:{authorization_id}"
                ),
                "project_id": project_id,
                "approval_record_id": str(payload["delegation_id"]),
                "approval_event_id": str(payload["founder_approval_event_id"]),
                "founder_session_id": str(
                    payload["founder_authenticated_session_id"]
                ),
                "challenge_id": str(
                    payload.get("founder_challenge_id")
                    or f"legacy-challenge:{authorization_id}"
                ),
                "approval_digest": str(
                    payload.get("founder_approval_digest")
                    or payload["founder_approval_event_digest"]
                ),
                "challenge_proof_digest": str(
                    payload.get("founder_challenge_proof_digest")
                    or f"legacy-proof:{authorization_id}"
                ),
                "capability_digest": str(
                    payload.get("founder_capability_digest")
                    or hashlib.sha256(
                        f"legacy-capability:{authorization_id}".encode("utf-8")
                    ).hexdigest()
                ),
                "signature_digest": str(
                    payload.get("founder_capability_signature_digest")
                    or hashlib.sha256(
                        f"legacy-signature:{authorization_id}".encode("utf-8")
                    ).hexdigest()
                ),
                "generation": int(row["generation"]),
                "authorization_id": authorization_id,
                "consumed_at": str(
                    payload.get("authorized_at") or _now()
                ),
            }
            existing = connection.execute(
                "SELECT authorization_id FROM founder_capability_consumptions "
                "WHERE authorization_id=?",
                (authorization_id,),
            ).fetchone()
            if existing is not None:
                continue
            try:
                connection.execute(
                    "INSERT INTO founder_capability_consumptions VALUES("
                    ":capability_id,:project_id,:approval_record_id,"
                    ":approval_event_id,:founder_session_id,:challenge_id,"
                    ":approval_digest,:challenge_proof_digest,"
                    ":capability_digest,:signature_digest,:generation,"
                    ":authorization_id,:consumed_at)",
                    legacy,
                )
            except sqlite3.IntegrityError as error:
                raise RuntimeError(
                    "legacy Founder approval identities are not project-unique"
                ) from error

    def consume_request(
        self,
        request_id: str,
        operation_id: str,
        nonce: str,
        client_sid: str,
    ) -> None:
        try:
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO replay_guard VALUES(?,?,?,?,?)",
                    (request_id, operation_id, nonce, client_sid, _now()),
                )
        except sqlite3.IntegrityError as error:
            raise PermissionError("authority request replay was rejected") from error

    def insert(
        self,
        table: str,
        identifier: str,
        state: str,
        payload: dict[str, Any],
        *,
        registration_id: str | None = None,
        run_id: str | None = None,
        attempt_number: int | None = None,
        challenge: str | None = None,
    ) -> None:
        serialized, digest = _serialize(payload)
        timestamp = _now()
        try:
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                project_id = (
                    _payload_project_id(payload)
                    if table in {"attempts", "launch_authorizations"}
                    else None
                )
                if project_id is not None:
                    self._assert_projects_unfenced(connection, {project_id})
                if table == "registrations":
                    connection.execute(
                        "INSERT INTO registrations VALUES(?,?,?,?,?,?)",
                        (identifier, state, serialized, digest, timestamp, timestamp),
                    )
                elif table == "qualifications":
                    connection.execute(
                        "INSERT INTO qualifications VALUES(?,?,?,?,?,?,?,?)",
                        (
                            identifier,
                            registration_id,
                            state,
                            challenge,
                            serialized,
                            digest,
                            timestamp,
                            timestamp,
                        ),
                    )
                elif table == "attempts":
                    connection.execute(
                        "INSERT INTO attempts VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            identifier,
                            registration_id,
                            state,
                            challenge,
                            run_id,
                            attempt_number,
                            serialized,
                            digest,
                            timestamp,
                            timestamp,
                        ),
                    )
                elif table == "launch_authorizations":
                    connection.execute(
                        "INSERT INTO launch_authorizations VALUES(?,?,?,?,?,?,?,?)",
                        (
                            identifier,
                            state,
                            attempt_number,
                            run_id,
                            serialized,
                            digest,
                            timestamp,
                            timestamp,
                        ),
                    )
                elif table == "provider_host_enrollments":
                    connection.execute(
                        "INSERT INTO provider_host_enrollments VALUES(?,?,?,?,?,?)",
                        (identifier, state, serialized, digest, timestamp, timestamp),
                    )
                else:
                    raise ValueError("unsupported authority table")
                if project_id is not None:
                    self._bump_project_version(connection, project_id)
        except sqlite3.IntegrityError as error:
            raise PermissionError(
                f"authority {table} identity is already reserved"
            ) from error

    def get(self, table: str, identifier: str) -> dict[str, Any] | None:
        if table not in {
            "registrations", "qualifications", "attempts",
            "launch_authorizations", "provider_host_enrollments",
        }:
            raise ValueError("unsupported authority table")
        with self.connect() as connection:
            row = connection.execute(
                f"SELECT state,payload,payload_hash FROM {table} WHERE id=?",
                (identifier,),
            ).fetchone()
        if row is None:
            return None
        payload = str(row["payload"])
        if hashlib.sha256(payload.encode("utf-8")).hexdigest() != row["payload_hash"]:
            raise RuntimeError(f"authority {table} record integrity failed")
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise RuntimeError(f"authority {table} record is malformed")
        return {**value, "service_state": str(row["state"])}

    def transition(
        self,
        table: str,
        identifier: str,
        expected_state: str,
        state: str,
        payload: dict[str, Any],
        *,
        before_transition: Callable[[], None] | None = None,
    ) -> None:
        if table not in {
            "registrations", "qualifications", "attempts",
            "launch_authorizations", "provider_host_enrollments",
        }:
            raise ValueError("unsupported authority table")
        serialized, digest = _serialize(payload)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            project_id: str | None = None
            if table in {"attempts", "launch_authorizations"}:
                current = connection.execute(
                    f"SELECT payload,payload_hash FROM {table} WHERE id=?",
                    (identifier,),
                ).fetchone()
                if current is None:
                    raise PermissionError(
                        f"authority {table} lifecycle transition was rejected"
                    )
                current_serialized = str(current["payload"])
                if (
                    hashlib.sha256(current_serialized.encode("utf-8")).hexdigest()
                    != current["payload_hash"]
                ):
                    raise RuntimeError(f"authority {table} record integrity failed")
                current_payload = json.loads(current_serialized)
                if not isinstance(current_payload, dict):
                    raise RuntimeError(f"authority {table} record is malformed")
                project_id = _payload_project_id(current_payload)
                replacement_project = payload.get("project_id")
                if replacement_project is not None and replacement_project != project_id:
                    raise PermissionError("Authority project identity cannot change")
                self._assert_projects_unfenced(connection, {project_id})
            if before_transition is not None:
                before_transition()
            cursor = connection.execute(
                f"UPDATE {table} SET state=?,payload=?,payload_hash=?,updated_at=? "
                "WHERE id=? AND state=?",
                (state, serialized, digest, _now(), identifier, expected_state),
            )
            if cursor.rowcount != 1:
                raise PermissionError(
                    f"authority {table} lifecycle transition was rejected"
                )
            if project_id is not None:
                self._bump_project_version(connection, project_id)

    def dispose_provider_registration_failure(
        self,
        identifier: str,
        *,
        expected_failure_digest: str,
        state: str,
        payload: dict[str, Any],
        consumption: dict[str, Any],
    ) -> None:
        """Atomically consume Founder authority and dispose one failed claim."""

        if state not in {
            "REGISTRATION_ABANDONED",
            "REGISTRATION_RETRY_AUTHORIZED",
        }:
            raise ValueError("provider registration disposition state is invalid")
        expected_consumption = {
            "capability_id", "project_id", "approval_record_id",
            "approval_event_id", "founder_session_id", "challenge_id",
            "approval_digest", "challenge_proof_digest",
            "capability_digest", "signature_digest", "generation",
            "authorization_id",
        }
        if set(consumption) != expected_consumption:
            raise PermissionError(
                "Founder capability consumption fields are invalid"
            )
        serialized, digest = _serialize(payload)
        timestamp = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state,payload,payload_hash FROM registrations WHERE id=?",
                (identifier,),
            ).fetchone()
            if row is None or str(row["state"]) != "REGISTRATION_FAILED":
                raise PermissionError(
                    "provider registration failure disposition was rejected"
                )
            current_serialized = str(row["payload"])
            if (
                hashlib.sha256(current_serialized.encode("utf-8")).hexdigest()
                != row["payload_hash"]
            ):
                raise RuntimeError("authority registrations record integrity failed")
            current = json.loads(current_serialized)
            if (
                not isinstance(current, dict)
                or current.get("failure_digest") != expected_failure_digest
            ):
                raise PermissionError(
                    "provider registration failure disposition binding differs"
                )
            try:
                connection.execute(
                    "INSERT INTO founder_capability_consumptions VALUES("
                    ":capability_id,:project_id,:approval_record_id,"
                    ":approval_event_id,:founder_session_id,:challenge_id,"
                    ":approval_digest,:challenge_proof_digest,"
                    ":capability_digest,:signature_digest,:generation,"
                    ":authorization_id,:consumed_at)",
                    {**consumption, "consumed_at": timestamp},
                )
                cursor = connection.execute(
                    "UPDATE registrations SET state=?,payload=?,payload_hash=?,"
                    "updated_at=? WHERE id=? AND state='REGISTRATION_FAILED'",
                    (state, serialized, digest, timestamp, identifier),
                )
            except sqlite3.IntegrityError as error:
                raise PermissionError(
                    "Founder capability or approval identity was already used"
                ) from error
            if cursor.rowcount != 1:
                raise PermissionError(
                    "provider registration failure disposition was rejected"
                )

    def migrate_legacy_predispatch_registration(
        self,
        registration_id: str,
        enrollment_id: str,
        *,
        expected_request_identity_digest: str,
        registration_payload: dict[str, Any],
        enrollment_payload: dict[str, Any],
        consumption: dict[str, Any],
    ) -> None:
        """Atomically consume Founder authority, authorize one retry, and revoke Host."""

        expected_consumption = {
            "capability_id", "project_id", "approval_record_id",
            "approval_event_id", "founder_session_id", "challenge_id",
            "approval_digest", "challenge_proof_digest",
            "capability_digest", "signature_digest", "generation",
            "authorization_id",
        }
        if set(consumption) != expected_consumption:
            raise PermissionError(
                "Founder capability consumption fields are invalid"
            )
        registration_serialized, registration_hash = _serialize(
            registration_payload
        )
        enrollment_serialized, enrollment_hash = _serialize(enrollment_payload)
        timestamp = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            registration_row = connection.execute(
                "SELECT state,payload,payload_hash FROM registrations WHERE id=?",
                (registration_id,),
            ).fetchone()
            enrollment_row = connection.execute(
                "SELECT state,payload,payload_hash FROM provider_host_enrollments "
                "WHERE id=?",
                (enrollment_id,),
            ).fetchone()
            if (
                registration_row is None
                or str(registration_row["state"]) != "REGISTRATION_STARTED"
                or enrollment_row is None
                or str(enrollment_row["state"]) != "ACTIVE"
            ):
                raise PermissionError(
                    "legacy predispatch migration checkpoint changed"
                )
            current_registration_serialized = str(registration_row["payload"])
            current_enrollment_serialized = str(enrollment_row["payload"])
            if (
                hashlib.sha256(
                    current_registration_serialized.encode("utf-8")
                ).hexdigest()
                != registration_row["payload_hash"]
                or hashlib.sha256(
                    current_enrollment_serialized.encode("utf-8")
                ).hexdigest()
                != enrollment_row["payload_hash"]
            ):
                raise RuntimeError(
                    "legacy predispatch migration source integrity failed"
                )
            current_registration = json.loads(current_registration_serialized)
            if (
                not isinstance(current_registration, dict)
                or current_registration.get("request_identity_digest")
                != expected_request_identity_digest
            ):
                raise PermissionError(
                    "legacy predispatch registration binding changed"
                )
            try:
                connection.execute(
                    "INSERT INTO founder_capability_consumptions VALUES("
                    ":capability_id,:project_id,:approval_record_id,"
                    ":approval_event_id,:founder_session_id,:challenge_id,"
                    ":approval_digest,:challenge_proof_digest,"
                    ":capability_digest,:signature_digest,:generation,"
                    ":authorization_id,:consumed_at)",
                    {**consumption, "consumed_at": timestamp},
                )
                registration_cursor = connection.execute(
                    "UPDATE registrations SET state='REGISTRATION_RETRY_AUTHORIZED',"
                    "payload=?,payload_hash=?,updated_at=? "
                    "WHERE id=? AND state='REGISTRATION_STARTED'",
                    (
                        registration_serialized,
                        registration_hash,
                        timestamp,
                        registration_id,
                    ),
                )
                enrollment_cursor = connection.execute(
                    "UPDATE provider_host_enrollments SET state='REVOKED',"
                    "payload=?,payload_hash=?,updated_at=? "
                    "WHERE id=? AND state='ACTIVE'",
                    (
                        enrollment_serialized,
                        enrollment_hash,
                        timestamp,
                        enrollment_id,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise PermissionError(
                    "Founder migration capability or approval identity was already used"
                ) from error
            if registration_cursor.rowcount != 1 or enrollment_cursor.rowcount != 1:
                raise PermissionError(
                    "legacy predispatch migration atomic transition was rejected"
                )

    def authorize_exhausted_provider_registration(
        self,
        predecessor_id: str,
        successor_id: str,
        *,
        expected_failure_digest: str,
        predecessor_payload: dict[str, Any],
        successor_payload: dict[str, Any],
        consumption: dict[str, Any],
    ) -> None:
        """Atomically consume Founder authority and create one successor claim."""

        if predecessor_id == successor_id:
            raise ValueError("provider registration successor identity is invalid")
        expected_consumption = {
            "capability_id", "project_id", "approval_record_id",
            "approval_event_id", "founder_session_id", "challenge_id",
            "approval_digest", "challenge_proof_digest",
            "capability_digest", "signature_digest", "generation",
            "authorization_id",
        }
        if set(consumption) != expected_consumption:
            raise PermissionError(
                "Founder capability consumption fields are invalid"
            )
        predecessor_serialized, predecessor_hash = _serialize(
            predecessor_payload
        )
        successor_serialized, successor_hash = _serialize(successor_payload)
        timestamp = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state,payload,payload_hash FROM registrations WHERE id=?",
                (predecessor_id,),
            ).fetchone()
            if row is None or str(row["state"]) != "REGISTRATION_FAILED":
                raise PermissionError(
                    "exhausted provider registration authorization was rejected"
                )
            current_serialized = str(row["payload"])
            if (
                hashlib.sha256(current_serialized.encode("utf-8")).hexdigest()
                != row["payload_hash"]
            ):
                raise RuntimeError("authority registrations record integrity failed")
            current = json.loads(current_serialized)
            if (
                not isinstance(current, dict)
                or current.get("failure_digest") != expected_failure_digest
            ):
                raise PermissionError(
                    "exhausted provider registration binding differs"
                )
            if connection.execute(
                "SELECT 1 FROM registrations WHERE id=?", (successor_id,)
            ).fetchone() is not None:
                raise PermissionError(
                    "provider registration successor already exists"
                )
            try:
                connection.execute(
                    "INSERT INTO founder_capability_consumptions VALUES("
                    ":capability_id,:project_id,:approval_record_id,"
                    ":approval_event_id,:founder_session_id,:challenge_id,"
                    ":approval_digest,:challenge_proof_digest,"
                    ":capability_digest,:signature_digest,:generation,"
                    ":authorization_id,:consumed_at)",
                    {**consumption, "consumed_at": timestamp},
                )
                cursor = connection.execute(
                    "UPDATE registrations SET state='REGISTRATION_EXHAUSTED',"
                    "payload=?,payload_hash=?,updated_at=? "
                    "WHERE id=? AND state='REGISTRATION_FAILED'",
                    (
                        predecessor_serialized,
                        predecessor_hash,
                        timestamp,
                        predecessor_id,
                    ),
                )
                connection.execute(
                    "INSERT INTO registrations VALUES(?,?,?,?,?,?)",
                    (
                        successor_id,
                        "REGISTRATION_REPLACEMENT_AUTHORIZED",
                        successor_serialized,
                        successor_hash,
                        timestamp,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise PermissionError(
                    "Founder capability or successor identity was already used"
                ) from error
            if cursor.rowcount != 1:
                raise PermissionError(
                    "exhausted provider registration authorization was rejected"
                )

    def stage_provider_qualification_binding(
        self,
        registration_id: str,
        qualification_id: str,
        registration: dict[str, Any],
        qualification: dict[str, Any],
        *,
        expected_registration: str = "REGISTERED_UNQUALIFIED",
    ) -> None:
        """Atomically fence a qualified observation before Host binding."""
        self._transition_provider_qualification_pair(
            registration_id,
            qualification_id,
            expected_registration=expected_registration,
            expected_qualification="EXECUTION_STARTED",
            state="UNCERTAIN",
            registration=registration,
            qualification=qualification,
        )

    def begin_provider_qualification(
        self,
        registration_id: str,
        qualification_id: str,
        registration: dict[str, Any],
        qualification_start: dict[str, Any],
        *,
        challenge: str,
    ) -> None:
        """Atomically fence one stable qualification before provider execution."""
        registration_serialized, registration_digest = _serialize(registration)
        qualification_serialized, qualification_digest = _serialize(
            {"start": qualification_start}
        )
        timestamp = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            registration_cursor = connection.execute(
                "UPDATE registrations SET state='QUALIFICATION_STARTED',"
                "payload=?,payload_hash=?,updated_at=? "
                "WHERE id=? AND state='REGISTERED_UNQUALIFIED'",
                (
                    registration_serialized,
                    registration_digest,
                    timestamp,
                    registration_id,
                ),
            )
            if registration_cursor.rowcount != 1:
                raise PermissionError(
                    "Provider qualification claim lost registration eligibility"
                )
            try:
                connection.execute(
                    "INSERT INTO qualifications VALUES(?,?,?,?,?,?,?,?)",
                    (
                        qualification_id,
                        registration_id,
                        "EXECUTION_STARTED",
                        challenge,
                        qualification_serialized,
                        qualification_digest,
                        timestamp,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise PermissionError(
                    "Provider qualification identity is already reserved"
                ) from error

    def fail_provider_qualification(
        self,
        registration_id: str,
        qualification_id: str,
        registration: dict[str, Any],
        qualification: dict[str, Any],
        *,
        expected_registration: str,
    ) -> None:
        """Atomically publish terminal qualification failure for both records."""
        self._transition_provider_qualification_pair(
            registration_id,
            qualification_id,
            expected_registration=expected_registration,
            expected_qualification="EXECUTION_STARTED",
            state="QUALIFICATION_FAILED",
            registration=registration,
            qualification=qualification,
        )

    def authorize_provider_qualification_retry(
        self,
        registration_id: str,
        failed_qualification_id: str,
        retry_qualification_id: str,
        *,
        expected_failure_digest: str,
        retry_challenge: str,
        retry_authorization: dict[str, Any],
        consumption: dict[str, Any],
    ) -> None:
        """Atomically consume Founder authority and reserve one retry identity."""

        if failed_qualification_id == retry_qualification_id:
            raise ValueError("provider qualification retry identity is invalid")
        expected_consumption = {
            "capability_id", "project_id", "approval_record_id",
            "approval_event_id", "founder_session_id", "challenge_id",
            "approval_digest", "challenge_proof_digest",
            "capability_digest", "signature_digest", "generation",
            "authorization_id",
        }
        if set(consumption) != expected_consumption:
            raise PermissionError("Founder capability consumption fields are invalid")
        retry_payload, retry_digest = _serialize(
            {"retry_authorization": retry_authorization}
        )
        timestamp = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            registration = connection.execute(
                "SELECT state,payload,payload_hash FROM registrations WHERE id=?",
                (registration_id,),
            ).fetchone()
            failed = connection.execute(
                "SELECT state,payload,payload_hash,registration_id "
                "FROM qualifications WHERE id=?",
                (failed_qualification_id,),
            ).fetchone()
            if (
                registration is None
                or str(registration["state"]) != "QUALIFICATION_FAILED"
                or failed is None
                or str(failed["state"]) != "QUALIFICATION_FAILED"
                or str(failed["registration_id"]) != registration_id
            ):
                raise PermissionError(
                    "provider qualification failure retry was rejected"
                )
            for table, row in (
                ("registrations", registration),
                ("qualifications", failed),
            ):
                serialized = str(row["payload"])
                if (
                    hashlib.sha256(serialized.encode("utf-8")).hexdigest()
                    != row["payload_hash"]
                ):
                    raise RuntimeError(f"authority {table} record integrity failed")
            failed_payload = json.loads(str(failed["payload"]))
            evidence = (
                failed_payload.get("evidence")
                if isinstance(failed_payload, dict)
                else None
            )
            if (
                not isinstance(evidence, dict)
                or evidence.get("evidence_digest") != expected_failure_digest
                or evidence.get("qualification_result") != "failed"
                or evidence.get("registration_id") != registration_id
            ):
                raise PermissionError(
                    "provider qualification failure retry binding differs"
                )
            try:
                connection.execute(
                    "INSERT INTO founder_capability_consumptions VALUES("
                    ":capability_id,:project_id,:approval_record_id,"
                    ":approval_event_id,:founder_session_id,:challenge_id,"
                    ":approval_digest,:challenge_proof_digest,"
                    ":capability_digest,:signature_digest,:generation,"
                    ":authorization_id,:consumed_at)",
                    {**consumption, "consumed_at": timestamp},
                )
                connection.execute(
                    "INSERT INTO qualifications VALUES(?,?,?,?,?,?,?,?)",
                    (
                        retry_qualification_id,
                        registration_id,
                        "QUALIFICATION_RETRY_AUTHORIZED",
                        retry_challenge,
                        retry_payload,
                        retry_digest,
                        timestamp,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise PermissionError(
                    "Founder capability or qualification retry identity was "
                    "already used"
                ) from error

    def begin_provider_qualification_retry(
        self,
        registration_id: str,
        retry_qualification_id: str,
        registration: dict[str, Any],
        qualification_start: dict[str, Any],
        retry_authorization: dict[str, Any],
        *,
        challenge: str,
    ) -> None:
        """Atomically activate exactly one previously authorized retry."""

        registration_serialized, registration_digest = _serialize(registration)
        qualification_serialized, qualification_digest = _serialize(
            {
                "start": qualification_start,
                "retry_authorization": retry_authorization,
            }
        )
        timestamp = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            registration_cursor = connection.execute(
                "UPDATE registrations SET state='QUALIFICATION_STARTED',"
                "payload=?,payload_hash=?,updated_at=? "
                "WHERE id=? AND state='QUALIFICATION_FAILED'",
                (
                    registration_serialized,
                    registration_digest,
                    timestamp,
                    registration_id,
                ),
            )
            qualification_cursor = connection.execute(
                "UPDATE qualifications SET state='EXECUTION_STARTED',"
                "challenge=?,payload=?,payload_hash=?,updated_at=? "
                "WHERE id=? AND registration_id=? "
                "AND state='QUALIFICATION_RETRY_AUTHORIZED'",
                (
                    challenge,
                    qualification_serialized,
                    qualification_digest,
                    timestamp,
                    retry_qualification_id,
                    registration_id,
                ),
            )
            if registration_cursor.rowcount != 1 or qualification_cursor.rowcount != 1:
                raise PermissionError(
                    "Provider qualification retry activation lost eligibility"
                )

    def complete_provider_qualification(
        self,
        registration_id: str,
        qualification_id: str,
        registration: dict[str, Any],
        qualification: dict[str, Any],
        *,
        expected_registration: str,
    ) -> None:
        """Atomically publish a qualification that needs no Host binding step."""
        self._transition_provider_qualification_pair(
            registration_id,
            qualification_id,
            expected_registration=expected_registration,
            expected_qualification="EXECUTION_STARTED",
            state="QUALIFIED",
            registration=registration,
            qualification=qualification,
        )

    def complete_provider_qualification_binding(
        self,
        registration_id: str,
        qualification_id: str,
        registration: dict[str, Any],
        qualification: dict[str, Any],
    ) -> None:
        """Atomically publish an exact, idempotently Host-bound qualification."""
        self._transition_provider_qualification_pair(
            registration_id,
            qualification_id,
            expected_registration="UNCERTAIN",
            expected_qualification="UNCERTAIN",
            state="QUALIFIED",
            registration=registration,
            qualification=qualification,
        )

    def _transition_provider_qualification_pair(
        self,
        registration_id: str,
        qualification_id: str,
        *,
        expected_registration: str,
        expected_qualification: str,
        state: str,
        registration: dict[str, Any],
        qualification: dict[str, Any],
    ) -> None:
        registration_serialized, registration_digest = _serialize(registration)
        qualification_serialized, qualification_digest = _serialize(qualification)
        timestamp = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            registration_cursor = connection.execute(
                "UPDATE registrations SET state=?,payload=?,payload_hash=?,updated_at=? "
                "WHERE id=? AND state=?",
                (
                    state,
                    registration_serialized,
                    registration_digest,
                    timestamp,
                    registration_id,
                    expected_registration,
                ),
            )
            qualification_cursor = connection.execute(
                "UPDATE qualifications SET state=?,payload=?,payload_hash=?,updated_at=? "
                "WHERE id=? AND registration_id=? AND state=?",
                (
                    state,
                    qualification_serialized,
                    qualification_digest,
                    timestamp,
                    qualification_id,
                    registration_id,
                    expected_qualification,
                ),
            )
            if (
                registration_cursor.rowcount != 1
                or qualification_cursor.rowcount != 1
            ):
                raise PermissionError(
                    "Provider qualification binding transition was rejected"
                )

    def list_records(self, table: str) -> list[dict[str, Any]]:
        if table not in {
            "registrations", "qualifications", "attempts",
            "launch_authorizations", "provider_host_enrollments",
        }:
            raise ValueError("unsupported authority table")
        with self.connect() as connection:
            identifiers = [
                str(row["id"])
                for row in connection.execute(
                    f"SELECT id FROM {table} ORDER BY created_at"
                ).fetchall()
            ]
        return [
            value
            for identifier in identifiers
            if (value := self.get(table, identifier)) is not None
        ]

    def begin_provider_host_enrollment(
        self,
        identifier: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Atomically create, or exactly reconcile, one pending enrollment."""
        serialized, digest = _serialize(payload)
        timestamp = _now()
        capability_digest = str(payload.get("founder_capability_digest", ""))
        proposal_digest = str(payload.get("proposal_digest", ""))
        generation = payload.get("enrollment_generation")
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise PermissionError("Provider Host enrollment generation is invalid")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT id,state,payload,payload_hash FROM provider_host_enrollments "
                "ORDER BY created_at"
            ).fetchall()
            maximum_generation = 0
            for row in rows:
                existing_serialized = str(row["payload"])
                if hashlib.sha256(existing_serialized.encode("utf-8")).hexdigest() != row["payload_hash"]:
                    raise RuntimeError("Provider Host enrollment integrity failed")
                existing = json.loads(existing_serialized)
                if not isinstance(existing, dict):
                    raise RuntimeError("Provider Host enrollment is malformed")
                prior_generation = existing.get("enrollment_generation")
                if (
                    isinstance(prior_generation, bool)
                    or not isinstance(prior_generation, int)
                    or prior_generation <= 0
                ):
                    raise RuntimeError(
                        "Provider Host enrollment generation is malformed"
                    )
                maximum_generation = max(maximum_generation, prior_generation)
                if (
                    str(row["id"]) == identifier
                    and str(row["state"]) == "PENDING"
                    and existing == payload
                ):
                    return {**existing, "service_state": "PENDING"}
                if existing.get("founder_capability_digest") == capability_digest:
                    raise PermissionError("Founder Host-enrollment capability is replayed")
                if existing.get("proposal_digest") == proposal_digest:
                    raise PermissionError("Provider Host enrollment proposal is replayed")
                if str(row["state"]) in {"PENDING", "ACTIVE", "UNCERTAIN"}:
                    raise PermissionError("A Provider Host enrollment is already unresolved")
            if generation <= maximum_generation:
                raise PermissionError("Provider Host enrollment generation is stale")
            connection.execute(
                "INSERT INTO provider_host_enrollments VALUES(?,?,?,?,?,?)",
                (identifier, "PENDING", serialized, digest, timestamp, timestamp),
            )
        return {**payload, "service_state": "PENDING"}

    def complete_provider_host_enrollment(
        self,
        identifier: str,
        *,
        proof_digest: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Commit the exact Host proof once; lost acknowledgements reconcile."""
        serialized, digest = _serialize(payload)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state,payload,payload_hash FROM provider_host_enrollments WHERE id=?",
                (identifier,),
            ).fetchone()
            if row is None:
                raise PermissionError("Provider Host enrollment is absent")
            current_serialized = str(row["payload"])
            if hashlib.sha256(current_serialized.encode("utf-8")).hexdigest() != row["payload_hash"]:
                raise RuntimeError("Provider Host enrollment integrity failed")
            current = json.loads(current_serialized)
            if not isinstance(current, dict):
                raise RuntimeError("Provider Host enrollment is malformed")
            if str(row["state"]) == "ACTIVE":
                if current.get("proof_digest") == proof_digest:
                    return {**current, "service_state": "ACTIVE"}
                raise PermissionError("Provider Host enrollment proof conflicts")
            if str(row["state"]) != "PENDING":
                raise PermissionError("Provider Host enrollment cannot be completed")
            cursor = connection.execute(
                "UPDATE provider_host_enrollments SET state='ACTIVE',payload=?,payload_hash=?,updated_at=? "
                "WHERE id=? AND state='PENDING'",
                (serialized, digest, _now(), identifier),
            )
            if cursor.rowcount != 1:
                raise PermissionError("Provider Host enrollment completion lost its claim")
        return {**payload, "service_state": "ACTIVE"}

    def transition_provider_host_enrollment(
        self,
        identifier: str,
        *,
        expected: tuple[str, ...],
        state: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if state not in {"REVOKED", "EXPIRED", "UNCERTAIN"}:
            raise ValueError("Provider Host enrollment terminal state is invalid")
        serialized, digest = _serialize(payload)
        placeholders = ",".join("?" for _ in expected)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                f"UPDATE provider_host_enrollments SET state=?,payload=?,payload_hash=?,updated_at=? "
                f"WHERE id=? AND state IN ({placeholders})",
                (state, serialized, digest, _now(), identifier, *expected),
            )
            if cursor.rowcount != 1:
                raise PermissionError("Provider Host enrollment transition was rejected")
        return {**payload, "service_state": state}

    def record_provider_host_launch_reconciliation(
        self,
        identifier: str,
        *,
        expected_payload_hash: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        serialized, digest = _serialize(payload)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state,payload_hash FROM provider_host_enrollments WHERE id=?",
                (identifier,),
            ).fetchone()
            if (
                row is None
                or str(row["state"]) != "ACTIVE"
                or str(row["payload_hash"]) != expected_payload_hash
            ):
                raise PermissionError(
                    "Provider Host launch reconciliation lost its enrollment claim"
                )
            cursor = connection.execute(
                "UPDATE provider_host_enrollments SET payload=?,payload_hash=?,updated_at=? "
                "WHERE id=? AND state='ACTIVE' AND payload_hash=?",
                (serialized, digest, _now(), identifier, expected_payload_hash),
            )
            if cursor.rowcount != 1:
                raise PermissionError(
                    "Provider Host launch reconciliation was not committed"
                )
        return {**payload, "service_state": "ACTIVE"}

    def current_provider_host_enrollment(self) -> dict[str, Any] | None:
        records = self.list_records("provider_host_enrollments")
        unresolved = [
            value
            for value in records
            if value.get("service_state") in {"PENDING", "ACTIVE", "UNCERTAIN"}
        ]
        if len(unresolved) > 1:
            raise RuntimeError("Multiple Provider Host enrollments are unresolved")
        return unresolved[0] if unresolved else (records[-1] if records else None)

    def create_launch_authorization(
        self,
        identifier: str,
        generation: int,
        client_sid: str,
        payload: dict[str, Any],
        consumption: dict[str, Any],
    ) -> dict[str, Any]:
        serialized, digest = _serialize(payload)
        timestamp = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            project_id = _payload_project_id(payload)
            self._assert_projects_unfenced(connection, {project_id})
            row = connection.execute(
                "SELECT state,generation,client_sid,payload,payload_hash "
                "FROM launch_authorizations WHERE id=?",
                (identifier,),
            ).fetchone()
            if row is not None:
                existing_serialized = str(row["payload"])
                if (
                    hashlib.sha256(existing_serialized.encode("utf-8")).hexdigest()
                    != row["payload_hash"]
                ):
                    raise RuntimeError(
                        "stored launch authorization failed integrity validation"
                    )
                existing = json.loads(existing_serialized)
                if (
                    row["state"] == "ACTIVE"
                    and int(row["generation"]) == generation
                    and row["client_sid"] == client_sid
                    and existing == payload
                ):
                    return payload
                raise PermissionError(
                    "launch authorization generation is revoked or stale"
                )
            prior_rows = connection.execute(
                "SELECT state,generation,client_sid,payload,payload_hash "
                "FROM launch_authorizations"
            ).fetchall()
            prior: list[tuple[sqlite3.Row, dict[str, Any]]] = []
            for prior_row in prior_rows:
                prior_serialized = str(prior_row["payload"])
                if (
                    hashlib.sha256(prior_serialized.encode("utf-8")).hexdigest()
                    != prior_row["payload_hash"]
                ):
                    raise RuntimeError(
                        "stored launch authorization failed integrity validation"
                    )
                prior_payload = json.loads(prior_serialized)
                if (
                    isinstance(prior_payload, dict)
                    and prior_payload.get("project_id") == payload.get("project_id")
                ):
                    prior.append((prior_row, prior_payload))
            if prior:
                latest_row, _latest_payload = max(
                    prior, key=lambda item: int(item[0]["generation"])
                )
                if (
                    generation != int(latest_row["generation"]) + 1
                    or latest_row["state"] != "REVOKED"
                    or latest_row["client_sid"] != client_sid
                    or payload.get("revocation_epoch")
                    != int(latest_row["generation"])
                ):
                    raise PermissionError(
                        "higher launch generation requires the exact next revoked epoch"
                    )
            elif generation != 1 or payload.get("revocation_epoch") != 0:
                raise PermissionError(
                    "initial launch authorization generation must be one"
                )
            expected_consumption = {
                "capability_id", "project_id", "approval_record_id",
                "approval_event_id", "founder_session_id", "challenge_id",
                "approval_digest", "challenge_proof_digest",
                "capability_digest", "signature_digest", "generation",
                "authorization_id",
            }
            if set(consumption) != expected_consumption:
                raise PermissionError(
                    "Founder capability consumption fields are invalid"
                )
            try:
                connection.execute(
                    "INSERT INTO founder_capability_consumptions VALUES("
                    ":capability_id,:project_id,:approval_record_id,"
                    ":approval_event_id,:founder_session_id,:challenge_id,"
                    ":approval_digest,:challenge_proof_digest,"
                    ":capability_digest,:signature_digest,:generation,"
                    ":authorization_id,:consumed_at)",
                    {**consumption, "consumed_at": timestamp},
                )
                connection.execute(
                    "INSERT INTO launch_authorizations VALUES(?,?,?,?,?,?,?,?)",
                    (
                        identifier, "ACTIVE", generation, client_sid,
                        serialized, digest, timestamp, timestamp,
                    ),
                )
                self._bump_project_version(connection, project_id)
            except sqlite3.IntegrityError as error:
                raise PermissionError(
                    "Founder capability or approval identity was already used"
                ) from error
        return payload

    def revoke_launch_authorization(
        self,
        identifier: str,
        generation: int,
        client_sid: str,
        payload: dict[str, Any],
    ) -> tuple[str, ...]:
        serialized, digest = _serialize(payload)
        timestamp = _now()
        canceled: list[str] = []
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            project_id = _payload_project_id(payload)
            self._assert_projects_unfenced(connection, {project_id})
            cursor = connection.execute(
                "UPDATE launch_authorizations SET state='REVOKED',payload=?,"
                "payload_hash=?,updated_at=? WHERE id=? AND state='ACTIVE' "
                "AND generation=? AND client_sid=?",
                (
                    serialized, digest, timestamp, identifier, generation,
                    client_sid,
                ),
            )
            if cursor.rowcount != 1:
                raise PermissionError("launch authorization revocation is stale")
            rows = connection.execute(
                "SELECT id,payload,payload_hash FROM attempts "
                "WHERE state IN ('RESERVED','INPUT_BOUND','LAUNCH_CLAIMED')"
            ).fetchall()
            for row in rows:
                attempt = json.loads(str(row["payload"]))
                if (
                    isinstance(attempt, dict)
                    and attempt.get("launch_authorization_id") == identifier
                    and attempt.get("authorization_generation") == generation
                ):
                    connection.execute(
                        "UPDATE attempts SET state='CANCELLED',updated_at=? "
                        "WHERE id=? AND payload_hash=?",
                        (timestamp, row["id"], row["payload_hash"]),
                    )
                    canceled.append(str(row["id"]))
            self._bump_project_version(connection, project_id)
        return tuple(canceled)

    def claim_attempt_with_launch_authority(
        self,
        attempt_id: str,
        authorization_id: str,
        generation: int,
        client_sid: str,
        claim: dict[str, Any],
        *,
        expected_attempt_state: str = "RESERVED",
        provider_usage_policy: object = None,
        usage_observation: object = None,
    ) -> None:
        serialized, digest = _serialize(claim)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            project_id = _payload_project_id(claim)
            self._assert_projects_unfenced(connection, {project_id})
            authorization = connection.execute(
                "SELECT state,generation,client_sid,payload FROM "
                "launch_authorizations WHERE id=?",
                (authorization_id,),
            ).fetchone()
            if (
                authorization is None
                or authorization["state"] != "ACTIVE"
                or int(authorization["generation"]) != generation
                or authorization["client_sid"] != client_sid
            ):
                raise PermissionError(
                    "authoritative launch generation is revoked or stale"
                )
            authorization_payload = json.loads(str(authorization["payload"]))
            if datetime.fromisoformat(
                str(authorization_payload["expires_at"])
            ) <= datetime.now(UTC):
                raise PermissionError("authoritative launch lease expired")
            if provider_usage_policy is not None:
                _assert_provider_usage_claim(
                    connection,
                    str(claim.get("registration_id", "")),
                    provider_usage_policy,
                    usage_observation,
                )
            cursor = connection.execute(
                "UPDATE attempts SET state='LAUNCH_CLAIMED',payload=?,"
                "payload_hash=?,updated_at=? WHERE id=? AND state=?",
                (
                    serialized,
                    digest,
                    _now(),
                    attempt_id,
                    expected_attempt_state,
                ),
            )
            if cursor.rowcount != 1:
                raise PermissionError("provider launch is not reserved")
            self._bump_project_version(connection, project_id)

    def begin_restore_fence(
        self,
        fence_id: str,
        identity: dict[str, Any],
        client_sid: str,
        issued_at: str,
        expires_at: str,
    ) -> dict[str, Any]:
        scope_value = identity.get("project_scope")
        if not isinstance(scope_value, list) or not all(
            isinstance(item, str) and item for item in scope_value
        ):
            raise ValueError("Authority restore fence scope is invalid")
        project_scope = set(scope_value)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_projects_unfenced(connection, project_scope)
            snapshot = self._restore_snapshot(connection, project_scope)
            payload = {
                **identity,
                "fence_id": fence_id,
                "authorized_client_sid": client_sid,
                **snapshot,
                "issued_at": issued_at,
                "expires_at": expires_at,
            }
            serialized, digest = _serialize(payload)
            connection.execute(
                "INSERT INTO restore_reconciliation_fences VALUES("
                "?,?,?,'ACTIVE',?,?,?,?,?,?,?,?,?,?)",
                (
                    fence_id,
                    identity["restore_operation_id"],
                    client_sid,
                    json.dumps(scope_value, separators=(",", ":")),
                    snapshot["state_digest"],
                    snapshot["version_digest"],
                    identity["authorization_digest"],
                    identity["backup_sha256"],
                    issued_at,
                    expires_at,
                    issued_at,
                    serialized,
                    digest,
                ),
            )
        return payload

    def confirm_restore_fence(
        self, fence_id: str, restore_operation_id: str, client_sid: str
    ) -> dict[str, Any]:
        now = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row, payload = self._active_fence(
                connection, fence_id, restore_operation_id, client_sid
            )
            if datetime.fromisoformat(str(row["expires_at"])) <= datetime.now(UTC):
                raise PermissionError("Authority restore fence expired")
            scope = set(json.loads(str(row["project_scope"])))
            snapshot = self._restore_snapshot(connection, scope)
            if (
                snapshot["state_digest"] != row["state_digest"]
                or snapshot["version_digest"] != row["version_digest"]
            ):
                raise PermissionError("Authority changed during fenced restore")
            return {
                "fence_id": fence_id,
                "restore_operation_id": restore_operation_id,
                "authorized_client_sid": client_sid,
                "state_digest": row["state_digest"],
                "version_digest": row["version_digest"],
                "authorization_digest": row["authorization_digest"],
                "backup_sha256": row["backup_sha256"],
                "project_scope": payload["project_scope"],
                "issued_at": row["issued_at"],
                "expires_at": row["expires_at"],
                "confirmed_at": now,
            }

    def finish_restore_fence(
        self,
        fence_id: str,
        restore_operation_id: str,
        client_sid: str,
        state: str,
    ) -> dict[str, Any]:
        if state not in {"COMPLETED", "ABORTED"}:
            raise ValueError("Authority restore fence outcome is invalid")
        now = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row, _payload = self._active_fence(
                connection, fence_id, restore_operation_id, client_sid
            )
            if (
                state == "COMPLETED"
                and datetime.fromisoformat(str(row["expires_at"]))
                <= datetime.now(UTC)
            ):
                raise PermissionError("Authority restore fence expired")
            connection.execute(
                "UPDATE restore_reconciliation_fences SET state=?,updated_at=? "
                "WHERE fence_id=? AND state='ACTIVE'",
                (state, now, fence_id),
            )
        return {
            "fence_id": fence_id,
            "restore_operation_id": restore_operation_id,
            "state": state,
            "finished_at": now,
        }

    def recover_restore_fence(
        self, fence_id: str, restore_operation_id: str, client_sid: str
    ) -> dict[str, Any]:
        now = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row, _payload = self._active_fence(
                connection, fence_id, restore_operation_id, client_sid
            )
            if datetime.fromisoformat(str(row["expires_at"])) > datetime.now(UTC):
                raise PermissionError("active Authority restore fence has not expired")
            connection.execute(
                "UPDATE restore_reconciliation_fences SET state='EXPIRED',updated_at=? "
                "WHERE fence_id=? AND state='ACTIVE'",
                (now, fence_id),
            )
        return {
            "fence_id": fence_id,
            "restore_operation_id": restore_operation_id,
            "state": "EXPIRED",
            "recovered_at": now,
        }

    @staticmethod
    def _active_fence(
        connection: sqlite3.Connection,
        fence_id: str,
        restore_operation_id: str,
        client_sid: str,
    ) -> tuple[sqlite3.Row, dict[str, Any]]:
        row = connection.execute(
            "SELECT * FROM restore_reconciliation_fences "
            "WHERE fence_id=? AND restore_operation_id=? AND client_sid=? "
            "AND state='ACTIVE'",
            (fence_id, restore_operation_id, client_sid),
        ).fetchone()
        if row is None:
            raise PermissionError("Authority restore fence is unavailable")
        serialized = str(row["payload"])
        if hashlib.sha256(serialized.encode("utf-8")).hexdigest() != row["payload_hash"]:
            raise RuntimeError("Authority restore fence integrity failed")
        payload = json.loads(serialized)
        if not isinstance(payload, dict):
            raise RuntimeError("Authority restore fence is malformed")
        return row, payload

    @staticmethod
    def _restore_snapshot(
        connection: sqlite3.Connection, project_scope: set[str]
    ) -> dict[str, Any]:
        attempts = AuthorityStore._records_in_connection(
            connection, "attempts", project_scope
        )
        authorizations = AuthorityStore._records_in_connection(
            connection, "launch_authorizations", project_scope
        )
        versions = {
            project_id: (
                int(row["version"])
                if (
                    row := connection.execute(
                        "SELECT version FROM authority_project_versions "
                        "WHERE project_id=?",
                        (project_id,),
                    ).fetchone()
                ) is not None
                else 0
            )
            for project_id in sorted(project_scope)
        }
        state = {
            "attempts": attempts,
            "launch_authorizations": authorizations,
        }
        return {
            **state,
            "project_versions": versions,
            "state_digest": _canonical_digest(state),
            "version_digest": _canonical_digest(versions),
        }

    @staticmethod
    def _records_in_connection(
        connection: sqlite3.Connection, table: str, project_scope: set[str]
    ) -> list[dict[str, Any]]:
        rows = connection.execute(
            f"SELECT id,state,payload,payload_hash FROM {table} ORDER BY id"
        ).fetchall()
        records: list[dict[str, Any]] = []
        for row in rows:
            serialized = str(row["payload"])
            if hashlib.sha256(serialized.encode("utf-8")).hexdigest() != row["payload_hash"]:
                raise RuntimeError(f"authority {table} record integrity failed")
            value = json.loads(serialized)
            if not isinstance(value, dict):
                raise RuntimeError(f"authority {table} record is malformed")
            if value.get("project_id") in project_scope:
                records.append({**value, "service_state": str(row["state"])})
        return records

    @staticmethod
    def _assert_projects_unfenced(
        connection: sqlite3.Connection, project_ids: set[str]
    ) -> None:
        if not project_ids:
            return
        for row in connection.execute(
            "SELECT project_scope FROM restore_reconciliation_fences "
            "WHERE state='ACTIVE'"
        ).fetchall():
            scope = json.loads(str(row["project_scope"]))
            if isinstance(scope, list) and project_ids.intersection(scope):
                raise PermissionError(
                    "Authority project state is fenced for Executive restore"
                )

    @staticmethod
    def _bump_project_version(
        connection: sqlite3.Connection, project_id: str
    ) -> None:
        timestamp = _now()
        connection.execute(
            "INSERT INTO authority_project_versions VALUES(?,1,?) "
            "ON CONFLICT(project_id) DO UPDATE SET "
            "version=version+1,updated_at=excluded.updated_at",
            (project_id, timestamp),
        )

    def audit(
        self,
        event_id: str,
        event_type: str,
        client_sid: str,
        object_id: str | None,
        detail: dict[str, Any],
    ) -> None:
        safe_detail = json.dumps(
            detail, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO audit_log(event_id,event_type,client_sid,object_id,"
                "detail,created_at) VALUES(?,?,?,?,?,?)",
                (event_id, event_type, client_sid, object_id, safe_detail, _now()),
            )

    def schema_identity(self) -> dict[str, Any]:
        if not self.path.is_file():
            raise FileNotFoundError("authority database is unavailable")
        connection = sqlite3.connect(
            f"{self.path.resolve().as_uri()}?mode=ro",
            uri=True,
            timeout=30,
        )
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                "SELECT value FROM service_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                raise RuntimeError("authority database schema version is missing")
            version = int(row["value"])
            definitions = [
                {
                    "type": str(item["type"]),
                    "name": str(item["name"]),
                    "table": str(item["tbl_name"]),
                    "sql": " ".join(str(item["sql"]).split()),
                }
                for item in connection.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_master "
                    "WHERE sql IS NOT NULL ORDER BY type,name"
                ).fetchall()
            ]
            tables = {
                str(item["name"])
                for item in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
                if not str(item["name"]).startswith("sqlite_")
            }
            journal_mode = str(
                connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).casefold()
        finally:
            connection.close()
        serialized = json.dumps(
            definitions, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return {
            "schema_version": version,
            "schema_sha256": hashlib.sha256(serialized).hexdigest(),
            "journal_mode": journal_mode,
            "table_names_sha256": hashlib.sha256(
                json.dumps(sorted(tables), separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest(),
            "schema_matches_expected": (
                version == SERVICE_SCHEMA_VERSION
                and tables == _EXPECTED_TABLES
                and journal_mode == "wal"
            ),
        }

    def backup(self, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as source, sqlite3.connect(destination) as target:
            source.backup(target)
        return destination


def _payload_project_id(payload: dict[str, Any]) -> str:
    project_id = payload.get("project_id")
    if not isinstance(project_id, str) or not project_id:
        raise ValueError("Authority project identity is invalid")
    return project_id


def _assert_provider_usage_claim(
    connection: sqlite3.Connection,
    registration_id: str,
    policy_value: object,
    observation_value: object,
) -> None:
    if not isinstance(policy_value, dict):
        raise PermissionError("provider usage authority is malformed")
    if not isinstance(observation_value, dict):
        raise PermissionError("provider usage state is unavailable")
    if observation_value.get("exhausted") is True:
        raise PermissionError(
            "WAITING_FOR_USAGE_RESET: provider capacity exhausted"
        )
    budget = policy_value.get("keeper_launch_budget")
    window = policy_value.get("budget_window_seconds")
    if (
        isinstance(budget, bool)
        or not isinstance(budget, int)
        or isinstance(window, bool)
        or not isinstance(window, int)
    ):
        raise PermissionError("provider usage budget is invalid")
    cutoff = datetime.now(UTC).timestamp() - window
    launched = 0
    latest_wait: datetime | None = None
    rows = connection.execute(
        "SELECT state,payload FROM attempts"
    ).fetchall()
    launched_states = {
        "LAUNCH_CLAIMED",
        "EXECUTION_STARTED",
        "COMPLETED",
        "FAILED",
        "CANCELLED",
        "TIMED_OUT",
        "UNCERTAIN",
        "LAUNCH_FAILED",
    }
    for row in rows:
        try:
            record = json.loads(str(row["payload"]))
        except json.JSONDecodeError as error:
            raise PermissionError("provider usage history is malformed") from error
        if (
            not isinstance(record, dict)
            or record.get("registration_id") != registration_id
        ):
            continue
        state = str(row["state"])
        launched_wait = (
            state == "WAITING_FOR_USAGE_RESET"
            and isinstance(record.get("claimed_at"), str)
            and isinstance(record.get("started_at"), str)
            and isinstance(record.get("process_id"), int)
        )
        if state in launched_states or launched_wait:
            timestamp = record.get("claimed_at") or record.get("started_at")
            try:
                claimed_at = datetime.fromisoformat(str(timestamp))
            except (TypeError, ValueError) as error:
                raise PermissionError(
                    "provider usage history is malformed"
                ) from error
            if claimed_at.tzinfo is None:
                raise PermissionError("provider usage history is malformed")
            if claimed_at.timestamp() >= cutoff:
                launched += 1
        if state == "WAITING_FOR_USAGE_RESET":
            try:
                waited = datetime.fromisoformat(
                    str(record.get("waited_at") or record.get("finished_at"))
                )
            except (TypeError, ValueError) as error:
                raise PermissionError(
                    "provider usage wait history is malformed"
                ) from error
            if waited.tzinfo is None:
                raise PermissionError(
                    "provider usage wait history is malformed"
                )
            if latest_wait is None or waited > latest_wait:
                latest_wait = waited
    if latest_wait is not None:
        try:
            observed_at = datetime.fromisoformat(
                str(observation_value.get("observed_at"))
            )
        except (TypeError, ValueError) as error:
            raise PermissionError(
                "WAITING_FOR_USAGE_RESET: reset observation is unavailable"
            ) from error
        if (
            observed_at.tzinfo is None
            or observed_at <= latest_wait
            or observation_value.get("capacity_state") != "OBSERVED"
            or observation_value.get("confidence") != "HIGH"
            or observation_value.get("exhausted") is not False
        ):
            raise PermissionError(
                "WAITING_FOR_USAGE_RESET: reset is not authoritatively observed"
            )
    if launched >= budget:
        raise PermissionError(
            "WAITING_FOR_USAGE_RESET: Keeper launch budget exhausted"
        )


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _serialize(payload: dict[str, Any]) -> tuple[str, str]:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return serialized, hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
