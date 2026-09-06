from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterator

from keeper.provider_host.protocol import parse_utc


_ACTIVE_STATES = {"CLAIMED", "STARTED", "RUNNING", "UNCERTAIN"}
_TERMINAL_STATES = {"COMPLETED", "FAILED", "CANCELLED"}
_TRANSITIONS = {
    "CLAIMED": {"STARTED", "FAILED", "UNCERTAIN"},
    "STARTED": {"RUNNING", "FAILED", "CANCELLED", "UNCERTAIN"},
    "RUNNING": {"COMPLETED", "FAILED", "CANCELLED", "UNCERTAIN"},
    "UNCERTAIN": set(),
    "COMPLETED": set(),
    "FAILED": set(),
    "CANCELLED": set(),
}
_OPERATIONS = {"PROVIDER_EXECUTION", "REGISTER_PROBE", "QUALIFY", "LEGACY_UNKNOWN"}
_PHASES = {
    "CLAIM_DURABLE",
    "STARTED_AWAITING_ACK",
    "STARTED_ACK_VERIFIED",
    "RESUMED",
    "TERMINAL",
    "LEGACY_UNRECORDED",
}


class ProviderHostStore:
    """Durable replay, endpoint, launch, and workspace journal."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")
            yield connection
        finally:
            connection.close()

    def claim_launch(
        self,
        *,
        authority_id: str,
        nonce: str,
        sequence: int,
        issued_at: str,
        expires_at: str,
        now: datetime,
        maximum_ttl: timedelta,
        maximum_future_skew: timedelta,
        launch_id: str,
        authority_attempt_id: str,
        envelope_digest: str,
        workspace_path: str,
        operation: str = "PROVIDER_EXECUTION",
    ) -> None:
        observed_now = now.astimezone(UTC)
        issued = parse_utc(issued_at)
        expires = parse_utc(expires_at)
        if issued > observed_now + maximum_future_skew:
            raise PermissionError("Provider Host launch was issued in the future")
        if expires <= observed_now:
            raise PermissionError("Provider Host launch is expired")
        if expires - issued > maximum_ttl:
            raise PermissionError("Provider Host launch TTL exceeds policy")
        canonical_workspace = _canonical_workspace(workspace_path)
        if operation not in _OPERATIONS - {"LEGACY_UNKNOWN"}:
            raise PermissionError("Provider Host launch operation is invalid")
        with self.connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM replay WHERE nonce = ?", (nonce,)
                ).fetchone() is not None:
                    raise PermissionError("Provider Host nonce is replayed")
                prior = connection.execute(
                    "SELECT MAX(sequence) FROM replay WHERE authority_id = ?",
                    (authority_id,),
                ).fetchone()[0]
                if prior is not None and sequence <= int(prior):
                    raise PermissionError("Provider Host sequence is stale")
                if connection.execute(
                    "SELECT 1 FROM launches WHERE launch_id = ? OR authority_attempt_id = ?",
                    (launch_id, authority_attempt_id),
                ).fetchone() is not None:
                    raise PermissionError("Provider Host launch is duplicated")
                for row in connection.execute(
                    "SELECT workspace_path FROM launches WHERE state IN "
                    "('CLAIMED','STARTED','RUNNING','UNCERTAIN')"
                ).fetchall():
                    if _paths_overlap(str(row[0]), canonical_workspace):
                        raise PermissionError("Provider Host workspace overlaps")
                connection.execute(
                    "INSERT INTO replay(authority_id,nonce,sequence,expires_at) "
                    "VALUES(?,?,?,?)",
                    (authority_id, nonce, sequence, expires_at),
                )
                connection.execute(
                    "INSERT INTO launches(launch_id,authority_attempt_id,envelope_digest,"
                    "workspace_path,state,detail,updated_at,operation,phase,reconciliation,"
                    "reconciliation_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        launch_id,
                        authority_attempt_id,
                        envelope_digest,
                        canonical_workspace,
                        "CLAIMED",
                        "",
                        _now(),
                        operation,
                        "CLAIM_DURABLE",
                        None,
                        None,
                    ),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def claim_peer_message(
        self,
        *,
        channel: str,
        authority_id: str,
        nonce: str,
        sequence: int,
        issued_at: str,
        expires_at: str,
        now: datetime,
        maximum_ttl: timedelta,
        maximum_future_skew: timedelta,
    ) -> None:
        if not channel or not nonce or sequence <= 0:
            raise PermissionError("Provider Host peer message is invalid")
        observed_now = now.astimezone(UTC)
        issued = parse_utc(issued_at)
        expires = parse_utc(expires_at)
        if issued > observed_now + maximum_future_skew:
            raise PermissionError("Provider Host peer message is future-issued")
        if expires <= observed_now or expires - issued > maximum_ttl:
            raise PermissionError("Provider Host peer message lifetime is invalid")
        with self.connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                prior = connection.execute(
                    "SELECT MAX(sequence) FROM message_replay "
                    "WHERE channel=? AND authority_id=?",
                    (channel, authority_id),
                ).fetchone()[0]
                if prior is not None and sequence <= int(prior):
                    raise PermissionError("Provider Host peer message is stale")
                connection.execute(
                    "INSERT INTO message_replay(channel,authority_id,nonce,sequence,expires_at) "
                    "VALUES(?,?,?,?,?)",
                    (channel, authority_id, nonce, sequence, expires_at),
                )
                connection.commit()
            except sqlite3.IntegrityError as error:
                connection.rollback()
                raise PermissionError("Provider Host peer message is replayed") from error
            except BaseException:
                connection.rollback()
                raise

    def transition(
        self,
        launch_id: str,
        expected: str | tuple[str, ...],
        state: str,
        *,
        detail: str = "",
        phase: str | None = None,
    ) -> None:
        expected_states = (expected,) if isinstance(expected, str) else expected
        allowed = _ACTIVE_STATES | _TERMINAL_STATES
        if state not in allowed or any(item not in allowed for item in expected_states):
            raise ValueError("Provider Host launch state is invalid")
        if any(state not in _TRANSITIONS[item] for item in expected_states):
            raise ValueError("Provider Host launch state transition is invalid")
        if phase is not None and phase not in _PHASES:
            raise ValueError("Provider Host launch phase is invalid")
        placeholders = ",".join("?" for _ in expected_states)
        with self.connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                result = connection.execute(
                    f"UPDATE launches SET state=?, detail=?, updated_at=?,phase=COALESCE(?,phase) "
                    f"WHERE launch_id=? AND state IN ({placeholders})",
                    (state, detail[:500], _now(), phase, launch_id, *expected_states),
                )
                if result.rowcount != 1:
                    raise PermissionError("Provider Host state transition rejected")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def set_phase(self, launch_id: str, expected_state: str, phase: str) -> None:
        if expected_state not in _ACTIVE_STATES or phase not in _PHASES:
            raise ValueError("Provider Host launch phase update is invalid")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                "UPDATE launches SET phase=?,updated_at=? WHERE launch_id=? AND state=?",
                (phase, _now(), launch_id, expected_state),
            )
            if result.rowcount != 1:
                raise PermissionError("Provider Host launch phase update was rejected")
            connection.commit()

    def complete_setup(
        self,
        launch_id: str,
        expected_state: str,
        state: str,
        signed_result: dict[str, object],
    ) -> None:
        if state not in _TERMINAL_STATES:
            raise ValueError("Provider Host setup terminal state is invalid")
        serialized = json.dumps(
            signed_result, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT operation FROM launches WHERE launch_id=? AND state=?",
                (launch_id, expected_state),
            ).fetchone()
            if row is None or str(row["operation"]) not in {
                "REGISTER_PROBE",
                "QUALIFY",
            }:
                raise PermissionError(
                    "Provider Host setup terminal transition was rejected"
                )
            cursor = connection.execute(
                "UPDATE launches SET state=?,phase='TERMINAL',terminal_result=?,"
                "terminal_result_hash=?,updated_at=? WHERE launch_id=? AND state=?",
                (
                    state,
                    serialized,
                    digest,
                    _now(),
                    launch_id,
                    expected_state,
                ),
            )
            if cursor.rowcount != 1:
                raise PermissionError(
                    "Provider Host setup terminal transition lost its claim"
                )
            connection.commit()

    def terminal_setup_result(self, launch_id: str) -> dict[str, object] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT state,operation,terminal_result,terminal_result_hash "
                "FROM launches WHERE launch_id=?",
                (launch_id,),
            ).fetchone()
        if row is None:
            return None
        if str(row["state"]) not in _TERMINAL_STATES:
            raise PermissionError("Provider Host setup result is not terminal")
        if str(row["operation"]) not in {"REGISTER_PROBE", "QUALIFY"}:
            raise PermissionError("Provider Host terminal launch is not setup work")
        serialized = row["terminal_result"]
        digest = row["terminal_result_hash"]
        if not isinstance(serialized, str) or not isinstance(digest, str):
            raise RuntimeError("Provider Host terminal setup result is unavailable")
        if hashlib.sha256(serialized.encode("utf-8")).hexdigest() != digest:
            raise RuntimeError("Provider Host terminal setup result integrity failed")
        value = json.loads(serialized)
        if not isinstance(value, dict):
            raise RuntimeError("Provider Host terminal setup result is malformed")
        return value

    def recover_uncertain(self, reason: str) -> int:
        with self.connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                result = connection.execute(
                    "UPDATE launches SET state='UNCERTAIN',detail=?,updated_at=? "
                    "WHERE state IN ('CLAIMED','STARTED','RUNNING')",
                    (reason[:500], _now()),
                )
                connection.commit()
                return int(result.rowcount)
            except BaseException:
                connection.rollback()
                raise

    def set_host_state(self, state: str, detail: str = "") -> None:
        allowed = {
            "STARTING",
            "READY",
            "PREPARING",
            "CLAIMED",
            "STARTED",
            "RUNNING",
            "LOCKED",
            "DRAINING",
            "STOPPED",
            "STALE",
        }
        if state not in allowed:
            raise ValueError("Provider Host lifecycle state is invalid")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO host_state(singleton,state,detail,updated_at) VALUES(1,?,?,?) "
                "ON CONFLICT(singleton) DO UPDATE SET state=excluded.state,"
                "detail=excluded.detail,updated_at=excluded.updated_at",
                (state, detail[:500], _now()),
            )
            connection.commit()

    def get_launch(self, launch_id: str) -> dict[str, object]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM launches WHERE launch_id=?", (launch_id,)
            ).fetchone()
            if row is None:
                raise KeyError(launch_id)
            return dict(row)

    def list_active(self) -> list[dict[str, object]]:
        with self.connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM launches WHERE state IN "
                    "('CLAIMED','STARTED','RUNNING','UNCERTAIN') ORDER BY launch_id"
                ).fetchall()
            ]

    def active_or_uncertain_summary(self) -> dict[str, object]:
        records = self.list_active()
        return self._launch_summary(records)

    def recovery_barrier_summary(self) -> dict[str, object]:
        """Advance a durable barrier and snapshot the launch journal atomically."""

        with self.connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key='recovery_barrier_generation'"
                ).fetchone()
                generation = 1 if row is None else int(row[0]) + 1
                connection.execute(
                    "INSERT INTO metadata(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ("recovery_barrier_generation", str(generation)),
                )
                records = [
                    dict(item)
                    for item in connection.execute(
                        "SELECT * FROM launches WHERE state IN "
                        "('CLAIMED','STARTED','RUNNING','UNCERTAIN') "
                        "ORDER BY launch_id"
                    ).fetchall()
                ]
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        return {
            "recovery_barrier_generation": generation,
            **self._launch_summary(records),
        }

    @staticmethod
    def _launch_summary(records: list[dict[str, object]]) -> dict[str, object]:
        entries = [_public_launch_record(record) for record in records]
        active = sum(
            1 for record in records if record["state"] in {"CLAIMED", "STARTED", "RUNNING"}
        )
        uncertain = sum(1 for record in records if record["state"] == "UNCERTAIN")
        return {
            "active_or_uncertain_launch_count": len(entries),
            "active_launch_count": active,
            "uncertain_launch_count": uncertain,
            "launches": entries,
            "summary_digest": hashlib.sha256(
                json.dumps(
                    entries, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode("utf-8")
            ).hexdigest(),
        }

    def reconcile_uncertain_registration_probe(
        self,
        expected: dict[str, object],
        reconciliation: dict[str, object],
    ) -> dict[str, object]:
        serialized = json.dumps(
            reconciliation, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        launch_id = str(expected.get("launch_id", ""))
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM launches WHERE launch_id=?", (launch_id,)
            ).fetchone()
            if row is None:
                raise PermissionError("Provider Host uncertain launch is absent")
            current = dict(row)
            public = _public_launch_record(current)
            if current.get("state") == "FAILED" and current.get("reconciliation_hash") == digest:
                return expected | {
                    "state": "FAILED",
                    "reconciliation_digest": digest,
                }
            if public != expected or current.get("state") != "UNCERTAIN":
                raise PermissionError("Provider Host uncertain launch identity differs")
            operation = str(current.get("operation", ""))
            if operation == "LEGACY_UNKNOWN":
                if not launch_id.startswith("provider-registration-probe:"):
                    raise PermissionError("Provider Host legacy launch operation is unverifiable")
            elif operation != "REGISTER_PROBE":
                raise PermissionError("Provider Host uncertain launch is not a registration probe")
            cursor = connection.execute(
                "UPDATE launches SET state='FAILED',detail='RECONCILED_READ_ONLY_PROBE',"
                "phase='TERMINAL',updated_at=?,reconciliation=?,reconciliation_hash=? "
                "WHERE launch_id=? AND state='UNCERTAIN'",
                (_now(), serialized, digest, launch_id),
            )
            if cursor.rowcount != 1:
                raise PermissionError(
                    "Provider Host uncertain launch reconciliation lost its claim"
                )
            connection.commit()
        return public | {"state": "FAILED", "reconciliation_digest": digest}

    def bind_provider(self, value: dict[str, object]) -> None:
        registration_id = value.get("registration_id")
        provider_id = value.get("provider_id")
        if (
            not isinstance(registration_id, str)
            or not registration_id
            or not isinstance(provider_id, str)
            or not provider_id
        ):
            raise PermissionError("Provider Host provider binding identity is invalid")
        serialized = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        with self.connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT payload,payload_hash FROM provider_bindings "
                    "WHERE registration_id=?",
                    (registration_id,),
                ).fetchone()
                if row is not None:
                    current = str(row["payload"])
                    if hashlib.sha256(current.encode("utf-8")).hexdigest() != row["payload_hash"]:
                        raise RuntimeError("Provider Host provider binding integrity failed")
                    if current != serialized:
                        raise PermissionError("Provider Host provider binding conflicts")
                    connection.commit()
                    return
                provider_row = connection.execute(
                    "SELECT registration_id,payload,payload_hash FROM provider_bindings "
                    "WHERE provider_id=?",
                    (provider_id,),
                ).fetchone()
                if provider_row is not None:
                    current = str(provider_row["payload"])
                    if (
                        hashlib.sha256(current.encode("utf-8")).hexdigest()
                        != provider_row["payload_hash"]
                    ):
                        raise RuntimeError(
                            "Provider Host provider binding integrity failed"
                        )
                    raise PermissionError("Provider Host provider binding conflicts")
                connection.execute(
                    "INSERT INTO provider_bindings(registration_id,provider_id,payload,"
                    "payload_hash,updated_at) VALUES(?,?,?,?,?)",
                    (registration_id, provider_id, serialized, digest, _now()),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def provider_binding(self) -> dict[str, object] | None:
        bindings = self.provider_bindings()
        if not bindings:
            return None
        for binding in bindings:
            if binding.get("provider_id") == "codex":
                return binding
        return bindings[0]

    def provider_bindings(self) -> tuple[dict[str, object], ...]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT registration_id,provider_id,payload,payload_hash "
                "FROM provider_bindings ORDER BY provider_id,registration_id"
            ).fetchall()
        result: list[dict[str, object]] = []
        for row in rows:
            serialized = str(row["payload"])
            if (
                hashlib.sha256(serialized.encode("utf-8")).hexdigest()
                != row["payload_hash"]
            ):
                raise RuntimeError("Provider Host provider binding integrity failed")
            value = json.loads(serialized)
            if (
                not isinstance(value, dict)
                or value.get("registration_id") != row["registration_id"]
                or value.get("provider_id") != row["provider_id"]
            ):
                raise RuntimeError("Provider Host provider binding is malformed")
            result.append(value)
        return tuple(result)

    def _migrate(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                "CREATE TABLE IF NOT EXISTS replay("
                "authority_id TEXT NOT NULL,nonce TEXT NOT NULL UNIQUE,"
                "sequence INTEGER NOT NULL,expires_at TEXT NOT NULL,"
                "PRIMARY KEY(authority_id,sequence));"
                "CREATE TABLE IF NOT EXISTS launches("
                "launch_id TEXT PRIMARY KEY,authority_attempt_id TEXT NOT NULL UNIQUE,"
                "envelope_digest TEXT NOT NULL,workspace_path TEXT NOT NULL,"
                "state TEXT NOT NULL,detail TEXT NOT NULL,updated_at TEXT NOT NULL,"
                "operation TEXT NOT NULL DEFAULT 'LEGACY_UNKNOWN',"
                "phase TEXT NOT NULL DEFAULT 'LEGACY_UNRECORDED',"
                "reconciliation TEXT,reconciliation_hash TEXT,"
                "terminal_result TEXT,terminal_result_hash TEXT);"
                "CREATE TABLE IF NOT EXISTS message_replay("
                "channel TEXT NOT NULL,authority_id TEXT NOT NULL,"
                "nonce TEXT NOT NULL UNIQUE,sequence INTEGER NOT NULL,"
                "expires_at TEXT NOT NULL,PRIMARY KEY(channel,authority_id,sequence));"
                "CREATE TABLE IF NOT EXISTS host_state("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                "state TEXT NOT NULL,detail TEXT NOT NULL,updated_at TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS provider_binding("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                "payload TEXT NOT NULL,payload_hash TEXT NOT NULL,updated_at TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS provider_bindings("
                "registration_id TEXT PRIMARY KEY,provider_id TEXT NOT NULL UNIQUE,"
                "payload TEXT NOT NULL,payload_hash TEXT NOT NULL,updated_at TEXT NOT NULL);"
            )
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO metadata(key,value) VALUES('schema_version','4')"
                )
            elif str(row[0]) in {"1", "2", "3"}:
                columns = {
                    str(value[1])
                    for value in connection.execute(
                        "PRAGMA table_info(launches)"
                    ).fetchall()
                }
                for name, declaration in (
                    ("operation", "TEXT NOT NULL DEFAULT 'LEGACY_UNKNOWN'"),
                    ("phase", "TEXT NOT NULL DEFAULT 'LEGACY_UNRECORDED'"),
                    ("reconciliation", "TEXT"),
                    ("reconciliation_hash", "TEXT"),
                    ("terminal_result", "TEXT"),
                    ("terminal_result_hash", "TEXT"),
                ):
                    if name not in columns:
                        connection.execute(
                            f"ALTER TABLE launches ADD COLUMN {name} {declaration}"
                        )
                connection.execute(
                    "UPDATE metadata SET value='4' WHERE key='schema_version'"
                )
            elif str(row[0]) not in {"4", "5"}:
                raise RuntimeError("Provider Host store schema is incompatible")
            legacy = connection.execute(
                "SELECT payload,payload_hash FROM provider_binding WHERE singleton=1"
            ).fetchone()
            if legacy is not None:
                serialized = str(legacy["payload"])
                if (
                    hashlib.sha256(serialized.encode("utf-8")).hexdigest()
                    != legacy["payload_hash"]
                ):
                    raise RuntimeError("Provider Host provider binding integrity failed")
                value = json.loads(serialized)
                if not isinstance(value, dict):
                    raise RuntimeError("Provider Host provider binding is malformed")
                registration_id = value.get("registration_id")
                provider_id = value.get("provider_id")
                if not isinstance(registration_id, str) or not isinstance(provider_id, str):
                    raise RuntimeError("Provider Host provider binding is malformed")
                connection.execute(
                    "INSERT INTO provider_bindings(registration_id,provider_id,payload,"
                    "payload_hash,updated_at) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(registration_id) DO NOTHING",
                    (
                        registration_id,
                        provider_id,
                        serialized,
                        str(legacy["payload_hash"]),
                        _now(),
                    ),
                )
            connection.execute(
                "UPDATE metadata SET value='5' WHERE key='schema_version'"
            )
            connection.commit()


def _canonical_workspace(value: str) -> str:
    if not value or "\x00" in value:
        raise PermissionError("Provider Host workspace is invalid")
    path = Path(value)
    if not path.is_absolute():
        raise PermissionError("Provider Host workspace is not absolute")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise PermissionError("Provider Host workspace cannot be resolved") from error
    if os.path.normcase(os.path.abspath(value)) != os.path.normcase(str(resolved)):
        raise PermissionError("Provider Host workspace is not canonical")
    return str(resolved)


def _paths_overlap(left: str, right: str) -> bool:
    left_path = os.path.normcase(os.path.abspath(left))
    right_path = os.path.normcase(os.path.abspath(right))
    try:
        common = os.path.commonpath((left_path, right_path))
    except ValueError:
        return False
    return common in {left_path, right_path}


def _public_launch_record(record: dict[str, object]) -> dict[str, object]:
    detail = str(record.get("detail", ""))
    detail_code = (
        detail
        if detail
        and len(detail) <= 80
        and detail.replace("_", "").isalnum()
        else "UNAVAILABLE"
    )
    workspace = str(record.get("workspace_path", ""))
    return {
        "authority_attempt_id": str(record.get("authority_attempt_id", "")),
        "detail_code": detail_code,
        "envelope_digest": str(record.get("envelope_digest", "")),
        "launch_id": str(record.get("launch_id", "")),
        "operation": str(record.get("operation", "LEGACY_UNKNOWN")),
        "phase": str(record.get("phase", "LEGACY_UNRECORDED")),
        "state": str(record.get("state", "")),
        "updated_at": str(record.get("updated_at", "")),
        "workspace_digest": hashlib.sha256(
            workspace.casefold().encode("utf-8")
        ).hexdigest(),
    }


def _now() -> str:
    return datetime.now(UTC).isoformat()
