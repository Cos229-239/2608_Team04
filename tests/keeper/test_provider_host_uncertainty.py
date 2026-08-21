from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from keeper.authority_service.observer import ServiceProviderObserver
from keeper.authority_service.core import AuthorityServiceCore
from keeper.authority_service.protocol import Operation, Request
from keeper.authority_service.provider_host_gateway import _validate_host_status
from keeper.provider_host.protocol import structured_digest
from keeper.provider_host.replay_store import ProviderHostStore


def _claim(
    store: ProviderHostStore,
    workspace: Path,
    *,
    launch_id: str = "provider-registration-probe:" + "a" * 32,
    operation: str = "REGISTER_PROBE",
) -> None:
    now = datetime.now(UTC)
    store.claim_launch(
        authority_id="authority-test",
        nonce="b" * 32,
        sequence=1,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=1)).isoformat(),
        now=now,
        maximum_ttl=timedelta(minutes=2),
        maximum_future_skew=timedelta(seconds=5),
        launch_id=launch_id,
        authority_attempt_id=launch_id,
        envelope_digest="c" * 64,
        workspace_path=str(workspace.resolve()),
        operation=operation,
    )


def test_launch_journal_exposes_unresolved_state_without_workspace_path(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = ProviderHostStore(tmp_path / "state" / "host.db")
    _claim(store, workspace)
    store.transition(
        "provider-registration-probe:" + "a" * 32,
        "CLAIMED",
        "STARTED",
        phase="STARTED_AWAITING_ACK",
    )
    store.transition(
        "provider-registration-probe:" + "a" * 32,
        "STARTED",
        "UNCERTAIN",
        detail="PermissionError",
    )

    summary = store.active_or_uncertain_summary()

    assert summary["active_or_uncertain_launch_count"] == 1
    assert summary["active_launch_count"] == 0
    assert summary["uncertain_launch_count"] == 1
    assert summary["summary_digest"] == structured_digest(summary["launches"])
    launch = summary["launches"][0]  # type: ignore[index]
    assert launch["state"] == "UNCERTAIN"
    assert launch["phase"] == "STARTED_AWAITING_ACK"
    assert str(workspace) not in str(summary)


def test_schema_two_legacy_probe_migrates_and_reconciles_exactly(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    database = state / "host.db"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launch_id = "provider-registration-probe:" + "d" * 32
    with sqlite3.connect(database) as connection:
        connection.executescript(
            "CREATE TABLE replay(authority_id TEXT NOT NULL,nonce TEXT NOT NULL UNIQUE,"
            "sequence INTEGER NOT NULL,expires_at TEXT NOT NULL,PRIMARY KEY(authority_id,sequence));"
            "CREATE TABLE launches(launch_id TEXT PRIMARY KEY,authority_attempt_id TEXT NOT NULL UNIQUE,"
            "envelope_digest TEXT NOT NULL,workspace_path TEXT NOT NULL,state TEXT NOT NULL,"
            "detail TEXT NOT NULL,updated_at TEXT NOT NULL);"
            "CREATE TABLE message_replay(channel TEXT NOT NULL,authority_id TEXT NOT NULL,"
            "nonce TEXT NOT NULL UNIQUE,sequence INTEGER NOT NULL,expires_at TEXT NOT NULL,"
            "PRIMARY KEY(channel,authority_id,sequence));"
            "CREATE TABLE host_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
            "state TEXT NOT NULL,detail TEXT NOT NULL,updated_at TEXT NOT NULL);"
            "CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
            "CREATE TABLE provider_binding(singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
            "payload TEXT NOT NULL,payload_hash TEXT NOT NULL,updated_at TEXT NOT NULL);"
        )
        connection.execute(
            "INSERT INTO metadata VALUES('schema_version','2')"
        )
        connection.execute(
            "INSERT INTO launches VALUES(?,?,?,?,?,?,?)",
            (
                launch_id,
                launch_id,
                "e" * 64,
                str(workspace.resolve()),
                "UNCERTAIN",
                "PermissionError",
                datetime.now(UTC).isoformat(),
            ),
        )
    store = ProviderHostStore(database)
    expected = store.active_or_uncertain_summary()["launches"][0]  # type: ignore[index]
    assert expected["operation"] == "LEGACY_UNKNOWN"
    assert expected["phase"] == "LEGACY_UNRECORDED"
    reconciliation: dict[str, object] = {
        "authorization_digest": "f" * 64,
        "effect_accounting": {
            "model_request_possible": False,
            "provider_mutation_possible": False,
            "read_only_process_execution_upper_bound": 2,
            "usage_observation_possible": True,
        },
        "reconciliation_id": "provider-host-launch-reconciliation:" + "1" * 64,
        "resolution": "LEGACY_REGISTER_PROBE_READ_ONLY_EFFECT_ACCOUNTED",
    }

    first = store.reconcile_uncertain_registration_probe(expected, reconciliation)
    second = store.reconcile_uncertain_registration_probe(expected, reconciliation)

    assert first == second
    assert first["state"] == "FAILED"
    assert store.active_or_uncertain_summary()["active_or_uncertain_launch_count"] == 0


def test_qualification_uncertainty_cannot_use_registration_reconciliation(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = ProviderHostStore(tmp_path / "state" / "host.db")
    _claim(
        store,
        workspace,
        launch_id="provider-qualification:" + "2" * 32,
        operation="QUALIFY",
    )
    store.transition(
        "provider-qualification:" + "2" * 32,
        "CLAIMED",
        "UNCERTAIN",
        detail="RuntimeError",
    )
    expected = store.active_or_uncertain_summary()["launches"][0]  # type: ignore[index]
    with pytest.raises(PermissionError, match="not a registration probe"):
        store.reconcile_uncertain_registration_probe(expected, {"id": "no"})


@pytest.mark.parametrize("operation", ["REGISTER_PROBE", "QUALIFY"])
def test_terminal_setup_result_survives_restart_and_leaves_no_active_work(
    tmp_path: Path, operation: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launch_id = (
        "provider-registration-probe:" if operation == "REGISTER_PROBE"
        else "provider-qualification:"
    ) + "4" * 32
    database = tmp_path / "state" / "terminal.db"
    store = ProviderHostStore(database)
    _claim(store, workspace, launch_id=launch_id, operation=operation)
    store.transition(launch_id, "CLAIMED", "STARTED", phase="RESUMED")
    store.transition(launch_id, "STARTED", "RUNNING", phase="RESUMED")
    signed_result: dict[str, object] = {
        "authority_id": "authority-test",
        "host_id": "host-test",
        "setup_id": launch_id,
        "challenge": "5" * 64,
        "operation": operation,
        "signed": "terminal-result",
    }

    store.complete_setup(launch_id, "RUNNING", "COMPLETED", signed_result)

    restarted = ProviderHostStore(database)
    assert restarted.active_or_uncertain_summary()[
        "active_or_uncertain_launch_count"
    ] == 0
    assert restarted.terminal_setup_result(launch_id) == signed_result


def test_terminal_setup_result_integrity_tamper_fails_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launch_id = "provider-registration-probe:" + "6" * 32
    database = tmp_path / "state" / "tamper.db"
    store = ProviderHostStore(database)
    _claim(store, workspace, launch_id=launch_id)
    store.complete_setup(
        launch_id,
        "CLAIMED",
        "FAILED",
        {"setup_id": launch_id, "signed": "result"},
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE launches SET terminal_result='{}' WHERE launch_id=?",
            (launch_id,),
        )

    with pytest.raises(RuntimeError, match="integrity failed"):
        ProviderHostStore(database).terminal_setup_result(launch_id)


class _Gateway:
    def __init__(self, status: dict[str, object]) -> None:
        self._status = status

    def status(self) -> dict[str, object]:
        return self._status


def test_observer_never_reports_idle_for_uncertain_durable_launch() -> None:
    launch = {
        "authority_attempt_id": "provider-registration-probe:" + "3" * 32,
        "detail_code": "PermissionError",
        "envelope_digest": "4" * 64,
        "launch_id": "provider-registration-probe:" + "3" * 32,
        "operation": "LEGACY_UNKNOWN",
        "phase": "LEGACY_UNRECORDED",
        "state": "UNCERTAIN",
        "updated_at": datetime.now(UTC).isoformat(),
        "workspace_digest": "5" * 64,
    }
    observer = object.__new__(ServiceProviderObserver)
    observer.provider_host_gateway = cast(
        Any,
        _Gateway(
            {
                "host_protocol": "keeper-provider-host/1",
                "launch_journal": {
                    "active_launch_count": 0,
                    "active_or_uncertain_launch_count": 1,
                    "launches": [launch],
                    "summary_digest": structured_digest([launch]),
                    "uncertain_launch_count": 1,
                },
                "provider_binding": None,
                "state": "READY",
            },
        ),
    )

    status = observer.provider_host_status()

    assert status["state"] == "READY"
    assert status["execution_state"] == "UNCERTAIN"
    assert status["founder_action_required"] == "RECONCILE_PROVIDER_HOST_LAUNCH"
    assert status["active_or_uncertain_launch_count"] == 1


def test_gateway_status_validator_rejects_false_zero_accounting() -> None:
    launch = {
        "authority_attempt_id": "attempt",
        "detail_code": "PermissionError",
        "envelope_digest": "6" * 64,
        "launch_id": "launch",
        "operation": "REGISTER_PROBE",
        "phase": "STARTED_AWAITING_ACK",
        "state": "UNCERTAIN",
        "updated_at": datetime.now(UTC).isoformat(),
        "workspace_digest": "7" * 64,
    }
    with pytest.raises(PermissionError, match="accounting differs"):
        _validate_host_status(
            {
                "launch_journal": {
                    "active_launch_count": 0,
                    "active_or_uncertain_launch_count": 0,
                    "launches": [launch],
                    "summary_digest": structured_digest([launch]),
                    "uncertain_launch_count": 0,
                }
            }
        )


def test_authority_serializes_zero_work_revocation_against_new_host_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = AuthorityServiceCore(tmp_path / "authority")
    revocation_inside = threading.Event()
    release_revocation = threading.Event()
    registration_inside = threading.Event()

    def revoke(payload: dict[str, object], client_sid: str) -> dict[str, object]:
        del payload, client_sid
        revocation_inside.set()
        assert release_revocation.wait(timeout=5)
        return {"state": "REVOKED"}

    def register(payload: dict[str, object], client_sid: str) -> dict[str, object]:
        del payload, client_sid
        registration_inside.set()
        return {"state": "REGISTERED"}

    monkeypatch.setattr(core, "_revoke_provider_host_enrollment", revoke)
    monkeypatch.setattr(core, "_register_provider", register)
    with ThreadPoolExecutor(max_workers=2) as pool:
        revoking = pool.submit(
            core.dispatch,
            Request.create(Operation.REVOKE_PROVIDER_HOST_ENROLLMENT, {}),
            "S-1-5-21-1000",
        )
        assert revocation_inside.wait(timeout=5)
        registering = pool.submit(
            core.dispatch,
            Request.create(Operation.REGISTER_PROVIDER, {}),
            "S-1-5-21-1000",
        )
        assert not registration_inside.wait(timeout=0.1)
        release_revocation.set()
        assert revoking.result(timeout=5)["state"] == "REVOKED"
        assert registering.result(timeout=5)["state"] == "REGISTERED"
    assert registration_inside.is_set()
