from __future__ import annotations

import hashlib
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from keeper.app.storage import KeeperStore
from keeper.providers.codex_cli import CliProvider
from keeper.recovery import ProcessProbe, ProcessState


def test_process_probe_states_are_explicit() -> None:
    assert ProcessProbe(ProcessState.CONFIRMED_ABSENT, "missing").state.value == (
        "confirmed_absent"
    )
    denied = ProcessProbe(ProcessState.INDETERMINATE, "access denied", 5)
    assert denied.state is ProcessState.INDETERMINATE
    assert denied.os_error == 5


def test_missing_immutable_command_registration_fails_closed(tmp_path: Path) -> None:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"provider")
    with pytest.raises(PermissionError, match="registration is incomplete"):
        CliProvider((str(executable), "{prompt}")).validate()


def test_same_size_registered_content_change_fails_closed(tmp_path: Path) -> None:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"first")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    provider = CliProvider(
        (str(executable), "{prompt}"),
        expected_executable_sha256=digest,
        expected_executable_size=5,
        registration_id="test-provider",
        registration_version="1",
        configuration_digest="c" * 64,
    )
    provider.validate()
    executable.write_bytes(b"other")
    with pytest.raises(PermissionError, match="content changed"):
        provider.validate()


def test_two_independent_connections_cannot_consume_one_reroute(
    tmp_path: Path,
) -> None:
    path = tmp_path / "keeper.sqlite3"
    first = KeeperStore(path)
    second = KeeperStore(path)
    first.migrate()
    expected = {
        "capability": "provider_reroute",
        "task_id": "task",
        "run_id": "run",
        "retry_stage": "review",
        "provider_policy": "independent",
        "from_routing_digest": "a" * 64,
        "to_routing_digest": "b" * 64,
        "source_attempt_id": "source",
        "destination_attempt_number": 2,
        "capability_requirements": {"reviewer": "review"},
        "independence_requirements": {"reviewer": "independent"},
    }
    authorization = {
        "id": "authorization",
        **expected,
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "revoked_at": None,
        "consumed_at": None,
    }
    first.upsert("authorizations", "authorization", authorization)
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def consume(store: KeeperStore, consumer: str) -> None:
        barrier.wait()
        try:
            store.consume_reroute_authorization(
                "authorization", expected, consumer_id=consumer
            )
            outcomes.append("won")
        except PermissionError:
            outcomes.append("lost")

    threads = [
        threading.Thread(target=consume, args=(first, "first")),
        threading.Thread(target=consume, args=(second, "second")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["lost", "won"]
    stored = first.get("authorizations", "authorization")
    assert stored is not None
    assert stored["consumption_state"] == "RESERVED"
    assert stored["consumed_at"]
    with pytest.raises(PermissionError):
        first.consume_reroute_authorization("authorization", expected)
