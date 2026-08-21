from __future__ import annotations

import hashlib
import os
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterator

import pytest

import keeper.authority_service.provider_host_gateway as gateway_module
import keeper.authority_service.restricted_process as restricted_process_module
import keeper.authority_service.service_main as service_main_module
import keeper.authority_service.windows_identity as windows_identity_module
import keeper.provider_host.cli as cli_module
import keeper.provider_host.identity as identity_module
import keeper.provider_host.server as server_module
from keeper.authority_service.provider_host_gateway import ProviderHostGateway
from keeper.authority_service.windows_identity import (
    NamedPipeClientProcessBinding,
    NamedPipeClientProcessIdentity,
    RestrictedServicePipeTokenIdentity,
    authenticated_named_pipe_client_process,
)
from keeper.provider_host.identity import (
    PipePeerIdentity,
    ProviderHostIdentityUncertain,
    current_user_binding,
)
from keeper.provider_host.pipe import (
    connected_client_pipe,
    connected_server_pipe,
    read_frame,
    write_frame,
)
from keeper.provider_host.protocol import (
    HELLO_PURPOSE,
    REQUEST_PURPOSE,
    RESPONSE_PURPOSE,
    STARTED_ACK_PURPOSE,
    STARTED_PURPOSE,
    TestEnvelopeIdentity as EnvelopeTestIdentity,
    structured_digest,
)
from keeper.provider_host.replay_store import ProviderHostStore
from keeper.provider_host.server import ProviderHostServer
from keeper.provider_host.server import _validate_started_ack


SID = "S-1-5-21-1000"
AUTHORITY_SERVICE_SID = "S-1-5-80-1-2-3-4-5"
AUTHORITY_SID = AUTHORITY_SERVICE_SID
AUTHORITY = EnvelopeTestIdentity("authority-test", b"authority-test-key")
HOST = EnvelopeTestIdentity("host-test", b"host-test-key")


def _expected_host(profile: Path) -> Path:
    return (
        profile
        / "AppData"
        / "Local"
        / "Programs"
        / "DarkSage"
        / "KeeperProviderHost"
        / "versions"
        / "1.7.15"
        / "KeeperProviderHost.exe"
    )


def _expected_peer(
    executable: Path,
    *,
    file_identity: tuple[int, int, int, int] = (7, 11, 4096, 123456789),
) -> PipePeerIdentity:
    return PipePeerIdentity(
        process_id=0,
        session_id=3,
        user_sid=SID,
        executable_path=str(executable),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        executable_file_identity=file_identity,
    )


@contextmanager
def _gateway_binding(
    identity: NamedPipeClientProcessIdentity,
) -> Iterator[object]:
    class Binding:
        @staticmethod
        def revalidate_core(expected_sid: str) -> NamedPipeClientProcessIdentity:
            del expected_sid
            return identity

        revalidate_retained = revalidate_core

    yield Binding()


@contextmanager
def _gateway_checked_binding(
    identity: NamedPipeClientProcessIdentity,
    expected: PipePeerIdentity,
) -> Iterator[object]:
    identity_module._require_expected_host_core(identity, expected)
    with _gateway_binding(identity) as binding:
        yield binding


def _gateway(
    tmp_path: Path,
    *,
    active: bool = True,
    file_identity: tuple[int, int, int, int] | None = (
        7,
        11,
        4096,
        123456789,
    ),
) -> ProviderHostGateway:
    profile = tmp_path / "profile"
    profile.mkdir(exist_ok=True)
    return ProviderHostGateway(
        pipe_name=r"\\.\pipe\KeeperProviderHost-peer-test",
        authority_id="authority-test",
        host_id="host-test",
        authority_signer=AUTHORITY,
        host_verifier=HOST,
        expected_host_sid=SID,
        expected_host_session_id=3,
        expected_host_executable=_expected_host(profile),
        expected_host_executable_sha256="a" * 64,
        expected_host_profile_path=profile,
        sequence_store=tmp_path / "sequences.db",
        expected_host_executable_file_identity=file_identity,
        enrollment_is_active=lambda: active,
        production=False,
    )


def test_gateway_construction_does_not_touch_user_owned_host_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = _expected_host(tmp_path / "profile")
    assert not expected.exists()

    def forbidden(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("Authority constructor touched protected Host path")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    gateway = _gateway(tmp_path)

    assert gateway.expected_host_executable == expected
    assert not expected.exists()


def test_dynamic_gateway_activation_requires_exact_durable_file_identity() -> None:
    installation: dict[str, object] = {
        "executable_file_identity": {
            "device_id": 7,
            "file_id": 11,
            "modified_ns": 123456789,
            "schema_version": 1,
            "size": 4096,
        }
    }
    assert service_main_module._host_executable_file_identity(installation) == (
        7,
        11,
        4096,
        123456789,
    )


@pytest.mark.parametrize(
    "mutation",
    ["missing", "extra", "boolean", "zero-file", "zero-size", "old-schema"],
)
def test_dynamic_gateway_activation_rejects_invalid_file_identity(
    mutation: str,
) -> None:
    identity: dict[str, object] = {
        "device_id": 7,
        "file_id": 11,
        "modified_ns": 123456789,
        "schema_version": 1,
        "size": 4096,
    }
    installation: dict[str, object] = {"executable_file_identity": identity}
    if mutation == "missing":
        installation = {}
    elif mutation == "extra":
        identity["unexpected"] = 1
    elif mutation == "boolean":
        identity["device_id"] = True
    elif mutation == "zero-file":
        identity["file_id"] = 0
    elif mutation == "zero-size":
        identity["size"] = 0
    else:
        identity["schema_version"] = 0

    with pytest.raises(PermissionError, match="file identity"):
        service_main_module._host_executable_file_identity(installation)


def test_gateway_rejects_peer_mismatch_before_first_protocol_frame(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gateway = _gateway(tmp_path)
    writes: list[object] = []

    @contextmanager
    def connected(*args: object, **kwargs: object) -> Iterator[int]:
        del args, kwargs
        yield 41

    monkeypatch.setattr(gateway_module, "connected_client_pipe", connected)
    monkeypatch.setattr(
        gateway_module,
        "authenticated_named_pipe_server_binding",
        lambda pipe, *, expected: _gateway_checked_binding(
            NamedPipeClientProcessIdentity(
                process_id=700,
                session_id=3,
                sid=expected.user_sid,
                computer_name="LOCAL",
                process_creation_time_100ns=123,
                executable_path=str(
                    gateway.expected_host_executable.parent / "other.exe"
                ),
            ),
            expected,
        ),
    )
    monkeypatch.setattr(
        gateway_module, "write_frame", lambda *args: writes.append(args)
    )

    with pytest.raises(PermissionError, match="peer identity differs"):
        gateway.status()

    assert writes == []


@pytest.mark.parametrize(
    "mutation", ["session", "sid", "path"]
)
def test_gateway_rejects_every_host_identity_mismatch_before_first_frame(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    expected_identity = (7, 11, 4096, 123456789)
    gateway = _gateway(tmp_path, file_identity=expected_identity)
    values: dict[str, object] = {
        "process_id": 700,
        "session_id": 3,
        "user_sid": SID,
        "executable_path": str(gateway.expected_host_executable),
        "executable_sha256": "a" * 64,
        "executable_file_identity": expected_identity,
    }
    if mutation == "session":
        values["session_id"] = 4
    elif mutation == "sid":
        values["user_sid"] = "S-1-5-21-2000"
    elif mutation == "path":
        values["executable_path"] = str(
            gateway.expected_host_executable.parent / "other.exe"
        )
    writes: list[object] = []

    @contextmanager
    def connected(*args: object, **kwargs: object) -> Iterator[int]:
        del args, kwargs
        yield 41

    monkeypatch.setattr(gateway_module, "connected_client_pipe", connected)
    monkeypatch.setattr(
        gateway_module,
        "authenticated_named_pipe_server_binding",
        lambda pipe, *, expected: _gateway_checked_binding(
            NamedPipeClientProcessIdentity(
                process_id=700,
                session_id=int(values["session_id"]),
                sid=str(values["user_sid"]),
                computer_name="LOCAL",
                process_creation_time_100ns=123,
                executable_path=str(values["executable_path"]),
            ),
            expected,
        ),
    )
    monkeypatch.setattr(
        gateway_module, "write_frame", lambda *args: writes.append(args)
    )

    with pytest.raises(PermissionError, match="peer identity differs"):
        gateway.status()

    assert writes == []


def test_gateway_identity_uncertainty_disables_automatic_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gateway = _gateway(tmp_path)
    connections = 0

    @contextmanager
    def connected(*args: object, **kwargs: object) -> Iterator[int]:
        nonlocal connections
        del args, kwargs
        connections += 1
        yield 41

    monkeypatch.setattr(gateway_module, "connected_client_pipe", connected)
    monkeypatch.setattr(
        gateway_module,
        "authenticated_named_pipe_server_binding",
        lambda pipe, *, expected: (_ for _ in ()).throw(
            ProviderHostIdentityUncertain("synthetic bounded-worker timeout")
        ),
    )

    with pytest.raises(ProviderHostIdentityUncertain, match="timeout"):
        gateway.status()
    with pytest.raises(PermissionError, match="enrollment is not active"):
        gateway.status()

    assert connections == 1


def test_gateway_rejects_wrong_signed_host_process_id_before_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gateway = _gateway(tmp_path)
    writes: list[dict[str, object]] = []

    @contextmanager
    def connected(*args: object, **kwargs: object) -> Iterator[int]:
        del args, kwargs
        yield 41

    monkeypatch.setattr(gateway_module, "connected_client_pipe", connected)
    monkeypatch.setattr(
        gateway_module,
        "authenticated_named_pipe_server_binding",
        lambda pipe, *, expected: _gateway_binding(NamedPipeClientProcessIdentity(
            process_id=700,
            session_id=3,
            sid=expected.user_sid,
            computer_name="LOCAL",
            process_creation_time_100ns=123,
            executable_path=str(gateway.expected_host_executable),
        )),
    )
    monkeypatch.setattr(
        gateway_module,
        "write_frame",
        lambda pipe, value: writes.append(dict(value)),
    )

    def read(pipe: int) -> dict[str, object]:
        del pipe
        authority_hello = AUTHORITY.verify(
            writes[0], purpose=HELLO_PURPOSE
        )
        return HOST.sign(
            HELLO_PURPOSE,
            {
                "authority_nonce": authority_hello["nonce"],
                "host_id": "host-test",
                "host_nonce": "host-nonce",
                "host_process_id": 701,
                "host_executable_file_identity": gateway_module._file_identity_record(
                    gateway.expected_host_executable_file_identity
                ),
                "host_executable_sha256": "a" * 64,
                "state": "READY",
                "user_binding": {
                    "profile_path": str(gateway.expected_host_profile_path),
                    "session_id": 3,
                    "user_sid": SID,
                },
            },
        )

    monkeypatch.setattr(gateway_module, "read_frame", read)

    with pytest.raises(PermissionError, match="hello response differs"):
        gateway.status()

    assert len(writes) == 1


def test_gateway_started_ack_binds_exact_authority_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gateway = _gateway(tmp_path)
    file_identity = gateway.expected_host_executable_file_identity
    assert file_identity is not None
    observed = PipePeerIdentity(
        process_id=700,
        session_id=3,
        user_sid=SID,
        executable_path=str(gateway.expected_host_executable),
        executable_sha256="a" * 64,
        executable_file_identity=file_identity,
    )
    writes: list[dict[str, object]] = []
    started: list[dict[str, object]] = []
    body = {
        "authority_attempt_id": "authority-attempt:test",
        "launch_id": "provider-host-launch:test",
    }

    monkeypatch.setattr(
        gateway_module,
        "write_frame",
        lambda pipe, value: writes.append(dict(value)),
    )

    def read(pipe: int) -> dict[str, object]:
        del pipe
        if len(writes) == 1:
            hello = AUTHORITY.verify(writes[0], purpose=HELLO_PURPOSE)
            return HOST.sign(
                HELLO_PURPOSE,
                {
                    "authority_nonce": hello["nonce"],
                    "host_id": "host-test",
                    "host_nonce": "host-nonce",
                    "host_process_id": 700,
                    "host_executable_file_identity": (
                        gateway_module._file_identity_record(
                            file_identity
                        )
                    ),
                    "host_executable_sha256": "a" * 64,
                    "state": "READY",
                    "user_binding": {
                        "profile_path": str(gateway.expected_host_profile_path),
                        "session_id": 3,
                        "user_sid": SID,
                    },
                },
            )
        if len(writes) == 2:
            return {
                "event": "STARTED",
                "record": HOST.sign(
                    STARTED_PURPOSE,
                    {
                        "authority_attempt_id": body["authority_attempt_id"],
                        "launch_id": body["launch_id"],
                        "observation": {"pid": 811, "suspended": True},
                    },
                ),
            }
        request = AUTHORITY.verify(writes[1], purpose=REQUEST_PURPOSE)
        return HOST.sign(
            RESPONSE_PURPOSE,
            {
                "authority_nonce": request["authority_nonce"],
                "host_nonce": "host-nonce",
                "operation": "setup",
                "request_digest": structured_digest(writes[1]),
                "result": {"status": "ok"},
            },
        )

    monkeypatch.setattr(gateway_module, "read_frame", read)
    result = gateway._rpc_bound(
        pipe=41,
        observed=observed,
        operation="setup",
        body=body,
        on_started=started.append,
    )

    ack = AUTHORITY.verify(writes[2], purpose=STARTED_ACK_PURPOSE)
    assert ack["authority_id"] == "authority-test"
    assert ack["authority_attempt_id"] == body["authority_attempt_id"]
    assert ack["launch_id"] == body["launch_id"]
    assert started == [{"pid": 811, "suspended": True}]
    assert result == {"status": "ok"}


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("missing", None),
        ("authority_id", "authority-other"),
        ("authority_attempt_id", "authority-attempt:other"),
        ("launch_id", "provider-host-launch:other"),
        ("event_digest", "b" * 64),
        ("extra", True),
    ],
)
def test_started_ack_rejects_every_identity_or_schema_mismatch(
    mutation: str, value: object
) -> None:
    ack: dict[str, object] = {
        "authority_attempt_id": "authority-attempt:test",
        "authority_id": "authority-test",
        "event_digest": "a" * 64,
        "expires_at": "2099-01-01T00:01:00+00:00",
        "issued_at": "2099-01-01T00:00:00+00:00",
        "launch_id": "provider-host-launch:test",
        "nonce": "started-ack-nonce",
        "sequence": 3,
    }
    if mutation == "missing":
        del ack["authority_id"]
    elif mutation == "extra":
        ack["unexpected"] = value
    else:
        ack[mutation] = value

    with pytest.raises(PermissionError, match="acknowledgement differs"):
        _validate_started_ack(
            ack,
            authority_attempt_id="authority-attempt:test",
            authority_id="authority-test",
            event_digest="a" * 64,
            launch_id="provider-host-launch:test",
        )


def test_started_ack_claim_is_durable_and_replay_fails_closed(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    ack = {
        "authority_attempt_id": "authority-attempt:test",
        "authority_id": "authority-test",
        "event_digest": "a" * 64,
        "expires_at": (now + timedelta(minutes=1)).isoformat(),
        "issued_at": now.isoformat(),
        "launch_id": "provider-host-launch:test",
        "nonce": "started-ack-nonce",
        "sequence": 3,
    }
    server = object.__new__(ProviderHostServer)
    server.store = ProviderHostStore(tmp_path / "host-state.db")
    server.now = lambda: now

    _validate_started_ack(
        ack,
        authority_attempt_id="authority-attempt:test",
        authority_id="authority-test",
        event_digest="a" * 64,
        launch_id="provider-host-launch:test",
    )
    server._claim_message("started-ack", ack)
    with pytest.raises(PermissionError, match="replayed|stale"):
        server._claim_message("started-ack", ack)


def test_server_signed_hello_binds_host_executable_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("C:/ProgramData/Keeper/AuthorityService/bin/runtime/python.exe")
    host_file_identity = {
        "device_id": 7,
        "file_id": 11,
        "modified_ns": 123456789,
        "schema_version": 1,
        "size": 4096,
    }
    runtime = type(
        "Runtime",
        (),
        {
            "identity": type(
                "Identity",
                (),
                {
                    "authority_id": "authority-test",
                    "host_id": "host-test",
                    "binding": type(
                        "Binding",
                        (),
                        {
                            "as_dict": lambda self: {
                                "profile_path": "C:/Users/founder",
                                "session_id": 3,
                                "user_sid": SID,
                            }
                        },
                    )(),
                },
            )(),
            "state": type("State", (), {"value": "READY"})(),
        },
    )()
    server = ProviderHostServer(
        pipe_name=r"\\.\pipe\KeeperProviderHost-authority-test",
        runtime=runtime,  # type: ignore[arg-type]
        launcher=object(),  # type: ignore[arg-type]
        setup_runner=object(),  # type: ignore[arg-type]
        authority_verifier=object(),  # type: ignore[arg-type]
        host_signer=HOST,
        store=object(),  # type: ignore[arg-type]
        authority_peer=PipePeerIdentity(
            0, 0, AUTHORITY_SID, str(path), "a" * 64, (0, 2, 4, 3)
        ),
        authority_service_sid=AUTHORITY_SERVICE_SID,
        authority_executable=path,
        authority_executable_sha256="a" * 64,
        authority_executable_file_identity=(0, 2, 4, 3),
        host_executable_attestation={
            "file_identity": host_file_identity,
            "sha256": "b" * 64,
        },
    )
    hello = {
        "authority_id": "authority-test",
        "authority_executable_file_identity": {
            "device_id": 0, "file_id": 2, "modified_ns": 3,
            "schema_version": 1, "size": 4
        },
        "authority_executable_path": str(path),
        "authority_executable_sha256": "a" * 64,
        "authority_process_id": 811,
        "expires_at": "2099-01-01T00:00:00+00:00",
        "host_id": "host-test",
        "issued_at": "2098-01-01T00:00:00+00:00",
        "nonce": "n",
        "sequence": 1,
    }
    server.authority_verifier = type(
        "Verifier", (), {"verify": lambda self, record, *, purpose: hello}
    )()
    writes: list[dict[str, object]] = []
    monkeypatch.setattr(server_module, "read_frame", lambda pipe: {"signed": "hello"})
    monkeypatch.setattr(
        server_module,
        "authenticated_named_pipe_client_identity",
        lambda *args, **kwargs: PipePeerIdentity(
            811, 0, AUTHORITY_SID, str(path), "a" * 64, (0, 2, 4, 3)
        ),
    )
    monkeypatch.setattr(
        server_module, "write_frame", lambda pipe, value: writes.append(dict(value))
    )
    monkeypatch.setattr(server, "_claim_message", lambda *args: None)

    with pytest.raises(PermissionError, match="request fields"):
        server._serve_connection(41)

    response = HOST.verify(writes[0], purpose=HELLO_PURPOSE)
    assert response["authority_nonce"] == "n"
    assert response["host_executable_sha256"] == "b" * 64
    assert response["host_executable_file_identity"] == host_file_identity


@pytest.mark.parametrize(
    "mutation", ["digest", "file-id", "size", "mtime", "binding"]
)
def test_gateway_rejects_signed_host_self_attestation_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    gateway = _gateway(tmp_path)
    writes: list[dict[str, object]] = []

    @contextmanager
    def connected(*args: object, **kwargs: object) -> Iterator[int]:
        del args, kwargs
        yield 41

    monkeypatch.setattr(gateway_module, "connected_client_pipe", connected)
    monkeypatch.setattr(
        gateway_module,
        "authenticated_named_pipe_server_binding",
        lambda pipe, *, expected: _gateway_binding(
            NamedPipeClientProcessIdentity(
                process_id=700,
                session_id=3,
                sid=expected.user_sid,
                computer_name="LOCAL",
                process_creation_time_100ns=123,
                executable_path=str(gateway.expected_host_executable),
            )
        ),
    )
    monkeypatch.setattr(
        gateway_module,
        "write_frame",
        lambda pipe, value: writes.append(dict(value)),
    )

    def read(pipe: int) -> dict[str, object]:
        del pipe
        authority_hello = AUTHORITY.verify(writes[0], purpose=HELLO_PURPOSE)
        file_identity = gateway_module._file_identity_record(
            gateway.expected_host_executable_file_identity
        )
        digest = "a" * 64
        binding = {
            "profile_path": str(gateway.expected_host_profile_path),
            "session_id": 3,
            "user_sid": SID,
        }
        if mutation == "digest":
            digest = "b" * 64
        elif mutation == "binding":
            binding["session_id"] = 4
        else:
            field = {"file-id": "file_id", "size": "size", "mtime": "modified_ns"}[
                mutation
            ]
            file_identity[field] += 1
        return HOST.sign(
            HELLO_PURPOSE,
            {
                "authority_nonce": authority_hello["nonce"],
                "host_id": "host-test",
                "host_nonce": "host-nonce",
                "host_process_id": 700,
                "host_executable_file_identity": file_identity,
                "host_executable_sha256": digest,
                "state": "READY",
                "user_binding": binding,
            },
        )

    monkeypatch.setattr(gateway_module, "read_frame", read)

    with pytest.raises(PermissionError, match="hello response|peer identity differs"):
        gateway.status()

    assert len(writes) == 1


class _Binding:
    def __init__(self, executable: Path) -> None:
        self.executable = executable
        self.calls = 0
        self.revalidations = 0

    def bind_or_revalidate_executable_identity(
        self, expected_sid: str
    ) -> NamedPipeClientProcessIdentity:
        assert expected_sid == SID
        self.calls += 1
        return NamedPipeClientProcessIdentity(
            process_id=700,
            session_id=3,
            sid=SID,
            computer_name="LOCAL",
            process_creation_time_100ns=123456789,
            executable_path=str(self.executable),
            executable_file_identity=(7, 11, 4096, 123456789),
        )

    def revalidate(self, expected_sid: str) -> NamedPipeClientProcessIdentity:
        assert expected_sid == SID
        self.revalidations += 1
        return self.bind_or_revalidate_executable_identity(expected_sid)

    def revalidate_core(
        self, expected_sid: str
    ) -> NamedPipeClientProcessIdentity:
        assert expected_sid == SID
        self.revalidations += 1
        return NamedPipeClientProcessIdentity(
            process_id=700,
            session_id=3,
            sid=SID,
            computer_name="LOCAL",
            process_creation_time_100ns=123456789,
            executable_path=str(self.executable),
        )

    revalidate_retained = revalidate_core

def test_host_peer_binding_retains_and_revalidates_exact_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "KeeperProviderHost.exe"
    executable.write_bytes(b"MZ exact host")
    binding = _Binding(executable)

    monkeypatch.setattr(
        identity_module, "_authority_service_sid", lambda: AUTHORITY_SERVICE_SID
    )
    monkeypatch.setattr(
        identity_module,
        "require_current_restricted_service_identity",
        lambda expected: expected,
    )
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: object())
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: object())
    monkeypatch.setattr(
        restricted_process_module,
        "_assert_thread_not_impersonating",
        lambda **kwargs: None,
    )

    @contextmanager
    def server_process(pipe: int, expected_sid: str) -> Iterator[_Binding]:
        assert pipe == 41
        assert expected_sid == SID
        yield binding

    monkeypatch.setattr(
        identity_module, "authenticated_named_pipe_server_process", server_process
    )
    expected = _expected_peer(executable)
    with identity_module.authenticated_named_pipe_server_binding(
        41, expected=expected
    ) as observed:
        assert observed is binding
    assert binding.calls == 0
    assert binding.revalidations == 2


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("wrong-service", "virtual-service identity differs"),
        ("changed", "changed during authenticated RPC"),
    ],
)
def test_host_peer_measurement_fails_closed_without_publishing_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message: str,
) -> None:
    executable = tmp_path / "KeeperProviderHost.exe"
    executable.write_bytes(b"MZ exact host")
    binding = _Binding(executable)
    monkeypatch.setattr(
        identity_module, "_authority_service_sid", lambda: AUTHORITY_SERVICE_SID
    )

    def require(expected: str) -> str:
        if mutation == "wrong-service":
            raise PermissionError("virtual-service identity differs")
        return expected

    monkeypatch.setattr(
        identity_module, "require_current_restricted_service_identity", require
    )
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: object())
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: object())
    monkeypatch.setattr(
        restricted_process_module,
        "_assert_thread_not_impersonating",
        lambda **kwargs: None,
    )

    @contextmanager
    def server_process(pipe: int, expected_sid: str) -> Iterator[_Binding]:
        del pipe, expected_sid
        yield binding

    monkeypatch.setattr(
        identity_module, "authenticated_named_pipe_server_process", server_process
    )
    expected = _expected_peer(executable)
    if mutation == "changed":
        original = binding.revalidate_retained

        def changed(expected_sid: str) -> NamedPipeClientProcessIdentity:
            result = original(expected_sid)
            if binding.revalidations >= 2:
                return NamedPipeClientProcessIdentity(
                    process_id=result.process_id,
                    session_id=result.session_id,
                    sid=result.sid,
                    computer_name=result.computer_name,
                    process_creation_time_100ns=(
                        result.process_creation_time_100ns + 1
                    ),
                    executable_path=result.executable_path,
                    executable_file_identity=result.executable_file_identity,
                )
            return result

        monkeypatch.setattr(binding, "revalidate_retained", changed)

    with pytest.raises(PermissionError, match=message):
        with identity_module.authenticated_named_pipe_server_binding(
            41, expected=expected
        ):
            pass

    assert binding.revalidations == (0 if mutation == "wrong-service" else 2)


class _AuthorityBinding:
    def __init__(self, executable: Path, impersonated: set[int]) -> None:
        self.executable = executable
        self.impersonated = impersonated
        self.calls = 0

    def bind_or_revalidate_signed_executable_identity(
        self,
        expected_sid: str,
        *,
        expected_path: str,
        expected_file_identity: tuple[int, int, int, int],
    ) -> NamedPipeClientProcessIdentity:
        if expected_sid != AUTHORITY_SID:
            raise PermissionError("Authority SID differs")
        assert threading.get_ident() not in self.impersonated
        if expected_path != str(self.executable):
            raise PermissionError("Authority path differs")
        if expected_file_identity != (9, 17, 8192, 987654321):
            raise PermissionError("Authority file identity differs")
        self.calls += 1
        return NamedPipeClientProcessIdentity(
            process_id=811,
            session_id=0,
            sid=AUTHORITY_SID,
            computer_name="LOCAL",
            process_creation_time_100ns=987654321,
            executable_path=str(self.executable),
            executable_file_identity=(9, 17, 8192, 987654321),
        )

    def revalidate_core(self) -> NamedPipeClientProcessIdentity:
        return self.bind_or_revalidate_signed_executable_identity(
            AUTHORITY_SID,
            expected_path=str(self.executable),
            expected_file_identity=(9, 17, 8192, 987654321),
        )


class _AuthorityAdvapi:
    def __init__(
        self,
        impersonated: set[int],
        *,
        impersonate: bool = True,
        revert: bool = True,
        revert_exception: bool = False,
    ) -> None:
        self.impersonated = impersonated
        self.impersonate_result = impersonate
        self.revert_result = revert
        self.revert_exception = revert_exception
        self.events: list[tuple[str, int]] = []

    def ImpersonateNamedPipeClient(self, pipe: object) -> bool:
        del pipe
        self.events.append(("impersonate", threading.get_ident()))
        if self.impersonate_result:
            self.impersonated.add(threading.get_ident())
        return self.impersonate_result

    def RevertToSelf(self) -> bool:
        self.events.append(("revert", threading.get_ident()))
        if self.revert_exception:
            raise OSError("synthetic reversion failure")
        if self.revert_result:
            self.impersonated.discard(threading.get_ident())
        return self.revert_result


def _expected_authority(executable: Path) -> PipePeerIdentity:
    return PipePeerIdentity(
        process_id=0,
        session_id=0,
        user_sid=AUTHORITY_SID,
        executable_path=str(executable),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        executable_file_identity=(9, 17, 8192, 987654321),
    )


def _install_authority_worker_fakes(
    monkeypatch: pytest.MonkeyPatch,
    advapi: _AuthorityAdvapi,
    impersonated: set[int],
    binding: _AuthorityBinding,
) -> None:
    monkeypatch.setattr(
        restricted_process_module, "_advapi32", lambda: advapi
    )
    monkeypatch.setattr(
        restricted_process_module, "_kernel32", lambda: object()
    )

    def assert_clean(*args: object, **kwargs: object) -> None:
        del args, kwargs
        if threading.get_ident() in impersonated:
            raise PermissionError("thread is still impersonating")

    monkeypatch.setattr(
        restricted_process_module,
        "_assert_thread_not_impersonating",
        assert_clean,
    )

    def client_token(
        pipe: int, *, expected_service_sid: str
    ) -> RestrictedServicePipeTokenIdentity:
        assert pipe == 41
        assert expected_service_sid == AUTHORITY_SERVICE_SID
        assert threading.get_ident() in impersonated
        return RestrictedServicePipeTokenIdentity(
            process_id=811,
            session_id=0,
            service_sid=AUTHORITY_SERVICE_SID,
            restricting_sids=(AUTHORITY_SERVICE_SID,),
            impersonation_level=1,
        )

    @contextmanager
    def client_process(
        pipe: int, *, token_identity: RestrictedServicePipeTokenIdentity
    ) -> Iterator[_AuthorityBinding]:
        assert pipe == 41
        assert token_identity.service_sid == AUTHORITY_SERVICE_SID
        assert threading.get_ident() not in impersonated
        yield binding

    monkeypatch.setattr(
        identity_module,
        "authenticated_named_pipe_restricted_service_token",
        client_token,
    )
    monkeypatch.setattr(
        identity_module,
        "authenticated_named_pipe_restricted_service_process",
        client_process,
    )


def test_authority_peer_measurement_uses_disposable_worker_and_reverts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "python.exe"
    executable.write_bytes(b"MZ exact Authority runtime")
    impersonated: set[int] = set()
    advapi = _AuthorityAdvapi(impersonated)
    binding = _AuthorityBinding(executable, impersonated)
    _install_authority_worker_fakes(
        monkeypatch, advapi, impersonated, binding
    )
    service_thread = threading.get_ident()

    observed = identity_module.authenticated_named_pipe_client_identity(
        41,
        expected=_expected_authority(executable),
        expected_service_sid=AUTHORITY_SERVICE_SID,
    )

    assert observed.process_id == 811
    assert observed.executable_sha256 == hashlib.sha256(
        executable.read_bytes()
    ).hexdigest()
    assert observed.executable_file_identity == (9, 17, 8192, 987654321)
    assert binding.calls == 2
    assert [event for event, _ in advapi.events] == ["impersonate", "revert"]
    assert {thread for _, thread in advapi.events} == {
        advapi.events[0][1]
    }
    assert advapi.events[0][1] != service_thread
    assert impersonated == set()


@pytest.mark.parametrize(
    ("impersonate", "revert", "message"),
    [
        (False, True, "impersonation failed"),
        (True, False, "worker identity could not be verified"),
    ],
)
def test_authority_peer_measurement_fails_closed_without_publishing_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    impersonate: bool,
    revert: bool,
    message: str,
) -> None:
    executable = tmp_path / "python.exe"
    executable.write_bytes(b"MZ exact Authority runtime")
    impersonated: set[int] = set()
    advapi = _AuthorityAdvapi(
        impersonated,
        impersonate=impersonate,
        revert=revert,
    )
    binding = _AuthorityBinding(executable, impersonated)
    _install_authority_worker_fakes(
        monkeypatch, advapi, impersonated, binding
    )

    with pytest.raises(
        (PermissionError, ProviderHostIdentityUncertain), match=message
    ):
        identity_module.authenticated_named_pipe_client_identity(
            41,
            expected=_expected_authority(executable),
            expected_service_sid=AUTHORITY_SERVICE_SID,
        )

    assert binding.calls == 0


def test_authority_peer_reversion_exception_publishes_no_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "python.exe"
    executable.write_bytes(b"MZ exact Authority runtime")
    impersonated: set[int] = set()
    advapi = _AuthorityAdvapi(impersonated, revert_exception=True)
    binding = _AuthorityBinding(executable, impersonated)
    _install_authority_worker_fakes(
        monkeypatch, advapi, impersonated, binding
    )

    with pytest.raises(
        ProviderHostIdentityUncertain,
        match="worker identity could not be verified",
    ):
        identity_module.authenticated_named_pipe_client_identity(
            41,
            expected=_expected_authority(executable),
            expected_service_sid=AUTHORITY_SERVICE_SID,
        )

    assert binding.calls == 0
    assert [event for event, _ in advapi.events] == ["impersonate", "revert"]


def test_authority_peer_timeout_publishes_no_identity_and_abandons_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "python.exe"
    executable.write_bytes(b"MZ exact Authority runtime")
    impersonated: set[int] = set()
    advapi = _AuthorityAdvapi(impersonated)
    binding = _AuthorityBinding(executable, impersonated)
    _install_authority_worker_fakes(
        monkeypatch, advapi, impersonated, binding
    )
    entered = threading.Event()
    release = threading.Event()

    def blocked_client_token(
        pipe: int, *, expected_service_sid: str
    ) -> RestrictedServicePipeTokenIdentity:
        assert pipe == 41
        assert expected_service_sid == AUTHORITY_SERVICE_SID
        assert threading.get_ident() in impersonated
        entered.set()
        release.wait(5.0)
        return RestrictedServicePipeTokenIdentity(
            process_id=811,
            session_id=0,
            service_sid=AUTHORITY_SERVICE_SID,
            restricting_sids=(AUTHORITY_SERVICE_SID,),
            impersonation_level=1,
        )

    monkeypatch.setattr(
        identity_module,
        "authenticated_named_pipe_restricted_service_token",
        blocked_client_token,
    )
    try:
        with pytest.raises(ProviderHostIdentityUncertain, match="timed out"):
            identity_module.authenticated_named_pipe_client_identity(
                41,
                expected=_expected_authority(executable),
                expected_service_sid=AUTHORITY_SERVICE_SID,
                timeout_seconds=0.01,
            )
        assert entered.is_set()
    finally:
        release.set()
    deadline = time.monotonic() + 5.0
    while impersonated and time.monotonic() < deadline:
        time.sleep(0.01)
    assert impersonated == set()


@pytest.mark.parametrize(
    "mutation",
    ["session", "sid", "path", "file-identity"],
)
def test_authority_peer_measurement_rejects_every_identity_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    executable = tmp_path / "python.exe"
    executable.write_bytes(b"MZ exact Authority runtime")
    impersonated: set[int] = set()
    advapi = _AuthorityAdvapi(impersonated)
    binding = _AuthorityBinding(executable, impersonated)
    _install_authority_worker_fakes(
        monkeypatch, advapi, impersonated, binding
    )
    expected = _expected_authority(executable)
    values = {
        "process_id": expected.process_id,
        "session_id": expected.session_id,
        "user_sid": expected.user_sid,
        "executable_path": expected.executable_path,
        "executable_sha256": expected.executable_sha256,
        "executable_file_identity": expected.executable_file_identity,
    }
    if mutation == "session":
        values["session_id"] = 2
    elif mutation == "sid":
        values["user_sid"] = "S-1-5-19"
    elif mutation == "path":
        values["executable_path"] = str(tmp_path / "other.exe")
    else:
        values["executable_file_identity"] = (9, 18, 8192, 987654321)

    with pytest.raises(PermissionError):
        identity_module.authenticated_named_pipe_client_identity(
            41,
            expected=PipePeerIdentity(**values),  # type: ignore[arg-type]
            expected_service_sid=AUTHORITY_SERVICE_SID,
        )

    assert impersonated == set()


def test_authority_peer_configuration_is_lexical_and_does_not_touch_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("C:/ProgramData/Keeper/AuthorityService/bin/runtime/python.exe")

    def forbidden(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("Host startup touched protected Authority file")

    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "stat", forbidden)

    observed = cli_module._expected_authority_peer(
        {
            "executable_file_identity": {
                "device_id": 0,
                "file_id": 2,
                "modified_ns": 3,
                "schema_version": 1,
                "size": 4,
            },
            "executable_path": str(path),
            "executable_sha256": "a" * 64,
            "session_id": 0,
            "user_sid": AUTHORITY_SID,
        }
    )

    assert observed == (path, "a" * 64, (0, 2, 4, 3))


def test_server_constructor_does_not_touch_protected_authority_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("C:/ProgramData/Keeper/AuthorityService/bin/runtime/python.exe")

    def forbidden(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("Host constructor touched protected Authority file")

    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "stat", forbidden)

    server = ProviderHostServer(
        pipe_name=r"\\.\pipe\KeeperProviderHost-authority-test",
        runtime=object(),  # type: ignore[arg-type]
        launcher=object(),  # type: ignore[arg-type]
        setup_runner=object(),  # type: ignore[arg-type]
        authority_verifier=object(),  # type: ignore[arg-type]
        host_signer=object(),  # type: ignore[arg-type]
        store=object(),  # type: ignore[arg-type]
        authority_peer=PipePeerIdentity(
            0,
            0,
            AUTHORITY_SID,
            str(path),
            "a" * 64,
            (0, 2, 4, 3),
        ),
        authority_service_sid=AUTHORITY_SERVICE_SID,
        authority_executable=path,
        authority_executable_sha256="a" * 64,
        authority_executable_file_identity=(0, 2, 4, 3),
        host_executable_attestation={"file_identity": {}, "sha256": "b" * 64},
    )
    assert server.authority_executable == path


def test_server_rejects_authority_measurement_before_effect_or_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("C:/ProgramData/Keeper/AuthorityService/bin/runtime/python.exe")
    server = ProviderHostServer(
        pipe_name=r"\\.\pipe\KeeperProviderHost-authority-test",
        runtime=object(),  # type: ignore[arg-type]
        launcher=object(),  # type: ignore[arg-type]
        setup_runner=object(),  # type: ignore[arg-type]
        authority_verifier=object(),  # type: ignore[arg-type]
        host_signer=object(),  # type: ignore[arg-type]
        store=object(),  # type: ignore[arg-type]
        authority_peer=PipePeerIdentity(
            0,
            0,
            AUTHORITY_SID,
            str(path),
            "a" * 64,
            (0, 2, 4, 3),
        ),
        authority_service_sid=AUTHORITY_SERVICE_SID,
        authority_executable=path,
        authority_executable_sha256="a" * 64,
        authority_executable_file_identity=(0, 2, 4, 3),
        host_executable_attestation={"file_identity": {}, "sha256": "b" * 64},
    )
    writes: list[object] = []
    claims: list[object] = []
    hello = {
        "authority_id": "authority-test",
        "authority_executable_file_identity": {
            "device_id": 0, "file_id": 2, "modified_ns": 3,
            "schema_version": 1, "size": 4
        },
        "authority_executable_path": str(path),
        "authority_executable_sha256": "a" * 64,
        "authority_process_id": 811,
        "expires_at": "2099-01-01T00:00:00+00:00",
        "host_id": "host-test",
        "issued_at": "2098-01-01T00:00:00+00:00",
        "nonce": "n",
        "sequence": 1,
    }
    server.authority_verifier = type(
        "Verifier",
        (),
        {"verify": lambda self, record, *, purpose: hello},
    )()
    monkeypatch.setattr(
        server_module,
        "authenticated_named_pipe_client_identity",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            PermissionError("Authority measurement denied")
        ),
    )
    monkeypatch.setattr(
        server_module, "read_frame", lambda pipe: {"signed": "hello"}
    )
    monkeypatch.setattr(
        server_module, "write_frame", lambda *args: writes.append(args)
    )
    monkeypatch.setattr(server, "_claim_message", lambda *args: claims.append(args))

    with pytest.raises(PermissionError, match="measurement denied"):
        server._serve_connection(41)

    assert claims == []
    assert writes == []


def test_server_rejects_wrong_signed_authority_process_id_before_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("C:/ProgramData/Keeper/AuthorityService/bin/runtime/python.exe")
    server = ProviderHostServer(
        pipe_name=r"\\.\pipe\KeeperProviderHost-authority-test",
        runtime=type(
            "Runtime",
            (),
            {
                "identity": type(
                    "Identity",
                    (),
                    {"authority_id": "authority-test", "host_id": "host-test"},
                )()
            },
        )(),
        launcher=object(),  # type: ignore[arg-type]
        setup_runner=object(),  # type: ignore[arg-type]
        authority_verifier=object(),  # type: ignore[arg-type]
        host_signer=object(),  # type: ignore[arg-type]
        store=object(),  # type: ignore[arg-type]
        authority_peer=PipePeerIdentity(
            0, 0, AUTHORITY_SID, str(path), "a" * 64, (0, 2, 4, 3)
        ),
        authority_service_sid=AUTHORITY_SERVICE_SID,
        authority_executable=path,
        authority_executable_sha256="a" * 64,
        authority_executable_file_identity=(0, 2, 4, 3),
        host_executable_attestation={"file_identity": {}, "sha256": "b" * 64},
    )
    hello = {
        "authority_id": "authority-test",
        "authority_executable_file_identity": {
            "device_id": 0, "file_id": 2, "modified_ns": 3,
            "schema_version": 1, "size": 4
        },
        "authority_executable_path": str(path),
        "authority_executable_sha256": "a" * 64,
        "authority_process_id": 812,
        "expires_at": "2099-01-01T00:00:00+00:00",
        "host_id": "host-test",
        "issued_at": "2098-01-01T00:00:00+00:00",
        "nonce": "n",
        "sequence": 1,
    }
    server.authority_verifier = type(
        "Verifier", (), {"verify": lambda self, record, *, purpose: hello}
    )()
    claims: list[object] = []
    writes: list[object] = []
    monkeypatch.setattr(server_module, "read_frame", lambda pipe: {"signed": "hello"})
    monkeypatch.setattr(
        server_module,
        "authenticated_named_pipe_client_identity",
        lambda *args, **kwargs: PipePeerIdentity(
            811, 0, AUTHORITY_SID, str(path), "a" * 64, (0, 2, 4, 3)
        ),
    )
    monkeypatch.setattr(server_module, "write_frame", lambda *args: writes.append(args))
    monkeypatch.setattr(server, "_claim_message", lambda *args: claims.append(args))

    with pytest.raises(PermissionError, match="hello binding is invalid"):
        server._serve_connection(41)

    assert len(claims) == 1
    assert writes == []


def test_server_identity_uncertainty_fail_stops_without_second_accept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("C:/ProgramData/Keeper/AuthorityService/bin/runtime/python.exe")
    server = ProviderHostServer(
        pipe_name=r"\\.\pipe\KeeperProviderHost-authority-test",
        runtime=object(),  # type: ignore[arg-type]
        launcher=object(),  # type: ignore[arg-type]
        setup_runner=object(),  # type: ignore[arg-type]
        authority_verifier=object(),  # type: ignore[arg-type]
        host_signer=object(),  # type: ignore[arg-type]
        store=object(),  # type: ignore[arg-type]
        authority_peer=PipePeerIdentity(
            0, 0, AUTHORITY_SID, str(path), "a" * 64, (0, 2, 4, 3)
        ),
        authority_service_sid=AUTHORITY_SERVICE_SID,
        authority_executable=path,
        authority_executable_sha256="a" * 64,
        authority_executable_file_identity=(0, 2, 4, 3),
        host_executable_attestation={"file_identity": {}, "sha256": "b" * 64},
    )
    server.runtime = type(
        "Runtime",
        (),
        {
            "identity": type(
                "Identity",
                (),
                {"binding": type("Binding", (), {"user_sid": SID})()},
            )()
        },
    )()

    @contextmanager
    def connected(*args: object, **kwargs: object) -> Iterator[int]:
        del args, kwargs
        yield 41

    class Successor:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def start(self) -> None:
            return None

    monkeypatch.setattr(server_module, "connected_server_pipe", connected)
    monkeypatch.setattr(threading, "Thread", Successor)
    monkeypatch.setattr(
        server,
        "_serve_connection",
        lambda pipe: (_ for _ in ()).throw(
            ProviderHostIdentityUncertain("synthetic uncertain identity")
        ),
    )

    with pytest.raises(ProviderHostIdentityUncertain, match="uncertain identity"):
        server._accept_once(True)

    assert server._stop.is_set()


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe identity only")
def test_real_windows_pipe_client_measurement_reverts_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Production separately requires the exact restricted virtual-service
    # TokenUser, service SID, and session zero.
    # This disposable pipe exercises the same Windows impersonation and image
    # measurement mechanics with the unelevated test process as its client.
    monkeypatch.setattr(
        identity_module,
        "_validate_expected_peer",
        lambda expected, expected_service_sid: None,
    )
    direct = identity_module.measured_process_identity(os.getpid())
    executable = Path(direct.executable_path).resolve(strict=True)
    stat = executable.stat()
    binding = current_user_binding()

    def ordinary_client_token(
        pipe: int, *, expected_service_sid: str
    ) -> RestrictedServicePipeTokenIdentity:
        assert expected_service_sid == AUTHORITY_SERVICE_SID
        return RestrictedServicePipeTokenIdentity(
            process_id=0,
            session_id=binding.session_id,
            service_sid=binding.user_sid,
            restricting_sids=(AUTHORITY_SERVICE_SID,),
            impersonation_level=1,
        )

    @contextmanager
    def ordinary_client_process(
        pipe: int, *, token_identity: RestrictedServicePipeTokenIdentity
    ) -> Iterator[NamedPipeClientProcessBinding]:
        del token_identity
        with authenticated_named_pipe_client_process(
            pipe, binding.user_sid
        ) as process_binding:
            yield process_binding

    monkeypatch.setattr(
        identity_module,
        "authenticated_named_pipe_restricted_service_token",
        ordinary_client_token,
    )
    monkeypatch.setattr(
        identity_module,
        "authenticated_named_pipe_restricted_service_process",
        ordinary_client_process,
    )
    expected = PipePeerIdentity(
        process_id=0,
        session_id=binding.session_id,
        user_sid=binding.user_sid,
        executable_path=str(executable),
        executable_sha256=direct.executable_sha256,
        executable_file_identity=(
            int(stat.st_dev),
            int(stat.st_ino),
            int(stat.st_size),
            int(stat.st_mtime_ns),
        ),
    )
    pipe_name = rf"\\.\pipe\KeeperProviderHost-peer-{uuid.uuid4().hex}"
    outcome: list[PipePeerIdentity | BaseException] = []
    measured = threading.Event()

    def server() -> None:
        try:
            with connected_server_pipe(
                pipe_name,
                user_sid=binding.user_sid,
                authority_service_sid=AUTHORITY_SERVICE_SID,
                first_instance=True,
            ) as pipe:
                assert read_frame(pipe) == {"probe": "authority"}
                outcome.append(
                    identity_module.authenticated_named_pipe_client_identity(
                        pipe,
                        expected=expected,
                        expected_service_sid=AUTHORITY_SERVICE_SID,
                    )
                )
                measured.set()
        except BaseException as error:
            outcome.append(error)
            measured.set()

    worker = threading.Thread(target=server, daemon=True)
    worker.start()
    connected = False
    for _ in range(50):
        try:
            with connected_client_pipe(pipe_name, timeout_seconds=1.0) as pipe:
                write_frame(pipe, {"probe": "authority"})
                assert measured.wait(10.0)
            connected = True
            break
        except OSError as error:
            if (getattr(error, "winerror", None) or error.errno) not in {2, 231}:
                raise
            time.sleep(0.02)
    worker.join(10.0)

    assert connected
    assert not worker.is_alive()
    assert len(outcome) == 1
    if isinstance(outcome[0], BaseException):
        raise outcome[0]
    assert outcome[0].process_id == os.getpid()
    assert outcome[0].executable_path == str(executable)
    assert outcome[0].executable_sha256 == expected.executable_sha256


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe identity only")
def test_real_windows_separate_process_pipe_client_measurement_reverts_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the production peer-measurement shape across process boundaries."""
    import subprocess

    monkeypatch.setattr(
        identity_module,
        "_validate_expected_peer",
        lambda expected, expected_service_sid: None,
    )
    executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve(
        strict=True
    )
    stat = executable.stat()
    binding = current_user_binding()

    def ordinary_client_token(
        pipe: int, *, expected_service_sid: str
    ) -> RestrictedServicePipeTokenIdentity:
        assert expected_service_sid == AUTHORITY_SERVICE_SID
        return RestrictedServicePipeTokenIdentity(
            process_id=0,
            session_id=binding.session_id,
            service_sid=binding.user_sid,
            restricting_sids=(AUTHORITY_SERVICE_SID,),
            impersonation_level=1,
        )

    @contextmanager
    def ordinary_client_process(
        pipe: int, *, token_identity: RestrictedServicePipeTokenIdentity
    ) -> Iterator[NamedPipeClientProcessBinding]:
        del token_identity
        with authenticated_named_pipe_client_process(
            pipe, binding.user_sid
        ) as process_binding:
            yield process_binding

    monkeypatch.setattr(
        identity_module,
        "authenticated_named_pipe_restricted_service_token",
        ordinary_client_token,
    )
    monkeypatch.setattr(
        identity_module,
        "authenticated_named_pipe_restricted_service_process",
        ordinary_client_process,
    )
    expected = PipePeerIdentity(
        process_id=0,
        session_id=binding.session_id,
        user_sid=binding.user_sid,
        executable_path=str(executable),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        executable_file_identity=(
            int(stat.st_dev),
            int(stat.st_ino),
            int(stat.st_size),
            int(stat.st_mtime_ns),
        ),
    )
    pipe_name = rf"\\.\pipe\KeeperProviderHost-peer-process-{uuid.uuid4().hex}"
    outcome: list[PipePeerIdentity | BaseException] = []
    measured = threading.Event()

    def server() -> None:
        try:
            with connected_server_pipe(
                pipe_name,
                user_sid=binding.user_sid,
                authority_service_sid=AUTHORITY_SERVICE_SID,
                first_instance=True,
            ) as pipe:
                assert read_frame(pipe) == {"probe": "authority"}
                outcome.append(
                    identity_module.authenticated_named_pipe_client_identity(
                        pipe,
                        expected=expected,
                        expected_service_sid=AUTHORITY_SERVICE_SID,
                    )
                )
                write_frame(pipe, {"measured": True})
                measured.set()
        except BaseException as error:
            outcome.append(error)
            measured.set()

    worker = threading.Thread(target=server, daemon=True)
    worker.start()
    child_code = (
        "import sys; "
        "from keeper.provider_host.pipe import connected_client_pipe,read_frame,write_frame; "
        "p=sys.argv[1]; "
        "c=connected_client_pipe(p,timeout_seconds=10.0); "
        "h=c.__enter__(); "
        "write_frame(h,{'probe':'authority'}); "
        "assert read_frame(h)=={'measured':True}; "
        "c.__exit__(None,None,None)"
    )
    child = subprocess.Popen(
        [str(executable), "-c", child_code, pipe_name],
        cwd=Path.cwd(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert measured.wait(20.0)
        stdout, stderr = child.communicate(timeout=20.0)
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=10.0)
    worker.join(10.0)

    assert stdout == ""
    assert stderr == ""
    assert child.returncode == 0
    assert not worker.is_alive()
    assert len(outcome) == 1
    if isinstance(outcome[0], BaseException):
        raise outcome[0]
    assert outcome[0].process_id == child.pid
    assert outcome[0].executable_path == str(executable)
    assert outcome[0].executable_sha256 == expected.executable_sha256


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe identity only")
def test_real_windows_separate_process_pipe_server_binding_retains_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Measure a disposable Host process before sending its first protocol frame."""
    import subprocess

    executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve(
        strict=True
    )
    binding = current_user_binding()
    monkeypatch.setattr(
        identity_module, "_authority_service_sid", lambda: AUTHORITY_SERVICE_SID
    )
    monkeypatch.setattr(
        identity_module,
        "require_current_restricted_service_identity",
        lambda expected: expected,
    )
    pipe_name = rf"\\.\pipe\KeeperProviderHost-server-process-{uuid.uuid4().hex}"
    child_code = (
        "import sys; "
        "from keeper.provider_host.pipe import connected_server_pipe,read_frame,write_frame; "
        "p=sys.argv[1];sid=sys.argv[2];service_sid=sys.argv[3]; "
        "c=connected_server_pipe(p,user_sid=sid,authority_service_sid=service_sid,first_instance=True); "
        "h=c.__enter__(); "
        "assert read_frame(h)=={'measured':True}; "
        "write_frame(h,{'server':'ready'}); "
        "c.__exit__(None,None,None)"
    )
    child = subprocess.Popen(
        [
            str(executable),
            "-c",
            child_code,
            pipe_name,
            binding.user_sid,
            AUTHORITY_SERVICE_SID,
        ],
        cwd=Path.cwd(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    connected = False
    stat = executable.stat()
    expected = PipePeerIdentity(
        process_id=0,
        session_id=binding.session_id,
        user_sid=binding.user_sid,
        executable_path=str(executable),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        executable_file_identity=(
            int(stat.st_dev),
            int(stat.st_ino),
            int(stat.st_size),
            int(stat.st_mtime_ns),
        ),
    )
    try:
        for _ in range(100):
            try:
                with connected_client_pipe(pipe_name, timeout_seconds=1.0) as pipe:
                    with identity_module.authenticated_named_pipe_server_binding(
                        pipe, expected=expected
                    ) as retained:
                        core = retained.revalidate_core(binding.user_sid)
                        observed = PipePeerIdentity(
                            core.process_id,
                            core.session_id,
                            core.sid,
                            core.executable_path,
                            expected.executable_sha256,
                            expected.executable_file_identity,
                        )
                        write_frame(pipe, {"measured": True})
                        assert read_frame(pipe) == {"server": "ready"}
                connected = True
                break
            except OSError as error:
                if (getattr(error, "winerror", None) or error.errno) not in {2, 231}:
                    raise
                time.sleep(0.02)
        stdout, stderr = child.communicate(timeout=20.0)
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=10.0)

    assert connected
    assert stdout == ""
    assert stderr == ""
    assert child.returncode == 0
    assert observed.process_id == child.pid
    assert observed.session_id == binding.session_id
    assert observed.user_sid.casefold() == binding.user_sid.casefold()
    assert observed.executable_path == str(executable)
    assert observed.executable_sha256 == hashlib.sha256(
        executable.read_bytes()
    ).hexdigest()
