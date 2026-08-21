from __future__ import annotations

import ctypes
import os
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator

import pytest

import keeper.provider_host.pipe as pipe_module
import keeper.provider_host.server as server_module
import keeper.provider_host.cli as cli_module
from keeper.authority_service import restricted_process
from keeper.provider_host.identity import current_user_binding
from keeper.provider_host.server import ProviderHostServer


SID = "S-1-5-21-1000"
SERVICE_SID = "S-1-5-80-1-2-3-4-5"


class _Runtime:
    def __init__(self) -> None:
        self.identity = SimpleNamespace(binding=SimpleNamespace(user_sid=SID))
        self.drain_count = 0

    def drain(self) -> None:
        self.drain_count += 1


def _server(tmp_path: Path) -> tuple[ProviderHostServer, _Runtime]:
    runtime = _Runtime()
    authority = (tmp_path / "keeper-authority.pyz").resolve()
    result = ProviderHostServer(
        pipe_name=r"\\.\pipe\KeeperProviderHost-startup-test",
        runtime=runtime,  # type: ignore[arg-type]
        launcher=object(),  # type: ignore[arg-type]
        setup_runner=object(),  # type: ignore[arg-type]
        authority_verifier=object(),  # type: ignore[arg-type]
        host_signer=object(),  # type: ignore[arg-type]
        store=object(),  # type: ignore[arg-type]
        authority_peer=object(),  # type: ignore[arg-type]
        authority_service_sid=SERVICE_SID,
        authority_executable=authority,
        authority_executable_sha256="a" * 64,
        authority_executable_file_identity=(0, 1, 1, 1),
        host_executable_attestation={
            "file_identity": {
                "device_id": 0,
                "file_id": 1,
                "modified_ns": 1,
                "schema_version": 1,
                "size": 1,
            },
            "sha256": "b" * 64,
        },
    )
    return result, runtime


def test_listener_creation_failure_reaches_main_host_loop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server, _ = _server(tmp_path)
    listener_calls = 0
    connection_calls = 0

    @contextmanager
    def failed_listener(*args: object, **kwargs: object) -> Iterator[int]:
        nonlocal listener_calls
        del args, kwargs
        listener_calls += 1
        raise OSError(5, "synthetic listener creation failure")
        yield 1

    def serve_connection(pipe: int) -> None:
        nonlocal connection_calls
        del pipe
        connection_calls += 1

    monkeypatch.setattr(server_module, "connected_server_pipe", failed_listener)
    monkeypatch.setattr(server, "_serve_connection", serve_connection)

    with pytest.raises(OSError, match="synthetic listener creation failure"):
        server.serve_forever()

    assert server._stop.is_set()
    assert not server._listener_ready.is_set()
    assert isinstance(server._fatal_error, OSError)
    assert listener_calls == 1
    assert connection_calls == 0
    for worker in server._workers:
        worker.join(2.0)
    assert all(not worker.is_alive() for worker in server._workers)


def test_first_listener_readiness_precedes_main_wait_loop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server, runtime = _server(tmp_path)
    permit_connection = threading.Event()
    server_errors: list[BaseException] = []

    @contextmanager
    def listener(
        *args: object,
        created_observer: object = None,
        **kwargs: object,
    ) -> Iterator[int]:
        del args, kwargs
        assert callable(created_observer)
        created_observer()
        assert permit_connection.wait(5.0)
        yield 41

    @contextmanager
    def client(*args: object, **kwargs: object) -> Iterator[int]:
        del args, kwargs
        permit_connection.set()
        yield 42

    monkeypatch.setattr(server_module, "connected_server_pipe", listener)
    monkeypatch.setattr(server_module, "connected_client_pipe", client)

    def run() -> None:
        try:
            server.serve_forever()
        except BaseException as error:
            server_errors.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert server._listener_ready.wait(2.0)
    assert thread.is_alive()

    server.stop()
    thread.join(5.0)

    assert not thread.is_alive()
    assert server_errors == []
    assert runtime.drain_count == 1
    assert server._fatal_error is None


def test_successor_listener_failure_fail_stops_host(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server, _ = _server(tmp_path)
    calls = 0
    lock = threading.Lock()
    successor_failed = threading.Event()

    @contextmanager
    def listener(
        *args: object,
        created_observer: object = None,
        **kwargs: object,
    ) -> Iterator[int]:
        nonlocal calls
        del args, kwargs
        with lock:
            calls += 1
            current = calls
        if current == 1:
            assert callable(created_observer)
            created_observer()
            yield 41
            return
        successor_failed.set()
        raise OSError(5, "synthetic successor listener failure")
        yield 42

    monkeypatch.setattr(server_module, "connected_server_pipe", listener)
    monkeypatch.setattr(
        server,
        "_serve_connection",
        lambda pipe: successor_failed.wait(2.0),
    )

    with pytest.raises(OSError, match="synthetic successor listener failure"):
        server.serve_forever()

    assert successor_failed.is_set()
    assert server._stop.is_set()
    assert isinstance(server._fatal_error, OSError)


def test_listener_startup_timeout_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server, _ = _server(tmp_path)
    release = threading.Event()

    @contextmanager
    def stalled_listener(
        *args: object,
        created_observer: object = None,
        **kwargs: object,
    ) -> Iterator[int]:
        del args, kwargs
        assert release.wait(5.0)
        assert callable(created_observer)
        created_observer()
        yield 41

    monkeypatch.setattr(server_module, "connected_server_pipe", stalled_listener)
    monkeypatch.setattr(server_module, "_LISTENER_STARTUP_TIMEOUT_SECONDS", 0.05)

    try:
        with pytest.raises(TimeoutError, match="listener startup timed out"):
            server.serve_forever()
    finally:
        release.set()
        for worker in server._workers:
            worker.join(2.0)

    assert server._stop.is_set()
    assert isinstance(server._fatal_error, TimeoutError)


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe API only")
def test_pipe_created_observer_runs_after_handle_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Kernel:
        def CreateNamedPipeW(self, *args: object) -> int:
            del args
            calls.append("create")
            return 41

        def ConnectNamedPipe(self, *args: object) -> bool:
            del args
            calls.append("connect")
            return True

        def FlushFileBuffers(self, *args: object) -> bool:
            del args
            calls.append("flush")
            return True

        def DisconnectNamedPipe(self, *args: object) -> bool:
            del args
            calls.append("disconnect")
            return True

        def CloseHandle(self, *args: object) -> bool:
            del args
            calls.append("close")
            return True

    @contextmanager
    def security(user_sid: str, authority_service_sid: str) -> Iterator[object]:
        assert user_sid == SID
        assert authority_service_sid == SERVICE_SID
        yield pipe_module._SecurityAttributes()

    monkeypatch.setattr(pipe_module, "_kernel32", lambda: Kernel())
    monkeypatch.setattr(pipe_module, "_security_attributes", security)

    with pipe_module.connected_server_pipe(
        r"\\.\pipe\KeeperProviderHost-created-test",
        user_sid=SID,
        authority_service_sid=SERVICE_SID,
        first_instance=True,
        created_observer=lambda: calls.append("ready"),
    ) as handle:
        assert handle == 41
        calls.append("yield")

    assert calls == [
        "create",
        "ready",
        "connect",
        "yield",
        "flush",
        "disconnect",
        "close",
    ]


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe API only")
def test_pipe_callback_failure_closes_only_created_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Kernel:
        def CreateNamedPipeW(self, *args: object) -> int:
            del args
            calls.append("create")
            return 41

        def ConnectNamedPipe(self, *args: object) -> bool:
            del args
            calls.append("connect")
            return True

        def FlushFileBuffers(self, *args: object) -> bool:
            del args
            calls.append("flush")
            return True

        def DisconnectNamedPipe(self, *args: object) -> bool:
            del args
            calls.append("disconnect")
            return True

        def CloseHandle(self, *args: object) -> bool:
            del args
            calls.append("close")
            return True

    @contextmanager
    def security(user_sid: str, authority_service_sid: str) -> Iterator[object]:
        assert user_sid == SID
        assert authority_service_sid == SERVICE_SID
        yield pipe_module._SecurityAttributes()

    monkeypatch.setattr(pipe_module, "_kernel32", lambda: Kernel())
    monkeypatch.setattr(pipe_module, "_security_attributes", security)

    with pytest.raises(RuntimeError, match="observer failed"):
        with pipe_module.connected_server_pipe(
            r"\\.\pipe\KeeperProviderHost-callback-test",
            user_sid=SID,
            authority_service_sid=SERVICE_SID,
            first_instance=True,
            created_observer=lambda: (_ for _ in ()).throw(
                RuntimeError("observer failed")
            ),
        ):
            raise AssertionError("pipe must not be yielded")

    assert calls == ["create", "close"]


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe API only")
def test_pipe_security_policy_still_denies_restricted_code() -> None:
    assert pipe_module._pipe_security_sddl(SID, SERVICE_SID) == (
        f"D:P(D;;GA;;;{pipe_module._RESTRICTED_CODE_SID})"
        f"(A;;GA;;;SY)(A;;GA;;;{SERVICE_SID})(A;;GA;;;{SID})"
    )


def test_pipe_security_policy_rejects_non_service_sid() -> None:
    with pytest.raises(ValueError, match="service SID"):
        pipe_module._pipe_security_sddl(SID, "S-1-5-18")


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe API only")
def test_client_pipe_requests_exact_local_impersonation_qos(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[object, ...]] = []

    class Kernel:
        def CreateFileW(self, *args: object) -> int:
            observed.append(args)
            return 41

        def CloseHandle(self, handle: int) -> bool:
            assert handle == 41
            return True

    monkeypatch.setattr(pipe_module, "_kernel32", lambda: Kernel())

    with pipe_module.connected_client_pipe(
        r"\\.\pipe\KeeperProviderHost-qos-test", timeout_seconds=1.0
    ) as handle:
        assert handle == 41

    assert len(observed) == 1
    assert observed[0][5] == 0x00120000
    assert observed[0][5] == (
        pipe_module._SECURITY_SQOS_PRESENT | pipe_module._SECURITY_IMPERSONATION
    )
    assert observed[0][5] != 0
    assert observed[0][5] != 0x00130000


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe API only")
def test_real_windows_client_qos_allows_local_impersonation_and_clean_revert() -> None:
    binding = current_user_binding()
    pipe_name = rf"\\.\pipe\KeeperProviderHost-qos-{uuid.uuid4().hex}"
    ready = threading.Event()
    completed = threading.Event()
    outcome: list[int | BaseException] = []

    def serve() -> None:
        try:
            with pipe_module.connected_server_pipe(
                pipe_name,
                user_sid=binding.user_sid,
                authority_service_sid=SERVICE_SID,
                first_instance=True,
                created_observer=ready.set,
            ) as handle:
                assert pipe_module.read_frame(handle) == {"probe": "qos"}
                with restricted_process.authenticated_named_pipe_client_token(
                    handle
                ) as token:
                    outcome.append(
                        restricted_process.token_impersonation_level(token)
                    )
                restricted_process._assert_thread_not_impersonating(
                    advapi32=restricted_process._advapi32(),
                    kernel32=restricted_process._kernel32(),
                )
        except BaseException as error:
            outcome.append(error)
        finally:
            completed.set()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    assert ready.wait(5.0)
    with pipe_module.connected_client_pipe(
        pipe_name, timeout_seconds=5.0
    ) as handle:
        pipe_module.write_frame(handle, {"probe": "qos"})
        assert completed.wait(10.0)
    worker.join(10.0)

    assert not worker.is_alive()
    assert outcome == [restricted_process._SECURITY_IMPERSONATION]


def test_authority_service_sid_uses_exact_service_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    def resolve(account: str) -> str:
        observed.append(account)
        return SERVICE_SID

    monkeypatch.setattr(cli_module, "account_sid", resolve)
    assert cli_module._authority_service_sid() == SERVICE_SID
    assert observed == [r"NT SERVICE\KeeperAuthority"]


def test_authority_service_sid_resolution_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_module, "account_sid", lambda account: "S-1-5-18")
    with pytest.raises(PermissionError, match="service SID"):
        cli_module._authority_service_sid()


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe API only")
def test_windows_pipe_api_bindings_are_explicit() -> None:
    kernel32 = pipe_module._kernel32()
    assert len(kernel32.CreateNamedPipeW.argtypes) == 8
    assert len(kernel32.CreateFileW.argtypes) == 7
    assert len(kernel32.ConnectNamedPipe.argtypes) == 2
    assert len(kernel32.ReadFile.argtypes) == 5
    assert len(kernel32.WriteFile.argtypes) == 5
    assert len(kernel32.WaitNamedPipeW.argtypes) == 2
    assert kernel32.CreateNamedPipeW.restype is ctypes.wintypes.HANDLE
    assert kernel32.CreateFileW.restype is ctypes.wintypes.HANDLE
