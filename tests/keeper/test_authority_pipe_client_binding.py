from __future__ import annotations

import ctypes
import inspect
from ctypes import wintypes
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import keeper.authority_service.windows_identity as identity_module
from keeper.authority_service.codex_registration import register_and_qualify_once
from keeper.authority_service.windows_identity import (
    PROCESS_DUP_HANDLE,
    ERROR_ACCESS_DENIED,
    NamedPipeClientProcessBinding,
    NamedPipeClientProcessIdentity,
    PROCESS_QUERY_LIMITED_INFORMATION,
    TOKEN_DUPLICATE,
    TOKEN_QUERY,
    authenticated_named_pipe_client_process,
    authenticated_named_pipe_server_process,
)


SID = "S-1-5-21-1000"
LOCAL = "KEEPER-CLIENT"
CLIENT_EXECUTABLE = r"C:\Program Files\Keeper\client.exe"
CLIENT_FILE_IDENTITY = (7, 11, 4096, 123456789)
CLIENT_CREATION_TIME = 987654321


def _identity(
    *, process_id: int = 700, session_id: int = 3, sid: str = SID
) -> NamedPipeClientProcessIdentity:
    return NamedPipeClientProcessIdentity(
        process_id=process_id,
        session_id=session_id,
        sid=sid,
        computer_name=LOCAL,
        process_creation_time_100ns=CLIENT_CREATION_TIME,
        executable_path=CLIENT_EXECUTABLE,
        executable_file_identity=CLIENT_FILE_IDENTITY,
    )


def _provisional_identity(
    *, process_id: int = 700, session_id: int = 3, sid: str = SID
) -> NamedPipeClientProcessIdentity:
    return replace(
        _identity(process_id=process_id, session_id=session_id, sid=sid),
        executable_file_identity=(0, 0, 0, 0),
    )


def _inspection_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity_module, "_local_computer_name", lambda: LOCAL)
    monkeypatch.setattr(
        identity_module, "_named_pipe_client_process_id", lambda pipe: 700
    )
    monkeypatch.setattr(
        identity_module, "_named_pipe_client_session_id", lambda pipe: 3
    )
    monkeypatch.setattr(
        identity_module, "_process_handle_id", lambda process: 700
    )
    monkeypatch.setattr(
        identity_module, "_process_id_session", lambda process_id: 3
    )
    monkeypatch.setattr(
        identity_module,
        "_process_token_sid_and_session",
        lambda process: (SID, 3),
    )
    monkeypatch.setattr(identity_module, "_process_is_active", lambda process: True)
    monkeypatch.setattr(
        identity_module,
        "_process_creation_time",
        lambda process: CLIENT_CREATION_TIME,
    )
    monkeypatch.setattr(
        identity_module,
        "_process_executable_path",
        lambda process: CLIENT_EXECUTABLE,
    )
    monkeypatch.setattr(
        identity_module,
        "_named_pipe_client_computer_name",
        lambda pipe: LOCAL,
    )


def test_pipe_client_inspection_cross_checks_pid_session_sid_and_locality(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inspection_defaults(monkeypatch)

    assert identity_module._inspect_named_pipe_client(41, 99) == _provisional_identity()


def test_pipe_server_inspection_uses_server_pid_and_session_apis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity_module, "_local_computer_name", lambda: LOCAL)
    monkeypatch.setattr(
        identity_module, "_named_pipe_server_process_id", lambda pipe: 700
    )
    monkeypatch.setattr(
        identity_module, "_named_pipe_server_session_id", lambda pipe: 3
    )
    monkeypatch.setattr(identity_module, "_process_handle_id", lambda process: 700)
    monkeypatch.setattr(identity_module, "_process_id_session", lambda process_id: 3)
    monkeypatch.setattr(
        identity_module, "_token_sid_and_session", lambda token: (SID, 3)
    )
    monkeypatch.setattr(identity_module, "_process_is_active", lambda process: True)
    monkeypatch.setattr(
        identity_module,
        "_process_creation_time",
        lambda process: CLIENT_CREATION_TIME,
    )
    monkeypatch.setattr(
        identity_module,
        "_process_executable_path",
        lambda process: CLIENT_EXECUTABLE,
    )

    assert identity_module._inspect_bound_named_pipe_server(
        41, 99, 88
    ) == _provisional_identity()


def test_pid_session_access_denial_is_optional_but_pipe_and_token_must_agree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inspection_defaults(monkeypatch)
    monkeypatch.setattr(
        identity_module, "_process_id_session", lambda process_id: None
    )

    assert identity_module._inspect_named_pipe_client(41, 99) == _provisional_identity()

    monkeypatch.setattr(
        identity_module,
        "_process_token_sid_and_session",
        lambda process: (SID, 4),
    )
    with pytest.raises(PermissionError, match="session is mismatched"):
        identity_module._inspect_named_pipe_client(41, 99)


class _PidSessionKernel:
    def __init__(self, *, succeeds: bool, session_id: int = 3) -> None:
        self.succeeds = succeeds
        self.session_id = session_id

    def ProcessIdToSessionId(self, process_id: int, value: object) -> bool:
        assert process_id == 700
        if self.succeeds:
            getattr(value, "_obj").value = self.session_id
        return self.succeeds


def test_process_id_session_treats_only_access_denied_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _PidSessionKernel(succeeds=False)
    monkeypatch.setattr(identity_module, "_kernel32", lambda: kernel)
    monkeypatch.setattr(
        ctypes, "get_last_error", lambda: ERROR_ACCESS_DENIED,
    )

    assert identity_module._process_id_session(700) is None

    monkeypatch.setattr(ctypes, "get_last_error", lambda: 87)
    with pytest.raises(PermissionError, match="unavailable: 87"):
        identity_module._process_id_session(700)


def test_process_id_session_success_remains_diagnostic_corroboration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _PidSessionKernel(succeeds=True, session_id=3)
    monkeypatch.setattr(identity_module, "_kernel32", lambda: kernel)

    assert identity_module._process_id_session(700) == 3


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ("handle-pid", "process handle is mismatched"),
        ("direct-session", "session is mismatched"),
        ("pid-session", "session is mismatched"),
        ("token-session", "session is mismatched"),
        ("inactive", "process is not active"),
        ("remote", "remote authority clients"),
    ],
)
def test_pipe_client_inspection_fails_closed_on_identity_disagreement(
    monkeypatch: pytest.MonkeyPatch, replacement: str, message: str
) -> None:
    _inspection_defaults(monkeypatch)
    if replacement == "handle-pid":
        monkeypatch.setattr(
            identity_module, "_process_handle_id", lambda process: 701
        )
    elif replacement == "direct-session":
        monkeypatch.setattr(
            identity_module, "_named_pipe_client_session_id", lambda pipe: 4
        )
    elif replacement == "pid-session":
        monkeypatch.setattr(
            identity_module, "_process_id_session", lambda process_id: 4
        )
    elif replacement == "token-session":
        monkeypatch.setattr(
            identity_module,
            "_process_token_sid_and_session",
            lambda process: (SID, 4),
        )
    elif replacement == "inactive":
        monkeypatch.setattr(
            identity_module, "_process_is_active", lambda process: False
        )
    else:
        monkeypatch.setattr(
            identity_module,
            "_named_pipe_client_computer_name",
            lambda pipe: "REMOTE-HOST",
        )

    with pytest.raises(PermissionError, match=message):
        identity_module._inspect_named_pipe_client(41, 99)


class _Kernel:
    def __init__(self, *, close_ok: bool = True) -> None:
        self.open_calls: list[tuple[int, bool, int]] = []
        self.close_calls: list[int] = []
        self.close_ok = close_ok

    def OpenProcess(self, access: int, inherit: bool, process_id: int) -> int:
        self.open_calls.append((access, inherit, process_id))
        return 99

    def CloseHandle(self, handle: object) -> bool:
        value = getattr(handle, "value", handle)
        assert isinstance(value, int)
        self.close_calls.append(int(value))
        return self.close_ok


class _TransferKernel(_Kernel):
    def __init__(self, *, close_ok: bool = True) -> None:
        super().__init__(close_ok=close_ok)
        self.duplicate_calls: list[tuple[int, int, int, int, bool, int]] = []

    def GetCurrentProcess(self) -> int:
        return 1

    def DuplicateHandle(
        self,
        source_process: object,
        source_handle: object,
        target_process: object,
        target_handle: object,
        access: int,
        inherit: bool,
        options: int,
    ) -> bool:
        def value(item: object) -> int:
            raw = getattr(item, "value", item)
            assert isinstance(raw, int)
            return raw

        source_process_value = value(source_process)
        source_handle_value = value(source_handle)
        target_process_value = value(target_process)
        self.duplicate_calls.append(
            (
                source_process_value,
                source_handle_value,
                target_process_value,
                access,
                inherit,
                options,
            )
        )
        target_address = getattr(target_handle, "_obj", None)
        assert isinstance(target_address, wintypes.HANDLE)
        target_address.value = 222
        return True


def test_binding_uses_minimum_process_rights_retains_handle_and_revalidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _Kernel()
    token_open_calls: list[tuple[int, int]] = []
    observations: list[NamedPipeClientProcessIdentity] = [_identity()] * 3
    monkeypatch.setattr(identity_module, "_kernel32", lambda: kernel)
    monkeypatch.setattr(
        identity_module, "_named_pipe_client_process_id", lambda pipe: 700
    )
    monkeypatch.setattr(
        identity_module,
        "_inspect_bound_named_pipe_client",
        lambda pipe, process, process_token: observations.pop(0),
    )
    def open_process_token(process: int, access: int) -> int:
        token_open_calls.append((process, access))
        return 88

    monkeypatch.setattr(identity_module, "_open_process_token", open_process_token)

    with authenticated_named_pipe_client_process(41, SID) as binding:
        assert binding.process == 99
        assert binding.profile_token == 88
        assert binding.revalidate(SID) == _identity()
        assert kernel.close_calls == []

    assert kernel.open_calls == [
        (PROCESS_QUERY_LIMITED_INFORMATION, False, 700)
    ]
    assert token_open_calls == [(99, TOKEN_QUERY | TOKEN_DUPLICATE)]
    assert kernel.close_calls == [88, 99]


def test_handle_transfer_opens_narrow_process_only_for_transfer_and_closes_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _TransferKernel()
    validated: list[int] = []
    monkeypatch.setattr(identity_module, "_kernel32", lambda: kernel)
    monkeypatch.setattr(
        identity_module,
        "_inspect_bound_named_pipe_client",
        lambda pipe, process, token: _identity(),
    )
    monkeypatch.setattr(
        identity_module,
        "_require_read_only_disk_handle",
        lambda handle: validated.append(handle),
    )
    binding = NamedPipeClientProcessBinding(
        41, 77, 88, _identity(), server=False
    )

    with binding.duplicate_client_handle(
        123, SID, transfer_process=99
    ) as duplicated:
        assert duplicated == 222

    assert kernel.duplicate_calls == [(99, 123, 1, 0, False, 2)]
    assert validated == [222]
    assert kernel.close_calls == [222]
    assert binding.process == 77


def test_handle_transfer_rejects_identity_change_before_duplication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _TransferKernel()
    observations = [_identity(), _identity(process_id=701)]
    monkeypatch.setattr(identity_module, "_kernel32", lambda: kernel)
    monkeypatch.setattr(
        identity_module,
        "_inspect_bound_named_pipe_client",
        lambda pipe, process, token: observations.pop(0),
    )
    binding = NamedPipeClientProcessBinding(
        41, 77, 88, _identity(), server=False
    )

    with pytest.raises(PermissionError, match="transfer process identity changed"):
        with binding.duplicate_client_handle(
            123, SID, transfer_process=99
        ):
            raise AssertionError("unreachable")

    assert kernel.duplicate_calls == []
    assert kernel.close_calls == []


def test_server_binding_uses_exact_server_pid_and_retains_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _Kernel()
    token_open_calls: list[tuple[int, int]] = []
    observations: list[NamedPipeClientProcessIdentity] = [_identity()] * 3
    monkeypatch.setattr(identity_module, "_kernel32", lambda: kernel)
    monkeypatch.setattr(
        identity_module, "_named_pipe_server_process_id", lambda pipe: 700
    )
    monkeypatch.setattr(
        identity_module,
        "_inspect_bound_named_pipe_server",
        lambda pipe, process, process_token: observations.pop(0),
    )

    def open_process_token(process: int, access: int) -> int:
        token_open_calls.append((process, access))
        return 88

    monkeypatch.setattr(identity_module, "_open_process_token", open_process_token)

    with authenticated_named_pipe_server_process(41, SID) as binding:
        assert binding.server is True
        assert binding.process == 99
        assert binding.profile_token == 88
        assert binding.revalidate(SID) == _identity()
        assert kernel.close_calls == []

    assert kernel.open_calls == [
        (PROCESS_QUERY_LIMITED_INFORMATION, False, 700)
    ]
    assert token_open_calls == [(99, TOKEN_QUERY)]
    assert kernel.close_calls == [88, 99]


@pytest.mark.parametrize("change", ["pid", "session", "sid", "lifetime"])
def test_server_binding_rejects_peer_rebinding_and_closes_handles(
    monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    kernel = _Kernel()
    changed = _identity()
    if change == "pid":
        changed = _identity(process_id=701)
    elif change == "session":
        changed = _identity(session_id=4)
    elif change == "sid":
        changed = _identity(sid="S-1-5-21-9999")
    else:
        changed = replace(
            changed,
            process_creation_time_100ns=CLIENT_CREATION_TIME + 1,
        )
    observations = [_identity(), _identity(), changed]
    monkeypatch.setattr(identity_module, "_kernel32", lambda: kernel)
    monkeypatch.setattr(
        identity_module, "_named_pipe_server_process_id", lambda pipe: 700
    )
    monkeypatch.setattr(
        identity_module,
        "_inspect_bound_named_pipe_server",
        lambda pipe, process, process_token: observations.pop(0),
    )
    monkeypatch.setattr(identity_module, "_open_process_token", lambda *args: 88)

    with pytest.raises(PermissionError, match="identity changed|SID is mismatched"):
        with authenticated_named_pipe_server_process(41, SID) as binding:
            binding.revalidate(SID)

    assert kernel.close_calls == [88, 99]


def test_binding_rejects_missing_process_lifetime_or_executable_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for identity in (
        replace(_identity(), process_creation_time_100ns=0),
        replace(_identity(), executable_path="client.exe"),
        replace(_identity(), executable_file_identity=(7, 0, 4096, 123456789)),
    ):
        with pytest.raises(PermissionError, match="lifetime or executable"):
            NamedPipeClientProcessBinding(41, 99, 88, identity)

    provisional = NamedPipeClientProcessBinding(
        41, 99, 88, _provisional_identity()
    )
    monkeypatch.setattr(
        identity_module,
        "_inspect_bound_named_pipe_client",
        lambda pipe, process, token: _provisional_identity(),
    )
    with pytest.raises(PermissionError, match="not finalized"):
        provisional.revalidate(SID)


def test_pid_reuse_or_pipe_rebinding_rejects_and_closes_retained_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _Kernel()
    observations = [_identity(), _identity(), _identity(process_id=701)]
    monkeypatch.setattr(identity_module, "_kernel32", lambda: kernel)
    monkeypatch.setattr(
        identity_module, "_named_pipe_client_process_id", lambda pipe: 700
    )
    monkeypatch.setattr(
        identity_module,
        "_inspect_bound_named_pipe_client",
        lambda pipe, process, process_token: observations.pop(0),
    )
    monkeypatch.setattr(identity_module, "_open_process_token", lambda *args: 88)

    with pytest.raises(PermissionError, match="identity changed"):
        with authenticated_named_pipe_client_process(41, SID) as binding:
            binding.revalidate(SID)

    assert kernel.close_calls == [88, 99]


@pytest.mark.parametrize("change", ["creation", "executable"])
def test_retained_process_creation_and_executable_identity_changes_reject(
    monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    kernel = _Kernel()
    changed = _identity()
    if change == "creation":
        changed = replace(
            changed, process_creation_time_100ns=CLIENT_CREATION_TIME + 1
        )
    elif change == "executable":
        changed = replace(changed, executable_path=r"C:\Other\client.exe")
    observations = [_identity(), _identity(), changed]
    monkeypatch.setattr(identity_module, "_kernel32", lambda: kernel)
    monkeypatch.setattr(
        identity_module, "_named_pipe_client_process_id", lambda pipe: 700
    )
    monkeypatch.setattr(
        identity_module,
        "_inspect_bound_named_pipe_client",
        lambda pipe, process, process_token: observations.pop(0),
    )
    monkeypatch.setattr(identity_module, "_open_process_token", lambda *args: 88)

    with pytest.raises(PermissionError, match="identity changed"):
        with authenticated_named_pipe_client_process(41, SID) as binding:
            binding.revalidate(SID)

    assert kernel.close_calls == [88, 99]


def test_executable_file_identity_is_revalidated_only_by_bounded_path_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = NamedPipeClientProcessBinding(41, 99, 88, _identity())
    monkeypatch.setattr(
        identity_module,
        "_inspect_bound_named_pipe_client",
        lambda pipe, process, token: _provisional_identity(),
    )
    monkeypatch.setattr(
        identity_module,
        "_process_executable_file_identity",
        lambda path: (path, (7, 12, 4096, 123456789)),
    )

    # Core revalidation intentionally performs no protected filesystem read.
    assert binding.revalidate(SID) == _identity()
    with pytest.raises(PermissionError, match="identity changed"):
        binding.bind_or_revalidate_executable_identity(SID)


@pytest.mark.parametrize("stage", ["open", "token", "initial", "revalidate"])
def test_process_exit_or_pipe_disconnect_fails_closed_and_cleans_handle(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    kernel = _Kernel()
    if stage == "open":
        kernel.OpenProcess = lambda access, inherit, process_id: 0  # type: ignore[method-assign]
    monkeypatch.setattr(identity_module, "_kernel32", lambda: kernel)
    monkeypatch.setattr(
        identity_module, "_named_pipe_client_process_id", lambda pipe: 700
    )
    if stage == "token":
        def fail_open_token(*args: object) -> int:
            del args
            raise PermissionError("authority client process token cannot be opened")

        monkeypatch.setattr(identity_module, "_open_process_token", fail_open_token)
    else:
        monkeypatch.setattr(identity_module, "_open_process_token", lambda *args: 88)
    calls = 0

    def inspect_client(
        pipe: int, process: int, process_token: int
    ) -> NamedPipeClientProcessIdentity:
        nonlocal calls
        del pipe, process, process_token
        calls += 1
        if stage == "initial" and calls == 1:
            raise PermissionError("authority client process is not active")
        if stage == "revalidate" and calls == 3:
            raise PermissionError("authority named-pipe client session is unavailable")
        return _identity()

    monkeypatch.setattr(
        identity_module, "_inspect_bound_named_pipe_client", inspect_client
    )

    with pytest.raises(PermissionError):
        with authenticated_named_pipe_client_process(41, SID) as binding:
            if stage == "revalidate":
                binding.revalidate(SID)

    expected_closes = {
        "open": [],
        "token": [99],
        "initial": [88, 99],
        "revalidate": [88, 99],
    }
    assert kernel.close_calls == expected_closes[stage]


def test_process_sid_mismatch_and_cleanup_uncertainty_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _Kernel(close_ok=False)
    monkeypatch.setattr(identity_module, "_kernel32", lambda: kernel)
    monkeypatch.setattr(
        identity_module, "_named_pipe_client_process_id", lambda pipe: 700
    )
    monkeypatch.setattr(
        identity_module,
        "_inspect_bound_named_pipe_client",
        lambda pipe, process, process_token: _identity(sid="S-1-5-21-9999"),
    )
    monkeypatch.setattr(identity_module, "_open_process_token", lambda *args: 88)

    with pytest.raises(PermissionError, match="binding cleanup failed"):
        with authenticated_named_pipe_client_process(41, SID):
            pass

    assert kernel.close_calls == [88, 99]


def test_binding_contract_accepts_no_caller_supplied_pid_or_session() -> None:
    parameters = set(
        inspect.signature(authenticated_named_pipe_client_process).parameters
    )
    assert parameters == {"pipe", "expected_sid"}


class _RejectingRegistrationClient:
    def __init__(self) -> None:
        self.register_calls = 0
        self.qualify_calls = 0

    def register_provider(self, *args: object, **kwargs: object) -> dict[str, Any]:
        del args, kwargs
        self.register_calls += 1
        raise PermissionError("authority authenticated client process is unavailable")

    def qualify_provider(
        self, registration_id: str, executable: Path | None = None
    ) -> dict[str, Any]:
        del registration_id, executable
        self.qualify_calls += 1
        raise AssertionError("qualification must not run")

    def reconcile_provider_qualification(
        self, registration_id: str
    ) -> dict[str, Any]:
        del registration_id
        raise AssertionError("reconciliation must not run")


def test_binding_failure_persists_no_response_and_invokes_no_qualification(
    tmp_path: Path,
) -> None:
    client = _RejectingRegistrationClient()

    with pytest.raises(PermissionError, match="client process"):
        register_and_qualify_once(
            client,
            tmp_path / "codex.exe",
            tmp_path / "public",
            {},
        )

    assert client.register_calls == 1
    assert client.qualify_calls == 0
    assert not (tmp_path / "public" / "registration-response.json").exists()
    assert not (tmp_path / "public" / "qualification-response.json").exists()
