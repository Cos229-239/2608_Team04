from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
from typing import Any

import pytest

from keeper.authority_service import windows_identity
from keeper.authority_service.windows_identity import (
    NamedPipeClientProcessIdentity,
    PROCESS_QUERY_LIMITED_INFORMATION,
    RESTRICTED_CODE_SID,
    authenticated_named_pipe_restricted_service_process,
    authenticated_named_pipe_restricted_service_token,
)


SERVICE_SID = "S-1-5-80-1-2-3-4-5"


class _Advapi:
    def __init__(self, *, restricted: bool = True) -> None:
        self.restricted = restricted
        self.open_thread_calls: list[int] = []

    def OpenThreadToken(
        self,
        thread: object,
        access: int,
        open_as_self: bool,
        output: Any,
    ) -> bool:
        del thread, open_as_self
        self.open_thread_calls.append(access)
        ctypes.cast(output, ctypes.POINTER(wintypes.HANDLE)).contents.value = 101
        return True

    def IsTokenRestricted(self, token: object) -> bool:
        del token
        return self.restricted


class _Kernel:
    def __init__(self, *, process: int = 202) -> None:
        self.process = process
        self.open_calls: list[tuple[int, bool, int]] = []
        self.closed: list[int] = []

    def GetCurrentThread(self) -> int:
        return 77

    def OpenProcess(self, access: int, inherit: bool, process_id: int) -> int:
        self.open_calls.append((access, inherit, process_id))
        return self.process

    def CloseHandle(self, handle: object) -> bool:
        value = getattr(handle, "value", handle)
        if not isinstance(value, int):
            raise AssertionError("synthetic handle is invalid")
        self.closed.append(value)
        return True


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch,
    executable: Path,
    *,
    user_sid: str = SERVICE_SID,
    token_session: int = 0,
    restricting_sids: tuple[str, ...] = (SERVICE_SID,),
    restricted: bool = True,
    token_type: int = 2,
    impersonation_level: int = windows_identity.SECURITY_IMPERSONATION,
    pipe_process_id: int = 811,
    observed_process_id: int = 811,
    pipe_session: int = 0,
    process_handle: int = 202,
) -> tuple[_Advapi, _Kernel]:
    advapi = _Advapi(restricted=restricted)
    kernel = _Kernel(process=process_handle)
    monkeypatch.setattr(windows_identity, "_advapi32", lambda: advapi)
    monkeypatch.setattr(windows_identity, "_kernel32", lambda: kernel)
    monkeypatch.setattr(windows_identity, "_token_sid", lambda token: user_sid)
    monkeypatch.setattr(
        windows_identity, "_token_session_id", lambda token: token_session
    )
    monkeypatch.setattr(
        windows_identity,
        "_token_restricting_sids",
        lambda token: restricting_sids,
    )
    monkeypatch.setattr(
        windows_identity,
        "_token_dword",
        lambda token, kind: (
            impersonation_level
            if kind == windows_identity.TOKEN_IMPERSONATION_LEVEL
            else token_type
        ),
    )
    monkeypatch.setattr(
        windows_identity,
        "_named_pipe_client_process_id",
        lambda pipe: pipe_process_id,
    )
    monkeypatch.setattr(
        windows_identity,
        "_named_pipe_client_session_id",
        lambda pipe: pipe_session,
    )
    monkeypatch.setattr(
        windows_identity,
        "_inspect_named_pipe_client_identity",
        lambda pipe, process, sid, session: NamedPipeClientProcessIdentity(
            process_id=observed_process_id,
            session_id=session,
            sid=sid,
            computer_name="LOCAL",
            process_creation_time_100ns=123456789,
            executable_path=str(executable),
        ),
    )
    monkeypatch.setattr(
        windows_identity,
        "_open_process_token",
        lambda *args: (_ for _ in ()).throw(
            AssertionError("Authority process token must never be opened")
        ),
    )
    monkeypatch.setattr(
        windows_identity, "_require_thread_not_impersonating", lambda: None
    )
    return advapi, kernel


def test_exact_restricted_service_peer_uses_query_only_and_no_process_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "keeper-authority.exe"
    executable.write_bytes(b"exact disposable Authority image")
    advapi, kernel = _install_fakes(monkeypatch, executable)

    token_identity = authenticated_named_pipe_restricted_service_token(
        41, expected_service_sid=SERVICE_SID
    )
    with authenticated_named_pipe_restricted_service_process(
        41, token_identity=token_identity
    ) as binding:
        identity = binding.bind_or_revalidate_signed_executable_identity(
            SERVICE_SID,
            expected_path=str(executable),
            expected_file_identity=(1, 2, 3, 4),
        )
        assert identity.process_id == 811
        assert identity.session_id == 0
        assert identity.sid == SERVICE_SID
        assert identity.executable_file_identity != (0, 0, 0, 0)

    assert advapi.open_thread_calls == [windows_identity.TOKEN_QUERY]
    assert kernel.open_calls == [
        (PROCESS_QUERY_LIMITED_INFORMATION, False, 811)
    ]
    assert kernel.closed == [101, 202]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"user_sid": "S-1-5-18"}, "restricted-token identity differs"),
        (
            {"user_sid": "S-1-5-80-9-8-7-6-5"},
            "restricted-token identity differs",
        ),
        ({"user_sid": "S-1-5-19"}, "restricted-token identity differs"),
        ({"token_session": 1}, "restricted-token identity differs"),
        ({"restricting_sids": ()}, "restricted-token identity differs"),
        (
            {"restricting_sids": (SERVICE_SID, RESTRICTED_CODE_SID)},
            "restricted-token identity differs",
        ),
        ({"restricted": False}, "restricted-token identity differs"),
        ({"token_type": 1}, "restricted-token identity differs"),
        ({"impersonation_level": 0}, "restricted-token identity differs"),
        ({"impersonation_level": 3}, "restricted-token identity differs"),
        ({"pipe_session": 1}, "pipe session differs"),
        ({"observed_process_id": 812}, "process ID changed"),
        ({"process_handle": 0}, "process cannot be inspected"),
    ],
)
def test_restricted_service_peer_identity_mismatches_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, object],
    message: str,
) -> None:
    executable = tmp_path / "keeper-authority.exe"
    executable.write_bytes(b"exact disposable Authority image")
    _, kernel = _install_fakes(
        monkeypatch, executable, **changes  # type: ignore[arg-type]
    )

    with pytest.raises(PermissionError, match=message):
        token_identity = authenticated_named_pipe_restricted_service_token(
            41, expected_service_sid=SERVICE_SID
        )
        with authenticated_named_pipe_restricted_service_process(
            41, token_identity=token_identity
        ):
            raise AssertionError("mismatched peer must not be yielded")

    assert 101 in kernel.closed


def test_invalid_service_sid_rejects_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "keeper-authority.exe"
    executable.write_bytes(b"exact disposable Authority image")
    advapi, kernel = _install_fakes(monkeypatch, executable)

    with pytest.raises(PermissionError, match="service SID is invalid"):
        authenticated_named_pipe_restricted_service_token(
            41, expected_service_sid="S-1-5-18"
        )

    assert advapi.open_thread_calls == []
    assert kernel.open_calls == []


def test_process_replacement_during_measurement_rejects_and_closes_handles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "keeper-authority.exe"
    executable.write_bytes(b"exact disposable Authority image")
    advapi, kernel = _install_fakes(monkeypatch, executable)
    calls = 0

    def inspect(
        pipe: int, process: int, sid: str, session: int
    ) -> NamedPipeClientProcessIdentity:
        nonlocal calls
        del pipe, process
        calls += 1
        return NamedPipeClientProcessIdentity(
            process_id=811,
            session_id=session,
            sid=sid,
            computer_name="LOCAL",
            process_creation_time_100ns=123456789 + calls,
            executable_path=str(executable),
        )

    monkeypatch.setattr(
        windows_identity, "_inspect_named_pipe_client_identity", inspect
    )

    token_identity = authenticated_named_pipe_restricted_service_token(
        41, expected_service_sid=SERVICE_SID
    )
    with pytest.raises(PermissionError, match="identity changed"):
        with authenticated_named_pipe_restricted_service_process(
            41, token_identity=token_identity
        ):
            raise AssertionError("replaced peer must not be yielded")

    assert calls == 2
    assert advapi.open_thread_calls == [windows_identity.TOKEN_QUERY]
    assert kernel.closed == [101, 202]
