from __future__ import annotations

import os
from typing import Any

import pytest

from keeper.authority_service import windows_identity


SERVICE_SID = "S-1-5-80-1-2-3-4-5"
LOGON_SID = "S-1-5-5-0-12345"
ACTUAL_RESTRICTING_SIDS = (
    SERVICE_SID,
    windows_identity.WORLD_SID,
    LOGON_SID,
    windows_identity.WRITE_RESTRICTED_CODE_SID,
)


class _Kernel:
    def __init__(self, *, close: bool = True) -> None:
        self.close = close
        self.closed: list[int] = []

    def GetCurrentProcess(self) -> int:
        return -1

    def CloseHandle(self, handle: object) -> bool:
        value = getattr(handle, "value", handle)
        if not isinstance(value, int):
            raise AssertionError("test handle is invalid")
        self.closed.append(value)
        return self.close


class _Advapi:
    def __init__(self, *, restricted: bool = True) -> None:
        self.restricted = restricted

    def IsTokenRestricted(self, token: object) -> bool:
        del token
        return self.restricted


def _install(
    monkeypatch: pytest.MonkeyPatch,
    *,
    user_sid: str = SERVICE_SID,
    session: int = 0,
    restricting_sids: tuple[str, ...] = ACTUAL_RESTRICTING_SIDS,
    restricted: bool = True,
    token_type: int = windows_identity.TOKEN_PRIMARY,
    close: bool = True,
) -> _Kernel:
    kernel = _Kernel(close=close)
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(windows_identity, "_kernel32", lambda: kernel)
    monkeypatch.setattr(
        windows_identity, "_advapi32", lambda: _Advapi(restricted=restricted)
    )
    monkeypatch.setattr(
        windows_identity, "_open_process_token", lambda process, access: 101
    )
    monkeypatch.setattr(windows_identity, "_token_sid", lambda token: user_sid)
    monkeypatch.setattr(
        windows_identity, "_token_session_id", lambda token: session
    )
    monkeypatch.setattr(
        windows_identity,
        "_token_restricting_sids",
        lambda token: restricting_sids,
    )
    monkeypatch.setattr(
        windows_identity, "_token_dword", lambda token, kind: token_type
    )
    return kernel


def test_exact_restricted_virtual_service_process_identity_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _install(monkeypatch)

    assert (
        windows_identity.require_current_restricted_service_identity(SERVICE_SID)
        == SERVICE_SID
    )
    assert kernel.closed == [101]


@pytest.mark.parametrize(
    "changes",
    [
        {"user_sid": "S-1-5-18"},
        {"user_sid": "S-1-5-80-9-8-7-6-5"},
        {"user_sid": "S-1-5-21-1000"},
        {"session": 1},
        {"restricting_sids": ()},
        {"restricting_sids": (SERVICE_SID,)},
        {
            "restricting_sids": ACTUAL_RESTRICTING_SIDS
            + ("S-1-5-21-1-2-3-9999",)
        },
        {
            "restricting_sids": tuple(
                sid
                for sid in ACTUAL_RESTRICTING_SIDS
                if sid != windows_identity.WRITE_RESTRICTED_CODE_SID
            )
        },
        {
            "restricting_sids": (
                *ACTUAL_RESTRICTING_SIDS,
                windows_identity.RESTRICTED_CODE_SID,
            )
        },
        {"restricted": False},
        {"token_type": windows_identity.TOKEN_IMPERSONATION},
    ],
)
def test_virtual_service_process_identity_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch, changes: dict[str, Any]
) -> None:
    kernel = _install(monkeypatch, **changes)

    with pytest.raises(PermissionError, match="identity differs"):
        windows_identity.require_current_restricted_service_identity(SERVICE_SID)

    assert kernel.closed == [101]


def test_invalid_service_sid_rejects_before_token_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(
        windows_identity,
        "_open_process_token",
        lambda *arguments: (_ for _ in ()).throw(
            AssertionError("invalid SID must reject before token open")
        ),
    )

    with pytest.raises(PermissionError, match="service SID is invalid"):
        windows_identity.require_current_restricted_service_identity("S-1-5-18")


def test_virtual_service_process_token_cleanup_failure_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, close=False)

    with pytest.raises(PermissionError, match="handle cleanup failed"):
        windows_identity.require_current_restricted_service_identity(SERVICE_SID)
