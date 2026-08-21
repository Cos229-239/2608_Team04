from __future__ import annotations

import ctypes
import sqlite3
import sys
from ctypes import wintypes
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from keeper.executive import founder_auth
from keeper.executive.service import KeeperExecutive


class _FakeFunction:
    def __init__(self, callback: Any) -> None:
        self.callback = callback
        self.argtypes: object = None
        self.restype: object = None

    def __call__(self, *args: Any) -> Any:
        return self.callback(*args)


def _fake_native_api(
    *,
    prompt_result: int = 0,
    output_size: int = 48,
    return_null_output: bool = False,
    unpack_result: bool = True,
    unpack_exception: BaseException | None = None,
    logon_result: bool = True,
) -> tuple[SimpleNamespace, dict[str, Any]]:
    events: dict[str, Any] = {
        "calls": [],
        "freed": [],
        "ui": [],
        "initial": [],
    }
    packed = ctypes.create_string_buffer(b"x" * max(output_size, 1))

    def prompt(*args: Any) -> int:
        events["calls"].append("prompt")
        info = ctypes.cast(
            args[0], ctypes.POINTER(founder_auth._CREDUI_INFOW)
        ).contents
        events["ui"].append(
            (
                info.cbSize,
                info.hwndParent,
                info.pszMessageText,
                info.pszCaptionText,
                info.hbmBanner,
            )
        )
        events["initial"].append(
            (
                ctypes.cast(args[2], ctypes.POINTER(wintypes.ULONG))[0],
                args[3],
                args[4],
                ctypes.cast(args[5], ctypes.POINTER(ctypes.c_void_p))[0],
                ctypes.cast(args[6], ctypes.POINTER(wintypes.ULONG))[0],
                ctypes.cast(args[7], ctypes.POINTER(wintypes.BOOL))[0],
                args[8],
            )
        )
        if prompt_result == 0:
            address = 0 if return_null_output else ctypes.addressof(packed)
            ctypes.cast(args[5], ctypes.POINTER(ctypes.c_void_p))[0] = (
                ctypes.c_void_p(address)
            )
            ctypes.cast(args[6], ctypes.POINTER(wintypes.ULONG))[0] = (
                wintypes.ULONG(output_size)
            )
        return prompt_result

    def unpack(*args: Any) -> bool:
        events["calls"].append("unpack")
        if unpack_exception is not None:
            raise unpack_exception
        if unpack_result:
            args[3].value = "founder"
            args[5].value = "DARKSAGE"
            args[7].value = "not-a-real-password"
        return unpack_result

    def logon(*args: Any) -> bool:
        events["calls"].append("logon")
        if logon_result:
            ctypes.cast(args[5], ctypes.POINTER(wintypes.HANDLE))[0] = (
                wintypes.HANDLE(0x777)
            )
        return logon_result

    def close(*_args: Any) -> bool:
        events["calls"].append("close")
        return True

    def free(buffer: ctypes.c_void_p) -> None:
        events["calls"].append("free")
        events["freed"].append(int(buffer.value or 0))

    api = SimpleNamespace(
        credui=SimpleNamespace(
            CredUIPromptForWindowsCredentialsW=_FakeFunction(prompt),
            CredUnPackAuthenticationBufferW=_FakeFunction(unpack),
        ),
        advapi32=SimpleNamespace(LogonUserW=_FakeFunction(logon)),
        kernel32=SimpleNamespace(CloseHandle=_FakeFunction(close)),
        ole32=SimpleNamespace(CoTaskMemFree=_FakeFunction(free)),
        packed=packed,
    )
    return api, events


def _run(
    monkeypatch: pytest.MonkeyPatch, api: SimpleNamespace
) -> tuple[str, str, str]:
    monkeypatch.setattr(ctypes, "windll", api)
    monkeypatch.setattr(
        founder_auth,
        "_token_identity",
        lambda _token: ("S-1-5-21-1000", "0x123"),
    )
    return founder_auth._credential_ui_logon()


def test_credui_info_has_exact_native_layout() -> None:
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    pointer_alignment = ctypes.alignment(ctypes.c_void_p)
    first_pointer = (
        ctypes.sizeof(wintypes.DWORD) + pointer_alignment - 1
    ) // pointer_alignment * pointer_alignment
    assert founder_auth._CREDUI_INFOW._fields_ == [
        ("cbSize", wintypes.DWORD),
        ("hwndParent", wintypes.HWND),
        ("pszMessageText", wintypes.LPCWSTR),
        ("pszCaptionText", wintypes.LPCWSTR),
        ("hbmBanner", wintypes.HBITMAP),
    ]
    assert founder_auth._CREDUI_INFOW.cbSize.offset == 0
    assert founder_auth._CREDUI_INFOW.hwndParent.offset == first_pointer
    assert (
        founder_auth._CREDUI_INFOW.pszMessageText.offset
        == first_pointer + pointer_size
    )
    assert (
        founder_auth._CREDUI_INFOW.pszCaptionText.offset
        == first_pointer + 2 * pointer_size
    )
    assert founder_auth._CREDUI_INFOW.hbmBanner.offset == (
        first_pointer + 3 * pointer_size
    )
    assert ctypes.sizeof(founder_auth._CREDUI_INFOW) == first_pointer + 4 * pointer_size


def test_success_uses_typed_ui_info_exact_signatures_and_single_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, events = _fake_native_api()
    assert _run(monkeypatch, api) == (
        "S-1-5-21-1000",
        "DARKSAGE\\founder",
        "0x123",
    )

    prompt = api.credui.CredUIPromptForWindowsCredentialsW
    assert prompt.argtypes == [
        ctypes.POINTER(founder_auth._CREDUI_INFOW),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.ULONG),
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
        ctypes.POINTER(wintypes.BOOL),
        wintypes.DWORD,
    ]
    assert prompt.restype is wintypes.DWORD
    assert api.credui.CredUnPackAuthenticationBufferW.restype is wintypes.BOOL
    assert api.advapi32.LogonUserW.restype is wintypes.BOOL
    assert api.kernel32.CloseHandle.restype is wintypes.BOOL
    assert api.ole32.CoTaskMemFree.argtypes == [ctypes.c_void_p]
    assert api.ole32.CoTaskMemFree.restype is None

    assert events["ui"] == [
        (
            ctypes.sizeof(founder_auth._CREDUI_INFOW),
            None,
            "Confirm the Windows identity authorized to approve this Keeper action.",
            "Keeper Founder Authentication",
            None,
        )
    ]
    assert events["initial"] == [
        (0, None, 0, None, 0, 0, founder_auth.CREDUIWIN_GENERIC)
    ]
    assert events["freed"] == [ctypes.addressof(api.packed)]
    assert events["calls"] == ["prompt", "unpack", "logon", "close", "free"]
    assert bytes(api.packed) == b"\x00" * ctypes.sizeof(api.packed)


@pytest.mark.parametrize("result", [5, 87])
def test_native_prompt_error_is_distinct_and_does_not_cleanup_null_output(
    monkeypatch: pytest.MonkeyPatch, result: int
) -> None:
    api, events = _fake_native_api(prompt_result=result)
    with pytest.raises(OSError, match="credential prompt") as raised:
        _run(monkeypatch, api)
    assert raised.value.errno == result
    assert events["calls"] == ["prompt"]
    assert events["freed"] == []


def test_user_cancellation_is_clean_and_distinct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, events = _fake_native_api(prompt_result=founder_auth.ERROR_CANCELLED)
    with pytest.raises(PermissionError, match="canceled"):
        _run(monkeypatch, api)
    assert events["calls"] == ["prompt"]
    assert events["freed"] == []


@pytest.mark.parametrize(
    ("return_null_output", "output_size", "message", "free_count"),
    [
        (True, 48, "no credential buffer", 0),
        (False, 0, "empty credential buffer", 1),
    ],
)
def test_reported_success_requires_nonempty_native_output(
    monkeypatch: pytest.MonkeyPatch,
    return_null_output: bool,
    output_size: int,
    message: str,
    free_count: int,
) -> None:
    api, events = _fake_native_api(
        return_null_output=return_null_output, output_size=output_size
    )
    with pytest.raises(OSError, match=message):
        _run(monkeypatch, api)
    assert "unpack" not in events["calls"]
    assert len(events["freed"]) == free_count


def test_unpack_exception_frees_exactly_once_without_secret_output(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    api, events = _fake_native_api(
        unpack_exception=RuntimeError("safe validation failure")
    )
    with pytest.raises(RuntimeError, match="safe validation failure") as raised:
        _run(monkeypatch, api)
    captured = capsys.readouterr()
    combined = f"{raised.value} {captured.out} {captured.err} {caplog.text}"
    assert "not-a-real-password" not in combined
    assert events["calls"] == ["prompt", "unpack", "free"]
    assert len(events["freed"]) == 1


def test_repeated_calls_remain_stable_and_cleanup_each_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, events = _fake_native_api()
    for _ in range(2):
        assert _run(monkeypatch, api)[0] == "S-1-5-21-1000"
    assert events["calls"].count("prompt") == 2
    assert events["calls"].count("free") == 2
    assert len(events["freed"]) == 2


def test_null_authentication_buffer_requires_no_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, events = _fake_native_api()
    monkeypatch.setattr(ctypes, "windll", api)
    founder_auth._zero_and_free_authentication_buffer(ctypes.c_void_p(None), 99)
    assert events["calls"] == []
    assert events["freed"] == []


def test_non_windows_wrapper_fails_before_loading_native_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delattr(ctypes, "windll", raising=False)
    with pytest.raises(RuntimeError, match="requires local Windows APIs"):
        founder_auth._credential_ui_logon()


def test_failed_production_authentication_creates_no_downstream_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    database = tmp_path / "production.db"
    executive = KeeperExecutive(database)
    project, intake = executive.begin(
        f"I want a small application called Pocket List in {tmp_path}. "
        "Use full delegation, no spending, and do not push."
    )
    draft = executive.draft(
        project.project_id,
        intake,
        founder_revisions={
            "success_criteria": ("users can add and complete items",),
            "target_audience": "personal users",
            "approved_providers": ("codex", "reviewer-provider"),
            "approved_tools": ("filesystem",),
        },
    )
    challenge = executive.request_charter_approval(
        executive.propose_charter(draft)
    )

    def durable_counts() -> dict[str, int]:
        with sqlite3.connect(database) as connection:
            tables = tuple(
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' ORDER BY name"
                )
            )
            return {
                table: int(
                    connection.execute(
                        f'SELECT COUNT(*) FROM "{table}"'
                    ).fetchone()[0]
                )
                for table in tables
            }

    before = durable_counts()

    def cancel() -> tuple[str, str, str]:
        raise PermissionError("Windows Founder authentication was canceled")

    monkeypatch.setattr(founder_auth, "_credential_ui_logon", cancel)
    with pytest.raises(PermissionError, match="canceled"):
        executive.authenticate_founder(challenge)

    assert durable_counts() == before
