from __future__ import annotations

import ctypes
import json
import os
import queue
import sys
import threading
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path
from typing import Any

import pytest

from keeper.authority_service.restricted_process import (
    ProviderLaunchIdentityUncertain,
    ProviderServiceIdentityUncertain,
    WindowsSessionQueryResult,
    WindowsSessionQueryStatus,
    _create_process_with_bounded_restricted_impersonation,
    authenticated_client_process_impersonation_token,
    authenticated_client_transfer_process,
    authenticated_client_environment,
    authenticated_client_profile_path,
    authenticated_client_windows_session_state,
    authenticated_named_pipe_client,
    authenticated_named_pipe_client_token,
    authenticated_profile_primary_token,
    current_process_token,
    impersonate_token,
    profile_restricted_primary_token,
    restricted_current_process_token,
    run_restricted_process,
    token_environment,
    token_session_id,
    token_user_sid_string,
    windows_session_is_active,
)
import keeper.authority_service.restricted_process as restricted_process_module
from keeper.authority_service.windows_identity import (
    NamedPipeClientProcessIdentity,
)


SID = "S-1-5-21-1000"


def _synthetic_jsonl_exchange() -> tuple[tuple[str, int | None], ...]:
    return (
        (json.dumps({"method": "initialize", "id": 1, "params": {}}), 1),
        (json.dumps({"method": "initialized", "params": {}}), None),
        (json.dumps({"method": "account/read", "id": 2, "params": {}}), 2),
    )


class _FakeWtsApi:
    def __init__(
        self,
        *,
        state: int = 0,
        succeeds: bool = True,
        error: int = 5,
        size: int | None = None,
        null_buffer: bool = False,
        cleanup_fails: bool = False,
        events: list[str] | None = None,
    ) -> None:
        self.state = wintypes.DWORD(state)
        self.succeeds = succeeds
        self.error = error
        self.size = ctypes.sizeof(wintypes.DWORD) if size is None else size
        self.null_buffer = null_buffer
        self.cleanup_fails = cleanup_fails
        self.freed = 0
        self.events = events

    def WTSQuerySessionInformationW(
        self,
        server: object,
        session_id: int,
        information_class: int,
        output: Any,
        size: Any,
    ) -> bool:
        assert getattr(server, "value", server) in {None, 0}
        assert session_id == 1
        assert information_class == 8
        if self.events is not None:
            self.events.append("query")
        if not self.succeeds:
            ctypes.set_last_error(self.error)
            return False
        ctypes.cast(size, ctypes.POINTER(wintypes.DWORD)).contents.value = self.size
        if not self.null_buffer:
            ctypes.cast(output, ctypes.POINTER(wintypes.LPVOID)).contents.value = (
                ctypes.addressof(self.state)
            )
        return True

    def WTSFreeMemory(self, buffer: Any) -> None:
        assert ctypes.cast(buffer, wintypes.LPVOID).value == ctypes.addressof(
            self.state
        )
        self.freed += 1
        if self.events is not None:
            self.events.append("free")
        if self.cleanup_fails:
            raise OSError("synthetic WTS cleanup failure")


class _FakeWtsImpersonationAdvapi:
    def __init__(
        self,
        *,
        impersonate_result: bool = True,
        revert_result: bool = True,
        events: list[str] | None = None,
    ) -> None:
        self.impersonate_result = impersonate_result
        self.revert_result = revert_result
        self.events = events if events is not None else []
        self.local = threading.local()

    def OpenThreadToken(
        self,
        thread: int,
        access: int,
        open_as_self: bool,
        output: Any,
    ) -> bool:
        del thread
        assert access == 0x0008
        assert open_as_self is True
        self.events.append("verify")
        if getattr(self.local, "impersonating", False):
            ctypes.cast(output, ctypes.POINTER(wintypes.HANDLE)).contents.value = 97
            return True
        ctypes.set_last_error(1008)
        return False

    def ImpersonateNamedPipeClient(self, pipe: int) -> bool:
        assert pipe == 11
        self.events.append("impersonate")
        if not self.impersonate_result:
            ctypes.set_last_error(5)
            return False
        self.local.impersonating = True
        return True

    def RevertToSelf(self) -> bool:
        self.events.append("revert")
        if not self.revert_result:
            ctypes.set_last_error(5)
            return False
        self.local.impersonating = False
        return True


def test_windows_session_query_distinguishes_active_and_api_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_api = _FakeWtsApi(state=0)
    monkeypatch.setattr(restricted_process_module, "_wtsapi32", lambda: active_api)
    active = windows_session_is_active(1)
    assert active == WindowsSessionQueryResult(
        WindowsSessionQueryStatus.ACTIVE, state=0
    )
    assert active_api.freed == 1

    failed_api = _FakeWtsApi(succeeds=False, error=5)
    monkeypatch.setattr(restricted_process_module, "_wtsapi32", lambda: failed_api)
    failed = windows_session_is_active(1)
    assert failed == WindowsSessionQueryResult(
        WindowsSessionQueryStatus.QUERY_FAILED, win32_error=5
    )
    assert failed_api.freed == 0


@pytest.mark.parametrize("state", range(1, 10))
def test_windows_session_query_preserves_every_inactive_state(
    monkeypatch: pytest.MonkeyPatch, state: int
) -> None:
    api = _FakeWtsApi(state=state)
    monkeypatch.setattr(restricted_process_module, "_wtsapi32", lambda: api)
    assert windows_session_is_active(1) == WindowsSessionQueryResult(
        WindowsSessionQueryStatus.INACTIVE, state=state
    )
    assert api.freed == 1


@pytest.mark.parametrize(
    "api",
    [
        _FakeWtsApi(size=0),
        _FakeWtsApi(size=8),
        _FakeWtsApi(null_buffer=True),
        _FakeWtsApi(state=10),
        _FakeWtsApi(cleanup_fails=True),
    ],
    ids=["empty-size", "oversized", "null-buffer", "invalid-state", "cleanup"],
)
def test_windows_session_query_rejects_invalid_shape_or_cleanup(
    monkeypatch: pytest.MonkeyPatch, api: _FakeWtsApi
) -> None:
    monkeypatch.setattr(restricted_process_module, "_wtsapi32", lambda: api)
    assert windows_session_is_active(1) == WindowsSessionQueryResult(
        WindowsSessionQueryStatus.QUERY_FAILED, win32_error=13
    )


def test_authenticated_client_wts_query_has_exact_impersonation_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    advapi = _FakeWtsImpersonationAdvapi(events=events)
    wts = _FakeWtsApi(state=0, events=events)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi)
    monkeypatch.setattr(
        restricted_process_module, "_kernel32", lambda: _FakeKernel32()
    )
    monkeypatch.setattr(restricted_process_module, "_wtsapi32", lambda: wts)

    result = authenticated_client_windows_session_state(11, 1)

    assert result.is_active
    assert events == [
        "verify",
        "verify",
        "impersonate",
        "query",
        "free",
        "revert",
        "verify",
        "verify",
    ]


def test_authenticated_client_wts_query_fails_closed_on_impersonation_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    advapi = _FakeWtsImpersonationAdvapi(
        impersonate_result=False, events=events
    )
    wts = _FakeWtsApi(state=0, events=events)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi)
    monkeypatch.setattr(
        restricted_process_module, "_kernel32", lambda: _FakeKernel32()
    )
    monkeypatch.setattr(restricted_process_module, "_wtsapi32", lambda: wts)

    with pytest.raises(PermissionError, match="WTS impersonation failed"):
        authenticated_client_windows_session_state(11, 1)

    assert "query" not in events
    assert events[-1] == "verify"


def test_authenticated_client_wts_query_reports_query_failure_after_reversion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    advapi = _FakeWtsImpersonationAdvapi(events=events)
    wts = _FakeWtsApi(succeeds=False, error=5, events=events)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi)
    monkeypatch.setattr(
        restricted_process_module, "_kernel32", lambda: _FakeKernel32()
    )
    monkeypatch.setattr(restricted_process_module, "_wtsapi32", lambda: wts)

    result = authenticated_client_windows_session_state(11, 1)

    assert result == WindowsSessionQueryResult(
        WindowsSessionQueryStatus.QUERY_FAILED, win32_error=5
    )
    assert events.index("query") < events.index("revert")
    assert events[-1] == "verify"


def test_authenticated_client_wts_query_abandons_worker_on_reversion_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    advapi = _FakeWtsImpersonationAdvapi(revert_result=False, events=events)
    wts = _FakeWtsApi(state=0, events=events)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi)
    monkeypatch.setattr(
        restricted_process_module, "_kernel32", lambda: _FakeKernel32()
    )
    monkeypatch.setattr(restricted_process_module, "_wtsapi32", lambda: wts)

    with pytest.raises(
        ProviderLaunchIdentityUncertain, match="reversion could not be verified"
    ):
        authenticated_client_windows_session_state(11, 1)

    assert events.count("query") == 1
    assert events.count("revert") == 1


class _FakeKernel32:
    def __init__(self) -> None:
        self.closed: list[int] = []

    def CloseHandle(self, handle: object) -> bool:
        value = getattr(handle, "value", handle)
        assert isinstance(value, int)
        self.closed.append(value)
        return True

    def GetCurrentThread(self) -> int:
        return 7


class _FakeAdvapi32:
    def __init__(
        self,
        *,
        duplicate_result: bool = True,
        set_session_result: bool = True,
    ) -> None:
        self.duplicate_result = duplicate_result
        self.set_session_result = set_session_result
        self.requested_access: int | None = None
        self.source_token: int | None = None
        self.selected_session: int | None = None
        self.local = threading.local()

    def DuplicateTokenEx(
        self,
        source: object,
        access: int,
        attributes: object,
        impersonation_level: int,
        token_type: int,
        output: Any,
    ) -> bool:
        del attributes, impersonation_level, token_type
        source_value = getattr(source, "value", source)
        assert isinstance(source_value, int)
        self.source_token = source_value
        self.requested_access = access
        if not self.duplicate_result:
            return False
        ctypes.cast(output, ctypes.POINTER(wintypes.HANDLE)).contents.value = 84
        return True

    def SetTokenInformation(
        self,
        token: object,
        token_class: int,
        value: Any,
        size: int,
    ) -> bool:
        del token, size
        assert token_class == 12
        self.selected_session = ctypes.cast(
            value, ctypes.POINTER(wintypes.DWORD)
        ).contents.value
        return self.set_session_result


class _FakeUserenv:
    def __init__(
        self,
        *,
        succeeds: bool,
        destroy_succeeds: bool = True,
        events: list[str] | None = None,
    ) -> None:
        self.succeeds = succeeds
        self.destroy_succeeds = destroy_succeeds
        self.events = events
        self.destroyed: list[int] = []
        self.create_calls = 0
        self.token: int | None = None
        self.buffer = ctypes.create_unicode_buffer(
            "USERPROFILE=C:\\Users\\Founder\0PATH=C:\\bin\0\0"
        )

    def CreateEnvironmentBlock(
        self, output: Any, token: int, inherit: bool
    ) -> bool:
        self.token = token
        self.create_calls += 1
        if self.events is not None:
            self.events.append("create-environment")
        del inherit
        if not self.succeeds:
            ctypes.set_last_error(5)
            return False
        ctypes.cast(output, ctypes.POINTER(wintypes.LPVOID)).contents.value = (
            ctypes.addressof(self.buffer)
        )
        return True

    def DestroyEnvironmentBlock(self, block: object) -> bool:
        value = getattr(block, "value", block)
        assert isinstance(value, int)
        self.destroyed.append(value)
        if self.events is not None:
            self.events.append("destroy-environment")
        if not self.destroy_succeeds:
            ctypes.set_last_error(5)
        return self.destroy_succeeds


class _FakeClientTokenAdvapi32:
    def __init__(
        self, *, level: int = 2, revert_result: bool = True
    ) -> None:
        self.level = level
        self.revert_result = revert_result
        self.requested_access: int | None = None
        self.revert_calls = 0
        self.logged_on_calls = 0

    def ImpersonateNamedPipeClient(self, pipe: int) -> bool:
        assert pipe == 11
        return True

    def OpenThreadToken(
        self,
        thread: int,
        access: int,
        open_as_self: bool,
        output: Any,
    ) -> bool:
        assert thread == 7
        assert open_as_self is True
        self.requested_access = access
        ctypes.cast(output, ctypes.POINTER(wintypes.HANDLE)).contents.value = 42
        return True

    def GetTokenInformation(
        self,
        token: int,
        information_class: int,
        output: Any,
        length: int,
        needed: Any,
    ) -> bool:
        assert token == 42
        assert information_class == 9
        assert length == ctypes.sizeof(wintypes.DWORD)
        ctypes.cast(output, ctypes.POINTER(wintypes.DWORD)).contents.value = (
            self.level
        )
        ctypes.cast(needed, ctypes.POINTER(wintypes.DWORD)).contents.value = length
        return True

    def ImpersonateLoggedOnUser(self, token: int) -> bool:
        assert token == 42
        self.logged_on_calls += 1
        return True

    def RevertToSelf(self) -> bool:
        self.revert_calls += 1
        return self.revert_result


class _FakeLaunchKernel32:
    def __init__(self) -> None:
        self.closed: list[int] = []
        self.terminated: list[int] = []
        self.waited: list[int] = []

    def GetCurrentThread(self) -> int:
        return threading.get_ident()

    def CloseHandle(self, handle: object) -> bool:
        value = getattr(handle, "value", handle)
        assert isinstance(value, int)
        self.closed.append(value)
        return True

    def TerminateProcess(self, process: int, exit_code: int) -> bool:
        assert exit_code == 125
        self.terminated.append(process)
        return True

    def WaitForSingleObject(self, process: int, timeout: int) -> int:
        assert timeout == 10_000
        self.waited.append(process)
        return 0


@pytest.mark.parametrize(
    ("terminate_result", "wait_result"),
    [(False, 0), (True, 258)],
)
def test_restricted_process_cleanup_requires_proven_job_termination(
    monkeypatch: pytest.MonkeyPatch,
    terminate_result: bool,
    wait_result: int,
) -> None:
    class _CleanupKernel32:
        def __init__(self) -> None:
            self.calls: list[tuple[object, ...]] = []

        def TerminateJobObject(self, job: int, exit_code: int) -> bool:
            self.calls.append(("terminate", job, exit_code))
            return terminate_result

        def WaitForSingleObject(self, process: int, timeout: int) -> int:
            self.calls.append(("wait", process, timeout))
            return wait_result

    api = _CleanupKernel32()
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: api)

    with pytest.raises(
        restricted_process_module.RestrictedProcessCleanupUncertain,
        match="terminal cleanup is uncertain",
    ):
        restricted_process_module._terminate_restricted_process_or_raise(41, 42)

    assert api.calls == [("terminate", 41, 125), ("wait", 42, 10_000)]


def test_restricted_process_cleanup_accepts_only_signaled_job_termination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _CleanupKernel32:
        def TerminateJobObject(self, job: int, exit_code: int) -> bool:
            return (job, exit_code) == (41, 125)

        def WaitForSingleObject(self, process: int, timeout: int) -> int:
            assert (process, timeout) == (42, 10_000)
            return 0

    monkeypatch.setattr(
        restricted_process_module, "_kernel32", lambda: _CleanupKernel32()
    )

    restricted_process_module._terminate_restricted_process_or_raise(41, 42)


class _FakeLaunchAdvapi32:
    def __init__(
        self,
        *,
        impersonate_result: bool = True,
        revert_result: bool = True,
        worker_verification_error: int | None = None,
        service_post_verification_error: int | None = None,
        impersonate_raises: bool = False,
        revert_raises: bool = False,
    ) -> None:
        self.impersonate_result = impersonate_result
        self.revert_result = revert_result
        self.worker_verification_error = worker_verification_error
        self.service_post_verification_error = service_post_verification_error
        self.impersonate_raises = impersonate_raises
        self.revert_raises = revert_raises
        self.local = threading.local()
        self.worker_thread_id: int | None = None
        self.service_thread_id = threading.get_ident()
        self.service_checks = 0
        self.events: list[str] = []

    def OpenThreadToken(
        self,
        thread: int,
        access: int,
        open_as_self: bool,
        output: Any,
    ) -> bool:
        del output
        assert access == 0x0008
        assert open_as_self is True
        if getattr(self.local, "impersonating", False):
            self.events.append("token-present")
            return True
        if (
            self.worker_thread_id == thread
            and self.worker_verification_error is not None
        ):
            ctypes.set_last_error(self.worker_verification_error)
            self.events.append("worker-verification-failed")
            return False
        if thread == self.service_thread_id:
            self.service_checks += 1
            if (
                self.service_checks > 1
                and self.service_post_verification_error is not None
            ):
                ctypes.set_last_error(self.service_post_verification_error)
                self.events.append("service-verification-failed")
                return False
        ctypes.set_last_error(1008)
        self.events.append("no-token")
        return False

    def ImpersonateLoggedOnUser(self, token: int) -> bool:
        assert token == 84
        self.worker_thread_id = threading.get_ident()
        self.events.append("impersonate")
        if self.impersonate_raises:
            raise OSError("synthetic impersonation API exception")
        if self.impersonate_result:
            self.local.impersonating = True
        else:
            ctypes.set_last_error(5)
        return self.impersonate_result

    def RevertToSelf(self) -> bool:
        self.events.append("revert")
        if self.revert_raises:
            raise OSError("synthetic reversion API exception")
        if self.revert_result:
            self.local.impersonating = False
        else:
            ctypes.set_last_error(5)
        return self.revert_result


def test_named_pipe_client_token_uses_minimum_rights_and_reverts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeClientTokenAdvapi32()
    kernel32 = _FakeKernel32()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)

    with authenticated_named_pipe_client_token(11) as token:
        assert token == 42
        assert kernel32.closed == []

    assert advapi32.requested_access == 0x0002 | 0x0004 | 0x0008
    assert advapi32.revert_calls == 1
    assert kernel32.closed == [42]


def test_named_pipe_client_token_rejects_insufficient_impersonation_level(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeClientTokenAdvapi32(level=1)
    kernel32 = _FakeKernel32()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)

    with pytest.raises(PermissionError, match="insufficient impersonation"):
        with authenticated_named_pipe_client_token(11):
            pass

    assert advapi32.revert_calls == 1
    assert kernel32.closed == [42]


def test_named_pipe_client_token_revert_failure_closes_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeClientTokenAdvapi32(revert_result=False)
    kernel32 = _FakeKernel32()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5)

    with pytest.raises(PermissionError, match="could not be reverted"):
        with authenticated_named_pipe_client_token(11):
            pass

    assert kernel32.closed == [42]


def test_named_pipe_client_process_token_is_captured_before_verified_reversion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeClientTokenAdvapi32()
    kernel32 = _FakeKernel32()
    events: list[str] = []

    class Binding:
        profile_token = 86

        def revalidate_core(self, expected_sid: str):  # type: ignore[no-untyped-def]
            assert expected_sid == "S-1-5-21-1000"
            return type("Identity", (), {"sid": expected_sid})()

        def revalidate(self, expected_sid: str):  # type: ignore[no-untyped-def]
            return self.revalidate_core(expected_sid)

        def bind_or_revalidate_executable_identity(
            self, expected_sid: str
        ):  # type: ignore[no-untyped-def]
            events.append("bind-client-image")
            return self.revalidate_core(expected_sid)

    @contextmanager
    def bind_process(pipe: int, sid: str):  # type: ignore[no-untyped-def]
        assert pipe == 11
        assert sid == "S-1-5-21-1000"
        assert advapi32.revert_calls == 0
        events.append("bind-process-token")
        yield Binding()
        events.append("release-process-token")

    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(
        restricted_process_module,
        "token_user_sid_string",
        lambda token: "S-1-5-21-1000",
    )
    monkeypatch.setattr(
        restricted_process_module,
        "authenticated_named_pipe_client_process",
        bind_process,
    )
    monkeypatch.setattr(
        restricted_process_module,
        "_finalize_authenticated_client_process_binding",
        lambda binding, *, expected_sid: events.append(
            f"finalize-client-image:{expected_sid}"
        ),
    )

    with authenticated_named_pipe_client(11) as (token, binding):
        assert token == 42
        assert binding.profile_token == 86
        assert advapi32.revert_calls == 1
        assert kernel32.closed == []

    assert events == [
        "bind-process-token",
        "finalize-client-image:S-1-5-21-1000",
        "release-process-token",
    ]
    assert kernel32.closed == [42]


def test_named_pipe_client_process_binding_failure_reverts_and_closes_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeClientTokenAdvapi32()
    kernel32 = _FakeKernel32()

    @contextmanager
    def reject_binding(pipe: int, sid: str):  # type: ignore[no-untyped-def]
        del pipe, sid
        raise PermissionError("process token denied")
        yield

    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(
        restricted_process_module,
        "token_user_sid_string",
        lambda token: "S-1-5-21-1000",
    )
    monkeypatch.setattr(
        restricted_process_module,
        "authenticated_named_pipe_client_process",
        reject_binding,
    )

    with pytest.raises(PermissionError, match="process token denied"):
        with authenticated_named_pipe_client(11):
            pass

    assert advapi32.revert_calls == 1
    assert kernel32.closed == [42]


def test_bounded_impersonation_reverts_on_body_error_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeClientTokenAdvapi32()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)

    with pytest.raises(RuntimeError, match="body failed"):
        with impersonate_token(42):
            raise RuntimeError("body failed")
    assert advapi32.logged_on_calls == 1
    assert advapi32.revert_calls == 1

    failing = _FakeClientTokenAdvapi32(revert_result=False)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: failing)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5)
    with pytest.raises(PermissionError, match="could not be reverted"):
        with impersonate_token(42):
            pass


def test_restricted_launch_impersonates_only_for_create_and_reverts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeLaunchAdvapi32()
    kernel32 = _FakeLaunchKernel32()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    process = restricted_process_module._ProcessInformation()
    create_thread: list[int] = []

    def create_process() -> bool:
        assert getattr(advapi32.local, "impersonating", False) is True
        advapi32.events.append("create")
        create_thread.append(threading.get_ident())
        process.hProcess = 101
        process.hThread = 102
        process.dwProcessId = 4101
        return True

    _create_process_with_bounded_restricted_impersonation(
        84, process, create_process
    )
    for later_service_step in ("assign-job", "callback", "resume"):
        assert getattr(advapi32.local, "impersonating", False) is False
        advapi32.events.append(later_service_step)

    assert create_thread == [advapi32.worker_thread_id]
    assert create_thread[0] != threading.get_ident()
    assert advapi32.events == [
        "no-token",
        "no-token",
        "impersonate",
        "create",
        "revert",
        "no-token",
        "no-token",
        "assign-job",
        "callback",
        "resume",
    ]
    assert process.hProcess == 101
    assert process.hThread == 102
    assert kernel32.terminated == []
    assert kernel32.closed == []


def test_restricted_launch_impersonation_failure_never_creates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeLaunchAdvapi32(impersonate_result=False)
    kernel32 = _FakeLaunchKernel32()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    process = restricted_process_module._ProcessInformation()
    create_calls = 0

    def create_process() -> bool:
        nonlocal create_calls
        create_calls += 1
        return True

    with pytest.raises(PermissionError, match="impersonation failed"):
        _create_process_with_bounded_restricted_impersonation(
            84, process, create_process
        )

    assert create_calls == 0
    assert advapi32.events == [
        "no-token",
        "no-token",
        "impersonate",
        "no-token",
        "no-token",
    ]
    assert kernel32.terminated == []
    assert kernel32.closed == []


def test_restricted_launch_create_failure_reverts_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeLaunchAdvapi32()
    kernel32 = _FakeLaunchKernel32()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    process = restricted_process_module._ProcessInformation()
    create_calls = 0

    def create_process() -> bool:
        nonlocal create_calls
        assert getattr(advapi32.local, "impersonating", False) is True
        create_calls += 1
        ctypes.set_last_error(5)
        return False

    with pytest.raises(PermissionError, match="creation failed"):
        _create_process_with_bounded_restricted_impersonation(
            84, process, create_process
        )

    assert create_calls == 1
    assert advapi32.events.index("revert") > advapi32.events.index("impersonate")
    assert advapi32.events[-1] == "no-token"
    assert kernel32.terminated == []
    assert kernel32.closed == []


@pytest.mark.parametrize(
    "advapi32",
    [
        _FakeLaunchAdvapi32(revert_result=False),
        _FakeLaunchAdvapi32(worker_verification_error=5),
    ],
    ids=["revert-failure", "verification-failure"],
)
def test_restricted_launch_identity_uncertainty_terminates_suspended_process(
    advapi32: _FakeLaunchAdvapi32,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = _FakeLaunchKernel32()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    process = restricted_process_module._ProcessInformation()
    resumed_or_callback = False

    def create_process() -> bool:
        nonlocal resumed_or_callback
        assert resumed_or_callback is False
        process.hProcess = 101
        process.hThread = 102
        process.dwProcessId = 4101
        return True

    with pytest.raises(
        ProviderLaunchIdentityUncertain,
        match="reversion|reverted|verified",
    ):
        _create_process_with_bounded_restricted_impersonation(
            84, process, create_process
        )

    assert resumed_or_callback is False
    assert kernel32.terminated == [101]
    assert kernel32.waited == [101]
    assert kernel32.closed == [102, 101]
    assert process.hProcess in {None, 0}
    assert process.hThread in {None, 0}
    assert advapi32.worker_thread_id != threading.get_ident()


def test_unclean_service_thread_fails_stop_and_terminates_suspended_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeLaunchAdvapi32(service_post_verification_error=5)
    kernel32 = _FakeLaunchKernel32()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    process = restricted_process_module._ProcessInformation()

    def create_process() -> bool:
        process.hProcess = 101
        process.hThread = 102
        return True

    with pytest.raises(
        ProviderServiceIdentityUncertain, match="not clean after launch"
    ):
        _create_process_with_bounded_restricted_impersonation(
            84, process, create_process
        )

    assert kernel32.terminated == [101]
    assert kernel32.waited == [101]
    assert kernel32.closed == [102, 101]
    assert process.hProcess in {None, 0}
    assert process.hThread in {None, 0}

def test_profile_primary_token_requests_only_documented_rights_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeAdvapi32()
    kernel32 = _FakeKernel32()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)

    with authenticated_profile_primary_token(42) as token:
        assert token == 84
        assert kernel32.closed == []

    assert advapi32.source_token == 42
    assert advapi32.requested_access == 0x0002 | 0x0008
    assert kernel32.closed == [84]


def test_profile_primary_token_access_denied_is_sanitized_and_leak_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeAdvapi32(duplicate_result=False)
    kernel32 = _FakeKernel32()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5)

    with pytest.raises(PermissionError) as caught:
        with authenticated_profile_primary_token(42):
            pass

    message = str(caught.value)
    assert "api=DuplicateTokenEx" in message
    assert "win32_error=5" in message
    assert "symbolic=ERROR_ACCESS_DENIED" in message
    assert "TOKEN_DUPLICATE|TOKEN_QUERY" in message
    assert kernel32.closed == []


class _RetainedClientProcessBinding:
    def __init__(self, *, failure_at: int | None = None) -> None:
        self.profile_token = 86
        self.failure_at = failure_at
        self.revalidations = 0
        self.identity = NamedPipeClientProcessIdentity(
            process_id=700,
            session_id=1,
            sid=SID,
            computer_name="LOCALHOST",
            process_creation_time_100ns=123456,
            executable_path=r"C:\Program Files\Keeper\client.exe",
            executable_file_identity=(7, 11, 4096, 987654),
        )

    def revalidate(self, expected_sid: str) -> NamedPipeClientProcessIdentity:
        self.revalidations += 1
        if expected_sid.casefold() != SID.casefold():
            raise PermissionError("authority client process SID is mismatched")
        if self.failure_at == self.revalidations:
            raise PermissionError("authority client process identity changed")
        return self.identity

    def revalidate_core(
        self, expected_sid: str
    ) -> NamedPipeClientProcessIdentity:
        return self.revalidate(expected_sid)


def _client_token_policy(
    token_type: int,
    *,
    sid: str = SID,
    session: int = 1,
    restricted: bool = False,
    groups: tuple[tuple[str, int], ...] = (("S-1-5-32-545", 4),),
    restricting_sids: tuple[tuple[str, int], ...] = (),
) -> restricted_process_module._AuthenticatedClientTokenPolicy:
    return restricted_process_module._AuthenticatedClientTokenPolicy(
        user_sid=sid,
        session_id=session,
        integrity_level="medium",
        elevation_type=3,
        has_restrictions=True,
        restricted=restricted,
        groups=groups,
        restricting_sids=restricting_sids,
        token_type=token_type,
    )


def test_client_process_impersonation_duplicate_is_minimal_exact_and_revalidated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeAdvapi32()
    kernel32 = _FakeKernel32()
    binding = _RetainedClientProcessBinding()
    policies = {86: _client_token_policy(1), 84: _client_token_policy(2)}
    checked: list[int] = []
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(
        restricted_process_module,
        "_authenticated_client_token_policy",
        lambda token: policies[token],
    )
    monkeypatch.setattr(
        restricted_process_module,
        "require_impersonation_level",
        lambda token: checked.append(token) or 2,
    )

    with authenticated_client_process_impersonation_token(
        binding, expected_sid=SID  # type: ignore[arg-type]
    ) as token:
        assert token == 84
        assert binding.revalidations == 2
        assert kernel32.closed == []

    assert binding.revalidations == 3
    assert advapi32.source_token == 86
    assert advapi32.requested_access == 0x0004 | 0x0008
    assert checked == [84]
    assert kernel32.closed == [84]


@pytest.mark.parametrize(
    ("source_policy", "duplicate_policy", "message"),
    [
        (
            _client_token_policy(1, restricted=True),
            _client_token_policy(2),
            "restricted",
        ),
        (
            _client_token_policy(
                1, restricting_sids=(("S-1-5-12", 7),)
            ),
            _client_token_policy(2),
            "restricted",
        ),
        (
            _client_token_policy(1, sid="S-1-5-21-9999"),
            _client_token_policy(2),
            "mismatched",
        ),
        (_client_token_policy(1, session=2), _client_token_policy(2), "mismatched"),
        (_client_token_policy(2), _client_token_policy(2), "mismatched"),
        (
            _client_token_policy(1),
            _client_token_policy(2, groups=(("S-1-5-32-544", 16),)),
            "duplicate is mismatched",
        ),
    ],
)
def test_client_process_impersonation_duplicate_rejects_ambiguous_or_changed_policy(
    monkeypatch: pytest.MonkeyPatch,
    source_policy: restricted_process_module._AuthenticatedClientTokenPolicy,
    duplicate_policy: restricted_process_module._AuthenticatedClientTokenPolicy,
    message: str,
) -> None:
    advapi32 = _FakeAdvapi32()
    kernel32 = _FakeKernel32()
    policies = {86: source_policy, 84: duplicate_policy}
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(
        restricted_process_module,
        "_authenticated_client_token_policy",
        lambda token: policies[token],
    )
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )

    with pytest.raises(PermissionError, match=message):
        with authenticated_client_process_impersonation_token(
            _RetainedClientProcessBinding(), expected_sid=SID  # type: ignore[arg-type]
        ):
            pass

    if advapi32.source_token is None:
        assert kernel32.closed == []
    else:
        assert kernel32.closed == [84]


def test_client_process_duplicate_fails_on_duplication_or_peer_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = _FakeKernel32()
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(
        restricted_process_module,
        "_authenticated_client_token_policy",
        lambda token: _client_token_policy(1 if token == 86 else 2),
    )
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )
    denied = _FakeAdvapi32(duplicate_result=False)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: denied)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5)
    with pytest.raises(PermissionError, match="duplication failed"):
        with authenticated_client_process_impersonation_token(
            _RetainedClientProcessBinding(), expected_sid=SID  # type: ignore[arg-type]
        ):
            pass
    assert kernel32.closed == []

    allowed = _FakeAdvapi32()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: allowed)
    binding = _RetainedClientProcessBinding(failure_at=3)
    with pytest.raises(PermissionError, match="identity changed"):
        with authenticated_client_process_impersonation_token(
            binding, expected_sid=SID  # type: ignore[arg-type]
        ):
            pass
    assert kernel32.closed == [84]


class _TransferWorkerKernel(_FakeKernel32):
    def __init__(self) -> None:
        super().__init__()
        self.local: threading.local | None = None
        self.opens: list[tuple[int, bool, int, bool]] = []

    def OpenProcess(self, access: int, inherit: bool, process_id: int) -> int:
        impersonating = bool(
            self.local is not None
            and getattr(self.local, "impersonating", False)
        )
        self.opens.append((access, inherit, process_id, impersonating))
        return 73 if impersonating else 0

    def GetCurrentThread(self) -> int:
        return threading.get_ident()


@pytest.mark.parametrize(
    ("impersonate", "revert", "post_error", "message"),
    [
        (False, True, None, "impersonation failed"),
        (True, False, None, "produced no outcome"),
        (True, True, 5, "not clean after"),
    ],
)
def test_authenticated_client_transfer_worker_fails_closed_and_cleans_handles(
    monkeypatch: pytest.MonkeyPatch,
    impersonate: bool,
    revert: bool,
    post_error: int | None,
    message: str,
) -> None:
    launch_advapi32 = _FakeLaunchAdvapi32(
        impersonate_result=impersonate,
        revert_result=revert,
        service_post_verification_error=post_error,
    )
    duplicate_advapi32 = _FakeAdvapi32()
    duplicate_advapi32.local = launch_advapi32.local
    for api_name in (
        "ImpersonateLoggedOnUser",
        "RevertToSelf",
        "OpenThreadToken",
    ):
        setattr(duplicate_advapi32, api_name, getattr(launch_advapi32, api_name))
    kernel32 = _TransferWorkerKernel()
    kernel32.local = launch_advapi32.local
    binding = _RetainedClientProcessBinding()
    policies = {86: _client_token_policy(1), 84: _client_token_policy(2)}
    monkeypatch.setattr(
        restricted_process_module, "_advapi32", lambda: duplicate_advapi32
    )
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(
        restricted_process_module,
        "_authenticated_client_token_policy",
        lambda token: policies[token],
    )
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )

    with pytest.raises(BaseException, match=message):
        with authenticated_client_transfer_process(
            binding, expected_sid=SID  # type: ignore[arg-type]
        ):
            raise AssertionError("failed transfer must not publish a handle")

    assert 84 in kernel32.closed
    if impersonate:
        assert kernel32.opens == [(0x1040, False, 700, True)]
        assert 73 in kernel32.closed
    else:
        assert kernel32.opens == []


def test_authenticated_client_transfer_worker_publishes_only_after_reversion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launch_advapi32 = _FakeLaunchAdvapi32()
    duplicate_advapi32 = _FakeAdvapi32()
    duplicate_advapi32.local = launch_advapi32.local
    for api_name in (
        "ImpersonateLoggedOnUser",
        "RevertToSelf",
        "OpenThreadToken",
    ):
        setattr(duplicate_advapi32, api_name, getattr(launch_advapi32, api_name))
    kernel32 = _TransferWorkerKernel()
    kernel32.local = launch_advapi32.local
    binding = _RetainedClientProcessBinding()
    policies = {86: _client_token_policy(1), 84: _client_token_policy(2)}
    monkeypatch.setattr(
        restricted_process_module, "_advapi32", lambda: duplicate_advapi32
    )
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(
        restricted_process_module,
        "_authenticated_client_token_policy",
        lambda token: policies[token],
    )
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )

    with authenticated_client_transfer_process(
        binding, expected_sid=SID  # type: ignore[arg-type]
    ) as process:
        assert process == 73
        assert not getattr(launch_advapi32.local, "impersonating", False)
        assert threading.get_ident() == launch_advapi32.service_thread_id
        assert kernel32.closed == []

    assert kernel32.opens == [(0x1040, False, 700, True)]
    assert kernel32.closed == [73, 84]
    assert binding.revalidations == 5


class _ClientImageBinding:
    def __init__(
        self,
        advapi32: _FakeLaunchAdvapi32,
        *,
        validation_error: BaseException | None = None,
        final_error: BaseException | None = None,
    ) -> None:
        self.advapi32 = advapi32
        self.validation_error = validation_error
        self.final_error = final_error
        self.worker_thread: int | None = None
        self.binds = 0
        self.revalidations = 0

    def bind_or_revalidate_executable_identity(
        self, expected_sid: str
    ) -> NamedPipeClientProcessIdentity:
        assert expected_sid == SID
        assert getattr(self.advapi32.local, "impersonating", False)
        assert threading.get_ident() != self.advapi32.service_thread_id
        self.worker_thread = threading.get_ident()
        self.binds += 1
        if self.validation_error is not None:
            raise self.validation_error
        return _RetainedClientProcessBinding().identity

    def revalidate(self, expected_sid: str) -> NamedPipeClientProcessIdentity:
        assert expected_sid == SID
        assert not getattr(self.advapi32.local, "impersonating", False)
        self.revalidations += 1
        if self.final_error is not None:
            raise self.final_error
        return _RetainedClientProcessBinding().identity


def _stub_client_process_token_duplicate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextmanager
    def duplicate(
        binding: object, *, expected_sid: str, require_finalized: bool
    ) -> Iterator[int]:
        del binding
        assert expected_sid == SID
        assert require_finalized is False
        yield 84

    monkeypatch.setattr(
        restricted_process_module,
        "_authenticated_client_process_token_duplicate",
        duplicate,
    )
    monkeypatch.setattr(
        restricted_process_module,
        "require_impersonation_level",
        lambda token: 2 if token == 84 else 0,
    )


def test_client_image_identity_is_bound_only_on_disposable_impersonated_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeLaunchAdvapi32()
    kernel32 = _FakeLaunchKernel32()
    binding = _ClientImageBinding(advapi32)
    _stub_client_process_token_duplicate(monkeypatch)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)

    restricted_process_module._finalize_authenticated_client_process_binding(
        binding, expected_sid=SID  # type: ignore[arg-type]
    )

    assert binding.binds == 1
    assert binding.revalidations == 1
    assert binding.worker_thread not in {None, threading.get_ident()}
    assert advapi32.events == [
        "no-token",
        "no-token",
        "impersonate",
        "revert",
        "no-token",
        "no-token",
    ]


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("impersonation", "impersonation failed"),
        ("impersonation-exception", "worker identity could not be verified"),
        ("read", "synthetic executable read denied"),
        ("reversion", "worker identity could not be verified"),
        ("reversion-exception", "worker identity could not be verified"),
        ("worker-verification", "worker identity could not be verified"),
        ("service-after", "service thread identity is not clean after"),
        ("peer-change", "client process identity changed"),
    ],
)
def test_client_image_identity_binding_fails_closed_and_never_publishes(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    message: str,
) -> None:
    advapi32 = _FakeLaunchAdvapi32(
        impersonate_result=failure != "impersonation",
        revert_result=failure != "reversion",
        impersonate_raises=failure == "impersonation-exception",
        revert_raises=failure == "reversion-exception",
        worker_verification_error=5 if failure == "worker-verification" else None,
        service_post_verification_error=5 if failure == "service-after" else None,
    )
    kernel32 = _FakeLaunchKernel32()
    binding = _ClientImageBinding(
        advapi32,
        validation_error=(
            PermissionError("synthetic executable read denied")
            if failure == "read"
            else None
        ),
        final_error=(
            PermissionError("authority client process identity changed")
            if failure == "peer-change"
            else None
        ),
    )
    _stub_client_process_token_duplicate(monkeypatch)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)

    with pytest.raises(
        (
            PermissionError,
            restricted_process_module.ProviderServiceIdentityUncertain,
        ),
        match=message,
    ):
        restricted_process_module._finalize_authenticated_client_process_binding(
            binding, expected_sid=SID  # type: ignore[arg-type]
        )

    assert binding.revalidations == (1 if failure == "peer-change" else 0)
    assert binding.binds == (
        0 if failure in {"impersonation", "impersonation-exception"} else 1
    )


def test_loaded_profile_environment_is_created_and_destroyed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    userenv = _FakeUserenv(succeeds=True)
    monkeypatch.setattr(restricted_process_module, "_userenv", lambda: userenv)

    environment = token_environment(84)

    assert environment["USERPROFILE"] == r"C:\Users\Founder"
    assert environment["PATH"] == r"C:\bin"
    assert userenv.destroyed == [ctypes.addressof(userenv.buffer)]


def test_authenticated_client_environment_uses_exact_impersonation_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeLaunchAdvapi32()
    kernel32 = _FakeLaunchKernel32()
    userenv = _FakeUserenv(succeeds=True, events=advapi32.events)
    checked: list[int] = []
    parse_environment = restricted_process_module._environment_from_block

    def parse_after_reversion(block: wintypes.LPVOID) -> dict[str, str]:
        advapi32.events.append("parse-environment")
        return parse_environment(block)

    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(restricted_process_module, "_userenv", lambda: userenv)
    monkeypatch.setattr(
        restricted_process_module,
        "_environment_from_block",
        parse_after_reversion,
    )
    def check_level(token: int) -> int:
        checked.append(token)
        return 2

    monkeypatch.setattr(
        restricted_process_module,
        "require_impersonation_level",
        check_level,
    )

    environment = authenticated_client_environment(84)

    assert checked == [84]
    assert userenv.token == 84
    assert userenv.create_calls == 1
    assert environment["USERPROFILE"] == r"C:\Users\Founder"
    assert userenv.destroyed == [ctypes.addressof(userenv.buffer)]
    assert advapi32.events.count("impersonate") == 1
    assert advapi32.events.count("revert") == 1
    assert advapi32.events.index("impersonate") < advapi32.events.index(
        "create-environment"
    )
    assert advapi32.events.index("create-environment") < advapi32.events.index(
        "revert"
    )
    assert advapi32.events.index("revert") < advapi32.events.index(
        "parse-environment"
    )
    assert advapi32.events.index("parse-environment") < advapi32.events.index(
        "destroy-environment"
    )
    assert advapi32.events[-1] == "no-token"


def test_authenticated_client_environment_failure_reports_minimum_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeLaunchAdvapi32()
    kernel32 = _FakeLaunchKernel32()
    userenv = _FakeUserenv(succeeds=False)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(restricted_process_module, "_userenv", lambda: userenv)
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )

    with pytest.raises(PermissionError) as caught:
        authenticated_client_environment(84)

    message = str(caught.value)
    assert "token_type=authenticated-impersonation" in message
    assert "required_access=TOKEN_QUERY" in message
    assert "TOKEN_DUPLICATE" not in message
    assert "win32_error=5" in message
    assert userenv.destroyed == []
    assert advapi32.events.count("impersonate") == 1
    assert advapi32.events.count("revert") == 1
    assert advapi32.events[-1] == "no-token"


def test_authenticated_client_environment_impersonation_failure_never_calls_userenv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeLaunchAdvapi32(impersonate_result=False)
    kernel32 = _FakeLaunchKernel32()
    userenv = _FakeUserenv(succeeds=True)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(restricted_process_module, "_userenv", lambda: userenv)
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )

    with pytest.raises(PermissionError, match="profile impersonation failed"):
        authenticated_client_environment(84)

    assert userenv.create_calls == 0
    assert userenv.destroyed == []
    assert advapi32.events.count("impersonate") == 1
    assert advapi32.events.count("revert") == 0
    assert advapi32.events[-1] == "no-token"


def test_authenticated_client_environment_reversion_failure_discards_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeLaunchAdvapi32(revert_result=False)
    kernel32 = _FakeLaunchKernel32()
    userenv = _FakeUserenv(succeeds=True)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(restricted_process_module, "_userenv", lambda: userenv)
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )

    with pytest.raises(
        ProviderLaunchIdentityUncertain,
        match="reversion could not be verified",
    ):
        authenticated_client_environment(84)

    assert userenv.create_calls == 1
    assert userenv.destroyed == [ctypes.addressof(userenv.buffer)]
    assert advapi32.events.count("impersonate") == 1
    assert advapi32.events.count("revert") == 1
    assert advapi32.events[-1] == "no-token"


def test_authenticated_client_environment_worker_verification_failure_discards_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeLaunchAdvapi32(worker_verification_error=6)
    kernel32 = _FakeLaunchKernel32()
    userenv = _FakeUserenv(succeeds=True)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(restricted_process_module, "_userenv", lambda: userenv)
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )

    with pytest.raises(
        ProviderLaunchIdentityUncertain,
        match="reversion could not be verified",
    ):
        authenticated_client_environment(84)

    assert userenv.create_calls == 1
    assert userenv.destroyed == [ctypes.addressof(userenv.buffer)]
    assert advapi32.events[-1] == "no-token"


def test_authenticated_client_environment_service_identity_failure_is_fail_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeLaunchAdvapi32(service_post_verification_error=6)
    kernel32 = _FakeLaunchKernel32()
    userenv = _FakeUserenv(succeeds=True)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(restricted_process_module, "_userenv", lambda: userenv)
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )

    with pytest.raises(
        ProviderServiceIdentityUncertain,
        match="not clean after profile environment lookup",
    ):
        authenticated_client_environment(84)

    assert userenv.create_calls == 1
    assert userenv.destroyed == [ctypes.addressof(userenv.buffer)]
    assert "service-verification-failed" in advapi32.events


def test_authenticated_client_environment_cleanup_failure_rejects_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advapi32 = _FakeLaunchAdvapi32()
    kernel32 = _FakeLaunchKernel32()
    userenv = _FakeUserenv(succeeds=True, destroy_succeeds=False)
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(restricted_process_module, "_userenv", lambda: userenv)
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )

    with pytest.raises(PermissionError, match="environment cleanup failed"):
        authenticated_client_environment(84)

    assert userenv.create_calls == 1
    assert userenv.destroyed == [ctypes.addressof(userenv.buffer)]
    assert advapi32.events[-1] == "no-token"


def test_authenticated_client_profile_path_has_exact_worker_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    advapi32 = _FakeLaunchAdvapi32()
    kernel32 = _FakeLaunchKernel32()
    checked: list[int] = []
    profile = tmp_path / "Founder"
    profile.mkdir()
    original_resolve = Path.resolve

    def guarded_resolve(path: Path, strict: bool = False) -> Path:
        if path == profile:
            advapi32.events.append("resolve-profile")
            assert getattr(advapi32.local, "impersonating", False)
            assert threading.get_ident() != advapi32.service_thread_id
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(Path, "resolve", guarded_resolve)
    monkeypatch.setattr(
        restricted_process_module,
        "require_impersonation_level",
        lambda token: checked.append(token) or 2,
    )

    assert authenticated_client_profile_path(84, str(profile)) == str(profile)
    assert checked == [84]
    assert advapi32.events.count("impersonate") == 1
    assert advapi32.events.count("resolve-profile") == 1
    assert advapi32.events.count("revert") == 1
    assert advapi32.events.index("impersonate") < advapi32.events.index(
        "resolve-profile"
    )
    assert advapi32.events.index("resolve-profile") < advapi32.events.index(
        "revert"
    )
    assert advapi32.events[-1] == "no-token"


def test_authenticated_client_profile_path_impersonation_failure_does_not_resolve(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    advapi32 = _FakeLaunchAdvapi32(impersonate_result=False)
    kernel32 = _FakeLaunchKernel32()
    profile = tmp_path / "Founder"
    profile.mkdir()
    resolves = 0
    original_resolve = Path.resolve

    def guarded_resolve(path: Path, strict: bool = False) -> Path:
        nonlocal resolves
        if path == profile:
            resolves += 1
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(Path, "resolve", guarded_resolve)
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )

    with pytest.raises(PermissionError, match="path impersonation failed"):
        authenticated_client_profile_path(84, str(profile))
    assert resolves == 0
    assert advapi32.events.count("revert") == 0


def test_authenticated_client_profile_path_resolution_failure_still_reverts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    advapi32 = _FakeLaunchAdvapi32()
    kernel32 = _FakeLaunchKernel32()
    profile = tmp_path / "Founder"
    profile.mkdir()
    original_resolve = Path.resolve

    def denied_resolve(path: Path, strict: bool = False) -> Path:
        if path == profile:
            assert getattr(advapi32.local, "impersonating", False)
            raise PermissionError("synthetic path denial")
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(Path, "resolve", denied_resolve)
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )

    with pytest.raises(PermissionError, match="synthetic path denial"):
        authenticated_client_profile_path(84, str(profile))
    assert advapi32.events.count("revert") == 1
    assert advapi32.events[-1] == "no-token"


@pytest.mark.parametrize(
    ("advapi32", "expected"),
    [
        (
            _FakeLaunchAdvapi32(revert_result=False),
            ProviderLaunchIdentityUncertain,
        ),
        (
            _FakeLaunchAdvapi32(service_post_verification_error=6),
            ProviderServiceIdentityUncertain,
        ),
    ],
)
def test_authenticated_client_profile_path_discards_result_when_identity_uncertain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    advapi32: _FakeLaunchAdvapi32,
    expected: type[BaseException],
) -> None:
    kernel32 = _FakeLaunchKernel32()
    profile = tmp_path / "Founder"
    profile.mkdir()
    monkeypatch.setattr(restricted_process_module, "_advapi32", lambda: advapi32)
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(
        restricted_process_module, "require_impersonation_level", lambda token: 2
    )

    with pytest.raises(expected):
        authenticated_client_profile_path(84, str(profile))


def test_environment_error_five_reports_stage_and_does_not_destroy_null_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    userenv = _FakeUserenv(succeeds=False)
    monkeypatch.setattr(restricted_process_module, "_userenv", lambda: userenv)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5)

    with pytest.raises(PermissionError) as caught:
        token_environment(84)

    message = str(caught.value)
    assert "api=CreateEnvironmentBlock" in message
    assert "token_type=primary" in message
    assert "required_access=TOKEN_QUERY|TOKEN_DUPLICATE" in message
    assert "win32_error=5" in message
    assert "symbolic=ERROR_ACCESS_DENIED" in message
    assert userenv.destroyed == []


def test_handle_allowlist_retains_backing_array_through_process_creation_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _AttributeApi:
        def __init__(self) -> None:
            self.initialized = 0
            self.observed_size = 0

        def InitializeProcThreadAttributeList(
            self, pointer: object, count: int, flags: int, size: object
        ) -> bool:
            del count, flags
            if pointer is None:
                size._obj.value = 128  # type: ignore[attr-defined]
                return False
            self.initialized += 1
            return True

        def UpdateProcThreadAttribute(
            self,
            pointer: object,
            flags: int,
            attribute: int,
            values: object,
            size: int,
            previous: object,
            returned: object,
        ) -> bool:
            del pointer, flags, attribute, values, previous, returned
            self.observed_size = size
            return True

        def DeleteProcThreadAttributeList(self, pointer: object) -> None:
            del pointer

    api = _AttributeApi()
    monkeypatch.setattr(restricted_process_module, "_kernel32", lambda: api)
    for _ in range(250):
        buffer, pointer, backing = restricted_process_module._handle_allowlist(
            [101, 102, 103]
        )
        assert len(buffer) == 128
        assert pointer != 0
        assert [int(value) for value in backing] == [101, 102, 103]
        assert api.observed_size == ctypes.sizeof(backing)
    assert api.initialized == 250


@pytest.mark.skipif(os.name != "nt", reason="Windows security-token test")
def test_provider_starts_suspended_restricted_low_and_job_confined(
    tmp_path: Path,
) -> None:
    stdout = tmp_path / "stdout.log"
    stderr = tmp_path / "stderr.log"
    executable = Path(
        os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "PATHEXT"}
    }
    try:
        with restricted_current_process_token() as token:
            result = run_restricted_process(
                token,
                [str(executable), "/d", "/c", "echo restricted-ok"],
                executable,
                tmp_path,
                environment,
                stdout,
                stderr,
                10,
            )
    except PermissionError as error:
        if "failed: 87" in str(error):
            pytest.skip(
                "the managed test sandbox rejects restricted-token derivation"
            )
        if "restricted provider creation failed: 1314" in str(error):
            pytest.skip(
                "the unelevated test host lacks CreateProcessAsUser privilege"
            )
        raise

    if (
        result.exit_code == 0xC0000022
        and os.environ.get("USERNAME") == "CodexSandboxOffline"
    ):
        pytest.skip(
            "the managed sandbox temp directory does not grant the "
            "desktop user/restricted Users token access"
        )
    assert result.exit_code == 0
    assert result.stdout.strip() == "restricted-ok"
    assert result.stderr == ""
    assert result.restricted is True
    assert result.integrity_level == "low"
    assert result.job_confined is True
    assert result.timed_out is False


@pytest.mark.skipif(os.name != "nt", reason="Windows security-token test")
def test_profile_provider_retains_exact_user_session_but_not_api_keys(
    tmp_path: Path,
) -> None:
    executable = Path(sys.executable)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {
            "SYSTEMROOT",
            "WINDIR",
            "PATH",
            "TEMP",
            "TMP",
            "PATHEXT",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
        }
    }
    environment.pop("OPENAI_API_KEY", None)
    environment.pop("CODEX_API_KEY", None)
    try:
        with current_process_token() as source_token:
            with authenticated_profile_primary_token(source_token) as profile_token:
                source_sid = token_user_sid_string(profile_token)
                source_session = token_session_id(profile_token)
                source_environment = token_environment(profile_token)
                assert source_sid.startswith("S-1-")
                assert source_session >= 0
                assert source_environment.get("USERPROFILE")
                assert windows_session_is_active(source_session).is_active
                with profile_restricted_primary_token(profile_token) as token:
                    result = run_restricted_process(
                        token,
                        [
                            str(executable),
                            "-I",
                            "-c",
                            "import os; assert 'OPENAI_API_KEY' not in os.environ; "
                            "assert 'CODEX_API_KEY' not in os.environ; "
                            "print('profile-restricted-ok')",
                        ],
                        executable,
                        tmp_path,
                        environment,
                        tmp_path / "profile-stdout.log",
                        tmp_path / "profile-stderr.log",
                        10,
                        integrity_level="medium",
                    )
    except PermissionError as error:
        if "failed: 87" in str(error):
            pytest.skip(
                "the managed test sandbox rejects restricted-token derivation"
            )
        if "restricted provider creation failed: 1314" in str(error):
            pytest.skip(
                "the unelevated test host lacks CreateProcessAsUser privilege"
            )
        raise
    if (
        result.exit_code == 0xC0000022
        and os.environ.get("USERNAME") == "CodexSandboxOffline"
    ):
        pytest.skip(
            "the managed sandbox denies its derived user token temp access"
        )
    assert result.exit_code == 0
    assert result.stdout.strip() == "profile-restricted-ok"
    assert result.restricted is True
    assert result.integrity_level == "medium"
    assert result.job_confined is True


def test_jsonl_exchange_validates_closed_request_identity() -> None:
    validated = restricted_process_module._validated_jsonl_exchange(
        _synthetic_jsonl_exchange()
    )
    assert validated is not None
    assert [response_id for _, response_id in validated] == [1, None, 2]
    with pytest.raises(ValueError, match="entry identity"):
        restricted_process_module._validated_jsonl_exchange(
            ((json.dumps({"method": "read", "id": 8}), 7),)
        )
    with pytest.raises(ValueError, match="entry is invalid"):
        restricted_process_module._validated_jsonl_exchange(
            ((json.dumps({"method": "read", "id": 1}), 1),) * 2
        )


def test_jsonl_pipe_ownership_transfer_prevents_reused_descriptor_close() -> None:
    first_read, first_write = os.pipe()
    owner_descriptors = [first_read, first_write]
    worker = threading.Thread(
        target=lambda: (os.close(first_read), os.close(first_write))
    )

    restricted_process_module._transfer_jsonl_pipe_ownership(
        owner_descriptors,
        (first_read, first_write),
        worker,
    )
    worker.join(timeout=10)
    assert not worker.is_alive()
    assert owner_descriptors == []

    reused_read, reused_write = os.pipe()
    try:
        for descriptor in owner_descriptors:
            os.close(descriptor)
        os.write(reused_write, b"safe")
        assert os.read(reused_read, 4) == b"safe"
    finally:
        os.close(reused_read)
        os.close(reused_write)


def test_jsonl_pipe_ownership_transfer_closes_on_start_failure() -> None:
    first_read, first_write = os.pipe()
    owner_descriptors = [first_read, first_write]

    class FailingWorker:
        @staticmethod
        def start() -> None:
            raise RuntimeError("synthetic worker start failure")

    with pytest.raises(RuntimeError, match="synthetic worker start failure"):
        restricted_process_module._transfer_jsonl_pipe_ownership(
            owner_descriptors,
            (first_read, first_write),
            FailingWorker(),  # type: ignore[arg-type]
        )
    assert owner_descriptors == []
    for descriptor in (first_read, first_write):
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_jsonl_exchange_is_sequential_and_persists_complete_output(
    tmp_path: Path,
) -> None:
    server_stdin, client_stdin = os.pipe()
    client_stdout, server_stdout = os.pipe()
    observed: list[int | None] = []

    def server() -> None:
        with os.fdopen(server_stdin, "rb", buffering=0) as incoming:
            with os.fdopen(server_stdout, "wb", buffering=0) as outgoing:
                while line := incoming.readline():
                    request = json.loads(line)
                    identifier = request.get("id")
                    observed.append(identifier)
                    if identifier is None:
                        continue
                    if identifier == 2:
                        outgoing.write(
                            json.dumps(
                                {"method": "account/updated", "params": {}}
                            ).encode("utf-8")
                            + b"\n"
                        )
                    outgoing.write(
                        json.dumps(
                            {"id": identifier, "result": {"ok": True}}
                        ).encode("utf-8")
                        + b"\n"
                    )

    thread = threading.Thread(target=server)
    thread.start()
    errors: queue.Queue[BaseException] = queue.Queue(maxsize=1)
    validated = restricted_process_module._validated_jsonl_exchange(
        _synthetic_jsonl_exchange()
    )
    assert validated is not None
    restricted_process_module._run_jsonl_exchange(
        client_stdin,
        client_stdout,
        tmp_path / "stdout.jsonl",
        validated,
        65_536,
        errors,
    )
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert errors.empty()
    assert observed == [1, None, 2]
    for descriptor in (client_stdin, client_stdout):
        with pytest.raises(OSError):
            os.fstat(descriptor)
    lines = (tmp_path / "stdout.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line).get("id") for line in lines] == [1, None, 2]


@pytest.mark.parametrize(
    "response",
    (
        b'{"id":2,"result":{}}\n',
        b'{"id":1,"result":{}}\n{"id":1,"result":{}}\n',
        b"not-json\n",
        b"",
        b'{"id":1,"padding":"' + (b"x" * 70_000) + b'"}\n',
    ),
    ids=("out-of-order", "duplicate", "malformed", "missing", "oversized"),
)
def test_jsonl_exchange_rejects_invalid_response_stream(
    tmp_path: Path, response: bytes
) -> None:
    server_stdin, client_stdin = os.pipe()
    client_stdout, server_stdout = os.pipe()

    def server() -> None:
        with os.fdopen(server_stdin, "rb", buffering=0) as incoming:
            with os.fdopen(server_stdout, "wb", buffering=0) as outgoing:
                assert incoming.readline()
                outgoing.write(response)

    thread = threading.Thread(target=server)
    thread.start()
    errors: queue.Queue[BaseException] = queue.Queue(maxsize=1)
    validated = restricted_process_module._validated_jsonl_exchange(
        ((json.dumps({"method": "initialize", "id": 1}), 1),)
    )
    assert validated is not None
    restricted_process_module._run_jsonl_exchange(
        client_stdin,
        client_stdout,
        tmp_path / "stdout.jsonl",
        validated,
        65_536,
        errors,
    )
    thread.join(timeout=10)

    assert not errors.empty()
    assert isinstance(errors.get_nowait(), PermissionError)
    for descriptor in (client_stdin, client_stdout):
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="Windows restricted-token boundary")
def test_restricted_process_jsonl_exchange_runs_under_medium_job(
    tmp_path: Path,
) -> None:
    code = """import json,sys
for line in sys.stdin:
 value=json.loads(line)
 if 'id' in value:
  print(json.dumps({'id':value['id'],'result':{'ok':True}}),flush=True)
"""
    allowed = {
        "APPDATA",
        "LOCALAPPDATA",
        "PATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in allowed
    }
    with current_process_token() as token:
        with profile_restricted_primary_token(token) as restricted:
            result = run_restricted_process(
                restricted,
                [sys.executable, "-I", "-c", code],
                Path(sys.executable),
                tmp_path,
                environment,
                tmp_path / "stdout.jsonl",
                tmp_path / "stderr.txt",
                30,
                cancel_requested=threading.Event(),
                integrity_level="medium",
                active_process_limit=4,
                memory_bytes=512 * 1024 * 1024,
                stdout_bytes=65_536,
                stderr_bytes=65_536,
                jsonl_exchange=_synthetic_jsonl_exchange(),
            )

    assert result.exit_code == 0
    assert result.timed_out is False
    assert result.restricted is True
    assert result.integrity_level == "medium"
    assert result.job_confined is True
    assert [json.loads(line)["id"] for line in result.stdout.splitlines()] == [1, 2]
