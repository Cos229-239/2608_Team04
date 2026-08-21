from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from ctypes import wintypes

import pytest

from keeper.authority_service import process_security
from keeper.authority_service import host_process_policy
from keeper.authority_service.process_security import (
    PROCESS_QUERY_LIMITED_INFORMATION,
    ProcessAce,
    ProcessSecurityError,
    ProcessSecuritySnapshot,
    ProcessSecurityStage,
)


SERVICE_SID = "S-1-5-80-1-2-3-4-5"
HOST_USER_SID = "S-1-5-21-1000-1001-1002-1003"
RESTRICTED_CODE_SID = "S-1-5-12"
SYSTEM = ProcessAce("allow", "S-1-5-18", 0x1FFFFF, 0)
ADMINISTRATORS = ProcessAce("allow", "S-1-5-32-544", 0x1FFFFF, 0)
INHERITED_USER = ProcessAce("allow", HOST_USER_SID, 0x1000, 0x10)


def _snapshot(*aces: ProcessAce) -> ProcessSecuritySnapshot:
    return ProcessSecuritySnapshot(
        owner_sid="S-1-5-18",
        group_sid="S-1-5-18",
        control=0x8004,
        revision=1,
        dacl_defaulted=False,
        aces=tuple(aces),
    )


def _install_snapshot_fakes(
    monkeypatch: pytest.MonkeyPatch,
    snapshots: list[ProcessSecuritySnapshot],
) -> list[tuple[ProcessAce, ...]]:
    writes: list[tuple[ProcessAce, ...]] = []

    @contextmanager
    def handle(access: int) -> Iterator[wintypes.HANDLE]:
        assert access == 0x00060000
        yield wintypes.HANDLE(41)

    monkeypatch.setattr(
        process_security,
        "require_current_restricted_service_identity",
        lambda expected: SERVICE_SID if expected == SERVICE_SID else None,
    )
    monkeypatch.setattr(
        host_process_policy,
        "require_current_restricted_service_identity",
        lambda expected: SERVICE_SID if expected == SERVICE_SID else None,
    )
    monkeypatch.setattr(process_security, "_current_process_security_handle", handle)
    monkeypatch.setattr(
        process_security,
        "read_current_process_security",
        lambda observed=None: snapshots.pop(0),
    )
    monkeypatch.setattr(
        process_security,
        "_write_current_process_dacl",
        lambda aces, handle=None: writes.append(aces),
    )
    return writes


def test_exact_query_grant_is_only_delta_and_precedes_inherited_aces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _snapshot(SYSTEM, ADMINISTRATORS, INHERITED_USER)
    required = ProcessAce(
        "allow", SERVICE_SID, PROCESS_QUERY_LIMITED_INFORMATION, 0
    )
    after = replace(
        before,
        aces=(SYSTEM, ADMINISTRATORS, required, INHERITED_USER),
    )
    writes = _install_snapshot_fakes(monkeypatch, [before, after])

    assert (
        process_security.ensure_current_process_service_query_access(SERVICE_SID)
        == after
    )
    assert writes == [after.aces]


def test_exact_existing_query_grant_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    required = ProcessAce(
        "allow", SERVICE_SID, PROCESS_QUERY_LIMITED_INFORMATION, 0
    )
    before = _snapshot(SYSTEM, required, ADMINISTRATORS)
    writes = _install_snapshot_fakes(monkeypatch, [before])

    assert (
        process_security.ensure_current_process_service_query_access(SERVICE_SID)
        == before
    )
    assert writes == []


def test_exact_host_user_query_grant_is_only_delta(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _snapshot(SYSTEM, ADMINISTRATORS)
    restricted_deny = ProcessAce(
        "deny", RESTRICTED_CODE_SID, PROCESS_QUERY_LIMITED_INFORMATION, 0
    )
    host_allow = ProcessAce(
        "allow", HOST_USER_SID, PROCESS_QUERY_LIMITED_INFORMATION, 0
    )
    after = replace(
        before,
        aces=(restricted_deny,) + before.aces + (host_allow,),
    )
    writes = _install_snapshot_fakes(monkeypatch, [before, after])

    assert host_process_policy.ensure_current_process_host_query_access(
        HOST_USER_SID, service_sid=SERVICE_SID
    ) == after
    assert writes == [after.aces]


def test_exact_host_user_query_policy_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    restricted_deny = ProcessAce(
        "deny", RESTRICTED_CODE_SID, PROCESS_QUERY_LIMITED_INFORMATION, 0
    )
    host_allow = ProcessAce(
        "allow", HOST_USER_SID, PROCESS_QUERY_LIMITED_INFORMATION, 0
    )
    before = _snapshot(restricted_deny, SYSTEM, ADMINISTRATORS, host_allow)
    writes = _install_snapshot_fakes(monkeypatch, [before])

    assert host_process_policy.ensure_current_process_host_query_access(
        HOST_USER_SID, service_sid=SERVICE_SID
    ) == before
    assert writes == []


@pytest.mark.parametrize(
    "mutation",
    ["owner", "group", "control", "revision", "defaulted", "unexpected-ace"],
)
def test_host_query_policy_requires_exact_readback(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    before = _snapshot(SYSTEM, ADMINISTRATORS)
    restricted_deny = ProcessAce(
        "deny", RESTRICTED_CODE_SID, PROCESS_QUERY_LIMITED_INFORMATION, 0
    )
    host_allow = ProcessAce(
        "allow", HOST_USER_SID, PROCESS_QUERY_LIMITED_INFORMATION, 0
    )
    expected = replace(
        before,
        aces=(restricted_deny,) + before.aces + (host_allow,),
    )
    after = expected
    if mutation == "owner":
        after = replace(after, owner_sid="S-1-5-32-544")
    elif mutation == "group":
        after = replace(after, group_sid="S-1-5-32-544")
    elif mutation == "control":
        after = replace(after, control=after.control ^ 0x1000)
    elif mutation == "revision":
        after = replace(after, revision=2)
    elif mutation == "defaulted":
        after = replace(after, dacl_defaulted=True)
    else:
        after = replace(
            after,
            aces=after.aces
            + (ProcessAce("allow", "S-1-5-32-545", 0x1000, 0),),
        )
    writes = _install_snapshot_fakes(monkeypatch, [before, after])

    with pytest.raises(ProcessSecurityError, match="did not verify exactly"):
        host_process_policy.ensure_current_process_host_query_access(
            HOST_USER_SID, service_sid=SERVICE_SID
        )

    assert writes == [expected.aces]


@pytest.mark.parametrize(
    ("restricted_aces", "host_aces"),
    [
        ((), (ProcessAce("allow", HOST_USER_SID, 0x1000, 0),)),
        ((ProcessAce("deny", RESTRICTED_CODE_SID, 0x1000, 0),), ()),
        ((ProcessAce("deny", RESTRICTED_CODE_SID, 0x101000, 0),), ()),
        ((), (ProcessAce("allow", HOST_USER_SID, 0x101000, 0),)),
        ((ProcessAce("allow", RESTRICTED_CODE_SID, 0x1000, 0),), ()),
        (
            (
                ProcessAce("deny", RESTRICTED_CODE_SID, 0x1000, 0),
                ProcessAce("deny", RESTRICTED_CODE_SID, 0x1000, 0),
            ),
            (ProcessAce("allow", HOST_USER_SID, 0x1000, 0),),
        ),
        (
            (ProcessAce("deny", RESTRICTED_CODE_SID, 0x1000, 0),),
            (
                ProcessAce("allow", HOST_USER_SID, 0x1000, 0),
                ProcessAce("allow", HOST_USER_SID, 0x1000, 0),
            ),
        ),
        (
            (ProcessAce("deny", RESTRICTED_CODE_SID, 0x1000, 0x10),),
            (ProcessAce("allow", HOST_USER_SID, 0x1000, 0),),
        ),
        (
            (ProcessAce("deny", RESTRICTED_CODE_SID, 0x1000, 0),),
            (ProcessAce("allow", HOST_USER_SID, 0x1000, 0x10),),
        ),
    ],
)
def test_incomplete_or_broad_host_query_policy_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    restricted_aces: tuple[ProcessAce, ...],
    host_aces: tuple[ProcessAce, ...],
) -> None:
    before = _snapshot(*restricted_aces, SYSTEM, ADMINISTRATORS, *host_aces)
    writes = _install_snapshot_fakes(monkeypatch, [before])

    with pytest.raises(ProcessSecurityError):
        host_process_policy.ensure_current_process_host_query_access(
            HOST_USER_SID, service_sid=SERVICE_SID
        )

    assert writes == []


@pytest.mark.parametrize(
    "sid",
    ["S-1-5-18", "S-1-5-12", SERVICE_SID, "not-a-sid"],
)
def test_invalid_host_user_query_principal_rejects_before_write(
    monkeypatch: pytest.MonkeyPatch, sid: str
) -> None:
    writes = _install_snapshot_fakes(monkeypatch, [])

    with pytest.raises(ProcessSecurityError, match="Host user SID is invalid"):
        host_process_policy.ensure_current_process_host_query_access(
            sid, service_sid=SERVICE_SID
        )

    assert writes == []


@pytest.mark.parametrize(
    "existing",
    [
        ProcessAce("allow", SERVICE_SID, 0x101000, 0),
        ProcessAce("allow", SERVICE_SID, 0x1000, 0x10),
        ProcessAce("deny", SERVICE_SID, 0x1000, 0),
    ],
)
def test_existing_broad_inherited_or_denied_service_grant_fails_closed(
    monkeypatch: pytest.MonkeyPatch, existing: ProcessAce
) -> None:
    before = _snapshot(SYSTEM, existing, ADMINISTRATORS)
    writes = _install_snapshot_fakes(monkeypatch, [before])

    with pytest.raises(PermissionError, match="ambiguous or broad"):
        process_security.ensure_current_process_service_query_access(SERVICE_SID)

    assert writes == []


def test_duplicate_service_grants_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    required = ProcessAce(
        "allow", SERVICE_SID, PROCESS_QUERY_LIMITED_INFORMATION, 0
    )
    before = _snapshot(SYSTEM, required, required)
    writes = _install_snapshot_fakes(monkeypatch, [before])

    with pytest.raises(PermissionError, match="ambiguous or broad"):
        process_security.ensure_current_process_service_query_access(SERVICE_SID)

    assert writes == []


def test_noncanonical_existing_dacl_fails_before_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _snapshot(ADMINISTRATORS, ProcessAce("deny", "S-1-5-12", 0x1000, 0))
    writes = _install_snapshot_fakes(monkeypatch, [before])

    with pytest.raises(PermissionError, match="ordering is not canonical"):
        process_security.ensure_current_process_service_query_access(SERVICE_SID)

    assert writes == []


@pytest.mark.parametrize(
    "mutation",
    ["owner", "group", "control", "revision", "defaulted", "extra-right"],
)
def test_readback_requires_exact_descriptor_delta(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    before = _snapshot(SYSTEM, ADMINISTRATORS)
    required = ProcessAce(
        "allow", SERVICE_SID, PROCESS_QUERY_LIMITED_INFORMATION, 0
    )
    after = replace(before, aces=before.aces + (required,))
    if mutation == "owner":
        after = replace(after, owner_sid="S-1-5-32-544")
    elif mutation == "group":
        after = replace(after, group_sid="S-1-5-32-544")
    elif mutation == "control":
        after = replace(after, control=after.control ^ 0x1000)
    elif mutation == "revision":
        after = replace(after, revision=2)
    elif mutation == "defaulted":
        after = replace(after, dacl_defaulted=True)
    else:
        after = replace(
            after,
            aces=before.aces
            + (ProcessAce("allow", SERVICE_SID, 0x101000, 0),),
        )
    writes = _install_snapshot_fakes(monkeypatch, [before, after])

    with pytest.raises(PermissionError, match="did not verify exactly"):
        process_security.ensure_current_process_service_query_access(SERVICE_SID)

    assert len(writes) == 1


def test_mismatched_or_invalid_service_identity_fails_before_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(expected: str) -> str:
        del expected
        raise PermissionError("virtual-service identity differs")

    monkeypatch.setattr(
        process_security,
        "require_current_restricted_service_identity",
        reject,
    )
    with pytest.raises(PermissionError, match="security identity differs"):
        process_security.ensure_current_process_service_query_access(SERVICE_SID)
    with pytest.raises(PermissionError, match="service SID is invalid"):
        process_security.ensure_current_process_service_query_access("S-1-5-18")


def test_shared_process_delta_rejects_unknown_security_subject() -> None:
    with pytest.raises(ProcessSecurityError) as captured:
        process_security._ensure_current_process_sid_query_access(
            SERVICE_SID,
            subject="untrusted caller",
        )

    assert captured.value.stage is ProcessSecurityStage.VALIDATE_IDENTITY


def test_host_token_query_grant_is_exact_and_uses_token_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _snapshot(SYSTEM, ADMINISTRATORS, INHERITED_USER)
    required = ProcessAce("allow", SERVICE_SID, process_security.TOKEN_QUERY, 0)
    after = replace(
        before,
        aces=(SYSTEM, ADMINISTRATORS, required, INHERITED_USER),
    )
    writes: list[tuple[ProcessAce, ...]] = []

    @contextmanager
    def token_handle(access: int) -> Iterator[wintypes.HANDLE]:
        assert access == 0x00060000
        yield wintypes.HANDLE(83)

    monkeypatch.setattr(
        process_security, "_current_process_token_security_handle", token_handle
    )
    monkeypatch.setattr(
        process_security,
        "read_current_process_security",
        lambda handle=None: before if not writes else after,
    )
    monkeypatch.setattr(
        process_security,
        "_write_current_process_dacl",
        lambda aces, handle=None: writes.append(aces),
    )

    assert process_security._ensure_current_process_token_sid_query_access(
        SERVICE_SID, subject="Provider Host"
    ) == after
    assert writes == [after.aces]


@pytest.mark.parametrize(
    "existing",
    [
        ProcessAce("allow", SERVICE_SID, 0x000A, 0),
        ProcessAce("allow", SERVICE_SID, process_security.TOKEN_QUERY, 0x10),
        ProcessAce("deny", SERVICE_SID, process_security.TOKEN_QUERY, 0),
    ],
)
def test_host_token_broad_inherited_or_denied_grant_fails_closed(
    monkeypatch: pytest.MonkeyPatch, existing: ProcessAce
) -> None:
    @contextmanager
    def token_handle(access: int) -> Iterator[wintypes.HANDLE]:
        assert access == 0x00060000
        yield wintypes.HANDLE(83)

    monkeypatch.setattr(
        process_security, "_current_process_token_security_handle", token_handle
    )
    monkeypatch.setattr(
        process_security,
        "read_current_process_security",
        lambda handle=None: _snapshot(SYSTEM, existing, ADMINISTRATORS),
    )
    monkeypatch.setattr(
        process_security,
        "_write_current_process_dacl",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("token DACL must not be written")
        ),
    )

    with pytest.raises(ProcessSecurityError, match="ambiguous or broad"):
        process_security._ensure_current_process_token_sid_query_access(
            SERVICE_SID, subject="Provider Host"
        )


def test_self_handle_is_duplicated_with_only_security_descriptor_rights(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int, int, int, bool, int]] = []
    closed: list[int] = []

    class Kernel:
        def GetCurrentProcess(self) -> int:
            return -1

        def DuplicateHandle(
            self,
            source_process: int,
            source_handle: int,
            target_process: int,
            target: object,
            desired_access: int,
            inheritable: bool,
            options: int,
        ) -> bool:
            calls.append(
                (
                    source_process,
                    source_handle,
                    target_process,
                    desired_access,
                    inheritable,
                    options,
                )
            )
            target._obj.value = 73  # type: ignore[attr-defined]
            return True

        def CloseHandle(self, handle: wintypes.HANDLE) -> bool:
            closed.append(int(handle.value or 0))
            return True

    monkeypatch.setattr(process_security, "_kernel32", lambda: Kernel())

    with process_security._current_process_security_handle(0x00060000) as handle:
        assert handle.value == 73

    assert calls == [(-1, -1, -1, 0x00060000, False, 0)]
    assert closed == [73]


@pytest.mark.parametrize("failure", ["duplicate", "close"])
def test_self_handle_failure_is_stage_bound_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    class Kernel:
        def GetCurrentProcess(self) -> int:
            return -1

        def DuplicateHandle(self, *arguments: object) -> bool:
            if failure == "duplicate":
                return False
            arguments[3]._obj.value = 91  # type: ignore[attr-defined]
            return True

        def CloseHandle(self, handle: wintypes.HANDLE) -> bool:
            del handle
            return failure != "close"

    monkeypatch.setattr(process_security, "_kernel32", lambda: Kernel())

    expected = (
        ProcessSecurityStage.DUPLICATE_SELF_HANDLE
        if failure == "duplicate"
        else ProcessSecurityStage.CLOSE_SELF_HANDLE
    )
    with pytest.raises(ProcessSecurityError) as captured:
        with process_security._current_process_security_handle(0x00060000):
            pass
    assert captured.value.stage is expected


@pytest.mark.parametrize("failure", ["open", "close"])
def test_token_security_handle_failure_is_stage_bound_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    class Kernel:
        def GetCurrentProcess(self) -> int:
            return -1

        def CloseHandle(self, handle: wintypes.HANDLE) -> bool:
            assert int(handle.value or 0) == 92
            return failure != "close"

    class Advapi:
        def OpenProcessToken(
            self, process: int, access: int, target: object
        ) -> bool:
            assert process == -1
            assert access == 0x00060000
            if failure == "open":
                return False
            target._obj.value = 92  # type: ignore[attr-defined]
            return True

    monkeypatch.setattr(process_security, "_kernel32", lambda: Kernel())
    monkeypatch.setattr(process_security, "_advapi32", lambda: Advapi())

    expected = (
        ProcessSecurityStage.DUPLICATE_SELF_HANDLE
        if failure == "open"
        else ProcessSecurityStage.CLOSE_SELF_HANDLE
    )
    with pytest.raises(ProcessSecurityError) as captured:
        with process_security._current_process_token_security_handle(0x00060000):
            pass
    assert captured.value.stage is expected


@pytest.mark.skipif(os.name != "nt", reason="Windows security API binding only")
def test_kernel_object_security_apis_have_explicit_windows_bindings() -> None:
    api = process_security._advapi32()

    assert api.GetKernelObjectSecurity.argtypes is not None
    assert len(api.GetKernelObjectSecurity.argtypes) == 5
    assert api.GetKernelObjectSecurity.restype is wintypes.BOOL
    assert api.SetKernelObjectSecurity.argtypes is not None
    assert len(api.SetKernelObjectSecurity.argtypes) == 3
    assert api.SetKernelObjectSecurity.restype is wintypes.BOOL
    assert api.OpenProcessToken.argtypes is not None
    assert len(api.OpenProcessToken.argtypes) == 3
    assert api.OpenProcessToken.restype is wintypes.BOOL
    assert api.GetSecurityDescriptorOwner.argtypes is not None
    assert api.GetSecurityDescriptorGroup.argtypes is not None


@pytest.mark.parametrize(
    "ace",
    [
        ProcessAce("audit", "S-1-5-18", 0x1000, 0),
        ProcessAce("allow", "not-a-sid", 0x1000, 0),
        ProcessAce("allow", "S-1-5-18", 0, 0),
        ProcessAce("allow", "S-1-5-18", 0x1_0000_0000, 0),
        ProcessAce("allow", "S-1-5-18", 0x1000, 0x20),
    ],
)
def test_invalid_or_unsupported_ace_cannot_be_serialized(
    ace: ProcessAce,
) -> None:
    with pytest.raises(ProcessSecurityError) as captured:
        process_security._ace_sddl(ace)

    assert captured.value.stage is ProcessSecurityStage.BUILD_DACL


@pytest.mark.skipif(os.name != "nt", reason="Windows restricted token only")
def test_real_restricted_service_context_can_apply_exact_self_grant() -> None:
    code = r"""
import ctypes
import json
from ctypes import wintypes
import keeper.authority_service.host_process_policy as h
import keeper.authority_service.process_security as p
from keeper.authority_service.provider_identity import account_sid

k = ctypes.WinDLL('kernel32', use_last_error=True)
a = ctypes.WinDLL('advapi32', use_last_error=True)
k.GetCurrentProcess.restype = wintypes.HANDLE
k.CloseHandle.argtypes = [wintypes.HANDLE]
k.CloseHandle.restype = wintypes.BOOL
k.LocalFree.argtypes = [wintypes.HLOCAL]
k.LocalFree.restype = wintypes.HLOCAL
a.OpenProcessToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
]
a.OpenProcessToken.restype = wintypes.BOOL
a.ConvertStringSidToSidW.argtypes = [
    wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)
]
a.ConvertStringSidToSidW.restype = wintypes.BOOL
a.CreateRestrictedToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID,
    ctypes.POINTER(wintypes.HANDLE),
]
a.CreateRestrictedToken.restype = wintypes.BOOL
a.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
a.ImpersonateLoggedOnUser.restype = wintypes.BOOL
a.RevertToSelf.restype = wintypes.BOOL

class SidAndAttributes(ctypes.Structure):
    _fields_ = [('Sid', wintypes.LPVOID), ('Attributes', wintypes.DWORD)]

service_sid = account_sid(r'NT SERVICE\KeeperAuthority')
base = wintypes.HANDLE()
sid_pointer = wintypes.LPVOID()
restricted = wintypes.HANDLE()
assert a.OpenProcessToken(k.GetCurrentProcess(), 0x000F01FF, ctypes.byref(base))
assert a.ConvertStringSidToSidW(service_sid, ctypes.byref(sid_pointer))
entry = SidAndAttributes(sid_pointer, 0)
assert a.CreateRestrictedToken(
    base, 1, 0, None, 0, None, 1, ctypes.byref(entry),
    ctypes.byref(restricted),
)
p.require_current_restricted_service_identity = lambda value: value
try:
    assert a.ImpersonateLoggedOnUser(restricted)
    snapshot = p.ensure_current_process_service_query_access(service_sid)
    assert a.RevertToSelf()
finally:
    k.LocalFree(sid_pointer)
    k.CloseHandle(restricted)
    k.CloseHandle(base)
matches = [
    [ace.ace_type, ace.rights_mask, ace.flags]
    for ace in snapshot.aces
    if ace.trustee_sid.casefold() == service_sid.casefold()
]
print(json.dumps({'matches': matches, 'reverted': True}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.getcwd(),
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "matches": [["allow", PROCESS_QUERY_LIMITED_INFORMATION, 0]],
        "reverted": True,
    }


@pytest.mark.skipif(os.name != "nt", reason="Windows process DACL only")
def test_real_disposable_process_dacl_adds_only_query_and_is_idempotent() -> None:
    code = r"""
import ctypes
import json
import os
from ctypes import wintypes
import keeper.authority_service.host_process_policy as h
import keeper.authority_service.process_security as p
from keeper.authority_service.provider_identity import account_sid
import keeper.authority_service.windows_identity as w
p.require_current_restricted_service_identity = lambda value: value
sid = account_sid(r'NT SERVICE\KeeperAuthority')
before = p.read_current_process_security()
after = p.ensure_current_process_service_query_access(sid)
again = p.ensure_current_process_service_query_access(sid)
k = ctypes.WinDLL('kernel32', use_last_error=True)
a = ctypes.WinDLL('advapi32', use_last_error=True)
k.GetCurrentProcess.restype = wintypes.HANDLE
k.GetCurrentThread.restype = wintypes.HANDLE
k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k.OpenProcess.restype = wintypes.HANDLE
a.OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
a.OpenProcessToken.restype = wintypes.BOOL
a.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
a.ConvertStringSidToSidW.restype = wintypes.BOOL
a.CreateRestrictedToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.HANDLE),
]
a.CreateRestrictedToken.restype = wintypes.BOOL
a.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
a.ImpersonateLoggedOnUser.restype = wintypes.BOOL
a.RevertToSelf.restype = wintypes.BOOL
class SidAndAttributes(ctypes.Structure):
    _fields_ = [('Sid', wintypes.LPVOID), ('Attributes', wintypes.DWORD)]
def attempt(restricting_sid):
    base = wintypes.HANDLE()
    assert a.OpenProcessToken(k.GetCurrentProcess(), 0x000F01FF, ctypes.byref(base))
    sid_pointer = wintypes.LPVOID()
    assert a.ConvertStringSidToSidW(restricting_sid, ctypes.byref(sid_pointer))
    entry = SidAndAttributes(sid_pointer, 0)
    token = wintypes.HANDLE()
    assert a.CreateRestrictedToken(
        base, 1, 0, None, 0, None, 1, ctypes.byref(entry), ctypes.byref(token)
    )
    try:
        assert a.ImpersonateLoggedOnUser(token)
        handle = k.OpenProcess(0x1000, False, os.getpid())
        error = ctypes.get_last_error()
        measured = False
        if handle:
            session = wintypes.DWORD()
            assert k.ProcessIdToSessionId(os.getpid(), ctypes.byref(session))
            identity = w._build_named_pipe_peer_identity(
                process_id=os.getpid(),
                direct_session=int(session.value),
                process=int(handle),
                token_sid=restricting_sid,
                token_session=int(session.value),
                computer_name='.',
            )
            measured = (
                identity.process_id == os.getpid()
                and identity.sid.casefold() == restricting_sid.casefold()
                and bool(identity.executable_path)
                and identity.process_creation_time_100ns > 0
            )
            k.CloseHandle(handle)
        assert a.RevertToSelf()
        return [bool(handle), error, measured]
    finally:
        k.LocalFree(sid_pointer)
        k.CloseHandle(token)
        k.CloseHandle(base)
matches = [
    [ace.ace_type, ace.rights_mask, ace.flags]
    for ace in after.aces
    if ace.trustee_sid.casefold() == sid.casefold()
]
print(json.dumps({
    'delta': len(after.aces) - len(before.aces),
    'idempotent': after == again,
    'matches': matches,
    'owner_preserved': before.owner_sid == after.owner_sid,
    'group_preserved': before.group_sid == after.group_sid,
    'control_preserved': before.control == after.control,
    'service_restricted_measurement': attempt(sid),
    'restricted_code_open': attempt('S-1-5-12'),
}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.getcwd(),
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "delta": 1,
        "idempotent": True,
        "matches": [["allow", 0x1000, 0]],
        "owner_preserved": True,
        "group_preserved": True,
        "control_preserved": True,
        "service_restricted_measurement": [True, 0, True],
        "restricted_code_open": [False, 5, False],
    }


@pytest.mark.skipif(os.name != "nt", reason="Windows process-token DACL only")
def test_real_host_grants_service_query_only_on_process_and_token() -> None:
    code = r"""
import ctypes
import json
import os
from ctypes import wintypes
import keeper.authority_service.process_security as p
from keeper.authority_service.provider_identity import account_sid

sid = account_sid(r'NT SERVICE\KeeperAuthority')
p.require_current_restricted_service_identity = lambda value: value
process_snapshot = p._ensure_current_process_sid_query_access(
    sid, subject='Provider Host'
)
token_snapshot = p._ensure_current_process_token_sid_query_access(
    sid, subject='Provider Host'
)

k = ctypes.WinDLL('kernel32', use_last_error=True)
a = ctypes.WinDLL('advapi32', use_last_error=True)
k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL,wintypes.DWORD]
k.OpenProcess.restype = wintypes.HANDLE
k.CloseHandle.argtypes = [wintypes.HANDLE]
k.CloseHandle.restype = wintypes.BOOL
k.LocalFree.argtypes = [wintypes.HLOCAL]
a.OpenProcessToken.argtypes = [wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
a.OpenProcessToken.restype = wintypes.BOOL
a.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR,ctypes.POINTER(wintypes.LPVOID)]
a.ConvertStringSidToSidW.restype = wintypes.BOOL
a.CreateRestrictedToken.argtypes = [wintypes.HANDLE,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.LPVOID,ctypes.POINTER(wintypes.HANDLE)]
a.CreateRestrictedToken.restype = wintypes.BOOL
a.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
a.ImpersonateLoggedOnUser.restype = wintypes.BOOL
a.RevertToSelf.restype = wintypes.BOOL
class SidAndAttributes(ctypes.Structure):
    _fields_ = [('Sid', wintypes.LPVOID), ('Attributes', wintypes.DWORD)]

def attempt(restricting_sid):
    base = wintypes.HANDLE()
    assert a.OpenProcessToken(k.GetCurrentProcess(), 0x000F01FF, ctypes.byref(base))
    pointer = wintypes.LPVOID()
    assert a.ConvertStringSidToSidW(restricting_sid, ctypes.byref(pointer))
    entry = SidAndAttributes(pointer, 0)
    restricted = wintypes.HANDLE()
    assert a.CreateRestrictedToken(base, 1, 0, None, 0, None, 1, ctypes.byref(entry), ctypes.byref(restricted))
    process = wintypes.HANDLE()
    token = wintypes.HANDLE()
    try:
        assert a.ImpersonateLoggedOnUser(restricted)
        process = k.OpenProcess(0x1000, False, os.getpid())
        process_error = ctypes.get_last_error()
        token_ok = False
        token_error = 0
        if process:
            token_ok = bool(a.OpenProcessToken(process, 0x0008, ctypes.byref(token)))
            token_error = ctypes.get_last_error()
        assert a.RevertToSelf()
        return [bool(process), process_error, token_ok, token_error]
    finally:
        if token: k.CloseHandle(token)
        if process: k.CloseHandle(process)
        k.LocalFree(pointer)
        k.CloseHandle(restricted)
        k.CloseHandle(base)

def matches(snapshot, rights):
    return [[ace.ace_type, ace.rights_mask, ace.flags] for ace in snapshot.aces if ace.trustee_sid.casefold() == sid.casefold() and ace.rights_mask == rights]

print(json.dumps({
    'process_grant': matches(process_snapshot, 0x1000),
    'token_grant': matches(token_snapshot, 0x0008),
    'service': attempt(sid),
    'restricted_code': attempt('S-1-5-12'),
}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.getcwd(),
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "process_grant": [["allow", 0x1000, 0]],
        "token_grant": [["allow", 0x0008, 0]],
        "service": [True, 0, True, 0],
        "restricted_code": [False, 5, False, 0],
    }


@pytest.mark.skipif(os.name != "nt", reason="Windows process DACL only")
def test_real_authority_grants_host_user_query_but_denies_restricted_code() -> None:
    code = r"""
import ctypes
import json
import os
from ctypes import wintypes
import keeper.authority_service.host_process_policy as h
import keeper.authority_service.process_security as p
from keeper.authority_service.provider_identity import account_sid

service_sid = account_sid(r'NT SERVICE\KeeperAuthority')
host_sid = 'S-1-5-21-424242-434343-444444-1001'
h.require_current_restricted_service_identity = lambda value: value
snapshot = h.ensure_current_process_host_query_access(
    host_sid, service_sid=service_sid
)

k = ctypes.WinDLL('kernel32', use_last_error=True)
a = ctypes.WinDLL('advapi32', use_last_error=True)
k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k.OpenProcess.restype = wintypes.HANDLE
k.CloseHandle.argtypes = [wintypes.HANDLE]
k.CloseHandle.restype = wintypes.BOOL
k.LocalFree.argtypes = [wintypes.HLOCAL]
a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
a.OpenProcessToken.restype = wintypes.BOOL
a.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
a.ConvertStringSidToSidW.restype = wintypes.BOOL
a.CreateRestrictedToken.argtypes = [wintypes.HANDLE,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.LPVOID,ctypes.POINTER(wintypes.HANDLE)]
a.CreateRestrictedToken.restype = wintypes.BOOL
a.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
a.ImpersonateLoggedOnUser.restype = wintypes.BOOL
a.RevertToSelf.restype = wintypes.BOOL
class SidAndAttributes(ctypes.Structure):
    _fields_ = [('Sid', wintypes.LPVOID), ('Attributes', wintypes.DWORD)]

def attempt(*restricting_sids):
    base = wintypes.HANDLE()
    assert a.OpenProcessToken(k.GetCurrentProcess(), 0x000F01FF, ctypes.byref(base))
    pointers = []
    for restricting_sid in restricting_sids:
        pointer = wintypes.LPVOID()
        assert a.ConvertStringSidToSidW(restricting_sid, ctypes.byref(pointer))
        pointers.append(pointer)
    entries = (SidAndAttributes * len(pointers))(
        *(SidAndAttributes(pointer, 0) for pointer in pointers)
    )
    restricted = wintypes.HANDLE()
    assert a.CreateRestrictedToken(base, 1, 0, None, 0, None, len(entries), entries, ctypes.byref(restricted))
    process = wintypes.HANDLE()
    try:
        assert a.ImpersonateLoggedOnUser(restricted)
        process = k.OpenProcess(0x1000, False, os.getpid())
        error = ctypes.get_last_error()
        assert a.RevertToSelf()
        return [bool(process), error]
    finally:
        if process: k.CloseHandle(process)
        for pointer in pointers:
            k.LocalFree(pointer)
        k.CloseHandle(restricted)
        k.CloseHandle(base)

host_matching = [
    [ace.ace_type, ace.rights_mask, ace.flags]
    for ace in snapshot.aces
    if ace.trustee_sid.casefold() == host_sid.casefold()
]
restricted_matching = [
    [ace.ace_type, ace.rights_mask, ace.flags]
    for ace in snapshot.aces
    if ace.trustee_sid.casefold() == 's-1-5-12'
]
print(json.dumps({
    'host_grant': host_matching,
    'restricted_deny': restricted_matching,
    'host_user_restricted': attempt(host_sid),
    'restricted_code': attempt('S-1-5-12'),
    'production_combined': attempt(host_sid, 'S-1-5-12'),
}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.getcwd(),
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "host_grant": [["allow", 0x1000, 0]],
        "restricted_deny": [["deny", 0x1000, 0]],
        "host_user_restricted": [True, 0],
        "restricted_code": [False, 5],
        "production_combined": [False, 5],
    }
