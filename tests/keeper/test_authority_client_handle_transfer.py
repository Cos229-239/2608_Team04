from __future__ import annotations

import ctypes
import hashlib
import msvcrt
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

from keeper.authority_service import client_process_policy, process_security
from keeper.authority_service.client import AuthorityServiceClient
from keeper.authority_service.process_security import (
    PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION,
    ProcessAce,
    ProcessSecuritySnapshot,
)
from keeper.authority_service.windows_identity import (
    _require_read_only_disk_handle,
)


SERVICE_SID = "S-1-5-80-1-2-3-4-5"
RESTRICTED_CODE_SID = "S-1-5-12"
TRANSFER = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE


def _snapshot(*aces: ProcessAce) -> ProcessSecuritySnapshot:
    return ProcessSecuritySnapshot(
        owner_sid="S-1-5-21-1-2-3-1001",
        group_sid="S-1-5-21-1-2-3-513",
        control=0x8004,
        revision=1,
        dacl_defaulted=False,
        aces=tuple(aces),
    )


def test_client_transfer_dacl_is_exact_closed_and_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system = ProcessAce("allow", "S-1-5-18", 0x1FFFFF, 0)
    user = ProcessAce("allow", "S-1-5-21-1-2-3-1001", 0x1FFFFF, 0)
    before = _snapshot(system, user)
    deny = ProcessAce("deny", RESTRICTED_CODE_SID, TRANSFER, 0)
    after = _snapshot(deny, system, user)
    observations = [before, after, after]
    writes: list[tuple[ProcessAce, ...]] = []

    @contextmanager
    def handle(access: int) -> Iterator[ctypes.c_void_p]:
        assert access == 0x00060000
        yield ctypes.c_void_p(41)

    monkeypatch.setattr(process_security, "_current_process_security_handle", handle)
    monkeypatch.setattr(
        process_security,
        "read_current_process_security",
        lambda value=None: observations.pop(0),
    )
    monkeypatch.setattr(
        process_security,
        "_write_current_process_dacl",
        lambda aces, handle=None: writes.append(aces),
    )

    assert (
        client_process_policy.ensure_current_process_authority_transfer_access(
            SERVICE_SID
        )
        == after
    )
    assert (
        client_process_policy.ensure_current_process_authority_transfer_access(
            SERVICE_SID
        )
        == after
    )
    assert writes == [after.aces]


def test_client_transfer_dacl_removes_exact_superseded_service_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deny = ProcessAce("deny", RESTRICTED_CODE_SID, TRANSFER, 0)
    system = ProcessAce("allow", "S-1-5-18", 0x1FFFFF, 0)
    user = ProcessAce("allow", "S-1-5-21-1-2-3-1001", 0x1FFFFF, 0)
    obsolete = ProcessAce("allow", SERVICE_SID, TRANSFER, 0)
    before = _snapshot(deny, system, user, obsolete)
    after = _snapshot(deny, system, user)
    observations = [before, after]
    writes: list[tuple[ProcessAce, ...]] = []

    @contextmanager
    def handle(access: int) -> Iterator[ctypes.c_void_p]:
        assert access == 0x00060000
        yield ctypes.c_void_p(41)

    monkeypatch.setattr(process_security, "_current_process_security_handle", handle)
    monkeypatch.setattr(
        process_security,
        "read_current_process_security",
        lambda value=None: observations.pop(0),
    )
    monkeypatch.setattr(
        process_security,
        "_write_current_process_dacl",
        lambda aces, handle=None: writes.append(aces),
    )

    assert client_process_policy.ensure_current_process_authority_transfer_access(
        SERVICE_SID
    ) == after
    assert writes == [after.aces]


@pytest.mark.parametrize(
    "aces",
    [
        (ProcessAce("allow", SERVICE_SID, 0x1FFFFF, 0),),
        (ProcessAce("allow", SERVICE_SID, TRANSFER, 0x10),),
        (ProcessAce("deny", RESTRICTED_CODE_SID, 0x1000, 0),),
        (
            ProcessAce("deny", RESTRICTED_CODE_SID, TRANSFER, 0),
            ProcessAce("allow", SERVICE_SID, TRANSFER, 0),
            ProcessAce("allow", SERVICE_SID, TRANSFER, 0),
        ),
    ],
)
def test_client_transfer_dacl_rejects_broad_or_ambiguous_existing_grants(
    monkeypatch: pytest.MonkeyPatch, aces: tuple[ProcessAce, ...]
) -> None:
    @contextmanager
    def handle(access: int) -> Iterator[ctypes.c_void_p]:
        yield ctypes.c_void_p(41)

    monkeypatch.setattr(process_security, "_current_process_security_handle", handle)
    monkeypatch.setattr(
        process_security,
        "read_current_process_security",
        lambda value=None: _snapshot(*aces),
    )
    with pytest.raises(PermissionError, match="ambiguous or broad"):
        client_process_policy.ensure_current_process_authority_transfer_access(
            SERVICE_SID
        )


def test_client_opened_handle_locks_and_measures_exact_object(tmp_path: Path) -> None:
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"locked-review-fixture")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    client = AuthorityServiceClient(test_transport=lambda request: {})
    with client.reviewed_executable_handle(executable) as handle:
        _require_read_only_disk_handle(handle)
        with pytest.raises((PermissionError, OSError)):
            executable.write_bytes(b"replacement")

    assert executable.read_bytes() == b"locked-review-fixture"
    assert digest == hashlib.sha256(executable.read_bytes()).hexdigest()


@pytest.mark.skipif(os.name != "nt", reason="Windows handle rights only")
def test_writable_and_closed_handles_reject_before_measurement(tmp_path: Path) -> None:
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"handle-rights-fixture")
    writable = os.open(executable, os.O_RDWR)
    try:
        with pytest.raises(PermissionError, match="not read-only"):
            _require_read_only_disk_handle(msvcrt.get_osfhandle(writable))
    finally:
        os.close(writable)

    closed = os.open(executable, os.O_RDONLY)
    closed_handle = msvcrt.get_osfhandle(closed)
    os.close(closed)
    with pytest.raises(PermissionError, match="not a disk file"):
        _require_read_only_disk_handle(closed_handle)


@pytest.mark.skipif(os.name != "nt", reason="Windows process DACL only")
def test_real_production_shaped_restricted_token_denies_client_dup_handle() -> None:
    code = r'''
import ctypes, json, msvcrt, os, tempfile
from ctypes import wintypes
from keeper.authority_service import client_process_policy as c
from keeper.authority_service.provider_identity import account_sid

service = account_sid(r'NT SERVICE\KeeperAuthority')
snapshot = c.ensure_current_process_authority_transfer_access(service)
k=ctypes.WinDLL('kernel32',use_last_error=True); a=ctypes.WinDLL('advapi32',use_last_error=True)
k.GetCurrentProcess.restype=wintypes.HANDLE
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.DuplicateHandle.argtypes=[wintypes.HANDLE,wintypes.HANDLE,wintypes.HANDLE,ctypes.POINTER(wintypes.HANDLE),wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.DuplicateHandle.restype=wintypes.BOOL
k.ReadFile.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID]; k.ReadFile.restype=wintypes.BOOL
k.CloseHandle.argtypes=[wintypes.HANDLE]; k.CloseHandle.restype=wintypes.BOOL
k.LocalFree.argtypes=[wintypes.HLOCAL]
a.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]; a.OpenProcessToken.restype=wintypes.BOOL
a.ConvertStringSidToSidW.argtypes=[wintypes.LPCWSTR,ctypes.POINTER(wintypes.LPVOID)]; a.ConvertStringSidToSidW.restype=wintypes.BOOL
a.CreateRestrictedToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.LPVOID,ctypes.POINTER(wintypes.HANDLE)]; a.CreateRestrictedToken.restype=wintypes.BOOL
a.ImpersonateLoggedOnUser.argtypes=[wintypes.HANDLE]; a.ImpersonateLoggedOnUser.restype=wintypes.BOOL
a.RevertToSelf.restype=wintypes.BOOL
class SA(ctypes.Structure): _fields_=[('Sid',wintypes.LPVOID),('Attributes',wintypes.DWORD)]
fd, path = tempfile.mkstemp()
os.write(fd, b'exact-locked-handle')
os.lseek(fd, 0, os.SEEK_SET)
def attempt(*sids):
    base=wintypes.HANDLE(); assert a.OpenProcessToken(k.GetCurrentProcess(),0xF01FF,ctypes.byref(base))
    pointers=[]
    for sid in sids:
        p=wintypes.LPVOID(); assert a.ConvertStringSidToSidW(sid,ctypes.byref(p)); pointers.append(p)
    entries=(SA*len(pointers))(*(SA(p,0) for p in pointers)); token=wintypes.HANDLE()
    assert a.CreateRestrictedToken(base,1,0,None,0,None,len(entries),entries,ctypes.byref(token))
    try:
        assert a.ImpersonateLoggedOnUser(token)
        h=k.OpenProcess(0x1040,False,os.getpid()); error=ctypes.get_last_error()
        duplicated=wintypes.HANDLE(); duplicate_ok=False; observed=''
        if h:
            duplicate_ok=bool(k.DuplicateHandle(h,wintypes.HANDLE(msvcrt.get_osfhandle(fd)),k.GetCurrentProcess(),ctypes.byref(duplicated),0,False,2))
            if duplicate_ok:
                buffer=ctypes.create_string_buffer(64); count=wintypes.DWORD()
                assert k.ReadFile(duplicated,buffer,64,ctypes.byref(count),None)
                observed=buffer.raw[:count.value].decode('ascii')
        assert a.RevertToSelf()
        if duplicated.value: k.CloseHandle(duplicated)
        if h: k.CloseHandle(h)
        return [bool(h),error,duplicate_ok,observed]
    finally:
        for p in pointers: k.LocalFree(p)
        k.CloseHandle(token); k.CloseHandle(base)
try:
    actual=(service,'S-1-1-0','S-1-5-5-0-12345','S-1-5-33')
    print(json.dumps({'service':attempt(*actual),'provider':attempt(*actual,'S-1-5-12')}))
finally:
    os.close(fd); os.unlink(path)
'''
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.getcwd(),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    observed = __import__("json").loads(result.stdout)
    assert observed["service"] == [False, 5, False, ""]
    assert observed["provider"] == [False, 5, False, ""]
