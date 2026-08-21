from __future__ import annotations

import ctypes
import os
import uuid
from contextlib import contextmanager
from ctypes import wintypes
from typing import Iterator

import pytest

import keeper.provider_host.pipe as pipe_module
from keeper.authority_service.windows_identity import current_process_sid


SERVICE_SID = "S-1-5-80-1-2-3-4-5"
_TOKEN_ALL_ACCESS = 0x000F01FF
_INVALID_HANDLE = ctypes.c_void_p(-1).value


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]


@contextmanager
def _restricted_impersonation(restricting_sid: str) -> Iterator[None]:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.CreateRestrictedToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(_SidAndAttributes),
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.CreateRestrictedToken.restype = wintypes.BOOL
    advapi32.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
    advapi32.ImpersonateLoggedOnUser.restype = wintypes.BOOL
    advapi32.RevertToSelf.argtypes = []
    advapi32.RevertToSelf.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    source = wintypes.HANDLE()
    restricted = wintypes.HANDLE()
    sid = wintypes.LPVOID()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_ALL_ACCESS, ctypes.byref(source)
    ):
        raise OSError(ctypes.get_last_error(), "test process token open failed")
    try:
        if not advapi32.ConvertStringSidToSidW(restricting_sid, ctypes.byref(sid)):
            raise OSError(ctypes.get_last_error(), "test restricting SID failed")
        restriction = _SidAndAttributes(sid, 0)
        if not advapi32.CreateRestrictedToken(
            source,
            0,
            0,
            None,
            0,
            None,
            1,
            ctypes.byref(restriction),
            ctypes.byref(restricted),
        ):
            raise OSError(ctypes.get_last_error(), "test restricted token failed")
        if not advapi32.ImpersonateLoggedOnUser(restricted):
            raise OSError(ctypes.get_last_error(), "test impersonation failed")
        try:
            yield
        finally:
            if not advapi32.RevertToSelf():
                raise OSError(ctypes.get_last_error(), "test reversion failed")
    finally:
        if restricted.value:
            kernel32.CloseHandle(restricted)
        if sid.value:
            kernel32.LocalFree(sid)
        if source.value:
            kernel32.CloseHandle(source)


@contextmanager
def _listening_pipe() -> Iterator[tuple[str, object]]:
    pipe_name = rf"\\.\pipe\KeeperProviderHost-acl-{uuid.uuid4().hex}"
    kernel32 = pipe_module._kernel32()
    with pipe_module._security_attributes(
        current_process_sid(), SERVICE_SID
    ) as security:
        handle = kernel32.CreateNamedPipeW(
            pipe_name,
            pipe_module._PIPE_ACCESS_DUPLEX
            | pipe_module._FILE_FLAG_FIRST_PIPE_INSTANCE,
            pipe_module._PIPE_TYPE_BYTE
            | pipe_module._PIPE_READMODE_BYTE
            | pipe_module._PIPE_WAIT
            | pipe_module._PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            ctypes.byref(security),
        )
    if handle in {None, _INVALID_HANDLE}:
        raise OSError(ctypes.get_last_error(), "test pipe creation failed")
    try:
        yield pipe_name, kernel32
    finally:
        kernel32.CloseHandle(handle)


def _open_pipe(kernel32: object, pipe_name: str) -> int:
    return int(
        kernel32.CreateFileW(  # type: ignore[attr-defined]
            pipe_name,
            pipe_module._GENERIC_READ | pipe_module._GENERIC_WRITE,
            0,
            None,
            pipe_module._OPEN_EXISTING,
            0,
            None,
        )
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows restricted-token ACL test")
def test_restricted_service_sid_can_open_host_pipe() -> None:
    with _listening_pipe() as (pipe_name, kernel32):
        with _restricted_impersonation(SERVICE_SID):
            client = _open_pipe(kernel32, pipe_name)
        assert client not in {None, _INVALID_HANDLE}
        assert kernel32.CloseHandle(client)  # type: ignore[attr-defined]


@pytest.mark.skipif(os.name != "nt", reason="Windows restricted-token ACL test")
def test_restricted_provider_sid_remains_denied_by_host_pipe() -> None:
    with _listening_pipe() as (pipe_name, kernel32):
        ctypes.set_last_error(0)
        with _restricted_impersonation(pipe_module._RESTRICTED_CODE_SID):
            client = _open_pipe(kernel32, pipe_name)
            error = ctypes.get_last_error()
        assert client in {None, _INVALID_HANDLE}
        assert error == 5
