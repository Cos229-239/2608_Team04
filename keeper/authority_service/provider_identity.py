from __future__ import annotations

import ctypes
import os
import secrets
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path
from typing import Any, Iterator

from keeper.authority_service.restricted_process import (
    create_restricted_primary_token,
)


PROVIDER_ACCOUNT_NAME = "KeeperAuthorityPvd"
PROVIDER_ACCOUNT_RIGHTS = (
    "SeBatchLogonRight",
    "SeDenyInteractiveLogonRight",
    "SeDenyRemoteInteractiveLogonRight",
)
AUTHORITY_SERVICE_PROCESS_RIGHTS = (
    "SeAssignPrimaryTokenPrivilege",
    "SeIncreaseQuotaPrivilege",
)

_NERR_SUCCESS = 0
_NERR_USER_NOT_FOUND = 2221
_USER_PRIV_USER = 1
_UF_SCRIPT = 0x0001
_UF_PASSWD_CANT_CHANGE = 0x0040
_UF_NORMAL_ACCOUNT = 0x0200
_UF_DONT_EXPIRE_PASSWD = 0x10000
_CRYPTPROTECT_UI_FORBIDDEN = 0x1
_CRYPTPROTECT_LOCAL_MACHINE = 0x4
_LOGON32_LOGON_BATCH = 4
_LOGON32_PROVIDER_DEFAULT = 0
_POLICY_CREATE_ACCOUNT = 0x0010
_POLICY_LOOKUP_NAMES = 0x0800


class _UserInfo0(ctypes.Structure):
    _fields_ = [("usri0_name", wintypes.LPWSTR)]


class _UserInfo1(ctypes.Structure):
    _fields_ = [
        ("usri1_name", wintypes.LPWSTR),
        ("usri1_password", wintypes.LPWSTR),
        ("usri1_password_age", wintypes.DWORD),
        ("usri1_priv", wintypes.DWORD),
        ("usri1_home_dir", wintypes.LPWSTR),
        ("usri1_comment", wintypes.LPWSTR),
        ("usri1_flags", wintypes.DWORD),
        ("usri1_script_path", wintypes.LPWSTR),
    ]


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class _LsaObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", wintypes.LPVOID),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID),
    ]


class _LsaUnicodeString(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


def generate_provider_password() -> str:
    return secrets.token_urlsafe(64)


def provider_account_sid(account_name: str = PROVIDER_ACCOUNT_NAME) -> str | None:
    pointer = wintypes.LPBYTE()
    status = _netapi32().NetUserGetInfo(
        None, account_name, 0, ctypes.byref(pointer)
    )
    if status == _NERR_USER_NOT_FOUND:
        return None
    if status != _NERR_SUCCESS:
        raise OSError(status, "provider account lookup failed")
    try:
        return _lookup_account_sid(account_name)[0]
    finally:
        _netapi32().NetApiBufferFree(pointer)


def account_sid(account_name: str) -> str:
    return _lookup_account_sid(account_name)[0]


def create_provider_account(
    password: str, account_name: str = PROVIDER_ACCOUNT_NAME
) -> str:
    if provider_account_sid(account_name) is not None:
        raise FileExistsError(f"provider account already exists: {account_name}")
    information = _UserInfo1(
        account_name,
        password,
        0,
        _USER_PRIV_USER,
        None,
        "Keeper Authority restricted provider identity",
        _UF_SCRIPT
        | _UF_PASSWD_CANT_CHANGE
        | _UF_NORMAL_ACCOUNT
        | _UF_DONT_EXPIRE_PASSWD,
        None,
    )
    parameter_error = wintypes.DWORD()
    status = _netapi32().NetUserAdd(
        None, 1, ctypes.byref(information), ctypes.byref(parameter_error)
    )
    if status != _NERR_SUCCESS:
        raise OSError(
            status,
            "provider account creation failed "
            f"(parameter {parameter_error.value})",
        )
    sid = provider_account_sid(account_name)
    if sid is None:
        raise PermissionError("created provider account identity is unavailable")
    return sid


def grant_provider_account_rights(
    account_name: str = PROVIDER_ACCOUNT_NAME,
) -> tuple[str, ...]:
    return grant_account_rights(account_name, PROVIDER_ACCOUNT_RIGHTS)


def grant_account_rights(
    account_name: str, account_rights: tuple[str, ...]
) -> tuple[str, ...]:
    if not account_rights:
        raise ValueError("account rights cannot be empty")
    _, sid_buffer = _lookup_account_sid(account_name)
    attributes = _LsaObjectAttributes()
    attributes.Length = ctypes.sizeof(attributes)
    policy = wintypes.HANDLE()
    status = _advapi32().LsaOpenPolicy(
        None,
        ctypes.byref(attributes),
        _POLICY_CREATE_ACCOUNT | _POLICY_LOOKUP_NAMES,
        ctypes.byref(policy),
    )
    _raise_lsa(status, "provider account policy could not be opened")
    buffers = [ctypes.create_unicode_buffer(value) for value in account_rights]
    rights = (_LsaUnicodeString * len(buffers))(
        *(
            _LsaUnicodeString(
                len(buffer.value.encode("utf-16-le")),
                ctypes.sizeof(buffer),
                ctypes.cast(buffer, wintypes.LPWSTR),
            )
            for buffer in buffers
        )
    )
    try:
        sid = ctypes.cast(sid_buffer, wintypes.LPVOID)
        status = _advapi32().LsaAddAccountRights(
            policy, sid, rights, len(rights)
        )
        _raise_lsa(status, "provider account rights could not be applied")
    finally:
        _advapi32().LsaClose(policy)
    return account_rights


def account_rights(account_name: str) -> tuple[str, ...]:
    _, sid_buffer = _lookup_account_sid(account_name)
    attributes = _LsaObjectAttributes()
    attributes.Length = ctypes.sizeof(attributes)
    policy = wintypes.HANDLE()
    status = _advapi32().LsaOpenPolicy(
        None,
        ctypes.byref(attributes),
        _POLICY_LOOKUP_NAMES,
        ctypes.byref(policy),
    )
    _raise_lsa(status, "account-rights policy could not be opened")
    rights = ctypes.POINTER(_LsaUnicodeString)()
    count = wintypes.ULONG()
    try:
        status = _advapi32().LsaEnumerateAccountRights(
            policy,
            ctypes.cast(sid_buffer, wintypes.LPVOID),
            ctypes.byref(rights),
            ctypes.byref(count),
        )
        _raise_lsa(status, "account rights could not be enumerated")
        return tuple(
            ctypes.wstring_at(
                rights[index].Buffer, rights[index].Length // 2
            )
            for index in range(int(count.value))
        )
    finally:
        if rights:
            _advapi32().LsaFreeMemory(rights)
        _advapi32().LsaClose(policy)


def protect_provider_password(password: str, destination: Path) -> None:
    if destination.exists():
        raise FileExistsError(destination)
    content = password.encode("utf-8")
    source_buffer = (ctypes.c_ubyte * len(content)).from_buffer_copy(content)
    source = _DataBlob(
        len(content), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte))
    )
    protected = _DataBlob()
    if not _crypt32().CryptProtectData(
        ctypes.byref(source),
        "Keeper Authority provider identity",
        None,
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN | _CRYPTPROTECT_LOCAL_MACHINE,
        ctypes.byref(protected),
    ):
        raise PermissionError(
            f"provider credential protection failed: {ctypes.get_last_error()}"
        )
    try:
        value = ctypes.string_at(protected.pbData, protected.cbData)
    finally:
        _kernel32().LocalFree(protected.pbData)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".provisioning")
    if temporary.exists():
        raise PermissionError("provider credential staging file already exists")
    with temporary.open("xb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)


def unprotect_provider_password(source: Path) -> str:
    content = source.resolve(strict=True).read_bytes()
    if not content:
        raise PermissionError("provider credential is empty")
    source_buffer = (ctypes.c_ubyte * len(content)).from_buffer_copy(content)
    encrypted = _DataBlob(
        len(content), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte))
    )
    plain = _DataBlob()
    if not _crypt32().CryptUnprotectData(
        ctypes.byref(encrypted),
        None,
        None,
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(plain),
    ):
        raise PermissionError(
            f"provider credential decryption failed: {ctypes.get_last_error()}"
        )
    try:
        return ctypes.string_at(plain.pbData, plain.cbData).decode("utf-8")
    except UnicodeDecodeError as error:
        raise PermissionError("provider credential is malformed") from error
    finally:
        _kernel32().LocalFree(plain.pbData)


@contextmanager
def restricted_provider_identity_token(
    account_name: str, credential_path: Path
) -> Iterator[int]:
    password = unprotect_provider_password(credential_path)
    source = wintypes.HANDLE()
    if not _advapi32().LogonUserW(
        account_name,
        ".",
        password,
        _LOGON32_LOGON_BATCH,
        _LOGON32_PROVIDER_DEFAULT,
        ctypes.byref(source),
    ):
        raise PermissionError(
            f"restricted provider logon failed: {ctypes.get_last_error()}"
        )
    password = "\0" * len(password)
    source_value = source.value
    if not isinstance(source_value, int) or source_value <= 0:
        raise PermissionError("restricted provider token handle is invalid")
    restricted = 0
    try:
        restricted = create_restricted_primary_token(source_value)
        yield restricted
    finally:
        if restricted:
            _kernel32().CloseHandle(restricted)
        if source.value:
            _kernel32().CloseHandle(source)


def _lookup_account_sid(account_name: str) -> tuple[str, ctypes.Array[Any]]:
    sid_size = wintypes.DWORD()
    domain_size = wintypes.DWORD()
    use = wintypes.DWORD()
    _advapi32().LookupAccountNameW(
        None,
        account_name,
        None,
        ctypes.byref(sid_size),
        None,
        ctypes.byref(domain_size),
        ctypes.byref(use),
    )
    if not sid_size.value:
        raise PermissionError(
            f"provider account SID size failed: {ctypes.get_last_error()}"
        )
    sid_buffer = ctypes.create_string_buffer(sid_size.value)
    domain = ctypes.create_unicode_buffer(max(1, domain_size.value))
    if not _advapi32().LookupAccountNameW(
        None,
        account_name,
        sid_buffer,
        ctypes.byref(sid_size),
        domain,
        ctypes.byref(domain_size),
        ctypes.byref(use),
    ):
        raise PermissionError(
            f"provider account SID lookup failed: {ctypes.get_last_error()}"
        )
    value = wintypes.LPWSTR()
    if not _advapi32().ConvertSidToStringSidW(
        sid_buffer, ctypes.byref(value)
    ):
        raise PermissionError(
            f"provider account SID conversion failed: {ctypes.get_last_error()}"
        )
    try:
        return str(value.value), sid_buffer
    finally:
        _kernel32().LocalFree(value)


def _raise_lsa(status: int, message: str) -> None:
    if status:
        raise OSError(int(_advapi32().LsaNtStatusToWinError(status)), message)


def _netapi32() -> Any:
    value: Any = ctypes.WinDLL("netapi32", use_last_error=True)
    value.NetUserGetInfo.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPBYTE),
    ]
    value.NetUserGetInfo.restype = wintypes.DWORD
    value.NetUserAdd.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
    ]
    value.NetUserAdd.restype = wintypes.DWORD
    value.NetApiBufferFree.argtypes = [wintypes.LPVOID]
    value.NetApiBufferFree.restype = wintypes.DWORD
    return value


def _crypt32() -> Any:
    value: Any = ctypes.WinDLL("crypt32", use_last_error=True)
    value.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    value.CryptProtectData.restype = wintypes.BOOL
    value.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DataBlob),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    value.CryptUnprotectData.restype = wintypes.BOOL
    return value


def _advapi32() -> Any:
    value: Any = ctypes.WinDLL("advapi32", use_last_error=True)
    value.LookupAccountNameW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    value.LookupAccountNameW.restype = wintypes.BOOL
    value.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    value.ConvertSidToStringSidW.restype = wintypes.BOOL
    value.LogonUserW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    value.LogonUserW.restype = wintypes.BOOL
    value.LsaOpenPolicy.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(_LsaObjectAttributes),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    value.LsaOpenPolicy.restype = wintypes.LONG
    value.LsaAddAccountRights.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        ctypes.POINTER(_LsaUnicodeString),
        wintypes.DWORD,
    ]
    value.LsaAddAccountRights.restype = wintypes.LONG
    value.LsaEnumerateAccountRights.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        ctypes.POINTER(ctypes.POINTER(_LsaUnicodeString)),
        ctypes.POINTER(wintypes.ULONG),
    ]
    value.LsaEnumerateAccountRights.restype = wintypes.LONG
    value.LsaFreeMemory.argtypes = [wintypes.LPVOID]
    value.LsaFreeMemory.restype = wintypes.LONG
    value.LsaClose.argtypes = [wintypes.HANDLE]
    value.LsaClose.restype = wintypes.LONG
    value.LsaNtStatusToWinError.argtypes = [wintypes.LONG]
    value.LsaNtStatusToWinError.restype = wintypes.ULONG
    return value


def _kernel32() -> Any:
    value: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    value.CloseHandle.argtypes = [wintypes.HANDLE]
    value.CloseHandle.restype = wintypes.BOOL
    value.LocalFree.argtypes = [wintypes.HLOCAL]
    value.LocalFree.restype = wintypes.HLOCAL
    return value
