from __future__ import annotations

import ctypes
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from enum import Enum
from typing import Any

from keeper.authority_service.windows_identity import (
    require_current_restricted_service_identity,
)


PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_DUP_HANDLE = 0x0040
TOKEN_QUERY = 0x0008
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_ERROR_INSUFFICIENT_BUFFER = 122

_OWNER_SECURITY_INFORMATION = 0x00000001
_GROUP_SECURITY_INFORMATION = 0x00000002
_DACL_SECURITY_INFORMATION = 0x00000004
_ACCESS_ALLOWED_ACE_TYPE = 0
_ACCESS_DENIED_ACE_TYPE = 1
_INHERITED_ACE = 0x10
_ACL_SIZE_INFORMATION_CLASS = 2
_SERVICE_SID = re.compile(r"S-1-5-80-(?:\d+-){4}\d+")
_WINDOWS_SID = re.compile(r"S-\d-(?:\d+-)+\d+")


class ProcessSecurityStage(str, Enum):
    VALIDATE_IDENTITY = "VALIDATE_IDENTITY"
    DUPLICATE_SELF_HANDLE = "DUPLICATE_SELF_HANDLE"
    READ_DESCRIPTOR = "READ_DESCRIPTOR"
    VALIDATE_EXISTING_GRANT = "VALIDATE_EXISTING_GRANT"
    BUILD_DACL = "BUILD_DACL"
    WRITE_DACL = "WRITE_DACL"
    VERIFY_DACL = "VERIFY_DACL"
    CLOSE_SELF_HANDLE = "CLOSE_SELF_HANDLE"


class ProcessSecurityError(PermissionError):
    """Fail-closed error with a non-sensitive startup stage."""

    def __init__(self, stage: ProcessSecurityStage, message: str) -> None:
        super().__init__(message)
        self.stage = stage


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("AceType", ctypes.c_ubyte),
        ("AceFlags", ctypes.c_ubyte),
        ("AceSize", wintypes.WORD),
    ]


@dataclass(frozen=True, slots=True)
class ProcessAce:
    ace_type: str
    trustee_sid: str
    rights_mask: int
    flags: int


@dataclass(frozen=True, slots=True)
class ProcessSecuritySnapshot:
    owner_sid: str
    group_sid: str
    control: int
    revision: int
    dacl_defaulted: bool
    aces: tuple[ProcessAce, ...]


def ensure_current_process_service_query_access(
    service_sid: str,
) -> ProcessSecuritySnapshot:
    """Grant only QLI to this service's exact restricted service SID.

    The grant lets the two-pass restricted service token inspect its own
    process lifetime and image identity through the per-user Provider Host.
    Existing ownership, group, control flags, denials, and grants must survive
    byte-for-byte at the semantic ACE level.  Any ambiguous descriptor fails
    service startup closed.
    """
    if os.name != "nt":
        raise RuntimeError("Windows process security is unavailable")
    if not _SERVICE_SID.fullmatch(service_sid):
        raise ProcessSecurityError(
            ProcessSecurityStage.VALIDATE_IDENTITY,
            "KeeperAuthority service SID is invalid",
        )
    try:
        require_current_restricted_service_identity(service_sid)
    except (OSError, PermissionError, RuntimeError, ValueError) as error:
        raise ProcessSecurityError(
            ProcessSecurityStage.VALIDATE_IDENTITY,
            "KeeperAuthority process security identity differs",
        ) from error
    return _ensure_current_process_sid_query_access(
        service_sid,
        subject="KeeperAuthority",
    )


def _ensure_current_process_sid_query_access(
    principal_sid: str,
    *,
    subject: str,
) -> ProcessSecuritySnapshot:
    """Apply the exact QLI-only self-process delta after caller validation.

    This private primitive exists so the independently authenticated
    KeeperAuthority service and Provider Host startup paths can share one
    descriptor implementation without weakening either identity gate.  A
    caller must validate its complete process identity before entering here.
    """
    if subject not in {
        "KeeperAuthority",
        "Provider Host",
        "Provider Host user",
    }:
        raise ProcessSecurityError(
            ProcessSecurityStage.VALIDATE_IDENTITY,
            "Keeper process security subject is invalid",
        )
    if not _WINDOWS_SID.fullmatch(principal_sid):
        raise ProcessSecurityError(
            ProcessSecurityStage.VALIDATE_IDENTITY,
            f"{subject} SID is invalid",
        )
    # A SERVICE_SID_TYPE_RESTRICTED process cannot open its own process object
    # through a normal access check before the service SID grant exists.  A
    # duplicated GetCurrentProcess pseudo-handle is the documented, narrow way
    # to obtain a real self-handle.  Its access is explicitly down-scoped to
    # READ_CONTROL | WRITE_DAC and it never leaves this process.
    with _current_process_security_handle(_READ_CONTROL | _WRITE_DAC) as handle:
        return _ensure_kernel_object_sid_access(
            handle,
            service_sid=principal_sid,
            required_rights=PROCESS_QUERY_LIMITED_INFORMATION,
            subject=f"{subject} process",
        )


def _ensure_current_process_token_sid_query_access(
    service_sid: str,
    *,
    subject: str,
) -> ProcessSecuritySnapshot:
    """Grant only TOKEN_QUERY on this process token to the exact service SID."""
    if subject != "Provider Host":
        raise ProcessSecurityError(
            ProcessSecurityStage.VALIDATE_IDENTITY,
            "Keeper process-token security subject is invalid",
        )
    if not _SERVICE_SID.fullmatch(service_sid):
        raise ProcessSecurityError(
            ProcessSecurityStage.VALIDATE_IDENTITY,
            f"{subject} service SID is invalid",
        )
    with _current_process_token_security_handle(
        _READ_CONTROL | _WRITE_DAC
    ) as handle:
        return _ensure_kernel_object_sid_access(
            handle,
            service_sid=service_sid,
            required_rights=TOKEN_QUERY,
            subject=f"{subject} token",
        )


def _ensure_kernel_object_sid_access(
    handle: wintypes.HANDLE,
    *,
    service_sid: str,
    required_rights: int,
    subject: str,
) -> ProcessSecuritySnapshot:
    before = read_current_process_security(handle)
    matching = [
        ace
        for ace in before.aces
        if ace.trustee_sid.casefold() == service_sid.casefold()
    ]
    required = ProcessAce("allow", service_sid, required_rights, 0)
    if matching:
        if matching != [required]:
            raise ProcessSecurityError(
                ProcessSecurityStage.VALIDATE_EXISTING_GRANT,
                f"{subject} service grant is ambiguous or broad",
            )
        if not _canonical_ace_order(before.aces):
            raise ProcessSecurityError(
                ProcessSecurityStage.VALIDATE_EXISTING_GRANT,
                f"{subject} DACL ordering is not canonical",
            )
        return before
    if not _canonical_ace_order(before.aces):
        raise ProcessSecurityError(
            ProcessSecurityStage.VALIDATE_EXISTING_GRANT,
            f"{subject} DACL ordering is not canonical",
        )
    insertion = next(
        (
            index
            for index, ace in enumerate(before.aces)
            if ace.flags & _INHERITED_ACE
        ),
        len(before.aces),
    )
    expected_aces = (
        before.aces[:insertion] + (required,) + before.aces[insertion:]
    )
    _write_current_process_dacl(expected_aces, handle=handle)
    after = read_current_process_security(handle)
    if (
        after.owner_sid.casefold() != before.owner_sid.casefold()
        or after.group_sid.casefold() != before.group_sid.casefold()
        or after.control != before.control
        or after.revision != before.revision
        or after.dacl_defaulted != before.dacl_defaulted
        or after.aces != expected_aces
    ):
        raise ProcessSecurityError(
            ProcessSecurityStage.VERIFY_DACL,
            f"{subject} security delta did not verify exactly",
        )
    return after


def _canonical_ace_order(aces: tuple[ProcessAce, ...]) -> bool:
    """Require explicit deny/allow before inherited deny/allow ACEs."""
    order = tuple(
        (2 if ace.flags & _INHERITED_ACE else 0)
        + (1 if ace.ace_type == "allow" else 0)
        for ace in aces
    )
    return order == tuple(sorted(order))


def read_current_process_security(
    handle: wintypes.HANDLE | None = None,
) -> ProcessSecuritySnapshot:
    if os.name != "nt":
        raise RuntimeError("Windows process security is unavailable")
    if handle is None:
        with _current_process_security_handle(_READ_CONTROL) as duplicated:
            return read_current_process_security(duplicated)
    advapi32 = _advapi32()
    required_size = wintypes.DWORD()
    ctypes.set_last_error(0)
    if advapi32.GetKernelObjectSecurity(
        handle,
        _OWNER_SECURITY_INFORMATION
        | _GROUP_SECURITY_INFORMATION
        | _DACL_SECURITY_INFORMATION,
        None,
        0,
        ctypes.byref(required_size),
    ) or ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
        raise ProcessSecurityError(
            ProcessSecurityStage.READ_DESCRIPTOR,
            "KeeperAuthority process security size probe failed",
        )
    if not required_size.value:
        raise ProcessSecurityError(
            ProcessSecurityStage.READ_DESCRIPTOR,
            "KeeperAuthority process security descriptor is empty",
        )
    descriptor_buffer = ctypes.create_string_buffer(required_size.value)
    if not advapi32.GetKernelObjectSecurity(
        handle,
        _OWNER_SECURITY_INFORMATION
        | _GROUP_SECURITY_INFORMATION
        | _DACL_SECURITY_INFORMATION,
        descriptor_buffer,
        required_size.value,
        ctypes.byref(required_size),
    ):
        raise ProcessSecurityError(
            ProcessSecurityStage.READ_DESCRIPTOR,
            "KeeperAuthority process security read failed",
        )
    descriptor = ctypes.cast(descriptor_buffer, wintypes.LPVOID)
    owner = wintypes.LPVOID()
    group = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    owner_defaulted = wintypes.BOOL()
    group_defaulted = wintypes.BOOL()
    if not advapi32.GetSecurityDescriptorOwner(
        descriptor, ctypes.byref(owner), ctypes.byref(owner_defaulted)
    ) or not owner.value:
        raise ProcessSecurityError(
            ProcessSecurityStage.READ_DESCRIPTOR,
            "KeeperAuthority process security owner is unavailable",
        )
    if not advapi32.GetSecurityDescriptorGroup(
        descriptor, ctypes.byref(group), ctypes.byref(group_defaulted)
    ) or not group.value:
        raise ProcessSecurityError(
            ProcessSecurityStage.READ_DESCRIPTOR,
            "KeeperAuthority process security group is unavailable",
        )
    control = wintypes.WORD()
    revision = wintypes.DWORD()
    if not advapi32.GetSecurityDescriptorControl(
        descriptor, ctypes.byref(control), ctypes.byref(revision)
    ):
        raise ProcessSecurityError(
            ProcessSecurityStage.READ_DESCRIPTOR,
            "KeeperAuthority process security control is unavailable",
        )
    present = wintypes.BOOL()
    defaulted = wintypes.BOOL()
    if not advapi32.GetSecurityDescriptorDacl(
        descriptor,
        ctypes.byref(present),
        ctypes.byref(dacl),
        ctypes.byref(defaulted),
    ) or not present or not dacl.value:
        raise ProcessSecurityError(
            ProcessSecurityStage.READ_DESCRIPTOR,
            "KeeperAuthority process DACL is unavailable",
        )
    return ProcessSecuritySnapshot(
        owner_sid=_sid_string(int(owner.value)),
        group_sid=_sid_string(int(group.value)),
        control=int(control.value),
        revision=int(revision.value),
        dacl_defaulted=bool(defaulted.value),
        aces=_read_dacl(dacl),
    )


def _read_dacl(pointer: wintypes.LPVOID) -> tuple[ProcessAce, ...]:
    information = _AclSizeInformation()
    advapi32 = _advapi32()
    if not advapi32.GetAclInformation(
        pointer,
        ctypes.byref(information),
        ctypes.sizeof(information),
        _ACL_SIZE_INFORMATION_CLASS,
    ):
        raise ProcessSecurityError(
            ProcessSecurityStage.READ_DESCRIPTOR,
            "KeeperAuthority process DACL cannot be read",
        )
    values: list[ProcessAce] = []
    for index in range(int(information.AceCount)):
        ace_pointer = wintypes.LPVOID()
        if not advapi32.GetAce(pointer, index, ctypes.byref(ace_pointer)):
            raise ProcessSecurityError(
                ProcessSecurityStage.READ_DESCRIPTOR,
                "KeeperAuthority process ACE cannot be read",
            )
        if not ace_pointer.value:
            raise ProcessSecurityError(
                ProcessSecurityStage.READ_DESCRIPTOR,
                "KeeperAuthority process ACE is invalid",
            )
        address = int(ace_pointer.value)
        header = ctypes.cast(address, ctypes.POINTER(_AceHeader)).contents
        if (
            header.AceType
            not in {_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_DENIED_ACE_TYPE}
            or int(header.AceSize) < 12
        ):
            raise ProcessSecurityError(
                ProcessSecurityStage.READ_DESCRIPTOR,
                "KeeperAuthority process DACL contains an unsupported ACE",
            )
        values.append(
            ProcessAce(
                "allow"
                if header.AceType == _ACCESS_ALLOWED_ACE_TYPE
                else "deny",
                _sid_string(address + 8),
                int(ctypes.c_uint32.from_address(address + 4).value),
                int(header.AceFlags),
            )
        )
    if not values:
        raise ProcessSecurityError(
            ProcessSecurityStage.READ_DESCRIPTOR,
            "KeeperAuthority process DACL is empty",
        )
    return tuple(values)


def _write_current_process_dacl(
    aces: tuple[ProcessAce, ...],
    *,
    handle: wintypes.HANDLE | None = None,
) -> None:
    if not aces:
        raise ProcessSecurityError(
            ProcessSecurityStage.BUILD_DACL,
            "KeeperAuthority process DACL cannot be empty",
        )
    if handle is None:
        with _current_process_security_handle(_WRITE_DAC) as duplicated:
            _write_current_process_dacl(aces, handle=duplicated)
            return
    sddl = "D:" + "".join(_ace_sddl(ace) for ace in aces)
    descriptor = wintypes.LPVOID()
    advapi32 = _advapi32()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise ProcessSecurityError(
            ProcessSecurityStage.BUILD_DACL,
            "KeeperAuthority process DACL construction failed",
        )
    try:
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        dacl = wintypes.LPVOID()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(dacl),
            ctypes.byref(defaulted),
        ) or not present or not dacl.value:
            raise ProcessSecurityError(
                ProcessSecurityStage.BUILD_DACL,
                "KeeperAuthority process DACL construction is invalid",
            )
        if not advapi32.SetKernelObjectSecurity(
            handle,
            _DACL_SECURITY_INFORMATION,
            descriptor,
        ):
            raise ProcessSecurityError(
                ProcessSecurityStage.WRITE_DACL,
                "KeeperAuthority process DACL update failed",
            )
    finally:
        _kernel32().LocalFree(descriptor)


def _ace_sddl(ace: ProcessAce) -> str:
    if (
        ace.ace_type not in {"allow", "deny"}
        or not re.fullmatch(r"S-\d-(?:\d+-)+\d+", ace.trustee_sid)
        or ace.rights_mask <= 0
        or ace.rights_mask > 0xFFFFFFFF
        or ace.flags & ~0x1F
    ):
        raise ProcessSecurityError(
            ProcessSecurityStage.BUILD_DACL,
            "KeeperAuthority process ACE is invalid",
        )
    flags = "".join(
        label
        for bit, label in (
            (0x01, "OI"),
            (0x02, "CI"),
            (0x04, "NP"),
            (0x08, "IO"),
            (0x10, "ID"),
        )
        if ace.flags & bit
    )
    kind = "A" if ace.ace_type == "allow" else "D"
    return (
        f"({kind};{flags};0x{ace.rights_mask:08x};;;{ace.trustee_sid})"
    )


def _sid_string(pointer: int) -> str:
    advapi32 = _advapi32()
    if not advapi32.IsValidSid(wintypes.LPVOID(pointer)):
        raise ProcessSecurityError(
            ProcessSecurityStage.READ_DESCRIPTOR,
            "KeeperAuthority process trustee SID is invalid",
        )
    value = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(pointer, ctypes.byref(value)):
        raise ProcessSecurityError(
            ProcessSecurityStage.READ_DESCRIPTOR,
            "KeeperAuthority process trustee SID is unavailable",
        )
    try:
        return str(value.value)
    finally:
        _kernel32().LocalFree(value)


def _kernel32() -> Any:
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.DuplicateHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    kernel32.DuplicateHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    return kernel32


@contextmanager
def _current_process_security_handle(
    desired_access: int,
) -> Iterator[wintypes.HANDLE]:
    if desired_access not in {
        _READ_CONTROL,
        _WRITE_DAC,
        _READ_CONTROL | _WRITE_DAC,
    }:
        raise ProcessSecurityError(
            ProcessSecurityStage.DUPLICATE_SELF_HANDLE,
            "KeeperAuthority process security handle rights are invalid",
        )
    kernel32 = _kernel32()
    current = kernel32.GetCurrentProcess()
    duplicated = wintypes.HANDLE()
    if not kernel32.DuplicateHandle(
        current,
        current,
        current,
        ctypes.byref(duplicated),
        desired_access,
        False,
        0,
    ) or not duplicated.value:
        raise ProcessSecurityError(
            ProcessSecurityStage.DUPLICATE_SELF_HANDLE,
            "KeeperAuthority process security handle duplication failed",
        )
    try:
        yield duplicated
    finally:
        if not kernel32.CloseHandle(duplicated):
            raise ProcessSecurityError(
                ProcessSecurityStage.CLOSE_SELF_HANDLE,
                "KeeperAuthority process security handle cleanup failed",
            )


@contextmanager
def _current_process_token_security_handle(
    desired_access: int,
) -> Iterator[wintypes.HANDLE]:
    if desired_access not in {
        _READ_CONTROL,
        _WRITE_DAC,
        _READ_CONTROL | _WRITE_DAC,
    }:
        raise ProcessSecurityError(
            ProcessSecurityStage.DUPLICATE_SELF_HANDLE,
            "Provider Host token security handle rights are invalid",
        )
    advapi32 = _advapi32()
    kernel32 = _kernel32()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        desired_access,
        ctypes.byref(token),
    ) or not token.value:
        raise ProcessSecurityError(
            ProcessSecurityStage.DUPLICATE_SELF_HANDLE,
            "Provider Host token security handle open failed",
        )
    try:
        yield token
    finally:
        if not kernel32.CloseHandle(token):
            raise ProcessSecurityError(
                ProcessSecurityStage.CLOSE_SELF_HANDLE,
                "Provider Host token security handle cleanup failed",
            )


def _advapi32() -> Any:
    advapi32: Any = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.GetKernelObjectSecurity.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetKernelObjectSecurity.restype = wintypes.BOOL
    advapi32.SetKernelObjectSecurity.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    advapi32.SetKernelObjectSecurity.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorOwner.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorOwner.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorGroup.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorGroup.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorControl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.IsValidSid.argtypes = [wintypes.LPVOID]
    advapi32.IsValidSid.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    return advapi32
