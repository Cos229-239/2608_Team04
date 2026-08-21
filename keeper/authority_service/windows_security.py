from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
from ctypes import wintypes
from pathlib import Path
from typing import Any


_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_LABEL_SECURITY_INFORMATION = 0x00000010
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
_SE_DACL_PROTECTED = 0x1000
_ACL_SIZE_INFORMATION_CLASS = 2
_ACCESS_ALLOWED_ACE_TYPE = 0
_ACCESS_DENIED_ACE_TYPE = 1
_SYSTEM_MANDATORY_LABEL_ACE_TYPE = 17
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_NO_PROPAGATE_INHERIT_ACE = 0x04
_INHERIT_ONLY_ACE = 0x08
_INHERITED_ACE = 0x10
_FILE_ALL_ACCESS = 0x001F01FF
_FILE_MODIFY_ACCESS = 0x001301BF
_NO_WRITE_UP = 0x1
_NO_READ_UP = 0x2
_NO_EXECUTE_UP = 0x4
_SID = re.compile(r"S-\d-(?:\d+-)+\d+")
_RESULTS = {"PASS", "FAIL", "INDETERMINATE"}
_ERROR_INSUFFICIENT_BUFFER = 122


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


def expected_authority_security(
    *,
    service_root: Path,
    exchange_root: Path,
    service_sid: str,
    client_sid: str,
    provider_sid: str,
) -> dict[str, Any]:
    for label, sid in (
        ("service", service_sid),
        ("client", client_sid),
        ("provider", provider_sid),
    ):
        _validate_sid(sid, label)
    return {
        "schema_version": 1,
        "service_root": exact_path_policy(
            service_root,
            [
                ("S-1-5-18", "full"),
                ("S-1-5-32-544", "full"),
                (service_sid, "full"),
            ],
            integrity="medium",
        ),
        "client_exchange": exact_path_policy(
            exchange_root,
            [
                ("S-1-5-18", "full"),
                ("S-1-5-32-544", "full"),
                (service_sid, "modify"),
                (client_sid, "modify"),
                (provider_sid, "modify"),
                ("S-1-5-12", "modify"),
            ],
            integrity="low",
        ),
    }


def exact_path_policy(
    path: Path,
    grants: list[tuple[str, str]],
    *,
    integrity: str,
) -> dict[str, Any]:
    masks = {"full": _FILE_ALL_ACCESS, "modify": _FILE_MODIFY_ACCESS}
    if integrity not in {"low", "medium"}:
        raise ValueError("Windows integrity policy is invalid")
    aces = [
        _expected_ace(sid, masks[right])
        for sid, right in grants
        if right in masks
    ]
    if len(aces) != len(grants):
        raise ValueError("Windows DACL grant is invalid")
    _reject_duplicate_trustees(aces, str(path))
    integrity_sid = {
        "low": "S-1-16-4096",
        "medium": "S-1-16-8192",
    }[integrity]
    return {
        "path": str(path.resolve()),
        "dacl_protected": True,
        "aces": aces,
        "mandatory_integrity": _expected_integrity(
            integrity_sid, integrity
        ),
    }


def enforce_authority_security(
    *,
    service_root: Path,
    exchange_root: Path,
    service_sid: str,
    client_sid: str,
    provider_sid: str,
) -> dict[str, Any]:
    expected = expected_authority_security(
        service_root=service_root,
        exchange_root=exchange_root,
        service_sid=service_sid,
        client_sid=client_sid,
        provider_sid=provider_sid,
    )
    _require_resolved_trustees(expected)
    apply_path_security(service_root, expected["service_root"])
    apply_path_security(exchange_root, expected["client_exchange"])
    attestation = attest_authority_security(
        service_root=service_root,
        exchange_root=exchange_root,
        service_sid=service_sid,
        client_sid=client_sid,
        provider_sid=provider_sid,
    )
    if attestation["result"] != "PASS":
        raise PermissionError(
            "Authority security descriptor repair did not verify exactly"
        )
    return attestation


def attest_authority_security(
    *,
    service_root: Path,
    exchange_root: Path,
    service_sid: str,
    client_sid: str,
    provider_sid: str,
) -> dict[str, Any]:
    expected = expected_authority_security(
        service_root=service_root,
        exchange_root=exchange_root,
        service_sid=service_sid,
        client_sid=client_sid,
        provider_sid=provider_sid,
    )
    try:
        _require_resolved_trustees(expected)
    except (OSError, PermissionError, RuntimeError, ValueError) as error:
        return _unavailable_policy_attestation(
            expected, type(error).__name__
        )
    policy_digest = _canonical_sha256(expected)
    paths: dict[str, Any] = {}
    for name, path in (
        ("service_root", service_root),
        ("client_exchange", exchange_root),
    ):
        try:
            live = read_path_security(path)
        except (OSError, PermissionError, RuntimeError, ValueError) as error:
            paths[name] = _unavailable_attestation(
                expected[name], type(error).__name__
            )
        else:
            paths[name] = compare_path_security(expected[name], live)
    result = _aggregate(
        str(item["result"]) for item in paths.values()
    )
    live_summary = {
        name: item["live"] for name, item in paths.items()
    }
    return {
        "schema_version": 1,
        "expected_policy": expected,
        "expected_policy_sha256": policy_digest,
        "live_policy": live_summary,
        "live_policy_sha256": (
            _canonical_sha256(live_summary)
            if result != "INDETERMINATE"
            else None
        ),
        "paths": paths,
        "result": result,
    }


def apply_path_security(path: Path, policy: dict[str, Any]) -> None:
    if os.name != "nt":
        raise RuntimeError("Windows security descriptors are unavailable")
    resolved = path.resolve(strict=True)
    aces = policy.get("aces")
    integrity = policy.get("mandatory_integrity")
    if (
        not isinstance(aces, list)
        or not aces
        or not isinstance(integrity, dict)
        or not isinstance(policy.get("dacl_protected"), bool)
    ):
        raise ValueError("Windows security policy is invalid")
    _reject_duplicate_trustees(aces, "path policy")
    dacl = "".join(_ace_sddl(item) for item in aces)
    label = _integrity_sddl(integrity)
    sddl = (
        f"D:{'P' if policy['dacl_protected'] else ''}{dacl}"
        f"S:{label}"
    )
    descriptor = _security_descriptor_from_sddl(sddl)
    advapi32 = _advapi32()
    dacl_pointer = wintypes.LPVOID()
    sacl_pointer = wintypes.LPVOID()
    dacl_present = wintypes.BOOL()
    sacl_present = wintypes.BOOL()
    defaulted = wintypes.BOOL()
    try:
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(dacl_present),
            ctypes.byref(dacl_pointer),
            ctypes.byref(defaulted),
        ) or not dacl_present:
            raise OSError("exact DACL could not be constructed")
        if not advapi32.GetSecurityDescriptorSacl(
            descriptor,
            ctypes.byref(sacl_present),
            ctypes.byref(sacl_pointer),
            ctypes.byref(defaulted),
        ) or not sacl_present:
            raise OSError("exact mandatory label could not be constructed")
        protection = (
            _PROTECTED_DACL_SECURITY_INFORMATION
            if policy["dacl_protected"]
            else _UNPROTECTED_DACL_SECURITY_INFORMATION
        )
        status = advapi32.SetNamedSecurityInfoW(
            str(resolved),
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION
            | _LABEL_SECURITY_INFORMATION
            | protection,
            None,
            None,
            dacl_pointer,
            sacl_pointer,
        )
        if status:
            raise PermissionError(
                f"exact Windows security descriptor replacement failed: {status}"
            )
    finally:
        _kernel32().LocalFree(descriptor)
    comparison = compare_path_security(
        {**policy, "path": str(resolved)},
        read_path_security(resolved),
    )
    if comparison["result"] != "PASS":
        raise PermissionError(
            "exact Windows security descriptor replacement did not verify"
        )


def read_path_security(path: Path) -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("Windows security descriptors are unavailable")
    resolved = path.resolve(strict=True)
    advapi32 = _advapi32()
    dacl = wintypes.LPVOID()
    sacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    status = advapi32.GetNamedSecurityInfoW(
        str(resolved),
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION | _LABEL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(dacl),
        ctypes.byref(sacl),
        ctypes.byref(descriptor),
    )
    if status:
        raise PermissionError(
            f"Windows security descriptor read failed: {status}"
        )
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise OSError(
                ctypes.get_last_error(),
                "Windows security descriptor control read failed",
            )
        dacl_aces = _read_acl(dacl, mandatory=False)
        labels = _read_acl(sacl, mandatory=True)
        integrity = labels[0] if len(labels) == 1 else None
        return {
            "path": str(resolved),
            "dacl_protected": bool(
                int(control.value) & _SE_DACL_PROTECTED
            ),
            "aces": dacl_aces,
            "mandatory_integrity": integrity,
            "mandatory_label_count": len(labels),
        }
    finally:
        _kernel32().LocalFree(descriptor)


def read_path_owner_sid(path: Path) -> str:
    """Return the exact owner SID for one canonical Windows filesystem path."""
    if os.name != "nt":
        raise RuntimeError("Windows security descriptors are unavailable")
    resolved = path.resolve(strict=True)
    advapi32 = _advapi32()
    owner = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    status = advapi32.GetNamedSecurityInfoW(
        str(resolved),
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        None,
        None,
        ctypes.byref(descriptor),
    )
    if status:
        raise PermissionError(
            f"Windows path owner read failed: {status}"
        )
    try:
        if not owner.value:
            raise PermissionError("Windows path owner is unavailable")
        return _sid_string(int(owner.value))
    finally:
        _kernel32().LocalFree(descriptor)


def compare_path_security(
    expected: dict[str, Any], live: dict[str, Any]
) -> dict[str, Any]:
    expected_aces = expected.get("aces")
    live_aces = live.get("aces")
    if not isinstance(expected_aces, list) or not isinstance(live_aces, list):
        raise ValueError("security descriptor ACE collections are invalid")
    missing = _multiset_difference(expected_aces, live_aces)
    unexpected = _multiset_difference(live_aces, expected_aces)
    excessive = _excessive_rights(expected_aces, live_aces)
    inheritance: list[str] = []
    if live.get("dacl_protected") is not expected.get("dacl_protected"):
        inheritance.append("DACL protection differs")
    for expected_ace in expected_aces:
        same_trustee = [
            item
            for item in live_aces
            if item.get("trustee_sid") == expected_ace.get("trustee_sid")
            and item.get("ace_type") == expected_ace.get("ace_type")
        ]
        if same_trustee and not any(
            item.get("inheritance_flags")
            == expected_ace.get("inheritance_flags")
            and item.get("propagation_flags")
            == expected_ace.get("propagation_flags")
            and item.get("inherited") == expected_ace.get("inherited")
            for item in same_trustee
        ):
            inheritance.append(
                f"ACE inheritance differs for {expected_ace['trustee_sid']}"
            )
    duplicate_trustees = _duplicate_trustees(live_aces)
    expected_integrity = expected.get("mandatory_integrity")
    live_integrity = live.get("mandatory_integrity")
    integrity_mismatches: list[str] = []
    if live.get("mandatory_label_count") != 1:
        integrity_mismatches.append(
            "exactly one mandatory integrity label is required"
        )
    if live_integrity != expected_integrity:
        integrity_mismatches.append(
            "mandatory integrity label or policy differs"
        )
    passed = not any(
        (
            missing,
            unexpected,
            excessive,
            inheritance,
            duplicate_trustees,
            integrity_mismatches,
        )
    )
    return {
        "expected": expected,
        "live": live,
        "unexpected_aces": unexpected,
        "missing_aces": missing,
        "excessive_rights": excessive,
        "incorrect_inheritance": inheritance,
        "duplicate_trustees": duplicate_trustees,
        "integrity_mismatches": integrity_mismatches,
        "result": "PASS" if passed else "FAIL",
    }


def _read_acl(pointer: wintypes.LPVOID, *, mandatory: bool) -> list[dict[str, Any]]:
    if not pointer:
        return []
    advapi32 = _advapi32()
    information = _AclSizeInformation()
    if not advapi32.GetAclInformation(
        pointer,
        ctypes.byref(information),
        ctypes.sizeof(information),
        _ACL_SIZE_INFORMATION_CLASS,
    ):
        raise OSError(
            ctypes.get_last_error(), "Windows ACL metadata read failed"
        )
    values: list[dict[str, Any]] = []
    for index in range(int(information.AceCount)):
        ace = wintypes.LPVOID()
        if not advapi32.GetAce(pointer, index, ctypes.byref(ace)):
            raise OSError(
                ctypes.get_last_error(), "Windows ACE read failed"
            )
        if ace.value is None:
            raise ValueError("Windows ACE pointer is invalid")
        address = int(ace.value)
        header = ctypes.cast(
            address, ctypes.POINTER(_AceHeader)
        ).contents
        if mandatory:
            if header.AceType != _SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                continue
            values.append(
                _live_integrity(
                    _sid_string(address + 8),
                    int(ctypes.c_uint32.from_address(address + 4).value),
                    int(header.AceFlags),
                )
            )
        elif header.AceType in {
            _ACCESS_ALLOWED_ACE_TYPE,
            _ACCESS_DENIED_ACE_TYPE,
        }:
            values.append(
                _live_ace(
                    (
                        "allow"
                        if header.AceType == _ACCESS_ALLOWED_ACE_TYPE
                        else "deny"
                    ),
                    _sid_string(address + 8),
                    int(ctypes.c_uint32.from_address(address + 4).value),
                    int(header.AceFlags),
                )
            )
        else:
            values.append(
                {
                    "ace_type": f"unknown:{int(header.AceType)}",
                    "trustee_sid": None,
                    "rights_mask": None,
                    **_flags(int(header.AceFlags)),
                }
            )
    return values


def _expected_ace(sid: str, mask: int) -> dict[str, Any]:
    _validate_sid(sid, "trustee")
    return {
        "ace_type": "allow",
        "trustee_sid": sid,
        "rights_mask": mask,
        "inheritance_flags": ["container_inherit", "object_inherit"],
        "propagation_flags": [],
        "inherited": False,
    }


def _expected_integrity(sid: str, level: str) -> dict[str, Any]:
    return {
        "level": level,
        "trustee_sid": sid,
        "policy_mask": _NO_WRITE_UP,
        "policy_flags": ["no_write_up"],
        "inheritance_flags": ["container_inherit", "object_inherit"],
        "propagation_flags": [],
        "inherited": False,
    }


def _live_ace(
    ace_type: str, sid: str, mask: int, flags: int
) -> dict[str, Any]:
    return {
        "ace_type": ace_type,
        "trustee_sid": sid,
        "rights_mask": mask,
        **_flags(flags),
    }


def _live_integrity(sid: str, mask: int, flags: int) -> dict[str, Any]:
    levels = {
        "S-1-16-0": "untrusted",
        "S-1-16-4096": "low",
        "S-1-16-8192": "medium",
        "S-1-16-12288": "high",
        "S-1-16-16384": "system",
    }
    policy_flags = [
        name
        for bit, name in (
            (_NO_WRITE_UP, "no_write_up"),
            (_NO_READ_UP, "no_read_up"),
            (_NO_EXECUTE_UP, "no_execute_up"),
        )
        if mask & bit
    ]
    return {
        "level": levels.get(sid, "unknown"),
        "trustee_sid": sid,
        "policy_mask": mask,
        "policy_flags": policy_flags,
        **_flags(flags),
    }


def _flags(value: int) -> dict[str, Any]:
    return {
        "inheritance_flags": [
            name
            for bit, name in (
                (_CONTAINER_INHERIT_ACE, "container_inherit"),
                (_OBJECT_INHERIT_ACE, "object_inherit"),
            )
            if value & bit
        ],
        "propagation_flags": [
            name
            for bit, name in (
                (_NO_PROPAGATE_INHERIT_ACE, "no_propagate"),
                (_INHERIT_ONLY_ACE, "inherit_only"),
            )
            if value & bit
        ],
        "inherited": bool(value & _INHERITED_ACE),
    }


def _ace_sddl(value: dict[str, Any]) -> str:
    if set(value) != {
        "ace_type",
        "trustee_sid",
        "rights_mask",
        "inheritance_flags",
        "propagation_flags",
        "inherited",
    }:
        raise ValueError("Windows DACL ACE fields are invalid")
    sid = str(value["trustee_sid"])
    _validate_sid(sid, "trustee")
    ace_type = {"allow": "A", "deny": "D"}.get(str(value["ace_type"]))
    if ace_type is None:
        raise ValueError("Windows DACL ACE type is invalid")
    mask = value["rights_mask"]
    if not isinstance(mask, int) or mask <= 0 or mask > 0xFFFFFFFF:
        raise ValueError("Windows DACL rights mask is invalid")
    flags = _sddl_flags(value)
    return f"({ace_type};{flags};0x{mask:08x};;;{sid})"


def _integrity_sddl(value: dict[str, Any]) -> str:
    sid = str(value.get("trustee_sid", ""))
    _validate_sid(sid, "mandatory integrity")
    mask = value.get("policy_mask")
    if not isinstance(mask, int) or mask <= 0 or mask > 0x7:
        raise ValueError("mandatory integrity policy mask is invalid")
    rights = "".join(
        name
        for bit, name in (
            (_NO_WRITE_UP, "NW"),
            (_NO_READ_UP, "NR"),
            (_NO_EXECUTE_UP, "NX"),
        )
        if mask & bit
    )
    return f"(ML;{_sddl_flags(value)};{rights};;;{sid})"


def _sddl_flags(value: dict[str, Any]) -> str:
    inheritance = value.get("inheritance_flags")
    propagation = value.get("propagation_flags")
    if not isinstance(inheritance, list) or not isinstance(propagation, list):
        raise ValueError("Windows ACE inheritance fields are invalid")
    allowed_inheritance = {"container_inherit": "CI", "object_inherit": "OI"}
    allowed_propagation = {"no_propagate": "NP", "inherit_only": "IO"}
    if (
        any(item not in allowed_inheritance for item in inheritance)
        or any(item not in allowed_propagation for item in propagation)
        or value.get("inherited") is not False
    ):
        raise ValueError("Windows ACE inheritance policy is invalid")
    return "".join(
        allowed_inheritance[item]
        for item in ("container_inherit", "object_inherit")
        if item in inheritance
    ) + "".join(
        allowed_propagation[item]
        for item in ("no_propagate", "inherit_only")
        if item in propagation
    )


def _security_descriptor_from_sddl(value: str) -> wintypes.LPVOID:
    descriptor = wintypes.LPVOID()
    if not _advapi32().ConvertStringSecurityDescriptorToSecurityDescriptorW(
        value, 1, ctypes.byref(descriptor), None
    ):
        raise OSError(
            ctypes.get_last_error(),
            "Windows security descriptor construction failed",
        )
    return descriptor


def _sid_string(pointer: int) -> str:
    if not _advapi32().IsValidSid(pointer):
        raise ValueError("Windows ACE trustee SID is malformed")
    value = wintypes.LPWSTR()
    if not _advapi32().ConvertSidToStringSidW(
        pointer, ctypes.byref(value)
    ):
        raise OSError(
            ctypes.get_last_error(), "Windows SID conversion failed"
        )
    try:
        return str(value.value)
    finally:
        _kernel32().LocalFree(value)


def _multiset_difference(
    left: list[dict[str, Any]], right: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    remaining = [dict(item) for item in right]
    result: list[dict[str, Any]] = []
    for item in left:
        try:
            index = remaining.index(item)
        except ValueError:
            result.append(dict(item))
        else:
            remaining.pop(index)
    return result


def _excessive_rights(
    expected: list[dict[str, Any]], live: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in live:
        mask = item.get("rights_mask")
        if not isinstance(mask, int):
            continue
        candidates = [
            candidate
            for candidate in expected
            if candidate.get("trustee_sid") == item.get("trustee_sid")
            and candidate.get("ace_type") == item.get("ace_type")
            and isinstance(candidate.get("rights_mask"), int)
        ]
        if candidates and all(
            mask & ~int(candidate["rights_mask"]) for candidate in candidates
        ):
            results.append(dict(item))
    return results


def _duplicate_trustees(aces: list[dict[str, Any]]) -> list[str]:
    values = [
        str(item.get("trustee_sid"))
        for item in aces
        if item.get("trustee_sid") is not None
    ]
    return sorted({sid for sid in values if values.count(sid) > 1})


def _reject_duplicate_trustees(
    aces: list[dict[str, Any]], label: str
) -> None:
    duplicates = _duplicate_trustees(aces)
    if duplicates:
        raise ValueError(
            f"{label} contains duplicate trustees: {','.join(duplicates)}"
        )


def _unavailable_attestation(
    expected: dict[str, Any], error_type: str
) -> dict[str, Any]:
    return {
        "expected": expected,
        "live": None,
        "unexpected_aces": [],
        "missing_aces": [],
        "excessive_rights": [],
        "incorrect_inheritance": [],
        "duplicate_trustees": [],
        "integrity_mismatches": [],
        "unavailable_reason": error_type,
        "result": "INDETERMINATE",
    }


def _unavailable_policy_attestation(
    expected: dict[str, Any], error_type: str
) -> dict[str, Any]:
    paths = {
        name: _unavailable_attestation(expected[name], error_type)
        for name in ("service_root", "client_exchange")
    }
    return {
        "schema_version": 1,
        "expected_policy": expected,
        "expected_policy_sha256": _canonical_sha256(expected),
        "live_policy": {
            "service_root": None,
            "client_exchange": None,
        },
        "live_policy_sha256": None,
        "paths": paths,
        "result": "INDETERMINATE",
    }


def _aggregate(results: Any) -> str:
    values = list(results)
    if any(value == "FAIL" for value in values):
        return "FAIL"
    if any(value == "INDETERMINATE" for value in values):
        return "INDETERMINATE"
    if any(value not in _RESULTS for value in values):
        raise ValueError("Windows security attestation result is invalid")
    return "PASS"


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _validate_sid(value: str, label: str) -> None:
    if not isinstance(value, str) or not _SID.fullmatch(value):
        raise ValueError(f"{label} SID is invalid")


def _require_resolved_trustees(policy: dict[str, Any]) -> None:
    if os.name != "nt":
        raise RuntimeError("Windows trustee resolution is unavailable")
    trustees = {
        str(ace["trustee_sid"])
        for name in ("service_root", "client_exchange")
        for ace in policy[name]["aces"]
    }
    for sid in sorted(trustees):
        _resolved_account_name(sid)


def _resolved_account_name(sid: str) -> str:
    _validate_sid(sid, "trustee")
    advapi32 = _advapi32()
    pointer = wintypes.LPVOID()
    if not advapi32.ConvertStringSidToSidW(
        sid, ctypes.byref(pointer)
    ):
        raise ValueError("Windows trustee SID cannot be converted")
    try:
        name_size = wintypes.DWORD()
        domain_size = wintypes.DWORD()
        sid_type = wintypes.DWORD()
        advapi32.LookupAccountSidW(
            None,
            pointer,
            None,
            ctypes.byref(name_size),
            None,
            ctypes.byref(domain_size),
            ctypes.byref(sid_type),
        )
        error = ctypes.get_last_error()
        if error != _ERROR_INSUFFICIENT_BUFFER:
            raise ValueError(f"Windows trustee SID is unresolved: {sid}")
        name = ctypes.create_unicode_buffer(name_size.value)
        domain = ctypes.create_unicode_buffer(domain_size.value)
        if not advapi32.LookupAccountSidW(
            None,
            pointer,
            name,
            ctypes.byref(name_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(sid_type),
        ):
            raise ValueError(f"Windows trustee SID is unresolved: {sid}")
        return (
            f"{domain.value}\\{name.value}"
            if domain.value
            else name.value
        )
    finally:
        _kernel32().LocalFree(pointer)


def _kernel32() -> Any:
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    return kernel32


def _advapi32() -> Any:
    advapi32: Any = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorSacl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorSacl.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
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
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.LookupAccountSidW.restype = wintypes.BOOL
    return advapi32
