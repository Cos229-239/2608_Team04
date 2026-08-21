from __future__ import annotations

import copy
import ctypes
import hashlib
import os
import subprocess
from ctypes import wintypes
from pathlib import Path
from typing import Any, Callable

import pytest

from keeper.authority_service import windows_security as _windows_security
from keeper.authority_service.windows_identity import current_process_sid
from keeper.authority_service.windows_security import (
    apply_path_security,
    attest_authority_security,
    compare_path_security,
    enforce_authority_security,
    expected_authority_security,
    read_path_owner_sid,
)


_EVERYONE = "S-1-1-0"
_USERS = "S-1-5-32-545"
_AUTHENTICATED_USERS = "S-1-5-11"
_UNKNOWN_LOCAL = "S-1-5-21-111111111-222222222-333333333-4444"
_UNKNOWN_DOMAIN = "S-1-5-21-987654321-876543210-765432109-5555"
_PROVIDER = "S-1-5-20"
_CLIENT = "S-1-5-19"


def _expected(tmp_path: Path) -> dict[str, Any]:
    return expected_authority_security(
        service_root=tmp_path / "AuthorityService",
        exchange_root=tmp_path / "ClientExchange",
        service_sid="S-1-5-21-111111111-222222222-333333333-1003",
        client_sid=_CLIENT,
        provider_sid=_PROVIDER,
    )


def _live(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        **copy.deepcopy(policy),
        "mandatory_label_count": 1,
    }


def _allow(sid: str, mask: int) -> dict[str, Any]:
    return {
        "ace_type": "allow",
        "trustee_sid": sid,
        "rights_mask": mask,
        "inheritance_flags": ["container_inherit", "object_inherit"],
        "propagation_flags": [],
        "inherited": False,
    }


@pytest.mark.skipif(os.name != "nt", reason="Windows owner SID requires Windows")
def test_path_owner_sid_uses_documented_security_descriptor_boundary(
    tmp_path: Path,
) -> None:
    target = tmp_path / "owner-probe"
    target.write_bytes(b"fixture")

    assert read_path_owner_sid(target) == current_process_sid()


def _deny(sid: str, mask: int) -> dict[str, Any]:
    return {**_allow(sid, mask), "ace_type": "deny"}


def _apply_raw_corrupt_policy(
    path: Path, policy: dict[str, Any]
) -> None:
    dacl = "".join(
        _windows_security._ace_sddl(item)
        for item in policy["aces"]
    )
    label = _windows_security._integrity_sddl(
        policy["mandatory_integrity"]
    )
    descriptor = _windows_security._security_descriptor_from_sddl(
        f"D:P{dacl}S:{label}"
    )
    dacl_pointer = wintypes.LPVOID()
    sacl_pointer = wintypes.LPVOID()
    present = wintypes.BOOL()
    defaulted = wintypes.BOOL()
    api = _windows_security._advapi32()
    try:
        assert api.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(dacl_pointer),
            ctypes.byref(defaulted),
        )
        assert api.GetSecurityDescriptorSacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(sacl_pointer),
            ctypes.byref(defaulted),
        )
        status = api.SetNamedSecurityInfoW(
            str(path),
            1,
            0x00000004 | 0x00000010 | 0x80000000,
            None,
            None,
            dacl_pointer,
            sacl_pointer,
        )
        assert status == 0
    finally:
        _windows_security._kernel32().LocalFree(descriptor)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda live, expected: live["aces"].append(
            _allow(_EVERYONE, 0x001F01FF)
        ),
        lambda live, expected: live["aces"].append(
            _allow(_USERS, 0x001301BF)
        ),
        lambda live, expected: live["aces"].append(
            _allow(_AUTHENTICATED_USERS, 0x00120089)
        ),
        lambda live, expected: live["aces"].append(
            _allow(_PROVIDER, 0x001301BF)
        ),
        lambda live, expected: live["aces"].append(
            _allow(_UNKNOWN_LOCAL, 0x00120089)
        ),
        lambda live, expected: live["aces"].append(
            _allow(_UNKNOWN_DOMAIN, 0x00120089)
        ),
        lambda live, expected: live["aces"].append(
            {
                **copy.deepcopy(expected["aces"][-1]),
                "rights_mask": 0x001F01FF,
            }
        ),
        lambda live, expected: live["aces"].append(
            {
                **_allow(_EVERYONE, 0x001F01FF),
                "inherited": True,
            }
        ),
        lambda live, expected: live["aces"].append(
            _deny(_EVERYONE, 0x00120089)
        ),
        lambda live, expected: live["aces"][-1].update(
            {"inheritance_flags": []}
        ),
        lambda live, expected: live.update({"dacl_protected": False}),
        lambda live, expected: live["aces"].pop(),
        lambda live, expected: live["mandatory_integrity"].update(
            {
                "level": "high",
                "trustee_sid": "S-1-16-12288",
            }
        ),
        lambda live, expected: live["mandatory_integrity"].update(
            {"policy_mask": 2, "policy_flags": ["no_read_up"]}
        ),
    ],
    ids=[
        "everyone-full",
        "users-modify",
        "authenticated-users-read",
        "provider-on-service-root",
        "unknown-local-sid",
        "unknown-domain-sid",
        "duplicate-excessive-intended",
        "inherited-unauthorized",
        "unexpected-deny",
        "wrong-inheritance-flags",
        "inheritance-enabled",
        "missing-required",
        "wrong-integrity-level",
        "missing-no-write-up",
    ],
)
def test_live_descriptor_comparison_rejects_every_required_corruption(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any], dict[str, Any]], None],
) -> None:
    expected = _expected(tmp_path)["service_root"]
    live = _live(expected)
    mutate(live, expected)

    result = compare_path_security(expected, live)

    assert result["result"] == "FAIL"
    assert any(
        result[field]
        for field in (
            "unexpected_aces",
            "missing_aces",
            "excessive_rights",
            "incorrect_inheritance",
            "duplicate_trustees",
            "integrity_mismatches",
        )
    )


def test_descriptor_read_failure_is_indeterminate(
    tmp_path: Path,
) -> None:
    result = attest_authority_security(
        service_root=tmp_path / "missing-service",
        exchange_root=tmp_path / "missing-exchange",
        service_sid=(
            current_process_sid()
            if os.name == "nt"
            else "S-1-5-21-111111111-222222222-333333333-1003"
        ),
        client_sid=_CLIENT,
        provider_sid=_PROVIDER,
    )

    assert result["result"] == "INDETERMINATE"
    assert all(
        item["result"] == "INDETERMINATE"
        for item in result["paths"].values()
    )


def test_duplicate_expected_trustees_fail_closed(tmp_path: Path) -> None:
    expected = _expected(tmp_path)["client_exchange"]
    duplicate = copy.deepcopy(expected)
    duplicate["aces"].append(copy.deepcopy(duplicate["aces"][-1]))

    with pytest.raises(ValueError, match="duplicate trustees"):
        apply_path_security(tmp_path, duplicate)


@pytest.mark.skipif(
    os.name != "nt" or not ctypes.windll.shell32.IsUserAnAdmin(),
    reason="exact Windows ACL replacement requires an elevated token",
)
@pytest.mark.parametrize(
    "mutation",
    [
        "everyone-full",
        "users-modify",
        "authenticated-users-read",
        "provider-service-access",
        "unknown-local",
        "unknown-domain",
        "unexpected-deny",
        "wrong-flags",
        "inherited-unauthorized",
        "inheritance-enabled",
        "missing-required",
        "wrong-integrity",
        "missing-no-write-up",
        "duplicate-excessive",
    ],
)
def test_production_enforcement_removes_isolated_acl_corruption(
    tmp_path: Path, mutation: str
) -> None:
    service_root = tmp_path / "AuthorityService"
    exchange_root = tmp_path / "ClientExchange"
    service_root.mkdir()
    exchange_root.mkdir()
    service_sid = current_process_sid()
    expected = expected_authority_security(
        service_root=service_root,
        exchange_root=exchange_root,
        service_sid=service_sid,
        client_sid=_CLIENT,
        provider_sid=_PROVIDER,
    )
    enforce_authority_security(
        service_root=service_root,
        exchange_root=exchange_root,
        service_sid=service_sid,
        client_sid=_CLIENT,
        provider_sid=_PROVIDER,
    )
    protected_markers = {
        name: service_root / name
        for name in (
            "authority-key-v1.bin",
            "provider-identity.bin",
            "authority.db",
            "audit-history.json",
        )
    }
    for name, path in protected_markers.items():
        path.write_bytes(f"preserve:{name}".encode("ascii"))
    before = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in protected_markers.items()
    }

    target_name = (
        "client_exchange"
        if mutation in {"users-modify", "duplicate-excessive"}
        else "service_root"
    )
    target_path = (
        exchange_root
        if target_name == "client_exchange"
        else service_root
    )
    bad = copy.deepcopy(expected[target_name])
    if mutation == "everyone-full":
        bad["aces"].append(_allow(_EVERYONE, 0x001F01FF))
    elif mutation == "users-modify":
        bad["aces"].append(_allow(_USERS, 0x001301BF))
    elif mutation == "authenticated-users-read":
        bad["aces"].append(_allow(_AUTHENTICATED_USERS, 0x00120089))
    elif mutation == "provider-service-access":
        bad["aces"].append(_allow(_PROVIDER, 0x001301BF))
    elif mutation == "unknown-local":
        bad["aces"].append(_allow(_UNKNOWN_LOCAL, 0x00120089))
    elif mutation == "unknown-domain":
        bad["aces"].append(_allow(_UNKNOWN_DOMAIN, 0x00120089))
    elif mutation == "unexpected-deny":
        bad["aces"].append(_deny(_EVERYONE, 0x00120089))
    elif mutation == "wrong-flags":
        bad["aces"][-1]["inheritance_flags"] = []
    elif mutation == "inherited-unauthorized":
        parent_result = subprocess.run(
            [
                "icacls.exe",
                str(tmp_path),
                "/grant",
                "*S-1-1-0:(OI)(CI)F",
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            timeout=30,
        )
        assert parent_result.returncode == 0, parent_result.stdout
        child_result = subprocess.run(
            ["icacls.exe", str(target_path), "/inheritance:e"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            timeout=30,
        )
        assert child_result.returncode == 0, child_result.stdout
    elif mutation == "inheritance-enabled":
        result = subprocess.run(
            ["icacls.exe", str(target_path), "/inheritance:e"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout
    elif mutation == "missing-required":
        bad["aces"].pop()
    elif mutation == "wrong-integrity":
        bad["mandatory_integrity"].update(
            {
                "level": "high",
                "trustee_sid": "S-1-16-12288",
            }
        )
    elif mutation == "missing-no-write-up":
        bad["mandatory_integrity"].update(
            {"policy_mask": 2, "policy_flags": ["no_read_up"]}
        )
    elif mutation == "duplicate-excessive":
        bad["aces"].append(
            {
                **copy.deepcopy(bad["aces"][2]),
                "rights_mask": 0x001F01FF,
            }
        )
        _apply_raw_corrupt_policy(target_path, bad)
    else:
        raise AssertionError("unknown corruption fixture")
    if mutation not in {
        "duplicate-excessive",
        "inherited-unauthorized",
        "inheritance-enabled",
    }:
        apply_path_security(target_path, bad)

    corrupted = attest_authority_security(
        service_root=service_root,
        exchange_root=exchange_root,
        service_sid=service_sid,
        client_sid=_CLIENT,
        provider_sid=_PROVIDER,
    )
    assert corrupted["result"] == "FAIL"
    if mutation == "duplicate-excessive":
        exchange = corrupted["paths"]["client_exchange"]
        assert exchange["duplicate_trustees"]
        assert exchange["excessive_rights"]
    repaired = enforce_authority_security(
        service_root=service_root,
        exchange_root=exchange_root,
        service_sid=service_sid,
        client_sid=_CLIENT,
        provider_sid=_PROVIDER,
    )

    assert repaired["result"] == "PASS"
    assert all(
        not item["unexpected_aces"]
        and not item["missing_aces"]
        and not item["excessive_rights"]
        and not item["incorrect_inheritance"]
        and not item["duplicate_trustees"]
        and not item["integrity_mismatches"]
        for item in repaired["paths"].values()
    )
    after = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in protected_markers.items()
    }
    assert after == before
