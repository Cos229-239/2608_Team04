from __future__ import annotations

import os
import re
from ctypes import wintypes

from keeper.authority_service import process_security as security
from keeper.authority_service.windows_identity import (
    require_current_restricted_service_identity,
)


_WINDOWS_USER_SID = re.compile(r"S-1-5-21-(?:\d+-){3}\d+")
_RESTRICTED_CODE_SID = "S-1-5-12"


def ensure_current_process_host_query_access(
    host_user_sid: str,
    *,
    service_sid: str,
) -> security.ProcessSecuritySnapshot:
    """Apply Authority-only Host observation access to this service process.

    Keeping this service startup policy outside the shared process-security
    primitives prevents the per-user Provider Host artifact from embedding
    code that mutates the Authority process DACL. The exact restricted service
    identity is still revalidated immediately before the closed DACL delta.
    """
    if os.name != "nt":
        raise RuntimeError("Windows process security is unavailable")
    if not security._SERVICE_SID.fullmatch(service_sid):
        raise security.ProcessSecurityError(
            security.ProcessSecurityStage.VALIDATE_IDENTITY,
            "KeeperAuthority service SID is invalid",
        )
    if (
        not _WINDOWS_USER_SID.fullmatch(host_user_sid)
        or security._SERVICE_SID.fullmatch(host_user_sid)
        or host_user_sid.casefold() in {"s-1-5-18", "s-1-5-12"}
    ):
        raise security.ProcessSecurityError(
            security.ProcessSecurityStage.VALIDATE_IDENTITY,
            "Provider Host user SID is invalid",
        )
    try:
        require_current_restricted_service_identity(service_sid)
    except (OSError, PermissionError, RuntimeError, ValueError) as error:
        raise security.ProcessSecurityError(
            security.ProcessSecurityStage.VALIDATE_IDENTITY,
            "KeeperAuthority process security identity differs",
        ) from error
    with security._current_process_security_handle(
        security._READ_CONTROL | security._WRITE_DAC
    ) as handle:
        return _ensure_kernel_object_host_query_access(
            handle,
            host_user_sid=host_user_sid,
        )


def _ensure_kernel_object_host_query_access(
    handle: wintypes.HANDLE,
    *,
    host_user_sid: str,
) -> security.ProcessSecuritySnapshot:
    """Apply the exact deny-Restricted-Code/allow-Host-user QLI delta."""
    before = security.read_current_process_security(handle)
    if not security._canonical_ace_order(before.aces):
        raise security.ProcessSecurityError(
            security.ProcessSecurityStage.VALIDATE_EXISTING_GRANT,
            "Provider Host user process DACL ordering is not canonical",
        )

    restricted_deny = security.ProcessAce(
        "deny",
        _RESTRICTED_CODE_SID,
        security.PROCESS_QUERY_LIMITED_INFORMATION,
        0,
    )
    host_allow = security.ProcessAce(
        "allow",
        host_user_sid,
        security.PROCESS_QUERY_LIMITED_INFORMATION,
        0,
    )
    restricted_matches = [
        ace
        for ace in before.aces
        if ace.trustee_sid.casefold() == _RESTRICTED_CODE_SID.casefold()
    ]
    host_matches = [
        ace
        for ace in before.aces
        if ace.trustee_sid.casefold() == host_user_sid.casefold()
    ]
    if restricted_matches or host_matches:
        if (
            restricted_matches != [restricted_deny]
            or host_matches != [host_allow]
        ):
            raise security.ProcessSecurityError(
                security.ProcessSecurityStage.VALIDATE_EXISTING_GRANT,
                "Provider Host process grants are incomplete, ambiguous, or broad",
            )
        return before

    first_explicit_allow = next(
        (
            index
            for index, ace in enumerate(before.aces)
            if not ace.flags & security._INHERITED_ACE and ace.ace_type == "allow"
        ),
        next(
            (
                index
                for index, ace in enumerate(before.aces)
                if ace.flags & security._INHERITED_ACE
            ),
            len(before.aces),
        ),
    )
    with_deny = (
        before.aces[:first_explicit_allow]
        + (restricted_deny,)
        + before.aces[first_explicit_allow:]
    )
    first_inherited = next(
        (
            index
            for index, ace in enumerate(with_deny)
            if ace.flags & security._INHERITED_ACE
        ),
        len(with_deny),
    )
    expected_aces = (
        with_deny[:first_inherited]
        + (host_allow,)
        + with_deny[first_inherited:]
    )
    if not security._canonical_ace_order(expected_aces):
        raise security.ProcessSecurityError(
            security.ProcessSecurityStage.BUILD_DACL,
            "Provider Host process DACL delta is not canonical",
        )
    security._write_current_process_dacl(expected_aces, handle=handle)
    after = security.read_current_process_security(handle)
    if (
        after.owner_sid.casefold() != before.owner_sid.casefold()
        or after.group_sid.casefold() != before.group_sid.casefold()
        or after.control != before.control
        or after.revision != before.revision
        or after.dacl_defaulted != before.dacl_defaulted
        or after.aces != expected_aces
    ):
        raise security.ProcessSecurityError(
            security.ProcessSecurityStage.VERIFY_DACL,
            "Provider Host process security delta did not verify exactly",
        )
    return after
