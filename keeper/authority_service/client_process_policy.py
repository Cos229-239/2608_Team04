from __future__ import annotations

import os

from keeper.authority_service import process_security as security


_RESTRICTED_CODE_SID = "S-1-5-12"
_TRANSFER_RIGHTS = (
    security.PROCESS_QUERY_LIMITED_INFORMATION | security.PROCESS_DUP_HANDLE
)


def ensure_current_process_authority_transfer_access(
    service_sid: str,
) -> security.ProcessSecuritySnapshot:
    """Deny restricted execution identities the client-transfer rights.

    This delta is applied by the authenticated desktop client immediately
    before a handle-transfer request.  The restricted KeeperAuthority primary
    token is intentionally *not* granted process access: Windows evaluates a
    ``SERVICE_SID_TYPE_RESTRICTED`` token in two passes and that grant is not a
    reliable transfer boundary.  Authority opens the exact retained pipe peer
    only on a disposable worker under the already-authenticated client token.

    Restricted provider/Host tokens retain an explicit deny for the same
    rights, including when their restricting set also contains the Founder
    user SID.  An exact grant left by the superseded policy is removed
    idempotently; every broader or ambiguous grant still fails closed.
    """
    if os.name != "nt":
        raise RuntimeError("Windows client process security is unavailable")
    if not security._SERVICE_SID.fullmatch(service_sid):
        raise security.ProcessSecurityError(
            security.ProcessSecurityStage.VALIDATE_IDENTITY,
            "KeeperAuthority service SID is invalid",
        )
    with security._current_process_security_handle(
        security._READ_CONTROL | security._WRITE_DAC
    ) as handle:
        before = security.read_current_process_security(handle)
        if not security._canonical_ace_order(before.aces):
            raise security.ProcessSecurityError(
                security.ProcessSecurityStage.VALIDATE_EXISTING_GRANT,
                "Authority client process DACL ordering is not canonical",
            )
        denied = security.ProcessAce(
            "deny", _RESTRICTED_CODE_SID, _TRANSFER_RIGHTS, 0
        )
        superseded_allow = security.ProcessAce(
            "allow", service_sid, _TRANSFER_RIGHTS, 0
        )
        restricted_matches = [
            ace
            for ace in before.aces
            if ace.trustee_sid.casefold() == _RESTRICTED_CODE_SID.casefold()
        ]
        service_matches = [
            ace
            for ace in before.aces
            if ace.trustee_sid.casefold() == service_sid.casefold()
        ]
        if restricted_matches not in ([], [denied]) or service_matches not in (
            [],
            [superseded_allow],
        ):
            raise security.ProcessSecurityError(
                security.ProcessSecurityStage.VALIDATE_EXISTING_GRANT,
                "Authority client transfer grants are ambiguous or broad",
            )
        without_superseded = tuple(
            ace
            for ace in before.aces
            if ace.trustee_sid.casefold() != service_sid.casefold()
        )
        if restricted_matches == [denied] and not service_matches:
            return before
        if restricted_matches:
            expected = without_superseded
        else:
            first_explicit_allow = next(
                (
                    index
                    for index, ace in enumerate(without_superseded)
                    if not ace.flags & security._INHERITED_ACE
                    and ace.ace_type == "allow"
                ),
                next(
                    (
                        index
                        for index, ace in enumerate(without_superseded)
                        if ace.flags & security._INHERITED_ACE
                    ),
                    len(without_superseded),
                ),
            )
            expected = (
                without_superseded[:first_explicit_allow]
                + (denied,)
                + without_superseded[first_explicit_allow:]
            )
        if not security._canonical_ace_order(expected):
            raise security.ProcessSecurityError(
                security.ProcessSecurityStage.BUILD_DACL,
                "Authority client transfer DACL delta is not canonical",
            )
        security._write_current_process_dacl(expected, handle=handle)
        after = security.read_current_process_security(handle)
        if (
            after.owner_sid.casefold() != before.owner_sid.casefold()
            or after.group_sid.casefold() != before.group_sid.casefold()
            or after.control != before.control
            or after.revision != before.revision
            or after.dacl_defaulted != before.dacl_defaulted
            or after.aces != expected
        ):
            raise security.ProcessSecurityError(
                security.ProcessSecurityStage.VERIFY_DACL,
                "Authority client transfer DACL did not verify exactly",
            )
        return after
