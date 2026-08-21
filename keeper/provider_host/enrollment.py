from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping, cast

from keeper.provider_host.protocol import (
    HOST_PROTOCOL,
    EnvelopeVerifier,
    parse_utc,
    require_sha256,
    structured_digest,
)


ENROLLMENT_PROPOSAL_PURPOSE = "keeper-provider-host-enrollment-proposal"
ENROLLMENT_GRANT_PURPOSE = "keeper-provider-host-enrollment-grant"
ENROLLMENT_PROOF_PURPOSE = "keeper-provider-host-enrollment-proof"
ENROLLMENT_RECEIPT_PURPOSE = "keeper-provider-host-enrollment-receipt"
ENROLLMENT_REVOCATION_PURPOSE = "keeper-provider-host-enrollment-revocation"
MAXIMUM_ENROLLMENT_TTL = timedelta(minutes=2)
MAXIMUM_FUTURE_SKEW = timedelta(seconds=5)


_PROPOSAL_FIELDS = {
    "authority_protocol_version",
    "authority_schema_version",
    "enrollment_generation",
    "expires_at",
    "host_id",
    "host_key_name",
    "host_protocol",
    "host_public_identity",
    "installation",
    "issued_at",
    "output_root",
    "pipe_name",
    "proposal_nonce",
    "schema_version",
    "service_key_id",
    "state_root",
    "user_binding",
}
_INSTALLATION_FIELDS = {
    "authenticode_binding",
    "executable_file_identity",
    "executable_path",
    "executable_sha256",
    "executable_size",
    "install_root",
    "manifest_sha256",
    "package_version",
}
_FILE_IDENTITY_FIELDS = {
    "device_id",
    "file_id",
    "modified_ns",
    "schema_version",
    "size",
}
_AUTHENTICODE_FIELDS = {
    "certificate_thumbprint",
    "publisher_subject",
    "source",
    "status",
}
_USER_BINDING_FIELDS = {"profile_path", "session_id", "user_sid"}
_PUBLIC_IDENTITY_FIELDS = {
    "algorithm",
    "exponent",
    "identity",
    "key_id",
    "modulus",
    "schema_version",
}
_GRANT_FIELDS = {
    "authority_id",
    "authority_protocol_version",
    "authority_public_identity",
    "authority_schema_version",
    "challenge",
    "enrollment_generation",
    "enrollment_id",
    "expires_at",
    "host_id",
    "host_protocol",
    "issued_at",
    "proposal_digest",
    "sequence",
    "service_key_id",
    "state",
}
_PROOF_FIELDS = {
    "authority_id",
    "challenge",
    "enrollment_generation",
    "enrollment_id",
    "grant_digest",
    "host_id",
    "host_public_key_id",
    "issued_at",
    "nonce",
    "proposal_digest",
    "sequence",
}
_RECEIPT_FIELDS = {
    "activated_at",
    "authority_id",
    "authority_key_id",
    "authority_protocol_version",
    "authority_schema_version",
    "enrollment_generation",
    "enrollment_id",
    "grant_digest",
    "host_id",
    "host_protocol",
    "host_public_key_id",
    "proof_digest",
    "proposal_digest",
    "runtime_configuration",
    "service_key_id",
    "state",
}
_REVOCATION_FIELDS = {
    "authority_id",
    "authority_key_id",
    "enrollment_generation",
    "enrollment_id",
    "host_id",
    "receipt_digest",
    "revoked_at",
    "service_key_id",
    "state",
}
_RUNTIME_CONFIGURATION_FIELDS = {
    "authority_id",
    "authority_peer",
    "authority_public_identity",
    "enrollment_id",
    "host_id",
    "host_key_name",
    "host_public_identity",
    "output_root",
    "pipe_name",
    "schema_version",
    "state_root",
    "user_binding",
}


def stable_host_identity(
    user_sid: str, manifest_sha256: str
) -> tuple[str, str]:
    binding = hashlib.sha256(
        (user_sid.casefold() + ":" + manifest_sha256.casefold()).encode("utf-8")
    ).hexdigest()
    return (
        "keeper-provider-host:" + binding,
        "DarkSage.KeeperProviderHost." + binding,
    )
_AUTHORITY_PEER_FIELDS = {
    "executable_file_identity",
    "executable_path",
    "executable_sha256",
    "session_id",
    "user_sid",
}


def validate_enrollment_proposal(
    record: Mapping[str, Any],
    *,
    expected_authority_protocol: int,
    expected_authority_schema: int,
    expected_service_key_id: str,
    verifier: EnvelopeVerifier | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate a Host-signed, execution-inert enrollment proposal."""
    payload = (
        verifier.verify(record, purpose=ENROLLMENT_PROPOSAL_PURPOSE)
        if verifier is not None
        else dict(record)
    )
    _exact(payload, _PROPOSAL_FIELDS, "enrollment proposal")
    if (
        payload.get("schema_version") != 1
        or payload.get("host_protocol") != HOST_PROTOCOL
        or payload.get("authority_protocol_version")
        != expected_authority_protocol
        or payload.get("authority_schema_version")
        != expected_authority_schema
        or payload.get("service_key_id") != expected_service_key_id
    ):
        raise PermissionError("Provider Host enrollment compatibility differs")
    _positive_integer(payload.get("enrollment_generation"), "enrollment generation")
    for name in (
        "host_id", "host_key_name", "pipe_name", "proposal_nonce",
        "state_root", "output_root",
    ):
        _text(payload.get(name), f"enrollment {name}")
    _lifetime(payload, now=now)
    _exact(payload.get("user_binding"), _USER_BINDING_FIELDS, "enrollment user binding")
    user_binding = cast(dict[str, Any], payload["user_binding"])
    if not str(user_binding.get("user_sid", "")).startswith("S-1-"):
        raise PermissionError("Provider Host enrollment user SID is invalid")
    _positive_integer(user_binding.get("session_id"), "Windows session", allow_zero=True)
    _text(user_binding.get("profile_path"), "profile path")
    _exact(payload.get("installation"), _INSTALLATION_FIELDS, "enrollment installation")
    installation = cast(dict[str, Any], payload["installation"])
    for name in ("executable_path", "install_root", "package_version"):
        _text(installation.get(name), f"installation {name}")
    require_sha256(installation.get("executable_sha256"), "enrollment executable digest")
    require_sha256(installation.get("manifest_sha256"), "enrollment manifest digest")
    size = installation.get("executable_size")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise PermissionError("Provider Host enrollment executable size is invalid")
    _exact(
        installation.get("executable_file_identity"),
        _FILE_IDENTITY_FIELDS,
        "enrollment executable identity",
    )
    file_identity = cast(dict[str, Any], installation["executable_file_identity"])
    if file_identity.get("schema_version") != 1:
        raise PermissionError("Provider Host enrollment file identity schema is invalid")
    for value in file_identity.values():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PermissionError("Provider Host enrollment file identity is invalid")
    if file_identity.get("size") != size:
        raise PermissionError("Provider Host enrollment file size binding differs")
    _exact(
        installation.get("authenticode_binding"),
        _AUTHENTICODE_FIELDS,
        "enrollment Authenticode binding",
    )
    authenticode = cast(dict[str, Any], installation["authenticode_binding"])
    if authenticode.get("source") != "windows-authenticode":
        raise PermissionError("Provider Host enrollment signer source is invalid")
    status = authenticode.get("status")
    thumbprint = authenticode.get("certificate_thumbprint")
    publisher = authenticode.get("publisher_subject")
    if status == "Valid":
        if (
            not isinstance(thumbprint, str)
            or len(thumbprint) != 40
            or any(character not in "0123456789ABCDEF" for character in thumbprint)
            or not isinstance(publisher, str)
            or not publisher
        ):
            raise PermissionError("Provider Host enrollment signer identity is invalid")
    elif status == "NotSigned":
        if thumbprint is not None or publisher is not None:
            raise PermissionError("Unsigned Provider Host identity is malformed")
    else:
        raise PermissionError("Provider Host enrollment signature status is invalid")
    _validate_public_identity(payload.get("host_public_identity"), str(payload["host_id"]))
    return _copy(payload)


def validate_enrollment_grant(
    record: Mapping[str, Any],
    verifier: EnvelopeVerifier,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    payload = verifier.verify(record, purpose=ENROLLMENT_GRANT_PURPOSE)
    _exact(payload, _GRANT_FIELDS, "enrollment grant")
    if payload.get("state") != "PENDING" or payload.get("host_protocol") != HOST_PROTOCOL:
        raise PermissionError("Provider Host enrollment grant state is invalid")
    for name in (
        "authority_id", "challenge", "enrollment_id", "host_id",
        "proposal_digest", "service_key_id",
    ):
        _text(payload.get(name), f"enrollment grant {name}")
    require_sha256(payload.get("proposal_digest"), "enrollment proposal digest")
    for name in ("sequence", "enrollment_generation", "authority_protocol_version", "authority_schema_version"):
        _positive_integer(payload.get(name), f"enrollment grant {name}")
    _validate_public_identity(payload.get("authority_public_identity"), str(payload["authority_id"]))
    _lifetime(payload, now=now)
    return _copy(payload)


def validate_enrollment_proof(
    record: Mapping[str, Any],
    verifier: EnvelopeVerifier,
    grant: Mapping[str, Any],
    *,
    expected_grant_digest: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    _lifetime(grant, now=now)
    payload = verifier.verify(record, purpose=ENROLLMENT_PROOF_PURPOSE)
    _exact(payload, _PROOF_FIELDS, "enrollment proof")
    for name in _PROOF_FIELDS - {"enrollment_generation", "sequence"}:
        _text(payload.get(name), f"enrollment proof {name}")
    _positive_integer(payload.get("enrollment_generation"), "proof enrollment generation")
    _positive_integer(payload.get("sequence"), "proof sequence")
    for name in ("grant_digest", "proposal_digest"):
        require_sha256(payload.get(name), f"enrollment proof {name}")
    comparisons = {
        "authority_id": grant.get("authority_id"),
        "challenge": grant.get("challenge"),
        "enrollment_generation": grant.get("enrollment_generation"),
        "enrollment_id": grant.get("enrollment_id"),
        "host_id": grant.get("host_id"),
        "proposal_digest": grant.get("proposal_digest"),
        "grant_digest": expected_grant_digest or structured_digest(grant),
    }
    if any(payload.get(name) != expected for name, expected in comparisons.items()):
        raise PermissionError("Provider Host enrollment proof binding differs")
    observed_now = (now or datetime.now(UTC)).astimezone(UTC)
    issued = parse_utc(payload["issued_at"])
    if issued > observed_now + MAXIMUM_FUTURE_SKEW or issued < observed_now - MAXIMUM_ENROLLMENT_TTL:
        raise PermissionError("Provider Host enrollment proof is stale")
    return _copy(payload)


def validate_enrollment_receipt(
    record: Mapping[str, Any],
    verifier: EnvelopeVerifier,
    *,
    expected_enrollment_id: str,
) -> dict[str, Any]:
    payload = verifier.verify(record, purpose=ENROLLMENT_RECEIPT_PURPOSE)
    _exact(payload, _RECEIPT_FIELDS, "enrollment receipt")
    if (
        payload.get("state") != "ACTIVE"
        or payload.get("enrollment_id") != expected_enrollment_id
        or payload.get("host_protocol") != HOST_PROTOCOL
    ):
        raise PermissionError("Provider Host enrollment receipt identity differs")
    for name in (
        "authority_id", "authority_key_id", "enrollment_id", "host_id",
        "host_public_key_id", "service_key_id",
    ):
        _text(payload.get(name), f"enrollment receipt {name}")
    for name in ("grant_digest", "proof_digest", "proposal_digest"):
        require_sha256(payload.get(name), f"enrollment receipt {name}")
    for name in ("authority_protocol_version", "authority_schema_version", "enrollment_generation"):
        _positive_integer(payload.get(name), f"enrollment receipt {name}")
    parse_utc(payload.get("activated_at"))
    _exact(
        payload.get("runtime_configuration"),
        _RUNTIME_CONFIGURATION_FIELDS,
        "enrollment runtime configuration",
    )
    runtime = cast(dict[str, Any], payload["runtime_configuration"])
    if (
        runtime.get("schema_version") != 2
        or runtime.get("enrollment_id") != expected_enrollment_id
        or runtime.get("host_id") != payload.get("host_id")
        or runtime.get("authority_id") != payload.get("authority_id")
    ):
        raise PermissionError("Provider Host runtime enrollment identity differs")
    _validate_public_identity(
        runtime.get("authority_public_identity"), str(runtime["authority_id"])
    )
    _validate_public_identity(
        runtime.get("host_public_identity"), str(runtime["host_id"])
    )
    _exact(runtime.get("user_binding"), _USER_BINDING_FIELDS, "runtime user binding")
    runtime_binding = cast(dict[str, Any], runtime["user_binding"])
    if (
        not str(runtime_binding.get("user_sid", "")).startswith("S-1-")
        or isinstance(runtime_binding.get("session_id"), bool)
        or not isinstance(runtime_binding.get("session_id"), int)
        or cast(int, runtime_binding["session_id"]) < 0
    ):
        raise PermissionError("Provider Host runtime user binding is invalid")
    _text(runtime_binding.get("profile_path"), "runtime profile path")
    _exact(runtime.get("authority_peer"), _AUTHORITY_PEER_FIELDS, "Authority peer")
    peer = cast(dict[str, Any], runtime["authority_peer"])
    _text(peer.get("executable_path"), "Authority peer executable")
    _text(peer.get("user_sid"), "Authority peer SID")
    require_sha256(peer.get("executable_sha256"), "Authority peer digest")
    _positive_integer(peer.get("session_id"), "Authority peer session", allow_zero=True)
    _exact(peer.get("executable_file_identity"), _FILE_IDENTITY_FIELDS, "Authority peer file identity")
    for name in ("host_key_name", "output_root", "pipe_name", "state_root"):
        _text(runtime.get(name), f"runtime {name}")
    return _copy(payload)


def validate_enrollment_revocation(
    record: Mapping[str, Any],
    verifier: EnvelopeVerifier,
    *,
    expected_enrollment_id: str,
    expected_receipt_digest: str,
) -> dict[str, Any]:
    """Validate an Authority-signed, execution-denying Host revocation."""
    payload = verifier.verify(record, purpose=ENROLLMENT_REVOCATION_PURPOSE)
    _exact(payload, _REVOCATION_FIELDS, "enrollment revocation")
    if (
        payload.get("state") != "REVOKED"
        or payload.get("enrollment_id") != expected_enrollment_id
        or payload.get("receipt_digest") != expected_receipt_digest
    ):
        raise PermissionError("Provider Host enrollment revocation identity differs")
    for name in (
        "authority_id",
        "authority_key_id",
        "enrollment_id",
        "host_id",
        "service_key_id",
    ):
        _text(payload.get(name), f"enrollment revocation {name}")
    _positive_integer(
        payload.get("enrollment_generation"), "revocation enrollment generation"
    )
    require_sha256(payload.get("receipt_digest"), "revocation receipt digest")
    parse_utc(payload.get("revoked_at"))
    return _copy(payload)


def redacted_enrollment_status(record: Mapping[str, Any] | None) -> dict[str, Any]:
    if record is None:
        return {
            "installed": False,
            "online": False,
            "state": "NOT_INSTALLED",
            "protocol": HOST_PROTOCOL,
            "protocol_compatible": True,
            "provider_state": "UNAVAILABLE",
            "founder_action_required": "INSTALL_PROVIDER_HOST",
        }
    state = str(record.get("service_state", record.get("state", "UNCERTAIN")))
    public_state = {
        "PENDING": "ENROLLMENT_PENDING",
        "ACTIVE": "ENROLLED_OFFLINE",
        "REVOKED": "REVOKED",
        "EXPIRED": "ENROLLMENT_EXPIRED",
        "UNCERTAIN": "UNCERTAIN",
    }.get(state, "UNCERTAIN")
    action = {
        "PENDING": "COMPLETE_OR_RECONCILE_PROVIDER_HOST_ENROLLMENT",
        "ACTIVE": "START_PROVIDER_HOST",
        "REVOKED": "CREATE_NEW_PROVIDER_HOST_ENROLLMENT",
        "EXPIRED": "CREATE_NEW_PROVIDER_HOST_ENROLLMENT",
        "UNCERTAIN": "RECONCILE_PROVIDER_HOST_ENROLLMENT",
    }.get(state, "RECONCILE_PROVIDER_HOST_ENROLLMENT")
    if state == "UNCERTAIN" and record.get("uncertainty_kind") == "REVOCATION":
        action = "COMPLETE_PROVIDER_HOST_REVOCATION"
    return {
        "installed": True,
        "online": False,
        "state": public_state,
        "protocol": HOST_PROTOCOL,
        "protocol_compatible": True,
        "provider_state": "UNAVAILABLE",
        "enrollment_id": record.get("enrollment_id"),
        "enrollment_generation": record.get("enrollment_generation"),
        "founder_action_required": action,
    }


def _validate_public_identity(value: object, expected_identity: str) -> None:
    _exact(value, _PUBLIC_IDENTITY_FIELDS, "enrollment public identity")
    public = cast(dict[str, Any], value)
    if (
        public.get("schema_version") != 1
        or public.get("algorithm") != "RSA-PKCS1-SHA256"
        or public.get("identity") != expected_identity
        or not isinstance(public.get("key_id"), str)
        or not public["key_id"]
        or not all(isinstance(public.get(name), str) and public[name] for name in ("modulus", "exponent"))
    ):
        raise PermissionError("Provider Host enrollment public identity is invalid")


def _lifetime(value: Mapping[str, Any], *, now: datetime | None) -> None:
    issued = parse_utc(value.get("issued_at"))
    expires = parse_utc(value.get("expires_at"))
    observed = (now or datetime.now(UTC)).astimezone(UTC)
    if (
        issued > observed + MAXIMUM_FUTURE_SKEW
        or expires <= observed
        or expires <= issued
        or expires - issued > MAXIMUM_ENROLLMENT_TTL
    ):
        raise PermissionError("Provider Host enrollment lifetime is invalid")


def _exact(value: object, fields: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise PermissionError(f"Provider Host {label} fields are invalid")


def _positive_integer(value: object, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise PermissionError(f"Provider Host {label} is invalid")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PermissionError(f"Provider Host {label} is invalid")
    return value


def _copy(value: Mapping[str, Any]) -> dict[str, Any]:
    # Canonical digestability is validated by structured_digest; this also rejects
    # non-finite numbers and non-JSON objects before crossing a trust boundary.
    structured_digest(value)
    return cast(dict[str, Any], json.loads(json.dumps(value)))
