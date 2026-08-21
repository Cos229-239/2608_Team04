from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Mapping, cast


CAPABILITY_SCHEMA_VERSION = 1
CAPABILITY_ALGORITHM = "RS256-CNG-HIGH-PROTECTION"
TEST_CAPABILITY_ALGORITHM = "TEST-HMAC-SHA256"
CAPABILITY_PURPOSE = b"keeper-founder-authorization-capability-v1\x00"
CONFIRMATION_PURPOSE = b"keeper-founder-confirmation-v2\x00"
EXECUTIVE_INPUT_RECEIPT_PURPOSE = (
    b"keeper-executive-delivered-input-commit-receipt-v1\x00"
)
APPLICATION_IDENTITY = "KEEPER_EXECUTIVE"
_TEST_ISSUER_ID = "keeper-test-founder-issuer"
_TEST_KEY = hashlib.sha256(
    b"Keeper explicit test-only Founder capability key v1"
).digest()
_RSA_SHA256_DIGEST_INFO = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
_EXECUTIVE_INPUT_RECEIPT_FIELDS = {
    "schema_version", "kind", "receipt_id", "database_id",
    "recovery_epoch", "repository_mode", "delivered_input_id",
    "delivered_input_record_revision", "delivered_input_record_digest",
    "reviewer_attempt_id", "reviewer_assignment_id", "authority_attempt_id",
    "project_id", "charter_id", "charter_revision", "workflow_id",
    "work_item_id", "producer_assignment_id", "producer_attempt_id",
    "provider_id", "account_id", "session_id", "model_id", "workspace",
    "composition_identity", "provider_input_digest", "delivered_input_digest",
    "manifest_digest",
    "reference_set_digest", "usage_reservation_id", "session_slot_claimed",
    "launch_claim_state", "committed_at", "issued_at",
}
_SIGNED_EXECUTIVE_INPUT_RECEIPT_FIELDS = (
    _EXECUTIVE_INPUT_RECEIPT_FIELDS
    | {"issuer_id", "issuer_key_id", "signature_algorithm", "signature"}
)


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _digest(purpose: bytes, value: Mapping[str, object]) -> bytes:
    return hashlib.sha256(purpose + _canonical(value)).digest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    if not value or any(
        character not in
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        raise PermissionError("Founder capability signature is not canonical")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _validate_executive_input_receipt_unsigned(
    value: Mapping[str, object],
) -> dict[str, object]:
    if set(value) != _EXECUTIVE_INPUT_RECEIPT_FIELDS:
        raise PermissionError(
            "Executive delivered-input commit receipt fields are invalid"
        )
    receipt = dict(value)
    text_fields = _EXECUTIVE_INPUT_RECEIPT_FIELDS - {
        "schema_version", "recovery_epoch", "charter_revision",
        "delivered_input_record_revision", "session_slot_claimed",
        "usage_reservation_id",
    }
    integer_minimums = {
        "recovery_epoch": 0,
        "charter_revision": 1,
        "delivered_input_record_revision": 1,
    }
    if (
        receipt.get("schema_version") != 1
        or receipt.get("kind")
        != "executive_delivered_input_commit_receipt"
        or receipt.get("repository_mode") not in {"PRODUCTION", "TEST"}
        or receipt.get("launch_claim_state") != "LAUNCH_CLAIMED"
        or receipt.get("session_slot_claimed") is not True
        or any(
            not isinstance(receipt.get(name), str) or not str(receipt[name])
            for name in text_fields
        )
        or any(
            isinstance(receipt.get(name), bool)
            or not isinstance(receipt.get(name), int)
            or cast(int, receipt[name]) < minimum
            for name, minimum in integer_minimums.items()
        )
    ):
        raise PermissionError(
            "Executive delivered-input commit receipt is invalid"
        )
    usage_reservation_id = receipt.get("usage_reservation_id")
    if usage_reservation_id is not None and (
        not isinstance(usage_reservation_id, str) or not usage_reservation_id
    ):
        raise PermissionError(
            "Executive delivered-input usage reservation is invalid"
        )
    for name in {
        "delivered_input_record_digest", "provider_input_digest",
        "delivered_input_digest", "manifest_digest", "reference_set_digest",
    }:
        digest = receipt.get(name)
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise PermissionError(
                "Executive delivered-input commit digest is invalid"
            )
    for name in {"committed_at", "issued_at"}:
        try:
            timestamp = datetime.fromisoformat(str(receipt[name]))
        except ValueError as error:
            raise PermissionError(
                "Executive delivered-input commit time is invalid"
            ) from error
        if timestamp.tzinfo is None:
            raise PermissionError(
                "Executive delivered-input commit time is invalid"
            )
    if datetime.fromisoformat(str(receipt["committed_at"])) > (
        datetime.fromisoformat(str(receipt["issued_at"]))
    ):
        raise PermissionError(
            "Executive delivered-input commit receipt predates its record"
        )
    return receipt


def validate_executive_input_receipt(
    value: Mapping[str, object],
) -> dict[str, object]:
    if set(value) != _SIGNED_EXECUTIVE_INPUT_RECEIPT_FIELDS:
        raise PermissionError(
            "signed Executive delivered-input receipt fields are invalid"
        )
    unsigned = {
        name: value[name] for name in _EXECUTIVE_INPUT_RECEIPT_FIELDS
    }
    _validate_executive_input_receipt_unsigned(unsigned)
    for name in {
        "issuer_id", "issuer_key_id", "signature_algorithm", "signature",
    }:
        if not isinstance(value.get(name), str) or not value[name]:
            raise PermissionError(
                "signed Executive delivered-input receipt is invalid"
            )
    _unb64(str(value["signature"]))
    return dict(value)


@dataclass(frozen=True, slots=True)
class FounderCapabilityClaims:
    capability_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    authorization_kind: str
    protected_action: str
    action_digest: str
    approval_digest: str
    approval_event_digest: str
    founder_principal_sid: str
    founder_authenticated_session_id: str
    approval_event_id: str
    approval_record_id: str
    challenge_id: str
    challenge_proof_digest: str
    authorization_generation: int
    revocation_epoch: int
    issued_at: str
    expires_at: str
    usage: str
    machine_identity: str
    application_identity: str

    def __post_init__(self) -> None:
        values = asdict(self)
        if any(
            not isinstance(value, str) or not value
            for key, value in values.items()
            if key not in {"charter_revision", "authorization_generation",
                           "revocation_epoch"}
        ):
            raise ValueError("Founder capability claims require non-empty text")
        allowed_actions = {
            ("PROJECT_LAUNCH", "DELEGATE_CHARTER"),
            ("PROVIDER_HOST_ENROLLMENT", "ENROLL_PROVIDER_HOST"),
            ("PROVIDER_HOST_ENROLLMENT", "REVOKE_PROVIDER_HOST"),
            (
                "PROVIDER_HOST_ENROLLMENT",
                "RECONCILE_PROVIDER_HOST_LAUNCH",
            ),
            (
                "PROVIDER_HOST_ENROLLMENT",
                "DISPOSE_PROVIDER_REGISTRATION_FAILURE",
            ),
            (
                "PROVIDER_HOST_ENROLLMENT",
                "LEGACY_AUTHORITY_PREDISPATCH_MIGRATION",
            ),
            (
                "PROVIDER_HOST_ENROLLMENT",
                "NEW_REGISTRATION_AFTER_EXHAUSTION",
            ),
            (
                "PROVIDER_HOST_ENROLLMENT",
                "AUTHORIZE_PROVIDER_QUALIFICATION_RETRY",
            ),
        }
        if (
            self.charter_revision < 1
            or self.authorization_generation < 1
            or self.revocation_epoch != self.authorization_generation - 1
            or (self.authorization_kind, self.protected_action)
            not in allowed_actions
            or self.usage != "ONE_TIME_GENERATION"
            or self.application_identity != APPLICATION_IDENTITY
            or not self.founder_principal_sid.startswith("S-1-")
        ):
            raise ValueError("Founder capability claims are invalid")
        for value in (
            self.action_digest,
            self.approval_digest,
            self.approval_event_digest,
            self.challenge_proof_digest,
        ):
            if len(value) != 64 or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise ValueError("Founder capability digest is not canonical")
        issued = datetime.fromisoformat(self.issued_at)
        expires = datetime.fromisoformat(self.expires_at)
        if (
            issued.tzinfo is None
            or expires.tzinfo is None
            or expires <= issued
        ):
            raise ValueError("Founder capability lifetime is invalid")


@dataclass(frozen=True, slots=True)
class FounderAuthorizationCapability:
    schema_version: int
    issuer_id: str
    issuer_key_id: str
    signature_algorithm: str
    capability_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    authorization_kind: str
    protected_action: str
    action_digest: str
    approval_digest: str
    approval_event_digest: str
    founder_principal_sid: str
    founder_authenticated_session_id: str
    approval_event_id: str
    approval_record_id: str
    challenge_id: str
    challenge_proof_digest: str
    authorization_generation: int
    revocation_epoch: int
    issued_at: str
    expires_at: str
    usage: str
    machine_identity: str
    application_identity: str
    signature: str

    def __post_init__(self) -> None:
        if self.schema_version != CAPABILITY_SCHEMA_VERSION:
            raise ValueError("Founder capability schema is unsupported")
        FounderCapabilityClaims(**self.claims())
        if not self.issuer_id or not self.issuer_key_id or not self.signature:
            raise ValueError("Founder capability authentication is missing")

    def claims(self) -> dict[str, Any]:
        value = asdict(self)
        for key in (
            "schema_version",
            "issuer_id",
            "issuer_key_id",
            "signature_algorithm",
            "signature",
        ):
            value.pop(key)
        return value

    def unsigned(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature")
        return value

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, object]
    ) -> FounderAuthorizationCapability:
        expected = set(cls.__dataclass_fields__)
        if set(value) != expected:
            raise ValueError("Founder capability fields are invalid")
        return cls(**cast(Any, dict(value)))


def capability_digest(capability: FounderAuthorizationCapability) -> str:
    return hashlib.sha256(_canonical(capability.to_dict())).hexdigest()


def capability_signature_digest(
    capability: FounderAuthorizationCapability,
) -> str:
    return hashlib.sha256(_unb64(capability.signature)).hexdigest()


_CONFIRMATION_FIELDS = {
    "session_id", "principal_sid", "account_name", "authentication_method",
    "authenticated_at", "expires_at", "machine_identity",
    "application_identity", "process_identity", "challenge_id",
    "challenge_nonce", "project_id", "charter_id", "charter_revision",
    "approval_action", "bound_digest", "source_user_interaction_id",
    "proof_version", "proof",
}


def _validate_issuance_confirmation(
    claims: FounderCapabilityClaims,
    confirmation: Mapping[str, object],
    verify: Callable[[Mapping[str, object], str], bool],
    *,
    expected_method: str,
) -> None:
    if set(confirmation) != _CONFIRMATION_FIELDS:
        raise PermissionError("Founder capability confirmation fields are invalid")
    unsigned = dict(confirmation)
    proof_value = unsigned.pop("proof")
    if not isinstance(proof_value, str) or not verify(unsigned, proof_value):
        raise PermissionError("Founder capability confirmation is unauthenticated")
    try:
        authenticated_at = datetime.fromisoformat(
            str(confirmation["authenticated_at"])
        )
        confirmation_expires = datetime.fromisoformat(
            str(confirmation["expires_at"])
        )
        issued_at = datetime.fromisoformat(claims.issued_at)
    except (KeyError, ValueError) as error:
        raise PermissionError(
            "Founder capability confirmation lifetime is invalid"
        ) from error
    expected_action = (
        "APPROVE_CHARTER"
        if (
            claims.authorization_kind,
            claims.protected_action,
        )
        == ("PROJECT_LAUNCH", "DELEGATE_CHARTER")
        else "APPROVE_ACTION"
    )
    if (
        confirmation.get("authentication_method") != expected_method
        or confirmation.get("approval_action") != expected_action
        or confirmation.get("proof_version") != 2
        or confirmation.get("principal_sid") != claims.founder_principal_sid
        or confirmation.get("session_id")
        != claims.founder_authenticated_session_id
        or confirmation.get("challenge_id") != claims.challenge_id
        or confirmation.get("project_id") != claims.project_id
        or confirmation.get("charter_id") != claims.charter_id
        or confirmation.get("charter_revision") != claims.charter_revision
        or confirmation.get("bound_digest") != claims.action_digest
        or confirmation.get("machine_identity") != claims.machine_identity
        or confirmation.get("application_identity")
        != claims.application_identity
        or claims.challenge_proof_digest
        != hashlib.sha256(proof_value.encode("ascii")).hexdigest()
        or authenticated_at.tzinfo is None
        or confirmation_expires.tzinfo is None
        or not authenticated_at <= issued_at <= confirmation_expires
        or not str(confirmation.get("account_name", ""))
        or not str(confirmation.get("process_identity", ""))
        or not str(confirmation.get("challenge_nonce", ""))
        or not str(confirmation.get("source_user_interaction_id", ""))
    ):
        raise PermissionError(
            "Founder capability is not bound to the fresh confirmation"
        )


class ProductionFounderCapabilityIssuer:
    """Purpose-bound Windows CNG signer; its private key is non-exportable."""

    __principal_sid: str
    __key_name: str
    __sealed: bool
    __slots__ = ("__principal_sid", "__key_name", "__sealed")

    def __init__(self, principal_sid: str) -> None:
        if os.name != "nt" or not principal_sid.startswith("S-1-"):
            raise RuntimeError("production Founder capability signing requires Windows")
        object.__setattr__(self, "_ProductionFounderCapabilityIssuer__sealed", False)
        object.__setattr__(
            self,
            "_ProductionFounderCapabilityIssuer__principal_sid",
            principal_sid,
        )
        suffix = hashlib.sha256(principal_sid.encode("ascii")).hexdigest()[:24]
        object.__setattr__(
            self,
            "_ProductionFounderCapabilityIssuer__key_name",
            f"KeeperFounderAuthorization-v2-{suffix}",
        )
        object.__setattr__(self, "_ProductionFounderCapabilityIssuer__sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(
            self, "_ProductionFounderCapabilityIssuer__sealed", False
        ):
            raise AttributeError("production Founder capability issuer is immutable")
        object.__setattr__(self, name, value)

    def sign_confirmation(self, unsigned: Mapping[str, object]) -> str:
        return _b64(
            _cng_sign(self.__key_name, _digest(CONFIRMATION_PURPOSE, unsigned))
        )

    def verify_confirmation(
        self, unsigned: Mapping[str, object], signature: str
    ) -> bool:
        verifier = self.verifier_configuration()
        return _rsa_verify(
            verifier,
            _digest(CONFIRMATION_PURPOSE, unsigned),
            _unb64(signature),
        )

    def issue(
        self,
        claims: FounderCapabilityClaims,
        confirmation: Mapping[str, object],
    ) -> FounderAuthorizationCapability:
        _validate_issuance_confirmation(
            claims,
            confirmation,
            self.verify_confirmation,
            expected_method="WINDOWS_CREDENTIAL_LOGON",
        )
        if claims.founder_principal_sid != self.__principal_sid:
            raise PermissionError("Founder capability principal is not provisioned")
        verifier = self.verifier_configuration()
        unsigned: dict[str, Any] = {
            "schema_version": CAPABILITY_SCHEMA_VERSION,
            "issuer_id": verifier["issuer_id"],
            "issuer_key_id": verifier["key_id"],
            "signature_algorithm": CAPABILITY_ALGORITHM,
            **asdict(claims),
        }
        signature = _b64(
            _cng_sign(
                self.__key_name,
                _digest(CAPABILITY_PURPOSE, unsigned),
            )
        )
        return FounderAuthorizationCapability(**unsigned, signature=signature)

    def _sign_executive_input_receipt(
        self, unsigned: Mapping[str, object]
    ) -> dict[str, object]:
        receipt = _validate_executive_input_receipt_unsigned(unsigned)
        verifier = self.verifier_configuration()
        signed = {
            **receipt,
            "issuer_id": verifier["issuer_id"],
            "issuer_key_id": verifier["key_id"],
            "signature_algorithm": CAPABILITY_ALGORITHM,
        }
        return {
            **signed,
            "signature": _b64(
                _cng_sign(
                    self.__key_name,
                    _digest(EXECUTIVE_INPUT_RECEIPT_PURPOSE, signed),
                )
            ),
        }

    def verifier_configuration(self) -> dict[str, object]:
        modulus, exponent = _cng_public_key(self.__key_name)
        public = {
            "algorithm": CAPABILITY_ALGORITHM,
            "modulus": _b64(modulus),
            "exponent": _b64(exponent),
        }
        key_id = "keeper-founder-rsa:" + hashlib.sha256(
            _canonical(public)
        ).hexdigest()
        return {
            "schema_version": 1,
            "issuer_id": f"keeper-founder:{self.__principal_sid}",
            "principal_sid": self.__principal_sid,
            "key_id": key_id,
            **public,
        }


class TestFounderCapabilityIssuer:
    __slots__ = ()
    __test__ = False

    def sign_confirmation(self, unsigned: Mapping[str, object]) -> str:
        return _b64(
            hmac.new(
                _TEST_KEY,
                CONFIRMATION_PURPOSE + _canonical(unsigned),
                hashlib.sha256,
            ).digest()
        )

    def verify_confirmation(
        self, unsigned: Mapping[str, object], signature: str
    ) -> bool:
        expected = self.sign_confirmation(unsigned)
        return hmac.compare_digest(expected, signature)

    def issue(
        self,
        claims: FounderCapabilityClaims,
        confirmation: Mapping[str, object],
    ) -> FounderAuthorizationCapability:
        _validate_issuance_confirmation(
            claims,
            confirmation,
            self.verify_confirmation,
            expected_method="TEST_CHALLENGE_HMAC",
        )
        unsigned: dict[str, Any] = {
            "schema_version": CAPABILITY_SCHEMA_VERSION,
            "issuer_id": _TEST_ISSUER_ID,
            "issuer_key_id": test_issuer_key_id(),
            "signature_algorithm": TEST_CAPABILITY_ALGORITHM,
            **asdict(claims),
        }
        signature = _b64(
            hmac.new(
                _TEST_KEY,
                CAPABILITY_PURPOSE + _canonical(unsigned),
                hashlib.sha256,
            ).digest()
        )
        return FounderAuthorizationCapability(**unsigned, signature=signature)

    def sign_executive_input_receipt(
        self, unsigned: Mapping[str, object]
    ) -> dict[str, object]:
        receipt = _validate_executive_input_receipt_unsigned(unsigned)
        signed = {
            **receipt,
            "issuer_id": _TEST_ISSUER_ID,
            "issuer_key_id": test_issuer_key_id(),
            "signature_algorithm": TEST_CAPABILITY_ALGORITHM,
        }
        return {
            **signed,
            "signature": _b64(
                hmac.new(
                    _TEST_KEY,
                    EXECUTIVE_INPUT_RECEIPT_PURPOSE + _canonical(signed),
                    hashlib.sha256,
                ).digest()
            ),
        }


def test_issuer_key_id() -> str:
    return "keeper-test-founder:" + hashlib.sha256(_TEST_KEY).hexdigest()


class ProductionFounderCapabilityVerifier:
    __configuration: dict[str, object]
    __sealed: bool
    __slots__ = ("__configuration", "__sealed")

    def __init__(self, configuration: Mapping[str, object]) -> None:
        expected = {
            "schema_version", "issuer_id", "principal_sid", "key_id",
            "algorithm", "modulus", "exponent",
        }
        if (
            set(configuration) != expected
            or configuration.get("schema_version") != 1
            or configuration.get("algorithm") != CAPABILITY_ALGORITHM
            or not str(configuration.get("principal_sid", "")).startswith("S-1-")
        ):
            raise PermissionError(
                "production Founder capability verifier is invalid"
            )
        object.__setattr__(
            self, "_ProductionFounderCapabilityVerifier__sealed", False
        )
        object.__setattr__(
            self,
            "_ProductionFounderCapabilityVerifier__configuration",
            dict(configuration),
        )
        object.__setattr__(
            self, "_ProductionFounderCapabilityVerifier__sealed", True
        )

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(
            self, "_ProductionFounderCapabilityVerifier__sealed", False
        ):
            raise AttributeError("production Founder capability verifier is immutable")
        object.__setattr__(self, name, value)

    def verify(
        self, value: Mapping[str, object]
    ) -> FounderAuthorizationCapability:
        capability = FounderAuthorizationCapability.from_dict(value)
        config = self.__configuration
        if (
            capability.signature_algorithm != CAPABILITY_ALGORITHM
            or capability.issuer_id != config["issuer_id"]
            or capability.issuer_key_id != config["key_id"]
            or capability.founder_principal_sid != config["principal_sid"]
            or not _rsa_verify(
                config,
                _digest(CAPABILITY_PURPOSE, capability.unsigned()),
                _unb64(capability.signature),
            )
        ):
            raise PermissionError(
                "Founder authorization capability authentication failed"
            )
        return capability

    def verify_executive_input_receipt(
        self, value: Mapping[str, object]
    ) -> dict[str, object]:
        receipt = validate_executive_input_receipt(value)
        signature = str(receipt.pop("signature"))
        config = self.__configuration
        if (
            receipt.get("signature_algorithm") != CAPABILITY_ALGORITHM
            or receipt.get("issuer_id") != config["issuer_id"]
            or receipt.get("issuer_key_id") != config["key_id"]
            or not _rsa_verify(
                config,
                _digest(EXECUTIVE_INPUT_RECEIPT_PURPOSE, receipt),
                _unb64(signature),
            )
        ):
            raise PermissionError(
                "Executive delivered-input receipt authentication failed"
            )
        return {**receipt, "signature": signature}


class TestFounderCapabilityVerifier:
    __slots__ = ()
    __test__ = False

    def verify(
        self, value: Mapping[str, object]
    ) -> FounderAuthorizationCapability:
        capability = FounderAuthorizationCapability.from_dict(value)
        if (
            capability.signature_algorithm != TEST_CAPABILITY_ALGORITHM
            or capability.issuer_id != _TEST_ISSUER_ID
            or capability.issuer_key_id != test_issuer_key_id()
        ):
            raise PermissionError("test Founder capability issuer is invalid")
        expected = hmac.new(
            _TEST_KEY,
            CAPABILITY_PURPOSE + _canonical(capability.unsigned()),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expected, _unb64(capability.signature)):
            raise PermissionError(
                "Founder authorization capability authentication failed"
            )
        return capability

    def verify_executive_input_receipt(
        self, value: Mapping[str, object]
    ) -> dict[str, object]:
        receipt = validate_executive_input_receipt(value)
        signature = str(receipt.pop("signature"))
        if (
            receipt.get("signature_algorithm") != TEST_CAPABILITY_ALGORITHM
            or receipt.get("issuer_id") != _TEST_ISSUER_ID
            or receipt.get("issuer_key_id") != test_issuer_key_id()
        ):
            raise PermissionError(
                "test Executive delivered-input receipt issuer is invalid"
            )
        expected = hmac.new(
            _TEST_KEY,
            EXECUTIVE_INPUT_RECEIPT_PURPOSE + _canonical(receipt),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expected, _unb64(signature)):
            raise PermissionError(
                "Executive delivered-input receipt authentication failed"
            )
        return {**receipt, "signature": signature}


def _rsa_verify(
    configuration: Mapping[str, object], digest: bytes, signature: bytes
) -> bool:
    modulus_bytes = _unb64(str(configuration["modulus"]))
    exponent_bytes = _unb64(str(configuration["exponent"]))
    modulus = int.from_bytes(modulus_bytes, "big")
    exponent = int.from_bytes(exponent_bytes, "big")
    if (
        modulus.bit_length() < 2048
        or exponent < 3
        or exponent % 2 == 0
        or len(signature) != len(modulus_bytes)
    ):
        return False
    encoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(
        len(modulus_bytes), "big"
    )
    digest_info = _RSA_SHA256_DIGEST_INFO + digest
    padding_length = len(encoded) - len(digest_info) - 3
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    return padding_length >= 8 and hmac.compare_digest(encoded, expected)


class _NcryptUiPolicy(ctypes.Structure):
    _fields_ = [
        ("dwVersion", ctypes.c_uint32),
        ("dwFlags", ctypes.c_uint32),
        ("pszCreationTitle", ctypes.c_wchar_p),
        ("pszFriendlyName", ctypes.c_wchar_p),
        ("pszDescription", ctypes.c_wchar_p),
    ]


class _BcryptRsaKeyBlob(ctypes.Structure):
    _fields_ = [
        ("Magic", ctypes.c_uint32),
        ("BitLength", ctypes.c_uint32),
        ("cbPublicExp", ctypes.c_uint32),
        ("cbModulus", ctypes.c_uint32),
        ("cbPrime1", ctypes.c_uint32),
        ("cbPrime2", ctypes.c_uint32),
    ]


class _BcryptPkcs1PaddingInfo(ctypes.Structure):
    _fields_ = [("pszAlgId", ctypes.c_wchar_p)]


def _ncrypt() -> Any:
    if os.name != "nt":
        raise RuntimeError("Windows CNG is unavailable")
    api: Any = ctypes.WinDLL("ncrypt.dll")
    handle = ctypes.c_void_p
    dword = ctypes.c_uint32
    byte_pointer = ctypes.c_void_p
    api.NCryptOpenStorageProvider.argtypes = [
        ctypes.POINTER(handle), ctypes.c_wchar_p, dword
    ]
    api.NCryptOpenKey.argtypes = [
        handle, ctypes.POINTER(handle), ctypes.c_wchar_p, dword, dword
    ]
    api.NCryptCreatePersistedKey.argtypes = [
        handle, ctypes.POINTER(handle), ctypes.c_wchar_p, ctypes.c_wchar_p,
        dword, dword,
    ]
    api.NCryptSetProperty.argtypes = [
        handle, ctypes.c_wchar_p, byte_pointer, dword, dword
    ]
    api.NCryptFinalizeKey.argtypes = [handle, dword]
    api.NCryptExportKey.argtypes = [
        handle, handle, ctypes.c_wchar_p, byte_pointer, byte_pointer,
        dword, ctypes.POINTER(dword), dword,
    ]
    api.NCryptSignHash.argtypes = [
        handle, byte_pointer, byte_pointer, dword, byte_pointer, dword,
        ctypes.POINTER(dword), dword,
    ]
    api.NCryptFreeObject.argtypes = [handle]
    for function in (
        api.NCryptOpenStorageProvider,
        api.NCryptOpenKey,
        api.NCryptCreatePersistedKey,
        api.NCryptSetProperty,
        api.NCryptFinalizeKey,
        api.NCryptExportKey,
        api.NCryptSignHash,
        api.NCryptFreeObject,
    ):
        function.restype = ctypes.c_long
    return api


def _check(status: int, operation: str) -> None:
    if status != 0:
        raise OSError(status & 0xFFFFFFFF, f"Windows CNG {operation} failed")


def _open_cng_key(name: str) -> tuple[ctypes.c_void_p, ctypes.c_void_p]:
    api = _ncrypt()
    provider = ctypes.c_void_p()
    key = ctypes.c_void_p()
    _check(
        api.NCryptOpenStorageProvider(
            ctypes.byref(provider),
            "Microsoft Software Key Storage Provider",
            0,
        ),
        "provider open",
    )
    status = api.NCryptOpenKey(
        provider, ctypes.byref(key), name, 0, 0
    )
    if status == 0:
        return provider, key
    if status & 0xFFFFFFFF not in {0x80090016, 0x8009000D}:
        api.NCryptFreeObject(provider)
        _check(status, "key open")
    try:
        _check(
            api.NCryptCreatePersistedKey(
                provider, ctypes.byref(key), "RSA", name, 0, 0
            ),
            "key creation",
        )
        length = ctypes.c_uint32(3072)
        _check(
            api.NCryptSetProperty(
                key,
                "Length",
                ctypes.byref(length),
                ctypes.sizeof(length),
                0,
            ),
            "key length",
        )
        policy = _NcryptUiPolicy(
            1,
            0x3,
            "Keeper Founder authorization",
            "Keeper Founder authorization key",
            (
                "Confirms a narrowly scoped Keeper Founder authorization "
                "capability. Approval is not granted by a background process."
            ),
        )
        _check(
            api.NCryptSetProperty(
                key,
                "UI Policy",
                ctypes.byref(policy),
                ctypes.sizeof(policy),
                0,
            ),
            "high-protection policy",
        )
        _check(api.NCryptFinalizeKey(key, 0), "key finalization")
        return provider, key
    except BaseException:
        if key:
            api.NCryptFreeObject(key)
        api.NCryptFreeObject(provider)
        raise


def _cng_public_key(name: str) -> tuple[bytes, bytes]:
    api = _ncrypt()
    provider, key = _open_cng_key(name)
    try:
        required = ctypes.c_uint32()
        _check(
            api.NCryptExportKey(
                key, 0, "RSAPUBLICBLOB", None, None, 0,
                ctypes.byref(required), 0,
            ),
            "public-key size",
        )
        buffer = ctypes.create_string_buffer(required.value)
        _check(
            api.NCryptExportKey(
                key, 0, "RSAPUBLICBLOB", None, buffer, required.value,
                ctypes.byref(required), 0,
            ),
            "public-key export",
        )
        header = _BcryptRsaKeyBlob.from_buffer_copy(buffer.raw)
        if header.Magic != 0x31415352 or header.BitLength < 2048:
            raise RuntimeError("Windows CNG Founder public key is invalid")
        offset = ctypes.sizeof(_BcryptRsaKeyBlob)
        exponent = buffer.raw[offset:offset + header.cbPublicExp]
        offset += header.cbPublicExp
        modulus = buffer.raw[offset:offset + header.cbModulus]
        return modulus, exponent
    finally:
        api.NCryptFreeObject(key)
        api.NCryptFreeObject(provider)


def _cng_sign(name: str, digest: bytes) -> bytes:
    api = _ncrypt()
    provider, key = _open_cng_key(name)
    padding = _BcryptPkcs1PaddingInfo("SHA256")
    digest_buffer = ctypes.create_string_buffer(digest)
    try:
        required = ctypes.c_uint32()
        _check(
            api.NCryptSignHash(
                key,
                ctypes.byref(padding),
                digest_buffer,
                len(digest),
                None,
                0,
                ctypes.byref(required),
                0x2,
            ),
            "signature size",
        )
        signature = ctypes.create_string_buffer(required.value)
        _check(
            api.NCryptSignHash(
                key,
                ctypes.byref(padding),
                digest_buffer,
                len(digest),
                signature,
                required.value,
                ctypes.byref(required),
                0x2,
            ),
            "signature",
        )
        return signature.raw[:required.value]
    finally:
        ctypes.memset(
            ctypes.addressof(digest_buffer), 0, ctypes.sizeof(digest_buffer)
        )
        api.NCryptFreeObject(key)
        api.NCryptFreeObject(provider)
