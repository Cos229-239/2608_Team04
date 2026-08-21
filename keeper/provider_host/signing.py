from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import os
import re
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, Iterator, Mapping

from keeper.provider_host.protocol import (
    CallbackEnvelopeIdentity,
    canonical_json,
)


_RSA_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
_NCRYPT_MACHINE_KEY_FLAG = 0x00000020
_NCRYPT_SILENT_FLAG = 0x00000040
_NCRYPT_PAD_PKCS1_FLAG = 0x00000002
_OWNER_SECURITY_INFORMATION = 0x00000001
_GROUP_SECURITY_INFORMATION = 0x00000002
_DACL_SECURITY_INFORMATION = 0x00000004
_KEY_SECURITY_INFORMATION = (
    _OWNER_SECURITY_INFORMATION
    | _GROUP_SECURITY_INFORMATION
    | _DACL_SECURITY_INFORMATION
)
_SDDL_REVISION_1 = 1
_RESTRICTED_CODE_SID = "S-1-5-12"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_SOFTWARE_KEY_STORAGE_PROVIDER = "Microsoft Software Key Storage Provider"
_MAX_CNG_PROPERTY_BYTES = 1024 * 1024
_ACCESS_ALLOWED_ACE_TYPE = 0
_ACCESS_DENIED_ACE_TYPE = 1
_ACL_SIZE_INFORMATION_CLASS = 2
_SE_DACL_PRESENT = 0x0004
_SE_DACL_DEFAULTED = 0x0008
_SE_DACL_AUTO_INHERIT_REQ = 0x0100
_SE_DACL_AUTO_INHERITED = 0x0400
_SE_DACL_PROTECTED = 0x1000
_SE_SELF_RELATIVE = 0x8000
_EXPECTED_DESCRIPTOR_CONTROL = (
    _SE_DACL_PRESENT | _SE_DACL_PROTECTED | _SE_SELF_RELATIVE
)
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_GENERIC_EXECUTE = 0x20000000
_GENERIC_ALL = 0x10000000
_GENERIC_RIGHTS = (
    _GENERIC_READ | _GENERIC_WRITE | _GENERIC_EXECUTE | _GENERIC_ALL
)
# The Microsoft Software KSP normalizes key security descriptors with the
# file-object generic mapping. A disposable persisted-key probe demonstrates
# that GA and FA are both read back as 0xD01F01FF. MapGenericMask reduces every
# equivalent representation to this exact specific-rights set.
_SOFTWARE_KSP_GENERIC_READ = 0x00120089
_SOFTWARE_KSP_GENERIC_WRITE = 0x00120116
_SOFTWARE_KSP_GENERIC_EXECUTE = 0x001200A0
_SOFTWARE_KSP_FULL_CONTROL = 0x001F01FF
_SID_PATTERN = re.compile(r"S-\d+(?:-\d+)+\Z")


class _BcryptRsaKeyBlob(ctypes.Structure):
    _fields_ = [
        ("Magic", wintypes.ULONG),
        ("BitLength", wintypes.ULONG),
        ("cbPublicExp", wintypes.ULONG),
        ("cbModulus", wintypes.ULONG),
        ("cbPrime1", wintypes.ULONG),
        ("cbPrime2", wintypes.ULONG),
    ]


class _BcryptPkcs1PaddingInfo(ctypes.Structure):
    _fields_ = [("pszAlgId", wintypes.LPCWSTR)]


class _GenericMapping(ctypes.Structure):
    _fields_ = [
        ("GenericRead", wintypes.DWORD),
        ("GenericWrite", wintypes.DWORD),
        ("GenericExecute", wintypes.DWORD),
        ("GenericAll", wintypes.DWORD),
    ]


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


@dataclass(frozen=True, slots=True, order=True)
class _SecurityAce:
    ace_type: int
    access_mask: int
    sid: str


@dataclass(frozen=True, slots=True)
class _SecurityPolicy:
    revision: int
    control: int
    owner_sid: str
    group_sid: str | None
    owner_defaulted: bool
    group_defaulted: bool
    dacl_defaulted: bool
    aces: tuple[_SecurityAce, ...]


class ProviderHostCngKeyNotProvisioned(PermissionError):
    """The exact CNG identity is absent, not merely inaccessible or invalid."""


class ProviderHostCngPolicyMismatch(PermissionError):
    """The key exists but its exact machine security policy does not match."""


@dataclass(frozen=True, slots=True)
class RsaPublicIdentity:
    identity: str
    key_id: str
    modulus: bytes
    exponent: bytes
    production: bool = True

    @classmethod
    def from_configuration(cls, value: Mapping[str, object]) -> RsaPublicIdentity:
        expected = {"algorithm", "exponent", "identity", "key_id", "modulus", "schema_version"}
        if (
            set(value) != expected
            or value.get("schema_version") != 1
            or value.get("algorithm") != "RSA-PKCS1-SHA256"
        ):
            raise PermissionError("Provider Host public identity is invalid")
        try:
            modulus = base64.b64decode(str(value["modulus"]), validate=True)
            exponent = base64.b64decode(str(value["exponent"]), validate=True)
        except ValueError as error:
            raise PermissionError("Provider Host public key is invalid") from error
        identity = str(value["identity"])
        key_id = str(value["key_id"])
        public = {"algorithm": "RSA-PKCS1-SHA256", "exponent": value["exponent"], "modulus": value["modulus"]}
        expected_key_id = "keeper-provider-host-rsa:" + hashlib.sha256(
            canonical_json(public)
        ).hexdigest()
        if (
            not identity
            or key_id != expected_key_id
            or int.from_bytes(modulus, "big").bit_length() < 2048
            or int.from_bytes(exponent, "big") < 3
            or int.from_bytes(exponent, "big") % 2 == 0
        ):
            raise PermissionError("Provider Host public key binding is invalid")
        return cls(identity, key_id, modulus, exponent)

    def verify_digest(self, digest: bytes, signature: bytes) -> bool:
        return _rsa_verify(self.modulus, self.exponent, digest, signature)

    def verifier(self) -> CallbackEnvelopeIdentity:
        def no_sign(_: bytes) -> bytes:
            raise PermissionError("Provider Host public identity cannot sign")

        return CallbackEnvelopeIdentity(
            self.identity,
            self.key_id,
            no_sign,
            self.verify_digest,
            True,
        )


class WindowsCngEnvelopeIdentity:
    """Non-exportable Windows CNG RSA identity for Authority or user host."""

    def __init__(
        self,
        *,
        identity: str,
        key_name: str,
        machine_key: bool,
        owner_sid: str | None = None,
        create_if_missing: bool = True,
        machine_access_sids: tuple[str, ...] = (),
        reconcile_interrupted_machine_key: bool = False,
        inspect_recoverable_legacy_machine_key: bool = False,
    ) -> None:
        if os.name != "nt" or not identity or not key_name:
            raise RuntimeError("Provider Host CNG identity requires Windows")
        if machine_key and owner_sid is not None:
            raise ValueError("machine CNG identity cannot use a user owner SID")
        if not machine_key and (
            owner_sid is None or not owner_sid.startswith("S-1-")
        ):
            raise ValueError("user CNG identity requires an exact owner SID")
        if not machine_key and machine_access_sids:
            raise ValueError("user CNG identity cannot use machine access SIDs")
        if not machine_key and reconcile_interrupted_machine_key:
            raise ValueError("user CNG identity cannot reconcile a machine key")
        if not machine_key and inspect_recoverable_legacy_machine_key:
            raise ValueError("user CNG identity cannot inspect a machine key")
        if (
            reconcile_interrupted_machine_key
            and inspect_recoverable_legacy_machine_key
        ):
            raise ValueError("machine CNG identity recovery mode is ambiguous")
        if inspect_recoverable_legacy_machine_key and create_if_missing:
            raise ValueError("legacy machine-key inspection cannot create a key")
        if machine_key and any(
            not _valid_sid_text(sid) for sid in machine_access_sids
        ):
            raise ValueError("machine CNG identity access SID is invalid")
        if len(set(machine_access_sids)) != len(machine_access_sids):
            raise ValueError("machine CNG identity access SIDs are duplicated")
        self.identity = identity
        self.key_name = key_name
        self.machine_key = machine_key
        self.owner_sid = owner_sid
        self.create_if_missing = create_if_missing
        self.machine_access_sids = machine_access_sids
        self.reconcile_interrupted_machine_key = (
            reconcile_interrupted_machine_key
        )
        self.inspect_recoverable_legacy_machine_key = (
            inspect_recoverable_legacy_machine_key
        )
        modulus, exponent, legacy_policy_sha256 = _public_key(
            key_name,
            machine_key=machine_key,
            owner_sid=owner_sid,
            create_if_missing=create_if_missing,
            machine_access_sids=machine_access_sids,
            reconcile_interrupted_machine_key=reconcile_interrupted_machine_key,
            inspect_recoverable_legacy_machine_key=(
                inspect_recoverable_legacy_machine_key
            ),
        )
        self.recoverable_legacy_policy_sha256 = legacy_policy_sha256
        self._public = RsaPublicIdentity.from_configuration(
            _public_configuration(identity, modulus, exponent)
        )
        self.key_id = self._public.key_id
        self.production = True

    def sign(self, purpose: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if self.inspect_recoverable_legacy_machine_key:
            raise PermissionError(
                "recoverable legacy machine-key inspection cannot sign"
            )
        codec = CallbackEnvelopeIdentity(
            self.identity,
            self.key_id,
            lambda digest: _sign(
                self.key_name,
                digest,
                machine_key=self.machine_key,
                owner_sid=self.owner_sid,
                create_if_missing=self.create_if_missing,
                machine_access_sids=self.machine_access_sids,
                reconcile_interrupted_machine_key=(
                    self.reconcile_interrupted_machine_key
                ),
                inspect_recoverable_legacy_machine_key=False,
            ),
            self._public.verify_digest,
            True,
        )
        return codec.sign(purpose, payload)

    def verify(
        self, record: Mapping[str, Any], *, purpose: str
    ) -> dict[str, Any]:
        return self._public.verifier().verify(record, purpose=purpose)

    def public_configuration(self) -> dict[str, object]:
        return _public_configuration(
            self.identity, self._public.modulus, self._public.exponent
        )


def _public_configuration(
    identity: str, modulus: bytes, exponent: bytes
) -> dict[str, object]:
    public = {
        "algorithm": "RSA-PKCS1-SHA256",
        "exponent": base64.b64encode(exponent).decode("ascii"),
        "modulus": base64.b64encode(modulus).decode("ascii"),
    }
    return {
        "schema_version": 1,
        "identity": identity,
        "key_id": "keeper-provider-host-rsa:"
        + hashlib.sha256(canonical_json(public)).hexdigest(),
        **public,
    }


def _rsa_verify(
    modulus_bytes: bytes,
    exponent_bytes: bytes,
    digest: bytes,
    signature: bytes,
) -> bool:
    modulus = int.from_bytes(modulus_bytes, "big")
    exponent = int.from_bytes(exponent_bytes, "big")
    if (
        len(digest) != 32
        or modulus.bit_length() < 2048
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


def _public_key(
    name: str,
    *,
    machine_key: bool,
    owner_sid: str | None,
    create_if_missing: bool,
    machine_access_sids: tuple[str, ...],
    reconcile_interrupted_machine_key: bool,
    inspect_recoverable_legacy_machine_key: bool,
) -> tuple[bytes, bytes, str | None]:
    api = _ncrypt()
    provider, key = _open_key(
        api,
        name,
        machine_key=machine_key,
        owner_sid=owner_sid,
        create_if_missing=create_if_missing,
        machine_access_sids=machine_access_sids,
        reconcile_interrupted_machine_key=reconcile_interrupted_machine_key,
        inspect_recoverable_legacy_machine_key=(
            inspect_recoverable_legacy_machine_key
        ),
    )
    try:
        legacy_policy_sha256 = (
            _recoverable_legacy_machine_key_policy_sha256(
                api, key, machine_access_sids
            )
            if inspect_recoverable_legacy_machine_key
            else None
        )
        required = wintypes.DWORD()
        _check(
            api.NCryptExportKey(
                key,
                None,
                "RSAPUBLICBLOB",
                None,
                None,
                0,
                ctypes.byref(required),
                0,
            ),
            "public-key size",
        )
        buffer = ctypes.create_string_buffer(required.value)
        _check(
            api.NCryptExportKey(
                key,
                None,
                "RSAPUBLICBLOB",
                None,
                buffer,
                required.value,
                ctypes.byref(required),
                0,
            ),
            "public-key export",
        )
        header = _BcryptRsaKeyBlob.from_buffer_copy(buffer.raw)
        if header.Magic != 0x31415352 or header.BitLength < 2048:
            raise RuntimeError("Provider Host CNG public key is invalid")
        offset = ctypes.sizeof(_BcryptRsaKeyBlob)
        exponent = buffer.raw[offset : offset + header.cbPublicExp]
        offset += header.cbPublicExp
        modulus = buffer.raw[offset : offset + header.cbModulus]
        return modulus, exponent, legacy_policy_sha256
    finally:
        api.NCryptFreeObject(key)
        api.NCryptFreeObject(provider)


def _sign(
    name: str,
    digest: bytes,
    *,
    machine_key: bool,
    owner_sid: str | None,
    create_if_missing: bool,
    machine_access_sids: tuple[str, ...],
    reconcile_interrupted_machine_key: bool,
    inspect_recoverable_legacy_machine_key: bool,
) -> bytes:
    if len(digest) != 32:
        raise ValueError("Provider Host signing digest is invalid")
    api = _ncrypt()
    provider, key = _open_key(
        api,
        name,
        machine_key=machine_key,
        owner_sid=owner_sid,
        create_if_missing=create_if_missing,
        machine_access_sids=machine_access_sids,
        reconcile_interrupted_machine_key=reconcile_interrupted_machine_key,
        inspect_recoverable_legacy_machine_key=(
            inspect_recoverable_legacy_machine_key
        ),
    )
    padding = _BcryptPkcs1PaddingInfo("SHA256")
    digest_buffer = ctypes.create_string_buffer(digest)
    try:
        required = wintypes.DWORD()
        _check(
            api.NCryptSignHash(
                key,
                ctypes.byref(padding),
                digest_buffer,
                len(digest),
                None,
                0,
                ctypes.byref(required),
                _NCRYPT_PAD_PKCS1_FLAG,
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
                _NCRYPT_PAD_PKCS1_FLAG,
            ),
            "signature",
        )
        return signature.raw[: required.value]
    finally:
        api.NCryptFreeObject(key)
        api.NCryptFreeObject(provider)


def _open_key(
    api: Any,
    name: str,
    *,
    machine_key: bool,
    owner_sid: str | None,
    create_if_missing: bool = True,
    machine_access_sids: tuple[str, ...] = (),
    reconcile_interrupted_machine_key: bool = False,
    inspect_recoverable_legacy_machine_key: bool = False,
) -> tuple[ctypes.c_void_p, ctypes.c_void_p]:
    provider = ctypes.c_void_p()
    key = ctypes.c_void_p()
    _check(
        api.NCryptOpenStorageProvider(
            ctypes.byref(provider),
            _SOFTWARE_KEY_STORAGE_PROVIDER,
            0,
        ),
        "provider open",
    )
    if machine_key:
        try:
            _validate_machine_storage_provider(api, provider)
        except BaseException:
            api.NCryptFreeObject(provider)
            raise
    flags = _NCRYPT_SILENT_FLAG | (
        _NCRYPT_MACHINE_KEY_FLAG if machine_key else 0
    )
    status = api.NCryptOpenKey(provider, ctypes.byref(key), name, 0, flags)
    if status == 0:
        try:
            if machine_key:
                _validate_machine_key(api, key, name)
            if owner_sid is not None:
                _protect_user_key(api, key, owner_sid)
            elif machine_access_sids:
                if reconcile_interrupted_machine_key:
                    _protect_machine_key(api, key, machine_access_sids)
                elif inspect_recoverable_legacy_machine_key:
                    _recoverable_legacy_machine_key_policy_sha256(
                        api, key, machine_access_sids
                    )
                else:
                    _verify_machine_key_security(
                        api, key, machine_access_sids
                    )
            return provider, key
        except BaseException:
            api.NCryptFreeObject(key)
            api.NCryptFreeObject(provider)
            raise
    if status & 0xFFFFFFFF not in {0x80090016, 0x8009000D}:
        api.NCryptFreeObject(provider)
        _check(status, "key open")
    if not create_if_missing:
        api.NCryptFreeObject(provider)
        raise ProviderHostCngKeyNotProvisioned(
            "Provider Host CNG key is not provisioned"
        )
    if machine_key and not machine_access_sids:
        api.NCryptFreeObject(provider)
        raise PermissionError(
            "machine Provider Host CNG key requires an explicit access policy"
        )
    try:
        _check(
            api.NCryptCreatePersistedKey(
                provider,
                ctypes.byref(key),
                "RSA",
                name,
                0,
                flags,
            ),
            "key creation",
        )
        length = wintypes.DWORD(3072)
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
        _check(api.NCryptFinalizeKey(key, _NCRYPT_SILENT_FLAG), "key finalization")
        if machine_key:
            _validate_machine_key(api, key, name)
        if owner_sid is not None:
            _protect_user_key(api, key, owner_sid)
        elif machine_access_sids:
            _protect_machine_key(api, key, machine_access_sids)
        return provider, key
    except BaseException:
        if key:
            api.NCryptFreeObject(key)
        api.NCryptFreeObject(provider)
        raise


def _protect_user_key(api: Any, key: ctypes.c_void_p, owner_sid: str) -> None:
    """Persist an exact DACL that excludes every restricted provider token."""
    with _key_security_descriptor(owner_sid) as (descriptor, length):
        _check(
            api.NCryptSetProperty(
                key,
                "Security Descr",
                descriptor,
                length,
                _DACL_SECURITY_INFORMATION,
            ),
            "restricted-provider DACL",
        )


def _protect_machine_key(
    api: Any, key: ctypes.c_void_p, access_sids: tuple[str, ...]
) -> None:
    """Persist an exact machine-key DACL supplied by elevated lifecycle code."""
    expected_sddl = _machine_key_security_sddl(access_sids)
    with _key_security_descriptor_for_sddl(expected_sddl) as (
        descriptor,
        length,
    ):
        _check(
            api.NCryptSetProperty(
                key,
                "Security Descr",
                descriptor,
                length,
                _KEY_SECURITY_INFORMATION,
            ),
            "machine-key owner and DACL",
        )
    _verify_machine_key_security(api, key, access_sids)


def _validate_machine_storage_provider(
    api: Any, provider: ctypes.c_void_p
) -> None:
    support = _ncrypt_dword_property(api, provider, "Security Descr Support")
    if support != 1:
        raise PermissionError(
            "Provider Host machine-key storage provider cannot enforce security "
            "descriptors"
        )


def _validate_machine_key(
    api: Any, key: ctypes.c_void_p, expected_name: str
) -> None:
    """Reject a same-name object unless every non-secret key property agrees."""
    properties = {
        "name": _ncrypt_string_property(api, key, "Name"),
        "unique_name": _ncrypt_string_property(api, key, "Unique Name"),
        "algorithm": _ncrypt_string_property(api, key, "Algorithm Name"),
        "length": _ncrypt_dword_property(api, key, "Length"),
        "export_policy": _ncrypt_dword_property(api, key, "Export Policy"),
    }
    if (
        properties["name"] != expected_name
        or not properties["unique_name"]
        or properties["algorithm"] != "RSA"
        or properties["length"] != 3072
        or properties["export_policy"] != 0
    ):
        raise PermissionError(
            "existing Provider Host machine-key identity differs"
        )


def _verify_machine_key_security(
    api: Any, key: ctypes.c_void_p, access_sids: tuple[str, ...]
) -> None:
    live = _ncrypt_property(
        api,
        key,
        "Security Descr",
        flags=_KEY_SECURITY_INFORMATION,
    )
    live_buffer = ctypes.create_string_buffer(live)
    live_descriptor = ctypes.cast(live_buffer, wintypes.LPVOID)
    with _key_security_descriptor_for_sddl(
        _machine_key_security_sddl(access_sids)
    ) as (
        expected_descriptor,
        _expected_length,
    ):
        expected = _canonical_machine_key_security_policy(
            expected_descriptor, access_sids
        )
    try:
        actual = _canonical_machine_key_security_policy(
            live_descriptor, access_sids
        )
    except PermissionError as error:
        raise ProviderHostCngPolicyMismatch(
            "Provider Host machine-key security policy did not verify exactly"
        ) from error
    if actual != expected:
        raise ProviderHostCngPolicyMismatch(
            "Provider Host machine-key security policy did not verify exactly"
        )


def _recoverable_legacy_machine_key_policy_sha256(
    api: Any, key: ctypes.c_void_p, access_sids: tuple[str, ...]
) -> str:
    """Classify only the primary-group gap left by the 1.7.3 lifecycle."""
    live = _ncrypt_property(
        api,
        key,
        "Security Descr",
        flags=_KEY_SECURITY_INFORMATION,
    )
    live_buffer = ctypes.create_string_buffer(live)
    policy = _closed_machine_key_security_policy(
        _read_security_policy(
            ctypes.cast(live_buffer, wintypes.LPVOID),
            allow_absent_group=True,
        ),
        access_sids,
    )
    if (
        policy.group_sid == _ADMINISTRATORS_SID
        and not policy.group_defaulted
    ):
        raise PermissionError(
            "Provider Host machine-key policy is not a recoverable legacy state"
        )
    return _security_policy_sha256(policy)


def machine_key_security_policy_sha256(
    access_sids: tuple[str, ...],
) -> str:
    """Return a sanitized deterministic hash of the exact closed policy."""
    with _key_security_descriptor_for_sddl(
        _machine_key_security_sddl(access_sids)
    ) as (descriptor, _length):
        policy = _canonical_machine_key_security_policy(
            descriptor, access_sids
        )
    return _security_policy_sha256(policy)


def _security_policy_sha256(policy: _SecurityPolicy) -> str:
    summary = {
        "schema_version": 1,
        "revision": policy.revision,
        "control": policy.control,
        "owner_sid": policy.owner_sid,
        "group_sid": policy.group_sid,
        "owner_defaulted": policy.owner_defaulted,
        "group_defaulted": policy.group_defaulted,
        "dacl_defaulted": policy.dacl_defaulted,
        "aces": [
            {
                "type": ace.ace_type,
                "access_mask": f"0x{ace.access_mask:08X}",
                "sid": ace.sid,
            }
            for ace in policy.aces
        ],
    }
    return hashlib.sha256(canonical_json(summary)).hexdigest().upper()


def _canonical_machine_key_security_policy(
    descriptor: wintypes.LPVOID, access_sids: tuple[str, ...]
) -> _SecurityPolicy:
    policy = _closed_machine_key_security_policy(
        _read_security_policy(descriptor), access_sids
    )
    if (
        policy.group_sid != _ADMINISTRATORS_SID
        or policy.group_defaulted
    ):
        raise PermissionError(
            "Provider Host machine-key owner, group, or DACL control differs"
        )
    return _SecurityPolicy(
        revision=policy.revision,
        control=policy.control,
        owner_sid=policy.owner_sid,
        group_sid=policy.group_sid,
        owner_defaulted=False,
        group_defaulted=False,
        dacl_defaulted=False,
        aces=policy.aces,
    )


def _closed_machine_key_security_policy(
    policy: _SecurityPolicy, access_sids: tuple[str, ...]
) -> _SecurityPolicy:
    if (
        policy.revision != _SDDL_REVISION_1
        or policy.control != _EXPECTED_DESCRIPTOR_CONTROL
        or policy.owner_sid != _ADMINISTRATORS_SID
        or policy.owner_defaulted
        or policy.dacl_defaulted
    ):
        raise PermissionError(
            "Provider Host machine-key owner or DACL control differs"
        )
    expected_sids = (
        _RESTRICTED_CODE_SID,
        *access_sids,
    )
    if len(policy.aces) != len(expected_sids):
        raise PermissionError(
            "Provider Host machine-key authorization set differs"
        )
    denied = [ace for ace in policy.aces if ace.ace_type == _ACCESS_DENIED_ACE_TYPE]
    allowed = [ace for ace in policy.aces if ace.ace_type == _ACCESS_ALLOWED_ACE_TYPE]
    if (
        len(denied) != 1
        or denied[0].sid != _RESTRICTED_CODE_SID
        or denied[0].access_mask != _SOFTWARE_KSP_FULL_CONTROL
        or len(allowed) != len(access_sids)
        or {ace.sid for ace in allowed} != set(access_sids)
        or any(
            ace.access_mask != _SOFTWARE_KSP_FULL_CONTROL
            for ace in allowed
        )
    ):
        raise PermissionError(
            "Provider Host machine-key authorization set differs"
        )
    return _SecurityPolicy(
        revision=policy.revision,
        control=policy.control,
        owner_sid=policy.owner_sid,
        group_sid=policy.group_sid,
        owner_defaulted=False,
        group_defaulted=policy.group_defaulted,
        dacl_defaulted=False,
        aces=(denied[0], *sorted(allowed, key=lambda ace: ace.sid)),
    )


def _read_security_policy(
    descriptor: wintypes.LPVOID, *, allow_absent_group: bool = False
) -> _SecurityPolicy:
    advapi32, kernel32 = _security_descriptor_apis()
    if not descriptor or not advapi32.IsValidSecurityDescriptor(descriptor):
        raise PermissionError(
            "Provider Host machine-key security descriptor is invalid"
        )
    control = wintypes.WORD()
    revision = wintypes.DWORD()
    if not advapi32.GetSecurityDescriptorControl(
        descriptor, ctypes.byref(control), ctypes.byref(revision)
    ):
        raise OSError(
            ctypes.get_last_error(),
            "Provider Host machine-key control read failed",
        )
    owner = wintypes.LPVOID()
    owner_defaulted = wintypes.BOOL()
    if not advapi32.GetSecurityDescriptorOwner(
        descriptor, ctypes.byref(owner), ctypes.byref(owner_defaulted)
    ):
        raise OSError(
            ctypes.get_last_error(),
            "Provider Host machine-key owner read failed",
        )
    group = wintypes.LPVOID()
    group_defaulted = wintypes.BOOL()
    if not advapi32.GetSecurityDescriptorGroup(
        descriptor, ctypes.byref(group), ctypes.byref(group_defaulted)
    ):
        raise OSError(
            ctypes.get_last_error(),
            "Provider Host machine-key group read failed",
        )
    dacl_present = wintypes.BOOL()
    dacl = wintypes.LPVOID()
    dacl_defaulted = wintypes.BOOL()
    if not advapi32.GetSecurityDescriptorDacl(
        descriptor,
        ctypes.byref(dacl_present),
        ctypes.byref(dacl),
        ctypes.byref(dacl_defaulted),
    ):
        raise OSError(
            ctypes.get_last_error(),
            "Provider Host machine-key DACL read failed",
        )
    if not owner:
        raise PermissionError("Provider Host machine-key owner is absent")
    if not group and not allow_absent_group:
        raise PermissionError("Provider Host machine-key group is absent")
    if not dacl_present.value or not dacl:
        raise PermissionError(
            "Provider Host machine-key DACL is absent or null"
        )
    owner_sid = _sid_to_string(advapi32, kernel32, owner)
    group_sid = (
        _sid_to_string(advapi32, kernel32, group) if group else None
    )
    if not advapi32.IsValidAcl(dacl):
        raise PermissionError("Provider Host machine-key DACL is invalid")
    information = _AclSizeInformation()
    if not advapi32.GetAclInformation(
        dacl,
        ctypes.byref(information),
        ctypes.sizeof(information),
        _ACL_SIZE_INFORMATION_CLASS,
    ):
        raise OSError(
            ctypes.get_last_error(),
            "Provider Host machine-key DACL metadata read failed",
        )
    aces: list[_SecurityAce] = []
    seen_allow = False
    for index in range(information.AceCount):
        ace_pointer = wintypes.LPVOID()
        if not advapi32.GetAce(dacl, index, ctypes.byref(ace_pointer)):
            raise OSError(
                ctypes.get_last_error(),
                "Provider Host machine-key ACE read failed",
            )
        address = int(ace_pointer.value or 0)
        if not address:
            raise PermissionError("Provider Host machine-key ACE is invalid")
        header = ctypes.cast(
            ace_pointer, ctypes.POINTER(_AceHeader)
        ).contents
        if (
            header.AceType
            not in {_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_DENIED_ACE_TYPE}
            or header.AceFlags != 0
            or header.AceSize < ctypes.sizeof(_AceHeader) + 4 + 8
        ):
            raise PermissionError(
                "Provider Host machine-key ACE type or flags differ"
            )
        if header.AceType == _ACCESS_DENIED_ACE_TYPE and seen_allow:
            raise PermissionError(
                "Provider Host machine-key ACE order is noncanonical"
            )
        if header.AceType == _ACCESS_ALLOWED_ACE_TYPE:
            seen_allow = True
        mask = ctypes.cast(
            address + ctypes.sizeof(_AceHeader),
            ctypes.POINTER(wintypes.DWORD),
        ).contents.value
        sid_pointer = wintypes.LPVOID(
            address + ctypes.sizeof(_AceHeader) + ctypes.sizeof(wintypes.DWORD)
        )
        if not advapi32.IsValidSid(sid_pointer):
            raise PermissionError(
                "Provider Host machine-key ACE trustee is invalid"
            )
        sid_length = int(advapi32.GetLengthSid(sid_pointer))
        if sid_length <= 0 or sid_length > (
            header.AceSize
            - ctypes.sizeof(_AceHeader)
            - ctypes.sizeof(wintypes.DWORD)
        ):
            raise PermissionError(
                "Provider Host machine-key ACE trustee length is invalid"
            )
        aces.append(
            _SecurityAce(
                ace_type=int(header.AceType),
                access_mask=_map_software_ksp_access_mask(
                    advapi32, int(mask)
                ),
                sid=_sid_to_string(advapi32, kernel32, sid_pointer),
            )
        )
    return _SecurityPolicy(
        revision=int(revision.value),
        control=int(control.value),
        owner_sid=owner_sid,
        group_sid=group_sid,
        owner_defaulted=bool(owner_defaulted.value),
        group_defaulted=bool(group_defaulted.value),
        dacl_defaulted=bool(dacl_defaulted.value),
        aces=tuple(aces),
    )


def _map_software_ksp_access_mask(advapi32: Any, mask: int) -> int:
    mapped = wintypes.DWORD(mask)
    mapping = _GenericMapping(
        _SOFTWARE_KSP_GENERIC_READ,
        _SOFTWARE_KSP_GENERIC_WRITE,
        _SOFTWARE_KSP_GENERIC_EXECUTE,
        _SOFTWARE_KSP_FULL_CONTROL,
    )
    advapi32.MapGenericMask(ctypes.byref(mapped), ctypes.byref(mapping))
    if mapped.value & _GENERIC_RIGHTS:
        raise PermissionError(
            "Provider Host machine-key generic rights are unresolved"
        )
    return int(mapped.value)


def _sid_to_string(
    advapi32: Any, kernel32: Any, sid: wintypes.LPVOID
) -> str:
    if not sid or not advapi32.IsValidSid(sid):
        raise PermissionError("Provider Host machine-key SID is invalid")
    value = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(value)):
        raise OSError(
            ctypes.get_last_error(),
            "Provider Host machine-key SID conversion failed",
        )
    try:
        result = str(value.value or "")
        if not _valid_sid_text(result):
            raise PermissionError(
                "Provider Host machine-key SID conversion is invalid"
            )
        return result
    finally:
        kernel32.LocalFree(value)


def _ncrypt_property(
    api: Any,
    handle: ctypes.c_void_p,
    name: str,
    *,
    flags: int = 0,
) -> bytes:
    required = wintypes.DWORD()
    _check(
        api.NCryptGetProperty(
            handle,
            name,
            None,
            0,
            ctypes.byref(required),
            flags,
        ),
        f"{name} property size",
    )
    if required.value <= 0 or required.value > _MAX_CNG_PROPERTY_BYTES:
        raise PermissionError(f"Provider Host CNG {name} property size is invalid")
    buffer = ctypes.create_string_buffer(required.value)
    copied = wintypes.DWORD()
    _check(
        api.NCryptGetProperty(
            handle,
            name,
            buffer,
            required.value,
            ctypes.byref(copied),
            flags,
        ),
        f"{name} property",
    )
    if copied.value != required.value:
        raise PermissionError(f"Provider Host CNG {name} property changed")
    return buffer.raw[: copied.value]


def _ncrypt_string_property(
    api: Any, handle: ctypes.c_void_p, name: str
) -> str:
    raw = _ncrypt_property(api, handle, name)
    if len(raw) < 2 or len(raw) % 2:
        raise PermissionError(f"Provider Host CNG {name} property is invalid")
    try:
        value = raw.decode("utf-16-le")
    except UnicodeDecodeError as error:
        raise PermissionError(
            f"Provider Host CNG {name} property is invalid"
        ) from error
    if not value.endswith("\x00") or "\x00" in value[:-1]:
        raise PermissionError(f"Provider Host CNG {name} property is invalid")
    return value[:-1]


def _ncrypt_dword_property(
    api: Any, handle: ctypes.c_void_p, name: str
) -> int:
    raw = _ncrypt_property(api, handle, name)
    if len(raw) != ctypes.sizeof(wintypes.DWORD):
        raise PermissionError(f"Provider Host CNG {name} property is invalid")
    return int.from_bytes(raw, "little")


@contextmanager
def _key_security_descriptor(
    owner_sid: str,
) -> Iterator[tuple[wintypes.LPVOID, int]]:
    if not _valid_sid_text(owner_sid):
        raise ValueError("Provider Host key owner SID is invalid")
    with _key_security_descriptor_for_sddl(
        _key_security_sddl(owner_sid)
    ) as value:
        yield value


@contextmanager
def _key_security_descriptor_for_sddl(
    sddl: str,
) -> Iterator[tuple[wintypes.LPVOID, int]]:
    advapi32, kernel32 = _security_descriptor_apis()
    descriptor = wintypes.LPVOID()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        None,
    ):
        raise OSError(
            ctypes.get_last_error(),
            "Provider Host key DACL creation failed",
        )
    try:
        length = int(advapi32.GetSecurityDescriptorLength(descriptor))
        if length <= 0:
            raise OSError("Provider Host key DACL length is invalid")
        yield descriptor, length
    finally:
        kernel32.LocalFree(descriptor)


def _security_descriptor_to_sddl(
    descriptor: wintypes.LPVOID, security_information: int
) -> str:
    advapi32, kernel32 = _security_descriptor_apis()
    value = wintypes.LPWSTR()
    length = wintypes.DWORD()
    if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor,
        _SDDL_REVISION_1,
        security_information,
        ctypes.byref(value),
        ctypes.byref(length),
    ):
        raise OSError(
            ctypes.get_last_error(),
            "Provider Host key security policy read-back failed",
        )
    try:
        if not value.value or length.value <= 1:
            raise PermissionError(
                "Provider Host key security policy read-back is invalid"
            )
        return str(value.value)
    finally:
        kernel32.LocalFree(value)


def _security_descriptor_apis() -> tuple[Any, Any]:
    if os.name != "nt":
        raise RuntimeError("Provider Host security descriptors require Windows")
    try:
        advapi32: Any = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
            wintypes.BOOL
        )
        advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = (
            wintypes.BOOL
        )
        advapi32.GetSecurityDescriptorLength.argtypes = [wintypes.LPVOID]
        advapi32.GetSecurityDescriptorLength.restype = wintypes.DWORD
        advapi32.IsValidSecurityDescriptor.argtypes = [wintypes.LPVOID]
        advapi32.IsValidSecurityDescriptor.restype = wintypes.BOOL
        advapi32.GetSecurityDescriptorControl.argtypes = [
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
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
        advapi32.GetSecurityDescriptorDacl.argtypes = [
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.BOOL),
        ]
        advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        advapi32.IsValidAcl.argtypes = [wintypes.LPVOID]
        advapi32.IsValidAcl.restype = wintypes.BOOL
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
        advapi32.GetLengthSid.argtypes = [wintypes.LPVOID]
        advapi32.GetLengthSid.restype = wintypes.DWORD
        advapi32.ConvertSidToStringSidW.argtypes = [
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        advapi32.MapGenericMask.argtypes = [
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(_GenericMapping),
        ]
        advapi32.MapGenericMask.restype = None
        kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
        kernel32.LocalFree.restype = wintypes.HLOCAL
    except AttributeError as error:
        raise RuntimeError(
            "required Windows security descriptor API is unavailable"
        ) from error
    return advapi32, kernel32


def _key_security_sddl(owner_sid: str) -> str:
    if not _valid_sid_text(owner_sid):
        raise ValueError("Provider Host key owner SID is invalid")
    return (
        f"D:P(D;;GA;;;{_RESTRICTED_CODE_SID})"
        f"(A;;GA;;;SY)(A;;GA;;;{owner_sid})"
    )


def _machine_key_security_sddl(access_sids: tuple[str, ...]) -> str:
    if (
        not access_sids
        or any(not _valid_sid_text(sid) for sid in access_sids)
        or len(set(access_sids)) != len(access_sids)
        or access_sids[:2] != ("S-1-5-18", _ADMINISTRATORS_SID)
    ):
        raise ValueError("Provider Host machine-key access policy is invalid")
    grants = "".join(f"(A;;GA;;;{sid})" for sid in access_sids)
    return (
        f"O:{_ADMINISTRATORS_SID}G:{_ADMINISTRATORS_SID}"
        f"D:P(D;;GA;;;{_RESTRICTED_CODE_SID}){grants}"
    )


def _valid_sid_text(value: str) -> bool:
    return bool(_SID_PATTERN.fullmatch(value))


def _check(status: int, operation: str) -> None:
    if status != 0:
        raise OSError(status & 0xFFFFFFFF, f"Provider Host CNG {operation} failed")


def _ncrypt() -> Any:
    if os.name != "nt":
        raise RuntimeError("Provider Host CNG requires Windows")
    api: Any = ctypes.WinDLL("ncrypt.dll")
    handle = ctypes.c_void_p
    dword = wintypes.DWORD
    pointer = ctypes.c_void_p
    api.NCryptOpenStorageProvider.argtypes = [ctypes.POINTER(handle), wintypes.LPCWSTR, dword]
    api.NCryptOpenKey.argtypes = [handle, ctypes.POINTER(handle), wintypes.LPCWSTR, dword, dword]
    api.NCryptCreatePersistedKey.argtypes = [handle, ctypes.POINTER(handle), wintypes.LPCWSTR, wintypes.LPCWSTR, dword, dword]
    api.NCryptSetProperty.argtypes = [handle, wintypes.LPCWSTR, pointer, dword, dword]
    api.NCryptGetProperty.argtypes = [handle, wintypes.LPCWSTR, pointer, dword, ctypes.POINTER(dword), dword]
    api.NCryptFinalizeKey.argtypes = [handle, dword]
    api.NCryptExportKey.argtypes = [handle, handle, wintypes.LPCWSTR, pointer, pointer, dword, ctypes.POINTER(dword), dword]
    api.NCryptSignHash.argtypes = [handle, pointer, pointer, dword, pointer, dword, ctypes.POINTER(dword), dword]
    api.NCryptFreeObject.argtypes = [handle]
    for function in (
        api.NCryptOpenStorageProvider,
        api.NCryptOpenKey,
        api.NCryptCreatePersistedKey,
        api.NCryptSetProperty,
        api.NCryptGetProperty,
        api.NCryptFinalizeKey,
        api.NCryptExportKey,
        api.NCryptSignHash,
        api.NCryptFreeObject,
    ):
        function.restype = ctypes.c_long
    return api
