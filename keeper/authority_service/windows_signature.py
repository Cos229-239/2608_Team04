from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path
from typing import Any


_CERT_QUERY_OBJECT_FILE = 1
_CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
_CERT_QUERY_FORMAT_FLAG_BINARY = 2
_CMSG_SIGNER_INFO_PARAM = 6
_CERT_FIND_SUBJECT_CERT = 0x000B0000
_CERT_SHA1_HASH_PROP_ID = 3
_CERT_X500_NAME_STR = 3
_X509_ASN_ENCODING = 0x00000001
_PKCS_7_ASN_ENCODING = 0x00010000
_ENCODING = _X509_ASN_ENCODING | _PKCS_7_ASN_ENCODING
_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000
_TRUST_E_NOSIGNATURE = 0x800B0100


class _Guid(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _CryptDataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


_CryptIntegerBlob = _CryptDataBlob
_CertNameBlob = _CryptDataBlob


class _CryptAlgorithmIdentifier(ctypes.Structure):
    _fields_ = [
        ("pszObjId", ctypes.c_char_p),
        ("Parameters", _CryptDataBlob),
    ]


class _CryptAttribute(ctypes.Structure):
    _fields_ = [
        ("pszObjId", ctypes.c_char_p),
        ("cValue", wintypes.DWORD),
        ("rgValue", ctypes.POINTER(_CryptDataBlob)),
    ]


class _CryptAttributes(ctypes.Structure):
    _fields_ = [
        ("cAttr", wintypes.DWORD),
        ("rgAttr", ctypes.POINTER(_CryptAttribute)),
    ]


class _CmsgSignerInfo(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("Issuer", _CertNameBlob),
        ("SerialNumber", _CryptIntegerBlob),
        ("HashAlgorithm", _CryptAlgorithmIdentifier),
        ("HashEncryptionAlgorithm", _CryptAlgorithmIdentifier),
        ("EncryptedHash", _CryptDataBlob),
        ("AuthAttrs", _CryptAttributes),
        ("UnauthAttrs", _CryptAttributes),
    ]


class _CryptBitBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ("cUnusedBits", wintypes.DWORD),
    ]


class _CertPublicKeyInfo(ctypes.Structure):
    _fields_ = [
        ("Algorithm", _CryptAlgorithmIdentifier),
        ("PublicKey", _CryptBitBlob),
    ]


class _CertInfo(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("SerialNumber", _CryptIntegerBlob),
        ("SignatureAlgorithm", _CryptAlgorithmIdentifier),
        ("Issuer", _CertNameBlob),
        ("NotBefore", wintypes.FILETIME),
        ("NotAfter", wintypes.FILETIME),
        ("Subject", _CertNameBlob),
        ("SubjectPublicKeyInfo", _CertPublicKeyInfo),
        ("IssuerUniqueId", _CryptBitBlob),
        ("SubjectUniqueId", _CryptBitBlob),
        ("cExtension", wintypes.DWORD),
        ("rgExtension", wintypes.LPVOID),
    ]


class _CertContext(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", ctypes.POINTER(_CertInfo)),
        ("hCertStore", wintypes.HANDLE),
    ]


class _CryptProviderCert(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pCert", ctypes.POINTER(_CertContext)),
    ]


class _CryptProviderSigner(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("sftVerifyAsOf", wintypes.FILETIME),
        ("csCertChain", wintypes.DWORD),
        ("pasCertChain", ctypes.POINTER(_CryptProviderCert)),
    ]


class _WintrustFileInfo(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(_Guid)),
    ]


class _WintrustData(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", wintypes.LPVOID),
        ("pSIPClientData", wintypes.LPVOID),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(_WintrustFileInfo)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", wintypes.LPVOID),
    ]


_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _Guid(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)


def authenticode_identity(executable: Path) -> dict[str, Any]:
    """Validate Authenticode in-process under the caller's thread token.

    No child process is created.  This matters to KeeperAuthority because the
    service may temporarily impersonate an authenticated desktop client solely
    while measuring that client's reviewed provider executable.
    """
    if os.name != "nt":
        raise RuntimeError("Authenticode verification requires Windows")
    path = executable.resolve(strict=True)
    _verify_trust(path)
    subject, thumbprint = _signer_identity(path)
    return {
        "status": "Valid",
        "publisher_subject": subject,
        "certificate_thumbprint": thumbprint,
        "source": "windows-authenticode",
    }


def authenticode_identity_from_handle(
    handle: int, canonical_path: Path
) -> dict[str, Any]:
    """Validate Authenticode against one already-open immutable file object."""
    if os.name != "nt" or isinstance(handle, bool) or handle <= 0:
        raise RuntimeError("Handle-bound Authenticode verification requires Windows")
    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    verify = wintrust.WinVerifyTrust
    verify.argtypes = [wintypes.HWND, ctypes.POINTER(_Guid), wintypes.LPVOID]
    verify.restype = ctypes.c_long
    provider_data = wintrust.WTHelperProvDataFromStateData
    provider_data.argtypes = [wintypes.HANDLE]
    provider_data.restype = wintypes.LPVOID
    signer_from_chain = wintrust.WTHelperGetProvSignerFromChain
    signer_from_chain.argtypes = [wintypes.LPVOID, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    signer_from_chain.restype = ctypes.POINTER(_CryptProviderSigner)
    if not canonical_path.is_absolute():
        raise PermissionError("Handle-bound Authenticode path is invalid")
    file_info = _WintrustFileInfo(
        ctypes.sizeof(_WintrustFileInfo),
        str(canonical_path),
        wintypes.HANDLE(handle),
        None,
    )
    data = _WintrustData(
        ctypes.sizeof(_WintrustData),
        None,
        None,
        _WTD_UI_NONE,
        _WTD_REVOKE_NONE,
        _WTD_CHOICE_FILE,
        ctypes.pointer(file_info),
        _WTD_STATEACTION_VERIFY,
        None,
        None,
        _WTD_CACHE_ONLY_URL_RETRIEVAL,
        0,
        None,
    )
    status = int(
        verify(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(data))
    )
    try:
        if status != 0 or not data.hWVTStateData:
            raise PermissionError(
                f"Authenticode verification failed (status=0x{status & 0xFFFFFFFF:08X})"
            )
        chain = provider_data(data.hWVTStateData)
        signer = signer_from_chain(chain, 0, False, 0) if chain else None
        if (
            not signer
            or signer.contents.csCertChain <= 0
            or not signer.contents.pasCertChain
            or not signer.contents.pasCertChain[0].pCert
        ):
            raise PermissionError("Authenticode signer certificate is unavailable")
        subject, thumbprint = _certificate_identity(
            signer.contents.pasCertChain[0].pCert
        )
        return {
            "status": "Valid",
            "publisher_subject": subject,
            "certificate_thumbprint": thumbprint,
            "source": "windows-authenticode",
        }
    finally:
        data.dwStateAction = _WTD_STATEACTION_CLOSE
        close_status = int(
            verify(
                None,
                ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(data),
            )
        )
        if close_status != 0:
            raise PermissionError(
                "Handle-bound Authenticode cleanup failed "
                f"(status=0x{close_status & 0xFFFFFFFF:08X})"
            )


def authenticode_enrollment_binding(executable: Path) -> dict[str, Any]:
    """Measure a reviewed Host package without pretending unsigned means valid.

    Phase-2 development artifacts are locally built and may be explicitly
    unsigned.  The exact ``NotSigned`` observation is bound alongside the
    package manifest, executable digest, file identity, and Founder approval.
    Invalid, expired, revoked, or otherwise untrusted signatures still reject.
    """
    if os.name != "nt":
        raise RuntimeError("Authenticode verification requires Windows")
    path = executable.resolve(strict=True)
    status = _verify_trust_status(path)
    if status == 0:
        subject, thumbprint = _signer_identity(path)
        return {
            "status": "Valid",
            "publisher_subject": subject,
            "certificate_thumbprint": thumbprint,
            "source": "windows-authenticode",
        }
    if status & 0xFFFFFFFF == _TRUST_E_NOSIGNATURE:
        return {
            "status": "NotSigned",
            "publisher_subject": None,
            "certificate_thumbprint": None,
            "source": "windows-authenticode",
        }
    raise PermissionError(
        f"Authenticode verification failed (status=0x{status & 0xFFFFFFFF:08X})"
    )


def _verify_trust(path: Path) -> None:
    status = _verify_trust_status(path)
    if status != 0:
        raise PermissionError(
            f"Authenticode verification failed (status=0x{status & 0xFFFFFFFF:08X})"
        )


def _verify_trust_status(path: Path) -> int:
    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    verify = wintrust.WinVerifyTrust
    verify.argtypes = [wintypes.HWND, ctypes.POINTER(_Guid), wintypes.LPVOID]
    verify.restype = ctypes.c_long
    file_info = _WintrustFileInfo(
        ctypes.sizeof(_WintrustFileInfo), str(path), None, None
    )
    data = _WintrustData(
        ctypes.sizeof(_WintrustData),
        None,
        None,
        _WTD_UI_NONE,
        _WTD_REVOKE_NONE,
        _WTD_CHOICE_FILE,
        ctypes.pointer(file_info),
        _WTD_STATEACTION_VERIFY,
        None,
        None,
        _WTD_CACHE_ONLY_URL_RETRIEVAL,
        0,
        None,
    )
    status = int(
        verify(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(data))
    )
    try:
        return status
    finally:
        data.dwStateAction = _WTD_STATEACTION_CLOSE
        verify(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(data))


def _signer_identity(path: Path) -> tuple[str, str]:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    query = crypt32.CryptQueryObject
    query.argtypes = [
        wintypes.DWORD,
        wintypes.LPCVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    query.restype = wintypes.BOOL
    get_param = crypt32.CryptMsgGetParam
    get_param.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_param.restype = wintypes.BOOL
    find = crypt32.CertFindCertificateInStore
    find.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    find.restype = ctypes.POINTER(_CertContext)
    name_to_string = crypt32.CertNameToStrW
    name_to_string.argtypes = [
        wintypes.DWORD,
        ctypes.POINTER(_CertNameBlob),
        wintypes.DWORD,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    name_to_string.restype = wintypes.DWORD
    get_property = crypt32.CertGetCertificateContextProperty
    get_property.argtypes = [
        ctypes.POINTER(_CertContext),
        wintypes.DWORD,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_property.restype = wintypes.BOOL
    crypt32.CertFreeCertificateContext.argtypes = [ctypes.POINTER(_CertContext)]
    crypt32.CryptMsgClose.argtypes = [wintypes.HANDLE]
    crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]

    encoding = wintypes.DWORD()
    content_type = wintypes.DWORD()
    format_type = wintypes.DWORD()
    store = wintypes.HANDLE()
    message = wintypes.HANDLE()
    context = wintypes.LPVOID()
    if not query(
        _CERT_QUERY_OBJECT_FILE,
        str(path),
        _CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        _CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        ctypes.byref(encoding),
        ctypes.byref(content_type),
        ctypes.byref(format_type),
        ctypes.byref(store),
        ctypes.byref(message),
        ctypes.byref(context),
    ):
        raise PermissionError(
            f"Authenticode signer query failed: {ctypes.get_last_error()}"
        )
    certificate: Any = None
    try:
        needed = wintypes.DWORD()
        if not get_param(
            message, _CMSG_SIGNER_INFO_PARAM, 0, None, ctypes.byref(needed)
        ) or not needed.value:
            raise PermissionError("Authenticode signer information is unavailable")
        signer_buffer = ctypes.create_string_buffer(needed.value)
        if not get_param(
            message,
            _CMSG_SIGNER_INFO_PARAM,
            0,
            signer_buffer,
            ctypes.byref(needed),
        ):
            raise PermissionError("Authenticode signer information is invalid")
        signer = ctypes.cast(
            signer_buffer, ctypes.POINTER(_CmsgSignerInfo)
        ).contents
        certificate_info = _CertInfo()
        certificate_info.Issuer = signer.Issuer
        certificate_info.SerialNumber = signer.SerialNumber
        certificate = find(
            store,
            _ENCODING,
            0,
            _CERT_FIND_SUBJECT_CERT,
            ctypes.byref(certificate_info),
            None,
        )
        if not certificate:
            raise PermissionError("Authenticode signer certificate is unavailable")
        return _certificate_identity(certificate)
    finally:
        if certificate:
            crypt32.CertFreeCertificateContext(certificate)
        if message.value:
            crypt32.CryptMsgClose(message)
        if store.value:
            crypt32.CertCloseStore(store, 0)


def _certificate_identity(
    certificate: Any,
) -> tuple[str, str]:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    name_to_string = crypt32.CertNameToStrW
    name_to_string.argtypes = [
        wintypes.DWORD,
        ctypes.POINTER(_CertNameBlob),
        wintypes.DWORD,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    name_to_string.restype = wintypes.DWORD
    get_property = crypt32.CertGetCertificateContextProperty
    get_property.argtypes = [
        ctypes.POINTER(_CertContext),
        wintypes.DWORD,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_property.restype = wintypes.BOOL
    subject_blob = certificate.contents.pCertInfo.contents.Subject
    subject_length = name_to_string(
        _ENCODING, ctypes.byref(subject_blob), _CERT_X500_NAME_STR, None, 0
    )
    if subject_length <= 1:
        raise PermissionError("Authenticode signer subject is unavailable")
    subject_buffer = ctypes.create_unicode_buffer(subject_length)
    if not name_to_string(
        _ENCODING,
        ctypes.byref(subject_blob),
        _CERT_X500_NAME_STR,
        subject_buffer,
        subject_length,
    ):
        raise PermissionError("Authenticode signer subject is invalid")
    digest_size = wintypes.DWORD()
    if not get_property(
        certificate,
        _CERT_SHA1_HASH_PROP_ID,
        None,
        ctypes.byref(digest_size),
    ) or digest_size.value != 20:
        raise PermissionError("Authenticode signer thumbprint is unavailable")
    digest = (ctypes.c_ubyte * digest_size.value)()
    if not get_property(
        certificate,
        _CERT_SHA1_HASH_PROP_ID,
        digest,
        ctypes.byref(digest_size),
    ):
        raise PermissionError("Authenticode signer thumbprint is invalid")
    subject = subject_buffer.value
    thumbprint = bytes(digest).hex().upper()
    if not subject or not thumbprint:
        raise PermissionError("Authenticode identity is incomplete")
    return subject, thumbprint
