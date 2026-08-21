from __future__ import annotations

import ctypes
import hashlib
import os
import secrets
import sys
import uuid
from ctypes import wintypes
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Mapping, Protocol, TypedDict

from keeper.executive.founder_capability import (
    FounderAuthorizationCapability,
    FounderCapabilityClaims,
    ProductionFounderCapabilityIssuer,
    ProductionFounderCapabilityVerifier,
    TestFounderCapabilityIssuer,
    TestFounderCapabilityVerifier,
)

from keeper.executive.models import (
    FounderApprovalChallenge,
    FounderAuthenticatedSession,
)


APPLICATION_IDENTITY: Final = "KEEPER_EXECUTIVE"
PROOF_VERSION: Final = 2
CONFIRMATION_LIFETIME: Final = timedelta(minutes=2)
ERROR_CANCELLED: Final = 1223
CREDUIWIN_GENERIC: Final = 0x1


class _CREDUI_INFOW(ctypes.Structure):
    """Native CREDUI_INFOW from the Windows SDK's wincred.h."""

    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hwndParent", wintypes.HWND),
        ("pszMessageText", wintypes.LPCWSTR),
        ("pszCaptionText", wintypes.LPCWSTR),
        ("hbmBanner", wintypes.HBITMAP),
    ]


class _UnsignedConfirmation(TypedDict):
    session_id: str
    principal_sid: str
    account_name: str
    authentication_method: str
    authenticated_at: str
    expires_at: str
    machine_identity: str
    application_identity: str
    process_identity: str
    challenge_id: str
    challenge_nonce: str
    project_id: str
    charter_id: str
    charter_revision: int
    approval_action: str
    bound_digest: str
    source_user_interaction_id: str
    proof_version: int


@dataclass(frozen=True, slots=True)
class ProductionApprovalConfirmation:
    session_id: str
    principal_sid: str
    account_name: str
    authentication_method: str
    authenticated_at: str
    expires_at: str
    machine_identity: str
    application_identity: str
    process_identity: str
    challenge_id: str
    challenge_nonce: str
    project_id: str
    charter_id: str
    charter_revision: int
    approval_action: str
    bound_digest: str
    source_user_interaction_id: str
    proof_version: int
    proof: str


@dataclass(frozen=True, slots=True)
class TestApprovalConfirmation:
    __test__ = False
    session_id: str
    principal_sid: str
    account_name: str
    authentication_method: str
    authenticated_at: str
    expires_at: str
    machine_identity: str
    application_identity: str
    process_identity: str
    challenge_id: str
    challenge_nonce: str
    project_id: str
    charter_id: str
    charter_revision: int
    approval_action: str
    bound_digest: str
    source_user_interaction_id: str
    proof_version: int
    proof: str


ApprovalConfirmation = ProductionApprovalConfirmation | TestApprovalConfirmation


class ProductionFounderAuthenticator:
    """OS-backed local confirmation. No identity is accepted from the caller."""

    __slots__ = (
        "__machine_identity", "__founder_sid", "__capability_issuer",
        "__sealed",
    )
    __machine_identity: str
    __founder_sid: str
    __capability_issuer: ProductionFounderCapabilityIssuer
    __sealed: bool

    def __init__(self, key_path: Path) -> None:
        if sys.platform != "win32":
            raise RuntimeError(
                "production Founder authentication requires local Windows APIs"
            )
        object.__setattr__(self, "_ProductionFounderAuthenticator__sealed", False)
        # Constructor compatibility only. Production proof and capability
        # signing no longer use an exportable current-user DPAPI key.
        key_path.resolve()
        object.__setattr__(
            self,
            "_ProductionFounderAuthenticator__machine_identity",
            _windows_machine_identity(),
        )
        object.__setattr__(
            self,
            "_ProductionFounderAuthenticator__founder_sid",
            _current_process_sid(),
        )
        object.__setattr__(
            self,
            "_ProductionFounderAuthenticator__capability_issuer",
            ProductionFounderCapabilityIssuer(self.__founder_sid),
        )
        object.__setattr__(self, "_ProductionFounderAuthenticator__sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_ProductionFounderAuthenticator__sealed", False):
            raise AttributeError("production Founder authenticator is immutable")
        object.__setattr__(self, name, value)

    def authenticate(
        self, challenge: FounderApprovalChallenge
    ) -> ProductionApprovalConfirmation:
        try:
            principal_sid, account_name, logon_session = _credential_ui_logon()
        except PermissionError:
            raise
        except OSError as error:
            raise RuntimeError(
                "Windows Founder authentication is unavailable"
            ) from error
        if principal_sid != self.__founder_sid:
            raise PermissionError(
                "authenticated Windows principal is not the provisioned Founder"
            )
        now = datetime.now(UTC)
        unsigned: _UnsignedConfirmation = {
            "session_id": f"founder-session-{uuid.uuid4().hex}",
            "principal_sid": principal_sid,
            "account_name": account_name,
            "authentication_method": "WINDOWS_CREDENTIAL_LOGON",
            "authenticated_at": now.isoformat(),
            "expires_at": min(
                now + CONFIRMATION_LIFETIME,
                datetime.fromisoformat(challenge.expires_at),
            ).isoformat(),
            "machine_identity": self.__machine_identity,
            "application_identity": APPLICATION_IDENTITY,
            "process_identity": f"{os.getpid()}:{logon_session}",
            "challenge_id": challenge.challenge_id,
            "challenge_nonce": challenge.nonce,
            "project_id": challenge.project_id,
            "charter_id": challenge.charter_id,
            "charter_revision": challenge.charter_revision,
            "approval_action": challenge.approval_action,
            "bound_digest": challenge.charter_digest,
            "source_user_interaction_id": (
                f"windows-credential-ui-{uuid.uuid4().hex}"
            ),
            "proof_version": PROOF_VERSION,
        }
        return ProductionApprovalConfirmation(
            **unsigned,
            proof=self.__capability_issuer.sign_confirmation(unsigned),
        )

    def verify(
        self,
        challenge: FounderApprovalChallenge,
        confirmation: ApprovalConfirmation,
    ) -> FounderAuthenticatedSession:
        if type(confirmation) is not ProductionApprovalConfirmation:
            raise PermissionError(
                "production authentication rejects non-production confirmation"
            )
        return _verify_confirmation(
            self.__capability_issuer,
            self.__machine_identity,
            challenge,
            confirmation,
            expected_method="WINDOWS_CREDENTIAL_LOGON",
            expected_principal_sid=self.__founder_sid,
        )

    def issue_authorization_capability(
        self,
        claims: FounderCapabilityClaims,
        confirmation: ApprovalConfirmation,
    ) -> FounderAuthorizationCapability:
        if type(confirmation) is not ProductionApprovalConfirmation:
            raise PermissionError(
                "production capability rejects non-production confirmation"
            )
        return self.__capability_issuer.issue(claims, asdict(confirmation))

    def capability_verifier_configuration(self) -> dict[str, object]:
        return self.__capability_issuer.verifier_configuration()

    def _issue_executive_input_receipt(
        self, unsigned: Mapping[str, object]
    ) -> dict[str, object]:
        return self.__capability_issuer._sign_executive_input_receipt(unsigned)

    def verify_authorization_capability(
        self, value: Mapping[str, object]
    ) -> FounderAuthorizationCapability:
        return ProductionFounderCapabilityVerifier(
            self.capability_verifier_configuration()
        ).verify(value)


class TestFounderAuthenticator:
    """Deterministic test-only trust boundary; never accepted by production."""

    __slots__ = (
        "__principal_sid", "__account_name", "__machine_identity",
        "__capability_issuer", "__sealed",
    )
    __principal_sid: str
    __account_name: str
    __machine_identity: str
    __capability_issuer: TestFounderCapabilityIssuer
    __sealed: bool
    __test__ = False

    def __init__(
        self,
        *,
        principal_sid: str = "S-1-5-21-1000-1000-1000-1001",
        account_name: str = "KEEPER-TEST\\Founder",
        machine_identity: str = "keeper-test-machine",
    ) -> None:
        if not principal_sid.startswith("S-1-"):
            raise ValueError("test principal must use a canonical SID")
        object.__setattr__(self, "_TestFounderAuthenticator__sealed", False)
        object.__setattr__(self, "_TestFounderAuthenticator__principal_sid", principal_sid)
        object.__setattr__(self, "_TestFounderAuthenticator__account_name", account_name)
        object.__setattr__(self, "_TestFounderAuthenticator__machine_identity", machine_identity)
        object.__setattr__(
            self,
            "_TestFounderAuthenticator__capability_issuer",
            TestFounderCapabilityIssuer(),
        )
        object.__setattr__(self, "_TestFounderAuthenticator__sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_TestFounderAuthenticator__sealed", False):
            raise AttributeError("test Founder authenticator is immutable")
        object.__setattr__(self, name, value)

    def authenticate(
        self, challenge: FounderApprovalChallenge
    ) -> TestApprovalConfirmation:
        now = datetime.now(UTC)
        unsigned: _UnsignedConfirmation = {
            "session_id": f"test-founder-session-{uuid.uuid4().hex}",
            "principal_sid": self.__principal_sid,
            "account_name": self.__account_name,
            "authentication_method": "TEST_CHALLENGE_HMAC",
            "authenticated_at": now.isoformat(),
            "expires_at": min(
                now + CONFIRMATION_LIFETIME,
                datetime.fromisoformat(challenge.expires_at),
            ).isoformat(),
            "machine_identity": self.__machine_identity,
            "application_identity": APPLICATION_IDENTITY,
            "process_identity": f"test-process-{os.getpid()}",
            "challenge_id": challenge.challenge_id,
            "challenge_nonce": challenge.nonce,
            "project_id": challenge.project_id,
            "charter_id": challenge.charter_id,
            "charter_revision": challenge.charter_revision,
            "approval_action": challenge.approval_action,
            "bound_digest": challenge.charter_digest,
            "source_user_interaction_id": f"test-confirmation-{uuid.uuid4().hex}",
            "proof_version": PROOF_VERSION,
        }
        return TestApprovalConfirmation(
            **unsigned,
            proof=self.__capability_issuer.sign_confirmation(unsigned),
        )

    def verify(
        self,
        challenge: FounderApprovalChallenge,
        confirmation: ApprovalConfirmation,
    ) -> FounderAuthenticatedSession:
        if type(confirmation) is not TestApprovalConfirmation:
            raise PermissionError(
                "test authentication rejects production confirmation"
            )
        return _verify_confirmation(
            self.__capability_issuer,
            self.__machine_identity,
            challenge,
            confirmation,
            expected_method="TEST_CHALLENGE_HMAC",
            expected_principal_sid=self.__principal_sid,
        )

    def issue_authorization_capability(
        self,
        claims: FounderCapabilityClaims,
        confirmation: ApprovalConfirmation,
    ) -> FounderAuthorizationCapability:
        if type(confirmation) is not TestApprovalConfirmation:
            raise PermissionError(
                "test capability rejects production confirmation"
            )
        return self.__capability_issuer.issue(claims, asdict(confirmation))

    def verify_authorization_capability(
        self, value: Mapping[str, object]
    ) -> FounderAuthorizationCapability:
        return TestFounderCapabilityVerifier().verify(value)

    def _issue_executive_input_receipt(
        self, unsigned: Mapping[str, object]
    ) -> dict[str, object]:
        return self.__capability_issuer.sign_executive_input_receipt(unsigned)


FounderAuthenticator = ProductionFounderAuthenticator | TestFounderAuthenticator


class _ConfirmationVerifier(Protocol):
    def verify_confirmation(
        self, unsigned: Mapping[str, object], signature: str
    ) -> bool: ...


def confirmation_response_digest(confirmation: ApprovalConfirmation) -> str:
    return hashlib.sha256(confirmation.proof.encode("ascii")).hexdigest()


def _verify_confirmation(
    verifier: _ConfirmationVerifier,
    machine_identity: str,
    challenge: FounderApprovalChallenge,
    confirmation: ApprovalConfirmation,
    *,
    expected_method: str,
    expected_principal_sid: str,
) -> FounderAuthenticatedSession:
    unsigned = asdict(confirmation)
    proof = str(unsigned.pop("proof"))
    now = datetime.now(UTC)
    expires = datetime.fromisoformat(confirmation.expires_at)
    authenticated = datetime.fromisoformat(confirmation.authenticated_at)
    if not verifier.verify_confirmation(unsigned, proof):
        raise PermissionError("Founder challenge response proof is invalid")
    if (
        confirmation.authentication_method != expected_method
        or confirmation.application_identity != APPLICATION_IDENTITY
        or confirmation.machine_identity != machine_identity
        or not confirmation.principal_sid.startswith("S-1-")
        or confirmation.principal_sid != expected_principal_sid
        or confirmation.proof_version != PROOF_VERSION
        or confirmation.challenge_id != challenge.challenge_id
        or confirmation.challenge_nonce != challenge.nonce
        or confirmation.project_id != challenge.project_id
        or confirmation.charter_id != challenge.charter_id
        or confirmation.charter_revision != challenge.charter_revision
        or confirmation.approval_action != challenge.approval_action
        or confirmation.bound_digest != challenge.charter_digest
        or expires <= now
        or expires > datetime.fromisoformat(challenge.expires_at)
        or authenticated > now + timedelta(seconds=5)
        or authenticated > expires
    ):
        raise PermissionError(
            "Founder confirmation does not match the exact challenge"
        )
    proof_digest = hashlib.sha256(proof.encode("ascii")).hexdigest()
    return FounderAuthenticatedSession(
        confirmation.session_id,
        2,
        confirmation.principal_sid,
        confirmation.account_name,
        confirmation.authentication_method,
        confirmation.authenticated_at,
        confirmation.expires_at,
        confirmation.machine_identity,
        confirmation.application_identity,
        confirmation.process_identity,
        confirmation.challenge_id,
        confirmation.project_id,
        confirmation.charter_id,
        confirmation.charter_revision,
        confirmation.approval_action,
        confirmation.bound_digest,
        proof_digest,
        "ACTIVE",
        None,
        None,
    )


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint32),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _blob(data: bytes) -> tuple[_DataBlob, object]:
    buffer = ctypes.create_string_buffer(data)
    return (
        _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))),
        buffer,
    )


def _protect(data: bytes) -> bytes:
    source, source_buffer = _blob(data)
    output = _DataBlob()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(source), "Keeper Founder authentication", None, None,
        None, 0x1, ctypes.byref(output)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        del source_buffer
        ctypes.windll.kernel32.LocalFree(output.pbData)


def _unprotect(data: bytes) -> bytes:
    source, source_buffer = _blob(data)
    output = _DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(source), None, None, None, None, 0x1, ctypes.byref(output)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        del source_buffer
        ctypes.windll.kernel32.LocalFree(output.pbData)


def _load_or_create_dpapi_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        key = _unprotect(path.read_bytes())
        if len(key) != 32:
            raise RuntimeError("production Founder proof key is invalid")
        return key
    key = secrets.token_bytes(32)
    protected = _protect(key)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, protected)
    finally:
        os.close(descriptor)
    return key


def _windows_machine_identity() -> str:
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            machine_guid = str(winreg.QueryValueEx(key, "MachineGuid")[0])
    except OSError as error:
        raise RuntimeError("Windows machine identity is unavailable") from error
    return hashlib.sha256(
        f"keeper-machine:{machine_guid}".encode("utf-8")
    ).hexdigest()


def _credential_ui_logon() -> tuple[str, str, str]:
    """Prompt for Windows credentials, validate them, and return token identity."""
    if sys.platform != "win32":
        raise RuntimeError(
            "Windows Founder authentication requires local Windows APIs"
        )

    credui = ctypes.windll.credui
    advapi = ctypes.windll.advapi32
    kernel = ctypes.windll.kernel32
    credui.CredUIPromptForWindowsCredentialsW.argtypes = [
        ctypes.POINTER(_CREDUI_INFOW),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.ULONG),
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
        ctypes.POINTER(wintypes.BOOL),
        wintypes.DWORD,
    ]
    credui.CredUIPromptForWindowsCredentialsW.restype = wintypes.DWORD
    credui.CredUnPackAuthenticationBufferW.argtypes = [
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    credui.CredUnPackAuthenticationBufferW.restype = wintypes.BOOL
    advapi.LogonUserW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.LogonUserW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL

    caption = ctypes.create_unicode_buffer("Keeper Founder Authentication")
    message = ctypes.create_unicode_buffer(
        "Confirm the Windows identity authorized to approve this Keeper action."
    )
    ui_info = _CREDUI_INFOW(
        cbSize=ctypes.sizeof(_CREDUI_INFOW),
        hwndParent=None,
        pszMessageText=ctypes.cast(message, wintypes.LPCWSTR),
        pszCaptionText=ctypes.cast(caption, wintypes.LPCWSTR),
        hbmBanner=None,
    )
    package = wintypes.ULONG(0)
    output = ctypes.c_void_p(None)
    output_size = wintypes.ULONG(0)
    save = wintypes.BOOL(False)
    username = ctypes.create_unicode_buffer(512)
    domain = ctypes.create_unicode_buffer(512)
    password = ctypes.create_unicode_buffer(512)
    username_size = wintypes.DWORD(len(username))
    domain_size = wintypes.DWORD(len(domain))
    password_size = wintypes.DWORD(len(password))
    token = wintypes.HANDLE()
    try:
        result = credui.CredUIPromptForWindowsCredentialsW(
            ctypes.byref(ui_info), 0, ctypes.byref(package), None, 0,
            ctypes.byref(output), ctypes.byref(output_size),
            ctypes.byref(save), CREDUIWIN_GENERIC,
        )
        if result == ERROR_CANCELLED:
            raise PermissionError(
                "Windows Founder authentication was canceled"
            )
        if result != 0:
            raise OSError(
                result, "Windows Founder credential prompt failed"
            )
        if not output.value:
            raise OSError(
                "Windows Founder credential prompt returned no credential buffer"
            )
        if output_size.value == 0:
            raise OSError(
                "Windows Founder credential prompt returned an empty credential buffer"
            )
        if not credui.CredUnPackAuthenticationBufferW(
            0, output, output_size, username, ctypes.byref(username_size),
            domain, ctypes.byref(domain_size), password,
            ctypes.byref(password_size),
        ):
            raise ctypes.WinError()
        if not advapi.LogonUserW(
            username.value, domain.value or None, password.value,
            2, 0, ctypes.byref(token),
        ):
            raise PermissionError("Windows rejected the supplied Founder credentials")
        sid, logon_session = _token_identity(token)
        account = (
            f"{domain.value}\\{username.value}"
            if domain.value
            else username.value
        )
        return sid, account, logon_session
    finally:
        _secure_zero(ctypes.addressof(username), ctypes.sizeof(username))
        _secure_zero(ctypes.addressof(domain), ctypes.sizeof(domain))
        _secure_zero(ctypes.addressof(password), ctypes.sizeof(password))
        if token:
            kernel.CloseHandle(token)
        _zero_and_free_authentication_buffer(output, output_size.value)


def _secure_zero(address: int, length: int) -> None:
    if address and length > 0:
        ctypes.memset(address, 0, length)


def _zero_and_free_authentication_buffer(
    buffer: ctypes.c_void_p, length: int
) -> None:
    if not buffer:
        return
    free = ctypes.windll.ole32.CoTaskMemFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = None
    try:
        _secure_zero(int(buffer.value or 0), length)
    finally:
        free(buffer)


def _token_identity(token: object) -> tuple[str, str]:
    from ctypes import wintypes

    advapi = ctypes.windll.advapi32
    kernel = ctypes.windll.kernel32
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    required = wintypes.DWORD()
    advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
    user_buffer = ctypes.create_string_buffer(required.value)
    if not advapi.GetTokenInformation(
        token, 1, user_buffer, required, ctypes.byref(required)
    ):
        raise ctypes.WinError()
    sid_pointer = ctypes.cast(
        user_buffer, ctypes.POINTER(ctypes.c_void_p)
    ).contents.value
    sid_text = ctypes.c_void_p()
    if not advapi.ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid_text)):
        raise ctypes.WinError()
    try:
        sid = ctypes.wstring_at(sid_text)
    finally:
        kernel.LocalFree(sid_text)

    stats_size = wintypes.DWORD()
    advapi.GetTokenInformation(token, 10, None, 0, ctypes.byref(stats_size))
    stats = ctypes.create_string_buffer(stats_size.value)
    if not advapi.GetTokenInformation(
        token, 10, stats, stats_size, ctypes.byref(stats_size)
    ):
        raise ctypes.WinError()
    class _Luid(ctypes.Structure):
        _fields_ = [
            ("LowPart", wintypes.DWORD),
            ("HighPart", wintypes.LONG),
        ]

    # TOKEN_STATISTICS begins with TokenId, followed by AuthenticationId.
    authentication_id = ctypes.cast(
        ctypes.byref(stats, ctypes.sizeof(_Luid)),
        ctypes.POINTER(_Luid),
    ).contents
    return (
        sid,
        f"{authentication_id.HighPart & 0xffffffff:08x}:"
        f"{authentication_id.LowPart:08x}",
    )


def _current_process_sid() -> str:
    from ctypes import wintypes

    advapi = ctypes.windll.advapi32
    kernel = ctypes.windll.kernel32
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(
        kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)
    ):
        raise RuntimeError("current Windows principal is unavailable")
    try:
        sid, _ = _token_identity(token)
        return sid
    finally:
        kernel.CloseHandle(token)
