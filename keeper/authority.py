from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path
from typing import Any, Iterator


AUTHORITY_SCHEMA_VERSION = 1
AUTHORITY_KEY_VERSION = 1


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class AuthorityKey:
    """Installation-local authenticated-writer capability."""

    def __init__(self, data_directory: Path) -> None:
        self.data_directory = data_directory.resolve()
        self.directory = self.data_directory / "authority"
        self.path = self.directory / f"authority-key-v{AUTHORITY_KEY_VERSION}.bin"
        self.directory.mkdir(parents=True, exist_ok=True)
        self._validate_directory()
        self._key = self._load_or_create()
        self._provider_guard = threading.RLock()
        self.key_id = (
            f"keeper-authority:v{AUTHORITY_KEY_VERSION}:"
            f"{hashlib.sha256(self._key).hexdigest()[:16]}"
        )

    def sign(self, purpose: str, record: dict[str, Any]) -> dict[str, Any]:
        if not purpose:
            raise ValueError("authority purpose is required")
        signed = {
            **record,
            "authority_schema_version": AUTHORITY_SCHEMA_VERSION,
            "authority_key_id": self.key_id,
        }
        signed["authenticated_writer_proof"] = hmac.new(
            self._key,
            _authenticated_payload(purpose, signed),
            hashlib.sha256,
        ).hexdigest()
        return signed

    def verify(self, purpose: str, record: object) -> bool:
        if not isinstance(record, dict):
            return False
        proof = record.get("authenticated_writer_proof")
        if (
            record.get("authority_schema_version") != AUTHORITY_SCHEMA_VERSION
            or record.get("authority_key_id") != self.key_id
            or not isinstance(proof, str)
            or len(proof) != 64
        ):
            return False
        expected = hmac.new(
            self._key,
            _authenticated_payload(purpose, record),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(proof, expected)

    @contextmanager
    def provider_launch_guard(self) -> Iterator[None]:
        with self._provider_guard:
            handle = (
                _hold_exclusive_noninheritable(self.path)
                if os.name == "nt"
                else None
            )
            try:
                yield
            finally:
                if handle is not None:
                    _close_windows_handle(handle)

    def _load_or_create(self) -> bytes:
        if self.path.exists():
            return self._load_existing()
        key = secrets.token_bytes(32)
        protected = _protect(key)
        temporary = self.directory / (
            f".authority-key-v{AUTHORITY_KEY_VERSION}."
            f"{os.getpid()}.{secrets.token_hex(8)}.tmp"
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            written = 0
            while written < len(protected):
                count = os.write(descriptor, protected[written:])
                if count <= 0:
                    raise OSError("Keeper authority key temporary write stalled")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            try:
                os.link(temporary, self.path)
            except FileExistsError:
                return self._load_existing()
            except OSError as error:
                raise PermissionError(
                    "Keeper authority key atomic publication failed"
                ) from error
            if os.name != "nt":
                directory_descriptor = os.open(
                    self.directory,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
            published = self._load_existing()
            if not hmac.compare_digest(published, key):
                raise PermissionError(
                    "Keeper authority key publication did not preserve key material"
                )
            return published
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _load_existing(self) -> bytes:
        self._validate_permissions()
        try:
            protected = self.path.read_bytes()
            key = _unprotect(protected)
        except OSError as error:
            raise PermissionError(
                "Keeper authority key could not be loaded"
            ) from error
        if len(key) != 32:
            raise PermissionError("Keeper authority key has an invalid length")
        return key

    def _validate_directory(self) -> None:
        is_junction = getattr(self.directory, "is_junction", lambda: False)
        if (
            self.directory.is_symlink()
            or is_junction()
            or not self.directory.resolve().is_relative_to(self.data_directory)
        ):
            raise PermissionError("Keeper authority directory is unsafe")

    def _validate_permissions(self) -> None:
        if self.path.is_symlink() or not self.path.is_file():
            raise PermissionError("Keeper authority key path is unsafe")
        if os.name != "nt":
            mode = stat.S_IMODE(self.path.stat().st_mode)
            if mode & 0o077:
                raise PermissionError("Keeper authority key permissions are too broad")
        elif not self.path.resolve().is_relative_to(self.directory.resolve()):
            raise PermissionError("Keeper authority key escapes protected storage")


def _authenticated_payload(purpose: str, record: dict[str, Any]) -> bytes:
    value = {
        key: item
        for key, item in record.items()
        if key != "authenticated_writer_proof"
    }
    return (
        purpose.encode("utf-8")
        + b"\0"
        + json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _protect(value: bytes) -> bytes:
    if os.name != "nt":
        return value
    return _crypt_protect(value)


def _unprotect(value: bytes) -> bytes:
    if os.name != "nt":
        return value
    return _crypt_unprotect(value)


def _blob(value: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    buffer = ctypes.create_string_buffer(value)
    return (
        _DataBlob(
            len(value),
            ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
        ),
        buffer,
    )


def _crypt_protect(value: bytes) -> bytes:
    source, source_buffer = _blob(value)
    _ = source_buffer
    target = _DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not crypt32.CryptProtectData(
        ctypes.byref(source),
        "Keeper authority",
        None,
        None,
        None,
        0x1,
        ctypes.byref(target),
    ):
        raise PermissionError(
            f"Keeper authority key protection failed: {ctypes.get_last_error()}"
        )
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(target.pbData)


def _crypt_unprotect(value: bytes) -> bytes:
    source, source_buffer = _blob(value)
    _ = source_buffer
    target = _DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source),
        None,
        None,
        None,
        None,
        0x1,
        ctypes.byref(target),
    ):
        raise PermissionError(
            f"Keeper authority key loading failed: {ctypes.get_last_error()}"
        )
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(target.pbData)


def _hold_exclusive_noninheritable(path: Path) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    set_handle_information = kernel32.SetHandleInformation
    set_handle_information.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    set_handle_information.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    handle = create_file(
        str(path),
        0x80000000,
        0,
        None,
        3,
        0x80,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, invalid_handle}:
        raise PermissionError(
            f"Keeper authority key exclusive lock failed: {ctypes.get_last_error()}"
        )
    if not set_handle_information(handle, 0x1, 0):
        error = ctypes.get_last_error()
        close_handle(handle)
        raise PermissionError(
            f"Keeper authority key inheritance lock failed: {error}"
        )
    return int(handle)


def _close_windows_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    if not close_handle(handle):
        raise PermissionError(
            f"Keeper authority key lock release failed: {ctypes.get_last_error()}"
        )
