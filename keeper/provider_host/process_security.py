from __future__ import annotations

import hashlib
import os
import re
import ctypes
from ctypes import wintypes
from pathlib import Path
from typing import Mapping

from keeper.authority_service.process_security import (
    ProcessSecurityError,
    ProcessSecuritySnapshot,
    ProcessSecurityStage,
    _ensure_current_process_sid_query_access,
    _ensure_current_process_token_sid_query_access,
)
from keeper.authority_service.windows_signature import (
    authenticode_enrollment_binding,
)
from keeper.provider_host.enrollment import stable_host_identity
from keeper.provider_host.identity import UserBinding, current_user_binding
from keeper.provider_host.install import ProviderHostInstaller


_SERVICE_SID = re.compile(r"S-1-5-80-(?:\d+-){4}\d+")
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


def ensure_provider_host_process_service_query_access(
    *,
    service_sid: str,
    binding: UserBinding,
    host_id: str,
    host_key_name: str,
    installation: Mapping[str, object],
) -> ProcessSecuritySnapshot:
    """Validate the signed Host installation, then grant exact service QLI.

    No process other than the current Host is opened.  The shared descriptor
    primitive duplicates the current-process pseudo-handle with only
    READ_CONTROL | WRITE_DAC and preserves every pre-existing descriptor
    property while adding the exact service-SID 0x1000 ACE.
    """
    if os.name != "nt":
        raise RuntimeError("Provider Host process security is unavailable")
    if not _SERVICE_SID.fullmatch(service_sid):
        raise ProcessSecurityError(
            ProcessSecurityStage.VALIDATE_IDENTITY,
            "KeeperAuthority service SID is invalid",
        )
    try:
        _validate_provider_host_process(
            service_sid=service_sid,
            binding=binding,
            host_id=host_id,
            host_key_name=host_key_name,
            installation=installation,
        )
    except ProcessSecurityError:
        raise
    except (FileNotFoundError, OSError, PermissionError, RuntimeError, ValueError) as error:
        raise ProcessSecurityError(
            ProcessSecurityStage.VALIDATE_IDENTITY,
            "Provider Host process or installation identity differs",
        ) from error
    process_snapshot = _ensure_current_process_sid_query_access(
        service_sid,
        subject="Provider Host",
    )
    _ensure_current_process_token_sid_query_access(
        service_sid,
        subject="Provider Host",
    )
    return process_snapshot


def _validate_provider_host_process(
    *,
    service_sid: str,
    binding: UserBinding,
    host_id: str,
    host_key_name: str,
    installation: Mapping[str, object],
) -> None:
    if current_user_binding() != binding:
        raise PermissionError("Provider Host configured user binding differs")
    profile_path = Path(binding.profile_path)
    profile = profile_path.resolve(strict=True)
    if os.path.normcase(str(profile_path)) != os.path.normcase(str(profile)):
        raise PermissionError("Provider Host profile path is aliased")
    value = dict(installation)
    if set(value) != _INSTALLATION_FIELDS:
        raise PermissionError("Provider Host committed installation is invalid")
    install_path = (
        profile / "AppData" / "Local" / "Programs" / "DarkSage" / "KeeperProviderHost"
    )
    install_root = install_path.resolve(strict=True)
    signed_install_root = Path(_text(value, "install_root"))
    if (
        os.path.normcase(str(install_path)) != os.path.normcase(str(install_root))
        or os.path.normcase(str(signed_install_root))
        != os.path.normcase(str(install_root))
    ):
        raise PermissionError("Provider Host install root is aliased")
    startup_path = (
        profile
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )
    startup_root = startup_path.resolve(strict=True)
    if os.path.normcase(str(startup_path)) != os.path.normcase(str(startup_root)):
        raise PermissionError("Provider Host startup root is aliased")
    installer = ProviderHostInstaller(
        install_root,
        startup_root,
        owner_sid=binding.user_sid,
        authority_service_sid=service_sid,
    )
    status = installer.status()
    current = status.get("current")
    if (
        status.get("transaction_pending") is not False
        or status.get("startup_registered") is not True
        or not isinstance(current, dict)
    ):
        raise PermissionError("Provider Host installed package selection differs")
    version = _text(value, "package_version")
    if _text(current, "version") != version:
        raise PermissionError("Provider Host installed package version differs")
    selected_path = Path(_text(current, "artifact_path"))
    expected_executable = selected_path.resolve(strict=True)
    signed_executable = Path(_text(value, "executable_path"))
    expected_version_path = (
        install_root / "versions" / version / "KeeperProviderHost.exe"
    ).resolve(strict=True)
    package_sha256 = _digest(value, "manifest_sha256")
    executable_sha256 = _digest(value, "executable_sha256")
    expected_host_id, expected_key_name = stable_host_identity(
        binding.user_sid,
        package_sha256,
    )
    if host_id != expected_host_id or host_key_name != expected_key_name:
        raise PermissionError("Provider Host signed installation identity differs")
    if (
        os.path.normcase(str(selected_path))
        != os.path.normcase(str(expected_executable))
        or os.path.normcase(str(signed_executable))
        != os.path.normcase(str(expected_executable))
        or os.path.normcase(str(_current_process_image_path()))
        != os.path.normcase(str(expected_executable))
        or os.path.normcase(str(expected_executable))
        != os.path.normcase(str(expected_version_path))
    ):
        raise PermissionError("Provider Host process executable path differs")
    startup_launcher = startup_root / "KeeperProviderHost.cmd"
    expected_launcher = (
        "@echo off\r\n"
        f'"{expected_executable}" run '
        f'--config "{install_root / "state" / "provider-host-enrollment.json"}"\r\n'
    ).encode("utf-8")
    if startup_launcher.read_bytes() != expected_launcher:
        raise PermissionError("Provider Host startup launcher content differs")
    before = expected_executable.stat()
    expected_identity = _object(
        value.get("executable_file_identity"),
        "executable file identity",
    )
    if (
        set(expected_identity) != _FILE_IDENTITY_FIELDS
        or expected_identity.get("schema_version") != 1
        or _file_identity_mapping(before) != expected_identity
        or _positive_int(value.get("executable_size")) != before.st_size
        or _digest(current, "artifact_sha256") != executable_sha256
        or _digest(current, "package_sha256") != package_sha256
        or _sha256(expected_executable) != executable_sha256
    ):
        raise PermissionError("Provider Host executable content differs")
    if dict(authenticode_enrollment_binding(expected_executable)) != _object(
        value.get("authenticode_binding"),
        "Authenticode binding",
    ):
        raise PermissionError("Provider Host executable signer identity differs")
    after = expected_executable.stat()
    if _file_identity(before) != _file_identity(after):
        raise PermissionError("Provider Host executable file identity changed")
    installer.attest_protected_tree()


def _current_process_image_path() -> Path:
    """Return the exact current Windows process image, independent of Python.

    Standalone Nuitka applications expose their bundled Python runtime through
    ``sys.executable`` rather than the outer executable.  Windows owns the
    authoritative process-image identity, so the Host observes its own image
    directly and rejects aliases or an unverifiable path.
    """
    if os.name != "nt":
        raise RuntimeError("Provider Host process image requires Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    capacity = wintypes.DWORD(32768)
    buffer = ctypes.create_unicode_buffer(capacity.value)
    process = kernel32.GetCurrentProcess()
    if not process or not kernel32.QueryFullProcessImageNameW(
        process,
        0,
        buffer,
        ctypes.byref(capacity),
    ):
        raise PermissionError(
            "Provider Host process image is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    if capacity.value <= 0 or capacity.value >= len(buffer):
        raise PermissionError("Provider Host process image is invalid")
    raw = Path(buffer.value)
    if not raw.is_absolute():
        raise PermissionError("Provider Host process image is not absolute")
    resolved = raw.resolve(strict=True)
    if os.path.normcase(str(raw)) != os.path.normcase(str(resolved)):
        raise PermissionError("Provider Host process image is aliased")
    return resolved


def current_host_executable_attestation() -> dict[str, object]:
    """Measure the current Host image for the signed Authority hello."""
    executable = _current_process_image_path()
    before = executable.stat()
    digest = _sha256(executable)
    after = executable.stat()
    if _file_identity(before) != _file_identity(after):
        raise PermissionError("Provider Host executable changed during attestation")
    return {
        "file_identity": _file_identity_mapping(after),
        "sha256": digest,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _text(value: Mapping[str, object], field: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise PermissionError(f"Provider Host {field} is invalid")
    return result


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PermissionError(f"Provider Host {label} is invalid")
    return dict(value)


def _digest(value: Mapping[str, object], field: str) -> str:
    result = _text(value, field)
    if len(result) != 64 or any(
        character not in "0123456789abcdef" for character in result
    ):
        raise PermissionError(f"Provider Host {field} is invalid")
    return result


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
    )


def _file_identity_mapping(value: os.stat_result) -> dict[str, int]:
    return {
        "device_id": int(value.st_dev),
        "file_id": int(value.st_ino),
        "modified_ns": int(value.st_mtime_ns),
        "schema_version": 1,
        "size": int(value.st_size),
    }


def _positive_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PermissionError("Provider Host executable size is invalid")
    return value
