from __future__ import annotations

import hashlib
import os
import ctypes
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol, cast

import pytest

from keeper.authority_service.process_security import (
    ProcessAce,
    ProcessSecurityError,
    ProcessSecuritySnapshot,
    ProcessSecurityStage,
)
from keeper.provider_host import cli as cli_module
from keeper.provider_host import process_security
from keeper.provider_host.enrollment import stable_host_identity
from keeper.provider_host.identity import UserBinding


SERVICE_SID = "S-1-5-80-1-2-3-4-5"
USER_SID = "S-1-5-21-1000-1000-1000-1001"


@dataclass
class _Fixture:
    binding: UserBinding
    executable: Path
    executable_sha256: str
    package_sha256: str
    host_id: str
    host_key_name: str
    installation: dict[str, object]
    installer: type[_Installer]
    calls: list[str]


class _Installer(Protocol):
    def status(self) -> dict[str, object]: ...

    def attest_protected_tree(self) -> str: ...


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Fixture:
    profile = tmp_path / "profile"
    install_root = (
        profile
        / "AppData"
        / "Local"
        / "Programs"
        / "DarkSage"
        / "KeeperProviderHost"
    )
    executable = install_root / "versions" / "1.7.28" / "KeeperProviderHost.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"exact-disposable-provider-host")
    startup = (
        profile
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )
    startup.mkdir(parents=True)
    launcher = startup / "KeeperProviderHost.cmd"
    launcher.write_bytes(
        (
            "@echo off\r\n"
            f'"{executable.resolve(strict=True)}" run '
            f'--config "{install_root.resolve(strict=True) / "state" / "provider-host-enrollment.json"}"\r\n'
        ).encode("utf-8")
    )
    package_sha256 = "a" * 64
    executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
    binding = UserBinding(USER_SID, 7, str(profile.resolve(strict=True)))
    host_id, host_key_name = stable_host_identity(USER_SID, package_sha256)
    stat_result = executable.stat()
    authenticode = {
        "certificate_thumbprint": None,
        "publisher_subject": None,
        "source": "windows-authenticode",
        "status": "NotSigned",
    }
    installation: dict[str, object] = {
        "authenticode_binding": authenticode,
        "executable_file_identity": {
            "device_id": int(stat_result.st_dev),
            "file_id": int(stat_result.st_ino),
            "modified_ns": int(stat_result.st_mtime_ns),
            "schema_version": 1,
            "size": int(stat_result.st_size),
        },
        "executable_path": str(executable.resolve(strict=True)),
        "executable_sha256": executable_sha256,
        "executable_size": int(stat_result.st_size),
        "install_root": str(install_root.resolve(strict=True)),
        "manifest_sha256": package_sha256,
        "package_version": "1.7.28",
    }
    calls: list[str] = []

    class Installer:
        def __init__(
            self,
            root: Path,
            startup_root: Path,
            *,
            owner_sid: str,
            authority_service_sid: str,
        ) -> None:
            assert root == install_root.resolve(strict=True)
            assert startup_root == startup.resolve(strict=True)
            assert owner_sid == USER_SID
            assert authority_service_sid == SERVICE_SID

        def status(self) -> dict[str, object]:
            calls.append("status")
            return {
                "installed": True,
                "current": {
                    "version": "1.7.28",
                    "artifact_path": str(executable.resolve(strict=True)),
                    "artifact_sha256": executable_sha256,
                    "package_sha256": package_sha256,
                    "previous_version": "1.7.17",
                    "schema_version": 2,
                    "selected_at": "2026-08-11T00:00:00Z",
                },
                "startup_registered": True,
                "transaction_pending": False,
            }

        def attest_protected_tree(self) -> str:
            calls.append("attest")
            return "b" * 64

    monkeypatch.setattr(process_security, "ProviderHostInstaller", Installer)
    monkeypatch.setattr(
        process_security,
        "current_user_binding",
        lambda: binding,
    )
    monkeypatch.setattr(
        process_security,
        "_current_process_image_path",
        lambda: executable.resolve(strict=True),
    )
    monkeypatch.setattr(
        process_security,
        "authenticode_enrollment_binding",
        lambda path: dict(authenticode),
    )
    return _Fixture(
        binding,
        executable,
        executable_sha256,
        package_sha256,
        host_id,
        host_key_name,
        installation,
        Installer,
        calls,
    )


def _snapshot() -> ProcessSecuritySnapshot:
    return ProcessSecuritySnapshot(
        owner_sid=USER_SID,
        group_sid=USER_SID,
        control=0x8004,
        revision=1,
        dacl_defaulted=False,
        aces=(ProcessAce("allow", SERVICE_SID, 0x1000, 0),),
    )


def test_exact_installed_host_is_attested_before_process_grant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    result = _snapshot()

    def apply(service_sid: str, *, subject: str) -> ProcessSecuritySnapshot:
        assert fixture.calls == ["status", "attest"]
        assert service_sid == SERVICE_SID
        assert subject == "Provider Host"
        fixture.calls.append("grant")
        return result

    monkeypatch.setattr(
        process_security,
        "_ensure_current_process_sid_query_access",
        apply,
    )
    token_result = _snapshot()

    def apply_token(service_sid: str, *, subject: str) -> ProcessSecuritySnapshot:
        assert fixture.calls == ["status", "attest", "grant"]
        assert service_sid == SERVICE_SID
        assert subject == "Provider Host"
        fixture.calls.append("grant-token-query")
        return token_result

    monkeypatch.setattr(
        process_security,
        "_ensure_current_process_token_sid_query_access",
        apply_token,
    )

    observed = process_security.ensure_provider_host_process_service_query_access(
        service_sid=SERVICE_SID,
        binding=fixture.binding,
        host_id=fixture.host_id,
        host_key_name=fixture.host_key_name,
        installation=fixture.installation,
    )

    assert observed == result
    assert fixture.calls == [
        "status",
        "attest",
        "grant",
        "grant-token-query",
    ]


@pytest.mark.parametrize(
    "failure",
    [
        "user",
        "session",
        "host-id",
        "key-name",
        "path",
        "hash",
        "transaction",
        "startup",
        "attestation",
        "file-identity",
        "launcher",
        "signer",
    ],
)
def test_identity_or_installation_mismatch_rejects_before_process_grant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    binding = fixture.binding
    host_id = fixture.host_id
    key_name = fixture.host_key_name
    if failure == "user":
        monkeypatch.setattr(
            process_security,
            "current_user_binding",
            lambda: replace(binding, user_sid="S-1-5-21-999"),
        )
    elif failure == "session":
        monkeypatch.setattr(
            process_security,
            "current_user_binding",
            lambda: replace(binding, session_id=8),
        )
    elif failure == "host-id":
        host_id = "keeper-provider-host:" + "0" * 64
    elif failure == "key-name":
        key_name = "DarkSage.KeeperProviderHost." + "0" * 64
    elif failure == "path":
        monkeypatch.setattr(
            process_security,
            "_current_process_image_path",
            lambda: fixture.executable.parent / "other.exe",
        )
    elif failure == "file-identity":
        count = 0

        def changing_identity(value: os.stat_result) -> tuple[int, int, int, int]:
            nonlocal count
            count += 1
            return (
                int(value.st_dev),
                int(value.st_ino),
                int(value.st_size) + (1 if count >= 2 else 0),
                int(value.st_mtime_ns),
            )

        monkeypatch.setattr(process_security, "_file_identity", changing_identity)
    elif failure == "launcher":
        launcher = (
            Path(binding.profile_path)
            / "AppData"
            / "Roaming"
            / "Microsoft"
            / "Windows"
            / "Start Menu"
            / "Programs"
            / "Startup"
            / "KeeperProviderHost.cmd"
        )
        launcher.write_bytes(b"@echo off\r\nunsafe\r\n")
    elif failure == "signer":
        monkeypatch.setattr(
            process_security,
            "authenticode_enrollment_binding",
            lambda path: {
                "certificate_thumbprint": "0" * 40,
                "publisher_subject": "Unexpected",
                "source": "windows-authenticode",
                "status": "Valid",
            },
        )
    else:
        original_status = fixture.installer.status
        original_attest = fixture.installer.attest_protected_tree

        def broken_status(self: _Installer) -> dict[str, object]:
            value = original_status(self)
            if failure == "hash":
                current = cast(dict[str, object], value["current"])
                current["artifact_sha256"] = "0" * 64
            elif failure == "transaction":
                value["transaction_pending"] = True
            elif failure == "startup":
                value["startup_registered"] = False
            return value

        def broken_attest(self: _Installer) -> str:
            if failure == "attestation":
                raise PermissionError("protected tree differs")
            return original_attest(self)

        monkeypatch.setattr(fixture.installer, "status", broken_status)
        monkeypatch.setattr(
            fixture.installer,
            "attest_protected_tree",
            broken_attest,
        )

    invoked = False

    def apply(*args: object, **kwargs: object) -> ProcessSecuritySnapshot:
        nonlocal invoked
        invoked = True
        return _snapshot()

    monkeypatch.setattr(
        process_security,
        "_ensure_current_process_sid_query_access",
        apply,
    )

    with pytest.raises(ProcessSecurityError) as captured:
        process_security.ensure_provider_host_process_service_query_access(
            service_sid=SERVICE_SID,
            binding=binding,
            host_id=host_id,
            host_key_name=key_name,
            installation=fixture.installation,
        )

    assert captured.value.stage is ProcessSecurityStage.VALIDATE_IDENTITY
    assert invoked is False


def test_descriptor_failure_is_preserved_after_exact_host_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    expected = ProcessSecurityError(
        ProcessSecurityStage.WRITE_DACL,
        "Provider Host process DACL update failed",
    )

    def reject(*args: object, **kwargs: object) -> ProcessSecuritySnapshot:
        raise expected

    monkeypatch.setattr(
        process_security,
        "_ensure_current_process_sid_query_access",
        reject,
    )

    with pytest.raises(ProcessSecurityError) as captured:
        process_security.ensure_provider_host_process_service_query_access(
            service_sid=SERVICE_SID,
            binding=fixture.binding,
            host_id=fixture.host_id,
            host_key_name=fixture.host_key_name,
            installation=fixture.installation,
        )

    assert captured.value is expected


def test_token_descriptor_failure_is_preserved_after_process_grant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    expected = ProcessSecurityError(
        ProcessSecurityStage.WRITE_DACL,
        "Provider Host token DACL update failed",
    )
    calls: list[str] = []

    def process_grant(*args: object, **kwargs: object) -> ProcessSecuritySnapshot:
        calls.append("process")
        return _snapshot()

    def token_reject(*args: object, **kwargs: object) -> ProcessSecuritySnapshot:
        calls.append("token")
        raise expected

    monkeypatch.setattr(
        process_security,
        "_ensure_current_process_sid_query_access",
        process_grant,
    )
    monkeypatch.setattr(
        process_security,
        "_ensure_current_process_token_sid_query_access",
        token_reject,
    )

    with pytest.raises(ProcessSecurityError) as captured:
        process_security.ensure_provider_host_process_service_query_access(
            service_sid=SERVICE_SID,
            binding=fixture.binding,
            host_id=fixture.host_id,
            host_key_name=fixture.host_key_name,
            installation=fixture.installation,
        )

    assert captured.value is expected
    assert calls == ["process", "token"]


def test_invalid_service_sid_rejects_before_installation_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)

    with pytest.raises(ProcessSecurityError) as captured:
        process_security.ensure_provider_host_process_service_query_access(
            service_sid="S-1-5-18",
            binding=fixture.binding,
            host_id=fixture.host_id,
            host_key_name=fixture.host_key_name,
            installation=fixture.installation,
        )

    assert captured.value.stage is ProcessSecurityStage.VALIDATE_IDENTITY
    assert fixture.calls == []


@pytest.mark.skipif(os.name != "nt", reason="process-image API requires Windows")
def test_current_process_image_uses_explicit_windows_api_signatures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = Path(__file__).resolve(strict=True)

    class Operation:
        argtypes: object = None
        restype: object = None

        def __init__(self, callback: object) -> None:
            self.callback = callback

        def __call__(self, *args: object) -> object:
            return self.callback(*args)  # type: ignore[operator]

    get_current = Operation(lambda: 123)

    def query(
        handle: object,
        flags: object,
        buffer: object,
        capacity: object,
    ) -> bool:
        assert handle == 123
        assert getattr(flags, "value", flags) == 0
        buffer.value = str(expected)  # type: ignore[attr-defined]
        capacity._obj.value = len(str(expected))  # type: ignore[attr-defined]
        return True

    query_image = Operation(query)

    class Kernel32:
        GetCurrentProcess = get_current
        QueryFullProcessImageNameW = query_image

    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: Kernel32())

    assert process_security._current_process_image_path() == expected
    assert get_current.argtypes == []
    assert get_current.restype is process_security.wintypes.HANDLE
    assert query_image.argtypes == [
        process_security.wintypes.HANDLE,
        process_security.wintypes.DWORD,
        process_security.wintypes.LPWSTR,
        ctypes.POINTER(process_security.wintypes.DWORD),
    ]
    assert query_image.restype is process_security.wintypes.BOOL


@pytest.mark.skipif(os.name != "nt", reason="process-image API requires Windows")
@pytest.mark.parametrize("mode", ["open", "query", "empty", "relative"])
def test_current_process_image_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    class Operation:
        argtypes: object = None
        restype: object = None

        def __init__(self, callback: object) -> None:
            self.callback = callback

        def __call__(self, *args: object) -> object:
            return self.callback(*args)  # type: ignore[operator]

    def query(
        handle: object,
        flags: object,
        buffer: object,
        capacity: object,
    ) -> bool:
        if mode == "query":
            return False
        value = "relative.exe" if mode == "relative" else ""
        buffer.value = value  # type: ignore[attr-defined]
        capacity._obj.value = len(value)  # type: ignore[attr-defined]
        return True

    class Kernel32:
        GetCurrentProcess = Operation(lambda: 0 if mode == "open" else 123)
        QueryFullProcessImageNameW = Operation(query)

    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: Kernel32())

    with pytest.raises((PermissionError, RuntimeError)):
        process_security._current_process_image_path()


def test_runtime_construction_fails_before_store_or_pipe_on_bootstrap_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    binding = UserBinding(USER_SID, 7, str(profile.resolve(strict=True)))
    config = {
        "user_binding": {
            "user_sid": binding.user_sid,
            "session_id": binding.session_id,
            "profile_path": binding.profile_path,
        },
        "host_id": "keeper-provider-host:" + "a" * 64,
        "host_key_name": "DarkSage.KeeperProviderHost." + "a" * 64,
    }
    installation = {"install_root": str(profile)}
    monkeypatch.setattr(
        cli_module,
        "_startup_configuration",
        lambda path: (config, installation),
    )
    monkeypatch.setattr(cli_module, "current_user_binding", lambda: binding)
    monkeypatch.setattr(cli_module, "_authority_service_sid", lambda: SERVICE_SID)

    order: list[str] = []

    def reject(**kwargs: object) -> ProcessSecuritySnapshot:
        order.append("bootstrap")
        raise ProcessSecurityError(
            ProcessSecurityStage.VERIFY_DACL,
            "Provider Host process security delta did not verify exactly",
        )

    def store(*args: object, **kwargs: object) -> object:
        order.append("store")
        raise AssertionError("store must not be opened")

    monkeypatch.setattr(
        cli_module,
        "ensure_provider_host_process_service_query_access",
        reject,
    )
    monkeypatch.setattr(cli_module, "ProviderHostStore", store)

    with pytest.raises(ProcessSecurityError):
        cli_module._build_runtime(tmp_path / "signed-receipt.json")

    assert order == ["bootstrap"]
