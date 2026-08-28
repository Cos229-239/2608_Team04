from __future__ import annotations

import re
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

from keeper.provider_host import cli as host_cli


ROOT = Path(__file__).resolve().parents[2]


def test_machine_host_install_path_matches_production_enrollment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = (ROOT / "scripts/install-keeper-machine-user.ps1").read_text(
        encoding="utf-8"
    )
    match = re.search(
        r'\$InstallRoot = Join-Path \$env:LOCALAPPDATA "([^"]+)"', script
    )
    assert match is not None
    profile = tmp_path / "Founder Profile"
    profile.mkdir()
    installed_root = (
        profile / "AppData" / "Local" / Path(*PureWindowsPath(match[1]).parts)
    )
    captured_roots: list[Path] = []

    class PathCaptured(Exception):
        pass

    def capture_install_root(root: Path, *args: object, **kwargs: object) -> None:
        captured_roots.append(root)
        raise PathCaptured

    monkeypatch.setattr(host_cli, "_enrollment_client_factory", None)
    monkeypatch.setattr(
        host_cli,
        "ProductionAuthorityServiceClient",
        lambda: SimpleNamespace(require_live_identity=lambda: {"client_sid": "test-user"}),
    )
    monkeypatch.setattr(host_cli, "_validate_authority_compatibility", lambda _: None)
    monkeypatch.setattr(
        host_cli,
        "current_user_binding",
        lambda: SimpleNamespace(user_sid="test-user", profile_path=str(profile)),
    )
    monkeypatch.setattr(host_cli, "_authority_service_sid", lambda: "test-service")
    # Stop before constructing a real installer, creating keys, or contacting IPC.
    monkeypatch.setattr(host_cli, "ProviderHostInstaller", capture_install_root)
    with pytest.raises(PathCaptured):
        host_cli._production_enrollment_client()

    assert captured_roots == [installed_root.resolve()]


def test_full_machine_setup_splits_admin_and_user_phases() -> None:
    definition = (ROOT / "packaging/windows/keeper-machine.iss").read_text(
        encoding="utf-8"
    )

    assert "PrivilegesRequired=admin" in definition
    assert "install-machine-authority.ps1" in definition
    assert "install-user-components.ps1" in definition
    assert "runasoriginaluser" in definition
    assert "Founder confirmation is required" in definition


def test_signing_pipeline_fails_closed_and_timestamps_sha256() -> None:
    script = (ROOT / "scripts/sign-keeper-release.ps1").read_text(encoding="utf-8")

    assert "trusted Authenticode certificate thumbprint is required" in script
    assert "HasPrivateKey" in script
    assert "X509Chain" in script
    assert "/fd SHA256" in script
    assert "/td SHA256" in script
    assert 'Status -ne "Valid"' in script


def test_machine_setup_does_not_embed_or_copy_provider_credentials() -> None:
    scripts = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in (
            "scripts/build-keeper-machine-installer.ps1",
            "scripts/install-keeper-machine-authority.ps1",
            "scripts/install-keeper-machine-user.ps1",
        )
    ).lower()

    assert "api_key" not in scripts
    assert "credential copy" not in scripts
    assert "provider-host enroll" in scripts


def test_machine_builder_binds_all_artifacts_to_one_source_identity() -> None:
    script = (ROOT / "scripts/build-keeper-machine-installer.ps1").read_text(
        encoding="utf-8"
    )

    assert "keeper-package-manifest.json" in script
    assert "keeper-provider-host-build-provenance.json" in script
    assert "keeper-authority-package-manifest.json" in script
    assert "source_commit -ne $SourceCommit" in script
    assert "source_tree -ne $SourceTree" in script


def test_machine_builder_removes_runtime_build_and_bootstrap_material() -> None:
    script = (ROOT / "scripts/build-keeper-machine-installer.ps1").read_text(
        encoding="utf-8"
    )

    assert "__pycache__" in script
    assert "'*.pyc','*.pyo'" in script
    for library in ("ensurepip", "idlelib", "tkinter", "test", "turtledemo", "venv"):
        assert library in script
