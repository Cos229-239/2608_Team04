from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


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
