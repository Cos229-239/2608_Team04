from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows lifecycle script")


def test_desktop_deployment_enables_reproducible_windows_linking() -> None:
    template = (
        Path(__file__).parents[2]
        / "keeper"
        / "ui_qml"
        / "pysidedeploy.template.spec"
    ).read_text(encoding="utf-8")

    assert "--reproducible=yes" in template


def _package(
    root: Path,
    *,
    escaping: bool = False,
    extra: bool = False,
    payload: bytes = b"keeper-package-fixture",
    version: str = "test",
) -> Path:
    root.mkdir()
    executable = root / "Keeper.exe"
    executable.write_bytes(payload)
    path = "../escape.exe" if escaping else "Keeper.exe"
    manifest = {
        "product": "Keeper",
        "version": version,
        "composition": "PRODUCTION_CAPABLE_LOCAL_CLIENT",
        "files": [
            {
                "path": path,
                "size": executable.stat().st_size,
                "sha256": hashlib.sha256(executable.read_bytes()).hexdigest().upper(),
            }
        ],
    }
    (root / "keeper-package-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    if extra:
        (root / "unlisted.dll").write_bytes(b"unmanifested")
    return root


def _manifest_hash(package: Path) -> str:
    return hashlib.sha256(
        (package / "keeper-package-manifest.json").read_bytes()
    ).hexdigest().upper()


def _run(script: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            *arguments,
            "-SkipShortcuts",
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def _installer_release(root: Path, package: Path) -> Path:
    scripts = Path(__file__).parents[2] / "scripts"
    installer = root / "install-keeper-desktop.ps1"
    lifecycle = root / "keeper-local-lifecycle.ps1"
    shutil.copy2(scripts / installer.name, installer)
    shutil.copy2(scripts / lifecycle.name, lifecycle)
    shutil.copytree(package, root / "Keeper.dist")
    descriptor = {
        "schema_version": 1,
        "product": "Keeper",
        "version": "test",
        "package_directory": "Keeper.dist",
        "package_manifest_sha256": _manifest_hash(root / "Keeper.dist"),
        "installer_sha256": hashlib.sha256(installer.read_bytes()).hexdigest(),
        "lifecycle_sha256": hashlib.sha256(lifecycle.read_bytes()).hexdigest(),
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
    }
    (root / "keeper-installer-release.json").write_text(
        json.dumps(descriptor), encoding="utf-8"
    )
    return installer


def test_local_lifecycle_install_repair_upgrade_rollback_and_uninstall(
    tmp_path: Path,
) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    package = _package(tmp_path / "package")
    approved = _manifest_hash(package)
    install = tmp_path / "install"
    data = tmp_path / "data"
    common = ("-InstallRoot", str(install), "-DataDirectory", str(data))
    source = (
        "-PackageDirectory",
        str(package),
        "-ExpectedManifestSha256",
        approved,
    )

    installed = _run(script, "-Action", "Install", *source, *common)
    assert installed.returncode == 0, installed.stderr
    sentinel = data / "founder-data.txt"
    sentinel.write_text("preserve", encoding="utf-8")

    repaired = _run(script, "-Action", "Repair", *source, *common)
    assert repaired.returncode == 0, repaired.stderr
    upgraded = _run(script, "-Action", "Upgrade", *source, *common)
    assert upgraded.returncode == 0, upgraded.stderr
    assert (install / "rollback" / "Keeper.exe").is_file()

    rolled_back = _run(
        script,
        "-Action",
        "Rollback",
        "-ExpectedManifestSha256",
        approved,
        *common,
    )
    assert rolled_back.returncode == 0, rolled_back.stderr
    uninstalled = _run(script, "-Action", "Uninstall", *common)
    assert uninstalled.returncode == 0, uninstalled.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert not (install / "current").exists()
    assert not (install / "rollback").exists()


def test_single_local_installer_selects_install_then_repair(tmp_path: Path) -> None:
    package = _package(tmp_path / "package")
    release = tmp_path / "release"
    release.mkdir()
    installer = _installer_release(release, package)
    install = tmp_path / "install"
    data = tmp_path / "data"
    arguments = (
        "-InstallRoot",
        str(install),
        "-DataDirectory",
        str(data),
    )

    installed = _run(installer, *arguments)
    assert installed.returncode == 0, installed.stderr
    assert json.loads(installed.stdout)["action"] == "Install"
    repaired = _run(installer, *arguments)
    assert repaired.returncode == 0, repaired.stderr
    assert json.loads(repaired.stdout)["action"] == "Repair"
    assert (install / "current" / "Keeper.exe").is_file()


def test_single_local_installer_rejects_tampered_lifecycle(tmp_path: Path) -> None:
    package = _package(tmp_path / "package")
    release = tmp_path / "release"
    release.mkdir()
    installer = _installer_release(release, package)
    with (release / "keeper-local-lifecycle.ps1").open(
        "a", encoding="utf-8"
    ) as target:
        target.write("\n# tampered\n")

    result = _run(
        installer,
        "-InstallRoot",
        str(tmp_path / "install"),
        "-DataDirectory",
        str(tmp_path / "data"),
    )
    assert result.returncode != 0
    assert "lifecycle bytes differ" in result.stderr


@pytest.mark.parametrize(
    "data_location",
    (
        "install",
        "install/current/user-data",
        "install/rollback/user-data",
        "install/.stage-attacker/user-data",
        "install/.swap-attacker/user-data",
        ".",
    ),
)
def test_local_lifecycle_rejects_overlapping_data_roots_before_install(
    tmp_path: Path,
    data_location: str,
) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    package = _package(tmp_path / "package")
    install = tmp_path / "install"
    data = (tmp_path / data_location).resolve()
    data.mkdir(parents=True, exist_ok=True)
    sentinel = data / "founder-data.txt"
    sentinel.write_text("preserve", encoding="utf-8")

    result = _run(
        script,
        "-Action",
        "Install",
        "-PackageDirectory",
        str(package),
        "-ExpectedManifestSha256",
        _manifest_hash(package),
        "-InstallRoot",
        str(install),
        "-DataDirectory",
        str(data),
    )

    assert result.returncode != 0
    assert "must be disjoint" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve"


@pytest.mark.parametrize(
    "action",
    ("Install", "Repair", "Upgrade", "Rollback", "Uninstall"),
)
def test_local_lifecycle_never_deletes_overlapping_data_for_any_action(
    tmp_path: Path,
    action: str,
) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    package = _package(tmp_path / "package")
    approved = _manifest_hash(package)
    install = tmp_path / "install"
    safe_data = tmp_path / "safe-data"
    common = ("-InstallRoot", str(install), "-DataDirectory", str(safe_data))
    source = (
        "-PackageDirectory",
        str(package),
        "-ExpectedManifestSha256",
        approved,
    )
    assert _run(script, "-Action", "Install", *source, *common).returncode == 0
    assert _run(script, "-Action", "Repair", *source, *common).returncode == 0
    overlapping_data = install / "rollback" / "user-data"
    overlapping_data.mkdir()
    sentinel = overlapping_data / "founder-data.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    arguments: tuple[str, ...] = (
        "-Action",
        action,
        "-InstallRoot",
        str(install),
        "-DataDirectory",
        str(overlapping_data),
    )
    if action in {"Install", "Repair", "Upgrade"}:
        arguments += source
    elif action == "Rollback":
        arguments += ("-ExpectedManifestSha256", approved)

    result = _run(script, *arguments)

    assert result.returncode != 0
    assert "must be disjoint" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_local_lifecycle_rejects_reparse_alias_before_mutation(tmp_path: Path) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    package = _package(tmp_path / "package")
    install = tmp_path / "install"
    target = tmp_path / "data-target"
    target.mkdir()
    sentinel = target / "founder-data.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    alias = tmp_path / "data-alias"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(alias), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip(f"directory junction is unavailable: {created.stderr.strip()}")

    result = _run(
        script,
        "-Action",
        "Install",
        "-PackageDirectory",
        str(package),
        "-ExpectedManifestSha256",
        _manifest_hash(package),
        "-InstallRoot",
        str(install),
        "-DataDirectory",
        str(alias),
    )

    assert result.returncode != 0
    assert "contains a reparse point" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_local_lifecycle_rejects_reparse_package_source(tmp_path: Path) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    package = _package(tmp_path / "package-target")
    alias = tmp_path / "package-alias"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(alias), str(package)],
        check=False,
        capture_output=True,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip(f"directory junction is unavailable: {created.stderr.strip()}")

    result = _run(
        script,
        "-Action",
        "Install",
        "-PackageDirectory",
        str(alias),
        "-ExpectedManifestSha256",
        _manifest_hash(package),
        "-InstallRoot",
        str(tmp_path / "install"),
        "-DataDirectory",
        str(tmp_path / "data"),
    )

    assert result.returncode != 0
    assert "contains a reparse point" in result.stderr
    assert (package / "Keeper.exe").read_bytes() == b"keeper-package-fixture"


def test_local_lifecycle_rejects_manifest_path_escape(tmp_path: Path) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    package = _package(tmp_path / "package", escaping=True)
    result = _run(
        script,
        "-Action",
        "Install",
        "-PackageDirectory",
        str(package),
        "-ExpectedManifestSha256",
        _manifest_hash(package),
        "-InstallRoot",
        str(tmp_path / "install"),
        "-DataDirectory",
        str(tmp_path / "data"),
    )
    assert result.returncode != 0
    assert "escaping path" in result.stderr


def test_local_lifecycle_rejects_unmanifested_files_and_wrong_identity(
    tmp_path: Path,
) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    package = _package(tmp_path / "package", extra=True)
    common = (
        "-InstallRoot",
        str(tmp_path / "install"),
        "-DataDirectory",
        str(tmp_path / "data"),
    )
    extra = _run(
        script,
        "-Action",
        "Install",
        "-PackageDirectory",
        str(package),
        "-ExpectedManifestSha256",
        _manifest_hash(package),
        *common,
    )
    assert extra.returncode != 0
    assert "unmanifested" in extra.stderr
    wrong = _run(
        script,
        "-Action",
        "Install",
        "-PackageDirectory",
        str(package),
        "-ExpectedManifestSha256",
        "0" * 64,
        *common,
    )
    assert wrong.returncode != 0
    assert "approved SHA-256" in wrong.stderr


def test_local_lifecycle_rejects_tampered_rollback(tmp_path: Path) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    package = _package(tmp_path / "package")
    approved = _manifest_hash(package)
    install = tmp_path / "install"
    common = ("-InstallRoot", str(install), "-DataDirectory", str(tmp_path / "data"))
    source = (
        "-PackageDirectory",
        str(package),
        "-ExpectedManifestSha256",
        approved,
    )
    assert _run(script, "-Action", "Install", *source, *common).returncode == 0
    assert _run(script, "-Action", "Repair", *source, *common).returncode == 0
    (install / "rollback" / "Keeper.exe").write_bytes(b"tampered-rollback")

    result = _run(
        script,
        "-Action",
        "Rollback",
        "-ExpectedManifestSha256",
        approved,
        *common,
    )
    assert result.returncode != 0
    assert "size mismatch" in result.stderr or "hash mismatch" in result.stderr
    assert (install / "current" / "Keeper.exe").read_bytes() == b"keeper-package-fixture"

def _write_rollback_journal(
    install: Path, swap: Path, current_hash: str, rollback_hash: str
) -> None:
    (install / ".keeper-rollback-transaction.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "operation": "Rollback",
                "swap": str(swap.resolve()),
                "current_manifest_sha256": current_hash,
                "rollback_manifest_sha256": rollback_hash,
            }
        ),
        encoding="utf-8",
    )


def _write_install_journal(
    install: Path,
    stage: Path,
    new_hash: str,
    current_hash: str | None,
) -> None:
    (install / ".keeper-install-transaction.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "operation": "Upgrade",
                "stage": str(stage.resolve()),
                "new_manifest_sha256": new_hash,
                "current_manifest_sha256": current_hash,
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize("crash_point", ["journal", "moved-current", "promoted"])
def test_local_lifecycle_recovers_every_upgrade_crash_boundary(
    tmp_path: Path, crash_point: str
) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    old_package = _package(
        tmp_path / "old-package", payload=b"keeper-generation-old", version="old"
    )
    new_package = _package(
        tmp_path / "new-package", payload=b"keeper-generation-new", version="new"
    )
    install = tmp_path / "install"
    common = ("-InstallRoot", str(install), "-DataDirectory", str(tmp_path / "data"))
    assert _run(
        script,
        "-Action",
        "Install",
        "-PackageDirectory",
        str(old_package),
        "-ExpectedManifestSha256",
        _manifest_hash(old_package),
        *common,
    ).returncode == 0
    current = install / "current"
    rollback = install / "rollback"
    stage = install / ".stage-interrupted"
    shutil.copytree(new_package, stage)
    _write_install_journal(
        install,
        stage,
        _manifest_hash(new_package),
        _manifest_hash(old_package),
    )
    if crash_point in {"moved-current", "promoted"}:
        current.rename(rollback)
    if crash_point == "promoted":
        stage.rename(current)

    result = _run(script, "-Action", "Status", *common)
    assert result.returncode == 0, result.stderr
    assert not (install / ".keeper-install-transaction.json").exists()
    assert (current / "Keeper.exe").read_bytes() == b"keeper-generation-new"
    assert (rollback / "Keeper.exe").read_bytes() == b"keeper-generation-old"


@pytest.mark.parametrize("crash_point", ["journal", "first", "second", "third"])
def test_local_lifecycle_recovers_every_rollback_crash_boundary(
    tmp_path: Path, crash_point: str
) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    old_package = _package(
        tmp_path / "old-package", payload=b"keeper-generation-old", version="old"
    )
    new_package = _package(
        tmp_path / "new-package", payload=b"keeper-generation-new", version="new"
    )
    install = tmp_path / "install"
    common = ("-InstallRoot", str(install), "-DataDirectory", str(tmp_path / "data"))
    old_source = (
        "-PackageDirectory",
        str(old_package),
        "-ExpectedManifestSha256",
        _manifest_hash(old_package),
    )
    new_source = (
        "-PackageDirectory",
        str(new_package),
        "-ExpectedManifestSha256",
        _manifest_hash(new_package),
    )
    assert _run(script, "-Action", "Install", *old_source, *common).returncode == 0
    assert _run(script, "-Action", "Upgrade", *new_source, *common).returncode == 0

    current = install / "current"
    rollback = install / "rollback"
    swap = install / ".swap-interrupted"
    _write_rollback_journal(
        install, swap, _manifest_hash(new_package), _manifest_hash(old_package)
    )
    if crash_point in {"first", "second", "third"}:
        current.rename(swap)
    if crash_point in {"second", "third"}:
        rollback.rename(current)
    if crash_point == "third":
        swap.rename(rollback)

    result = _run(script, "-Action", "Status", *common)
    assert result.returncode == 0, result.stderr
    assert not (install / ".keeper-rollback-transaction.json").exists()
    if crash_point in {"journal", "first"}:
        assert (current / "Keeper.exe").read_bytes() == b"keeper-generation-new"
        assert (rollback / "Keeper.exe").read_bytes() == b"keeper-generation-old"
    else:
        assert (current / "Keeper.exe").read_bytes() == b"keeper-generation-old"
        assert (rollback / "Keeper.exe").read_bytes() == b"keeper-generation-new"


def test_local_lifecycle_status_rejects_tampered_current(tmp_path: Path) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    package = _package(tmp_path / "package")
    install = tmp_path / "install"
    common = ("-InstallRoot", str(install), "-DataDirectory", str(tmp_path / "data"))
    source = (
        "-PackageDirectory",
        str(package),
        "-ExpectedManifestSha256",
        _manifest_hash(package),
    )
    assert _run(script, "-Action", "Install", *source, *common).returncode == 0
    (install / "current" / "Keeper.exe").write_bytes(b"tampered-current")

    result = _run(script, "-Action", "Status", *common)
    assert result.returncode != 0
    assert "size mismatch" in result.stderr or "hash mismatch" in result.stderr

def test_local_lifecycle_status_rejects_current_without_manifest(tmp_path: Path) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    install = tmp_path / "install"
    current = install / "current"
    current.mkdir(parents=True)
    (current / "Keeper.exe").write_bytes(b"unverified-keeper")

    result = _run(
        script,
        "-Action",
        "Status",
        "-InstallRoot",
        str(install),
        "-DataDirectory",
        str(tmp_path / "data"),
    )

    assert result.returncode != 0
    assert "no package manifest" in result.stderr

def test_local_lifecycle_status_rejects_rollback_without_manifest(tmp_path: Path) -> None:
    script = Path(__file__).parents[2] / "scripts" / "keeper-local-lifecycle.ps1"
    package = _package(tmp_path / "package")
    install = tmp_path / "install"
    common = ("-InstallRoot", str(install), "-DataDirectory", str(tmp_path / "data"))
    source = (
        "-PackageDirectory",
        str(package),
        "-ExpectedManifestSha256",
        _manifest_hash(package),
    )
    assert _run(script, "-Action", "Install", *source, *common).returncode == 0
    assert _run(script, "-Action", "Repair", *source, *common).returncode == 0
    (install / "rollback" / "keeper-package-manifest.json").unlink()

    result = _run(script, "-Action", "Status", *common)

    assert result.returncode != 0
    assert "Rollback Keeper generation has no package manifest" in result.stderr
