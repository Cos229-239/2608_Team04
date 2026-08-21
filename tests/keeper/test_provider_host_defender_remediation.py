from __future__ import annotations

import sys
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from keeper.provider_host import install
from keeper.provider_host.cli import parser as provider_host_parser
from keeper.provider_host.install import ProviderHostInstaller


ROOT = Path(__file__).resolve().parents[2]
_REAL_DEFENDER_BOUNDARY = install._verify_provider_host_with_defender


def test_provider_host_import_graph_excludes_authority_host_dacl_policy() -> None:
    sys.modules.pop("keeper.authority_service.host_process_policy", None)
    sys.modules.pop("keeper.provider_host.process_security", None)

    __import__("keeper.provider_host.process_security")

    assert "keeper.authority_service.host_process_policy" not in sys.modules


def test_provider_host_build_requires_exact_offline_toolchain_inputs() -> None:
    script = (ROOT / "scripts" / "build-keeper-provider-host.ps1").read_text(
        encoding="utf-8"
    )

    for required in (
        "ExpectedPythonSha256",
        "ExpectedCompilerSha256",
        "ExpectedDeveloperEnvironmentSha256",
        "ExpectedDependencyWalkerSha256",
        "Provider Host release builds require an exact clean Git source",
        "Provider Host build attempted an unapproved download",
        'build_network = "DISALLOWED_NO_DOWNLOAD_OBSERVED"',
    ):
        assert required in script
    assert "--assume-yes-for-downloads" not in script
    assert "verify-keeper-provider-host-defender.ps1" in script


def test_install_requires_defender_before_first_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    executable = package / "KeeperProviderHost.exe"
    executable.write_bytes(b"MZexact-host")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    manifest = package / "keeper-provider-host-package-manifest.json"
    manifest.write_text(
        '{"schema_version":1,"product":"KeeperProviderHost","version":"1.7.28",'
        f'"files":[{{"path":"KeeperProviderHost.exe","size":{executable.stat().st_size},'
        f'"sha256":"{digest}"}}]}}',
        encoding="utf-8",
    )
    events: list[str] = []

    def reject(_artifact: Path, _digest: str) -> None:
        events.append("defender")
        raise PermissionError("detected")

    monkeypatch.setattr(install, "_verify_provider_host_with_defender", reject)
    lifecycle = install.ProviderHostInstaller(
        tmp_path / "installed", tmp_path / "startup", owner_sid="S-1-5-21-1-2-3-1001"
    )
    with pytest.raises(PermissionError, match="detected"):
        lifecycle.install(
            executable,
            version="1.7.28",
            expected_package_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
        )

    assert events == ["defender"]
    assert not lifecycle.root.exists()


def test_defender_boundary_accepts_only_exact_pass_and_unchanged_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "KeeperProviderHost.exe"
    artifact.write_bytes(b"MZexact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    captured: list[subprocess.CompletedProcess[str]] = []

    def passed(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        result = subprocess.CompletedProcess(
            [], 0, json.dumps({"engine": "1.2.3", "intelligence": "4.5.6", "result": "PASS"}), ""
        )
        captured.append(result)
        return result

    monkeypatch.setattr(subprocess, "run", passed)
    _REAL_DEFENDER_BOUNDARY(artifact, digest)
    assert len(captured) == 1


@pytest.mark.parametrize(
    "completed",
    [
        subprocess.CompletedProcess([], 1, "", "detected"),
        subprocess.CompletedProcess([], 0, "not-json", ""),
        subprocess.CompletedProcess([], 0, '{"result":"FAIL"}', ""),
    ],
)
def test_defender_boundary_rejects_failure_or_malformed_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    completed: subprocess.CompletedProcess[str],
) -> None:
    artifact = tmp_path / "KeeperProviderHost.exe"
    artifact.write_bytes(b"MZexact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: completed)

    with pytest.raises(PermissionError, match="Defender"):
        _REAL_DEFENDER_BOUNDARY(artifact, digest)


def test_rollback_scans_selected_generation_before_drain_or_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = object.__new__(install.ProviderHostInstaller)
    events: list[str] = []
    monkeypatch.setattr(
        lifecycle,
        "_load_current",
        lambda **_kwargs: {"version": "1.7.28", "previous_version": "1.7.27"},
    )

    def reject(*_args: object, **kwargs: object) -> None:
        events.append(f"scan:{kwargs.get('require_defender')}")
        raise PermissionError("detected rollback")

    monkeypatch.setattr(lifecycle, "_installed_package", reject)
    with pytest.raises(PermissionError, match="detected rollback"):
        lifecycle.rollback(drain=lambda: events.append("drain"))
    assert events == ["scan:True"]


def test_recovery_scans_transaction_generation_before_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = object.__new__(install.ProviderHostInstaller)
    lifecycle.transaction_path = tmp_path / "lifecycle-transaction.json"
    lifecycle.versions = tmp_path / "versions"
    lifecycle.transaction_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "operation": "update",
                "version": "1.7.28",
                "package_sha256": "a" * 64,
                "previous_version": "1.7.27",
                "retained_rollback_version": "1.7.27",
            }
        ),
        encoding="utf-8",
    )
    events: list[str] = []

    def reject(*_args: object, **kwargs: object) -> None:
        events.append(f"scan:{kwargs.get('require_defender')}")
        raise PermissionError("detected recovery")

    monkeypatch.setattr(install, "_verify_package", reject)
    monkeypatch.setattr(lifecycle, "_restore_transaction_backup", lambda *_: None)
    monkeypatch.setattr(
        lifecycle,
        "_load_current",
        lambda **_kwargs: {
            "version": "1.7.27",
            "package_sha256": "b" * 64,
            "artifact_path": str(tmp_path / "old.exe"),
            "previous_version": None,
        },
    )
    monkeypatch.setattr(lifecycle, "_installed_package", reject)
    with pytest.raises(PermissionError, match="detected recovery"):
        lifecycle.recover()
    assert events == ["scan:True", "scan:True"]


def test_provider_host_defender_gate_never_weakens_endpoint_protection() -> None:
    script = (
        ROOT / "scripts" / "verify-keeper-provider-host-defender.ps1"
    ).read_text(encoding="utf-8")

    assert "Start-MpScan -ScanType CustomScan" in script
    assert "Get-MpThreatDetection" in script
    assert "Add-MpPreference" not in script
    assert "Set-MpPreference" not in script
    assert "Remove-MpPreference" not in script
    assert "ThreatIDDefaultAction" not in script


def _distribution(
    root: Path, *, version: str, marker: bytes
) -> tuple[Path, str, str]:
    root.mkdir(parents=True)
    executable = root / "KeeperProviderHost.exe"
    runtime = root / "python-runtime.dll"
    executable.write_bytes(b"MZ" + marker)
    runtime.write_bytes(b"runtime-" + marker)
    files = [
        {
            "path": path.name,
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in (executable, runtime)
    ]
    manifest = root / "keeper-provider-host-package-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "product": "KeeperProviderHost",
                "version": version,
                "files": files,
            }
        ),
        encoding="utf-8",
    )
    return (
        executable,
        hashlib.sha256(manifest.read_bytes()).hexdigest(),
        hashlib.sha256(executable.read_bytes()).hexdigest(),
    )


def _quarantined_install(
    tmp_path: Path,
) -> tuple[ProviderHostInstaller, Path, str, Path, str]:
    old, old_manifest, _ = _distribution(
        tmp_path / "old", version="1.7.26", marker=b"old"
    )
    selected, selected_manifest, _ = _distribution(
        tmp_path / "selected", version="1.7.27", marker=b"selected"
    )
    replacement, replacement_manifest, _ = _distribution(
        tmp_path / "replacement", version="1.7.29", marker=b"replacement"
    )
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid="S-1-5-80-1-2-3-4-5",
    )
    installer.install(old, version="1.7.26", expected_package_sha256=old_manifest)
    installer.update(
        selected,
        version="1.7.27",
        expected_package_sha256=selected_manifest,
        drain=lambda: None,
    )
    (installer.versions / "1.7.27" / "KeeperProviderHost.exe").unlink()
    return installer, replacement, replacement_manifest, old, old_manifest


def _recovery_kwargs(installer: ProviderHostInstaller) -> dict[str, str]:
    rollback_root = installer.versions / "1.7.26"
    return {
        "expected_current_sha256": hashlib.sha256(
            installer.current_path.read_bytes()
        ).hexdigest(),
        "expected_rollback_version": "1.7.26",
        "expected_rollback_artifact_sha256": hashlib.sha256(
            (rollback_root / "KeeperProviderHost.exe").read_bytes()
        ).hexdigest(),
        "expected_rollback_package_sha256": hashlib.sha256(
            (rollback_root / "keeper-provider-host-package-manifest.json").read_bytes()
        ).hexdigest(),
    }


def test_exact_quarantined_selection_replacement_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer, replacement, replacement_manifest, _, _ = _quarantined_install(
        tmp_path
    )
    scans: list[str] = []
    monkeypatch.setattr(
        install,
        "_verify_provider_host_with_defender",
        lambda artifact, _digest: scans.append(str(artifact)),
    )

    result = installer.replace_quarantined_selection(
        replacement,
        version="1.7.29",
        expected_package_sha256=replacement_manifest,
        **_recovery_kwargs(installer),
        drain=lambda: None,
    )

    assert result.version == "1.7.29"
    assert result.previous_version == "1.7.26"
    assert [Path(path).parent.name for path in scans] == ["replacement", "1.7.26"]
    assert installer.status()["current"]["version"] == "1.7.29"  # type: ignore[index]
    assert installer.status()["current"]["previous_version"] == "1.7.26"  # type: ignore[index]
    assert not (installer.versions / "1.7.27").exists()
    assert (installer.versions / "1.7.26" / "KeeperProviderHost.exe").is_file()
    assert not installer.transaction_path.exists()


@pytest.mark.parametrize(
    "mutation,error",
    [
        ("selected-present", "not an exact quarantine state"),
        ("selected-symlink", "not an exact quarantine state"),
        ("current-extra-field", "current selection is invalid"),
        ("current-wrong-path", "not an exact quarantine state"),
        ("current-wrong-digest", "quarantined executable identity differs"),
        ("manifest-tamper", "not an exact quarantine state"),
        ("runtime-missing", "package coverage differs"),
        ("runtime-tamper", "package file differs"),
        ("rollback-missing", "No such file|cannot find|path specified"),
        ("rollback-mismatch", "file differs"),
    ],
)
def test_quarantined_selection_replacement_rejects_ambiguous_state_before_mutation(
    tmp_path: Path,
    mutation: str,
    error: str,
) -> None:
    installer, replacement, replacement_manifest, _, _ = _quarantined_install(
        tmp_path
    )
    selected_root = installer.versions / "1.7.27"
    rollback_root = installer.versions / "1.7.26"
    current_before = installer.current_path.read_bytes()
    startup_before = installer.startup_path.read_bytes()
    if mutation == "selected-present":
        (selected_root / "KeeperProviderHost.exe").write_bytes(b"MZreturned")
    elif mutation == "selected-symlink":
        try:
            (selected_root / "KeeperProviderHost.exe").symlink_to(replacement)
        except OSError:
            pytest.skip("symlink creation is unavailable")
    elif mutation.startswith("current-"):
        current = json.loads(installer.current_path.read_text(encoding="utf-8"))
        if mutation == "current-extra-field":
            current["unexpected"] = True
        elif mutation == "current-wrong-path":
            current["artifact_path"] = str(selected_root / "other.exe")
        else:
            current["artifact_sha256"] = "0" * 64
        installer.current_path.write_text(json.dumps(current), encoding="utf-8")
        current_before = installer.current_path.read_bytes()
    elif mutation == "manifest-tamper":
        (selected_root / "keeper-provider-host-package-manifest.json").write_text(
            "{}", encoding="utf-8"
        )
    elif mutation == "runtime-missing":
        (selected_root / "python-runtime.dll").unlink()
    elif mutation == "runtime-tamper":
        (selected_root / "python-runtime.dll").write_bytes(b"changed")
    elif mutation == "rollback-missing":
        (rollback_root / "KeeperProviderHost.exe").unlink()
    else:
        (rollback_root / "python-runtime.dll").write_bytes(b"changed")

    with pytest.raises((FileNotFoundError, PermissionError), match=error):
        installer.replace_quarantined_selection(
            replacement,
            version="1.7.29",
            expected_package_sha256=replacement_manifest,
            **_recovery_kwargs(installer),
            drain=lambda: (_ for _ in ()).throw(AssertionError("drain called")),
        )

    assert installer.current_path.read_bytes() == current_before
    assert installer.startup_path.read_bytes() == startup_before
    assert not installer.transaction_path.exists()
    assert not (installer.versions / "1.7.29").exists()


def test_quarantined_replacement_scans_replacement_then_rollback_before_drain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer, replacement, replacement_manifest, _, _ = _quarantined_install(
        tmp_path
    )
    events: list[str] = []

    def scan(artifact: Path, _digest: str) -> None:
        events.append(f"scan:{artifact.parent.name}")
        if artifact.parent.name == "1.7.26":
            raise PermissionError("Defender rejected rollback")

    monkeypatch.setattr(install, "_verify_provider_host_with_defender", scan)
    with pytest.raises(PermissionError, match="Defender rejected rollback"):
        installer.replace_quarantined_selection(
            replacement,
            version="1.7.29",
            expected_package_sha256=replacement_manifest,
            **_recovery_kwargs(installer),
            drain=lambda: events.append("drain"),
        )

    assert events == ["scan:replacement", "scan:1.7.26"]
    assert not installer.transaction_path.exists()
    assert not (installer.versions / "1.7.29").exists()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("expected_current_sha256", "0" * 64, "current record differs"),
        ("expected_rollback_version", "1.7.25", "rollback version differs"),
        (
            "expected_rollback_package_sha256",
            "0" * 64,
            "package manifest digest differs",
        ),
        (
            "expected_rollback_artifact_sha256",
            "0" * 64,
            "rollback executable digest differs",
        ),
    ],
)
def test_quarantined_replacement_requires_exact_authorized_recovery_identities(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    installer, replacement, replacement_manifest, _, _ = _quarantined_install(
        tmp_path
    )
    identities = _recovery_kwargs(installer)
    identities[field] = value
    current_before = installer.current_path.read_bytes()
    startup_before = installer.startup_path.read_bytes()

    with pytest.raises(PermissionError, match=message):
        installer.replace_quarantined_selection(
            replacement,
            version="1.7.29",
            expected_package_sha256=replacement_manifest,
            **identities,
            drain=lambda: (_ for _ in ()).throw(AssertionError("drain called")),
        )

    assert installer.current_path.read_bytes() == current_before
    assert installer.startup_path.read_bytes() == startup_before
    assert not installer.transaction_path.exists()
    assert not (installer.versions / "1.7.29").exists()


def test_quarantined_replacement_interruption_is_durably_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer, replacement, replacement_manifest, _, _ = _quarantined_install(
        tmp_path
    )
    original_finalize = installer._finalize_protected_install  # noqa: SLF001
    quarantined_current_sha256 = _recovery_kwargs(installer)[
        "expected_current_sha256"
    ]

    def interrupt(version: str, rollback: str | None) -> None:
        assert version == "1.7.29"
        assert rollback == "1.7.26"
        raise RuntimeError("simulated quarantine replacement interruption")

    monkeypatch.setattr(installer, "_finalize_protected_install", interrupt)
    with pytest.raises(RuntimeError, match="interruption"):
        installer.replace_quarantined_selection(
            replacement,
            version="1.7.29",
            expected_package_sha256=replacement_manifest,
            **_recovery_kwargs(installer),
            drain=lambda: None,
        )
    transaction = json.loads(installer.transaction_path.read_text(encoding="utf-8"))
    assert transaction["operation"] == "quarantine-replacement"
    assert transaction["previous_version"] == "1.7.27"
    assert transaction["retained_rollback_version"] == "1.7.26"
    assert transaction["quarantined_current_sha256"] == quarantined_current_sha256
    assert transaction["retained_rollback_package_sha256"] == _recovery_kwargs(
        installer
    )["expected_rollback_package_sha256"]
    monkeypatch.setattr(installer, "_finalize_protected_install", original_finalize)

    recovered = installer.recover()

    assert recovered["recovered"] is True
    assert recovered["current"]["version"] == "1.7.29"  # type: ignore[index]
    assert recovered["current"]["previous_version"] == "1.7.26"  # type: ignore[index]
    assert not installer.transaction_path.exists()


def test_quarantined_replacement_recovery_rejects_tampered_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer, replacement, replacement_manifest, _, _ = _quarantined_install(
        tmp_path
    )

    monkeypatch.setattr(
        installer,
        "_copy_package",
        lambda _package, _destination: (_ for _ in ()).throw(
            RuntimeError("simulated interruption")
        ),
    )
    with pytest.raises(RuntimeError, match="interruption"):
        installer.replace_quarantined_selection(
            replacement,
            version="1.7.29",
            expected_package_sha256=replacement_manifest,
            **_recovery_kwargs(installer),
            drain=lambda: None,
        )
    transaction = json.loads(installer.transaction_path.read_text(encoding="utf-8"))
    transaction["quarantined_current_sha256"] = "0" * 64
    installer.transaction_path.write_text(json.dumps(transaction), encoding="utf-8")
    current_before = installer.current_path.read_bytes()
    startup_before = installer.startup_path.read_bytes()

    with pytest.raises(PermissionError, match="current selection differs"):
        installer.recover()

    assert installer.current_path.read_bytes() == current_before
    assert installer.startup_path.read_bytes() == startup_before
    assert installer.transaction_path.is_file()


def test_quarantined_replacement_precommit_interruption_restores_quarantine_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer, replacement, replacement_manifest, _, _ = _quarantined_install(
        tmp_path
    )
    current_before = installer.current_path.read_bytes()
    startup_before = installer.startup_path.read_bytes()

    def interrupt(_package: object, _destination: Path) -> None:
        raise RuntimeError("simulated precommit interruption")

    monkeypatch.setattr(installer, "_copy_package", interrupt)
    with pytest.raises(RuntimeError, match="precommit interruption"):
        installer.replace_quarantined_selection(
            replacement,
            version="1.7.29",
            expected_package_sha256=replacement_manifest,
            **_recovery_kwargs(installer),
            drain=lambda: None,
        )
    assert installer.transaction_path.is_file()

    recovered = installer.recover()

    assert recovered["recovered"] is True
    assert recovered["selection_quarantined"] is True
    assert installer.current_path.read_bytes() == current_before
    assert installer.startup_path.read_bytes() == startup_before
    assert not installer.transaction_path.exists()
    assert not (installer.versions / "1.7.29").exists()


def test_quarantined_replacement_rejects_same_or_rollback_version(
    tmp_path: Path,
) -> None:
    installer, _, _, old, old_manifest = _quarantined_install(tmp_path)
    same, same_manifest, _ = _distribution(
        tmp_path / "same", version="1.7.27", marker=b"same"
    )
    with pytest.raises(PermissionError, match="version is unchanged"):
        installer.replace_quarantined_selection(
            same,
            version="1.7.27",
            expected_package_sha256=same_manifest,
            **_recovery_kwargs(installer),
            drain=lambda: None,
        )
    with pytest.raises(PermissionError, match="matches rollback generation"):
        installer.replace_quarantined_selection(
            old,
            version="1.7.26",
            expected_package_sha256=old_manifest,
            **_recovery_kwargs(installer),
            drain=lambda: None,
        )


def test_quarantined_replacement_rejects_preexisting_destination(
    tmp_path: Path,
) -> None:
    installer, replacement, replacement_manifest, _, _ = _quarantined_install(
        tmp_path
    )
    destination = installer.versions / "1.7.29"
    destination.mkdir()
    marker = destination / "unrelated.txt"
    marker.write_bytes(b"preserve")
    current_before = installer.current_path.read_bytes()
    startup_before = installer.startup_path.read_bytes()

    with pytest.raises(PermissionError, match="generation already exists"):
        installer.replace_quarantined_selection(
            replacement,
            version="1.7.29",
            expected_package_sha256=replacement_manifest,
            **_recovery_kwargs(installer),
            drain=lambda: (_ for _ in ()).throw(AssertionError("drain called")),
        )

    assert marker.read_bytes() == b"preserve"
    assert installer.current_path.read_bytes() == current_before
    assert installer.startup_path.read_bytes() == startup_before
    assert not installer.transaction_path.exists()


@pytest.mark.parametrize(
    "timestamp",
    ["", "not-a-timestamp", "2026-08-12T10:00:00", "2026-08-12T10:00:00-04:00"],
)
def test_quarantined_replacement_requires_exact_utc_timestamp_field(
    tmp_path: Path, timestamp: str
) -> None:
    installer, replacement, replacement_manifest, _, _ = _quarantined_install(
        tmp_path
    )
    current = json.loads(installer.current_path.read_text(encoding="utf-8"))
    current["selected_at"] = timestamp
    installer.current_path.write_text(json.dumps(current), encoding="utf-8")
    current_before = installer.current_path.read_bytes()
    startup_before = installer.startup_path.read_bytes()
    with pytest.raises(PermissionError, match="selection identity is invalid"):
        installer.replace_quarantined_selection(
            replacement,
            version="1.7.29",
            expected_package_sha256=replacement_manifest,
            **_recovery_kwargs(installer),
            drain=lambda: (_ for _ in ()).throw(AssertionError("drain called")),
        )
    assert installer.current_path.read_bytes() == current_before
    assert installer.startup_path.read_bytes() == startup_before
    assert not installer.transaction_path.exists()


@pytest.mark.parametrize("mutation", ["startup-missing", "startup-changed", "pending"])
def test_quarantined_replacement_rejects_startup_or_pending_lifecycle(
    tmp_path: Path, mutation: str
) -> None:
    installer, replacement, replacement_manifest, _, _ = _quarantined_install(
        tmp_path
    )
    current_before = installer.current_path.read_bytes()
    if mutation == "startup-missing":
        installer.startup_path.unlink()
        startup_before: bytes | None = None
    elif mutation == "startup-changed":
        installer.startup_path.write_bytes(b"@echo off\r\nmalformed\r\n")
        startup_before = installer.startup_path.read_bytes()
    else:
        installer.transaction_path.write_text("{}", encoding="utf-8")
        startup_before = installer.startup_path.read_bytes()

    with pytest.raises(PermissionError, match="pending lifecycle|quarantine state"):
        installer.replace_quarantined_selection(
            replacement,
            version="1.7.29",
            expected_package_sha256=replacement_manifest,
            **_recovery_kwargs(installer),
            drain=lambda: (_ for _ in ()).throw(AssertionError("drain called")),
        )

    assert installer.current_path.read_bytes() == current_before
    if startup_before is None:
        assert not installer.startup_path.exists()
    else:
        assert installer.startup_path.read_bytes() == startup_before
    assert not (installer.versions / "1.7.29").exists()


def test_provider_host_cli_exposes_only_explicit_quarantine_recovery_command() -> None:
    options = provider_host_parser().parse_args(
        [
            "replace-quarantined-selection",
            "--install-root",
            "C:/tmp/install",
            "--startup-root",
            "C:/tmp/startup",
            "--artifact",
            "C:/tmp/package/KeeperProviderHost.exe",
            "--version",
            "1.7.29",
            "--package-sha256",
            "a" * 64,
            "--current-sha256",
            "b" * 64,
            "--rollback-version",
            "1.7.26",
            "--rollback-artifact-sha256",
            "c" * 64,
            "--rollback-package-sha256",
            "d" * 64,
        ]
    )
    assert options.provider_host_command == "replace-quarantined-selection"
    assert options.version == "1.7.29"
    assert options.current_sha256 == "b" * 64
