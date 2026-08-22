from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from keeper.authority_service import service_install
from keeper.authority_service.service_install import AuthorityServiceInstaller
from keeper.authority_service.service_main import SERVICE_NAME
from keeper.authority_service.service_package import (
    PACKAGE_MANIFEST,
    build_service_package,
    verify_external_manifest,
    verify_rollback_package,
    verify_service_package,
    write_external_manifest,
)
from keeper.recovery import atomic_write_json


def _repository() -> Path:
    return Path(__file__).resolve().parents[2]


def _build(tmp_path: Path, name: str = "keeper-authority.pyz") -> Path:
    package = tmp_path / name
    AuthorityServiceInstaller(_repository())._build_package(package)
    return package


def _capture_recovery_preimage(service_root: Path, destination: Path) -> Path:
    data = service_root / "data"
    data.mkdir(exist_ok=True)
    (data / "authority.db").write_bytes(b"synthetic-authority-state")
    event = service_install.verified_recovery_backup(destination)
    return Path(str(event["manifest"]))


def _upgrade_package(
    package: Path,
    package_sha256: str,
    current_sha256: str,
    recovery_manifest: Path,
) -> dict[str, object]:
    return service_install.upgrade_package(
        package,
        package_sha256,
        current_sha256,
        recovery_manifest,
        package.parent / "external-manifest.json",
        "E" * 64,
        _repository(),
    )


def _production_verifier_fixture() -> dict[str, object]:
    return {
        "schema_version": 1,
        "issuer_id": "keeper-founder:S-1-5-21-1000",
        "principal_sid": "S-1-5-21-1000",
        "key_id": "keeper-founder-rsa:synthetic",
        "algorithm": "RS256-CNG-HIGH-PROTECTION",
        "modulus": "AQ==",
        "exponent": "AQAB",
    }


def test_authority_service_package_is_self_contained_and_reachable(
    tmp_path: Path,
) -> None:
    package = _build(tmp_path)

    for arguments, expected in (
        (["--help"], "service"),
        (["codex-probe", "--help"], "codex-probe"),
        (
            ["codex-discover-account-identity", "--help"],
            "codex-discover-account-identity",
        ),
        (["codex-register-once", "--help"], "codex-register-once"),
        (["codex-reconcile-qualification", "--help"], "codex-reconcile-qualification"),
    ):
        result = subprocess.run(
            [sys.executable, str(package), *arguments],
            cwd=tmp_path,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert expected in result.stdout


def test_authority_service_package_is_reproducible_across_roots_and_mtimes(
    tmp_path: Path,
) -> None:
    first_source = tmp_path / "source-a"
    second_source = tmp_path / "source-b"
    shutil.copytree(_repository() / "keeper", first_source / "keeper")
    shutil.copytree(_repository() / "keeper", second_source / "keeper")
    os.utime(
        second_source / "keeper" / "authority_service" / "service_main.py",
        (1_800_000_000, 1_800_000_000),
    )
    first = tmp_path / "first.pyz"
    second = tmp_path / "second.pyz"

    build_service_package(first_source, first)
    build_service_package(second_source, second)

    assert first.read_bytes() == second.read_bytes()
    assert verify_service_package(first).manifest == verify_service_package(second).manifest


def test_authority_service_package_has_exact_service_closure_and_metadata(
    tmp_path: Path,
) -> None:
    package = _build(tmp_path)
    verified = verify_service_package(package)

    assert verified.manifest["service_version"] == "1.7.51"
    assert verified.manifest["protocol_version"] == 7
    assert verified.manifest["service_schema_version"] == 6
    assert verified.manifest["provider_host_protocol"] == "keeper-provider-host/1"
    with zipfile.ZipFile(package) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        assert names[-1] == PACKAGE_MANIFEST
        assert names == [
            *(entry["path"] for entry in verified.manifest["entries"]),
            PACKAGE_MANIFEST,
        ]
        assert all(item.date_time == (1980, 1, 1, 0, 0, 0) for item in infos)
        assert all(item.compress_type == zipfile.ZIP_DEFLATED for item in infos)
        assert all(item.create_system == 3 for item in infos)
        assert not any(
            name.startswith(("keeper/app/", "keeper/ui/", "keeper/ui_qml/", "keeper/assets/"))
            or "__pycache__" in name
            or name.endswith((".pyc", ".pyo"))
            for name in names
        )


def test_unrelated_ui_source_does_not_change_authority_package(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(_repository() / "keeper", source / "keeper")
    first = tmp_path / "first.pyz"
    second = tmp_path / "second.pyz"
    build_service_package(source, first)
    ui_file = source / "keeper" / "ui" / "theme.py"
    ui_file.parent.mkdir(parents=True, exist_ok=True)
    ui_file.write_text("UNRELATED = True\n", encoding="utf-8")
    build_service_package(source, second)
    assert first.read_bytes() == second.read_bytes()


def test_required_runtime_source_change_changes_package(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(_repository() / "keeper", source / "keeper")
    first = tmp_path / "first.pyz"
    second = tmp_path / "second.pyz"
    build_service_package(source, first)
    protocol = source / "keeper" / "authority_service" / "protocol.py"
    protocol.write_text(protocol.read_text(encoding="utf-8") + "\n# closure change\n", encoding="utf-8")
    build_service_package(source, second)
    assert first.read_bytes() != second.read_bytes()


def test_missing_imported_runtime_dependency_rejects_package(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(_repository() / "keeper", source / "keeper")
    (source / "keeper" / "evidence_input.py").unlink()
    with pytest.raises(PermissionError, match="dependency is missing"):
        build_service_package(source, tmp_path / "missing.pyz")


def test_package_verification_rejects_hash_tamper_and_extra_entry(tmp_path: Path) -> None:
    package = _build(tmp_path)
    digest = hashlib.sha256(package.read_bytes()).hexdigest().upper()
    verify_service_package(package, digest)
    with pytest.raises(PermissionError, match="authorization"):
        verify_service_package(package, "0" * 64)

    changed = tmp_path / "changed.pyz"
    changed.write_bytes(package.read_bytes())
    with zipfile.ZipFile(changed, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("keeper/unexpected.py", b"VALUE = 1\n")
    with pytest.raises(PermissionError, match="entry order|coverage"):
        verify_service_package(changed)


def test_external_manifest_binds_package_and_git_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    subprocess.run(
        [
            "git", "clone", "--quiet", "--no-hardlinks", str(_repository()),
            str(source),
        ],
        check=True,
    )
    package = tmp_path / "keeper-authority.pyz"
    build_service_package(source, package)
    verified = verify_service_package(package)
    manifest_path = write_external_manifest(
        verified, tmp_path / "entry-manifest.json", source_root=source
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["package_sha256"] == verified.package_sha256
    assert manifest["package_size"] == package.stat().st_size
    assert manifest["archive_manifest"] == verified.manifest
    assert manifest["packaged_entries_match_source_commit"] is True
    assert len(manifest["source_commit"]) == 40
    assert len(manifest["source_tree"]) == 40
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest().upper()
    assert verify_external_manifest(
        verified, manifest_path, digest, source_root=source
    ) == manifest

    with pytest.raises(PermissionError, match="SHA-256 differs"):
        verify_external_manifest(
            verified, manifest_path, "0" * 64, source_root=source
        )

    altered = tmp_path / "altered-manifest.json"
    altered_value = dict(manifest)
    altered_value["package_path"] = str(tmp_path / "substituted.pyz")
    altered.write_text(
        json.dumps(altered_value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    altered_digest = hashlib.sha256(altered.read_bytes()).hexdigest().upper()
    with pytest.raises(PermissionError, match="binding differs"):
        verify_external_manifest(
            verified, altered, altered_digest, source_root=source
        )


def test_external_manifest_verification_rejects_changed_source_identity(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    subprocess.run(
        [
            "git", "clone", "--quiet", "--no-hardlinks", str(_repository()),
            str(source),
        ],
        check=True,
    )
    package = tmp_path / "keeper-authority.pyz"
    verified = build_service_package(source, package)
    manifest_path = write_external_manifest(
        verified, tmp_path / "external-manifest.json", source_root=source
    )
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest().upper()
    subprocess.run(
        ["git", "-C", str(source), "commit", "--allow-empty", "-m", "new identity"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    with pytest.raises(PermissionError, match="source identity differs"):
        verify_external_manifest(
            verified, manifest_path, digest, source_root=source
        )


def test_external_manifest_rejects_package_built_from_dirty_runtime_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    subprocess.run(
        [
            "git", "clone", "--quiet", "--no-hardlinks", str(_repository()),
            str(source),
        ],
        check=True,
    )
    runtime = source / "keeper" / "authority_service" / "protocol.py"
    runtime.write_text(runtime.read_text(encoding="utf-8") + "\nDIRTY = True\n", encoding="utf-8")
    package = tmp_path / "dirty.pyz"
    verified = build_service_package(source, package)
    with pytest.raises(PermissionError, match="recorded source commit"):
        write_external_manifest(
            verified, tmp_path / "dirty-manifest.json", source_root=source
        )


def test_upgrade_installs_exact_frozen_bytes_and_captures_exact_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _build(tmp_path, "candidate.pyz")
    candidate_digest = hashlib.sha256(candidate.read_bytes()).hexdigest().upper()
    service_root = tmp_path / "service"
    package = service_root / "bin" / "keeper-authority.pyz"
    manifest_path = service_root / "audit" / "machine-artifacts.json"
    package.parent.mkdir(parents=True)
    (service_root / "backups").mkdir(parents=True)
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("__main__.py", "print('old service')\n")
    old_package = package.read_bytes()
    manifest = {
        "schema_version": 1,
        "service_name": SERVICE_NAME,
        "source_commit": "a" * 40,
        "source_tree": "d" * 40,
        "installation_completed_at": "2026-01-01T00:00:00+00:00",
        "artifacts": [],
        "commands": [],
    }
    service_install._record_file(manifest, package)
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(service_install, "SERVICE_ROOT", service_root)
    monkeypatch.setattr(service_install, "MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(service_install, "_require_admin", lambda: None)
    monkeypatch.setattr(
        service_install,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "STATE: STOPPED\n"),
    )
    monkeypatch.setattr(
        service_install,
        "_migrate_founder_capability_configuration",
        lambda value: {"key_id": "founder-test-key"},
    )
    monkeypatch.setattr(
        service_install,
        "_provision_provider_host_authority_identity",
        lambda value: {
            "schema_version": 1,
            "key_id": "keeper-provider-host-rsa:test",
        },
    )
    monkeypatch.setattr(
        service_install,
        "build_service_package",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("upgrade rebuilt package")),
    )
    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    monkeypatch.setattr(service_install, "apply_path_security", lambda *_: None)
    monkeypatch.setattr(
        service_install,
        "verify_external_manifest",
        lambda *args, **kwargs: {
            "source_commit": "b" * 40,
            "source_tree": "c" * 40,
        },
    )
    preimage_manifest = _capture_recovery_preimage(
        service_root, tmp_path / "recovery-preimage"
    )

    old_digest = hashlib.sha256(old_package).hexdigest().upper()
    with pytest.raises(PermissionError, match="does not match its manifest"):
        _upgrade_package(
            candidate, candidate_digest, "0" * 64, preimage_manifest
        )
    assert package.read_bytes() == old_package
    assert not any((service_root / "backups").iterdir())

    monkeypatch.setattr(
        service_install,
        "_provision_provider_host_authority_identity",
        lambda value: (_ for _ in ()).throw(
            PermissionError("synthetic Provider Host identity failure")
        ),
    )
    with pytest.raises(PermissionError, match="synthetic Provider Host"):
        _upgrade_package(
            candidate, candidate_digest, old_digest, preimage_manifest
        )
    assert package.read_bytes() == old_package

    monkeypatch.setattr(
        service_install,
        "_provision_provider_host_authority_identity",
        lambda value: {
            "schema_version": 1,
            "key_id": "keeper-provider-host-rsa:test",
        },
    )

    real_persist = service_install._persist_manifest
    interrupted_after_claim = False

    def persist_then_interrupt_after_claim(value: dict[str, object]) -> None:
        nonlocal interrupted_after_claim
        real_persist(value)
        if (
            not interrupted_after_claim
            and "package_upgrade_claim" in value
            and not value.get("upgrades")
        ):
            interrupted_after_claim = True
            raise RuntimeError("simulated interruption after upgrade claim")

    monkeypatch.setattr(
        service_install, "_persist_manifest", persist_then_interrupt_after_claim
    )
    with pytest.raises(RuntimeError, match="after upgrade claim"):
        _upgrade_package(
            candidate, candidate_digest, old_digest, preimage_manifest
        )
    assert package.read_bytes() == old_package
    claimed_before_replace = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )
    assert claimed_before_replace["package_upgrade_claim"][
        "package_sha256"
    ] == candidate_digest
    assert claimed_before_replace["package_upgrade_claim"][
        "previous_source_commit"
    ] == "a" * 40
    monkeypatch.setattr(service_install, "_persist_manifest", real_persist)
    manifest_before_mismatch = manifest_path.read_bytes()
    with pytest.raises(PermissionError, match="upgrade claim differs"):
        _upgrade_package(
            candidate, candidate_digest, "F" * 64, preimage_manifest
        )
    assert package.read_bytes() == old_package
    assert manifest_path.read_bytes() == manifest_before_mismatch

    real_replace = os.replace

    def upgrade_replace_then_interrupt(source: Path, destination: Path) -> None:
        real_replace(source, destination)
        if Path(source).suffix == ".upgrade":
            raise RuntimeError("simulated interruption after upgrade replacement")

    monkeypatch.setattr(os, "replace", upgrade_replace_then_interrupt)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        _upgrade_package(
            candidate, candidate_digest, old_digest, preimage_manifest
        )
    assert package.read_bytes() == candidate.read_bytes()
    interrupted_upgrade = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert interrupted_upgrade["package_upgrade_claim"][
        "package_sha256"
    ] == candidate_digest
    assert interrupted_upgrade.get("upgrades") is None

    monkeypatch.setattr(os, "replace", real_replace)
    interrupted_backup = Path(
        str(interrupted_upgrade["package_upgrade_claim"]["backup_path"])
    )
    interrupted_rollback = service_install.rollback_package(
        interrupted_backup, old_digest
    )
    assert interrupted_rollback["package_sha256"] == old_digest
    assert package.read_bytes() == old_package
    after_interrupted_rollback = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )
    assert "package_upgrade_claim" not in after_interrupted_rollback

    interrupted_after_completion = False

    def persist_then_interrupt_after_completion(value: dict[str, object]) -> None:
        nonlocal interrupted_after_completion
        real_persist(value)
        if (
            not interrupted_after_completion
            and value.get("upgrades")
            and "package_upgrade_claim" not in value
        ):
            interrupted_after_completion = True
            raise RuntimeError("simulated interruption after upgrade completion")

    monkeypatch.setattr(
        service_install,
        "_persist_manifest",
        persist_then_interrupt_after_completion,
    )
    with pytest.raises(RuntimeError, match="after upgrade completion"):
        _upgrade_package(
            candidate, candidate_digest, old_digest, preimage_manifest
        )
    monkeypatch.setattr(service_install, "_persist_manifest", real_persist)
    result = _upgrade_package(
        candidate, candidate_digest, old_digest, preimage_manifest
    )

    assert package.read_bytes() == candidate.read_bytes()
    assert result["package_sha256"] == candidate_digest
    backup = Path(str(result["backup"]))
    assert backup.read_bytes() == old_package
    assert result["backup_sha256"] == hashlib.sha256(old_package).hexdigest().upper()
    persisted = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert persisted["upgrades"][-1]["package_sha256"] == candidate_digest
    assert persisted["upgrades"][-1]["source_tree_sha256"] == (
        verify_service_package(candidate).manifest["source_tree_sha256"]
    )
    assert persisted["upgrades"][-1]["source_commit"] == "b" * 40
    assert persisted["upgrades"][-1]["source_tree"] == "c" * 40
    assert persisted["upgrades"][-1]["previous_source_commit"] == "a" * 40
    assert persisted["upgrades"][-1]["previous_source_tree"] == "d" * 40
    assert persisted["source_commit"] == "b" * 40
    assert persisted["source_tree"] == "c" * 40
    assert persisted["upgrades"][-1]["provider_host_authority_key_id"] == (
        "keeper-provider-host-rsa:test"
    )
    assert persisted["upgrades"][-1]["recovery_preimage"][
        "manifest"
    ] == str(preimage_manifest.resolve())
    assert "package_upgrade_claim" not in persisted

    repeated = _upgrade_package(
        candidate, candidate_digest, old_digest, preimage_manifest
    )
    assert repeated["package_sha256"] == candidate_digest
    repeated_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert len(repeated_manifest["upgrades"]) == 1

    def replace_then_interrupt(source: Path, destination: Path) -> None:
        real_replace(source, destination)
        if Path(source).suffix == ".rollback":
            raise RuntimeError("simulated interruption after rollback replacement")

    monkeypatch.setattr(os, "replace", replace_then_interrupt)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        service_install.rollback_package(backup, str(result["backup_sha256"]))
    assert package.read_bytes() == old_package
    interrupted = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert interrupted["package_rollback_claim"]["restored_package_sha256"] == str(
        result["backup_sha256"]
    )
    monkeypatch.setattr(os, "replace", real_replace)
    rollback_result = service_install.rollback_package(
        backup, str(result["backup_sha256"])
    )
    assert package.read_bytes() == old_package
    assert rollback_result["package_sha256"] == str(result["backup_sha256"])
    rolled_back = json.loads(manifest_path.read_text(encoding="utf-8"))
    event = rolled_back["rollbacks"][-1]
    assert event == {
        "rolled_back_at": event["rolled_back_at"],
        "rollback_claimed_at": event["rollback_claimed_at"],
        "replaced_package_sha256": candidate_digest,
        "restored_package_sha256": str(result["backup_sha256"]),
        "source_backup_path": str(backup),
        "restored_source_commit": "a" * 40,
        "restored_source_tree": "d" * 40,
    }
    assert rolled_back["source_commit"] == "a" * 40
    assert rolled_back["source_tree"] == "d" * 40
    assert "package_rollback_claim" not in rolled_back


def test_rollback_requires_latest_recorded_backup_and_stopped_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _build(tmp_path, "candidate.pyz")
    candidate_digest = hashlib.sha256(candidate.read_bytes()).hexdigest().upper()
    service_root = tmp_path / "service"
    package = service_root / "bin" / "keeper-authority.pyz"
    backup = service_root / "backups" / "old.pyz"
    manifest_path = service_root / "audit" / "machine-artifacts.json"
    package.parent.mkdir(parents=True)
    backup.parent.mkdir(parents=True)
    package.write_bytes(candidate.read_bytes())
    with zipfile.ZipFile(backup, "w") as archive:
        archive.writestr("__main__.py", "print('old service')\n")
    backup_digest = hashlib.sha256(backup.read_bytes()).hexdigest().upper()
    manifest = {
        "schema_version": 1,
        "service_name": SERVICE_NAME,
        "source_commit": "a" * 40,
        "installation_completed_at": "2026-01-01T00:00:00+00:00",
        "artifacts": [],
        "commands": [],
        "upgrades": [{
            "package_sha256": candidate_digest,
            "previous_package_sha256": backup_digest,
            "backup_path": str(backup.resolve()),
        }],
    }
    service_install._record_file(manifest, package)
    service_install._record_file(manifest, backup)
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(service_install, "SERVICE_ROOT", service_root)
    monkeypatch.setattr(service_install, "MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(service_install, "_require_admin", lambda: None)
    monkeypatch.setattr(
        service_install,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, "STATE: RUNNING\n"
        ),
    )
    with pytest.raises(PermissionError, match="stopped"):
        service_install.rollback_package(backup, backup_digest)
    monkeypatch.setattr(
        service_install,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, "STATE: STOPPED\n"
        ),
    )
    unrecorded = tmp_path / "unrecorded.pyz"
    unrecorded.write_bytes(backup.read_bytes())
    with pytest.raises(PermissionError, match="identity differs"):
        service_install.rollback_package(unrecorded, backup_digest)
    package.write_bytes(b"changed-current-package")
    with pytest.raises(PermissionError, match="installed Authority"):
        service_install.rollback_package(backup, backup_digest)


def test_upgrade_retry_preserves_claimed_previous_source_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = {
        "source_commit": "b" * 40,
        "source_tree": "c" * 40,
        "package_upgrade_claim": {
            "previous_source_commit": "a" * 40,
            "previous_source_tree": "d" * 40,
        },
    }
    monkeypatch.setattr(service_install, "_require_admin", lambda: None)
    monkeypatch.setattr(
        service_install,
        "verify_service_package",
        lambda *_args, **_kwargs: type(
            "Candidate",
            (),
            {"path": tmp_path / "candidate.pyz"},
        )(),
    )
    monkeypatch.setattr(
        service_install,
        "verify_external_manifest",
        lambda *_args, **_kwargs: {
            "source_commit": "b" * 40,
            "source_tree": "c" * 40,
        },
    )
    monkeypatch.setattr(
        service_install, "_load_completed_manifest", lambda: manifest
    )
    monkeypatch.setattr(
        service_install, "_require_service_stopped", lambda _operation: None
    )
    monkeypatch.setattr(
        service_install,
        "_verified_recovery_preimage",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("identity checkpoint reached")
        ),
    )
    monkeypatch.setattr(service_install, "SERVICE_ROOT", tmp_path / "service")

    with pytest.raises(RuntimeError, match="identity checkpoint reached"):
        service_install.upgrade_package(
            tmp_path / "candidate.pyz",
            "A" * 64,
            "B" * 64,
            tmp_path / "preimage.json",
            tmp_path / "external.json",
            "C" * 64,
            tmp_path,
        )

    assert manifest["package_upgrade_claim"]["previous_source_commit"] == "a" * 40
    assert manifest["package_upgrade_claim"]["previous_source_tree"] == "d" * 40


@pytest.mark.parametrize(
    ("return_code", "output"),
    [
        (0, "STATE : 3 STOP_PENDING\n"),
        (0, "STATE : 7 PAUSED\n"),
        (1060, ""),
        (0, "STATE : 4 RUNNING\n"),
    ],
)
def test_package_lifecycle_requires_exact_confirmed_stopped_state(
    monkeypatch: pytest.MonkeyPatch, return_code: int, output: str
) -> None:
    monkeypatch.setattr(
        service_install,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], return_code, output
        ),
    )
    with pytest.raises(PermissionError, match="confirmed stopped"):
        service_install._require_service_stopped("upgrade")
    with pytest.raises(PermissionError, match="confirmed stopped"):
        service_install._require_service_stopped("rollback")


@pytest.mark.parametrize(
    "output", ["STATE: STOPPED\n", "        STATE : 1  STOPPED\r\n"]
)
def test_package_lifecycle_accepts_only_supported_stopped_forms(
    monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    monkeypatch.setattr(
        service_install,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, output),
    )
    service_install._require_service_stopped("upgrade")
    service_install._require_service_stopped("rollback")


def test_upgrade_rejects_wrong_hash_before_touching_installed_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _build(tmp_path, "candidate.pyz")
    monkeypatch.setattr(service_install, "_require_admin", lambda: None)
    with pytest.raises(PermissionError, match="authorization"):
        _upgrade_package(
            candidate, "0" * 64, "0" * 64, tmp_path / "absent.json"
        )


def test_founder_configuration_migration_reconciles_write_interruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service_root = tmp_path / "service"
    config = service_root / "config" / "service.json"
    config.parent.mkdir(parents=True)
    (service_root / "backups").mkdir()
    config.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "service_name": SERVICE_NAME,
                "service_root": str(service_root),
            }
        ),
        encoding="utf-8",
    )
    manifest_path = service_root / "audit" / "machine-artifacts.json"
    manifest_path.parent.mkdir()
    manifest: dict[str, object] = {
        "schema_version": 1,
        "service_name": SERVICE_NAME,
        "source_commit": "a" * 40,
        "installation_completed_at": "2026-01-01T00:00:00+00:00",
        "artifacts": [],
        "commands": [],
        "package_upgrade_claim": {
            "schema_version": 1,
            "package_sha256": "A" * 64,
            "claimed_at": "2026-01-01T00:00:00+00:00",
        },
    }
    service_install._record_file(manifest, config)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(service_install, "SERVICE_ROOT", service_root)
    monkeypatch.setattr(service_install, "MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(
        service_install,
        "_founder_verifier_configuration",
        _production_verifier_fixture,
    )
    real_copy = shutil.copy2
    interrupted_backup = False

    def copy_then_interrupt(source: Path, destination: Path) -> Path:
        nonlocal interrupted_backup
        result = Path(real_copy(source, destination))
        if not interrupted_backup and result.parent == service_root / "backups":
            interrupted_backup = True
            raise RuntimeError("simulated configuration backup interruption")
        return result

    monkeypatch.setattr(shutil, "copy2", copy_then_interrupt)
    with pytest.raises(RuntimeError, match="backup interruption"):
        service_install._migrate_founder_capability_configuration(manifest)
    orphan_backup = next((service_root / "backups").iterdir())
    assert orphan_backup.is_file()
    assert not service_install._recorded_file_matches(manifest, orphan_backup)
    assert "configuration_migration_claim" not in manifest
    monkeypatch.setattr(shutil, "copy2", real_copy)

    real_atomic_write = atomic_write_json
    interrupted = False

    def write_then_interrupt(path: Path, value: object) -> None:
        nonlocal interrupted
        real_atomic_write(path, value)
        if path == config and not interrupted:
            interrupted = True
            raise RuntimeError("simulated configuration write interruption")

    monkeypatch.setattr(service_install, "atomic_write_json", write_then_interrupt)
    with pytest.raises(RuntimeError, match="configuration write interruption"):
        service_install._migrate_founder_capability_configuration(manifest)
    assert json.loads(config.read_text(encoding="utf-8"))["schema_version"] == 3
    interrupted_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "configuration_migration_claim" in interrupted_manifest
    assert not service_install._recorded_file_matches(interrupted_manifest, config)

    mismatched_manifest = json.loads(json.dumps(interrupted_manifest))
    mismatched_manifest["package_upgrade_claim"]["package_sha256"] = "B" * 64
    with pytest.raises(PermissionError, match="package claim differs"):
        service_install._migrate_founder_capability_configuration(
            mismatched_manifest
        )

    monkeypatch.setattr(service_install, "atomic_write_json", real_atomic_write)
    verifier = service_install._migrate_founder_capability_configuration(
        interrupted_manifest
    )
    assert verifier == _production_verifier_fixture()
    completed = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "configuration_migration_claim" not in completed
    assert service_install._recorded_file_matches(completed, config)
    assert len(completed["configuration_migrations"]) == 1

    repeated = service_install._migrate_founder_capability_configuration(completed)
    assert repeated == verifier
    assert len(
        json.loads(manifest_path.read_text(encoding="utf-8"))[
            "configuration_migrations"
        ]
    ) == 1


def test_rollback_reconciles_interrupted_configuration_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service_root = tmp_path / "service"
    package = service_root / "bin" / "keeper-authority.pyz"
    backup_path = service_root / "backups" / "keeper-authority-old.pyz"
    config = service_root / "config" / "service.json"
    package.parent.mkdir(parents=True)
    backup_path.parent.mkdir()
    config.parent.mkdir()
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("__main__.py", "print('candidate')\n")
    with zipfile.ZipFile(backup_path, "w") as archive:
        archive.writestr("__main__.py", "print('old')\n")
    config.write_text(
        json.dumps({"schema_version": 2, "service_name": SERVICE_NAME}),
        encoding="utf-8",
    )
    candidate_digest = hashlib.sha256(package.read_bytes()).hexdigest().upper()
    old_digest = hashlib.sha256(backup_path.read_bytes()).hexdigest().upper()
    manifest_path = service_root / "audit" / "machine-artifacts.json"
    manifest_path.parent.mkdir()
    manifest: dict[str, object] = {
        "schema_version": 1,
        "service_name": SERVICE_NAME,
        "source_commit": "a" * 40,
        "installation_completed_at": "2026-01-01T00:00:00+00:00",
        "artifacts": [],
        "commands": [],
        "package_upgrade_claim": {
            "schema_version": 1,
            "claimed_at": "2026-01-01T00:00:00+00:00",
            "previous_package_sha256": old_digest,
            "package_sha256": candidate_digest,
            "backup_path": str(backup_path.resolve()),
        },
    }
    for path in (package, backup_path, config):
        service_install._record_file(manifest, path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(service_install, "SERVICE_ROOT", service_root)
    monkeypatch.setattr(service_install, "MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(service_install, "_require_admin", lambda: None)
    monkeypatch.setattr(
        service_install,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, "STATE: STOPPED\n"
        ),
    )
    monkeypatch.setattr(
        service_install,
        "_founder_verifier_configuration",
        _production_verifier_fixture,
    )
    real_atomic_write = atomic_write_json

    def write_then_interrupt(path: Path, value: object) -> None:
        real_atomic_write(path, value)
        if path == config:
            raise RuntimeError("simulated config interruption before rollback")

    monkeypatch.setattr(service_install, "atomic_write_json", write_then_interrupt)
    with pytest.raises(RuntimeError, match="before rollback"):
        service_install._migrate_founder_capability_configuration(manifest)
    interrupted = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "configuration_migration_claim" in interrupted

    wrong_backup = tmp_path / "wrong-but-byte-identical-old.pyz"
    wrong_backup.write_bytes(backup_path.read_bytes())
    before_wrong_request = {
        "manifest": manifest_path.read_bytes(),
        "config": config.read_bytes(),
        "package": package.read_bytes(),
    }
    with pytest.raises(PermissionError, match="rollback identity differs"):
        service_install.rollback_package(wrong_backup, old_digest)
    assert manifest_path.read_bytes() == before_wrong_request["manifest"]
    assert config.read_bytes() == before_wrong_request["config"]
    assert package.read_bytes() == before_wrong_request["package"]

    monkeypatch.setattr(service_install, "atomic_write_json", real_atomic_write)
    result = service_install.rollback_package(backup_path, old_digest)
    assert result["package_sha256"] == old_digest
    assert package.read_bytes() == backup_path.read_bytes()
    completed = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "configuration_migration_claim" not in completed
    assert "package_upgrade_claim" not in completed
    assert service_install._recorded_file_matches(completed, config)
    assert json.loads(config.read_text(encoding="utf-8"))["schema_version"] == 3


def test_rollback_verification_accepts_exact_legacy_package_only(tmp_path: Path) -> None:
    package = tmp_path / "legacy.pyz"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("__main__.py", "print('legacy service')\n")
        archive.writestr("keeper/service.py", "VALUE = 1\n")
    digest = hashlib.sha256(package.read_bytes()).hexdigest().upper()
    verified = verify_rollback_package(package, digest)
    assert verified.package_sha256 == digest
    with pytest.raises(PermissionError, match="SHA-256"):
        verify_rollback_package(package, "0" * 64)


def test_lazy_package_exports_preserve_public_compatibility() -> None:
    from keeper.executive import AuthorityEvaluator, ExecutiveRepository
    from keeper.providers import AgentProvider, CliProvider, MockProvider

    assert AuthorityEvaluator.__name__ == "AuthorityEvaluator"
    assert ExecutiveRepository.__name__ == "ExecutiveRepository"
    assert AgentProvider.__name__ == "AgentProvider"
    assert CliProvider.__name__ == "CliProvider"
    assert MockProvider.__name__ == "MockProvider"


def test_identity_verification_command_uses_read_only_verifier(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    expected = {"verified": True, "key_id": "synthetic"}
    monkeypatch.setattr(
        service_install,
        "verify_provider_host_authority_identity",
        lambda: expected,
    )

    assert service_install.main(
        ["verify-provider-host-authority-identity"]
    ) == 0
    assert json.loads(capsys.readouterr().out) == expected
