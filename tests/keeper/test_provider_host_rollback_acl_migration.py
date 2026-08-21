from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from keeper.authority_service.windows_security import (
    apply_path_security,
    read_path_security,
)
from keeper.provider_host import install as host_install
from keeper.provider_host.install import ProviderHostInstaller


_SERVICE_SID = "S-1-5-80-1-2-3-4-5"
_RESTRICTED_CODE_SID = "S-1-5-12"


def _distribution(
    root: Path, *, version: str, marker: bytes
) -> tuple[Path, str]:
    root.mkdir(parents=True)
    executable = root / "KeeperProviderHost.exe"
    runtime = root / "lib" / "python-runtime.dll"
    runtime.parent.mkdir()
    executable.write_bytes(b"MZ" + marker)
    runtime.write_bytes(b"runtime-" + marker)
    files = [
        {
            "path": path.relative_to(root).as_posix(),
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
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return executable, hashlib.sha256(manifest.read_bytes()).hexdigest()


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_update_and_same_version_repair_secure_retained_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_artifact, old_manifest = _distribution(
        tmp_path / "old", version="1.7.17", marker=b"old"
    )
    new_artifact, new_manifest = _distribution(
        tmp_path / "new", version="1.7.22", marker=b"new"
    )
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid=_SERVICE_SID,
    )
    installer.install(
        old_artifact,
        version="1.7.17",
        expected_package_sha256=old_manifest,
    )
    old_root = installer.versions / "1.7.17"
    old_hashes = _tree_hashes(old_root)
    secured: list[Path] = []
    original_secure = installer._secure_tree  # noqa: SLF001 - lifecycle probe

    def record_secure(path: Path) -> None:
        secured.append(path)
        original_secure(path)

    monkeypatch.setattr(installer, "_secure_tree", record_secure)
    updated = installer.update(
        new_artifact,
        version="1.7.22",
        expected_package_sha256=new_manifest,
        drain=lambda: None,
    )

    assert updated.previous_version == "1.7.17"
    assert old_root in secured
    assert installer.versions / "1.7.22" in secured
    assert _tree_hashes(old_root) == old_hashes
    assert installer.status()["transaction_pending"] is False

    secured.clear()
    repaired = installer.repair(
        new_artifact, expected_package_sha256=new_manifest
    )

    assert repaired.previous_version == "1.7.17"
    assert old_root in secured
    assert installer.versions / "1.7.22" in secured
    assert old_root.is_dir()
    assert _tree_hashes(old_root) == old_hashes
    assert installer.status()["current"]["previous_version"] == "1.7.17"  # type: ignore[index]


def test_failed_rollback_security_finalization_remains_durable_and_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_artifact, old_manifest = _distribution(
        tmp_path / "old", version="1.7.17", marker=b"old"
    )
    new_artifact, new_manifest = _distribution(
        tmp_path / "new", version="1.7.22", marker=b"new"
    )
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid=_SERVICE_SID,
    )
    installer.install(
        old_artifact,
        version="1.7.17",
        expected_package_sha256=old_manifest,
    )
    original_finalize = installer._finalize_protected_install  # noqa: SLF001

    def fail_finalization(version: str, rollback: str | None) -> None:
        assert version == "1.7.22"
        assert rollback == "1.7.17"
        raise PermissionError("simulated rollback ACL read-back failure")

    monkeypatch.setattr(
        installer, "_finalize_protected_install", fail_finalization
    )
    with pytest.raises(PermissionError, match="ACL read-back"):
        installer.update(
            new_artifact,
            version="1.7.22",
            expected_package_sha256=new_manifest,
            drain=lambda: None,
        )

    assert installer.transaction_path.is_file()
    transaction = json.loads(installer.transaction_path.read_text(encoding="utf-8"))
    assert transaction["retained_rollback_version"] == "1.7.17"
    assert installer.status()["current"]["version"] == "1.7.22"  # type: ignore[index]
    monkeypatch.setattr(
        installer, "_finalize_protected_install", original_finalize
    )

    recovered = installer.recover()

    assert recovered["recovered"] is True
    assert recovered["current"]["version"] == "1.7.22"  # type: ignore[index]
    assert recovered["current"]["previous_version"] == "1.7.17"  # type: ignore[index]
    assert not installer.transaction_path.exists()


def test_attestation_failure_does_not_clear_lifecycle_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_artifact, old_manifest = _distribution(
        tmp_path / "old", version="1.7.17", marker=b"old"
    )
    new_artifact, new_manifest = _distribution(
        tmp_path / "new", version="1.7.22", marker=b"new"
    )
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid=_SERVICE_SID,
    )
    installer.install(
        old_artifact,
        version="1.7.17",
        expected_package_sha256=old_manifest,
    )
    original_attest = installer.attest_protected_tree
    monkeypatch.setattr(
        installer,
        "attest_protected_tree",
        lambda: (_ for _ in ()).throw(
            PermissionError("simulated protected-tree mismatch")
        ),
    )

    with pytest.raises(PermissionError, match="protected-tree mismatch"):
        installer.update(
            new_artifact,
            version="1.7.22",
            expected_package_sha256=new_manifest,
            drain=lambda: None,
        )

    assert installer.transaction_path.is_file()
    monkeypatch.setattr(installer, "attest_protected_tree", original_attest)
    assert installer.recover()["recovered"] is True
    assert not installer.transaction_path.exists()


def test_recovery_understands_legacy_same_version_repair_transaction(
    tmp_path: Path,
) -> None:
    old_artifact, old_manifest = _distribution(
        tmp_path / "old", version="1.7.17", marker=b"old"
    )
    new_artifact, new_manifest = _distribution(
        tmp_path / "new", version="1.7.22", marker=b"new"
    )
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid=_SERVICE_SID,
    )
    installer.install(
        old_artifact,
        version="1.7.17",
        expected_package_sha256=old_manifest,
    )
    installed = installer.update(
        new_artifact,
        version="1.7.22",
        expected_package_sha256=new_manifest,
        drain=lambda: None,
    )
    installer.transaction_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "operation": "update",
                "version": "1.7.22",
                "artifact_sha256": installed.artifact_sha256,
                "package_sha256": installed.package_sha256,
                "previous_version": "1.7.22",
                "staging_path": "",
                "backup_path": "",
                "started_at": "2026-08-11T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )

    recovered = installer.recover()

    assert recovered["recovered"] is True
    assert recovered["current"]["version"] == "1.7.22"  # type: ignore[index]
    assert recovered["current"]["previous_version"] == "1.7.17"  # type: ignore[index]
    assert (installer.versions / "1.7.17").is_dir()
    assert not installer.transaction_path.exists()


@pytest.mark.skipif(os.name != "nt", reason="exact Host ACLs require Windows")
def test_update_migrates_legacy_rollback_acl_without_changing_package_bytes(
    tmp_path: Path,
) -> None:
    old_artifact, old_manifest = _distribution(
        tmp_path / "old", version="1.7.17", marker=b"old"
    )
    new_artifact, new_manifest = _distribution(
        tmp_path / "new", version="1.7.22", marker=b"new"
    )
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid=_SERVICE_SID,
    )
    installer.install(
        old_artifact,
        version="1.7.17",
        expected_package_sha256=old_manifest,
    )
    old_root = installer.versions / "1.7.17"
    before = _tree_hashes(old_root)
    for path in [old_root, *old_root.rglob("*")]:
        policy = installer._security_policy(path)  # noqa: SLF001 - legacy fixture
        aces = policy["aces"]
        assert isinstance(aces, list)
        policy["aces"] = [
            ace
            for ace in aces
            if isinstance(ace, dict)
            if ace["trustee_sid"] != _SERVICE_SID
        ]
        apply_path_security(path, policy)
    with pytest.raises(PermissionError, match="protected path security differs"):
        installer.attest_protected_tree()

    installer.update(
        new_artifact,
        version="1.7.22",
        expected_package_sha256=new_manifest,
        drain=lambda: None,
    )

    assert len(installer.attest_protected_tree()) == 64
    assert _tree_hashes(old_root) == before
    live = read_path_security(old_root / "KeeperProviderHost.exe")
    service = [
        ace for ace in live["aces"] if ace["trustee_sid"] == _SERVICE_SID
    ]
    restricted = [
        ace
        for ace in live["aces"]
        if ace["trustee_sid"] == _RESTRICTED_CODE_SID
    ]
    assert service == [
        host_install._host_ace(  # noqa: SLF001 - exact ACL contract
            "allow", _SERVICE_SID, [], rights_mask=host_install._FILE_READ_EXECUTE
        )
    ]
    assert len(restricted) == 1
    assert restricted[0]["ace_type"] == "deny"

    for path in [old_root, *old_root.rglob("*")]:
        policy = installer._security_policy(path)  # noqa: SLF001 - live fixture
        aces = policy["aces"]
        assert isinstance(aces, list)
        policy["aces"] = [
            ace
            for ace in aces
            if isinstance(ace, dict)
            if ace["trustee_sid"] != _SERVICE_SID
        ]
        apply_path_security(path, policy)
    with pytest.raises(PermissionError, match="protected path security differs"):
        installer.attest_protected_tree()

    repaired = installer.repair(
        new_artifact, expected_package_sha256=new_manifest
    )

    assert repaired.version == "1.7.22"
    assert repaired.previous_version == "1.7.17"
    assert old_root.is_dir()
    assert _tree_hashes(old_root) == before
    assert len(installer.attest_protected_tree()) == 64
