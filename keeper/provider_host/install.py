from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Callable

from keeper.authority_service.windows_security import (
    apply_path_security,
    compare_path_security,
    read_path_owner_sid,
    read_path_security,
)
from keeper.provider_host.identity import current_user_binding
from keeper.recovery import atomic_write_json


_RESTRICTED_CODE_SID = "S-1-5-12"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_SYSTEM_SID = "S-1-5-18"
_FILE_ALL_ACCESS = 0x001F01FF
_FILE_READ_EXECUTE = 0x001200A9
_SERVICE_SID = re.compile(r"S-1-5-80-(?:\d+-){4}\d+")
_PACKAGE_MANIFEST = "keeper-provider-host-package-manifest.json"
_PACKAGE_SCHEMA_VERSION = 1
_PACKAGE_PRODUCT = "KeeperProviderHost"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass(frozen=True, slots=True)
class HostInstallResult:
    version: str
    artifact_path: str
    artifact_sha256: str
    package_sha256: str
    previous_version: str | None
    startup_path: str


@dataclass(frozen=True, slots=True)
class _VerifiedPackage:
    root: Path
    executable: Path
    executable_sha256: str
    manifest_sha256: str
    manifest: dict[str, object]


class ProviderHostInstaller:
    """Crash-safe per-user lifecycle with one verified rollback generation."""

    def __init__(
        self,
        install_root: Path,
        startup_root: Path,
        *,
        owner_sid: str | None = None,
        authority_service_sid: str | None = None,
    ) -> None:
        self.root = install_root.resolve()
        self.startup_root = startup_root.resolve()
        self.versions = self.root / "versions"
        self.state = self.root / "state"
        self.logs = self.root / "logs"
        self.current_path = self.root / "current.json"
        self.transaction_path = self.root / "lifecycle-transaction.json"
        self.startup_path = self.startup_root / "KeeperProviderHost.cmd"
        self.owner_sid = owner_sid or (
            current_user_binding().user_sid if os.name == "nt" else None
        )
        if (
            authority_service_sid is not None
            and not _SERVICE_SID.fullmatch(authority_service_sid)
        ):
            raise PermissionError("KeeperAuthority service SID is invalid")
        self.authority_service_sid = authority_service_sid
    def install(
        self,
        artifact: Path,
        *,
        version: str,
        expected_package_sha256: str,
    ) -> HostInstallResult:
        _validate_version(version)
        package = _verify_package(
            artifact,
            version=version,
            expected_manifest_sha256=expected_package_sha256,
            require_defender=True,
        )
        current = self._load_current(required=False)
        previous = str(current["version"]) if current is not None else None
        retained_rollback = _retained_rollback_version(current, version)
        return self._install_verified(
            package,
            version=version,
            previous=previous,
            retained_rollback=retained_rollback,
            operation="install" if current is None else "update",
        )

    def _install_verified(
        self,
        package: _VerifiedPackage,
        *,
        version: str,
        previous: str | None,
        retained_rollback: str | None,
        operation: str,
        recovery_binding: dict[str, str] | None = None,
    ) -> HostInstallResult:
        if operation not in {"install", "update", "quarantine-replacement"}:
            raise PermissionError("Provider Host lifecycle operation is invalid")
        self._ensure_roots()
        transaction_id = uuid.uuid4().hex
        destination_root = self.versions / version
        staging_root = self.versions / f".{version}.{transaction_id}.staging"
        backup_root = self.versions / f".{version}.{transaction_id}.backup"
        transaction = {
            "schema_version": 2,
            "operation": operation,
            "version": version,
            "artifact_sha256": package.executable_sha256,
            "package_sha256": package.manifest_sha256,
            "previous_version": previous,
            "retained_rollback_version": retained_rollback,
            "staging_path": str(staging_root),
            "backup_path": str(backup_root),
            "started_at": _now(),
        }
        if recovery_binding is not None:
            if operation != "quarantine-replacement":
                raise PermissionError(
                    "Provider Host recovery binding is invalid for this lifecycle"
                )
            transaction.update(recovery_binding)
        atomic_write_json(self.transaction_path, transaction)
        try:
            self._copy_package(package, staging_root)
            _verify_package(
                staging_root / "KeeperProviderHost.exe",
                version=version,
                expected_manifest_sha256=package.manifest_sha256,
            )
            if destination_root.exists():
                if _unsafe_tree(destination_root, self.versions):
                    raise PermissionError("Provider Host version path is unsafe")
                os.replace(destination_root, backup_root)
            os.replace(staging_root, destination_root)
            installed = _verify_package(
                destination_root / "KeeperProviderHost.exe",
                version=version,
                expected_manifest_sha256=package.manifest_sha256,
            )
            self._secure_tree(destination_root)
            self._commit_selection(
                installed,
                version=version,
                previous_version=retained_rollback,
            )
        except Exception:
            if not destination_root.exists() and backup_root.exists():
                os.replace(backup_root, destination_root)
            raise
        finally:
            if staging_root.exists() and not _unsafe_tree(staging_root, self.versions):
                shutil.rmtree(staging_root)
        if backup_root.exists():
            if _unsafe_tree(backup_root, self.versions):
                raise PermissionError("Provider Host backup path is unsafe")
            shutil.rmtree(backup_root)
        self._finalize_protected_install(version, retained_rollback)
        self.transaction_path.unlink(missing_ok=True)
        return self._result(installed, version, retained_rollback)

    def repair(
        self, artifact: Path, *, expected_package_sha256: str
    ) -> HostInstallResult:
        current = self._load_current(required=True)
        assert current is not None
        return self.install(
            artifact,
            version=str(current["version"]),
            expected_package_sha256=expected_package_sha256,
        )

    def update(
        self,
        artifact: Path,
        *,
        version: str,
        expected_package_sha256: str,
        drain: Callable[[], None],
    ) -> HostInstallResult:
        current = self._load_current(required=True)
        assert current is not None
        if current["version"] == version:
            raise ValueError("Provider Host update version is unchanged")
        drain()
        return self.install(
            artifact,
            version=version,
            expected_package_sha256=expected_package_sha256,
        )

    def replace_quarantined_selection(
        self,
        artifact: Path,
        *,
        version: str,
        expected_package_sha256: str,
        expected_current_sha256: str,
        expected_rollback_version: str,
        expected_rollback_artifact_sha256: str,
        expected_rollback_package_sha256: str,
        drain: Callable[[], None],
    ) -> HostInstallResult:
        """Replace one exact selected package whose executable was quarantined.

        This is intentionally narrower than normal recovery.  It accepts only a
        structurally exact current record, an absent selected executable with
        the rest of that selected package still measured, one intact retained
        rollback generation, and a different exact Defender-clean replacement.
        No lifecycle root, transaction, or selection is changed until all three
        identities have been validated.
        """
        _validate_version(version)
        _validate_digest(expected_current_sha256)
        _validate_version(expected_rollback_version)
        _validate_digest(expected_rollback_artifact_sha256)
        _validate_digest(expected_rollback_package_sha256)
        replacement = _verify_package(
            artifact,
            version=version,
            expected_manifest_sha256=expected_package_sha256,
            require_defender=True,
        )
        current = self._load_quarantined_current(
            expected_current_sha256=expected_current_sha256
        )
        selected_version = str(current["version"])
        if selected_version == version:
            raise PermissionError(
                "Provider Host quarantine replacement version is unchanged"
            )
        rollback_version = current["previous_version"]
        assert isinstance(rollback_version, str)
        if rollback_version != expected_rollback_version:
            raise PermissionError(
                "Provider Host quarantine rollback version differs"
            )
        if rollback_version == version:
            raise PermissionError(
                "Provider Host quarantine replacement matches rollback generation"
            )
        replacement_root = self.versions / version
        if os.path.lexists(replacement_root):
            raise PermissionError(
                "Provider Host quarantine replacement generation already exists"
            )
        if os.name == "nt":
            self.attest_protected_tree()
        rollback = self._installed_package(
            rollback_version,
            expected_rollback_package_sha256,
            require_defender=True,
        )
        if rollback.executable_sha256 != expected_rollback_artifact_sha256.casefold():
            raise PermissionError(
                "Provider Host quarantine rollback executable digest differs"
            )
        drain()
        return self._install_verified(
            replacement,
            version=version,
            previous=selected_version,
            retained_rollback=rollback_version,
            operation="quarantine-replacement",
            recovery_binding={
                "quarantined_current_sha256": expected_current_sha256.casefold(),
                "retained_rollback_artifact_sha256": (
                    expected_rollback_artifact_sha256.casefold()
                ),
                "retained_rollback_package_sha256": (
                    expected_rollback_package_sha256.casefold()
                ),
            },
        )

    def rollback(self, *, drain: Callable[[], None]) -> HostInstallResult:
        current = self._load_current(required=True)
        assert current is not None
        previous = current.get("previous_version")
        if not isinstance(previous, str) or not previous:
            raise PermissionError("Provider Host rollback generation is unavailable")
        package = self._installed_package(previous, require_defender=True)
        drain()
        atomic_write_json(
            self.transaction_path,
            {
                "schema_version": 2,
                "operation": "rollback",
                "version": previous,
                "artifact_sha256": package.executable_sha256,
                "package_sha256": package.manifest_sha256,
                "previous_version": str(current["version"]),
                "retained_rollback_version": str(current["version"]),
                "staging_path": "",
                "backup_path": "",
                "started_at": _now(),
            },
        )
        self._commit_selection(
            package, version=previous, previous_version=str(current["version"])
        )
        self._finalize_protected_install(previous, str(current["version"]))
        self.transaction_path.unlink()
        return self._result(package, previous, str(current["version"]))

    def uninstall_preserving_data(
        self, *, drain: Callable[[], None]
    ) -> dict[str, object]:
        self._load_current(required=True)
        drain()
        atomic_write_json(
            self.transaction_path,
            {
                "schema_version": 2,
                "operation": "uninstall",
                "version": "",
                "artifact_sha256": "",
                "package_sha256": "",
                "previous_version": None,
                "staging_path": "",
                "backup_path": "",
                "started_at": _now(),
            },
        )
        self._finish_program_removal()
        self.transaction_path.unlink(missing_ok=True)
        return {
            "program_removed": True,
            "startup_removed": True,
            "state_preserved": self.state.exists(),
            "logs_preserved": self.logs.exists(),
        }

    def recover(self) -> dict[str, object]:
        if not self.transaction_path.exists():
            current = self._load_current(required=False)
            return {"recovered": False, "current": current}
        transaction = _read_object(self.transaction_path)
        if transaction.get("schema_version") != 2:
            raise PermissionError("Provider Host lifecycle transaction is invalid")
        if transaction.get("operation") == "uninstall":
            self._finish_program_removal()
            self.transaction_path.unlink()
            return {"recovered": True, "current": None}
        if transaction.get("operation") == "quarantine-replacement":
            return self._recover_quarantine_replacement(transaction)
        version = transaction.get("version")
        package_sha256 = transaction.get("package_sha256")
        previous = transaction.get("previous_version")
        retained_rollback = transaction.get("retained_rollback_version", previous)
        if (
            "retained_rollback_version" not in transaction
            and isinstance(version, str)
            and previous == version
            and self.current_path.is_file()
        ):
            selection = _read_object(self.current_path)
            if selection.get("version") == version:
                retained_rollback = selection.get("previous_version")
        if retained_rollback is not None and not isinstance(retained_rollback, str):
            raise PermissionError("Provider Host rollback generation is invalid")
        if isinstance(version, str) and isinstance(package_sha256, str):
            try:
                package = _verify_package(
                    self.versions / version / "KeeperProviderHost.exe",
                    version=version,
                    expected_manifest_sha256=package_sha256,
                    require_defender=True,
                )
            except (FileNotFoundError, OSError, PermissionError, ValueError):
                package = None
            if package is not None:
                self._commit_selection(
                    package,
                    version=version,
                    previous_version=retained_rollback,
                )
                self._finalize_protected_install(version, retained_rollback)
                self._clean_transaction_paths(transaction)
                self.transaction_path.unlink()
                return {"recovered": True, "current": self._load_current(required=True)}
            self._restore_transaction_backup(transaction, version)
        current = self._load_current(required=False)
        if current is not None:
            self._installed_package(
                str(current["version"]),
                str(current["package_sha256"]),
                require_defender=True,
            )
            self._write_startup_launcher(Path(str(current["artifact_path"])))
            current_version = str(current["version"])
            current_rollback = current.get("previous_version")
            if current_rollback is not None and not isinstance(
                current_rollback, str
            ):
                raise PermissionError(
                    "Provider Host rollback generation is invalid"
                )
            self._finalize_protected_install(current_version, current_rollback)
            self._clean_transaction_paths(transaction)
            self.transaction_path.unlink()
            return {"recovered": True, "current": current}
        raise PermissionError("Provider Host lifecycle recovery is ambiguous")

    def status(self) -> dict[str, object]:
        current = self._load_current(required=False)
        return {
            "installed": current is not None,
            "current": current,
            "startup_registered": self.startup_path.is_file(),
            "transaction_pending": self.transaction_path.is_file(),
        }

    def _load_quarantined_current(
        self,
        *,
        expected_current_sha256: str,
        allow_pending_transaction: bool = False,
    ) -> dict[str, object]:
        """Validate an exact selected package with only its executable absent."""
        if self.transaction_path.exists() and not allow_pending_transaction:
            raise PermissionError(
                "Provider Host quarantine replacement requires no pending lifecycle"
            )
        if not self.current_path.is_file():
            raise PermissionError("Provider Host current selection is unavailable")
        _validate_digest(expected_current_sha256)
        if _digest_file(self.current_path) != expected_current_sha256.casefold():
            raise PermissionError("Provider Host quarantine current record differs")
        value = _read_object(self.current_path)
        expected = {
            "schema_version",
            "version",
            "artifact_path",
            "artifact_sha256",
            "package_sha256",
            "previous_version",
            "selected_at",
        }
        if set(value) != expected or value.get("schema_version") != 2:
            raise PermissionError("Provider Host current selection is invalid")
        version = value.get("version")
        previous = value.get("previous_version")
        artifact_sha256 = value.get("artifact_sha256")
        package_sha256 = value.get("package_sha256")
        selected_at = value.get("selected_at")
        if (
            not isinstance(version, str)
            or not isinstance(previous, str)
            or previous == version
            or not isinstance(artifact_sha256, str)
            or not isinstance(package_sha256, str)
            or not isinstance(selected_at, str)
            or not _valid_utc_timestamp(selected_at)
        ):
            raise PermissionError(
                "Provider Host quarantined selection identity is invalid"
            )
        _validate_version(version)
        _validate_version(previous)
        _validate_digest(artifact_sha256)
        _validate_digest(package_sha256)
        selected_root = self.versions / version
        manifest_path = selected_root / _PACKAGE_MANIFEST
        expected_executable = selected_root / "KeeperProviderHost.exe"
        recorded_executable = Path(str(value.get("artifact_path", "")))
        expected_launcher = (
            "@echo off\r\n"
            f'"{expected_executable}" run '
            f'--config "{self.state / "provider-host-enrollment.json"}"\r\n'
        ).encode("utf-8")
        selected_root_resolved = selected_root.resolve(strict=True)
        if (
            not selected_root.is_dir()
            or _is_link_or_reparse(selected_root)
            or recorded_executable != expected_executable
            or os.path.lexists(expected_executable)
            or not manifest_path.is_file()
            or _digest_file(manifest_path) != package_sha256.casefold()
            or not self.startup_path.is_file()
            or _is_link_or_reparse(self.startup_path)
            or self.startup_path.read_bytes() != expected_launcher
        ):
            raise PermissionError(
                "Provider Host selected package is not an exact quarantine state"
            )
        manifest = _read_object(manifest_path)
        if (
            set(manifest) != {"schema_version", "product", "version", "files"}
            or manifest.get("schema_version") != _PACKAGE_SCHEMA_VERSION
            or manifest.get("product") != _PACKAGE_PRODUCT
            or manifest.get("version") != version
        ):
            raise PermissionError("Provider Host quarantined package identity differs")
        files = _manifest_files(manifest)
        executable_entries = [
            entry
            for entry in files
            if str(entry["path"]).casefold() == "keeperproviderhost.exe"
        ]
        if (
            len(executable_entries) != 1
            or executable_entries[0]["sha256"] != artifact_sha256.casefold()
        ):
            raise PermissionError(
                "Provider Host quarantined executable identity differs"
            )
        expected_paths = {
            str(entry["path"])
            for entry in files
            if str(entry["path"]).casefold() != "keeperproviderhost.exe"
        }
        if _actual_package_paths(selected_root) != expected_paths:
            raise PermissionError(
                "Provider Host quarantined package coverage differs"
            )
        for entry in files:
            relative_text = str(entry["path"])
            if relative_text.casefold() == "keeperproviderhost.exe":
                continue
            target = selected_root.joinpath(*PurePosixPath(relative_text).parts)
            resolved = target.resolve(strict=True)
            if (
                selected_root_resolved not in resolved.parents
                or _is_link_or_reparse(target)
                or not target.is_file()
                or target.stat().st_size != entry["size"]
                or _digest_file(target) != entry["sha256"]
            ):
                raise PermissionError(
                    "Provider Host quarantined package file differs"
                )
        return value

    def _recover_quarantine_replacement(
        self, transaction: dict[str, object]
    ) -> dict[str, object]:
        """Restore the exact pre-replacement quarantined selection after interruption."""
        expected_fields = {
            "schema_version",
            "operation",
            "version",
            "artifact_sha256",
            "package_sha256",
            "previous_version",
            "retained_rollback_version",
            "staging_path",
            "backup_path",
            "started_at",
            "quarantined_current_sha256",
            "retained_rollback_artifact_sha256",
            "retained_rollback_package_sha256",
        }
        if set(transaction) != expected_fields:
            raise PermissionError(
                "Provider Host quarantine replacement transaction is invalid"
            )
        version = transaction.get("version")
        previous = transaction.get("previous_version")
        retained = transaction.get("retained_rollback_version")
        artifact_sha256 = transaction.get("artifact_sha256")
        package_sha256 = transaction.get("package_sha256")
        started_at = transaction.get("started_at")
        current_sha256 = transaction.get("quarantined_current_sha256")
        rollback_artifact_sha256 = transaction.get(
            "retained_rollback_artifact_sha256"
        )
        rollback_package_sha256 = transaction.get(
            "retained_rollback_package_sha256"
        )
        if (
            not isinstance(version, str)
            or not isinstance(previous, str)
            or not isinstance(retained, str)
            or not isinstance(artifact_sha256, str)
            or not isinstance(package_sha256, str)
            or not isinstance(started_at, str)
            or not isinstance(current_sha256, str)
            or not isinstance(rollback_artifact_sha256, str)
            or not isinstance(rollback_package_sha256, str)
            or not _valid_utc_timestamp(started_at)
        ):
            raise PermissionError(
                "Provider Host quarantine replacement transaction is invalid"
            )
        _validate_version(version)
        _validate_version(previous)
        _validate_version(retained)
        _validate_digest(artifact_sha256)
        _validate_digest(package_sha256)
        _validate_digest(current_sha256)
        _validate_digest(rollback_artifact_sha256)
        _validate_digest(rollback_package_sha256)
        if version in {previous, retained}:
            raise PermissionError(
                "Provider Host quarantine replacement transaction binding differs"
            )
        rollback = self._installed_package(
            retained,
            rollback_package_sha256,
            require_defender=True,
        )
        if rollback.executable_sha256 != rollback_artifact_sha256.casefold():
            raise PermissionError(
                "Provider Host quarantine rollback executable digest differs"
            )
        staging = Path(str(transaction.get("staging_path", "")))
        backup = Path(str(transaction.get("backup_path", "")))
        match = re.fullmatch(
            rf"\.{re.escape(version)}\.([0-9a-f]{{32}})\.staging", staging.name
        )
        if (
            match is None
            or staging.parent != self.versions
            or backup.parent != self.versions
            or backup.name != f".{version}.{match.group(1)}.backup"
            or os.path.lexists(backup)
        ):
            raise PermissionError(
                "Provider Host quarantine replacement transaction path differs"
            )
        destination = self.versions / version
        actual_current_sha256 = _digest_file(self.current_path)
        current_is_quarantined = actual_current_sha256 == current_sha256.casefold()
        if current_is_quarantined:
            current = self._load_quarantined_current(
                expected_current_sha256=current_sha256,
                allow_pending_transaction=True,
            )
            if (
                current.get("version") != previous
                or current.get("previous_version") != retained
            ):
                raise PermissionError(
                    "Provider Host quarantine replacement transaction binding differs"
                )
        else:
            try:
                loaded = self._load_current(required=True)
            except (FileNotFoundError, OSError, PermissionError, ValueError) as error:
                raise PermissionError(
                    "Provider Host quarantine replacement current selection differs"
                ) from error
            assert loaded is not None
            current = loaded
            if (
                current.get("version") != version
                or current.get("previous_version") != retained
                or current.get("artifact_sha256") != artifact_sha256.casefold()
                or current.get("package_sha256") != package_sha256.casefold()
            ):
                raise PermissionError(
                    "Provider Host quarantine replacement current selection differs"
                )
        try:
            replacement = _verify_package(
                destination / "KeeperProviderHost.exe",
                version=version,
                expected_manifest_sha256=package_sha256,
                require_defender=True,
            )
        except (FileNotFoundError, OSError, PermissionError, ValueError):
            if not current_is_quarantined:
                raise PermissionError(
                    "Provider Host selected quarantine replacement is invalid"
                )
            if os.path.lexists(staging) or os.path.lexists(destination):
                raise PermissionError(
                    "Provider Host quarantine replacement recovery is ambiguous"
                )
            self.transaction_path.unlink()
            return {
                "recovered": True,
                "current": current,
                "selection_quarantined": True,
            }
        if replacement.executable_sha256 != artifact_sha256.casefold():
            raise PermissionError(
                "Provider Host quarantine replacement executable digest differs"
            )
        if current_is_quarantined:
            self._commit_selection(
                replacement,
                version=version,
                previous_version=retained,
            )
        self._finalize_protected_install(version, retained)
        self._clean_transaction_paths(transaction)
        self.transaction_path.unlink()
        return {"recovered": True, "current": self._load_current(required=True)}

    def attest_protected_tree(self) -> str:
        """Verify and summarize the exact fail-closed Host filesystem policy.

        KeeperAuthority uses this only inside its fixed read-only Host-path
        observation body. Production enrollment runs that body on a disposable
        worker under the already authenticated desktop client's token, then
        reverts and proves the worker identity clean before using the result.
        The traversal never follows aliases and never reads protected file
        contents. Every reachable Host path must retain the exact owner, DACL,
        and mandatory-integrity policy installed by Keeper.
        """
        if os.name != "nt":
            raise RuntimeError("Provider Host path attestation requires Windows")
        if self.owner_sid is None or not self.owner_sid.startswith("S-1-"):
            raise PermissionError("Provider Host owner SID is unavailable")
        if self.authority_service_sid is None:
            raise PermissionError("KeeperAuthority service SID is unavailable")
        paths = _protected_tree_paths(self.root)
        for required in (self.startup_root, self.startup_path):
            if not required.exists():
                raise PermissionError("Provider Host protected path is absent")
            if _is_link_or_reparse(required):
                raise PermissionError("Provider Host protected path is an alias")
            paths.append((required, False))
        observations: list[dict[str, object]] = []
        for path, inherited in sorted(
            paths, key=lambda item: os.path.normcase(str(item[0]))
        ):
            expected = self._security_policy(path, inherited=inherited)
            live = read_path_security(path)
            comparison = compare_path_security(expected, live)
            owner = read_path_owner_sid(path)
            if (
                comparison["result"] != "PASS"
                or owner.casefold() != self.owner_sid.casefold()
            ):
                raise PermissionError(
                    "Provider Host protected path security differs"
                )
            stat_result = path.stat()
            observations.append(
                {
                    "directory": path.is_dir(),
                    "file_id": [
                        int(stat_result.st_dev),
                        int(stat_result.st_ino),
                    ],
                    "modified_ns": int(stat_result.st_mtime_ns),
                    "owner_sid": owner,
                    "path": str(path.resolve(strict=True)),
                    "security": live,
                    "size": int(stat_result.st_size),
                }
            )
        return hashlib.sha256(
            json.dumps(
                observations,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    def _ensure_roots(self) -> None:
        for path in (self.root, self.versions, self.state, self.logs, self.startup_root):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        for path in (self.root, self.versions, self.state, self.logs, self.startup_root):
            self._secure(path)

    def _load_current(self, *, required: bool) -> dict[str, object] | None:
        if not self.current_path.is_file():
            if required:
                raise PermissionError("Provider Host is not installed")
            return None
        value = _read_object(self.current_path)
        expected = {
            "schema_version",
            "version",
            "artifact_path",
            "artifact_sha256",
            "package_sha256",
            "previous_version",
            "selected_at",
        }
        if set(value) != expected or value.get("schema_version") != 2:
            raise PermissionError("Provider Host current selection is invalid")
        version = str(value["version"])
        _validate_version(version)
        package = self._installed_package(version, str(value["package_sha256"]))
        if package.executable != Path(str(value["artifact_path"])).resolve(strict=True):
            raise PermissionError("Provider Host current artifact path differs")
        if package.executable_sha256 != value["artifact_sha256"]:
            raise PermissionError("Provider Host current executable digest differs")
        return value

    def _installed_package(
        self,
        version: str,
        expected_package_sha256: str | None = None,
        *,
        require_defender: bool = False,
    ) -> _VerifiedPackage:
        manifest_path = self.versions / version / _PACKAGE_MANIFEST
        if expected_package_sha256 is None:
            expected_package_sha256 = _digest_file(manifest_path)
        return _verify_package(
            self.versions / version / "KeeperProviderHost.exe",
            version=version,
            expected_manifest_sha256=expected_package_sha256,
            require_defender=require_defender,
        )

    def _copy_package(self, package: _VerifiedPackage, destination: Path) -> None:
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        files = _manifest_files(package.manifest)
        for entry in files:
            relative = Path(*PurePosixPath(str(entry["path"])).parts)
            source = package.root / relative
            target = destination / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _atomic_replace_bytes(target, source.read_bytes())
        _atomic_replace_bytes(
            destination / _PACKAGE_MANIFEST,
            (package.root / _PACKAGE_MANIFEST).read_bytes(),
        )
        self._secure_tree(destination)

    def _secure_tree(self, root: Path) -> None:
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts)):
            self._secure(path)
        self._secure(root)

    def _finalize_protected_install(
        self, version: str, rollback_version: str | None
    ) -> None:
        """Verify, migrate, and attest every retained executable generation.

        A rollback package remains executable product state.  It therefore
        receives the same closed Host-tree policy as the selected package
        before an install, update, repair, rollback, or recovered lifecycle can
        clear its durable transaction.  ACL migration must not alter package
        bytes, and any failed read-back leaves the transaction pending.
        """
        _validate_version(version)
        retained = {version}
        if rollback_version is not None:
            _validate_version(rollback_version)
            if rollback_version == version:
                raise PermissionError(
                    "Provider Host rollback generation matches current version"
                )
            retained.add(rollback_version)
        self._prune_versions(retained)
        packages = [self._installed_package(item) for item in sorted(retained)]
        for package in packages:
            self._secure_tree(package.root)
        for package in packages:
            _verify_package(
                package.executable,
                version=str(package.manifest["version"]),
                expected_manifest_sha256=package.manifest_sha256,
            )
        if os.name == "nt":
            self.attest_protected_tree()

    def _commit_selection(
        self,
        package: _VerifiedPackage,
        *,
        version: str,
        previous_version: str | None,
    ) -> None:
        self._write_startup_launcher(package.executable)
        atomic_write_json(
            self.current_path,
            {
                "schema_version": 2,
                "version": version,
                "artifact_path": str(package.executable),
                "artifact_sha256": package.executable_sha256,
                "package_sha256": package.manifest_sha256,
                "previous_version": previous_version,
                "selected_at": _now(),
            },
        )

    def _result(
        self, package: _VerifiedPackage, version: str, previous: str | None
    ) -> HostInstallResult:
        return HostInstallResult(
            version,
            str(package.executable),
            package.executable_sha256,
            package.manifest_sha256,
            previous,
            str(self.startup_path),
        )

    def _write_startup_launcher(self, artifact: Path) -> None:
        self.startup_root.mkdir(parents=True, exist_ok=True)
        content = (
            "@echo off\r\n"
            f'"{artifact.resolve(strict=True)}" run '
            f'--config "{(self.state / "provider-host-enrollment.json").resolve()}"\r\n'
        ).encode("utf-8")
        _atomic_replace_bytes(self.startup_path, content)
        self._secure(self.startup_path)

    def _secure(self, path: Path) -> None:
        if os.name != "nt":
            path.chmod(0o700)
            return
        if self.owner_sid is None or not self.owner_sid.startswith("S-1-"):
            raise PermissionError("Provider Host owner SID is unavailable")
        apply_path_security(path, self._security_policy(path))

    def _security_policy(
        self, path: Path, *, inherited: bool = False
    ) -> dict[str, object]:
        if self.owner_sid is None or not self.owner_sid.startswith("S-1-"):
            raise PermissionError("Provider Host owner SID is unavailable")
        if self.authority_service_sid is None:
            raise PermissionError("KeeperAuthority service SID is unavailable")
        inheritance = (
            []
            if inherited
            else (["container_inherit", "object_inherit"] if path.is_dir() else [])
        )
        aces = [
            _host_ace("deny", _RESTRICTED_CODE_SID, inheritance),
            _host_ace("allow", "S-1-5-18", inheritance),
            _host_ace(
                "allow",
                self.authority_service_sid,
                inheritance,
                rights_mask=_FILE_READ_EXECUTE,
            ),
            _host_ace("allow", self.owner_sid, inheritance),
        ]
        if inherited:
            for ace in aces:
                ace["inherited"] = True
        return {
            "path": str(path.resolve(strict=True)),
            "dacl_protected": not inherited,
            "aces": aces,
            "mandatory_integrity": {
                "level": "medium",
                "trustee_sid": "S-1-16-8192",
                "policy_mask": 1,
                "policy_flags": ["no_write_up"],
                "inheritance_flags": inheritance,
                "propagation_flags": [],
                "inherited": inherited,
            },
        }

    def _clean_transaction_paths(self, transaction: dict[str, object]) -> None:
        for key in ("staging_path", "backup_path"):
            value = transaction.get(key)
            if not isinstance(value, str) or not value:
                continue
            path = Path(value)
            if path.exists():
                if _unsafe_tree(path, self.versions):
                    raise PermissionError("Provider Host transaction path is unsafe")
                shutil.rmtree(path)

    def _restore_transaction_backup(
        self, transaction: dict[str, object], version: str
    ) -> None:
        backup_value = transaction.get("backup_path")
        if not isinstance(backup_value, str):
            return
        backup = Path(backup_value)
        destination = self.versions / version
        if not backup.exists() or destination.exists():
            return
        if _unsafe_tree(backup, self.versions):
            raise PermissionError("Provider Host transaction backup path is unsafe")
        manifest_path = backup / _PACKAGE_MANIFEST
        backup_digest = _digest_file(manifest_path)
        _verify_package(
            backup / "KeeperProviderHost.exe",
            version=version,
            expected_manifest_sha256=backup_digest,
            require_defender=True,
        )
        os.replace(backup, destination)

    def _finish_program_removal(self) -> None:
        self.startup_path.unlink(missing_ok=True)
        if self.versions.exists():
            resolved = self.versions.resolve(strict=True)
            if resolved.parent != self.root:
                raise PermissionError("Provider Host versions root is not canonical")
            shutil.rmtree(resolved)
        self.current_path.unlink(missing_ok=True)

    def _prune_versions(self, retained: set[str]) -> None:
        if not self.versions.exists():
            return
        for child in self.versions.iterdir():
            if child.is_dir() and child.name not in retained:
                if _unsafe_tree(child, self.versions):
                    raise PermissionError("Provider Host version path is unsafe")
                shutil.rmtree(child)


def _verify_package(
    artifact: Path,
    *,
    version: str,
    expected_manifest_sha256: str,
    require_defender: bool = False,
) -> _VerifiedPackage:
    _validate_digest(expected_manifest_sha256)
    source = artifact.resolve(strict=True)
    if source.name.casefold() != "keeperproviderhost.exe" or source.read_bytes()[:2] != b"MZ":
        raise PermissionError("Provider Host requires a dedicated Windows executable")
    root = source.parent.resolve(strict=True)
    manifest_path = root / _PACKAGE_MANIFEST
    if _digest_file(manifest_path) != expected_manifest_sha256.casefold():
        raise PermissionError("Provider Host package manifest digest differs")
    manifest = _read_object(manifest_path)
    if set(manifest) != {"schema_version", "product", "version", "files"}:
        raise PermissionError("Provider Host package manifest is invalid")
    if (
        manifest.get("schema_version") != _PACKAGE_SCHEMA_VERSION
        or manifest.get("product") != _PACKAGE_PRODUCT
        or manifest.get("version") != version
    ):
        raise PermissionError("Provider Host package identity differs")
    files = _manifest_files(manifest)
    expected_paths: set[str] = set()
    executable_sha256: str | None = None
    for entry in files:
        relative_text = str(entry["path"])
        relative = PurePosixPath(relative_text)
        target = root.joinpath(*relative.parts)
        resolved = target.resolve(strict=True)
        if root not in resolved.parents or _is_link_or_reparse(target) or not target.is_file():
            raise PermissionError("Provider Host package path is unsafe")
        if target.stat().st_size != entry["size"] or _digest_file(target) != entry["sha256"]:
            raise PermissionError("Provider Host package file differs")
        expected_paths.add(relative_text)
        if relative_text.casefold() == "keeperproviderhost.exe":
            executable_sha256 = str(entry["sha256"])
    if executable_sha256 is None:
        raise PermissionError("Provider Host package executable is absent")
    actual_paths = _actual_package_paths(root)
    if actual_paths != expected_paths:
        raise PermissionError("Provider Host package file coverage differs")
    if require_defender:
        _verify_provider_host_with_defender(source, executable_sha256)
    return _VerifiedPackage(
        root,
        source,
        executable_sha256,
        expected_manifest_sha256.casefold(),
        manifest,
    )


def _verify_provider_host_with_defender(artifact: Path, expected_sha256: str) -> None:
    """Require a current Windows Defender scan before lifecycle mutation."""
    if os.name != "nt":
        raise PermissionError("Microsoft Defender release verification requires Windows")
    _validate_digest(expected_sha256)
    before = _digest_file(artifact)
    if before != expected_sha256.casefold():
        raise PermissionError("Provider Host digest differs before Defender scan")
    script = r'''
$ErrorActionPreference = "Stop"
$Path = [IO.Path]::GetFullPath($env:KEEPER_DEFENDER_ARTIFACT)
foreach ($Command in @("Get-MpComputerStatus", "Start-MpScan", "Get-MpThreatDetection")) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) { throw "Defender command unavailable" }
}
$Status = Get-MpComputerStatus
if (-not $Status.AntivirusEnabled -or -not $Status.RealTimeProtectionEnabled) { throw "Defender protection disabled" }
$Started = Get-Date
Start-MpScan -ScanType CustomScan -ScanPath $Path
if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "artifact quarantined" }
$Needle = $Path.ToLowerInvariant()
$Detections = @(Get-MpThreatDetection | Where-Object {
    $_.InitialDetectionTime -ge $Started.AddSeconds(-2) -and
    @($_.Resources | ForEach-Object { $_.ToString().ToLowerInvariant() } | Where-Object { $_ -like "*$Needle*" }).Count -gt 0
})
if ($Detections.Count -ne 0) { throw "artifact detected" }
[ordered]@{ engine = [string]$Status.AMEngineVersion; intelligence = [string]$Status.AntivirusSignatureVersion; result = "PASS" } | ConvertTo-Json -Compress
'''
    environment = dict(os.environ)
    environment["KEEPER_DEFENDER_ARTIFACT"] = str(artifact)
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PermissionError("Microsoft Defender release verification failed") from error
    if completed.returncode != 0:
        raise PermissionError("Microsoft Defender rejected the Provider Host artifact")
    try:
        result = json.loads(completed.stdout.strip())
    except (json.JSONDecodeError, TypeError) as error:
        raise PermissionError("Microsoft Defender verification response is invalid") from error
    if (
        not isinstance(result, dict)
        or result.get("result") != "PASS"
        or not isinstance(result.get("engine"), str)
        or not result.get("engine")
        or not isinstance(result.get("intelligence"), str)
        or not result.get("intelligence")
    ):
        raise PermissionError("Microsoft Defender verification response is invalid")
    try:
        after = _digest_file(artifact)
    except (FileNotFoundError, OSError) as error:
        raise PermissionError("Provider Host artifact was removed by Defender") from error
    if after != before:
        raise PermissionError("Provider Host artifact changed during Defender verification")


def _retained_rollback_version(
    current: dict[str, object] | None, version: str
) -> str | None:
    if current is None:
        return None
    current_version = str(current["version"])
    if current_version != version:
        return current_version
    previous = current.get("previous_version")
    if previous is None:
        return None
    if not isinstance(previous, str):
        raise PermissionError("Provider Host rollback generation is invalid")
    if previous == version:
        raise PermissionError(
            "Provider Host rollback generation matches current version"
        )
    return previous


def _manifest_files(manifest: dict[str, object]) -> list[dict[str, object]]:
    value = manifest.get("files")
    if not isinstance(value, list) or not value:
        raise PermissionError("Provider Host package file manifest is invalid")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise PermissionError("Provider Host package file entry is invalid")
        path = item.get("path")
        size = item.get("size")
        digest = item.get("sha256")
        if not isinstance(path, str) or not _safe_relative_path(path):
            raise PermissionError("Provider Host package relative path is invalid")
        if path.casefold() in seen:
            raise PermissionError("Provider Host package path is duplicated")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise PermissionError("Provider Host package file size is invalid")
        if not isinstance(digest, str):
            raise PermissionError("Provider Host package file digest is invalid")
        _validate_digest(digest)
        seen.add(path.casefold())
        result.append({"path": path, "size": size, "sha256": digest.casefold()})
    return result


def _actual_package_paths(root: Path) -> set[str]:
    actual: set[str] = set()
    for directory, directories, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        for name in directories:
            candidate = parent / name
            if _is_link_or_reparse(candidate):
                raise PermissionError("Provider Host package directory is unsafe")
        for name in files:
            candidate = parent / name
            if _is_link_or_reparse(candidate):
                raise PermissionError("Provider Host package file is unsafe")
            relative = candidate.relative_to(root).as_posix()
            if relative != _PACKAGE_MANIFEST:
                actual.add(relative)
    return actual


def _protected_tree_paths(root: Path) -> list[tuple[Path, bool]]:
    if not root.exists() or _is_link_or_reparse(root):
        raise PermissionError("Provider Host protected root is unavailable or aliased")
    resolved_root = root.resolve(strict=True)
    paths: list[tuple[Path, bool]] = [(resolved_root, False)]
    for directory, directories, files in os.walk(
        resolved_root, topdown=True, followlinks=False
    ):
        parent = Path(directory)
        if parent == resolved_root and "output" in directories:
            directories.remove("output")
        for name in [*directories, *files]:
            candidate = parent / name
            if _is_link_or_reparse(candidate):
                raise PermissionError("Provider Host protected tree contains an alias")
            resolved = candidate.resolve(strict=True)
            if resolved != resolved_root and resolved_root not in resolved.parents:
                raise PermissionError("Provider Host protected tree escapes its root")
            dynamic = (
                not candidate.is_dir()
                and (
                    parent == resolved_root
                    or resolved_root / "state" in candidate.parents
                    or resolved_root / "logs" in candidate.parents
                )
            )
            paths.append((resolved, dynamic))
    return paths


def _safe_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        value == path.as_posix()
        and not path.is_absolute()
        and len(path.parts) > 0
        and all(part not in {"", ".", ".."} for part in path.parts)
        and "\\" not in value
        and ":" not in value
        and value != _PACKAGE_MANIFEST
    )


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _unsafe_tree(path: Path, expected_parent: Path) -> bool:
    return (
        _is_link_or_reparse(path)
        or path.resolve(strict=True).parent != expected_parent.resolve(strict=True)
    )


def _atomic_replace_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    with temporary.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _host_ace(
    ace_type: str,
    sid: str,
    inheritance: list[str],
    *,
    rights_mask: int = _FILE_ALL_ACCESS,
) -> dict[str, object]:
    return {
        "ace_type": ace_type,
        "trustee_sid": sid,
        "rights_mask": rights_mask,
        "inheritance_flags": list(inheritance),
        "propagation_flags": [],
        "inherited": False,
    }


def ensure_provider_host_exchange_root(path: Path, *, owner_sid: str) -> str:
    """Create and attest the exact user-owned provider exchange root.

    The exchange root is deliberately outside the protected Host installation.
    Restricted provider tokens retain the enrolled user SID in their restricting
    set, so this exact owner allow permits traversal without weakening the
    installation tree's explicit Restricted Code deny.
    """

    if not path.is_absolute() or not owner_sid.startswith("S-1-"):
        raise PermissionError("Provider Host exchange root binding is invalid")
    lexical = Path(os.path.abspath(path))
    lexical.mkdir(mode=0o700, parents=True, exist_ok=True)
    _reject_path_aliases(lexical)
    canonical = lexical.resolve(strict=True)
    if os.path.normcase(str(canonical)) != os.path.normcase(str(lexical)):
        raise PermissionError("Provider Host exchange root is not canonical")
    if os.name == "nt":
        apply_path_security(canonical, _exchange_security_policy(canonical, owner_sid))
    else:
        canonical.chmod(0o700)
    return attest_provider_host_exchange_root(canonical, owner_sid=owner_sid)


def attest_provider_host_exchange_root(path: Path, *, owner_sid: str) -> str:
    """Verify the closed, owner-bound exchange-root policy without widening it."""

    if not path.is_absolute() or not owner_sid.startswith("S-1-"):
        raise PermissionError("Provider Host exchange root binding is invalid")
    lexical = Path(os.path.abspath(path))
    _reject_path_aliases(lexical)
    canonical = lexical.resolve(strict=True)
    if os.path.normcase(str(canonical)) != os.path.normcase(str(lexical)):
        raise PermissionError("Provider Host exchange root is not canonical")
    if os.name == "nt":
        expected = _exchange_security_policy(canonical, owner_sid)
        live = read_path_security(canonical)
        if (
            compare_path_security(expected, live)["result"] != "PASS"
            or read_path_owner_sid(canonical).casefold() != owner_sid.casefold()
        ):
            raise PermissionError("Provider Host exchange root security differs")
        evidence = {"owner_sid": owner_sid, "path": str(canonical), "security": live}
    else:
        if stat.S_IMODE(canonical.stat().st_mode) != 0o700:
            raise PermissionError("Provider Host exchange root security differs")
        evidence = {"owner_sid": owner_sid, "path": str(canonical), "mode": "0700"}
    return hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _exchange_security_policy(path: Path, owner_sid: str) -> dict[str, object]:
    inheritance = ["container_inherit", "object_inherit"]
    return {
        "path": str(path.resolve(strict=True)),
        "dacl_protected": True,
        "aces": [
            _host_ace("allow", _SYSTEM_SID, inheritance),
            _host_ace("allow", _ADMINISTRATORS_SID, inheritance),
            _host_ace("allow", owner_sid, inheritance),
        ],
        "mandatory_integrity": {
            "level": "medium",
            "trustee_sid": "S-1-16-8192",
            "policy_mask": 1,
            "policy_flags": ["no_write_up"],
            "inheritance_flags": inheritance,
            "propagation_flags": [],
            "inherited": False,
        },
    }


def _reject_path_aliases(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if _is_link_or_reparse(current):
            raise PermissionError("Provider Host exchange root contains an alias")


def _validate_digest(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdefABCDEF" for character in value):
        raise PermissionError("Provider Host package digest is invalid")


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("Provider Host lifecycle metadata is invalid") from error
    if not isinstance(value, dict):
        raise PermissionError("Provider Host lifecycle metadata is invalid")
    return value


def _validate_version(value: str) -> None:
    if (
        not value
        or len(value) > 64
        or any(character not in "0123456789.-_" for character in value)
        or value.startswith(".")
    ):
        raise ValueError("Provider Host version is invalid")


def _valid_utc_timestamp(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == UTC.utcoffset(parsed)


def _now() -> str:
    return datetime.now(UTC).isoformat()
