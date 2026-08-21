from __future__ import annotations

import hashlib
import json
import re
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from keeper.authority_service.protocol import PROTOCOL_VERSION, Request
from keeper.authority_service.provider_identity import account_sid
from keeper.authority_service.windows_security import (
    attest_authority_security,
)


AUDIT_REPORT_SCHEMA_VERSION = 1
AUDIT_REPORT_PURPOSE = "authority-provenance-report"
_RESULTS = {"PASS", "FAIL", "INDETERMINATE"}
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_HEX_40 = re.compile(r"[0-9a-f]{40}")
_REPORT_FIELDS = {
    "audit_report_schema_version",
    "kind",
    "audit_operation_id",
    "generated_at",
    "request_binding",
    "protocol_version",
    "installed_package_version",
    "package_source_provenance",
    "service",
    "identities",
    "machine_manifest",
    "configuration",
    "authority_key",
    "provider_credential_envelope",
    "database_schema",
    "package",
    "runtime_artifacts",
    "module_artifacts",
    "package_backups",
    "acl_policy",
    "artifact_results",
    "overall_result",
    "service_key_version",
    "authority_schema_version",
    "authority_key_id",
    "authenticated_writer_proof",
}


class AuthorityProvenanceReporter:
    """Build a fixed, non-secret report from service-owned canonical paths."""

    def __init__(
        self,
        service_root: Path,
        config_path: Path,
        *,
        identity_resolver: Callable[[str], str] = account_sid,
        security_attestor: Callable[..., dict[str, Any]] = (
            attest_authority_security
        ),
    ) -> None:
        self.service_root = service_root.resolve(strict=True)
        self.config_path = config_path.resolve()
        if self.config_path != self.service_root / "config" / "service.json":
            raise PermissionError("Authority Service config path is not canonical")
        self.manifest_path = (
            self.service_root / "audit" / "machine-artifacts.json"
        )
        self.package_path = (
            self.service_root / "bin" / "keeper-authority.pyz"
        )
        self.runtime_root = self.service_root / "bin" / "runtime"
        self.backup_root = self.service_root / "backups"
        self.credential_path = (
            self.service_root / "config" / "provider-identity.bin"
        )
        self._identity_resolver = identity_resolver
        self._security_attestor = security_attestor

    def build(
        self,
        request: Request,
        client_sid: str,
        *,
        installed_package_version: str,
        authority_key_id: str,
        authority_key_version: int,
        database_path: Path,
        database_identity: dict[str, Any] | None,
    ) -> dict[str, Any]:
        manifest_content = self.manifest_path.read_bytes()
        manifest = _json_object(manifest_content, "machine manifest")
        _validate_manifest(manifest)
        config_content: bytes | None
        config: dict[str, Any] | None
        try:
            config_content = self.config_path.read_bytes()
            config = _json_object(config_content, "service configuration")
        except (FileNotFoundError, OSError, PermissionError, ValueError):
            config_content = None
            config = None

        results: list[dict[str, str]] = []

        def record(artifact: str, result: str, detail: str) -> str:
            if result not in _RESULTS:
                raise ValueError("provenance result is invalid")
            results.append(
                {"artifact": artifact, "result": result, "detail": detail}
            )
            return result

        manifest_digest = hashlib.sha256(manifest_content).hexdigest()
        record(
            "machine_manifest",
            "PASS",
            "protected manifest parsed with the required schema",
        )
        source_commit = str(manifest["source_commit"])
        upgrades = manifest.get("upgrades")
        latest_upgrade = (
            upgrades[-1]
            if isinstance(upgrades, list)
            and upgrades
            and isinstance(upgrades[-1], dict)
            else None
        )
        latest_source = (
            str(latest_upgrade.get("source_commit"))
            if latest_upgrade is not None
            else ""
        )
        source_match = source_commit == latest_source
        source_result = record(
            "package_source_provenance",
            "PASS" if source_match else "FAIL",
            (
                "manifest and latest package upgrade identify the same commit"
                if source_match
                else "manifest and latest package upgrade commits differ"
            ),
        )

        package_identity = self._file_identity(
            self.package_path, manifest, immutable=True
        )
        package_digest = package_identity["sha256"]
        upgrade_package_value = (
            latest_upgrade.get("package_sha256")
            if latest_upgrade is not None
            else None
        )
        upgrade_package_digest = (
            upgrade_package_value.lower()
            if isinstance(upgrade_package_value, str)
            and re.fullmatch(r"[0-9A-Fa-f]{64}", upgrade_package_value)
            else None
        )
        if package_identity["result"] == "PASS":
            package_identity["result"] = (
                "PASS"
                if package_digest == upgrade_package_digest
                else "FAIL"
            )
            if package_identity["result"] == "FAIL":
                package_identity["reason"] = (
                    "installed package differs from latest upgrade provenance"
                )
        package_content_digest: str | None = None
        module_artifacts: list[dict[str, Any]] = []
        if package_identity["result"] != "INDETERMINATE":
            try:
                package_content_digest = package_content_sha256(
                    self.package_path
                )
                module_artifacts = package_module_artifacts(
                    self.package_path
                )
            except (OSError, ValueError, zipfile.BadZipFile):
                package_identity["result"] = "FAIL"
                package_identity["reason"] = "installed package is not readable"
                record(
                    "package_content",
                    "FAIL",
                    "installed package content could not be verified",
                )
            else:
                record(
                    "package_content",
                    "PASS",
                    "installed package has a canonical content digest",
                )
        else:
            record(
                "package_content",
                "INDETERMINATE",
                "installed package content is unavailable",
            )
        record(
            "installed_package",
            str(package_identity["result"]),
            str(package_identity["reason"]),
        )

        runtime_artifacts = [
            self._file_identity(path, manifest, immutable=True)
            for path in self._authoritative_runtime_paths()
        ]
        runtime_result = _aggregate(
            str(item["result"]) for item in runtime_artifacts
        )
        record(
            "python_runtime",
            runtime_result,
            "authoritative Python runtime artifacts compared with manifest",
        )

        config_identity = self._optional_identity(
            self.config_path, manifest, config_content
        )
        config_schema = (
            config.get("schema_version") if isinstance(config, dict) else None
        )
        if config_schema != 3 and config_identity["result"] == "PASS":
            config_identity["result"] = "FAIL"
            config_identity["reason"] = "configuration schema is incompatible"
        record(
            "service_configuration",
            str(config_identity["result"]),
            str(config_identity["reason"]),
        )

        credential_identity = self._file_identity(
            self.credential_path, manifest, immutable=True
        )
        configured_credential = (
            config.get("provider_credential_path")
            if isinstance(config, dict)
            else None
        )
        if (
            credential_identity["result"] == "PASS"
            and configured_credential != str(self.credential_path)
        ):
            credential_identity["result"] = "FAIL"
            credential_identity["reason"] = (
                "configured provider credential path is not canonical"
            )
        record(
            "provider_credential_envelope",
            str(credential_identity["result"]),
            str(credential_identity["reason"]),
        )

        key_path = (
            self.service_root
            / "data"
            / "keys"
            / f"key-v{authority_key_version}"
            / "authority"
            / "authority-key-v1.bin"
        )
        key_identity = self._file_identity(
            key_path, manifest, immutable=True
        )
        record(
            "authority_key_file",
            str(key_identity["result"]),
            str(key_identity["reason"]),
        )

        database = _database_report(database_path, database_identity)
        _require_service_child(database_path, self.service_root)
        record(
            "authority_database_schema",
            str(database["result"]),
            str(database["reason"]),
        )

        service_account = str(manifest["service_account"])
        provider_manifest = manifest.get("provider_identity")
        provider_account = (
            str(provider_manifest.get("account_name"))
            if isinstance(provider_manifest, dict)
            else ""
        )
        provider_recorded_sid = (
            str(provider_manifest.get("sid"))
            if isinstance(provider_manifest, dict)
            else ""
        )
        try:
            service_sid = self._identity_resolver(service_account)
            provider_sid = self._identity_resolver(provider_account)
        except (OSError, PermissionError, ValueError):
            service_sid = ""
            provider_sid = ""
        service_identity_result = record(
            "service_identity",
            "PASS" if service_sid.startswith("S-1-") else "INDETERMINATE",
            (
                "service virtual account SID resolved"
                if service_sid.startswith("S-1-")
                else "service virtual account SID could not be resolved"
            ),
        )
        provider_identity_result = record(
            "provider_identity",
            (
                "PASS"
                if provider_sid.startswith("S-1-")
                and provider_sid == provider_recorded_sid
                else "FAIL"
            ),
            (
                "provider account SID matches protected manifest"
                if provider_sid == provider_recorded_sid
                else "provider account SID differs from protected manifest"
            ),
        )

        backups = [
            self._file_identity(path, manifest, immutable=True)
            for path in sorted(self.backup_root.glob("*.pyz"))
        ]
        backup_result = _aggregate(
            str(item["result"]) for item in backups
        )
        record(
            "package_backups",
            backup_result,
            "installed package backups compared with manifest",
        )

        exchange_root = Path(
            str(
                config.get("allowed_evidence_root", "")
                if isinstance(config, dict)
                else ""
            )
        ).parent
        try:
            expected_exchange_root = (
                self.service_root.parent
                / "ClientExchange"
                / str(manifest["authorized_client_sid"]).replace("-", "_")
            )
            if exchange_root.resolve() != expected_exchange_root.resolve():
                raise PermissionError(
                    "configured client exchange root is not canonical"
                )
            acl_attestation = self._security_attestor(
                service_root=self.service_root,
                exchange_root=exchange_root,
                service_sid=service_sid,
                client_sid=str(manifest["authorized_client_sid"]),
                provider_sid=provider_sid,
            )
            acl_result_value = str(acl_attestation["result"])
            if acl_result_value not in _RESULTS:
                raise ValueError("live ACL attestation result is invalid")
        except (KeyError, OSError, PermissionError, RuntimeError, ValueError):
            acl_attestation = _unavailable_acl_attestation(
                self.service_root, exchange_root
            )
            acl_result_value = "INDETERMINATE"
        acl_result = record(
            "acl_policy",
            acl_result_value,
            (
                "live DACL and mandatory integrity descriptors match exactly"
                if acl_result_value == "PASS"
                else "live DACL or mandatory integrity verification did not pass"
            ),
        )

        service_executable = self.runtime_root / "python.exe"
        executable_identity = next(
            (
                item
                for item in runtime_artifacts
                if item["path"] == str(service_executable)
            ),
            self._file_identity(
                service_executable, manifest, immutable=True
            ),
        )
        image_path = str(manifest.get("service_image_path", ""))
        expected_image = (
            f'"{service_executable}" "{self.package_path}" service '
            f'--config "{self.config_path}"'
        )
        startup_result = record(
            "service_startup_configuration",
            "PASS" if image_path == expected_image else "FAIL",
            (
                "service image path matches canonical installation paths"
                if image_path == expected_image
                else "service image path differs from canonical installation paths"
            ),
        )

        overall = _aggregate(item["result"] for item in results)
        return {
            "audit_report_schema_version": AUDIT_REPORT_SCHEMA_VERSION,
            "kind": "authority_provenance_report",
            "audit_operation_id": request.operation_id,
            "generated_at": datetime.now(UTC).isoformat(),
            "request_binding": {
                "request_id": request.request_id,
                "operation_id": request.operation_id,
                "nonce_sha256": hashlib.sha256(
                    request.nonce.encode("ascii")
                ).hexdigest(),
                "issued_at": request.issued_at,
                "client_sid": client_sid,
            },
            "protocol_version": PROTOCOL_VERSION,
            "installed_package_version": installed_package_version,
            "package_source_provenance": {
                "installed_source_commit": source_commit,
                "latest_upgrade_source_commit": latest_source,
                "latest_upgrade_at": (
                    latest_upgrade.get("upgraded_at")
                    if latest_upgrade is not None
                    else None
                ),
                "source_commit_match": source_match,
                "result": source_result,
            },
            "service": {
                "name": str(manifest["service_name"]),
                "account_name": service_account,
                "account_sid": service_sid,
                "root_path": str(self.service_root),
                "executable_path": str(service_executable),
                "executable_sha256": executable_identity["sha256"],
                "binary_path": image_path,
                "startup_type": "demand",
                "result": _aggregate(
                    [
                        service_identity_result,
                        str(executable_identity["result"]),
                        startup_result,
                    ]
                ),
            },
            "identities": {
                "authorized_client_sid": str(
                    manifest["authorized_client_sid"]
                ),
                "provider_account_name": provider_account,
                "provider_account_sid": provider_sid,
                "provider_identity_result": provider_identity_result,
                "service_root_identity": service_sid,
            },
            "machine_manifest": {
                "path": str(self.manifest_path),
                "size": len(manifest_content),
                "sha256": manifest_digest,
                "schema_version": manifest["schema_version"],
                "result": "PASS",
            },
            "configuration": {
                **config_identity,
                "schema_version": config_schema,
            },
            "authority_key": {
                **key_identity,
                "key_id": authority_key_id,
                "key_version": authority_key_version,
            },
            "provider_credential_envelope": credential_identity,
            "database_schema": database,
            "package": {
                **package_identity,
                "content_sha256": package_content_digest,
            },
            "runtime_artifacts": runtime_artifacts,
            "module_artifacts": module_artifacts,
            "package_backups": backups,
            "acl_policy": {**acl_attestation, "result": acl_result},
            "artifact_results": results,
            "overall_result": overall,
        }

    def _authoritative_runtime_paths(self) -> list[Path]:
        if not self.runtime_root.is_dir():
            return [self.runtime_root / "python.exe"]
        return [
            path
            for path in sorted(self.runtime_root.rglob("*"))
            if path.is_file()
        ]

    def _optional_identity(
        self,
        path: Path,
        manifest: dict[str, Any],
        content: bytes | None,
    ) -> dict[str, Any]:
        if content is None:
            return _missing_identity(path)
        return _content_identity(path, content, manifest, immutable=True)

    def _file_identity(
        self,
        path: Path,
        manifest: dict[str, Any],
        *,
        immutable: bool,
    ) -> dict[str, Any]:
        _require_service_child(path, self.service_root)
        try:
            content = path.read_bytes()
        except (FileNotFoundError, OSError, PermissionError):
            return _missing_identity(path)
        return _content_identity(path, content, manifest, immutable=immutable)


def package_content_sha256(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        entries = [
            (name, archive.read(name))
            for name in sorted(archive.namelist())
            if not name.endswith("/")
        ]
    return _entries_digest(entries)


def source_package_content_sha256(source_root: Path) -> str:
    keeper_root = source_root.resolve(strict=True) / "keeper"
    if not keeper_root.is_dir():
        raise FileNotFoundError("candidate Keeper source is unavailable")
    entries: list[tuple[str, bytes]] = [
        (
            "__main__.py",
            b"from keeper.authority_service.service_main import main\n"
            b"raise SystemExit(main())\n",
        )
    ]
    entries.extend(
        (
            (Path("keeper") / path.relative_to(keeper_root)).as_posix(),
            path.read_bytes(),
        )
        for path in sorted(keeper_root.rglob("*.py"))
    )
    return _entries_digest(entries)


def package_module_artifacts(path: Path) -> list[dict[str, Any]]:
    with zipfile.ZipFile(path) as archive:
        return [
            {
                "path": name,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "result": "PASS",
            }
            for name in sorted(archive.namelist())
            if name.startswith("keeper/authority_service/")
            and name.endswith(".py")
            and not name.endswith("/")
            for content in [archive.read(name)]
        ]


def validate_provenance_report(report: object, request: Request) -> dict[str, Any]:
    if not isinstance(report, dict) or set(report) != _REPORT_FIELDS:
        raise RuntimeError("Authority provenance report fields are invalid")
    if (
        report.get("audit_report_schema_version")
        != AUDIT_REPORT_SCHEMA_VERSION
        or report.get("kind") != "authority_provenance_report"
        or report.get("protocol_version") != PROTOCOL_VERSION
        or report.get("audit_operation_id") != request.operation_id
        or report.get("overall_result") not in _RESULTS
    ):
        raise RuntimeError("Authority provenance report identity is invalid")
    binding = report.get("request_binding")
    if not isinstance(binding, dict) or set(binding) != {
        "request_id",
        "operation_id",
        "nonce_sha256",
        "issued_at",
        "client_sid",
    }:
        raise RuntimeError("Authority provenance request binding is invalid")
    if (
        binding.get("request_id") != request.request_id
        or binding.get("operation_id") != request.operation_id
        or binding.get("issued_at") != request.issued_at
        or binding.get("nonce_sha256")
        != hashlib.sha256(request.nonce.encode("ascii")).hexdigest()
    ):
        raise RuntimeError("Authority provenance response replay was rejected")
    _fresh_report_timestamp(report.get("generated_at"))
    _validate_signed_fields(report)
    _validate_report_schema(report)
    _validate_no_secret_fields(report)
    artifacts = report.get("artifact_results")
    if not isinstance(artifacts, list) or not artifacts:
        raise RuntimeError("Authority provenance artifact results are invalid")
    for item in artifacts:
        if (
            not isinstance(item, dict)
            or set(item) != {"artifact", "result", "detail"}
            or not isinstance(item.get("artifact"), str)
            or item.get("result") not in _RESULTS
            or not isinstance(item.get("detail"), str)
        ):
            raise RuntimeError(
                "Authority provenance artifact result is invalid"
            )
    return report


def _validate_report_schema(report: dict[str, Any]) -> None:
    _exact_object(
        report["package_source_provenance"],
        {
            "installed_source_commit",
            "latest_upgrade_source_commit",
            "latest_upgrade_at",
            "source_commit_match",
            "result",
        },
        "package source provenance",
    )
    _exact_object(
        report["service"],
        {
            "name",
            "account_name",
            "account_sid",
            "root_path",
            "executable_path",
            "executable_sha256",
            "binary_path",
            "startup_type",
            "result",
        },
        "service identity",
    )
    _exact_object(
        report["identities"],
        {
            "authorized_client_sid",
            "provider_account_name",
            "provider_account_sid",
            "provider_identity_result",
            "service_root_identity",
        },
        "Windows identities",
    )
    _exact_object(
        report["machine_manifest"],
        {"path", "size", "sha256", "schema_version", "result"},
        "machine manifest",
    )
    _exact_object(
        report["configuration"],
        _FILE_IDENTITY_FIELDS | {"schema_version"},
        "configuration",
    )
    _exact_object(
        report["authority_key"],
        _FILE_IDENTITY_FIELDS | {"key_id", "key_version"},
        "authority key",
    )
    _exact_object(
        report["provider_credential_envelope"],
        _FILE_IDENTITY_FIELDS,
        "provider credential envelope",
    )
    _exact_object(
        report["database_schema"],
        {
            "path",
            "mutable",
            "file_sha256",
            "schema_version",
            "schema_sha256",
            "table_names_sha256",
            "journal_mode",
            "result",
            "reason",
        },
        "database schema",
    )
    _exact_object(
        report["package"],
        _FILE_IDENTITY_FIELDS | {"content_sha256"},
        "installed package",
    )
    for label in ("runtime_artifacts", "package_backups"):
        values = report[label]
        if not isinstance(values, list):
            raise RuntimeError(f"Authority provenance {label} is invalid")
        for item in values:
            _exact_object(item, _FILE_IDENTITY_FIELDS, label)
    modules = report["module_artifacts"]
    if not isinstance(modules, list):
        raise RuntimeError("Authority provenance module artifacts are invalid")
    for item in modules:
        _exact_object(
            item, {"path", "size", "sha256", "result"}, "module artifact"
        )
    acl = report["acl_policy"]
    _exact_object(
        acl,
        {
            "schema_version",
            "expected_policy",
            "expected_policy_sha256",
            "live_policy",
            "live_policy_sha256",
            "paths",
            "result",
        },
        "ACL policy",
    )
    _validate_acl_attestation(acl)
    if (
        not isinstance(report["installed_package_version"], str)
        or not _HEX_40.fullmatch(
            str(
                report["package_source_provenance"][
                    "installed_source_commit"
                ]
            )
        )
        or report["package_source_provenance"]["result"] not in _RESULTS
        or report["service"]["result"] not in _RESULTS
        or report["identities"]["provider_identity_result"] not in _RESULTS
        or report["database_schema"]["mutable"] is not True
        or report["database_schema"]["file_sha256"] is not None
        or report["database_schema"]["result"] not in _RESULTS
        or report["acl_policy"]["result"] not in _RESULTS
    ):
        raise RuntimeError("Authority provenance report values are invalid")
    for identity in (
        report["configuration"],
        report["authority_key"],
        report["provider_credential_envelope"],
        report["package"],
        *report["runtime_artifacts"],
        *report["package_backups"],
    ):
        if identity["result"] not in _RESULTS:
            raise RuntimeError(
                "Authority provenance artifact identity is invalid"
            )
    for module in report["module_artifacts"]:
        if module["result"] not in _RESULTS:
            raise RuntimeError("Authority provenance module identity is invalid")


def _validate_acl_attestation(acl: dict[str, Any]) -> None:
    if (
        acl.get("schema_version") != 1
        or acl.get("result") not in _RESULTS
    ):
        raise RuntimeError("Authority live ACL result is invalid")
    expected = acl["expected_policy"]
    _exact_object(
        expected,
        {"schema_version", "service_root", "client_exchange"},
        "expected ACL policy",
    )
    paths = acl["paths"]
    live_policy = acl["live_policy"]
    _exact_object(
        paths, {"service_root", "client_exchange"}, "live ACL paths"
    )
    _exact_object(
        live_policy,
        {"service_root", "client_exchange"},
        "live ACL policy",
    )
    for name in ("service_root", "client_exchange"):
        _validate_path_policy(expected[name], f"expected {name}")
        item = paths[name]
        base_fields = {
            "expected",
            "live",
            "unexpected_aces",
            "missing_aces",
            "excessive_rights",
            "incorrect_inheritance",
            "duplicate_trustees",
            "integrity_mismatches",
            "result",
        }
        fields = (
            base_fields | {"unavailable_reason"}
            if isinstance(item, dict) and item.get("result") == "INDETERMINATE"
            else base_fields
        )
        _exact_object(item, fields, f"{name} ACL attestation")
        if item["result"] not in _RESULTS:
            raise RuntimeError("Authority path ACL result is invalid")
        if item["live"] is not None:
            _validate_live_path_policy(item["live"], f"live {name}")
        for collection in (
            "unexpected_aces",
            "missing_aces",
            "excessive_rights",
        ):
            values = item[collection]
            if not isinstance(values, list):
                raise RuntimeError("Authority ACL differences are invalid")
            for ace in values:
                _validate_ace(ace, "ACL difference")
        for collection in (
            "incorrect_inheritance",
            "duplicate_trustees",
            "integrity_mismatches",
        ):
            if not isinstance(item[collection], list) or not all(
                isinstance(value, str) for value in item[collection]
            ):
                raise RuntimeError("Authority ACL findings are invalid")


def _validate_path_policy(value: object, label: str) -> None:
    item = _exact_object(
        value,
        {"path", "dacl_protected", "aces", "mandatory_integrity"},
        label,
    )
    if not isinstance(item["aces"], list):
        raise RuntimeError("Authority ACL ACE collection is invalid")
    for ace in item["aces"]:
        _validate_ace(ace, label)
    _validate_integrity(item["mandatory_integrity"], label)


def _validate_live_path_policy(value: object, label: str) -> None:
    item = _exact_object(
        value,
        {
            "path",
            "dacl_protected",
            "aces",
            "mandatory_integrity",
            "mandatory_label_count",
        },
        label,
    )
    if not isinstance(item["aces"], list):
        raise RuntimeError("Authority live ACL ACE collection is invalid")
    for ace in item["aces"]:
        _validate_ace(ace, label)
    if item["mandatory_integrity"] is not None:
        _validate_integrity(item["mandatory_integrity"], label)


def _validate_ace(value: object, label: str) -> None:
    _exact_object(
        value,
        {
            "ace_type",
            "trustee_sid",
            "rights_mask",
            "inheritance_flags",
            "propagation_flags",
            "inherited",
        },
        label,
    )


def _validate_integrity(value: object, label: str) -> None:
    _exact_object(
        value,
        {
            "level",
            "trustee_sid",
            "policy_mask",
            "policy_flags",
            "inheritance_flags",
            "propagation_flags",
            "inherited",
        },
        label,
    )


_FILE_IDENTITY_FIELDS = {
    "path",
    "size",
    "sha256",
    "immutable",
    "manifest_match",
    "result",
    "reason",
}


def _exact_object(
    value: object, fields: set[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeError(f"Authority provenance {label} fields are invalid")
    return value


def _database_report(
    path: Path, identity: dict[str, Any] | None
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "path": str(path.resolve()),
        "mutable": True,
        "file_sha256": None,
        "schema_version": None,
        "schema_sha256": None,
        "table_names_sha256": None,
        "journal_mode": None,
        "result": "INDETERMINATE",
        "reason": "database schema identity is unavailable",
    }
    if identity is None:
        return fields
    fields.update(
        {
            "schema_version": identity.get("schema_version"),
            "schema_sha256": identity.get("schema_sha256"),
            "table_names_sha256": identity.get("table_names_sha256"),
            "journal_mode": identity.get("journal_mode"),
            "result": (
                "PASS"
                if identity.get("schema_matches_expected") is True
                else "FAIL"
            ),
            "reason": (
                "mutable database schema and WAL identities match"
                if identity.get("schema_matches_expected") is True
                else "mutable database schema or journal identity differs"
            ),
        }
    )
    return fields


def _content_identity(
    path: Path,
    content: bytes,
    manifest: dict[str, Any],
    *,
    immutable: bool,
) -> dict[str, Any]:
    digest = hashlib.sha256(content).hexdigest()
    resolved = str(path.resolve())
    matched = any(
        isinstance(item, dict)
        and item.get("path") == resolved
        and item.get("size") == len(content)
        and item.get("sha256") == digest
        for item in manifest.get("artifacts", [])
    )
    return {
        "path": resolved,
        "size": len(content),
        "sha256": digest,
        "immutable": immutable,
        "manifest_match": matched,
        "result": "PASS" if matched else "FAIL",
        "reason": (
            "artifact matches protected manifest"
            if matched
            else "artifact differs from protected manifest"
        ),
    }


def _missing_identity(path: Path) -> dict[str, Any]:
    return {
        "path": str(path.resolve()),
        "size": None,
        "sha256": None,
        "immutable": True,
        "manifest_match": False,
        "result": "INDETERMINATE",
        "reason": "artifact is missing or unreadable",
    }


def _unavailable_acl_attestation(
    service_root: Path, exchange_root: Path
) -> dict[str, Any]:
    empty_policy = {
        "schema_version": 1,
        "service_root": {
            "path": str(service_root.resolve()),
            "dacl_protected": True,
            "aces": [],
            "mandatory_integrity": {
                "level": "unknown",
                "trustee_sid": "S-1-16-0",
                "policy_mask": 1,
                "policy_flags": ["no_write_up"],
                "inheritance_flags": [],
                "propagation_flags": [],
                "inherited": False,
            },
        },
        "client_exchange": {
            "path": str(exchange_root.resolve()),
            "dacl_protected": True,
            "aces": [],
            "mandatory_integrity": {
                "level": "unknown",
                "trustee_sid": "S-1-16-0",
                "policy_mask": 1,
                "policy_flags": ["no_write_up"],
                "inheritance_flags": [],
                "propagation_flags": [],
                "inherited": False,
            },
        },
    }
    paths = {
        name: {
            "expected": empty_policy[name],
            "live": None,
            "unexpected_aces": [],
            "missing_aces": [],
            "excessive_rights": [],
            "incorrect_inheritance": [],
            "duplicate_trustees": [],
            "integrity_mismatches": [],
            "unavailable_reason": "LiveSecurityDescriptorUnavailable",
            "result": "INDETERMINATE",
        }
        for name in ("service_root", "client_exchange")
    }
    return {
        "schema_version": 1,
        "expected_policy": empty_policy,
        "expected_policy_sha256": None,
        "live_policy": {
            "service_root": None,
            "client_exchange": None,
        },
        "live_policy_sha256": None,
        "paths": paths,
        "result": "INDETERMINATE",
    }


def _entries_digest(entries: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    for name, content in entries:
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def _aggregate(results: Any) -> str:
    values = list(results)
    if any(value == "FAIL" for value in values):
        return "FAIL"
    if any(value == "INDETERMINATE" for value in values):
        return "INDETERMINATE"
    return "PASS"


def _json_object(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PermissionError(f"Authority {label} is invalid") from error
    if not isinstance(value, dict):
        raise PermissionError(f"Authority {label} is invalid")
    return value


def _validate_manifest(manifest: dict[str, Any]) -> None:
    if (
        manifest.get("schema_version") != 1
        or manifest.get("service_name") != "KeeperAuthority"
        or manifest.get("service_account")
        != r"NT SERVICE\KeeperAuthority"
        or not isinstance(manifest.get("authorized_client_sid"), str)
        or not _HEX_40.fullmatch(str(manifest.get("source_commit", "")))
        or not isinstance(manifest.get("artifacts"), list)
        or not isinstance(manifest.get("commands"), list)
        or not isinstance(manifest.get("upgrades"), list)
        or not isinstance(manifest.get("provider_identity"), dict)
        or not isinstance(manifest.get("service_image_path"), str)
    ):
        raise PermissionError("Authority machine manifest schema is invalid")


def _require_service_child(path: Path, service_root: Path) -> None:
    resolved = path.resolve()
    if not resolved.is_relative_to(service_root):
        raise PermissionError("provenance artifact path is outside service root")


def _fresh_report_timestamp(value: object) -> None:
    if not isinstance(value, str):
        raise RuntimeError("Authority provenance timestamp is invalid")
    try:
        generated = datetime.fromisoformat(value)
    except ValueError as error:
        raise RuntimeError(
            "Authority provenance timestamp is invalid"
        ) from error
    now = datetime.now(UTC)
    if (
        generated.tzinfo is None
        or generated < now - timedelta(seconds=60)
        or generated > now + timedelta(seconds=10)
    ):
        raise RuntimeError("Authority provenance report is stale")


def _validate_signed_fields(report: dict[str, Any]) -> None:
    if (
        not isinstance(report.get("service_key_version"), int)
        or report["service_key_version"] <= 0
        or not isinstance(report.get("authority_schema_version"), int)
        or not isinstance(report.get("authority_key_id"), str)
        or not _HEX_64.fullmatch(
            str(report.get("authenticated_writer_proof", ""))
        )
    ):
        raise RuntimeError("Authority provenance authentication is invalid")


def _validate_no_secret_fields(value: object) -> None:
    forbidden = {
        "key_material",
        "password",
        "plaintext",
        "token",
        "database_content",
        "manifest_content",
        "credential_content",
    }
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).casefold() in forbidden:
                raise RuntimeError(
                    "Authority provenance report exposes forbidden data"
                )
            _validate_no_secret_fields(item)
    elif isinstance(value, list):
        for item in value:
            _validate_no_secret_fields(item)
