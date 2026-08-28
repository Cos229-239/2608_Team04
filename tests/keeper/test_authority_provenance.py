from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from keeper.authority_service.client import AuthorityServiceClient
from keeper.authority_service import service_install
from keeper.authority_service.core import AuthorityServiceCore
from keeper.authority_service.protocol import Operation, Request
from keeper.authority_service.provenance import (
    AUDIT_REPORT_PURPOSE,
    AuthorityProvenanceReporter,
    validate_provenance_report,
)
from keeper.authority_service.windows_security import (
    compare_path_security,
    expected_authority_security,
)


_CLIENT_SID = "S-1-5-21-1000"
_SERVICE_SID = "S-1-5-80-12345"
_PROVIDER_SID = "S-1-5-21-2000"
_SERVICE_ACCOUNT = r"NT SERVICE\KeeperAuthority"
_PROVIDER_ACCOUNT = r".\KeeperProvider"
_SOURCE_COMMIT = "a" * 40


def test_release_source_identity_supports_fresh_machine_install(tmp_path: Path) -> None:
    (tmp_path / "keeper-release-source.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_commit": _SOURCE_COMMIT,
                "source_tree": "b" * 40,
            }
        ),
        encoding="utf-8",
    )

    assert service_install._git_head(tmp_path) == _SOURCE_COMMIT


def test_release_source_identity_fails_closed_when_malformed(tmp_path: Path) -> None:
    (tmp_path / "keeper-release-source.json").write_text(
        '{"schema_version":1,"source_commit":"not-a-commit","source_tree":"bad"}',
        encoding="utf-8",
    )

    with pytest.raises(PermissionError, match="release source identity"):
        service_install._git_head(tmp_path)


def _installation(
    tmp_path: Path,
) -> tuple[
    AuthorityServiceCore,
    AuthorityServiceClient,
    Path,
    Path,
    Path,
]:
    service_root = tmp_path / "AuthorityService"
    exchange_root = (
        tmp_path / "ClientExchange" / _CLIENT_SID.replace("-", "_")
    )
    for directory in (
        service_root / "bin" / "runtime",
        service_root / "config",
        service_root / "data",
        service_root / "audit",
        service_root / "backups",
        exchange_root / "evidence",
    ):
        directory.mkdir(parents=True, exist_ok=True)

    package = service_root / "bin" / "keeper-authority.pyz"
    candidate_root = tmp_path / "candidate"
    candidate_module = (
        candidate_root
        / "keeper"
        / "authority_service"
        / "service_main.py"
    )
    candidate_module.parent.mkdir(parents=True, exist_ok=True)
    module_content = b"SERVICE_NAME = 'KeeperAuthority'\n"
    candidate_module.write_bytes(module_content)
    with zipfile.ZipFile(
        package, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr(
            "__main__.py",
            "from keeper.authority_service.service_main import main\n"
            "raise SystemExit(main())\n",
        )
        archive.writestr(
            "keeper/authority_service/service_main.py",
            module_content,
        )
    runtime = service_root / "bin" / "runtime" / "python.exe"
    runtime.write_bytes(b"test-python-runtime")
    credential = service_root / "config" / "provider-identity.bin"
    credential.write_bytes(b"TEST-CREDENTIAL-ENVELOPE-SECRET")
    config_path = service_root / "config" / "service.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "service_name": "KeeperAuthority",
                "service_root": str(service_root / "data"),
                "provider_root": str(exchange_root / "provider-work"),
                "allowed_evidence_root": str(exchange_root / "evidence"),
                "authorized_client_sid": _CLIENT_SID,
                "provider_account_name": _PROVIDER_ACCOUNT,
                "provider_credential_path": str(credential),
                "pipe_name": r"\\.\pipe\KeeperAuthority-test",
                "founder_capability_verifier": {
                    "schema_version": 1,
                    "issuer_id": "keeper-founder:S-1-5-21-1000",
                    "principal_sid": "S-1-5-21-1000",
                    "key_id": "keeper-founder-rsa:test",
                    "algorithm": "RS256-CNG-HIGH-PROTECTION",
                    "modulus": "g" + "A" * 341,
                    "exponent": "AQAB",
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    core = AuthorityServiceCore(service_root / "data")
    key_path = (
        service_root
        / "data"
        / "keys"
        / "key-v1"
        / "authority"
        / "authority-key-v1.bin"
    )
    artifacts = [
        _artifact(path)
        for path in (package, runtime, credential, config_path, key_path)
    ]
    package_digest = hashlib.sha256(package.read_bytes()).hexdigest()
    service_image = (
        f'"{runtime}" "{package}" service --config "{config_path}"'
    )
    manifest_path = (
        service_root / "audit" / "machine-artifacts.json"
    )
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "service_name": "KeeperAuthority",
                "service_account": _SERVICE_ACCOUNT,
                "authorized_client_sid": _CLIENT_SID,
                "source_commit": _SOURCE_COMMIT,
                "artifacts": artifacts,
                "commands": _acl_commands(service_root, exchange_root),
                "upgrades": [
                    {
                        "upgraded_at": "2026-07-27T00:00:00+00:00",
                        "package_sha256": package_digest,
                        "source_commit": _SOURCE_COMMIT,
                    }
                ],
                "provider_identity": {
                    "account_name": _PROVIDER_ACCOUNT,
                    "sid": _PROVIDER_SID,
                },
                "service_image_path": service_image,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    reporter = AuthorityProvenanceReporter(
        service_root,
        config_path,
        identity_resolver=lambda account: {
            _SERVICE_ACCOUNT: _SERVICE_SID,
            _PROVIDER_ACCOUNT: _PROVIDER_SID,
        }[account],
        security_attestor=_passing_security_attestor,
    )
    core.provenance_reporter = reporter
    client = AuthorityServiceClient(
        test_transport=lambda request: core.dispatch(request, _CLIENT_SID)
    )
    return core, client, manifest_path, package, credential


def _artifact(path: Path) -> dict[str, Any]:
    content = path.read_bytes()
    return {
        "kind": "file",
        "path": str(path.resolve()),
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _acl_commands(
    service_root: Path, exchange_root: Path
) -> list[dict[str, Any]]:
    return [
        {
            "arguments": [
                "icacls",
                str(service_root),
                "/inheritance:r",
                "/grant:r",
                "SYSTEM:(OI)(CI)F",
                "BUILTIN\\Administrators:(OI)(CI)F",
                rf"{_SERVICE_ACCOUNT}:(OI)(CI)F",
            ],
            "exit_code": 0,
        },
        {
            "arguments": [
                "icacls",
                str(exchange_root),
                "/inheritance:r",
                "/grant:r",
                "SYSTEM:(OI)(CI)F",
                "BUILTIN\\Administrators:(OI)(CI)F",
                rf"{_SERVICE_ACCOUNT}:(OI)(CI)M",
                f"*{_CLIENT_SID}:(OI)(CI)M",
                f"*{_PROVIDER_SID}:(OI)(CI)M",
                "*S-1-5-12:(OI)(CI)M",
            ],
            "exit_code": 0,
        },
        {
            "arguments": [
                "icacls",
                str(exchange_root),
                "/setintegritylevel",
                "(OI)(CI)L",
            ],
            "exit_code": 0,
        },
    ]


def _passing_security_attestor(**arguments: Any) -> dict[str, Any]:
    expected = expected_authority_security(**arguments)
    paths: dict[str, Any] = {}
    live_policy: dict[str, Any] = {}
    for name in ("service_root", "client_exchange"):
        live = {
            **copy.deepcopy(expected[name]),
            "mandatory_label_count": 1,
        }
        paths[name] = compare_path_security(expected[name], live)
        live_policy[name] = live
    expected_digest = hashlib.sha256(
        json.dumps(
            expected, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    live_digest = hashlib.sha256(
        json.dumps(
            live_policy, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": 1,
        "expected_policy": expected,
        "expected_policy_sha256": expected_digest,
        "live_policy": live_policy,
        "live_policy_sha256": live_digest,
        "paths": paths,
        "result": "PASS",
    }


def _failing_security_attestor(**arguments: Any) -> dict[str, Any]:
    value = _passing_security_attestor(**arguments)
    service = value["live_policy"]["service_root"]
    service["aces"].append(
        {
            "ace_type": "allow",
            "trustee_sid": "S-1-1-0",
            "rights_mask": 0x001F01FF,
            "inheritance_flags": [
                "container_inherit",
                "object_inherit",
            ],
            "propagation_flags": [],
            "inherited": False,
        }
    )
    value["paths"]["service_root"] = compare_path_security(
        value["expected_policy"]["service_root"], service
    )
    value["live_policy_sha256"] = hashlib.sha256(
        json.dumps(
            value["live_policy"],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    value["result"] = "FAIL"
    return value


def test_authenticated_provenance_passes_without_exposing_secrets(
    tmp_path: Path,
) -> None:
    core, client, _manifest, _package, _credential = _installation(
        tmp_path
    )
    database_secret = "RAW-DATABASE-CONTENT-MUST-NOT-LEAK"
    core.store.audit(
        "f" * 32,
        "secret-test",
        _CLIENT_SID,
        None,
        {"value": database_secret},
    )
    raw_key = core.keys._key(1)._key.hex()

    report = client.audit_provenance()
    serialized = json.dumps(report, sort_keys=True)

    assert report["overall_result"] == "PASS"
    assert client.verify(AUDIT_REPORT_PURPOSE, report) is True
    assert report["database_schema"]["mutable"] is True
    assert report["database_schema"]["file_sha256"] is None
    assert raw_key not in serialized
    assert "TEST-CREDENTIAL-ENVELOPE-SECRET" not in serialized
    assert database_secret not in serialized


def test_provenance_accepts_canonical_uppercase_upgrade_digest(
    tmp_path: Path,
) -> None:
    _core, client, manifest_path, package, _credential = _installation(
        tmp_path
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["upgrades"][-1]["package_sha256"] = hashlib.sha256(
        package.read_bytes()
    ).hexdigest().upper()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = client.audit_provenance()

    assert report["package"]["result"] == "PASS"
    assert report["overall_result"] == "PASS"


@pytest.mark.parametrize(
    "recorded_digest",
    ["0" * 64, "not-a-digest", 12345, None],
)
def test_provenance_rejects_nonmatching_or_malformed_upgrade_digest(
    tmp_path: Path, recorded_digest: object
) -> None:
    _core, client, manifest_path, _package, _credential = _installation(
        tmp_path
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["upgrades"][-1]["package_sha256"] = recorded_digest
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = client.audit_provenance()

    assert report["package"]["result"] == "FAIL"
    assert report["overall_result"] == "FAIL"


def test_provenance_rejects_paths_unknown_fields_replay_and_tampering(
    tmp_path: Path,
) -> None:
    core, client, _manifest, _package, _credential = _installation(
        tmp_path
    )
    with pytest.raises(ValueError, match="fields"):
        core.dispatch(
            Request.create(
                Operation.AUDIT_PROVENANCE,
                {"path": str(tmp_path / "attacker-selected")},
            ),
            _CLIENT_SID,
        )

    request = Request.create(Operation.AUDIT_PROVENANCE, {})
    report = client._send(request)["report"]
    with pytest.raises(PermissionError, match="replay"):
        core.dispatch(request, _CLIENT_SID)

    other_request = Request.create(Operation.AUDIT_PROVENANCE, {})
    with pytest.raises(RuntimeError, match="identity|replay"):
        validate_provenance_report(report, other_request)

    unknown = copy.deepcopy(report)
    unknown["service"]["unexpected"] = True
    with pytest.raises(RuntimeError, match="fields"):
        validate_provenance_report(unknown, request)

    tampered = copy.deepcopy(report)
    tampered["package"]["sha256"] = "0" * 64
    assert client.verify(AUDIT_REPORT_PURPOSE, tampered) is False


def test_provenance_reports_manifest_package_and_missing_artifact_failures(
    tmp_path: Path,
) -> None:
    _core, client, manifest_path, package, credential = _installation(
        tmp_path
    )
    package.write_bytes(b"tampered-not-a-zip")
    report = client.audit_provenance()
    assert report["overall_result"] == "FAIL"
    assert report["package"]["result"] == "FAIL"

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_commit"] = "b" * 40
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    report = client.audit_provenance()
    assert report["package_source_provenance"]["result"] == "FAIL"

    credential.unlink()
    report = client.audit_provenance()
    assert report["provider_credential_envelope"]["result"] == (
        "INDETERMINATE"
    )
    assert report["database_schema"]["mutable"] is True
    assert report["database_schema"]["file_sha256"] is None
    assert report["overall_result"] == "FAIL"


def test_manifest_artifact_mutation_produces_failure(
    tmp_path: Path,
) -> None:
    _core, client, manifest_path, package, _credential = _installation(
        tmp_path
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        if artifact.get("path") == str(package.resolve()):
            artifact["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = client.audit_provenance()

    assert report["package"]["manifest_match"] is False
    assert report["package"]["result"] == "FAIL"
    assert report["overall_result"] == "FAIL"


def test_successful_acl_command_history_cannot_override_live_failure(
    tmp_path: Path,
) -> None:
    core, client, manifest_path, _package, _credential = _installation(
        tmp_path
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert all(item["exit_code"] == 0 for item in manifest["commands"])
    reporter = core.provenance_reporter
    assert isinstance(reporter, AuthorityProvenanceReporter)
    reporter._security_attestor = _failing_security_attestor

    report = client.audit_provenance()

    assert report["acl_policy"]["result"] == "FAIL"
    assert report["acl_policy"]["paths"]["service_root"][
        "unexpected_aces"
    ]
    assert report["overall_result"] == "FAIL"


def test_acl_mutation_after_prior_pass_is_detected(tmp_path: Path) -> None:
    core, client, _manifest, _package, _credential = _installation(
        tmp_path
    )
    assert client.audit_provenance()["acl_policy"]["result"] == "PASS"
    reporter = core.provenance_reporter
    assert isinstance(reporter, AuthorityProvenanceReporter)
    reporter._security_attestor = _failing_security_attestor

    mutated = client.audit_provenance()

    assert mutated["acl_policy"]["result"] == "FAIL"
    assert mutated["overall_result"] == "FAIL"


def test_unavailable_live_descriptor_is_indeterminate(
    tmp_path: Path,
) -> None:
    core, client, _manifest, _package, _credential = _installation(
        tmp_path
    )
    reporter = core.provenance_reporter
    assert isinstance(reporter, AuthorityProvenanceReporter)

    def unavailable(**_arguments: Any) -> dict[str, Any]:
        raise PermissionError("live descriptor unavailable")

    reporter._security_attestor = unavailable
    report = client.audit_provenance()

    assert report["acl_policy"]["result"] == "INDETERMINATE"
    assert report["overall_result"] == "INDETERMINATE"


def test_auditor_rejects_invalid_report_authentication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _core, client, _manifest, _package, _credential = _installation(
        tmp_path
    )
    monkeypatch.setattr(
        client, "verify", lambda _purpose, _report: False
    )
    module = _audit_script_module()

    with pytest.raises(PermissionError, match="authentication"):
        module.verify_live_provenance(
            expected_source_commit=_SOURCE_COMMIT,
            source_root=tmp_path,
            client=client,
            service_query=lambda: {},
            protected_read_denied=lambda _path: True,
        )


def test_auditor_rejects_wrong_installed_commit(tmp_path: Path) -> None:
    _core, client, _manifest, _package, _credential = _installation(
        tmp_path
    )
    module = _audit_script_module()
    with pytest.raises(PermissionError, match="commit differs"):
        module.verify_live_provenance(
            expected_source_commit="b" * 40,
            source_root=tmp_path,
            client=client,
            service_query=lambda: {},
            protected_read_denied=lambda _path: True,
        )


def test_valid_candidate_produces_verifiable_auditor_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _core, client, _manifest, package, _credential = _installation(
        tmp_path
    )
    module = _audit_script_module()
    monkeypatch.setattr(
        module, "_git_head", lambda _source_root: _SOURCE_COMMIT
    )
    service_root = package.parent.parent
    runtime = service_root / "bin" / "runtime" / "python.exe"
    config = service_root / "config" / "service.json"
    image = (
        f'"{runtime}" "{package}" service --config "{config}"'
    )

    result = module.verify_live_provenance(
        expected_source_commit=_SOURCE_COMMIT,
        source_root=tmp_path / "candidate",
        client=client,
        service_query=lambda: {
            "configuration": (
                f"SERVICE_START_NAME : {_SERVICE_ACCOUNT}\n"
                f"BINARY_PATH_NAME : {image}\n"
                "START_TYPE : 3 DEMAND_START"
            ),
            "state": "STATE : 4 RUNNING",
        },
        protected_read_denied=lambda _path: True,
    )

    assert result["candidate_source_match"] == "PASS"
    assert result["report_authentication"] == "PASS"
    assert result["windows_service_query"] == "PASS"
    assert result["overall_result"] == "PASS"


def _audit_script_module() -> ModuleType:
    path = Path(__file__).resolve().parents[2] / "scripts" / (
        "audit-keeper-authority.py"
    )
    spec = importlib.util.spec_from_file_location(
        "audit_keeper_authority_test", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("auditor utility could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
