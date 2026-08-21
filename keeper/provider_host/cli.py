from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.authority_service.core import SERVICE_VERSION
from keeper.authority_service.provider_identity import account_sid
from keeper.authority_service.protocol import PROTOCOL_VERSION
from keeper.authority_service.store import SERVICE_SCHEMA_VERSION
from keeper.executive.founder_auth import ProductionFounderAuthenticator
from keeper.provider_host.bootstrap import build_production_bootstrap
from keeper.provider_host.enrollment_client import ProviderHostEnrollmentClient
from keeper.provider_host.identity import PipePeerIdentity, UserBinding, current_user_binding
from keeper.provider_host.enrollment import (
    validate_enrollment_proposal,
    validate_enrollment_receipt,
    validate_enrollment_revocation,
)
from keeper.provider_host.install import (
    ProviderHostInstaller,
    attest_provider_host_exchange_root,
)
from keeper.provider_host.protocol import parse_utc, structured_digest
from keeper.provider_host.process_security import (
    current_host_executable_attestation,
    ensure_provider_host_process_service_query_access,
)
from keeper.provider_host.replay_store import ProviderHostStore
from keeper.provider_host.runtime import HostIdentity, KeeperProviderHost, ProviderBinding
from keeper.provider_host.server import ProviderHostServer
from keeper.provider_host.signing import RsaPublicIdentity, WindowsCngEnvelopeIdentity
from keeper.provider_host.windows_process import (
    CodexSetupRunner,
    ProviderProcessLauncher,
)


_enrollment_client_factory: Callable[[], ProviderHostEnrollmentClient] | None = None


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="keeper provider-host")
    commands = result.add_subparsers(dest="provider_host_command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--config", type=Path, required=True)
    status = commands.add_parser("status")
    status.add_argument("--config", type=Path, required=True)
    for name in ("install", "repair", "update", "replace-quarantined-selection"):
        command = commands.add_parser(name)
        command.add_argument("--install-root", type=Path, required=True)
        command.add_argument("--startup-root", type=Path, required=True)
        command.add_argument("--artifact", type=Path, required=True)
        command.add_argument("--version", required=True)
        command.add_argument("--package-sha256", required=True)
        if name == "replace-quarantined-selection":
            command.add_argument("--current-sha256", required=True)
            command.add_argument("--rollback-version", required=True)
            command.add_argument("--rollback-artifact-sha256", required=True)
            command.add_argument("--rollback-package-sha256", required=True)
    rollback = commands.add_parser("rollback")
    rollback.add_argument("--install-root", type=Path, required=True)
    rollback.add_argument("--startup-root", type=Path, required=True)
    uninstall = commands.add_parser("uninstall-preserve")
    uninstall.add_argument("--install-root", type=Path, required=True)
    uninstall.add_argument("--startup-root", type=Path, required=True)
    commands.add_parser("enrollment-status")
    enroll = commands.add_parser("enroll")
    enroll.add_argument("--generation", type=int, required=True)
    commands.add_parser("resume-enrollment")
    commands.add_parser("reconcile-enrollment")
    reconcile_launch = commands.add_parser("reconcile-uncertain-launch")
    reconcile_launch.add_argument("--launch-id", required=True)
    expired = commands.add_parser("reconcile-expired-enrollment")
    expired.add_argument("--enrollment-id", required=True)
    revoke = commands.add_parser("revoke-enrollment")
    revoke.add_argument("--enrollment-id", required=True)
    revoke.add_argument("--receipt-digest", required=True)
    revoke.add_argument("--generation", type=int, required=True)
    disposition = commands.add_parser("dispose-registration-failure")
    disposition.add_argument("--registration-id", required=True)
    disposition.add_argument("--failure-digest", required=True)
    disposition.add_argument(
        "--disposition", choices=("ABANDON", "RETRY_ONCE"), required=True
    )
    disposition.add_argument("--attempt-generation", type=int, required=True)
    predispatch = commands.add_parser(
        "migrate-legacy-predispatch-registration"
    )
    predispatch.add_argument("--registration-id", required=True)
    predispatch.add_argument("--enrollment-id", required=True)
    predispatch.add_argument(
        "--offline-host-process-evidence", type=Path, required=True
    )
    replacement = commands.add_parser(
        "authorize-exhausted-registration-replacement"
    )
    replacement.add_argument("--registration-id", required=True)
    replacement.add_argument("--failure-digest", required=True)
    replacement.add_argument(
        "--expected-account-identity-digest", required=True
    )
    replacement.add_argument(
        "--expected-account-plan-type", choices=("plus", "pro"), required=True
    )
    replacement.add_argument(
        "--account-identity-discovery-digest", required=True
    )
    replacement_recovery = commands.add_parser(
        "recover-exhausted-registration-replacement"
    )
    replacement_recovery.add_argument("--registration-id", required=True)
    qualification_retry = commands.add_parser(
        "authorize-qualification-retry"
    )
    qualification_retry.add_argument("--registration-id", required=True)
    qualification_retry.add_argument("--qualification-id", required=True)
    qualification_retry.add_argument(
        "--qualification-failure-digest", required=True
    )
    return result


def main(arguments: Sequence[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        command = str(options.provider_host_command)
        if command in {"run", "status"}:
            config_path = options.config.resolve()
            if not config_path.is_file():
                print(
                    json.dumps(
                        {
                            "installed": True,
                            "online": False,
                            "state": "INSTALLED_UNENROLLED",
                            "provider_state": "NO_QUALIFIED_PROVIDERS",
                            "founder_action_required": "ENROLL_PROVIDER_HOST",
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
                return 0
            revoked = _revoked_status(config_path)
            if revoked is not None:
                print(json.dumps(revoked, indent=2, sort_keys=True))
                return 0
            runtime, server = _build_runtime(config_path.resolve(strict=True))
            recovered = runtime.start()
            if command == "status":
                print(json.dumps({**runtime.status(), "recovered_uncertain": recovered}, indent=2, sort_keys=True))
                return 0
            server.serve_forever()
            runtime.logoff()
            return 0
        if command == "enrollment-status":
            authority = ProductionAuthorityServiceClient()
            identity = authority.require_live_identity()
            status_value = {
                "authority_identity": {
                    "protocol_version": identity["protocol_version"],
                    "schema_version": identity["schema_version"],
                    "service_key_id": identity["service_key_id"],
                    "service_version": identity["service_version"],
                },
                "enrollment": authority.provider_host_enrollment_status(),
            }
            print(json.dumps(status_value, indent=2, sort_keys=True))
            return 0
        if command in {
            "enroll",
            "resume-enrollment",
            "reconcile-enrollment",
            "reconcile-uncertain-launch",
            "reconcile-expired-enrollment",
            "revoke-enrollment",
            "dispose-registration-failure",
            "migrate-legacy-predispatch-registration",
            "authorize-exhausted-registration-replacement",
            "recover-exhausted-registration-replacement",
            "authorize-qualification-retry",
        }:
            client = _production_enrollment_client()
            if command == "enroll":
                enrollment_value = client.enroll(generation=options.generation)
            elif command == "resume-enrollment":
                enrollment_value = client.resume_authorization()
            elif command == "reconcile-enrollment":
                enrollment_value = client.reconcile()
            elif command == "reconcile-uncertain-launch":
                enrollment_value = client.reconcile_launch(options.launch_id)
            elif command == "reconcile-expired-enrollment":
                enrollment_value = client.reconcile_expired(options.enrollment_id)
            elif command == "revoke-enrollment":
                enrollment_value = client.revoke(
                    enrollment_id=options.enrollment_id,
                    receipt_digest=options.receipt_digest,
                    generation=options.generation,
                )
            elif command == "dispose-registration-failure":
                enrollment_value = client.dispose_registration_failure(
                    registration_id=options.registration_id,
                    failure_digest=options.failure_digest,
                    disposition=options.disposition,
                    attempt_generation=options.attempt_generation,
                )
            elif command == "migrate-legacy-predispatch-registration":
                evidence_path = options.offline_host_process_evidence.resolve(
                    strict=True
                )
                evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                if not isinstance(evidence, dict):
                    raise PermissionError(
                        "offline Host process evidence must be an object"
                    )
                enrollment_value = (
                    client.migrate_legacy_authority_predispatch_registration(
                        registration_id=options.registration_id,
                        enrollment_id=options.enrollment_id,
                        offline_host_process_evidence=evidence,
                    )
                )
            elif command == "authorize-exhausted-registration-replacement":
                enrollment_value = (
                    client.authorize_exhausted_registration_replacement(
                        registration_id=options.registration_id,
                        failure_digest=options.failure_digest,
                        expected_account_identity_digest=(
                            options.expected_account_identity_digest
                        ),
                        expected_account_plan_type=(
                            options.expected_account_plan_type
                        ),
                        account_identity_discovery_digest=(
                            options.account_identity_discovery_digest
                        ),
                    )
                )
            elif command == "recover-exhausted-registration-replacement":
                enrollment_value = (
                    client.recover_exhausted_registration_replacement(
                        options.registration_id
                    )
                )
            else:
                enrollment_value = client.authorize_qualification_retry(
                    registration_id=options.registration_id,
                    qualification_id=options.qualification_id,
                    qualification_failure_digest=(
                        options.qualification_failure_digest
                    ),
                )
            print(json.dumps(enrollment_value, indent=2, sort_keys=True))
            return 0
        installer = ProviderHostInstaller(
            options.install_root,
            options.startup_root,
            authority_service_sid=_authority_service_sid(),
        )
        if command == "install":
            lifecycle_value: object = installer.install(
                options.artifact,
                version=options.version,
                expected_package_sha256=options.package_sha256,
            )
        elif command == "repair":
            lifecycle_value = installer.repair(
                options.artifact,
                expected_package_sha256=options.package_sha256,
            )
        elif command == "update":
            lifecycle_value = installer.update(
                options.artifact,
                version=options.version,
                expected_package_sha256=options.package_sha256,
                drain=lambda: None,
            )
        elif command == "replace-quarantined-selection":
            lifecycle_value = installer.replace_quarantined_selection(
                options.artifact,
                version=options.version,
                expected_package_sha256=options.package_sha256,
                expected_current_sha256=options.current_sha256,
                expected_rollback_version=options.rollback_version,
                expected_rollback_artifact_sha256=options.rollback_artifact_sha256,
                expected_rollback_package_sha256=options.rollback_package_sha256,
                drain=lambda: None,
            )
        elif command == "rollback":
            lifecycle_value = installer.rollback(drain=lambda: None)
        elif command == "uninstall-preserve":
            lifecycle_value = installer.uninstall_preserving_data(drain=lambda: None)
        else:
            raise ValueError("Provider Host command is unsupported")
        print(json.dumps(_json_value(lifecycle_value), indent=2, sort_keys=True))
        return 0
    except (FileNotFoundError, OSError, PermissionError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


def _production_enrollment_client() -> ProviderHostEnrollmentClient:
    if _enrollment_client_factory is not None:
        return _enrollment_client_factory()
    authority = ProductionAuthorityServiceClient()
    diagnostics = authority.require_live_identity()
    _validate_authority_compatibility(diagnostics)
    binding = current_user_binding()
    if str(diagnostics.get("client_sid", "")).casefold() != binding.user_sid.casefold():
        raise PermissionError("Provider Host enrollment client identity differs")
    profile = Path(binding.profile_path).resolve(strict=True)
    installer = ProviderHostInstaller(
        profile
        / "AppData"
        / "Local"
        / "Programs"
        / "DarkSage"
        / "KeeperProviderHost",
        profile
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup",
        owner_sid=binding.user_sid,
        authority_service_sid=_authority_service_sid(),
    )
    bootstrap = build_production_bootstrap(installer, diagnostics)
    authenticator = ProductionFounderAuthenticator(
        installer.state / "founder-auth" / "proof-key.dpapi"
    )
    return ProviderHostEnrollmentClient(
        authority=authority,
        authenticator=authenticator,
        bootstrap=bootstrap,
    )


def _validate_authority_compatibility(
    diagnostics: Mapping[str, object],
) -> None:
    if (
        diagnostics.get("service_version") != SERVICE_VERSION
        or diagnostics.get("protocol_version") != PROTOCOL_VERSION
        or diagnostics.get("schema_version") != SERVICE_SCHEMA_VERSION
    ):
        raise PermissionError(
            "Provider Host enrollment requires the exact matching KeeperAuthority"
        )


def _build_runtime(config_path: Path) -> tuple[KeeperProviderHost, ProviderHostServer]:
    config, installation = _startup_configuration(config_path)
    binding_value = _object(config["user_binding"], "user binding")
    binding = UserBinding(
        str(binding_value["user_sid"]),
        int(binding_value["session_id"]),
        str(Path(str(binding_value["profile_path"])).resolve(strict=True)),
    )
    if current_user_binding() != binding:
        raise PermissionError("Provider Host configured user binding differs")
    authority_service_sid = _authority_service_sid()
    ensure_provider_host_process_service_query_access(
        service_sid=authority_service_sid,
        binding=binding,
        host_id=str(config["host_id"]),
        host_key_name=str(config["host_key_name"]),
        installation=installation,
    )
    state_root = Path(str(config["state_root"])).resolve()
    output_lexical = Path(os.path.abspath(Path(str(config["output_root"]))))
    expected_output_lexical = (
        Path(binding.profile_path)
        / "AppData"
        / "Local"
        / "DarkSage"
        / "KeeperProviderExchange"
    )
    if os.path.normcase(str(output_lexical)) != os.path.normcase(
        str(expected_output_lexical)
    ):
        raise PermissionError("Provider Host output exchange binding differs")
    attest_provider_host_exchange_root(
        output_lexical,
        owner_sid=binding.user_sid,
    )
    output_root = output_lexical.resolve(strict=True)
    provider: ProviderBinding | None = None
    provider_value = config.get("provider_binding")
    if provider_value is not None:
        provider_mapping = _object(provider_value, "provider binding")
        provider = ProviderBinding.from_mapping(provider_mapping)
    host_signer = WindowsCngEnvelopeIdentity(
        identity=str(config["host_id"]),
        key_name=str(config["host_key_name"]),
        machine_key=False,
        owner_sid=binding.user_sid,
    )
    if host_signer.public_configuration() != _object(
        config["host_public_identity"], "host public identity"
    ):
        raise PermissionError("Provider Host enrolled key identity differs")
    authority_verifier = RsaPublicIdentity.from_configuration(
        _object(config["authority_public_identity"], "Authority public identity")
    ).verifier()
    store = ProviderHostStore(state_root / "provider-host.db")
    runtime = KeeperProviderHost(
        identity=HostIdentity(
            str(config["host_id"]), str(config["authority_id"]), binding
        ),
        observed_binding=current_user_binding,
        authority_verifier=authority_verifier,
        host_signer=host_signer,
        store=store,
        provider_binding=provider,
        environment_attestation_key=secrets.token_bytes(32),
        setup_workspace_root=output_root / "setup",
    )
    authority_peer_value = _object(config["authority_peer"], "Authority peer")
    authority_path, authority_digest, authority_identity = (
        _expected_authority_peer(authority_peer_value)
    )
    server = ProviderHostServer(
        pipe_name=str(config["pipe_name"]),
        runtime=runtime,
        launcher=ProviderProcessLauncher(output_root),
        setup_runner=CodexSetupRunner(output_root / "setup"),
        authority_verifier=authority_verifier,
        host_signer=host_signer,
        store=store,
        authority_peer=PipePeerIdentity(
            0,
            int(authority_peer_value["session_id"]),
            str(authority_peer_value["user_sid"]),
            str(authority_path),
            authority_digest,
            authority_identity,
        ),
        authority_service_sid=authority_service_sid,
        authority_executable=authority_path,
        authority_executable_sha256=authority_digest,
        authority_executable_file_identity=authority_identity,
        host_executable_attestation=current_host_executable_attestation(),
    )
    return runtime, server


def _config(path: Path) -> dict[str, Any]:
    runtime, _ = _startup_configuration(path)
    return runtime


def _startup_configuration(
    path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("Provider Host configuration is unavailable") from error
    signed_receipt = isinstance(value, dict) and "signature" in value
    if signed_receipt:
        receipt_record = _object(value, "enrollment receipt")
        unsigned = _object(
            receipt_record.get("payload"),
            "enrollment receipt payload",
        )
        runtime_value = _object(
            unsigned.get("runtime_configuration"), "runtime configuration"
        )
        public = _object(
            runtime_value.get("authority_public_identity"),
            "Authority public identity",
        )
        verifier = RsaPublicIdentity.from_configuration(public).verifier()
        receipt = validate_enrollment_receipt(
            receipt_record,
            verifier,
            expected_enrollment_id=str(unsigned.get("enrollment_id", "")),
        )
        value = _object(receipt["runtime_configuration"], "runtime configuration")
    common = {
        "schema_version",
        "authority_id",
        "authority_peer",
        "authority_public_identity",
        "enrollment_id",
        "host_id",
        "host_key_name",
        "host_public_identity",
        "output_root",
        "pipe_name",
        "state_root",
        "user_binding",
    }
    schema = value.get("schema_version") if isinstance(value, dict) else None
    expected = common
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or schema != 2
        or not signed_receipt
    ):
        raise PermissionError("Provider Host configuration is invalid")
    pending_path = path.parent / "provider-host-enrollment-pending.json"
    try:
        pending = _object(
            json.loads(pending_path.read_text(encoding="utf-8")),
            "enrollment checkpoint",
        )
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError(
            "Provider Host committed enrollment checkpoint is unavailable"
        ) from error
    proposal_record = _object(
        pending.get("proposal"),
        "enrollment proposal",
    )
    proposal_payload = _object(
        proposal_record.get("payload"),
        "enrollment proposal payload",
    )
    if (
        pending.get("schema_version") != 1
        or pending.get("state") != "COMMITTED"
        or pending.get("proposal_digest") != structured_digest(proposal_record)
        or receipt.get("proposal_digest") != pending.get("proposal_digest")
        or pending.get("receipt_digest") != structured_digest(receipt_record)
        or pending.get("receipt") != receipt_record
    ):
        raise PermissionError(
            "Provider Host committed enrollment checkpoint differs"
        )
    issued_at = parse_utc(proposal_payload.get("issued_at"))
    proposal = validate_enrollment_proposal(
        proposal_payload,
        expected_authority_protocol=int(receipt["authority_protocol_version"]),
        expected_authority_schema=int(receipt["authority_schema_version"]),
        expected_service_key_id=str(receipt["service_key_id"]),
        now=issued_at,
    )
    runtime_matches = {
        "host_id": proposal.get("host_id"),
        "host_key_name": proposal.get("host_key_name"),
        "host_public_identity": proposal.get("host_public_identity"),
        "output_root": proposal.get("output_root"),
        "pipe_name": proposal.get("pipe_name"),
        "state_root": proposal.get("state_root"),
        "user_binding": proposal.get("user_binding"),
    }
    if any(value.get(name) != expected for name, expected in runtime_matches.items()):
        raise PermissionError("Provider Host committed runtime identity differs")
    return value, _object(
        proposal.get("installation"),
        "committed installation binding",
    )


def _revoked_status(receipt_path: Path) -> dict[str, Any] | None:
    revocation_path = receipt_path.parent / "provider-host-enrollment-revoked.json"
    if not revocation_path.is_file():
        return None
    try:
        receipt_record = _object(
            json.loads(receipt_path.read_text(encoding="utf-8")),
            "enrollment receipt",
        )
        receipt_payload = _object(
            receipt_record.get("payload"), "enrollment receipt payload"
        )
        runtime = _object(
            receipt_payload.get("runtime_configuration"),
            "runtime configuration",
        )
        public = _object(
            runtime.get("authority_public_identity"), "Authority public identity"
        )
        revocation_record = _object(
            json.loads(revocation_path.read_text(encoding="utf-8")),
            "enrollment revocation",
        )
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError(
            "Provider Host revocation state is unavailable"
        ) from error
    verifier = RsaPublicIdentity.from_configuration(public).verifier()
    revocation = validate_enrollment_revocation(
        revocation_record,
        verifier,
        expected_enrollment_id=str(receipt_payload.get("enrollment_id", "")),
        expected_receipt_digest=structured_digest(receipt_record),
    )
    return {
        "enrollment_id": revocation["enrollment_id"],
        "founder_action_required": "CREATE_NEW_PROVIDER_HOST_ENROLLMENT",
        "installed": True,
        "online": False,
        "provider_state": "UNAVAILABLE",
        "state": "REVOKED",
    }


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PermissionError(f"Provider Host {label} is invalid")
    return dict(value)


def _expected_authority_peer(
    value: Mapping[str, object],
) -> tuple[Path, str, tuple[int, int, int, int]]:
    authority_path = Path(str(value.get("executable_path", "")))
    authority_digest = str(value.get("executable_sha256", ""))
    authority_identity_value = _object(
        value.get("executable_file_identity"),
        "Authority executable file identity",
    )
    if (
        not authority_path.is_absolute()
        or os.path.normcase(os.path.abspath(str(authority_path)))
        != os.path.normcase(str(authority_path))
        or len(authority_digest) != 64
        or any(
            character not in "0123456789abcdef"
            for character in authority_digest
        )
        or authority_identity_value.get("schema_version") != 1
    ):
        raise PermissionError("Provider Host Authority peer identity is invalid")
    return (
        authority_path,
        authority_digest,
        (
            _positive_int(
                authority_identity_value.get("device_id"), allow_zero=True
            ),
            _positive_int(authority_identity_value.get("file_id")),
            _positive_int(authority_identity_value.get("size")),
            _positive_int(authority_identity_value.get("modified_ns")),
        ),
    )


def _authority_service_sid() -> str:
    sid = account_sid(r"NT SERVICE\KeeperAuthority")
    if not sid.startswith("S-1-5-80-"):
        raise PermissionError("KeeperAuthority service SID is invalid")
    return sid


def _positive_int(value: object, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise PermissionError(
            "Provider Host Authority executable file identity is invalid"
        )
    return value


def _json_value(value: object) -> object:
    if hasattr(value, "__dataclass_fields__"):
        return {
            name: getattr(value, name)
            for name in value.__dataclass_fields__
        }
    return value


if __name__ == "__main__":
    raise SystemExit(main())
