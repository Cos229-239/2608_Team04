from __future__ import annotations

import copy
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Mapping, cast

import pytest

from keeper.authority_service.claude_registration import registration_declaration
from keeper.authority_service.client import AuthorityServiceClient
from keeper.authority_service.core import (
    AuthorityServiceCore,
    TrustedObserver,
    _validated_offline_host_process_evidence,
)
from keeper.authority_service.provider_host_enrollment import (
    ProviderHostEnrollmentCoordinator,
)
from keeper.executive.founder_capability import TestFounderCapabilityVerifier
from keeper.provider_host.enrollment import (
    ENROLLMENT_GRANT_PURPOSE,
    ENROLLMENT_PROPOSAL_PURPOSE,
    ENROLLMENT_RECEIPT_PURPOSE,
)
from keeper.provider_host.protocol import (
    HOST_PROTOCOL,
    TestEnvelopeIdentity as EnvelopeTestIdentity,
    structured_digest,
)
from tests.keeper.authority_testkit import make_test_founder_capability


SID = "S-1-5-21-1000-1000-1000-1001"
AUTHORITY = EnvelopeTestIdentity("authority-test", b"authority-migration-key")
HOST = EnvelopeTestIdentity("host-test", b"host-migration-key")
LEGACY_AUTHORITY_SHA256 = (
    "19102c5ed7ad2a278c18d49284a8fbea0a189031d4ee4ddf55ed4687120e2211"
)
LEGACY_HOST_SHA256 = (
    "e81327789faff88c187c007182268049fb81ca4974f02a0ba53e6618a1340fae"
)
LEGACY_HOST_MANIFEST_SHA256 = (
    "3f9f7135d73f5c309550107bfd2648a8c38a850b7edad001cda3b5567f0e4fee"
)


class _PredispatchObserver:
    def __init__(self) -> None:
        self.host_rpc_count = 0
        self.allow_terminal_failure = False

    def register_provider(
        self, provider_id: str, *args: object, **kwargs: object
    ) -> dict[str, Any]:
        del args
        if not self.allow_terminal_failure:
            raise PermissionError(
                "legacy Claude provider identity omitted before Host RPC"
            )
        self.host_rpc_count += 1
        assert provider_id == "claude"
        assert kwargs["recovering_registration"] is True
        assert kwargs["planned_setup_id"].startswith(
            "provider-registration-probe:"
        )
        return {
            "registration_terminal_failure": {
                "failure_stage": "ACCOUNT_PROBE_VALIDATE",
                "failure_code": "PERMISSION_REJECTED",
                "process_result": {"detail_status": "DETAIL_UNAVAILABLE"},
                "setup_result_digest": "a" * 64,
                "setup_envelope_digest": "b" * 64,
            }
        }


class _EnrollmentObserver:
    def __init__(self) -> None:
        self.deactivations: list[str] = []

    def provider_host_status(self) -> dict[str, object]:
        raise AssertionError("offline migration must not contact the legacy Host")

    def deactivate(self, record: Mapping[str, Any]) -> None:
        self.deactivations.append(str(record["enrollment_id"]))


def _public(identity: EnvelopeTestIdentity) -> dict[str, object]:
    return {
        "schema_version": 1,
        "algorithm": "RSA-PKCS1-SHA256",
        "identity": identity.identity,
        "key_id": identity.key_id,
        "modulus": "dGVzdA==",
        "exponent": "AQAB",
    }


def _fixture(
    tmp_path: Path,
) -> tuple[
    AuthorityServiceCore,
    AuthorityServiceClient,
    _EnrollmentObserver,
    str,
    str,
    dict[str, object],
]:
    executable = (tmp_path / "claude.exe").resolve()
    executable.write_bytes(b"MZ-claude-predispatch-fixture")
    observer = _PredispatchObserver()
    core = AuthorityServiceCore(
        tmp_path / "authority",
        observer=cast(TrustedObserver, observer),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    enrollment_observer = _EnrollmentObserver()
    coordinator = ProviderHostEnrollmentCoordinator(
        store=core.store,
        service_key_id=core.keys.current_key_id,
        authority_protocol_version=7,
        authority_schema_version=6,
        founder_verifier=TestFounderCapabilityVerifier(),
        authority_signer=AUTHORITY,
        authority_public_identity=_public(AUTHORITY),
        proposal_observer=cast(Any, enrollment_observer),
        activate=lambda record: None,
        deactivate=enrollment_observer.deactivate,
        host_verifier_factory=lambda value: HOST,
    )
    core.provider_host_enrollment = coordinator
    client = AuthorityServiceClient(
        test_transport=lambda request: core.dispatch(request, SID)
    )
    declaration = registration_declaration(
        expected_executable_sha256=hashlib.sha256(
            executable.read_bytes()
        ).hexdigest(),
        expected_executable_size=executable.stat().st_size,
        expected_version="2.1.220 (Claude Code)",
        subscription_plan="pro",
        keeper_launch_budget=20,
    )
    with pytest.raises(PermissionError, match="before Host RPC"):
        client.register_provider("claude", executable, **declaration)
    claim = core.store.list_records("registrations")[0]
    registration_id = str(claim["start"]["registration_id"])
    host_executable = (tmp_path / "KeeperProviderHost.exe").resolve()
    host_executable.write_bytes(b"MZ-host-fixture")
    host_size = host_executable.stat().st_size
    observed = datetime.now(UTC)
    user_binding = {
        "profile_path": str(tmp_path),
        "session_id": 1,
        "user_sid": SID,
    }
    installation = {
        "authenticode_binding": {
            "certificate_thumbprint": None,
            "publisher_subject": None,
            "source": "windows-authenticode",
            "status": "NotSigned",
        },
        "executable_file_identity": {
            "device_id": 1,
            "file_id": 2,
            "modified_ns": 3,
            "schema_version": 1,
            "size": host_size,
        },
        "executable_path": str(host_executable),
        "executable_sha256": LEGACY_HOST_SHA256,
        "executable_size": host_size,
        "install_root": str(tmp_path / "installed-host"),
        "manifest_sha256": LEGACY_HOST_MANIFEST_SHA256,
        "package_version": "1.7.47",
    }
    proposal_payload = {
        "authority_protocol_version": 7,
        "authority_schema_version": 6,
        "enrollment_generation": 27,
        "expires_at": (observed + timedelta(minutes=1)).isoformat(),
        "host_id": HOST.identity,
        "host_key_name": "DarkSage.KeeperProviderHost.test",
        "host_protocol": HOST_PROTOCOL,
        "host_public_identity": _public(HOST),
        "installation": installation,
        "issued_at": observed.isoformat(),
        "output_root": str(tmp_path / "output"),
        "pipe_name": r"\\.\pipe\keeper-provider-host-test",
        "proposal_nonce": "1" * 64,
        "schema_version": 1,
        "service_key_id": core.keys.current_key_id,
        "state_root": str(tmp_path / "state"),
        "user_binding": user_binding,
    }
    proposal = HOST.sign(ENROLLMENT_PROPOSAL_PURPOSE, proposal_payload)
    proposal_digest = structured_digest(proposal)
    enrollment_id = "provider-host-enrollment:" + hashlib.sha256(
        (HOST.identity + ":" + proposal_digest).encode("utf-8")
    ).hexdigest()
    grant_payload = {
        "authority_id": AUTHORITY.identity,
        "authority_protocol_version": 7,
        "authority_public_identity": _public(AUTHORITY),
        "authority_schema_version": 6,
        "challenge": "3" * 64,
        "enrollment_generation": 27,
        "enrollment_id": enrollment_id,
        "expires_at": (observed + timedelta(minutes=1)).isoformat(),
        "host_id": HOST.identity,
        "host_protocol": HOST_PROTOCOL,
        "issued_at": observed.isoformat(),
        "proposal_digest": proposal_digest,
        "sequence": 27,
        "service_key_id": core.keys.current_key_id,
        "state": "PENDING",
    }
    grant = AUTHORITY.sign(ENROLLMENT_GRANT_PURPOSE, grant_payload)
    grant_digest = structured_digest(grant)
    proof_digest = "b" * 64
    runtime_configuration = {
        "authority_id": AUTHORITY.identity,
        "authority_peer": {
            "executable_file_identity": {
                "device_id": 4,
                "file_id": 5,
                "modified_ns": 6,
                "schema_version": 1,
                "size": 7,
            },
            "executable_path": str(tmp_path / "keeper-authority.pyz"),
            "executable_sha256": LEGACY_AUTHORITY_SHA256,
            "session_id": 0,
            "user_sid": "S-1-5-18",
        },
        "authority_public_identity": _public(AUTHORITY),
        "enrollment_id": enrollment_id,
        "host_id": HOST.identity,
        "host_key_name": proposal_payload["host_key_name"],
        "host_public_identity": _public(HOST),
        "output_root": proposal_payload["output_root"],
        "pipe_name": proposal_payload["pipe_name"],
        "schema_version": 2,
        "state_root": proposal_payload["state_root"],
        "user_binding": user_binding,
    }
    receipt_payload = {
        "activated_at": observed.isoformat(),
        "authority_id": AUTHORITY.identity,
        "authority_key_id": AUTHORITY.key_id,
        "authority_protocol_version": 7,
        "authority_schema_version": 6,
        "enrollment_generation": 27,
        "enrollment_id": enrollment_id,
        "grant_digest": grant_digest,
        "host_id": HOST.identity,
        "host_protocol": HOST_PROTOCOL,
        "host_public_key_id": HOST.key_id,
        "proof_digest": proof_digest,
        "proposal_digest": proposal_digest,
        "runtime_configuration": {
            **runtime_configuration,
        },
        "service_key_id": core.keys.current_key_id,
        "state": "ACTIVE",
    }
    receipt = AUTHORITY.sign(ENROLLMENT_RECEIPT_PURPOSE, receipt_payload)
    core.store.insert(
        "provider_host_enrollments",
        enrollment_id,
        "ACTIVE",
        {
            "enrollment_id": enrollment_id,
            "enrollment_generation": 27,
            "proposal": proposal,
            "proposal_digest": proposal_digest,
            "grant": grant,
            "grant_digest": grant_digest,
            "proof_digest": proof_digest,
            "receipt": receipt,
            "launch_reconciliation_claims": [],
        },
    )
    offline_evidence: dict[str, object] = {
        "process_id": 4242,
        "session_id": 1,
        "process_start_time_utc": (observed - timedelta(minutes=1)).isoformat(),
        "executable_path": str(host_executable),
        "executable_sha256": LEGACY_HOST_SHA256,
        "executable_size": host_size,
        "retained_kernel_handle": True,
        "termination_observed": True,
        "zero_matching_processes": True,
        "observed_at": observed.isoformat(),
    }
    return (
        core,
        client,
        enrollment_observer,
        registration_id,
        enrollment_id,
        offline_evidence,
    )


def _request(
    core: AuthorityServiceCore,
    registration_id: str,
    enrollment_id: str,
    offline_evidence: dict[str, object],
    *,
    suffix: str = "legacy-predispatch",
) -> dict[str, Any]:
    claim = core.store.get("registrations", registration_id)
    assert claim is not None
    start = cast(dict[str, Any], claim["start"])
    effect_accounting = {
        "host_rpc_count": 0,
        "model_request_count": 0,
        "provider_binding_created": False,
        "qualification_started": False,
        "registration_persisted": False,
        "usage_reservation_count": 0,
    }
    binding = {
        "action": "LEGACY_AUTHORITY_PREDISPATCH_MIGRATION",
        "attempt_generation": 1,
        "authorization_generation": 28,
        "effect_accounting": effect_accounting,
        "enrollment_generation": 27,
        "enrollment_id": enrollment_id,
        "event_challenge_digest": hashlib.sha256(
            str(start["event_challenge"]).encode("utf-8")
        ).hexdigest(),
        "legacy_authority_package_sha256": LEGACY_AUTHORITY_SHA256,
        "legacy_authority_version": "1.7.47",
        "legacy_host_executable_sha256": LEGACY_HOST_SHA256,
        "legacy_host_manifest_sha256": LEGACY_HOST_MANIFEST_SHA256,
        "legacy_host_version": "1.7.47",
        "offline_host_process_evidence_digest": structured_digest(
            offline_evidence
        ),
        "registration_id": registration_id,
        "request_identity_digest": claim["request_identity_digest"],
        "retry_attempt_generation": 2,
        "setup_id": start["setup_id"],
    }
    capability = make_test_founder_capability(
        "keeper-system:provider-host",
        generation=28,
        suffix=suffix,
        charter_id="keeper-system:provider-host-enrollment",
        claim_overrides={
            "charter_revision": 1,
            "authorization_kind": "PROVIDER_HOST_ENROLLMENT",
            "protected_action": "LEGACY_AUTHORITY_PREDISPATCH_MIGRATION",
            "action_digest": structured_digest(binding),
            "founder_principal_sid": SID,
        },
    )
    return {
        "registration_id": registration_id,
        "enrollment_id": enrollment_id,
        "offline_host_process_evidence": offline_evidence,
        "founder_capability": capability,
    }


def _replace_enrollment(
    core: AuthorityServiceCore,
    enrollment_id: str,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    record = core.store.get("provider_host_enrollments", enrollment_id)
    assert record is not None
    payload = copy.deepcopy(
        {name: value for name, value in record.items() if name != "service_state"}
    )
    mutate(payload)
    core.store.transition(
        "provider_host_enrollments",
        enrollment_id,
        "ACTIVE",
        "ACTIVE",
        payload,
    )


def _assert_unmigrated(
    core: AuthorityServiceCore,
    registration_id: str,
    enrollment_id: str,
) -> None:
    assert core.store.get("registrations", registration_id)["service_state"] == (
        "REGISTRATION_STARTED"
    )
    assert core.store.get("provider_host_enrollments", enrollment_id)[
        "service_state"
    ] == "ACTIVE"


def test_exact_preserved_offline_checkpoint_evidence_may_outlive_freshness_window(
) -> None:
    evidence = {
        "process_id": 9136,
        "session_id": 1,
        "process_start_time_utc": "2026-08-16T03:57:11.0329912Z",
        "executable_path": (
            r"C:\Users\nhfah\AppData\Local\Programs\DarkSage"
            r"\KeeperProviderHost\versions\1.7.47\KeeperProviderHost.exe"
        ),
        "executable_sha256": LEGACY_HOST_SHA256,
        "executable_size": 14531584,
        "retained_kernel_handle": True,
        "termination_observed": True,
        "zero_matching_processes": True,
        "observed_at": "2026-08-16T15:51:20.5344155Z",
    }
    digest = structured_digest(evidence)
    assert digest == (
        "17f1f2273f89241da8248773b452a86f734c0988cf24445e56a7914504f36489"
    )
    assert _validated_offline_host_process_evidence(
        evidence,
        installation={
            "executable_path": evidence["executable_path"],
            "executable_sha256": LEGACY_HOST_SHA256,
            "executable_size": 14531584,
        },
        user_binding={"session_id": 1},
        allowed_historical_digest=digest,
    ) == evidence


def test_other_stale_offline_checkpoint_evidence_remains_rejected() -> None:
    evidence = {
        "process_id": 9137,
        "session_id": 1,
        "process_start_time_utc": "2026-08-16T03:57:11.0329912Z",
        "executable_path": (
            r"C:\Users\nhfah\AppData\Local\Programs\DarkSage"
            r"\KeeperProviderHost\versions\1.7.47\KeeperProviderHost.exe"
        ),
        "executable_sha256": LEGACY_HOST_SHA256,
        "executable_size": 14531584,
        "retained_kernel_handle": True,
        "termination_observed": True,
        "zero_matching_processes": True,
        "observed_at": "2026-08-16T15:51:20.5344155Z",
    }
    with pytest.raises(PermissionError, match="evidence is stale"):
        _validated_offline_host_process_evidence(
            evidence,
            installation={
                "executable_path": evidence["executable_path"],
                "executable_sha256": LEGACY_HOST_SHA256,
                "executable_size": 14531584,
            },
            user_binding={"session_id": 1},
            allowed_historical_digest=(
                "17f1f2273f89241da8248773b452a86f734c0988cf24445e56a7914504f36489"
            ),
        )


@pytest.mark.parametrize("target", ("proposal", "grant", "receipt"))
def test_predispatch_migration_rejects_tampered_signed_envelope(
    tmp_path: Path,
    target: str,
) -> None:
    core, client, _, registration_id, enrollment_id, evidence = _fixture(tmp_path)

    def tamper(payload: dict[str, Any]) -> None:
        envelope = cast(dict[str, Any], payload[target])
        envelope_payload = cast(dict[str, Any], envelope["payload"])
        if target == "proposal":
            envelope_payload["proposal_nonce"] = "2" * 64
        elif target == "grant":
            envelope_payload["challenge"] = "4" * 64
        else:
            envelope_payload["activated_at"] = (
                datetime.now(UTC) + timedelta(seconds=1)
            ).isoformat()

    _replace_enrollment(core, enrollment_id, tamper)
    with pytest.raises(PermissionError):
        client.migrate_legacy_authority_predispatch_registration(
            **_request(core, registration_id, enrollment_id, evidence)
        )
    _assert_unmigrated(core, registration_id, enrollment_id)


def test_predispatch_migration_rejects_flattened_unsigned_receipt(
    tmp_path: Path,
) -> None:
    core, client, _, registration_id, enrollment_id, evidence = _fixture(tmp_path)

    def flatten(payload: dict[str, Any]) -> None:
        receipt = cast(dict[str, Any], payload["receipt"])
        payload["receipt"] = copy.deepcopy(receipt["payload"])

    _replace_enrollment(core, enrollment_id, flatten)
    with pytest.raises(PermissionError):
        client.migrate_legacy_authority_predispatch_registration(
            **_request(core, registration_id, enrollment_id, evidence)
        )
    _assert_unmigrated(core, registration_id, enrollment_id)


def test_predispatch_migration_rejects_validly_signed_cross_binding(
    tmp_path: Path,
) -> None:
    core, client, _, registration_id, enrollment_id, evidence = _fixture(tmp_path)

    def mismatch(payload: dict[str, Any]) -> None:
        receipt = cast(dict[str, Any], payload["receipt"])
        receipt_payload = copy.deepcopy(cast(dict[str, Any], receipt["payload"]))
        runtime = cast(dict[str, Any], receipt_payload["runtime_configuration"])
        user_binding = copy.deepcopy(cast(dict[str, Any], runtime["user_binding"]))
        user_binding["profile_path"] = str(tmp_path / "different-profile")
        runtime["user_binding"] = user_binding
        payload["receipt"] = AUTHORITY.sign(
            ENROLLMENT_RECEIPT_PURPOSE,
            receipt_payload,
        )

    _replace_enrollment(core, enrollment_id, mismatch)
    with pytest.raises(
        PermissionError,
        match="proposal and receipt binding differs",
    ):
        client.migrate_legacy_authority_predispatch_registration(
            **_request(core, registration_id, enrollment_id, evidence)
        )
    _assert_unmigrated(core, registration_id, enrollment_id)


def test_predispatch_migration_rejects_validly_signed_generation_mismatch(
    tmp_path: Path,
) -> None:
    core, client, _, registration_id, enrollment_id, evidence = _fixture(tmp_path)

    def mismatch(payload: dict[str, Any]) -> None:
        proposal = cast(dict[str, Any], payload["proposal"])
        proposal_payload = copy.deepcopy(
            cast(dict[str, Any], proposal["payload"])
        )
        proposal_payload["enrollment_generation"] = 26
        signed_proposal = HOST.sign(
            ENROLLMENT_PROPOSAL_PURPOSE,
            proposal_payload,
        )
        proposal_digest = structured_digest(signed_proposal)

        grant = cast(dict[str, Any], payload["grant"])
        grant_payload = copy.deepcopy(cast(dict[str, Any], grant["payload"]))
        grant_payload["proposal_digest"] = proposal_digest
        signed_grant = AUTHORITY.sign(ENROLLMENT_GRANT_PURPOSE, grant_payload)
        grant_digest = structured_digest(signed_grant)

        receipt = cast(dict[str, Any], payload["receipt"])
        receipt_payload = copy.deepcopy(cast(dict[str, Any], receipt["payload"]))
        receipt_payload["proposal_digest"] = proposal_digest
        receipt_payload["grant_digest"] = grant_digest

        payload["proposal"] = signed_proposal
        payload["proposal_digest"] = proposal_digest
        payload["grant"] = signed_grant
        payload["grant_digest"] = grant_digest
        payload["receipt"] = AUTHORITY.sign(
            ENROLLMENT_RECEIPT_PURPOSE,
            receipt_payload,
        )

    _replace_enrollment(core, enrollment_id, mismatch)
    with pytest.raises(PermissionError):
        client.migrate_legacy_authority_predispatch_registration(
            **_request(core, registration_id, enrollment_id, evidence)
        )
    _assert_unmigrated(core, registration_id, enrollment_id)


def test_predispatch_migration_rejects_validly_signed_grant_host_mismatch(
    tmp_path: Path,
) -> None:
    core, client, _, registration_id, enrollment_id, evidence = _fixture(tmp_path)

    def mismatch(payload: dict[str, Any]) -> None:
        grant = cast(dict[str, Any], payload["grant"])
        grant_payload = copy.deepcopy(cast(dict[str, Any], grant["payload"]))
        grant_payload["host_id"] = "host-other"
        signed_grant = AUTHORITY.sign(ENROLLMENT_GRANT_PURPOSE, grant_payload)
        grant_digest = structured_digest(signed_grant)

        receipt = cast(dict[str, Any], payload["receipt"])
        receipt_payload = copy.deepcopy(cast(dict[str, Any], receipt["payload"]))
        receipt_payload["grant_digest"] = grant_digest

        payload["grant"] = signed_grant
        payload["grant_digest"] = grant_digest
        payload["receipt"] = AUTHORITY.sign(
            ENROLLMENT_RECEIPT_PURPOSE,
            receipt_payload,
        )

    _replace_enrollment(core, enrollment_id, mismatch)
    with pytest.raises(PermissionError):
        client.migrate_legacy_authority_predispatch_registration(
            **_request(core, registration_id, enrollment_id, evidence)
        )
    _assert_unmigrated(core, registration_id, enrollment_id)


def test_exact_predispatch_migration_is_atomic_dormant_and_idempotent(
    tmp_path: Path,
) -> None:
    core, client, observer, registration_id, enrollment_id, evidence = _fixture(
        tmp_path
    )
    request = _request(core, registration_id, enrollment_id, evidence)
    first = client.migrate_legacy_authority_predispatch_registration(**request)
    repeated = client.migrate_legacy_authority_predispatch_registration(**request)

    assert repeated == first
    registration = core.store.get("registrations", registration_id)
    enrollment = core.store.get("provider_host_enrollments", enrollment_id)
    assert registration is not None
    assert enrollment is not None
    assert registration["service_state"] == "REGISTRATION_RETRY_AUTHORIZED"
    assert registration["attempt_generation"] == 2
    assert registration["start"]["attempt_generation"] == 2
    assert enrollment["service_state"] == "REVOKED"
    assert enrollment["predispatch_migration_digest"] == first["migration_digest"]
    assert core.store.list_records("qualifications") == []
    assert core.store.list_records("attempts") == []
    assert observer.deactivations == [enrollment_id, enrollment_id]


def test_predispatch_migration_rejects_mismatch_without_partial_transition(
    tmp_path: Path,
) -> None:
    core, client, _, registration_id, enrollment_id, evidence = _fixture(tmp_path)
    request = _request(core, registration_id, enrollment_id, evidence)
    bad_evidence = dict(evidence)
    bad_evidence["zero_matching_processes"] = False
    request["offline_host_process_evidence"] = bad_evidence
    with pytest.raises(PermissionError):
        client.migrate_legacy_authority_predispatch_registration(**request)
    assert core.store.get("registrations", registration_id)["service_state"] == (
        "REGISTRATION_STARTED"
    )
    assert core.store.get("provider_host_enrollments", enrollment_id)[
        "service_state"
    ] == "ACTIVE"


def test_predispatch_migration_atomic_failure_leaves_both_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core, client, _, registration_id, enrollment_id, evidence = _fixture(tmp_path)
    request = _request(core, registration_id, enrollment_id, evidence)

    class SimulatedPowerLoss(BaseException):
        pass

    original = core.store.migrate_legacy_predispatch_registration

    def fail(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise SimulatedPowerLoss("before atomic commit")

    monkeypatch.setattr(core.store, "migrate_legacy_predispatch_registration", fail)
    with pytest.raises(SimulatedPowerLoss):
        client.migrate_legacy_authority_predispatch_registration(**request)
    monkeypatch.setattr(core.store, "migrate_legacy_predispatch_registration", original)
    assert core.store.get("registrations", registration_id)["service_state"] == (
        "REGISTRATION_STARTED"
    )
    assert core.store.get("provider_host_enrollments", enrollment_id)[
        "service_state"
    ] == "ACTIVE"


def test_predispatch_migration_concurrency_has_one_durable_result(
    tmp_path: Path,
) -> None:
    core, client, _, registration_id, enrollment_id, evidence = _fixture(tmp_path)
    request = _request(core, registration_id, enrollment_id, evidence)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(
            executor.map(
                lambda _: client.migrate_legacy_authority_predispatch_registration(
                    **request
                ),
                range(2),
            )
        )
    assert results[0] == results[1]
    assert len(core.store.list_records("registrations")) == 1
    assert len(core.store.list_records("provider_host_enrollments")) == 1


def test_predispatch_migration_restart_recovers_same_signed_result(
    tmp_path: Path,
) -> None:
    core, client, _, registration_id, enrollment_id, evidence = _fixture(tmp_path)
    request = _request(core, registration_id, enrollment_id, evidence)
    first = client.migrate_legacy_authority_predispatch_registration(**request)

    restarted = AuthorityServiceCore(
        tmp_path / "authority",
        observer=cast(TrustedObserver, _PredispatchObserver()),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    enrollment_observer = _EnrollmentObserver()
    restarted.provider_host_enrollment = ProviderHostEnrollmentCoordinator(
        store=restarted.store,
        service_key_id=restarted.keys.current_key_id,
        authority_protocol_version=7,
        authority_schema_version=6,
        founder_verifier=TestFounderCapabilityVerifier(),
        authority_signer=AUTHORITY,
        authority_public_identity=_public(AUTHORITY),
        proposal_observer=cast(Any, enrollment_observer),
        activate=lambda record: None,
        deactivate=enrollment_observer.deactivate,
        host_verifier_factory=lambda value: HOST,
    )
    restarted_client = AuthorityServiceClient(
        test_transport=lambda value: restarted.dispatch(value, SID)
    )
    recovered = restarted_client.migrate_legacy_authority_predispatch_registration(
        **request
    )
    assert recovered == first
    assert enrollment_observer.deactivations == [enrollment_id]


def test_predispatch_migration_activates_only_generation_two_and_keeps_lineage(
    tmp_path: Path,
) -> None:
    core, client, _, registration_id, enrollment_id, evidence = _fixture(tmp_path)
    request = _request(core, registration_id, enrollment_id, evidence)
    migrated = client.migrate_legacy_authority_predispatch_registration(**request)
    observer = cast(_PredispatchObserver, core.observer)
    observer.allow_terminal_failure = True
    claim = core.store.get("registrations", registration_id)
    assert claim is not None
    request_binding = cast(dict[str, Any], claim["request_binding"])
    executable = Path(str(request_binding["executable"]))
    declaration = registration_declaration(
        expected_executable_sha256=str(
            request_binding["expected_executable_sha256"]
        ),
        expected_executable_size=int(request_binding["expected_executable_size"]),
        expected_version=str(request_binding["expected_version"]),
        subscription_plan="pro",
        keeper_launch_budget=20,
    )
    failed = client.register_provider("claude", executable, **declaration)

    assert observer.host_rpc_count == 1
    assert failed["state"] == "REGISTRATION_FAILED"
    stored = core.store.get("registrations", registration_id)
    assert stored is not None
    assert stored["attempt_generation"] == 2
    assert stored["predispatch_migration_digest"] == migrated["migration_digest"]
    assert stored["failure"]["effect_accounting"]["model_request_count"] == 0
    assert core.store.list_records("qualifications") == []
