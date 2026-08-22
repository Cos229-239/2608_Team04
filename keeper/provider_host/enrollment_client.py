from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Protocol

from keeper.authority_service.client import AuthorityServiceClient
from keeper.executive.founder_auth import FounderAuthenticator
from keeper.executive.founder_capability import (
    APPLICATION_IDENTITY,
    FounderAuthorizationCapability,
    FounderCapabilityClaims,
)
from keeper.executive.models import FounderApprovalChallenge
from keeper.provider_host.bootstrap import ProviderHostBootstrap
from keeper.provider_host.protocol import structured_digest
from keeper.providers.codex_contract import CODEX_ALLOWED_SUBSCRIPTION_PLANS
from keeper.providers.claude_contract import CLAUDE_ALLOWED_SUBSCRIPTION_PLANS


_SYSTEM_PROJECT = "keeper-system:provider-host"
_SYSTEM_CHARTER = "keeper-system:provider-host-enrollment"


class EnrollmentAuthorityClient(Protocol):
    def diagnostics(self) -> dict[str, Any]: ...

    def provider_host_enrollment_status(self) -> dict[str, Any]: ...

    def query_state(self, kind: str, identifier: str) -> dict[str, Any]: ...

    def authorize_exhausted_provider_registration(
        self,
        *,
        registration_id: str,
        failure_digest: str,
        request_identity_digest: str,
        expected_account_identity_digest: str,
        expected_account_plan_type: str,
        account_identity_discovery_digest: str,
        expected_executable_sha256: str,
        expected_executable_size: int,
        required_authority_version: str,
        required_host_version: str,
        founder_capability: dict[str, object],
    ) -> dict[str, Any]: ...

    def recover_exhausted_provider_registration(
        self, registration_id: str
    ) -> dict[str, Any]: ...

    def authorize_provider_qualification_retry(
        self,
        *,
        registration_id: str,
        qualification_id: str,
        qualification_failure_digest: str,
        required_authority_version: str,
        required_host_version: str,
        founder_capability: dict[str, object],
        retry_generation: int = 2,
    ) -> dict[str, Any]: ...

    def begin_provider_host_enrollment(
        self,
        *,
        founder_capability: dict[str, object],
        proposal: dict[str, object],
    ) -> dict[str, Any]: ...

    def complete_provider_host_enrollment(
        self, enrollment_id: str, proof: dict[str, object]
    ) -> dict[str, Any]: ...

    def reconcile_provider_host_enrollment(
        self, enrollment_id: str, proof: dict[str, object] | None
    ) -> dict[str, Any]: ...

    def revoke_provider_host_enrollment(
        self, enrollment_id: str, founder_capability: dict[str, object]
    ) -> dict[str, Any]: ...

    def reconcile_provider_host_launch(
        self,
        *,
        founder_capability: dict[str, object],
        expected_launch: dict[str, object],
        enrollment_id: str,
    ) -> dict[str, Any]: ...

    def dispose_provider_registration_failure(
        self,
        *,
        registration_id: str,
        failure_digest: str,
        disposition: str,
        attempt_generation: int,
        founder_capability: dict[str, object],
    ) -> dict[str, Any]: ...

    def migrate_legacy_authority_predispatch_registration(
        self,
        *,
        registration_id: str,
        enrollment_id: str,
        offline_host_process_evidence: dict[str, object],
        founder_capability: dict[str, object],
    ) -> dict[str, Any]: ...


class ProviderHostEnrollmentClient:
    """Founder-confirmed client flow; no protected config edits are required."""

    def __init__(
        self,
        *,
        authority: AuthorityServiceClient | EnrollmentAuthorityClient,
        authenticator: FounderAuthenticator,
        bootstrap: ProviderHostBootstrap,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.authority = authority
        self.authenticator = authenticator
        self.bootstrap = bootstrap
        self.now = now or (lambda: datetime.now(UTC))

    def enroll(self, *, generation: int) -> dict[str, Any]:
        with self.bootstrap.checkpoint_transaction():
            self.bootstrap.prepare_new_enrollment(
                self.authority.provider_host_enrollment_status()
            )
            proposal = self.bootstrap.create_proposal(generation=generation)
            proposal_digest = structured_digest(proposal)
            try:
                capability = self._founder_capability(
                    action="ENROLL_PROVIDER_HOST",
                    action_digest=proposal_digest,
                    generation=generation,
                )
            except (OSError, PermissionError, RuntimeError, TypeError, ValueError):
                self.bootstrap.abandon_unauthorized_proposal(proposal_digest)
                raise
            capability_record = asdict(capability)
            self.bootstrap.store_founder_capability(capability_record)
            return self._begin_and_complete(proposal, capability_record)

    def resume_authorization(self) -> dict[str, Any]:
        with self.bootstrap.checkpoint_transaction():
            proposal, capability = self.bootstrap.authorization_material()
            return self._begin_and_complete(proposal, capability)

    def _begin_and_complete(
        self,
        proposal: dict[str, object],
        capability: dict[str, object],
    ) -> dict[str, Any]:
        begun = self.authority.begin_provider_host_enrollment(
            founder_capability=capability,
            proposal=proposal,
        )
        proof = self.bootstrap.prove_grant(_dict(begun.get("grant"), "grant"))
        completed = self.authority.complete_provider_host_enrollment(
            str(begun["enrollment_id"]), proof
        )
        return self.bootstrap.commit_receipt(
            _dict(completed.get("receipt"), "receipt")
        )

    def reconcile(self) -> dict[str, Any]:
        with self.bootstrap.checkpoint_transaction():
            enrollment_id, proof = self.bootstrap.reconciliation_material()
            completed = self.authority.reconcile_provider_host_enrollment(
                enrollment_id, proof
            )
            return self.bootstrap.commit_receipt(
                _dict(completed.get("receipt"), "receipt")
            )

    def reconcile_expired(self, enrollment_id: str) -> dict[str, Any]:
        with self.bootstrap.checkpoint_transaction():
            return self.authority.reconcile_provider_host_enrollment(
                enrollment_id, None
            )

    def revoke(
        self,
        *,
        enrollment_id: str,
        receipt_digest: str,
        generation: int,
    ) -> dict[str, Any]:
        with self.bootstrap.checkpoint_transaction():
            binding = {
                "action": "REVOKE_PROVIDER_HOST",
                "enrollment_id": enrollment_id,
                "receipt_digest": receipt_digest,
            }
            capability = self._founder_capability(
                action="REVOKE_PROVIDER_HOST",
                action_digest=structured_digest(binding),
                generation=generation,
            )
            result = self.authority.revoke_provider_host_enrollment(
                enrollment_id, asdict(capability)
            )
            return self.bootstrap.commit_revocation(
                _dict(result.get("revocation"), "revocation")
            )

    def reconcile_launch(self, launch_id: str) -> dict[str, Any]:
        diagnostics = self.authority.diagnostics()
        host = _dict(diagnostics.get("provider_host"), "Host diagnostics")
        launches = host.get("launches")
        pending = host.get("launch_reconciliation_pending_launches", [])
        if (
            host.get("online") is not True
            or host.get("launch_state_proven") is not True
            or not isinstance(launches, list)
            or not isinstance(pending, list)
        ):
            raise PermissionError(
                "Provider Host launch reconciliation diagnostics are unavailable"
            )
        matches_by_digest = {
            structured_digest(value): dict(value)
            for value in [*launches, *pending]
            if isinstance(value, dict) and value.get("launch_id") == launch_id
        }
        matches = list(matches_by_digest.values())
        if len(matches) != 1:
            raise PermissionError(
                "Provider Host uncertain launch identity is not unique"
            )
        enrollment = self.authority.provider_host_enrollment_status()
        enrollment_id = str(enrollment.get("enrollment_id", ""))
        generation = enrollment.get("enrollment_generation")
        if (
            not enrollment_id
            or isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation <= 0
        ):
            raise PermissionError("Provider Host active enrollment is unavailable")
        expected_launch = matches[0]
        effect_accounting = {
            "model_request_possible": False,
            "provider_mutation_possible": False,
            "read_only_process_execution_upper_bound": 2,
            "usage_observation_possible": True,
        }
        binding = {
            "action": "RECONCILE_PROVIDER_HOST_LAUNCH",
            "effect_accounting": effect_accounting,
            "enrollment_id": enrollment_id,
            "expected_launch": expected_launch,
            "resolution": "LEGACY_REGISTER_PROBE_READ_ONLY_EFFECT_ACCOUNTED",
        }
        capability = self._founder_capability(
            action="RECONCILE_PROVIDER_HOST_LAUNCH",
            action_digest=structured_digest(binding),
            generation=generation,
        )
        return self.authority.reconcile_provider_host_launch(
            founder_capability=asdict(capability),
            expected_launch=expected_launch,
            enrollment_id=enrollment_id,
        )

    def dispose_registration_failure(
        self,
        *,
        registration_id: str,
        failure_digest: str,
        disposition: str,
        attempt_generation: int,
    ) -> dict[str, Any]:
        if disposition not in {"ABANDON", "RETRY_ONCE"}:
            raise ValueError("provider registration disposition is invalid")
        authorization_generation = attempt_generation + 1
        binding = {
            "action": "DISPOSE_PROVIDER_REGISTRATION_FAILURE",
            "attempt_generation": attempt_generation,
            "authorization_generation": authorization_generation,
            "disposition": disposition,
            "failure_digest": failure_digest,
            "registration_id": registration_id,
        }
        capability = self._founder_capability(
            action="DISPOSE_PROVIDER_REGISTRATION_FAILURE",
            action_digest=structured_digest(binding),
            generation=authorization_generation,
        )
        return self.authority.dispose_provider_registration_failure(
            registration_id=registration_id,
            failure_digest=failure_digest,
            disposition=disposition,
            attempt_generation=attempt_generation,
            founder_capability=asdict(capability),
        )

    def migrate_legacy_authority_predispatch_registration(
        self,
        *,
        registration_id: str,
        enrollment_id: str,
        offline_host_process_evidence: dict[str, object],
    ) -> dict[str, Any]:
        state = self.authority.query_state("registrations", registration_id)
        record = state.get("record")
        if state.get("found") is not True or not isinstance(record, dict):
            raise PermissionError(
                "legacy predispatch provider registration is unavailable"
            )
        start = record.get("start")
        request_identity_digest = record.get("request_identity_digest")
        enrollment = self.authority.provider_host_enrollment_status()
        if (
            record.get("service_state") != "REGISTRATION_STARTED"
            or not isinstance(start, dict)
            or start.get("attempt_generation", 1) != 1
            or not isinstance(start.get("setup_id"), str)
            or not isinstance(start.get("event_challenge"), str)
            or len(str(start["event_challenge"])) != 64
            or not isinstance(request_identity_digest, str)
            or len(request_identity_digest) != 64
            or enrollment.get("enrollment_id") != enrollment_id
            or enrollment.get("enrollment_generation") != 27
        ):
            raise PermissionError(
                "legacy predispatch provider registration checkpoint differs"
            )
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
            "legacy_authority_package_sha256": (
                "19102c5ed7ad2a278c18d49284a8fbea0a189031d4ee4ddf55ed4687120e2211"
            ),
            "legacy_authority_runtime_executable_sha256": (
                "03168c01b7b7491423350e82c26fee71f35b43694d1319d3c668bda6903a0c38"
            ),
            "legacy_authority_runtime_peer_digest": (
                "da25662c9921d468fc039fe1bcbde86be791570c66fa335f50c6d604bc381fbc"
            ),
            "legacy_authority_version": "1.7.47",
            "legacy_host_executable_sha256": (
                "e81327789faff88c187c007182268049fb81ca4974f02a0ba53e6618a1340fae"
            ),
            "legacy_host_manifest_sha256": (
                "3f9f7135d73f5c309550107bfd2648a8c38a850b7edad001cda3b5567f0e4fee"
            ),
            "legacy_host_version": "1.7.47",
            "offline_host_process_evidence_digest": structured_digest(
                offline_host_process_evidence
            ),
            "registration_id": registration_id,
            "request_identity_digest": request_identity_digest,
            "retry_attempt_generation": 2,
            "setup_id": start["setup_id"],
        }
        capability = self._founder_capability(
            action="LEGACY_AUTHORITY_PREDISPATCH_MIGRATION",
            action_digest=structured_digest(binding),
            generation=28,
        )
        return self.authority.migrate_legacy_authority_predispatch_registration(
            registration_id=registration_id,
            enrollment_id=enrollment_id,
            offline_host_process_evidence=offline_host_process_evidence,
            founder_capability=asdict(capability),
        )

    def authorize_exhausted_registration_replacement(
        self,
        *,
        registration_id: str,
        failure_digest: str,
        expected_account_identity_digest: str,
        expected_account_plan_type: str,
        account_identity_discovery_digest: str,
    ) -> dict[str, Any]:
        state = self.authority.query_state("registrations", registration_id)
        record = state.get("record")
        if state.get("found") is not True or not isinstance(record, dict):
            raise PermissionError("exhausted provider registration is unavailable")
        request_binding = record.get("request_binding")
        authentication_policy = (
            request_binding.get("authentication_policy")
            if isinstance(request_binding, dict)
            else None
        )
        request_identity_digest = record.get("request_identity_digest")
        expected_executable_sha256 = (
            request_binding.get("expected_executable_sha256")
            if isinstance(request_binding, dict)
            else None
        )
        expected_executable_size = (
            request_binding.get("expected_executable_size")
            if isinstance(request_binding, dict)
            else None
        )
        authorized_client_sid = (
            request_binding.get("authorized_client_sid")
            if isinstance(request_binding, dict)
            else None
        )
        provider_id = (
            request_binding.get("provider_id")
            if isinstance(request_binding, dict)
            else None
        )
        allowed_plans = (
            CODEX_ALLOWED_SUBSCRIPTION_PLANS
            if provider_id == "codex"
            else CLAUDE_ALLOWED_SUBSCRIPTION_PLANS
            if provider_id == "claude"
            else frozenset()
        )
        if (
            record.get("service_state") != "REGISTRATION_FAILED"
            or record.get("attempt_generation") != 2
            or record.get("failure_digest") != failure_digest
            or not isinstance(authentication_policy, dict)
            or not isinstance(authorized_client_sid, str)
            or not authorized_client_sid
            or not isinstance(request_identity_digest, str)
            or len(request_identity_digest) != 64
            or not isinstance(expected_executable_sha256, str)
            or len(expected_executable_sha256) != 64
            or isinstance(expected_executable_size, bool)
            or not isinstance(expected_executable_size, int)
            or expected_executable_size <= 0
            or not isinstance(expected_account_identity_digest, str)
            or len(expected_account_identity_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_account_identity_digest
            )
            or not isinstance(expected_account_plan_type, str)
            or expected_account_plan_type not in allowed_plans
            or not isinstance(account_identity_discovery_digest, str)
            or len(account_identity_discovery_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in account_identity_discovery_digest
            )
        ):
            raise PermissionError(
                "exhausted provider registration state is misbound"
            )
        diagnostics = self.authority.diagnostics()
        required_version = diagnostics.get("service_version")
        if required_version != "1.7.51":
            raise PermissionError(
                "exhausted provider registration requires Keeper 1.7.51"
            )
        assert isinstance(provider_id, str)
        successor_id = f"keeper-provider:{provider_id}:v1:" + hashlib.sha256(
            (
                f"{provider_id}-subscription-registration-successor-v1\0"
                + registration_id
                + "\0"
                + failure_digest
                + "\0"
                + request_identity_digest
            ).encode("utf-8")
        ).hexdigest()[:32]
        effect_accounting = {
            "model_request_count": 0,
            "provider_execution_count": 0,
            "qualification_count": 0,
            "registration_success_count": 0,
            "usage_reservation_count": 0,
        }
        binding = {
            "action": "NEW_REGISTRATION_AFTER_EXHAUSTION",
            "account_identity_discovery_digest": (
                account_identity_discovery_digest
            ),
            "expected_account_identity_digest": expected_account_identity_digest,
            "expected_account_plan_type": expected_account_plan_type,
            "authorized_client_sid": authorized_client_sid,
            "effect_accounting": effect_accounting,
            "exhausted_attempt_generation": 2,
            "expected_executable_sha256": expected_executable_sha256,
            "expected_executable_size": expected_executable_size,
            "predecessor_failure_digest": failure_digest,
            "predecessor_registration_id": registration_id,
            "request_identity_digest": request_identity_digest,
            "required_authority_version": required_version,
            "required_host_version": required_version,
            "successor_registration_id": successor_id,
        }
        capability = self._founder_capability(
            action="NEW_REGISTRATION_AFTER_EXHAUSTION",
            action_digest=structured_digest(binding),
            generation=3,
        )
        return self.authority.authorize_exhausted_provider_registration(
            registration_id=registration_id,
            failure_digest=failure_digest,
            request_identity_digest=request_identity_digest,
            expected_account_identity_digest=expected_account_identity_digest,
            expected_account_plan_type=expected_account_plan_type,
            account_identity_discovery_digest=account_identity_discovery_digest,
            expected_executable_sha256=expected_executable_sha256,
            expected_executable_size=expected_executable_size,
            required_authority_version=required_version,
            required_host_version=required_version,
            founder_capability=asdict(capability),
        )

    def recover_exhausted_registration_replacement(
        self, registration_id: str
    ) -> dict[str, Any]:
        return self.authority.recover_exhausted_provider_registration(
            registration_id
        )

    def authorize_qualification_retry(
        self,
        *,
        registration_id: str,
        qualification_id: str,
        qualification_failure_digest: str,
        retry_generation: int = 2,
    ) -> dict[str, Any]:
        required_version = self.authority.diagnostics().get("service_version")
        if required_version != "1.7.51":
            raise PermissionError(
                "provider qualification retry requires Keeper 1.7.51"
            )
        binding = {
            "action": "AUTHORIZE_PROVIDER_QUALIFICATION_RETRY",
            "qualification_failure_digest": qualification_failure_digest,
            "qualification_id": qualification_id,
            "registration_id": registration_id,
            "required_authority_version": required_version,
            "required_host_version": required_version,
            "retry_generation": retry_generation,
        }
        capability = self._founder_capability(
            action="AUTHORIZE_PROVIDER_QUALIFICATION_RETRY",
            action_digest=structured_digest(binding),
            generation=retry_generation,
        )
        return self.authority.authorize_provider_qualification_retry(
            registration_id=registration_id,
            qualification_id=qualification_id,
            qualification_failure_digest=qualification_failure_digest,
            required_authority_version=required_version,
            required_host_version=required_version,
            founder_capability=asdict(capability),
            retry_generation=retry_generation,
        )

    def _founder_capability(
        self, *, action: str, action_digest: str, generation: int
    ) -> FounderAuthorizationCapability:
        now = self.now().astimezone(UTC)
        challenge = FounderApprovalChallenge(
            challenge_id="provider-host-challenge:" + uuid.uuid4().hex,
            schema_version=2,
            project_id=_SYSTEM_PROJECT,
            charter_id=_SYSTEM_CHARTER,
            charter_revision=1,
            charter_digest=action_digest,
            approval_action="APPROVE_ACTION",
            approval_binding={
                "action": action,
                "action_digest": action_digest,
                "authorization_generation": generation,
            },
            nonce=secrets.token_hex(32),
            requested_at=now.isoformat(),
            expires_at=(now + timedelta(minutes=2)).isoformat(),
            state="PENDING",
            consumed_event_id=None,
        )
        confirmation = self.authenticator.authenticate(challenge)
        session = self.authenticator.verify(challenge, confirmation)
        issued = self.now().astimezone(UTC)
        claims = FounderCapabilityClaims(
            capability_id="provider-host-capability:" + uuid.uuid4().hex,
            project_id=_SYSTEM_PROJECT,
            charter_id=_SYSTEM_CHARTER,
            charter_revision=1,
            authorization_kind="PROVIDER_HOST_ENROLLMENT",
            protected_action=action,
            action_digest=action_digest,
            approval_digest=structured_digest(challenge.to_dict()),
            approval_event_digest=hashlib.sha256(
                confirmation.proof.encode("ascii")
            ).hexdigest(),
            founder_principal_sid=session.principal_sid,
            founder_authenticated_session_id=session.session_id,
            approval_event_id="provider-host-approval:" + challenge.challenge_id,
            approval_record_id="provider-host-record:" + challenge.challenge_id,
            challenge_id=challenge.challenge_id,
            challenge_proof_digest=session.proof_digest,
            authorization_generation=generation,
            revocation_epoch=generation - 1,
            issued_at=issued.isoformat(),
            expires_at=min(
                issued + timedelta(minutes=2),
                datetime.fromisoformat(session.expires_at),
            ).isoformat(),
            usage="ONE_TIME_GENERATION",
            machine_identity=session.machine_identity,
            application_identity=APPLICATION_IDENTITY,
        )
        return self.authenticator.issue_authorization_capability(
            claims, confirmation
        )


def _dict(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PermissionError(f"Provider Host {label} is invalid")
    return dict(value)
