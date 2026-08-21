from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from keeper.app.storage import SCHEMA_VERSION, KeeperStore
from keeper.evidence_input import structured_digest, validate_provider_input
from keeper.executive.enums import (
    ActionCategory,
    ApprovalKind,
    CharterStatus,
    ExecutiveState,
    FounderApprovalIntent,
    TaskStatus,
)
from keeper.executive.models import (
    ApprovalRecord,
    AssumptionRecord,
    DecisionRecord,
    ExecutiveTask,
    FounderApprovalChallenge,
    FounderApprovalEvent,
    FounderAuthenticatedSession,
    MemoryRecord,
    ProjectCharter,
    ProjectRecord,
    ProposedAction,
    WorkflowRecord,
    utc_now,
)
from keeper.executive.founder_capability import (
    FounderAuthorizationCapability,
    FounderCapabilityClaims,
    capability_digest,
)
from keeper.executive.founder_auth import (
    ApprovalConfirmation,
    FounderAuthenticator,
    ProductionFounderAuthenticator,
    TestFounderAuthenticator,
    confirmation_response_digest,
)
from keeper.executive.state import PROJECT_TRANSITIONS, TASK_TRANSITIONS


@dataclass(frozen=True, slots=True)
class _ProductionRepositoryRuntimeIdentity:
    repository_token: str
    database_binding: tuple[str, str, str, str, int]


class ExecutiveRepository:
    __slots__ = (
        "__store",
        "__founder_authenticator",
        "__mode",
        "__runtime_token",
        "__database_binding",
        "__sealed",
    )
    __store: KeeperStore
    __founder_authenticator: FounderAuthenticator
    __mode: str
    __runtime_token: str
    __database_binding: tuple[str, str, str, str, int]
    __sealed: bool

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "use ProductionExecutiveRepository or TestExecutiveRepository"
        )

    def _initialize(
        self,
        store: KeeperStore,
        founder_authenticator: FounderAuthenticator,
        mode: str,
    ) -> None:
        if getattr(self, "_ExecutiveRepository__sealed", False):
            raise AttributeError("Executive repository is already initialized")
        object.__setattr__(self, "_ExecutiveRepository__sealed", False)
        store.bind_executive_repository_mode(mode)
        database_binding = store.executive_repository_binding()
        if database_binding[1] != mode:
            raise PermissionError(
                "Executive database repository mode binding is invalid"
            )
        object.__setattr__(self, "_ExecutiveRepository__store", store)
        object.__setattr__(
            self,
            "_ExecutiveRepository__founder_authenticator",
            founder_authenticator,
        )
        object.__setattr__(self, "_ExecutiveRepository__mode", mode)
        object.__setattr__(
            self, "_ExecutiveRepository__runtime_token", secrets.token_hex(32)
        )
        object.__setattr__(
            self, "_ExecutiveRepository__database_binding", database_binding
        )
        object.__setattr__(self, "_ExecutiveRepository__sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_ExecutiveRepository__sealed", False):
            raise AttributeError("Executive repository composition is immutable")
        object.__setattr__(self, name, value)

    @property
    def store(self) -> KeeperStore:
        if type(self) is not TestExecutiveRepository:
            raise AttributeError(
                "production repository does not expose mutable storage"
            )
        return self.__store

    def _production_runtime_identity(
        self,
    ) -> _ProductionRepositoryRuntimeIdentity:
        if type(self) is not ProductionExecutiveRepository:
            raise PermissionError(
                "production runtime requires the exact production repository"
            )
        if self.__mode != "PRODUCTION":
            raise PermissionError(
                "production repository mode is invalid"
            )
        self._trusted_authenticator()
        current_binding = self.__store.executive_repository_binding()
        if (
            current_binding != self.__database_binding
            or current_binding[1] != "PRODUCTION"
        ):
            raise PermissionError(
                "production repository database binding changed"
            )
        return _ProductionRepositoryRuntimeIdentity(
            repository_token=self.__runtime_token,
            database_binding=current_binding,
        )

    def _trusted_authenticator(self) -> FounderAuthenticator:
        authenticator = self.__founder_authenticator
        expected = (
            ProductionFounderAuthenticator
            if type(self) is ProductionExecutiveRepository
            else TestFounderAuthenticator
            if type(self) is TestExecutiveRepository
            else None
        )
        if expected is None or type(authenticator) is not expected:
            raise PermissionError(
                "repository Founder authenticator composition is invalid"
            )
        return authenticator

    def issue_pass_b_delivered_input_receipt(
        self,
        delivered_input_id: str,
        *,
        authority_attempt_id: str,
        provider_input_digest: str,
        delivered_input_digest: str,
        manifest_digest: str,
    ) -> dict[str, object]:
        if type(self) not in {
            ProductionExecutiveRepository,
            TestExecutiveRepository,
        }:
            raise PermissionError(
                "input receipts require an exact Executive repository"
            )
        expected_mode = (
            "PRODUCTION"
            if type(self) is ProductionExecutiveRepository
            else "TEST"
        )
        current_binding = self.__store.executive_repository_binding()
        if (
            self.__mode != expected_mode
            or current_binding != self.__database_binding
            or current_binding[1] != expected_mode
        ):
            raise PermissionError(
                "Executive delivered-input repository binding changed"
            )
        self._trusted_authenticator()
        with self.__store.connect() as connection:
            delivered_row = connection.execute(
                "SELECT payload,payload_hash,revision,updated_at "
                "FROM pass_b_records WHERE kind='delivered_input' AND id=?",
                (delivered_input_id,),
            ).fetchone()
            if delivered_row is None:
                raise PermissionError(
                    "delivered input was not committed to the Executive database"
                )
            delivered_serialized = str(delivered_row["payload"])
            if hashlib.sha256(delivered_serialized.encode("utf-8")).hexdigest() != (
                delivered_row["payload_hash"]
            ):
                raise RuntimeError("committed delivered input failed integrity validation")
            delivered = json.loads(delivered_serialized)
            if not isinstance(delivered, dict):
                raise RuntimeError("committed delivered input is malformed")
            try:
                provider_input = validate_provider_input(
                    delivered.get("provider_input")
                )
            except ValueError as error:
                raise RuntimeError(
                    "committed provider input is malformed"
                ) from error
            project = self.project(str(delivered.get("project_id") or ""))
            charter = self.charter(str(delivered.get("charter_id") or ""))
            if (
                project.state != ExecutiveState.ACTIVE
                or project.active_charter_id != charter.charter_id
                or project.active_charter_revision != charter.revision
                or charter.project_id != project.project_id
                or charter.revision != delivered.get("charter_revision")
                or charter.status != CharterStatus.ACTIVE
                or not charter.founder_approval_record_id
                or not charter.founder_authorization_capability_digest
            ):
                raise PermissionError(
                    "Executive delivered input is not bound to the current "
                    "Founder-approved charter"
                )
            reviewer_attempt_id = str(delivered.get("reviewer_attempt_id") or "")
            attempt_row = connection.execute(
                "SELECT payload,payload_hash FROM pass_b_records "
                "WHERE kind='attempt' AND id=?",
                (reviewer_attempt_id,),
            ).fetchone()
            claim = connection.execute(
                "SELECT assignment_id,authority_attempt_id,state "
                "FROM pass_b_launch_claims WHERE attempt_id=?",
                (reviewer_attempt_id,),
            ).fetchone()
            if attempt_row is None or claim is None:
                raise PermissionError(
                    "delivered input has no committed Executive launch claim"
                )
            attempt_serialized = str(attempt_row["payload"])
            if hashlib.sha256(attempt_serialized.encode("utf-8")).hexdigest() != (
                attempt_row["payload_hash"]
            ):
                raise RuntimeError("committed reviewer attempt failed integrity validation")
            attempt = json.loads(attempt_serialized)
            expected = {
                "delivered_input_id": delivered_input_id,
                "authority_attempt_id": authority_attempt_id,
                "provider_input_digest": provider_input_digest,
                "delivered_input_digest": delivered_input_digest,
            }
            if (
                not isinstance(attempt, dict)
                or any(attempt.get(name) != value for name, value in expected.items())
                or delivered.get("provider_input_digest") != provider_input_digest
                or delivered.get("delivered_input_digest") != delivered_input_digest
                or delivered.get("manifest_digest") != manifest_digest
                or delivered.get("composition_identity")
                != provider_input["composition_identity"]
                or provider_input["references"] != delivered.get("references")
                or provider_input["manifest_digest"] != manifest_digest
                or structured_digest(provider_input) != provider_input_digest
                or claim["assignment_id"] != delivered.get("reviewer_assignment_id")
                or claim["authority_attempt_id"] != authority_attempt_id
                or claim["state"] != "LAUNCH_CLAIMED"
                or attempt.get("state") != "LAUNCH_CLAIMED"
                or attempt.get("session_slot_claimed") is not True
            ):
                raise PermissionError(
                    "Executive delivered-input commit binding is invalid"
                )
            issued_at = utc_now()
            unsigned: dict[str, object] = {
                "schema_version": 1,
                "kind": "executive_delivered_input_commit_receipt",
                "receipt_id": (
                    f"input-receipt:{delivered_input_id}:"
                    f"{delivered_row['revision']}"
                ),
                "database_id": current_binding[3],
                "recovery_epoch": current_binding[4],
                "repository_mode": current_binding[1],
                "delivered_input_id": delivered_input_id,
                "delivered_input_record_revision": int(delivered_row["revision"]),
                "delivered_input_record_digest": str(delivered_row["payload_hash"]),
                "reviewer_attempt_id": reviewer_attempt_id,
                "reviewer_assignment_id": str(
                    delivered["reviewer_assignment_id"]
                ),
                "authority_attempt_id": authority_attempt_id,
                "project_id": str(delivered["project_id"]),
                "charter_id": str(delivered["charter_id"]),
                "charter_revision": int(delivered["charter_revision"]),
                "workflow_id": str(delivered["workflow_id"]),
                "work_item_id": str(delivered["work_item_id"]),
                "producer_assignment_id": str(
                    delivered["producer_assignment_id"]
                ),
                "producer_attempt_id": str(delivered["producer_attempt_id"]),
                "provider_id": str(provider_input["provider_id"]),
                "account_id": str(provider_input["account_id"]),
                "session_id": str(provider_input["session_id"]),
                "model_id": str(provider_input["model_id"]),
                "workspace": str(provider_input["workspace"]),
                "composition_identity": str(
                    delivered["composition_identity"]
                ),
                "provider_input_digest": provider_input_digest,
                "delivered_input_digest": delivered_input_digest,
                "manifest_digest": manifest_digest,
                "reference_set_digest": structured_digest(
                    delivered["references"]
                ),
                "usage_reservation_id": attempt.get("usage_reservation_id"),
                "session_slot_claimed": True,
                "launch_claim_state": "LAUNCH_CLAIMED",
                "committed_at": str(delivered_row["updated_at"]),
                "issued_at": issued_at,
            }
            return self._trusted_authenticator()._issue_executive_input_receipt(
                unsigned
            )

    def save_project(
        self,
        project: ProjectRecord,
        *,
        expected: ProjectRecord | None = None,
    ) -> None:
        existing = self.__store.get("executive_projects", project.project_id)
        target = ExecutiveState(project.state)
        if existing is None:
            if target not in {
                ExecutiveState.INTAKE,
                ExecutiveState.CLARIFICATION_REQUIRED,
            }:
                raise PermissionError(
                    "new projects must begin in intake or clarification"
                )
        else:
            prior = ProjectRecord.from_dict(existing)
            if expected is None or prior != expected:
                raise PermissionError(
                    "project write is stale or lacks exact CAS"
                )
            current = ExecutiveState(prior.state)
            if (
                (target == ExecutiveState.ACTIVE and current != target)
                or project.name != prior.name
                or project.project_type != prior.project_type
                or project.created_at != prior.created_at
                or project.active_charter_id != prior.active_charter_id
                or project.active_charter_revision
                != prior.active_charter_revision
            ):
                raise PermissionError(
                    "project identity and charter binding are trusted-state only"
                )
            if target != current and target not in PROJECT_TRANSITIONS[current]:
                raise PermissionError(
                    f"repository rejected executive transition: {current} -> {target}"
                )
            self._cas_entity(
                "executive_projects",
                project.project_id,
                expected.to_dict(),
                project.to_dict(),
            )
            return
        self._insert_trusted_entity(
            "executive_projects", project.project_id, project.to_dict()
        )

    def project(self, project_id: str) -> ProjectRecord:
        return ProjectRecord.from_dict(self._required("executive_projects", project_id))

    def save_charter(
        self,
        charter: ProjectCharter,
        *,
        expected: ProjectCharter | None = None,
    ) -> None:
        existing = self.__store.get("project_charters", charter.charter_id)
        if existing is None:
            if charter.status != CharterStatus.DRAFT:
                raise PermissionError("new charters must begin as drafts")
            if self.__store.get("executive_projects", charter.project_id) is None:
                raise PermissionError("charter project does not exist")
            self._insert_trusted_entity(
                "project_charters", charter.charter_id, charter.to_dict()
            )
            self._relate(
                charter.project_id,
                "project",
                charter.project_id,
                "charter",
                charter.charter_id,
            )
            return
        prior = ProjectCharter.from_dict(existing)
        if expected is None or prior != expected:
            raise PermissionError("charter write is stale or lacks an exact CAS record")
        if (
            prior.project_id != charter.project_id
            or prior.charter_id != charter.charter_id
            or prior.revision != charter.revision
            or charter_approval_digest(prior) != charter_approval_digest(charter)
        ):
            raise PermissionError("charter identity and approved content are immutable")
        if (
            prior.status != CharterStatus.DRAFT
            or charter.status != CharterStatus.PROPOSED
        ):
            raise PermissionError(
                f"repository rejected charter transition: "
                f"{prior.status} -> {charter.status}"
            )
        self._cas_entity(
            "project_charters",
            charter.charter_id,
            expected.to_dict(),
            charter.to_dict(),
        )

    def insert_approved_charter(self, charter: ProjectCharter) -> None:
        del charter
        raise PermissionError(
            "approved charters may only be created by the trusted approval transaction"
        )

    def create_charter_approval_challenge(
        self,
        *,
        project_id: str,
        charter_id: str,
        charter_revision: int,
    ) -> FounderApprovalChallenge:
        """Create a one-use challenge for explicit local-Founder confirmation."""
        requested = datetime.now(UTC)
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            charter_payload, _ = self._entity_in_transaction(
                connection, "project_charters", charter_id
            )
            charter = ProjectCharter.from_dict(charter_payload)
            if (
                charter.project_id != project_id
                or charter.revision != charter_revision
                or charter.status != CharterStatus.PROPOSED
            ):
                raise PermissionError(
                    "approval challenge requires the exact proposed charter"
                )
            self._require_no_newer_charter(
                connection, project_id, charter_revision
            )
            challenge = FounderApprovalChallenge(
                challenge_id=new_id("founder-challenge"),
                schema_version=2,
                project_id=project_id,
                charter_id=charter_id,
                charter_revision=charter_revision,
                charter_digest=charter_approval_digest(charter),
                approval_action=FounderApprovalIntent.APPROVE_CHARTER.value,
                approval_binding=None,
                nonce=secrets.token_hex(32),
                requested_at=requested.isoformat(),
                expires_at=(requested + timedelta(minutes=10)).isoformat(),
                state="PENDING",
                consumed_event_id=None,
            )
            self._insert_entity(
                connection,
                "executive_founder_approval_challenges",
                challenge.challenge_id,
                challenge.to_dict(),
            )
        return challenge

    def register_founder_session(
        self,
        *,
        challenge_id: str,
        confirmation: ApprovalConfirmation,
    ) -> FounderAuthenticatedSession:
        """Verify a separately produced proof and durably register its session."""
        authenticator = self._trusted_authenticator()
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            challenge_payload, _ = self._entity_in_transaction(
                connection,
                "executive_founder_approval_challenges",
                challenge_id,
            )
            challenge = FounderApprovalChallenge.from_dict(challenge_payload)
            if (
                challenge.state != "PENDING"
                or challenge.consumed_event_id is not None
                or datetime.fromisoformat(challenge.expires_at)
                <= datetime.now(UTC)
            ):
                raise PermissionError(
                    "Founder approval challenge is stale or consumed"
                )
            session = authenticator.verify(challenge, confirmation)
            self._insert_entity(
                connection,
                "executive_founder_authenticated_sessions",
                session.session_id,
                session.to_dict(),
            )
        return session

    def revoke_founder_session(self, session_id: str) -> None:
        timestamp = utc_now()
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            payload, payload_hash = self._entity_in_transaction(
                connection,
                "executive_founder_authenticated_sessions",
                session_id,
            )
            session = FounderAuthenticatedSession.from_dict(payload)
            if session.state != "ACTIVE":
                raise PermissionError("Founder session is not revocable")
            revoked = replace(
                session, state="REVOKED", revoked_at=timestamp
            )
            self._update_entity_cas(
                connection,
                "executive_founder_authenticated_sessions",
                session_id,
                payload_hash,
                revoked.to_dict(),
            )

    def approve_charter(
        self,
        *,
        project_id: str,
        charter_id: str,
        charter_revision: int,
        approver: str,
        source_interaction_id: str,
    ) -> tuple[ProjectCharter, ApprovalRecord]:
        del (
            project_id,
            charter_id,
            charter_revision,
            approver,
            source_interaction_id,
        )
        raise PermissionError(
            "caller identities and conversation rows cannot approve charters"
        )

    def confirm_charter_approval(
        self,
        *,
        challenge_id: str,
        confirmation: ApprovalConfirmation | None = None,
        explicit_intent: FounderApprovalIntent,
    ) -> tuple[ProjectCharter, ApprovalRecord, FounderApprovalEvent]:
        """Consume one explicit Founder challenge and approve atomically."""
        if (
            explicit_intent is not FounderApprovalIntent.APPROVE_CHARTER
            or confirmation is None
        ):
            raise PermissionError("explicit charter approval intent is required")
        authenticator = self._trusted_authenticator()
        timestamp = utc_now()
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            challenge_payload, challenge_hash = self._entity_in_transaction(
                connection,
                "executive_founder_approval_challenges",
                challenge_id,
            )
            challenge = FounderApprovalChallenge.from_dict(
                challenge_payload
            )
            if (
                challenge.state != "PENDING"
                or challenge.consumed_event_id is not None
                or challenge.approval_action != explicit_intent
                or datetime.fromisoformat(challenge.expires_at)
                <= datetime.now(UTC)
            ):
                raise PermissionError(
                    "Founder approval challenge is stale or consumed"
                )
            verified_session = authenticator.verify(challenge, confirmation)
            try:
                session_payload, session_hash = self._entity_in_transaction(
                    connection,
                    "executive_founder_authenticated_sessions",
                    verified_session.session_id,
                )
            except KeyError as error:
                raise PermissionError(
                    "authenticated Founder session is not registered"
                ) from error
            session = FounderAuthenticatedSession.from_dict(session_payload)
            if (
                session != verified_session
                or session.state != "ACTIVE"
                or session.revoked_at is not None
                or session.consumed_at is not None
                or datetime.fromisoformat(session.expires_at)
                <= datetime.now(UTC)
            ):
                raise PermissionError(
                    "authenticated Founder session is stale or revoked"
                )
            project_id = challenge.project_id
            charter_id = challenge.charter_id
            charter_revision = challenge.charter_revision
            try:
                charter_payload, charter_hash = self._entity_in_transaction(
                    connection, "project_charters", charter_id
                )
            except KeyError as error:
                raise PermissionError(
                    "proposed charter is unavailable"
                ) from error
            charter = ProjectCharter.from_dict(charter_payload)
            if (
                charter.project_id != project_id
                or charter.revision != charter_revision
                or charter.status != CharterStatus.PROPOSED
            ):
                raise PermissionError(
                    "approval does not identify the current proposed charter"
                )
            self._require_no_newer_charter(
                connection, project_id, charter_revision
            )
            if (
                challenge.charter_digest
                != charter_approval_digest(charter)
            ):
                raise PermissionError(
                    "approval challenge no longer matches the proposed charter"
                )
            event_id = new_id("founder-approval-event")
            event = FounderApprovalEvent(
                event_id=event_id,
                schema_version=2,
                authenticated_identity=session.principal_sid,
                authentication_method=session.authentication_method,
                authenticated_account=session.account_name,
                authenticated_session_id=session.session_id,
                machine_identity=session.machine_identity,
                application_identity=session.application_identity,
                project_id=project_id,
                charter_id=charter_id,
                charter_revision=charter_revision,
                charter_digest=challenge.charter_digest,
                approval_action=explicit_intent.value,
                explicit_intent=explicit_intent.value,
                challenge_id=challenge.challenge_id,
                challenge_response_digest=confirmation_response_digest(
                    confirmation
                ),
                proof_version=confirmation.proof_version,
                source_user_interaction_id=(
                    confirmation.source_user_interaction_id
                ),
                confirmed_at=timestamp,
                expires_at=charter.authority_envelope.expires_at,
            )
            approval_id = new_id("approval")
            charter_digest = charter_approval_digest(charter)
            approval = ApprovalRecord(
                approval_id,
                project_id,
                charter_id,
                charter_revision,
                "CHARTER_DURATION",
                None,
                session.principal_sid,
                charter.deliverables,
                {
                    "authentication_method": session.authentication_method,
                    "authenticated_session_id": session.session_id,
                    "approval_event_digest": canonical_digest(
                        event.to_dict()
                    ),
                    "delegation_mode": charter.delegation_mode,
                    "maximum_cost": charter.budget_limit,
                },
                timestamp,
                charter.authority_envelope.expires_at,
                None,
                None,
                charter_digest,
                event_id,
            )
            event_digest = canonical_digest(event.to_dict())
            approval_digest = canonical_digest(approval.to_dict())
            self._insert_entity(
                connection,
                "executive_founder_approval_events",
                event_id,
                event.to_dict(),
            )
            self._insert_entity(
                connection,
                "executive_approvals",
                approval_id,
                approval.to_dict(),
            )
            self._insert_relation(
                connection,
                project_id,
                "charter",
                charter_id,
                "approval",
                approval_id,
            )
            consumed_challenge = replace(
                challenge,
                state="CONSUMED",
                consumed_event_id=event_id,
            )
            self._update_entity_cas(
                connection,
                "executive_founder_approval_challenges",
                challenge.challenge_id,
                challenge_hash,
                consumed_challenge.to_dict(),
            )
            consumed_session = replace(
                session, state="CONSUMED", consumed_at=timestamp
            )
            self._update_entity_cas(
                connection,
                "executive_founder_authenticated_sessions",
                session.session_id,
                session_hash,
                consumed_session.to_dict(),
            )
            # Re-read the complete durable approval chain before the
            # purpose-bound issuer is allowed to create a capability.
            durable_event = FounderApprovalEvent.from_dict(
                self._entity_in_transaction(
                    connection, "executive_founder_approval_events", event_id
                )[0]
            )
            durable_approval = ApprovalRecord.from_dict(
                self._entity_in_transaction(
                    connection, "executive_approvals", approval_id
                )[0]
            )
            durable_challenge = FounderApprovalChallenge.from_dict(
                self._entity_in_transaction(
                    connection,
                    "executive_founder_approval_challenges",
                    challenge.challenge_id,
                )[0]
            )
            durable_session = FounderAuthenticatedSession.from_dict(
                self._entity_in_transaction(
                    connection,
                    "executive_founder_authenticated_sessions",
                    session.session_id,
                )[0]
            )
            if (
                durable_event != event
                or durable_approval != approval
                or durable_challenge != consumed_challenge
                or durable_session != consumed_session
            ):
                raise PermissionError(
                    "durable Founder approval state changed before capability issue"
                )
            capability_expiration = datetime.fromisoformat(timestamp) + timedelta(
                minutes=15
            )
            if charter.authority_envelope.expires_at is not None:
                capability_expiration = min(
                    capability_expiration,
                    datetime.fromisoformat(
                        charter.authority_envelope.expires_at
                    ),
                )
            if capability_expiration <= datetime.fromisoformat(timestamp):
                raise PermissionError("Founder capability expiration is stale")
            capability = authenticator.issue_authorization_capability(
                FounderCapabilityClaims(
                    capability_id=new_id("founder-capability"),
                    project_id=project_id,
                    charter_id=charter_id,
                    charter_revision=charter_revision,
                    authorization_kind="PROJECT_LAUNCH",
                    protected_action="DELEGATE_CHARTER",
                    action_digest=charter_digest,
                    approval_digest=approval_digest,
                    approval_event_digest=event_digest,
                    founder_principal_sid=session.principal_sid,
                    founder_authenticated_session_id=session.session_id,
                    approval_event_id=event_id,
                    approval_record_id=approval_id,
                    challenge_id=challenge.challenge_id,
                    challenge_proof_digest=event.challenge_response_digest,
                    authorization_generation=charter_revision,
                    revocation_epoch=charter_revision - 1,
                    issued_at=timestamp,
                    expires_at=capability_expiration.isoformat(),
                    usage="ONE_TIME_GENERATION",
                    machine_identity=session.machine_identity,
                    application_identity=session.application_identity,
                ),
                confirmation,
            )
            capability_value = capability.to_dict()
            capability_value_digest = capability_digest(capability)
            self._insert_entity(
                connection,
                "executive_founder_authorization_capabilities",
                capability.capability_id,
                capability_value,
            )
            approved = replace(
                charter,
                status=CharterStatus.APPROVED.value,
                founder_approval_identity=session.principal_sid,
                founder_approval_record_id=approval_id,
                founder_approval_event_id=event_id,
                founder_approval_event_digest=event_digest,
                founder_authenticated_session_id=session.session_id,
                founder_authorization_capability=capability_value,
                founder_authorization_capability_digest=(
                    capability_value_digest
                ),
                updated_at=timestamp,
            )
            self._update_entity_cas(
                connection,
                "project_charters",
                charter_id,
                charter_hash,
                approved.to_dict(),
            )
        return approved, approval, event

    def activate_charter(
        self,
        *,
        project_id: str,
        charter_id: str,
        charter_revision: int,
    ) -> tuple[ProjectRecord, ProjectCharter, ApprovalRecord]:
        """Reload and activate one exactly approved durable charter revision."""
        timestamp = utc_now()
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            project_payload, project_hash = self._entity_in_transaction(
                connection, "executive_projects", project_id
            )
            project = ProjectRecord.from_dict(project_payload)
            charter_payload, charter_hash = self._entity_in_transaction(
                connection, "project_charters", charter_id
            )
            charter = ProjectCharter.from_dict(charter_payload)
            if (
                charter.project_id != project_id
                or charter.revision != charter_revision
                or charter.status != CharterStatus.APPROVED
            ):
                raise PermissionError(
                    "activation does not identify the durable approved charter"
                )
            if charter.unresolved_questions:
                raise PermissionError(
                    "material unresolved questions block charter activation"
                )
            self._require_no_newer_charter(
                connection, project_id, charter_revision
            )
            approval_id = charter.founder_approval_record_id
            if approval_id is None:
                raise PermissionError("charter approval record is missing")
            try:
                approval_payload, _ = self._entity_in_transaction(
                    connection, "executive_approvals", approval_id
                )
            except KeyError as error:
                raise PermissionError(
                    "charter approval record is unavailable"
                ) from error
            approval = ApprovalRecord.from_dict(approval_payload)
            event_payload, _ = self._entity_in_transaction(
                connection,
                "executive_founder_approval_events",
                approval.source_interaction_id,
            )
            event = FounderApprovalEvent.from_dict(event_payload)
            challenge_payload, _ = self._entity_in_transaction(
                connection,
                "executive_founder_approval_challenges",
                event.challenge_id,
            )
            session_payload, _ = self._entity_in_transaction(
                connection,
                "executive_founder_authenticated_sessions",
                event.authenticated_session_id,
            )
            capability_value = charter.founder_authorization_capability
            if not isinstance(capability_value, dict):
                raise PermissionError("Founder authorization capability is missing")
            capability = self._trusted_authenticator().verify_authorization_capability(
                capability_value
            )
            stored_capability, _ = self._entity_in_transaction(
                connection,
                "executive_founder_authorization_capabilities",
                capability.capability_id,
            )
            if (
                stored_capability != capability_value
                or charter.founder_authorization_capability_digest
                != capability_digest(capability)
            ):
                raise PermissionError(
                    "Founder authorization capability storage is invalid"
                )
            self._validate_charter_approval(
                charter,
                approval,
                event,
                FounderApprovalChallenge.from_dict(challenge_payload),
                FounderAuthenticatedSession.from_dict(session_payload),
                capability,
                timestamp,
            )
            current_state = ExecutiveState(project.state)
            if ExecutiveState.ACTIVE not in PROJECT_TRANSITIONS[current_state]:
                raise PermissionError(
                    f"project state {current_state} cannot activate a charter"
                )
            active_charter = replace(
                charter,
                status=CharterStatus.ACTIVE.value,
                updated_at=timestamp,
            )
            active_project = replace(
                project,
                state=ExecutiveState.ACTIVE.value,
                active_charter_id=charter_id,
                active_charter_revision=charter_revision,
                pause_reason=None,
                updated_at=timestamp,
            )
            self._update_entity_cas(
                connection,
                "project_charters",
                charter_id,
                charter_hash,
                active_charter.to_dict(),
            )
            self._update_entity_cas(
                connection,
                "executive_projects",
                project_id,
                project_hash,
                active_project.to_dict(),
            )
        return active_project, active_charter, approval

    def charter(self, charter_id: str) -> ProjectCharter:
        return ProjectCharter.from_dict(self._required("project_charters", charter_id))

    def charters(self, project_id: str) -> list[ProjectCharter]:
        values = [
            ProjectCharter.from_dict(item)
            for item in self.__store.list("project_charters")
            if item.get("project_id") == project_id
        ]
        return sorted(values, key=lambda item: item.revision)

    def save_workflow(self, workflow: WorkflowRecord) -> None:
        project = self.project(workflow.project_id)
        charter = self.charter(workflow.charter_id)
        if (
            charter.project_id != workflow.project_id
            or charter.revision != workflow.charter_revision
            or project.active_charter_id != workflow.charter_id
            or project.active_charter_revision != workflow.charter_revision
        ):
            raise PermissionError("workflow parent-child ownership is invalid")
        self._insert_trusted_entity(
            "executive_workflows", workflow.workflow_id, workflow.to_dict()
        )
        self._relate(workflow.project_id, "charter", workflow.charter_id, "workflow", workflow.workflow_id)

    def workflows(self, project_id: str) -> list[WorkflowRecord]:
        return [
            WorkflowRecord.from_dict(item)
            for item in self.__store.list("executive_workflows")
            if item.get("project_id") == project_id
        ]

    def save_task(
        self,
        task: ExecutiveTask,
        *,
        expected: ExecutiveTask | None = None,
    ) -> None:
        from keeper.executive.authority import validate_durable_task_effects

        validate_durable_task_effects(task)
        existing = self.__store.get("executive_tasks", task.task_id)
        if existing is None:
            if task.status != TaskStatus.PROPOSED or task.revision != 1:
                raise PermissionError(
                    "new tasks must begin proposed at revision one"
                )
            self._validate_task_parentage(task)
            self._insert_trusted_entity(
                "executive_tasks", task.task_id, task.to_dict()
            )
            self._relate(
                task.project_id,
                "workflow",
                task.workflow_id,
                "task",
                task.task_id,
            )
            return
        prior = ExecutiveTask.from_dict(existing)
        if expected is None or prior != expected:
            raise PermissionError("task write is stale or lacks exact CAS")
        current = TaskStatus(prior.status)
        target = TaskStatus(task.status)
        if (
            task.revision != prior.revision + 1
            or target not in TASK_TRANSITIONS[current]
            or task.project_id != prior.project_id
            or task.charter_id != prior.charter_id
            or task.charter_revision != prior.charter_revision
            or task.workflow_id != prior.workflow_id
            or task_definition_digest(task)
            != task_definition_digest(prior)
        ):
            raise PermissionError(
                f"repository rejected task transition: {current} -> {target}"
            )
        self._cas_entity(
            "executive_tasks",
            task.task_id,
            expected.to_dict(),
            task.to_dict(),
        )

    def claim_execution(
        self,
        task_id: str,
        *,
        expected_revision: int,
        plan: dict[str, Any],
        action: ProposedAction,
        approval_id: str | None,
    ) -> ExecutiveTask:
        """Give one worker a durable attempt binding before Authority launch."""
        attempt_id = str(plan["authority_attempt_id"])
        timestamp = utc_now()
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task_payload, task_hash = self._entity_in_transaction(
                connection, "executive_tasks", task_id
            )
            task = ExecutiveTask.from_dict(task_payload)
            if (
                task.revision != expected_revision
                or task.status
                not in {TaskStatus.READY, TaskStatus.REPAIR_REQUIRED}
                or task.authority_attempt_id is not None
                or plan.get("project_id") != task.project_id
                or plan.get("charter_id") != task.charter_id
                or plan.get("charter_revision") != task.charter_revision
                or plan.get("workflow_id") != task.workflow_id
                or plan.get("task_id") != task.task_id
                or plan.get("task_revision") != task.revision
            ):
                raise PermissionError("task execution claim is stale or misbound")
            project_payload, _ = self._entity_in_transaction(
                connection, "executive_projects", task.project_id
            )
            project = ProjectRecord.from_dict(project_payload)
            charter_payload, _ = self._entity_in_transaction(
                connection, "project_charters", task.charter_id
            )
            charter = ProjectCharter.from_dict(charter_payload)
            if (
                project.state != ExecutiveState.EXECUTING
                or project.active_charter_id != task.charter_id
                or project.active_charter_revision != task.charter_revision
                or charter.status != CharterStatus.ACTIVE
            ):
                raise PermissionError("project is not launchable")
            if (
                action.project_id != task.project_id
                or action.charter_revision != task.charter_revision
                or action.trusted_source != "DURABLE_WORKFLOW_TASK"
            ):
                raise PermissionError(
                    "execution claim action facts are misbound"
                )
            budget_reservation_id: str | None = None
            if approval_id is not None:
                _, budget_reservation_id = (
                    self._consume_action_authority_in_transaction(
                        connection,
                        action,
                        approval_id,
                        task.task_id,
                        timestamp,
                    )
                )
            elif (
                action.spending
                or action.cost is None
                or (action.cost or 0) > 0
            ):
                raise PermissionError(
                    "spending claim lacks a bound action approval"
                )
            claimed = replace(
                task,
                provider_id=str(plan["provider_id"]),
                model_id=str(plan["model_id"]),
                session_id=str(plan["session_id"]),
                status=TaskStatus.LAUNCH_CLAIMED.value,
                authority_attempt_id=attempt_id,
                revision=task.revision + 1,
                attempt_history=task.attempt_history
                + (
                    {
                        "authority_attempt_id": attempt_id,
                        "state": "LAUNCH_CLAIMED",
                        "recorded_at": timestamp,
                    },
                ),
                updated_at=timestamp,
            )
            attempt_record = {
                **plan,
                "state": "LAUNCH_CLAIMED",
                "created_at": timestamp,
                "updated_at": timestamp,
                "completion_digest": None,
                "artifact_digest": None,
                "action_id": action.action_id,
                "approval_id": approval_id,
                "budget_reservation_id": budget_reservation_id,
            }
            self._insert_entity(
                connection,
                "executive_execution_attempts",
                attempt_id,
                attempt_record,
            )
            self._insert_relation(
                connection,
                task.project_id,
                "task",
                task.task_id,
                "authority_attempt",
                attempt_id,
            )
            self._update_entity_cas(
                connection,
                "executive_tasks",
                task.task_id,
                task_hash,
                claimed.to_dict(),
            )
        return claimed

    def transition_execution(
        self,
        task_id: str,
        *,
        expected_revision: int,
        expected_status: TaskStatus,
        target_status: TaskStatus,
        attempt_state: str,
    ) -> ExecutiveTask:
        timestamp = utc_now()
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task_payload, task_hash = self._entity_in_transaction(
                connection, "executive_tasks", task_id
            )
            task = ExecutiveTask.from_dict(task_payload)
            if (
                task.revision != expected_revision
                or task.status != expected_status
                or target_status not in TASK_TRANSITIONS[expected_status]
                or task.authority_attempt_id is None
            ):
                raise PermissionError("execution transition is stale")
            attempt_payload, attempt_hash = self._entity_in_transaction(
                connection,
                "executive_execution_attempts",
                task.authority_attempt_id,
            )
            updated_task = replace(
                task,
                status=target_status.value,
                revision=task.revision + 1,
                updated_at=timestamp,
            )
            updated_attempt = {
                **attempt_payload,
                "state": attempt_state,
                "updated_at": timestamp,
            }
            self._update_entity_cas(
                connection,
                "executive_tasks",
                task.task_id,
                task_hash,
                updated_task.to_dict(),
            )
            self._update_entity_cas(
                connection,
                "executive_execution_attempts",
                task.authority_attempt_id,
                attempt_hash,
                updated_attempt,
            )
        return updated_task

    def release_prelaunch_execution_claim(
        self,
        task_id: str,
        *,
        expected_revision: int,
    ) -> ExecutiveTask:
        """Release local authority only when no Authority attempt was created."""
        timestamp = utc_now()
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task_payload, task_hash = self._entity_in_transaction(
                connection, "executive_tasks", task_id
            )
            task = ExecutiveTask.from_dict(task_payload)
            if (
                task.revision != expected_revision
                or task.status != TaskStatus.LAUNCH_CLAIMED
                or task.authority_attempt_id is None
            ):
                raise PermissionError("prelaunch claim release is stale")
            attempt_payload, attempt_hash = self._entity_in_transaction(
                connection,
                "executive_execution_attempts",
                task.authority_attempt_id,
            )
            if attempt_payload.get("state") != "LAUNCH_CLAIMED":
                raise PermissionError("launch boundary was already crossed")
            reservation_id = attempt_payload.get("budget_reservation_id")
            if isinstance(reservation_id, str):
                cursor = connection.execute(
                    "UPDATE executive_budget_reservations SET state='RELEASED' "
                    "WHERE reservation_id=? AND state='RESERVED'",
                    (reservation_id,),
                )
                if cursor.rowcount != 1:
                    raise PermissionError("budget hold is not releasable")
            approval_id = attempt_payload.get("approval_id")
            if isinstance(approval_id, str):
                approval_payload, approval_hash = self._entity_in_transaction(
                    connection, "executive_approvals", approval_id
                )
                approval = ApprovalRecord.from_dict(approval_payload)
                if approval.kind == ApprovalKind.ONE_TIME:
                    consumption = connection.execute(
                        "SELECT task_id,action_id FROM "
                        "executive_approval_consumptions WHERE approval_id=?",
                        (approval_id,),
                    ).fetchone()
                    if (
                        consumption is None
                        or consumption["task_id"] != task.task_id
                        or consumption["action_id"]
                        != attempt_payload.get("action_id")
                    ):
                        raise PermissionError(
                            "one-time approval consumption is not releasable"
                        )
                    connection.execute(
                        "DELETE FROM executive_approval_consumptions "
                        "WHERE approval_id=?",
                        (approval_id,),
                    )
                    self._update_entity_cas(
                        connection,
                        "executive_approvals",
                        approval_id,
                        approval_hash,
                        replace(approval, consumed_at=None).to_dict(),
                    )
            released_attempt = {
                **attempt_payload,
                "state": "PRELAUNCH_RELEASED",
                "updated_at": timestamp,
            }
            released_task = replace(
                task,
                provider_id=None,
                model_id=None,
                session_id=None,
                status=TaskStatus.READY.value,
                authority_attempt_id=None,
                revision=task.revision + 1,
                result_disposition="PRELAUNCH_AUTHORITY_RELEASED",
                attempt_history=task.attempt_history
                + (
                    {
                        "authority_attempt_id": task.authority_attempt_id,
                        "state": "PRELAUNCH_RELEASED",
                        "recorded_at": timestamp,
                    },
                ),
                updated_at=timestamp,
            )
            self._update_entity_cas(
                connection,
                "executive_execution_attempts",
                task.authority_attempt_id,
                attempt_hash,
                released_attempt,
            )
            self._update_entity_cas(
                connection,
                "executive_tasks",
                task.task_id,
                task_hash,
                released_task.to_dict(),
            )
        return released_task

    def mark_execution_waiting_for_usage(
        self,
        task_id: str,
        *,
        expected_revision: int,
        reason: str,
    ) -> ExecutiveTask:
        """Persist a known pre-provider usage pause and release uncrossed budget."""
        timestamp = utc_now()
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task_payload, task_hash = self._entity_in_transaction(
                connection, "executive_tasks", task_id
            )
            task = ExecutiveTask.from_dict(task_payload)
            if (
                task.revision != expected_revision
                or task.status
                not in {
                    TaskStatus.EXECUTION_STARTED,
                    TaskStatus.RUNNING,
                    TaskStatus.UNCERTAIN,
                }
                or task.authority_attempt_id is None
            ):
                raise PermissionError("usage-wait transition is stale")
            attempt_payload, attempt_hash = self._entity_in_transaction(
                connection,
                "executive_execution_attempts",
                task.authority_attempt_id,
            )
            if attempt_payload.get("subscription_contract") is not True:
                raise PermissionError(
                    "usage-wait release is limited to included subscriptions"
                )
            reservation_id = attempt_payload.get("budget_reservation_id")
            if isinstance(reservation_id, str):
                connection.execute(
                    "UPDATE executive_budget_reservations SET state='RELEASED' "
                    "WHERE reservation_id=? AND state IN ('RESERVED','CROSSED')",
                    (reservation_id,),
                )
            waiting_attempt = {
                **attempt_payload,
                "state": "WAITING_FOR_USAGE_RESET",
                "updated_at": timestamp,
            }
            waiting_task = replace(
                task,
                status=TaskStatus.WAITING.value,
                result_disposition="AUTHORITY_WAITING_FOR_USAGE_RESET",
                revision=task.revision + 1,
                attempt_history=task.attempt_history
                + (
                    {
                        "authority_attempt_id": task.authority_attempt_id,
                        "state": "WAITING_FOR_USAGE_RESET",
                        "reason": reason,
                        "recorded_at": timestamp,
                    },
                ),
                updated_at=timestamp,
            )
            self._update_entity_cas(
                connection,
                "executive_execution_attempts",
                task.authority_attempt_id,
                attempt_hash,
                waiting_attempt,
            )
            self._update_entity_cas(
                connection,
                "executive_tasks",
                task.task_id,
                task_hash,
                waiting_task.to_dict(),
            )
        return waiting_task

    def accept_author_completion(
        self,
        task_id: str,
        *,
        expected_revision: int,
        result: dict[str, Any],
    ) -> ExecutiveTask:
        """Import one authenticated Authority completion without reviving cancel."""
        timestamp = utc_now()
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task_payload, task_hash = self._entity_in_transaction(
                connection, "executive_tasks", task_id
            )
            task = ExecutiveTask.from_dict(task_payload)
            project_payload, _ = self._entity_in_transaction(
                connection, "executive_projects", task.project_id
            )
            project = ProjectRecord.from_dict(project_payload)
            attempt_id = str(result.get("authority_attempt_id", ""))
            if (
                task.authority_attempt_id != attempt_id
                or result.get("task_id") != task.task_id
                or result.get("authenticated") is not True
            ):
                raise PermissionError("completion does not bind to the task attempt")
            attempt_payload, attempt_hash = self._entity_in_transaction(
                connection, "executive_execution_attempts", attempt_id
            )
            if (
                attempt_payload.get("state") == "COMPLETED"
                and task.status
                in {
                    TaskStatus.REVIEW_REQUIRED,
                    TaskStatus.REPAIR_REQUIRED,
                    TaskStatus.COMPLETED,
                    TaskStatus.FAILED,
                }
                and attempt_payload.get("completion_digest")
                == result.get("completion_digest")
            ):
                return task
            late = (
                project.state == ExecutiveState.CANCELED
                or task.status == TaskStatus.CANCELED
            )
            if late:
                late_id = f"late-result:{attempt_id}"
                late_payload = {
                    **result,
                    "project_id": task.project_id,
                    "original_task_id": task.task_id,
                    "recorded_at": timestamp,
                    "task_state": task.status,
                    "project_state": project.state,
                }
                try:
                    self._insert_entity(
                        connection,
                        "executive_late_results",
                        late_id,
                        late_payload,
                    )
                except PermissionError:
                    pass
                recorded = replace(
                    task,
                    late_result=True,
                    revision=task.revision + 1,
                    updated_at=timestamp,
                )
                self._update_entity_cas(
                    connection,
                    "executive_tasks",
                    task.task_id,
                    task_hash,
                    recorded.to_dict(),
                )
                return recorded
            if (
                task.revision != expected_revision
                or task.status
                not in {
                    TaskStatus.EXECUTION_STARTED,
                    TaskStatus.RUNNING,
                    TaskStatus.COMPLETION_PENDING,
                    TaskStatus.UNCERTAIN,
                }
            ):
                raise PermissionError("completion import is stale")
            terminal = result.get("terminal_disposition")
            if terminal != "SUCCEEDED":
                failed_attempt = {
                    **attempt_payload,
                    "state": str(terminal or "UNCERTAIN"),
                    "completion_digest": result.get("completion_digest"),
                    "evidence_digest": result.get("evidence_digest"),
                    "updated_at": timestamp,
                }
                target = (
                    TaskStatus.CANCELED
                    if terminal == "CANCELED"
                    else (
                        TaskStatus.WAITING
                        if terminal == "WAITING_FOR_USAGE_RESET"
                        else TaskStatus.FAILED
                    )
                )
                failed = replace(
                    task,
                    status=target.value,
                    result_disposition=f"AUTHORITY_{terminal or 'UNCERTAIN'}",
                    revision=task.revision + 1,
                    attempt_history=task.attempt_history
                    + (
                        {
                            "authority_attempt_id": attempt_id,
                            "state": str(terminal or "UNCERTAIN"),
                            "completion_digest": result.get("completion_digest"),
                            "recorded_at": timestamp,
                        },
                    ),
                    updated_at=timestamp,
                )
                self._update_entity_cas(
                    connection,
                    "executive_execution_attempts",
                    attempt_id,
                    attempt_hash,
                    failed_attempt,
                )
                self._update_entity_cas(
                    connection,
                    "executive_tasks",
                    task.task_id,
                    task_hash,
                    failed.to_dict(),
                )
                return failed
            artifact_digest = result.get("artifact_digest")
            if (
                not isinstance(artifact_digest, str)
                or len(artifact_digest) != 64
                or not isinstance(result.get("artifact_identity"), str)
                or not isinstance(result.get("artifact_files"), (list, tuple))
                or not result.get("artifact_files")
                or not isinstance(result.get("evidence_digest"), str)
            ):
                raise PermissionError("successful completion has no authenticated artifact")
            completed_attempt = {
                **attempt_payload,
                "state": "COMPLETED",
                "completion_digest": result["completion_digest"],
                "artifact_digest": artifact_digest,
                "artifact_identity": result["artifact_identity"],
                "artifact_files": list(result["artifact_files"]),
                "evidence_digest": result["evidence_digest"],
                "updated_at": timestamp,
            }
            imported = replace(
                task,
                status=TaskStatus.REVIEW_REQUIRED.value,
                artifact_digest=artifact_digest,
                revision=task.revision + 1,
                result_disposition="AUTHORITY_COMPLETED",
                attempt_history=task.attempt_history
                + (
                    {
                        "authority_attempt_id": attempt_id,
                        "state": "COMPLETED",
                        "artifact_digest": artifact_digest,
                        "completion_digest": result["completion_digest"],
                        "recorded_at": timestamp,
                    },
                ),
                updated_at=timestamp,
            )
            self._update_entity_cas(
                connection,
                "executive_execution_attempts",
                attempt_id,
                attempt_hash,
                completed_attempt,
            )
            self._update_entity_cas(
                connection,
                "executive_tasks",
                task.task_id,
                task_hash,
                imported.to_dict(),
            )
        return imported

    def mark_execution_uncertain(
        self,
        task_id: str,
        *,
        expected_revision: int,
        reason: str,
    ) -> ExecutiveTask:
        task = self.task(task_id)
        if task.revision != expected_revision:
            raise PermissionError("uncertain execution write is stale")
        if TaskStatus.UNCERTAIN not in TASK_TRANSITIONS[TaskStatus(task.status)]:
            raise PermissionError("task cannot become uncertain")
        uncertain = replace(
            task,
            status=TaskStatus.UNCERTAIN.value,
            result_disposition=reason,
            revision=task.revision + 1,
            updated_at=utc_now(),
        )
        self.save_task(uncertain, expected=task)
        return uncertain

    def execution_attempt(self, attempt_id: str) -> dict[str, Any]:
        return self._required("executive_execution_attempts", attempt_id)

    def claim_review(
        self,
        task_id: str,
        *,
        expected_revision: int,
        plan: dict[str, Any],
    ) -> ExecutiveTask:
        timestamp = utc_now()
        review_attempt_id = str(plan["authority_attempt_id"])
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task_payload, task_hash = self._entity_in_transaction(
                connection, "executive_tasks", task_id
            )
            task = ExecutiveTask.from_dict(task_payload)
            if (
                task.revision != expected_revision
                or task.status != TaskStatus.REVIEW_REQUIRED
                or task.artifact_digest is None
                or task.review_attempt_id is not None
                or plan.get("artifact_revision_digest")
                != task.artifact_digest
                or plan.get("project_id") != task.project_id
                or plan.get("charter_id") != task.charter_id
                or plan.get("charter_revision") != task.charter_revision
                or plan.get("workflow_id") != task.workflow_id
                or plan.get("session_id") == task.session_id
                or review_attempt_id == task.authority_attempt_id
            ):
                raise PermissionError("review claim is stale or not independent")
            review_record = {
                "review_attempt_id": review_attempt_id,
                "review_task_id": plan["task_id"],
                "project_id": task.project_id,
                "charter_id": task.charter_id,
                "charter_revision": task.charter_revision,
                "workflow_id": task.workflow_id,
                "task_id": task.task_id,
                "task_revision": task.revision,
                "artifact_revision_digest": task.artifact_digest,
                "author_attempt_id": task.authority_attempt_id,
                "author_provider_id": task.provider_id,
                "author_session_id": task.session_id,
                "reviewer_provider_id": plan["provider_id"],
                "reviewer_model_id": plan["model_id"],
                "reviewer_session_id": plan["session_id"],
                "reviewer_registration_id": plan["registration_id"],
                "reviewer_qualification_id": plan["qualification_id"],
                "state": "LAUNCH_CLAIMED",
                "findings_digest": None,
                "disposition": None,
                "created_at": timestamp,
                "updated_at": timestamp,
                "plan": plan,
            }
            claimed = replace(
                task,
                review_attempt_id=review_attempt_id,
                revision=task.revision + 1,
                updated_at=timestamp,
            )
            self._insert_entity(
                connection,
                "executive_reviews",
                review_attempt_id,
                review_record,
            )
            self._insert_relation(
                connection,
                task.project_id,
                "task",
                task.task_id,
                "review_attempt",
                review_attempt_id,
            )
            self._update_entity_cas(
                connection,
                "executive_tasks",
                task.task_id,
                task_hash,
                claimed.to_dict(),
            )
        return claimed

    def transition_review(
        self,
        review_attempt_id: str,
        *,
        expected_state: str,
        target_state: str,
    ) -> None:
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            payload, payload_hash = self._entity_in_transaction(
                connection, "executive_reviews", review_attempt_id
            )
            if payload.get("state") != expected_state:
                raise PermissionError("review transition is stale")
            self._update_entity_cas(
                connection,
                "executive_reviews",
                review_attempt_id,
                payload_hash,
                {
                    **payload,
                    "state": target_state,
                    "updated_at": utc_now(),
                },
            )

    def accept_review_completion(
        self,
        task_id: str,
        *,
        expected_revision: int,
        result: dict[str, Any],
    ) -> ExecutiveTask:
        timestamp = utc_now()
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task_payload, task_hash = self._entity_in_transaction(
                connection, "executive_tasks", task_id
            )
            task = ExecutiveTask.from_dict(task_payload)
            project_payload, _ = self._entity_in_transaction(
                connection, "executive_projects", task.project_id
            )
            project = ProjectRecord.from_dict(project_payload)
            if (
                (
                    project.state == ExecutiveState.CANCELED
                    or task.status == TaskStatus.CANCELED
                )
                and task.review_attempt_id is not None
                and result.get("authority_attempt_id")
                == task.review_attempt_id
                and result.get("authenticated") is True
            ):
                late_id = f"late-review:{task.review_attempt_id}"
                try:
                    self._insert_entity(
                        connection,
                        "executive_late_results",
                        late_id,
                        {
                            **result,
                            "project_id": task.project_id,
                            "original_task_id": task.task_id,
                            "history_kind": "LATE_REVIEW_RESULT",
                            "recorded_at": timestamp,
                        },
                    )
                except PermissionError:
                    pass
                recorded = replace(
                    task,
                    late_result=True,
                    revision=task.revision + 1,
                    updated_at=timestamp,
                )
                self._update_entity_cas(
                    connection,
                    "executive_tasks",
                    task.task_id,
                    task_hash,
                    recorded.to_dict(),
                )
                return recorded
            if (
                task.revision != expected_revision
                or task.status != TaskStatus.REVIEW_REQUIRED
                or task.review_attempt_id is None
                or result.get("authority_attempt_id")
                != task.review_attempt_id
                or result.get("authenticated") is not True
            ):
                raise PermissionError("review completion import is stale")
            review_payload, review_hash = self._entity_in_transaction(
                connection,
                "executive_reviews",
                task.review_attempt_id,
            )
            if (
                result.get("task_id")
                != review_payload.get("review_task_id")
                or result.get("session_id")
                != review_payload.get("reviewer_session_id")
                or result.get("registration_id")
                != review_payload.get("reviewer_registration_id")
            ):
                raise PermissionError("review completion identity binding is invalid")
            if result.get("terminal_disposition") != "SUCCEEDED":
                failed_review = {
                    **review_payload,
                    "state": str(
                        result.get("terminal_disposition") or "UNCERTAIN"
                    ),
                    "completion_digest": result.get("completion_digest"),
                    "evidence_digest": result.get("evidence_digest"),
                    "disposition": "INDETERMINATE",
                    "updated_at": timestamp,
                }
                failed_task = replace(
                    task,
                    status=(
                        TaskStatus.FAILED.value
                        if task.retry_count >= task.max_retries
                        else TaskStatus.REPAIR_REQUIRED.value
                    ),
                    provider_id=None,
                    model_id=None,
                    session_id=None,
                    authority_attempt_id=None,
                    artifact_digest=None,
                    review_attempt_id=None,
                    retry_count=task.retry_count + 1,
                    result_disposition=(
                        "INDEPENDENT_REVIEW_PROCESS_FAILED"
                    ),
                    revision=task.revision + 1,
                    updated_at=timestamp,
                )
                self._update_entity_cas(
                    connection,
                    "executive_reviews",
                    str(review_payload["review_attempt_id"]),
                    review_hash,
                    failed_review,
                )
                self._update_entity_cas(
                    connection,
                    "executive_tasks",
                    task.task_id,
                    task_hash,
                    failed_task.to_dict(),
                )
                return failed_task
            if (
                review_payload.get("state")
                not in {"EXECUTION_STARTED", "COMPLETION_PENDING", "UNCERTAIN"}
                or review_payload.get("reviewer_session_id")
                == review_payload.get("author_session_id")
                or review_payload.get("review_attempt_id")
                == review_payload.get("author_attempt_id")
                or review_payload.get("artifact_revision_digest")
                != task.artifact_digest
                or result.get("author_attempt_id")
                != review_payload.get("author_attempt_id")
                or result.get("artifact_digest") != task.artifact_digest
                or not isinstance(result.get("structured_review_digest"), str)
                or result.get("review_disposition")
                not in {
                    "ACCEPTED",
                    "REPAIR_REQUIRED",
                    "REJECTED",
                    "INDETERMINATE",
                }
            ):
                raise PermissionError(
                    "review completion independence or artifact binding is invalid"
                )
            accepted = result.get("review_disposition") == "ACCEPTED"
            review_updated = {
                **review_payload,
                "state": "COMPLETED",
                "findings_digest": result["structured_review_digest"],
                "completion_digest": result["completion_digest"],
                "evidence_digest": result["evidence_digest"],
                "disposition": result["review_disposition"],
                "updated_at": timestamp,
            }
            if accepted:
                disposition = replace(
                    task,
                    status=TaskStatus.COMPLETED.value,
                    result_disposition="INDEPENDENT_REVIEW_ACCEPTED",
                    revision=task.revision + 1,
                    updated_at=timestamp,
                )
            elif task.retry_count >= task.max_retries:
                disposition = replace(
                    task,
                    status=TaskStatus.FAILED.value,
                    result_disposition="RETRY_LIMIT_EXCEEDED",
                    revision=task.revision + 1,
                    updated_at=timestamp,
                )
            else:
                disposition = replace(
                    task,
                    status=TaskStatus.REPAIR_REQUIRED.value,
                    provider_id=None,
                    model_id=None,
                    session_id=None,
                    authority_attempt_id=None,
                    artifact_digest=None,
                    review_attempt_id=None,
                    retry_count=task.retry_count + 1,
                    result_disposition="INDEPENDENT_REVIEW_REPAIR_REQUIRED",
                    revision=task.revision + 1,
                    updated_at=timestamp,
                )
            self._update_entity_cas(
                connection,
                "executive_reviews",
                task.review_attempt_id,
                review_hash,
                review_updated,
            )
            self._update_entity_cas(
                connection,
                "executive_tasks",
                task.task_id,
                task_hash,
                disposition.to_dict(),
            )
        return disposition

    def complete_automated_review(
        self,
        task_id: str,
        *,
        expected_revision: int,
    ) -> ExecutiveTask:
        task = self.task(task_id)
        if (
            task.revision != expected_revision
            or task.status != TaskStatus.REVIEW_REQUIRED
            or task.artifact_digest is None
            or any(
                "independent" in item.casefold()
                for item in task.review_requirements
            )
        ):
            raise PermissionError("local review cannot complete this task")
        completed = replace(
            task,
            status=TaskStatus.COMPLETED.value,
            result_disposition="AUTHORITY_EVIDENCE_ACCEPTED",
            revision=task.revision + 1,
            updated_at=utc_now(),
        )
        self.save_task(completed, expected=task)
        return completed

    def review(self, review_attempt_id: str) -> dict[str, Any]:
        return self._required("executive_reviews", review_attempt_id)

    def reviews(self, project_id: str) -> list[dict[str, Any]]:
        return [
            item
            for item in self.__store.list("executive_reviews")
            if item.get("project_id") == project_id
        ]

    def late_results(self, project_id: str) -> list[dict[str, Any]]:
        return [
            item
            for item in self.__store.list("executive_late_results")
            if item.get("project_id") == project_id
        ]

    def cancel_project_execution(
        self, project_id: str
    ) -> tuple[ProjectRecord, tuple[str, ...]]:
        timestamp = utc_now()
        attempt_ids: list[str] = []
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            project_payload, project_hash = self._entity_in_transaction(
                connection, "executive_projects", project_id
            )
            project = ProjectRecord.from_dict(project_payload)
            if ExecutiveState.CANCELED not in PROJECT_TRANSITIONS[
                ExecutiveState(project.state)
            ]:
                raise PermissionError("project cannot be canceled")
            canceled_project = replace(
                project,
                state=ExecutiveState.CANCELED.value,
                pause_reason=None,
                updated_at=timestamp,
            )
            self._update_entity_cas(
                connection,
                "executive_projects",
                project_id,
                project_hash,
                canceled_project.to_dict(),
            )
            rows = connection.execute(
                'SELECT id, payload, payload_hash FROM "executive_tasks"'
            ).fetchall()
            for row in rows:
                serialized = str(row["payload"])
                if _digest_serialized(serialized) != row["payload_hash"]:
                    raise RuntimeError(
                        "stored executive task failed integrity validation"
                    )
                payload = json.loads(serialized)
                if not isinstance(payload, dict) or payload.get(
                    "project_id"
                ) != project_id:
                    continue
                task = ExecutiveTask.from_dict(payload)
                if task.status in {
                    TaskStatus.COMPLETED,
                    TaskStatus.FAILED,
                    TaskStatus.CANCELED,
                    TaskStatus.SKIPPED,
                }:
                    continue
                canceled_task = replace(
                    task,
                    status=TaskStatus.CANCELED.value,
                    revision=task.revision + 1,
                    updated_at=timestamp,
                )
                self._update_entity_cas(
                    connection,
                    "executive_tasks",
                    task.task_id,
                    str(row["payload_hash"]),
                    canceled_task.to_dict(),
                )
                if task.authority_attempt_id:
                    attempt_ids.append(task.authority_attempt_id)
                if task.review_attempt_id:
                    attempt_ids.append(task.review_attempt_id)
        return canceled_project, tuple(attempt_ids)

    def revoke_project_launch_authority(
        self, project_id: str
    ) -> tuple[ProjectRecord, tuple[str, ...]]:
        """Persist revocation and invalidate every launch-capable local claim."""
        timestamp = utc_now()
        attempt_ids: list[str] = []
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            project_payload, project_hash = self._entity_in_transaction(
                connection, "executive_projects", project_id
            )
            project = ProjectRecord.from_dict(project_payload)
            if ExecutiveState(project.state) in {
                ExecutiveState.CANCELED,
                ExecutiveState.COMPLETED,
                ExecutiveState.FAILED,
            }:
                raise PermissionError("terminal project authority cannot be revoked")
            revoked_project = replace(
                project,
                state=ExecutiveState.PAUSED.value,
                pause_reason="Founder revoked delegation.",
                updated_at=timestamp,
            )
            self._update_entity_cas(
                connection,
                "executive_projects",
                project_id,
                project_hash,
                revoked_project.to_dict(),
            )
            approval_rows = connection.execute(
                'SELECT id, payload, payload_hash FROM "executive_approvals"'
            ).fetchall()
            for row in approval_rows:
                payload = json.loads(str(row["payload"]))
                if (
                    isinstance(payload, dict)
                    and payload.get("project_id") == project_id
                    and payload.get("revoked_at") is None
                ):
                    approval = ApprovalRecord.from_dict(payload)
                    self._update_entity_cas(
                        connection,
                        "executive_approvals",
                        approval.approval_id,
                        str(row["payload_hash"]),
                        replace(approval, revoked_at=timestamp).to_dict(),
                    )
            task_rows = connection.execute(
                'SELECT id, payload, payload_hash FROM "executive_tasks"'
            ).fetchall()
            for row in task_rows:
                payload = json.loads(str(row["payload"]))
                if not isinstance(payload, dict) or payload.get(
                    "project_id"
                ) != project_id:
                    continue
                task = ExecutiveTask.from_dict(payload)
                if task.authority_attempt_id and task.status in {
                    TaskStatus.LAUNCH_CLAIMED,
                    TaskStatus.EXECUTION_STARTED,
                    TaskStatus.RUNNING,
                    TaskStatus.COMPLETION_PENDING,
                    TaskStatus.UNCERTAIN,
                }:
                    attempt_ids.append(task.authority_attempt_id)
                    revoked_task = replace(
                        task,
                        status=TaskStatus.CANCELED.value,
                        result_disposition="DELEGATION_REVOKED",
                        revision=task.revision + 1,
                        updated_at=timestamp,
                    )
                    self._update_entity_cas(
                        connection,
                        "executive_tasks",
                        task.task_id,
                        str(row["payload_hash"]),
                        revoked_task.to_dict(),
                    )
                if task.review_attempt_id:
                    attempt_ids.append(task.review_attempt_id)
        return revoked_project, tuple(dict.fromkeys(attempt_ids))

    def task(self, task_id: str) -> ExecutiveTask:
        return ExecutiveTask.from_dict(self._required("executive_tasks", task_id))

    def tasks(self, project_id: str) -> list[ExecutiveTask]:
        return [
            ExecutiveTask.from_dict(item)
            for item in self.__store.list("executive_tasks")
            if item.get("project_id") == project_id
        ]

    def insert_approval(self, approval: ApprovalRecord) -> None:
        del approval
        raise PermissionError(
            "approvals may only be created by trusted approval operations"
        )

    def grant_action_approval(
        self,
        *,
        project_id: str,
        charter_id: str,
        charter_revision: int,
        kind: ApprovalKind,
        action_category: ActionCategory,
        scope: tuple[str, ...],
        limits: dict[str, Any],
        approver: str,
        source_interaction_id: str,
        expires_at: str | None = None,
    ) -> ApprovalRecord:
        del (
            project_id, charter_id, charter_revision, kind, action_category,
            scope, limits, approver, source_interaction_id, expires_at,
        )
        raise PermissionError(
            "caller identities and conversations cannot approve protected actions"
        )

    def create_action_approval_challenge(
        self,
        action: ProposedAction,
        *,
        charter_id: str,
        kind: ApprovalKind,
        scope: tuple[str, ...],
        limits: dict[str, Any],
        expires_at: str | None = None,
    ) -> FounderApprovalChallenge:
        if kind is ApprovalKind.CHARTER_DURATION:
            raise PermissionError("action approval kind is invalid")
        requested = datetime.now(UTC)
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            charter_payload, _ = self._entity_in_transaction(
                connection, "project_charters", charter_id
            )
            charter = ProjectCharter.from_dict(charter_payload)
            if (
                charter.project_id != action.project_id
                or charter.revision != action.charter_revision
                or charter.status != CharterStatus.ACTIVE
                or not set(scope).issubset(set(charter.deliverables))
            ):
                raise PermissionError(
                    "action approval is outside the active charter"
                )
            if expires_at is not None:
                expiration = datetime.fromisoformat(expires_at)
                if expiration.tzinfo is None or expiration <= datetime.now(UTC):
                    raise PermissionError("action approval expiration is invalid")
            binding = {
                "schema_version": 1,
                "project_id": action.project_id,
                "charter_id": charter_id,
                "charter_revision": action.charter_revision,
                "kind": kind.value,
                "action": action.to_dict(),
                "scope": scope,
                "limits": dict(limits),
                "expires_at": expires_at,
            }
            challenge = FounderApprovalChallenge(
                new_id("founder-challenge"),
                2,
                action.project_id,
                charter_id,
                action.charter_revision,
                canonical_digest(binding),
                FounderApprovalIntent.APPROVE_ACTION.value,
                binding,
                secrets.token_hex(32),
                requested.isoformat(),
                (requested + timedelta(minutes=10)).isoformat(),
                "PENDING",
                None,
            )
            self._insert_entity(
                connection,
                "executive_founder_approval_challenges",
                challenge.challenge_id,
                challenge.to_dict(),
            )
        return challenge

    def confirm_action_approval(
        self,
        *,
        challenge_id: str,
        confirmation: ApprovalConfirmation | None,
        explicit_intent: FounderApprovalIntent,
    ) -> tuple[ApprovalRecord, FounderApprovalEvent]:
        if (
            explicit_intent is not FounderApprovalIntent.APPROVE_ACTION
            or confirmation is None
        ):
            raise PermissionError("explicit action approval intent is required")
        authenticator = self._trusted_authenticator()
        timestamp = utc_now()
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            challenge_payload, challenge_hash = self._entity_in_transaction(
                connection,
                "executive_founder_approval_challenges",
                challenge_id,
            )
            challenge = FounderApprovalChallenge.from_dict(challenge_payload)
            if (
                challenge.state != "PENDING"
                or challenge.approval_action
                != FounderApprovalIntent.APPROVE_ACTION
                or challenge.approval_binding is None
                or datetime.fromisoformat(challenge.expires_at)
                <= datetime.now(UTC)
            ):
                raise PermissionError("action approval challenge is stale")
            session = authenticator.verify(challenge, confirmation)
            session_payload, session_hash = self._entity_in_transaction(
                connection,
                "executive_founder_authenticated_sessions",
                session.session_id,
            )
            stored_session = FounderAuthenticatedSession.from_dict(
                session_payload
            )
            if (
                stored_session != session
                or stored_session.state != "ACTIVE"
                or stored_session.revoked_at is not None
                or datetime.fromisoformat(stored_session.expires_at)
                <= datetime.now(UTC)
            ):
                raise PermissionError("authenticated Founder session is stale")
            binding = challenge.approval_binding
            if canonical_digest(binding) != challenge.charter_digest:
                raise PermissionError("action approval binding was modified")
            charter_payload, _ = self._entity_in_transaction(
                connection, "project_charters", challenge.charter_id
            )
            charter = ProjectCharter.from_dict(charter_payload)
            if (
                charter.project_id != challenge.project_id
                or charter.revision != challenge.charter_revision
                or charter.status != CharterStatus.ACTIVE
            ):
                raise PermissionError("action charter is no longer active")
            action_value = binding.get("action")
            if not isinstance(action_value, dict):
                raise PermissionError("action approval binding is malformed")
            action = ProposedAction.from_dict(action_value)
            limits_value = binding.get("limits")
            scope_value = binding.get("scope")
            if (
                not isinstance(limits_value, dict)
                or not isinstance(scope_value, (list, tuple))
                or action.project_id != challenge.project_id
                or action.charter_revision != challenge.charter_revision
            ):
                raise PermissionError("action approval binding is invalid")
            event_id = new_id("founder-approval-event")
            event = FounderApprovalEvent(
                event_id,
                2,
                session.principal_sid,
                session.authentication_method,
                session.account_name,
                session.session_id,
                session.machine_identity,
                session.application_identity,
                challenge.project_id,
                challenge.charter_id,
                challenge.charter_revision,
                challenge.charter_digest,
                FounderApprovalIntent.APPROVE_ACTION.value,
                explicit_intent.value,
                challenge.challenge_id,
                confirmation_response_digest(confirmation),
                confirmation.proof_version,
                confirmation.source_user_interaction_id,
                timestamp,
                str(binding["expires_at"])
                if binding.get("expires_at") is not None
                else None,
            )
            normalized_limits = dict(limits_value)
            normalized_limits.update(
                {
                    "authentication_method": session.authentication_method,
                    "authenticated_session_id": session.session_id,
                    "approval_event_digest": canonical_digest(event.to_dict()),
                    "action_binding": binding,
                }
            )
            approval = ApprovalRecord(
                new_id("approval"),
                challenge.project_id,
                challenge.charter_id,
                challenge.charter_revision,
                str(binding["kind"]),
                action.category,
                session.principal_sid,
                tuple(str(item) for item in scope_value),
                normalized_limits,
                timestamp,
                event.expires_at,
                None,
                None,
                challenge.charter_digest,
                event_id,
            )
            self._insert_entity(
                connection,
                "executive_founder_approval_events",
                event_id,
                event.to_dict(),
            )
            self._insert_entity(
                connection,
                "executive_approvals",
                approval.approval_id,
                approval.to_dict(),
            )
            self._insert_relation(
                connection,
                challenge.project_id,
                "charter",
                challenge.charter_id,
                "approval",
                approval.approval_id,
            )
            self._update_entity_cas(
                connection,
                "executive_founder_approval_challenges",
                challenge.challenge_id,
                challenge_hash,
                replace(
                    challenge,
                    state="CONSUMED",
                    consumed_event_id=event_id,
                ).to_dict(),
            )
            self._update_entity_cas(
                connection,
                "executive_founder_authenticated_sessions",
                session.session_id,
                session_hash,
                replace(
                    session, state="CONSUMED", consumed_at=timestamp
                ).to_dict(),
            )
        return approval, event

    def reserve_action_authority(
        self,
        action: ProposedAction,
        *,
        approval_id: str,
        task_id: str | None = None,
    ) -> tuple[ApprovalRecord, str | None]:
        """Atomically consume one-time authority and reserve cumulative spend."""
        if action.trusted_source != "DURABLE_WORKFLOW_TASK":
            raise PermissionError("caller-classified action facts are not consumable")
        timestamp = utc_now()
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            consumed, reservation_id = self._consume_action_authority_in_transaction(
                connection,
                action,
                approval_id,
                task_id,
                timestamp,
            )
        return consumed, reservation_id

    def mark_budget_boundary(self, reservation_id: str) -> None:
        with self.__store.connect() as connection:
            cursor = connection.execute(
                "UPDATE executive_budget_reservations SET state='CROSSED' "
                "WHERE reservation_id=? AND state='RESERVED'",
                (reservation_id,),
            )
            if cursor.rowcount != 1:
                raise PermissionError("budget reservation is not crossable")

    def release_budget_reservation(self, reservation_id: str) -> None:
        with self.__store.connect() as connection:
            cursor = connection.execute(
                "UPDATE executive_budget_reservations SET state='RELEASED' "
                "WHERE reservation_id=? AND state='RESERVED'",
                (reservation_id,),
            )
            if cursor.rowcount != 1:
                raise PermissionError(
                    "crossed or missing budget reservation cannot be released"
                )

    def approvals(self, project_id: str, charter_revision: int | None = None) -> list[ApprovalRecord]:
        values = [
            ApprovalRecord.from_dict(item)
            for item in self.__store.list("executive_approvals")
            if item.get("project_id") == project_id
        ]
        return [
            item for item in values
            if charter_revision is None or item.charter_revision == charter_revision
        ]

    def pending_founder_approval_challenges(
        self, project_id: str
    ) -> list[FounderApprovalChallenge]:
        return [
            FounderApprovalChallenge.from_dict(item)
            for item in self.__store.list(
                "executive_founder_approval_challenges"
            )
            if item.get("project_id") == project_id
            and item.get("state") == "PENDING"
            and isinstance(item.get("expires_at"), str)
            and datetime.fromisoformat(str(item["expires_at"]))
            > datetime.now(UTC)
        ]

    def revoke_approval(self, approval_id: str, revoked_at: str) -> ApprovalRecord:
        approval = ApprovalRecord.from_dict(self._required("executive_approvals", approval_id))
        if approval.revoked_at is not None:
            raise PermissionError("approval is already revoked")
        updated = replace(approval, revoked_at=revoked_at)
        self._cas_entity(
            "executive_approvals",
            approval_id,
            approval.to_dict(),
            updated.to_dict(),
        )
        return updated

    def insert_decision(self, record: DecisionRecord) -> None:
        project = self.project(record.project_id)
        if (
            project.active_charter_revision is not None
            and record.charter_revision > project.active_charter_revision
        ):
            raise PermissionError("decision charter ownership is invalid")
        self._insert_trusted_entity("project_decisions", record.decision_id, record.to_dict())
        self._relate(record.project_id, "project", record.project_id, "decision", record.decision_id)

    def insert_assumption(self, record: AssumptionRecord) -> None:
        self.project(record.project_id)
        self._insert_trusted_entity("project_assumptions", record.assumption_id, record.to_dict())
        self._relate(record.project_id, "project", record.project_id, "assumption", record.assumption_id)

    def insert_memory(self, record: MemoryRecord) -> None:
        project = self.project(record.project_id)
        if (
            project.active_charter_revision is not None
            and record.charter_revision > project.active_charter_revision
        ):
            raise PermissionError("memory charter ownership is invalid")
        if record.task_id is not None:
            task = self.task(record.task_id)
            if (
                task.project_id != record.project_id
                or task.charter_revision != record.charter_revision
                or (
                    record.stage_id is not None
                    and task.stage_id != record.stage_id
                )
            ):
                raise PermissionError("memory task ownership is invalid")
        self._insert_trusted_entity("project_memories", record.memory_id, record.to_dict())
        self._relate(record.project_id, "project", record.project_id, "memory", record.memory_id)

    def memory(self, memory_id: str) -> MemoryRecord | None:
        value = self.__store.get("project_memories", memory_id)
        return None if value is None else MemoryRecord.from_dict(value)

    def memories(
        self,
        project_id: str,
        *,
        charter_revision: int | None = None,
        task_id: str | None = None,
        stage_id: str | None = None,
        category: str | None = None,
        authority_relevant: bool | None = None,
    ) -> list[MemoryRecord]:
        values = [
            MemoryRecord.from_dict(item)
            for item in self.__store.list("project_memories")
            if item.get("project_id") == project_id
        ]
        return [
            item for item in values
            if (charter_revision is None or item.charter_revision == charter_revision)
            and (task_id is None or item.task_id == task_id)
            and (stage_id is None or item.stage_id == stage_id)
            and (category is None or item.category == category)
            and (authority_relevant is None or item.authority_relevant == authority_relevant)
        ]

    def decisions(self, project_id: str) -> list[DecisionRecord]:
        return [
            DecisionRecord.from_dict(item)
            for item in self.__store.list("project_decisions")
            if item.get("project_id") == project_id
        ]

    def assumptions(self, project_id: str) -> list[AssumptionRecord]:
        return [
            AssumptionRecord.from_dict(item)
            for item in self.__store.list("project_assumptions")
            if item.get("project_id") == project_id
        ]

    def save_conversation(self, interaction_id: str, payload: dict[str, Any]) -> None:
        required = {"interaction_id", "project_id", "speaker", "message", "created_at"}
        if set(payload) != required:
            raise ValueError("conversation record fields are invalid")
        self._insert_trusted_entity("project_conversations", interaction_id, payload)

    def conversations(self, project_id: str) -> list[dict[str, Any]]:
        return [
            item
            for item in self.__store.list("project_conversations")
            if item.get("project_id") == project_id
        ]

    def _required(self, table: str, identifier: str) -> dict[str, Any]:
        value = self.__store.get(table, identifier)
        if value is None:
            raise KeyError(f"{table} record not found: {identifier}")
        return value

    def _relate(
        self,
        project_id: str,
        parent_kind: str,
        parent_id: str,
        child_kind: str,
        child_id: str,
    ) -> None:
        with self.__store.connect() as connection:
            self._insert_relation(
                connection,
                project_id,
                parent_kind,
                parent_id,
                child_kind,
                child_id,
            )

    def _cas_entity(
        self,
        table: str,
        identifier: str,
        expected: dict[str, Any],
        updated: dict[str, Any],
    ) -> None:
        expected_serialized = _serialize(expected)
        expected_hash = _digest_serialized(expected_serialized)
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._update_entity_cas(
                connection, table, identifier, expected_hash, updated
            )

    def _insert_trusted_entity(
        self,
        table: str,
        identifier: str,
        payload: dict[str, Any],
    ) -> None:
        with self.__store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._insert_entity(connection, table, identifier, payload)

    def _validate_task_parentage(self, task: ExecutiveTask) -> None:
        project = self.project(task.project_id)
        workflows = {
            item.workflow_id: item for item in self.workflows(task.project_id)
        }
        workflow = workflows.get(task.workflow_id)
        if (
            workflow is None
            or workflow.project_id != task.project_id
            or workflow.charter_id != task.charter_id
            or workflow.charter_revision != task.charter_revision
            or project.active_charter_id != task.charter_id
            or project.active_charter_revision != task.charter_revision
            or task.stage_id
            not in {stage.stage_id for stage in workflow.stages}
        ):
            raise PermissionError("task parent-child ownership is invalid")

    @staticmethod
    def _entity_in_transaction(
        connection: sqlite3.Connection,
        table: str,
        identifier: str,
    ) -> tuple[dict[str, Any], str]:
        row = connection.execute(
            f'SELECT payload, payload_hash FROM "{table}" WHERE id=?',
            (identifier,),
        ).fetchone()
        if row is None:
            raise KeyError(f"{table} record not found: {identifier}")
        serialized = str(row["payload"])
        digest = _digest_serialized(serialized)
        if digest != row["payload_hash"]:
            raise RuntimeError(
                f"stored {table} record failed integrity validation"
            )
        payload = json.loads(serialized)
        if not isinstance(payload, dict):
            raise RuntimeError(f"stored {table} record is not an object")
        return payload, str(row["payload_hash"])

    @staticmethod
    def _insert_entity(
        connection: sqlite3.Connection,
        table: str,
        identifier: str,
        payload: dict[str, Any],
    ) -> None:
        serialized = _serialize(payload)
        timestamp = utc_now()
        try:
            connection.execute(
                f'INSERT INTO "{table}" '
                "(id, schema_version, created_at, updated_at, payload, payload_hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    identifier,
                    SCHEMA_VERSION,
                    timestamp,
                    timestamp,
                    serialized,
                    _digest_serialized(serialized),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise PermissionError(
                f"immutable {table} record already exists: {identifier}"
            ) from error

    @staticmethod
    def _update_entity_cas(
        connection: sqlite3.Connection,
        table: str,
        identifier: str,
        expected_hash: str,
        payload: dict[str, Any],
    ) -> None:
        serialized = _serialize(payload)
        cursor = connection.execute(
            f'UPDATE "{table}" SET updated_at=?, payload=?, payload_hash=? '
            "WHERE id=? AND payload_hash=?",
            (
                utc_now(),
                serialized,
                _digest_serialized(serialized),
                identifier,
                expected_hash,
            ),
        )
        if cursor.rowcount != 1:
            raise PermissionError(f"stale {table} write was rejected")

    @staticmethod
    def _insert_relation(
        connection: sqlite3.Connection,
        project_id: str,
        parent_kind: str,
        parent_id: str,
        child_kind: str,
        child_id: str,
    ) -> None:
        material = f"{parent_kind}:{parent_id}:{child_kind}:{child_id}"
        relationship_id = hashlib.sha256(material.encode("utf-8")).hexdigest()
        connection.execute(
            "INSERT OR IGNORE INTO executive_relationships VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                relationship_id,
                project_id,
                parent_kind,
                parent_id,
                child_kind,
                child_id,
                _now(),
            ),
        )

    @staticmethod
    def _require_no_newer_charter(
        connection: sqlite3.Connection,
        project_id: str,
        revision: int,
    ) -> None:
        rows = connection.execute(
            'SELECT payload, payload_hash FROM "project_charters"'
        ).fetchall()
        for row in rows:
            serialized = str(row["payload"])
            if _digest_serialized(serialized) != row["payload_hash"]:
                raise RuntimeError(
                    "stored project_charters record failed integrity validation"
                )
            payload = json.loads(serialized)
            if (
                isinstance(payload, dict)
                and payload.get("project_id") == project_id
                and int(payload.get("revision", 0)) > revision
            ):
                raise PermissionError(
                    "a newer charter revision supersedes this approval"
                )

    @staticmethod
    def _validate_charter_approval(
        charter: ProjectCharter,
        approval: ApprovalRecord,
        event: FounderApprovalEvent,
        challenge: FounderApprovalChallenge,
        session: FounderAuthenticatedSession,
        capability: FounderAuthorizationCapability,
        now: str,
    ) -> None:
        if (
            approval.approval_id != charter.founder_approval_record_id
            or approval.project_id != charter.project_id
            or approval.charter_id != charter.charter_id
            or approval.charter_revision != charter.revision
            or approval.approver != session.principal_sid
            or charter.founder_approval_identity != session.principal_sid
            or charter.founder_approval_event_id != event.event_id
            or charter.founder_approval_event_digest
            != canonical_digest(event.to_dict())
            or charter.founder_authenticated_session_id
            != session.session_id
            or approval.evidence_digest != charter_approval_digest(charter)
            or approval.revoked_at is not None
            or approval.consumed_at is not None
            or event.event_id != approval.source_interaction_id
            or event.authenticated_identity != session.principal_sid
            or event.authenticated_account != session.account_name
            or event.authenticated_session_id != session.session_id
            or event.machine_identity != session.machine_identity
            or event.application_identity != session.application_identity
            or event.project_id != charter.project_id
            or event.charter_id != charter.charter_id
            or event.charter_revision != charter.revision
            or event.charter_digest != charter_approval_digest(charter)
            or event.approval_action
            != FounderApprovalIntent.APPROVE_CHARTER
            or event.explicit_intent
            != FounderApprovalIntent.APPROVE_CHARTER
            or challenge.challenge_id != event.challenge_id
            or challenge.state != "CONSUMED"
            or challenge.consumed_event_id != event.event_id
            or challenge.project_id != charter.project_id
            or challenge.charter_id != charter.charter_id
            or challenge.charter_revision != charter.revision
            or challenge.charter_digest != event.charter_digest
            or challenge.approval_action
            != FounderApprovalIntent.APPROVE_CHARTER
            or session.challenge_id != challenge.challenge_id
            or session.project_id != charter.project_id
            or session.charter_id != charter.charter_id
            or session.charter_revision != charter.revision
            or session.approval_action
            != FounderApprovalIntent.APPROVE_CHARTER
            or session.bound_digest != event.charter_digest
            or session.state != "CONSUMED"
            or session.consumed_at is None
            or session.revoked_at is not None
            or event.challenge_response_digest != session.proof_digest
            or event.confirmed_at != approval.approved_at
            or event.expires_at != approval.expires_at
            or datetime.fromisoformat(event.confirmed_at)
            > datetime.fromisoformat(session.expires_at)
            or approval.limits.get("authentication_method")
            != session.authentication_method
            or approval.limits.get("authenticated_session_id")
            != session.session_id
            or approval.limits.get("approval_event_digest")
            != canonical_digest(event.to_dict())
            or capability.project_id != charter.project_id
            or capability.charter_id != charter.charter_id
            or capability.charter_revision != charter.revision
            or capability.action_digest != charter_approval_digest(charter)
            or capability.approval_digest
            != canonical_digest(approval.to_dict())
            or capability.founder_principal_sid != session.principal_sid
            or capability.founder_authenticated_session_id
            != session.session_id
            or capability.approval_event_id != event.event_id
            or capability.approval_record_id != approval.approval_id
            or capability.challenge_id != challenge.challenge_id
            or capability.challenge_proof_digest
            != event.challenge_response_digest
            or capability.authorization_generation != charter.revision
            or capability.revocation_epoch != charter.revision - 1
            or capability.machine_identity != session.machine_identity
            or capability.application_identity != session.application_identity
            or datetime.fromisoformat(capability.expires_at)
            <= datetime.fromisoformat(now).astimezone(UTC)
        ):
            raise PermissionError(
                "charter approval authentication or binding is invalid"
            )
        if (
            approval.expires_at is not None
            and datetime.fromisoformat(approval.expires_at)
            <= datetime.fromisoformat(now).astimezone(UTC)
        ):
            raise PermissionError("charter approval is expired")

    @staticmethod
    def _validate_action_approval(
        approval: ApprovalRecord,
        charter: ProjectCharter,
        event: FounderApprovalEvent,
        challenge: FounderApprovalChallenge,
        session: FounderAuthenticatedSession,
        action: ProposedAction,
        now: str,
    ) -> None:
        binding = approval.limits.get("action_binding")
        if (
            not isinstance(binding, dict)
            or
            approval.project_id != action.project_id
            or approval.charter_id != charter.charter_id
            or approval.charter_revision != action.charter_revision
            or charter.revision != action.charter_revision
            or charter.status != CharterStatus.ACTIVE
            or approval.approver != session.principal_sid
            or (
                approval.action_category is not None
                and ActionCategory(approval.action_category)
                is not ActionCategory(action.category)
            )
            or not set(action.scope).issubset(set(approval.scope))
            or approval.revoked_at is not None
            or approval.consumed_at is not None
            or event.event_id != approval.source_interaction_id
            or event.authenticated_identity != session.principal_sid
            or event.authenticated_session_id != session.session_id
            or event.project_id != action.project_id
            or event.charter_id != charter.charter_id
            or event.charter_revision != charter.revision
            or event.approval_action
            != FounderApprovalIntent.APPROVE_ACTION
            or event.explicit_intent
            != FounderApprovalIntent.APPROVE_ACTION
            or event.charter_digest != approval.evidence_digest
            or event.challenge_response_digest != session.proof_digest
            or event.confirmed_at != approval.approved_at
            or event.expires_at != approval.expires_at
            or datetime.fromisoformat(event.confirmed_at)
            > datetime.fromisoformat(session.expires_at)
            or challenge.challenge_id != event.challenge_id
            or challenge.state != "CONSUMED"
            or challenge.consumed_event_id != event.event_id
            or challenge.approval_binding != binding
            or challenge.charter_digest != approval.evidence_digest
            or session.state != "CONSUMED"
            or session.consumed_at is None
            or session.revoked_at is not None
            or session.challenge_id != challenge.challenge_id
            or session.bound_digest != approval.evidence_digest
            or approval.limits.get("authentication_method")
            != session.authentication_method
            or approval.limits.get("authenticated_session_id")
            != session.session_id
            or approval.limits.get("approval_event_digest")
            != canonical_digest(event.to_dict())
            or approval.evidence_digest != canonical_digest(binding)
            or not isinstance(binding.get("action"), dict)
            or canonical_digest(binding["action"])
            != canonical_digest(action.to_dict())
        ):
            raise PermissionError("action approval binding is invalid")
        if (
            approval.expires_at is not None
            and datetime.fromisoformat(approval.expires_at)
            <= datetime.fromisoformat(now).astimezone(UTC)
        ):
            raise PermissionError("action approval is expired")
        provider = approval.limits.get("provider")
        tool = approval.limits.get("tool")
        workspace = approval.limits.get("workspace")
        repository = approval.limits.get("repository")
        branch = approval.limits.get("branch")
        action_id = approval.limits.get("action_id")
        if (
            (provider is not None and action.provider != provider)
            or (tool is not None and action.tool != tool)
            or (workspace is not None and action.workspace != workspace)
            or (repository is not None and action.repository != repository)
            or (branch is not None and action.branch != branch)
            or (action_id is not None and action.action_id != action_id)
        ):
            raise PermissionError("action approval limits do not match")

    def _consume_action_authority_in_transaction(
        self,
        connection: sqlite3.Connection,
        action: ProposedAction,
        approval_id: str,
        task_id: str | None,
        timestamp: str,
    ) -> tuple[ApprovalRecord, str | None]:
        approval_payload, approval_hash = self._entity_in_transaction(
            connection, "executive_approvals", approval_id
        )
        approval = ApprovalRecord.from_dict(approval_payload)
        charter_payload, _ = self._entity_in_transaction(
            connection, "project_charters", approval.charter_id
        )
        charter = ProjectCharter.from_dict(charter_payload)
        event_payload, _ = self._entity_in_transaction(
            connection,
            "executive_founder_approval_events",
            approval.source_interaction_id,
        )
        event = FounderApprovalEvent.from_dict(event_payload)
        challenge_payload, _ = self._entity_in_transaction(
            connection,
            "executive_founder_approval_challenges",
            event.challenge_id,
        )
        session_payload, _ = self._entity_in_transaction(
            connection,
            "executive_founder_authenticated_sessions",
            event.authenticated_session_id,
        )
        self._validate_action_approval(
            approval,
            charter,
            event,
            FounderApprovalChallenge.from_dict(challenge_payload),
            FounderAuthenticatedSession.from_dict(session_payload),
            action,
            timestamp,
        )
        consumed = approval
        if approval.kind == ApprovalKind.ONE_TIME:
            consumed = replace(approval, consumed_at=timestamp)
            self._update_entity_cas(
                connection,
                "executive_approvals",
                approval.approval_id,
                approval_hash,
                consumed.to_dict(),
            )
            try:
                connection.execute(
                    "INSERT INTO executive_approval_consumptions "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        approval.approval_id,
                        action.project_id,
                        approval.charter_id,
                        action.charter_revision,
                        action.action_id,
                        task_id,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise PermissionError(
                    "one-time approval was already consumed"
                ) from error
        reservation_id = self._reserve_budget_in_transaction(
            connection,
            charter,
            approval,
            action,
            task_id,
            timestamp,
        )
        return consumed, reservation_id

    @staticmethod
    def _reserve_budget_in_transaction(
        connection: sqlite3.Connection,
        charter: ProjectCharter,
        approval: ApprovalRecord,
        action: ProposedAction,
        task_id: str | None,
        timestamp: str,
    ) -> str | None:
        spending = action.spending or action.cost is None or (action.cost or 0) > 0
        if not spending:
            return None
        if action.cost is None:
            raise PermissionError("unknown action cost fails closed")
        currency = action.currency
        approved_currency = approval.limits.get("currency")
        if (
            currency is None
            or currency != charter.authority_envelope.currency
            or currency != approved_currency
        ):
            raise PermissionError("spending currency is not explicitly approved")
        try:
            amount = Decimal(str(action.cost))
            amount_minor_decimal = amount * 100
            if amount_minor_decimal != amount_minor_decimal.to_integral_value():
                raise PermissionError("spending amount has unsupported precision")
            amount_minor = int(amount_minor_decimal)
            approval_limit = Decimal(str(approval.limits["maximum_cost"]))
        except (InvalidOperation, KeyError, TypeError, ValueError) as error:
            raise PermissionError("spending approval limit is invalid") from error
        if amount_minor <= 0:
            raise PermissionError("spending reservation must be positive")
        charter_limit = min(
            Decimal(str(charter.budget_limit)),
            Decimal(str(charter.authority_envelope.maximum_cost)),
            approval_limit,
        )
        limit_minor = int(charter_limit * 100)
        reserved = int(
            connection.execute(
                "SELECT COALESCE(SUM(amount_minor), 0) "
                "FROM executive_budget_reservations "
                "WHERE project_id=? AND charter_id=? AND charter_revision=? "
                "AND currency=? AND state IN ('RESERVED', 'CROSSED')",
                (
                    action.project_id,
                    charter.charter_id,
                    charter.revision,
                    currency,
                ),
            ).fetchone()[0]
        )
        if reserved + amount_minor > limit_minor:
            raise PermissionError(
                "cumulative spending would exceed the approved limit"
            )
        reservation_id = new_id("budget")
        try:
            connection.execute(
                "INSERT INTO executive_budget_reservations "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    reservation_id,
                    action.project_id,
                    charter.charter_id,
                    charter.revision,
                    approval.approval_id,
                    action.action_id,
                    task_id,
                    amount_minor,
                    currency,
                    "RESERVED",
                    timestamp,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise PermissionError(
                "spending action already has a reservation"
            ) from error
        return reservation_id


def canonical_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def charter_approval_digest(charter: ProjectCharter) -> str:
    """Digest immutable identity and content, excluding lifecycle metadata."""
    payload = charter.to_dict()
    for field_name in (
        "status",
        "founder_approval_identity",
        "founder_approval_record_id",
        "founder_approval_event_id",
        "founder_approval_event_digest",
        "founder_authenticated_session_id",
        "founder_authorization_capability",
        "founder_authorization_capability_digest",
        "updated_at",
    ):
        payload.pop(field_name)
    return canonical_digest(payload)


def task_definition_digest(task: ExecutiveTask) -> str:
    payload = task.to_dict()
    for field_name in (
        "provider_id",
        "model_id",
        "session_id",
        "status",
        "retry_count",
        "attempt_history",
        "result_disposition",
        "updated_at",
        "revision",
        "authority_attempt_id",
        "artifact_digest",
        "review_attempt_id",
        "late_result",
    ):
        payload.pop(field_name)
    return canonical_digest(payload)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def _now() -> str:
    return utc_now()


def _serialize(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest_serialized(serialized: str) -> str:
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

class ProductionExecutiveRepository(ExecutiveRepository):
    __slots__ = ()

    def __init__(
        self,
        store: KeeperStore,
        founder_authenticator: ProductionFounderAuthenticator,
    ) -> None:
        if type(founder_authenticator) is not ProductionFounderAuthenticator:
            raise TypeError(
                "production repository requires the exact production authenticator"
            )
        self._initialize(store, founder_authenticator, "PRODUCTION")


class TestExecutiveRepository(ExecutiveRepository):
    __slots__ = ()
    __test__ = False

    def __init__(
        self,
        store: KeeperStore,
        founder_authenticator: TestFounderAuthenticator,
    ) -> None:
        if type(founder_authenticator) is not TestFounderAuthenticator:
            raise TypeError(
                "test repository requires the exact test authenticator"
            )
        self._initialize(store, founder_authenticator, "TEST")
