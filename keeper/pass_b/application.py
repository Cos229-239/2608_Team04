from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Protocol, cast

from keeper.app.storage import KeeperStore, default_data_directory
from keeper.executive.authority_gateway import (
    AuthorityProviderBinding,
    ProductionAuthorityBackedSpecialistGateway,
)
from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.executive.models import (
    FounderApprovalChallenge,
    ProjectCharter,
    ProjectRecord,
)
from keeper.executive.service import KeeperExecutive
from keeper.pass_b.authority_reservation import (
    AuthorityAttemptReservation,
    ProductionAuthorityAttemptReservation,
)
from keeper.pass_b.completion import CompletionCoordinator, CompletionStepResult
from keeper.pass_b.control_room import ControlRoomService
from keeper.pass_b.conversation import (
    CharterDraftContextRecord,
    ConversationExecutive,
    DynamicWorkflowDesigner,
    ProjectStatusReader,
)
from keeper.pass_b.conversation_runtime import DurableConversationService
from keeper.pass_b.enums import (
    AssignmentRole,
    CostMode,
    HealthState,
    PresentationMode,
    ProviderClassification,
    ProviderSessionState,
    SessionModel,
)
from keeper.pass_b.models import (
    AssignmentRecord,
    EvidenceBundleRecord,
    PrelaunchAbandonmentRecord,
    PresentationStateRecord,
    ProviderAccountRecord,
    ProviderRecord,
    ProviderSessionRecord,
    UsagePoolRecord,
)
from keeper.pass_b.launch_authority import (
    ExecutiveAuthorityLaunchGate,
    LaunchAuthority,
)
from keeper.pass_b.orchestration import (
    OrchestrationService,
    RecoveryActionAuthority,
    authority_envelope_digest,
)
from keeper.pass_b.providers import LocalMockAdapter, ProviderAdapter
from keeper.pass_b.repository import PassBRepository
from keeper.pass_b.usage_authority import (
    ProductionUsageResetVerifier,
    TestUsageResetVerifier,
    UsageResetVerifier,
)


class AuthorityHealthClient(Protocol):
    def require_live_identity(self) -> dict[str, Any]: ...


class CharterActivator(Protocol):
    def activate_charter(self, charter: ProjectCharter) -> ProjectRecord: ...


def authority_exchange_root_from_diagnostics(
    diagnostics: dict[str, Any],
) -> Path:
    """Return the authenticated Authority-owned Pass B exchange directory."""

    client_value = diagnostics.get("client_exchange_root")
    evidence_value = diagnostics.get("allowed_evidence_root")
    if (
        not isinstance(client_value, str)
        or not client_value
        or not isinstance(evidence_value, str)
        or not evidence_value
    ):
        raise RuntimeError("Authority Service client exchange is unavailable")
    client_root = Path(client_value).resolve(strict=True)
    evidence_root = Path(evidence_value).resolve(strict=True)
    if evidence_root.parent != client_root:
        raise PermissionError("Authority evidence root is outside the client exchange")
    return evidence_root / "pass-b"




class PassBApplication:
    """Conversation-first Pass B application composition."""

    def __init__(
        self,
        data_directory: Path | None = None,
        *,
        executive: ConversationExecutive | None = None,
        authority_client: ProductionAuthorityServiceClient | None = None,
        authority_health_client: AuthorityHealthClient | None = None,
        provider_bindings: tuple[AuthorityProviderBinding, ...] = (),
        authority_exchange_root: Path | None = None,
        usage_reset_verifier: UsageResetVerifier | None = None,
        _test_launch_authority: LaunchAuthority | None = None,
        _test_authority_reservation: (
            AuthorityAttemptReservation | None
        ) = None,
        _test_recovery_action_authority: (
            RecoveryActionAuthority | None
        ) = None,
        _test_uncertain_execution_observer: (
            Callable[[str], dict[str, object]] | None
        ) = None,
        _test_uncertain_execution_finalizer: (
            Callable[[str, dict[str, object]], dict[str, object]] | None
        ) = None,
    ) -> None:
        self.data_directory = (
            data_directory or default_data_directory()
        ).resolve()
        self.store = KeeperStore(self.data_directory / "keeper.db")
        self.store.migrate()
        self.repository = PassBRepository(self.store)
        self.startup_recovery = (
            self.repository.recover_interrupted_attempts(_now())
        )
        self.executive = executive or KeeperExecutive(self.store.path)
        self.authority_client = authority_client
        self.authority_health_client = (
            authority_health_client or authority_client
        )
        self.project_status: ProjectStatusReader = (
            lambda project_id: _product_project_status(
                self.executive, project_id
            )
        )
        self._test_authority_configured = _test_launch_authority is not None
        if _test_launch_authority is not None:
            if type(usage_reset_verifier) is not TestUsageResetVerifier:
                raise TypeError(
                    "test composition requires the exact test usage verifier"
                )
        elif (
            authority_client is not None
            and type(usage_reset_verifier) is not ProductionUsageResetVerifier
        ) or (
            usage_reset_verifier is not None
            and type(usage_reset_verifier) is not ProductionUsageResetVerifier
        ):
            raise TypeError(
                "production composition requires the exact production usage verifier"
            )
        if _test_launch_authority is not None:
            launch_authority = _test_launch_authority
        elif authority_client is not None:
            if not isinstance(self.executive, KeeperExecutive):
                raise TypeError(
                    "production Authority requires the production Executive"
                )
            launch_authority = ExecutiveAuthorityLaunchGate.production(
                self.executive,
                authority_client,
                authority_exchange_root,
            )
        else:
            launch_authority = None
        if _test_authority_reservation is not None:
            if _test_launch_authority is None:
                raise TypeError(
                    "test reservation requires test launch composition"
                )
            authority_reservation = _test_authority_reservation
        elif authority_client is not None and (
            provider_bindings or authority_exchange_root is not None
        ):
            if not provider_bindings or authority_exchange_root is None:
                raise TypeError(
                    "production reservation requires bindings and exchange root"
                )
            gateway = ProductionAuthorityBackedSpecialistGateway(
                authority_client,
                provider_bindings,
                authority_exchange_root,
            )
            authority_reservation = ProductionAuthorityAttemptReservation(
                gateway, self.project_status
            )
        else:
            authority_reservation = None
        if _test_recovery_action_authority is not None:
            if _test_launch_authority is None:
                raise TypeError(
                    "test recovery authority requires test launch composition"
                )
            recovery_action_authority = _test_recovery_action_authority
        elif type(self.executive) is KeeperExecutive:
            recovery_action_authority = cast(
                RecoveryActionAuthority, self.executive
            )
        else:
            recovery_action_authority = None
        self.recovery_action_authority = recovery_action_authority
        if _test_uncertain_execution_observer is not None:
            if _test_launch_authority is None:
                raise TypeError(
                    "test uncertainty observer requires test launch composition"
                )
            uncertain_execution_observer = _test_uncertain_execution_observer
        elif authority_client is not None:
            def uncertain_execution_observer(
                authority_attempt_id: str,
            ) -> dict[str, object]:
                try:
                    result = authority_client.observe_uncertain_provider_attempt(
                        authority_attempt_id
                    )
                    observation = result.get("observation")
                except PermissionError:
                    durable = authority_client.query_state(
                        "attempts", authority_attempt_id
                    )
                    disposition = durable.get("record")
                    if not isinstance(disposition, dict):
                        raise
                    terminal = dict(disposition)
                    state = terminal.pop("service_state", None)
                    if (
                        state != "FOUNDER_DISPOSITIONED"
                        or not authority_client.verify(
                            "uncertain-provider-attempt-disposition", terminal
                        )
                        or terminal.get("authority_attempt_id")
                        != authority_attempt_id
                    ):
                        raise
                    observation = terminal.get("inactivity_observation")
                if (
                    not isinstance(observation, dict)
                    or not authority_client.verify(
                        "uncertain-provider-attempt-observation", observation
                    )
                ):
                    raise PermissionError(
                        "Authority provider inactivity observation is invalid"
                    )
                return cast(dict[str, object], observation)
        else:
            uncertain_execution_observer = None
        if _test_uncertain_execution_finalizer is not None:
            if _test_launch_authority is None:
                raise TypeError(
                    "test uncertainty finalizer requires test launch composition"
                )
            uncertain_execution_finalizer = _test_uncertain_execution_finalizer
        elif authority_client is not None:
            def uncertain_execution_finalizer(
                authority_attempt_id: str,
                executive_recovery_receipt: dict[str, object],
            ) -> dict[str, object]:
                result = authority_client.finalize_uncertain_provider_attempt_disposition(
                    authority_attempt_id, executive_recovery_receipt
                )
                disposition = result.get("disposition")
                if (
                    not isinstance(disposition, dict)
                    or not authority_client.verify(
                        "uncertain-provider-attempt-disposition", disposition
                    )
                ):
                    raise PermissionError(
                        "Authority uncertain execution disposition is invalid"
                    )
                return cast(dict[str, object], disposition)
        else:
            uncertain_execution_finalizer = None
        self.orchestration = OrchestrationService(
            self.repository,
            launch_authority=launch_authority,
            authority_reservation=authority_reservation,
            usage_reset_verifier=usage_reset_verifier,
            project_status=self.project_status,
            recovery_action_authority=recovery_action_authority,
            uncertain_execution_observer=uncertain_execution_observer,
            uncertain_execution_finalizer=uncertain_execution_finalizer,
            completed_execution_reconciler=(
                launch_authority.reconcile_completed_execution
                if isinstance(launch_authority, ExecutiveAuthorityLaunchGate)
                else None
            ),
        )
        self.conversation = DurableConversationService(
            self.repository, self.executive
        )
        self.control_room = ControlRoomService(
            self.repository,
            authority_health=self._authority_health,
            project_status=self.project_status,
        )
        self.completion = CompletionCoordinator(
            self.repository,
            self.orchestration,
            self.project_status,
            self.data_directory,
        )
        self._ensure_presentation_state()

    def abandon_prelaunch_assignment(
        self, assignment_id: str
    ) -> PrelaunchAbandonmentRecord:
        return self.orchestration.abandon_prelaunch_assignment(assignment_id)

    def create_repository_snapshot_evidence(
        self, workflow_id: str, repository_root: Path
    ) -> EvidenceBundleRecord:
        return self.orchestration.create_repository_snapshot_evidence(
            workflow_id, repository_root
        )

    @classmethod
    def test_composition(
        cls,
        data_directory: Path,
        *,
        executive: ConversationExecutive,
        launch_authority: LaunchAuthority,
        usage_reset_verifier: UsageResetVerifier,
        authority_reservation: (
            AuthorityAttemptReservation | None
        ) = None,
        recovery_action_authority: RecoveryActionAuthority | None = None,
        uncertain_execution_observer: (
            Callable[[str], dict[str, object]] | None
        ) = None,
        uncertain_execution_finalizer: (
            Callable[[str, dict[str, object]], dict[str, object]] | None
        ) = None,
    ) -> PassBApplication:
        """Build an explicitly non-production deterministic composition."""

        recovery_generation = 0

        def default_uncertain_execution_observer(
            authority_attempt_id: str,
        ) -> dict[str, object]:
            nonlocal recovery_generation
            recovery_generation += 1
            return {
                "schema_version": 1,
                "kind": "uncertain_provider_attempt_observation",
                "authority_attempt_id": authority_attempt_id,
                "host_id": "test-provider-host",
                "enrollment_id": "test-provider-host-enrollment",
                "enrollment_generation": 1,
                "launch_id": f"test-launch:{authority_attempt_id}",
                "recovery_barrier_generation": recovery_generation,
                "disposition_readiness": "EXACT_ATTEMPT_INACTIVE",
                "launch_state": "ABSENT_FROM_ACTIVE_OR_UNCERTAIN_JOURNAL",
                "composition": "TEST_AUTHORITY",
            }

        return cls(
            data_directory,
            executive=executive,
            usage_reset_verifier=usage_reset_verifier,
            _test_launch_authority=launch_authority,
            _test_authority_reservation=authority_reservation,
            _test_recovery_action_authority=recovery_action_authority,
            _test_uncertain_execution_observer=(
                uncertain_execution_observer
                or default_uncertain_execution_observer
            ),
            _test_uncertain_execution_finalizer=(
                uncertain_execution_finalizer
                or (
                    lambda authority_attempt_id, executive_receipt: {
                        "schema_version": 1,
                        "kind": "uncertain_provider_attempt_disposition",
                        "authority_attempt_id": authority_attempt_id,
                        "project_id": executive_receipt["project_id"],
                        "charter_id": executive_receipt["execution_charter_id"],
                        "charter_revision": executive_receipt[
                            "execution_charter_revision"
                        ],
                        "approval_charter_id": executive_receipt["charter_id"],
                        "approval_charter_revision": executive_receipt[
                            "charter_revision"
                        ],
                        "assignment_id": executive_receipt["assignment_id"],
                        "pass_b_attempt_id": executive_receipt[
                            "pass_b_attempt_id"
                        ],
                        "action_id": executive_receipt["action_id"],
                        "action_digest": executive_receipt["action_digest"],
                        "approval_id": executive_receipt["approval_id"],
                        "approval_event_id": executive_receipt[
                            "approval_event_id"
                        ],
                        "observation_digest": executive_receipt[
                            "observation_digest"
                        ],
                        "terminal_disposition": (
                            "FOUNDER_ABANDONED_UNCERTAIN_EXTERNAL_EXECUTION"
                        ),
                        "possible_external_effect_preserved": True,
                        "result_accepted": False,
                        "retry_authorized": False,
                        "usage_disposition": "CONSUME_UPPER_BOUND",
                        "composition": "TEST_AUTHORITY",
                    }
                )
            ),
        )

    def request_uncertain_cancellation_approval(
        self,
        assignment_id: str,
        *,
        observation_digest: str,
    ) -> dict[str, Any]:
        authority = self.recovery_action_authority
        if authority is None or not hasattr(
            authority, "request_action_approval"
        ):
            raise PermissionError(
                "Founder recovery approval composition is unavailable"
            )
        action = self.orchestration.uncertainty_reconciliation_action(
            assignment_id,
            observation_digest=observation_digest,
        )
        assignment = self.repository.get(
            AssignmentRecord, assignment_id
        )
        approval_authority = cast(Any, authority)
        challenge = approval_authority.request_action_approval(
            action,
            charter_id=assignment.charter_id,
            scope=action.scope,
            limits={
                "action_id": action.action_id,
                "provider": action.provider,
                "tool": action.tool,
                "workspace": action.workspace,
            },
        )
        return {
            "action": action.to_dict(),
            "challenge": challenge.to_dict(),
        }

    def confirm_uncertain_cancellation_approval(
        self,
        challenge: FounderApprovalChallenge,
    ) -> dict[str, Any]:
        return self.confirm_recovery_action_approval(challenge)

    def confirm_recovery_action_approval(
        self,
        challenge: FounderApprovalChallenge,
    ) -> dict[str, Any]:
        authority = self.recovery_action_authority
        if (
            authority is None
            or not hasattr(authority, "authenticate_founder")
            or not hasattr(authority, "confirm_action_approval")
        ):
            raise PermissionError(
                "Founder recovery approval composition is unavailable"
            )
        approval_authority = cast(Any, authority)
        confirmation = approval_authority.authenticate_founder(challenge)
        approval, event = approval_authority.confirm_action_approval(
            challenge.challenge_id, confirmation
        )
        return {
            "approval": approval.to_dict(),
            "event": event.to_dict(),
        }

    def apply_uncertain_cancellation_approval(
        self,
        assignment_id: str,
        *,
        observation_digest: str,
        approval_id: str,
    ) -> dict[str, Any]:
        attempt = self.orchestration.reconcile_uncertain_cancellation(
            assignment_id,
            observation_digest=observation_digest,
            approval_id=approval_id,
        )
        return attempt.to_dict()

    def request_uncertain_execution_disposition_approval(
        self, assignment_id: str
    ) -> dict[str, Any]:
        authority = self.recovery_action_authority
        if authority is None or not hasattr(
            authority, "request_action_approval"
        ):
            raise PermissionError(
                "Founder recovery approval composition is unavailable"
            )
        observation = (
            self.orchestration.uncertain_execution_disposition_observation(
                assignment_id
            )
        )
        observation_digest = hashlib.sha256(
            json.dumps(
                observation, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        action = self.orchestration.uncertain_execution_disposition_action(
            assignment_id,
            observation_digest=observation_digest,
            observation=observation,
        )
        status = self.project_status(str(observation["project_id"]))
        active_charter = dict(status.get("active_charter") or {})
        charter_id = active_charter.get("charter_id")
        if not isinstance(charter_id, str) or not charter_id:
            raise PermissionError(
                "current charter is unavailable for Founder disposition"
            )
        approval_authority = cast(Any, authority)
        challenge = approval_authority.request_action_approval(
            action,
            charter_id=charter_id,
            scope=action.scope,
            limits={
                "action_id": action.action_id,
                "assignment_id": assignment_id,
                "attempt_id": observation["attempt_id"],
                "authority_attempt_id": observation[
                    "authority_attempt_id"
                ],
                "execution_charter_id": observation["charter_id"],
                "execution_charter_revision": observation["charter_revision"],
                "observation_digest": observation_digest,
                "approved_inactivity_observation": observation[
                    "inactivity_observation"
                ],
                "approved_inactivity_observation_digest": observation[
                    "inactivity_observation_digest"
                ],
                "possible_external_effect": True,
                "retry_authorized": False,
            },
        )
        return {
            "action": action.to_dict(),
            "challenge": challenge.to_dict(),
            "observation": observation,
            "observation_digest": observation_digest,
        }

    def reconcile_completed_uncertain_execution(
        self, assignment_id: str
    ) -> dict[str, Any] | None:
        evidence = (
            self.orchestration.reconcile_completed_uncertain_execution(
                assignment_id
            )
        )
        return evidence.to_dict() if evidence is not None else None

    def apply_uncertain_execution_disposition_approval(
        self,
        assignment_id: str,
        *,
        observation_digest: str,
        approval_id: str,
    ) -> dict[str, Any]:
        attempt = self.orchestration.apply_uncertain_execution_disposition(
            assignment_id,
            observation_digest=observation_digest,
            approval_id=approval_id,
        )
        return attempt.to_dict()

    def begin_conversation(
        self,
        message: str,
        *,
        founder_revisions: dict[str, Any] | None = None,
    ) -> Any:
        outcome = self.conversation.begin(
            message,
            founder_revisions=founder_revisions,
        )
        self.select_project(outcome.project.project_id)
        return outcome

    def continue_conversation(self, project_id: str, message: str) -> Any:
        outcome = self.conversation.continue_project(project_id, message)
        self.select_project(project_id)
        return outcome

    def casual_conversation(
        self,
        project_id: str | None,
        message: str,
    ) -> Any:
        return self.conversation.converse(project_id, message)

    def advance_delegated_completion(
        self, project_id: str
    ) -> CompletionStepResult:
        return self.completion.advance(project_id)

    def run_delegated_completion(
        self, project_id: str, *, max_steps: int = 100
    ) -> tuple[CompletionStepResult, ...]:
        return self.completion.run_until_blocked(
            project_id, max_steps=max_steps
        )

    def project_catalog(self) -> tuple[dict[str, Any], ...]:
        project_ids = tuple(
            dict.fromkeys(
                item.project_id
                for item in self.repository.list(CharterDraftContextRecord)
            )
        )
        catalog: list[dict[str, Any]] = []
        for project_id in project_ids:
            try:
                status = self.project_status(project_id)
            except (KeyError, PermissionError, RuntimeError, ValueError):
                catalog.append(
                    {
                        "project_id": project_id,
                        "title": project_id,
                        "state": "RECOVERY_REQUIRED",
                        "charter_id": None,
                        "charter_revision": None,
                        "updated_at": None,
                    }
                )
                continue
            project = dict(status.get("project_summary") or {})
            charter = dict(status.get("active_charter") or {})
            catalog.append(
                {
                    "project_id": project_id,
                    "title": project.get("name") or project_id,
                    "state": project.get("state") or "UNKNOWN",
                    "charter_id": charter.get("charter_id"),
                    "charter_revision": charter.get("revision"),
                    "updated_at": project.get("updated_at"),
                }
            )
        return tuple(catalog)

    def selected_project_id(self) -> str | None:
        setting = self.store.get("settings", "pass_b_active_project")
        selected = (
            str(setting.get("project_id"))
            if isinstance(setting, dict) and setting.get("project_id")
            else None
        )
        if selected is None:
            return None
        if any(
            item["project_id"] == selected for item in self.project_catalog()
        ):
            return selected
        return None

    def select_project(self, project_id: str) -> None:
        if not any(
            item["project_id"] == project_id
            for item in self.project_catalog()
        ):
            raise KeyError("Keeper project is unavailable")
        self.store.upsert(
            "settings",
            "pass_b_active_project",
            {"project_id": project_id},
        )

    def product_snapshot(
        self, project_id: str | None = None
    ) -> dict[str, Any]:
        catalog = self.project_catalog()
        selected = project_id or self.selected_project_id()
        if selected is None and catalog:
            selected = str(
                max(
                    catalog,
                    key=lambda item: str(item.get("updated_at") or ""),
                )["project_id"]
            )
            self.select_project(selected)
        snapshot = self.control_room.snapshot(selected).to_dict()
        snapshot["projects"] = list(catalog)
        if selected is None:
            snapshot["executive"] = {}
        else:
            try:
                snapshot["executive"] = self.project_status(selected)
            except (KeyError, PermissionError, RuntimeError, ValueError):
                snapshot["executive"] = {
                    "project_summary": {
                        "project_id": selected,
                        "name": selected,
                        "state": "RECOVERY_REQUIRED",
                    },
                    "active_charter": None,
                    "charter_history": (),
                    "controls": (),
                    "blockers": (
                        "Authoritative project state is unavailable; "
                        "preserve data and use supported recovery.",
                    ),
                }
        return snapshot

    def approve_and_plan_current_charter(
        self,
        project_id: str,
        *,
        expected_charter_id: str | None = None,
        expected_charter_revision: int | None = None,
        founder_username: str | None = None,
        founder_password: str | None = None,
    ) -> dict[str, Any]:
        if type(self.executive) is not KeeperExecutive:
            raise RuntimeError(
                "Founder approval requires the production Executive composition"
            )
        context = self.conversation.current_context(project_id)
        if (expected_charter_id is None) != (
            expected_charter_revision is None
        ):
            raise ValueError(
                "expected charter identity must include ID and revision"
            )
        if expected_charter_id is not None and (
            context.charter_id != expected_charter_id
            or context.charter_revision != expected_charter_revision
        ):
            raise PermissionError(
                "displayed charter is not the current approval target"
            )
        status = self.project_status(project_id)
        durable_charters = [
            item
            for item in (
                status.get("active_charter"),
                *status.get("charter_history", ()),
            )
            if isinstance(item, dict)
            and item.get("project_id") == project_id
            and item.get("charter_id") == context.charter_id
            and item.get("revision") == context.charter_revision
            and item.get("status") in {"APPROVED", "ACTIVE"}
            and item.get("founder_approval_record_id")
            and item.get("founder_authorization_capability_digest")
        ]
        if durable_charters:
            charter = ProjectCharter.from_dict(durable_charters[0])
            if charter.status == "APPROVED":
                _, charter = _activate_and_reload_charter(
                    self.executive, self.project_status, charter
                )
            if context.state != "APPROVED":
                self.conversation.record_approval(charter)
        elif context.state == "APPROVED":
            raise PermissionError("active charter is unavailable")
        else:
            if context.state == "PROPOSED":
                challenge = self.conversation.request_approval(project_id)
            elif context.state == "APPROVAL_REQUESTED":
                status = self.project_status(project_id)
                pending = [
                    item
                    for item in status.get("pending_approvals", ())
                    if isinstance(item, dict)
                    and item.get("project_id") == project_id
                    and item.get("charter_id") == context.charter_id
                    and item.get("charter_revision")
                    == context.charter_revision
                ]
                if len(pending) != 1:
                    raise PermissionError(
                        "exact pending Founder approval is unavailable"
                    )
                challenge = FounderApprovalChallenge.from_dict(pending[0])
            else:
                raise PermissionError(
                    "current charter is not available for approval"
                )
            if expected_charter_id is not None and (
                challenge.project_id != project_id
                or challenge.charter_id != expected_charter_id
                or challenge.charter_revision
                != expected_charter_revision
            ):
                raise PermissionError(
                    "Founder challenge does not match the displayed charter"
                )
            confirmation = self.executive.authenticate_founder(
                challenge,
                username=founder_username,
                password=founder_password,
            )
            charter, approval, event = (
                self.executive.confirm_charter_approval(
                    challenge.challenge_id, confirmation
                )
            )
            project, charter = _activate_and_reload_charter(
                self.executive, self.project_status, charter
            )
            self.conversation.record_approval(charter)
            if (
                approval.project_id != project.project_id
                or event.project_id != project.project_id
            ):
                raise RuntimeError("Founder approval activation binding failed")

        blueprint = DynamicWorkflowDesigner().design(charter)
        workflow, work_items = self.orchestration.create_workflow_plan(
            blueprint,
            authority_envelope_digest=authority_envelope_digest(
                charter.authority_envelope.to_dict()
            ),
        )
        self.select_project(project_id)
        return {
            "project_id": project_id,
            "charter": charter.to_dict(),
            "workflow": workflow.to_dict(),
            "work_items": [item.to_dict() for item in work_items],
        }

    def register_local_mock(
        self,
        *,
        provider_id: str = "local-mock",
        account_id: str = "local-default",
        session_count: int = 2,
    ) -> tuple[ProviderRecord, tuple[ProviderSessionRecord, ...]]:
        if session_count < 1:
            raise ValueError("at least one provider session is required")
        adapter = LocalMockAdapter(provider_id)
        descriptor = adapter.descriptor()
        now = _now()
        existing = self.repository.optional(ProviderRecord, provider_id)
        if existing is not None:
            account = self.repository.get(
                ProviderAccountRecord, account_id
            )
            sessions = tuple(
                item
                for item in self.repository.list(ProviderSessionRecord)
                if item.provider_id == provider_id
                and item.account_id == account_id
            )
            if (
                account.provider_id != provider_id
                or len(sessions) != session_count
            ):
                raise PermissionError(
                    "local provider restart configuration changed"
                )
            self.orchestration.attach_adapter(provider_id, adapter)
            return existing, sessions
        pool_id = f"usage-{provider_id}-{account_id}"
        provider = ProviderRecord(
            provider_id=provider_id,
            identity=descriptor.provider_identity,
            display_name="Local deterministic provider",
            classification=ProviderClassification.LOCAL,
            adapter_kind="local-mock",
            capabilities=tuple(
                role.value.casefold() for role in AssignmentRole
            )
            + descriptor.capabilities,
            session_model=SessionModel.RESUMABLE,
            usage_pool_strategy="shared-account-window",
            concurrency_limit=descriptor.concurrency_limit,
            cost_mode=CostMode.FREE,
            authentication_ready=True,
            tool_support=descriptor.tool_support,
            workspace_support=descriptor.workspace_support,
            cancellation_support=True,
            resume_support=True,
            evidence_format=descriptor.evidence_format,
            health=HealthState.READY,
            created_at=now,
            updated_at=now,
            revision=1,
        )
        account = ProviderAccountRecord(
            account_id=account_id,
            provider_id=provider_id,
            identity=f"{provider_id}:{account_id}",
            display_name="Local included account",
            usage_pool_id=pool_id,
            cost_mode=CostMode.FREE,
            privacy_classification="LOCAL",
            authentication_ready=True,
            enabled=True,
            created_at=now,
            updated_at=now,
            revision=1,
        )
        pool = UsagePoolRecord(
            pool_id=pool_id,
            provider_id=provider_id,
            account_id=account_id,
            identity=descriptor.usage_pool_identity,
            limit_type="UNLIMITED_LOCAL",
            capacity=None,
            consumed=0,
            reserved=0,
            remaining=None,
            reset_at=None,
            observation_source="deterministic-local",
            confidence="HIGH",
            exhausted=False,
            last_observed_at=now,
            created_at=now,
            updated_at=now,
            revision=1,
        )
        sessions = tuple(
            ProviderSessionRecord(
                session_id=f"{provider_id}-session-{index}",
                provider_id=provider_id,
                account_id=account_id,
                model_id="deterministic-v1",
                external_session_id=None,
                state=ProviderSessionState.READY,
                concurrency_limit=1,
                active_assignments=0,
                supports_resume=True,
                resume_token_digest=None,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
                revision=1,
            )
            for index in range(1, session_count + 1)
        )
        self.orchestration.register_provider(
            provider, account, pool, sessions, adapter
        )
        return provider, sessions

    def attach_adapter(
        self, provider_id: str, adapter: ProviderAdapter
    ) -> None:
        self.orchestration.attach_adapter(provider_id, adapter)

    def register_adapter(
        self,
        provider: ProviderRecord,
        account: ProviderAccountRecord,
        pool: UsagePoolRecord,
        sessions: tuple[ProviderSessionRecord, ...],
        adapter: ProviderAdapter,
    ) -> None:
        self.orchestration.register_provider(
            provider, account, pool, sessions, adapter
        )

    def diagnostics(self) -> dict[str, Any]:
        return {
            "data_directory": str(self.data_directory),
            "pass_b_schema_version": 6,
            "authority": self._authority_health(),
            "launch_authority_configured": (
                self.authority_client is not None
                or self._test_authority_configured
            ),
            "providers": len(self.repository.list(ProviderRecord)),
            "sessions": len(self.repository.list(ProviderSessionRecord)),
            "startup_recovery": dict(self.startup_recovery),
            "presentation_authority_effect": "NONE",
            "automatic_paid_fallback": False,
            "provider_code_loading": False,
        }

    def _authority_health(self) -> dict[str, Any]:
        client = self.authority_health_client
        checked_at = _now()
        if client is None:
            if self._test_authority_configured:
                return {
                    "state": "TEST_COMPOSITION",
                    "production_validation": False,
                    "composition": "TEST_COMPOSITION",
                    "last_checked_at": checked_at,
                }
            return {
                "state": "NOT_CONFIGURED",
                "composition": "NOT_CONFIGURED",
                "last_checked_at": checked_at,
            }
        try:
            value = client.require_live_identity()
        except Exception as error:
            return {
                "state": "UNAVAILABLE",
                "composition": (
                    "PRODUCTION"
                    if self.authority_client is not None
                    else "PRODUCTION_HEALTH_ONLY"
                ),
                "last_checked_at": checked_at,
                "error": f"{type(error).__name__}: {error}",
            }
        if (
            not isinstance(value, dict)
            or (
                not isinstance(value.get("protocol_version"), (str, int))
                or isinstance(value.get("protocol_version"), bool)
            )
            or value.get("observer_available") is not True
        ):
            return {
                "state": "UNAVAILABLE",
                "composition": (
                    "PRODUCTION"
                    if self.authority_client is not None
                    else "PRODUCTION_HEALTH_ONLY"
                ),
                "last_checked_at": checked_at,
                "error": "RuntimeError: malformed KeeperAuthority identity",
            }
        return {
            "state": "READY",
            "service_version": value.get("service_version"),
            "protocol_version": value.get("protocol_version"),
            "schema_version": value.get("schema_version"),
            "service_key_id": value.get("service_key_id"),
            "identity_state": (
                "VERIFIED" if value.get("service_key_id") else "AVAILABLE"
            ),
            "provenance_state": value.get("provenance_state", "NOT_REPORTED"),
            "composition": (
                "PRODUCTION"
                if self.authority_client is not None
                else "PRODUCTION_HEALTH_ONLY"
            ),
            "last_checked_at": checked_at,
            "provider_host": value.get("provider_host"),
        }

    def _ensure_presentation_state(self) -> None:
        if self.repository.optional(
            PresentationStateRecord, "sage-default"
        ) is not None:
            return
        self.repository.insert(
            PresentationStateRecord(
                presentation_state_id="sage-default",
                project_id=None,
                form="default",
                mode=PresentationMode.CONVERSATION,
                expression="neutral",
                intensity=0.25,
                background="black-gold",
                ambient_effect="none",
                updated_at=_now(),
                revision=1,
            )
        )


def _activate_and_reload_charter(
    executive: CharterActivator,
    project_status: ProjectStatusReader,
    charter: ProjectCharter,
) -> tuple[ProjectRecord, ProjectCharter]:
    project = executive.activate_charter(charter)
    active = project_status(project.project_id).get("active_charter")
    if not isinstance(active, dict):
        raise RuntimeError("approved charter activation was not durable")
    return project, ProjectCharter.from_dict(active)


def _project_status(
    executive: ConversationExecutive, project_id: str
) -> dict[str, Any]:
    if isinstance(executive, KeeperExecutive):
        status = executive.status(project_id)
        return {
            "project_summary": dict(status.project_summary),
            "active_charter": (
                dict(status.active_charter)
                if status.active_charter is not None
                else None
            ),
        }
    reader = getattr(executive, "project_status", None)
    if not callable(reader):
        raise PermissionError("Executive project status reader is unavailable")
    value = reader(project_id)
    if not isinstance(value, dict):
        raise PermissionError("Executive project status is malformed")
    return value


def _product_project_status(
    executive: ConversationExecutive, project_id: str
) -> dict[str, Any]:
    if isinstance(executive, KeeperExecutive):
        return executive.status(project_id).to_dict()
    reader = getattr(executive, "project_status", None)
    if not callable(reader):
        raise PermissionError("Executive project status reader is unavailable")
    value = reader(project_id)
    if not isinstance(value, dict):
        raise PermissionError("Executive project status is malformed")
    return value

def _now() -> str:
    return datetime.now(UTC).isoformat()
