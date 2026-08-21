from __future__ import annotations

from pathlib import Path
from typing import Any

from keeper.app.storage import KeeperStore
from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.executive.authority_gateway import (
    AuthorityProviderBinding,
    ProductionAuthorityBackedSpecialistGateway,
)
from keeper.executive.charters import CharterService
from keeper.executive.founder_auth import ProductionFounderAuthenticator
from keeper.executive.intake import ConversationIntake, IntakeResult
from keeper.executive.models import (
    ApprovalRecord,
    FounderApprovalChallenge,
    FounderApprovalEvent,
    MemoryRecord,
    ProposedAction,
    ProjectCharter,
    ProjectRecord,
    utc_now,
)
from keeper.executive.enums import ApprovalKind, FounderApprovalIntent
from keeper.executive.founder_auth import ProductionApprovalConfirmation
from keeper.executive.repository import ProductionExecutiveRepository, new_id
from keeper.executive.runtime import ExecutiveRuntime
from keeper.executive.surfaces import ProjectStatusView, StatusSurface


class KeeperExecutive:
    """Narrow production facade; trusted repository state is never exposed."""

    __repository: ProductionExecutiveRepository
    __charters: CharterService
    __intake: ConversationIntake
    __sealed: bool
    __slots__ = ("__repository", "__charters", "__intake", "__sealed")

    def __init__(self, database: Path) -> None:
        object.__setattr__(self, "_KeeperExecutive__sealed", False)
        store = KeeperStore(database)
        store.migrate()
        authenticator = ProductionFounderAuthenticator(
            database.parent / "founder-auth" / "proof-key.dpapi"
        )
        repository = ProductionExecutiveRepository(store, authenticator)
        object.__setattr__(self, "_KeeperExecutive__repository", repository)
        object.__setattr__(
            self,
            "_KeeperExecutive__charters",
            CharterService.production(repository, authenticator),
        )
        object.__setattr__(
            self, "_KeeperExecutive__intake", ConversationIntake()
        )
        object.__setattr__(self, "_KeeperExecutive__sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_KeeperExecutive__sealed", False):
            raise AttributeError("KeeperExecutive production composition is immutable")
        object.__setattr__(self, name, value)

    def _trusted_repository(self) -> ProductionExecutiveRepository:
        repository = self.__repository
        if type(repository) is not ProductionExecutiveRepository:
            raise RuntimeError("production Executive repository composition is invalid")
        return repository

    def issue_pass_b_delivered_input_receipt(
        self,
        delivered_input_id: str,
        *,
        authority_attempt_id: str,
        provider_input_digest: str,
        delivered_input_digest: str,
        manifest_digest: str,
    ) -> dict[str, object]:
        return self._trusted_repository().issue_pass_b_delivered_input_receipt(
            delivered_input_id,
            authority_attempt_id=authority_attempt_id,
            provider_input_digest=provider_input_digest,
            delivered_input_digest=delivered_input_digest,
            manifest_digest=manifest_digest,
        )

    def begin(self, message: str) -> tuple[ProjectRecord, IntakeResult]:
        result = self.__intake.extract(message)
        project = self.__charters.create_project(result)
        interaction_id = new_id("interaction")
        self._trusted_repository().save_conversation(
            interaction_id,
            {
                "interaction_id": interaction_id,
                "project_id": project.project_id,
                "speaker": "Founder",
                "message": message,
                "created_at": utc_now(),
            },
        )
        for field_name, item in result.fields.items():
            self._trusted_repository().insert_memory(
                MemoryRecord(
                    new_id("memory"),
                    project.project_id,
                    0,
                    None,
                    None,
                    "FACT" if item.provenance == "EXPLICIT" else "ASSUMPTION",
                    item.provenance,
                    f"intake:{field_name}",
                    str(item.value),
                    field_name in {
                        "budget_policy",
                        "budget_limit",
                        "delegation_mode",
                        "workspaces",
                        "approved_providers",
                        "approved_tools",
                    },
                    (interaction_id,),
                    None,
                    utc_now(),
                )
            )
        return project, result

    def draft(
        self,
        project_id: str,
        intake: IntakeResult,
        *,
        founder_revisions: dict[str, Any] | None = None,
    ) -> ProjectCharter:
        revised = (
            ConversationIntake.revise(intake, replacements=founder_revisions)
            if founder_revisions
            else intake
        )
        return self.__charters.draft(self._trusted_repository().project(project_id), revised)

    def propose_charter(self, charter: ProjectCharter) -> ProjectCharter:
        return self.__charters.propose(charter)

    def request_charter_approval(
        self, charter: ProjectCharter
    ) -> FounderApprovalChallenge:
        return self.__charters.request_approval(charter)

    def authenticate_founder(
        self, challenge: FounderApprovalChallenge
    ) -> ProductionApprovalConfirmation:
        confirmation = self.__charters.authenticate(challenge)
        if type(confirmation) is not ProductionApprovalConfirmation:
            raise RuntimeError("production Founder confirmation type is invalid")
        return confirmation

    def confirm_charter_approval(
        self,
        challenge_id: str,
        confirmation: ProductionApprovalConfirmation,
    ) -> tuple[ProjectCharter, ApprovalRecord, FounderApprovalEvent]:
        return self.__charters.confirm_approval(
            challenge_id,
            intent=FounderApprovalIntent.APPROVE_CHARTER,
            confirmation=confirmation,
        )

    def activate_charter(self, charter: ProjectCharter) -> ProjectRecord:
        return self.__charters.activate(charter)

    def request_action_approval(
        self,
        action: ProposedAction,
        *,
        charter_id: str,
        scope: tuple[str, ...],
        limits: dict[str, Any],
    ) -> FounderApprovalChallenge:
        return self.__charters.request_action_approval(
            action,
            charter_id=charter_id,
            kind=ApprovalKind.ONE_TIME,
            scope=scope,
            limits=limits,
        )

    def confirm_action_approval(
        self,
        challenge_id: str,
        confirmation: ProductionApprovalConfirmation,
    ) -> tuple[ApprovalRecord, FounderApprovalEvent]:
        return self.__charters.confirm_action_approval(
            challenge_id,
            confirmation=confirmation,
            intent=FounderApprovalIntent.APPROVE_ACTION,
        )

    def reserve_action_authority(
        self,
        action: ProposedAction,
        *,
        approval_id: str,
        task_id: str | None = None,
    ) -> tuple[ApprovalRecord, str | None]:
        return self._trusted_repository().reserve_action_authority(
            action,
            approval_id=approval_id,
            task_id=task_id,
        )

    def status(self, project_id: str) -> ProjectStatusView:
        return StatusSurface(self._trusted_repository()).project(project_id)

    def production_runtime(
        self,
        authority_client: ProductionAuthorityServiceClient,
        *,
        provider_bindings: tuple[AuthorityProviderBinding, ...],
        exchange_root: Path,
    ) -> ExecutiveRuntime:
        """Fail-closed production composition root; no mock gateway seam."""
        if type(authority_client) is not ProductionAuthorityServiceClient:
            raise RuntimeError(
                "production runtime requires the production Authority client"
            )
        authority_client.require_live_identity()
        gateway = ProductionAuthorityBackedSpecialistGateway(
            authority_client,
            provider_bindings,
            exchange_root,
        )
        return ExecutiveRuntime.production(self._trusted_repository(), gateway)
