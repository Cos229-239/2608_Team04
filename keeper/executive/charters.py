from __future__ import annotations

from dataclasses import replace
from typing import Any

from keeper.executive.enums import (
    ActionCategory,
    ApprovalKind,
    CharterStatus,
    ExecutiveState,
    FounderApprovalIntent,
)
from keeper.executive.intake import IntakeResult
from keeper.executive.models import (
    ApprovalRecord,
    AssumptionRecord,
    AuthorityEnvelope,
    DecisionRecord,
    FounderApprovalChallenge,
    FounderApprovalEvent,
    ProjectCharter,
    ProjectRecord,
    ProposedAction,
    utc_now,
)
from keeper.executive.founder_auth import (
    ApprovalConfirmation,
    ProductionFounderAuthenticator,
    TestFounderAuthenticator,
)
from keeper.executive.repository import (
    ExecutiveRepository,
    ProductionExecutiveRepository,
    TestExecutiveRepository,
    new_id,
)
from keeper.executive.state import transition_project


class CharterService:
    __slots__ = (
        "__repository", "__authenticator", "__production", "__sealed",
    )
    __repository: ExecutiveRepository
    __authenticator: ProductionFounderAuthenticator | TestFounderAuthenticator
    __production: bool
    __sealed: bool

    def __init__(
        self,
        repository: ExecutiveRepository,
        authenticator: ProductionFounderAuthenticator
        | TestFounderAuthenticator,
        *,
        production: bool,
    ) -> None:
        expected_authenticator = (
            ProductionFounderAuthenticator
            if production
            else TestFounderAuthenticator
        )
        expected_repository = (
            ProductionExecutiveRepository
            if production
            else TestExecutiveRepository
        )
        if (
            type(authenticator) is not expected_authenticator
            or type(repository) is not expected_repository
        ):
            raise TypeError(
                "Founder authenticator and repository do not match composition mode"
            )
        object.__setattr__(self, "_CharterService__sealed", False)
        object.__setattr__(self, "_CharterService__repository", repository)
        object.__setattr__(self, "_CharterService__authenticator", authenticator)
        object.__setattr__(self, "_CharterService__production", production)
        object.__setattr__(self, "_CharterService__sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_CharterService__sealed", False):
            raise AttributeError("CharterService authentication composition is immutable")
        object.__setattr__(self, name, value)

    @property
    def repository(self) -> TestExecutiveRepository:
        if not isinstance(self.__repository, TestExecutiveRepository):
            raise AttributeError(
                "production CharterService does not expose its repository"
            )
        return self.__repository

    @classmethod
    def production(
        cls,
        repository: ProductionExecutiveRepository,
        authenticator: ProductionFounderAuthenticator,
    ) -> CharterService:
        return cls(repository, authenticator, production=True)

    @classmethod
    def for_test(
        cls,
        repository: TestExecutiveRepository,
        authenticator: TestFounderAuthenticator,
    ) -> CharterService:
        return cls(repository, authenticator, production=False)

    def create_project(self, intake: IntakeResult) -> ProjectRecord:
        now = utc_now()
        project = ProjectRecord(
            new_id("project"),
            str(intake.explicit("project_name", "Untitled Project")),
            str(intake.explicit("project_type", "general")),
            ExecutiveState.CLARIFICATION_REQUIRED.value if intake.unresolved_questions else ExecutiveState.INTAKE.value,
            None,
            None,
            None,
            now,
            now,
        )
        self.__repository.save_project(project)
        return project

    def draft(self, project: ProjectRecord, intake: IntakeResult) -> ProjectCharter:
        prior = self.__repository.charters(project.project_id)
        revision = max((item.revision for item in prior), default=0) + 1
        now = utc_now()
        workspace_values = tuple(str(item) for item in intake.explicit("workspaces", ()))
        provider_values = tuple(
            str(item)
            for item in intake.explicit("approved_providers", ())
        )
        tool_values = tuple(str(item) for item in intake.explicit("approved_tools", ("filesystem",)))
        deliverables = tuple(str(item) for item in intake.explicit("deliverables", ("project deliverable",)))
        mode = str(intake.explicit("delegation_mode", "ADVISORY"))
        budget_limit = float(intake.explicit("budget_limit", 0.0))
        budget_currency = (
            str(intake.explicit("budget_currency", "USD")).upper()
            if budget_limit > 0
            else None
        )
        allowed_actions = (
            ActionCategory.ANALYZE.value,
            ActionCategory.PLAN.value,
            ActionCategory.DRAFT.value,
            ActionCategory.READ.value,
            ActionCategory.WRITE.value,
            ActionCategory.TEST.value,
            ActionCategory.REVIEW.value,
            ActionCategory.REPAIR.value,
        )
        envelope = AuthorityEnvelope(
            allowed_actions,
            tuple(item.value for item in (
                ActionCategory.COMMIT, ActionCategory.PUSH,
                ActionCategory.DEPLOY_STAGING,
                ActionCategory.DEPLOY_PRODUCTION,
                ActionCategory.PUBLISH_PRIVATE,
                ActionCategory.PUBLISH_PUBLIC,
                ActionCategory.PURCHASE,
                ActionCategory.SPENDING,
            )),
            tuple(item.value for item in (ActionCategory.CREDENTIAL_ACCESS, ActionCategory.SECURITY_BOUNDARY_CHANGE, ActionCategory.HISTORY_REWRITE, ActionCategory.LIVE_TRADING, ActionCategory.FINANCIAL_AUTHORITY_CHANGE, ActionCategory.CHANGE_GOVERNANCE, ActionCategory.EXPAND_SCOPE, ActionCategory.IRREVERSIBLE_DELETE)),
            workspace_values,
            tool_values,
            provider_values,
            budget_limit,
            str(intake.explicit("risk_classification", "LOW")),
            tuple(str(item) for item in intake.explicit("data_classifications", ("INTERNAL",))),
            None,
            budget_currency,
        )
        charter = ProjectCharter(
            new_id("charter"),
            project.project_id,
            project.name,
            project.project_type,
            str(intake.explicit("purpose", intake.explicit("desired_outcome", ""))),
            str(intake.explicit("problem_or_opportunity", "")),
            str(intake.explicit("desired_outcome", "")),
            deliverables,
            tuple(str(item) for item in intake.explicit("non_goals", ())),
            tuple(str(item) for item in intake.explicit("success_criteria", ())),
            tuple(str(item) for item in intake.explicit("constraints", ())),
            intake.proposed_assumptions,
            intake.unresolved_questions,
            _optional_string(intake.explicit("timeline")),
            str(intake.explicit("budget_policy", "spending prohibited")),
            budget_limit,
            tool_values,
            provider_values,
            tuple(str(item) for item in intake.explicit("prohibited_tools", ())),
            tuple(str(item) for item in intake.explicit("prohibited_providers", ())),
            workspace_values,
            tuple(str(item) for item in intake.explicit("data_privacy_restrictions", ("Do not store secrets in project records.",))),
            str(intake.explicit("risk_classification", "LOW")),
            mode,
            envelope,
            tuple(str(item) for item in intake.explicit("escalation_rules", ("Pause when authority is ambiguous or exceeded.",))),
            tuple(str(item) for item in intake.explicit("review_requirements", ("Verify each deliverable against its criteria.",))),
            tuple(str(item) for item in intake.explicit("evidence_requirements", ("Preserve outputs and verification results.",))),
            tuple(str(item) for item in intake.explicit("completion_definition", ("All success criteria and deliverables are satisfied.",))),
            revision,
            CharterStatus.DRAFT.value,
            prior[-1].charter_id if prior else None,
            None,
            (),
            None,
            None,
            now,
            now,
        )
        self.__repository.save_charter(charter)
        for assumption in charter.assumptions:
            self.__repository.insert_assumption(
                AssumptionRecord(
                    new_id("assumption"),
                    project.project_id,
                    revision,
                    assumption,
                    "conversation intake",
                    0.6,
                    "Confirm during charter review.",
                    "May change scope, schedule, or completion criteria.",
                    "PROPOSED",
                    None,
                    now,
                )
            )
        drafted_project = transition_project(
            project
            if project.state
            in {
                ExecutiveState.INTAKE,
                ExecutiveState.CLARIFICATION_REQUIRED,
            }
            else replace(project, state=ExecutiveState.INTAKE.value),
            ExecutiveState.CHARTER_DRAFT,
        )
        self.__repository.save_project(
            drafted_project,
            expected=project,
        )
        return charter

    def propose(self, charter: ProjectCharter) -> ProjectCharter:
        if charter.status != CharterStatus.DRAFT:
            raise PermissionError("only draft charters may be proposed")
        proposed = replace(charter, status=CharterStatus.PROPOSED.value, updated_at=utc_now())
        self.__repository.save_charter(proposed, expected=charter)
        project = self.__repository.project(charter.project_id)
        self.__repository.save_project(
            transition_project(
                project, ExecutiveState.AWAITING_CHARTER_APPROVAL
            ),
            expected=project,
        )
        return proposed

    def approve(
        self,
        charter: ProjectCharter,
        *,
        approver: str,
        source_interaction_id: str,
    ) -> tuple[ProjectCharter, ApprovalRecord]:
        return self.__repository.approve_charter(
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            approver=approver,
            source_interaction_id=source_interaction_id,
        )

    def request_approval(
        self, charter: ProjectCharter
    ) -> FounderApprovalChallenge:
        return self.__repository.create_charter_approval_challenge(
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
        )

    def confirm_approval(
        self,
        challenge_id: str,
        *,
        intent: FounderApprovalIntent,
        confirmation: ApprovalConfirmation | None = None,
    ) -> tuple[ProjectCharter, ApprovalRecord, FounderApprovalEvent]:
        return self.__repository.confirm_charter_approval(
            challenge_id=challenge_id,
            confirmation=confirmation,
            explicit_intent=intent,
        )

    def authenticate(
        self, challenge: FounderApprovalChallenge
    ) -> ApprovalConfirmation:
        confirmation = self.__authenticator.authenticate(challenge)
        self.__repository.register_founder_session(
            challenge_id=challenge.challenge_id,
            confirmation=confirmation,
        )
        return confirmation

    def request_action_approval(
        self,
        action: ProposedAction,
        *,
        charter_id: str,
        kind: ApprovalKind,
        scope: tuple[str, ...],
        limits: dict[str, Any],
        expires_at: str | None = None,
    ) -> FounderApprovalChallenge:
        return self.__repository.create_action_approval_challenge(
            action,
            charter_id=charter_id,
            kind=kind,
            scope=scope,
            limits=limits,
            expires_at=expires_at,
        )

    def confirm_action_approval(
        self,
        challenge_id: str,
        *,
        confirmation: ApprovalConfirmation | None,
        intent: FounderApprovalIntent,
    ) -> tuple[ApprovalRecord, FounderApprovalEvent]:
        return self.__repository.confirm_action_approval(
            challenge_id=challenge_id,
            confirmation=confirmation,
            explicit_intent=intent,
        )

    def activate(self, charter: ProjectCharter) -> ProjectRecord:
        active, stored_charter, approval = self.__repository.activate_charter(
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
        )
        self.__repository.insert_decision(
            DecisionRecord(
                new_id("decision"),
                stored_charter.project_id,
                stored_charter.revision,
                "Activate Project Charter",
                ("keep draft", "activate approved charter"),
                "activate approved charter",
                "Explicit local Founder approval authorizes project execution within the charter.",
                stored_charter.founder_approval_identity
                or "AUTHENTICATED_FOUNDER",
                approval.approval_id,
                (approval.approval_id,),
                ("Keeper may plan and act only within the active authority envelope.",),
                True,
                utc_now(),
                None,
            )
        )
        return active

    def revise(
        self,
        active: ProjectCharter,
        changes: dict[str, Any],
        *,
        reason: str,
        authority_basis: str,
    ) -> ProjectCharter:
        durable = self.__repository.charter(active.charter_id)
        if (
            durable.status not in {CharterStatus.APPROVED, CharterStatus.ACTIVE}
            or durable.project_id != active.project_id
            or durable.revision != active.revision
            or not reason.strip()
        ):
            raise PermissionError("only the current approved charter may be amended")
        forbidden = {
            "charter_id", "project_id", "revision", "status", "created_at",
            "founder_approval_identity", "founder_approval_record_id",
            "founder_approval_event_id", "founder_approval_event_digest",
            "founder_authenticated_session_id",
            "founder_authorization_capability",
            "founder_authorization_capability_digest",
        }
        if set(changes) & forbidden or not set(changes).issubset(ProjectCharter.FIELDS):
            raise ValueError("charter revision contains forbidden or unknown fields")
        data = durable.to_dict()
        differences: list[str] = []
        for key, value in changes.items():
            if data[key] != value:
                differences.append(f"{key}: {data[key]!r} -> {value!r}")
                data[key] = value
        data.update(
            {
                "charter_id": new_id("charter"),
                "revision": active.revision + 1,
                "status": CharterStatus.DRAFT.value,
                "supersedes_charter_id": active.charter_id,
                "change_reason": reason,
                "differences": differences + [f"authority_basis: {authority_basis}"],
                "founder_approval_identity": None,
                "founder_approval_record_id": None,
                "founder_approval_event_id": None,
                "founder_approval_event_digest": None,
                "founder_authenticated_session_id": None,
                "founder_authorization_capability": None,
                "founder_authorization_capability_digest": None,
                "created_at": utc_now(),
                "updated_at": utc_now(),
            }
        )
        revised = ProjectCharter.from_dict(data)
        self.__repository.save_charter(revised)
        project = self.__repository.project(active.project_id)
        paused = replace(project, state=ExecutiveState.PAUSED.value, pause_reason="Charter revision awaiting approval", updated_at=utc_now())
        self.__repository.save_project(paused, expected=project)
        return revised


def _optional_string(value: Any) -> str | None:
    return str(value) if value is not None else None
