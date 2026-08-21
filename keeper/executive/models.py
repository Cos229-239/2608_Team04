from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar, TypeVar, cast

from keeper.executive.enums import (
    ActionEffect,
    ActionCategory,
    ApprovalKind,
    AuthorityOutcome,
    CharterStatus,
    DelegationMode,
    ExecutiveState,
    FounderApprovalIntent,
    MemoryKind,
    ReviewPolicy,
    TaskStatus,
    ValueProvenance,
)


T = TypeVar("T", bound="StrictRecord")


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def validate_timestamp(value: str, field_name: str) -> None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{field_name} must be an ISO timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone aware")


@dataclass(frozen=True, slots=True)
class StrictRecord:
    FIELDS: ClassVar[frozenset[str]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def _validated_data(cls: type[T], value: dict[str, Any]) -> dict[str, Any]:
        unknown = set(value) - cls.FIELDS
        missing = cls.FIELDS - set(value)
        if unknown or missing:
            raise ValueError(
                f"{cls.__name__} fields invalid; unknown={sorted(unknown)}, "
                f"missing={sorted(missing)}"
            )
        return dict(value)


@dataclass(frozen=True, slots=True)
class AuthorityEnvelope(StrictRecord):
    allowed_actions: tuple[str, ...]
    separately_approvable_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]
    allowed_workspaces: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    allowed_providers: tuple[str, ...]
    maximum_cost: float
    risk_limit: str
    data_classifications: tuple[str, ...]
    expires_at: str | None
    currency: str | None = None

    FIELDS = frozenset(
        {
            "allowed_actions",
            "separately_approvable_actions",
            "denied_actions",
            "allowed_workspaces",
            "allowed_tools",
            "allowed_providers",
            "maximum_cost",
            "risk_limit",
            "data_classifications",
            "expires_at",
            "currency",
        }
    )

    def __post_init__(self) -> None:
        if self.maximum_cost < 0:
            raise ValueError("maximum_cost cannot be negative")
        if self.expires_at is not None:
            validate_timestamp(self.expires_at, "expires_at")
        if self.currency is not None and (
            len(self.currency) != 3 or not self.currency.isalpha()
        ):
            raise ValueError("currency must be a three-letter code")
        for value in (
            *self.allowed_actions,
            *self.separately_approvable_actions,
            *self.denied_actions,
        ):
            ActionCategory(value)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AuthorityEnvelope:
        normalized = dict(value)
        normalized.setdefault("currency", None)
        data = cls._validated_data(normalized)
        for key in (
            "allowed_actions", "separately_approvable_actions", "denied_actions"
        ):
            data[key] = tuple(
                ActionCategory(item).value for item in data[key]
            )
        for key in (
            "allowed_workspaces",
            "allowed_tools",
            "allowed_providers",
            "data_classifications",
        ):
            data[key] = tuple(data[key])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ProjectRecord(StrictRecord):
    project_id: str
    name: str
    project_type: str
    state: str
    active_charter_id: str | None
    active_charter_revision: int | None
    pause_reason: str | None
    created_at: str
    updated_at: str

    FIELDS = frozenset(
        {
            "project_id",
            "name",
            "project_type",
            "state",
            "active_charter_id",
            "active_charter_revision",
            "pause_reason",
            "created_at",
            "updated_at",
        }
    )

    def __post_init__(self) -> None:
        ExecutiveState(self.state)
        validate_timestamp(self.created_at, "created_at")
        validate_timestamp(self.updated_at, "updated_at")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ProjectRecord:
        return cls(**cls._validated_data(value))


@dataclass(frozen=True, slots=True)
class ProjectCharter(StrictRecord):
    charter_id: str
    project_id: str
    title: str
    project_type: str
    purpose: str
    problem_statement: str
    desired_outcome: str
    deliverables: tuple[str, ...]
    non_goals: tuple[str, ...]
    success_criteria: tuple[str, ...]
    constraints: tuple[str, ...]
    assumptions: tuple[str, ...]
    unresolved_questions: tuple[str, ...]
    timeline: str | None
    budget_policy: str
    budget_limit: float
    approved_tools: tuple[str, ...]
    approved_providers: tuple[str, ...]
    prohibited_tools: tuple[str, ...]
    prohibited_providers: tuple[str, ...]
    workspaces: tuple[str, ...]
    data_privacy_restrictions: tuple[str, ...]
    risk_classification: str
    delegation_mode: str
    authority_envelope: AuthorityEnvelope
    escalation_rules: tuple[str, ...]
    review_requirements: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    completion_definition: tuple[str, ...]
    revision: int
    status: str
    supersedes_charter_id: str | None
    change_reason: str | None
    differences: tuple[str, ...]
    founder_approval_identity: str | None
    founder_approval_record_id: str | None
    created_at: str
    updated_at: str
    founder_approval_event_id: str | None = None
    founder_approval_event_digest: str | None = None
    founder_authenticated_session_id: str | None = None
    founder_authorization_capability: dict[str, Any] | None = None
    founder_authorization_capability_digest: str | None = None

    FIELDS = frozenset(
        {
            "charter_id", "project_id", "title", "project_type", "purpose",
            "problem_statement", "desired_outcome", "deliverables", "non_goals",
            "success_criteria", "constraints", "assumptions", "unresolved_questions",
            "timeline", "budget_policy", "budget_limit", "approved_tools",
            "approved_providers", "prohibited_tools", "prohibited_providers",
            "workspaces", "data_privacy_restrictions", "risk_classification",
            "delegation_mode", "authority_envelope", "escalation_rules",
            "review_requirements", "evidence_requirements", "completion_definition",
            "revision", "status", "supersedes_charter_id", "change_reason",
            "differences", "founder_approval_identity", "founder_approval_record_id",
            "created_at", "updated_at",
            "founder_approval_event_id", "founder_approval_event_digest",
            "founder_authenticated_session_id",
            "founder_authorization_capability",
            "founder_authorization_capability_digest",
        }
    )
    TUPLE_FIELDS = (
        "deliverables", "non_goals", "success_criteria", "constraints", "assumptions",
        "unresolved_questions", "approved_tools", "approved_providers",
        "prohibited_tools", "prohibited_providers", "workspaces",
        "data_privacy_restrictions", "escalation_rules", "review_requirements",
        "evidence_requirements", "completion_definition", "differences",
    )

    def __post_init__(self) -> None:
        if self.revision < 1 or self.budget_limit < 0:
            raise ValueError("charter revision and budget must be valid")
        CharterStatus(self.status)
        DelegationMode(self.delegation_mode)
        validate_timestamp(self.created_at, "created_at")
        validate_timestamp(self.updated_at, "updated_at")
        if self.status in {CharterStatus.APPROVED, CharterStatus.ACTIVE} and (
            not self.founder_approval_identity
            or not self.founder_approval_record_id
            or not isinstance(self.founder_authorization_capability, dict)
            or not self.founder_authorization_capability_digest
        ):
            raise ValueError(
                "approved charters require a Founder approval and capability"
            )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ProjectCharter:
        normalized = dict(value)
        normalized.setdefault("founder_approval_event_id", None)
        normalized.setdefault("founder_approval_event_digest", None)
        normalized.setdefault("founder_authenticated_session_id", None)
        normalized.setdefault("founder_authorization_capability", None)
        normalized.setdefault("founder_authorization_capability_digest", None)
        data = cls._validated_data(normalized)
        for key in cls.TUPLE_FIELDS:
            data[key] = tuple(data[key])
        envelope = data["authority_envelope"]
        if not isinstance(envelope, dict):
            raise ValueError("authority_envelope must be an object")
        data["authority_envelope"] = AuthorityEnvelope.from_dict(envelope)
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ApprovalRecord(StrictRecord):
    approval_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    kind: str
    action_category: str | None
    approver: str
    scope: tuple[str, ...]
    limits: dict[str, Any]
    approved_at: str
    expires_at: str | None
    revoked_at: str | None
    consumed_at: str | None
    evidence_digest: str
    source_interaction_id: str

    FIELDS = frozenset(
        {
            "approval_id", "project_id", "charter_id", "charter_revision", "kind",
            "action_category", "approver", "scope", "limits", "approved_at",
            "expires_at", "revoked_at", "consumed_at", "evidence_digest",
            "source_interaction_id",
        }
    )

    def __post_init__(self) -> None:
        ApprovalKind(self.kind)
        if self.action_category is not None:
            ActionCategory(self.action_category)
        for name, value in (
            ("approved_at", self.approved_at),
            ("expires_at", self.expires_at),
            ("revoked_at", self.revoked_at),
            ("consumed_at", self.consumed_at),
        ):
            if value is not None:
                validate_timestamp(value, name)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ApprovalRecord:
        data = cls._validated_data(value)
        data["scope"] = tuple(data["scope"])
        if data["action_category"] is not None:
            data["action_category"] = ActionCategory(
                data["action_category"]
            ).value
        return cls(**data)


@dataclass(frozen=True, slots=True)
class FounderApprovalChallenge(StrictRecord):
    challenge_id: str
    schema_version: int
    project_id: str
    charter_id: str
    charter_revision: int
    charter_digest: str
    approval_action: str
    approval_binding: dict[str, Any] | None
    nonce: str
    requested_at: str
    expires_at: str
    state: str
    consumed_event_id: str | None

    FIELDS = frozenset(
        {
            "challenge_id",
            "schema_version",
            "project_id",
            "charter_id",
            "charter_revision",
            "charter_digest",
            "approval_action",
            "approval_binding",
            "nonce",
            "requested_at",
            "expires_at",
            "state",
            "consumed_event_id",
        }
    )

    def __post_init__(self) -> None:
        if self.schema_version != 2 or self.state not in {"PENDING", "CONSUMED"}:
            raise ValueError("Founder approval challenge is invalid")
        FounderApprovalIntent(self.approval_action)
        if self.approval_action == FounderApprovalIntent.APPROVE_ACTION:
            if not isinstance(self.approval_binding, dict):
                raise ValueError("action approval challenge requires an exact binding")
        elif self.approval_binding is not None:
            raise ValueError("charter approval challenge cannot contain an action binding")
        validate_timestamp(self.requested_at, "requested_at")
        validate_timestamp(self.expires_at, "expires_at")

    @classmethod
    def from_dict(
        cls, value: dict[str, Any]
    ) -> FounderApprovalChallenge:
        return cls(**cls._validated_data(value))


@dataclass(frozen=True, slots=True)
class FounderApprovalEvent(StrictRecord):
    event_id: str
    schema_version: int
    authenticated_identity: str
    authentication_method: str
    authenticated_account: str
    authenticated_session_id: str
    machine_identity: str
    application_identity: str
    project_id: str
    charter_id: str
    charter_revision: int
    charter_digest: str
    approval_action: str
    explicit_intent: str
    challenge_id: str
    challenge_response_digest: str
    proof_version: int
    source_user_interaction_id: str
    confirmed_at: str
    expires_at: str | None

    FIELDS = frozenset(
        {
            "event_id",
            "schema_version",
            "authenticated_identity",
            "authentication_method",
            "authenticated_account",
            "authenticated_session_id",
            "machine_identity",
            "application_identity",
            "project_id",
            "charter_id",
            "charter_revision",
            "charter_digest",
            "approval_action",
            "explicit_intent",
            "challenge_id",
            "challenge_response_digest",
            "proof_version",
            "source_user_interaction_id",
            "confirmed_at",
            "expires_at",
        }
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version != 2
            or not self.authenticated_identity.startswith("S-1-")
            or self.authentication_method
            not in {"WINDOWS_CREDENTIAL_LOGON", "TEST_CHALLENGE_HMAC"}
            or not self.authenticated_account
            or not self.authenticated_session_id
            or not self.machine_identity
            or self.application_identity != "KEEPER_EXECUTIVE"
            or self.proof_version != 2
            or not self.source_user_interaction_id
        ):
            raise ValueError("Founder approval event is invalid")
        FounderApprovalIntent(self.approval_action)
        validate_timestamp(self.confirmed_at, "confirmed_at")
        if self.expires_at is not None:
            validate_timestamp(self.expires_at, "expires_at")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> FounderApprovalEvent:
        return cls(**cls._validated_data(value))


@dataclass(frozen=True, slots=True)
class FounderAuthenticatedSession(StrictRecord):
    session_id: str
    schema_version: int
    principal_sid: str
    account_name: str
    authentication_method: str
    authenticated_at: str
    expires_at: str
    machine_identity: str
    application_identity: str
    process_identity: str
    challenge_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    approval_action: str
    bound_digest: str
    proof_digest: str
    state: str
    revoked_at: str | None
    consumed_at: str | None

    FIELDS = frozenset(
        {
            "session_id", "schema_version", "principal_sid", "account_name",
            "authentication_method", "authenticated_at", "expires_at",
            "machine_identity", "application_identity", "process_identity",
            "challenge_id", "project_id", "charter_id", "charter_revision",
            "approval_action", "bound_digest", "proof_digest", "state",
            "revoked_at", "consumed_at",
        }
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version != 2
            or not self.principal_sid.startswith("S-1-")
            or self.authentication_method
            not in {"WINDOWS_CREDENTIAL_LOGON", "TEST_CHALLENGE_HMAC"}
            or self.application_identity != "KEEPER_EXECUTIVE"
            or self.state not in {"ACTIVE", "CONSUMED", "REVOKED"}
        ):
            raise ValueError("authenticated Founder session is invalid")
        FounderApprovalIntent(self.approval_action)
        validate_timestamp(self.authenticated_at, "authenticated_at")
        validate_timestamp(self.expires_at, "expires_at")
        if self.revoked_at is not None:
            validate_timestamp(self.revoked_at, "revoked_at")
        if self.consumed_at is not None:
            validate_timestamp(self.consumed_at, "consumed_at")

    @classmethod
    def from_dict(
        cls, value: dict[str, Any]
    ) -> FounderAuthenticatedSession:
        return cls(**cls._validated_data(value))


@dataclass(frozen=True, slots=True)
class ActionEffects(StrictRecord):
    side_effect_classes: tuple[str, ...]
    execution_environment: str
    external_visibility: str
    publication_effect: str
    deployment_effect: str
    production_effect: str
    spending_effect: str
    git_mutation: str
    security_boundary_effect: str
    credential_requirement: str
    financial_effect: str
    target_resource: str
    workspace: str | None
    provider: str | None
    tool: str | None
    reversible: bool
    data_classification: str

    FIELDS = frozenset(
        {
            "side_effect_classes", "execution_environment",
            "external_visibility", "publication_effect", "deployment_effect",
            "production_effect", "spending_effect", "git_mutation",
            "security_boundary_effect", "credential_requirement",
            "financial_effect", "target_resource", "workspace", "provider",
            "tool", "reversible", "data_classification",
        }
    )

    def __post_init__(self) -> None:
        for item in self.side_effect_classes:
            ActionEffect(item)
        allowed = {
            "execution_environment": {"LOCAL", "STAGING", "PRODUCTION", "EXTERNAL", "UNKNOWN"},
            "external_visibility": {"INTERNAL", "PRIVATE", "PUBLIC", "CUSTOMER_FACING", "UNKNOWN"},
            "publication_effect": {"NONE", "PRIVATE", "PUBLIC", "UNKNOWN"},
            "deployment_effect": {"NONE", "STAGING", "PRODUCTION", "UNKNOWN"},
            "production_effect": {"NONE", "LIVE", "UNKNOWN"},
            "spending_effect": {"NONE", "INCLUDED_PLAN", "PAID", "UNKNOWN"},
            "git_mutation": {"NONE", "COMMIT", "PUSH", "HISTORY_REWRITE", "UNKNOWN"},
            "security_boundary_effect": {"NONE", "CHANGE", "UNKNOWN"},
            "credential_requirement": {"NONE", "REQUIRED", "UNKNOWN"},
            "financial_effect": {"NONE", "LIVE_TRADING", "AUTHORITY_CHANGE", "UNKNOWN"},
        }
        for field_name, values in allowed.items():
            if getattr(self, field_name) not in values:
                raise ValueError(f"invalid structured action effect: {field_name}")
        if not self.target_resource or not self.data_classification:
            raise ValueError("structured action target and data classification are required")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ActionEffects:
        data = cls._validated_data(value)
        data["side_effect_classes"] = tuple(data["side_effect_classes"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ProposedAction(StrictRecord):
    action_id: str
    project_id: str
    charter_revision: int
    category: str
    target_resource: str
    provider: str | None
    tool: str | None
    workspace: str | None
    scope: tuple[str, ...]
    cost: float | None
    reversible: bool
    risk: str
    data_classification: str
    external_side_effect: bool
    objective: str = ""
    currency: str | None = None
    publication: bool = False
    deployment: bool = False
    spending: bool = False
    git_mutation: str | None = None
    security_boundary_impact: bool = False
    trusted_source: str = "CALLER"
    effect_classes: tuple[str, ...] = ()
    repository: str | None = None
    branch: str | None = None

    FIELDS = frozenset(
        {
            "action_id", "project_id", "charter_revision", "category",
            "target_resource", "provider", "tool", "workspace", "scope", "cost",
            "reversible", "risk", "data_classification", "external_side_effect",
            "objective", "currency", "publication", "deployment", "spending",
            "git_mutation", "security_boundary_impact", "trusted_source",
            "effect_classes",
            "repository", "branch",
        }
    )

    def __post_init__(self) -> None:
        ActionCategory(self.category)
        if self.cost is not None and self.cost < 0:
            raise ValueError("action cost cannot be negative")
        if self.currency is not None and (
            len(self.currency) != 3 or not self.currency.isalpha()
        ):
            raise ValueError("currency must be a three-letter code")
        for item in self.effect_classes:
            ActionEffect(item)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ProposedAction:
        normalized = dict(value)
        for key, default in {
            "objective": "",
            "currency": None,
            "publication": False,
            "deployment": False,
            "spending": False,
            "git_mutation": None,
            "security_boundary_impact": False,
            "trusted_source": "CALLER",
            "effect_classes": (),
            "repository": None,
            "branch": None,
        }.items():
            normalized.setdefault(key, default)
        data = cls._validated_data(normalized)
        data["category"] = ActionCategory(data["category"]).value
        data["scope"] = tuple(data["scope"])
        data["effect_classes"] = tuple(data["effect_classes"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class AuthorityDecision(StrictRecord):
    outcome: str
    rule: str
    charter_field: str
    limits: dict[str, Any]
    reason: str
    required_next_step: str
    approval_id: str | None = None

    FIELDS = frozenset(
        {
            "outcome", "rule", "charter_field", "limits", "reason",
            "required_next_step", "approval_id",
        }
    )

    def __post_init__(self) -> None:
        AuthorityOutcome(self.outcome)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AuthorityDecision:
        return cls(**cls._validated_data(value))


@dataclass(frozen=True, slots=True)
class WorkflowStage(StrictRecord):
    stage_id: str
    title: str
    purpose: str
    rationale: str
    dependencies: tuple[str, ...]
    milestone: bool

    FIELDS = frozenset(
        {"stage_id", "title", "purpose", "rationale", "dependencies", "milestone"}
    )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> WorkflowStage:
        data = cls._validated_data(value)
        data["dependencies"] = tuple(data["dependencies"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class WorkflowRecord(StrictRecord):
    workflow_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    revision: int
    strategy: str
    explanation: str
    stages: tuple[WorkflowStage, ...]
    created_at: str

    FIELDS = frozenset(
        {
            "workflow_id", "project_id", "charter_id", "charter_revision",
            "revision", "strategy", "explanation", "stages", "created_at",
        }
    )

    def __post_init__(self) -> None:
        validate_timestamp(self.created_at, "created_at")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> WorkflowRecord:
        data = cls._validated_data(value)
        data["stages"] = tuple(
            WorkflowStage.from_dict(item) for item in data["stages"]
        )
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ExecutiveTask(StrictRecord):
    task_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    workflow_id: str
    stage_id: str
    title: str
    objective: str
    role: str
    required_capabilities: tuple[str, ...]
    instructions: tuple[str, ...]
    constraints: tuple[str, ...]
    dependencies: tuple[str, ...]
    provider_id: str | None
    model_id: str | None
    session_id: str | None
    status: str
    authority_category: str
    inputs: tuple[str, ...]
    expected_outputs: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    review_requirements: tuple[str, ...]
    retry_count: int
    max_retries: int
    attempt_history: tuple[dict[str, Any], ...]
    result_disposition: str | None
    created_at: str
    updated_at: str
    revision: int = 1
    authority_attempt_id: str | None = None
    artifact_digest: str | None = None
    review_attempt_id: str | None = None
    late_result: bool = False
    action_effects: ActionEffects | None = None

    FIELDS = frozenset(
        {
            "task_id", "project_id", "charter_id", "charter_revision",
            "workflow_id", "stage_id", "title", "objective", "role",
            "required_capabilities", "instructions", "constraints", "dependencies",
            "provider_id", "model_id", "session_id", "status",
            "authority_category", "inputs", "expected_outputs",
            "evidence_requirements", "review_requirements", "retry_count",
            "max_retries", "attempt_history", "result_disposition", "created_at",
            "updated_at", "revision", "authority_attempt_id", "artifact_digest",
            "review_attempt_id", "late_result", "action_effects",
        }
    )
    TUPLE_FIELDS = (
        "required_capabilities", "instructions", "constraints", "dependencies",
        "inputs", "expected_outputs", "evidence_requirements", "review_requirements",
        "attempt_history",
    )

    def __post_init__(self) -> None:
        TaskStatus(self.status)
        ActionCategory(self.authority_category)
        if self.action_effects is not None:
            if self.action_effects.target_resource != self.objective:
                raise ValueError("action effect target must match the task objective")
        if self.retry_count < 0 or self.max_retries < 0:
            raise ValueError("retry counts cannot be negative")
        if self.revision < 1:
            raise ValueError("task revision must be positive")
        validate_timestamp(self.created_at, "created_at")
        validate_timestamp(self.updated_at, "updated_at")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ExecutiveTask:
        normalized = dict(value)
        for key, default in {
            "revision": 1,
            "authority_attempt_id": None,
            "artifact_digest": None,
            "review_attempt_id": None,
            "late_result": False,
            "action_effects": None,
        }.items():
            normalized.setdefault(key, default)
        data = cls._validated_data(normalized)
        data["authority_category"] = ActionCategory(
            data["authority_category"]
        ).value
        for key in cls.TUPLE_FIELDS:
            data[key] = tuple(data[key])
        effects = data["action_effects"]
        if isinstance(effects, dict):
            data["action_effects"] = ActionEffects.from_dict(effects)
        return cls(**data)


@dataclass(frozen=True, slots=True)
class DecisionRecord(StrictRecord):
    decision_id: str
    project_id: str
    charter_revision: int
    subject: str
    options_considered: tuple[str, ...]
    selected_option: str
    rationale: str
    decision_maker: str
    authority_basis: str
    evidence: tuple[str, ...]
    consequences: tuple[str, ...]
    reversible: bool
    decided_at: str
    supersedes_decision_id: str | None

    FIELDS = frozenset(
        {
            "decision_id", "project_id", "charter_revision", "subject",
            "options_considered", "selected_option", "rationale", "decision_maker",
            "authority_basis", "evidence", "consequences", "reversible",
            "decided_at", "supersedes_decision_id",
        }
    )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> DecisionRecord:
        data = cls._validated_data(value)
        for key in ("options_considered", "evidence", "consequences"):
            data[key] = tuple(data[key])
        validate_timestamp(cast(str, data["decided_at"]), "decided_at")
        return cls(**data)


@dataclass(frozen=True, slots=True)
class AssumptionRecord(StrictRecord):
    assumption_id: str
    project_id: str
    charter_revision: int
    assumption: str
    source: str
    confidence: float
    validation_plan: str
    impact_if_false: str
    status: str
    resolution: str | None
    created_at: str

    FIELDS = frozenset(
        {
            "assumption_id", "project_id", "charter_revision", "assumption",
            "source", "confidence", "validation_plan", "impact_if_false", "status",
            "resolution", "created_at",
        }
    )

    def __post_init__(self) -> None:
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between zero and one")
        validate_timestamp(self.created_at, "created_at")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AssumptionRecord:
        return cls(**cls._validated_data(value))


@dataclass(frozen=True, slots=True)
class MemoryRecord(StrictRecord):
    memory_id: str
    project_id: str
    charter_revision: int
    task_id: str | None
    stage_id: str | None
    kind: str
    provenance: str
    category: str
    content: str
    authority_relevant: bool
    evidence: tuple[str, ...]
    superseded_by: str | None
    created_at: str

    FIELDS = frozenset(
        {
            "memory_id", "project_id", "charter_revision", "task_id", "stage_id",
            "kind", "provenance", "category", "content", "authority_relevant",
            "evidence", "superseded_by", "created_at",
        }
    )

    def __post_init__(self) -> None:
        MemoryKind(self.kind)
        ValueProvenance(self.provenance)
        validate_timestamp(self.created_at, "created_at")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> MemoryRecord:
        data = cls._validated_data(value)
        data["evidence"] = tuple(data["evidence"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class SpecialistProfile(StrictRecord):
    provider_id: str
    model_id: str
    session_id: str
    capabilities: tuple[str, ...]
    project_types: tuple[str, ...]
    qualified: bool
    available: bool
    independence_identity: str
    cost_tier: int
    effort_levels: tuple[str, ...]
    credential_available: bool
    prior_success_rate: float
    pricing_identity: str | None = None
    pricing_version: str | None = None
    currency: str | None = None
    estimated_cost: float | None = None
    maximum_cost: float | None = None
    billing_unit: str | None = None
    included_plan: bool = False
    marginally_free: bool = False
    quote_timestamp: str | None = None
    quote_expiration: str | None = None
    pricing_source: str | None = None
    billing_mode: str | None = None
    incremental_charge_authorized: bool = False
    api_billing_authorized: bool = False
    paid_fallback_authorized: bool = False
    capacity_bounded: bool = False
    role_eligibility: tuple[str, ...] = ()

    FIELDS = frozenset(
        {
            "provider_id", "model_id", "session_id", "capabilities",
            "project_types", "qualified", "available", "independence_identity",
            "cost_tier", "effort_levels", "credential_available",
            "prior_success_rate", "pricing_identity", "pricing_version",
            "currency", "estimated_cost", "maximum_cost", "billing_unit",
            "included_plan", "marginally_free", "quote_timestamp",
            "quote_expiration", "pricing_source",
            "billing_mode", "incremental_charge_authorized",
            "api_billing_authorized", "paid_fallback_authorized",
            "capacity_bounded",
            "role_eligibility",
        }
    )

    def __post_init__(self) -> None:
        for amount in (self.estimated_cost, self.maximum_cost):
            if amount is not None and amount < 0:
                raise ValueError("provider pricing cannot be negative")
        for name, value in (
            ("quote_timestamp", self.quote_timestamp),
            ("quote_expiration", self.quote_expiration),
        ):
            if value is not None:
                validate_timestamp(value, name)
        if self.currency is not None and (
            len(self.currency) != 3 or not self.currency.isalpha()
        ):
            raise ValueError("provider pricing currency must be a three-letter code")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SpecialistProfile:
        normalized = dict(value)
        for key, default in {
            "pricing_identity": None, "pricing_version": None, "currency": None,
            "estimated_cost": None, "maximum_cost": None, "billing_unit": None,
            "included_plan": False, "marginally_free": False,
            "quote_timestamp": None, "quote_expiration": None,
            "pricing_source": None,
            "billing_mode": None,
            "incremental_charge_authorized": False,
            "api_billing_authorized": False,
            "paid_fallback_authorized": False,
            "capacity_bounded": False,
            "role_eligibility": (),
        }.items():
            normalized.setdefault(key, default)
        data = cls._validated_data(normalized)
        data["capabilities"] = tuple(data["capabilities"])
        data["project_types"] = tuple(data["project_types"])
        data["effort_levels"] = tuple(data["effort_levels"])
        data["role_eligibility"] = tuple(data["role_eligibility"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ReviewResult(StrictRecord):
    accepted: bool
    disposition: str
    failed_criteria: tuple[str, ...]
    evidence: tuple[str, ...]
    repair_instructions: tuple[str, ...]
    review_policy: str

    FIELDS = frozenset(
        {
            "accepted", "disposition", "failed_criteria", "evidence",
            "repair_instructions", "review_policy",
        }
    )

    def __post_init__(self) -> None:
        ReviewPolicy(self.review_policy)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ReviewResult:
        data = cls._validated_data(value)
        for key in ("failed_criteria", "evidence", "repair_instructions"):
            data[key] = tuple(data[key])
        return cls(**data)
