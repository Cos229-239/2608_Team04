from __future__ import annotations

import math
from dataclasses import asdict, dataclass, fields
from datetime import datetime
from typing import Any, ClassVar, TypeVar

from keeper.evidence_input import structured_digest, validate_provider_input
from keeper.pass_b.enums import (
    AssignmentRole,
    AssignmentState,
    AttemptState,
    CostMode,
    DelegatedModeState,
    EvidenceReferenceKind,
    EvidenceReferenceState,
    EvidenceState,
    HealthState,
    PauseCode,
    PresentationMode,
    ProviderClassification,
    ProviderSessionState,
    ReservationMode,
    ReservationState,
    ReviewState,
    SessionModel,
    WorkItemState,
    WorkflowState,
)


R = TypeVar("R", bound="PassBRecord")


def _timestamp(value: str, name: str) -> None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an ISO timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must be timezone aware")


def _optional_timestamp(value: str | None, name: str) -> None:
    if value is not None:
        _timestamp(value, name)


def _positive_revision(value: int) -> None:
    if value < 1:
        raise ValueError("record revision must be positive")


@dataclass(frozen=True, slots=True)
class PassBRecord:
    KIND: ClassVar[str]
    ID_FIELD: ClassVar[str]
    TUPLE_FIELDS: ClassVar[tuple[str, ...]] = ()
    DEFAULTS: ClassVar[dict[str, Any]] = {}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls: type[R], value: dict[str, Any]) -> R:
        expected = {item.name for item in fields(cls) if item.init}
        normalized = {**cls.DEFAULTS, **value}
        if set(normalized) != expected:
            raise ValueError(
                f"{cls.__name__} fields invalid; "
                f"unknown={sorted(set(normalized) - expected)}, "
                f"missing={sorted(expected - set(normalized))}"
            )
        for name in cls.TUPLE_FIELDS:
            normalized[name] = tuple(normalized[name])
        return cls(**normalized)

    @property
    def record_id(self) -> str:
        value = getattr(self, self.ID_FIELD)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{self.ID_FIELD} must be a durable identity")
        return value


@dataclass(frozen=True, slots=True)
class ProviderRecord(PassBRecord):
    provider_id: str
    identity: str
    display_name: str
    classification: str
    adapter_kind: str
    capabilities: tuple[str, ...]
    session_model: str
    usage_pool_strategy: str
    concurrency_limit: int
    cost_mode: str
    authentication_ready: bool
    tool_support: tuple[str, ...]
    workspace_support: tuple[str, ...]
    cancellation_support: bool
    resume_support: bool
    evidence_format: str
    health: str
    created_at: str
    updated_at: str
    revision: int
    authority_registration_id: str | None = None
    project_types: tuple[str, ...] = ()
    effort_levels: tuple[str, ...] = ()
    pricing_authority_digest: str | None = None
    pricing_quoted_at: str | None = None
    pricing_expires_at: str | None = None
    billing_mode: str | None = None
    authentication_mode: str | None = None
    reviewer_eligible: bool = True
    model_allowlist: tuple[str, ...] = ()
    paid_fallback_authorized: bool = False
    model_revalidation_expires_at: str | None = None
    api_billing_authorized: bool = False
    subscription_capacity_bounded: bool = False

    KIND = "provider"
    ID_FIELD = "provider_id"
    TUPLE_FIELDS = (
        "capabilities",
        "tool_support",
        "workspace_support",
        "project_types",
        "effort_levels",
        "model_allowlist",
    )
    DEFAULTS = {
        "authority_registration_id": None,
        "project_types": (),
        "effort_levels": (),
        "pricing_authority_digest": None,
        "pricing_quoted_at": None,
        "pricing_expires_at": None,
        "billing_mode": None,
        "authentication_mode": None,
        "reviewer_eligible": True,
        "model_allowlist": (),
        "paid_fallback_authorized": False,
        "model_revalidation_expires_at": None,
        "api_billing_authorized": False,
        "subscription_capacity_bounded": False,
    }

    def __post_init__(self) -> None:
        ProviderClassification(self.classification)
        SessionModel(self.session_model)
        CostMode(self.cost_mode)
        HealthState(self.health)
        if self.concurrency_limit < 1:
            raise ValueError("provider concurrency limit must be positive")
        if len(set(self.project_types)) != len(self.project_types):
            raise ValueError("provider project types must be unique")
        if len(set(self.effort_levels)) != len(self.effort_levels):
            raise ValueError("provider effort levels must be unique")
        if len(set(self.model_allowlist)) != len(self.model_allowlist):
            raise ValueError("provider model allowlist must be unique")
        if any(
            type(value) is not bool
            for value in (
                self.reviewer_eligible,
                self.paid_fallback_authorized,
                self.api_billing_authorized,
                self.subscription_capacity_bounded,
            )
        ):
            raise ValueError("provider authority flags must be Boolean")
        if self.pricing_quoted_at is not None:
            _timestamp(self.pricing_quoted_at, "pricing_quoted_at")
        if self.pricing_expires_at is not None:
            _timestamp(self.pricing_expires_at, "pricing_expires_at")
        if self.model_revalidation_expires_at is not None:
            _timestamp(
                self.model_revalidation_expires_at,
                "model_revalidation_expires_at",
            )
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class ProviderAccountRecord(PassBRecord):
    account_id: str
    provider_id: str
    identity: str
    display_name: str
    usage_pool_id: str
    cost_mode: str
    privacy_classification: str
    authentication_ready: bool
    enabled: bool
    created_at: str
    updated_at: str
    revision: int

    KIND = "provider_account"
    ID_FIELD = "account_id"

    def __post_init__(self) -> None:
        CostMode(self.cost_mode)
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class ProviderSessionRecord(PassBRecord):
    session_id: str
    provider_id: str
    account_id: str
    model_id: str
    external_session_id: str | None
    state: str
    concurrency_limit: int
    active_assignments: int
    supports_resume: bool
    resume_token_digest: str | None
    last_seen_at: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "provider_session"
    ID_FIELD = "session_id"

    def __post_init__(self) -> None:
        ProviderSessionState(self.state)
        if (
            self.concurrency_limit < 1
            or self.active_assignments < 0
            or self.active_assignments > self.concurrency_limit
        ):
            raise ValueError("provider session concurrency is invalid")
        _timestamp(self.last_seen_at, "last_seen_at")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class UsagePoolRecord(PassBRecord):
    pool_id: str
    provider_id: str
    account_id: str
    identity: str
    limit_type: str
    capacity: float | None
    consumed: float
    reserved: float
    remaining: float | None
    reset_at: str | None
    observation_source: str
    confidence: str
    exhausted: bool
    last_observed_at: str
    created_at: str
    updated_at: str
    revision: int
    observation_generation: int = 1

    KIND = "usage_pool"
    ID_FIELD = "pool_id"
    DEFAULTS = {"observation_generation": 1}

    def __post_init__(self) -> None:
        values = [self.consumed, self.reserved]
        if self.capacity is not None:
            values.append(self.capacity)
        if self.remaining is not None:
            values.append(self.remaining)
        if any(not math.isfinite(value) or value < 0 for value in values):
            raise ValueError(
                "usage values must be finite and cannot be negative"
            )
        if self.observation_generation < 1:
            raise ValueError("usage observation generation must be positive")
        _optional_timestamp(self.reset_at, "reset_at")
        _timestamp(self.last_observed_at, "last_observed_at")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class WorkflowRecord(PassBRecord):
    workflow_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    strategy: str
    authority_envelope_digest: str
    state: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "workflow"
    ID_FIELD = "workflow_id"

    def __post_init__(self) -> None:
        WorkflowState(self.state)
        if (
            self.charter_revision < 1
            or not self.strategy
            or len(self.authority_envelope_digest) != 64
        ):
            raise ValueError("workflow charter binding is invalid")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class WorkItemRecord(PassBRecord):
    work_item_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    workflow_id: str
    title: str
    objective: str
    dependencies: tuple[str, ...]
    required_roles: tuple[str, ...]
    state: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "work_item"
    ID_FIELD = "work_item_id"
    TUPLE_FIELDS = ("dependencies", "required_roles")

    def __post_init__(self) -> None:
        WorkItemState(self.state)
        if self.charter_revision < 1:
            raise ValueError("work item charter revision must be positive")
        for role in self.required_roles:
            AssignmentRole(role)
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class AssignmentRecord(PassBRecord):
    assignment_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    workflow_id: str
    work_item_id: str
    provider_id: str
    account_id: str
    session_id: str
    role: str
    model_id: str
    workspace_id: str
    authority_envelope_digest: str
    expected_evidence: tuple[str, ...]
    usage_policy: dict[str, Any]
    state: str
    read_only: bool
    independence_key: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "assignment"
    ID_FIELD = "assignment_id"
    TUPLE_FIELDS = ("expected_evidence",)

    def __post_init__(self) -> None:
        AssignmentRole(self.role)
        AssignmentState(self.state)
        if self.charter_revision < 1 or not self.authority_envelope_digest:
            raise ValueError("assignment charter and authority binding are required")
        if self.role == AssignmentRole.REVIEWER and not self.read_only:
            raise ValueError("review assignments must be read-only")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class ExecutionProfileRecord(PassBRecord):
    execution_profile_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    workflow_id: str
    work_item_id: str
    role: str
    review_of_assignment_id: str | None
    workspace_id: str
    canonical_workspace_path: str
    write_scopes: tuple[str, ...]
    write_scope_keys: tuple[str, ...]
    expected_evidence: tuple[str, ...]
    usage_amount: float
    effort_level: str
    required_capabilities: tuple[str, ...]
    privacy_classification: str
    preferred_provider_id: str | None
    allow_substitution: bool
    allow_paid: bool
    authority_envelope_digest: str
    created_at: str
    updated_at: str
    revision: int
    project_type: str | None = None

    KIND = "execution_profile"
    ID_FIELD = "execution_profile_id"
    TUPLE_FIELDS = (
        "write_scopes",
        "write_scope_keys",
        "expected_evidence",
        "required_capabilities",
    )
    DEFAULTS = {"project_type": None}

    def __post_init__(self) -> None:
        role = AssignmentRole(self.role)
        if (
            self.charter_revision < 1
            or not self.workspace_id
            or not self.canonical_workspace_path
            or len(self.authority_envelope_digest) != 64
            or self.effort_level not in {"MEDIUM", "HIGH"}
            or not math.isfinite(self.usage_amount)
            or self.usage_amount < 0
            or not self.expected_evidence
            or not self.required_capabilities
            or not self.privacy_classification
            or len(self.write_scopes) != len(self.write_scope_keys)
            or len(set(self.write_scope_keys)) != len(self.write_scope_keys)
            or len(set(self.expected_evidence)) != len(self.expected_evidence)
            or len(set(self.required_capabilities))
            != len(self.required_capabilities)
            or (role == AssignmentRole.REVIEWER and self.write_scopes)
            or (
                role == AssignmentRole.REVIEWER
                and not self.review_of_assignment_id
            )
            or (
                role != AssignmentRole.REVIEWER
                and self.review_of_assignment_id is not None
            )
            or self.allow_paid
        ):
            raise ValueError("execution profile policy is invalid")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class ProviderSelectionRecord(PassBRecord):
    provider_selection_id: str
    execution_profile_id: str
    assignment_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    workflow_id: str
    work_item_id: str
    role: str
    provider_id: str
    account_id: str
    session_id: str
    model_id: str
    usage_pool_id: str
    cost_mode: str
    privacy_classification: str
    independence_key: str
    effort_level: str
    allowed_provider_ids: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    excluded_independence_keys: tuple[str, ...]
    policy_digest: str
    delegated_mode_grant_id: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "provider_selection"
    ID_FIELD = "provider_selection_id"
    TUPLE_FIELDS = (
        "allowed_provider_ids",
        "required_capabilities",
        "excluded_independence_keys",
    )

    def __post_init__(self) -> None:
        AssignmentRole(self.role)
        CostMode(self.cost_mode)
        if (
            self.charter_revision < 1
            or self.effort_level not in {"MEDIUM", "HIGH"}
            or len(self.policy_digest) != 64
            or not self.execution_profile_id
            or not self.assignment_id
            or not self.usage_pool_id
            or not self.privacy_classification
            or not self.independence_key
            or not self.delegated_mode_grant_id
            or not self.allowed_provider_ids
            or not self.required_capabilities
            or len(set(self.allowed_provider_ids))
            != len(self.allowed_provider_ids)
            or len(set(self.required_capabilities))
            != len(self.required_capabilities)
            or len(set(self.excluded_independence_keys))
            != len(self.excluded_independence_keys)
        ):
            raise ValueError("provider selection binding is invalid")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class AttemptRecord(PassBRecord):
    attempt_id: str
    assignment_id: str
    authority_attempt_id: str
    launch_token: str
    state: str
    external_execution_id: str | None
    side_effect_class: str
    started_at: str | None
    finished_at: str | None
    last_error: str | None
    created_at: str
    updated_at: str
    revision: int
    workspace_reservation_id: str = ""
    usage_reservation_id: str | None = None
    launch_plan_digest: str = ""
    session_slot_claimed: bool = False
    delivered_input_id: str | None = None
    delivered_input_digest: str | None = None
    provider_input_digest: str | None = None
    authority_reservation_state: str = "LOCAL_PREPARED"
    authority_reservation_plan_digest: str = "legacy-unbound"
    uncertainty_kind: str | None = None
    cancellation_requested_at: str | None = None

    KIND = "attempt"
    ID_FIELD = "attempt_id"
    DEFAULTS = {
        "workspace_reservation_id": "legacy-unbound",
        "usage_reservation_id": None,
        "launch_plan_digest": "legacy-unbound",
        "session_slot_claimed": False,
        "delivered_input_id": None,
        "delivered_input_digest": None,
        "provider_input_digest": None,
        "authority_reservation_state": "AUTHORIZED",
        "authority_reservation_plan_digest": "legacy-unbound",
        "uncertainty_kind": None,
        "cancellation_requested_at": None,
    }

    def __post_init__(self) -> None:
        AttemptState(self.state)
        if (
            not self.authority_attempt_id
            or not self.launch_token
            or not self.workspace_reservation_id
            or not self.launch_plan_digest
        ):
            raise ValueError("attempt authority and launch identities are required")
        if self.authority_reservation_state not in {
            "LOCAL_PREPARED",
            "RESERVATION_IN_FLIGHT",
            "AUTHORITY_RESERVED",
            "AUTHORIZED",
        }:
            raise ValueError("attempt Authority reservation state is invalid")
        if self.authority_reservation_plan_digest != "legacy-unbound" and len(
            self.authority_reservation_plan_digest
        ) != 64:
            raise ValueError("attempt Authority reservation digest is invalid")
        input_binding = (
            self.delivered_input_id,
            self.delivered_input_digest,
            self.provider_input_digest,
        )
        if any(input_binding) and (
            not all(input_binding)
            or len(self.delivered_input_digest or "") != 64
            or len(self.provider_input_digest or "") != 64
        ):
            raise ValueError("attempt delivered-input binding is incomplete")
        _optional_timestamp(self.started_at, "started_at")
        _optional_timestamp(self.finished_at, "finished_at")
        _optional_timestamp(
            self.cancellation_requested_at, "cancellation_requested_at"
        )
        if self.uncertainty_kind not in {
            None,
            "AUTHORITY_RESERVATION_OUTCOME_AMBIGUOUS",
            "CANCELLATION_OUTCOME_AMBIGUOUS",
            "EXTERNAL_EXECUTION_OUTCOME_AMBIGUOUS",
        }:
            raise ValueError("attempt uncertainty kind is invalid")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class UncertaintyReconciliationRecord(PassBRecord):
    reconciliation_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    workflow_id: str
    work_item_id: str
    assignment_id: str
    attempt_id: str
    provider_id: str
    account_id: str
    session_id: str
    model_id: str
    authority_attempt_id: str
    launch_token: str
    external_execution_id: str
    workspace_reservation_id: str
    canonical_workspace_path: str
    resolution: str
    observation_digest: str
    action_id: str
    action_digest: str
    approval_id: str
    approval_event_id: str
    founder_identity: str
    state: str
    reconciled_at: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "uncertainty_reconciliation"
    ID_FIELD = "reconciliation_id"

    def __post_init__(self) -> None:
        if (
            self.charter_revision < 1
            or self.resolution != "CONFIRMED_CANCELED"
            or self.state != "APPLIED"
            or any(
                len(value) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in value
                )
                for value in (self.observation_digest, self.action_digest)
            )
            or not self.founder_identity.startswith("S-1-")
        ):
            raise ValueError("uncertainty reconciliation binding is invalid")
        _timestamp(self.reconciled_at, "reconciled_at")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class UncertainExecutionDispositionRecord(PassBRecord):
    disposition_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    approval_charter_id: str
    approval_charter_revision: int
    workflow_id: str
    work_item_id: str
    assignment_id: str
    attempt_id: str
    provider_id: str
    account_id: str
    session_id: str
    model_id: str
    authority_attempt_id: str
    launch_token: str
    external_execution_id: str | None
    workspace_reservation_ids: tuple[str, ...]
    write_reservation_ids: tuple[str, ...]
    write_reservation_digests: tuple[str, ...]
    usage_reservation_id: str
    usage_pool_id: str
    usage_amount: float
    resolution: str
    observation_digest: str
    action_id: str
    action_digest: str
    approval_id: str
    approval_event_id: str
    founder_identity: str
    possible_external_effect_preserved: bool
    inactivity_observation: dict[str, object]
    inactivity_observation_digest: str
    authority_disposition: dict[str, object]
    authority_disposition_digest: str
    usage_reservation_consumed: bool
    state: str
    disposed_at: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "uncertain_execution_disposition"
    ID_FIELD = "disposition_id"
    TUPLE_FIELDS = (
        "workspace_reservation_ids",
        "write_reservation_ids",
        "write_reservation_digests",
    )

    def __post_init__(self) -> None:
        if (
            self.charter_revision < 1
            or self.approval_charter_revision < 1
            or self.resolution
            != "FOUNDER_ABANDONED_UNCERTAIN_EXTERNAL_EXECUTION"
            or self.state != "APPLIED"
            or not self.possible_external_effect_preserved
            or not self.usage_reservation_consumed
            or not self.usage_reservation_id
            or not self.usage_pool_id
            or not math.isfinite(self.usage_amount)
            or self.usage_amount < 0
            or len(set(self.workspace_reservation_ids))
            != len(self.workspace_reservation_ids)
            or len(self.write_reservation_ids)
            != len(self.write_reservation_digests)
            or len(set(self.write_reservation_ids))
            != len(self.write_reservation_ids)
            or structured_digest(self.inactivity_observation)
            != self.inactivity_observation_digest
            or structured_digest(self.authority_disposition)
            != self.authority_disposition_digest
            or self.authority_disposition.get("authority_attempt_id")
            != self.authority_attempt_id
            or self.authority_disposition.get("approval_id")
            != self.approval_id
            or self.authority_disposition.get("action_digest")
            != self.action_digest
            or self.authority_disposition.get("observation_digest")
            != self.observation_digest
            or self.authority_disposition.get("terminal_disposition")
            != "FOUNDER_ABANDONED_UNCERTAIN_EXTERNAL_EXECUTION"
            or self.authority_disposition.get(
                "possible_external_effect_preserved"
            ) is not True
            or self.authority_disposition.get("retry_authorized") is not False
            or any(
                len(value) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in value
                )
                for value in (
                    self.observation_digest,
                    self.action_digest,
                    self.inactivity_observation_digest,
                    self.authority_disposition_digest,
                    *self.write_reservation_digests,
                )
            )
            or not self.founder_identity.startswith("S-1-")
        ):
            raise ValueError(
                "uncertain execution disposition binding is invalid"
            )
        _timestamp(self.disposed_at, "disposed_at")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class AuthorityReservationReconciliationRecord(PassBRecord):
    reconciliation_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    workflow_id: str
    work_item_id: str
    assignment_id: str
    attempt_id: str
    authority_attempt_id: str
    observation_digest: str
    service_key_id: str
    service_key_version: int
    client_sid: str
    released_workspace_reservation_ids: tuple[str, ...]
    released_write_reservation_ids: tuple[str, ...]
    released_usage_reservation_id: str | None
    released_usage_pool_id: str | None
    released_usage_amount: float
    state: str
    reconciled_at: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "authority_reservation_reconciliation"
    ID_FIELD = "reconciliation_id"
    TUPLE_FIELDS = (
        "released_workspace_reservation_ids",
        "released_write_reservation_ids",
    )

    def __post_init__(self) -> None:
        if (
            self.charter_revision < 1
            or self.state != "APPLIED"
            or not self.attempt_id
            or not self.authority_attempt_id
            or len(self.observation_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.observation_digest
            )
            or not self.service_key_id
            or self.service_key_version < 1
            or not self.client_sid.startswith("S-1-")
            or not math.isfinite(self.released_usage_amount)
            or self.released_usage_amount < 0
            or (self.released_usage_reservation_id is None)
            != (self.released_usage_pool_id is None)
            or (
                self.released_usage_reservation_id is None
                and self.released_usage_amount != 0
            )
            or len(set(self.released_workspace_reservation_ids))
            != len(self.released_workspace_reservation_ids)
            or len(set(self.released_write_reservation_ids))
            != len(self.released_write_reservation_ids)
        ):
            raise ValueError(
                "Authority reservation reconciliation binding is invalid"
            )
        _timestamp(self.reconciled_at, "reconciled_at")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class PrelaunchAbandonmentRecord(PassBRecord):
    abandonment_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    workflow_id: str
    work_item_id: str
    assignment_id: str
    released_workspace_reservation_ids: tuple[str, ...]
    released_write_reservation_ids: tuple[str, ...]
    released_usage_reservation_id: str | None
    released_usage_pool_id: str | None
    released_usage_amount: float
    state: str
    abandoned_at: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "prelaunch_abandonment"
    ID_FIELD = "abandonment_id"
    TUPLE_FIELDS = (
        "released_workspace_reservation_ids",
        "released_write_reservation_ids",
    )

    def __post_init__(self) -> None:
        if (
            self.charter_revision < 1
            or self.state != "APPLIED"
            or not self.assignment_id
            or not math.isfinite(self.released_usage_amount)
            or self.released_usage_amount < 0
            or (self.released_usage_reservation_id is None)
            != (self.released_usage_pool_id is None)
            or (
                self.released_usage_reservation_id is None
                and self.released_usage_amount != 0
            )
            or len(set(self.released_workspace_reservation_ids))
            != len(self.released_workspace_reservation_ids)
            or len(set(self.released_write_reservation_ids))
            != len(self.released_write_reservation_ids)
        ):
            raise ValueError("prelaunch abandonment binding is invalid")
        _timestamp(self.abandoned_at, "abandoned_at")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class RepositorySnapshotRecord(PassBRecord):
    snapshot_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    workflow_id: str
    work_item_id: str
    assignment_id: str
    attempt_id: str
    evidence_bundle_id: str
    canonical_repository_path: str
    commit_hash: str
    tree_hash: str
    manifest_digest: str
    file_count: int
    total_size_bytes: int
    state: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "repository_snapshot"
    ID_FIELD = "snapshot_id"

    def __post_init__(self) -> None:
        digests = (self.commit_hash, self.tree_hash, self.manifest_digest)
        if (
            self.charter_revision < 1
            or self.state != "VALIDATED"
            or not self.canonical_repository_path
            or self.file_count < 1
            or self.total_size_bytes < 0
            or any(
                len(value) not in {40, 64}
                or any(character not in "0123456789abcdef" for character in value)
                for value in digests[:2]
            )
            or len(self.manifest_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.manifest_digest
            )
        ):
            raise ValueError("repository snapshot binding is invalid")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class DeliveredInputRecord(PassBRecord):
    delivered_input_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    workflow_id: str
    work_item_id: str
    reviewer_assignment_id: str
    reviewer_attempt_id: str
    producer_assignment_id: str
    producer_attempt_id: str
    references: tuple[dict[str, Any], ...]
    manifest_digest: str
    delivered_input_digest: str
    provider_input_digest: str
    provider_input: dict[str, Any]
    delivery_method: str
    composition_identity: str
    delivered_at: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "delivered_input"
    ID_FIELD = "delivered_input_id"
    TUPLE_FIELDS = ("references",)

    def __post_init__(self) -> None:
        validate_provider_input(self.provider_input)
        if structured_digest(self.provider_input) != self.provider_input_digest:
            raise ValueError(
                "delivered-input provider digest does not match provider input"
            )
        expected = {
            "project_id": self.project_id,
            "charter_id": self.charter_id,
            "charter_revision": self.charter_revision,
            "workflow_id": self.workflow_id,
            "work_item_id": self.work_item_id,
            "reviewer_assignment_id": self.reviewer_assignment_id,
            "reviewer_attempt_id": self.reviewer_attempt_id,
            "producer_assignment_id": self.producer_assignment_id,
            "producer_attempt_id": self.producer_attempt_id,
            "references": list(self.references),
            "manifest_digest": self.manifest_digest,
            "delivered_input_digest": self.delivered_input_digest,
            "delivery_method": self.delivery_method,
            "composition_identity": self.composition_identity,
            "delivered_at": self.delivered_at,
        }
        for name, value in expected.items():
            if self.provider_input[name] != value:
                raise ValueError(f"delivered-input {name} does not match provider input")
        if self.charter_revision < 1:
            raise ValueError("delivered-input charter revision is invalid")
        _timestamp(self.delivered_at, "delivered_at")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class ReviewRecord(PassBRecord):
    review_id: str
    project_id: str
    assignment_id: str
    attempt_id: str
    reviewer_assignment_id: str
    independence_key: str
    state: str
    findings: tuple[dict[str, Any], ...]
    disposition: str | None
    created_at: str
    updated_at: str
    revision: int
    producer_evidence_bundle_id: str = ""
    reviewer_attempt_id: str = ""
    reviewer_evidence_bundle_id: str = ""
    consumed_evidence_reference_id: str | None = None
    consumed_evidence_reference_revision: int | None = None
    delivered_input_id: str | None = None
    delivered_input_digest: str | None = None
    consumed_evidence_reference_ids: tuple[str, ...] = ()
    consumed_evidence_reference_revisions: tuple[int, ...] = ()

    KIND = "review"
    ID_FIELD = "review_id"
    TUPLE_FIELDS = (
        "findings",
        "consumed_evidence_reference_ids",
        "consumed_evidence_reference_revisions",
    )
    DEFAULTS = {
        "producer_evidence_bundle_id": "legacy-unbound",
        "reviewer_attempt_id": "legacy-unbound",
        "reviewer_evidence_bundle_id": "legacy-unbound",
        "consumed_evidence_reference_id": None,
        "consumed_evidence_reference_revision": None,
        "delivered_input_id": None,
        "delivered_input_digest": None,
        "consumed_evidence_reference_ids": (),
        "consumed_evidence_reference_revisions": (),
    }

    def __post_init__(self) -> None:
        ReviewState(self.state)
        if (
            not self.producer_evidence_bundle_id
            or not self.reviewer_attempt_id
            or not self.reviewer_evidence_bundle_id
        ):
            raise ValueError(
                "review requires producer and reviewer execution evidence"
            )
        if (self.consumed_evidence_reference_id is None) != (
            self.consumed_evidence_reference_revision is None
        ):
            raise ValueError("review evidence-reference binding is incomplete")
        if (
            self.consumed_evidence_reference_revision is not None
            and self.consumed_evidence_reference_revision < 1
        ):
            raise ValueError("review evidence-reference revision is invalid")
        if (self.delivered_input_id is None) != (
            self.delivered_input_digest is None
        ):
            raise ValueError("review delivered-input binding is incomplete")
        if self.delivered_input_digest is not None and len(
            self.delivered_input_digest
        ) != 64:
            raise ValueError("review delivered-input digest is invalid")
        if len(self.consumed_evidence_reference_ids) != len(
            self.consumed_evidence_reference_revisions
        ) or any(
            revision < 1
            for revision in self.consumed_evidence_reference_revisions
        ):
            raise ValueError("review evidence-reference set is invalid")
        if self.delivered_input_id and not self.consumed_evidence_reference_ids:
            raise ValueError("review delivered-input set cannot be empty")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class EvidenceBundleRecord(PassBRecord):
    evidence_bundle_id: str
    project_id: str
    assignment_id: str
    attempt_id: str
    producer_provider_id: str
    producer_session_id: str
    schema_version: int
    artifacts: tuple[dict[str, Any], ...]
    summary: str
    content_digest: str
    state: str
    validation_errors: tuple[str, ...]
    created_at: str
    updated_at: str
    revision: int
    delivered_input_id: str | None = None
    delivered_input_digest: str | None = None
    provider_input_digest: str | None = None

    KIND = "evidence_bundle"
    ID_FIELD = "evidence_bundle_id"
    TUPLE_FIELDS = ("artifacts", "validation_errors")
    DEFAULTS = {
        "delivered_input_id": None,
        "delivered_input_digest": None,
        "provider_input_digest": None,
    }

    def __post_init__(self) -> None:
        EvidenceState(self.state)
        if self.schema_version != 1 or len(self.content_digest) != 64:
            raise ValueError("evidence schema or digest is invalid")
        input_binding = (
            self.delivered_input_id,
            self.delivered_input_digest,
            self.provider_input_digest,
        )
        if any(input_binding) and (
            not all(input_binding)
            or len(self.delivered_input_digest or "") != 64
            or len(self.provider_input_digest or "") != 64
        ):
            raise ValueError("reviewer evidence input binding is invalid")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class EvidenceReferenceRecord(PassBRecord):
    evidence_reference_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    workflow_id: str
    work_item_id: str
    assignment_id: str
    source_kind: str
    source_identity: str
    canonical_source_path: str | None
    source_evidence_bundle_id: str | None
    sha256: str
    size_bytes: int
    state: str
    validation_error: str | None
    created_at: str
    validated_at: str | None
    updated_at: str
    revision: int
    source_project_id: str = ""
    source_charter_id: str = ""
    source_charter_revision: int = 0
    source_workflow_id: str = ""
    source_work_item_id: str = ""
    producer_assignment_id: str = ""
    producer_attempt_id: str = ""
    review_target_assignment_id: str = ""
    consumed_by_review_id: str | None = None
    consumed_at: str | None = None

    KIND = "evidence_reference"
    ID_FIELD = "evidence_reference_id"
    DEFAULTS = {
        "source_project_id": "",
        "source_charter_id": "",
        "source_charter_revision": 0,
        "source_workflow_id": "",
        "source_work_item_id": "",
        "producer_assignment_id": "",
        "producer_attempt_id": "",
        "review_target_assignment_id": "",
        "consumed_by_review_id": None,
        "consumed_at": None,
    }

    def __post_init__(self) -> None:
        kind = EvidenceReferenceKind(self.source_kind)
        EvidenceReferenceState(self.state)
        if len(self.sha256) != 64 or any(
            item not in "0123456789abcdef" for item in self.sha256
        ):
            raise ValueError("evidence reference digest is invalid")
        if self.size_bytes < 0:
            raise ValueError("evidence reference size is invalid")
        if (
            kind == EvidenceReferenceKind.LOCAL_PROTECTED_ARTIFACT
            and not self.canonical_source_path
        ):
            raise ValueError("local evidence reference requires a source path")
        if (
            kind == EvidenceReferenceKind.REMOTE_STRUCTURED_EVIDENCE
            and self.canonical_source_path is not None
        ):
            raise ValueError("remote evidence reference cannot expose a local path")
        if self.charter_revision < 1 or not self.source_identity:
            raise ValueError("evidence reference binding is invalid")
        lineage = (
            self.source_project_id,
            self.source_charter_id,
            self.source_workflow_id,
            self.source_work_item_id,
            self.producer_assignment_id,
            self.producer_attempt_id,
            self.review_target_assignment_id,
        )
        if any(lineage) and (
            not all(lineage) or self.source_charter_revision < 1
        ):
            raise ValueError("evidence reference source lineage is incomplete")
        if self.consumed_by_review_id and not self.consumed_at:
            raise ValueError("consumed evidence reference needs a timestamp")
        _timestamp(self.created_at, "created_at")
        _optional_timestamp(self.validated_at, "validated_at")
        _optional_timestamp(self.consumed_at, "consumed_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class WorkspaceReservationRecord(PassBRecord):
    workspace_reservation_id: str
    project_id: str
    assignment_id: str
    workspace_id: str
    canonical_path: str
    mode: str
    owner_token: str
    lease_expires_at: str
    state: str
    worktree_branch: str | None
    base_commit: str | None
    created_at: str
    updated_at: str
    revision: int

    KIND = "workspace_reservation"
    ID_FIELD = "workspace_reservation_id"

    def __post_init__(self) -> None:
        ReservationMode(self.mode)
        ReservationState(self.state)
        _timestamp(self.lease_expires_at, "lease_expires_at")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class WriteReservationRecord(PassBRecord):
    write_reservation_id: str
    workspace_reservation_id: str
    assignment_id: str
    scope: tuple[str, ...]
    scope_keys: tuple[str, ...]
    owner_token: str
    lease_expires_at: str
    state: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "write_reservation"
    ID_FIELD = "write_reservation_id"
    TUPLE_FIELDS = ("scope", "scope_keys")

    def __post_init__(self) -> None:
        ReservationState(self.state)
        if not self.scope or len(self.scope) != len(self.scope_keys):
            raise ValueError("write reservation scope is invalid")
        _timestamp(self.lease_expires_at, "lease_expires_at")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class PauseReasonRecord(PassBRecord):
    pause_reason_id: str
    assignment_id: str
    code: str
    detail: str
    reset_at: str | None
    safe_to_release_workspace: bool
    created_at: str
    resolved_at: str | None
    revision: int

    KIND = "pause_reason"
    ID_FIELD = "pause_reason_id"

    def __post_init__(self) -> None:
        PauseCode(self.code)
        _optional_timestamp(self.reset_at, "reset_at")
        _timestamp(self.created_at, "created_at")
        _optional_timestamp(self.resolved_at, "resolved_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class ResumeCheckpointRecord(PassBRecord):
    resume_checkpoint_id: str
    assignment_id: str
    attempt_id: str | None
    project_id: str
    charter_id: str
    charter_revision: int
    workspace_reservation_id: str
    usage_pool_id: str
    authority_envelope_digest: str
    checkpoint_state: dict[str, Any]
    created_at: str
    resumed_at: str | None
    revision: int

    KIND = "resume_checkpoint"
    ID_FIELD = "resume_checkpoint_id"

    def __post_init__(self) -> None:
        if self.charter_revision < 1 or not self.authority_envelope_digest:
            raise ValueError("resume checkpoint binding is invalid")
        _timestamp(self.created_at, "created_at")
        _optional_timestamp(self.resumed_at, "resumed_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class DelegatedModeGrantRecord(PassBRecord):
    delegated_mode_grant_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    founder_identity: str
    founder_approval_id: str
    founder_approval_digest: str
    scope: tuple[str, ...]
    starts_at: str
    expires_at: str
    state: str
    revoked_at: str | None
    created_at: str
    updated_at: str
    revision: int
    project_generation: str = ""
    max_actions: int = 0
    actions_used: int = 0
    last_action_at: str | None = None

    KIND = "delegated_mode_grant"
    ID_FIELD = "delegated_mode_grant_id"
    TUPLE_FIELDS = ("scope",)
    DEFAULTS = {
        "project_generation": "",
        "max_actions": 0,
        "actions_used": 0,
        "last_action_at": None,
    }

    def __post_init__(self) -> None:
        DelegatedModeState(self.state)
        if self.charter_revision < 1 or not self.founder_approval_digest:
            raise ValueError("delegated mode requires Founder-bound authority")
        _timestamp(self.starts_at, "starts_at")
        _timestamp(self.expires_at, "expires_at")
        _optional_timestamp(self.revoked_at, "revoked_at")
        _optional_timestamp(self.last_action_at, "last_action_at")
        if (
            self.max_actions < 0
            or self.actions_used < 0
            or self.actions_used > self.max_actions
        ):
            raise ValueError("delegated action count is invalid")
        _timestamp(self.created_at, "created_at")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class ConversationMessageRecord(PassBRecord):
    message_id: str
    project_id: str | None
    speaker: str
    text: str
    intent: str
    durable_authority: bool
    created_at: str
    revision: int

    KIND = "conversation_message"
    ID_FIELD = "message_id"

    def __post_init__(self) -> None:
        if self.speaker not in {"FOUNDER", "KEEPER"}:
            raise ValueError("conversation speaker is invalid")
        if self.durable_authority:
            raise ValueError("conversation text cannot be durable authority")
        _timestamp(self.created_at, "created_at")
        _positive_revision(self.revision)


@dataclass(frozen=True, slots=True)
class PresentationStateRecord(PassBRecord):
    presentation_state_id: str
    project_id: str | None
    form: str
    mode: str
    expression: str
    intensity: float
    background: str
    ambient_effect: str
    updated_at: str
    revision: int
    avatar_asset_identity: str = "sage-default"
    activity_state: str = "LISTENING"
    mood: str = "CALM"
    interruption_state: str = "IDLE"
    authority_effect: str = "NONE"

    KIND = "presentation_state"
    ID_FIELD = "presentation_state_id"
    DEFAULTS = {
        "avatar_asset_identity": "sage-default",
        "activity_state": "LISTENING",
        "mood": "CALM",
        "interruption_state": "IDLE",
        "authority_effect": "NONE",
    }

    def __post_init__(self) -> None:
        PresentationMode(self.mode)
        if self.activity_state not in {"SPEAKING", "LISTENING", "THINKING"}:
            raise ValueError("Sage activity state is invalid")
        if self.interruption_state not in {"IDLE", "INTERRUPTED"}:
            raise ValueError("Sage interruption state is invalid")
        if self.authority_effect != "NONE":
            raise ValueError("Sage presentation cannot have authority effect")
        if not self.avatar_asset_identity or not self.mood:
            raise ValueError("Sage presentation identity is incomplete")
        if not math.isfinite(self.intensity) or not (
            0 <= self.intensity <= 1
        ):
            raise ValueError("presentation intensity must be between zero and one")
        _timestamp(self.updated_at, "updated_at")
        _positive_revision(self.revision)


PASS_B_RECORD_TYPES: tuple[type[PassBRecord], ...] = (
    ProviderRecord,
    ProviderAccountRecord,
    ProviderSessionRecord,
    UsagePoolRecord,
    WorkflowRecord,
    WorkItemRecord,
    AssignmentRecord,
    ExecutionProfileRecord,
    ProviderSelectionRecord,
    AttemptRecord,
    UncertaintyReconciliationRecord,
    UncertainExecutionDispositionRecord,
    AuthorityReservationReconciliationRecord,
    PrelaunchAbandonmentRecord,
    RepositorySnapshotRecord,
    DeliveredInputRecord,
    ReviewRecord,
    EvidenceBundleRecord,
    EvidenceReferenceRecord,
    WorkspaceReservationRecord,
    WriteReservationRecord,
    PauseReasonRecord,
    ResumeCheckpointRecord,
    DelegatedModeGrantRecord,
    ConversationMessageRecord,
    PresentationStateRecord,
)

PASS_B_RECORD_BY_KIND = {
    record_type.KIND: record_type for record_type in PASS_B_RECORD_TYPES
}
