from __future__ import annotations

from dataclasses import replace

import pytest

from keeper.pass_b.enums import (
    AssignmentRole,
    AssignmentState,
    AttemptState,
    CostMode,
    EvidenceState,
    HealthState,
    PresentationMode,
    ProviderClassification,
    ProviderSessionState,
    SessionModel,
)
from keeper.pass_b.models import (
    AssignmentRecord,
    ConversationMessageRecord,
    EvidenceBundleRecord,
    PASS_B_RECORD_BY_KIND,
    PASS_B_RECORD_TYPES,
    PresentationStateRecord,
    ProviderRecord,
    ProviderSessionRecord,
    UsagePoolRecord,
)


NOW = "2026-07-28T12:00:00+00:00"


def _provider() -> ProviderRecord:
    return ProviderRecord(
        provider_id="provider-1",
        identity="provider-identity-1",
        display_name="Provider One",
        classification=ProviderClassification.LOCAL,
        adapter_kind="local-test",
        capabilities=("implementer", "structured-evidence"),
        session_model=SessionModel.RESUMABLE,
        usage_pool_strategy="shared-account-window",
        concurrency_limit=2,
        cost_mode=CostMode.FREE,
        authentication_ready=True,
        tool_support=("filesystem",),
        workspace_support=("isolated-worktree", "read-only"),
        cancellation_support=True,
        resume_support=True,
        evidence_format="keeper-evidence-v1",
        health=HealthState.READY,
        created_at=NOW,
        updated_at=NOW,
        revision=1,
    )


def _session() -> ProviderSessionRecord:
    return ProviderSessionRecord(
        session_id="session-1",
        provider_id="provider-1",
        account_id="account-1",
        model_id="model-1",
        external_session_id=None,
        state=ProviderSessionState.READY,
        concurrency_limit=2,
        active_assignments=0,
        supports_resume=True,
        resume_token_digest=None,
        last_seen_at=NOW,
        created_at=NOW,
        updated_at=NOW,
        revision=1,
    )


def _assignment() -> AssignmentRecord:
    return AssignmentRecord(
        assignment_id="assignment-1",
        project_id="project-1",
        charter_id="charter-1",
        charter_revision=2,
        workflow_id="workflow-1",
        work_item_id="work-1",
        provider_id="provider-1",
        account_id="account-1",
        session_id="session-1",
        role=AssignmentRole.IMPLEMENTER,
        model_id="model-1",
        workspace_id="workspace-1",
        authority_envelope_digest="a" * 64,
        expected_evidence=("structured-report",),
        usage_policy={"reservation_required": True, "paid_fallback": False},
        state=AssignmentState.READY,
        read_only=False,
        independence_key="provider-1:account-1:session-1",
        created_at=NOW,
        updated_at=NOW,
        revision=1,
    )


def test_record_registry_is_complete_and_uses_durable_kinds() -> None:
    assert len(PASS_B_RECORD_TYPES) == 25
    assert set(PASS_B_RECORD_BY_KIND) == {
        record_type.KIND for record_type in PASS_B_RECORD_TYPES
    }
    assert len(PASS_B_RECORD_BY_KIND) == len(PASS_B_RECORD_TYPES)


def test_provider_json_round_trip_normalizes_tuple_fields() -> None:
    provider = _provider()
    payload = provider.to_dict()
    payload["capabilities"] = list(provider.capabilities)
    payload["tool_support"] = list(provider.tool_support)
    payload["workspace_support"] = list(provider.workspace_support)

    restored = ProviderRecord.from_dict(payload)

    assert restored == provider
    assert restored.record_id == "provider-1"
    assert isinstance(restored.capabilities, tuple)


def test_record_schema_rejects_unknown_and_missing_fields() -> None:
    payload = _provider().to_dict()
    payload["unexpected"] = True
    with pytest.raises(ValueError, match="fields invalid"):
        ProviderRecord.from_dict(payload)

    payload = _provider().to_dict()
    del payload["identity"]
    with pytest.raises(ValueError, match="fields invalid"):
        ProviderRecord.from_dict(payload)


def test_timestamps_and_revisions_are_strict() -> None:
    provider = _provider()
    with pytest.raises(ValueError, match="timezone aware"):
        replace(provider, updated_at="2026-07-28T12:00:00")
    with pytest.raises(ValueError, match="revision"):
        replace(provider, revision=0)
    with pytest.raises(ValueError, match="provider_id"):
        replace(provider, provider_id="").record_id


def test_provider_session_enforces_concurrency_bounds() -> None:
    session = _session()
    assert session.active_assignments == 0
    with pytest.raises(ValueError, match="concurrency"):
        replace(session, active_assignments=3)
    with pytest.raises(ValueError, match="concurrency"):
        replace(session, concurrency_limit=0)


def test_usage_pool_rejects_negative_accounting() -> None:
    pool = UsagePoolRecord(
        pool_id="pool-1",
        provider_id="provider-1",
        account_id="account-1",
        identity="provider-1:account-1:pool",
        limit_type="MEASURED_WINDOW",
        capacity=10,
        consumed=1,
        reserved=2,
        remaining=7,
        reset_at=NOW,
        observation_source="provider",
        confidence="HIGH",
        exhausted=False,
        last_observed_at=NOW,
        created_at=NOW,
        updated_at=NOW,
        revision=1,
    )
    with pytest.raises(ValueError, match="negative"):
        replace(pool, reserved=-1)
    with pytest.raises(ValueError, match="finite"):
        replace(pool, remaining=float("nan"))


def test_assignment_binds_identity_and_reviewer_read_only() -> None:
    assignment = _assignment()
    assert assignment.charter_revision == 2
    assert assignment.authority_envelope_digest == "a" * 64
    with pytest.raises(ValueError, match="read-only"):
        replace(
            assignment,
            role=AssignmentRole.REVIEWER,
            read_only=False,
        )


def test_evidence_requires_fixed_schema_and_digest() -> None:
    evidence = EvidenceBundleRecord(
        evidence_bundle_id="evidence-1",
        project_id="project-1",
        assignment_id="assignment-1",
        attempt_id="attempt-1",
        producer_provider_id="provider-1",
        producer_session_id="session-1",
        schema_version=1,
        artifacts=(),
        summary="bounded result",
        content_digest="b" * 64,
        state=EvidenceState.UNTRUSTED,
        validation_errors=(),
        created_at=NOW,
        updated_at=NOW,
        revision=1,
    )
    assert evidence.record_id == "evidence-1"
    with pytest.raises(ValueError, match="schema or digest"):
        replace(evidence, content_digest="short")
    with pytest.raises(ValueError, match="schema or digest"):
        replace(evidence, schema_version=2)


def test_conversation_text_cannot_be_durable_authority() -> None:
    message = ConversationMessageRecord(
        message_id="message-1",
        project_id="project-1",
        speaker="FOUNDER",
        text="Continue within the charter.",
        intent="PROJECT_REQUEST",
        durable_authority=False,
        created_at=NOW,
        revision=1,
    )
    assert message.durable_authority is False
    with pytest.raises(ValueError, match="cannot be durable authority"):
        replace(message, durable_authority=True)


def test_presentation_state_is_bounded_and_non_authoritative_data() -> None:
    presentation = PresentationStateRecord(
        presentation_state_id="sage-default",
        project_id=None,
        form="default",
        mode=PresentationMode.CONVERSATION,
        expression="neutral",
        intensity=0.25,
        background="black-gold",
        ambient_effect="none",
        updated_at=NOW,
        revision=1,
    )
    assert "authority" not in presentation.to_dict()
    with pytest.raises(ValueError, match="between zero and one"):
        replace(presentation, intensity=1.5)
    with pytest.raises(ValueError, match="between zero and one"):
        replace(presentation, intensity=float("nan"))


def test_cancellation_claim_states_are_explicit() -> None:
    assert (
        AssignmentState.CANCELLATION_CLAIMED
        == "CANCELLATION_CLAIMED"
    )
    assert AttemptState.CANCELLATION_CLAIMED == "CANCELLATION_CLAIMED"
