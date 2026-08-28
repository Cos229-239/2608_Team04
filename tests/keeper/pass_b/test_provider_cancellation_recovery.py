from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from keeper.executive.models import FounderApprovalChallenge
from keeper.pass_b.application import PassBApplication
from keeper.pass_b.conversation import DynamicWorkflowDesigner
from keeper.pass_b.enums import (
    AssignmentState,
    AttemptState,
    ReservationState,
)
from keeper.pass_b.launch_authority import TestLaunchAuthority
from keeper.pass_b.models import (
    AssignmentRecord,
    AttemptRecord,
    ProviderAccountRecord,
    ProviderSessionRecord,
    UncertainExecutionDispositionRecord,
    UncertaintyReconciliationRecord,
    UsagePoolRecord,
    WorkspaceReservationRecord,
    WriteReservationRecord,
)
from keeper.pass_b.orchestration import authority_envelope_digest
from keeper.pass_b.pilot import PilotConversationExecutive
from keeper.pass_b.providers import LocalMockAdapter
from keeper.pass_b.usage_authority import TestUsageResetVerifier
from tests.keeper.pass_b.test_orchestration import _authorize


class _CancelThenRaiseAdapter(LocalMockAdapter):
    def cancel(self, external_execution_id: str) -> None:
        super().cancel(external_execution_id)
        raise RuntimeError("simulated lost cancellation response")


def _running(
    root: Path,
) -> tuple[
    PassBApplication,
    PilotConversationExecutive,
    AssignmentRecord,
    AttemptRecord,
    WorkspaceReservationRecord,
    WriteReservationRecord,
    Path,
]:
    workspace_root = root / "workspace"
    workspace_root.mkdir(parents=True)
    execution_path = workspace_root / "isolated-execution"
    execution_path.mkdir()
    executive = PilotConversationExecutive(root / "keeper.db")
    application = PassBApplication.test_composition(
        root,
        executive=executive,
        launch_authority=TestLaunchAuthority(),
        usage_reset_verifier=TestUsageResetVerifier(),
        recovery_action_authority=executive,
    )
    outcome = application.begin_conversation(
        "Build one bounded local software artifact. No spending, deployment, "
        "push, service change, or live trading."
    )
    outcome = application.conversation.revise(
        outcome.project.project_id,
        {
            "success_criteria": ("provider cancellation is recoverable",),
            "approved_providers": ("cancel-provider",),
            "approved_tools": ("filesystem", "tests"),
            "workspaces": (str(workspace_root),),
        },
    )
    challenge = application.conversation.request_approval(
        outcome.project.project_id
    )
    _, charter = executive.approve_and_activate(challenge)
    application.conversation.record_approval(charter)
    workflow, work_items = application.orchestration.create_workflow_plan(
        DynamicWorkflowDesigner().design(charter),
        authority_envelope_digest=authority_envelope_digest(
            charter.authority_envelope.to_dict()
        ),
    )
    assert workflow.project_id == charter.project_id
    provider, sessions = application.register_local_mock(
        provider_id="cancel-provider",
        account_id="cancel-account",
        session_count=1,
    )
    account = application.repository.get(
        ProviderAccountRecord, "cancel-account"
    )
    assignment = application.orchestration.create_assignment(
        work_item=work_items[0],
        provider_id=provider.provider_id,
        account_id=account.account_id,
        session_id=sessions[0].session_id,
        role=work_items[0].required_roles[0],
        model_id=sessions[0].model_id,
        workspace_id="cancel-workspace",
        authority_envelope_digest=workflow.authority_envelope_digest,
        expected_evidence=("structured-report",),
        usage_policy={
            "reservation_required": True,
            "paid_fallback": False,
        },
        independence_key=(
            f"{provider.provider_id}:{sessions[0].session_id}"
        ),
    )
    workspace = application.orchestration.reserve_workspace(
        assignment,
        execution_path,
        lease_seconds=300,
        branch="test/cancel-recovery",
        base_commit="abc",
    )
    write = application.orchestration.reserve_writes(
        assignment,
        workspace,
        ("src",),
        lease_seconds=300,
    )
    application.orchestration.reserve_usage(
        assignment, workspace, 1
    )
    authority_attempt_id = _authorize(
        application.orchestration,
        assignment,
        workspace,
        "authority-cancel-recovery",
    )
    attempt = AttemptRecord(
        attempt_id="cancel-recovery-attempt",
        assignment_id=assignment.assignment_id,
        authority_attempt_id=authority_attempt_id,
        launch_token="cancel-recovery-launch",
        state=AttemptState.RESERVED,
        external_execution_id=None,
        side_effect_class="REVERSIBLE_WORKSPACE_WRITE",
        started_at=None,
        finished_at=None,
        last_error=None,
        created_at=application.orchestration._now(),
        updated_at=application.orchestration._now(),
        revision=1,
        workspace_reservation_id=workspace.workspace_reservation_id,
        usage_reservation_id=str(
            application.repository.usage_reservations(
                assignment.assignment_id
            )[0]["reservation_id"]
        ),
        launch_plan_digest="cancel-recovery-plan",
        session_slot_claimed=True,
    )
    application.repository.reserve_attempt(attempt)
    application.repository.claim_launch(
        attempt.attempt_id, application.orchestration._now()
    )
    running = application.repository.mark_running(
        attempt.attempt_id,
        "external-cancel-recovery",
        application.orchestration._now(),
    )
    return (
        application,
        executive,
        assignment,
        running,
        workspace,
        write,
        execution_path,
    )


def test_cancel_side_effect_then_exception_is_durably_uncertain(
    tmp_path: Path,
) -> None:
    (
        application,
        _,
        assignment,
        attempt,
        workspace,
        write,
        execution_path,
    ) = _running(tmp_path)
    adapter = _CancelThenRaiseAdapter(assignment.provider_id)
    application.attach_adapter(assignment.provider_id, adapter)

    with pytest.raises(
        RuntimeError, match="simulated lost cancellation response"
    ):
        application.orchestration.cancel_assignment(
            assignment.assignment_id
        )

    current = application.repository.get(
        AttemptRecord, attempt.attempt_id
    )
    assert current.state == AttemptState.UNCERTAIN
    assert (
        current.uncertainty_kind
        == "CANCELLATION_OUTCOME_AMBIGUOUS"
    )
    assert current.cancellation_requested_at is not None
    assert application.repository.get(
        AssignmentRecord, assignment.assignment_id
    ).state == AssignmentState.UNCERTAIN
    assert application.repository.get(
        WorkspaceReservationRecord,
        workspace.workspace_reservation_id,
    ).state == ReservationState.UNCERTAIN
    assert application.repository.get(
        WriteReservationRecord, write.write_reservation_id
    ).state == ReservationState.UNCERTAIN
    assert application.repository.launch_claim(
        attempt.attempt_id
    )["state"] == "UNCERTAIN"
    assert application.repository.usage_reservations(
        assignment.assignment_id
    )[0]["state"] == "ACTIVE"
    session = application.repository.get(
        ProviderSessionRecord, assignment.session_id
    )
    assert session.active_assignments == 1
    assert adapter.health()["canceled"] == 1
    with pytest.raises(PermissionError):
        application.orchestration.run_assignment(
            assignment.assignment_id,
            execution_path,
            authority_attempt_id=attempt.authority_attempt_id,
            global_context={},
            task_context={},
        )


def test_cancel_success_then_commit_failure_is_durably_uncertain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        application,
        _,
        assignment,
        attempt,
        workspace,
        write,
        _,
    ) = _running(tmp_path)
    adapter = LocalMockAdapter(assignment.provider_id)
    application.attach_adapter(assignment.provider_id, adapter)

    def fail_completion(attempt_id: str, canceled_at: str) -> AttemptRecord:
        del attempt_id, canceled_at
        raise OSError("simulated cancellation commit failure")

    monkeypatch.setattr(
        application.repository,
        "complete_cancellation",
        fail_completion,
    )
    with pytest.raises(
        OSError, match="simulated cancellation commit failure"
    ):
        application.orchestration.cancel_assignment(
            assignment.assignment_id
        )

    current = application.repository.get(
        AttemptRecord, attempt.attempt_id
    )
    assert current.state == AttemptState.UNCERTAIN
    assert (
        current.uncertainty_kind
        == "CANCELLATION_OUTCOME_AMBIGUOUS"
    )
    assert adapter.health()["canceled"] == 1
    assert application.repository.get(
        WorkspaceReservationRecord,
        workspace.workspace_reservation_id,
    ).state == ReservationState.UNCERTAIN
    assert application.repository.get(
        WriteReservationRecord, write.write_reservation_id
    ).state == ReservationState.UNCERTAIN


def test_restart_classifies_interrupted_cancel_and_preserves_claims(
    tmp_path: Path,
) -> None:
    (
        application,
        _,
        assignment,
        attempt,
        workspace,
        write,
        _,
    ) = _running(tmp_path)
    application.repository.claim_cancellation(
        assignment.assignment_id,
        application.orchestration._now(),
    )

    recovered = application.repository.recover_interrupted_attempts(
        application.orchestration._now()
    )

    assert recovered == {"prelaunch_released": 0, "uncertain": 1}
    current = application.repository.get(
        AttemptRecord, attempt.attempt_id
    )
    assert (
        current.uncertainty_kind
        == "CANCELLATION_OUTCOME_AMBIGUOUS"
    )
    assert application.repository.get(
        WorkspaceReservationRecord,
        workspace.workspace_reservation_id,
    ).state == ReservationState.UNCERTAIN
    assert application.repository.get(
        WriteReservationRecord, write.write_reservation_id
    ).state == ReservationState.UNCERTAIN


def test_exact_founder_approval_reconciles_one_cancellation(
    tmp_path: Path,
) -> None:
    (
        application,
        _,
        assignment,
        attempt,
        workspace,
        write,
        _,
    ) = _running(tmp_path)
    adapter = _CancelThenRaiseAdapter(assignment.provider_id)
    application.attach_adapter(assignment.provider_id, adapter)
    with pytest.raises(RuntimeError):
        application.orchestration.cancel_assignment(
            assignment.assignment_id
        )
    observation_digest = hashlib.sha256(
        b"provider reports exact execution canceled"
    ).hexdigest()
    request = application.request_uncertain_cancellation_approval(
        assignment.assignment_id,
        observation_digest=observation_digest,
    )
    challenge = FounderApprovalChallenge.from_dict(
        request["challenge"]
    )
    confirmed = application.confirm_uncertain_cancellation_approval(
        challenge
    )
    approval_id = str(confirmed["approval"]["approval_id"])

    reconciled = application.apply_uncertain_cancellation_approval(
        assignment.assignment_id,
        observation_digest=observation_digest,
        approval_id=approval_id,
    )

    assert reconciled["state"] == AttemptState.CANCELED
    assert application.repository.get(
        AssignmentRecord, assignment.assignment_id
    ).state == AssignmentState.CANCELED
    assert application.repository.get(
        ProviderSessionRecord, assignment.session_id
    ).active_assignments == 0
    assert application.repository.usage_reservations(
        assignment.assignment_id
    )[0]["state"] == "CONSUMED"
    assert application.repository.get(
        WorkspaceReservationRecord,
        workspace.workspace_reservation_id,
    ).state == ReservationState.ACTIVE
    assert application.repository.get(
        WriteReservationRecord, write.write_reservation_id
    ).state == ReservationState.ACTIVE
    records = application.repository.list(
        UncertaintyReconciliationRecord,
        project_id=assignment.project_id,
    )
    assert len(records) == 1
    assert records[0].attempt_id == attempt.attempt_id
    assert records[0].approval_id == approval_id
    assert records[0].observation_digest == observation_digest
    with pytest.raises(PermissionError):
        application.apply_uncertain_cancellation_approval(
            assignment.assignment_id,
            observation_digest=observation_digest,
            approval_id=approval_id,
        )


def test_wrong_observation_cannot_consume_exact_founder_approval(
    tmp_path: Path,
) -> None:
    application, _, assignment, _, _, _, _ = _running(tmp_path)
    adapter = _CancelThenRaiseAdapter(assignment.provider_id)
    application.attach_adapter(assignment.provider_id, adapter)
    with pytest.raises(RuntimeError):
        application.orchestration.cancel_assignment(
            assignment.assignment_id
        )
    correct = hashlib.sha256(b"confirmed canceled").hexdigest()
    wrong = hashlib.sha256(b"different observation").hexdigest()
    request = application.request_uncertain_cancellation_approval(
        assignment.assignment_id,
        observation_digest=correct,
    )
    confirmed = application.confirm_uncertain_cancellation_approval(
        FounderApprovalChallenge.from_dict(request["challenge"])
    )
    approval_id = str(confirmed["approval"]["approval_id"])

    with pytest.raises(
        PermissionError, match="action approval binding is invalid"
    ):
        application.apply_uncertain_cancellation_approval(
            assignment.assignment_id,
            observation_digest=wrong,
            approval_id=approval_id,
        )

    applied = application.apply_uncertain_cancellation_approval(
        assignment.assignment_id,
        observation_digest=correct,
        approval_id=approval_id,
    )
    assert applied["state"] == AttemptState.CANCELED


def test_ordinary_execution_uncertainty_cannot_use_cancel_reconciliation(
    tmp_path: Path,
) -> None:
    application, _, assignment, attempt, _, _, _ = _running(tmp_path)
    application.repository.recover_interrupted_attempts(
        application.orchestration._now()
    )
    current = application.repository.get(
        AttemptRecord, attempt.attempt_id
    )
    assert (
        current.uncertainty_kind
        == "EXTERNAL_EXECUTION_OUTCOME_AMBIGUOUS"
    )
    with pytest.raises(
        PermissionError,
        match="no exact uncertain cancellation",
    ):
        application.request_uncertain_cancellation_approval(
            assignment.assignment_id,
            observation_digest=hashlib.sha256(b"not a cancel").hexdigest(),
        )


def test_exact_founder_disposition_releases_stale_execution_fence(
    tmp_path: Path,
) -> None:
    (
        application,
        _,
        assignment,
        attempt,
        workspace,
        write,
        _,
    ) = _running(tmp_path)
    application.repository.recover_interrupted_attempts(
        application.orchestration._now()
    )
    request = (
        application.request_uncertain_execution_disposition_approval(
            assignment.assignment_id
        )
    )
    confirmed = application.confirm_recovery_action_approval(
        FounderApprovalChallenge.from_dict(request["challenge"])
    )
    approval_id = str(confirmed["approval"]["approval_id"])

    disposed = (
        application.apply_uncertain_execution_disposition_approval(
            assignment.assignment_id,
            observation_digest=str(request["observation_digest"]),
            approval_id=approval_id,
        )
    )

    assert disposed["state"] == AttemptState.FAILED
    assert disposed["uncertainty_kind"] is None
    assert disposed["session_slot_claimed"] is False
    assert "possible external effect" in str(disposed["last_error"])
    assert application.repository.get(
        AssignmentRecord, assignment.assignment_id
    ).state == AssignmentState.CANCELED
    assert application.repository.get(
        ProviderSessionRecord, assignment.session_id
    ).active_assignments == 0
    assert application.repository.get(
        ProviderSessionRecord, assignment.session_id
    ).state == "READY"
    assert application.repository.get(
        WorkspaceReservationRecord, workspace.workspace_reservation_id
    ).state == ReservationState.RELEASED
    assert application.repository.get(
        WriteReservationRecord, write.write_reservation_id
    ).state == ReservationState.RELEASED
    assert application.repository.usage_reservations(
        assignment.assignment_id
    )[0]["state"] == "CONSUMED"
    assert application.repository.launch_claim(attempt.attempt_id)[
        "state"
    ] == AttemptState.FAILED
    records = application.repository.list(
        UncertainExecutionDispositionRecord,
        project_id=assignment.project_id,
    )
    assert len(records) == 1
    assert records[0].possible_external_effect_preserved is True
    assert records[0].usage_reservation_consumed is True
    assert records[0].usage_amount == 1
    assert records[0].usage_reservation_id == attempt.usage_reservation_id
    assert records[0].approval_id == approval_id


def test_uncertain_execution_disposition_rejects_changed_observation(
    tmp_path: Path,
) -> None:
    application, _, assignment, _, _, _, _ = _running(tmp_path)
    application.repository.recover_interrupted_attempts(
        application.orchestration._now()
    )
    request = (
        application.request_uncertain_execution_disposition_approval(
            assignment.assignment_id
        )
    )
    confirmed = application.confirm_recovery_action_approval(
        FounderApprovalChallenge.from_dict(request["challenge"])
    )
    wrong_digest = hashlib.sha256(b"different observation").hexdigest()

    with pytest.raises(
        PermissionError,
        match="recovery authority binding is invalid",
    ):
        application.apply_uncertain_execution_disposition_approval(
            assignment.assignment_id,
            observation_digest=wrong_digest,
            approval_id=str(confirmed["approval"]["approval_id"]),
        )


def test_uncertain_execution_disposition_binds_exact_write_claims(
    tmp_path: Path,
) -> None:
    application, _, assignment, _, _, write, _ = _running(tmp_path)
    application.repository.recover_interrupted_attempts(
        application.orchestration._now()
    )
    request = application.request_uncertain_execution_disposition_approval(
        assignment.assignment_id
    )
    changed = application.repository.get(
        WriteReservationRecord, write.write_reservation_id
    )
    with application.repository.store.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        application.repository._replace(
            connection,
            replace(
                changed,
                owner_token="changed-after-founder-observation",
                revision=changed.revision + 1,
            ),
            changed.revision,
        )
        connection.commit()

    with pytest.raises(
        (PermissionError, KeyError),
        match="approval|record not found",
    ):
        application.apply_uncertain_execution_disposition_approval(
            assignment.assignment_id,
            observation_digest=str(request["observation_digest"]),
            approval_id="unconsumed-approval",
        )
    assert application.repository.get(
        WriteReservationRecord, write.write_reservation_id
    ).state == ReservationState.UNCERTAIN


def test_uncertain_execution_disposition_requires_exact_inactivity_proof(
    tmp_path: Path,
) -> None:
    application, _, assignment, _, _, _, _ = _running(tmp_path)
    application.repository.recover_interrupted_attempts(
        application.orchestration._now()
    )
    application.orchestration.uncertain_execution_observer = (
        lambda authority_attempt_id: {
            "authority_attempt_id": authority_attempt_id,
            "disposition_readiness": "BLOCKED_ACTIVE",
            "launch_state": "RUNNING",
        }
    )

    with pytest.raises(
        PermissionError, match="inactivity is not proven"
    ):
        application.request_uncertain_execution_disposition_approval(
            assignment.assignment_id
        )


def test_uncertain_execution_disposition_is_not_replayable(
    tmp_path: Path,
) -> None:
    application, _, assignment, _, _, _, _ = _running(tmp_path)
    application.repository.recover_interrupted_attempts(
        application.orchestration._now()
    )
    request = (
        application.request_uncertain_execution_disposition_approval(
            assignment.assignment_id
        )
    )
    confirmed = application.confirm_recovery_action_approval(
        FounderApprovalChallenge.from_dict(request["challenge"])
    )
    application.apply_uncertain_execution_disposition_approval(
        assignment.assignment_id,
        observation_digest=str(request["observation_digest"]),
        approval_id=str(confirmed["approval"]["approval_id"]),
    )

    with pytest.raises(PermissionError):
        application.apply_uncertain_execution_disposition_approval(
            assignment.assignment_id,
            observation_digest=str(request["observation_digest"]),
            approval_id=str(confirmed["approval"]["approval_id"]),
        )


def test_current_charter_can_disposition_older_uncertain_execution(
    tmp_path: Path,
) -> None:
    application, executive, assignment, _, _, _, _ = _running(tmp_path)
    application.repository.recover_interrupted_attempts(
        application.orchestration._now()
    )
    revised = application.conversation.revise(
        assignment.project_id,
        {"purpose": "Continue only after exact Founder recovery."},
    )
    challenge = application.conversation.request_approval(
        assignment.project_id
    )
    _, current_charter = executive.approve_and_activate(challenge)
    application.conversation.record_approval(current_charter)
    assert current_charter.revision > assignment.charter_revision
    assert revised.charter.revision == current_charter.revision

    request = (
        application.request_uncertain_execution_disposition_approval(
            assignment.assignment_id
        )
    )
    confirmed = application.confirm_recovery_action_approval(
        FounderApprovalChallenge.from_dict(request["challenge"])
    )
    application.apply_uncertain_execution_disposition_approval(
        assignment.assignment_id,
        observation_digest=str(request["observation_digest"]),
        approval_id=str(confirmed["approval"]["approval_id"]),
    )

    record = application.repository.list(
        UncertainExecutionDispositionRecord,
        project_id=assignment.project_id,
    )[0]
    assert record.charter_revision == assignment.charter_revision
    assert record.approval_charter_revision == current_charter.revision
    assert record.approval_charter_id == current_charter.charter_id


def test_monotonic_recovery_proofs_bind_initial_approval_and_newer_finalization(
    tmp_path: Path,
) -> None:
    application, _, assignment, _, _, _, _ = _running(tmp_path)
    application.repository.recover_interrupted_attempts(
        application.orchestration._now()
    )
    generation = 0

    def observe(authority_attempt_id: str) -> dict[str, object]:
        nonlocal generation
        generation += 1
        return {
            "schema_version": 1,
            "kind": "uncertain_provider_attempt_observation",
            "authority_attempt_id": authority_attempt_id,
            "host_id": "host-monotonic-test",
            "enrollment_id": "enrollment-monotonic-test",
            "enrollment_generation": 7,
            "launch_id": "launch-monotonic-test",
            "launch_state": "ABSENT_FROM_ACTIVE_OR_UNCERTAIN_JOURNAL",
            "disposition_readiness": "EXACT_ATTEMPT_INACTIVE",
            "recovery_barrier_generation": generation,
        }

    def finalize(
        authority_attempt_id: str,
        receipt: dict[str, object],
    ) -> dict[str, object]:
        inactivity = observe(authority_attempt_id)
        return {
            "schema_version": 1,
            "kind": "uncertain_provider_attempt_disposition",
            "authority_attempt_id": authority_attempt_id,
            "project_id": receipt["project_id"],
            "charter_id": receipt["execution_charter_id"],
            "charter_revision": receipt["execution_charter_revision"],
            "approval_charter_id": receipt["charter_id"],
            "approval_charter_revision": receipt["charter_revision"],
            "assignment_id": receipt["assignment_id"],
            "pass_b_attempt_id": receipt["pass_b_attempt_id"],
            "action_id": receipt["action_id"],
            "action_digest": receipt["action_digest"],
            "approval_id": receipt["approval_id"],
            "approval_event_id": receipt["approval_event_id"],
            "observation_digest": receipt["observation_digest"],
            "inactivity_observation": inactivity,
            "inactivity_observation_digest": hashlib.sha256(
                json.dumps(
                    inactivity, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest(),
            "terminal_disposition": (
                "FOUNDER_ABANDONED_UNCERTAIN_EXTERNAL_EXECUTION"
            ),
            "possible_external_effect_preserved": True,
            "result_accepted": False,
            "retry_authorized": False,
        }

    application.orchestration.uncertain_execution_observer = observe
    application.orchestration.uncertain_execution_finalizer = finalize
    request = application.request_uncertain_execution_disposition_approval(
        assignment.assignment_id
    )
    assert generation == 1
    confirmed = application.confirm_recovery_action_approval(
        FounderApprovalChallenge.from_dict(request["challenge"])
    )
    application.apply_uncertain_execution_disposition_approval(
        assignment.assignment_id,
        observation_digest=str(request["observation_digest"]),
        approval_id=str(confirmed["approval"]["approval_id"]),
    )
    assert generation == 3


def test_recovery_disposition_rejects_host_reenrollment_after_approval(
    tmp_path: Path,
) -> None:
    application, _, assignment, _, _, _, _ = _running(tmp_path)
    application.repository.recover_interrupted_attempts(
        application.orchestration._now()
    )
    generation = 0

    def observe(authority_attempt_id: str) -> dict[str, object]:
        nonlocal generation
        generation += 1
        return {
            "authority_attempt_id": authority_attempt_id,
            "host_id": "host-before" if generation == 1 else "host-after",
            "enrollment_id": (
                "enrollment-before" if generation == 1 else "enrollment-after"
            ),
            "enrollment_generation": generation,
            "launch_id": "launch-stable",
            "recovery_barrier_generation": generation,
            "disposition_readiness": "EXACT_ATTEMPT_INACTIVE",
            "launch_state": "ABSENT_FROM_ACTIVE_OR_UNCERTAIN_JOURNAL",
        }

    application.orchestration.uncertain_execution_observer = observe
    request = application.request_uncertain_execution_disposition_approval(
        assignment.assignment_id
    )
    confirmed = application.confirm_recovery_action_approval(
        FounderApprovalChallenge.from_dict(request["challenge"])
    )

    with pytest.raises(PermissionError, match="signed Executive recovery receipt"):
        application.apply_uncertain_execution_disposition_approval(
            assignment.assignment_id,
            observation_digest=str(request["observation_digest"]),
            approval_id=str(confirmed["approval"]["approval_id"]),
        )


def test_disposition_cleanup_failure_rolls_back_every_local_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        application,
        _,
        assignment,
        attempt,
        workspace,
        write,
        _,
    ) = _running(tmp_path)
    application.repository.recover_interrupted_attempts(
        application.orchestration._now()
    )
    request = (
        application.request_uncertain_execution_disposition_approval(
            assignment.assignment_id
        )
    )
    confirmed = application.confirm_recovery_action_approval(
        FounderApprovalChallenge.from_dict(request["challenge"])
    )
    original_consume_usage = application.repository._consume_usage
    authority_receipts: list[dict[str, object]] = []
    original_finalizer = application.orchestration.uncertain_execution_finalizer
    assert original_finalizer is not None

    def record_finalization(
        authority_attempt_id: str,
        executive_receipt: dict[str, object],
    ) -> dict[str, object]:
        authority_receipts.append(executive_receipt)
        return original_finalizer(authority_attempt_id, executive_receipt)

    application.orchestration.uncertain_execution_finalizer = record_finalization

    def fail_usage_accounting(*args: object) -> None:
        del args
        raise OSError("simulated usage accounting failure")

    monkeypatch.setattr(
        application.repository, "_consume_usage", fail_usage_accounting
    )
    with pytest.raises(OSError, match="usage accounting failure"):
        application.apply_uncertain_execution_disposition_approval(
            assignment.assignment_id,
            observation_digest=str(request["observation_digest"]),
            approval_id=str(confirmed["approval"]["approval_id"]),
        )

    assert application.repository.get(
        AttemptRecord, attempt.attempt_id
    ).state == AttemptState.UNCERTAIN
    assert application.repository.get(
        AssignmentRecord, assignment.assignment_id
    ).state == AssignmentState.UNCERTAIN
    assert application.repository.get(
        ProviderSessionRecord, assignment.session_id
    ).active_assignments == 1
    assert application.repository.get(
        WorkspaceReservationRecord, workspace.workspace_reservation_id
    ).state == ReservationState.UNCERTAIN
    assert application.repository.get(
        WriteReservationRecord, write.write_reservation_id
    ).state == ReservationState.UNCERTAIN
    assert application.repository.list(
        UncertainExecutionDispositionRecord,
        project_id=assignment.project_id,
    ) == []

    monkeypatch.setattr(
        application.repository, "_consume_usage", original_consume_usage
    )
    retried = application.apply_uncertain_execution_disposition_approval(
        assignment.assignment_id,
        observation_digest=str(request["observation_digest"]),
        approval_id=str(confirmed["approval"]["approval_id"]),
    )
    assert retried["state"] == AttemptState.FAILED
    assert len(authority_receipts) == 2
    assert authority_receipts[0] == authority_receipts[1]


def test_authority_finalization_failure_preserves_every_local_claim(
    tmp_path: Path,
) -> None:
    (
        application,
        _,
        assignment,
        attempt,
        workspace,
        write,
        _,
    ) = _running(tmp_path)
    application.repository.recover_interrupted_attempts(
        application.orchestration._now()
    )
    request = application.request_uncertain_execution_disposition_approval(
        assignment.assignment_id
    )
    confirmed = application.confirm_recovery_action_approval(
        FounderApprovalChallenge.from_dict(request["challenge"])
    )

    def reject_finalization(
        authority_attempt_id: str,
        executive_receipt: dict[str, object],
    ) -> dict[str, object]:
        del authority_attempt_id, executive_receipt
        raise PermissionError("simulated Authority refusal")

    application.orchestration.uncertain_execution_finalizer = reject_finalization
    with pytest.raises(PermissionError, match="Authority refusal"):
        application.apply_uncertain_execution_disposition_approval(
            assignment.assignment_id,
            observation_digest=str(request["observation_digest"]),
            approval_id=str(confirmed["approval"]["approval_id"]),
        )

    assert application.repository.get(
        AttemptRecord, attempt.attempt_id
    ).state == AttemptState.UNCERTAIN
    assert application.repository.get(
        AssignmentRecord, assignment.assignment_id
    ).state == AssignmentState.UNCERTAIN
    assert application.repository.get(
        ProviderSessionRecord, assignment.session_id
    ).active_assignments == 1
    assert application.repository.get(
        WorkspaceReservationRecord, workspace.workspace_reservation_id
    ).state == ReservationState.UNCERTAIN
    assert application.repository.get(
        WriteReservationRecord, write.write_reservation_id
    ).state == ReservationState.UNCERTAIN
    assert application.repository.usage_reservations(
        assignment.assignment_id
    )[0]["state"] == "ACTIVE"


def test_stale_charter_rejects_cancellation_reconciliation(
    tmp_path: Path,
) -> None:
    application, _, assignment, _, _, _, _ = _running(tmp_path)
    adapter = _CancelThenRaiseAdapter(assignment.provider_id)
    application.attach_adapter(assignment.provider_id, adapter)
    with pytest.raises(RuntimeError):
        application.orchestration.cancel_assignment(
            assignment.assignment_id
        )
    observation = hashlib.sha256(b"confirmed canceled").hexdigest()
    request = application.request_uncertain_cancellation_approval(
        assignment.assignment_id,
        observation_digest=observation,
    )
    confirmed = application.confirm_uncertain_cancellation_approval(
        FounderApprovalChallenge.from_dict(request["challenge"])
    )
    status = application.project_status(assignment.project_id)
    project = dict(status["project_summary"])
    charter = dict(status["active_charter"])
    project["active_charter_revision"] = assignment.charter_revision + 1
    charter["revision"] = assignment.charter_revision + 1
    charter["founder_approval_record_id"] = "replacement-approval"
    charter["founder_authorization_capability_digest"] = "b" * 64
    superseded = {
        **status,
        "project_summary": project,
        "active_charter": charter,
    }
    application.orchestration.project_status = (
        lambda requested: (
            superseded
            if requested == assignment.project_id
            else application.project_status(requested)
        )
    )

    with pytest.raises(
        PermissionError,
        match="current Founder-approved charter",
    ):
        application.apply_uncertain_cancellation_approval(
            assignment.assignment_id,
            observation_digest=observation,
            approval_id=str(confirmed["approval"]["approval_id"]),
        )

    assert application.repository.get(
        AttemptRecord, "cancel-recovery-attempt"
    ).state == AttemptState.UNCERTAIN


def test_test_recovery_authority_cannot_enter_normal_composition(
    tmp_path: Path,
) -> None:
    executive = PilotConversationExecutive(tmp_path / "executive.db")
    with pytest.raises(
        TypeError,
        match="test recovery authority requires test launch composition",
    ):
        PassBApplication(
            tmp_path / "application",
            executive=executive,
            _test_recovery_action_authority=executive,
        )
