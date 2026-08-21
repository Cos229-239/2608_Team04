from __future__ import annotations

import hashlib
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
