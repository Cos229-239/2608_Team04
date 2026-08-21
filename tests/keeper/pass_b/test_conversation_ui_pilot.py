from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from keeper.executive.models import ProjectCharter
from keeper.pass_b.conversation import (
    DynamicWorkflowDesigner,
    activate_delegated_mode,
    revoke_delegated_mode,
)
from keeper.pass_b.desktop import PassBDesktop
from keeper.pass_b.models import ConversationMessageRecord
from keeper.pass_b.pilot import PilotConversationExecutive, run_darksage_pilot
from keeper.pass_b.application import PassBApplication


def _approved_application(
    tmp_path: Path,
) -> tuple[PassBApplication, ProjectCharter]:
    executive = PilotConversationExecutive(tmp_path / "keeper.db")
    application = PassBApplication(tmp_path, executive=executive)
    outcome = application.begin_conversation(
        "Build a software app. I am going to work; continue under delegated "
        "mode. No spending, deployment, live trading, or push."
    )
    outcome = application.conversation.revise(
        outcome.project.project_id,
        {
            "success_criteria": ("structured evidence is independently reviewed",),
            "target_audience": "Founder",
            "approved_providers": ("local-builder", "local-reviewer"),
            "approved_tools": ("filesystem", "tests"),
            "review_requirements": ("independent specialist",),
            "evidence_requirements": ("structured-report",),
            "workspaces": (str(tmp_path / "bounded-workspace"),),
        },
    )
    challenge = application.conversation.request_approval(
        outcome.project.project_id
    )
    _, charter = executive.approve_and_activate(challenge)
    application.conversation.record_approval(charter)
    return application, charter


def test_conversation_requires_explicit_approval_and_drives_ui_state(
    tmp_path: Path,
) -> None:
    application, charter = _approved_application(tmp_path)
    blueprint = DynamicWorkflowDesigner().design(charter)
    snapshot = application.control_room.snapshot(charter.project_id).to_dict()
    messages = application.repository.list(ConversationMessageRecord)

    assert blueprint.strategy == "software-adaptive"
    assert snapshot["conversation"]["approval_required"] is False
    assert snapshot["project"]["charter_revision"] == charter.revision
    assert snapshot["safety"]["authority"]["state"] == "NOT_CONFIGURED"
    assert all(message.durable_authority is False for message in messages)
    assert application.diagnostics()["presentation_authority_effect"] == "NONE"
    assert "no authority effect" in PassBDesktop._presentation_summary(
        snapshot["presentation"]
    )


def test_approval_recording_rejects_unapproved_charter(tmp_path: Path) -> None:
    executive = PilotConversationExecutive(tmp_path / "keeper.db")
    application = PassBApplication(tmp_path, executive=executive)
    outcome = application.begin_conversation("Build a software app.")

    with pytest.raises(PermissionError):
        application.conversation.record_approval(outcome.charter)


def test_delegated_mode_is_founder_bound_scoped_and_revocable(
    tmp_path: Path,
) -> None:
    application, charter = _approved_application(tmp_path)
    expires_at = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    assert charter.founder_approval_identity is not None
    assert charter.founder_approval_record_id is not None
    assert charter.founder_authorization_capability_digest is not None

    with pytest.raises(PermissionError):
        activate_delegated_mode(
            application.repository,
            project_status=application.project_status,
            project_id=charter.project_id,
            charter=charter,
            founder_identity=charter.founder_approval_identity,
            founder_approval_id=charter.founder_approval_record_id,
            founder_approval_digest="wrong",
            scope=("RUN_TESTS",),
            expires_at=expires_at,
        )
    with pytest.raises(PermissionError):
        activate_delegated_mode(
            application.repository,
            project_status=application.project_status,
            project_id=charter.project_id,
            charter=charter,
            founder_identity=charter.founder_approval_identity,
            founder_approval_id=charter.founder_approval_record_id,
            founder_approval_digest=(
                charter.founder_authorization_capability_digest
            ),
            scope=("SPENDING",),
            expires_at=expires_at,
        )

    grant = activate_delegated_mode(
        application.repository,
        project_status=application.project_status,
        project_id=charter.project_id,
        charter=charter,
        founder_identity=charter.founder_approval_identity,
        founder_approval_id=charter.founder_approval_record_id,
        founder_approval_digest=charter.founder_authorization_capability_digest,
        scope=("RUN_TESTS",),
        expires_at=expires_at,
    )
    snapshot = application.control_room.snapshot(charter.project_id).to_dict()
    assert snapshot["safety"]["delegated_mode"][0][
        "delegated_mode_grant_id"
    ] == grant.delegated_mode_grant_id
    revoked = revoke_delegated_mode(
        application.repository, grant.delegated_mode_grant_id
    )
    assert revoked.state == "REVOKED"


def test_local_registration_exposes_distinct_durable_sessions(
    tmp_path: Path,
) -> None:
    application, _ = _approved_application(tmp_path)
    provider, sessions = application.register_local_mock(session_count=3)
    snapshot = application.control_room.snapshot().to_dict()

    assert provider.provider_id == "local-mock"
    assert len({session.session_id for session in sessions}) == 3
    assert len(snapshot["providers"]["sessions"]) == 3
    assert snapshot["safety"]["prohibited_actions"]


def test_restart_reattaches_adapter_to_durable_provider(
    tmp_path: Path,
) -> None:
    first, _ = _approved_application(tmp_path)
    provider, sessions = first.register_local_mock(session_count=2)

    restarted_executive = PilotConversationExecutive(tmp_path / "keeper.db")
    restarted = PassBApplication(
        tmp_path, executive=restarted_executive
    )
    recovered_provider, recovered_sessions = restarted.register_local_mock(
        session_count=2
    )

    assert recovered_provider.provider_id == provider.provider_id
    assert tuple(item.session_id for item in recovered_sessions) == tuple(
        item.session_id for item in sessions
    )
    assert provider.provider_id in restarted.orchestration.adapters


def test_darksage_pilot_completes_with_independent_roles(
    tmp_path: Path,
) -> None:
    evidence_path = tmp_path / "evidence" / "pass-b-pilot.json"
    report = run_darksage_pilot(tmp_path / "pilot", evidence_path)

    assert report["result"] == "PASS"
    assert report["workflow_strategy"] == "software-adaptive"
    assert report["durable_workflow_present"] is True
    assert len(report["durable_work_item_ids"]) == 3
    assert len(set(report["provider_sessions"])) == 2
    assert report["charter_founder_approved"] is True
    assert report["implementation_evidence"]["state"] == "VALIDATED"
    assert report["independent_review"]["state"] == "ACCEPTED"
    assert report["usage_pause_observed"] is True
    assert report["usage_resume_state"] == "READY"
    assert report["delegated_prohibited_action_denied"] is True
    assert report["delegated_push_denied"] is True
    assert report["delegated_force_push_denied"] is True
    assert report["delegated_supersession_enforced"] is True
    assert report["delegated_superseded_state"] == "SUPERSEDED"
    assert report["delegated_expiry_enforced"] is True
    assert report["delegated_expired_state"] == "EXPIRED"
    assert report["delegated_absent_from_active_projection"] is True
    assert report["duplicate_launch_count"] == 0
    assert report["production_rejected_test_reset_verifier"] is True
    assert report["pilot_evidence_read_only_reference"] is True
    assert report["pilot_evidence_reference_id"]
    assert report["pilot_evidence_writer_rejected"] is True
    assert report["pilot_evidence_reference_preserved"] is True
    assert report["reviewer_workspace_isolated"] is True
    assert report["reviewer_executive_commit_receipt_bound"] is True
    assert len(report["reviewer_executive_commit_receipt_digest"]) == 64
    assert report["reviewer_parent_workspace_rejected"] is True
    assert report["reviewer_parent_adapter_not_invoked"] is True
    assert report["reviewer_parent_evidence_unchanged"] is True
    assert report["automatic_paid_fallback"] is False
    assert report["provider_self_approval"] is False
    assert report["push_performed"] is False
    assert report["deployment_performed"] is False
    assert report["spending_performed"] is False
    assert report["service_change_performed"] is False
    assert report["live_trading_enabled"] is False
    assert report["presentation_authority_effect"] == "NONE"
    assert set(report["authority_attempt_states"].values()) == {
        "COMPLETED"
    }
    assert report["authority_production_validation"] is False
    assert report["control_room_summary"]["authority_state"] == (
        "TEST_COMPOSITION"
    )
    assert evidence_path.is_file()
