from __future__ import annotations

from pathlib import Path

from keeper.pass_b.application import PassBApplication
from keeper.pass_b.authority_reservation import TestAuthorityAttemptReservation
from keeper.pass_b.completion import CompletionCoordinator
from keeper.pass_b.conversation import DynamicWorkflowDesigner
from keeper.pass_b.enums import AssignmentRole, WorkflowState
from keeper.pass_b.launch_authority import TestLaunchAuthority
from keeper.pass_b.models import (
    AssignmentRecord,
    DelegatedModeGrantRecord,
    EvidenceReferenceRecord,
    ExecutionProfileRecord,
    ReviewRecord,
    WorkspaceReservationRecord,
    WorkflowRecord,
)
from keeper.pass_b.orchestration import authority_envelope_digest
from keeper.pass_b.pilot import PilotConversationExecutive
from keeper.pass_b.usage_authority import TestUsageResetVerifier


def _application(root: Path) -> tuple[PassBApplication, str]:
    launch = TestLaunchAuthority()
    executive = PilotConversationExecutive(root / "keeper.db")
    application = PassBApplication.test_composition(
        root,
        executive=executive,
        launch_authority=launch,
        authority_reservation=TestAuthorityAttemptReservation(launch),
        usage_reset_verifier=TestUsageResetVerifier(),
    )
    application.register_local_mock(
        provider_id="local-builder", account_id="builder", session_count=1
    )
    application.register_local_mock(
        provider_id="local-reviewer", account_id="reviewer", session_count=1
    )
    workspace = root / "project-workspaces"
    outcome = application.begin_conversation(
        f"Build a small local software application in {workspace}. "
        "Use full delegation and no spending, deployment, push, or live trading."
    )
    outcome = application.conversation.revise(
        outcome.project.project_id,
        {
            "success_criteria": (
                "all planned stages have independently accepted evidence",
            ),
            "target_audience": "Founder",
            "approved_providers": ("local-builder", "local-reviewer"),
            "approved_tools": ("filesystem", "tests"),
            "workspaces": (str(workspace),),
            "review_requirements": ("independent typed-evidence review",),
            "evidence_requirements": ("structured-report",),
        },
    )
    challenge = application.conversation.request_approval(
        outcome.project.project_id
    )
    project, charter = executive.approve_and_activate(challenge)
    application.conversation.record_approval(charter)
    blueprint = DynamicWorkflowDesigner().design(charter)
    application.orchestration.create_workflow_plan(
        blueprint,
        authority_envelope_digest=authority_envelope_digest(
            charter.authority_envelope.to_dict()
        ),
    )
    return application, project.project_id


def test_one_approval_autonomous_completion_reaches_terminal_workflow(
    tmp_path: Path,
) -> None:
    application, project_id = _application(tmp_path)

    results = application.run_delegated_completion(project_id, max_steps=50)

    assert results[-1].state == "COMPLETED"
    workflows = application.repository.list(
        WorkflowRecord, project_id=project_id
    )
    assert len(workflows) == 1
    assert workflows[0].state == WorkflowState.COMPLETED
    grants = application.repository.list(
        DelegatedModeGrantRecord, project_id=project_id
    )
    assert len(grants) == 1
    assert grants[0].state == "ACTIVE"
    assignments = application.repository.list(
        AssignmentRecord, project_id=project_id
    )
    producers = [
        item for item in assignments if item.role != AssignmentRole.REVIEWER
    ]
    reviewers = [
        item for item in assignments if item.role == AssignmentRole.REVIEWER
    ]
    assert producers
    assert len(reviewers) == len(producers)
    assert all(item.state == "COMPLETED" for item in assignments)
    reviews = application.repository.list(ReviewRecord, project_id=project_id)
    assert len(reviews) == len(producers)
    assert all(item.state == "ACCEPTED" for item in reviews)
    references = application.repository.list(
        EvidenceReferenceRecord, project_id=project_id
    )
    assert len(references) == len(reviews)
    assert all(item.consumed_by_review_id for item in references)
    assert sum(item.actions_used for item in grants) > 0
    workspaces = application.repository.list(
        WorkspaceReservationRecord, project_id=project_id
    )
    by_assignment = {
        item.assignment_id: item.canonical_path for item in workspaces
    }
    producer_paths = {
        by_assignment[item.assignment_id] for item in producers
    }
    reviewer_paths = {
        by_assignment[item.assignment_id] for item in reviewers
    }
    assert len(producer_paths) == 1
    assert reviewer_paths
    assert producer_paths.isdisjoint(reviewer_paths)
    assert len(reviewer_paths) == len(reviewers)
    profiles = application.repository.list(
        ExecutionProfileRecord, project_id=project_id
    )
    assert profiles
    assert all(item.project_type == "software" for item in profiles)


def test_completion_coordinator_is_restart_resumable(tmp_path: Path) -> None:
    application, project_id = _application(tmp_path)

    first = application.advance_delegated_completion(project_id)
    assert first.state == "PROGRESS"
    restarted = CompletionCoordinator(
        application.repository,
        application.orchestration,
        application.project_status,
        tmp_path,
    )
    results = restarted.run_until_blocked(project_id, max_steps=50)

    assert results[-1].state == "COMPLETED"

def test_repair_uses_fresh_selection_and_returns_to_independent_review(
    tmp_path: Path,
) -> None:
    application, project_id = _application(tmp_path)
    first = application.advance_delegated_completion(project_id)
    assert first.state == "PROGRESS"
    producer = next(
        item
        for item in application.repository.list(
            AssignmentRecord, project_id=project_id
        )
        if item.assignment_id == first.assignment_id
    )
    for provider_id, adapter in application.orchestration.adapters.items():
        if provider_id != producer.provider_id and hasattr(
            adapter, "set_review_outcome"
        ):
            adapter.set_review_outcome(
                "REPAIR_REQUIRED",
                ({"severity": "MEDIUM", "summary": "repair fixture"},),
            )
    reviewed = application.advance_delegated_completion(project_id)
    assert reviewed.state == "PROGRESS"
    decided = application.advance_delegated_completion(project_id)
    assert "repair" in decided.detail.casefold()
    for adapter in application.orchestration.adapters.values():
        if hasattr(adapter, "set_review_outcome"):
            adapter.set_review_outcome("ACCEPTED")

    results = application.run_delegated_completion(project_id, max_steps=60)

    assert results[-1].state == "COMPLETED"
    assignments = application.repository.list(
        AssignmentRecord, project_id=project_id
    )
    repairs = [
        item
        for item in assignments
        if item.usage_policy.get("repair_of_assignment_id")
        == producer.assignment_id
    ]
    assert len(repairs) == 1
    assert repairs[0].usage_policy["provider_selection_id"] != (
        producer.usage_policy["provider_selection_id"]
    )
    assert repairs[0].state == "COMPLETED"


def test_project_continuation_revises_selected_project_not_new_project(
    tmp_path: Path,
) -> None:
    executive = PilotConversationExecutive(tmp_path / "keeper.db")
    application = PassBApplication(tmp_path, executive=executive)
    outcome = application.begin_conversation("Build a small local application.")
    project_id = outcome.project.project_id

    revised = application.continue_conversation(
        project_id,
        "Use full delegation and no spending.",
    )

    assert revised is not None
    assert revised.project.project_id == project_id
    assert len(application.project_catalog()) == 1
    assert application.conversation.current_context(project_id).charter_revision == 2
