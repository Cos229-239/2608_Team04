from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest

from keeper.pass_b.application import PassBApplication
from keeper.pass_b.conversation import (
    DynamicWorkflowDesigner,
    activate_delegated_mode,
)
from keeper.pass_b.enums import AssignmentRole, WorkItemState
from keeper.pass_b.models import (
    AssignmentRecord,
    AttemptRecord,
    ExecutionProfileRecord,
    ProviderSelectionRecord,
    WorkItemRecord,
)
from keeper.pass_b.orchestration import authority_envelope_digest
from keeper.pass_b.pilot import PilotConversationExecutive


def _stack(
    root: Path,
    *,
    grant_scope: tuple[str, ...] = (
        "SELECT_APPROVED_PROVIDER",
        "ASSIGN_IMPLEMENTATION",
        "ASSIGN_READ_ONLY_REVIEW",
    ),
) -> tuple[
    PassBApplication,
    tuple[WorkItemRecord, ...],
    str,
    Path,
]:
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    executive = PilotConversationExecutive(root / "keeper.db")
    application = PassBApplication(root, executive=executive)
    outcome = application.begin_conversation(
        "Build a software application with full delegation in an isolated "
        "workspace. No spending, deployment, push, or live trading."
    )
    outcome = application.conversation.revise(
        outcome.project.project_id,
        {
            "success_criteria": ("independent evidence is accepted",),
            "approved_providers": ("local-builder", "local-reviewer"),
            "approved_tools": ("filesystem", "tests"),
            "workspaces": (str(workspace),),
            "delegation_mode": "FULL_DELEGATION",
        },
    )
    challenge = application.conversation.request_approval(
        outcome.project.project_id
    )
    _, charter = executive.approve_and_activate(challenge)
    application.conversation.record_approval(charter)
    blueprint = DynamicWorkflowDesigner().design(charter)
    _, items = application.orchestration.create_workflow_plan(
        blueprint,
        authority_envelope_digest=authority_envelope_digest(
            charter.authority_envelope.to_dict()
        ),
    )
    application.register_local_mock(
        provider_id="local-builder",
        account_id="builder-account",
        session_count=2,
    )
    application.register_local_mock(
        provider_id="local-reviewer",
        account_id="reviewer-account",
        session_count=1,
    )
    assert charter.founder_approval_identity
    assert charter.founder_approval_record_id
    assert charter.founder_authorization_capability_digest
    grant = activate_delegated_mode(
        application.repository,
        project_status=application.project_status,
        project_id=charter.project_id,
        charter=charter,
        founder_identity=charter.founder_approval_identity,
        founder_approval_id=charter.founder_approval_record_id,
        founder_approval_digest=(
            charter.founder_authorization_capability_digest
        ),
        scope=grant_scope,
        expires_at=(
            datetime.now(UTC) + timedelta(hours=1)
        ).isoformat(),
        max_actions=30,
    )
    return application, items, grant.delegated_mode_grant_id, workspace


def _profile(
    application: PassBApplication,
    item: WorkItemRecord,
    workspace: Path,
) -> ExecutionProfileRecord:
    return application.orchestration.register_execution_profile(
        work_item_id=item.work_item_id,
        role=item.required_roles[0],
        workspace_path=workspace,
        write_scopes=("src",),
        expected_evidence=("structured-report",),
        usage_amount=2,
        effort_level="HIGH",
        required_capabilities=(item.required_roles[0].casefold(),),
        privacy_classification="LOCAL",
        preferred_provider_id="local-builder",
    )


def test_profile_and_selection_are_durable_without_external_launch(
    tmp_path: Path,
) -> None:
    application, items, grant_id, workspace = _stack(tmp_path)
    profile = _profile(application, items[0], workspace)

    assignment, selection = (
        application.orchestration.prepare_assignment_from_profile(
            profile.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )
    )

    assert assignment.state == "READY"
    assert selection.execution_profile_id == profile.execution_profile_id
    assert selection.assignment_id == assignment.assignment_id
    assert selection.provider_id == "local-builder"
    assert selection.cost_mode == "FREE"
    assert assignment.usage_policy == {
        "reservation_required": True,
        "paid_fallback": False,
        "requested_amount": 2,
        "execution_profile_id": profile.execution_profile_id,
        "provider_selection_id": selection.provider_selection_id,
        "effort_level": "HIGH",
    }
    assert application.repository.get(
        WorkItemRecord, items[0].work_item_id
    ).state == WorkItemState.ASSIGNED
    assert application.repository.list(AttemptRecord) == []
    snapshot = application.control_room.snapshot(
        assignment.project_id
    ).to_dict()
    assert snapshot["project"]["execution_profiles"][0][
        "execution_profile_id"
    ] == profile.execution_profile_id
    assert snapshot["project"]["provider_selections"][0][
        "provider_selection_id"
    ] == selection.provider_selection_id


def test_incomplete_dependency_rejects_before_assignment(
    tmp_path: Path,
) -> None:
    application, items, grant_id, workspace = _stack(tmp_path)
    profile = _profile(application, items[1], workspace)

    with pytest.raises(PermissionError, match="dependencies"):
        application.orchestration.prepare_assignment_from_profile(
            profile.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )

    assert not any(
        item.work_item_id == items[1].work_item_id
        for item in application.repository.list(AssignmentRecord)
    )
    assert application.repository.list(AttemptRecord) == []


def test_concurrent_preparation_has_one_durable_assignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application, items, grant_id, workspace = _stack(tmp_path)
    profile = _profile(application, items[0], workspace)
    original = application.repository.claim_prepared_assignment
    barrier = Barrier(2)
    monkeypatch.setattr(
        "keeper.pass_b.orchestration.validate_delegated_action",
        lambda *args, **kwargs: None,
    )

    def synchronized_claim(**kwargs: object) -> bool:
        barrier.wait(timeout=5)
        return original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        application.repository,
        "claim_prepared_assignment",
        synchronized_claim,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                application.orchestration.prepare_assignment_from_profile,
                profile.execution_profile_id,
                delegated_mode_grant_id=grant_id,
            )
            for _ in range(2)
        ]
        results = [future.result(timeout=10) for future in futures]

    assert len(
        [
            item
            for item in application.repository.list(AssignmentRecord)
            if item.work_item_id == items[0].work_item_id
        ]
    ) == 1
    assert len(
        application.repository.list(ProviderSelectionRecord)
    ) == 1
    assert {item[0].assignment_id for item in results} == {
        results[0][0].assignment_id
    }
    assert application.repository.list(AttemptRecord) == []


def test_durable_selection_count_balances_ready_sessions(
    tmp_path: Path,
) -> None:
    application, items, grant_id, workspace = _stack(tmp_path)
    first = _profile(application, items[0], workspace)
    first_assignment, first_selection = (
        application.orchestration.prepare_assignment_from_profile(
            first.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )
    )
    extra = application.orchestration.create_work_item(
        project_id=items[0].project_id,
        charter_id=items[0].charter_id,
        charter_revision=items[0].charter_revision,
        workflow_id=items[0].workflow_id,
        title="Parallel planning",
        objective="Plan an independent bounded task",
        dependencies=(),
        required_roles=(AssignmentRole.PLANNER,),
    )
    second = _profile(application, extra, workspace)
    second_assignment, second_selection = (
        application.orchestration.prepare_assignment_from_profile(
            second.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )
    )

    assert first_assignment.assignment_id != second_assignment.assignment_id
    assert first_selection.session_id != second_selection.session_id


def test_reviewer_selection_excludes_producer_identity_and_writes(
    tmp_path: Path,
) -> None:
    application, items, grant_id, workspace = _stack(tmp_path)
    producer_profile = _profile(application, items[0], workspace)
    producer, _ = application.orchestration.prepare_assignment_from_profile(
        producer_profile.execution_profile_id,
        delegated_mode_grant_id=grant_id,
    )
    review_item = application.orchestration.create_work_item(
        project_id=items[0].project_id,
        charter_id=items[0].charter_id,
        charter_revision=items[0].charter_revision,
        workflow_id=items[0].workflow_id,
        title="Independent review",
        objective="Review the producer evidence",
        dependencies=(),
        required_roles=(AssignmentRole.REVIEWER,),
    )
    review_profile = (
        application.orchestration.register_execution_profile(
            work_item_id=review_item.work_item_id,
            role=AssignmentRole.REVIEWER,
            workspace_path=workspace,
            write_scopes=(),
            expected_evidence=("structured-report",),
            usage_amount=1,
            effort_level="HIGH",
            required_capabilities=("reviewer",),
            privacy_classification="LOCAL",
            preferred_provider_id="local-builder",
            review_of_assignment_id=producer.assignment_id,
        )
    )
    reviewer, selection = (
        application.orchestration.prepare_assignment_from_profile(
            review_profile.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )
    )

    assert reviewer.read_only is True
    assert reviewer.provider_id == "local-reviewer"
    assert selection.independence_key != producer.independence_key
    assert reviewer.usage_policy["review_of_assignment_id"] == (
        producer.assignment_id
    )


def test_missing_delegated_assignment_scope_fails_closed(
    tmp_path: Path,
) -> None:
    application, items, grant_id, workspace = _stack(
        tmp_path,
        grant_scope=("SELECT_APPROVED_PROVIDER",),
    )
    profile = _profile(application, items[0], workspace)

    with pytest.raises(PermissionError, match="out of scope"):
        application.orchestration.prepare_assignment_from_profile(
            profile.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )

    assert application.repository.list(AssignmentRecord) == []
    assert application.repository.list(AttemptRecord) == []


def test_restart_preserves_profile_and_selection(
    tmp_path: Path,
) -> None:
    application, items, grant_id, workspace = _stack(tmp_path)
    profile = _profile(application, items[0], workspace)
    assignment, selection = (
        application.orchestration.prepare_assignment_from_profile(
            profile.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )
    )

    restarted = PassBApplication(
        tmp_path,
        executive=PilotConversationExecutive(tmp_path / "keeper.db"),
    )

    assert restarted.repository.get(
        ExecutionProfileRecord, profile.execution_profile_id
    ) == profile
    assert restarted.repository.get(
        AssignmentRecord, assignment.assignment_id
    ) == assignment
    assert restarted.repository.get(
        ProviderSelectionRecord, selection.provider_selection_id
    ) == selection
    assert restarted.repository.list(AttemptRecord) == []


def test_tampered_selection_policy_digest_rejects_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application, items, grant_id, workspace = _stack(tmp_path)
    profile = _profile(application, items[0], workspace)
    original = application.repository.claim_prepared_assignment

    def tampered_claim(**kwargs: object) -> bool:
        selection = kwargs["selection"]
        assert isinstance(selection, ProviderSelectionRecord)
        kwargs["selection"] = replace(
            selection, policy_digest="f" * 64
        )
        return original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        application.repository,
        "claim_prepared_assignment",
        tampered_claim,
    )

    with pytest.raises(PermissionError, match="no longer satisfies policy"):
        application.orchestration.prepare_assignment_from_profile(
            profile.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )

    assert application.repository.list(AssignmentRecord) == []
    assert application.repository.list(ProviderSelectionRecord) == []


def test_stale_charter_rejects_before_assignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application, items, grant_id, workspace = _stack(tmp_path)
    profile = _profile(application, items[0], workspace)
    original_status = application.project_status

    def stale_status(project_id: str) -> dict[str, Any]:
        status = copy.deepcopy(original_status(project_id))
        status["project_summary"]["active_charter_revision"] += 1
        status["active_charter"]["revision"] += 1
        return status

    monkeypatch.setattr(
        application.orchestration, "project_status", stale_status
    )

    with pytest.raises(PermissionError, match="current Founder-approved"):
        application.orchestration.prepare_assignment_from_profile(
            profile.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )

    assert application.repository.list(AssignmentRecord) == []
    assert application.repository.list(AttemptRecord) == []


def test_prepared_assignment_cannot_substitute_workspace_or_scope(
    tmp_path: Path,
) -> None:
    application, items, grant_id, workspace = _stack(tmp_path)
    profile = _profile(application, items[0], workspace)
    assignment, _ = (
        application.orchestration.prepare_assignment_from_profile(
            profile.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )
    )
    alternate = workspace / "alternate"
    alternate.mkdir()

    with pytest.raises(
        PermissionError, match="differs from durable execution profile"
    ):
        application.orchestration.reserve_workspace(
            assignment,
            alternate,
            lease_seconds=60,
            branch="feature/alternate",
            base_commit="a" * 40,
        )

    reservation = application.orchestration.reserve_workspace(
        assignment,
        workspace,
        lease_seconds=60,
        branch="feature/exact",
        base_commit="a" * 40,
    )
    with pytest.raises(
        PermissionError, match="differs from durable execution profile"
    ):
        application.orchestration.reserve_writes(
            assignment,
            reservation,
            ("different-scope",),
            lease_seconds=60,
        )

    write = application.orchestration.reserve_writes(
        assignment,
        reservation,
        profile.write_scopes,
        lease_seconds=60,
    )
    assert reservation.canonical_path == profile.canonical_workspace_path
    assert write.scope_keys == profile.write_scope_keys
    assert application.repository.list(AttemptRecord) == []
