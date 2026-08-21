from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest

from keeper.pass_b.application import PassBApplication
from keeper.pass_b.enums import (
    AssignmentState,
    ReviewState,
    WorkItemState,
    WorkflowState,
)
from keeper.pass_b.models import (
    AssignmentRecord,
    AttemptRecord,
    EvidenceBundleRecord,
    ReviewRecord,
    WorkflowRecord,
    WorkItemRecord,
)
from keeper.pass_b.orchestration import evidence_content_digest
from keeper.pass_b.pilot import PilotConversationExecutive
from tests.keeper.pass_b.test_authority_reservation import _launch_ready
from tests.keeper.pass_b.test_provider_lifecycle import _profile, _stack
from tests.keeper.pass_b.test_typed_evidence_input_binding import (
    _completed_typed_review,
)


def test_next_reserved_stage_runs_exact_dependency_ready_assignment(
    tmp_path: Path,
) -> None:
    application, assignment, _, reservation = _launch_ready(tmp_path)
    workflow = application.repository.get(
        WorkflowRecord, assignment.workflow_id
    )

    evidence = application.orchestration.run_next_reserved_stage(
        workflow.workflow_id,
        global_context={"project": workflow.project_id},
        task_context={"objective": "run one prepared lifecycle stage"},
    )

    assert evidence.assignment_id == assignment.assignment_id
    assert reservation.reserve_calls == 1
    attempts = application.repository.list(AttemptRecord)
    assert len(attempts) == 1
    assert attempts[0].state == "COMPLETED"
    assert application.repository.get(
        WorkflowRecord, workflow.workflow_id
    ).state == WorkflowState.ACTIVE


def test_incomplete_dependency_has_no_runnable_stage(
    tmp_path: Path,
) -> None:
    application, items, _, _ = _stack(tmp_path)
    workflow = application.repository.get(
        WorkflowRecord, items[0].workflow_id
    )

    with pytest.raises(PermissionError, match="no dependency-ready"):
        application.orchestration.run_next_reserved_stage(
            workflow.workflow_id,
            global_context={},
            task_context={},
        )

    assert application.repository.list(AttemptRecord) == []


def test_completed_workflow_cannot_launch(tmp_path: Path) -> None:
    application, assignment, _, reservation = _launch_ready(tmp_path)
    workflow = application.repository.get(
        WorkflowRecord, assignment.workflow_id
    )
    application.repository.replace(
        replace(
            workflow,
            state=WorkflowState.COMPLETED,
            revision=workflow.revision + 1,
        ),
        expected_revision=workflow.revision,
    )

    with pytest.raises(PermissionError, match="not active"):
        application.orchestration.run_next_reserved_stage(
            workflow.workflow_id,
            global_context={},
            task_context={},
        )

    assert reservation.reserve_calls == 0
    assert application.repository.list(AttemptRecord) == []


def test_concurrent_next_stage_has_one_external_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application, assignment, _, reservation = _launch_ready(tmp_path)
    workflow = application.repository.get(
        WorkflowRecord, assignment.workflow_id
    )
    original = application.repository.reserve_attempt
    barrier = Barrier(2)

    def synchronized_reserve(*args: object, **kwargs: object) -> None:
        barrier.wait(timeout=5)
        original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        application.repository, "reserve_attempt", synchronized_reserve
    )

    def run() -> EvidenceBundleRecord:
        return application.orchestration.run_next_reserved_stage(
            workflow.workflow_id,
            global_context={},
            task_context={"objective": "one winner"},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run) for _ in range(2)]
        outcomes: list[EvidenceBundleRecord] = []
        errors: list[BaseException] = []
        for future in futures:
            try:
                outcomes.append(future.result(timeout=10))
            except BaseException as error:
                errors.append(error)

    assert len(outcomes) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], PermissionError)
    assert reservation.reserve_calls == 1
    assert len(application.repository.list(AttemptRecord)) == 1


def test_dependency_completion_allows_next_prepared_stage(
    tmp_path: Path,
) -> None:
    application, items, grant_id, workspace_path = _stack(tmp_path)
    first = application.repository.get(
        WorkItemRecord, items[0].work_item_id
    )
    application.repository.replace(
        replace(
            first,
            state=WorkItemState.COMPLETED,
            revision=first.revision + 1,
        ),
        expected_revision=first.revision,
    )
    profile = _profile(application, items[1], workspace_path)
    assignment, _ = (
        application.orchestration.prepare_assignment_from_profile(
            profile.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )
    )
    workspace = application.orchestration.reserve_workspace(
        assignment,
        workspace_path,
        lease_seconds=300,
        branch="feature/lifecycle-next-stage",
        base_commit="a" * 40,
    )
    application.orchestration.reserve_writes(
        assignment,
        workspace,
        profile.write_scopes,
        lease_seconds=300,
    )
    assert application.orchestration.reserve_usage(
        assignment, workspace, profile.usage_amount
    )
    from keeper.pass_b.authority_reservation import (
        TestAuthorityAttemptReservation,
    )
    from keeper.pass_b.launch_authority import TestLaunchAuthority

    launch_authority = TestLaunchAuthority()
    reservation = TestAuthorityAttemptReservation(launch_authority)
    application.orchestration.launch_authority = launch_authority
    application.orchestration.authority_reservation = reservation

    evidence = application.orchestration.run_next_reserved_stage(
        items[1].workflow_id,
        global_context={},
        task_context={"objective": "run dependency successor"},
    )

    assert evidence.assignment_id == assignment.assignment_id
    assert reservation.reserve_calls == 1


def test_final_accepted_review_completes_workflow_atomically(
    tmp_path: Path,
) -> None:
    service, source, reviewer, _, evidence, _ = _completed_typed_review(
        tmp_path
    )
    producer = service.repository.get(
        AssignmentRecord, source.assignment_id
    )
    review = service.create_review(
        source.evidence_bundle_id,
        reviewer.assignment_id,
        evidence.evidence_bundle_id,
    )

    decided, _, work_item = service.decide_review(review.review_id)

    workflow = service.repository.get(
        WorkflowRecord, producer.workflow_id
    )
    assert decided.state == ReviewState.ACCEPTED
    assert work_item.state == WorkItemState.COMPLETED
    assert workflow.state == WorkflowState.COMPLETED
    assert service.repository.get(
        WorkItemRecord, reviewer.work_item_id
    ).state == WorkItemState.COMPLETED


def test_workflow_completion_failure_rolls_back_review_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, source, reviewer, _, evidence, _ = _completed_typed_review(
        tmp_path
    )
    producer = service.repository.get(
        AssignmentRecord, source.assignment_id
    )
    review = service.create_review(
        source.evidence_bundle_id,
        reviewer.assignment_id,
        evidence.evidence_bundle_id,
    )
    original = service.repository._replace

    def fail_workflow_replace(
        connection: Any, record: Any, expected_revision: int
    ) -> None:
        if isinstance(record, WorkflowRecord):
            raise RuntimeError("simulated terminal workflow write failure")
        original(connection, record, expected_revision)

    monkeypatch.setattr(
        service.repository, "_replace", fail_workflow_replace
    )

    with pytest.raises(RuntimeError, match="terminal workflow"):
        service.decide_review(review.review_id)

    assert service.repository.get(
        ReviewRecord, review.review_id
    ).state == ReviewState.PENDING
    assert service.repository.get(
        AssignmentRecord, producer.assignment_id
    ).state == AssignmentState.REVIEW_REQUIRED
    assert service.repository.get(
        AssignmentRecord, reviewer.assignment_id
    ).state == AssignmentState.REVIEW_REQUIRED
    assert service.repository.get(
        WorkItemRecord, producer.work_item_id
    ).state != WorkItemState.COMPLETED
    assert service.repository.get(
        WorkItemRecord, reviewer.work_item_id
    ).state != WorkItemState.COMPLETED


def test_intermediate_accepted_review_keeps_workflow_active(
    tmp_path: Path,
) -> None:
    service, source, reviewer, _, evidence, _ = _completed_typed_review(
        tmp_path
    )
    producer = service.repository.get(
        AssignmentRecord, source.assignment_id
    )
    service.create_work_item(
        project_id=producer.project_id,
        charter_id=producer.charter_id,
        charter_revision=producer.charter_revision,
        workflow_id=producer.workflow_id,
        title="remaining lifecycle stage",
        objective="remain incomplete",
        required_roles=(producer.role,),
    )
    review = service.create_review(
        source.evidence_bundle_id,
        reviewer.assignment_id,
        evidence.evidence_bundle_id,
    )

    service.decide_review(review.review_id)

    assert service.repository.get(
        WorkflowRecord, producer.workflow_id
    ).state == WorkflowState.ACTIVE


def test_repair_required_review_keeps_workflow_active(
    tmp_path: Path,
) -> None:
    service, source, reviewer, _, evidence, _ = _completed_typed_review(
        tmp_path
    )
    artifacts = [copy.deepcopy(item) for item in evidence.artifacts]
    for artifact in artifacts:
        if artifact.get("kind") == "structured-report":
            artifact["review_disposition"] = "REPAIR_REQUIRED"
            artifact["findings"] = [{"severity": "High"}]
        declaration = artifact.get("review_input_declaration")
        if isinstance(declaration, dict):
            declaration["review_disposition"] = "REPAIR_REQUIRED"
    changed = replace(
        evidence,
        artifacts=tuple(artifacts),
        content_digest=evidence_content_digest(
            project_id=evidence.project_id,
            assignment_id=evidence.assignment_id,
            attempt_id=evidence.attempt_id,
            producer_provider_id=evidence.producer_provider_id,
            producer_session_id=evidence.producer_session_id,
            schema_version=evidence.schema_version,
            artifacts=tuple(artifacts),
            summary=evidence.summary,
        ),
        revision=evidence.revision + 1,
    )
    service.repository.replace(
        changed, expected_revision=evidence.revision
    )
    producer = service.repository.get(
        AssignmentRecord, source.assignment_id
    )
    review = service.create_review(
        source.evidence_bundle_id,
        reviewer.assignment_id,
        changed.evidence_bundle_id,
    )

    decided, assignment, work_item = service.decide_review(
        review.review_id
    )

    assert decided.state == ReviewState.REPAIR_REQUIRED
    assert assignment.state == AssignmentState.REPAIR_REQUIRED
    assert work_item.state == WorkItemState.REPAIR_REQUIRED
    assert service.repository.get(
        WorkflowRecord, producer.workflow_id
    ).state == WorkflowState.ACTIVE
    assert service.repository.get(
        WorkItemRecord, reviewer.work_item_id
    ).state == WorkItemState.COMPLETED


def test_restart_reconciles_all_completed_active_workflow(
    tmp_path: Path,
) -> None:
    application, items, _, _ = _stack(tmp_path)
    workflow = application.repository.get(
        WorkflowRecord, items[0].workflow_id
    )
    for item in items:
        durable = application.repository.get(
            WorkItemRecord, item.work_item_id
        )
        application.repository.replace(
            replace(
                durable,
                state=WorkItemState.COMPLETED,
                revision=durable.revision + 1,
            ),
            expected_revision=durable.revision,
        )

    reopened = PassBApplication(
        tmp_path,
        executive=PilotConversationExecutive(tmp_path / "keeper.db"),
    )
    completed = reopened.orchestration.reconcile_workflow_completion(
        workflow.workflow_id
    )
    repeated = reopened.orchestration.reconcile_workflow_completion(
        workflow.workflow_id
    )

    assert completed.state == WorkflowState.COMPLETED
    assert repeated == completed


def test_incomplete_workflow_cannot_reconcile(tmp_path: Path) -> None:
    application, items, _, _ = _stack(tmp_path)

    with pytest.raises(PermissionError, match="before all durable work"):
        application.orchestration.reconcile_workflow_completion(
            items[0].workflow_id
        )

    assert application.repository.get(
        WorkflowRecord, items[0].workflow_id
    ).state == WorkflowState.ACTIVE


def test_stale_charter_rejects_next_stage_before_external_reservation(
    tmp_path: Path,
) -> None:
    application, assignment, _, reservation = _launch_ready(tmp_path)
    workflow = application.repository.get(
        WorkflowRecord, assignment.workflow_id
    )
    application.orchestration.project_status = lambda project_id: {
        "project_summary": {
            "project_id": project_id,
            "state": "ACTIVE",
            "active_charter_id": "new-charter",
            "active_charter_revision": 2,
        },
        "active_charter": {
            "project_id": project_id,
            "charter_id": "new-charter",
            "revision": 2,
            "status": "ACTIVE",
            "founder_approval_record_id": "approval",
            "founder_approval_identity": "founder",
            "founder_authorization_capability_digest": "a" * 64,
            "authority_envelope": {},
        },
    }

    with pytest.raises(PermissionError, match="current"):
        application.orchestration.run_next_reserved_stage(
            workflow.workflow_id,
            global_context={},
            task_context={},
        )

    assert reservation.reserve_calls == 0
    assert application.repository.list(AttemptRecord) == []
