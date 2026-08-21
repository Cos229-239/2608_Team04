from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
import threading

from keeper.pass_b.enums import (
    AssignmentState,
    AttemptState,
    EvidenceState,
    ReservationState,
)
from keeper.pass_b.models import (
    AttemptRecord,
    EvidenceBundleRecord,
    WorkItemRecord,
    WorkspaceReservationRecord,
    WriteReservationRecord,
)
from tests.keeper.pass_b.test_orchestration import (
    _assignment,
    _authorize,
    _stack,
)


def test_workspace_release_atomically_releases_write_claims(
    tmp_path: Path,
) -> None:
    (
        repository,
        service,
        clock,
        provider,
        account,
        _,
        sessions,
        _,
    ) = _stack(tmp_path)
    first = _assignment(service, provider, account, sessions[0])
    path = tmp_path / "workspace"
    path.mkdir()
    workspace = service.reserve_workspace(
        first,
        path,
        lease_seconds=300,
        branch="test/first",
        base_commit="abc",
    )
    write = service.reserve_writes(
        first, workspace, ("keeper/pass_b",), lease_seconds=300
    )
    released = repository.release_workspace(
        workspace.workspace_reservation_id,
        workspace.owner_token,
        clock().isoformat(),
    )

    assert released.state == ReservationState.RELEASED
    assert repository.get(
        WriteReservationRecord, write.write_reservation_id
    ).state == ReservationState.RELEASED

    second = _assignment(service, provider, account, sessions[1])
    replacement_workspace = service.reserve_workspace(
        second,
        path,
        lease_seconds=300,
        branch="test/second",
        base_commit="abc",
    )
    replacement_write = service.reserve_writes(
        second,
        replacement_workspace,
        ("keeper/pass_b",),
        lease_seconds=300,
    )
    assert replacement_write.state == ReservationState.ACTIVE


def test_uncertain_recovery_updates_durable_workspace_and_write_records(
    tmp_path: Path,
) -> None:
    (
        repository,
        service,
        clock,
        provider,
        account,
        _,
        sessions,
        _,
    ) = _stack(tmp_path)
    assignment = _assignment(service, provider, account, sessions[0])
    path = tmp_path / "workspace"
    path.mkdir()
    workspace = service.reserve_workspace(
        assignment,
        path,
        lease_seconds=300,
        branch="test/uncertain",
        base_commit="abc",
    )
    write = service.reserve_writes(
        assignment, workspace, ("keeper/pass_b",), lease_seconds=300
    )
    service.reserve_usage(assignment, workspace, 1)
    authority_id = _authorize(
        service, assignment, workspace, "authority-uncertain"
    )

    def interrupt_after_claim() -> None:
        raise RuntimeError("simulated interruption")

    try:
        service.run_assignment(
            assignment.assignment_id,
            path,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
            after_launch_claim=interrupt_after_claim,
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("simulated interruption did not occur")

    repository.recover_interrupted_attempts(clock().isoformat())
    assert repository.get(
        WorkspaceReservationRecord, workspace.workspace_reservation_id
    ).state == ReservationState.UNCERTAIN
    assert repository.get(
        WriteReservationRecord, write.write_reservation_id
    ).state == ReservationState.UNCERTAIN


def test_evidence_digest_is_bound_to_stored_payload(tmp_path: Path) -> None:
    (
        repository,
        service,
        clock,
        provider,
        account,
        _,
        sessions,
        _,
    ) = _stack(tmp_path)
    assignment = _assignment(service, provider, account, sessions[0])
    path = tmp_path / "workspace"
    path.mkdir()
    workspace = service.reserve_workspace(
        assignment,
        path,
        lease_seconds=300,
        branch="test/evidence-digest",
        base_commit="abc",
    )
    service.reserve_writes(
        assignment, workspace, ("keeper/pass_b",), lease_seconds=300
    )
    service.reserve_usage(assignment, workspace, 1)
    authority_id = _authorize(
        service, assignment, workspace, "authority-evidence"
    )
    evidence = service.run_assignment(
        assignment.assignment_id,
        path,
        authority_attempt_id=authority_id,
        global_context={},
        task_context={},
    )
    repository.replace(
        replace(
            evidence,
            summary="tampered after provider translation",
            updated_at=clock().isoformat(),
            revision=evidence.revision + 1,
        ),
        expected_revision=evidence.revision,
    )

    validated = service.validate_evidence(
        evidence.evidence_bundle_id, path
    )
    assert isinstance(validated, EvidenceBundleRecord)
    assert validated.state == EvidenceState.REJECTED
    assert "digest" in validated.validation_errors[0]


def test_concurrent_cancellation_claim_emits_one_external_effect(
    tmp_path: Path,
) -> None:
    (
        repository,
        service,
        clock,
        provider,
        account,
        _,
        sessions,
        adapter,
    ) = _stack(tmp_path)
    assignment = _assignment(service, provider, account, sessions[0])
    path = tmp_path / "workspace"
    path.mkdir()
    workspace = service.reserve_workspace(
        assignment,
        path,
        lease_seconds=300,
        branch="test/cancel",
        base_commit="abc",
    )
    service.reserve_writes(
        assignment, workspace, ("keeper/pass_b",), lease_seconds=300
    )
    service.reserve_usage(assignment, workspace, 1)
    attempt = AttemptRecord(
        attempt_id="cancel-attempt",
        assignment_id=assignment.assignment_id,
        authority_attempt_id="authority-cancel",
        launch_token="cancel-launch",
        state=AttemptState.RESERVED,
        external_execution_id=None,
        side_effect_class="REVERSIBLE_WORKSPACE_WRITE",
        started_at=None,
        finished_at=None,
        last_error=None,
        created_at=clock().isoformat(),
        updated_at=clock().isoformat(),
        revision=1,
        workspace_reservation_id=workspace.workspace_reservation_id,
        usage_reservation_id=str(
            repository.usage_reservations(
                assignment.assignment_id
            )[0]["reservation_id"]
        ),
        launch_plan_digest="cancel-test-plan",
        session_slot_claimed=True,
    )
    repository.reserve_attempt(attempt)
    repository.claim_launch(attempt.attempt_id, clock().isoformat())
    repository.mark_running(
        attempt.attempt_id, "external-cancel", clock().isoformat()
    )
    barrier = threading.Barrier(3)
    outcomes: list[str] = []
    guard = threading.Lock()

    def cancel() -> None:
        barrier.wait()
        try:
            service.cancel_assignment(assignment.assignment_id)
        except PermissionError:
            outcome = "blocked"
        else:
            outcome = "canceled"
        with guard:
            outcomes.append(outcome)

    threads = [threading.Thread(target=cancel) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["blocked", "canceled"]
    assert adapter.health()["canceled"] == 1
    assert repository.get(
        AttemptRecord, attempt.attempt_id
    ).state == AttemptState.CANCELED
    assert repository.get(
        type(assignment), assignment.assignment_id
    ).state == AssignmentState.CANCELED
    assert repository.usage_reservations(
        assignment.assignment_id
    )[0]["state"] == "CONSUMED"


def test_review_repair_is_transactional_and_retry_is_explicit(
    tmp_path: Path,
) -> None:
    (
        repository,
        service,
        _,
        provider,
        account,
        _,
        sessions,
        adapter,
    ) = _stack(tmp_path)
    producer = _assignment(service, provider, account, sessions[0])
    path = tmp_path / "workspace"
    path.mkdir()
    workspace = service.reserve_workspace(
        producer,
        path,
        lease_seconds=300,
        branch="test/repair",
        base_commit="abc",
    )
    service.reserve_writes(
        producer, workspace, ("keeper/pass_b",), lease_seconds=300
    )
    service.reserve_usage(producer, workspace, 1)
    producer_authority_id = _authorize(
        service, producer, workspace, "authority-repair"
    )
    evidence = service.run_assignment(
        producer.assignment_id,
        path,
        authority_attempt_id=producer_authority_id,
        global_context={},
        task_context={},
    )
    evidence = service.validate_evidence(
        evidence.evidence_bundle_id, path
    )
    reviewer = _assignment(
        service,
        provider,
        account,
        sessions[1],
        role="REVIEWER",
        work_item=repository.get(
            WorkItemRecord, producer.work_item_id
        ),
        review_of_assignment_id=producer.assignment_id,
    )
    review_path = tmp_path / "review-workspace"
    review_path.mkdir()
    review_workspace = service.reserve_workspace(
        reviewer,
        review_path,
        lease_seconds=300,
        branch="test/repair-review",
        base_commit="abc",
    )
    service.reserve_usage(reviewer, review_workspace, 1)
    adapter.set_review_outcome(
        "REPAIR_REQUIRED",
        (
            {
                "severity": "MEDIUM",
                "summary": "bounded repair required",
            },
        ),
    )
    reviewer_authority_id = _authorize(
        service,
        reviewer,
        review_workspace,
        "authority-repair-review",
    )
    reference = service.create_remote_evidence_reference(
        reviewer.assignment_id,
        source_identity="keeper-evidence:repair-review",
        sha256=hashlib.sha256(b"repair-review").hexdigest(),
        size_bytes=len(b"repair-review"),
        source_evidence_bundle_id=evidence.evidence_bundle_id,
    )
    reviewer_evidence = service.run_assignment(
        reviewer.assignment_id,
        review_path,
        authority_attempt_id=reviewer_authority_id,
        global_context={},
        task_context={},
        evidence_reference_ids=(reference.evidence_reference_id,),
    )
    reviewer_evidence = service.validate_evidence(
        reviewer_evidence.evidence_bundle_id,
        review_path,
    )
    review = service.create_review(
        evidence.evidence_bundle_id,
        reviewer.assignment_id,
        reviewer_evidence.evidence_bundle_id,
    )
    decided, original, work_item = service.decide_review(review.review_id)

    assert decided.state == "REPAIR_REQUIRED"
    assert original.state == "REPAIR_REQUIRED"
    assert work_item.state == "REPAIR_REQUIRED"
    assert repository.get(
        WorkItemRecord, original.work_item_id
    ).state == "REPAIR_REQUIRED"

    repair = service.create_repair_assignment(review.review_id)
    assert repair.assignment_id != original.assignment_id
    assert repair.state == "READY"
    assert repair.usage_policy["repair_of_assignment_id"] == (
        original.assignment_id
    )
    assert repair.usage_policy["repair_review_id"] == review.review_id
    assert repair.usage_policy["repair_ordinal"] == 1
