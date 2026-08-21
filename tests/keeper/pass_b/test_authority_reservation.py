from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest

from keeper.pass_b.application import PassBApplication
from keeper.pass_b.authority_reservation import (
    PreparedAuthorityReservation,
    TestAuthorityAttemptReservation,
)
from keeper.pass_b.enums import (
    AssignmentState,
    AttemptState,
    ReservationState,
)
from keeper.pass_b.launch_authority import TestLaunchAuthority
from keeper.pass_b.models import (
    AssignmentRecord,
    AttemptRecord,
    ExecutionProfileRecord,
    ProviderRecord,
    ProviderSelectionRecord,
    ProviderSessionRecord,
    WorkspaceReservationRecord,
)
from tests.keeper.pass_b.test_provider_lifecycle import _profile, _stack


class _SideEffectThenExceptionReservation:
    def __init__(self, delegate: TestAuthorityAttemptReservation) -> None:
        self.delegate = delegate

    def prepare(self, *args: object, **kwargs: object) -> PreparedAuthorityReservation:
        return self.delegate.prepare(*args, **kwargs)  # type: ignore[arg-type]

    def reserve(self, prepared: PreparedAuthorityReservation) -> None:
        self.delegate.reserve(prepared)
        raise RuntimeError("simulated response loss after reservation")


class _SelectionMutationReservation:
    def __init__(
        self,
        application: PassBApplication,
        delegate: TestAuthorityAttemptReservation,
    ) -> None:
        self.application = application
        self.delegate = delegate

    def prepare(
        self, *args: object, **kwargs: object
    ) -> PreparedAuthorityReservation:
        prepared = self.delegate.prepare(*args, **kwargs)  # type: ignore[arg-type]
        selection = args[4]
        assert isinstance(selection, ProviderSelectionRecord)
        self.application.repository.replace(
            replace(
                selection,
                updated_at="2026-07-31T12:45:00+00:00",
                revision=selection.revision + 1,
            ),
            expected_revision=selection.revision,
        )
        return prepared

    def reserve(self, prepared: PreparedAuthorityReservation) -> None:
        self.delegate.reserve(prepared)


class _ProviderMutationReservation:
    def __init__(
        self,
        application: PassBApplication,
        delegate: TestAuthorityAttemptReservation,
    ) -> None:
        self.application = application
        self.delegate = delegate

    def prepare(
        self, *args: object, **kwargs: object
    ) -> PreparedAuthorityReservation:
        prepared = self.delegate.prepare(*args, **kwargs)  # type: ignore[arg-type]
        provider = args[5]
        assert isinstance(provider, ProviderRecord)
        self.application.repository.replace(
            replace(
                provider,
                health="UNAVAILABLE",
                updated_at="2026-07-31T12:46:00+00:00",
                revision=provider.revision + 1,
            ),
            expected_revision=provider.revision,
        )
        return prepared

    def reserve(self, prepared: PreparedAuthorityReservation) -> None:
        self.delegate.reserve(prepared)


class _ReleaseDuringReservation:
    def __init__(
        self,
        application: PassBApplication,
        assignment: AssignmentRecord,
        delegate: TestAuthorityAttemptReservation,
    ) -> None:
        self.application = application
        self.assignment = assignment
        self.delegate = delegate
        self.release_rejected = False

    def prepare(
        self, *args: object, **kwargs: object
    ) -> PreparedAuthorityReservation:
        return self.delegate.prepare(*args, **kwargs)  # type: ignore[arg-type]

    def reserve(self, prepared: PreparedAuthorityReservation) -> None:
        workspace = self.application.repository.list(
            WorkspaceReservationRecord,
            project_id=self.assignment.project_id,
        )[0]
        try:
            self.application.repository.release_workspace(
                workspace.workspace_reservation_id,
                workspace.owner_token,
                "2026-07-31T12:47:00+00:00",
            )
        except PermissionError:
            self.release_rejected = True
        else:
            raise AssertionError("active launch workspace was released")
        self.delegate.reserve(prepared)


def _launch_ready(
    root: Path,
) -> tuple[
    PassBApplication,
    AssignmentRecord,
    Path,
    TestAuthorityAttemptReservation,
]:
    application, items, grant_id, workspace_path = _stack(root)
    profile = _profile(application, items[0], workspace_path)
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
        branch="feature/authority-reservation-test",
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
    launch_authority = TestLaunchAuthority()
    reservation = TestAuthorityAttemptReservation(launch_authority)
    application.orchestration.launch_authority = launch_authority
    application.orchestration.authority_reservation = reservation
    return application, assignment, workspace_path, reservation


def test_prepared_assignment_reserves_then_executes_once(
    tmp_path: Path,
) -> None:
    application, assignment, workspace_path, reservation = _launch_ready(
        tmp_path
    )

    evidence = application.orchestration.run_prepared_assignment(
        assignment.assignment_id,
        workspace_path,
        global_context={"project": assignment.project_id},
        task_context={"objective": "produce deterministic evidence"},
    )

    attempts = application.repository.list(AttemptRecord)
    assert len(attempts) == 1
    attempt = attempts[0]
    assert attempt.state == AttemptState.COMPLETED
    assert attempt.authority_reservation_state == "AUTHORIZED"
    assert len(attempt.authority_reservation_plan_digest) == 64
    assert evidence.attempt_id == attempt.attempt_id
    assert reservation.reserve_calls == 1
    assert application.repository.launch_claim(attempt.attempt_id)[
        "state"
    ] == AttemptState.COMPLETED


def test_missing_usage_rejects_before_external_reservation(
    tmp_path: Path,
) -> None:
    application, items, grant_id, workspace_path = _stack(tmp_path)
    profile = _profile(application, items[0], workspace_path)
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
        branch="feature/no-usage",
        base_commit="a" * 40,
    )
    application.orchestration.reserve_writes(
        assignment,
        workspace,
        profile.write_scopes,
        lease_seconds=300,
    )
    launch_authority = TestLaunchAuthority()
    reservation = TestAuthorityAttemptReservation(launch_authority)
    application.orchestration.launch_authority = launch_authority
    application.orchestration.authority_reservation = reservation

    with pytest.raises(PermissionError, match="usage reservation"):
        application.orchestration.run_prepared_assignment(
            assignment.assignment_id,
            workspace_path,
            global_context={},
            task_context={},
        )

    assert reservation.reserve_calls == 0
    assert application.repository.list(AttemptRecord) == []


def test_full_session_rejects_before_external_reservation(
    tmp_path: Path,
) -> None:
    application, assignment, workspace_path, reservation = _launch_ready(
        tmp_path
    )
    session = application.repository.get(
        ProviderSessionRecord, assignment.session_id
    )
    application.repository.replace(
        replace(
            session,
            active_assignments=session.concurrency_limit,
            state="BUSY",
            revision=session.revision + 1,
        ),
        expected_revision=session.revision,
    )

    with pytest.raises(PermissionError, match="launch-ready"):
        application.orchestration.run_prepared_assignment(
            assignment.assignment_id,
            workspace_path,
            global_context={},
            task_context={},
        )

    assert reservation.reserve_calls == 0
    assert application.repository.list(AttemptRecord) == []


def test_changed_selection_rejects_before_external_reservation(
    tmp_path: Path,
) -> None:
    application, assignment, workspace_path, reservation = _launch_ready(
        tmp_path
    )
    application.orchestration.authority_reservation = (
        _SelectionMutationReservation(application, reservation)
    )

    with pytest.raises(
        PermissionError,
        match="profile, provider selection, or provider changed",
    ):
        application.orchestration.run_prepared_assignment(
            assignment.assignment_id,
            workspace_path,
            global_context={},
            task_context={},
        )

    assert reservation.reserve_calls == 0
    assert application.repository.list(AttemptRecord) == []
    session = application.repository.get(
        ProviderSessionRecord, assignment.session_id
    )
    assert session.active_assignments == 0


def test_changed_provider_rejects_before_external_reservation(
    tmp_path: Path,
) -> None:
    application, assignment, workspace_path, reservation = _launch_ready(
        tmp_path
    )
    application.orchestration.authority_reservation = (
        _ProviderMutationReservation(application, reservation)
    )

    with pytest.raises(
        PermissionError,
        match="profile, provider selection, or provider changed",
    ):
        application.orchestration.run_prepared_assignment(
            assignment.assignment_id,
            workspace_path,
            global_context={},
            task_context={},
        )

    assert reservation.reserve_calls == 0
    assert application.repository.list(AttemptRecord) == []
    session = application.repository.get(
        ProviderSessionRecord, assignment.session_id
    )
    assert session.active_assignments == 0


def test_workspace_release_after_local_claim_rejects_and_launch_completes(
    tmp_path: Path,
) -> None:
    application, assignment, workspace_path, reservation = _launch_ready(
        tmp_path
    )
    racing = _ReleaseDuringReservation(
        application, assignment, reservation
    )
    application.orchestration.authority_reservation = racing

    evidence = application.orchestration.run_prepared_assignment(
        assignment.assignment_id,
        workspace_path,
        global_context={},
        task_context={},
    )

    assert racing.release_rejected
    assert reservation.reserve_calls == 1
    assert evidence.attempt_id == application.repository.list(
        AttemptRecord
    )[0].attempt_id
    workspace = application.repository.list(
        WorkspaceReservationRecord,
        project_id=assignment.project_id,
    )[0]
    assert workspace.state == ReservationState.ACTIVE


def test_under_reserved_usage_rejects_before_external_reservation(
    tmp_path: Path,
) -> None:
    application, items, grant_id, workspace_path = _stack(tmp_path)
    profile = _profile(application, items[0], workspace_path)
    assert profile.usage_amount == 2
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
        branch="feature/under-reserved-usage",
        base_commit="a" * 40,
    )
    application.orchestration.reserve_writes(
        assignment,
        workspace,
        profile.write_scopes,
        lease_seconds=300,
    )
    assert application.orchestration.reserve_usage(
        assignment, workspace, 1
    )
    launch_authority = TestLaunchAuthority()
    reservation = TestAuthorityAttemptReservation(launch_authority)
    application.orchestration.launch_authority = launch_authority
    application.orchestration.authority_reservation = reservation

    with pytest.raises(
        PermissionError,
        match="usage reservation amount is not exact",
    ):
        application.orchestration.run_prepared_assignment(
            assignment.assignment_id,
            workspace_path,
            global_context={},
            task_context={},
        )

    assert reservation.reserve_calls == 0
    assert application.repository.list(AttemptRecord) == []
    session = application.repository.get(
        ProviderSessionRecord, assignment.session_id
    )
    assert session.active_assignments == 0


def test_side_effect_then_exception_is_durably_uncertain(
    tmp_path: Path,
) -> None:
    application, assignment, workspace_path, reservation = _launch_ready(
        tmp_path
    )
    application.orchestration.authority_reservation = (
        _SideEffectThenExceptionReservation(reservation)
    )

    with pytest.raises(RuntimeError, match="response loss"):
        application.orchestration.run_prepared_assignment(
            assignment.assignment_id,
            workspace_path,
            global_context={},
            task_context={},
        )

    attempt = application.repository.list(AttemptRecord)[0]
    current_assignment = application.repository.get(
        AssignmentRecord, assignment.assignment_id
    )
    session = application.repository.get(
        ProviderSessionRecord, assignment.session_id
    )
    workspace = application.repository.list(
        WorkspaceReservationRecord,
        project_id=assignment.project_id,
    )[0]
    assert attempt.state == AttemptState.UNCERTAIN
    assert attempt.authority_reservation_state == "RESERVATION_IN_FLIGHT"
    assert current_assignment.state == AssignmentState.UNCERTAIN
    assert session.active_assignments == 1
    assert workspace.state == ReservationState.UNCERTAIN
    assert application.repository.usage_reservations(
        assignment.assignment_id
    )[0]["state"] == "ACTIVE"
    assert application.repository.launch_claim(attempt.attempt_id)[
        "state"
    ] == AttemptState.UNCERTAIN
    assert reservation.reserve_calls == 1

    with pytest.raises(PermissionError):
        application.orchestration.run_prepared_assignment(
            assignment.assignment_id,
            workspace_path,
            global_context={},
            task_context={},
        )
    assert reservation.reserve_calls == 1


def test_restart_marks_in_flight_reserved_attempt_uncertain(
    tmp_path: Path,
) -> None:
    application, assignment, _, reservation = _launch_ready(tmp_path)
    workflow, work_item, current = (
        application.repository.assignment_launch_binding(
            assignment.assignment_id
        )
    )
    profile_id = str(current.usage_policy["execution_profile_id"])
    selection_id = str(current.usage_policy["provider_selection_id"])
    profile = application.repository.get(
        ExecutionProfileRecord,
        profile_id,
    )
    selection = application.repository.get(
        ProviderSelectionRecord,
        selection_id,
    )
    provider = application.repository.get(
        ProviderRecord,
        current.provider_id,
    )
    workspace = application.repository.list(
        WorkspaceReservationRecord, project_id=current.project_id
    )[0]
    prepared = reservation.prepare(
        workflow,
        work_item,
        current,
        profile,
        selection,
        provider,
        workspace,
        reviewer_attempt_id="restart-attempt",
    )
    usage = application.repository.usage_reservations(
        current.assignment_id
    )[0]
    attempt = AttemptRecord(
        attempt_id="restart-attempt",
        assignment_id=current.assignment_id,
        authority_attempt_id=prepared.authority_attempt_id,
        launch_token="pending:" + prepared.reservation_plan_digest,
        state=AttemptState.RESERVED,
        external_execution_id=None,
        side_effect_class="REVERSIBLE_WORKSPACE_WRITE",
        started_at=None,
        finished_at=None,
        last_error=None,
        created_at=current.updated_at,
        updated_at=current.updated_at,
        revision=1,
        workspace_reservation_id=workspace.workspace_reservation_id,
        usage_reservation_id=str(usage["reservation_id"]),
        launch_plan_digest=prepared.reservation_plan_digest,
        session_slot_claimed=True,
        authority_reservation_state="LOCAL_PREPARED",
        authority_reservation_plan_digest=prepared.reservation_plan_digest,
    )
    application.repository.reserve_attempt(
        attempt,
        expected_workflow=workflow,
        expected_work_item=work_item,
        expected_assignment=current,
    )
    application.repository.mark_authority_reservation_in_flight(
        attempt.attempt_id,
        prepared.reservation_plan_digest,
        current.updated_at,
    )

    recovered = application.repository.recover_interrupted_attempts(
        "2026-07-31T12:30:00+00:00"
    )

    assert recovered == {"prelaunch_released": 0, "uncertain": 1}
    assert application.repository.get(
        AttemptRecord, attempt.attempt_id
    ).state == AttemptState.UNCERTAIN


def test_two_contenders_make_one_external_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application, assignment, workspace_path, reservation = _launch_ready(
        tmp_path
    )
    original = application.repository.reserve_attempt
    barrier = Barrier(2)

    def synchronized(
        attempt: AttemptRecord,
        **kwargs: object,
    ) -> None:
        barrier.wait(timeout=5)
        original(attempt, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        application.repository, "reserve_attempt", synchronized
    )

    def run() -> str:
        try:
            application.orchestration.run_prepared_assignment(
                assignment.assignment_id,
                workspace_path,
                global_context={},
                task_context={},
            )
        except PermissionError:
            return "REJECTED"
        return "COMPLETED"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _: run(), range(2)))

    assert sorted(results) == ["COMPLETED", "REJECTED"]
    assert reservation.reserve_calls == 1
    assert len(application.repository.list(AttemptRecord)) == 1
