from __future__ import annotations

import threading
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from keeper.app.storage import KeeperStore
from keeper.pass_b.enums import (
    AssignmentRole,
    AssignmentState,
    AttemptState,
    CostMode,
    HealthState,
    ProviderClassification,
    ProviderSessionState,
    ReservationState,
    SessionModel,
)
from keeper.pass_b.models import (
    AssignmentRecord,
    AttemptRecord,
    ProviderAccountRecord,
    ProviderRecord,
    ProviderSessionRecord,
    ResumeCheckpointRecord,
    UsagePoolRecord,
    WorkflowRecord,
    WorkItemRecord,
    WorkspaceReservationRecord,
)
from keeper.pass_b.launch_authority import TestLaunchAuthority
from keeper.pass_b.orchestration import OrchestrationService
from keeper.pass_b.providers import LocalMockAdapter
from keeper.pass_b.repository import PassBRepository
from keeper.pass_b.usage_authority import TestUsageResetVerifier


class FixedClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **values: float) -> None:
        self.value += timedelta(**values)


def _stack(
    tmp_path: Path,
    *,
    provider_id: str = "provider-a",
    capacity: float = 10,
    sessions: int = 2,
) -> tuple[
    PassBRepository,
    OrchestrationService,
    FixedClock,
    ProviderRecord,
    ProviderAccountRecord,
    UsagePoolRecord,
    tuple[ProviderSessionRecord, ...],
    LocalMockAdapter,
]:
    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    repository = PassBRepository(store)
    clock = FixedClock()
    launch_authority = TestLaunchAuthority()
    usage_reset_verifier = TestUsageResetVerifier()
    service = OrchestrationService(
        repository,
        clock=clock,
        launch_authority=launch_authority,
        usage_reset_verifier=usage_reset_verifier,
    )
    now = clock().isoformat()
    account_id = f"{provider_id}-account"
    pool_id = f"{provider_id}-pool"
    adapter = LocalMockAdapter(provider_id)
    descriptor = adapter.descriptor()
    provider = ProviderRecord(
        provider_id=provider_id,
        identity=provider_id,
        display_name=provider_id,
        classification=ProviderClassification.LOCAL,
        adapter_kind="test-mock",
        capabilities=tuple(
            role.value.casefold() for role in AssignmentRole
        )
        + descriptor.capabilities,
        session_model=SessionModel.RESUMABLE,
        usage_pool_strategy="shared-account-window",
        concurrency_limit=descriptor.concurrency_limit,
        cost_mode=CostMode.FREE,
        authentication_ready=True,
        tool_support=("filesystem",),
        workspace_support=("isolated-worktree", "read-only"),
        cancellation_support=True,
        resume_support=True,
        evidence_format="keeper-evidence-v1",
        health=HealthState.READY,
        created_at=now,
        updated_at=now,
        revision=1,
        authority_registration_id=f"test-registration:{provider_id}",
    )
    account = ProviderAccountRecord(
        account_id=account_id,
        provider_id=provider_id,
        identity=f"{provider_id}:{account_id}",
        display_name=account_id,
        usage_pool_id=pool_id,
        cost_mode=CostMode.FREE,
        privacy_classification="LOCAL",
        authentication_ready=True,
        enabled=True,
        created_at=now,
        updated_at=now,
        revision=1,
    )
    pool = UsagePoolRecord(
        pool_id=pool_id,
        provider_id=provider_id,
        account_id=account_id,
        identity=descriptor.usage_pool_identity,
        limit_type="MEASURED_WINDOW",
        capacity=capacity,
        consumed=0,
        reserved=0,
        remaining=capacity,
        reset_at=(clock() + timedelta(hours=1)).isoformat(),
        observation_source="test",
        confidence="HIGH",
        exhausted=False,
        last_observed_at=now,
        created_at=now,
        updated_at=now,
        revision=1,
    )
    provider_sessions = tuple(
        ProviderSessionRecord(
            session_id=f"{provider_id}-session-{index}",
            provider_id=provider_id,
            account_id=account_id,
            model_id=descriptor.model_identity,
            external_session_id=None,
            state=ProviderSessionState.READY,
            concurrency_limit=1,
            active_assignments=0,
            supports_resume=True,
            resume_token_digest=None,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
            revision=1,
        )
        for index in range(1, sessions + 1)
    )
    service.register_provider(
        provider, account, pool, provider_sessions, adapter
    )
    return (
        repository,
        service,
        clock,
        provider,
        account,
        pool,
        provider_sessions,
        adapter,
    )


def _authorize(
    service: OrchestrationService,
    assignment: AssignmentRecord,
    workspace: WorkspaceReservationRecord,
    authority_attempt_id: str,
) -> str:
    authority = service.launch_authority
    assert isinstance(authority, TestLaunchAuthority)
    provider = service.repository.get(
        ProviderRecord, assignment.provider_id
    )
    workflow, work_item, durable_assignment = (
        service.repository.assignment_launch_binding(
            assignment.assignment_id
        )
    )
    return authority.reserve(
        workflow,
        work_item,
        durable_assignment,
        provider,
        workspace,
        authority_attempt_id,
    )


def _observe_reset(
    service: OrchestrationService,
    pool: UsagePoolRecord,
    clock: FixedClock,
) -> UsagePoolRecord:
    verifier = service.usage_reset_verifier
    assert isinstance(verifier, TestUsageResetVerifier)
    current = service.repository.get(UsagePoolRecord, pool.pool_id)
    sessions = tuple(
        item
        for item in service.repository.list(ProviderSessionRecord)
        if item.provider_id == current.provider_id
        and item.account_id == current.account_id
    )
    observation = verifier.issue(
        current,
        reset_at=current.reset_at or pool.reset_at or "",
        observed_at=clock().isoformat(),
        model_ids=tuple(sorted({item.model_id for item in sessions})),
        session_ids=tuple(sorted(item.session_id for item in sessions)),
    )
    return service.observe_usage_reset(observation)


def _assignment(
    service: OrchestrationService,
    provider: ProviderRecord,
    account: ProviderAccountRecord,
    session: ProviderSessionRecord,
    *,
    role: str = AssignmentRole.IMPLEMENTER,
    workspace_id: str | None = None,
    work_item: WorkItemRecord | None = None,
    review_of_assignment_id: str | None = None,
) -> AssignmentRecord:
    if work_item is None:
        workflow = service.repository.optional(
            WorkflowRecord, "workflow-1"
        )
        if workflow is None:
            workflow = service.create_workflow(
                workflow_id="workflow-1",
                project_id="project-1",
                charter_id="charter-1",
                charter_revision=1,
                strategy="test-bounded",
                authority_envelope_digest="a" * 64,
            )
        work_item = service.create_work_item(
            project_id="project-1",
            charter_id="charter-1",
            charter_revision=1,
            workflow_id=workflow.workflow_id,
            title=f"{role} work",
            objective="Produce bounded evidence",
            required_roles=(role,),
        )
    return service.create_assignment(
        work_item=work_item,
        provider_id=provider.provider_id,
        account_id=account.account_id,
        session_id=session.session_id,
        role=role,
        model_id=session.model_id,
        workspace_id=workspace_id or uuid.uuid4().hex,
        authority_envelope_digest="a" * 64,
        expected_evidence=("structured-report",),
        usage_policy={
            "reservation_required": True,
            "paid_fallback": False,
            **(
                {"review_of_assignment_id": review_of_assignment_id}
                if review_of_assignment_id is not None
                else {}
            ),
        },
        independence_key=f"{provider.provider_id}:{session.session_id}",
    )


def test_multiple_sessions_share_provider_and_usage_pool(tmp_path: Path) -> None:
    (
        repository,
        service,
        _,
        provider,
        account,
        pool,
        sessions,
        _,
    ) = _stack(tmp_path)
    first = _assignment(service, provider, account, sessions[0])
    second = _assignment(service, provider, account, sessions[1])
    assert first.provider_id == second.provider_id
    assert first.session_id != second.session_id
    assert repository.get(
        ProviderAccountRecord, first.account_id
    ).usage_pool_id == pool.pool_id


def test_usage_exhaustion_waits_and_resumes_from_checkpoint(
    tmp_path: Path,
) -> None:
    (
        repository,
        service,
        clock,
        provider,
        account,
        pool,
        sessions,
        _,
    ) = _stack(tmp_path, capacity=1)
    assignment = _assignment(service, provider, account, sessions[0])
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()
    workspace = service.reserve_workspace(
        assignment,
        workspace_path,
        lease_seconds=300,
        branch="test/usage",
        base_commit="abc",
    )
    with pytest.raises(ValueError, match="finite"):
        service.reserve_usage(assignment, workspace, float("nan"))
    assert not service.reserve_usage(assignment, workspace, 2)
    waiting = repository.get(AssignmentRecord, assignment.assignment_id)
    assert waiting.state == AssignmentState.WAITING_FOR_USAGE_RESET
    checkpoints = repository.list(ResumeCheckpointRecord)
    assert len(checkpoints) == 1
    clock.advance(hours=2)
    _observe_reset(service, pool, clock)
    resumed = service.resume_after_reset(
        assignment.assignment_id,
        checkpoints[0].resume_checkpoint_id,
    )
    assert resumed.state == AssignmentState.READY
    assert repository.get(
        UsagePoolRecord, pool.pool_id
    ).exhausted is False


def test_launch_is_durable_and_completion_cannot_duplicate(
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
    assignment = _assignment(service, provider, account, sessions[0])
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()
    workspace = service.reserve_workspace(
        assignment,
        workspace_path,
        lease_seconds=300,
        branch="test/launch",
        base_commit="abc",
    )
    service.reserve_writes(
        assignment, workspace, ("keeper/pass_b",), lease_seconds=300
    )
    assert service.reserve_usage(assignment, workspace, 1)
    authority_id = _authorize(
        service, assignment, workspace, "authority-1"
    )
    evidence = service.run_assignment(
        assignment.assignment_id,
        workspace_path,
        authority_attempt_id=authority_id,
        global_context={"project": "test"},
        task_context={"objective": "test"},
    )
    assert evidence.state == "UNTRUSTED"
    assert adapter.health()["launched"] == 1
    assert repository.get(
        AssignmentRecord, assignment.assignment_id
    ).state == AssignmentState.REVIEW_REQUIRED
    with pytest.raises(PermissionError):
        _authorize(service, assignment, workspace, "authority-2")
        service.run_assignment(
            assignment.assignment_id,
            workspace_path,
            authority_attempt_id="authority-2",
            global_context={},
            task_context={},
        )
    assert adapter.health()["launched"] == 1


def test_crash_after_launch_claim_becomes_uncertain_and_not_retryable(
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
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()
    workspace = service.reserve_workspace(
        assignment,
        workspace_path,
        lease_seconds=300,
        branch="test/crash",
        base_commit="abc",
    )
    service.reserve_writes(
        assignment, workspace, ("keeper/pass_b",), lease_seconds=300
    )
    service.reserve_usage(assignment, workspace, 1)
    authority_id = _authorize(
        service, assignment, workspace, "authority-1"
    )

    def crash() -> None:
        raise RuntimeError("simulated process loss")

    with pytest.raises(RuntimeError, match="simulated process loss"):
        service.run_assignment(
            assignment.assignment_id,
            workspace_path,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
            after_launch_claim=crash,
        )
    clock.advance(seconds=1)
    recovered = repository.recover_interrupted_attempts(
        clock().isoformat()
    )
    assert recovered == {"prelaunch_released": 0, "uncertain": 1}
    assert repository.get(
        AssignmentRecord, assignment.assignment_id
    ).state == AssignmentState.UNCERTAIN
    assert repository.usage_reservations(
        assignment.assignment_id
    )[0]["state"] == "ACTIVE"
    with pytest.raises(PermissionError):
        repository.release_workspace(
            workspace.workspace_reservation_id,
            workspace.owner_token,
            clock().isoformat(),
        )


def test_interruption_before_launch_claim_is_safe_to_reprepare(
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
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()
    workspace = service.reserve_workspace(
        assignment,
        workspace_path,
        lease_seconds=300,
        branch="test/prelaunch",
        base_commit="abc",
    )
    service.reserve_writes(
        assignment, workspace, ("keeper/pass_b",), lease_seconds=300
    )
    service.reserve_usage(assignment, workspace, 1)
    attempt = AttemptRecord(
        attempt_id="attempt-before-launch",
        assignment_id=assignment.assignment_id,
        authority_attempt_id="authority-1",
        launch_token="launch-1",
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
        launch_plan_digest="legacy-test-plan",
        session_slot_claimed=True,
    )
    repository.reserve_attempt(attempt)
    recovered = repository.recover_interrupted_attempts(
        clock().isoformat()
    )
    assert recovered == {"prelaunch_released": 1, "uncertain": 0}
    assert repository.launch_claim(attempt.attempt_id)["state"] == "FAILED"
    replacement = replace(
        attempt,
        attempt_id="attempt-replacement",
        authority_attempt_id="authority-2",
        launch_token="launch-2",
        created_at=(clock() + timedelta(seconds=1)).isoformat(),
        updated_at=(clock() + timedelta(seconds=1)).isoformat(),
    )
    repository.reserve_attempt(replacement)


def test_two_writers_contending_for_same_workspace_have_one_winner(
    tmp_path: Path,
) -> None:
    (
        _,
        service,
        _,
        provider,
        account,
        _,
        sessions,
        _,
    ) = _stack(tmp_path)
    first = _assignment(service, provider, account, sessions[0])
    second = _assignment(service, provider, account, sessions[1])
    path = tmp_path / "shared"
    path.mkdir()
    barrier = threading.Barrier(3)
    results: list[str] = []
    guard = threading.Lock()

    def reserve(assignment: AssignmentRecord) -> None:
        barrier.wait()
        try:
            service.reserve_workspace(
                assignment,
                path,
                lease_seconds=300,
                branch=f"test/{assignment.assignment_id}",
                base_commit="abc",
            )
        except PermissionError:
            outcome = "blocked"
        else:
            outcome = "reserved"
        with guard:
            results.append(outcome)

    threads = [
        threading.Thread(target=reserve, args=(first,)),
        threading.Thread(target=reserve, args=(second,)),
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert sorted(results) == ["blocked", "reserved"]


def test_read_only_reviewer_cannot_reserve_write_scope(
    tmp_path: Path,
) -> None:
    (
        _,
        service,
        _,
        provider,
        account,
        _,
        sessions,
        _,
    ) = _stack(tmp_path)
    reviewer = _assignment(
        service,
        provider,
        account,
        sessions[0],
        role=AssignmentRole.REVIEWER,
    )
    path = tmp_path / "review"
    path.mkdir()
    workspace = service.reserve_workspace(
        reviewer,
        path,
        lease_seconds=300,
        branch=None,
        base_commit="abc",
    )
    assert workspace.mode == "READ_ONLY"
    with pytest.raises(PermissionError):
        service.reserve_writes(
            reviewer, workspace, ("keeper",), lease_seconds=300
        )


def test_stale_lease_recovery_is_explicit_and_conservative(
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
    path = tmp_path / "stale"
    path.mkdir()
    workspace = service.reserve_workspace(
        assignment,
        path,
        lease_seconds=10,
        branch="test/stale",
        base_commit="abc",
    )
    with pytest.raises(PermissionError):
        repository.recover_stale_workspace(
            workspace.workspace_reservation_id, clock().isoformat()
        )
    clock.advance(seconds=11)
    stale = repository.recover_stale_workspace(
        workspace.workspace_reservation_id, clock().isoformat()
    )
    assert stale.state == ReservationState.STALE
