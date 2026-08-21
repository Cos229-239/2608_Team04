from __future__ import annotations

import hashlib
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from keeper.pass_b.conversation import (
    activate_delegated_mode,
    validate_delegated_action,
)
from keeper.pass_b.enums import (
    AssignmentRole,
    AssignmentState,
    DelegatedModeState,
)
from keeper.pass_b.models import (
    AssignmentRecord,
    DelegatedModeGrantRecord,
    ProviderRecord,
    ResumeCheckpointRecord,
    UsagePoolRecord,
)
from keeper.pass_b.providers import (
    AdapterAssignment,
    AdapterDescriptor,
    AdapterResult,
    LocalMockAdapter,
)
from keeper.pass_b.usage_authority import TestUsageResetVerifier
from tests.keeper.pass_b.test_conversation_ui_pilot import (
    _approved_application,
)
from tests.keeper.pass_b.test_orchestration import (
    _assignment,
    _authorize,
    _observe_reset,
    _stack,
)


class _BlockingAdapter(LocalMockAdapter):
    def __init__(self, provider_id: str) -> None:
        super().__init__(provider_id)
        self.entered = threading.Event()
        self.release = threading.Event()

    def launch(self, assignment: AdapterAssignment) -> AdapterResult:
        self.entered.set()
        if not self.release.wait(timeout=5):
            raise TimeoutError("blocking adapter test timed out")
        return super().launch(assignment)


class _SideEffectThenExceptionAdapter(LocalMockAdapter):
    def __init__(self, provider_id: str) -> None:
        super().__init__(provider_id)
        self.effects = 0

    def launch(self, assignment: AdapterAssignment) -> AdapterResult:
        del assignment
        self.effects += 1
        raise RuntimeError("side effect then exception")


class _DescriptorAdapter(LocalMockAdapter):
    def __init__(
        self, provider_id: str, descriptor: AdapterDescriptor
    ) -> None:
        super().__init__(provider_id)
        self._descriptor = descriptor

    def descriptor(self) -> AdapterDescriptor:
        return self._descriptor


def _launch_ready(
    service: Any,
    assignment: AssignmentRecord,
    path: Path,
    label: str,
) -> tuple[Any, str]:
    path.mkdir(parents=True, exist_ok=True)
    workspace = service.reserve_workspace(
        assignment,
        path,
        lease_seconds=300,
        branch=f"test/{label}",
        base_commit="abc",
    )
    if not assignment.read_only:
        service.reserve_writes(
            assignment,
            workspace,
            ("bounded",),
            lease_seconds=300,
        )
    assert service.reserve_usage(assignment, workspace, 1)
    authority_id = _authorize(
        service, assignment, workspace, f"authority:{label}"
    )
    return workspace, authority_id


def test_authority_literal_is_rejected_before_provider_launch(
    tmp_path: Path,
) -> None:
    _, service, _, provider, account, _, sessions, adapter = _stack(
        tmp_path
    )
    assignment = _assignment(service, provider, account, sessions[0])
    path = tmp_path / "workspace"
    _launch_ready(service, assignment, path, "literal")

    with pytest.raises(PermissionError, match="not reserved"):
        service.run_assignment(
            assignment.assignment_id,
            path,
            authority_attempt_id="forged-literal",
            global_context={},
            task_context={},
        )
    assert adapter.health()["launched"] == 0


def test_authority_binding_rejects_stale_charter_revision(
    tmp_path: Path,
) -> None:
    repository, service, clock, provider, account, _, sessions, adapter = (
        _stack(tmp_path)
    )
    assignment = _assignment(service, provider, account, sessions[0])
    path = tmp_path / "workspace"
    workspace, authority_id = _launch_ready(
        service, assignment, path, "stale-charter"
    )
    repository.replace(
        replace(
            assignment,
            charter_revision=assignment.charter_revision + 1,
            updated_at=clock().isoformat(),
            revision=assignment.revision + 1,
        ),
        expected_revision=assignment.revision,
    )

    with pytest.raises(PermissionError, match="binding mismatch"):
        service.run_assignment(
            assignment.assignment_id,
            path,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
        )
    assert workspace.state == "ACTIVE"
    assert adapter.health()["launched"] == 0


def test_session_capacity_is_claimed_before_adapter_launch(
    tmp_path: Path,
) -> None:
    repository, service, _, provider, account, _, sessions, _ = _stack(
        tmp_path
    )
    first = _assignment(service, provider, account, sessions[0])
    second = _assignment(service, provider, account, sessions[0])
    _, first_authority = _launch_ready(
        service, first, tmp_path / "first", "capacity-first"
    )
    _, second_authority = _launch_ready(
        service, second, tmp_path / "second", "capacity-second"
    )
    blocking = _BlockingAdapter(provider.provider_id)
    service.adapters[provider.provider_id] = blocking
    errors: list[BaseException] = []

    def launch_first() -> None:
        try:
            service.run_assignment(
                first.assignment_id,
                tmp_path / "first",
                authority_attempt_id=first_authority,
                global_context={},
                task_context={},
            )
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=launch_first)
    thread.start()
    assert blocking.entered.wait(timeout=5)
    assert repository.get(
        type(sessions[0]), sessions[0].session_id
    ).active_assignments == 1
    with pytest.raises(PermissionError, match="launch-ready"):
        service.run_assignment(
            second.assignment_id,
            tmp_path / "second",
            authority_attempt_id=second_authority,
            global_context={},
            task_context={},
        )
    blocking.release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert errors == []


def test_side_effect_exception_becomes_uncertain_without_slot_release(
    tmp_path: Path,
) -> None:
    repository, service, clock, provider, account, _, sessions, _ = _stack(
        tmp_path
    )
    assignment = _assignment(service, provider, account, sessions[0])
    _, authority_id = _launch_ready(
        service, assignment, tmp_path / "workspace", "ambiguous"
    )
    adapter = _SideEffectThenExceptionAdapter(provider.provider_id)
    service.adapters[provider.provider_id] = adapter

    with pytest.raises(RuntimeError, match="side effect"):
        service.run_assignment(
            assignment.assignment_id,
            tmp_path / "workspace",
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
        )
    assert adapter.effects == 1
    assert repository.get(
        type(sessions[0]), sessions[0].session_id
    ).active_assignments == 1
    assert repository.recover_interrupted_attempts(
        clock().isoformat()
    ) == {"prelaunch_released": 0, "uncertain": 1}
    assert repository.get(
        AssignmentRecord, assignment.assignment_id
    ).state == AssignmentState.UNCERTAIN


def test_two_sessions_compete_atomically_for_one_usage_unit(
    tmp_path: Path,
) -> None:
    _, service, _, provider, account, _, sessions, _ = _stack(
        tmp_path, capacity=1
    )
    assignments = (
        _assignment(service, provider, account, sessions[0]),
        _assignment(service, provider, account, sessions[1]),
    )
    workspaces = []
    for index, assignment in enumerate(assignments):
        path = tmp_path / f"usage-{index}"
        path.mkdir()
        workspaces.append(
            service.reserve_workspace(
                assignment,
                path,
                lease_seconds=300,
                branch=f"test/usage-{index}",
                base_commit="abc",
            )
        )
    barrier = threading.Barrier(3)
    outcomes: list[bool] = []
    guard = threading.Lock()

    def reserve(index: int) -> None:
        barrier.wait()
        result = service.reserve_usage(
            assignments[index], workspaces[index], 1
        )
        with guard:
            outcomes.append(result)

    threads = [
        threading.Thread(target=reserve, args=(index,))
        for index in range(2)
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)
    assert sorted(outcomes) == [False, True]


def test_usage_exhaustion_after_reservation_blocks_launch(
    tmp_path: Path,
) -> None:
    repository, service, clock, provider, account, pool, sessions, adapter = (
        _stack(tmp_path)
    )
    assignment = _assignment(service, provider, account, sessions[0])
    _, authority_id = _launch_ready(
        service, assignment, tmp_path / "workspace", "late-exhaustion"
    )
    current = repository.get(UsagePoolRecord, pool.pool_id)
    repository.replace(
        replace(
            current,
            exhausted=True,
            updated_at=clock().isoformat(),
            last_observed_at=clock().isoformat(),
            revision=current.revision + 1,
        ),
        expected_revision=current.revision,
    )

    with pytest.raises(PermissionError, match="exhausted"):
        service.run_assignment(
            assignment.assignment_id,
            tmp_path / "workspace",
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
        )
    assert adapter.health()["launched"] == 0


def test_usage_reset_preserves_other_active_reservations(
    tmp_path: Path,
) -> None:
    repository, service, clock, provider, account, pool, sessions, _ = _stack(
        tmp_path, capacity=2
    )
    holder = _assignment(service, provider, account, sessions[0])
    waiter = _assignment(service, provider, account, sessions[1])
    holder_path = tmp_path / "holder"
    waiter_path = tmp_path / "waiter"
    holder_path.mkdir()
    waiter_path.mkdir()
    holder_workspace = service.reserve_workspace(
        holder,
        holder_path,
        lease_seconds=300,
        branch="test/holder",
        base_commit="abc",
    )
    waiter_workspace = service.reserve_workspace(
        waiter,
        waiter_path,
        lease_seconds=300,
        branch="test/waiter",
        base_commit="abc",
    )
    assert service.reserve_usage(holder, holder_workspace, 1)
    assert not service.reserve_usage(waiter, waiter_workspace, 2)
    clock.advance(hours=2)
    updated = _observe_reset(service, pool, clock)

    assert updated.observation_generation == 2
    assert updated.reserved == 1
    assert updated.remaining == 1
    reservations = repository.usage_reservations(holder.assignment_id)
    assert reservations[0]["state"] == "ACTIVE"


def test_reset_checkpoint_is_one_use(
    tmp_path: Path,
) -> None:
    repository, service, clock, provider, account, pool, sessions, _ = _stack(
        tmp_path, capacity=1
    )
    assignment = _assignment(service, provider, account, sessions[0])
    path = tmp_path / "workspace"
    path.mkdir()
    workspace = service.reserve_workspace(
        assignment,
        path,
        lease_seconds=300,
        branch="test/checkpoint",
        base_commit="abc",
    )
    assert not service.reserve_usage(assignment, workspace, 2)
    checkpoint = repository.list(ResumeCheckpointRecord)[0]
    clock.advance(hours=2)
    verifier = service.usage_reset_verifier
    assert isinstance(verifier, TestUsageResetVerifier)
    current = repository.get(UsagePoolRecord, pool.pool_id)
    observation = verifier.issue(
        current,
        reset_at=current.reset_at or "",
        observed_at=clock().isoformat(),
        model_ids=tuple(sorted({item.model_id for item in sessions})),
        session_ids=tuple(sorted(item.session_id for item in sessions)),
    )
    service.observe_usage_reset(observation)
    with pytest.raises(PermissionError, match="replayed"):
        service.observe_usage_reset(observation)
    service.resume_after_reset(
        assignment.assignment_id, checkpoint.resume_checkpoint_id
    )
    with pytest.raises(PermissionError, match="no longer matches"):
        service.resume_after_reset(
            assignment.assignment_id, checkpoint.resume_checkpoint_id
        )


def test_parent_and_child_writer_workspaces_collide_both_directions(
    tmp_path: Path,
) -> None:
    repository, service, clock, provider, account, _, sessions, _ = _stack(
        tmp_path, sessions=3
    )
    parent = tmp_path / "worktree"
    child = parent / "nested"
    child.mkdir(parents=True)
    first = _assignment(service, provider, account, sessions[0])
    second = _assignment(service, provider, account, sessions[1])
    third = _assignment(service, provider, account, sessions[2])
    parent_reservation = service.reserve_workspace(
        first,
        parent,
        lease_seconds=300,
        branch="test/parent",
        base_commit="abc",
    )
    with pytest.raises(PermissionError, match="incompatible"):
        service.reserve_workspace(
            second,
            child,
            lease_seconds=300,
            branch="test/child-blocked",
            base_commit="abc",
        )
    repository.release_workspace(
        parent_reservation.workspace_reservation_id,
        parent_reservation.owner_token,
        clock().isoformat(),
    )
    service.reserve_workspace(
        second,
        child,
        lease_seconds=300,
        branch="test/child",
        base_commit="abc",
    )
    with pytest.raises(PermissionError, match="incompatible"):
        service.reserve_workspace(
            third,
            parent,
            lease_seconds=300,
            branch="test/parent-blocked",
            base_commit="abc",
        )


def test_browser_evidence_workspace_is_never_reservable(
    tmp_path: Path,
) -> None:
    _, service, _, provider, account, _, sessions, _ = _stack(tmp_path)
    assignment = _assignment(service, provider, account, sessions[0])
    protected = tmp_path / ".ai-workflow" / "pw" / "session"
    protected.mkdir(parents=True)

    with pytest.raises(PermissionError, match="protected"):
        service.reserve_workspace(
            assignment,
            protected,
            lease_seconds=300,
            branch="test/protected",
            base_commit="abc",
        )


def test_launch_path_must_match_exact_workspace_reservation(
    tmp_path: Path,
) -> None:
    _, service, _, provider, account, _, sessions, adapter = _stack(tmp_path)
    assignment = _assignment(service, provider, account, sessions[0])
    reserved = tmp_path / "reserved"
    other = tmp_path / "other"
    other.mkdir()
    _, authority_id = _launch_ready(
        service, assignment, reserved, "path-binding"
    )

    with pytest.raises(PermissionError, match="does not match"):
        service.run_assignment(
            assignment.assignment_id,
            other,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
        )
    assert adapter.health()["launched"] == 0


def test_adapter_reattachment_cannot_widen_capabilities(
    tmp_path: Path,
) -> None:
    _, service, _, provider, _, _, _, adapter = _stack(tmp_path)
    widened = replace(
        adapter.descriptor(),
        capabilities=adapter.descriptor().capabilities
        + ("credential-access",),
    )

    with pytest.raises(PermissionError, match="does not match"):
        service.attach_adapter(
            provider.provider_id,
            _DescriptorAdapter(provider.provider_id, widened),
        )


def test_review_requires_matching_reviewer_attempt_and_evidence(
    tmp_path: Path,
) -> None:
    repository, service, _, provider, account, _, sessions, _ = _stack(
        tmp_path, sessions=3
    )
    producer = _assignment(service, provider, account, sessions[0])
    _, producer_authority = _launch_ready(
        service, producer, tmp_path / "producer", "producer"
    )
    producer_evidence = service.run_assignment(
        producer.assignment_id,
        tmp_path / "producer",
        authority_attempt_id=producer_authority,
        global_context={},
        task_context={},
    )
    producer_evidence = service.validate_evidence(
        producer_evidence.evidence_bundle_id, tmp_path / "producer"
    )
    reviewers = (
        _assignment(
            service,
            provider,
            account,
            sessions[1],
            role=AssignmentRole.REVIEWER,
            review_of_assignment_id=producer.assignment_id,
        ),
        _assignment(
            service,
            provider,
            account,
            sessions[2],
            role=AssignmentRole.REVIEWER,
            review_of_assignment_id=producer.assignment_id,
        ),
    )
    reviewer_evidence = []
    reviewer_references = []
    for index, reviewer in enumerate(reviewers):
        reference = service.create_remote_evidence_reference(
            reviewer.assignment_id,
            source_identity=f"keeper-evidence:reviewer-{index}",
            sha256=hashlib.sha256(
                f"reviewer-{index}".encode("utf-8")
            ).hexdigest(),
            size_bytes=len(f"reviewer-{index}"),
            source_evidence_bundle_id=producer_evidence.evidence_bundle_id,
        )
        reviewer_references.append(reference)
        path = tmp_path / f"reviewer-{index}"
        _, authority_id = _launch_ready(
            service, reviewer, path, f"reviewer-{index}"
        )
        evidence = service.run_assignment(
            reviewer.assignment_id,
            path,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
            evidence_reference_ids=(reference.evidence_reference_id,),
        )
        reviewer_evidence.append(
            service.validate_evidence(evidence.evidence_bundle_id, path)
        )
    with pytest.raises(KeyError):
        service.create_review(
            producer_evidence.evidence_bundle_id,
            reviewers[0].assignment_id,
            "missing-reviewer-evidence",
        )
    with pytest.raises(PermissionError, match="invalid"):
        service.create_review(
            producer_evidence.evidence_bundle_id,
            reviewers[0].assignment_id,
            reviewer_evidence[1].evidence_bundle_id,
        )
    assert repository.list(DelegatedModeGrantRecord) == []


def test_delegated_force_push_variants_are_denied(
    tmp_path: Path,
) -> None:
    application, charter = _approved_application(tmp_path)
    assert charter.founder_approval_identity is not None
    assert charter.founder_approval_record_id is not None
    assert charter.founder_authorization_capability_digest is not None
    expiry = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

    for action in (
        "FORCE_PUSH",
        "force-push",
        "git push --force-with-lease",
    ):
        with pytest.raises(PermissionError, match="outside"):
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
                scope=(action,),
                expires_at=expiry,
            )


def test_delegated_expiry_persists_and_stale_charter_is_denied(
    tmp_path: Path,
) -> None:
    application, charter = _approved_application(tmp_path)
    assert charter.founder_approval_identity is not None
    assert charter.founder_approval_record_id is not None
    assert charter.founder_authorization_capability_digest is not None
    now = datetime.now(UTC)
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
        scope=("RUN_TESTS",),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )
    with pytest.raises(PermissionError, match="stale"):
        validate_delegated_action(
            application.repository,
            grant.delegated_mode_grant_id,
            project_status=application.project_status,
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision + 1,
            action="RUN_TESTS",
        )
    with pytest.raises(PermissionError, match="expired"):
        validate_delegated_action(
            application.repository,
            grant.delegated_mode_grant_id,
            project_status=application.project_status,
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            action="RUN_TESTS",
            observed_at=(now + timedelta(minutes=10)).isoformat(),
        )
    persisted = application.repository.get(
        DelegatedModeGrantRecord, grant.delegated_mode_grant_id
    )
    assert persisted.state == DelegatedModeState.EXPIRED
