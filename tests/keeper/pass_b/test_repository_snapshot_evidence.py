from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from keeper.pass_b import repository_snapshot
from keeper.pass_b.enums import (
    AssignmentRole,
    AssignmentState,
    AttemptState,
    EvidenceState,
    ReservationState,
)
from keeper.pass_b.models import (
    AssignmentRecord,
    AttemptRecord,
    DelegatedModeGrantRecord,
    EvidenceBundleRecord,
    PrelaunchAbandonmentRecord,
    RepositorySnapshotRecord,
    UsagePoolRecord,
    WorkspaceReservationRecord,
)
from keeper.pass_b.repository_snapshot import capture_repository_snapshot
from tests.keeper.pass_b.test_authority_reservation import _launch_ready
from tests.keeper.pass_b.test_orchestration import _assignment, _stack


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repository(root: Path) -> Path:
    root.mkdir()
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.name", "Keeper Test")
    _git(root, "config", "user.email", "keeper-test@example.invalid")
    (root / "alpha.txt").write_text("alpha\n", encoding="utf-8")
    nested = root / "nested"
    nested.mkdir()
    (nested / "beta.txt").write_text("beta\n", encoding="utf-8")
    _git(root, "add", "alpha.txt", "nested/beta.txt")
    _git(root, "commit", "-m", "test snapshot")
    return root


def test_capture_repository_snapshot_binds_clean_commit_tree_and_blobs(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path / "repository")
    first = capture_repository_snapshot(root)
    second = capture_repository_snapshot(root)

    assert first == second
    assert first.commit_hash == _git(root, "rev-parse", "HEAD")
    assert first.tree_hash == _git(root, "rev-parse", "HEAD^{tree}")
    assert [item["path"] for item in first.entries] == [
        "alpha.txt",
        "nested/beta.txt",
    ]
    assert all(len(str(item["sha256"])) == 64 for item in first.entries)

    (root / "alpha.txt").write_text("changed\n", encoding="utf-8")
    with pytest.raises(PermissionError, match="clean worktree"):
        capture_repository_snapshot(root)


def test_capture_repository_snapshot_rejects_concurrent_head_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path / "repository")
    original = repository_snapshot._git_bytes
    changed = False

    def mutate_after_first_blob(
        repository: Path, *arguments: str
    ) -> bytes:
        nonlocal changed
        result = original(repository, *arguments)
        if arguments[:1] == ("cat-file",) and not changed:
            changed = True
            (root / "alpha.txt").write_text("new commit\n", encoding="utf-8")
            _git(root, "add", "alpha.txt")
            _git(root, "commit", "-m", "concurrent commit")
        return result

    monkeypatch.setattr(repository_snapshot, "_git_bytes", mutate_after_first_blob)
    with pytest.raises(PermissionError, match="changed during snapshot"):
        capture_repository_snapshot(root)


def test_repository_snapshot_is_validated_producer_evidence(
    tmp_path: Path,
) -> None:
    repository, service, _, provider, account, _, sessions, _ = _stack(
        tmp_path / "state"
    )
    workflow = service.create_workflow(
        workflow_id="workflow-snapshot",
        project_id="project-1",
        charter_id="charter-1",
        charter_revision=1,
        strategy="review-clean-repository",
        authority_envelope_digest="a" * 64,
    )
    root = _repository(tmp_path / "repository")

    with ThreadPoolExecutor(max_workers=2) as executor:
        evidence, replay = tuple(
            executor.map(
                lambda _: service.create_repository_snapshot_evidence(
                    workflow.workflow_id, root
                ),
                range(2),
            )
        )
    producer = repository.get(AssignmentRecord, evidence.assignment_id)
    attempt = repository.get(AttemptRecord, evidence.attempt_id)
    snapshots = repository.list(RepositorySnapshotRecord, project_id="project-1")

    assert replay == evidence
    assert evidence.state == EvidenceState.VALIDATED
    assert producer.state == AssignmentState.REVIEW_REQUIRED
    assert producer.provider_id == "keeper-repository-snapshot"
    assert attempt.state == AttemptState.COMPLETED
    assert attempt.external_execution_id is None
    assert attempt.side_effect_class == "READ_ONLY_REPOSITORY_SNAPSHOT"
    assert len(snapshots) == 1

    reviewer_item = service.create_work_item(
        project_id="project-1",
        charter_id="charter-1",
        charter_revision=1,
        workflow_id=workflow.workflow_id,
        title="Review snapshot",
        objective="Review exact snapshot evidence",
        required_roles=(AssignmentRole.REVIEWER,),
    )
    reviewer = _assignment(
        service,
        provider,
        account,
        sessions[0],
        role=AssignmentRole.REVIEWER,
        work_item=reviewer_item,
        review_of_assignment_id=producer.assignment_id,
    )
    reference = service.create_remote_evidence_reference(
        reviewer.assignment_id,
        source_identity=f"keeper-evidence:{evidence.evidence_bundle_id}",
        sha256=evidence.content_digest,
        size_bytes=len(str(evidence.to_dict()).encode("utf-8")),
        source_evidence_bundle_id=evidence.evidence_bundle_id,
    )
    assert (
        service.validate_evidence_reference(
            reference.evidence_reference_id,
            reviewer.assignment_id,
            expected_source_evidence_bundle_id=evidence.evidence_bundle_id,
        )
        == reference
    )

    (root / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    with pytest.raises(PermissionError, match="clean worktree"):
        service.validate_evidence_reference(
            reference.evidence_reference_id,
            reviewer.assignment_id,
        )


def test_prelaunch_abandonment_returns_usage_without_consumption(
    tmp_path: Path,
) -> None:
    application, assignment, _, _ = _launch_ready(tmp_path)
    before_usage = application.repository.usage_reservations(
        assignment.assignment_id
    )[0]
    pool = application.repository.get(
        UsagePoolRecord, str(before_usage["pool_id"])
    )

    record = application.abandon_prelaunch_assignment(assignment.assignment_id)
    replay = application.abandon_prelaunch_assignment(assignment.assignment_id)
    current_pool = application.repository.get(UsagePoolRecord, pool.pool_id)
    current_assignment = application.repository.get(
        AssignmentRecord, assignment.assignment_id
    )
    workspaces = [
        item
        for item in application.repository.list(
            WorkspaceReservationRecord, project_id=assignment.project_id
        )
        if item.assignment_id == assignment.assignment_id
    ]

    assert replay == record
    assert record.state == "APPLIED"
    assert current_assignment.state == AssignmentState.CANCELED
    assert application.repository.usage_reservations(assignment.assignment_id)[0][
        "state"
    ] == "RELEASED"
    assert current_pool.reserved == pool.reserved - float(before_usage["amount"])
    assert current_pool.consumed == pool.consumed
    assert current_pool.remaining == (
        None
        if pool.remaining is None
        else pool.remaining + float(before_usage["amount"])
    )
    assert all(item.state == ReservationState.RELEASED for item in workspaces)
    assert application.repository.list(AttemptRecord) == []
    grant = application.repository.list(DelegatedModeGrantRecord)[0]
    replacement, _ = application.orchestration.prepare_assignment_from_profile(
        str(assignment.usage_policy["execution_profile_id"]),
        delegated_mode_grant_id=grant.delegated_mode_grant_id,
    )
    assert replacement.assignment_id != assignment.assignment_id
    assert replacement.state == AssignmentState.READY


def test_prelaunch_abandonment_is_single_winner_under_concurrency(
    tmp_path: Path,
) -> None:
    application, assignment, _, _ = _launch_ready(tmp_path)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(
            executor.map(
                lambda _: application.abandon_prelaunch_assignment(
                    assignment.assignment_id
                ),
                range(2),
            )
        )
    assert results[0] == results[1]
    assert len(application.repository.list(PrelaunchAbandonmentRecord)) == 1


def test_prelaunch_abandonment_rejects_uncertain_workspace(
    tmp_path: Path,
) -> None:
    application, assignment, _, _ = _launch_ready(tmp_path)
    workspace = next(
        item
        for item in application.repository.list(
            WorkspaceReservationRecord, project_id=assignment.project_id
        )
        if item.assignment_id == assignment.assignment_id
    )
    application.repository.replace(
        replace(
            workspace,
            state=ReservationState.UNCERTAIN,
            revision=workspace.revision + 1,
        ),
        expected_revision=workspace.revision,
    )
    with pytest.raises(PermissionError, match="uncertain"):
        application.abandon_prelaunch_assignment(assignment.assignment_id)
    assert (
        application.repository.get(AssignmentRecord, assignment.assignment_id).state
        == AssignmentState.READY
    )
    assert application.repository.usage_reservations(assignment.assignment_id)[0][
        "state"
    ] == "ACTIVE"


def test_prelaunch_abandonment_rejects_completed_attempt(
    tmp_path: Path,
) -> None:
    application, assignment, workspace_path, _ = _launch_ready(tmp_path)
    application.orchestration.run_prepared_assignment(
        assignment.assignment_id,
        workspace_path,
        global_context={},
        task_context={"objective": "bounded deterministic evidence"},
    )
    with pytest.raises(PermissionError, match="never-launched"):
        application.abandon_prelaunch_assignment(assignment.assignment_id)
    assert (
        application.repository.get(AssignmentRecord, assignment.assignment_id).state
        == AssignmentState.REVIEW_REQUIRED
    )
    assert application.repository.usage_reservations(assignment.assignment_id)[0][
        "state"
    ] == "CONSUMED"
