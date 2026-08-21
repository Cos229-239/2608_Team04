from __future__ import annotations

from pathlib import Path

import pytest

from keeper.executive.authority_gateway import AuthorityProviderBinding
from keeper.executive.authority_gateway import AuthorityBackedSpecialistGateway
from keeper.executive.enums import FounderApprovalIntent
from keeper.executive.models import ExecutiveTask, ProjectCharter, SpecialistProfile
from keeper.executive.planning import WorkflowPlanner
from keeper.executive.runtime import ExecutiveRuntime
from tests.keeper.executive.authority_semantics import (
    ALL_CAPABILITIES,
    SemanticAuthorityTransport,
    semantic_gateway,
)
from tests.keeper.executive.test_intake_charters import approved_project


def _task_and_gateway(
    tmp_path: Path,
) -> tuple[
    ProjectCharter,
    ExecutiveTask,
    AuthorityBackedSpecialistGateway,
    SemanticAuthorityTransport,
    tuple[SpecialistProfile, ...],
]:
    service, project, charter = approved_project(tmp_path)
    _, tasks = WorkflowPlanner(service.repository).generate(project, charter)
    gateway, authority = semantic_gateway(tmp_path)
    specialists = gateway.specialists(charter)
    return charter, tasks[0], gateway, authority, specialists


def test_injected_semantic_reauthorization_uses_new_authenticated_generation(
    tmp_path: Path,
) -> None:
    service, project, charter_one = approved_project(tmp_path)
    _, tasks_one = WorkflowPlanner(service.repository).generate(
        project, charter_one
    )
    gateway, authority = semantic_gateway(tmp_path)
    specialist_one = gateway.specialists(charter_one)[0]
    plan_one = gateway.prepare(tasks_one[0], charter_one, specialist_one)
    gateway.reserve(plan_one)

    service.repository.revoke_project_launch_authority(project.project_id)
    canceled = gateway.revoke_project_launch(project.project_id, 1)
    assert plan_one.authority_attempt_id in canceled
    assert authority.attempts[plan_one.authority_attempt_id][
        "service_state"
    ] == "CANCELLED"

    draft_two = service.revise(
        charter_one,
        {"purpose": f"{charter_one.purpose} reauthorized"},
        reason="Founder approved a new authorization generation",
        authority_basis="new authenticated Founder event",
    )
    proposed_two = service.propose(draft_two)
    challenge_two = service.request_approval(proposed_two)
    confirmation_two = service.authenticate(challenge_two)
    approved_two, _, _ = service.confirm_approval(
        challenge_two.challenge_id,
        confirmation=confirmation_two,
        intent=FounderApprovalIntent.APPROVE_CHARTER,
    )
    project_two = service.activate(approved_two)
    charter_two = service.repository.charter(approved_two.charter_id)
    _, tasks_two = WorkflowPlanner(service.repository).generate(
        project_two, charter_two
    )
    specialist_two = gateway.specialists(charter_two)[0]
    plan_two = gateway.prepare(tasks_two[0], charter_two, specialist_two)
    gateway.reserve(plan_two)

    first_id = (
        f"launch-authorization:{project.project_id}:generation:1"
    )
    second_id = (
        f"launch-authorization:{project.project_id}:generation:2"
    )
    assert authority.launch_authorizations[first_id]["service_state"] == "REVOKED"
    assert authority.launch_authorizations[second_id]["service_state"] == "ACTIVE"
    assert plan_one.founder_approval_event_id != plan_two.founder_approval_event_id
    assert authority.attempts[plan_one.authority_attempt_id][
        "service_state"
    ] == "CANCELLED"


def test_caller_created_profile_cannot_establish_qualification(
    tmp_path: Path,
) -> None:
    charter, task, gateway, _, _ = _task_and_gateway(tmp_path)
    forged = SpecialistProfile(
        "codex",
        "caller-model",
        "caller-session",
        task.required_capabilities,
        ("software",),
        True,
        True,
        "caller-independence",
        0,
        ("high",),
        True,
        1.0,
    )
    with pytest.raises(PermissionError, match="Authority state"):
        gateway.prepare(task, charter, forged)


def test_no_authority_reservation_means_no_provider_launch(
    tmp_path: Path,
) -> None:
    charter, task, gateway, authority, specialists = _task_and_gateway(
        tmp_path
    )
    plan = gateway.prepare(task, charter, specialists[0])
    with pytest.raises((PermissionError, KeyError)):
        gateway.execute(plan)
    assert authority.side_effect_count == 0


def test_prepare_binds_exact_charter_contained_workspace(
    tmp_path: Path,
) -> None:
    charter, task, gateway, _, specialists = _task_and_gateway(tmp_path)
    child = Path(charter.workspaces[0]) / "isolated-child"
    child.mkdir(parents=True, exist_ok=True)

    plan = gateway.prepare(
        task,
        charter,
        specialists[0],
        workspace=str(child),
    )

    assert Path(plan.workspace) == child.resolve()
    assert Path(plan.reservation_payload["workspace"]) == child.resolve()


def test_prepare_rejects_workspace_outside_charter(
    tmp_path: Path,
) -> None:
    charter, task, gateway, _, specialists = _task_and_gateway(tmp_path)
    outside = (
        Path(charter.workspaces[0]).resolve().parent / "outside-charter"
    )
    outside.mkdir()

    with pytest.raises(PermissionError, match="outside the active charter"):
        gateway.prepare(
            task,
            charter,
            specialists[0],
            workspace=str(outside),
        )


def test_reservation_nonce_makes_safe_repreparation_unique(
    tmp_path: Path,
) -> None:
    charter, task, gateway, _, specialists = _task_and_gateway(tmp_path)

    first = gateway.prepare(
        task,
        charter,
        specialists[0],
        reservation_nonce="a" * 32,
    )
    second = gateway.prepare(
        task,
        charter,
        specialists[0],
        reservation_nonce="b" * 32,
    )

    assert first.authority_attempt_id != second.authority_attempt_id
    assert first.project_id == second.project_id
    assert first.task_id == second.task_id


def test_reservation_nonce_rejects_noncanonical_identity(
    tmp_path: Path,
) -> None:
    charter, task, gateway, _, specialists = _task_and_gateway(tmp_path)

    with pytest.raises(ValueError, match="32 lowercase hex"):
        gateway.prepare(
            task, charter, specialists[0], reservation_nonce="NOT-CANONICAL"
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("task_id", "wrong-task", "binding"),
        ("registration_id", "wrong-provider", "binding"),
        ("provider_instance_id", "wrong-session", "binding"),
        ("provider_evidence_digest", "not-a-sha256", "SHA-256"),
    ],
)
def test_wrong_authenticated_completion_binding_is_rejected(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    charter, task, gateway, authority, specialists = _task_and_gateway(
        tmp_path
    )
    plan = gateway.prepare(task, charter, specialists[0])
    gateway.reserve(plan)
    authority.wrong_completion_field = (field, value)
    with pytest.raises(PermissionError, match=message):
        gateway.execute(plan)


def test_unsigned_completion_is_rejected(tmp_path: Path) -> None:
    charter, task, gateway, authority, specialists = _task_and_gateway(
        tmp_path
    )
    plan = gateway.prepare(task, charter, specialists[0])
    gateway.reserve(plan)
    authority.unsigned_completion = True
    with pytest.raises(PermissionError, match="authentication"):
        gateway.execute(plan)


def test_changed_executable_registration_is_rejected_before_launch(
    tmp_path: Path,
) -> None:
    charter, task, gateway, authority, specialists = _task_and_gateway(
        tmp_path
    )
    plan = gateway.prepare(task, charter, specialists[0])
    gateway.reserve(plan)
    authority.registrations[plan.registration_id][
        "canonical_executable_path"
    ] = "C:/Authority/substituted.exe"
    with pytest.raises(PermissionError, match="registration changed"):
        gateway.execute(plan)
    assert authority.side_effect_count == 0


def test_missing_distinct_reviewer_blocks_completion(
    tmp_path: Path,
) -> None:
    service, project, _ = approved_project(tmp_path)
    only_author = (
        AuthorityProviderBinding(
            "registration-codex",
            "qualification-codex",
        ),
    )
    gateway, authority = semantic_gateway(
        tmp_path, bindings=only_author
    )
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    runtime.progress(project.project_id)
    blocked = runtime.progress(project.project_id)
    architecture = next(
        task
        for task in service.repository.tasks(project.project_id)
        if task.title == "Architecture"
    )
    assert blocked.state == "BLOCKED"
    assert architecture.status == "REVIEW_REQUIRED"
    assert architecture.review_attempt_id is None
    assert len(authority.execution_calls) == 2


def test_review_plan_must_bind_current_artifact_revision(
    tmp_path: Path,
) -> None:
    service, project, _ = approved_project(tmp_path)
    gateway, _ = semantic_gateway(tmp_path)
    runtime = ExecutiveRuntime(service.repository, gateway)
    for _ in range(5):
        runtime.progress(project.project_id)
        current = next(
            task
            for task in service.repository.tasks(project.project_id)
            if task.title == "Architecture"
        )
        if current.review_attempt_id is not None:
            break
    architecture = next(
        task
        for task in service.repository.tasks(project.project_id)
        if task.title == "Architecture"
    )
    # A completed review remains durably bound to the author artifact digest.
    assert architecture.review_attempt_id is not None
    review = service.repository.review(architecture.review_attempt_id)
    assert (
        review["artifact_revision_digest"]
        == architecture.artifact_digest
    )
    with pytest.raises(PermissionError):
        service.repository.claim_review(
            architecture.task_id,
            expected_revision=architecture.revision,
            plan={
                **review["plan"],
                "authority_attempt_id": "copied-review-attempt",
                "artifact_revision_digest": "stale-artifact",
            },
        )


def test_repaired_artifact_requires_a_new_current_review(
    tmp_path: Path,
) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    authority.fail_review_once = True
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    runtime.progress(project.project_id)
    blocked = runtime.progress(project.project_id)
    first = next(
        task
        for task in service.repository.tasks(project.project_id)
        if task.title == "Architecture"
    )
    first_reviews = service.repository.reviews(project.project_id)
    assert blocked.state == "BLOCKED"
    assert first.status == "REPAIR_REQUIRED"
    assert first.retry_count == 1
    assert len(first_reviews) == 1
    runtime.resume(project.project_id)
    runtime.progress(project.project_id)
    repaired = service.repository.task(first.task_id)
    reviews = service.repository.reviews(project.project_id)
    assert repaired.status == "COMPLETED"
    assert repaired.review_attempt_id is not None
    assert len(reviews) == 2
    current_review = service.repository.review(
        repaired.review_attempt_id
    )
    assert (
        current_review["artifact_revision_digest"]
        == repaired.artifact_digest
    )
    assert {
        item["artifact_revision_digest"] for item in reviews
    } == {
        first_reviews[0]["artifact_revision_digest"],
        repaired.artifact_digest,
    }


@pytest.mark.parametrize(
    "terminal",
    ["failed", "timed_out", "canceled", "terminated", "launch_failed"],
)
def test_non_successful_author_execution_never_enters_review(
    tmp_path: Path,
    terminal: str,
) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    authority.normalized_result_override = terminal
    state = runtime.progress(project.project_id)
    first = service.repository.tasks(project.project_id)[0]
    assert state.state == "BLOCKED"
    assert first.status in {"FAILED", "CANCELED"}
    assert first.review_attempt_id is None
    assert first.status != "COMPLETED"


def test_successful_author_without_actual_artifact_fails_closed(
    tmp_path: Path,
) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    authority.omit_author_artifact = True
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    state = runtime.progress(project.project_id)
    first = service.repository.tasks(project.project_id)[0]
    assert state.state == "BLOCKED"
    assert first.status == "UNCERTAIN"
    assert first.review_attempt_id is None


@pytest.mark.parametrize(
    ("disposition", "expected_status"),
    [
        ("REJECTED", "REPAIR_REQUIRED"),
        ("REPAIR_REQUIRED", "REPAIR_REQUIRED"),
        ("INDETERMINATE", "REPAIR_REQUIRED"),
    ],
)
def test_successful_review_process_does_not_imply_semantic_acceptance(
    tmp_path: Path,
    disposition: str,
    expected_status: str,
) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    runtime.progress(project.project_id)
    authority.review_disposition = disposition
    state = runtime.progress(project.project_id)
    architecture = next(
        task
        for task in service.repository.tasks(project.project_id)
        if task.title == "Architecture"
    )
    assert state.state == "BLOCKED"
    assert architecture.status == expected_status
    assert architecture.status != "COMPLETED"


@pytest.mark.parametrize(
    "mode",
    ["malformed", "wrong-artifact", "process-failed", "stale-artifact"],
)
def test_review_binding_or_process_failure_cannot_accept(
    tmp_path: Path,
    mode: str,
) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    runtime.progress(project.project_id)
    if mode == "malformed":
        authority.malformed_review = True
    elif mode == "wrong-artifact":
        authority.wrong_review_artifact = True
    elif mode == "process-failed":
        authority.review_normalized_result_override = "failed"
    else:
        authority.mutate_artifact_during_review = True
    state = runtime.progress(project.project_id)
    architecture = next(
        task
        for task in service.repository.tasks(project.project_id)
        if task.title == "Architecture"
    )
    assert state.state == "BLOCKED"
    assert architecture.status != "COMPLETED"
