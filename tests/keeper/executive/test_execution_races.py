from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from keeper.executive.enums import TaskStatus
from keeper.executive.founder_auth import TestFounderAuthenticator
from keeper.executive.models import utc_now
from keeper.executive.runtime import ExecutiveRuntime
from keeper.executive.surfaces import StatusSurface
from tests.keeper.executive.authority_semantics import (
    SemanticAuthorityTransport,
    semantic_gateway,
)
from tests.keeper.executive.fixture_store import replace_executive_fixture
from tests.keeper.executive.test_intake_charters import approved_project


def test_side_effect_then_exception_stays_uncertain_and_is_not_retried(
    tmp_path: Path,
) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    authority.raise_after_side_effect = True
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    blocked = runtime.progress(project.project_id)
    task = service.repository.tasks(project.project_id)[0]
    attempt_id = task.authority_attempt_id
    assert blocked.state == "BLOCKED"
    assert task.status == "UNCERTAIN"
    assert attempt_id is not None
    assert authority.side_effect_count == 1
    reopened_gateway, _ = semantic_gateway(
        tmp_path, transport=authority
    )
    reopened = ExecutiveRuntime(service.repository, reopened_gateway)
    reopened.progress(project.project_id)
    after = service.repository.task(task.task_id)
    assert after.status == "UNCERTAIN"
    assert after.authority_attempt_id == attempt_id
    assert authority.side_effect_count == 1


def test_restart_reconciles_reserved_attempt_without_new_reservation(
    tmp_path: Path,
) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    authority.raise_after_reservation = True
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    runtime.progress(project.project_id)
    before = service.repository.tasks(project.project_id)[0]
    assert before.status == "UNCERTAIN"
    assert before.authority_attempt_id in authority.attempts
    assert authority.side_effect_count == 0

    reopened_gateway, _ = semantic_gateway(
        tmp_path, transport=authority
    )
    reopened = ExecutiveRuntime(service.repository, reopened_gateway)
    reopened.progress(project.project_id)
    after = service.repository.task(before.task_id)
    assert after.authority_attempt_id == before.authority_attempt_id
    assert after.status == "COMPLETED"
    assert authority.side_effect_count == 1
    assert len(authority.attempts) == 1


def test_restart_reconciles_reserved_review_without_duplicate_attempt(
    tmp_path: Path,
) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    runtime.progress(project.project_id)
    authority.raise_after_review_reservation = True
    blocked = runtime.progress(project.project_id)
    architecture = next(
        task
        for task in service.repository.tasks(project.project_id)
        if task.title == "Architecture"
    )
    assert blocked.state == "BLOCKED"
    assert architecture.review_attempt_id is not None
    review_attempt_id = architecture.review_attempt_id
    assert authority.attempts[review_attempt_id]["service_state"] == "RESERVED"

    runtime.resume(project.project_id)
    runtime.progress(project.project_id)
    completed = service.repository.task(architecture.task_id)
    assert completed.status == "COMPLETED"
    assert completed.review_attempt_id == review_attempt_id
    reviews = service.repository.reviews(project.project_id)
    assert len(reviews) == 1


def test_concurrent_authenticated_completion_import_is_idempotent(
    tmp_path: Path,
) -> None:
    service, project, _ = approved_project(tmp_path)
    gateway, _ = semantic_gateway(tmp_path)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    runtime.progress(project.project_id)
    imported = service.repository.tasks(project.project_id)[0]
    assert imported.authority_attempt_id is not None
    attempt = service.repository.execution_attempt(
        imported.authority_attempt_id
    )
    completion = {
        "authority_attempt_id": imported.authority_attempt_id,
        "task_id": imported.task_id,
        "authenticated": True,
        "terminal_disposition": "SUCCEEDED",
        "completion_digest": attempt["completion_digest"],
        "artifact_digest": attempt["artifact_digest"],
        "artifact_identity": attempt["artifact_identity"],
        "artifact_files": attempt["artifact_files"],
        "evidence_digest": attempt["evidence_digest"],
    }
    pending = replace(
        imported,
        status=TaskStatus.RUNNING.value,
        artifact_digest=None,
        review_attempt_id=None,
        result_disposition=None,
        attempt_history=(),
        revision=imported.revision + 1,
        updated_at=utc_now(),
    )
    replace_executive_fixture(
        service.repository.store,
        "executive_tasks",
        pending.task_id,
        pending.to_dict(),
    )
    replace_executive_fixture(
        service.repository.store,
        "executive_execution_attempts",
        imported.authority_attempt_id,
        {**attempt, "state": "EXECUTION_STARTED"},
    )

    def import_completion() -> str:
        repository = type(service.repository)(
            type(service.repository.store)(
                service.repository.store.path
            ),
            TestFounderAuthenticator(),
        )
        return repository.accept_author_completion(
            pending.task_id,
            expected_revision=pending.revision,
            result=dict(completion),
        ).status

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: import_completion(), range(2)))
    final = service.repository.task(pending.task_id)
    assert outcomes == ("REVIEW_REQUIRED", "REVIEW_REQUIRED")
    assert final.status == "REVIEW_REQUIRED"
    assert final.review_attempt_id is None
    assert len(final.attempt_history) == 1
    assert (
        final.attempt_history[0]["completion_digest"]
        == completion["completion_digest"]
    )


def test_two_runtime_instances_create_one_claim_and_one_launch(
    tmp_path: Path,
) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    setup_gateway, _ = semantic_gateway(
        tmp_path, transport=authority
    )
    ExecutiveRuntime(service.repository, setup_gateway).progress(
        project.project_id
    )

    def progress() -> str:
        gateway, _ = semantic_gateway(tmp_path, transport=authority)
        runtime = ExecutiveRuntime(service.repository, gateway)
        return runtime.progress(project.project_id).state

    with ThreadPoolExecutor(max_workers=2) as pool:
        states = tuple(pool.map(lambda _: progress(), range(2)))
    first_task = service.repository.tasks(project.project_id)[0]
    assert states
    assert first_task.status == "COMPLETED"
    assert authority.side_effect_count == 1
    assert len(authority.execution_calls) == 1


def test_cancellation_wins_over_late_authenticated_completion(
    tmp_path: Path,
) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    authority.started = threading.Event()
    authority.release = threading.Event()
    authority.ignore_cancel_completion = True
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)

    errors: list[BaseException] = []

    def worker() -> None:
        try:
            runtime.progress(project.project_id)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=worker)
    thread.start()
    assert authority.started.wait(timeout=10)
    canceled = runtime.cancel(project.project_id)
    authority.release.set()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert errors == []
    assert canceled.state == "CANCELED"
    final_project = service.repository.project(project.project_id)
    first_task = service.repository.tasks(project.project_id)[0]
    assert final_project.state == "CANCELED"
    assert first_task.status == "CANCELED"
    assert first_task.late_result is True
    assert service.repository.store.list("executive_late_results")
    view = StatusSurface(service.repository).project(project.project_id)
    assert view.controls == ()
    assert any(
        item.get("history_kind") == "LATE_AUTHORITY_RESULT"
        for item in view.evidence_history
    )


def test_cancellation_before_launch_prevents_authority_execution(
    tmp_path: Path,
) -> None:
    service, project, _ = approved_project(tmp_path)
    gateway, authority = semantic_gateway(tmp_path)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    runtime.cancel(project.project_id)
    assert runtime.progress(project.project_id).state == "CANCELED"
    assert authority.execution_calls == []


def test_revocation_between_local_recheck_and_authority_launch_prevents_side_effects(
    tmp_path: Path,
) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    authority.before_launch_started = threading.Event()
    authority.before_launch_release = threading.Event()
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)

    errors: list[BaseException] = []

    def worker() -> None:
        try:
            runtime.progress(project.project_id)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=worker)
    thread.start()
    assert authority.before_launch_started.wait(timeout=10)
    revoked = runtime.revoke_delegation(project.project_id)
    authority.before_launch_release.set()
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert errors == []
    assert revoked.state == "PAUSED"
    assert authority.execution_calls == []
    assert authority.side_effect_count == 0
    task = service.repository.tasks(project.project_id)[0]
    assert task.status == "CANCELED"
    assert task.authority_attempt_id is not None
    assert (
        authority.attempts[task.authority_attempt_id]["service_state"]
        == "CANCELLED"
    )
    approval = service.repository.approvals(
        project.project_id, project.active_charter_revision
    )[0]
    assert approval.revoked_at is not None


def test_stale_task_write_is_rejected(tmp_path: Path) -> None:
    service, project, _ = approved_project(tmp_path)
    gateway, _ = semantic_gateway(tmp_path)
    ExecutiveRuntime(service.repository, gateway).progress(project.project_id)
    task = service.repository.tasks(project.project_id)[0]
    ready = replace(
        task,
        status=TaskStatus.READY.value,
        revision=task.revision + 1,
        updated_at=utc_now(),
    )
    service.repository.save_task(ready, expected=task)
    with pytest.raises(PermissionError, match="stale"):
        service.repository.save_task(ready, expected=task)
