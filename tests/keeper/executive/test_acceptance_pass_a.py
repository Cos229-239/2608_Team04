from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from keeper.executive.authority import AuthorityEvaluator
from keeper.executive.charters import CharterService
from keeper.executive.enums import ActionCategory, TaskStatus
from keeper.executive.intake import ConversationIntake
from keeper.executive.models import ProposedAction
from keeper.executive.planning import WorkflowPlanner
from keeper.executive.runtime import ExecutiveRuntime
from keeper.executive.service import KeeperExecutive
from keeper.executive.specialists import (
    SpecialistOrchestrator,
    SpecialistResult,
)
from tests.keeper.executive.test_intake_charters import (
    approved_project,
    explicitly_approve,
    service as test_charter_service,
)
from tests.keeper.executive.authority_semantics import (
    SemanticAuthorityTransport,
    semantic_gateway,
)
from tests.keeper.executive.test_specialists import FakeGateway, profile, result_for


def test_injected_non_production_authoritative_scenario_a_software_full_delegation(
    tmp_path: Path,
) -> None:
    service, active, _charter = approved_project(tmp_path)
    gateway, authority = semantic_gateway(tmp_path)
    runtime = ExecutiveRuntime(service.repository, gateway)
    for _ in range(20):
        active = runtime.progress(active.project_id)
        if active.state == "COMPLETED":
            break
    assert active.state == "COMPLETED"
    assert all(
        task.authority_attempt_id
        for task in service.repository.tasks(active.project_id)
    )
    assert authority.execution_calls
    assert service.repository.decisions(active.project_id)
    assert service.repository.memories(active.project_id)


def test_injected_non_production_authoritative_scenario_b_non_software(
    tmp_path: Path,
) -> None:
    service = test_charter_service(tmp_path)
    intake = ConversationIntake.revise(
        ConversationIntake().extract(
            "Research urban gardens and create a sourced final report."
        ),
        replacements={
            "success_criteria": ("all material claims are sourced",),
            "target_audience": "city planners",
            "approved_providers": ("codex", "reviewer-provider"),
            "approved_tools": ("filesystem",),
            "workspaces": (str(tmp_path),),
            "delegation_mode": "FULL_DELEGATION",
        },
    )
    project = service.create_project(intake)
    approved, _ = explicitly_approve(
        service, service.propose(service.draft(project, intake))
    )
    active = service.activate(approved)
    workflow, _ = WorkflowPlanner(service.repository).generate(active, approved)
    titles = {stage.title for stage in workflow.stages}
    assert "Source quality review" in titles
    assert "Implementation" not in titles


@pytest.mark.parametrize(
    "category",
    [
        ActionCategory.SPEND,
        ActionCategory.PUBLISH_EXTERNAL,
        ActionCategory.DEPLOY_PRODUCTION,
        ActionCategory.REWRITE_HISTORY,
    ],
)
def test_scenario_c_authority_exceeded_pauses_or_denies(
    tmp_path: Path, category: ActionCategory
) -> None:
    _, project, charter = approved_project(tmp_path)
    action = ProposedAction(
        "outside", project.project_id, charter.revision, category.value, "external",
        "codex", "filesystem", str(tmp_path), (charter.deliverables[0],), 10, False,
        "HIGH", "INTERNAL", True,
    )
    decision = AuthorityEvaluator().evaluate(project, charter, action)
    assert decision.outcome in {"DENIED", "REQUIRES_FOUNDER_APPROVAL"}


def test_scenario_d_revocation_stops_new_launches(tmp_path: Path) -> None:
    service, project, _ = approved_project(tmp_path)
    gateway, authority = semantic_gateway(tmp_path)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    runtime.revoke_delegation(project.project_id)
    count = len(authority.execution_calls)
    runtime.progress(project.project_id)
    assert len(authority.execution_calls) == count


def test_scenario_e_charter_expansion_requires_new_approval(tmp_path: Path) -> None:
    service, project, charter = approved_project(tmp_path)
    revised = service.revise(
        charter,
        {"deliverables": charter.deliverables + ("external launch",)},
        reason="Expanded delivery",
        authority_basis="Founder request",
    )
    assert project.active_charter_revision is not None
    assert revised.revision == project.active_charter_revision + 1
    assert not service.repository.approvals(project.project_id, revised.revision)


def test_scenario_f_specialist_overreach_is_rejected(tmp_path: Path) -> None:
    service, project, charter = approved_project(tmp_path)
    _, tasks = WorkflowPlanner(service.repository).generate(project, charter)
    task = replace(tasks[0], status=TaskStatus.READY.value)
    specialist = profile(task.required_capabilities[0])
    result = result_for(task, specialist, claims={"self_approved": True})
    with pytest.raises(PermissionError):
        SpecialistOrchestrator(FakeGateway(result)).run(task, charter, specialist)


def test_scenario_g_restart_does_not_duplicate_completed_work(tmp_path: Path) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    runtime.progress(project.project_id)
    completed_before = {
        task.task_id for task in service.repository.tasks(project.project_id)
        if task.status == "COMPLETED"
    }
    from keeper.executive.founder_auth import TestFounderAuthenticator
    from keeper.executive.repository import TestExecutiveRepository
    from keeper.app.storage import KeeperStore

    reopened_store = KeeperStore(service.repository.store.path)
    reopened_store.migrate()
    reopened = TestExecutiveRepository(
        reopened_store, TestFounderAuthenticator()
    )
    reopened_gateway, _ = semantic_gateway(
        tmp_path, transport=authority
    )
    ExecutiveRuntime(reopened, reopened_gateway).progress(project.project_id)
    completed_after = [
        task.task_id for task in reopened.tasks(project.project_id)
        if task.status == "COMPLETED"
    ]
    assert completed_before.issubset(completed_after)
    assert len(completed_after) == len(set(completed_after))


def test_scenario_h_missing_provider_or_credential_waits(tmp_path: Path) -> None:
    service, project, _ = approved_project(tmp_path)
    authority = SemanticAuthorityTransport()
    for registration in authority.registrations.values():
        registration["service_state"] = "REVOKED"
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    assert runtime.progress(project.project_id).state == "WAITING_FOR_PROVIDER"
