from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from keeper.executive.authority import AuthorityEvaluator
from keeper.executive.enums import TaskStatus
from keeper.executive.models import SpecialistProfile
from keeper.executive.models import utc_now
from keeper.executive.repository import TestExecutiveRepository
from keeper.executive.planning import TaskReadiness, WorkflowPlanner
from tests.keeper.executive.test_intake_charters import approved_project, explicitly_approve


def specialist(capability: str) -> SpecialistProfile:
    return SpecialistProfile(
        "codex", "model", "session", (capability,), ("software", "research"),
        True, True, "identity-1", 0, ("medium",), True, 1.0,
        "included-plan", "2026-07", "USD", 0.0, 0.0, "session",
        True, True, "2026-07-01T00:00:00+00:00",
        "2099-01-01T00:00:00+00:00", "AUTHORITY_REGISTRATION",
    )


def test_software_workflow_is_workload_specific(tmp_path: Path) -> None:
    charter_service, project, charter = approved_project(tmp_path)
    workflow, tasks = WorkflowPlanner(charter_service.repository).generate(project, charter)
    titles = [stage.title for stage in workflow.stages]
    assert titles == [
        "Requirements", "Architecture", "Implementation", "Tests",
        "Security review", "Packaging", "Pilot",
    ]
    assert len(tasks) == len(workflow.stages)
    assert all(stage.rationale for stage in workflow.stages)


def test_research_workflow_is_not_software_pipeline(tmp_path: Path) -> None:
    from keeper.executive.charters import CharterService
    from keeper.executive.intake import ConversationIntake

    from keeper.executive.founder_auth import TestFounderAuthenticator
    from keeper.app.storage import KeeperStore

    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    authenticator = TestFounderAuthenticator()
    service = CharterService.for_test(
        TestExecutiveRepository(store, authenticator),
        authenticator,
    )
    intake = ConversationIntake.revise(
        ConversationIntake().extract("Research urban gardens and create a final report."),
        replacements={
            "success_criteria": ("claims are sourced",),
            "target_audience": "city planners",
            "approved_providers": ("mock",),
            "approved_tools": ("filesystem",),
            "workspaces": (str(tmp_path),),
            "delegation_mode": "FULL_DELEGATION",
        },
    )
    created = service.create_project(intake)
    service.repository.save_conversation(
        "m",
        {
            "interaction_id": "m",
            "project_id": created.project_id,
            "speaker": "Founder",
            "message": "Approve the proposed research charter.",
            "created_at": utc_now(),
        },
    )
    draft = service.draft(created, intake)
    approved, _ = explicitly_approve(service, service.propose(draft))
    project = service.activate(approved)
    workflow, _ = WorkflowPlanner(service.repository).generate(project, approved)
    titles = [stage.title for stage in workflow.stages]
    assert "Source collection" in titles
    assert "Contradiction analysis" in titles
    assert "Implementation" not in titles


def test_readiness_requires_dependencies_inputs_capability_and_authority(tmp_path: Path) -> None:
    charter_service, project, charter = approved_project(tmp_path)
    _, tasks = WorkflowPlanner(charter_service.repository).generate(project, charter)
    first = tasks[0]
    readiness = TaskReadiness(AuthorityEvaluator()).evaluate(
        first,
        all_tasks=tasks,
        project=project,
        charter=charter,
        specialist=specialist(first.required_capabilities[0]),
        available_inputs=frozenset(),
    )
    assert readiness.ready
    assert TaskReadiness.mark_ready(first, readiness).status == TaskStatus.READY

    second = tasks[1]
    blocked = TaskReadiness(AuthorityEvaluator()).evaluate(
        second,
        all_tasks=tasks,
        project=project,
        charter=charter,
        specialist=specialist("wrong"),
        available_inputs=frozenset(),
    )
    assert not blocked.ready
    assert "dependencies are incomplete" in blocked.reasons
    assert "required inputs are unavailable" in blocked.reasons
    assert "assigned specialist lacks required capabilities" in blocked.reasons


def test_stale_charter_task_cannot_become_ready(tmp_path: Path) -> None:
    charter_service, project, charter = approved_project(tmp_path)
    _, tasks = WorkflowPlanner(charter_service.repository).generate(project, charter)
    stale = replace(tasks[0], charter_revision=0)
    readiness = TaskReadiness(AuthorityEvaluator()).evaluate(
        stale,
        all_tasks=(stale,),
        project=project,
        charter=charter,
        specialist=specialist(stale.required_capabilities[0]),
        available_inputs=frozenset(),
    )
    assert not readiness.ready
    assert "CHARTER_REVISION_REQUIRED" in readiness.reasons[-1]


def charter_service_repository(tmp_path: Path) -> TestExecutiveRepository:
    from keeper.app.storage import KeeperStore
    from keeper.executive.founder_auth import TestFounderAuthenticator

    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    return TestExecutiveRepository(store, TestFounderAuthenticator())
