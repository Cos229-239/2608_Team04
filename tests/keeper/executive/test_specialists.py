from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from keeper.executive.enums import TaskStatus
from keeper.executive.models import ExecutiveTask, ProjectCharter, SpecialistProfile
from keeper.executive.planning import WorkflowPlanner
from keeper.executive.specialists import (
    GlobalProjectBrief,
    GuidanceBuilder,
    ReviewOrchestrator,
    SpecialistGateway,
    SpecialistOrchestrator,
    SpecialistResult,
    SpecialistSelector,
    TaskGuidance,
)
from tests.keeper.executive.test_intake_charters import approved_project


def profile(
    capability: str,
    *,
    provider: str = "codex",
    identity: str = "author",
    qualified: bool = True,
    cost: int = 0,
) -> SpecialistProfile:
    return SpecialistProfile(
        provider, f"{provider}-model", f"{provider}-session", (capability,),
        ("software", "general"), qualified, True, identity, cost,
        ("medium",), True, 1.0,
        "included-plan", "2026-07", "USD", 0.0, 0.0, "session",
        True, True, "2026-07-01T00:00:00+00:00",
        "2099-01-01T00:00:00+00:00", "AUTHORITY_REGISTRATION",
    )


class FakeGateway(SpecialistGateway):
    def __init__(self, result: SpecialistResult) -> None:
        self.result = result
        self.brief_deliverables: tuple[str, ...] = ()
        self.guidance_scope: tuple[str, ...] = ()

    def execute(
        self,
        specialist: SpecialistProfile,
        brief: GlobalProjectBrief,
        guidance: TaskGuidance,
    ) -> SpecialistResult:
        self.brief_deliverables = brief.deliverables
        self.guidance_scope = guidance.allowed_scope
        return self.result


def setup_task(
    tmp_path: Path,
) -> tuple[ProjectCharter, ExecutiveTask, SpecialistProfile]:
    service, project, charter = approved_project(tmp_path)
    _, tasks = WorkflowPlanner(service.repository).generate(project, charter)
    task = replace(tasks[0], status=TaskStatus.READY.value)
    specialist = profile(task.required_capabilities[0])
    return charter, task, specialist


def result_for(
    task: ExecutiveTask,
    specialist: SpecialistProfile,
    *,
    evidence: tuple[str, ...] = ("evidence:test",),
    claims: dict[str, object] | None = None,
    role: str | None = None,
    scope: tuple[str, ...] | None = None,
) -> SpecialistResult:
    return SpecialistResult(
        task.task_id, specialist.provider_id, specialist.model_id,
        specialist.session_id, "COMPLETED", task.expected_outputs, evidence,
        claims or {}, scope or (task.title,), role or task.role, ("checks passed",),
    )


def test_selector_uses_qualification_constraints_and_cost(tmp_path: Path) -> None:
    charter, task, _ = setup_task(tmp_path)
    candidates = (
        profile(task.required_capabilities[0], provider="expensive", cost=3),
        profile(task.required_capabilities[0], provider="codex", cost=0),
        profile(task.required_capabilities[0], provider="codex", qualified=False),
    )
    selected = SpecialistSelector().select(task, charter, candidates)
    assert selected is not None
    assert selected.cost_tier == 0
    assert selected.qualified


def test_guidance_is_scoped_and_does_not_include_unrestricted_state(tmp_path: Path) -> None:
    charter, task, _ = setup_task(tmp_path)
    guidance = GuidanceBuilder.task_guidance(task, charter)
    assert "Changing the Project Charter" in guidance.prohibited_scope
    assert set(guidance.allowed_scope) == {task.title, *charter.deliverables}
    assert not hasattr(guidance, "approvals")


def test_specialist_overreach_and_false_completion_are_rejected(tmp_path: Path) -> None:
    charter, task, specialist = setup_task(tmp_path)
    overreach = result_for(task, specialist, role="executive")
    with pytest.raises(PermissionError, match="role"):
        SpecialistOrchestrator(FakeGateway(overreach)).run(task, charter, specialist)
    false_completion = result_for(task, specialist, evidence=())
    with pytest.raises(PermissionError, match="evidence"):
        SpecialistOrchestrator(FakeGateway(false_completion)).run(task, charter, specialist)


def test_review_requests_repair_then_accepts_preserved_work(tmp_path: Path) -> None:
    charter, task, specialist = setup_task(tmp_path)
    first = result_for(task, specialist)
    returned, _ = SpecialistOrchestrator(FakeGateway(first)).run(task, charter, specialist)
    failed = ReviewOrchestrator().evaluate(
        returned, first, deterministic_checks=("failed",)
    )
    repair_task = ReviewOrchestrator.apply(returned, failed)
    assert repair_task.status == "REPAIR_REQUIRED"
    request = ReviewOrchestrator.repair_request(
        repair_task, failed, preserve=("valid output",), use_different_specialist=False
    )
    assert request.failed_criteria
    assert request.preserve == ("valid output",)

    repaired_result = result_for(repair_task, specialist)
    repaired_returned, _ = SpecialistOrchestrator(
        FakeGateway(repaired_result)
    ).run(repair_task, charter, specialist)
    accepted = ReviewOrchestrator().evaluate(
        repaired_returned, repaired_result, deterministic_checks=("passed",)
    )
    assert ReviewOrchestrator.apply(repaired_returned, accepted).status == "COMPLETED"


def test_independent_review_cannot_share_identity(tmp_path: Path) -> None:
    charter, task, author = setup_task(tmp_path)
    task = replace(task, review_requirements=("independent specialist",))
    result = result_for(task, author)
    returned, _ = SpecialistOrchestrator(FakeGateway(result)).run(task, charter, author)
    same_context = profile(task.required_capabilities[0], identity=author.independence_identity)
    review = ReviewOrchestrator().evaluate(
        returned, result, reviewer=same_context, author=author
    )
    assert review.disposition == "INDEPENDENCE_REQUIRED"
    assert ReviewOrchestrator.apply(returned, review).status == "BLOCKED"
