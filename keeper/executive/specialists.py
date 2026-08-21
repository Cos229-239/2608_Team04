from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any, Protocol

from keeper.executive.enums import ReviewPolicy, TaskStatus
from keeper.executive.models import (
    ExecutiveTask,
    ProjectCharter,
    ReviewResult,
    SpecialistProfile,
    utc_now,
)


@dataclass(frozen=True, slots=True)
class GlobalProjectBrief:
    project_id: str
    charter_revision: int
    title: str
    purpose: str
    desired_outcome: str
    deliverables: tuple[str, ...]
    constraints: tuple[str, ...]
    non_goals: tuple[str, ...]
    definitions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TaskGuidance:
    task_id: str
    role: str
    objective: str
    allowed_scope: tuple[str, ...]
    prohibited_scope: tuple[str, ...]
    required_tools: tuple[str, ...]
    instructions: tuple[str, ...]
    required_outputs: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    review_criteria: tuple[str, ...]
    handoff_expectations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SpecialistResult:
    task_id: str
    provider_id: str
    model_id: str
    session_id: str
    status: str
    outputs: tuple[str, ...]
    evidence: tuple[str, ...]
    claims: dict[str, Any]
    requested_scope: tuple[str, ...]
    requested_role: str
    verification: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RepairRequest:
    task_id: str
    failed_criteria: tuple[str, ...]
    supporting_evidence: tuple[str, ...]
    expected_corrections: tuple[str, ...]
    preserve: tuple[str, ...]
    remaining_retries: int
    repair_assignment: str


class SpecialistGateway(Protocol):
    """Injected boundary; production implementations use qualified Authority operations."""

    def execute(
        self,
        specialist: SpecialistProfile,
        brief: GlobalProjectBrief,
        guidance: TaskGuidance,
    ) -> SpecialistResult: ...


class SpecialistSelector:
    def select(
        self,
        task: ExecutiveTask,
        charter: ProjectCharter,
        candidates: tuple[SpecialistProfile, ...],
        *,
        author: SpecialistProfile | None = None,
        independent: bool = False,
        effort_level: str = "medium",
    ) -> SpecialistProfile | None:
        raw_role = task.role.casefold()
        normalized_role = {
            "author": "builder",
            "implementer": "builder",
            "executive_builder": "builder",
            "executive_reviewer": "reviewer",
            "executive_post_repair_reviewer": "post_repair_reviewer",
        }.get(raw_role)
        if normalized_role is None:
            if "review" in raw_role:
                normalized_role = "reviewer"
            elif "repair" in raw_role:
                normalized_role = "repairer"
            else:
                normalized_role = "builder"
        eligible = [
            item
            for item in candidates
            if item.qualified
            and item.available
            and item.credential_available
            and item.provider_id in charter.approved_providers
            and not set(item.capabilities).isdisjoint(task.required_capabilities)
            and (
                charter.project_type in item.project_types
                or "general" in item.project_types
            )
            and effort_level in item.effort_levels
            and (
                not item.role_eligibility
                or normalized_role in item.role_eligibility
            )
            and (
                not independent
                or author is None
                or item.independence_identity != author.independence_identity
            )
        ]
        if not eligible:
            return None
        return min(
            eligible,
            key=lambda item: (
                item.cost_tier,
                -item.prior_success_rate,
                item.provider_id,
                item.model_id,
                item.session_id,
            ),
        )


class GuidanceBuilder:
    @staticmethod
    def global_brief(charter: ProjectCharter) -> GlobalProjectBrief:
        return GlobalProjectBrief(
            charter.project_id,
            charter.revision,
            charter.title,
            charter.purpose,
            charter.desired_outcome,
            charter.deliverables,
            charter.constraints,
            charter.non_goals,
            (
                "The active Project Charter is the authority boundary.",
                "Model output is untrusted until deterministic validation completes.",
                "Do not claim completion without the required evidence.",
            ),
        )

    @staticmethod
    def task_guidance(
        task: ExecutiveTask, charter: ProjectCharter
    ) -> TaskGuidance:
        return TaskGuidance(
            task.task_id,
            task.role,
            task.objective,
            (task.title,) + charter.deliverables,
            charter.non_goals
            + (
                "Changing the Project Charter",
                "Changing this assignment or role",
                "Granting tools, authority, or permissions",
                "Approving this output where independence is required",
            ),
            charter.approved_tools,
            task.instructions,
            task.expected_outputs,
            task.evidence_requirements,
            task.review_requirements,
            (
                "Return only scoped outputs and evidence references.",
                "Surface blockers and uncertainty explicitly.",
            ),
        )


class SpecialistOrchestrator:
    def __init__(self, gateway: SpecialistGateway) -> None:
        self.gateway = gateway

    def run(
        self,
        task: ExecutiveTask,
        charter: ProjectCharter,
        specialist: SpecialistProfile,
    ) -> tuple[ExecutiveTask, SpecialistResult]:
        if task.status not in {TaskStatus.READY, TaskStatus.REPAIR_REQUIRED}:
            raise PermissionError("only ready or repair tasks may be assigned")
        assigned = replace(
            task,
            provider_id=specialist.provider_id,
            model_id=specialist.model_id,
            session_id=specialist.session_id,
            status=TaskStatus.RUNNING.value,
            updated_at=utc_now(),
        )
        result = self.gateway.execute(
            specialist,
            GuidanceBuilder.global_brief(charter),
            GuidanceBuilder.task_guidance(assigned, charter),
        )
        self._validate_result(assigned, result, charter)
        history = assigned.attempt_history + (
            {
                "provider_id": specialist.provider_id,
                "model_id": specialist.model_id,
                "session_id": specialist.session_id,
                "status": result.status,
                "outputs": list(result.outputs),
                "evidence": list(result.evidence),
                "recorded_at": utc_now(),
            },
        )
        returned = replace(
            assigned,
            status=TaskStatus.REVIEW_REQUIRED.value,
            attempt_history=history,
            updated_at=utc_now(),
        )
        return returned, result

    @staticmethod
    def _validate_result(
        task: ExecutiveTask,
        result: SpecialistResult,
        charter: ProjectCharter,
    ) -> None:
        if (
            result.task_id != task.task_id
            or result.provider_id != task.provider_id
            or result.model_id != task.model_id
            or result.session_id != task.session_id
        ):
            raise PermissionError("specialist result identity does not match assignment")
        if result.requested_role != task.role:
            raise PermissionError("specialist attempted to alter its assigned role")
        if not set(result.requested_scope).issubset(
            {task.title, *charter.deliverables}
        ):
            raise PermissionError("specialist attempted to expand task scope")
        if result.claims.get("charter_change") or result.claims.get("self_approved"):
            raise PermissionError("specialist attempted to grant itself authority")
        if result.status == "COMPLETED" and (
            not set(task.expected_outputs).issubset(result.outputs)
            or not result.evidence
        ):
            raise PermissionError(
                "specialist claimed completion without outputs and evidence"
            )


class ReviewOrchestrator:
    def evaluate(
        self,
        task: ExecutiveTask,
        result: SpecialistResult,
        *,
        reviewer: SpecialistProfile | None = None,
        author: SpecialistProfile | None = None,
        deterministic_checks: tuple[str, ...] = (),
    ) -> ReviewResult:
        if task.status != TaskStatus.REVIEW_REQUIRED:
            raise PermissionError("task is not ready for review")
        requires_independent = any(
            "independent" in item.casefold() for item in task.review_requirements
        )
        if requires_independent and (
            reviewer is None
            or author is None
            or reviewer.independence_identity == author.independence_identity
        ):
            return ReviewResult(
                False,
                "INDEPENDENCE_REQUIRED",
                ("independent reviewer identity is missing",),
                (),
                ("Assign a qualified reviewer with an independent identity.",),
                ReviewPolicy.INDEPENDENT_SPECIALIST.value,
            )
        failed: list[str] = []
        if not set(task.expected_outputs).issubset(result.outputs):
            failed.append("expected outputs are incomplete")
        if not result.evidence:
            failed.append("required evidence is missing")
        if "failed" in deterministic_checks:
            failed.append("deterministic verification failed")
        if failed:
            return ReviewResult(
                False,
                "REPAIR_REQUIRED",
                tuple(failed),
                result.evidence + deterministic_checks,
                tuple(f"Correct: {item}." for item in failed),
                ReviewPolicy.AUTOMATED.value,
            )
        return ReviewResult(
            True,
            "ACCEPTED",
            (),
            result.evidence + deterministic_checks,
            (),
            ReviewPolicy.INDEPENDENT_SPECIALIST.value
            if requires_independent
            else ReviewPolicy.AUTOMATED.value,
        )

    @staticmethod
    def apply(task: ExecutiveTask, review: ReviewResult) -> ExecutiveTask:
        if review.accepted:
            return replace(
                task,
                status=TaskStatus.COMPLETED.value,
                result_disposition=review.disposition,
                updated_at=utc_now(),
            )
        if review.disposition == "INDEPENDENCE_REQUIRED":
            return replace(
                task,
                status=TaskStatus.BLOCKED.value,
                result_disposition=review.disposition,
                updated_at=utc_now(),
            )
        if task.retry_count >= task.max_retries:
            return replace(
                task,
                status=TaskStatus.FAILED.value,
                result_disposition="RETRY_LIMIT_EXCEEDED",
                updated_at=utc_now(),
            )
        return replace(
            task,
            status=TaskStatus.REPAIR_REQUIRED.value,
            retry_count=task.retry_count + 1,
            result_disposition=review.disposition,
            updated_at=utc_now(),
        )

    @staticmethod
    def repair_request(
        task: ExecutiveTask,
        review: ReviewResult,
        *,
        preserve: tuple[str, ...],
        use_different_specialist: bool,
    ) -> RepairRequest:
        if review.accepted:
            raise ValueError("accepted work does not need repair")
        return RepairRequest(
            task.task_id,
            review.failed_criteria,
            review.evidence,
            review.repair_instructions,
            preserve,
            max(task.max_retries - task.retry_count, 0),
            "different specialist" if use_different_specialist else "original specialist",
        )
