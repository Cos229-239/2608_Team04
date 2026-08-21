from __future__ import annotations

from dataclasses import dataclass, replace

from keeper.executive.authority import AuthorityEvaluator, TrustedActionClassifier
from keeper.executive.enums import ActionCategory, ActionEffect, TaskStatus
from keeper.executive.models import (
    ApprovalRecord,
    ActionEffects,
    ExecutiveTask,
    ProjectCharter,
    ProjectRecord,
    SpecialistProfile,
    WorkflowRecord,
    WorkflowStage,
    utc_now,
)
from keeper.executive.repository import ExecutiveRepository, new_id


@dataclass(frozen=True, slots=True)
class StageTemplate:
    title: str
    role: str
    purpose: str
    rationale: str
    capability: str
    review: str
    milestone: bool = False


WORKLOAD_STRATEGIES: dict[str, tuple[StageTemplate, ...]] = {
    "software": (
        StageTemplate("Requirements", "requirements analyst", "Define behavior and boundaries.", "Implementation needs testable scope.", "requirements", "automated"),
        StageTemplate("Architecture", "architect", "Design components and trust boundaries.", "The solution needs a coherent structure before changes.", "architecture", "independent specialist"),
        StageTemplate("Implementation", "builder", "Create the approved application.", "The charter requires a working application.", "implementation", "automated"),
        StageTemplate("Tests", "test specialist", "Verify behavior and failure paths.", "Success criteria require deterministic evidence.", "testing", "independent specialist"),
        StageTemplate("Security review", "security reviewer", "Review trust and data boundaries.", "Software actions can create security exposure.", "security", "independent specialist"),
        StageTemplate("Packaging", "release specialist", "Prepare a reproducible package.", "The deliverable must be usable outside development.", "packaging", "automated"),
        StageTemplate("Pilot", "acceptance reviewer", "Exercise the end-to-end outcome.", "Completion requires user-visible proof.", "acceptance", "founder", True),
    ),
    "research": (
        StageTemplate("Question definition", "research lead", "Bound the research questions.", "Focused questions prevent an unbounded source search.", "research design", "self verification"),
        StageTemplate("Source collection", "source researcher", "Collect relevant sources.", "Claims require traceable source evidence.", "source collection", "automated"),
        StageTemplate("Source quality review", "source reviewer", "Evaluate provenance and credibility.", "Low-quality sources must not silently drive conclusions.", "source review", "independent specialist"),
        StageTemplate("Synthesis", "research synthesist", "Integrate supported findings.", "The audience needs a coherent answer.", "synthesis", "self verification"),
        StageTemplate("Contradiction analysis", "critical reviewer", "Surface disagreement and uncertainty.", "Contradictions materially affect confidence.", "critical analysis", "independent specialist"),
        StageTemplate("Final report", "editor", "Produce the approved report package.", "The charter requires a durable usable output.", "report writing", "founder", True),
    ),
    "video": (
        StageTemplate("Concept", "creative director", "Define audience, message, and format.", "Creative work needs a shared north star.", "creative direction", "self verification"),
        StageTemplate("Script", "script writer", "Write the narrative and spoken content.", "Production needs an approved content spine.", "script writing", "independent specialist"),
        StageTemplate("Storyboard", "visual planner", "Plan shots, scenes, and transitions.", "Visual dependencies should be decided before asset work.", "storyboarding", "self verification"),
        StageTemplate("Asset creation", "asset specialist", "Create approved source assets.", "The edit depends on complete licensed inputs.", "asset creation", "automated"),
        StageTemplate("Edit", "video editor", "Assemble the program.", "The charter requires a finished viewing experience.", "video editing", "self verification"),
        StageTemplate("Quality review", "media reviewer", "Check content, audio, visuals, and constraints.", "Independent viewing catches production defects.", "media review", "independent specialist"),
        StageTemplate("Export", "delivery specialist", "Create the delivery package.", "Completion requires usable target-format files.", "media export", "founder", True),
    ),
    "music": (
        StageTemplate("Creative brief", "creative director", "Define intent, references, and constraints.", "Musical decisions need an approved direction.", "music direction", "self verification"),
        StageTemplate("Composition", "composer", "Create the core musical material.", "The project outcome depends on original structure.", "composition", "self verification"),
        StageTemplate("Arrangement", "arranger", "Develop instrumentation and form.", "The composition must translate into a complete production.", "arrangement", "independent specialist"),
        StageTemplate("Recording", "recording specialist", "Create performance source material.", "The mix requires complete source tracks.", "recording", "automated"),
        StageTemplate("Mix", "mix engineer", "Balance and process the production.", "The work needs a coherent listening experience.", "mixing", "self verification"),
        StageTemplate("Mastering", "mastering reviewer", "Prepare consistent delivery masters.", "Independent final processing protects translation quality.", "mastering", "independent specialist"),
        StageTemplate("Release package", "delivery specialist", "Assemble masters and metadata.", "Completion requires an organized handoff.", "music delivery", "founder", True),
    ),
    "writing": (
        StageTemplate("Brief", "editor", "Define audience, voice, and structure.", "A clear editorial brief controls scope.", "editorial planning", "self verification"),
        StageTemplate("Outline", "outliner", "Create the content structure.", "The draft needs a coherent progression.", "outlining", "self verification"),
        StageTemplate("Draft", "writer", "Produce the manuscript.", "The charter requires complete written content.", "writing", "self verification"),
        StageTemplate("Developmental review", "developmental editor", "Review structure and argument.", "Independent critique improves coherence.", "developmental editing", "independent specialist"),
        StageTemplate("Revision", "writer", "Address review findings.", "Accepted findings must be resolved.", "revision", "automated"),
        StageTemplate("Copy edit", "copy editor", "Correct language and consistency.", "Delivery quality requires a clean manuscript.", "copy editing", "independent specialist"),
        StageTemplate("Final package", "publishing specialist", "Prepare the requested formats.", "Completion requires usable artifacts.", "document production", "founder", True),
    ),
}


class WorkflowPlanner:
    def __init__(self, repository: ExecutiveRepository) -> None:
        self.repository = repository

    def generate(
        self, project: ProjectRecord, charter: ProjectCharter
    ) -> tuple[WorkflowRecord, tuple[ExecutiveTask, ...]]:
        charter = self.repository.charter(charter.charter_id)
        if project.active_charter_id != charter.charter_id or charter.status != "ACTIVE":
            raise PermissionError("planning requires the active approved charter")
        templates = WORKLOAD_STRATEGIES.get(
            charter.project_type,
            (
                StageTemplate("Define", "project lead", "Define the work.", "The charter must become actionable.", "planning", "self verification"),
                StageTemplate("Produce", "specialist", "Create the deliverables.", "The approved outcome requires production.", "production", "automated"),
                StageTemplate("Review", "independent reviewer", "Validate the outputs.", "Completion requires independent evidence.", "review", "independent specialist", True),
            ),
        )
        workflow_id = new_id("workflow")
        stages: list[WorkflowStage] = []
        tasks: list[ExecutiveTask] = []
        prior_stage: str | None = None
        prior_task: str | None = None
        now = utc_now()
        for index, template in enumerate(templates, start=1):
            stage_id = f"{workflow_id}-stage-{index}"
            stage = WorkflowStage(
                stage_id,
                template.title,
                template.purpose,
                template.rationale,
                (prior_stage,) if prior_stage else (),
                template.milestone,
            )
            stages.append(stage)
            category = self._action_category(template)
            side_effect = {
                ActionCategory.READ: ActionEffect.LOCAL_READ,
                ActionCategory.TEST: ActionEffect.TEST_EXECUTION,
            }.get(category, ActionEffect.LOCAL_WRITE)
            task_id = f"{workflow_id}-task-{index}"
            task = ExecutiveTask(
                task_id,
                project.project_id,
                charter.charter_id,
                charter.revision,
                workflow_id,
                stage_id,
                template.title,
                template.purpose,
                template.role,
                (template.capability,),
                (template.purpose, f"Work only within charter revision {charter.revision}."),
                charter.constraints,
                (prior_task,) if prior_task else (),
                None,
                None,
                None,
                TaskStatus.PROPOSED.value,
                category.value,
                (f"{prior_task}:output",) if prior_task else (),
                (f"{task_id}:output",),
                charter.evidence_requirements,
                (template.review,),
                0,
                2,
                (),
                None,
                now,
                now,
                action_effects=ActionEffects(
                    (side_effect.value,),
                    "LOCAL",
                    "INTERNAL",
                    "NONE",
                    "NONE",
                    "NONE",
                    "NONE",
                    "NONE",
                    "NONE",
                    "NONE",
                    "NONE",
                    template.purpose,
                    charter.workspaces[0] if len(charter.workspaces) == 1 else None,
                    None,
                    charter.approved_tools[0] if len(charter.approved_tools) == 1 else None,
                    True,
                    charter.authority_envelope.data_classifications[0],
                ),
            )
            tasks.append(task)
            prior_stage = stage_id
            prior_task = task_id
        prior_workflows = self.repository.workflows(project.project_id)
        workflow = WorkflowRecord(
            workflow_id,
            project.project_id,
            charter.charter_id,
            charter.revision,
            max((item.revision for item in prior_workflows), default=0) + 1,
            f"{charter.project_type}-aware",
            f"Generated {len(stages)} stages from the active {charter.project_type} charter; each stage exists to satisfy a deliverable, review, or evidence need.",
            tuple(stages),
            now,
        )
        self.repository.save_workflow(workflow)
        for task in tasks:
            self.repository.save_task(task)
        return workflow, tuple(tasks)

    @staticmethod
    def _action_category(template: StageTemplate) -> ActionCategory:
        if "review" in template.role or "review" in template.title.casefold():
            return ActionCategory.REVIEW
        if template.capability == "testing":
            return ActionCategory.TEST
        return ActionCategory.WRITE


@dataclass(frozen=True, slots=True)
class ReadinessResult:
    ready: bool
    reasons: tuple[str, ...]


class TaskReadiness:
    def __init__(self, evaluator: AuthorityEvaluator) -> None:
        self.evaluator = evaluator

    def evaluate(
        self,
        task: ExecutiveTask,
        *,
        all_tasks: tuple[ExecutiveTask, ...],
        project: ProjectRecord,
        charter: ProjectCharter,
        specialist: SpecialistProfile | None,
        available_inputs: frozenset[str],
        approvals: tuple[ApprovalRecord, ...] = (),
    ) -> ReadinessResult:
        reasons: list[str] = []
        by_id = {item.task_id: item for item in all_tasks}
        if any(
            dependency not in by_id
            or by_id[dependency].status != TaskStatus.COMPLETED
            for dependency in task.dependencies
        ):
            reasons.append("dependencies are incomplete")
        if not set(task.inputs).issubset(available_inputs):
            reasons.append("required inputs are unavailable")
        if specialist is None:
            reasons.append("no specialist is assigned")
        else:
            if not specialist.qualified:
                reasons.append("assigned specialist is not qualified")
            if not specialist.available:
                reasons.append("assigned specialist is unavailable")
            if not specialist.credential_available:
                reasons.append("assigned specialist credential is unavailable")
            if not set(task.required_capabilities).issubset(specialist.capabilities):
                reasons.append("assigned specialist lacks required capabilities")
            if specialist.provider_id not in charter.approved_providers:
                reasons.append("assigned provider is outside the charter")
        if specialist is not None:
            try:
                action = TrustedActionClassifier().classify(
                    task, charter, specialist
                )
            except PermissionError as error:
                reasons.append(f"trusted action classification failed: {error}")
            else:
                decision = self.evaluator.evaluate(
                    project,
                    charter,
                    action,
                    approvals,
                )
                if decision.outcome not in {"ALLOWED", "ALLOWED_WITHIN_LIMIT"}:
                    reasons.append(f"authority is not present: {decision.outcome}")
        return ReadinessResult(not reasons, tuple(reasons))

    @staticmethod
    def mark_ready(task: ExecutiveTask, readiness: ReadinessResult) -> ExecutiveTask:
        if not readiness.ready:
            raise PermissionError("; ".join(readiness.reasons))
        return replace(
            task,
            status=TaskStatus.READY.value,
            revision=task.revision + 1,
            updated_at=utc_now(),
        )
