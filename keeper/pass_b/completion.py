from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from keeper.executive.models import ProjectCharter
from keeper.pass_b.conversation import (
    ALLOWED_DELEGATED_ACTIONS,
    activate_delegated_mode,
    reconcile_delegated_grants,
    validate_delegated_action,
)
from keeper.pass_b.enums import (
    AssignmentRole,
    AssignmentState,
    EvidenceState,
    ReviewState,
    WorkItemState,
    WorkflowState,
)
from keeper.pass_b.models import (
    AssignmentRecord,
    AttemptRecord,
    EvidenceBundleRecord,
    EvidenceReferenceRecord,
    ExecutionProfileRecord,
    ProviderAccountRecord,
    ReviewRecord,
    WorkflowRecord,
    WorkItemRecord,
    WorkspaceReservationRecord,
    WriteReservationRecord,
)
from keeper.pass_b.orchestration import OrchestrationService
from keeper.pass_b.repository import (
    PassBRepository,
    validate_protected_workspace_tree,
)


class ProjectStatusReader(Protocol):
    def __call__(self, project_id: str) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class CompletionStepResult:
    project_id: str
    workflow_id: str | None
    state: str
    detail: str
    work_item_id: str | None = None
    assignment_id: str | None = None


_GRANT_SCOPE = tuple(
    item
    for item in (
        "TASK_SEQUENCING",
        "SELECT_APPROVED_PROVIDER",
        "ASSIGN_IMPLEMENTATION",
        "ASSIGN_READ_ONLY_REVIEW",
        "RUN_TESTS",
        "RUN_VERIFICATION",
        "REQUEST_BOUNDED_REPAIR",
        "CREATE_ISOLATED_WORKTREE",
        "PAUSE_FOR_USAGE_RESET",
        "RESUME_AFTER_VALIDATED_RESET",
        "UPDATE_ROUTINE_DOCUMENTATION",
        "COLLECT_EVIDENCE",
    )
    if item in ALLOWED_DELEGATED_ACTIONS
)


class CompletionCoordinator:
    """Advance one Founder-approved project through durable Pass B state.

    The coordinator owns no authoritative in-memory queue.  Each call reloads
    current records and performs at most one externally executable assignment.
    Restarts therefore resume from SQLite rather than replaying a local plan.
    """

    def __init__(
        self,
        repository: PassBRepository,
        orchestration: OrchestrationService,
        project_status: ProjectStatusReader,
        data_directory: Path,
    ) -> None:
        self.repository = repository
        self.orchestration = orchestration
        self.project_status = project_status
        self.data_directory = data_directory.resolve()

    def run_until_blocked(
        self, project_id: str, *, max_steps: int = 100
    ) -> tuple[CompletionStepResult, ...]:
        if max_steps < 1:
            raise ValueError("completion step limit must be positive")
        results: list[CompletionStepResult] = []
        for _ in range(max_steps):
            result = self.advance(project_id)
            results.append(result)
            if result.state != "PROGRESS":
                return tuple(results)
        return tuple(
            [
                *results,
                CompletionStepResult(
                    project_id,
                    results[-1].workflow_id if results else None,
                    "BLOCKED",
                    "Completion stopped at its bounded step limit.",
                ),
            ]
        )

    def advance(self, project_id: str) -> CompletionStepResult:
        charter = self._active_charter(project_id)
        workflow = self._workflow(project_id, charter)
        if workflow.state == WorkflowState.COMPLETED:
            return self._result(workflow, "COMPLETED", "Workflow is complete.")
        grant_id = self._grant(charter)
        assignments = self._assignments(workflow)
        if any(item.state == AssignmentState.UNCERTAIN for item in assignments):
            return self._result(
                workflow,
                "UNCERTAIN",
                "An external effect is uncertain; automatic retry is prohibited.",
            )
        waiting = next(
            (
                item
                for item in assignments
                if item.state == AssignmentState.WAITING_FOR_USAGE_RESET
            ),
            None,
        )
        if waiting is not None:
            return self._result(
                workflow,
                "WAITING_FOR_USAGE_RESET",
                "Provider usage is exhausted; a validated reset is required.",
                assignment=waiting,
            )

        pending_review = next(
            (
                item
                for item in assignments
                if item.role == AssignmentRole.REVIEWER
                and item.state == AssignmentState.REVIEW_REQUIRED
            ),
            None,
        )
        if pending_review is not None:
            return self._finish_review(workflow, pending_review)

        producer = next(
            (
                item
                for item in assignments
                if item.role != AssignmentRole.REVIEWER
                and item.state == AssignmentState.REVIEW_REQUIRED
            ),
            None,
        )
        if producer is not None:
            return self._run_reviewer(workflow, charter, grant_id, producer)

        repaired_parent_ids = {
            parent_id
            for item in assignments
            if isinstance(
                parent_id := item.usage_policy.get("repair_of_assignment_id"),
                str,
            )
        }
        repair_target = next(
            (
                item
                for item in assignments
                if item.role != AssignmentRole.REVIEWER
                and item.state == AssignmentState.REPAIR_REQUIRED
                and item.assignment_id not in repaired_parent_ids
            ),
            None,
        )
        if repair_target is not None:
            return self._run_repair(workflow, grant_id, repair_target)

        runnable = self._runnable_work_item(workflow)
        if runnable is not None:
            if runnable.required_roles == (AssignmentRole.REVIEWER,):
                return self._result(
                    workflow,
                    "BLOCKED",
                    "A reviewer stage has no exact producer awaiting review.",
                    work_item=runnable,
                )
            return self._run_producer(workflow, charter, grant_id, runnable)

        work_items = self._work_items(workflow)
        if work_items and all(
            item.state == WorkItemState.COMPLETED for item in work_items
        ):
            completed = self.orchestration.reconcile_workflow_completion(
                workflow.workflow_id
            )
            return self._result(
                completed, "COMPLETED", "Workflow completed with accepted evidence."
            )
        return self._result(
            workflow,
            "BLOCKED",
            "No dependency-ready stage can progress from durable state.",
        )

    def _run_producer(
        self,
        workflow: WorkflowRecord,
        charter: ProjectCharter,
        grant_id: str,
        work_item: WorkItemRecord,
    ) -> CompletionStepResult:
        profile = self._profile(
            charter, work_item, grant_id=grant_id, role=work_item.required_roles[0]
        )
        assignment, _ = self.orchestration.prepare_assignment_from_profile(
            profile.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )
        workspace = self._reserve(assignment, profile)
        if not self._reserve_usage(assignment, workspace, profile.usage_amount):
            return self._result(
                workflow,
                "WAITING_FOR_USAGE_RESET",
                "Usage reservation could not be satisfied.",
                work_item=work_item,
                assignment=assignment,
            )
        evidence = self.orchestration.run_next_reserved_stage(
            workflow.workflow_id,
            global_context={
                "project_id": workflow.project_id,
                "charter_id": workflow.charter_id,
                "charter_revision": workflow.charter_revision,
            },
            task_context={
                "work_item_id": work_item.work_item_id,
                "objective": work_item.objective,
            },
        )
        self.orchestration.validate_evidence(
            evidence.evidence_bundle_id, Path(workspace.canonical_path)
        )
        self._release(workspace)
        return self._result(
            workflow,
            "PROGRESS",
            f"{work_item.title} completed and is awaiting independent review.",
            work_item=work_item,
            assignment=assignment,
        )

    def _run_reviewer(
        self,
        workflow: WorkflowRecord,
        charter: ProjectCharter,
        grant_id: str,
        producer: AssignmentRecord,
    ) -> CompletionStepResult:
        producer_evidence = self._validated_evidence(producer)
        review_item = self._review_work_item(workflow, producer)
        profile = self._profile(
            charter,
            review_item,
            grant_id=grant_id,
            role=AssignmentRole.REVIEWER,
            review_of_assignment_id=producer.assignment_id,
        )
        reviewer, _ = self.orchestration.prepare_assignment_from_profile(
            profile.execution_profile_id,
            delegated_mode_grant_id=grant_id,
        )
        reference = self._reference(reviewer, producer_evidence)
        workspace = self._reserve(reviewer, profile)
        if not self._reserve_usage(reviewer, workspace, profile.usage_amount):
            return self._result(
                workflow,
                "WAITING_FOR_USAGE_RESET",
                "Reviewer usage reservation could not be satisfied.",
                work_item=review_item,
                assignment=reviewer,
            )
        evidence = self.orchestration.run_prepared_assignment(
            reviewer.assignment_id,
            Path(workspace.canonical_path),
            global_context={
                "project_id": workflow.project_id,
                "charter_id": workflow.charter_id,
                "charter_revision": workflow.charter_revision,
            },
            task_context={
                "objective": review_item.objective,
                "reviewed_assignment_id": producer.assignment_id,
            },
            evidence_reference_ids=(reference.evidence_reference_id,),
            side_effect_class="READ_ONLY_REVIEW",
        )
        self.orchestration.validate_evidence(
            evidence.evidence_bundle_id, Path(workspace.canonical_path)
        )
        return self._result(
            workflow,
            "PROGRESS",
            f"Independent review completed for {producer.assignment_id}.",
            work_item=review_item,
            assignment=reviewer,
        )

    def _finish_review(
        self, workflow: WorkflowRecord, reviewer: AssignmentRecord
    ) -> CompletionStepResult:
        producer_id = reviewer.usage_policy.get("review_of_assignment_id")
        if not isinstance(producer_id, str) or not producer_id:
            return self._result(
                workflow,
                "BLOCKED",
                "Reviewer assignment lacks an exact producer binding.",
                assignment=reviewer,
            )
        producer = self.repository.get(AssignmentRecord, producer_id)
        producer_evidence = self._validated_evidence(producer)
        reviewer_evidence = self._validated_evidence(reviewer)
        existing = [
            item
            for item in self.repository.list(
                ReviewRecord, project_id=workflow.project_id
            )
            if item.reviewer_assignment_id == reviewer.assignment_id
            and item.assignment_id == producer.assignment_id
        ]
        if len(existing) > 1:
            raise PermissionError("reviewer assignment has multiple review records")
        review = (
            existing[0]
            if existing
            else self.orchestration.create_review(
                producer_evidence.evidence_bundle_id,
                reviewer.assignment_id,
                reviewer_evidence.evidence_bundle_id,
            )
        )
        if review.state == ReviewState.PENDING:
            review, _, _ = self.orchestration.decide_review(review.review_id)
        workspace = self._active_workspace(reviewer)
        if workspace is not None:
            self._release(workspace)
        state = (
            "PROGRESS"
            if review.state in {ReviewState.ACCEPTED, ReviewState.REPAIR_REQUIRED}
            else "BLOCKED"
        )
        return self._result(
            workflow,
            state,
            (
                "Independent review accepted the exact delivered evidence."
                if review.state == ReviewState.ACCEPTED
                else "Independent review requested a bounded repair."
            ),
            assignment=producer,
        )

    def _run_repair(
        self,
        workflow: WorkflowRecord,
        grant_id: str,
        original: AssignmentRecord,
    ) -> CompletionStepResult:
        reviews = [
            item
            for item in self.repository.list(
                ReviewRecord, project_id=workflow.project_id
            )
            if item.assignment_id == original.assignment_id
            and item.state == ReviewState.REPAIR_REQUIRED
        ]
        if len(reviews) != 1:
            return self._result(
                workflow,
                "BLOCKED",
                "Repair target lacks one exact review decision.",
                assignment=original,
            )
        repair = self.orchestration.create_repair_assignment(
            reviews[0].review_id,
            delegated_mode_grant_id=grant_id,
        )
        profile_id = repair.usage_policy.get("execution_profile_id")
        if not isinstance(profile_id, str):
            raise PermissionError("repair assignment lacks its execution profile")
        profile = self.repository.get(ExecutionProfileRecord, profile_id)
        workspace = self._reserve(repair, profile)
        if not self._reserve_usage(repair, workspace, profile.usage_amount):
            return self._result(
                workflow,
                "WAITING_FOR_USAGE_RESET",
                "Repair usage reservation could not be satisfied.",
                assignment=repair,
            )
        work_item = self.repository.get(WorkItemRecord, repair.work_item_id)
        evidence = self.orchestration.run_prepared_assignment(
            repair.assignment_id,
            Path(workspace.canonical_path),
            global_context={"project_id": workflow.project_id},
            task_context={
                "objective": work_item.objective,
                "repair_review_id": reviews[0].review_id,
                "repair_of_assignment_id": original.assignment_id,
            },
        )
        self.orchestration.validate_evidence(
            evidence.evidence_bundle_id, Path(workspace.canonical_path)
        )
        self._release(workspace)
        return self._result(
            workflow,
            "PROGRESS",
            "Bounded repair completed and is awaiting fresh independent review.",
            work_item=work_item,
            assignment=repair,
        )

    def _active_charter(self, project_id: str) -> ProjectCharter:
        status = self.project_status(project_id)
        project = status.get("project_summary")
        charter = status.get("active_charter")
        if (
            not isinstance(project, dict)
            or not isinstance(charter, dict)
            or project.get("project_id") != project_id
            or project.get("state") != "ACTIVE"
            or project.get("active_charter_id") != charter.get("charter_id")
            or project.get("active_charter_revision") != charter.get("revision")
        ):
            raise PermissionError("completion requires the active project charter")
        result = ProjectCharter.from_dict(dict(charter))
        if (
            result.status != "ACTIVE"
            or not result.founder_approval_record_id
            or not result.founder_approval_identity
            or not result.founder_authorization_capability_digest
        ):
            raise PermissionError("completion requires Founder-approved authority")
        return result

    def _workflow(
        self, project_id: str, charter: ProjectCharter
    ) -> WorkflowRecord:
        values = [
            item
            for item in self.repository.list(WorkflowRecord, project_id=project_id)
            if item.charter_id == charter.charter_id
            and item.charter_revision == charter.revision
            and item.state in {WorkflowState.ACTIVE, WorkflowState.COMPLETED}
        ]
        if len(values) != 1:
            raise PermissionError("project does not have one current workflow")
        return values[0]

    def _grant(self, charter: ProjectCharter) -> str:
        active = reconcile_delegated_grants(
            self.repository, project_status=self.project_status
        )
        matching = [
            item
            for item in active
            if item.project_id == charter.project_id
            and item.charter_id == charter.charter_id
            and item.charter_revision == charter.revision
        ]
        if len(matching) > 1:
            raise PermissionError("project has multiple active delegated grants")
        if matching:
            return matching[0].delegated_mode_grant_id
        grant = activate_delegated_mode(
            self.repository,
            project_status=self.project_status,
            project_id=charter.project_id,
            charter=charter,
            founder_identity=str(charter.founder_approval_identity),
            founder_approval_id=str(charter.founder_approval_record_id),
            founder_approval_digest=str(
                charter.founder_authorization_capability_digest
            ),
            scope=_GRANT_SCOPE,
            expires_at=(datetime.now(UTC) + timedelta(hours=8)).isoformat(),
            max_actions=10_000,
        )
        return grant.delegated_mode_grant_id

    def _profile(
        self,
        charter: ProjectCharter,
        work_item: WorkItemRecord,
        *,
        grant_id: str,
        role: str,
        review_of_assignment_id: str | None = None,
    ) -> ExecutionProfileRecord:
        workspace = self._workspace_path(charter, work_item, role)
        validate_delegated_action(
            self.repository,
            grant_id,
            project_status=self.project_status,
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            action="CREATE_ISOLATED_WORKTREE",
            action_scope={"workspace": str(workspace)},
        )
        workspace.mkdir(parents=True, exist_ok=True)
        validate_protected_workspace_tree(workspace)
        if role != AssignmentRole.REVIEWER:
            (workspace / "output").mkdir(exist_ok=True)
        privacy_values = {
            account.privacy_classification
            for account in self.repository.list(ProviderAccountRecord)
            if account.provider_id in charter.approved_providers
            and account.enabled
            and account.authentication_ready
            and str(account.cost_mode) != "PAID"
        }
        if len(privacy_values) != 1:
            raise PermissionError(
                "approved providers do not share one explicit privacy policy"
            )
        return self.orchestration.register_execution_profile(
            work_item_id=work_item.work_item_id,
            role=role,
            workspace_path=workspace,
            write_scopes=() if role == AssignmentRole.REVIEWER else ("output",),
            expected_evidence=("structured-report",),
            usage_amount=1.0,
            effort_level="MEDIUM",
            required_capabilities=(str(role).casefold(),),
            privacy_classification=next(iter(privacy_values)),
            preferred_provider_id=None,
            allow_substitution=True,
            review_of_assignment_id=review_of_assignment_id,
        )

    def _workspace_path(
        self, charter: ProjectCharter, work_item: WorkItemRecord, role: str
    ) -> Path:
        if not charter.workspaces:
            raise PermissionError("charter has no approved workspace")
        root = validate_protected_workspace_tree(
            Path(charter.workspaces[0]), require_exists=False
        )
        root.mkdir(parents=True, exist_ok=True)
        validate_protected_workspace_tree(root)
        identity = (
            f"review:{work_item.work_item_id}:{role}"
            if role == AssignmentRole.REVIEWER
            else (
                f"project:{charter.project_id}:{charter.charter_id}:"
                f"{charter.revision}"
            )
        )
        suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        return root / f"keeper-{suffix}"

    def _reserve(
        self, assignment: AssignmentRecord, profile: ExecutionProfileRecord
    ) -> WorkspaceReservationRecord:
        active = self._active_workspace(assignment)
        if active is None:
            active = self.orchestration.reserve_workspace(
                assignment,
                Path(profile.canonical_workspace_path),
                lease_seconds=8 * 60 * 60,
                branch=None,
                base_commit=None,
            )
        if not assignment.read_only:
            writes = [
                item
                for item in self.repository.list(WriteReservationRecord)
                if item.assignment_id == assignment.assignment_id
                and item.state == "ACTIVE"
            ]
            if not writes:
                self.orchestration.reserve_writes(
                    assignment,
                    active,
                    profile.write_scopes,
                    lease_seconds=8 * 60 * 60,
                )
            elif len(writes) != 1 or writes[0].scope != profile.write_scopes:
                raise PermissionError("assignment write reservation changed")
        return active

    def _reserve_usage(
        self,
        assignment: AssignmentRecord,
        workspace: WorkspaceReservationRecord,
        amount: float,
    ) -> bool:
        rows = [
            item
            for item in self.repository.usage_reservations(
                assignment.assignment_id
            )
            if item["state"] == "ACTIVE"
        ]
        if rows:
            if len(rows) != 1 or float(rows[0]["amount"]) != amount:
                raise PermissionError("assignment usage reservation changed")
            return True
        return self.orchestration.reserve_usage(assignment, workspace, amount)

    def _release(self, workspace: WorkspaceReservationRecord) -> None:
        current = self.repository.get(
            WorkspaceReservationRecord, workspace.workspace_reservation_id
        )
        if current.state == "ACTIVE":
            self.repository.release_workspace(
                current.workspace_reservation_id,
                current.owner_token,
                datetime.now(UTC).isoformat(),
            )

    def _review_work_item(
        self, workflow: WorkflowRecord, producer: AssignmentRecord
    ) -> WorkItemRecord:
        identifier = uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"keeper-review:{workflow.workflow_id}:{producer.assignment_id}",
        ).hex
        existing = self.repository.optional(WorkItemRecord, identifier)
        if existing is not None:
            if (
                existing.workflow_id != workflow.workflow_id
                or existing.required_roles != (AssignmentRole.REVIEWER,)
            ):
                raise PermissionError("review work item identity changed")
            return existing
        return self.orchestration.create_work_item(
            project_id=workflow.project_id,
            charter_id=workflow.charter_id,
            charter_revision=workflow.charter_revision,
            workflow_id=workflow.workflow_id,
            work_item_id=identifier,
            title=f"Independent review: {producer.work_item_id}",
            objective="Review the exact validated producer evidence independently.",
            dependencies=(),
            required_roles=(AssignmentRole.REVIEWER,),
        )

    def _reference(
        self,
        reviewer: AssignmentRecord,
        producer_evidence: EvidenceBundleRecord,
    ) -> EvidenceReferenceRecord:
        values = [
            item
            for item in self.repository.list(
                EvidenceReferenceRecord, project_id=reviewer.project_id
            )
            if item.assignment_id == reviewer.assignment_id
            and item.source_evidence_bundle_id
            == producer_evidence.evidence_bundle_id
            and item.consumed_by_review_id is None
        ]
        if len(values) > 1:
            raise PermissionError("reviewer has multiple unused evidence references")
        if values:
            return values[0]
        encoded = json.dumps(
            producer_evidence.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return self.orchestration.create_remote_evidence_reference(
            reviewer.assignment_id,
            source_identity=(
                "keeper-evidence:" + producer_evidence.evidence_bundle_id
            ),
            sha256=producer_evidence.content_digest,
            size_bytes=len(encoded),
            source_evidence_bundle_id=producer_evidence.evidence_bundle_id,
        )

    def _validated_evidence(
        self, assignment: AssignmentRecord
    ) -> EvidenceBundleRecord:
        values = [
            item
            for item in self.repository.list(
                EvidenceBundleRecord, project_id=assignment.project_id
            )
            if item.assignment_id == assignment.assignment_id
        ]
        if len(values) != 1 or values[0].state != EvidenceState.VALIDATED:
            raise PermissionError("assignment lacks one validated evidence bundle")
        return values[0]

    def _active_workspace(
        self, assignment: AssignmentRecord
    ) -> WorkspaceReservationRecord | None:
        values = [
            item
            for item in self.repository.list(
                WorkspaceReservationRecord, project_id=assignment.project_id
            )
            if item.assignment_id == assignment.assignment_id
            and item.state == "ACTIVE"
        ]
        if len(values) > 1:
            raise PermissionError("assignment has multiple active workspaces")
        return values[0] if values else None

    def _runnable_work_item(
        self, workflow: WorkflowRecord
    ) -> WorkItemRecord | None:
        items = self._work_items(workflow)
        by_id = {item.work_item_id: item for item in items}
        assignments = self._assignments(workflow)
        assigned = {item.work_item_id for item in assignments}
        candidates = [
            item
            for item in items
            if item.state == WorkItemState.READY
            and item.work_item_id not in assigned
            and item.required_roles
            and all(
                by_id[dependency].state == WorkItemState.COMPLETED
                for dependency in item.dependencies
            )
        ]
        candidates.sort(key=lambda item: (item.created_at, item.work_item_id))
        return candidates[0] if candidates else None

    def _work_items(self, workflow: WorkflowRecord) -> tuple[WorkItemRecord, ...]:
        return tuple(
            item
            for item in self.repository.list(
                WorkItemRecord, project_id=workflow.project_id
            )
            if item.workflow_id == workflow.workflow_id
        )

    def _assignments(
        self, workflow: WorkflowRecord
    ) -> tuple[AssignmentRecord, ...]:
        return tuple(
            item
            for item in self.repository.list(
                AssignmentRecord, project_id=workflow.project_id
            )
            if item.workflow_id == workflow.workflow_id
        )

    @staticmethod
    def _result(
        workflow: WorkflowRecord,
        state: str,
        detail: str,
        *,
        work_item: WorkItemRecord | None = None,
        assignment: AssignmentRecord | None = None,
    ) -> CompletionStepResult:
        return CompletionStepResult(
            workflow.project_id,
            workflow.workflow_id,
            state,
            detail,
            work_item.work_item_id if work_item else None,
            assignment.assignment_id if assignment else None,
        )
