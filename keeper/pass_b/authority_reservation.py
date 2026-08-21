from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from keeper.executive.authority_gateway import (
    AuthorityExecutionPlan,
    ProductionAuthorityBackedSpecialistGateway,
)
from keeper.executive.enums import ActionCategory, TaskStatus
from keeper.executive.models import ExecutiveTask, ProjectCharter
from keeper.pass_b.enums import AssignmentRole
from keeper.pass_b.launch_authority import TestLaunchAuthority
from keeper.pass_b.models import (
    AssignmentRecord,
    ExecutionProfileRecord,
    ProviderRecord,
    ProviderSelectionRecord,
    WorkflowRecord,
    WorkItemRecord,
    WorkspaceReservationRecord,
)
from keeper.pass_b.repository import canonical_workspace_path


class _ProjectStatusReader(Protocol):
    def __call__(self, project_id: str) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class PreparedAuthorityReservation:
    authority_attempt_id: str
    reservation_plan_digest: str
    composition_identity: str
    plan: object

    def __post_init__(self) -> None:
        if (
            not self.authority_attempt_id
            or len(self.reservation_plan_digest) != 64
            or self.composition_identity
            not in {"TEST_AUTHORITY", "PRODUCTION_AUTHORITY"}
        ):
            raise ValueError("prepared Authority reservation is invalid")


class AuthorityAttemptReservation(Protocol):
    def prepare(
        self,
        workflow: WorkflowRecord,
        work_item: WorkItemRecord,
        assignment: AssignmentRecord,
        profile: ExecutionProfileRecord,
        selection: ProviderSelectionRecord,
        provider: ProviderRecord,
        workspace: WorkspaceReservationRecord,
        *,
        reviewer_attempt_id: str,
    ) -> PreparedAuthorityReservation: ...

    def reserve(self, prepared: PreparedAuthorityReservation) -> None: ...


class UnavailableAuthorityAttemptReservation:
    def prepare(
        self,
        workflow: WorkflowRecord,
        work_item: WorkItemRecord,
        assignment: AssignmentRecord,
        profile: ExecutionProfileRecord,
        selection: ProviderSelectionRecord,
        provider: ProviderRecord,
        workspace: WorkspaceReservationRecord,
        *,
        reviewer_attempt_id: str,
    ) -> PreparedAuthorityReservation:
        del (
            workflow,
            work_item,
            assignment,
            profile,
            selection,
            provider,
            workspace,
            reviewer_attempt_id,
        )
        raise PermissionError(
            "Authority attempt reservation is not configured"
        )

    def reserve(self, prepared: PreparedAuthorityReservation) -> None:
        del prepared
        raise PermissionError(
            "Authority attempt reservation is not configured"
        )


@dataclass(frozen=True, slots=True)
class _TestReservationPlan:
    workflow: WorkflowRecord
    work_item: WorkItemRecord
    assignment: AssignmentRecord
    provider: ProviderRecord
    workspace: WorkspaceReservationRecord
    profile: ExecutionProfileRecord
    selection: ProviderSelectionRecord


class TestAuthorityAttemptReservation:
    """Explicit deterministic reservation seam; never valid in production."""

    __test__ = False

    def __init__(self, launch_authority: TestLaunchAuthority) -> None:
        if type(launch_authority) is not TestLaunchAuthority:
            raise TypeError(
                "test reservation requires the exact test launch authority"
            )
        self._launch_authority = launch_authority
        self.reserve_calls = 0

    def prepare(
        self,
        workflow: WorkflowRecord,
        work_item: WorkItemRecord,
        assignment: AssignmentRecord,
        profile: ExecutionProfileRecord,
        selection: ProviderSelectionRecord,
        provider: ProviderRecord,
        workspace: WorkspaceReservationRecord,
        *,
        reviewer_attempt_id: str,
    ) -> PreparedAuthorityReservation:
        _validate_prepared_binding(
            workflow,
            work_item,
            assignment,
            profile,
            selection,
            provider,
            workspace,
        )
        authority_attempt_id = (
            f"test-authority:{assignment.assignment_id}:{reviewer_attempt_id}"
        )
        plan = _TestReservationPlan(
            workflow,
            work_item,
            assignment,
            provider,
            workspace,
            profile,
            selection,
        )
        digest = _digest(
            {
                "composition_identity": "TEST_AUTHORITY",
                "authority_attempt_id": authority_attempt_id,
                "workflow": workflow.to_dict(),
                "work_item": work_item.to_dict(),
                "assignment": assignment.to_dict(),
                "profile": plan.profile.to_dict(),
                "selection": plan.selection.to_dict(),
                "provider": provider.to_dict(),
                "workspace": workspace.to_dict(),
            }
        )
        return PreparedAuthorityReservation(
            authority_attempt_id,
            digest,
            "TEST_AUTHORITY",
            plan,
        )

    def reserve(self, prepared: PreparedAuthorityReservation) -> None:
        if (
            type(prepared.plan) is not _TestReservationPlan
            or prepared.composition_identity != "TEST_AUTHORITY"
        ):
            raise PermissionError("test Authority reservation plan is invalid")
        plan = prepared.plan
        expected = _digest(
            {
                "composition_identity": "TEST_AUTHORITY",
                "authority_attempt_id": prepared.authority_attempt_id,
                "workflow": plan.workflow.to_dict(),
                "work_item": plan.work_item.to_dict(),
                "assignment": plan.assignment.to_dict(),
                "profile": plan.profile.to_dict(),
                "selection": plan.selection.to_dict(),
                "provider": plan.provider.to_dict(),
                "workspace": plan.workspace.to_dict(),
            }
        )
        if expected != prepared.reservation_plan_digest:
            raise PermissionError(
                "test Authority reservation digest changed"
            )
        self._launch_authority.reserve(
            plan.workflow,
            plan.work_item,
            plan.assignment,
            plan.provider,
            plan.workspace,
            prepared.authority_attempt_id,
        )
        self.reserve_calls += 1


class ProductionAuthorityAttemptReservation:
    """Production-only adapter over the hardened Executive Authority gateway."""

    __slots__ = ("__gateway", "__project_status")

    def __init__(
        self,
        gateway: ProductionAuthorityBackedSpecialistGateway,
        project_status: _ProjectStatusReader,
    ) -> None:
        if type(gateway) is not ProductionAuthorityBackedSpecialistGateway:
            raise TypeError(
                "production reservation requires the exact production gateway"
            )
        self.__gateway = gateway
        self.__project_status = project_status

    def prepare(
        self,
        workflow: WorkflowRecord,
        work_item: WorkItemRecord,
        assignment: AssignmentRecord,
        profile: ExecutionProfileRecord,
        selection: ProviderSelectionRecord,
        provider: ProviderRecord,
        workspace: WorkspaceReservationRecord,
        *,
        reviewer_attempt_id: str,
    ) -> PreparedAuthorityReservation:
        _validate_prepared_binding(
            workflow,
            work_item,
            assignment,
            profile,
            selection,
            provider,
            workspace,
        )
        if not provider.authority_registration_id:
            raise PermissionError(
                "production provider lacks an Authority registration"
            )
        status = self.__project_status(assignment.project_id)
        project = status.get("project_summary")
        charter_value = status.get("active_charter")
        if (
            not isinstance(project, dict)
            or not isinstance(charter_value, dict)
            or project.get("project_id") != assignment.project_id
            or project.get("state") != "ACTIVE"
            or project.get("active_charter_id") != assignment.charter_id
            or project.get("active_charter_revision")
            != assignment.charter_revision
        ):
            raise PermissionError(
                "Authority reservation requires the current active project"
            )
        charter = ProjectCharter.from_dict(dict(charter_value))
        if (
            charter.project_id != assignment.project_id
            or charter.charter_id != assignment.charter_id
            or charter.revision != assignment.charter_revision
            or charter.status != "ACTIVE"
            or not charter.founder_approval_record_id
            or not charter.founder_authorization_capability_digest
        ):
            raise PermissionError(
                "Authority reservation requires the active Founder charter"
            )
        specialists = self.__gateway.specialists(charter)
        matches = tuple(
            specialist
            for specialist in specialists
            if specialist.provider_id == assignment.provider_id
            and specialist.model_id == assignment.model_id
            and specialist.session_id == assignment.session_id
        )
        if len(matches) != 1:
            raise PermissionError(
                "prepared provider is not one exact qualified specialist"
            )
        now = assignment.updated_at
        task = ExecutiveTask(
            task_id=assignment.assignment_id,
            project_id=assignment.project_id,
            charter_id=assignment.charter_id,
            charter_revision=assignment.charter_revision,
            workflow_id=assignment.workflow_id,
            stage_id=assignment.work_item_id,
            title=work_item.title,
            objective=work_item.objective,
            role=assignment.role.casefold(),
            required_capabilities=profile.required_capabilities,
            instructions=(work_item.objective,),
            constraints=charter.constraints,
            dependencies=work_item.dependencies,
            provider_id=assignment.provider_id,
            model_id=assignment.model_id,
            session_id=assignment.session_id,
            status=TaskStatus.ASSIGNED,
            authority_category=(
                ActionCategory.REVIEW
                if assignment.role == AssignmentRole.REVIEWER
                else ActionCategory.WRITE
            ),
            inputs=(),
            expected_outputs=assignment.expected_evidence,
            evidence_requirements=assignment.expected_evidence,
            review_requirements=charter.review_requirements,
            retry_count=0,
            max_retries=0,
            attempt_history=(),
            result_disposition=None,
            created_at=now,
            updated_at=now,
            revision=assignment.revision,
        )
        plan = self.__gateway.prepare(
            task,
            charter,
            matches[0],
            task_id=assignment.assignment_id,
            role=assignment.role.casefold(),
            workspace=workspace.canonical_path,
            reservation_nonce=reviewer_attempt_id,
        )
        if (
            plan.project_id != assignment.project_id
            or plan.charter_id != assignment.charter_id
            or plan.charter_revision != assignment.charter_revision
            or plan.workflow_id != assignment.workflow_id
            or plan.task_id != assignment.assignment_id
            or plan.task_revision != assignment.revision
            or plan.stage_id != assignment.work_item_id
            or plan.role != assignment.role.casefold()
            or plan.provider_id != assignment.provider_id
            or plan.model_id != assignment.model_id
            or plan.session_id != assignment.session_id
            or plan.registration_id != provider.authority_registration_id
            or canonical_workspace_path(Path(plan.workspace))
            != workspace.canonical_path
        ):
            raise PermissionError(
                "production Authority reservation plan does not match Pass B"
            )
        digest = _digest(
            {
                "composition_identity": "PRODUCTION_AUTHORITY",
                "plan": asdict(plan),
            }
        )
        return PreparedAuthorityReservation(
            plan.authority_attempt_id,
            digest,
            "PRODUCTION_AUTHORITY",
            plan,
        )

    def reserve(self, prepared: PreparedAuthorityReservation) -> None:
        if (
            type(prepared.plan) is not AuthorityExecutionPlan
            or prepared.composition_identity != "PRODUCTION_AUTHORITY"
        ):
            raise PermissionError(
                "production Authority reservation plan is invalid"
            )
        expected = _digest(
            {
                "composition_identity": "PRODUCTION_AUTHORITY",
                "plan": asdict(prepared.plan),
            }
        )
        if expected != prepared.reservation_plan_digest:
            raise PermissionError(
                "production Authority reservation digest changed"
            )
        self.__gateway.reserve(prepared.plan)


def _validate_prepared_binding(
    workflow: WorkflowRecord,
    work_item: WorkItemRecord,
    assignment: AssignmentRecord,
    profile: ExecutionProfileRecord,
    selection: ProviderSelectionRecord,
    provider: ProviderRecord,
    workspace: WorkspaceReservationRecord,
) -> None:
    profile_id = assignment.usage_policy.get("execution_profile_id")
    selection_id = assignment.usage_policy.get("provider_selection_id")
    if (
        workflow.project_id != assignment.project_id
        or workflow.charter_id != assignment.charter_id
        or workflow.charter_revision != assignment.charter_revision
        or workflow.workflow_id != assignment.workflow_id
        or work_item.project_id != assignment.project_id
        or work_item.charter_id != assignment.charter_id
        or work_item.charter_revision != assignment.charter_revision
        or work_item.workflow_id != assignment.workflow_id
        or work_item.work_item_id != assignment.work_item_id
        or profile_id != profile.execution_profile_id
        or selection_id != selection.provider_selection_id
        or profile.project_id != assignment.project_id
        or profile.charter_id != assignment.charter_id
        or profile.charter_revision != assignment.charter_revision
        or profile.workflow_id != assignment.workflow_id
        or profile.work_item_id != assignment.work_item_id
        or profile.workspace_id != assignment.workspace_id
        or profile.canonical_workspace_path != workspace.canonical_path
        or selection.execution_profile_id != profile.execution_profile_id
        or selection.assignment_id != assignment.assignment_id
        or selection.project_id != assignment.project_id
        or selection.charter_id != assignment.charter_id
        or selection.charter_revision != assignment.charter_revision
        or selection.workflow_id != assignment.workflow_id
        or selection.work_item_id != assignment.work_item_id
        or selection.provider_id != assignment.provider_id
        or selection.account_id != assignment.account_id
        or selection.session_id != assignment.session_id
        or selection.model_id != assignment.model_id
        or provider.provider_id != assignment.provider_id
        or workspace.assignment_id != assignment.assignment_id
        or workspace.workspace_id != assignment.workspace_id
    ):
        raise PermissionError(
            "prepared Authority reservation binding is inconsistent"
        )


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()
