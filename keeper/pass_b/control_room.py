from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

from keeper.pass_b.conversation import (
    CharterDraftContextRecord,
    ProjectStatusReader,
    reconcile_delegated_grants,
)
from keeper.pass_b.enums import AssignmentState
from keeper.pass_b.models import (
    AssignmentRecord,
    AttemptRecord,
    ConversationMessageRecord,
    DelegatedModeGrantRecord,
    EvidenceBundleRecord,
    EvidenceReferenceRecord,
    ExecutionProfileRecord,
    PauseReasonRecord,
    PresentationStateRecord,
    ProviderAccountRecord,
    ProviderRecord,
    ProviderSelectionRecord,
    ProviderSessionRecord,
    ResumeCheckpointRecord,
    ReviewRecord,
    UsagePoolRecord,
    WorkItemRecord,
    WorkspaceReservationRecord,
    WriteReservationRecord,
)
from keeper.pass_b.repository import PassBRepository


AuthorityHealth = Callable[[], dict[str, Any]]


@dataclass(frozen=True, slots=True)
class ControlRoomSnapshot:
    conversation: dict[str, Any]
    control_room: dict[str, Any]
    project: dict[str, Any]
    providers: dict[str, Any]
    safety: dict[str, Any]
    presentation: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "conversation": self.conversation,
            "control_room": self.control_room,
            "project": self.project,
            "providers": self.providers,
            "safety": self.safety,
            "presentation": self.presentation,
        }


class ControlRoomService:
    def __init__(
        self,
        repository: PassBRepository,
        *,
        authority_health: AuthorityHealth | None = None,
        project_status: ProjectStatusReader,
    ) -> None:
        self.repository = repository
        self.authority_health = authority_health or (
            lambda: {"state": "NOT_CONFIGURED"}
        )
        self.project_status = project_status

    def snapshot(self, project_id: str | None = None) -> ControlRoomSnapshot:
        assignments = self.repository.list(
            AssignmentRecord, project_id=project_id
        )
        work_items = self.repository.list(WorkItemRecord, project_id=project_id)
        execution_profiles = self.repository.list(
            ExecutionProfileRecord, project_id=project_id
        )
        provider_selections = self.repository.list(
            ProviderSelectionRecord, project_id=project_id
        )
        assignment_ids = {
            item.assignment_id for item in assignments
        }
        attempts = [
            item
            for item in self.repository.list(AttemptRecord)
            if project_id is None
            or item.assignment_id in assignment_ids
        ]
        reviews = self.repository.list(ReviewRecord, project_id=project_id)
        evidence = self.repository.list(
            EvidenceBundleRecord, project_id=project_id
        )
        evidence_references = self.repository.list(
            EvidenceReferenceRecord, project_id=project_id
        )
        workspaces = self.repository.list(
            WorkspaceReservationRecord, project_id=project_id
        )
        writes = self.repository.list(WriteReservationRecord)
        pauses = [
            item
            for item in self.repository.list(PauseReasonRecord)
            if project_id is None
            or item.assignment_id in assignment_ids
        ]
        checkpoints = self.repository.list(
            ResumeCheckpointRecord, project_id=project_id
        )
        messages = self.repository.list(
            ConversationMessageRecord, project_id=project_id
        )
        contexts = self.repository.list(
            CharterDraftContextRecord, project_id=project_id
        )

        providers = self.repository.list(ProviderRecord)
        accounts = self.repository.list(ProviderAccountRecord)
        sessions = self.repository.list(ProviderSessionRecord)
        usage = self.repository.list(UsagePoolRecord)
        presentation = self.repository.list(PresentationStateRecord)
        attempt_by_assignment = {
            item.assignment_id: item for item in attempts
        }
        active_delegation = [
            item
            for item in reconcile_delegated_grants(
                self.repository, project_status=self.project_status
            )
            if project_id is None or item.project_id == project_id
        ]
        grant_history = [
            item
            for item in self.repository.list(DelegatedModeGrantRecord)
            if project_id is None or item.project_id == project_id
        ]
        uncertain = [
            item
            for item in assignments
            if item.state == AssignmentState.UNCERTAIN
        ]
        waiting = [
            item
            for item in assignments
            if item.state == AssignmentState.WAITING_FOR_USAGE_RESET
        ]
        current_context = next(
            (
                item
                for item in reversed(contexts)
                if item.state != "SUPERSEDED"
            ),
            None,
        )
        selected_presentation = next(
            (
                item
                for item in reversed(presentation)
                if item.project_id == project_id
            ),
            presentation[-1] if presentation else None,
        )
        return ControlRoomSnapshot(
            conversation={
                "messages": [item.to_dict() for item in messages],
                "charter_proposal": (
                    current_context.to_dict()
                    if current_context is not None
                    else None
                ),
                "approval_required": bool(
                    current_context
                    and current_context.state
                    in {"PROPOSED", "APPROVAL_REQUESTED"}
                ),
                "recovery_prompts": [
                    {
                        "assignment_id": item.assignment_id,
                        "message": (
                            "External outcome is uncertain. Review evidence "
                            "before any retry."
                        ),
                    }
                    for item in uncertain
                ],
            },
            control_room={
                "assignment_counts": dict(
                    Counter(item.state for item in assignments)
                ),
                "active_assignments": [
                    item.to_dict()
                    for item in assignments
                    if item.state
                    in {
                        AssignmentState.LAUNCH_CLAIMED,
                        AssignmentState.RUNNING,
                    }
                ],
                "waiting_for_usage_reset": [
                    item.to_dict() for item in waiting
                ],
                "usage_pools": [item.to_dict() for item in usage],
                "provider_sessions": [item.to_dict() for item in sessions],
                "workspace_reservations": [
                    item.to_dict() for item in workspaces
                ],
                "recent_evidence": [
                    item.to_dict() for item in evidence[-10:]
                ],
                "recent_evidence_references": [
                    item.to_dict() for item in evidence_references[-10:]
                ],
                "recent_reviews": [
                    item.to_dict() for item in reviews[-10:]
                ],
            },
            project={
                "project_id": project_id,
                "charter_revision": (
                    current_context.charter_revision
                    if current_context is not None
                    else None
                ),
                "work_items": [item.to_dict() for item in work_items],
                "execution_profiles": [
                    item.to_dict() for item in execution_profiles
                ],
                "provider_selections": [
                    item.to_dict() for item in provider_selections
                ],
                "assignments": [
                    {
                        **item.to_dict(),
                        "attempt": (
                            attempt_by_assignment[item.assignment_id].to_dict()
                            if item.assignment_id in attempt_by_assignment
                            else None
                        ),
                    }
                    for item in assignments
                ],
                "workspaces": [item.to_dict() for item in workspaces],
                "write_reservations": [
                    item.to_dict()
                    for item in writes
                    if any(
                        workspace.assignment_id == item.assignment_id
                        for workspace in workspaces
                    )
                ],
                "evidence": [item.to_dict() for item in evidence],
                "reviews": [item.to_dict() for item in reviews],
                "evidence_references": [item.to_dict() for item in evidence_references],
            },
            providers={
                "providers": [item.to_dict() for item in providers],
                "accounts": [item.to_dict() for item in accounts],
                "sessions": [item.to_dict() for item in sessions],
                "usage_pools": [item.to_dict() for item in usage],
            },
            safety={
                "authority": self.authority_health(),
                "delegated_mode": [
                    item.to_dict() for item in active_delegation
                ],
                "delegated_mode_history": [
                    item.to_dict() for item in grant_history
                ],
                "uncertain_assignments": [
                    item.to_dict() for item in uncertain
                ],
                "open_pauses": [
                    item.to_dict()
                    for item in pauses
                    if item.resolved_at is None
                ],
                "resume_checkpoints": [
                    item.to_dict()
                    for item in checkpoints
                    if item.resumed_at is None
                ],
                "prohibited_actions": (
                    "provider-self-approval",
                    "automatic-paid-fallback",
                    "provider-code-in-trusted-process",
                    "unapproved-push",
                    "unapproved-deployment",
                    "live-trading",
                ),
            },
            presentation=(
                selected_presentation.to_dict()
                if selected_presentation is not None
                else {
                    "form": "default",
                    "mode": "CONVERSATION",
                    "expression": "neutral",
                    "intensity": 0.25,
                    "background": "black-gold",
                    "ambient_effect": "none",
                    "authority_effect": "NONE",
                }
            ),
        )
