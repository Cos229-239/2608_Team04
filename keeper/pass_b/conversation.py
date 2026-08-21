from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from keeper.executive.enums import CharterStatus
from keeper.executive.intake import ConversationIntake, IntakeResult, IntakeValue
from keeper.executive.models import (
    FounderApprovalChallenge,
    ProjectCharter,
    ProjectRecord,
)
from keeper.pass_b.enums import DelegatedModeState
from keeper.pass_b.models import (
    ConversationMessageRecord,
    DelegatedModeGrantRecord,
    PassBRecord,
)
from keeper.pass_b.repository import PassBRepository


class ConversationExecutive(Protocol):
    def begin(self, message: str) -> tuple[ProjectRecord, IntakeResult]: ...

    def draft(
        self,
        project_id: str,
        intake: IntakeResult,
        *,
        founder_revisions: dict[str, Any] | None = None,
    ) -> ProjectCharter: ...

    def propose_charter(self, charter: ProjectCharter) -> ProjectCharter: ...

    def request_charter_approval(
        self, charter: ProjectCharter
    ) -> FounderApprovalChallenge: ...


@dataclass(frozen=True, slots=True)
class CharterDraftContextRecord(PassBRecord):
    charter_draft_context_id: str
    project_id: str
    intake: dict[str, Any]
    charter_id: str
    charter_revision: int
    state: str
    created_at: str
    updated_at: str
    revision: int

    KIND = "charter_draft_context"
    ID_FIELD = "charter_draft_context_id"

    def __post_init__(self) -> None:
        if self.charter_revision < 1 or self.state not in {
            "DRAFT",
            "PROPOSED",
            "APPROVAL_REQUESTED",
            "APPROVED",
            "SUPERSEDED",
        }:
            raise ValueError("charter draft context is invalid")
        _parse_time(self.created_at)
        _parse_time(self.updated_at)
        if self.revision < 1:
            raise ValueError("charter draft revision must be positive")


@dataclass(frozen=True, slots=True)
class ConversationOutcome:
    project: ProjectRecord
    charter: ProjectCharter
    unresolved_questions: tuple[str, ...]
    proposed_assumptions: tuple[str, ...]
    approval_required: bool


@dataclass(frozen=True, slots=True)
class WorkflowStepBlueprint:
    title: str
    role: str
    objective: str
    dependencies: tuple[str, ...]
    independent_review: bool


@dataclass(frozen=True, slots=True)
class WorkflowBlueprint:
    project_id: str
    charter_id: str
    charter_revision: int
    strategy: str
    explanation: str
    steps: tuple[WorkflowStepBlueprint, ...]


class ConversationService:
    def __init__(
        self,
        repository: PassBRepository,
        executive: ConversationExecutive,
    ) -> None:
        self.repository = repository
        self.executive = executive

    def begin(self, message: str) -> ConversationOutcome:
        self._message(None, "FOUNDER", message, "PROJECT_REQUEST")
        project, intake = self.executive.begin(message)
        draft = self.executive.draft(project.project_id, intake)
        proposed = self.executive.propose_charter(draft)
        now = _now()
        context = CharterDraftContextRecord(
            charter_draft_context_id=uuid.uuid4().hex,
            project_id=project.project_id,
            intake=_intake_to_dict(intake),
            charter_id=proposed.charter_id,
            charter_revision=proposed.revision,
            state="PROPOSED",
            created_at=now,
            updated_at=now,
            revision=1,
        )
        self.repository.insert(context)
        self._message(
            project.project_id,
            "KEEPER",
            self._proposal_summary(proposed, intake),
            "CHARTER_PROPOSAL",
        )
        return ConversationOutcome(
            project,
            proposed,
            intake.unresolved_questions,
            intake.proposed_assumptions,
            True,
        )

    def continue_project(
        self, project_id: str, message: str
    ) -> ConversationOutcome | None:
        """Continue one selected project without silently creating another."""
        if not message.strip():
            raise ValueError("conversation message cannot be empty")
        current = self.current_context(project_id)
        self._message(project_id, "FOUNDER", message, "PROJECT_CONTINUATION")
        if current.state == "APPROVAL_REQUESTED":
            raise PermissionError(
                "charter approval is already pending; approve or revise it explicitly"
            )
        if current.state == "APPROVED":
            self._message(
                project_id,
                "KEEPER",
                "Continuation recorded. Execution remains bound to the current "
                "Founder-approved charter; changed scope requires a new revision.",
                "CHARTER_BOUND_CONTINUATION",
            )
            return None
        extracted = ConversationIntake().extract(message)
        replacements = {
            name: item.value
            for name, item in extracted.fields.items()
            if item.provenance == "EXPLICIT"
        }
        if not replacements:
            raise ValueError(
                "continuation did not provide an explicit charter clarification"
            )
        return self.revise(project_id, replacements)

    def revise(
        self, project_id: str, replacements: dict[str, Any]
    ) -> ConversationOutcome:
        current = self.current_context(project_id)
        intake = ConversationIntake.revise(
            _intake_from_dict(current.intake), replacements=replacements
        )
        draft = self.executive.draft(project_id, intake)
        proposed = self.executive.propose_charter(draft)
        now = _now()
        self.repository.replace(
            replace(
                current,
                state="SUPERSEDED",
                updated_at=now,
                revision=current.revision + 1,
            ),
            expected_revision=current.revision,
        )
        context = CharterDraftContextRecord(
            charter_draft_context_id=uuid.uuid4().hex,
            project_id=project_id,
            intake=_intake_to_dict(intake),
            charter_id=proposed.charter_id,
            charter_revision=proposed.revision,
            state="PROPOSED",
            created_at=now,
            updated_at=now,
            revision=1,
        )
        self.repository.insert(context)
        self._message(
            project_id,
            "FOUNDER",
            f"Revised charter fields: {', '.join(sorted(replacements))}",
            "CHARTER_REVISION",
        )
        self._message(
            project_id,
            "KEEPER",
            self._proposal_summary(proposed, intake),
            "CHARTER_PROPOSAL",
        )
        return ConversationOutcome(
            ProjectRecord(
                project_id=project_id,
                name=proposed.title,
                project_type=proposed.project_type,
                state="AWAITING_CHARTER_APPROVAL",
                active_charter_id=None,
                active_charter_revision=None,
                pause_reason=None,
                created_at=proposed.created_at,
                updated_at=proposed.updated_at,
            ),
            proposed,
            intake.unresolved_questions,
            intake.proposed_assumptions,
            True,
        )

    def request_approval(self, project_id: str) -> FounderApprovalChallenge:
        current = self.current_context(project_id)
        if current.state != "PROPOSED":
            raise PermissionError("only the current proposed charter can be approved")
        charter = self._charter_from_context(current)
        challenge = self.executive.request_charter_approval(charter)
        now = _now()
        self.repository.replace(
            replace(
                current,
                state="APPROVAL_REQUESTED",
                updated_at=now,
                revision=current.revision + 1,
            ),
            expected_revision=current.revision,
        )
        return challenge

    def current_context(self, project_id: str) -> CharterDraftContextRecord:
        values = [
            item
            for item in self.repository.list(
                CharterDraftContextRecord, project_id=project_id
            )
            if item.state != "SUPERSEDED"
        ]
        if len(values) != 1:
            raise RuntimeError("project does not have one current charter draft")
        return values[0]

    def _charter_from_context(
        self, context: CharterDraftContextRecord
    ) -> ProjectCharter:
        # Draft/proposal truth remains in the Executive repository. Re-drafting
        # the exact durable intake returns the current version-bound proposal.
        draft = self.executive.draft(
            context.project_id, _intake_from_dict(context.intake)
        )
        if (
            draft.charter_id != context.charter_id
            or draft.revision != context.charter_revision
        ):
            raise PermissionError("durable charter context is stale")
        return draft

    def _message(
        self,
        project_id: str | None,
        speaker: str,
        text: str,
        intent: str,
    ) -> ConversationMessageRecord:
        record = ConversationMessageRecord(
            message_id=uuid.uuid4().hex,
            project_id=project_id,
            speaker=speaker,
            text=text,
            intent=intent,
            durable_authority=False,
            created_at=_now(),
            revision=1,
        )
        self.repository.insert(record)
        return record

    @staticmethod
    def _proposal_summary(
        charter: ProjectCharter, intake: IntakeResult
    ) -> str:
        questions = (
            " Material questions: " + "; ".join(intake.unresolved_questions)
            if intake.unresolved_questions
            else ""
        )
        return (
            f"Proposed charter revision {charter.revision}: {charter.title}. "
            f"Goals: {', '.join(charter.deliverables)}. "
            f"Exclusions: {', '.join(charter.non_goals) or 'none recorded'}. "
            "Conversation text is not approval; explicit Founder confirmation "
            f"is required.{questions}"
        )


class DynamicWorkflowDesigner:
    """Charter-derived workflow selection; there is no universal pipeline."""

    def design(self, charter: ProjectCharter) -> WorkflowBlueprint:
        if (
            charter.status != CharterStatus.ACTIVE
            or not charter.founder_approval_record_id
            or not charter.founder_authorization_capability_digest
        ):
            raise PermissionError("workflow design requires active Founder authority")
        templates: dict[str, tuple[tuple[str, str, str, bool], ...]] = {
            "software": (
                ("Plan", "PLANNER", "Translate charter into bounded work", False),
                ("Implement", "IMPLEMENTER", "Create assigned deliverables", False),
                ("Test", "TESTER", "Verify behavior and failure paths", True),
            ),
            "research": (
                ("Research plan", "PLANNER", "Bound questions and sources", False),
                ("Investigate", "RESEARCHER", "Collect structured evidence", False),
                (
                    "Synthesize",
                    "DOCUMENTATION_SPECIALIST",
                    "Produce the supported report",
                    False,
                ),
            ),
            "video": (
                ("Creative plan", "PLANNER", "Define audience and structure", False),
                (
                    "Produce assets",
                    "IMPLEMENTER",
                    "Create charter-approved media assets",
                    False,
                ),
            ),
            "writing": (
                ("Outline", "PLANNER", "Design structure and voice", False),
                (
                    "Draft",
                    "DOCUMENTATION_SPECIALIST",
                    "Create the manuscript",
                    False,
                ),
                (
                    "Revise",
                    "DOCUMENTATION_SPECIALIST",
                    "Address accepted findings",
                    False,
                ),
            ),
        }
        selected = templates.get(
            charter.project_type,
            (
                ("Plan", "PLANNER", "Design a charter-specific workflow", False),
                ("Produce", "IMPLEMENTER", "Create the deliverables", False),
            ),
        )
        steps: list[WorkflowStepBlueprint] = []
        previous: str | None = None
        for title, role, objective, independent in selected:
            steps.append(
                WorkflowStepBlueprint(
                    title=title,
                    role=role,
                    objective=objective,
                    dependencies=(previous,) if previous else (),
                    independent_review=independent,
                )
            )
            previous = title
        return WorkflowBlueprint(
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            strategy=f"{charter.project_type}-adaptive",
            explanation=(
                "Stages were selected from the approved project type, "
                "deliverables, evidence needs, and review requirements."
            ),
            steps=tuple(steps),
        )


class ProjectStatusReader(Protocol):
    def __call__(self, project_id: str) -> dict[str, Any]: ...


ALLOWED_DELEGATED_ACTIONS = frozenset(
    {
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
        "MARK_SAFE_IDEMPOTENT_RETRY",
    }
)


def activate_delegated_mode(
    repository: PassBRepository,
    *,
    project_status: ProjectStatusReader,
    project_id: str,
    charter: ProjectCharter,
    founder_identity: str,
    founder_approval_id: str,
    founder_approval_digest: str,
    scope: tuple[str, ...],
    expires_at: str,
    max_actions: int = 100,
) -> DelegatedModeGrantRecord:
    normalized_scope = tuple(_delegated_action(item) for item in scope)
    project, active_charter = _current_project_charter(
        project_status, project_id
    )
    if (
        charter.project_id != project_id
        or charter.status != CharterStatus.ACTIVE
        or charter.delegation_mode not in {"DELEGATED", "FULL_DELEGATION"}
        or not charter.founder_approval_record_id
        or not charter.founder_approval_identity
        or not charter.founder_authorization_capability_digest
        or founder_approval_id != charter.founder_approval_record_id
        or founder_identity != charter.founder_approval_identity
        or founder_approval_digest
        != charter.founder_authorization_capability_digest
        or active_charter.get("charter_id") != charter.charter_id
        or active_charter.get("revision") != charter.revision
        or active_charter.get("founder_approval_record_id")
        != founder_approval_id
        or active_charter.get("founder_approval_identity")
        != founder_identity
        or active_charter.get("founder_authorization_capability_digest")
        != founder_approval_digest
        or not normalized_scope
        or len(set(normalized_scope)) != len(normalized_scope)
        or any(item not in ALLOWED_DELEGATED_ACTIONS for item in normalized_scope)
        or max_actions < 1
    ):
        raise PermissionError("delegated mode is outside Founder charter authority")
    now = _now()
    if _parse_time(expires_at) <= _parse_time(now):
        raise ValueError("delegated mode expiry must be in the future")
    reconcile_delegated_grants(
        repository, project_status=project_status, observed_at=now
    )
    existing = repository.list(
        DelegatedModeGrantRecord, project_id=project_id
    )
    if any(
        item.founder_approval_id == founder_approval_id
        or (
            item.charter_id == charter.charter_id
            and item.charter_revision == charter.revision
            and item.state == DelegatedModeState.ACTIVE
        )
        for item in existing
    ):
        raise PermissionError(
            "delegated Founder approval was replayed or is already active"
        )
    record = DelegatedModeGrantRecord(
        delegated_mode_grant_id=uuid.uuid4().hex,
        project_id=project_id,
        charter_id=charter.charter_id,
        charter_revision=charter.revision,
        founder_identity=founder_identity,
        founder_approval_id=founder_approval_id,
        founder_approval_digest=founder_approval_digest,
        scope=normalized_scope,
        starts_at=now,
        expires_at=expires_at,
        state=DelegatedModeState.ACTIVE,
        revoked_at=None,
        created_at=now,
        updated_at=now,
        revision=1,
        project_generation=_project_generation(project, active_charter),
        max_actions=max_actions,
        actions_used=0,
        last_action_at=None,
    )
    repository.insert(record)
    return record


def validate_delegated_action(
    repository: PassBRepository,
    grant_id: str,
    *,
    project_status: ProjectStatusReader,
    project_id: str,
    charter_id: str,
    charter_revision: int,
    action: str,
    action_scope: dict[str, str] | None = None,
    observed_at: str | None = None,
) -> DelegatedModeGrantRecord:
    now = observed_at or _now()
    record = repository.get(DelegatedModeGrantRecord, grant_id)
    if (
        record.state == DelegatedModeState.ACTIVE
        and _parse_time(record.expires_at) <= _parse_time(now)
    ):
        expired = repository.replace(
            replace(
                record,
                state=DelegatedModeState.EXPIRED,
                updated_at=now,
                revision=record.revision + 1,
            ),
            expected_revision=record.revision,
        )
        raise PermissionError(
            f"delegated mode grant expired: {expired.delegated_mode_grant_id}"
        )
    project, active_charter = _current_project_charter(
        project_status, project_id
    )
    current_generation = _project_generation(project, active_charter)
    if (
        record.state == DelegatedModeState.ACTIVE
        and (
            record.project_id != project_id
            or record.charter_id != active_charter.get("charter_id")
            or record.charter_revision != active_charter.get("revision")
            or record.founder_approval_id
            != active_charter.get("founder_approval_record_id")
            or record.founder_identity
            != active_charter.get("founder_approval_identity")
            or record.founder_approval_digest
            != active_charter.get(
                "founder_authorization_capability_digest"
            )
            or record.project_generation != current_generation
        )
    ):
        repository.replace(
            replace(
                record,
                state=DelegatedModeState.SUPERSEDED,
                updated_at=now,
                revision=record.revision + 1,
            ),
            expected_revision=record.revision,
        )
        raise PermissionError("delegated mode grant is superseded")
    normalized_action = _delegated_action(action)
    if (
        record.state != DelegatedModeState.ACTIVE
        or _parse_time(record.starts_at) > _parse_time(now)
        or record.project_id != project_id
        or record.charter_id != charter_id
        or record.charter_revision != charter_revision
        or normalized_action not in ALLOWED_DELEGATED_ACTIONS
        or normalized_action not in record.scope
        or not _delegated_scope_allowed(
            active_charter, normalized_action, action_scope
        )
        or record.actions_used >= record.max_actions
    ):
        raise PermissionError(
            "delegated action is expired, revoked, stale, or out of scope"
        )
    return repository.replace(
        replace(
            record,
            actions_used=record.actions_used + 1,
            last_action_at=now,
            updated_at=now,
            revision=record.revision + 1,
        ),
        expected_revision=record.revision,
    )


def expire_delegated_grants(
    repository: PassBRepository,
    *,
    observed_at: str | None = None,
) -> tuple[DelegatedModeGrantRecord, ...]:
    now = observed_at or _now()
    expired: list[DelegatedModeGrantRecord] = []
    for record in repository.list(DelegatedModeGrantRecord):
        if (
            record.state == DelegatedModeState.ACTIVE
            and _parse_time(record.expires_at) <= _parse_time(now)
        ):
            expired.append(
                repository.replace(
                    replace(
                        record,
                        state=DelegatedModeState.EXPIRED,
                        updated_at=now,
                        revision=record.revision + 1,
                    ),
                    expected_revision=record.revision,
                )
            )
    return tuple(expired)


def reconcile_delegated_grants(
    repository: PassBRepository,
    *,
    project_status: ProjectStatusReader,
    observed_at: str | None = None,
) -> tuple[DelegatedModeGrantRecord, ...]:
    now = observed_at or _now()
    expire_delegated_grants(repository, observed_at=now)
    active: list[DelegatedModeGrantRecord] = []
    for record in repository.list(DelegatedModeGrantRecord):
        if record.state != DelegatedModeState.ACTIVE:
            continue
        try:
            project, charter = _current_project_charter(
                project_status, record.project_id
            )
        except (KeyError, PermissionError, RuntimeError, ValueError):
            continue
        if (
            record.charter_id != charter.get("charter_id")
            or record.charter_revision != charter.get("revision")
            or record.founder_approval_id
            != charter.get("founder_approval_record_id")
            or record.founder_identity
            != charter.get("founder_approval_identity")
            or record.founder_approval_digest
            != charter.get("founder_authorization_capability_digest")
            or record.project_generation
            != _project_generation(project, charter)
        ):
            repository.replace(
                replace(
                    record,
                    state=DelegatedModeState.SUPERSEDED,
                    updated_at=now,
                    revision=record.revision + 1,
                ),
                expected_revision=record.revision,
            )
            continue
        active.append(record)
    return tuple(active)


def revoke_delegated_mode(
    repository: PassBRepository, grant_id: str
) -> DelegatedModeGrantRecord:
    record = repository.get(DelegatedModeGrantRecord, grant_id)
    if record.state != DelegatedModeState.ACTIVE:
        raise PermissionError("delegated mode is not active")
    now = _now()
    return repository.replace(
        replace(
            record,
            state=DelegatedModeState.REVOKED,
            revoked_at=now,
            updated_at=now,
            revision=record.revision + 1,
        ),
        expected_revision=record.revision,
    )


def _current_project_charter(
    project_status: ProjectStatusReader, project_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        status = project_status(project_id)
    except (KeyError, RuntimeError, ValueError) as error:
        raise PermissionError("delegated project status is unavailable") from error
    project = status.get("project_summary")
    charter = status.get("active_charter")
    if (
        not isinstance(project, dict)
        or not isinstance(charter, dict)
        or project.get("project_id") != project_id
        or project.get("state") != "ACTIVE"
        or project.get("active_charter_id") != charter.get("charter_id")
        or project.get("active_charter_revision") != charter.get("revision")
        or charter.get("project_id") != project_id
        or charter.get("status") != "ACTIVE"
        or not charter.get("founder_approval_record_id")
        or not charter.get("founder_approval_identity")
        or not charter.get("founder_authorization_capability_digest")
    ):
        raise PermissionError(
            "delegated project lacks a current Founder-approved charter"
        )
    return project, charter


def _delegated_scope_allowed(
    charter: dict[str, Any],
    action: str,
    action_scope: dict[str, str] | None,
) -> bool:
    scope = action_scope or {}
    if any(
        key not in {"provider_id", "workspace"}
        or not isinstance(value, str)
        or not value
        for key, value in scope.items()
    ):
        return False
    provider_id = scope.get("provider_id")
    if provider_id is not None:
        approved = charter.get("approved_providers")
        if not isinstance(approved, (list, tuple)) or provider_id not in approved:
            return False
    workspace = scope.get("workspace")
    if workspace is not None:
        approved_workspaces = charter.get("workspaces")
        if not isinstance(approved_workspaces, (list, tuple)):
            return False
        candidate = Path(workspace).resolve()
        allowed = False
        for item in approved_workspaces:
            if not isinstance(item, str) or not item:
                continue
            root = Path(item).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                continue
            allowed = True
            break
        if not allowed:
            return False
    if action == "SELECT_APPROVED_PROVIDER" and provider_id is None:
        return False
    if action == "CREATE_ISOLATED_WORKTREE" and workspace is None:
        return False
    return True

def _project_generation(
    project: dict[str, Any], charter: dict[str, Any]
) -> str:
    value = {
        "project_id": project.get("project_id"),
        "project_state": project.get("state"),
        "charter_id": charter.get("charter_id"),
        "charter_revision": charter.get("revision"),
        "founder_approval_id": charter.get("founder_approval_record_id"),
        "founder_identity": charter.get("founder_approval_identity"),
        "founder_approval_digest": charter.get(
            "founder_authorization_capability_digest"
        ),
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()

def _intake_to_dict(value: IntakeResult) -> dict[str, Any]:
    return value.to_dict()


def _intake_from_dict(value: dict[str, Any]) -> IntakeResult:
    fields = value.get("fields")
    questions = value.get("unresolved_questions")
    assumptions = value.get("proposed_assumptions")
    if (
        not isinstance(fields, dict)
        or not isinstance(questions, list)
        or not isinstance(assumptions, list)
    ):
        raise ValueError("durable intake context is malformed")
    converted: dict[str, IntakeValue] = {}
    for key, item in fields.items():
        if not isinstance(key, str) or not isinstance(item, dict):
            raise ValueError("durable intake field is malformed")
        converted[key] = IntakeValue(
            item["value"],
            str(item["provenance"]),
            float(item["confidence"]),
            str(item["source_excerpt"]),
        )
    return IntakeResult(
        converted,
        tuple(str(item) for item in questions),
        tuple(str(item) for item in assumptions),
    )


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone aware")
    return parsed


def _delegated_action(value: str) -> str:
    normalized = "".join(
        character if character.isalnum() else "_"
        for character in value.strip().upper()
    )
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    normalized = normalized.strip("_")
    if not normalized:
        raise ValueError("delegated action cannot be empty")
    aliases = {
        "GIT_PUSH_FORCE_WITH_LEASE": "FORCE_PUSH",
        "PUSH_FORCE": "FORCE_PUSH",
        "PUSH_FORCE_WITH_LEASE": "FORCE_PUSH",
    }
    return aliases.get(normalized, normalized)


def _now() -> str:
    return datetime.now(UTC).isoformat()
