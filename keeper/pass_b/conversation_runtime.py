from __future__ import annotations

from dataclasses import replace
from typing import Any

from keeper.executive.models import ProjectCharter
from keeper.pass_b.conversation import (
    CharterDraftContextRecord,
    ConversationOutcome,
    ConversationService,
)


class DurableConversationService(ConversationService):
    """Conversation flow that retains the exact Executive charter proposal."""

    def begin(self, message: str) -> ConversationOutcome:
        outcome = super().begin(message)
        self._bind_charter(outcome.project.project_id, outcome.charter)
        return outcome

    def revise(
        self, project_id: str, replacements: dict[str, Any]
    ) -> ConversationOutcome:
        outcome = super().revise(project_id, replacements)
        self._bind_charter(project_id, outcome.charter)
        return outcome

    def _charter_from_context(
        self, context: CharterDraftContextRecord
    ) -> ProjectCharter:
        value = context.intake.get("__charter__")
        if not isinstance(value, dict):
            raise PermissionError("durable charter proposal is unavailable")
        charter = ProjectCharter.from_dict(value)
        if (
            charter.project_id != context.project_id
            or charter.charter_id != context.charter_id
            or charter.revision != context.charter_revision
            or charter.status != "PROPOSED"
        ):
            raise PermissionError("durable charter proposal is stale")
        return charter

    def record_approval(
        self, charter: ProjectCharter
    ) -> CharterDraftContextRecord:
        current = self.current_context(charter.project_id)
        if (
            current.state != "APPROVAL_REQUESTED"
            or charter.charter_id != current.charter_id
            or charter.revision != current.charter_revision
            or charter.status != "ACTIVE"
            or not charter.founder_approval_record_id
            or not charter.founder_authorization_capability_digest
        ):
            raise PermissionError("active Founder-approved charter does not match")
        return self.repository.replace(
            replace(
                current,
                state="APPROVED",
                updated_at=charter.updated_at,
                revision=current.revision + 1,
            ),
            expected_revision=current.revision,
        )

    def _bind_charter(
        self, project_id: str, charter: ProjectCharter
    ) -> CharterDraftContextRecord:
        context = self.current_context(project_id)
        intake = dict(context.intake)
        intake["__charter__"] = charter.to_dict()
        return self.repository.replace(
            replace(
                context,
                intake=intake,
                revision=context.revision + 1,
            ),
            expected_revision=context.revision,
        )
