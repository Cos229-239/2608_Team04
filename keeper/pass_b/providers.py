from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Protocol

from keeper.evidence_input import (
    review_input_declaration,
    structured_digest,
    validate_provider_input,
)
from keeper.pass_b.enums import (
    AssignmentRole,
    CostMode,
    HealthState,
    ProviderSessionState,
)
from keeper.pass_b.models import (
    AssignmentRecord,
    ProviderAccountRecord,
    ProviderRecord,
    ProviderSessionRecord,
)


@dataclass(frozen=True, slots=True)
class AdapterDescriptor:
    provider_identity: str
    model_identity: str
    capabilities: tuple[str, ...]
    classification: str
    session_model: str
    usage_pool_identity: str
    concurrency_limit: int
    cost_mode: str
    authentication_ready: bool
    tool_support: tuple[str, ...]
    workspace_support: tuple[str, ...]
    cancellation_support: bool
    resume_support: bool
    evidence_format: str
    health: str


@dataclass(frozen=True, slots=True)
class AdapterAssignment:
    assignment_id: str
    attempt_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    role: str
    model_id: str
    workspace: Path
    read_only: bool
    global_context: dict[str, Any]
    task_context: dict[str, Any]
    expected_evidence: tuple[str, ...]
    authority_attempt_id: str
    session_id: str = ""
    workflow_id: str = ""
    work_item_id: str = ""
    provider_id: str = ""
    account_id: str = ""


@dataclass(frozen=True, slots=True)
class AdapterResult:
    external_execution_id: str
    summary: str
    artifacts: tuple[dict[str, Any], ...]
    usage: float | None
    session_resume_token: str | None = None

    def content_digest(self) -> str:
        value = {
            "external_execution_id": self.external_execution_id,
            "summary": self.summary,
            "artifacts": self.artifacts,
            "usage": self.usage,
            "session_resume_token": self.session_resume_token,
        }
        return hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()


class ProviderAdapter(Protocol):
    """Provider translation only; adapters never make authority decisions."""

    def descriptor(self) -> AdapterDescriptor: ...

    def launch(self, assignment: AdapterAssignment) -> AdapterResult: ...

    def cancel(self, external_execution_id: str) -> None: ...

    def resume(
        self, assignment: AdapterAssignment, resume_token: str
    ) -> AdapterResult: ...

    def health(self) -> dict[str, Any]: ...


class LocalMockAdapter:
    """Deterministic local adapter used by diagnostics, tests, and pilots."""

    def __init__(self, provider_id: str = "local-mock") -> None:
        self.provider_id = provider_id
        self._launched: set[str] = set()
        self._canceled: set[str] = set()
        self._review_disposition = "ACCEPTED"
        self._review_findings: tuple[dict[str, Any], ...] = ()

    def set_review_outcome(
        self,
        disposition: str,
        findings: tuple[dict[str, Any], ...] = (),
    ) -> None:
        if disposition not in {"ACCEPTED", "REPAIR_REQUIRED"}:
            raise ValueError("mock review disposition is invalid")
        self._review_disposition = disposition
        self._review_findings = tuple(dict(item) for item in findings)

    def descriptor(self) -> AdapterDescriptor:
        return AdapterDescriptor(
            provider_identity=self.provider_id,
            model_identity="deterministic-v1",
            capabilities=tuple(
                role.value.casefold() for role in AssignmentRole
            )
            + ("structured-evidence", "workspace", "resume"),
            classification="LOCAL",
            session_model="RESUMABLE",
            usage_pool_identity=f"{self.provider_id}:included",
            concurrency_limit=8,
            cost_mode=CostMode.FREE,
            authentication_ready=True,
            tool_support=("filesystem",),
            workspace_support=("isolated-worktree", "read-only"),
            cancellation_support=True,
            resume_support=True,
            evidence_format="keeper-evidence-v1",
            health=HealthState.READY,
        )

    def launch(self, assignment: AdapterAssignment) -> AdapterResult:
        if assignment.attempt_id in self._launched:
            raise PermissionError("mock provider attempt was already launched")
        if assignment.role == AssignmentRole.REVIEWER and not assignment.read_only:
            raise PermissionError("review provider requires a read-only assignment")
        self._launched.add(assignment.attempt_id)
        external_id = f"{self.provider_id}:{assignment.attempt_id}"
        artifact: dict[str, Any] = {
            "kind": "structured-report",
            "path": None,
            "digest": hashlib.sha256(
                assignment.assignment_id.encode("utf-8")
            ).hexdigest(),
            "execution_requested": False,
        }
        if assignment.role == AssignmentRole.REVIEWER:
            provider_input = assignment.task_context.get(
                "keeper_provider_input"
            )
            provider_input_digest = assignment.task_context.get(
                "keeper_provider_input_digest"
            )
            artifact.update(
                {
                    "review_disposition": self._review_disposition,
                    "findings": list(self._review_findings),
                }
            )
            if provider_input is not None:
                if not isinstance(provider_input_digest, str):
                    raise PermissionError(
                        "review provider input digest is missing"
                    )
                try:
                    validate_provider_input(provider_input)
                    if (
                        structured_digest(provider_input)
                        != provider_input_digest
                    ):
                        raise ValueError("provider input digest mismatch")
                    declaration = review_input_declaration(
                        provider_input,
                        provider_input_digest=provider_input_digest,
                        review_disposition=self._review_disposition,
                    )
                except ValueError as error:
                    raise PermissionError(
                        "review provider input binding is invalid"
                    ) from error
                artifact["review_input_declaration"] = declaration
        return AdapterResult(
            external_execution_id=external_id,
            summary=f"Completed {assignment.role.casefold()} assignment.",
            artifacts=(artifact,),
            usage=1.0,
            session_resume_token=hashlib.sha256(
                external_id.encode("utf-8")
            ).hexdigest(),
        )

    def cancel(self, external_execution_id: str) -> None:
        self._canceled.add(external_execution_id)

    def resume(
        self, assignment: AdapterAssignment, resume_token: str
    ) -> AdapterResult:
        if len(resume_token) != 64:
            raise PermissionError("resume token is invalid")
        return self.launch(assignment)

    def health(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "state": HealthState.READY,
            "launched": len(self._launched),
            "canceled": len(self._canceled),
        }


class CodexSessionAdapter:
    """Codex-style resumable session translation with an injected launcher."""

    def __init__(
        self,
        launcher: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        provider_id: str = "codex-session",
        model_id: str = "configured-model",
    ) -> None:
        self.launcher = launcher
        self.provider_id = provider_id
        self.model_id = model_id

    def descriptor(self) -> AdapterDescriptor:
        return AdapterDescriptor(
            provider_identity=self.provider_id,
            model_identity=self.model_id,
            capabilities=tuple(
                role.value.casefold() for role in AssignmentRole
            )
            + (
                "structured-evidence",
                "workspace",
                "session-resume",
                "tool-use",
            ),
            classification="REMOTE",
            session_model="PERSISTENT",
            usage_pool_identity=f"{self.provider_id}:account",
            concurrency_limit=4,
            cost_mode=CostMode.INCLUDED,
            authentication_ready=True,
            tool_support=("configured-tools",),
            workspace_support=("isolated-worktree", "read-only"),
            cancellation_support=True,
            resume_support=True,
            evidence_format="keeper-evidence-v1",
            health=HealthState.READY,
        )

    def launch(self, assignment: AdapterAssignment) -> AdapterResult:
        return self._convert(self.launcher(self._request(assignment, None)))

    def cancel(self, external_execution_id: str) -> None:
        self.launcher(
            {
                "operation": "cancel",
                "provider_id": self.provider_id,
                "external_execution_id": external_execution_id,
            }
        )

    def resume(
        self, assignment: AdapterAssignment, resume_token: str
    ) -> AdapterResult:
        return self._convert(
            self.launcher(self._request(assignment, resume_token))
        )

    def health(self) -> dict[str, Any]:
        value = self.launcher(
            {"operation": "health", "provider_id": self.provider_id}
        )
        return dict(value)

    def _request(
        self, assignment: AdapterAssignment, resume_token: str | None
    ) -> dict[str, Any]:
        return {
            "operation": "resume" if resume_token else "launch",
            "provider_id": self.provider_id,
            "model_id": assignment.model_id,
            "assignment_id": assignment.assignment_id,
            "attempt_id": assignment.attempt_id,
            "project_id": assignment.project_id,
            "charter_id": assignment.charter_id,
            "charter_revision": assignment.charter_revision,
            "role": assignment.role,
            "workspace": str(assignment.workspace),
            "read_only": assignment.read_only,
            "global_context": assignment.global_context,
            "task_context": assignment.task_context,
            "expected_evidence": list(assignment.expected_evidence),
            "authority_attempt_id": assignment.authority_attempt_id,
            "resume_token": resume_token,
        }

    @staticmethod
    def _convert(value: dict[str, Any]) -> AdapterResult:
        external_execution_id = value.get("external_execution_id")
        summary = value.get("summary")
        artifacts = value.get("artifacts")
        usage = value.get("usage")
        session_resume_token = value.get("session_resume_token")
        if (
            not isinstance(external_execution_id, str)
            or not external_execution_id.strip()
        ):
            raise ValueError("provider returned an invalid execution identity")
        if not isinstance(summary, str) or not summary.strip():
            raise ValueError("provider returned an invalid summary")
        if not isinstance(artifacts, list) or any(
            not isinstance(item, dict) for item in artifacts
        ):
            raise ValueError("provider returned invalid evidence artifacts")
        if usage is not None and (
            isinstance(usage, bool)
            or not isinstance(usage, (int, float))
            or not math.isfinite(float(usage))
            or float(usage) < 0
        ):
            raise ValueError("provider returned invalid usage")
        if session_resume_token is not None and (
            not isinstance(session_resume_token, str)
            or not session_resume_token.strip()
        ):
            raise ValueError("provider returned an invalid resume token")
        return AdapterResult(
            external_execution_id=external_execution_id,
            summary=summary,
            artifacts=tuple(dict(item) for item in artifacts),
            usage=float(usage) if usage is not None else None,
            session_resume_token=session_resume_token,
        )


class GenericRemoteAdapter(CodexSessionAdapter):
    """Generic structured remote transport with no vendor-specific authority."""

    def __init__(
        self,
        transport: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        provider_id: str,
        model_id: str,
        cost_mode: str = CostMode.INCLUDED,
    ) -> None:
        super().__init__(
            transport, provider_id=provider_id, model_id=model_id
        )
        self.cost_mode = CostMode(cost_mode)

    def descriptor(self) -> AdapterDescriptor:
        base = super().descriptor()
        return AdapterDescriptor(
            provider_identity=base.provider_identity,
            model_identity=base.model_identity,
            capabilities=base.capabilities,
            classification=base.classification,
            session_model=base.session_model,
            usage_pool_identity=base.usage_pool_identity,
            concurrency_limit=base.concurrency_limit,
            cost_mode=self.cost_mode,
            authentication_ready=base.authentication_ready,
            tool_support=base.tool_support,
            workspace_support=base.workspace_support,
            cancellation_support=base.cancellation_support,
            resume_support=base.resume_support,
            evidence_format=base.evidence_format,
            health=base.health,
        )


@dataclass(frozen=True, slots=True)
class ProviderSelectionPolicy:
    allowed_provider_ids: frozenset[str]
    required_capabilities: frozenset[str]
    allow_substitution: bool
    allow_paid: bool
    privacy_classification: str
    excluded_independence_keys: frozenset[str] = frozenset()
    preferred_provider_id: str | None = None
    project_type: str | None = None
    effort_level: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderSelectionDecision:
    session: ProviderSessionRecord
    policy_digest: str


class PolicyDrivenSelector:
    """Pure policy selector; callers persist the decision before execution."""

    def select(
        self,
        *,
        assignment_role: str,
        providers: list[ProviderRecord],
        accounts: list[ProviderAccountRecord],
        sessions: list[ProviderSessionRecord],
        policy: ProviderSelectionPolicy,
        selection_counts: dict[str, int] | None = None,
    ) -> ProviderSelectionDecision:
        session = select_provider_session(
            assignment_role,
            providers,
            accounts,
            sessions,
            policy,
            selection_counts=selection_counts,
        )
        return ProviderSelectionDecision(
            session=session,
            policy_digest=provider_selection_policy_digest(
                assignment_role, policy
            ),
        )


def provider_selection_policy_digest(
    assignment_role: str, policy: ProviderSelectionPolicy
) -> str:
    payload = {
        "allowed_provider_ids": sorted(policy.allowed_provider_ids),
        "required_capabilities": sorted(policy.required_capabilities),
        "allow_substitution": policy.allow_substitution,
        "allow_paid": policy.allow_paid,
        "privacy_classification": policy.privacy_classification,
        "excluded_independence_keys": sorted(
            policy.excluded_independence_keys
        ),
        "preferred_provider_id": policy.preferred_provider_id,
        "project_type": policy.project_type,
        "effort_level": policy.effort_level,
        "assignment_role": AssignmentRole(assignment_role).value,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def select_provider_session(
    assignment_role: str,
    providers: list[ProviderRecord],
    accounts: list[ProviderAccountRecord],
    sessions: list[ProviderSessionRecord],
    policy: ProviderSelectionPolicy,
    *,
    selection_counts: dict[str, int] | None = None,
) -> ProviderSessionRecord:
    role = AssignmentRole(assignment_role)
    if not policy.allow_substitution:
        raise PermissionError("provider substitution is not charter-approved")
    account_by_id = {item.account_id: item for item in accounts}
    provider_by_id = {item.provider_id: item for item in providers}
    candidates: list[ProviderSessionRecord] = []
    for session in sessions:
        provider = provider_by_id.get(session.provider_id)
        account = account_by_id.get(session.account_id)
        if provider is None or account is None:
            continue
        try:
            validate_provider_execution_declarations(
                provider,
                project_type=policy.project_type,
                effort_level=policy.effort_level,
            )
        except PermissionError:
            continue
        independence_keys = {
            provider.provider_id,
            f"provider:{provider.provider_id}",
            account.account_id,
            f"account:{account.account_id}",
            session.session_id,
            f"session:{session.session_id}",
            f"{provider.provider_id}:{account.account_id}:{session.session_id}",
        }
        if (
            provider.provider_id not in policy.allowed_provider_ids
            or not independence_keys.isdisjoint(policy.excluded_independence_keys)
            or not provider.authentication_ready
            or not account.enabled
            or not account.authentication_ready
            or provider.health != HealthState.READY
            or session.state != ProviderSessionState.READY
            or (
                role.value.casefold()
                not in {item.casefold() for item in provider.capabilities}
                and "all-roles"
                not in {item.casefold() for item in provider.capabilities}
            )
            or not policy.required_capabilities.issubset(
                provider.capabilities
            )
            or (
                account.cost_mode == CostMode.PAID
                and not policy.allow_paid
            )
            or account.privacy_classification
            != policy.privacy_classification
            or session.active_assignments >= session.concurrency_limit
        ):
            continue
        candidates.append(session)
    if not candidates:
        raise RuntimeError("no already-approved provider session satisfies policy")
    candidates.sort(
        key=lambda item: (
            0 if item.provider_id == policy.preferred_provider_id else 1,
            (selection_counts or {}).get(item.session_id, 0),
            item.active_assignments,
            item.provider_id,
            item.account_id,
            item.session_id,
        )
    )
    return candidates[0]


def validate_provider_execution_declarations(
    provider: ProviderRecord,
    *,
    project_type: str | None,
    effort_level: str | None,
    checked_at: str | None = None,
) -> None:
    """Fail closed on the durable Authority-qualified execution envelope."""

    if provider.adapter_kind != "authority-managed":
        return
    if not provider.authority_registration_id:
        raise PermissionError("Authority-managed provider lacks registration")
    normalized_project_type = (
        project_type.casefold()
        if isinstance(project_type, str) and project_type
        else None
    )
    normalized_effort = (
        effort_level.casefold()
        if isinstance(effort_level, str) and effort_level
        else None
    )
    if (
        normalized_project_type is None
        or normalized_project_type not in provider.project_types
        or normalized_effort is None
        or normalized_effort not in provider.effort_levels
        or provider.pricing_authority_digest is None
        or len(provider.pricing_authority_digest) != 64
        or any(
            character not in "0123456789abcdef"
            for character in provider.pricing_authority_digest
        )
        or provider.pricing_quoted_at is None
        or provider.pricing_expires_at is None
    ):
        raise PermissionError(
            "provider execution is outside its Authority-qualified declarations"
        )
    try:
        quoted = datetime.fromisoformat(provider.pricing_quoted_at)
        expires = datetime.fromisoformat(provider.pricing_expires_at)
        current = (
            datetime.fromisoformat(checked_at)
            if checked_at is not None
            else datetime.now(UTC)
        )
    except ValueError as error:
        raise PermissionError(
            "provider pricing validity window is malformed"
        ) from error
    if (
        quoted.tzinfo is None
        or expires.tzinfo is None
        or current.tzinfo is None
        or expires <= quoted
        or quoted > current
        or expires <= current
    ):
        raise PermissionError(
            "provider pricing authority is not currently valid"
        )


def assignment_to_adapter(
    assignment: AssignmentRecord,
    attempt_id: str,
    authority_attempt_id: str,
    workspace: Path,
    *,
    global_context: dict[str, Any],
    task_context: dict[str, Any],
) -> AdapterAssignment:
    return AdapterAssignment(
        assignment_id=assignment.assignment_id,
        attempt_id=attempt_id,
        project_id=assignment.project_id,
        charter_id=assignment.charter_id,
        charter_revision=assignment.charter_revision,
        role=assignment.role,
        model_id=assignment.model_id,
        workspace=workspace.resolve(),
        read_only=assignment.read_only,
        global_context=dict(global_context),
        task_context=dict(task_context),
        expected_evidence=assignment.expected_evidence,
        authority_attempt_id=authority_attempt_id,
        session_id=assignment.session_id,
        workflow_id=assignment.workflow_id,
        work_item_id=assignment.work_item_id,
        provider_id=assignment.provider_id,
        account_id=assignment.account_id,
    )
