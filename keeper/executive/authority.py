from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import re

from keeper.executive.enums import (
    ActionCategory,
    ActionEffect,
    ApprovalKind,
    AuthorityOutcome,
    DelegationMode,
    ExecutiveState,
)
from keeper.executive.models import (
    ApprovalRecord,
    AuthorityDecision,
    ExecutiveTask,
    ProjectCharter,
    ProjectRecord,
    ProposedAction,
    SpecialistProfile,
)


NON_DELEGABLE = frozenset(
    {
        ActionCategory.IRREVERSIBLE_DELETE,
        ActionCategory.HISTORY_REWRITE,
        ActionCategory.CREDENTIAL_ACCESS,
        ActionCategory.SECURITY_BOUNDARY_CHANGE,
        ActionCategory.LIVE_TRADING,
        ActionCategory.FINANCIAL_AUTHORITY_CHANGE,
        ActionCategory.CHANGE_GOVERNANCE,
    }
)
SEPARATELY_APPROVABLE = frozenset(
    {
        ActionCategory.PUSH,
        ActionCategory.DEPLOY_PRODUCTION,
        ActionCategory.PUBLISH_PUBLIC,
        ActionCategory.PURCHASE,
        ActionCategory.SPENDING,
        ActionCategory.COMMIT,
    }
)
ADVISORY_ACTIONS = frozenset(
    {ActionCategory.ANALYZE, ActionCategory.PLAN, ActionCategory.DRAFT, ActionCategory.READ}
)
TERMINAL_STATES = frozenset(
    {ExecutiveState.COMPLETED, ExecutiveState.CANCELED, ExecutiveState.FAILED}
)


class AuthorityEvaluator:
    def evaluate(
        self,
        project: ProjectRecord,
        charter: ProjectCharter,
        action: ProposedAction,
        approvals: tuple[ApprovalRecord, ...] = (),
        *,
        now: datetime | None = None,
    ) -> AuthorityDecision:
        current_time = now or datetime.now(UTC)
        category = ActionCategory(action.category)
        if project.project_id != action.project_id or charter.project_id != project.project_id:
            return self._decision(AuthorityOutcome.INDETERMINATE, "identity-binding", "project_id", "project identity does not match", "reject the action")
        if ExecutiveState(project.state) in TERMINAL_STATES:
            return self._decision(AuthorityOutcome.DENIED, "terminal-project", "state", "terminal projects cannot launch actions", "create a new project")
        if ExecutiveState(project.state) in {
            ExecutiveState.PAUSED,
            ExecutiveState.BLOCKED,
            ExecutiveState.WAITING_FOR_FOUNDER,
            ExecutiveState.WAITING_FOR_PROVIDER,
            ExecutiveState.WAITING_FOR_CREDENTIAL,
            ExecutiveState.WAITING_FOR_EXTERNAL_SYSTEM,
            ExecutiveState.WAITING_FOR_USAGE_RESET,
        }:
            return self._decision(AuthorityOutcome.DENIED, "non-executable-project-state", "state", "the project is paused or waiting", "resolve the pause before launching work")
        if project.active_charter_revision != action.charter_revision or charter.revision != action.charter_revision:
            return self._decision(AuthorityOutcome.CHARTER_REVISION_REQUIRED, "active-revision", "revision", "action is bound to a stale charter revision", "bind the action to the active charter")
        if charter.status != "ACTIVE" or project.active_charter_id != charter.charter_id:
            return self._decision(AuthorityOutcome.DENIED, "active-charter", "status", "charter is not the active approved revision", "activate an approved charter")
        if charter.authority_envelope.expires_at is not None and datetime.fromisoformat(charter.authority_envelope.expires_at) <= current_time:
            return self._decision(AuthorityOutcome.EXPIRED, "envelope-expiration", "authority_envelope.expires_at", "charter authority has expired", "obtain a charter revision")
        if category in NON_DELEGABLE:
            return self._decision(AuthorityOutcome.DENIED, "non-delegable-action", "authority_envelope.denied_actions", "this action class cannot be delegated", "Founder must perform the action outside Keeper")
        denied_actions = {
            ActionCategory(item).value
            for item in charter.authority_envelope.denied_actions
        }
        if category.value in denied_actions:
            return self._decision(AuthorityOutcome.DENIED, "charter-denial", "authority_envelope.denied_actions", "the active charter explicitly denies this action", "revise the charter")
        if any(_action_matches_non_goal(action, item) for item in charter.non_goals):
            return self._decision(
                AuthorityOutcome.DENIED,
                "explicit-non-goal",
                "non_goals",
                "the action targets or materially contributes to an explicit non-goal",
                "remove the action or obtain a charter revision",
            )
        classification_error = self._classification_error(action)
        if classification_error is not None:
            return classification_error
        if category is ActionCategory.EXPAND_SCOPE or not set(action.scope).issubset(set(charter.deliverables)):
            return self._decision(AuthorityOutcome.CHARTER_REVISION_REQUIRED, "scope-containment", "deliverables", "the action expands or does not map to charter scope", "create a charter amendment")
        constraint_error = self._constraint_error(charter, action)
        if constraint_error is not None:
            return constraint_error
        approval = self._matching_approval(charter, action, approvals, current_time)
        if approval == "REVOKED":
            return self._decision(AuthorityOutcome.REVOKED, "approval-revocation", "approval.revoked_at", "matching authority was revoked", "pause and request new Founder direction")
        if approval == "EXPIRED":
            return self._decision(AuthorityOutcome.EXPIRED, "approval-expiration", "approval.expires_at", "matching approval expired", "request renewed Founder approval")
        if isinstance(approval, ApprovalRecord):
            return AuthorityDecision(
                AuthorityOutcome.ALLOWED_WITHIN_LIMIT.value,
                "bound-founder-approval",
                "approval",
                dict(approval.limits),
                "a current approval authorizes this action",
                "execute within the recorded limits",
                approval.approval_id,
            )
        mode = DelegationMode(charter.delegation_mode)
        if mode is DelegationMode.ADVISORY and category not in ADVISORY_ACTIONS:
            return self._decision(AuthorityOutcome.REQUIRES_FOUNDER_APPROVAL, "advisory-mode", "delegation_mode", "Advisory mode cannot execute material actions", "request one-time or charter approval")
        if category in SEPARATELY_APPROVABLE or action.external_side_effect:
            return self._decision(AuthorityOutcome.REQUIRES_FOUNDER_APPROVAL, "separate-approval", "authority_envelope.separately_approvable_actions", "the action requires separate Founder approval", "request a bound approval")
        allowed_actions = {
            ActionCategory(item).value
            for item in charter.authority_envelope.allowed_actions
        }
        if category.value not in allowed_actions:
            return self._decision(AuthorityOutcome.REQUIRES_FOUNDER_APPROVAL if mode is DelegationMode.DELEGATED else AuthorityOutcome.DENIED, "allowed-action-list", "authority_envelope.allowed_actions", "the action is not in the approved authority envelope", "request approval or revise the charter")
        return AuthorityDecision(
            AuthorityOutcome.ALLOWED_WITHIN_LIMIT.value if action.cost or action.workspace else AuthorityOutcome.ALLOWED.value,
            "delegation-envelope",
            "authority_envelope",
            {"maximum_cost": charter.authority_envelope.maximum_cost, "risk_limit": charter.authority_envelope.risk_limit},
            "deterministic charter policy permits the action",
            "execute and preserve evidence",
        )

    def _constraint_error(
        self, charter: ProjectCharter, action: ProposedAction
    ) -> AuthorityDecision | None:
        envelope = charter.authority_envelope
        if action.spending or action.cost is None or (action.cost or 0) > 0:
            if action.cost is None:
                return self._decision(
                    AuthorityOutcome.DENIED,
                    "unknown-cost",
                    "cost",
                    "paid or potentially paid work requires a known cost",
                    "supply a trusted exact cost before approval",
                )
            if (
                charter.budget_limit <= 0
                or envelope.maximum_cost <= 0
                or envelope.currency is None
            ):
                return self._decision(
                    AuthorityOutcome.DENIED,
                    "absent-spending-authority",
                    "budget_policy",
                    "delegation does not itself grant spending authority",
                    "obtain explicit Founder spending authority",
                )
            if action.currency != envelope.currency:
                return self._decision(
                    AuthorityOutcome.DENIED,
                    "currency-mismatch",
                    "authority_envelope.currency",
                    "implicit currency conversion is not permitted",
                    "use the approved canonical currency",
                )
        if (action.cost or 0) > min(charter.budget_limit, envelope.maximum_cost):
            return self._decision(AuthorityOutcome.DENIED, "budget-limit", "budget_limit", "action cost exceeds the approved budget", "reduce cost or revise the charter")
        if action.provider and (
            action.provider in charter.prohibited_providers
            or action.provider not in charter.approved_providers
            or action.provider not in envelope.allowed_providers
        ):
            return self._decision(AuthorityOutcome.DENIED, "provider-allowlist", "approved_providers", "provider is not approved", "select an approved provider")
        if action.tool and (
            action.tool in charter.prohibited_tools
            or action.tool not in charter.approved_tools
            or action.tool not in envelope.allowed_tools
        ):
            return self._decision(AuthorityOutcome.DENIED, "tool-allowlist", "approved_tools", "tool is not approved", "select an approved tool")
        if action.workspace:
            try:
                target = Path(action.workspace).resolve()
                roots = tuple(Path(item).resolve() for item in envelope.allowed_workspaces)
            except OSError:
                return self._decision(AuthorityOutcome.INDETERMINATE, "workspace-canonicalization", "workspaces", "workspace cannot be canonicalized", "pause and verify the workspace")
            if not any(target == root or target.is_relative_to(root) for root in roots):
                return self._decision(AuthorityOutcome.DENIED, "workspace-containment", "workspaces", "workspace is outside approved roots", "use an approved workspace")
        if action.data_classification not in envelope.data_classifications:
            return self._decision(AuthorityOutcome.DENIED, "data-classification", "data_privacy_restrictions", "data classification is not approved", "revise data authority")
        return None

    def _classification_error(
        self, action: ProposedAction
    ) -> AuthorityDecision | None:
        category = ActionCategory(action.category)
        effects = {ActionEffect(item) for item in action.effect_classes}
        required_by_effect = {
            ActionEffect.DEPLOY_PRODUCTION: ActionCategory.DEPLOY_PRODUCTION,
            ActionEffect.PUBLISH_PUBLIC: ActionCategory.PUBLISH_PUBLIC,
            ActionEffect.PURCHASE: ActionCategory.PURCHASE,
            ActionEffect.PAID_PROVIDER_USE: ActionCategory.SPENDING,
            ActionEffect.HISTORY_REWRITE: ActionCategory.HISTORY_REWRITE,
            ActionEffect.SECURITY_BOUNDARY_CHANGE: ActionCategory.SECURITY_BOUNDARY_CHANGE,
            ActionEffect.CREDENTIAL_ACCESS: ActionCategory.CREDENTIAL_ACCESS,
            ActionEffect.LIVE_TRADING: ActionCategory.LIVE_TRADING,
            ActionEffect.FINANCIAL_AUTHORITY_CHANGE: ActionCategory.FINANCIAL_AUTHORITY_CHANGE,
            ActionEffect.IRREVERSIBLE_DELETE: ActionCategory.IRREVERSIBLE_DELETE,
        }
        for effect, required_category in required_by_effect.items():
            if effect in effects and category is not required_category:
                return self._decision(
                    AuthorityOutcome.DENIED,
                    "classification-mismatch",
                    "action_effects",
                    f"structured action facts require {required_category.value}, not {category.value}",
                    "correct the durable workflow classification",
                )
        text = _normalized(
            " ".join((action.objective, action.target_resource, *action.scope))
        )
        expected = _effects_required_by_objective(text)
        missing = expected - effects
        if missing:
            return self._decision(
                AuthorityOutcome.DENIED,
                "classification-mismatch",
                "action_effects",
                "objective requires protected structured effects: "
                + ", ".join(sorted(item.value for item in missing)),
                "correct the durable workflow classification",
            )
        if _ambiguous_external_effect(text) and not expected:
            return self._decision(
                AuthorityOutcome.INDETERMINATE,
                "ambiguous-external-effect",
                "action_effects",
                "external effect is ambiguous and cannot default to WRITE",
                "supply explicit trusted action effects or revise the charter",
            )
        return None

    def _matching_approval(
        self,
        charter: ProjectCharter,
        action: ProposedAction,
        approvals: tuple[ApprovalRecord, ...],
        now: datetime,
    ) -> ApprovalRecord | str | None:
        expired = False
        revoked = False
        category = ActionCategory(action.category)
        for approval in approvals:
            if approval.kind == ApprovalKind.CHARTER_DURATION:
                continue
            if (
                approval.project_id != charter.project_id
                or approval.charter_id != charter.charter_id
                or approval.charter_revision != charter.revision
                or (
                    approval.action_category is not None
                    and ActionCategory(approval.action_category) is not category
                )
                or not set(action.scope).issubset(set(approval.scope))
            ):
                continue
            if approval.revoked_at is not None:
                revoked = True
                continue
            if approval.expires_at is not None and datetime.fromisoformat(approval.expires_at) <= now:
                expired = True
                continue
            if approval.kind == ApprovalKind.ONE_TIME and approval.consumed_at is not None:
                continue
            amount = approval.limits.get("maximum_cost")
            if isinstance(amount, (int, float)) and (
                action.cost is None or action.cost > float(amount)
            ):
                continue
            provider = approval.limits.get("provider")
            if provider is not None and action.provider != provider:
                continue
            workspace = approval.limits.get("workspace")
            if workspace is not None and action.workspace != workspace:
                continue
            return approval
        if revoked:
            return "REVOKED"
        if expired:
            return "EXPIRED"
        return None

    @staticmethod
    def _decision(
        outcome: AuthorityOutcome,
        rule: str,
        field: str,
        reason: str,
        next_step: str,
    ) -> AuthorityDecision:
        return AuthorityDecision(outcome.value, rule, field, {}, reason, next_step)


class TrustedActionClassifier:
    """Derive launch facts from the durable task and charter, never caller labels."""

    def classify(
        self,
        task: ExecutiveTask,
        charter: ProjectCharter,
        specialist: SpecialistProfile,
    ) -> ProposedAction:
        if task.project_id != charter.project_id or task.charter_id != charter.charter_id:
            raise PermissionError("task and charter identity do not match")
        validate_durable_task_effects(task)
        if len(charter.workspaces) != 1 or len(charter.approved_tools) != 1:
            raise PermissionError(
                "workflow launch requires one explicit workspace and tool"
            )
        if not charter.authority_envelope.data_classifications:
            raise PermissionError("workflow data classification is missing")
        effects = task.action_effects
        if effects is None:
            raise PermissionError("durable structured action effects are missing")
        if (
            effects.workspace != charter.workspaces[0]
            or effects.tool != charter.approved_tools[0]
            or effects.provider not in {None, specialist.provider_id}
        ):
            raise PermissionError("structured action target binding is invalid")
        effect_classes = {ActionEffect(item) for item in effects.side_effect_classes}
        quoted_cost = _trusted_provider_cost(specialist)
        if quoted_cost > 0:
            effect_classes.add(ActionEffect.PAID_PROVIDER_USE)
        deployment = effects.deployment_effect == "PRODUCTION"
        publication = effects.publication_effect == "PUBLIC"
        spending = effects.spending_effect == "PAID" or quoted_cost > 0
        git_mutation = (
            None if effects.git_mutation == "NONE" else effects.git_mutation
        )
        security_impact = effects.security_boundary_effect == "CHANGE"
        action = ProposedAction(
            action_id=f"task-action:{task.task_id}",
            project_id=task.project_id,
            charter_revision=task.charter_revision,
            category=(
                ActionCategory.SPENDING.value
                if quoted_cost > 0
                else task.authority_category
            ),
            target_resource=task.objective,
            provider=specialist.provider_id,
            tool=charter.approved_tools[0],
            workspace=charter.workspaces[0],
            scope=charter.deliverables,
            cost=quoted_cost,
            reversible=effects.reversible,
            risk=charter.risk_classification,
            data_classification=charter.authority_envelope.data_classifications[0],
            external_side_effect=any(
                item not in {
                    ActionEffect.LOCAL_READ,
                    ActionEffect.LOCAL_WRITE,
                    ActionEffect.SOURCE_EDIT,
                    ActionEffect.TEST_EXECUTION,
                }
                for item in effect_classes
            ),
            objective=task.objective,
            currency=charter.authority_envelope.currency,
            publication=publication,
            deployment=deployment,
            spending=spending,
            git_mutation=git_mutation,
            security_boundary_impact=security_impact,
            trusted_source="DURABLE_WORKFLOW_TASK",
            effect_classes=tuple(sorted(item.value for item in effect_classes)),
        )
        mismatch = AuthorityEvaluator()._classification_error(action)
        if mismatch is not None:
            raise PermissionError(mismatch.reason)
        return action


def validate_durable_task_effects(task: ExecutiveTask) -> None:
    effects = task.action_effects
    if effects is None:
        raise PermissionError("durable structured action effects are missing")
    declared = {ActionEffect(item) for item in effects.side_effect_classes}
    text = _normalized(" ".join((task.title, task.objective, *task.instructions)))
    required = _effects_required_by_objective(text)
    missing = required - declared
    if missing:
        raise PermissionError(
            "task objective is inconsistent with structured action effects: "
            + ", ".join(sorted(item.value for item in missing))
        )
    if _ambiguous_external_effect(text) and not required:
        raise PermissionError("ambiguous external-effect task fails closed")
    protected_categories = {
        ActionEffect.DEPLOY_PRODUCTION: ActionCategory.DEPLOY_PRODUCTION,
        ActionEffect.PUBLISH_PUBLIC: ActionCategory.PUBLISH_PUBLIC,
        ActionEffect.PURCHASE: ActionCategory.PURCHASE,
        ActionEffect.PAID_PROVIDER_USE: ActionCategory.SPENDING,
        ActionEffect.HISTORY_REWRITE: ActionCategory.HISTORY_REWRITE,
        ActionEffect.SECURITY_BOUNDARY_CHANGE: ActionCategory.SECURITY_BOUNDARY_CHANGE,
        ActionEffect.CREDENTIAL_ACCESS: ActionCategory.CREDENTIAL_ACCESS,
        ActionEffect.LIVE_TRADING: ActionCategory.LIVE_TRADING,
        ActionEffect.FINANCIAL_AUTHORITY_CHANGE: ActionCategory.FINANCIAL_AUTHORITY_CHANGE,
        ActionEffect.IRREVERSIBLE_DELETE: ActionCategory.IRREVERSIBLE_DELETE,
    }
    category = ActionCategory(task.authority_category)
    for effect, expected_category in protected_categories.items():
        if effect in declared and category is not expected_category:
            raise PermissionError(
                f"{effect.value} requires {expected_category.value}"
            )


def _normalized(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9/ ._-]+", " ", value.casefold())).strip()


def _contains_any(value: str, phrases: tuple[str, ...]) -> bool:
    return any(phrase in value for phrase in phrases)


def _action_matches_non_goal(action: ProposedAction, non_goal: str) -> bool:
    denied = _normalized(non_goal)
    if not denied:
        return False
    denied_effects = _effects_required_by_objective(denied)
    if denied_effects.intersection(
        ActionEffect(item) for item in action.effect_classes
    ):
        return True
    material = _normalized(
        " ".join(
            (
                action.objective,
                action.target_resource,
                action.category,
                *action.scope,
            )
        )
    )
    if denied in material:
        return True
    denied_tokens = {
        token
        for token in denied.split()
        if len(token) > 3 and token not in {"with", "from", "that", "this"}
    }
    material_tokens = set(material.split())
    return bool(denied_tokens) and denied_tokens.issubset(material_tokens)


def _trusted_provider_cost(specialist: SpecialistProfile) -> float:
    now = datetime.now(UTC)
    required = (
        specialist.pricing_identity,
        specialist.pricing_version,
        specialist.billing_unit,
        specialist.quote_timestamp,
        specialist.quote_expiration,
        specialist.pricing_source,
    )
    if any(value is None or value == "" for value in required):
        raise PermissionError("trusted provider pricing is unavailable")
    if datetime.fromisoformat(str(specialist.quote_expiration)) <= now:
        raise PermissionError("trusted provider quote is expired")
    if specialist.currency is None:
        raise PermissionError("trusted provider pricing currency is unavailable")
    if specialist.billing_mode == "included-subscription":
        if (
            specialist.included_plan is not True
            or specialist.marginally_free is not False
            or specialist.incremental_charge_authorized is not False
            or specialist.api_billing_authorized is not False
            or specialist.paid_fallback_authorized is not False
            or specialist.capacity_bounded is not True
            or specialist.cost_tier != 0
            or specialist.estimated_cost != 0
            or specialist.maximum_cost != 0
        ):
            raise PermissionError(
                "included-subscription pricing is contradictory"
            )
        return 0.0
    if specialist.included_plan and specialist.marginally_free:
        if specialist.cost_tier > 0:
            raise PermissionError(
                "positive provider cost tier cannot become zero-cost usage"
            )
        if specialist.estimated_cost != 0 or specialist.maximum_cost != 0:
            raise PermissionError("included-plan pricing is inconsistent")
        return 0.0
    if specialist.maximum_cost is None or specialist.maximum_cost <= 0:
        raise PermissionError("paid or unknown provider pricing fails closed")
    if specialist.cost_tier <= 0:
        raise PermissionError("paid pricing conflicts with provider cost tier")
    return specialist.maximum_cost


def _effects_required_by_objective(value: str) -> set[ActionEffect]:
    mappings = (
        (
            (
                "production deployment", "deploy production", "deploy to production",
                "release the service on the customer-facing environment",
                "release to customer-facing environment", "ship to customers",
                "promote the build",
            ),
            {ActionEffect.DEPLOY_PRODUCTION},
        ),
        (
            (
                "publish externally", "external publication", "public release",
                "publish the final artifact", "make available to users",
                "ship to users",
            ),
            {ActionEffect.PUBLISH_PUBLIC},
        ),
        (
            ("purchase", "buy access"),
            {ActionEffect.PURCHASE, ActionEffect.PAID_PROVIDER_USE},
        ),
        (
            ("paid provider", "premium provider", "spend money"),
            {ActionEffect.PAID_PROVIDER_USE},
        ),
        (
            (
                "rewrite history", "force push", "reset --hard",
                "replace remote branch history",
            ),
            {ActionEffect.HISTORY_REWRITE},
        ),
        (
            ("change security boundary", "disable authentication"),
            {ActionEffect.SECURITY_BOUNDARY_CHANGE},
        ),
        (
            (
                "enable live trading", "place live trade", "authorize real trades",
                "activate live execution",
            ),
            {ActionEffect.LIVE_TRADING},
        ),
    )
    found: set[ActionEffect] = set()
    for phrases, effects in mappings:
        if _contains_any(value, phrases):
            found.update(effects)
    return found


def _ambiguous_external_effect(value: str) -> bool:
    return _contains_any(
        value,
        (
            "external environment", "live environment", "release environment",
            "make available", "ship ", "promote ", "activate ",
        ),
    )
