from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.executive.authority_gateway import AuthorityProviderBinding
from keeper.pass_b.enums import (
    CostMode,
    HealthState,
    ProviderClassification,
    ProviderSessionState,
    SessionModel,
)
from keeper.pass_b.models import (
    ProviderAccountRecord,
    ProviderRecord,
    ProviderSessionRecord,
    UsagePoolRecord,
)
from keeper.pass_b.orchestration import OrchestrationService
from keeper.pass_b.providers import AdapterAssignment, AdapterDescriptor, AdapterResult


_ROLE_ALIASES = MappingProxyType(
    {
        "planning": "planner",
        "implementation": "implementer",
        "review": "reviewer",
        "research": "researcher",
        "testing": "tester",
        "documentation": "documentation_specialist",
    }
)
_PROJECT_TYPES = frozenset(
    {
        "business_operations",
        "design",
        "general",
        "marketing",
        "music",
        "research",
        "software",
        "video",
        "writing",
    }
)
_EFFORT_LEVELS = frozenset({"low", "medium", "high", "xhigh"})


@dataclass(frozen=True, slots=True)
class AuthorityManagedAdapter:
    """Descriptor-only adapter; production execution remains Authority-owned."""

    adapter_descriptor: AdapterDescriptor

    def descriptor(self) -> AdapterDescriptor:
        return self.adapter_descriptor

    def launch(self, assignment: AdapterAssignment) -> AdapterResult:
        del assignment
        raise PermissionError(
            "Authority-managed provider cannot execute through a local adapter"
        )

    def cancel(self, external_execution_id: str) -> None:
        del external_execution_id
        raise PermissionError(
            "Authority-managed cancellation requires the Authority service"
        )

    def resume(
        self, assignment: AdapterAssignment, resume_token: str
    ) -> AdapterResult:
        del assignment, resume_token
        raise PermissionError(
            "Authority-managed resume requires the Authority service"
        )

    def health(self) -> dict[str, Any]:
        return {
            "provider_id": self.adapter_descriptor.provider_identity,
            "state": self.adapter_descriptor.health,
            "composition": "PRODUCTION_AUTHORITY",
        }


def bridge_qualified_provider(
    orchestration: OrchestrationService,
    authority: ProductionAuthorityServiceClient,
    binding: AuthorityProviderBinding,
) -> ProviderRecord:
    """Project one exact Authority-qualified provider into Pass B records."""

    registration_container = authority.query_state(
        "registrations", binding.registration_id
    )
    qualification_container = authority.query_state(
        "qualifications", binding.qualification_id
    )
    registration = _record(registration_container, "registration")
    qualified = _record(qualification_container, "qualification")
    evidence = qualified.get("evidence")
    if (
        registration.get("service_state") != "QUALIFIED"
        or qualified.get("service_state") != "QUALIFIED"
        or not isinstance(evidence, dict)
        or evidence.get("registration_id") != binding.registration_id
        or evidence.get("id") != binding.qualification_id
        or evidence.get("qualification_result") != "qualified"
        or not authority.verify("provider-qualification", evidence)
    ):
        raise PermissionError("Authority provider qualification is invalid")
    provider_id = _text(registration, "logical_provider_id")
    model_id = _text(registration, "model_or_service_identity")
    session_id = _text(evidence, "provider_instance_id")
    declared_capabilities = _texts(
        registration, "executive_capability_set"
    )
    role_eligibility_value = registration.get("role_eligibility")
    role_eligibility = (
        tuple(str(item) for item in role_eligibility_value)
        if isinstance(role_eligibility_value, list)
        else ()
    )
    has_explicit_role_eligibility = isinstance(role_eligibility_value, list)
    project_types = _texts(registration, "project_types")
    effort_levels = _texts(registration, "effort_levels")
    if (
        project_types != tuple(sorted(project_types))
        or len(set(project_types)) != len(project_types)
        or any(item not in _PROJECT_TYPES for item in project_types)
        or (
            registration.get("registration_schema_version") in {4, 5}
            and effort_levels != ("medium", "high")
        )
        or (
            registration.get("registration_schema_version") not in {4, 5}
            and effort_levels != tuple(sorted(effort_levels))
        )
        or len(set(effort_levels)) != len(effort_levels)
        or any(item not in _EFFORT_LEVELS for item in effort_levels)
    ):
        raise PermissionError(
            "Authority provider execution declarations are invalid"
        )
    capabilities = tuple(
        dict.fromkeys(
            [
                *(item.casefold() for item in declared_capabilities),
                *(
                    alias
                    for source, alias in _ROLE_ALIASES.items()
                    if source in {item.casefold() for item in declared_capabilities}
                    and (
                        alias != "reviewer"
                        or not has_explicit_role_eligibility
                        or "reviewer" in role_eligibility
                    )
                ),
                *(
                    "reviewer"
                    for role in role_eligibility
                    if role in {"reviewer", "post_repair_reviewer"}
                ),
            ]
        )
    )
    pricing = registration.get("pricing_authority")
    pricing_core_fields = {
        "pricing_identity",
        "pricing_version",
        "currency",
        "estimated_cost",
        "maximum_cost",
        "billing_unit",
        "included_plan",
        "marginally_free",
        "quoted_at",
        "expires_at",
        "source",
        "cost_tier",
    }
    if not isinstance(pricing, dict) or not pricing_core_fields.issubset(pricing):
        raise PermissionError("Authority provider pricing declaration is invalid")
    current = datetime.now(UTC)
    try:
        quoted = datetime.fromisoformat(_text(pricing, "quoted_at"))
        expires = datetime.fromisoformat(_text(pricing, "expires_at"))
    except ValueError as error:
        raise PermissionError(
            "Authority provider pricing validity window is malformed"
        ) from error
    if (
        quoted.tzinfo is None
        or expires.tzinfo is None
        or expires <= quoted
        or quoted > current
        or expires <= current
    ):
        raise PermissionError(
            "Authority provider pricing authority is not currently valid"
        )
    pricing_digest = hashlib.sha256(
        json.dumps(pricing, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    if pricing.get("billing_mode") == "included-subscription":
        if (
            pricing.get("marginally_free") is not False
            or pricing.get("included_plan") is not True
            or pricing.get("api_billing_authorized") is not False
            or pricing.get("paid_fallback_authorized") is not False
            or pricing.get("capacity_bounded") is not True
        ):
            raise PermissionError(
                "Authority subscription pricing declaration is contradictory"
            )
        cost_mode = CostMode.INCLUDED_SUBSCRIPTION
    elif pricing.get("marginally_free") is True:
        cost_mode = CostMode.FREE
    elif pricing.get("included_plan") is True:
        cost_mode = CostMode.INCLUDED
    else:
        cost_mode = CostMode.PAID
    now = datetime.now(UTC).isoformat()
    account_id = f"authority-account:{binding.registration_id}"
    pool_id = f"authority-pool:{binding.registration_id}"
    model_allowlist_value = registration.get("model_allowlist")
    model_allowlist = (
        tuple(str(item) for item in model_allowlist_value)
        if isinstance(model_allowlist_value, list)
        else (model_id,)
    )
    reviewer_eligible = bool(
        (
            not has_explicit_role_eligibility
            and "reviewer" in capabilities
        )
        or (
            any(
                item in {"reviewer", "post_repair_reviewer"}
                for item in role_eligibility
            )
            and registration.get("independence_classification")
            == "independent-capable"
        )
    )
    descriptor = AdapterDescriptor(
        provider_identity=f"authority:{binding.registration_id}",
        model_identity=model_id,
        capabilities=capabilities,
        classification=ProviderClassification.LOCAL,
        session_model=SessionModel.PERSISTENT,
        usage_pool_identity=f"authority-usage:{binding.registration_id}",
        concurrency_limit=1,
        cost_mode=cost_mode,
        authentication_ready=True,
        tool_support=("authority-managed-tools",),
        workspace_support=("isolated-worktree", "read-only"),
        cancellation_support=True,
        resume_support=False,
        evidence_format="keeper-evidence-v1",
        health=HealthState.READY,
    )
    provider = ProviderRecord(
        provider_id=provider_id,
        identity=descriptor.provider_identity,
        display_name=provider_id,
        classification=descriptor.classification,
        adapter_kind="authority-managed",
        capabilities=descriptor.capabilities,
        session_model=descriptor.session_model,
        usage_pool_strategy="authority-declared",
        concurrency_limit=descriptor.concurrency_limit,
        cost_mode=descriptor.cost_mode,
        authentication_ready=True,
        tool_support=descriptor.tool_support,
        workspace_support=descriptor.workspace_support,
        cancellation_support=descriptor.cancellation_support,
        resume_support=descriptor.resume_support,
        evidence_format=descriptor.evidence_format,
        health=descriptor.health,
        created_at=now,
        updated_at=now,
        revision=1,
        authority_registration_id=binding.registration_id,
        project_types=project_types,
        effort_levels=effort_levels,
        pricing_authority_digest=pricing_digest,
        pricing_quoted_at=quoted.isoformat(),
        pricing_expires_at=expires.isoformat(),
        billing_mode=(
            str(pricing["billing_mode"])
            if pricing.get("billing_mode") is not None
            else None
        ),
        authentication_mode=str(
            registration.get("authentication_mode", "")
        ),
        reviewer_eligible=reviewer_eligible,
        model_allowlist=model_allowlist,
        paid_fallback_authorized=(
            pricing.get("paid_fallback_authorized") is True
        ),
        model_revalidation_expires_at=(
            str(registration["model_revalidation_expires_at"])
            if registration.get("model_revalidation_expires_at") is not None
            else None
        ),
        api_billing_authorized=(
            pricing.get("api_billing_authorized") is True
        ),
        subscription_capacity_bounded=(
            pricing.get("capacity_bounded") is True
        ),
    )
    account = ProviderAccountRecord(
        account_id=account_id,
        provider_id=provider_id,
        identity=f"authority:{binding.registration_id}:account",
        display_name="Authority-managed account",
        usage_pool_id=pool_id,
        cost_mode=cost_mode,
        privacy_classification="AUTHORITY_DECLARED",
        authentication_ready=True,
        enabled=cost_mode != CostMode.PAID,
        created_at=now,
        updated_at=now,
        revision=1,
    )
    usage = evidence.get("usage_observation")
    usage_policy = registration.get("usage_policy")
    observed_buckets: list[Any] = []
    if isinstance(usage, dict) and isinstance(usage.get("buckets"), list):
        observed_buckets = list(usage["buckets"])
    used_percent: float | None = max(
        (
            float(item["used_percent"])
            for item in observed_buckets
            if isinstance(item, dict)
            and isinstance(item.get("used_percent"), (int, float))
            and not isinstance(item.get("used_percent"), bool)
        ),
        default=None,
    )
    if used_percent is not None:
        pool_capacity: float | None = 100.0
        pool_consumed: float = used_percent
        pool_remaining: float | None = max(0.0, 100.0 - used_percent)
        pool_limit_type = "SUBSCRIPTION_RATE_LIMIT_PERCENT"
    else:
        budget = (
            usage_policy.get("keeper_launch_budget")
            if isinstance(usage_policy, dict)
            else None
        )
        pool_capacity = float(budget) if isinstance(budget, int) else None
        pool_consumed = 0.0
        pool_remaining = pool_capacity
        pool_limit_type = "KEEPER_CONSERVATIVE_LAUNCH_BUDGET"
    reset_values = [
        item.get("resets_at")
        for item in observed_buckets
        if isinstance(item, dict) and item.get("resets_at") is not None
    ]
    reset_at: str | None = None
    if reset_values:
        reset_value = min(reset_values, key=lambda item: str(item))
        if isinstance(reset_value, (int, float)) and not isinstance(
            reset_value, bool
        ):
            reset_at = datetime.fromtimestamp(
                float(reset_value), tz=UTC
            ).isoformat()
        elif isinstance(reset_value, str):
            parsed_reset = datetime.fromisoformat(reset_value)
            if parsed_reset.tzinfo is None:
                raise PermissionError(
                    "Authority usage reset observation is timezone-naive"
                )
            reset_at = parsed_reset.isoformat()
    pool = UsagePoolRecord(
        pool_id=pool_id,
        provider_id=provider_id,
        account_id=account_id,
        identity=descriptor.usage_pool_identity,
        limit_type=pool_limit_type,
        capacity=pool_capacity,
        consumed=pool_consumed,
        reserved=0.0,
        remaining=pool_remaining,
        reset_at=reset_at,
        observation_source=(
            str(usage.get("source"))
            if isinstance(usage, dict)
            else "KEEPERAUTHORITY_QUALIFICATION"
        ),
        confidence=(
            str(usage.get("confidence"))
            if isinstance(usage, dict)
            else "LOW"
        ),
        exhausted=(
            usage.get("exhausted") is True
            if isinstance(usage, dict)
            else False
        ),
        last_observed_at=now,
        created_at=now,
        updated_at=now,
        revision=1,
    )
    session = ProviderSessionRecord(
        session_id=session_id,
        provider_id=provider_id,
        account_id=account_id,
        model_id=model_id,
        external_session_id=session_id,
        state=ProviderSessionState.READY,
        concurrency_limit=1,
        active_assignments=0,
        supports_resume=False,
        resume_token_digest=None,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
        revision=1,
    )
    adapter = AuthorityManagedAdapter(descriptor)
    existing = orchestration.repository.optional(ProviderRecord, provider_id)
    if existing is None:
        orchestration.register_provider(
            provider, account, pool, (session,), adapter
        )
        return provider
    if existing.authority_registration_id != binding.registration_id:
        raise PermissionError("durable provider registration identity changed")
    if (
        existing.project_types != project_types
        or existing.effort_levels != effort_levels
        or existing.pricing_authority_digest != pricing_digest
        or existing.pricing_quoted_at != quoted.isoformat()
        or existing.pricing_expires_at != expires.isoformat()
        or existing.cost_mode != cost_mode
        or existing.model_allowlist != model_allowlist
        or existing.authentication_mode
        != str(registration.get("authentication_mode", ""))
        or existing.reviewer_eligible != reviewer_eligible
        or existing.paid_fallback_authorized
        != (pricing.get("paid_fallback_authorized") is True)
        or existing.api_billing_authorized
        != (pricing.get("api_billing_authorized") is True)
        or existing.subscription_capacity_bounded
        != (pricing.get("capacity_bounded") is True)
        or existing.model_revalidation_expires_at
        != (
            str(registration["model_revalidation_expires_at"])
            if registration.get("model_revalidation_expires_at") is not None
            else None
        )
    ):
        raise PermissionError(
            "durable provider qualification declarations changed"
        )
    if set(existing.capabilities) != set(provider.capabilities):
        existing_projection = existing.to_dict()
        provider_projection = provider.to_dict()
        for name in ("capabilities", "created_at", "updated_at", "revision"):
            existing_projection.pop(name, None)
            provider_projection.pop(name, None)
        added_capabilities = set(provider.capabilities).difference(
            existing.capabilities
        )
        if (
            existing_projection != provider_projection
            or added_capabilities != {"reviewer"}
            or not set(existing.capabilities).issubset(provider.capabilities)
            or not reviewer_eligible
            or "reviewer" not in role_eligibility
            or registration.get("independence_classification")
            != "independent-capable"
        ):
            raise PermissionError(
                "durable provider projection changed without exact signed authority"
            )
        existing = orchestration.repository.replace(
            replace(
                existing,
                capabilities=provider.capabilities,
                updated_at=now,
                revision=existing.revision + 1,
            ),
            expected_revision=existing.revision,
        )
    orchestration.attach_adapter(provider_id, adapter)
    return existing


def _record(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("found") is not True:
        raise PermissionError(f"Authority {label} is unavailable")
    record = value.get("record")
    if not isinstance(record, dict):
        raise PermissionError(f"Authority {label} is malformed")
    return dict(record)


def _text(value: dict[str, Any], name: str) -> str:
    result = value.get(name)
    if not isinstance(result, str) or not result:
        raise PermissionError(f"Authority provider {name} is invalid")
    return result


def _texts(value: dict[str, Any], name: str) -> tuple[str, ...]:
    result = value.get(name)
    if (
        not isinstance(result, list)
        or not result
        or any(not isinstance(item, str) or not item for item in result)
    ):
        raise PermissionError(f"Authority provider {name} is invalid")
    return tuple(result)
