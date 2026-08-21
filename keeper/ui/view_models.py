from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SETUP_STEPS: tuple[tuple[str, str], ...] = (
    ("boundaries", "Safety boundaries"),
    ("storage", "Evidence directory"),
    ("repository", "First project or repository"),
    ("providers", "Provider configuration"),
    ("provider_validation", "Provider validation"),
    ("authority", "KeeperAuthority health"),
    ("finish", "Finish and open Keeper"),
)


@dataclass(frozen=True, slots=True)
class TimelineItem:
    kind: str
    title: str
    body: str
    state: str
    created_at: str | None = None


@dataclass(frozen=True, slots=True)
class ProductViewModel:
    project_id: str | None
    project_title: str
    project_status: str
    charter_revision: int | None
    project_catalog: tuple[dict[str, Any], ...]
    charter_detail: dict[str, Any]
    approval_charter_detail: dict[str, Any]
    approval_required: bool
    controls: tuple[str, ...]
    composition: str
    timeline: tuple[TimelineItem, ...]
    project_cards: tuple[dict[str, Any], ...]
    workflow_rows: tuple[dict[str, Any], ...]
    provider_cards: tuple[dict[str, Any], ...]
    provider_host: dict[str, Any]
    usage_cards: tuple[dict[str, Any], ...]
    evidence_cards: tuple[dict[str, Any], ...]
    evidence_reference_cards: tuple[dict[str, Any], ...]
    review_cards: tuple[dict[str, Any], ...]
    safety_rows: tuple[dict[str, Any], ...]
    right_rail: tuple[tuple[str, str], ...]
    sage: dict[str, Any]
    developer_details: dict[str, Any] | None


def build_product_view(
    snapshot: dict[str, Any],
    *,
    developer_details: bool = False,
) -> ProductViewModel:
    conversation = _mapping(snapshot.get("conversation"))
    control = _mapping(snapshot.get("control_room"))
    project = _mapping(snapshot.get("project"))
    executive = _mapping(snapshot.get("executive"))
    executive_project = _mapping(executive.get("project_summary"))
    providers = _mapping(snapshot.get("providers"))
    safety = _mapping(snapshot.get("safety"))
    sage = _mapping(snapshot.get("presentation"))
    if sage.get("authority_effect", "NONE") != "NONE":
        raise ValueError("Sage presentation must remain authority-neutral")

    authority = _mapping(safety.get("authority"))
    provider_host = _mapping(authority.get("provider_host"))
    if not provider_host:
        provider_host = {
            "installed": False,
            "online": False,
            "state": "NOT_CONFIGURED",
            "protocol_compatible": False,
            "provider_state": "UNAVAILABLE",
            "founder_action_required": "INSTALL_AND_ENROLL_PROVIDER_HOST",
        }
    authority_state = str(authority.get("state", "NOT_CONFIGURED"))
    composition = str(
        authority.get("composition") or _composition_label(authority_state)
    )
    proposal = _mapping(conversation.get("charter_proposal"))
    intake = _mapping(proposal.get("intake"))
    active_charter = _mapping(executive.get("active_charter"))
    approval_required = bool(conversation.get("approval_required"))
    proposed_charter = next(
        (
            _mapping(item)
            for item in _rows(executive.get("charter_history"))
            if item.get("project_id") == proposal.get("project_id")
            and item.get("charter_id") == proposal.get("charter_id")
            and item.get("revision") == proposal.get("charter_revision")
        ),
        _mapping(intake.get("__charter__")),
    )
    approval_charter_detail = (
        proposed_charter if approval_required else {}
    )
    charter_detail = active_charter or proposed_charter
    project_id = _optional_text(
        executive_project.get("project_id")
        or project.get("project_id")
        or proposal.get("project_id")
    )
    project_title = str(
        executive_project.get("name")
        or charter_detail.get("title")
        or intake.get("title")
        or intake.get("project_name")
        or project_id
        or "No active project"
    )
    project_status = str(
        executive_project.get("state")
        or proposal.get("state")
        or "NOT_STARTED"
    )

    timeline: list[TimelineItem] = []
    for message in _rows(conversation.get("messages")):
        speaker = str(message.get("speaker", "KEEPER"))
        timeline.append(
            TimelineItem(
                kind="founder" if speaker == "FOUNDER" else "keeper",
                title="Founder" if speaker == "FOUNDER" else "Keeper",
                body=str(message.get("text", "")),
                state="MESSAGE",
                created_at=_optional_text(message.get("created_at")),
            )
        )
    if proposal:
        timeline.append(
            TimelineItem(
                kind="approval" if approval_required else "status",
                title=(
                    "Charter approval required"
                    if approval_required
                    else "Project charter"
                ),
                body=_charter_summary(proposal),
                state=str(proposal.get("state", "PROPOSED")),
                created_at=_optional_text(proposal.get("updated_at")),
            )
        )
    for prompt in _rows(conversation.get("recovery_prompts")):
        timeline.append(
            TimelineItem(
                kind="warning",
                title="Recovery decision required",
                body=str(prompt.get("message", "Review uncertain work.")),
                state="UNCERTAIN",
            )
        )
    for evidence in _rows(control.get("recent_evidence"))[-3:]:
        timeline.append(
            TimelineItem(
                kind="evidence",
                title="Evidence received",
                body=str(evidence.get("summary", "Structured evidence")),
                state=str(evidence.get("state", "UNTRUSTED")),
                created_at=_optional_text(evidence.get("updated_at")),
            )
        )
    for review in _rows(control.get("recent_reviews"))[-3:]:
        timeline.append(
            TimelineItem(
                kind="review",
                title="Independent review",
                body=str(review.get("disposition") or "Review pending"),
                state=str(review.get("state", "PENDING")),
                created_at=_optional_text(review.get("updated_at")),
            )
        )

    work_items = _rows(project.get("work_items"))
    assignments = _rows(project.get("assignments"))
    workflow_rows = tuple(
        {
            "title": item.get("title", item.get("work_item_id", "Work item")),
            "role": _first_role(item),
            "status": item.get("state", "PROPOSED"),
            "dependencies": tuple(item.get("dependencies") or ()),
            "assignment": _assignment_for(item, assignments),
        }
        for item in work_items
    )
    project_cards = (
        {
            "title": project_title,
            "status": project_status,
            "project_id": project_id,
            "charter_revision": (
                charter_detail.get("revision")
                or project.get("charter_revision")
            ),
            "goals": tuple(
                charter_detail.get("deliverables")
                or intake.get("goals")
                or intake.get("objectives")
                or ()
            ),
            "exclusions": tuple(
                charter_detail.get("non_goals")
                or intake.get("exclusions")
                or ()
            ),
            "constraints": tuple(charter_detail.get("constraints") or ()),
            "budget_limit": charter_detail.get("budget_limit"),
            "budget_currency": charter_detail.get("budget_currency"),
            "approved_providers": tuple(
                charter_detail.get("approved_providers") or ()
            ),
            "approved_tools": tuple(
                charter_detail.get("approved_tools") or ()
            ),
            "workspaces": tuple(charter_detail.get("workspaces") or ()),
            "data_classifications": tuple(
                _mapping(charter_detail.get("authority_envelope")).get(
                    "data_classifications"
                )
                or ()
            ),
            "delegation_mode": charter_detail.get("delegation_mode"),
            "unresolved_questions": tuple(
                charter_detail.get("unresolved_questions") or ()
            ),
            "progress": _progress(work_items),
            "last_activity": (
                executive_project.get("updated_at")
                or proposal.get("updated_at")
            ),
        },
    ) if project_id else ()

    accounts = {
        str(item.get("account_id")): item
        for item in _rows(providers.get("accounts"))
    }
    sessions = _rows(providers.get("sessions"))
    usage_pools = _rows(providers.get("usage_pools"))
    waiting_provider_ids = {
        str(item.get("provider_id"))
        for item in _rows(control.get("waiting_for_usage_reset"))
        if item.get("provider_id")
    }
    waiting_provider_ids.update(
        str(item.get("provider_id"))
        for item in _rows(executive.get("task_status"))
        if (
            item.get("provider_id")
            and item.get("status") == "WAITING"
            and item.get("result_disposition")
            == "AUTHORITY_WAITING_FOR_USAGE_RESET"
        )
    )
    provider_cards = tuple(
        _provider_card(
            item,
            accounts,
            sessions,
            usage_pools,
            composition,
            waiting_provider_ids,
        )
        for item in _rows(providers.get("providers"))
    )
    usage_cards = tuple(
        {
            "pool_id": item.get("pool_id"),
            "provider_id": item.get("provider_id"),
            "consumed": item.get("consumed"),
            "reserved": item.get("reserved"),
            "remaining": (
                None
                if str(item.get("provider_id")) in waiting_provider_ids
                else item.get("remaining")
            ),
            "reset_at": item.get("reset_at"),
            "source": (
                "KEEPER_EXECUTIVE_WAIT"
                if str(item.get("provider_id")) in waiting_provider_ids
                else item.get("observation_source")
            ),
            "confidence": item.get("confidence"),
            "status": (
                "WAITING_FOR_USAGE_RESET"
                if item.get("exhausted")
                or str(item.get("provider_id")) in waiting_provider_ids
                else "AVAILABLE"
            ),
        }
        for item in usage_pools
    )

    reviews = _rows(project.get("reviews"))
    evidence_cards = tuple(
        {
            "evidence_id": item.get("evidence_bundle_id"),
            "producer": item.get("producer_provider_id"),
            "assignment_id": item.get("assignment_id"),
            "attempt_id": item.get("attempt_id"),
            "kind": _artifact_kinds(item),
            "state": item.get("state", "UNTRUSTED"),
            "digest": item.get("content_digest"),
            "timestamp": item.get("updated_at"),
            "review": _review_for_evidence(item, reviews),
        }
        for item in _rows(project.get("evidence"))
    )
    evidence_reference_cards = tuple(
        {
            "reference_id": item.get("evidence_reference_id"),
            "classification": item.get("source_kind"),
            "source_producer": item.get("producer_assignment_id"),
            "reviewed_assignment": item.get("review_target_assignment_id"),
            "digest": item.get("sha256"),
            "size_bytes": item.get("size_bytes"),
            "validation_state": item.get("state", "UNVALIDATED"),
            "review_state": (
                f"CONSUMED:{item.get('consumed_by_review_id')}"
                if item.get("consumed_by_review_id")
                else "AVAILABLE"
            ),
        }
        for item in _rows(project.get("evidence_references"))
    )
    review_cards = tuple(
        {
            "review_id": item.get("review_id"),
            "assignment_id": item.get("assignment_id"),
            "reviewer_assignment_id": item.get("reviewer_assignment_id"),
            "state": item.get("state", "PENDING"),
            "disposition": item.get("disposition"),
            "producer_evidence": item.get("producer_evidence_bundle_id"),
            "reviewer_evidence": item.get("reviewer_evidence_bundle_id"),
            "timestamp": item.get("updated_at"),
        }
        for item in reviews
    )

    grant_history = _rows(safety.get("delegated_mode_history"))
    safety_rows = (
        {
            "label": "KeeperAuthority",
            "value": _authority_summary(authority),
            "detail": authority,
        },
        {
            "label": "KeeperProviderHost",
            "value": str(provider_host.get("state", "NOT_CONFIGURED")),
            "detail": provider_host,
        },
        {
            "label": "Delegated mode",
            "value": _grant_summary(grant_history),
            "detail": grant_history,
        },
        {
            "label": "Uncertain assignments",
            "value": str(len(_rows(safety.get("uncertain_assignments")))),
            "detail": _rows(safety.get("uncertain_assignments")),
        },
        {
            "label": "Open pauses",
            "value": str(len(_rows(safety.get("open_pauses")))),
            "detail": _rows(safety.get("open_pauses")),
        },
        {
            "label": "Protected actions",
            "value": "Enforced",
            "detail": tuple(safety.get("prohibited_actions") or ()),
        },
    )
    active_assignments = _rows(control.get("active_assignments"))
    waiting = _rows(control.get("waiting_for_usage_reset"))
    uncertain_count = len(_rows(safety.get("uncertain_assignments")))
    right_rail = (
        ("Keeper", "Operational"),
        ("Active project", project_title),
        ("Assignments working", str(len(active_assignments))),
        ("Providers working", str(_busy_sessions(sessions))),
        ("Usage waits", str(len(waiting))),
        ("Approvals", "1" if conversation.get("approval_required") else "0"),
        ("Uncertain", str(uncertain_count)),
        ("Workspace conflicts", str(_workspace_conflicts(control))),
        ("KeeperAuthority", authority_state),
        ("Provider Host", str(provider_host.get("state", "NOT_CONFIGURED"))),
        ("Provider readiness", str(provider_host.get("provider_state", "UNAVAILABLE"))),
        ("Delegated mode", _active_grant_count(grant_history)),
    )
    normalized_sage = {
        "avatar_asset_identity": sage.get("avatar_asset_identity", "sage-default"),
        "form": sage.get("form", "default"),
        "expression": sage.get("expression", "neutral"),
        "activity_state": sage.get("activity_state", "LISTENING"),
        "mood": sage.get("mood", "CALM"),
        "background": sage.get("background", "black-gold"),
        "intensity": sage.get("intensity", 0.25),
        "interruption_state": sage.get("interruption_state", "IDLE"),
        "mode": sage.get("mode", "CONVERSATION"),
        "visible": str(sage.get("mode", "CONVERSATION")) != "HIDDEN",
        "authority_effect": "NONE",
    }
    return ProductViewModel(
        project_id=project_id,
        project_title=project_title,
        project_status=project_status,
        charter_revision=_optional_int(
            charter_detail.get("revision")
            or project.get("charter_revision")
        ),
        project_catalog=tuple(_rows(snapshot.get("projects"))),
        approval_charter_detail=approval_charter_detail,
        approval_required=approval_required,
        charter_detail=charter_detail,
        controls=tuple(str(item) for item in executive.get("controls", ())),
        composition=composition,
        timeline=tuple(timeline),
        project_cards=project_cards,
        workflow_rows=workflow_rows,
        provider_cards=provider_cards,
        provider_host=provider_host,
        usage_cards=usage_cards,
        evidence_cards=evidence_cards,
        evidence_reference_cards=evidence_reference_cards,
        review_cards=review_cards,
        safety_rows=safety_rows,
        right_rail=right_rail,
        sage=normalized_sage,
        developer_details=snapshot if developer_details else None,
    )


def _mapping(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _rows(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _optional_text(value: object) -> str | None:
    return str(value) if value is not None else None


def _optional_int(value: object) -> int | None:
    return int(value) if isinstance(value, int) else None


def _composition_label(authority_state: str) -> str:
    if authority_state == "TEST_COMPOSITION":
        return "TEST_COMPOSITION"
    if authority_state == "READY":
        return "PRODUCTION"
    return "NOT_CONFIGURED"


def _authority_summary(authority: dict[str, Any]) -> str:
    state = str(authority.get("state", "NOT_CONFIGURED"))
    parts = [state]
    for label, field in (
        ("service", "service_version"),
        ("protocol", "protocol_version"),
        ("schema", "schema_version"),
        ("identity", "identity_state"),
        ("provenance", "provenance_state"),
        ("checked", "last_checked_at"),
    ):
        value = authority.get(field)
        if value is not None:
            parts.append(f"{label} {value}")
    if authority.get("error"):
        parts.append(f"reason {authority['error']}")
    return " | ".join(parts)


def _charter_summary(proposal: dict[str, Any]) -> str:
    intake = _mapping(proposal.get("intake"))
    objective = (
        intake.get("objective")
        or intake.get("message")
        or intake.get("original_message")
        or "Review the proposed project boundaries."
    )
    return f"Revision {proposal.get('charter_revision', 1)} ? {objective}"


def _first_role(item: dict[str, Any]) -> str:
    roles = item.get("required_roles") or ()
    return str(roles[0]) if isinstance(roles, (list, tuple)) and roles else "UNASSIGNED"


def _assignment_for(
    work_item: dict[str, Any], assignments: list[dict[str, Any]]
) -> dict[str, Any] | None:
    work_item_id = work_item.get("work_item_id")
    return next(
        (item for item in assignments if item.get("work_item_id") == work_item_id),
        None,
    )


def _progress(work_items: list[dict[str, Any]]) -> str:
    if not work_items:
        return "No workflow yet"
    completed = sum(item.get("state") == "COMPLETED" for item in work_items)
    return f"{completed}/{len(work_items)} complete"


def _provider_card(
    provider: dict[str, Any],
    accounts: dict[str, dict[str, Any]],
    sessions: list[dict[str, Any]],
    usage_pools: list[dict[str, Any]],
    composition: str,
    waiting_provider_ids: set[str],
) -> dict[str, Any]:
    provider_id = str(provider.get("provider_id", ""))
    matching_sessions = [
        item for item in sessions if item.get("provider_id") == provider_id
    ]
    account = next(
        (
            value
            for value in accounts.values()
            if value.get("provider_id") == provider_id
        ),
        {},
    )
    label = "MOCK" if provider.get("adapter_kind") == "local-mock" else composition
    usage = next(
        (
            item
            for item in usage_pools
            if item.get("provider_id") == provider_id
        ),
        {},
    )
    return {
        "provider_id": provider_id,
        "name": provider.get("display_name") or provider_id,
        "classification": provider.get("classification"),
        "composition": label,
        "health": provider.get("health", "UNAVAILABLE"),
        "capabilities": tuple(provider.get("capabilities") or ()),
        "account": account.get("display_name") or account.get("account_id"),
        "cost_mode": account.get("cost_mode") or provider.get("cost_mode"),
        "privacy": account.get("privacy_classification"),
        "sessions": tuple(matching_sessions),
        "active_jobs": sum(int(item.get("active_assignments", 0)) for item in matching_sessions),
        "capacity": sum(int(item.get("concurrency_limit", 0)) for item in matching_sessions),
        "authentication_mode": provider.get("authentication_mode"),
        "billing_mode": provider.get("billing_mode"),
        "effort_levels": tuple(provider.get("effort_levels") or ()),
        "model_allowlist": tuple(provider.get("model_allowlist") or ()),
        "qualification_expires_at": provider.get(
            "model_revalidation_expires_at"
        ) or provider.get("pricing_expires_at"),
        "reviewer_eligible": provider.get("reviewer_eligible", True),
        "reviewer_status": (
            "AVAILABLE"
            if provider.get("reviewer_eligible", True)
            else "SEPARATE QUALIFIED REVIEWER REQUIRED"
        ),
        "api_billing": (
            "ENABLED"
            if provider.get("api_billing_authorized") is True
            else "DISABLED"
        ),
        "paid_fallback": (
            "ENABLED"
            if provider.get("paid_fallback_authorized") is True
            else "DISABLED"
        ),
        "usage_state": (
            "WAITING_FOR_USAGE_RESET"
            if usage.get("exhausted") is True
            or provider_id in waiting_provider_ids
            else ("UNKNOWN" if usage.get("remaining") is None else "AVAILABLE")
        ),
        "usage_remaining": (
            None if provider_id in waiting_provider_ids else usage.get("remaining")
        ),
        "usage_reset_at": usage.get("reset_at"),
        "usage_source": (
            "KEEPER_EXECUTIVE_WAIT"
            if provider_id in waiting_provider_ids
            else usage.get("observation_source")
        ),
        "binary_state": provider.get("health", "UNAVAILABLE"),
    }


def _artifact_kinds(evidence: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        str(item.get("kind", "unknown"))
        for item in _rows(evidence.get("artifacts"))
    )


def _review_for_evidence(
    evidence: dict[str, Any], reviews: list[dict[str, Any]]
) -> dict[str, Any] | None:
    evidence_id = evidence.get("evidence_bundle_id")
    return next(
        (
            item
            for item in reviews
            if item.get("producer_evidence_bundle_id") == evidence_id
            or item.get("reviewer_evidence_bundle_id") == evidence_id
        ),
        None,
    )


def _grant_summary(grants: list[dict[str, Any]]) -> str:
    states: dict[str, int] = {}
    for grant in grants:
        state = str(grant.get("state", "UNKNOWN"))
        states[state] = states.get(state, 0) + 1
    return ", ".join(f"{key}: {value}" for key, value in sorted(states.items())) or "None"


def _active_grant_count(grants: list[dict[str, Any]]) -> str:
    return str(sum(item.get("state") == "ACTIVE" for item in grants))


def _busy_sessions(sessions: list[dict[str, Any]]) -> int:
    return sum(int(item.get("active_assignments", 0)) > 0 for item in sessions)


def _workspace_conflicts(control: dict[str, Any]) -> int:
    counts = _mapping(control.get("assignment_counts"))
    return int(counts.get("BLOCKED", 0))
