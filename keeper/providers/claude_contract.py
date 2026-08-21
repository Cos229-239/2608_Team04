from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


CLAUDE_PROVIDER_ID = "claude"
CLAUDE_AUTHENTICATION_MODE = "claude-ai-subscription"
CLAUDE_BILLING_MODE = "included-subscription"
CLAUDE_AUTHENTICODE_PUBLISHER = "Anthropic, PBC"
CLAUDE_AUTHENTICODE_THUMBPRINT = "0D7581D2C51C59DF686C3000C70BF543F9F6C6CB"
CLAUDE_ALLOWED_SUBSCRIPTION_PLANS = frozenset({"pro", "max"})
CLAUDE_ALLOWED_EFFORTS = frozenset({"medium", "high"})
CLAUDE_PINNED_REVIEW_MODEL = "claude-sonnet-4-6-20251114"
CLAUDE_QUALIFICATION_NONCE = "keeper-claude-qualification-v1"
CLAUDE_QUALIFICATION_PROMPT = (
    "Return only the JSON object required by the supplied schema. This is a "
    "harmless Keeper provider qualification. Do not read or write project "
    "files, use tools, access credentials, or perform any operation beyond "
    "this response."
)


def validate_claude_version_output(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[1-9][0-9]*\.[0-9]+\.[0-9]+ \(Claude Code\)",
        value.strip(),
    ):
        raise ValueError("Claude executable version is invalid")
    return value.strip()


def claude_qualification_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "status": {"type": "string", "const": "ok"},
            "provider": {"type": "string", "const": "claude"},
            "effort": {"type": "string", "const": "medium"},
            "nonce": {
                "type": "string",
                "const": CLAUDE_QUALIFICATION_NONCE,
            },
        },
        "required": ["status", "provider", "effort", "nonce"],
    }


def build_claude_qualification_command(executable: Path) -> list[str]:
    return build_claude_exec_command(
        executable,
        model_id=CLAUDE_PINNED_REVIEW_MODEL,
        reasoning_level="medium",
        schema=claude_qualification_schema(),
        prompt=CLAUDE_QUALIFICATION_PROMPT,
    )


def validate_claude_model_allowlist(value: object) -> list[str]:
    if value != [CLAUDE_PINNED_REVIEW_MODEL]:
        raise ValueError("Claude model allowlist is not the pinned reviewer model")
    return [CLAUDE_PINNED_REVIEW_MODEL]


def validate_claude_authentication_policy(value: object) -> dict[str, Any]:
    expected = {
        "mode": CLAUDE_AUTHENTICATION_MODE,
        "identity_source": "authenticated-named-pipe-client",
        "session_selection": "authenticated-client-session-only",
        "profile_access": "restricted-user-profile",
        "setting_sources": "none",
        "api_keys_allowed": False,
        "credential_copy_allowed": False,
        "paid_fallback_allowed": False,
        "provider_switch_allowed": False,
    }
    if not isinstance(value, dict) or value != expected:
        raise ValueError("Claude authentication policy is not fail-closed")
    return dict(value)


def validate_claude_usage_policy(value: object) -> dict[str, Any]:
    expected_fields = {
        "capacity_mode",
        "keeper_launch_budget",
        "budget_window_seconds",
        "unknown_capacity_behavior",
        "reset_policy",
        "automatic_retry",
        "provider_switch",
        "account_switch",
        "api_fallback",
        "credit_purchase",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise ValueError("Claude usage policy fields are invalid")
    result = dict(value)
    if (
        result.get("capacity_mode") != "keeper-budget-only"
        or isinstance(result.get("keeper_launch_budget"), bool)
        or not isinstance(result.get("keeper_launch_budget"), int)
        or not 1 <= result["keeper_launch_budget"] <= 1000
        or isinstance(result.get("budget_window_seconds"), bool)
        or not isinstance(result.get("budget_window_seconds"), int)
        or not 3600 <= result["budget_window_seconds"] <= 31_536_000
        or result.get("unknown_capacity_behavior") != "fail-closed-at-keeper-budget"
        or result.get("reset_policy") != "founder-reauthorization-only"
        or any(
            result.get(name) is not False
            for name in (
                "automatic_retry",
                "provider_switch",
                "account_switch",
                "api_fallback",
                "credit_purchase",
            )
        )
    ):
        raise ValueError("Claude usage policy is not fail-closed")
    return result


def validate_claude_subscription_pricing_authority(
    value: object,
) -> dict[str, Any]:
    fields = {
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
        "billing_mode",
        "incremental_charge_authorized",
        "api_billing_authorized",
        "paid_fallback_authorized",
        "credit_purchase_authorized",
        "provider_switch_authorized",
        "account_switch_authorized",
        "capacity_bounded",
        "founder_confirmed",
        "subscription_plan",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Claude pricing authority fields are invalid")
    result = dict(value)
    try:
        quoted = datetime.fromisoformat(str(result["quoted_at"]))
        expires = datetime.fromisoformat(str(result["expires_at"]))
    except (KeyError, ValueError) as error:
        raise ValueError("Claude pricing timestamps are invalid") from error
    if (
        quoted.tzinfo is None
        or expires.tzinfo is None
        or expires <= quoted
        or expires <= datetime.now(UTC)
        or result.get("currency") != "USD"
        or result.get("billing_mode") != CLAUDE_BILLING_MODE
        or result.get("billing_unit") != "claude-subscription"
        or result.get("subscription_plan") not in CLAUDE_ALLOWED_SUBSCRIPTION_PLANS
        or result.get("estimated_cost") != 0
        or result.get("maximum_cost") != 0
        or result.get("cost_tier") != 0
        or result.get("included_plan") is not True
        or result.get("marginally_free") is not False
        or result.get("incremental_charge_authorized") is not False
        or result.get("api_billing_authorized") is not False
        or result.get("paid_fallback_authorized") is not False
        or result.get("credit_purchase_authorized") is not False
        or result.get("provider_switch_authorized") is not False
        or result.get("account_switch_authorized") is not False
        or result.get("capacity_bounded") is not True
        or result.get("founder_confirmed") is not True
        or not all(
            isinstance(result.get(name), str)
            and bool(str(result[name]).strip())
            and len(str(result[name])) <= 256
            for name in (
                "pricing_identity",
                "pricing_version",
                "billing_unit",
                "source",
            )
        )
    ):
        raise ValueError("Claude pricing authority is contradictory")
    return result


def validate_claude_authenticode_binding(value: object) -> dict[str, Any]:
    fields = {
        "status",
        "publisher_subject",
        "certificate_thumbprint",
        "source",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Claude Authenticode binding fields are invalid")
    result = dict(value)
    if (
        result.get("status") != "Valid"
        or CLAUDE_AUTHENTICODE_PUBLISHER
        not in str(result.get("publisher_subject", ""))
        or str(result.get("certificate_thumbprint", "")).upper()
        != CLAUDE_AUTHENTICODE_THUMBPRINT
        or result.get("source") != "windows-authenticode"
    ):
        raise ValueError("Claude Authenticode publisher is not authorized")
    return result


def validate_claude_subscription_account_binding(
    value: object,
) -> dict[str, Any]:
    fields = {
        "authentication_method",
        "plan_type",
        "account_identity_digest",
        "source",
        "observed_at",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Claude account binding fields are invalid")
    result = dict(value)
    digest = result.get("account_identity_digest")
    try:
        observed_at = datetime.fromisoformat(str(result.get("observed_at")))
    except ValueError as error:
        raise ValueError("Claude account binding timestamp is invalid") from error
    if (
        result.get("authentication_method") != CLAUDE_AUTHENTICATION_MODE
        or result.get("plan_type") not in CLAUDE_ALLOWED_SUBSCRIPTION_PLANS
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or result.get("source") != "authority-verified-provider-host-probe"
        or observed_at.tzinfo is None
    ):
        raise ValueError("Claude account binding is invalid")
    return result


def validate_claude_model_capability_binding(
    value: object,
) -> dict[str, Any]:
    fields = {"models", "source", "observed_at"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Claude model capability fields are invalid")
    result = dict(value)
    if result.get("models") != [
        {
            "model_id": CLAUDE_PINNED_REVIEW_MODEL,
            "supported_reasoning_efforts": ["medium", "high"],
        }
    ] or result.get("source") != "authority-verified-provider-host-probe":
        raise ValueError("Claude model capability binding is invalid")
    try:
        observed_at = datetime.fromisoformat(str(result.get("observed_at")))
    except ValueError as error:
        raise ValueError("Claude model capability timestamp is invalid") from error
    if observed_at.tzinfo is None:
        raise ValueError("Claude model capability timestamp is invalid")
    return result


def parse_claude_auth_status(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise PermissionError("Claude authentication response is not JSON") from error
    fields = {
        "loggedIn",
        "authMethod",
        "apiProvider",
        "email",
        "orgId",
        "orgName",
        "subscriptionType",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise PermissionError("Claude authentication response fields are invalid")
    email = str(value.get("email", "")).strip().casefold()
    organization = str(value.get("orgId", "")).strip()
    plan = str(value.get("subscriptionType", "")).strip().casefold()
    if (
        value.get("loggedIn") is not True
        or value.get("authMethod") != "claude.ai"
        or value.get("apiProvider") != "firstParty"
        or not email
        or "@" not in email
        or len(email) > 320
        or not organization
        or len(organization) > 256
        or plan not in CLAUDE_ALLOWED_SUBSCRIPTION_PLANS
    ):
        raise PermissionError("Claude subscription authentication is not authorized")
    digest = hashlib.sha256(
        ("claude.ai\0" + email + "\0" + organization).encode("utf-8")
    ).hexdigest()
    return {
        "authentication_method": CLAUDE_AUTHENTICATION_MODE,
        "plan_type": plan,
        "account_identity_digest": digest,
        "models": [CLAUDE_PINNED_REVIEW_MODEL],
        "model_capabilities": [
            {
                "model_id": CLAUDE_PINNED_REVIEW_MODEL,
                "supported_reasoning_efforts": ["medium", "high"],
            }
        ],
        "usage_observation": {
            "capacity_known": False,
            "source": "claude-subscription-auth-status",
        },
    }


def build_claude_exec_command(
    executable: Path,
    *,
    model_id: str,
    reasoning_level: str,
    schema: dict[str, Any],
    prompt: str,
) -> list[str]:
    if model_id != CLAUDE_PINNED_REVIEW_MODEL:
        raise PermissionError("Claude model differs from the pinned reviewer model")
    if reasoning_level not in CLAUDE_ALLOWED_EFFORTS:
        raise PermissionError("Claude effort differs from the reviewer contract")
    return [
        str(executable),
        "--setting-sources=",
        "--strict-mcp-config",
        "--mcp-config",
        "{}",
        "--disable-slash-commands",
        "--no-chrome",
        "--no-session-persistence",
        "--permission-mode",
        "plan",
        "--tools",
        "Read,Grep,Glob",
        "--model",
        model_id,
        "--effort",
        reasoning_level,
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(schema, sort_keys=True, separators=(",", ":")),
        "-p",
        prompt,
    ]
