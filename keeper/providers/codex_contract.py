from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


CODEX_PROVIDER_ID = "codex"
CODEX_AUTHENTICATION_MODE = "chatgpt-subscription"
CODEX_BILLING_MODE = "included-subscription"
CODEX_AUTHENTICODE_PUBLISHER = "OpenAI OpCo, LLC"
CODEX_AUTHENTICODE_THUMBPRINT = "0B7C30C11BF7250EC1ECD3254AC781D9E13D62F8"  # gitleaks:allow
CODEX_ALLOWED_EFFORTS = frozenset({"medium", "high"})
CODEX_KNOWN_MODEL_EFFORTS = frozenset(
    {"low", "medium", "high", "xhigh", "max", "ultra"}
)
# The pricing declaration retains the original Plus entitlement class so the
# already-exhausted registration family keeps its exact semantic identity.
# Runtime account evidence may be either Plus or Pro; both are ChatGPT-managed
# included-subscription plans and neither authorizes API-key billing or fallback.
CODEX_REQUIRED_SUBSCRIPTION_PLAN = "plus"
CODEX_ALLOWED_SUBSCRIPTION_PLANS = frozenset({"plus", "pro"})
CODEX_PROHIBITED_ENVIRONMENT = frozenset(
    {
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "OPENAI_ORG_ID",
        "OPENAI_PROJECT_ID",
    }
)


def validate_executable_file_identity(value: object) -> dict[str, int]:
    fields = {
        "schema_version",
        "device_id",
        "file_id",
        "size",
        "modified_ns",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Codex executable file identity fields are invalid")
    result: dict[str, int] = {}
    for name in fields:
        item = value.get(name)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ValueError("Codex executable file identity is invalid")
        result[name] = item
    if (
        result["schema_version"] != 1
        or result["file_id"] == 0
        or result["size"] == 0
    ):
        raise ValueError("Codex executable file identity is invalid")
    return result


def validate_codex_model_allowlist(value: object) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 8
        or value != sorted(set(value))
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 128
            or item != item.strip()
            or any(ord(character) < 32 for character in item)
            for item in value
        )
    ):
        raise ValueError("Codex model allowlist is invalid")
    return list(value)


def validate_codex_authentication_policy(value: object) -> dict[str, Any]:
    fields = {
        "mode",
        "identity_source",
        "session_selection",
        "profile_access",
        "ignore_user_config",
        "api_keys_allowed",
        "credential_copy_allowed",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Codex authentication policy fields are invalid")
    result = dict(value)
    expected = {
        "mode": CODEX_AUTHENTICATION_MODE,
        "identity_source": "authenticated-named-pipe-client",
        "session_selection": "authenticated-client-session-only",
        "profile_access": "restricted-user-profile",
        "ignore_user_config": True,
        "api_keys_allowed": False,
        "credential_copy_allowed": False,
    }
    if result != expected:
        raise ValueError("Codex authentication policy is not fail-closed")
    return result


def validate_windows_authentication_binding(value: object) -> dict[str, Any]:
    fields = {
        "principal_sid",
        "windows_session_id",
        "profile_identity",
        "profile_digest",
        "source",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Codex Windows authentication binding fields are invalid")
    result = dict(value)
    sid = result.get("principal_sid")
    session_id = result.get("windows_session_id")
    profile = result.get("profile_identity")
    digest = result.get("profile_digest")
    if (
        not isinstance(sid, str)
        or not sid.startswith("S-1-")
        or isinstance(session_id, bool)
        or not isinstance(session_id, int)
        or session_id < 0
        or not isinstance(profile, str)
        or not profile
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or result.get("source") != "authenticated-named-pipe-client-process"
    ):
        raise ValueError("Codex Windows authentication binding is invalid")
    return result


def validate_subscription_account_binding(value: object) -> dict[str, Any]:
    fields = {
        "authentication_method",
        "plan_type",
        "account_identity_digest",
        "source",
        "observed_at",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Codex subscription account binding fields are invalid")
    result = dict(value)
    digest = result.get("account_identity_digest")
    try:
        observed_at = datetime.fromisoformat(str(result.get("observed_at")))
    except ValueError as error:
        raise ValueError("Codex subscription account timestamp is invalid") from error
    if (
        result.get("authentication_method") != CODEX_AUTHENTICATION_MODE
        or result.get("plan_type") not in CODEX_ALLOWED_SUBSCRIPTION_PLANS
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or result.get("source") not in {
            "authority-public-codex-probe",
            "authority-verified-provider-host-probe",
        }
        or observed_at.tzinfo is None
    ):
        raise ValueError("Codex subscription account binding is invalid")
    return result


def validate_codex_model_capability_binding(value: object) -> dict[str, Any]:
    fields = {"models", "source", "observed_at"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Codex model capability binding fields are invalid")
    result = dict(value)
    models = result.get("models")
    if not isinstance(models, list) or not models:
        raise ValueError("Codex model capability binding is empty")
    normalized: list[dict[str, Any]] = []
    for model in models:
        if not isinstance(model, dict) or set(model) != {
            "model_id",
            "supported_reasoning_efforts",
        }:
            raise ValueError("Codex model capability entry is invalid")
        model_id = model.get("model_id")
        efforts = model.get("supported_reasoning_efforts")
        if (
            not isinstance(model_id, str)
            or not model_id
            or not isinstance(efforts, list)
            or not all(isinstance(item, str) for item in efforts)
            or len(efforts) != len(set(efforts))
            or not CODEX_ALLOWED_EFFORTS.issubset(efforts)
            or any(item not in CODEX_KNOWN_MODEL_EFFORTS for item in efforts)
        ):
            raise ValueError("Codex model capability authority is invalid")
        normalized.append(
            {
                "model_id": model_id,
                "supported_reasoning_efforts": list(efforts),
            }
        )
    if [item["model_id"] for item in normalized] != sorted(
        {item["model_id"] for item in normalized}
    ):
        raise ValueError("Codex model capability identities are invalid")
    try:
        observed_at = datetime.fromisoformat(str(result.get("observed_at")))
    except ValueError as error:
        raise ValueError("Codex model capability timestamp is invalid") from error
    if (
        result.get("source") not in {
            "authority-public-codex-probe",
            "authority-verified-provider-host-probe",
        }
        or observed_at.tzinfo is None
    ):
        raise ValueError("Codex model capability binding is invalid")
    result["models"] = normalized
    return result


def validate_codex_authenticode_binding(value: object) -> dict[str, Any]:
    fields = {
        "status",
        "publisher_subject",
        "certificate_thumbprint",
        "source",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Codex Authenticode binding fields are invalid")
    result = dict(value)
    if (
        result.get("status") != "Valid"
        or CODEX_AUTHENTICODE_PUBLISHER
        not in str(result.get("publisher_subject", ""))
        or str(result.get("certificate_thumbprint", "")).upper()
        != CODEX_AUTHENTICODE_THUMBPRINT
        or result.get("source") != "windows-authenticode"
    ):
        raise ValueError("Codex Authenticode publisher is not authorized")
    return result


def validate_codex_usage_policy(value: object) -> dict[str, Any]:
    fields = {
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
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Codex usage policy fields are invalid")
    result = dict(value)
    if (
        result.get("capacity_mode")
        != "provider-observed-or-keeper-budget"
        or isinstance(result.get("keeper_launch_budget"), bool)
        or not isinstance(result.get("keeper_launch_budget"), int)
        or not 1 <= result["keeper_launch_budget"] <= 1000
        or isinstance(result.get("budget_window_seconds"), bool)
        or not isinstance(result.get("budget_window_seconds"), int)
        or not 3600 <= result["budget_window_seconds"] <= 31_536_000
        or result.get("unknown_capacity_behavior")
        != "fail-closed-at-keeper-budget"
        or result.get("reset_policy") != "provider-observed-only"
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
        raise ValueError("Codex usage policy is not fail-closed")
    return result


def validate_subscription_pricing_authority(value: object) -> dict[str, Any]:
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
        raise ValueError("subscription pricing authority fields are invalid")
    result = dict(value)
    for name in (
        "pricing_identity",
        "pricing_version",
        "currency",
        "billing_unit",
        "quoted_at",
        "expires_at",
        "source",
        "billing_mode",
        "subscription_plan",
    ):
        item = result.get(name)
        if (
            not isinstance(item, str)
            or not item
            or item != item.strip()
            or len(item) > 256
            or any(ord(character) < 32 for character in item)
        ):
            raise ValueError(f"subscription pricing authority {name} is invalid")
    try:
        quoted = datetime.fromisoformat(str(result["quoted_at"]))
        expires = datetime.fromisoformat(str(result["expires_at"]))
    except ValueError as error:
        raise ValueError("subscription pricing timestamps are invalid") from error
    if (
        quoted.tzinfo is None
        or expires.tzinfo is None
        or expires <= quoted
        or expires <= datetime.now(UTC)
        or result.get("currency") != "USD"
        or result.get("billing_mode") != CODEX_BILLING_MODE
        or result.get("billing_unit") != "chatgpt-subscription"
        or result.get("subscription_plan") != CODEX_REQUIRED_SUBSCRIPTION_PLAN
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
    ):
        raise ValueError("subscription pricing authority is contradictory")
    return result


def sanitized_codex_environment(
    environment: dict[str, str], *, codex_home: Path
) -> dict[str, str]:
    keep = {
        "ALLUSERSPROFILE",
        "APPDATA",
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        "COMMONPROGRAMW6432",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    }
    result = {
        key: value
        for key, value in environment.items()
        if key.upper() in keep
        and key.upper() not in CODEX_PROHIBITED_ENVIRONMENT
    }
    if not codex_home.is_absolute() or ".." in codex_home.parts:
        raise PermissionError("Codex profile path is not Authority-canonical")
    # The profile root was already bound to the authenticated SID/session by
    # KeeperAuthority.  Do not make the service identity traverse the
    # Founder-owned credential directory while constructing the restricted
    # provider environment.
    result["CODEX_HOME"] = str(codex_home)
    result["CODEX_NON_INTERACTIVE"] = "1"
    if any(name in result for name in CODEX_PROHIBITED_ENVIRONMENT):
        raise PermissionError("Codex API-key environment was not removed")
    return result


def build_codex_exec_command(
    executable: Path,
    *,
    model_id: str,
    reasoning_level: str,
    schema_path: Path,
    output_path: Path,
    prompt: str,
) -> list[str]:
    if reasoning_level not in CODEX_ALLOWED_EFFORTS:
        raise PermissionError("Codex reasoning effort is not authorized")
    if not model_id:
        raise ValueError("Codex model identity is required")
    if not executable.is_absolute():
        raise PermissionError("Codex executable path is not Authority-canonical")
    return [
        # The Authority observer already measured and locked this exact path
        # under the authenticated Founder token.  Command construction must be
        # lexical: the service identity is not authorized to traverse the
        # Founder-owned installation path.
        str(executable),
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--skip-git-repo-check",
        "--sandbox",
        "workspace-write",
        "--model",
        model_id,
        "-c",
        f'model_reasoning_effort="{reasoning_level}"',
        "--json",
        "--output-schema",
        str(schema_path.resolve()),
        "--output-last-message",
        str(output_path.resolve()),
        prompt,
    ]


def _app_server_probe_requests() -> tuple[dict[str, Any], ...]:
    return (
        {"method": "initialize", "id": 1, "params": {"clientInfo": {"name": "keeper-authority", "version": "1"}}},
        {"method": "initialized", "params": {}},
        {"method": "account/read", "id": 2, "params": {}},
        {"method": "model/list", "id": 3, "params": {}},
        {"method": "account/rateLimits/read", "id": 4, "params": {}},
        {"method": "account/usage/read", "id": 5, "params": {}},
    )


def app_server_probe_input() -> str:
    return "".join(
        json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
        for item in _app_server_probe_requests()
    )


def app_server_probe_exchange() -> tuple[tuple[str, int | None], ...]:
    return tuple(
        (
            json.dumps(item, sort_keys=True, separators=(",", ":")),
            int(item["id"]) if "id" in item else None,
        )
        for item in _app_server_probe_requests()
    )


def account_identity_probe_exchange() -> tuple[tuple[str, int | None], ...]:
    """Return the account-only app-server exchange used by Founder discovery.

    This intentionally excludes model, rate-limit, usage, and execution calls.
    """

    return tuple(
        (
            json.dumps(item, sort_keys=True, separators=(",", ":")),
            int(item["id"]) if "id" in item else None,
        )
        for item in _app_server_probe_requests()[:3]
    )


def parse_codex_account_identity_probe(lines: Iterable[str]) -> dict[str, str]:
    responses = _app_server_responses(lines)
    if set(responses) != {1, 2}:
        raise PermissionError("Codex public account probe response set is invalid")
    for identifier in (1, 2):
        response = responses.get(identifier)
        if not isinstance(response, dict) or "error" in response:
            raise PermissionError("Codex public account probe is incomplete")
    return _account_identity_from_response(responses[2])


def parse_codex_app_server_probe(
    lines: Iterable[str], *, model_allowlist: list[str]
) -> dict[str, Any]:
    responses = _app_server_responses(lines)
    for identifier in (1, 2, 3, 4):
        response = responses.get(identifier)
        if not isinstance(response, dict) or "error" in response:
            raise PermissionError("Codex public account/model probe is incomplete")
    account_identity = _account_identity_from_response(responses[2])
    plan_type = account_identity["plan_type"]
    account_identity_digest = account_identity["account_identity_digest"]
    model_result = responses[3].get("result")
    models = model_result.get("data") if isinstance(model_result, dict) else None
    if not isinstance(models, list):
        raise PermissionError("Codex model response is malformed")
    visible: dict[str, list[str]] = {}
    for item in models:
        if not isinstance(item, dict) or item.get("hidden") is True:
            continue
        model_id = str(item.get("model", item.get("id", "")))
        raw_efforts = item.get("supportedReasoningEfforts")
        if not isinstance(raw_efforts, list):
            continue
        efforts: list[str] = []
        for effort in raw_efforts:
            if isinstance(effort, str):
                value = effort
            elif isinstance(effort, dict):
                value = str(
                    effort.get("reasoningEffort", effort.get("effort", ""))
                )
            else:
                value = ""
            normalized = value.strip().casefold()
            if normalized:
                efforts.append(normalized)
        visible[model_id] = efforts
    if not set(model_allowlist).issubset(visible):
        raise PermissionError("Codex approved model is unavailable")
    model_capabilities = [
        {
            "model_id": model_id,
            "supported_reasoning_efforts": visible[model_id],
        }
        for model_id in model_allowlist
    ]
    if any(
        not CODEX_ALLOWED_EFFORTS.issubset(
            item["supported_reasoning_efforts"]
        )
        for item in model_capabilities
    ):
        raise PermissionError(
            "Codex approved model reasoning efforts are not exactly authorized"
        )
    rate_result = responses[4].get("result")
    if not isinstance(rate_result, dict):
        raise PermissionError("Codex rate-limit response is malformed")
    observation = _rate_limit_observation(rate_result)
    return {
        "authentication_method": "chatgpt-subscription",
        "plan_type": plan_type,
        "account_identity_digest": account_identity_digest,
        "models": sorted(set(model_allowlist)),
        "model_capabilities": model_capabilities,
        "usage_observation": observation,
        "usage_summary_available": 5 in responses and "error" not in responses[5],
    }


def _app_server_responses(lines: Iterable[str]) -> dict[int, dict[str, Any]]:
    responses: dict[int, dict[str, Any]] = {}
    for line in lines:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and isinstance(value.get("id"), int):
            identifier = int(value["id"])
            if identifier in responses:
                raise PermissionError("Codex app-server response ID is duplicated")
            responses[identifier] = value
    return responses


def _account_identity_from_response(response: dict[str, Any]) -> dict[str, str]:
    account_result = response.get("result")
    if not isinstance(account_result, dict):
        raise PermissionError("Codex account response is malformed")
    account = account_result.get("account", account_result)
    if (
        not isinstance(account, dict)
        or str(account.get("type", "")).casefold() != "chatgpt"
    ):
        raise PermissionError("Codex is not authenticated with ChatGPT")
    plan_type = str(account.get("planType", "")).strip().casefold()
    account_email = str(account.get("email", "")).strip().casefold()
    if plan_type not in CODEX_ALLOWED_SUBSCRIPTION_PLANS:
        raise PermissionError("Codex ChatGPT subscription plan is not authorized")
    if not account_email or "@" not in account_email or len(account_email) > 320:
        raise PermissionError("Codex ChatGPT account identity is unavailable")
    return {
        "authentication_method": "chatgpt-subscription",
        "plan_type": plan_type,
        "account_identity_digest": hashlib.sha256(
            f"chatgpt\0{account_email}".encode("utf-8")
        ).hexdigest(),
    }


def _rate_limit_observation(value: dict[str, Any]) -> dict[str, Any]:
    buckets: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    primary_limits = value.get("rateLimits")
    if isinstance(primary_limits, dict):
        candidates.append(primary_limits)
    by_identifier = value.get("rateLimitsByLimitId")
    if isinstance(by_identifier, dict):
        candidates.extend(
            item for item in by_identifier.values() if isinstance(item, dict)
        )
    seen: set[tuple[object, object, object, object]] = set()
    exhausted_type: object = None
    spend_control_reached = False
    for limit in candidates:
        exhausted_type = exhausted_type or limit.get("rateLimitReachedType")
        spend_control_reached = spend_control_reached or (
            limit.get("spendControlReached") is True
        )
        for window_name in ("primary", "secondary"):
            item = limit.get(window_name)
            if not isinstance(item, dict):
                continue
            used = item.get("usedPercent")
            reset = item.get("resetsAt")
            duration = item.get("windowDurationMins")
            if (
                isinstance(used, (int, float))
                and not isinstance(used, bool)
                and 0 <= float(used) <= 100
                and (reset is None or isinstance(reset, (int, float, str)))
                and (duration is None or isinstance(duration, (int, float)))
            ):
                identity = (limit.get("limitId"), window_name, duration, reset)
                if identity not in seen:
                    seen.add(identity)
                    buckets.append(
                        {
                            "limit_id": str(limit.get("limitId", "unknown")),
                            "window": window_name,
                            "used_percent": float(used),
                            "resets_at": reset,
                            "window_duration_minutes": duration,
                        }
                    )
    if not buckets:
        return {
            "capacity_state": "UNKNOWN",
            "source": "CODEX_APP_SERVER_RATE_LIMITS",
            "confidence": "LOW",
            "exhausted": False,
            "credits_ignored": True,
            "buckets": [],
        }
    return {
        "capacity_state": "OBSERVED",
        "source": "CODEX_APP_SERVER_RATE_LIMITS",
        "confidence": "HIGH",
        "exhausted": bool(exhausted_type) or spend_control_reached or any(
            item["used_percent"] >= 100 for item in buckets
        ),
        "credits_ignored": True,
        "buckets": buckets,
    }


def structured_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def classify_codex_execution_failure(
    *,
    exit_status: int,
    timed_out: bool,
    cancelled: bool,
    stderr: str,
    structured_events: str,
    output_valid: bool,
) -> str:
    """Classify sanitized Codex outcomes without retaining provider text."""
    if cancelled:
        return "CANCELLED"
    if timed_out:
        return "TIMEOUT"
    combined = f"{stderr}\n{structured_events}".casefold()
    if any(
        marker in combined
        for marker in (
            "rate limit",
            "rate_limit",
            "usage limit",
            "usage_limit",
            "quota exceeded",
            "too many requests",
            '"status":429',
            '"code":429',
        )
    ):
        return "SUBSCRIPTION_EXHAUSTED"
    if any(
        marker in combined
        for marker in (
            "not logged in",
            "authentication failed",
            "unauthorized",
            "login required",
            '"status":401',
            '"code":401',
        )
    ):
        return "AUTHENTICATION_FAILED"
    if any(
        marker in combined
        for marker in (
            "connection refused",
            "connection reset",
            "network is unreachable",
            "dns",
            "tls",
            "timed out connecting",
        )
    ):
        return "NETWORK_FAILURE"
    if exit_status == 0 and not output_valid:
        return "INVALID_OUTPUT"
    if exit_status != 0:
        return "PROVIDER_ERROR"
    return "COMPLETED"
