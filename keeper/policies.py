from __future__ import annotations

from pathlib import Path, PurePosixPath
from datetime import datetime


PROTECTED_ACTIONS = frozenset(
    {
        "force_push",
        "rewrite_history",
        "delete_repository",
        "delete_backup_branch",
        "publish_secret",
        "spend_money",
        "create_paid_resource",
        "deploy_production",
        "enable_live_trading",
        "place_real_trade",
        "weaken_security",
        "disable_required_test",
        "major_architecture_change",
        "brokerage_access",
        "authentication_change",
        "authorization_change",
        "credential_access",
        "financial_operation",
        "database_migration",
        "destructive_database_operation",
        "delete_branch",
        "delete_worktree",
        "unrestricted_shell",
        "outside_repository_scope",
    }
)
KNOWN_CAPABILITIES = PROTECTED_ACTIONS | frozenset(
    {"repository_read", "repository_write", "run_verification"}
)

SENSITIVE_ENV_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "PRIVATE_KEY", "COOKIE", "CREDENTIAL")
DISABLED_PROVIDERS: frozenset[str] = frozenset({"qwen2.5-coder:14b"})
LIMITED_PROVIDER = "qwen3-coder:30b"
OLLAMA_MODEL = "qwen2.5-coder:14b"
OLLAMA_ALLOWED_ROLES = frozenset(
    {
        "preliminary_reviewer",
        "acceptance_checker",
        "diff_summarizer",
        "test_gap_analyzer",
        "documentation_reviewer",
        "log_analyzer",
        "implementation_advisor",
    }
)
LIMITED_PROVIDER_COMPONENTS = frozenset(
    {
        "authentication",
        "authorization",
        "secrets",
        "financial-calculation",
        "risk",
        "trade-validation",
        "execution",
        "broker",
        "database-migration",
        "deployment",
        "live-trading",
    }
)


def require_unprotected(action: str) -> None:
    if action in PROTECTED_ACTIONS:
        raise PermissionError(f"protected action requires explicit authorization: {action}")


def validate_capabilities(
    capabilities: list[str],
    *,
    task_id: str,
    attempt_id: str,
    repository: Path,
    authorizations: list[dict[str, object]],
    now: str,
) -> list[dict[str, object]]:
    try:
        now_timestamp = _parse_aware_timestamp(now)
    except ValueError as error:
        raise PermissionError("authorization validation time is invalid") from error
    unknown = sorted(set(capabilities) - KNOWN_CAPABILITIES)
    if unknown:
        raise PermissionError(f"unknown task capabilities: {', '.join(unknown)}")
    consumed: list[dict[str, object]] = []
    repository_identity = str(repository.resolve())
    for capability in capabilities:
        if capability not in PROTECTED_ACTIONS:
            continue
        matches: list[dict[str, object]] = []
        for item in authorizations:
            expires_at = item.get("expires_at")
            try:
                expiration = (
                    _parse_aware_timestamp(expires_at)
                    if isinstance(expires_at, str)
                    else None
                )
            except ValueError:
                expiration = None
            if (
                item.get("capability") == capability
                and item.get("task_id") == task_id
                and item.get("attempt_id") == attempt_id
                and item.get("repository") == repository_identity
                and isinstance(item.get("approving_authority"), str)
                and bool(item.get("approving_authority"))
                and expiration is not None
                and expiration > now_timestamp
                and item.get("consumed_at") is None
            ):
                matches.append(item)
        if len(matches) != 1:
            raise PermissionError(
                f"protected capability requires one valid scoped authorization: {capability}"
            )
        consumed.append(matches[0])
    return consumed


def _parse_aware_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include an unambiguous timezone")
    return parsed


def validate_provider_assignment(provider: str, risk: str, size: str, component: str) -> None:
    if provider in DISABLED_PROVIDERS:
        raise PermissionError(f"provider is disabled by policy: {provider}")
    return


def validate_provider_role(provider: str, role: str) -> None:
    if provider in DISABLED_PROVIDERS:
        raise PermissionError(f"provider is disabled by policy: {provider}")


def is_high_risk_component(component: str) -> bool:
    normalized = component.lower().replace("_", "-").replace(" ", "-")
    return normalized in LIMITED_PROVIDER_COMPONENTS


def is_qwen_provider(provider: str) -> bool:
    return provider.lower().startswith("qwen")


def select_reasoning_level(
    *,
    important_file_count: int = 0,
    changes_architecture_or_workflow: bool = False,
    test_failure_count: int = 0,
    qwen_authored_important_area: bool = False,
    sensitive_area: bool = False,
    live_or_brokerage: bool = False,
    unresolved_critical: bool = False,
    crosses_major_boundaries: bool = False,
) -> str:
    if live_or_brokerage or unresolved_critical or crosses_major_boundaries:
        return "extra-high"
    if (
        important_file_count > 5
        or changes_architecture_or_workflow
        or test_failure_count >= 2
        or qwen_authored_important_area
        or sensitive_area
    ):
        return "high"
    return "medium"


def filtered_environment(environment: dict[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in environment.items()
        if not any(marker in key.upper() for marker in SENSITIVE_ENV_MARKERS)
    }


def normalize_relative_path(value: str) -> str:
    normalized_input = value.replace("\\", "/")
    path = PurePosixPath(normalized_input)
    if (
        not value
        or "\x00" in value
        or path.is_absolute()
        or ".." in path.parts
        or ":" in normalized_input
        or normalized_input.startswith("//")
        or any(
            part.rstrip(" .").upper()
            in {
                "CON",
                "PRN",
                "AUX",
                "NUL",
                "COM1",
                "COM2",
                "COM3",
                "COM4",
                "COM5",
                "COM6",
                "COM7",
                "COM8",
                "COM9",
                "LPT1",
                "LPT2",
                "LPT3",
                "LPT4",
                "LPT5",
                "LPT6",
                "LPT7",
                "LPT8",
                "LPT9",
            }
            or part != part.rstrip(" .")
            for part in path.parts
        )
    ):
        raise ValueError(f"unsafe repository-relative path: {value}")
    normalized = path.as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized:
        raise ValueError("empty path is not allowed")
    return normalized


def enforce_path_scope(changed: list[str], allowed: list[str], blocked: list[str]) -> None:
    safe_allowed = [normalize_relative_path(item).rstrip("/") for item in allowed]
    safe_blocked = [normalize_relative_path(item).rstrip("/") for item in blocked]
    for raw in changed:
        path = normalize_relative_path(raw)
        if any(path == item or path.startswith(f"{item}/") for item in safe_blocked):
            raise PermissionError(f"changed path is blocked: {path}")
        if not any(path == item or path.startswith(f"{item}/") for item in safe_allowed):
            raise PermissionError(f"changed path is outside allowed scope: {path}")


def resolve_within(root: Path, relative: str) -> Path:
    candidate = (root / normalize_relative_path(relative)).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"path escapes repository root: {relative}")
    return candidate
