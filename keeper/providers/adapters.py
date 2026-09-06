from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import uuid
from datetime import UTC, datetime
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from keeper.evidence_input import review_input_declaration_json_schema
from keeper.providers.base import AgentRequest, ProcessResult
from keeper.providers.codex_cli import CliProvider
from keeper.providers.codex_contract import (
    build_codex_exec_command,
    structured_digest,
    validate_codex_authentication_policy,
    validate_codex_authenticode_binding,
    validate_codex_model_capability_binding,
    validate_codex_model_allowlist,
    validate_codex_usage_policy,
    validate_executable_file_identity,
    validate_subscription_account_binding,
    validate_subscription_pricing_authority,
    validate_windows_authentication_binding,
)
from keeper.providers.claude_contract import (
    build_claude_qualification_command,
    validate_claude_authentication_policy,
    validate_claude_authenticode_binding,
    validate_claude_model_allowlist,
    validate_claude_model_capability_binding,
    validate_claude_subscription_account_binding,
    validate_claude_subscription_pricing_authority,
    validate_claude_usage_policy,
    validate_claude_version_output,
)

REGISTRATION_SCHEMA_VERSION = 3
CODEX_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION = 4
CLAUDE_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION = 5
_SHA256_LENGTH = 64
_EFFORT_LEVELS = frozenset({"low", "medium", "high", "xhigh"})
_EXECUTIVE_CAPABILITIES = frozenset(
    {
        "acceptance", "architecture", "arrangement", "asset creation",
        "composition", "copy editing", "creative direction",
        "critical analysis", "developmental editing", "document production",
        "editorial planning", "implementation", "mastering", "media export",
        "media review", "mixing", "music delivery", "music direction",
        "outlining", "packaging", "planning", "production", "recording",
        "report writing", "requirements", "research design", "review",
        "revision", "script writing", "security", "source collection",
        "source review", "storyboarding", "synthesis", "testing",
        "video editing", "writing",
    }
)
_PROJECT_TYPES = frozenset(
    {
        "business_operations", "design", "general", "marketing", "music",
        "research", "software", "video", "writing",
    }
)
_PRICING_AUTHORITY_FIELDS = frozenset(
    {
        "pricing_identity", "pricing_version", "currency",
        "estimated_cost", "maximum_cost", "billing_unit",
        "included_plan", "marginally_free", "quoted_at",
        "expires_at", "source", "cost_tier",
    }
)
_REGISTRATION_FIELDS = {
    "registration_schema_version",
    "trusted_registration_id",
    "registration_version",
    "logical_provider_id",
    "provider_name",
    "provider_type",
    "canonical_executable_path",
    "executable_sha256",
    "executable_size",
    "executable_registration_id",
    "executable_registration_version",
    "launcher_path",
    "launcher_sha256",
    "launcher_size",
    "launcher_registration_id",
    "launcher_registration_version",
    "script_path",
    "script_sha256",
    "script_size",
    "script_registration_id",
    "script_registration_version",
    "invocation_shape",
    "working_directory_policy",
    "allowed_environment",
    "endpoint_identity",
    "authentication_mode",
    "authentication_profile",
    "capability_set",
    "executive_capability_set",
    "project_types",
    "effort_levels",
    "pricing_authority",
    "provider_policy",
    "independence_classification",
    "role_eligibility",
    "model_or_service_identity",
    "qualified_version",
    "qualification_timestamp",
    "qualification_method",
    "qualification_result",
    "registration_lifecycle",
    "qualification_evidence_id",
    "qualification_evidence_digest",
    "qualifying_component_digests",
    "registration_status",
    "authorized_by",
    "authorized_at",
    "revoked_at",
    "expires_at",
    "configuration_digest",
}
_CODEX_SUBSCRIPTION_REGISTRATION_FIELDS = _REGISTRATION_FIELDS | {
    "expected_version",
    "model_allowlist",
    "model_revalidation_expires_at",
    "authentication_policy",
    "windows_authentication_binding",
    "usage_policy",
    "authenticode_binding",
    "subscription_account_binding",
    "model_capability_binding",
    "executable_file_identity",
}


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    author: bool = True
    reviewer: bool = True
    repairer: bool = True
    structured_output: bool = True
    streaming: bool = True
    cancellation: bool = True
    usage_reporting: bool = False
    local_only: bool = False


@dataclass(frozen=True, slots=True)
class ProviderDiagnostic:
    provider_id: str
    display_name: str
    available: bool
    executable: str | None
    version: str | None
    verification_status: str
    capabilities: ProviderCapabilities
    detail: str = ""
    registration: dict[str, Any] | None = None
    discovery_state: str = "unavailable"
    role_eligibility: tuple[str, ...] = ()
    independence_classification: str = ""
    provider_policy: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CodexCommandAdapter(CliProvider):
    def __init__(self, executable: str, registration: dict[str, Any]) -> None:
        resolved = str(Path(executable).resolve(strict=True))
        super().__init__(
            (resolved, "{prompt}"),
            provider_name="codex-command",
            **_cli_registration_arguments(registration),
        )
        self.executable = resolved
        self.executable_sha256 = str(registration["executable_sha256"])
        self.registration = dict(registration)
        self.instance_id = uuid.uuid4().hex
        self.validate()

    def build_command(self, request: AgentRequest) -> list[str]:
        schema_path = request.stdout_path.parent / "provider-output-schema.json"
        schema_path.write_text(json.dumps(_domain_schema(request.role)), encoding="utf-8")
        result_path = request.stdout_path.with_suffix(".result.json")
        prompt = request.prompt_path.read_text(encoding="utf-8")
        models = self.registration.get("model_allowlist")
        model_id = (
            str(models[0])
            if isinstance(models, list) and len(models) == 1
            else str(self.registration["model_or_service_identity"])
        )
        return build_codex_exec_command(
            Path(self.executable),
            model_id=model_id,
            reasoning_level=request.reasoning_level,
            schema_path=schema_path,
            output_path=result_path,
            prompt=prompt,
        )

    def run(self, request: AgentRequest) -> ProcessResult:
        events_path = request.stdout_path.with_suffix(".events.jsonl")
        result_path = events_path.with_suffix(".result.json")
        raw_request = AgentRequest(
            request.role,
            request.prompt_path,
            request.workspace,
            request.timeout_seconds,
            events_path,
            request.stderr_path,
            request.reasoning_level,
            request.on_process_started,
            request.on_process_owned,
            request.authority_attempt_id,
        )
        result = super().run(raw_request)
        if result.exit_code:
            return ProcessResult(
                result.exit_code,
                request.stdout_path,
                request.stderr_path,
                result.process_id,
                result.timed_out,
            )
        try:
            domain = json.loads(result_path.read_text(encoding="utf-8"))
            if not isinstance(domain, dict):
                raise ValueError("Codex result is not a structured object")
            request.stdout_path.write_text(json.dumps(domain), encoding="utf-8")
            return ProcessResult(
                0,
                request.stdout_path,
                request.stderr_path,
                result.process_id,
                output=domain,
            )
        except (json.JSONDecodeError, OSError, ValueError) as error:
            request.stdout_path.write_text("", encoding="utf-8")
            request.stderr_path.write_text(
                f"invalid Codex structured result: {error}", encoding="utf-8"
            )
            return ProcessResult(
                65, request.stdout_path, request.stderr_path, result.process_id
            )


class ClaudeCommandAdapter(CliProvider):
    """Claude CLI adapter. Implemented against documented flags; locally unverified."""

    def __init__(self, executable: str, registration: dict[str, Any]) -> None:
        resolved = str(Path(executable).resolve(strict=True))
        super().__init__(
            (resolved, "{prompt}"),
            provider_name="claude-command",
            **_cli_registration_arguments(registration),
        )
        self.executable = resolved
        self.executable_sha256 = str(registration["executable_sha256"])
        self.registration = dict(registration)
        self.instance_id = uuid.uuid4().hex
        self.validate()

    def build_command(self, request: AgentRequest) -> list[str]:
        prompt = request.prompt_path.read_text(encoding="utf-8")
        return [
            self.executable,
            "--output-format",
            "json",
            "--json-schema",
            json.dumps(_domain_schema(request.role), separators=(",", ":")),
            "-p",
            prompt,
        ]

    def run(self, request: AgentRequest) -> ProcessResult:
        raw_path = request.stdout_path.with_suffix(".envelope.json")
        raw_request = AgentRequest(
            request.role,
            request.prompt_path,
            request.workspace,
            request.timeout_seconds,
            raw_path,
            request.stderr_path,
            request.reasoning_level,
            request.on_process_started,
            request.on_process_owned,
            request.authority_attempt_id,
        )
        result = super().run(raw_request)
        if result.exit_code:
            return ProcessResult(
                result.exit_code,
                request.stdout_path,
                request.stderr_path,
                result.process_id,
                result.timed_out,
            )
        try:
            envelope = json.loads(raw_path.read_text(encoding="utf-8"))
            domain = envelope.get("structured_output", envelope.get("result"))
            if isinstance(domain, str):
                domain = json.loads(domain)
            if not isinstance(domain, dict):
                raise ValueError("Claude envelope contains no domain result")
            request.stdout_path.write_text(json.dumps(domain), encoding="utf-8")
            return ProcessResult(
                0, request.stdout_path, request.stderr_path, result.process_id, output=domain
            )
        except (json.JSONDecodeError, OSError, ValueError) as error:
            request.stdout_path.write_text("", encoding="utf-8")
            request.stderr_path.write_text(
                f"invalid Claude result envelope: {error}", encoding="utf-8"
            )
            return ProcessResult(65, request.stdout_path, request.stderr_path, result.process_id)


class GeminiCommandAdapter(CliProvider):
    """Fail-closed Gemini CLI adapter for non-interactive structured output."""

    def __init__(self, executable: str, registration: dict[str, Any]) -> None:
        resolved = str(Path(executable).resolve(strict=True))
        super().__init__(
            (resolved, "{prompt}"),
            provider_name="gemini-command",
            **_cli_registration_arguments(registration),
        )
        self.executable = resolved
        self.executable_sha256 = str(registration["executable_sha256"])
        self.registration = dict(registration)
        self.instance_id = uuid.uuid4().hex
        self.validate()

    def build_command(self, request: AgentRequest) -> list[str]:
        schema = json.dumps(_domain_schema(request.role), separators=(",", ":"))
        prompt = request.prompt_path.read_text(encoding="utf-8")
        governed_prompt = (
            "Return only one JSON object that validates against this JSON Schema: "
            f"{schema}\n\nTask:\n{prompt}"
        )
        return [
            self.executable,
            "--sandbox",
            "--approval-mode=plan",
            "--output-format",
            "json",
            "--prompt",
            governed_prompt,
        ]

    def run(self, request: AgentRequest) -> ProcessResult:
        envelope_path = request.stdout_path.with_suffix(".envelope.json")
        raw_request = AgentRequest(
            request.role,
            request.prompt_path,
            request.workspace,
            request.timeout_seconds,
            envelope_path,
            request.stderr_path,
            request.reasoning_level,
            request.on_process_started,
            request.on_process_owned,
            request.authority_attempt_id,
        )
        result = super().run(raw_request)
        if result.exit_code:
            return ProcessResult(
                result.exit_code,
                request.stdout_path,
                request.stderr_path,
                result.process_id,
                result.timed_out,
            )
        try:
            envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
            if not isinstance(envelope, dict) or not isinstance(
                envelope.get("response"), str
            ):
                raise ValueError("Gemini envelope contains no response")
            domain = json.loads(str(envelope["response"]))
            if not isinstance(domain, dict):
                raise ValueError("Gemini response is not a structured object")
            request.stdout_path.write_text(json.dumps(domain), encoding="utf-8")
            return ProcessResult(
                0, request.stdout_path, request.stderr_path, result.process_id, output=domain
            )
        except (json.JSONDecodeError, OSError, ValueError) as error:
            request.stdout_path.write_text("", encoding="utf-8")
            request.stderr_path.write_text(
                f"invalid Gemini result envelope: {error}", encoding="utf-8"
            )
            return ProcessResult(65, request.stdout_path, request.stderr_path, result.process_id)


class ProviderDiscovery:
    def __init__(
        self,
        configured_paths: dict[str, str] | None = None,
        registrations: dict[str, dict[str, Any]] | None = None,
        qualification_evidence: dict[str, dict[str, Any]] | None = None,
        authority_verifier: Callable[[str, object], bool] | None = None,
    ) -> None:
        self.configured_paths = configured_paths or {}
        self.registrations = registrations or {}
        self.qualification_evidence = qualification_evidence or {}
        self.authority_verifier = authority_verifier

    def discover(self) -> list[ProviderDiagnostic]:
        return [
            self._command(
                "codex",
                "Codex command",
                ("codex", "codex.exe"),
                "implemented; local execution requires authenticated CLI",
            ),
            self._command(
                "claude",
                "Claude Code command",
                ("claude", "claude.exe"),
                "implemented; not verified on this machine",
            ),
            self._command(
                "gemini",
                "Gemini CLI command",
                ("gemini", "gemini.cmd", "gemini.exe"),
                "structured execution implemented; Authority qualification required",
            ),
            self._qwen(),
            ProviderDiagnostic(
                "mock",
                "Deterministic mock",
                True,
                None,
                "built-in",
                "verified",
                ProviderCapabilities(local_only=True, streaming=False),
                "Always available for diagnostics and demonstrations.",
            ),
        ]

    def _command(
        self,
        identifier: str,
        display_name: str,
        candidates: tuple[str, ...],
        verification: str,
    ) -> ProviderDiagnostic:
        configured = self.configured_paths.get(identifier)
        executable = configured if configured and Path(configured).is_file() else None
        if executable is None:
            executable = next(
                (path for candidate in candidates if (path := shutil.which(candidate))),
                None,
            )

        registration = self.registrations.get(identifier)

        valid, detail = _validate_discovery_registration(
            identifier,
            executable,
            registration,
            self.qualification_evidence,
            self.authority_verifier,
        )

        if executable is None:
            detail = (
                f"{display_name} executable was not found. "
                "Install the provider CLI or configure its executable path."
            )
        elif not valid:
            detail = (
                f"{display_name} executable was found, but its provider "
                f"registration or authorization is not valid. {detail}"
            )

        capabilities = (
            ProviderCapabilities(**dict(registration["capability_set"]))
            if valid and registration
            else ProviderCapabilities(
                author=False,
                reviewer=False,
                repairer=False,
                structured_output=False,
                streaming=False,
                cancellation=False,
                usage_reporting=False,
                local_only=False,
            )
        )
        lifecycle = "BLOCKED"
        if isinstance(registration, dict):
            if (
                registration.get("registration_status") == "revoked"
                or registration.get("revoked_at") is not None
            ):
                lifecycle = "REVOKED"
            elif _registration_expired(registration):
                lifecycle = "EXPIRED"
            elif valid:
                lifecycle = str(registration.get("registration_lifecycle"))
        return ProviderDiagnostic(
            identifier,
            display_name,
            valid,
            executable,
            (
                str(registration.get("qualified_version"))
                if valid and registration
                and registration.get("qualified_version") is not None
                else None
            ),
            verification if valid else "blocked",
            capabilities,
            detail,
            dict(registration) if valid and registration else None,
            lifecycle.casefold().replace("_", "-")
            if registration is not None
            else "blocked" if executable else "unavailable",
            tuple(registration.get("role_eligibility", ()))
            if valid and registration
            else (),
            str(registration.get("independence_classification", ""))
            if valid and registration
            else "",
            str(registration.get("provider_policy", ""))
            if valid and registration
            else "",
        )

    def _qwen(self) -> ProviderDiagnostic:
        executable = (
            self.configured_paths.get("qwen")
            or self.configured_paths.get("ollama")
            or shutil.which("ollama")
        )
        registration = self.registrations.get("qwen")
        valid, detail = _validate_discovery_registration(
            "qwen",
            executable,
            registration,
            self.qualification_evidence,
            self.authority_verifier,
        )
        return ProviderDiagnostic(
            "qwen",
            "Qwen local model",
            valid,
            executable,
            str(registration.get("qualified_version")) if valid and registration else None,
            "qualified" if valid else "blocked",
            ProviderCapabilities(**dict(registration["capability_set"]))
            if valid and registration
            else ProviderCapabilities(
                author=False,
                reviewer=False,
                repairer=False,
                structured_output=False,
                streaming=False,
                cancellation=False,
                usage_reporting=False,
                local_only=True,
            ),
            detail if executable else "Qwen requires a local Ollama installation.",
            dict(registration) if valid and registration else None,
            "qualified" if valid else "blocked" if executable else "unavailable",
            tuple(registration.get("role_eligibility", ()))
            if valid and registration
            else (),
            str(registration.get("independence_classification", ""))
            if valid and registration
            else "",
            str(registration.get("provider_policy", ""))
            if valid and registration
            else "",
        )


@dataclass(frozen=True, slots=True)
class RoutingRequest:
    role: str
    risk: str
    component: str
    previous_provider_ids: frozenset[str] = field(default_factory=frozenset)
    qwen_authored: bool = False


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    provider_id: str
    reasons: list[str]


def route_provider(
    request: RoutingRequest, providers: list[ProviderDiagnostic]
) -> RoutingDecision:
    available = [provider for provider in providers if provider.available]
    if not available:
        raise RuntimeError("no provider is available")
    candidates = [
        provider
        for provider in available
        if provider.provider_id not in request.previous_provider_ids
        and (
            provider.registration is None
            or provider.discovery_state == "qualified"
        )
        and _supports_role(provider, request.role)
        and (
            request.role not in {"reviewer", "post_repair_reviewer"}
            or provider.registration is None
            or provider.independence_classification == "independent-capable"
        )
        and not (
            provider.provider_id == "mock"
            and request.role in {"reviewer", "post_repair_reviewer"}
        )
    ]
    if request.role in {"reviewer", "post_repair_reviewer"} and not candidates:
        raise RuntimeError("no independent reviewer is available")
    if not candidates:
        raise RuntimeError(f"no provider can perform role: {request.role}")
    strength = {"mock": 0, "qwen": 1, "gemini": 2, "claude": 2, "codex": 2}
    candidates.sort(key=lambda item: (-strength.get(item.provider_id, 0), item.provider_id))
    chosen = candidates[0]
    reasons = [
        f"provider is available and supports {request.role}",
        "provider identity has not participated in an incompatible prior role",
    ]
    if request.qwen_authored:
        if chosen.provider_id == "qwen":
            raise RuntimeError("Qwen-authored work requires a non-Qwen independent reviewer")
        reasons.append("non-Qwen reviewer required for Qwen-authored work")
    if request.risk.lower() in {"high", "critical"}:
        reasons.append("strongest available independent provider selected for high risk")
    return RoutingDecision(chosen.provider_id, reasons)


def _supports_role(provider: ProviderDiagnostic, role: str) -> bool:
    if provider.registration is not None and role not in provider.role_eligibility:
        return False
    capabilities = provider.capabilities
    if role == "builder":
        return capabilities.author
    if role in {"reviewer", "post_repair_reviewer"}:
        return capabilities.reviewer
    if role == "repairer":
        return capabilities.repairer
    return False


def create_provider_registration(
    provider_id: str,
    executable: Path,
    *,
    authorized_by: str,
    invocation_shape: list[str] | None = None,
    capabilities: ProviderCapabilities | None = None,
    role_eligibility: list[str] | None = None,
    independence_classification: str = "independent-capable",
    executive_capabilities: list[str],
    project_types: list[str],
    effort_levels: list[str],
    pricing_authority: dict[str, Any],
    expected_version: str | None = None,
    model_allowlist: list[str] | None = None,
    model_revalidation_expires_at: str | None = None,
    authentication_policy: dict[str, Any] | None = None,
    windows_authentication_binding: dict[str, Any] | None = None,
    usage_policy: dict[str, Any] | None = None,
    authenticode_binding: dict[str, Any] | None = None,
    subscription_account_binding: dict[str, Any] | None = None,
    model_capability_binding: dict[str, Any] | None = None,
    authority_executable_measurement: dict[str, Any] | None = None,
    trusted_registration_id: str | None = None,
) -> dict[str, Any]:
    normalized_executive_capabilities = _validated_string_authority_list(
        executive_capabilities, "executive capability"
    )
    if any(item not in _EXECUTIVE_CAPABILITIES for item in normalized_executive_capabilities):
        raise ValueError("provider Executive capability declaration is unsupported")
    normalized_project_types = _validated_string_authority_list(
        project_types, "project type"
    )
    if any(item not in _PROJECT_TYPES for item in normalized_project_types):
        raise ValueError("provider project-type declaration is unsupported")
    subscription_contract = any(
        item is not None
        for item in (
            model_allowlist,
            expected_version,
            model_revalidation_expires_at,
            authentication_policy,
            windows_authentication_binding,
            usage_policy,
            authenticode_binding,
            subscription_account_binding,
            model_capability_binding,
            authority_executable_measurement,
        )
    )
    if subscription_contract:
        if provider_id not in {"codex", "claude"} or any(
            item is None
            for item in (
                model_allowlist,
                expected_version,
                model_revalidation_expires_at,
                authentication_policy,
                windows_authentication_binding,
                usage_policy,
                authenticode_binding,
                subscription_account_binding,
                model_capability_binding,
            )
        ):
            raise ValueError("subscription registration is incomplete")
        if effort_levels != ["medium", "high"]:
            raise ValueError("subscription effort levels must be medium and high")
        # Hosted subscription contracts preserve this semantic order.
        # Do not reuse the alphabetic normalization used by legacy providers.
        normalized_effort_levels = ["medium", "high"]
        normalized_pricing_authority = (
            validate_subscription_pricing_authority(pricing_authority)
            if provider_id == "codex"
            else validate_claude_subscription_pricing_authority(pricing_authority)
        )
        normalized_model_allowlist = (
            validate_codex_model_allowlist(model_allowlist)
            if provider_id == "codex"
            else validate_claude_model_allowlist(model_allowlist)
        )
        if not isinstance(expected_version, str) or (
            provider_id == "codex"
            and not _version_output_valid(provider_id, expected_version)
        ):
            raise ValueError("subscription expected executable version is invalid")
        if provider_id == "claude":
            validate_claude_version_output(expected_version)
        normalized_authentication_policy = (
            validate_codex_authentication_policy(authentication_policy)
            if provider_id == "codex"
            else validate_claude_authentication_policy(authentication_policy)
        )
        normalized_authentication_binding = validate_windows_authentication_binding(
            windows_authentication_binding
        )
        normalized_usage_policy = (
            validate_codex_usage_policy(usage_policy)
            if provider_id == "codex"
            else validate_claude_usage_policy(usage_policy)
        )
        normalized_authenticode_binding = (
            validate_codex_authenticode_binding(authenticode_binding)
            if provider_id == "codex"
            else validate_claude_authenticode_binding(authenticode_binding)
        )
        normalized_subscription_account_binding = (
            validate_subscription_account_binding(subscription_account_binding)
            if provider_id == "codex"
            else validate_claude_subscription_account_binding(
                subscription_account_binding
            )
        )
        normalized_model_capability_binding = (
            validate_codex_model_capability_binding(model_capability_binding)
            if provider_id == "codex"
            else validate_claude_model_capability_binding(
                model_capability_binding
            )
        )
        normalized_executable_measurement = (
            _validated_executable_measurement(
                authority_executable_measurement,
                executable=executable,
                authenticode_binding=normalized_authenticode_binding,
            )
            if authority_executable_measurement is not None
            else None
        )
        normalized_executable_file_identity = (
            validate_executable_file_identity(
                normalized_executable_measurement["file_identity"]
            )
            if normalized_executable_measurement is not None
            else None
        )
        if [
            item["model_id"]
            for item in normalized_model_capability_binding["models"]
        ] != normalized_model_allowlist:
            raise ValueError("subscription model capabilities do not match the allowlist")
        try:
            model_expiry = datetime.fromisoformat(
                str(model_revalidation_expires_at)
            )
        except ValueError as error:
            raise ValueError("subscription model revalidation expiry is invalid") from error
        if model_expiry.tzinfo is None or model_expiry <= datetime.now(UTC):
            raise ValueError("subscription model revalidation authority is expired")
    else:
        normalized_effort_levels = _validated_effort_levels(effort_levels)
        normalized_pricing_authority = _validated_pricing_authority(pricing_authority)
        normalized_model_allowlist = None
        normalized_authentication_policy = None
        normalized_authentication_binding = None
        normalized_usage_policy = None
        normalized_authenticode_binding = None
        normalized_subscription_account_binding = None
        normalized_model_capability_binding = None
        normalized_executable_measurement = None
        normalized_executable_file_identity = None
    configured = (
        Path(str(normalized_executable_measurement["canonical_path"]))
        if normalized_executable_measurement is not None
        else executable.resolve(strict=True)
    )
    registration_nonce = uuid.uuid4().hex
    generated_registration_id = (
        f"keeper-provider:{provider_id}:v1:{registration_nonce}"
    )
    if trusted_registration_id is not None:
        expected_prefix = f"keeper-provider:{provider_id}:v1:"
        if (
            not trusted_registration_id.startswith(expected_prefix)
            or len(trusted_registration_id) != len(expected_prefix) + 32
            or any(
                character not in "0123456789abcdef"
                for character in trusted_registration_id[len(expected_prefix) :]
            )
        ):
            raise ValueError("trusted provider registration ID is invalid")
        generated_registration_id = trusted_registration_id
    capability_values = asdict(capabilities or ProviderCapabilities())
    roles = role_eligibility if role_eligibility is not None else [
        "builder",
        "post_repair_reviewer",
        "repairer",
        "reviewer",
    ]
    launcher = configured
    script: Path | None = None
    if configured.suffix.casefold() in {".cmd", ".bat"}:
        if subscription_contract:
            raise ValueError("Codex subscription executable must be a direct binary")
        script = configured
        launcher = Path(os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")).resolve(
            strict=True
        )
    if normalized_executable_measurement is not None:
        executable_digest = str(normalized_executable_measurement["sha256"])
        executable_size = int(normalized_executable_measurement["size"])
        launcher_digest = executable_digest
        launcher_size = executable_size
    else:
        executable_content = configured.read_bytes()
        launcher_content = launcher.read_bytes()
        executable_digest = hashlib.sha256(executable_content).hexdigest()
        executable_size = len(executable_content)
        launcher_digest = hashlib.sha256(launcher_content).hexdigest()
        launcher_size = len(launcher_content)
        if subscription_contract:
            normalized_executable_file_identity = _file_identity(configured.stat())
    invocation_base = (
        [str(launcher), "/d", "/c", str(script)]
        if script is not None
        else [str(launcher)]
    )
    invocation = invocation_shape
    if invocation is None and provider_id == "gemini":
        invocation = [
            *invocation_base,
            "--sandbox",
            "--approval-mode=plan",
            "--model",
            "gemini-2.5-pro",
            "--output-format",
            "json",
            "--prompt",
            "{prompt}",
        ]
    elif invocation is None and provider_id == "qwen":
        invocation = [*invocation_base, "run", "qwen3-coder:30b", "{prompt}"]
    elif invocation is None:
        invocation = [*invocation_base, "{prompt}"]
    if subscription_contract and role_eligibility is None:
        if provider_id == "codex":
            roles = ["builder", "repairer"]
            independence_classification = "authoring-only"
            capability_values["reviewer"] = False
        else:
            roles = ["post_repair_reviewer", "reviewer"]
            independence_classification = "independent-capable"
            capability_values["author"] = False
            capability_values["repairer"] = False
        capability_values["usage_reporting"] = True
    registration: dict[str, Any] = {
        "registration_schema_version": (
            (
                CODEX_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION
                if provider_id == "codex"
                else CLAUDE_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION
            )
            if subscription_contract
            else REGISTRATION_SCHEMA_VERSION
        ),
        "trusted_registration_id": generated_registration_id,
        "registration_version": "1",
        "logical_provider_id": provider_id,
        "provider_name": f"{provider_id}-command",
        "provider_type": "local-command",
        "canonical_executable_path": str(configured),
        "executable_sha256": executable_digest,
        "executable_size": executable_size,
        "executable_registration_id": (
            f"keeper-executable:{provider_id}:v1:{registration_nonce}"
        ),
        "executable_registration_version": "1",
        "launcher_path": str(launcher),
        "launcher_sha256": launcher_digest,
        "launcher_size": launcher_size,
        "launcher_registration_id": (
            f"keeper-launcher:{provider_id}:v1:{registration_nonce}"
        ),
        "launcher_registration_version": "1",
        "script_path": str(script) if script is not None else None,
        "script_sha256": (
            hashlib.sha256(script.read_bytes()).hexdigest() if script is not None else None
        ),
        "script_size": script.stat().st_size if script is not None else None,
        "script_registration_id": (
            f"keeper-script:{provider_id}:v1:{registration_nonce}"
            if script is not None
            else None
        ),
        "script_registration_version": "1" if script is not None else None,
        "invocation_shape": invocation,
        "working_directory_policy": "task-worktree",
        "allowed_environment": "keeper-filtered",
        "endpoint_identity": "local-process",
        "authentication_mode": (
            (
                "chatgpt-subscription-session"
                if provider_id == "codex"
                else "claude-ai-subscription-session"
            )
            if subscription_contract
            else "external-cli-session"
        ),
        "authentication_profile": (
            "authority-bound-windows-user-profile"
            if subscription_contract
            else f"external-session:{provider_id}"
        ),
        "capability_set": capability_values,
        "executive_capability_set": normalized_executive_capabilities,
        "project_types": normalized_project_types,
        "effort_levels": normalized_effort_levels,
        "pricing_authority": normalized_pricing_authority,
        "provider_policy": "registered-command",
        "independence_classification": independence_classification,
        "role_eligibility": roles,
        "model_or_service_identity": (
            normalized_model_allowlist[0]
            if normalized_model_allowlist is not None
            and len(normalized_model_allowlist) == 1
            else "gemini-2.5-pro"
            if provider_id == "gemini"
            else "qwen3-coder:30b"
            if provider_id == "qwen"
            else provider_id
        ),
        "qualified_version": None,
        "qualification_timestamp": None,
        "qualification_method": "none",
        "qualification_result": "not-qualified",
        "registration_lifecycle": "REGISTERED_UNQUALIFIED",
        "qualification_evidence_id": None,
        "qualification_evidence_digest": None,
        "qualifying_component_digests": {
            "executable": executable_digest,
            "launcher": launcher_digest,
            "script": (
                hashlib.sha256(script.read_bytes()).hexdigest()
                if script is not None
                else None
            ),
        },
        "registration_status": "active",
        "authorized_by": authorized_by,
        "authorized_at": datetime.now(UTC).isoformat(),
        "revoked_at": None,
        "expires_at": None,
    }
    if subscription_contract:
        registration.update(
            {
                "model_allowlist": normalized_model_allowlist,
                "expected_version": expected_version,
                "model_revalidation_expires_at": str(
                    model_revalidation_expires_at
                ),
                "authentication_policy": normalized_authentication_policy,
                "windows_authentication_binding": normalized_authentication_binding,
                "usage_policy": normalized_usage_policy,
                "authenticode_binding": normalized_authenticode_binding,
                "subscription_account_binding": (
                    normalized_subscription_account_binding
                ),
                "model_capability_binding": normalized_model_capability_binding,
                "executable_file_identity": normalized_executable_file_identity,
            }
        )
    registration["configuration_digest"] = _registration_configuration_digest(
        registration
    )
    return registration


def _file_identity(value: os.stat_result) -> dict[str, int]:
    return validate_executable_file_identity(
        {
            "schema_version": 1,
            "device_id": int(value.st_dev),
            "file_id": int(value.st_ino),
            "size": int(value.st_size),
            "modified_ns": int(value.st_mtime_ns),
        }
    )


def _validated_executable_measurement(
    value: object,
    *,
    executable: Path,
    authenticode_binding: dict[str, Any],
) -> dict[str, Any]:
    fields = {
        "canonical_path",
        "sha256",
        "size",
        "file_identity",
        "authenticode_binding",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Authority executable measurement fields are invalid")
    result = dict(value)
    canonical_path = result.get("canonical_path")
    digest = result.get("sha256")
    size = result.get("size")
    if (
        not isinstance(canonical_path, str)
        or not canonical_path
        or not Path(canonical_path).is_absolute()
        or os.path.normcase(os.path.abspath(str(executable)))
        != os.path.normcase(canonical_path)
        or not isinstance(digest, str)
        or len(digest) != _SHA256_LENGTH
        or any(character not in "0123456789abcdef" for character in digest)
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size <= 0
        or validate_executable_file_identity(result.get("file_identity"))[
            "size"
        ]
        != size
        or result.get("authenticode_binding") != authenticode_binding
    ):
        raise ValueError("Authority executable measurement is invalid")
    return result


def _validate_discovery_registration(
    provider_id: str,
    executable: str | None,
    registration: dict[str, Any] | None,
    qualification_evidence: dict[str, dict[str, Any]] | None = None,
    authority_verifier: Callable[[str, object], bool] | None = None,
) -> tuple[bool, str]:
    if executable is None:
        return False, "Executable was not found; configure its full path in Settings."
    if not isinstance(registration, dict):
        return False, "Configured provider has no immutable registration."
    if set(registration) != _registration_fields(registration):
        return False, "Provider registration is malformed or incomplete."
    if not _registration_types_valid(registration):
        return False, "Provider registration field types or values are invalid."
    if (
        registration.get("logical_provider_id") != provider_id
        or registration.get("registration_status") != "active"
        or registration.get("revoked_at") is not None
        or _registration_expired(registration)
    ):
        return False, "Provider registration is stale, revoked, or mismatched."
    if registration.get("configuration_digest") != _registration_configuration_digest(
        registration
    ):
        return False, "Provider registration configuration digest is stale."
    if not _qualification_is_consistent(
        registration, qualification_evidence or {}, authority_verifier
    ):
        return False, "Provider qualification authority is missing or inconsistent."
    try:
        configured = Path(executable).resolve(strict=True)
        registered_executable = Path(
            str(registration["canonical_executable_path"])
        ).resolve(strict=True)
        if configured != registered_executable or str(configured) != str(
            registration["canonical_executable_path"]
        ):
            return False, "Configured provider path differs from registration."
        executable_content = configured.read_bytes()
        if (
            hashlib.sha256(executable_content).hexdigest()
            != registration["executable_sha256"]
            or len(executable_content) != registration["executable_size"]
        ):
            return False, "Registered provider executable identity changed."
        launcher = Path(str(registration["launcher_path"])).resolve(strict=True)
        if str(launcher) != str(registration["launcher_path"]):
            return False, "Registered provider launcher path is not canonical."
        launcher_content = launcher.read_bytes()
        if (
            hashlib.sha256(launcher_content).hexdigest()
            != registration["launcher_sha256"]
            or len(launcher_content) != registration["launcher_size"]
        ):
            return False, "Registered provider launcher identity changed."
        script_path = registration.get("script_path")
        if script_path is not None:
            script = Path(str(script_path)).resolve(strict=True)
            script_content = script.read_bytes()
            if (
                script != configured
                or hashlib.sha256(script_content).hexdigest()
                != registration.get("script_sha256")
                or len(script_content) != registration.get("script_size")
            ):
                return False, "Registered provider script identity changed."
    except (OSError, TypeError, ValueError):
        return False, "Provider registration could not be validated."
    return True, "Immutable registration validated; discovery did not execute provider code."


def validate_provider_registration_contract(
    registration: object,
) -> tuple[bool, str]:
    """Validate the Authority-owned record before qualification or execution."""
    if not isinstance(registration, dict) or set(registration) != _registration_fields(
        registration
    ):
        return False, "Provider registration is malformed or incomplete."
    if not _registration_types_valid(registration):
        return False, "Provider registration field types or values are invalid."
    if registration.get("configuration_digest") != _registration_configuration_digest(
        registration
    ):
        return False, "Provider registration configuration digest is stale."
    return True, "Provider registration contract is valid."


def validate_provider_registration(
    provider_id: str,
    executable: str,
    registration: dict[str, Any],
    qualification_evidence: dict[str, dict[str, Any]] | None = None,
    authority_verifier: Callable[[str, object], bool] | None = None,
) -> tuple[bool, str]:
    """Validate the one canonical provider-registration schema without execution."""
    return _validate_discovery_registration(
        provider_id,
        executable,
        registration,
        qualification_evidence,
        authority_verifier,
    )


def canonical_provider_registration_digest(
    registration: dict[str, Any],
) -> str:
    """Return the deterministic digest over every authoritative schema field."""
    return _registration_configuration_digest(registration)


def qualification_evidence_digest(evidence: dict[str, Any]) -> str:
    value = {
        key: item
        for key, item in evidence.items()
        if key
        not in {
            "evidence_digest",
            "authority_schema_version",
            "authority_key_id",
            "authenticated_writer_proof",
            "service_key_version",
        }
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _command_flag_value(command: object, flag: str) -> str | None:
    if not isinstance(command, list) or not all(
        isinstance(item, str) for item in command
    ):
        return None
    try:
        index = command.index(flag)
    except ValueError:
        return None
    if index + 1 >= len(command):
        return None
    return str(command[index + 1])


def apply_protected_qualification(
    registration: dict[str, Any],
    evidence: dict[str, Any],
    *,
    authority_verifier: Callable[[str, object], bool],
    expected_challenge: str,
    expected_authorization_reference: str,
) -> dict[str, Any]:
    updated = dict(registration)
    if updated.get("registration_lifecycle") != "REGISTERED_UNQUALIFIED":
        raise PermissionError("registration is not eligible for qualification")
    digest = qualification_evidence_digest(evidence)
    if not authority_verifier("provider-qualification", evidence):
        raise PermissionError("qualification writer authority is invalid")
    try:
        started_at = datetime.fromisoformat(str(evidence.get("started_at")))
        finished_at = datetime.fromisoformat(str(evidence.get("finished_at")))
    except ValueError as error:
        raise PermissionError("qualification chronology is invalid") from error
    command = evidence.get("qualification_command")
    schema_version = updated.get("registration_schema_version")
    subscription = schema_version in {
        CODEX_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION,
        CLAUDE_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION,
    }
    command_valid = (
        isinstance(command, list)
        and all(isinstance(item, str) for item in command)
        and evidence.get("command_digest")
        == hashlib.sha256(json.dumps(command).encode("utf-8")).hexdigest()
    )
    if schema_version == CODEX_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION:
        command_valid = bool(
            command_valid
            and command
            and command[0] == updated.get("canonical_executable_path")
            and command[1:5]
            == [
                "exec",
                "--ephemeral",
                "--ignore-user-config",
                "--skip-git-repo-check",
            ]
            and _command_flag_value(command, "--sandbox") == "workspace-write"
            and _command_flag_value(command, "--model")
            == updated.get("model_or_service_identity")
            and 'model_reasoning_effort="medium"' in command
            and "--output-schema" in command
            and "--output-last-message" in command
            and evidence.get("schema_version") == 3
            and evidence.get("qualified_model_id")
            == updated.get("model_or_service_identity")
            and evidence.get("normalized_version")
            == updated.get("expected_version")
            and evidence.get("qualified_reasoning_level") == "medium"
            and evidence.get("authentication_probe", {}).get(
                "authentication_method"
            )
            == "chatgpt-subscription"
            and evidence.get("authentication_probe", {}).get("plan_type")
            == updated.get("subscription_account_binding", {}).get(
                "plan_type"
            )
            and evidence.get("authentication_probe", {}).get(
                "account_identity_digest"
            )
            == updated.get("subscription_account_binding", {}).get(
                "account_identity_digest"
            )
            and evidence.get("authentication_probe", {}).get("models")
            == updated.get("model_allowlist")
            and evidence.get("authentication_probe", {}).get(
                "model_capabilities"
            )
            == updated.get("model_capability_binding", {}).get("models")
            and evidence.get("structured_output")
            == {
                "status": "ok",
                "provider": "codex",
                "effort": "medium",
                "nonce": "keeper-codex-qualification-v1",
            }
            and evidence.get("registration_configuration_digest")
            == updated.get("configuration_digest")
            and evidence.get("pricing_authority_digest")
            == structured_digest(updated.get("pricing_authority"))
            and evidence.get("usage_policy_digest")
            == structured_digest(updated.get("usage_policy"))
            and evidence.get("authentication_binding_digest")
            == structured_digest(updated.get("windows_authentication_binding"))
            and isinstance(evidence.get("prompt_digest"), str)
            and isinstance(evidence.get("schema_digest"), str)
        )
    elif schema_version == CLAUDE_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION:
        command_valid = bool(
            command_valid
            and command
            == build_claude_qualification_command(
                Path(str(updated.get("canonical_executable_path")))
            )
            and evidence.get("schema_version") == 4
            and evidence.get("qualified_model_id")
            == updated.get("model_or_service_identity")
            and evidence.get("normalized_version")
            == updated.get("expected_version")
            and evidence.get("qualified_reasoning_level") == "medium"
            and evidence.get("authentication_probe", {}).get(
                "authentication_method"
            )
            == "claude-ai-subscription"
            and evidence.get("authentication_probe", {}).get("plan_type")
            == updated.get("subscription_account_binding", {}).get("plan_type")
            and evidence.get("authentication_probe", {}).get(
                "account_identity_digest"
            )
            == updated.get("subscription_account_binding", {}).get(
                "account_identity_digest"
            )
            and evidence.get("authentication_probe", {}).get("models")
            == updated.get("model_allowlist")
            and evidence.get("authentication_probe", {}).get(
                "model_capabilities"
            )
            == updated.get("model_capability_binding", {}).get("models")
            and evidence.get("structured_output")
            == {
                "status": "ok",
                "provider": "claude",
                "effort": "medium",
                "nonce": "keeper-claude-qualification-v1",
            }
            and evidence.get("registration_configuration_digest")
            == updated.get("configuration_digest")
            and evidence.get("pricing_authority_digest")
            == structured_digest(updated.get("pricing_authority"))
            and evidence.get("usage_policy_digest")
            == structured_digest(updated.get("usage_policy"))
            and evidence.get("authentication_binding_digest")
            == structured_digest(updated.get("windows_authentication_binding"))
            and isinstance(evidence.get("prompt_digest"), str)
            and isinstance(evidence.get("schema_digest"), str)
        )
    else:
        command_valid = bool(
            command_valid
            and command
            == [updated.get("canonical_executable_path"), "--version"]
        )
    if (
        started_at.tzinfo is None
        or finished_at.tzinfo is None
        or finished_at < started_at
        or not isinstance(evidence.get("id"), str)
        or not evidence["id"]
        or evidence.get("qualification_method") != "protected-registered-launch"
        or evidence.get("event_challenge") != expected_challenge
        or evidence.get("authorization_reference")
        != expected_authorization_reference
        or not command_valid
        or not isinstance(evidence.get("provider_instance_id"), str)
        or not evidence["provider_instance_id"]
        or not isinstance(evidence.get("provider_run_id"), str)
        or not evidence["provider_run_id"]
        or not isinstance(evidence.get("authorized_by"), str)
        or not evidence["authorized_by"]
        or not isinstance(evidence.get("ownership"), dict)
        or not evidence["ownership"].get("launch_nonce")
        or evidence.get("evidence_digest") != digest
        or evidence.get("registration_id") != updated.get("trusted_registration_id")
        or evidence.get("registration_version") != updated.get("registration_version")
        or evidence.get("provider_id") != updated.get("logical_provider_id")
        or evidence.get("executable_sha256") != updated.get("executable_sha256")
        or evidence.get("launcher_sha256") != updated.get("launcher_sha256")
        or evidence.get("script_sha256") != updated.get("script_sha256")
        or evidence.get("exit_status") != 0
        or evidence.get("qualification_result") != "qualified"
        or not isinstance(evidence.get("normalized_version"), str)
        or not evidence["normalized_version"]
        or not _version_output_valid(
            str(updated.get("logical_provider_id")),
            str(evidence.get("normalized_version")),
        )
    ):
        raise PermissionError("protected qualification evidence is inconsistent")
    updated.update(
        {
            "qualified_version": evidence["normalized_version"],
            "qualification_timestamp": evidence["finished_at"],
            "qualification_method": "protected-registered-launch",
            "qualification_result": "qualified",
            "registration_lifecycle": "QUALIFIED",
            "qualification_evidence_id": evidence["id"],
            "qualification_evidence_digest": digest,
        }
    )
    updated["configuration_digest"] = _registration_configuration_digest(updated)
    return updated


def _qualification_is_consistent(
    registration: dict[str, Any],
    evidence_by_id: dict[str, dict[str, Any]],
    authority_verifier: Callable[[str, object], bool] | None,
) -> bool:
    if registration.get("registration_lifecycle") == "QUALIFICATION_FAILED":
        evidence_id = registration.get("qualification_evidence_id")
        evidence = evidence_by_id.get(str(evidence_id))
        return bool(
            isinstance(evidence, dict)
            and authority_verifier is not None
            and authority_verifier("provider-qualification", evidence)
            and _qualification_start_is_valid(
                registration, evidence, evidence_by_id, authority_verifier
            )
            and evidence.get("evidence_digest")
            == qualification_evidence_digest(evidence)
            == registration.get("qualification_evidence_digest")
            and evidence.get("registration_id")
            == registration.get("trusted_registration_id")
            and evidence.get("provider_id")
            == registration.get("logical_provider_id")
            and evidence.get("qualification_result") == "failed"
            and (
                evidence.get("exit_status") != 0
                or not _version_output_valid(
                    str(registration.get("logical_provider_id")),
                    str(evidence.get("normalized_version", "")),
                )
            )
        )
    if registration.get("registration_lifecycle") != "QUALIFIED":
        return registration.get("qualification_result") in {
            "not-qualified",
            "pending",
        }
    evidence_id = registration.get("qualification_evidence_id")
    if not isinstance(evidence_id, str):
        return False
    evidence = evidence_by_id.get(evidence_id)
    if (
        not isinstance(evidence, dict)
        or authority_verifier is None
        or not authority_verifier("provider-qualification", evidence)
        or not _qualification_start_is_valid(
            registration, evidence, evidence_by_id, authority_verifier
        )
    ):
        return False
    try:
        unqualified = {
            **registration,
            "qualified_version": None,
            "qualification_timestamp": None,
            "qualification_method": "none",
            "qualification_result": "not-qualified",
            "registration_lifecycle": "REGISTERED_UNQUALIFIED",
            "qualification_evidence_id": None,
            "qualification_evidence_digest": None,
            "configuration_digest": "",
        }
        unqualified["configuration_digest"] = _registration_configuration_digest(
            unqualified
        )
        expected = apply_protected_qualification(
            unqualified,
            evidence,
            authority_verifier=authority_verifier,
            expected_challenge=str(evidence["event_challenge"]),
            expected_authorization_reference=str(
                evidence["authorization_reference"]
            ),
        )
    except (KeyError, PermissionError, TypeError):
        return False
    return all(
        expected.get(key) == registration.get(key)
        for key in (
            "qualified_version",
            "qualification_timestamp",
            "qualification_method",
            "qualification_result",
            "registration_lifecycle",
            "qualification_evidence_id",
            "qualification_evidence_digest",
        )
    )


def _qualification_start_is_valid(
    registration: dict[str, Any],
    evidence: dict[str, Any],
    evidence_by_id: dict[str, dict[str, Any]],
    authority_verifier: Callable[[str, object], bool],
) -> bool:
    reference = evidence.get("authorization_reference")
    start = evidence_by_id.get(str(reference))
    return bool(
        isinstance(start, dict)
        and authority_verifier("provider-qualification-start", start)
        and start.get("id") == reference
        and start.get("registration_id")
        == registration.get("trusted_registration_id")
        and start.get("provider_id") == registration.get("logical_provider_id")
        and start.get("event_challenge") == evidence.get("event_challenge")
    )


def _version_output_valid(provider_id: str, value: str) -> bool:
    if provider_id == "qwen" and re.fullmatch(
        r"(?i)ollama\s+version\s+is\s+v?\d+\.\d+(?:\.\d+)?(?:[-+.\w ]*)",
        value.strip(),
    ):
        return True
    if provider_id == "claude":
        try:
            validate_claude_version_output(value)
        except ValueError:
            pass
        else:
            return True
    allowed_names = {
        "codex": r"(?:codex|controlled-provider|protected-version)",
        "claude": r"(?:claude|controlled-provider|protected-version)",
        "gemini": r"(?:gemini|controlled-provider|protected-version)",
        "qwen": r"(?:ollama|qwen|controlled-provider|protected-version)",
    }
    name = allowed_names.get(provider_id)
    return bool(
        name
        and re.fullmatch(
            rf"(?i){name}(?:[\s_-]+(?:cli[\s_-]+)?)?v?\d+\.\d+(?:\.\d+)?(?:[-+.\w ]*)",
            value.strip(),
        )
    )


def qualified_version_is_valid(provider_id: str, value: str) -> bool:
    return _version_output_valid(provider_id, value)


def _registration_fields(registration: dict[str, Any]) -> set[str]:
    if (
        registration.get("registration_schema_version")
        in {
            CODEX_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION,
            CLAUDE_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION,
        }
    ):
        return _CODEX_SUBSCRIPTION_REGISTRATION_FIELDS | (
            {"registration_lineage"}
            if "registration_lineage" in registration
            else set()
        )
    return _REGISTRATION_FIELDS


def _registration_configuration_digest(registration: dict[str, Any]) -> str:
    fields = _registration_fields(registration)
    authority = {
        key: registration.get(key)
        for key in sorted(fields - {"configuration_digest"})
    }
    return hashlib.sha256(
        json.dumps(authority, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _registration_types_valid(registration: dict[str, Any]) -> bool:
    string_fields = {
        "trusted_registration_id",
        "registration_version",
        "logical_provider_id",
        "provider_name",
        "provider_type",
        "canonical_executable_path",
        "executable_registration_id",
        "executable_registration_version",
        "launcher_path",
        "launcher_registration_id",
        "launcher_registration_version",
        "working_directory_policy",
        "allowed_environment",
        "endpoint_identity",
        "authentication_mode",
        "authentication_profile",
        "provider_policy",
        "independence_classification",
        "model_or_service_identity",
        "qualification_method",
        "qualification_result",
        "registration_status",
        "authorized_by",
        "authorized_at",
        "configuration_digest",
    }
    schema_version = registration.get("registration_schema_version")
    if schema_version not in {
        REGISTRATION_SCHEMA_VERSION,
        CODEX_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION,
        CLAUDE_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION,
    }:
        return False
    if "registration_lineage" in registration and not isinstance(
        registration["registration_lineage"], dict
    ):
        return False
    if any(
        not isinstance(registration.get(key), str) or not registration[key]
        for key in string_fields
    ):
        return False
    if registration["provider_type"] != "local-command":
        return False
    if registration["endpoint_identity"] != "local-process":
        return False
    if registration["authentication_mode"] not in {
        "external-cli-session",
        "chatgpt-subscription-session",
        "claude-ai-subscription-session",
    }:
        return False
    if registration["provider_policy"] != "registered-command":
        return False
    if registration["independence_classification"] not in {
        "authoring-only",
        "independent-capable",
    }:
        return False
    if registration["registration_status"] not in {"active", "revoked"}:
        return False
    if registration["qualification_result"] not in {
        "qualified",
        "not-qualified",
        "failed",
        "pending",
    }:
        return False
    if registration["qualification_method"] not in {
        "protected-registered-launch",
        "none",
    }:
        return False
    for key in ("executable_sha256", "launcher_sha256", "configuration_digest"):
        value = registration.get(key)
        if (
            not isinstance(value, str)
            or len(value) != _SHA256_LENGTH
            or any(character not in "0123456789abcdef" for character in value)
        ):
            return False
    if any(
        not isinstance(registration.get(key), int) or registration[key] < 0
        for key in ("executable_size", "launcher_size")
    ):
        return False
    capabilities = registration.get("capability_set")
    if (
        not isinstance(capabilities, dict)
        or set(capabilities) != set(asdict(ProviderCapabilities()))
        or any(type(value) is not bool for value in capabilities.values())
    ):
        return False
    roles = registration.get("role_eligibility")
    if (
        not isinstance(roles, list)
        or any(not isinstance(item, str) or not item for item in roles)
        or roles != sorted(roles)
        or len(roles) != len(set(roles))
        or any(
            item
            not in {
                "builder",
                "reviewer",
                "repairer",
                "post_repair_reviewer",
            }
            for item in roles
        )
    ):
        return False
    required_capability = {
        "builder": "author",
        "reviewer": "reviewer",
        "repairer": "repairer",
        "post_repair_reviewer": "reviewer",
    }
    if any(
        capabilities[required_capability[role]] is not True for role in roles
    ):
        return False
    try:
        if registration.get("executive_capability_set") != _validated_string_authority_list(
            registration.get("executive_capability_set"), "executive capability"
        ):
            return False
        executive_capabilities = _validated_string_authority_list(
            registration.get("executive_capability_set"), "executive capability"
        )
        if any(item not in _EXECUTIVE_CAPABILITIES for item in executive_capabilities):
            return False
        project_types = _validated_string_authority_list(
            registration.get("project_types"), "project type"
        )
        if registration.get("project_types") != project_types:
            return False
        if any(item not in _PROJECT_TYPES for item in project_types):
            return False
        if schema_version == CODEX_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION:
            if (
                registration.get("logical_provider_id") != "codex"
                or registration.get("authentication_mode")
                != "chatgpt-subscription-session"
                or registration.get("authentication_profile")
                != "authority-bound-windows-user-profile"
                or registration.get("independence_classification")
                != "authoring-only"
                or registration.get("role_eligibility")
                != ["builder", "repairer"]
                or registration.get("effort_levels") != ["medium", "high"]
                or registration.get("model_or_service_identity")
                not in validate_codex_model_allowlist(
                    registration.get("model_allowlist")
                )
                or not isinstance(registration.get("expected_version"), str)
                or not _version_output_valid(
                    "codex", str(registration.get("expected_version"))
                )
                or validate_subscription_pricing_authority(
                    registration.get("pricing_authority")
                )
                != registration.get("pricing_authority")
                or validate_codex_authentication_policy(
                    registration.get("authentication_policy")
                )
                != registration.get("authentication_policy")
                or validate_windows_authentication_binding(
                    registration.get("windows_authentication_binding")
                )
                != registration.get("windows_authentication_binding")
                or validate_codex_usage_policy(registration.get("usage_policy"))
                != registration.get("usage_policy")
                or validate_codex_authenticode_binding(
                    registration.get("authenticode_binding")
                )
                != registration.get("authenticode_binding")
                or validate_executable_file_identity(
                    registration.get("executable_file_identity")
                )
                != registration.get("executable_file_identity")
                or registration["executable_file_identity"]["size"]
                != registration.get("executable_size")
                or validate_subscription_account_binding(
                    registration.get("subscription_account_binding")
                )
                != registration.get("subscription_account_binding")
                or validate_codex_model_capability_binding(
                    registration.get("model_capability_binding")
                )
                != registration.get("model_capability_binding")
                or [
                    item["model_id"]
                    for item in registration["model_capability_binding"]["models"]
                ]
                != registration.get("model_allowlist")
            ):
                return False
            expiry = datetime.fromisoformat(
                str(registration.get("model_revalidation_expires_at"))
            )
            if expiry.tzinfo is None or expiry <= datetime.now(UTC):
                return False
        elif schema_version == CLAUDE_SUBSCRIPTION_REGISTRATION_SCHEMA_VERSION:
            if (
                registration.get("logical_provider_id") != "claude"
                or registration.get("authentication_mode")
                != "claude-ai-subscription-session"
                or registration.get("authentication_profile")
                != "authority-bound-windows-user-profile"
                or registration.get("independence_classification")
                != "independent-capable"
                or registration.get("role_eligibility")
                != ["post_repair_reviewer", "reviewer"]
                or registration.get("capability_set", {}).get("author") is not False
                or registration.get("capability_set", {}).get("reviewer") is not True
                or registration.get("capability_set", {}).get("repairer") is not False
                or registration.get("effort_levels") != ["medium", "high"]
                or registration.get("model_or_service_identity")
                not in validate_claude_model_allowlist(
                    registration.get("model_allowlist")
                )
                or not isinstance(registration.get("expected_version"), str)
                or validate_claude_version_output(
                    registration.get("expected_version")
                )
                != registration.get("expected_version")
                or validate_claude_subscription_pricing_authority(
                    registration.get("pricing_authority")
                )
                != registration.get("pricing_authority")
                or validate_claude_authentication_policy(
                    registration.get("authentication_policy")
                )
                != registration.get("authentication_policy")
                or validate_windows_authentication_binding(
                    registration.get("windows_authentication_binding")
                )
                != registration.get("windows_authentication_binding")
                or validate_claude_usage_policy(registration.get("usage_policy"))
                != registration.get("usage_policy")
                or validate_claude_authenticode_binding(
                    registration.get("authenticode_binding")
                )
                != registration.get("authenticode_binding")
                or validate_executable_file_identity(
                    registration.get("executable_file_identity")
                )
                != registration.get("executable_file_identity")
                or registration["executable_file_identity"]["size"]
                != registration.get("executable_size")
                or validate_claude_subscription_account_binding(
                    registration.get("subscription_account_binding")
                )
                != registration.get("subscription_account_binding")
                or validate_claude_model_capability_binding(
                    registration.get("model_capability_binding")
                )
                != registration.get("model_capability_binding")
                or [
                    item["model_id"]
                    for item in registration["model_capability_binding"]["models"]
                ]
                != registration.get("model_allowlist")
            ):
                return False
            expiry = datetime.fromisoformat(
                str(registration.get("model_revalidation_expires_at"))
            )
            if expiry.tzinfo is None or expiry <= datetime.now(UTC):
                return False
        else:
            if registration.get("effort_levels") != _validated_effort_levels(
                registration.get("effort_levels")
            ):
                return False
            if registration.get("pricing_authority") != _validated_pricing_authority(
                registration.get("pricing_authority")
            ):
                return False
    except (TypeError, ValueError):
        return False
    if any(
        role in {"reviewer", "post_repair_reviewer"}
        for role in roles
    ) and registration["independence_classification"] != "independent-capable":
        return False
    invocation = registration.get("invocation_shape")
    if (
        not isinstance(invocation, list)
        or not invocation
        or any(not isinstance(item, str) or not item for item in invocation)
    ):
        return False
    digests = registration.get("qualifying_component_digests")
    if not isinstance(digests, dict) or set(digests) != {
        "executable",
        "launcher",
        "script",
    }:
        return False
    if (
        digests.get("executable") != registration.get("executable_sha256")
        or digests.get("launcher") != registration.get("launcher_sha256")
        or digests.get("script") != registration.get("script_sha256")
    ):
        return False
    script_path = registration.get("script_path")
    script_fields = (
        registration.get("script_sha256"),
        registration.get("script_size"),
        registration.get("script_registration_id"),
        registration.get("script_registration_version"),
    )
    if script_path is None:
        if any(value is not None for value in script_fields):
            return False
        if invocation[0] != registration.get("launcher_path"):
            return False
    elif (
        not isinstance(script_path, str)
        or not script_path
        or not isinstance(script_fields[0], str)
        or len(script_fields[0]) != _SHA256_LENGTH
        or not isinstance(script_fields[1], int)
        or script_fields[1] < 0
        or not isinstance(script_fields[2], str)
        or not script_fields[2]
        or not isinstance(script_fields[3], str)
        or not script_fields[3]
    ):
        return False
    elif invocation[:4] != [
        registration.get("launcher_path"),
        "/d",
        "/c",
        script_path,
    ]:
        return False
    qualified = registration.get("qualification_result") == "qualified"
    qualification_values = (
        registration.get("qualified_version"),
        registration.get("qualification_timestamp"),
    )
    if qualified != all(isinstance(value, str) and value for value in qualification_values):
        return False
    lifecycle = registration.get("registration_lifecycle")
    expected_lifecycle = {
        "qualified": "QUALIFIED",
        "not-qualified": "REGISTERED_UNQUALIFIED",
        "pending": "QUALIFICATION_PENDING",
        "failed": "QUALIFICATION_FAILED",
    }.get(str(registration.get("qualification_result")))
    if lifecycle != expected_lifecycle:
        return False
    evidence_values = (
        registration.get("qualification_evidence_id"),
        registration.get("qualification_evidence_digest"),
    )
    evidence_required = registration.get("qualification_result") in {
        "qualified",
        "failed",
    }
    if evidence_required != all(
        isinstance(value, str) and value for value in evidence_values
    ):
        return False
    for key in ("revoked_at", "expires_at"):
        if registration.get(key) is not None and not isinstance(
            registration.get(key), str
        ):
            return False
    try:
        authorized = datetime.fromisoformat(str(registration["authorized_at"]))
        if authorized.tzinfo is None:
            return False
        if registration.get("qualification_timestamp"):
            qualified_at = datetime.fromisoformat(
                str(registration["qualification_timestamp"])
            )
            if qualified_at.tzinfo is None:
                return False
        if registration.get("expires_at"):
            datetime.fromisoformat(str(registration["expires_at"]))
    except ValueError:
        return False
    return True


def _validated_string_authority_list(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list) or not value or len(value) > 64
        or any(
            not isinstance(item, str) or not item or len(item) > 128
            or item != item.strip()
            or any(ord(character) < 32 for character in item)
            for item in value
        )
        or value != sorted(value) or len(value) != len(set(value))
    ):
        raise ValueError(f"provider {label} declarations are invalid")
    return list(value)


def _validated_effort_levels(value: object) -> list[str]:
    values = _validated_string_authority_list(value, "effort level")
    if any(item not in _EFFORT_LEVELS for item in values):
        raise ValueError("provider effort-level declaration is unsupported")
    return values


def _validated_pricing_authority(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != _PRICING_AUTHORITY_FIELDS:
        raise ValueError("provider pricing authority fields are invalid")
    result = dict(value)
    for field in (
        "pricing_identity", "pricing_version", "currency", "billing_unit",
        "quoted_at", "expires_at", "source",
    ):
        item = result.get(field)
        if (
            not isinstance(item, str) or not item or len(item) > 256
            or item != item.strip()
            or any(ord(character) < 32 for character in item)
        ):
            raise ValueError(f"provider pricing authority {field} is invalid")
    currency = str(result["currency"])
    if len(currency) != 3 or not currency.isalpha() or currency != currency.upper():
        raise ValueError("provider pricing authority currency is invalid")
    for field in ("estimated_cost", "maximum_cost"):
        item = result.get(field)
        if (
            isinstance(item, bool) or not isinstance(item, (int, float))
            or not math.isfinite(float(item)) or float(item) < 0
        ):
            raise ValueError(f"provider pricing authority {field} is invalid")
        result[field] = float(item)
    tier = result.get("cost_tier")
    if isinstance(tier, bool) or not isinstance(tier, int) or not 0 <= tier <= 100:
        raise ValueError("provider pricing authority cost tier is invalid")
    for field in ("included_plan", "marginally_free"):
        if type(result.get(field)) is not bool:
            raise ValueError(f"provider pricing authority {field} is invalid")
    if result["maximum_cost"] < result["estimated_cost"]:
        raise ValueError("provider pricing maximum is below its estimate")
    included = result["included_plan"] is True
    marginally_free = result["marginally_free"] is True
    if included != marginally_free:
        raise ValueError("provider free-pricing declarations are inconsistent")
    if included:
        if result["estimated_cost"] != 0 or result["maximum_cost"] != 0 or tier != 0:
            raise ValueError("included provider pricing must be exactly zero")
    elif result["maximum_cost"] <= 0 or tier <= 0:
        raise ValueError("paid provider pricing must declare a positive bound and tier")
    try:
        quoted = datetime.fromisoformat(str(result["quoted_at"]))
        expires = datetime.fromisoformat(str(result["expires_at"]))
    except ValueError as error:
        raise ValueError("provider pricing timestamps are invalid") from error
    if (
        quoted.tzinfo is None
        or expires.tzinfo is None
        or expires <= quoted
        or expires <= datetime.now(UTC)
    ):
        raise ValueError("provider pricing validity window is invalid")
    return result


def _registration_expired(registration: dict[str, Any]) -> bool:
    expires_at = registration.get("expires_at")
    if not isinstance(expires_at, str):
        return False
    try:
        expiry = datetime.fromisoformat(expires_at)
    except ValueError:
        return True
    if expiry.tzinfo is None:
        return True
    return expiry <= datetime.now(UTC)


def _cli_registration_arguments(registration: dict[str, Any]) -> dict[str, Any]:
    return {
        "expected_executable_sha256": registration.get("launcher_sha256"),
        "expected_executable_size": registration.get("launcher_size"),
        "registration_id": registration.get("trusted_registration_id"),
        "registration_version": registration.get("registration_version"),
        "configuration_digest": registration.get("configuration_digest"),
        "expected_script_sha256": registration.get("script_sha256"),
        "expected_script_size": registration.get("script_size"),
        "script_registration_id": registration.get("script_registration_id"),
        "script_registration_version": registration.get("script_registration_version"),
    }


def _domain_schema(role: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "status": {"type": "string", "enum": ["completed", "resolved"]},
        "files_changed": {"type": "array", "items": {"type": "string"}},
    }
    required = ["status", "files_changed"]
    if role in {"reviewer", "post_repair_reviewer"}:
        properties["findings"] = {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["finding_id", "severity", "title", "description"],
                "properties": {
                    "finding_id": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["Critical", "High", "Medium", "Low", "Minor"],
                    },
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "file": {"type": ["string", "null"]},
                    "line": {"type": ["integer", "null"]},
                },
                "additionalProperties": False,
            },
        }
        required.append("findings")
    if role == "reviewer":
        review_fields: dict[str, Any] = {
            "schema_version": {"type": "integer", "const": 1},
            "review_id": {"type": "string"},
            "review_attempt_id": {"type": "string"},
            "reviewer_registration": {"type": "string"},
            "reviewer_qualification": {"type": "string"},
            "reviewer_independence_identity": {"type": "string"},
            "project_id": {"type": "string"},
            "charter_revision": {"type": "integer"},
            "workflow_id": {"type": "string"},
            "task_id": {"type": "string"},
            "author_attempt_id": {"type": "string"},
            "artifact_identity": {"type": "string"},
            "artifact_digest": {"type": "string"},
            "evidence_digest": {"type": "string"},
            "review_criteria_version": {"type": "string", "const": "keeper-review-v1"},
            "review_criteria_digest": {"type": "string"},
            "review_disposition": {
                "type": "string",
                "enum": [
                    "ACCEPTED", "REPAIR_REQUIRED", "REJECTED", "INDETERMINATE"
                ],
            },
            "failed_criteria": {"type": "array", "items": {"type": "string"}},
            "required_repairs": {"type": "array", "items": {"type": "string"}},
            "timestamp": {"type": "string"},
        }
        properties.update(review_fields)
        required.extend(review_fields)
        required.remove("status")
        required.remove("files_changed")
        properties.pop("status")
        properties.pop("files_changed")
    if role == "post_repair_reviewer":
        properties["dispositions"] = {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["finding_id", "status", "justification"],
                "properties": {
                    "finding_id": {"type": "string"},
                    "status": {"type": "string", "enum": ["resolved", "open"]},
                    "justification": {"type": "string"},
                },
                "additionalProperties": False,
            },
        }
        required.append("dispositions")
    return {
        "type": "object",
        "x-keeper-role": role,
        "required": required,
        "properties": properties,
        "additionalProperties": False,
    }


def authority_provider_output_schema(
    role: str, *, provider_input_required: bool
) -> dict[str, Any]:
    """Return the one Authority-owned schema used at reserve and launch."""
    role = normalize_authority_provider_role(role)
    schema = _domain_schema(role)
    if not provider_input_required or role != "reviewer":
        return schema
    properties = schema.get("properties")
    required = schema.get("required")
    if not isinstance(properties, dict) or not isinstance(required, list):
        raise PermissionError("provider output schema is unavailable")
    properties["review_input_declaration"] = (
        review_input_declaration_json_schema()
    )
    required.append("review_input_declaration")
    return schema


def normalize_authority_provider_role(role: str) -> str:
    """Normalize Executive role aliases before schema construction."""
    raw_role = role.casefold()
    normalized = {
        "author": "builder",
        "implementer": "builder",
        "executive_builder": "builder",
        "executive_reviewer": "reviewer",
        "executive_post_repair_reviewer": "post_repair_reviewer",
    }.get(raw_role)
    if normalized is not None:
        return normalized
    if "review" in raw_role:
        return "reviewer"
    if "repair" in raw_role:
        return "repairer"
    return "builder"


def validate_value_against_schema(value: object, schema: object) -> bool:
    """Validate the strict JSON-Schema subset emitted by Keeper."""
    if not isinstance(schema, dict):
        return False
    if "const" in schema and value != schema["const"]:
        return False
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        return False
    expected_type = schema.get("type")
    allowed_types = (
        tuple(expected_type)
        if isinstance(expected_type, list)
        else (expected_type,)
    )
    if expected_type is not None and not any(
        _json_type_matches(value, item) for item in allowed_types
    ):
        return False
    if isinstance(value, dict):
        required = schema.get("required", [])
        properties = schema.get("properties", {})
        if not isinstance(required, list) or not isinstance(properties, dict):
            return False
        if not all(isinstance(item, str) and item in value for item in required):
            return False
        if schema.get("additionalProperties") is False and not set(value).issubset(
            properties
        ):
            return False
        return all(
            name not in properties
            or validate_value_against_schema(item, properties[name])
            for name, item in value.items()
        )
    if isinstance(value, list):
        item_schema = schema.get("items")
        return item_schema is None or all(
            validate_value_against_schema(item, item_schema) for item in value
        )
    return True


def _json_type_matches(value: object, expected: object) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": (
            isinstance(value, (int, float)) and not isinstance(value, bool)
        ),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(str(expected), False)
