from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, Sequence

from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.authority_service.codex_registration import persist_public_response
from keeper.authority_service.windows_signature import authenticode_identity
from keeper.providers.claude_contract import (
    CLAUDE_ALLOWED_SUBSCRIPTION_PLANS,
    CLAUDE_PINNED_REVIEW_MODEL,
    validate_claude_authenticode_binding,
)


class RegistrationClient(Protocol):
    def register_provider(
        self,
        provider_id: str,
        executable: Path,
        *,
        executive_capabilities: list[str],
        project_types: list[str],
        effort_levels: list[str],
        pricing_authority: dict[str, Any],
        expected_executable_sha256: str | None = None,
        expected_executable_size: int | None = None,
        expected_version: str | None = None,
        model_allowlist: list[str] | None = None,
        model_revalidation_expires_at: str | None = None,
        authentication_policy: dict[str, Any] | None = None,
        usage_policy: dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...

    def qualify_provider(
        self, registration_id: str, executable: Path | None = None
    ) -> dict[str, Any]: ...


def file_sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest().upper()


def verify_reviewed_executable(
    executable: Path,
    *,
    expected_sha256: str,
    expected_size: int,
    expected_version: str,
) -> dict[str, object]:
    canonical = executable.resolve(strict=True)
    observed_hash = file_sha256(canonical)
    if observed_hash != expected_sha256.upper():
        raise PermissionError("Claude executable SHA-256 differs from review")
    if canonical.stat().st_size != expected_size:
        raise PermissionError("Claude executable size differs from review")
    signature = validate_claude_authenticode_binding(
        authenticode_identity(canonical)
    )
    completed = subprocess.run(
        [str(canonical), "--version"],
        check=False,
        text=True,
        encoding="utf-8",
        errors="strict",
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        env={
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
            "WINDIR": os.environ.get("WINDIR", r"C:\Windows"),
            "PATH": str(canonical.parent),
        },
    )
    version = completed.stdout.splitlines()[0].strip() if completed.stdout else ""
    if completed.returncode != 0 or version != expected_version:
        raise PermissionError("Claude executable version differs from review")
    return {
        "path": str(canonical),
        "sha256": observed_hash,
        "size": expected_size,
        "version": version,
        "authenticode_status": signature["status"],
        "publisher_subject": signature["publisher_subject"],
        "certificate_thumbprint": signature["certificate_thumbprint"],
    }


def registration_declaration(
    *,
    expected_executable_sha256: str,
    expected_executable_size: int,
    expected_version: str,
    subscription_plan: str,
    keeper_launch_budget: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    plan = subscription_plan.casefold()
    if plan not in CLAUDE_ALLOWED_SUBSCRIPTION_PLANS:
        raise ValueError("Claude subscription plan is unsupported")
    current = now or datetime.now(UTC)
    expiry = current + timedelta(days=30)
    return {
        "executive_capabilities": ["security", "testing"],
        "project_types": ["software"],
        "effort_levels": ["medium", "high"],
        "pricing_authority": {
            "pricing_identity": "founder-claude-subscription",
            "pricing_version": "2026-08",
            "currency": "USD",
            "estimated_cost": 0,
            "maximum_cost": 0,
            "billing_unit": "claude-subscription",
            "included_plan": True,
            "marginally_free": False,
            "quoted_at": current.isoformat(),
            "expires_at": expiry.isoformat(),
            "source": "FOUNDER_CONFIRMED_SUBSCRIPTION",
            "cost_tier": 0,
            "billing_mode": "included-subscription",
            "incremental_charge_authorized": False,
            "api_billing_authorized": False,
            "paid_fallback_authorized": False,
            "credit_purchase_authorized": False,
            "provider_switch_authorized": False,
            "account_switch_authorized": False,
            "capacity_bounded": True,
            "founder_confirmed": True,
            "subscription_plan": plan,
        },
        "expected_executable_sha256": expected_executable_sha256.lower(),
        "expected_executable_size": expected_executable_size,
        "expected_version": expected_version,
        "model_allowlist": [CLAUDE_PINNED_REVIEW_MODEL],
        "model_revalidation_expires_at": expiry.isoformat(),
        "authentication_policy": {
            "mode": "claude-ai-subscription",
            "identity_source": "authenticated-named-pipe-client",
            "session_selection": "authenticated-client-session-only",
            "profile_access": "restricted-user-profile",
            "setting_sources": "none",
            "api_keys_allowed": False,
            "credential_copy_allowed": False,
            "paid_fallback_allowed": False,
            "provider_switch_allowed": False,
        },
        "usage_policy": {
            "capacity_mode": "keeper-budget-only",
            "keeper_launch_budget": keeper_launch_budget,
            "budget_window_seconds": 604800,
            "unknown_capacity_behavior": "fail-closed-at-keeper-budget",
            "reset_policy": "founder-reauthorization-only",
            "automatic_retry": False,
            "provider_switch": False,
            "account_switch": False,
            "api_fallback": False,
            "credit_purchase": False,
        },
    }


def register_and_qualify_once(
    client: RegistrationClient,
    executable: Path,
    output_directory: Path,
    declaration: dict[str, Any],
) -> dict[str, str]:
    output = output_directory.resolve()
    output.mkdir(parents=True, exist_ok=False)
    persist_public_response(
        output / "registration-attempt.claim.json",
        {
            "schema_version": 1,
            "operation": "claude-register-and-qualify-once",
            "state": "CLAIMED",
        },
    )
    registration_response = client.register_provider(
        "claude", executable, **declaration
    )
    registration_path = output / "registration-response.json"
    persist_public_response(registration_path, registration_response)
    if isinstance(registration_response.get("registration_failed"), dict):
        raise PermissionError(
            "Claude registration failure was persisted and requires Founder disposition"
        )
    registration_id = registration_response.get("registration_id")
    if not isinstance(registration_id, str) or not registration_id:
        raise RuntimeError(
            "Claude registration response contains no registration ID"
        )
    qualification_response = client.qualify_provider(registration_id, executable)
    qualification_path = output / "qualification-response.json"
    persist_public_response(qualification_path, qualification_response)
    qualification = qualification_response.get("qualification")
    qualification_id = (
        qualification.get("id") if isinstance(qualification, dict) else None
    )
    if not isinstance(qualification_id, str) or not qualification_id:
        raise RuntimeError(
            "Claude qualification response contains no qualification ID"
        )
    return {
        "registration_id": registration_id,
        "qualification_id": qualification_id,
        "registration_response": str(registration_path.resolve()),
        "qualification_response": str(qualification_path.resolve()),
    }


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keeper-authority claude-register-once"
    )
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-size", type=int, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument(
        "--subscription-plan", choices=sorted(CLAUDE_ALLOWED_SUBSCRIPTION_PLANS), required=True
    )
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--keeper-launch-budget", type=int, default=20)
    parser.add_argument("--apply", action="store_true")
    options = parser.parse_args(arguments)
    identity = verify_reviewed_executable(
        options.executable,
        expected_sha256=options.expected_sha256,
        expected_size=options.expected_size,
        expected_version=options.expected_version,
    )
    if not options.apply:
        print(json.dumps({"verified_identity": identity}, sort_keys=True))
        return 0
    result = register_and_qualify_once(
        ProductionAuthorityServiceClient(),
        options.executable.resolve(strict=True),
        options.output_directory,
        registration_declaration(
            expected_executable_sha256=options.expected_sha256,
            expected_executable_size=options.expected_size,
            expected_version=options.expected_version,
            subscription_plan=options.subscription_plan,
            keeper_launch_budget=options.keeper_launch_budget,
        ),
    )
    print(json.dumps(result, sort_keys=True))
    return 0
