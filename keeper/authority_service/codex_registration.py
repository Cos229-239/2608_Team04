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
from keeper.authority_service.windows_signature import authenticode_identity
from keeper.provider_host.protocol import structured_digest
from keeper.providers.codex_contract import (
    CODEX_REQUIRED_SUBSCRIPTION_PLAN,
    validate_codex_authenticode_binding,
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

    def reconcile_provider_qualification(
        self, registration_id: str
    ) -> dict[str, Any]: ...

    def recover_provider_registration_failure(
        self, registration_id: str
    ) -> dict[str, Any]: ...

    def retry_provider_qualification(
        self,
        registration_id: str,
        retry_qualification_id: str,
        executable: Path,
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
    if canonical != executable.resolve():
        raise PermissionError("Codex executable path is not canonical")
    observed_hash = file_sha256(canonical)
    if observed_hash != expected_sha256.upper():
        raise PermissionError("Codex executable SHA-256 differs from review")
    if canonical.stat().st_size != expected_size:
        raise PermissionError("Codex executable size differs from review")
    signature = validate_codex_authenticode_binding(
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
            "PATH": os.environ.get("PATH", ""),
        },
    )
    version = completed.stdout.splitlines()[0].strip() if completed.stdout else ""
    if completed.returncode != 0 or version != expected_version:
        raise PermissionError("Codex executable version differs from review")
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
    keeper_launch_budget: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = now or datetime.now(UTC)
    expiry = current + timedelta(days=30)
    return {
        "executive_capabilities": [
            "architecture",
            "implementation",
            "packaging",
            "planning",
            "requirements",
            "security",
            "testing",
        ],
        "project_types": ["software"],
        "effort_levels": ["medium", "high"],
        "pricing_authority": {
            "pricing_identity": "founder-chatgpt-subscription",
            "pricing_version": "2026-08",
            "currency": "USD",
            "estimated_cost": 0.0,
            "maximum_cost": 0.0,
            "billing_unit": "chatgpt-subscription",
            "included_plan": True,
            "marginally_free": False,
            "quoted_at": current.isoformat(),
            "expires_at": expiry.isoformat(),
            "source": "FOUNDER_CONFIRMED_SUBSCRIPTION",
            "cost_tier": 0,
            "billing_mode": "included-subscription",
            "subscription_plan": CODEX_REQUIRED_SUBSCRIPTION_PLAN,
            "incremental_charge_authorized": False,
            "api_billing_authorized": False,
            "paid_fallback_authorized": False,
            "credit_purchase_authorized": False,
            "provider_switch_authorized": False,
            "account_switch_authorized": False,
            "capacity_bounded": True,
            "founder_confirmed": True,
        },
        "expected_executable_sha256": expected_executable_sha256.lower(),
        "expected_executable_size": expected_executable_size,
        "expected_version": expected_version,
        "model_allowlist": ["gpt-5.6-sol"],
        "model_revalidation_expires_at": expiry.isoformat(),
        "authentication_policy": {
            "mode": "chatgpt-subscription",
            "identity_source": "authenticated-named-pipe-client",
            "session_selection": "authenticated-client-session-only",
            "profile_access": "restricted-user-profile",
            "ignore_user_config": True,
            "api_keys_allowed": False,
            "credential_copy_allowed": False,
        },
        "usage_policy": {
            "capacity_mode": "provider-observed-or-keeper-budget",
            "keeper_launch_budget": keeper_launch_budget,
            "budget_window_seconds": 604800,
            "unknown_capacity_behavior": "fail-closed-at-keeper-budget",
            "reset_policy": "provider-observed-only",
            "automatic_retry": False,
            "provider_switch": False,
            "account_switch": False,
            "api_fallback": False,
            "credit_purchase": False,
        },
    }


def persist_public_response(path: Path, value: dict[str, Any]) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite {destination.name}")
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.tmp"
    )
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def claim_registration_attempt(output_directory: Path) -> Path:
    destination = output_directory.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    claim = destination / "registration-attempt.claim.json"
    try:
        with claim.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(
                {
                    "schema_version": 1,
                    "operation": "codex-register-and-qualify-once",
                    "state": "CLAIMED",
                },
                output,
                sort_keys=True,
                separators=(",", ":"),
            )
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as error:
        raise FileExistsError(
            "Codex registration output directory is already claimed"
        ) from error
    return claim


def claim_qualification_reconciliation(
    output_directory: Path, registration_id: str
) -> Path:
    destination = output_directory.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    claim = destination / "qualification-reconciliation.claim.json"
    try:
        with claim.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(
                {
                    "schema_version": 1,
                    "operation": "codex-reconcile-qualification-once",
                    "registration_id": registration_id,
                    "state": "CLAIMED",
                },
                output,
                sort_keys=True,
                separators=(",", ":"),
            )
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as error:
        raise FileExistsError(
            "Codex qualification reconciliation output directory is already claimed"
        ) from error
    return claim


def register_and_qualify_once(
    client: RegistrationClient,
    executable: Path,
    output_directory: Path,
    declaration: dict[str, Any],
) -> dict[str, str]:
    claim_registration_attempt(output_directory)
    register_response = client.register_provider(
        "codex", executable, **declaration
    )
    registration_path = output_directory / "registration-response.json"
    persist_public_response(registration_path, register_response)
    if isinstance(register_response.get("registration_failed"), dict):
        raise PermissionError(
            "registration failure was persisted and requires Founder disposition"
        )
    registration_id = register_response.get("registration_id")
    if not isinstance(registration_id, str) or not registration_id:
        raise RuntimeError(
            "registration response was persisted but contains no registration ID"
        )
    qualification_response = client.qualify_provider(registration_id, executable)
    qualification_path = output_directory / "qualification-response.json"
    persist_public_response(qualification_path, qualification_response)
    qualification = qualification_response.get("qualification")
    qualification_id = (
        qualification.get("id") if isinstance(qualification, dict) else None
    )
    if not isinstance(qualification_id, str) or not qualification_id:
        raise RuntimeError(
            "qualification response was persisted but contains no qualification ID"
        )
    return {
        "registration_id": registration_id,
        "qualification_id": qualification_id,
        "registration_response": str(registration_path.resolve()),
        "qualification_response": str(qualification_path.resolve()),
    }


def reconcile_qualification_once(
    client: RegistrationClient,
    registration_id: str,
    output_directory: Path,
) -> dict[str, str]:
    exact_registration_id = registration_id.strip()
    if not exact_registration_id or exact_registration_id != registration_id:
        raise ValueError("registration ID must be an exact non-empty value")
    claim_qualification_reconciliation(output_directory, exact_registration_id)
    response = client.reconcile_provider_qualification(exact_registration_id)
    response_path = output_directory / "qualification-reconciliation-response.json"
    persist_public_response(response_path, response)

    registration = response.get("registration")
    qualification = response.get("qualification")
    returned_registration_id = (
        registration.get("trusted_registration_id")
        if isinstance(registration, dict)
        else None
    )
    qualification_id = (
        qualification.get("id") if isinstance(qualification, dict) else None
    )
    qualification_registration_id = (
        qualification.get("registration_id")
        if isinstance(qualification, dict)
        else None
    )
    if (
        response.get("reconciled") is not True
        or returned_registration_id != exact_registration_id
        or not isinstance(qualification_id, str)
        or not qualification_id
        or qualification_registration_id != exact_registration_id
    ):
        raise RuntimeError(
            "qualification reconciliation response was persisted but its exact "
            "binding is invalid"
        )
    return {
        "registration_id": exact_registration_id,
        "qualification_id": qualification_id,
        "reconciliation_response": str(response_path.resolve()),
    }


def recover_registration_failure_once(
    client: RegistrationClient,
    registration_id: str,
    output_directory: Path,
) -> dict[str, str]:
    exact_registration_id = registration_id.strip()
    if not exact_registration_id or exact_registration_id != registration_id:
        raise ValueError("registration ID must be an exact non-empty value")
    output = output_directory.resolve()
    output.mkdir(parents=True, exist_ok=True)
    claim = output / "registration-failure-recovery.claim.json"
    persist_public_response(
        claim,
        {
            "schema_version": 1,
            "operation": "codex-recover-registration-failure-once",
            "registration_id": exact_registration_id,
            "state": "CLAIMED",
        },
    )
    response = client.recover_provider_registration_failure(
        exact_registration_id
    )
    response_path = output / "registration-failure-response.json"
    persist_public_response(response_path, response)
    failure = response.get("registration_failed")
    if (
        response.get("registration_id") != exact_registration_id
        or response.get("state") != "REGISTRATION_FAILED"
        or not isinstance(failure, dict)
        or failure.get("registration_id") != exact_registration_id
        or failure.get("attempt_generation") not in {1, 2}
    ):
        raise RuntimeError(
            "registration failure response was persisted but is invalid"
        )
    return {
        "registration_id": exact_registration_id,
        "failure_digest": structured_digest(failure),
        "attempt_generation": str(failure["attempt_generation"]),
        "recovery_response": str(response_path.resolve()),
    }


def retry_qualification_once(
    client: RegistrationClient,
    registration_id: str,
    retry_qualification_id: str,
    executable: Path,
    output_directory: Path,
) -> dict[str, str]:
    exact_registration_id = registration_id.strip()
    exact_retry_id = retry_qualification_id.strip()
    if not exact_registration_id or exact_registration_id != registration_id:
        raise ValueError("registration ID must be an exact non-empty value")
    if not exact_retry_id or exact_retry_id != retry_qualification_id:
        raise ValueError("retry qualification ID must be an exact non-empty value")
    output = output_directory.resolve()
    output.mkdir(parents=True, exist_ok=False)
    claim = output / "qualification-retry.claim.json"
    persist_public_response(
        claim,
        {
            "schema_version": 1,
            "operation": "codex-retry-qualification-once",
            "registration_id": exact_registration_id,
            "retry_qualification_id": exact_retry_id,
            "state": "CLAIMED",
        },
    )
    response = client.retry_provider_qualification(
        exact_registration_id,
        exact_retry_id,
        executable.resolve(strict=True),
    )
    response_path = output / "qualification-retry-response.json"
    persist_public_response(response_path, response)
    registration = response.get("registration")
    qualification = response.get("qualification")
    if (
        not isinstance(registration, dict)
        or not isinstance(qualification, dict)
        or registration.get("trusted_registration_id") != exact_registration_id
        or qualification.get("registration_id") != exact_registration_id
        or qualification.get("id") != exact_retry_id
    ):
        raise RuntimeError(
            "qualification retry response was persisted but is misbound"
        )
    return {
        "registration_id": exact_registration_id,
        "qualification_id": exact_retry_id,
        "qualification_result": str(qualification.get("qualification_result")),
        "retry_response": str(response_path.resolve()),
    }


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keeper-authority codex-register-once"
    )
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-size", type=int, required=True)
    parser.add_argument("--expected-version", required=True)
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
        options.output_directory.resolve(),
        registration_declaration(
            expected_executable_sha256=options.expected_sha256,
            expected_executable_size=options.expected_size,
            expected_version=options.expected_version,
            keeper_launch_budget=options.keeper_launch_budget,
        ),
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def reconciliation_main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keeper-authority codex-reconcile-qualification"
    )
    parser.add_argument("--registration-id", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    options = parser.parse_args(arguments)
    registration_id = str(options.registration_id)
    if not registration_id or registration_id.strip() != registration_id:
        parser.error("--registration-id must be an exact non-empty value")
    if not options.apply:
        print(
            json.dumps(
                {
                    "apply_required": True,
                    "operation": "codex-reconcile-qualification-once",
                    "registration_id": registration_id,
                },
                sort_keys=True,
            )
        )
        return 0
    result = reconcile_qualification_once(
        ProductionAuthorityServiceClient(),
        registration_id,
        options.output_directory.resolve(),
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def registration_failure_recovery_main(
    arguments: Sequence[str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="keeper-authority codex-recover-registration-failure"
    )
    parser.add_argument("--registration-id", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    options = parser.parse_args(arguments)
    registration_id = str(options.registration_id)
    if not registration_id or registration_id.strip() != registration_id:
        parser.error("--registration-id must be an exact non-empty value")
    if not options.apply:
        print(
            json.dumps(
                {
                    "apply_required": True,
                    "operation": "codex-recover-registration-failure-once",
                    "registration_id": registration_id,
                },
                sort_keys=True,
            )
        )
        return 0
    result = recover_registration_failure_once(
        ProductionAuthorityServiceClient(),
        registration_id,
        options.output_directory.resolve(),
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def qualification_retry_main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keeper-authority codex-retry-qualification"
    )
    parser.add_argument("--registration-id", required=True)
    parser.add_argument("--retry-qualification-id", required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-size", type=int, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
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
    result = retry_qualification_once(
        ProductionAuthorityServiceClient(),
        str(options.registration_id),
        str(options.retry_qualification_id),
        options.executable,
        options.output_directory,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
