from __future__ import annotations

import hashlib
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, cast

import pytest

from keeper.authority_service.client import AuthorityServiceClient
from keeper.authority_service.protocol import Operation, Request
from keeper.authority_service.codex_registration import (
    persist_public_response,
    reconcile_qualification_once,
    reconciliation_main,
    register_and_qualify_once,
    registration_declaration,
)
from keeper.authority_service.observer import (
    ServiceProviderObserver,
    _open_validated_reviewed_codex_executable,
    _validated_reviewed_codex_executable,
)
from keeper.authority_service.restricted_process import (
    WindowsSessionQueryResult,
    WindowsSessionQueryStatus,
)
from keeper.authority_service.windows_identity import (
    NamedPipeClientProcessBinding,
    NamedPipeClientProcessIdentity,
)
from keeper.authority_service.core import (
    AuthorityServiceCore,
    ExecutionObservation,
    ProcessObservation,
    QualificationObservation,
    TrustedObserver,
    _provider_input_is_required,
)
from keeper.executive.founder_capability import TestFounderCapabilityVerifier
from keeper.executive.authority_gateway import (
    AuthorityProviderBinding,
    SemanticAuthorityTestGateway,
    authority_operations,
)
from keeper.executive.models import ExecutiveTask, SpecialistProfile
from keeper.executive.runtime import ExecutiveRuntime
from keeper.executive.specialists import SpecialistSelector
from keeper.pass_b.application import PassBApplication
from keeper.pass_b.pilot import PilotConversationExecutive
from keeper.providers.adapters import (
    authority_provider_output_schema,
    canonical_provider_registration_digest,
    create_provider_registration,
    validate_value_against_schema,
    validate_provider_registration_contract,
)
from keeper.providers.codex_contract import (
    app_server_probe_exchange,
    app_server_probe_input,
    build_codex_exec_command,
    classify_codex_execution_failure,
    parse_codex_app_server_probe,
    sanitized_codex_environment,
    structured_digest,
    validate_subscription_account_binding,
    validate_subscription_pricing_authority,
)
from tests.keeper.test_authority_service_core import _launch_authority, _service
from tests.keeper.executive.test_intake_charters import approved_project
from tests.keeper.executive.authority_semantics import ALL_CAPABILITIES


def _zero_launch_journal() -> dict[str, object]:
    return {
        "active_launch_count": 0,
        "active_or_uncertain_launch_count": 0,
        "launches": [],
        "summary_digest": hashlib.sha256(b"[]").hexdigest(),
        "uncertain_launch_count": 0,
    }


class _FakeClientProcessBinding(NamedPipeClientProcessBinding):
    def __init__(self, sid: str = "S-1-5-21-1000", session_id: int = 1) -> None:
        self.pipe = 11
        self.expected_identity = NamedPipeClientProcessIdentity(
            process_id=700,
            session_id=session_id,
            sid=sid,
            computer_name="LOCALHOST",
        )

    @property
    def profile_token(self) -> int:
        return 86

    def revalidate(self, expected_sid: str) -> NamedPipeClientProcessIdentity:
        if self.expected_identity.sid.casefold() != expected_sid.casefold():
            raise PermissionError("authority client process SID is mismatched")
        return self.expected_identity

    @contextmanager
    def duplicate_client_handle(
        self,
        handle_value: int,
        expected_sid: str,
        *,
        transfer_process: int,
    ) -> Iterator[int]:
        assert transfer_process == 73
        self.revalidate(expected_sid)
        yield handle_value
        self.revalidate(expected_sid)

    def release(self) -> None:
        return


def _attach_fake_client_process_binding(
    service: ServiceProviderObserver,
    sid: str = "S-1-5-21-1000",
    session_id: int = 1,
) -> None:
    service._local.client_binding = _FakeClientProcessBinding(sid, session_id)


class _OneShotRegistrationClient:
    def __init__(
        self,
        *,
        registration_response: dict[str, Any] | None = None,
        qualification_response: dict[str, Any] | None = None,
    ) -> None:
        self.registration_response = registration_response or {
            "registration_id": "registration-1",
            "registration": {"public": True},
        }
        self.qualification_response = qualification_response or {
            "qualification": {"id": "qualification-1", "public": True}
        }
        self.register_calls = 0
        self.qualify_calls = 0
        self.declaration: dict[str, Any] | None = None

    def register_provider(
        self, provider_id: str, executable: Path, **declaration: Any
    ) -> dict[str, Any]:
        assert provider_id == "codex"
        assert executable.name == "codex.exe"
        self.register_calls += 1
        self.declaration = declaration
        return dict(self.registration_response)

    def qualify_provider(
        self, registration_id: str, executable: Path | None = None
    ) -> dict[str, Any]:
        assert registration_id == "registration-1"
        assert executable is None or executable.name == "codex.exe"
        self.qualify_calls += 1
        return dict(self.qualification_response)


class _CodexObserver:
    def __init__(
        self,
        *,
        qualification_complete: bool = True,
        exhausted: bool = False,
        execution_model: str = "gpt-5.6-sol",
        execution_effort: str | None = None,
        failure_classification: str | None = None,
        qualification_version: str = "codex-cli 0.146.0",
        capacity_state: str = "OBSERVED",
        usage_confidence: str = "HIGH",
    ) -> None:
        self.qualification_complete = qualification_complete
        self.exhausted = exhausted
        self.execution_model = execution_model
        self.execution_effort = execution_effort
        self.failure_classification = failure_classification
        self.qualification_version = qualification_version
        self.capacity_state = capacity_state
        self.usage_confidence = usage_confidence
        self.qualify_calls = 0
        self.execute_calls = 0
        self.validation_calls = 0

    def validate_registered_executable(
        self,
        registration: dict[str, Any],
        client_executable_handle: int,
    ) -> None:
        del client_executable_handle
        self.validation_calls += 1
        executable = Path(str(registration["canonical_executable_path"]))
        content = executable.read_bytes()
        stat = executable.stat()
        observed_identity = {
            "schema_version": 1,
            "device_id": stat.st_dev,
            "file_id": stat.st_ino,
            "size": stat.st_size,
            "modified_ns": stat.st_mtime_ns,
        }
        if (
            hashlib.sha256(content).hexdigest()
            != registration["executable_sha256"]
            or len(content) != registration["executable_size"]
            or observed_identity != registration["executable_file_identity"]
        ):
            raise PermissionError(
                "registered provider executable changed before qualification"
            )

    def qualify(
        self, registration: dict[str, Any], challenge: str
    ) -> QualificationObservation:
        self.qualify_calls += 1
        executable = Path(str(registration["canonical_executable_path"]))
        transaction = executable.parent / f"qualification-{challenge[:8]}"
        transaction.mkdir(exist_ok=True)
        schema = transaction / "schema.json"
        output = transaction / "output.json"
        schema.write_text("{}", encoding="utf-8")
        command = build_codex_exec_command(
            executable,
            model_id="gpt-5.6-sol",
            reasoning_level="medium",
            schema_path=schema,
            output_path=output,
            prompt="qualification",
        )
        now = datetime.now(UTC).isoformat()
        return QualificationObservation(
            "codex-session:test",
            {
                "pid": 4001,
                "launch_nonce": challenge,
                "restricted": True,
                "job_confined": True,
                "integrity_level": "medium",
                "executable": str(executable),
                "executable_sha256": hashlib.sha256(
                    executable.read_bytes()
                ).hexdigest(),
            },
            now,
            now,
            0,
            self.qualification_version,
            None,
            (
                {
                    "authentication_method": "chatgpt-subscription",
                    "plan_type": "plus",
                    "account_identity_digest": "c" * 64,
                    "models": ["gpt-5.6-sol"],
                    "model_capabilities": [
                        {
                            "model_id": "gpt-5.6-sol",
                            "supported_reasoning_efforts": ["medium", "high"],
                        }
                    ],
                    "usage_observation": self._usage(),
                }
                if self.qualification_complete
                else None
            ),
            self._usage() if self.qualification_complete else None,
            (
                {
                    "status": "ok",
                    "provider": "codex",
                    "effort": "medium",
                    "nonce": "keeper-codex-qualification-v1",
                }
                if self.qualification_complete
                else None
            ),
            tuple(command) if self.qualification_complete else (),
            "c" * 64 if self.qualification_complete else None,
            "d" * 64 if self.qualification_complete else None,
        )

    def preflight_provider(
        self, registration: dict[str, Any], attempt: dict[str, Any]
    ) -> dict[str, Any]:
        del registration, attempt
        return {
            **self._usage(),
            "authentication_method": "chatgpt-subscription",
            "plan_type": "plus",
            "account_identity_digest": "c" * 64,
            "model_allowlist": ["gpt-5.6-sol"],
            "model_capabilities": [
                {
                    "model_id": "gpt-5.6-sol",
                    "supported_reasoning_efforts": ["medium", "high"],
                }
            ],
        }

    def read_exchange_file(
        self, value: object, label: str, maximum_bytes: int
    ) -> tuple[Path, bytes]:
        del label
        path = Path(str(value)).resolve(strict=True)
        content = path.read_bytes()
        if len(content) > maximum_bytes:
            raise PermissionError("test exchange file is too large")
        return path, content

    def execute_provider(
        self,
        registration: dict[str, Any],
        attempt: dict[str, Any],
        on_started: Any,
    ) -> ExecutionObservation:
        self.execute_calls += 1
        executable = Path(str(registration["launcher_path"]))
        on_started(
            ProcessObservation(
                4100 + self.execute_calls,
                datetime.now(UTC).isoformat(),
                str(executable),
                str(registration["launcher_sha256"]),
                True,
                "medium",
                True,
            )
        )
        stdout = Path(str(attempt["stdout_path"]))
        stderr = Path(str(attempt["stderr_path"]))
        stdout.parent.mkdir(parents=True, exist_ok=True)
        stdout.write_text(
            '{"status":"completed","files_changed":["result.txt"]}',
            encoding="utf-8",
        )
        stderr.write_text("", encoding="utf-8")
        return ExecutionObservation(
            4100 + self.execute_calls,
            0,
            False,
            str(stdout),
            str(stderr),
            "e" * 64,
            datetime.now(UTC).isoformat(),
            cast(dict[str, Any], attempt["usage_observation"]),
            self.execution_model,
            self.execution_effort or str(attempt["reasoning_level"]),
            "1" * 64,
            str(attempt["prompt_digest"]),
            str(attempt["output_schema_digest"]),
            "2" * 64,
            self.failure_classification,
        )

    def _usage(self) -> dict[str, Any]:
        return {
            "capacity_state": self.capacity_state,
            "buckets": [],
            "exhausted": self.exhausted,
            "source": "codex-app-server-public-api",
            "confidence": self.usage_confidence,
            "credits_ignored": True,
        }


class _HostQualificationObserver(_CodexObserver):
    def __init__(self, *, lose_first_bind_response: bool = False) -> None:
        super().__init__()
        self.bound: dict[str, Any] | None = None
        self.bind_calls = 0
        self.lose_first_bind_response = lose_first_bind_response

    def qualification_identifier(
        self, registration: dict[str, Any], planned_identifier: str
    ) -> str:
        del registration
        return planned_identifier

    def bind_qualified_provider(
        self,
        registration: dict[str, Any],
        qualification: dict[str, Any],
    ) -> dict[str, Any]:
        self.bind_calls += 1
        binding = {
            "registration_id": registration["trusted_registration_id"],
            "qualification_id": qualification["id"],
            "evidence_digest": qualification["evidence_digest"],
        }
        if self.bound is not None and self.bound != binding:
            raise PermissionError("Provider Host provider binding conflicts")
        self.bound = binding
        if self.lose_first_bind_response and self.bind_calls == 1:
            raise OSError("simulated lost Host bind response")
        return {**binding, "state": "QUALIFIED"}


class _RecoverableTerminalQualificationObserver(_HostQualificationObserver):
    def __init__(self) -> None:
        super().__init__()
        self.external_model_requests = 0
        self._terminal: QualificationObservation | None = None

    def qualify(
        self, registration: dict[str, Any], challenge: str
    ) -> QualificationObservation:
        if registration.get("_recovering_qualification") is True:
            assert self._terminal is not None
            return self._terminal
        self.external_model_requests += 1
        self._terminal = super().qualify(registration, challenge)
        return self._terminal


def _codex_service(
    tmp_path: Path, observer: _CodexObserver
) -> tuple[AuthorityServiceCore, AuthorityServiceClient]:
    core = AuthorityServiceCore(
        tmp_path / "authority",
        observer=cast(TrustedObserver, observer),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    return core, AuthorityServiceClient(
        test_transport=lambda request: core.dispatch(
            request, "S-1-5-21-1000"
        )
    )


def _pricing() -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "pricing_identity": "founder-chatgpt-plus",
        "pricing_version": "2026-08",
        "currency": "USD",
        "estimated_cost": 0.0,
        "maximum_cost": 0.0,
        "billing_unit": "chatgpt-subscription",
        "included_plan": True,
        "marginally_free": False,
        "quoted_at": now.isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "source": "FOUNDER_CONFIRMED_SUBSCRIPTION",
        "cost_tier": 0,
        "billing_mode": "included-subscription",
        "subscription_plan": "plus",
        "incremental_charge_authorized": False,
        "api_billing_authorized": False,
        "paid_fallback_authorized": False,
        "credit_purchase_authorized": False,
        "provider_switch_authorized": False,
        "account_switch_authorized": False,
        "capacity_bounded": True,
        "founder_confirmed": True,
    }


def _authentication_policy() -> dict[str, object]:
    return {
        "mode": "chatgpt-subscription",
        "identity_source": "authenticated-named-pipe-client",
        "session_selection": "authenticated-client-session-only",
        "profile_access": "restricted-user-profile",
        "ignore_user_config": True,
        "api_keys_allowed": False,
        "credential_copy_allowed": False,
    }


def _usage_policy(*, budget: int = 20) -> dict[str, object]:
    return {
        "capacity_mode": "provider-observed-or-keeper-budget",
        "keeper_launch_budget": budget,
        "budget_window_seconds": 604800,
        "unknown_capacity_behavior": "fail-closed-at-keeper-budget",
        "reset_policy": "provider-observed-only",
        "automatic_retry": False,
        "provider_switch": False,
        "account_switch": False,
        "api_fallback": False,
        "credit_purchase": False,
    }


def _registration(
    executable: Path,
    *,
    budget: int = 20,
    executive_capabilities: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    return create_provider_registration(
        "codex",
        executable,
        authorized_by="S-1-5-21-1000",
        executive_capabilities=(
            executive_capabilities or ["implementation", "testing"]
        ),
        project_types=["software"],
        effort_levels=["medium", "high"],
        pricing_authority=_pricing(),
        expected_version="codex-cli 0.146.0",
        model_allowlist=["gpt-5.6-sol"],
        model_revalidation_expires_at=(now + timedelta(days=30)).isoformat(),
        authentication_policy=_authentication_policy(),
        windows_authentication_binding={
            "principal_sid": "S-1-5-21-1000",
            "windows_session_id": 1,
            "profile_identity": r"C:\Users\Founder",
            "profile_digest": "a" * 64,
            "source": "authenticated-named-pipe-client-process",
        },
        usage_policy=_usage_policy(budget=budget),
        authenticode_binding={
            "status": "Valid",
            "publisher_subject": 'CN="OpenAI OpCo, LLC"',
            "certificate_thumbprint": (
                "0B7C30C11BF7250EC1ECD3254AC781D9E13D62F8"
            ),
            "source": "windows-authenticode",
        },
        subscription_account_binding={
            "authentication_method": "chatgpt-subscription",
            "plan_type": "plus",
            "account_identity_digest": "c" * 64,
            "source": "authority-public-codex-probe",
            "observed_at": now.isoformat(),
        },
        model_capability_binding={
            "models": [
                {
                    "model_id": "gpt-5.6-sol",
                    "supported_reasoning_efforts": ["medium", "high"],
                }
            ],
            "source": "authority-public-codex-probe",
            "observed_at": now.isoformat(),
        },
    )


def _qualified(registration: dict[str, object]) -> dict[str, object]:
    result = dict(registration)
    result.update(
        {
            "qualified_version": "codex-cli 0.146.0",
            "qualification_timestamp": datetime.now(UTC).isoformat(),
            "qualification_method": "protected-registered-launch",
            "qualification_result": "qualified",
            "registration_lifecycle": "QUALIFIED",
            "qualification_evidence_id": "provider-qualification:test",
            "qualification_evidence_digest": "b" * 64,
        }
    )
    result["configuration_digest"] = canonical_provider_registration_digest(
        result
    )
    return result


def test_unbound_enrolled_host_can_qualify_and_bind_exact_provider(
    tmp_path: Path,
) -> None:
    observer = _HostQualificationObserver()
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _registration(executable)
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations",
        registration_id,
        "REGISTERED_UNQUALIFIED",
        registration,
    )

    qualified = client.qualify_provider(registration_id, executable)

    qualification_id = str(qualified["qualification"]["id"])
    assert observer.bound == {
        "registration_id": registration_id,
        "qualification_id": qualification_id,
        "evidence_digest": qualified["qualification"]["evidence_digest"],
    }
    assert observer.bind_calls == 1
    stored_registration = core.store.get("registrations", registration_id)
    stored_qualification = core.store.get("qualifications", qualification_id)
    assert stored_registration is not None
    assert stored_registration["service_state"] == "QUALIFIED"
    stored_contract = dict(stored_registration)
    stored_contract.pop("service_state")
    assert validate_provider_registration_contract(stored_contract)[0] is True
    assert stored_qualification is not None
    assert stored_qualification["service_state"] == "QUALIFIED"


def test_lost_provider_bind_response_reconciles_exact_durable_binding(
    tmp_path: Path,
) -> None:
    observer = _HostQualificationObserver(lose_first_bind_response=True)
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _registration(executable)
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations",
        registration_id,
        "REGISTERED_UNQUALIFIED",
        registration,
    )

    with pytest.raises(RuntimeError, match="binding is uncertain"):
        client.qualify_provider(registration_id, executable)
    uncertain = core.store.get("registrations", registration_id)
    assert uncertain is not None
    assert uncertain["service_state"] == "UNCERTAIN"
    assert uncertain["registration_lifecycle"] == "QUALIFIED"
    uncertain_contract = dict(uncertain)
    uncertain_contract.pop("service_state")
    assert validate_provider_registration_contract(uncertain_contract)[0] is True
    assert observer.bound is not None
    qualification_id = str(uncertain["qualification_evidence_id"])
    qualification = core.store.get("qualifications", qualification_id)
    assert qualification is not None
    assert qualification["service_state"] == "UNCERTAIN"

    recovered = client.reconcile_provider_qualification(registration_id)

    assert recovered["reconciled"] is True
    assert observer.bind_calls == 2
    reconciled_registration = core.store.get("registrations", registration_id)
    reconciled_qualification = core.store.get(
        "qualifications", qualification_id
    )
    assert reconciled_registration is not None
    assert reconciled_qualification is not None
    assert reconciled_registration["service_state"] == "QUALIFIED"
    assert reconciled_qualification["service_state"] == "QUALIFIED"
    reconciled_contract = dict(reconciled_registration)
    reconciled_contract.pop("service_state")
    assert validate_provider_registration_contract(reconciled_contract)[0] is True
    with pytest.raises(PermissionError, match="not eligible"):
        client.reconcile_provider_qualification(registration_id)


def test_crash_after_terminal_qualification_recovers_without_second_model_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SimulatedCrash(BaseException):
        pass

    observer = _RecoverableTerminalQualificationObserver()
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _registration(executable)
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations", registration_id, "REGISTERED_UNQUALIFIED", registration
    )
    original_stage = core.store.stage_provider_qualification_binding

    def crash_before_authority_stage(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise SimulatedCrash("power loss after Host terminal result")

    monkeypatch.setattr(
        core.store,
        "stage_provider_qualification_binding",
        crash_before_authority_stage,
    )
    with pytest.raises(SimulatedCrash, match="power loss"):
        client.qualify_provider(registration_id, executable)

    pending_registration = core.store.get("registrations", registration_id)
    assert pending_registration is not None
    assert pending_registration["service_state"] == "QUALIFICATION_STARTED"
    pending = [
        value
        for value in core.store.list_records("qualifications")
        if value["service_state"] == "EXECUTION_STARTED"
    ]
    assert len(pending) == 1
    qualification_id = str(pending[0]["start"]["id"]).removesuffix(":started")
    assert observer.external_model_requests == 1
    diagnostics = client.diagnostics()["provider_host"]
    assert diagnostics["qualification_recovery_ids"] == [qualification_id]
    assert diagnostics["provider_state"] == "QUALIFICATION_RECOVERY_REQUIRED"

    monkeypatch.setattr(
        core.store,
        "stage_provider_qualification_binding",
        original_stage,
    )
    recovered = client.qualify_provider(registration_id, executable)

    assert recovered["qualification"]["id"] == qualification_id
    assert observer.external_model_requests == 1
    assert core.store.get("registrations", registration_id)["service_state"] == (
        "QUALIFIED"
    )
    assert core.store.get("qualifications", qualification_id)["service_state"] == (
        "QUALIFIED"
    )
    repeated = client.qualify_provider(registration_id, executable)
    assert repeated == recovered
    assert observer.external_model_requests == 1


def test_lost_provider_bind_diagnostics_require_exact_reconciliation(
    tmp_path: Path,
) -> None:
    observer = _HostQualificationObserver(lose_first_bind_response=True)
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _registration(executable)
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations",
        registration_id,
        "REGISTERED_UNQUALIFIED",
        registration,
    )

    with pytest.raises(RuntimeError, match="binding is uncertain"):
        client.qualify_provider(registration_id, executable)

    status = client.diagnostics()["provider_host"]
    assert status["provider_state"] == "QUALIFICATION_UNCERTAIN"
    assert status["founder_action_required"] == (
        "RECONCILE_PROVIDER_QUALIFICATION"
    )
    assert status["qualification_reconciliation_required"] is True
    assert status["qualification_reconciliation_count"] == 1
    assert status["qualification_reconciliation_registration_ids"] == [
        registration_id
    ]

    client.reconcile_provider_qualification(registration_id)
    recovered = client.diagnostics()["provider_host"]
    assert recovered["qualification_reconciliation_required"] is False
    assert recovered["qualification_reconciliation_count"] == 0
    assert recovered["qualification_reconciliation_registration_ids"] == []
    assert recovered["provider_state"] != "QUALIFICATION_UNCERTAIN"
    assert recovered.get("founder_action_required") != (
        "RECONCILE_PROVIDER_QUALIFICATION"
    )


def test_crash_before_provider_bind_ack_leaves_non_executable_uncertain_state(
    tmp_path: Path,
) -> None:
    class SimulatedCrash(BaseException):
        pass

    observer = _HostQualificationObserver()

    def crash_after_durable_host_bind(
        registration: dict[str, Any], qualification: dict[str, Any]
    ) -> dict[str, Any]:
        observer.bound = {
            "registration_id": registration["trusted_registration_id"],
            "qualification_id": qualification["id"],
            "evidence_digest": qualification["evidence_digest"],
        }
        raise SimulatedCrash()

    observer.bind_qualified_provider = crash_after_durable_host_bind  # type: ignore[method-assign]
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _registration(executable)
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations",
        registration_id,
        "REGISTERED_UNQUALIFIED",
        registration,
    )

    with pytest.raises(SimulatedCrash):
        client.qualify_provider(registration_id, executable)
    uncertain = core.store.get("registrations", registration_id)
    assert uncertain is not None
    assert uncertain["service_state"] == "UNCERTAIN"


def test_subscription_registration_is_bounded_and_not_free(tmp_path: Path) -> None:
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"signed-fixture")
    registration = _registration(executable)

    assert validate_provider_registration_contract(registration)[0] is True
    assert registration["registration_schema_version"] == 4
    assert registration["pricing_authority"]["billing_mode"] == "included-subscription"
    assert registration["pricing_authority"]["marginally_free"] is False
    assert registration["pricing_authority"]["maximum_cost"] == 0.0
    assert registration["effort_levels"] == ["medium", "high"]
    assert registration["role_eligibility"] == ["builder", "repairer"]
    assert registration["capability_set"]["reviewer"] is False
    with pytest.raises(ValueError, match="medium and high"):
        create_provider_registration(
            "codex",
            executable,
            authorized_by="S-1-5-21-1000",
            executive_capabilities=["implementation", "testing"],
            project_types=["software"],
            effort_levels=["high", "medium"],
            pricing_authority=_pricing(),
            expected_version="codex-cli 0.146.0",
            model_allowlist=["gpt-5.6-sol"],
            model_revalidation_expires_at=(
                datetime.now(UTC) + timedelta(days=30)
            ).isoformat(),
            authentication_policy=_authentication_policy(),
            windows_authentication_binding={
                "principal_sid": "S-1-5-21-1000",
                "windows_session_id": 1,
                "profile_identity": r"C:\Users\Founder",
                "profile_digest": "a" * 64,
                "source": "authenticated-named-pipe-client-process",
            },
            usage_policy=_usage_policy(),
            authenticode_binding={
                "status": "Valid",
                "publisher_subject": 'CN="OpenAI OpCo, LLC"',
                "certificate_thumbprint": (
                    "0B7C30C11BF7250EC1ECD3254AC781D9E13D62F8"
                ),
                "source": "windows-authenticode",
            },
            subscription_account_binding={
                "authentication_method": "chatgpt-subscription",
                "plan_type": "plus",
                "account_identity_digest": "c" * 64,
                "source": "authority-public-codex-probe",
                "observed_at": datetime.now(UTC).isoformat(),
            },
            model_capability_binding={
                "models": [
                    {
                        "model_id": "gpt-5.6-sol",
                        "supported_reasoning_efforts": ["medium", "high"],
                    }
                ],
                "source": "authority-public-codex-probe",
                "observed_at": datetime.now(UTC).isoformat(),
            },
        )


def test_one_shot_registration_persists_each_response_before_id_use(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    client = _OneShotRegistrationClient()
    declaration = registration_declaration(
        expected_executable_sha256=hashlib.sha256(b"fixture").hexdigest(),
        expected_executable_size=len(b"fixture"),
        expected_version="codex-cli 0.146.0",
        keeper_launch_budget=20,
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )

    result = register_and_qualify_once(
        cast(Any, client), executable, tmp_path / "responses", declaration
    )

    assert client.register_calls == 1
    assert client.qualify_calls == 1
    assert result["registration_id"] == "registration-1"
    assert result["qualification_id"] == "qualification-1"
    assert json.loads(
        (tmp_path / "responses" / "registration-response.json").read_text(
            encoding="utf-8"
        )
    ) == client.registration_response
    assert json.loads(
        (tmp_path / "responses" / "qualification-response.json").read_text(
            encoding="utf-8"
        )
    ) == client.qualification_response
    assert client.declaration is not None
    assert client.declaration["effort_levels"] == ["medium", "high"]
    assert client.declaration["expected_executable_sha256"] == (
        hashlib.sha256(b"fixture").hexdigest()
    )
    assert client.declaration["expected_executable_size"] == len(b"fixture")
    assert client.declaration["expected_version"] == "codex-cli 0.146.0"
    assert client.declaration["pricing_authority"]["billing_mode"] == (
        "included-subscription"
    )


def test_one_shot_registration_never_retries_or_qualifies_without_persisted_id(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    client = _OneShotRegistrationClient(
        registration_response={"registration": {"public": True}}
    )

    with pytest.raises(RuntimeError, match="persisted.*no registration ID"):
        register_and_qualify_once(
            cast(Any, client),
            executable,
            tmp_path / "responses",
            registration_declaration(
                expected_executable_sha256=hashlib.sha256(b"fixture").hexdigest(),
                expected_executable_size=len(b"fixture"),
                expected_version="codex-cli 0.146.0",
                keeper_launch_budget=20,
            ),
        )

    assert client.register_calls == 1
    assert client.qualify_calls == 0
    assert (tmp_path / "responses" / "registration-response.json").is_file()


def test_one_shot_registration_claim_prevents_duplicate_mutation(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    client = _OneShotRegistrationClient()
    declaration = registration_declaration(
        expected_executable_sha256=hashlib.sha256(b"fixture").hexdigest(),
        expected_executable_size=len(b"fixture"),
        expected_version="codex-cli 0.146.0",
        keeper_launch_budget=20,
    )
    output = tmp_path / "responses"
    register_and_qualify_once(
        cast(Any, client), executable, output, declaration
    )

    with pytest.raises(FileExistsError, match="already claimed"):
        register_and_qualify_once(
            cast(Any, client), executable, output, declaration
        )

    assert client.register_calls == 1
    assert client.qualify_calls == 1
    claim = json.loads(
        (output / "registration-attempt.claim.json").read_text(encoding="utf-8")
    )
    assert claim == {
        "schema_version": 1,
        "operation": "codex-register-and-qualify-once",
        "state": "CLAIMED",
    }


def test_one_shot_qualification_reconciliation_persists_exact_response(
    tmp_path: Path,
) -> None:
    class ReconciliationClient:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.response = {
                "registration": {
                    "trusted_registration_id": "registration-1",
                },
                "qualification": {
                    "id": "qualification-1",
                    "registration_id": "registration-1",
                },
                "reconciled": True,
                "reconciled_at": "2026-08-02T12:00:00+00:00",
            }

        def reconcile_provider_qualification(
            self, registration_id: str
        ) -> dict[str, Any]:
            self.calls.append(registration_id)
            return dict(self.response)

    client = ReconciliationClient()
    output = tmp_path / "reconcile"

    result = reconcile_qualification_once(
        cast(Any, client), "registration-1", output
    )

    assert client.calls == ["registration-1"]
    assert result == {
        "registration_id": "registration-1",
        "qualification_id": "qualification-1",
        "reconciliation_response": str(
            (output / "qualification-reconciliation-response.json").resolve()
        ),
    }
    assert json.loads(
        (output / "qualification-reconciliation-response.json").read_text(
            encoding="utf-8"
        )
    ) == client.response
    assert json.loads(
        (output / "qualification-reconciliation.claim.json").read_text(
            encoding="utf-8"
        )
    ) == {
        "schema_version": 1,
        "operation": "codex-reconcile-qualification-once",
        "registration_id": "registration-1",
        "state": "CLAIMED",
    }

    with pytest.raises(FileExistsError, match="already claimed"):
        reconcile_qualification_once(
            cast(Any, client), "registration-1", output
        )
    assert client.calls == ["registration-1"]


def test_qualification_reconciliation_persists_malformed_response_before_reject(
    tmp_path: Path,
) -> None:
    class MalformedClient:
        response = {
            "registration": {"trusted_registration_id": "registration-other"},
            "qualification": {
                "id": "qualification-other",
                "registration_id": "registration-other",
            },
            "reconciled": True,
        }

        def reconcile_provider_qualification(
            self, registration_id: str
        ) -> dict[str, Any]:
            assert registration_id == "registration-1"
            return dict(self.response)

    output = tmp_path / "malformed"
    with pytest.raises(RuntimeError, match="persisted.*binding is invalid"):
        reconcile_qualification_once(
            cast(Any, MalformedClient()), "registration-1", output
        )

    assert json.loads(
        (output / "qualification-reconciliation-response.json").read_text(
            encoding="utf-8"
        )
    ) == MalformedClient.response


def test_qualification_reconciliation_cli_requires_explicit_apply(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        reconciliation_main(
            [
                "--registration-id",
                "registration-1",
                "--output-directory",
                str(tmp_path / "unused"),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "apply_required": True,
        "operation": "codex-reconcile-qualification-once",
        "registration_id": "registration-1",
    }
    assert not (tmp_path / "unused").exists()


def test_authority_service_entrypoint_exposes_reconciliation_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from keeper.authority_service.service_main import main as authority_main

    with pytest.raises(SystemExit) as stopped:
        authority_main(["codex-reconcile-qualification", "--help"])

    assert stopped.value.code == 0
    help_text = capsys.readouterr().out
    assert "codex-reconcile-qualification" in help_text
    assert "--registration-id" in help_text
    assert "--output-directory" in help_text
    assert "--apply" in help_text


def test_subscription_registration_requires_and_forwards_reviewed_identity(
    tmp_path: Path,
) -> None:
    class CapturingObserver:
        def __init__(self) -> None:
            self.arguments: dict[str, Any] | None = None

        def register_provider(
            self,
            provider_id: str,
            executable: Path,
            client_sid: str,
            **arguments: Any,
        ) -> dict[str, Any]:
            self.arguments = {
                "provider_id": provider_id,
                "executable": executable,
                "client_sid": client_sid,
                **arguments,
            }
            raise RuntimeError("captured before observer execution")

    executable = (tmp_path / "codex.exe").resolve()
    executable.write_bytes(b"fixture")
    observer = CapturingObserver()
    core = AuthorityServiceCore(
        tmp_path / "authority",
        observer=cast(TrustedObserver, observer),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    client = AuthorityServiceClient(
        test_transport=lambda request: core.dispatch(request, "S-1-5-21-1000")
    )
    declaration = registration_declaration(
        expected_executable_sha256=hashlib.sha256(b"fixture").hexdigest(),
        expected_executable_size=len(b"fixture"),
        expected_version="codex-cli 0.146.0",
        keeper_launch_budget=20,
    )

    with pytest.raises(RuntimeError, match="captured before observer execution"):
        client.register_provider("codex", executable, **declaration)

    assert observer.arguments is not None
    assert observer.arguments["expected_executable_sha256"] == (
        hashlib.sha256(b"fixture").hexdigest()
    )
    assert observer.arguments["expected_executable_size"] == len(b"fixture")
    claims = core.store.list_records("registrations")
    assert len(claims) == 1
    assert claims[0]["service_state"] == "REGISTRATION_STARTED"
    assert claims[0]["kind"] == "provider_registration_started"


def test_crash_after_terminal_registration_probe_recovers_without_second_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SimulatedCrash(BaseException):
        pass

    class RecoverableRegistrationObserver:
        def __init__(self) -> None:
            self.external_probe_calls = 0
            self.registration: dict[str, Any] | None = None

        def register_provider(
            self,
            provider_id: str,
            executable: Path,
            client_sid: str,
            **arguments: Any,
        ) -> dict[str, Any]:
            assert provider_id == "codex"
            assert client_sid == "S-1-5-21-1000"
            if arguments["recovering_registration"] is not True:
                self.external_probe_calls += 1
                value = _registration(executable)
                value["trusted_registration_id"] = arguments[
                    "planned_registration_id"
                ]
                value["configuration_digest"] = (
                    canonical_provider_registration_digest(value)
                )
                self.registration = value
            assert self.registration is not None
            return dict(self.registration)

        def validate_registered_executable(
            self,
            registration: dict[str, Any],
            client_executable_handle: int,
        ) -> None:
            assert registration == self.registration
            assert client_executable_handle > 0

    executable = (tmp_path / "codex.exe").resolve()
    executable.write_bytes(b"fixture")
    observer = RecoverableRegistrationObserver()
    core = AuthorityServiceCore(
        tmp_path / "authority",
        observer=cast(TrustedObserver, observer),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    client = AuthorityServiceClient(
        test_transport=lambda request: core.dispatch(request, "S-1-5-21-1000")
    )
    declaration = registration_declaration(
        expected_executable_sha256=hashlib.sha256(b"fixture").hexdigest(),
        expected_executable_size=len(b"fixture"),
        expected_version="codex-cli 0.146.0",
        keeper_launch_budget=20,
    )
    original_transition = core.store.transition

    def crash_before_registration_publish(
        table: str,
        identifier: str,
        expected_state: str,
        state: str,
        payload: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        if (
            table == "registrations"
            and expected_state == "REGISTRATION_STARTED"
            and state == "REGISTERED_UNQUALIFIED"
        ):
            raise SimulatedCrash("power loss after registration probe")
        original_transition(
            table,
            identifier,
            expected_state,
            state,
            payload,
            **kwargs,
        )

    monkeypatch.setattr(core.store, "transition", crash_before_registration_publish)
    with pytest.raises(SimulatedCrash, match="power loss"):
        client.register_provider("codex", executable, **declaration)

    claims = core.store.list_records("registrations")
    assert len(claims) == 1
    assert claims[0]["service_state"] == "REGISTRATION_STARTED"
    assert observer.external_probe_calls == 1
    status = client.diagnostics()["provider_host"]
    assert status["registration_recovery_pending_count"] == 1
    assert status["provider_state"] == "REGISTRATION_RECOVERY_REQUIRED"

    monkeypatch.setattr(core.store, "transition", original_transition)
    retry_declaration = registration_declaration(
        expected_executable_sha256=hashlib.sha256(b"fixture").hexdigest(),
        expected_executable_size=len(b"fixture"),
        expected_version="codex-cli 0.146.0",
        keeper_launch_budget=20,
    )
    recovered = client.register_provider(
        "codex", executable, **retry_declaration
    )

    assert recovered["registration_id"] == claims[0]["start"]["registration_id"]
    assert observer.external_probe_calls == 1
    stored = core.store.get("registrations", recovered["registration_id"])
    assert stored is not None
    assert stored["service_state"] == "REGISTERED_UNQUALIFIED"
    repeated = client.register_provider(
        "codex",
        executable,
        **registration_declaration(
            expected_executable_sha256=hashlib.sha256(b"fixture").hexdigest(),
            expected_executable_size=len(b"fixture"),
            expected_version="codex-cli 0.146.0",
            keeper_launch_budget=20,
        ),
    )
    assert repeated == recovered
    assert observer.external_probe_calls == 1
    assert core.store.list_records("qualifications") == []

    incomplete = dict(declaration)
    incomplete.pop("expected_executable_size")
    with pytest.raises(ValueError, match="declaration is incomplete"):
        client.register_provider("codex", executable, **incomplete)


def test_subscription_registration_missing_locked_handle_has_zero_durable_effect(
    tmp_path: Path,
) -> None:
    executable = (tmp_path / "codex.exe").resolve()
    executable.write_bytes(b"fixture")
    captured: list[Request] = []
    capture_client = AuthorityServiceClient(
        test_transport=lambda request: captured.append(request) or {}
    )
    capture_client.register_provider(
        "codex",
        executable,
        **registration_declaration(
            expected_executable_sha256=hashlib.sha256(b"fixture").hexdigest(),
            expected_executable_size=len(b"fixture"),
            expected_version="codex-cli 0.146.0",
            keeper_launch_budget=20,
        ),
    )
    assert len(captured) == 1
    payload = dict(captured[0].payload)
    payload.pop("client_executable_handle")

    class ForbiddenObserver:
        def register_provider(self, *args: object, **kwargs: object) -> dict[str, Any]:
            del args, kwargs
            raise AssertionError("observer must not run without a locked handle")

    core = AuthorityServiceCore(
        tmp_path / "authority",
        observer=cast(TrustedObserver, ForbiddenObserver()),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    with pytest.raises(ValueError, match="payload fields are invalid"):
        core.dispatch(
            Request.create(Operation.REGISTER_PROVIDER, payload),
            "S-1-5-21-1000",
        )
    assert core.store.list_records("registrations") == []
    assert core.store.list_records("qualifications") == []


def test_public_response_persistence_refuses_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "response.json"
    persist_public_response(destination, {"first": True})

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        persist_public_response(destination, {"second": True})

    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "first": True
    }


def test_subscription_registration_expiry_is_fail_closed(tmp_path: Path) -> None:
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"signed-fixture")
    registration = _registration(executable)
    registration["model_revalidation_expires_at"] = (
        datetime.now(UTC) - timedelta(seconds=1)
    ).isoformat()
    registration["configuration_digest"] = canonical_provider_registration_digest(
        registration
    )

    valid, detail = validate_provider_registration_contract(registration)

    assert valid is False
    assert "invalid" in detail.casefold()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("api_billing_authorized", True),
        ("paid_fallback_authorized", True),
        ("credit_purchase_authorized", True),
        ("provider_switch_authorized", True),
        ("account_switch_authorized", True),
        ("capacity_bounded", False),
        ("marginally_free", True),
    ],
)
def test_contradictory_subscription_pricing_rejects(
    field: str, value: object
) -> None:
    pricing = _pricing()
    pricing[field] = value
    with pytest.raises(ValueError, match="contradictory"):
        validate_subscription_pricing_authority(pricing)


def test_codex_command_binds_model_effort_and_ignores_configuration(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "founder-profile" / "unreadable" / "codex.exe"
    assert not executable.exists()
    schema = tmp_path / "schema.json"
    schema.write_text("{}", encoding="utf-8")
    output = tmp_path / "output.json"
    medium = build_codex_exec_command(
        executable,
        model_id="gpt-5.6-sol",
        reasoning_level="medium",
        schema_path=schema,
        output_path=output,
        prompt="authority prompt",
    )
    high = build_codex_exec_command(
        executable,
        model_id="gpt-5.6-sol",
        reasoning_level="high",
        schema_path=schema,
        output_path=output,
        prompt="authority prompt",
    )
    assert "--ignore-user-config" in medium
    assert "--skip-git-repo-check" in medium
    assert medium[0] == str(executable)
    assert medium[medium.index("--model") + 1] == "gpt-5.6-sol"
    assert 'model_reasoning_effort="medium"' in medium
    assert 'model_reasoning_effort="high"' in high
    with pytest.raises(PermissionError, match="effort"):
        build_codex_exec_command(
            executable,
            model_id="gpt-5.6-sol",
            reasoning_level="low",
            schema_path=schema,
            output_path=output,
            prompt="authority prompt",
        )


def test_codex_environment_preserves_profile_but_removes_api_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    codex_home = tmp_path / "Founder" / ".codex"

    def forbidden_resolve(self: Path, strict: bool = False) -> Path:
        del self, strict
        raise PermissionError("service identity profile access denied")

    monkeypatch.setattr(Path, "resolve", forbidden_resolve)
    value = sanitized_codex_environment(
        {
            "USERPROFILE": str(tmp_path),
            "LOCALAPPDATA": str(tmp_path / "Local"),
            "PATH": r"C:\Windows\System32",
            "OPENAI_API_KEY": "must-not-survive",
            "CODEX_API_KEY": "must-not-survive",
            "UNRELATED_SECRET": "must-not-survive",
        },
        codex_home=codex_home,
    )
    assert value["USERPROFILE"] == str(tmp_path)
    assert value["CODEX_HOME"] == str(codex_home)
    assert not any("API_KEY" in key or "SECRET" in key for key in value)


def test_prelaunch_command_failure_cannot_strand_active_execution_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    exchange = tmp_path / "exchange"
    evidence = exchange / "evidence"
    workspace = exchange / "workspace"
    evidence.mkdir(parents=True)
    workspace.mkdir()
    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture")
    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        evidence,
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
    )
    service._local.token = 42
    executable = Path(r"C:\FounderProfile\unreadable\codex.exe")
    prompt = "Authority-owned prompt"
    output_schema = authority_provider_output_schema(
        "builder", provider_input_required=False
    )
    attempt: dict[str, Any] = {
        "id": "provider-attempt:prelaunch-failure",
        "prompt_path": str(exchange / "prompt.txt"),
        "stdout_path": str(exchange / "stdout.json"),
        "stderr_path": str(exchange / "stderr.log"),
        "workspace": str(workspace),
        "authority_prompt": prompt,
        "prompt_digest": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "output_schema_digest": structured_digest(output_schema),
        "provider_input": None,
        "provider_input_digest": None,
        "provider_input_required": False,
        "role": "builder",
        "model_id": "gpt-5.6-sol",
        "reasoning_level": "medium",
        "environment": {},
        "timeout_seconds": 30,
    }
    registration = {
        "registration_schema_version": 4,
        "logical_provider_id": "codex",
        "launcher_path": str(executable),
        "canonical_executable_path": str(executable),
        "model_allowlist": ["gpt-5.6-sol"],
        "effort_levels": ["medium", "high"],
        "script_path": None,
    }

    def fail_without_access(*args: object, **kwargs: object) -> list[str]:
        del args, kwargs
        raise PermissionError("service identity executable access denied")

    monkeypatch.setattr(
        observer_module, "build_codex_exec_command", fail_without_access
    )
    with pytest.raises(PermissionError, match="service identity executable"):
        service.execute_provider(cast(Any, registration), attempt, lambda value: None)

    assert service._active_cancellations == {}


def test_authority_prestart_failure_becomes_durably_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observer = _CodexObserver()
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations", registration_id, "QUALIFIED", registration
    )
    reserved = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="prestart-uncertain",
        )
    )

    def fail_before_start(
        registration_value: dict[str, Any],
        attempt_value: dict[str, Any],
        on_started: Any,
    ) -> ExecutionObservation:
        del registration_value, attempt_value, on_started
        observer.execute_calls += 1
        raise PermissionError(
            "deterministic prelaunch failure before start observation"
        )

    monkeypatch.setattr(observer, "execute_provider", fail_before_start)
    attempt_id = str(reserved["attempt_id"])
    with pytest.raises(PermissionError, match="before start observation"):
        client.execute_provider(attempt_id)

    assert observer.execute_calls == 1
    stored = client.query_state("attempts", attempt_id)["record"]
    assert stored["service_state"] == "UNCERTAIN"
    assert stored["launch_claim_state"] == "UNCERTAIN"
    assert stored["uncertainty_kind"] == (
        "PROVIDER_START_OBSERVATION_FAILED"
    )
    signed = dict(stored)
    signed.pop("service_state")
    assert core.keys.verify("provider-launch-claim", signed)
    with pytest.raises(PermissionError, match="not reserved"):
        client.execute_provider(attempt_id)
    assert observer.execute_calls == 1


def test_public_probe_exchange_preserves_exact_sequential_requests() -> None:
    exchange = app_server_probe_exchange()
    assert [response_id for _, response_id in exchange] == [1, None, 2, 3, 4, 5]
    assert "".join(line + "\n" for line, _ in exchange) == app_server_probe_input()
    assert [json.loads(line).get("id") for line, _ in exchange] == [
        1,
        None,
        2,
        3,
        4,
        5,
    ]


def test_public_app_server_probe_reports_chatgpt_and_bounded_usage() -> None:
    responses = [
        json.dumps({"id": 1, "result": {"platformOs": "windows"}}),
        json.dumps(
            {
                "id": 2,
                "result": {
                    "account": {
                        "type": "chatgpt",
                        "planType": "plus",
                        "email": "founder@example.invalid",
                    }
                },
            }
        ),
        json.dumps(
            {
                "id": 3,
                "result": {
                    "data": [
                        {
                            "model": "gpt-5.6-sol",
                            "hidden": False,
                            "supportedReasoningEfforts": ["medium", "high"],
                        }
                    ]
                },
            }
        ),
        json.dumps(
            {
                "id": 4,
                "result": {
                    "rateLimits": {
                        "limitId": "codex",
                        "primary": {
                            "usedPercent": 72,
                            "windowDurationMins": 10080,
                            "resetsAt": 2_000_000_000,
                        },
                        "rateLimitReachedType": None,
                    }
                },
            }
        ),
        json.dumps({"id": 5, "result": {"summary": {}}}),
    ]
    result = parse_codex_app_server_probe(
        responses, model_allowlist=["gpt-5.6-sol"]
    )
    assert result["authentication_method"] == "chatgpt-subscription"
    assert result["plan_type"] == "plus"
    assert len(result["account_identity_digest"]) == 64
    assert result["model_capabilities"] == [
        {
            "model_id": "gpt-5.6-sol",
            "supported_reasoning_efforts": ["medium", "high"],
        }
    ]
    observation = result["usage_observation"]
    assert observation["capacity_state"] == "OBSERVED"
    assert observation["buckets"][0]["used_percent"] == 72.0
    assert observation["credits_ignored"] is True


def test_public_app_server_probe_accepts_chatgpt_pro() -> None:
    responses = [
        json.dumps({"id": 1, "result": {"platformOs": "windows"}}),
        json.dumps(
            {
                "id": 2,
                "result": {
                    "account": {
                        "type": "chatgpt",
                        "planType": "pro",
                        "email": "founder@example.invalid",
                    }
                },
            }
        ),
        json.dumps(
            {
                "id": 3,
                "result": {
                    "data": [
                        {
                            "model": "gpt-5.6-sol",
                            "hidden": False,
                            "supportedReasoningEfforts": ["medium", "high"],
                        }
                    ]
                },
            }
        ),
        json.dumps(
            {
                "id": 4,
                "result": {
                    "rateLimits": {
                        "limitId": "codex",
                        "primary": {
                            "usedPercent": 0,
                            "windowDurationMins": 10080,
                            "resetsAt": 2_000_000_000,
                        },
                    }
                },
            }
        ),
    ]
    result = parse_codex_app_server_probe(
        responses, model_allowlist=["gpt-5.6-sol"]
    )
    assert result["plan_type"] == "pro"


def test_subscription_account_binding_accepts_only_plus_or_pro() -> None:
    base = {
        "authentication_method": "chatgpt-subscription",
        "plan_type": "pro",
        "account_identity_digest": "a" * 64,
        "source": "authority-public-codex-probe",
        "observed_at": datetime.now(UTC).isoformat(),
    }
    assert validate_subscription_account_binding(base) == base
    for plan_type in ("free", "team", "business", "enterprise", ""):
        with pytest.raises(ValueError, match="account binding"):
            validate_subscription_account_binding(
                {**base, "plan_type": plan_type}
            )


def test_public_probe_rejects_unknown_subscription_plan() -> None:
    responses = [
        json.dumps({"id": 1, "result": {"platformOs": "windows"}}),
        json.dumps(
            {"id": 2, "result": {"account": {"type": "chatgpt"}}}
        ),
        json.dumps(
            {
                "id": 3,
                "result": {
                    "data": [{"model": "gpt-5.6-sol", "hidden": False}]
                },
            }
        ),
        json.dumps({"id": 4, "result": {"rateLimits": {}}}),
    ]

    with pytest.raises(PermissionError, match="plan"):
        parse_codex_app_server_probe(
            responses, model_allowlist=["gpt-5.6-sol"]
        )


def test_public_probe_rejects_unqualified_effort_declaration() -> None:
    responses = [
        json.dumps({"id": 1, "result": {"platformOs": "windows"}}),
        json.dumps(
            {
                "id": 2,
                "result": {
                    "account": {
                        "type": "chatgpt",
                        "planType": "plus",
                        "email": "founder@example.invalid",
                    }
                },
            }
        ),
        json.dumps(
            {
                "id": 3,
                "result": {
                    "data": [
                        {
                            "model": "gpt-5.6-sol",
                            "hidden": False,
                            "supportedReasoningEfforts": [
                                "low",
                                "medium",
                            ],
                        }
                    ]
                },
            }
        ),
        json.dumps({"id": 4, "result": {"rateLimits": {}}}),
    ]
    with pytest.raises(PermissionError, match="reasoning efforts"):
        parse_codex_app_server_probe(
            responses, model_allowlist=["gpt-5.6-sol"]
        )


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"cancelled": True}, "CANCELLED"),
        ({"timed_out": True}, "TIMEOUT"),
        ({"stderr": "HTTP 429: rate limit reached"}, "SUBSCRIPTION_EXHAUSTED"),
        ({"stderr": "not logged in; login required"}, "AUTHENTICATION_FAILED"),
        ({"stderr": "connection reset"}, "NETWORK_FAILURE"),
        ({"exit_status": 1}, "PROVIDER_ERROR"),
        ({"output_valid": False}, "INVALID_OUTPUT"),
        ({}, "COMPLETED"),
    ],
)
def test_codex_failure_classification_is_fail_closed(
    kwargs: dict[str, object], expected: str
) -> None:
    arguments: dict[str, object] = {
        "exit_status": 0,
        "timed_out": False,
        "cancelled": False,
        "stderr": "",
        "structured_events": "",
        "output_valid": True,
    }
    arguments.update(kwargs)
    assert classify_codex_execution_failure(**cast(Any, arguments)) == expected


def test_authority_output_schema_rejects_extra_or_missing_fields() -> None:
    schema = authority_provider_output_schema(
        "builder", provider_input_required=False
    )
    assert validate_value_against_schema(
        {"status": "completed", "files_changed": ["result.txt"]}, schema
    )
    assert not validate_value_against_schema(
        {
            "status": "completed",
            "files_changed": ["result.txt"],
            "untrusted": True,
        },
        schema,
    )
    assert not validate_value_against_schema(
        {"status": "completed"}, schema
    )


def _reservation(
    client: AuthorityServiceClient,
    tmp_path: Path,
    registration_id: str,
    *,
    effort: str,
    model_id: str = "gpt-5.6-sol",
    suffix: str,
) -> dict[str, object]:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    evidence = tmp_path / "evidence"
    evidence.mkdir(exist_ok=True)
    prompt = evidence / f"prompt-{suffix}.json"
    prompt.write_text('{"task":"safe"}', encoding="utf-8")
    workspace_path = str(workspace.resolve())
    return {
        **_launch_authority(client, f"project-{suffix}"),
        "registration_id": registration_id,
        "keeper_run_id": f"run-{suffix}",
        "task_id": f"task-{suffix}",
        "stage_id": "builder",
        "role": "builder",
        "attempt_number": 1,
        "provider_run_id": f"provider-{suffix}",
        "provider_instance_id": "codex-session",
        "evidence_path": str((evidence / f"result-{suffix}.json").resolve()),
        "prompt_path": str(prompt.resolve()),
        "stdout_path": str((evidence / f"stdout-{suffix}.json").resolve()),
        "stderr_path": str((evidence / f"stderr-{suffix}.log").resolve()),
        "workspace": workspace_path,
        "workflow_id": f"workflow-{suffix}",
        "work_item_id": f"work-item-{suffix}",
        "assignment_id": f"assignment-{suffix}",
        "provider_account_id": "chatgpt-subscription:" + "c" * 64,
        "workspace_identity": hashlib.sha256(
            workspace_path.casefold().encode("utf-8")
        ).hexdigest(),
        "workspace_reservation_id": f"workspace-reservation-{suffix}",
        "timeout_seconds": 30,
        "reasoning_level": effort,
        "model_id": model_id,
        "prompt_digest": hashlib.sha256(prompt.read_bytes()).hexdigest(),
        "environment": {},
    }


def test_authority_rejects_low_and_model_substitution_before_attempt(
    tmp_path: Path,
) -> None:
    core, client = _codex_service(tmp_path, _CodexObserver())
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations", registration_id, "QUALIFIED", registration
    )

    with pytest.raises(PermissionError, match="effort"):
        client.reserve_attempt(
            **_reservation(
                client,
                tmp_path,
                registration_id,
                effort="low",
                suffix="low",
            )
        )
    with pytest.raises(PermissionError, match="model"):
        client.reserve_attempt(
            **_reservation(
                client,
                tmp_path,
                registration_id,
                effort="medium",
                model_id="gpt-unknown",
                suffix="model",
            )
        )
    valid = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="valid",
        )
    )["attempt"]
    assert valid["model_id"] == "gpt-5.6-sol"
    assert valid["reasoning_level"] == "medium"
    assert valid["authority_prompt"] == '{"task":"safe"}'
    assert valid["pricing_authority_digest"]


def test_authority_rejects_authoring_only_registration_for_reviewer(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver()
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    request = _reservation(
        client,
        tmp_path,
        registration_id,
        effort="medium",
        suffix="review-role",
    )
    request["role"] = "reviewer"
    request["stage_id"] = "reviewer"
    request["provider_input_required"] = True

    with pytest.raises(PermissionError, match="role"):
        client.reserve_attempt(**request)

    assert observer.execute_calls == 0
    assert core.store.list_records("attempts") == []


def test_service_exchange_reader_rejects_privileged_prompt_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    exchange = tmp_path / "exchange"
    evidence = exchange / "evidence"
    evidence.mkdir(parents=True)
    inside = exchange / "prompt.json"
    inside.write_text("safe", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    observer = object.__new__(ServiceProviderObserver)
    observer.allowed_evidence_root = evidence.resolve()
    observer._local = threading.local()
    observer._local.client_token = 42
    inside_client_identity = False

    @contextmanager
    def client_identity(token: int):  # type: ignore[no-untyped-def]
        nonlocal inside_client_identity
        assert token == 42
        inside_client_identity = True
        try:
            yield
        finally:
            inside_client_identity = False

    real_open = os.open

    def checked_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
    ) -> int:
        assert inside_client_identity is True
        return real_open(path, flags, mode)

    monkeypatch.setattr(observer_module, "impersonate_token", client_identity)
    monkeypatch.setattr(os, "open", checked_open)

    path, content = observer.read_exchange_file(inside, "prompt", 1024)
    assert path == inside.resolve()
    assert content == b"safe"
    with pytest.raises(PermissionError, match="outside"):
        observer.read_exchange_file(outside, "prompt", 1024)

    alias = exchange / "alias.txt"
    try:
        os.symlink(outside, alias)
    except OSError:
        pytest.skip("Windows symlink privilege is unavailable")
    with pytest.raises(PermissionError, match="alias"):
        observer.read_exchange_file(alias, "prompt", 1024)


def test_supported_reservation_rejects_prompt_outside_exchange_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    exchange = tmp_path / "exchange"
    evidence = exchange / "evidence"
    evidence.mkdir(parents=True)
    reader = object.__new__(ServiceProviderObserver)
    reader.allowed_evidence_root = evidence.resolve()
    reader._local = threading.local()
    reader._local.client_token = 42

    @contextmanager
    def client_identity(token: int):  # type: ignore[no-untyped-def]
        assert token == 42
        yield

    monkeypatch.setattr(observer_module, "impersonate_token", client_identity)

    class _ConfiningObserver(_CodexObserver):
        def read_exchange_file(
            self, value: object, label: str, maximum_bytes: int
        ) -> tuple[Path, bytes]:
            return reader.read_exchange_file(value, label, maximum_bytes)

    observer = _ConfiningObserver()
    core, client = _codex_service(tmp_path / "authority", observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)

    with pytest.raises(PermissionError, match="outside"):
        client.reserve_attempt(
            **_reservation(
                client,
                tmp_path,
                registration_id,
                effort="medium",
                suffix="outside-prompt",
            )
        )

    assert observer.execute_calls == 0
    assert core.store.list_records("attempts") == []
    with pytest.raises(PermissionError, match="local path"):
        reader.read_exchange_file(
            r"\\example.invalid\share\prompt.json", "prompt", 1024
        )
def test_expired_registration_rejects_after_reservation_before_execution(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver()
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    reserved = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="expires-before-execute",
        )
    )
    expired = dict(registration)
    expired["model_revalidation_expires_at"] = (
        datetime.now(UTC) - timedelta(seconds=1)
    ).isoformat()
    expired["configuration_digest"] = canonical_provider_registration_digest(expired)
    core.store.transition(
        "registrations", registration_id, "QUALIFIED", "QUALIFIED", expired
    )

    with pytest.raises(PermissionError, match="no longer valid"):
        client.execute_provider(str(reserved["attempt_id"]))

    assert observer.execute_calls == 0
    state = client.query_state("attempts", str(reserved["attempt_id"]))
    assert state["record"]["service_state"] == "RESERVED"


def _bind_fake_founder_identity(
    monkeypatch: pytest.MonkeyPatch,
    observer_module: Any,
    profile: Path,
    *,
    sid: str = "S-1-5-21-1000",
) -> None:
    monkeypatch.setattr(observer_module, "require_impersonation_level", lambda token: 2)
    monkeypatch.setattr(observer_module, "token_user_sid_string", lambda token: sid)
    monkeypatch.setattr(observer_module, "token_session_id", lambda token: 1)
    monkeypatch.setattr(
        observer_module,
        "windows_session_is_active",
        lambda session: WindowsSessionQueryResult(
            WindowsSessionQueryStatus.ACTIVE, state=0
        ),
    )
    monkeypatch.setattr(
        observer_module,
        "authenticated_client_environment",
        lambda token: {"USERPROFILE": str(profile), "PATH": str(profile.parent)},
    )
    monkeypatch.setattr(
        observer_module,
        "authenticated_client_profile_path",
        lambda token, value: str(Path(value).resolve(strict=True)),
    )

    @contextmanager
    def profile_primary(  # type: ignore[no-untyped-def]
        token: int,
    ):
        assert token == 86
        yield 84

    @contextmanager
    def client_identity(token: int):  # type: ignore[no-untyped-def]
        del token
        yield

    @contextmanager
    def restricted(token: int):  # type: ignore[no-untyped-def]
        del token
        yield 85

    monkeypatch.setattr(
        observer_module, "authenticated_profile_primary_token", profile_primary
    )
    monkeypatch.setattr(observer_module, "impersonate_token", client_identity)

    @contextmanager
    def process_identity(
        value: object, *, expected_sid: str
    ) -> Iterator[int]:
        del value
        assert expected_sid == "S-1-5-21-1000"
        yield 42

    monkeypatch.setattr(
        observer_module,
        "authenticated_client_process_impersonation_token",
        process_identity,
    )
    monkeypatch.setattr(
        observer_module, "profile_restricted_primary_token", restricted
    )


def test_codex_execution_identity_rejects_sid_session_and_token_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture-not-a-real-credential")
    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
    )
    service._local.client_token = 42
    _attach_fake_client_process_binding(service)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    profile = tmp_path / "Founder"
    profile.mkdir()
    registration = _registration(executable)
    binding = cast(dict[str, object], registration["windows_authentication_binding"])
    binding.update(
        {
            "profile_identity": str(profile.resolve()),
            "profile_digest": hashlib.sha256(
                str(profile.resolve()).casefold().encode("utf-8")
            ).hexdigest(),
        }
    )
    signature = cast(dict[str, object], registration["authenticode_binding"])
    monkeypatch.setattr(
        observer_module, "authenticode_identity", lambda path: dict(signature)
    )
    _bind_fake_founder_identity(monkeypatch, observer_module, profile)
    monkeypatch.setattr(
        observer_module, "token_user_sid_string", lambda token: "S-1-5-21-wrong"
    )
    with pytest.raises(PermissionError, match="SID is mismatched"):
        with service._codex_execution_identity(registration):
            pass

    monkeypatch.setattr(
        observer_module, "token_user_sid_string", lambda token: "S-1-5-21-1000"
    )
    monkeypatch.setattr(
        observer_module,
        "windows_session_is_active",
        lambda session: WindowsSessionQueryResult(
            WindowsSessionQueryStatus.INACTIVE, state=4
        ),
    )
    with pytest.raises(PermissionError, match="not active"):
        with service._codex_execution_identity(registration):
            pass

    monkeypatch.setattr(
        observer_module,
        "windows_session_is_active",
        lambda session: WindowsSessionQueryResult(
            WindowsSessionQueryStatus.ACTIVE, state=0
        ),
    )

    def fail_token(token: int) -> str:
        del token
        raise PermissionError("token acquisition failed")

    monkeypatch.setattr(observer_module, "token_user_sid_string", fail_token)
    with pytest.raises(PermissionError, match="token acquisition failed"):
        with service._codex_execution_identity(registration):
            pass


def test_client_profile_uses_bounded_pipe_wts_only_for_service_access_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture-not-a-real-credential")
    profile = tmp_path / "Founder"
    profile.mkdir()
    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
    )
    service._local.client_token = 42
    _attach_fake_client_process_binding(service)
    _bind_fake_founder_identity(monkeypatch, observer_module, profile)
    calls: list[tuple[int, int]] = []
    monkeypatch.setattr(
        observer_module,
        "windows_session_is_active",
        lambda session: WindowsSessionQueryResult(
            WindowsSessionQueryStatus.QUERY_FAILED, win32_error=5
        ),
    )

    def client_query(pipe: int, session: int) -> WindowsSessionQueryResult:
        calls.append((pipe, session))
        return WindowsSessionQueryResult(
            WindowsSessionQueryStatus.ACTIVE, state=0
        )

    monkeypatch.setattr(
        observer_module, "authenticated_client_windows_session_state", client_query
    )

    result = service._validated_client_profile(
        42, 84, expected_sid="S-1-5-21-1000"
    )

    assert result[1] == str(profile.resolve())
    assert calls == [(11, 1)]


def test_registration_canonicalizes_enrolled_profile_only_on_authenticated_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    profile = tmp_path / "Founder"
    profile.mkdir()
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture-not-a-real-credential")

    class _ReadyGateway:
        def status(self) -> dict[str, object]:
            return {
                "launch_journal": _zero_launch_journal(),
                "state": "READY",
                "provider_binding": None,
                "user_binding": {
                    "profile_path": str(profile),
                    "session_id": 1,
                    "user_sid": "S-1-5-21-1000",
                },
            }

    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
        provider_host_gateway=cast(Any, _ReadyGateway()),
    )
    service._local.client_token = 42
    _attach_fake_client_process_binding(service)
    monkeypatch.setattr(
        service,
        "_validated_client_profile",
        lambda client_token, profile_token, *, expected_sid: (
            {},
            str(profile),
            expected_sid,
            1,
        ),
    )
    worker_calls: list[tuple[int, str]] = []

    def worker_path(token: int, value: str) -> str:
        worker_calls.append((token, value))
        return str(profile)

    monkeypatch.setattr(
        observer_module, "authenticated_client_profile_path", worker_path
    )
    original_resolve = Path.resolve

    def deny_service_profile_traversal(
        path: Path, strict: bool = False
    ) -> Path:
        if path == profile:
            raise PermissionError("service must not traverse Founder profile")
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", deny_service_profile_traversal)

    @contextmanager
    def client_identity(token: int):  # type: ignore[no-untyped-def]
        assert token == 42
        yield

    monkeypatch.setattr(observer_module, "impersonate_token", client_identity)

    @contextmanager
    def process_identity(
        value: object, *, expected_sid: str
    ) -> Iterator[int]:
        del value
        assert expected_sid == "S-1-5-21-1000"
        yield 42

    monkeypatch.setattr(
        observer_module,
        "authenticated_client_process_impersonation_token",
        process_identity,
    )
    @contextmanager
    def transfer_process(
        value: object, *, expected_sid: str
    ) -> Iterator[int]:
        del value
        assert expected_sid == "S-1-5-21-1000"
        yield 73

    monkeypatch.setattr(
        observer_module,
        "authenticated_client_transfer_process",
        transfer_process,
    )
    monkeypatch.setattr(
        observer_module,
        "_measure_duplicated_reviewed_executable",
        lambda *args: (_ for _ in ()).throw(
            PermissionError("stop after profile validation")
        ),
    )

    with pytest.raises(PermissionError, match="stop after profile validation"):
        service._register_codex_through_host(
            provider_id="codex",
            executable=executable,
            client_sid="S-1-5-21-1000",
            executive_capabilities=["implementation"],
            project_types=["software"],
            effort_levels=["medium", "high"],
            pricing_authority=_pricing(),
            expected_executable_sha256=hashlib.sha256(b"fixture").hexdigest(),
            expected_executable_size=len(b"fixture"),
            expected_version="codex-cli 0.146.0",
            model_allowlist=["gpt-5.6-sol"],
            model_revalidation_expires_at=(
                datetime.now(UTC) + timedelta(days=30)
            ).isoformat(),
            authentication_policy=_authentication_policy(),
                usage_policy=_usage_policy(),
                client_executable_handle=77,
                planned_registration_id="keeper-provider:codex:v1:" + "1" * 32,
                planned_setup_id="provider-registration-probe:" + "2" * 32,
                planned_challenge="3" * 64,
                recovering_registration=False,
            )

    assert worker_calls == [(42, str(profile))]


def test_registration_discards_enrolled_profile_when_worker_reversion_is_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    profile = tmp_path / "Founder"
    profile.mkdir()
    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture-not-a-real-credential")

    class _ReadyGateway:
        def status(self) -> dict[str, object]:
            return {
                "launch_journal": _zero_launch_journal(),
                "state": "READY",
                "provider_binding": None,
                "user_binding": {
                    "profile_path": str(profile),
                    "session_id": 1,
                    "user_sid": "S-1-5-21-1000",
                },
            }

    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
        provider_host_gateway=cast(Any, _ReadyGateway()),
    )
    service._local.client_token = 42
    _attach_fake_client_process_binding(service)
    monkeypatch.setattr(
        service,
        "_validated_client_profile",
        lambda client_token, profile_token, *, expected_sid: (
            {},
            str(profile),
            expected_sid,
            1,
        ),
    )
    monkeypatch.setattr(
        observer_module,
        "authenticated_client_profile_path",
        lambda token, value: (_ for _ in ()).throw(
            PermissionError("profile worker reversion uncertain")
        ),
    )
    measurements = 0

    def forbidden_measurement(*args: object) -> object:
        nonlocal measurements
        del args
        measurements += 1
        raise AssertionError("executable measurement must not start")

    monkeypatch.setattr(
        observer_module,
        "_measure_duplicated_reviewed_executable",
        forbidden_measurement,
    )

    with pytest.raises(PermissionError, match="reversion uncertain"):
        service._register_codex_through_host(
            provider_id="codex",
            executable=tmp_path / "codex.exe",
            client_sid="S-1-5-21-1000",
            executive_capabilities=["implementation"],
            project_types=["software"],
            effort_levels=["medium", "high"],
            pricing_authority=_pricing(),
            expected_executable_sha256="0" * 64,
            expected_executable_size=1,
            expected_version="codex-cli 0.146.0",
            model_allowlist=["gpt-5.6-sol"],
            model_revalidation_expires_at=(
                datetime.now(UTC) + timedelta(days=30)
            ).isoformat(),
            authentication_policy=_authentication_policy(),
                usage_policy=_usage_policy(),
                client_executable_handle=77,
                planned_registration_id="keeper-provider:codex:v1:" + "1" * 32,
                planned_setup_id="provider-registration-probe:" + "2" * 32,
                planned_challenge="3" * 64,
                recovering_registration=False,
            )

    assert measurements == 0


@pytest.mark.parametrize(
    ("service_result", "message"),
    [
        (
            WindowsSessionQueryResult(
                WindowsSessionQueryStatus.INACTIVE, state=4
            ),
            "wts_state=4",
        ),
        (
            WindowsSessionQueryResult(
                WindowsSessionQueryStatus.QUERY_FAILED, win32_error=87
            ),
            "win32_error=87",
        ),
    ],
)
def test_client_profile_fails_closed_without_pipe_fallback_for_inactive_or_other_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    service_result: WindowsSessionQueryResult,
    message: str,
) -> None:
    import keeper.authority_service.observer as observer_module

    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture-not-a-real-credential")
    profile = tmp_path / "Founder"
    profile.mkdir()
    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
    )
    service._local.client_token = 42
    _attach_fake_client_process_binding(service)
    _bind_fake_founder_identity(monkeypatch, observer_module, profile)
    monkeypatch.setattr(
        observer_module, "windows_session_is_active", lambda session: service_result
    )
    monkeypatch.setattr(
        observer_module,
        "authenticated_client_windows_session_state",
        lambda pipe, session: pytest.fail("unexpected client impersonation"),
    )

    with pytest.raises(PermissionError, match=message):
        service._validated_client_profile(
            42, 84, expected_sid="S-1-5-21-1000"
        )

    assert list((tmp_path / "provider-root").glob("registration-probe-*")) == []


def test_registration_environment_failure_prevents_probe_and_returns_sanitized_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture-not-a-real-credential")
    provider_root = tmp_path / "provider-root"
    service = ServiceProviderObserver(
        provider_root,
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
    )
    service._local.client_token = 42
    _attach_fake_client_process_binding(service)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")

    @contextmanager
    def profile_primary(  # type: ignore[no-untyped-def]
        token: int,
    ):
        assert token == 86
        yield 84

    def environment_failure(token: int) -> dict[str, str]:
        assert token == 42
        raise PermissionError(
            "provider profile environment is unavailable "
            "(api=CreateEnvironmentBlock, token_type=authenticated-impersonation, "
            "required_access=TOKEN_QUERY, "
            "win32_error=5, symbolic=ERROR_ACCESS_DENIED)"
        )

    monkeypatch.setattr(
        observer_module, "authenticated_profile_primary_token", profile_primary
    )
    monkeypatch.setattr(observer_module, "require_impersonation_level", lambda token: 2)
    monkeypatch.setattr(
        observer_module, "token_user_sid_string", lambda token: "S-1-5-21-1000"
    )
    monkeypatch.setattr(observer_module, "token_session_id", lambda token: 1)
    monkeypatch.setattr(
        observer_module,
        "windows_session_is_active",
        lambda session: WindowsSessionQueryResult(
            WindowsSessionQueryStatus.ACTIVE, state=0
        ),
    )
    monkeypatch.setattr(
        observer_module, "authenticated_client_environment", environment_failure
    )

    with pytest.raises(PermissionError) as caught:
        service.register_provider(
            "codex",
            executable,
            "S-1-5-21-1000",
            executive_capabilities=["provider.execution"],
            project_types=["coding"],
            effort_levels=["medium", "high"],
            pricing_authority={"mode": "INCLUDED_SUBSCRIPTION"},
            expected_executable_sha256=hashlib.sha256(b"fixture").hexdigest(),
            expected_executable_size=len(b"fixture"),
            expected_version="codex-cli 0.146.0",
            model_allowlist=["gpt-5.6-sol"],
        )

    assert "requires KeeperProviderHost" in str(caught.value)
    assert list(provider_root.glob("registration-probe-*")) == []


def test_registration_binds_profile_then_rejects_unreviewed_executable_before_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture-not-a-real-credential")
    provider_root = tmp_path / "provider-root"
    service = ServiceProviderObserver(
        provider_root,
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
    )
    service._local.client_token = 42
    _attach_fake_client_process_binding(service)
    executable = (tmp_path / "codex.exe").resolve()
    executable.write_bytes(b"unreviewed-executable")
    profile = tmp_path / "Founder"
    profile.mkdir()
    profile_calls = 0
    probe_calls = 0

    @contextmanager
    def forbidden_profile(  # type: ignore[no-untyped-def]
        token: int,
    ):
        nonlocal profile_calls
        assert token == 86
        profile_calls += 1
        yield 84

    def forbidden_probe(*args: object, **kwargs: object) -> object:
        nonlocal probe_calls
        del args, kwargs
        probe_calls += 1
        raise AssertionError("provider probe must not execute")

    monkeypatch.setattr(
        observer_module, "authenticated_profile_primary_token", forbidden_profile
    )
    monkeypatch.setattr(observer_module, "require_impersonation_level", lambda token: 2)
    monkeypatch.setattr(
        observer_module, "token_user_sid_string", lambda token: "S-1-5-21-1000"
    )
    monkeypatch.setattr(observer_module, "token_session_id", lambda token: 1)
    monkeypatch.setattr(
        observer_module,
        "windows_session_is_active",
        lambda session: WindowsSessionQueryResult(
            WindowsSessionQueryStatus.ACTIVE, state=0
        ),
    )
    monkeypatch.setattr(
        observer_module,
        "authenticated_client_environment",
        lambda token: {"USERPROFILE": str(profile), "PATH": str(tmp_path)},
    )

    @contextmanager
    def client_identity(token: int):  # type: ignore[no-untyped-def]
        del token
        yield

    monkeypatch.setattr(observer_module, "impersonate_token", client_identity)
    monkeypatch.setattr(observer_module, "run_restricted_process", forbidden_probe)

    with pytest.raises(PermissionError, match="requires KeeperProviderHost"):
        service.register_provider(
            "codex",
            executable,
            "S-1-5-21-1000",
            executive_capabilities=["provider.execution"],
            project_types=["coding"],
            effort_levels=["medium", "high"],
            pricing_authority={"mode": "INCLUDED_SUBSCRIPTION"},
            expected_executable_sha256="0" * 64,
            expected_executable_size=len(b"unreviewed-executable"),
            expected_version="codex-cli 0.146.0",
            model_allowlist=["gpt-5.6-sol"],
        )

    assert profile_calls == 0
    assert probe_calls == 0
    assert list(provider_root.glob("registration-probe-*")) == []


def test_registration_binds_profile_then_rejects_unapproved_signature_before_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture-not-a-real-credential")
    provider_root = tmp_path / "provider-root"
    service = ServiceProviderObserver(
        provider_root,
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
    )
    service._local.client_token = 42
    _attach_fake_client_process_binding(service)
    executable = (tmp_path / "codex.exe").resolve()
    content = b"correctly-reviewed-bytes"
    executable.write_bytes(content)
    profile = tmp_path / "Founder"
    profile.mkdir()
    profile_calls = 0
    probe_calls = 0

    @contextmanager
    def forbidden_profile(  # type: ignore[no-untyped-def]
        token: int,
    ):
        nonlocal profile_calls
        assert token == 86
        profile_calls += 1
        yield 84

    def forbidden_probe(*args: object, **kwargs: object) -> object:
        nonlocal probe_calls
        del args, kwargs
        probe_calls += 1
        raise AssertionError("provider probe must not execute")

    monkeypatch.setattr(
        observer_module,
        "authenticode_identity",
        lambda path: {
            "status": "NotSigned",
            "publisher_subject": "",
            "certificate_thumbprint": "",
        },
    )
    monkeypatch.setattr(
        observer_module, "authenticated_profile_primary_token", forbidden_profile
    )
    monkeypatch.setattr(observer_module, "require_impersonation_level", lambda token: 2)
    monkeypatch.setattr(
        observer_module, "token_user_sid_string", lambda token: "S-1-5-21-1000"
    )
    monkeypatch.setattr(observer_module, "token_session_id", lambda token: 1)
    monkeypatch.setattr(
        observer_module,
        "windows_session_is_active",
        lambda session: WindowsSessionQueryResult(
            WindowsSessionQueryStatus.ACTIVE, state=0
        ),
    )
    monkeypatch.setattr(
        observer_module,
        "authenticated_client_environment",
        lambda token: {"USERPROFILE": str(profile), "PATH": str(tmp_path)},
    )

    @contextmanager
    def client_identity(token: int):  # type: ignore[no-untyped-def]
        del token
        yield

    monkeypatch.setattr(observer_module, "impersonate_token", client_identity)
    monkeypatch.setattr(observer_module, "run_restricted_process", forbidden_probe)

    with pytest.raises(PermissionError, match="requires KeeperProviderHost"):
        service.register_provider(
            "codex",
            executable,
            "S-1-5-21-1000",
            executive_capabilities=["provider.execution"],
            project_types=["coding"],
            effort_levels=["medium", "high"],
            pricing_authority={"mode": "INCLUDED_SUBSCRIPTION"},
            expected_executable_sha256=hashlib.sha256(content).hexdigest(),
            expected_executable_size=len(content),
            expected_version="codex-cli 0.146.0",
            model_allowlist=["gpt-5.6-sol"],
        )

    assert profile_calls == 0
    assert probe_calls == 0
    assert list(provider_root.glob("registration-probe-*")) == []


def test_reviewed_executable_measurement_binds_canonical_hash_signature_and_file_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    executable = (tmp_path / "codex.exe").resolve()
    content = b"reviewed-codex-fixture"
    executable.write_bytes(content)
    signature = {
        "status": "Valid",
        "publisher_subject": "CN=OpenAI OpCo, LLC",
        "certificate_thumbprint": "0B7C30C11BF7250EC1ECD3254AC781D9E13D62F8",
        "source": "windows-authenticode",
    }
    monkeypatch.setattr(
        observer_module, "authenticode_identity", lambda path: dict(signature)
    )

    canonical, measurement = _validated_reviewed_codex_executable(
        executable, hashlib.sha256(content).hexdigest(), len(content)
    )

    assert canonical == executable
    assert measurement["canonical_path"] == str(executable)
    assert measurement["sha256"] == hashlib.sha256(content).hexdigest()
    assert measurement["size"] == len(content)
    assert measurement["authenticode_binding"] == signature
    identity = cast(dict[str, int], measurement["file_identity"])
    assert identity["file_id"] == executable.stat().st_ino
    assert identity["device_id"] == executable.stat().st_dev
    assert identity["modified_ns"] == executable.stat().st_mtime_ns

    with pytest.raises(PermissionError, match="reviewed identity"):
        _validated_reviewed_codex_executable(
            executable, "0" * 64, len(content)
        )
    with pytest.raises(PermissionError, match="not absolute"):
        _validated_reviewed_codex_executable(
            Path("codex.exe"), hashlib.sha256(content).hexdigest(), len(content)
        )
    for prohibited in (
        Path(r"\\server\share\codex.exe"),
        Path(r"\\?\C:\reviewed\codex.exe"),
        Path(r"C:\reviewed\codex.exe:alternate"),
    ):
        with pytest.raises(PermissionError, match="path form is prohibited"):
            _validated_reviewed_codex_executable(
                prohibited, hashlib.sha256(content).hexdigest(), len(content)
            )


def test_reviewed_executable_rejects_alias_inaccessible_and_publisher_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    executable = (tmp_path / "codex.exe").resolve()
    content = b"reviewed-codex-fixture"
    executable.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    alias_path = tmp_path / "codex-alias.exe"
    alias: Path | None = alias_path
    try:
        os.symlink(executable, alias_path)
    except OSError:
        alias = None
    if alias is not None:
        with pytest.raises(PermissionError, match="alias"):
            _validated_reviewed_codex_executable(alias, digest, len(content))

    def denied(path: Path) -> int:
        del path
        raise PermissionError("service identity access denied")

    monkeypatch.setattr(observer_module, "_open_locked_executable", denied)
    with pytest.raises(PermissionError, match="service identity access denied"):
        _validated_reviewed_codex_executable(executable, digest, len(content))
    monkeypatch.undo()
    monkeypatch.setattr(
        observer_module,
        "authenticode_identity",
        lambda path: {
            "status": "Valid",
            "publisher_subject": "CN=Unexpected Publisher",
            "certificate_thumbprint": "0" * 40,
            "source": "windows-authenticode",
        },
    )
    with pytest.raises(ValueError, match="publisher"):
        _validated_reviewed_codex_executable(executable, digest, len(content))


@pytest.mark.skipif(os.name != "nt", reason="Windows executable sharing test")
def test_locked_reviewed_executable_cannot_be_replaced_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    executable = (tmp_path / "codex.exe").resolve()
    replacement = tmp_path / "replacement.exe"
    content = b"reviewed-codex-fixture"
    executable.write_bytes(content)
    replacement.write_bytes(b"replaced-codex-fixture")
    monkeypatch.setattr(
        observer_module,
        "authenticode_identity",
        lambda path: {
            "status": "Valid",
            "publisher_subject": "CN=OpenAI OpCo, LLC",
            "certificate_thumbprint": "0B7C30C11BF7250EC1ECD3254AC781D9E13D62F8",
            "source": "windows-authenticode",
        },
    )
    canonical, measurement, descriptor = (
        _open_validated_reviewed_codex_executable(
            executable, hashlib.sha256(content).hexdigest(), len(content)
        )
    )
    try:
        assert canonical == executable
        assert measurement["file_identity"]["file_id"] == executable.stat().st_ino
        with pytest.raises(PermissionError):
            os.replace(replacement, executable)
    finally:
        os.close(descriptor)
    assert executable.read_bytes() == content


def test_bounded_measurement_is_only_work_done_while_impersonating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture")
    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
    )
    state = {"impersonating": False, "measurements": 0}

    @contextmanager
    def client_identity(token: int):  # type: ignore[no-untyped-def]
        assert token == 42
        assert state["impersonating"] is False
        state["impersonating"] = True
        try:
            yield
        finally:
            state["impersonating"] = False

    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    opened: list[int] = []

    def measured(
        path: Path, expected_hash: str | None, expected_size: int | None
    ) -> tuple[Path, dict[str, Any], int]:
        assert state["impersonating"] is True
        state["measurements"] += 1
        descriptor = os.open(path, os.O_RDONLY)
        opened.append(descriptor)
        return path, {"bounded": True}, descriptor

    monkeypatch.setattr(observer_module, "impersonate_token", client_identity)
    monkeypatch.setattr(
        observer_module, "_open_validated_reviewed_codex_executable", measured
    )
    result = service._measure_reviewed_codex_executable(
        42, executable, "0" * 64, len(b"fixture")
    )
    assert result[1] == {"bounded": True}
    assert state == {"impersonating": False, "measurements": 1}
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_registration_measurement_worker_publishes_only_after_clean_reversion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture")
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
    )
    request_thread = threading.get_ident()
    state = {"impersonating": False, "clean_checks": 0}

    def clean_thread() -> None:
        assert state["impersonating"] is False
        state["clean_checks"] += 1

    @contextmanager
    def client_identity(token: int):  # type: ignore[no-untyped-def]
        assert token == 42
        assert threading.get_ident() != request_thread
        assert state["impersonating"] is False
        state["impersonating"] = True
        try:
            yield
        finally:
            state["impersonating"] = False

    def measured(
        path: Path, expected_hash: str | None, expected_size: int | None
    ) -> tuple[Path, dict[str, Any], int]:
        del expected_hash, expected_size
        assert state["impersonating"] is True
        descriptor = os.open(path, os.O_RDONLY)
        return path, {"bounded": True}, descriptor

    monkeypatch.setattr(
        observer_module.restricted_process_runtime,
        "_assert_thread_not_impersonating",
        clean_thread,
    )
    monkeypatch.setattr(observer_module, "impersonate_token", client_identity)
    monkeypatch.setattr(
        observer_module, "_open_validated_reviewed_codex_executable", measured
    )

    canonical, measurement, descriptor = (
        service._open_reviewed_codex_executable_on_authenticated_worker(
            42, executable, "0" * 64, len(b"fixture")
        )
    )
    try:
        assert canonical == executable
        assert measurement == {"bounded": True}
        assert state == {"impersonating": False, "clean_checks": 4}
    finally:
        os.close(descriptor)


def test_registration_uses_exact_retained_process_token_for_measurement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    profile = tmp_path / "Founder"
    profile.mkdir()
    executable = profile / "codex.exe"
    executable.write_bytes(b"fixture")
    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture")

    class _ReadyGateway:
        def status(self) -> dict[str, object]:
            return {
                "launch_journal": _zero_launch_journal(),
                "state": "READY",
                "provider_binding": None,
                "user_binding": {
                    "profile_path": str(profile),
                    "session_id": 1,
                    "user_sid": "S-1-5-21-1000",
                },
            }

        @staticmethod
        def setup_workspace(setup_id: str) -> Path:
            assert setup_id.startswith("provider-registration-probe:")
            return profile / "HostOutput" / "setup" / hashlib.sha256(
                setup_id.encode("utf-8")
            ).hexdigest()

    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
        provider_host_gateway=cast(Any, _ReadyGateway()),
    )
    service._local.client_token = 42
    _attach_fake_client_process_binding(service)
    binding = service._local.client_binding
    monkeypatch.setattr(
        service,
        "_validated_client_profile",
        lambda client_token, profile_token, *, expected_sid: (
            {}, str(profile), expected_sid, 1
        ),
    )
    monkeypatch.setattr(
        observer_module,
        "authenticated_client_profile_path",
        lambda token, value: str(profile),
    )
    measured: list[int] = []

    @contextmanager
    def retained_process_token(
        value: object, *, expected_sid: str
    ) -> Iterator[int]:
        assert value is binding
        assert expected_sid == "S-1-5-21-1000"
        yield 84

    monkeypatch.setattr(
        observer_module,
        "authenticated_client_process_impersonation_token",
        retained_process_token,
    )
    @contextmanager
    def transfer_process(
        value: object, *, expected_sid: str
    ) -> Iterator[int]:
        assert value is binding
        assert expected_sid == "S-1-5-21-1000"
        yield 73

    monkeypatch.setattr(
        observer_module,
        "authenticated_client_transfer_process",
        transfer_process,
    )
    monkeypatch.setattr(
        observer_module,
        "_measure_duplicated_reviewed_executable",
        lambda handle, path, expected_hash, expected_size: (
            measured.append(handle) or path,
            {
                "canonical_path": str(path),
                "sha256": expected_hash,
                "size": expected_size,
                "file_identity": {
                    "schema_version": 1,
                    "device_id": 1,
                    "file_id": 2,
                    "size": expected_size,
                    "modified_ns": 3,
                },
                "authenticode_binding": _registration(path)[
                    "authenticode_binding"
                ],
            },
        ),
    )
    provisional_bindings: list[dict[str, Any]] = []
    monkeypatch.setattr(
        service.provider_host_gateway,
        "prepare_environment",
        lambda *args: {},
        raising=False,
    )

    def capture_setup_envelope(**arguments: Any) -> dict[str, Any]:
        registration = cast(dict[str, Any], arguments["registration"])
        provisional_bindings.append(
            dict(registration["subscription_account_binding"])
        )
        raise PermissionError("stop before effect")

    monkeypatch.setattr(
        service.provider_host_gateway,
        "build_setup_envelope",
        capture_setup_envelope,
        raising=False,
    )

    with pytest.raises(PermissionError, match="stop before effect"):
        service._register_codex_through_host(
            provider_id="codex",
            executable=executable,
            client_sid="S-1-5-21-1000",
            executive_capabilities=["implementation"],
            project_types=["software"],
            effort_levels=["medium", "high"],
            pricing_authority=_pricing(),
            expected_executable_sha256="0" * 64,
            expected_executable_size=len(b"fixture"),
            expected_version="codex-cli 0.146.0",
            model_allowlist=["gpt-5.6-sol"],
            model_revalidation_expires_at=(
                datetime.now(UTC) + timedelta(days=30)
            ).isoformat(),
            authentication_policy=_authentication_policy(),
                usage_policy=_usage_policy(),
                client_executable_handle=77,
                planned_registration_id="keeper-provider:codex:v1:" + "1" * 32,
                planned_setup_id="provider-registration-probe:" + "2" * 32,
                planned_challenge="3" * 64,
                recovering_registration=False,
                expected_account_identity_digest="c" * 64,
                expected_account_plan_type="pro",
            )

    assert measured == [77]
    assert provisional_bindings == [
        {
            "account_identity_digest": "c" * 64,
            "authentication_method": "chatgpt-subscription",
            "plan_type": "pro",
        }
    ]


def test_registration_passes_handle_validated_parent_without_reopening_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    profile = (tmp_path / "Founder").resolve()
    profile.mkdir()
    executable = profile / "bin" / "codex.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"fixture")
    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture")
    prepared: list[Path] = []

    class _ReadyGateway:
        def status(self) -> dict[str, object]:
            return {
                "launch_journal": _zero_launch_journal(),
                "state": "READY",
                "provider_binding": None,
                "user_binding": {
                    "profile_path": str(profile),
                    "session_id": 1,
                    "user_sid": "S-1-5-21-1000",
                },
            }

        @staticmethod
        def setup_workspace(setup_id: str) -> Path:
            assert setup_id.startswith("provider-registration-probe:")
            return profile / "HostOutput" / "setup" / hashlib.sha256(
                setup_id.encode("utf-8")
            ).hexdigest()

        def prepare_environment(self, nonce: str, provider_bin: Path) -> object:
            assert nonce
            prepared.append(provider_bin)
            raise PermissionError("stop after environment path")

    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
        provider_host_gateway=cast(Any, _ReadyGateway()),
    )
    service._local.client_token = 42
    _attach_fake_client_process_binding(service)
    monkeypatch.setattr(
        service,
        "_validated_client_profile",
        lambda client_token, profile_token, *, expected_sid: (
            {}, str(profile), expected_sid, 1
        ),
    )
    monkeypatch.setattr(
        observer_module,
        "authenticated_client_profile_path",
        lambda token, value: str(profile),
    )

    @contextmanager
    def transfer_process(
        value: object, *, expected_sid: str
    ) -> Iterator[int]:
        del value
        assert expected_sid == "S-1-5-21-1000"
        yield 73

    monkeypatch.setattr(
        observer_module, "authenticated_client_transfer_process", transfer_process
    )
    monkeypatch.setattr(
        observer_module,
        "_measure_duplicated_reviewed_executable",
        lambda handle, path, expected_hash, expected_size: (
            executable,
            {
                "canonical_path": str(executable),
                "sha256": expected_hash,
                "size": expected_size,
                "file_identity": _registration(executable)["executable_file_identity"],
                "authenticode_binding": _registration(executable)["authenticode_binding"],
            },
        ),
    )

    with pytest.raises(PermissionError, match="stop after environment path"):
        service._register_codex_through_host(
            provider_id="codex",
            executable=executable,
            client_sid="S-1-5-21-1000",
            executive_capabilities=["implementation"],
            project_types=["software"],
            effort_levels=["medium", "high"],
            pricing_authority=_pricing(),
            expected_executable_sha256="0" * 64,
            expected_executable_size=len(b"fixture"),
            expected_version="codex-cli 0.146.0",
            model_allowlist=["gpt-5.6-sol"],
            model_revalidation_expires_at=(
                datetime.now(UTC) + timedelta(days=30)
            ).isoformat(),
            authentication_policy=_authentication_policy(),
                usage_policy=_usage_policy(),
                client_executable_handle=77,
                planned_registration_id="keeper-provider:codex:v1:" + "1" * 32,
                planned_setup_id="provider-registration-probe:" + "2" * 32,
                planned_challenge="3" * 64,
                recovering_registration=False,
            )

    assert prepared == [executable.parent]


def test_registration_measurement_worker_discards_descriptor_when_reversion_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture")
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
    )
    opened: list[int] = []

    @contextmanager
    def uncertain_reversion(token: int):  # type: ignore[no-untyped-def]
        assert token == 42
        yield
        raise PermissionError("client identity reversion uncertain")

    def measured(
        path: Path, expected_hash: str | None, expected_size: int | None
    ) -> tuple[Path, dict[str, Any], int]:
        del expected_hash, expected_size
        descriptor = os.open(path, os.O_RDONLY)
        opened.append(descriptor)
        return path, {"bounded": True}, descriptor

    monkeypatch.setattr(
        observer_module.restricted_process_runtime,
        "_assert_thread_not_impersonating",
        lambda: None,
    )
    monkeypatch.setattr(observer_module, "impersonate_token", uncertain_reversion)
    monkeypatch.setattr(
        observer_module, "_open_validated_reviewed_codex_executable", measured
    )

    with pytest.raises(PermissionError, match="reversion uncertain"):
        service._open_reviewed_codex_executable_on_authenticated_worker(
            42, executable, "0" * 64, len(b"fixture")
        )
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_codex_probe_command_does_not_read_the_reviewed_executable(
    tmp_path: Path
) -> None:
    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture")
    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
    )
    inaccessible = Path(r"C:\FounderProfile\unreadable\codex.exe")

    command = service._codex_probe_command(inaccessible, ["gpt-5.6-sol"])

    assert command[-4:] == [
        "--executable",
        str(inaccessible),
        "--model",
        "gpt-5.6-sol",
    ]


def test_locked_measurement_closes_descriptor_when_reversion_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture")
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
    )
    opened: list[int] = []

    @contextmanager
    def revert_failure(token: int):  # type: ignore[no-untyped-def]
        assert token == 42
        yield
        raise PermissionError("restricted provider impersonation could not be reverted")

    def open_fixture(
        path: Path, expected_hash: str | None, expected_size: int | None
    ) -> tuple[Path, dict[str, Any], int]:
        del expected_hash, expected_size
        descriptor = os.open(path, os.O_RDONLY)
        opened.append(descriptor)
        return path, {"bounded": True}, descriptor

    monkeypatch.setattr(observer_module, "impersonate_token", revert_failure)
    monkeypatch.setattr(
        observer_module, "_open_validated_reviewed_codex_executable", open_fixture
    )
    with pytest.raises(PermissionError, match="could not be reverted"):
        with service._hold_reviewed_codex_executable(
            42, executable, "0" * 64, len(b"fixture")
        ):
            pytest.fail("the locked executable must not escape failed reversion")
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_version_only_qualification_is_not_sufficient(tmp_path: Path) -> None:
    observer = _CodexObserver(qualification_complete=False)
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _registration(executable)
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations",
        registration_id,
        "REGISTERED_UNQUALIFIED",
        registration,
    )

    result = client.qualify_provider(registration_id, executable)

    assert result["registration"]["registration_lifecycle"] == (
        "QUALIFICATION_FAILED"
    )
    assert result["qualification"]["qualification_result"] == "failed"


def test_qualification_rechecks_binary_before_any_provider_process(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver()
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _registration(executable)
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations",
        registration_id,
        "REGISTERED_UNQUALIFIED",
        registration,
    )
    executable.write_bytes(b"replaced-fixture")

    with pytest.raises(PermissionError, match="changed before qualification"):
        client.qualify_provider(registration_id, executable)

    assert observer.qualify_calls == 0
    stored = core.store.get("registrations", registration_id)
    assert stored is not None
    assert stored["service_state"] == "REGISTERED_UNQUALIFIED"


def test_schema4_qualification_missing_locked_handle_has_zero_durable_effect(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver()
    core, _client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _registration(executable)
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations",
        registration_id,
        "REGISTERED_UNQUALIFIED",
        registration,
    )

    with pytest.raises(ValueError, match="client executable handle is invalid"):
        core.dispatch(
            Request.create(
                Operation.BEGIN_QUALIFICATION,
                {"registration_id": registration_id},
            ),
            "S-1-5-21-1000",
        )

    assert observer.qualify_calls == 0
    stored = core.store.get("registrations", registration_id)
    assert stored is not None
    assert stored["service_state"] == "REGISTERED_UNQUALIFIED"
    assert core.store.list_records("qualifications") == []


def test_qualification_rejects_exact_executable_version_mismatch(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver(qualification_version="codex-cli 0.147.0")
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _registration(executable)
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations",
        registration_id,
        "REGISTERED_UNQUALIFIED",
        registration,
    )

    result = client.qualify_provider(registration_id, executable)

    assert observer.qualify_calls == 1
    assert result["registration"]["registration_lifecycle"] == (
        "QUALIFICATION_FAILED"
    )
    assert result["qualification"]["qualification_result"] == "failed"


def test_production_equivalent_fixture_qualification_binds_model_and_effort(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver()
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _registration(executable)
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations",
        registration_id,
        "REGISTERED_UNQUALIFIED",
        registration,
    )

    result = client.qualify_provider(registration_id, executable)
    evidence = result["qualification"]

    assert result["registration"]["registration_lifecycle"] == "QUALIFIED"
    assert evidence["qualified_model_id"] == "gpt-5.6-sol"
    assert evidence["qualified_reasoning_level"] == "medium"
    assert evidence["authentication_probe"]["authentication_method"] == (
        "chatgpt-subscription"
    )
    assert core.keys.verify("provider-qualification", evidence)
    repeated = client.qualify_provider(registration_id, executable)
    assert repeated == result
    assert observer.qualify_calls == 1


def test_usage_exhaustion_rejects_before_external_execution(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver(exhausted=True)
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    reserved = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="exhausted",
        )
    )

    with pytest.raises(PermissionError, match="WAITING_FOR_USAGE_RESET"):
        client.execute_provider(str(reserved["attempt_id"]))

    assert observer.execute_calls == 0
    state = client.query_state("attempts", str(reserved["attempt_id"]))
    assert state["record"]["service_state"] == "WAITING_FOR_USAGE_RESET"
    waiting_record = dict(state["record"])
    waiting_record.pop("service_state")
    assert core.keys.verify("provider-usage-wait", waiting_record)
    with pytest.raises(PermissionError, match="not reserved"):
        client.execute_provider(str(reserved["attempt_id"]))


def test_waiting_requires_fresh_authoritative_reset_observation(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver(exhausted=True)
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)

    first = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="reset-first",
        )
    )
    with pytest.raises(PermissionError, match="WAITING_FOR_USAGE_RESET"):
        client.execute_provider(str(first["attempt_id"]))

    observer.exhausted = False
    observer.capacity_state = "UNKNOWN"
    observer.usage_confidence = "LOW"
    second = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="reset-unknown",
        )
    )
    with pytest.raises(PermissionError, match="not authoritatively observed"):
        client.execute_provider(str(second["attempt_id"]))
    assert observer.execute_calls == 0

    observer.capacity_state = "OBSERVED"
    observer.usage_confidence = "HIGH"
    third = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="reset-observed",
        )
    )
    result = client.execute_provider(str(third["attempt_id"]))

    assert observer.execute_calls == 1
    assert result["completion"]["normalized_result"] == "completed"


def test_keeper_launch_budget_stops_second_launch_without_retry(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver()
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable, budget=1))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    first = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="budget-one",
        )
    )
    completed = client.execute_provider(str(first["attempt_id"]))
    assert completed["completion"]["reasoning_level"] == "medium"
    assert completed["completion"]["model_id"] == "gpt-5.6-sol"
    assert completed["completion"]["prompt_digest"]
    second = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="high",
            suffix="budget-two",
        )
    )

    with pytest.raises(PermissionError, match="Keeper launch budget"):
        client.execute_provider(str(second["attempt_id"]))

    assert observer.execute_calls == 1


def test_old_usage_wait_requires_fresh_authoritative_reset(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver(capacity_state="UNKNOWN", usage_confidence="LOW")
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    old_wait = core.keys.sign(
        "provider-usage-wait",
        {
            "id": "provider-attempt:old-wait",
            "kind": "provider_usage_wait",
            "registration_id": registration_id,
            "project_id": "project-old-wait",
            "waited_at": (datetime.now(UTC) - timedelta(days=30)).isoformat(),
        },
    )
    core.store.insert(
        "attempts",
        "provider-attempt:old-wait",
        "WAITING_FOR_USAGE_RESET",
        old_wait,
        registration_id=registration_id,
        run_id="old-wait",
        attempt_number=1,
        challenge="0" * 64,
    )
    attempt = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="after-old-wait",
        )
    )

    with pytest.raises(PermissionError, match="reset is not authoritatively"):
        client.execute_provider(str(attempt["attempt_id"]))

    assert observer.execute_calls == 0


def test_subscription_account_switch_rejects_before_provider_launch(
    tmp_path: Path,
) -> None:
    class _SwitchedAccountObserver(_CodexObserver):
        def preflight_provider(
            self, registration: dict[str, Any], attempt: dict[str, Any]
        ) -> dict[str, Any]:
            result = super().preflight_provider(registration, attempt)
            result["account_identity_digest"] = "d" * 64
            return result

    observer = _SwitchedAccountObserver()
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    attempt = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="account-switch",
        )
    )

    with pytest.raises(PermissionError, match="account or model"):
        client.execute_provider(str(attempt["attempt_id"]))

    assert observer.execute_calls == 0


def test_timed_out_launch_consumes_conservative_budget(tmp_path: Path) -> None:
    observer = _CodexObserver(failure_classification="TIMEOUT")
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable, budget=1))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    first = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="timeout-one",
        )
    )
    first_result = client.execute_provider(str(first["attempt_id"]))
    assert first_result["completion"]["terminal_disposition"] == "TIMED_OUT"
    second = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="timeout-two",
        )
    )

    with pytest.raises(PermissionError, match="Keeper launch budget"):
        client.execute_provider(str(second["attempt_id"]))

    assert observer.execute_calls == 1


def test_concurrent_provider_budget_claim_has_one_winner(tmp_path: Path) -> None:
    barrier = threading.Barrier(2)

    class _ContendedObserver(_CodexObserver):
        def preflight_provider(
            self, registration: dict[str, Any], attempt: dict[str, Any]
        ) -> dict[str, Any]:
            result = super().preflight_provider(registration, attempt)
            barrier.wait(timeout=10)
            return result

    observer = _ContendedObserver()
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable, budget=1))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    attempts = [
        client.reserve_attempt(
            **_reservation(
                client,
                tmp_path,
                registration_id,
                effort="medium",
                suffix=f"contended-{index}",
            )
        )
        for index in range(2)
    ]

    def execute(identifier: str) -> str:
        try:
            client.execute_provider(identifier)
        except PermissionError as error:
            return str(error)
        return "completed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(
            executor.map(
                execute, [str(item["attempt_id"]) for item in attempts]
            )
        )

    assert outcomes.count("completed") == 1
    assert sum("Keeper launch budget" in item for item in outcomes) == 1
    assert observer.execute_calls == 1


def test_execution_model_substitution_fails_after_start_and_is_not_completed(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver(execution_model="gpt-substituted")
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    reserved = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="high",
            suffix="substitution",
        )
    )

    with pytest.raises(PermissionError, match="execution observation differs"):
        client.execute_provider(str(reserved["attempt_id"]))

    state = client.query_state("attempts", str(reserved["attempt_id"]))
    assert state["record"]["service_state"] == "EXECUTION_STARTED"
    assert observer.execute_calls == 1


def test_execution_effort_substitution_fails_after_start_and_is_not_completed(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver(execution_effort="high")
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    reserved = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="effort-substitution",
        )
    )

    with pytest.raises(PermissionError, match="execution observation differs"):
        client.execute_provider(str(reserved["attempt_id"]))

    state = client.query_state("attempts", str(reserved["attempt_id"]))
    assert state["record"]["service_state"] == "EXECUTION_STARTED"
    assert observer.execute_calls == 1


@pytest.mark.parametrize("effort", ["medium", "high"])
def test_each_declared_effort_is_preserved_in_signed_completion(
    tmp_path: Path, effort: str
) -> None:
    observer = _CodexObserver()
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    reserved = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort=effort,
            suffix=f"declared-{effort}",
        )
    )

    result = client.execute_provider(str(reserved["attempt_id"]))

    assert result["completion"]["reasoning_level"] == effort
    assert result["completion"]["model_id"] == "gpt-5.6-sol"
    assert core.keys.verify("provider-completion", result["completion"])


def test_external_subscription_exhaustion_becomes_durable_waiting_state(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver(
        failure_classification="SUBSCRIPTION_EXHAUSTED"
    )
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    reserved = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="external-exhaustion",
        )
    )

    result = client.execute_provider(str(reserved["attempt_id"]))

    assert result["completion"]["normalized_result"] == (
        "waiting_for_usage_reset"
    )
    assert result["completion"]["failure_classification"] == (
        "SUBSCRIPTION_EXHAUSTED"
    )
    state = client.query_state("attempts", str(reserved["attempt_id"]))
    assert state["record"]["service_state"] == "WAITING_FOR_USAGE_RESET"
    with pytest.raises(PermissionError, match="not reserved"):
        client.execute_provider(str(reserved["attempt_id"]))
    assert observer.execute_calls == 1


def test_post_launch_subscription_wait_consumes_conservative_budget(
    tmp_path: Path,
) -> None:
    observer = _CodexObserver(
        failure_classification="SUBSCRIPTION_EXHAUSTED"
    )
    core, client = _codex_service(tmp_path, observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _qualified(_registration(executable, budget=1))
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert("registrations", registration_id, "QUALIFIED", registration)
    first = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="post-launch-exhaustion",
        )
    )
    result = client.execute_provider(str(first["attempt_id"]))
    assert result["completion"]["normalized_result"] == (
        "waiting_for_usage_reset"
    )

    observer.failure_classification = None
    second = client.reserve_attempt(
        **_reservation(
            client,
            tmp_path,
            registration_id,
            effort="medium",
            suffix="after-post-launch-exhaustion",
        )
    )
    with pytest.raises(PermissionError, match="Keeper launch budget"):
        client.execute_provider(str(second["attempt_id"]))

    assert observer.execute_calls == 1


@pytest.mark.parametrize(
    "role",
    ["reviewer", "executive_reviewer", "executive_post_repair_reviewer"],
)
def test_all_reviewer_role_aliases_require_bound_provider_input(role: str) -> None:
    assert _provider_input_is_required({"role": role}) is True
    assert _provider_input_is_required(
        {"role": role, "provider_input_required": True}
    ) is True


def test_executive_projects_known_prelaunch_exhaustion_as_durable_waiting(
    tmp_path: Path,
) -> None:
    service, project, _charter = approved_project(tmp_path / "executive")
    observer = _CodexObserver()
    core, client = _codex_service(tmp_path / "authority", observer)
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _registration(
        executable, executive_capabilities=sorted(ALL_CAPABILITIES)
    )
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations",
        registration_id,
        "REGISTERED_UNQUALIFIED",
        registration,
    )
    qualified = client.qualify_provider(registration_id, executable)
    qualification_id = str(qualified["qualification"]["id"])
    observer.exhausted = True
    gateway = SemanticAuthorityTestGateway(
        authority_operations(client),
        (AuthorityProviderBinding(registration_id, qualification_id),),
        tmp_path / "exchange",
    )
    runtime = ExecutiveRuntime(service.repository, gateway)

    runtime.progress(project.project_id)
    waiting = runtime.progress(project.project_id)

    assert waiting.state == "WAITING_FOR_USAGE_RESET"
    assert "automatic retry" in str(waiting.pause_reason)
    tasks = service.repository.tasks(project.project_id)
    paused = next(item for item in tasks if item.status == "WAITING")
    assert paused.result_disposition == "AUTHORITY_WAITING_FOR_USAGE_RESET"
    assert paused.authority_attempt_id is not None
    state = client.query_state("attempts", paused.authority_attempt_id)
    assert state["record"]["service_state"] == "WAITING_FOR_USAGE_RESET"
    assert observer.execute_calls == 0
    assert runtime.progress(project.project_id).state == "WAITING_FOR_USAGE_RESET"
    desktop_application = PassBApplication(
        tmp_path / "executive",
        executive=PilotConversationExecutive(
            tmp_path / "executive" / "keeper.db"
        ),
    )
    desktop_snapshot = desktop_application.product_snapshot(
        project.project_id
    )
    assert any(
        item.get("provider_id") == "codex"
        and item.get("status") == "WAITING"
        and item.get("result_disposition")
        == "AUTHORITY_WAITING_FOR_USAGE_RESET"
        for item in desktop_snapshot["executive"]["task_status"]
    )


def test_authoring_only_codex_cannot_be_selected_as_reviewer() -> None:
    now = datetime.now(UTC).isoformat()
    specialist = SpecialistProfile(
        "codex",
        "gpt-5.6-sol",
        "session",
        ("review",),
        ("software",),
        True,
        True,
        "authoring-only:registration:session",
        0,
        ("medium", "high"),
        True,
        1.0,
        role_eligibility=("builder", "repairer"),
    )
    task = ExecutiveTask(
        task_id="review",
        project_id="project",
        charter_id="charter",
        charter_revision=1,
        workflow_id="workflow",
        stage_id="review",
        title="Review",
        role="reviewer",
        objective="independently review",
        required_capabilities=("review",),
        instructions=("review",),
        expected_outputs=("review",),
        evidence_requirements=("evidence",),
        review_requirements=("independent",),
        dependencies=(),
        constraints=(),
        authority_category="REVIEW",
        inputs=(),
        status="READY",
        retry_count=0,
        max_retries=0,
        provider_id=None,
        model_id=None,
        session_id=None,
        attempt_history=(),
        result_disposition=None,
        created_at=now,
        updated_at=now,
        revision=1,
    )
    # The role gate applies before independence comparison.
    assert SpecialistSelector().select(
        task,
        _minimal_charter(),
        (specialist,),
        independent=True,
        effort_level="medium",
    ) is None

    same_session_alias = replace(
        specialist,
        provider_id="codex-alias",
        role_eligibility=("reviewer",),
        qualified=False,
    )
    assert SpecialistSelector().select(
        task,
        replace(_minimal_charter(), approved_providers=("codex", "codex-alias")),
        (specialist, same_session_alias),
        author=specialist,
        independent=True,
        effort_level="medium",
    ) is None

    future_reviewer = replace(
        specialist,
        provider_id="future-reviewer",
        session_id="future-review-session",
        independence_identity="independent:future-reviewer:session",
        role_eligibility=("reviewer",),
        qualified=True,
    )
    selected = SpecialistSelector().select(
        task,
        replace(
            _minimal_charter(),
            approved_providers=("codex", "future-reviewer"),
        ),
        (specialist, future_reviewer),
        author=specialist,
        independent=True,
        effort_level="medium",
    )
    assert selected == future_reviewer


def _minimal_charter(tmp_path: Path | None = None):  # type: ignore[no-untyped-def]
    from tests.keeper.executive.test_foundation import charter

    return replace(
        charter(tmp_path or Path(r"C:\tmp\keeper-codex-role-test")),
        approved_providers=("codex",),
    )
