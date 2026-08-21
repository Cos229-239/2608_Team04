from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol, cast

from keeper.evidence_input import structured_digest, validate_provider_input
from keeper.authority_service.key_ring import ServiceKeyRing
from keeper.authority_service.protocol import (
    PROTOCOL_VERSION,
    Operation,
    Request,
)
from keeper.authority_service.provenance import AUDIT_REPORT_PURPOSE
from keeper.authority_service.provider_host_enrollment import (
    ProviderHostEnrollmentCoordinator,
)
from keeper.authority_service.store import AuthorityStore, SERVICE_SCHEMA_VERSION
from keeper.provider_host.enrollment import ENROLLMENT_REVOCATION_PURPOSE
from keeper.executive.founder_capability import (
    ProductionFounderCapabilityVerifier,
    TestFounderCapabilityVerifier,
    capability_digest,
    capability_signature_digest,
)
from keeper.providers.adapters import (
    apply_protected_qualification,
    authority_provider_output_schema,
    canonical_provider_registration_digest,
    create_provider_registration,
    qualification_evidence_digest,
    qualified_version_is_valid,
    validate_provider_registration_contract,
)
from keeper.providers.codex_contract import CODEX_ALLOWED_SUBSCRIPTION_PLANS
from keeper.providers.claude_contract import (
    CLAUDE_ALLOWED_SUBSCRIPTION_PLANS,
    CLAUDE_AUTHENTICATION_MODE,
    CLAUDE_PINNED_REVIEW_MODEL,
)


SERVICE_VERSION = "1.7.50"
RESTORE_FENCE_LIFETIME = timedelta(minutes=2)
_LEGACY_PREDISPATCH_AUTHORITY_VERSION = "1.7.47"
_LEGACY_PREDISPATCH_AUTHORITY_PACKAGE_SHA256 = (
    "19102c5ed7ad2a278c18d49284a8fbea0a189031d4ee4ddf55ed4687120e2211"
)
_LEGACY_PREDISPATCH_HOST_VERSION = "1.7.47"
_LEGACY_PREDISPATCH_HOST_EXECUTABLE_SHA256 = (
    "e81327789faff88c187c007182268049fb81ca4974f02a0ba53e6618a1340fae"
)
_LEGACY_PREDISPATCH_HOST_MANIFEST_SHA256 = (
    "3f9f7135d73f5c309550107bfd2648a8c38a850b7edad001cda3b5567f0e4fee"
)
_LEGACY_PREDISPATCH_OFFLINE_HOST_PROCESS_EVIDENCE_DIGEST = (
    "17f1f2273f89241da8248773b452a86f734c0988cf24445e56a7914504f36489"
)
_LEGACY_PREDISPATCH_EFFECT_ACCOUNTING = {
    "host_rpc_count": 0,
    "model_request_count": 0,
    "provider_binding_created": False,
    "qualification_started": False,
    "registration_persisted": False,
    "usage_reservation_count": 0,
}
_PROVIDER_HOST_EXCLUSIVE_OPERATIONS = {
    Operation.BEGIN_PROVIDER_HOST_ENROLLMENT,
    Operation.COMPLETE_PROVIDER_HOST_ENROLLMENT,
    Operation.RECONCILE_PROVIDER_HOST_ENROLLMENT,
    Operation.REVOKE_PROVIDER_HOST_ENROLLMENT,
    Operation.RECONCILE_PROVIDER_HOST_LAUNCH,
    Operation.AUTHORIZE_EXHAUSTED_PROVIDER_REGISTRATION,
    Operation.MIGRATE_LEGACY_AUTHORITY_PREDISPATCH_REGISTRATION,
}
_PROVIDER_HOST_SHARED_OPERATIONS = {
    Operation.REGISTER_PROVIDER,
    Operation.RECOVER_PROVIDER_REGISTRATION_FAILURE,
    Operation.DISPOSE_PROVIDER_REGISTRATION_FAILURE,
    Operation.RECOVER_EXHAUSTED_PROVIDER_REGISTRATION,
    Operation.BEGIN_QUALIFICATION,
    Operation.AUTHORIZE_PROVIDER_QUALIFICATION_RETRY,
    Operation.RETRY_PROVIDER_QUALIFICATION,
    Operation.RECONCILE_PROVIDER_QUALIFICATION,
    Operation.RESERVE_ATTEMPT,
    Operation.AUTHORIZE_PROJECT_LAUNCH,
    Operation.BIND_PROVIDER_INPUT,
    Operation.EXECUTE_PROVIDER,
    Operation.PAUSE_ATTEMPT,
    Operation.RESUME_ATTEMPT,
    Operation.CANCEL_ATTEMPT,
    Operation.MIGRATE_LEGACY,
}
_PROVIDER_HOST_NEW_WORK_OPERATIONS = {
    Operation.REGISTER_PROVIDER,
    Operation.BEGIN_QUALIFICATION,
    Operation.RETRY_PROVIDER_QUALIFICATION,
    Operation.RESERVE_ATTEMPT,
    Operation.AUTHORIZE_PROJECT_LAUNCH,
    Operation.BIND_PROVIDER_INPUT,
    Operation.EXECUTE_PROVIDER,
    Operation.MIGRATE_LEGACY,
}


class _ProviderHostOperationGate:
    """Allow concurrent work while giving lifecycle changes an exclusive fence."""

    def __init__(self) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._active = 0
        self._exclusive = False
        self._exclusive_waiters = 0

    @contextmanager
    def shared(self) -> Iterator[None]:
        with self._condition:
            while self._exclusive or self._exclusive_waiters:
                self._condition.wait()
            self._active += 1
        try:
            yield
        finally:
            with self._condition:
                self._active -= 1
                self._condition.notify_all()

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        with self._condition:
            self._exclusive_waiters += 1
            try:
                while self._exclusive or self._active:
                    self._condition.wait()
                self._exclusive = True
            finally:
                self._exclusive_waiters -= 1
        try:
            yield
        finally:
            with self._condition:
                self._exclusive = False
                self._condition.notify_all()


@dataclass(frozen=True, slots=True)
class QualificationObservation:
    provider_instance_id: str
    process_ownership: dict[str, Any]
    started_at: str
    finished_at: str
    exit_status: int
    raw_version_output: str
    failure_reason: str | None = None
    authentication_probe: dict[str, Any] | None = None
    usage_observation: dict[str, Any] | None = None
    structured_output: dict[str, Any] | None = None
    production_command: tuple[str, ...] = ()
    prompt_digest: str | None = None
    schema_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ProcessObservation:
    pid: int
    creation_time: str
    executable: str
    executable_sha256: str
    restricted: bool
    integrity_level: str
    job_confined: bool


@dataclass(frozen=True, slots=True)
class CompletionObservation:
    evidence_digest: str
    exit_status: int
    normalized_result: str
    finished_at: str


@dataclass(frozen=True, slots=True)
class ExecutionObservation:
    process_id: int
    exit_status: int
    timed_out: bool
    stdout_path: str
    stderr_path: str
    provider_evidence_digest: str
    finished_at: str
    usage_observation: dict[str, Any] | None = None
    model_id: str | None = None
    reasoning_level: str | None = None
    command_digest: str | None = None
    prompt_digest: str | None = None
    schema_digest: str | None = None
    structured_event_digest: str | None = None
    failure_classification: str | None = None
    provider_host_envelope_digest: str | None = None
    provider_host_receipt_digest: str | None = None


class TrustedObserver(Protocol):
    def qualify(
        self, registration: dict[str, Any], challenge: str
    ) -> QualificationObservation: ...

    def register_provider(
        self,
        provider_id: str,
        executable: Path,
        client_sid: str,
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
        client_executable_handle: int | None = None,
        planned_registration_id: str | None = None,
        planned_setup_id: str | None = None,
        planned_challenge: str | None = None,
        recovering_registration: bool = False,
    ) -> dict[str, Any]: ...

    def validate_registered_executable(
        self, registration: dict[str, Any], client_executable_handle: int
    ) -> None: ...

    def recover_provider_registration_failure(
        self,
        registration_id: str,
        setup_id: str,
        challenge: str,
    ) -> dict[str, Any]: ...

    def observe_process(
        self, attempt: dict[str, Any], pid: int
    ) -> ProcessObservation: ...

    def execute_provider(
        self,
        registration: dict[str, Any],
        attempt: dict[str, Any],
        on_started: Callable[[ProcessObservation], None],
    ) -> ExecutionObservation: ...

    def preflight_provider(
        self, registration: dict[str, Any], attempt: dict[str, Any]
    ) -> dict[str, Any] | None: ...

    def read_exchange_file(
        self, value: object, label: str, maximum_bytes: int
    ) -> tuple[Path, bytes]: ...

    def observe_completion(
        self, attempt: dict[str, Any]
    ) -> CompletionObservation: ...


class ProvenanceReporter(Protocol):
    def build(
        self,
        request: Request,
        client_sid: str,
        *,
        installed_package_version: str,
        authority_key_id: str,
        authority_key_version: int,
        database_path: Path,
        database_identity: dict[str, Any] | None,
    ) -> dict[str, Any]: ...


class AuthorityServiceCore:
    """Service-owned lifecycle authority; callers never supply signed records."""

    def __init__(
        self,
        root: Path,
        *,
        observer: TrustedObserver | None = None,
        provenance_reporter: ProvenanceReporter | None = None,
        founder_capability_verifier: (
            ProductionFounderCapabilityVerifier
            | TestFounderCapabilityVerifier
            | None
        ) = None,
    ) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.store = AuthorityStore(self.root / "authority.db")
        self.store.migrate()
        self.keys = ServiceKeyRing(self.root / "keys")
        self.observer = observer
        self.provenance_reporter = provenance_reporter
        if founder_capability_verifier is not None and type(
            founder_capability_verifier
        ) not in {
            ProductionFounderCapabilityVerifier,
            TestFounderCapabilityVerifier,
        }:
            raise TypeError("Founder capability verifier type is not trusted")
        self.founder_capability_verifier = founder_capability_verifier
        self._provider_host_lock = threading.RLock()
        self._provider_host_operation_gate = _ProviderHostOperationGate()
        self.provider_host_enrollment: ProviderHostEnrollmentCoordinator | None = None
        self._provider_host_bootstrap: dict[str, Any] = {
            "state": "NOT_CONFIGURED",
            "failure_reason": None,
        }

    def begin_provider_host_initialization(self) -> None:
        with self._provider_host_lock:
            if self.provider_host_enrollment is not None:
                raise RuntimeError("Provider Host enrollment is already configured")
            self._provider_host_bootstrap = {
                "state": "INITIALIZING",
                "failure_reason": None,
            }

    def fail_provider_host_initialization(self, reason: str) -> None:
        if reason not in {
            "IDENTITY_INITIALIZATION_FAILED",
            "UNEXPECTED_INITIALIZATION_FAILURE",
        }:
            raise ValueError("Provider Host initialization failure is invalid")
        with self._provider_host_lock:
            if self.provider_host_enrollment is None:
                self._provider_host_bootstrap = {
                    "state": "UNAVAILABLE",
                    "failure_reason": reason,
                }

    def configure_provider_host_enrollment(
        self, coordinator: ProviderHostEnrollmentCoordinator
    ) -> None:
        with self._provider_host_lock:
            if self.provider_host_enrollment is not None:
                raise RuntimeError("Provider Host enrollment is already configured")
            coordinator.activate_current()
            self.provider_host_enrollment = coordinator
            self._provider_host_bootstrap = {
                "state": "READY",
                "failure_reason": None,
            }

    def dispatch(self, request: Request, client_sid: str) -> dict[str, Any]:
        if not client_sid:
            raise PermissionError("authority client identity is missing")
        try:
            self.store.consume_request(
                request.request_id,
                request.operation_id,
                request.nonce,
                client_sid,
            )
        except PermissionError:
            self.store.audit(
                uuid.uuid4().hex,
                "request_rejected",
                client_sid,
                None,
                {"operation": request.operation.value, "reason": "replay"},
            )
            raise
        handlers = {
            Operation.DIAGNOSTICS: self._diagnostics,
            Operation.AUDIT_PROVENANCE: self._audit_provenance,
            Operation.PROVIDER_HOST_ENROLLMENT_STATUS: (
                self._provider_host_enrollment_status
            ),
            Operation.BEGIN_PROVIDER_HOST_ENROLLMENT: (
                self._begin_provider_host_enrollment
            ),
            Operation.COMPLETE_PROVIDER_HOST_ENROLLMENT: (
                self._complete_provider_host_enrollment
            ),
            Operation.RECONCILE_PROVIDER_HOST_ENROLLMENT: (
                self._reconcile_provider_host_enrollment
            ),
            Operation.REVOKE_PROVIDER_HOST_ENROLLMENT: (
                self._revoke_provider_host_enrollment
            ),
            Operation.RECONCILE_PROVIDER_HOST_LAUNCH: (
                self._reconcile_provider_host_launch
            ),
            Operation.REGISTER_PROVIDER: self._register_provider,
            Operation.RECOVER_PROVIDER_REGISTRATION_FAILURE: (
                self._recover_provider_registration_failure
            ),
            Operation.MIGRATE_LEGACY_AUTHORITY_PREDISPATCH_REGISTRATION: (
                self._migrate_legacy_authority_predispatch_registration
            ),
            Operation.DISPOSE_PROVIDER_REGISTRATION_FAILURE: (
                self._dispose_provider_registration_failure
            ),
            Operation.AUTHORIZE_EXHAUSTED_PROVIDER_REGISTRATION: (
                self._authorize_exhausted_provider_registration
            ),
            Operation.RECOVER_EXHAUSTED_PROVIDER_REGISTRATION: (
                self._recover_exhausted_provider_registration
            ),
            Operation.BEGIN_QUALIFICATION: self._qualify_provider,
            Operation.AUTHORIZE_PROVIDER_QUALIFICATION_RETRY: (
                self._authorize_provider_qualification_retry
            ),
            Operation.RETRY_PROVIDER_QUALIFICATION: (
                self._retry_provider_qualification
            ),
            Operation.RECONCILE_PROVIDER_QUALIFICATION: (
                self._reconcile_provider_qualification
            ),
            Operation.FINALIZE_QUALIFICATION: self._internal_only,
            Operation.RESERVE_ATTEMPT: self._reserve_attempt,
            Operation.AUTHORIZE_PROJECT_LAUNCH: self._authorize_project_launch,
            Operation.REVOKE_PROJECT_LAUNCH: self._revoke_project_launch,
            Operation.BIND_PROVIDER_INPUT: self._bind_provider_input,
            Operation.EXECUTE_PROVIDER: self._execute_provider,
            Operation.RECORD_PROVIDER_START: self._record_provider_start,
            Operation.FINALIZE_COMPLETION: self._finalize_completion,
            Operation.QUERY_STATE: self._query_state,
            Operation.RECONCILE_EXECUTIVE_RESTORE: (
                self._reconcile_executive_restore
            ),
            Operation.BEGIN_EXECUTIVE_RESTORE_FENCE: (
                self._begin_executive_restore_fence
            ),
            Operation.CONFIRM_EXECUTIVE_RESTORE_FENCE: (
                self._confirm_executive_restore_fence
            ),
            Operation.COMPLETE_EXECUTIVE_RESTORE_FENCE: (
                self._complete_executive_restore_fence
            ),
            Operation.ABORT_EXECUTIVE_RESTORE_FENCE: (
                self._abort_executive_restore_fence
            ),
            Operation.RECOVER_EXECUTIVE_RESTORE_FENCE: (
                self._recover_executive_restore_fence
            ),
            Operation.VERIFY_EVIDENCE: self._verify_evidence,
            Operation.PAUSE_ATTEMPT: self._pause_attempt,
            Operation.RESUME_ATTEMPT: self._resume_attempt,
            Operation.CANCEL_ATTEMPT: self._cancel_attempt,
            Operation.REVOKE_REGISTRATION: self._revoke_registration,
            Operation.ROTATE_KEY: self._rotate_key,
            Operation.MIGRATE_LEGACY: self._migrate_legacy,
        }
        try:
            if request.operation == Operation.AUDIT_PROVENANCE:
                result = self._audit_provenance_request(
                    request, client_sid
                )
            elif request.operation in _PROVIDER_HOST_EXCLUSIVE_OPERATIONS:
                # Keep the signed zero-work observation, Host transition, and
                # Authority durable mutation in one Authority-local critical
                # section. Otherwise another named-pipe worker could begin a
                # setup/execution between revocation's zero-count check and its
                # durable enrollment transition.
                with self._provider_host_operation_gate.exclusive():
                    result = handlers[request.operation](
                        request.payload, client_sid
                    )
            elif request.operation in _PROVIDER_HOST_SHARED_OPERATIONS:
                with self._provider_host_operation_gate.shared():
                    if request.operation in _PROVIDER_HOST_NEW_WORK_OPERATIONS:
                        self._require_no_pending_host_launch_reconciliation()
                        if request.operation not in {
                            Operation.REGISTER_PROVIDER,
                            Operation.BEGIN_QUALIFICATION,
                            Operation.RETRY_PROVIDER_QUALIFICATION,
                        }:
                            self._require_no_pending_provider_operation_claims()
                    result = handlers[request.operation](
                        request.payload, client_sid
                    )
            else:
                result = handlers[request.operation](
                    request.payload, client_sid
                )
        except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as error:
            self.store.audit(
                request.operation_id,
                request.operation.value,
                client_sid,
                None,
                {
                    "outcome": "rejected",
                    "error_type": type(error).__name__,
                },
            )
            raise
        self.store.audit(
            request.operation_id,
            request.operation.value,
            client_sid,
            _object_id(result),
            {"outcome": "accepted"},
        )
        return result

    def _audit_provenance_request(
        self, request: Request, client_sid: str
    ) -> dict[str, Any]:
        _exact(request.payload, set())
        if self.provenance_reporter is None:
            raise RuntimeError(
                "Authority provenance reporter is unavailable"
            )
        try:
            database_identity = self.store.schema_identity()
        except (FileNotFoundError, OSError, RuntimeError, ValueError):
            database_identity = None
        report = self.provenance_reporter.build(
            request,
            client_sid,
            installed_package_version=SERVICE_VERSION,
            authority_key_id=self.keys.current_key_id,
            authority_key_version=self.keys.current_version,
            database_path=self.store.path,
            database_identity=database_identity,
        )
        return {
            "report": self.keys.sign(AUDIT_REPORT_PURPOSE, report)
        }

    def _audit_provenance(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        raise RuntimeError(
            "Authority provenance requires authenticated request binding"
        )

    def _diagnostics(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, set())
        allowed_evidence_root = getattr(
            self.observer, "allowed_evidence_root", None
        )
        provider_host = getattr(self.observer, "provider_host_status", None)
        with self._provider_host_lock:
            enrollment = self.provider_host_enrollment
            bootstrap = dict(self._provider_host_bootstrap)
        enrollment_status = enrollment.status() if enrollment is not None else None
        live_status = provider_host() if callable(provider_host) else None
        if enrollment_status is not None:
            provider_host_status = dict(enrollment_status)
            if (
                enrollment_status.get("state") == "ENROLLED_OFFLINE"
                and isinstance(live_status, dict)
                and live_status.get("online") is True
            ):
                provider_host_status.update(live_status)
                provider_host_status["enrollment_id"] = enrollment_status.get(
                    "enrollment_id"
                )
                provider_host_status["enrollment_generation"] = (
                    enrollment_status.get("enrollment_generation")
                )
            elif (
                enrollment_status.get("state") == "ENROLLED_OFFLINE"
                and isinstance(live_status, dict)
                and isinstance(live_status.get("failure_reason"), str)
            ):
                # Preserve durable enrollment truth while exposing the
                # sanitized, read-only handshake failure needed for supported
                # recovery. Never replace it with an optimistic online state.
                provider_host_status["failure_reason"] = live_status[
                    "failure_reason"
                ]
                provider_host_status["founder_action_required"] = live_status.get(
                    "founder_action_required",
                    "START_OR_REPAIR_PROVIDER_HOST",
                )
        elif bootstrap["state"] in {"INITIALIZING", "UNAVAILABLE"}:
            provider_host_status = (
                dict(live_status) if isinstance(live_status, dict) else {}
            )
            provider_host_status.update(
                {
                    "installed": bool(provider_host_status.get("installed", False)),
                    "online": False,
                    "state": bootstrap["state"],
                    "protocol_compatible": False,
                    "provider_state": "UNAVAILABLE",
                    "failure_reason": bootstrap["failure_reason"],
                }
            )
        elif isinstance(live_status, dict):
            provider_host_status = live_status
        else:
            provider_host_status = {
                "installed": False,
                "online": False,
                "state": bootstrap["state"],
                "protocol_compatible": False,
                "provider_state": "UNAVAILABLE",
                "failure_reason": bootstrap["failure_reason"],
            }
        reconciliation_registration_ids = sorted(
            str(record["trusted_registration_id"])
            for record in self.store.list_records("registrations")
            if record.get("service_state") == "UNCERTAIN"
            and record.get("registration_schema_version") in {4, 5}
            and record.get("registration_lifecycle") == "QUALIFIED"
            and isinstance(record.get("trusted_registration_id"), str)
            and record.get("trusted_registration_id")
            and isinstance(record.get("qualification_evidence_id"), str)
            and record.get("qualification_evidence_id")
            and (
                qualification := self.store.get(
                    "qualifications", str(record["qualification_evidence_id"])
                )
            )
            is not None
            and qualification.get("service_state") == "UNCERTAIN"
            and isinstance(qualification.get("evidence"), dict)
            and qualification["evidence"].get("registration_id")
            == record.get("trusted_registration_id")
        )
        provider_host_status = dict(provider_host_status)
        pending_host_reconciliations: list[dict[str, object]] = []
        with self._provider_host_lock:
            enrollment_coordinator = self.provider_host_enrollment
        if enrollment_coordinator is not None:
            pending_host_reconciliations = (
                enrollment_coordinator.pending_launch_reconciliations()
            )
        pending_provider_claims = self._pending_provider_operation_claims()
        provider_host_status.setdefault("active_or_uncertain_launch_count", None)
        provider_host_status.setdefault("active_launch_count", None)
        provider_host_status.setdefault("uncertain_launch_count", None)
        provider_host_status.setdefault("launch_state_proven", False)
        provider_host_status.setdefault("launches", [])
        provider_host_status["launch_reconciliation_pending_count"] = len(
            pending_host_reconciliations
        )
        provider_host_status["launch_reconciliation_pending_launches"] = (
            pending_host_reconciliations
        )
        provider_host_status["registration_recovery_pending_count"] = len(
            pending_provider_claims["registrations"]
        )
        provider_host_status["registration_recovery_ids"] = (
            pending_provider_claims["registrations"]
        )
        provider_host_status["registration_failure_disposition_pending_count"] = len(
            pending_provider_claims["registration_failures"]
        )
        provider_host_status["registration_failure_disposition_ids"] = (
            pending_provider_claims["registration_failures"]
        )
        provider_host_status["registration_retry_authorized_count"] = len(
            pending_provider_claims["registration_retries"]
        )
        provider_host_status["registration_retry_authorized_ids"] = (
            pending_provider_claims["registration_retries"]
        )
        provider_host_status["registration_replacement_authorized_count"] = len(
            pending_provider_claims["registration_replacements"]
        )
        provider_host_status["registration_replacement_authorized_ids"] = (
            pending_provider_claims["registration_replacements"]
        )
        provider_host_status["qualification_recovery_pending_count"] = len(
            pending_provider_claims["qualifications"]
        )
        provider_host_status["qualification_recovery_ids"] = (
            pending_provider_claims["qualifications"]
        )
        provider_host_status["qualification_retry_authorized_count"] = len(
            pending_provider_claims["qualification_retries"]
        )
        provider_host_status["qualification_retry_authorized_ids"] = (
            pending_provider_claims["qualification_retries"]
        )
        provider_host_status["qualification_reconciliation_required"] = bool(
            reconciliation_registration_ids
        )
        provider_host_status["qualification_reconciliation_count"] = len(
            reconciliation_registration_ids
        )
        provider_host_status["qualification_reconciliation_registration_ids"] = (
            reconciliation_registration_ids
        )
        launches = provider_host_status.get("launches")
        active_launches = launches if isinstance(launches, list) else []
        if reconciliation_registration_ids:
            provider_host_status["provider_state"] = "QUALIFICATION_UNCERTAIN"
            provider_host_status["founder_action_required"] = (
                "RECONCILE_PROVIDER_QUALIFICATION"
            )
        elif pending_host_reconciliations:
            provider_host_status["provider_state"] = (
                "HOST_LAUNCH_RECONCILIATION_UNCERTAIN"
            )
            provider_host_status["founder_action_required"] = (
                "RECONCILE_PROVIDER_HOST_LAUNCH"
            )
        elif provider_host_status.get("active_or_uncertain_launch_count"):
            operations = {
                str(value.get("operation", ""))
                for value in active_launches
                if isinstance(value, dict)
            }
            if "QUALIFY" in operations:
                provider_host_status["provider_state"] = (
                    "QUALIFICATION_EXECUTION_UNCERTAIN"
                )
                provider_host_status["founder_action_required"] = (
                    "FOUNDER_DISPOSITION_REQUIRED"
                )
            else:
                provider_host_status["provider_state"] = "HOST_LAUNCH_UNCERTAIN"
                provider_host_status["founder_action_required"] = (
                    "RECONCILE_PROVIDER_HOST_LAUNCH"
                )
        elif pending_provider_claims["registration_failures"]:
            provider_host_status["provider_state"] = (
                "REGISTRATION_FAILURE_DISPOSITION_REQUIRED"
            )
            provider_host_status["founder_action_required"] = (
                "DISPOSE_PROVIDER_REGISTRATION_FAILURE"
            )
        elif pending_provider_claims["registration_retries"]:
            provider_host_status["provider_state"] = (
                "REGISTRATION_RETRY_AUTHORIZED"
            )
            provider_host_status["founder_action_required"] = (
                "RESUME_EXACT_PROVIDER_REGISTRATION"
            )
        elif pending_provider_claims["registration_replacements"]:
            provider_host_status["provider_state"] = (
                "REGISTRATION_REPLACEMENT_AUTHORIZED"
            )
            provider_host_status["founder_action_required"] = (
                "RESUME_EXACT_PROVIDER_REGISTRATION"
            )
        elif pending_provider_claims["qualification_retries"]:
            provider_host_status["provider_state"] = (
                "QUALIFICATION_RETRY_AUTHORIZED"
            )
            provider_host_status["founder_action_required"] = (
                "RESUME_EXACT_PROVIDER_QUALIFICATION"
            )
        elif pending_provider_claims["qualifications"]:
            provider_host_status["provider_state"] = "QUALIFICATION_RECOVERY_REQUIRED"
            provider_host_status["founder_action_required"] = (
                "RESUME_EXACT_PROVIDER_QUALIFICATION"
            )
        elif pending_provider_claims["registrations"]:
            provider_host_status["provider_state"] = "REGISTRATION_RECOVERY_REQUIRED"
            provider_host_status["founder_action_required"] = (
                "RESUME_EXACT_PROVIDER_REGISTRATION"
            )
        return {
            "service_version": SERVICE_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SERVICE_SCHEMA_VERSION,
            "service_root": str(self.root),
            "service_key_id": self.keys.current_key_id,
            "service_key_version": self.keys.current_version,
            "client_sid": client_sid,
            "observer_available": self.observer is not None,
            "registrations": len(self.store.list_records("registrations")),
            "qualifications": len(self.store.list_records("qualifications")),
            "attempts": len(self.store.list_records("attempts")),
            "allowed_evidence_root": (
                str(allowed_evidence_root)
                if isinstance(allowed_evidence_root, Path)
                else None
            ),
            "client_exchange_root": (
                str(allowed_evidence_root.parent)
                if isinstance(allowed_evidence_root, Path)
                else None
            ),
            "provider_host": provider_host_status,
        }

    def _provider_host_enrollment_status(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, set())
        coordinator = self._provider_host_enrollment_coordinator()
        return coordinator.status()

    def _begin_provider_host_enrollment(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        return self._provider_host_enrollment_coordinator().begin(
            payload, client_sid
        )

    def _complete_provider_host_enrollment(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        return self._provider_host_enrollment_coordinator().complete(
            payload, client_sid
        )

    def _reconcile_provider_host_enrollment(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        return self._provider_host_enrollment_coordinator().reconcile(
            payload, client_sid
        )

    def _revoke_provider_host_enrollment(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        # A one-shot registration retry authorization is deliberately dormant:
        # it has no Host launch or external effect and must survive the exact
        # version-bound Host replacement needed before it can be activated.
        self._require_no_pending_provider_operation_claims(
            allow_registration_retry_authorized=True,
            allow_registration_replacement_authorized=True,
            allow_qualification_retry_authorized=True,
        )
        return self._provider_host_enrollment_coordinator().revoke(
            payload, client_sid
        )

    def _reconcile_provider_host_launch(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        return self._provider_host_enrollment_coordinator().reconcile_launch(
            payload, client_sid
        )

    def _provider_host_enrollment_coordinator(
        self,
    ) -> ProviderHostEnrollmentCoordinator:
        with self._provider_host_lock:
            coordinator = self.provider_host_enrollment
        if coordinator is None:
            raise PermissionError("Provider Host enrollment is not configured")
        return coordinator

    def _require_no_pending_host_launch_reconciliation(self) -> None:
        with self._provider_host_lock:
            coordinator = self.provider_host_enrollment
        if coordinator is not None and coordinator.pending_launch_reconciliations():
            raise PermissionError(
                "Provider Host launch reconciliation must complete before provider work"
            )

    def _pending_provider_operation_claims(self) -> dict[str, list[str]]:
        registrations: list[str] = []
        registration_failures: list[str] = []
        registration_retries: list[str] = []
        registration_replacements: list[str] = []
        for record in self.store.list_records("registrations"):
            state = record.get("service_state")
            if state not in {
                "REGISTRATION_REPLACEMENT_AUTHORIZED",
                "REGISTRATION_RETRY_AUTHORIZED",
                "REGISTRATION_STARTED",
                "REGISTRATION_FAILED",
            }:
                continue
            start = record.get("start")
            identifier = (
                start.get("registration_id")
                if isinstance(start, dict)
                else None
            )
            if not isinstance(identifier, str) or not identifier:
                raise RuntimeError(
                    "Provider registration recovery claim is malformed"
                )
            if state == "REGISTRATION_RETRY_AUTHORIZED":
                registration_retries.append(identifier)
            elif state == "REGISTRATION_REPLACEMENT_AUTHORIZED":
                registration_replacements.append(identifier)
            else:
                registrations.append(identifier)
            if state == "REGISTRATION_FAILED":
                registration_failures.append(identifier)
        qualifications: list[str] = []
        qualification_retries: list[str] = []
        for record in self.store.list_records("qualifications"):
            state = record.get("service_state")
            if state == "QUALIFICATION_RETRY_AUTHORIZED":
                authorization = record.get("retry_authorization")
                identifier = (
                    authorization.get("retry_qualification_id")
                    if isinstance(authorization, dict)
                    else None
                )
                if not isinstance(identifier, str) or not identifier:
                    raise RuntimeError(
                        "Provider qualification retry authorization is malformed"
                    )
                qualification_retries.append(identifier)
                continue
            if state != "EXECUTION_STARTED":
                continue
            start = record.get("start")
            start_id = start.get("id") if isinstance(start, dict) else None
            if (
                not isinstance(start_id, str)
                or not start_id.endswith(":started")
            ):
                raise RuntimeError(
                    "Provider qualification recovery claim is malformed"
                )
            qualifications.append(start_id.removesuffix(":started"))
        registrations.sort()
        registration_failures.sort()
        registration_retries.sort()
        registration_replacements.sort()
        qualifications.sort()
        qualification_retries.sort()
        return {
            "registrations": registrations,
            "registration_failures": registration_failures,
            "registration_retries": registration_retries,
            "registration_replacements": registration_replacements,
            "qualifications": qualifications,
            "qualification_retries": qualification_retries,
        }

    def _require_no_pending_provider_operation_claims(
        self,
        *,
        allow_registration_retry_authorized: bool = False,
        allow_registration_replacement_authorized: bool = False,
        allow_qualification_retry_authorized: bool = False,
    ) -> None:
        claims = self._pending_provider_operation_claims()
        if (
            claims["registrations"]
            or claims["qualifications"]
            or (
                claims["qualification_retries"]
                and not allow_qualification_retry_authorized
            )
            or (
                claims["registration_retries"]
                and not allow_registration_retry_authorized
            )
            or (
                claims["registration_replacements"]
                and not allow_registration_replacement_authorized
            )
        ):
            raise PermissionError(
                "Provider registration or qualification recovery must complete first"
            )

    def _authorize_project_launch(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        if set(payload) != {"founder_capability"}:
            raise PermissionError(
                "cryptographically verified Founder capability is required"
            )
        value = payload["founder_capability"]
        verifier = self.founder_capability_verifier
        if verifier is None or not isinstance(value, dict):
            raise PermissionError(
                "cryptographically verified Founder capability is required"
            )
        try:
            capability = verifier.verify(value)
        except (KeyError, PermissionError, TypeError, ValueError) as error:
            raise PermissionError(
                "Founder authorization capability authentication failed"
            ) from error
        now = datetime.now(UTC)
        expires_at = datetime.fromisoformat(capability.expires_at)
        issued_at = datetime.fromisoformat(capability.issued_at)
        if (
            expires_at <= now
            or issued_at > now
            or capability.authorization_kind != "PROJECT_LAUNCH"
            or capability.protected_action != "DELEGATE_CHARTER"
            or capability.usage != "ONE_TIME_GENERATION"
            or capability.authorization_generation != capability.charter_revision
            or capability.revocation_epoch
            != capability.authorization_generation - 1
        ):
            raise PermissionError("Founder authorization capability is stale or invalid")
        generation = capability.authorization_generation
        project_id = capability.project_id
        identifier = (
            f"launch-authorization:{project_id}:generation:{generation}"
        )
        capability_value_digest = capability_digest(capability)
        signature_digest = capability_signature_digest(capability)
        record = self.keys.sign(
            "project-launch-authorization",
            {
                "id": identifier,
                "kind": "project_launch_authorization",
                "schema_version": 2,
                "project_id": project_id,
                "charter_id": capability.charter_id,
                "charter_revision": capability.charter_revision,
                "delegation_id": capability.approval_record_id,
                "founder_approval_event_id": capability.approval_event_id,
                "founder_approval_event_digest": (
                    capability.approval_event_digest
                ),
                "founder_approval_digest": capability.approval_digest,
                "founder_authenticated_session_id": (
                    capability.founder_authenticated_session_id
                ),
                "founder_principal_sid": capability.founder_principal_sid,
                "founder_challenge_id": capability.challenge_id,
                "founder_challenge_proof_digest": (
                    capability.challenge_proof_digest
                ),
                "founder_action_digest": capability.action_digest,
                "founder_capability_id": capability.capability_id,
                "founder_capability_digest": capability_value_digest,
                "founder_capability_signature_digest": signature_digest,
                "founder_capability_issuer_id": capability.issuer_id,
                "founder_capability_issuer_key_id": capability.issuer_key_id,
                "authorization_generation": generation,
                "revocation_epoch": capability.revocation_epoch,
                "authorized_client_sid": client_sid,
                "expires_at": capability.expires_at,
                "authorized_at": capability.issued_at,
            },
        )
        durable = self.store.create_launch_authorization(
            identifier,
            generation,
            client_sid,
            record,
            {
                "capability_id": capability.capability_id,
                "project_id": project_id,
                "approval_record_id": capability.approval_record_id,
                "approval_event_id": capability.approval_event_id,
                "founder_session_id": (
                    capability.founder_authenticated_session_id
                ),
                "challenge_id": capability.challenge_id,
                "approval_digest": capability.approval_digest,
                "challenge_proof_digest": (
                    capability.challenge_proof_digest
                ),
                "capability_digest": capability_value_digest,
                "signature_digest": signature_digest,
                "generation": generation,
                "authorization_id": identifier,
            },
        )
        return {"authorization": durable}

    def _revoke_project_launch(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, {"project_id", "authorization_generation"})
        project_id = _text(payload["project_id"], "project ID")
        generation = _positive_int(
            payload["authorization_generation"], "authorization generation"
        )
        identifier = (
            f"launch-authorization:{project_id}:generation:{generation}"
        )
        prior = self.store.get("launch_authorizations", identifier)
        if (
            prior is None
            or prior.get("authorized_client_sid") != client_sid
            or prior.get("authorization_generation") != generation
        ):
            raise PermissionError("launch authorization revocation is misbound")
        record = self.keys.sign(
            "project-launch-revocation",
            {
                **{key: value for key, value in prior.items() if key != "service_state"},
                "kind": "project_launch_revocation",
                "revocation_epoch": generation,
                "revoked_at": _now(),
            },
        )
        canceled = self.store.revoke_launch_authorization(
            identifier, generation, client_sid, record
        )
        return {
            "authorization_id": identifier,
            "revocation_epoch": generation,
            "canceled_attempt_ids": list(canceled),
        }

    def _recover_provider_registration_failure(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, {"registration_id"})
        registration_id = _text(payload["registration_id"], "registration ID")
        current = self.store.get("registrations", registration_id)
        if current is None:
            raise PermissionError("provider registration recovery claim is absent")
        state = str(current.pop("service_state", ""))
        if state == "REGISTRATION_FAILED":
            failure = current.get("failure")
            if (
                not isinstance(failure, dict)
                or not self.keys.verify("provider-registration-failure", failure)
                or current.get("failure_digest") != _canonical_digest(failure)
            ):
                raise PermissionError(
                    "provider registration failure claim is malformed"
                )
            return {
                "registration_id": registration_id,
                "registration_failed": failure,
                "state": "REGISTRATION_FAILED",
            }
        start = current.get("start")
        if (
            state != "REGISTRATION_STARTED"
            or not isinstance(start, dict)
            or not self.keys.verify("provider-registration-start", start)
            or start.get("registration_id") != registration_id
            or start.get("authorization_reference") != client_sid
            or not isinstance(start.get("setup_id"), str)
            or not isinstance(start.get("event_challenge"), str)
        ):
            raise PermissionError(
                "provider registration is not eligible for failure recovery"
            )
        attempt_generation = start.get("attempt_generation", 1)
        if (
            isinstance(attempt_generation, bool)
            or not isinstance(attempt_generation, int)
            or attempt_generation not in {1, 2}
        ):
            raise PermissionError(
                "provider registration recovery generation is invalid"
            )
        observer = self.observer
        if observer is None or not hasattr(
            observer, "recover_provider_registration_failure"
        ):
            raise PermissionError(
                "provider registration failure recovery is unavailable"
            )
        terminal_failure = observer.recover_provider_registration_failure(
            registration_id,
            str(start["setup_id"]),
            str(start["event_challenge"]),
        )
        return self._commit_provider_registration_failure(
            registration_id,
            str(start["setup_id"]),
            attempt_generation,
            client_sid,
            terminal_failure,
        )

    def _migrate_legacy_authority_predispatch_registration(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        """Dispose the exact 1.7.47 Claude pre-RPC defect without inventing a Host result."""

        _exact(
            payload,
            {
                "registration_id",
                "enrollment_id",
                "legacy_authority_version",
                "legacy_authority_package_sha256",
                "legacy_host_version",
                "legacy_host_executable_sha256",
                "legacy_host_manifest_sha256",
                "effect_accounting",
                "offline_host_process_evidence",
                "founder_capability",
            },
        )
        registration_id = _text(payload["registration_id"], "registration ID")
        enrollment_id = _text(payload["enrollment_id"], "enrollment ID")
        if (
            payload["legacy_authority_version"]
            != _LEGACY_PREDISPATCH_AUTHORITY_VERSION
            or _sha256_text(
                payload["legacy_authority_package_sha256"],
                "legacy Authority package digest",
            )
            != _LEGACY_PREDISPATCH_AUTHORITY_PACKAGE_SHA256
            or payload["legacy_host_version"] != _LEGACY_PREDISPATCH_HOST_VERSION
            or _sha256_text(
                payload["legacy_host_executable_sha256"],
                "legacy Host executable digest",
            )
            != _LEGACY_PREDISPATCH_HOST_EXECUTABLE_SHA256
            or _sha256_text(
                payload["legacy_host_manifest_sha256"],
                "legacy Host manifest digest",
            )
            != _LEGACY_PREDISPATCH_HOST_MANIFEST_SHA256
            or payload["effect_accounting"]
            != _LEGACY_PREDISPATCH_EFFECT_ACCOUNTING
        ):
            raise PermissionError(
                "legacy Authority predispatch migration release binding differs"
            )
        current = self.store.get("registrations", registration_id)
        enrollment = self.store.get("provider_host_enrollments", enrollment_id)
        if current is None or enrollment is None:
            raise PermissionError(
                "legacy Authority predispatch migration checkpoint is absent"
            )
        current_state = str(current.pop("service_state", ""))
        enrollment_state = str(enrollment.pop("service_state", ""))
        if (
            current_state == "REGISTRATION_RETRY_AUTHORIZED"
            and enrollment_state == "REVOKED"
        ):
            migration = current.get("predispatch_migration")
            enrollment_migration = enrollment.get("predispatch_migration")
            if (
                not isinstance(migration, dict)
                or not self.keys.verify(
                    "legacy-authority-predispatch-migration", migration
                )
                or migration != enrollment_migration
                or current.get("predispatch_migration_digest")
                != _canonical_digest(migration)
                or enrollment.get("predispatch_migration_digest")
                != _canonical_digest(migration)
                or migration.get("registration_id") != registration_id
                or migration.get("enrollment_id") != enrollment_id
            ):
                raise PermissionError(
                    "legacy Authority predispatch migration replay differs"
                )
            coordinator = self._provider_host_enrollment_coordinator()
            replay_binding_fields = {
                "action",
                "attempt_generation",
                "authorization_generation",
                "effect_accounting",
                "enrollment_generation",
                "enrollment_id",
                "event_challenge_digest",
                "legacy_authority_package_sha256",
                "legacy_authority_version",
                "legacy_host_executable_sha256",
                "legacy_host_manifest_sha256",
                "legacy_host_version",
                "offline_host_process_evidence_digest",
                "registration_id",
                "request_identity_digest",
                "retry_attempt_generation",
                "setup_id",
            }
            replay_binding = {
                name: migration[name] for name in replay_binding_fields
            }
            replay_capability = coordinator.verify_founder_action(
                payload["founder_capability"],
                client_sid,
                action="LEGACY_AUTHORITY_PREDISPATCH_MIGRATION",
                action_digest=structured_digest(replay_binding),
                generation=28,
            )
            if (
                capability_digest(replay_capability)
                != migration.get("founder_capability_digest")
                or _canonical_digest(payload["offline_host_process_evidence"])
                != migration.get("offline_host_process_evidence_digest")
            ):
                raise PermissionError(
                    "legacy Authority predispatch migration replay authority differs"
                )
            coordinator.deactivate({**enrollment, "service_state": "REVOKED"})
            return {
                "registration_id": registration_id,
                "registration_state": "REGISTRATION_RETRY_AUTHORIZED",
                "attempt_generation": 2,
                "enrollment_id": enrollment_id,
                "enrollment_state": "REVOKED",
                "migration": migration,
                "migration_digest": _canonical_digest(migration),
                "revocation": enrollment["revocation"],
            }
        if current_state != "REGISTRATION_STARTED" or enrollment_state != "ACTIVE":
            raise PermissionError(
                "legacy Authority predispatch migration checkpoint changed"
            )
        request_binding = current.get("request_binding")
        start = current.get("start")
        if not isinstance(request_binding, dict) or not isinstance(start, dict):
            raise PermissionError(
                "legacy Authority predispatch registration claim is malformed"
            )
        _validate_legacy_claude_predispatch_claim(
            registration_id=registration_id,
            client_sid=client_sid,
            request_binding=request_binding,
            request_identity_digest=current.get("request_identity_digest"),
            start=start,
            verify=self.keys.verify,
        )
        pending = self._pending_provider_operation_claims()
        if (
            pending["registrations"] != [registration_id]
            or pending["registration_failures"]
            or pending["registration_retries"]
            or pending["registration_replacements"]
            or pending["qualifications"]
            or pending["qualification_retries"]
            or any(
                value.get("registration_id") == registration_id
                for value in self.store.list_records("qualifications")
            )
        ):
            raise PermissionError(
                "legacy Authority predispatch migration requires one exact pending claim"
            )
        proposal = enrollment.get("proposal")
        receipt = enrollment.get("receipt")
        if not isinstance(proposal, dict) or not isinstance(receipt, dict):
            raise PermissionError("legacy Provider Host enrollment is malformed")
        coordinator = self._provider_host_enrollment_coordinator()
        validated_enrollment = coordinator.validate_completed_enrollment_record(
            enrollment,
            expected_enrollment_id=enrollment_id,
        )
        proposal_payload = validated_enrollment["proposal"]
        runtime = validated_enrollment["receipt"]["runtime_configuration"]
        installation = proposal_payload.get("installation")
        user_binding = proposal_payload.get("user_binding")
        authority_peer = runtime.get("authority_peer")
        if (
            enrollment.get("enrollment_id") != enrollment_id
            or enrollment.get("enrollment_generation") != 27
            or enrollment.get("launch_reconciliation_claims", []) != []
            or not isinstance(installation, dict)
            or not isinstance(user_binding, dict)
            or not isinstance(authority_peer, dict)
            or installation.get("package_version")
            != _LEGACY_PREDISPATCH_HOST_VERSION
            or str(installation.get("executable_sha256", "")).casefold()
            != _LEGACY_PREDISPATCH_HOST_EXECUTABLE_SHA256
            or str(installation.get("manifest_sha256", "")).casefold()
            != _LEGACY_PREDISPATCH_HOST_MANIFEST_SHA256
            or str(authority_peer.get("executable_sha256", "")).casefold()
            != _LEGACY_PREDISPATCH_AUTHORITY_PACKAGE_SHA256
        ):
            raise PermissionError(
                "legacy Provider Host enrollment does not match the bounded defect"
            )
        offline_evidence = _validated_offline_host_process_evidence(
            payload["offline_host_process_evidence"],
            installation=installation,
            user_binding=user_binding,
            allowed_historical_digest=(
                _LEGACY_PREDISPATCH_OFFLINE_HOST_PROCESS_EVIDENCE_DIGEST
            ),
        )
        request_identity_digest = _sha256_text(
            current.get("request_identity_digest"),
            "registration request identity digest",
        )
        action_binding = {
            "action": "LEGACY_AUTHORITY_PREDISPATCH_MIGRATION",
            "attempt_generation": 1,
            "authorization_generation": 28,
            "effect_accounting": dict(_LEGACY_PREDISPATCH_EFFECT_ACCOUNTING),
            "enrollment_generation": 27,
            "enrollment_id": enrollment_id,
            "event_challenge_digest": hashlib.sha256(
                str(start["event_challenge"]).encode("utf-8")
            ).hexdigest(),
            "legacy_authority_package_sha256": (
                _LEGACY_PREDISPATCH_AUTHORITY_PACKAGE_SHA256
            ),
            "legacy_authority_version": _LEGACY_PREDISPATCH_AUTHORITY_VERSION,
            "legacy_host_executable_sha256": (
                _LEGACY_PREDISPATCH_HOST_EXECUTABLE_SHA256
            ),
            "legacy_host_manifest_sha256": (
                _LEGACY_PREDISPATCH_HOST_MANIFEST_SHA256
            ),
            "legacy_host_version": _LEGACY_PREDISPATCH_HOST_VERSION,
            "offline_host_process_evidence_digest": _canonical_digest(
                offline_evidence
            ),
            "registration_id": registration_id,
            "request_identity_digest": request_identity_digest,
            "retry_attempt_generation": 2,
            "setup_id": start["setup_id"],
        }
        capability = coordinator.verify_founder_action(
            payload["founder_capability"],
            client_sid,
            action="LEGACY_AUTHORITY_PREDISPATCH_MIGRATION",
            action_digest=structured_digest(action_binding),
            generation=28,
        )
        capability_value_digest = capability_digest(capability)
        signature_digest = capability_signature_digest(capability)
        migrated_at = _now()
        migration = self.keys.sign(
            "legacy-authority-predispatch-migration",
            {
                **action_binding,
                "authorized_client_sid": client_sid,
                "founder_approval_event_digest": capability.approval_event_digest,
                "founder_approval_event_id": capability.approval_event_id,
                "founder_capability_digest": capability_value_digest,
                "founder_capability_id": capability.capability_id,
                "founder_capability_signature_digest": signature_digest,
                "founder_session_id": capability.founder_authenticated_session_id,
                "migration_id": (
                    f"legacy-predispatch-migration:{registration_id}:generation:2"
                ),
                "migrated_at": migrated_at,
                "offline_host_process_evidence": offline_evidence,
            },
        )
        migration_digest = _canonical_digest(migration)
        retry_setup_id = "provider-registration-probe:" + hashlib.sha256(
            (registration_id + "\0setup-v2").encode("utf-8")
        ).hexdigest()[:32]
        retry_start = self.keys.sign(
            "provider-registration-start",
            {
                "id": f"{registration_id}:started:g2",
                "kind": "provider_registration_started",
                "schema_version": 2,
                "registration_id": registration_id,
                "setup_id": retry_setup_id,
                "attempt_generation": 2,
                "authorization_reference": client_sid,
                "event_challenge": secrets.token_hex(32),
                "predispatch_migration_digest": migration_digest,
                "started_at": migrated_at,
            },
        )
        retry_payload = {
            "kind": "provider_registration_retry_authorized",
            "request_binding": request_binding,
            "request_identity_digest": request_identity_digest,
            "start": retry_start,
            "attempt_generation": 2,
            "predispatch_migration": migration,
            "predispatch_migration_digest": migration_digest,
        }
        receipt_digest = structured_digest(receipt)
        revocation = coordinator.authority_signer.sign(
            ENROLLMENT_REVOCATION_PURPOSE,
            {
                "authority_id": coordinator.authority_signer.identity,
                "authority_key_id": coordinator.authority_signer.key_id,
                "enrollment_generation": 27,
                "enrollment_id": enrollment_id,
                "host_id": str(proposal_payload["host_id"]),
                "receipt_digest": receipt_digest,
                "revoked_at": migrated_at,
                "service_key_id": coordinator.service_key_id,
                "state": "REVOKED",
            },
        )
        revoked_enrollment = {
            **enrollment,
            "predispatch_migration": migration,
            "predispatch_migration_digest": migration_digest,
            "revocation_capability_digest": capability_value_digest,
            "revocation": revocation,
            "revoked_at": migrated_at,
            "updated_at": migrated_at,
        }
        authorization_id = (
            f"legacy-predispatch-migration:{registration_id}:authorization:28"
        )
        consumption = {
            "capability_id": capability.capability_id,
            "project_id": capability.project_id,
            "approval_record_id": capability.approval_record_id,
            "approval_event_id": capability.approval_event_id,
            "founder_session_id": capability.founder_authenticated_session_id,
            "challenge_id": capability.challenge_id,
            "approval_digest": capability.approval_digest,
            "challenge_proof_digest": capability.challenge_proof_digest,
            "capability_digest": capability_value_digest,
            "signature_digest": signature_digest,
            "generation": 28,
            "authorization_id": authorization_id,
        }
        self.store.migrate_legacy_predispatch_registration(
            registration_id,
            enrollment_id,
            expected_request_identity_digest=request_identity_digest,
            registration_payload=retry_payload,
            enrollment_payload=revoked_enrollment,
            consumption=consumption,
        )
        coordinator.deactivate({**revoked_enrollment, "service_state": "REVOKED"})
        return {
            "registration_id": registration_id,
            "registration_state": "REGISTRATION_RETRY_AUTHORIZED",
            "attempt_generation": 2,
            "enrollment_id": enrollment_id,
            "enrollment_state": "REVOKED",
            "migration": migration,
            "migration_digest": migration_digest,
            "revocation": revocation,
        }

    def _commit_provider_registration_failure(
        self,
        registration_id: str,
        setup_id: str,
        attempt_generation: int,
        client_sid: str,
        terminal_failure: dict[str, Any],
    ) -> dict[str, Any]:
        terminal_failure = _validated_registration_terminal_failure(
            terminal_failure
        )
        failure = self.keys.sign(
            "provider-registration-failure",
            {
                "id": (
                    f"{registration_id}:failure:generation:{attempt_generation}"
                ),
                "kind": "provider_registration_failure",
                "schema_version": 1,
                "registration_id": registration_id,
                "setup_id": setup_id,
                "attempt_generation": attempt_generation,
                "authorization_reference": client_sid,
                "failure_stage": terminal_failure["failure_stage"],
                "failure_code": terminal_failure["failure_code"],
                "process_result": terminal_failure["process_result"],
                "setup_result_digest": terminal_failure["setup_result_digest"],
                "setup_envelope_digest": terminal_failure[
                    "setup_envelope_digest"
                ],
                "effect_accounting": {
                    "registration_persisted": False,
                    "qualification_started": False,
                    "model_request_count": 0,
                    "provider_binding_created": False,
                    "usage_reservation_count": 0,
                },
                "failed_at": _now(),
            },
        )
        prior = self.store.get("registrations", registration_id)
        if prior is None or prior.pop("service_state", None) != "REGISTRATION_STARTED":
            raise PermissionError(
                "Provider registration failure claim changed before commit"
            )
        failed_claim = {
            "kind": "provider_registration_failed",
            "request_binding": prior["request_binding"],
            "request_identity_digest": prior["request_identity_digest"],
            "start": prior["start"],
            "attempt_generation": attempt_generation,
            "failure": failure,
            "failure_digest": _canonical_digest(failure),
        }
        if "predispatch_migration" in prior:
            migration = prior.get("predispatch_migration")
            prior_start = prior.get("start")
            if (
                not isinstance(migration, dict)
                or not isinstance(prior_start, dict)
                or not self.keys.verify(
                    "legacy-authority-predispatch-migration", migration
                )
                or prior.get("predispatch_migration_digest")
                != _canonical_digest(migration)
                or prior_start.get("predispatch_migration_digest")
                != _canonical_digest(migration)
            ):
                raise PermissionError(
                    "Provider registration predispatch migration changed before failure"
                )
            failed_claim.update(
                {
                    "predispatch_migration": migration,
                    "predispatch_migration_digest": _canonical_digest(migration),
                }
            )
        if "registration_lineage" in prior:
            lineage = _validated_registration_replacement_lineage(
                prior.get("registration_lineage"),
                self.keys.verify,
                require_current_release=False,
            )
            if prior.get("registration_lineage_digest") != _canonical_digest(
                lineage
            ):
                raise PermissionError(
                    "Provider registration replacement lineage changed before failure"
                )
            failed_claim.update(
                {
                    "family_generation": 2,
                    "predecessor_registration_id": lineage[
                        "predecessor_registration_id"
                    ],
                    "predecessor_failure_digest": lineage[
                        "predecessor_failure_digest"
                    ],
                    "registration_lineage": lineage,
                    "registration_lineage_digest": _canonical_digest(lineage),
                }
            )
        self.store.transition(
            "registrations",
            registration_id,
            "REGISTRATION_STARTED",
            "REGISTRATION_FAILED",
            failed_claim,
        )
        return {
            "registration_id": registration_id,
            "registration_failed": failure,
            "state": "REGISTRATION_FAILED",
        }

    def _dispose_provider_registration_failure(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(
            payload,
            {
                "registration_id",
                "failure_digest",
                "disposition",
                "attempt_generation",
                "founder_capability",
            },
        )
        registration_id = _text(payload["registration_id"], "registration ID")
        failure_digest = _sha256_text(
            payload["failure_digest"], "registration failure digest"
        )
        disposition = _choice(payload["disposition"], {"ABANDON", "RETRY_ONCE"})
        attempt_generation = _positive_int(
            payload["attempt_generation"], "registration attempt generation"
        )
        if disposition == "RETRY_ONCE" and attempt_generation != 1:
            raise PermissionError("provider registration retry was already consumed")
        authorization_generation = attempt_generation + 1
        action_binding = {
            "action": "DISPOSE_PROVIDER_REGISTRATION_FAILURE",
            "attempt_generation": attempt_generation,
            "authorization_generation": authorization_generation,
            "disposition": disposition,
            "failure_digest": failure_digest,
            "registration_id": registration_id,
        }
        capability = self._provider_host_enrollment_coordinator().verify_founder_action(
            payload["founder_capability"],
            client_sid,
            action="DISPOSE_PROVIDER_REGISTRATION_FAILURE",
            action_digest=structured_digest(action_binding),
            generation=authorization_generation,
        )
        capability_value_digest = capability_digest(capability)
        signature_digest = capability_signature_digest(capability)
        current = self.store.get("registrations", registration_id)
        if current is None:
            raise PermissionError(
                "provider registration has no failed claim for disposition"
            )
        current_state = str(current.pop("service_state", ""))
        if current_state != "REGISTRATION_FAILED":
            prior_disposition = (
                current.get("retry_disposition")
                if current_state
                in {"REGISTRATION_RETRY_AUTHORIZED", "REGISTRATION_STARTED"}
                else current.get("disposition")
                if current_state == "REGISTRATION_ABANDONED"
                else None
            )
            if (
                not isinstance(prior_disposition, dict)
                or not self.keys.verify(
                    "provider-registration-failure-disposition",
                    prior_disposition,
                )
                or any(
                    prior_disposition.get(name) != value
                    for name, value in action_binding.items()
                )
                or prior_disposition.get("authorized_client_sid") != client_sid
                or prior_disposition.get("founder_capability_digest")
                != capability_value_digest
            ):
                raise PermissionError(
                    "provider registration has no failed claim for disposition"
                )
            return {
                "registration_id": registration_id,
                "disposition": disposition,
                "disposition_record": prior_disposition,
                "state": current_state,
                "attempt_generation": (
                    attempt_generation + 1
                    if disposition == "RETRY_ONCE"
                    else attempt_generation
                ),
            }
        start = current.get("start")
        if (
            not isinstance(start, dict)
            or start.get("registration_id") != registration_id
            or start.get("authorization_reference") != client_sid
            or current.get("failure_digest") != failure_digest
            or current.get("attempt_generation") != attempt_generation
        ):
            raise PermissionError(
                "provider registration failure disposition binding differs"
            )
        authorization_id = (
            f"provider-registration-disposition:{registration_id}:"
            f"generation:{authorization_generation}"
        )
        disposition_record = self.keys.sign(
            "provider-registration-failure-disposition",
            {
                **action_binding,
                "authorization_id": authorization_id,
                "authorized_client_sid": client_sid,
                "founder_capability_id": capability.capability_id,
                "founder_capability_digest": capability_value_digest,
                "founder_capability_signature_digest": signature_digest,
                "founder_approval_event_id": capability.approval_event_id,
                "founder_approval_event_digest": capability.approval_event_digest,
                "founder_approval_record_id": capability.approval_record_id,
                "founder_session_id": capability.founder_authenticated_session_id,
                "disposed_at": _now(),
            },
        )
        if disposition == "RETRY_ONCE":
            next_generation = attempt_generation + 1
            setup_id = "provider-registration-probe:" + hashlib.sha256(
                (
                    registration_id
                    + f"\0setup-v{next_generation}"
                ).encode("utf-8")
            ).hexdigest()[:32]
            retry_start = self.keys.sign(
                "provider-registration-start",
                {
                    "id": f"{registration_id}:started:g{next_generation}",
                    "kind": "provider_registration_started",
                    "schema_version": 2,
                    "registration_id": registration_id,
                    "setup_id": setup_id,
                    "attempt_generation": next_generation,
                    "authorization_reference": client_sid,
                    "event_challenge": secrets.token_hex(32),
                    "disposition_digest": _canonical_digest(disposition_record),
                    **(
                        {
                            "registration_lineage_digest": current[
                                "registration_lineage_digest"
                            ]
                        }
                        if "registration_lineage_digest" in current
                        else {}
                    ),
                    "started_at": _now(),
                },
            )
            replacement = {
                "kind": "provider_registration_retry_authorized",
                "request_binding": current["request_binding"],
                "request_identity_digest": current["request_identity_digest"],
                "start": retry_start,
                "attempt_generation": next_generation,
                "prior_failure": current["failure"],
                "prior_failure_digest": failure_digest,
                "retry_disposition": disposition_record,
            }
            if "registration_lineage" in current:
                lineage = _validated_registration_replacement_lineage(
                    current.get("registration_lineage"),
                    self.keys.verify,
                    require_current_release=False,
                )
                if current.get("registration_lineage_digest") != _canonical_digest(
                    lineage
                ):
                    raise PermissionError(
                        "Provider registration replacement lineage differs"
                    )
                replacement.update(
                    {
                        "family_generation": 2,
                        "predecessor_registration_id": lineage[
                            "predecessor_registration_id"
                        ],
                        "predecessor_failure_digest": lineage[
                            "predecessor_failure_digest"
                        ],
                        "registration_lineage": lineage,
                        "registration_lineage_digest": _canonical_digest(lineage),
                    }
                )
            # Authorizing the single retry is deliberately not a launch claim.
            # This dormant state carries the exact signed retry identity while
            # allowing a version-bound Provider Host enrollment to be revoked
            # and replaced before the retry starts.  The matching registration
            # request atomically activates it immediately before any Host work.
            state = "REGISTRATION_RETRY_AUTHORIZED"
        else:
            replacement = {
                **current,
                "kind": "provider_registration_abandoned",
                "disposition": disposition_record,
                "abandoned_at": _now(),
            }
            state = "REGISTRATION_ABANDONED"
        consumption = {
            "capability_id": capability.capability_id,
            "project_id": capability.project_id,
            "approval_record_id": capability.approval_record_id,
            "approval_event_id": capability.approval_event_id,
            "founder_session_id": capability.founder_authenticated_session_id,
            "challenge_id": capability.challenge_id,
            "approval_digest": capability.approval_digest,
            "challenge_proof_digest": capability.challenge_proof_digest,
            "capability_digest": capability_value_digest,
            "signature_digest": signature_digest,
            "generation": authorization_generation,
            "authorization_id": authorization_id,
        }
        self.store.dispose_provider_registration_failure(
            registration_id,
            expected_failure_digest=failure_digest,
            state=state,
            payload=replacement,
            consumption=consumption,
        )
        return {
            "registration_id": registration_id,
            "disposition": disposition,
            "disposition_record": disposition_record,
            "state": state,
            "attempt_generation": (
                attempt_generation + 1
                if disposition == "RETRY_ONCE"
                else attempt_generation
            ),
        }

    def _authorize_exhausted_provider_registration(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(
            payload,
            {
                "registration_id",
                "failure_digest",
                "attempt_generation",
                "request_identity_digest",
                "expected_account_identity_digest",
                "expected_account_plan_type",
                "account_identity_discovery_digest",
                "expected_executable_sha256",
                "expected_executable_size",
                "required_authority_version",
                "required_host_version",
                "effect_accounting",
                "founder_capability",
            },
        )
        registration_id = _text(payload["registration_id"], "registration ID")
        failure_digest = _sha256_text(
            payload["failure_digest"], "registration failure digest"
        )
        request_identity_digest = _sha256_text(
            payload["request_identity_digest"], "registration request identity digest"
        )
        expected_account_identity_digest = _sha256_text(
            payload["expected_account_identity_digest"],
            "expected subscription account identity digest",
        )
        expected_account_plan_type = _text(
            payload["expected_account_plan_type"],
            "expected subscription account plan",
        )
        account_identity_discovery_digest = _sha256_text(
            payload["account_identity_discovery_digest"],
            "account identity discovery record digest",
        )
        expected_executable_sha256 = _sha256_text(
            payload["expected_executable_sha256"], "provider executable digest"
        )
        expected_executable_size = _positive_int(
            payload["expected_executable_size"], "provider executable size"
        )
        if (
            payload["attempt_generation"] != 2
            or expected_account_plan_type not in CODEX_ALLOWED_SUBSCRIPTION_PLANS
            or payload["required_authority_version"] != SERVICE_VERSION
            or payload["required_host_version"] != SERVICE_VERSION
            or payload["effect_accounting"]
            != _zero_registration_effect_accounting()
        ):
            raise PermissionError(
                "exhausted provider registration authorization is misbound"
            )
        current = self.store.get("registrations", registration_id)
        if current is None:
            raise PermissionError("exhausted provider registration is unavailable")
        current_state = str(current.pop("service_state", ""))
        if current_state == "REGISTRATION_EXHAUSTED":
            lineage = _validated_registration_replacement_lineage(
                current.get("registration_lineage"), self.keys.verify
            )
            action_binding = _registration_replacement_action_binding(lineage)
            if action_binding != {
                "action": "NEW_REGISTRATION_AFTER_EXHAUSTION",
                "account_identity_discovery_digest": (
                    account_identity_discovery_digest
                ),
                "expected_account_identity_digest": (
                    expected_account_identity_digest
                ),
                "expected_account_plan_type": expected_account_plan_type,
                "authorized_client_sid": client_sid,
                "effect_accounting": payload["effect_accounting"],
                "exhausted_attempt_generation": payload["attempt_generation"],
                "expected_executable_sha256": expected_executable_sha256,
                "expected_executable_size": expected_executable_size,
                "predecessor_failure_digest": failure_digest,
                "predecessor_registration_id": registration_id,
                "request_identity_digest": request_identity_digest,
                "required_authority_version": payload[
                    "required_authority_version"
                ],
                "required_host_version": payload["required_host_version"],
                "successor_registration_id": lineage[
                    "successor_registration_id"
                ],
            }:
                raise PermissionError(
                    "exhausted provider registration replay binding differs"
                )
            capability = self._provider_host_enrollment_coordinator().verify_founder_action(
                payload["founder_capability"],
                client_sid,
                action="NEW_REGISTRATION_AFTER_EXHAUSTION",
                action_digest=structured_digest(action_binding),
                generation=3,
            )
            if lineage.get("founder_capability_digest") != capability_digest(capability):
                raise PermissionError(
                    "exhausted provider registration capability differs"
                )
            return self._exhausted_registration_replacement_result(
                registration_id, current, client_sid
            )
        if current_state != "REGISTRATION_FAILED":
            raise PermissionError(
                "provider registration is not eligible for exhausted replacement"
            )
        start = current.get("start")
        failure = current.get("failure")
        request_binding = current.get("request_binding")
        if (
            current.get("kind") != "provider_registration_failed"
            or "registration_lineage" in current
            or "predecessor_registration_id" in current
            or current.get("attempt_generation") != 2
            or current.get("request_identity_digest") != request_identity_digest
            or current.get("failure_digest") != failure_digest
            or not isinstance(start, dict)
            or not self.keys.verify("provider-registration-start", start)
            or start.get("registration_id") != registration_id
            or start.get("attempt_generation") != 2
            or start.get("authorization_reference") != client_sid
            or not isinstance(failure, dict)
            or not self.keys.verify("provider-registration-failure", failure)
            or _canonical_digest(failure) != failure_digest
            or failure.get("failure_stage") != "ACCOUNT_PROBE_VALIDATE"
            or failure.get("failure_code") != "PERMISSION_REJECTED"
            or failure.get("effect_accounting")
            != {
                "registration_persisted": False,
                "qualification_started": False,
                "model_request_count": 0,
                "provider_binding_created": False,
                "usage_reservation_count": 0,
            }
            or not isinstance(request_binding, dict)
            or request_binding.get("authorized_client_sid") != client_sid
            or request_binding.get("expected_executable_sha256")
            != expected_executable_sha256
            or request_binding.get("expected_executable_size")
            != expected_executable_size
            or not isinstance(request_binding.get("authentication_policy"), dict)
        ):
            raise PermissionError(
                "exhausted provider registration evidence binding differs"
            )
        if any(
            record.get("registration_id") == registration_id
            for record in self.store.list_records("qualifications")
        ) or any(
            record.get("registration_id") == registration_id
            for record in self.store.list_records("attempts")
        ):
            raise PermissionError(
                "exhausted provider registration has downstream effects"
            )
        self._require_no_pending_host_launch_reconciliation()
        claims = self._pending_provider_operation_claims()
        if claims != {
            "registrations": [registration_id],
            "registration_failures": [registration_id],
            "registration_retries": [],
            "registration_replacements": [],
            "qualifications": [],
            "qualification_retries": [],
        }:
            raise PermissionError(
                "another provider operation requires exact recovery first"
            )
        successor_id = _replacement_registration_id(
            registration_id, failure_digest, request_identity_digest
        )
        authorization_id = (
            f"provider-registration-replacement:{registration_id}:generation:3"
        )
        action_binding = {
            "action": "NEW_REGISTRATION_AFTER_EXHAUSTION",
            "account_identity_discovery_digest": account_identity_discovery_digest,
            "expected_account_identity_digest": expected_account_identity_digest,
            "expected_account_plan_type": expected_account_plan_type,
            "authorized_client_sid": client_sid,
            "effect_accounting": _zero_registration_effect_accounting(),
            "exhausted_attempt_generation": 2,
            "expected_executable_sha256": expected_executable_sha256,
            "expected_executable_size": expected_executable_size,
            "predecessor_failure_digest": failure_digest,
            "predecessor_registration_id": registration_id,
            "request_identity_digest": request_identity_digest,
            "required_authority_version": SERVICE_VERSION,
            "required_host_version": SERVICE_VERSION,
            "successor_registration_id": successor_id,
        }
        capability = self._provider_host_enrollment_coordinator().verify_founder_action(
            payload["founder_capability"],
            client_sid,
            action="NEW_REGISTRATION_AFTER_EXHAUSTION",
            action_digest=structured_digest(action_binding),
            generation=3,
        )
        capability_value_digest = capability_digest(capability)
        signature_digest = capability_signature_digest(capability)
        lineage = self.keys.sign(
            "provider-registration-replacement-lineage",
            {
                **action_binding,
                "authorization_id": authorization_id,
                "family_generation": 2,
                "founder_capability_digest": capability_value_digest,
                "founder_capability_id": capability.capability_id,
                "founder_capability_signature_digest": signature_digest,
                "founder_approval_event_id": capability.approval_event_id,
                "founder_approval_event_digest": capability.approval_event_digest,
                "founder_approval_record_id": capability.approval_record_id,
                "founder_session_id": capability.founder_authenticated_session_id,
                "authorized_at": _now(),
            },
        )
        lineage_digest = _canonical_digest(lineage)
        setup_id = "provider-registration-probe:" + hashlib.sha256(
            (successor_id + "\0setup-v1").encode("utf-8")
        ).hexdigest()[:32]
        replacement_start = self.keys.sign(
            "provider-registration-start",
            {
                "id": f"{successor_id}:started",
                "kind": "provider_registration_started",
                "schema_version": 2,
                "registration_id": successor_id,
                "setup_id": setup_id,
                "attempt_generation": 1,
                "authorization_reference": client_sid,
                "event_challenge": secrets.token_hex(32),
                "registration_lineage_digest": lineage_digest,
                "started_at": _now(),
            },
        )
        exhausted = {
            **current,
            "kind": "provider_registration_exhausted",
            "registration_lineage": lineage,
            "registration_lineage_digest": lineage_digest,
            "successor_registration_id": successor_id,
            "exhausted_at": _now(),
        }
        successor = {
            "kind": "provider_registration_replacement_authorized",
            "request_binding": request_binding,
            "request_identity_digest": request_identity_digest,
            "start": replacement_start,
            "attempt_generation": 1,
            "family_generation": 2,
            "predecessor_registration_id": registration_id,
            "predecessor_failure_digest": failure_digest,
            "registration_lineage": lineage,
            "registration_lineage_digest": lineage_digest,
        }
        consumption = {
            "capability_id": capability.capability_id,
            "project_id": capability.project_id,
            "approval_record_id": capability.approval_record_id,
            "approval_event_id": capability.approval_event_id,
            "founder_session_id": capability.founder_authenticated_session_id,
            "challenge_id": capability.challenge_id,
            "approval_digest": capability.approval_digest,
            "challenge_proof_digest": capability.challenge_proof_digest,
            "capability_digest": capability_value_digest,
            "signature_digest": signature_digest,
            "generation": 3,
            "authorization_id": authorization_id,
        }
        self.store.authorize_exhausted_provider_registration(
            registration_id,
            successor_id,
            expected_failure_digest=failure_digest,
            predecessor_payload=exhausted,
            successor_payload=successor,
            consumption=consumption,
        )
        return {
            "authorization_id": authorization_id,
            "predecessor_registration_id": registration_id,
            "registration_lineage": lineage,
            "state": "REGISTRATION_REPLACEMENT_AUTHORIZED",
            "successor_registration_id": successor_id,
        }

    def _recover_exhausted_provider_registration(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, {"registration_id"})
        registration_id = _text(payload["registration_id"], "registration ID")
        current = self.store.get("registrations", registration_id)
        if current is None or current.pop("service_state", None) != "REGISTRATION_EXHAUSTED":
            raise PermissionError(
                "exhausted provider registration replacement is unavailable"
            )
        return self._exhausted_registration_replacement_result(
            registration_id, current, client_sid
        )

    def _exhausted_registration_replacement_result(
        self,
        registration_id: str,
        predecessor: dict[str, Any],
        client_sid: str,
    ) -> dict[str, Any]:
        lineage = _validated_registration_replacement_lineage(
            predecessor.get("registration_lineage"),
            self.keys.verify,
            require_current_release=False,
        )
        successor_id = lineage.get("successor_registration_id")
        if (
            lineage.get("predecessor_registration_id") != registration_id
            or lineage.get("authorized_client_sid") != client_sid
            or predecessor.get("successor_registration_id") != successor_id
            or predecessor.get("registration_lineage_digest")
            != _canonical_digest(lineage)
            or not isinstance(successor_id, str)
        ):
            raise PermissionError(
                "exhausted provider registration replacement binding differs"
            )
        successor = self.store.get("registrations", successor_id)
        if successor is None:
            raise RuntimeError("provider registration successor claim is absent")
        successor_state = str(successor.pop("service_state", ""))
        if (
            successor_state == "REGISTRATION_REPLACEMENT_AUTHORIZED"
            and lineage.get("required_authority_version") != SERVICE_VERSION
        ):
            raise PermissionError(
                "provider registration replacement release differs"
            )
        if (
            successor.get("predecessor_registration_id") != registration_id
            or successor.get("predecessor_failure_digest")
            != lineage.get("predecessor_failure_digest")
            or successor.get("registration_lineage_digest")
            != _canonical_digest(lineage)
            or successor.get("registration_lineage") != lineage
        ):
            raise PermissionError("provider registration successor binding differs")
        return {
            "authorization_id": lineage["authorization_id"],
            "predecessor_registration_id": registration_id,
            "registration_lineage": lineage,
            "state": successor_state,
            "successor_registration_id": successor_id,
        }

    def _register_provider(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        base_fields = {
            "provider_id",
            "executable",
            "executive_capabilities",
            "project_types",
            "effort_levels",
            "pricing_authority",
        }
        subscription_fields = base_fields | {
            "expected_executable_sha256",
            "expected_executable_size",
            "expected_version",
            "model_allowlist",
            "model_revalidation_expires_at",
            "authentication_policy",
            "usage_policy",
            "client_executable_handle",
        }
        if set(payload) not in {frozenset(base_fields), frozenset(subscription_fields)}:
            raise ValueError("authority operation payload fields are invalid")
        provider_id = _choice(payload["provider_id"], {"codex", "claude"})
        executable = Path(_text(payload["executable"], "provider executable"))
        executive_capabilities = payload["executive_capabilities"]
        project_types = payload["project_types"]
        effort_levels = payload["effort_levels"]
        pricing_authority = payload["pricing_authority"]
        subscription = set(payload) == subscription_fields
        expected_executable_sha256 = (
            _sha256_text(
                payload["expected_executable_sha256"],
                "expected provider executable SHA-256",
            )
            if subscription
            else None
        )
        expected_executable_size = (
            _nonnegative_int(
                payload["expected_executable_size"],
                "expected provider executable size",
            )
            if subscription
            else None
        )
        if subscription and expected_executable_size == 0:
            raise ValueError("authority expected provider executable size is invalid")
        model_allowlist = payload.get("model_allowlist")
        expected_version = payload.get("expected_version")
        model_revalidation_expires_at = payload.get(
            "model_revalidation_expires_at"
        )
        authentication_policy = payload.get("authentication_policy")
        usage_policy = payload.get("usage_policy")
        if subscription and self.observer is None:
            raise PermissionError(
                "Codex subscription registration requires the production observer"
            )
        planned_registration_id: str | None = None
        planned_setup_id: str | None = None
        planned_challenge: str | None = None
        planned_attempt_generation = 1
        registration_lineage: dict[str, Any] | None = None
        expected_account_identity_digest: str | None = None
        expected_account_plan_type: str | None = None
        recovering_registration = False
        if subscription:
            request_binding = {
                "provider_id": provider_id,
                "executable": str(executable),
                "executive_capabilities": executive_capabilities,
                "project_types": project_types,
                "effort_levels": effort_levels,
                "pricing_authority": pricing_authority,
                "expected_executable_sha256": expected_executable_sha256,
                "expected_executable_size": expected_executable_size,
                "expected_version": expected_version,
                "model_allowlist": model_allowlist,
                "model_revalidation_expires_at": model_revalidation_expires_at,
                "authentication_policy": authentication_policy,
                "usage_policy": usage_policy,
                "authorized_client_sid": client_sid,
            }
            semantic_pricing = dict(cast(dict[str, Any], pricing_authority))
            semantic_pricing.pop("quoted_at", None)
            semantic_pricing.pop("expires_at", None)
            request_identity = {
                **request_binding,
                "pricing_authority": semantic_pricing,
                "model_revalidation_expires_at": None,
            }
            request_identity_digest = _canonical_digest(request_identity)
            planned_registration_id = f"keeper-provider:{provider_id}:v1:" + hashlib.sha256(
                (
                    provider_id
                    + "-subscription-registration-v1\0"
                    + request_identity_digest
                ).encode("utf-8")
            ).hexdigest()[:32]
            family_root_id = planned_registration_id
            family_root = self.store.get("registrations", family_root_id)
            if family_root is not None:
                family_root_state = str(family_root.pop("service_state", ""))
                if family_root_state == "REGISTRATION_EXHAUSTED":
                    lineage = _validated_registration_replacement_lineage(
                        family_root.get("registration_lineage"),
                        self.keys.verify,
                        require_current_release=False,
                    )
                    if (
                        lineage.get("predecessor_registration_id") != family_root_id
                        or lineage.get("request_identity_digest")
                        != request_identity_digest
                        or lineage.get("authorized_client_sid") != client_sid
                        or lineage.get("expected_executable_sha256")
                        != expected_executable_sha256
                        or lineage.get("expected_executable_size")
                        != expected_executable_size
                        or family_root.get("successor_registration_id")
                        != lineage.get("successor_registration_id")
                    ):
                        raise PermissionError(
                            "Provider registration replacement request differs"
                        )
                    planned_registration_id = str(
                        lineage["successor_registration_id"]
                    )
                    registration_lineage = lineage
                    expected_account_identity_digest = str(
                        lineage["expected_account_identity_digest"]
                    )
                    expected_account_plan_type = str(
                        lineage["expected_account_plan_type"]
                    )
            planned_setup_id = "provider-registration-probe:" + hashlib.sha256(
                (planned_registration_id + "\0setup-v1").encode("utf-8")
            ).hexdigest()[:32]
            pending_claims = self._pending_provider_operation_claims()
            if (
                pending_claims["qualifications"]
                or any(
                    value != planned_registration_id
                    for value in pending_claims["registrations"]
                )
                or any(
                    value != planned_registration_id
                    for value in pending_claims["registration_retries"]
                )
                or any(
                    value != planned_registration_id
                    for value in pending_claims["registration_replacements"]
                )
            ):
                raise PermissionError(
                    "Another provider operation requires exact recovery first"
                )
            existing = self.store.get("registrations", planned_registration_id)
            if existing is not None:
                existing_state = str(existing.pop("service_state", ""))
                if existing_state in {
                    "REGISTRATION_REPLACEMENT_AUTHORIZED",
                    "REGISTRATION_RETRY_AUTHORIZED",
                    "REGISTRATION_STARTED",
                }:
                    start = existing.get("start")
                    attempt_generation = (
                        start.get("attempt_generation", 1)
                        if isinstance(start, dict)
                        else None
                    )
                    expected_setup_id = (
                        "provider-registration-probe:"
                        + hashlib.sha256(
                            (
                                planned_registration_id
                                + f"\0setup-v{attempt_generation}"
                            ).encode("utf-8")
                        ).hexdigest()[:32]
                        if isinstance(attempt_generation, int)
                        and not isinstance(attempt_generation, bool)
                        and attempt_generation in {1, 2}
                        else None
                    )
                    initial_fields = {
                        "kind",
                        "request_binding",
                        "request_identity_digest",
                        "start",
                    }
                    retry_fields = initial_fields | {
                        "attempt_generation",
                        "prior_failure",
                        "prior_failure_digest",
                        "retry_disposition",
                    }
                    replacement_fields = initial_fields | {
                        "attempt_generation",
                        "family_generation",
                        "predecessor_registration_id",
                        "predecessor_failure_digest",
                        "registration_lineage",
                        "registration_lineage_digest",
                    }
                    replacement_retry_fields = retry_fields | {
                        "family_generation",
                        "predecessor_registration_id",
                        "predecessor_failure_digest",
                        "registration_lineage",
                        "registration_lineage_digest",
                    }
                    predispatch_retry_fields = initial_fields | {
                        "attempt_generation",
                        "predispatch_migration",
                        "predispatch_migration_digest",
                    }
                    if (
                        frozenset(existing)
                        not in {
                            frozenset(initial_fields),
                            frozenset(retry_fields),
                            frozenset(replacement_fields),
                            frozenset(replacement_retry_fields),
                            frozenset(predispatch_retry_fields),
                        }
                        or existing.get("kind")
                        != (
                            "provider_registration_replacement_authorized"
                            if existing_state
                            == "REGISTRATION_REPLACEMENT_AUTHORIZED"
                            else "provider_registration_retry_authorized"
                            if existing_state == "REGISTRATION_RETRY_AUTHORIZED"
                            else "provider_registration_started"
                        )
                        or existing.get("request_identity_digest")
                        != request_identity_digest
                        or not isinstance(existing.get("request_binding"), dict)
                        or not isinstance(start, dict)
                        or not self.keys.verify("provider-registration-start", start)
                        or start.get("registration_id") != planned_registration_id
                        or start.get("setup_id") != expected_setup_id
                        or start.get("authorization_reference") != client_sid
                        or not isinstance(start.get("event_challenge"), str)
                        or len(str(start["event_challenge"])) != 64
                    ):
                        raise PermissionError(
                            "Provider registration claim binding differs"
                        )
                    assert isinstance(attempt_generation, int)
                    planned_attempt_generation = attempt_generation
                    planned_setup_id = str(expected_setup_id)
                    planned_challenge = str(start["event_challenge"])
                    if frozenset(existing) in {
                        frozenset(retry_fields),
                        frozenset(replacement_retry_fields),
                    }:
                        retry_disposition = existing.get("retry_disposition")
                        if (
                            planned_attempt_generation != 2
                            or existing.get("attempt_generation") != 2
                            or not isinstance(existing.get("prior_failure"), dict)
                            or not isinstance(existing.get("prior_failure_digest"), str)
                            or not isinstance(retry_disposition, dict)
                            or not self.keys.verify(
                                "provider-registration-failure-disposition",
                                retry_disposition,
                            )
                            or start.get("disposition_digest")
                            != _canonical_digest(retry_disposition)
                        ):
                            raise PermissionError(
                                "Provider registration retry claim is malformed"
                            )
                    if frozenset(existing) == frozenset(
                        predispatch_retry_fields
                    ):
                        migration = existing.get("predispatch_migration")
                        if (
                            planned_attempt_generation != 2
                            or existing.get("attempt_generation") != 2
                            or not isinstance(migration, dict)
                            or not self.keys.verify(
                                "legacy-authority-predispatch-migration",
                                migration,
                            )
                            or existing.get("predispatch_migration_digest")
                            != _canonical_digest(migration)
                            or start.get("predispatch_migration_digest")
                            != _canonical_digest(migration)
                            or migration.get("registration_id")
                            != planned_registration_id
                            or migration.get("retry_attempt_generation") != 2
                        ):
                            raise PermissionError(
                                "Provider registration predispatch retry claim is malformed"
                            )
                    if frozenset(existing) in {
                        frozenset(replacement_fields),
                        frozenset(replacement_retry_fields),
                    }:
                        claim_lineage = _validated_registration_replacement_lineage(
                            existing.get("registration_lineage"),
                            self.keys.verify,
                            require_current_release=(
                                existing_state
                                == "REGISTRATION_REPLACEMENT_AUTHORIZED"
                            ),
                        )
                        lineage_attempt_generation = (
                            2
                            if frozenset(existing)
                            == frozenset(replacement_retry_fields)
                            else 1
                        )
                        if (
                            planned_attempt_generation
                            != lineage_attempt_generation
                            or existing.get("attempt_generation")
                            != lineage_attempt_generation
                            or existing.get("family_generation") != 2
                            or existing.get("predecessor_registration_id")
                            != family_root_id
                            or existing.get("predecessor_failure_digest")
                            != claim_lineage.get("predecessor_failure_digest")
                            or existing.get("registration_lineage_digest")
                            != _canonical_digest(claim_lineage)
                            or start.get("registration_lineage_digest")
                            != _canonical_digest(claim_lineage)
                            or claim_lineage.get("successor_registration_id")
                            != planned_registration_id
                        ):
                            raise PermissionError(
                                "Provider registration replacement claim is malformed"
                            )
                        registration_lineage = claim_lineage
                        expected_account_identity_digest = str(
                            claim_lineage["expected_account_identity_digest"]
                        )
                        expected_account_plan_type = str(
                            claim_lineage["expected_account_plan_type"]
                        )
                    original_binding = cast(
                        dict[str, Any], existing["request_binding"]
                    )
                    if _canonical_digest(
                        {
                            **original_binding,
                            "pricing_authority": {
                                key: value
                                for key, value in cast(
                                    dict[str, Any],
                                    original_binding["pricing_authority"],
                                ).items()
                                if key not in {"quoted_at", "expires_at"}
                            },
                            "model_revalidation_expires_at": None,
                        }
                    ) != request_identity_digest:
                        raise PermissionError(
                            "Provider registration claim content differs"
                        )
                    executive_capabilities = original_binding[
                        "executive_capabilities"
                    ]
                    project_types = original_binding["project_types"]
                    effort_levels = original_binding["effort_levels"]
                    pricing_authority = original_binding["pricing_authority"]
                    expected_version = original_binding["expected_version"]
                    model_allowlist = original_binding["model_allowlist"]
                    model_revalidation_expires_at = original_binding[
                        "model_revalidation_expires_at"
                    ]
                    authentication_policy = original_binding[
                        "authentication_policy"
                    ]
                    usage_policy = original_binding["usage_policy"]
                    recovering_registration = True
                    if existing_state in {
                        "REGISTRATION_REPLACEMENT_AUTHORIZED",
                        "REGISTRATION_RETRY_AUTHORIZED",
                    }:
                        activated_claim = {
                            **existing,
                            "kind": "provider_registration_started",
                        }
                        self.store.transition(
                            "registrations",
                            planned_registration_id,
                            existing_state,
                            "REGISTRATION_STARTED",
                            activated_claim,
                        )
                elif existing_state == "REGISTRATION_FAILED":
                    start = existing.get("start")
                    failure = existing.get("failure")
                    if (
                        existing.get("kind") != "provider_registration_failed"
                        or existing.get("request_identity_digest")
                        != request_identity_digest
                        or not isinstance(start, dict)
                        or start.get("registration_id") != planned_registration_id
                        or start.get("authorization_reference") != client_sid
                        or not isinstance(failure, dict)
                        or not self.keys.verify(
                            "provider-registration-failure", failure
                        )
                        or existing.get("failure_digest")
                        != _canonical_digest(failure)
                    ):
                        raise PermissionError(
                            "Provider registration failure claim binding differs"
                        )
                    return {
                        "registration_id": planned_registration_id,
                        "registration_failed": failure,
                        "state": "REGISTRATION_FAILED",
                    }
                elif existing_state == "REGISTERED_UNQUALIFIED":
                    valid, detail = validate_provider_registration_contract(existing)
                    if not valid:
                        raise PermissionError(
                            "Existing provider registration is invalid: " + detail
                        )
                    if registration_lineage is not None:
                        account_binding = existing.get(
                            "subscription_account_binding"
                        )
                        if (
                            not isinstance(account_binding, dict)
                            or account_binding.get("account_identity_digest")
                            != registration_lineage.get(
                                "expected_account_identity_digest"
                            )
                            or account_binding.get("plan_type")
                            != registration_lineage.get(
                                "expected_account_plan_type"
                            )
                        ):
                            raise PermissionError(
                                "Existing provider registration account identity differs from its lineage"
                            )
                    if (
                        existing.get("logical_provider_id") != provider_id
                        or existing.get("authorized_by") != client_sid
                        or existing.get("executable_sha256")
                        != expected_executable_sha256
                        or existing.get("executable_size")
                        != expected_executable_size
                        or existing.get("expected_version") != expected_version
                    ):
                        raise PermissionError(
                            "Existing provider registration request binding differs"
                        )
                    if self.observer is None:
                        raise RuntimeError(
                            "Authority provider observer became unavailable"
                        )
                    self.observer.validate_registered_executable(
                        existing,
                        _positive_int(
                            payload["client_executable_handle"],
                            "client executable handle",
                        ),
                    )
                    return {
                        "registration": existing,
                        "registration_id": planned_registration_id,
                    }
                else:
                    raise PermissionError(
                        "Provider registration identity is not recoverable"
                    )
            else:
                planned_challenge = secrets.token_hex(32)
                registration_start = self.keys.sign(
                    "provider-registration-start",
                    {
                        "id": f"{planned_registration_id}:started",
                        "kind": "provider_registration_started",
                        "schema_version": 2,
                        "registration_id": planned_registration_id,
                        "setup_id": planned_setup_id,
                        "attempt_generation": 1,
                        "authorization_reference": client_sid,
                        "event_challenge": planned_challenge,
                        "started_at": _now(),
                    },
                )
                registration_claim = {
                    "kind": "provider_registration_started",
                    "request_binding": request_binding,
                    "request_identity_digest": request_identity_digest,
                    "start": registration_start,
                }
                self.store.insert(
                    "registrations",
                    planned_registration_id,
                    "REGISTRATION_STARTED",
                    registration_claim,
                )
        if self.observer is not None and hasattr(
            self.observer, "register_provider"
        ):
            registration_arguments: dict[str, Any] = {
                "executive_capabilities": executive_capabilities,
                "project_types": project_types,
                "effort_levels": effort_levels,
                "pricing_authority": pricing_authority,
            }
            if subscription:
                registration_arguments.update(
                    {
                        "model_allowlist": model_allowlist,
                        "expected_executable_sha256": expected_executable_sha256,
                        "expected_executable_size": expected_executable_size,
                        "expected_version": expected_version,
                        "model_revalidation_expires_at": (
                            model_revalidation_expires_at
                        ),
                        "authentication_policy": authentication_policy,
                        "usage_policy": usage_policy,
                        "client_executable_handle": _positive_int(
                            payload["client_executable_handle"],
                            "client executable handle",
                        ),
                        "planned_registration_id": planned_registration_id,
                        "planned_setup_id": planned_setup_id,
                        "planned_challenge": planned_challenge,
                        "recovering_registration": recovering_registration,
                        "expected_account_identity_digest": (
                            expected_account_identity_digest
                        ),
                        "expected_account_plan_type": expected_account_plan_type,
                    }
                )
            registration = self.observer.register_provider(
                provider_id,
                executable,
                client_sid,
                **registration_arguments,
            )
        else:
            if subscription:
                raise PermissionError(
                    "Codex subscription registration requires the production observer"
                )
            registration = create_provider_registration(
                provider_id,
                executable,
                authorized_by=client_sid,
                executive_capabilities=executive_capabilities,
                project_types=project_types,
                effort_levels=effort_levels,
                pricing_authority=pricing_authority,
            )
        terminal_failure = registration.get("registration_terminal_failure")
        if subscription and "registration_terminal_failure" in registration:
            if not isinstance(terminal_failure, dict):
                raise PermissionError(
                    "provider registration terminal failure is invalid"
                )
            assert planned_registration_id is not None
            assert planned_setup_id is not None
            return self._commit_provider_registration_failure(
                planned_registration_id,
                planned_setup_id,
                planned_attempt_generation,
                client_sid,
                terminal_failure,
            )
        identifier = str(registration["trusted_registration_id"])
        if subscription:
            if identifier != planned_registration_id:
                raise PermissionError(
                    "Provider registration result identity differs from its claim"
                )
            if registration_lineage is not None:
                account_binding = registration.get("subscription_account_binding")
                if (
                    not isinstance(account_binding, dict)
                    or account_binding.get("account_identity_digest")
                    != registration_lineage.get(
                        "expected_account_identity_digest"
                    )
                    or account_binding.get("plan_type")
                    != registration_lineage.get("expected_account_plan_type")
                ):
                    raise PermissionError(
                        "Provider registration account identity differs from its lineage"
                    )
            if registration_lineage is not None:
                registration = {
                    **registration,
                    "registration_lineage": registration_lineage,
                }
                registration["configuration_digest"] = (
                    canonical_provider_registration_digest(registration)
                )
            self.store.transition(
                "registrations",
                identifier,
                "REGISTRATION_STARTED",
                "REGISTERED_UNQUALIFIED",
                registration,
            )
        else:
            self.store.insert(
                "registrations",
                identifier,
                "REGISTERED_UNQUALIFIED",
                registration,
            )
        return {"registration": registration, "registration_id": identifier}

    def _authorize_provider_qualification_retry(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(
            payload,
            {
                "registration_id",
                "qualification_id",
                "qualification_failure_digest",
                "retry_generation",
                "required_authority_version",
                "required_host_version",
                "founder_capability",
            },
        )
        registration_id = _text(payload["registration_id"], "registration ID")
        qualification_id = _text(payload["qualification_id"], "qualification ID")
        failure_digest = _sha256_text(
            payload["qualification_failure_digest"],
            "qualification failure digest",
        )
        retry_generation = _positive_int(
            payload["retry_generation"], "qualification retry generation"
        )
        required_authority_version = _text(
            payload["required_authority_version"], "required Authority version"
        )
        required_host_version = _text(
            payload["required_host_version"], "required Host version"
        )
        if (
            retry_generation != 2
            or required_authority_version != SERVICE_VERSION
            or required_host_version != SERVICE_VERSION
        ):
            raise PermissionError(
                "Provider qualification retry release or generation is invalid"
            )
        registration_record = self.store.get("registrations", registration_id)
        qualification_record = self.store.get("qualifications", qualification_id)
        if (
            registration_record is None
            or registration_record.pop("service_state", None)
            != "QUALIFICATION_FAILED"
            or registration_record.get("qualification_evidence_id")
            != qualification_id
            or registration_record.get("qualification_evidence_digest")
            != failure_digest
            or qualification_record is None
            or qualification_record.pop("service_state", None)
            != "QUALIFICATION_FAILED"
            or set(qualification_record) != {"start", "evidence"}
        ):
            raise PermissionError(
                "Provider qualification has no exact terminal failure for retry"
            )
        evidence = qualification_record.get("evidence")
        if (
            not isinstance(evidence, dict)
            or not self.keys.verify("provider-qualification", evidence)
            or evidence.get("evidence_digest") != failure_digest
            or evidence.get("qualification_result") != "failed"
            or evidence.get("registration_id") != registration_id
            or evidence.get("id") != qualification_id
        ):
            raise PermissionError(
                "Provider qualification terminal failure evidence is invalid"
            )
        action_binding = {
            "action": "AUTHORIZE_PROVIDER_QUALIFICATION_RETRY",
            "qualification_failure_digest": failure_digest,
            "qualification_id": qualification_id,
            "registration_id": registration_id,
            "required_authority_version": required_authority_version,
            "required_host_version": required_host_version,
            "retry_generation": retry_generation,
        }
        capability = self._provider_host_enrollment_coordinator().verify_founder_action(
            payload["founder_capability"],
            client_sid,
            action="AUTHORIZE_PROVIDER_QUALIFICATION_RETRY",
            action_digest=structured_digest(action_binding),
            generation=retry_generation,
        )
        capability_value_digest = capability_digest(capability)
        signature_digest = capability_signature_digest(capability)
        provider_id = _choice(
            registration_record.get("logical_provider_id"),
            {"codex", "claude"},
        )
        retry_qualification_id = "provider-qualification:" + hashlib.sha256(
            (
                provider_id
                + "-subscription-qualification-retry-v1\0"
                + registration_id
                + "\0"
                + qualification_id
                + "\0"
                + failure_digest
            ).encode("utf-8")
        ).hexdigest()[:32]
        existing = self.store.get("qualifications", retry_qualification_id)
        if existing is not None:
            authorization = existing.get("retry_authorization")
            if (
                existing.get("service_state")
                not in {
                    "QUALIFICATION_RETRY_AUTHORIZED",
                    "EXECUTION_STARTED",
                    "QUALIFIED",
                    "QUALIFICATION_FAILED",
                    "UNCERTAIN",
                }
                or not isinstance(authorization, dict)
                or not self.keys.verify(
                    "provider-qualification-retry-authorization", authorization
                )
                or any(
                    authorization.get(name) != value
                    for name, value in action_binding.items()
                )
                or authorization.get("retry_qualification_id")
                != retry_qualification_id
                or authorization.get("authorized_client_sid") != client_sid
                or authorization.get("founder_capability_digest")
                != capability_value_digest
            ):
                raise PermissionError(
                    "Provider qualification retry identity is already reserved"
                )
            return {
                "registration_id": registration_id,
                "failed_qualification_id": qualification_id,
                "retry_qualification_id": retry_qualification_id,
                "retry_authorization": authorization,
                "state": str(existing["service_state"]),
            }
        authorization_id = (
            f"provider-qualification-retry:{registration_id}:generation:2"
        )
        event_challenge = secrets.token_hex(32)
        authorization = self.keys.sign(
            "provider-qualification-retry-authorization",
            {
                **action_binding,
                "authorization_id": authorization_id,
                "retry_qualification_id": retry_qualification_id,
                "event_challenge": event_challenge,
                "authorized_client_sid": client_sid,
                "founder_capability_id": capability.capability_id,
                "founder_capability_digest": capability_value_digest,
                "founder_capability_signature_digest": signature_digest,
                "founder_approval_event_id": capability.approval_event_id,
                "founder_approval_event_digest": capability.approval_event_digest,
                "founder_approval_record_id": capability.approval_record_id,
                "founder_session_id": capability.founder_authenticated_session_id,
                "authorized_at": _now(),
            },
        )
        consumption = {
            "capability_id": capability.capability_id,
            "project_id": capability.project_id,
            "approval_record_id": capability.approval_record_id,
            "approval_event_id": capability.approval_event_id,
            "founder_session_id": capability.founder_authenticated_session_id,
            "challenge_id": capability.challenge_id,
            "approval_digest": capability.approval_digest,
            "challenge_proof_digest": capability.challenge_proof_digest,
            "capability_digest": capability_value_digest,
            "signature_digest": signature_digest,
            "generation": retry_generation,
            "authorization_id": authorization_id,
        }
        self._require_no_pending_host_launch_reconciliation()
        self._require_no_pending_provider_operation_claims()
        provider_host_status = getattr(
            self.observer, "provider_host_status", None
        )
        if callable(provider_host_status):
            host_status = provider_host_status()
            if (
                not isinstance(host_status, dict)
                or host_status.get("state") != "READY"
                or host_status.get("launch_state_proven") is not True
                or host_status.get("active_or_uncertain_launch_count") != 0
            ):
                raise PermissionError(
                    "Provider Host launch state is not clear for qualification retry"
                )
        self.store.authorize_provider_qualification_retry(
            registration_id,
            qualification_id,
            retry_qualification_id,
            expected_failure_digest=failure_digest,
            retry_challenge=event_challenge,
            retry_authorization=authorization,
            consumption=consumption,
        )
        return {
            "registration_id": registration_id,
            "failed_qualification_id": qualification_id,
            "retry_qualification_id": retry_qualification_id,
            "retry_authorization": authorization,
            "state": "QUALIFICATION_RETRY_AUTHORIZED",
        }

    def _retry_provider_qualification(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        if set(payload) != {
            "registration_id",
            "retry_qualification_id",
            "client_executable_handle",
        }:
            raise ValueError("authority operation payload fields are invalid")
        registration_id = _text(payload["registration_id"], "registration ID")
        retry_id = _text(
            payload["retry_qualification_id"], "retry qualification ID"
        )
        terminal_registration = self.store.get("registrations", registration_id)
        if (
            terminal_registration is not None
            and terminal_registration.get("service_state")
            in {"QUALIFIED", "QUALIFICATION_FAILED"}
            and terminal_registration.get("qualification_evidence_id") == retry_id
        ):
            terminal_qualification = self.store.get("qualifications", retry_id)
            authorization = (
                terminal_qualification.get("retry_authorization")
                if isinstance(terminal_qualification, dict)
                else None
            )
            evidence = (
                terminal_qualification.get("evidence")
                if isinstance(terminal_qualification, dict)
                else None
            )
            start = (
                terminal_qualification.get("start")
                if isinstance(terminal_qualification, dict)
                else None
            )
            if (
                terminal_qualification is None
                or terminal_qualification.get("service_state")
                != terminal_registration.get("service_state")
                or not isinstance(authorization, dict)
                or not self.keys.verify(
                    "provider-qualification-retry-authorization", authorization
                )
                or authorization.get("authorized_client_sid") != client_sid
                or authorization.get("retry_qualification_id") != retry_id
                or not isinstance(evidence, dict)
                or not self.keys.verify("provider-qualification", evidence)
                or evidence.get("id") != retry_id
                or not isinstance(start, dict)
                or not self.keys.verify("provider-qualification-start", start)
            ):
                raise PermissionError(
                    "Provider qualification retry terminal record is incomplete"
                )
            terminal_registration.pop("service_state", None)
            return {
                "registration": terminal_registration,
                "qualification": evidence,
                "qualification_start": start,
            }
        return self._qualify_provider(payload, client_sid, qualification_retry=True)

    def _qualify_provider(
        self,
        payload: dict[str, Any],
        client_sid: str,
        *,
        qualification_retry: bool = False,
    ) -> dict[str, Any]:
        accepted = (
            {
                frozenset(
                    {
                        "registration_id",
                        "retry_qualification_id",
                        "client_executable_handle",
                    }
                )
            }
            if qualification_retry
            else {
                frozenset({"registration_id"}),
                frozenset({"registration_id", "client_executable_handle"}),
            }
        )
        if set(payload) not in accepted:
            raise ValueError("authority operation payload fields are invalid")
        if self.observer is None:
            raise RuntimeError("authority provider observer is unavailable")
        identifier = _text(payload["registration_id"], "registration ID")
        registration = self.store.get("registrations", identifier)
        if registration is None:
            raise PermissionError("registration is not eligible for qualification")
        registration_state = str(registration.pop("service_state", ""))
        subscription_qualification = (
            registration.get("registration_schema_version") in {4, 5}
        )
        if qualification_retry and (
            not subscription_qualification
            or registration_state
            not in {"QUALIFICATION_FAILED", "QUALIFICATION_STARTED"}
        ):
            raise PermissionError(
                "registration is not eligible for qualification retry"
            )
        eligible_states = (
            {
                "REGISTERED_UNQUALIFIED",
                "QUALIFICATION_STARTED",
                "QUALIFIED",
                "QUALIFICATION_FAILED",
            }
            if subscription_qualification
            else {"REGISTERED_UNQUALIFIED"}
        )
        if registration_state not in eligible_states:
            raise PermissionError("registration is not eligible for qualification")
        if "registration_lineage" in registration:
            lineage = _validated_registration_replacement_lineage(
                registration.get("registration_lineage"),
                self.keys.verify,
                require_current_release=False,
            )
            account_binding = registration.get("subscription_account_binding")
            if (
                lineage.get("successor_registration_id") != identifier
                or not isinstance(account_binding, dict)
                or account_binding.get("account_identity_digest")
                != lineage.get("expected_account_identity_digest")
                or account_binding.get("plan_type")
                != lineage.get("expected_account_plan_type")
            ):
                raise PermissionError(
                    "registration replacement lineage identity differs"
                )
        valid, detail = validate_provider_registration_contract(registration)
        if not valid:
            raise PermissionError(
                f"registration contract is incomplete or invalid: {detail}"
            )
        if registration.get("registration_schema_version") in {4, 5}:
            self.observer.validate_registered_executable(
                registration,
                _positive_int(
                    payload.get("client_executable_handle"),
                    "client executable handle",
                ),
            )
        elif "client_executable_handle" in payload:
            raise ValueError("client executable handle is unsupported")
        else:
            configured = Path(
                str(registration["canonical_executable_path"])
            ).resolve(strict=True)
            executable_content = configured.read_bytes()
            if (
                str(configured) != registration["canonical_executable_path"]
                or hashlib.sha256(executable_content).hexdigest()
                != registration["executable_sha256"]
                or len(executable_content) != registration["executable_size"]
            ):
                raise PermissionError(
                    "registered provider executable changed before qualification"
                )
        qualification_id = f"provider-qualification:{uuid.uuid4().hex}"
        retry_authorization: dict[str, Any] | None = None
        recovering_qualification = registration_state == "QUALIFICATION_STARTED"
        if subscription_qualification:
            if qualification_retry:
                qualification_id = _text(
                    payload["retry_qualification_id"],
                    "retry qualification ID",
                )
                retry_record = self.store.get(
                    "qualifications", qualification_id
                )
                retry_authorization = (
                    retry_record.get("retry_authorization")
                    if isinstance(retry_record, dict)
                    else None
                )
                if (
                    retry_record is None
                    or retry_record.get("service_state")
                    not in {
                        "QUALIFICATION_RETRY_AUTHORIZED",
                        "EXECUTION_STARTED",
                    }
                    or not isinstance(retry_authorization, dict)
                    or not self.keys.verify(
                        "provider-qualification-retry-authorization",
                        retry_authorization,
                    )
                    or retry_authorization.get("registration_id") != identifier
                    or retry_authorization.get("retry_qualification_id")
                    != qualification_id
                    or retry_authorization.get("authorized_client_sid")
                    != client_sid
                    or retry_authorization.get("retry_generation") != 2
                    or retry_authorization.get("required_authority_version")
                    != SERVICE_VERSION
                    or retry_authorization.get("required_host_version")
                    != SERVICE_VERSION
                    or registration.get("qualification_evidence_id")
                    != retry_authorization.get("qualification_id")
                    or registration.get("qualification_evidence_digest")
                    != retry_authorization.get(
                        "qualification_failure_digest"
                    )
                ):
                    raise PermissionError(
                        "Provider qualification retry authorization is invalid"
                    )
            elif registration_state in {"QUALIFIED", "QUALIFICATION_FAILED"}:
                qualification_id = str(
                    registration.get("qualification_evidence_id", "")
                )
            else:
                provider_id = str(registration["logical_provider_id"])
                qualification_id = "provider-qualification:" + hashlib.sha256(
                    (
                        provider_id
                        + "-subscription-qualification-v1\0"
                        + identifier
                        + "\0"
                        + str(registration["configuration_digest"])
                    ).encode("utf-8")
                ).hexdigest()[:32]
            if (
                not qualification_id.startswith("provider-qualification:")
                or len(qualification_id)
                != len("provider-qualification:") + 32
            ):
                raise PermissionError(
                    "Provider qualification terminal identity is invalid"
                )
            pending_claims = self._pending_provider_operation_claims()
            if (
                pending_claims["registrations"]
                or pending_claims["registration_retries"]
                or any(
                    value != qualification_id
                    for value in pending_claims["qualifications"]
                )
                or any(
                    value != qualification_id
                    for value in pending_claims["qualification_retries"]
                )
            ):
                raise PermissionError(
                    "Another provider operation requires exact recovery first"
                )
            if hasattr(self.observer, "qualification_identifier"):
                observed_qualification_id = str(
                    self.observer.qualification_identifier(
                        registration, qualification_id
                    )
                )
                if observed_qualification_id != qualification_id:
                    raise PermissionError(
                        "Provider Host planned qualification ID differs"
                    )
            if (
                not qualification_retry
                and registration_state in {"QUALIFIED", "QUALIFICATION_FAILED"}
            ):
                qualification = self.store.get(
                    "qualifications", qualification_id
                )
                expected_qualification_state = registration_state
                if (
                    qualification is None
                    or qualification.pop("service_state", None)
                    != expected_qualification_state
                    or set(qualification) not in (
                        {"start", "evidence"},
                        {"start", "evidence", "retry_authorization"},
                    )
                    or not isinstance(qualification.get("start"), dict)
                    or not isinstance(qualification.get("evidence"), dict)
                    or qualification["evidence"].get("id") != qualification_id
                    or qualification["evidence"].get("registration_id")
                    != identifier
                    or not self.keys.verify(
                        "provider-qualification-start", qualification["start"]
                    )
                    or not self.keys.verify(
                        "provider-qualification", qualification["evidence"]
                    )
                ):
                    raise PermissionError(
                        "Provider qualification terminal record is incomplete"
                    )
                return {
                    "registration": registration,
                    "qualification": qualification["evidence"],
                    "qualification_start": qualification["start"],
                }
        def registration_for_qualification_retry(
            value: dict[str, Any],
        ) -> dict[str, Any]:
            normalized = dict(value)
            for name in (
                "qualified_version",
                "qualification_timestamp",
                "qualification_method",
                "qualification_evidence_id",
                "qualification_evidence_digest",
            ):
                normalized.pop(name, None)
            normalized["qualified_version"] = None
            normalized["qualification_timestamp"] = None
            normalized["qualification_method"] = "none"
            normalized["qualification_evidence_id"] = None
            normalized["qualification_evidence_digest"] = None
            normalized["qualification_result"] = "not-qualified"
            normalized["registration_lifecycle"] = "REGISTERED_UNQUALIFIED"
            normalized["configuration_digest"] = (
                canonical_provider_registration_digest(normalized)
            )
            return normalized
        if registration_state == "QUALIFICATION_STARTED":
            qualification = self.store.get("qualifications", qualification_id)
            if (
                qualification is None
                or qualification.pop("service_state", None) != "EXECUTION_STARTED"
                or set(qualification) not in (
                    {"start"},
                    {"start", "retry_authorization"},
                )
                or not isinstance(qualification.get("start"), dict)
            ):
                raise PermissionError(
                    "Provider qualification claim is incomplete or ambiguous"
                )
            start = cast(dict[str, Any], qualification["start"])
            if (
                not self.keys.verify("provider-qualification-start", start)
                or start.get("id") != f"{qualification_id}:started"
                or start.get("registration_id") != identifier
                or start.get("provider_id") != registration["logical_provider_id"]
                or start.get("authorization_reference") != client_sid
                or not isinstance(start.get("event_challenge"), str)
                or len(str(start["event_challenge"])) != 64
            ):
                raise PermissionError("Provider qualification claim binding differs")
            challenge = str(start["event_challenge"])
        else:
            challenge = (
                _sha256_text(
                    retry_authorization.get("event_challenge"),
                    "qualification retry event challenge",
                )
                if retry_authorization is not None
                else secrets.token_hex(32)
            )
            start = self.keys.sign(
                "provider-qualification-start",
                {
                    "id": f"{qualification_id}:started",
                    "kind": "provider_qualification_started",
                    "schema_version": 2,
                    "registration_id": identifier,
                    "provider_id": registration["logical_provider_id"],
                    "authorization_reference": client_sid,
                    "event_challenge": challenge,
                    **(
                        {
                            "retry_authorization": retry_authorization,
                            "retry_authorization_digest": _canonical_digest(
                                retry_authorization
                            ),
                        }
                        if retry_authorization is not None
                        else {}
                    ),
                    "started_at": _now(),
                },
            )
            if qualification_retry:
                assert retry_authorization is not None
                self.store.begin_provider_qualification_retry(
                    identifier,
                    qualification_id,
                    registration,
                    start,
                    retry_authorization,
                    challenge=challenge,
                )
                registration_state = "QUALIFICATION_STARTED"
            elif subscription_qualification:
                self.store.begin_provider_qualification(
                    identifier,
                    qualification_id,
                    registration,
                    start,
                    challenge=challenge,
                )
                registration_state = "QUALIFICATION_STARTED"
            else:
                self.store.insert(
                    "qualifications",
                    qualification_id,
                    "EXECUTION_STARTED",
                    {"start": start},
                    registration_id=identifier,
                    challenge=challenge,
                )
        if qualification_retry:
            # Keep the exact terminal failure payload durably attached to the
            # QUALIFICATION_STARTED row.  It is the restart-time binding for
            # the one Founder-authorized retry.  Only the in-memory provider
            # observation uses a clean REGISTERED_UNQUALIFIED projection.
            registration = registration_for_qualification_retry(registration)
        observed_registration = (
            {
                **registration,
                "_qualification_id": qualification_id,
                "_recovering_qualification": (
                    recovering_qualification
                ),
            }
            if registration.get("registration_schema_version") in {4, 5}
            else registration
        )
        observation = self.observer.qualify(observed_registration, challenge)
        normalized = (
            observation.raw_version_output.splitlines()[0].strip()[:200]
            if observation.raw_version_output
            else ""
        )
        command = (
            list(observation.production_command)
            if subscription_qualification
            else [registration["canonical_executable_path"], "--version"]
        )
        evidence: dict[str, Any] = {
            "id": qualification_id,
            "kind": "provider_qualification",
            "schema_version": (
                4
                if registration.get("registration_schema_version") == 5
                else 3
                if subscription_qualification
                else 2
            ),
            "registration_id": identifier,
            "registration_version": registration["registration_version"],
            "provider_id": registration["logical_provider_id"],
            "provider_instance_id": observation.provider_instance_id,
            "provider_run_id": qualification_id,
            "executable_sha256": registration["executable_sha256"],
            "launcher_sha256": registration["launcher_sha256"],
            "script_sha256": registration["script_sha256"],
            "qualification_command": command,
            "command_digest": hashlib.sha256(
                json.dumps(command).encode("utf-8")
            ).hexdigest(),
            "started_at": observation.started_at,
            "finished_at": observation.finished_at,
            "exit_status": observation.exit_status,
            "raw_version_output": observation.raw_version_output,
            "normalized_version": normalized,
            "qualification_method": "authority-service-restricted-launch",
            "qualification_result": (
                "qualified"
                if observation.exit_status == 0
                and qualified_version_is_valid(
                    str(registration["logical_provider_id"]), normalized
                )
                and (
                    not subscription_qualification
                    or normalized == registration.get("expected_version")
                )
                and observation.process_ownership.get("restricted") is True
                and observation.process_ownership.get("job_confined") is True
                and (
                    not subscription_qualification
                    or (
                        observation.process_ownership.get("executable")
                        == registration["canonical_executable_path"]
                        and observation.process_ownership.get(
                            "executable_sha256"
                        )
                        == registration["executable_sha256"]
                    )
                )
                and (
                    not subscription_qualification
                    or (
                        observation.process_ownership.get("integrity_level")
                        == "medium"
                        and isinstance(observation.authentication_probe, dict)
                        and observation.authentication_probe.get(
                            "authentication_method"
                        )
                        == (
                            "chatgpt-subscription"
                            if registration["logical_provider_id"] == "codex"
                            else CLAUDE_AUTHENTICATION_MODE
                        )
                        and observation.structured_output
                        == {
                            "status": "ok",
                            "provider": registration["logical_provider_id"],
                            "effort": "medium",
                            "nonce": (
                                "keeper-codex-qualification-v1"
                                if registration["logical_provider_id"] == "codex"
                                else "keeper-claude-qualification-v1"
                            ),
                        }
                        and observation.prompt_digest is not None
                        and observation.schema_digest is not None
                    )
                )
                else "failed"
            ),
            "authorized_by": client_sid,
            "authorization_reference": start["id"],
            "event_challenge": challenge,
            "ownership": observation.process_ownership,
            "failure_reason": observation.failure_reason,
            "authentication_probe": observation.authentication_probe,
            "usage_observation": observation.usage_observation,
            "structured_output": observation.structured_output,
            "qualified_model_id": (
                registration.get("model_or_service_identity")
                if subscription_qualification
                else None
            ),
            "qualified_reasoning_level": (
                "medium" if subscription_qualification else None
            ),
            "prompt_digest": observation.prompt_digest,
            "schema_digest": observation.schema_digest,
            "registration_configuration_digest": registration[
                "configuration_digest"
            ],
            "pricing_authority_digest": _canonical_digest(
                registration["pricing_authority"]
            ),
            "usage_policy_digest": (
                _canonical_digest(registration["usage_policy"])
                if subscription_qualification
                else None
            ),
            "authentication_binding_digest": (
                _canonical_digest(
                    registration["windows_authentication_binding"]
                )
                if subscription_qualification
                else None
            ),
        }
        # Preserve the legacy digest contract while changing the owning writer.
        evidence["qualification_method"] = "protected-registered-launch"
        evidence["evidence_digest"] = qualification_evidence_digest(evidence)
        evidence = self.keys.sign("provider-qualification", evidence)
        state = (
            "QUALIFIED"
            if evidence["qualification_result"] == "qualified"
            else "QUALIFICATION_FAILED"
        )
        qualification_record = {
            "start": start,
            "evidence": evidence,
            **(
                {"retry_authorization": retry_authorization}
                if retry_authorization is not None
                else {}
            ),
        }
        if state == "QUALIFIED":
            updated = apply_protected_qualification(
                registration,
                evidence,
                authority_verifier=self.keys.verify,
                expected_challenge=challenge,
                expected_authorization_reference=str(start["id"]),
            )
        else:
            updated = {
                **registration,
                "qualification_timestamp": observation.finished_at,
                "qualification_method": "protected-registered-launch",
                "qualification_result": "failed",
                "registration_lifecycle": "QUALIFICATION_FAILED",
                "qualification_evidence_id": qualification_id,
                "qualification_evidence_digest": evidence["evidence_digest"],
            }
            updated["configuration_digest"] = canonical_provider_registration_digest(
                updated
            )
        if (
            state == "QUALIFIED"
            and subscription_qualification
            and hasattr(self.observer, "bind_qualified_provider")
        ):
            # The database lifecycle is the execution fence. Keep the exact
            # immutable registration payload schema-valid so recovery cannot
            # smuggle operational metadata into provider authority.
            uncertain_registration = dict(updated)
            self.store.stage_provider_qualification_binding(
                identifier,
                qualification_id,
                uncertain_registration,
                qualification_record,
                expected_registration=registration_state,
            )
            try:
                self.observer.bind_qualified_provider(updated, evidence)
            except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as error:
                self.store.transition(
                    "registrations",
                    identifier,
                    "UNCERTAIN",
                    "UNCERTAIN",
                    uncertain_registration,
                )
                self.store.transition(
                    "qualifications",
                    qualification_id,
                    "UNCERTAIN",
                    "UNCERTAIN",
                    {"start": start, "evidence": evidence},
                )
                raise RuntimeError(
                    "Provider Host qualification binding is uncertain"
                ) from error
            completed_registration = {
                **updated,
            }
            self.store.complete_provider_qualification_binding(
                identifier,
                qualification_id,
                completed_registration,
                qualification_record,
            )
            updated = completed_registration
        elif subscription_qualification:
            if state == "QUALIFIED":
                self.store.complete_provider_qualification(
                    identifier,
                    qualification_id,
                    updated,
                    qualification_record,
                    expected_registration=registration_state,
                )
            else:
                self.store.fail_provider_qualification(
                    identifier,
                    qualification_id,
                    updated,
                    qualification_record,
                    expected_registration=registration_state,
                )
        else:
            self.store.transition(
                "qualifications",
                qualification_id,
                "EXECUTION_STARTED",
                state,
                qualification_record,
            )
            self.store.transition(
                "registrations",
                identifier,
                "REGISTERED_UNQUALIFIED",
                state,
                updated,
            )
        return {
            "registration": updated,
            "qualification": evidence,
            "qualification_start": start,
        }

    def _reconcile_provider_qualification(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        if set(payload) != {"registration_id"}:
            raise PermissionError(
                "Provider qualification reconciliation fields are invalid"
            )
        if self.observer is None or not hasattr(
            self.observer, "bind_qualified_provider"
        ):
            raise RuntimeError("authority provider observer is unavailable")
        identifier = _text(payload["registration_id"], "registration ID")
        registration = self.store.get("registrations", identifier)
        if (
            registration is None
            or registration.pop("service_state", None) != "UNCERTAIN"
            or registration.get("registration_schema_version") not in {4, 5}
            or registration.get("registration_lifecycle") != "QUALIFIED"
        ):
            raise PermissionError(
                "Provider qualification is not eligible for reconciliation"
            )
        qualification_id = registration.get("qualification_evidence_id")
        if not isinstance(qualification_id, str) or not qualification_id:
            raise PermissionError(
                "Provider qualification evidence identity is unavailable"
            )
        qualification = self.store.get("qualifications", qualification_id)
        if (
            qualification is None
            or qualification.pop("service_state", None) != "UNCERTAIN"
            or not isinstance(qualification.get("start"), dict)
            or not isinstance(qualification.get("evidence"), dict)
        ):
            raise PermissionError(
                "Provider qualification evidence is not reconcilable"
            )
        evidence = cast(dict[str, Any], qualification["evidence"])
        if (
            evidence.get("id") != qualification_id
            or evidence.get("registration_id") != identifier
            or evidence.get("qualification_result") != "qualified"
            or registration.get("qualification_evidence_digest")
            != evidence.get("evidence_digest")
        ):
            raise PermissionError(
                "Provider qualification reconciliation binding differs"
            )
        completed_registration = dict(registration)
        reconciled_at = _now()
        self.observer.bind_qualified_provider(completed_registration, evidence)
        self.store.complete_provider_qualification_binding(
            identifier,
            qualification_id,
            completed_registration,
            qualification,
        )
        return {
            "registration": completed_registration,
            "qualification": evidence,
            "reconciled": True,
            "reconciled_at": reconciled_at,
        }

    def _reserve_attempt(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        fields = {
            "registration_id",
            "keeper_run_id",
            "task_id",
            "stage_id",
            "role",
            "attempt_number",
            "provider_run_id",
            "provider_instance_id",
            "evidence_path",
            "prompt_path",
            "stdout_path",
            "stderr_path",
            "workspace",
            "timeout_seconds",
            "reasoning_level",
            "environment",
            "launch_authorization_id",
            "authorization_generation",
            "delegation_id",
            "authorization_expires_at",
            "project_id",
            "charter_id",
            "charter_revision",
            "task_revision",
            "founder_approval_event_id",
            "founder_approval_event_digest",
            "founder_authenticated_session_id",
            "founder_principal_sid",
        }
        accepted_field_sets = {
            frozenset(fields),
            frozenset(fields | {"provider_input_required"}),
            frozenset(fields | {"model_id"}),
            frozenset(fields | {"provider_input_required", "model_id"}),
            frozenset(fields | {"model_id", "prompt_digest"}),
            frozenset(
                fields
                | {"provider_input_required", "model_id", "prompt_digest"}
            ),
        }
        host_binding_fields = {
            "workflow_id",
            "work_item_id",
            "assignment_id",
            "provider_account_id",
            "workspace_identity",
            "workspace_reservation_id",
        }
        accepted_field_sets |= {
            frozenset(set(item) | host_binding_fields)
            for item in tuple(accepted_field_sets)
        }
        if set(payload) not in accepted_field_sets:
            raise ValueError("authority operation payload fields are invalid")
        registration_id = _text(payload["registration_id"], "registration ID")
        registration = self.store.get("registrations", registration_id)
        if registration is None or registration.pop("service_state", None) != "QUALIFIED":
            raise PermissionError("provider registration is not service-qualified")
        valid_registration, detail = validate_provider_registration_contract(
            registration
        )
        if not valid_registration:
            raise PermissionError(
                f"provider registration is no longer valid: {detail}"
            )
        if (
            registration.get("registration_schema_version") in {4, 5}
            and not host_binding_fields.issubset(payload)
        ):
            raise PermissionError(
                "Provider Host durable launch binding is incomplete"
            )
        authorization_id = _text(
            payload["launch_authorization_id"], "launch authorization ID"
        )
        authorization = self.store.get(
            "launch_authorizations", authorization_id
        )
        if (
            authorization is None
            or authorization.pop("service_state", None) != "ACTIVE"
            or authorization.get("project_id") != payload["project_id"]
            or authorization.get("charter_id") != payload["charter_id"]
            or authorization.get("charter_revision")
            != payload["charter_revision"]
            or authorization.get("delegation_id") != payload["delegation_id"]
            or authorization.get("founder_approval_event_id")
            != payload["founder_approval_event_id"]
            or authorization.get("founder_approval_event_digest")
            != payload["founder_approval_event_digest"]
            or authorization.get("founder_authenticated_session_id")
            != payload["founder_authenticated_session_id"]
            or authorization.get("founder_principal_sid")
            != payload["founder_principal_sid"]
            or authorization.get("authorization_generation")
            != payload["authorization_generation"]
            or authorization.get("authorized_client_sid") != client_sid
            or authorization.get("expires_at")
            != payload["authorization_expires_at"]
        ):
            raise PermissionError(
                "attempt launch authorization generation is invalid"
            )
        role = _text(payload["role"], "role")
        normalized_role = _normalized_provider_role(role)
        eligible_roles = registration.get("role_eligibility")
        if (
            not isinstance(eligible_roles, list)
            or normalized_role not in eligible_roles
        ):
            raise PermissionError(
                "provider role is outside the qualified registration"
            )
        stage_id = _text(payload["stage_id"], "stage ID")
        provider_input_required_value = payload.get("provider_input_required")
        if provider_input_required_value is None:
            provider_input_required = _reviewer_role(normalized_role)
        elif type(provider_input_required_value) is not bool:
            raise ValueError(
                "authority provider input requirement is invalid"
            )
        else:
            provider_input_required = provider_input_required_value
        if (
            registration.get("registration_schema_version") in {4, 5}
            and _reviewer_role(normalized_role)
            and not provider_input_required
        ):
            raise PermissionError("reviewer provider input cannot be optional")
        attempt_id = (
            f"provider-attempt:{_text(payload['keeper_run_id'], 'run ID')}:"
            f"{_text(payload['provider_run_id'], 'provider run ID')}"
        )
        challenge = secrets.token_hex(32)
        reasoning_level = _choice(
            payload["reasoning_level"],
            {"low", "medium", "high", "xhigh", "extra-high"},
        )
        declared_efforts = registration.get("effort_levels")
        if (
            not isinstance(declared_efforts, list)
            or reasoning_level not in declared_efforts
        ):
            raise PermissionError(
                "provider reasoning effort is outside the qualified declaration"
            )
        model_id = payload.get(
            "model_id", registration.get("model_or_service_identity")
        )
        if not isinstance(model_id, str) or not model_id:
            raise PermissionError("provider model identity is unavailable")
        model_allowlist = registration.get("model_allowlist")
        if (
            registration.get("registration_schema_version") in {4, 5}
            and (
                "model_id" not in payload
                or "prompt_digest" not in payload
                or not isinstance(model_allowlist, list)
                or model_id not in model_allowlist
            )
        ):
            raise PermissionError(
                "provider model is outside the qualified allowlist"
            )
        authority_prompt: str | None = None
        output_schema_digest: str | None = None
        canonical_prompt_path: str
        if registration.get("registration_schema_version") in {4, 5}:
            if self.observer is None:
                raise RuntimeError("authority provider observer is unavailable")
            prompt_path, prompt_content = self.observer.read_exchange_file(
                payload["prompt_path"], "prompt", 1_048_576
            )
            canonical_prompt_path = str(prompt_path)
            prompt_digest = _sha256_text(
                payload["prompt_digest"], "prompt digest"
            )
            if hashlib.sha256(prompt_content).hexdigest() != prompt_digest:
                raise PermissionError("Authority provider prompt digest changed")
            try:
                authority_prompt = prompt_content.decode("utf-8")
            except UnicodeDecodeError as error:
                raise PermissionError(
                    "Authority provider prompt is not UTF-8"
                ) from error
            output_schema_digest = _canonical_digest(
                authority_provider_output_schema(
                    normalized_role,
                    provider_input_required=provider_input_required,
                )
            )
        else:
            canonical_prompt_path = _canonical_path(
                payload["prompt_path"], "prompt path"
            )
        record = self.keys.sign(
            "provider-launch-authorization",
            {
                "id": attempt_id,
                "kind": "provider_launch_authorization",
                "schema_version": 1,
                "registration_id": registration_id,
                "registration_digest": registration["configuration_digest"],
                "pricing_authority_digest": _canonical_digest(
                    registration.get("pricing_authority")
                ),
                "usage_policy_digest": (
                    _canonical_digest(registration["usage_policy"])
                    if isinstance(registration.get("usage_policy"), dict)
                    else None
                ),
                "authentication_binding_digest": (
                    _canonical_digest(
                        registration["windows_authentication_binding"]
                    )
                    if isinstance(
                        registration.get("windows_authentication_binding"),
                        dict,
                    )
                    else None
                ),
                "model_allowlist_digest": (
                    _canonical_digest(registration["model_allowlist"])
                    if isinstance(registration.get("model_allowlist"), list)
                    else None
                ),
                "subscription_account_binding_digest": (
                    _canonical_digest(
                        registration["subscription_account_binding"]
                    )
                    if isinstance(
                        registration.get("subscription_account_binding"), dict
                    )
                    else None
                ),
                "model_capability_binding_digest": (
                    _canonical_digest(registration["model_capability_binding"])
                    if isinstance(
                        registration.get("model_capability_binding"), dict
                    )
                    else None
                ),
                "keeper_run_id": payload["keeper_run_id"],
                "task_id": _text(payload["task_id"], "task ID"),
                "stage_id": stage_id,
                "role": role,
                "attempt_number": _positive_int(
                    payload["attempt_number"], "attempt number"
                ),
                "provider_run_id": payload["provider_run_id"],
                "provider_instance_id": _text(
                    payload["provider_instance_id"], "provider instance ID"
                ),
                "evidence_path": _canonical_path(
                    payload["evidence_path"], "evidence path"
                ),
                "prompt_path": canonical_prompt_path,
                "stdout_path": _canonical_path(
                    payload["stdout_path"], "stdout path"
                ),
                "stderr_path": _canonical_path(
                    payload["stderr_path"], "stderr path"
                ),
                "workspace": _canonical_path(payload["workspace"], "workspace"),
                "timeout_seconds": _bounded_int(
                    payload["timeout_seconds"], "timeout seconds", 1, 86_400
                ),
                "reasoning_level": reasoning_level,
                "model_id": model_id,
                "prompt_digest": (
                    _sha256_text(payload["prompt_digest"], "prompt digest")
                    if "prompt_digest" in payload
                    else None
                ),
                "authority_prompt": authority_prompt,
                "output_schema_digest": output_schema_digest,
                "environment": _safe_environment(payload["environment"]),
                "provider_input_required": provider_input_required,
                "launch_challenge": challenge,
                "authorized_client_sid": client_sid,
                "reserved_at": _now(),
                "launch_authorization_id": authorization_id,
                "authorization_generation": payload[
                    "authorization_generation"
                ],
                "revocation_epoch": authorization["revocation_epoch"],
                "delegation_id": payload["delegation_id"],
                "founder_approval_event_id": payload[
                    "founder_approval_event_id"
                ],
                "founder_approval_event_digest": payload[
                    "founder_approval_event_digest"
                ],
                "founder_authenticated_session_id": payload[
                    "founder_authenticated_session_id"
                ],
                "founder_principal_sid": payload["founder_principal_sid"],
                "authorization_expires_at": payload[
                    "authorization_expires_at"
                ],
                "project_id": payload["project_id"],
                "charter_id": payload["charter_id"],
                "charter_revision": payload["charter_revision"],
                "task_revision": payload["task_revision"],
                "workflow_id": (
                    _text(payload["workflow_id"], "workflow ID")
                    if "workflow_id" in payload
                    else None
                ),
                "work_item_id": (
                    _text(payload["work_item_id"], "work item ID")
                    if "work_item_id" in payload
                    else None
                ),
                "assignment_id": (
                    _text(payload["assignment_id"], "assignment ID")
                    if "assignment_id" in payload
                    else None
                ),
                "provider_account_id": (
                    _text(payload["provider_account_id"], "provider account ID")
                    if "provider_account_id" in payload
                    else None
                ),
                "workspace_identity": (
                    _text(payload["workspace_identity"], "workspace identity")
                    if "workspace_identity" in payload
                    else None
                ),
                "workspace_reservation_id": (
                    _text(
                        payload["workspace_reservation_id"],
                        "workspace reservation ID",
                    )
                    if "workspace_reservation_id" in payload
                    else None
                ),
            },
        )
        self.store.insert(
            "attempts",
            attempt_id,
            "RESERVED",
            record,
            registration_id=registration_id,
            run_id=str(payload["keeper_run_id"]),
            attempt_number=int(payload["attempt_number"]),
            challenge=challenge,
        )
        return {"attempt": record, "attempt_id": attempt_id}

    def _verified_executive_input_receipt(
        self,
        value: object,
        attempt: dict[str, Any],
        provider_input: dict[str, Any],
        *,
        provider_input_digest: str,
        delivered_input_digest: str,
        manifest_digest: str,
    ) -> dict[str, object]:
        if not isinstance(value, dict):
            raise PermissionError(
                "provider input lacks an Executive commit receipt"
            )
        verifier = self.founder_capability_verifier
        if verifier is None:
            raise PermissionError(
                "Executive commit receipt verification is unavailable"
            )
        composition = provider_input["composition_identity"]
        if (
            composition == "PRODUCTION_AUTHORITY"
            and type(verifier) is not ProductionFounderCapabilityVerifier
        ) or (
            composition == "TEST_AUTHORITY"
            and type(verifier) is not TestFounderCapabilityVerifier
        ):
            raise PermissionError(
                "Executive receipt composition does not match Authority"
            )
        receipt = verifier.verify_executive_input_receipt(value)
        issued_at = datetime.fromisoformat(str(receipt["issued_at"]))
        now = datetime.now(UTC)
        if issued_at > now + timedelta(seconds=5) or issued_at < (
            now - timedelta(minutes=5)
        ):
            raise PermissionError(
                "Executive delivered-input receipt is stale"
            )
        expected: dict[str, object] = {
            "repository_mode": (
                "PRODUCTION"
                if provider_input["composition_identity"]
                == "PRODUCTION_AUTHORITY"
                else "TEST"
            ),
            "authority_attempt_id": attempt.get("id"),
            "reviewer_attempt_id": provider_input["reviewer_attempt_id"],
            "reviewer_assignment_id": attempt.get("task_id"),
            "project_id": attempt.get("project_id"),
            "charter_id": attempt.get("charter_id"),
            "charter_revision": attempt.get("charter_revision"),
            "workflow_id": provider_input["workflow_id"],
            "work_item_id": attempt.get("stage_id"),
            "producer_assignment_id": provider_input[
                "producer_assignment_id"
            ],
            "producer_attempt_id": provider_input["producer_attempt_id"],
            "provider_id": provider_input["provider_id"],
            "account_id": provider_input["account_id"],
            "session_id": attempt.get("provider_instance_id"),
            "model_id": provider_input["model_id"],
            "workspace": provider_input["workspace"],
            "composition_identity": provider_input[
                "composition_identity"
            ],
            "provider_input_digest": provider_input_digest,
            "delivered_input_digest": delivered_input_digest,
            "manifest_digest": manifest_digest,
            "reference_set_digest": structured_digest(
                provider_input["references"]
            ),
            "session_slot_claimed": True,
            "launch_claim_state": "LAUNCH_CLAIMED",
        }
        mismatches = [
            name
            for name, expected_value in expected.items()
            if receipt.get(name) != expected_value
        ]
        if mismatches:
            raise PermissionError(
                "Executive delivered-input receipt binding mismatch: "
                + ", ".join(sorted(mismatches))
            )
        return receipt

    def _bind_provider_input(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(
            payload,
            {
                "attempt_id",
                "provider_input",
                "provider_input_digest",
                "delivered_input_digest",
                "manifest_digest",
                "executive_commit_receipt",
            },
        )
        attempt_id = _text(payload["attempt_id"], "attempt ID")
        provider_input = validate_provider_input(payload["provider_input"])
        provider_input_digest = _sha256_text(
            payload["provider_input_digest"], "provider input digest"
        )
        delivered_input_digest = _sha256_text(
            payload["delivered_input_digest"], "delivered input digest"
        )
        manifest_digest = _sha256_text(
            payload["manifest_digest"], "manifest digest"
        )
        if (
            structured_digest(provider_input) != provider_input_digest
            or provider_input["delivered_input_digest"]
            != delivered_input_digest
            or provider_input["manifest_digest"] != manifest_digest
            or provider_input["authority_attempt_id"] != attempt_id
        ):
            raise PermissionError("provider input digest binding is invalid")
        current = self.store.get("attempts", attempt_id)
        if current is None:
            raise PermissionError("provider attempt is unavailable")
        state = current.pop("service_state", None)
        receipt = self._verified_executive_input_receipt(
            payload["executive_commit_receipt"],
            current,
            provider_input,
            provider_input_digest=provider_input_digest,
            delivered_input_digest=delivered_input_digest,
            manifest_digest=manifest_digest,
        )
        receipt_digest = structured_digest(receipt)
        if state == "INPUT_BOUND":
            if (
                current.get("authorized_client_sid") != client_sid
                or current.get("provider_input") != provider_input
                or current.get("provider_input_digest")
                != provider_input_digest
                or current.get("delivered_input_digest")
                != delivered_input_digest
                or current.get("executive_commit_receipt") != receipt
                or current.get("executive_commit_receipt_digest")
                != receipt_digest
                or not self.keys.verify("provider-input-binding", current)
            ):
                raise PermissionError(
                    "provider input is already bound differently"
                )
            return {"attempt": {**current, "service_state": "INPUT_BOUND"}}
        expected = {
            "project_id": current.get("project_id"),
            "charter_id": current.get("charter_id"),
            "charter_revision": current.get("charter_revision"),
            "reviewer_assignment_id": current.get("task_id"),
            "work_item_id": current.get("stage_id"),
            "session_id": current.get("provider_instance_id"),
            "launch_authorization_id": current.get(
                "launch_authorization_id"
            ),
            "authorization_generation": current.get(
                "authorization_generation"
            ),
        }
        mismatches = [
            name
            for name, value in expected.items()
            if provider_input[name] != value
        ]
        if str(Path(str(provider_input["workspace"])).resolve()).casefold() != str(
            Path(str(current.get("workspace"))).resolve()
        ).casefold():
            mismatches.append("workspace")
        if (
            state != "RESERVED"
            or current.get("authorized_client_sid") != client_sid
            or str(current.get("role", "")).casefold() != "reviewer"
            or (
                provider_input["composition_identity"]
                == "TEST_AUTHORITY"
                and type(self.founder_capability_verifier)
                is not TestFounderCapabilityVerifier
            )
            or mismatches
        ):
            raise PermissionError(
                "provider input does not match the reserved Authority attempt"
                + (
                    ": " + ", ".join(sorted(mismatches))
                    if mismatches
                    else ""
                )
            )
        bound = self.keys.sign(
            "provider-input-binding",
            {
                **current,
                "kind": "provider_input_binding",
                "provider_input": provider_input,
                "provider_input_digest": provider_input_digest,
                "delivered_input_digest": delivered_input_digest,
                "manifest_digest": manifest_digest,
                "executive_commit_receipt": receipt,
                "executive_commit_receipt_digest": receipt_digest,
                "provider_input_bound_at": _now(),
            },
        )
        self.store.transition(
            "attempts",
            attempt_id,
            "RESERVED",
            "INPUT_BOUND",
            bound,
        )
        return {"attempt": {**bound, "service_state": "INPUT_BOUND"}}

    def _execute_provider(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, {"attempt_id"})
        if self.observer is None:
            raise RuntimeError("authority provider observer is unavailable")
        attempt_id = _text(payload["attempt_id"], "attempt ID")
        attempt = self.store.get("attempts", attempt_id)
        if attempt is None:
            raise PermissionError("provider launch is not reserved")
        state = attempt.pop("service_state", None)
        provider_input = attempt.get("provider_input")
        input_binding_valid = False
        if state == "INPUT_BOUND" and isinstance(provider_input, dict):
            try:
                validated_input = validate_provider_input(provider_input)
                receipt = self._verified_executive_input_receipt(
                    attempt.get("executive_commit_receipt"),
                    attempt,
                    validated_input,
                    provider_input_digest=str(
                        attempt.get("provider_input_digest")
                    ),
                    delivered_input_digest=str(
                        attempt.get("delivered_input_digest")
                    ),
                    manifest_digest=str(attempt.get("manifest_digest")),
                )
            except (PermissionError, ValueError):
                pass
            else:
                input_binding_valid = (
                    self.keys.verify("provider-input-binding", attempt)
                    and structured_digest(validated_input)
                    == attempt.get("provider_input_digest")
                    and validated_input["delivered_input_digest"]
                    == attempt.get("delivered_input_digest")
                    and validated_input["manifest_digest"]
                    == attempt.get("manifest_digest")
                    and structured_digest(receipt)
                    == attempt.get("executive_commit_receipt_digest")
                )
        if (
            state not in {"RESERVED", "INPUT_BOUND"}
            or (
                _provider_input_is_required(attempt)
                and state != "INPUT_BOUND"
            )
            or (
                state == "INPUT_BOUND"
                and not input_binding_valid
            )
        ):
            raise PermissionError(
                "provider launch is not reserved or validly input-bound"
            )
        if attempt.get("authorized_client_sid") != client_sid:
            raise PermissionError("provider launch belongs to another client")
        registration = self.store.get(
            "registrations", str(attempt["registration_id"])
        )
        if registration is None or registration.pop("service_state", None) != "QUALIFIED":
            raise PermissionError("provider registration is not qualified")
        valid_registration, detail = validate_provider_registration_contract(
            registration
        )
        if not valid_registration:
            raise PermissionError(
                f"provider registration is no longer valid: {detail}"
            )
        normalized_role = _normalized_provider_role(
            str(attempt.get("role", ""))
        )
        if normalized_role not in registration.get("role_eligibility", []):
            raise PermissionError(
                "provider role is outside the qualified registration"
            )
        usage_observation = (
            self.observer.preflight_provider(registration, attempt)
            if hasattr(self.observer, "preflight_provider")
            else None
        )
        if isinstance(usage_observation, dict):
            usage_observation = {
                **usage_observation,
                "observed_at": usage_observation.get("observed_at") or _now(),
            }
        self._validate_codex_preflight_binding(registration, usage_observation)
        claim = self.keys.sign(
            "provider-launch-claim",
            {
                **attempt,
                "kind": "provider_launch_claim",
                "claimed_at": _now(),
                "claim_transaction_id": uuid.uuid4().hex,
                "usage_observation": usage_observation,
            },
        )
        try:
            self.store.claim_attempt_with_launch_authority(
                attempt_id,
                str(attempt["launch_authorization_id"]),
                int(attempt["authorization_generation"]),
                client_sid,
                claim,
                expected_attempt_state=str(state),
                provider_usage_policy=registration.get("usage_policy"),
                usage_observation=usage_observation,
            )
        except PermissionError as error:
            if not str(error).startswith("WAITING_FOR_USAGE_RESET:"):
                raise
            waiting = self.keys.sign(
                "provider-usage-wait",
                {
                    **attempt,
                    "kind": "provider_usage_wait",
                    "usage_observation": usage_observation,
                    "wait_reason": str(error).partition(":")[2].strip(),
                    "waited_at": _now(),
                },
            )
            self.store.transition(
                "attempts",
                attempt_id,
                str(state),
                "WAITING_FOR_USAGE_RESET",
                waiting,
            )
            raise
        started_result: dict[str, Any] = {}

        def on_started(observation: ProcessObservation) -> None:
            expected_integrity = (
                "medium"
                if registration.get("registration_schema_version") in {4, 5}
                else "low"
            )
            if (
                not observation.restricted
                or observation.integrity_level != expected_integrity
                or not observation.job_confined
            ):
                raise PermissionError(
                    "provider restricted confinement was not established"
                )
            expected_path = str(registration["launcher_path"])
            observed_path = str(observation.executable)
            path_matches = (
                os.path.normcase(os.path.abspath(observed_path))
                == os.path.normcase(os.path.abspath(expected_path))
                if registration.get("registration_schema_version") in {4, 5}
                else Path(observed_path).resolve() == Path(expected_path).resolve()
            )
            if (
                not path_matches
                or observation.executable_sha256
                != registration["launcher_sha256"]
            ):
                raise PermissionError(
                    "provider process identity differs from registration"
                )
            started = self.keys.sign(
                "provider-start",
                {
                    **claim,
                    "kind": "provider_execution_started",
                    "pid": observation.pid,
                    "process_creation_time": observation.creation_time,
                    "process_executable": observation.executable,
                    "process_executable_sha256": observation.executable_sha256,
                    "restricted_token": observation.restricted,
                    "integrity_level": observation.integrity_level,
                    "job_confined": observation.job_confined,
                    "started_at": _now(),
                    "completion_challenge": secrets.token_hex(32),
                },
            )
            self.store.transition(
                "attempts",
                attempt_id,
                "LAUNCH_CLAIMED",
                "EXECUTION_STARTED",
                started,
            )
            started_result.update(started)

        try:
            observed = self.observer.execute_provider(
                registration, claim, on_started
            )
        except Exception:
            # Once the durable claim is committed, any observer failure before
            # the service records process start is ambiguous: the observer may
            # have crossed the external process boundary before its callback.
            # Preserve the consumed claim as UNCERTAIN so restart/recovery can
            # reconcile it and the same attempt can never launch again.
            current = self.store.get("attempts", attempt_id)
            if isinstance(current, dict):
                current_state = current.pop("service_state", None)
                if current_state == "LAUNCH_CLAIMED":
                    uncertain = self.keys.sign(
                        "provider-launch-claim",
                        {
                            **current,
                            "launch_claim_state": "UNCERTAIN",
                            "uncertainty_kind": (
                                "PROVIDER_START_OBSERVATION_FAILED"
                            ),
                            "uncertain_at": _now(),
                        },
                    )
                    self.store.transition(
                        "attempts",
                        attempt_id,
                        "LAUNCH_CLAIMED",
                        "UNCERTAIN",
                        uncertain,
                    )
            raise
        if not started_result:
            raise RuntimeError("provider start was not service-observed")
        if registration.get("registration_schema_version") in {4, 5} and (
            observed.model_id != started_result.get("model_id")
            or observed.reasoning_level
            != started_result.get("reasoning_level")
            or observed.usage_observation
            != started_result.get("usage_observation")
            or not observed.command_digest
            or observed.prompt_digest != started_result.get("prompt_digest")
            or observed.schema_digest
            != started_result.get("output_schema_digest")
            or not observed.structured_event_digest
            or (
                getattr(self.observer, "provider_host_gateway", None)
                is not None
                and (
                    not observed.provider_host_envelope_digest
                    or not observed.provider_host_receipt_digest
                )
            )
        ):
            raise PermissionError(
                "Codex execution observation differs from its launch claim"
            )
        current = self.store.get("attempts", attempt_id)
        if (
            isinstance(current, dict)
            and current.get("service_state") == "CANCELLED"
        ):
            return {
                "attempt_id": attempt_id,
                "start": started_result,
                "cancelled": True,
                "process_result": {
                    "process_id": observed.process_id,
                    "exit_status": observed.exit_status,
                    "timed_out": observed.timed_out,
                    "stdout_path": observed.stdout_path,
                    "stderr_path": observed.stderr_path,
                },
            }
        normalized_result = {
            "COMPLETED": "completed",
            "CANCELLED": "cancelled",
            "TIMEOUT": "timed_out",
            "SUBSCRIPTION_EXHAUSTED": "waiting_for_usage_reset",
            "AUTHENTICATION_FAILED": "failed",
            "NETWORK_FAILURE": "failed",
            "INVALID_OUTPUT": "failed",
            "PROVIDER_ERROR": "failed",
        }.get(
            str(observed.failure_classification),
            "completed" if observed.exit_status == 0 else "failed",
        )
        completion_source = {
            **started_result,
            "execution_command_digest": observed.command_digest,
            "execution_prompt_digest": observed.prompt_digest,
            "execution_schema_digest": observed.schema_digest,
            "structured_event_digest": observed.structured_event_digest,
            "execution_usage_observation": observed.usage_observation,
            "failure_classification": observed.failure_classification,
            "provider_host_envelope_digest": (
                observed.provider_host_envelope_digest
            ),
            "provider_host_receipt_digest": observed.provider_host_receipt_digest,
        }
        completion = self._completion_record(
            attempt_id,
            completion_source,
            observed.provider_evidence_digest,
            observed.exit_status,
            normalized_result,
            observed.finished_at,
        )
        self.store.transition(
            "attempts",
            attempt_id,
            "EXECUTION_STARTED",
            normalized_result.upper(),
            completion,
        )
        return {
            "attempt_id": attempt_id,
            "start": started_result,
            "completion": completion,
            "process_result": {
                "process_id": observed.process_id,
                "exit_status": observed.exit_status,
                "timed_out": observed.timed_out,
                "stdout_path": observed.stdout_path,
                "stderr_path": observed.stderr_path,
            },
        }

    @staticmethod
    def _validate_codex_preflight_binding(
        registration: dict[str, Any],
        observation: dict[str, Any] | None,
    ) -> None:
        policy = registration.get("usage_policy")
        if policy is None:
            return
        if not isinstance(policy, dict):
            raise PermissionError("provider usage authority is malformed")
        if not isinstance(observation, dict):
            raise PermissionError("provider usage state is unavailable")
        account = registration.get("subscription_account_binding")
        models = registration.get("model_capability_binding")
        if (
            not isinstance(account, dict)
            or observation.get("authentication_method")
            != account.get("authentication_method")
            or observation.get("plan_type") != account.get("plan_type")
            or observation.get("account_identity_digest")
            != account.get("account_identity_digest")
            or not isinstance(models, dict)
            or observation.get("model_capabilities") != models.get("models")
            or observation.get("model_allowlist")
            != registration.get("model_allowlist")
        ):
            raise PermissionError(
                "provider subscription account or model capability changed"
            )

    def _record_provider_start(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, {"attempt_id", "pid"})
        if self.observer is None:
            raise RuntimeError("authority provider observer is unavailable")
        attempt_id = _text(payload["attempt_id"], "attempt ID")
        attempt = self.store.get("attempts", attempt_id)
        if attempt is None:
            raise PermissionError("provider launch is not reserved")
        state = attempt.pop("service_state", None)
        if state not in {"RESERVED", "INPUT_BOUND"}:
            raise PermissionError("provider launch is not reserved")
        if _provider_input_is_required(attempt):
            raise PermissionError(
                "typed reviewer execution must use Authority-bound provider input"
            )
        if attempt.get("authorized_client_sid") != client_sid:
            raise PermissionError("provider launch belongs to another client")
        observation = self.observer.observe_process(
            attempt, _positive_int(payload["pid"], "process ID")
        )
        if not observation.restricted or not observation.job_confined:
            raise PermissionError("provider restricted confinement was not established")
        expected = self.store.get("registrations", str(attempt["registration_id"]))
        if expected is None:
            raise PermissionError("provider registration is unavailable")
        expected.pop("service_state", None)
        expected_path = str(expected["launcher_path"])
        observed_path = str(observation.executable)
        path_matches = (
            os.path.normcase(os.path.abspath(observed_path))
            == os.path.normcase(os.path.abspath(expected_path))
            if expected.get("registration_schema_version") in {4, 5}
            else Path(observed_path).resolve() == Path(expected_path).resolve()
        )
        if (
            not path_matches
            or observation.executable_sha256 != expected["launcher_sha256"]
        ):
            raise PermissionError("provider process identity differs from registration")
        started = self.keys.sign(
            "provider-start",
            {
                **attempt,
                "kind": "provider_execution_started",
                "pid": observation.pid,
                "process_creation_time": observation.creation_time,
                "process_executable": observation.executable,
                "process_executable_sha256": observation.executable_sha256,
                "restricted_token": observation.restricted,
                "integrity_level": observation.integrity_level,
                "job_confined": observation.job_confined,
                "started_at": _now(),
                "completion_challenge": secrets.token_hex(32),
            },
        )
        self.store.transition(
            "attempts",
            attempt_id,
            str(state),
            "EXECUTION_STARTED",
            started,
        )
        return {"attempt": started, "attempt_id": attempt_id}

    def _finalize_completion(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, {"attempt_id"})
        if self.observer is None:
            raise RuntimeError("authority provider observer is unavailable")
        attempt_id = _text(payload["attempt_id"], "attempt ID")
        attempt = self.store.get("attempts", attempt_id)
        if attempt is None:
            raise PermissionError("provider attempt is not finalizable")
        state = attempt.pop("service_state", None)
        if state in {"COMPLETED", "FAILED"}:
            if (
                attempt.get("kind") != "provider_completion"
                or attempt.get("authorized_client_sid") != client_sid
                or not self.keys.verify("provider-completion", attempt)
            ):
                raise PermissionError(
                    "provider terminal completion is not authentic"
                )
            return {"completion": attempt, "attempt_id": attempt_id}
        if state != "EXECUTION_STARTED":
            raise PermissionError("provider attempt is not finalizable")
        if attempt.get("authorized_client_sid") != client_sid:
            raise PermissionError("provider attempt belongs to another client")
        observed = self.observer.observe_completion(attempt)
        completion = self._completion_record(
            attempt_id,
            attempt,
            observed.evidence_digest,
            observed.exit_status,
            observed.normalized_result,
            observed.finished_at,
        )
        self.store.transition(
            "attempts",
            attempt_id,
            "EXECUTION_STARTED",
            observed.normalized_result.upper(),
            completion,
        )
        return {"completion": completion, "attempt_id": attempt_id}

    def _completion_record(
        self,
        attempt_id: str,
        attempt: dict[str, Any],
        evidence_digest: str,
        exit_status: int,
        normalized_result: str,
        finished_at: str,
    ) -> dict[str, Any]:
        return self.keys.sign(
            "provider-completion",
            {
                "id": f"provider-completion:{attempt_id}",
                "kind": "provider_completion",
                "schema_version": 2,
                "attempt_id": attempt_id,
                "project_id": attempt["project_id"],
                "charter_id": attempt.get("charter_id"),
                "charter_revision": attempt.get("charter_revision"),
                "approval_id": attempt.get("approval_id"),
                "budget_reservation_id": attempt.get("budget_reservation_id"),
                "launch_authorization_id": attempt["launch_authorization_id"],
                "authorization_generation": attempt["authorization_generation"],
                "completion_challenge": attempt["completion_challenge"],
                "keeper_run_id": attempt["keeper_run_id"],
                "task_id": attempt["task_id"],
                "stage_id": attempt["stage_id"],
                "role": attempt["role"],
                "attempt_number": attempt["attempt_number"],
                "provider_run_id": attempt["provider_run_id"],
                "provider_instance_id": attempt["provider_instance_id"],
                "model_id": attempt.get("model_id"),
                "reasoning_level": attempt.get("reasoning_level"),
                "prompt_digest": attempt.get("prompt_digest"),
                "output_schema_digest": attempt.get(
                    "output_schema_digest"
                ),
                "registration_id": attempt["registration_id"],
                "registration_digest": attempt["registration_digest"],
                "pricing_authority_digest": attempt.get(
                    "pricing_authority_digest"
                ),
                "usage_policy_digest": attempt.get("usage_policy_digest"),
                "authentication_binding_digest": attempt.get(
                    "authentication_binding_digest"
                ),
                "model_allowlist_digest": attempt.get(
                    "model_allowlist_digest"
                ),
                "subscription_account_binding_digest": attempt.get(
                    "subscription_account_binding_digest"
                ),
                "model_capability_binding_digest": attempt.get(
                    "model_capability_binding_digest"
                ),
                "process_id": attempt["pid"],
                "process_creation_time": attempt["process_creation_time"],
                "provider_evidence_digest": evidence_digest,
                "delivered_input_digest": attempt.get(
                    "delivered_input_digest"
                ),
                "provider_input_digest": attempt.get(
                    "provider_input_digest"
                ),
                "executive_commit_receipt_digest": attempt.get(
                    "executive_commit_receipt_digest"
                ),
                "manifest_digest": attempt.get("manifest_digest"),
                "usage_observation": attempt.get("usage_observation"),
                "claimed_at": attempt.get("claimed_at"),
                "started_at": attempt.get("started_at"),
                "execution_usage_observation": attempt.get(
                    "execution_usage_observation"
                ),
                "execution_command_digest": attempt.get(
                    "execution_command_digest"
                ),
                "execution_prompt_digest": attempt.get(
                    "execution_prompt_digest"
                ),
                "execution_schema_digest": attempt.get(
                    "execution_schema_digest"
                ),
                "structured_event_digest": attempt.get(
                    "structured_event_digest"
                ),
                "failure_classification": attempt.get(
                    "failure_classification"
                ),
                "provider_host_envelope_digest": attempt.get(
                    "provider_host_envelope_digest"
                ),
                "provider_host_receipt_digest": attempt.get(
                    "provider_host_receipt_digest"
                ),
                "exit_status": exit_status,
                "normalized_result": normalized_result,
                "terminal_disposition": normalized_result.upper(),
                "finished_at": finished_at,
                "authorized_client_sid": attempt["authorized_client_sid"],
                "transaction_id": uuid.uuid4().hex,
            },
        )

    def _reconcile_executive_restore(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        fields = {
            "restore_operation_id",
            "backup_sha256",
            "source_database_id",
            "source_recovery_epoch",
            "target_database_id",
            "target_recovery_epoch",
            "target_generation",
            "project_scope",
        }
        _exact(payload, fields)
        operation_id = _text(
            payload["restore_operation_id"], "restore operation ID"
        )
        backup_sha256 = _sha256_text(
            payload["backup_sha256"], "backup SHA-256"
        )
        source_database_id = _text(
            payload["source_database_id"], "source database ID"
        )
        target_database_id = _text(
            payload["target_database_id"], "target database ID"
        )
        source_epoch = _nonnegative_int(
            payload["source_recovery_epoch"], "source recovery epoch"
        )
        target_epoch = _nonnegative_int(
            payload["target_recovery_epoch"], "target recovery epoch"
        )
        target_generation = _nonnegative_int(
            payload["target_generation"], "target generation"
        )
        scope_value = payload["project_scope"]
        if (
            not isinstance(scope_value, list)
            or not all(isinstance(item, str) and item for item in scope_value)
            or scope_value != sorted(set(scope_value))
        ):
            raise ValueError("Authority restore project scope is invalid")
        project_scope = set(scope_value)
        attempts = sorted(
            (
                record
                for record in self.store.list_records("attempts")
                if record.get("project_id") in project_scope
            ),
            key=lambda item: str(item.get("id", "")),
        )
        authorizations = sorted(
            (
                record
                for record in self.store.list_records("launch_authorizations")
                if record.get("project_id") in project_scope
            ),
            key=lambda item: str(item.get("id", "")),
        )
        state = {
            "attempts": attempts,
            "launch_authorizations": authorizations,
        }
        receipt = self.keys.sign(
            "executive-restore-reconciliation",
            {
                "schema_version": 1,
                "kind": "executive-restore-reconciliation",
                "restore_operation_id": operation_id,
                "backup_sha256": backup_sha256,
                "source_database_id": source_database_id,
                "source_recovery_epoch": source_epoch,
                "target_database_id": target_database_id,
                "target_recovery_epoch": target_epoch,
                "target_generation": target_generation,
                "project_scope": scope_value,
                "protocol_version": PROTOCOL_VERSION,
                "service_key_id": self.keys.current_key_id,
                "authorized_client_sid": client_sid,
                **state,
                "state_digest": _canonical_digest(state),
                "reconciled_at": _now(),
            },
        )
        return {"reconciliation": receipt}

    def _begin_executive_restore_fence(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        identity = _validated_restore_fence_identity(payload)
        now = datetime.now(UTC)
        fence = self.store.begin_restore_fence(
            f"restore-fence:{identity['restore_operation_id']}",
            identity,
            client_sid,
            now.isoformat(),
            (now + RESTORE_FENCE_LIFETIME).isoformat(),
        )
        signed = self.keys.sign(
            "executive-restore-reconciliation-fence",
            {
                "schema_version": 1,
                "kind": "executive-restore-reconciliation-fence",
                "protocol_version": PROTOCOL_VERSION,
                "service_key_id": self.keys.current_key_id,
                **fence,
            },
        )
        return {"fence": signed}

    def _confirm_executive_restore_fence(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, {"fence_id", "restore_operation_id"})
        confirmation = self.store.confirm_restore_fence(
            _text(payload["fence_id"], "restore fence ID"),
            _text(payload["restore_operation_id"], "restore operation ID"),
            client_sid,
        )
        signed = self.keys.sign(
            "executive-restore-fence-confirmation",
            {
                "schema_version": 1,
                "kind": "executive-restore-fence-confirmation",
                "protocol_version": PROTOCOL_VERSION,
                "service_key_id": self.keys.current_key_id,
                **confirmation,
            },
        )
        return {"confirmation": signed}

    def _complete_executive_restore_fence(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        return self._finish_executive_restore_fence(
            payload, client_sid, "COMPLETED"
        )

    def _abort_executive_restore_fence(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        return self._finish_executive_restore_fence(
            payload, client_sid, "ABORTED"
        )

    def _finish_executive_restore_fence(
        self, payload: dict[str, Any], client_sid: str, state: str
    ) -> dict[str, Any]:
        _exact(payload, {"fence_id", "restore_operation_id"})
        outcome = self.store.finish_restore_fence(
            _text(payload["fence_id"], "restore fence ID"),
            _text(payload["restore_operation_id"], "restore operation ID"),
            client_sid,
            state,
        )
        return {
            "outcome": self.keys.sign(
                "executive-restore-fence-outcome",
                {
                    "schema_version": 1,
                    "kind": "executive-restore-fence-outcome",
                    "protocol_version": PROTOCOL_VERSION,
                    "service_key_id": self.keys.current_key_id,
                    "authorized_client_sid": client_sid,
                    **outcome,
                },
            )
        }

    def _recover_executive_restore_fence(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, {"fence_id", "restore_operation_id"})
        outcome = self.store.recover_restore_fence(
            _text(payload["fence_id"], "restore fence ID"),
            _text(payload["restore_operation_id"], "restore operation ID"),
            client_sid,
        )
        return {
            "outcome": self.keys.sign(
                "executive-restore-fence-outcome",
                {
                    "schema_version": 1,
                    "kind": "executive-restore-fence-outcome",
                    "protocol_version": PROTOCOL_VERSION,
                    "service_key_id": self.keys.current_key_id,
                    "authorized_client_sid": client_sid,
                    **outcome,
                },
            )
        }

    def _query_state(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, {"kind", "id"})
        table = _choice(
            payload["kind"],
            {
                "registrations", "qualifications", "attempts",
                "launch_authorizations",
            },
        )
        identifier = _text(payload["id"], "state ID")
        value = self.store.get(table, identifier)
        return {"found": value is not None, "record": value}

    def _verify_evidence(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, {"purpose", "record"})
        purpose = _choice(
            payload["purpose"],
            {
                "project-launch-authorization",
                "provider-registration",
                "provider-qualification-start",
                "provider-qualification",
                "provider-launch-authorization",
                "provider-input-binding",
                "provider-launch-claim",
                "provider-start",
                "provider-completion",
                "provider-usage-wait",
                "executive-restore-reconciliation",
                "executive-restore-reconciliation-fence",
                "executive-restore-fence-confirmation",
                "executive-restore-fence-outcome",
                AUDIT_REPORT_PURPOSE,
            },
        )
        return {"valid": self.keys.verify(purpose, payload["record"])}

    def _pause_attempt(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        return self._transition_attempt(payload, client_sid, "EXECUTION_STARTED", "PAUSED")

    def _resume_attempt(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        return self._transition_attempt(payload, client_sid, "PAUSED", "EXECUTION_STARTED")

    def _cancel_attempt(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, {"attempt_id"})
        attempt_id = _text(payload["attempt_id"], "attempt ID")
        value = self.store.get("attempts", attempt_id)
        if value is None:
            raise PermissionError("provider attempt is unavailable")
        state = str(value.pop("service_state"))
        if state not in {
            "RESERVED",
            "INPUT_BOUND",
            "LAUNCH_CLAIMED",
            "EXECUTION_STARTED",
            "PAUSED",
        }:
            raise PermissionError("provider attempt cannot be cancelled")
        if value.get("authorized_client_sid") != client_sid:
            raise PermissionError("provider attempt belongs to another client")
        cancellation_intent_id = f"cancellation-intent:{uuid.uuid4().hex}"
        claimed = {
            **value,
            "cancellation_intent_id": cancellation_intent_id,
            "cancellation_requested_at": _now(),
        }
        self.store.transition(
            "attempts",
            attempt_id,
            state,
            "CANCELLATION_CLAIMED",
            claimed,
        )
        cancel_provider = getattr(self.observer, "cancel_provider", None)
        if callable(cancel_provider):
            cancel_provider(attempt_id)
        cancelled = {**claimed, "cancelled_at": _now()}
        self.store.transition(
            "attempts",
            attempt_id,
            "CANCELLATION_CLAIMED",
            "CANCELLED",
            cancelled,
        )
        return {
            "attempt_id": attempt_id,
            "state": "CANCELLED",
            "cancellation_intent_id": cancellation_intent_id,
        }

    def _transition_attempt(
        self,
        payload: dict[str, Any],
        client_sid: str,
        expected: str,
        state: str,
    ) -> dict[str, Any]:
        _exact(payload, {"attempt_id"})
        attempt_id = _text(payload["attempt_id"], "attempt ID")
        value = self.store.get("attempts", attempt_id)
        if value is None or value.pop("service_state", None) != expected:
            raise PermissionError("provider attempt transition was rejected")
        if value.get("authorized_client_sid") != client_sid:
            raise PermissionError("provider attempt belongs to another client")
        updated = {**value, f"{state.casefold()}_at": _now()}
        self.store.transition("attempts", attempt_id, expected, state, updated)
        return {"attempt_id": attempt_id, "state": state}

    def _revoke_registration(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        self._require_no_pending_host_launch_reconciliation()
        self._require_no_pending_provider_operation_claims()
        _exact(payload, {"registration_id"})
        identifier = _text(payload["registration_id"], "registration ID")
        value = self.store.get("registrations", identifier)
        if value is None:
            raise PermissionError("provider registration is unavailable")
        state = str(value.pop("service_state"))
        if state == "REGISTRATION_EXHAUSTED":
            raise PermissionError(
                "exhausted provider registration evidence is permanent"
            )
        if state == "REVOKED":
            raise PermissionError("provider registration is already revoked")
        revoked = {
            **value,
            "registration_status": "revoked",
            "registration_lifecycle": "REVOKED",
            "revoked_at": _now(),
        }
        revoked["configuration_digest"] = canonical_provider_registration_digest(revoked)
        self.store.transition("registrations", identifier, state, "REVOKED", revoked)
        return {"registration": revoked, "registration_id": identifier}

    def _rotate_key(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        self._require_no_pending_host_launch_reconciliation()
        self._require_no_pending_provider_operation_claims()
        _exact(payload, {"confirmation"})
        if payload["confirmation"] != "ROTATE_KEEPER_AUTHORITY_KEY":
            raise PermissionError("authority key rotation confirmation is invalid")
        return self.keys.rotate()

    def _migrate_legacy(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        _exact(payload, {"registrations"})
        registrations = payload["registrations"]
        if not isinstance(registrations, list):
            raise ValueError("legacy registrations must be a list")
        migrated = 0
        created: list[dict[str, Any]] = []
        for old in registrations:
            if not isinstance(old, dict):
                raise ValueError("legacy registration is malformed")
            _exact(
                old,
                {
                    "logical_provider_id",
                    "canonical_executable_path",
                    "executive_capabilities",
                    "project_types",
                    "effort_levels",
                    "pricing_authority",
                },
            )
            provider_id = _choice(old.get("logical_provider_id"), {"codex", "claude"})
            executable = Path(
                _text(old.get("canonical_executable_path"), "legacy executable")
            )
            executive_capabilities = old["executive_capabilities"]
            project_types = old["project_types"]
            effort_levels = old["effort_levels"]
            pricing_authority = old["pricing_authority"]
            matches = [
                value
                for value in self.store.list_records("registrations")
                if value.get("logical_provider_id") == provider_id
                and value.get("canonical_executable_path")
                == str(executable.resolve(strict=True))
            ]
            if len(matches) > 1:
                raise PermissionError(
                    "legacy registration migration is ambiguous"
                )
            if matches:
                existing = dict(matches[0])
                existing.pop("service_state", None)
                created.append(existing)
                continue
            if self.observer is not None and hasattr(
                self.observer, "register_provider"
            ):
                registration = self.observer.register_provider(
                    provider_id,
                    executable,
                    client_sid,
                    executive_capabilities=executive_capabilities,
                    project_types=project_types,
                    effort_levels=effort_levels,
                    pricing_authority=pricing_authority,
                )
            else:
                registration = create_provider_registration(
                    provider_id,
                    executable,
                    authorized_by=client_sid,
                    executive_capabilities=executive_capabilities,
                    project_types=project_types,
                    effort_levels=effort_levels,
                    pricing_authority=pricing_authority,
                )
            self.store.insert(
                "registrations",
                str(registration["trusted_registration_id"]),
                "REGISTERED_UNQUALIFIED",
                registration,
            )
            migrated += 1
            created.append(registration)
        return {
            "migrated_registrations": migrated,
            "registrations": created,
            "legacy_evidence_status": "UNVERIFIABLE",
        }

    def _internal_only(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, Any]:
        raise PermissionError("qualification finalization is service-internal")


def _validated_registration_terminal_failure(
    value: dict[str, Any],
) -> dict[str, Any]:
    fields = {
        "failure_stage",
        "failure_code",
        "process_result",
        "setup_result_digest",
        "setup_envelope_digest",
    }
    if set(value) != fields:
        raise PermissionError("provider registration failure fields are invalid")
    stage = value.get("failure_stage")
    code = value.get("failure_code")
    allowed_stages = {
        "SETUP_INITIALIZATION", "EXECUTABLE_LOCK", "SOURCE_TOKEN_OPEN",
        "RESTRICTED_TOKEN_CREATE", "VERSION_LAUNCH", "VERSION_CREATE_PROCESS",
        "VERSION_JOB_ASSIGN", "VERSION_JOB_VERIFY", "VERSION_STARTED_CALLBACK",
        "VERSION_STARTED_ACK", "VERSION_RESUME", "VERSION_WAIT",
        "VERSION_VALIDATE", "ACCOUNT_PROBE_LAUNCH", "ACCOUNT_PROBE_VALIDATE",
        "ACCOUNT_BINDING_VALIDATE", "QUALIFICATION_PREPARE",
        "QUALIFICATION_LAUNCH", "QUALIFICATION_VALIDATE", "UNAVAILABLE",
    }
    valid_code = code in {
        "TIMEOUT", "PERMISSION_REJECTED", "OS_ERROR", "INVALID_RESULT",
        "RUNTIME_FAILURE",
    } or (
        isinstance(code, str)
        and code.startswith("WIN32_")
        and code[6:].isdigit()
        and 0 < int(code[6:]) <= 65_535
    )
    if stage not in allowed_stages or not valid_code:
        raise PermissionError(
            "provider registration failure classification is invalid"
        )
    for name in ("setup_result_digest", "setup_envelope_digest"):
        _sha256_text(value.get(name), name.replace("_", " "))
    process_result = value.get("process_result")
    if process_result == {"detail_status": "DETAIL_UNAVAILABLE"}:
        return dict(value)
    expected_process_fields = {
        "operation", "exit_code", "timed_out", "stdout_sha256", "stdout_bytes",
        "stderr_sha256", "stderr_bytes", "restricted", "job_confined",
        "started", "resumed",
    }
    if not isinstance(process_result, dict) or set(process_result) != expected_process_fields:
        raise PermissionError("provider registration process result is invalid")
    if process_result.get("operation") not in {
        "VERSION", "ACCOUNT_PROBE", "QUALIFICATION"
    }:
        raise PermissionError("provider registration process operation is invalid")
    exit_code = process_result.get("exit_code")
    if (
        isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or not 0 <= exit_code <= 0xFFFFFFFF
    ):
        raise PermissionError("provider registration process exit code is invalid")
    for name in ("stdout_bytes", "stderr_bytes"):
        count = process_result.get(name)
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or not 0 <= count <= 1_048_576
        ):
            raise PermissionError("provider registration process byte count is invalid")
    for name in ("stdout_sha256", "stderr_sha256"):
        _sha256_text(process_result.get(name), name.replace("_", " "))
    if (
        not isinstance(process_result.get("timed_out"), bool)
        or any(
            process_result.get(name) is not True
            for name in {"restricted", "job_confined", "started", "resumed"}
        )
    ):
        raise PermissionError("provider registration process confinement is invalid")
    return dict(value)


def _zero_registration_effect_accounting() -> dict[str, int]:
    return {
        "model_request_count": 0,
        "provider_execution_count": 0,
        "qualification_count": 0,
        "registration_success_count": 0,
        "usage_reservation_count": 0,
    }


def _replacement_registration_id(
    predecessor_id: str,
    failure_digest: str,
    request_identity_digest: str,
) -> str:
    return "keeper-provider:codex:v1:" + hashlib.sha256(
        (
            "codex-subscription-registration-successor-v1\0"
            + predecessor_id
            + "\0"
            + failure_digest
            + "\0"
            + request_identity_digest
        ).encode("utf-8")
    ).hexdigest()[:32]


def _registration_replacement_action_binding(
    lineage: dict[str, Any],
) -> dict[str, Any]:
    fields = {
        "action",
        "account_identity_discovery_digest",
        "expected_account_identity_digest",
        "expected_account_plan_type",
        "authorized_client_sid",
        "effect_accounting",
        "exhausted_attempt_generation",
        "expected_executable_sha256",
        "expected_executable_size",
        "predecessor_failure_digest",
        "predecessor_registration_id",
        "request_identity_digest",
        "required_authority_version",
        "required_host_version",
        "successor_registration_id",
    }
    return {name: lineage[name] for name in fields}


def _validated_registration_replacement_lineage(
    value: object,
    verifier: Callable[[str, object], bool],
    *,
    require_current_release: bool = True,
) -> dict[str, Any]:
    """Validate immutable lineage and optionally its activation release lock.

    An unactivated successor authorization is usable only by the release named
    in its signed lineage.  After the successor has started, those version
    fields remain historical evidence while recovery and exact retry continue
    to enforce every signed identity, account, executable, and failure binding.
    """
    if not isinstance(value, dict) or not verifier(
        "provider-registration-replacement-lineage", value
    ):
        raise PermissionError("provider registration replacement lineage is invalid")
    required = {
        "action",
        "account_identity_discovery_digest",
        "expected_account_identity_digest",
        "expected_account_plan_type",
        "authorized_at",
        "authorized_client_sid",
        "authorization_id",
        "effect_accounting",
        "exhausted_attempt_generation",
        "expected_executable_sha256",
        "expected_executable_size",
        "family_generation",
        "founder_approval_event_digest",
        "founder_approval_event_id",
        "founder_approval_record_id",
        "founder_capability_digest",
        "founder_capability_id",
        "founder_capability_signature_digest",
        "founder_session_id",
        "predecessor_failure_digest",
        "predecessor_registration_id",
        "request_identity_digest",
        "required_authority_version",
        "required_host_version",
        "successor_registration_id",
        "authority_schema_version",
        "authority_key_id",
        "authenticated_writer_proof",
        "service_key_version",
    }
    if (
        set(value) != required
        or value.get("action") != "NEW_REGISTRATION_AFTER_EXHAUSTION"
        or value.get("effect_accounting")
        != _zero_registration_effect_accounting()
        or value.get("exhausted_attempt_generation") != 2
        or value.get("family_generation") != 2
        or not isinstance(value.get("required_authority_version"), str)
        or not re.fullmatch(
            r"[1-9][0-9]*\.[0-9]+\.[0-9]+",
            str(value.get("required_authority_version")),
        )
        or value.get("required_host_version")
        != value.get("required_authority_version")
        or (
            require_current_release
            and value.get("required_authority_version") != SERVICE_VERSION
        )
        or value.get("expected_account_plan_type")
        not in CODEX_ALLOWED_SUBSCRIPTION_PLANS
    ):
        raise PermissionError("provider registration replacement lineage is malformed")
    for name in {
        "account_identity_discovery_digest",
        "expected_account_identity_digest",
        "expected_executable_sha256",
        "founder_approval_event_digest",
        "founder_capability_digest",
        "founder_capability_signature_digest",
        "predecessor_failure_digest",
        "request_identity_digest",
    }:
        _sha256_text(value.get(name), name.replace("_", " "))
    if (
        _positive_int(value.get("expected_executable_size"), "provider executable size")
        <= 0
        or not str(value.get("predecessor_registration_id", "")).startswith(
            "keeper-provider:codex:v1:"
        )
        or not str(value.get("successor_registration_id", "")).startswith(
            "keeper-provider:codex:v1:"
        )
        or value.get("predecessor_registration_id")
        == value.get("successor_registration_id")
    ):
        raise PermissionError("provider registration replacement identity is invalid")
    return dict(value)


def _provider_input_is_required(attempt: dict[str, Any]) -> bool:
    value = attempt.get("provider_input_required")
    if value is None:
        return _reviewer_role(
            _normalized_provider_role(str(attempt.get("role", "")))
        )
    if type(value) is not bool:
        raise PermissionError("provider input requirement is invalid")
    return value


def _normalized_provider_role(role: str) -> str:
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


def _reviewer_role(role: str) -> bool:
    return role in {"reviewer", "post_repair_reviewer"}


def _exact(payload: dict[str, Any], fields: set[str]) -> None:
    if set(payload) != fields:
        raise ValueError("authority operation payload fields are invalid")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError(f"authority {label} is invalid")
    return value


def _validate_legacy_claude_predispatch_claim(
    *,
    registration_id: str,
    client_sid: str,
    request_binding: dict[str, Any],
    request_identity_digest: object,
    start: dict[str, Any],
    verify: Callable[[str, dict[str, Any]], bool],
) -> None:
    expected_binding_fields = {
        "provider_id",
        "executable",
        "executive_capabilities",
        "project_types",
        "effort_levels",
        "pricing_authority",
        "expected_executable_sha256",
        "expected_executable_size",
        "expected_version",
        "model_allowlist",
        "model_revalidation_expires_at",
        "authentication_policy",
        "usage_policy",
        "authorized_client_sid",
    }
    pricing = request_binding.get("pricing_authority")
    authentication = request_binding.get("authentication_policy")
    usage = request_binding.get("usage_policy")
    semantic_pricing = dict(pricing) if isinstance(pricing, dict) else {}
    semantic_pricing.pop("quoted_at", None)
    semantic_pricing.pop("expires_at", None)
    expected_identity = _canonical_digest(
        {
            **request_binding,
            "pricing_authority": semantic_pricing,
            "model_revalidation_expires_at": None,
        }
    )
    expected_setup_id = "provider-registration-probe:" + hashlib.sha256(
        (registration_id + "\0setup-v1").encode("utf-8")
    ).hexdigest()[:32]
    if (
        set(request_binding) != expected_binding_fields
        or request_binding.get("provider_id") != "claude"
        or request_binding.get("authorized_client_sid") != client_sid
        or request_binding.get("model_allowlist") != [CLAUDE_PINNED_REVIEW_MODEL]
        or not isinstance(pricing, dict)
        or pricing.get("subscription_plan")
        not in CLAUDE_ALLOWED_SUBSCRIPTION_PLANS
        or pricing.get("api_billing_authorized") is not False
        or pricing.get("paid_fallback_authorized") is not False
        or pricing.get("provider_switch_authorized") is not False
        or not isinstance(authentication, dict)
        or authentication.get("mode") != CLAUDE_AUTHENTICATION_MODE
        or authentication.get("api_keys_allowed") is not False
        or authentication.get("paid_fallback_allowed") is not False
        or authentication.get("provider_switch_allowed") is not False
        or not isinstance(usage, dict)
        or usage.get("automatic_retry") is not False
        or usage.get("provider_switch") is not False
        or usage.get("api_fallback") is not False
        or usage.get("credit_purchase") is not False
        or request_identity_digest != expected_identity
        or not verify("provider-registration-start", start)
        or start.get("registration_id") != registration_id
        or start.get("authorization_reference") != client_sid
        or start.get("attempt_generation", 1) != 1
        or start.get("setup_id") != expected_setup_id
        or not isinstance(start.get("event_challenge"), str)
        or len(str(start["event_challenge"])) != 64
    ):
        raise PermissionError(
            "registration is not the exact legacy Claude predispatch defect"
        )


def _validated_offline_host_process_evidence(
    value: object,
    *,
    installation: dict[str, Any],
    user_binding: dict[str, Any],
    allowed_historical_digest: str | None = None,
) -> dict[str, Any]:
    fields = {
        "process_id",
        "session_id",
        "process_start_time_utc",
        "executable_path",
        "executable_sha256",
        "executable_size",
        "retained_kernel_handle",
        "termination_observed",
        "zero_matching_processes",
        "observed_at",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise PermissionError("offline Provider Host process evidence is malformed")
    process_id = value.get("process_id")
    session_id = value.get("session_id")
    executable_size = value.get("executable_size")
    if (
        isinstance(process_id, bool)
        or not isinstance(process_id, int)
        or process_id <= 0
        or isinstance(session_id, bool)
        or not isinstance(session_id, int)
        or session_id < 0
        or isinstance(executable_size, bool)
        or not isinstance(executable_size, int)
        or executable_size <= 0
        or session_id != user_binding.get("session_id")
        or str(value.get("executable_path", "")).casefold()
        != str(installation.get("executable_path", "")).casefold()
        or str(value.get("executable_sha256", "")).casefold()
        != str(installation.get("executable_sha256", "")).casefold()
        or executable_size != installation.get("executable_size")
        or value.get("retained_kernel_handle") is not True
        or value.get("termination_observed") is not True
        or value.get("zero_matching_processes") is not True
    ):
        raise PermissionError(
            "offline Provider Host process evidence binding differs"
        )
    try:
        process_start = datetime.fromisoformat(
            _text(value.get("process_start_time_utc"), "Host process start time")
        )
        observed = datetime.fromisoformat(
            _text(value.get("observed_at"), "Host termination observation time")
        )
    except ValueError as error:
        raise PermissionError(
            "offline Provider Host process evidence time is invalid"
        ) from error
    now = datetime.now(UTC)
    historical_evidence_is_exact = (
        allowed_historical_digest is not None
        and _canonical_digest(value) == allowed_historical_digest
    )
    if (
        process_start.tzinfo is None
        or observed.tzinfo is None
        or process_start >= observed
        or (
            observed < now - timedelta(minutes=15)
            and not historical_evidence_is_exact
        )
        or observed > now + timedelta(seconds=10)
    ):
        raise PermissionError(
            "offline Provider Host process evidence is stale"
        )
    return {str(key): item for key, item in value.items()}


def _choice(value: object, choices: set[str]) -> str:
    text = _text(value, "enum")
    if text not in choices:
        raise ValueError("authority enum value is unsupported")
    return text


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"authority {label} is invalid")
    return value


def _bounded_int(
    value: object, label: str, minimum: int, maximum: int
) -> int:
    result = _positive_int(value, label)
    if result < minimum or result > maximum:
        raise ValueError(f"authority {label} is out of range")
    return result


def _safe_environment(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 256:
        raise ValueError("authority provider environment is invalid")
    result: dict[str, str] = {}
    sensitive = (
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "PRIVATE_KEY",
        "COOKIE",
        "CREDENTIAL",
    )
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key) > 128
            or "=" in key
            or "\0" in key
            or any(marker in key.upper() for marker in sensitive)
            or not isinstance(item, str)
            or len(item) > 32_768
            or "\0" in item
        ):
            raise ValueError("authority provider environment is invalid")
        result[key] = item
    return result


def _canonical_path(value: object, label: str) -> str:
    path = Path(_text(value, label))
    if not path.is_absolute():
        raise ValueError(f"authority {label} must be absolute")
    return str(path.resolve())


def _object_id(result: dict[str, Any]) -> str | None:
    report = result.get("report")
    if isinstance(report, dict) and isinstance(
        report.get("audit_operation_id"), str
    ):
        return str(report["audit_operation_id"])
    for key in ("attempt_id", "registration_id", "qualification_id"):
        value = result.get(key)
        if isinstance(value, str):
            return value
    return None


def _validated_restore_fence_identity(payload: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "restore_operation_id",
        "backup_operation_id",
        "backup_artifact_path",
        "backup_sha256",
        "source_database_id",
        "source_recovery_epoch",
        "source_generation",
        "target_database_id",
        "target_recovery_epoch",
        "target_generation",
        "project_scope",
        "authorization_digest",
    }
    _exact(payload, fields)
    scope = payload["project_scope"]
    if (
        not isinstance(scope, list)
        or not all(isinstance(item, str) and item for item in scope)
        or scope != sorted(set(scope))
    ):
        raise ValueError("Authority restore project scope is invalid")
    return {
        "restore_operation_id": _text(
            payload["restore_operation_id"], "restore operation ID"
        ),
        "backup_operation_id": _text(
            payload["backup_operation_id"], "backup operation ID"
        ),
        "backup_artifact_path": _text(
            payload["backup_artifact_path"], "backup artifact path"
        ),
        "backup_sha256": _sha256_text(
            payload["backup_sha256"], "backup SHA-256"
        ),
        "source_database_id": _text(
            payload["source_database_id"], "source database ID"
        ),
        "source_recovery_epoch": _nonnegative_int(
            payload["source_recovery_epoch"], "source recovery epoch"
        ),
        "source_generation": _nonnegative_int(
            payload["source_generation"], "source generation"
        ),
        "target_database_id": _text(
            payload["target_database_id"], "target database ID"
        ),
        "target_recovery_epoch": _nonnegative_int(
            payload["target_recovery_epoch"], "target recovery epoch"
        ),
        "target_generation": _nonnegative_int(
            payload["target_generation"], "target generation"
        ),
        "project_scope": scope,
        "authorization_digest": _sha256_text(
            payload["authorization_digest"], "authorization digest"
        ),
    }


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"authority {label} is invalid")
    return value


def _sha256_text(value: object, label: str) -> str:
    text = _text(value, label)
    if len(text) != 64 or any(item not in "0123456789abcdef" for item in text):
        raise ValueError(f"authority {label} is invalid")
    return text


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
