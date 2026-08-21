from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, cast

from keeper.authority_service.client import AuthorityServiceClient
from keeper.authority_service.core import (
    AuthorityServiceCore,
    CompletionObservation,
    ExecutionObservation,
    ProcessObservation,
    QualificationObservation,
)
from keeper.authority_service.protocol import Request
from keeper.executive.founder_capability import (
    FounderCapabilityClaims,
    TestFounderCapabilityIssuer,
    TestFounderCapabilityVerifier,
)
from keeper.providers.adapters import _domain_schema
from keeper.providers.adapters import create_provider_registration


def _text_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def provider_authority_kwargs(provider_id: str = "codex") -> dict[str, Any]:
    """Explicit safe declarations used by Authority contract tests."""
    return {
        "executive_capabilities": sorted(
            {
                "acceptance", "architecture", "critical analysis",
                "implementation", "packaging", "planning", "production",
                "report writing", "requirements", "research design",
                "review", "security", "source collection", "source review",
                "synthesis", "testing",
            }
        ),
        "project_types": sorted(
            {
                "business_operations", "design", "general", "marketing",
                "music", "research", "software", "video", "writing",
            }
        ),
        "effort_levels": ["high", "medium"],
        "pricing_authority": {
            "pricing_identity": f"test-pricing:{provider_id}",
            "pricing_version": "2026-07",
            "currency": "USD",
            "estimated_cost": 0.0,
            "maximum_cost": 0.0,
            "billing_unit": "included-test-session",
            "included_plan": True,
            "marginally_free": True,
            "quoted_at": "2026-07-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "source": "TEST_AUTHORITY_REGISTRATION",
            "cost_tier": 0,
        },
    }




def make_test_founder_capability(
    project_id: str,
    generation: int = 1,
    suffix: str = "one",
    *,
    charter_id: str | None = None,
    claim_overrides: dict[str, object] | None = None,
) -> dict[str, Any]:
    event_id = f"event:{project_id}:{suffix}"
    approval_id = f"approval:{project_id}:{suffix}"
    challenge_id = f"challenge:{project_id}:{suffix}"
    claim_values: dict[str, object] = {
        "capability_id": f"capability:{project_id}:{suffix}",
        "project_id": project_id,
        "charter_id": charter_id or f"charter-{generation}",
        "charter_revision": generation,
        "authorization_kind": "PROJECT_LAUNCH",
        "protected_action": "DELEGATE_CHARTER",
        "action_digest": _text_digest(f"action:{project_id}:{suffix}"),
        "approval_digest": _text_digest(f"approval-digest:{project_id}:{suffix}"),
        "approval_event_digest": _text_digest(event_id),
        "founder_principal_sid": "S-1-5-21-KEEPER-TEST",
        "founder_authenticated_session_id": f"session:{project_id}:{suffix}",
        "approval_event_id": event_id,
        "approval_record_id": approval_id,
        "challenge_id": challenge_id,
        "challenge_proof_digest": _text_digest(f"proof:{project_id}:{suffix}"),
        "authorization_generation": generation,
        "revocation_epoch": generation - 1,
        "issued_at": _now(),
        "expires_at": "2099-01-01T00:00:00+00:00",
        "usage": "ONE_TIME_GENERATION",
        "machine_identity": "keeper-test-machine",
        "application_identity": "KEEPER_EXECUTIVE",
    }
    if claim_overrides:
        claim_values.update(claim_overrides)
    confirmation_unsigned: dict[str, object] = {
        "session_id": claim_values["founder_authenticated_session_id"],
        "principal_sid": claim_values["founder_principal_sid"],
        "account_name": "KEEPER-TEST\\Founder",
        "authentication_method": "TEST_CHALLENGE_HMAC",
        "authenticated_at": claim_values["issued_at"],
        "expires_at": claim_values["expires_at"],
        "machine_identity": claim_values["machine_identity"],
        "application_identity": claim_values["application_identity"],
        "process_identity": "test-authority-capability-fixture",
        "challenge_id": claim_values["challenge_id"],
        "challenge_nonce": f"nonce:{project_id}:{suffix}",
        "project_id": claim_values["project_id"],
        "charter_id": claim_values["charter_id"],
        "charter_revision": claim_values["charter_revision"],
        "approval_action": (
            "APPROVE_ACTION"
            if claim_values["authorization_kind"]
            == "PROVIDER_HOST_ENROLLMENT"
            else "APPROVE_CHARTER"
        ),
        "bound_digest": claim_values["action_digest"],
        "source_user_interaction_id": f"interaction:{project_id}:{suffix}",
        "proof_version": 2,
    }
    issuer = TestFounderCapabilityIssuer()
    proof = issuer.sign_confirmation(confirmation_unsigned)
    if not claim_overrides or "challenge_proof_digest" not in claim_overrides:
        claim_values["challenge_proof_digest"] = hashlib.sha256(
            proof.encode("ascii")
        ).hexdigest()
    claims = FounderCapabilityClaims(**cast(Any, claim_values))
    confirmation = {**confirmation_unsigned, "proof": proof}
    return issuer.issue(claims, confirmation).to_dict()


class _TestObserver:
    """Explicit non-production observer used by the repository test suite."""

    def __init__(self, exchange_root: Path) -> None:
        self.exchange_root = exchange_root.resolve()
        self.allowed_evidence_root = self.exchange_root / "evidence"
        for directory in (
            self.allowed_evidence_root,
            self.exchange_root / "worktrees",
            self.exchange_root / "provider-work",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        self._active_lock = threading.Lock()
        self._active_processes: dict[str, subprocess.Popen[str]] = {}
        self._cancelled_attempts: set[str] = set()

    def validate_registered_executable(
        self,
        registration: dict[str, Any],
        client_executable_handle: int,
    ) -> None:
        del client_executable_handle
        if registration.get("registration_schema_version") in {4, 5}:
            raise PermissionError(
                "test observer cannot validate a production Codex registration"
            )

    def qualify(
        self, registration: dict[str, Any], challenge: str
    ) -> QualificationObservation:
        started = _now()
        command, executable = _qualification_command(registration)
        result = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=15,
        )
        return QualificationObservation(
            f"test-qualification:{uuid.uuid4().hex}",
            {
                "pid": 1,
                "launch_nonce": challenge,
                "restricted": True,
                "integrity_level": "low",
                "job_confined": True,
                "executable": str(executable),
                "executable_sha256": hashlib.sha256(
                    executable.read_bytes()
                ).hexdigest(),
            },
            started,
            _now(),
            result.returncode,
            result.stdout.strip(),
            result.stderr.strip() or None,
        )

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
    ) -> dict[str, Any]:
        del (
            expected_executable_sha256,
            expected_executable_size,
            client_executable_handle,
        )
        return create_provider_registration(
            provider_id,
            executable,
            authorized_by=client_sid,
            executive_capabilities=executive_capabilities,
            project_types=project_types,
            effort_levels=effort_levels,
            pricing_authority=pricing_authority,
            expected_version=expected_version,
            model_allowlist=model_allowlist,
            model_revalidation_expires_at=model_revalidation_expires_at,
            authentication_policy=authentication_policy,
            usage_policy=usage_policy,
        )

    def preflight_provider(
        self, registration: dict[str, Any], attempt: dict[str, Any]
    ) -> dict[str, Any] | None:
        del registration, attempt
        return None

    def read_exchange_file(
        self, value: object, label: str, maximum_bytes: int
    ) -> tuple[Path, bytes]:
        del label
        path = Path(str(value)).resolve(strict=True)
        if not path.is_relative_to(self.exchange_root):
            raise PermissionError("test provider path is outside the exchange")
        content = path.read_bytes()
        if len(content) > maximum_bytes:
            raise PermissionError("test provider exchange file is too large")
        return path, content

    def execute_provider(
        self,
        registration: dict[str, Any],
        attempt: dict[str, Any],
        on_started: Callable[[ProcessObservation], None],
    ) -> ExecutionObservation:
        attempt_id = str(attempt["id"])
        executable = Path(str(registration["launcher_path"])).resolve(strict=True)
        prompt = Path(str(attempt["prompt_path"])).read_text(encoding="utf-8")
        stdout_path = Path(str(attempt["stdout_path"]))
        stderr_path = Path(str(attempt["stderr_path"]))
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        base = _provider_base(registration)
        provider_id = str(registration["logical_provider_id"])
        if provider_id == "codex":
            schema = stdout_path.parent / "provider-output-schema.json"
            schema.write_text(
                json.dumps(_domain_schema(str(attempt["role"]))),
                encoding="utf-8",
            )
            command = [
                *base,
                "exec",
                "--ephemeral",
                "--sandbox",
                "workspace-write",
                "--output-schema",
                str(schema),
                prompt,
            ]
        else:
            command = [
                *base,
                "--output-format",
                "json",
                "--json-schema",
                json.dumps(
                    _domain_schema(str(attempt["role"])),
                    separators=(",", ":"),
                ),
                "-p",
                prompt,
            ]
        process_stdout_path = (
            stdout_path.with_suffix(".envelope.json")
            if provider_id == "claude"
            else stdout_path
        )
        with (
            process_stdout_path.open("w", encoding="utf-8") as stdout,
            stderr_path.open("w", encoding="utf-8") as stderr,
        ):
            process = subprocess.Popen(
                command,
                cwd=str(attempt["workspace"]),
                env={str(k): str(v) for k, v in attempt["environment"].items()},
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                text=True,
                shell=False,
            )
            with self._active_lock:
                if attempt_id in self._cancelled_attempts:
                    process.kill()
                self._active_processes[attempt_id] = process
            on_started(
                ProcessObservation(
                    process.pid,
                    _now(),
                    str(executable),
                    hashlib.sha256(executable.read_bytes()).hexdigest(),
                    True,
                    "low",
                    True,
                )
            )
            timed_out = False
            deadline = time.monotonic() + float(attempt["timeout_seconds"])
            try:
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        process.kill()
                        break
                    time.sleep(0.02)
                exit_status = process.wait(timeout=10)
            finally:
                with self._active_lock:
                    self._active_processes.pop(attempt_id, None)
                    self._cancelled_attempts.discard(attempt_id)
        if provider_id == "claude" and exit_status == 0:
            try:
                envelope = json.loads(
                    process_stdout_path.read_text(encoding="utf-8")
                )
                domain = envelope.get(
                    "structured_output", envelope.get("result")
                )
                if isinstance(domain, str):
                    domain = json.loads(domain)
                if not isinstance(domain, dict):
                    raise ValueError(
                        "Claude envelope contains no domain result"
                    )
                stdout_path.write_text(
                    json.dumps(domain), encoding="utf-8"
                )
            except (json.JSONDecodeError, OSError, ValueError) as error:
                stdout_path.write_text("", encoding="utf-8")
                stderr_path.write_text(
                    f"invalid Claude result envelope: {error}",
                    encoding="utf-8",
                )
                exit_status = 65
        return ExecutionObservation(
            process.pid,
            exit_status,
            timed_out,
            str(stdout_path),
            str(stderr_path),
            hashlib.sha256(
                json.dumps(
                    {
                        "stdout_sha256": hashlib.sha256(
                            stdout_path.read_bytes()
                            if stdout_path.exists()
                            else b""
                        ).hexdigest(),
                        "stderr_sha256": hashlib.sha256(
                            stderr_path.read_bytes()
                            if stderr_path.exists()
                            else b""
                        ).hexdigest(),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            _now(),
        )

    def cancel_provider(self, attempt_id: str) -> None:
        with self._active_lock:
            self._cancelled_attempts.add(attempt_id)
            process = self._active_processes.get(attempt_id)
            if process is not None:
                process.kill()

    def observe_process(
        self, attempt: dict[str, Any], pid: int
    ) -> ProcessObservation:
        registration_path = Path(
            str(attempt.get("process_executable") or os.environ.get("COMSPEC"))
        ).resolve(strict=True)
        return ProcessObservation(
            pid,
            _now(),
            str(registration_path),
            hashlib.sha256(registration_path.read_bytes()).hexdigest(),
            True,
            "low",
            True,
        )

    def observe_completion(
        self, attempt: dict[str, Any]
    ) -> CompletionObservation:
        evidence = Path(str(attempt["evidence_path"])).resolve(strict=True)
        content = evidence.read_bytes()
        value = json.loads(content.decode("utf-8"))
        return CompletionObservation(
            hashlib.sha256(content).hexdigest(),
            int(value["process_exit_code"]),
            str(value["status"]),
            _now(),
        )


class TestAuthorityClient(AuthorityServiceClient):
    """Semantic in-process transport explicitly injected only by pytest."""

    __test__ = False

    def __init__(self, data_directory: Path) -> None:
        root = data_directory.resolve()
        observer = _TestObserver(root / "test-authority-exchange")
        self.core = AuthorityServiceCore(
            root / "test-authority-service",
            observer=observer,
            founder_capability_verifier=TestFounderCapabilityVerifier(),
        )
        self.__launch_lock = threading.Lock()
        super().__init__(
            test_transport=lambda request: self.core.dispatch(
                request, "S-1-5-21-KEEPER-TEST"
            )
        )

    def sign(self, purpose: str, record: dict[str, Any]) -> dict[str, Any]:
        return self.core.keys.sign(purpose, record)

    def reserve_attempt(self, **identity: Any) -> dict[str, Any]:
        if "launch_authorization_id" not in identity:
            project_id = f"test-project:{identity['keeper_run_id']}"
            authorization_id = (
                f"launch-authorization:{project_id}:generation:1"
            )
            with self.__launch_lock:
                authorized = self.core.store.get(
                    "launch_authorizations", authorization_id
                )
                if authorized is None:
                    response = self.authorize_project_launch(
                        founder_capability=make_test_founder_capability(
                            project_id,
                            1,
                            "implicit",
                            charter_id="test-charter",
                        )
                    )
                    authorized = cast(
                        dict[str, Any], response["authorization"]
                    )
                elif authorized.get("service_state") != "ACTIVE":
                    raise PermissionError(
                        "implicit test launch authorization is not active"
                    )
            identity.update(
                {
                    "launch_authorization_id": authorized["id"],
                    "authorization_generation": 1,
                    "delegation_id": authorized["delegation_id"],
                    "founder_approval_event_id": authorized[
                        "founder_approval_event_id"
                    ],
                    "founder_approval_event_digest": authorized[
                        "founder_approval_event_digest"
                    ],
                    "founder_authenticated_session_id": authorized[
                        "founder_authenticated_session_id"
                    ],
                    "founder_principal_sid": authorized[
                        "founder_principal_sid"
                    ],
                    "authorization_expires_at": authorized["expires_at"],
                    "project_id": project_id,
                    "charter_id": "test-charter",
                    "charter_revision": 1,
                    "task_revision": 1,
                }
            )
        return super().reserve_attempt(**identity)


def _qualification_command(
    registration: dict[str, Any],
) -> tuple[list[str], Path]:
    executable = Path(str(registration["launcher_path"])).resolve(strict=True)
    return [*_provider_base(registration), "--version"], executable


def _provider_base(registration: dict[str, Any]) -> list[str]:
    executable = Path(str(registration["launcher_path"])).resolve(strict=True)
    script = registration.get("script_path")
    return (
        [str(executable), "/d", "/c", str(script)]
        if script is not None
        else [str(executable)]
    )


def _now() -> str:
    return datetime.now(UTC).isoformat()
