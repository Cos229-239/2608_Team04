from __future__ import annotations

import hashlib
import os
import sqlite3
import sys
import threading
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, cast

from keeper.provider_host.identity import (
    PipePeerIdentity,
    ProviderHostIdentityUncertain,
    authenticated_named_pipe_server_binding,
    require_peer_identity,
)
from keeper.provider_host.pipe import connected_client_pipe, read_frame, write_frame
from keeper.provider_host.protocol import (
    HOST_PROTOCOL,
    HELLO_PURPOSE,
    LAUNCH_PURPOSE,
    LAUNCH_RECONCILIATION_PURPOSE,
    LAUNCH_RECONCILIATION_RESULT_PURPOSE,
    REQUEST_PURPOSE,
    RESPONSE_PURPOSE,
    SETUP_PURPOSE,
    SETUP_RESULT_PURPOSE,
    STARTED_ACK_PURPOSE,
    STARTED_PURPOSE,
    EnvelopeSigner,
    EnvelopeVerifier,
    require_production_identity,
    structured_digest,
    validate_completion,
    validate_launch_envelope,
    validate_setup_envelope,
    validate_setup_result,
)


class ProviderHostGateway:
    """Authority-side mutually authenticated client for the user Provider Host."""

    def __init__(
        self,
        *,
        pipe_name: str,
        authority_id: str,
        host_id: str,
        authority_signer: EnvelopeSigner,
        host_verifier: EnvelopeVerifier,
        expected_host_sid: str,
        expected_host_session_id: int,
        expected_host_executable: Path,
        expected_host_executable_sha256: str,
        expected_host_profile_path: Path,
        sequence_store: Path,
        expected_host_executable_file_identity: tuple[int, int, int, int]
        | None = None,
        timeout_seconds: float = 15.0,
        now: Callable[[], datetime] | None = None,
        enrollment_is_active: Callable[[], bool] | None = None,
        production: bool = True,
    ) -> None:
        if production:
            require_production_identity(authority_signer)
            require_production_identity(host_verifier)
        self.pipe_name = pipe_name
        self.authority_id = authority_id
        self.host_id = host_id
        self.authority_signer = authority_signer
        self.host_verifier = host_verifier
        self.expected_host_sid = expected_host_sid
        self.expected_host_session_id = expected_host_session_id
        if (
            not expected_host_executable.is_absolute()
            or not expected_host_profile_path.is_absolute()
        ):
            raise PermissionError("Provider Host stored path binding is invalid")
        self.expected_host_executable = Path(
            os.path.abspath(expected_host_executable)
        )
        self.expected_host_profile_path = Path(
            os.path.abspath(expected_host_profile_path)
        )
        expected_root = (
            self.expected_host_profile_path
            / "AppData"
            / "Local"
            / "Programs"
            / "DarkSage"
            / "KeeperProviderHost"
        )
        self.expected_host_executable_sha256 = (
            expected_host_executable_sha256.lower()
        )
        self.expected_host_executable_file_identity = (
            expected_host_executable_file_identity
        )
        self._setup_workspace_root = (
            self.expected_host_profile_path
            / "AppData"
            / "Local"
            / "DarkSage"
            / "KeeperProviderExchange"
            / "setup"
        )
        if (
            self.expected_host_executable.name.casefold()
            != "keeperproviderhost.exe"
            or expected_root not in self.expected_host_executable.parents
            or len(expected_host_executable_sha256) != 64
            or any(
                character not in "0123456789abcdefABCDEF"
                for character in expected_host_executable_sha256
            )
            or (
                expected_host_executable_file_identity is not None
                and not _valid_file_identity(
                    expected_host_executable_file_identity
                )
            )
        ):
            raise PermissionError(
                "Authority requires a dedicated measured Provider Host executable"
            )
        self.timeout_seconds = timeout_seconds
        self.now = now or (lambda: datetime.now(UTC))
        self._enrollment_is_active = enrollment_is_active or (lambda: True)
        self._lifecycle_lock = threading.RLock()
        self._enabled = True
        self._sequences = _GatewaySequenceStore(sequence_store)

    def deactivate(self) -> None:
        """Fence all future Host RPCs after a durable enrollment denial."""
        with self._lifecycle_lock:
            self._enabled = False

    def enrollment_record(self) -> dict[str, Any]:
        """Return the exact protected-config-backed host enrollment identity."""
        return {
            "authority_id": self.authority_id,
            "authority_key_id": self.authority_signer.key_id,
            "enrollment_id": self.host_id,
            "host_executable": str(self.expected_host_executable),
            "host_executable_sha256": self.expected_host_executable_sha256,
            "host_id": self.host_id,
            "host_key_id": self.host_verifier.key_id,
            "host_profile_path": str(self.expected_host_profile_path),
            "host_protocol": HOST_PROTOCOL,
            "host_session_id": self.expected_host_session_id,
            "host_user_sid": self.expected_host_sid,
            "state": "ACTIVE",
        }

    def prepare_environment(
        self,
        preparation_nonce: str,
        provider_bin: Path,
        provider_registration_id: str | None = None,
    ) -> dict[str, Any]:
        # The caller derives this directory from an executable identity that
        # has already been validated through the authenticated client's locked
        # handle.  Do not reopen or resolve the user-owned path from the
        # restricted Authority service: that would both discard the handle
        # binding and make a second, service-token filesystem access check.
        if not provider_bin.is_absolute():
            raise PermissionError("Provider Host environment bin is invalid")
        lexical_bin = Path(os.path.abspath(provider_bin))
        if os.path.normcase(str(lexical_bin)) != os.path.normcase(str(provider_bin)):
            raise PermissionError("Provider Host environment bin is not canonical")
        body = {
            "preparation_nonce": preparation_nonce,
            "provider_bin": str(lexical_bin),
        }
        if provider_registration_id is not None:
            if not provider_registration_id:
                raise PermissionError(
                    "Provider Host environment registration is invalid"
                )
            body["provider_registration_id"] = provider_registration_id
        result = self._rpc("prepare_environment", body)
        if not isinstance(result, dict):
            raise PermissionError("Provider Host environment response is invalid")
        record = cast(dict[str, Any], result)
        payload = self.host_verifier.verify(
            record, purpose="keeper-provider-host-environment"
        )
        if (
            payload.get("host_id") != self.host_id
            or payload.get("preparation_nonce") != preparation_nonce
        ):
            raise PermissionError("Provider Host environment response differs")
        return record

    def setup_workspace(self, setup_id: str) -> Path:
        """Return the exact Host-owned launch workspace for one setup attempt.

        The Authority constructs this path lexically from the enrolled Host
        installation.  The unelevated Host creates and validates it beneath
        its output exchange tree before any provider process is launched.
        Keeping it outside the protected Host state tree preserves the
        Restricted Code deny on durable state while giving the restricted
        provider token a valid current directory.
        """

        if not setup_id or "\x00" in setup_id:
            raise PermissionError("Provider Host setup identifier is invalid")
        return self._setup_workspace_root / hashlib.sha256(
            setup_id.encode("utf-8")
        ).hexdigest()

    def bind_provider(self, provider_binding: Mapping[str, Any]) -> dict[str, Any]:
        result = self._rpc(
            "bind_provider", {"provider_binding": dict(provider_binding)}
        )
        if (
            not isinstance(result, dict)
            or result.get("state") != "QUALIFIED"
            or result.get("registration_id")
            != provider_binding.get("registration_id")
            or result.get("qualification_id")
            != provider_binding.get("qualification_id")
        ):
            raise PermissionError("Provider Host provider binding response differs")
        return dict(result)

    def execute(
        self,
        envelope: Mapping[str, Any],
        *,
        on_started: Callable[[dict[str, object]], None],
    ) -> dict[str, Any]:
        validated = validate_launch_envelope(envelope)
        if (
            validated["authority_id"] != self.authority_id
            or validated["host_id"] != self.host_id
        ):
            raise PermissionError("Provider Host gateway launch identity differs")
        signed = self.authority_signer.sign(LAUNCH_PURPOSE, validated)
        result = self._rpc(
            "execute",
            {
                "authority_attempt_id": validated["authority_attempt_id"],
                "launch_id": validated["launch_id"],
                "signed_envelope": signed,
            },
            on_started=on_started,
        )
        if not isinstance(result, dict):
            raise PermissionError("Provider Host completion is unavailable")
        completion_record = cast(dict[str, Any], result)
        completion = validate_completion(
            self.host_verifier.verify(
                completion_record, purpose="keeper-provider-host-completion"
            )
        )
        if (
            completion["authority_attempt_id"]
            != validated["authority_attempt_id"]
            or completion["launch_id"] != validated["launch_id"]
            or completion["envelope_digest"] != structured_digest(validated)
            or completion["provider_input_digest"]
            != validated["provider_input_digest"]
        ):
            raise PermissionError("Provider Host completion binding differs")
        return {
            "completion": completion,
            "signed_completion": completion_record,
        }

    def execute_setup(
        self,
        envelope: Mapping[str, Any],
        *,
        on_started: Callable[[dict[str, object]], None],
    ) -> dict[str, Any]:
        validated = validate_setup_envelope(envelope)
        if (
            validated["authority_id"] != self.authority_id
            or validated["host_id"] != self.host_id
        ):
            raise PermissionError("Provider Host gateway setup identity differs")
        signed = self.authority_signer.sign(SETUP_PURPOSE, validated)
        result = self._rpc(
            "setup",
            {
                "authority_attempt_id": validated["setup_id"],
                "launch_id": validated["setup_id"],
                "signed_envelope": signed,
            },
            on_started=on_started,
        )
        if not isinstance(result, dict):
            raise PermissionError("Provider Host setup result is unavailable")
        signed_result = cast(dict[str, Any], result)
        setup_result = validate_setup_result(
            self.host_verifier.verify(
                signed_result, purpose=SETUP_RESULT_PURPOSE
            )
        )
        if (
            setup_result["authority_id"] != self.authority_id
            or setup_result["host_id"] != self.host_id
            or setup_result["setup_id"] != validated["setup_id"]
            or setup_result["challenge"] != validated["challenge"]
            or setup_result["operation"] != validated["operation"]
            or setup_result["provider_registration_id"]
            != validated["provider_registration_id"]
            or setup_result["setup_envelope_digest"]
            != structured_digest(validated)
            or setup_result["environment_digest"]
            != validated["environment"]["digest"]
        ):
            raise PermissionError("Provider Host setup result binding differs")
        return {
            "observation": setup_result["observation"],
            "signed_result": signed_result,
            "setup_envelope_digest": structured_digest(validated),
            "setup_result_digest": structured_digest(signed_result),
        }

    def terminal_setup_result(
        self,
        *,
        setup_id: str,
        operation: str,
        provider_registration_id: str,
        challenge: str,
    ) -> dict[str, Any] | None:
        if (
            not setup_id
            or operation not in {"REGISTER_PROBE", "QUALIFY"}
            or not provider_registration_id
            or not challenge
        ):
            raise ValueError("Provider Host terminal setup query is invalid")
        result = self._rpc("terminal_setup_result", {"setup_id": setup_id})
        if result is None:
            return None
        if not isinstance(result, dict):
            raise PermissionError("Provider Host terminal setup result is invalid")
        signed_result = cast(dict[str, Any], result)
        setup_result = validate_setup_result(
            self.host_verifier.verify(
                signed_result, purpose=SETUP_RESULT_PURPOSE
            )
        )
        if (
            setup_result["authority_id"] != self.authority_id
            or setup_result["host_id"] != self.host_id
            or setup_result["setup_id"] != setup_id
            or setup_result["challenge"] != challenge
            or setup_result["operation"] != operation
            or setup_result["provider_registration_id"]
            != provider_registration_id
        ):
            raise PermissionError("Provider Host terminal setup result binding differs")
        return {
            "observation": setup_result["observation"],
            "signed_result": signed_result,
            "setup_envelope_digest": setup_result["setup_envelope_digest"],
            "setup_result_digest": structured_digest(signed_result),
        }

    def build_setup_envelope(
        self,
        *,
        operation: str,
        registration: Mapping[str, Any],
        provider_registration_id: str,
        challenge: str,
        setup_id: str,
        workspace: Path,
        environment_attestation: Mapping[str, Any],
    ) -> dict[str, Any]:
        binding = registration.get("windows_authentication_binding")
        executable_identity = registration.get("executable_file_identity")
        authenticode = registration.get("authenticode_binding")
        account_binding = registration.get("subscription_account_binding")
        usage_policy = registration.get("usage_policy")
        if not all(
            isinstance(value, dict)
            for value in (
                binding,
                executable_identity,
                authenticode,
                account_binding,
                usage_policy,
            )
        ):
            raise PermissionError("Provider Host setup registration is incomplete")
        binding = cast(dict[str, Any], binding)
        executable_identity = cast(dict[str, Any], executable_identity)
        authenticode = cast(dict[str, Any], authenticode)
        account_binding = cast(dict[str, Any], account_binding)
        usage_policy = cast(dict[str, Any], usage_policy)
        profile = Path(str(binding["profile_identity"]))
        if not profile.is_absolute():
            raise PermissionError("Provider Host setup profile binding is invalid")
        profile = Path(os.path.abspath(profile))
        if (
            str(binding["principal_sid"]).casefold()
            != self.expected_host_sid.casefold()
            or int(binding["windows_session_id"])
            != self.expected_host_session_id
            or profile != self.expected_host_profile_path
        ):
            raise PermissionError("Provider Host setup user binding differs")
        environment = self.host_verifier.verify(
            environment_attestation,
            purpose="keeper-provider-host-environment",
        )
        if (
            set(environment)
            != {
                "allowlist",
                "digest",
                "host_id",
                "preparation_nonce",
                "recorded_at",
                "scrubbed_names",
                "tls_root_bundle",
            }
            or environment.get("host_id") != self.host_id
        ):
            raise PermissionError(
                "Provider Host setup environment attestation is invalid"
            )
        if not workspace.is_absolute():
            raise PermissionError("Provider Host setup workspace is invalid")
        canonical_workspace = Path(os.path.abspath(workspace))
        if os.path.normcase(str(canonical_workspace)) != os.path.normcase(
            str(workspace)
        ):
            raise PermissionError("Provider Host setup workspace is not canonical")
        model_allowlist = registration.get("model_allowlist")
        if not isinstance(model_allowlist, list) or len(model_allowlist) != 1:
            raise PermissionError("Provider Host setup model binding is invalid")
        now = self.now().astimezone(UTC)
        return validate_setup_envelope(
            {
                "account_binding": {
                    "account_identity_digest": account_binding[
                        "account_identity_digest"
                    ],
                    "authentication_method": account_binding[
                        "authentication_method"
                    ],
                    "plan_type": account_binding["plan_type"],
                },
                "authority_id": self.authority_id,
                "challenge": challenge,
                "composition_identity": "PRODUCTION",
                "environment": {
                    name: environment[name]
                    for name in (
                        "allowlist",
                        "digest",
                        "preparation_nonce",
                        "scrubbed_names",
                        "tls_root_bundle",
                    )
                },
                "executable": {
                    "authenticode_binding": dict(authenticode),
                    "file_identity": dict(executable_identity),
                    "path": str(registration["canonical_executable_path"]),
                    "publisher": str(authenticode["publisher_subject"]),
                    "sha256": str(registration["executable_sha256"]),
                    "size": int(registration["executable_size"]),
                    "version": str(registration["expected_version"]),
                },
                "expires_at": (now + timedelta(minutes=1)).isoformat(),
                "host_id": self.host_id,
                "issued_at": now.isoformat(),
                "model_id": str(model_allowlist[0]),
                "nonce": uuid.uuid4().hex,
                "operation": operation,
                "provider_id": str(
                    registration.get("logical_provider_id", "codex")
                ),
                "provider_registration_id": provider_registration_id,
                "resource_limits": {
                    "active_process_limit": 8,
                    "memory_bytes": 2 * 1024 * 1024 * 1024,
                    "stderr_bytes": 8 * 1024 * 1024,
                    "stdout_bytes": 16 * 1024 * 1024,
                    "timeout_seconds": 180,
                },
                "sequence": self._sequences.next(self.authority_id),
                "setup_id": setup_id,
                "usage_policy_digest": structured_digest(usage_policy),
                "user_binding": {
                    "profile_path": str(profile),
                    "session_id": int(binding["windows_session_id"]),
                    "user_sid": str(binding["principal_sid"]),
                },
                "workspace": {
                    "canonical_path": str(canonical_workspace),
                    "identity": hashlib.sha256(
                        str(canonical_workspace).casefold().encode("utf-8")
                    ).hexdigest(),
                    "reservation_id": setup_id,
                },
            }
        )

    def build_launch_envelope(
        self,
        *,
        registration: Mapping[str, Any],
        attempt: Mapping[str, Any],
        argv: list[str],
        environment_attestation: Mapping[str, Any],
    ) -> dict[str, Any]:
        binding = registration.get("windows_authentication_binding")
        executable_identity = registration.get("executable_file_identity")
        authenticode = registration.get("authenticode_binding")
        usage_policy = registration.get("usage_policy")
        account_binding = registration.get("subscription_account_binding")
        qualification_id = registration.get("qualification_evidence_id")
        if not all(
            isinstance(value, dict)
            for value in (
                binding,
                executable_identity,
                authenticode,
                usage_policy,
                account_binding,
            )
        ) or not isinstance(qualification_id, str):
            raise PermissionError("Provider Host registration binding is incomplete")
        binding = cast(dict[str, Any], binding)
        executable_identity = cast(dict[str, Any], executable_identity)
        authenticode = cast(dict[str, Any], authenticode)
        usage_policy = cast(dict[str, Any], usage_policy)
        account_binding = cast(dict[str, Any], account_binding)
        profile = Path(str(binding["profile_identity"]))
        if not profile.is_absolute():
            raise PermissionError(
                "Provider Host registration profile binding is invalid"
            )
        profile = Path(os.path.abspath(profile))
        if (
            str(binding["principal_sid"]).casefold()
            != self.expected_host_sid.casefold()
            or int(binding["windows_session_id"])
            != self.expected_host_session_id
            or profile != self.expected_host_profile_path
        ):
            raise PermissionError("Provider Host registration user binding differs")
        environment = self.host_verifier.verify(
            environment_attestation,
            purpose="keeper-provider-host-environment",
        )
        required_environment = {
            "allowlist",
            "digest",
            "host_id",
            "preparation_nonce",
            "recorded_at",
            "scrubbed_names",
            "tls_root_bundle",
        }
        if set(environment) != required_environment or environment.get(
            "host_id"
        ) != self.host_id:
            raise PermissionError("Provider Host environment attestation is invalid")
        now = self.now().astimezone(UTC)
        provider_input_digest = attempt.get("provider_input_digest")
        if not isinstance(provider_input_digest, str):
            provider_input_digest = str(attempt.get("prompt_digest", ""))
        provider_input = attempt.get("provider_input")
        input_record = provider_input if isinstance(provider_input, dict) else {}
        for input_name, attempt_name in (
            ("reviewer_assignment_id", "assignment_id"),
            ("work_item_id", "work_item_id"),
            ("workflow_id", "workflow_id"),
            ("project_id", "project_id"),
            ("charter_id", "charter_id"),
            ("charter_revision", "charter_revision"),
        ):
            if input_name in input_record and (
                input_record[input_name] != attempt.get(attempt_name)
            ):
                raise PermissionError(
                    "Provider Host typed-input lineage differs from launch"
                )
        usage_observation = attempt.get("usage_observation")
        usage = usage_observation if isinstance(usage_observation, dict) else {}
        account_digest = str(account_binding["account_identity_digest"])
        provider_id = str(registration["logical_provider_id"])
        authentication_method = str(account_binding["authentication_method"])
        expected_account_id = authentication_method + ":" + account_digest
        if attempt.get("provider_account_id") != expected_account_id:
            raise PermissionError("Provider Host provider-account binding differs")
        executable_path = str(registration["canonical_executable_path"])
        executable_size = int(registration["executable_size"])
        return validate_launch_envelope(
            {
                "account_id": expected_account_id,
                "argv": list(argv),
                "assignment_id": str(
                    input_record.get("reviewer_assignment_id")
                    or attempt.get("assignment_id")
                    or attempt["task_id"]
                ),
                "authority_attempt_id": str(attempt["id"]),
                "authority_id": self.authority_id,
                "cancellation": {
                    "on_lock": "CANCEL_EXISTING",
                    "on_logoff": "CANCEL_AND_EXIT",
                    "token_digest": hashlib.sha256(
                        str(attempt["launch_challenge"]).encode("utf-8")
                    ).hexdigest(),
                },
                "charter_id": str(attempt["charter_id"]),
                "charter_revision_id": (
                    f"{attempt['charter_id']}:r{attempt['charter_revision']}"
                ),
                "composition_identity": "PRODUCTION",
                "effort": str(attempt["reasoning_level"]),
                "environment": {
                    name: environment[name]
                    for name in (
                        "allowlist",
                        "digest",
                        "preparation_nonce",
                        "scrubbed_names",
                        "tls_root_bundle",
                    )
                },
                "executable": {
                    "authenticode_binding": dict(authenticode),
                    "file_identity": dict(executable_identity),
                    "path": executable_path,
                    "publisher": str(authenticode["publisher_subject"]),
                    "sha256": str(registration["executable_sha256"]),
                    "size": executable_size,
                    "version": str(registration["expected_version"]),
                },
                "expires_at": (now + timedelta(minutes=1)).isoformat(),
                "host_id": self.host_id,
                "issued_at": now.isoformat(),
                "launch_claim_digest": structured_digest(attempt),
                "launch_id": str(attempt["claim_transaction_id"]),
                "model_id": str(attempt["model_id"]),
                "network_policy": {
                    "allow_external": True,
                    "policy_id": provider_id + "-subscription-only",
                },
                "nonce": uuid.uuid4().hex,
                "project_id": str(attempt["project_id"]),
                "provider_id": provider_id,
                "provider_input_digest": provider_input_digest,
                "provider_qualification_id": qualification_id,
                "provider_registration_id": str(attempt["registration_id"]),
                "provider_session_id": str(attempt["provider_instance_id"]),
                "resource_limits": {
                    "active_process_limit": 8,
                    "memory_bytes": 2 * 1024 * 1024 * 1024,
                    "stderr_bytes": 8 * 1024 * 1024,
                    "stdout_bytes": 16 * 1024 * 1024,
                    "timeout_seconds": int(attempt["timeout_seconds"]),
                },
                "sequence": self._sequences.next(self.authority_id),
                "usage": {
                    "generation": int(usage.get("generation", 1)),
                    "max_units": int(usage_policy["keeper_launch_budget"]),
                    "pool_id": provider_id + ":" + account_digest,
                    "reservation_id": str(attempt["claim_transaction_id"]),
                },
                "user_binding": {
                    "profile_path": str(profile),
                    "session_id": int(binding["windows_session_id"]),
                    "user_sid": str(binding["principal_sid"]),
                },
                "work_item_id": str(
                    input_record.get("work_item_id")
                    or attempt.get("work_item_id")
                    or attempt["task_id"]
                ),
                "workflow_id": str(
                    input_record.get("workflow_id")
                    or attempt.get("workflow_id")
                    or attempt["keeper_run_id"]
                ),
                "workspace": {
                    "canonical_path": str(Path(str(attempt["workspace"])).resolve(strict=True)),
                    "identity": str(attempt["workspace_identity"]),
                    "reservation_id": str(attempt["workspace_reservation_id"]),
                },
            }
        )

    def cancel(self, authority_attempt_id: str, launch_id: str) -> bool:
        result = self._rpc(
            "cancel",
            {
                "authority_attempt_id": authority_attempt_id,
                "launch_id": launch_id,
            },
        )
        return isinstance(result, dict) and result.get("cancel_requested") is True

    def status(self) -> dict[str, Any]:
        result = self._rpc("status", {})
        if not isinstance(result, dict):
            raise PermissionError("Provider Host status is invalid")
        return _validate_host_status(dict(result))

    def reconcile_uncertain_launch(
        self, reconciliation: Mapping[str, Any]
    ) -> dict[str, Any]:
        signed = self.authority_signer.sign(
            LAUNCH_RECONCILIATION_PURPOSE, dict(reconciliation)
        )
        result = self._rpc(
            "reconcile_uncertain_launch",
            {"signed_reconciliation": signed},
        )
        if not isinstance(result, dict):
            raise PermissionError(
                "Provider Host launch reconciliation result is invalid"
            )
        payload = self.host_verifier.verify(
            result, purpose=LAUNCH_RECONCILIATION_RESULT_PURPOSE
        )
        expected_launch = reconciliation.get("expected_launch")
        effect_accounting = reconciliation.get("effect_accounting")
        expected_reconciliation_digest = structured_digest(
            {
                "authorization_digest": structured_digest(reconciliation),
                "effect_accounting": effect_accounting,
                "reconciliation_id": reconciliation.get("reconciliation_id"),
                "resolution": reconciliation.get("resolution"),
            }
        )
        expected = {
            "authority_id",
            "effect_accounting",
            "host_id",
            "launch_id",
            "reconciliation_digest",
            "reconciliation_id",
            "state",
        }
        if (
            set(payload) != expected
            or payload.get("authority_id") != self.authority_id
            or payload.get("host_id") != self.host_id
            or payload.get("reconciliation_id")
            != reconciliation.get("reconciliation_id")
            or not isinstance(expected_launch, dict)
            or payload.get("launch_id") != expected_launch.get("launch_id")
            or payload.get("effect_accounting") != effect_accounting
            or payload.get("reconciliation_digest")
            != expected_reconciliation_digest
            or payload.get("state") != "FAILED"
        ):
            raise PermissionError(
                "Provider Host launch reconciliation result differs"
            )
        return {"receipt": dict(result), "result": dict(payload)}

    def _rpc(
        self,
        operation: str,
        body: Mapping[str, Any],
        *,
        on_started: Callable[[dict[str, object]], None] | None = None,
    ) -> object:
        with self._lifecycle_lock:
            if not self._enabled or not self._enrollment_is_active():
                raise PermissionError("Provider Host enrollment is not active")
            try:
                return self._rpc_active(operation, body, on_started=on_started)
            except ProviderHostIdentityUncertain:
                # Never retry an identity-uncertain worker automatically. A
                # fresh enrollment or service lifecycle must rebuild the
                # gateway after the preserved failure is reviewed.
                self._enabled = False
                raise

    def _rpc_active(
        self,
        operation: str,
        body: Mapping[str, Any],
        *,
        on_started: Callable[[dict[str, object]], None] | None = None,
    ) -> object:
        if self.expected_host_executable_file_identity is None:
            raise PermissionError(
                "Provider Host durable executable identity is unavailable"
            )
        with connected_client_pipe(
            self.pipe_name, timeout_seconds=self.timeout_seconds
        ) as pipe:
            expected_peer = PipePeerIdentity(
                process_id=0,
                session_id=self.expected_host_session_id,
                user_sid=self.expected_host_sid,
                executable_path=str(self.expected_host_executable),
                executable_sha256=self.expected_host_executable_sha256,
                executable_file_identity=(
                    self.expected_host_executable_file_identity
                ),
            )
            with authenticated_named_pipe_server_binding(
                pipe, expected=expected_peer
            ) as peer_binding:
                observed_core = peer_binding.revalidate_core(
                    self.expected_host_sid
                )
                observed = PipePeerIdentity(
                    process_id=observed_core.process_id,
                    session_id=observed_core.session_id,
                    user_sid=observed_core.sid,
                    executable_path=observed_core.executable_path,
                    executable_sha256=self.expected_host_executable_sha256,
                    executable_file_identity=(
                        self.expected_host_executable_file_identity
                    ),
                )
                return self._rpc_bound(
                    pipe=pipe,
                    observed=observed,
                    operation=operation,
                    body=body,
                    on_started=on_started,
                )

    def _rpc_bound(
        self,
        *,
        pipe: int,
        observed: PipePeerIdentity,
        operation: str,
        body: Mapping[str, Any],
        on_started: Callable[[dict[str, object]], None] | None,
    ) -> object:
        authority_executable = Path(sys.executable).resolve(strict=True)
        authority_stat = authority_executable.stat()
        authority_file_identity = (
            int(authority_stat.st_dev),
            int(authority_stat.st_ino),
            int(authority_stat.st_size),
            int(authority_stat.st_mtime_ns),
        )
        hello = self._message(
            {
                "authority_executable_file_identity": _file_identity_record(
                    authority_file_identity
                ),
                "authority_executable_path": str(authority_executable),
                "authority_executable_sha256": hashlib.sha256(
                    authority_executable.read_bytes()
                ).hexdigest(),
                "authority_id": self.authority_id,
                "authority_process_id": os.getpid(),
                "host_id": self.host_id,
            }
        )
        write_frame(pipe, self.authority_signer.sign(HELLO_PURPOSE, hello))
        hello_record = read_frame(pipe)
        host_hello = self.host_verifier.verify(
            hello_record, purpose=HELLO_PURPOSE
        )
        host_file_identity = _parse_file_identity_record(
            host_hello.get("host_executable_file_identity")
        )
        host_digest = host_hello.get("host_executable_sha256")
        host_binding = host_hello.get("user_binding")
        if (
            set(host_hello)
            != {
                "authority_nonce",
                "host_id",
                "host_nonce",
                "host_process_id",
                "host_executable_file_identity",
                "host_executable_sha256",
                "state",
                "user_binding",
            }
            or host_hello.get("authority_nonce") != hello["nonce"]
            or host_hello.get("host_id") != self.host_id
            or host_hello.get("host_process_id") != observed.process_id
            or host_binding
            != {
                "profile_path": str(self.expected_host_profile_path),
                "session_id": self.expected_host_session_id,
                "user_sid": self.expected_host_sid,
            }
        ):
            raise PermissionError("Provider Host hello response differs")
        if not isinstance(host_digest, str):
            raise PermissionError("Provider Host hello executable digest is invalid")
        require_peer_identity(
            PipePeerIdentity(
                process_id=observed.process_id,
                session_id=observed.session_id,
                user_sid=observed.user_sid,
                executable_path=observed.executable_path,
                executable_sha256=host_digest,
                executable_file_identity=host_file_identity,
            ),
            process_id=observed.process_id,
            session_id=self.expected_host_session_id,
            user_sid=self.expected_host_sid,
            executable_path=self.expected_host_executable,
            executable_sha256=self.expected_host_executable_sha256,
            executable_file_identity=self.expected_host_executable_file_identity,
        )
        request = self._message(
            {
                "authority_id": self.authority_id,
                "authority_nonce": hello["nonce"],
                "body": dict(body),
                "body_digest": structured_digest(body),
                "host_nonce": host_hello["host_nonce"],
                "operation": operation,
            }
        )
        request_record = self.authority_signer.sign(REQUEST_PURPOSE, request)
        write_frame(pipe, request_record)
        while True:
            frame = read_frame(pipe)
            if frame.get("event") == "STARTED":
                record = frame.get("record")
                if not isinstance(record, dict) or on_started is None:
                    raise PermissionError("Provider Host STARTED event is unexpected")
                event = self.host_verifier.verify(
                    record, purpose=STARTED_PURPOSE
                )
                if (
                    event.get("authority_attempt_id")
                    != body.get("authority_attempt_id")
                    or event.get("launch_id") != body.get("launch_id")
                    or not isinstance(event.get("observation"), dict)
                ):
                    raise PermissionError("Provider Host STARTED event differs")
                on_started(dict(event["observation"]))
                ack = self._message(
                    {
                        "authority_id": self.authority_id,
                        "authority_attempt_id": event["authority_attempt_id"],
                        "event_digest": structured_digest(record),
                        "launch_id": event["launch_id"],
                    }
                )
                write_frame(
                    pipe,
                    self.authority_signer.sign(STARTED_ACK_PURPOSE, ack),
                )
                continue
            response = self.host_verifier.verify(
                frame, purpose=RESPONSE_PURPOSE
            )
            if (
                set(response)
                != {
                    "authority_nonce",
                    "host_nonce",
                    "operation",
                    "request_digest",
                    "result",
                }
                or response.get("authority_nonce") != hello["nonce"]
                or response.get("host_nonce") != host_hello["host_nonce"]
                or response.get("operation") != operation
                or response.get("request_digest")
                != structured_digest(request_record)
            ):
                raise PermissionError("Provider Host response binding differs")
            return response["result"]

    def _message(self, value: Mapping[str, Any]) -> dict[str, Any]:
        now = self.now().astimezone(UTC)
        return {
            **dict(value),
            "expires_at": (now + timedelta(minutes=1)).isoformat(),
            "issued_at": now.isoformat(),
            "nonce": uuid.uuid4().hex,
            "sequence": self._sequences.next(self.authority_id),
        }


def _validate_host_status(value: dict[str, Any]) -> dict[str, Any]:
    journal = value.get("launch_journal")
    if not isinstance(journal, dict) or set(journal) != {
        "active_launch_count",
        "active_or_uncertain_launch_count",
        "launches",
        "summary_digest",
        "uncertain_launch_count",
    }:
        raise PermissionError("Provider Host launch journal is invalid")
    launches = journal.get("launches")
    active = journal.get("active_launch_count")
    total = journal.get("active_or_uncertain_launch_count")
    uncertain = journal.get("uncertain_launch_count")
    if (
        not isinstance(launches, list)
        or isinstance(active, bool)
        or not isinstance(active, int)
        or active < 0
        or isinstance(total, bool)
        or not isinstance(total, int)
        or total < 0
        or isinstance(uncertain, bool)
        or not isinstance(uncertain, int)
        or uncertain < 0
        or total != len(launches)
        or total != active + uncertain
        or journal.get("summary_digest") != structured_digest(launches)
    ):
        raise PermissionError("Provider Host launch journal accounting differs")
    fields = {
        "authority_attempt_id",
        "detail_code",
        "envelope_digest",
        "launch_id",
        "operation",
        "phase",
        "state",
        "updated_at",
        "workspace_digest",
    }
    for launch in launches:
        if (
            not isinstance(launch, dict)
            or set(launch) != fields
            or launch.get("state") not in {"CLAIMED", "STARTED", "RUNNING", "UNCERTAIN"}
            or launch.get("operation")
            not in {"PROVIDER_EXECUTION", "REGISTER_PROBE", "QUALIFY", "LEGACY_UNKNOWN"}
            or not all(
                isinstance(launch.get(name), str) and launch.get(name)
                for name in fields
            )
            or any(
                len(str(launch.get(name))) != 64
                or any(character not in "0123456789abcdef" for character in str(launch.get(name)))
                for name in ("envelope_digest", "workspace_digest")
            )
        ):
            raise PermissionError("Provider Host launch journal entry is invalid")
    return value


def _valid_file_identity(value: tuple[int, int, int, int]) -> bool:
    return (
        all(isinstance(item, int) and not isinstance(item, bool) for item in value)
        and value[0] >= 0
        and value[1] > 0
        and value[2] > 0
        and value[3] > 0
    )


def _file_identity_record(
    value: tuple[int, int, int, int],
) -> dict[str, int]:
    return {
        "device_id": value[0],
        "file_id": value[1],
        "modified_ns": value[3],
        "schema_version": 1,
        "size": value[2],
    }


def _parse_file_identity_record(value: object) -> tuple[int, int, int, int]:
    if not isinstance(value, dict) or set(value) != {
        "device_id",
        "file_id",
        "modified_ns",
        "schema_version",
        "size",
    }:
        raise PermissionError("Provider Host hello file identity is invalid")
    items = (
        value.get("device_id"),
        value.get("file_id"),
        value.get("size"),
        value.get("modified_ns"),
    )
    if value.get("schema_version") != 1 or not all(
        isinstance(item, int) and not isinstance(item, bool) for item in items
    ):
        raise PermissionError("Provider Host hello file identity is invalid")
    result = cast(tuple[int, int, int, int], items)
    if not _valid_file_identity(result):
        raise PermissionError("Provider Host hello file identity is invalid")
    return result


class _GatewaySequenceStore:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS sequences("
                "authority_id TEXT PRIMARY KEY,value INTEGER NOT NULL)"
            )
            connection.commit()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            yield connection
        finally:
            connection.close()

    def next(self, authority_id: str) -> int:
        with self.connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT value FROM sequences WHERE authority_id=?",
                    (authority_id,),
                ).fetchone()
                value = 1 if row is None else int(row[0]) + 1
                connection.execute(
                    "INSERT INTO sequences(authority_id,value) VALUES(?,?) "
                    "ON CONFLICT(authority_id) DO UPDATE SET value=excluded.value",
                    (authority_id, value),
                )
                connection.commit()
                return value
            except BaseException:
                connection.rollback()
                raise
