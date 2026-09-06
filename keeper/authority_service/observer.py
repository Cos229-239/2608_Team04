from __future__ import annotations

import hashlib
import ctypes
import json
import os
import secrets
import sys
import threading
import uuid
from contextlib import contextmanager
from ctypes import wintypes
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterator, Mapping, cast

if TYPE_CHECKING:
    from keeper.authority_service.provider_host_gateway import ProviderHostGateway

from keeper.evidence_input import (
    provider_prompt_context,
)
from keeper.authority_service.core import (
    CompletionObservation,
    ExecutionObservation,
    ProcessObservation,
    QualificationObservation,
)
from keeper.authority_service import restricted_process as restricted_process_runtime
from keeper.authority_service.provider_identity import (
    account_sid,
    restricted_provider_identity_token,
)
from keeper.authority_service.restricted_process import (
    WindowsSessionQueryStatus,
    authenticated_client_environment,
    authenticated_client_process_impersonation_token,
    authenticated_client_transfer_process,
    authenticated_client_profile_path,
    authenticated_client_windows_session_state,
    authenticated_profile_primary_token,
    authenticated_named_pipe_client,
    profile_restricted_primary_token,
    impersonate_token,
    run_restricted_process,
    require_impersonation_level,
    token_session_id,
    token_user_sid_string,
    windows_session_is_active,
)
from keeper.authority_service.windows_identity import (
    NamedPipeClientProcessBinding,
    process_image,
)
from keeper.authority_service.windows_signature import (
    authenticode_enrollment_binding,
    authenticode_identity,
    authenticode_identity_from_handle,
)
from keeper.policies import filtered_environment
from keeper.providers.adapters import (
    ProviderCapabilities,
    authority_provider_output_schema,
    create_provider_registration,
    validate_value_against_schema,
)
from keeper.providers.codex_contract import (
    CODEX_ALLOWED_SUBSCRIPTION_PLANS,
    CODEX_REQUIRED_SUBSCRIPTION_PLAN,
    build_codex_exec_command,
    classify_codex_execution_failure,
    sanitized_codex_environment,
    structured_digest,
    validate_codex_authenticode_binding,
    validate_executable_file_identity,
)
from keeper.providers.claude_contract import (
    CLAUDE_ALLOWED_SUBSCRIPTION_PLANS,
    CLAUDE_AUTHENTICATION_MODE,
    CLAUDE_PINNED_REVIEW_MODEL,
    build_claude_exec_command,
    validate_claude_authenticode_binding,
)
from keeper.provider_host.enrollment import stable_host_identity
from keeper.provider_host.install import (
    ProviderHostInstaller,
    attest_provider_host_exchange_root,
)


_HOSTED_SUBSCRIPTION_SCHEMAS = frozenset({4, 5})


class ServiceProviderObserver:
    """OS-backed observations available only inside the Authority Service host."""

    def __init__(
        self,
        provider_root: Path,
        allowed_evidence_root: Path,
        provider_account_name: str,
        provider_credential_path: Path,
        authorized_client_sid: str,
        provider_host_gateway: ProviderHostGateway | None = None,
    ) -> None:
        self.provider_root = provider_root.resolve()
        self.allowed_evidence_root = allowed_evidence_root.resolve()
        self.provider_account_name = provider_account_name
        self.provider_credential_path = provider_credential_path.resolve(
            strict=True
        )
        self.authorized_client_sid = authorized_client_sid
        self.provider_host_gateway = provider_host_gateway
        self.provider_root.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._active_lock = threading.Lock()
        self._active_cancellations: dict[str, threading.Event] = {}
        self._cancelled_attempts: set[str] = set()
        self._active_host_launches: dict[str, str] = {}

    def provider_host_status(self) -> dict[str, Any]:
        """Return a redacted, read-only Provider Host health projection."""
        gateway = self.provider_host_gateway
        if gateway is None:
            return {
                "installed": False,
                "online": False,
                "state": "NOT_INSTALLED",
                "protocol": None,
                "protocol_compatible": False,
                "provider_state": "UNAVAILABLE",
                "founder_action_required": "INSTALL_AND_ENROLL_PROVIDER_HOST",
                "active_or_uncertain_launch_count": None,
                "active_launch_count": None,
                "uncertain_launch_count": None,
                "launch_state_proven": False,
                "launches": [],
            }
        try:
            raw = gateway.status()
        except (OSError, PermissionError, RuntimeError, ValueError) as error:
            return {
                "installed": True,
                "online": False,
                "state": "OFFLINE",
                "protocol": "keeper-provider-host/1",
                "protocol_compatible": True,
                "provider_state": "UNAVAILABLE",
                "founder_action_required": "START_OR_REPAIR_PROVIDER_HOST",
                "failure_reason": _provider_host_failure_reason(error),
                "active_or_uncertain_launch_count": None,
                "active_launch_count": None,
                "uncertain_launch_count": None,
                "launch_state_proven": False,
                "launches": [],
            }
        providers = _status_provider_bindings(raw)
        provider = providers[0] if providers else {}
        state = str(raw.get("state", "STALE"))
        protocol = str(raw.get("host_protocol", ""))
        compatible = protocol == "keeper-provider-host/1"
        registration_id = provider.get("registration_id")
        qualification_id = provider.get("qualification_id")
        provider_state = (
            "QUALIFIED"
            if isinstance(qualification_id, str) and qualification_id
            else (
                "REGISTERED"
                if isinstance(registration_id, str) and registration_id
                else "NO_QUALIFIED_PROVIDERS"
            )
        )
        action: str | None = None
        journal = raw.get("launch_journal")
        if not isinstance(journal, dict):
            raise PermissionError("Provider Host launch journal is unavailable")
        unresolved_count = journal.get("active_or_uncertain_launch_count")
        if isinstance(unresolved_count, bool) or not isinstance(unresolved_count, int):
            raise PermissionError("Provider Host launch journal count is invalid")
        if not compatible:
            action = "UPDATE_PROVIDER_HOST_PROTOCOL"
        elif state not in {"READY", "RUNNING", "PREPARING", "CLAIMED", "STARTED"}:
            action = "RESTORE_PROVIDER_HOST_READINESS"
        elif provider_state != "QUALIFIED":
            action = "COMPLETE_PROVIDER_REGISTRATION_AND_QUALIFICATION"
        if unresolved_count:
            action = "RECONCILE_PROVIDER_HOST_LAUNCH"
        return {
            "installed": True,
            "online": True,
            "state": state,
            "protocol": protocol or None,
            "protocol_compatible": compatible,
            "provider_id": provider.get("provider_id"),
            "provider_state": provider_state,
            "execution_state": (
                "UNCERTAIN"
                if int(journal["uncertain_launch_count"]) > 0
                else state
                if state in {"CLAIMED", "STARTED", "RUNNING"}
                else "IDLE"
            ),
            "active_or_uncertain_launch_count": unresolved_count,
            "active_launch_count": int(journal["active_launch_count"]),
            "uncertain_launch_count": int(journal["uncertain_launch_count"]),
            "launch_state_proven": True,
            "launches": list(journal["launches"]),
            "usage_state": "AUTHORITY_MANAGED",
            "founder_action_required": action,
        }

    def reconcile_provider_host_launch(
        self, reconciliation: Mapping[str, Any]
    ) -> dict[str, Any]:
        gateway = self.provider_host_gateway
        if gateway is None:
            raise PermissionError(
                "Provider Host launch reconciliation requires an active enrollment"
            )
        return gateway.reconcile_uncertain_launch(reconciliation)

    def validate_provider_host_enrollment_proposal(
        self, proposal: Mapping[str, Any], client_sid: str
    ) -> dict[str, Any]:
        """Independently remeasure a Host proposal under its authenticated user."""
        if client_sid.casefold() != self.authorized_client_sid.casefold():
            raise PermissionError("Provider Host enrollment client SID differs")
        process = self._client_process_binding()
        process_identity = process.revalidate(client_sid)
        _, profile, observed_sid, observed_session = self._validated_client_profile(
            self._client_token(),
            process.profile_token,
            expected_sid=client_sid,
        )
        binding = proposal.get("user_binding")
        installation = proposal.get("installation")
        if not isinstance(binding, dict) or not isinstance(installation, dict):
            raise PermissionError("Provider Host enrollment binding is incomplete")
        binding = dict(binding)
        installation = dict(installation)
        executable = Path(str(installation.get("executable_path", "")))
        install_root = Path(str(installation.get("install_root", "")))
        if not executable.is_absolute() or not install_root.is_absolute():
            raise PermissionError("Provider Host enrollment path is not absolute")
        lexical_executable = Path(os.path.abspath(executable))
        lexical_root = Path(os.path.abspath(install_root))
        observation = _authority_provider_host_path_observation(
            client_process_binding=process,
            expected_sid=client_sid,
            profile=profile,
            installation=installation,
            observed_sid=observed_sid,
        )
        installed = cast(dict[str, Any], observation["installed"])
        current = installed.get("current")
        if (
            installed.get("transaction_pending") is not False
            or not isinstance(current, dict)
        ):
            raise PermissionError("Provider Host installation is not stable")
        expected_root = Path(str(observation["expected_root"]))
        canonical = Path(str(observation["canonical_executable"]))
        canonical_root = Path(str(observation["canonical_root"]))
        expected_host_id, expected_key_name = stable_host_identity(
            observed_sid, str(current.get("package_sha256", ""))
        )
        pipe_suffix = hashlib.sha256(
            (expected_host_id + ":" + observed_sid).encode("utf-8")
        ).hexdigest()[:24]
        expected_state = Path(str(observation["expected_state"]))
        expected_output = Path(str(observation["expected_output"]))
        if (
            os.path.normcase(str(canonical))
            != os.path.normcase(str(current.get("artifact_path", "")))
            or installation.get("executable_sha256")
            != current.get("artifact_sha256")
            or installation.get("manifest_sha256")
            != current.get("package_sha256")
            or installation.get("package_version") != current.get("version")
        ):
            raise PermissionError("Provider Host enrollment installed package differs")
        if (
            os.path.normcase(str(canonical_root))
            != os.path.normcase(str(expected_root))
            or os.path.normcase(str(canonical))
            != os.path.normcase(str(lexical_executable))
            or canonical_root not in canonical.parents
            or canonical.name.casefold() != "keeperproviderhost.exe"
            or observation.get("executable_prefix") != b"MZ"
            or proposal.get("host_id") != expected_host_id
            or proposal.get("host_key_name") != expected_key_name
            or proposal.get("pipe_name")
            != rf"\\.\pipe\KeeperProviderHost-{pipe_suffix}"
            or os.path.normcase(str(proposal.get("state_root", "")))
            != os.path.normcase(str(expected_state))
            or os.path.normcase(str(proposal.get("output_root", "")))
            != os.path.normcase(str(expected_output))
            or not isinstance(observation.get("exchange_security_digest"), str)
            or len(str(observation.get("exchange_security_digest"))) != 64
            or str(binding.get("user_sid", "")).casefold()
            != observed_sid.casefold()
            or binding.get("session_id") != observed_session
            or os.path.normcase(str(binding.get("profile_path", "")))
            != os.path.normcase(profile)
            or process_identity.sid.casefold() != observed_sid.casefold()
            or process_identity.session_id != observed_session
        ):
            raise PermissionError("Provider Host enrollment user or path binding differs")
        if (
            observation.get("executable_sha256")
            != installation.get("executable_sha256")
            or observation.get("executable_size")
            != installation.get("executable_size")
            or observation.get("executable_file_identity")
            != installation.get("executable_file_identity")
            or observation.get("authenticode_binding")
            != installation.get("authenticode_binding")
            or observation.get("final_executable_file_identity")
            != observation.get("executable_file_identity")
        ):
            raise PermissionError("Provider Host enrollment executable differs")
        process.revalidate(client_sid)
        return dict(proposal)

    def provider_host_runtime_configuration(
        self,
        proposal: Mapping[str, Any],
        *,
        enrollment_id: str,
        authority_id: str,
        authority_public_identity: Mapping[str, object],
    ) -> dict[str, Any]:
        """Create the exact receipt-owned Host runtime configuration."""
        binding = proposal.get("user_binding")
        installation = proposal.get("installation")
        public = proposal.get("host_public_identity")
        if not all(isinstance(value, dict) for value in (binding, installation, public)):
            raise PermissionError("Provider Host runtime binding is incomplete")
        service_executable = Path(sys.executable).resolve(strict=True)
        service_stat = service_executable.stat()
        return {
            "authority_id": authority_id,
            "authority_peer": {
                "executable_file_identity": _executable_file_identity(service_stat),
                "executable_path": str(service_executable),
                "executable_sha256": hashlib.sha256(
                    service_executable.read_bytes()
                ).hexdigest(),
                "session_id": 0,
                "user_sid": account_sid(r"NT SERVICE\KeeperAuthority"),
            },
            "authority_public_identity": dict(authority_public_identity),
            "enrollment_id": enrollment_id,
            "host_id": str(proposal["host_id"]),
            "host_key_name": str(proposal["host_key_name"]),
            "host_public_identity": dict(cast(dict[str, Any], public)),
            "output_root": str(proposal["output_root"]),
            "pipe_name": str(proposal["pipe_name"]),
            "schema_version": 2,
            "state_root": str(proposal["state_root"]),
            "user_binding": dict(cast(dict[str, Any], binding)),
        }

    def bind_qualified_provider(
        self,
        registration: Mapping[str, Any],
        qualification: Mapping[str, Any],
    ) -> dict[str, Any]:
        gateway = self.provider_host_gateway
        if gateway is None:
            raise PermissionError(
                "Qualified Codex binding requires KeeperProviderHost"
            )
        if (
            registration.get("registration_schema_version")
            not in _HOSTED_SUBSCRIPTION_SCHEMAS
            or registration.get("registration_lifecycle") != "QUALIFIED"
            or qualification.get("qualification_result") != "qualified"
        ):
            raise PermissionError("Provider Host qualification is not complete")
        account = registration.get("subscription_account_binding")
        file_identity = registration.get("executable_file_identity")
        authenticode = registration.get("authenticode_binding")
        models = registration.get("model_allowlist")
        efforts = registration.get("effort_levels")
        if (
            not isinstance(account, dict)
            or not isinstance(file_identity, dict)
            or not isinstance(authenticode, dict)
            or not isinstance(models, list)
            or not isinstance(efforts, list)
        ):
            raise PermissionError("Provider Host qualified binding is incomplete")
        account_digest = str(account.get("account_identity_digest", ""))
        binding = {
            "account_id": str(account.get("authentication_method"))
            + ":"
            + account_digest,
            "authenticode_binding": dict(authenticode),
            "efforts": list(efforts),
            "executable_path": str(registration["canonical_executable_path"]),
            "executable_sha256": str(registration["executable_sha256"]),
            "executable_size": int(registration["executable_size"]),
            "file_identity": dict(file_identity),
            "models": list(models),
            "provider_id": str(registration["logical_provider_id"]),
            "publisher": str(authenticode["publisher_subject"]),
            "qualification_id": str(registration["qualification_evidence_id"]),
            "registration_id": str(registration["trusted_registration_id"]),
            "session_id": str(qualification["provider_instance_id"]),
            "version": str(registration["expected_version"]),
        }
        return gateway.bind_provider(binding)

    @contextmanager
    def bind_client(self, pipe: int) -> Iterator[None]:
        if getattr(self._local, "token", None) is not None:
            raise RuntimeError("authority observer token is already bound")
        with authenticated_named_pipe_client(pipe) as (
            client_token,
            client_binding,
        ):
            with restricted_provider_identity_token(
                self.provider_account_name,
                self.provider_credential_path,
            ) as restricted_token:
                self._local.client_token = client_token
                self._local.client_binding = client_binding
                self._local.token = restricted_token
                try:
                    yield
                finally:
                    self._local.client_token = None
                    self._local.client_binding = None
                    self._local.token = None

    @contextmanager
    def bind_authenticated_client(self, pipe: int) -> Iterator[None]:
        """Bind only the authenticated caller for client-owned file reads."""
        if getattr(self._local, "client_token", None) is not None:
            raise RuntimeError("authority observer client token is already bound")
        with authenticated_named_pipe_client(pipe) as (
            client_token,
            client_binding,
        ):
            self._local.client_token = client_token
            self._local.client_binding = client_binding
            try:
                yield
            finally:
                self._local.client_token = None
                self._local.client_binding = None

    def qualify(
        self, registration: dict[str, Any], challenge: str
    ) -> QualificationObservation:
        if registration.get("registration_schema_version") in _HOSTED_SUBSCRIPTION_SCHEMAS:
            return self._qualify_codex_subscription(registration, challenge)
        token = self._token()
        transaction = self.provider_root / f"qualification-{uuid.uuid4().hex}"
        transaction.mkdir(parents=True, exist_ok=False)
        executable = Path(str(registration["launcher_path"])).resolve(strict=True)
        configured = Path(
            str(registration["canonical_executable_path"])
        ).resolve(strict=True)
        if registration.get("script_path") is not None:
            command = [
                str(executable),
                "/d",
                "/c",
                str(configured),
                "--version",
            ]
        else:
            command = [str(executable), "--version"]
        environment = filtered_environment(dict(os.environ))
        environment["PATH"] = (
            str(executable.parent)
            + os.pathsep
            + environment.get("PATH", "")
        )
        started_at = _now()
        failure_reason: str | None = None
        try:
            result = run_restricted_process(
                token,
                command,
                executable,
                transaction,
                environment,
                transaction / "stdout.log",
                transaction / "stderr.log",
                15,
            )
            raw = result.stdout.strip()
            exit_status = result.exit_code
            ownership = {
                "pid": result.process_id,
                "launch_nonce": challenge,
                "restricted": result.restricted,
                "integrity_level": result.integrity_level,
                "job_confined": result.job_confined,
                "executable": result.executable,
                "executable_sha256": result.executable_sha256,
            }
            provider_instance_id = f"qualification:{result.process_id}:{challenge[:16]}"
        except (OSError, PermissionError, RuntimeError, ValueError) as error:
            raw = ""
            exit_status = 70
            failure_reason = f"{type(error).__name__}: {error}"
            ownership = {
                "launch_nonce": challenge,
                "restricted": False,
                "integrity_level": "unknown",
                "job_confined": False,
            }
            provider_instance_id = f"qualification-failed:{challenge[:16]}"
        return QualificationObservation(
            provider_instance_id,
            ownership,
            started_at,
            _now(),
            exit_status,
            raw,
            failure_reason,
        )

    def _qualify_codex_subscription(
        self, registration: dict[str, Any], challenge: str
    ) -> QualificationObservation:
        return self._qualify_codex_through_host(registration, challenge)

    def qualification_identifier(
        self, registration: dict[str, Any], planned_identifier: str
    ) -> str:
        gateway = self.provider_host_gateway
        if gateway is None:
            raise PermissionError(
                "Codex qualification requires KeeperProviderHost"
            )
        status = gateway.status()
        providers = _status_provider_bindings(status)
        journal = status.get("launch_journal")
        if (
            status.get("state") != "READY"
            or not isinstance(journal, dict)
            or journal.get("active_or_uncertain_launch_count") != 0
        ):
            raise PermissionError(
                "KeeperProviderHost is not ready and durably clear for qualification"
            )
        provider = next(
            (
                value
                for value in providers
                if isinstance(value, dict)
                and value.get("registration_id")
                == registration.get("trusted_registration_id")
            ),
            None,
        )
        if provider is None:
            return planned_identifier
        return str(provider.get("qualification_id", ""))

    def _qualify_codex_through_host(
        self, registration: dict[str, Any], challenge: str
    ) -> QualificationObservation:
        gateway = self.provider_host_gateway
        if gateway is None:
            raise PermissionError(
                "Codex qualification requires KeeperProviderHost"
            )
        qualification_id = str(registration.get("_qualification_id", ""))
        if not qualification_id:
            raise PermissionError(
                "KeeperProviderHost planned qualification ID is absent"
            )
        started: dict[str, object] = {}
        result = None
        if registration.get("_recovering_qualification") is True:
            result = gateway.terminal_setup_result(
                setup_id=qualification_id,
                operation="QUALIFY",
                provider_registration_id=str(
                    registration["trusted_registration_id"]
                ),
                challenge=challenge,
            )
        if result is None:
            binding = registration.get("windows_authentication_binding")
            if not isinstance(binding, dict):
                raise PermissionError(
                    "Codex qualification Windows binding is unavailable"
                )
            profile = Path(str(binding["profile_identity"]))
            if not profile.is_absolute():
                raise PermissionError(
                    "Codex qualification profile binding is invalid"
                )
            workspace = gateway.setup_workspace(qualification_id)
            preparation_nonce = uuid.uuid4().hex
            provider_bin = _validated_codex_lexical_path(
                Path(str(registration["canonical_executable_path"]))
            ).parent
            environment = (
                gateway.prepare_environment(
                    preparation_nonce,
                    provider_bin,
                    str(registration["trusted_registration_id"]),
                )
                if registration.get("logical_provider_id") == "claude"
                else gateway.prepare_environment(preparation_nonce, provider_bin)
            )
            envelope = gateway.build_setup_envelope(
                operation="QUALIFY",
                registration=registration,
                provider_registration_id=str(
                    registration["trusted_registration_id"]
                ),
                challenge=challenge,
                setup_id=qualification_id,
                workspace=workspace,
                environment_attestation=environment,
            )
            result = gateway.execute_setup(
                envelope,
                on_started=lambda value: started.update(value),
            )
        observation = result.get("observation")
        if not isinstance(observation, dict):
            raise PermissionError(
                "KeeperProviderHost qualification observation is unavailable"
            )
        ownership = observation.get("process_ownership")
        if not isinstance(ownership, dict):
            ownership = dict(started)
        ownership = {
            **ownership,
            "provider_host_setup_envelope_digest": result.get(
                "setup_envelope_digest"
            ),
            "provider_host_setup_result_digest": result.get(
                "setup_result_digest"
            ),
        }
        command = observation.get("production_command")
        if not isinstance(command, list) or not all(
            isinstance(item, str) for item in command
        ):
            command = []
        return QualificationObservation(
            str(observation.get("provider_instance_id", "")),
            ownership,
            str(started.get("creation_time", _now())),
            _now(),
            int(observation.get("exit_status", 70)),
            str(observation.get("raw_version_output", "")),
            (
                str(observation["failure_reason"])
                if observation.get("failure_reason") is not None
                else None
            ),
            cast(
                dict[str, Any] | None,
                observation.get("authentication_probe"),
            ),
            cast(
                dict[str, Any] | None,
                observation.get("usage_observation"),
            ),
            cast(
                dict[str, Any] | None,
                observation.get("structured_output"),
            ),
            tuple(command),
            cast(str | None, observation.get("prompt_digest")),
            cast(str | None, observation.get("schema_digest")),
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
        planned_registration_id: str | None = None,
        planned_setup_id: str | None = None,
        planned_challenge: str | None = None,
        recovering_registration: bool = False,
        expected_account_identity_digest: str | None = None,
        expected_account_plan_type: str | None = None,
    ) -> dict[str, Any]:
        if model_allowlist is not None:
            return self._register_codex_through_host(
                provider_id=provider_id,
                executable=executable,
                client_sid=client_sid,
                executive_capabilities=executive_capabilities,
                project_types=project_types,
                effort_levels=effort_levels,
                pricing_authority=pricing_authority,
                expected_executable_sha256=expected_executable_sha256,
                expected_executable_size=expected_executable_size,
                expected_version=expected_version,
                model_allowlist=model_allowlist,
                model_revalidation_expires_at=model_revalidation_expires_at,
                authentication_policy=authentication_policy,
                usage_policy=usage_policy,
                client_executable_handle=client_executable_handle,
                planned_registration_id=planned_registration_id,
                planned_setup_id=planned_setup_id,
                planned_challenge=planned_challenge,
                recovering_registration=recovering_registration,
                expected_account_identity_digest=(
                    expected_account_identity_digest
                ),
                expected_account_plan_type=expected_account_plan_type,
            )
        with impersonate_token(self._client_token()):
            capabilities: ProviderCapabilities | None = None
            role_eligibility: list[str] | None = None
            if provider_id == "gemini":
                capabilities = ProviderCapabilities(
                    author=False,
                    reviewer=True,
                    repairer=False,
                    structured_output=True,
                    streaming=False,
                    cancellation=True,
                    usage_reporting=False,
                    local_only=False,
                )
                role_eligibility = ["post_repair_reviewer", "reviewer"]
            elif provider_id == "qwen":
                capabilities = ProviderCapabilities(
                    author=False,
                    reviewer=True,
                    repairer=False,
                    structured_output=True,
                    streaming=False,
                    cancellation=True,
                    usage_reporting=False,
                    local_only=True,
                )
                role_eligibility = ["post_repair_reviewer", "reviewer"]
            registration = create_provider_registration(
                provider_id,
                executable,
                authorized_by=client_sid,
                capabilities=capabilities,
                role_eligibility=role_eligibility,
                executive_capabilities=executive_capabilities,
                project_types=project_types,
                effort_levels=effort_levels,
                pricing_authority=pricing_authority,
            )
        self._finalize_client_process_binding(client_sid)
        return registration

    def _register_codex_through_host(
        self,
        *,
        provider_id: str,
        executable: Path,
        client_sid: str,
        executive_capabilities: list[str],
        project_types: list[str],
        effort_levels: list[str],
        pricing_authority: dict[str, Any],
        expected_executable_sha256: str | None,
        expected_executable_size: int | None,
        expected_version: str | None,
        model_allowlist: list[str],
        model_revalidation_expires_at: str | None,
        authentication_policy: dict[str, Any] | None,
        usage_policy: dict[str, Any] | None,
        client_executable_handle: int | None,
        planned_registration_id: str | None = None,
        planned_setup_id: str | None = None,
        planned_challenge: str | None = None,
        recovering_registration: bool = False,
        expected_account_identity_digest: str | None = None,
        expected_account_plan_type: str | None = None,
    ) -> dict[str, Any]:
        gateway = self.provider_host_gateway
        if gateway is None:
            raise PermissionError(
                "Codex subscription registration requires KeeperProviderHost"
            )
        if (
            provider_id not in {"codex", "claude"}
            or client_sid.casefold() != self.authorized_client_sid.casefold()
        ):
            raise PermissionError("Hosted provider registration identity is unauthorized")
        registration_prefix = f"keeper-provider:{provider_id}:v1:"
        if (
            not isinstance(expected_executable_sha256, str)
            or not isinstance(expected_executable_size, int)
            or expected_executable_size <= 0
            or not isinstance(expected_version, str)
            or not expected_version
            or not model_allowlist
            or authentication_policy is None
            or usage_policy is None
            or isinstance(client_executable_handle, bool)
            or not isinstance(client_executable_handle, int)
            or client_executable_handle <= 0
            or not isinstance(planned_registration_id, str)
            or not planned_registration_id.startswith(registration_prefix)
            or len(planned_registration_id)
            != len(registration_prefix) + 32
            or not isinstance(planned_setup_id, str)
            or not planned_setup_id.startswith("provider-registration-probe:")
            or len(planned_setup_id)
            != len("provider-registration-probe:") + 32
            or not isinstance(planned_challenge, str)
            or len(planned_challenge) != 64
        ):
            raise PermissionError("Codex host registration declaration is incomplete")
        client = self._client_process_binding().revalidate(client_sid)
        _, client_profile, client_profile_sid, client_profile_session = (
            self._validated_client_profile(
                self._client_token(),
                self._client_process_binding().profile_token,
                expected_sid=client_sid,
            )
        )
        status = gateway.status()
        user_binding = status.get("user_binding")
        providers = _status_provider_bindings(status)
        if (
            status.get("state") != "READY"
            or not isinstance(status.get("launch_journal"), dict)
            or status["launch_journal"].get("active_or_uncertain_launch_count") != 0
            or not isinstance(user_binding, dict)
            or any(
                isinstance(value, dict)
                and value.get("provider_id") == provider_id
                for value in providers
            )
        ):
            raise PermissionError(
                "KeeperProviderHost is not ready and durably clear for a new registration"
            )
        # The enrolled profile is Founder-owned and may intentionally deny the
        # restricted service identity traversal access.  Canonicalize it on
        # the existing disposable authenticated-client worker; that helper
        # publishes no result until reversion and a clean-thread check pass.
        profile = Path(
            authenticated_client_profile_path(
                self._client_token(),
                str(user_binding.get("profile_path", "")),
            )
        )
        if (
            str(user_binding.get("user_sid", "")).casefold()
            != client.sid.casefold()
            or int(user_binding.get("session_id", -1)) != client.session_id
            or profile != Path(client_profile)
            or client_profile_sid.casefold() != client.sid.casefold()
            or client_profile_session != client.session_id
        ):
            raise PermissionError("KeeperProviderHost enrolled user binding differs")
        client_binding = self._client_process_binding()
        with authenticated_client_transfer_process(
            client_binding, expected_sid=client_sid
        ) as transfer_process:
            with client_binding.duplicate_client_handle(
                client_executable_handle,
                client_sid,
                transfer_process=transfer_process,
            ) as duplicated_handle:
                canonical, measurement = (
                    _measure_duplicated_reviewed_executable(
                        duplicated_handle,
                        executable,
                        expected_executable_sha256,
                        expected_executable_size,
                        provider_id="claude",
                    )
                    if provider_id == "claude"
                    else _measure_duplicated_reviewed_executable(
                        duplicated_handle,
                        executable,
                        expected_executable_sha256,
                        expected_executable_size,
                    )
                )
        registration_id = planned_registration_id
        binding = {
            "principal_sid": client.sid,
            "windows_session_id": client.session_id,
            "profile_identity": str(profile),
            "profile_digest": hashlib.sha256(
                str(profile).casefold().encode("utf-8")
            ).hexdigest(),
            "source": "authenticated-named-pipe-client-process",
        }
        allowed_plans = (
            CODEX_ALLOWED_SUBSCRIPTION_PLANS
            if provider_id == "codex"
            else CLAUDE_ALLOWED_SUBSCRIPTION_PLANS
        )
        if (
            expected_account_plan_type is not None
            and expected_account_plan_type not in allowed_plans
        ):
            raise PermissionError(
                "authorized successor subscription plan is invalid"
            )
        provisional_plan_type = (
            expected_account_plan_type
            if expected_account_plan_type is not None
            else (
                CODEX_REQUIRED_SUBSCRIPTION_PLAN
                if provider_id == "codex"
                else str(pricing_authority.get("subscription_plan", ""))
            )
        )
        provisional = {
            "authenticode_binding": measurement["authenticode_binding"],
            "canonical_executable_path": measurement["canonical_path"],
            "executable_file_identity": measurement["file_identity"],
            "executable_sha256": measurement["sha256"],
            "executable_size": measurement["size"],
            "expected_version": expected_version,
            "logical_provider_id": provider_id,
            "model_allowlist": model_allowlist,
            "subscription_account_binding": {
                "account_identity_digest": (
                    expected_account_identity_digest
                    if expected_account_identity_digest is not None
                    else "DISCOVER"
                ),
                "authentication_method": (
                    "chatgpt-subscription"
                    if provider_id == "codex"
                    else CLAUDE_AUTHENTICATION_MODE
                ),
                "plan_type": provisional_plan_type,
            },
            "usage_policy": usage_policy,
            "windows_authentication_binding": binding,
        }
        setup_id = planned_setup_id
        result = None
        if recovering_registration:
            result = gateway.terminal_setup_result(
                setup_id=setup_id,
                operation="REGISTER_PROBE",
                provider_registration_id=registration_id,
                challenge=planned_challenge,
            )
        if result is None:
            workspace = gateway.setup_workspace(setup_id)
            preparation_nonce = uuid.uuid4().hex
            environment = (
                gateway.prepare_environment(
                    preparation_nonce, canonical.parent, registration_id
                )
                if provider_id == "claude"
                else gateway.prepare_environment(
                    preparation_nonce, canonical.parent
                )
            )
            envelope = gateway.build_setup_envelope(
                operation="REGISTER_PROBE",
                registration=provisional,
                provider_registration_id=registration_id,
                challenge=planned_challenge,
                setup_id=setup_id,
                workspace=workspace,
                environment_attestation=environment,
            )
            result = gateway.execute_setup(
                envelope, on_started=lambda value: None
            )
        observation = result.get("observation")
        if not isinstance(observation, dict) or observation.get("exit_status") != 0:
            return {
                "registration_terminal_failure": (
                    _provider_registration_terminal_failure(result, observation)
                )
            }
        public_probe = observation.get("authentication_probe")
        if not isinstance(public_probe, dict):
            raise PermissionError("KeeperProviderHost account probe is unavailable")
        observed_account = {
            "authentication_method": public_probe.get("authentication_method"),
            "plan_type": public_probe.get("plan_type"),
            "account_identity_digest": public_probe.get(
                "account_identity_digest"
            ),
            "source": "authority-verified-provider-host-probe",
            "observed_at": _now(),
        }
        account_digest = str(
            observed_account["account_identity_digest"]
        )
        if len(account_digest) != 64 or any(
            character not in "0123456789abcdef"
            for character in account_digest
        ):
            raise PermissionError(
                "KeeperProviderHost account identity digest is invalid"
            )
        if (
            expected_account_identity_digest is not None
            and account_digest != expected_account_identity_digest
        ):
            raise PermissionError(
                "KeeperProviderHost account identity differs from the authorized successor"
            )
        model_binding = {
            "models": public_probe.get("model_capabilities"),
            "source": "authority-verified-provider-host-probe",
            "observed_at": _now(),
        }
        registration = create_provider_registration(
            provider_id,
            canonical,
            authorized_by=client_sid,
            executive_capabilities=executive_capabilities,
            project_types=project_types,
            effort_levels=effort_levels,
            pricing_authority=pricing_authority,
            expected_version=expected_version,
            model_allowlist=model_allowlist,
            model_revalidation_expires_at=model_revalidation_expires_at,
            authentication_policy=authentication_policy,
            windows_authentication_binding=binding,
            usage_policy=usage_policy,
            authenticode_binding=cast(dict[str, Any], measurement["authenticode_binding"]),
            subscription_account_binding=observed_account,
            model_capability_binding=model_binding,
            authority_executable_measurement=measurement,
            trusted_registration_id=registration_id,
        )
        self._finalize_client_process_binding(client_sid)
        return registration

    def execute_provider(
        self,
        registration: dict[str, Any],
        attempt: dict[str, Any],
        on_started: Callable[[ProcessObservation], None],
    ) -> ExecutionObservation:
        token = self._token()
        attempt_id = str(attempt["id"])
        cancellation = threading.Event()
        prompt_path = self._exchange_path(attempt["prompt_path"], "prompt")
        stdout_path = self._exchange_path(attempt["stdout_path"], "stdout")
        stderr_path = self._exchange_path(attempt["stderr_path"], "stderr")
        workspace = self._exchange_path(attempt["workspace"], "workspace")
        executable = Path(str(registration["launcher_path"]))
        if registration.get("registration_schema_version") not in _HOSTED_SUBSCRIPTION_SCHEMAS:
            executable = executable.resolve(strict=True)
            launcher_content = executable.read_bytes()
            if (
                hashlib.sha256(launcher_content).hexdigest()
                != registration["launcher_sha256"]
                or len(launcher_content) != registration["launcher_size"]
            ):
                raise PermissionError(
                    "registered provider launcher identity changed"
                )
        provider_id = str(registration["logical_provider_id"])
        if registration.get("registration_schema_version") in _HOSTED_SUBSCRIPTION_SCHEMAS:
            prompt = attempt.get("authority_prompt")
            if (
                not isinstance(prompt, str)
                or hashlib.sha256(prompt.encode("utf-8")).hexdigest()
                != attempt.get("prompt_digest")
            ):
                raise PermissionError("Authority-owned Codex prompt is invalid")
        else:
            prompt = prompt_path.read_text(encoding="utf-8")
        provider_input = attempt.get("provider_input")
        provider_input_digest = attempt.get("provider_input_digest")
        if provider_input is not None:
            if not isinstance(provider_input_digest, str):
                raise PermissionError(
                    "Authority-bound provider input digest is unavailable"
                )
            prompt = (
                prompt
                + "\n\nKEEPER TRUSTED REVIEW INPUT (server-owned; echo the "
                "required_review_input_binding exactly in structured review "
                "output and bind the same top-level review disposition):\n"
                + provider_prompt_context(
                    provider_input,
                    provider_input_digest=provider_input_digest,
                )
            )
        role = str(attempt["role"])
        schema_role = {
            "executive_reviewer": "reviewer",
            "executive_post_repair_reviewer": "post_repair_reviewer",
        }.get(role.casefold(), role)

        def provider_output_schema() -> dict[str, Any]:
            return authority_provider_output_schema(
                schema_role,
                provider_input_required=(
                    provider_input is not None
                    and attempt.get("provider_input_required") is True
                ),
            )
        base_command = (
            [
                str(executable),
                "/d",
                "/c",
                str(registration["script_path"]),
            ]
            if registration.get("script_path") is not None
            else [str(executable)]
        )
        if provider_id == "codex":
            schema_path = stdout_path.parent / "provider-output-schema.json"
            output_schema = provider_output_schema()
            if (
                registration.get("registration_schema_version") in _HOSTED_SUBSCRIPTION_SCHEMAS
                and structured_digest(output_schema)
                != attempt.get("output_schema_digest")
            ):
                raise PermissionError(
                    "Authority-owned Codex output schema is invalid"
                )
            schema_path.write_text(
                json.dumps(output_schema),
                encoding="utf-8",
            )
            if registration.get("registration_schema_version") in _HOSTED_SUBSCRIPTION_SCHEMAS:
                model_id = str(attempt.get("model_id", ""))
                allowlist = registration.get("model_allowlist")
                reasoning_level = str(attempt.get("reasoning_level", ""))
                if (
                    not isinstance(allowlist, list)
                    or model_id not in allowlist
                    or reasoning_level not in registration.get(
                        "effort_levels", []
                    )
                ):
                    raise PermissionError(
                        "Codex model or effort differs from registration"
                    )
                command = build_codex_exec_command(
                    Path(str(registration["canonical_executable_path"])),
                    model_id=model_id,
                    reasoning_level=reasoning_level,
                    schema_path=schema_path,
                    output_path=stdout_path,
                    prompt=prompt,
                )
            else:
                command = [
                    *base_command,
                    "exec",
                    "--ephemeral",
                    "--sandbox",
                    "workspace-write",
                    "--output-schema",
                    str(schema_path),
                    prompt,
                ]
        elif provider_id == "claude":
            output_schema = provider_output_schema()
            if (
                registration.get("registration_schema_version") == 5
                and structured_digest(output_schema)
                != attempt.get("output_schema_digest")
            ):
                raise PermissionError(
                    "Authority-owned Claude output schema is invalid"
                )
            if registration.get("registration_schema_version") == 5:
                model_id = str(attempt.get("model_id", ""))
                reasoning_level = str(attempt.get("reasoning_level", ""))
                if (
                    model_id != CLAUDE_PINNED_REVIEW_MODEL
                    or registration.get("model_allowlist") != [model_id]
                    or reasoning_level not in registration.get("effort_levels", [])
                ):
                    raise PermissionError(
                        "Claude model or effort differs from registration"
                    )
                command = build_claude_exec_command(
                    Path(str(registration["canonical_executable_path"])),
                    model_id=model_id,
                    reasoning_level=reasoning_level,
                    schema=output_schema,
                    prompt=prompt,
                )
            else:
                command = [
                    *base_command,
                    "--output-format",
                    "json",
                    "--json-schema",
                    json.dumps(output_schema, separators=(",", ":")),
                    "-p",
                    prompt,
                ]
        elif provider_id == "gemini":
            output_schema = provider_output_schema()
            governed_prompt = (
                "Return only one JSON object that validates against this JSON Schema: "
                + json.dumps(output_schema, separators=(",", ":"))
                + "\n\nTask:\n"
                + prompt
            )
            command = [
                *base_command,
                "--sandbox",
                "--approval-mode=plan",
                "--model",
                "gemini-2.5-pro",
                "--output-format",
                "json",
                "--prompt",
                governed_prompt,
            ]
        elif provider_id == "qwen":
            output_schema = provider_output_schema()
            governed_prompt = (
                "Return only one JSON object that validates against this JSON Schema: "
                + json.dumps(output_schema, separators=(",", ":"))
                + "\n\nTask:\n"
                + prompt
            )
            command = [
                *base_command,
                "run",
                "qwen3-coder:30b",
                governed_prompt,
            ]
        else:
            raise PermissionError("provider execution adapter is unsupported")
        process_stdout_path = (
            stdout_path.with_suffix(".envelope.json")
            if provider_id in {"claude", "gemini"}
            else (
                stdout_path.with_suffix(".events.jsonl")
                if registration.get("registration_schema_version")
                in _HOSTED_SUBSCRIPTION_SCHEMAS
                else stdout_path
            )
        )
        environment = attempt.get("environment")
        if not isinstance(environment, dict):
            raise PermissionError("provider environment is unavailable")
        safe_environment = {
            str(key): str(value) for key, value in environment.items()
        }

        def started(value: dict[str, object]) -> None:
            on_started(
                ProcessObservation(
                    cast(int, value["pid"]),
                    str(value["creation_time"]),
                    str(value["executable"]),
                    str(value["executable_sha256"]),
                    value["restricted"] is True,
                    str(value["integrity_level"]),
                    value["job_confined"] is True,
                )
            )

        if registration.get("registration_schema_version") in _HOSTED_SUBSCRIPTION_SCHEMAS:
            gateway = self.provider_host_gateway
            if gateway is None:
                raise PermissionError(
                    "Codex production execution requires KeeperProviderHost"
                )
            preparation_nonce = uuid.uuid4().hex
            provider_bin = _validated_codex_lexical_path(
                Path(str(registration["canonical_executable_path"]))
            ).parent
            environment_record = (
                gateway.prepare_environment(
                    preparation_nonce,
                    provider_bin,
                    str(registration["trusted_registration_id"]),
                )
                if provider_id == "claude"
                else gateway.prepare_environment(preparation_nonce, provider_bin)
            )
            envelope = gateway.build_launch_envelope(
                registration=registration,
                attempt=attempt,
                argv=command[1:],
                environment_attestation=environment_record,
            )
            with self._active_lock:
                if attempt_id in self._active_host_launches:
                    raise PermissionError("provider attempt is already executing")
                self._active_host_launches[attempt_id] = str(
                    envelope["launch_id"]
                )
            try:
                host_result = gateway.execute(envelope, on_started=started)
            finally:
                with self._active_lock:
                    self._active_host_launches.pop(attempt_id, None)
            completion = host_result.get("completion")
            signed_completion = host_result.get("signed_completion")
            if not isinstance(completion, dict) or not isinstance(
                signed_completion, dict
            ):
                raise PermissionError("Provider Host completion is invalid")
            provider_output = completion.get("provider_output")
            if not isinstance(provider_output, dict):
                raise PermissionError("Provider Host process result is invalid")
            exit_status = int(provider_output.get("exit_code", 1))
            timed_out = provider_output.get("timed_out") is True
            if provider_id == "claude":
                output_value = provider_output.get("structured_output")
                output_valid = validate_value_against_schema(
                    output_value, output_schema
                )
                if output_valid:
                    stdout_path.write_text(
                        json.dumps(output_value, sort_keys=True),
                        encoding="utf-8",
                    )
                else:
                    stdout_path.write_text("", encoding="utf-8")
                if not stderr_path.exists():
                    stderr_path.write_text("", encoding="utf-8")
                host_failure_classification = (
                    "COMPLETED"
                    if exit_status == 0
                    and not timed_out
                    and completion.get("state") == "COMPLETED"
                    and output_valid
                    else "FAILED"
                )
            else:
                output_valid = False
                try:
                    output_value = json.loads(
                        stdout_path.read_text(encoding="utf-8")
                    )
                    output_valid = validate_value_against_schema(
                        output_value, output_schema
                    )
                except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                    output_valid = False
                event_text = _bounded_text(process_stdout_path)
                error_text = _bounded_text(stderr_path)
                host_failure_classification = classify_codex_execution_failure(
                    exit_status=exit_status,
                    timed_out=timed_out,
                    cancelled=completion.get("state") == "CANCELLED",
                    stderr=error_text,
                    structured_events=event_text,
                    output_valid=output_valid,
                )
            if host_failure_classification != "COMPLETED" and exit_status == 0:
                exit_status = 65
            return ExecutionObservation(
                int(provider_output.get("pid", 0)),
                exit_status,
                timed_out,
                str(stdout_path),
                str(stderr_path),
                _execution_evidence_digest(stdout_path, stderr_path),
                str(completion["recorded_at"]),
                (
                    dict(attempt["usage_observation"])
                    if isinstance(attempt.get("usage_observation"), dict)
                    else None
                ),
                str(attempt.get("model_id")),
                str(attempt.get("reasoning_level")),
                structured_digest(command),
                hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                structured_digest(output_schema),
                hashlib.sha256(
                    process_stdout_path.read_bytes()
                    if process_stdout_path.exists()
                    else b""
                ).hexdigest(),
                host_failure_classification,
                structured_digest(envelope),
                structured_digest(signed_completion),
            )

        # Claim only after every service-owned preparation check succeeds.  The
        # lock remains the one-winner external-launch boundary; pre-launch
        # validation failures therefore cannot strand an active claim.
        with self._active_lock:
            if attempt_id in self._active_cancellations:
                raise PermissionError("provider attempt is already executing")
            if attempt_id in self._cancelled_attempts:
                cancellation.set()
            self._active_cancellations[attempt_id] = cancellation
        try:
            if registration.get("registration_schema_version") in _HOSTED_SUBSCRIPTION_SCHEMAS:
                with self._codex_execution_identity(registration) as (
                    codex_token,
                    codex_environment,
                    executable_measurement,
                ):
                    result = run_restricted_process(
                        codex_token,
                        command,
                        executable,
                        workspace,
                        codex_environment,
                        process_stdout_path,
                        stderr_path,
                        float(attempt["timeout_seconds"]),
                        started,
                        cancellation,
                        integrity_level="medium",
                        validated_executable_identity=executable_measurement,
                    )
            else:
                result = run_restricted_process(
                    token,
                    command,
                    executable,
                    workspace,
                    safe_environment,
                    process_stdout_path,
                    stderr_path,
                    float(attempt["timeout_seconds"]),
                    started,
                    cancellation,
                )
        finally:
            with self._active_lock:
                self._active_cancellations.pop(attempt_id, None)
                self._cancelled_attempts.discard(attempt_id)
        exit_status = result.exit_code
        failure_classification: str | None = None
        if registration.get("registration_schema_version") in _HOSTED_SUBSCRIPTION_SCHEMAS:
            output_valid = False
            try:
                output_value = json.loads(stdout_path.read_text(encoding="utf-8"))
                output_valid = validate_value_against_schema(
                    output_value, output_schema
                )
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                output_valid = False
            event_text = _bounded_text(process_stdout_path)
            error_text = _bounded_text(stderr_path)
            failure_classification = classify_codex_execution_failure(
                exit_status=exit_status,
                timed_out=result.timed_out,
                cancelled=cancellation.is_set(),
                stderr=error_text,
                structured_events=event_text,
                output_valid=output_valid,
            )
            if failure_classification != "COMPLETED" and exit_status == 0:
                exit_status = 65
        if provider_id in {"claude", "gemini"} and exit_status == 0:
            try:
                envelope = json.loads(
                    process_stdout_path.read_text(encoding="utf-8")
                )
                domain = (
                    envelope.get("response")
                    if provider_id == "gemini"
                    else envelope.get("structured_output", envelope.get("result"))
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
        if provider_id == "qwen" and exit_status == 0:
            try:
                domain = json.loads(stdout_path.read_text(encoding="utf-8"))
                if not isinstance(domain, dict) or not validate_value_against_schema(
                    domain, provider_output_schema()
                ):
                    raise ValueError("Qwen response does not match the output schema")
            except (json.JSONDecodeError, OSError, ValueError) as error:
                stdout_path.write_text("", encoding="utf-8")
                stderr_path.write_text(
                    f"invalid Qwen structured result: {error}", encoding="utf-8"
                )
                exit_status = 65
        return ExecutionObservation(
            result.process_id,
            exit_status,
            result.timed_out,
            str(stdout_path),
            str(stderr_path),
            _execution_evidence_digest(stdout_path, stderr_path),
            _now(),
            (
                dict(attempt["usage_observation"])
                if isinstance(attempt.get("usage_observation"), dict)
                else None
            ),
            str(attempt.get("model_id"))
            if attempt.get("model_id") is not None
            else None,
            str(attempt.get("reasoning_level"))
            if attempt.get("reasoning_level") is not None
            else None,
            structured_digest(command),
            hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            (
                structured_digest(output_schema)
                if provider_id == "codex"
                else structured_digest(provider_output_schema())
            ),
            (
                hashlib.sha256(process_stdout_path.read_bytes()).hexdigest()
                if process_stdout_path.exists()
                else hashlib.sha256(b"").hexdigest()
            ),
            failure_classification,
        )

    def preflight_provider(
        self, registration: dict[str, Any], attempt: dict[str, Any]
    ) -> dict[str, Any] | None:
        del attempt
        if registration.get("registration_schema_version") not in _HOSTED_SUBSCRIPTION_SCHEMAS:
            return None
        gateway = self.provider_host_gateway
        if gateway is None:
            raise PermissionError(
                "Codex production preflight requires KeeperProviderHost"
            )
        host_status = gateway.status()
        journal = host_status.get("launch_journal")
        if (
            host_status.get("state") != "READY"
            or not isinstance(journal, dict)
            or journal.get("active_or_uncertain_launch_count") != 0
        ):
            raise PermissionError(
                "KeeperProviderHost is not ready and durably clear"
            )
        account = registration.get("subscription_account_binding")
        models = registration.get("model_capability_binding")
        if not isinstance(account, dict) or not isinstance(models, dict):
            raise PermissionError("Codex qualified binding is unavailable")
        return {
            "authentication_method": account.get("authentication_method"),
            "plan_type": account.get("plan_type"),
            "account_identity_digest": account.get(
                "account_identity_digest"
            ),
            "model_capabilities": models.get("models"),
            "model_allowlist": registration.get("model_allowlist"),
            "observed_at": _now(),
            "source": "keeper-provider-host-qualified-binding",
        }
    @staticmethod
    def _validate_codex_public_binding(
        registration: dict[str, Any], probe: dict[str, Any]
    ) -> None:
        account_binding = registration.get("subscription_account_binding")
        model_binding = registration.get("model_capability_binding")
        if (
            not isinstance(account_binding, dict)
            or probe.get("authentication_method")
            != account_binding.get("authentication_method")
            or probe.get("plan_type") != account_binding.get("plan_type")
            or probe.get("account_identity_digest")
            != account_binding.get("account_identity_digest")
            or not isinstance(model_binding, dict)
            or probe.get("model_capabilities") != model_binding.get("models")
            or probe.get("models") != registration.get("model_allowlist")
        ):
            raise PermissionError(
                "Codex subscription account or model capability changed"
            )

    def cancel_provider(self, attempt_id: str) -> None:
        with self._active_lock:
            self._cancelled_attempts.add(attempt_id)
            cancellation = self._active_cancellations.get(attempt_id)
            if cancellation is not None:
                cancellation.set()
            host_launch_id = self._active_host_launches.get(attempt_id)
        if host_launch_id is not None:
            gateway = self.provider_host_gateway
            if gateway is None or not gateway.cancel(
                attempt_id, host_launch_id
            ):
                raise PermissionError(
                    "Provider Host cancellation was not acknowledged"
                )

    def observe_process(
        self, attempt: dict[str, Any], pid: int
    ) -> ProcessObservation:
        image = process_image(pid)
        content = image.read_bytes()
        # Desktop-owned processes are deliberately not promoted to trusted
        # restricted execution. Production attempts must be broker-launched.
        raise PermissionError(
            "desktop-owned provider processes are not service-authoritative; "
            f"observed image {image} ({hashlib.sha256(content).hexdigest()[:16]})"
        )

    def observe_completion(
        self, attempt: dict[str, Any]
    ) -> CompletionObservation:
        path = Path(str(attempt["evidence_path"])).resolve(strict=True)
        if not path.is_relative_to(self.allowed_evidence_root):
            raise PermissionError("provider evidence path is outside the configured root")
        content = path.read_bytes()
        try:
            value = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PermissionError("provider evidence is malformed") from error
        if not isinstance(value, dict):
            raise PermissionError("provider evidence is malformed")
        exit_status = value.get("process_exit_code")
        result = value.get("status")
        if (
            isinstance(exit_status, bool)
            or not isinstance(exit_status, int)
            or result not in {"completed", "failed"}
        ):
            raise PermissionError("provider completion fields are malformed")
        return CompletionObservation(
            hashlib.sha256(content).hexdigest(),
            exit_status,
            str(result),
            _now(),
        )

    def _token(self) -> int:
        value = getattr(self._local, "token", None)
        if not isinstance(value, int) or value <= 0:
            raise PermissionError("authority client restricted token is unavailable")
        return value

    def _client_token(self) -> int:
        value = getattr(self._local, "client_token", None)
        if not isinstance(value, int) or value <= 0:
            raise PermissionError(
                "authority authenticated client token is unavailable"
            )
        return value

    def _client_process_binding(self) -> NamedPipeClientProcessBinding:
        value = getattr(self._local, "client_binding", None)
        if not isinstance(value, NamedPipeClientProcessBinding):
            raise PermissionError(
                "authority authenticated client process is unavailable"
            )
        return value

    def _finalize_client_process_binding(self, expected_sid: str) -> None:
        binding = self._client_process_binding()
        binding.revalidate(expected_sid)
        binding.release()

    def _validated_client_profile(
        self,
        client_token: int,
        profile_token: int,
        *,
        expected_sid: str,
        expected_binding: dict[str, Any] | None = None,
    ) -> tuple[dict[str, str], str, str, int]:
        require_impersonation_level(client_token)
        client_sid = token_user_sid_string(client_token)
        process_binding = self._client_process_binding()
        process_identity = process_binding.revalidate(expected_sid)
        client_session = process_identity.session_id
        if (
            client_sid.casefold() != expected_sid.casefold()
            or client_sid.casefold() != self.authorized_client_sid.casefold()
            or process_identity.sid.casefold() != client_sid.casefold()
        ):
            raise PermissionError("Codex authenticated Windows SID is mismatched")
        observed_sid = token_user_sid_string(profile_token)
        observed_session = token_session_id(profile_token)
        if (
            observed_sid.casefold() != client_sid.casefold()
            or observed_session != client_session
        ):
            raise PermissionError(
                "Codex profile token differs from authenticated client"
            )
        if expected_binding is not None and (
            observed_sid.casefold()
            != str(expected_binding.get("principal_sid", "")).casefold()
            or observed_session != expected_binding.get("windows_session_id")
        ):
            raise PermissionError("Codex authenticated Windows identity changed")
        process_binding.revalidate(expected_sid)
        service_session_state = windows_session_is_active(client_session)
        session_state = service_session_state
        if (
            service_session_state.status
            is WindowsSessionQueryStatus.QUERY_FAILED
            and service_session_state.win32_error == 5
        ):
            session_state = authenticated_client_windows_session_state(
                process_binding.pipe, client_session
            )
        process_binding.revalidate(expected_sid)
        if session_state.status is WindowsSessionQueryStatus.INACTIVE:
            raise PermissionError(
                "Codex authenticated Windows session is not active "
                f"(wts_state={session_state.state})"
            )
        if session_state.status is WindowsSessionQueryStatus.QUERY_FAILED:
            raise PermissionError(
                "Codex authenticated Windows session query failed "
                f"(win32_error={session_state.win32_error})"
            )
        # CreateEnvironmentBlock explicitly supports an impersonation token
        # with TOKEN_QUERY access.  Use the exact authenticated pipe token;
        # the primary duplicate remains limited to profile-restricted process
        # derivation and is not used for this read-only profile lookup.
        environment = authenticated_client_environment(client_token)
        profile = environment.get("USERPROFILE")
        if not isinstance(profile, str) or not profile:
            raise PermissionError("Codex authenticated user profile is unavailable")
        canonical_profile = authenticated_client_profile_path(client_token, profile)
        profile_digest = hashlib.sha256(
            canonical_profile.casefold().encode("utf-8")
        ).hexdigest()
        if expected_binding is not None and (
            canonical_profile.casefold()
            != str(expected_binding.get("profile_identity", "")).casefold()
            or profile_digest != expected_binding.get("profile_digest")
        ):
            raise PermissionError("Codex authenticated Windows identity changed")
        process_binding.revalidate(expected_sid)
        return environment, canonical_profile, observed_sid, observed_session

    def _measure_reviewed_codex_executable(
        self,
        client_token: int,
        executable: Path,
        expected_sha256: str | None,
        expected_size: int | None,
    ) -> tuple[Path, dict[str, Any]]:
        canonical, measurement, descriptor = (
            self._open_reviewed_codex_executable_on_authenticated_worker(
                client_token,
                executable,
                expected_sha256,
                expected_size,
            )
        )
        os.close(descriptor)
        return canonical, measurement

    @staticmethod
    def _open_reviewed_codex_executable_on_authenticated_worker(
        client_token: int,
        executable: Path,
        expected_sha256: str | None,
        expected_size: int | None,
    ) -> tuple[Path, dict[str, Any], int]:
        """Measure one user-owned executable on a disposable client worker.

        The service request thread never impersonates.  The worker publishes
        the locked descriptor and measurement only after client-token
        reversion and an explicit clean-thread check both succeed.
        """
        restricted_process_runtime._assert_thread_not_impersonating()
        completed = threading.Event()
        outcome: list[tuple[Path, dict[str, Any], int] | BaseException] = []

        def worker() -> None:
            descriptor = -1
            try:
                restricted_process_runtime._assert_thread_not_impersonating()
                with impersonate_token(client_token):
                    canonical, measurement, descriptor = (
                        _open_validated_reviewed_codex_executable(
                            executable,
                            expected_sha256,
                            expected_size,
                        )
                    )
                restricted_process_runtime._assert_thread_not_impersonating()
                outcome.append((canonical, measurement, descriptor))
                descriptor = -1
            except BaseException as error:
                if descriptor >= 0:
                    os.close(descriptor)
                outcome.append(error)
            finally:
                completed.set()

        validation_thread = threading.Thread(
            target=worker,
            name="KeeperAuthenticatedClientExecutableMeasurement",
            daemon=True,
        )
        validation_thread.start()
        completed.wait()
        validation_thread.join()
        try:
            restricted_process_runtime._assert_thread_not_impersonating()
        except BaseException:
            if outcome and not isinstance(outcome[0], BaseException):
                os.close(outcome[0][2])
            raise
        if not outcome:
            raise PermissionError(
                "authenticated-client executable measurement produced no outcome"
            )
        first = outcome[0]
        if isinstance(first, BaseException):
            raise first
        return first

    @contextmanager
    def _hold_reviewed_codex_executable(
        self,
        client_token: int,
        executable: Path,
        expected_sha256: str | None,
        expected_size: int | None,
    ) -> Iterator[tuple[Path, dict[str, Any]]]:
        descriptor = -1
        try:
            canonical, measurement, descriptor = (
                self._open_reviewed_codex_executable_on_authenticated_worker(
                    client_token,
                    executable,
                    expected_sha256,
                    expected_size,
                )
            )
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        try:
            yield canonical, measurement
        finally:
            os.close(descriptor)

    @staticmethod
    def _assert_registered_executable_measurement(
        registration: dict[str, Any], measurement: dict[str, Any]
    ) -> None:
        if (
            os.path.normcase(str(measurement.get("canonical_path", "")))
            != os.path.normcase(
                str(registration.get("canonical_executable_path", ""))
            )
            or measurement.get("sha256")
            != registration.get("executable_sha256")
            or measurement.get("size") != registration.get("executable_size")
            or measurement.get("file_identity")
            != registration.get("executable_file_identity")
            or measurement.get("authenticode_binding")
            != registration.get("authenticode_binding")
        ):
            raise PermissionError("Codex executable identity changed")

    def validate_registered_executable(
        self, registration: dict[str, Any], client_executable_handle: int
    ) -> None:
        if registration.get("registration_schema_version") not in _HOSTED_SUBSCRIPTION_SCHEMAS:
            return
        binding = registration.get("windows_authentication_binding")
        if not isinstance(binding, dict):
            raise PermissionError(
                "Codex Windows authentication binding is unavailable"
            )
        client_token = self._client_token()
        client_binding = self._client_process_binding()
        client_binding.revalidate(str(binding.get("principal_sid", "")))
        with authenticated_profile_primary_token(
            client_binding.profile_token
        ) as profile_token:
            self._validated_client_profile(
                client_token,
                profile_token,
                expected_sid=str(binding.get("principal_sid", "")),
                expected_binding=binding,
            )
            expected_sid = str(binding.get("principal_sid", ""))
            with authenticated_client_transfer_process(
                client_binding, expected_sid=expected_sid
            ) as transfer_process:
                with client_binding.duplicate_client_handle(
                    client_executable_handle,
                    expected_sid,
                    transfer_process=transfer_process,
                ) as duplicated_handle:
                    measurement_args = (
                        duplicated_handle,
                        Path(
                            str(
                                registration.get(
                                    "canonical_executable_path", ""
                                )
                            )
                        ),
                        str(registration.get("executable_sha256", "")),
                        registration.get("executable_size"),
                    )
                    _, measurement = (
                        _measure_duplicated_reviewed_executable(
                            *measurement_args, provider_id="claude"
                        )
                        if registration.get("logical_provider_id") == "claude"
                        else _measure_duplicated_reviewed_executable(
                            *measurement_args
                        )
                    )
        self._assert_registered_executable_measurement(
            registration, measurement
        )

    def recover_provider_registration_failure(
        self,
        registration_id: str,
        setup_id: str,
        challenge: str,
    ) -> dict[str, Any]:
        """Recover only an already-terminal Host result; never launch setup."""

        gateway = self.provider_host_gateway
        if gateway is None:
            raise PermissionError(
                "Provider registration failure recovery requires KeeperProviderHost"
            )
        status = gateway.status()
        journal = status.get("launch_journal")
        if (
            status.get("state") != "READY"
            or any(
                value.get("registration_id") == registration_id
                for value in _status_provider_bindings(status)
            )
            or not isinstance(journal, dict)
            or journal.get("active_or_uncertain_launch_count") != 0
        ):
            raise PermissionError(
                "KeeperProviderHost is not durably clear for registration recovery"
            )
        result = gateway.terminal_setup_result(
            setup_id=setup_id,
            operation="REGISTER_PROBE",
            provider_registration_id=registration_id,
            challenge=challenge,
        )
        if result is None:
            raise PermissionError(
                "Provider registration terminal result is unavailable"
            )
        observation = result.get("observation")
        if not isinstance(observation, dict) or observation.get("exit_status") == 0:
            raise PermissionError(
                "Provider registration terminal result is not a failure"
            )
        return _provider_registration_terminal_failure(result, observation)

    @contextmanager
    def _codex_execution_identity(
        self, registration: dict[str, Any]
    ) -> Iterator[tuple[int, dict[str, str], dict[str, Any]]]:
        binding = registration.get("windows_authentication_binding")
        if not isinstance(binding, dict):
            raise PermissionError(
                "Codex Windows authentication binding is unavailable"
            )
        client_token = self._client_token()
        client_binding = self._client_process_binding()
        client_binding.revalidate(str(binding.get("principal_sid", "")))
        with authenticated_profile_primary_token(
            client_binding.profile_token
        ) as profile_token:
            environment, canonical_profile, _, _ = self._validated_client_profile(
                client_token,
                profile_token,
                expected_sid=str(binding.get("principal_sid", "")),
                expected_binding=binding,
            )
            with self._hold_reviewed_codex_executable(
                client_token,
                Path(str(registration.get("canonical_executable_path", ""))),
                str(registration.get("executable_sha256", "")),
                registration.get("executable_size"),
            ) as (_, measurement):
                self._assert_registered_executable_measurement(
                    registration, measurement
                )
                codex_home = Path(canonical_profile) / ".codex"
                safe_environment = sanitized_codex_environment(
                    environment, codex_home=codex_home
                )
                with profile_restricted_primary_token(profile_token) as restricted:
                    yield restricted, safe_environment, measurement

    @staticmethod
    def _codex_probe_command(
        executable: Path, model_allowlist: list[str]
    ) -> list[str]:
        runtime = str(Path(sys.executable).resolve(strict=True))
        entry = Path(sys.argv[0]).resolve()
        if entry.suffix.casefold() == ".pyz" and entry.is_file():
            command = [runtime, str(entry), "codex-probe"]
        else:
            command = [
                runtime,
                "-m",
                "keeper.authority_service.codex_probe",
            ]
        # The reviewed user-profile executable was already canonically measured
        # under the authenticated client token.  Do not make the service identity
        # traverse that path while assembling the service-owned probe command.
        command.extend(("--executable", str(executable)))
        for model in model_allowlist:
            command.extend(("--model", model))
        return command

    def read_exchange_file(
        self, value: object, label: str, maximum_bytes: int
    ) -> tuple[Path, bytes]:
        # The exchange tree is client-writable. Perform validation, open, and
        # read while impersonating that authenticated pipe client so a retarget
        # race can never turn this operation into a service-identity file read
        # or service-credential network authentication.
        with impersonate_token(self._client_token()):
            path = self._exchange_path(value, label, must_exist=True)
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                current = path.stat()
                if (opened.st_dev, opened.st_ino) != (
                    current.st_dev,
                    current.st_ino,
                ):
                    raise PermissionError(
                        f"provider {label} path changed during secure open"
                    )
                if opened.st_size > maximum_bytes:
                    raise PermissionError(
                        f"Authority provider {label} is too large"
                    )
                chunks: list[bytes] = []
                remaining = maximum_bytes + 1
                while remaining:
                    chunk = os.read(descriptor, min(65_536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                content = b"".join(chunks)
                if len(content) > maximum_bytes:
                    raise PermissionError(
                        f"Authority provider {label} is too large"
                    )
                final_path = self._exchange_path(
                    path, label, must_exist=True
                )
                final = final_path.stat()
                if (
                    final_path != path
                    or (opened.st_dev, opened.st_ino)
                    != (final.st_dev, final.st_ino)
                ):
                    raise PermissionError(
                        f"provider {label} path changed during secure read"
                    )
                return final_path, content
            finally:
                os.close(descriptor)

    def _exchange_path(
        self, value: object, label: str, *, must_exist: bool = False
    ) -> Path:
        raw_text = str(value)
        if (
            not raw_text
            or raw_text.startswith("\\\\")
            or raw_text.startswith("\\\\?\\")
            or raw_text.startswith("\\\\.\\")
        ):
            raise PermissionError(f"provider {label} path is not a local path")
        raw = Path(raw_text)
        if not raw.is_absolute():
            raise PermissionError(f"provider {label} path is not absolute")
        exchange_root = self.allowed_evidence_root.parent.resolve(strict=True)
        lexical = Path(os.path.abspath(raw))
        if not lexical.is_relative_to(exchange_root):
            raise PermissionError(
                f"provider {label} path is outside the client exchange"
            )
        current = exchange_root
        for component in lexical.relative_to(exchange_root).parts:
            current /= component
            if not current.exists():
                break
            item_stat = current.lstat()
            is_reparse = bool(
                getattr(item_stat, "st_file_attributes", 0)
                & getattr(os, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            )
            if current.is_symlink() or is_reparse:
                raise PermissionError(
                    f"provider {label} path contains an alias"
                )
        path = lexical.resolve(strict=must_exist)
        if not path.is_relative_to(exchange_root):
            raise PermissionError(
                f"provider {label} path is outside the client exchange"
            )
        return path


def _authority_provider_host_path_observation(
    *,
    client_process_binding: NamedPipeClientProcessBinding,
    expected_sid: str,
    profile: str,
    installation: Mapping[str, Any],
    observed_sid: str,
) -> dict[str, Any]:
    """Measure one authenticated user's Host tree on a disposable worker.

    The caller has already authenticated and retained the exact pipe-client
    SID, process, session, and profile binding. The fixed worker derives the
    Host root only from that canonical profile, verifies the exact owner and
    fail-closed Host ACL on every protected path, and performs only read-only
    package observations while impersonating a minimal duplicate of the exact
    retained client-process token. The worker reverts and positively proves its
    clean identity before publishing any result. No Authority storage, signing,
    mutation, provider execution, or caller callback is reachable from the
    impersonated body.
    """
    if observed_sid.casefold() != expected_sid.casefold():
        raise PermissionError("Provider Host observation SID is mismatched")
    client_process_binding.revalidate(expected_sid)
    with restricted_process_runtime.authenticated_client_process_impersonation_token(
        client_process_binding,
        expected_sid=expected_sid,
    ) as client_token:
        client_process_binding.revalidate(expected_sid)
        observation = _provider_host_path_observation_with_token(
            client_token=client_token,
            client_process_binding=client_process_binding,
            expected_sid=expected_sid,
            profile=profile,
            installation=installation,
            observed_sid=observed_sid,
        )
        client_process_binding.revalidate(expected_sid)
    client_process_binding.revalidate(expected_sid)
    return observation


def _provider_host_path_observation_with_token(
    *,
    client_token: int,
    client_process_binding: NamedPipeClientProcessBinding,
    expected_sid: str,
    profile: str,
    installation: Mapping[str, Any],
    observed_sid: str,
) -> dict[str, Any]:
    """Run the fixed Host observation with a verified process-token duplicate."""
    require_impersonation_level(client_token)
    advapi32 = restricted_process_runtime._advapi32()
    kernel32 = restricted_process_runtime._kernel32()
    try:
        restricted_process_runtime._assert_thread_not_impersonating(
            advapi32=advapi32,
            kernel32=kernel32,
        )
    except BaseException as error:
        raise restricted_process_runtime.ProviderServiceIdentityUncertain(
            "Authority service thread identity is not clean before Provider Host "
            "path validation"
        ) from error
    outcome: list[dict[str, Any] | BaseException] = []

    def worker() -> None:
        try:
            restricted_process_runtime._assert_thread_not_impersonating(
                advapi32=advapi32,
                kernel32=kernel32,
            )
        except BaseException as error:
            # This check ran before impersonation, so reporting is safe.
            outcome.append(error)
            return
        ctypes.set_last_error(0)
        try:
            impersonated = bool(advapi32.ImpersonateLoggedOnUser(client_token))
        except BaseException:
            # The API call did not produce a trustworthy identity outcome.
            return
        if not impersonated:
            win32_error = ctypes.get_last_error()
            try:
                restricted_process_runtime._assert_thread_not_impersonating(
                    advapi32=advapi32,
                    kernel32=kernel32,
                )
            except BaseException:
                # Do not publish from a worker whose identity is uncertain.
                return
            outcome.append(
                PermissionError(
                    "Provider Host authenticated-client path impersonation "
                    f"failed: {win32_error}"
                )
            )
            return
        observation: dict[str, Any] | None = None
        observation_error: BaseException | None = None
        try:
            client_process_binding.bind_or_revalidate_executable_identity(
                expected_sid
            )
            observation = _read_provider_host_path_observation(
                profile=profile,
                installation=installation,
                observed_sid=observed_sid,
            )
            client_process_binding.bind_or_revalidate_executable_identity(
                expected_sid
            )
        except BaseException as error:
            observation_error = error
        try:
            reverted = bool(advapi32.RevertToSelf())
        except BaseException:
            # Never publish or signal from an identity-uncertain worker.
            return
        try:
            restricted_process_runtime._assert_thread_not_impersonating(
                advapi32=advapi32,
                kernel32=kernel32,
            )
        except BaseException:
            # Permanently abandon this disposable worker. It must not publish
            # a result or perform any callback under an uncertain identity.
            return
        if not reverted:
            # RevertToSelf itself failed even though the subsequent probe did
            # not expose a token. Treat the identity transition as uncertain.
            return
        if observation_error is not None:
            outcome.append(observation_error)
            return
        if observation is None:
            outcome.append(
                PermissionError(
                    "Provider Host path validation produced no observation"
                )
            )
            return
        outcome.append(observation)

    validation_thread = threading.Thread(
        target=worker,
        name="KeeperAuthorityProviderHostPaths",
        daemon=True,
    )
    validation_thread.start()
    validation_thread.join()
    try:
        restricted_process_runtime._assert_thread_not_impersonating(
            advapi32=advapi32,
            kernel32=kernel32,
        )
    except BaseException as error:
        raise restricted_process_runtime.ProviderServiceIdentityUncertain(
            "Authority service thread identity is not clean after Provider Host "
            "path validation"
        ) from error
    if not outcome:
        raise restricted_process_runtime.ProviderServiceIdentityUncertain(
            "Provider Host path-validation worker identity could not be verified"
        )
    first = outcome[0]
    if isinstance(first, BaseException):
        raise first
    return first


def _read_provider_host_path_observation(
    *,
    profile: str,
    installation: Mapping[str, Any],
    observed_sid: str,
) -> dict[str, Any]:
    """Fixed, read-only filesystem body for authenticated Host validation."""
    expected_root_lexical = (
        Path(profile)
        / "AppData"
        / "Local"
        / "Programs"
        / "DarkSage"
        / "KeeperProviderHost"
    )
    startup_root_lexical = (
        Path(profile)
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )
    executable = Path(str(installation.get("executable_path", "")))
    install_root = Path(str(installation.get("install_root", "")))
    if not executable.is_absolute() or not install_root.is_absolute():
        raise PermissionError("Provider Host enrollment path is not absolute")
    lexical_executable = Path(os.path.abspath(executable))
    lexical_root = Path(os.path.abspath(install_root))
    for path in (
        expected_root_lexical,
        startup_root_lexical,
        lexical_executable,
        lexical_root,
    ):
        _reject_path_aliases(path)
    expected_root = expected_root_lexical.resolve(strict=True)
    startup_root = startup_root_lexical.resolve(strict=True)
    canonical = lexical_executable.resolve(strict=True)
    canonical_root = lexical_root.resolve(strict=True)
    installer = ProviderHostInstaller(
        expected_root,
        startup_root,
        owner_sid=observed_sid,
        authority_service_sid=account_sid(r"NT SERVICE\KeeperAuthority"),
    )
    security_before = installer.attest_protected_tree()
    installed = installer.status()
    expected_state_lexical = expected_root / "state"
    expected_output_lexical = (
        Path(profile)
        / "AppData"
        / "Local"
        / "DarkSage"
        / "KeeperProviderExchange"
    )
    _reject_path_aliases(expected_state_lexical)
    _reject_path_aliases(expected_output_lexical)
    expected_state = expected_state_lexical.resolve(strict=True)
    expected_output = expected_output_lexical.resolve(strict=True)
    exchange_security_digest = attest_provider_host_exchange_root(
        expected_output,
        owner_sid=observed_sid,
    )
    descriptor = _open_locked_executable(canonical)
    try:
        opened = os.fstat(descriptor)
        identity = _executable_file_identity(opened)
        digest = hashlib.sha256()
        size = 0
        prefix = b""
        while True:
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            if len(prefix) < 2:
                prefix = (prefix + chunk)[:2]
            digest.update(chunk)
            size += len(chunk)
        signature = authenticode_enrollment_binding(canonical)
        final_opened_identity = _executable_file_identity(os.fstat(descriptor))
        final_path_identity = _executable_file_identity(canonical.stat())
        if final_opened_identity != identity or final_path_identity != identity:
            raise PermissionError(
                "Provider Host executable changed during path validation"
            )
        installed_after = installer.status()
        security_after = installer.attest_protected_tree()
        if installed_after != installed or security_after != security_before:
            raise PermissionError(
                "Provider Host installation changed during path validation"
            )
        return {
            "authenticode_binding": signature,
            "canonical_executable": str(canonical),
            "canonical_root": str(canonical_root),
            "executable_file_identity": identity,
            "executable_prefix": prefix,
            "executable_sha256": digest.hexdigest(),
            "executable_size": size,
            "expected_output": str(expected_output),
            "exchange_security_digest": exchange_security_digest,
            "expected_root": str(expected_root),
            "expected_state": str(expected_state),
            "final_executable_file_identity": final_path_identity,
            "installed": installed,
            "startup_root": str(startup_root),
        }
    finally:
        os.close(descriptor)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _status_provider_bindings(status: Mapping[str, Any]) -> list[dict[str, Any]]:
    values = status.get("provider_bindings")
    if values is None:
        legacy = status.get("provider_binding")
        values = [] if legacy is None else [legacy]
    if not isinstance(values, list) or not all(
        isinstance(value, dict) for value in values
    ):
        raise PermissionError("KeeperProviderHost provider bindings are invalid")
    result = [dict(value) for value in values]
    identities = [
        (value.get("provider_id"), value.get("registration_id"))
        for value in result
    ]
    if any(
        not isinstance(provider_id, str)
        or not provider_id
        or not isinstance(registration_id, str)
        or not registration_id
        for provider_id, registration_id in identities
    ) or len(identities) != len(set(identities)):
        raise PermissionError("KeeperProviderHost provider bindings are invalid")
    return sorted(
        result,
        key=lambda value: (
            str(value["provider_id"]),
            str(value["registration_id"]),
        ),
    )


def _execution_evidence_digest(stdout_path: Path, stderr_path: Path) -> str:
    evidence = {
        "stdout_sha256": hashlib.sha256(
            stdout_path.read_bytes() if stdout_path.exists() else b""
        ).hexdigest(),
        "stderr_sha256": hashlib.sha256(
            stderr_path.read_bytes() if stderr_path.exists() else b""
        ).hexdigest(),
    }
    return hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _bounded_text(path: Path, maximum_bytes: int = 1_048_576) -> str:
    if not path.exists():
        return ""
    content = path.read_bytes()[:maximum_bytes]
    return content.decode("utf-8", errors="replace")


def _validated_reviewed_codex_executable(
    executable: Path,
    expected_sha256: str | None,
    expected_size: int | None,
) -> tuple[Path, dict[str, Any]]:
    canonical, measurement, descriptor = _open_validated_reviewed_codex_executable(
        executable, expected_sha256, expected_size
    )
    try:
        return canonical, measurement
    finally:
        os.close(descriptor)


def _measure_duplicated_reviewed_executable(
    handle: int,
    executable: Path,
    expected_sha256: str | None,
    expected_size: int | None,
    *,
    provider_id: str = "codex",
) -> tuple[Path, dict[str, Any]]:
    """Validate an exact read handle duplicated from the authenticated client."""
    descriptor = -1
    try:
        descriptor = _descriptor_from_duplicated_handle(
            _duplicate_local_handle(handle)
        )
        canonical = _final_path_from_descriptor(descriptor)
        lexical = _validated_codex_lexical_path(executable)
        if os.path.normcase(str(canonical)) != os.path.normcase(str(lexical)):
            raise PermissionError("Codex client handle path is mismatched")
        _validate_reviewed_identity(expected_sha256, expected_size)
        opened = os.fstat(descriptor)
        opened_identity = _executable_file_identity(opened)
        if opened_identity["size"] != expected_size:
            raise PermissionError("Codex executable differs from reviewed identity")
        digest = hashlib.sha256()
        total = 0
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        if digest.hexdigest() != expected_sha256 or total != expected_size:
            raise PermissionError("Codex executable differs from reviewed identity")
        raw_signature = authenticode_identity_from_handle(
            _descriptor_handle(descriptor), canonical
        )
        signature = (
            validate_codex_authenticode_binding(raw_signature)
            if provider_id == "codex"
            else validate_claude_authenticode_binding(raw_signature)
            if provider_id == "claude"
            else None
        )
        if signature is None:
            raise PermissionError("Provider executable signer is unsupported")
        final_path = _final_path_from_descriptor(descriptor)
        final_identity = _executable_file_identity(os.fstat(descriptor))
        if (
            os.path.normcase(str(final_path)) != os.path.normcase(str(canonical))
            or final_identity != opened_identity
        ):
            raise PermissionError(
                "Codex executable changed during reviewed identity validation"
            )
        return canonical, {
            "canonical_path": str(canonical),
            "sha256": digest.hexdigest(),
            "size": total,
            "file_identity": opened_identity,
            "authenticode_binding": signature,
        }
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _duplicate_local_handle(handle: int) -> int:
    if os.name != "nt":
        return os.dup(handle)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    duplicate = kernel32.DuplicateHandle
    duplicate.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    duplicate.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    copied = wintypes.HANDLE()
    current = kernel32.GetCurrentProcess()
    if not duplicate(
        current,
        wintypes.HANDLE(handle),
        current,
        ctypes.byref(copied),
        0,
        False,
        0x00000002,
    ) or not copied.value:
        raise PermissionError(
            "Codex duplicated client handle cannot be retained: "
            f"{ctypes.get_last_error()}"
        )
    return int(copied.value)


def _validate_reviewed_identity(
    expected_sha256: str | None, expected_size: int | None
) -> None:
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(item not in "0123456789abcdef" for item in expected_sha256)
        or isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or expected_size <= 0
    ):
        raise PermissionError("Codex reviewed executable identity is invalid")


def _validated_codex_lexical_path(executable: Path) -> Path:
    raw_path = str(executable).replace("/", "\\")
    if (
        raw_path.startswith("\\\\")
        or raw_path.startswith("\\\\?\\")
        or raw_path.startswith("\\\\.\\")
        or ":" in raw_path[2:]
    ):
        raise PermissionError("Codex executable path form is prohibited")
    if not executable.is_absolute():
        raise PermissionError("Codex executable path is not absolute")
    return Path(os.path.abspath(executable))


def _descriptor_from_duplicated_handle(handle: int) -> int:
    if os.name != "nt":
        return handle
    import msvcrt

    try:
        return msvcrt.open_osfhandle(
            handle, os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
    except BaseException:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(
            wintypes.HANDLE(handle)
        )
        raise


def _descriptor_handle(descriptor: int) -> int:
    if os.name != "nt":
        return descriptor
    import msvcrt

    return int(msvcrt.get_osfhandle(descriptor))


def _final_path_from_descriptor(descriptor: int) -> Path:
    if os.name != "nt":
        return Path(os.readlink(f"/proc/self/fd/{descriptor}")).resolve(strict=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_path = kernel32.GetFinalPathNameByHandleW
    get_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    get_path.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    length = int(
        get_path(
            wintypes.HANDLE(_descriptor_handle(descriptor)),
            buffer,
            len(buffer),
            0,
        )
    )
    if length <= 0 or length >= len(buffer):
        raise PermissionError("Codex client handle final path is unavailable")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        raise PermissionError("Codex client handle path is remote")
    if value.startswith("\\\\?\\"):
        value = value[4:]
    path = Path(value)
    if not path.is_absolute():
        raise PermissionError("Codex client handle final path is invalid")
    return path


def _open_validated_reviewed_codex_executable(
    executable: Path,
    expected_sha256: str | None,
    expected_size: int | None,
) -> tuple[Path, dict[str, Any], int]:
    _validate_reviewed_identity(expected_sha256, expected_size)
    lexical = _validated_codex_lexical_path(executable)
    _reject_path_aliases(lexical)
    canonical = lexical.resolve(strict=True)
    if os.path.normcase(str(canonical)) != os.path.normcase(str(lexical)):
        raise PermissionError("Codex executable path is not canonical")
    descriptor = _open_locked_executable(canonical)
    try:
        opened = os.fstat(descriptor)
        opened_identity = _executable_file_identity(opened)
        if opened_identity["size"] != expected_size:
            raise PermissionError("Codex executable differs from reviewed identity")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        if digest.hexdigest() != expected_sha256 or total != expected_size:
            raise PermissionError("Codex executable differs from reviewed identity")
        signature = validate_codex_authenticode_binding(
            authenticode_identity(canonical)
        )
        final_opened = os.fstat(descriptor)
        final_path = canonical.stat()
        final_identity = _executable_file_identity(final_opened)
        if (
            final_identity != opened_identity
            or _executable_file_identity(final_path) != opened_identity
        ):
            raise PermissionError(
                "Codex executable changed during reviewed identity validation"
            )
        measurement = {
            "canonical_path": str(canonical),
            "sha256": digest.hexdigest(),
            "size": total,
            "file_identity": opened_identity,
            "authenticode_binding": signature,
        }
        return canonical, measurement, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _executable_file_identity(value: os.stat_result) -> dict[str, int]:
    return validate_executable_file_identity(
        {
            "schema_version": 1,
            "device_id": int(value.st_dev),
            "file_id": int(value.st_ino),
            "size": int(value.st_size),
            "modified_ns": int(value.st_mtime_ns),
        }
    )


def _reject_path_aliases(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        item = current.lstat()
        is_reparse = bool(
            getattr(item, "st_file_attributes", 0)
            & getattr(os, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
        if current.is_symlink() or is_reparse:
            raise PermissionError("Codex executable path contains an alias")


def _open_locked_executable(path: Path) -> int:
    if os.name != "nt":
        return os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0),
        )
    import msvcrt

    generic_read = 0x80000000
    file_share_read = 0x00000001
    open_existing = 3
    file_attribute_normal = 0x00000080
    file_flag_open_reparse_point = 0x00200000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        generic_read,
        file_share_read,
        None,
        open_existing,
        file_attribute_normal | file_flag_open_reparse_point,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    handle_value = getattr(handle, "value", handle)
    if handle_value in {None, invalid}:
        raise PermissionError(
            f"Codex executable secure open failed: {ctypes.get_last_error()}"
        )
    try:
        return msvcrt.open_osfhandle(
            int(handle_value), os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


def _provider_host_failure_reason(error: BaseException) -> str:
    """Classify a Host handshake failure without exposing local path data."""
    name = type(error).__name__
    message = str(error).casefold()
    if name == "ProviderHostIdentityUncertain":
        reason = (
            "IDENTITY_MEASUREMENT_TIMEOUT"
            if "timed out" in message
            else "IDENTITY_REVERSION_UNCERTAIN"
            if "not clean" in message or "could not be verified" in message
            else "IDENTITY_MEASUREMENT_UNCERTAIN"
        )
    elif isinstance(error, TimeoutError):
        reason = "PIPE_TIMEOUT"
    elif isinstance(error, OSError) and not isinstance(error, PermissionError):
        reason = "PIPE_UNAVAILABLE"
    elif isinstance(error, PermissionError):
        reason = "IDENTITY_OR_PROTOCOL_REJECTED"
    else:
        reason = "HANDSHAKE_FAILED"
    return f"{name}:{reason}"


def _provider_host_setup_failure(observation: object) -> str:
    """Validate one signed Host failure classification without exposing text."""

    stage = observation.get("failure_stage") if isinstance(observation, dict) else None
    code = observation.get("failure_code") if isinstance(observation, dict) else None
    allowed_stages = {
        "SETUP_INITIALIZATION",
        "EXECUTABLE_LOCK",
        "SOURCE_TOKEN_OPEN",
        "RESTRICTED_TOKEN_CREATE",
        "VERSION_LAUNCH",
        "VERSION_CREATE_PROCESS",
        "VERSION_JOB_ASSIGN",
        "VERSION_JOB_VERIFY",
        "VERSION_STARTED_CALLBACK",
        "VERSION_STARTED_ACK",
        "VERSION_RESUME",
        "VERSION_WAIT",
        "VERSION_VALIDATE",
        "ACCOUNT_PROBE_LAUNCH",
        "ACCOUNT_PROBE_VALIDATE",
        "ACCOUNT_BINDING_VALIDATE",
        "QUALIFICATION_PREPARE",
        "QUALIFICATION_LAUNCH",
        "QUALIFICATION_VALIDATE",
    }
    allowed_codes = {
        "TIMEOUT",
        "PERMISSION_REJECTED",
        "OS_ERROR",
        "INVALID_RESULT",
        "RUNTIME_FAILURE",
    }
    valid_win32 = (
        isinstance(code, str)
        and code.startswith("WIN32_")
        and code[6:].isdigit()
        and 0 < int(code[6:]) <= 65_535
    )
    if (
        not isinstance(stage, str)
        or stage not in allowed_stages
        or not isinstance(code, str)
        or (code not in allowed_codes and not valid_win32)
    ):
        return "stage=UNAVAILABLE, code=INVALID_RESULT"
    return f"stage={stage}, code={code}"


def _provider_registration_terminal_failure(
    result: Mapping[str, Any], observation: object
) -> dict[str, Any]:
    """Validate and reduce one signed terminal registration failure."""

    classification = _provider_host_setup_failure(observation)
    stage_part, code_part = classification.split(", ", 1)
    stage = stage_part.removeprefix("stage=")
    code = code_part.removeprefix("code=")
    process_result = (
        observation.get("process_result")
        if isinstance(observation, dict)
        else None
    )
    if process_result is None:
        sanitized_process: dict[str, Any] = {
            "detail_status": "DETAIL_UNAVAILABLE"
        }
    else:
        required = {
            "operation",
            "exit_code",
            "timed_out",
            "stdout_sha256",
            "stdout_bytes",
            "stderr_sha256",
            "stderr_bytes",
            "restricted",
            "job_confined",
            "started",
            "resumed",
        }
        if not isinstance(process_result, dict) or set(process_result) != required:
            raise PermissionError(
                "Provider Host registration process result is invalid"
            )
        operation = process_result.get("operation")
        exit_code = process_result.get("exit_code")
        byte_counts = (
            process_result.get("stdout_bytes"),
            process_result.get("stderr_bytes"),
        )
        digests = (
            process_result.get("stdout_sha256"),
            process_result.get("stderr_sha256"),
        )
        if (
            operation not in {"VERSION", "ACCOUNT_PROBE", "QUALIFICATION"}
            or isinstance(exit_code, bool)
            or not isinstance(exit_code, int)
            or exit_code < 0
            or exit_code > 0xFFFFFFFF
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > 1_048_576
                for value in byte_counts
            )
            or any(
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in digests
            )
            or any(
                not isinstance(process_result.get(name), bool)
                for name in {
                    "timed_out",
                    "restricted",
                    "job_confined",
                    "started",
                    "resumed",
                }
            )
            or process_result.get("restricted") is not True
            or process_result.get("job_confined") is not True
            or process_result.get("started") is not True
            or process_result.get("resumed") is not True
        ):
            raise PermissionError(
                "Provider Host registration process result is invalid"
            )
        sanitized_process = dict(process_result)
    setup_result_digest = result.get("setup_result_digest")
    setup_envelope_digest = result.get("setup_envelope_digest")
    for value in (setup_result_digest, setup_envelope_digest):
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise PermissionError(
                "Provider Host registration terminal digest is invalid"
            )
    return {
        "failure_stage": stage,
        "failure_code": code,
        "process_result": sanitized_process,
        "setup_result_digest": setup_result_digest,
        "setup_envelope_digest": setup_envelope_digest,
    }
