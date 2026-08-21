from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from keeper.provider_host.environment import (
    EnvironmentSnapshot,
    assert_attestation_matches,
    build_sanitized_environment,
)
from keeper.provider_host.identity import UserBinding, require_same_binding
from keeper.provider_host.protocol import (
    COMPLETION_PURPOSE,
    LAUNCH_PURPOSE,
    LAUNCH_RECONCILIATION_PURPOSE,
    LAUNCH_RECONCILIATION_RESULT_PURPOSE,
    SETUP_PURPOSE,
    SETUP_RESULT_PURPOSE,
    EnvelopeSigner,
    EnvelopeVerifier,
    structured_digest,
    validate_launch_envelope,
    validate_setup_envelope,
)
from keeper.provider_host.replay_store import ProviderHostStore
from keeper.providers.claude_contract import CLAUDE_PINNED_REVIEW_MODEL


class HostState(StrEnum):
    STARTING = "STARTING"
    READY = "READY"
    PREPARING = "PREPARING"
    CLAIMED = "CLAIMED"
    STARTED = "STARTED"
    RUNNING = "RUNNING"
    LOCKED = "LOCKED"
    DRAINING = "DRAINING"
    STOPPED = "STOPPED"
    STALE = "STALE"


class Launcher(Protocol):
    def launch(
        self,
        envelope: Mapping[str, Any],
        environment: Mapping[str, str],
        cancel_requested: threading.Event,
        *,
        on_started: Callable[[dict[str, object]], None],
        on_resumed: Callable[[dict[str, object]], None],
    ) -> dict[str, Any]: ...


class SetupRunner(Protocol):
    def run_setup(
        self,
        envelope: Mapping[str, Any],
        environment: Mapping[str, str],
        cancel_requested: threading.Event,
        *,
        on_started: Callable[[dict[str, object]], None],
        on_resumed: Callable[[dict[str, object]], None],
    ) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class HostIdentity:
    host_id: str
    authority_id: str
    binding: UserBinding


@dataclass(frozen=True, slots=True)
class ProviderBinding:
    provider_id: str
    account_id: str
    session_id: str
    registration_id: str
    qualification_id: str
    executable_path: str
    executable_sha256: str
    executable_size: int
    file_identity: Mapping[str, int]
    authenticode_binding: Mapping[str, object]
    publisher: str
    version: str
    models: tuple[str, ...]
    efforts: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ProviderBinding:
        expected = {
            "account_id", "authenticode_binding", "efforts",
            "executable_path", "executable_sha256", "executable_size",
            "file_identity", "models", "provider_id", "publisher",
            "qualification_id", "registration_id", "session_id", "version",
        }
        if set(value) != expected:
            raise PermissionError("Provider Host provider-binding fields are invalid")
        for name in (
            "account_id", "executable_path", "executable_sha256", "provider_id",
            "publisher", "qualification_id", "registration_id", "session_id", "version",
        ):
            if not isinstance(value.get(name), str) or not value[name]:
                raise PermissionError("Provider Host provider-binding value is invalid")
        size = value.get("executable_size")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise PermissionError("Provider Host provider-binding size is invalid")
        if not isinstance(value.get("file_identity"), dict) or not isinstance(
            value.get("authenticode_binding"), dict
        ):
            raise PermissionError("Provider Host provider-binding identity is invalid")
        models = value.get("models")
        efforts = value.get("efforts")
        if (
            not isinstance(models, (list, tuple))
            or not models
            or not all(isinstance(item, str) and item for item in models)
            or not isinstance(efforts, (list, tuple))
            or not efforts
            or not all(isinstance(item, str) and item for item in efforts)
        ):
            raise PermissionError("Provider Host provider capabilities are invalid")
        provider_id = str(value["provider_id"])
        expected_account_prefix = {
            "codex": "chatgpt-subscription:",
            "claude": "claude-ai-subscription:",
        }.get(provider_id)
        expected_models = {
            "codex": None,
            "claude": (CLAUDE_PINNED_REVIEW_MODEL,),
        }.get(provider_id)
        account_id = str(value["account_id"])
        account_digest = (
            account_id.removeprefix(expected_account_prefix)
            if expected_account_prefix is not None
            else ""
        )
        normalized_models = tuple(str(item) for item in models)
        normalized_efforts = tuple(str(item) for item in efforts)
        if (
            expected_account_prefix is None
            or not account_id.startswith(expected_account_prefix)
            or len(account_digest) != 64
            or any(character not in "0123456789abcdef" for character in account_digest)
            or (expected_models is not None and normalized_models != expected_models)
            or normalized_efforts != ("medium", "high")
        ):
            raise PermissionError("Provider Host provider capabilities are invalid")
        return cls(
            provider_id=provider_id,
            account_id=account_id,
            session_id=str(value["session_id"]),
            registration_id=str(value["registration_id"]),
            qualification_id=str(value["qualification_id"]),
            executable_path=str(value["executable_path"]),
            executable_sha256=str(value["executable_sha256"]),
            executable_size=int(size),
            file_identity=dict(value["file_identity"]),
            authenticode_binding=dict(value["authenticode_binding"]),
            publisher=str(value["publisher"]),
            version=str(value["version"]),
            models=normalized_models,
            efforts=normalized_efforts,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "authenticode_binding": dict(self.authenticode_binding),
            "efforts": list(self.efforts),
            "executable_path": self.executable_path,
            "executable_sha256": self.executable_sha256,
            "executable_size": self.executable_size,
            "file_identity": dict(self.file_identity),
            "models": list(self.models),
            "provider_id": self.provider_id,
            "publisher": self.publisher,
            "qualification_id": self.qualification_id,
            "registration_id": self.registration_id,
            "session_id": self.session_id,
            "version": self.version,
        }


class KeeperProviderHost:
    """Unelevated execution deputy for exact Authority-signed launches."""

    def __init__(
        self,
        *,
        identity: HostIdentity,
        observed_binding: Callable[[], UserBinding],
        authority_verifier: EnvelopeVerifier,
        host_signer: EnvelopeSigner,
        store: ProviderHostStore,
        provider_binding: ProviderBinding | None,
        environment_attestation_key: bytes,
        setup_workspace_root: Path,
        now: Callable[[], datetime] | None = None,
        maximum_ttl: timedelta = timedelta(minutes=2),
        maximum_future_skew: timedelta = timedelta(seconds=5),
    ) -> None:
        if not environment_attestation_key:
            raise ValueError("Provider Host environment attestation key is required")
        self.identity = identity
        self._observed_binding = observed_binding
        self._authority_verifier = authority_verifier
        self._host_signer = host_signer
        self._store = store
        durable_bindings = {
            item.registration_id: item
            for item in (
                ProviderBinding.from_mapping(value)
                for value in self._store.provider_bindings()
            )
        }
        if provider_binding is not None:
            durable = durable_bindings.get(provider_binding.registration_id)
            if durable is not None and durable != provider_binding:
                raise PermissionError("Provider Host durable provider binding differs")
            same_provider = next(
                (
                    value
                    for value in durable_bindings.values()
                    if value.provider_id == provider_binding.provider_id
                ),
                None,
            )
            if same_provider is not None and same_provider != provider_binding:
                raise PermissionError("Provider Host durable provider binding conflicts")
            durable_bindings[provider_binding.registration_id] = provider_binding
        self._provider_bindings = durable_bindings
        self._environment_attestation_key = environment_attestation_key
        if not setup_workspace_root.is_absolute():
            raise PermissionError(
                "Provider Host setup workspace root is not absolute"
            )
        profile = Path(identity.binding.profile_path).resolve(strict=True)
        canonical_setup_root = Path(os.path.abspath(setup_workspace_root))
        try:
            canonical_setup_root.relative_to(profile)
        except ValueError as error:
            raise PermissionError(
                "Provider Host setup workspace root escapes the enrolled profile"
            ) from error
        self._setup_workspace_root = canonical_setup_root
        self._now = now or (lambda: datetime.now(UTC))
        self._maximum_ttl = maximum_ttl
        self._maximum_future_skew = maximum_future_skew
        self._snapshots: dict[str, EnvironmentSnapshot] = {}
        self._active_cancel: threading.Event | None = None
        self._active_identity: tuple[str, str] | None = None
        self._lock = threading.RLock()
        self.state = HostState.STARTING

    def start(self) -> int:
        with self._lock:
            if self.state not in {HostState.STARTING, HostState.STOPPED}:
                raise PermissionError("Provider Host is already started")
            require_same_binding(self.identity.binding, self._observed_binding())
            recovered = self._store.recover_uncertain(
                "Provider Host restart with unresolved external effect"
            )
            self._set_state(HostState.READY)
            return recovered

    def prepare_environment(
        self,
        *,
        preparation_nonce: str,
        provider_bin: Path,
        provider_registration_id: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self._require_ready()
            self._set_state(HostState.PREPARING)
            try:
                canonical_bin = provider_bin.resolve(strict=True)
                provider = (
                    self._provider_bindings.get(provider_registration_id)
                    if provider_registration_id is not None
                    else self._preferred_provider_binding()
                )
                if provider is not None:
                    expected_bin = Path(provider.executable_path).resolve(
                        strict=True
                    ).parent
                    if canonical_bin != expected_bin:
                        raise PermissionError(
                            "Provider Host environment bin differs from registration"
                        )
                else:
                    profile = Path(self.identity.binding.profile_path).resolve(
                        strict=True
                    )
                    try:
                        canonical_bin.relative_to(profile)
                    except ValueError as error:
                        raise PermissionError(
                            "Unbound Provider Host setup executable is outside the enrolled profile"
                        ) from error
                snapshot = build_sanitized_environment(
                    os.environ,
                    profile_path=Path(self.identity.binding.profile_path),
                    provider_bin=canonical_bin,
                    preparation_nonce=preparation_nonce,
                    attestation_key=self._environment_attestation_key,
                    exchange_root=self._setup_workspace_root.parent,
                )
                self._snapshots[preparation_nonce] = snapshot
                return self._host_signer.sign(
                    "keeper-provider-host-environment",
                    {
                        "host_id": self.identity.host_id,
                        "recorded_at": self._now().astimezone(UTC).isoformat(),
                        **snapshot.public_attestation(),
                    },
                )
            finally:
                if self.state is HostState.PREPARING:
                    self._set_state(HostState.READY)

    def execute(
        self,
        signed_envelope: Mapping[str, Any],
        launcher: Launcher,
        *,
        started_observer: Callable[[dict[str, object]], None] | None = None,
        resumed_observer: Callable[[dict[str, object]], None] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self._require_ready()
            require_same_binding(self.identity.binding, self._observed_binding())
            payload = self._authority_verifier.verify(
                signed_envelope, purpose=LAUNCH_PURPOSE
            )
            envelope = validate_launch_envelope(payload)
            self._validate_binding(envelope)
            nonce = str(envelope["environment"]["preparation_nonce"])
            snapshot = self._snapshots.pop(nonce, None)
            if snapshot is None:
                raise PermissionError("Provider Host environment preparation is absent")
            assert_attestation_matches(snapshot, envelope["environment"])
            for name in (
                "OPENAI_API_KEY",
                "CODEX_API_KEY",
                "CODEX_ACCESS_TOKEN",
            ):
                if name in snapshot.values:
                    raise PermissionError("Provider Host API-key environment is prohibited")
            envelope_digest = structured_digest(envelope)
            self._store.claim_launch(
                authority_id=str(envelope["authority_id"]),
                nonce=str(envelope["nonce"]),
                sequence=int(envelope["sequence"]),
                issued_at=str(envelope["issued_at"]),
                expires_at=str(envelope["expires_at"]),
                now=self._now(),
                maximum_ttl=self._maximum_ttl,
                maximum_future_skew=self._maximum_future_skew,
                launch_id=str(envelope["launch_id"]),
                authority_attempt_id=str(envelope["authority_attempt_id"]),
                envelope_digest=envelope_digest,
                workspace_path=str(envelope["workspace"]["canonical_path"]),
                operation="PROVIDER_EXECUTION",
            )
            self._active_cancel = threading.Event()
            self._active_identity = (
                str(envelope["authority_attempt_id"]),
                str(envelope["launch_id"]),
            )
            self._set_state(HostState.CLAIMED)
        launch_id = str(envelope["launch_id"])
        started = False
        resumed = False

        def on_started(observation: dict[str, object]) -> None:
            nonlocal started
            self._store.transition(
                launch_id,
                "CLAIMED",
                "STARTED",
                phase="STARTED_AWAITING_ACK",
            )
            started = True
            with self._lock:
                if self.state is HostState.CLAIMED:
                    self._set_state(HostState.STARTED)
            if started_observer is not None:
                started_observer(observation)
            self._store.set_phase(launch_id, "STARTED", "STARTED_ACK_VERIFIED")

        def on_resumed(observation: dict[str, object]) -> None:
            nonlocal resumed
            self._store.transition(
                launch_id, "STARTED", "RUNNING", phase="RESUMED"
            )
            resumed = True
            with self._lock:
                if self.state is HostState.STARTED:
                    self._set_state(HostState.RUNNING)
            if resumed_observer is not None:
                resumed_observer(observation)

        try:
            cancellation = self._active_cancel
            if cancellation is None:
                raise RuntimeError("Provider Host cancellation state is unavailable")
            result = launcher.launch(
                envelope,
                snapshot.values,
                cancellation,
                on_started=on_started,
                on_resumed=on_resumed,
            )
            terminal = (
                "CANCELLED"
                if cancellation.is_set()
                else "COMPLETED"
                if result.get("exit_code") == 0
                else "FAILED"
            )
            expected = "RUNNING" if resumed else "STARTED" if started else "CLAIMED"
            self._store.transition(
                launch_id, expected, terminal, phase="TERMINAL"
            )
            completion = {
                "authority_attempt_id": envelope["authority_attempt_id"],
                "envelope_digest": envelope_digest,
                "environment_digest": snapshot.digest,
                "evidence_digest": structured_digest(result),
                "host_id": self.identity.host_id,
                "launch_id": launch_id,
                "provider_input_digest": envelope["provider_input_digest"],
                "provider_output": result,
                "recorded_at": self._now().astimezone(UTC).isoformat(),
                "state": terminal,
            }
            return self._host_signer.sign(COMPLETION_PURPOSE, completion)
        except BaseException as error:
            current = self._store.get_launch(launch_id)["state"]
            if current in {"STARTED", "RUNNING"}:
                self._store.transition(
                    launch_id,
                    str(current),
                    "UNCERTAIN",
                    detail=type(error).__name__,
                )
            elif current == "CLAIMED":
                self._store.transition(
                    launch_id,
                    "CLAIMED",
                    "FAILED",
                    detail=type(error).__name__,
                )
            raise
        finally:
            with self._lock:
                self._active_cancel = None
                self._active_identity = None
                if self.state not in {
                    HostState.LOCKED,
                    HostState.DRAINING,
                    HostState.STOPPED,
                    HostState.STALE,
                }:
                    self._set_state(HostState.READY)

    def execute_setup(
        self,
        signed_envelope: Mapping[str, Any],
        runner: SetupRunner,
        *,
        started_observer: Callable[[dict[str, object]], None] | None = None,
        resumed_observer: Callable[[dict[str, object]], None] | None = None,
    ) -> dict[str, Any]:
        """Execute an Authority-owned registration probe or qualification."""
        with self._lock:
            self._require_ready()
            require_same_binding(self.identity.binding, self._observed_binding())
            payload = self._authority_verifier.verify(
                signed_envelope, purpose=SETUP_PURPOSE
            )
            envelope = validate_setup_envelope(payload)
            self._validate_setup_binding(envelope)
            preparation_nonce = str(
                envelope["environment"]["preparation_nonce"]
            )
            snapshot = self._snapshots.pop(preparation_nonce, None)
            if snapshot is None:
                raise PermissionError(
                    "Provider Host setup environment preparation is absent"
                )
            assert_attestation_matches(snapshot, envelope["environment"])
            for name in (
                "OPENAI_API_KEY",
                "CODEX_API_KEY",
                "CODEX_ACCESS_TOKEN",
            ):
                if name in snapshot.values:
                    raise PermissionError(
                        "Provider Host setup API-key environment is prohibited"
                    )
            setup_id = str(envelope["setup_id"])
            envelope_digest = structured_digest(envelope)
            self._store.claim_launch(
                authority_id=str(envelope["authority_id"]),
                nonce=str(envelope["nonce"]),
                sequence=int(envelope["sequence"]),
                issued_at=str(envelope["issued_at"]),
                expires_at=str(envelope["expires_at"]),
                now=self._now(),
                maximum_ttl=self._maximum_ttl,
                maximum_future_skew=self._maximum_future_skew,
                launch_id=setup_id,
                authority_attempt_id=setup_id,
                envelope_digest=envelope_digest,
                workspace_path=str(envelope["workspace"]["canonical_path"]),
                operation=str(envelope["operation"]),
            )
            self._active_cancel = threading.Event()
            self._active_identity = (setup_id, setup_id)
            self._set_state(HostState.CLAIMED)
        started = False
        resumed = False

        def on_started(observation: dict[str, object]) -> None:
            nonlocal started
            self._store.transition(
                setup_id,
                "CLAIMED",
                "STARTED",
                phase="STARTED_AWAITING_ACK",
            )
            started = True
            with self._lock:
                if self.state is HostState.CLAIMED:
                    self._set_state(HostState.STARTED)
            if started_observer is not None:
                started_observer(observation)
            self._store.set_phase(setup_id, "STARTED", "STARTED_ACK_VERIFIED")

        def on_resumed(observation: dict[str, object]) -> None:
            nonlocal resumed
            self._store.transition(
                setup_id, "STARTED", "RUNNING", phase="RESUMED"
            )
            resumed = True
            with self._lock:
                if self.state is HostState.STARTED:
                    self._set_state(HostState.RUNNING)
            if resumed_observer is not None:
                resumed_observer(observation)

        try:
            cancellation = self._active_cancel
            if cancellation is None:
                raise RuntimeError(
                    "Provider Host setup cancellation state is unavailable"
                )
            observation = runner.run_setup(
                envelope,
                snapshot.values,
                cancellation,
                on_started=on_started,
                on_resumed=on_resumed,
            )
            expected = "RUNNING" if resumed else "STARTED" if started else "CLAIMED"
            terminal = (
                "CANCELLED"
                if cancellation.is_set()
                else "COMPLETED"
                if observation.get("exit_status") == 0
                else "FAILED"
            )
            signed_result = self._host_signer.sign(
                SETUP_RESULT_PURPOSE,
                {
                    "authority_id": envelope["authority_id"],
                    "challenge": envelope["challenge"],
                    "environment_digest": snapshot.digest,
                    "host_id": self.identity.host_id,
                    "observation": observation,
                    "operation": envelope["operation"],
                    "provider_registration_id": envelope[
                        "provider_registration_id"
                    ],
                    "recorded_at": self._now().astimezone(UTC).isoformat(),
                    "setup_envelope_digest": envelope_digest,
                    "setup_id": setup_id,
                },
            )
            self._store.complete_setup(
                setup_id, expected, terminal, signed_result
            )
            return signed_result
        except BaseException as error:
            current = str(self._store.get_launch(setup_id)["state"])
            if current in {"STARTED", "RUNNING"}:
                self._store.transition(
                    setup_id, current, "UNCERTAIN", detail=type(error).__name__
                )
            elif current == "CLAIMED":
                self._store.transition(
                    setup_id, "CLAIMED", "FAILED", detail=type(error).__name__
                )
            raise
        finally:
            with self._lock:
                self._active_cancel = None
                self._active_identity = None
                if self.state not in {
                    HostState.LOCKED,
                    HostState.DRAINING,
                    HostState.STOPPED,
                    HostState.STALE,
                }:
                    self._set_state(HostState.READY)

    def lock_workstation(self) -> None:
        with self._lock:
            if self._active_cancel is not None:
                self._active_cancel.set()
            self._set_state(HostState.LOCKED)

    def cancel_active(
        self, authority_attempt_id: str, launch_id: str
    ) -> bool:
        with self._lock:
            if (
                self._active_cancel is None
                or self._active_identity
                != (authority_attempt_id, launch_id)
            ):
                return False
            self._active_cancel.set()
            return True

    def unlock_workstation(self) -> None:
        with self._lock:
            if self.state is not HostState.LOCKED or self._active_cancel is not None:
                raise PermissionError("Provider Host cannot unlock while work is active")
            require_same_binding(self.identity.binding, self._observed_binding())
            self._set_state(HostState.READY)

    def drain(self) -> None:
        with self._lock:
            self._set_state(HostState.DRAINING)

    def logoff(self) -> None:
        with self._lock:
            if self._active_cancel is not None:
                self._active_cancel.set()
            self._snapshots.clear()
            self._set_state(HostState.STOPPED)

    def mark_stale(self, detail: str = "Authority connection is stale") -> None:
        with self._lock:
            if self._active_cancel is not None:
                self._active_cancel.set()
            self._set_state(HostState.STALE, detail)

    def status(self) -> dict[str, object]:
        provider = self._preferred_provider_binding()
        providers = sorted(
            self._provider_bindings.values(),
            key=lambda value: (value.provider_id, value.registration_id),
        )
        journal = self._store.active_or_uncertain_summary()
        return {
            "authority_id": self.identity.authority_id,
            "host_id": self.identity.host_id,
            "host_protocol": "keeper-provider-host/1",
            "pending_environment_preparations": len(self._snapshots),
            "state": self.state.value,
            "user_binding": self.identity.binding.as_dict(),
            "provider_binding": provider.as_dict() if provider is not None else None,
            "provider_bindings": [value.as_dict() for value in providers],
            "provider_state": "QUALIFIED" if providers else "NO_QUALIFIED_PROVIDERS",
            "launch_journal": journal,
        }

    def reconcile_uncertain_launch(
        self, signed_reconciliation: Mapping[str, Any]
    ) -> dict[str, object]:
        with self._lock:
            if self.state is not HostState.READY:
                raise PermissionError(
                    "Provider Host launch reconciliation requires READY state"
                )
            require_same_binding(self.identity.binding, self._observed_binding())
            value = self._authority_verifier.verify(
                signed_reconciliation, purpose=LAUNCH_RECONCILIATION_PURPOSE
            )
            expected_fields = {
                "authority_id",
                "authorized_client_sid",
                "effect_accounting",
                "enrollment_id",
                "expected_launch",
                "host_id",
                "reconciliation_id",
                "resolution",
            }
            expected_launch = value.get("expected_launch")
            accounting = value.get("effect_accounting")
            if (
                set(value) != expected_fields
                or value.get("authority_id") != self.identity.authority_id
                or value.get("host_id") != self.identity.host_id
                or not isinstance(value.get("authorized_client_sid"), str)
                or str(value["authorized_client_sid"]).casefold()
                != self.identity.binding.user_sid.casefold()
                or value.get("resolution")
                != "LEGACY_REGISTER_PROBE_READ_ONLY_EFFECT_ACCOUNTED"
                or not isinstance(expected_launch, dict)
                or accounting
                != {
                    "model_request_possible": False,
                    "provider_mutation_possible": False,
                    "read_only_process_execution_upper_bound": 2,
                    "usage_observation_possible": True,
                }
                or self._provider_bindings
            ):
                raise PermissionError(
                    "Provider Host launch reconciliation binding is invalid"
                )
            result = self._store.reconcile_uncertain_registration_probe(
                dict(expected_launch),
                {
                    # Bind durable idempotency to the verified semantic request,
                    # not to the signer's fresh envelope nonce/timestamp.  An
                    # Authority response lost after the Host commit must be
                    # safely repeatable with a newly signed envelope.
                    "authorization_digest": structured_digest(value),
                    "effect_accounting": dict(accounting),
                    "reconciliation_id": value["reconciliation_id"],
                    "resolution": value["resolution"],
                },
            )
            return self._host_signer.sign(
                LAUNCH_RECONCILIATION_RESULT_PURPOSE,
                {
                    "authority_id": self.identity.authority_id,
                    "effect_accounting": dict(accounting),
                    "host_id": self.identity.host_id,
                    "launch_id": result["launch_id"],
                    "reconciliation_digest": result["reconciliation_digest"],
                    "reconciliation_id": value["reconciliation_id"],
                    "state": "FAILED",
                },
            )

    def terminal_setup_result(self, setup_id: str) -> dict[str, object] | None:
        with self._lock:
            require_same_binding(self.identity.binding, self._observed_binding())
            return self._store.terminal_setup_result(setup_id)

    def bind_provider(self, value: Mapping[str, Any]) -> dict[str, object]:
        with self._lock:
            self._require_ready()
            require_same_binding(self.identity.binding, self._observed_binding())
            binding = ProviderBinding.from_mapping(value)
            expected = self._provider_bindings.get(binding.registration_id)
            provider_collision = next(
                (
                    current
                    for current in self._provider_bindings.values()
                    if current.provider_id == binding.provider_id
                ),
                None,
            )
            if expected is not None and expected != binding:
                raise PermissionError("Provider Host provider binding conflicts")
            if provider_collision is not None and provider_collision != binding:
                raise PermissionError("Provider Host provider binding conflicts")
            self._store.bind_provider(binding.as_dict())
            self._provider_bindings[binding.registration_id] = binding
            return {
                "provider_id": binding.provider_id,
                "registration_id": binding.registration_id,
                "qualification_id": binding.qualification_id,
                "state": "QUALIFIED",
            }

    @property
    def provider_bin(self) -> Path:
        provider = self._preferred_provider_binding()
        if provider is None:
            raise PermissionError("Provider Host has no qualified provider binding")
        return Path(provider.executable_path).resolve(
            strict=True
        ).parent

    def _validate_binding(self, envelope: Mapping[str, Any]) -> None:
        provider = self._provider_bindings.get(
            str(envelope.get("provider_registration_id", ""))
        )
        if provider is None:
            raise PermissionError("Provider Host has no qualified provider binding")
        if (
            envelope["authority_id"] != self.identity.authority_id
            or envelope["host_id"] != self.identity.host_id
            or envelope["user_binding"] != self.identity.binding.as_dict()
            or envelope["provider_id"] != provider.provider_id
            or envelope["account_id"] != provider.account_id
            or envelope["provider_session_id"] != provider.session_id
            or envelope["provider_registration_id"] != provider.registration_id
            or envelope["provider_qualification_id"] != provider.qualification_id
            or envelope["executable"]["sha256"] != provider.executable_sha256
            or envelope["executable"]["size"] != provider.executable_size
            or envelope["executable"]["file_identity"] != dict(provider.file_identity)
            or envelope["executable"]["authenticode_binding"]
            != dict(provider.authenticode_binding)
            or envelope["executable"]["publisher"] != provider.publisher
            or envelope["executable"]["version"] != provider.version
            or envelope["model_id"] not in provider.models
            or envelope["effort"] not in provider.efforts
        ):
            raise PermissionError("Provider Host qualified binding differs")
        executable = Path(str(envelope["executable"]["path"]))
        expected = Path(provider.executable_path).resolve(strict=True)
        if (
            not executable.is_absolute()
            or os.path.normcase(os.path.abspath(str(executable)))
            != os.path.normcase(str(expected))
            or hashlib.sha256(expected.read_bytes()).hexdigest()
            != provider.executable_sha256
        ):
            raise PermissionError("Provider Host executable path or hash differs")

    def _validate_setup_binding(self, envelope: Mapping[str, Any]) -> None:
        provider = self._provider_bindings.get(
            str(envelope.get("provider_registration_id", ""))
        )
        if provider is None:
            if (
                envelope["authority_id"] != self.identity.authority_id
                or envelope["host_id"] != self.identity.host_id
                or envelope["user_binding"] != self.identity.binding.as_dict()
                or envelope["provider_id"] not in {"codex", "claude"}
                or envelope["operation"] not in {"REGISTER_PROBE", "QUALIFY"}
            ):
                raise PermissionError("Provider Host unbound setup identity differs")
            self._validate_unbound_setup_executable(envelope)
            self._validate_setup_workspace(envelope)
            return
        if (
            envelope["authority_id"] != self.identity.authority_id
            or envelope["host_id"] != self.identity.host_id
            or envelope["user_binding"] != self.identity.binding.as_dict()
            or envelope["provider_id"] != provider.provider_id
            or envelope["provider_registration_id"] != provider.registration_id
            or envelope["executable"]["sha256"] != provider.executable_sha256
            or envelope["executable"]["size"] != provider.executable_size
            or envelope["executable"]["file_identity"]
            != dict(provider.file_identity)
            or envelope["executable"]["authenticode_binding"]
            != dict(provider.authenticode_binding)
            or envelope["executable"]["publisher"] != provider.publisher
            or envelope["executable"]["version"] != provider.version
            or envelope["model_id"] not in provider.models
            or (
                envelope["operation"] != "REGISTER_PROBE"
                and envelope["account_binding"].get(
                    "account_identity_digest"
                )
                != provider.account_id.partition(":")[2]
            )
        ):
            raise PermissionError("Provider Host setup binding differs")
        executable = Path(str(envelope["executable"]["path"]))
        expected = Path(provider.executable_path).resolve(strict=True)
        if (
            not executable.is_absolute()
            or os.path.normcase(os.path.abspath(str(executable)))
            != os.path.normcase(str(expected))
            or hashlib.sha256(expected.read_bytes()).hexdigest()
            != provider.executable_sha256
        ):
            raise PermissionError(
                "Provider Host setup executable path or hash differs"
            )
        self._validate_setup_workspace(envelope)

    def _preferred_provider_binding(self) -> ProviderBinding | None:
        for provider_id in ("codex", "claude"):
            for binding in self._provider_bindings.values():
                if binding.provider_id == provider_id:
                    return binding
        return next(iter(self._provider_bindings.values()), None)

    def _validate_unbound_setup_executable(
        self, envelope: Mapping[str, Any]
    ) -> None:
        executable_value = envelope["executable"]
        executable = Path(str(executable_value["path"]))
        canonical = executable.resolve(strict=True)
        profile = Path(self.identity.binding.profile_path).resolve(strict=True)
        try:
            canonical.relative_to(profile)
        except ValueError as error:
            raise PermissionError(
                "Unbound Provider Host executable is outside the enrolled profile"
            ) from error
        stat = canonical.stat()
        actual_identity = {
            "device_id": stat.st_dev,
            "file_id": stat.st_ino,
            "modified_ns": stat.st_mtime_ns,
            "schema_version": 1,
            "size": stat.st_size,
        }
        if (
            hashlib.sha256(canonical.read_bytes()).hexdigest()
            != executable_value["sha256"]
            or stat.st_size != executable_value["size"]
            or actual_identity != executable_value["file_identity"]
        ):
            raise PermissionError("Unbound Provider Host executable identity differs")

    def _validate_setup_workspace(self, envelope: Mapping[str, Any]) -> None:
        workspace = Path(str(envelope["workspace"]["canonical_path"]))
        setup_root = self._setup_workspace_root
        setup_root.mkdir(parents=True, exist_ok=True)
        canonical_root = setup_root.resolve(strict=True)
        expected_workspace = canonical_root / hashlib.sha256(
            str(envelope["setup_id"]).encode("utf-8")
        ).hexdigest()
        if (
            not workspace.is_absolute()
            or os.path.normcase(os.path.abspath(str(workspace)))
            != os.path.normcase(str(expected_workspace))
        ):
            raise PermissionError("Provider Host setup workspace differs")
        try:
            workspace.mkdir(exist_ok=False)
        except FileExistsError as error:
            raise PermissionError(
                "Provider Host setup workspace is replayed"
            ) from error
        if workspace.resolve(strict=True).parent != canonical_root:
            raise PermissionError("Provider Host setup workspace is unsafe")

    def _require_ready(self) -> None:
        if self.state is not HostState.READY:
            raise PermissionError(f"Provider Host state {self.state.value} rejects work")
        if self._store.list_active():
            raise PermissionError(
                "Provider Host unresolved durable launch state rejects work"
            )

    def _set_state(self, state: HostState, detail: str = "") -> None:
        self.state = state
        self._store.set_host_state(state.value, detail)
