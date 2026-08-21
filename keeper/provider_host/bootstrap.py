from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import (
    Any,
    Callable,
    Concatenate,
    Iterator,
    Mapping,
    ParamSpec,
    TypeVar,
    cast,
)

from keeper.app.database_lock import DatabaseFileLock, DatabaseMaintenanceBusyError
from keeper.provider_host.enrollment import (
    ENROLLMENT_PROOF_PURPOSE,
    ENROLLMENT_PROPOSAL_PURPOSE,
    MAXIMUM_ENROLLMENT_TTL,
    stable_host_identity,
    validate_enrollment_grant,
    validate_enrollment_receipt,
    validate_enrollment_revocation,
)
from keeper.provider_host.identity import UserBinding
from keeper.provider_host.install import (
    ProviderHostInstaller,
    ensure_provider_host_exchange_root,
)
from keeper.provider_host.protocol import (
    HOST_PROTOCOL,
    EnvelopeSigner,
    EnvelopeVerifier,
    structured_digest,
)
from keeper.provider_host.signing import RsaPublicIdentity
from keeper.recovery import atomic_write_json


_PENDING_SCHEMA = 1
_RUNTIME_SCHEMA = 2
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_LOCK_TIMEOUT_SECONDS = 30.0
_P = ParamSpec("_P")
_R = TypeVar("_R")


class ProviderHostCheckpointBusyError(RuntimeError):
    """A supported enrollment checkpoint transition is already in progress."""


def _checkpoint_locked(
    method: Callable[Concatenate["ProviderHostBootstrap", _P], _R],
) -> Callable[Concatenate["ProviderHostBootstrap", _P], _R]:
    @wraps(method)
    def locked(
        self: "ProviderHostBootstrap", *args: _P.args, **kwargs: _P.kwargs
    ) -> _R:
        with self.checkpoint_transaction():
            return method(self, *args, **kwargs)

    return cast(Callable[Concatenate["ProviderHostBootstrap", _P], _R], locked)


class ProviderHostBootstrap:
    """User-owned, execution-inert Provider Host enrollment bootstrap.

    The bootstrap can create and prove an enrollment identity, but it cannot
    bind or launch a provider.  Only an Authority-signed receipt can create the
    runtime configuration consumed by the Host.
    """

    def __init__(
        self,
        *,
        installer: ProviderHostInstaller,
        signer: EnvelopeSigner,
        user_binding: UserBinding,
        authority_protocol_version: int,
        authority_schema_version: int,
        service_key_id: str,
        authenticode_observer: Callable[[Path], Mapping[str, Any]],
        exchange_root_preparer: Callable[[Path, str], str] | None = None,
        authority_verifier_factory: (
            Callable[[Mapping[str, object]], EnvelopeVerifier] | None
        ) = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.installer = installer
        self.signer = signer
        self.user_binding = user_binding
        self.authority_protocol_version = authority_protocol_version
        self.authority_schema_version = authority_schema_version
        self.service_key_id = service_key_id
        self.authenticode_observer = authenticode_observer
        self.exchange_root_preparer = (
            exchange_root_preparer
            or (
                lambda path, owner_sid: ensure_provider_host_exchange_root(
                    path,
                    owner_sid=owner_sid,
                )
            )
        )
        self.authority_verifier_factory = authority_verifier_factory or (
            lambda value: RsaPublicIdentity.from_configuration(value).verifier()
        )
        self.now = now or (lambda: datetime.now(UTC))
        self.pending_path = installer.state / "provider-host-enrollment-pending.json"
        self.superseded_prefix = "provider-host-enrollment-superseded-"
        self.receipt_path = installer.state / "provider-host-enrollment.json"
        self.revocation_path = installer.state / "provider-host-enrollment-revoked.json"
        self.config_path = self.receipt_path
        self._checkpoint_lock_state = threading.local()

    @contextmanager
    def checkpoint_transaction(self) -> Iterator[None]:
        """Serialize one complete supported enrollment flow across processes.

        The operating-system byte-range lock is released automatically if the
        client process exits. Nested bootstrap transitions in the same flow are
        reentrant only on the owning thread.
        """
        depth = int(getattr(self._checkpoint_lock_state, "depth", 0))
        if depth:
            self._checkpoint_lock_state.depth = depth + 1
            try:
                yield
            finally:
                self._checkpoint_lock_state.depth = depth
            return
        try:
            with DatabaseFileLock(
                self.pending_path,
                "exclusive",
                timeout_seconds=_LOCK_TIMEOUT_SECONDS,
            ):
                self._checkpoint_lock_state.depth = 1
                try:
                    yield
                finally:
                    self._checkpoint_lock_state.depth = 0
        except DatabaseMaintenanceBusyError as exc:
            raise ProviderHostCheckpointBusyError(
                "Provider Host enrollment checkpoint is busy"
            ) from exc

    @_checkpoint_locked
    def create_proposal(self, *, generation: int) -> dict[str, Any]:
        if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
            raise ValueError("Provider Host enrollment generation is invalid")
        if self.receipt_path.is_file() and not self.revocation_path.is_file():
            raise PermissionError("Provider Host enrollment is already active")
        if self.pending_path.exists():
            pending = self._pending()
            if (
                pending.get("state") != "COMMITTED"
                or not self.revocation_path.exists()
            ):
                raise PermissionError(
                    "Provider Host enrollment checkpoint must be resolved before a new proposal"
                )
        current = self._installed_selection()
        executable = Path(str(current["artifact_path"]))
        installation = self._measure_installation(executable, current)
        public = _public_configuration(self.signer)
        if public.get("identity") != self.signer.identity:
            raise PermissionError("Provider Host signing identity differs")
        observed = self.now().astimezone(UTC)
        host_id = str(self.signer.identity)
        root = self.installer.root.resolve(strict=True)
        state_root = self.installer.state.resolve(strict=True)
        output_root = (
            Path(self.user_binding.profile_path)
            / "AppData"
            / "Local"
            / "DarkSage"
            / "KeeperProviderExchange"
        )
        self.exchange_root_preparer(
            output_root,
            self.user_binding.user_sid,
        )
        output_root = output_root.resolve(strict=True)
        pipe_suffix = hashlib.sha256(
            (host_id + ":" + self.user_binding.user_sid).encode("utf-8")
        ).hexdigest()[:24]
        payload = {
            "authority_protocol_version": self.authority_protocol_version,
            "authority_schema_version": self.authority_schema_version,
            "enrollment_generation": generation,
            "expires_at": (observed + MAXIMUM_ENROLLMENT_TTL).isoformat(),
            "host_id": host_id,
            "host_key_name": _signer_key_name(self.signer),
            "host_protocol": HOST_PROTOCOL,
            "host_public_identity": public,
            "installation": installation,
            "issued_at": observed.isoformat(),
            "output_root": str(output_root),
            "pipe_name": rf"\\.\pipe\KeeperProviderHost-{pipe_suffix}",
            "proposal_nonce": secrets.token_hex(32),
            "schema_version": 1,
            "service_key_id": self.service_key_id,
            "state_root": str(state_root),
            "user_binding": {
                "profile_path": self.user_binding.profile_path,
                "session_id": self.user_binding.session_id,
                "user_sid": self.user_binding.user_sid,
            },
        }
        proposal = self.signer.sign(ENROLLMENT_PROPOSAL_PURPOSE, payload)
        atomic_write_json(
            self.pending_path,
            {
                "schema_version": _PENDING_SCHEMA,
                "state": "PROPOSED",
                "proposal": proposal,
                "proposal_digest": structured_digest(proposal),
                "grant": None,
                "grant_digest": None,
                "founder_capability": None,
                "proof": None,
                "proof_digest": None,
            },
        )
        return proposal

    @_checkpoint_locked
    def prepare_new_enrollment(
        self, authority_status: Mapping[str, object]
    ) -> dict[str, Any] | None:
        """Durably supersede only a rejected proposal for an older Host package.

        The Authority status is obtained through the supported protocol before
        this method is called.  Any Authority enrollment record, local grant,
        proof, receipt, same-package proposal, or ambiguous checkpoint blocks a
        new enrollment.  The complete prior checkpoint is archived before its
        active-path name is removed.
        """
        no_enrollment_status = {
            "founder_action_required": "INSTALL_PROVIDER_HOST",
            "installed": False,
            "online": False,
            "protocol": "keeper-provider-host/1",
            "protocol_compatible": True,
            "provider_state": "UNAVAILABLE",
            "state": "NOT_INSTALLED",
        }
        if not self.pending_path.exists():
            return None
        pending = self._pending()
        if pending.get("state") == "COMMITTED" and self.revocation_path.exists():
            return None
        if pending.get("state") != "PROPOSED":
            raise PermissionError(
                "Provider Host enrollment checkpoint cannot be superseded"
            )
        current = self._installed_selection()
        status = dict(authority_status)
        founder_capability = pending.get("founder_capability")
        inert_unauthorized = (
            founder_capability is None
            and pending.get("grant") is None
            and pending.get("grant_digest") is None
            and pending.get("proof") is None
            and pending.get("proof_digest") is None
        )
        founder_authorized = (
            isinstance(founder_capability, dict)
            and pending.get("grant") is None
            and pending.get("grant_digest") is None
            and pending.get("proof") is None
            and pending.get("proof_digest") is None
        )
        if not inert_unauthorized and not founder_authorized:
            raise PermissionError(
                "Provider Host enrollment checkpoint cannot be superseded"
            )
        if status == no_enrollment_status:
            if self.receipt_path.exists() or self.revocation_path.exists():
                raise PermissionError(
                    "Provider Host enrollment receipt state is unresolved"
                )
            if inert_unauthorized:
                reason = "UNAUTHORIZED_PROPOSAL_INTERRUPTED"
                require_changed_package = False
            else:
                reason = "PACKAGE_CHANGED_AFTER_AUTHORITY_REJECTION"
                require_changed_package = True
        else:
            if not self.receipt_path.exists() or not self.revocation_path.exists():
                raise PermissionError(
                    "Authority does not prove the prior Host enrollment was rejected"
                )
            revocation_record = _object(
                json.loads(self.revocation_path.read_text(encoding="utf-8")),
                "stored enrollment revocation",
            )
            revocation_payload = _object(
                revocation_record.get("payload"), "stored enrollment revocation payload"
            )
            if (
                status.get("state") != "REVOKED"
                or status.get("installed") is not True
                or status.get("online") is not False
                or status.get("protocol") != "keeper-provider-host/1"
                or status.get("protocol_compatible") is not True
                or status.get("provider_state") != "UNAVAILABLE"
                or status.get("founder_action_required")
                != "CREATE_NEW_PROVIDER_HOST_ENROLLMENT"
                or status.get("enrollment_id")
                != revocation_payload.get("enrollment_id")
                or status.get("enrollment_generation")
                != revocation_payload.get("enrollment_generation")
                or set(status)
                != {
                    "enrollment_generation",
                    "enrollment_id",
                    "founder_action_required",
                    "installed",
                    "online",
                    "protocol",
                    "protocol_compatible",
                    "provider_state",
                    "state",
                }
            ):
                raise PermissionError(
                    "Authority does not prove the prior Host enrollment was rejected"
                )
            if inert_unauthorized:
                reason = "UNAUTHORIZED_REENROLLMENT_PROPOSAL_INTERRUPTED"
            else:
                reason = "NEW_GENERATION_REJECTED_WHILE_PRIOR_ENROLLMENT_REVOKED"
            require_changed_package = False
        proposal = _object(pending.get("proposal"), "stored proposal")
        proposal_digest = structured_digest(proposal)
        if pending.get("proposal_digest") != proposal_digest:
            raise PermissionError("Provider Host proposal digest differs")
        payload = _object(proposal.get("payload"), "stored proposal payload")
        installation = _object(
            payload.get("installation"), "stored proposal installation"
        )
        user_binding = _object(
            payload.get("user_binding"), "stored proposal user binding"
        )
        current_user_binding = self.user_binding.as_dict()
        session_rollover = (
            founder_authorized
            and status == no_enrollment_status
            and require_changed_package
            and _same_user_profile_session_rollover(
                user_binding, current_user_binding
            )
        )
        old_manifest = installation.get("manifest_sha256")
        if (
            (user_binding != current_user_binding and not session_rollover)
            or payload.get("authority_protocol_version")
            != self.authority_protocol_version
            or payload.get("authority_schema_version")
            != self.authority_schema_version
            or payload.get("service_key_id") != self.service_key_id
            or installation.get("install_root")
            != str(self.installer.root.resolve(strict=True))
            or not isinstance(old_manifest, str)
            or len(old_manifest) != 64
            or any(character not in "0123456789abcdef" for character in old_manifest)
            or (
                require_changed_package
                and old_manifest == current.get("package_sha256")
            )
        ):
            raise PermissionError(
                "Provider Host stale enrollment package binding differs"
            )
        if session_rollover:
            reason = "PACKAGE_AND_SESSION_CHANGED_AFTER_AUTHORITY_REJECTION"
        public = _object(
            payload.get("host_public_identity"), "stored Host public identity"
        )
        if (
            payload.get("host_id") != public.get("identity")
            or not isinstance(public.get("key_id"), str)
            or not public.get("key_id")
        ):
            raise PermissionError("Provider Host stale enrollment identity differs")
        if getattr(self.signer, "production", False):
            expected_host_id, expected_key_name = stable_host_identity(
                self.user_binding.user_sid, old_manifest
            )
            if (
                payload.get("host_id") != expected_host_id
                or payload.get("host_key_name") != expected_key_name
            ):
                raise PermissionError(
                    "Provider Host stale enrollment package identity differs"
                )
        prior_digest = structured_digest(pending)
        archive = self.installer.state / (
            self.superseded_prefix + proposal_digest + ".json"
        )
        record = {
            "schema_version": 1,
            "state": "SUPERSEDED",
            "reason": reason,
            "superseded_at": self.now().astimezone(UTC).isoformat(),
            "authority_status": dict(authority_status),
            "prior_checkpoint": pending,
            "prior_checkpoint_digest": prior_digest,
            "prior_manifest_sha256": old_manifest,
            "replacement_manifest_sha256": str(current["package_sha256"]),
        }
        if session_rollover:
            record["session_rollover"] = {
                "prior_user_binding": dict(user_binding),
                "replacement_user_binding": dict(current_user_binding),
            }
        if archive.exists():
            existing = _object(
                json.loads(archive.read_text(encoding="utf-8")),
                "superseded enrollment record",
            )
            if (
                existing.get("schema_version") != 1
                or existing.get("state") != "SUPERSEDED"
                or existing.get("reason") != reason
                or existing.get("prior_checkpoint_digest") != prior_digest
                or existing.get("prior_checkpoint") != pending
                or existing.get("authority_status") != dict(authority_status)
                or existing.get("prior_manifest_sha256") != old_manifest
                or existing.get("replacement_manifest_sha256")
                != current.get("package_sha256")
                or (
                    session_rollover
                    and existing.get("session_rollover")
                    != record["session_rollover"]
                )
                or (
                    not session_rollover
                    and "session_rollover" in existing
                )
            ):
                raise PermissionError(
                    "Provider Host superseded enrollment record differs"
                )
            record = existing
        else:
            atomic_write_json(archive, record)
            verified = _object(
                json.loads(archive.read_text(encoding="utf-8")),
                "superseded enrollment record",
            )
            if verified != record:
                raise PermissionError(
                    "Provider Host superseded enrollment record did not persist"
                )
        current_pending = self._pending("PROPOSED")
        if (
            current_pending != pending
            or structured_digest(current_pending) != prior_digest
        ):
            raise PermissionError(
                "Provider Host enrollment checkpoint changed during supersession"
            )
        self.pending_path.unlink()
        return {
            "state": "SUPERSEDED",
            "proposal_digest": proposal_digest,
            "prior_checkpoint_digest": prior_digest,
            "archive_path": str(archive),
        }

    @_checkpoint_locked
    def store_founder_capability(
        self, capability: Mapping[str, object]
    ) -> None:
        pending = self._pending("PROPOSED")
        # Canonical serialization rejects non-JSON and non-finite values before
        # the one-use signed capability enters the ACL-bound checkpoint.
        structured_digest(capability)
        atomic_write_json(
            self.pending_path,
            {**pending, "founder_capability": dict(capability)},
        )

    @_checkpoint_locked
    def abandon_unauthorized_proposal(self, proposal_digest: str) -> None:
        """Remove only an inert proposal for which Founder auth did not succeed."""
        pending = self._pending("PROPOSED")
        if (
            pending.get("proposal_digest") != proposal_digest
            or pending.get("founder_capability") is not None
            or pending.get("grant") is not None
            or pending.get("proof") is not None
        ):
            raise PermissionError(
                "Provider Host unauthorized proposal cleanup binding differs"
            )
        self.pending_path.unlink()

    @_checkpoint_locked
    def authorization_material(
        self,
    ) -> tuple[dict[str, object], dict[str, object]]:
        pending = self._pending("PROPOSED")
        proposal = _object(pending.get("proposal"), "stored proposal")
        capability = _object(
            pending.get("founder_capability"), "stored Founder capability"
        )
        return proposal, capability

    @_checkpoint_locked
    def prove_grant(self, grant_record: Mapping[str, Any]) -> dict[str, Any]:
        pending = self._pending("PROPOSED")
        unsigned = _object(grant_record.get("payload"), "enrollment grant payload")
        authority_public = _object(
            unsigned.get("authority_public_identity"), "Authority public identity"
        )
        verifier = self.authority_verifier_factory(authority_public)
        grant = validate_enrollment_grant(grant_record, verifier, now=self.now())
        proposal = _object(pending["proposal"], "pending proposal")
        proposal_payload = _object(proposal["payload"], "pending proposal payload")
        if (
            grant.get("proposal_digest") != pending["proposal_digest"]
            or grant.get("host_id") != proposal_payload.get("host_id")
            or grant.get("service_key_id") != proposal_payload.get("service_key_id")
            or grant.get("authority_protocol_version")
            != proposal_payload.get("authority_protocol_version")
            or grant.get("authority_schema_version")
            != proposal_payload.get("authority_schema_version")
            or grant.get("enrollment_generation")
            != proposal_payload.get("enrollment_generation")
        ):
            raise PermissionError("Provider Host enrollment grant binding differs")
        grant_digest = structured_digest(grant_record)
        proof_payload = {
            "authority_id": str(grant["authority_id"]),
            "challenge": str(grant["challenge"]),
            "enrollment_generation": int(grant["enrollment_generation"]),
            "enrollment_id": str(grant["enrollment_id"]),
            "grant_digest": grant_digest,
            "host_id": str(proposal_payload["host_id"]),
            "host_public_key_id": self.signer.key_id,
            "issued_at": self.now().astimezone(UTC).isoformat(),
            "nonce": secrets.token_hex(32),
            "proposal_digest": str(pending["proposal_digest"]),
            "sequence": int(grant["sequence"]),
        }
        proof = self.signer.sign(ENROLLMENT_PROOF_PURPOSE, proof_payload)
        atomic_write_json(
            self.pending_path,
            {
                **pending,
                "state": "PROVED",
                "grant": dict(grant_record),
                "grant_digest": grant_digest,
                "proof": proof,
                "proof_digest": structured_digest(proof),
            },
        )
        return proof

    @_checkpoint_locked
    def commit_receipt(self, receipt_record: Mapping[str, Any]) -> dict[str, Any]:
        pending = self._pending("PROVED")
        grant_record = _object(pending["grant"], "pending grant")
        grant_payload = _object(grant_record["payload"], "pending grant payload")
        authority_public = _object(
            grant_payload["authority_public_identity"], "Authority public identity"
        )
        verifier = self.authority_verifier_factory(authority_public)
        receipt = validate_enrollment_receipt(
            receipt_record,
            verifier,
            expected_enrollment_id=str(grant_payload["enrollment_id"]),
        )
        proposal = _object(pending["proposal"], "pending proposal")
        proposal_payload = _object(proposal["payload"], "pending proposal payload")
        proof = _object(pending["proof"], "pending proof")
        if (
            receipt.get("proposal_digest") != pending["proposal_digest"]
            or receipt.get("grant_digest") != pending["grant_digest"]
            or receipt.get("proof_digest") != pending["proof_digest"]
            or receipt.get("host_id") != proposal_payload.get("host_id")
            or receipt.get("host_public_key_id") != self.signer.key_id
            or receipt.get("service_key_id") != self.service_key_id
        ):
            raise PermissionError("Provider Host enrollment receipt binding differs")
        runtime = _object(receipt["runtime_configuration"], "runtime configuration")
        runtime_matches = {
            "authority_id": grant_payload.get("authority_id"),
            "authority_public_identity": grant_payload.get(
                "authority_public_identity"
            ),
            "enrollment_id": grant_payload.get("enrollment_id"),
            "host_id": proposal_payload.get("host_id"),
            "host_key_name": proposal_payload.get("host_key_name"),
            "host_public_identity": proposal_payload.get("host_public_identity"),
            "output_root": proposal_payload.get("output_root"),
            "pipe_name": proposal_payload.get("pipe_name"),
            "state_root": proposal_payload.get("state_root"),
            "user_binding": proposal_payload.get("user_binding"),
        }
        if any(runtime.get(name) != expected for name, expected in runtime_matches.items()):
            raise PermissionError("Provider Host runtime identity differs")
        # Receipt and configuration are committed separately but both are signed,
        # exact, and idempotently recoverable from the durable receipt.
        atomic_write_json(self.receipt_path, dict(receipt_record))
        # A prior Authority-signed revocation remains a fail-closed Startup gate
        # until this exact newer receipt has been durably written.
        self.revocation_path.unlink(missing_ok=True)
        atomic_write_json(
            self.pending_path,
            {
                **pending,
                "state": "COMMITTED",
                "receipt": dict(receipt_record),
                "receipt_digest": structured_digest(receipt_record),
                "proof": proof,
            },
        )
        return {
            "enrollment_id": str(receipt["enrollment_id"]),
            "state": "ACTIVE",
            "receipt_digest": structured_digest(receipt_record),
            "config_path": str(self.config_path),
        }

    @_checkpoint_locked
    def commit_revocation(
        self, revocation_record: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Persist the exact Authority-signed denial before Startup can run."""
        receipt_record = _object(
            json.loads(self.receipt_path.read_text(encoding="utf-8")),
            "stored receipt",
        )
        receipt_unsigned = _object(
            receipt_record.get("payload"), "stored receipt payload"
        )
        runtime = _object(
            receipt_unsigned.get("runtime_configuration"),
            "stored runtime configuration",
        )
        authority_public = _object(
            runtime.get("authority_public_identity"), "Authority public identity"
        )
        verifier = self.authority_verifier_factory(authority_public)
        revocation = validate_enrollment_revocation(
            revocation_record,
            verifier,
            expected_enrollment_id=str(receipt_unsigned.get("enrollment_id", "")),
            expected_receipt_digest=structured_digest(receipt_record),
        )
        if (
            revocation.get("host_id") != receipt_unsigned.get("host_id")
            or revocation.get("service_key_id")
            != receipt_unsigned.get("service_key_id")
            or revocation.get("authority_id")
            != receipt_unsigned.get("authority_id")
        ):
            raise PermissionError("Provider Host enrollment revocation binding differs")
        atomic_write_json(self.revocation_path, dict(revocation_record))
        return {
            "enrollment_id": str(revocation["enrollment_id"]),
            "state": "REVOKED",
            "revoked_at": str(revocation["revoked_at"]),
        }

    @_checkpoint_locked
    def status(self) -> dict[str, Any]:
        installed = self.installer.status()
        if not installed["installed"]:
            return {
                "installed": False,
                "state": "NOT_INSTALLED",
                "provider_state": "UNAVAILABLE",
            }
        if not self.pending_path.is_file():
            return {
                "installed": True,
                "state": "INSTALLED_UNENROLLED",
                "provider_state": "NO_QUALIFIED_PROVIDERS",
            }
        if self.revocation_path.is_file():
            return {
                "installed": True,
                "state": "REVOKED",
                "provider_state": "UNAVAILABLE",
                "founder_action_required": "CREATE_NEW_PROVIDER_HOST_ENROLLMENT",
            }
        pending = self._pending()
        state = str(pending["state"])
        return {
            "installed": True,
            "state": {
                "PROPOSED": "ENROLLMENT_PROPOSED",
                "PROVED": "ENROLLMENT_PROOF_READY",
                "COMMITTED": "ENROLLED_OFFLINE",
            }[state],
            "provider_state": "NO_QUALIFIED_PROVIDERS",
            "proposal_digest": pending["proposal_digest"],
            "receipt_digest": pending.get("receipt_digest"),
        }

    @_checkpoint_locked
    def reconciliation_material(self) -> tuple[str, dict[str, object]]:
        pending = self._pending("PROVED")
        grant = _object(pending.get("grant"), "stored grant")
        grant_payload = _object(grant.get("payload"), "stored grant payload")
        proof = _object(pending.get("proof"), "stored proof")
        return str(grant_payload["enrollment_id"]), proof

    def _installed_selection(self) -> dict[str, object]:
        status = self.installer.status()
        current = status.get("current")
        if status.get("transaction_pending") or not isinstance(current, dict):
            raise PermissionError("Provider Host installation is not stable")
        return dict(current)

    def _measure_installation(
        self, executable: Path, current: Mapping[str, object]
    ) -> dict[str, Any]:
        root = self.installer.root.resolve(strict=True)
        canonical = executable.resolve(strict=True)
        _require_canonical_tree(canonical, root)
        stat = canonical.stat()
        digest = _digest(canonical)
        if digest != current.get("artifact_sha256") or stat.st_size <= 0:
            raise PermissionError("Provider Host installed executable differs")
        authenticode = dict(self.authenticode_observer(canonical))
        return {
            "authenticode_binding": authenticode,
            "executable_file_identity": {
                "device_id": int(stat.st_dev),
                "file_id": int(stat.st_ino),
                "modified_ns": int(stat.st_mtime_ns),
                "schema_version": 1,
                "size": int(stat.st_size),
            },
            "executable_path": str(canonical),
            "executable_sha256": digest,
            "executable_size": int(stat.st_size),
            "install_root": str(root),
            "manifest_sha256": str(current["package_sha256"]),
            "package_version": str(current["version"]),
        }

    def _pending(self, expected: str | None = None) -> dict[str, Any]:
        try:
            value = json.loads(self.pending_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PermissionError("Provider Host enrollment checkpoint is unavailable") from error
        valid_states = {"PROPOSED", "PROVED", "COMMITTED"}
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != _PENDING_SCHEMA
            or value.get("state") not in valid_states
            or (expected is not None and value.get("state") != expected)
        ):
            raise PermissionError("Provider Host enrollment checkpoint is invalid")
        return cast(dict[str, Any], value)


def build_production_bootstrap(
    installer: ProviderHostInstaller,
    diagnostics: Mapping[str, Any],
) -> ProviderHostBootstrap:
    """Construct the supported production bootstrap from authenticated diagnostics."""
    from keeper.authority_service.windows_signature import (
        authenticode_enrollment_binding,
    )
    from keeper.provider_host.identity import current_user_binding
    from keeper.provider_host.signing import WindowsCngEnvelopeIdentity

    protocol = diagnostics.get("protocol_version")
    schema = diagnostics.get("schema_version")
    service_key_id = diagnostics.get("service_key_id")
    if (
        isinstance(protocol, bool)
        or not isinstance(protocol, int)
        or protocol <= 0
        or isinstance(schema, bool)
        or not isinstance(schema, int)
        or schema <= 0
        or not isinstance(service_key_id, str)
        or not service_key_id
    ):
        raise PermissionError("Provider Host Authority diagnostics are incomplete")
    status = installer.status()
    current = status.get("current")
    if not isinstance(current, dict):
        raise PermissionError("Provider Host is not installed")
    binding = current_user_binding()
    host_id, key_name = stable_host_identity(
        binding.user_sid, str(current["package_sha256"])
    )
    signer = WindowsCngEnvelopeIdentity(
        identity=host_id,
        key_name=key_name,
        machine_key=False,
        owner_sid=binding.user_sid,
    )
    return ProviderHostBootstrap(
        installer=installer,
        signer=signer,
        user_binding=binding,
        authority_protocol_version=protocol,
        authority_schema_version=schema,
        service_key_id=service_key_id,
        authenticode_observer=authenticode_enrollment_binding,
    )


def _same_user_profile_session_rollover(
    prior: Mapping[str, object], current: Mapping[str, object]
) -> bool:
    """Accept only an interactive-session change for one exact local principal."""
    expected = {"profile_path", "session_id", "user_sid"}
    prior_session = prior.get("session_id")
    current_session = current.get("session_id")
    return (
        set(prior) == expected
        and set(current) == expected
        and isinstance(prior_session, int)
        and not isinstance(prior_session, bool)
        and prior_session >= 0
        and isinstance(current_session, int)
        and not isinstance(current_session, bool)
        and current_session >= 0
        and prior_session != current_session
        and prior.get("user_sid") == current.get("user_sid")
        and prior.get("profile_path") == current.get("profile_path")
    )


def _public_configuration(signer: EnvelopeSigner) -> dict[str, object]:
    method = getattr(signer, "public_configuration", None)
    if not callable(method):
        raise TypeError("Provider Host signer has no public configuration")
    value = method()
    if not isinstance(value, dict):
        raise TypeError("Provider Host signer public configuration is invalid")
    return dict(cast(dict[str, object], value))


def _signer_key_name(signer: EnvelopeSigner) -> str:
    value = getattr(signer, "key_name", None)
    if not isinstance(value, str) or not value:
        # Test identities do not own a CNG key name; their key ID is still exact.
        value = signer.key_id
    return value


def _require_canonical_tree(path: Path, root: Path) -> None:
    canonical_root = root.resolve(strict=True)
    canonical = path.resolve(strict=True)
    if canonical != canonical_root and canonical_root not in canonical.parents:
        raise PermissionError("Provider Host path escapes the installed root")
    current = canonical_root
    relative = canonical.relative_to(canonical_root)
    for component in relative.parts:
        current /= component
        stat = current.lstat()
        if current.is_symlink() or bool(
            getattr(stat, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise PermissionError("Provider Host path contains an alias")


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PermissionError(f"Provider Host {label} is invalid")
    return dict(cast(dict[str, Any], value))
