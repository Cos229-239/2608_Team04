from __future__ import annotations

import hashlib
import os
import re
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Mapping, cast

from keeper.provider_host.identity import (
    PipePeerIdentity,
    ProviderHostIdentityUncertain,
    authenticated_named_pipe_client_identity,
    require_peer_identity,
)
from keeper.provider_host.pipe import (
    connected_client_pipe,
    connected_server_pipe,
    read_frame,
    write_frame,
)
from keeper.provider_host.protocol import (
    HELLO_PURPOSE,
    REQUEST_PURPOSE,
    RESPONSE_PURPOSE,
    STARTED_ACK_PURPOSE,
    STARTED_PURPOSE,
    EnvelopeSigner,
    EnvelopeVerifier,
    canonical_json,
    parse_utc,
    structured_digest,
)
from keeper.provider_host.replay_store import ProviderHostStore
from keeper.provider_host.runtime import KeeperProviderHost, Launcher, SetupRunner


_LISTENER_STARTUP_TIMEOUT_SECONDS = 5.0
_SERVICE_SID = re.compile(r"S-1-5-80-(?:\d+-){4}\d+")


class ProviderHostServer:
    """Local-only authenticated Provider Host named-pipe server."""

    def __init__(
        self,
        *,
        pipe_name: str,
        runtime: KeeperProviderHost,
        launcher: Launcher,
        setup_runner: SetupRunner,
        authority_verifier: EnvelopeVerifier,
        host_signer: EnvelopeSigner,
        store: ProviderHostStore,
        authority_peer: PipePeerIdentity,
        authority_service_sid: str,
        authority_executable: Path,
        authority_executable_sha256: str,
        authority_executable_file_identity: tuple[int, int, int, int],
        host_executable_attestation: Mapping[str, object],
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.pipe_name = pipe_name
        self.runtime = runtime
        self.launcher = launcher
        self.setup_runner = setup_runner
        self.authority_verifier = authority_verifier
        self.host_signer = host_signer
        self.store = store
        self.authority_peer = authority_peer
        if not _SERVICE_SID.fullmatch(authority_service_sid):
            raise PermissionError("Provider Host Authority service SID is invalid")
        self.authority_service_sid = authority_service_sid
        if not authority_executable.is_absolute():
            raise PermissionError("Provider Host Authority path is invalid")
        self.authority_executable = Path(
            os.path.abspath(str(authority_executable))
        )
        self.authority_executable_sha256 = authority_executable_sha256
        self.authority_executable_file_identity = (
            authority_executable_file_identity
        )
        self.host_executable_attestation = dict(host_executable_attestation)
        if (
            set(self.host_executable_attestation) != {"file_identity", "sha256"}
            or not isinstance(self.host_executable_attestation["sha256"], str)
            or len(str(self.host_executable_attestation["sha256"])) != 64
            or not isinstance(
                self.host_executable_attestation["file_identity"], dict
            )
        ):
            raise PermissionError("Provider Host executable attestation is invalid")
        self.now = now or (lambda: datetime.now(UTC))
        self._stop = threading.Event()
        self._first = True
        self._workers: list[threading.Thread] = []
        self._listener_ready = threading.Event()
        self._fatal_lock = threading.Lock()
        self._fatal_error: BaseException | None = None

    def serve_forever(self) -> None:
        first = threading.Thread(
            target=self._accept_once,
            args=(True,),
            name="KeeperProviderHostAccept",
            daemon=True,
        )
        self._workers.append(first)
        first.start()
        deadline = time.monotonic() + _LISTENER_STARTUP_TIMEOUT_SECONDS
        while not self._listener_ready.is_set():
            self._raise_fatal_error()
            if self._stop.wait(0.01):
                self._raise_fatal_error()
                return
            if time.monotonic() >= deadline:
                self._record_fatal_error(
                    TimeoutError("Provider Host listener startup timed out")
                )
                self._raise_fatal_error()
        while not self._stop.wait(0.25):
            self._workers = [worker for worker in self._workers if worker.is_alive()]
            self._raise_fatal_error()
        self._raise_fatal_error()

    def stop(self) -> None:
        self._stop.set()
        self.runtime.drain()
        try:
            with connected_client_pipe(self.pipe_name, timeout_seconds=0.25):
                pass
        except (OSError, TimeoutError):
            pass

    def _accept_once(self, first_instance: bool) -> None:
        successor_started = False
        try:
            with connected_server_pipe(
                self.pipe_name,
                user_sid=self.runtime.identity.binding.user_sid,
                authority_service_sid=self.authority_service_sid,
                first_instance=first_instance,
                created_observer=(
                    self._listener_ready.set if first_instance else None
                ),
            ) as pipe:
                if self._stop.is_set():
                    return
                successor = threading.Thread(
                    target=self._accept_once,
                    args=(False,),
                    name="KeeperProviderHostAccept",
                    daemon=True,
                )
                self._workers.append(successor)
                successor.start()
                successor_started = True
                self._serve_connection(pipe)
        except ProviderHostIdentityUncertain as error:
            # An identity worker that cannot prove bounded completion or clean
            # reversion must fail-stop this Host process.  It may not accept a
            # second Authority connection under uncertain thread identity.
            self._record_fatal_error(error)
            raise
        except BaseException as error:
            # A listener that fails before its successor is running leaves no
            # endpoint for Authority. Publish the first exact failure to the
            # main Host loop instead of leaving an alive, listenerless process.
            if not successor_started:
                self._record_fatal_error(error)
                return
            raise

    def _record_fatal_error(self, error: BaseException) -> None:
        with self._fatal_lock:
            if self._fatal_error is None:
                self._fatal_error = error
        self._stop.set()

    def _raise_fatal_error(self) -> None:
        with self._fatal_lock:
            error = self._fatal_error
        if error is not None:
            raise error

    def _serve_connection(self, pipe: int) -> None:
        # Windows permits ImpersonateNamedPipeClient only after this server has
        # read from the connected client.  Verify the signed hello in memory,
        # but do not claim it, write a response, sign, or touch runtime state
        # until the exact Authority process image has been measured.
        hello_record = read_frame(pipe)
        hello = self.authority_verifier.verify(
            hello_record, purpose=HELLO_PURPOSE
        )
        if (
            hello.get("authority_executable_path")
            != str(self.authority_executable)
            or hello.get("authority_executable_sha256")
            != self.authority_executable_sha256
            or hello.get("authority_executable_file_identity")
            != _file_identity_record(self.authority_executable_file_identity)
        ):
            raise PermissionError("Provider Host Authority hello attestation differs")
        observed = authenticated_named_pipe_client_identity(
            pipe,
            expected_service_sid=self.authority_service_sid,
            expected=PipePeerIdentity(
                process_id=0,
                session_id=self.authority_peer.session_id,
                user_sid=self.authority_peer.user_sid,
                executable_path=str(self.authority_executable),
                executable_sha256=self.authority_executable_sha256,
                executable_file_identity=(
                    self.authority_executable_file_identity
                ),
            ),
        )
        require_peer_identity(
            observed,
            session_id=self.authority_peer.session_id,
            user_sid=self.authority_peer.user_sid,
            executable_path=self.authority_executable,
            executable_sha256=self.authority_executable_sha256,
            executable_file_identity=self.authority_executable_file_identity,
        )
        self._claim_message("hello", hello)
        if (
            set(hello)
            != {
                "authority_id",
                "authority_executable_file_identity",
                "authority_executable_path",
                "authority_executable_sha256",
                "authority_process_id",
                "expires_at",
                "host_id",
                "issued_at",
                "nonce",
                "sequence",
            }
            or hello.get("authority_id") != self.runtime.identity.authority_id
            or hello.get("host_id") != self.runtime.identity.host_id
            or hello.get("authority_process_id") != observed.process_id
        ):
            raise PermissionError("Provider Host hello binding is invalid")
        host_nonce = uuid.uuid4().hex
        write_frame(
            pipe,
            self.host_signer.sign(
                HELLO_PURPOSE,
                {
                    "authority_nonce": hello["nonce"],
                    "host_id": self.runtime.identity.host_id,
                    "host_nonce": host_nonce,
                    "host_process_id": os.getpid(),
                    "host_executable_file_identity": (
                        self.host_executable_attestation["file_identity"]
                    ),
                    "host_executable_sha256": (
                        self.host_executable_attestation["sha256"]
                    ),
                    "state": self.runtime.state.value,
                    "user_binding": self.runtime.identity.binding.as_dict(),
                },
            ),
        )
        request_record = read_frame(pipe)
        request = self.authority_verifier.verify(
            request_record, purpose=REQUEST_PURPOSE
        )
        self._claim_message("request", request)
        operation, body = _validated_request(request, hello, host_nonce)
        result: dict[str, Any] | None
        if operation == "prepare_environment":
            provider_bin = body.get("provider_bin")
            provider_registration_id = body.get("provider_registration_id")
            if not isinstance(provider_bin, str) or not provider_bin:
                raise PermissionError("Provider Host provider bin is absent")
            if provider_registration_id is not None and (
                not isinstance(provider_registration_id, str)
                or not provider_registration_id
            ):
                raise PermissionError(
                    "Provider Host environment registration is invalid"
                )
            result = self.runtime.prepare_environment(
                preparation_nonce=str(body["preparation_nonce"]),
                provider_bin=Path(provider_bin),
                provider_registration_id=provider_registration_id,
            )
        elif operation == "bind_provider":
            provider_binding = body.get("provider_binding")
            if not isinstance(provider_binding, dict):
                raise PermissionError("Provider Host provider binding is absent")
            result = self.runtime.bind_provider(provider_binding)
        elif operation == "reconcile_uncertain_launch":
            signed_reconciliation = body.get("signed_reconciliation")
            if not isinstance(signed_reconciliation, dict):
                raise PermissionError(
                    "Provider Host signed launch reconciliation is absent"
                )
            result = self.runtime.reconcile_uncertain_launch(
                signed_reconciliation
            )
        elif operation == "terminal_setup_result":
            if set(body) != {"setup_id"} or not isinstance(
                body.get("setup_id"), str
            ):
                raise PermissionError(
                    "Provider Host terminal setup result request is invalid"
                )
            result = self.runtime.terminal_setup_result(str(body["setup_id"]))
        elif operation in {"execute", "setup"}:
            signed_envelope = body.get("signed_envelope")
            if not isinstance(signed_envelope, dict):
                raise PermissionError("Provider Host signed envelope is absent")

            def started(observation: dict[str, object]) -> None:
                event = self.host_signer.sign(
                    STARTED_PURPOSE,
                    {
                        "authority_attempt_id": body["authority_attempt_id"],
                        "launch_id": body["launch_id"],
                        "observation": observation,
                    },
                )
                write_frame(pipe, {"event": "STARTED", "record": event})
                ack_record = read_frame(pipe)
                ack = self.authority_verifier.verify(
                    ack_record, purpose=STARTED_ACK_PURPOSE
                )
                _validate_started_ack(
                    ack,
                    authority_attempt_id=str(body["authority_attempt_id"]),
                    authority_id=self.runtime.identity.authority_id,
                    event_digest=structured_digest(event),
                    launch_id=str(body["launch_id"]),
                )
                self._claim_message("started-ack", ack)

            if operation == "execute":
                result = self.runtime.execute(
                    signed_envelope,
                    self.launcher,
                    started_observer=started,
                )
            else:
                result = self.runtime.execute_setup(
                    signed_envelope,
                    self.setup_runner,
                    started_observer=started,
                )
        elif operation == "cancel":
            result = {
                "cancel_requested": self.runtime.cancel_active(
                    str(body.get("authority_attempt_id", "")),
                    str(body.get("launch_id", "")),
                )
            }
        elif operation == "status":
            result = self.runtime.status()
        elif operation == "lock":
            self.runtime.lock_workstation()
            result = self.runtime.status()
        elif operation == "drain":
            self.runtime.drain()
            result = self.runtime.status()
        else:
            raise PermissionError("Provider Host operation is unsupported")
        write_frame(
            pipe,
            self.host_signer.sign(
                RESPONSE_PURPOSE,
                {
                    "authority_nonce": hello["nonce"],
                    "host_nonce": host_nonce,
                    "operation": operation,
                    "request_digest": structured_digest(request_record),
                    "result": result,
                },
            ),
        )

    def _claim_message(self, channel: str, value: Mapping[str, Any]) -> None:
        required = {"authority_id", "expires_at", "issued_at", "nonce", "sequence"}
        if not required.issubset(value):
            raise PermissionError("Provider Host peer message lifetime is absent")
        self.store.claim_peer_message(
            channel=channel,
            authority_id=str(value["authority_id"]),
            nonce=str(value["nonce"]),
            sequence=int(value["sequence"]),
            issued_at=str(value["issued_at"]),
            expires_at=str(value["expires_at"]),
            now=self.now(),
            maximum_ttl=timedelta(minutes=2),
            maximum_future_skew=timedelta(seconds=5),
        )


def _file_identity_record(
    value: tuple[int, int, int, int],
) -> dict[str, int]:
    device, inode, size, modified_ns = value
    if min(device, inode, size, modified_ns) < 0 or inode == 0:
        raise PermissionError("Provider Host Authority file identity is invalid")
    return {
        "device_id": device,
        "file_id": inode,
        "modified_ns": modified_ns,
        "schema_version": 1,
        "size": size,
    }


def _validate_started_ack(
    value: Mapping[str, Any],
    *,
    authority_attempt_id: str,
    authority_id: str,
    event_digest: str,
    launch_id: str,
) -> None:
    if (
        set(value)
        != {
            "authority_attempt_id",
            "authority_id",
            "event_digest",
            "expires_at",
            "issued_at",
            "launch_id",
            "nonce",
            "sequence",
        }
        or value.get("authority_attempt_id") != authority_attempt_id
        or value.get("authority_id") != authority_id
        or value.get("launch_id") != launch_id
        or value.get("event_digest") != event_digest
    ):
        raise PermissionError("Provider Host STARTED acknowledgement differs")


def _validated_request(
    value: Mapping[str, Any], hello: Mapping[str, Any], host_nonce: str
) -> tuple[str, dict[str, Any]]:
    expected = {
        "authority_id",
        "authority_nonce",
        "body",
        "body_digest",
        "expires_at",
        "host_nonce",
        "issued_at",
        "nonce",
        "operation",
        "sequence",
    }
    if set(value) != expected or not isinstance(value.get("body"), dict):
        raise PermissionError("Provider Host request fields are invalid")
    if (
        value.get("authority_id") != hello.get("authority_id")
        or value.get("authority_nonce") != hello.get("nonce")
        or value.get("host_nonce") != host_nonce
        or value.get("body_digest") != structured_digest(value["body"])
        or value.get("operation")
        not in {
            "prepare_environment",
            "bind_provider",
            "execute",
            "setup",
            "cancel",
            "status",
            "lock",
            "drain",
            "reconcile_uncertain_launch",
            "terminal_setup_result",
        }
    ):
        raise PermissionError("Provider Host request binding is invalid")
    return str(value["operation"]), dict(cast(dict[str, Any], value["body"]))
