from __future__ import annotations

import uuid
from pathlib import Path
import threading
from typing import Any

from keeper.authority_service.client import AuthorityServiceClient
from keeper.providers.base import AgentProvider, AgentRequest, ProcessResult


class AuthorityServiceProvider(AgentProvider):
    """Provider adapter whose process is created and owned by the Authority Service."""

    def __init__(
        self,
        client: AuthorityServiceClient,
        registration: dict[str, Any],
    ) -> None:
        self.client = client
        self.registration = dict(registration)
        self.provider_name = str(registration["provider_name"])
        self.instance_id = uuid.uuid4().hex
        self._active_lock = threading.Lock()
        self._active_attempt_id: str | None = None

    def validate(self) -> None:
        if (
            self.registration.get("registration_lifecycle") != "QUALIFIED"
            or self.registration.get("registration_status") != "active"
            or not self.registration.get("trusted_registration_id")
        ):
            raise PermissionError(
                "Authority Service provider registration is not qualified"
            )

    def run(self, request: AgentRequest) -> ProcessResult:
        attempt_id = request.authority_attempt_id
        if not attempt_id:
            raise PermissionError(
                "Authority Service provider attempt reservation is missing"
            )
        with self._active_lock:
            if self._active_attempt_id is not None:
                raise RuntimeError("provider adapter is already executing")
            self._active_attempt_id = attempt_id
        try:
            result = self.client.execute_provider(attempt_id)
        finally:
            with self._active_lock:
                self._active_attempt_id = None
        process = result.get("process_result")
        started = result.get("start")
        if not isinstance(process, dict) or not isinstance(started, dict):
            raise RuntimeError("Authority Service provider response is malformed")
        if (
            Path(str(process.get("stdout_path"))).resolve()
            != request.stdout_path.resolve()
            or Path(str(process.get("stderr_path"))).resolve()
            != request.stderr_path.resolve()
        ):
            raise PermissionError(
                "Authority Service provider output paths do not match reservation"
            )
        process_id = process.get("process_id")
        exit_status = process.get("exit_status")
        timed_out = process.get("timed_out")
        if (
            isinstance(process_id, bool)
            or not isinstance(process_id, int)
            or process_id <= 0
            or isinstance(exit_status, bool)
            or not isinstance(exit_status, int)
            or not isinstance(timed_out, bool)
        ):
            raise RuntimeError("Authority Service process result is malformed")
        if request.on_process_started is not None:
            request.on_process_started(process_id)
        if request.on_process_owned is not None:
            request.on_process_owned(
                {
                    "pid": process_id,
                    "creation_time": started.get("process_creation_time"),
                    "registered_executable": self.registration.get(
                        "canonical_executable_path"
                    ),
                    "launched_executable": started.get("process_executable"),
                    "launched_executable_sha256": started.get(
                        "process_executable_sha256"
                    ),
                    "launched_executable_size": self.registration.get(
                        "launcher_size"
                    ),
                    "registration_id": self.registration.get(
                        "trusted_registration_id"
                    ),
                    "registration_version": self.registration.get(
                        "registration_version"
                    ),
                    "configuration_digest": self.registration.get(
                        "configuration_digest"
                    ),
                    "batch_script": self.registration.get("script_path"),
                    "batch_script_sha256": self.registration.get("script_sha256"),
                    "batch_script_size": self.registration.get("script_size"),
                    "script_registration_id": self.registration.get(
                        "script_registration_id"
                    ),
                    "script_registration_version": self.registration.get(
                        "script_registration_version"
                    ),
                    "launch_nonce": started.get("launch_challenge"),
                    "ownership_token": started.get("claim_transaction_id"),
                    "job_or_group_identity": f"authority-service:{attempt_id}",
                    "started_at": started.get("started_at"),
                    "restricted": started.get("restricted_token"),
                    "integrity_level": started.get("integrity_level"),
                    "job_confined": started.get("job_confined"),
                    "authority_attempt_id": attempt_id,
                    "completion_challenge": started.get(
                        "completion_challenge"
                    ),
                }
            )
        return ProcessResult(
            exit_status,
            request.stdout_path,
            request.stderr_path,
            process_id,
            timed_out,
        )

    def cancel(self) -> None:
        with self._active_lock:
            attempt_id = self._active_attempt_id
        if attempt_id is not None:
            self.client.cancel_attempt(attempt_id)
