from __future__ import annotations

import ctypes
import os
import time
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path
from typing import Any, Callable, Iterator

from keeper.authority_service.protocol import (
    PROTOCOL_VERSION,
    Operation,
    Request,
    decode_frame,
    encode_frame,
    parse_response,
)
from keeper.authority_service.provenance import validate_provenance_report
from keeper.authority_service.provider_identity import account_sid


DEFAULT_PIPE_NAME = r"\\.\pipe\KeeperAuthority-v1"


class AuthorityServiceClient:
    """Fail-closed client for the local Keeper Authority Windows service."""

    def __init__(
        self,
        pipe_name: str = DEFAULT_PIPE_NAME,
        *,
        timeout_seconds: float = 15.0,
        test_transport: Callable[[Request], dict[str, Any]] | None = None,
    ) -> None:
        self.pipe_name = pipe_name
        self.timeout_seconds = timeout_seconds
        self._test_transport = test_transport

    def request(
        self, operation: Operation, payload: dict[str, Any]
    ) -> dict[str, Any]:
        request = Request.create(operation, payload)
        return self._send(request)

    def _send(self, request: Request) -> dict[str, Any]:
        if self._test_transport is not None:
            return self._test_transport(request)
        if os.name != "nt":
            raise RuntimeError("Keeper Authority Service requires Windows")
        if "client_executable_handle" in request.payload:
            from keeper.authority_service.client_process_policy import (
                ensure_current_process_authority_transfer_access,
            )

            ensure_current_process_authority_transfer_access(
                account_sid(r"NT SERVICE\KeeperAuthority")
            )
        handle = _connect(self.pipe_name, self.timeout_seconds)
        try:
            _write_all(handle, encode_frame(request.to_dict()))
            response = decode_frame(lambda length: _read(handle, length))
        finally:
            _close(handle)
        return parse_response(response, request.request_id)

    def diagnostics(self) -> dict[str, Any]:
        return self.request(Operation.DIAGNOSTICS, {})

    def audit_provenance(self) -> dict[str, Any]:
        request = Request.create(Operation.AUDIT_PROVENANCE, {})
        result = self._send(request)
        if set(result) != {"report"}:
            raise RuntimeError(
                "Authority provenance response fields are invalid"
            )
        return validate_provenance_report(result["report"], request)

    def provider_host_enrollment_status(self) -> dict[str, Any]:
        return self.request(Operation.PROVIDER_HOST_ENROLLMENT_STATUS, {})

    def reconcile_provider_host_launch(
        self,
        *,
        founder_capability: dict[str, object],
        expected_launch: dict[str, object],
        enrollment_id: str,
    ) -> dict[str, Any]:
        return self.request(
            Operation.RECONCILE_PROVIDER_HOST_LAUNCH,
            {
                "enrollment_id": enrollment_id,
                "expected_launch": expected_launch,
                "founder_capability": founder_capability,
            },
        )

    def begin_provider_host_enrollment(
        self,
        *,
        founder_capability: dict[str, object],
        proposal: dict[str, object],
    ) -> dict[str, Any]:
        return self.request(
            Operation.BEGIN_PROVIDER_HOST_ENROLLMENT,
            {
                "founder_capability": founder_capability,
                "proposal": proposal,
            },
        )

    def complete_provider_host_enrollment(
        self, enrollment_id: str, proof: dict[str, object]
    ) -> dict[str, Any]:
        return self.request(
            Operation.COMPLETE_PROVIDER_HOST_ENROLLMENT,
            {"enrollment_id": enrollment_id, "proof": proof},
        )

    def reconcile_provider_host_enrollment(
        self, enrollment_id: str, proof: dict[str, object] | None
    ) -> dict[str, Any]:
        return self.request(
            Operation.RECONCILE_PROVIDER_HOST_ENROLLMENT,
            {"enrollment_id": enrollment_id, "proof": proof},
        )

    def revoke_provider_host_enrollment(
        self,
        enrollment_id: str,
        founder_capability: dict[str, object],
    ) -> dict[str, Any]:
        return self.request(
            Operation.REVOKE_PROVIDER_HOST_ENROLLMENT,
            {
                "enrollment_id": enrollment_id,
                "founder_capability": founder_capability,
            },
        )

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
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "provider_id": provider_id,
            "executable": str(executable.resolve()),
            "executive_capabilities": executive_capabilities,
            "project_types": project_types,
            "effort_levels": effort_levels,
            "pricing_authority": pricing_authority,
        }
        extended = (
            model_allowlist,
            expected_executable_sha256,
            expected_executable_size,
            expected_version,
            model_revalidation_expires_at,
            authentication_policy,
            usage_policy,
        )
        if any(item is not None for item in extended):
            if any(item is None for item in extended):
                raise ValueError(
                    "Codex subscription registration declaration is incomplete"
                )
            payload.update(
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
                }
            )
            with self.reviewed_executable_handle(executable) as exact_handle:
                payload["client_executable_handle"] = exact_handle
                return self.request(Operation.REGISTER_PROVIDER, payload)
        return self.request(Operation.REGISTER_PROVIDER, payload)

    def dispose_provider_registration_failure(
        self,
        *,
        registration_id: str,
        failure_digest: str,
        disposition: str,
        attempt_generation: int,
        founder_capability: dict[str, object],
    ) -> dict[str, Any]:
        return self.request(
            Operation.DISPOSE_PROVIDER_REGISTRATION_FAILURE,
            {
                "registration_id": registration_id,
                "failure_digest": failure_digest,
                "disposition": disposition,
                "attempt_generation": attempt_generation,
                "founder_capability": founder_capability,
            },
        )

    def recover_provider_registration_failure(
        self, registration_id: str
    ) -> dict[str, Any]:
        return self.request(
            Operation.RECOVER_PROVIDER_REGISTRATION_FAILURE,
            {"registration_id": registration_id},
        )

    def migrate_legacy_authority_predispatch_registration(
        self,
        *,
        registration_id: str,
        enrollment_id: str,
        offline_host_process_evidence: dict[str, object],
        founder_capability: dict[str, object],
    ) -> dict[str, Any]:
        return self.request(
            Operation.MIGRATE_LEGACY_AUTHORITY_PREDISPATCH_REGISTRATION,
            {
                "registration_id": registration_id,
                "enrollment_id": enrollment_id,
                "legacy_authority_version": "1.7.47",
                "legacy_authority_package_sha256": (
                    "19102c5ed7ad2a278c18d49284a8fbea0a189031d4ee4ddf55ed4687120e2211"
                ),
                "legacy_authority_runtime_executable_sha256": (
                    "03168c01b7b7491423350e82c26fee71f35b43694d1319d3c668bda6903a0c38"
                ),
                "legacy_authority_runtime_peer_digest": (
                    "da25662c9921d468fc039fe1bcbde86be791570c66fa335f50c6d604bc381fbc"
                ),
                "legacy_host_version": "1.7.47",
                "legacy_host_executable_sha256": (
                    "e81327789faff88c187c007182268049fb81ca4974f02a0ba53e6618a1340fae"
                ),
                "legacy_host_manifest_sha256": (
                    "3f9f7135d73f5c309550107bfd2648a8c38a850b7edad001cda3b5567f0e4fee"
                ),
                "effect_accounting": {
                    "host_rpc_count": 0,
                    "model_request_count": 0,
                    "provider_binding_created": False,
                    "qualification_started": False,
                    "registration_persisted": False,
                    "usage_reservation_count": 0,
                },
                "offline_host_process_evidence": offline_host_process_evidence,
                "founder_capability": founder_capability,
            },
        )

    def authorize_exhausted_provider_registration(
        self,
        *,
        registration_id: str,
        failure_digest: str,
        request_identity_digest: str,
        expected_account_identity_digest: str,
        expected_account_plan_type: str,
        account_identity_discovery_digest: str,
        expected_executable_sha256: str,
        expected_executable_size: int,
        required_authority_version: str,
        required_host_version: str,
        founder_capability: dict[str, object],
    ) -> dict[str, Any]:
        return self.request(
            Operation.AUTHORIZE_EXHAUSTED_PROVIDER_REGISTRATION,
            {
                "registration_id": registration_id,
                "failure_digest": failure_digest,
                "attempt_generation": 2,
                "request_identity_digest": request_identity_digest,
                "expected_account_identity_digest": expected_account_identity_digest,
                "expected_account_plan_type": expected_account_plan_type,
                "account_identity_discovery_digest": account_identity_discovery_digest,
                "expected_executable_sha256": expected_executable_sha256,
                "expected_executable_size": expected_executable_size,
                "required_authority_version": required_authority_version,
                "required_host_version": required_host_version,
                "effect_accounting": {
                    "model_request_count": 0,
                    "provider_execution_count": 0,
                    "qualification_count": 0,
                    "registration_success_count": 0,
                    "usage_reservation_count": 0,
                },
                "founder_capability": founder_capability,
            },
        )

    def recover_exhausted_provider_registration(
        self, registration_id: str
    ) -> dict[str, Any]:
        return self.request(
            Operation.RECOVER_EXHAUSTED_PROVIDER_REGISTRATION,
            {"registration_id": registration_id},
        )

    @contextmanager
    def reviewed_executable_handle(self, executable: Path) -> Iterator[int]:
        """Hold a client-opened reviewed executable for one Authority request."""
        descriptor = _open_locked_executable(executable)
        try:
            yield _descriptor_handle(descriptor)
        finally:
            os.close(descriptor)

    def qualify_provider(
        self, registration_id: str, executable: Path | None = None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"registration_id": registration_id}
        if executable is None:
            return self.request(Operation.BEGIN_QUALIFICATION, payload)
        with self.reviewed_executable_handle(executable) as exact_handle:
            payload["client_executable_handle"] = exact_handle
            return self.request(Operation.BEGIN_QUALIFICATION, payload)

    def authorize_provider_qualification_retry(
        self,
        *,
        registration_id: str,
        qualification_id: str,
        qualification_failure_digest: str,
        required_authority_version: str,
        required_host_version: str,
        founder_capability: dict[str, object],
        retry_generation: int = 2,
    ) -> dict[str, Any]:
        return self.request(
            Operation.AUTHORIZE_PROVIDER_QUALIFICATION_RETRY,
            {
                "registration_id": registration_id,
                "qualification_id": qualification_id,
                "qualification_failure_digest": qualification_failure_digest,
                "retry_generation": retry_generation,
                "required_authority_version": required_authority_version,
                "required_host_version": required_host_version,
                "founder_capability": founder_capability,
            },
        )

    def retry_provider_qualification(
        self,
        registration_id: str,
        retry_qualification_id: str,
        executable: Path,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "registration_id": registration_id,
            "retry_qualification_id": retry_qualification_id,
        }
        with self.reviewed_executable_handle(executable) as exact_handle:
            payload["client_executable_handle"] = exact_handle
            return self.request(Operation.RETRY_PROVIDER_QUALIFICATION, payload)

    def reconcile_provider_qualification(
        self, registration_id: str
    ) -> dict[str, Any]:
        return self.request(
            Operation.RECONCILE_PROVIDER_QUALIFICATION,
            {"registration_id": registration_id},
        )

    def reserve_attempt(self, **identity: Any) -> dict[str, Any]:
        return self.request(Operation.RESERVE_ATTEMPT, dict(identity))

    def authorize_project_launch(self, **identity: Any) -> dict[str, Any]:
        return self.request(Operation.AUTHORIZE_PROJECT_LAUNCH, dict(identity))

    def revoke_project_launch(
        self, project_id: str, authorization_generation: int
    ) -> dict[str, Any]:
        return self.request(
            Operation.REVOKE_PROJECT_LAUNCH,
            {
                "project_id": project_id,
                "authorization_generation": authorization_generation,
            },
        )

    def record_provider_start(self, attempt_id: str, pid: int) -> dict[str, Any]:
        return self.request(
            Operation.RECORD_PROVIDER_START,
            {"attempt_id": attempt_id, "pid": pid},
        )

    def execute_provider(self, attempt_id: str) -> dict[str, Any]:
        return self.request(
            Operation.EXECUTE_PROVIDER, {"attempt_id": attempt_id}
        )

    def bind_provider_input(
        self,
        attempt_id: str,
        provider_input: dict[str, Any],
        provider_input_digest: str,
        delivered_input_digest: str,
        manifest_digest: str,
        executive_commit_receipt: dict[str, object],
    ) -> dict[str, Any]:
        return self.request(
            Operation.BIND_PROVIDER_INPUT,
            {
                "attempt_id": attempt_id,
                "provider_input": provider_input,
                "provider_input_digest": provider_input_digest,
                "delivered_input_digest": delivered_input_digest,
                "manifest_digest": manifest_digest,
                "executive_commit_receipt": executive_commit_receipt,
            },
        )

    def finalize_completion(self, attempt_id: str) -> dict[str, Any]:
        return self.request(
            Operation.FINALIZE_COMPLETION, {"attempt_id": attempt_id}
        )

    def cancel_attempt(self, attempt_id: str) -> dict[str, Any]:
        return self.request(
            Operation.CANCEL_ATTEMPT, {"attempt_id": attempt_id}
        )

    def query_state(self, kind: str, identifier: str) -> dict[str, Any]:
        return self.request(Operation.QUERY_STATE, {"kind": kind, "id": identifier})

    def observe_uncertain_provider_attempt(
        self, attempt_id: str
    ) -> dict[str, Any]:
        return self.request(
            Operation.OBSERVE_UNCERTAIN_PROVIDER_ATTEMPT,
            {"attempt_id": attempt_id},
        )

    def finalize_uncertain_provider_attempt_disposition(
        self,
        attempt_id: str,
        executive_recovery_receipt: dict[str, object],
    ) -> dict[str, Any]:
        return self.request(
            Operation.FINALIZE_UNCERTAIN_PROVIDER_ATTEMPT_DISPOSITION,
            {
                "attempt_id": attempt_id,
                "executive_recovery_receipt": executive_recovery_receipt,
            },
        )

    def reconcile_executive_restore(self, **identity: Any) -> dict[str, Any]:
        return self.request(
            Operation.RECONCILE_EXECUTIVE_RESTORE, dict(identity)
        )

    def begin_executive_restore_fence(self, **identity: Any) -> dict[str, Any]:
        return self.request(
            Operation.BEGIN_EXECUTIVE_RESTORE_FENCE, dict(identity)
        )

    def confirm_executive_restore_fence(
        self, fence_id: str, restore_operation_id: str
    ) -> dict[str, Any]:
        return self.request(
            Operation.CONFIRM_EXECUTIVE_RESTORE_FENCE,
            {
                "fence_id": fence_id,
                "restore_operation_id": restore_operation_id,
            },
        )

    def complete_executive_restore_fence(
        self, fence_id: str, restore_operation_id: str
    ) -> dict[str, Any]:
        return self.request(
            Operation.COMPLETE_EXECUTIVE_RESTORE_FENCE,
            {
                "fence_id": fence_id,
                "restore_operation_id": restore_operation_id,
            },
        )

    def abort_executive_restore_fence(
        self, fence_id: str, restore_operation_id: str
    ) -> dict[str, Any]:
        return self.request(
            Operation.ABORT_EXECUTIVE_RESTORE_FENCE,
            {
                "fence_id": fence_id,
                "restore_operation_id": restore_operation_id,
            },
        )

    def recover_executive_restore_fence(
        self, fence_id: str, restore_operation_id: str
    ) -> dict[str, Any]:
        return self.request(
            Operation.RECOVER_EXECUTIVE_RESTORE_FENCE,
            {
                "fence_id": fence_id,
                "restore_operation_id": restore_operation_id,
            },
        )

    def verify(self, purpose: str, record: object) -> bool:
        return bool(
            self.request(
                Operation.VERIFY_EVIDENCE,
                {"purpose": purpose, "record": record},
            ).get("valid")
        )

    def rotate_key(self, confirmation: str) -> dict[str, Any]:
        return self.request(Operation.ROTATE_KEY, {"confirmation": confirmation})

    def migrate_legacy(
        self, registrations: list[dict[str, Any]]
    ) -> dict[str, Any]:
        return self.request(
            Operation.MIGRATE_LEGACY, {"registrations": registrations}
        )


class ProductionAuthorityServiceClient(AuthorityServiceClient):
    """Structurally production-only client with fixed authenticated IPC transport."""

    __slots__ = ()

    def __init__(
        self,
        pipe_name: str = DEFAULT_PIPE_NAME,
        *,
        timeout_seconds: float = 15.0,
    ) -> None:
        if pipe_name != DEFAULT_PIPE_NAME:
            raise RuntimeError("production Authority endpoint is not canonical")
        super().__init__(pipe_name, timeout_seconds=timeout_seconds)
        del self._test_transport

    def _send(self, request: Request) -> dict[str, Any]:
        if os.name != "nt":
            raise RuntimeError("Keeper Authority Service requires Windows")
        handle = _connect(self.pipe_name, self.timeout_seconds)
        try:
            _write_all(handle, encode_frame(request.to_dict()))
            response = decode_frame(lambda length: _read(handle, length))
        finally:
            _close(handle)
        return parse_response(response, request.request_id)

    def require_live_identity(self) -> dict[str, Any]:
        diagnostics = self.diagnostics()
        if (
            diagnostics.get("protocol_version") != PROTOCOL_VERSION
            or diagnostics.get("observer_available") is not True
            or not isinstance(diagnostics.get("service_root"), str)
            or not isinstance(diagnostics.get("service_key_id"), str)
            or not isinstance(diagnostics.get("service_key_version"), int)
            or not isinstance(diagnostics.get("client_sid"), str)
        ):
            raise RuntimeError("live Keeper Authority identity is invalid")
        return diagnostics


class TestAuthorityServiceClient(AuthorityServiceClient):
    """Explicit test-only injected Authority transport."""

    __test__ = False
    __slots__ = ()

    def __init__(self, test_transport: Callable[[Request], dict[str, Any]]) -> None:
        super().__init__(test_transport=test_transport)


def _connect(pipe_name: str, timeout_seconds: float) -> int:
    kernel32 = _kernel32()
    deadline = time.monotonic() + timeout_seconds
    last_error = 2
    while time.monotonic() < deadline:
        remaining = max(1, int((deadline - time.monotonic()) * 1000))
        if not kernel32.WaitNamedPipeW(pipe_name, min(remaining, 250)):
            last_error = ctypes.get_last_error()
            if last_error in {2, 121, 231}:
                time.sleep(0.01)
                continue
            raise PermissionError(
                f"Keeper Authority Service connection was rejected: {last_error}"
            )
        handle = kernel32.CreateFileW(
            pipe_name,
            0xC0000000,
            0,
            None,
            3,
            0,
            None,
        )
        if handle not in {None, ctypes.c_void_p(-1).value}:
            return int(handle)
        last_error = ctypes.get_last_error()
        if last_error not in {2, 121, 231}:
            raise PermissionError(
                f"Keeper Authority Service connection was rejected: {last_error}"
            )
    raise TimeoutError(f"Keeper Authority Service is unavailable: {last_error}")


def _open_locked_executable(executable: Path) -> int:
    """Open one exact local executable read-only without replacement sharing."""
    canonical = executable.resolve(strict=True)
    if os.name != "nt":
        return os.open(canonical, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    import msvcrt

    kernel32 = _kernel32()
    handle = kernel32.CreateFileW(
        str(canonical),
        0x80000000,  # GENERIC_READ
        0x00000001,  # FILE_SHARE_READ only
        None,
        3,  # OPEN_EXISTING
        0x00000080 | 0x00200000,  # NORMAL | OPEN_REPARSE_POINT
        None,
    )
    if handle in {None, ctypes.c_void_p(-1).value}:
        raise PermissionError(
            f"Codex executable secure client open failed: {ctypes.get_last_error()}"
        )
    try:
        return msvcrt.open_osfhandle(
            int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


def _descriptor_handle(descriptor: int) -> int:
    if os.name != "nt":
        return descriptor
    import msvcrt

    return int(msvcrt.get_osfhandle(descriptor))


def _write_all(handle: int, value: bytes) -> None:
    offset = 0
    kernel32 = _kernel32()
    while offset < len(value):
        written = wintypes.DWORD()
        chunk = value[offset:]
        buffer = ctypes.create_string_buffer(chunk)
        if not kernel32.WriteFile(
            handle, buffer, len(chunk), ctypes.byref(written), None
        ):
            raise OSError(
                ctypes.get_last_error(), "Keeper Authority IPC write failed"
            )
        if written.value <= 0:
            raise OSError("Keeper Authority IPC write stalled")
        offset += int(written.value)


def _read(handle: int, length: int) -> bytes:
    kernel32 = _kernel32()
    buffer = ctypes.create_string_buffer(length)
    read = wintypes.DWORD()
    if not kernel32.ReadFile(
        handle, buffer, length, ctypes.byref(read), None
    ):
        error = ctypes.get_last_error()
        if error == 109:
            return b""
        raise OSError(error, "Keeper Authority IPC read failed")
    return buffer.raw[: read.value]


def _close(handle: int) -> None:
    if not _kernel32().CloseHandle(handle):
        raise OSError(ctypes.get_last_error(), "Keeper Authority IPC close failed")


def _kernel32() -> Any:
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = kernel32.ReadFile.argtypes
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32
