from __future__ import annotations

import ctypes
import hashlib
import os
import re
import threading
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from keeper.authority_service import restricted_process as restricted_process_runtime
from keeper.authority_service.provider_identity import account_sid
from keeper.authority_service.windows_identity import (
    NamedPipeClientProcessBinding,
    authenticated_named_pipe_restricted_service_process,
    authenticated_named_pipe_restricted_service_token,
    authenticated_named_pipe_server_process,
    current_process_sid,
    process_sid,
    require_current_restricted_service_identity,
)


_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SERVICE_SID = re.compile(r"S-1-5-80-(?:\d+-){4}\d+")
_PEER_MEASUREMENT_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True, slots=True)
class UserBinding:
    user_sid: str
    session_id: int
    profile_path: str

    def as_dict(self) -> dict[str, object]:
        return {
            "profile_path": self.profile_path,
            "session_id": self.session_id,
            "user_sid": self.user_sid,
        }


@dataclass(frozen=True, slots=True)
class PipePeerIdentity:
    process_id: int
    session_id: int
    user_sid: str
    executable_path: str
    executable_sha256: str
    executable_file_identity: tuple[int, int, int, int] = (0, 0, 0, 0)


class ProviderHostIdentityUncertain(RuntimeError):
    """A bounded peer-identity worker could not prove a safe result."""


def current_user_binding() -> UserBinding:
    if os.name != "nt":
        raise RuntimeError("Provider Host identity requires Windows")
    session = wintypes.DWORD()
    kernel32 = _kernel32()
    process_id = int(kernel32.GetCurrentProcessId())
    if not kernel32.ProcessIdToSessionId(process_id, ctypes.byref(session)):
        raise PermissionError("Provider Host Windows session is unavailable")
    profile = Path(os.environ["USERPROFILE"]).resolve(strict=True)
    return UserBinding(current_process_sid(), int(session.value), str(profile))


def require_same_binding(expected: UserBinding, observed: UserBinding) -> None:
    if (
        expected.user_sid.casefold() != observed.user_sid.casefold()
        or expected.session_id != observed.session_id
        or os.path.normcase(expected.profile_path)
        != os.path.normcase(observed.profile_path)
    ):
        raise PermissionError("Provider Host SID/session/profile binding differs")


def named_pipe_server_identity(pipe: int) -> PipePeerIdentity:
    """Authenticate the local process serving a connected host pipe."""

    return _named_pipe_peer_identity(pipe, server=True)


@contextmanager
def authenticated_named_pipe_server_binding(
    pipe: int,
    *,
    expected: PipePeerIdentity,
) -> Iterator[NamedPipeClientProcessBinding]:
    """Retain the exact Host pipe process through signed self-attestation.

    The restricted Authority service can inspect the pipe server's process,
    token, SID, session, lifetime, and OS-reported image path without traversing
    the user's profile.  The enrolled Host then signs a nonce-bound measurement
    of its exact executable bytes and durable file identity.  Keep the process
    and token handles retained until the complete RPC finishes so that neither
    PID reuse nor process replacement can substitute the measured peer.
    """
    _validate_expected_host_peer(expected)
    service_sid = _authority_service_sid()
    require_current_restricted_service_identity(service_sid)
    advapi32 = restricted_process_runtime._advapi32()
    kernel32 = restricted_process_runtime._kernel32()
    try:
        restricted_process_runtime._assert_thread_not_impersonating(
            advapi32=advapi32, kernel32=kernel32
        )
    except BaseException as error:
        raise ProviderHostIdentityUncertain(
            "Authority service thread identity is not clean before Host peer "
            "measurement"
        ) from error
    with authenticated_named_pipe_server_process(
        pipe, expected.user_sid
    ) as binding:
        observed = binding.revalidate_core(expected.user_sid)
        _require_expected_host_core(observed, expected)
        try:
            yield binding
        finally:
            final = binding.revalidate_retained(expected.user_sid)
            if _process_identity_core(final) != _process_identity_core(observed):
                raise PermissionError(
                    "Provider Host pipe peer changed during authenticated RPC"
                )
            _require_expected_host_core(final, expected)
            try:
                restricted_process_runtime._assert_thread_not_impersonating(
                    advapi32=advapi32, kernel32=kernel32
                )
            except BaseException as error:
                raise ProviderHostIdentityUncertain(
                    "Authority service thread identity is not clean after Host "
                    "peer authentication"
                ) from error


def _validate_expected_host_peer(expected: PipePeerIdentity) -> None:
    path = Path(expected.executable_path)
    if (
        expected.process_id != 0
        or expected.session_id < 0
        or not expected.user_sid.startswith("S-1-")
        or not path.is_absolute()
        or path.drive == ""
        or not path.drive.endswith(":")
        or os.path.normcase(os.path.abspath(str(path)))
        != os.path.normcase(str(path))
        or len(expected.executable_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in expected.executable_sha256
        )
        or not _valid_file_identity(expected.executable_file_identity)
    ):
        raise PermissionError("Provider Host expected peer is invalid")


def _require_expected_host_core(
    observed: NamedPipeClientProcessIdentity,
    expected: PipePeerIdentity,
) -> None:
    if (
        observed.session_id != expected.session_id
        or observed.sid.casefold() != expected.user_sid.casefold()
        or os.path.normcase(observed.executable_path)
        != os.path.normcase(expected.executable_path)
    ):
        raise PermissionError("Provider Host pipe peer identity differs")


def _process_identity_core(
    value: NamedPipeClientProcessIdentity,
) -> tuple[object, ...]:
    return (
        value.process_id,
        value.session_id,
        value.sid.casefold(),
        value.computer_name.casefold(),
        value.process_creation_time_100ns,
        os.path.normcase(value.executable_path),
    )


def named_pipe_client_identity(pipe: int) -> PipePeerIdentity:
    """Authenticate the local process connected to a host pipe server."""

    return _named_pipe_peer_identity(pipe, server=False)


def authenticated_named_pipe_client_identity(
    pipe: int,
    *,
    expected: PipePeerIdentity,
    expected_service_sid: str,
    timeout_seconds: float = _PEER_MEASUREMENT_TIMEOUT_SECONDS,
) -> PipePeerIdentity:
    """Authenticate the Authority token, revert, then inspect its process.

    The disposable worker uses the pipe client's token only for exact service
    SID/session/restriction authentication. It reverts and positively proves a
    clean thread before opening the Authority process. The protected Authority
    installation is never traversed by the Host; executable hash and file
    identity come from the already Authority-signed enrollment receipt.
    """
    if timeout_seconds <= 0:
        raise ValueError("Provider Host Authority measurement timeout is invalid")
    if not _SERVICE_SID.fullmatch(expected_service_sid):
        raise PermissionError("Provider Host Authority service SID is invalid")
    _validate_expected_peer(expected, expected_service_sid)
    advapi32 = restricted_process_runtime._advapi32()
    kernel32 = restricted_process_runtime._kernel32()
    try:
        restricted_process_runtime._assert_thread_not_impersonating(
            advapi32=advapi32, kernel32=kernel32
        )
    except BaseException as error:
        raise ProviderHostIdentityUncertain(
            "Provider Host thread identity is not clean before Authority peer "
            "measurement"
        ) from error
    outcome: list[PipePeerIdentity | BaseException] = []
    completed = threading.Event()

    def worker() -> None:
        try:
            restricted_process_runtime._assert_thread_not_impersonating(
                advapi32=advapi32, kernel32=kernel32
            )
        except BaseException as error:
            outcome.append(error)
            return
        ctypes.set_last_error(0)
        try:
            impersonated = bool(
                advapi32.ImpersonateNamedPipeClient(wintypes.HANDLE(pipe))
            )
        except BaseException:
            return
        if not impersonated:
            win32_error = ctypes.get_last_error()
            try:
                restricted_process_runtime._assert_thread_not_impersonating(
                    advapi32=advapi32, kernel32=kernel32
                )
            except BaseException:
                return
            outcome.append(
                PermissionError(
                    "Provider Host Authority-peer impersonation failed: "
                    f"{win32_error}"
                )
            )
            return
        token_identity = None
        authentication_error: BaseException | None = None
        try:
            token_identity = authenticated_named_pipe_restricted_service_token(
                pipe,
                expected_service_sid=expected_service_sid,
            )
        except BaseException as error:
            authentication_error = error
        try:
            reverted = bool(advapi32.RevertToSelf())
        except BaseException:
            return
        try:
            restricted_process_runtime._assert_thread_not_impersonating(
                advapi32=advapi32, kernel32=kernel32
            )
        except BaseException:
            return
        if not reverted:
            return
        if authentication_error is not None:
            outcome.append(authentication_error)
            return
        if token_identity is None:
            return
        try:
            with authenticated_named_pipe_restricted_service_process(
                pipe,
                token_identity=token_identity,
            ) as binding:
                identity = binding.bind_or_revalidate_signed_executable_identity(
                    expected.user_sid,
                    expected_path=expected.executable_path,
                    expected_file_identity=expected.executable_file_identity,
                )
                measured = PipePeerIdentity(
                    process_id=identity.process_id,
                    session_id=identity.session_id,
                    user_sid=identity.sid,
                    executable_path=identity.executable_path,
                    executable_sha256=expected.executable_sha256,
                    executable_file_identity=identity.executable_file_identity,
                )
                _require_expected_peer(measured, expected)
                final = (
                    binding.revalidate_core(expected.user_sid)
                    if isinstance(binding, NamedPipeClientProcessBinding)
                    else binding.revalidate_core()
                )
                if _process_identity_core(final) != _process_identity_core(identity):
                    raise PermissionError(
                        "Provider Host Authority process changed during measurement"
                    )
                outcome.append(measured)
        except BaseException as error:
            outcome.append(error)

    thread = threading.Thread(
        target=lambda: _complete_worker(worker, completed),
        name="KeeperProviderHostAuthorityPeer",
        daemon=True,
    )
    thread.start()
    if not completed.wait(timeout_seconds):
        raise ProviderHostIdentityUncertain(
            "Provider Host Authority-peer measurement timed out"
        )
    thread.join()
    try:
        restricted_process_runtime._assert_thread_not_impersonating(
            advapi32=advapi32, kernel32=kernel32
        )
    except BaseException as error:
        raise ProviderHostIdentityUncertain(
            "Provider Host thread identity is not clean after Authority peer "
            "measurement"
        ) from error
    if not outcome:
        raise ProviderHostIdentityUncertain(
            "Provider Host Authority-peer worker identity could not be verified"
        )
    first = outcome[0]
    if isinstance(first, BaseException):
        raise first
    return first


def _complete_worker(
    worker: Callable[[], None], completed: threading.Event
) -> None:
    """Signal completion even when an identity worker abandons its result."""
    try:
        worker()
    finally:
        completed.set()


def require_peer_identity(
    observed: PipePeerIdentity,
    *,
    process_id: int | None = None,
    session_id: int,
    user_sid: str,
    executable_path: Path,
    executable_sha256: str,
    executable_file_identity: tuple[int, int, int, int] | None = None,
) -> None:
    if not executable_path.is_absolute():
        raise PermissionError("Provider Host expected peer path is invalid")
    canonical = Path(os.path.abspath(executable_path))
    if (
        (process_id is not None and observed.process_id != process_id)
        or observed.session_id != session_id
        or observed.user_sid.casefold() != user_sid.casefold()
        or os.path.normcase(observed.executable_path)
        != os.path.normcase(str(canonical))
        or observed.executable_sha256 != executable_sha256
        or (
            executable_file_identity is not None
            and observed.executable_file_identity != executable_file_identity
        )
    ):
        raise PermissionError("Provider Host pipe peer identity differs")


def _validate_expected_peer(
    expected: PipePeerIdentity, expected_service_sid: str
) -> None:
    path = Path(expected.executable_path)
    if (
        expected.process_id != 0
        or expected.session_id != 0
        or expected.user_sid.casefold() != expected_service_sid.casefold()
        or not path.is_absolute()
        or os.path.normcase(os.path.abspath(str(path)))
        != os.path.normcase(str(path))
        or len(expected.executable_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in expected.executable_sha256
        )
        or not _valid_file_identity(expected.executable_file_identity)
    ):
        raise PermissionError("Provider Host expected Authority peer is invalid")


def _authority_service_sid() -> str:
    sid = account_sid(r"NT SERVICE\KeeperAuthority")
    if not _SERVICE_SID.fullmatch(sid):
        raise PermissionError("KeeperAuthority service SID is invalid")
    return sid


def _require_expected_peer(
    observed: PipePeerIdentity, expected: PipePeerIdentity
) -> None:
    require_peer_identity(
        observed,
        session_id=expected.session_id,
        user_sid=expected.user_sid,
        executable_path=Path(expected.executable_path),
        executable_sha256=expected.executable_sha256,
        executable_file_identity=expected.executable_file_identity,
    )


def _valid_file_identity(value: tuple[int, int, int, int]) -> bool:
    return value[0] >= 0 and value[1] > 0 and value[2] > 0 and value[3] > 0


def measured_process_identity(process_id: int) -> PipePeerIdentity:
    if os.name != "nt" or process_id <= 0:
        raise PermissionError("Provider Host peer process is invalid")
    kernel32 = _kernel32()
    process = kernel32.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION, False, process_id
    )
    if not process:
        raise PermissionError(
            "Provider Host peer process cannot be opened: "
            f"{ctypes.get_last_error()}"
        )
    try:
        session = wintypes.DWORD()
        if not kernel32.ProcessIdToSessionId(process_id, ctypes.byref(session)):
            raise PermissionError("Provider Host peer session is unavailable")
        capacity = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(capacity.value)
        if not kernel32.QueryFullProcessImageNameW(
            process, 0, buffer, ctypes.byref(capacity)
        ):
            raise PermissionError("Provider Host peer executable is unavailable")
        executable = Path(buffer.value).resolve(strict=True)
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        return PipePeerIdentity(
            process_id=process_id,
            session_id=int(session.value),
            user_sid=process_sid(process_id),
            executable_path=str(executable),
            executable_sha256=digest,
        )
    finally:
        if not kernel32.CloseHandle(process):
            raise PermissionError("Provider Host peer process handle did not close")


def _named_pipe_peer_identity(pipe: int, *, server: bool) -> PipePeerIdentity:
    if os.name != "nt" or pipe <= 0:
        raise PermissionError("Provider Host pipe handle is invalid")
    kernel32 = _kernel32()
    process_id = wintypes.ULONG()
    operation = (
        kernel32.GetNamedPipeServerProcessId
        if server
        else kernel32.GetNamedPipeClientProcessId
    )
    if not operation(wintypes.HANDLE(pipe), ctypes.byref(process_id)):
        raise PermissionError(
            "Provider Host pipe peer process is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    first = int(process_id.value)
    observed = measured_process_identity(first)
    check = wintypes.ULONG()
    if not operation(wintypes.HANDLE(pipe), ctypes.byref(check)) or int(
        check.value
    ) != first:
        raise PermissionError("Provider Host pipe peer changed during validation")
    return observed


def _kernel32() -> Any:
    if os.name != "nt":
        raise RuntimeError("Provider Host identity requires Windows")
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.GetCurrentProcessId.restype = wintypes.DWORD
    api.ProcessIdToSessionId.argtypes = [
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    api.ProcessIdToSessionId.restype = wintypes.BOOL
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    api.QueryFullProcessImageNameW.restype = wintypes.BOOL
    api.GetNamedPipeServerProcessId.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.ULONG),
    ]
    api.GetNamedPipeServerProcessId.restype = wintypes.BOOL
    api.GetNamedPipeClientProcessId.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.ULONG),
    ]
    api.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    return api
