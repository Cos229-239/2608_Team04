from __future__ import annotations

import ctypes
import os
import re
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterator


TOKEN_QUERY = 0x0008
TOKEN_DUPLICATE = 0x0002
TOKEN_USER = 1
TOKEN_INTEGRITY_LEVEL = 25
TOKEN_RESTRICTED_SIDS = 11
TOKEN_TYPE = 8
TOKEN_IMPERSONATION_LEVEL = 9
TOKEN_PRIMARY = 1
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_DUP_HANDLE = 0x0040
STILL_ACTIVE = 259
ERROR_ACCESS_DENIED = 5
ERROR_PIPE_LOCAL = 229
TOKEN_IMPERSONATION = 2
SECURITY_IDENTIFICATION = 1
SECURITY_IMPERSONATION = 2
LOCAL_SYSTEM_SID = "S-1-5-18"
RESTRICTED_CODE_SID = "S-1-5-12"
WORLD_SID = "S-1-1-0"
WRITE_RESTRICTED_CODE_SID = "S-1-5-33"
_SERVICE_SID = re.compile(r"S-1-5-80-(?:\d+-){4}\d+")
_LOGON_SID = re.compile(r"S-1-5-5-\d+-\d+")


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


class _TokenMandatoryLabel(ctypes.Structure):
    _fields_ = [("Label", _SidAndAttributes)]


class _TokenGroups(ctypes.Structure):
    _fields_ = [
        ("GroupCount", wintypes.DWORD),
        ("Groups", _SidAndAttributes * 1),
    ]


class _PublicObjectBasicInformation(ctypes.Structure):
    _fields_ = [
        ("Attributes", wintypes.ULONG),
        ("GrantedAccess", wintypes.ULONG),
        ("HandleCount", wintypes.ULONG),
        ("PointerCount", wintypes.ULONG),
        ("Reserved", wintypes.ULONG * 10),
    ]


@dataclass(frozen=True, slots=True)
class WindowsTokenIdentity:
    sid: str
    restricted: bool
    integrity_rid: int


@dataclass(frozen=True, slots=True)
class NamedPipeClientProcessIdentity:
    process_id: int
    session_id: int
    sid: str
    computer_name: str
    process_creation_time_100ns: int = 0
    executable_path: str = ""
    executable_file_identity: tuple[int, int, int, int] = (0, 0, 0, 0)


@dataclass(frozen=True, slots=True)
class RestrictedServicePipeTokenIdentity:
    process_id: int
    session_id: int
    service_sid: str
    restricting_sids: tuple[str, ...]
    impersonation_level: int


class NamedPipeClientProcessBinding:
    """Retain and repeatedly authenticate the process behind one pipe instance."""

    def __init__(
        self,
        pipe: int,
        process: int,
        process_token: int,
        identity: NamedPipeClientProcessIdentity,
        *,
        server: bool = False,
    ) -> None:
        if (
            identity.process_creation_time_100ns <= 0
            or not Path(identity.executable_path).is_absolute()
            or identity.executable_file_identity != (0, 0, 0, 0)
            and not _valid_file_identity(identity.executable_file_identity)
        ):
            raise PermissionError(
                "authority client process lifetime or executable identity is invalid"
            )
        self.pipe = pipe
        self.process = process
        self.process_token = process_token
        self.identity = identity
        self.server = server
        self._released = False

    @property
    def profile_token(self) -> int:
        if self._released or self.process_token <= 0:
            raise PermissionError("authority client process token is released")
        return self.process_token

    def revalidate(self, expected_sid: str) -> NamedPipeClientProcessIdentity:
        """Revalidate immutable pipe/process identity without filesystem access."""
        if self._released:
            raise PermissionError("authority client process binding is released")
        current = (
            _inspect_bound_named_pipe_server(
                self.pipe, self.process, self.process_token
            )
            if self.server
            else _inspect_bound_named_pipe_client(
                self.pipe, self.process, self.process_token
            )
        )
        if _process_core_identity(current) != _process_core_identity(self.identity):
            raise PermissionError("authority client process identity changed")
        if current.sid.casefold() != expected_sid.casefold():
            raise PermissionError("authority client process SID is mismatched")
        if not _valid_file_identity(self.identity.executable_file_identity):
            raise PermissionError(
                "authority client process executable identity is not finalized"
            )
        return self.identity

    def revalidate_core(self, expected_sid: str) -> NamedPipeClientProcessIdentity:
        """Revalidate the retained peer without touching its protected image path."""
        if self._released:
            raise PermissionError("authority client process binding is released")
        current = (
            _inspect_bound_named_pipe_server(
                self.pipe, self.process, self.process_token
            )
            if self.server
            else _inspect_bound_named_pipe_client(
                self.pipe, self.process, self.process_token
            )
        )
        if _process_core_identity(current) != _process_core_identity(self.identity):
            raise PermissionError("authority client process identity changed")
        if current.sid.casefold() != expected_sid.casefold():
            raise PermissionError("authority client process SID is mismatched")
        return current

    def bind_or_revalidate_signed_executable_identity(
        self,
        expected_sid: str,
        *,
        expected_path: str,
        expected_file_identity: tuple[int, int, int, int],
    ) -> NamedPipeClientProcessIdentity:
        """Bind an OS-observed process to immutable signed file metadata."""
        current = self.revalidate_core(expected_sid)
        if (
            os.path.normcase(current.executable_path)
            != os.path.normcase(expected_path)
            or not _valid_file_identity(expected_file_identity)
            or _valid_file_identity(current.executable_file_identity)
            and current.executable_file_identity != expected_file_identity
        ):
            raise PermissionError("Authority service executable identity differs")
        measured = replace(
            current, executable_file_identity=expected_file_identity
        )
        if not _valid_file_identity(self.identity.executable_file_identity):
            self.identity = measured
        return measured

    def revalidate_retained(
        self, expected_sid: str
    ) -> NamedPipeClientProcessIdentity:
        """Revalidate retained process/token handles after pipe disconnect."""
        if self._released:
            raise PermissionError("authority client process binding is released")
        token_sid, token_session = _token_sid_and_session(self.process_token)
        process_id = _process_handle_id(self.process)
        pid_session = _process_id_session(process_id)
        current = NamedPipeClientProcessIdentity(
            process_id=process_id,
            session_id=token_session,
            sid=token_sid,
            computer_name=self.identity.computer_name,
            process_creation_time_100ns=_process_creation_time(self.process),
            executable_path=_process_executable_path(self.process),
        )
        if (
            not _process_is_active(self.process)
            or pid_session is not None
            and pid_session != token_session
            or _process_core_identity(current)
            != _process_core_identity(self.identity)
            or token_sid.casefold() != expected_sid.casefold()
        ):
            raise PermissionError("authority client process identity changed")
        return current

    @contextmanager
    def duplicate_client_handle(
        self,
        handle_value: int,
        expected_sid: str,
        *,
        transfer_process: int,
    ) -> Iterator[int]:
        """Duplicate one exact handle from the retained authenticated client.

        The caller supplies only a handle-table index from this exact pipe peer
        and a narrowly privileged process handle that was opened by the
        authenticated-client transfer worker.  The lifetime-bound retained
        process handle remains query-only.  This method never impersonates and
        never opens a process by PID.
        """
        if (
            isinstance(handle_value, bool)
            or not isinstance(handle_value, int)
            or handle_value <= 0
        ):
            raise PermissionError("authority client file handle is invalid")
        if isinstance(transfer_process, bool) or transfer_process <= 0:
            raise PermissionError("authority client transfer process is invalid")
        self.revalidate(expected_sid)
        duplicated = wintypes.HANDLE()
        kernel32 = _kernel32()
        transfer_value = _handle_value(transfer_process)
        transfer_validated = False
        try:
            current = _inspect_bound_named_pipe_client(
                self.pipe, transfer_value, self.process_token
            )
            if _process_core_identity(current) != _process_core_identity(
                self.identity
            ):
                raise PermissionError(
                    "authority client transfer process identity changed"
                )
            transfer_validated = True
            self.revalidate(expected_sid)
            if not kernel32.DuplicateHandle(
                transfer_process,
                wintypes.HANDLE(handle_value),
                kernel32.GetCurrentProcess(),
                ctypes.byref(duplicated),
                0,
                False,
                0x00000002,  # DUPLICATE_SAME_ACCESS
            ):
                raise PermissionError(
                    "authority client file handle cannot be duplicated: "
                    f"{ctypes.get_last_error()}"
                )
            duplicate_value = _handle_value(duplicated)
            _require_read_only_disk_handle(duplicate_value)
            self.revalidate(expected_sid)
            yield duplicate_value
        finally:
            failures: list[str] = []
            if transfer_validated:
                try:
                    current = _inspect_bound_named_pipe_client(
                        self.pipe, transfer_value, self.process_token
                    )
                    if _process_core_identity(current) != _process_core_identity(
                        self.identity
                    ):
                        raise PermissionError(
                            "authority client transfer process identity changed"
                        )
                    self.revalidate(expected_sid)
                except PermissionError as error:
                    failures.append(f"identity:{error}")
            duplicate_raw = getattr(duplicated, "value", duplicated)
            if isinstance(duplicate_raw, int) and duplicate_raw > 0:
                if not kernel32.CloseHandle(duplicated):
                    failures.append(f"file:{ctypes.get_last_error()}")
            if failures:
                raise PermissionError(
                    "authority client handle-transfer cleanup failed: "
                    + ",".join(failures)
                )


    def bind_or_revalidate_executable_identity(
        self, expected_sid: str
    ) -> NamedPipeClientProcessIdentity:
        """Bind the peer's exact image identity under its authenticated token.

        Callers must invoke this only on a bounded worker whose filesystem
        identity is explicitly authorized to read the peer image: either the
        exact restricted KeeperAuthority virtual-service worker for the closed
        per-user Host tree, or the Host's narrowly impersonated Authority-client
        worker for the protected service tree. The process handle, creation
        time, path, SID, and session are checked before the path is resolved and
        again by the caller after observation.
        """
        current = self.revalidate_core(expected_sid)
        canonical, file_identity = _process_executable_file_identity(
            current.executable_path
        )
        if os.path.normcase(canonical) != os.path.normcase(current.executable_path):
            raise PermissionError(
                "authority client process executable path is aliased"
            )
        measured = replace(
            current,
            executable_path=canonical,
            executable_file_identity=file_identity,
        )
        if _valid_file_identity(self.identity.executable_file_identity):
            if measured != self.identity:
                raise PermissionError(
                    "authority client process executable identity changed"
                )
        else:
            self.identity = measured
        return self.identity

    def release(self) -> None:
        if self._released:
            return
        failures: list[str] = []
        kernel32 = _kernel32()
        for label, handle in (
            ("process-token", self.process_token),
            ("process", self.process),
        ):
            if handle > 0 and not kernel32.CloseHandle(wintypes.HANDLE(handle)):
                failures.append(f"{label}:{ctypes.get_last_error()}")
        self.process_token = 0
        self.process = 0
        self._released = True
        if failures:
            raise PermissionError(
                "authority client process binding cleanup failed: "
                + ",".join(failures)
            )


def _require_read_only_disk_handle(handle: int) -> None:
    """Reject non-file, non-readable, writable, or administrable handles."""
    kernel32 = _kernel32()
    if int(kernel32.GetFileType(wintypes.HANDLE(handle))) != 0x0001:
        raise PermissionError("authority client handle is not a disk file")
    basic = _PublicObjectBasicInformation()
    returned = wintypes.ULONG()
    status = int(
        _ntdll().NtQueryObject(
            wintypes.HANDLE(handle),
            0,
            ctypes.byref(basic),
            ctypes.sizeof(basic),
            ctypes.byref(returned),
        )
    )
    if status != 0:
        raise PermissionError(
            "authority client handle access cannot be verified: "
            f"0x{status & 0xFFFFFFFF:08X}"
        )
    write_or_control = (
        0x00000002
        | 0x00000004
        | 0x00000010
        | 0x00000100
        | 0x00010000
        | 0x00040000
        | 0x00080000
        | 0x10000000
        | 0x40000000
    )
    if (
        not basic.GrantedAccess & 0x00000001
        or basic.GrantedAccess & write_or_control
    ):
        raise PermissionError("authority client handle is not read-only")


@contextmanager
def authenticated_named_pipe_client_process(
    pipe: int, expected_sid: str
) -> Iterator[NamedPipeClientProcessBinding]:
    """Bind a local pipe peer to a retained process handle and token identity."""
    with _authenticated_named_pipe_peer_process(
        pipe, expected_sid, server=False
    ) as binding:
        yield binding


@contextmanager
def authenticated_named_pipe_server_process(
    pipe: int, expected_sid: str
) -> Iterator[NamedPipeClientProcessBinding]:
    """Bind the exact local process serving one connected named-pipe instance."""
    with _authenticated_named_pipe_peer_process(
        pipe, expected_sid, server=True
    ) as binding:
        yield binding


@contextmanager
def _authenticated_named_pipe_peer_process(
    pipe: int, expected_sid: str, *, server: bool
) -> Iterator[NamedPipeClientProcessBinding]:
    if os.name != "nt":
        raise RuntimeError("Windows identity is unavailable")
    process_id = (
        _named_pipe_server_process_id(pipe)
        if server
        else _named_pipe_client_process_id(pipe)
    )
    process_access = PROCESS_QUERY_LIMITED_INFORMATION
    process = _kernel32().OpenProcess(
        process_access,
        False,
        process_id,
    )
    if not process:
        raise PermissionError(
            "authority client process cannot be inspected: "
            f"{ctypes.get_last_error()}"
        )
    process_token = 0
    binding: NamedPipeClientProcessBinding | None = None
    try:
        process_value = _handle_value(process)
        process_token = _open_process_token(
            process_value,
            TOKEN_QUERY if server else TOKEN_QUERY | TOKEN_DUPLICATE,
        )
        identity = (
            _inspect_bound_named_pipe_server(
                pipe, process_value, process_token
            )
            if server
            else _inspect_bound_named_pipe_client(
                pipe, process_value, process_token
            )
        )
        if identity.process_id != process_id:
            raise PermissionError("authority client process ID changed")
        if identity.sid.casefold() != expected_sid.casefold():
            raise PermissionError("authority client process SID is mismatched")
        binding = NamedPipeClientProcessBinding(
            pipe, process_value, process_token, identity, server=server
        )
        binding.revalidate_core(expected_sid)
        yield binding
    finally:
        if binding is None:
            failures: list[str] = []
            kernel32 = _kernel32()
            if process_token > 0 and not kernel32.CloseHandle(
                wintypes.HANDLE(process_token)
            ):
                failures.append(f"process-token:{ctypes.get_last_error()}")
            if not kernel32.CloseHandle(process):
                failures.append(f"process:{ctypes.get_last_error()}")
            if failures:
                raise PermissionError(
                    "authority client process binding cleanup failed: "
                    + ",".join(failures)
                )
        else:
            binding.release()


class NamedPipeRestrictedServiceProcessBinding:
    """Retain a service peer process without opening its process token."""

    def __init__(
        self,
        pipe: int,
        process: int,
        identity: NamedPipeClientProcessIdentity,
    ) -> None:
        if (
            identity.process_creation_time_100ns <= 0
            or not Path(identity.executable_path).is_absolute()
        ):
            raise PermissionError(
                "Authority service process lifetime or image is invalid"
            )
        self.pipe = pipe
        self.process = process
        self.identity = identity
        self._released = False

    def revalidate_core(self) -> NamedPipeClientProcessIdentity:
        if self._released:
            raise PermissionError("Authority service process binding is released")
        current = _inspect_named_pipe_client_identity(
            self.pipe,
            self.process,
            self.identity.sid,
            self.identity.session_id,
        )
        if _process_core_identity(current) != _process_core_identity(self.identity):
            raise PermissionError("Authority service process identity changed")
        return current

    def bind_or_revalidate_signed_executable_identity(
        self,
        expected_sid: str,
        *,
        expected_path: str,
        expected_file_identity: tuple[int, int, int, int],
    ) -> NamedPipeClientProcessIdentity:
        current = self.revalidate_core()
        if (
            current.sid.casefold() != expected_sid.casefold()
            or not Path(expected_path).is_absolute()
            or os.path.normcase(current.executable_path)
            != os.path.normcase(expected_path)
            or not _valid_file_identity(expected_file_identity)
        ):
            raise PermissionError("Authority service process SID is mismatched")
        measured = replace(
            current,
            executable_path=expected_path,
            executable_file_identity=expected_file_identity,
        )
        if _valid_file_identity(self.identity.executable_file_identity):
            if measured != self.identity:
                raise PermissionError("Authority service executable identity changed")
        else:
            self.identity = measured
        return self.identity

    def release(self) -> None:
        if self._released:
            return
        process = self.process
        self.process = 0
        self._released = True
        if process > 0 and not _kernel32().CloseHandle(wintypes.HANDLE(process)):
            raise PermissionError(
                "Authority service process binding cleanup failed: "
                f"{ctypes.get_last_error()}"
            )


@contextmanager
def authenticated_named_pipe_restricted_service_process(
    pipe: int,
    *,
    token_identity: RestrictedServicePipeTokenIdentity,
) -> Iterator[NamedPipeRestrictedServiceProcessBinding]:
    """Bind the authenticated restricted-service peer after clean reversion."""
    if os.name != "nt":
        raise RuntimeError("Windows identity is unavailable")
    if not _SERVICE_SID.fullmatch(token_identity.service_sid):
        raise PermissionError("Authority service SID is invalid")
    kernel32 = _kernel32()
    process = wintypes.HANDLE()
    binding: NamedPipeRestrictedServiceProcessBinding | None = None
    try:
        _require_thread_not_impersonating()
        process_id = _named_pipe_client_process_id(pipe)
        pipe_session = _named_pipe_client_session_id(pipe)
        if (
            process_id != token_identity.process_id
            or pipe_session != token_identity.session_id
            or pipe_session != 0
        ):
            raise PermissionError("Authority service pipe session differs")
        process = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, process_id
        )
        if not process:
            raise PermissionError(
                "Authority service process cannot be inspected: "
                f"{ctypes.get_last_error()}"
            )
        identity = _inspect_named_pipe_client_identity(
            pipe,
            _handle_value(process),
            token_identity.service_sid,
            token_identity.session_id,
        )
        if identity.process_id != process_id:
            raise PermissionError("Authority service process ID changed")
        binding = NamedPipeRestrictedServiceProcessBinding(
            pipe, _handle_value(process), identity
        )
        binding.revalidate_core()
        yield binding
    finally:
        failures: list[str] = []
        if binding is None:
            process_value = getattr(process, "value", process)
            if isinstance(process_value, int) and process_value > 0:
                if not kernel32.CloseHandle(process):
                    failures.append(f"process:{ctypes.get_last_error()}")
        else:
            try:
                binding.release()
            except PermissionError as error:
                failures.append(str(error))
        if failures:
            raise PermissionError(
                "Authority service peer cleanup failed: " + ",".join(failures)
            )


def authenticated_named_pipe_restricted_service_token(
    pipe: int,
    *,
    expected_service_sid: str,
) -> RestrictedServicePipeTokenIdentity:
    """Authenticate only the impersonated pipe token; perform no process I/O."""
    if os.name != "nt":
        raise RuntimeError("Windows identity is unavailable")
    if not _SERVICE_SID.fullmatch(expected_service_sid):
        raise PermissionError("Authority service SID is invalid")
    advapi32 = _advapi32()
    kernel32 = _kernel32()
    token = wintypes.HANDLE()
    if not advapi32.OpenThreadToken(
        kernel32.GetCurrentThread(),
        TOKEN_QUERY,
        True,
        ctypes.byref(token),
    ):
        raise PermissionError(
            "Authority service impersonation token is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    try:
        token_value = _handle_value(token)
        user_sid = _token_sid(token_value)
        token_session = _token_session_id(token_value)
        restricting_sids = tuple(_token_restricting_sids(token_value))
        impersonation_level = _token_dword(
            token_value, TOKEN_IMPERSONATION_LEVEL
        )
        folded_restricting_sids = {
            sid.casefold() for sid in restricting_sids
        }
        if (
            user_sid.casefold() != expected_service_sid.casefold()
            or token_session != 0
            or not bool(advapi32.IsTokenRestricted(token))
            or _token_dword(token_value, TOKEN_TYPE) != TOKEN_IMPERSONATION
            or impersonation_level
            not in {SECURITY_IDENTIFICATION, SECURITY_IMPERSONATION}
            or expected_service_sid.casefold() not in folded_restricting_sids
            or RESTRICTED_CODE_SID.casefold() in folded_restricting_sids
        ):
            raise PermissionError(
                "Authority service restricted-token identity differs"
            )
        process_id = _named_pipe_client_process_id(pipe)
        pipe_session = _named_pipe_client_session_id(pipe)
        if pipe_session != token_session:
            raise PermissionError("Authority service pipe session differs")
        return RestrictedServicePipeTokenIdentity(
            process_id=process_id,
            session_id=token_session,
            service_sid=user_sid,
            restricting_sids=restricting_sids,
            impersonation_level=impersonation_level,
        )
    finally:
        if token.value and not kernel32.CloseHandle(token):
            raise PermissionError(
                "Authority service peer cleanup failed: thread-token:"
                f"{ctypes.get_last_error()}"
            )


def _require_thread_not_impersonating() -> None:
    advapi32 = _advapi32()
    kernel32 = _kernel32()
    token = wintypes.HANDLE()
    ctypes.set_last_error(0)
    if advapi32.OpenThreadToken(
        kernel32.GetCurrentThread(), TOKEN_QUERY, True, ctypes.byref(token)
    ):
        try:
            raise PermissionError("Authority service peer thread is impersonating")
        finally:
            kernel32.CloseHandle(token)
    error = ctypes.get_last_error()
    if error != 1008:
        raise PermissionError(
            "Authority service peer thread identity is unavailable: "
            f"{error}"
        )


def current_process_sid() -> str:
    if os.name != "nt":
        raise RuntimeError("Windows identity is unavailable")
    kernel32 = _kernel32()
    return _process_sid(int(kernel32.GetCurrentProcess()))


def require_current_restricted_service_identity(
    expected_service_sid: str,
) -> str:
    """Require this process to be the exact session-zero restricted service.

    KeeperAuthority runs as the virtual account
    ``NT SERVICE\\KeeperAuthority``.
    Its TokenUser is therefore the unique service SID, and
    SERVICE_SID_TYPE_RESTRICTED also places that SID in the token's restricting
    set.  Both halves are required so another service account, LocalSystem, or
    an unrestricted process cannot satisfy the production identity boundary.
    """
    if os.name != "nt":
        raise RuntimeError("Windows identity is unavailable")
    if not _SERVICE_SID.fullmatch(expected_service_sid):
        raise PermissionError("Authority service SID is invalid")
    kernel32 = _kernel32()
    token = _open_process_token(int(kernel32.GetCurrentProcess()), TOKEN_QUERY)
    try:
        user_sid = _token_sid(token)
        restricting = tuple(_token_restricting_sids(token))
        restricting_sids = {sid.casefold() for sid in restricting}
        logon_sids = tuple(sid for sid in restricting if _LOGON_SID.fullmatch(sid))
        required_restricting = {
            expected_service_sid.casefold(),
            WORLD_SID.casefold(),
            WRITE_RESTRICTED_CODE_SID.casefold(),
            *(sid.casefold() for sid in logon_sids),
        }
        if (
            user_sid.casefold() != expected_service_sid.casefold()
            or _token_session_id(token) != 0
            or not bool(_advapi32().IsTokenRestricted(wintypes.HANDLE(token)))
            or _token_dword(token, TOKEN_TYPE) != TOKEN_PRIMARY
            or expected_service_sid.casefold() not in restricting_sids
            or RESTRICTED_CODE_SID.casefold() in restricting_sids
            or len(logon_sids) != 1
            or restricting_sids != required_restricting
        ):
            raise PermissionError(
                "Authority process restricted virtual-service identity differs"
            )
        return user_sid
    finally:
        if not kernel32.CloseHandle(wintypes.HANDLE(token)):
            raise PermissionError(
                "Authority process-token handle cleanup failed: "
                f"{ctypes.get_last_error()}"
            )


def process_sid(process_id: int) -> str:
    if os.name != "nt":
        raise RuntimeError("Windows identity is unavailable")
    kernel32 = _kernel32()
    process = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, process_id
    )
    if not process:
        raise PermissionError(
            f"authority client process cannot be inspected: {ctypes.get_last_error()}"
        )
    try:
        return _process_sid(_handle_value(process))
    finally:
        kernel32.CloseHandle(process)


def _inspect_named_pipe_client(
    pipe: int, process: int
) -> NamedPipeClientProcessIdentity:
    token_sid, token_session = _process_token_sid_and_session(process)
    return _inspect_named_pipe_client_identity(
        pipe, process, token_sid, token_session
    )


def _inspect_bound_named_pipe_client(
    pipe: int, process: int, process_token: int
) -> NamedPipeClientProcessIdentity:
    token_sid, token_session = _token_sid_and_session(process_token)
    return _inspect_named_pipe_client_identity(
        pipe, process, token_sid, token_session
    )


def _inspect_bound_named_pipe_server(
    pipe: int, process: int, process_token: int
) -> NamedPipeClientProcessIdentity:
    token_sid, token_session = _token_sid_and_session(process_token)
    return _build_named_pipe_peer_identity(
        process_id=_named_pipe_server_process_id(pipe),
        direct_session=_named_pipe_server_session_id(pipe),
        process=process,
        token_sid=token_sid,
        token_session=token_session,
        computer_name=_local_computer_name(),
    )


def _inspect_named_pipe_client_identity(
    pipe: int,
    process: int,
    token_sid: str,
    token_session: int,
) -> NamedPipeClientProcessIdentity:
    return _build_named_pipe_peer_identity(
        process_id=_named_pipe_client_process_id(pipe),
        direct_session=_named_pipe_client_session_id(pipe),
        process=process,
        token_sid=token_sid,
        token_session=token_session,
        computer_name=_named_pipe_client_computer_name(pipe),
    )


def _build_named_pipe_peer_identity(
    *,
    process_id: int,
    direct_session: int,
    process: int,
    token_sid: str,
    token_session: int,
    computer_name: str,
) -> NamedPipeClientProcessIdentity:
    if _process_handle_id(process) != process_id:
        raise PermissionError("authority client process handle is mismatched")
    pid_session = _process_id_session(process_id)
    if direct_session != token_session:
        raise PermissionError("authority client Windows session is mismatched")
    if pid_session is not None and pid_session != direct_session:
        raise PermissionError("authority client Windows session is mismatched")
    if not _process_is_active(process):
        raise PermissionError("authority client process is not active")
    local_name = _local_computer_name()
    normalized_computer_name = computer_name.lstrip("\\")
    if (
        normalized_computer_name.casefold()
        not in {local_name.casefold(), "."}
    ):
        raise PermissionError("remote authority clients are unauthorized")
    creation_time = _process_creation_time(process)
    executable_path = _process_executable_path(process)
    return NamedPipeClientProcessIdentity(
        process_id=process_id,
        session_id=direct_session,
        sid=token_sid,
        computer_name=computer_name,
        process_creation_time_100ns=creation_time,
        executable_path=executable_path,
        executable_file_identity=(0, 0, 0, 0),
    )


def _named_pipe_client_process_id(pipe: int) -> int:
    value = wintypes.ULONG()
    if not _kernel32().GetNamedPipeClientProcessId(
        wintypes.HANDLE(pipe), ctypes.byref(value)
    ):
        raise PermissionError(
            "authority named-pipe client process is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    if value.value <= 0:
        raise PermissionError("authority named-pipe client process is invalid")
    return int(value.value)


def _named_pipe_server_process_id(pipe: int) -> int:
    return _named_pipe_peer_process_id(pipe, server=True)


def _named_pipe_peer_process_id(pipe: int, *, server: bool) -> int:
    value = wintypes.ULONG()
    operation = (
        _kernel32().GetNamedPipeServerProcessId
        if server
        else _kernel32().GetNamedPipeClientProcessId
    )
    if not operation(wintypes.HANDLE(pipe), ctypes.byref(value)):
        raise PermissionError(
            "authority named-pipe client process is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    if value.value <= 0:
        raise PermissionError("authority named-pipe client process is invalid")
    return int(value.value)


def _named_pipe_client_session_id(pipe: int) -> int:
    value = wintypes.ULONG()
    if not _kernel32().GetNamedPipeClientSessionId(
        wintypes.HANDLE(pipe), ctypes.byref(value)
    ):
        raise PermissionError(
            "authority named-pipe client session is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    return int(value.value)


def _named_pipe_server_session_id(pipe: int) -> int:
    return _named_pipe_peer_session_id(pipe, server=True)


def _named_pipe_peer_session_id(pipe: int, *, server: bool) -> int:
    value = wintypes.ULONG()
    operation = (
        _kernel32().GetNamedPipeServerSessionId
        if server
        else _kernel32().GetNamedPipeClientSessionId
    )
    if not operation(wintypes.HANDLE(pipe), ctypes.byref(value)):
        raise PermissionError(
            "authority named-pipe client session is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    return int(value.value)


def _named_pipe_client_computer_name(pipe: int) -> str:
    size = 256
    buffer = ctypes.create_unicode_buffer(size)
    if not _kernel32().GetNamedPipeClientComputerNameW(
        wintypes.HANDLE(pipe), buffer, size
    ):
        error = ctypes.get_last_error()
        if error == ERROR_PIPE_LOCAL:
            return _local_computer_name()
        raise PermissionError(
            "authority named-pipe client computer is unavailable: "
            f"{error}"
        )
    value = buffer.value.strip()
    if not value:
        raise PermissionError("authority named-pipe client computer is invalid")
    return value


def _local_computer_name() -> str:
    size = wintypes.DWORD(256)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not _kernel32().GetComputerNameW(buffer, ctypes.byref(size)):
        raise PermissionError(
            "authority local computer identity is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    value = buffer.value.strip()
    if not value:
        raise PermissionError("authority local computer identity is invalid")
    return value


def _process_id_session(process_id: int) -> int | None:
    """Return optional PID/session corroboration without broader process rights."""
    value = wintypes.DWORD()
    if not _kernel32().ProcessIdToSessionId(process_id, ctypes.byref(value)):
        error = ctypes.get_last_error()
        if error == ERROR_ACCESS_DENIED:
            return None
        raise PermissionError(
            "authority client process session is unavailable: "
            f"{error}"
        )
    return int(value.value)


def _process_handle_id(process: int) -> int:
    process_id = int(_kernel32().GetProcessId(wintypes.HANDLE(process)))
    if process_id <= 0:
        raise PermissionError(
            "authority client process handle identity is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    return process_id


def _process_token_sid_and_session(process: int) -> tuple[str, int]:
    token = _open_process_token(process, TOKEN_QUERY)
    try:
        return _token_sid_and_session(token)
    finally:
        if not _kernel32().CloseHandle(wintypes.HANDLE(token)):
            raise PermissionError(
                "authority client process-token handle cleanup failed: "
                f"{ctypes.get_last_error()}"
            )


def _open_process_token(process: int, access: int) -> int:
    token = wintypes.HANDLE()
    if not _advapi32().OpenProcessToken(
        wintypes.HANDLE(process), access, ctypes.byref(token)
    ):
        raise PermissionError(
            "authority client process token cannot be opened: "
            f"{ctypes.get_last_error()}"
        )
    return _handle_value(token)


def _token_sid_and_session(token: int) -> tuple[str, int]:
    return _token_sid(token), _token_session_id(token)


def _process_is_active(process: int) -> bool:
    exit_code = wintypes.DWORD()
    if not _kernel32().GetExitCodeProcess(
        wintypes.HANDLE(process), ctypes.byref(exit_code)
    ):
        raise PermissionError(
            "authority client process state is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    return int(exit_code.value) == STILL_ACTIVE


def _process_creation_time(process: int) -> int:
    creation = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel = wintypes.FILETIME()
    user = wintypes.FILETIME()
    if not _kernel32().GetProcessTimes(
        wintypes.HANDLE(process),
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        raise PermissionError(
            "authority client process creation identity is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    value = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
    if value <= 0:
        raise PermissionError("authority client process creation identity is invalid")
    return value


def _process_executable_path(process: int) -> str:
    size = wintypes.DWORD(32768)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not _kernel32().QueryFullProcessImageNameW(
        wintypes.HANDLE(process), 0, buffer, ctypes.byref(size)
    ):
        raise PermissionError(
            "authority client process executable is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    lexical = Path(buffer.value)
    if not lexical.is_absolute():
        raise PermissionError("authority client process executable is invalid")
    return os.path.abspath(str(lexical))


def _process_executable_file_identity(
    executable_path: str,
) -> tuple[str, tuple[int, int, int, int]]:
    lexical = Path(executable_path)
    if not lexical.is_absolute():
        raise PermissionError("authority client process executable is invalid")
    canonical = lexical.resolve(strict=True)
    stat = canonical.stat()
    identity = (
        int(stat.st_dev),
        int(stat.st_ino),
        int(stat.st_size),
        int(stat.st_mtime_ns),
    )
    if not _valid_file_identity(identity):
        raise PermissionError(
            "authority client process executable identity is invalid"
        )
    return str(canonical), identity


def _valid_file_identity(value: tuple[int, int, int, int]) -> bool:
    return value[0] >= 0 and value[1] > 0 and value[2] > 0 and value[3] > 0


def _process_core_identity(
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


def named_pipe_client_sid(pipe: int) -> str:
    return named_pipe_client_identity(pipe).sid


def named_pipe_client_identity(pipe: int) -> WindowsTokenIdentity:
    if os.name != "nt":
        raise RuntimeError("Windows identity is unavailable")
    advapi32 = _advapi32()
    if not advapi32.ImpersonateNamedPipeClient(pipe):
        raise PermissionError(
            f"authority client impersonation failed: {ctypes.get_last_error()}"
        )
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenThreadToken(
            _kernel32().GetCurrentThread(),
            TOKEN_QUERY,
            True,
            ctypes.byref(token),
        ):
            raise PermissionError(
                "authority client token cannot be opened: "
                f"{ctypes.get_last_error()}"
            )
        token_value = _handle_value(token)
        return WindowsTokenIdentity(
            _token_sid(token_value),
            bool(advapi32.IsTokenRestricted(token)),
            _token_integrity_rid(token_value),
        )
    finally:
        if token.value:
            _kernel32().CloseHandle(token)
        if not advapi32.RevertToSelf():
            raise PermissionError(
                "authority client impersonation could not be reverted: "
                f"{ctypes.get_last_error()}"
            )


def process_image(process_id: int) -> Path:
    kernel32 = _kernel32()
    process = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, process_id
    )
    if not process:
        raise PermissionError(
            f"provider process cannot be inspected: {ctypes.get_last_error()}"
        )
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(
            process, 0, buffer, ctypes.byref(size)
        ):
            raise PermissionError(
                f"provider process image cannot be inspected: {ctypes.get_last_error()}"
            )
        return Path(buffer.value).resolve(strict=True)
    finally:
        kernel32.CloseHandle(process)


def _process_sid(process: int) -> str:
    advapi32 = _advapi32()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
        raise PermissionError(
            f"Windows process token cannot be opened: {ctypes.get_last_error()}"
        )
    try:
        return _token_sid(_handle_value(token))
    finally:
        _kernel32().CloseHandle(token)


def _token_sid(token: int) -> str:
    advapi32 = _advapi32()
    needed = wintypes.DWORD()
    advapi32.GetTokenInformation(
        token, TOKEN_USER, None, 0, ctypes.byref(needed)
    )
    if not needed.value:
        raise PermissionError("Windows token identity is unavailable")
    buffer = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetTokenInformation(
        token, TOKEN_USER, buffer, needed, ctypes.byref(needed)
    ):
        raise PermissionError(
            f"Windows token identity cannot be read: {ctypes.get_last_error()}"
        )
    user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
    return _sid_string(user.User.Sid)


def _token_session_id(token: int) -> int:
    value = wintypes.DWORD()
    needed = wintypes.DWORD()
    if not _advapi32().GetTokenInformation(
        wintypes.HANDLE(token),
        12,
        ctypes.byref(value),
        ctypes.sizeof(value),
        ctypes.byref(needed),
    ):
        raise PermissionError(
            "authority client process-token session is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    return int(value.value)


def _token_dword(token: int, information_class: int) -> int:
    value = wintypes.DWORD()
    needed = wintypes.DWORD()
    if not _advapi32().GetTokenInformation(
        wintypes.HANDLE(token),
        information_class,
        ctypes.byref(value),
        ctypes.sizeof(value),
        ctypes.byref(needed),
    ):
        raise PermissionError(
            "Authority service token policy is unavailable: "
            f"{ctypes.get_last_error()}"
        )
    return int(value.value)


def _token_restricting_sids(token: int) -> tuple[str, ...]:
    needed = wintypes.DWORD()
    _advapi32().GetTokenInformation(
        wintypes.HANDLE(token),
        TOKEN_RESTRICTED_SIDS,
        None,
        0,
        ctypes.byref(needed),
    )
    if not needed.value:
        raise PermissionError(
            "Authority service restricting SIDs are unavailable"
        )
    buffer = ctypes.create_string_buffer(needed.value)
    if not _advapi32().GetTokenInformation(
        wintypes.HANDLE(token),
        TOKEN_RESTRICTED_SIDS,
        buffer,
        needed,
        ctypes.byref(needed),
    ):
        raise PermissionError(
            "Authority service restricting SIDs cannot be read: "
            f"{ctypes.get_last_error()}"
        )
    groups = ctypes.cast(buffer, ctypes.POINTER(_TokenGroups)).contents
    first = ctypes.addressof(groups.Groups)
    values: list[str] = []
    for index in range(int(groups.GroupCount)):
        group = _SidAndAttributes.from_address(
            first + index * ctypes.sizeof(_SidAndAttributes)
        )
        values.append(_sid_string(group.Sid))
    return tuple(sorted(values, key=str.casefold))


def _token_integrity_rid(token: int) -> int:
    advapi32 = _advapi32()
    needed = wintypes.DWORD()
    advapi32.GetTokenInformation(
        token, TOKEN_INTEGRITY_LEVEL, None, 0, ctypes.byref(needed)
    )
    if not needed.value:
        raise PermissionError("Windows token integrity is unavailable")
    buffer = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetTokenInformation(
        token,
        TOKEN_INTEGRITY_LEVEL,
        buffer,
        needed,
        ctypes.byref(needed),
    ):
        raise PermissionError(
            f"Windows token integrity cannot be read: {ctypes.get_last_error()}"
        )
    label = ctypes.cast(
        buffer, ctypes.POINTER(_TokenMandatoryLabel)
    ).contents
    count = int(advapi32.GetSidSubAuthorityCount(label.Label.Sid)[0])
    if count <= 0:
        raise PermissionError("Windows token integrity SID is invalid")
    return int(
        advapi32.GetSidSubAuthority(label.Label.Sid, count - 1)[0]
    )


def _sid_string(sid: int) -> str:
    advapi32 = _advapi32()
    value = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(value)):
        raise PermissionError(
            f"Windows SID conversion failed: {ctypes.get_last_error()}"
        )
    try:
        return str(value.value)
    finally:
        _kernel32().LocalFree(value)


def _kernel32() -> Any:
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentThread.restype = wintypes.HANDLE
    kernel32.GetFileType.argtypes = [wintypes.HANDLE]
    kernel32.GetFileType.restype = wintypes.DWORD
    kernel32.DuplicateHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    kernel32.DuplicateHandle.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetNamedPipeClientProcessId.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.ULONG),
    ]
    kernel32.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    kernel32.GetNamedPipeServerProcessId.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.ULONG),
    ]
    kernel32.GetNamedPipeServerProcessId.restype = wintypes.BOOL
    kernel32.GetNamedPipeClientSessionId.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.ULONG),
    ]
    kernel32.GetNamedPipeClientSessionId.restype = wintypes.BOOL
    kernel32.GetNamedPipeServerSessionId.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.ULONG),
    ]
    kernel32.GetNamedPipeServerSessionId.restype = wintypes.BOOL
    kernel32.GetNamedPipeClientComputerNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.ULONG,
    ]
    kernel32.GetNamedPipeClientComputerNameW.restype = wintypes.BOOL
    kernel32.GetComputerNameW.argtypes = [
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetComputerNameW.restype = wintypes.BOOL
    kernel32.ProcessIdToSessionId.argtypes = [
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel32.GetProcessId.restype = wintypes.DWORD
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    return kernel32


def _ntdll() -> Any:
    ntdll: Any = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtQueryObject.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    ntdll.NtQueryObject.restype = ctypes.c_long
    return ntdll


def _advapi32() -> Any:
    advapi32: Any = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.OpenThreadToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.BOOL,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenThreadToken.restype = wintypes.BOOL
    advapi32.ImpersonateNamedPipeClient.argtypes = [wintypes.HANDLE]
    advapi32.ImpersonateNamedPipeClient.restype = wintypes.BOOL
    advapi32.RevertToSelf.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.IsTokenRestricted.argtypes = [wintypes.HANDLE]
    advapi32.IsTokenRestricted.restype = wintypes.BOOL
    advapi32.GetSidSubAuthorityCount.argtypes = [wintypes.LPVOID]
    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(
        ctypes.c_ubyte
    )
    advapi32.GetSidSubAuthority.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    return advapi32


def _handle_value(handle: object) -> int:
    value = getattr(handle, "value", handle)
    if not isinstance(value, int) or value <= 0:
        raise OSError("Windows handle is invalid")
    return value
