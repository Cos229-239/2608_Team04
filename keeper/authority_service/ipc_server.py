from __future__ import annotations

import ctypes
import threading
import time
from collections import defaultdict, deque
from contextlib import nullcontext
from ctypes import wintypes
from typing import Any

from keeper.authority_service.client import DEFAULT_PIPE_NAME
from keeper.authority_service.core import AuthorityServiceCore
from keeper.authority_service.protocol import (
    Operation,
    decode_frame,
    encode_frame,
    error_response,
    parse_request,
    success_response,
)
from keeper.authority_service.windows_identity import (
    named_pipe_client_identity,
)


_PIPE_ACCESS_DUPLEX = 0x00000003
_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
_PIPE_TYPE_BYTE = 0x00000000
_PIPE_READMODE_BYTE = 0x00000000
_PIPE_WAIT = 0x00000000
_PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
_PIPE_UNLIMITED_INSTANCES = 255
_ERROR_PIPE_CONNECTED = 535
_ERROR_BROKEN_PIPE = 109


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class NamedPipeAuthorityServer:
    def __init__(
        self,
        core: AuthorityServiceCore,
        authorized_client_sid: str,
        *,
        pipe_name: str = DEFAULT_PIPE_NAME,
        maximum_concurrency: int = 4,
        requests_per_minute: int = 120,
    ) -> None:
        if not authorized_client_sid.startswith("S-1-"):
            raise ValueError("authorized Keeper client SID is invalid")
        self.core = core
        self.authorized_client_sid = authorized_client_sid
        self.pipe_name = pipe_name
        self.maximum_concurrency = maximum_concurrency
        self.requests_per_minute = requests_per_minute
        self._stop = threading.Event()
        self.ready = threading.Event()
        self._slots = threading.BoundedSemaphore(maximum_concurrency)
        self._rate_lock = threading.Lock()
        self._request_times: dict[str, deque[float]] = defaultdict(deque)
        self._threads: set[threading.Thread] = set()
        self.accepted_connections = 0

    def serve_forever(self) -> None:
        first = True
        while not self._stop.is_set():
            pipe = self._create_pipe(first)
            first = False
            self.ready.set()
            kernel32 = _kernel32()
            connected = bool(kernel32.ConnectNamedPipe(pipe, None))
            error = ctypes.get_last_error()
            if not connected and error != _ERROR_PIPE_CONNECTED:
                kernel32.CloseHandle(pipe)
                if self._stop.is_set():
                    break
                raise OSError(error, "Keeper Authority named-pipe accept failed")
            self.accepted_connections += 1
            thread = threading.Thread(
                target=self._serve_connection,
                args=(int(pipe),),
                name="keeper-authority-ipc",
                daemon=True,
            )
            self._threads.add(thread)
            thread.start()

    def stop(self) -> None:
        self._stop.set()
        _poke_pipe(self.pipe_name)
        # The service host may terminate after SCM stop timeout; active requests are
        # bounded by provider/request timeouts and never receive a partially signed result.
        for thread in tuple(self._threads):
            if thread.ident is not None:
                thread.join(timeout=5)

    def _serve_connection(self, pipe: int) -> None:
        request_id = "0" * 32
        try:
            request = parse_request(
                decode_frame(lambda length: _read(pipe, length))
            )
            request_id = request.request_id
            client_sid = self._authenticated_client_sid(pipe)
            self._rate_limit(client_sid)
            if not self._slots.acquire(timeout=5):
                raise PermissionError("authority service concurrency limit reached")
            try:
                observer = self.core.observer
                if (
                    observer is not None
                    and (
                        request.operation is Operation.RESERVE_ATTEMPT
                        or request.operation
                        in {
                            Operation.BEGIN_PROVIDER_HOST_ENROLLMENT,
                            Operation.COMPLETE_PROVIDER_HOST_ENROLLMENT,
                            Operation.RECONCILE_PROVIDER_HOST_ENROLLMENT,
                            Operation.REVOKE_PROVIDER_HOST_ENROLLMENT,
                            Operation.DISPOSE_PROVIDER_REGISTRATION_FAILURE,
                            Operation.RECOVER_PROVIDER_REGISTRATION_FAILURE,
                            Operation.AUTHORIZE_EXHAUSTED_PROVIDER_REGISTRATION,
                            Operation.RECOVER_EXHAUSTED_PROVIDER_REGISTRATION,
                            Operation.AUTHORIZE_PROVIDER_QUALIFICATION_RETRY,
                        }
                        or (
                            request.operation is Operation.REGISTER_PROVIDER
                            and "model_allowlist" in request.payload
                        )
                        or (
                            request.operation
                            in {
                                Operation.BEGIN_QUALIFICATION,
                                Operation.RETRY_PROVIDER_QUALIFICATION,
                                Operation.RECONCILE_PROVIDER_QUALIFICATION,
                            }
                            and self._subscription_qualification(
                                request.payload
                            )
                        )
                    )
                    and hasattr(observer, "bind_authenticated_client")
                ):
                    binding = observer.bind_authenticated_client(pipe)
                elif (
                    observer is not None
                    and hasattr(observer, "bind_client")
                    and request.operation
                    in {
                        Operation.REGISTER_PROVIDER,
                        Operation.BEGIN_QUALIFICATION,
                        Operation.RETRY_PROVIDER_QUALIFICATION,
                        Operation.RECONCILE_PROVIDER_QUALIFICATION,
                        Operation.EXECUTE_PROVIDER,
                        Operation.RECORD_PROVIDER_START,
                    }
                ):
                    binding = observer.bind_client(pipe)
                else:
                    binding = nullcontext()
                with binding:
                    result = self.core.dispatch(request, client_sid)
                response = success_response(request_id, result)
            finally:
                self._slots.release()
        except (
            EOFError,
            OSError,
            PermissionError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as error:
            response = error_response(request_id, str(error))
        try:
            _write(pipe, encode_frame(response))
            _kernel32().FlushFileBuffers(pipe)
        except OSError:
            pass
        finally:
            kernel32 = _kernel32()
            kernel32.DisconnectNamedPipe(pipe)
            kernel32.CloseHandle(pipe)
            self._threads.discard(threading.current_thread())

    def _subscription_qualification(
        self, payload: dict[str, Any]
    ) -> bool:
        registration_id = payload.get("registration_id")
        if not isinstance(registration_id, str):
            return False
        registration = self.core.store.get(
            "registrations", registration_id
        )
        if registration is None:
            return False
        return registration.get("registration_schema_version") in {4, 5}

    def _authenticated_client_sid(self, pipe: int) -> str:
        identity = named_pipe_client_identity(pipe)
        if identity.sid != self.authorized_client_sid:
            raise PermissionError("authority client identity is unauthorized")
        if identity.restricted:
            raise PermissionError(
                "restricted authority clients are unauthorized"
            )
        if identity.integrity_rid < 8192:
            raise PermissionError(
                "low-integrity authority clients are unauthorized"
            )
        return identity.sid

    def _rate_limit(self, client_sid: str) -> None:
        now = time.monotonic()
        with self._rate_lock:
            requests = self._request_times[client_sid]
            while requests and requests[0] < now - 60:
                requests.popleft()
            if len(requests) >= self.requests_per_minute:
                raise PermissionError("authority service request rate limit reached")
            requests.append(now)

    def _create_pipe(self, first: bool) -> int:
        descriptor = wintypes.LPVOID()
        # Owner/SYSTEM and the configured desktop SID can use the pipe. The
        # mandatory medium label rejects both reads and writes from
        # low-integrity restricted providers.
        sddl = (
            "D:P(A;;GA;;;SY)(A;;GA;;;OW)"
            f"(A;;GRGW;;;{self.authorized_client_sid})"
            "S:(ML;;NRNW;;;ME)"
        )
        if not _advapi32().ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ):
            raise PermissionError(
                f"authority IPC security descriptor failed: {ctypes.get_last_error()}"
            )
        attributes = _SecurityAttributes(
            ctypes.sizeof(_SecurityAttributes), descriptor, False
        )
        try:
            open_mode = _PIPE_ACCESS_DUPLEX
            if first:
                open_mode |= _FILE_FLAG_FIRST_PIPE_INSTANCE
            handle = _kernel32().CreateNamedPipeW(
                self.pipe_name,
                open_mode,
                _PIPE_TYPE_BYTE
                | _PIPE_READMODE_BYTE
                | _PIPE_WAIT
                | _PIPE_REJECT_REMOTE_CLIENTS,
                _PIPE_UNLIMITED_INSTANCES,
                1_048_580,
                1_048_580,
                15_000,
                ctypes.byref(attributes),
            )
            if handle in {None, ctypes.c_void_p(-1).value}:
                raise PermissionError(
                    f"authority named pipe creation failed: {ctypes.get_last_error()}"
                )
            return int(handle)
        finally:
            _kernel32().LocalFree(descriptor)


def _read(handle: int, length: int) -> bytes:
    buffer = ctypes.create_string_buffer(length)
    read = wintypes.DWORD()
    if not _kernel32().ReadFile(
        handle, buffer, length, ctypes.byref(read), None
    ):
        error = ctypes.get_last_error()
        if error == _ERROR_BROKEN_PIPE:
            return b""
        raise OSError(error, "authority named-pipe read failed")
    return buffer.raw[: read.value]


def _write(handle: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        buffer = ctypes.create_string_buffer(value[offset:])
        written = wintypes.DWORD()
        if not _kernel32().WriteFile(
            handle,
            buffer,
            len(value) - offset,
            ctypes.byref(written),
            None,
        ):
            raise OSError(
                ctypes.get_last_error(), "authority named-pipe write failed"
            )
        if not written.value:
            raise OSError("authority named-pipe write stalled")
        offset += int(written.value)


def _poke_pipe(pipe_name: str) -> None:
    kernel32 = _kernel32()
    handle = kernel32.CreateFileW(
        pipe_name, 0xC0000000, 0, None, 3, 0, None
    )
    if handle not in {None, ctypes.c_void_p(-1).value}:
        kernel32.CloseHandle(handle)


def _kernel32() -> Any:
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SecurityAttributes),
    ]
    kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
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
    kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    kernel32.ConnectNamedPipe.restype = wintypes.BOOL
    kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
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
    kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel32.FlushFileBuffers.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    return kernel32


def _advapi32() -> Any:
    advapi32: Any = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    return advapi32
