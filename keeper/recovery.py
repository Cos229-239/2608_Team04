from __future__ import annotations

import ctypes
import hashlib
import json
import os
import tempfile
from ctypes import wintypes
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


class ProcessState(str, Enum):
    CONFIRMED_ABSENT = "confirmed_absent"
    CONFIRMED_PRESENT = "confirmed_present"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class ProcessProbe:
    state: ProcessState
    diagnostic: str
    os_error: int | None = None


def probe_process(pid: int | None) -> ProcessProbe:
    if not pid or pid <= 0:
        return ProcessProbe(ProcessState.CONFIRMED_ABSENT, "invalid or missing pid")
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.GetExitCodeProcess.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        )
        kernel32.GetExitCodeProcess.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            return _classify_windows_open_failure(error)
        try:
            exit_code = ctypes.c_uint32()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return ProcessProbe(
                    ProcessState.INDETERMINATE,
                    "process exit state query failed",
                    ctypes.get_last_error(),
                )
            if exit_code.value == 259:
                return ProcessProbe(ProcessState.CONFIRMED_PRESENT, "process is active")
            return ProcessProbe(ProcessState.CONFIRMED_ABSENT, "process has exited")
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError as error:
        return ProcessProbe(
            ProcessState.CONFIRMED_ABSENT, "operating system confirmed absence", error.errno
        )
    except PermissionError as error:
        return ProcessProbe(
            ProcessState.INDETERMINATE, "process query access denied", error.errno
        )
    except OSError as error:
        return ProcessProbe(
            ProcessState.INDETERMINATE,
            "process state could not be established",
            error.errno,
        )
    return ProcessProbe(ProcessState.CONFIRMED_PRESENT, "process is active")


def _classify_windows_open_failure(error: int) -> ProcessProbe:
    if error == 87:
        return ProcessProbe(
            ProcessState.CONFIRMED_ABSENT,
            "operating system confirmed that the pid does not exist",
            error,
        )
    diagnostic = (
        "process query access denied"
        if error in {5, 1314}
        else "process state could not be established"
    )
    return ProcessProbe(ProcessState.INDETERMINATE, diagnostic, error)


def process_exists(pid: int | None) -> bool:
    """Compatibility predicate. Security decisions must use ``probe_process``."""
    return probe_process(pid).state is ProcessState.CONFIRMED_PRESENT


class RetainedProcessHandle(Protocol):
    """A live OS process object retained across validation and termination."""

    @property
    def pid(self) -> int: ...

    def identity(self) -> dict[str, object] | None: ...

    def is_exited(self) -> bool: ...

    def terminate_exact(self, exit_code: int = 1) -> bool: ...

    def close(self) -> None: ...


class _WindowsRetainedProcessHandle:
    def __init__(self, pid: int, handle: int) -> None:
        self._pid = pid
        self._handle = handle
        self._closed = False

    @property
    def pid(self) -> int:
        return self._pid

    def identity(self) -> dict[str, object] | None:
        if self._closed:
            return None
        return _windows_identity_from_handle(self._handle, self._pid)

    def is_exited(self) -> bool:
        if self._closed:
            return False
        kernel32 = _windows_kernel32()
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        return int(kernel32.WaitForSingleObject(self._handle, 0)) == 0

    def terminate_exact(self, exit_code: int = 1) -> bool:
        if self._closed or self.identity() is None:
            return False
        kernel32 = _windows_kernel32()
        kernel32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel32.TerminateProcess.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        if not kernel32.TerminateProcess(self._handle, exit_code):
            return False
        wait_result = int(kernel32.WaitForSingleObject(self._handle, 5000))
        return wait_result == 0 and self.identity() is None

    def close(self) -> None:
        if self._closed:
            return
        kernel32 = _windows_kernel32()
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle(self._handle)
        self._closed = True


def retain_process_handle(pid: int) -> RetainedProcessHandle | None:
    """Acquire one authoritative Windows process object for a destructive boundary."""
    if os.name != "nt" or pid <= 0:
        return None
    kernel32 = _windows_kernel32()
    kernel32.OpenProcess.argtypes = (
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    )
    kernel32.OpenProcess.restype = wintypes.HANDLE
    access = 0x0001 | 0x1000 | 0x00100000
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        return None
    retained = _WindowsRetainedProcessHandle(pid, int(handle))
    if retained.identity() is None:
        retained.close()
        return None
    return retained


def _windows_kernel32() -> Any:
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _windows_identity_from_handle(
    handle: int, expected_pid: int
) -> dict[str, object] | None:
    kernel32 = _windows_kernel32()
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    kernel32.GetProcessId.argtypes = (wintypes.HANDLE,)
    kernel32.GetProcessId.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    )
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    ntdll.NtQueryInformationProcess.argtypes = (
        wintypes.HANDLE,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    )
    ntdll.NtQueryInformationProcess.restype = wintypes.LONG
    if int(kernel32.GetProcessId(handle)) != expected_pid:
        return None
    exit_code = wintypes.DWORD()
    if (
        not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        or exit_code.value != 259
    ):
        return None
    image_buffer = ctypes.create_unicode_buffer(32768)
    image_size = wintypes.DWORD(len(image_buffer))
    if not kernel32.QueryFullProcessImageNameW(
        handle, 0, image_buffer, ctypes.byref(image_size)
    ):
        return None
    creation = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel_time = wintypes.FILETIME()
    user_time = wintypes.FILETIME()
    if not kernel32.GetProcessTimes(
        handle,
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel_time),
        ctypes.byref(user_time),
    ):
        return None

    class ProcessBasicInformation(ctypes.Structure):
        _fields_ = [
            ("Reserved1", wintypes.LPVOID),
            ("PebBaseAddress", wintypes.LPVOID),
            ("Reserved2_0", wintypes.LPVOID),
            ("Reserved2_1", wintypes.LPVOID),
            ("UniqueProcessId", ctypes.c_size_t),
            ("InheritedFromUniqueProcessId", ctypes.c_size_t),
        ]

    basic = ProcessBasicInformation()
    returned = wintypes.ULONG()
    if ntdll.NtQueryInformationProcess(
        handle,
        0,
        ctypes.byref(basic),
        ctypes.sizeof(basic),
        ctypes.byref(returned),
    ) != 0:
        return None
    required = wintypes.ULONG()
    status = ntdll.NtQueryInformationProcess(
        handle, 60, None, 0, ctypes.byref(required)
    )
    if status not in {-1073741820, -1073741789} or required.value <= 2:
        return None
    command_buffer = ctypes.create_string_buffer(required.value)
    if ntdll.NtQueryInformationProcess(
        handle,
        60,
        command_buffer,
        required.value,
        ctypes.byref(returned),
    ) != 0:
        return None
    command_length = ctypes.cast(
        command_buffer, ctypes.POINTER(wintypes.USHORT)
    ).contents.value
    pointer_offset = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 4
    command_pointer = ctypes.c_void_p.from_buffer(
        command_buffer, pointer_offset
    ).value
    if not command_pointer or not command_length:
        return None
    command_line = ctypes.wstring_at(command_pointer, command_length // 2)
    creation_ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
    return {
        "pid": expected_pid,
        "creation_time": str(creation_ticks),
        "executable": str(Path(image_buffer.value).resolve()),
        "command_line_hash": hashlib.sha256(
            command_line.strip().casefold().encode("utf-8")
        ).hexdigest(),
        "parent_pid": int(basic.InheritedFromUniqueProcessId),
    }


def process_identity(pid: int) -> dict[str, object] | None:
    if pid <= 0 or probe_process(pid).state is not ProcessState.CONFIRMED_PRESENT:
        return None
    if os.name == "nt":
        kernel32 = _windows_kernel32()
        kernel32.OpenProcess.argtypes = (
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        try:
            return _windows_identity_from_handle(int(handle), pid)
        finally:
            kernel32.CloseHandle(handle)
    proc = Path("/proc") / str(pid)
    try:
        executable = proc.joinpath("exe").resolve(strict=True)
        command = proc.joinpath("cmdline").read_bytes()
        stat = proc.joinpath("stat").read_text(encoding="utf-8").split()
    except OSError:
        return None
    if len(stat) < 22 or not command:
        return None
    return {
        "pid": pid,
        "creation_time": stat[21],
        "executable": str(executable),
        "command_line_hash": hashlib.sha256(command).hexdigest(),
        "parent_pid": int(stat[3]),
    }


def process_identity_matches(
    ownership: object, current: dict[str, object] | None
) -> bool:
    if not isinstance(ownership, dict) or current is None:
        return False
    required = (
        "pid",
        "creation_time",
        "executable",
        "command_line_hash",
        "parent_pid",
        "launch_nonce",
        "ownership_token",
        "keeper_run_id",
        "task_id",
        "stage_id",
        "provider_run_id",
        "provider_name",
        "provider_instance_id",
        "role",
        "evidence_path",
        "job_or_group_identity",
    )
    if any(ownership.get(key) in {None, ""} for key in required):
        return False
    return all(
        ownership.get(key) == current.get(key)
        for key in (
            "pid",
            "creation_time",
            "executable",
            "command_line_hash",
            "parent_pid",
        )
    )


def ownership_records_match(
    authority: object, evidence: object
) -> bool:
    if not isinstance(authority, dict) or not isinstance(evidence, dict):
        return False
    required = (
        "keeper_run_id",
        "task_id",
        "stage_id",
        "provider_name",
        "provider_instance_id",
        "provider_run_id",
        "role",
        "ownership_token",
        "launch_nonce",
        "evidence_path",
        "pid",
        "creation_time",
        "executable",
        "command_line_hash",
        "parent_pid",
        "job_or_group_identity",
        "started_at",
    )
    if any(
        authority.get(key) in {None, ""} or evidence.get(key) in {None, ""}
        for key in required
    ):
        return False
    return all(authority.get(key) == evidence.get(key) for key in required)
