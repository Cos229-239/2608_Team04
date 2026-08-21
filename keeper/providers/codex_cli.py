from __future__ import annotations

import ctypes
import hashlib
import os
import re
import signal
import shutil
import subprocess
import threading
import uuid
from contextlib import AbstractContextManager, nullcontext
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol, TextIO

from keeper.policies import filtered_environment
from keeper.providers.base import AgentProvider, AgentRequest, ProcessResult
from keeper.recovery import process_identity


_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000


class _ProviderProcess(Protocol):
    pid: int
    stdout: TextIO | None
    stderr: TextIO | None

    def wait(self, timeout: float | None = None) -> int: ...

    def poll(self) -> int | None: ...

    def kill(self) -> None: ...


@dataclass
class _WindowsSuspendedProcess:
    command: str
    process_handle: int
    thread_handle: int
    pid: int
    stdout: TextIO | None
    stderr: TextIO | None

    def resume(self) -> None:
        kernel32 = _windows_kernel32()
        previous_count = int(kernel32.ResumeThread(self.thread_handle))
        if previous_count != 1:
            raise RuntimeError("provider primary thread could not be resumed exactly once")

    def wait(self, timeout: float | None = None) -> int:
        winapi: Any = __import__("_winapi")
        milliseconds = (
            int(winapi.INFINITE)
            if timeout is None
            else max(0, int(timeout * 1000))
        )
        result = int(winapi.WaitForSingleObject(self.process_handle, milliseconds))
        if result == int(winapi.WAIT_TIMEOUT):
            raise subprocess.TimeoutExpired(self.command, float(timeout or 0))
        if result != int(winapi.WAIT_OBJECT_0):
            raise OSError("waiting for the confined provider process failed")
        return int(winapi.GetExitCodeProcess(self.process_handle))

    def poll(self) -> int | None:
        winapi: Any = __import__("_winapi")
        exit_code = int(winapi.GetExitCodeProcess(self.process_handle))
        return None if exit_code == int(winapi.STILL_ACTIVE) else exit_code

    def kill(self) -> None:
        winapi: Any = __import__("_winapi")
        if self.poll() is None:
            try:
                winapi.TerminateProcess(self.process_handle, 124)
            except OSError as error:
                raise OSError(
                    "unable to terminate confined provider process"
                ) from error

    def close(self) -> None:
        errors: list[BaseException] = []
        for stream in (self.stdout, self.stderr):
            if stream is not None:
                try:
                    stream.close()
                except BaseException as error:
                    errors.append(error)
        for handle in (self.thread_handle, self.process_handle):
            try:
                _close_windows_handle(handle)
            except BaseException as error:
                errors.append(error)
        if errors:
            raise RuntimeError("provider process handles were not fully closed") from errors[0]


class CliProvider(AgentProvider):
    """Runs a configurable local development-agent command."""

    def __init__(
        self,
        command_template: tuple[str, ...],
        provider_name: str = "primary",
        *,
        expected_executable_sha256: str | None = None,
        expected_executable_size: int | None = None,
        registration_id: str | None = None,
        registration_version: str | None = None,
        configuration_digest: str | None = None,
        expected_script_sha256: str | None = None,
        expected_script_size: int | None = None,
        script_registration_id: str | None = None,
        script_registration_version: str | None = None,
        before_process_create: Callable[[Path], None] | None = None,
        require_prompt_placeholder: bool = True,
        launch_guard: Callable[[], AbstractContextManager[None]] | None = None,
    ) -> None:
        self.command_script: Path | None = None
        if (
            os.name == "nt"
            and command_template
            and Path(command_template[0]).suffix.casefold() in {".cmd", ".bat"}
        ):
            self.command_script = Path(command_template[0]).resolve(strict=True)
            launcher = Path(os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"))
            command_template = (str(launcher), *command_template[1:])
        self.command_template = command_template
        self.provider_name = provider_name
        self.expected_executable_sha256 = expected_executable_sha256
        self.expected_executable_size = expected_executable_size
        self.registration_id = registration_id
        self.registration_version = registration_version
        self.configuration_digest = configuration_digest
        self.expected_script_sha256 = expected_script_sha256
        self.expected_script_size = expected_script_size
        self.script_registration_id = script_registration_id
        self.script_registration_version = script_registration_version
        self.before_process_create = before_process_create
        self.require_prompt_placeholder = require_prompt_placeholder
        self.launch_guard = launch_guard
        self.instance_id = uuid.uuid4().hex
        self._active_process: _ProviderProcess | None = None
        self._active_job: int | None = None

    def build_command(self, request: AgentRequest) -> list[str]:
        substitutions = {
            "{prompt}": str(request.prompt_path),
            "{workspace}": str(request.workspace),
            "{role}": request.role,
            "{reasoning}": request.reasoning_level,
        }
        return [substitutions.get(part, part) for part in self.command_template]

    def validate(self) -> None:
        self._validated_executable()

    def _validated_executable(self) -> tuple[Path, bytes]:
        if not self.command_template:
            raise RuntimeError(
                "agent provider command is not configured; set provider_command "
                "in .ai-workflow/config.json"
            )
        executable = self.command_template[0]
        if not Path(executable).exists() and shutil.which(executable) is None:
            raise RuntimeError(f"configured agent provider executable was not found: {executable}")
        if (
            self.expected_executable_sha256 is None
            or self.expected_executable_size is None
            or not self.registration_id
            or not self.registration_version
            or not self.configuration_digest
        ):
            raise PermissionError("immutable provider executable registration is incomplete")
        resolved = Path(executable).resolve(strict=True)
        content = resolved.read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        if (
            actual != self.expected_executable_sha256
            or len(content) != self.expected_executable_size
        ):
            raise PermissionError(
                "provider executable content changed after registration"
            )
        if self.command_script is not None:
            if (
                self.expected_script_sha256 is None
                or self.expected_script_size is None
                or not self.script_registration_id
                or not self.script_registration_version
            ):
                raise PermissionError(
                    "immutable batch-script registration is incomplete"
                )
            script_content = self.command_script.read_bytes()
            if (
                hashlib.sha256(script_content).hexdigest()
                != self.expected_script_sha256
                or len(script_content) != self.expected_script_size
            ):
                raise PermissionError(
                    "provider batch script changed after registration"
                )
        if self.require_prompt_placeholder and "{prompt}" not in self.command_template:
            raise RuntimeError("provider_command must include the {prompt} argument placeholder")
        return resolved, content

    def run(self, request: AgentRequest) -> ProcessResult:
        guard = self.launch_guard() if self.launch_guard is not None else nullcontext()
        with guard:
            return self._run_guarded(request)

    def _run_guarded(self, request: AgentRequest) -> ProcessResult:
        registered_path, registered_content = self._validated_executable()
        request.stdout_path.parent.mkdir(parents=True, exist_ok=True)
        retained_executable_handles: list[int] = []
        protected_executable_fd: int | None = None
        protected_path = registered_path
        if os.name == "nt":
            retained_executable_handles.append(
                _retain_windows_file(registered_path, "registered executable")
            )
            if self.command_script is not None:
                retained_executable_handles.append(
                    _retain_windows_file(self.command_script, "registered command script")
                )
            if hashlib.sha256(registered_path.read_bytes()).hexdigest() != (
                self.expected_executable_sha256
            ):
                for handle in retained_executable_handles:
                    _close_windows_handle(handle)
                raise PermissionError(
                    "retained provider executable failed identity verification"
                )
            if self.command_script is not None and hashlib.sha256(
                self.command_script.read_bytes()
            ).hexdigest() != self.expected_script_sha256:
                for handle in retained_executable_handles:
                    _close_windows_handle(handle)
                raise PermissionError(
                    "retained provider batch script failed identity verification"
                )
        else:
            protected_executable_fd, protected_path = _sealed_executable(
                registered_content
            )
        environment = filtered_environment(dict(os.environ))
        environment["KEEPER_PROVIDER_ROLE"] = request.role
        environment["PATH"] = (
            str(registered_path.parent)
            + os.pathsep
            + environment.get("PATH", "")
        )
        with (
            request.stdout_path.open("w", encoding="utf-8") as stdout,
            request.stderr_path.open("w", encoding="utf-8") as stderr,
        ):
            command = self.build_command(request)
            if self.command_script is not None:
                command = [
                    str(protected_path),
                    "/d",
                    "/c",
                    str(self.command_script),
                    *command[1:],
                ]
            else:
                command[0] = str(protected_path)
            if self.before_process_create is not None:
                self.before_process_create(protected_path)
            job: int | None = None
            if os.name == "nt":
                try:
                    job = _create_configured_windows_job()
                except BaseException:
                    _release_launch_protections(
                        retained_executable_handles, protected_executable_fd
                    )
                    raise
                try:
                    process: Any = _create_windows_process_suspended(
                        command,
                        protected_path,
                        request.workspace,
                        environment,
                    )
                except BaseException:
                    _close_windows_handle(job)
                    _release_launch_protections(
                        retained_executable_handles, protected_executable_fd
                    )
                    raise
                try:
                    _assign_process_to_windows_job(job, process)
                except BaseException:
                    _abort_suspended_windows_launch(
                        process,
                        job,
                        retained_executable_handles,
                        protected_executable_fd,
                    )
                    raise
            else:
                popen_options: dict[str, Any] = {}
                if protected_executable_fd is not None:
                    popen_options["pass_fds"] = (protected_executable_fd,)
                process = subprocess.Popen(
                    command,
                    cwd=request.workspace,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                    start_new_session=True,
                    **popen_options,
                )
            if process.stdout is None or process.stderr is None:
                process.kill()
                process.wait()
                if job:
                    _close_windows_handle(job)
                _release_launch_protections(
                    retained_executable_handles, protected_executable_fd
                )
                raise RuntimeError("provider output streams were not created")
            pumps = [
                threading.Thread(
                    target=self._pump_stream,
                    args=(process.stdout, stdout),
                    daemon=True,
                ),
                threading.Thread(
                    target=self._pump_stream,
                    args=(process.stderr, stderr),
                    daemon=True,
                ),
            ]
            for pump in pumps:
                pump.start()
            self._active_process = process
            self._active_job = job
            try:
                if request.on_process_started is not None:
                    request.on_process_started(process.pid)
                if request.on_process_owned is not None:
                    identity = process_identity(process.pid)
                    if identity is None:
                        raise RuntimeError("provider process ownership could not be established")
                    if Path(str(identity["executable"])).resolve() != protected_path.resolve():
                        raise PermissionError(
                            "launched provider image did not match retained registration"
                        )
                    request.on_process_owned(
                        {
                            **identity,
                            "registered_executable": str(registered_path),
                            "launched_executable": str(protected_path),
                            "launched_executable_sha256": self.expected_executable_sha256,
                            "launched_executable_size": self.expected_executable_size,
                            "registration_id": self.registration_id,
                            "registration_version": self.registration_version,
                            "configuration_digest": self.configuration_digest,
                            "batch_script": (
                                str(self.command_script)
                                if self.command_script is not None
                                else None
                            ),
                            "batch_script_sha256": self.expected_script_sha256,
                            "batch_script_size": self.expected_script_size,
                            "script_registration_id": self.script_registration_id,
                            "script_registration_version": (
                                self.script_registration_version
                            ),
                            "launch_nonce": uuid.uuid4().hex,
                            "ownership_token": uuid.uuid4().hex,
                            "job_or_group_identity": (
                                f"windows-job:{job}"
                                if os.name == "nt"
                                else f"process-group:{process.pid}"
                            ),
                            "started_at": identity.get("creation_time"),
                        }
                    )
                if isinstance(process, _WindowsSuspendedProcess):
                    process.resume()
                exit_code = process.wait(timeout=request.timeout_seconds)
                self._terminate_remaining_group(process, job)
                return ProcessResult(exit_code, request.stdout_path, request.stderr_path, process.pid)
            except subprocess.TimeoutExpired:
                self._terminate_tree(process, job)
                return ProcessResult(124, request.stdout_path, request.stderr_path, process.pid, True)
            except BaseException:
                self._terminate_tree(process, job)
                raise
            finally:
                for pump in pumps:
                    pump.join(timeout=5)
                self._active_process = None
                if job and self._active_job == job:
                    self._active_job = None
                _close_execution_resources(
                    process,
                    job,
                    retained_executable_handles,
                    protected_executable_fd,
                )

    def cancel(self) -> None:
        if self._active_process:
            self._terminate_tree(self._active_process, self._active_job)

    @staticmethod
    def _pump_stream(source: TextIO, destination: TextIO) -> None:
        for line in source:
            destination.write(
                re.sub(
                    r"(?i)(token|secret|password|passwd|api[_-]?key|credential)"
                    r"(\s*[:=]\s*)\S+",
                    r"\1\2[REDACTED]",
                    line,
                )
            )
            destination.flush()

    @staticmethod
    def _terminate_remaining_group(
        process: _ProviderProcess, job: int | None = None
    ) -> None:
        if os.name == "nt":
            kernel32 = _windows_kernel32()
            if not job or not kernel32.TerminateJobObject(job, 0):
                raise RuntimeError("unable to confirm provider descendant termination")
            process.wait(timeout=10)
            return
        killpg = getattr(os, "killpg")
        try:
            killpg(process.pid, signal.SIGTERM)
            killpg(process.pid, getattr(signal, "SIGKILL"))
        except ProcessLookupError:
            return

    @staticmethod
    def _terminate_tree(process: _ProviderProcess, job: int | None = None) -> None:
        if os.name == "nt":
            kernel32 = _windows_kernel32()
            if not job or not kernel32.TerminateJobObject(job, 124):
                raise RuntimeError("unable to terminate provider Windows Job Object")
        else:
            if process.poll() is not None:
                return
            killpg = getattr(os, "killpg")
            killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            if os.name != "nt":
                killpg = getattr(os, "killpg")
                killpg(process.pid, getattr(signal, "SIGKILL"))
            else:
                process.kill()
            process.wait(timeout=10)


class _JobBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JobExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _windows_kernel32() -> Any:
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.IsProcessInJob.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.BOOL),
    ]
    kernel32.IsProcessInJob.restype = wintypes.BOOL
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    return kernel32


def _create_configured_windows_job() -> int:
    kernel32 = _windows_kernel32()
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(
            ctypes.get_last_error(), "unable to create provider Windows Job Object"
        )
    try:
        _configure_windows_job(int(job))
    except BaseException:
        _close_windows_handle(int(job))
        raise
    return int(job)


def _configure_windows_job(job: int) -> None:
    kernel32 = _windows_kernel32()
    information = _JobExtendedLimitInformation()
    information.BasicLimitInformation.LimitFlags = (
        _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    if not kernel32.SetInformationJobObject(
        job,
        _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise OSError(
            ctypes.get_last_error(),
            "unable to configure kill-on-close provider Windows Job Object",
        )


def _duplicate_inheritable_windows_handle(handle: int) -> int:
    winapi: Any = __import__("_winapi")
    return int(
        winapi.DuplicateHandle(
            winapi.GetCurrentProcess(),
            handle,
            winapi.GetCurrentProcess(),
            0,
            True,
            winapi.DUPLICATE_SAME_ACCESS,
        )
    )


def _create_windows_process_suspended(
    command: list[str],
    executable: Path,
    workspace: Path,
    environment: dict[str, str],
) -> _WindowsSuspendedProcess:
    winapi: Any = __import__("_winapi")
    import msvcrt

    stdout_read, stdout_write = winapi.CreatePipe(None, 0)
    stderr_read, stderr_write = winapi.CreatePipe(None, 0)
    stdin_fd = os.open(os.devnull, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    child_handles: list[int] = []
    parent_handles = [
        int(stdout_read),
        int(stdout_write),
        int(stderr_read),
        int(stderr_write),
    ]
    process_handle: int | None = None
    thread_handle: int | None = None
    stdout_stream: TextIO | None = None
    stderr_stream: TextIO | None = None
    created_process: _WindowsSuspendedProcess | None = None
    try:
        child_stdin = _duplicate_inheritable_windows_handle(
            int(msvcrt.get_osfhandle(stdin_fd))
        )
        child_stdout = _duplicate_inheritable_windows_handle(int(stdout_write))
        child_stderr = _duplicate_inheritable_windows_handle(int(stderr_write))
        child_handles.extend((child_stdin, child_stdout, child_stderr))
        winapi.CloseHandle(stdout_write)
        parent_handles.remove(int(stdout_write))
        winapi.CloseHandle(stderr_write)
        parent_handles.remove(int(stderr_write))
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= int(winapi.STARTF_USESTDHANDLES)
        startup.hStdInput = child_stdin
        startup.hStdOutput = child_stdout
        startup.hStdError = child_stderr
        startup.lpAttributeList = {"handle_list": list(child_handles)}
        command_line = subprocess.list2cmdline(command)
        creation_flags = (
            _CREATE_SUSPENDED
            | _CREATE_UNICODE_ENVIRONMENT
            | int(winapi.CREATE_NEW_PROCESS_GROUP)
        )
        process_handle, thread_handle, pid, _thread_id = winapi.CreateProcess(
            str(executable),
            command_line,
            None,
            None,
            True,
            creation_flags,
            environment,
            str(workspace),
            startup,
        )
        for handle in child_handles:
            winapi.CloseHandle(handle)
        child_handles.clear()
        stdout_stream = _windows_text_stream(int(stdout_read))
        parent_handles.remove(int(stdout_read))
        stderr_stream = _windows_text_stream(int(stderr_read))
        parent_handles.remove(int(stderr_read))
        created_process = _WindowsSuspendedProcess(
            command_line,
            int(process_handle),
            int(thread_handle),
            int(pid),
            stdout_stream,
            stderr_stream,
        )
    except BaseException:
        cleanup_error: BaseException | None = None
        for stream in (stdout_stream, stderr_stream):
            if stream is not None:
                try:
                    stream.close()
                except BaseException as error:
                    cleanup_error = cleanup_error or error
        try:
            if process_handle is not None:
                winapi.TerminateProcess(process_handle, 125)
                result = int(winapi.WaitForSingleObject(process_handle, 10_000))
                if result != int(winapi.WAIT_OBJECT_0):
                    raise RuntimeError(
                        "partially created suspended provider did not terminate"
                    )
        except BaseException as error:
            cleanup_error = cleanup_error or error
        for optional_handle in (thread_handle, process_handle):
            if optional_handle is not None:
                try:
                    winapi.CloseHandle(optional_handle)
                except BaseException as error:
                    cleanup_error = cleanup_error or error
        if cleanup_error is not None:
            raise RuntimeError(
                "partially created suspended provider cleanup failed"
            ) from cleanup_error
        raise
    finally:
        finalization_errors: list[BaseException] = []
        try:
            os.close(stdin_fd)
        except BaseException as error:
            finalization_errors.append(error)
        for handle in [*child_handles, *parent_handles]:
            try:
                winapi.CloseHandle(handle)
            except BaseException as error:
                finalization_errors.append(error)
        if finalization_errors:
            if created_process is not None:
                try:
                    created_process.kill()
                    created_process.wait(timeout=10)
                    created_process.close()
                except BaseException as error:
                    finalization_errors.append(error)
            raise RuntimeError(
                "provider standard-handle cleanup failed"
            ) from finalization_errors[0]
    if created_process is None:
        raise RuntimeError("suspended provider creation returned no process")
    return created_process


def _windows_text_stream(handle: int) -> TextIO:
    import msvcrt

    descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY)
    try:
        return os.fdopen(
            descriptor, "r", encoding="utf-8", errors="replace"
        )
    except BaseException:
        os.close(descriptor)
        raise


def _assign_process_to_windows_job(
    job: int, process: _ProviderProcess
) -> None:
    if not isinstance(process, _WindowsSuspendedProcess):
        raise TypeError("Windows Job assignment requires a suspended process")
    kernel32 = _windows_kernel32()
    if not kernel32.AssignProcessToJobObject(job, process.process_handle):
        raise OSError(
            ctypes.get_last_error(),
            "unable to assign suspended provider to Windows Job Object",
        )
    assigned = wintypes.BOOL()
    if (
        not kernel32.IsProcessInJob(
            process.process_handle, job, ctypes.byref(assigned)
        )
        or not assigned.value
    ):
        raise RuntimeError("provider Windows Job Object assignment was not confirmed")


def _abort_suspended_windows_launch(
    process: _ProviderProcess,
    job: int,
    retained_handles: list[int],
    protected_executable_fd: int | None,
) -> None:
    errors: list[BaseException] = []
    kernel32 = _windows_kernel32()
    try:
        kernel32.TerminateJobObject(job, 125)
    except BaseException as error:
        errors.append(error)
    try:
        process.kill()
    except BaseException as error:
        errors.append(error)
    try:
        process.wait(timeout=10)
    except BaseException as error:
        errors.append(error)
    try:
        _close_execution_resources(
            process,
            job,
            retained_handles,
            protected_executable_fd,
        )
    except BaseException as error:
        errors.append(error)
    if errors:
        raise RuntimeError(
            "suspended provider launch could not be terminated cleanly"
        ) from errors[0]


def _close_execution_resources(
    process: _ProviderProcess,
    job: int | None,
    retained_handles: list[int],
    protected_executable_fd: int | None,
) -> None:
    errors: list[BaseException] = []
    if job is not None:
        try:
            _close_windows_handle(job)
        except BaseException as error:
            errors.append(error)
    if isinstance(process, _WindowsSuspendedProcess):
        try:
            process.close()
        except BaseException as error:
            errors.append(error)
    try:
        _release_launch_protections(retained_handles, protected_executable_fd)
    except BaseException as error:
        errors.append(error)
    if errors:
        raise RuntimeError("provider execution handles were not fully closed") from errors[0]


def _release_launch_protections(
    retained_handles: list[int], protected_executable_fd: int | None
) -> None:
    errors: list[BaseException] = []
    for handle in retained_handles:
        try:
            _close_windows_handle(handle)
        except BaseException as error:
            errors.append(error)
    retained_handles.clear()
    if protected_executable_fd is not None:
        try:
            os.close(protected_executable_fd)
        except BaseException as error:
            errors.append(error)
    if errors:
        raise RuntimeError("retained launch protections were not fully closed") from errors[0]


def _retain_windows_file(path: Path, label: str) -> int:
    kernel32: Any = ctypes.windll.kernel32
    kernel32.CreateFileW.restype = ctypes.c_void_p
    handle = kernel32.CreateFileW(
        str(path),
        0x80000000,
        0x00000001,
        None,
        3,
        0x00000080,
        None,
    )
    if not handle or int(handle) == -1:
        raise PermissionError(f"{label} could not be retained against replacement")
    return int(handle)


def _close_windows_handle(handle: int) -> None:
    kernel32: Any = ctypes.windll.kernel32
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_int
    if not kernel32.CloseHandle(ctypes.c_void_p(handle)):
        raise OSError(ctypes.get_last_error(), "unable to close retained file handle")


def _sealed_executable(content: bytes) -> tuple[int, Path]:
    if not hasattr(os, "memfd_create") or not Path("/proc/self/fd").is_dir():
        raise RuntimeError(
            "secure protected executable launch is unavailable on this platform"
        )
    import importlib

    fcntl: Any = importlib.import_module("fcntl")
    memfd_create: Any = getattr(os, "memfd_create")

    descriptor = memfd_create(
        "keeper-provider",
        int(getattr(os, "MFD_CLOEXEC", 1))
        | int(getattr(os, "MFD_ALLOW_SEALING", 2)),
    )
    try:
        view = memoryview(content)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fchmod(descriptor, 0o500)
        os.fsync(descriptor)
        fcntl.fcntl(
            descriptor,
            int(getattr(fcntl, "F_ADD_SEALS", 1033)),
            int(getattr(fcntl, "F_SEAL_SEAL", 1))
            | int(getattr(fcntl, "F_SEAL_SHRINK", 2))
            | int(getattr(fcntl, "F_SEAL_GROW", 4))
            | int(getattr(fcntl, "F_SEAL_WRITE", 8)),
        )
        path = Path(f"/proc/self/fd/{descriptor}")
        if hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(content).digest():
            raise PermissionError("sealed provider executable digest mismatch")
        return descriptor, path
    except BaseException:
        os.close(descriptor)
        raise
