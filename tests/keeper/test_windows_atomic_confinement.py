from __future__ import annotations

import ctypes
import gc
import hashlib
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

import pytest

import keeper.providers.codex_cli as codex_cli
from keeper.authority import AuthorityKey
from keeper.providers.base import AgentRequest, ProcessResult
from keeper.providers.codex_cli import CliProvider
from keeper.recovery import process_exists


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows Job confinement")


def _provider(command: tuple[str, ...], **values: Any) -> CliProvider:
    executable = Path(command[0])
    return CliProvider(
        command,
        expected_executable_sha256=hashlib.sha256(
            executable.read_bytes()
        ).hexdigest(),
        expected_executable_size=executable.stat().st_size,
        registration_id="suspended-launch-test",
        registration_version="1",
        configuration_digest="c" * 64,
        **values,
    )


def _request(tmp_path: Path, timeout: int = 10) -> AgentRequest:
    prompt = tmp_path / "prompt.md"
    prompt.write_text("controlled", encoding="utf-8")
    return AgentRequest(
        "builder",
        prompt,
        tmp_path,
        timeout,
        tmp_path / "stdout.log",
        tmp_path / "stderr.log",
    )


def _handle_count() -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetProcessHandleCount.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetProcessHandleCount.restype = wintypes.BOOL
    count = wintypes.DWORD()
    if not kernel32.GetProcessHandleCount(
        kernel32.GetCurrentProcess(), ctypes.byref(count)
    ):
        raise OSError(ctypes.get_last_error(), "handle count failed")
    return int(count.value)


def test_provider_cannot_execute_during_delayed_job_assignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "first-instruction.txt"
    code = f"from pathlib import Path;Path({str(marker)!r}).write_text('ran')"
    provider = _provider((sys.executable, "-c", code, "{prompt}"))
    original_assign = codex_cli._assign_process_to_windows_job
    original_resume = codex_cli._WindowsSuspendedProcess.resume
    assigned = False

    def delayed_assign(job: int, process: Any) -> None:
        nonlocal assigned
        time.sleep(0.4)
        assert marker.exists() is False
        original_assign(job, process)
        assigned = True

    def checked_resume(process: Any) -> None:
        assert assigned
        original_resume(process)

    monkeypatch.setattr(codex_cli, "_assign_process_to_windows_job", delayed_assign)
    monkeypatch.setattr(
        codex_cli._WindowsSuspendedProcess, "resume", checked_resume
    )

    result = provider.run(_request(tmp_path))

    assert result.exit_code == 0
    assert marker.read_text(encoding="utf-8") == "ran"


@pytest.mark.parametrize(
    "failure_stage",
    ["job-configuration", "process-creation", "assignment", "resume"],
)
def test_pre_resume_failure_never_executes_and_leaks_no_handles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    marker = tmp_path / f"{failure_stage}.txt"
    code = f"from pathlib import Path;Path({str(marker)!r}).write_text('unsafe')"
    provider = _provider((sys.executable, "-c", code, "{prompt}"))
    before = _handle_count()

    def fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"{failure_stage} failed")

    if failure_stage == "job-configuration":
        monkeypatch.setattr(codex_cli, "_configure_windows_job", fail)
    elif failure_stage == "process-creation":
        winapi: Any = __import__("_winapi")
        monkeypatch.setattr(winapi, "CreateProcess", fail)
    elif failure_stage == "assignment":
        monkeypatch.setattr(codex_cli, "_assign_process_to_windows_job", fail)
    else:
        monkeypatch.setattr(codex_cli._WindowsSuspendedProcess, "resume", fail)

    with pytest.raises(RuntimeError, match="failed"):
        provider.run(_request(tmp_path))

    gc.collect()
    assert marker.exists() is False
    assert _handle_count() <= before


@pytest.mark.parametrize("invocation", ["executable", "script"])
def test_parent_exit_kills_nested_descendants_before_authority_unlock(
    tmp_path: Path,
    invocation: str,
) -> None:
    authority = AuthorityKey(tmp_path / "data")
    started = tmp_path / f"{invocation}-started.txt"
    nested_started = tmp_path / f"{invocation}-nested-started.txt"
    survived = tmp_path / f"{invocation}-survived.txt"
    accessed = tmp_path / f"{invocation}-authority-access.txt"
    parent = tmp_path / "parent.py"
    child = tmp_path / "child.py"
    grandchild = tmp_path / "grandchild.py"
    parent.write_text(
        "import pathlib,subprocess,sys,time\n"
        "subprocess.Popen([sys.executable,sys.argv[1],*sys.argv[2:]])\n"
        "marker=pathlib.Path(sys.argv[4]);deadline=time.time()+5\n"
        "while not marker.exists() and time.time()<deadline: time.sleep(.02)\n"
        "raise SystemExit(0 if marker.exists() else 3)\n",
        encoding="utf-8",
    )
    child.write_text(
        "import os,pathlib,subprocess,sys,time\n"
        "subprocess.Popen([sys.executable,sys.argv[1],sys.argv[2],"
        "sys.argv[4],sys.argv[5],sys.argv[6]])\n"
        "nested=pathlib.Path(sys.argv[4]);deadline=time.time()+5\n"
        "while not nested.exists() and time.time()<deadline: time.sleep(.02)\n"
        "pathlib.Path(sys.argv[3]).write_text(str(os.getpid()))\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    grandchild.write_text(
        "import os,pathlib,sys,time\n"
        "pathlib.Path(sys.argv[2]).write_text(str(os.getpid()))\n"
        "time.sleep(1)\n"
        "try:\n"
        " open(sys.argv[1],'rb').read(1)\n"
        " pathlib.Path(sys.argv[4]).write_text('opened')\n"
        "except OSError: pass\n"
        "pathlib.Path(sys.argv[3]).write_text('survived')\n",
        encoding="utf-8",
    )
    arguments = (
        str(parent),
        str(child),
        str(grandchild),
        str(authority.path),
        str(started),
        str(nested_started),
        str(survived),
        str(accessed),
    )
    if invocation == "executable":
        provider = _provider(
            (sys.executable, *arguments, "{prompt}"),
            launch_guard=authority.provider_launch_guard,
        )
    else:
        script = tmp_path / "provider.cmd"
        script.write_text(
            f'@echo off\n"{sys.executable}" '
            + " ".join(f'"{item}"' for item in arguments)
            + "\nexit /b %errorlevel%\n",
            encoding="utf-8",
        )
        launcher = Path(os.environ["COMSPEC"])
        provider = CliProvider(
            (str(script), "{prompt}"),
            expected_executable_sha256=hashlib.sha256(
                launcher.read_bytes()
            ).hexdigest(),
            expected_executable_size=launcher.stat().st_size,
            registration_id="suspended-script-test",
            registration_version="1",
            configuration_digest="d" * 64,
            expected_script_sha256=hashlib.sha256(
                script.read_bytes()
            ).hexdigest(),
            expected_script_size=script.stat().st_size,
            script_registration_id="suspended-script",
            script_registration_version="1",
            launch_guard=authority.provider_launch_guard,
        )

    result = provider.run(_request(tmp_path))
    time.sleep(1.5)

    assert result.exit_code == 0
    assert started.exists()
    assert nested_started.exists()
    assert process_exists(int(started.read_text(encoding="utf-8"))) is False
    assert process_exists(int(nested_started.read_text(encoding="utf-8"))) is False
    assert survived.exists() is False
    assert accessed.exists() is False


def test_cancellation_immediately_after_resume_kills_descendants(
    tmp_path: Path,
) -> None:
    started = tmp_path / "cancel-started.txt"
    survived = tmp_path / "cancel-survived.txt"
    child_code = (
        "import pathlib,time;time.sleep(1);"
        f"pathlib.Path({str(survived)!r}).write_text('survived')"
    )
    parent_code = (
        "import pathlib,subprocess,sys,time;"
        f"pathlib.Path({str(started)!r}).write_text('started');"
        f"subprocess.Popen([sys.executable,'-c',{child_code!r}]);time.sleep(30)"
    )
    provider = _provider((sys.executable, "-c", parent_code, "{prompt}"))
    result: list[ProcessResult] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            result.append(provider.run(_request(tmp_path, 30)))
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=run)
    worker.start()
    deadline = time.time() + 10
    while not started.exists() and time.time() < deadline:
        time.sleep(0.02)
    assert started.exists()
    provider.cancel()
    worker.join(10)
    time.sleep(1.5)

    assert worker.is_alive() is False
    assert errors == []
    assert result and result[0].exit_code != 0
    assert survived.exists() is False
