from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path

import pytest

from keeper.authority_service.restricted_process import (
    current_process_token,
    profile_restricted_primary_token,
    run_restricted_process,
)
from keeper.authority_service.windows_identity import current_process_sid
from keeper.authority_service.provider_identity import account_sid
from keeper.authority_service.windows_signature import authenticode_identity
from keeper.provider_host.install import (
    ProviderHostInstaller,
    ensure_provider_host_exchange_root,
)
from keeper.provider_host.windows_process import locked_executable


@pytest.mark.skipif(os.name != "nt", reason="Windows restricted-token test")
def test_profile_restricted_setup_uses_output_not_protected_state(
    tmp_path: Path,
) -> None:
    """Reproduce the live Win32-267 setup-CWD failure and its exact repair."""

    executable = Path(
        os.environ.get(
            "KEEPER_TEST_CODEX_EXECUTABLE",
            str(
                Path(os.environ["LOCALAPPDATA"])
                / "Programs"
                / "OpenAI"
                / "Codex"
                / "bin"
                / "codex.exe"
            ),
        )
    ).resolve(strict=True)
    stat = executable.stat()
    content = executable.read_bytes()
    declared = {
        "authenticode_binding": dict(authenticode_identity(executable)),
        "file_identity": {
            "device_id": int(stat.st_dev),
            "file_id": int(stat.st_ino),
            "modified_ns": int(stat.st_mtime_ns),
            "schema_version": 1,
            "size": int(stat.st_size),
        },
        "path": str(executable),
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }
    installer = ProviderHostInstaller(
        tmp_path / "installed-host",
        tmp_path / "startup",
        owner_sid=current_process_sid(),
        authority_service_sid=account_sid(r"NT SERVICE\KeeperAuthority"),
    )
    installer._ensure_roots()
    protected_workspace = installer.root / "output" / "setup"
    protected_workspace.mkdir(parents=True)
    output_root = tmp_path / "KeeperProviderExchange"
    ensure_provider_host_exchange_root(
        output_root,
        owner_sid=current_process_sid(),
    )
    output_workspace = output_root / "setup"
    output_workspace.mkdir()
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper()
        in {
            "APPDATA",
            "LOCALAPPDATA",
            "PATH",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "WINDIR",
        }
    }
    output = tmp_path / "process-output"
    output.mkdir()
    with (
        locked_executable(executable, declared) as measurement,
        current_process_token() as source_token,
        profile_restricted_primary_token(source_token) as restricted,
    ):
        with pytest.raises(
            PermissionError,
            match=r"win32_error=267",
        ):
            run_restricted_process(
                restricted,
                [str(executable), "--version"],
                executable,
                protected_workspace,
                environment,
                output / "protected.stdout",
                output / "protected.stderr",
                10,
                cancel_requested=threading.Event(),
                integrity_level="medium",
                validated_executable_identity=measurement,
                active_process_limit=8,
                memory_bytes=1024 * 1024 * 1024,
                stdout_bytes=1024,
                stderr_bytes=1024,
            )
        result = run_restricted_process(
            restricted,
            [str(executable), "--version"],
            executable,
            output_workspace,
            environment,
            output / "allowed.stdout",
            output / "allowed.stderr",
            10,
            cancel_requested=threading.Event(),
            integrity_level="medium",
            validated_executable_identity=measurement,
            active_process_limit=8,
            memory_bytes=1024 * 1024 * 1024,
            stdout_bytes=1024,
            stderr_bytes=1024,
        )
    assert result.exit_code == 0
    assert result.stdout.startswith("codex-cli ")
    assert result.restricted is True
    assert result.integrity_level == "medium"
    assert result.job_confined is True
