from __future__ import annotations

import os
import sys
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from keeper.authority_service.client import AuthorityServiceClient
from keeper.authority_service.core import AuthorityServiceCore
from keeper.authority_service.ipc_server import NamedPipeAuthorityServer
from keeper.authority_service.windows_identity import (
    NamedPipeClientProcessIdentity,
    WindowsTokenIdentity,
    current_process_sid,
)
from keeper.authority_service.restricted_process import (
    authenticated_client_environment,
    authenticated_named_pipe_client,
    authenticated_profile_primary_token,
    restricted_current_process_token,
    run_restricted_process,
    token_session_id,
    token_user_sid_string,
)


class _CapturingPipeBindingObserver:
    def __init__(self) -> None:
        self.identity: NamedPipeClientProcessIdentity | None = None
        self.profile_sid: str | None = None
        self.profile_session: int | None = None
        self.profile_path: str | None = None

    @contextmanager
    def bind_client(self, pipe: int) -> Iterator[None]:
        with authenticated_named_pipe_client(pipe) as (client_token, binding):
            self.identity = binding.revalidate(current_process_sid())
            self.profile_path = authenticated_client_environment(client_token).get(
                "USERPROFILE"
            )
            with authenticated_profile_primary_token(
                binding.profile_token
            ) as profile_token:
                self.profile_sid = token_user_sid_string(profile_token)
                self.profile_session = token_session_id(profile_token)
            yield

    def register_provider(
        self, provider_id: str, executable: Path, client_sid: str, **values: Any
    ) -> dict[str, Any]:
        del provider_id, executable, client_sid, values
        raise PermissionError("binding-only observer")


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe test")
def test_named_pipe_authenticates_client_and_serves_framed_request(
    tmp_path: Path,
) -> None:
    pipe_name = rf"\\.\pipe\KeeperAuthority-test-{uuid.uuid4().hex}"
    core = AuthorityServiceCore(tmp_path / "service")
    server = NamedPipeAuthorityServer(
        core, current_process_sid(), pipe_name=pipe_name
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert server.ready.wait(timeout=5)
    try:
        try:
            result = AuthorityServiceClient(
                pipe_name, timeout_seconds=5
            ).diagnostics()
        except PermissionError as error:
            if "restricted authority clients" in str(error):
                pytest.skip(
                    "Codex sandbox intentionally presents a restricted token"
                )
            raise
        assert result["service_version"] == "1.7.50"
        assert result["schema_version"] == 6
        assert result["client_sid"] == current_process_sid()
    finally:
        server.stop()
        thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe test")
def test_named_pipe_rejects_wrong_os_identity(tmp_path: Path) -> None:
    pipe_name = rf"\\.\pipe\KeeperAuthority-test-{uuid.uuid4().hex}"
    core = AuthorityServiceCore(tmp_path / "service")
    server = NamedPipeAuthorityServer(
        core, "S-1-5-18", pipe_name=pipe_name
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert server.ready.wait(timeout=5)
    try:
        with pytest.raises(PermissionError, match="unauthorized"):
            AuthorityServiceClient(
                pipe_name, timeout_seconds=5
            ).diagnostics()
    finally:
        server.stop()
        thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe test")
def test_named_pipe_binds_actual_client_pid_session_and_process_token(
    tmp_path: Path,
) -> None:
    pipe_name = rf"\\.\pipe\KeeperAuthority-test-{uuid.uuid4().hex}"
    observer = _CapturingPipeBindingObserver()
    core = AuthorityServiceCore(tmp_path / "service", observer=observer)  # type: ignore[arg-type]
    server = NamedPipeAuthorityServer(
        core, current_process_sid(), pipe_name=pipe_name
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert server.ready.wait(timeout=5)
    try:
        with pytest.raises(PermissionError, match="binding-only observer"):
            AuthorityServiceClient(pipe_name, timeout_seconds=5).register_provider(
                "codex",
                Path(sys.executable),
                executive_capabilities=["provider.execution"],
                project_types=["coding"],
                effort_levels=["medium"],
                pricing_authority={"mode": "INCLUDED_SUBSCRIPTION"},
            )
        assert observer.identity is not None
        assert observer.identity.process_id == os.getpid()
        assert observer.identity.sid.casefold() == current_process_sid().casefold()
        assert observer.identity.session_id >= 0
        assert observer.identity.process_creation_time_100ns > 0
        expected_process_image = Path(
            getattr(sys, "_base_executable", sys.executable)
        ).resolve(strict=True)
        assert (
            Path(observer.identity.executable_path).resolve(strict=True)
            == expected_process_image
        )
        assert observer.identity.executable_file_identity[0] >= 0
        assert observer.identity.executable_file_identity[1] > 0
        assert observer.identity.executable_file_identity[2] > 0
        assert observer.identity.executable_file_identity[3] > 0
        assert observer.profile_sid is not None
        assert observer.profile_sid.casefold() == current_process_sid().casefold()
        assert observer.profile_session == observer.identity.session_id
        assert observer.profile_path
        assert Path(observer.profile_path).resolve(strict=True) == Path(
            os.environ["USERPROFILE"]
        ).resolve(strict=True)
    finally:
        server.stop()
        thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe test")
def test_low_restricted_provider_cannot_connect_to_authority_pipe(
    tmp_path: Path,
) -> None:
    pipe_leaf = f"KeeperAuthority-test-{uuid.uuid4().hex}"
    pipe_name = rf"\\.\pipe\{pipe_leaf}"
    core = AuthorityServiceCore(tmp_path / "service")
    server = NamedPipeAuthorityServer(
        core, current_process_sid(), pipe_name=pipe_name
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert server.ready.wait(timeout=5)
    executable = Path(
        os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}
    }
    try:
        try:
            with restricted_current_process_token() as token:
                result = run_restricted_process(
                    token,
                    [str(executable), "/d", "/c", "type", pipe_name],
                    executable,
                    tmp_path,
                    environment,
                    tmp_path / "provider-stdout.log",
                    tmp_path / "provider-stderr.log",
                    10,
                )
        except PermissionError as error:
            if "failed: 87" in str(error):
                pytest.skip("Codex sandbox token cannot derive another restricted token")
            raise
        assert result.exit_code != 0
        assert result.timed_out is False
        assert server.accepted_connections == 0
    finally:
        server.stop()
        thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.parametrize(
    ("identity", "message"),
    [
        (
            WindowsTokenIdentity("S-1-5-21-1000", True, 8192),
            "restricted",
        ),
        (
            WindowsTokenIdentity("S-1-5-21-1000", False, 4096),
            "low-integrity",
        ),
        (
            WindowsTokenIdentity("S-1-5-21-9999", False, 8192),
            "unauthorized",
        ),
    ],
)
def test_pipe_server_rejects_ineligible_client_tokens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    identity: WindowsTokenIdentity,
    message: str,
) -> None:
    core = AuthorityServiceCore(tmp_path / "service")
    server = NamedPipeAuthorityServer(core, "S-1-5-21-1000")
    monkeypatch.setattr(
        "keeper.authority_service.ipc_server.named_pipe_client_identity",
        lambda _pipe: identity,
    )

    with pytest.raises(PermissionError, match=message):
        server._authenticated_client_sid(1)


def test_pipe_server_accepts_authorized_medium_unrestricted_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = AuthorityServiceCore(tmp_path / "service")
    server = NamedPipeAuthorityServer(core, "S-1-5-21-1000")
    monkeypatch.setattr(
        "keeper.authority_service.ipc_server.named_pipe_client_identity",
        lambda _pipe: WindowsTokenIdentity(
            "S-1-5-21-1000", False, 8192
        ),
    )

    assert server._authenticated_client_sid(1) == "S-1-5-21-1000"
