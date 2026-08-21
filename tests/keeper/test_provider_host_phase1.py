from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import sys
import threading
import uuid
from contextlib import contextmanager
from ctypes import wintypes
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, cast

import pytest

from keeper.authority_service import observer as observer_module
from keeper.authority_service.provider_host_gateway import ProviderHostGateway
from keeper.authority_service.provider_identity import account_sid
from keeper.authority_service.observer import (
    ServiceProviderObserver,
    _authority_provider_host_path_observation,
)
from keeper.authority_service.restricted_process import (
    RestrictedProcessCleanupUncertain,
    RestrictedProcessResult,
    current_process_token,
    impersonate_token,
    profile_restricted_primary_token,
    token_session_id,
)
from keeper.authority_service.windows_identity import (
    NamedPipeClientProcessIdentity,
    current_process_sid,
)
from keeper.authority_service.windows_security import read_path_security
from keeper.provider_host import windows_process
from keeper.provider_host import install as host_install
from keeper.provider_host.install import (
    ProviderHostInstaller,
    ensure_provider_host_exchange_root,
)
from keeper.provider_host import pipe as host_pipe
from keeper.provider_host import signing as host_signing
from keeper.provider_host.protocol import (
    LAUNCH_PURPOSE,
    TestEnvelopeIdentity as EnvelopeTestIdentity,
    require_production_identity,
    structured_digest,
    validate_launch_envelope,
    validate_setup_envelope,
)
from keeper.provider_host.replay_store import ProviderHostStore
from keeper.provider_host.runtime import (
    HostIdentity,
    HostState,
    KeeperProviderHost,
    ProviderBinding,
)
from keeper.provider_host.identity import UserBinding


AUTHORITY = EnvelopeTestIdentity("authority-test", b"authority-test-key")
HOST = EnvelopeTestIdentity("host-test", b"host-test-key")
_TEST_OWNER_SID = "S-1-5-21-1000"
_TEST_SERVICE_SID = "S-1-5-80-1-2-3-4-5"


@pytest.mark.skipif(os.name != "nt", reason="exact Host ACLs require Windows")
def test_provider_host_policy_grants_service_read_execute_only(
    tmp_path: Path,
) -> None:
    root = tmp_path / "host"
    startup = tmp_path / "startup"
    root.mkdir()
    startup.mkdir()
    installer = ProviderHostInstaller(
        root,
        startup,
        owner_sid=_TEST_OWNER_SID,
        authority_service_sid=_TEST_SERVICE_SID,
    )

    policy = installer._security_policy(root)  # noqa: SLF001 - exact policy
    aces = policy["aces"]
    assert isinstance(aces, list)
    service_aces = [
        ace
        for ace in aces
        if isinstance(ace, dict)
        if ace["trustee_sid"] == _TEST_SERVICE_SID
    ]

    assert len(service_aces) == 1
    assert service_aces[0]["ace_type"] == "allow"
    assert service_aces[0]["rights_mask"] == host_install._FILE_READ_EXECUTE
    assert service_aces[0]["rights_mask"] & 0x00000116 == 0


def test_provider_host_protected_tree_excludes_only_provider_output_exchange(
    tmp_path: Path,
) -> None:
    root = tmp_path / "host"
    state_file = root / "state" / "checkpoint.json"
    output_file = root / "output" / "provider.stdout"
    state_file.parent.mkdir(parents=True)
    output_file.parent.mkdir(parents=True)
    state_file.write_bytes(b"state")
    output_file.write_bytes(b"provider-output")

    observed = {
        path.relative_to(root).as_posix() if path != root else "."
        for path, _ in host_install._protected_tree_paths(root)
    }

    assert "." in observed
    assert "state" in observed
    assert "state/checkpoint.json" in observed
    assert "output" not in observed
    assert "output/provider.stdout" not in observed


@pytest.mark.skipif(os.name != "nt", reason="exact Host ACLs require Windows")
def test_provider_host_protected_tree_attestation_accepts_exact_closed_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "host"
    state = root / "state"
    versions = root / "versions"
    startup = tmp_path / "startup"
    executable = versions / "1.7.12" / "KeeperProviderHost.exe"
    current = root / "current.json"
    pending = state / "pending.json"
    launcher = startup / "KeeperProviderHost.cmd"
    for directory in (state, executable.parent, startup):
        directory.mkdir(parents=True, exist_ok=True)
    for path in (executable, current, pending, launcher):
        path.write_bytes(b"fixture")
    installer = ProviderHostInstaller(
        root,
        startup,
        owner_sid=_TEST_OWNER_SID,
        authority_service_sid=_TEST_SERVICE_SID,
    )
    paths = [
        (root, False),
        (state, False),
        (versions, False),
        (executable.parent, False),
        (executable, False),
        (current, True),
        (pending, True),
    ]
    monkeypatch.setattr(host_install, "_protected_tree_paths", lambda value: paths)
    monkeypatch.setattr(
        host_install,
        "read_path_security",
        lambda path: {
            **installer._security_policy(  # noqa: SLF001 - exact policy fixture
                path,
                inherited=next(flag for item, flag in paths if item == path)
                if path not in {startup, launcher}
                else False,
            ),
            "mandatory_label_count": 1,
        },
    )
    monkeypatch.setattr(
        host_install, "read_path_owner_sid", lambda path: _TEST_OWNER_SID
    )

    digest = installer.attest_protected_tree()

    assert len(digest) == 64
    assert all(character in "0123456789abcdef" for character in digest)
    pending.write_bytes(b"changed-during-observation")
    assert installer.attest_protected_tree() != digest


@pytest.mark.skipif(os.name != "nt", reason="exact Host ACLs require Windows")
@pytest.mark.parametrize(
    "corruption",
    ["missing-deny", "extra-trustee", "wrong-owner", "wrong-integrity"],
)
def test_provider_host_protected_tree_attestation_rejects_policy_corruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    corruption: str,
) -> None:
    root = tmp_path / "host"
    startup = tmp_path / "startup"
    launcher = startup / "KeeperProviderHost.cmd"
    root.mkdir()
    startup.mkdir()
    launcher.write_bytes(b"fixture")
    installer = ProviderHostInstaller(
        root,
        startup,
        owner_sid=_TEST_OWNER_SID,
        authority_service_sid=_TEST_SERVICE_SID,
    )
    monkeypatch.setattr(
        host_install, "_protected_tree_paths", lambda value: [(root, False)]
    )

    def live(path: Path) -> dict[str, object]:
        policy: dict[str, Any] = installer._security_policy(path)  # noqa: SLF001
        policy["mandatory_label_count"] = 1
        if path == root and corruption == "missing-deny":
            policy["aces"] = list(policy["aces"])[1:]
        elif path == root and corruption == "extra-trustee":
            policy["aces"] = [
                *list(policy["aces"]),
                host_install._host_ace("allow", "S-1-1-0", []),
            ]
        elif path == root and corruption == "wrong-integrity":
            integrity = dict(policy["mandatory_integrity"])
            integrity["trustee_sid"] = "S-1-16-4096"
            integrity["level"] = "low"
            policy["mandatory_integrity"] = integrity
        return policy

    monkeypatch.setattr(host_install, "read_path_security", live)
    monkeypatch.setattr(
        host_install,
        "read_path_owner_sid",
        lambda path: (
            "S-1-5-18"
            if path == root and corruption == "wrong-owner"
            else _TEST_OWNER_SID
        ),
    )

    with pytest.raises(PermissionError, match="protected path security differs"):
        installer.attest_protected_tree()


def _host_distribution(
    root: Path, *, version: str, marker: bytes
) -> tuple[Path, str, str]:
    root.mkdir(parents=True)
    executable = root / "KeeperProviderHost.exe"
    runtime = root / "lib" / "python-runtime.dll"
    runtime.parent.mkdir()
    executable.write_bytes(b"MZ" + marker)
    runtime.write_bytes(b"runtime-" + marker)
    files = []
    for path in (executable, runtime):
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    manifest = root / "keeper-provider-host-package-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "product": "KeeperProviderHost",
                "version": version,
                "files": files,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return (
        executable,
        hashlib.sha256(manifest.read_bytes()).hexdigest(),
        hashlib.sha256(executable.read_bytes()).hexdigest(),
    )


def _paths(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    profile = tmp_path / "profile"
    provider_bin = profile / "Programs" / "Codex"
    system_root = tmp_path / "Windows"
    workspace = tmp_path / "workspace"
    for path in (
        profile / "AppData" / "Local" / "Temp",
        profile / "AppData" / "Roaming",
        provider_bin,
        system_root / "System32",
        workspace,
        profile / "AppData" / "Local" / "DarkSage" / "KeeperProviderExchange" / "setup",
    ):
        path.mkdir(parents=True, exist_ok=True)
    executable = provider_bin / "codex.exe"
    executable.write_bytes(b"official-codex-test-fixture")
    return profile, system_root, workspace, executable


def _tls_bundle(tmp_path: Path) -> dict[str, object]:
    path = tmp_path / "windows-roots.pem"
    if not path.exists():
        path.write_bytes(b"-----BEGIN CERTIFICATE-----\nVEVTVA==\n-----END CERTIFICATE-----\n")
    stat = path.stat()
    return {
        "canonical_path": str(path.resolve()),
        "certificate_count": 1,
        "file_identity": {
            "device_id": int(stat.st_dev),
            "file_id": int(stat.st_ino),
            "modified_ns": int(stat.st_mtime_ns),
            "schema_version": 1,
            "size": int(stat.st_size),
        },
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": int(stat.st_size),
        "source": "windows-root-store",
    }


def _provider(executable: Path) -> ProviderBinding:
    stat = executable.stat()
    return ProviderBinding(
        provider_id="codex",
        account_id="chatgpt-subscription:" + "c" * 64,
        session_id="codex-session:test",
        registration_id="registration-test",
        qualification_id="qualification-test",
        executable_path=str(executable.resolve()),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        executable_size=stat.st_size,
        file_identity={
            "device_id": stat.st_dev,
            "file_id": stat.st_ino,
            "modified_ns": stat.st_mtime_ns,
            "schema_version": 1,
            "size": stat.st_size,
        },
        authenticode_binding={
            "certificate_thumbprint": "A" * 40,
            "publisher_subject": 'CN="OpenAI OpCo, LLC"',
            "source": "windows-authenticode",
            "status": "Valid",
        },
        publisher='CN="OpenAI OpCo, LLC"',
        version="codex-cli 0.146.0",
        models=("gpt-5.6-sol",),
        efforts=("medium", "high"),
    )


def _launch(
    tmp_path: Path,
    provider: ProviderBinding,
    binding: UserBinding,
    environment: Mapping[str, object],
    *,
    sequence: int = 1,
    launch_id: str = "launch-test",
    attempt_id: str = "attempt-test",
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    now = issued_at or datetime.now(UTC)
    workspace = tmp_path / "workspace"
    return validate_launch_envelope(
        {
            "account_id": provider.account_id,
            "argv": ["exec", "--model", "gpt-5.6-sol"],
            "assignment_id": "assignment-test",
            "authority_attempt_id": attempt_id,
            "authority_id": "authority-test",
            "cancellation": {
                "on_lock": "CANCEL_EXISTING",
                "on_logoff": "CANCEL_AND_EXIT",
                "token_digest": "1" * 64,
            },
            "charter_id": "charter-test",
            "charter_revision_id": "charter-test:r1",
            "composition_identity": "PRODUCTION",
            "effort": "medium",
            "environment": dict(environment),
            "executable": {
                "authenticode_binding": dict(provider.authenticode_binding),
                "file_identity": dict(provider.file_identity),
                "path": provider.executable_path,
                "publisher": provider.publisher,
                "sha256": provider.executable_sha256,
                "size": provider.executable_size,
                "version": provider.version,
            },
            "expires_at": (now + timedelta(minutes=1)).isoformat(),
            "host_id": "host-test",
            "issued_at": now.isoformat(),
            "launch_claim_digest": "2" * 64,
            "launch_id": launch_id,
            "model_id": "gpt-5.6-sol",
            "network_policy": {
                "allow_external": True,
                "policy_id": "codex-chatgpt-subscription-only",
            },
            "nonce": f"nonce-{launch_id}",
            "project_id": "project-test",
            "provider_id": "codex",
            "provider_input_digest": "3" * 64,
            "provider_qualification_id": provider.qualification_id,
            "provider_registration_id": provider.registration_id,
            "provider_session_id": provider.session_id,
            "resource_limits": {
                "active_process_limit": 8,
                "memory_bytes": 1024,
                "stderr_bytes": 1024,
                "stdout_bytes": 1024,
                "timeout_seconds": 30,
            },
            "sequence": sequence,
            "usage": {
                "generation": 1,
                "max_units": 1,
                "pool_id": "pool-test",
                "reservation_id": "usage-test",
            },
            "user_binding": binding.as_dict(),
            "work_item_id": "work-item-test",
            "workflow_id": "workflow-test",
            "workspace": {
                "canonical_path": str(workspace.resolve()),
                "identity": "workspace-test",
                "reservation_id": "workspace-reservation-test",
            },
        }
    )


def test_provider_host_protocol_rejects_tamper_and_test_identity_in_production(
    tmp_path: Path,
) -> None:
    profile, _, _, executable = _paths(tmp_path)
    provider = _provider(executable)
    binding = UserBinding("S-1-5-21-1000", 1, str(profile.resolve()))
    environment = {
        "allowlist": ["PATH", "USERPROFILE"],
        "digest": "4" * 64,
        "preparation_nonce": "prepare-test",
        "scrubbed_names": ["OPENAI_API_KEY"],
        "tls_root_bundle": _tls_bundle(tmp_path),
    }
    launch = _launch(tmp_path, provider, binding, environment)
    record = AUTHORITY.sign(LAUNCH_PURPOSE, launch)
    assert AUTHORITY.verify(record, purpose=LAUNCH_PURPOSE) == launch
    record["payload"]["effort"] = "low"
    with pytest.raises(PermissionError, match="signature"):
        AUTHORITY.verify(record, purpose=LAUNCH_PURPOSE)
    with pytest.raises(PermissionError, match="test Provider Host identity"):
        require_production_identity(AUTHORITY)


def test_provider_host_store_replay_overlap_expiry_future_and_restart(
    tmp_path: Path,
) -> None:
    _, _, workspace, _ = _paths(tmp_path)
    child = workspace / "child"
    child.mkdir()
    store = ProviderHostStore(tmp_path / "state" / "host.db")
    now = datetime.now(UTC)

    def claim(**overrides: object) -> None:
        values: dict[str, object] = {
            "authority_id": "authority-test",
            "nonce": "nonce-1",
            "sequence": 1,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=1)).isoformat(),
            "now": now,
            "maximum_ttl": timedelta(minutes=2),
            "maximum_future_skew": timedelta(seconds=5),
            "launch_id": "launch-1",
            "authority_attempt_id": "attempt-1",
            "envelope_digest": "1" * 64,
            "workspace_path": str(workspace.resolve()),
        }
        values.update(overrides)
        store.claim_launch(**values)  # type: ignore[arg-type]

    claim()
    with pytest.raises(PermissionError, match="replay|duplicated|stale"):
        claim()
    with pytest.raises(PermissionError, match="overlaps"):
        claim(
            nonce="nonce-2",
            sequence=2,
            launch_id="launch-2",
            authority_attempt_id="attempt-2",
            workspace_path=str(child.resolve()),
        )
    with pytest.raises(PermissionError, match="future"):
        claim(
            nonce="nonce-3",
            sequence=3,
            launch_id="launch-3",
            authority_attempt_id="attempt-3",
            issued_at=(now + timedelta(minutes=1)).isoformat(),
            expires_at=(now + timedelta(minutes=2)).isoformat(),
        )
    with pytest.raises(PermissionError, match="expired"):
        claim(
            nonce="nonce-4",
            sequence=4,
            launch_id="launch-4",
            authority_attempt_id="attempt-4",
            issued_at=(now - timedelta(minutes=2)).isoformat(),
            expires_at=(now - timedelta(minutes=1)).isoformat(),
        )
    assert ProviderHostStore(store.path).recover_uncertain("restart") == 1
    assert store.get_launch("launch-1")["state"] == "UNCERTAIN"


class _Launcher:
    def __init__(self) -> None:
        self.calls = 0

    def launch(
        self,
        envelope: Mapping[str, Any],
        environment: Mapping[str, str],
        cancel_requested: threading.Event,
        *,
        on_started: Any,
        on_resumed: Any,
    ) -> dict[str, Any]:
        self.calls += 1
        assert "OPENAI_API_KEY" not in environment
        assert cancel_requested.is_set() is False
        on_started({"pid": 100, "suspended": True})
        on_resumed({"pid": 100, "resumed": True})
        return {"exit_code": 0, "output_digest": "5" * 64}


def test_provider_host_runtime_exact_launch_replay_lock_and_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, system_root, _, executable = _paths(tmp_path)
    temp = profile / "AppData" / "Local" / "Temp"
    monkeypatch.setenv("SYSTEMROOT", str(system_root.resolve()))
    monkeypatch.setenv("WINDIR", str(system_root.resolve()))
    monkeypatch.setenv("USERPROFILE", str(profile.resolve()))
    monkeypatch.setenv("LOCALAPPDATA", str((profile / "AppData" / "Local").resolve()))
    monkeypatch.setenv("APPDATA", str((profile / "AppData" / "Roaming").resolve()))
    monkeypatch.setenv("TEMP", str(temp.resolve()))
    monkeypatch.setenv("TMP", str(temp.resolve()))
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-propagate")
    binding = UserBinding("S-1-5-21-1000", 1, str(profile.resolve()))
    provider = _provider(executable)
    store = ProviderHostStore(tmp_path / "state" / "runtime.db")
    runtime = KeeperProviderHost(
        identity=HostIdentity("host-test", "authority-test", binding),
        observed_binding=lambda: binding,
        authority_verifier=AUTHORITY,
        host_signer=HOST,
        store=store,
        provider_binding=provider,
        environment_attestation_key=b"environment-test-key",
        setup_workspace_root=profile / "AppData" / "Local" / "DarkSage" / "KeeperProviderExchange" / "setup",
    )
    assert runtime.start() == 0
    attestation = runtime.prepare_environment(
        preparation_nonce="prepare-test", provider_bin=executable.parent
    )
    environment = HOST.verify(
        attestation, purpose="keeper-provider-host-environment"
    )
    environment.pop("host_id")
    environment.pop("recorded_at")
    launch = _launch(tmp_path, provider, binding, environment)
    launcher = _Launcher()
    completion_record = runtime.execute(
        AUTHORITY.sign(LAUNCH_PURPOSE, launch), launcher
    )
    completion = HOST.verify(
        completion_record, purpose="keeper-provider-host-completion"
    )
    assert completion["state"] == "COMPLETED"
    assert completion["envelope_digest"] == structured_digest(launch)
    assert launcher.calls == 1
    with pytest.raises(PermissionError, match="replayed|preparation is absent"):
        runtime.execute(AUTHORITY.sign(LAUNCH_PURPOSE, launch), launcher)
    runtime.lock_workstation()
    assert runtime.state is HostState.LOCKED
    with pytest.raises(PermissionError, match="LOCKED"):
        runtime.prepare_environment(
            preparation_nonce="locked", provider_bin=executable.parent
        )
    runtime.unlock_workstation()
    assert runtime.state.value == HostState.READY.value
    restart_workspace = tmp_path / "restart-workspace"
    restart_workspace.mkdir()
    store.claim_launch(
        authority_id="authority-test",
        nonce="restart-nonce",
        sequence=2,
        issued_at=datetime.now(UTC).isoformat(),
        expires_at=(datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
        now=datetime.now(UTC),
        maximum_ttl=timedelta(minutes=2),
        maximum_future_skew=timedelta(seconds=5),
        launch_id="restart-launch",
        authority_attempt_id="restart-attempt",
        envelope_digest="6" * 64,
        workspace_path=str(restart_workspace.resolve()),
    )
    restarted = KeeperProviderHost(
        identity=runtime.identity,
        observed_binding=lambda: binding,
        authority_verifier=AUTHORITY,
        host_signer=HOST,
        store=ProviderHostStore(store.path),
        provider_binding=provider,
        environment_attestation_key=b"environment-test-key",
        setup_workspace_root=profile / "AppData" / "Local" / "DarkSage" / "KeeperProviderExchange" / "setup",
    )
    assert restarted.start() == 1
    assert store.get_launch("restart-launch")["state"] == "UNCERTAIN"


def test_runtime_reconciliation_is_semantically_idempotent_across_signed_envelopes(
    tmp_path: Path,
) -> None:
    profile, _, workspace, _ = _paths(tmp_path)
    binding = UserBinding("S-1-5-21-1000", 1, str(profile.resolve()))
    store = ProviderHostStore(tmp_path / "state" / "reconcile-runtime.db")
    launch_id = "provider-registration-probe:" + "e" * 32
    now = datetime.now(UTC)
    store.claim_launch(
        authority_id="authority-test",
        nonce="semantic-reconciliation",
        sequence=1,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=1)).isoformat(),
        now=now,
        maximum_ttl=timedelta(minutes=2),
        maximum_future_skew=timedelta(seconds=5),
        launch_id=launch_id,
        authority_attempt_id=launch_id,
        envelope_digest="f" * 64,
        workspace_path=str(workspace.resolve()),
        operation="REGISTER_PROBE",
    )
    runtime = KeeperProviderHost(
        identity=HostIdentity("host-test", "authority-test", binding),
        observed_binding=lambda: binding,
        authority_verifier=AUTHORITY,
        host_signer=HOST,
        store=store,
        provider_binding=None,
        environment_attestation_key=b"environment-test-key",
        setup_workspace_root=(
            profile
            / "AppData"
            / "Local"
            / "DarkSage"
            / "KeeperProviderExchange"
            / "setup"
        ),
    )
    assert runtime.start() == 1
    status = runtime.status()
    journal = cast(dict[str, Any], status["launch_journal"])
    expected = cast(list[dict[str, object]], journal["launches"])[0]
    accounting = {
        "model_request_possible": False,
        "provider_mutation_possible": False,
        "read_only_process_execution_upper_bound": 2,
        "usage_observation_possible": True,
    }
    reconciliation = {
        "authority_id": "authority-test",
        "authorized_client_sid": binding.user_sid,
        "effect_accounting": accounting,
        "enrollment_id": "enrollment-test",
        "expected_launch": expected,
        "host_id": "host-test",
        "reconciliation_id": "provider-host-launch-reconciliation:" + "1" * 64,
        "resolution": "LEGACY_REGISTER_PROBE_READ_ONLY_EFFECT_ACCOUNTED",
    }

    with pytest.raises(PermissionError, match="binding is invalid"):
        runtime.reconcile_uncertain_launch(
            AUTHORITY.sign(
                "keeper-provider-host-launch-reconciliation",
                {**reconciliation, "authorized_client_sid": "S-1-5-21-WRONG"},
            )
        )

    first = HOST.verify(
        runtime.reconcile_uncertain_launch(
            AUTHORITY.sign(
                "keeper-provider-host-launch-reconciliation", reconciliation
            )
        ),
        purpose="keeper-provider-host-launch-reconciliation-result",
    )
    second = HOST.verify(
        runtime.reconcile_uncertain_launch(
            AUTHORITY.sign(
                "keeper-provider-host-launch-reconciliation", reconciliation
            )
        ),
        purpose="keeper-provider-host-launch-reconciliation-result",
    )

    assert first == second
    assert first["state"] == "FAILED"
    final_journal = cast(
        dict[str, object], runtime.status()["launch_journal"]
    )
    assert final_journal["active_or_uncertain_launch_count"] == 0


class _SetupRunner:
    def __init__(self) -> None:
        self.calls = 0

    def run_setup(
        self,
        envelope: Mapping[str, Any],
        environment: Mapping[str, str],
        cancel_requested: threading.Event,
        *,
        on_started: Any,
        on_resumed: Any,
    ) -> dict[str, Any]:
        self.calls += 1
        assert "OPENAI_API_KEY" not in environment
        assert cancel_requested.is_set() is False
        on_started({"pid": 200, "creation_time": datetime.now(UTC).isoformat()})
        on_resumed({"pid": 200})
        return {
            "authentication_probe": {
                "account_identity_digest": "c" * 64,
                "authentication_method": "chatgpt-subscription",
                "model_capabilities": [
                    {
                        "model_id": "gpt-5.6-sol",
                        "supported_reasoning_efforts": ["medium", "high"],
                    }
                ],
                "plan_type": "pro",
                "usage_observation": {
                    "capacity_state": "UNKNOWN",
                    "buckets": [],
                    "exhausted": False,
                    "source": "codex-app-server-public-api",
                    "confidence": "LOW",
                    "credits_ignored": True,
                },
            },
            "exit_status": 0,
            "failure_reason": None,
            "process_ownership": {"pid": 200, "restricted": True},
            "production_command": [],
            "prompt_digest": None,
            "provider_instance_id": "codex-session:test",
            "raw_version_output": "codex-cli 0.146.0",
            "schema_digest": None,
            "structured_output": None,
            "usage_observation": {
                "capacity_state": "UNKNOWN",
                "buckets": [],
                "exhausted": False,
                "source": "codex-app-server-public-api",
                "confidence": "LOW",
                "credits_ignored": True,
            },
        }


def test_provider_host_setup_is_exact_durable_and_host_executed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, system_root, _, executable = _paths(tmp_path)
    temp = profile / "AppData" / "Local" / "Temp"
    for name, value in {
        "SYSTEMROOT": system_root,
        "WINDIR": system_root,
        "USERPROFILE": profile,
        "LOCALAPPDATA": profile / "AppData" / "Local",
        "APPDATA": profile / "AppData" / "Roaming",
        "TEMP": temp,
        "TMP": temp,
    }.items():
        monkeypatch.setenv(name, str(value.resolve()))
    binding = UserBinding("S-1-5-21-1000", 1, str(profile.resolve()))
    provider = _provider(executable)
    store = ProviderHostStore(tmp_path / "state" / "setup.db")
    runtime = KeeperProviderHost(
        identity=HostIdentity("host-test", "authority-test", binding),
        observed_binding=lambda: binding,
        authority_verifier=AUTHORITY,
        host_signer=HOST,
        store=store,
        provider_binding=None,
        environment_attestation_key=b"environment-test-key",
        setup_workspace_root=profile / "AppData" / "Local" / "DarkSage" / "KeeperProviderExchange" / "setup",
    )
    runtime.start()
    assert runtime.status()["provider_state"] == "NO_QUALIFIED_PROVIDERS"
    with pytest.raises(PermissionError, match="no qualified provider"):
        _ = runtime.provider_bin
    attestation = runtime.prepare_environment(
        preparation_nonce="setup-prepare", provider_bin=executable.parent
    )
    environment = HOST.verify(
        attestation, purpose="keeper-provider-host-environment"
    )
    environment.pop("host_id")
    environment.pop("recorded_at")
    now = datetime.now(UTC)
    setup_id = "provider-qualification:" + "a" * 32
    workspace = (
        profile
        / "AppData"
        / "Local"
        / "DarkSage"
        / "KeeperProviderExchange"
        / "setup"
        / hashlib.sha256(setup_id.encode("utf-8")).hexdigest()
    )
    setup = validate_setup_envelope(
        {
            "account_binding": {
                "account_identity_digest": "c" * 64,
                "authentication_method": "chatgpt-subscription",
                "plan_type": "pro",
            },
            "authority_id": "authority-test",
            "challenge": "challenge-test",
            "composition_identity": "PRODUCTION",
            "environment": environment,
            "executable": {
                "authenticode_binding": dict(provider.authenticode_binding),
                "file_identity": dict(provider.file_identity),
                "path": provider.executable_path,
                "publisher": provider.publisher,
                "sha256": provider.executable_sha256,
                "size": provider.executable_size,
                "version": provider.version,
            },
            "expires_at": (now + timedelta(minutes=1)).isoformat(),
            "host_id": "host-test",
            "issued_at": now.isoformat(),
            "model_id": "gpt-5.6-sol",
            "nonce": "setup-nonce",
            "operation": "QUALIFY",
            "provider_id": "codex",
            "provider_registration_id": provider.registration_id,
            "resource_limits": {
                "active_process_limit": 8,
                "memory_bytes": 1024,
                "stderr_bytes": 1024,
                "stdout_bytes": 1024,
                "timeout_seconds": 30,
            },
            "sequence": 1,
            "setup_id": setup_id,
            "usage_policy_digest": "7" * 64,
            "user_binding": binding.as_dict(),
            "workspace": {
                "canonical_path": str(workspace),
                "identity": "setup-workspace",
                "reservation_id": setup_id,
            },
        }
    )
    unsupported = dict(setup)
    unsupported["account_binding"] = {
        **setup["account_binding"],
        "plan_type": "business",
    }
    with pytest.raises(PermissionError, match="account policy"):
        validate_setup_envelope(unsupported)
    runner = _SetupRunner()
    result = runtime.execute_setup(
        AUTHORITY.sign("keeper-provider-host-provider-setup", setup), runner
    )
    payload = HOST.verify(
        result, purpose="keeper-provider-host-provider-setup-result"
    )
    assert payload["setup_envelope_digest"] == structured_digest(setup)
    assert runner.calls == 1
    assert store.get_launch(setup_id)["state"] == "COMPLETED"
    assert runtime.terminal_setup_result(setup_id) == result
    with pytest.raises(PermissionError, match="replayed|preparation is absent"):
        runtime.execute_setup(
            AUTHORITY.sign("keeper-provider-host-provider-setup", setup), runner
        )
    bound = runtime.bind_provider(provider.as_dict())
    assert bound["state"] == "QUALIFIED"
    assert runtime.status()["provider_state"] == "QUALIFIED"


def test_authority_gateway_builds_exact_host_setup_contract(tmp_path: Path) -> None:
    profile, _, _, executable = _paths(tmp_path)
    provider = _provider(executable)
    host_process = (
        profile
        / "AppData"
        / "Local"
        / "Programs"
        / "DarkSage"
        / "KeeperProviderHost"
        / "versions"
        / "1.7.15"
        / "KeeperProviderHost.exe"
    )
    host_process.parent.mkdir(parents=True)
    host_process.write_bytes(b"MZhost")
    gateway = ProviderHostGateway(
        pipe_name=r"\\.\pipe\KeeperProviderHost-test",
        authority_id="authority-test",
        host_id="host-test",
        authority_signer=AUTHORITY,
        host_verifier=HOST,
        expected_host_sid="S-1-5-21-1000",
        expected_host_session_id=1,
        expected_host_executable=host_process,
        expected_host_executable_sha256=hashlib.sha256(
            host_process.read_bytes()
        ).hexdigest(),
        expected_host_profile_path=profile,
        sequence_store=tmp_path / "gateway-sequences.db",
        production=False,
    )
    now = datetime.now(UTC)
    environment = HOST.sign(
        "keeper-provider-host-environment",
        {
            "allowlist": ["PATH", "USERPROFILE"],
            "digest": "8" * 64,
            "host_id": "host-test",
            "preparation_nonce": "prepare-gateway",
            "recorded_at": now.isoformat(),
            "scrubbed_names": ["OPENAI_API_KEY"],
            "tls_root_bundle": _tls_bundle(tmp_path),
        },
    )
    registration = {
        "authenticode_binding": dict(provider.authenticode_binding),
        "canonical_executable_path": provider.executable_path,
        "executable_file_identity": dict(provider.file_identity),
        "executable_sha256": provider.executable_sha256,
        "executable_size": provider.executable_size,
        "expected_version": provider.version,
        "model_allowlist": ["gpt-5.6-sol"],
        "subscription_account_binding": {
            "account_identity_digest": "c" * 64,
            "authentication_method": "chatgpt-subscription",
            "plan_type": "plus",
        },
        "usage_policy": {"keeper_launch_budget": 1},
        "windows_authentication_binding": {
            "principal_sid": "S-1-5-21-1000",
            "windows_session_id": 1,
            "profile_identity": str(profile.resolve()),
        },
    }
    setup_id = "provider-registration-probe:" + "b" * 32
    workspace = gateway.setup_workspace(setup_id)
    setup = gateway.build_setup_envelope(
        operation="REGISTER_PROBE",
        registration=registration,
        provider_registration_id="keeper-provider:codex:v1:" + "d" * 32,
        challenge="gateway-challenge",
        setup_id=setup_id,
        workspace=workspace,
        environment_attestation=environment,
    )
    assert setup["authority_id"] == "authority-test"
    assert setup["host_id"] == "host-test"
    assert setup["provider_registration_id"].endswith("d" * 32)
    changed = dict(setup)
    changed["composition_identity"] = "TEST"
    with pytest.raises(PermissionError, match="not production"):
        validate_setup_envelope(changed)


def test_gateway_reconciliation_binds_semantic_request_and_host_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, _, _, _ = _paths(tmp_path)
    host_process = (
        profile
        / "AppData"
        / "Local"
        / "Programs"
        / "DarkSage"
        / "KeeperProviderHost"
        / "versions"
        / "1.7.50"
        / "KeeperProviderHost.exe"
    )
    host_process.parent.mkdir(parents=True)
    host_process.write_bytes(b"MZhost")
    gateway = ProviderHostGateway(
        pipe_name=r"\\.\pipe\KeeperProviderHost-reconciliation",
        authority_id="authority-test",
        host_id="host-test",
        authority_signer=AUTHORITY,
        host_verifier=HOST,
        expected_host_sid="S-1-5-21-1000",
        expected_host_session_id=1,
        expected_host_executable=host_process,
        expected_host_executable_sha256=hashlib.sha256(
            host_process.read_bytes()
        ).hexdigest(),
        expected_host_profile_path=profile,
        sequence_store=tmp_path / "reconciliation-sequences.db",
        production=False,
    )
    accounting = {
        "model_request_possible": False,
        "provider_mutation_possible": False,
        "read_only_process_execution_upper_bound": 2,
        "usage_observation_possible": True,
    }
    reconciliation: dict[str, Any] = {
        "authority_id": "authority-test",
        "authorized_client_sid": "S-1-5-21-1000",
        "effect_accounting": accounting,
        "enrollment_id": "enrollment-test",
        "expected_launch": {
            "launch_id": "provider-registration-probe:" + "a" * 32
        },
        "host_id": "host-test",
        "reconciliation_id": "provider-host-launch-reconciliation:" + "b" * 64,
        "resolution": "LEGACY_REGISTER_PROBE_READ_ONLY_EFFECT_ACCOUNTED",
    }

    def rpc(operation: str, body: Mapping[str, object]) -> dict[str, object]:
        assert operation == "reconcile_uncertain_launch"
        signed = body["signed_reconciliation"]
        assert isinstance(signed, dict)
        verified = AUTHORITY.verify(
            signed, purpose="keeper-provider-host-launch-reconciliation"
        )
        assert verified == reconciliation
        internal = {
            "authorization_digest": structured_digest(verified),
            "effect_accounting": accounting,
            "reconciliation_id": reconciliation["reconciliation_id"],
            "resolution": reconciliation["resolution"],
        }
        return HOST.sign(
            "keeper-provider-host-launch-reconciliation-result",
            {
                "authority_id": "authority-test",
                "effect_accounting": accounting,
                "host_id": "host-test",
                "launch_id": reconciliation["expected_launch"]["launch_id"],
                "reconciliation_digest": structured_digest(internal),
                "reconciliation_id": reconciliation["reconciliation_id"],
                "state": "FAILED",
            },
        )

    monkeypatch.setattr(gateway, "_rpc", rpc)
    result = gateway.reconcile_uncertain_launch(reconciliation)
    assert result["result"]["state"] == "FAILED"

    def altered_rpc(
        operation: str, body: Mapping[str, object]
    ) -> dict[str, object]:
        result = rpc(operation, body)
        payload = HOST.verify(
            result, purpose="keeper-provider-host-launch-reconciliation-result"
        )
        payload["effect_accounting"] = {**accounting, "model_request_possible": True}
        return HOST.sign(
            "keeper-provider-host-launch-reconciliation-result", payload
        )

    monkeypatch.setattr(gateway, "_rpc", altered_rpc)
    with pytest.raises(PermissionError, match="result differs"):
        gateway.reconcile_uncertain_launch(reconciliation)


def test_authority_gateway_environment_uses_handle_validated_bin_without_service_path_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, _, _, executable = _paths(tmp_path)
    host_process = (
        profile
        / "AppData"
        / "Local"
        / "Programs"
        / "DarkSage"
        / "KeeperProviderHost"
        / "versions"
        / "1.7.50"
        / "KeeperProviderHost.exe"
    )
    host_process.parent.mkdir(parents=True)
    host_process.write_bytes(b"MZhost")
    gateway = ProviderHostGateway(
        pipe_name=r"\\.\pipe\KeeperProviderHost-environment-path",
        authority_id="authority-test",
        host_id="host-test",
        authority_signer=AUTHORITY,
        host_verifier=HOST,
        expected_host_sid="S-1-5-21-1000",
        expected_host_session_id=1,
        expected_host_executable=host_process,
        expected_host_executable_sha256=hashlib.sha256(
            host_process.read_bytes()
        ).hexdigest(),
        expected_host_profile_path=profile,
        sequence_store=tmp_path / "environment-path-sequences.db",
        production=False,
    )
    provider_bin = executable.parent
    tls_root_bundle = _tls_bundle(tmp_path)
    rpc_payloads: list[dict[str, object]] = []

    def rpc(operation: str, payload: Mapping[str, object]) -> dict[str, object]:
        assert operation == "prepare_environment"
        rpc_payloads.append(dict(payload))
        return HOST.sign(
            "keeper-provider-host-environment",
            {
                "allowlist": ["PATH", "USERPROFILE"],
                "digest": "8" * 64,
                "host_id": "host-test",
                "preparation_nonce": "prepare-handle-bin",
                "recorded_at": datetime.now(UTC).isoformat(),
                "scrubbed_names": ["OPENAI_API_KEY"],
                "tls_root_bundle": tls_root_bundle,
            },
        )

    monkeypatch.setattr(gateway, "_rpc", rpc)

    def forbidden_resolve(self: Path, strict: bool = False) -> Path:
        del self, strict
        raise AssertionError("restricted Authority must not resolve the provider path")

    monkeypatch.setattr(Path, "resolve", forbidden_resolve)
    gateway.prepare_environment("prepare-handle-bin", provider_bin)

    assert rpc_payloads == [
        {
            "preparation_nonce": "prepare-handle-bin",
            "provider_bin": str(provider_bin),
        }
    ]
    with pytest.raises(PermissionError, match="environment bin is invalid"):
        gateway.prepare_environment("prepare-relative", Path("relative"))


def test_authority_gateway_fences_rpc_when_enrollment_is_not_durably_active(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    executable = (
        profile
        / "AppData"
        / "Local"
        / "Programs"
        / "DarkSage"
        / "KeeperProviderHost"
        / "versions"
        / "1.7.15"
        / "KeeperProviderHost.exe"
    )
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"MZhost")
    active = True
    gateway = ProviderHostGateway(
        pipe_name=r"\\.\pipe\KeeperProviderHost-never-opened",
        authority_id="authority-test",
        host_id="host-test",
        authority_signer=AUTHORITY,
        host_verifier=HOST,
        expected_host_sid="S-1-5-21-1000",
        expected_host_session_id=1,
        expected_host_executable=executable,
        expected_host_executable_sha256=hashlib.sha256(
            executable.read_bytes()
        ).hexdigest(),
        expected_host_profile_path=profile,
        sequence_store=tmp_path / "gateway-sequences.db",
        timeout_seconds=0.01,
        enrollment_is_active=lambda: active,
        production=False,
    )
    active = False
    with pytest.raises(PermissionError, match="enrollment is not active"):
        gateway.status()
    active = True
    gateway.deactivate()
    with pytest.raises(PermissionError, match="enrollment is not active"):
        gateway.status()


def test_provider_host_security_descriptors_deny_restricted_code_first() -> None:
    sid = "S-1-5-21-1000"
    service_sid = "S-1-5-80-1-2-3-4-5"
    expected_pipe = (
        f"D:P(D;;GA;;;S-1-5-12)(A;;GA;;;SY)"
        f"(A;;GA;;;{service_sid})(A;;GA;;;{sid})"
    )
    expected_key = f"D:P(D;;GA;;;S-1-5-12)(A;;GA;;;SY)(A;;GA;;;{sid})"
    assert host_pipe._pipe_security_sddl(sid, service_sid) == expected_pipe
    assert host_signing._key_security_sddl(sid) == expected_key
    with pytest.raises(ValueError, match="SID"):
        host_pipe._pipe_security_sddl("current-user", service_sid)
    with pytest.raises(ValueError, match="service SID"):
        host_pipe._pipe_security_sddl(sid, "S-1-5-18")
    with pytest.raises(ValueError, match="SID"):
        host_signing._key_security_sddl("current-user")


@pytest.mark.skipif(os.name != "nt", reason="exact Host ACLs require Windows")
def test_restricted_provider_cannot_read_protected_host_program(
    tmp_path: Path,
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    executable = package / "KeeperProviderHost.exe"
    executable.write_bytes(b"MZ-host-restricted-read-test")
    manifest = package / "keeper-provider-host-package-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "product": "KeeperProviderHost",
                "version": "1.7.12",
                "files": [
                    {
                        "path": executable.name,
                        "size": executable.stat().st_size,
                        "sha256": hashlib.sha256(
                            executable.read_bytes()
                        ).hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    installer = ProviderHostInstaller(
        tmp_path / "host",
        tmp_path / "startup",
        authority_service_sid=_TEST_SERVICE_SID,
    )
    installed = installer.install(
        executable,
        version="1.7.12",
        expected_package_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
    )
    protected = Path(installed.artifact_path)
    assert protected.read_bytes() == executable.read_bytes()

    with current_process_token() as source_token:
        with profile_restricted_primary_token(source_token) as restricted:
            with impersonate_token(restricted):
                with pytest.raises(PermissionError):
                    protected.read_bytes()


@pytest.mark.skipif(os.name != "nt", reason="exact Host ACLs require Windows")
def test_authenticated_client_observes_protected_old_host_while_provider_is_denied(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profile"
    root = (
        profile
        / "AppData"
        / "Local"
        / "Programs"
        / "DarkSage"
        / "KeeperProviderHost"
    )
    startup = (
        profile
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )
    package = tmp_path / "old-host-package"
    package.mkdir(parents=True)
    executable = package / "KeeperProviderHost.exe"
    shutil.copyfile(sys.executable, executable)
    manifest = package / "keeper-provider-host-package-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "product": "KeeperProviderHost",
                "version": "1.7.8",
                "files": [
                    {
                        "path": executable.name,
                        "size": executable.stat().st_size,
                        "sha256": hashlib.sha256(
                            executable.read_bytes()
                        ).hexdigest(),
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    installer = ProviderHostInstaller(
        root,
        startup,
        authority_service_sid=account_sid(r"NT SERVICE\KeeperAuthority"),
    )
    installed = installer.install(
        executable,
        version="1.7.8",
        expected_package_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
    )
    exchange = profile / "AppData" / "Local" / "DarkSage" / "KeeperProviderExchange"
    ensure_provider_host_exchange_root(exchange, owner_sid=current_process_sid())
    protected = Path(installed.artifact_path)

    with current_process_token() as source_token:
        sid = current_process_sid()
        session_id = token_session_id(source_token)
        process_executable = Path(sys.executable).resolve(strict=True)
        process_stat = process_executable.stat()
        identity = NamedPipeClientProcessIdentity(
            process_id=os.getpid(),
            session_id=session_id,
            sid=sid,
            computer_name="LOCALHOST",
            process_creation_time_100ns=1,
            executable_path=str(process_executable),
            executable_file_identity=(
                int(process_stat.st_dev),
                int(process_stat.st_ino),
                int(process_stat.st_size),
                int(process_stat.st_mtime_ns),
            ),
        )

        class CurrentClientBinding:
            profile_token = source_token

            @staticmethod
            def revalidate(expected_sid: str) -> NamedPipeClientProcessIdentity:
                assert expected_sid.casefold() == sid.casefold()
                return identity

            @staticmethod
            def bind_or_revalidate_executable_identity(
                expected_sid: str,
            ) -> NamedPipeClientProcessIdentity:
                assert expected_sid.casefold() == sid.casefold()
                measured = process_executable.stat()
                assert (
                    int(measured.st_dev),
                    int(measured.st_ino),
                    int(measured.st_size),
                    int(measured.st_mtime_ns),
                ) == identity.executable_file_identity
                return identity

        observation = _authority_provider_host_path_observation(
            client_process_binding=CurrentClientBinding(),  # type: ignore[arg-type]
            expected_sid=sid,
            profile=str(profile),
            installation={
                "executable_path": installed.artifact_path,
                "install_root": str(root),
            },
            observed_sid=sid,
        )
        assert observation["executable_sha256"] == installed.artifact_sha256

        with profile_restricted_primary_token(source_token) as restricted:
            with impersonate_token(restricted):
                with pytest.raises(PermissionError):
                    protected.read_bytes()


def test_provider_host_user_key_applies_exact_persistent_dacl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []

    class Api:
        def NCryptSetProperty(self, *args: object) -> int:
            calls.append(args)
            return 0

    @contextmanager
    def descriptor(_: str) -> Any:
        yield wintypes.LPVOID(123), 456

    monkeypatch.setattr(host_signing, "_key_security_descriptor", descriptor)
    host_signing._protect_user_key(Api(), ctypes.c_void_p(42), "S-1-5-21-1000")
    assert len(calls) == 1
    assert calls[0][1] == "Security Descr"
    assert calls[0][3] == 456
    assert calls[0][4] == 0x00000004


def test_authority_gateway_rejects_shared_or_unmeasured_host_binary(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    shared = tmp_path / "python.exe"
    shared.write_bytes(b"MZpython")
    dedicated = tmp_path / "KeeperProviderHost.exe"
    dedicated.write_bytes(b"MZhost")
    with pytest.raises(PermissionError, match="dedicated measured"):
        ProviderHostGateway(
            pipe_name=r"\\.\pipe\KeeperProviderHost-test",
            authority_id="authority-test",
            host_id="host-test",
            authority_signer=AUTHORITY,
            host_verifier=HOST,
            expected_host_sid="S-1-5-21-1000",
            expected_host_session_id=1,
            expected_host_profile_path=profile,
            sequence_store=tmp_path / "sequences.db",
            production=False,
            expected_host_executable=shared,
            expected_host_executable_sha256=hashlib.sha256(
                shared.read_bytes()
            ).hexdigest(),
        )
    with pytest.raises(PermissionError, match="dedicated measured"):
        ProviderHostGateway(
            pipe_name=r"\\.\pipe\KeeperProviderHost-test",
            authority_id="authority-test",
            host_id="host-test",
            authority_signer=AUTHORITY,
            host_verifier=HOST,
            expected_host_sid="S-1-5-21-1000",
            expected_host_session_id=1,
            expected_host_profile_path=profile,
            sequence_store=tmp_path / "sequences.db",
            production=False,
            expected_host_executable=dedicated,
            expected_host_executable_sha256="0" * 64,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows restricted-token test")
def test_profile_restricted_provider_cannot_open_provider_host_pipe() -> None:
    pipe_name = rf"\\.\pipe\KeeperProviderHost-deny-{uuid.uuid4().hex}"
    kernel32 = host_pipe._kernel32()
    with host_pipe._security_attributes(
        current_process_sid(), "S-1-5-80-1-2-3-4-5"
    ) as security:
        handle = kernel32.CreateNamedPipeW(
            pipe_name,
            host_pipe._PIPE_ACCESS_DUPLEX
            | host_pipe._FILE_FLAG_FIRST_PIPE_INSTANCE,
            host_pipe._PIPE_TYPE_BYTE
            | host_pipe._PIPE_READMODE_BYTE
            | host_pipe._PIPE_WAIT
            | host_pipe._PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            ctypes.byref(security),
        )
    assert handle not in {None, host_pipe._INVALID_HANDLE}
    try:
        with current_process_token() as source_token:
            with profile_restricted_primary_token(source_token) as token:
                with impersonate_token(token):
                    ctypes.set_last_error(0)
                    opened = kernel32.CreateFileW(
                        pipe_name,
                        host_pipe._GENERIC_READ | host_pipe._GENERIC_WRITE,
                        0,
                        None,
                        host_pipe._OPEN_EXISTING,
                        0,
                        None,
                    )
                    error = ctypes.get_last_error()
        assert opened in {None, host_pipe._INVALID_HANDLE}
        assert error == 5
    finally:
        assert kernel32.CloseHandle(handle)


def test_provider_host_install_repair_update_rollback_uninstall_and_recovery(
    tmp_path: Path,
) -> None:
    artifact_one, package_one, digest_one = _host_distribution(
        tmp_path / "host-1", version="1.0.0", marker=b"host-one"
    )
    artifact_two, package_two, digest_two = _host_distribution(
        tmp_path / "host-2", version="1.1.0", marker=b"host-two"
    )
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid=_TEST_SERVICE_SID,
    )
    installed = installer.install(
        artifact_one,
        version="1.0.0",
        expected_package_sha256=package_one,
    )
    assert installed.previous_version is None
    assert installed.package_sha256 == package_one
    assert installed.artifact_sha256 == digest_one
    assert (
        Path(installed.artifact_path).parent / "lib" / "python-runtime.dll"
    ).is_file()
    launcher = Path(installed.startup_path).read_text(encoding="utf-8")
    assert "KeeperProviderHost.exe" in launcher
    assert "python" not in launcher.casefold()
    assert ".pyz" not in launcher.casefold()
    if os.name == "nt":
        for protected_path in (
            installer.root,
            installer.startup_root,
            Path(installed.artifact_path),
            Path(installed.startup_path),
        ):
            policy = read_path_security(protected_path)
            matching = [
                ace
                for ace in policy["aces"]
                if ace["trustee_sid"] == "S-1-5-12"
            ]
            assert matching
            assert all(ace["ace_type"] == "deny" for ace in matching)
        kernel32 = host_pipe._kernel32()
        with current_process_token() as source_token:
            with profile_restricted_primary_token(source_token) as token:
                with impersonate_token(token):
                    ctypes.set_last_error(0)
                    opened = kernel32.CreateFileW(
                        installed.artifact_path,
                        host_pipe._GENERIC_READ,
                        0,
                        None,
                        host_pipe._OPEN_EXISTING,
                        0,
                        None,
                    )
                    error = ctypes.get_last_error()
        assert opened in {None, host_pipe._INVALID_HANDLE}
        assert error == 5
        with current_process_token() as source_token:
            with profile_restricted_primary_token(source_token) as token:
                with impersonate_token(token):
                    with pytest.raises(PermissionError):
                        Path(installed.startup_path).unlink()
                    with pytest.raises(PermissionError):
                        (installer.startup_root / "restricted-replacement.cmd").write_bytes(
                            b"untrusted"
                        )
        assert Path(installed.startup_path).is_file()
        assert not (installer.startup_root / "restricted-replacement.cmd").exists()
    assert (
        installer.repair(
            artifact_one, expected_package_sha256=package_one
        ).version
        == "1.0.0"
    )
    drained: list[str] = []
    updated = installer.update(
        artifact_two,
        version="1.1.0",
        expected_package_sha256=package_two,
        drain=lambda: drained.append("update"),
    )
    assert updated.previous_version == "1.0.0"
    assert installer.rollback(drain=lambda: drained.append("rollback")).version == "1.0.0"
    assert drained == ["update", "rollback"]
    assert installer.recover()["recovered"] is False
    result = installer.uninstall_preserving_data(
        drain=lambda: drained.append("uninstall")
    )
    assert result == {
        "program_removed": True,
        "startup_removed": True,
        "state_preserved": True,
        "logs_preserved": True,
    }
    assert installer.state.is_dir()
    assert installer.logs.is_dir()


def test_provider_host_171_to_174_update_is_inert_and_preserves_empty_state(
    tmp_path: Path,
) -> None:
    old_artifact, old_manifest, _ = _host_distribution(
        tmp_path / "host-171", version="1.7.1", marker=b"host-171"
    )
    new_artifact, new_manifest, new_digest = _host_distribution(
        tmp_path / "host-174", version="1.7.4", marker=b"host-174"
    )
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid=_TEST_SERVICE_SID,
    )
    installer.install(
        old_artifact,
        version="1.7.1",
        expected_package_sha256=old_manifest,
    )
    assert list(installer.state.iterdir()) == []
    assert list(installer.logs.iterdir()) == []

    drains: list[str] = []
    result = installer.update(
        new_artifact,
        version="1.7.4",
        expected_package_sha256=new_manifest,
        drain=lambda: drains.append("drained"),
    )

    assert result.version == "1.7.4"
    assert result.previous_version == "1.7.1"
    assert result.artifact_sha256 == new_digest
    assert drains == ["drained"]
    assert list(installer.state.iterdir()) == []
    assert list(installer.logs.iterdir()) == []
    assert not (installer.state / "enrollment-receipt.json").exists()
    assert not (installer.state / "provider-host.db").exists()
    status = installer.status()
    assert status["transaction_pending"] is False
    assert status["current"]["version"] == "1.7.4"  # type: ignore[index]
    assert status["current"]["previous_version"] == "1.7.1"  # type: ignore[index]
    assert str(Path(result.artifact_path).resolve()) in Path(
        result.startup_path
    ).read_text(encoding="utf-8")


def test_provider_host_package_manifest_rejects_tamper_omission_and_extra_file(
    tmp_path: Path,
) -> None:
    artifact, package_digest, _ = _host_distribution(
        tmp_path / "package", version="1.0.0", marker=b"package"
    )
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid=_TEST_SERVICE_SID,
    )
    (artifact.parent / "lib" / "python-runtime.dll").write_bytes(b"changed")
    with pytest.raises(PermissionError, match="file differs"):
        installer.install(
            artifact,
            version="1.0.0",
            expected_package_sha256=package_digest,
        )

    artifact, package_digest, _ = _host_distribution(
        tmp_path / "omission", version="1.0.0", marker=b"omission"
    )
    (artifact.parent / "lib" / "python-runtime.dll").unlink()
    with pytest.raises((FileNotFoundError, PermissionError)):
        installer.install(
            artifact,
            version="1.0.0",
            expected_package_sha256=package_digest,
        )

    artifact, package_digest, _ = _host_distribution(
        tmp_path / "extra", version="1.0.0", marker=b"extra"
    )
    (artifact.parent / "unmeasured.dll").write_bytes(b"unmeasured")
    with pytest.raises(PermissionError, match="coverage differs"):
        installer.install(
            artifact,
            version="1.0.0",
            expected_package_sha256=package_digest,
        )


def test_provider_host_package_manifest_rejects_path_escape_and_wrong_identity(
    tmp_path: Path,
) -> None:
    artifact, _, _ = _host_distribution(
        tmp_path / "package", version="1.0.0", marker=b"package"
    )
    manifest = artifact.parent / "keeper-provider-host-package-manifest.json"
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["files"][0]["path"] = "../KeeperProviderHost.exe"
    manifest.write_text(json.dumps(value), encoding="utf-8")
    package_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid=_TEST_SERVICE_SID,
    )
    with pytest.raises(PermissionError, match="relative path"):
        installer.install(
            artifact,
            version="1.0.0",
            expected_package_sha256=package_digest,
        )
    artifact, package_digest, _ = _host_distribution(
        tmp_path / "wrong-version", version="2.0.0", marker=b"version"
    )
    with pytest.raises(PermissionError, match="identity differs"):
        installer.install(
            artifact,
            version="1.0.0",
            expected_package_sha256=package_digest,
        )


def test_provider_host_recovery_restores_verified_pre_swap_backup(
    tmp_path: Path,
) -> None:
    artifact, package_digest, _ = _host_distribution(
        tmp_path / "package", version="1.0.0", marker=b"original"
    )
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid=_TEST_SERVICE_SID,
    )
    installed = installer.install(
        artifact,
        version="1.0.0",
        expected_package_sha256=package_digest,
    )
    version_root = Path(installed.artifact_path).parent
    backup = installer.versions / ".1.0.0.crash.backup"
    staging = installer.versions / ".1.0.0.crash.staging"
    staging.mkdir()
    (staging / "partial.tmp").write_bytes(b"partial")
    os.replace(version_root, backup)
    installer.transaction_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "operation": "update",
                "version": "1.0.0",
                "artifact_sha256": installed.artifact_sha256,
                "package_sha256": package_digest,
                "previous_version": "1.0.0",
                "staging_path": str(staging),
                "backup_path": str(backup),
                "started_at": datetime.now(UTC).isoformat(),
            }
        ),
        encoding="utf-8",
    )

    recovered = installer.recover()

    assert recovered["recovered"] is True
    assert Path(installed.artifact_path).is_file()
    assert hashlib.sha256(Path(installed.artifact_path).read_bytes()).hexdigest() == (
        installed.artifact_sha256
    )
    assert not backup.exists()
    assert not staging.exists()
    assert not installer.transaction_path.exists()


def test_provider_host_recovery_completes_claimed_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_one, package_one, _ = _host_distribution(
        tmp_path / "one", version="1.0.0", marker=b"one"
    )
    artifact_two, package_two, _ = _host_distribution(
        tmp_path / "two", version="1.1.0", marker=b"two"
    )
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid=_TEST_SERVICE_SID,
    )
    installer.install(
        artifact_one, version="1.0.0", expected_package_sha256=package_one
    )
    installer.update(
        artifact_two,
        version="1.1.0",
        expected_package_sha256=package_two,
        drain=lambda: None,
    )
    original_commit = installer._commit_selection

    def crash_after_launcher(*args: object, **kwargs: object) -> None:
        del kwargs
        package: Any = args[0]
        installer._write_startup_launcher(package.executable)
        raise RuntimeError("simulated rollback interruption")

    monkeypatch.setattr(installer, "_commit_selection", crash_after_launcher)
    with pytest.raises(RuntimeError, match="interruption"):
        installer.rollback(drain=lambda: None)
    monkeypatch.setattr(installer, "_commit_selection", original_commit)

    recovered = installer.recover()

    assert recovered["recovered"] is True
    assert recovered["current"]["version"] == "1.0.0"  # type: ignore[index]
    assert str(
        (installer.versions / "1.0.0" / "KeeperProviderHost.exe").resolve()
    ) in Path(installer.startup_path).read_text(encoding="utf-8")


def test_provider_host_recovery_completes_data_preserving_uninstall(
    tmp_path: Path,
) -> None:
    artifact, package_digest, _ = _host_distribution(
        tmp_path / "package", version="1.0.0", marker=b"one"
    )
    installer = ProviderHostInstaller(
        tmp_path / "install",
        tmp_path / "startup",
        authority_service_sid=_TEST_SERVICE_SID,
    )
    installer.install(
        artifact, version="1.0.0", expected_package_sha256=package_digest
    )
    installer.transaction_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "operation": "uninstall",
                "version": "",
                "artifact_sha256": "",
                "package_sha256": "",
                "previous_version": None,
                "staging_path": "",
                "backup_path": "",
                "started_at": datetime.now(UTC).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    installer.startup_path.unlink()

    recovered = installer.recover()

    assert recovered == {"recovered": True, "current": None}
    assert not installer.versions.exists()
    assert not installer.current_path.exists()
    assert not installer.startup_path.exists()
    assert installer.state.is_dir()
    assert installer.logs.is_dir()

class _StatusGateway:
    def __init__(self, result: dict[str, Any] | Exception) -> None:
        self.result = result

    def status(self) -> dict[str, Any]:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_provider_host_status_is_redacted_truthful_and_fail_closed() -> None:
    observer = object.__new__(ServiceProviderObserver)
    observer.provider_host_gateway = _StatusGateway(
        {
            "state": "READY",
            "host_protocol": "keeper-provider-host/1",
            "launch_journal": {
                "active_launch_count": 0,
                "active_or_uncertain_launch_count": 0,
                "launches": [],
                "summary_digest": structured_digest([]),
                "uncertain_launch_count": 0,
            },
            "provider_binding": {
                "provider_id": "codex",
                "registration_id": "registration-test",
                "qualification_id": "qualification-test",
                "executable_path": r"C:\private\codex.exe",
                "account_id": "private-account",
            },
        }
    )  # type: ignore[assignment]
    status = observer.provider_host_status()
    assert status == {
        "installed": True,
        "online": True,
        "state": "READY",
        "protocol": "keeper-provider-host/1",
        "protocol_compatible": True,
        "provider_id": "codex",
        "provider_state": "QUALIFIED",
        "execution_state": "IDLE",
        "active_or_uncertain_launch_count": 0,
        "active_launch_count": 0,
        "uncertain_launch_count": 0,
        "launch_state_proven": True,
        "launches": [],
        "usage_state": "AUTHORITY_MANAGED",
        "founder_action_required": None,
    }
    assert "executable_path" not in status
    assert "account_id" not in status

    observer.provider_host_gateway = _StatusGateway(
        {
            "state": "READY",
            "host_protocol": "keeper-provider-host/1",
            "launch_journal": {
                "active_launch_count": 0,
                "active_or_uncertain_launch_count": 0,
                "launches": [],
                "summary_digest": structured_digest([]),
                "uncertain_launch_count": 0,
            },
            "provider_binding": None,
        }
    )  # type: ignore[assignment]
    unbound = observer.provider_host_status()
    assert unbound["provider_state"] == "NO_QUALIFIED_PROVIDERS"
    assert unbound["founder_action_required"] == (
        "COMPLETE_PROVIDER_REGISTRATION_AND_QUALIFICATION"
    )

    observer.provider_host_gateway = _StatusGateway(
        PermissionError("identity mismatch")
    )  # type: ignore[assignment]
    unavailable = observer.provider_host_status()
    assert unavailable["state"] == "OFFLINE"
    assert unavailable["provider_state"] == "UNAVAILABLE"
    assert unavailable["founder_action_required"] == "START_OR_REPAIR_PROVIDER_HOST"
    assert unavailable["failure_reason"] == (
        "PermissionError:IDENTITY_OR_PROTOCOL_REJECTED"
    )

    observer.provider_host_gateway = _StatusGateway(
        OSError(5, r"C:\private\host\KeeperProviderHost.exe")
    )  # type: ignore[assignment]
    path_failure = observer.provider_host_status()
    assert path_failure["failure_reason"] == "OSError:PIPE_UNAVAILABLE"
    assert "private" not in path_failure["failure_reason"].casefold()


@pytest.mark.parametrize(
    ("observation", "expected"),
    [
        (
            {"failure_stage": "VERSION_LAUNCH", "failure_code": "WIN32_267"},
            "stage=VERSION_LAUNCH, code=WIN32_267",
        ),
        (
            {
                "failure_stage": r"C:\Users\Founder\private",
                "failure_code": "WIN32_267",
                "failure_reason": "password=secret",
            },
            "stage=UNAVAILABLE, code=INVALID_RESULT",
        ),
        (
            {
                "failure_stage": "VERSION_LAUNCH",
                "failure_code": "WIN32_999999",
            },
            "stage=UNAVAILABLE, code=INVALID_RESULT",
        ),
        (None, "stage=UNAVAILABLE, code=INVALID_RESULT"),
    ],
)
def test_provider_host_setup_failure_is_fixed_and_sanitized(
    observation: object, expected: str
) -> None:
    assert observer_module._provider_host_setup_failure(observation) == expected
    assert "private" not in expected.casefold()
    assert "secret" not in expected.casefold()


@pytest.mark.parametrize(
    ("expected_plan", "observed_plan", "succeeds"),
    [
        ("pro", "pro", True),
        ("plus", "pro", False),
        ("pro", "plus", False),
    ],
)
def test_codex_setup_runner_uses_exact_restricted_host_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    expected_plan: str,
    observed_plan: str,
    succeeds: bool,
) -> None:
    profile, _, _, executable = _paths(tmp_path)
    provider = _provider(executable)
    account_digest = hashlib.sha256(
        b"chatgpt\0founder@example.invalid"
    ).hexdigest()
    setup_id = "provider-qualification:" + "e" * 32
    output_root = tmp_path / "setup-output"
    workspace = output_root / hashlib.sha256(setup_id.encode("utf-8")).hexdigest()
    workspace.mkdir(parents=True)
    envelope: dict[str, Any] = {
        "account_binding": {
            "account_identity_digest": account_digest,
            "authentication_method": "chatgpt-subscription",
            "plan_type": expected_plan,
        },
        "challenge": "setup-challenge",
        "environment": {"tls_root_bundle": _tls_bundle(tmp_path)},
        "executable": {
            "path": provider.executable_path,
            "version": provider.version,
            "sha256": provider.executable_sha256,
        },
        "model_id": "gpt-5.6-sol",
        "operation": "QUALIFY",
        "provider_registration_id": provider.registration_id,
        "resource_limits": {
            "active_process_limit": 8,
            "memory_bytes": 1024,
            "stderr_bytes": 1024,
            "stdout_bytes": 1024,
            "timeout_seconds": 30,
        },
        "setup_id": setup_id,
        "user_binding": {
            "profile_path": str(profile),
            "session_id": 1,
            "user_sid": "S-1-5-21-1000",
        },
        "workspace": {"canonical_path": str(workspace.resolve())},
    }

    @contextmanager
    def fake_context(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        yield 123

    @contextmanager
    def fake_lock(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        yield {"sha256": provider.executable_sha256}

    calls: list[list[str]] = []
    probe_lines = [
        json.dumps({"id": 1, "result": {"platformOs": "windows"}}),
        json.dumps(
            {
                "id": 2,
                "result": {
                    "account": {
                        "type": "chatgpt",
                        "planType": observed_plan,
                        "email": "founder@example.invalid",
                    }
                },
            }
        ),
        json.dumps(
            {
                "id": 3,
                "result": {
                    "data": [
                        {
                            "model": "gpt-5.6-sol",
                            "hidden": False,
                            "supportedReasoningEfforts": ["medium", "high"],
                        }
                    ]
                },
            }
        ),
        json.dumps({"id": 4, "result": {"rateLimits": {}}}),
    ]

    def fake_run(
        token: object,
        command: list[str],
        *args: object,
        **kwargs: object,
    ) -> RestrictedProcessResult:
        del token
        calls.append(command)
        if command[-1] == "--version":
            args[6]({"pid": 321, "suspended": True})  # type: ignore[operator]
            kwargs["on_resumed"]({"pid": 321, "resumed": True})  # type: ignore[operator]
            stdout = provider.version
        elif "app-server" in command:
            assert kwargs.get("stdin_path") is None
            assert (
                kwargs.get("jsonl_exchange")
                == windows_process.app_server_probe_exchange()
            )
            stdout = "\n".join(probe_lines)
        else:
            schema_index = command.index("--output-schema") + 1
            schema = json.loads(Path(command[schema_index]).read_text("utf-8"))
            assert schema == {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "status": {"type": "string", "const": "ok"},
                    "provider": {"type": "string", "const": "codex"},
                    "effort": {"type": "string", "const": "medium"},
                    "nonce": {
                        "type": "string",
                        "const": "keeper-codex-qualification-v1",
                    },
                },
                "required": ["status", "provider", "effort", "nonce"],
            }
            output_index = command.index("--output-last-message") + 1
            Path(command[output_index]).write_text(
                json.dumps(
                    {
                        "status": "ok",
                        "provider": "codex",
                        "effort": "medium",
                        "nonce": "keeper-codex-qualification-v1",
                    }
                ),
                encoding="utf-8",
            )
            stdout = ""
        return RestrictedProcessResult(
            321,
            0,
            stdout,
            "",
            str(executable),
            provider.executable_sha256,
            True,
            "medium",
            True,
            False,
        )

    monkeypatch.setattr(windows_process, "locked_executable", fake_lock)
    monkeypatch.setattr(windows_process, "locked_tls_root_bundle", fake_lock)
    monkeypatch.setattr(windows_process, "current_process_token", fake_context)
    monkeypatch.setattr(
        windows_process, "profile_restricted_primary_token", fake_context
    )
    monkeypatch.setattr(windows_process, "run_restricted_process", fake_run)
    runner = windows_process.CodexSetupRunner(output_root)
    started: list[dict[str, object]] = []
    resumed: list[dict[str, object]] = []
    result = runner.run_setup(
        envelope,
        {
            "PATH": str(executable.parent),
            "SSL_CERT_FILE": str(_tls_bundle(tmp_path)["canonical_path"]),
            "USERPROFILE": str(profile),
        },
        threading.Event(),
        on_started=started.append,
        on_resumed=resumed.append,
    )
    assert result["exit_status"] == (0 if succeeds else 70)
    if succeeds:
        assert result["failure_reason"] is None
        assert result["structured_output"]["status"] == "ok"
    else:
        assert result["failure_reason"] == "PermissionError:PERMISSION_REJECTED"
        assert result["failure_stage"] == "ACCOUNT_BINDING_VALIDATE"
        assert result["structured_output"] is None
    assert result["authentication_probe"]["account_identity_digest"] == account_digest
    assert [call[1] for call in calls[:2]] == ["--version", "app-server"]
    if succeeds:
        assert "--model" in calls[2]
        assert any("medium" in item for item in calls[2])
    else:
        assert len(calls) == 2
    assert started and resumed


@pytest.mark.parametrize(
    ("failure_point", "expected_stage", "expected_code"),
    [
        ("launch", "VERSION_CREATE_PROCESS", "WIN32_267"),
        ("started", "VERSION_STARTED_ACK", "PERMISSION_REJECTED"),
        ("resumed", "VERSION_RESUME", "PERMISSION_REJECTED"),
        ("version", "VERSION_VALIDATE", "PERMISSION_REJECTED"),
        ("probe", "ACCOUNT_PROBE_LAUNCH", "WIN32_5"),
        ("probe_exit", "ACCOUNT_PROBE_VALIDATE", "PERMISSION_REJECTED"),
        ("probe_timeout", "ACCOUNT_PROBE_VALIDATE", "TIMEOUT"),
    ],
)
def test_codex_setup_runner_reports_only_bounded_failure_stage_and_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
    expected_stage: str,
    expected_code: str,
) -> None:
    profile, _, _, executable = _paths(tmp_path)
    provider = _provider(executable)
    setup_id = "provider-registration-probe:" + "d" * 32
    output_root = tmp_path / "setup-output"
    workspace = output_root / hashlib.sha256(setup_id.encode("utf-8")).hexdigest()
    workspace.mkdir(parents=True)
    envelope: dict[str, Any] = {
        "account_binding": {
            "account_identity_digest": "DISCOVER",
            "authentication_method": "chatgpt-subscription",
            "plan_type": "plus",
        },
        "challenge": "setup-failure-challenge",
        "environment": {"tls_root_bundle": _tls_bundle(tmp_path)},
        "executable": {
            "path": provider.executable_path,
            "version": provider.version,
            "sha256": provider.executable_sha256,
        },
        "model_id": "gpt-5.6-sol",
        "operation": "REGISTER_PROBE",
        "provider_registration_id": provider.registration_id,
        "resource_limits": {
            "active_process_limit": 8,
            "memory_bytes": 1024,
            "stderr_bytes": 1024,
            "stdout_bytes": 1024,
            "timeout_seconds": 30,
        },
        "setup_id": setup_id,
        "user_binding": {
            "profile_path": str(profile),
            "session_id": 1,
            "user_sid": "S-1-5-21-1000",
        },
        "workspace": {"canonical_path": str(workspace.resolve())},
    }

    @contextmanager
    def fake_context(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        yield 123

    @contextmanager
    def fake_lock(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        yield {"sha256": provider.executable_sha256}

    calls = 0

    def fake_run(
        token: object,
        command: list[str],
        *args: object,
        **kwargs: object,
    ) -> RestrictedProcessResult:
        nonlocal calls
        del token
        calls += 1
        launch_stage = kwargs.get("on_launch_stage")
        if launch_stage is not None:
            launch_stage("CREATE_PROCESS")  # type: ignore[operator]
        if failure_point == "launch" and calls == 1:
            raise PermissionError(
                "restricted provider creation failed "
                "(win32_error=267, symbolic=ERROR_DIRECTORY, "
                r"private=C:\Users\Founder\secret)"
            )
        if failure_point == "started" and calls == 1:
            args[6]({"pid": 321})  # type: ignore[operator]
        if failure_point == "resumed" and calls == 1:
            args[6]({"pid": 321})  # type: ignore[operator]
            kwargs["on_resumed"]({"pid": 321})  # type: ignore[operator]
        if failure_point == "probe" and calls == 2:
            raise OSError(5, r"C:\Users\Founder\private")
        stdout = (
            "codex-cli 0.999.0"
            if failure_point == "version" and calls == 1
            else provider.version
        )
        return RestrictedProcessResult(
            321,
            7 if failure_point == "probe_exit" and calls == 2 else 0,
            stdout,
            "",
            str(executable),
            provider.executable_sha256,
            True,
            "medium",
            True,
            failure_point == "probe_timeout" and calls == 2,
        )

    monkeypatch.setattr(windows_process, "locked_executable", fake_lock)
    monkeypatch.setattr(windows_process, "locked_tls_root_bundle", fake_lock)
    monkeypatch.setattr(windows_process, "current_process_token", fake_context)
    monkeypatch.setattr(
        windows_process, "profile_restricted_primary_token", fake_context
    )
    monkeypatch.setattr(windows_process, "run_restricted_process", fake_run)
    started = (
        (lambda value: (_ for _ in ()).throw(PermissionError("private ack")))
        if failure_point == "started"
        else lambda value: None
    )
    resumed = (
        (lambda value: (_ for _ in ()).throw(PermissionError("private resume")))
        if failure_point == "resumed"
        else lambda value: None
    )

    result = windows_process.CodexSetupRunner(output_root).run_setup(
        envelope,
        {
            "PATH": str(executable.parent),
            "SSL_CERT_FILE": str(_tls_bundle(tmp_path)["canonical_path"]),
            "USERPROFILE": str(profile),
        },
        threading.Event(),
        on_started=started,
        on_resumed=resumed,
    )

    assert result["exit_status"] == 70
    assert result["failure_stage"] == expected_stage
    assert result["failure_code"] == expected_code
    assert "private" not in str(result["failure_stage"]).casefold()
    assert "private" not in str(result["failure_code"]).casefold()
    assert result["authentication_probe"] is None
    if failure_point in {"probe_exit", "probe_timeout"}:
        assert result["process_result"] == {
            "operation": "ACCOUNT_PROBE",
            "exit_code": 7 if failure_point == "probe_exit" else 0,
            "timed_out": failure_point == "probe_timeout",
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_bytes": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "stderr_bytes": 0,
            "restricted": True,
            "job_confined": True,
            "started": True,
            "resumed": True,
        }


def test_codex_setup_runner_preserves_cleanup_uncertainty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, _, _, executable = _paths(tmp_path)
    provider = _provider(executable)
    setup_id = "provider-registration-probe:" + "e" * 32
    output_root = tmp_path / "setup-output"
    workspace = output_root / hashlib.sha256(setup_id.encode("utf-8")).hexdigest()
    workspace.mkdir(parents=True)
    envelope = {
        "account_binding": {
            "account_identity_digest": "DISCOVER",
            "authentication_method": "chatgpt-subscription",
            "plan_type": "plus",
        },
        "challenge": "cleanup-uncertain",
        "environment": {"tls_root_bundle": _tls_bundle(tmp_path)},
        "executable": {
            "path": provider.executable_path,
            "version": provider.version,
            "sha256": provider.executable_sha256,
        },
        "model_id": "gpt-5.6-sol",
        "operation": "REGISTER_PROBE",
        "provider_registration_id": provider.registration_id,
        "resource_limits": {
            "active_process_limit": 8,
            "memory_bytes": 1024,
            "stderr_bytes": 1024,
            "stdout_bytes": 1024,
            "timeout_seconds": 30,
        },
        "setup_id": setup_id,
        "user_binding": {
            "profile_path": str(profile),
            "session_id": 1,
            "user_sid": "S-1-5-21-1000",
        },
        "workspace": {"canonical_path": str(workspace.resolve())},
    }

    @contextmanager
    def fake_context(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        yield 123

    @contextmanager
    def fake_lock(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        yield {"sha256": provider.executable_sha256}

    def uncertain(*args: object, **kwargs: object) -> RestrictedProcessResult:
        del args, kwargs
        raise RestrictedProcessCleanupUncertain("sanitized cleanup uncertainty")

    monkeypatch.setattr(windows_process, "locked_executable", fake_lock)
    monkeypatch.setattr(windows_process, "locked_tls_root_bundle", fake_lock)
    monkeypatch.setattr(windows_process, "current_process_token", fake_context)
    monkeypatch.setattr(
        windows_process, "profile_restricted_primary_token", fake_context
    )
    monkeypatch.setattr(windows_process, "run_restricted_process", uncertain)

    with pytest.raises(RestrictedProcessCleanupUncertain):
        windows_process.CodexSetupRunner(output_root).run_setup(
            envelope,
            {
                "PATH": str(executable.parent),
                "SSL_CERT_FILE": str(_tls_bundle(tmp_path)["canonical_path"]),
                "USERPROFILE": str(profile),
            },
            threading.Event(),
            on_started=lambda value: None,
            on_resumed=lambda value: None,
        )


def test_codex_setup_runner_rejects_workspace_outside_exact_output_root(
    tmp_path: Path,
) -> None:
    setup_id = "provider-registration-probe:" + "f" * 32
    output_root = tmp_path / "output" / "setup"
    expected = output_root / hashlib.sha256(setup_id.encode("utf-8")).hexdigest()
    expected.mkdir(parents=True)
    outside = tmp_path / "protected-state" / "setup" / expected.name
    outside.mkdir(parents=True)
    envelope = {
        "challenge": "setup-workspace-challenge",
        "executable": {"path": str(tmp_path / "codex.exe")},
        "model_id": "gpt-5.6-sol",
        "operation": "REGISTER_PROBE",
        "provider_registration_id": "keeper-provider:codex:v1:" + "a" * 32,
        "resource_limits": {
            "active_process_limit": 8,
            "memory_bytes": 1024,
            "stderr_bytes": 1024,
            "stdout_bytes": 1024,
            "timeout_seconds": 30,
        },
        "setup_id": setup_id,
        "user_binding": {
            "profile_path": str(tmp_path),
            "session_id": 1,
            "user_sid": "S-1-5-21-1000",
        },
        "workspace": {"canonical_path": str(outside)},
    }
    runner = windows_process.CodexSetupRunner(output_root)
    with pytest.raises(
        PermissionError, match="setup output workspace differs"
    ):
        runner.run_setup(
            envelope,
            {},
            threading.Event(),
            on_started=lambda value: None,
            on_resumed=lambda value: None,
        )
