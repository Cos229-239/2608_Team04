from __future__ import annotations

import json
import hashlib
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

import pytest

from keeper.authority_service.restricted_process import RestrictedProcessResult
from keeper.authority_service.client import AuthorityServiceClient
from keeper.authority_service.claude_registration import (
    register_and_qualify_once,
    registration_declaration,
)
from keeper.authority_service.core import (
    AuthorityServiceCore,
    QualificationObservation,
)
from keeper.authority_service.observer import ServiceProviderObserver
from keeper.executive.founder_capability import TestFounderCapabilityVerifier
from keeper.provider_host.replay_store import ProviderHostStore
from keeper.provider_host.protocol import (
    TestEnvelopeIdentity as EnvelopeTestIdentity,
)
from keeper.provider_host.identity import UserBinding
from keeper.provider_host.runtime import HostIdentity, KeeperProviderHost
from keeper.provider_host import windows_process
from keeper.provider_host.windows_process import (
    CodexSetupRunner,
    ProviderProcessLauncher,
)
from keeper.providers.adapters import qualified_version_is_valid
from keeper.providers.adapters import (
    create_provider_registration,
    validate_provider_registration_contract,
)
from keeper.providers.claude_contract import (
    CLAUDE_AUTHENTICODE_THUMBPRINT,
)
from keeper.providers.claude_contract import (
    CLAUDE_PINNED_REVIEW_MODEL,
    build_claude_exec_command,
    build_claude_qualification_command,
    parse_claude_auth_status,
    validate_claude_version_output,
)


def _auth(**changes: object) -> str:
    value: dict[str, object] = {
        "loggedIn": True,
        "authMethod": "claude.ai",
        "apiProvider": "firstParty",
        "email": "reviewer@example.invalid",
        "orgId": "organization-1",
        "orgName": "Reviewer",
        "subscriptionType": "pro",
    }
    value.update(changes)
    return json.dumps(value)


def test_auth_status_is_sanitized_and_account_bound() -> None:
    result = parse_claude_auth_status(_auth())
    assert result["authentication_method"] == "claude-ai-subscription"
    assert result["plan_type"] == "pro"
    assert len(str(result["account_identity_digest"])) == 64
    assert "reviewer@example.invalid" not in json.dumps(result)
    assert result["models"] == [CLAUDE_PINNED_REVIEW_MODEL]


@pytest.mark.parametrize(
    ("change", "value"),
    [
        ("loggedIn", False),
        ("authMethod", "apiKey"),
        ("apiProvider", "thirdParty"),
        ("subscriptionType", "free"),
        ("email", ""),
        ("orgId", ""),
    ],
)
def test_auth_status_rejects_unapproved_identity(
    change: str, value: object
) -> None:
    with pytest.raises(PermissionError):
        parse_claude_auth_status(_auth(**{change: value}))


def test_auth_status_rejects_extra_fields() -> None:
    with pytest.raises(PermissionError, match="fields"):
        parse_claude_auth_status(_auth(token="secret"))


def test_exec_command_is_pinned_and_has_no_fallback_or_write_tools() -> None:
    command = build_claude_exec_command(
        Path(r"C:\reviewed\claude.exe"),
        model_id=CLAUDE_PINNED_REVIEW_MODEL,
        reasoning_level="medium",
        schema={"type": "object"},
        prompt="Review only.",
    )
    assert command[0] == r"C:\reviewed\claude.exe"
    assert command[command.index("--model") + 1] == CLAUDE_PINNED_REVIEW_MODEL
    assert command[command.index("--effort") + 1] == "medium"
    assert command[command.index("--tools") + 1] == "Read,Grep,Glob"
    assert "--setting-sources=" in command
    assert "--no-session-persistence" in command
    assert "--fallback-model" not in command
    assert "Bash" not in command
    assert "Edit" not in command
    assert "Write" not in command


def test_exec_command_rejects_alias_and_unsupported_effort() -> None:
    with pytest.raises(PermissionError, match="model"):
        build_claude_exec_command(
            Path("claude.exe"),
            model_id="sonnet",
            reasoning_level="medium",
            schema={"type": "object"},
            prompt="Review.",
        )


def test_claude_one_shot_persists_registration_before_qualification(
    tmp_path: Path,
) -> None:
    class Client:
        register_calls = 0
        qualify_calls = 0

        def register_provider(
            self, provider_id: str, executable: Path, **declaration: Any
        ) -> dict[str, Any]:
            assert provider_id == "claude"
            assert executable.name == "claude.exe"
            assert declaration["model_allowlist"] == [CLAUDE_PINNED_REVIEW_MODEL]
            self.register_calls += 1
            return {"registration_id": "registration-claude"}

        def qualify_provider(
            self, registration_id: str, executable: Path | None = None
        ) -> dict[str, Any]:
            assert (
                tmp_path / "output" / "registration-response.json"
            ).is_file()
            assert registration_id == "registration-claude"
            assert executable is not None
            self.qualify_calls += 1
            return {"qualification": {"id": "qualification-claude"}}

    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"fixture")
    declaration = registration_declaration(
        expected_executable_sha256=hashlib.sha256(b"fixture").hexdigest(),
        expected_executable_size=7,
        expected_version="2.1.220 (Claude Code)",
        subscription_plan="pro",
        keeper_launch_budget=10,
        now=datetime(2026, 8, 15, tzinfo=UTC),
    )
    client = Client()
    result = register_and_qualify_once(
        client, executable, tmp_path / "output", declaration
    )
    assert result["registration_id"] == "registration-claude"
    assert result["qualification_id"] == "qualification-claude"
    assert client.register_calls == client.qualify_calls == 1


def test_claude_one_shot_never_qualifies_failed_registration(
    tmp_path: Path,
) -> None:
    class Client:
        qualify_calls = 0

        @staticmethod
        def register_provider(
            provider_id: str, executable: Path, **declaration: Any
        ) -> dict[str, Any]:
            del provider_id, executable, declaration
            return {"registration_failed": {"id": "failure"}}

        def qualify_provider(
            self, registration_id: str, executable: Path | None = None
        ) -> dict[str, Any]:
            del registration_id, executable
            self.qualify_calls += 1
            return {}

    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"fixture")
    with pytest.raises(PermissionError, match="failure was persisted"):
        register_and_qualify_once(
            Client(), executable, tmp_path / "failed", {}
        )
    assert Client.qualify_calls == 0
    with pytest.raises(PermissionError, match="effort"):
        build_claude_exec_command(
            Path("claude.exe"),
            model_id=CLAUDE_PINNED_REVIEW_MODEL,
            reasoning_level="low",
            schema={"type": "object"},
            prompt="Review.",
        )


def test_claude_registration_provisional_envelope_keeps_provider_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.observer as observer_module

    profile = tmp_path / "Founder"
    profile.mkdir()
    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"signed-claude-fixture")
    credential = tmp_path / "provider.credential"
    credential.write_bytes(b"fixture-not-a-real-credential")
    registration_id = "keeper-provider:claude:v1:" + "1" * 32
    setup_id = "provider-registration-probe:" + "2" * 32

    class ExpectedEnvelope(RuntimeError):
        pass

    class Gateway:
        @staticmethod
        def status() -> dict[str, object]:
            return {
                "launch_journal": {"active_or_uncertain_launch_count": 0},
                "provider_bindings": [],
                "state": "READY",
                "user_binding": {
                    "profile_path": str(profile),
                    "session_id": 1,
                    "user_sid": "S-1-5-21-1000",
                },
            }

        @staticmethod
        def setup_workspace(value: str) -> Path:
            assert value == setup_id
            workspace = tmp_path / "setup"
            workspace.mkdir()
            return workspace

        @staticmethod
        def terminal_setup_result(**values: object) -> None:
            assert values == {
                "setup_id": setup_id,
                "operation": "REGISTER_PROBE",
                "provider_registration_id": registration_id,
                "challenge": "3" * 64,
            }
            return None

        @staticmethod
        def prepare_environment(
            nonce: str, executable_parent: Path, provider_registration_id: str
        ) -> dict[str, object]:
            assert len(nonce) == 32
            assert executable_parent == executable.parent
            assert provider_registration_id == registration_id
            return {"attestation": "fixture"}

        @staticmethod
        def build_setup_envelope(**values: Any) -> dict[str, object]:
            registration = values["registration"]
            assert registration["logical_provider_id"] == "claude"
            assert registration["subscription_account_binding"] == {
                "account_identity_digest": "DISCOVER",
                "authentication_method": "claude-ai-subscription",
                "plan_type": "pro",
            }
            assert values["operation"] == "REGISTER_PROBE"
            assert values["provider_registration_id"] == registration_id
            raise ExpectedEnvelope("captured exact Claude setup envelope")

    class ClientBinding:
        sid = "S-1-5-21-1000"
        session_id = 1
        profile_token = 84

        def revalidate(self, expected_sid: str) -> "ClientBinding":
            assert expected_sid == self.sid
            return self

        @contextmanager
        def duplicate_client_handle(
            self,
            handle: int,
            expected_sid: str,
            *,
            transfer_process: int,
        ) -> Iterator[int]:
            assert handle == 77
            assert expected_sid == self.sid
            assert transfer_process == 73
            yield 99

    service = ServiceProviderObserver(
        tmp_path / "provider-root",
        tmp_path / "evidence",
        "unused-provider-account",
        credential,
        "S-1-5-21-1000",
        provider_host_gateway=Gateway(),  # type: ignore[arg-type]
    )
    binding = ClientBinding()
    monkeypatch.setattr(service, "_client_token", lambda: 42)
    monkeypatch.setattr(service, "_client_process_binding", lambda: binding)
    monkeypatch.setattr(
        service,
        "_validated_client_profile",
        lambda client_token, profile_token, *, expected_sid: (
            {},
            str(profile),
            expected_sid,
            1,
        ),
    )
    monkeypatch.setattr(
        observer_module,
        "authenticated_client_profile_path",
        lambda token, value: str(profile),
    )

    @contextmanager
    def transfer_process(
        value: object, *, expected_sid: str
    ) -> Iterator[int]:
        assert value is binding
        assert expected_sid == binding.sid
        yield 73

    monkeypatch.setattr(
        observer_module,
        "authenticated_client_transfer_process",
        transfer_process,
    )
    monkeypatch.setattr(
        observer_module,
        "_measure_duplicated_reviewed_executable",
        lambda handle, path, expected_sha, expected_size, *, provider_id: (
            path,
            {
                "authenticode_binding": {"status": "Valid"},
                "canonical_path": str(path),
                "file_identity": {"size": expected_size},
                "sha256": expected_sha,
                "size": expected_size,
            },
        ),
    )

    with pytest.raises(ExpectedEnvelope, match="exact Claude setup envelope"):
        service._register_codex_through_host(
            provider_id="claude",
            executable=executable,
            client_sid=binding.sid,
            executive_capabilities=["security", "testing"],
            project_types=["software"],
            effort_levels=["medium", "high"],
            pricing_authority={"subscription_plan": "pro"},
            expected_executable_sha256=hashlib.sha256(
                executable.read_bytes()
            ).hexdigest(),
            expected_executable_size=executable.stat().st_size,
            expected_version="2.1.220 (Claude Code)",
            model_allowlist=[CLAUDE_PINNED_REVIEW_MODEL],
            model_revalidation_expires_at=(
                datetime.now(UTC) + timedelta(days=30)
            ).isoformat(),
            authentication_policy={"mode": "claude-ai-subscription"},
            usage_policy={"keeper_launch_budget": 20},
            client_executable_handle=77,
            planned_registration_id=registration_id,
            planned_setup_id=setup_id,
            planned_challenge="3" * 64,
            recovering_registration=True,
        )


def test_claude_predispatch_claim_resumes_same_identity_after_release_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keeper.authority_service.core as authority_core

    executable = (tmp_path / "claude.exe").resolve()
    executable.write_bytes(b"signed-claude-fixture")
    declaration = registration_declaration(
        expected_executable_sha256=hashlib.sha256(
            executable.read_bytes()
        ).hexdigest(),
        expected_executable_size=executable.stat().st_size,
        expected_version="2.1.220 (Claude Code)",
        subscription_plan="pro",
        keeper_launch_budget=20,
    )
    observed: dict[str, str] = {}

    class InitialObserver:
        @staticmethod
        def register_provider(
            provider_id: str,
            executable_path: Path,
            client_sid: str,
            **arguments: Any,
        ) -> dict[str, Any]:
            assert provider_id == "claude"
            assert executable_path == executable
            assert client_sid == "S-1-5-21-1000"
            assert arguments["recovering_registration"] is False
            observed["registration_id"] = arguments["planned_registration_id"]
            observed["setup_id"] = arguments["planned_setup_id"]
            observed["challenge"] = arguments["planned_challenge"]
            raise PermissionError("simulated pre-dispatch envelope rejection")

    monkeypatch.setattr(authority_core, "SERVICE_VERSION", "1.7.47")
    first_core = AuthorityServiceCore(
        tmp_path / "authority", observer=InitialObserver()  # type: ignore[arg-type]
    )
    first_client = AuthorityServiceClient(
        test_transport=lambda request: first_core.dispatch(
            request, "S-1-5-21-1000"
        )
    )
    with pytest.raises(PermissionError, match="pre-dispatch envelope"):
        first_client.register_provider("claude", executable, **declaration)
    claim = first_core.store.list_records("registrations")
    assert len(claim) == 1
    assert claim[0]["service_state"] == "REGISTRATION_STARTED"

    class ReachedRecoveredClaim(RuntimeError):
        pass

    class RestartedObserver:
        @staticmethod
        def register_provider(
            provider_id: str,
            executable_path: Path,
            client_sid: str,
            **arguments: Any,
        ) -> dict[str, Any]:
            assert provider_id == "claude"
            assert executable_path == executable
            assert client_sid == "S-1-5-21-1000"
            assert arguments["recovering_registration"] is True
            assert arguments["planned_registration_id"] == observed["registration_id"]
            assert arguments["planned_setup_id"] == observed["setup_id"]
            assert arguments["planned_challenge"] == observed["challenge"]
            raise ReachedRecoveredClaim("resumed exact durable Claude claim")

    monkeypatch.setattr(authority_core, "SERVICE_VERSION", "1.7.52")
    restarted_core = AuthorityServiceCore(
        tmp_path / "authority", observer=RestartedObserver()  # type: ignore[arg-type]
    )
    restarted_client = AuthorityServiceClient(
        test_transport=lambda request: restarted_core.dispatch(
            request, "S-1-5-21-1000"
        )
    )
    with pytest.raises(ReachedRecoveredClaim, match="exact durable Claude claim"):
        restarted_client.register_provider("claude", executable, **declaration)
    repeated_claim = restarted_core.store.list_records("registrations")
    assert len(repeated_claim) == 1
    assert repeated_claim[0]["service_state"] == "REGISTRATION_STARTED"
    assert repeated_claim[0]["start"]["registration_id"] == observed[
        "registration_id"
    ]


def _binding(provider_id: str, registration_id: str) -> dict[str, object]:
    return {
        "account_id": (
            "chatgpt-subscription:"
            if provider_id == "codex"
            else "claude-ai-subscription:"
        )
        + "a" * 64,
        "authenticode_binding": {
            "certificate_thumbprint": "A" * 40,
            "publisher_subject": "publisher",
            "source": "windows-authenticode",
            "status": "Valid",
        },
        "efforts": ["medium", "high"],
        "executable_path": rf"C:\reviewed\{provider_id}.exe",
        "executable_sha256": "b" * 64,
        "executable_size": 100,
        "file_identity": {
            "device_id": 1,
            "file_id": 2,
            "modified_ns": 3,
            "schema_version": 1,
            "size": 100,
        },
        "models": [
            CLAUDE_PINNED_REVIEW_MODEL
            if provider_id == "claude"
            else "gpt-5.6-sol"
        ],
        "provider_id": provider_id,
        "publisher": "publisher",
        "qualification_id": "provider-qualification:" + provider_id,
        "registration_id": registration_id,
        "session_id": provider_id + "-session",
        "version": "2.1.220 (Claude Code)"
        if provider_id == "claude"
        else "codex-cli 0.146.0",
    }


def test_provider_store_migrates_codex_and_adds_distinct_claude(
    tmp_path: Path,
) -> None:
    path = tmp_path / "provider-host.db"
    codex = _binding("codex", "keeper-provider:codex:v1:" + "1" * 32)
    serialized = json.dumps(codex, sort_keys=True, separators=(",", ":"))
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
            "INSERT INTO metadata(key,value) VALUES('schema_version','4');"
            "CREATE TABLE provider_binding(singleton INTEGER PRIMARY KEY,"
            "payload TEXT NOT NULL,payload_hash TEXT NOT NULL,updated_at TEXT NOT NULL);"
        )
        connection.execute(
            "INSERT INTO provider_binding VALUES(1,?,?,?)",
            (
                serialized,
                hashlib.sha256(serialized.encode()).hexdigest(),
                "2026-08-15T00:00:00+00:00",
            ),
        )
    store = ProviderHostStore(path)
    claude = _binding("claude", "keeper-provider:claude:v1:" + "2" * 32)
    store.bind_provider(claude)
    assert store.provider_bindings() == (claude, codex)
    assert store.provider_binding() == codex
    with pytest.raises(PermissionError, match="conflicts"):
        store.bind_provider(
            _binding("claude", "keeper-provider:claude:v1:" + "3" * 32)
        )


def test_claude_version_contract_matches_official_cli_shape() -> None:
    assert validate_claude_version_output("2.1.220 (Claude Code)") == (
        "2.1.220 (Claude Code)"
    )
    with pytest.raises(ValueError):
        validate_claude_version_output("2.1.220")
    with pytest.raises(ValueError):
        validate_claude_version_output("Claude 2.1.220")
    assert qualified_version_is_valid("claude", "controlled-provider 1.0")


def test_claude_registration_is_reviewer_only_and_contract_valid(
    tmp_path: Path,
) -> None:
    executable = (tmp_path / "claude.exe").resolve()
    executable.write_bytes(b"MZclaude")
    stat = executable.stat()
    now = datetime.now(UTC)
    signature = {
        "status": "Valid",
        "publisher_subject": "CN=Anthropic, PBC",
        "certificate_thumbprint": CLAUDE_AUTHENTICODE_THUMBPRINT,
        "source": "windows-authenticode",
    }
    identity = {
        "device_id": stat.st_dev,
        "file_id": stat.st_ino,
        "modified_ns": stat.st_mtime_ns,
        "schema_version": 1,
        "size": stat.st_size,
    }
    registration = create_provider_registration(
        "claude",
        executable,
        authorized_by="S-1-5-21-1000",
        executive_capabilities=["security", "testing"],
        project_types=["software"],
        effort_levels=["medium", "high"],
        pricing_authority={
            "pricing_identity": "founder-claude-pro",
            "pricing_version": "2026-08",
            "currency": "USD",
            "estimated_cost": 0,
            "maximum_cost": 0,
            "billing_unit": "claude-subscription",
            "included_plan": True,
            "marginally_free": False,
            "quoted_at": now.isoformat(),
            "expires_at": (now + timedelta(days=30)).isoformat(),
            "source": "FOUNDER_CONFIRMED_SUBSCRIPTION",
            "cost_tier": 0,
            "billing_mode": "included-subscription",
            "incremental_charge_authorized": False,
            "api_billing_authorized": False,
            "paid_fallback_authorized": False,
            "credit_purchase_authorized": False,
            "provider_switch_authorized": False,
            "account_switch_authorized": False,
            "capacity_bounded": True,
            "founder_confirmed": True,
            "subscription_plan": "pro",
        },
        expected_version="2.1.220 (Claude Code)",
        model_allowlist=[CLAUDE_PINNED_REVIEW_MODEL],
        model_revalidation_expires_at=(now + timedelta(days=30)).isoformat(),
        authentication_policy={
            "mode": "claude-ai-subscription",
            "identity_source": "authenticated-named-pipe-client",
            "session_selection": "authenticated-client-session-only",
            "profile_access": "restricted-user-profile",
            "setting_sources": "none",
            "api_keys_allowed": False,
            "credential_copy_allowed": False,
            "paid_fallback_allowed": False,
            "provider_switch_allowed": False,
        },
        windows_authentication_binding={
            "principal_sid": "S-1-5-21-1000",
            "windows_session_id": 1,
            "profile_identity": str(tmp_path.resolve()),
            "profile_digest": "d" * 64,
            "source": "authenticated-named-pipe-client-process",
        },
        usage_policy={
            "capacity_mode": "keeper-budget-only",
            "keeper_launch_budget": 20,
            "budget_window_seconds": 604800,
            "unknown_capacity_behavior": "fail-closed-at-keeper-budget",
            "reset_policy": "founder-reauthorization-only",
            "automatic_retry": False,
            "provider_switch": False,
            "account_switch": False,
            "api_fallback": False,
            "credit_purchase": False,
        },
        authenticode_binding=signature,
        subscription_account_binding={
            "authentication_method": "claude-ai-subscription",
            "plan_type": "pro",
            "account_identity_digest": "e" * 64,
            "source": "authority-verified-provider-host-probe",
            "observed_at": now.isoformat(),
        },
        model_capability_binding={
            "models": [
                {
                    "model_id": CLAUDE_PINNED_REVIEW_MODEL,
                    "supported_reasoning_efforts": ["medium", "high"],
                }
            ],
            "source": "authority-verified-provider-host-probe",
            "observed_at": now.isoformat(),
        },
        authority_executable_measurement={
            "authenticode_binding": signature,
            "canonical_path": str(executable),
            "file_identity": identity,
            "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "size": stat.st_size,
        },
        trusted_registration_id="keeper-provider:claude:v1:" + "6" * 32,
    )
    assert validate_provider_registration_contract(registration)[0] is True
    assert registration["registration_schema_version"] == 5
    assert registration["role_eligibility"] == ["post_repair_reviewer", "reviewer"]
    assert registration["capability_set"]["author"] is False
    assert registration["capability_set"]["repairer"] is False
    assert registration["capability_set"]["reviewer"] is True

    class ClaudeObserver:
        bind_calls = 0
        model_calls = 0

        @staticmethod
        def validate_registered_executable(
            value: dict[str, Any], client_executable_handle: int
        ) -> None:
            assert value["trusted_registration_id"] == registration[
                "trusted_registration_id"
            ]
            assert client_executable_handle > 0

        @staticmethod
        def qualification_identifier(
            value: dict[str, Any], planned_identifier: str
        ) -> str:
            assert value["logical_provider_id"] == "claude"
            return planned_identifier

        def qualify(
            self, value: dict[str, Any], challenge: str
        ) -> QualificationObservation:
            self.model_calls += 1
            command = build_claude_qualification_command(executable)
            return QualificationObservation(
                "claude-session:test",
                {
                    "executable": str(executable),
                    "executable_sha256": registration["executable_sha256"],
                    "integrity_level": "medium",
                    "job_confined": True,
                    "launch_nonce": challenge,
                    "restricted": True,
                },
                now.isoformat(),
                now.isoformat(),
                0,
                "2.1.220 (Claude Code)",
                None,
                {
                    "authentication_method": "claude-ai-subscription",
                    "plan_type": "pro",
                    "account_identity_digest": "e" * 64,
                    "models": [CLAUDE_PINNED_REVIEW_MODEL],
                    "model_capabilities": [
                        {
                            "model_id": CLAUDE_PINNED_REVIEW_MODEL,
                            "supported_reasoning_efforts": ["medium", "high"],
                        }
                    ],
                },
                {"capacity_known": False},
                {
                    "status": "ok",
                    "provider": "claude",
                    "effort": "medium",
                    "nonce": "keeper-claude-qualification-v1",
                },
                tuple(command),
                "a" * 64,
                "b" * 64,
            )

        def bind_qualified_provider(
            self, value: dict[str, Any], evidence: dict[str, Any]
        ) -> dict[str, Any]:
            self.bind_calls += 1
            return {
                "registration_id": value["trusted_registration_id"],
                "qualification_id": evidence["id"],
                "state": "QUALIFIED",
            }

    observer = ClaudeObserver()
    core = AuthorityServiceCore(
        tmp_path / "authority",
        observer=observer,  # type: ignore[arg-type]
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations",
        registration_id,
        "REGISTERED_UNQUALIFIED",
        registration,
    )
    client = AuthorityServiceClient(
        test_transport=lambda request: core.dispatch(
            request, "S-1-5-21-1000"
        )
    )
    qualified = client.qualify_provider(registration_id, executable)
    assert qualified["registration"]["registration_lifecycle"] == "QUALIFIED"
    assert qualified["qualification"]["schema_version"] == 4
    assert observer.model_calls == 1
    assert observer.bind_calls == 1


def test_claude_setup_uses_restricted_auth_and_one_schema_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"MZclaude")
    output_root = tmp_path / "setup"
    setup_id = "provider-qualification:" + "4" * 32
    workspace = output_root / hashlib.sha256(setup_id.encode()).hexdigest()
    workspace.mkdir(parents=True)
    account = parse_claude_auth_status(_auth())
    envelope: dict[str, Any] = {
        "account_binding": {
            name: account[name]
            for name in (
                "account_identity_digest",
                "authentication_method",
                "plan_type",
            )
        },
        "challenge": "challenge",
        "environment": {"tls_root_bundle": {}},
        "executable": {
            "path": str(executable),
            "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "version": "2.1.220 (Claude Code)",
        },
        "model_id": CLAUDE_PINNED_REVIEW_MODEL,
        "operation": "QUALIFY",
        "provider_id": "claude",
        "provider_registration_id": "keeper-provider:claude:v1:" + "5" * 32,
        "resource_limits": {
            "active_process_limit": 8,
            "memory_bytes": 1024,
            "stderr_bytes": 1024,
            "stdout_bytes": 4096,
            "timeout_seconds": 30,
        },
        "setup_id": setup_id,
        "user_binding": {"session_id": 1},
        "workspace": {"canonical_path": str(workspace.resolve())},
    }

    @contextmanager
    def fake_context(*args: object, **kwargs: object) -> Iterator[int]:
        del args, kwargs
        yield 73

    calls: list[list[str]] = []

    def fake_run(
        token: object, command: list[str], *args: object, **kwargs: object
    ) -> RestrictedProcessResult:
        del token
        calls.append(command)
        if command[-1] == "--version":
            args[6]({"pid": 100, "suspended": True})  # type: ignore[operator]
            kwargs["on_resumed"]({"pid": 100, "resumed": True})  # type: ignore[operator]
            output = "2.1.220 (Claude Code)"
        elif "auth" in command:
            output = _auth()
        else:
            output = json.dumps(
                {
                    "structured_output": {
                        "status": "ok",
                        "provider": "claude",
                        "effort": "medium",
                        "nonce": "keeper-claude-qualification-v1",
                    }
                }
            )
        return RestrictedProcessResult(
            100,
            0,
            output,
            "",
            str(executable),
            hashlib.sha256(executable.read_bytes()).hexdigest(),
            True,
            "medium",
            True,
            False,
        )

    monkeypatch.setattr(windows_process, "locked_executable", fake_context)
    monkeypatch.setattr(windows_process, "locked_tls_root_bundle", fake_context)
    monkeypatch.setattr(windows_process, "current_process_token", fake_context)
    monkeypatch.setattr(
        windows_process, "profile_restricted_primary_token", fake_context
    )
    monkeypatch.setattr(windows_process, "run_restricted_process", fake_run)
    result = CodexSetupRunner(output_root).run_setup(
        envelope,
        {"PATH": str(tmp_path)},
        threading.Event(),
        on_started=lambda value: None,
        on_resumed=lambda value: None,
    )
    assert result["exit_status"] == 0
    assert result["authentication_probe"] == account
    assert result["structured_output"] == {
        "status": "ok",
        "provider": "claude",
        "effort": "medium",
        "nonce": "keeper-claude-qualification-v1",
    }
    assert calls[1][1:] == [
        "--setting-sources=",
        "auth",
        "status",
        "--json",
    ]
    qualification = calls[2]
    assert qualification.count("-p") == 1
    assert "--strict-mcp-config" in qualification
    assert "--no-session-persistence" in qualification
    assert "ANTHROPIC_API_KEY" not in " ".join(qualification)


def test_provider_host_restart_preserves_distinct_codex_and_claude_bindings(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profile"
    setup_root = (
        profile
        / "AppData"
        / "Local"
        / "DarkSage"
        / "KeeperProviderExchange"
        / "setup"
    )
    setup_root.mkdir(parents=True)
    store = ProviderHostStore(tmp_path / "state" / "provider-host.db")
    codex = _binding("codex", "keeper-provider:codex:v1:" + "1" * 32)
    claude = _binding("claude", "keeper-provider:claude:v1:" + "2" * 32)
    store.bind_provider(codex)
    store.bind_provider(claude)
    user = UserBinding("S-1-5-21-1000", 1, str(profile.resolve()))
    authority = EnvelopeTestIdentity("authority-test", b"authority-test-key")
    host = EnvelopeTestIdentity("host-test", b"host-test-key")

    runtime = KeeperProviderHost(
        identity=HostIdentity("host-test", "authority-test", user),
        observed_binding=lambda: user,
        authority_verifier=authority,
        host_signer=host,
        store=ProviderHostStore(store.path),
        provider_binding=None,
        environment_attestation_key=b"environment-test-key",
        setup_workspace_root=setup_root,
    )

    assert runtime.start() == 0
    status = runtime.status()
    assert status["provider_binding"] == codex
    assert status["provider_bindings"] == [claude, codex]
    assert status["provider_state"] == "QUALIFIED"


def test_claude_provider_launch_returns_only_valid_structured_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"MZclaude")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    stdout = {
        "structured_output": {
            "status": "ok",
            "provider": "claude",
            "effort": "medium",
            "nonce": "review",
        }
    }

    @contextmanager
    def fake_context(*args: object, **kwargs: object) -> Iterator[int]:
        del args, kwargs
        yield 73

    def fake_run(
        token: object, command: list[str], *args: object, **kwargs: object
    ) -> RestrictedProcessResult:
        del token, command
        Path(str(args[3])).write_text(json.dumps(stdout), encoding="utf-8")
        Path(str(args[4])).write_text("", encoding="utf-8")
        args[6]({"pid": 100, "suspended": True})  # type: ignore[operator]
        kwargs["on_resumed"](  # type: ignore[operator]
            {"pid": 100, "resumed": True}
        )
        return RestrictedProcessResult(
            100,
            0,
            json.dumps(stdout),
            "",
            str(executable),
            hashlib.sha256(executable.read_bytes()).hexdigest(),
            True,
            "medium",
            True,
            False,
        )

    monkeypatch.setattr(windows_process, "locked_executable", fake_context)
    monkeypatch.setattr(windows_process, "locked_tls_root_bundle", fake_context)
    monkeypatch.setattr(windows_process, "current_process_token", fake_context)
    monkeypatch.setattr(
        windows_process, "profile_restricted_primary_token", fake_context
    )
    monkeypatch.setattr(windows_process, "run_restricted_process", fake_run)
    envelope = {
        "argv": ["--model", CLAUDE_PINNED_REVIEW_MODEL],
        "environment": {"tls_root_bundle": {}},
        "executable": {"path": str(executable)},
        "launch_id": "launch-claude",
        "provider_id": "claude",
        "resource_limits": {
            "active_process_limit": 8,
            "memory_bytes": 1024,
            "stderr_bytes": 1024,
            "stdout_bytes": 4096,
            "timeout_seconds": 30,
        },
        "workspace": {"canonical_path": str(workspace.resolve())},
    }
    launcher = ProviderProcessLauncher(tmp_path / "output")
    result = launcher.launch(
        envelope,
        {"PATH": str(tmp_path)},
        threading.Event(),
        on_started=lambda value: None,
        on_resumed=lambda value: None,
    )
    assert result["structured_output"] == stdout["structured_output"]

    stdout.clear()
    with pytest.raises(PermissionError, match="structured output"):
        launcher.launch(
            envelope,
            {"PATH": str(tmp_path)},
            threading.Event(),
            on_started=lambda value: None,
            on_resumed=lambda value: None,
        )
