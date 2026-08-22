from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest

from keeper.authority_service import service_install, service_main
from keeper.authority_service.core import AuthorityServiceCore, SERVICE_VERSION
from keeper.authority_service.process_security import (
    ProcessSecurityError,
    ProcessSecurityStage,
)
from keeper.authority_service.protocol import PROTOCOL_VERSION
from keeper.authority_service.store import SERVICE_SCHEMA_VERSION
from keeper.provider_host import signing


SID = "S-1-5-21-1000"


def test_recovery_release_keeps_protocol_and_schema_stable() -> None:
    assert SERVICE_VERSION == "1.7.51"
    assert PROTOCOL_VERSION == 7
    assert SERVICE_SCHEMA_VERSION == 6


def test_provider_host_identity_failure_leaves_core_available_and_fails_closed(
    tmp_path: Path,
) -> None:
    core = AuthorityServiceCore(tmp_path / "authority")

    def fail() -> None:
        raise OSError(5, "synthetic machine CNG access denied")

    worker = service_main._start_provider_host_initialization(core, fail)
    worker.join(timeout=5)

    assert not worker.is_alive()
    diagnostics = core._diagnostics({}, SID)
    assert diagnostics["service_version"] == "1.7.51"
    assert diagnostics["schema_version"] == 6
    assert diagnostics["provider_host"] == {
        "installed": False,
        "online": False,
        "state": "UNAVAILABLE",
        "protocol_compatible": False,
        "provider_state": "UNAVAILABLE",
        "failure_reason": "IDENTITY_INITIALIZATION_FAILED",
        "qualification_reconciliation_required": False,
        "qualification_reconciliation_count": 0,
        "qualification_reconciliation_registration_ids": [],
        "active_launch_count": None,
        "active_or_uncertain_launch_count": None,
        "launch_state_proven": False,
        "launches": [],
        "uncertain_launch_count": None,
        "launch_reconciliation_pending_count": 0,
        "launch_reconciliation_pending_launches": [],
        "registration_recovery_pending_count": 0,
        "registration_recovery_ids": [],
        "registration_failure_disposition_pending_count": 0,
        "registration_failure_disposition_ids": [],
        "registration_retry_authorized_count": 0,
        "registration_retry_authorized_ids": [],
        "registration_replacement_authorized_count": 0,
        "registration_replacement_authorized_ids": [],
        "qualification_recovery_pending_count": 0,
        "qualification_recovery_ids": [],
        "qualification_retry_authorized_count": 0,
        "qualification_retry_authorized_ids": [],
    }
    with pytest.raises(PermissionError, match="not configured"):
        core._provider_host_enrollment_status({}, SID)


def test_enrolled_offline_diagnostics_preserve_sanitized_live_failure(
    tmp_path: Path,
) -> None:
    core = AuthorityServiceCore(tmp_path / "authority")

    class Enrollment:
        def status(self) -> dict[str, object]:
            return {
                "installed": True,
                "online": False,
                "state": "ENROLLED_OFFLINE",
                "provider_state": "UNAVAILABLE",
            }

        def pending_launch_reconciliations(self) -> list[dict[str, object]]:
            return []

    class Observer:
        def provider_host_status(self) -> dict[str, object]:
            return {
                "installed": True,
                "online": False,
                "state": "OFFLINE",
                "provider_state": "UNAVAILABLE",
                "failure_reason": (
                    "ProviderHostIdentityUncertain:IDENTITY_MEASUREMENT_TIMEOUT"
                ),
                "founder_action_required": "START_OR_REPAIR_PROVIDER_HOST",
            }

    core.provider_host_enrollment = Enrollment()  # type: ignore[assignment]
    core.observer = Observer()  # type: ignore[assignment]

    diagnostics = core._diagnostics({}, SID)["provider_host"]

    assert diagnostics["state"] == "ENROLLED_OFFLINE"
    assert diagnostics["online"] is False
    assert diagnostics["failure_reason"] == (
        "ProviderHostIdentityUncertain:IDENTITY_MEASUREMENT_TIMEOUT"
    )
    assert diagnostics["founder_action_required"] == (
        "START_OR_REPAIR_PROVIDER_HOST"
    )


def test_service_reports_running_before_provider_host_cng_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "service.json"
    config.write_text("{}", encoding="utf-8")
    statuses: list[int] = []
    initialized = threading.Event()
    failed = threading.Event()

    class Core:
        def begin_provider_host_initialization(self) -> None:
            assert statuses[-1] == service_main._SERVICE_RUNNING

        def fail_provider_host_initialization(self, reason: str) -> None:
            assert reason == "IDENTITY_INITIALIZATION_FAILED"
            failed.set()

    class Server:
        core = Core()

        def serve_forever(self) -> None:
            assert initialized.wait(5)
            assert failed.wait(5)

    class Api:
        def RegisterServiceCtrlHandlerExW(self, *_: object) -> int:
            return 1

    def initialize() -> None:
        assert threading.current_thread().name == (
            "keeper-authority-provider-host-init"
        )
        assert statuses[-1] == service_main._SERVICE_RUNNING
        initialized.set()
        raise OSError(5, "synthetic machine CNG access denied")

    monkeypatch.setattr(service_main, "_advapi32", lambda: Api())
    monkeypatch.setattr(
        service_main,
        "account_sid",
        lambda account: "S-1-5-80-1-2-3-4-5",
    )
    monkeypatch.setattr(
        service_main,
        "ensure_current_process_service_query_access",
        lambda service_sid: None,
    )
    monkeypatch.setattr(
        service_main,
        "_build_service_server",
        lambda _: (Server(), initialize),
    )
    service = service_main.AuthorityWindowsService(config)
    monkeypatch.setattr(
        service,
        "_set_status",
        lambda state, **_: statuses.append(state),
    )

    service._service_main(0, None)

    assert statuses == [
        service_main._SERVICE_START_PENDING,
        service_main._SERVICE_RUNNING,
        service_main._SERVICE_STOPPED,
    ]


def test_service_process_query_grant_precedes_server_and_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "service.json"
    config.write_text("{}", encoding="utf-8")
    events: list[str] = []
    statuses: list[int] = []

    class Api:
        def RegisterServiceCtrlHandlerExW(self, *_: object) -> int:
            return 1

    class Server:
        core = object()

        def serve_forever(self) -> None:
            events.append("serve")

    monkeypatch.setattr(service_main, "_advapi32", lambda: Api())
    def resolve_service_sid(account: str) -> str:
        del account
        events.append("resolve-service-sid")
        return "S-1-5-80-1-2-3-4-5"

    monkeypatch.setattr(service_main, "account_sid", resolve_service_sid)
    monkeypatch.setattr(
        service_main,
        "ensure_current_process_service_query_access",
        lambda sid: events.append(f"process-dacl:{sid}"),
    )

    def build_server(path: Path) -> tuple[Server, None]:
        del path
        events.append("build-server")
        return Server(), None

    monkeypatch.setattr(
        service_main,
        "_build_service_server",
        build_server,
    )
    service = service_main.AuthorityWindowsService(config)
    monkeypatch.setattr(
        service,
        "_set_status",
        lambda state, **kwargs: statuses.append(state),
    )

    service._service_main(0, None)

    assert events == [
        "resolve-service-sid",
        "process-dacl:S-1-5-80-1-2-3-4-5",
        "build-server",
        "serve",
    ]
    assert statuses == [
        service_main._SERVICE_START_PENDING,
        service_main._SERVICE_RUNNING,
        service_main._SERVICE_STOPPED,
    ]


def test_service_process_query_grant_failure_stops_before_server_or_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "service.json"
    config.write_text("{}", encoding="utf-8")
    statuses: list[tuple[int, int, int]] = []
    built: list[bool] = []

    class Api:
        def RegisterServiceCtrlHandlerExW(self, *_: object) -> int:
            return 1

    monkeypatch.setattr(service_main, "_advapi32", lambda: Api())
    monkeypatch.setattr(
        service_main,
        "account_sid",
        lambda account: "S-1-5-80-1-2-3-4-5",
    )
    monkeypatch.setattr(
        service_main,
        "ensure_current_process_service_query_access",
        lambda sid: (_ for _ in ()).throw(
            ProcessSecurityError(
                ProcessSecurityStage.READ_DESCRIPTOR,
                "synthetic process DACL mismatch",
            )
        ),
    )
    def forbidden_build(path: Path) -> tuple[object, None]:
        del path
        built.append(True)
        return object(), None

    monkeypatch.setattr(service_main, "_build_service_server", forbidden_build)
    service = service_main.AuthorityWindowsService(config)
    monkeypatch.setattr(
        service,
        "_set_status",
        lambda state, **kwargs: statuses.append(
            (
                state,
                int(kwargs.get("win32_exit", 0)),
                int(kwargs.get("service_exit", 0)),
            )
        ),
    )

    service._service_main(0, None)

    assert built == []
    assert statuses == [
        (service_main._SERVICE_START_PENDING, 0, 0),
        (
            service_main._SERVICE_STOPPED,
            service_main._ERROR_SERVICE_SPECIFIC_ERROR,
            service_main._PROCESS_SECURITY_SERVICE_EXIT[
                ProcessSecurityStage.READ_DESCRIPTOR
            ],
        ),
    ]


@pytest.mark.parametrize("stage", list(ProcessSecurityStage))
def test_process_security_startup_stage_has_stable_sanitized_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: ProcessSecurityStage,
) -> None:
    config = tmp_path / "service.json"
    config.write_text("{}", encoding="utf-8")
    statuses: list[tuple[int, int, int]] = []

    class Api:
        def RegisterServiceCtrlHandlerExW(self, *_: object) -> int:
            return 1

    monkeypatch.setattr(service_main, "_advapi32", lambda: Api())
    monkeypatch.setattr(
        service_main,
        "account_sid",
        lambda account: "S-1-5-80-1-2-3-4-5",
    )
    monkeypatch.setattr(
        service_main,
        "ensure_current_process_service_query_access",
        lambda sid: (_ for _ in ()).throw(
            ProcessSecurityError(stage, "sensitive synthetic detail")
        ),
    )
    monkeypatch.setattr(
        service_main,
        "_build_service_server",
        lambda path: pytest.fail("server build must not run"),
    )
    service = service_main.AuthorityWindowsService(config)
    monkeypatch.setattr(
        service,
        "_set_status",
        lambda state, **kwargs: statuses.append(
            (
                state,
                int(kwargs.get("win32_exit", 0)),
                int(kwargs.get("service_exit", 0)),
            )
        ),
    )

    service._service_main(0, None)

    assert statuses[-1] == (
        service_main._SERVICE_STOPPED,
        service_main._ERROR_SERVICE_SPECIFIC_ERROR,
        service_main._PROCESS_SECURITY_SERVICE_EXIT[stage],
    )
    assert len(set(service_main._PROCESS_SECURITY_SERVICE_EXIT.values())) == len(
        ProcessSecurityStage
    )
    assert all(
        0 < value <= 0xFFFFFFFF
        for value in service_main._PROCESS_SECURITY_SERVICE_EXIT.values()
    )


def test_unrelated_startup_failure_retains_generic_service_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "service.json"
    config.write_text("{}", encoding="utf-8")
    statuses: list[tuple[int, int, int]] = []

    class Api:
        def RegisterServiceCtrlHandlerExW(self, *_: object) -> int:
            return 1

    monkeypatch.setattr(service_main, "_advapi32", lambda: Api())
    monkeypatch.setattr(
        service_main,
        "account_sid",
        lambda account: (_ for _ in ()).throw(RuntimeError("synthetic")),
    )
    service = service_main.AuthorityWindowsService(config)
    monkeypatch.setattr(
        service,
        "_set_status",
        lambda state, **kwargs: statuses.append(
            (
                state,
                int(kwargs.get("win32_exit", 0)),
                int(kwargs.get("service_exit", 0)),
            )
        ),
    )

    service._service_main(0, None)

    assert statuses[-1] == (service_main._SERVICE_STOPPED, 1064, 0)


def test_service_status_persists_only_sanitized_process_stage_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "service.json"
    config.write_text("{}", encoding="utf-8")
    observed: list[service_main._ServiceStatus] = []

    class Api:
        def SetServiceStatus(self, handle: int, pointer: object) -> bool:
            assert handle == 7
            source = pointer._obj  # type: ignore[attr-defined]
            observed.append(
                service_main._ServiceStatus(
                    *(
                        int(getattr(source, name))
                        for name, _ in service_main._ServiceStatus._fields_
                    )
                )
            )
            return True

    monkeypatch.setattr(service_main, "_advapi32", lambda: Api())
    service = service_main.AuthorityWindowsService(config)
    service.status_handle = 7
    code = service_main._PROCESS_SECURITY_SERVICE_EXIT[
        ProcessSecurityStage.READ_DESCRIPTOR
    ]

    service._set_status(
        service_main._SERVICE_STOPPED,
        win32_exit=service_main._ERROR_SERVICE_SPECIFIC_ERROR,
        service_exit=code,
    )

    assert len(observed) == 1
    assert observed[0].dwCurrentState == service_main._SERVICE_STOPPED
    assert (
        observed[0].dwWin32ExitCode
        == service_main._ERROR_SERVICE_SPECIFIC_ERROR
    )
    assert observed[0].dwServiceSpecificExitCode == code
    assert observed[0].dwControlsAccepted == 0
    assert observed[0].dwCheckPoint == 0
    assert observed[0].dwWaitHint == 0


def test_schema_five_upgrade_preserves_counts_and_service_key(
    tmp_path: Path,
) -> None:
    root = tmp_path / "authority"
    first = AuthorityServiceCore(root)
    for index in range(8):
        registration_id = f"registration-{index}"
        first.store.insert(
            "registrations",
            registration_id,
            "SYNTHETIC",
            {"synthetic": True, "index": index},
        )
        first.store.insert(
            "qualifications",
            f"qualification-{index}",
            "SYNTHETIC",
            {"synthetic": True, "index": index},
            registration_id=registration_id,
            challenge=f"qualification-challenge-{index}",
        )
    for index in range(2):
        first.store.insert(
            "attempts",
            f"attempt-{index}",
            "SYNTHETIC",
            {
                "synthetic": True,
                "index": index,
                "project_id": f"project-{index}",
            },
            registration_id=f"registration-{index}",
            challenge=f"attempt-challenge-{index}",
            run_id=f"run-{index}",
            attempt_number=1,
        )
    key_id = first.keys.current_key_id
    with sqlite3.connect(root / "authority.db") as connection:
        connection.execute(
            "UPDATE service_meta SET value='5' WHERE key='schema_version'"
        )
        connection.commit()

    recovered = AuthorityServiceCore(root)
    assert recovered.keys.current_key_id == key_id
    assert len(recovered.store.list_records("registrations")) == 8
    assert len(recovered.store.list_records("qualifications")) == 8
    assert len(recovered.store.list_records("attempts")) == 2
    assert recovered.store.schema_identity()["schema_version"] == 6


def test_machine_key_policy_is_exact_and_restricted_first() -> None:
    access = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-123")
    assert signing._machine_key_security_sddl(access) == (
        "O:S-1-5-32-544G:S-1-5-32-544D:P(D;;GA;;;S-1-5-12)"
        "(A;;GA;;;S-1-5-18)"
        "(A;;GA;;;S-1-5-32-544)"
        "(A;;GA;;;S-1-5-80-123)"
    )
    with pytest.raises(ValueError, match="policy"):
        signing._machine_key_security_sddl(())
    with pytest.raises(ValueError, match="policy"):
        signing._machine_key_security_sddl(("S-1-5-18", "S-1-5-18"))


def test_runtime_machine_key_open_never_creates_missing_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        signing, "_validate_machine_storage_provider", lambda *_: None
    )

    class Api:
        def NCryptOpenStorageProvider(self, *_: object) -> int:
            calls.append("open-provider")
            return 0

        def NCryptOpenKey(self, *_: object) -> int:
            calls.append("open-key")
            return 0x80090016

        def NCryptCreatePersistedKey(self, *_: object) -> int:
            calls.append("create-key")
            return 0

        def NCryptFreeObject(self, *_: object) -> int:
            calls.append("free")
            return 0

    with pytest.raises(PermissionError, match="not provisioned"):
        signing._open_key(
            Api(),
            "DarkSage.KeeperAuthority.ProviderHost.v1",
            machine_key=True,
            owner_sid=None,
            create_if_missing=False,
        )
    assert calls == ["open-provider", "open-key", "free"]


def test_elevated_provisioning_is_durable_idempotent_and_mismatch_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    persisted: list[dict[str, Any]] = []
    signer_calls: list[dict[str, object]] = []
    provisioned = False

    class Signer:
        key_id = "keeper-provider-host-rsa:synthetic"

        def __init__(self, **values: object) -> None:
            nonlocal provisioned
            signer_calls.append(dict(values))
            assert values["identity"] == (
                "keeper-authority-provider-host:provisioned"
            )
            assert values["key_name"] == (
                service_install.PROVIDER_HOST_AUTHORITY_KEY_NAME
            )
            assert values["machine_key"] is True
            if not values["create_if_missing"] and not provisioned:
                raise service_install.ProviderHostCngKeyNotProvisioned(
                    "synthetic identity is absent"
                )
            if values["create_if_missing"]:
                provisioned = True

        def public_configuration(self) -> dict[str, object]:
            return {
                "schema_version": 1,
                "identity": "keeper-authority-provider-host:provisioned",
                "key_id": self.key_id,
                "algorithm": "RSA-PKCS1-SHA256",
                "exponent": "AQAB",
                "modulus": "synthetic",
            }

    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    monkeypatch.setattr(service_install, "WindowsCngEnvelopeIdentity", Signer)
    monkeypatch.setattr(
        service_install,
        "_persist_manifest",
        lambda value: persisted.append(json.loads(json.dumps(value))),
    )
    manifest: dict[str, Any] = {}

    first = service_install._provision_provider_host_authority_identity(manifest)
    second = service_install._provision_provider_host_authority_identity(manifest)

    assert first == second
    assert len(persisted) == 3
    assert signer_calls[0]["create_if_missing"] is False
    assert signer_calls[1]["create_if_missing"] is True
    assert signer_calls[1]["machine_access_sids"] == (
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-123",
    )
    assert signer_calls[1].get("reconcile_interrupted_machine_key") is None
    assert signer_calls[2]["create_if_missing"] is False
    assert signer_calls[2]["machine_access_sids"] == (
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-123",
    )
    manifest["provider_host_authority_identity"] = {"changed": True}
    with pytest.raises(PermissionError, match="differs"):
        service_install._provision_provider_host_authority_identity(manifest)
    assert len(signer_calls) == 3


def test_provider_host_authority_identity_verification_is_exact_and_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    access_sids = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-123")
    public = {
        "schema_version": 1,
        "identity": "keeper-authority-provider-host:provisioned",
        "key_id": "keeper-provider-host-rsa:synthetic",
        "algorithm": "RSA-PKCS1-SHA256",
        "exponent": "AQAB",
        "modulus": "synthetic",
    }
    record = {
        "schema_version": 1,
        "key_name": service_install.PROVIDER_HOST_AUTHORITY_KEY_NAME,
        "key_id": "keeper-provider-host-rsa:synthetic",
        "public_identity": public,
        "access_sids": list(access_sids),
        "security_policy_sha256": "A" * 64,
    }
    signer_calls: list[dict[str, object]] = []

    class Signer:
        key_id = "keeper-provider-host-rsa:synthetic"

        def __init__(self, **values: object) -> None:
            signer_calls.append(dict(values))

        def public_configuration(self) -> dict[str, object]:
            return dict(public)

    monkeypatch.setattr(service_install, "_require_admin", lambda: None)
    monkeypatch.setattr(service_install, "account_sid", lambda _: access_sids[-1])
    monkeypatch.setattr(
        service_install,
        "machine_key_security_policy_sha256",
        lambda _: "A" * 64,
    )
    monkeypatch.setattr(
        service_install,
        "_load_completed_manifest",
        lambda: {"provider_host_authority_identity": record},
    )
    monkeypatch.setattr(service_install, "WindowsCngEnvelopeIdentity", Signer)
    monkeypatch.setattr(
        service_install,
        "_persist_manifest",
        lambda _: pytest.fail("read-only verification persisted the manifest"),
    )

    result = service_install.verify_provider_host_authority_identity()

    assert result == {"verified": True, **record}
    assert signer_calls == [
        {
            "identity": "keeper-authority-provider-host:provisioned",
            "key_name": service_install.PROVIDER_HOST_AUTHORITY_KEY_NAME,
            "machine_key": True,
            "create_if_missing": False,
            "machine_access_sids": access_sids,
        }
    ]


@pytest.mark.parametrize(
    "manifest",
    [
        {},
        {"provider_host_authority_identity": {"changed": True}},
        {
            "provider_host_authority_identity": {},
            "provider_host_authority_identity_claim": {"state": "CLAIMED"},
        },
    ],
)
def test_provider_host_authority_identity_verification_rejects_untrusted_state(
    monkeypatch: pytest.MonkeyPatch, manifest: dict[str, object]
) -> None:
    monkeypatch.setattr(service_install, "_require_admin", lambda: None)
    monkeypatch.setattr(
        service_install, "_load_completed_manifest", lambda: manifest
    )
    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    with pytest.raises(PermissionError, match="identity"):
        service_install.verify_provider_host_authority_identity()


def test_provider_host_authority_identity_verification_rejects_live_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    access_sids = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-123")
    record = {
        "schema_version": 1,
        "key_name": service_install.PROVIDER_HOST_AUTHORITY_KEY_NAME,
        "key_id": "keeper-provider-host-rsa:recorded",
        "public_identity": {"key_id": "keeper-provider-host-rsa:recorded"},
        "access_sids": list(access_sids),
        "security_policy_sha256": "A" * 64,
    }

    class Signer:
        key_id = "keeper-provider-host-rsa:different"

        def __init__(self, **_: object) -> None:
            pass

        def public_configuration(self) -> dict[str, object]:
            return {"key_id": self.key_id}

    monkeypatch.setattr(service_install, "_require_admin", lambda: None)
    monkeypatch.setattr(service_install, "account_sid", lambda _: access_sids[-1])
    monkeypatch.setattr(
        service_install,
        "machine_key_security_policy_sha256",
        lambda _: "A" * 64,
    )
    monkeypatch.setattr(
        service_install,
        "_load_completed_manifest",
        lambda: {"provider_host_authority_identity": record},
    )
    monkeypatch.setattr(service_install, "WindowsCngEnvelopeIdentity", Signer)

    with pytest.raises(PermissionError, match="differs"):
        service_install.verify_provider_host_authority_identity()


def test_interrupted_identity_claim_reconciles_once_and_clears(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    persisted: list[dict[str, Any]] = []
    signer_calls: list[dict[str, object]] = []

    class Signer:
        key_id = "keeper-provider-host-rsa:synthetic"

        def __init__(self, **values: object) -> None:
            signer_calls.append(dict(values))

        def public_configuration(self) -> dict[str, object]:
            return {
                "schema_version": 1,
                "identity": "keeper-authority-provider-host:provisioned",
                "key_id": self.key_id,
                "algorithm": "RSA-PKCS1-SHA256",
                "exponent": "AQAB",
                "modulus": "synthetic",
            }

    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    monkeypatch.setattr(service_install, "WindowsCngEnvelopeIdentity", Signer)
    monkeypatch.setattr(
        service_install,
        "_persist_manifest",
        lambda value: persisted.append(json.loads(json.dumps(value))),
    )
    access_sids = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-123")
    manifest: dict[str, Any] = {
        "provider_host_authority_identity_claim": {
            **service_install._provider_host_authority_identity_claim(
                access_sids
            ),
            "claimed_at": "2026-08-03T00:00:00+00:00",
        }
    }

    result = service_install._provision_provider_host_authority_identity(
        manifest
    )

    assert result["key_id"] == "keeper-provider-host-rsa:synthetic"
    assert "provider_host_authority_identity_claim" not in manifest
    assert signer_calls == [
        {
            "identity": "keeper-authority-provider-host:provisioned",
            "key_name": service_install.PROVIDER_HOST_AUTHORITY_KEY_NAME,
            "machine_key": True,
            "create_if_missing": True,
            "machine_access_sids": access_sids,
            "reconcile_interrupted_machine_key": True,
        }
    ]
    assert persisted[-1].get("provider_host_authority_identity") == result


def test_mismatched_unclaimed_identity_fails_without_creating_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Signer:
        def __init__(self, **_values: object) -> None:
            raise PermissionError("synthetic policy mismatch")

    persisted: list[dict[str, Any]] = []
    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    monkeypatch.setattr(service_install, "WindowsCngEnvelopeIdentity", Signer)
    monkeypatch.setattr(
        service_install,
        "_persist_manifest",
        lambda value: persisted.append(json.loads(json.dumps(value))),
    )
    manifest: dict[str, Any] = {}

    with pytest.raises(PermissionError, match="policy mismatch"):
        service_install._provision_provider_host_authority_identity(manifest)

    assert "provider_host_authority_identity_claim" not in manifest
    assert persisted == []


def test_identity_record_and_claim_are_rejected_as_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    access_sids = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-123")
    manifest: dict[str, Any] = {
        "provider_host_authority_identity": {
            "schema_version": 1,
            "key_name": service_install.PROVIDER_HOST_AUTHORITY_KEY_NAME,
            "key_id": "keeper-provider-host-rsa:synthetic",
            "public_identity": {},
            "access_sids": list(access_sids),
            "security_policy_sha256": (
                service_install.machine_key_security_policy_sha256(access_sids)
            ),
        },
        "provider_host_authority_identity_claim": {
            **service_install._provider_host_authority_identity_claim(
                access_sids
            ),
            "claimed_at": "2026-08-03T00:00:00+00:00",
        },
    }

    with pytest.raises(PermissionError, match="lifecycle is ambiguous"):
        service_install._provision_provider_host_authority_identity(manifest)


def test_changed_identity_claim_rejects_before_key_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer_called = False

    class Signer:
        def __init__(self, **_values: object) -> None:
            nonlocal signer_called
            signer_called = True

    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    monkeypatch.setattr(service_install, "WindowsCngEnvelopeIdentity", Signer)
    access_sids = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-123")
    claim = service_install._provider_host_authority_identity_claim(access_sids)
    claim["security_policy_sha256"] = "0" * 64
    manifest: dict[str, Any] = {
        "provider_host_authority_identity_claim": {
            **claim,
            "claimed_at": "2026-08-03T00:00:00+00:00",
        }
    }

    with pytest.raises(PermissionError, match="identity claim differs"):
        service_install._provision_provider_host_authority_identity(manifest)

    assert signer_called is False


def test_unclaimed_legacy_orphan_is_publicly_bound_before_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    persisted: list[dict[str, Any]] = []
    calls: list[dict[str, object]] = []
    public = signing._public_configuration(
        "keeper-authority-provider-host:provisioned",
        b"\x80" + b"\x00" * 383,
        b"\x03",
    )

    class Signer:
        recoverable_legacy_policy_sha256: str | None = None

        def __init__(self, **values: object) -> None:
            calls.append(dict(values))
            self.key_id = str(public["key_id"])
            if values.get("inspect_recoverable_legacy_machine_key") is True:
                self.recoverable_legacy_policy_sha256 = "A" * 64
            elif values.get("reconcile_interrupted_machine_key") is not True:
                raise service_install.ProviderHostCngPolicyMismatch(
                    "synthetic primary-group gap"
                )

        def public_configuration(self) -> dict[str, object]:
            return dict(public)

    service_install.RsaPublicIdentity.from_configuration(public)
    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    monkeypatch.setattr(service_install, "WindowsCngEnvelopeIdentity", Signer)
    monkeypatch.setattr(
        service_install,
        "_persist_manifest",
        lambda value: persisted.append(json.loads(json.dumps(value))),
    )
    manifest: dict[str, Any] = {}

    result = service_install._provision_provider_host_authority_identity(
        manifest
    )

    assert result["key_id"] == public["key_id"]
    claim_snapshot = persisted[-2]["provider_host_authority_identity_claim"]
    assert claim_snapshot["operation"] == (
        "RECONCILE_LEGACY_1_7_3_PRIMARY_GROUP"
    )
    assert claim_snapshot["observed_key_id"] == public["key_id"]
    assert claim_snapshot["observed_public_identity"] == public
    assert claim_snapshot["observed_policy_sha256"] == "A" * 64
    assert "provider_host_authority_identity_claim" not in persisted[-1]
    assert calls[0]["create_if_missing"] is False
    assert calls[1]["inspect_recoverable_legacy_machine_key"] is True
    assert calls[2]["create_if_missing"] is False
    assert calls[2].get("reconcile_interrupted_machine_key") is None
    assert calls[3]["inspect_recoverable_legacy_machine_key"] is True
    assert calls[4]["create_if_missing"] is False
    assert calls[4]["reconcile_interrupted_machine_key"] is True


def test_legacy_reconciliation_rejects_public_identity_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = signing._public_configuration(
        "keeper-authority-provider-host:provisioned",
        b"\x80" + b"\x00" * 383,
        b"\x03",
    )
    changed = {**observed, "identity": "changed"}
    access_sids = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-123")
    manifest: dict[str, Any] = {
        "provider_host_authority_identity_claim": {
            **service_install._provider_host_authority_identity_claim(
                access_sids,
                operation="RECONCILE_LEGACY_1_7_3_PRIMARY_GROUP",
                observed_key_id=str(observed["key_id"]),
                observed_public_identity=observed,
                observed_policy_sha256="A" * 64,
            ),
            "claimed_at": "2026-08-03T00:00:00+00:00",
        }
    }

    class Signer:
        key_id = observed["key_id"]

        def __init__(self, **_values: object) -> None:
            pass

        def public_configuration(self) -> dict[str, object]:
            return dict(changed)

    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    monkeypatch.setattr(service_install, "WindowsCngEnvelopeIdentity", Signer)

    with pytest.raises(PermissionError, match="changed before reconciliation"):
        service_install._provision_provider_host_authority_identity(manifest)


def test_persisted_legacy_claim_resumes_idempotently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public = signing._public_configuration(
        "keeper-authority-provider-host:provisioned",
        b"\x80" + b"\x00" * 383,
        b"\x03",
    )
    access_sids = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-123")
    manifest: dict[str, Any] = {
        "provider_host_authority_identity_claim": {
            **service_install._provider_host_authority_identity_claim(
                access_sids,
                operation="RECONCILE_LEGACY_1_7_3_PRIMARY_GROUP",
                observed_key_id=str(public["key_id"]),
                observed_public_identity=public,
                observed_policy_sha256="A" * 64,
            ),
            "claimed_at": "2026-08-03T00:00:00+00:00",
        }
    }
    calls: list[dict[str, object]] = []

    class Signer:
        key_id = public["key_id"]
        recoverable_legacy_policy_sha256: str | None = None

        def __init__(self, **values: object) -> None:
            calls.append(dict(values))
            if values.get("inspect_recoverable_legacy_machine_key") is True:
                self.recoverable_legacy_policy_sha256 = "A" * 64
            elif values.get("reconcile_interrupted_machine_key") is not True:
                raise service_install.ProviderHostCngPolicyMismatch(
                    "synthetic primary-group gap"
                )

        def public_configuration(self) -> dict[str, object]:
            return dict(public)

    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    monkeypatch.setattr(service_install, "WindowsCngEnvelopeIdentity", Signer)
    monkeypatch.setattr(service_install, "_persist_manifest", lambda _value: None)

    result = service_install._provision_provider_host_authority_identity(
        manifest
    )

    assert result["key_id"] == public["key_id"]
    assert "provider_host_authority_identity_claim" not in manifest
    assert len(calls) == 3
    assert calls[0]["create_if_missing"] is False
    assert calls[0].get("reconcile_interrupted_machine_key") is None
    assert calls[1]["inspect_recoverable_legacy_machine_key"] is True
    assert calls[2]["create_if_missing"] is False
    assert calls[2]["reconcile_interrupted_machine_key"] is True


def test_persisted_legacy_claim_rejects_policy_change_before_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public = signing._public_configuration(
        "keeper-authority-provider-host:provisioned",
        b"\x80" + b"\x00" * 383,
        b"\x03",
    )
    access_sids = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-123")
    manifest: dict[str, Any] = {
        "provider_host_authority_identity_claim": {
            **service_install._provider_host_authority_identity_claim(
                access_sids,
                operation="RECONCILE_LEGACY_1_7_3_PRIMARY_GROUP",
                observed_key_id=str(public["key_id"]),
                observed_public_identity=public,
                observed_policy_sha256="A" * 64,
            ),
            "claimed_at": "2026-08-03T00:00:00+00:00",
        }
    }
    calls: list[dict[str, object]] = []

    class Signer:
        key_id = public["key_id"]
        recoverable_legacy_policy_sha256: str | None = None

        def __init__(self, **values: object) -> None:
            calls.append(dict(values))
            if values.get("inspect_recoverable_legacy_machine_key") is True:
                self.recoverable_legacy_policy_sha256 = "B" * 64
            elif values.get("reconcile_interrupted_machine_key") is True:
                raise AssertionError("policy write must not be attempted")
            else:
                raise service_install.ProviderHostCngPolicyMismatch(
                    "synthetic primary-group gap"
                )

        def public_configuration(self) -> dict[str, object]:
            return dict(public)

    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    monkeypatch.setattr(service_install, "WindowsCngEnvelopeIdentity", Signer)

    with pytest.raises(PermissionError, match="policy changed before"):
        service_install._provision_provider_host_authority_identity(manifest)

    assert len(calls) == 2
    assert all(call["create_if_missing"] is False for call in calls)


def test_persisted_legacy_claim_never_recreates_a_missing_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public = signing._public_configuration(
        "keeper-authority-provider-host:provisioned",
        b"\x80" + b"\x00" * 383,
        b"\x03",
    )
    access_sids = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-123")
    manifest: dict[str, Any] = {
        "provider_host_authority_identity_claim": {
            **service_install._provider_host_authority_identity_claim(
                access_sids,
                operation="RECONCILE_LEGACY_1_7_3_PRIMARY_GROUP",
                observed_key_id=str(public["key_id"]),
                observed_public_identity=public,
                observed_policy_sha256="A" * 64,
            ),
            "claimed_at": "2026-08-03T00:00:00+00:00",
        }
    }
    calls: list[dict[str, object]] = []

    class Signer:
        def __init__(self, **values: object) -> None:
            calls.append(dict(values))
            raise service_install.ProviderHostCngKeyNotProvisioned(
                "synthetic key missing"
            )

    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    monkeypatch.setattr(service_install, "WindowsCngEnvelopeIdentity", Signer)

    with pytest.raises(
        service_install.ProviderHostCngKeyNotProvisioned, match="missing"
    ):
        service_install._provision_provider_host_authority_identity(manifest)

    assert len(calls) == 1
    assert calls[0]["create_if_missing"] is False


def test_persisted_legacy_claim_accepts_already_exact_target_idempotently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public = signing._public_configuration(
        "keeper-authority-provider-host:provisioned",
        b"\x80" + b"\x00" * 383,
        b"\x03",
    )
    access_sids = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-123")
    manifest: dict[str, Any] = {
        "provider_host_authority_identity_claim": {
            **service_install._provider_host_authority_identity_claim(
                access_sids,
                operation="RECONCILE_LEGACY_1_7_3_PRIMARY_GROUP",
                observed_key_id=str(public["key_id"]),
                observed_public_identity=public,
                observed_policy_sha256="A" * 64,
            ),
            "claimed_at": "2026-08-03T00:00:00+00:00",
        }
    }
    calls: list[dict[str, object]] = []

    class Signer:
        key_id = public["key_id"]

        def __init__(self, **values: object) -> None:
            calls.append(dict(values))

        def public_configuration(self) -> dict[str, object]:
            return dict(public)

    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    monkeypatch.setattr(service_install, "WindowsCngEnvelopeIdentity", Signer)
    monkeypatch.setattr(service_install, "_persist_manifest", lambda _value: None)

    result = service_install._provision_provider_host_authority_identity(
        manifest
    )

    assert result["key_id"] == public["key_id"]
    assert "provider_host_authority_identity_claim" not in manifest
    assert len(calls) == 1
    assert calls[0]["create_if_missing"] is False
    assert calls[0].get("reconcile_interrupted_machine_key") is None


def test_recovery_preimage_is_exclusive_hashed_and_rerun_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service_root = tmp_path / "service"
    data = service_root / "data"
    data.mkdir(parents=True)
    (data / "authority.db").write_bytes(b"synthetic-authority-state")
    (data / "keys").mkdir()
    (data / "keys" / "key-ring.json").write_text(
        '{"schema_version":1}', encoding="utf-8"
    )
    manifest_path = service_root / "audit" / "machine-artifacts.json"
    manifest_path.parent.mkdir()
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "service_name": service_main.SERVICE_NAME,
                "installation_completed_at": "2026-08-02T00:00:00+00:00",
                "artifacts": [],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(service_install, "SERVICE_ROOT", service_root)
    monkeypatch.setattr(service_install, "MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(service_install, "_require_admin", lambda: None)
    monkeypatch.setattr(
        service_install, "_require_service_stopped", lambda _: None
    )
    applied_security: list[dict[str, Any]] = []
    monkeypatch.setattr(service_install, "account_sid", lambda _: "S-1-5-80-123")
    monkeypatch.setattr(
        service_install,
        "apply_path_security",
        lambda path, policy: applied_security.append(policy),
    )
    destination = tmp_path / "preimage"

    with pytest.raises(PermissionError, match="disjoint"):
        service_install.verified_recovery_backup(data / "nested-preimage")

    denied_destination = tmp_path / "denied-preimage"
    monkeypatch.setattr(
        service_install,
        "apply_path_security",
        lambda *_: (_ for _ in ()).throw(
            PermissionError("synthetic recovery ACL rejection")
        ),
    )
    with pytest.raises(PermissionError, match="ACL rejection"):
        service_install.verified_recovery_backup(denied_destination)
    assert not denied_destination.exists()
    monkeypatch.setattr(
        service_install,
        "apply_path_security",
        lambda path, policy: applied_security.append(policy),
    )

    result = service_install.verified_recovery_backup(destination)

    assert len(applied_security) == 1
    applied_aces = applied_security[0]["aces"]
    assert isinstance(applied_aces, list)
    assert [
        item["trustee_sid"] for item in applied_aces
    ] == ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-123"]
    assert len(result["tree_sha256"]) == 64
    assert Path(str(result["manifest"])).is_file()
    assert (destination / "authority.db").read_bytes() == (
        b"synthetic-authority-state"
    )
    with pytest.raises(PermissionError, match="already exists"):
        service_install.verified_recovery_backup(destination)
    persisted = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert persisted["recovery_preimages"] == [result]
    (data / "authority.db").write_bytes(b"changed-after-preimage")
    with pytest.raises(PermissionError, match="no longer matches"):
        service_install._verified_recovery_preimage(
            persisted, Path(str(result["manifest"]))
        )
