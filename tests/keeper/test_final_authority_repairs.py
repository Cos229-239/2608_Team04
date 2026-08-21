from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from tests.keeper.authority_testkit import provider_authority_kwargs

from keeper.app.service import KeeperApplication
from keeper.cli import main
from keeper.authority import AuthorityKey
from keeper.authority_service.core import QualificationObservation
from keeper.providers.adapters import (
    ProviderCapabilities,
    ProviderDiagnostic,
    ProviderDiscovery,
    RoutingRequest,
    canonical_provider_registration_digest,
    create_provider_registration,
    apply_protected_qualification,
    qualification_evidence_digest,
    route_provider,
)
from tests.keeper.authority_testkit import TestAuthorityClient


def _version_script(path: Path, marker: Path, *, success: bool = True) -> None:
    path.write_text(
        "\n".join(
            [
                "@echo off",
                f'echo invoked>>"{marker}"',
                "echo protected-version 1.0" if success else "echo invalid 1>&2",
                "exit /b 0" if success else "exit /b 1",
                "",
            ]
        ),
        encoding="utf-8",
    )


def test_registration_creation_cannot_fabricate_qualification(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "marker.txt"
    _version_script(executable, marker)

    creator: Any = create_provider_registration
    with pytest.raises(TypeError):
        creator(
            "codex",
            executable,
            authorized_by="registrar",
            qualified_version="fabricated 9.9",
        )
    registration = create_provider_registration(
        "codex", executable, authorized_by="registrar"
    , **provider_authority_kwargs('codex'))

    assert marker.exists() is False
    assert registration["registration_lifecycle"] == "REGISTERED_UNQUALIFIED"
    assert registration["qualified_version"] is None
    assert registration["qualification_timestamp"] is None
    assert registration["qualification_evidence_id"] is None


def test_protected_qualification_records_actual_output(
    tmp_path: Path,
) -> None:
    app = KeeperApplication(tmp_path / "data")
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "marker.txt"
    _version_script(executable, marker)
    app.save_provider_paths({"codex": str(executable)})
    app.register_provider("codex", executable, "registrar", **provider_authority_kwargs())

    before = next(
        item for item in app.diagnostics()["providers"] if item["provider_id"] == "codex"
    )
    qualified = app.qualify_provider("codex", "qualifier")
    after = next(
        item for item in app.diagnostics()["providers"] if item["provider_id"] == "codex"
    )

    assert before["discovery_state"] == "registered-unqualified"
    assert before["version"] is None
    assert marker.read_text(encoding="utf-8").count("invoked") == 1
    assert qualified["qualified_version"] == "protected-version 1.0"
    assert qualified["qualification_evidence_id"]
    assert after["discovery_state"] == "qualified"
    assert after["version"] == "protected-version 1.0"


def test_application_schema4_qualification_forwards_registered_executable(
    tmp_path: Path,
) -> None:
    application = KeeperApplication(tmp_path / "data")
    executable = (tmp_path / "codex.exe").resolve()
    executable.write_bytes(b"reviewed-codex")
    registration = {
        "trusted_registration_id": "registration-1",
        "registration_schema_version": 4,
        "canonical_executable_path": str(executable),
        "registration_lifecycle": "REGISTERED_UNQUALIFIED",
    }
    application.store.upsert(
        "settings", "provider_registrations", {"codex": registration}
    )

    class RecordingAuthority:
        def qualify_provider(
            self, registration_id: str, reviewed_executable: Path | None = None
        ) -> dict[str, Any]:
            assert registration_id == "registration-1"
            assert reviewed_executable == executable
            return {
                "registration": {
                    **registration,
                    "registration_lifecycle": "QUALIFIED",
                },
                "qualification_start": {
                    "id": "qualification-start-1",
                    "kind": "provider_qualification_started",
                },
                "qualification": {
                    "id": "qualification-1",
                    "kind": "provider_qualification",
                },
            }

    application.authority = cast(Any, RecordingAuthority())

    qualified = application.qualify_provider("codex", "qualifier")

    assert qualified["registration_lifecycle"] == "QUALIFIED"


def test_qualified_provider_projection_is_verified_and_idempotent(
    tmp_path: Path,
) -> None:
    authority = KeeperApplication(tmp_path / "authority")
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "marker.txt"
    _version_script(executable, marker)
    authority.register_provider(
        "codex", executable, "registrar", **provider_authority_kwargs()
    )
    qualified = authority.qualify_provider("codex", "qualifier")
    registration_id = str(qualified["trusted_registration_id"])
    qualification_id = str(qualified["qualification_evidence_id"])

    projection = KeeperApplication(tmp_path / "desktop")
    projection.authority = authority.authority
    first = projection.sync_qualified_provider(
        "codex", registration_id, qualification_id
    )
    second = projection.sync_qualified_provider(
        "codex", registration_id, qualification_id
    )

    assert first == second
    assert first["registration_lifecycle"] == "QUALIFIED"
    assert projection.provider_registrations()["codex"] == qualified
    assert projection.provider_paths()["codex"] == str(executable.resolve())
    evidence = projection.qualification_evidence()
    assert evidence[qualification_id]["registration_id"] == registration_id
    assert evidence[qualification_id]["qualification_result"] == "qualified"


def test_qualified_provider_projection_rejects_mismatched_evidence(
    tmp_path: Path,
) -> None:
    authority = KeeperApplication(tmp_path / "authority")
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "marker.txt"
    _version_script(executable, marker)
    authority.register_provider(
        "codex", executable, "registrar", **provider_authority_kwargs()
    )
    qualified = authority.qualify_provider("codex", "qualifier")
    registration_id = str(qualified["trusted_registration_id"])

    projection = KeeperApplication(tmp_path / "desktop")
    projection.authority = authority.authority
    with pytest.raises(PermissionError, match="not projectable"):
        projection.sync_qualified_provider(
            "codex", registration_id, "provider-qualification:wrong"
        )

    assert projection.provider_registrations() == {}
    assert projection.qualification_evidence() == {}


def test_sync_qualified_provider_cli_projects_without_running_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = KeeperApplication(tmp_path / "authority")
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "marker.txt"
    _version_script(executable, marker)
    authority.register_provider(
        "codex", executable, "registrar", **provider_authority_kwargs()
    )
    qualified = authority.qualify_provider("codex", "qualifier")
    marker_before = marker.read_text(encoding="utf-8")
    registration_id = str(qualified["trusted_registration_id"])
    qualification_id = str(qualified["qualification_evidence_id"])
    data_directory = tmp_path / "desktop"
    monkeypatch.setattr(
        "keeper.app.service.authority_client_factory",
        lambda _data_directory: authority.authority,
    )

    assert (
        main(
            [
                "sync-qualified-provider",
                "codex",
                registration_id,
                qualification_id,
                "--data-directory",
                str(data_directory),
            ]
        )
        == 0
    )

    projection = KeeperApplication(data_directory)
    assert projection.provider_registrations()["codex"] == qualified
    assert marker.read_text(encoding="utf-8") == marker_before


def test_failed_protected_qualification_stays_unqualified(tmp_path: Path) -> None:
    app = KeeperApplication(tmp_path / "data")
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "marker.txt"
    _version_script(executable, marker, success=False)
    app.save_provider_paths({"codex": str(executable)})
    app.register_provider("codex", executable, "registrar", **provider_authority_kwargs())

    with pytest.raises(PermissionError, match="failed"):
        app.qualify_provider("codex", "qualifier")

    failed = app.provider_registrations()["codex"]
    assert failed["registration_lifecycle"] == "QUALIFICATION_FAILED"
    assert failed["qualified_version"] is None
    diagnostic = next(
        item for item in app.diagnostics()["providers"] if item["provider_id"] == "codex"
    )
    assert diagnostic["discovery_state"] == "qualification-failed"


def test_unrecognized_version_output_fails_qualification(tmp_path: Path) -> None:
    application = KeeperApplication(tmp_path / "data")
    executable = tmp_path / "provider.cmd"
    executable.write_text(
        "@echo off\necho arbitrary success text\nexit /b 0\n",
        encoding="utf-8",
    )
    application.save_provider_paths({"codex": str(executable)})
    application.register_provider("codex", executable, "registrar", **provider_authority_kwargs())

    with pytest.raises(PermissionError, match="failed"):
        application.qualify_provider("codex", "qualifier")

    registration = application.provider_registrations()["codex"]
    assert registration["registration_lifecycle"] == "QUALIFICATION_FAILED"
    diagnostic = next(
        item
        for item in application.diagnostics()["providers"]
        if item["provider_id"] == "codex"
    )
    assert diagnostic["discovery_state"] == "qualification-failed"


def test_provider_construction_failure_is_finalized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application = KeeperApplication(tmp_path / "data")
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "marker.txt"
    _version_script(executable, marker)
    application.register_provider("codex", executable, "registrar", **provider_authority_kwargs())

    def fail_construction(
        *_args: object, **_kwargs: object
    ) -> QualificationObservation:
        return QualificationObservation(
            "qualification-failed:test",
            {
                "restricted": False,
                "integrity_level": "unknown",
                "job_confined": False,
            },
            "2026-07-27T00:00:00+00:00",
            "2026-07-27T00:00:01+00:00",
            70,
            "",
            "RuntimeError: construction failed",
        )

    test_authority = cast(TestAuthorityClient, application.authority)
    monkeypatch.setattr(
        test_authority.core.observer, "qualify", fail_construction
    )
    with pytest.raises(PermissionError, match="failed"):
        application.qualify_provider("codex", "qualifier")

    registration = application.provider_registrations()["codex"]
    evidence = application.qualification_evidence()[
        str(registration["qualification_evidence_id"])
    ]
    assert registration["registration_lifecycle"] == "QUALIFICATION_FAILED"
    assert evidence["qualification_result"] == "failed"
    assert evidence["failure_reason"] == "RuntimeError: construction failed"


def test_standalone_batch_uses_composite_qualified_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = KeeperApplication(tmp_path / "authority")
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "marker.txt"
    _version_script(executable, marker)
    authority.register_provider("codex", executable, "registrar", **provider_authority_kwargs())
    registration = authority.qualify_provider("codex", "qualifier")
    evidence = authority.qualification_evidence()[
        str(registration["qualification_evidence_id"])
    ]
    monkeypatch.setattr(
        "keeper.cli.authority_client_factory", lambda _root: authority.authority
    )
    repository = tmp_path / "repository"
    state = repository / ".ai-workflow"
    state.mkdir(parents=True)
    (state / "config.json").write_text(
        json.dumps(
            {
                "provider_command": [str(executable), "{prompt}"],
                "provider_registration": registration,
                "provider_qualification_reference": evidence["id"],
            }
        ),
        encoding="utf-8",
    )

    assert main(["--root", str(repository), "run-next"]) == 0


def test_raw_qualification_evidence_in_standalone_config_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = KeeperApplication(tmp_path / "authority")
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "marker.txt"
    _version_script(executable, marker)
    authority.register_provider("codex", executable, "registrar", **provider_authority_kwargs())
    registration = authority.qualify_provider("codex", "qualifier")
    evidence = authority.qualification_evidence()[
        str(registration["qualification_evidence_id"])
    ]
    monkeypatch.setattr(
        "keeper.cli.authority_client_factory", lambda _root: authority.authority
    )
    repository = tmp_path / "repository"
    state = repository / ".ai-workflow"
    state.mkdir(parents=True)
    (state / "config.json").write_text(
        json.dumps(
            {
                "provider_command": [str(executable), "{prompt}"],
                "provider_registration": registration,
                "provider_qualification_evidence": evidence,
            }
        ),
        encoding="utf-8",
    )

    assert main(["--root", str(repository), "run-next"]) == 2


def test_public_digest_and_wrong_installation_key_do_not_authenticate(
    tmp_path: Path,
) -> None:
    application = KeeperApplication(tmp_path / "installation-a")
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "marker.txt"
    _version_script(executable, marker)
    unqualified = application.register_provider("codex", executable, "registrar", **provider_authority_kwargs())
    qualified = application.qualify_provider("codex", "qualifier")
    evidence_by_id = application.qualification_evidence()
    evidence = dict(
        evidence_by_id[str(qualified["qualification_evidence_id"])]
    )
    unsigned = {
        key: value
        for key, value in evidence.items()
        if key
        not in {
            "authority_schema_version",
            "authority_key_id",
            "authenticated_writer_proof",
        }
    }
    unsigned["evidence_digest"] = qualification_evidence_digest(unsigned)

    with pytest.raises(PermissionError, match="writer authority"):
        apply_protected_qualification(
            unqualified,
            unsigned,
            authority_verifier=application.authority.verify,
            expected_challenge=str(unsigned["event_challenge"]),
            expected_authorization_reference=str(
                unsigned["authorization_reference"]
            ),
        )
    other_authority = AuthorityKey(tmp_path / "installation-b")
    diagnostic = ProviderDiscovery(
        {"codex": str(executable)},
        {"codex": qualified},
        evidence_by_id,
        other_authority.verify,
    ).discover()[0]
    assert diagnostic.available is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("normalized_version", "codex 9.9"),
        ("executable_sha256", "f" * 64),
        ("authorization_reference", "forged-authorization"),
        ("event_challenge", "replayed-challenge"),
    ],
)
def test_signed_qualification_mutation_and_replay_are_rejected(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    application = KeeperApplication(tmp_path / field)
    executable = tmp_path / f"{field}.cmd"
    marker = tmp_path / f"{field}.txt"
    _version_script(executable, marker)
    application.register_provider("codex", executable, "registrar", **provider_authority_kwargs())
    qualified = application.qualify_provider("codex", "qualifier")
    evidence_by_id = application.qualification_evidence()
    evidence_id = str(qualified["qualification_evidence_id"])
    evidence_by_id[evidence_id] = {
        **evidence_by_id[evidence_id],
        field: value,
    }

    diagnostic = ProviderDiscovery(
        {"codex": str(executable)},
        {"codex": qualified},
        evidence_by_id,
        application.authority.verify,
    ).discover()[0]

    assert diagnostic.available is False


def test_authority_secret_is_outside_provider_roots_and_not_inherited(
    tmp_path: Path,
) -> None:
    application = KeeperApplication(tmp_path / "data")
    key_path = cast(
        TestAuthorityClient, application.authority
    ).core.keys.root
    exchange_root = Path(
        str(application.authority.diagnostics()["client_exchange_root"])
    )

    assert not hasattr(application.authority, "path")
    assert not key_path.is_relative_to(exchange_root)
    assert all(
        "AUTHORITY" not in key.upper() and str(key_path) != value
        for key, value in os.environ.items()
    )


def test_provider_receives_no_authority_key_location(tmp_path: Path) -> None:
    application = KeeperApplication(tmp_path / "data")
    executable = tmp_path / "provider.cmd"
    marker = tmp_path / "marker.txt"
    executable.write_text(
        "\n".join(
            [
                "@echo off",
                'if defined KEEPER_AUTHORITY_KEY_PATH exit /b 9',
                f'echo invoked>>"{marker}"',
                "echo protected-version 1.0",
                "exit /b 0",
                "",
            ]
        ),
        encoding="utf-8",
    )
    application.register_provider("codex", executable, "registrar", **provider_authority_kwargs())

    application.qualify_provider("codex", "qualifier")

    assert marker.exists()
    assert not hasattr(application.authority, "path")


@pytest.mark.parametrize(
    ("capabilities", "roles", "requested"),
    [
        (ProviderCapabilities(reviewer=False), ["builder", "repairer"], "reviewer"),
        (ProviderCapabilities(), [], "builder"),
        (ProviderCapabilities(), ["builder"], "reviewer"),
        (ProviderCapabilities(), ["reviewer"], "builder"),
        (ProviderCapabilities(repairer=False), ["builder"], "repairer"),
    ],
)
def test_registered_role_restrictions_prevent_routing(
    capabilities: ProviderCapabilities,
    roles: list[str],
    requested: str,
) -> None:
    diagnostic = ProviderDiagnostic(
        "codex",
        "controlled",
        True,
        "C:\\controlled.exe",
        "1.0",
        "verified",
        capabilities,
        registration={"protected": True},
        discovery_state="qualified",
        role_eligibility=tuple(roles),
        independence_classification="independent-capable",
        provider_policy="registered-command",
    )

    with pytest.raises(RuntimeError):
        route_provider(RoutingRequest(requested, "high", "keeper"), [diagnostic])


def test_discovery_preserves_all_disabled_capabilities_and_empty_roles(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"provider")
    disabled = ProviderCapabilities(
        author=False,
        reviewer=False,
        repairer=False,
        structured_output=False,
        streaming=False,
        cancellation=False,
        usage_reporting=False,
        local_only=False,
    )
    registration = create_provider_registration(
        "codex",
        executable,
        authorized_by="registrar",
        capabilities=disabled,
        role_eligibility=[],
        independence_classification="authoring-only",
     **provider_authority_kwargs('codex'))

    diagnostic = ProviderDiscovery(
        {"codex": str(executable)}, {"codex": registration}
    ).discover()[0]

    assert diagnostic.available is True
    assert diagnostic.capabilities == disabled
    assert diagnostic.role_eligibility == ()
    with pytest.raises(RuntimeError):
        route_provider(RoutingRequest("reviewer", "high", "keeper"), [diagnostic])


def test_unknown_duplicate_and_inconsistent_roles_are_rejected(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"provider")
    variants = [
        create_provider_registration(
            "codex", executable, authorized_by="registrar"
        , **provider_authority_kwargs('codex')),
        create_provider_registration(
            "codex", executable, authorized_by="registrar"
        , **provider_authority_kwargs('codex')),
        create_provider_registration(
            "codex", executable, authorized_by="registrar"
        , **provider_authority_kwargs('codex')),
    ]
    variants[0]["role_eligibility"] = ["unknown"]
    variants[1]["role_eligibility"] = ["builder", "builder"]
    variants[2]["capability_set"]["reviewer"] = False
    for registration in variants:
        registration["configuration_digest"] = canonical_provider_registration_digest(
            registration
        )
        diagnostic = ProviderDiscovery(
            {"codex": str(executable)}, {"codex": registration}
        ).discover()[0]
        assert diagnostic.available is False
