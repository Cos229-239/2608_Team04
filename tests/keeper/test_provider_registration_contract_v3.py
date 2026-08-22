from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from keeper.authority_service.client import AuthorityServiceClient
from keeper.authority_service.core import AuthorityServiceCore, TrustedObserver
from keeper.authority_service.protocol import Operation
from keeper.executive.authority_gateway import (
    AuthorityBackedSpecialistGateway,
    AuthorityProviderBinding,
)
from keeper.executive.founder_capability import TestFounderCapabilityVerifier
from keeper.providers.adapters import create_provider_registration
from tests.keeper.authority_testkit import provider_authority_kwargs
from tests.keeper.executive.test_intake_charters import approved_project
from tests.keeper.test_authority_service_core import _Observer, _service


def test_explicit_contract_persists_qualifies_and_reaches_executive(
    tmp_path: Path,
) -> None:
    authority_root = tmp_path / "authority"
    authority_root.mkdir()
    core, client = _service(authority_root)
    executable = authority_root / "controlled-provider.exe"
    declarations = provider_authority_kwargs()

    registered = client.register_provider("codex", executable, **declarations)
    registration_id = str(registered["registration_id"])
    persisted = client.query_state("registrations", registration_id)["record"]
    for field, expected in {
        "executive_capability_set": declarations["executive_capabilities"],
        "project_types": declarations["project_types"],
        "effort_levels": declarations["effort_levels"],
        "pricing_authority": declarations["pricing_authority"],
    }.items():
        assert persisted[field] == expected

    qualified = client.qualify_provider(registration_id)
    qualification_id = str(qualified["qualification"]["id"])
    assert qualified["registration"]["pricing_authority"] == declarations[
        "pricing_authority"
    ]
    assert client.query_state("registrations", registration_id)["record"][
        "service_state"
    ] == "QUALIFIED"

    restarted_core = AuthorityServiceCore(
        authority_root / "service",
        observer=cast(TrustedObserver, _Observer(executable)),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    restarted_client = AuthorityServiceClient(
        test_transport=lambda request: restarted_core.dispatch(
            request, "S-1-5-21-1000"
        )
    )
    restarted_record = restarted_client.query_state(
        "registrations", registration_id
    )["record"]
    assert restarted_record["service_state"] == "QUALIFIED"
    assert restarted_record["pricing_authority"] == declarations["pricing_authority"]

    _, _, charter = approved_project(tmp_path / "executive")
    gateway = AuthorityBackedSpecialistGateway(
        restarted_client,
        (AuthorityProviderBinding(registration_id, qualification_id),),
        tmp_path / "exchange",
    )
    specialists = gateway.specialists(charter)
    assert len(specialists) == 1
    assert specialists[0].capabilities == tuple(declarations["executive_capabilities"])
    assert specialists[0].project_types == tuple(declarations["project_types"])
    assert specialists[0].effort_levels == tuple(declarations["effort_levels"])
    assert specialists[0].maximum_cost == 0.0
    assert client.diagnostics()["service_version"] == "1.7.51"


def test_register_payload_requires_every_authority_field(tmp_path: Path) -> None:
    _, client = _service(tmp_path)
    executable = tmp_path / "controlled-provider.exe"
    with pytest.raises((PermissionError, ValueError), match="payload fields"):
        client.request(
            Operation.REGISTER_PROVIDER,
            {"provider_id": "codex", "executable": str(executable.resolve())},
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown_capability",
        "unknown_project_type",
        "unknown_effort",
        "duplicate_effort",
        "missing_pricing_field",
        "extra_pricing_field",
        "non_finite_cost",
        "boolean_cost",
        "inconsistent_free",
        "expired_quote",
    ],
)
def test_invalid_authority_declarations_reject_before_persistence(
    tmp_path: Path,
    mutation: str,
) -> None:
    core, client = _service(tmp_path)
    executable = tmp_path / "controlled-provider.exe"
    values = deepcopy(provider_authority_kwargs())
    pricing = values["pricing_authority"]
    assert isinstance(pricing, dict)
    if mutation == "unknown_capability":
        values["executive_capabilities"] = ["unsupported"]
    elif mutation == "unknown_project_type":
        values["project_types"] = ["unsupported"]
    elif mutation == "unknown_effort":
        values["effort_levels"] = ["unbounded"]
    elif mutation == "duplicate_effort":
        values["effort_levels"] = ["high", "high"]
    elif mutation == "missing_pricing_field":
        pricing.pop("source")
    elif mutation == "extra_pricing_field":
        pricing["authority_override"] = True
    elif mutation == "non_finite_cost":
        pricing["maximum_cost"] = float("nan")
    elif mutation == "boolean_cost":
        pricing["estimated_cost"] = False
    elif mutation == "inconsistent_free":
        pricing["marginally_free"] = False
    else:
        pricing["expires_at"] = "2026-07-01T00:00:01+00:00"

    with pytest.raises((PermissionError, ValueError)):
        client.register_provider("codex", executable, **values)
    assert core.store.list_records("registrations") == []


def test_qualification_rejects_incomplete_pre_v3_record(tmp_path: Path) -> None:
    core, client = _service(tmp_path)
    executable = tmp_path / "controlled-provider.exe"
    registration = create_provider_registration(
        "codex",
        executable,
        authorized_by="legacy-test",
        **provider_authority_kwargs(),
    )
    registration_id = str(registration["trusted_registration_id"])
    registration["registration_schema_version"] = 2
    for field in (
        "executive_capability_set",
        "project_types",
        "effort_levels",
        "pricing_authority",
    ):
        registration.pop(field)
    core.store.insert(
        "registrations", registration_id, "REGISTERED_UNQUALIFIED", registration
    )

    with pytest.raises(PermissionError, match="incomplete or invalid"):
        client.qualify_provider(registration_id)
    assert client.query_state("registrations", registration_id)["record"][
        "service_state"
    ] == "REGISTERED_UNQUALIFIED"


def test_legacy_migration_requires_explicit_authority_contract(
    tmp_path: Path,
) -> None:
    core, client = _service(tmp_path)
    executable = tmp_path / "controlled-provider.exe"
    with pytest.raises((PermissionError, ValueError), match="payload fields"):
        client.migrate_legacy(
            [
                {
                    "logical_provider_id": "codex",
                    "canonical_executable_path": str(executable.resolve()),
                }
            ]
        )
    assert core.store.list_records("registrations") == []

    result = client.migrate_legacy(
        [
            {
                "logical_provider_id": "codex",
                "canonical_executable_path": str(executable.resolve()),
                **provider_authority_kwargs(),
            }
        ]
    )
    assert result["migrated_registrations"] == 1
    assert result["registrations"][0]["registration_schema_version"] == 3


def test_registration_response_mutation_cannot_change_persisted_authority(
    tmp_path: Path,
) -> None:
    _, client = _service(tmp_path)
    executable = tmp_path / "controlled-provider.exe"
    result = client.register_provider(
        "codex", executable, **provider_authority_kwargs()
    )
    registration_id = str(result["registration_id"])
    result["registration"]["effort_levels"] = ["xhigh"]
    persisted = client.query_state("registrations", registration_id)["record"]
    assert persisted["effort_levels"] == ["high", "medium"]
