from __future__ import annotations

from pathlib import Path

import pytest

from tests.keeper.authority_testkit import provider_authority_kwargs

from keeper.app import workflow
from tests.keeper.authority_testkit import TestAuthorityClient
from keeper.providers.adapters import (
    ProviderCapabilities,
    ProviderDiagnostic,
    ProviderDiscovery,
    create_provider_registration,
)


def diagnostic(identifier: str, root: Path) -> ProviderDiagnostic:
    executable = root / f"{identifier}.exe"
    executable.write_bytes(f"controlled {identifier}".encode())
    return ProviderDiagnostic(
        identifier,
        identifier,
        True,
        str(executable),
        "test",
        "controlled fake executable",
        ProviderCapabilities(),
        registration=create_provider_registration(
            identifier,
            executable,
            authorized_by="routing-test",
         **provider_authority_kwargs(identifier)),
        discovery_state="qualified",
        role_eligibility=(
            "builder",
            "post_repair_reviewer",
            "repairer",
            "reviewer",
        ),
        independence_classification="independent-capable",
        provider_policy="registered-command",
    )


def test_automatic_policy_routes_independent_command_adapters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ProviderDiscovery,
        "discover",
        lambda self: [diagnostic("codex", tmp_path), diagnostic("claude", tmp_path)],
    )
    providers, routes, decisions = workflow._select_routes(  # noqa: SLF001
        {"provider_policy": "automatic", "risk": "high"},
        {"__authority_client__": TestAuthorityClient(tmp_path / "authority")},
    )
    assert providers[routes["builder"]].instance_id != providers[routes["reviewer"]].instance_id
    assert {item["role"] for item in decisions} == {
        "builder",
        "reviewer",
        "repairer",
        "post_repair_reviewer",
    }
    assert all(item["policy"] == "automatic" for item in decisions)


def test_automatic_policy_blocks_without_independent_reviewer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ProviderDiscovery,
        "discover",
        lambda self: [diagnostic("codex", tmp_path)],
    )
    with pytest.raises(RuntimeError, match="independent"):
        workflow._select_routes(  # noqa: SLF001
            {"provider_policy": "automatic", "risk": "high"}, {}
        )
