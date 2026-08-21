from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.executive.authority_gateway import AuthorityProviderBinding
from keeper.pass_b.enums import CostMode
from keeper.pass_b.provider_bridge import (
    AuthorityManagedAdapter,
    bridge_qualified_provider,
 )
from keeper.pass_b.models import (
    ProviderAccountRecord,
    ProviderRecord,
    ProviderSessionRecord,
)
from keeper.pass_b.providers import (
    ProviderSelectionPolicy,
    select_provider_session,
    validate_provider_execution_declarations,
)
from keeper.pass_b.repository import PassBRepository
from keeper.pass_b.orchestration import OrchestrationService
from keeper.app.storage import KeeperStore


class _Authority:
    def __init__(
        self,
        *,
        malformed_pricing: bool = False,
        expired_pricing: bool = False,
        project_types: tuple[str, ...] = ("software",),
        effort_levels: tuple[str, ...] = ("medium",),
    ) -> None:
        now = datetime.now(UTC)
        pricing: dict[str, object] = {
            "pricing_identity": "offline:test",
            "pricing_version": "1",
            "currency": "USD",
            "estimated_cost": 0.0,
            "maximum_cost": 0.0,
            "billing_unit": "included-offline",
            "included_plan": True,
            "marginally_free": True,
            "quoted_at": (now - timedelta(minutes=5)).isoformat(),
            "expires_at": (
                now - timedelta(minutes=1)
                if expired_pricing
                else now + timedelta(hours=1)
            ).isoformat(),
            "source": "FOUNDER_APPROVED_TEST",
            "cost_tier": 0,
        }
        if malformed_pricing:
            pricing.pop("maximum_cost")
        self.registration = {
            "service_state": "QUALIFIED",
            "logical_provider_id": "codex",
            "model_or_service_identity": "codex-test",
            "executive_capability_set": [
                "planning",
                "implementation",
                "review",
                "testing",
            ],
            "project_types": list(project_types),
            "effort_levels": list(effort_levels),
            "pricing_authority": pricing,
        }
        self.qualification = {
            "service_state": "QUALIFIED",
            "evidence": {
                "id": "qualification-1",
                "registration_id": "registration-1",
                "provider_instance_id": "instance-1",
                "qualification_result": "qualified",
            },
        }

    def query_state(self, collection: str, identifier: str) -> dict[str, object]:
        expected = {
            "registrations": ("registration-1", self.registration),
            "qualifications": ("qualification-1", self.qualification),
        }
        expected_id, record = expected[collection]
        return {"found": identifier == expected_id, "record": record}

    def verify(self, purpose: str, record: dict[str, object]) -> bool:
        return purpose == "provider-qualification" and record is self.qualification["evidence"]


def _orchestration(tmp_path: Path) -> OrchestrationService:
    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    return OrchestrationService(PassBRepository(store))


def test_bridge_projects_exact_qualified_authority_contract(tmp_path: Path) -> None:
    orchestration = _orchestration(tmp_path)
    authority = _Authority()
    provider = bridge_qualified_provider(
        orchestration,
        cast(ProductionAuthorityServiceClient, cast(Any, authority)),
        AuthorityProviderBinding("registration-1", "qualification-1"),
    )

    assert provider.provider_id == "codex"
    assert provider.authority_registration_id == "registration-1"
    assert provider.cost_mode == CostMode.FREE
    assert provider.project_types == ("software",)
    assert provider.effort_levels == ("medium",)
    assert len(provider.pricing_authority_digest or "") == 64
    assert provider.pricing_expires_at is not None
    assert {"planner", "implementer", "reviewer", "tester"} <= set(
        provider.capabilities
    )
    account = orchestration.repository.get(
        ProviderAccountRecord,
        "authority-account:registration-1",
    )
    assert account.enabled is True
    assert isinstance(orchestration.adapters["codex"], AuthorityManagedAdapter)
    with pytest.raises(PermissionError, match="cannot execute through a local adapter"):
        orchestration.adapters["codex"].launch(cast(Any, object()))


def test_bridge_rejects_incomplete_pricing_before_persistence(tmp_path: Path) -> None:
    orchestration = _orchestration(tmp_path)
    authority = _Authority(malformed_pricing=True)

    with pytest.raises(PermissionError, match="pricing declaration"):
        bridge_qualified_provider(
            orchestration,
            cast(ProductionAuthorityServiceClient, cast(Any, authority)),
            AuthorityProviderBinding("registration-1", "qualification-1"),
        )
    assert orchestration.repository.list(ProviderRecord) == []

def test_bridge_rejects_expired_pricing_before_persistence(tmp_path: Path) -> None:
    orchestration = _orchestration(tmp_path)

    with pytest.raises(PermissionError, match="not currently valid"):
        bridge_qualified_provider(
            orchestration,
            cast(
                ProductionAuthorityServiceClient,
                cast(Any, _Authority(expired_pricing=True)),
            ),
            AuthorityProviderBinding("registration-1", "qualification-1"),
        )

    assert orchestration.repository.list(ProviderRecord) == []
    assert orchestration.adapters == {}


def test_authority_provider_selection_enforces_project_and_effort(
    tmp_path: Path,
) -> None:
    orchestration = _orchestration(tmp_path)
    provider = bridge_qualified_provider(
        orchestration,
        cast(ProductionAuthorityServiceClient, cast(Any, _Authority())),
        AuthorityProviderBinding("registration-1", "qualification-1"),
    )
    account = orchestration.repository.get(
        ProviderAccountRecord, "authority-account:registration-1"
    )
    session = orchestration.repository.get(
        ProviderSessionRecord, "instance-1"
    )

    def policy(project_type: str, effort_level: str) -> ProviderSelectionPolicy:
        return ProviderSelectionPolicy(
            allowed_provider_ids=frozenset({"codex"}),
            required_capabilities=frozenset({"implementer"}),
            allow_substitution=True,
            allow_paid=False,
            privacy_classification="AUTHORITY_DECLARED",
            project_type=project_type,
            effort_level=effort_level,
        )

    assert select_provider_session(
        "IMPLEMENTER", [provider], [account], [session], policy("software", "MEDIUM")
    ) == session
    with pytest.raises(RuntimeError, match="no already-approved"):
        select_provider_session(
            "IMPLEMENTER", [provider], [account], [session], policy("research", "MEDIUM")
        )
    with pytest.raises(RuntimeError, match="no already-approved"):
        select_provider_session(
            "IMPLEMENTER", [provider], [account], [session], policy("software", "HIGH")
        )


def test_launch_revalidation_rejects_expired_durable_quote(tmp_path: Path) -> None:
    orchestration = _orchestration(tmp_path)
    provider = bridge_qualified_provider(
        orchestration,
        cast(ProductionAuthorityServiceClient, cast(Any, _Authority())),
        AuthorityProviderBinding("registration-1", "qualification-1"),
    )
    expired = ProviderRecord.from_dict(
        {
            **provider.to_dict(),
            "pricing_expires_at": (
                datetime.now(UTC) - timedelta(seconds=1)
            ).isoformat(),
        }
    )

    with pytest.raises(PermissionError, match="not currently valid"):
        validate_provider_execution_declarations(
            expired,
            project_type="software",
            effort_level="MEDIUM",
        )
