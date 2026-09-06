from __future__ import annotations

from pathlib import Path
from typing import Any

from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.pass_b.application import PassBApplication
from keeper.ui.setup import (
    ProductSetupController,
    configured_authority_bindings,
)


def desktop_pass_b_application(
    application: Any, *, authority_health_client: Any | None = None
) -> PassBApplication:
    data_directory = Path(application.data_directory)
    health_client = authority_health_client
    if health_client is None:
        health_client = ProductionAuthorityServiceClient(timeout_seconds=0.25)
        bindings = configured_authority_bindings(application)
        if bindings:
            from keeper.pass_b.provider_bridge import bridge_qualified_provider
            from keeper.pass_b.usage_authority import ProductionUsageResetVerifier

            result = PassBApplication(
                data_directory,
                authority_client=health_client,
                authority_health_client=health_client,
                provider_bindings=bindings,
                authority_exchange_root=data_directory / "authority-exchange",
                usage_reset_verifier=ProductionUsageResetVerifier.unavailable(),
            )
            for binding in bindings:
                bridge_qualified_provider(result.orchestration, health_client, binding)
            return result
    return PassBApplication(
        data_directory, authority_health_client=health_client
    )
__all__ = [
    "ProductSetupController",
    "configured_authority_bindings",
    "desktop_pass_b_application",
]
