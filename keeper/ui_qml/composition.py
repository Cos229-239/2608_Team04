from __future__ import annotations

from pathlib import Path
from typing import Any

from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.pass_b.application import (
    PassBApplication,
    authority_exchange_root_from_diagnostics,
)
from keeper.ui.setup import (
    ProductSetupController,
    configured_authority_bindings,
)

_PROVIDER_STARTUP_BLOCK = (
    "Provider execution is blocked: KeeperAuthority is unavailable or a saved "
    "provider authorization is no longer valid. Check service status and renew "
    "provider qualification through the supported setup flow, then restart Keeper. "
    "No provider fallback or paid execution has been enabled."
)


def _blocked_desktop(data_directory: Path, health_client: Any) -> PassBApplication:
    # Rebuild without launch/reservation authority, even if an earlier provider
    # bridged successfully. Durable records and recovery identity stay intact.
    result = PassBApplication(data_directory, authority_health_client=health_client)
    result.startup_provider_block = _PROVIDER_STARTUP_BLOCK
    return result


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

            try:
                exchange_root = authority_exchange_root_from_diagnostics(
                    health_client.diagnostics()
                )
            except (PermissionError, TimeoutError, ConnectionError):
                return _blocked_desktop(data_directory, health_client)
            # Do not swallow database/recovery identity or construction errors.
            result = PassBApplication(
                data_directory,
                authority_client=health_client,
                authority_health_client=health_client,
                provider_bindings=bindings,
                authority_exchange_root=exchange_root,
                usage_reset_verifier=ProductionUsageResetVerifier.unavailable(),
            )
            try:
                for binding in bindings:
                    bridge_qualified_provider(result.orchestration, health_client, binding)
            except (PermissionError, TimeoutError, ConnectionError):
                return _blocked_desktop(data_directory, health_client)
            return result
    return PassBApplication(
        data_directory, authority_health_client=health_client
    )
__all__ = [
    "ProductSetupController",
    "configured_authority_bindings",
    "desktop_pass_b_application",
]
