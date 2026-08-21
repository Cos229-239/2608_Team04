from __future__ import annotations

from keeper.policies import validate_provider_role
from keeper.providers.base import AgentProvider


class ProviderRouter:
    def __init__(self, providers: dict[str, AgentProvider], routes: dict[str, str]) -> None:
        self.providers = providers
        self.routes = routes

    def for_role(self, role: str) -> AgentProvider:
        provider_id = self.routes.get(role)
        if provider_id is None:
            raise RuntimeError(f"no provider is explicitly configured for role: {role}")
        provider = self.providers.get(provider_id)
        if provider is None:
            raise RuntimeError(f"configured provider is unavailable: {provider_id}")
        validate_provider_role(provider.provider_name, role)
        provider.validate()
        return provider
