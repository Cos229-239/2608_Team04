"""Provider interfaces with a lazy compatibility export surface.

KeeperAuthority imports the provider contract modules but must not pull mock,
Ollama, or desktop provider implementations into its service package.
"""

from typing import Any


__all__ = [
    "AgentProvider", "AgentRequest", "CliProvider", "MockOllamaClient",
    "MockProvider", "OllamaProvider", "ProcessResult",
]


def __getattr__(name: str) -> Any:
    value: Any
    if name in {"AgentProvider", "AgentRequest", "ProcessResult"}:
        from keeper.providers import base

        value = getattr(base, name)
    elif name == "CliProvider":
        from keeper.providers.codex_cli import CliProvider

        value = CliProvider
    elif name == "MockProvider":
        from keeper.providers.mock import MockProvider

        value = MockProvider
    elif name in {"MockOllamaClient", "OllamaProvider"}:
        from keeper.providers import ollama

        value = getattr(ollama, name)
    else:
        raise AttributeError(name)
    globals()[name] = value
    return value
