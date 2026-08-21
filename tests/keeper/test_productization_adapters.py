from __future__ import annotations

from pathlib import Path

import pytest

from tests.keeper.authority_testkit import provider_authority_kwargs

from keeper.providers.adapters import (
    ClaudeCommandAdapter,
    CodexCommandAdapter,
    ProviderCapabilities,
    ProviderDiagnostic,
    ProviderDiscovery,
    RoutingRequest,
    create_provider_registration,
    route_provider,
)
from keeper.providers.base import AgentRequest
from keeper.providers.ollama import HttpOllamaClient


def _request(tmp_path: Path, prompt: str = "safe prompt") -> AgentRequest:
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text(prompt, encoding="utf-8")
    return AgentRequest(
        "reviewer",
        prompt_path,
        tmp_path,
        30,
        tmp_path / "stdout.json",
        tmp_path / "stderr.log",
    )


def test_codex_adapter_uses_argument_array_and_output_schema(tmp_path: Path) -> None:
    request = _request(tmp_path, "content; Remove-Item -Recurse")
    executable = tmp_path / "provider-one.exe"
    executable.write_bytes(b"controlled provider")
    registration = create_provider_registration(
        "codex", executable, authorized_by="test"
    , **provider_authority_kwargs('codex'))
    command = CodexCommandAdapter(str(executable), registration).build_command(request)
    assert command[:2] == [str(executable.resolve()), "exec"]
    assert command[-1] == "content; Remove-Item -Recurse"
    assert (tmp_path / "provider-output-schema.json").is_file()


def test_claude_adapter_uses_argument_array_and_schema(tmp_path: Path) -> None:
    executable = tmp_path / "provider-two.exe"
    executable.write_bytes(b"controlled provider")
    registration = create_provider_registration(
        "claude", executable, authorized_by="test"
    , **provider_authority_kwargs('claude'))
    command = ClaudeCommandAdapter(str(executable), registration).build_command(
        _request(tmp_path)
    )
    assert command[0] == str(executable.resolve())
    assert "--json-schema" in command
    assert command[-2:] == ["-p", "safe prompt"]


def test_discovery_always_includes_available_mock() -> None:
    providers = ProviderDiscovery(
        {"codex": "Z:/does-not-exist", "claude": "Z:/does-not-exist"}
    ).discover()
    mock = next(item for item in providers if item.provider_id == "mock")
    assert mock.available and mock.verification_status == "verified"


def test_missing_independent_reviewer_blocks() -> None:
    only = [
        ProviderDiagnostic(
            "mock", "Mock", True, None, "1", "verified", ProviderCapabilities()
        )
    ]
    with pytest.raises(RuntimeError, match="independent"):
        route_provider(
            RoutingRequest("reviewer", "high", "authentication", frozenset({"mock"})),
            only,
        )


def test_qwen_review_routes_to_non_qwen_provider() -> None:
    providers = [
        ProviderDiagnostic(
            "ollama", "Qwen", True, "ollama", "1", "detected", ProviderCapabilities()
        ),
        ProviderDiagnostic(
            "codex", "Codex", True, "codex", "1", "detected", ProviderCapabilities()
        ),
    ]
    result = route_provider(
        RoutingRequest("reviewer", "high", "architecture", frozenset({"ollama"}), True),
        providers,
    )
    assert result.provider_id == "codex"


def test_ollama_http_client_rejects_non_loopback_endpoint() -> None:
    with pytest.raises(RuntimeError, match="loopback"):
        HttpOllamaClient().models("https://example.com", 1)
