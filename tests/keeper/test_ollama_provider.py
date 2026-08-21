from pathlib import Path

import pytest

from keeper.providers.base import AgentRequest
from keeper.providers.mock import MockProvider
from keeper.providers.ollama import MockOllamaClient, OllamaProvider
from keeper.providers.routing import ProviderRouter


def request(tmp_path: Path) -> AgentRequest:
    prompt = tmp_path / "prompt.md"
    prompt.write_text("Review the documentation.", encoding="utf-8")
    return AgentRequest(
        "documentation_reviewer",
        prompt,
        tmp_path,
        5,
        tmp_path / "stdout.log",
        tmp_path / "stderr.log",
    )


def test_ollama_availability_validation() -> None:
    provider = OllamaProvider(client=MockOllamaClient([], {}))
    with pytest.raises(RuntimeError, match="unavailable"):
        provider.validate()


def test_ollama_structured_output(tmp_path: Path) -> None:
    client = MockOllamaClient(
        ["qwen3-coder:30b"],
        {"response": '{"status":"completed","findings":[]}'},
    )
    result = OllamaProvider(client=client).run(request(tmp_path))
    assert result.exit_code == 0
    assert result.output["status"] == "completed"


def test_ollama_invalid_output_fails_closed(tmp_path: Path) -> None:
    client = MockOllamaClient(["qwen3-coder:30b"], {"response": "not json"})
    result = OllamaProvider(client=client).run(request(tmp_path))
    assert result.exit_code == 1


def test_routing_never_falls_back() -> None:
    router = ProviderRouter({"primary": MockProvider()}, {"builder": "missing"})
    with pytest.raises(RuntimeError, match="unavailable"):
        router.for_role("builder")


def test_disabled_local_model_cannot_be_final_reviewer() -> None:
    local = MockProvider(provider_name="qwen2.5-coder:14b")
    router = ProviderRouter({"ollama": local}, {"reviewer": "ollama"})
    with pytest.raises(PermissionError, match="disabled"):
        router.for_role("reviewer")


def test_author_and_reviewer_routes_have_distinct_contexts() -> None:
    builder = MockProvider(provider_name="primary")
    reviewer = MockProvider(provider_name="primary")
    router = ProviderRouter(
        {"builder": builder, "reviewer": reviewer},
        {"builder": "builder", "reviewer": "reviewer"},
    )
    assert router.for_role("builder").instance_id != router.for_role("reviewer").instance_id
