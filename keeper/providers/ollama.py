from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import urlparse
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from keeper.providers.base import AgentProvider, AgentRequest, ProcessResult


class OllamaClient(Protocol):
    def models(self, endpoint: str, timeout: int) -> list[str]: ...
    def generate(self, endpoint: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]: ...


class HttpOllamaClient:
    MAX_RESPONSE_BYTES = 4 * 1024 * 1024

    @staticmethod
    def _request(url: str, timeout: int, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        parsed = urlparse(url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeError("Ollama endpoint must use unencrypted loopback HTTP")
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST" if body is not None else "GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read(HttpOllamaClient.MAX_RESPONSE_BYTES + 1)
                if len(raw) > HttpOllamaClient.MAX_RESPONSE_BYTES:
                    raise RuntimeError("Ollama response exceeded the configured size limit")
                value = json.loads(raw.decode("utf-8"))
        except urllib.error.URLError as error:
            raise RuntimeError(f"unable to connect to local Ollama service at {url}: {error.reason}") from error
        except (TimeoutError, json.JSONDecodeError) as error:
            raise RuntimeError(f"invalid or timed-out response from local Ollama service: {error}") from error
        if not isinstance(value, dict):
            raise RuntimeError("local Ollama service returned a non-object response")
        return value

    def models(self, endpoint: str, timeout: int) -> list[str]:
        value = self._request(f"{endpoint.rstrip('/')}/api/tags", timeout)
        models = value.get("models", [])
        return [str(item["name"]) for item in models if isinstance(item, dict) and "name" in item]

    def generate(self, endpoint: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
        return self._request(f"{endpoint.rstrip('/')}/api/generate", timeout, payload)


@dataclass
class MockOllamaClient:
    available_models: list[str]
    response: dict[str, Any]
    failure: RuntimeError | None = None

    def models(self, endpoint: str, timeout: int) -> list[str]:
        if self.failure:
            raise self.failure
        return self.available_models

    def generate(self, endpoint: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
        if self.failure:
            raise self.failure
        return self.response


class OllamaProvider(AgentProvider):
    def __init__(
        self,
        model: str = "qwen3-coder:30b",
        endpoint: str = "http://127.0.0.1:11434",
        client: OllamaClient | None = None,
    ) -> None:
        self.model = model
        self.provider_name = model
        self.instance_id = uuid.uuid4().hex
        self.endpoint = endpoint
        self.client = client or HttpOllamaClient()

    def validate(self) -> None:
        models = self.client.models(self.endpoint, 10)
        if self.model not in models:
            raise RuntimeError(
                f"configured Ollama model is unavailable: {self.model}; "
                f"available models: {', '.join(models) or 'none'}"
            )

    def run(self, request: AgentRequest) -> ProcessResult:
        self.validate()
        prompt = request.prompt_path.read_text(encoding="utf-8")
        request.stdout_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            response = self.client.generate(
                self.endpoint,
                {"model": self.model, "prompt": prompt, "stream": False, "format": "json"},
                request.timeout_seconds,
            )
            raw = response.get("response")
            if not isinstance(raw, str):
                raise RuntimeError("Ollama response is missing the structured response field")
            output = json.loads(raw)
            if not isinstance(output, dict) or "status" not in output:
                raise RuntimeError("Ollama model output must be a JSON object with status")
            request.stdout_path.write_text(json.dumps(output), encoding="utf-8")
            request.stderr_path.write_text("", encoding="utf-8")
            return ProcessResult(0, request.stdout_path, request.stderr_path, output=output)
        except (json.JSONDecodeError, RuntimeError) as error:
            request.stdout_path.write_text("", encoding="utf-8")
            request.stderr_path.write_text(str(error), encoding="utf-8")
            return ProcessResult(1, request.stdout_path, request.stderr_path)
