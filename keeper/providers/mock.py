from __future__ import annotations

import json
import uuid
from pathlib import Path

from keeper.policies import resolve_within
from keeper.providers.base import AgentProvider, AgentRequest, ProcessResult


class MockProvider(AgentProvider):
    requires_authority_service = False

    def __init__(
        self,
        exit_code: int = 0,
        output: dict[str, object] | None = None,
        provider_name: str = "mock",
        file_writes: dict[str, str] | None = None,
    ) -> None:
        self.exit_code = exit_code
        self.output = output or {"status": "completed", "files_changed": []}
        self.provider_name = provider_name
        self.instance_id = uuid.uuid4().hex
        self.file_writes = file_writes or {}
        self.requests: list[AgentRequest] = []

    def validate(self) -> None:
        return

    def run(self, request: AgentRequest) -> ProcessResult:
        self.requests.append(request)
        for relative, content in self.file_writes.items():
            target = resolve_within(request.workspace, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        request.stdout_path.parent.mkdir(parents=True, exist_ok=True)
        request.stdout_path.write_text(json.dumps(self.output), encoding="utf-8")
        request.stderr_path.write_text("", encoding="utf-8")
        return ProcessResult(
            self.exit_code,
            request.stdout_path,
            request.stderr_path,
            output=self.output,
        )
