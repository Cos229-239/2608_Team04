from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
import uuid
from typing import Any, Callable


@dataclass(frozen=True, slots=True)
class AgentRequest:
    role: str
    prompt_path: Path
    workspace: Path
    timeout_seconds: int
    stdout_path: Path
    stderr_path: Path
    reasoning_level: str = "medium"
    on_process_started: Callable[[int], None] | None = None
    on_process_owned: Callable[[dict[str, Any]], None] | None = None
    authority_attempt_id: str | None = None


@dataclass(frozen=True, slots=True)
class ProcessResult:
    exit_code: int
    stdout_path: Path
    stderr_path: Path
    process_id: int | None = None
    timed_out: bool = False
    output: dict[str, object] = field(default_factory=dict)


class AgentProvider(ABC):
    provider_name = "primary"
    instance_id = uuid.uuid4().hex
    requires_authority_service = True

    @abstractmethod
    def validate(self) -> None: ...

    @abstractmethod
    def run(self, request: AgentRequest) -> ProcessResult: ...
