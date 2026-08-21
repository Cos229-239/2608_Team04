from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from keeper.state_machine import TaskStatus


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class Task:
    id: str
    title: str
    description: str
    phase: str
    sequence: int
    status: TaskStatus = TaskStatus.BACKLOG
    priority: int = 100
    risk: str = "low"
    component: str = "keeper"
    dependencies: list[str] = field(default_factory=list)
    acceptance_criteria: list[str] = field(default_factory=list)
    verification_commands: list[list[str]] = field(default_factory=list)
    final_verification_commands: list[list[str]] = field(default_factory=list)
    verification_specs: list[dict[str, Any]] = field(default_factory=list)
    final_verification_specs: list[dict[str, Any]] = field(default_factory=list)
    verification_waivers: list[dict[str, Any]] = field(default_factory=list)
    required_verification_categories: list[str] = field(default_factory=lambda: ["task"])
    capabilities: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=lambda: ["keeper/"])
    blocked_paths: list[str] = field(default_factory=list)
    maximum_attempts: int = 2
    provider: str = "primary"
    size: str = "small"
    created_timestamp: str = field(default_factory=now_iso)
    updated_timestamp: str = field(default_factory=now_iso)
    attempts: int = 0
    transition_history: list[dict[str, str]] = field(default_factory=list)
    active_attempt_id: str | None = None
    active_run_stage: str | None = None
    workspace_path: str | None = None
    branch_name: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Task:
        required = {"id", "title", "description", "phase", "sequence"}
        missing = sorted(required - data.keys())
        if missing:
            raise ValueError(f"task is missing required fields: {', '.join(missing)}")
        values = dict(data)
        values["status"] = TaskStatus(values.get("status", "BACKLOG"))
        commands = values.get("verification_commands", [])
        if not all(isinstance(command, list) and command for command in commands):
            raise ValueError("verification_commands must be non-empty argument arrays")
        final_commands = values.get("final_verification_commands", [])
        if not all(isinstance(command, list) and command for command in final_commands):
            raise ValueError("final_verification_commands must be non-empty argument arrays")
        for field_name in ("verification_specs", "final_verification_specs"):
            specs = values.get(field_name, [])
            if not isinstance(specs, list) or not all(isinstance(spec, dict) for spec in specs):
                raise ValueError(f"{field_name} must be an object array")
        categories = values.get("required_verification_categories", ["task"])
        if not isinstance(categories, list) or not categories or not all(
            isinstance(category, str) and category.strip() for category in categories
        ):
            raise ValueError("required_verification_categories must be a non-empty string array")
        if commands and len(commands) < len(categories):
            raise ValueError("verification_commands do not cover all required verification categories")
        capabilities = values.get("capabilities", [])
        if not isinstance(capabilities, list) or not all(
            isinstance(capability, str) and capability.strip() for capability in capabilities
        ):
            raise ValueError("capabilities must be a string array")
        if int(values.get("maximum_attempts", 2)) < 1:
            raise ValueError("maximum_attempts must be positive")
        return cls(**values)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        return result
