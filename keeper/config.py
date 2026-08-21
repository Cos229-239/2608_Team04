from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class KeeperConfig:
    repository_root: Path
    state_root: Path
    workspace_root: Path
    provider_command: tuple[str, ...]
    provider_registration: dict[str, Any] | None = None
    provider_qualification_reference: str | None = None
    ollama_endpoint: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3-coder:30b"
    provider_routes: tuple[tuple[str, str], ...] = (
        ("builder", "primary_builder"),
        ("reviewer", "primary_reviewer"),
        ("repairer", "primary_repairer"),
        ("post_repair_reviewer", "primary_post_repair_reviewer"),
        ("preliminary_reviewer", "ollama"),
        ("documentation_reviewer", "ollama"),
    )
    process_timeout_seconds: int = 1800
    maximum_repair_passes: int = 1
    maximum_process_restarts: int = 2
    auto_commit: bool = False

    @classmethod
    def load(cls, repository_root: Path) -> KeeperConfig:
        path = repository_root / ".ai-workflow" / "config.json"
        data: dict[str, Any] = {}
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
        if "provider_qualification_evidence" in data:
            raise PermissionError(
                "raw provider qualification evidence is not accepted from "
                "desktop configuration"
            )
        state_root = repository_root / ".ai-workflow"
        workspace = Path(data.get("workspace_root", repository_root.parent / f"{repository_root.name}.keeper-worktrees"))
        command = tuple(data.get("provider_command", []))
        return cls(
            repository_root=repository_root.resolve(),
            state_root=state_root.resolve(),
            workspace_root=workspace.resolve(),
            provider_command=command,
            provider_registration=(
                dict(data["provider_registration"])
                if isinstance(data.get("provider_registration"), dict)
                else None
            ),
            provider_qualification_reference=(
                str(data["provider_qualification_reference"])
                if isinstance(data.get("provider_qualification_reference"), str)
                else None
            ),
            ollama_endpoint=str(data.get("ollama_endpoint", "http://127.0.0.1:11434")),
            ollama_model=str(data.get("ollama_model", "qwen3-coder:30b")),
            provider_routes=tuple(
                (str(role), str(provider))
                for role, provider in data.get(
                    "provider_routes",
                    {
                        "builder": "primary_builder",
                        "reviewer": "primary_reviewer",
                        "repairer": "primary_repairer",
                        "post_repair_reviewer": "primary_post_repair_reviewer",
                        "preliminary_reviewer": "ollama",
                        "documentation_reviewer": "ollama",
                    },
                ).items()
            ),
            process_timeout_seconds=int(data.get("process_timeout_seconds", 1800)),
            maximum_repair_passes=int(data.get("maximum_repair_passes", 1)),
            maximum_process_restarts=int(data.get("maximum_process_restarts", 2)),
            auto_commit=bool(data.get("auto_commit", False)),
        )
