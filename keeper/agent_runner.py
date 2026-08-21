from __future__ import annotations

import json
import hashlib
import uuid
import re
from pathlib import Path
from typing import Any, Callable

from keeper.models.run import RunRecord
from keeper.models.task import Task, now_iso
from keeper.providers.base import AgentProvider, AgentRequest
from keeper.provider_output import validate_provider_output
from keeper.recovery import atomic_write_json
from keeper.app.path_safety import validate_path_budget


class AgentRunner:
    def __init__(
        self,
        provider: AgentProvider,
        runs_directory: Path,
        timeout_seconds: int,
        maximum_output_bytes: int = 1_048_576,
        keeper_run_id: str | None = None,
        ownership_sink: Callable[[dict[str, Any]], None] | None = None,
        execution_sink: Callable[
            [dict[str, Any]], dict[str, Any] | None
        ]
        | None = None,
        execution_authority: dict[str, Any] | None = None,
    ) -> None:
        self.provider = provider
        self.runs_directory = runs_directory
        self.timeout_seconds = timeout_seconds
        self.maximum_output_bytes = maximum_output_bytes
        self.keeper_run_id = keeper_run_id
        self.ownership_sink = ownership_sink
        self.execution_sink = execution_sink
        self.execution_authority = execution_authority or {}

    def run(
        self,
        task: Task,
        role: str,
        workspace: Path,
        branch: str,
        prompt: str,
        retry: int = 0,
        reasoning_level: str = "medium",
    ) -> RunRecord:
        role_label = {
            "builder": "b",
            "reviewer": "v",
            "repairer": "r",
            "post_repair_reviewer": "p",
        }.get(role, "x")
        run_id = f"pr-{role_label}-{uuid.uuid4().hex[:8]}"
        directory = self.runs_directory / run_id
        validate_path_budget(directory / "stderr.log", purpose="provider evidence path")
        directory.mkdir(parents=True, exist_ok=False)
        prompt_path = directory / "prompt.md"
        stdout_path = directory / "stdout.log"
        stderr_path = directory / "stderr.log"
        prompt_path.write_text(prompt, encoding="utf-8")
        record = RunRecord(
            run_id=run_id,
            task_id=task.id,
            role=role,
            provider_name=self.provider.provider_name,
            provider_instance_id=self.provider.instance_id,
            reasoning_level=reasoning_level,
            workspace_path=str(workspace),
            branch_name=branch,
            prompt_path=str(prompt_path),
            stdout_log_path=str(stdout_path),
            stderr_log_path=str(stderr_path),
            retry_count=retry,
            keeper_run_id=self.keeper_run_id,
            stage_id=task.active_run_stage,
            attempt_number=self.execution_authority.get("attempt_number"),
            retry_parent=self.execution_authority.get("retry_parent"),
        )
        record_path = directory / "run.json"
        registration = getattr(self.provider, "registration", None)
        if isinstance(registration, dict):
            record.stable_registration_digest = hashlib.sha256(
                json.dumps(
                    registration, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            record.provider_logical_id = str(
                registration.get("logical_provider_id") or ""
            )
            record.executable_path = str(
                registration.get("canonical_executable_path") or ""
            )
            record.executable_sha256 = str(
                registration.get("executable_sha256") or ""
            )
            record.configuration_digest = str(
                registration.get("configuration_digest") or ""
            )
            record.endpoint_identity = str(
                registration.get("endpoint_identity") or ""
            )
            record.authentication_mode = str(
                registration.get("authentication_mode") or ""
            )
            capabilities = registration.get("capability_set")
            record.capability_set = (
                dict(capabilities) if isinstance(capabilities, dict) else None
            )
            record.provider_policy = str(
                registration.get("provider_policy") or ""
            )
            record.independence_classification = str(
                registration.get("independence_classification") or ""
            )
        record.evidence_path = str(record_path.resolve())
        atomic_write_json(record_path, record.to_dict())
        execution_authorization: dict[str, Any] = {}
        if self.execution_sink is not None:
            execution_authorization = (
                self.execution_sink(
                    {
                        "event": "started",
                        "provider_run_id": run_id,
                        "task_id": task.id,
                        "stage_id": task.active_run_stage,
                        "role": role,
                        "retry_count": retry,
                        "provider_name": self.provider.provider_name,
                        "provider_instance_id": self.provider.instance_id,
                        "authority_required": bool(
                            self.provider.requires_authority_service
                        ),
                        "start_time": record.start_time,
                        "evidence_path": str(record_path.resolve()),
                        "prompt_path": str(prompt_path.resolve()),
                        "stdout_path": str(stdout_path.resolve()),
                        "stderr_path": str(stderr_path.resolve()),
                        "workspace": str(workspace.resolve()),
                        "timeout_seconds": self.timeout_seconds,
                        "reasoning_level": reasoning_level,
                    }
                )
                or {}
            )
            attempt_id = execution_authorization.get("attempt_id")
            if attempt_id is not None and not isinstance(attempt_id, str):
                raise PermissionError(
                    "provider authority attempt identity is malformed"
                )
            record.authority_attempt_id = attempt_id
            atomic_write_json(record_path, record.to_dict())

        def process_started(process_id: int) -> None:
            record.process_id = process_id
            atomic_write_json(record_path, record.to_dict())

        def process_owned(ownership: dict[str, object]) -> None:
            record.launch_nonce = str(ownership.get("launch_nonce") or "")
            record.ownership_token = str(ownership.get("ownership_token") or "")
            record.process_ownership = {
                **ownership,
                "keeper_run_id": self.keeper_run_id,
                "task_id": task.id,
                "provider_run_id": run_id,
                "stage_id": task.active_run_stage,
                        "provider_name": self.provider.provider_name,
                        "provider_instance_id": self.provider.instance_id,
                        "authority_required": bool(
                            self.provider.requires_authority_service
                        ),
                "role": role,
                "evidence_path": str(directory.resolve()),
            }
            if self.ownership_sink is not None:
                self.ownership_sink(dict(record.process_ownership))
            atomic_write_json(record_path, record.to_dict())

        result = self.provider.run(
            AgentRequest(
                role,
                prompt_path,
                workspace,
                self.timeout_seconds,
                stdout_path,
                stderr_path,
                reasoning_level,
                process_started,
                process_owned,
                record.authority_attempt_id,
            )
        )
        for log_path in (stdout_path, stderr_path):
            if log_path.exists():
                content = log_path.read_text(encoding="utf-8", errors="replace")
                redacted = re.sub(
                    r"(?i)(token|secret|password|passwd|api[_-]?key|credential)(\s*[:=]\s*)\S+",
                    r"\1\2[REDACTED]",
                    content,
                )
                log_path.write_text(redacted, encoding="utf-8")
        record.end_time = now_iso()
        record.process_exit_code = result.exit_code
        record.process_id = result.process_id
        record.status = "completed" if result.exit_code == 0 else "failed"
        if result.exit_code:
            record.failure_reason = "agent process timed out" if result.timed_out else "agent process failed"
        if stderr_path.exists() and stderr_path.stat().st_size > self.maximum_output_bytes:
            record.status = "failed"
            record.process_exit_code = 65
            record.failure_reason = "provider stderr exceeds configured size limit"
        if result.exit_code == 0:
            try:
                raw = (
                    json.dumps(result.output)
                    if result.output
                    else stdout_path.read_text(encoding="utf-8")
                )
                output = validate_provider_output(role, raw, self.maximum_output_bytes)
                changed = output["files_changed"]
                record.files_changed = [str(item) for item in changed]
            except (OSError, ValueError) as error:
                record.status = "failed"
                record.process_exit_code = 65
                record.failure_reason = f"invalid structured provider output: {error}"
        atomic_write_json(record_path, record.to_dict())
        if self.execution_sink is not None:
            self.execution_sink(
                {
                    "event": "finished",
                    "provider_run_id": run_id,
                    "task_id": task.id,
                    "stage_id": task.active_run_stage,
                    "role": role,
                    "provider_name": self.provider.provider_name,
                    "provider_instance_id": self.provider.instance_id,
                    "finish_time": record.end_time,
                    "result": record.status,
                    "process_exit_code": record.process_exit_code,
                    "failure_reason": record.failure_reason,
                    "evidence_path": str(record_path.resolve()),
                }
            )
        return record
