from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from keeper.models.finding import Finding
from keeper.models.task import now_iso


@dataclass(slots=True)
class RunRecord:
    run_id: str
    task_id: str
    role: str
    provider_name: str = ""
    provider_instance_id: str = ""
    provider_logical_id: str | None = None
    keeper_run_id: str | None = None
    stage_id: str | None = None
    attempt_number: int | None = None
    retry_parent: str | None = None
    stable_registration_digest: str | None = None
    executable_path: str | None = None
    executable_sha256: str | None = None
    configuration_digest: str | None = None
    endpoint_identity: str | None = None
    authentication_mode: str | None = None
    capability_set: dict[str, Any] | None = None
    provider_policy: str | None = None
    independence_classification: str | None = None
    launch_nonce: str | None = None
    ownership_token: str | None = None
    authority_attempt_id: str | None = None
    evidence_path: str | None = None
    reasoning_level: str = "medium"
    start_time: str = field(default_factory=now_iso)
    end_time: str | None = None
    status: str = "running"
    process_exit_code: int | None = None
    process_id: int | None = None
    process_ownership: dict[str, Any] | None = None
    workspace_path: str = ""
    branch_name: str = ""
    prompt_path: str = ""
    stdout_log_path: str = ""
    stderr_log_path: str = ""
    files_changed: list[str] = field(default_factory=list)
    verification_result: dict[str, Any] | None = None
    review_findings: list[Finding] = field(default_factory=list)
    retry_count: int = 0
    failure_reason: str | None = None
    accepted_findings: list[dict[str, Any]] = field(default_factory=list)
    rejected_findings: list[dict[str, Any]] = field(default_factory=list)
    repair_history: list[str] = field(default_factory=list)
    final_approval_authority: str | None = None
    review_tree_identity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["review_findings"] = [item.to_dict() for item in self.review_findings]
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RunRecord:
        data = dict(value)
        data["review_findings"] = [
            Finding.from_dict(item) if isinstance(item, dict) else item
            for item in data.get("review_findings", [])
        ]
        fields = cls.__dataclass_fields__
        return cls(**{key: item for key, item in data.items() if key in fields})
