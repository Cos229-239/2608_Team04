from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from keeper.models.finding import Finding, Severity
from keeper.recovery import atomic_write_json, load_json


BLOCKING_SEVERITIES = frozenset({Severity.CRITICAL, Severity.HIGH})


def parse_review_output(value: dict[str, Any]) -> list[Finding]:
    raw_findings = value.get("findings")
    if not isinstance(raw_findings, list):
        raise ValueError("review output must contain a findings array")
    return [Finding.from_dict(item) for item in raw_findings]


def blocking_findings(findings: list[Finding]) -> list[Finding]:
    return [finding for finding in findings if finding.severity in BLOCKING_SEVERITIES]


def validate_post_repair_review(
    value: dict[str, Any], original_blockers: list[Finding]
) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings = parse_review_output(value)
    raw_dispositions = value.get("dispositions")
    if not isinstance(raw_dispositions, list) or not all(
        isinstance(item, dict) for item in raw_dispositions
    ):
        raise ValueError("post-repair review must contain a dispositions array")
    dispositions = [dict(item) for item in raw_dispositions]
    expected_ids = {finding.finding_id for finding in original_blockers}
    disposition_ids = [item.get("finding_id") for item in dispositions]
    if (
        len(disposition_ids) != len(expected_ids)
        or len(set(disposition_ids)) != len(disposition_ids)
        or set(disposition_ids) != expected_ids
        or any(item.get("status") != "resolved" for item in dispositions)
    ):
        raise ValueError("post-repair dispositions do not resolve each original blocker exactly once")
    if blocking_findings(findings):
        raise ValueError("post-repair review reported a new blocking finding")
    return findings, dispositions


def record_cleanup(findings: list[Finding], register_path: Path, task_id: str) -> None:
    deferred = [finding for finding in findings if finding.severity not in BLOCKING_SEVERITIES]
    if not deferred:
        return
    register = load_json(register_path, {"items": []})
    items = register.setdefault("items", [])
    for finding in deferred:
        items.append({"task_id": task_id, **finding.to_dict(), "status": "open"})
    atomic_write_json(register_path, register)
