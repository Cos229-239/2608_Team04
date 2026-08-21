from __future__ import annotations

import json
from typing import Any


SUCCESS_STATUSES = frozenset({"completed", "resolved"})


def validate_provider_output(role: str, raw: str, maximum_bytes: int) -> dict[str, Any]:
    encoded = raw.encode("utf-8")
    if not encoded:
        raise ValueError("provider output is empty")
    if len(encoded) > maximum_bytes:
        raise ValueError("provider stdout exceeds configured size limit")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"provider output is not exactly one JSON object: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("provider output must be a JSON object")
    status = value.get("status")
    if status not in SUCCESS_STATUSES:
        raise ValueError(f"unsupported provider status: {status}")
    if value.get("failure_reason") or value.get("error"):
        raise ValueError("successful provider output contains failure details")
    changed = value.get("files_changed")
    if not isinstance(changed, list) or not all(isinstance(item, str) for item in changed):
        raise ValueError("provider output requires a files_changed string array")
    if role in {"reviewer", "post_repair_reviewer"}:
        findings = value.get("findings")
        if not isinstance(findings, list):
            raise ValueError("review output requires a findings array")
        for finding in findings:
            if not isinstance(finding, dict) or not isinstance(finding.get("finding_id"), str):
                raise ValueError("every review finding requires a stable finding_id")
        if role == "post_repair_reviewer":
            dispositions = value.get("dispositions")
            if not isinstance(dispositions, list):
                raise ValueError("post-repair review requires a dispositions array")
            for disposition in dispositions:
                if (
                    not isinstance(disposition, dict)
                    or not isinstance(disposition.get("finding_id"), str)
                    or disposition.get("status") not in {"resolved", "open"}
                    or not isinstance(disposition.get("justification"), str)
                    or not disposition["justification"].strip()
                ):
                    raise ValueError("invalid post-repair finding disposition")
    return value
