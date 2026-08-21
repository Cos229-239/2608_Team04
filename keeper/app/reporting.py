from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def finalize_evidence(directory: Path, report: dict[str, Any]) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "final-report.json"
    markdown_path = directory / "final-report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    files = []
    root = directory.resolve()
    for path in sorted(file for file in directory.rglob("*") if file.is_file()):
        if path.name == "evidence-index.json":
            continue
        if path.is_symlink():
            raise PermissionError("finalized evidence cannot contain symbolic links")
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise PermissionError("finalized evidence escapes the run directory")
        files.append(
            {
                "path": resolved.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
                "size": resolved.stat().st_size,
            }
        )
    index = {
        "schema_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "files": files,
    }
    (directory / "evidence-index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True), encoding="utf-8"
    )
    return index


def verify_evidence(directory: Path) -> None:
    index = json.loads((directory / "evidence-index.json").read_text(encoding="utf-8"))
    items = index.get("files")
    if not isinstance(items, list):
        raise RuntimeError("evidence index file list is malformed")
    paths = [str(item.get("path", "")) for item in items if isinstance(item, dict)]
    if len(paths) != len(items) or len(set(paths)) != len(paths):
        raise RuntimeError("evidence index contains duplicate or malformed paths")
    indexed = set(paths)
    actual = {
        path.resolve().relative_to(directory.resolve()).as_posix()
        for path in directory.rglob("*")
        if path.is_file() and path.name != "evidence-index.json"
    }
    if indexed != actual:
        raise RuntimeError("evidence index file set is incomplete or stale")
    for item in items:
        path = (directory / item["path"]).resolve()
        if not path.is_relative_to(directory.resolve()) or not path.is_file():
            raise RuntimeError("evidence index contains an unsafe or missing file")
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise RuntimeError(f"evidence tampering detected: {item['path']}")


def verify_protected_evidence(
    directory: Path,
    protected: dict[str, Any],
) -> dict[str, Any]:
    root = directory.resolve(strict=True)
    if protected.get("kind") != "evidence_finalization":
        raise RuntimeError("protected evidence finalization record is malformed")
    protected_files = protected.get("files")
    if not isinstance(protected_files, list):
        raise RuntimeError("protected evidence file set is malformed")
    paths = [
        str(item.get("path", ""))
        for item in protected_files
        if isinstance(item, dict)
    ]
    if len(paths) != len(protected_files) or len(set(paths)) != len(paths):
        raise RuntimeError("protected evidence contains duplicate or malformed paths")
    actual_paths = {
        path.resolve().relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }
    if set(paths) != actual_paths:
        raise RuntimeError("protected evidence file set does not match disk")
    for item in protected_files:
        relative = str(item["path"])
        target = root / relative
        if target.is_symlink():
            raise RuntimeError("protected evidence contains a symbolic link")
        resolved = target.resolve(strict=True)
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise RuntimeError("protected evidence path is unsafe or missing")
        content = resolved.read_bytes()
        if (
            len(content) != item.get("size")
            or hashlib.sha256(content).hexdigest() != item.get("sha256")
        ):
            raise RuntimeError(f"protected evidence tampering detected: {relative}")
    index_path = root / "evidence-index.json"
    manifest_digest = hashlib.sha256(index_path.read_bytes()).hexdigest()
    if manifest_digest != protected.get("manifest_digest"):
        raise RuntimeError("protected finalized manifest digest does not match")
    verify_evidence(root)
    mandatory = protected.get("mandatory_paths")
    if not isinstance(mandatory, list) or not set(
        str(item) for item in mandatory
    ).issubset(actual_paths):
        raise RuntimeError("mandatory evidence set is incomplete")
    report = json.loads((root / "final-report.json").read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise RuntimeError("final report is not a JSON object")
    critical = protected.get("critical_report_fields")
    if not isinstance(critical, dict) or any(
        report.get(key) != value for key, value in critical.items()
    ):
        raise RuntimeError("final report conflicts with protected Keeper state")
    markdown = (root / "final-report.md").read_text(encoding="utf-8")
    if markdown != render_markdown(report):
        raise RuntimeError("JSON and Markdown reports are inconsistent")
    return report


def render_markdown(report: dict[str, Any]) -> str:
    sections = [
        "# Keeper Run Report",
        "",
        "| Field | Value |",
        "| --- | --- |",
    ]
    for key in (
        "schema_version",
        "run_id",
        "task_id",
        "objective",
        "repository",
        "worktree",
        "branch",
        "baseline",
        "provider_policy",
        "start_time",
        "end_time",
        "terminal_status",
        "failure_reason",
    ):
        value = report.get(key, "")
        if value is None:
            value = ""
        display = str(value).replace("|", "\\|")
        sections.append(f"| {key.replace('_', ' ').title()} | {display} |")
    sections.append("")
    defaults: dict[str, object] = {
        "scope": {},
        "provider_identities": {},
        "routing_rationale": [],
        "routing_attempts": [],
        "lifecycle_stages": [],
        "authorizations": [],
        "waivers": [],
        "commands": [],
        "verification_results": [],
        "findings": [],
        "dispositions": [],
        "repairs": [],
        "post_repair_findings": [],
        "approval_result": {},
        "commit_result": {},
        "push_result": {},
        "logs": [],
        "artifacts": [],
        "evidence_paths": [],
        "evidence_hashes": [],
        "unresolved_observations": [],
    }
    for key, default in defaults.items():
        value = report.get(key, default)
        if value is None:
            value = default
        sections.extend(
            [
                f"## {key.replace('_', ' ').title()}",
                "",
                "```json",
                json.dumps(value, indent=2, sort_keys=True),
                "```",
                "",
            ]
        )
    return "\n".join(sections)
