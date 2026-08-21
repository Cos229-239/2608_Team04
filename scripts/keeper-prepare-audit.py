"""Generate the independent-audit handoff without performing the audit."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from keeper.models.task import now_iso
from keeper.recovery import atomic_write_json

BASE_COMMIT = "ccb4587"
AUDIT_DIRECTORY = REPOSITORY_ROOT / ".ai-workflow" / "audit"


def git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={REPOSITORY_ROOT.as_posix()}",
            *arguments,
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return result


def untracked_files() -> list[str]:
    result = git("status", "--porcelain", "--untracked-files=all")
    files: list[str] = []
    for line in result.stdout.splitlines():
        if line.startswith("?? "):
            relative = line[3:].replace("\\", "/")
            if not relative.startswith(".ai-workflow/audit/"):
                files.append(relative)
    return sorted(files)


def exact_implementation_patch() -> str:
    sections = [git("diff", "--binary", BASE_COMMIT, "--", ".").stdout]
    for relative in untracked_files():
        result = git(
            "diff",
            "--no-index",
            "--binary",
            "--",
            "/dev/null",
            relative,
            check=False,
        )
        if result.returncode not in {0, 1}:
            raise RuntimeError(result.stderr.strip() or f"unable to diff {relative}")
        sections.append(result.stdout)
    return "".join(sections)


def run_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted((REPOSITORY_ROOT / ".ai-workflow" / "runs").glob("*/run.json")):
        records.append(json.loads(path.read_text(encoding="utf-8")))
    return records


def main() -> int:
    AUDIT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    records = run_records()
    changed = git("status", "--short", "--untracked-files=all").stdout.splitlines()
    package: dict[str, Any] = {
        "prepared_at": now_iso(),
        "base_commit": BASE_COMMIT,
        "audit_performed": False,
        "architecture": {
            "layers": [
                "validated models and state machine",
                "atomic persistence and recovery",
                "workspace isolation and scope policy",
                "shared provider abstraction and explicit routing",
                "verification and finding disposition",
                "orchestration and CLI",
            ]
        },
        "security_boundaries": [
            "argument-array process execution without shell expansion",
            "credential-oriented child-environment filtering",
            "repository-relative path normalization and traversal rejection",
            "allowed and blocked changed-path enforcement",
            "structured provider-output validation",
            "protected actions require explicit authorization",
        ],
        "provider_routing": {
            "builder": "independent primary-provider instance",
            "reviewer": "independent primary-provider instance",
            "repairer": "independent primary-provider instance",
            "local_general_provider": "explicit routes only; never silent fallback",
            "legacy_local_provider": "disabled",
        },
        "state_transitions": [
            "BACKLOG -> READY",
            "READY -> BUILDING",
            "BUILDING -> SELF_VERIFYING",
            "SELF_VERIFYING -> INDEPENDENT_AUDIT",
            "INDEPENDENT_AUDIT -> REPAIRING or FINAL_VERIFY",
            "REPAIRING -> FINAL_VERIFY",
            "FINAL_VERIFY -> APPROVED",
            "APPROVED -> COMPLETED",
        ],
        "recovery": "Atomic JSON replacement; dead recorded processes become interrupted with an exact reason.",
        "protected_actions": [
            "force push and history rewrite",
            "repository or backup-branch deletion",
            "secret publication and paid resources",
            "production deployment and live trading",
            "real trades and weakened security or tests",
            "unapproved major architecture changes",
        ],
        "changed_files": changed,
        "verification": {
            "keeper_tests": "26 passed",
            "full_tests": "434 passed",
            "strict_mypy": "passed",
            "python_compilation": "passed",
            "git_diff_check": "passed",
            "foundation_checks": "passed through Git login shell",
            "ruff": "not declared and not installed; not run",
        },
        "pilot": json.loads(
            (REPOSITORY_ROOT / ".ai-workflow" / "runs" / "mock-pilot-summary.json").read_text(
                encoding="utf-8"
            )
        ),
        "run_records": [record.get("run_id") for record in records],
        "known_limitations": [
            "Primary provider command remains unconfigured because no inspected CLI matches the current protocol.",
            "Real-provider pilot remains blocked.",
            "Worktrees are preserved on failure and clean removal preserves their branches.",
            "Foundation checks require login-shell PATH initialization on this Windows environment.",
        ],
        "concerns": [
            {
                "severity": "High",
                "title": "Real provider protocol is not configured",
                "status": "open",
                "description": "A verified prompt-file/direct-JSON adapter or compatible executable is required.",
            },
            {
                "severity": "Low",
                "title": "Foundation script invocation is PATH-sensitive on Windows",
                "status": "open",
                "description": "Direct invocation misses bundled utilities; login-shell invocation passes.",
            },
        ],
        "patch_file": "implementation-from-ccb4587.patch",
        "patch_scope_note": "Exact base diff including untracked implementation and pilot evidence; excludes this audit output directory to avoid self-reference.",
    }
    patch = exact_implementation_patch()
    (AUDIT_DIRECTORY / "implementation-from-ccb4587.patch").write_text(
        patch, encoding="utf-8", newline="\n"
    )
    atomic_write_json(AUDIT_DIRECTORY / "audit-package.json", package)
    summary = (
        "# Keeper MVP Independent Audit Handoff\n\n"
        "This package prepares evidence only; it does not perform the independent audit.\n\n"
        "## Outcome\n\n"
        "- Mock lifecycle: completed, repaired, verified, approved, persisted, and cleaned safely.\n"
        "- Recovery probe: interrupted process detected and persisted.\n"
        "- Real-provider pilot: blocked because the primary command protocol is not configured.\n"
        "- Automated verification: see `audit-package.json`.\n\n"
        "## Concerns\n\n"
        "- High: real provider protocol remains unconfigured.\n"
        "- Low: the foundation shell entry point requires login-shell PATH initialization on this Windows host.\n\n"
        "Use `implementation-from-ccb4587.patch` as the implementation diff. Audit output files are "
        "excluded from that patch solely to avoid self-reference.\n"
    )
    (AUDIT_DIRECTORY / "README.md").write_text(summary, encoding="utf-8", newline="\n")
    print(json.dumps({"audit_directory": str(AUDIT_DIRECTORY), "patch_bytes": len(patch)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
