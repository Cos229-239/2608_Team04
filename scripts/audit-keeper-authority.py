from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from keeper.authority_service.client import (
    DEFAULT_PIPE_NAME,
    AuthorityServiceClient,
)
from keeper.authority_service.provenance import (
    AUDIT_REPORT_PURPOSE,
    source_package_content_sha256,
)


_COMMIT = re.compile(r"[0-9a-f]{40}")


def verify_live_provenance(
    *,
    expected_source_commit: str,
    source_root: Path,
    client: AuthorityServiceClient,
    service_query: Callable[[], dict[str, str]],
    protected_read_denied: Callable[[Path], bool],
) -> dict[str, Any]:
    if not _COMMIT.fullmatch(expected_source_commit):
        raise ValueError("expected source commit must be a full SHA-1")
    source_root = source_root.resolve(strict=True)
    report = client.audit_provenance()
    if not client.verify(AUDIT_REPORT_PURPOSE, report):
        raise PermissionError(
            "Authority provenance report authentication is invalid"
        )
    reported_commit = str(
        report["package_source_provenance"]["installed_source_commit"]
    )
    if reported_commit != expected_source_commit:
        raise PermissionError(
            "installed Authority source commit differs from candidate"
        )
    repository_commit = _git_head(source_root)
    if repository_commit != expected_source_commit:
        raise PermissionError(
            "candidate repository HEAD differs from expected commit"
        )
    candidate_content_digest = source_package_content_sha256(source_root)
    if report["package"]["content_sha256"] != candidate_content_digest:
        raise PermissionError(
            "installed Authority package content differs from candidate source"
        )
    if report["overall_result"] != "PASS":
        raise PermissionError(
            f"Authority provenance result is {report['overall_result']}"
        )
    if any(
        item.get("result") != "PASS"
        for item in report["artifact_results"]
    ):
        raise PermissionError(
            "one or more Authority provenance artifacts did not pass"
        )
    query = service_query()
    qc = query["configuration"].casefold()
    state = query["state"].casefold()
    service = report["service"]
    if (
        "running" not in state
        or str(service["account_name"]).casefold() not in qc
        or str(service["binary_path"]).casefold() not in qc
        or "demand_start" not in qc
    ):
        raise PermissionError(
            "live Windows service configuration differs from report"
        )
    manifest_path = Path(str(report["machine_manifest"]["path"]))
    if not protected_read_denied(manifest_path):
        raise PermissionError(
            "protected Authority manifest is directly readable"
        )
    return {
        "audit_operation_id": report["audit_operation_id"],
        "generated_at": report["generated_at"],
        "expected_source_commit": expected_source_commit,
        "reported_source_commit": reported_commit,
        "candidate_package_content_sha256": candidate_content_digest,
        "installed_package_sha256": report["package"]["sha256"],
        "machine_manifest_sha256": report["machine_manifest"]["sha256"],
        "configuration_sha256": report["configuration"]["sha256"],
        "service_name": service["name"],
        "service_account": service["account_name"],
        "service_account_sid": service["account_sid"],
        "provider_account": report["identities"][
            "provider_account_name"
        ],
        "provider_account_sid": report["identities"][
            "provider_account_sid"
        ],
        "authority_key_id": report["authority_key"]["key_id"],
        "authority_key_version": report["authority_key"]["key_version"],
        "database_schema_sha256": report["database_schema"][
            "schema_sha256"
        ],
        "acl_policy_sha256": report["acl_policy"][
            "expected_policy_sha256"
        ],
        "live_acl_policy_sha256": report["acl_policy"][
            "live_policy_sha256"
        ],
        "report_authentication": "PASS",
        "request_binding": "PASS",
        "candidate_source_match": "PASS",
        "windows_service_query": "PASS",
        "protected_root_direct_read": "DENIED",
        "overall_result": "PASS",
        "report": report,
    }


def _git_head(source_root: Path) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={source_root.as_posix()}",
            "-C",
            str(source_root),
            "rev-parse",
            "HEAD",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        timeout=30,
    )
    if result.returncode:
        raise OSError("candidate repository commit is unavailable")
    return result.stdout.strip()


def _windows_service_query() -> dict[str, str]:
    configuration = _run_sc(["qc", "KeeperAuthority"])
    state = _run_sc(["query", "KeeperAuthority"])
    return {"configuration": configuration, "state": state}


def _run_sc(arguments: list[str]) -> str:
    result = subprocess.run(
        ["sc.exe", *arguments],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
        timeout=30,
    )
    if result.returncode:
        raise OSError("KeeperAuthority service query failed")
    return result.stdout


def _protected_read_denied(path: Path) -> bool:
    try:
        path.read_bytes()
    except PermissionError:
        return True
    except OSError:
        return True
    return False


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="audit-keeper-authority")
    result.add_argument("--expected-source-commit", required=True)
    result.add_argument(
        "--source-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    result.add_argument("--pipe-name", default=DEFAULT_PIPE_NAME)
    result.add_argument("--timeout-seconds", type=float, default=30.0)
    return result


def main(arguments: Sequence[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        result = verify_live_provenance(
            expected_source_commit=options.expected_source_commit,
            source_root=options.source_root,
            client=AuthorityServiceClient(
                options.pipe_name,
                timeout_seconds=options.timeout_seconds,
            ),
            service_query=_windows_service_query,
            protected_read_denied=_protected_read_denied,
        )
    except (
        FileNotFoundError,
        KeyError,
        OSError,
        PermissionError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as error:
        print(
            json.dumps(
                {
                    "overall_result": "FAIL",
                    "error": str(error),
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
