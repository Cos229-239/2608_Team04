from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from keeper.app.reporting import finalize_evidence, verify_evidence
from keeper.app.service import KeeperApplication


def _completed(
    tmp_path: Path, label: str = "primary"
) -> tuple[KeeperApplication, dict[str, object], Path]:
    app = KeeperApplication(tmp_path / f"data-{label}")
    run = app.run_mock_demo()
    root = Path(str(run["evidence_root"]))
    verify_evidence(root)
    return app, run, root


def _rewrite_index(root: Path) -> None:
    files = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path.name == "evidence-index.json":
            continue
        content = path.read_bytes()
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    (root / "evidence-index.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "created_at": "2026-07-26T00:00:00+00:00",
                "files": files,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_untouched_protected_evidence_exports_successfully(tmp_path: Path) -> None:
    app, run, _ = _completed(tmp_path)
    destination = app.export_run_report(
        str(run["id"]), tmp_path / "exported"
    )
    verify_evidence(destination)


@pytest.mark.parametrize(
    "tamper",
    [
        "status_and_manifest",
        "removed_report_entry",
        "omitted_required_file",
        "other_run",
        "provider_identity",
        "git_result",
        "duplicate_manifest_path",
        "replacement_file",
        "protected_digest",
        "markdown_disagreement",
    ],
)
def test_export_rejects_mutable_evidence_and_manifest_rewrites(
    tmp_path: Path,
    tamper: str,
) -> None:
    app, run, root = _completed(tmp_path)
    report_path = root / "final-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if tamper == "status_and_manifest":
        report["terminal_status"] = "COMPLETED-BY-REWRITE"
        finalize_evidence(root, report)
    elif tamper == "removed_report_entry":
        index_path = root / "evidence-index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["files"] = [
            item
            for item in index["files"]
            if item["path"] != "final-report.json"
        ]
        index_path.write_text(json.dumps(index), encoding="utf-8")
    elif tamper == "omitted_required_file":
        (root / "task-definition.json").unlink()
        _rewrite_index(root)
    elif tamper == "other_run":
        _, _, other = _completed(tmp_path, "other")
        for name in ("final-report.json", "final-report.md"):
            (root / name).write_bytes((other / name).read_bytes())
        _rewrite_index(root)
    elif tamper == "provider_identity":
        report["provider_identities"] = {"builder": {"provider_name": "forged"}}
        finalize_evidence(root, report)
    elif tamper == "git_result":
        report["commit_result"] = {"commit_hash": "f" * 40}
        finalize_evidence(root, report)
    elif tamper == "duplicate_manifest_path":
        index_path = root / "evidence-index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["files"].append(dict(index["files"][0]))
        index_path.write_text(json.dumps(index), encoding="utf-8")
    elif tamper == "replacement_file":
        (root / "review-records.json").unlink()
        (root / "review-replacement.json").write_text("{}", encoding="utf-8")
        _rewrite_index(root)
    elif tamper == "protected_digest":
        finalization_id = str(run["evidence_finalization_id"])
        protected = app.store.get("artifacts", finalization_id)
        assert protected is not None
        protected["manifest_digest"] = "0" * 64
        app.store.upsert("artifacts", finalization_id, protected)
    elif tamper == "markdown_disagreement":
        (root / "final-report.md").write_text(
            "# inconsistent\n", encoding="utf-8"
        )
        _rewrite_index(root)
    with pytest.raises((PermissionError, RuntimeError, ValueError)):
        app.export_run_report(str(run["id"]), tmp_path / f"export-{tamper}")
