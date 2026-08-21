from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from tests.keeper.authority_testkit import provider_authority_kwargs

from keeper.app.workflow import _protected_record_digest, _resolve_execution_evidence
from keeper.app.lifecycle import RunStage
from keeper.app.service import KeeperApplication
from keeper.authority import AuthorityKey
from keeper.providers.adapters import (
    ProviderDiscovery,
    apply_protected_qualification,
    canonical_provider_registration_digest,
    create_provider_registration,
    qualification_evidence_digest,
)
from tests.keeper.authority_testkit import TestAuthorityClient


def _protected_attempt(root: Path) -> tuple[dict[str, Any], dict[str, Any], Path]:
    provider_run_id = "provider-run"
    path = (
        root
        / ".ai-workflow"
        / "runs"
        / provider_run_id
        / "run.json"
    )
    path.parent.mkdir(parents=True)
    registration = {
        "logical_provider_id": "codex",
        "configuration_digest": "c" * 64,
        "endpoint_identity": "local-process",
        "authentication_mode": "external-cli-session",
        "capability_set": {"builder": True},
        "provider_policy": "registered-command",
        "independence_classification": "role-enforced",
    }
    attempt = {
        "provider_run_id": provider_run_id,
        "task_id": "task",
        "stage_id": "author_execution",
        "role": "builder",
        "attempt_number": 2,
        "retry_parent": "attempt-1",
        "provider_name": "codex-command",
        "provider_instance_id": "instance-A",
        "stable_registration_digest": "r" * 64,
        "stable_registration": registration,
        "executable": str((root / "codex.exe").resolve()),
        "executable_sha256": "e" * 64,
        "evidence_path": str(path.resolve()),
        "launch_nonce": "launch-nonce",
        "ownership_token": "ownership-token",
        "completion_challenge": "challenge-" + ("c" * 55),
        "status": "EXECUTION_STARTED",
    }
    record = {
        "id": "keeper-run",
        "evidence_root": str(root.resolve()),
    }
    return record, attempt, path


def _matching_evidence(
    record: dict[str, Any],
    attempt: dict[str, Any],
    *,
    status: str = "RUNNING",
) -> dict[str, Any]:
    registration = attempt["stable_registration"]
    value = {
        "run_id": attempt["provider_run_id"],
        "keeper_run_id": record["id"],
        "task_id": attempt["task_id"],
        "stage_id": attempt["stage_id"],
        "role": attempt["role"],
        "attempt_number": attempt["attempt_number"],
        "retry_parent": attempt["retry_parent"],
        "provider_name": attempt["provider_name"],
        "provider_logical_id": registration["logical_provider_id"],
        "provider_instance_id": attempt["provider_instance_id"],
        "stable_registration_digest": attempt["stable_registration_digest"],
        "executable_path": attempt["executable"],
        "executable_sha256": attempt["executable_sha256"],
        "configuration_digest": registration["configuration_digest"],
        "endpoint_identity": registration["endpoint_identity"],
        "authentication_mode": registration["authentication_mode"],
        "capability_set": registration["capability_set"],
        "provider_policy": registration["provider_policy"],
        "independence_classification": registration[
            "independence_classification"
        ],
        "evidence_path": attempt["evidence_path"],
        "launch_nonce": attempt["launch_nonce"],
        "ownership_token": attempt["ownership_token"],
        "status": status,
        "end_time": None,
        "process_exit_code": None,
        "failure_reason": None,
    }
    if status == "COMPLETED":
        value.update(
            {
                "end_time": "2026-07-26T00:01:00+00:00",
                "process_exit_code": 0,
            }
        )
    return value


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_instance_id", "instance-B"),
        ("provider_logical_id", "other-provider"),
        ("attempt_number", 3),
        ("stage_id", "review_execution"),
        ("stage_id", None),
        ("role", "reviewer"),
        ("stable_registration_digest", "x" * 64),
        ("executable_sha256", "x" * 64),
        ("configuration_digest", "x" * 64),
        ("endpoint_identity", "remote"),
        ("authentication_mode", "none"),
        ("keeper_run_id", "other-run"),
        ("task_id", "other-task"),
        ("launch_nonce", "other-launch"),
        ("ownership_token", "other-owner"),
    ],
)
def test_recovery_rejects_every_mismatched_attempt_identity(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    record, attempt, path = _protected_attempt(tmp_path / field)
    evidence = _matching_evidence(record, attempt)
    evidence[field] = value
    path.write_text(json.dumps(evidence), encoding="utf-8")

    resolution = _resolve_execution_evidence(record, attempt)

    assert resolution["status"] == "IDENTITY_MISMATCH"


@pytest.mark.parametrize("status", [None, "SURPRISING", "almost-done"])
def test_recovery_rejects_missing_or_unknown_status(
    tmp_path: Path,
    status: str | None,
) -> None:
    record, attempt, path = _protected_attempt(tmp_path / str(status))
    evidence = _matching_evidence(record, attempt)
    if status is None:
        evidence.pop("status")
    else:
        evidence["status"] = status
    path.write_text(json.dumps(evidence), encoding="utf-8")

    assert _resolve_execution_evidence(record, attempt)["status"] == "INDETERMINATE"


def test_recovery_requires_complete_terminal_disposition(tmp_path: Path) -> None:
    record, attempt, path = _protected_attempt(tmp_path / "incomplete-terminal")
    evidence = _matching_evidence(record, attempt, status="COMPLETED")
    evidence["process_exit_code"] = None
    path.write_text(json.dumps(evidence), encoding="utf-8")

    assert _resolve_execution_evidence(record, attempt)["status"] == "INDETERMINATE"


def test_exact_complete_terminal_evidence_resolves(tmp_path: Path) -> None:
    record, attempt, path = _protected_attempt(tmp_path / "complete-terminal")
    path.write_text(
        json.dumps(_matching_evidence(record, attempt, status="COMPLETED")),
        encoding="utf-8",
    )

    assert _resolve_execution_evidence(record, attempt)["status"] == "RESOLVED_TERMINAL"


@pytest.mark.parametrize(
    "completion_case",
    [
        "missing",
        "valid",
        "unsigned",
        "wrong-key",
        "wrong-challenge",
        "replay",
        "forged-digest",
        "wrong-instance",
        "wrong-attempt",
    ],
)
def test_terminal_recovery_requires_protected_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    completion_case: str,
) -> None:
    app = KeeperApplication(tmp_path / "terminal-recovery")
    run_id = "keeper-run"
    app.lifecycle.create(run_id, "task")
    app.lifecycle.transition(run_id, RunStage.SCOPE_VALIDATION)
    root = app.data_directory / "evidence" / run_id
    protected, attempt, path = _protected_attempt(root)
    ownership = {
        "id": f"process-ownership:{run_id}:provider-run",
        "kind": "process_ownership",
        "keeper_run_id": run_id,
        "task_id": "task",
        "stage_id": "author_execution",
        "provider_name": "codex-command",
        "provider_instance_id": "instance-A",
        "provider_run_id": "provider-run",
        "role": "builder",
        "ownership_token": "ownership-token",
        "launch_nonce": "launch-nonce",
        "evidence_path": str(path.parent.resolve()),
        "pid": 4242,
        "creation_time": "creation",
        "executable": attempt["executable"],
        "command_line_hash": "h" * 64,
        "parent_pid": 100,
        "job_or_group_identity": "job:1",
        "started_at": "2026-07-26T00:00:00+00:00",
    }
    attempt["process_id"] = 4242
    attempt["process_ownership"] = ownership
    evidence = _matching_evidence(protected, attempt, status="COMPLETED")
    evidence["process_ownership"] = ownership
    path.write_text(json.dumps(evidence), encoding="utf-8")
    stored = app.store.get("runs", run_id)
    assert stored is not None
    stored.update(
        {
            "status": "running",
            "evidence_root": str(root.resolve()),
            "provider_execution_attempts": [attempt],
        }
    )
    app.store.upsert("runs", run_id, stored)
    app.store.insert_immutable("artifacts", ownership["id"], ownership)
    if completion_case != "missing":
        completion: dict[str, Any] = {
            "id": f"provider-completion:{run_id}:provider-run",
            "kind": "provider_completion",
            "schema_version": 1,
            "completion_challenge": attempt["completion_challenge"],
            "keeper_run_id": run_id,
            "task_id": attempt["task_id"],
            "stage_id": attempt["stage_id"],
            "role": attempt["role"],
            "attempt_number": attempt["attempt_number"],
            "provider_run_id": attempt["provider_run_id"],
            "provider_instance_id": attempt["provider_instance_id"],
            "stable_registration_digest": attempt["stable_registration_digest"],
            "executable": attempt["executable"],
            "executable_sha256": attempt["executable_sha256"],
            "configuration_digest": attempt["stable_registration"][
                "configuration_digest"
            ],
            "start_time": "2026-07-26T00:00:00+00:00",
            "end_time": evidence["end_time"],
            "exit_status": 0,
            "normalized_result": "completed",
            "provider_evidence_digest": hashlib.sha256(path.read_bytes()).hexdigest(),
            "terminal_disposition": "COMPLETED",
            "completion_event_id": "completion-event",
            "lifecycle_transaction_id": "lifecycle-transaction",
            "transaction_recorded_at": "2026-07-26T00:01:01+00:00",
            "process_ownership": ownership,
        }
        completion["integrity_digest"] = _protected_record_digest(completion)
        if completion_case == "forged-digest":
            completion["integrity_digest"] = "f" * 64
        elif completion_case == "wrong-instance":
            completion["provider_instance_id"] = "other-instance"
            completion["integrity_digest"] = _protected_record_digest(completion)
        elif completion_case == "wrong-attempt":
            completion["attempt_number"] = 999
            completion["integrity_digest"] = _protected_record_digest(completion)
        elif completion_case == "wrong-challenge":
            completion["completion_challenge"] = "wrong-" + ("x" * 58)
            completion["integrity_digest"] = _protected_record_digest(completion)
        if completion_case == "wrong-key":
            completion = AuthorityKey(tmp_path / "other-installation").sign(
                "provider-completion", completion
            )
        elif completion_case != "unsigned":
            completion = cast(
                TestAuthorityClient, app.authority
            ).sign("provider-completion", completion)
        app.store.insert_immutable(
            "artifacts", str(completion["id"]), completion
        )
        if completion_case == "replay":
            replay = cast(TestAuthorityClient, app.authority).sign(
                "provider-completion",
                {
                    **completion,
                    "id": f"{completion['id']}:replay",
                    "integrity_digest": _protected_record_digest(
                        {
                            **completion,
                            "id": f"{completion['id']}:replay",
                        }
                    ),
                },
            )
            app.store.insert_immutable("artifacts", str(replay["id"]), replay)
    monkeypatch.setattr("keeper.app.workflow.process_exists", lambda pid: False)

    recovered = app.workflow.recover_interrupted_runs()[0]

    assert recovered["recovery"]["provider_evidence_status"] == "RESOLVED_TERMINAL"
    assert recovered["recovery"]["retry_safe"] is False
    assert recovered["recovery"]["protected_completion_status"] == (
        "MISSING"
        if completion_case == "missing"
        else "INDETERMINATE"
        if completion_case == "replay"
        else "LEGACY_UNVERIFIABLE"
    )
    assert (
        recovered["provider_execution_attempts"][0]["status"]
        == "EXECUTION_STARTED"
    )


def test_missing_exact_path_never_falls_back_to_wrong_instance(
    tmp_path: Path,
) -> None:
    record, attempt, _ = _protected_attempt(tmp_path / "audit-case")
    sibling = (
        Path(record["evidence_root"])
        / ".ai-workflow"
        / "runs"
        / "sibling"
        / "run.json"
    )
    sibling.parent.mkdir()
    evidence = _matching_evidence(record, attempt, status="COMPLETED")
    evidence["provider_instance_id"] = "instance-B"
    sibling.write_text(json.dumps(evidence), encoding="utf-8")

    resolution = _resolve_execution_evidence(record, attempt)

    assert resolution["status"] == "MISSING_EVIDENCE"


def test_protected_evidence_path_must_be_canonical(tmp_path: Path) -> None:
    record, attempt, path = _protected_attempt(tmp_path / "canonical")
    path.write_text(json.dumps(_matching_evidence(record, attempt)), encoding="utf-8")
    attempt["evidence_path"] = str(path.parent / ".." / path.parent.name / "run.json")

    assert _resolve_execution_evidence(record, attempt)["status"] == "IDENTITY_MISMATCH"


def _qualified_registration(
    tmp_path: Path,
) -> tuple[
    Path,
    dict[str, Any],
    dict[str, dict[str, Any]],
    AuthorityKey,
]:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"registered provider")
    registration = create_provider_registration(
        "codex",
        executable,
        authorized_by="test-authority",
     **provider_authority_kwargs('codex'))
    evidence: dict[str, Any] = {
        "id": "qualification:test",
        "kind": "provider_qualification",
        "registration_id": registration["trusted_registration_id"],
        "registration_version": registration["registration_version"],
        "provider_id": "codex",
        "provider_instance_id": "qualification-instance",
        "provider_run_id": "qualification-run",
        "executable_sha256": registration["executable_sha256"],
        "launcher_sha256": registration["launcher_sha256"],
        "script_sha256": registration["script_sha256"],
        "qualification_command": [str(executable), "--version"],
        "command_digest": hashlib.sha256(
            json.dumps([str(executable), "--version"]).encode("utf-8")
        ).hexdigest(),
        "started_at": "2026-07-26T00:00:00+00:00",
        "finished_at": "2026-07-26T00:00:01+00:00",
        "exit_status": 0,
        "raw_version_output": "controlled-provider 1.2.3",
        "normalized_version": "controlled-provider 1.2.3",
        "qualification_method": "protected-registered-launch",
        "qualification_result": "qualified",
        "authorized_by": "test-authority",
        "ownership": {"launch_nonce": "qualification"},
    }
    evidence["evidence_digest"] = qualification_evidence_digest(evidence)
    authority = AuthorityKey(tmp_path / "protected")
    start = authority.sign(
        "provider-qualification-start",
        {
            "id": "qualification:test:start",
            "kind": "provider_qualification_started",
            "schema_version": 1,
            "registration_id": registration["trusted_registration_id"],
            "provider_id": "codex",
            "authorization_reference": "test-authority",
            "event_challenge": "qualification",
            "started_at": "2026-07-26T00:00:00+00:00",
        },
    )
    evidence["authorization_reference"] = start["id"]
    evidence["event_challenge"] = start["event_challenge"]
    evidence["evidence_digest"] = qualification_evidence_digest(evidence)
    evidence = authority.sign("provider-qualification", evidence)
    qualified = apply_protected_qualification(
        registration,
        evidence,
        authority_verifier=authority.verify,
        expected_challenge=str(start["event_challenge"]),
        expected_authorization_reference=str(start["id"]),
    )
    return (
        executable,
        qualified,
        {str(evidence["id"]): evidence, str(start["id"]): start},
        authority,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("endpoint_identity", "changed-endpoint"),
        ("authentication_mode", "changed-auth"),
        ("authentication_profile", "changed-profile"),
        ("capability_set", {"builder": False}),
        ("provider_policy", "changed-policy"),
        ("independence_classification", "changed-independence"),
        ("qualified_version", "9.9.9"),
        ("qualification_method", "none"),
        ("qualification_result", "not-qualified"),
        ("registration_version", "2"),
        ("trusted_registration_id", "changed-registration"),
        ("executable_registration_id", "changed-component"),
        ("executable_registration_version", "2"),
        ("launcher_registration_id", "changed-launcher"),
        ("launcher_registration_version", "2"),
        ("launcher_sha256", "a" * 64),
        ("executable_size", 999),
        ("model_or_service_identity", "changed-model"),
        ("authorized_by", "changed-authorizer"),
    ],
)
def test_any_authoritative_registration_mutation_blocks_discovery(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    executable, registration, evidence, authority = _qualified_registration(tmp_path)
    registration[field] = value

    diagnostic = ProviderDiscovery(
        {"codex": str(executable)},
        {"codex": registration},
        evidence,
        authority.verify,
    ).discover()[0]

    assert diagnostic.available is False
    assert diagnostic.discovery_state == "blocked"


def test_registration_rejects_unknown_missing_and_wrong_type_fields(
    tmp_path: Path,
) -> None:
    executable, original, evidence, authority = _qualified_registration(tmp_path)
    variants = []
    unknown = copy.deepcopy(original)
    unknown["unsigned_authority"] = "fabricated"
    variants.append(unknown)
    missing = copy.deepcopy(original)
    missing.pop("endpoint_identity")
    variants.append(missing)
    wrong_type = copy.deepcopy(original)
    wrong_type["launcher_size"] = "1"
    variants.append(wrong_type)
    copied = copy.deepcopy(original)
    copied["logical_provider_id"] = "other-provider"
    variants.append(copied)

    for registration in variants:
        diagnostic = ProviderDiscovery(
            {"codex": str(executable)},
            {"codex": registration},
            evidence,
            authority.verify,
        ).discover()[0]
        assert diagnostic.available is False


def test_every_canonical_registration_field_is_digest_bound(tmp_path: Path) -> None:
    executable, original, evidence, authority = _qualified_registration(tmp_path)
    for field, original_value in original.items():
        if field == "configuration_digest":
            continue
        registration = copy.deepcopy(original)
        if original_value is None:
            changed: object = "fabricated"
        elif isinstance(original_value, bool):
            changed = not original_value
        elif isinstance(original_value, int):
            changed = original_value + 1
        elif isinstance(original_value, str):
            changed = f"{original_value}-changed"
        elif isinstance(original_value, list):
            changed = [*original_value, "changed"]
        elif isinstance(original_value, dict):
            changed = {**original_value, "changed": True}
        else:
            raise AssertionError(f"unhandled registration field: {field}")
        registration[field] = changed
        diagnostic = ProviderDiscovery(
            {"codex": str(executable)},
            {"codex": registration},
            evidence,
            authority.verify,
        ).discover()[0]
        assert diagnostic.available is False, field


def test_audit_registration_metadata_fabrication_is_rejected(tmp_path: Path) -> None:
    executable, registration, evidence, authority = _qualified_registration(tmp_path)
    registration.update(
        {
            "endpoint_identity": "fabricated-endpoint",
            "authentication_mode": "fabricated-auth",
            "capability_set": {"builder": False},
            "provider_policy": "fabricated-policy",
            "independence_classification": "fabricated-independence",
            "qualified_version": "fabricated-version",
        }
    )

    diagnostic = ProviderDiscovery(
        {"codex": str(executable)},
        {"codex": registration},
        evidence,
        authority.verify,
    ).discover()[0]

    assert diagnostic.available is False
    assert diagnostic.discovery_state == "blocked"


def test_registration_rejects_revoked_and_expired_authority(tmp_path: Path) -> None:
    executable, original, evidence, authority = _qualified_registration(tmp_path)
    revoked = copy.deepcopy(original)
    revoked["registration_status"] = "revoked"
    revoked["revoked_at"] = datetime.now(UTC).isoformat()
    revoked["configuration_digest"] = canonical_provider_registration_digest(revoked)
    expired = copy.deepcopy(original)
    expired["expires_at"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    expired["configuration_digest"] = canonical_provider_registration_digest(expired)

    for registration in (revoked, expired):
        diagnostic = ProviderDiscovery(
            {"codex": str(executable)},
            {"codex": registration},
            evidence,
            authority.verify,
        ).discover()[0]
        assert diagnostic.available is False


def test_canonical_registration_serialization_is_stable_and_qualified(
    tmp_path: Path,
) -> None:
    executable, registration, evidence, authority = _qualified_registration(tmp_path)
    reordered = dict(reversed(list(registration.items())))
    reordered["capability_set"] = dict(
        reversed(list(registration["capability_set"].items()))
    )

    assert canonical_provider_registration_digest(registration) == (
        canonical_provider_registration_digest(reordered)
    )
    diagnostic = ProviderDiscovery(
        {"codex": str(executable)},
        {"codex": reordered},
        evidence,
        authority.verify,
    ).discover()[0]
    assert diagnostic.available is True
    assert diagnostic.discovery_state == "qualified"
    assert diagnostic.version == "controlled-provider 1.2.3"
