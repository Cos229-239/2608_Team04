from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from keeper.app.service import KeeperApplication
from keeper.app.workflow import (
    _mock_routes,
    _routing_digest,
    _stable_registration_digest,
    _validate_routing_decisions,
)
from keeper.providers.base import AgentProvider
from keeper.providers.codex_cli import CliProvider


def _state(
    app: KeeperApplication,
) -> tuple[
    str,
    dict[str, object],
    dict[str, AgentProvider],
    list[dict[str, object]],
]:
    run_id = "run-routing"
    task: dict[str, object] = {
        "id": "task-routing",
        "repository": str(app.data_directory),
        "provider_policy": "mock",
    }
    app.store.upsert("tasks", "task-routing", task)
    app.lifecycle.create(run_id, "task-routing")
    providers, _, decisions = _mock_routes("no-repair")
    app.workflow._record_routing_attempt(
        run_id, task, providers, decisions, None, None
    )
    stored_run = app.store.get("runs", run_id)
    assert stored_run is not None
    stored_run["status"] = "blocked"
    stored_run["stopped_from"] = "author_execution"
    evidence_root = app.data_directory / "evidence" / run_id
    evidence_root.mkdir(parents=True, exist_ok=True)
    stored_run["evidence_root"] = str(evidence_root.resolve())
    app.store.upsert("runs", run_id, stored_run)
    return run_id, task, providers, decisions


def _changed_registration(
    decision: dict[str, object], **changes: object
) -> dict[str, object]:
    changed = deepcopy(decision)
    registration = dict(
        cast(dict[str, object], changed["stable_registration"])
    )
    registration.update(changes)
    changed["stable_registration"] = registration
    changed["stable_registration_digest"] = _stable_registration_digest(registration)
    changed["provider_id"] = registration["logical_provider_id"]
    changed["provider"] = registration["provider_name"]
    changed["executable"] = registration["canonical_executable_path"]
    changed["executable_sha256"] = registration["executable_sha256"]
    changed["policy"] = registration["provider_policy"]
    changed["capability"] = registration["selected_capability"]
    changed["independence"] = registration["independence_classification"]
    return changed


def _authorization(
    *,
    previous: list[dict[str, object]],
    proposed: list[dict[str, object]],
    source_attempt_id: str,
    destination_attempt_number: int,
    expires_at: str | None = None,
) -> dict[str, object]:
    return {
        "id": "authorization-reroute",
        "capability": "provider_reroute",
        "task_id": "task-routing",
        "run_id": "run-routing",
        "repository": "",
        "retry_stage": "author_execution",
        "provider_policy": "mock",
        "from_routing_digest": _routing_digest(previous),
        "to_routing_digest": _routing_digest(proposed),
        "source_attempt_id": source_attempt_id,
        "destination_attempt_number": destination_attempt_number,
        "capability_requirements": {
            str(item["role"]): item["capability"] for item in proposed
        },
        "independence_requirements": {
            str(item["role"]): item["independence"] for item in proposed
        },
        "approving_authority": "operator",
        "issued_at": datetime.now(UTC).isoformat(),
        "expires_at": expires_at
        or (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "consumed_at": None,
        "revoked_at": None,
    }


def test_exact_registration_retry_preserves_truthful_new_attempt_instances(
    tmp_path: Path,
) -> None:
    app = KeeperApplication(tmp_path / "data")
    run_id, task, _, previous = _state(app)
    proposed_providers, _, proposed = _mock_routes("no-repair")
    rebound, decisions, authorization = app.workflow._bind_retry_routing(
        run_id,
        task,
        "author_execution",
        proposed_providers,
        proposed,
        None,
    )
    assert authorization is None
    previous_instances = {
        str(item["role"]): str(item["provider_instance_id"]) for item in previous
    }
    actual_instances = {
        str(item["role"]): str(item["provider_instance_id"]) for item in decisions
    }
    assert all(
        actual_instances[role] != previous_instances[role]
        for role in previous_instances
    )
    assert rebound["builder"].instance_id == actual_instances["builder"]
    assert rebound["builder"].instance_id != previous_instances["builder"]
    assert _routing_digest(previous) == _routing_digest(decisions)


@pytest.mark.parametrize(
    "changes",
    [
        {
            "canonical_executable_path": "C:\\provider\\same.exe",
            "executable_sha256": "b" * 64,
            "executable_size": 44,
        },
        {"configuration_digest": "c" * 64},
        {"endpoint_identity": "http://127.0.0.1:22444"},
        {"authentication_mode": "different-auth"},
        {"logical_provider_id": "replacement"},
        {"provider_policy": "different-policy"},
        {"selected_capability": "different-capability"},
        {"independence_classification": "independent-review"},
    ],
)
def test_every_material_registration_change_requires_reroute(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    app = KeeperApplication(tmp_path / "data")
    run_id, task, _, _ = _state(app)
    providers, _, proposed = _mock_routes("no-repair")
    proposed[0] = _changed_registration(proposed[0], **changes)
    with pytest.raises(PermissionError):
        app.workflow._bind_retry_routing(
            run_id, task, "author_execution", providers, proposed, None
        )


def test_provider_executable_replacement_in_place_is_detected(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"first")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    provider = CliProvider(
        (str(executable), "{prompt}"),
        expected_executable_sha256=digest,
        expected_executable_size=executable.stat().st_size,
        registration_id="replacement-test",
        registration_version="1",
        configuration_digest="c" * 64,
    )
    provider.validate()
    executable.write_bytes(b"replacement")
    with pytest.raises(PermissionError, match="content changed"):
        provider.validate()


def test_discovery_order_does_not_change_mock_registration_selection() -> None:
    first_providers, _, first = _mock_routes("no-repair")
    second_providers, _, second = _mock_routes("no-repair")
    assert _routing_digest(first) == _routing_digest(list(reversed(second)))
    assert first_providers["builder"].instance_id != (
        second_providers["builder"].instance_id
    )


def test_mock_downgrade_and_malformed_registration_fail_closed(
    tmp_path: Path,
) -> None:
    app = KeeperApplication(tmp_path / "data")
    _, _, _, decisions = _state(app)
    malformed = deepcopy(decisions)
    del malformed[0]["stable_registration"]
    with pytest.raises(PermissionError, match="malformed"):
        _validate_routing_decisions(malformed, "mock")

    non_mock = [_changed_registration(item, provider_policy="automatic") for item in decisions]
    non_mock[0] = _changed_registration(
        non_mock[0],
        logical_provider_id="mock-replacement",
        provider_name="mock-replacement",
    )
    with pytest.raises(PermissionError, match="mock"):
        _validate_routing_decisions(non_mock, "automatic")


def test_reroute_authorization_is_exact_one_use_and_attempt_bound(
    tmp_path: Path,
) -> None:
    app = KeeperApplication(tmp_path / "data")
    run_id, task, _, previous = _state(app)
    providers, _, proposed = _mock_routes("no-repair")
    proposed[0] = _changed_registration(
        proposed[0],
        logical_provider_id="authorized-replacement",
        provider_name="authorized-replacement",
        configuration_digest="d" * 64,
    )
    attempts = app.store.get("runs", run_id)["routing_attempts"]  # type: ignore[index]
    authorization = _authorization(
        previous=previous,
        proposed=proposed,
        source_attempt_id=str(attempts[-1]["attempt_id"]),
        destination_attempt_number=2,
    )
    authorization["repository"] = str(app.data_directory.resolve())
    app.store.upsert("authorizations", str(authorization["id"]), authorization)
    _, decisions, used = app.workflow._bind_retry_routing(
        run_id,
        task,
        "author_execution",
        providers,
        proposed,
        str(authorization["id"]),
    )
    assert used == authorization["id"]
    assert decisions[0]["provider_instance_id"] == providers["builder"].instance_id
    assert app.store.get("authorizations", str(authorization["id"]))["consumed_at"]  # type: ignore[index]
    with pytest.raises(PermissionError):
        app.workflow._bind_retry_routing(
            run_id,
            task,
            "author_execution",
            providers,
            proposed,
            str(authorization["id"]),
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"expires_at": "2020-01-01T00:00:00+00:00"},
        {"source_attempt_id": "other-attempt"},
        {"destination_attempt_number": 3},
    ],
)
def test_stale_or_wrong_attempt_reroute_authorization_is_rejected(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    app = KeeperApplication(tmp_path / "data")
    run_id, task, _, previous = _state(app)
    providers, _, proposed = _mock_routes("no-repair")
    proposed[0] = _changed_registration(
        proposed[0], configuration_digest="e" * 64
    )
    attempts = app.store.get("runs", run_id)["routing_attempts"]  # type: ignore[index]
    authorization = _authorization(
        previous=previous,
        proposed=proposed,
        source_attempt_id=str(attempts[-1]["attempt_id"]),
        destination_attempt_number=2,
    )
    authorization.update(mutation)
    authorization["repository"] = str(app.data_directory.resolve())
    app.store.upsert("authorizations", str(authorization["id"]), authorization)
    with pytest.raises(PermissionError, match="does not match"):
        app.workflow._bind_retry_routing(
            run_id,
            task,
            "author_execution",
            providers,
            proposed,
            str(authorization["id"]),
        )


def test_attempt_record_and_report_use_actual_instance_and_executable_digest(
    tmp_path: Path,
) -> None:
    app = KeeperApplication(tmp_path / "data")
    run_id, task, _, _ = _state(app)
    providers, _, decisions = _mock_routes("no-repair")
    app.workflow._record_routing_attempt(
        run_id,
        task,
        providers,
        decisions,
        "author_execution",
        None,
    )
    persisted = app.store.get("runs", run_id)
    assert persisted is not None
    latest = persisted["routing_attempts"][-1]
    assert latest["run_id"] == run_id
    assert latest["task_id"] == "task-routing"
    assert latest["retry_of"]
    assert latest["outcome"] == "selected"
    builder = latest["decisions"][0]
    assert "provider_attempt_id" not in builder
    assert "execution_started_at" not in builder
    assert builder["run_id"] == run_id
    assert builder["task_id"] == "task-routing"
    assert builder["stage_id"] == "author_execution"
    assert builder["attempt_number"] == 2
    assert builder["retry_parent_attempt"]
    assert builder["provider_instance_id"] == providers["builder"].instance_id
    assert builder["stable_registration_digest"]
    assert "executable_sha256" in builder
    assert builder["stable_registration"]["configuration_digest"]
    assert "execution_started_at" not in builder
    assert "execution_ended_at" not in builder
    app.workflow._complete_routing_attempt(run_id, "COMPLETED")
    app.workflow._finalize_report(run_id, task, None, "BLOCKED")
    report = json.loads(
        (
            app.data_directory / "evidence" / run_id / "final-report.json"
        ).read_text(encoding="utf-8")
    )
    reported = report["routing_attempts"][-1]["decisions"][0]
    assert reported["provider_instance_id"] == providers["builder"].instance_id
    assert reported["stable_registration_digest"] == (
        builder["stable_registration_digest"]
    )
    assert reported["outcome"] == "selected"
    assert reported["disposition"] == "COMPLETED"
    assert "execution_ended_at" not in reported
