from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from keeper.app.storage import KeeperStore
from keeper.executive.authority import AuthorityEvaluator
from keeper.executive.enums import ActionCategory, ExecutiveState
from keeper.executive.models import (
    AuthorityEnvelope,
    ProjectCharter,
    ProjectRecord,
    ProposedAction,
    utc_now,
)
from keeper.executive.repository import TestExecutiveRepository
from keeper.executive.state import transition_project
from keeper.executive.founder_auth import TestFounderAuthenticator


def project() -> ProjectRecord:
    now = utc_now()
    return ProjectRecord("project-1", "Demo", "software", "ACTIVE", "charter-1", 1, None, now, now)


def charter(workspace: Path) -> ProjectCharter:
    now = utc_now()
    envelope = AuthorityEnvelope(
        ("WRITE", "TEST", "REVIEW", "REPAIR"),
        ("COMMIT", "PUSH"),
        ("REWRITE_HISTORY",),
        (str(workspace),),
        ("filesystem",),
        ("mock",),
        0,
        "LOW",
        ("INTERNAL",),
        None,
    )
    return ProjectCharter(
        "charter-1", "project-1", "Demo", "software", "Build demo", "Need demo",
        "Working demo", ("application",), ("production deployment",), ("tests pass",),
        ("no spending",), (), (), None, "spending prohibited", 0, ("filesystem",),
        ("mock",), (), (), (str(workspace),), ("no secrets",), "LOW",
        "FULL_DELEGATION", envelope, ("pause on ambiguity",), ("independent review",),
        ("test results",), ("all tasks complete",), 1, "ACTIVE", None, None, (),
        "Founder", "approval-1", now, now,
        "event-1", "e" * 64, "session-1", {"test": True}, "c" * 64,
    )


def action(workspace: Path, category: ActionCategory = ActionCategory.WRITE) -> ProposedAction:
    return ProposedAction(
        "action-1", "project-1", 1, category.value, str(workspace / "file.txt"),
        "mock", "filesystem", str(workspace), ("application",), 0, True, "LOW",
        "INTERNAL", False,
    )


def test_state_machine_rejects_arbitrary_completion() -> None:
    current = replace(project(), state=ExecutiveState.INTAKE.value)
    with pytest.raises(PermissionError):
        transition_project(current, ExecutiveState.COMPLETED)


def test_charter_unknown_fields_fail_closed(tmp_path: Path) -> None:
    value = charter(tmp_path).to_dict()
    value["untrusted"] = True
    with pytest.raises(ValueError, match="unknown"):
        ProjectCharter.from_dict(value)


def test_approved_charter_is_immutable(tmp_path: Path) -> None:
    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    repository = TestExecutiveRepository(store, TestFounderAuthenticator())
    repository.save_project(
        replace(
            project(),
            state=ExecutiveState.INTAKE.value,
            active_charter_id=None,
            active_charter_revision=None,
        )
    )
    with pytest.raises(PermissionError):
        repository.insert_approved_charter(charter(tmp_path))


def test_repository_rejects_new_terminal_project(tmp_path: Path) -> None:
    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    repository = TestExecutiveRepository(store, TestFounderAuthenticator())
    with pytest.raises(PermissionError, match="begin"):
        repository.save_project(
            replace(project(), state=ExecutiveState.COMPLETED.value)
        )


def test_authority_allows_bounded_full_delegation(tmp_path: Path) -> None:
    decision = AuthorityEvaluator().evaluate(project(), charter(tmp_path), action(tmp_path))
    assert decision.outcome == "ALLOWED_WITHIN_LIMIT"


@pytest.mark.parametrize(
    "category",
    [
        ActionCategory.REWRITE_HISTORY,
        ActionCategory.DELETE_PROTECTED,
        ActionCategory.ENABLE_LIVE_TRADING,
        ActionCategory.CHANGE_SECURITY_BOUNDARY,
    ],
)
def test_non_delegable_actions_are_denied(tmp_path: Path, category: ActionCategory) -> None:
    decision = AuthorityEvaluator().evaluate(project(), charter(tmp_path), action(tmp_path, category))
    assert decision.outcome == "DENIED"
    assert decision.rule == "non-delegable-action"


def test_stale_revision_requires_charter_revision(tmp_path: Path) -> None:
    stale = replace(action(tmp_path), charter_revision=0)
    decision = AuthorityEvaluator().evaluate(project(), charter(tmp_path), stale)
    assert decision.outcome == "CHARTER_REVISION_REQUIRED"


def test_expired_authority_fails_closed(tmp_path: Path) -> None:
    expired = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    constrained = replace(
        charter(tmp_path),
        authority_envelope=replace(charter(tmp_path).authority_envelope, expires_at=expired),
    )
    decision = AuthorityEvaluator().evaluate(project(), constrained, action(tmp_path))
    assert decision.outcome == "EXPIRED"
