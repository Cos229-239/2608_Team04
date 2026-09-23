"""Renewal integration must preserve identity and explicit authentication."""
from datetime import UTC, datetime, timedelta

import pytest

from keeper.app.storage import KeeperStore
from keeper.executive.service import KeeperExecutive
from keeper.pass_b.application import PassBApplication
from tests.keeper.executive.fixture_store import replace_executive_fixture


def expired_application(tmp_path):
    database = tmp_path / "executive.db"
    executive = KeeperExecutive(database)
    application = PassBApplication(tmp_path, executive=executive)
    outcome = application.begin_conversation(
        "Build a local software project with no deployment or spending."
    )
    project_id = outcome.project.project_id
    challenge = application.conversation.request_approval(project_id)
    expired = challenge.to_dict()
    expired["expires_at"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    replace_executive_fixture(
        KeeperStore(database), "executive_founder_approval_challenges",
        challenge.challenge_id, expired,
    )
    return application, project_id, challenge


def approve(application, project_id, original):
    return application.approve_and_plan_current_charter(
        project_id, expected_charter_id=original.charter_id,
        expected_charter_revision=original.charter_revision,
    )


def test_renewal_survives_restart_and_reuses_challenge_after_auth_cancel(tmp_path, monkeypatch):
    application, project_id, original = expired_application(tmp_path)
    application = PassBApplication(
        tmp_path, executive=KeeperExecutive(tmp_path / "executive.db")
    )
    seen = []

    def deny(self, challenge):
        seen.append(challenge)
        raise PermissionError("authentication cancelled")

    monkeypatch.setattr(KeeperExecutive, "authenticate_founder", deny)
    for _ in range(2):
        with pytest.raises(PermissionError, match="authentication cancelled"):
            approve(application, project_id, original)
    assert len(seen) == 2
    assert seen[0].challenge_id == seen[1].challenge_id != original.challenge_id
    assert seen[0].charter_digest == original.charter_digest
    status = application.project_status(project_id)
    assert len(status["pending_approvals"]) == 1
    assert not status.get("active_charter")
    assert application.conversation.current_context(project_id).state == "APPROVAL_REQUESTED"


@pytest.mark.parametrize("case", ["missing", "duplicate", "changed_revision", "multiple_pending"])
def test_renewal_fails_closed_for_ambiguous_or_stale_projection(tmp_path, monkeypatch, case):
    application, project_id, original = expired_application(tmp_path)
    status = application.project_status(project_id)
    proposals = [item for item in status["charter_history"]
                 if item["charter_id"] == original.charter_id]
    assert len(proposals) == 1
    if case == "missing":
        status["charter_history"] = []
    elif case == "duplicate":
        status["charter_history"] = proposals * 2
    elif case == "changed_revision":
        status["charter_history"] = [{**proposals[0], "revision": original.charter_revision + 1}]
    else:
        status["pending_approvals"] = [original.to_dict(), original.to_dict()]
    monkeypatch.setattr(application, "project_status", lambda pid: status)

    def forbidden(*args, **kwargs):
        pytest.fail("ambiguous or stale approval must not authenticate")

    monkeypatch.setattr(KeeperExecutive, "authenticate_founder", forbidden)
    with pytest.raises(PermissionError):
        approve(application, project_id, original)


def test_renewal_rejects_stale_display_before_creating_challenge(tmp_path, monkeypatch):
    application, project_id, original = expired_application(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("stale display must not create a challenge")

    monkeypatch.setattr(KeeperExecutive, "request_charter_approval", forbidden)
    with pytest.raises(PermissionError, match="displayed charter"):
        application.approve_and_plan_current_charter(
            project_id, expected_charter_id=original.charter_id,
            expected_charter_revision=original.charter_revision + 1,
        )
