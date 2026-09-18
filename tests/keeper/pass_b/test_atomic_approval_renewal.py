"""Concurrent renewal uses one durable request, never an implicit approval."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest

from keeper.app.storage import KeeperStore
from keeper.executive.models import ProjectCharter
from keeper.executive.enums import FounderApprovalIntent
from keeper.executive.service import KeeperExecutive
from keeper.pass_b.application import PassBApplication
from tests.keeper.executive.fixture_store import insert_executive_fixture, replace_executive_fixture
from tests.keeper.executive.test_founder_authentication import _proposed
from tests.keeper.pass_b.test_teammate_approval_integration import expired_application, approve


def proposal(application, project_id, original):
    return ProjectCharter.from_dict(next(
        item for item in application.project_status(project_id)["charter_history"]
        if item["charter_id"] == original.charter_id
    ))


def test_concurrent_renewals_share_one_request_even_when_auth_cancelled(tmp_path, monkeypatch):
    application, project_id, original = expired_application(tmp_path)
    applications = [application] + [PassBApplication(
        tmp_path, executive=KeeperExecutive(tmp_path / "executive.db")
    ) for _ in range(3)]
    gate = Barrier(4)
    request = KeeperExecutive.request_charter_approval

    def simultaneous(self, charter, *, reuse_pending=False):
        assert reuse_pending
        gate.wait(timeout=20)
        return request(self, charter, reuse_pending=reuse_pending)

    def cancelled(self, challenge):
        raise PermissionError("cancelled " + challenge.challenge_id)

    monkeypatch.setattr(KeeperExecutive, "request_charter_approval", simultaneous)
    monkeypatch.setattr(KeeperExecutive, "authenticate_founder", cancelled)

    def renew(app):
        with pytest.raises(PermissionError, match="cancelled") as error:
            approve(app, project_id, original)
        return str(error.value)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(renew, applications))
    assert len(set(results)) == 1
    status = application.project_status(project_id)
    assert len(status["pending_approvals"]) == 1
    assert not status.get("active_charter")


def test_response_loss_and_restart_reuse_without_extending_expiry(tmp_path):
    application, project_id, original = expired_application(tmp_path)
    charter = proposal(application, project_id, original)
    first = application.executive.request_charter_approval(charter, reuse_pending=True)
    restarted = KeeperExecutive(tmp_path / "executive.db")
    second = restarted.request_charter_approval(charter, reuse_pending=True)
    assert second == first
    assert first.challenge_id != original.challenge_id
    assert first.nonce != original.nonce
    assert first.charter_digest == original.charter_digest


def test_expired_renewal_gets_new_nonce_and_identity(tmp_path):
    application, project_id, original = expired_application(tmp_path)
    charter = proposal(application, project_id, original)
    first = application.executive.request_charter_approval(charter, reuse_pending=True)
    payload = first.to_dict()
    payload["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    replace_executive_fixture(KeeperStore(tmp_path / "executive.db"),
        "executive_founder_approval_challenges", first.challenge_id, payload)
    second = application.executive.request_charter_approval(charter, reuse_pending=True)
    assert second.challenge_id != first.challenge_id
    assert second.nonce != first.nonce


@pytest.mark.parametrize("field,value", [
    ("charter_digest", "0" * 64),
    ("challenge_id", "wrong-id"),
    ("consumed_event_id", "already-consumed"),
    ("requested_at", "2099-01-01T00:00:00+00:00"),
])
def test_renewal_rejects_invalid_pending_binding(tmp_path, field, value):
    application, project_id, original = expired_application(tmp_path)
    charter = proposal(application, project_id, original)
    first = application.executive.request_charter_approval(charter, reuse_pending=True)
    payload = first.to_dict()
    payload[field] = value
    replace_executive_fixture(KeeperStore(tmp_path / "executive.db"),
        "executive_founder_approval_challenges", first.challenge_id, payload)
    with pytest.raises(PermissionError, match="binding"):
        application.executive.request_charter_approval(charter, reuse_pending=True)


def test_preexisting_duplicate_requests_are_not_silently_chosen(tmp_path):
    application, project_id, original = expired_application(tmp_path)
    charter = proposal(application, project_id, original)
    for _ in range(2):
        application.executive.request_charter_approval(charter)
    with pytest.raises(PermissionError, match="multiple pending"):
        application.executive.request_charter_approval(charter, reuse_pending=True)


def test_reused_request_still_requires_authentication_and_is_one_use(tmp_path):
    service, charter = _proposed(tmp_path)
    first = service.request_approval(charter, reuse_pending=True)
    reused = service.request_approval(charter, reuse_pending=True)
    assert first == reused
    with pytest.raises(PermissionError):
        service.confirm_approval(reused.challenge_id,
            intent=FounderApprovalIntent.APPROVE_CHARTER)
    confirmation = service.authenticate(reused)
    service.confirm_approval(reused.challenge_id,
        intent=FounderApprovalIntent.APPROVE_CHARTER, confirmation=confirmation)
    with pytest.raises(PermissionError, match="consumed"):
        service.confirm_approval(first.challenge_id,
            intent=FounderApprovalIntent.APPROVE_CHARTER, confirmation=confirmation)


def test_newer_charter_prevents_old_pending_request_reuse(tmp_path):
    service, charter = _proposed(tmp_path)
    service.request_approval(charter, reuse_pending=True)
    updated = replace(charter, charter_id="newer-charter", revision=charter.revision + 1)
    insert_executive_fixture(KeeperStore(tmp_path / "keeper.db"),
        "project_charters", updated.charter_id, updated.to_dict())
    with pytest.raises(PermissionError, match="newer|exact proposed"):
        service.request_approval(charter, reuse_pending=True)
