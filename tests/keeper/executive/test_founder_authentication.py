from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from keeper.app.storage import KeeperStore
from keeper.executive.charters import CharterService
from keeper.executive.enums import ActionCategory, ApprovalKind, FounderApprovalIntent
from keeper.executive.founder_auth import (
    ProductionFounderAuthenticator,
    TestApprovalConfirmation,
    TestFounderAuthenticator,
)
from keeper.executive.models import (
    FounderApprovalEvent,
    ProjectCharter,
    ProposedAction,
)
from keeper.executive.repository import (
    ExecutiveRepository,
    ProductionExecutiveRepository,
    TestExecutiveRepository,
)
from tests.keeper.executive.test_intake_charters import approved_project


def _proposed(tmp_path: Path) -> tuple[CharterService, ProjectCharter]:
    charter_service, _, active = approved_project(tmp_path)
    revised = charter_service.revise(
        active,
        {"purpose": f"{active.purpose} revised"},
        reason="authentication regression",
        authority_basis="new explicit approval required",
    )
    return charter_service, charter_service.propose(revised)


def test_challenge_id_or_missing_authenticator_result_cannot_confirm(
    tmp_path: Path,
) -> None:
    charter_service, proposed = _proposed(tmp_path)
    challenge = charter_service.request_approval(proposed)
    with pytest.raises(PermissionError, match="intent"):
        charter_service.confirm_approval(
            challenge.challenge_id,
            intent=FounderApprovalIntent.APPROVE_CHARTER,
        )
    with pytest.raises(TypeError, match="ProductionExecutiveRepository"):
        ExecutiveRepository(KeeperStore(tmp_path / "keeper.db"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("challenge_nonce", "wrong-nonce"),
        ("project_id", "wrong-project"),
        ("charter_id", "wrong-charter"),
        ("charter_revision", 999),
        ("approval_action", FounderApprovalIntent.APPROVE_ACTION.value),
        ("bound_digest", "0" * 64),
        ("session_id", "wrong-session"),
        ("principal_sid", "S-1-5-21-9999"),
        ("expires_at", "2000-01-01T00:00:00+00:00"),
    ],
)
def test_modified_challenge_response_is_rejected(
    tmp_path: Path, field: str, value: object
) -> None:
    charter_service, proposed = _proposed(tmp_path)
    challenge = charter_service.request_approval(proposed)
    confirmation = charter_service.authenticate(challenge)
    assert isinstance(confirmation, TestApprovalConfirmation)
    modified = replace(confirmation, **cast(Any, {field: value}))
    with pytest.raises(PermissionError, match="proof|match"):
        charter_service.confirm_approval(
            challenge.challenge_id,
            intent=FounderApprovalIntent.APPROVE_CHARTER,
            confirmation=modified,
        )


def test_confirmation_is_one_use_and_cannot_cross_challenges(
    tmp_path: Path,
) -> None:
    charter_service, proposed = _proposed(tmp_path)
    first = charter_service.request_approval(proposed)
    second = charter_service.request_approval(proposed)
    confirmation = charter_service.authenticate(first)
    with pytest.raises(PermissionError, match="match"):
        charter_service.confirm_approval(
            second.challenge_id,
            intent=FounderApprovalIntent.APPROVE_CHARTER,
            confirmation=confirmation,
        )
    approved, _, _ = charter_service.confirm_approval(
        first.challenge_id,
        intent=FounderApprovalIntent.APPROVE_CHARTER,
        confirmation=confirmation,
    )
    with pytest.raises(PermissionError, match="consumed"):
        charter_service.confirm_approval(
            first.challenge_id,
            intent=FounderApprovalIntent.APPROVE_CHARTER,
            confirmation=confirmation,
        )
    assert charter_service.activate(approved).active_charter_revision == 2


def test_revoked_session_cannot_confirm(tmp_path: Path) -> None:
    charter_service, proposed = _proposed(tmp_path)
    challenge = charter_service.request_approval(proposed)
    confirmation = charter_service.authenticate(challenge)
    charter_service.repository.revoke_founder_session(confirmation.session_id)
    with pytest.raises(PermissionError, match="stale|revoked"):
        charter_service.confirm_approval(
            challenge.challenge_id,
            intent=FounderApprovalIntent.APPROVE_CHARTER,
            confirmation=confirmation,
        )


def test_local_founder_string_cannot_construct_an_event() -> None:
    with pytest.raises(ValueError, match="invalid"):
        FounderApprovalEvent(
            "event",
            2,
            "LOCAL_FOUNDER",
            "TEST_CHALLENGE_HMAC",
            "Founder",
            "session",
            "machine",
            "KEEPER_EXECUTIVE",
            "project",
            "charter",
            1,
            "0" * 64,
            FounderApprovalIntent.APPROVE_CHARTER.value,
            FounderApprovalIntent.APPROVE_CHARTER.value,
            "challenge",
            "0" * 64,
            1,
            "interaction",
            "2026-07-28T00:00:00+00:00",
            None,
        )


def _commit_action(
    project_id: str,
    revision: int,
    scope: tuple[str, ...],
    tmp_path: Path,
) -> ProposedAction:
    return ProposedAction(
        "commit-authenticated",
        project_id,
        revision,
        ActionCategory.COMMIT.value,
        "repository commit",
        "codex",
        "filesystem",
        str(tmp_path),
        scope,
        0,
        False,
        "LOW",
        "INTERNAL",
        True,
        objective="Commit the reviewed changes",
        git_mutation="COMMIT",
        trusted_source="DURABLE_WORKFLOW_TASK",
        repository="keeper",
        branch="feature/authenticated",
    )


def test_conversation_and_caller_strings_cannot_approve_actions(
    tmp_path: Path,
) -> None:
    charter_service, project, charter = approved_project(tmp_path)
    charter_service.repository.save_conversation(
        "negative-founder-message",
        {
            "interaction_id": "negative-founder-message",
            "project_id": project.project_id,
            "speaker": "Founder",
            "message": "This does not approve any commit.",
            "created_at": charter.updated_at,
        },
    )
    with pytest.raises(PermissionError, match="conversations"):
        charter_service.repository.grant_action_approval(
            project_id=project.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            kind=ApprovalKind.ONE_TIME,
            action_category=ActionCategory.COMMIT,
            scope=charter.deliverables,
            limits={},
            approver="Founder",
            source_interaction_id="negative-founder-message",
        )


def test_action_approval_is_exact_and_succeeds_once(tmp_path: Path) -> None:
    charter_service, project, charter = approved_project(tmp_path)
    action = _commit_action(
        project.project_id, charter.revision, charter.deliverables, tmp_path
    )
    challenge = charter_service.request_action_approval(
        action,
        charter_id=charter.charter_id,
        kind=ApprovalKind.ONE_TIME,
        scope=charter.deliverables,
        limits={
            "action_id": action.action_id,
            "provider": action.provider,
            "tool": action.tool,
            "workspace": action.workspace,
            "repository": action.repository,
            "branch": action.branch,
        },
    )
    confirmation = charter_service.authenticate(challenge)
    approval, event = charter_service.confirm_action_approval(
        challenge.challenge_id,
        confirmation=confirmation,
        intent=FounderApprovalIntent.APPROVE_ACTION,
    )
    assert event.authenticated_identity.startswith("S-1-")
    for modified in (
        replace(action, target_resource="another repository"),
        replace(action, repository="another-repository"),
        replace(action, branch="main"),
        replace(action, provider="another-provider"),
    ):
        with pytest.raises(PermissionError, match="binding|limits"):
            charter_service.repository.reserve_action_authority(
                modified, approval_id=approval.approval_id
            )
    charter_service.repository.reserve_action_authority(
        action, approval_id=approval.approval_id
    )
    with pytest.raises(PermissionError, match="binding"):
        charter_service.repository.reserve_action_authority(
            action, approval_id=approval.approval_id
        )


def test_production_and_test_authenticators_are_structurally_sealed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    test_authenticator = TestFounderAuthenticator()
    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    test_repository = TestExecutiveRepository(store, test_authenticator)
    with pytest.raises(TypeError, match="composition"):
        CharterService.production(test_repository, test_authenticator)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="ProductionExecutiveRepository"):
        ExecutiveRepository(store, founder_authenticator=lambda _: None)
    test_service = CharterService.for_test(
        test_repository, test_authenticator
    )
    with pytest.raises(AttributeError, match="immutable"):
        test_service._CharterService__authenticator = test_authenticator
    monkeypatch.setenv("KEEPER_FOUNDER_AUTH_BYPASS", "LOCAL_FOUNDER")
    another_service, another_proposed = _proposed(tmp_path / "other")
    another_challenge = another_service.request_approval(another_proposed)
    test_confirmation = another_service.authenticate(another_challenge)

    production = ProductionFounderAuthenticator(
        tmp_path / "production-proof-key.dpapi"
    )
    with pytest.raises(TypeError, match="production authenticator"):
        ProductionExecutiveRepository(store, test_authenticator)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="test authenticator"):
        TestExecutiveRepository(store, production)  # type: ignore[arg-type]
    with pytest.raises(PermissionError, match="non-production"):
        production.verify(another_challenge, test_confirmation)


@pytest.mark.parametrize(
    "table",
    [
        "executive_founder_authenticated_sessions",
        "executive_founder_approval_challenges",
        "executive_founder_approval_events",
        "executive_approvals",
        "project_charters",
    ],
)
def test_generic_store_cannot_insert_trusted_lifecycle(
    tmp_path: Path, table: str
) -> None:
    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    with pytest.raises(PermissionError, match="specialized"):
        store.upsert(table, "forged", {"id": "forged"})
    with pytest.raises(PermissionError, match="specialized"):
        store.insert_immutable(table, "forged", {"id": "forged"})
