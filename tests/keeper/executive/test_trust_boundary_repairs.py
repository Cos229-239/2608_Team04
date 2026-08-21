from __future__ import annotations

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from keeper.app.storage import KeeperStore
from keeper.executive.authority import AuthorityEvaluator, TrustedActionClassifier
from keeper.executive.charters import CharterService
from keeper.executive.enums import ActionCategory, ActionEffect, ApprovalKind
from keeper.executive.enums import ExecutiveState, FounderApprovalIntent
from keeper.executive.founder_auth import TestFounderAuthenticator
from keeper.executive.intake import ConversationIntake
from keeper.executive.models import (
    ActionEffects,
    ApprovalRecord,
    ProjectCharter,
    ProjectRecord,
    ProposedAction,
    SpecialistProfile,
    utc_now,
)
from keeper.executive.planning import WorkflowPlanner
from keeper.executive.runtime import ExecutiveRuntime
from keeper.executive.state import transition_project
from keeper.executive.repository import TestExecutiveRepository, charter_approval_digest
from tests.keeper.executive.authority_semantics import (
    SemanticAuthorityTransport,
    semantic_gateway,
)
from tests.keeper.executive.fixture_store import (
    delete_executive_fixture,
    replace_executive_fixture,
)


def _proposed(
    tmp_path: Path,
    *,
    interaction_id: str = "founder-approval",
    resolve_questions: bool = True,
    budget_limit: float = 0,
) -> tuple[CharterService, ProjectRecord, ProjectCharter]:
    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    authenticator = TestFounderAuthenticator()
    service = CharterService.for_test(
        TestExecutiveRepository(store, authenticator),
        authenticator,
    )
    replacements: dict[str, object] = {
        "target_audience": "Founder",
        "approved_providers": ("codex", "reviewer-provider"),
        "approved_tools": ("filesystem",),
    }
    if budget_limit:
        replacements.update(
            {
                "budget_limit": budget_limit,
                "budget_policy": f"up to {budget_limit:.2f} USD",
                "budget_currency": "USD",
            }
        )
    if resolve_questions:
        replacements["success_criteria"] = ("tests pass",)
    intake = ConversationIntake.revise(
        ConversationIntake().extract(
            f"Create a small application in {tmp_path} with full delegation and no spending."
        ),
        replacements=replacements,
    )
    project = service.create_project(intake)
    service.repository.save_conversation(
        interaction_id,
        {
            "interaction_id": interaction_id,
            "project_id": project.project_id,
            "speaker": "Founder",
            "message": "Approve this exact proposed charter.",
            "created_at": utc_now(),
        },
    )
    return service, project, service.propose(service.draft(project, intake))


def _approve(
    service: CharterService,
    proposed: ProjectCharter,
) -> tuple[ProjectCharter, ApprovalRecord]:
    challenge = service.request_approval(proposed)
    confirmation = service.authenticate(challenge)
    approved, approval, _ = service.confirm_approval(
        challenge.challenge_id,
        intent=FounderApprovalIntent.APPROVE_CHARTER,
        confirmation=confirmation,
    )
    return approved, approval


def test_direct_or_caller_constructed_approved_charter_is_rejected(
    tmp_path: Path,
) -> None:
    service, _, proposed = _proposed(tmp_path)
    forged = replace(
        proposed,
        status="APPROVED",
        founder_approval_identity="specialist-impersonating-Founder",
        founder_approval_record_id="nonexistent-approval",
        founder_authorization_capability={"forged": True},
        founder_authorization_capability_digest="0" * 64,
    )
    with pytest.raises(PermissionError, match="transition"):
        service.repository.save_charter(forged, expected=proposed)
    with pytest.raises(PermissionError, match="CAS"):
        service.repository.save_charter(forged)


@pytest.mark.parametrize("identity", ["", "founder", "specialist-impersonating-Founder"])
def test_only_exact_authenticated_founder_identity_can_approve(
    tmp_path: Path,
    identity: str,
) -> None:
    service, _, proposed = _proposed(tmp_path)
    with pytest.raises(PermissionError, match="cannot approve"):
        service.approve(
            proposed,
            approver=identity,
            source_interaction_id="founder-approval",
        )


def test_missing_or_cross_project_approval_source_is_rejected(
    tmp_path: Path,
) -> None:
    service, _, proposed = _proposed(tmp_path)
    with pytest.raises(PermissionError, match="cannot approve"):
        service.approve(
            proposed,
            approver="Founder",
            source_interaction_id="nonexistent",
        )

    other_intake = ConversationIntake.revise(
        ConversationIntake().extract("Create a separate research report."),
        replacements={
            "success_criteria": ("report exists",),
            "target_audience": "Founder",
        },
    )
    other_project = service.create_project(other_intake)
    service.repository.save_conversation(
        "other-founder-approval",
        {
            "interaction_id": "other-founder-approval",
            "project_id": other_project.project_id,
            "speaker": "Founder",
            "message": "Approve only the other project.",
            "created_at": utc_now(),
        },
    )
    with pytest.raises(PermissionError, match="cannot approve"):
        service.approve(
            proposed,
            approver="Founder",
            source_interaction_id="other-founder-approval",
        )


def test_activation_reloads_durable_charter_and_approval(
    tmp_path: Path,
) -> None:
    service, project, proposed = _proposed(tmp_path)
    approved, approval = _approve(service, proposed)
    caller_substitution = replace(
        approved,
        title="same ID but caller-mutated content",
        founder_approval_record_id="nonexistent-approval",
    )
    active = service.activate(caller_substitution)
    stored = service.repository.charter(approved.charter_id)
    assert active.project_id == project.project_id
    assert stored.title == approved.title
    assert stored.status == "ACTIVE"
    assert stored.founder_approval_record_id == approval.approval_id


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("project_id", "another-project"),
        ("charter_id", "another-charter"),
        ("charter_revision", 999),
        ("evidence_digest", "0" * 64),
        ("approver", "copied-Founder-label"),
    ],
)
def test_copied_or_misbound_durable_approval_is_rejected(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    service, _, proposed = _proposed(tmp_path)
    approved, approval = _approve(service, proposed)
    tampered = approval.to_dict()
    tampered[field] = value
    replace_executive_fixture(
        service.repository.store,
        "executive_approvals",
        approval.approval_id,
        tampered,
    )
    with pytest.raises(PermissionError, match="binding"):
        service.activate(approved)


def test_missing_approval_and_same_content_different_id_are_rejected(
    tmp_path: Path,
) -> None:
    service, _, proposed = _proposed(tmp_path)
    substituted = replace(
        proposed,
        charter_id="same-content-different-id",
    )
    with pytest.raises(PermissionError, match="cannot approve"):
        service.approve(
            substituted,
            approver="Founder",
            source_interaction_id="founder-approval",
        )
    approved, approval = _approve(service, proposed)
    delete_executive_fixture(
        service.repository.store,
        "executive_approvals",
        approval.approval_id,
    )
    with pytest.raises(PermissionError, match="unavailable"):
        service.activate(approved)


def test_explicit_challenge_is_one_time_and_requires_structured_intent(
    tmp_path: Path,
) -> None:
    service, _, proposed = _proposed(tmp_path)
    challenge = service.request_approval(proposed)
    with pytest.raises(PermissionError, match="intent"):
        service.confirm_approval(challenge.challenge_id, intent=None)  # type: ignore[arg-type]
    confirmation = service.authenticate(challenge)
    approved, _, event = service.confirm_approval(
        challenge.challenge_id,
        intent=FounderApprovalIntent.APPROVE_CHARTER,
        confirmation=confirmation,
    )
    assert event.authenticated_identity.startswith("S-1-")
    assert event.charter_digest == charter_approval_digest(proposed)
    assert service.activate(approved).state == "ACTIVE"
    with pytest.raises(PermissionError, match="consumed"):
        service.confirm_approval(
            challenge.challenge_id,
            intent=FounderApprovalIntent.APPROVE_CHARTER,
            confirmation=confirmation,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("charter_digest", "0" * 64, "matches"),
        ("project_id", "another-project", "identify"),
        ("charter_revision", 999, "identify"),
        ("expires_at", "2000-01-01T00:00:00+00:00", "stale"),
    ],
)
def test_tampered_stale_or_cross_bound_challenge_is_rejected(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    service, _, proposed = _proposed(tmp_path)
    challenge = service.request_approval(proposed)
    confirmation = service.authenticate(challenge)
    tampered = challenge.to_dict()
    tampered[field] = value
    replace_executive_fixture(
        service.repository.store,
        "executive_founder_approval_challenges",
        challenge.challenge_id,
        tampered,
    )
    with pytest.raises(PermissionError, match="match|stale"):
        service.confirm_approval(
            challenge.challenge_id,
            intent=FounderApprovalIntent.APPROVE_CHARTER,
            confirmation=confirmation,
        )


def test_copied_or_modified_approval_event_cannot_activate(
    tmp_path: Path,
) -> None:
    service, _, proposed = _proposed(tmp_path)
    approved, approval = _approve(service, proposed)
    event = service.repository.store.get(
        "executive_founder_approval_events",
        approval.source_interaction_id,
    )
    assert event is not None
    event["project_id"] = "copied-project"
    replace_executive_fixture(
        service.repository.store,
        "executive_founder_approval_events",
        approval.source_interaction_id,
        event,
    )
    with pytest.raises(PermissionError, match="binding"):
        service.activate(approved)


def test_unresolved_material_question_blocks_activation(tmp_path: Path) -> None:
    service, _, proposed = _proposed(tmp_path, resolve_questions=False)
    approved, _ = _approve(service, proposed)
    with pytest.raises(PermissionError, match="unresolved"):
        service.activate(approved)


def test_exact_non_goal_and_disguised_deployment_are_denied(
    tmp_path: Path,
) -> None:
    service, project, proposed = _proposed(tmp_path)
    approved, _ = _approve(service, proposed)
    active_project = service.activate(approved)
    active = service.repository.charter(approved.charter_id)
    denied_charter = replace(active, non_goals=("production deployment",))
    action = ProposedAction(
        "deploy",
        project.project_id,
        active.revision,
        ActionCategory.WRITE.value,
        "production deployment",
        "codex",
        "filesystem",
        str(tmp_path),
        active.deliverables,
        0,
        False,
        "LOW",
        "INTERNAL",
        True,
        objective="Deploy the application to production",
        deployment=True,
        trusted_source="DURABLE_WORKFLOW_TASK",
    )
    decision = AuthorityEvaluator().evaluate(
        active_project, denied_charter, action
    )
    assert decision.outcome == "DENIED"
    assert decision.rule == "explicit-non-goal"


@pytest.mark.parametrize(
    ("objective", "flag"),
    [
        ("Publish externally as a public release", "publication"),
        ("Select and buy access to a paid provider", "spending"),
    ],
)
def test_publication_or_spending_disguised_as_write_is_denied(
    tmp_path: Path,
    objective: str,
    flag: str,
) -> None:
    service, _, proposed = _proposed(tmp_path)
    approved, _ = _approve(service, proposed)
    project = service.activate(approved)
    charter = service.repository.charter(approved.charter_id)
    action = ProposedAction(
        "hidden-side-effect",
        project.project_id,
        charter.revision,
        ActionCategory.WRITE.value,
        objective,
        "codex",
        "filesystem",
        str(tmp_path),
        charter.deliverables,
        None if flag == "spending" else 0,
        False,
        "LOW",
        "INTERNAL",
        True,
        objective=objective,
        publication=flag == "publication",
        spending=flag == "spending",
        trusted_source="DURABLE_WORKFLOW_TASK",
    )
    decision = AuthorityEvaluator().evaluate(project, charter, action)
    assert decision.outcome == "DENIED"
    assert decision.rule == "classification-mismatch"


def test_readiness_classification_uses_actual_task_objective(
    tmp_path: Path,
) -> None:
    service, _, proposed = _proposed(tmp_path)
    approved, _ = _approve(service, proposed)
    project = service.activate(approved)
    charter = service.repository.charter(approved.charter_id)
    _, tasks = WorkflowPlanner(service.repository).generate(project, charter)
    task = tasks[0]
    specialist = SpecialistProfile(
        "codex",
        "model",
        "session",
        task.required_capabilities,
        ("software",),
        True,
        True,
        "independent-1",
        0,
        ("medium",),
        True,
        1.0,
        "included-plan",
        "2026-07",
        "USD",
        0.0,
        0.0,
        "session",
        True,
        True,
        "2026-07-01T00:00:00+00:00",
        "2099-01-01T00:00:00+00:00",
        "AUTHORITY_REGISTRATION",
    )
    action = TrustedActionClassifier().classify(task, charter, specialist)
    assert action.objective == task.objective
    assert action.target_resource == task.objective
    assert action.scope == charter.deliverables


def _activate(
    service: CharterService,
    proposed: ProjectCharter,
) -> tuple[ProjectRecord, ProjectCharter]:
    approved, _ = _approve(service, proposed)
    project = service.activate(approved)
    return project, service.repository.charter(approved.charter_id)


def _record_action_approval_interaction(
    service: CharterService,
    project_id: str,
) -> None:
    service.repository.save_conversation(
        "action-approval",
        {
            "interaction_id": "action-approval",
            "project_id": project_id,
            "speaker": "Founder",
            "message": "Approve the exact bounded action.",
            "created_at": utc_now(),
        },
    )


def _approve_action(
    service: CharterService,
    charter: ProjectCharter,
    action: ProposedAction,
    *,
    kind: ApprovalKind,
    limits: dict[str, object],
) -> ApprovalRecord:
    challenge = service.request_action_approval(
        action,
        charter_id=charter.charter_id,
        kind=kind,
        scope=charter.deliverables,
        limits=limits,
    )
    confirmation = service.authenticate(challenge)
    approval, _ = service.confirm_action_approval(
        challenge.challenge_id,
        confirmation=confirmation,
        intent=FounderApprovalIntent.APPROVE_ACTION,
    )
    return approval


def test_one_time_approval_is_consumed_atomically_once(tmp_path: Path) -> None:
    service, _, proposed = _proposed(tmp_path)
    project, charter = _activate(service, proposed)
    _record_action_approval_interaction(service, project.project_id)
    action = ProposedAction(
        "commit-once",
        project.project_id,
        charter.revision,
        ActionCategory.COMMIT.value,
        "repository commit",
        "codex",
        "filesystem",
        str(tmp_path),
        charter.deliverables,
        0,
        False,
        "LOW",
        "INTERNAL",
        True,
        objective="Commit the reviewed changes",
        git_mutation="MUTATE",
        trusted_source="DURABLE_WORKFLOW_TASK",
    )
    approval = _approve_action(
        service,
        charter,
        action,
        kind=ApprovalKind.ONE_TIME,
        limits={"action_id": "commit-once"},
    )

    def consume() -> str:
        repository = TestExecutiveRepository(
            KeeperStore(tmp_path / "keeper.db"), TestFounderAuthenticator()
        )
        try:
            repository.reserve_action_authority(
                action,
                approval_id=approval.approval_id,
                task_id="task-commit",
            )
        except PermissionError:
            return "rejected"
        return "consumed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(lambda _: consume(), range(2)))
    assert outcomes == ["consumed", "rejected"]
    with pytest.raises(PermissionError, match="binding"):
        service.repository.reserve_action_authority(
            action,
            approval_id=approval.approval_id,
            task_id="task-commit",
        )


def test_cumulative_spending_prevents_split_action_bypass(
    tmp_path: Path,
) -> None:
    service, project, proposed = _proposed(tmp_path, budget_limit=50)
    _, charter = _activate(service, proposed)
    _record_action_approval_interaction(service, project.project_id)
    outcomes: list[str] = []
    for index in range(10):
        action = ProposedAction(
            f"paid-action-{index}",
            project.project_id,
            charter.revision,
            ActionCategory.SPEND.value,
            f"paid provider action {index}",
            "codex",
            "filesystem",
            str(tmp_path),
            charter.deliverables,
            10,
            False,
            "LOW",
            "INTERNAL",
            True,
            objective="Use the explicitly approved paid provider",
            currency="USD",
            spending=True,
            trusted_source="DURABLE_WORKFLOW_TASK",
        )
        approval = _approve_action(
            service,
            charter,
            action,
            kind=ApprovalKind.AMOUNT_LIMITED,
            limits={
                "maximum_cost": 50,
                "currency": "USD",
                "provider": "codex",
                "workspace": str(tmp_path),
            },
        )
        try:
            service.repository.reserve_action_authority(
                action,
                approval_id=approval.approval_id,
                task_id=f"paid-task-{index}",
            )
        except PermissionError:
            outcomes.append("rejected")
        else:
            outcomes.append("reserved")
    assert outcomes == ["reserved"] * 5 + ["rejected"] * 5


def test_unknown_cost_and_absent_budget_fail_closed(tmp_path: Path) -> None:
    service, _, proposed = _proposed(tmp_path)
    project, charter = _activate(service, proposed)
    action = ProposedAction(
        "unknown-cost",
        project.project_id,
        charter.revision,
        ActionCategory.SPEND.value,
        "paid provider",
        "codex",
        "filesystem",
        str(tmp_path),
        charter.deliverables,
        None,
        False,
        "LOW",
        "INTERNAL",
        True,
        objective="Use a paid provider",
        currency="USD",
        spending=True,
        trusted_source="DURABLE_WORKFLOW_TASK",
    )
    decision = AuthorityEvaluator().evaluate(project, charter, action)
    assert decision.outcome == "DENIED"
    assert decision.rule == "classification-mismatch"


@pytest.mark.parametrize(
    ("objective", "effect", "category"),
    [
        (
            "Release the service on the customer-facing environment",
            ActionEffect.DEPLOY_PRODUCTION,
            ActionCategory.DEPLOY_PRODUCTION,
        ),
        (
            "Make available to users",
            ActionEffect.PUBLISH_PUBLIC,
            ActionCategory.PUBLISH_EXTERNAL,
        ),
        (
            "Publish the final artifact",
            ActionEffect.PUBLISH_PUBLIC,
            ActionCategory.PUBLISH_EXTERNAL,
        ),
        (
            "Ship to customers",
            ActionEffect.DEPLOY_PRODUCTION,
            ActionCategory.DEPLOY_PRODUCTION,
        ),
        (
            "Promote the build",
            ActionEffect.DEPLOY_PRODUCTION,
            ActionCategory.DEPLOY_PRODUCTION,
        ),
        (
            "Replace remote branch history",
            ActionEffect.HISTORY_REWRITE,
            ActionCategory.REWRITE_HISTORY,
        ),
        (
            "Subscribe to premium provider",
            ActionEffect.PAID_PROVIDER_USE,
            ActionCategory.SPEND,
        ),
        (
            "Authorize real trades",
            ActionEffect.LIVE_TRADING,
            ActionCategory.ENABLE_LIVE_TRADING,
        ),
    ],
)
def test_euphemistic_protected_actions_require_exact_structured_effect(
    tmp_path: Path,
    objective: str,
    effect: ActionEffect,
    category: ActionCategory,
) -> None:
    service, _, proposed = _proposed(tmp_path)
    project, charter = _activate(service, proposed)
    _, tasks = WorkflowPlanner(service.repository).generate(project, charter)
    task = replace(
        tasks[0],
        objective=objective,
        authority_category=category.value,
        action_effects=ActionEffects(
            (effect.value,),
            "PRODUCTION" if effect is ActionEffect.DEPLOY_PRODUCTION else "EXTERNAL",
            "CUSTOMER_FACING",
            "PUBLIC" if effect is ActionEffect.PUBLISH_PUBLIC else "NONE",
            "PRODUCTION" if effect is ActionEffect.DEPLOY_PRODUCTION else "NONE",
            "LIVE" if effect is ActionEffect.LIVE_TRADING else "NONE",
            "PAID" if effect is ActionEffect.PAID_PROVIDER_USE else "NONE",
            "HISTORY_REWRITE" if effect is ActionEffect.HISTORY_REWRITE else "NONE",
            "NONE",
            "NONE",
            "LIVE_TRADING" if effect is ActionEffect.LIVE_TRADING else "NONE",
            objective,
            charter.workspaces[0],
            None,
            charter.approved_tools[0],
            False,
            "INTERNAL",
        ),
    )
    from keeper.executive.authority import validate_durable_task_effects

    validate_durable_task_effects(task)
    assert task.action_effects is not None
    with pytest.raises(PermissionError, match="inconsistent"):
        validate_durable_task_effects(
            replace(
                task,
                action_effects=replace(
                    task.action_effects,
                    side_effect_classes=(ActionEffect.LOCAL_WRITE.value,),
                ),
            )
        )


def test_ambiguous_external_action_fails_closed(tmp_path: Path) -> None:
    service, _, proposed = _proposed(tmp_path)
    project, charter = _activate(service, proposed)
    _, tasks = WorkflowPlanner(service.repository).generate(project, charter)
    assert tasks[0].action_effects is not None
    task = replace(
        tasks[0],
        objective="Activate the external environment",
        action_effects=replace(
            tasks[0].action_effects,
            target_resource="Activate the external environment",
        ),
    )
    from keeper.executive.authority import validate_durable_task_effects

    with pytest.raises(PermissionError, match="ambiguous"):
        validate_durable_task_effects(task)


def test_provider_pricing_is_trusted_and_unknown_or_false_zero_fails_closed(
    tmp_path: Path,
) -> None:
    service, _, proposed = _proposed(tmp_path)
    project, charter = _activate(service, proposed)
    _, tasks = WorkflowPlanner(service.repository).generate(project, charter)
    task = tasks[0]
    included = SpecialistProfile(
        "codex", "model", "session", task.required_capabilities, ("software",),
        True, True, "identity", 0, ("high",), True, 1.0,
        "pricing", "v1", "USD", 0.0, 0.0, "session", True, True,
        "2026-07-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00",
        "AUTHORITY_REGISTRATION",
    )
    action = TrustedActionClassifier().classify(task, charter, included)
    assert action.cost == 0
    assert action.spending is False

    with pytest.raises(PermissionError, match="positive provider cost tier"):
        TrustedActionClassifier().classify(
            task, charter, replace(included, cost_tier=9)
        )
    with pytest.raises(PermissionError, match="unavailable"):
        TrustedActionClassifier().classify(
            task, charter, replace(included, pricing_identity=None)
        )
    with pytest.raises(PermissionError, match="expired"):
        TrustedActionClassifier().classify(
            task,
            charter,
            replace(included, quote_expiration="2000-01-01T00:00:00+00:00"),
        )
    with pytest.raises(PermissionError, match="currency"):
        TrustedActionClassifier().classify(
            task, charter, replace(included, currency=None)
        )

    paid = replace(
        included,
        cost_tier=9,
        included_plan=False,
        marginally_free=False,
        estimated_cost=1.0,
        maximum_cost=2.0,
    )
    paid_action = TrustedActionClassifier().classify(task, charter, paid)
    assert paid_action.category == ActionCategory.SPEND
    assert paid_action.cost == 2.0
    decision = AuthorityEvaluator().evaluate(project, charter, paid_action)
    assert decision.rule == "absent-spending-authority"


def test_prelaunch_reservation_failure_releases_approval_and_budget(
    tmp_path: Path,
) -> None:
    service, _, proposed = _proposed(tmp_path, budget_limit=10)
    project, charter = _activate(service, proposed)
    authority = SemanticAuthorityTransport()
    paid = authority.registrations["registration-codex"][
        "pricing_authority"
    ]
    paid.update(
        {
            "estimated_cost": 1.0,
            "maximum_cost": 2.0,
            "included_plan": False,
            "marginally_free": False,
            "cost_tier": 9,
        }
    )
    authority.registrations["registration-reviewer"][
        "executive_capability_set"
    ] = ["review"]
    gateway, _ = semantic_gateway(tmp_path, transport=authority)
    runtime = ExecutiveRuntime(service.repository, gateway)
    runtime.progress(project.project_id)
    task = next(
        item
        for item in service.repository.tasks(project.project_id)
        if item.title == "Requirements"
    )
    _record_action_approval_interaction(service, project.project_id)
    specialist = next(
        item for item in gateway.specialists(charter)
        if item.provider_id == "codex"
    )
    action = TrustedActionClassifier().classify(task, charter, specialist)
    approval = _approve_action(
        service,
        charter,
        action,
        kind=ApprovalKind.ONE_TIME,
        limits={
            "action_id": f"task-action:{task.task_id}",
            "maximum_cost": 10.0,
            "currency": "USD",
            "provider": "codex",
        },
    )
    authority.fail_before_reservation = True
    waiting = runtime.progress(project.project_id)
    released = service.repository.task(task.task_id)
    restored = next(
        item
        for item in service.repository.approvals(
            project.project_id, charter.revision
        )
        if item.approval_id == approval.approval_id
    )
    with service.repository.store.connect() as connection:
        budget_states = [
            str(row["state"])
            for row in connection.execute(
                "SELECT state FROM executive_budget_reservations"
            ).fetchall()
        ]
        consumptions = int(
            connection.execute(
                "SELECT COUNT(*) FROM executive_approval_consumptions"
            ).fetchone()[0]
        )
    assert waiting.state == "WAITING_FOR_PROVIDER"
    assert released.status == "READY"
    assert released.authority_attempt_id is None
    assert restored.consumed_at is None
    assert budget_states == ["RELEASED"]
    assert consumptions == 0


def test_generic_store_cannot_mutate_executive_lifecycle_tables(
    tmp_path: Path,
) -> None:
    store = KeeperStore(tmp_path / "keeper.db")
    store.migrate()
    with pytest.raises(PermissionError, match="specialized repository"):
        store.upsert(
            "executive_tasks",
            "forged-task",
            {"task_id": "forged-task"},
        )
    with pytest.raises(PermissionError, match="specialized repository"):
        store.delete("executive_approvals", "approval")


def test_stale_project_write_and_cross_project_task_are_rejected(
    tmp_path: Path,
) -> None:
    service, project, proposed = _proposed(tmp_path)
    active_project, charter = _activate(service, proposed)
    paused = transition_project(
        active_project, ExecutiveState.PAUSED, "test pause"
    )
    service.repository.save_project(paused, expected=active_project)
    with pytest.raises(PermissionError, match="stale"):
        service.repository.save_project(paused, expected=active_project)

    resumed = replace(
        paused,
        state=ExecutiveState.EXECUTING.value,
        pause_reason=None,
        updated_at=utc_now(),
    )
    service.repository.save_project(resumed, expected=paused)
    _, tasks = WorkflowPlanner(service.repository).generate(resumed, charter)
    forged = replace(
        tasks[0],
        task_id="cross-project-task",
        project_id=project.project_id + "-other",
    )
    with pytest.raises((KeyError, PermissionError)):
        service.repository.save_task(forged)
