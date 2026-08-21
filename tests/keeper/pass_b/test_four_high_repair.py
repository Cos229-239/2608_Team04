from __future__ import annotations

import copy
import hashlib
import hmac
import os
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.pass_b.application import PassBApplication
from keeper.pass_b.conversation import (
    ProjectStatusReader,
    activate_delegated_mode,
    revoke_delegated_mode,
    validate_delegated_action,
)
from keeper.pass_b.enums import (
    AssignmentRole,
    AssignmentState,
    DelegatedModeState,
    WorkflowState,
)
from keeper.pass_b.launch_authority import TestLaunchAuthority
from keeper.pass_b.models import (
    AssignmentRecord,
    AttemptRecord,
    DelegatedModeGrantRecord,
    ProviderSessionRecord,
    UsagePoolRecord,
    WorkItemRecord,
    WorkflowRecord,
)
from keeper.pass_b.orchestration import (
    OrchestrationService,
    authority_envelope_digest,
)
from keeper.pass_b.repository import (
    canonical_evidence_reference_path,
    canonical_scope,
    canonical_workspace_path,
)
from keeper.pass_b.usage_authority import (
    ProductionUsageResetVerifier,
    TestUsageResetVerifier,
    UnavailableUsageResetVerifier,
    UsageResetObservation,
)
from keeper.pass_b.workspaces import GitWorktreeService, WorkspacePolicy
from tests.keeper.pass_b.test_conversation_ui_pilot import (
    _approved_application,
)
from tests.keeper.pass_b.test_completion_repair_matrix import (
    _launch_ready,
)
from tests.keeper.pass_b.test_orchestration import (
    _assignment,
    _stack,
)


def _create_assignment_from(
    service: OrchestrationService,
    work_item: WorkItemRecord,
    template: AssignmentRecord,
) -> AssignmentRecord:
    return service.create_assignment(
        work_item=work_item,
        provider_id=template.provider_id,
        account_id=template.account_id,
        session_id=template.session_id,
        role=template.role,
        model_id=template.model_id,
        workspace_id=template.workspace_id,
        authority_envelope_digest=template.authority_envelope_digest,
        expected_evidence=template.expected_evidence,
        usage_policy=template.usage_policy,
        independence_key=template.independence_key,
    )


def _reviewer_with_validated_source(
    service: OrchestrationService,
    provider: Any,
    account: Any,
    sessions: tuple[ProviderSessionRecord, ...],
    root: Path,
    label: str,
) -> tuple[AssignmentRecord, Any]:
    producer = _assignment(
        service, provider, account, sessions[0],
        role=AssignmentRole.IMPLEMENTER,
    )
    producer_workspace = root / f"{label}-producer"
    _, authority_id = _launch_ready(
        service, producer, producer_workspace, f"{label}-producer"
    )
    source = service.run_assignment(
        producer.assignment_id,
        producer_workspace,
        authority_attempt_id=authority_id,
        global_context={},
        task_context={},
    )
    source = service.validate_evidence(
        source.evidence_bundle_id, producer_workspace
    )
    reviewer = _assignment(
        service,
        provider,
        account,
        sessions[1],
        role=AssignmentRole.REVIEWER,
        review_of_assignment_id=producer.assignment_id,
    )
    return reviewer, source


def test_nonpersisted_work_item_rejects_assignment(tmp_path: Path) -> None:
    _, service, _, provider, account, _, sessions, _ = _stack(tmp_path)
    durable = _assignment(service, provider, account, sessions[0])
    work_item = service.repository.get(
        WorkItemRecord, durable.work_item_id
    )
    fabricated = replace(work_item, work_item_id="fabricated-work-item")
    with pytest.raises(KeyError, match="work_item not found"):
        _create_assignment_from(service, fabricated, durable)


def test_nonpersisted_work_item_rejects_before_launch(tmp_path: Path) -> None:
    repository, service, clock, provider, account, _, sessions, _ = _stack(
        tmp_path
    )
    assignment = _assignment(service, provider, account, sessions[0])
    path = tmp_path / "workspace"
    _, authority_id = _launch_ready(service, assignment, path, "missing-item")
    repository.replace(
        replace(
            assignment,
            work_item_id="missing-work-item",
            updated_at=clock().isoformat(),
            revision=assignment.revision + 1,
        ),
        expected_revision=assignment.revision,
    )
    with pytest.raises(KeyError, match="work_item not found"):
        service.run_assignment(
            assignment.assignment_id,
            path,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
        )


def test_application_workflow_rejects_stale_current_charter(
    tmp_path: Path,
) -> None:
    application, charter = _approved_application(tmp_path)
    with pytest.raises(PermissionError, match="current Founder-approved"):
        application.orchestration.create_workflow(
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision + 1,
            strategy="stale-charter",
            authority_envelope_digest=authority_envelope_digest(
                charter.authority_envelope.to_dict()
            ),
        )

def test_nonpersisted_workflow_rejects_work_item(tmp_path: Path) -> None:
    _, service, _, _, _, _, _, _ = _stack(tmp_path)
    with pytest.raises(KeyError, match="workflow not found"):
        service.create_work_item(
            project_id="project-1",
            charter_id="charter-1",
            charter_revision=1,
            workflow_id="missing-workflow",
            title="fabricated",
            objective="must reject",
            required_roles=(AssignmentRole.IMPLEMENTER,),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workflow_id", "other-workflow"),
        ("project_id", "other-project"),
        ("charter_revision", 2),
    ],
)
def test_mutated_work_item_copy_rejects(
    tmp_path: Path, field: str, value: str | int
) -> None:
    _, service, _, provider, account, _, sessions, _ = _stack(tmp_path)
    assignment = _assignment(service, provider, account, sessions[0])
    durable = service.repository.get(WorkItemRecord, assignment.work_item_id)
    if field == "charter_revision":
        mutated = replace(durable, charter_revision=int(value))
    elif field == "project_id":
        mutated = replace(durable, project_id=str(value))
    else:
        mutated = replace(durable, workflow_id=str(value))
    with pytest.raises((KeyError, PermissionError)):
        _create_assignment_from(service, mutated, assignment)


def test_workflow_wrong_project_rejects(tmp_path: Path) -> None:
    _, service, _, _, _, _, _, _ = _stack(tmp_path)
    workflow = service.create_workflow(
        project_id="project-2",
        charter_id="charter-1",
        charter_revision=1,
        strategy="wrong-project",
        authority_envelope_digest="a" * 64,
    )
    with pytest.raises(PermissionError, match="durable workflow"):
        service.create_work_item(
            project_id="project-1",
            charter_id="charter-1",
            charter_revision=1,
            workflow_id=workflow.workflow_id,
            title="cross project",
            objective="reject",
        )


def test_workflow_wrong_charter_rejects(tmp_path: Path) -> None:
    _, service, _, _, _, _, _, _ = _stack(tmp_path)
    workflow = service.create_workflow(
        project_id="project-1",
        charter_id="charter-1",
        charter_revision=2,
        strategy="wrong-charter",
        authority_envelope_digest="a" * 64,
    )
    with pytest.raises(PermissionError, match="durable workflow"):
        service.create_work_item(
            project_id="project-1",
            charter_id="charter-1",
            charter_revision=1,
            workflow_id=workflow.workflow_id,
            title="cross charter",
            objective="reject",
        )


def test_superseded_workflow_rejects_before_launch(tmp_path: Path) -> None:
    repository, service, clock, provider, account, _, sessions, _ = _stack(
        tmp_path
    )
    assignment = _assignment(service, provider, account, sessions[0])
    path = tmp_path / "workspace"
    _, authority_id = _launch_ready(service, assignment, path, "superseded")
    workflow = repository.get(WorkflowRecord, assignment.workflow_id)
    repository.replace(
        replace(
            workflow,
            state=WorkflowState.SUPERSEDED,
            updated_at=clock().isoformat(),
            revision=workflow.revision + 1,
        ),
        expected_revision=workflow.revision,
    )
    with pytest.raises(PermissionError, match="active durable workflow"):
        service.run_assignment(
            assignment.assignment_id,
            path,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
        )


def test_exact_durable_binding_launches_only_once(tmp_path: Path) -> None:
    repository, service, _, provider, account, _, sessions, _ = _stack(
        tmp_path
    )
    assignment = _assignment(service, provider, account, sessions[0])
    path = tmp_path / "workspace"
    _, authority_id = _launch_ready(service, assignment, path, "exact")
    service.run_assignment(
        assignment.assignment_id,
        path,
        authority_attempt_id=authority_id,
        global_context={},
        task_context={},
    )
    with pytest.raises(PermissionError):
        service.run_assignment(
            assignment.assignment_id,
            path,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
        )
    attempts = repository.list(AttemptRecord)
    assert [item.assignment_id for item in attempts].count(
        assignment.assignment_id
    ) == 1


def _protected_tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "worktree"
    root.mkdir()
    (root / ".git").write_text("gitdir: test", encoding="utf-8")
    evidence = root / ".ai-workflow" / "pilot-invocations"
    run = evidence / "pilot-run"
    run.mkdir(parents=True)
    return root, evidence, run


@pytest.mark.parametrize(
    "variant",
    ("root", "descendant", "parent", "relative", "case", "separator"),
)
def test_pilot_evidence_writer_aliases_reject(
    tmp_path: Path, variant: str
) -> None:
    root, evidence, run = _protected_tree(tmp_path)
    candidates = {
        "root": evidence,
        "descendant": run,
        "parent": root,
        "relative": run / ".." / "pilot-run",
        "case": Path(str(run).upper()),
        "separator": Path(str(run).replace("\\", "/")),
    }
    with pytest.raises(PermissionError, match="pilot evidence"):
        canonical_workspace_path(candidates[variant])


def test_ancestor_containing_nested_pilot_evidence_rejects(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "nested" / "worktree"
    nested.mkdir(parents=True)
    (nested / ".git").write_text("gitdir: test", encoding="utf-8")
    (nested / ".ai-workflow" / "pilot-invocations").mkdir(parents=True)
    with pytest.raises(PermissionError, match="pilot evidence"):
        canonical_workspace_path(tmp_path)


def test_pilot_evidence_symlink_alias_rejects(tmp_path: Path) -> None:
    _, _, run = _protected_tree(tmp_path)
    alias = tmp_path / "pilot-alias"
    try:
        alias.symlink_to(run, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink is unavailable: {error}")
    with pytest.raises(PermissionError, match="pilot evidence"):
        canonical_workspace_path(alias)


def test_pilot_evidence_junction_alias_rejects(tmp_path: Path) -> None:
    _, _, run = _protected_tree(tmp_path)
    alias = tmp_path / "pilot-junction"
    result = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(alias), str(run)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        pytest.skip(f"directory junction is unavailable: {result.stderr}")
    with pytest.raises(PermissionError, match="pilot evidence"):
        canonical_workspace_path(alias)


def test_write_claim_beneath_pilot_evidence_rejects(tmp_path: Path) -> None:
    root, _, _ = _protected_tree(tmp_path)
    with pytest.raises(PermissionError, match="pilot evidence"):
        canonical_scope(str(root), ".ai-workflow/pilot-invocations/pilot-run")


def test_workspace_policy_rejects_parent_containing_pilot_evidence(
    tmp_path: Path,
) -> None:
    root, _, _ = _protected_tree(tmp_path)
    policy = WorkspacePolicy(tmp_path, ())
    with pytest.raises(PermissionError, match="protected scope"):
        policy.validate_target(root)


def test_explicit_read_only_pilot_evidence_reference_allowed(
    tmp_path: Path,
) -> None:
    _, _, run = _protected_tree(tmp_path)
    assert canonical_evidence_reference_path(run).endswith(
        "/.ai-workflow/pilot-invocations/pilot-run"
    )


def test_unrelated_isolated_workspace_succeeds(tmp_path: Path) -> None:
    path = tmp_path / "isolated"
    path.mkdir()
    (path / ".git").write_text("gitdir: test", encoding="utf-8")
    assert canonical_workspace_path(path).endswith("/isolated")


class _ArbitraryVerifier:
    def verify(self, *_: object, **__: object) -> None:
        return None



@pytest.mark.parametrize(
    "verifier",
    (
        TestUsageResetVerifier(),
        _ArbitraryVerifier(),
        type(
            "ProductionVerifierSubclass",
            (ProductionUsageResetVerifier,),
            {},
        )({("p", "a"): b"x" * 32}),
    ),
)
def test_production_application_rejects_nonexact_verifier(
    tmp_path: Path, verifier: object
) -> None:
    with pytest.raises(TypeError, match="exact production"):
        PassBApplication(tmp_path, usage_reset_verifier=verifier)  # type: ignore[arg-type]


def test_production_authority_requires_trusted_reset_verifier(
    tmp_path: Path,
) -> None:
    fake_authority = cast(ProductionAuthorityServiceClient, object())
    with pytest.raises(TypeError, match="exact production"):
        PassBApplication(tmp_path, authority_client=fake_authority)

def test_test_factory_accepts_test_verifier_and_reports_nonproduction(
    tmp_path: Path,
) -> None:
    from keeper.pass_b.pilot import PilotConversationExecutive

    application = PassBApplication.test_composition(
        tmp_path,
        executive=PilotConversationExecutive(tmp_path / "keeper.db"),
        launch_authority=TestLaunchAuthority(),
        usage_reset_verifier=TestUsageResetVerifier(),
    )
    authority = application.diagnostics()["authority"]
    assert authority["state"] == "TEST_COMPOSITION"
    assert authority["production_validation"] is False
    assert authority["composition"] == "TEST_COMPOSITION"
    assert authority["last_checked_at"]


def _reset_observation(
    service: OrchestrationService,
    pool: UsagePoolRecord,
    *,
    remaining: float | None = None,
) -> UsageResetObservation:
    verifier = service.usage_reset_verifier
    assert type(verifier) is TestUsageResetVerifier
    sessions = tuple(
        item
        for item in service.repository.list(ProviderSessionRecord)
        if item.provider_id == pool.provider_id
        and item.account_id == pool.account_id
    )
    return verifier.issue(
        pool,
        reset_at=pool.reset_at or "",
        observed_at=service.clock().isoformat(),
        remaining=remaining,
        model_ids=tuple(sorted({item.model_id for item in sessions})),
        session_ids=tuple(sorted(item.session_id for item in sessions)),
    )


def _production_observation(
    observation: UsageResetObservation, key: bytes
) -> UsageResetObservation:
    unsigned = replace(
        observation,
        source="PROVIDER_AUTHENTICATED:test-adapter",
        proof="pending",
    )
    proof = "hmac-sha256:" + hmac.new(
        key, unsigned.digest().encode("ascii"), hashlib.sha256
    ).hexdigest()
    return replace(unsigned, proof=proof)


def test_missing_trusted_reset_verifier_fails_closed(tmp_path: Path) -> None:
    _, service, clock, _, _, pool, _, _ = _stack(tmp_path)
    clock.advance(hours=2)
    observation = _reset_observation(service, pool)
    service.usage_reset_verifier = UnavailableUsageResetVerifier()
    with pytest.raises(PermissionError, match="unavailable"):
        service.observe_usage_reset(observation)


def test_forged_production_reset_rejects(tmp_path: Path) -> None:
    _, service, clock, _, _, pool, _, _ = _stack(tmp_path)
    clock.advance(hours=2)
    observation = _production_observation(
        _reset_observation(service, pool), b"k" * 32
    )
    forged = replace(observation, proof="hmac-sha256:" + "0" * 64)
    service.usage_reset_verifier = ProductionUsageResetVerifier(
        {(pool.provider_id, pool.account_id): b"k" * 32}
    )
    with pytest.raises(PermissionError, match="unauthenticated"):
        service.observe_usage_reset(forged)


def test_production_reset_replay_rejects(tmp_path: Path) -> None:
    _, service, clock, _, _, pool, _, _ = _stack(tmp_path)
    clock.advance(hours=2)
    key = b"k" * 32
    observation = _production_observation(
        _reset_observation(service, pool), key
    )
    service.usage_reset_verifier = ProductionUsageResetVerifier(
        {(pool.provider_id, pool.account_id): key}
    )
    service.observe_usage_reset(observation)
    with pytest.raises(PermissionError):
        service.observe_usage_reset(observation)


@pytest.mark.parametrize(
    "field",
    ("provider_id", "account_id", "pool_id", "model_ids", "session_ids"),
)
def test_reset_binding_mismatch_rejects(
    tmp_path: Path, field: str
) -> None:
    _, service, clock, _, _, pool, _, _ = _stack(tmp_path)
    clock.advance(hours=2)
    observation = _reset_observation(service, pool)
    value: Any = "wrong"
    if field in {"model_ids", "session_ids"}:
        value = ("wrong",)
    with pytest.raises((KeyError, PermissionError)):
        service.observe_usage_reset(replace(observation, **{field: value}))


def test_stale_reset_observation_rejects(tmp_path: Path) -> None:
    _, service, clock, _, _, pool, _, _ = _stack(tmp_path)
    clock.advance(hours=2)
    observation = _reset_observation(service, pool)
    stale = replace(
        observation,
        observed_at=pool.last_observed_at,
        expires_at=(datetime.fromisoformat(pool.last_observed_at) + timedelta(minutes=5)).isoformat(),
    )
    with pytest.raises(PermissionError, match="stale"):
        service.observe_usage_reset(stale)


def test_valid_production_reset_updates_exactly_once(tmp_path: Path) -> None:
    repository, service, clock, _, _, pool, _, _ = _stack(tmp_path)
    clock.advance(hours=2)
    key = b"k" * 32
    observation = _production_observation(
        _reset_observation(service, pool), key
    )
    service.usage_reset_verifier = ProductionUsageResetVerifier(
        {(pool.provider_id, pool.account_id): key}
    )
    updated = service.observe_usage_reset(observation)
    assert updated.observation_generation == pool.observation_generation + 1
    assert repository.get(UsagePoolRecord, pool.pool_id) == updated


@pytest.mark.parametrize(
    "action",
    (
        "PUSH",
        "FORCE_PUSH",
        "DELETE_BRANCH",
        "SERVICE_CHANGE",
        "DEPLOY",
        "SPENDING",
        "TOTALLY_UNKNOWN_ACTION",
    ),
)
def test_prohibited_or_unknown_delegated_action_cannot_be_granted(
    tmp_path: Path, action: str
) -> None:
    application, charter = _approved_application(tmp_path)
    with pytest.raises(PermissionError, match="outside"):
        activate_delegated_mode(
            application.repository,
            project_status=application.project_status,
            project_id=charter.project_id,
            charter=charter,
            founder_identity=str(charter.founder_approval_identity),
            founder_approval_id=str(charter.founder_approval_record_id),
            founder_approval_digest=str(
                charter.founder_authorization_capability_digest
            ),
            scope=(action,),
            expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        )


def _grant(
    tmp_path: Path, *, max_actions: int = 100
) -> tuple[PassBApplication, Any, DelegatedModeGrantRecord]:
    application, charter = _approved_application(tmp_path)
    grant = activate_delegated_mode(
        application.repository,
        project_status=application.project_status,
        project_id=charter.project_id,
        charter=charter,
        founder_identity=str(charter.founder_approval_identity),
        founder_approval_id=str(charter.founder_approval_record_id),
        founder_approval_digest=str(
            charter.founder_authorization_capability_digest
        ),
        scope=("RUN_TESTS", "SELECT_APPROVED_PROVIDER"),
        expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        max_actions=max_actions,
    )
    return application, charter, grant


def test_valid_allowlisted_delegated_action_succeeds(tmp_path: Path) -> None:
    application, charter, grant = _grant(tmp_path)
    used = validate_delegated_action(
        application.repository,
        grant.delegated_mode_grant_id,
        project_status=application.project_status,
        project_id=charter.project_id,
        charter_id=charter.charter_id,
        charter_revision=charter.revision,
        action="RUN_TESTS",
    )
    assert used.actions_used == 1


def _superseded_status(
    application: PassBApplication, project_id: str
) -> ProjectStatusReader:
    status = copy.deepcopy(application.project_status(project_id))
    status["project_summary"]["active_charter_revision"] += 1
    status["active_charter"]["revision"] += 1
    status["active_charter"]["founder_approval_record_id"] = "new-approval"
    status["active_charter"]["founder_authorization_capability_digest"] = (
        "b" * 64
    )
    def reader(requested: str) -> dict[str, Any]:
        if requested == project_id:
            return status
        return application.project_status(requested)

    return cast(ProjectStatusReader, reader)


def test_new_active_charter_supersedes_old_grant(tmp_path: Path) -> None:
    application, charter, grant = _grant(tmp_path)
    reader = _superseded_status(application, charter.project_id)
    with pytest.raises(PermissionError, match="superseded"):
        validate_delegated_action(
            application.repository,
            grant.delegated_mode_grant_id,
            project_status=reader,
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            action="RUN_TESTS",
        )
    persisted = application.repository.get(
        DelegatedModeGrantRecord, grant.delegated_mode_grant_id
    )
    assert persisted.state == DelegatedModeState.SUPERSEDED


def test_old_caller_ids_cannot_revive_superseded_grant(tmp_path: Path) -> None:
    application, charter, grant = _grant(tmp_path)
    reader = _superseded_status(application, charter.project_id)
    with pytest.raises(PermissionError):
        validate_delegated_action(
            application.repository,
            grant.delegated_mode_grant_id,
            project_status=reader,
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            action="RUN_TESTS",
        )
    with pytest.raises(PermissionError):
        validate_delegated_action(
            application.repository,
            grant.delegated_mode_grant_id,
            project_status=application.project_status,
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            action="RUN_TESTS",
        )


def test_superseded_grant_disappears_from_control_room(tmp_path: Path) -> None:
    application, charter, grant = _grant(tmp_path)
    application.control_room.project_status = _superseded_status(
        application, charter.project_id
    )
    snapshot = application.control_room.snapshot(charter.project_id).to_dict()
    assert grant.delegated_mode_grant_id not in {
        item["delegated_mode_grant_id"]
        for item in snapshot["safety"]["delegated_mode"]
    }
    assert application.repository.get(
        DelegatedModeGrantRecord, grant.delegated_mode_grant_id
    ).state == DelegatedModeState.SUPERSEDED


@pytest.mark.parametrize("terminal", ("expired", "revoked"))
def test_expired_and_revoked_grants_reject(
    tmp_path: Path, terminal: str
) -> None:
    application, charter, grant = _grant(tmp_path)
    if terminal == "revoked":
        revoke_delegated_mode(
            application.repository, grant.delegated_mode_grant_id
        )
        observed_at = None
    else:
        observed_at = (
            datetime.fromisoformat(grant.expires_at) + timedelta(seconds=1)
        ).isoformat()
    with pytest.raises(PermissionError):
        validate_delegated_action(
            application.repository,
            grant.delegated_mode_grant_id,
            project_status=application.project_status,
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            action="RUN_TESTS",
            observed_at=observed_at,
        )


def test_cross_project_delegated_use_rejects(tmp_path: Path) -> None:
    application, charter, grant = _grant(tmp_path)
    with pytest.raises(PermissionError):
        validate_delegated_action(
            application.repository,
            grant.delegated_mode_grant_id,
            project_status=application.project_status,
            project_id="other-project",
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            action="RUN_TESTS",
        )


def test_delegated_provider_outside_current_charter_rejects(
    tmp_path: Path,
) -> None:
    application, charter, grant = _grant(tmp_path)
    with pytest.raises(PermissionError, match="out of scope"):
        validate_delegated_action(
            application.repository,
            grant.delegated_mode_grant_id,
            project_status=application.project_status,
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            action="SELECT_APPROVED_PROVIDER",
            action_scope={"provider_id": "unapproved-provider"},
        )


def test_delegated_action_count_is_enforced(tmp_path: Path) -> None:
    application, charter, grant = _grant(tmp_path, max_actions=1)
    validate_delegated_action(
        application.repository,
        grant.delegated_mode_grant_id,
        project_status=application.project_status,
        project_id=charter.project_id,
        charter_id=charter.charter_id,
        charter_revision=charter.revision,
        action="RUN_TESTS",
    )
    with pytest.raises(PermissionError, match="out of scope"):
        validate_delegated_action(
            application.repository,
            grant.delegated_mode_grant_id,
            project_status=application.project_status,
            project_id=charter.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            action="RUN_TESTS",
        )


@pytest.mark.parametrize(
    "role", (AssignmentRole.IMPLEMENTER, AssignmentRole.REVIEWER)
)
@pytest.mark.parametrize("location", ("root", "inside", "parent"))
def test_every_assignment_role_rejects_pilot_evidence_tree(
    tmp_path: Path, role: str, location: str
) -> None:
    _, service, _, provider, account, _, sessions, adapter = _stack(tmp_path)
    assignment = _assignment(
        service, provider, account, sessions[0], role=role
    )
    parent, evidence_root, evidence_run = _protected_tree(tmp_path)
    candidates = {
        "root": evidence_root,
        "inside": evidence_run,
        "parent": parent,
    }
    with pytest.raises(PermissionError, match="pilot evidence"):
        service.reserve_workspace(
            assignment,
            candidates[location],
            lease_seconds=300,
            branch="test/protected",
            base_commit="abc",
        )
    assert adapter.health()["launched"] == 0


def test_reviewer_parent_revalidated_immediately_before_adapter(
    tmp_path: Path,
) -> None:
    _, service, _, provider, account, _, sessions, adapter = _stack(tmp_path)
    _, _, evidence_run = _protected_tree(tmp_path)
    source_artifact = evidence_run / "source.json"
    source_artifact.write_bytes(b'{"validated":true}\n')
    reviewer, source = _reviewer_with_validated_source(
        service, provider, account, sessions, tmp_path, "parent-race"
    )
    reference = service.create_local_evidence_reference(
        reviewer.assignment_id, source_artifact,
        source_evidence_bundle_id=source.evidence_bundle_id,
    )
    workspace = tmp_path / "reviewer-parent"
    workspace.mkdir()
    (workspace / ".git").write_text("gitdir: test", encoding="utf-8")
    _, authority_id = _launch_ready(
        service, reviewer, workspace, "reviewer-parent-race"
    )
    artifact = (
        workspace
        / ".ai-workflow"
        / "pilot-invocations"
        / "preserved"
        / "evidence.json"
    )
    snapshot: dict[str, int | bytes] = {}

    def expose_protected_evidence() -> None:
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b'{"preserved":true}\n')
        snapshot["bytes"] = artifact.read_bytes()
        snapshot["mtime_ns"] = artifact.stat().st_mtime_ns

    launched_before = adapter.health()["launched"]
    with pytest.raises(PermissionError, match="pilot evidence"):
        service.run_assignment(
            reviewer.assignment_id,
            workspace,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
            evidence_reference_ids=(reference.evidence_reference_id,),
            after_launch_claim=expose_protected_evidence,
        )
    assert adapter.health()["launched"] == launched_before
    assert artifact.read_bytes() == snapshot["bytes"]
    assert artifact.stat().st_mtime_ns == snapshot["mtime_ns"]


def test_reviewer_write_reservation_still_rejects(tmp_path: Path) -> None:
    _, service, _, provider, account, _, sessions, _ = _stack(tmp_path)
    reviewer = _assignment(
        service,
        provider,
        account,
        sessions[0],
        role=AssignmentRole.REVIEWER,
    )
    workspace, _ = _launch_ready(
        service, reviewer, tmp_path / "isolated-review", "review-write"
    )
    with pytest.raises(PermissionError, match="cannot reserve writes"):
        service.reserve_writes(
            reviewer, workspace, ("review-output",), lease_seconds=300
        )


def test_explicit_reference_is_not_a_launch_workspace(tmp_path: Path) -> None:
    _, _, evidence_run = _protected_tree(tmp_path)
    artifact = evidence_run / "evidence.json"
    artifact.write_bytes(b'{"evidence":true}\n')
    reference = canonical_evidence_reference_path(artifact)
    assert reference.endswith("/evidence.json")
    with pytest.raises((PermissionError, ValueError)):
        canonical_workspace_path(Path(reference))


def test_isolated_reviewer_consumes_explicit_reference(tmp_path: Path) -> None:
    _, service, _, provider, account, _, sessions, adapter = _stack(tmp_path)
    _, _, evidence_run = _protected_tree(tmp_path)
    artifact = evidence_run / "evidence.json"
    artifact.write_bytes(b'{"evidence":true}\n')
    before = (artifact.read_bytes(), artifact.stat().st_mtime_ns)
    reviewer, source = _reviewer_with_validated_source(
        service, provider, account, sessions, tmp_path, "explicit-reference"
    )
    reference = service.create_local_evidence_reference(
        reviewer.assignment_id,
        artifact,
        source_evidence_bundle_id=source.evidence_bundle_id,
    )
    assert reference.canonical_source_path is not None
    workspace = tmp_path / "isolated-reviewer"
    _, authority_id = _launch_ready(
        service, reviewer, workspace, "isolated-reviewer"
    )
    result = service.run_assignment(
        reviewer.assignment_id,
        workspace,
        authority_attempt_id=authority_id,
        global_context={},
        task_context={},
        evidence_reference_ids=(reference.evidence_reference_id,),
    )
    assert result.assignment_id == reviewer.assignment_id
    assert adapter.health()["launched"] == 2
    assert (artifact.read_bytes(), artifact.stat().st_mtime_ns) == before


def test_changed_typed_reference_rejects_before_adapter(tmp_path: Path) -> None:
    _, service, _, provider, account, _, sessions, adapter = _stack(tmp_path)
    _, _, evidence_run = _protected_tree(tmp_path)
    artifact = evidence_run / "evidence.json"
    artifact.write_bytes(b'{"evidence":true}\n')
    reviewer, source = _reviewer_with_validated_source(
        service, provider, account, sessions, tmp_path, "changed-reference"
    )
    reference = service.create_local_evidence_reference(
        reviewer.assignment_id,
        artifact,
        source_evidence_bundle_id=source.evidence_bundle_id,
    )
    workspace = tmp_path / "changed-reference-reviewer"
    _, authority_id = _launch_ready(
        service, reviewer, workspace, "changed-reference-reviewer"
    )
    artifact.write_bytes(b'{"evidence":"changed"}\n')
    with pytest.raises(PermissionError, match="content changed"):
        service.run_assignment(
            reviewer.assignment_id,
            workspace,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
            evidence_reference_ids=(reference.evidence_reference_id,),
        )
    rejected = service.repository.get(
        type(reference), reference.evidence_reference_id
    )
    assert rejected.state == "REJECTED"
    assert adapter.health()["launched"] == 1


def test_raw_reference_dictionary_rejects_before_adapter(tmp_path: Path) -> None:
    _, service, _, provider, account, _, sessions, adapter = _stack(tmp_path)
    reviewer = _assignment(
        service,
        provider,
        account,
        sessions[0],
        role=AssignmentRole.REVIEWER,
    )
    workspace = tmp_path / "raw-reference-reviewer"
    _, authority_id = _launch_ready(
        service, reviewer, workspace, "raw-reference-reviewer"
    )
    with pytest.raises(PermissionError, match="durable IDs"):
        service.run_assignment(
            reviewer.assignment_id,
            workspace,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={"evidence_reference": {"path": "untrusted"}},
        )
    assert adapter.health()["launched"] == 0


def test_remote_structured_reference_is_typed_and_bound(tmp_path: Path) -> None:
    _, service, _, provider, account, _, sessions, _ = _stack(tmp_path)
    reviewer, source = _reviewer_with_validated_source(
        service, provider, account, sessions, tmp_path, "remote-reference"
    )
    reference = service.create_remote_evidence_reference(
        reviewer.assignment_id,
        source_identity="provider-object:review-input-1",
        sha256=hashlib.sha256(b"remote evidence").hexdigest(),
        size_bytes=len(b"remote evidence"),
        source_evidence_bundle_id=source.evidence_bundle_id,
    )
    validated = service.validate_evidence_reference(
        reference.evidence_reference_id,
        reviewer.assignment_id,
    )
    assert validated.source_kind == "REMOTE_STRUCTURED_EVIDENCE"
    assert validated.canonical_source_path is None


@pytest.mark.parametrize("fragment", ("pilot-invocations", "pw"))
def test_protected_workflow_parents_and_descendants_reject(
    tmp_path: Path, fragment: str
) -> None:
    parent = tmp_path / f"parent-{fragment}"
    protected = parent / ".ai-workflow" / fragment
    descendant = protected / "nested"
    descendant.mkdir(parents=True)
    for candidate in (parent, protected, descendant):
        with pytest.raises(PermissionError):
            canonical_workspace_path(candidate)


def test_dangling_alias_fails_conservatively(tmp_path: Path) -> None:
    alias = tmp_path / "dangling-workspace"
    try:
        os.symlink(tmp_path / "missing-target", alias, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink is unavailable: {error}")
    with pytest.raises(PermissionError, match="cannot be safely resolved"):
        canonical_workspace_path(alias)


def test_cleanup_rejects_tree_that_gains_pilot_evidence(tmp_path: Path) -> None:
    _, service, _, provider, account, _, sessions, _ = _stack(tmp_path)
    assignment = _assignment(service, provider, account, sessions[0])
    target = tmp_path / "cleanup-target"
    workspace, _ = _launch_ready(
        service, assignment, target, "cleanup-protected"
    )
    artifact = (
        target
        / ".ai-workflow"
        / "pilot-invocations"
        / "preserved"
        / "evidence.json"
    )
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"preserve me\n")
    before = (artifact.read_bytes(), artifact.stat().st_mtime_ns)
    calls: list[object] = []

    def runner(*args: object, **kwargs: object) -> Any:
        calls.append((args, kwargs))
        raise AssertionError("cleanup runner must not be invoked")

    cleanup = GitWorktreeService(WorkspacePolicy(tmp_path, ()), runner=runner)
    with pytest.raises(PermissionError, match="protected scope"):
        cleanup.cleanup_worktree(
            tmp_path,
            workspace,
            replace(assignment, state=AssignmentState.COMPLETED),
            (cast(Any, object()),),
            explicitly_approved=True,
        )
    assert calls == []
    assert (artifact.read_bytes(), artifact.stat().st_mtime_ns) == before


def test_fake_original_repository_and_parent_reject(tmp_path: Path) -> None:
    parent = tmp_path / "repository-parent"
    repository = parent / "original"
    (repository / ".git").mkdir(parents=True)
    for candidate in (repository, parent):
        with pytest.raises(PermissionError, match="repository"):
            canonical_workspace_path(candidate)


def test_normal_writer_and_reviewer_workspaces_remain_usable(
    tmp_path: Path,
) -> None:
    for index, role in enumerate(
        (AssignmentRole.IMPLEMENTER, AssignmentRole.REVIEWER)
    ):
        _, service, _, provider, account, _, sessions, adapter = _stack(
            tmp_path / str(index)
        )
        reference_ids: tuple[str, ...] = ()
        if role == AssignmentRole.REVIEWER:
            root = tmp_path / str(index)
            _, _, evidence_run = _protected_tree(root)
            artifact = evidence_run / "normal-source.json"
            artifact.write_bytes(b'{"validated":true}\n')
            assignment, source = _reviewer_with_validated_source(
                service, provider, account, sessions, root, "normal-reviewer"
            )
            reference = service.create_local_evidence_reference(
                assignment.assignment_id,
                artifact,
                source_evidence_bundle_id=source.evidence_bundle_id,
            )
            reference_ids = (reference.evidence_reference_id,)
        else:
            assignment = _assignment(
                service, provider, account, sessions[0], role=role
            )
        launched_before = adapter.health()["launched"]
        workspace = tmp_path / str(index) / "isolated"
        _, authority_id = _launch_ready(
            service, assignment, workspace, f"normal-{index}"
        )
        result = service.run_assignment(
            assignment.assignment_id,
            workspace,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={},
            evidence_reference_ids=reference_ids,
        )
        assert result.assignment_id == assignment.assignment_id
        assert adapter.health()["launched"] == launched_before + 1
