from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from keeper.pass_b.enums import (
    AssignmentRole,
    CostMode,
    EvidenceState,
    HealthState,
)
from keeper.pass_b.models import (
    AssignmentRecord,
    EvidenceBundleRecord,
    ProviderAccountRecord,
    ProviderRecord,
    ProviderSessionRecord,
    WorkspaceReservationRecord,
)
from keeper.pass_b.providers import (
    AdapterAssignment,
    AdapterResult,
    GenericRemoteAdapter,
    LocalMockAdapter,
    ProviderSelectionPolicy,
    select_provider_session,
)
from keeper.pass_b.workspaces import GitWorktreeService, WorkspacePolicy
from tests.keeper.pass_b.test_orchestration import (
    _assignment,
    _authorize,
    _stack,
)


def test_generic_remote_adapter_translates_structured_data_only() -> None:
    requests: list[dict[str, Any]] = []

    def transport(value: dict[str, Any]) -> dict[str, Any]:
        requests.append(value)
        return {
            "external_execution_id": "remote-1",
            "summary": "structured result",
            "artifacts": [
                {
                    "kind": "structured-report",
                    "path": None,
                    "digest": "a" * 64,
                    "execution_requested": False,
                }
            ],
            "usage": 2,
            "session_resume_token": "b" * 64,
        }

    adapter = GenericRemoteAdapter(
        transport,
        provider_id="remote-provider",
        model_id="remote-model",
    )
    assignment = AdapterAssignment(
        assignment_id="assignment-1",
        attempt_id="attempt-1",
        project_id="project-1",
        charter_id="charter-1",
        charter_revision=1,
        role=AssignmentRole.RESEARCHER,
        model_id="remote-model",
        workspace=Path("C:/tmp/remote"),
        read_only=False,
        global_context={"scope": "approved"},
        task_context={"question": "bounded"},
        expected_evidence=("structured-report",),
        authority_attempt_id="authority-1",
    )
    result = adapter.launch(assignment)
    assert result.external_execution_id == "remote-1"
    assert requests[0]["authority_attempt_id"] == "authority-1"
    assert "authority_decision" not in requests[0]
    assert result.artifacts[0]["execution_requested"] is False

@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ({"external_execution_id": None}, "execution identity"),
        ({"external_execution_id": " "}, "execution identity"),
        ({"summary": 3}, "summary"),
        ({"summary": ""}, "summary"),
        ({"usage": True}, "usage"),
        ({"usage": -1}, "usage"),
        ({"usage": float("inf")}, "usage"),
        ({"session_resume_token": 7}, "resume token"),
        ({"session_resume_token": ""}, "resume token"),
    ],
)
def test_remote_adapter_rejects_malformed_scalar_results(
    replacement: dict[str, object], message: str
) -> None:
    result: dict[str, object] = {
        "external_execution_id": "remote-1",
        "summary": "done",
        "artifacts": [],
        "usage": 1,
        "session_resume_token": None,
    }
    result.update(replacement)

    with pytest.raises(ValueError, match=message):
        GenericRemoteAdapter._convert(result)


def test_provider_substitution_respects_paid_privacy_and_charter() -> None:
    provider = ProviderRecord(
        provider_id="provider",
        identity="provider",
        display_name="Provider",
        classification="REMOTE",
        adapter_kind="generic",
        capabilities=("researcher", "structured-evidence"),
        session_model="RESUMABLE",
        usage_pool_strategy="shared",
        concurrency_limit=1,
        cost_mode=CostMode.PAID,
        authentication_ready=True,
        tool_support=(),
        workspace_support=("read-only",),
        cancellation_support=True,
        resume_support=True,
        evidence_format="keeper-evidence-v1",
        health=HealthState.READY,
        created_at="2026-07-28T12:00:00+00:00",
        updated_at="2026-07-28T12:00:00+00:00",
        revision=1,
    )
    account = ProviderAccountRecord(
        account_id="account",
        provider_id="provider",
        identity="provider:account",
        display_name="Account",
        usage_pool_id="pool",
        cost_mode=CostMode.PAID,
        privacy_classification="PRIVATE_REMOTE",
        authentication_ready=True,
        enabled=True,
        created_at="2026-07-28T12:00:00+00:00",
        updated_at="2026-07-28T12:00:00+00:00",
        revision=1,
    )
    session = ProviderSessionRecord(
        session_id="session",
        provider_id="provider",
        account_id="account",
        model_id="model",
        external_session_id=None,
        state="READY",
        concurrency_limit=1,
        active_assignments=0,
        supports_resume=True,
        resume_token_digest=None,
        last_seen_at="2026-07-28T12:00:00+00:00",
        created_at="2026-07-28T12:00:00+00:00",
        updated_at="2026-07-28T12:00:00+00:00",
        revision=1,
    )
    with pytest.raises(PermissionError, match="not charter-approved"):
        select_provider_session(
            AssignmentRole.RESEARCHER,
            [provider],
            [account],
            [session],
            ProviderSelectionPolicy(
                frozenset({"provider"}),
                frozenset({"researcher"}),
                False,
                False,
                "PRIVATE_REMOTE",
            ),
        )
    with pytest.raises(RuntimeError, match="no already-approved"):
        select_provider_session(
            AssignmentRole.RESEARCHER,
            [provider],
            [account],
            [session],
            ProviderSelectionPolicy(
                frozenset({"provider"}),
                frozenset({"researcher"}),
                True,
                False,
                "PRIVATE_REMOTE",
            ),
        )
    selected = select_provider_session(
        AssignmentRole.RESEARCHER,
        [provider],
        [account],
        [session],
        ProviderSelectionPolicy(
            frozenset({"provider"}),
            frozenset({"researcher"}),
            True,
            True,
            "PRIVATE_REMOTE",
        ),
    )
    assert selected.session_id == "session"
    with pytest.raises(RuntimeError, match="no already-approved"):
        select_provider_session(
            AssignmentRole.RESEARCHER,
            [provider],
            [account],
            [session],
            ProviderSelectionPolicy(
                frozenset({"provider"}),
                frozenset({"researcher"}),
                True,
                True,
                "PRIVATE_REMOTE",
                frozenset({"session:session"}),
            ),
        )


class GeneratedCodeEvidenceAdapter(LocalMockAdapter):
    def launch(self, assignment: AdapterAssignment) -> AdapterResult:
        result = super().launch(assignment)
        return AdapterResult(
            result.external_execution_id,
            result.summary,
            (
                {
                    "kind": "structured-report",
                    "path": None,
                    "digest": "a" * 64,
                    "execution_requested": False,
                    "import_module": "provider_generated",
                },
            ),
            1,
        )


def test_provider_generated_code_loading_request_is_rejected(
    tmp_path: Path,
) -> None:
    (
        repository,
        service,
        _,
        provider,
        account,
        _,
        sessions,
        _,
    ) = _stack(tmp_path)
    service.adapters[provider.provider_id] = GeneratedCodeEvidenceAdapter(
        provider.provider_id
    )
    assignment = _assignment(service, provider, account, sessions[0])
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()
    workspace = service.reserve_workspace(
        assignment,
        workspace_path,
        lease_seconds=300,
        branch="test/evidence",
        base_commit="abc",
    )
    service.reserve_writes(
        assignment, workspace, ("keeper",), lease_seconds=300
    )
    service.reserve_usage(assignment, workspace, 1)
    authority_id = _authorize(
        service, assignment, workspace, "authority-1"
    )
    evidence = service.run_assignment(
        assignment.assignment_id,
        workspace_path,
        authority_attempt_id=authority_id,
        global_context={},
        task_context={},
    )
    validated = service.validate_evidence(
        evidence.evidence_bundle_id, workspace_path
    )
    assert validated.state == EvidenceState.REJECTED
    assert "code loading" in validated.validation_errors[0]


def test_provider_cannot_approve_its_own_evidence(tmp_path: Path) -> None:
    (
        repository,
        service,
        _,
        provider,
        account,
        _,
        sessions,
        _,
    ) = _stack(tmp_path)
    producer = _assignment(service, provider, account, sessions[0])
    reviewer = _assignment(
        service,
        provider,
        account,
        sessions[0],
        role=AssignmentRole.REVIEWER,
    )
    evidence = EvidenceBundleRecord(
        evidence_bundle_id="evidence",
        project_id=producer.project_id,
        assignment_id=producer.assignment_id,
        attempt_id="attempt",
        producer_provider_id=producer.provider_id,
        producer_session_id=producer.session_id,
        schema_version=1,
        artifacts=(
            {
                "kind": "structured-report",
                "path": None,
                "digest": "a" * 64,
                "execution_requested": False,
            },
        ),
        summary="evidence",
        content_digest="b" * 64,
        state=EvidenceState.VALIDATED,
        validation_errors=(),
        created_at="2026-07-28T12:00:00+00:00",
        updated_at="2026-07-28T12:00:00+00:00",
        revision=1,
    )
    repository.insert(evidence)
    with pytest.raises(PermissionError, match="independence"):
        service.create_review(
            evidence.evidence_bundle_id,
            reviewer.assignment_id,
            evidence.evidence_bundle_id,
        )


def test_workspace_policy_blocks_protected_roots_and_implicit_cleanup(
    tmp_path: Path,
) -> None:
    implementation_root = tmp_path / "worktrees"
    implementation_root.mkdir()
    protected = implementation_root / "protected"
    protected.mkdir()
    policy = WorkspacePolicy(
        implementation_root=implementation_root,
        prohibited_roots=(protected,),
    )
    with pytest.raises(PermissionError):
        policy.validate_target(protected / "child")
    with pytest.raises(PermissionError):
        policy.validate_target(
            implementation_root / ".ai-workflow" / "pw" / "task"
        )


def test_worktree_creation_and_cleanup_are_explicitly_bounded(
    tmp_path: Path,
) -> None:
    calls: list[list[str]] = []

    def runner(
        command: list[str],
        *,
        capture_output: bool,
        text: bool,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "status" in command:
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    root = tmp_path / "worktrees"
    root.mkdir()
    repository_path = tmp_path / "repository"
    repository_path.mkdir()
    service = GitWorktreeService(
        WorkspacePolicy(root, (repository_path,)), runner=runner
    )
    assignment = AssignmentRecord(
        assignment_id="assignment",
        project_id="project",
        charter_id="charter",
        charter_revision=1,
        workflow_id="workflow",
        work_item_id="work",
        provider_id="provider",
        account_id="account",
        session_id="session",
        role=AssignmentRole.IMPLEMENTER,
        model_id="model",
        workspace_id="workspace",
        authority_envelope_digest="a" * 64,
        expected_evidence=("structured-report",),
        usage_policy={},
        state="COMPLETED",
        read_only=False,
        independence_key="key",
        created_at="2026-07-28T12:00:00+00:00",
        updated_at="2026-07-28T12:00:00+00:00",
        revision=1,
    )
    target = root / "task"
    created = service.create_implementation_worktree(
        repository_path,
        target,
        "test/task",
        "abc",
        assignment,
    )
    assert created == target.resolve()
    reservation = WorkspaceReservationRecord(
        workspace_reservation_id="reservation",
        project_id="project",
        assignment_id="assignment",
        workspace_id="workspace",
        canonical_path=str(target),
        mode="WRITE",
        owner_token="owner",
        lease_expires_at="2026-07-28T13:00:00+00:00",
        state="RELEASED",
        worktree_branch="test/task",
        base_commit="abc",
        created_at="2026-07-28T12:00:00+00:00",
        updated_at="2026-07-28T12:00:00+00:00",
        revision=1,
    )
    evidence = EvidenceBundleRecord(
        evidence_bundle_id="evidence",
        project_id="project",
        assignment_id="assignment",
        attempt_id="attempt",
        producer_provider_id="provider",
        producer_session_id="session",
        schema_version=1,
        artifacts=(),
        summary="preserved",
        content_digest="a" * 64,
        state="VALIDATED",
        validation_errors=(),
        created_at="2026-07-28T12:00:00+00:00",
        updated_at="2026-07-28T12:00:00+00:00",
        revision=1,
    )
    with pytest.raises(PermissionError, match="explicit approval"):
        service.cleanup_worktree(
            repository_path,
            reservation,
            assignment,
            (evidence,),
            explicitly_approved=False,
        )
    target.mkdir()
    service.cleanup_worktree(
        repository_path,
        reservation,
        assignment,
        (evidence,),
        explicitly_approved=True,
    )
    assert any("worktree" in command and "remove" in command for command in calls)
