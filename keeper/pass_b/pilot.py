from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, cast

from keeper.app.storage import KeeperStore
from keeper.authority_service.client import TestAuthorityServiceClient
from keeper.authority_service.core import (
    AuthorityServiceCore,
    CompletionObservation,
    ExecutionObservation,
    ProcessObservation,
    QualificationObservation,
    TrustedObserver,
)
from keeper.evidence_input import (
    review_input_declaration,
    structured_digest,
)
from keeper.executive.charters import CharterService
from keeper.executive.enums import ApprovalKind, FounderApprovalIntent
from keeper.executive.founder_auth import (
    TestApprovalConfirmation,
    TestFounderAuthenticator,
)
from keeper.executive.founder_capability import (
    FounderAuthorizationCapability,
    FounderCapabilityClaims,
    TestFounderCapabilityIssuer,
    TestFounderCapabilityVerifier,
)
from keeper.executive.intake import ConversationIntake, IntakeResult
from keeper.executive.models import (
    ApprovalRecord,
    FounderApprovalChallenge,
    FounderApprovalEvent,
    MemoryRecord,
    ProposedAction,
    ProjectCharter,
    ProjectRecord,
    utc_now,
)
from keeper.executive.repository import TestExecutiveRepository, new_id
from keeper.pass_b.application import PassBApplication
from keeper.pass_b.launch_authority import ExecutiveAuthorityLaunchGate
from keeper.pass_b.conversation import (
    DynamicWorkflowDesigner,
    ProjectStatusReader,
    activate_delegated_mode,
    validate_delegated_action,
)
from keeper.pass_b.enums import (
    AssignmentRole,
    AssignmentState,
    CostMode,
    HealthState,
    ProviderClassification,
    ProviderSessionState,
    ReviewState,
    SessionModel,
)
from keeper.pass_b.models import (
    AssignmentRecord,
    AttemptRecord,
    DeliveredInputRecord,
    ProviderAccountRecord,
    ProviderRecord,
    ProviderSessionRecord,
    ReviewRecord,
    ResumeCheckpointRecord,
    UsagePoolRecord,
)
from keeper.pass_b.orchestration import authority_envelope_digest
from keeper.pass_b.providers import LocalMockAdapter
from keeper.pass_b.repository import (
    canonical_evidence_reference_path,
    canonical_workspace_path,
)
from keeper.pass_b.usage_authority import TestUsageResetVerifier
from keeper.providers.adapters import create_provider_registration


class PilotConversationExecutive:
    """Test-bound Executive facade for the isolated product pilot."""

    def __init__(self, database: Path) -> None:
        store = KeeperStore(database)
        store.migrate()
        self.authenticator = TestFounderAuthenticator()
        self.repository = TestExecutiveRepository(store, self.authenticator)
        self.charters = CharterService.for_test(
            self.repository, self.authenticator
        )
        self.intake = ConversationIntake()

    def begin(self, message: str) -> tuple[ProjectRecord, IntakeResult]:
        result = self.intake.extract(message)
        result = ConversationIntake.revise(
            result,
            replacements={
                "success_criteria": (
                    "implementation evidence is independently reviewed",
                    "usage reset resumes without duplicate launch",
                    "presentation state remains non-authoritative",
                ),
                "target_audience": "Founder",
                "approved_providers": (
                    "pilot-builder",
                    "pilot-reviewer",
                ),
                "approved_tools": ("filesystem", "tests"),
                "delegation_mode": "DELEGATED",
                "review_requirements": ("independent specialist",),
                "evidence_requirements": ("structured-report",),
            },
        )
        project = self.charters.create_project(result)
        interaction_id = new_id("pilot-interaction")
        self.repository.save_conversation(
            interaction_id,
            {
                "interaction_id": interaction_id,
                "project_id": project.project_id,
                "speaker": "Founder",
                "message": message,
                "created_at": utc_now(),
            },
        )
        return project, result

    def draft(
        self,
        project_id: str,
        intake: IntakeResult,
        *,
        founder_revisions: dict[str, Any] | None = None,
    ) -> ProjectCharter:
        revised = (
            ConversationIntake.revise(
                intake, replacements=founder_revisions
            )
            if founder_revisions
            else intake
        )
        return self.charters.draft(
            self.repository.project(project_id), revised
        )

    def propose_charter(self, charter: ProjectCharter) -> ProjectCharter:
        return self.charters.propose(charter)

    def request_charter_approval(
        self, charter: ProjectCharter
    ) -> FounderApprovalChallenge:
        return self.charters.request_approval(charter)

    def request_action_approval(
        self,
        action: ProposedAction,
        *,
        charter_id: str,
        scope: tuple[str, ...],
        limits: dict[str, Any],
    ) -> FounderApprovalChallenge:
        return self.charters.request_action_approval(
            action,
            charter_id=charter_id,
            kind=ApprovalKind.ONE_TIME,
            scope=scope,
            limits=limits,
        )

    def authenticate_founder(
        self, challenge: FounderApprovalChallenge
    ) -> TestApprovalConfirmation:
        confirmation = self.charters.authenticate(challenge)
        if type(confirmation) is not TestApprovalConfirmation:
            raise RuntimeError("pilot Founder confirmation type is invalid")
        return confirmation

    def confirm_action_approval(
        self,
        challenge_id: str,
        confirmation: TestApprovalConfirmation,
    ) -> tuple[ApprovalRecord, FounderApprovalEvent]:
        return self.charters.confirm_action_approval(
            challenge_id,
            confirmation=confirmation,
            intent=FounderApprovalIntent.APPROVE_ACTION,
        )

    def reserve_action_authority(
        self,
        action: ProposedAction,
        *,
        approval_id: str,
        task_id: str | None = None,
    ) -> tuple[ApprovalRecord, str | None]:
        return self.repository.reserve_action_authority(
            action,
            approval_id=approval_id,
            task_id=task_id,
        )

    def approve_and_activate(
        self, challenge: FounderApprovalChallenge
    ) -> tuple[ProjectRecord, ProjectCharter]:
        confirmation = self.charters.authenticate(challenge)
        approved, _, _ = self.charters.confirm_approval(
            challenge.challenge_id,
            intent=FounderApprovalIntent.APPROVE_CHARTER,
            confirmation=confirmation,
        )
        project = self.charters.activate(approved)
        return project, self.repository.charter(approved.charter_id)

    def project_status(self, project_id: str) -> dict[str, Any]:
        project = self.repository.project(project_id)
        charter = (
            self.repository.charter(project.active_charter_id)
            if project.active_charter_id is not None
            else None
        )
        return {
            "project_summary": project.to_dict(),
            "active_charter": (
                charter.to_dict() if charter is not None else None
            ),
            "task_status": tuple(
                task.to_dict() for task in self.repository.tasks(project_id)
            ),
        }


class _PilotAuthorityObserver:
    """Non-executing observer for real Authority test-composition records."""

    def __init__(self) -> None:
        self.reviewer_commit_receipt: dict[str, Any] | None = None
        self.reviewer_commit_receipt_digest: str | None = None

    def register_provider(
        self,
        provider_id: str,
        executable: Path,
        client_sid: str,
        *,
        executive_capabilities: list[str],
        project_types: list[str],
        effort_levels: list[str],
        pricing_authority: dict[str, Any],
    ) -> dict[str, Any]:
        return create_provider_registration(
            provider_id,
            executable,
            authorized_by=client_sid,
            executive_capabilities=executive_capabilities,
            project_types=project_types,
            effort_levels=effort_levels,
            pricing_authority=pricing_authority,
        )

    def qualify(
        self, registration: dict[str, Any], challenge: str
    ) -> QualificationObservation:
        now = _now()
        provider_id = str(registration["logical_provider_id"])
        return QualificationObservation(
            provider_instance_id=f"pilot-qualified:{provider_id}",
            process_ownership={
                "restricted": True,
                "job_confined": True,
                "executable": registration["canonical_executable_path"],
                "launch_nonce": challenge,
            },
            started_at=now,
            finished_at=now,
            exit_status=0,
            raw_version_output=f"{provider_id} 1.0.0",
        )

    def observe_process(
        self, attempt: dict[str, Any], pid: int
    ) -> ProcessObservation:
        del attempt, pid
        raise RuntimeError("pilot Authority never launches provider code")

    def execute_provider(
        self,
        registration: dict[str, Any],
        attempt: dict[str, Any],
        on_started: Callable[[ProcessObservation], None],
    ) -> ExecutionObservation:
        now = _now()
        executable = Path(str(registration["launcher_path"])).resolve()
        process_id = 4100 + int(
            hashlib.sha256(
                str(attempt["id"]).encode("utf-8")
            ).hexdigest()[:3],
            16,
        )
        on_started(
            ProcessObservation(
                pid=process_id,
                creation_time=now,
                executable=str(executable),
                executable_sha256=hashlib.sha256(
                    executable.read_bytes()
                ).hexdigest(),
                restricted=True,
                integrity_level="low",
                job_confined=True,
            )
        )
        stdout_path = Path(str(attempt["stdout_path"]))
        stderr_path = Path(str(attempt["stderr_path"]))
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        if str(attempt["role"]).casefold() == "reviewer":
            receipt = attempt.get("executive_commit_receipt")
            receipt_digest = attempt.get(
                "executive_commit_receipt_digest"
            )
            if not isinstance(receipt, dict) or not isinstance(
                receipt_digest, str
            ):
                raise PermissionError(
                    "pilot reviewer lacks an Executive commit receipt"
                )
            self.reviewer_commit_receipt = dict(receipt)
            self.reviewer_commit_receipt_digest = receipt_digest
            output: dict[str, Any] = {
                "review_disposition": "ACCEPTED",
                "findings": [],
                "review_input_declaration": review_input_declaration(
                    attempt["provider_input"],
                    provider_input_digest=str(
                        attempt["provider_input_digest"]
                    ),
                    review_disposition="ACCEPTED",
                ),
            }
        else:
            output = {"status": "completed", "files_changed": []}
        stdout_path.write_text(
            json.dumps(output, sort_keys=True), encoding="utf-8"
        )
        stderr_path.write_text("", encoding="utf-8")
        evidence_digest = hashlib.sha256(
            json.dumps(
                {
                    "stdout_sha256": hashlib.sha256(
                        stdout_path.read_bytes()
                    ).hexdigest(),
                    "stderr_sha256": hashlib.sha256(
                        stderr_path.read_bytes()
                    ).hexdigest(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return ExecutionObservation(
            process_id=process_id,
            exit_status=0,
            timed_out=False,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            provider_evidence_digest=evidence_digest,
            finished_at=_now(),
        )

    def observe_completion(
        self, attempt: dict[str, Any]
    ) -> CompletionObservation:
        del attempt
        raise RuntimeError("pilot Authority never finalizes provider code")


def run_darksage_pilot(
    data_directory: Path, evidence_path: Path
) -> dict[str, Any]:
    data_directory = data_directory.resolve()
    data_directory.mkdir(parents=True, exist_ok=True)
    workspace = data_directory / "approved-workspace-root"
    workspace.mkdir(parents=True, exist_ok=True)
    builder_workspace_path = workspace / "isolated-builder-workspace"
    builder_workspace_path.mkdir(parents=True, exist_ok=True)
    reviewer_workspace_path = workspace / "isolated-reviewer-workspace"
    reviewer_workspace_path.mkdir(parents=True, exist_ok=True)
    executive = PilotConversationExecutive(data_directory / "keeper.db")
    pilot_authority_observer = _PilotAuthorityObserver()
    authority_core = AuthorityServiceCore(
        data_directory / "test-authority-service",
        observer=cast(TrustedObserver, pilot_authority_observer),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    authority_client = TestAuthorityServiceClient(
        lambda request: authority_core.dispatch(
            request, "S-1-5-21-KEEPER-PILOT"
        )
    )
    launch_gate = ExecutiveAuthorityLaunchGate.test(
        authority_client,
        executive.project_status,
        receipt_issuer=(
            executive.repository.issue_pass_b_delivered_input_receipt
        ),
    )
    usage_reset_verifier = TestUsageResetVerifier()
    application = PassBApplication.test_composition(
        data_directory,
        executive=executive,
        launch_authority=launch_gate,
        usage_reset_verifier=usage_reset_verifier,
        recovery_action_authority=executive,
    )
    production_rejected_test_reset_verifier = False
    try:
        PassBApplication(
            data_directory / "production-reset-boundary-check",
            executive=executive,
            usage_reset_verifier=usage_reset_verifier,
        )
    except TypeError:
        production_rejected_test_reset_verifier = True
    pilot_evidence_root = (
        data_directory
        / ".ai-workflow"
        / "pilot-invocations"
        / f"pass-b-{uuid.uuid4().hex}"
    )
    pilot_evidence_root.mkdir(parents=True, exist_ok=False)
    pilot_evidence_artifact = pilot_evidence_root / "reference.json"
    pilot_evidence_artifact.write_bytes(b'{"pilot":"preserved"}\n')
    pilot_evidence_reference = canonical_evidence_reference_path(
        pilot_evidence_artifact
    )
    pilot_evidence_digest = hashlib.sha256(
        pilot_evidence_artifact.read_bytes()
    ).hexdigest()
    pilot_evidence_snapshot = (
        pilot_evidence_artifact.read_bytes(),
        pilot_evidence_artifact.stat().st_mtime_ns,
    )
    pilot_evidence_read_only_reference = bool(pilot_evidence_reference)
    pilot_evidence_writer_rejected = False
    try:
        canonical_workspace_path(pilot_evidence_root)
    except PermissionError:
        pilot_evidence_writer_rejected = True
    outcome = application.begin_conversation(
        f"Continue the DarkSage software project in {workspace}. No spending, no deployment, "
        "no live trading, and do not push."
    )
    challenge = application.conversation.request_approval(
        outcome.project.project_id
    )
    project, charter = executive.approve_and_activate(challenge)
    application.conversation.record_approval(charter)
    blueprint = DynamicWorkflowDesigner().design(charter)
    capability = _pilot_launch_capability(charter)
    launch_authorization = cast(
        dict[str, Any],
        authority_client.authorize_project_launch(
            founder_capability=capability
        )["authorization"],
    )

    builder, builder_session, builder_pool = _register_provider(
        application,
        authority_client,
        data_directory,
        provider_id="pilot-builder",
        authority_provider_id=bytes.fromhex("636f646578").decode("ascii"),
        account_id="builder-account",
        session_id="builder-session",
        capacity=2,
    )
    reviewer, reviewer_session, _ = _register_provider(
        application,
        authority_client,
        data_directory,
        provider_id="pilot-reviewer",
        authority_provider_id=bytes.fromhex("636c61756465").decode("ascii"),
        account_id="reviewer-account",
        session_id="reviewer-session",
        capacity=2,
    )
    durable_workflow = application.orchestration.create_workflow(
        project_id=project.project_id,
        charter_id=charter.charter_id,
        charter_revision=charter.revision,
        strategy=blueprint.strategy,
        authority_envelope_digest=authority_envelope_digest(
            charter.authority_envelope.to_dict()
        ),
    )
    implementation_item = application.orchestration.create_work_item(
        project_id=project.project_id,
        charter_id=charter.charter_id,
        charter_revision=charter.revision,
        workflow_id=durable_workflow.workflow_id,
        title="Implement bounded DarkSage continuation",
        objective="Create isolated implementation evidence",
        required_roles=(AssignmentRole.IMPLEMENTER,),
    )
    implementation = application.orchestration.create_assignment(
        work_item=implementation_item,
        provider_id=builder.provider_id,
        account_id="builder-account",
        session_id=builder_session.session_id,
        role=AssignmentRole.IMPLEMENTER,
        model_id=builder_session.model_id,
        workspace_id="pilot-darksage",
        authority_envelope_digest=authority_envelope_digest(
            charter.authority_envelope.to_dict()
        ),
        expected_evidence=("structured-report",),
        usage_policy={"reservation_required": True, "paid_fallback": False},
        independence_key="builder-independence",
    )
    implementation_workspace = application.orchestration.reserve_workspace(
        implementation,
        builder_workspace_path,
        lease_seconds=3600,
        branch="pilot/pass-b-builder",
        base_commit="1f5ff458",
    )
    application.orchestration.reserve_writes(
        implementation,
        implementation_workspace,
        ("keeper/pass_b",),
        lease_seconds=3600,
    )
    application.orchestration.reserve_usage(
        implementation, implementation_workspace, 1
    )
    builder_authority_attempt = _reserve_authority_attempt(
        authority_client,
        launch_authorization,
        implementation,
        implementation_workspace,
        builder.authority_registration_id or "",
        data_directory,
        "builder",
    )
    implementation_evidence = application.orchestration.run_assignment(
        implementation.assignment_id,
        builder_workspace_path,
        authority_attempt_id=builder_authority_attempt,
        global_context={"charter_revision": charter.revision},
        task_context={"objective": implementation_item.objective},
    )
    implementation_evidence = application.orchestration.validate_evidence(
        implementation_evidence.evidence_bundle_id, builder_workspace_path
    )
    application.repository.release_workspace(
        implementation_workspace.workspace_reservation_id,
        implementation_workspace.owner_token,
        _now(),
    )

    review_item = application.orchestration.create_work_item(
        project_id=project.project_id,
        charter_id=charter.charter_id,
        charter_revision=charter.revision,
        workflow_id=durable_workflow.workflow_id,
        title="Independent review",
        objective="Review implementation evidence without writes",
        dependencies=(implementation_item.work_item_id,),
        required_roles=(AssignmentRole.REVIEWER,),
    )
    review_assignment = application.orchestration.create_assignment(
        work_item=review_item,
        provider_id=reviewer.provider_id,
        account_id="reviewer-account",
        session_id=reviewer_session.session_id,
        role=AssignmentRole.REVIEWER,
        model_id=reviewer_session.model_id,
        workspace_id="pilot-darksage-reviewer",
        authority_envelope_digest=authority_envelope_digest(
            charter.authority_envelope.to_dict()
        ),
        expected_evidence=("structured-report",),
        usage_policy={
            "reservation_required": True,
            "paid_fallback": False,
            "review_of_assignment_id": implementation.assignment_id,
        },
        independence_key="reviewer-independence",
    )
    pilot_evidence_reference_record = (
        application.orchestration.create_local_evidence_reference(
            review_assignment.assignment_id,
            pilot_evidence_artifact,
            source_evidence_bundle_id=(
                implementation_evidence.evidence_bundle_id
            ),
        )
    )
    alternate_pilot_evidence_reference = (
        application.orchestration.create_local_evidence_reference(
            review_assignment.assignment_id,
            pilot_evidence_artifact,
            source_evidence_bundle_id=(
                implementation_evidence.evidence_bundle_id
            ),
        )
    )
    boundary_item = application.orchestration.create_work_item(
        project_id=project.project_id,
        charter_id=charter.charter_id,
        charter_revision=charter.revision,
        workflow_id=durable_workflow.workflow_id,
        title="Reviewer protected-tree boundary",
        objective="Prove protected evidence never becomes a reviewer workspace",
        dependencies=(implementation_item.work_item_id,),
        required_roles=(AssignmentRole.REVIEWER,),
    )
    boundary_assignment = application.orchestration.create_assignment(
        work_item=boundary_item,
        provider_id=reviewer.provider_id,
        account_id="reviewer-account",
        session_id=reviewer_session.session_id,
        role=AssignmentRole.REVIEWER,
        model_id=reviewer_session.model_id,
        workspace_id="pilot-protected-parent-rejection",
        authority_envelope_digest=authority_envelope_digest(
            charter.authority_envelope.to_dict()
        ),
        expected_evidence=("structured-report",),
        usage_policy={"reservation_required": True, "paid_fallback": False},
        independence_key="reviewer-boundary-independence",
    )
    reviewer_adapter = application.orchestration.adapters[reviewer.provider_id]
    reviewer_launches_before_rejection = int(
        reviewer_adapter.health()["launched"]
    )
    reviewer_parent_workspace_rejected = False
    try:
        application.orchestration.reserve_workspace(
            boundary_assignment,
            data_directory,
            lease_seconds=3600,
            branch=None,
            base_commit="1f5ff458",
        )
    except PermissionError:
        reviewer_parent_workspace_rejected = True
    reviewer_parent_adapter_not_invoked = (
        int(reviewer_adapter.health()["launched"])
        == reviewer_launches_before_rejection
    )
    reviewer_parent_evidence_unchanged = (
        pilot_evidence_artifact.read_bytes(),
        pilot_evidence_artifact.stat().st_mtime_ns,
    ) == pilot_evidence_snapshot
    review_workspace = application.orchestration.reserve_workspace(
        review_assignment,
        reviewer_workspace_path,
        lease_seconds=3600,
        branch=None,
        base_commit="1f5ff458",
    )
    application.orchestration.reserve_usage(
        review_assignment, review_workspace, 1
    )
    reviewer_authority_attempt = _reserve_authority_attempt(
        authority_client,
        launch_authorization,
        review_assignment,
        review_workspace,
        reviewer.authority_registration_id or "",
        data_directory,
        "reviewer",
    )
    review_evidence = application.orchestration.run_assignment(
        review_assignment.assignment_id,
        reviewer_workspace_path,
        authority_attempt_id=reviewer_authority_attempt,
        global_context={"charter_revision": charter.revision},
        task_context={
            "implementation_evidence": implementation_evidence.evidence_bundle_id,
        },
        evidence_reference_ids=(
            pilot_evidence_reference_record.evidence_reference_id,
        ),
        side_effect_class="READ_ONLY_REVIEW",
    )
    review_evidence = application.orchestration.validate_evidence(
        review_evidence.evidence_bundle_id, reviewer_workspace_path
    )
    pilot_evidence_reference_preserved = (
        pilot_evidence_artifact.read_bytes(),
        pilot_evidence_artifact.stat().st_mtime_ns,
    ) == pilot_evidence_snapshot
    reviewer_workspace_isolated = (
        Path(review_workspace.canonical_path)
        != Path(implementation_workspace.canonical_path)
        and Path(review_workspace.canonical_path).parent
        == Path(implementation_workspace.canonical_path).parent
    )
    reviewer_attempt_record = application.repository.get(
        AttemptRecord, review_evidence.attempt_id
    )
    if reviewer_attempt_record.delivered_input_id is None:
        raise RuntimeError("pilot reviewer input was not durably bound")
    delivered_input_record = application.repository.get(
        DeliveredInputRecord,
        reviewer_attempt_record.delivered_input_id,
    )
    delivered_but_alternate_consumed_rejected = False
    try:
        application.orchestration.create_review(
            implementation_evidence.evidence_bundle_id,
            review_assignment.assignment_id,
            review_evidence.evidence_bundle_id,
            evidence_reference_id=(
                alternate_pilot_evidence_reference.evidence_reference_id
            ),
        )
    except PermissionError:
        delivered_but_alternate_consumed_rejected = True
    independent_review = application.orchestration.create_review(
        implementation_evidence.evidence_bundle_id,
        review_assignment.assignment_id,
        review_evidence.evidence_bundle_id,
        evidence_reference_id=(
            pilot_evidence_reference_record.evidence_reference_id
        ),
    )
    independent_review, _, _ = application.orchestration.decide_review(
        independent_review.review_id
    )

    waiting_item = application.orchestration.create_work_item(
        project_id=project.project_id,
        charter_id=charter.charter_id,
        charter_revision=charter.revision,
        workflow_id=durable_workflow.workflow_id,
        title="Usage reset simulation",
        objective="Pause and resume without duplicate execution",
        required_roles=(AssignmentRole.TESTER,),
    )
    waiting_assignment = application.orchestration.create_assignment(
        work_item=waiting_item,
        provider_id=builder.provider_id,
        account_id="builder-account",
        session_id=builder_session.session_id,
        role=AssignmentRole.TESTER,
        model_id=builder_session.model_id,
        workspace_id="pilot-waiting",
        authority_envelope_digest=authority_envelope_digest(
            charter.authority_envelope.to_dict()
        ),
        expected_evidence=("structured-report",),
        usage_policy={"reservation_required": True, "paid_fallback": False},
        independence_key="usage-test",
    )
    waiting_path = data_directory / "usage-waiting-workspace"
    waiting_path.mkdir(exist_ok=True)
    waiting_workspace = application.orchestration.reserve_workspace(
        waiting_assignment,
        waiting_path,
        lease_seconds=3600,
        branch="pilot/pass-b-usage",
        base_commit="1f5ff458",
    )
    paused = not application.orchestration.reserve_usage(
        waiting_assignment, waiting_workspace, 2
    )
    checkpoint = next(
        item
        for item in application.repository.list(ResumeCheckpointRecord)
        if item.assignment_id == waiting_assignment.assignment_id
    )
    current_pool = application.repository.get(
        UsagePoolRecord, builder_pool.pool_id
    )
    reset_observation = usage_reset_verifier.issue(
        current_pool,
        reset_at=current_pool.reset_at or "",
        observed_at=_now(),
        model_ids=(builder_session.model_id,),
        session_ids=(builder_session.session_id,),
    )
    application.orchestration.observe_usage_reset(reset_observation)
    resumed_assignment = application.orchestration.resume_after_reset(
        waiting_assignment.assignment_id,
        checkpoint.resume_checkpoint_id,
    )
    prohibited_delegation_results: dict[str, bool] = {}
    for prohibited_action in ("PUSH", "FORCE_PUSH"):
        try:
            activate_delegated_mode(
                application.repository,
                project_status=application.project_status,
                project_id=project.project_id,
                charter=charter,
                founder_identity=str(charter.founder_approval_identity),
                founder_approval_id=str(charter.founder_approval_record_id),
                founder_approval_digest=str(
                    charter.founder_authorization_capability_digest
                ),
                scope=(prohibited_action,),
                expires_at=(
                    datetime.now(UTC) + timedelta(minutes=1)
                ).isoformat(),
            )
        except PermissionError:
            prohibited_delegation_results[prohibited_action] = True
        else:
            prohibited_delegation_results[prohibited_action] = False
    prohibited_delegation_denied = all(
        prohibited_delegation_results.values()
    )
    delegation_observed_at = datetime.now(UTC)
    superseded_grant = activate_delegated_mode(
        application.repository,
        project_status=application.project_status,
        project_id=project.project_id,
        charter=charter,
        founder_identity=str(charter.founder_approval_identity),
        founder_approval_id=str(charter.founder_approval_record_id),
        founder_approval_digest=str(
            charter.founder_authorization_capability_digest
        ),
        scope=("RUN_TESTS",),
        expires_at=(
            delegation_observed_at + timedelta(minutes=10)
        ).isoformat(),
    )
    validate_delegated_action(
        application.repository,
        superseded_grant.delegated_mode_grant_id,
        project_status=application.project_status,
        project_id=project.project_id,
        charter_id=charter.charter_id,
        charter_revision=charter.revision,
        action="RUN_TESTS",
        observed_at=superseded_grant.starts_at,
    )
    superseding_status = json.loads(
        json.dumps(application.project_status(project.project_id))
    )
    superseding_status["project_summary"]["active_charter_revision"] = (
        charter.revision + 1
    )
    superseding_status["active_charter"]["revision"] = charter.revision + 1
    superseding_status["active_charter"]["founder_approval_record_id"] = (
        "pilot-superseding-approval"
    )
    superseding_status["active_charter"][
        "founder_authorization_capability_digest"
    ] = "b" * 64

    def superseding_project_status(requested_project_id: str) -> dict[str, Any]:
        if requested_project_id == project.project_id:
            return cast(dict[str, Any], superseding_status)
        return application.project_status(requested_project_id)
    delegated_supersession_enforced = False
    try:
        validate_delegated_action(
            application.repository,
            superseded_grant.delegated_mode_grant_id,
            project_status=cast(
                ProjectStatusReader, superseding_project_status
            ),
            project_id=project.project_id,
            charter_id=charter.charter_id,
            charter_revision=charter.revision,
            action="RUN_TESTS",
        )
    except PermissionError:
        delegated_supersession_enforced = True
    persisted_superseded_grant = application.repository.get(
        type(superseded_grant), superseded_grant.delegated_mode_grant_id
    )
    expiry_outcome = application.begin_conversation(
        "Build an isolated software verification fixture under delegated mode. "
        "Run tests only. No spending, deployment, service changes, live trading, "
        "or push."
    )
    expiry_outcome = application.conversation.revise(
        expiry_outcome.project.project_id,
        {
            "success_criteria": ("expiry enforcement is proven",),
            "target_audience": "Founder",
            "approved_providers": ("pilot-builder",),
            "approved_tools": ("tests",),
            "review_requirements": ("bounded deterministic check",),
            "evidence_requirements": ("structured-report",),
            "workspaces": (str(data_directory / "expiry-workspace"),),
        },
    )
    expiry_challenge = application.conversation.request_approval(
        expiry_outcome.project.project_id
    )
    expiry_project, current_charter = executive.approve_and_activate(
        expiry_challenge
    )
    application.conversation.record_approval(current_charter)
    expiry_observed_at = datetime.now(UTC)
    delegated_grant = activate_delegated_mode(
        application.repository,
        project_status=application.project_status,
        project_id=expiry_project.project_id,
        charter=current_charter,
        founder_identity=str(current_charter.founder_approval_identity),
        founder_approval_id=str(current_charter.founder_approval_record_id),
        founder_approval_digest=str(
            current_charter.founder_authorization_capability_digest
        ),
        scope=("RUN_TESTS",),
        expires_at=(
            expiry_observed_at + timedelta(minutes=1)
        ).isoformat(),
    )
    validate_delegated_action(
        application.repository,
        delegated_grant.delegated_mode_grant_id,
        project_status=application.project_status,
        project_id=expiry_project.project_id,
        charter_id=current_charter.charter_id,
        charter_revision=current_charter.revision,
        action="RUN_TESTS",
        observed_at=delegated_grant.starts_at,
    )
    delegated_expiry_enforced = False
    try:
        validate_delegated_action(
            application.repository,
            delegated_grant.delegated_mode_grant_id,
            project_status=application.project_status,
            project_id=expiry_project.project_id,
            charter_id=current_charter.charter_id,
            charter_revision=current_charter.revision,
            action="RUN_TESTS",
            observed_at=(
                expiry_observed_at + timedelta(minutes=2)
            ).isoformat(),
        )
    except PermissionError:
        delegated_expiry_enforced = True
    persisted_delegated_grant = application.repository.get(
        type(delegated_grant), delegated_grant.delegated_mode_grant_id
    )
    snapshot = application.control_room.snapshot(project.project_id).to_dict()
    delegated_absent_from_active_projection = all(
        item["delegated_mode_grant_id"]
        not in {
            delegated_grant.delegated_mode_grant_id,
            superseded_grant.delegated_mode_grant_id,
        }
        for item in snapshot["safety"]["delegated_mode"]
    )
    commit_receipt = pilot_authority_observer.reviewer_commit_receipt
    commit_receipt_digest = (
        pilot_authority_observer.reviewer_commit_receipt_digest
    )
    reviewer_commit_receipt_bound = (
        isinstance(commit_receipt, dict)
        and isinstance(commit_receipt_digest, str)
        and structured_digest(commit_receipt) == commit_receipt_digest
        and commit_receipt.get("delivered_input_id")
        == delivered_input_record.delivered_input_id
        and commit_receipt.get("reviewer_attempt_id")
        == reviewer_attempt_record.attempt_id
        and commit_receipt.get("reviewer_assignment_id")
        == review_assignment.assignment_id
        and commit_receipt.get("provider_input_digest")
        == delivered_input_record.provider_input_digest
        and commit_receipt.get("delivered_input_digest")
        == delivered_input_record.delivered_input_digest
        and commit_receipt.get("session_slot_claimed") is True
        and commit_receipt.get("launch_claim_state")
        == "LAUNCH_CLAIMED"
    )
    if not (
        reviewer_commit_receipt_bound
        and prohibited_delegation_denied
        and delegated_supersession_enforced
        and persisted_superseded_grant.state == "SUPERSEDED"
        and delegated_expiry_enforced
        and persisted_delegated_grant.state == "EXPIRED"
        and delegated_absent_from_active_projection
        and production_rejected_test_reset_verifier
        and pilot_evidence_read_only_reference
        and pilot_evidence_writer_rejected
        and reviewer_parent_workspace_rejected
        and reviewer_parent_adapter_not_invoked
        and reviewer_parent_evidence_unchanged
        and pilot_evidence_reference_preserved
        and reviewer_workspace_isolated
        and delivered_but_alternate_consumed_rejected
        and reviewer_attempt_record.delivered_input_digest
        == delivered_input_record.delivered_input_digest
        and review_evidence.delivered_input_digest
        == delivered_input_record.delivered_input_digest
        and delivered_input_record.composition_identity == "TEST_AUTHORITY"
    ):
        raise RuntimeError("pilot delegated-mode boundary proof failed")
    attempts = application.repository.list(AttemptRecord)
    launched_assignments = [
        item.assignment_id
        for item in attempts
        if item.external_execution_id is not None
    ]
    duplicate_launch_count = len(launched_assignments) - len(
        set(launched_assignments)
    )
    authority_attempt_states = {
        attempt_id: authority_client.query_state(
            "attempts", attempt_id
        )["record"]["service_state"]
        for attempt_id in (
            builder_authority_attempt,
            reviewer_authority_attempt,
        )
    }
    report = {
        "schema_version": 2,
        "pilot": "Keeper Completion Pass B DarkSage/Sage",
        "generated_at": _now(),
        "project_id": project.project_id,
        "charter_id": charter.charter_id,
        "charter_revision": charter.revision,
        "charter_founder_approved": bool(
            charter.founder_approval_record_id
            and charter.founder_authorization_capability_digest
        ),
        "workflow_strategy": blueprint.strategy,
        "workflow_roles": [item.role for item in blueprint.steps],
        "durable_workflow_id": durable_workflow.workflow_id,
        "durable_work_item_ids": (
            implementation_item.work_item_id,
            review_item.work_item_id,
            waiting_item.work_item_id,
        ),
        "durable_workflow_present": (
            application.repository.get(
                type(durable_workflow), durable_workflow.workflow_id
            )
            == durable_workflow
        ),
        "provider_sessions": [
            builder_session.session_id,
            reviewer_session.session_id,
        ],
        "implementation_assignment": implementation.assignment_id,
        "review_assignment": review_assignment.assignment_id,
        "implementation_evidence": implementation_evidence.to_dict(),
        "review_evidence": review_evidence.to_dict(),
        "independent_review": independent_review.to_dict(),
        "reviewer_delivered_input": delivered_input_record.to_dict(),
        "reviewer_delivered_input_digest": (
            delivered_input_record.delivered_input_digest
        ),
        "reviewer_provider_input_digest": (
            delivered_input_record.provider_input_digest
        ),
        "reviewer_input_composition_identity": (
            delivered_input_record.composition_identity
        ),
        "reviewer_executive_commit_receipt_bound": (
            reviewer_commit_receipt_bound
        ),
        "reviewer_executive_commit_receipt_digest": (
            commit_receipt_digest
        ),
        "reviewer_evidence_bound_to_delivered_input": (
            review_evidence.delivered_input_digest
            == delivered_input_record.delivered_input_digest
        ),
        "review_consumed_exact_delivered_input": (
            independent_review.delivered_input_digest
            == delivered_input_record.delivered_input_digest
            and independent_review.consumed_evidence_reference_ids
            == (
                pilot_evidence_reference_record.evidence_reference_id,
            )
        ),
        "delivered_a_consumed_b_rejected": (
            delivered_but_alternate_consumed_rejected
        ),
        "usage_pause_observed": paused,
        "usage_resume_state": resumed_assignment.state,
        "delegated_prohibited_action_denied": (
            prohibited_delegation_denied
        ),
        "delegated_push_denied": prohibited_delegation_results["PUSH"],
        "delegated_force_push_denied": (
            prohibited_delegation_results["FORCE_PUSH"]
        ),
        "delegated_supersession_enforced": (
            delegated_supersession_enforced
        ),
        "delegated_superseded_state": persisted_superseded_grant.state,
        "delegated_expiry_enforced": delegated_expiry_enforced,
        "delegated_expired_state": persisted_delegated_grant.state,
        "delegated_absent_from_active_projection": (
            delegated_absent_from_active_projection
        ),
        "duplicate_launch_count": duplicate_launch_count,
        "production_rejected_test_reset_verifier": (
            production_rejected_test_reset_verifier
        ),
        "pilot_evidence_read_only_reference": (
            pilot_evidence_read_only_reference
        ),
        "pilot_evidence_writer_rejected": pilot_evidence_writer_rejected,
        "pilot_evidence_reference": pilot_evidence_reference,
        "pilot_evidence_reference_id": (
            pilot_evidence_reference_record.evidence_reference_id
        ),
        "pilot_evidence_reference_digest": pilot_evidence_digest,
        "pilot_evidence_reference_preserved": (
            pilot_evidence_reference_preserved
        ),
        "reviewer_workspace": review_workspace.canonical_path,
        "reviewer_workspace_isolated": reviewer_workspace_isolated,
        "reviewer_parent_workspace_rejected": (
            reviewer_parent_workspace_rejected
        ),
        "reviewer_parent_adapter_not_invoked": (
            reviewer_parent_adapter_not_invoked
        ),
        "reviewer_parent_evidence_unchanged": (
            reviewer_parent_evidence_unchanged
        ),
        "automatic_paid_fallback": False,
        "provider_self_approval": False,
        "push_performed": False,
        "deployment_performed": False,
        "spending_performed": False,
        "service_change_performed": False,
        "live_trading_enabled": False,
        "presentation_authority_effect": "NONE",
        "authority_attempts": (
            builder_authority_attempt,
            reviewer_authority_attempt,
        ),
        "authority_attempt_states": authority_attempt_states,
        "authority_production_validation": False,
        "control_room_summary": {
            "assignment_counts": snapshot["control_room"][
                "assignment_counts"
            ],
            "uncertain_assignments": len(
                snapshot["safety"]["uncertain_assignments"]
            ),
            "authority_state": snapshot["safety"]["authority"]["state"],
        },
        "result": "PASS",
    }
    evidence_path = evidence_path.resolve()
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    return report


def _register_provider(
    application: PassBApplication,
    authority_client: TestAuthorityServiceClient,
    data_directory: Path,
    *,
    provider_id: str,
    authority_provider_id: str,
    account_id: str,
    session_id: str,
    capacity: float,
) -> tuple[ProviderRecord, ProviderSessionRecord, UsagePoolRecord]:
    now = _now()
    pool_id = f"{provider_id}-shared-pool"
    adapter = LocalMockAdapter(provider_id)
    descriptor = adapter.descriptor()
    executable = data_directory / "authority-providers" / (
        f"{provider_id}.exe"
    )
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(f"safe:{provider_id}".encode("utf-8"))
    registration_id = str(
        authority_client.register_provider(
            authority_provider_id,
            executable,
            executive_capabilities=sorted(
                {
                    "acceptance", "architecture", "implementation", "packaging",
                    "planning", "production", "requirements", "review",
                    "security", "testing",
                }
            ),
            project_types=["general", "software"],
            effort_levels=["high", "medium"],
            pricing_authority={
                "pricing_identity": f"pilot-pricing:{provider_id}",
                "pricing_version": "2026-07",
                "currency": "USD",
                "estimated_cost": 0.0,
                "maximum_cost": 0.0,
                "billing_unit": "included-pilot-session",
                "included_plan": True,
                "marginally_free": True,
                "quoted_at": "2026-07-01T00:00:00+00:00",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "source": "TEST_AUTHORITY_REGISTRATION",
                "cost_tier": 0,
            },
        )["registration_id"]
    )
    authority_client.qualify_provider(registration_id)
    provider = ProviderRecord(
        provider_id=provider_id,
        identity=provider_id,
        display_name=provider_id,
        classification=ProviderClassification.LOCAL,
        adapter_kind="pilot-mock",
        capabilities=tuple(
            role.value.casefold() for role in AssignmentRole
        )
        + descriptor.capabilities,
        session_model=SessionModel.RESUMABLE,
        usage_pool_strategy="shared-account-window",
        concurrency_limit=descriptor.concurrency_limit,
        cost_mode=CostMode.FREE,
        authentication_ready=True,
        tool_support=("filesystem",),
        workspace_support=("isolated-worktree", "read-only"),
        cancellation_support=True,
        resume_support=True,
        evidence_format="keeper-evidence-v1",
        health=HealthState.READY,
        created_at=now,
        updated_at=now,
        revision=1,
        authority_registration_id=registration_id,
    )
    account = ProviderAccountRecord(
        account_id=account_id,
        provider_id=provider_id,
        identity=f"{provider_id}:{account_id}",
        display_name=account_id,
        usage_pool_id=pool_id,
        cost_mode=CostMode.FREE,
        privacy_classification="LOCAL",
        authentication_ready=True,
        enabled=True,
        created_at=now,
        updated_at=now,
        revision=1,
    )
    pool = UsagePoolRecord(
        pool_id=pool_id,
        provider_id=provider_id,
        account_id=account_id,
        identity=descriptor.usage_pool_identity,
        limit_type="MEASURED_WINDOW",
        capacity=capacity,
        consumed=0,
        reserved=0,
        remaining=capacity,
        reset_at=(_utc_now() - timedelta(seconds=1)).isoformat(),
        observation_source="pilot-fixture",
        confidence="HIGH",
        exhausted=False,
        last_observed_at=now,
        created_at=now,
        updated_at=now,
        revision=1,
    )
    session = ProviderSessionRecord(
        session_id=session_id,
        provider_id=provider_id,
        account_id=account_id,
        model_id=descriptor.model_identity,
        external_session_id=None,
        state=ProviderSessionState.READY,
        concurrency_limit=1,
        active_assignments=0,
        supports_resume=True,
        resume_token_digest=None,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
        revision=1,
    )
    application.register_adapter(
        provider,
        account,
        pool,
        (session,),
        adapter,
    )
    return provider, session, pool


def _reserve_authority_attempt(
    authority_client: TestAuthorityServiceClient,
    launch_authorization: dict[str, Any],
    assignment: AssignmentRecord,
    workspace: Any,
    registration_id: str,
    data_directory: Path,
    label: str,
) -> str:
    evidence_root = data_directory / "authority-evidence" / label
    evidence_root.mkdir(parents=True, exist_ok=True)
    provider_run_id = f"pilot-{label}-{uuid.uuid4().hex}"
    result = authority_client.reserve_attempt(
        registration_id=registration_id,
        keeper_run_id=f"pilot-{assignment.project_id}",
        task_id=assignment.assignment_id,
        stage_id=assignment.work_item_id,
        role=assignment.role.casefold(),
        attempt_number=1,
        provider_run_id=provider_run_id,
        provider_instance_id=assignment.session_id,
        evidence_path=str((evidence_root / "evidence.json").resolve()),
        prompt_path=str((evidence_root / "prompt.md").resolve()),
        stdout_path=str((evidence_root / "stdout.log").resolve()),
        stderr_path=str((evidence_root / "stderr.log").resolve()),
        workspace=str(Path(workspace.canonical_path).resolve()),
        timeout_seconds=60,
        reasoning_level="medium",
        environment={},
        provider_input_required=assignment.role == AssignmentRole.REVIEWER,
        launch_authorization_id=launch_authorization["id"],
        authorization_generation=launch_authorization[
            "authorization_generation"
        ],
        delegation_id=launch_authorization["delegation_id"],
        founder_approval_event_id=launch_authorization[
            "founder_approval_event_id"
        ],
        founder_approval_event_digest=launch_authorization[
            "founder_approval_event_digest"
        ],
        founder_authenticated_session_id=launch_authorization[
            "founder_authenticated_session_id"
        ],
        founder_principal_sid=launch_authorization[
            "founder_principal_sid"
        ],
        authorization_expires_at=launch_authorization["expires_at"],
        project_id=assignment.project_id,
        charter_id=assignment.charter_id,
        charter_revision=assignment.charter_revision,
        task_revision=assignment.revision,
    )
    return str(result["attempt_id"])


def _pilot_launch_capability(
    charter: ProjectCharter,
) -> dict[str, Any]:
    value = charter.founder_authorization_capability
    if not isinstance(value, dict):
        raise RuntimeError("pilot charter has no Founder capability")
    existing = FounderAuthorizationCapability.from_dict(value)
    claims = FounderCapabilityClaims(
        **{
            **existing.claims(),
            "capability_id": f"pilot-launch:{charter.project_id}",
            "authorization_generation": 1,
            "revocation_epoch": 0,
        }
    )
    issuer = TestFounderCapabilityIssuer()
    unsigned_confirmation: dict[str, object] = {
        "session_id": claims.founder_authenticated_session_id,
        "principal_sid": claims.founder_principal_sid,
        "account_name": "KEEPER-PILOT\\Founder",
        "authentication_method": "TEST_CHALLENGE_HMAC",
        "authenticated_at": claims.issued_at,
        "expires_at": claims.expires_at,
        "machine_identity": claims.machine_identity,
        "application_identity": claims.application_identity,
        "process_identity": "keeper-pass-b-pilot",
        "challenge_id": claims.challenge_id,
        "challenge_nonce": f"pilot:{charter.project_id}",
        "project_id": claims.project_id,
        "charter_id": claims.charter_id,
        "charter_revision": claims.charter_revision,
        "approval_action": "APPROVE_CHARTER",
        "bound_digest": claims.action_digest,
        "source_user_interaction_id": claims.approval_event_id,
        "proof_version": 2,
    }
    proof = issuer.sign_confirmation(unsigned_confirmation)
    claims = FounderCapabilityClaims(
        **{
            **asdict(claims),
            "challenge_proof_digest": hashlib.sha256(
                proof.encode("ascii")
            ).hexdigest(),
        }
    )
    confirmation = {**unsigned_confirmation, "proof": proof}
    return issuer.issue(claims, confirmation).to_dict()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _now() -> str:
    return _utc_now().isoformat()
