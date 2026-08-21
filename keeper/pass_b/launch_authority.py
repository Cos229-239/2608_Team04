from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Protocol, cast

from keeper.evidence_input import (
    finalize_provider_input,
    structured_digest,
    validate_provider_input,
    validate_review_input_declaration,
)
from keeper.authority_service.client import (
    AuthorityServiceClient,
    ProductionAuthorityServiceClient,
    TestAuthorityServiceClient,
)
from keeper.executive.service import KeeperExecutive
from keeper.pass_b.models import (
    AssignmentRecord,
    ProviderRecord,
    WorkflowRecord,
    WorkItemRecord,
    WorkspaceReservationRecord,
)
from keeper.pass_b.providers import (
    AdapterAssignment,
    AdapterResult,
    ProviderAdapter,
)
from keeper.pass_b.repository import canonical_workspace_path


class ProjectStatusReader(Protocol):
    def __call__(self, project_id: str) -> dict[str, Any]: ...


class CommittedInputReceiptIssuer(Protocol):
    def __call__(
        self,
        delivered_input_id: str,
        *,
        authority_attempt_id: str,
        provider_input_digest: str,
        delivered_input_digest: str,
        manifest_digest: str,
    ) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class LaunchAuthorization:
    authority_attempt_id: str
    launch_token: str
    launch_plan_digest: str
    launch_authorization_id: str
    authorization_generation: int
    stdout_path: str
    stderr_path: str
    provider_input: dict[str, Any] | None = None
    delivered_input_digest: str | None = None
    provider_input_digest: str | None = None
    provider_input_bound: bool = False
    executive_commit_receipt_digest: str | None = None


class LaunchAuthority(Protocol):
    def authorize(
        self,
        workflow: WorkflowRecord,
        work_item: WorkItemRecord,
        assignment: AssignmentRecord,
        provider: ProviderRecord,
        workspace: WorkspaceReservationRecord,
        authority_attempt_id: str,
        *,
        reviewer_attempt_id: str | None = None,
        provider_input_base: dict[str, Any] | None = None,
    ) -> LaunchAuthorization: ...

    def bind_committed_input(
        self,
        authorization: LaunchAuthorization,
        delivered_input_id: str,
    ) -> LaunchAuthorization: ...

    def launch(
        self,
        authorization: LaunchAuthorization,
        request: AdapterAssignment,
        adapter: ProviderAdapter,
    ) -> AdapterResult: ...


class UnavailableLaunchAuthority:
    """Fail-closed launch authority used when production is not configured."""

    def authorize(
        self,
        workflow: WorkflowRecord,
        work_item: WorkItemRecord,
        assignment: AssignmentRecord,
        provider: ProviderRecord,
        workspace: WorkspaceReservationRecord,
        authority_attempt_id: str,
        *,
        reviewer_attempt_id: str | None = None,
        provider_input_base: dict[str, Any] | None = None,
    ) -> LaunchAuthorization:
        del (
            workflow,
            work_item,
            assignment,
            provider,
            workspace,
            authority_attempt_id,
            reviewer_attempt_id,
            provider_input_base,
        )
        raise PermissionError(
            "Pass B launch requires active Executive and KeeperAuthority binding"
        )

    def bind_committed_input(
        self,
        authorization: LaunchAuthorization,
        delivered_input_id: str,
    ) -> LaunchAuthorization:
        del authorization, delivered_input_id
        raise PermissionError("Pass B launch authority is unavailable")

    def launch(
        self,
        authorization: LaunchAuthorization,
        request: AdapterAssignment,
        adapter: ProviderAdapter,
    ) -> AdapterResult:
        del authorization, request, adapter
        raise PermissionError("Pass B launch authority is unavailable")


class ExecutiveAuthorityLaunchGate:
    """Validates one Executive charter and signed Authority attempt per launch."""

    def __init__(
        self,
        authority: AuthorityServiceClient,
        project_status: ProjectStatusReader,
        *,
        production: bool,
        receipt_issuer: CommittedInputReceiptIssuer,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if production and not isinstance(
            authority, ProductionAuthorityServiceClient
        ):
            raise TypeError("production launch gate requires the production client")
        if not production and not isinstance(
            authority, TestAuthorityServiceClient
        ):
            raise TypeError("test launch gate requires an explicit test client")
        self._authority = authority
        self._project_status = project_status
        self._production = production
        self._receipt_issuer = receipt_issuer
        self._clock = clock or (lambda: datetime.now(UTC))

    @classmethod
    def production(
        cls,
        executive: KeeperExecutive,
        authority: ProductionAuthorityServiceClient,
    ) -> ExecutiveAuthorityLaunchGate:
        authority.require_live_identity()
        return cls(
            authority,
            lambda project_id: _status_dict(executive, project_id),
            production=True,
            receipt_issuer=executive.issue_pass_b_delivered_input_receipt,
        )

    @classmethod
    def test(
        cls,
        authority: TestAuthorityServiceClient,
        project_status: ProjectStatusReader,
        *,
        receipt_issuer: CommittedInputReceiptIssuer,
        clock: Callable[[], datetime] | None = None,
    ) -> ExecutiveAuthorityLaunchGate:
        return cls(
            authority,
            project_status,
            production=False,
            receipt_issuer=receipt_issuer,
            clock=clock,
        )

    def authorize(
        self,
        workflow: WorkflowRecord,
        work_item: WorkItemRecord,
        assignment: AssignmentRecord,
        provider: ProviderRecord,
        workspace: WorkspaceReservationRecord,
        authority_attempt_id: str,
        *,
        reviewer_attempt_id: str | None = None,
        provider_input_base: dict[str, Any] | None = None,
    ) -> LaunchAuthorization:
        if not provider.authority_registration_id:
            raise PermissionError(
                "provider has no durable KeeperAuthority registration"
            )
        _validate_durable_binding(workflow, work_item, assignment)
        charter = self._active_charter(assignment)
        self._validate_charter_scope(charter, assignment, workspace)
        state = self._authority.query_state("attempts", authority_attempt_id)
        record = _queried_record(state, "Authority attempt")
        service_state = record.pop("service_state", None)
        if service_state != "RESERVED" or not self._authority.verify(
            "provider-launch-authorization", record
        ):
            raise PermissionError("Authority attempt is not valid and reserved")
        expected: dict[str, object] = {
            "id": authority_attempt_id,
            "registration_id": provider.authority_registration_id,
            "task_id": assignment.assignment_id,
            "stage_id": assignment.work_item_id,
            "role": assignment.role.casefold(),
            "provider_instance_id": assignment.session_id,
            "workspace": canonical_workspace_path(
                Path(workspace.canonical_path),
            ),
            "project_id": assignment.project_id,
            "charter_id": assignment.charter_id,
            "charter_revision": assignment.charter_revision,
            "task_revision": assignment.revision,
        }
        mismatches = [
            name
            for name, value in expected.items()
            if _comparable(record.get(name)) != _comparable(value)
        ]
        if mismatches:
            raise PermissionError(
                "Authority attempt binding mismatch: "
                + ", ".join(sorted(mismatches))
            )
        expires_at = _parse_time(
            str(record.get("authorization_expires_at"))
        )
        if expires_at <= self._clock():
            raise PermissionError("Authority launch authorization expired")
        authorization_id = str(record.get("launch_authorization_id") or "")
        generation = record.get("authorization_generation")
        if not authorization_id or not isinstance(generation, int):
            raise PermissionError("Authority launch generation is invalid")
        launch_state = self._authority.query_state(
            "launch_authorizations", authorization_id
        )
        launch_record = _queried_record(
            launch_state, "Authority launch authorization"
        )
        if (
            launch_record.get("service_state") != "ACTIVE"
            or launch_record.get("project_id") != assignment.project_id
            or launch_record.get("charter_id") != assignment.charter_id
            or launch_record.get("charter_revision")
            != assignment.charter_revision
            or launch_record.get("authorization_generation") != generation
            or launch_record.get("id") != authorization_id
        ):
            raise PermissionError(
                "Authority launch authorization is inactive or mismatched"
            )
        launch_token = str(record.get("provider_run_id") or "")
        if not launch_token:
            raise PermissionError("Authority attempt has no launch identity")
        plan = {
            **expected,
            "provider_run_id": launch_token,
            "launch_authorization_id": authorization_id,
            "authorization_generation": generation,
            "authority_envelope_digest": assignment.authority_envelope_digest,
            "workflow_id": workflow.workflow_id,
            "workflow_record_digest": _digest(workflow.to_dict()),
            "work_item_id": work_item.work_item_id,
            "work_item_record_digest": _digest(work_item.to_dict()),
            "workspace_reservation_id": workspace.workspace_reservation_id,
        }
        provider_input: dict[str, Any] | None = None
        delivered_input_digest: str | None = None
        provider_input_digest: str | None = None
        if provider_input_base is not None:
            if (
                assignment.role != "REVIEWER"
                or not reviewer_attempt_id
                or provider_input_base.get("reviewer_attempt_id")
                != reviewer_attempt_id
            ):
                raise PermissionError(
                    "typed evidence input is not bound to the reviewer attempt"
                )
            (
                provider_input,
                delivered_input_digest,
                provider_input_digest,
            ) = finalize_provider_input(
                provider_input_base,
                composition_identity=(
                    "PRODUCTION_AUTHORITY"
                    if self._production
                    else "TEST_AUTHORITY"
                ),
                provider_id=assignment.provider_id,
                account_id=assignment.account_id,
                session_id=assignment.session_id,
                model_id=assignment.model_id,
                workspace=canonical_workspace_path(
                    Path(workspace.canonical_path)
                ),
                authority_attempt_id=authority_attempt_id,
                launch_authorization_id=authorization_id,
                authorization_generation=generation,
            )
            plan.update(
                {
                    "reviewer_attempt_id": reviewer_attempt_id,
                    "delivered_input_digest": delivered_input_digest,
                    "provider_input_digest": provider_input_digest,
                }
            )
        return LaunchAuthorization(
            authority_attempt_id=authority_attempt_id,
            launch_token=launch_token,
            launch_plan_digest=_digest(plan),
            launch_authorization_id=authorization_id,
            authorization_generation=generation,
            stdout_path=str(record.get("stdout_path") or ""),
            stderr_path=str(record.get("stderr_path") or ""),
            provider_input=provider_input,
            delivered_input_digest=delivered_input_digest,
            provider_input_digest=provider_input_digest,
        )

    def bind_committed_input(
        self,
        authorization: LaunchAuthorization,
        delivered_input_id: str,
    ) -> LaunchAuthorization:
        if (
            authorization.provider_input is None
            or authorization.provider_input_digest is None
            or authorization.delivered_input_digest is None
        ):
            raise PermissionError("typed provider input was not prepared")
        manifest_digest = str(
            authorization.provider_input["manifest_digest"]
        )
        receipt = self._receipt_issuer(
            delivered_input_id,
            authority_attempt_id=authorization.authority_attempt_id,
            provider_input_digest=authorization.provider_input_digest,
            delivered_input_digest=authorization.delivered_input_digest,
            manifest_digest=manifest_digest,
        )
        receipt_digest = structured_digest(receipt)
        bound = self._authority.bind_provider_input(
            authorization.authority_attempt_id,
            authorization.provider_input,
            authorization.provider_input_digest,
            authorization.delivered_input_digest,
            manifest_digest,
            receipt,
        )
        bound_record = bound.get("attempt")
        bound_state = (
            bound_record.pop("service_state", None)
            if isinstance(bound_record, dict)
            else None
        )
        if (
            not isinstance(bound_record, dict)
            or bound_state != "INPUT_BOUND"
            or bound_record.get("provider_input_digest")
            != authorization.provider_input_digest
            or bound_record.get("delivered_input_digest")
            != authorization.delivered_input_digest
            or bound_record.get("executive_commit_receipt_digest")
            != receipt_digest
            or not self._authority.verify(
                "provider-input-binding", bound_record
            )
        ):
            raise PermissionError(
                "Authority provider-input binding is invalid"
            )
        return replace(
            authorization,
            provider_input_bound=True,
            executive_commit_receipt_digest=receipt_digest,
        )

    def launch(
        self,
        authorization: LaunchAuthorization,
        request: AdapterAssignment,
        adapter: ProviderAdapter,
    ) -> AdapterResult:
        del adapter
        if (
            authorization.provider_input is not None
            and not authorization.provider_input_bound
        ):
            raise PermissionError(
                "provider input lacks a committed Executive receipt"
            )
        self._validate_production_evidence_delivery(authorization, request)
        result = self._authority.execute_provider(
            authorization.authority_attempt_id
        )
        completion = result.get("completion")
        process_result = result.get("process_result")
        if (
            not isinstance(completion, dict)
            or not isinstance(process_result, dict)
            or not self._authority.verify(
                "provider-completion", completion
            )
            or completion.get("attempt_id")
            != authorization.authority_attempt_id
            or completion.get("project_id") != request.project_id
            or completion.get("charter_id") != request.charter_id
            or completion.get("charter_revision")
            != request.charter_revision
            or completion.get("task_id") != request.assignment_id
            or completion.get("role") != request.role.casefold()
            or completion.get("provider_instance_id")
            != request.session_id
            or completion.get("normalized_result") != "completed"
            or completion.get("delivered_input_digest")
            != authorization.delivered_input_digest
            or completion.get("provider_input_digest")
            != authorization.provider_input_digest
            or completion.get("executive_commit_receipt_digest")
            != authorization.executive_commit_receipt_digest
        ):
            raise PermissionError(
                "Authority provider completion is invalid or failed"
            )
        stdout_path = Path(authorization.stdout_path).resolve()
        stderr_path = Path(authorization.stderr_path).resolve()
        if (
            Path(str(process_result.get("stdout_path"))).resolve()
            != stdout_path
            or Path(str(process_result.get("stderr_path"))).resolve()
            != stderr_path
            or not stdout_path.is_file()
            or not stderr_path.is_file()
            or stdout_path.stat().st_size > 10_000_000
            or completion.get("provider_evidence_digest")
            != _execution_evidence_digest(stdout_path, stderr_path)
        ):
            raise PermissionError(
                "Authority provider output identity is invalid"
            )
        try:
            output = json.loads(stdout_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise PermissionError(
                "Authority provider output is malformed"
            ) from error
        if not isinstance(output, dict):
            raise PermissionError(
                "Authority provider output must be structured data"
            )
        artifact: dict[str, Any] = {
            "kind": "structured-report",
            "path": None,
            "digest": hashlib.sha256(
                stdout_path.read_bytes()
            ).hexdigest(),
            "execution_requested": False,
        }
        if request.role == "REVIEWER":
            disposition = output.get("review_disposition")
            findings = output.get("findings")
            declaration = output.get("review_input_declaration")
            if (
                disposition not in {"ACCEPTED", "REPAIR_REQUIRED"}
                or not isinstance(findings, list)
                or any(not isinstance(item, dict) for item in findings)
                or authorization.provider_input is None
                or authorization.provider_input_digest is None
            ):
                raise PermissionError(
                    "Authority review output is invalid"
                )
            try:
                validated_declaration = validate_review_input_declaration(
                    declaration,
                    authorization.provider_input,
                    provider_input_digest=(
                        authorization.provider_input_digest
                    ),
                    review_disposition=disposition,
                )
            except ValueError as error:
                raise PermissionError(
                    "Authority review input declaration is invalid"
                ) from error
            artifact.update(
                {
                    "review_disposition": disposition,
                    "findings": findings,
                    "review_input_declaration": validated_declaration,
                }
            )
        return AdapterResult(
            external_execution_id=authorization.authority_attempt_id,
            summary=f"Authority completed {request.role.casefold()} assignment.",
            artifacts=(artifact,),
            usage=None,
            session_resume_token=None,
        )

    @staticmethod
    def _validate_production_evidence_delivery(
        authorization: LaunchAuthorization,
        request: AdapterAssignment,
    ) -> None:
        provider_input = request.task_context.get("keeper_provider_input")
        provider_input_digest = request.task_context.get(
            "keeper_provider_input_digest"
        )
        if provider_input is None:
            if (
                request.role.casefold() == "reviewer"
                or authorization.provider_input is not None
            ):
                raise PermissionError("reserved provider input was omitted")
            return
        try:
            validated_input = validate_provider_input(provider_input)
        except ValueError as error:
            raise PermissionError(
                "production evidence context is not structured"
            ) from error
        if (
            validated_input != authorization.provider_input
            or provider_input_digest != authorization.provider_input_digest
            or structured_digest(validated_input) != provider_input_digest
            or validated_input["authority_attempt_id"]
            != authorization.authority_attempt_id
            or validated_input["project_id"] != request.project_id
            or validated_input["charter_id"] != request.charter_id
            or validated_input["charter_revision"]
            != request.charter_revision
            or validated_input["workflow_id"] != request.workflow_id
            or validated_input["work_item_id"] != request.work_item_id
            or validated_input["reviewer_assignment_id"]
            != request.assignment_id
            or validated_input["reviewer_attempt_id"] != request.attempt_id
            or validated_input["provider_id"] != request.provider_id
            or validated_input["account_id"] != request.account_id
            or validated_input["session_id"] != request.session_id
            or validated_input["model_id"] != request.model_id
            or validated_input["workspace"]
            != canonical_workspace_path(request.workspace)
        ):
            raise PermissionError(
                "production evidence context binding is invalid"
            )
        raw_references = validated_input["references"]
        manifest_value = request.task_context.get(
            "keeper_evidence_manifest"
        )
        if manifest_value != ".keeper-input/evidence-references.json":
            raise PermissionError(
                "production evidence manifest identity is invalid"
            )
        workspace = request.workspace.resolve(strict=True)
        manifest = (workspace / str(manifest_value)).resolve(strict=True)
        try:
            manifest.relative_to(workspace)
        except ValueError as error:
            raise PermissionError(
                "production evidence manifest escapes the workspace"
            ) from error
        try:
            manifest_json = json.loads(
                manifest.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise PermissionError(
                "production evidence manifest is unavailable"
            ) from error
        if manifest_json != raw_references:
            raise PermissionError(
                "production evidence manifest does not match task context"
            )
        for item in raw_references:
            if item.get("local_or_remote") == "REMOTE":
                if "review_copy" in item:
                    raise PermissionError(
                        "remote evidence context cannot expose a file"
                    )
                continue
            relative = item.get("review_copy")
            if (
                item.get("local_or_remote") != "LOCAL"
                or not isinstance(relative, str)
            ):
                raise PermissionError(
                    "local evidence review copy is missing"
                )
            copied = (workspace / relative).resolve(strict=True)
            try:
                copied.relative_to(workspace)
            except ValueError as error:
                raise PermissionError(
                    "evidence review copy escapes the workspace"
                ) from error
            content = copied.read_bytes()
            if (
                len(content) != item["size_bytes"]
                or hashlib.sha256(content).hexdigest()
                != item["sha256"]
            ):
                raise PermissionError(
                    "evidence review copy digest is invalid"
                )

    def _active_charter(
        self, assignment: AssignmentRecord
    ) -> dict[str, Any]:
        status = self._project_status(assignment.project_id)
        project = status.get("project_summary")
        charter = status.get("active_charter")
        if not isinstance(project, dict) or not isinstance(charter, dict):
            raise PermissionError("project has no durable active charter")
        if (
            project.get("project_id") != assignment.project_id
            or project.get("active_charter_id") != assignment.charter_id
            or project.get("active_charter_revision")
            != assignment.charter_revision
            or charter.get("project_id") != assignment.project_id
            or charter.get("charter_id") != assignment.charter_id
            or charter.get("revision") != assignment.charter_revision
            or charter.get("status") != "ACTIVE"
            or not charter.get("founder_approval_record_id")
            or not charter.get("founder_authorization_capability_digest")
        ):
            raise PermissionError(
                "assignment is not bound to the active Founder-approved charter"
            )
        envelope = charter.get("authority_envelope")
        if (
            not isinstance(envelope, dict)
            or _digest(envelope) != assignment.authority_envelope_digest
        ):
            raise PermissionError("assignment authority envelope is stale")
        return charter

    @staticmethod
    def _validate_charter_scope(
        charter: dict[str, Any],
        assignment: AssignmentRecord,
        workspace: WorkspaceReservationRecord,
    ) -> None:
        providers = charter.get("approved_providers")
        if isinstance(providers, (list, tuple)) and providers and (
            assignment.provider_id not in providers
        ):
            raise PermissionError("provider is outside the active charter")
        workspaces = charter.get("workspaces")
        if isinstance(workspaces, (list, tuple)) and workspaces:
            candidate = canonical_workspace_path(
                Path(workspace.canonical_path),
            )
            if not any(
                _path_contains(
                    canonical_workspace_path(
                        Path(item)
                    ),
                    candidate,
                )
                for item in workspaces
                if isinstance(item, str) and item
            ):
                raise PermissionError("workspace is outside the active charter")


class TestLaunchAuthority:
    """Explicit deterministic unit-test authority; never used by production."""

    __test__ = False

    def __init__(self) -> None:
        self._authorizations: dict[str, tuple[dict[str, object], str]] = {}
        self.last_launch_authorization: LaunchAuthorization | None = None

    def reserve(
        self,
        workflow: WorkflowRecord,
        work_item: WorkItemRecord,
        assignment: AssignmentRecord,
        provider: ProviderRecord,
        workspace: WorkspaceReservationRecord,
        authority_attempt_id: str,
        *,
        launch_token: str | None = None,
    ) -> str:
        token = launch_token or f"launch:{authority_attempt_id}"
        expected = _test_expectation(workflow, work_item, assignment, provider, workspace)
        self._authorizations[authority_attempt_id] = (expected, token)
        return authority_attempt_id

    def authorize(
        self,
        workflow: WorkflowRecord,
        work_item: WorkItemRecord,
        assignment: AssignmentRecord,
        provider: ProviderRecord,
        workspace: WorkspaceReservationRecord,
        authority_attempt_id: str,
        *,
        reviewer_attempt_id: str | None = None,
        provider_input_base: dict[str, Any] | None = None,
    ) -> LaunchAuthorization:
        registered = self._authorizations.get(authority_attempt_id)
        if registered is None:
            raise PermissionError("test Authority attempt was not reserved")
        expected, launch_token = registered
        actual = _test_expectation(workflow, work_item, assignment, provider, workspace)
        if actual != expected:
            raise PermissionError("test Authority attempt binding mismatch")
        plan = {
            **actual,
            "provider_run_id": launch_token,
            "launch_authorization_id": f"test-launch:{assignment.project_id}",
            "authorization_generation": assignment.charter_revision,
        }
        provider_input: dict[str, Any] | None = None
        delivered_input_digest: str | None = None
        provider_input_digest: str | None = None
        if provider_input_base is not None:
            if not reviewer_attempt_id:
                raise PermissionError("reviewer attempt identity is missing")
            (
                provider_input,
                delivered_input_digest,
                provider_input_digest,
            ) = finalize_provider_input(
                provider_input_base,
                composition_identity="TEST_AUTHORITY",
                provider_id=assignment.provider_id,
                account_id=assignment.account_id,
                session_id=assignment.session_id,
                model_id=assignment.model_id,
                workspace=canonical_workspace_path(
                    Path(workspace.canonical_path)
                ),
                authority_attempt_id=authority_attempt_id,
                launch_authorization_id=str(plan["launch_authorization_id"]),
                authorization_generation=assignment.charter_revision,
            )
            plan.update(
                {
                    "reviewer_attempt_id": reviewer_attempt_id,
                    "delivered_input_digest": delivered_input_digest,
                    "provider_input_digest": provider_input_digest,
                }
            )
        return LaunchAuthorization(
            authority_attempt_id=authority_attempt_id,
            launch_token=launch_token,
            launch_plan_digest=_digest(plan),
            launch_authorization_id=str(plan["launch_authorization_id"]),
            authorization_generation=assignment.charter_revision,
            stdout_path="",
            stderr_path="",
            provider_input=provider_input,
            delivered_input_digest=delivered_input_digest,
            provider_input_digest=provider_input_digest,
        )

    def bind_committed_input(
        self,
        authorization: LaunchAuthorization,
        delivered_input_id: str,
    ) -> LaunchAuthorization:
        if authorization.provider_input is None or not delivered_input_id:
            raise PermissionError("test delivered input was not committed")
        return replace(authorization, provider_input_bound=True)

    def launch(
        self,
        authorization: LaunchAuthorization,
        request: AdapterAssignment,
        adapter: ProviderAdapter,
    ) -> AdapterResult:
        self.last_launch_authorization = authorization
        if (
            request.role.casefold() == "reviewer"
            and (
                authorization.provider_input is None
                or not authorization.provider_input_bound
            )
        ):
            raise PermissionError(
                "reviewer launch requires Authority-bound provider input"
            )
        if request.task_context.get("keeper_provider_input") != (
            authorization.provider_input
        ) or request.task_context.get("keeper_provider_input_digest") != (
            authorization.provider_input_digest
        ):
            raise PermissionError("test provider input differs from reservation")
        return adapter.launch(request)


def _validate_durable_binding(
    workflow: WorkflowRecord,
    work_item: WorkItemRecord,
    assignment: AssignmentRecord,
) -> None:
    if (
        workflow.state != "ACTIVE"
        or work_item.workflow_id != workflow.workflow_id
        or assignment.workflow_id != workflow.workflow_id
        or assignment.work_item_id != work_item.work_item_id
        or workflow.project_id != assignment.project_id
        or work_item.project_id != assignment.project_id
        or workflow.charter_id != assignment.charter_id
        or work_item.charter_id != assignment.charter_id
        or workflow.charter_revision != assignment.charter_revision
        or work_item.charter_revision != assignment.charter_revision
        or workflow.authority_envelope_digest
        != assignment.authority_envelope_digest
    ):
        raise PermissionError(
            "launch is not bound to exact durable workflow and work item"
        )

def _status_dict(
    executive: KeeperExecutive, project_id: str
) -> dict[str, Any]:
    status = executive.status(project_id)
    return {
        "project_summary": dict(status.project_summary),
        "active_charter": (
            dict(status.active_charter)
            if status.active_charter is not None
            else None
        ),
    }


def _test_expectation(
    workflow: WorkflowRecord,
    work_item: WorkItemRecord,
    assignment: AssignmentRecord,
    provider: ProviderRecord,
    workspace: WorkspaceReservationRecord,
) -> dict[str, object]:
    return {
        "registration_id": provider.authority_registration_id,
        "project_id": assignment.project_id,
        "charter_id": assignment.charter_id,
        "charter_revision": assignment.charter_revision,
        "task_id": assignment.assignment_id,
        "task_revision": assignment.revision,
        "stage_id": assignment.work_item_id,
        "workflow_id": workflow.workflow_id,
        "workflow_record_digest": _digest(workflow.to_dict()),
        "work_item_id": work_item.work_item_id,
        "work_item_record_digest": _digest(work_item.to_dict()),
        "role": assignment.role,
        "provider_instance_id": assignment.session_id,
        "workspace": canonical_workspace_path(
            Path(workspace.canonical_path)
        ),
        "workspace_reservation_id": workspace.workspace_reservation_id,
        "authority_envelope_digest": assignment.authority_envelope_digest,
    }


def _queried_record(value: dict[str, Any], name: str) -> dict[str, Any]:
    record = value.get("record")
    if value.get("found") is not True or not isinstance(record, dict):
        raise PermissionError(f"{name} was not found")
    return dict(record)


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise PermissionError("Authority timestamp is not timezone aware")
    return parsed


def _comparable(value: object) -> object:
    if isinstance(value, str):
        return value.replace("\\", "/").casefold()
    return value


def _path_contains(root: str, candidate: str) -> bool:
    normalized_root = root.rstrip("/")
    return (
        candidate == normalized_root
        or candidate.startswith(normalized_root + "/")
    )


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            cast(Any, value),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _execution_evidence_digest(
    stdout_path: Path, stderr_path: Path
) -> str:
    return hashlib.sha256(
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
