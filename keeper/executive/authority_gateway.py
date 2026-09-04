from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Protocol, cast

import keeper.authority_service.client as authority_client_module
from keeper.authority_service.client import (
    DEFAULT_PIPE_NAME,
    AuthorityServiceClient,
    ProductionAuthorityServiceClient,
)
from keeper.authority_service.protocol import PROTOCOL_VERSION, Operation, Request
from keeper.executive.models import (
    ExecutiveTask,
    ProjectCharter,
    SpecialistProfile,
)
from keeper.executive.specialists import GuidanceBuilder


class AuthorityOperations(Protocol):
    """Narrow executive view of the approved Authority Service contract."""

    def diagnostics(self) -> dict[str, Any]: ...
    def query_state(self, kind: str, identifier: str) -> dict[str, Any]: ...
    def reserve_attempt(self, **identity: Any) -> dict[str, Any]: ...
    def authorize_project_launch(self, **identity: Any) -> dict[str, Any]: ...
    def revoke_project_launch(
        self, project_id: str, authorization_generation: int
    ) -> dict[str, Any]: ...
    def execute_provider(self, attempt_id: str) -> dict[str, Any]: ...
    def finalize_completion(self, attempt_id: str) -> dict[str, Any]: ...
    def cancel_attempt(self, attempt_id: str) -> dict[str, Any]: ...
    def verify(self, purpose: str, record: object) -> bool: ...


@dataclass(frozen=True, slots=True)
class AuthorityProviderBinding:
    registration_id: str
    qualification_id: str


@dataclass(frozen=True, slots=True)
class AuthorityExecutionPlan:
    authority_attempt_id: str
    project_id: str
    charter_id: str
    charter_revision: int
    workflow_id: str
    task_id: str
    task_revision: int
    stage_id: str
    role: str
    provider_id: str
    model_id: str
    session_id: str
    registration_id: str
    qualification_id: str
    registration_digest: str
    executable: str
    executable_digest: str
    workspace: str
    instructions_digest: str
    expected_outputs_digest: str
    expected_evidence_digest: str
    artifact_revision_digest: str | None
    author_attempt_id: str | None
    review_criteria_digest: str | None
    launch_authorization_id: str
    authorization_generation: int
    authorization_expires_at: str
    delegation_id: str
    founder_approval_event_id: str
    founder_approval_event_digest: str
    founder_authenticated_session_id: str
    founder_principal_sid: str
    reservation_payload: dict[str, Any]
    reasoning_level: str = "medium"
    subscription_contract: bool = False

    def binding(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("reservation_payload")
        return value


@dataclass(frozen=True, slots=True)
class AuthenticatedExecutionResult:
    authority_attempt_id: str
    task_id: str
    stage_id: str
    role: str
    provider_id: str
    model_id: str
    session_id: str
    registration_id: str
    executable_digest: str
    normalized_result: str
    terminal_disposition: str
    artifact_identity: str | None
    artifact_digest: str | None
    artifact_files: tuple[str, ...]
    evidence_digest: str
    review_disposition: str | None
    structured_review_digest: str | None
    author_attempt_id: str | None
    completion_digest: str
    authenticated: bool


def authority_operations(
    client: AuthorityServiceClient | ProductionAuthorityServiceClient,
) -> AuthorityOperations:
    """Dependency-inversion seam; no signing or protected state enters Executive."""
    return client


@dataclass(frozen=True, slots=True)
class _ProductionTransportIdentity:
    client_identity: int
    pipe_name: str
    timeout_seconds: float
    protocol_version: object
    implementation_identity: tuple[int, ...]


def _capture_production_transport_validator() -> Callable[
    [ProductionAuthorityServiceClient], _ProductionTransportIdentity
]:
    trusted_implementation = (
        ProductionAuthorityServiceClient.__dict__["_send"],
        AuthorityServiceClient.__dict__["request"],
        AuthorityServiceClient.__dict__["diagnostics"],
        AuthorityServiceClient.__dict__["query_state"],
        AuthorityServiceClient.__dict__["reconcile_executive_restore"],
        AuthorityServiceClient.__dict__["begin_executive_restore_fence"],
        AuthorityServiceClient.__dict__["confirm_executive_restore_fence"],
        AuthorityServiceClient.__dict__["complete_executive_restore_fence"],
        AuthorityServiceClient.__dict__["abort_executive_restore_fence"],
        AuthorityServiceClient.__dict__["recover_executive_restore_fence"],
        AuthorityServiceClient.__dict__["reserve_attempt"],
        AuthorityServiceClient.__dict__["authorize_project_launch"],
        AuthorityServiceClient.__dict__["revoke_project_launch"],
        AuthorityServiceClient.__dict__["execute_provider"],
        AuthorityServiceClient.__dict__["finalize_completion"],
        AuthorityServiceClient.__dict__["cancel_attempt"],
        AuthorityServiceClient.__dict__["verify"],
        authority_client_module._connect,
        authority_client_module._write_all,
        authority_client_module._read,
        authority_client_module._close,
        authority_client_module._kernel32,
        vars(authority_client_module)["encode_frame"],
        vars(authority_client_module)["decode_frame"],
        vars(authority_client_module)["parse_response"],
        vars(authority_client_module)["Request"],
        vars(authority_client_module)["Operation"],
        vars(authority_client_module)["PROTOCOL_VERSION"],
        Request.__dict__["create"],
        Request.__dict__["to_dict"],
    )
    protected_instance_names = frozenset(
        {
            "_send",
            "request",
            "diagnostics",
            "query_state",
            "reconcile_executive_restore",
            "begin_executive_restore_fence",
            "confirm_executive_restore_fence",
            "complete_executive_restore_fence",
            "abort_executive_restore_fence",
            "recover_executive_restore_fence",
            "reserve_attempt",
            "authorize_project_launch",
            "revoke_project_launch",
            "execute_provider",
            "finalize_completion",
            "cancel_attempt",
            "verify",
            "_test_transport",
        }
    )

    def validate(
        client: ProductionAuthorityServiceClient,
    ) -> _ProductionTransportIdentity:
        current_implementation = (
            ProductionAuthorityServiceClient.__dict__.get("_send"),
            AuthorityServiceClient.__dict__.get("request"),
            AuthorityServiceClient.__dict__.get("diagnostics"),
            AuthorityServiceClient.__dict__.get("query_state"),
            AuthorityServiceClient.__dict__.get("reconcile_executive_restore"),
            AuthorityServiceClient.__dict__.get("begin_executive_restore_fence"),
            AuthorityServiceClient.__dict__.get("confirm_executive_restore_fence"),
            AuthorityServiceClient.__dict__.get("complete_executive_restore_fence"),
            AuthorityServiceClient.__dict__.get("abort_executive_restore_fence"),
            AuthorityServiceClient.__dict__.get("recover_executive_restore_fence"),
            AuthorityServiceClient.__dict__.get("reserve_attempt"),
            AuthorityServiceClient.__dict__.get("authorize_project_launch"),
            AuthorityServiceClient.__dict__.get("revoke_project_launch"),
            AuthorityServiceClient.__dict__.get("execute_provider"),
            AuthorityServiceClient.__dict__.get("finalize_completion"),
            AuthorityServiceClient.__dict__.get("cancel_attempt"),
            AuthorityServiceClient.__dict__.get("verify"),
            vars(authority_client_module).get("_connect"),
            vars(authority_client_module).get("_write_all"),
            vars(authority_client_module).get("_read"),
            vars(authority_client_module).get("_close"),
            vars(authority_client_module).get("_kernel32"),
            vars(authority_client_module).get("encode_frame"),
            vars(authority_client_module).get("decode_frame"),
            vars(authority_client_module).get("parse_response"),
            vars(authority_client_module).get("Request"),
            vars(authority_client_module).get("Operation"),
            vars(authority_client_module).get("PROTOCOL_VERSION"),
            Request.__dict__.get("create"),
            Request.__dict__.get("to_dict"),
        )
        attributes = getattr(client, "__dict__", None)
        if (
            type(client) is not ProductionAuthorityServiceClient
            or not isinstance(attributes, dict)
            or protected_instance_names.intersection(attributes)
            or client.pipe_name != DEFAULT_PIPE_NAME
            or type(client.timeout_seconds) not in {int, float}
            or float(client.timeout_seconds) <= 0
            or len(current_implementation) != len(trusted_implementation)
            or any(
                current is not trusted
                for current, trusted in zip(
                    current_implementation, trusted_implementation, strict=True
                )
            )
        ):
            raise PermissionError(
                "production Authority transport implementation is invalid"
            )
        return _ProductionTransportIdentity(
            client_identity=id(client),
            pipe_name=client.pipe_name,
            timeout_seconds=float(client.timeout_seconds),
            protocol_version=PROTOCOL_VERSION,
            implementation_identity=tuple(
                id(item) for item in trusted_implementation
            ),
        )

    return validate


_validate_production_transport = _capture_production_transport_validator()
del _capture_production_transport_validator


class _PinnedProductionAuthorityOperations:
    __client: ProductionAuthorityServiceClient
    __identity: _ProductionTransportIdentity

    __slots__ = ("__client", "__identity")

    def __init__(self, client: ProductionAuthorityServiceClient) -> None:
        identity = _validate_production_transport(client)
        object.__setattr__(
            self, "_PinnedProductionAuthorityOperations__client", client
        )
        object.__setattr__(
            self, "_PinnedProductionAuthorityOperations__identity", identity
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("production Authority transport is immutable")

    def __delattr__(self, name: str) -> None:
        del name
        raise AttributeError("production Authority transport is immutable")

    def _validated_client(self) -> ProductionAuthorityServiceClient:
        client = self.__client
        identity = _validate_production_transport(client)
        if identity != self.__identity:
            raise PermissionError("production Authority transport identity changed")
        return client

    def _production_runtime_identity(self) -> _ProductionTransportIdentity:
        self._validated_client()
        return self.__identity

    def diagnostics(self) -> dict[str, Any]:
        return self._validated_client().diagnostics()

    def query_state(self, kind: str, identifier: str) -> dict[str, Any]:
        return self._validated_client().query_state(kind, identifier)

    def reserve_attempt(self, **identity: Any) -> dict[str, Any]:
        return self._validated_client().reserve_attempt(**identity)

    def authorize_project_launch(self, **identity: Any) -> dict[str, Any]:
        return self._validated_client().authorize_project_launch(**identity)

    def revoke_project_launch(
        self, project_id: str, authorization_generation: int
    ) -> dict[str, Any]:
        return self._validated_client().revoke_project_launch(
            project_id, authorization_generation
        )

    def execute_provider(self, attempt_id: str) -> dict[str, Any]:
        return self._validated_client().execute_provider(attempt_id)

    def finalize_completion(self, attempt_id: str) -> dict[str, Any]:
        return self._validated_client().finalize_completion(attempt_id)

    def cancel_attempt(self, attempt_id: str) -> dict[str, Any]:
        return self._validated_client().cancel_attempt(attempt_id)

    def verify(self, purpose: str, record: object) -> bool:
        return self._validated_client().verify(purpose, record)


class AuthorityBackedSpecialistGateway:
    """Production boundary for all Executive author and reviewer execution."""

    _authority: AuthorityOperations
    _bindings: tuple[AuthorityProviderBinding, ...]
    _exchange_root: Path
    _resolved: dict[
        tuple[str, str, str],
        tuple[AuthorityProviderBinding, dict[str, Any]],
    ]

    __slots__ = ("_authority", "_bindings", "_exchange_root", "_resolved")

    def __init__(
        self,
        authority: AuthorityOperations,
        bindings: tuple[AuthorityProviderBinding, ...],
        exchange_root: Path,
    ) -> None:
        if not bindings:
            raise RuntimeError(
                "production Executive startup requires Authority provider bindings"
            )
        object.__setattr__(self, "_authority", authority)
        object.__setattr__(self, "_bindings", bindings)
        object.__setattr__(self, "_exchange_root", exchange_root.resolve())
        object.__setattr__(self, "_resolved", {})

    def specialists(
        self,
        charter: ProjectCharter,
    ) -> tuple[SpecialistProfile, ...]:
        profiles: list[SpecialistProfile] = []
        self._resolved.clear()
        for binding in self._bindings:
            registration_state = self._authority.query_state(
                "registrations", binding.registration_id
            )
            qualification_state = self._authority.query_state(
                "qualifications", binding.qualification_id
            )
            registration = _record(registration_state, "registration")
            qualification_container = _record(
                qualification_state, "qualification"
            )
            qualification = qualification_container.get("evidence")
            if not isinstance(qualification, dict):
                continue
            if (
                registration.get("service_state") != "QUALIFIED"
                or qualification_container.get("service_state") != "QUALIFIED"
                or qualification.get("registration_id")
                != binding.registration_id
                or qualification.get("id") != binding.qualification_id
                or qualification.get("qualification_result") != "qualified"
                or not self._authority.verify(
                    "provider-qualification", qualification
                )
            ):
                continue
            provider_id = str(registration.get("logical_provider_id", ""))
            session_id = str(qualification.get("provider_instance_id", ""))
            executable = str(
                registration.get("canonical_executable_path", "")
            )
            executable_digest = str(
                registration.get("executable_sha256", "")
            )
            if (
                not provider_id
                or not session_id
                or not executable
                or not executable_digest
                or provider_id not in charter.approved_providers
            ):
                continue
            capabilities = registration.get("executive_capability_set")
            project_types = registration.get("project_types")
            model_id = registration.get("model_or_service_identity")
            independence = registration.get("independence_classification")
            effort_levels = registration.get("effort_levels")
            role_eligibility = registration.get("role_eligibility")
            pricing = registration.get("pricing_authority")
            pricing_core_fields = {
                "pricing_identity", "pricing_version", "currency",
                "estimated_cost", "maximum_cost", "billing_unit",
                "included_plan", "marginally_free", "quoted_at",
                "expires_at", "source", "cost_tier",
            }
            if (
                not isinstance(capabilities, list)
                or not capabilities
                or not all(isinstance(item, str) for item in capabilities)
                or not isinstance(project_types, list)
                or not project_types
                or not all(isinstance(item, str) for item in project_types)
                or not isinstance(model_id, str)
                or not model_id
                or not isinstance(independence, str)
                or not independence
                or not isinstance(effort_levels, list)
                or not effort_levels
                or not isinstance(role_eligibility, list)
                or not role_eligibility
                or not isinstance(pricing, dict)
                or not pricing_core_fields.issubset(pricing)
            ):
                continue
            try:
                profile = SpecialistProfile(
                    provider_id,
                    model_id,
                    session_id,
                    tuple(capabilities),
                    tuple(project_types),
                    True,
                    True,
                    f"{independence}:{binding.registration_id}:{session_id}",
                    int(pricing.get("cost_tier", -1)),
                    tuple(str(item) for item in effort_levels),
                    True,
                    1.0,
                    str(pricing["pricing_identity"]),
                    str(pricing["pricing_version"]),
                    str(pricing["currency"]),
                    float(pricing["estimated_cost"]),
                    float(pricing["maximum_cost"]),
                    str(pricing["billing_unit"]),
                    pricing.get("included_plan") is True,
                    pricing.get("marginally_free") is True,
                    str(pricing["quoted_at"]),
                    str(pricing["expires_at"]),
                    str(pricing["source"]),
                    (
                        str(pricing["billing_mode"])
                        if pricing.get("billing_mode") is not None
                        else None
                    ),
                    pricing.get("incremental_charge_authorized") is True,
                    pricing.get("api_billing_authorized") is True,
                    pricing.get("paid_fallback_authorized") is True,
                    pricing.get("capacity_bounded") is True,
                    tuple(str(item) for item in role_eligibility),
                )
            except (TypeError, ValueError):
                continue
            key = (profile.provider_id, profile.model_id, profile.session_id)
            self._resolved[key] = (binding, registration)
            profiles.append(profile)
        return tuple(profiles)

    def prepare(
        self,
        task: ExecutiveTask,
        charter: ProjectCharter,
        specialist: SpecialistProfile,
        *,
        task_id: str | None = None,
        role: str | None = None,
        artifact_revision_digest: str | None = None,
        review_instructions: tuple[str, ...] = (),
        workspace: str | None = None,
        reservation_nonce: str | None = None,
        reasoning_level: str | None = None,
    ) -> AuthorityExecutionPlan:
        key = (
            specialist.provider_id,
            specialist.model_id,
            specialist.session_id,
        )
        resolved = self._resolved.get(key)
        if resolved is None:
            raise PermissionError(
                "specialist identity did not come from current Authority state"
            )
        binding, registration = resolved
        selected_effort = reasoning_level or (
            "high"
            if task.retry_count > 0
            or not set(task.required_capabilities).isdisjoint(
                {"architecture", "critical analysis", "security"}
            )
            else "medium"
        )
        if selected_effort not in specialist.effort_levels:
            raise PermissionError(
                "assignment effort is outside the qualified provider policy"
            )
        model_allowlist = registration.get("model_allowlist")
        if (
            isinstance(model_allowlist, list)
            and specialist.model_id not in model_allowlist
        ):
            raise PermissionError(
                "assignment model is outside the qualified provider policy"
            )
        launch_task_id = task_id or task.task_id
        launch_role = role or task.role
        raw_role = launch_role.casefold()
        normalized_role = {
            "author": "builder",
            "implementer": "builder",
            "executive_builder": "builder",
            "executive_reviewer": "reviewer",
            "executive_post_repair_reviewer": "post_repair_reviewer",
        }.get(raw_role)
        if normalized_role is None:
            if "review" in raw_role:
                normalized_role = "reviewer"
            elif "repair" in raw_role:
                normalized_role = "repairer"
            else:
                normalized_role = "builder"
        role_eligibility = registration.get("role_eligibility")
        if (
            not isinstance(role_eligibility, list)
            or normalized_role not in role_eligibility
        ):
            raise PermissionError(
                "assignment role is outside the qualified provider policy"
            )
        if reservation_nonce is not None and (
            len(reservation_nonce) != 32
            or any(
                character not in "0123456789abcdef"
                for character in reservation_nonce
            )
        ):
            raise ValueError(
                "reservation nonce must be exactly 32 lowercase hex characters"
            )
        selected_workspace = str(
            Path(workspace or charter.workspaces[0]).resolve()
        )
        if not any(
            Path(selected_workspace).is_relative_to(
                Path(allowed_workspace).resolve()
            )
            for allowed_workspace in charter.workspaces
            if allowed_workspace
        ):
            raise PermissionError(
                "launch workspace is outside the active charter"
            )
        if (
            not charter.founder_approval_record_id
            or not charter.founder_approval_event_id
            or not charter.founder_approval_event_digest
            or not charter.founder_authenticated_session_id
            or not charter.founder_approval_identity
        ):
            raise PermissionError("launch delegation identity is unavailable")
        authorization_generation = charter.revision
        capability = charter.founder_authorization_capability
        capability_digest = charter.founder_authorization_capability_digest
        if not isinstance(capability, dict) or not capability_digest:
            raise PermissionError("Founder authorization capability is unavailable")
        authorization_result = self._authority.authorize_project_launch(
            founder_capability=capability,
        )
        launch_authorization = authorization_result.get("authorization")
        if (
            not isinstance(launch_authorization, dict)
            or not self._authority.verify(
                "project-launch-authorization", launch_authorization
            )
            or launch_authorization.get("project_id") != task.project_id
            or launch_authorization.get("charter_id") != task.charter_id
            or launch_authorization.get("charter_revision")
            != task.charter_revision
            or launch_authorization.get("delegation_id")
            != charter.founder_approval_record_id
            or launch_authorization.get("founder_approval_event_id")
            != charter.founder_approval_event_id
            or launch_authorization.get("founder_approval_event_digest")
            != charter.founder_approval_event_digest
            or launch_authorization.get("founder_authenticated_session_id")
            != charter.founder_authenticated_session_id
            or launch_authorization.get("founder_principal_sid")
            != charter.founder_approval_identity
            or launch_authorization.get("authorization_generation")
            != authorization_generation
            or launch_authorization.get("founder_capability_id")
            != capability.get("capability_id")
            or launch_authorization.get("founder_capability_digest")
            != capability_digest
        ):
            raise PermissionError(
                "Authority project launch authorization is invalid"
            )
        authorization_expires_at = str(
            launch_authorization["expires_at"]
        )
        prompt = {
            "global_brief": GuidanceBuilder.global_brief(charter).to_dict(),
            "task_guidance": GuidanceBuilder.task_guidance(
                task, charter
            ).to_dict(),
            "review_instructions": review_instructions,
            "artifact_revision_digest": artifact_revision_digest,
            "author_attempt_id": task.authority_attempt_id,
            "review_criteria_version": "keeper-review-v1",
            "review_criteria_digest": _digest(review_instructions),
            "provider_registration_id": binding.registration_id,
            "provider_qualification_id": binding.qualification_id,
        }
        instructions_digest = _digest(prompt)
        expected_outputs_digest = _digest(task.expected_outputs)
        expected_evidence_digest = _digest(task.evidence_requirements)
        binding_material = {
            "project_id": task.project_id,
            "charter_id": task.charter_id,
            "charter_revision": task.charter_revision,
            "workflow_id": task.workflow_id,
            "task_id": launch_task_id,
            "task_revision": task.revision,
            "stage_id": task.stage_id,
            "role": launch_role,
            "model_id": specialist.model_id,
            "prompt_digest": instructions_digest,
            "reasoning_level": selected_effort,
            "registration_id": binding.registration_id,
            "qualification_id": binding.qualification_id,
            "workspace": selected_workspace,
            "instructions_digest": instructions_digest,
            "expected_outputs_digest": expected_outputs_digest,
            "expected_evidence_digest": expected_evidence_digest,
            "artifact_revision_digest": artifact_revision_digest,
            "author_attempt_id": task.authority_attempt_id,
            "review_criteria_digest": _digest(review_instructions)
            if review_instructions
            else None,
        }
        if reservation_nonce is not None:
            binding_material["reservation_nonce"] = reservation_nonce
        provider_run_id = f"executive-{_digest(binding_material)[:32]}"
        keeper_run_id = (
            f"executive:{task.project_id}:{task.charter_id}:"
            f"r{task.charter_revision}:{task.workflow_id}"
        )
        attempt_id = f"provider-attempt:{keeper_run_id}:{provider_run_id}"
        attempt_root = (
            self._exchange_root
            / _digest(task.project_id)[:12]
            / _digest(launch_task_id)[:12]
            / _digest(provider_run_id)[:12]
        )
        attempt_root.mkdir(parents=True, exist_ok=True)
        prompt_path = attempt_root / "prompt.json"
        evidence_path = attempt_root / "evidence.json"
        stdout_path = attempt_root / "stdout.txt"
        stderr_path = attempt_root / "stderr.txt"
        prompt_path.write_text(
            json.dumps(prompt, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        reservation_payload: dict[str, Any] = {
            "registration_id": binding.registration_id,
            "keeper_run_id": keeper_run_id,
            "task_id": launch_task_id,
            "stage_id": task.stage_id,
            "role": launch_role,
            "attempt_number": task.retry_count + 1,
            "provider_run_id": provider_run_id,
            "provider_instance_id": specialist.session_id,
            "evidence_path": str(evidence_path),
            "prompt_path": str(prompt_path),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "workspace": selected_workspace,
            "timeout_seconds": 3600,
            "reasoning_level": selected_effort,
            "model_id": specialist.model_id,
            "prompt_digest": instructions_digest,
            "environment": {
                "KEEPER_EXECUTIVE_BINDING_DIGEST": _digest(binding_material)
            },
            "launch_authorization_id": str(launch_authorization["id"]),
            "authorization_generation": authorization_generation,
            "delegation_id": charter.founder_approval_record_id,
            "founder_approval_event_id": charter.founder_approval_event_id,
            "founder_approval_event_digest": charter.founder_approval_event_digest,
            "founder_authenticated_session_id": (
                charter.founder_authenticated_session_id
            ),
            "founder_principal_sid": charter.founder_approval_identity,
            "authorization_expires_at": str(
                launch_authorization["expires_at"]
            ),
            "project_id": task.project_id,
            "charter_id": task.charter_id,
            "charter_revision": task.charter_revision,
            "task_revision": task.revision,
            "workflow_id": task.workflow_id,
            "work_item_id": task.task_id,
            "assignment_id": launch_task_id,
            "provider_account_id": (
                "chatgpt-subscription:"
                + str(
                    registration.get("subscription_account_binding", {}).get(
                        "account_identity_digest", ""
                    )
                )
            ),
            "workspace_identity": _digest(
                {"project_id": task.project_id, "workspace": selected_workspace}
            ),
            "workspace_reservation_id": _digest(
                {
                    "assignment_id": launch_task_id,
                    "workspace": selected_workspace,
                    "revision": task.revision,
                }
            ),
        }
        return AuthorityExecutionPlan(
            attempt_id,
            task.project_id,
            task.charter_id,
            task.charter_revision,
            task.workflow_id,
            launch_task_id,
            task.revision,
            task.stage_id,
            launch_role,
            specialist.provider_id,
            specialist.model_id,
            specialist.session_id,
            binding.registration_id,
            binding.qualification_id,
            str(registration["configuration_digest"]),
            str(registration["canonical_executable_path"]),
            str(registration["executable_sha256"]),
            selected_workspace,
            instructions_digest,
            expected_outputs_digest,
            expected_evidence_digest,
            artifact_revision_digest,
            task.authority_attempt_id,
            _digest(review_instructions) if review_instructions else None,
            str(launch_authorization["id"]),
            authorization_generation,
            str(launch_authorization["expires_at"]),
            charter.founder_approval_record_id,
            charter.founder_approval_event_id,
            charter.founder_approval_event_digest,
            charter.founder_authenticated_session_id,
            charter.founder_approval_identity,
            reservation_payload,
            selected_effort,
            registration.get("registration_schema_version") in {4, 5},
        )

    def reserve(self, plan: AuthorityExecutionPlan) -> None:
        result = self._authority.reserve_attempt(**plan.reservation_payload)
        attempt = result.get("attempt")
        if (
            result.get("attempt_id") != plan.authority_attempt_id
            or not isinstance(attempt, dict)
            or not self._authority.verify(
                "provider-launch-authorization", attempt
            )
            or attempt.get("registration_id") != plan.registration_id
            or attempt.get("registration_digest")
            != plan.registration_digest
            or attempt.get("model_id") != plan.model_id
            or attempt.get("reasoning_level") != plan.reasoning_level
            or attempt.get("prompt_digest") != plan.instructions_digest
            or attempt.get("task_id") != plan.task_id
            or attempt.get("stage_id") != plan.stage_id
            or attempt.get("role") != plan.role
            or attempt.get("workspace") != str(Path(plan.workspace).resolve())
            or attempt.get("launch_authorization_id")
            != plan.launch_authorization_id
            or attempt.get("authorization_generation")
            != plan.authorization_generation
            or attempt.get("delegation_id") != plan.delegation_id
            or attempt.get("founder_approval_event_id")
            != plan.founder_approval_event_id
            or attempt.get("founder_approval_event_digest")
            != plan.founder_approval_event_digest
            or attempt.get("founder_authenticated_session_id")
            != plan.founder_authenticated_session_id
            or attempt.get("founder_principal_sid")
            != plan.founder_principal_sid
            or attempt.get("authorization_expires_at")
            != plan.authorization_expires_at
            or attempt.get("workflow_id") != plan.workflow_id
            or attempt.get("work_item_id")
            != plan.reservation_payload.get("work_item_id")
            or attempt.get("assignment_id") != plan.task_id
        ):
            raise PermissionError(
                "Authority attempt reservation binding is invalid"
            )

    def query_attempt(self, attempt_id: str) -> dict[str, Any]:
        return self._authority.query_state("attempts", attempt_id)

    def authority_identity(self) -> dict[str, Any]:
        return self._authority.diagnostics()

    def execute(
        self,
        plan: AuthorityExecutionPlan,
    ) -> AuthenticatedExecutionResult:
        self._revalidate_provider(plan)
        launched = self._authority.execute_provider(
            plan.authority_attempt_id
        )
        completion = launched.get("completion")
        if not isinstance(completion, dict):
            finalized = self._authority.finalize_completion(
                plan.authority_attempt_id
            )
            completion = finalized.get("completion")
        return self._authenticated_result(plan, completion)

    def reconcile(
        self,
        plan: AuthorityExecutionPlan,
    ) -> AuthenticatedExecutionResult | None:
        state = self._authority.query_state(
            "attempts", plan.authority_attempt_id
        )
        record = state.get("record")
        if not state.get("found") or not isinstance(record, dict):
            return None
        if record.get("service_state") not in {"COMPLETED", "FAILED"}:
            return None
        completion = dict(record)
        completion.pop("service_state", None)
        return self._authenticated_result(plan, completion)

    def attempt_state(self, attempt_id: str) -> str | None:
        state = self._authority.query_state("attempts", attempt_id)
        record = state.get("record")
        if not state.get("found") or not isinstance(record, dict):
            return None
        value = record.get("service_state")
        return str(value) if value is not None else None

    def cancel(self, attempt_id: str) -> None:
        self._authority.cancel_attempt(attempt_id)

    def revoke_project_launch(
        self, project_id: str, authorization_generation: int
    ) -> tuple[str, ...]:
        result = self._authority.revoke_project_launch(
            project_id, authorization_generation
        )
        canceled = result.get("canceled_attempt_ids")
        if (
            result.get("authorization_id")
            != (
                f"launch-authorization:{project_id}:"
                f"generation:{authorization_generation}"
            )
            or result.get("revocation_epoch") != authorization_generation
            or not isinstance(canceled, list)
            or not all(isinstance(item, str) for item in canceled)
        ):
            raise PermissionError(
                "Authority launch revocation response is invalid"
            )
        return tuple(canceled)

    @staticmethod
    def plan_from_record(record: dict[str, Any]) -> AuthorityExecutionPlan:
        fields = AuthorityExecutionPlan.__dataclass_fields__
        values = {
            name: record[name] for name in fields if name in record
        }
        values.setdefault("reasoning_level", "medium")
        values.setdefault("subscription_contract", False)
        return AuthorityExecutionPlan(**cast(Any, values))

    def _authenticated_result(
        self,
        plan: AuthorityExecutionPlan,
        completion: object,
    ) -> AuthenticatedExecutionResult:
        if not isinstance(completion, dict):
            raise PermissionError("Authority completion is missing")
        if (
            not self._authority.verify("provider-completion", completion)
            or completion.get("attempt_id") != plan.authority_attempt_id
            or completion.get("task_id") != plan.task_id
            or completion.get("stage_id") != plan.stage_id
            or completion.get("role") != plan.role
            or completion.get("registration_id") != plan.registration_id
            or completion.get("provider_instance_id") != plan.session_id
            or (
                plan.subscription_contract
                and (
                    completion.get("model_id") != plan.model_id
                    or completion.get("reasoning_level")
                    != plan.reasoning_level
                    or completion.get("prompt_digest")
                    != plan.instructions_digest
                    or completion.get("execution_prompt_digest")
                    != plan.instructions_digest
                )
            )
            or not isinstance(
                completion.get("provider_evidence_digest"), str
            )
        ):
            raise PermissionError(
                "Authority completion authentication or binding is invalid"
            )
        evidence_digest = str(completion["provider_evidence_digest"])
        if (
            len(evidence_digest) != 64
            or any(character not in "0123456789abcdef" for character in evidence_digest)
        ):
            raise PermissionError(
                "Authority evidence digest is not canonical SHA-256"
            )
        terminal = {
            "completed": "SUCCEEDED",
            "failed": "FAILED",
            "canceled": "CANCELED",
            "cancelled": "CANCELED",
            "timed_out": "TIMED_OUT",
            "terminated": "TERMINATED",
            "launch_failed": "LAUNCH_FAILED",
            "uncertain": "UNCERTAIN",
            "waiting_for_usage_reset": "WAITING_FOR_USAGE_RESET",
        }.get(str(completion.get("normalized_result", "")).casefold(), "UNCERTAIN")
        stdout_path = Path(str(plan.reservation_payload["stdout_path"]))
        stderr_path = Path(str(plan.reservation_payload["stderr_path"]))
        observed_evidence = _execution_evidence_digest(stdout_path, stderr_path)
        if observed_evidence != evidence_digest:
            raise PermissionError("Authority evidence digest does not match provider output")

        artifact_identity: str | None = None
        artifact_digest: str | None = None
        artifact_files: tuple[str, ...] = ()
        review_disposition: str | None = None
        structured_review_digest: str | None = None
        author_attempt_id: str | None = None
        if terminal == "SUCCEEDED":
            output = _strict_provider_output(stdout_path)
            if plan.role == "reviewer":
                review_disposition, structured_review_digest, author_attempt_id = (
                    _validate_review_output(plan, output)
                )
                artifact_identity = str(output["artifact_identity"])
                artifact_digest = str(output["artifact_digest"])
            else:
                artifact_identity, artifact_digest, artifact_files = (
                    _artifact_from_output(plan, output)
                )
        return AuthenticatedExecutionResult(
            plan.authority_attempt_id,
            plan.task_id,
            plan.stage_id,
            plan.role,
            plan.provider_id,
            plan.model_id,
            plan.session_id,
            plan.registration_id,
            plan.executable_digest,
            str(completion.get("normalized_result", "")),
            terminal,
            artifact_identity,
            artifact_digest,
            artifact_files,
            evidence_digest,
            review_disposition,
            structured_review_digest,
            author_attempt_id,
            _digest(completion),
            True,
        )

    def _revalidate_provider(self, plan: AuthorityExecutionPlan) -> None:
        registration = _record(
            self._authority.query_state(
                "registrations", plan.registration_id
            ),
            "registration",
        )
        if (
            registration.get("service_state") != "QUALIFIED"
            or registration.get("configuration_digest")
            != plan.registration_digest
            or registration.get("canonical_executable_path")
            != plan.executable
            or registration.get("executable_sha256")
            != plan.executable_digest
            or plan.reasoning_level not in registration.get(
                "effort_levels", []
            )
            or (
                isinstance(registration.get("model_allowlist"), list)
                and plan.model_id not in registration["model_allowlist"]
            )
        ):
            raise PermissionError(
                "Authority provider registration changed before launch"
            )


class SemanticAuthorityTestGateway(AuthorityBackedSpecialistGateway):
    """Test-only gateway for deterministic Authority semantic transports."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class _ProductionGatewayRuntimeIdentity:
    gateway_token: str
    client_identity: int
    transport_identity: _ProductionTransportIdentity
    pipe_name: str
    timeout_seconds: float
    bindings: tuple[AuthorityProviderBinding, ...]
    exchange_root: str


class ProductionAuthorityBackedSpecialistGateway(
    AuthorityBackedSpecialistGateway
):
    """Supported production gateway accepting only the real IPC client type.

    The gateway keeps its dependencies stable through public application paths.
    Its defensive identity checks are not a claim that Python objects resist
    arbitrary code already executing in the trusted Executive interpreter.
    Provider-generated code is never loaded into that interpreter.
    """

    _production_client: ProductionAuthorityServiceClient
    __operations: _PinnedProductionAuthorityOperations
    __runtime_token: str

    __slots__ = ("_production_client", "__operations", "__runtime_token")

    def __init__(
        self,
        authority_client: ProductionAuthorityServiceClient,
        bindings: tuple[AuthorityProviderBinding, ...],
        exchange_root: Path,
    ) -> None:
        if type(authority_client) is not ProductionAuthorityServiceClient:
            raise RuntimeError(
                "production gateway requires the production Authority IPC client"
            )
        operations = _PinnedProductionAuthorityOperations(authority_client)
        object.__setattr__(self, "_production_client", authority_client)
        object.__setattr__(
            self,
            "_ProductionAuthorityBackedSpecialistGateway__operations",
            operations,
        )
        super().__init__(operations, bindings, exchange_root)
        object.__setattr__(
            self,
            "_ProductionAuthorityBackedSpecialistGateway__runtime_token",
            secrets.token_hex(32),
        )

    def __setattr__(self, name: str, value: object) -> None:
        if name in {
            "_production_client",
            "_authority",
            "_bindings",
            "_exchange_root",
            "__sealed",
            "_ProductionAuthorityBackedSpecialistGateway__sealed",
            "_ProductionAuthorityBackedSpecialistGateway__operations",
            "_ProductionAuthorityBackedSpecialistGateway__runtime_token",
        }:
            raise AttributeError(
                "production Authority gateway composition is immutable"
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if name in {
            "_production_client",
            "_authority",
            "_bindings",
            "_exchange_root",
            "__sealed",
            "_ProductionAuthorityBackedSpecialistGateway__sealed",
            "_ProductionAuthorityBackedSpecialistGateway__operations",
            "_ProductionAuthorityBackedSpecialistGateway__runtime_token",
        }:
            raise AttributeError(
                "production Authority gateway composition is immutable"
            )
        object.__delattr__(self, name)

    def _production_runtime_identity(
        self,
    ) -> _ProductionGatewayRuntimeIdentity:
        if type(self) is not ProductionAuthorityBackedSpecialistGateway:
            raise PermissionError(
                "production runtime requires the exact production gateway"
            )
        client = self._production_client
        operations = self.__operations
        transport_identity = operations._production_runtime_identity()
        if (
            type(client) is not ProductionAuthorityServiceClient
            or self._authority is not operations
            or transport_identity.client_identity != id(client)
            or client.pipe_name != DEFAULT_PIPE_NAME
            or not isinstance(self._bindings, tuple)
            or not self._bindings
            or any(
                type(binding) is not AuthorityProviderBinding
                for binding in self._bindings
            )
            or not isinstance(self._exchange_root, Path)
        ):
            raise PermissionError(
                "production Authority gateway composition is invalid"
            )
        return _ProductionGatewayRuntimeIdentity(
            gateway_token=self.__runtime_token,
            client_identity=id(client),
            transport_identity=transport_identity,
            pipe_name=client.pipe_name,
            timeout_seconds=float(client.timeout_seconds),
            bindings=self._bindings,
            exchange_root=str(self._exchange_root),
        )

def _record(state: dict[str, Any], name: str) -> dict[str, Any]:
    record = state.get("record")
    if not state.get("found") or not isinstance(record, dict):
        raise PermissionError(f"Authority {name} record is unavailable")
    return record


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _execution_evidence_digest(stdout_path: Path, stderr_path: Path) -> str:
    evidence = {
        "stdout_sha256": hashlib.sha256(
            stdout_path.read_bytes() if stdout_path.exists() else b""
        ).hexdigest(),
        "stderr_sha256": hashlib.sha256(
            stderr_path.read_bytes() if stderr_path.exists() else b""
        ).hexdigest(),
    }
    return _digest(evidence)


def _strict_provider_output(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("provider structured output is unavailable or malformed") from error
    if not isinstance(value, dict):
        raise PermissionError("provider structured output must be an object")
    return value


def _artifact_from_output(
    plan: AuthorityExecutionPlan,
    output: dict[str, Any],
) -> tuple[str, str, tuple[str, ...]]:
    if set(output) != {"status", "files_changed"} or output.get("status") not in {
        "completed",
        "resolved",
    }:
        raise PermissionError("successful author output schema is invalid")
    files = output.get("files_changed")
    if not isinstance(files, list) or not files or not all(
        isinstance(item, str) and item for item in files
    ):
        raise PermissionError("successful author output has no artifact files")
    relative_files: list[str] = []
    workspace = Path(plan.workspace).resolve()
    for item in files:
        candidate = Path(item)
        path = (
            candidate.resolve()
            if candidate.is_absolute()
            else (workspace / candidate).resolve()
        )
        if not path.is_relative_to(workspace) or not path.is_file():
            raise PermissionError("author artifact is missing or outside the workspace")
        relative = path.relative_to(workspace).as_posix()
        relative_files.append(relative)
    identity = f"file-set:{plan.task_id}:{plan.task_revision}"
    normalized_files = tuple(sorted(relative_files))
    return identity, artifact_digest_from_files(
        identity, workspace, normalized_files
    ), normalized_files


def artifact_digest_from_files(
    identity: str,
    workspace: Path,
    files: tuple[str, ...],
) -> str:
    root = workspace.resolve()
    manifest: list[dict[str, Any]] = []
    for relative in files:
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise PermissionError("bound author artifact is missing or outside workspace")
        content = path.read_bytes()
        manifest.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    manifest.sort(key=lambda item: str(item["path"]))
    return _digest(
        {"identity": identity, "files": manifest}
    )


def _validate_review_output(
    plan: AuthorityExecutionPlan,
    output: dict[str, Any],
) -> tuple[str, str, str]:
    required = {
        "schema_version", "review_id", "review_attempt_id",
        "reviewer_registration", "reviewer_qualification",
        "reviewer_independence_identity", "project_id", "charter_revision",
        "workflow_id", "task_id", "author_attempt_id", "artifact_identity",
        "artifact_digest", "evidence_digest", "review_criteria_version",
        "review_criteria_digest", "review_disposition", "findings",
        "failed_criteria", "required_repairs", "timestamp",
    }
    if set(output) != required:
        raise PermissionError("structured review result fields are invalid")
    disposition = output.get("review_disposition")
    if disposition not in {
        "ACCEPTED", "REPAIR_REQUIRED", "REJECTED", "INDETERMINATE"
    }:
        raise PermissionError("structured review disposition is invalid")
    if (
        output.get("schema_version") != 1
        or output.get("review_attempt_id") != plan.authority_attempt_id
        or output.get("reviewer_registration") != plan.registration_id
        or output.get("reviewer_qualification") != plan.qualification_id
        or output.get("project_id") != plan.project_id
        or output.get("charter_revision") != plan.charter_revision
        or output.get("workflow_id") != plan.workflow_id
        or output.get("task_id") != plan.task_id.split(":review:r", 1)[0]
        or output.get("author_attempt_id") != plan.author_attempt_id
        or output.get("artifact_digest") != plan.artifact_revision_digest
        or output.get("review_criteria_version") != "keeper-review-v1"
        or output.get("review_criteria_digest") != plan.review_criteria_digest
        or not isinstance(output.get("findings"), list)
        or not isinstance(output.get("failed_criteria"), list)
        or not isinstance(output.get("required_repairs"), list)
    ):
        raise PermissionError("structured review result binding is invalid")
    return str(disposition), _digest(output), str(output["author_attempt_id"])
