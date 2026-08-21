from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from keeper.executive.authority_gateway import (
    AuthorityProviderBinding,
    SemanticAuthorityTestGateway,
)
from keeper.executive.enums import FounderApprovalIntent
from keeper.app.storage import KeeperStore
from keeper.executive.charters import CharterService
from keeper.executive.founder_auth import TestFounderAuthenticator
from keeper.executive.founder_capability import (
    TestFounderCapabilityVerifier,
    capability_digest,
    capability_signature_digest,
)
from keeper.executive.intake import ConversationIntake
from keeper.executive.repository import TestExecutiveRepository
from keeper.executive.runtime import ExecutiveRuntime


CAPABILITIES = (
    "requirements",
    "architecture",
    "implementation",
    "testing",
    "security",
    "packaging",
    "acceptance",
)


class PilotAuthorityTransport:
    """Injected Authority-semantic pilot transport; never production authority."""

    def __init__(self) -> None:
        self.registrations: dict[str, dict[str, Any]] = {}
        self.qualifications: dict[str, dict[str, Any]] = {}
        self.attempts: dict[str, dict[str, Any]] = {}
        self.launch_authorizations: dict[str, dict[str, Any]] = {}
        self.execution_count = 0
        for provider_id in ("codex", "reviewer-provider"):
            registration_id = f"pilot-registration-{provider_id}"
            qualification_id = f"pilot-qualification-{provider_id}"
            executable = f"C:/Pilot/{provider_id}.exe"
            executable_digest = self._digest(executable)
            registration_digest = self._digest(
                f"{registration_id}:{executable_digest}"
            )
            self.registrations[registration_id] = {
                "service_state": "QUALIFIED",
                "logical_provider_id": provider_id,
                "canonical_executable_path": executable,
                "executable_sha256": executable_digest,
                "configuration_digest": registration_digest,
                "capability_set": {
                    "author": True,
                    "reviewer": True,
                    "repairer": True,
                    "structured_output": True,
                    "streaming": True,
                    "cancellation": True,
                    "usage_reporting": False,
                    "local_only": False,
                },
                "executive_capability_set": list(CAPABILITIES),
                "role_eligibility": [
                    "builder", "post_repair_reviewer", "repairer", "reviewer"
                ],
                "project_types": ["software"],
                "model_or_service_identity": f"pilot-{provider_id}",
                "independence_classification": provider_id,
                "effort_levels": ["high", "medium"],
                "pricing_authority": {
                    "pricing_identity": f"pilot-pricing:{registration_id}",
                    "pricing_version": "2026-07",
                    "currency": "USD",
                    "estimated_cost": 0.0,
                    "maximum_cost": 0.0,
                    "billing_unit": "included-session",
                    "included_plan": True,
                    "marginally_free": True,
                    "quoted_at": "2026-07-01T00:00:00+00:00",
                    "expires_at": "2099-01-01T00:00:00+00:00",
                    "source": "AUTHORITY_REGISTRATION",
                    "cost_tier": 0,
                },
            }
            self.qualifications[qualification_id] = {
                "service_state": "QUALIFIED",
                "evidence": self._sign(
                    "provider-qualification",
                    {
                        "id": qualification_id,
                        "registration_id": registration_id,
                        "provider_instance_id": f"pilot-session-{provider_id}",
                        "qualification_result": "qualified",
                    },
                ),
            }

    def diagnostics(self) -> dict[str, Any]:
        return {"status": "PILOT_INJECTED_TRANSPORT"}

    def query_state(
        self, kind: str, identifier: str
    ) -> dict[str, Any]:
        values = {
            "registrations": self.registrations,
            "qualifications": self.qualifications,
            "attempts": self.attempts,
            "launch_authorizations": self.launch_authorizations,
        }[kind]
        record = values.get(identifier)
        return {
            "found": record is not None,
            "record": dict(record) if record is not None else None,
        }

    def authorize_project_launch(self, **identity: Any) -> dict[str, Any]:
        if set(identity) != {"founder_capability"}:
            raise PermissionError("signed Founder capability is required")
        value = identity["founder_capability"]
        if not isinstance(value, dict):
            raise PermissionError("Founder capability is malformed")
        capability = TestFounderCapabilityVerifier().verify(value)
        identifier = (
            f"launch-authorization:{capability.project_id}:"
            f"generation:{capability.authorization_generation}"
        )
        digest = capability_digest(capability)
        existing = self.launch_authorizations.get(identifier)
        if existing is not None:
            if (
                existing.get("service_state") == "ACTIVE"
                and existing.get("founder_capability_digest") == digest
            ):
                return {
                    "authorization": {
                        key: item
                        for key, item in existing.items()
                        if key != "service_state"
                    }
                }
            raise PermissionError("pilot launch generation is revoked or stale")
        authorization = self._sign(
            "project-launch-authorization",
            {
                "id": identifier,
                "kind": "project_launch_authorization",
                "schema_version": 2,
                "project_id": capability.project_id,
                "charter_id": capability.charter_id,
                "charter_revision": capability.charter_revision,
                "delegation_id": capability.approval_record_id,
                "founder_approval_event_id": capability.approval_event_id,
                "founder_approval_event_digest": capability.approval_event_digest,
                "founder_approval_digest": capability.approval_digest,
                "founder_authenticated_session_id": (
                    capability.founder_authenticated_session_id
                ),
                "founder_principal_sid": capability.founder_principal_sid,
                "founder_challenge_id": capability.challenge_id,
                "founder_challenge_proof_digest": (
                    capability.challenge_proof_digest
                ),
                "founder_action_digest": capability.action_digest,
                "founder_capability_id": capability.capability_id,
                "founder_capability_digest": digest,
                "founder_capability_signature_digest": (
                    capability_signature_digest(capability)
                ),
                "founder_capability_issuer_id": capability.issuer_id,
                "founder_capability_issuer_key_id": capability.issuer_key_id,
                "authorization_generation": capability.authorization_generation,
                "revocation_epoch": capability.revocation_epoch,
                "authorized_client_sid": "pilot-injected-client",
                "expires_at": capability.expires_at,
                "authorized_at": capability.issued_at,
            },
        )
        self.launch_authorizations[identifier] = {
            **authorization,
            "service_state": "ACTIVE",
        }
        return {"authorization": authorization}

    def revoke_project_launch(
        self, project_id: str, authorization_generation: int
    ) -> dict[str, Any]:
        identifier = (
            f"launch-authorization:{project_id}:"
            f"generation:{authorization_generation}"
        )
        self.launch_authorizations[identifier]["service_state"] = "REVOKED"
        canceled = []
        for attempt_id, attempt in self.attempts.items():
            if (
                attempt.get("launch_authorization_id") == identifier
                and attempt.get("authorization_generation")
                == authorization_generation
                and attempt.get("service_state") == "RESERVED"
            ):
                attempt["service_state"] = "CANCELLED"
                canceled.append(attempt_id)
        return {
            "authorization_id": identifier,
            "revocation_epoch": authorization_generation,
            "canceled_attempt_ids": canceled,
        }

    def reserve_attempt(self, **identity: Any) -> dict[str, Any]:
        authorization = self.launch_authorizations[
            str(identity["launch_authorization_id"])
        ]
        if authorization["service_state"] != "ACTIVE":
            raise PermissionError("pilot launch generation is revoked")
        attempt_id = (
            f"provider-attempt:{identity['keeper_run_id']}:"
            f"{identity['provider_run_id']}"
        )
        if attempt_id in self.attempts:
            raise PermissionError("pilot Authority attempt already exists")
        registration = self.registrations[
            str(identity["registration_id"])
        ]
        attempt = self._sign(
            "provider-launch-authorization",
            {
                "id": attempt_id,
                **identity,
                "workspace": str(
                    Path(str(identity["workspace"])).resolve()
                ),
                "registration_digest": registration[
                    "configuration_digest"
                ],
            },
        )
        self.attempts[attempt_id] = {
            **attempt,
            "service_state": "RESERVED",
        }
        return {"attempt_id": attempt_id, "attempt": attempt}

    def execute_provider(self, attempt_id: str) -> dict[str, Any]:
        attempt = self.attempts[attempt_id]
        authorization = self.launch_authorizations[
            str(attempt["launch_authorization_id"])
        ]
        if authorization["service_state"] != "ACTIVE":
            raise PermissionError("pilot launch generation is revoked")
        if attempt["service_state"] != "RESERVED":
            raise PermissionError("pilot Authority attempt is not reserved")
        self.execution_count += 1
        prompt = json.loads(
            Path(str(attempt["prompt_path"])).read_text(encoding="utf-8")
        )
        stdout_path = Path(str(attempt["stdout_path"]))
        stderr_path = Path(str(attempt["stderr_path"]))
        stderr_path.write_text("", encoding="utf-8")
        if attempt["role"] == "reviewer":
            output = {
                "schema_version": 1,
                "review_id": f"pilot-review:{attempt_id}",
                "review_attempt_id": attempt_id,
                "reviewer_registration": attempt["registration_id"],
                "reviewer_qualification": prompt[
                    "provider_qualification_id"
                ],
                "reviewer_independence_identity": attempt[
                    "provider_instance_id"
                ],
                "project_id": prompt["global_brief"]["project_id"],
                "charter_revision": prompt["global_brief"][
                    "charter_revision"
                ],
                "workflow_id": attempt["keeper_run_id"].split(":")[-1],
                "task_id": prompt["task_guidance"]["task_id"],
                "author_attempt_id": prompt["author_attempt_id"],
                "artifact_identity": (
                    f"file-set:{prompt['task_guidance']['task_id']}"
                ),
                "artifact_digest": prompt["artifact_revision_digest"],
                "evidence_digest": self._digest(f"review:{attempt_id}"),
                "review_criteria_version": "keeper-review-v1",
                "review_criteria_digest": prompt["review_criteria_digest"],
                "review_disposition": "ACCEPTED",
                "findings": [],
                "failed_criteria": [],
                "required_repairs": [],
                "timestamp": datetime.now(UTC).isoformat(),
            }
        else:
            relative = (
                Path(".keeper-artifacts")
                / f"{self._digest(attempt_id)}.json"
            )
            artifact = Path(str(attempt["workspace"])) / relative
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text(
                json.dumps(
                    {"attempt_id": attempt_id, "task_id": attempt["task_id"]},
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            output = {
                "status": "completed",
                "files_changed": [relative.as_posix()],
            }
        stdout_path.write_text(json.dumps(output), encoding="utf-8")
        evidence = {
            "stdout_sha256": hashlib.sha256(
                stdout_path.read_bytes()
            ).hexdigest(),
            "stderr_sha256": hashlib.sha256(
                stderr_path.read_bytes()
            ).hexdigest(),
        }
        evidence_digest = hashlib.sha256(
            json.dumps(
                evidence, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        completion = self._sign(
            "provider-completion",
            {
                "id": f"pilot-completion:{attempt_id}",
                "attempt_id": attempt_id,
                "task_id": attempt["task_id"],
                "stage_id": attempt["stage_id"],
                "role": attempt["role"],
                "registration_id": attempt["registration_id"],
                "provider_instance_id": attempt["provider_instance_id"],
                "normalized_result": "completed",
                "provider_evidence_digest": evidence_digest,
            },
        )
        self.attempts[attempt_id] = {
            **completion,
            "service_state": "COMPLETED",
        }
        return {"attempt_id": attempt_id, "completion": completion}

    def finalize_completion(self, attempt_id: str) -> dict[str, Any]:
        record = dict(self.attempts[attempt_id])
        if record.pop("service_state") != "COMPLETED":
            raise PermissionError("pilot completion is unavailable")
        return {"attempt_id": attempt_id, "completion": record}

    def cancel_attempt(self, attempt_id: str) -> dict[str, Any]:
        self.attempts[attempt_id]["service_state"] = "CANCELLED"
        return {"attempt_id": attempt_id, "state": "CANCELLED"}

    @staticmethod
    def verify(purpose: str, record: object) -> bool:
        return (
            isinstance(record, dict)
            and record.get("_purpose") == purpose
            and record.get("_signature") == "pilot-authority-signature"
        )

    @staticmethod
    def _sign(
        purpose: str, record: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            **record,
            "_purpose": purpose,
            "_signature": "pilot-authority-signature",
        }

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()


def main() -> int:
    with tempfile.TemporaryDirectory(
        prefix="keeper-executive-pilot-"
    ) as directory:
        root = Path(directory)
        store = KeeperStore(root / "keeper.db")
        store.migrate()
        authenticator = TestFounderAuthenticator()
        repository = TestExecutiveRepository(store, authenticator)
        charters = CharterService.for_test(repository, authenticator)
        intake = ConversationIntake.revise(
            ConversationIntake().extract(
                f"I want a small application called Pilot List in {root}. "
                "Use full delegation and no spending."
            ),
            replacements={
                "success_criteria": ("all pilot checks pass",),
                "target_audience": "pilot user",
                "approved_providers": ("codex", "reviewer-provider"),
                "approved_tools": ("filesystem",),
            },
        )
        project = charters.create_project(intake)
        proposed = charters.propose(charters.draft(project, intake))
        challenge = charters.request_approval(proposed)
        confirmation = charters.authenticate(challenge)
        approved, _, _ = charters.confirm_approval(
            challenge.challenge_id,
            confirmation=confirmation,
            intent=FounderApprovalIntent.APPROVE_CHARTER,
        )
        active = charters.activate(approved)
        authority = PilotAuthorityTransport()
        bindings = tuple(
            AuthorityProviderBinding(
                f"pilot-registration-{provider_id}",
                f"pilot-qualification-{provider_id}",
            )
            for provider_id in ("codex", "reviewer-provider")
        )
        runtime = ExecutiveRuntime(
            repository,
            SemanticAuthorityTestGateway(
                authority,
                bindings,
                root / "authority-exchange",
            ),
        )
        for _ in range(20):
            active = runtime.progress(active.project_id)
            if active.state == "COMPLETED":
                break
        print(
            json.dumps(
                {
                    "project_id": active.project_id,
                    "status": active.state,
                    "tasks": len(
                        repository.tasks(active.project_id)
                    ),
                    "evidence": len(
                        repository.memories(active.project_id)
                    ),
                    "authority_attempts_executed": authority.execution_count,
                    "execution_mode": "authority-semantic-injected-transport",
                    "production_authoritative": False,
                },
                sort_keys=True,
            )
        )
        return 0 if active.state == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
