from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Any, cast

import pytest

from keeper.authority_service import core as authority_core
from keeper.authority_service.client import AuthorityServiceClient
from keeper.authority_service.codex_registration import (
    recover_registration_failure_once,
    register_and_qualify_once,
    registration_declaration,
)
from keeper.authority_service.core import (
    SERVICE_VERSION,
    AuthorityServiceCore,
    TrustedObserver,
)
from keeper.executive.founder_capability import (
    FounderAuthorizationCapability,
    TestFounderCapabilityVerifier,
)
from keeper.provider_host.protocol import structured_digest
from keeper.provider_host.protocol import validate_setup_result
from keeper.providers.adapters import canonical_provider_registration_digest
from tests.keeper.authority_testkit import make_test_founder_capability
from tests.keeper.test_codex_subscription_provider_contract import _registration


SID = "S-1-5-21-1000"
ACCOUNT_IDENTITY_DIGEST = "c" * 64
ACCOUNT_DISCOVERY_DIGEST = "e" * 64
ACCOUNT_PLAN_TYPE = "pro"


class _DispositionCoordinator:
    def status(self) -> dict[str, object]:
        return {
            "state": "ENROLLED_OFFLINE",
            "enrollment_id": "test-enrollment",
            "enrollment_generation": 1,
        }

    def pending_launch_reconciliations(self) -> list[dict[str, object]]:
        return []

    def revoke(
        self, payload: dict[str, Any], client_sid: str
    ) -> dict[str, object]:
        assert payload == {"checkpoint": "version-bound-host-replacement"}
        assert client_sid == SID
        return {"state": "REVOKED"}

    def verify_founder_action(
        self,
        value: object,
        client_sid: str,
        *,
        action: str,
        action_digest: str,
        generation: int,
    ) -> FounderAuthorizationCapability:
        assert client_sid == SID
        capability = TestFounderCapabilityVerifier().verify(value)
        assert capability.authorization_kind == "PROVIDER_HOST_ENROLLMENT"
        assert capability.protected_action == action
        assert capability.action_digest == action_digest
        assert capability.authorization_generation == generation
        return capability


class _FailureThenSuccessObserver:
    def __init__(
        self,
        *,
        fail_every_time: bool = False,
        account_identity_digest: str = ACCOUNT_IDENTITY_DIGEST,
        plan_type: str = "plus",
    ) -> None:
        self.calls = 0
        self.fail_every_time = fail_every_time
        self.recovery_calls = 0
        self.last_failure: dict[str, Any] | None = None
        self.account_identity_digest = account_identity_digest
        self.plan_type = plan_type

    def register_provider(
        self,
        provider_id: str,
        executable: Path,
        client_sid: str,
        **arguments: Any,
    ) -> dict[str, Any]:
        assert provider_id == "codex"
        assert client_sid == SID
        if arguments.get("expected_account_identity_digest") is not None:
            assert (
                arguments["expected_account_identity_digest"]
                == ACCOUNT_IDENTITY_DIGEST
            )
        self.calls += 1
        if self.calls == 1 or self.fail_every_time:
            self.last_failure = {
                    "failure_stage": "ACCOUNT_PROBE_VALIDATE",
                    "failure_code": "PERMISSION_REJECTED",
                    "process_result": {
                        "detail_status": "DETAIL_UNAVAILABLE"
                    },
                    "setup_result_digest": hashlib.sha256(
                        f"result:{self.calls}".encode()
                    ).hexdigest(),
                    "setup_envelope_digest": hashlib.sha256(
                        f"envelope:{self.calls}".encode()
                    ).hexdigest(),
            }
            return {"registration_terminal_failure": dict(self.last_failure)}
        registration = _registration(executable)
        account_binding = cast(
            dict[str, Any], registration["subscription_account_binding"]
        )
        account_binding["account_identity_digest"] = self.account_identity_digest
        account_binding["plan_type"] = self.plan_type
        registration["trusted_registration_id"] = arguments[
            "planned_registration_id"
        ]
        registration["configuration_digest"] = (
            canonical_provider_registration_digest(registration)
        )
        return registration

    def recover_provider_registration_failure(
        self, registration_id: str, setup_id: str, challenge: str
    ) -> dict[str, Any]:
        assert registration_id.startswith("keeper-provider:codex:v1:")
        assert setup_id.startswith("provider-registration-probe:")
        assert len(challenge) == 64
        self.recovery_calls += 1
        assert self.last_failure is not None
        return dict(self.last_failure)

    def validate_registered_executable(
        self, registration: dict[str, Any], client_executable_handle: int
    ) -> None:
        assert registration
        assert client_executable_handle > 0


def _declaration(executable: Path) -> dict[str, Any]:
    content = executable.read_bytes()
    return registration_declaration(
        expected_executable_sha256=hashlib.sha256(content).hexdigest(),
        expected_executable_size=len(content),
        expected_version="codex-cli 0.146.0",
        keeper_launch_budget=20,
    )


def _capability(
    registration_id: str,
    failure_digest: str,
    disposition: str,
    attempt_generation: int,
) -> dict[str, Any]:
    authorization_generation = attempt_generation + 1
    binding = {
        "action": "DISPOSE_PROVIDER_REGISTRATION_FAILURE",
        "attempt_generation": attempt_generation,
        "authorization_generation": authorization_generation,
        "disposition": disposition,
        "failure_digest": failure_digest,
        "registration_id": registration_id,
    }
    return make_test_founder_capability(
        "keeper-system:provider-host",
        generation=authorization_generation,
        suffix=(
            "registration-"
            f"{hashlib.sha256(registration_id.encode('utf-8')).hexdigest()[:12]}-"
            f"{disposition}-{attempt_generation}"
        ),
        charter_id="keeper-system:provider-host-enrollment",
        claim_overrides={
            "charter_revision": 1,
            "authorization_kind": "PROVIDER_HOST_ENROLLMENT",
            "protected_action": "DISPOSE_PROVIDER_REGISTRATION_FAILURE",
            "action_digest": structured_digest(binding),
            "founder_principal_sid": SID,
        },
    )


def _replacement_request(
    record: dict[str, Any],
    registration_id: str,
    *,
    suffix: str = "exhausted-replacement",
    required_version: str = SERVICE_VERSION,
) -> dict[str, Any]:
    failure_digest = str(record["failure_digest"])
    request_identity_digest = str(record["request_identity_digest"])
    request_binding = cast(dict[str, Any], record["request_binding"])
    successor_id = "keeper-provider:codex:v1:" + hashlib.sha256(
        (
            "codex-subscription-registration-successor-v1\0"
            + registration_id
            + "\0"
            + failure_digest
            + "\0"
            + request_identity_digest
        ).encode("utf-8")
    ).hexdigest()[:32]
    effect_accounting = {
        "model_request_count": 0,
        "provider_execution_count": 0,
        "qualification_count": 0,
        "registration_success_count": 0,
        "usage_reservation_count": 0,
    }
    binding = {
        "action": "NEW_REGISTRATION_AFTER_EXHAUSTION",
        "account_identity_discovery_digest": ACCOUNT_DISCOVERY_DIGEST,
        "expected_account_identity_digest": ACCOUNT_IDENTITY_DIGEST,
        "expected_account_plan_type": ACCOUNT_PLAN_TYPE,
        "authorized_client_sid": SID,
        "effect_accounting": effect_accounting,
        "exhausted_attempt_generation": 2,
        "expected_executable_sha256": request_binding[
            "expected_executable_sha256"
        ],
        "expected_executable_size": request_binding["expected_executable_size"],
        "predecessor_failure_digest": failure_digest,
        "predecessor_registration_id": registration_id,
        "request_identity_digest": request_identity_digest,
        "required_authority_version": required_version,
        "required_host_version": required_version,
        "successor_registration_id": successor_id,
    }
    capability = make_test_founder_capability(
        "keeper-system:provider-host",
        generation=3,
        suffix=suffix,
        charter_id="keeper-system:provider-host-enrollment",
        claim_overrides={
            "charter_revision": 1,
            "authorization_kind": "PROVIDER_HOST_ENROLLMENT",
            "protected_action": "NEW_REGISTRATION_AFTER_EXHAUSTION",
            "action_digest": structured_digest(binding),
            "founder_principal_sid": SID,
        },
    )
    return {
        "registration_id": registration_id,
        "failure_digest": failure_digest,
        "request_identity_digest": request_identity_digest,
        "account_identity_discovery_digest": ACCOUNT_DISCOVERY_DIGEST,
        "expected_account_identity_digest": ACCOUNT_IDENTITY_DIGEST,
        "expected_account_plan_type": ACCOUNT_PLAN_TYPE,
        "expected_executable_sha256": str(
            request_binding["expected_executable_sha256"]
        ),
        "expected_executable_size": int(
            request_binding["expected_executable_size"]
        ),
        "required_authority_version": required_version,
        "required_host_version": required_version,
        "founder_capability": capability,
        "successor_id": successor_id,
    }


def _service(
    tmp_path: Path, observer: _FailureThenSuccessObserver
) -> tuple[AuthorityServiceCore, AuthorityServiceClient, Path]:
    executable = (tmp_path / "codex.exe").resolve()
    executable.write_bytes(b"official-codex-fixture")
    core = AuthorityServiceCore(
        tmp_path / "authority",
        observer=cast(TrustedObserver, observer),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    core.provider_host_enrollment = cast(Any, _DispositionCoordinator())
    client = AuthorityServiceClient(
        test_transport=lambda request: core.dispatch(request, SID)
    )
    return core, client, executable


def test_failed_terminal_result_is_idempotent_and_never_reprobes(
    tmp_path: Path,
) -> None:
    observer = _FailureThenSuccessObserver()
    core, client, executable = _service(tmp_path, observer)

    first = client.register_provider("codex", executable, **_declaration(executable))
    repeated = client.register_provider(
        "codex", executable, **_declaration(executable)
    )

    assert repeated == first
    assert observer.calls == 1
    restarted_observer = _FailureThenSuccessObserver()
    restarted_core = AuthorityServiceCore(
        tmp_path / "authority",
        observer=cast(TrustedObserver, restarted_observer),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    restarted_core.provider_host_enrollment = cast(
        Any, _DispositionCoordinator()
    )
    restarted_client = AuthorityServiceClient(
        test_transport=lambda request: restarted_core.dispatch(request, SID)
    )
    after_restart = restarted_client.register_provider(
        "codex", executable, **_declaration(executable)
    )
    assert after_restart == first
    assert restarted_observer.calls == 0
    assert first["state"] == "REGISTRATION_FAILED"
    failure = first["registration_failed"]
    assert failure["failure_stage"] == "ACCOUNT_PROBE_VALIDATE"
    assert failure["failure_code"] == "PERMISSION_REJECTED"
    assert failure["process_result"] == {
        "detail_status": "DETAIL_UNAVAILABLE"
    }
    assert failure["effect_accounting"] == {
        "registration_persisted": False,
        "qualification_started": False,
        "model_request_count": 0,
        "provider_binding_created": False,
        "usage_reservation_count": 0,
    }
    stored = core.store.get("registrations", first["registration_id"])
    assert stored is not None
    assert stored["service_state"] == "REGISTRATION_FAILED"
    assert core.store.list_records("qualifications") == []
    status = client.diagnostics()["provider_host"]
    assert status["registration_failure_disposition_pending_count"] == 1
    assert status["provider_state"] == (
        "REGISTRATION_FAILURE_DISPOSITION_REQUIRED"
    )


def test_lost_authority_commit_recovers_terminal_failure_without_new_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SimulatedPowerLoss(BaseException):
        pass

    observer = _FailureThenSuccessObserver()
    core, client, executable = _service(tmp_path, observer)
    original_transition = core.store.transition

    def lose_failure_commit(
        table: str,
        identifier: str,
        expected_state: str,
        state: str,
        payload: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        if (
            table == "registrations"
            and expected_state == "REGISTRATION_STARTED"
            and state == "REGISTRATION_FAILED"
        ):
            raise SimulatedPowerLoss("lost after Host terminal result")
        original_transition(
            table,
            identifier,
            expected_state,
            state,
            payload,
            **kwargs,
        )

    monkeypatch.setattr(core.store, "transition", lose_failure_commit)
    with pytest.raises(SimulatedPowerLoss, match="Host terminal"):
        client.register_provider("codex", executable, **_declaration(executable))
    claim = core.store.list_records("registrations")[0]
    assert claim["service_state"] == "REGISTRATION_STARTED"
    assert observer.calls == 1

    monkeypatch.setattr(core.store, "transition", original_transition)
    recovered = client.recover_provider_registration_failure(
        claim["start"]["registration_id"]
    )
    repeated = client.recover_provider_registration_failure(
        claim["start"]["registration_id"]
    )
    assert repeated == recovered
    assert recovered["state"] == "REGISTRATION_FAILED"
    assert observer.calls == 1
    assert observer.recovery_calls == 1
    assert core.store.list_records("qualifications") == []


def test_founder_exact_retry_uses_new_setup_once_and_then_registers(
    tmp_path: Path,
) -> None:
    observer = _FailureThenSuccessObserver()
    core, client, executable = _service(tmp_path, observer)
    failed = client.register_provider("codex", executable, **_declaration(executable))
    failure = cast(dict[str, Any], failed["registration_failed"])
    failure_digest = structured_digest(failure)

    wrong_digest = "0" * 64
    with pytest.raises(PermissionError, match="binding differs"):
        client.dispose_provider_registration_failure(
            registration_id=failed["registration_id"],
            failure_digest=wrong_digest,
            disposition="RETRY_ONCE",
            attempt_generation=1,
            founder_capability=_capability(
                failed["registration_id"], wrong_digest, "RETRY_ONCE", 1
            ),
        )
    assert core.store.get("registrations", failed["registration_id"])[
        "service_state"
    ] == "REGISTRATION_FAILED"

    capability = _capability(
        failed["registration_id"], failure_digest, "RETRY_ONCE", 1
    )
    disposition = client.dispose_provider_registration_failure(
        registration_id=failed["registration_id"],
        failure_digest=failure_digest,
        disposition="RETRY_ONCE",
        attempt_generation=1,
        founder_capability=capability,
    )

    assert disposition["state"] == "REGISTRATION_RETRY_AUTHORIZED"
    retry_claim = core.store.get("registrations", failed["registration_id"])
    assert retry_claim is not None
    assert retry_claim["service_state"] == "REGISTRATION_RETRY_AUTHORIZED"
    assert retry_claim["attempt_generation"] == 2
    assert retry_claim["start"]["attempt_generation"] == 2
    assert retry_claim["start"]["setup_id"] != failure["setup_id"]
    assert core._pending_provider_operation_claims()["registrations"] == []
    with pytest.raises(PermissionError, match="recovery must complete"):
        core._require_no_pending_provider_operation_claims()
    retry_status = client.diagnostics()["provider_host"]
    assert retry_status["registration_retry_authorized_count"] == 1
    assert retry_status["registration_retry_authorized_ids"] == [
        failed["registration_id"]
    ]
    assert retry_status["provider_state"] == "REGISTRATION_RETRY_AUTHORIZED"
    assert retry_status["founder_action_required"] == (
        "RESUME_EXACT_PROVIDER_REGISTRATION"
    )
    assert core._revoke_provider_host_enrollment(
        {"checkpoint": "version-bound-host-replacement"}, SID
    ) == {"state": "REVOKED"}
    unrelated_executable = (tmp_path / "other-codex.exe").resolve()
    unrelated_executable.write_bytes(b"different-reviewed-codex-fixture")
    with pytest.raises(PermissionError, match="exact recovery first"):
        client.register_provider(
            "codex",
            unrelated_executable,
            **_declaration(unrelated_executable),
        )
    assert observer.calls == 1
    repeated_disposition = client.dispose_provider_registration_failure(
        registration_id=failed["registration_id"],
        failure_digest=failure_digest,
        disposition="RETRY_ONCE",
        attempt_generation=1,
        founder_capability=capability,
    )
    assert repeated_disposition == disposition

    completed = client.register_provider(
        "codex", executable, **_declaration(executable)
    )
    assert completed["registration_id"] == failed["registration_id"]
    assert observer.calls == 2
    assert core.store.get("registrations", failed["registration_id"])[
        "service_state"
    ] == "REGISTERED_UNQUALIFIED"
    assert core.store.list_records("qualifications") == []


def test_second_failed_attempt_cannot_be_retried_again(tmp_path: Path) -> None:
    observer = _FailureThenSuccessObserver(fail_every_time=True)
    core, client, executable = _service(tmp_path, observer)
    first = client.register_provider("codex", executable, **_declaration(executable))
    first_failure = cast(dict[str, Any], first["registration_failed"])
    first_digest = structured_digest(first_failure)
    client.dispose_provider_registration_failure(
        registration_id=first["registration_id"],
        failure_digest=first_digest,
        disposition="RETRY_ONCE",
        attempt_generation=1,
        founder_capability=_capability(
            first["registration_id"], first_digest, "RETRY_ONCE", 1
        ),
    )
    second = client.register_provider(
        "codex", executable, **_declaration(executable)
    )
    second_failure = cast(dict[str, Any], second["registration_failed"])
    second_digest = structured_digest(second_failure)

    with pytest.raises(PermissionError, match="already consumed"):
        client.dispose_provider_registration_failure(
            registration_id=first["registration_id"],
            failure_digest=second_digest,
            disposition="RETRY_ONCE",
            attempt_generation=2,
            founder_capability=_capability(
                first["registration_id"], second_digest, "RETRY_ONCE", 2
            ),
        )
    assert observer.calls == 2
    assert core.store.get("registrations", first["registration_id"])[
        "service_state"
    ] == "REGISTRATION_FAILED"


def _fail_registration_twice(
    client: AuthorityServiceClient,
    executable: Path,
) -> tuple[str, dict[str, Any]]:
    first = client.register_provider("codex", executable, **_declaration(executable))
    first_failure = cast(dict[str, Any], first["registration_failed"])
    first_digest = structured_digest(first_failure)
    client.dispose_provider_registration_failure(
        registration_id=first["registration_id"],
        failure_digest=first_digest,
        disposition="RETRY_ONCE",
        attempt_generation=1,
        founder_capability=_capability(
            first["registration_id"], first_digest, "RETRY_ONCE", 1
        ),
    )
    second = client.register_provider(
        "codex", executable, **_declaration(executable)
    )
    return str(second["registration_id"]), cast(
        dict[str, Any], second["registration_failed"]
    )


def test_exhausted_replacement_is_atomic_idempotent_and_preserves_lineage(
    tmp_path: Path,
) -> None:
    observer = _FailureThenSuccessObserver(
        fail_every_time=True, plan_type="pro"
    )
    core, client, executable = _service(tmp_path, observer)
    predecessor_id, second_failure = _fail_registration_twice(client, executable)
    predecessor = core.store.get("registrations", predecessor_id)
    assert predecessor is not None
    request = _replacement_request(predecessor, predecessor_id)
    successor_id = str(request.pop("successor_id"))

    authorized = client.authorize_exhausted_provider_registration(**request)
    assert authorized["state"] == "REGISTRATION_REPLACEMENT_AUTHORIZED"
    assert authorized["successor_registration_id"] == successor_id
    assert observer.calls == 2
    exhausted = core.store.get("registrations", predecessor_id)
    successor = core.store.get("registrations", successor_id)
    assert exhausted is not None
    assert successor is not None
    assert exhausted["service_state"] == "REGISTRATION_EXHAUSTED"
    assert successor["service_state"] == "REGISTRATION_REPLACEMENT_AUTHORIZED"
    assert exhausted["failure"] == second_failure
    assert successor["predecessor_registration_id"] == predecessor_id
    assert successor["registration_lineage"] == authorized["registration_lineage"]

    assert client.authorize_exhausted_provider_registration(**request) == authorized
    changed_replay = dict(request)
    changed_replay["expected_executable_sha256"] = "0" * 64
    with pytest.raises(PermissionError, match="replay binding differs"):
        client.authorize_exhausted_provider_registration(**changed_replay)
    changed_account = dict(request)
    changed_account["expected_account_identity_digest"] = "d" * 64
    with pytest.raises(PermissionError, match="replay binding differs"):
        client.authorize_exhausted_provider_registration(**changed_account)
    changed_plan = dict(request)
    changed_plan["expected_account_plan_type"] = "plus"
    with pytest.raises(PermissionError, match="replay binding differs"):
        client.authorize_exhausted_provider_registration(**changed_plan)
    changed_discovery = dict(request)
    changed_discovery["account_identity_discovery_digest"] = "f" * 64
    with pytest.raises(PermissionError, match="replay binding differs"):
        client.authorize_exhausted_provider_registration(**changed_discovery)
    recovered = client.recover_exhausted_provider_registration(predecessor_id)
    assert recovered == authorized
    status = client.diagnostics()["provider_host"]
    assert status["registration_replacement_authorized_count"] == 1
    assert status["registration_replacement_authorized_ids"] == [successor_id]
    with pytest.raises(PermissionError, match="recovery must complete"):
        core._require_no_pending_provider_operation_claims()

    observer.fail_every_time = False
    completed = client.register_provider(
        "codex", executable, **_declaration(executable)
    )
    assert completed["registration_id"] == successor_id
    stored = core.store.get("registrations", successor_id)
    assert stored is not None
    assert stored["service_state"] == "REGISTERED_UNQUALIFIED"
    assert stored["subscription_account_binding"]["plan_type"] == "pro"
    assert (
        stored["registration_lineage"]["expected_account_plan_type"]
        == "pro"
    )
    assert stored["registration_lineage"] == authorized["registration_lineage"]
    assert observer.calls == 3
    assert core.store.get("registrations", predecessor_id)["service_state"] == (
        "REGISTRATION_EXHAUSTED"
    )
    with pytest.raises(PermissionError, match="evidence is permanent"):
        core._revoke_registration({"registration_id": predecessor_id}, SID)
    assert core.store.list_records("qualifications") == []


def test_started_successor_lineage_survives_release_upgrade_for_exact_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prior_release = "1.7.43"
    monkeypatch.setattr(authority_core, "SERVICE_VERSION", prior_release)
    observer = _FailureThenSuccessObserver(
        fail_every_time=True,
        plan_type=ACCOUNT_PLAN_TYPE,
    )
    core, client, executable = _service(tmp_path, observer)
    predecessor_id, _ = _fail_registration_twice(client, executable)
    predecessor = core.store.get("registrations", predecessor_id)
    assert predecessor is not None
    request = _replacement_request(
        predecessor,
        predecessor_id,
        required_version=prior_release,
    )
    successor_id = str(request.pop("successor_id"))
    client.authorize_exhausted_provider_registration(**request)
    failed = client.register_provider(
        "codex", executable, **_declaration(executable)
    )
    assert failed["registration_id"] == successor_id
    assert failed["state"] == "REGISTRATION_FAILED"
    failure = cast(dict[str, Any], failed["registration_failed"])
    failure_digest = structured_digest(failure)

    monkeypatch.setattr(authority_core, "SERVICE_VERSION", SERVICE_VERSION)
    recovered = client.recover_exhausted_provider_registration(predecessor_id)
    assert recovered["state"] == "REGISTRATION_FAILED"
    assert recovered["successor_registration_id"] == successor_id
    capability = _capability(successor_id, failure_digest, "RETRY_ONCE", 1)
    disposition = client.dispose_provider_registration_failure(
        registration_id=successor_id,
        failure_digest=failure_digest,
        disposition="RETRY_ONCE",
        attempt_generation=1,
        founder_capability=capability,
    )
    assert disposition["state"] == "REGISTRATION_RETRY_AUTHORIZED"
    assert (
        client.dispose_provider_registration_failure(
            registration_id=successor_id,
            failure_digest=failure_digest,
            disposition="RETRY_ONCE",
            attempt_generation=1,
            founder_capability=capability,
        )
        == disposition
    )

    observer.fail_every_time = False
    completed = client.register_provider(
        "codex", executable, **_declaration(executable)
    )
    assert completed["registration_id"] == successor_id
    stored = core.store.get("registrations", successor_id)
    assert stored is not None
    assert stored["service_state"] == "REGISTERED_UNQUALIFIED"
    assert stored["registration_lineage"]["required_authority_version"] == (
        prior_release
    )
    assert stored["registration_lineage"]["required_host_version"] == prior_release
    assert observer.calls == 4


def test_unstarted_successor_authorization_cannot_cross_release_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prior_release = "1.7.43"
    monkeypatch.setattr(authority_core, "SERVICE_VERSION", prior_release)
    observer = _FailureThenSuccessObserver(fail_every_time=True)
    core, client, executable = _service(tmp_path, observer)
    predecessor_id, _ = _fail_registration_twice(client, executable)
    predecessor = core.store.get("registrations", predecessor_id)
    assert predecessor is not None
    request = _replacement_request(
        predecessor,
        predecessor_id,
        required_version=prior_release,
    )
    client.authorize_exhausted_provider_registration(
        **{key: value for key, value in request.items() if key != "successor_id"}
    )

    monkeypatch.setattr(authority_core, "SERVICE_VERSION", SERVICE_VERSION)
    with pytest.raises(
        PermissionError,
        match="replacement release differs",
    ):
        client.recover_exhausted_provider_registration(predecessor_id)
    with pytest.raises(
        PermissionError,
        match="replacement lineage is malformed",
    ):
        client.register_provider("codex", executable, **_declaration(executable))
    assert observer.calls == 2


def test_exhausted_replacement_lost_response_recovers_after_restart(
    tmp_path: Path,
) -> None:
    observer = _FailureThenSuccessObserver(fail_every_time=True)
    core, client, executable = _service(tmp_path, observer)
    predecessor_id, _ = _fail_registration_twice(client, executable)
    predecessor = core.store.get("registrations", predecessor_id)
    assert predecessor is not None
    request = _replacement_request(predecessor, predecessor_id)
    successor_id = str(request.pop("successor_id"))

    def lost_response(authority_request: Any) -> dict[str, Any]:
        core.dispatch(authority_request, SID)
        raise OSError("synthetic response loss after commit")

    lossy = AuthorityServiceClient(test_transport=lost_response)
    with pytest.raises(OSError, match="response loss"):
        lossy.authorize_exhausted_provider_registration(**request)
    assert core.store.get("registrations", successor_id)["service_state"] == (
        "REGISTRATION_REPLACEMENT_AUTHORIZED"
    )

    restarted = AuthorityServiceCore(
        core.root,
        observer=cast(TrustedObserver, observer),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    restarted.provider_host_enrollment = cast(Any, _DispositionCoordinator())
    restarted_client = AuthorityServiceClient(
        test_transport=lambda authority_request: restarted.dispatch(
            authority_request, SID
        )
    )
    recovered = restarted_client.recover_exhausted_provider_registration(
        predecessor_id
    )
    assert recovered["successor_registration_id"] == successor_id
    assert recovered["state"] == "REGISTRATION_REPLACEMENT_AUTHORIZED"
    assert len(restarted.store.list_records("registrations")) == 2
    assert observer.calls == 2


def test_exhausted_replacement_rejects_account_switch_before_persistence(
    tmp_path: Path,
) -> None:
    observer = _FailureThenSuccessObserver(fail_every_time=True)
    core, client, executable = _service(tmp_path, observer)
    predecessor_id, _ = _fail_registration_twice(client, executable)
    predecessor = core.store.get("registrations", predecessor_id)
    assert predecessor is not None
    request = _replacement_request(predecessor, predecessor_id)
    successor_id = str(request.pop("successor_id"))
    client.authorize_exhausted_provider_registration(**request)

    observer.fail_every_time = False
    observer.account_identity_digest = "d" * 64
    with pytest.raises(PermissionError, match="account identity differs"):
        client.register_provider("codex", executable, **_declaration(executable))
    successor = core.store.get("registrations", successor_id)
    assert successor is not None
    assert successor["service_state"] == "REGISTRATION_STARTED"
    assert core.store.list_records("qualifications") == []
    assert core.store.list_records("attempts") == []


def test_exhausted_replacement_rejects_mismatch_concurrency_and_replacement_chain(
    tmp_path: Path,
) -> None:
    observer = _FailureThenSuccessObserver(fail_every_time=True)
    core, client, executable = _service(tmp_path, observer)
    predecessor_id, _ = _fail_registration_twice(client, executable)
    predecessor = core.store.get("registrations", predecessor_id)
    assert predecessor is not None
    first = _replacement_request(predecessor, predecessor_id, suffix="first")
    second = _replacement_request(predecessor, predecessor_id, suffix="second")
    successor_id = str(first.pop("successor_id"))
    second.pop("successor_id")

    mismatched = dict(first)
    mismatched["expected_executable_sha256"] = "0" * 64
    with pytest.raises(PermissionError, match="binding differs"):
        client.authorize_exhausted_provider_registration(**mismatched)
    assert len(core.store.list_records("registrations")) == 1

    client.authorize_exhausted_provider_registration(**first)
    with pytest.raises(PermissionError, match="capability differs"):
        client.authorize_exhausted_provider_registration(**second)
    assert len(core.store.list_records("registrations")) == 2

    first_successor_failure = client.register_provider(
        "codex", executable, **_declaration(executable)
    )
    first_failure = cast(
        dict[str, Any], first_successor_failure["registration_failed"]
    )
    first_failure_digest = structured_digest(first_failure)
    client.dispose_provider_registration_failure(
        registration_id=successor_id,
        failure_digest=first_failure_digest,
        disposition="RETRY_ONCE",
        attempt_generation=1,
        founder_capability=_capability(
            successor_id, first_failure_digest, "RETRY_ONCE", 1
        ),
    )
    second_successor_failure = client.register_provider(
        "codex", executable, **_declaration(executable)
    )
    assert second_successor_failure["state"] == "REGISTRATION_FAILED"
    successor = core.store.get("registrations", successor_id)
    assert successor is not None
    chained = _replacement_request(successor, successor_id, suffix="forbidden-chain")
    chained.pop("successor_id")
    with pytest.raises(PermissionError, match="evidence binding differs"):
        client.authorize_exhausted_provider_registration(**chained)
    assert len(core.store.list_records("registrations")) == 2
    assert observer.calls == 4


def test_exhausted_replacement_concurrent_capabilities_create_one_successor(
    tmp_path: Path,
) -> None:
    observer = _FailureThenSuccessObserver(fail_every_time=True)
    core, client, executable = _service(tmp_path, observer)
    predecessor_id, _ = _fail_registration_twice(client, executable)
    predecessor = core.store.get("registrations", predecessor_id)
    assert predecessor is not None
    requests = [
        _replacement_request(predecessor, predecessor_id, suffix="race-a"),
        _replacement_request(predecessor, predecessor_id, suffix="race-b"),
    ]
    successor_id = str(requests[0].pop("successor_id"))
    assert str(requests[1].pop("successor_id")) == successor_id
    barrier = threading.Barrier(3)
    results: list[dict[str, Any]] = []
    errors: list[BaseException] = []
    result_lock = threading.Lock()

    def authorize(request: dict[str, Any]) -> None:
        barrier.wait()
        try:
            result = client.authorize_exhausted_provider_registration(**request)
            with result_lock:
                results.append(result)
        except BaseException as exc:  # noqa: BLE001 - retain exact race outcome
            with result_lock:
                errors.append(exc)

    workers = [
        threading.Thread(target=authorize, args=(request,)) for request in requests
    ]
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join(timeout=10)
        assert not worker.is_alive()

    assert len(results) == 1
    assert results[0]["successor_registration_id"] == successor_id
    assert len(errors) == 1
    assert isinstance(errors[0], PermissionError)
    assert "capability differs" in str(errors[0])
    records = core.store.list_records("registrations")
    assert len(records) == 2
    assert core.store.get("registrations", predecessor_id)["service_state"] == (
        "REGISTRATION_EXHAUSTED"
    )
    assert core.store.get("registrations", successor_id)["service_state"] == (
        "REGISTRATION_REPLACEMENT_AUTHORIZED"
    )
    assert observer.calls == 2


def test_abandon_clears_work_fence_without_deleting_evidence(tmp_path: Path) -> None:
    observer = _FailureThenSuccessObserver()
    core, client, executable = _service(tmp_path, observer)
    failed = client.register_provider("codex", executable, **_declaration(executable))
    failure = cast(dict[str, Any], failed["registration_failed"])
    failure_digest = structured_digest(failure)
    with pytest.raises(PermissionError, match="recovery must complete"):
        core._require_no_pending_provider_operation_claims()

    result = client.dispose_provider_registration_failure(
        registration_id=failed["registration_id"],
        failure_digest=failure_digest,
        disposition="ABANDON",
        attempt_generation=1,
        founder_capability=_capability(
            failed["registration_id"], failure_digest, "ABANDON", 1
        ),
    )

    assert result["state"] == "REGISTRATION_ABANDONED"
    stored = core.store.get("registrations", failed["registration_id"])
    assert stored is not None
    assert stored["service_state"] == "REGISTRATION_ABANDONED"
    assert stored["failure"] == failure
    assert core._pending_provider_operation_claims()["registrations"] == []
    core._require_no_pending_provider_operation_claims()


def test_register_once_persists_failure_and_never_qualifies(tmp_path: Path) -> None:
    class FailedClient:
        qualified = False

        def register_provider(self, *args: object, **kwargs: object) -> dict[str, Any]:
            return {
                "registration_id": "keeper-provider:codex:v1:failed",
                "registration_failed": {"failure_code": "PERMISSION_REJECTED"},
            }

        def qualify_provider(self, *args: object, **kwargs: object) -> dict[str, Any]:
            self.qualified = True
            raise AssertionError("qualification must not run")

    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    client = FailedClient()
    with pytest.raises(PermissionError, match="requires Founder disposition"):
        register_and_qualify_once(
            cast(Any, client), executable, tmp_path / "output", {}
        )
    assert client.qualified is False
    assert (tmp_path / "output" / "registration-response.json").is_file()
    assert not (tmp_path / "output" / "qualification-response.json").exists()


def test_recovery_cli_helper_persists_response_before_identifier_use(
    tmp_path: Path,
) -> None:
    registration_id = "keeper-provider:codex:v1:" + "a" * 32
    failure = {
        "registration_id": registration_id,
        "attempt_generation": 1,
        "failure_code": "PERMISSION_REJECTED",
    }

    class RecoveryClient:
        def recover_provider_registration_failure(
            self, requested: str
        ) -> dict[str, Any]:
            assert requested == registration_id
            return {
                "registration_id": registration_id,
                "registration_failed": failure,
                "state": "REGISTRATION_FAILED",
            }

    result = recover_registration_failure_once(
        cast(Any, RecoveryClient()), registration_id, tmp_path / "recovery"
    )
    assert result["registration_id"] == registration_id
    assert result["failure_digest"] == structured_digest(failure)
    assert (tmp_path / "recovery" / "registration-failure-response.json").is_file()


@pytest.mark.parametrize(
    "mutation",
    [
        {"stdout": "secret"},
        {"stdout_sha256": "not-a-digest"},
        {"stdout_bytes": -1},
        {"restricted": False},
        {"started": "true"},
    ],
)
def test_signed_setup_process_result_schema_rejects_raw_or_malformed_detail(
    mutation: dict[str, object],
) -> None:
    process_result: dict[str, object] = {
        "operation": "ACCOUNT_PROBE",
        "exit_code": 5,
        "timed_out": False,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stdout_bytes": 0,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_bytes": 0,
        "restricted": True,
        "job_confined": True,
        "started": True,
        "resumed": True,
    }
    process_result.update(mutation)
    setup_result = {
        "authority_id": "authority",
        "challenge": "challenge",
        "environment_digest": hashlib.sha256(b"environment").hexdigest(),
        "host_id": "host",
        "observation": {"process_result": process_result},
        "operation": "REGISTER_PROBE",
        "provider_registration_id": "registration",
        "recorded_at": "2026-08-14T12:00:00+00:00",
        "setup_envelope_digest": hashlib.sha256(b"envelope").hexdigest(),
        "setup_id": "setup",
    }

    with pytest.raises(PermissionError, match="Provider Host"):
        validate_setup_result(setup_result)
