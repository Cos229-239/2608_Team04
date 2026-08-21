from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, cast

import pytest

from keeper.authority_service.core import (
    SERVICE_VERSION,
    AuthorityServiceCore,
    QualificationObservation,
    TrustedObserver,
)
from keeper.authority_service.client import AuthorityServiceClient
from keeper.executive.founder_capability import (
    FounderAuthorizationCapability,
    TestFounderCapabilityVerifier,
)
from keeper.provider_host.protocol import structured_digest
from tests.keeper.authority_testkit import make_test_founder_capability
from tests.keeper.test_codex_subscription_provider_contract import (
    _CodexObserver,
    _codex_service,
    _registration,
)


SID = "S-1-5-21-1000"


class _QualificationRetryCoordinator:
    def status(self) -> dict[str, object]:
        return {
            "state": "ENROLLED",
            "enrollment_id": "test-enrollment",
            "enrollment_generation": 1,
        }

    def pending_launch_reconciliations(self) -> list[dict[str, object]]:
        return []

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
        assert capability.protected_action == action
        assert capability.action_digest == action_digest
        assert capability.authorization_generation == generation
        return capability


class _FailureThenSuccessQualificationObserver(_CodexObserver):
    def __init__(self, *, fail_retry: bool = False) -> None:
        super().__init__(qualification_complete=False)
        self.fail_retry = fail_retry

    def qualify(
        self, registration: dict[str, Any], challenge: str
    ) -> QualificationObservation:
        result = super().qualify(registration, challenge)
        if self.qualify_calls == 1 and not self.fail_retry:
            self.qualification_complete = True
        return result


def _retry_capability(
    registration_id: str,
    qualification_id: str,
    failure_digest: str,
) -> dict[str, Any]:
    action_binding = {
        "action": "AUTHORIZE_PROVIDER_QUALIFICATION_RETRY",
        "qualification_failure_digest": failure_digest,
        "qualification_id": qualification_id,
        "registration_id": registration_id,
        "required_authority_version": SERVICE_VERSION,
        "required_host_version": SERVICE_VERSION,
        "retry_generation": 2,
    }
    return make_test_founder_capability(
        "keeper-system:provider-host",
        generation=2,
        suffix=(
            "qualification-retry-"
            + hashlib.sha256(qualification_id.encode()).hexdigest()[:12]
        ),
        charter_id="keeper-system:provider-host-enrollment",
        claim_overrides={
            "charter_revision": 1,
            "authorization_kind": "PROVIDER_HOST_ENROLLMENT",
            "protected_action": "AUTHORIZE_PROVIDER_QUALIFICATION_RETRY",
            "action_digest": structured_digest(action_binding),
            "founder_principal_sid": SID,
        },
    )


def _failed_qualification(
    tmp_path: Path,
    *,
    fail_retry: bool = False,
) -> tuple[
    AuthorityServiceCore,
    Any,
    _FailureThenSuccessQualificationObserver,
    Path,
    str,
    dict[str, Any],
]:
    observer = _FailureThenSuccessQualificationObserver(fail_retry=fail_retry)
    core, client = _codex_service(tmp_path, observer)
    core.provider_host_enrollment = cast(Any, _QualificationRetryCoordinator())
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"fixture")
    registration = _registration(executable)
    registration_id = str(registration["trusted_registration_id"])
    core.store.insert(
        "registrations",
        registration_id,
        "REGISTERED_UNQUALIFIED",
        registration,
    )
    failed = client.qualify_provider(registration_id, executable)
    assert failed["qualification"]["qualification_result"] == "failed"
    assert observer.qualify_calls == 1
    return core, client, observer, executable, registration_id, failed


def test_founder_authorized_qualification_retry_runs_exactly_once(
    tmp_path: Path,
) -> None:
    core, client, observer, executable, registration_id, failed = (
        _failed_qualification(tmp_path)
    )
    qualification_id = str(failed["qualification"]["id"])
    failure_digest = str(failed["qualification"]["evidence_digest"])
    capability = _retry_capability(
        registration_id, qualification_id, failure_digest
    )

    authorization = client.authorize_provider_qualification_retry(
        registration_id=registration_id,
        qualification_id=qualification_id,
        qualification_failure_digest=failure_digest,
        required_authority_version=SERVICE_VERSION,
        required_host_version=SERVICE_VERSION,
        founder_capability=capability,
    )
    retry_id = str(authorization["retry_qualification_id"])
    diagnostics = client.diagnostics()["provider_host"]
    assert diagnostics["qualification_retry_authorized_ids"] == [retry_id]

    # The ordinary qualification endpoint remains terminal/idempotent and cannot
    # accidentally consume the explicit retry authorization.
    with pytest.raises(
        PermissionError, match="requires exact recovery first"
    ):
        client.qualify_provider(registration_id, executable)
    assert observer.qualify_calls == 1

    completed = client.retry_provider_qualification(
        registration_id, retry_id, executable
    )
    assert completed["registration"]["registration_lifecycle"] == "QUALIFIED"
    assert completed["qualification"]["qualification_result"] == "qualified"
    assert observer.qualify_calls == 2

    repeated = client.retry_provider_qualification(
        registration_id, retry_id, executable
    )
    assert repeated == completed
    assert observer.qualify_calls == 2

    restarted = AuthorityServiceCore(
        core.root,
        observer=cast(TrustedObserver, observer),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    restarted_client = AuthorityServiceClient(
        test_transport=lambda request: restarted.dispatch(request, SID)
    )
    recovered_after_restart = restarted_client.retry_provider_qualification(
        registration_id, retry_id, executable
    )
    assert recovered_after_restart == completed
    assert observer.qualify_calls == 2
    assert core.store.get("qualifications", qualification_id) is not None
    retry_record = core.store.get("qualifications", retry_id)
    assert retry_record is not None
    assert retry_record["service_state"] == "QUALIFIED"
    assert retry_record["retry_authorization"]["qualification_id"] == (
        qualification_id
    )


def test_failed_retry_cannot_be_authorized_again(tmp_path: Path) -> None:
    core, client, observer, executable, registration_id, failed = (
        _failed_qualification(tmp_path, fail_retry=True)
    )
    qualification_id = str(failed["qualification"]["id"])
    failure_digest = str(failed["qualification"]["evidence_digest"])
    authorization = client.authorize_provider_qualification_retry(
        registration_id=registration_id,
        qualification_id=qualification_id,
        qualification_failure_digest=failure_digest,
        required_authority_version=SERVICE_VERSION,
        required_host_version=SERVICE_VERSION,
        founder_capability=_retry_capability(
            registration_id, qualification_id, failure_digest
        ),
    )
    retry_id = str(authorization["retry_qualification_id"])
    retried = client.retry_provider_qualification(
        registration_id, retry_id, executable
    )
    assert retried["qualification"]["qualification_result"] == "failed"
    assert observer.qualify_calls == 2

    retry_failure_digest = str(retried["qualification"]["evidence_digest"])
    with pytest.raises(
        PermissionError,
        match="no exact terminal failure",
    ):
        client.authorize_provider_qualification_retry(
            registration_id=registration_id,
            qualification_id=retry_id,
            qualification_failure_digest=retry_failure_digest,
            required_authority_version=SERVICE_VERSION,
            required_host_version=SERVICE_VERSION,
            founder_capability=_retry_capability(
                registration_id, retry_id, retry_failure_digest
            ),
        )
    assert observer.qualify_calls == 2


def test_retry_recovers_after_crash_immediately_after_durable_begin(
    tmp_path: Path,
) -> None:
    core, client, observer, executable, registration_id, failed = (
        _failed_qualification(tmp_path)
    )
    qualification_id = str(failed["qualification"]["id"])
    failure_digest = str(failed["qualification"]["evidence_digest"])
    authorization = client.authorize_provider_qualification_retry(
        registration_id=registration_id,
        qualification_id=qualification_id,
        qualification_failure_digest=failure_digest,
        required_authority_version=SERVICE_VERSION,
        required_host_version=SERVICE_VERSION,
        founder_capability=_retry_capability(
            registration_id, qualification_id, failure_digest
        ),
    )
    retry_id = str(authorization["retry_qualification_id"])

    begin = core.store.begin_provider_qualification_retry

    def crash_after_begin(*args: Any, **kwargs: Any) -> None:
        begin(*args, **kwargs)
        raise SystemExit("synthetic crash after durable retry begin")

    core.store.begin_provider_qualification_retry = crash_after_begin  # type: ignore[method-assign]
    with pytest.raises(SystemExit, match="synthetic crash"):
        client.retry_provider_qualification(registration_id, retry_id, executable)
    assert observer.qualify_calls == 1

    persisted_registration = core.store.get("registrations", registration_id)
    persisted_retry = core.store.get("qualifications", retry_id)
    assert persisted_registration is not None
    assert persisted_registration["service_state"] == "QUALIFICATION_STARTED"
    assert persisted_registration["registration_lifecycle"] == "QUALIFICATION_FAILED"
    assert persisted_registration["qualification_evidence_id"] == qualification_id
    assert persisted_registration["qualification_evidence_digest"] == failure_digest
    assert persisted_retry is not None
    assert persisted_retry["service_state"] == "EXECUTION_STARTED"

    restarted = AuthorityServiceCore(
        core.root,
        observer=cast(TrustedObserver, observer),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    restarted_client = AuthorityServiceClient(
        test_transport=lambda request: restarted.dispatch(request, SID)
    )
    completed = restarted_client.retry_provider_qualification(
        registration_id, retry_id, executable
    )
    assert completed["registration"]["registration_lifecycle"] == "QUALIFIED"
    assert completed["qualification"]["qualification_result"] == "qualified"
    assert observer.qualify_calls == 2
