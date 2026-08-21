from __future__ import annotations

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any, cast

import pytest

from tests.keeper.authority_testkit import provider_authority_kwargs

from keeper.authority_service.client import AuthorityServiceClient
from keeper.authority_service.core import (
    AuthorityServiceCore,
    CompletionObservation,
    ProcessObservation,
    QualificationObservation,
    TrustedObserver,
)
from keeper.authority_service.protocol import (
    MAX_MESSAGE_BYTES,
    Operation,
    Request,
    decode_frame,
    encode_frame,
    parse_request,
)
from keeper.authority_service.store import AuthorityStore
from keeper.executive.founder_capability import TestFounderCapabilityVerifier
from tests.keeper.authority_testkit import make_test_founder_capability


def test_schema_two_partial_launch_migration_is_restart_safe(
    tmp_path: Path,
) -> None:
    database = tmp_path / "authority.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE service_meta(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT INTO service_meta(key,value)
                VALUES('schema_version','2');
            CREATE TABLE launch_authorizations(
                id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                generation INTEGER NOT NULL,
                client_sid TEXT NOT NULL,
                payload TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
    store = AuthorityStore(database)
    store.migrate()
    store.migrate()
    with store.connect() as connection:
        schema_version = connection.execute(
            "SELECT value FROM service_meta WHERE key='schema_version'"
        ).fetchone()
        launch_table = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='launch_authorizations'"
        ).fetchone()
    assert schema_version is not None
    assert schema_version["value"] == "6"
    assert launch_table is not None


class _Observer:
    def __init__(self, executable: Path) -> None:
        self.executable = executable.resolve()
        self.evidence_digest = hashlib.sha256(b"evidence").hexdigest()
        self.cancel_entered = Event()
        self.cancel_release = Event()
        self.cancel_release.set()
        self.cancelled_attempts: list[str] = []

    def qualify(
        self, registration: dict[str, Any], challenge: str
    ) -> QualificationObservation:
        timestamp = datetime.now(UTC).isoformat()
        return QualificationObservation(
            "qualified-instance",
            {
                "pid": 4411,
                "launch_nonce": challenge,
                "restricted": True,
                "job_confined": True,
                "integrity_level": "low",
            },
            timestamp,
            timestamp,
            0,
            "controlled-provider 1.2.3",
        )

    def observe_process(
        self, attempt: dict[str, Any], pid: int
    ) -> ProcessObservation:
        content = self.executable.read_bytes()
        return ProcessObservation(
            pid,
            "2026-07-27T00:00:00+00:00",
            str(self.executable),
            hashlib.sha256(content).hexdigest(),
            True,
            "low",
            True,
        )

    def observe_completion(
        self, attempt: dict[str, Any]
    ) -> CompletionObservation:
        return CompletionObservation(
            self.evidence_digest,
            0,
            "completed",
            datetime.now(UTC).isoformat(),
        )


    def cancel_provider(self, attempt_id: str) -> None:
        self.cancelled_attempts.append(attempt_id)
        self.cancel_entered.set()
        if not self.cancel_release.wait(timeout=5):
            raise TimeoutError("test cancellation was not released")


def _service(tmp_path: Path) -> tuple[AuthorityServiceCore, AuthorityServiceClient]:
    executable = tmp_path / "controlled-provider.exe"
    executable.write_bytes(b"safe-test-provider")
    core = AuthorityServiceCore(
        tmp_path / "service",
        observer=cast(TrustedObserver, _Observer(executable)),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    client = AuthorityServiceClient(
        test_transport=lambda request: core.dispatch(request, "S-1-5-21-1000")
    )
    return core, client


def _launch_authority(
    client: AuthorityServiceClient, project_id: str
) -> dict[str, object]:
    authorization = client.authorize_project_launch(
        founder_capability=make_test_founder_capability(
            project_id, charter_id="charter-1"
        )
    )["authorization"]
    return {
        "launch_authorization_id": authorization["id"],
        "authorization_generation": 1,
        "delegation_id": authorization["delegation_id"],
        "founder_approval_event_id": authorization[
            "founder_approval_event_id"
        ],
        "founder_approval_event_digest": authorization[
            "founder_approval_event_digest"
        ],
        "founder_authenticated_session_id": authorization[
            "founder_authenticated_session_id"
        ],
        "founder_principal_sid": authorization["founder_principal_sid"],
        "authorization_expires_at": authorization["expires_at"],
        "project_id": project_id,
        "charter_id": "charter-1",
        "charter_revision": 1,
        "task_revision": 1,
    }


def _authorize_generation(
    client: AuthorityServiceClient,
    project_id: str,
    generation: int,
    approval_suffix: str,
) -> dict[str, Any]:
    response = client.authorize_project_launch(
        founder_capability=make_test_founder_capability(
            project_id, generation, approval_suffix
        )
    )
    return cast(dict[str, Any], response["authorization"])

def test_project_launch_authorization_verification_is_exact_and_fail_closed(
    tmp_path: Path,
) -> None:
    core, client = _service(tmp_path)
    authorization = _authorize_generation(
        client, "verification-project", 1, "verification"
    )

    assert client.verify("project-launch-authorization", authorization) is True

    altered = dict(authorization)
    altered["project_id"] = "other-project"
    assert client.verify("project-launch-authorization", altered) is False
    assert client.verify("provider-launch-authorization", authorization) is False
    assert client.verify("project-launch-authorization", {"malformed": True}) is False

    with pytest.raises((PermissionError, ValueError), match="unsupported"):
        client.verify("project-launch-authorization-v2", authorization)

    replay = Request.create(
        Operation.VERIFY_EVIDENCE,
        {
            "purpose": "project-launch-authorization",
            "record": authorization,
        },
    )
    assert core.dispatch(replay, "S-1-5-21-1000")["valid"] is True
    with pytest.raises(PermissionError, match="replay"):
        core.dispatch(replay, "S-1-5-21-1000")



def test_existing_signed_verification_purposes_remain_exact(
    tmp_path: Path,
) -> None:
    core, client = _service(tmp_path)
    purposes = (
        "provider-registration",
        "provider-qualification-start",
        "provider-qualification",
        "provider-launch-authorization",
        "provider-input-binding",
        "provider-launch-claim",
        "provider-start",
        "provider-completion",
        "executive-restore-reconciliation",
        "executive-restore-reconciliation-fence",
        "executive-restore-fence-confirmation",
        "executive-restore-fence-outcome",
        "authority-provenance-report",
    )
    for purpose in purposes:
        record = core.keys.sign(purpose, {"id": f"test:{purpose}"})
        assert client.verify(purpose, record) is True
        assert client.verify(
            purpose, {**record, "id": f"altered:{purpose}"}
        ) is False


def test_service_constructs_qualification_and_completion_records(
    tmp_path: Path,
) -> None:
    core, client = _service(tmp_path)
    executable = tmp_path / "controlled-provider.exe"
    registered = client.register_provider("codex", executable, **provider_authority_kwargs())
    registration_id = str(registered["registration_id"])

    qualified = client.qualify_provider(registration_id)
    registration = qualified["registration"]
    qualification = qualified["qualification"]
    assert registration["registration_lifecycle"] == "QUALIFIED"
    assert core.keys.verify("provider-qualification", qualification)

    reserved = client.reserve_attempt(
        **_launch_authority(client, "project-1"),
        registration_id=registration_id,
        keeper_run_id="keeper-run-1",
        task_id="task-1",
        stage_id="author_execution",
        role="builder",
        attempt_number=1,
        provider_run_id="provider-run-1",
        provider_instance_id="instance-1",
        evidence_path=str((tmp_path / "evidence" / "run.json").resolve()),
        prompt_path=str((tmp_path / "evidence" / "prompt.md").resolve()),
        stdout_path=str((tmp_path / "evidence" / "stdout.log").resolve()),
        stderr_path=str((tmp_path / "evidence" / "stderr.log").resolve()),
        workspace=str((tmp_path / "workspace").resolve()),
        timeout_seconds=30,
        reasoning_level="medium",
        environment={"PATH": "test"},
    )
    attempt_id = str(reserved["attempt_id"])
    assert core.keys.verify(
        "provider-launch-authorization", reserved["attempt"]
    )
    started = client.record_provider_start(attempt_id, 4411)
    assert started["attempt"]["restricted_token"] is True
    finalized = client.finalize_completion(attempt_id)
    assert finalized["completion"]["terminal_disposition"] == "COMPLETED"
    assert core.keys.verify("provider-completion", finalized["completion"])


def test_cancel_claim_precedes_side_effect_and_blocks_stale_resume(
    tmp_path: Path,
) -> None:
    core, client = _service(tmp_path)
    executable = tmp_path / "controlled-provider.exe"
    registration_id = str(
        client.register_provider("codex", executable, **provider_authority_kwargs())["registration_id"]
    )
    client.qualify_provider(registration_id)
    reserved = client.reserve_attempt(
        **_launch_authority(client, "cancel-race-project"),
        registration_id=registration_id,
        keeper_run_id="cancel-race-run",
        task_id="cancel-race-task",
        stage_id="author_execution",
        role="builder",
        attempt_number=1,
        provider_run_id="cancel-race-provider-run",
        provider_instance_id="instance",
        evidence_path=str((tmp_path / "evidence" / "run.json").resolve()),
        prompt_path=str((tmp_path / "evidence" / "prompt.md").resolve()),
        stdout_path=str((tmp_path / "evidence" / "stdout.log").resolve()),
        stderr_path=str((tmp_path / "evidence" / "stderr.log").resolve()),
        workspace=str((tmp_path / "workspace").resolve()),
        timeout_seconds=30,
        reasoning_level="medium",
        environment={},
    )
    attempt_id = str(reserved["attempt_id"])
    client.record_provider_start(attempt_id, 6611)
    core.dispatch(
        Request.create(
            Operation.PAUSE_ATTEMPT,
            {"attempt_id": attempt_id},
        ),
        "S-1-5-21-1000",
    )
    observer = cast(_Observer, core.observer)
    observer.cancel_release.clear()
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(client.cancel_attempt, attempt_id)
        assert observer.cancel_entered.wait(timeout=5)
        try:
            claimed = core.store.get("attempts", attempt_id)
            assert claimed is not None
            assert claimed["service_state"] == "CANCELLATION_CLAIMED"
            assert str(claimed["cancellation_intent_id"]).startswith(
                "cancellation-intent:"
            )
            with pytest.raises(PermissionError, match="transition was rejected"):
                core.dispatch(
                    Request.create(
                        Operation.RESUME_ATTEMPT,
                        {"attempt_id": attempt_id},
                    ),
                    "S-1-5-21-1000",
                )
        finally:
            observer.cancel_release.set()
        result = future.result(timeout=5)
    assert result["state"] == "CANCELLED"
    assert observer.cancelled_attempts == [attempt_id]
    final = core.store.get("attempts", attempt_id)
    assert final is not None
    assert final["service_state"] == "CANCELLED"


def test_service_rejects_arbitrary_signing_and_duplicate_launch(
    tmp_path: Path,
) -> None:
    core, client = _service(tmp_path)
    executable = tmp_path / "controlled-provider.exe"
    registered = client.register_provider("codex", executable, **provider_authority_kwargs())
    registration_id = str(registered["registration_id"])
    client.qualify_provider(registration_id)
    reserved = client.reserve_attempt(
        **_launch_authority(client, "project-2"),
        registration_id=registration_id,
        keeper_run_id="keeper-run-2",
        task_id="task-2",
        stage_id="author_execution",
        role="builder",
        attempt_number=1,
        provider_run_id="provider-run-2",
        provider_instance_id="instance-2",
        evidence_path=str((tmp_path / "evidence" / "run.json").resolve()),
        prompt_path=str((tmp_path / "evidence" / "prompt.md").resolve()),
        stdout_path=str((tmp_path / "evidence" / "stdout.log").resolve()),
        stderr_path=str((tmp_path / "evidence" / "stderr.log").resolve()),
        workspace=str((tmp_path / "workspace").resolve()),
        timeout_seconds=30,
        reasoning_level="medium",
        environment={"PATH": "test"},
    )
    attempt_id = str(reserved["attempt_id"])
    client.record_provider_start(attempt_id, 5511)
    with pytest.raises(PermissionError, match="not reserved"):
        client.record_provider_start(attempt_id, 5512)
    with pytest.raises(PermissionError, match="service-internal"):
        core.dispatch(
            Request.create(
                Operation.FINALIZE_QUALIFICATION,
                {"record": {"fabricated": True}},
            ),
            "S-1-5-21-1000",
        )


def test_revoked_launch_generation_invalidates_reserved_attempt(
    tmp_path: Path,
) -> None:
    core, client = _service(tmp_path)
    executable = tmp_path / "controlled-provider.exe"
    registration_id = str(
        client.register_provider("codex", executable, **provider_authority_kwargs())["registration_id"]
    )
    client.qualify_provider(registration_id)
    launch = _launch_authority(client, "revoked-project")
    reserved = client.reserve_attempt(
        **launch,
        registration_id=registration_id,
        keeper_run_id="revoked-run",
        task_id="revoked-task",
        stage_id="author_execution",
        role="builder",
        attempt_number=1,
        provider_run_id="revoked-provider-run",
        provider_instance_id="instance",
        evidence_path=str((tmp_path / "evidence" / "run.json").resolve()),
        prompt_path=str((tmp_path / "evidence" / "prompt.md").resolve()),
        stdout_path=str((tmp_path / "evidence" / "stdout.log").resolve()),
        stderr_path=str((tmp_path / "evidence" / "stderr.log").resolve()),
        workspace=str((tmp_path / "workspace").resolve()),
        timeout_seconds=30,
        reasoning_level="medium",
        environment={},
    )
    attempt_id = str(reserved["attempt_id"])
    revoked = client.revoke_project_launch("revoked-project", 1)
    assert attempt_id in revoked["canceled_attempt_ids"]
    with pytest.raises(PermissionError, match="not reserved"):
        client.execute_provider(attempt_id)
    attempt = core.store.get("attempts", attempt_id)
    assert attempt is not None
    assert attempt["service_state"] == "CANCELLED"
    generation_two = _authorize_generation(
        client, "revoked-project", 2, "new-authenticated-event"
    )
    assert generation_two["authorization_generation"] == 2
    first = core.store.get(
        "launch_authorizations",
        "launch-authorization:revoked-project:generation:1",
    )
    second = core.store.get(
        "launch_authorizations",
        "launch-authorization:revoked-project:generation:2",
    )
    assert first is not None and first["service_state"] == "REVOKED"
    assert second is not None and second["service_state"] == "ACTIVE"
    assert core.store.get("attempts", attempt_id)["service_state"] == "CANCELLED"  # type: ignore[index]


def test_higher_generation_requires_new_authenticated_approval_and_restarts(
    tmp_path: Path,
) -> None:
    core, client = _service(tmp_path)
    first = _authorize_generation(client, "generation-project", 1, "one")
    client.revoke_project_launch("generation-project", 1)
    with pytest.raises(PermissionError, match="revoked|stale"):
        _authorize_generation(client, "generation-project", 1, "one")
    with pytest.raises(PermissionError, match="capability"):
        client.authorize_project_launch(
            project_id="generation-project",
            founder_approval_event_id=first["founder_approval_event_id"],
        )
    second = _authorize_generation(client, "generation-project", 2, "two")
    assert second["revocation_epoch"] == 1

    restarted = AuthorityServiceCore(
        core.root,
        observer=core.observer,
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    first_after_restart = restarted.store.get(
        "launch_authorizations",
        "launch-authorization:generation-project:generation:1",
    )
    second_after_restart = restarted.store.get(
        "launch_authorizations",
        "launch-authorization:generation-project:generation:2",
    )
    assert first_after_restart is not None
    assert first_after_restart["service_state"] == "REVOKED"
    assert second_after_restart is not None
    assert second_after_restart["service_state"] == "ACTIVE"


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("issuer_id", "untrusted-founder-issuer"),
        ("issuer_key_id", "unknown-founder-key"),
        ("project_id", "copied-to-another-project"),
        ("charter_id", "copied-to-another-charter"),
        ("action_digest", "0" * 64),
        ("founder_principal_sid", "S-1-5-21-FABRICATED"),
        ("founder_authenticated_session_id", "fabricated-session"),
        ("approval_event_id", "fabricated-event"),
        ("approval_record_id", "fabricated-approval"),
        ("challenge_id", "fabricated-challenge"),
        ("signature", "ZmFicmljYXRlZA"),
    ],
)
def test_modified_or_copied_founder_capability_is_rejected(
    tmp_path: Path, mutation: str, value: object
) -> None:
    _core, client = _service(tmp_path)
    capability = make_test_founder_capability("capability-tamper")
    capability[mutation] = value
    with pytest.raises(PermissionError, match="capability"):
        client.authorize_project_launch(founder_capability=capability)


def test_unsigned_malformed_and_expired_capabilities_are_rejected(
    tmp_path: Path,
) -> None:
    _core, client = _service(tmp_path)
    unsigned = make_test_founder_capability("unsigned-capability")
    unsigned.pop("signature")
    with pytest.raises(PermissionError, match="capability"):
        client.authorize_project_launch(founder_capability=unsigned)
    with pytest.raises(PermissionError, match="capability"):
        client.authorize_project_launch(founder_capability={"schema_version": 1})

    expired = make_test_founder_capability(
        "expired-capability",
        claim_overrides={
            "issued_at": "2000-01-01T00:00:00+00:00",
            "expires_at": "2000-01-01T00:01:00+00:00",
        },
    )
    with pytest.raises(PermissionError, match="stale"):
        client.authorize_project_launch(founder_capability=expired)


def test_valid_capability_is_consumed_once_with_idempotent_retry(
    tmp_path: Path,
) -> None:
    _core, client = _service(tmp_path)
    capability = make_test_founder_capability("idempotent-capability")
    first = client.authorize_project_launch(founder_capability=capability)
    retry = client.authorize_project_launch(founder_capability=capability)
    assert retry == first
    client.revoke_project_launch("idempotent-capability", 1)
    with pytest.raises(PermissionError, match="revoked|stale"):
        client.authorize_project_launch(founder_capability=capability)


@pytest.mark.parametrize(
    "reused_field",
    [
        "capability_id",
        "approval_record_id",
        "approval_event_id",
        "founder_authenticated_session_id",
        "challenge_id",
        "approval_digest",
    ],
)
def test_project_wide_founder_identity_replay_is_permanently_rejected(
    tmp_path: Path, reused_field: str
) -> None:
    _core, client = _service(tmp_path)
    project_id = f"global-replay-{reused_field}"
    first_capability = make_test_founder_capability(project_id, 1, "one")
    client.authorize_project_launch(founder_capability=first_capability)
    client.revoke_project_launch(project_id, 1)
    client.authorize_project_launch(
        founder_capability=make_test_founder_capability(project_id, 2, "two")
    )
    client.revoke_project_launch(project_id, 2)
    with pytest.raises(PermissionError, match="already used"):
        client.authorize_project_launch(
            founder_capability=make_test_founder_capability(
                project_id,
                3,
                "three",
                claim_overrides={
                    reused_field: first_capability[reused_field]
                },
            )
        )


def test_confirmation_proof_digest_cannot_be_rebound_by_issuer() -> None:
    first = make_test_founder_capability("proof-rebinding", 1, "one")
    with pytest.raises(PermissionError, match="fresh confirmation"):
        make_test_founder_capability(
            "proof-rebinding",
            2,
            "two",
            claim_overrides={
                "challenge_proof_digest": first["challenge_proof_digest"]
            },
        )


def test_confirmation_proof_digest_is_durably_unique(
    tmp_path: Path,
) -> None:
    core, client = _service(tmp_path)
    project_id = "durable-proof-uniqueness"
    first = make_test_founder_capability(project_id, 1, "one")
    client.authorize_project_launch(founder_capability=first)
    client.revoke_project_launch(project_id, 1)
    client.authorize_project_launch(
        founder_capability=make_test_founder_capability(
            project_id, 2, "two"
        )
    )
    client.revoke_project_launch(project_id, 2)
    identifier = f"launch-authorization:{project_id}:generation:3"
    with pytest.raises(PermissionError, match="already used"):
        core.store.create_launch_authorization(
            identifier,
            3,
            "S-1-5-21-1000",
            {"project_id": project_id, "revocation_epoch": 2},
            {
                "capability_id": "capability:proof:three",
                "project_id": project_id,
                "approval_record_id": "approval:proof:three",
                "approval_event_id": "event:proof:three",
                "founder_session_id": "session:proof:three",
                "challenge_id": "challenge:proof:three",
                "approval_digest": "approval-digest:proof:three",
                "challenge_proof_digest": first[
                    "challenge_proof_digest"
                ],
                "capability_digest": "capability-digest:proof:three",
                "signature_digest": "signature-digest:proof:three",
                "generation": 3,
                "authorization_id": identifier,
            },
        )
    assert core.store.get("launch_authorizations", identifier) is None


def test_generation_one_capability_cannot_authorize_generation_three(
    tmp_path: Path,
) -> None:
    _core, client = _service(tmp_path)
    project_id = "generation-one-at-three"
    approval_a = make_test_founder_capability(project_id, 1, "approval-a")
    client.authorize_project_launch(founder_capability=approval_a)
    client.revoke_project_launch(project_id, 1)
    client.authorize_project_launch(
        founder_capability=make_test_founder_capability(
            project_id, 2, "approval-b"
        )
    )
    client.revoke_project_launch(project_id, 2)
    with pytest.raises(PermissionError, match="revoked|stale"):
        client.authorize_project_launch(founder_capability=approval_a)


def test_concurrent_higher_generation_has_one_canonical_winner(
    tmp_path: Path,
) -> None:
    _core, client = _service(tmp_path)
    _authorize_generation(client, "race-project", 1, "one")
    client.revoke_project_launch("race-project", 1)

    def create(suffix: str) -> str:
        try:
            _authorize_generation(client, "race-project", 2, suffix)
        except PermissionError:
            return "rejected"
        return "created"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(create, ("candidate-a", "candidate-b")))
    assert outcomes == ["created", "rejected"]


def test_request_replay_and_stale_timestamp_fail_closed(tmp_path: Path) -> None:
    core, _client = _service(tmp_path)
    request = Request.create(Operation.DIAGNOSTICS, {})
    core.dispatch(request, "S-1-5-21-1000")
    with pytest.raises(PermissionError, match="replay"):
        core.dispatch(request, "S-1-5-21-1000")

    value = request.to_dict()
    value["request_id"] = "1" * 32
    value["operation_id"] = "2" * 32
    value["nonce"] = "3" * 64
    value["issued_at"] = "2020-01-01T00:00:00+00:00"
    with pytest.raises(ValueError, match="stale"):
        parse_request(value)


def test_protocol_rejects_unknown_oversized_and_malformed_messages() -> None:
    request = Request.create(Operation.DIAGNOSTICS, {}).to_dict()
    request["unexpected"] = True
    with pytest.raises(ValueError, match="fields"):
        parse_request(request)

    with pytest.raises(ValueError, match="size"):
        encode_frame({"value": "x" * MAX_MESSAGE_BYTES})

    raw = b"\x05\x00\x00\x00nope!"
    offset = 0

    def read(length: int) -> bytes:
        nonlocal offset
        value = raw[offset : offset + length]
        offset += len(value)
        return value

    with pytest.raises(ValueError, match="encoding"):
        decode_frame(read)


def test_key_rotation_keeps_historical_verification(tmp_path: Path) -> None:
    core, client = _service(tmp_path)
    before = core.keys.sign("provider-start", {"id": "old"})
    rotated = client.rotate_key("ROTATE_KEEPER_AUTHORITY_KEY")
    after = core.keys.sign("provider-start", {"id": "new"})

    assert rotated["key_version"] == 2
    assert core.keys.verify("provider-start", before)
    assert core.keys.verify("provider-start", after)
    assert json.dumps(before) != json.dumps(after)


def test_missing_historical_key_fails_closed_without_recreation(
    tmp_path: Path,
) -> None:
    core, client = _service(tmp_path)
    before = core.keys.sign("provider-start", {"id": "old"})
    client.rotate_key("ROTATE_KEEPER_AUTHORITY_KEY")
    key_path = (
        core.keys.root
        / "key-v1"
        / "authority"
        / "authority-key-v1.bin"
    )
    core.keys.clear_cached_keys()
    key_path.unlink()

    assert core.keys.verify("provider-start", before) is False
    assert key_path.exists() is False
