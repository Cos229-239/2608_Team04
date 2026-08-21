from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, cast

import pytest

from tests.keeper.authority_testkit import provider_authority_kwargs

from keeper.authority_service.client import TestAuthorityServiceClient
from keeper.authority_service.protocol import Operation
from keeper.authority_service.core import (
    AuthorityServiceCore,
    ExecutionObservation,
    ProcessObservation,
    TrustedObserver,
)
from keeper.evidence_input import (
    finalize_provider_input,
    review_input_declaration,
    structured_digest,
    validate_provider_input,
)
from keeper.executive.founder_capability import (
    TestFounderCapabilityIssuer,
    TestFounderCapabilityVerifier,
)
from keeper.pass_b.launch_authority import (
    ExecutiveAuthorityLaunchGate,
    TestLaunchAuthority,
)
from keeper.pass_b.models import (
    AttemptRecord,
    DeliveredInputRecord,
    EvidenceBundleRecord,
    EvidenceReferenceRecord,
    ReviewRecord,
)
from keeper.pass_b.orchestration import evidence_content_digest
from keeper.pass_b.pilot import _PilotAuthorityObserver
from tests.keeper.pass_b.test_completion_repair_matrix import _launch_ready
from tests.keeper.pass_b.test_post_release_maintenance import (
    _CaptureAdapter,
    _typed_reference_stack,
)
from tests.keeper.test_authority_service_core import _launch_authority


def _completed_typed_review(
    tmp_path: Path,
    *,
    reference_count: int = 2,
) -> tuple[
    Any,
    EvidenceBundleRecord,
    Any,
    tuple[EvidenceReferenceRecord, ...],
    EvidenceBundleRecord,
    DeliveredInputRecord,
]:
    service, provider, _, _, artifact, _ = _typed_reference_stack(tmp_path)
    first = service.repository.list(EvidenceReferenceRecord)[0]
    reviewer = service.repository.assignment_launch_binding(
        first.assignment_id
    )[2]
    references = [first]
    for _ in range(reference_count - 1):
        references.append(
            service.create_local_evidence_reference(
                reviewer.assignment_id,
                artifact,
                source_evidence_bundle_id=first.source_evidence_bundle_id,
            )
        )
    capture = _CaptureAdapter(provider.provider_id)
    service.adapters[provider.provider_id] = capture
    workspace = tmp_path / "reviewer"
    _, authority_id = _launch_ready(
        service, reviewer, workspace, "typed-input-binding"
    )
    reviewer_evidence = service.run_assignment(
        reviewer.assignment_id,
        workspace,
        authority_attempt_id=authority_id,
        global_context={},
        task_context={"objective": "review exact typed input"},
        evidence_reference_ids=tuple(
            item.evidence_reference_id for item in references
        ),
        side_effect_class="READ_ONLY_REVIEW",
    )
    reviewer_evidence = service.validate_evidence(
        reviewer_evidence.evidence_bundle_id, workspace
    )
    attempt = service.repository.get(
        AttemptRecord, reviewer_evidence.attempt_id
    )
    assert attempt.delivered_input_id is not None
    delivered = service.repository.get(
        DeliveredInputRecord, attempt.delivered_input_id
    )
    source_id = first.source_evidence_bundle_id
    assert source_id is not None
    source = service.repository.get(EvidenceBundleRecord, source_id)
    return (
        service,
        source,
        reviewer,
        tuple(references),
        reviewer_evidence,
        delivered,
    )


def _replace_reviewer_declaration(
    service: Any,
    evidence: EvidenceBundleRecord,
    mutate: Callable[[dict[str, Any]], None],
) -> EvidenceBundleRecord:
    artifacts = [copy.deepcopy(item) for item in evidence.artifacts]
    declaration = cast(
        dict[str, Any], artifacts[0]["review_input_declaration"]
    )
    mutate(declaration)
    updated = replace(
        evidence,
        artifacts=tuple(artifacts),
        content_digest=evidence_content_digest(
            project_id=evidence.project_id,
            assignment_id=evidence.assignment_id,
            attempt_id=evidence.attempt_id,
            producer_provider_id=evidence.producer_provider_id,
            producer_session_id=evidence.producer_session_id,
            schema_version=evidence.schema_version,
            artifacts=tuple(artifacts),
            summary=evidence.summary,
        ),
        updated_at=datetime.now(UTC).isoformat(),
        revision=evidence.revision + 1,
    )
    return cast(
        EvidenceBundleRecord,
        service.repository.replace(
            updated, expected_revision=evidence.revision
        ),
    )


def test_exact_delivery_is_durable_and_review_consumes_exact_set(
    tmp_path: Path,
) -> None:
    service, source, reviewer, references, evidence, delivered = (
        _completed_typed_review(tmp_path)
    )
    attempt = service.repository.get(AttemptRecord, evidence.attempt_id)
    assert attempt.delivered_input_digest == delivered.delivered_input_digest
    assert attempt.provider_input_digest == delivered.provider_input_digest
    assert tuple(
        item["reference_id"] for item in delivered.references
    ) == tuple(item.evidence_reference_id for item in references)
    assert delivered.provider_input["reviewer_attempt_id"] == attempt.attempt_id

    review = service.create_review(
        source.evidence_bundle_id,
        reviewer.assignment_id,
        evidence.evidence_bundle_id,
    )
    stored = service.repository.get(ReviewRecord, review.review_id)
    assert stored.delivered_input_id == delivered.delivered_input_id
    assert stored.delivered_input_digest == delivered.delivered_input_digest
    assert stored.consumed_evidence_reference_ids == tuple(
        item.evidence_reference_id for item in references
    )
    assert stored.consumed_evidence_reference_revisions == tuple(
        item.revision + 1 for item in references
    )
    decided, _, _ = service.decide_review(review.review_id)
    assert decided.state == "ACCEPTED"


def test_durable_delivery_rejects_wrong_provider_input_digest(
    tmp_path: Path,
) -> None:
    *_, delivered = _completed_typed_review(tmp_path, reference_count=1)
    with pytest.raises(ValueError, match="provider digest"):
        replace(delivered, provider_input_digest="0" * 64)


@pytest.mark.parametrize(
    "selection",
    (
        lambda refs: (refs[1].evidence_reference_id,),
        lambda refs: (refs[0].evidence_reference_id,),
        lambda refs: (
            refs[0].evidence_reference_id,
            refs[1].evidence_reference_id,
            "fabricated-reference",
        ),
        lambda refs: (
            refs[1].evidence_reference_id,
            refs[0].evidence_reference_id,
        ),
    ),
    ids=("deliver-a-consume-b", "subset", "superset", "reordered"),
)
def test_caller_cannot_substitute_delivered_reference_set(
    tmp_path: Path,
    selection: Callable[
        [tuple[EvidenceReferenceRecord, ...]], tuple[str, ...]
    ],
) -> None:
    service, source, reviewer, references, evidence, _ = (
        _completed_typed_review(tmp_path)
    )
    with pytest.raises(PermissionError, match="differ"):
        service.create_review(
            source.evidence_bundle_id,
            reviewer.assignment_id,
            evidence.evidence_bundle_id,
            evidence_reference_ids=selection(references),
        )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda value: value.pop("delivered_input_digest"),
        lambda value: value.__setitem__(
            "delivered_input_digest", "f" * 64
        ),
        lambda value: value.__setitem__("manifest_digest", "e" * 64),
        lambda value: value.__setitem__(
            "review_disposition", "REPAIR_REQUIRED"
        ),
        lambda value: value.__setitem__("reviewer_attempt_id", "other"),
        lambda value: value.__setitem__("reviewer_assignment_id", "other"),
        lambda value: value.__setitem__("producer_assignment_id", "other"),
        lambda value: value.__setitem__("producer_attempt_id", "other"),
        lambda value: value.__setitem__("workflow_id", "other"),
        lambda value: value.__setitem__("work_item_id", "other"),
        lambda value: value.__setitem__(
            "references", value["references"][:1]
        ),
        lambda value: value.__setitem__(
            "references", list(reversed(value["references"]))
        ),
        lambda value: value["references"][0].__setitem__(
            "reference_revision",
            int(value["references"][0]["reference_revision"]) + 1,
        ),
        lambda value: value["references"][0].__setitem__(
            "sha256", "d" * 64
        ),
        lambda value: value["references"][0].__setitem__(
            "source_evidence_bundle_id", "other"
        ),
    ),
    ids=(
        "missing-input-digest",
        "wrong-input-digest",
        "wrong-manifest",
        "wrong-review-disposition",
        "wrong-reviewer-attempt",
        "wrong-reviewer-assignment",
        "wrong-producer-assignment",
        "wrong-producer-attempt",
        "wrong-workflow",
        "wrong-work-item",
        "omitted-reference",
        "reordered-reference",
        "stale-reference-revision",
        "wrong-reference-digest",
        "wrong-source-bundle",
    ),
)
def test_untrusted_reviewer_declaration_must_echo_exact_delivery(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    service, source, reviewer, _, evidence, _ = _completed_typed_review(
        tmp_path
    )
    changed = _replace_reviewer_declaration(service, evidence, mutate)
    with pytest.raises(PermissionError, match="invalid"):
        service.create_review(
            source.evidence_bundle_id,
            reviewer.assignment_id,
            changed.evidence_bundle_id,
        )


def test_reference_revision_change_after_delivery_rejects(
    tmp_path: Path,
) -> None:
    service, source, reviewer, references, evidence, _ = (
        _completed_typed_review(tmp_path)
    )
    reference = references[0]
    service.repository.replace(
        replace(
            reference,
            updated_at=datetime.now(UTC).isoformat(),
            revision=reference.revision + 1,
        ),
        expected_revision=reference.revision,
    )
    with pytest.raises(PermissionError, match="changed"):
        service.create_review(
            source.evidence_bundle_id,
            reviewer.assignment_id,
            evidence.evidence_bundle_id,
        )


def test_consumed_delivery_cannot_be_replayed(tmp_path: Path) -> None:
    service, source, reviewer, _, evidence, _ = _completed_typed_review(
        tmp_path
    )
    service.create_review(
        source.evidence_bundle_id,
        reviewer.assignment_id,
        evidence.evidence_bundle_id,
    )
    with pytest.raises(PermissionError, match="already consumed"):
        service.create_review(
            source.evidence_bundle_id,
            reviewer.assignment_id,
            evidence.evidence_bundle_id,
        )


def test_superseded_charter_rejects_review_disposition(
    tmp_path: Path,
) -> None:
    service, source, reviewer, _, evidence, _ = _completed_typed_review(
        tmp_path
    )
    review = service.create_review(
        source.evidence_bundle_id,
        reviewer.assignment_id,
        evidence.evidence_bundle_id,
    )
    service.project_status = lambda project_id: {
        "project_summary": {
            "project_id": project_id,
            "state": "ACTIVE",
            "active_charter_id": "new-charter",
            "active_charter_revision": 2,
        },
        "active_charter": {
            "project_id": project_id,
            "charter_id": "new-charter",
            "revision": 2,
            "status": "ACTIVE",
            "founder_approval_record_id": "approval",
            "founder_approval_identity": "founder",
            "founder_authorization_capability_digest": "a" * 64,
            "authority_envelope": {},
        },
    }
    with pytest.raises(PermissionError, match="current"):
        service.decide_review(review.review_id)


@pytest.mark.parametrize(
    "identity",
    (
        r"C:\evidence\item.json",
        "C:evidence-item.json",
        r"\\server\share\item.json",
        "file://evidence/item.json",
        "../evidence.json",
        "folder/evidence.json",
    ),
)
def test_remote_reference_filesystem_identity_rejects(
    tmp_path: Path, identity: str
) -> None:
    service, _, _, _, _, _ = _typed_reference_stack(tmp_path)
    reference = service.repository.list(EvidenceReferenceRecord)[0]
    reviewer = service.repository.assignment_launch_binding(
        reference.assignment_id
    )[2]
    with pytest.raises(ValueError, match="pathless"):
        service.create_remote_evidence_reference(
            reviewer.assignment_id,
            source_identity=identity,
            sha256="a" * 64,
            size_bytes=1,
            source_evidence_bundle_id=reference.source_evidence_bundle_id,
        )


@pytest.mark.parametrize(
    "review_copy",
    ("../escape", r"..\escape", r"C:escape", r"C:\escape", "/escape"),
)
def test_local_review_copy_path_escape_rejects(
    tmp_path: Path,
    review_copy: str,
) -> None:
    *_, provider_input, _ = _authority_bound_reviewer(tmp_path)
    mutated = copy.deepcopy(provider_input)
    reference = mutated["references"][0]
    reference["classification"] = "LOCAL_PROTECTED_ARTIFACT"
    reference["source_identity"] = "protected:reference-a"
    reference["local_or_remote"] = "LOCAL"
    reference["review_copy"] = review_copy
    material = {
        name: value
        for name, value in mutated.items()
        if name != "delivered_input_digest"
    }
    mutated["delivered_input_digest"] = structured_digest(material)
    with pytest.raises(ValueError, match="review copy path"):
        validate_provider_input(mutated)


class _CapturingPilotObserver(_PilotAuthorityObserver):
    def __init__(self) -> None:
        self.executed_attempt: dict[str, Any] | None = None

    def execute_provider(
        self,
        registration: dict[str, Any],
        attempt: dict[str, Any],
        on_started: Callable[[ProcessObservation], None],
    ) -> ExecutionObservation:
        self.executed_attempt = copy.deepcopy(attempt)
        return super().execute_provider(
            registration, attempt, on_started
        )


def _signed_test_commit_receipt(
    provider_input: dict[str, Any],
    *,
    authority_attempt_id: str,
    provider_input_digest: str,
    delivered_input_digest: str,
) -> dict[str, object]:
    now = datetime.now(UTC).isoformat()
    return TestFounderCapabilityIssuer().sign_executive_input_receipt(
        {
            "schema_version": 1,
            "kind": "executive_delivered_input_commit_receipt",
            "receipt_id": "test-input-receipt",
            "database_id": "test-executive-database",
            "recovery_epoch": 0,
            "repository_mode": "TEST",
            "delivered_input_id": "test-delivered-input",
            "delivered_input_record_revision": 1,
            "delivered_input_record_digest": "c" * 64,
            "reviewer_attempt_id": provider_input["reviewer_attempt_id"],
            "reviewer_assignment_id": provider_input[
                "reviewer_assignment_id"
            ],
            "authority_attempt_id": authority_attempt_id,
            "project_id": provider_input["project_id"],
            "charter_id": provider_input["charter_id"],
            "charter_revision": provider_input["charter_revision"],
            "workflow_id": provider_input["workflow_id"],
            "work_item_id": provider_input["work_item_id"],
            "producer_assignment_id": provider_input[
                "producer_assignment_id"
            ],
            "producer_attempt_id": provider_input["producer_attempt_id"],
            "provider_id": provider_input["provider_id"],
            "account_id": provider_input["account_id"],
            "session_id": provider_input["session_id"],
            "model_id": provider_input["model_id"],
            "workspace": provider_input["workspace"],
            "composition_identity": provider_input[
                "composition_identity"
            ],
            "provider_input_digest": provider_input_digest,
            "delivered_input_digest": delivered_input_digest,
            "manifest_digest": provider_input["manifest_digest"],
            "reference_set_digest": structured_digest(
                provider_input["references"]
            ),
            "usage_reservation_id": "test-usage-reservation",
            "session_slot_claimed": True,
            "launch_claim_state": "LAUNCH_CLAIMED",
            "committed_at": now,
            "issued_at": now,
        }
    )


def _authority_bound_reviewer(
    tmp_path: Path,
    *,
    bind_input: bool = True,
) -> tuple[
    AuthorityServiceCore,
    TestAuthorityServiceClient,
    _CapturingPilotObserver,
    str,
    dict[str, Any],
    str,
]:
    executable = tmp_path / "controlled-provider.exe"
    executable.write_bytes(b"safe-test-provider")
    observer = _CapturingPilotObserver()
    core = AuthorityServiceCore(
        tmp_path / "authority",
        observer=cast(TrustedObserver, observer),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    client = TestAuthorityServiceClient(
        lambda request: core.dispatch(request, "S-1-5-21-TYPED-INPUT")
    )
    registration_id = str(
        client.register_provider("codex", executable, **provider_authority_kwargs())["registration_id"]
    )
    client.qualify_provider(registration_id)
    launch = _launch_authority(client, "typed-project")
    workspace = tmp_path / "review-workspace"
    workspace.mkdir()
    exchange = tmp_path / "exchange"
    exchange.mkdir()
    (exchange / "prompt.md").write_text("review", encoding="utf-8")
    reserved = client.reserve_attempt(
        **launch,
        registration_id=registration_id,
        keeper_run_id="typed-run",
        task_id="reviewer-assignment",
        stage_id="review-work-item",
        role="reviewer",
        attempt_number=1,
        provider_run_id="typed-provider-run",
        provider_instance_id="review-session",
        evidence_path=str((exchange / "evidence.json").resolve()),
        prompt_path=str((exchange / "prompt.md").resolve()),
        stdout_path=str((exchange / "stdout.log").resolve()),
        stderr_path=str((exchange / "stderr.log").resolve()),
        workspace=str(workspace.resolve()),
        timeout_seconds=30,
        reasoning_level="medium",
        environment={},
    )
    attempt_id = str(reserved["attempt_id"])
    launch_id = str(launch["launch_authorization_id"])
    base = {
        "schema_version": 1,
        "project_id": "typed-project",
        "charter_id": "charter-1",
        "charter_revision": 1,
        "workflow_id": "review-workflow",
        "work_item_id": "review-work-item",
        "producer_assignment_id": "producer-assignment",
        "producer_attempt_id": "producer-attempt",
        "reviewer_assignment_id": "reviewer-assignment",
        "reviewer_attempt_id": "reviewer-attempt",
        "references": [
            {
                "reference_id": "reference-a",
                "reference_revision": 1,
                "classification": "REMOTE_STRUCTURED_EVIDENCE",
                "source_identity": "keeper-object:reference-a",
                "project_id": "typed-project",
                "charter_id": "charter-1",
                "charter_revision": 1,
                "workflow_id": "review-workflow",
                "work_item_id": "review-work-item",
                "producer_assignment_id": "producer-assignment",
                "producer_attempt_id": "producer-attempt",
                "reviewed_assignment_id": "producer-assignment",
                "source_evidence_bundle_id": "source-bundle",
                "sha256": "a" * 64,
                "size_bytes": 11,
                "validated_at": datetime.now(UTC).isoformat(),
                "local_or_remote": "REMOTE",
            }
        ],
        "manifest_digest": "b" * 64,
        "delivery_method": "PATHLESS_REMOTE",
        "delivered_at": datetime.now(UTC).isoformat(),
    }
    provider_input, delivered_digest, provider_digest = (
        finalize_provider_input(
            base,
            composition_identity="TEST_AUTHORITY",
            provider_id="provider",
            account_id="account",
            session_id="review-session",
            model_id="model",
            workspace=str(workspace.resolve()).casefold().replace("\\", "/"),
            authority_attempt_id=attempt_id,
            launch_authorization_id=launch_id,
            authorization_generation=1,
        )
    )
    if bind_input:
        receipt = _signed_test_commit_receipt(
            provider_input,
            authority_attempt_id=attempt_id,
            provider_input_digest=provider_digest,
            delivered_input_digest=delivered_digest,
        )
        bound = client.bind_provider_input(
            attempt_id,
            provider_input,
            provider_digest,
            delivered_digest,
            str(provider_input["manifest_digest"]),
            receipt,
        )
        assert bound["attempt"]["service_state"] == "INPUT_BOUND"
    return core, client, observer, attempt_id, provider_input, provider_digest


class _CommitOrderAuthority:
    def __init__(self, delegate: TestLaunchAuthority, repository: Any) -> None:
        self.delegate = delegate
        self.repository = repository
        self.committed_before_bind = False

    def authorize(self, *args: Any, **kwargs: Any) -> Any:
        return self.delegate.authorize(*args, **kwargs)

    def bind_committed_input(
        self, authorization: Any, delivered_input_id: str
    ) -> Any:
        delivered = self.repository.get(
            DeliveredInputRecord, delivered_input_id
        )
        attempt = self.repository.get(
            AttemptRecord, delivered.reviewer_attempt_id
        )
        claim = self.repository.launch_claim(attempt.attempt_id)
        assert attempt.state == "LAUNCH_CLAIMED"
        assert attempt.session_slot_claimed is True
        assert attempt.usage_reservation_id
        assert claim["state"] == "LAUNCH_CLAIMED"
        assert claim["authority_attempt_id"] == (
            authorization.authority_attempt_id
        )
        self.committed_before_bind = True
        return self.delegate.bind_committed_input(
            authorization, delivered_input_id
        )

    def launch(self, *args: Any, **kwargs: Any) -> Any:
        return self.delegate.launch(*args, **kwargs)


def test_orchestration_commits_attempt_before_input_binding(
    tmp_path: Path,
) -> None:
    service, provider, _, _, _, _ = _typed_reference_stack(tmp_path)
    reference = service.repository.list(EvidenceReferenceRecord)[0]
    reviewer = service.repository.assignment_launch_binding(
        reference.assignment_id
    )[2]
    delegate = cast(TestLaunchAuthority, service.launch_authority)
    capture = _CaptureAdapter(provider.provider_id)
    service.adapters[provider.provider_id] = capture
    workspace = tmp_path / "commit-order-reviewer"
    _, authority_id = _launch_ready(
        service, reviewer, workspace, "commit-order-reviewer"
    )
    authority = _CommitOrderAuthority(delegate, service.repository)
    service.launch_authority = authority
    service.run_assignment(
        reviewer.assignment_id,
        workspace,
        authority_attempt_id=authority_id,
        global_context={},
        task_context={"objective": "verify commit ordering"},
        evidence_reference_ids=(reference.evidence_reference_id,),
        side_effect_class="READ_ONLY_REVIEW",
    )
    assert authority.committed_before_bind is True
    assert capture.last_request is not None


def test_crash_after_local_claim_preserves_slot_and_becomes_uncertain(
    tmp_path: Path,
) -> None:
    service, provider, _, _, _, _ = _typed_reference_stack(tmp_path)
    reference = service.repository.list(EvidenceReferenceRecord)[0]
    reviewer = service.repository.assignment_launch_binding(
        reference.assignment_id
    )[2]
    capture = _CaptureAdapter(provider.provider_id)
    service.adapters[provider.provider_id] = capture
    workspace = tmp_path / "claim-crash-reviewer"
    _, authority_id = _launch_ready(
        service, reviewer, workspace, "claim-crash-reviewer"
    )

    def crash_after_claim() -> None:
        raise RuntimeError("deterministic crash after local claim")

    with pytest.raises(RuntimeError, match="deterministic crash"):
        service.run_assignment(
            reviewer.assignment_id,
            workspace,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={"objective": "crash boundary"},
            evidence_reference_ids=(reference.evidence_reference_id,),
            side_effect_class="READ_ONLY_REVIEW",
            after_launch_claim=crash_after_claim,
        )
    attempt = next(
        item
        for item in service.repository.list(AttemptRecord)
        if item.assignment_id == reviewer.assignment_id
        and item.state == "LAUNCH_CLAIMED"
    )
    assert attempt.session_slot_claimed is True
    assert service.repository.launch_claim(attempt.attempt_id)[
        "state"
    ] == "LAUNCH_CLAIMED"
    assert capture.last_request is None

    recovered = service.repository.recover_interrupted_attempts(
        datetime.now(UTC).isoformat()
    )
    uncertain = service.repository.get(AttemptRecord, attempt.attempt_id)
    assert recovered["uncertain"] == 1
    assert uncertain.state == "UNCERTAIN"
    assert uncertain.session_slot_claimed is True
    assert service.repository.launch_claim(attempt.attempt_id)[
        "state"
    ] == "UNCERTAIN"
    reservations = service.repository.usage_reservations(
        reviewer.assignment_id
    )
    assert [item["state"] for item in reservations] == ["ACTIVE"]


def test_authority_attempt_owns_exact_input_and_id_only_execution_uses_it(
    tmp_path: Path,
) -> None:
    core, client, observer, attempt_id, provider_input, provider_digest = (
        _authority_bound_reviewer(tmp_path)
    )
    queried = client.query_state("attempts", attempt_id)["record"]
    assert queried["service_state"] == "INPUT_BOUND"
    assert queried["provider_input"] == provider_input
    assert queried["provider_input_digest"] == provider_digest
    with pytest.raises(PermissionError, match="Authority-bound"):
        client.record_provider_start(attempt_id, 7777)
    result = client.execute_provider(attempt_id)
    assert observer.executed_attempt is not None
    assert observer.executed_attempt["provider_input"] == provider_input
    assert (
        observer.executed_attempt["provider_input_digest"]
        == provider_digest
    )
    assert observer.executed_attempt["executive_commit_receipt_digest"]
    assert observer.executed_attempt["executive_commit_receipt"][
        "reviewer_attempt_id"
    ] == provider_input["reviewer_attempt_id"]
    completion = result["completion"]
    assert completion["provider_input_digest"] == provider_digest
    assert completion["delivered_input_digest"] == (
        provider_input["delivered_input_digest"]
    )
    assert core.keys.verify("provider-completion", completion)
    output = json.loads(
        Path(result["process_result"]["stdout_path"]).read_text(
            encoding="utf-8"
        )
    )
    assert output["review_input_declaration"] == (
        review_input_declaration(
            provider_input,
            provider_input_digest=provider_digest,
            review_disposition="ACCEPTED",
        )
    )
    assert structured_digest(provider_input) == provider_digest


def test_authority_input_cannot_be_rebound_or_omitted(
    tmp_path: Path,
) -> None:
    _, client, _, attempt_id, provider_input, provider_digest = (
        _authority_bound_reviewer(tmp_path)
    )
    changed = copy.deepcopy(provider_input)
    changed["model_id"] = "substituted-model"
    changed["delivered_input_digest"] = structured_digest(
        {
            key: value
            for key, value in changed.items()
            if key != "delivered_input_digest"
        }
    )
    changed_digest = structured_digest(changed)
    with pytest.raises(PermissionError, match="differently"):
        client.bind_provider_input(
            attempt_id,
            changed,
            changed_digest,
            str(changed["delivered_input_digest"]),
            str(changed["manifest_digest"]),
            _signed_test_commit_receipt(
                changed,
                authority_attempt_id=attempt_id,
                provider_input_digest=changed_digest,
                delivered_input_digest=str(
                    changed["delivered_input_digest"]
                ),
            ),
        )
    assert client.query_state("attempts", attempt_id)["record"][
        "provider_input_digest"
    ] == provider_digest


def test_reviewer_launch_without_durable_evidence_rejects_before_adapter(
    tmp_path: Path,
) -> None:
    service, provider, _, _, _, _ = _typed_reference_stack(tmp_path)
    reference = service.repository.list(EvidenceReferenceRecord)[0]
    reviewer = service.repository.assignment_launch_binding(
        reference.assignment_id
    )[2]
    capture = _CaptureAdapter(provider.provider_id)
    service.adapters[provider.provider_id] = capture
    workspace = tmp_path / "empty-reviewer"
    _, authority_id = _launch_ready(
        service, reviewer, workspace, "empty-reviewer"
    )

    with pytest.raises(PermissionError, match="nonempty durable evidence"):
        service.run_assignment(
            reviewer.assignment_id,
            workspace,
            authority_attempt_id=authority_id,
            global_context={},
            task_context={"objective": "review without evidence"},
            evidence_reference_ids=(),
            side_effect_class="READ_ONLY_REVIEW",
        )

    assert capture.last_request is None
    assert not [
        attempt
        for attempt in service.repository.list(AttemptRecord)
        if attempt.assignment_id == reviewer.assignment_id
    ]


def test_reviewer_evidence_without_delivered_input_is_rejected(
    tmp_path: Path,
) -> None:
    service, _, _, _, evidence, _ = _completed_typed_review(
        tmp_path, reference_count=1
    )
    attempt = service.repository.get(AttemptRecord, evidence.attempt_id)
    service.repository.replace(
        replace(
            attempt,
            delivered_input_id=None,
            delivered_input_digest=None,
            provider_input_digest=None,
            updated_at=datetime.now(UTC).isoformat(),
            revision=attempt.revision + 1,
        ),
        expected_revision=attempt.revision,
    )
    artifacts = tuple(
        {
            key: value
            for key, value in artifact.items()
            if key != "review_input_declaration"
        }
        for artifact in evidence.artifacts
    )
    unbound = replace(
        evidence,
        artifacts=artifacts,
        content_digest=evidence_content_digest(
            project_id=evidence.project_id,
            assignment_id=evidence.assignment_id,
            attempt_id=evidence.attempt_id,
            producer_provider_id=evidence.producer_provider_id,
            producer_session_id=evidence.producer_session_id,
            schema_version=evidence.schema_version,
            artifacts=artifacts,
            summary=evidence.summary,
        ),
        state="UNTRUSTED",
        validation_errors=(),
        delivered_input_id=None,
        delivered_input_digest=None,
        provider_input_digest=None,
        updated_at=datetime.now(UTC).isoformat(),
        revision=evidence.revision + 1,
    )
    service.repository.replace(unbound, expected_revision=evidence.revision)

    rejected = service.validate_evidence(
        evidence.evidence_bundle_id, tmp_path / "reviewer"
    )
    assert rejected.state == "REJECTED"
    assert "reviewer evidence has an invalid delivered-input binding" in (
        rejected.validation_errors
    )


def test_authority_reserved_reviewer_cannot_execute_without_bound_input(
    tmp_path: Path,
) -> None:
    _, client, observer, attempt_id, provider_input, _ = (
        _authority_bound_reviewer(
            tmp_path, bind_input=False
        )
    )
    assert client.query_state("attempts", attempt_id)["record"][
        "service_state"
    ] == "RESERVED"
    provider_digest = structured_digest(provider_input)
    with pytest.raises(ValueError, match="payload fields"):
        client.request(
            Operation.BIND_PROVIDER_INPUT,
            {
                "attempt_id": attempt_id,
                "provider_input": provider_input,
                "provider_input_digest": provider_digest,
                "delivered_input_digest": provider_input[
                    "delivered_input_digest"
                ],
                "manifest_digest": provider_input["manifest_digest"],
            },
        )
    assert client.query_state("attempts", attempt_id)["record"][
        "service_state"
    ] == "RESERVED"

    with pytest.raises(PermissionError, match="input-bound"):
        client.execute_provider(attempt_id)
    with pytest.raises(PermissionError, match="Authority-bound"):
        client.record_provider_start(attempt_id, 7777)

    assert observer.executed_attempt is None
    assert client.query_state("attempts", attempt_id)["record"][
        "service_state"
    ] == "RESERVED"

    restarted_core = AuthorityServiceCore(
        tmp_path / "authority",
        observer=cast(TrustedObserver, observer),
        founder_capability_verifier=TestFounderCapabilityVerifier(),
    )
    restarted_client = TestAuthorityServiceClient(
        lambda request: restarted_core.dispatch(
            request, "S-1-5-21-TYPED-INPUT"
        )
    )
    with pytest.raises(PermissionError, match="input-bound"):
        restarted_client.execute_provider(attempt_id)
    assert observer.executed_attempt is None


def test_forged_executive_commit_receipt_rejects_before_execution(
    tmp_path: Path,
) -> None:
    _, client, observer, attempt_id, provider_input, provider_digest = (
        _authority_bound_reviewer(tmp_path, bind_input=False)
    )
    delivered_digest = str(provider_input["delivered_input_digest"])
    receipt = _signed_test_commit_receipt(
        provider_input,
        authority_attempt_id=attempt_id,
        provider_input_digest=provider_digest,
        delivered_input_digest=delivered_digest,
    )
    receipt["database_id"] = "caller-fabricated-database"
    with pytest.raises(PermissionError, match="authentication failed"):
        client.bind_provider_input(
            attempt_id,
            provider_input,
            provider_digest,
            delivered_digest,
            str(provider_input["manifest_digest"]),
            receipt,
        )
    assert observer.executed_attempt is None
    assert client.query_state("attempts", attempt_id)["record"][
        "service_state"
    ] == "RESERVED"


def test_production_reviewer_context_cannot_be_omitted(
    tmp_path: Path,
) -> None:
    service, _, reviewer, _, _, _ = _completed_typed_review(
        tmp_path, reference_count=1
    )
    capture = cast(_CaptureAdapter, service.adapters[reviewer.provider_id])
    request = capture.last_request
    authorization = service.launch_authority.last_launch_authorization
    assert request is not None
    assert authorization is not None
    omitted_context = dict(request.task_context)
    omitted_context.pop("keeper_provider_input", None)
    omitted_context.pop("keeper_provider_input_digest", None)
    omitted = replace(request, task_context=omitted_context)

    with pytest.raises(PermissionError, match="provider input was omitted"):
        ExecutiveAuthorityLaunchGate._validate_production_evidence_delivery(
            authorization, omitted
        )
