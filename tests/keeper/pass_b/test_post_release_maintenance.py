from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import keeper
from keeper.app.service import KeeperApplication
from keeper.pass_b.application import PassBApplication
from keeper.pass_b.enums import AssignmentRole
from keeper.pass_b.launch_authority import (
    ExecutiveAuthorityLaunchGate,
    TestLaunchAuthority,
)
from keeper.pass_b.models import EvidenceReferenceRecord, ReviewRecord
from keeper.pass_b.providers import AdapterAssignment, LocalMockAdapter
from keeper.ui.desktop import (
    KeeperProductDesktop,
    ProductSetupController,
    _desktop_pass_b_application,
)
from keeper.ui.view_models import build_product_view
from keeper.version import VERSION
from tests.keeper.pass_b.test_completion_repair_matrix import _launch_ready
from tests.keeper.pass_b.test_four_high_repair import (
    _protected_tree,
    _reviewer_with_validated_source,
)
from tests.keeper.pass_b.test_orchestration import _assignment, _stack
from tests.keeper.test_product_ui_view_models import _snapshot


class _CaptureAdapter(LocalMockAdapter):
    def __init__(self, provider_id: str) -> None:
        super().__init__(provider_id)
        self.last_request: AdapterAssignment | None = None

    def launch(self, assignment: AdapterAssignment) -> Any:
        self.last_request = assignment
        return super().launch(assignment)


class _HealthClient:
    def __init__(self, response: object = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.calls = 0

    def require_live_identity(self) -> dict[str, Any]:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.response if isinstance(self.response, dict) else {}


def _typed_reference_stack(
    tmp_path: Path,
) -> tuple[Any, Any, Any, Any, Path, bytes]:
    _, service, _, provider, account, _, sessions, _ = _stack(tmp_path)
    _, _, evidence_run = _protected_tree(tmp_path)
    artifact = evidence_run / "producer-evidence.json"
    content = b'{"validated":true}\n'
    artifact.write_bytes(content)
    reviewer, source = _reviewer_with_validated_source(
        service, provider, account, sessions, tmp_path, "lineage"
    )
    reference = service.create_local_evidence_reference(
        reviewer.assignment_id,
        artifact,
        source_evidence_bundle_id=source.evidence_bundle_id,
    )
    return service, provider, account, sessions, artifact, content


def test_exact_lineage_is_delivered_and_consumed_once(tmp_path: Path) -> None:
    service, provider, _, _, artifact, content = _typed_reference_stack(tmp_path)
    reference = service.repository.list(EvidenceReferenceRecord)[0]
    reviewer = service.repository.assignment_launch_binding(
        reference.assignment_id
    )[2]
    capture = _CaptureAdapter(provider.provider_id)
    service.adapters[provider.provider_id] = capture
    workspace = tmp_path / "reviewer"
    _, authority_id = _launch_ready(
        service, reviewer, workspace, "typed-review"
    )
    review_evidence = service.run_assignment(
        reviewer.assignment_id,
        workspace,
        authority_attempt_id=authority_id,
        global_context={},
        task_context={"objective": "independent review"},
        evidence_reference_ids=(reference.evidence_reference_id,),
        side_effect_class="READ_ONLY_REVIEW",
    )
    review_evidence = service.validate_evidence(
        review_evidence.evidence_bundle_id, workspace
    )
    source_bundle_id = reference.source_evidence_bundle_id
    assert source_bundle_id is not None
    review = service.create_review(
        source_bundle_id,
        reviewer.assignment_id,
        review_evidence.evidence_bundle_id,
        evidence_reference_id=reference.evidence_reference_id,
    )
    consumed = service.repository.get(
        EvidenceReferenceRecord, reference.evidence_reference_id
    )
    stored_review = service.repository.get(ReviewRecord, review.review_id)
    assert consumed.consumed_by_review_id == review.review_id
    assert stored_review.consumed_evidence_reference_id == reference.evidence_reference_id
    assert stored_review.consumed_evidence_reference_revision == consumed.revision
    assert artifact.read_bytes() == content
    assert capture.last_request is not None
    context = capture.last_request.task_context["keeper_evidence_references"]
    assert isinstance(context, list)
    assert context[0]["producer_assignment_id"] == reference.producer_assignment_id
    assert context[0]["producer_attempt_id"] == reference.producer_attempt_id
    assert context[0]["reviewed_assignment_id"] == reference.review_target_assignment_id
    assert "canonical_source_path" not in context[0]
    assert str(artifact.resolve()).casefold() not in json.dumps(context).casefold()
    authority = service.launch_authority
    assert isinstance(authority, TestLaunchAuthority)
    assert authority.last_launch_authorization is not None
    ExecutiveAuthorityLaunchGate._validate_production_evidence_delivery(
        authority.last_launch_authorization, capture.last_request
    )
    with pytest.raises(PermissionError, match="already consumed"):
        service.create_review(
            source_bundle_id,
            reviewer.assignment_id,
            review_evidence.evidence_bundle_id,
            evidence_reference_id=reference.evidence_reference_id,
        )


def test_wrong_producer_bundle_rejects_reference_creation(tmp_path: Path) -> None:
    _, service, _, provider, account, _, sessions, adapter = _stack(tmp_path)
    reviewer, expected_source = _reviewer_with_validated_source(
        service, provider, account, sessions, tmp_path, "expected"
    )
    other = _assignment(
        service, provider, account, sessions[0],
        role=AssignmentRole.IMPLEMENTER,
    )
    other_workspace = tmp_path / "other-producer"
    _, authority_id = _launch_ready(
        service, other, other_workspace, "other-producer"
    )
    wrong_source = service.run_assignment(
        other.assignment_id,
        other_workspace,
        authority_attempt_id=authority_id,
        global_context={},
        task_context={},
    )
    wrong_source = service.validate_evidence(
        wrong_source.evidence_bundle_id, other_workspace
    )
    _, _, evidence_run = _protected_tree(tmp_path)
    artifact = evidence_run / "wrong-producer.json"
    artifact.write_text("{}", encoding="utf-8")
    with pytest.raises(PermissionError, match="source lineage"):
        service.create_local_evidence_reference(
            reviewer.assignment_id,
            artifact,
            source_evidence_bundle_id=wrong_source.evidence_bundle_id,
        )
    assert expected_source.assignment_id != wrong_source.assignment_id
    assert adapter.health()["launched"] == 2


def test_typed_reference_wrong_reviewer_rejects(tmp_path: Path) -> None:
    service, provider, account, sessions, _, _ = _typed_reference_stack(tmp_path)
    reference = service.repository.list(EvidenceReferenceRecord)[0]
    other = _assignment(
        service,
        provider,
        account,
        sessions[1],
        role=AssignmentRole.REVIEWER,
        review_of_assignment_id=reference.producer_assignment_id,
    )
    with pytest.raises(PermissionError, match="assignment context"):
        service.validate_evidence_reference(
            reference.evidence_reference_id, other.assignment_id
        )


def test_remote_reference_delivery_is_pathless(tmp_path: Path) -> None:
    _, service, _, provider, account, _, sessions, _ = _stack(tmp_path)
    reviewer, source = _reviewer_with_validated_source(
        service, provider, account, sessions, tmp_path, "remote"
    )
    reference = service.create_remote_evidence_reference(
        reviewer.assignment_id,
        source_identity="provider-object:immutable-1",
        sha256="a" * 64,
        size_bytes=17,
        source_evidence_bundle_id=source.evidence_bundle_id,
    )
    capture = _CaptureAdapter(provider.provider_id)
    service.adapters[provider.provider_id] = capture
    workspace = tmp_path / "remote-reviewer"
    _, authority_id = _launch_ready(
        service, reviewer, workspace, "remote-reviewer"
    )
    service.run_assignment(
        reviewer.assignment_id,
        workspace,
        authority_attempt_id=authority_id,
        global_context={},
        task_context={},
        evidence_reference_ids=(reference.evidence_reference_id,),
    )
    assert capture.last_request is not None
    item = capture.last_request.task_context["keeper_evidence_references"][0]
    assert item["local_or_remote"] == "REMOTE"
    assert item["source_identity"] == "provider-object:immutable-1"
    assert "review_copy" not in item
    authority = service.launch_authority
    assert isinstance(authority, TestLaunchAuthority)
    assert authority.last_launch_authorization is not None
    ExecutiveAuthorityLaunchGate._validate_production_evidence_delivery(
        authority.last_launch_authorization, capture.last_request
    )


def test_desktop_health_client_is_observational_only(tmp_path: Path) -> None:
    healthy = _HealthClient(
        {
            "observer_available": True,
            "service_version": "1.0",
            "protocol_version": 3,
            "schema_version": 5,
            "service_key_id": "authority-key",
            "provenance_state": "VERIFIED",
        }
    )
    application = _desktop_pass_b_application(
        tmp_path / "healthy",
        authority_health_client=healthy,
    )
    diagnostics = application.diagnostics()
    assert diagnostics["authority"]["state"] == "READY"
    assert diagnostics["authority"]["composition"] == "PRODUCTION_HEALTH_ONLY"
    assert diagnostics["authority"]["last_checked_at"]
    assert diagnostics["launch_authority_configured"] is False
    assert healthy.calls >= 1
    view = build_product_view(application.control_room.snapshot().to_dict())
    assert "service 1.0" in view.safety_rows[0]["value"]
    assert "protocol 3" in view.safety_rows[0]["value"]
    assert "schema 5" in view.safety_rows[0]["value"]
    assert "identity VERIFIED" in view.safety_rows[0]["value"]


@pytest.mark.parametrize(
    "client",
    [
        _HealthClient(error=TimeoutError("unavailable")),
        _HealthClient({"observer_available": False}),
        _HealthClient(error=ValueError("malformed identity")),
    ],
)
def test_desktop_health_failure_is_safe(tmp_path: Path, client: _HealthClient) -> None:
    application = _desktop_pass_b_application(
        tmp_path / str(id(client)),
        authority_health_client=client,
    )
    health = application.diagnostics()["authority"]
    assert health["state"] == "UNAVAILABLE"
    assert health["composition"] == "PRODUCTION_HEALTH_ONLY"
    assert application.diagnostics()["launch_authority_configured"] is False


def test_setup_probe_preserves_existing_files_and_removes_only_probe(
    tmp_path: Path,
) -> None:
    application = KeeperApplication(tmp_path / "data")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    sentinel = evidence / ".keeper-write-test"
    sentinel.write_bytes(b"preserve-me")
    unrelated = evidence / "unrelated.bin"
    unrelated.write_bytes(b"also-preserve")
    controller = ProductSetupController(application)
    controller.index = 1
    controller.evidence_directory = str(evidence)
    controller.next()
    assert sentinel.read_bytes() == b"preserve-me"
    assert unrelated.read_bytes() == b"also-preserve"
    assert not tuple(evidence.glob(".keeper-write-probe-*.tmp"))


def test_setup_probe_rejects_tree_containing_protected_evidence(
    tmp_path: Path,
) -> None:
    application = KeeperApplication(tmp_path / "data")
    protected = tmp_path / "protected"
    protected.mkdir()
    selected, _, _ = _protected_tree(protected)
    controller = ProductSetupController(application)
    controller.index = 1
    controller.evidence_directory = str(selected)
    with pytest.raises(PermissionError, match="protected Keeper"):
        controller.next()


def test_evidence_cards_hide_paths_and_sage_hidden_collapses() -> None:
    snapshot = _snapshot()
    snapshot["project"]["evidence_references"] = [  # type: ignore[index]
        {
            "evidence_reference_id": "reference-1",
            "source_kind": "LOCAL_PROTECTED_ARTIFACT",
            "producer_assignment_id": "producer-1",
            "review_target_assignment_id": "producer-1",
            "sha256": "b" * 64,
            "size_bytes": 24,
            "state": "VALIDATED",
            "consumed_by_review_id": "review-1",
            "canonical_source_path": "C:/protected/private/evidence.json",
        }
    ]
    snapshot["presentation"]["mode"] = "HIDDEN"  # type: ignore[index]
    view = build_product_view(snapshot)
    assert view.sage["visible"] is False
    assert view.sage["authority_effect"] == "NONE"
    card = view.evidence_reference_cards[0]
    assert card["reference_id"] == "reference-1"
    assert card["review_state"] == "CONSUMED:review-1"
    assert "canonical_source_path" not in card
    assert "C:/protected" not in json.dumps(card)


class _HiddenWidget:
    def __init__(self) -> None:
        self.forgotten = False
        self.configured = False

    def pack_forget(self) -> None:
        self.forgotten = True

    def winfo_manager(self) -> str:
        return ""

    def pack(self, **_: object) -> None:
        raise AssertionError("hidden Sage widget must not be packed")

    def configure(self, **_: object) -> None:
        self.configured = True


def test_hidden_sage_renderer_removes_every_presentation_widget() -> None:
    desktop: Any = object.__new__(KeeperProductDesktop)
    sage_label = _HiddenWidget()
    sage_detail = _HiddenWidget()
    desktop.sage_label = sage_label
    desktop.sage_detail = sage_detail
    desktop.refresh_button = object()
    desktop._render_sage({"visible": False, "authority_effect": "NONE"})
    assert sage_label.forgotten
    assert sage_detail.forgotten
    assert not sage_label.configured
    assert not sage_detail.configured


def test_package_version_metadata_is_consistent() -> None:
    assert keeper.__version__ == VERSION
