from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import QCoreApplication

from keeper.app.service import KeeperApplication
from keeper.pass_b.application import PassBApplication
from keeper.pass_b.enums import AssignmentState, AttemptState
from keeper.pass_b.models import AssignmentRecord, AttemptRecord
from keeper.ui_qml.composition import ProductSetupController
from keeper.ui_qml.controller import (
    KeeperDesktopController,
    NAVIGATION,
    _completion_feedback,
    _primitive,
    _safe_error_message,
)


class _HealthClient:
    def require_live_identity(self) -> dict[str, object]:
        return {
            "service_version": "test-health-only",
            "protocol_version": 7,
            "schema_version": 6,
            "identity_state": "VERIFIED",
            "provenance_state": "TEST_INJECTION",
            "observer_available": True,
        }


@pytest.fixture
def controller(tmp_path: Path) -> KeeperDesktopController:
    application = KeeperApplication(tmp_path)
    pass_b = PassBApplication(
        tmp_path,
        authority_health_client=_HealthClient(),
    )
    return KeeperDesktopController(
        application,
        pass_b_application=pass_b,
        test_fixture=True,
    )


def test_navigation_is_canonical_and_test_composition_is_visible(
    controller: KeeperDesktopController,
) -> None:
    assert NAVIGATION == (
        "Overview",
        "Keeper",
        "Projects",
        "Repositories",
        "Workflows",
        "Tasks",
        "Findings",
        "Authorizations",
        "Evidence",
        "Reviews",
        "Reports",
        "Providers",
        "Recovery",
        "Settings",
    )
    assert controller.state_snapshot()["navigation"] == list(NAVIGATION)
    assert controller.state_snapshot()["environment"] == "TEST UI FIXTURE"


def test_qml_projection_is_primitive_and_redacts_evidence_path(
    controller: KeeperDesktopController,
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "private" / "evidence"
    controller.application.finish_setup(evidence)
    controller.refresh()

    snapshot = controller.state_snapshot()
    assert snapshot["settings"]["evidenceDirectory"] == "Local path configured (redacted)"

    assert str(tmp_path) not in repr(snapshot)
    assert _is_primitive(snapshot)


def test_qml_projection_stringifies_only_integers_outside_signed_64_bit() -> None:
    maximum = 2**63 - 1
    minimum = -(2**63)
    projected = _primitive(
        {
            "maximum": maximum,
            "minimum": minimum,
            "unsigned_file_id": 10687299546425997470,
            "negative_overflow": minimum - 1,
            "flag": True,
        }
    )

    assert projected == {
        "maximum": maximum,
        "minimum": minimum,
        "unsigned_file_id": "10687299546425997470",
        "negative_overflow": str(minimum - 1),
        "flag": True,
    }


def test_assistant_creates_durable_conversation_not_fake_chat(
    controller: KeeperDesktopController,
) -> None:
    controller.sendAssistantMessage(
        "Create a local report generator with tests and no network access."
    )

    snapshot = controller.state_snapshot()
    assert snapshot["project"]["id"]
    assert any(
        "report generator" in str(item["body"]).lower()
        for item in snapshot["timeline"]
    )
    assert snapshot["project"]["approvalRequired"] is True


def test_greeting_replies_without_creating_a_project(
    controller: KeeperDesktopController,
) -> None:
    controller.startNewProject()
    controller.sendAssistantMessage("Hello Keeper, are you ready?")

    snapshot = controller.state_snapshot()
    assert snapshot["project"]["id"] is None
    assert len(controller.pass_b.project_catalog()) == 0
    assert [item["body"] for item in snapshot["timeline"]] == [
        "Hello Keeper, are you ready?",
        (
            "Yes, I'm ready. Tell me what you want to build or change, and "
            "I'll help shape it into a project before anything runs."
        ),
    ]
    assert controller._get_status() == "Keeper replied"

    controller.sendAssistantMessage("Build a small local notes application.")

    assert len(controller.pass_b.project_catalog()) == 1
    assert controller.state_snapshot()["project"]["approvalRequired"] is True


def test_greeting_with_build_request_still_creates_a_project(
    controller: KeeperDesktopController,
) -> None:
    controller.startNewProject()
    controller.sendAssistantMessage(
        "Hello Keeper, build a local notes application with tests."
    )

    snapshot = controller.state_snapshot()
    assert snapshot["project"]["approvalRequired"] is True
    assert len(controller.pass_b.project_catalog()) == 1


def test_production_chat_send_returns_before_durable_refresh_finishes(
    controller: KeeperDesktopController,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_refresh = threading.Event()
    refresh_started = threading.Event()
    refresh_finished = threading.Event()
    original_build_state = controller._build_state

    def delayed_build_state() -> dict[str, object]:
        refresh_started.set()
        release_refresh.wait(timeout=2)
        state = original_build_state()
        refresh_finished.set()
        return state

    controller._test_fixture = False
    monkeypatch.setattr(controller, "_build_state", delayed_build_state)

    started = time.perf_counter()
    controller.sendAssistantMessage("Hello Keeper, are you ready?")
    elapsed = time.perf_counter() - started

    assert elapsed < 0.1
    assert controller._get_busy() is True
    assert refresh_started.wait(timeout=1)
    release_refresh.set()
    assert refresh_finished.wait(timeout=2)
    application = QCoreApplication.instance() or QCoreApplication([])
    deadline = time.monotonic() + 2
    while controller._get_busy() and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)
    assert controller._get_busy() is False
    assert controller._get_status() == "Keeper replied"


def test_conversation_draft_is_durable_and_clears_after_success(
    controller: KeeperDesktopController,
) -> None:
    message = "Draft a Keeper reliability improvement."
    controller.saveConversationDraft(message)

    stored = controller.application.store.get("settings", "conversation_draft")
    assert stored == {"message": message}
    assert controller._get_conversation_draft() == message

    controller.sendAssistantMessage("Hello Keeper, are you ready?")

    assert controller._get_conversation_draft() == ""
    assert controller.application.store.get("settings", "conversation_draft") is None


def test_failed_conversation_preserves_the_saved_draft(
    controller: KeeperDesktopController,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message = "Hello Keeper, are you ready?"
    monkeypatch.setattr(
        controller.pass_b,
        "casual_conversation",
        lambda project_id, text: (_ for _ in ()).throw(RuntimeError("offline")),
    )

    controller.sendAssistantMessage(message)

    assert controller._get_error() == "offline"
    assert controller._get_conversation_draft() == message
    assert controller.application.store.get("settings", "conversation_draft") == {
        "message": message
    }


def test_primary_agent_selection_is_ready_only_and_durable(
    controller: KeeperDesktopController,
) -> None:
    controller._state["settings"]["conversationProviders"] = [
        {"provider_id": "codex", "name": "codex", "health": "READY"},
        {"provider_id": "claude", "name": "claude", "health": "READY"},
    ]

    controller.selectConversationProvider("claude")

    routing = controller.application.store.get("settings", "routing")
    assert routing is not None
    assert routing["conversation_provider_id"] == "claude"
    assert controller._get_status() == "claude selected as the primary agent"

    controller.selectConversationProvider("unqualified-provider")

    assert controller._get_status() == "Action could not be completed"
    assert "qualified READY session" in controller._get_error()
    assert controller.application.store.get("settings", "routing") == routing


def test_new_project_binds_selected_agent_and_ready_reviewers(
    controller: KeeperDesktopController,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller._state["settings"].update(
        {
            "conversationProvider": "codex",
            "conversationProviders": [
                {"provider_id": "codex", "name": "codex", "health": "READY"},
                {"provider_id": "claude", "name": "claude", "health": "READY"},
            ],
        }
    )
    captured: list[tuple[str, dict[str, object] | None]] = []
    original = controller.pass_b.begin_conversation

    def record_begin(
        message: str,
        *,
        founder_revisions: dict[str, object] | None = None,
    ) -> object:
        captured.append((message, founder_revisions))
        return original(message, founder_revisions=founder_revisions)

    monkeypatch.setattr(controller.pass_b, "begin_conversation", record_begin)

    controller.startNewProject()
    controller.sendAssistantMessage("Build a small local notes application.")

    assert captured == [
        (
            "Build a small local notes application.",
            {"approved_providers": ("codex", "claude")},
        )
    ]
    assert controller.state_snapshot()["project"]["approvalCharter"][
        "approved_providers"
    ] == ["codex", "claude"]


def test_new_project_action_does_not_continue_selected_project(
    controller: KeeperDesktopController,
) -> None:
    controller.sendAssistantMessage(
        "Create a local report generator with tests and no network access."
    )
    first_project_id = controller.state_snapshot()["project"]["id"]

    controller.startNewProject()
    controller.sendAssistantMessage(
        "Fix one QML lint warning without changing layout or behavior."
    )

    snapshot = controller.state_snapshot()
    assert snapshot["project"]["id"] != first_project_id
    assert len(controller.pass_b.project_catalog()) == 2
    assert any(
        "qml lint warning" in str(item["body"]).lower()
        for item in snapshot["timeline"]
    )


def test_prepare_delegated_mode_creates_only_a_charter_revision(
    controller: KeeperDesktopController,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller.sendAssistantMessage(
        "Create a local report generator with tests and no network access."
    )
    project_id = controller.state_snapshot()["project"]["id"]
    revisions: list[tuple[str, dict[str, str]]] = []
    monkeypatch.setattr(
        controller.pass_b.conversation,
        "revise",
        lambda selected, replacements: revisions.append(
            (selected, replacements)
        ),
    )

    controller.prepareDelegatedMode()

    assert revisions == [(project_id, {"delegation_mode": "DELEGATED"})]
    assert controller._get_status() == (
        "Delegated-mode revision is ready for Founder approval"
    )


def test_simple_task_uses_safe_defaults(
    controller: KeeperDesktopController,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(
        controller.application,
        "create_task",
        lambda values: captured.append(values) or values,
    )

    controller.createSimpleTask(" Clean up Workflow UI ", " Keep behavior intact. ")

    assert captured[0]["title"] == "Clean up Workflow UI"
    assert captured[0]["objective"] == "Keep behavior intact."
    assert captured[0]["baseline"] == "HEAD"
    assert str(captured[0]["target_branch"]).startswith(
        "keeper/clean-up-workflow-ui-"
    )
    assert captured[0]["prohibited_actions"] == [
        "PUSH",
        "DEPLOY",
        "SPEND",
        "LIVE_TRADING",
    ]


def test_task_creation_uses_the_selected_projects_exact_repository(
    controller: KeeperDesktopController,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "approved-repository"
    repository.mkdir()
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(
        controller.pass_b, "selected_project_id", lambda: "project-1"
    )
    monkeypatch.setattr(
        controller,
        "_selected_project_repository",
        lambda project_id: repository.resolve(),
    )
    monkeypatch.setattr(
        controller,
        "_selected_project_charter_identity",
        lambda project_id: {
            "charter_id": "charter-1",
            "revision": 3,
            "founder_approval_record_id": "approval-1",
            "founder_approval_identity": "Founder",
        },
    )
    monkeypatch.setattr(
        controller.application,
        "create_task",
        lambda values: captured.append(values) or values,
    )

    controller.createTask("Bound", "Use the approved repository", "HEAD", "keeper/bound")

    assert captured[0]["keeper_project_id"] == "project-1"
    assert captured[0]["repository"] == str(repository.resolve())
    assert captured[0]["keeper_charter_id"] == "charter-1"
    assert captured[0]["keeper_charter_revision"] == 3


def test_task_start_rejects_a_different_project_workspace_binding(
    controller: KeeperDesktopController,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "approved-repository"
    other = tmp_path / "other-repository"
    repository.mkdir()
    other.mkdir()
    controller.application.store.upsert(
        "tasks",
        "task-mismatch",
        {
            "id": "task-mismatch",
            "keeper_project_id": "project-other",
            "repository": str(other.resolve()),
            "status": "INTAKE",
        },
    )
    calls: list[str] = []
    monkeypatch.setattr(
        controller.pass_b, "selected_project_id", lambda: "project-1"
    )
    monkeypatch.setattr(
        controller,
        "_selected_project_repository",
        lambda project_id: repository.resolve(),
    )
    monkeypatch.setattr(
        controller,
        "_selected_project_charter_identity",
        lambda project_id: {
            "charter_id": "charter-current",
            "revision": 4,
            "founder_approval_record_id": "approval-current",
            "founder_approval_identity": "Founder",
        },
    )
    monkeypatch.setattr(
        controller.application,
        "start_task",
        lambda task_id: calls.append(task_id),
    )

    controller.startTask("task-mismatch")

    assert calls == []
    assert "not bound" in controller._get_error()


def test_task_start_rejects_a_superseded_charter_binding(
    controller: KeeperDesktopController,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "approved-repository"
    repository.mkdir()
    controller.application.store.upsert(
        "tasks",
        "task-stale-charter",
        {
            "id": "task-stale-charter",
            "keeper_project_id": "project-1",
            "keeper_charter_id": "charter-old",
            "keeper_charter_revision": 3,
            "keeper_founder_approval_record_id": "approval-old",
            "keeper_founder_approval_identity": "Founder",
            "repository": str(repository.resolve()),
            "status": "INTAKE",
        },
    )
    calls: list[str] = []
    monkeypatch.setattr(
        controller.pass_b, "selected_project_id", lambda: "project-1"
    )
    monkeypatch.setattr(
        controller,
        "_selected_project_repository",
        lambda project_id: repository.resolve(),
    )
    monkeypatch.setattr(
        controller,
        "_selected_project_charter_identity",
        lambda project_id: {
            "charter_id": "charter-current",
            "revision": 4,
            "founder_approval_record_id": "approval-current",
            "founder_approval_identity": "Founder",
        },
    )
    monkeypatch.setattr(
        controller.application,
        "start_task",
        lambda task_id: calls.append(task_id),
    )

    controller.startTask("task-stale-charter")

    assert calls == []
    assert "current approved Keeper charter" in controller._get_error()


def test_completion_feedback_explains_next_required_action() -> None:
    completed = [SimpleNamespace(state="COMPLETED", detail="Done")]
    blocked = [
        SimpleNamespace(
            state="BLOCKED",
            detail="Independent reviewer is unavailable.",
        )
    ]

    assert _completion_feedback(completed) == (
        "Approved work is complete",
        "",
        True,
    )
    assert _completion_feedback(blocked) == (
        "Keeper reached the approved charter boundary",
        "Independent reviewer is unavailable.",
        False,
    )


def test_delegated_charter_approval_starts_work_automatically(
    controller: KeeperDesktopController,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller._state = {
        "project": {
            "approvalCharter": {
                "charter_id": "charter-1",
                "revision": 2,
            }
        }
    }
    calls: list[str] = []
    monkeypatch.setattr(
        controller.pass_b,
        "selected_project_id",
        lambda: "project-1",
    )
    monkeypatch.setattr(
        controller.pass_b,
        "approve_and_plan_current_charter",
        lambda *args, **kwargs: {
            "charter": {"delegation_mode": "DELEGATED"}
        },
    )
    monkeypatch.setattr(
        controller.pass_b,
        "run_delegated_completion",
        lambda project_id: calls.append(project_id)
        or [SimpleNamespace(state="COMPLETED", detail="Done")],
    )
    monkeypatch.setattr(controller, "_refresh_state_only", lambda: None)

    controller.approveCurrentCharter()
    deadline = time.monotonic() + 2
    while controller._get_busy() and time.monotonic() < deadline:
        time.sleep(0.01)

    assert calls == ["project-1"]
    assert controller._get_status() == (
        "Charter approved. Approved work is complete"
    )
    assert controller._get_error() == ""


def test_unknown_navigation_and_run_actions_fail_closed(
    controller: KeeperDesktopController,
) -> None:
    controller.navigate("Not A Keeper Page")
    assert controller._get_current_page() == "Overview"

    controller.runAction("fabricated-run", "launch-provider")
    assert controller._get_status() == "Action could not be completed"
    assert "Unsupported run action" in controller._get_error()


def test_qml_has_no_sage_surface_and_disables_unsupported_authority() -> None:
    qml = (
        Path(__file__).parents[2] / "keeper" / "ui_qml" / "qml" / "Main.qml"
    ).read_text(encoding="utf-8")
    assert "Sage" not in qml
    assert 'actionText: "+ Register Provider"; actionEnabled: false' in qml
    assert 'actionText: "+ New Authorization"; actionEnabled: false' in qml
    assert "Keeper Assistant" in qml
    assert "paid fallback is disabled" in qml


def test_authority_health_projection_drops_private_service_paths(
    controller: KeeperDesktopController,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    diagnostics = controller.application.diagnostics()
    diagnostics["authority_service_status"] = "available"
    diagnostics["authority_service"] = {
        "service_version": "unsafe-general-diagnostics",
        "service_root": r"C:\ProgramData\Keeper\AuthorityService\data",
        "client_sid": "S-1-5-private",
        "allowed_evidence_root": r"C:\ProgramData\Keeper\evidence",
    }
    monkeypatch.setattr(controller.application, "diagnostics", lambda: diagnostics)

    controller.refresh()

    authority = controller.state_snapshot()["diagnostics"]["authority"]
    rendered = repr(authority)
    assert authority["service_version"] == "test-health-only"
    assert authority["protocol_version"] == 7
    assert "ProgramData" not in rendered
    assert "S-1-5-private" not in rendered
    assert "service_root" not in authority


def test_qml_search_and_narrow_assistant_are_real_and_source_backed() -> None:
    qml = (
        Path(__file__).parents[2] / "keeper" / "ui_qml" / "qml" / "Main.qml"
    ).read_text(encoding="utf-8")
    assert "function filtered(values)" in qml
    assert "onTextChanged: window.searchQuery = text" in qml
    assert "model: filtered(keeper.state.evidenceReferences || [])" in qml
    assert "readonly property bool opened: userOpened" in qml
    assert 'keeper.navigate("Keeper")' in qml
    assert "keeper.startTask(modelData.id)" in qml
    assert "keeper.runAction(modelData.run_id, modelData.recovery_action)" in qml
    assert "keeper.exportRunReport(window.selectedRunId, selectedFile)" in qml
    assert "Math.min(460, Math.max(120, emptyRoot.width - 24))" in qml
    assert 'objectName: "delegatedModeDialog"' in qml
    assert 'objectName: "prepareDelegatedMode"' in qml
    assert "window.workflowActionText()" in qml
    assert "window.handleWorkflowAction()" in qml
    assert "window.workflowStatusText()" in qml
    assert "keeper.createSimpleTask(taskTitle.text, taskObjective.text)" in qml
    assert 'actionText: "+ Talk to Keeper"' in qml
    assert 'actionText: "Advanced: Add Task"' in qml
    assert "without asking you to manage tasks or workflows" in qml
    assert 'objectName: "keeperChatList"' in qml
    assert 'objectName: "conversationProviderSelector"' in qml
    assert "keeper.selectConversationProvider(currentValue)" in qml
    assert 'property bool followingNewest: true' in qml
    assert "ScrollBar.vertical: ScrollBar" in qml
    assert "if (moving && !atYEnd)" in qml
    assert 'text: "Jump to newest"' in qml


def test_recovery_projects_pass_b_uncertainty_and_founder_disposition(
    controller: KeeperDesktopController,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    product_snapshot = controller.pass_b.product_snapshot()
    monkeypatch.setattr(
        controller.pass_b, "product_snapshot", lambda: product_snapshot
    )
    original_list = controller.pass_b.repository.list
    uncertain_assignment = SimpleNamespace(
        assignment_id="uncertain-assignment-1",
        project_id="project-1",
        workflow_id="workflow-1",
        work_item_id="work-item-1",
        provider_id="codex",
        state=AssignmentState.UNCERTAIN,
    )
    uncertain_attempt = SimpleNamespace(
        assignment_id="uncertain-assignment-1",
        attempt_id="uncertain-attempt-1",
        state=AttemptState.UNCERTAIN,
        uncertainty_kind="EXTERNAL_EXECUTION_OUTCOME_AMBIGUOUS",
    )

    def repository_list(record_type: type[object], **filters: object) -> list[object]:
        if record_type is AssignmentRecord:
            return [uncertain_assignment]
        if record_type is AttemptRecord:
            return [uncertain_attempt]
        return original_list(record_type, **filters)

    monkeypatch.setattr(controller.pass_b.repository, "list", repository_list)

    controller.refresh()

    state = controller.state_snapshot()
    assert state["counts"]["uncertain"] == 1
    assert len(state["recoveries"]) == 1
    recovery = state["recoveries"][0]
    assert recovery == {
        "id": "uncertain-assignment-1",
        "assignment_id": "uncertain-assignment-1",
        "attempt_id": "uncertain-attempt-1",
        "project_id": "project-1",
        "workflow_id": "workflow-1",
        "work_item_id": "work-item-1",
        "provider_id": "codex",
        "source": "pass_b_uncertain_execution",
        "status": "UNCERTAIN",
        "reason": (
            "External execution outcome remains possible. "
            "Founder disposition is required; no result or retry "
            "will be accepted."
        ),
    }
    qml = (
        Path(__file__).parents[2] / "keeper" / "ui_qml" / "qml" / "Main.qml"
    ).read_text(encoding="utf-8")
    assert 'text: "Resolve safely"' in qml
    assert "keeper.resolveUncertainExecution(modelData.assignment_id)" in qml


def test_rendered_smoke_contract_covers_all_pages_at_wide_and_minimum() -> None:
    source = (
        Path(__file__).parents[2] / "keeper" / "ui_qml" / "app.py"
    ).read_text(encoding="utf-8")
    assert '("wide", 1600, 960)' in source
    assert '("minimum", 1120, 700)' in source
    assert "for page in NAVIGATION" in source
    assert '"rendered_frames": captured_frames' in source


def test_keeper_chat_shows_pending_work_and_preserves_failed_messages() -> None:
    qml = (
        Path(__file__).parents[2] / "keeper" / "ui_qml" / "qml" / "Main.qml"
    ).read_text(encoding="utf-8")

    assert 'property string pendingConversationText: ""' in qml
    assert 'property string failedConversationText: ""' in qml
    assert '"title": "Founder • Sending"' in qml
    assert '"localState": "working"' in qml
    assert "window.failedConversationText = window.pendingConversationText" in qml
    assert 'text: "Edit & retry"' in qml
    assert "keeper.sendAssistantMessage(outgoing)" in qml
    assert "keeper.saveConversationDraft(outgoing)" in qml
    assert "Ctrl+Enter to send" in qml

def _is_primitive(value: object) -> bool:
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, list):
        return all(_is_primitive(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _is_primitive(item)
            for key, item in value.items()
        )
    return False

def test_local_paths_are_redacted_before_qml(
    controller: KeeperDesktopController, tmp_path: Path
) -> None:
    controller.application.store.upsert(
        "projects",
        "private-project",
        {
            "id": "private-project",
            "name": "Private project",
            "repository": str(tmp_path / "private-repository"),
            "branch": "main",
            "protected_original": True,
            "worktrees": [str(tmp_path / "private-worktree")],
        },
    )
    controller.application.store.upsert(
        "runs",
        "private-run",
        {
            "id": "private-run",
            "task_id": "task-1",
            "status": "paused",
            "evidence_root": str(tmp_path / "private-evidence"),
        },
    )
    controller.refresh()

    snapshot = controller.state_snapshot()
    assert str(tmp_path) not in repr(snapshot)
    assert snapshot["projects"][0]["repository"].startswith("Local path configured")
    assert snapshot["runs"][0]["evidence_root"].startswith("Local path configured")


def test_provider_path_requires_existing_file_and_never_registers(
    controller: KeeperDesktopController, tmp_path: Path
) -> None:
    missing = tmp_path / "missing-provider.exe"
    controller.setProviderPath("offline", str(missing))
    assert controller.application.provider_paths() == {}
    assert "existing file" in controller._get_error()

    executable = tmp_path / "offline-provider.exe"
    executable.write_bytes(b"offline")
    controller.setProviderPath("offline", str(executable))
    assert controller.application.provider_paths()["offline"] == str(executable)
    assert controller.application.provider_registrations() == {}
    assert str(executable) not in repr(controller.state_snapshot())


def test_qml_exposes_visible_setup_errors_and_first_provider_configuration() -> None:
    qml = (
        Path(__file__).parents[2] / "keeper" / "ui_qml" / "qml" / "Main.qml"
    ).read_text(encoding="utf-8")
    assert 'objectName: "setupRetry"' in qml
    assert 'visible: keeper.error.length > 0' in qml
    assert 'id: settingsProviderName' in qml
    assert 'id: settingsProviderPath' in qml
    assert 'text: "Validate & Save"' in qml
    assert 'folderDialog.mode = "settingsEvidence"' in qml

def test_repaired_controls_call_exact_supported_services(
    controller: KeeperDesktopController,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    controller.application.store.upsert(
        "tasks",
        "task-1",
        {
            "id": "task-1",
            "status": "INTAKE",
            "repository": str(tmp_path),
            "keeper_project_id": None,
        },
    )
    monkeypatch.setattr(
        controller.application,
        "start_task",
        lambda task_id: calls.append(("start", task_id)),
    )
    monkeypatch.setattr(
        controller.pass_b.orchestration,
        "create_repair_assignment",
        lambda review_id: calls.append(("repair", review_id)),
    )
    monkeypatch.setattr(
        controller.application,
        "export_run_report",
        lambda run_id, destination: calls.append(
            ("export", run_id, Path(destination))
        ),
    )

    controller.startTask("task-1")
    controller.createRepair("review-1")
    destination = tmp_path / "report.json"
    controller.exportRunReport("run-1", str(destination))

    assert calls == [
        ("start", "task-1"),
        ("repair", "review-1"),
        ("export", "run-1", destination.resolve()),
    ]


def test_validated_evidence_preview_recursively_redacts_paths(
    controller: KeeperDesktopController,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private" / "provider.log"
    monkeypatch.setattr(
        controller.application,
        "evidence_details",
        lambda run_id, category: {
            "run_id": run_id,
            "category": category,
            "details": [
                {
                    "path": str(private),
                    "nested": {"workspace_root": str(tmp_path / "workspace")},
                    "recent_output": "safe redacted text",
                }
            ],
        },
    )

    preview = controller.evidenceDetails("run-1", "logs")

    assert str(tmp_path) not in repr(preview)
    assert preview["details"][0]["path"] == "Local path configured (redacted)"
    assert preview["details"][0]["nested"]["workspace_root"] == (
        "Local path configured (redacted)"
    )
    assert preview["details"][0]["recent_output"] == "safe redacted text"


def test_settings_evidence_directory_is_validated_before_persistence(
    controller: KeeperDesktopController,
    tmp_path: Path,
) -> None:
    protected = tmp_path / ".ai-workflow" / "pw" / "evidence"
    controller.setEvidenceDirectory(str(protected))
    assert "protected" in controller._get_error().lower()

    selected = tmp_path / "keeper-evidence"
    controller.setEvidenceDirectory(str(selected))
    settings = controller.application.store.get("settings", "application") or {}
    assert settings["evidence_directory"] == str(selected.resolve())
    assert not list(selected.glob(".keeper-write-probe-*"))


def test_qml_wires_validated_evidence_preview_and_no_raw_open() -> None:
    qml = (
        Path(__file__).parents[2] / "keeper" / "ui_qml" / "qml" / "Main.qml"
    ).read_text(encoding="utf-8")
    assert 'text: "Preview logs"' in qml
    assert 'keeper.evidenceDetails(modelData.id, "logs")' in qml
    assert "openUrlExternally" not in qml

def test_qml_task_finding_project_controls_and_responsive_assistant() -> None:
    qml = (
        Path(__file__).parents[2] / "keeper" / "ui_qml" / "qml" / "Main.qml"
    ).read_text(encoding="utf-8")
    assert "function filteredProjects()" in qml
    assert "function taskFilteredRows()" in qml
    assert "function taskPageRows()" in qml
    assert "function taskSafePage()" in qml
    assert "function filteredFindings()" in qml
    assert "model: taskPageRows()" in qml
    assert 'text: "Previous"' in qml
    assert 'text: "Next"' in qml
    assert "settingsProviderName.clear(); settingsProviderPath.clear()" in qml
    assert "userOpened && window.width >= 1360" in qml
    assert 'objectName: "narrowAssistantDialog"' in qml
    assert "if (window.width < 1360) narrowAssistantDialog.open()" in qml
    assert "if (width >= 1360 && narrowAssistantDialog.visible)" in qml
    assert "window.width < 1300 ? 210 : 248" in qml
    assert "Layout.preferredHeight: 380" in qml


def test_qml_reports_filter_exportable_and_pending_runs() -> None:
    qml = (
        Path(__file__).parents[2] / "keeper" / "ui_qml" / "qml" / "Main.qml"
    ).read_text(encoding="utf-8")
    assert 'property string reportAvailabilityFilter: "ALL"' in qml
    assert "function reportRows()" in qml
    assert 'model: ["ALL", "EXPORTABLE", "PENDING"]' in qml
    assert "model: reportRows()" in qml


def test_qml_filters_provider_health_and_recovery_action_state() -> None:
    qml = (
        Path(__file__).parents[2] / "keeper" / "ui_qml" / "qml" / "Main.qml"
    ).read_text(encoding="utf-8")
    assert 'model: ["ALL", "READY", "NOT READY"]' in qml
    assert "function providerRows()" in qml
    assert "model: providerRows()" in qml
    assert 'model: ["ALL", "UNCERTAIN", "RESUMABLE"]' in qml
    assert "function recoveryRows()" in qml
    assert "model: recoveryRows()" in qml
    for state in (
        "BACKLOG",
        "READY",
        "BUILDING",
        "SELF_VERIFYING",
        "INDEPENDENT_AUDIT",
        "REPAIRING",
        "FINAL_VERIFY",
        "APPROVED",
        "COMPLETED",
        "BLOCKED",
        "FAILED",
        "PAUSED",
        "CANCELLED",
    ):
        assert f'"{state}"' in qml
    assert '"CHARTER_DRAFT", "AWAITING_CHARTER_APPROVAL"' in qml
    assert '"WAITING_FOR_USAGE_RESET", "WAITING_FOR_FOUNDER"' in qml
    assert '"RECOVERY_REQUIRED", "UNKNOWN"' in qml
    assert 'text: "Page " + (taskSafePage() + 1)' in qml


def test_setup_finish_revalidates_protected_storage(
    tmp_path: Path,
) -> None:
    application = KeeperApplication(tmp_path / "data")
    setup = ProductSetupController(application)
    setup.index = 6
    setup.evidence_directory = str(tmp_path / ".ai-workflow" / "pw" / "evidence")

    with pytest.raises((ValueError, OSError)):
        setup.finish()

    assert application.store.get("settings", "setup") is None


def test_desktop_error_messages_redact_local_and_network_paths() -> None:
    message = _safe_error_message(
        r"Could not open C:\Program Files\Founder Name\secret.txt"
    )
    assert "Founder" not in message
    assert "Program Files" not in message
    assert "secret.txt" not in message
    assert "[local path redacted]" in message

    network_message = _safe_error_message(
        r"Could not open \\server\private share\evidence.bin"
    )
    assert "server" not in network_message
    assert "private share" not in network_message


def test_provider_diagnostics_error_is_redacted(
    controller: KeeperDesktopController, monkeypatch: pytest.MonkeyPatch
) -> None:
    diagnostics = controller.application.diagnostics()
    diagnostics["provider_diagnostics_error"] = (
        r"Provider failed at C:\Program Files\Founder Name\provider.exe"
    )
    monkeypatch.setattr(controller.application, "diagnostics", lambda: diagnostics)

    snapshot = controller._build_state()

    error = str(snapshot["diagnostics"]["providerError"])
    assert "Program Files" not in error
    assert "Founder Name" not in error
    assert "[local path redacted]" in error

def test_free_form_durable_record_paths_are_redacted(
    controller: KeeperDesktopController,
) -> None:
    controller.application.store.upsert(
        "runs",
        "run-redaction",
        {
            "id": "run-redaction",
            "status": "FAILED",
            "error": r"Provider failed at C:\Program Files\Founder Name\secret.txt",
            "failure_reason": r"Could not open \\server\private share\evidence.bin",
        },
    )

    snapshot = controller._build_state()
    run = next(item for item in snapshot["runs"] if item["id"] == "run-redaction")

    assert "Program Files" not in run["error"]
    assert "Founder Name" not in run["error"]
    assert "server" not in run["failure_reason"]
    assert "private share" not in run["failure_reason"]
    assert run["error"].endswith("[local path redacted]")
