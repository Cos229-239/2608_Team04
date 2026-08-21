from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from keeper.app.service import KeeperApplication
from keeper.pass_b.application import PassBApplication
from keeper.ui_qml.composition import ProductSetupController
from keeper.ui_qml.controller import (
    KeeperDesktopController,
    NAVIGATION,
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
    assert "assistantDrawer.userOpened = true" in qml
    assert "keeper.startTask(modelData.id)" in qml
    assert "keeper.runAction(modelData.run_id, \"resume\")" in qml
    assert "keeper.exportRunReport(window.selectedRunId, selectedFile)" in qml
    assert "Math.min(460, Math.max(120, emptyRoot.width - 24))" in qml


def test_rendered_smoke_contract_covers_all_pages_at_wide_and_minimum() -> None:
    source = (
        Path(__file__).parents[2] / "keeper" / "ui_qml" / "app.py"
    ).read_text(encoding="utf-8")
    assert '("wide", 1600, 960)' in source
    assert '("minimum", 1120, 700)' in source
    assert "for page in NAVIGATION" in source
    assert '"rendered_frames": captured_frames' in source

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
