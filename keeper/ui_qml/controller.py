from __future__ import annotations

import dataclasses
import re
import threading
from pathlib import Path
from typing import Any, Callable, cast

from PySide6.QtCore import QObject, Property, QUrl, Signal, Slot

from keeper.app.service import KeeperApplication
from keeper.pass_b.application import PassBApplication
from keeper.ui_qml.composition import (
    ProductSetupController,
    desktop_pass_b_application,
)
from keeper.ui.view_models import ProductViewModel, build_product_view


NAVIGATION: tuple[str, ...] = (
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


def _primitive(value: object) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _primitive(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): _primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_primitive(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _public_path(value: object) -> str:
    """Return a display-safe classification without leaking any local path part."""
    return "Local path configured (redacted)" if str(value or "") else "Not configured"


def _safe_error_message(value: object) -> str:
    """Keep actionable errors while redacting local and network filesystem paths."""
    message = str(value or "Operation failed")
    patterns = (
        r"(?im)(?:file:///)?[A-Z]:[\\/].*$",
        r"(?m)\\\\.*$",
        r"(?im)/(?:Users|home)/.*$",
    )
    for pattern in patterns:
        message = re.sub(pattern, "[local path redacted]", message)
    return message


_PRIVATE_PATH_FIELDS = {
    "repository",
    "repository_path",
    "workspace",
    "workspace_path",
    "workspace_root",
    "evidence_root",
    "path",
    "executable",
    "source_path",
}


def _public_value(key: str, value: object) -> Any:
    lowered = key.lower()
    if (
        lowered in _PRIVATE_PATH_FIELDS
        or lowered.endswith("_path")
        or lowered.endswith("_root")
        or lowered.endswith("_directory")
    ):
        return _public_path(value)
    if lowered == "worktrees":
        return "Protected worktrees recorded" if value else []
    if lowered in {"error", "message", "reason", "detail", "failure_reason"} and isinstance(value, str):
        return _safe_error_message(value)
    if isinstance(value, dict):
        return _public_record(value)
    if isinstance(value, (list, tuple, set)):
        return [
            _public_record(item) if isinstance(item, dict) else _primitive(item)
            for item in value
        ]
    return _primitive(value)


def _public_record(value: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact filesystem authority before a record crosses into QML."""
    return {str(key): _public_value(str(key), item) for key, item in value.items()}


class KeeperDesktopController(QObject):
    """Thin Qt adapter over durable Keeper application services.

    QML receives primitive, redacted snapshots only. Every write routes through
    an existing application or Pass B service method.
    """

    stateChanged = Signal()
    currentPageChanged = Signal()
    busyChanged = Signal()
    statusChanged = Signal()
    setupChanged = Signal()
    operationFinished = Signal(str, bool)

    def __init__(
        self,
        application: KeeperApplication,
        *,
        pass_b_application: PassBApplication | None = None,
        test_fixture: bool = False,
    ) -> None:
        super().__init__()
        self.application = application
        self.pass_b = pass_b_application or desktop_pass_b_application(application)
        self._current_page = "Overview"
        self._busy = False
        self._status = "Ready"
        self._error = ""
        self._developer_details = False
        self._test_fixture = test_fixture
        self._setup = ProductSetupController(application)
        self._state: dict[str, Any] = {}
        self.refresh()

    def _get_state(self) -> dict[str, Any]:
        return self._state

    def state_snapshot(self) -> dict[str, Any]:
        return self._state

    state = Property(dict, _get_state, notify=stateChanged)

    def _get_current_page(self) -> str:
        return self._current_page

    def _set_current_page(self, value: str) -> None:
        if value not in NAVIGATION or value == self._current_page:
            return
        self._current_page = value
        self.currentPageChanged.emit()

    currentPage = Property(
        str, _get_current_page, _set_current_page, notify=currentPageChanged
    )

    def _get_busy(self) -> bool:
        return self._busy

    busy = Property(bool, _get_busy, notify=busyChanged)

    def _get_status(self) -> str:
        return self._status

    status = Property(str, _get_status, notify=statusChanged)

    def _get_error(self) -> str:
        return self._error

    error = Property(str, _get_error, notify=statusChanged)

    def _get_setup_required(self) -> bool:
        return not self.application.setup_complete()

    setupRequired = Property(bool, _get_setup_required, notify=setupChanged)

    def _get_setup_index(self) -> int:
        return self._setup.index

    setupIndex = Property(int, _get_setup_index, notify=setupChanged)

    def _get_setup_draft(self) -> dict[str, Any]:
        return {
            "evidenceDirectory": self._setup.evidence_directory,
            "repository": self._setup.repository,
            "providerPolicy": self._setup.provider_policy,
        }

    setupDraft = Property(dict, _get_setup_draft, notify=setupChanged)

    @Slot(str)
    def navigate(self, page: str) -> None:
        self._set_current_page(page)

    @Slot()
    def refresh(self) -> None:
        self._run("Durable state refreshed", self._build_state, result_to_state=True)

    def _build_state(self) -> dict[str, Any]:
        snapshot = self.pass_b.product_snapshot()
        view = build_product_view(snapshot, developer_details=self._developer_details)
        diagnostics = self.application.diagnostics()
        authority_health = next(
            (
                dict(row.get("detail", {}))
                for row in view.safety_rows
                if row.get("label") == "KeeperAuthority"
            ),
            {},
        )
        runs = [
            _public_record(item) for item in self.application.store.list("runs")
        ]
        projects = [_public_record(item) for item in self.application.projects()]
        tasks = [_public_record(item) for item in self.application.tasks()]
        findings = [
            _public_record(item) for item in self.application.store.list("findings")
        ]
        authorizations = [
            _public_record(item)
            for item in self.application.store.list("authorizations")
        ]
        recoveries = [
            _public_record(item) for item in self.application.recover_runs()
        ]
        settings = self.application.store.get("settings", "application") or {}
        state = {
            "navigation": list(NAVIGATION),
            "environment": (
                "TEST UI FIXTURE"
                if self._test_fixture
                else str(
                    snapshot.get("authority", {}).get(
                        "composition", view.composition
                    )
                )
            ),
            "testFixture": self._test_fixture,
            "version": diagnostics.get("keeper_version", "unknown"),
            "project": {
                "id": view.project_id,
                "title": view.project_title,
                "status": view.project_status,
                "charterRevision": view.charter_revision,
                "cards": view.project_cards,
                "catalog": view.project_catalog,
                "charter": view.charter_detail,
                "approvalCharter": view.approval_charter_detail,
                "approvalRequired": view.approval_required,
            },
            "timeline": view.timeline,
            "workflows": view.workflow_rows,
            "providers": view.provider_cards,
            "providerHost": view.provider_host,
            "usage": view.usage_cards,
            "evidence": view.evidence_cards,
            "evidenceReferences": view.evidence_reference_cards,
            "reviews": view.review_cards,
            "safety": view.safety_rows,
            "rightRail": view.right_rail,
            "projects": projects,
            "tasks": tasks,
            "runs": runs,
            "findings": findings,
            "authorizations": authorizations,
            "recoveries": recoveries,

            "diagnostics": {
                "authorityStatus": authority_health.get("state", "NOT_CONFIGURED"),
                "authority": authority_health,
                "gitAvailable": diagnostics.get("git_available"),
                "dataDirectoryWritable": diagnostics.get("data_directory_writable"),
                "providerError": (
                    _safe_error_message(diagnostics.get("provider_diagnostics_error"))
                    if diagnostics.get("provider_diagnostics_error")
                    else None
                ),
            },
            "settings": {
                "theme": settings.get("theme", "Keeper Gold"),
                "localOnly": diagnostics.get("local_only", True),
                "developerDetails": self._developer_details,
                "evidenceDirectory": _public_path(settings.get("evidence_directory")),
                "providerPaths": {
                    provider: _public_path(path)
                    for provider, path in self.application.provider_paths().items()
                },
            },
            "counts": {
                "projects": len(view.project_catalog) + len(projects),
                "workflows": len(view.workflow_rows),
                "tasks": len(tasks),
                "findings": len(findings),
                "approvals": int(view.approval_required),
                "providers": len(view.provider_cards),
                "evidence": len(view.evidence_cards) + len(view.evidence_reference_cards),
                "uncertain": sum(
                    1 for row in runs if str(row.get("status", "")).upper() == "UNCERTAIN"
                ),
            },
        }
        return cast(dict[str, Any], _primitive(state))

    @Slot(str)
    def selectProject(self, project_id: str) -> None:
        self._run("Project selected", lambda: self.pass_b.select_project(project_id))

    @Slot(str)
    def sendAssistantMessage(self, message: str) -> None:
        clean = message.strip()
        if not clean:
            self._fail("Describe the project or ask Keeper a question first.")
            return
        project_id = self.pass_b.selected_project_id()
        operation: Callable[[], object] = (
            (lambda: self.pass_b.continue_conversation(project_id, clean))
            if project_id
            else (lambda: self.pass_b.begin_conversation(clean))
        )
        self._run("Keeper recorded the conversation", operation)

    @Slot()
    def approveCurrentCharter(self) -> None:
        project_id = self.pass_b.selected_project_id()
        approval = self._state.get("project", {}).get("approvalCharter", {})
        if not project_id or not approval:
            self._fail("There is no current charter awaiting Founder approval.")
            return
        self._run(
            "Founder-approved charter activated and planned",
            lambda: self.pass_b.approve_and_plan_current_charter(
                project_id,
                expected_charter_id=str(approval.get("charter_id")),
                expected_charter_revision=int(approval.get("revision")),
            ),
        )

    @Slot()
    def runDelegatedCompletion(self) -> None:
        project_id = self.pass_b.selected_project_id()
        if not project_id:
            self._fail("Select a Keeper project before running completion.")
            return
        if self._busy:
            return
        self._busy = True
        self._status = "Keeper is advancing the approved workflow"
        self._error = ""
        self.busyChanged.emit()
        self.statusChanged.emit()

        def worker() -> None:
            try:
                self.pass_b.run_delegated_completion(project_id)
            except Exception as error:  # UI boundary reports a safe failure.
                self._status = "Completion paused"
                self._error = str(error)
                success = False
            else:
                self._status = "Completion advanced to its next durable boundary"
                success = True
            self._busy = False
            self.busyChanged.emit()
            self.statusChanged.emit()
            self.operationFinished.emit(self._status, success)
            self.refresh()

        threading.Thread(target=worker, name="keeper-completion", daemon=True).start()

    @Slot(str, str)
    def addRepository(self, path_value: str, name: str) -> None:
        path = self._local_path(path_value)
        self._run("Repository added as a protected project", lambda: self.application.add_project(path, name or None))

    @Slot(str, str, str, str)
    def createTask(self, title: str, objective: str, baseline: str, branch: str) -> None:
        self._run(
            "Task created",
            lambda: self.application.create_task(
                {
                    "title": title,
                    "objective": objective,
                    "baseline": baseline,
                    "target_branch": branch,
                    "allowed_actions": ["READ", "WRITE", "RUN_TESTS"],
                    "prohibited_actions": ["PUSH", "DEPLOY", "SPEND", "LIVE_TRADING"],
                }
            ),
        )

    @Slot(str)
    def startTask(self, task_id: str) -> None:
        self._run(
            "Task started through the validated workflow service",
            lambda: self.application.start_task(task_id),
        )

    @Slot(str)
    def createRepair(self, review_id: str) -> None:
        self._run(
            "Bounded repair assignment created",
            lambda: self.pass_b.orchestration.create_repair_assignment(review_id),
        )

    @Slot(str, str, result="QVariantMap")
    def evidenceDetails(self, run_id: str, category: str) -> dict[str, Any]:
        try:
            details = self.application.evidence_details(run_id, category)
        except Exception as error:
            self._fail(str(error))
            return {}
        safe = _public_record(details)
        self._status, self._error = "Validated evidence details loaded", ""
        self.statusChanged.emit()
        self.operationFinished.emit(self._status, True)
        return safe

    @Slot(str, str)
    def exportRunReport(self, run_id: str, destination: str) -> None:
        target = self._local_path(destination)
        self._run(
            "Validated run report exported",
            lambda: self.application.export_run_report(run_id, target),
        )

    @Slot(str, str)
    def runAction(self, run_id: str, action: str) -> None:
        operations: dict[str, Callable[[], object]] = {
            "pause": lambda: self.application.pause_run(run_id),
            "resume": lambda: self.application.resume_run(run_id),
            "cancel": lambda: self.application.cancel_run(run_id),
            "retry": lambda: self.application.retry_run(run_id, "Explicit desktop recovery"),
        }
        operation = operations.get(action)
        if operation is None:
            self._fail(f"Unsupported run action: {action}")
            return
        self._run(f"Run action completed: {action}", operation)

    @Slot(str)
    def revokeAuthorization(self, authorization_id: str) -> None:
        self._run("Authorization revoked", lambda: self.application.revoke_authorization(authorization_id))

    @Slot(bool)
    def setDeveloperDetails(self, enabled: bool) -> None:
        self._developer_details = enabled
        self.refresh()

    @Slot(str, str)
    def setProviderPath(self, provider: str, path_value: str) -> None:
        provider_name = provider.strip().lower()
        if not provider_name:
            self._fail("Enter a provider name before saving its executable path.")
            return
        candidate = self._local_path(path_value)
        if not candidate.is_file():
            self._fail("Provider executable path must identify an existing file.")
            return
        paths = self.application.provider_paths()
        paths[provider_name] = str(candidate)
        self._run(
            "Provider path saved; qualification is still required",
            lambda: self.application.save_provider_paths(paths),
        )

    @Slot(str)
    def setEvidenceDirectory(self, path_value: str) -> None:
        candidate = self._local_path(path_value)

        def save() -> None:
            validated = self._setup.validate_evidence_directory(candidate)
            settings = self.application.store.get("settings", "application") or {}
            settings["evidence_directory"] = str(validated)
            self.application.store.upsert("settings", "application", settings)

        self._run("Evidence directory validated and saved", save)

    @Slot()
    def resetPresentationSettings(self) -> None:
        self._developer_details = False
        self._run(
            "Presentation reset; durable evidence and provider settings preserved",
            lambda: None,
        )

    @Slot(str, str)
    def setSetupValue(self, key: str, value: str) -> None:
        if key == "evidenceDirectory":
            self._setup.evidence_directory = str(self._local_path(value))
        elif key == "repository":
            self._setup.repository = str(self._local_path(value)) if value else ""
        elif key == "providerPolicy":
            self._setup.provider_policy = value
        else:
            self._fail(f"Unsupported setup field: {key}")
            return
        self.setupChanged.emit()

    @Slot()
    def setupNext(self) -> None:
        self._run_setup("Setup step validated", self._setup.next)

    @Slot()
    def setupBack(self) -> None:
        self._setup.back()
        self.setupChanged.emit()

    @Slot()
    def finishSetup(self) -> None:
        self._run_setup("Keeper setup complete", self._setup.finish, refresh=True)

    def _run_setup(self, success: str, operation: Callable[[], object], *, refresh: bool = False) -> None:
        try:
            operation()
        except Exception as error:
            self._fail(str(error))
            return
        self._status, self._error = success, ""
        self.statusChanged.emit()
        self.setupChanged.emit()
        if refresh:
            self.refresh()

    def _run(
        self,
        success: str,
        operation: Callable[[], object],
        *,
        result_to_state: bool = False,
    ) -> None:
        try:
            result = operation()
        except Exception as error:
            self._fail(str(error))
            return
        if result_to_state:
            self._state = dict(result) if isinstance(result, dict) else {}
            self.stateChanged.emit()
        self._status, self._error = success, ""
        self.statusChanged.emit()
        if not result_to_state:
            state = self._build_state()
            self._state = state
            self.stateChanged.emit()
        self.operationFinished.emit(success, True)

    def _fail(self, message: str) -> None:
        safe_message = _safe_error_message(message)
        self._status = "Action could not be completed"
        self._error = safe_message
        self.statusChanged.emit()
        self.operationFinished.emit(safe_message, False)

    @staticmethod
    def _local_path(value: str) -> Path:
        url = QUrl(value)
        return Path(url.toLocalFile() if url.isLocalFile() else value).resolve()


__all__ = ["KeeperDesktopController", "NAVIGATION"]
