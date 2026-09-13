from __future__ import annotations

import dataclasses
import re
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, cast

from PySide6.QtCore import QObject, Property, QUrl, Signal, Slot

from keeper.app.service import KeeperApplication
from keeper.executive.models import FounderApprovalChallenge
from keeper.pass_b.application import PassBApplication
from keeper.pass_b.enums import AssignmentState, AttemptState
from keeper.pass_b.models import AssignmentRecord, AttemptRecord
from keeper.ui_qml.composition import (
    ProductSetupController,
    desktop_pass_b_application,
)
from keeper.ui.view_models import ProductViewModel, build_product_view


NAVIGATION: tuple[str, ...] = (
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


def _primitive(value: object) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _primitive(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): _primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_primitive(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        # QVariant exposes Python integers to QML as signed 64-bit values.
        # Windows file identities are unsigned and may exceed that range;
        # preserve their exact display value as text instead of allowing the
        # entire state-map conversion to overflow and disappear from the UI.
        return value if -(2**63) <= value <= (2**63 - 1) else str(value)
    if value is None or isinstance(value, (str, float)):
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


def _completion_feedback(results: object) -> tuple[str, str, bool]:
    steps = tuple(results) if isinstance(results, (list, tuple)) else ()
    final = steps[-1] if steps else None
    state = str(getattr(final, "state", "BLOCKED")).upper()
    detail = str(getattr(final, "detail", "No workflow step was available."))
    if state == "COMPLETED":
        return "Approved work is complete", "", True
    if state == "PROGRESS":
        return detail, "", True
    if state == "WAITING_FOR_USAGE_RESET":
        return "Keeper exhausted the approved provider options", detail, False
    if state == "UNCERTAIN":
        return "Keeper preserved an uncertain external result", detail, False
    return "Keeper reached the approved charter boundary", detail, False


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
    conversationDraftChanged = Signal()
    operationFinished = Signal(str, bool)
    _asyncFinished = Signal(object, str, str, bool)

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
        self._new_project_intake = False
        stored_draft = self.application.store.get(
            "settings", "conversation_draft"
        )
        self._conversation_draft = str(
            (stored_draft or {}).get("message") or ""
        )
        self._test_fixture = test_fixture
        self._setup = ProductSetupController(application)
        self._state: dict[str, Any] = {}
        self._asyncFinished.connect(self._finish_async)
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

    def _get_conversation_draft(self) -> str:
        return self._conversation_draft

    conversationDraft = Property(
        str, _get_conversation_draft, notify=conversationDraftChanged
    )

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

    def _refresh_state_only(self) -> None:
        """Refresh presentation data without replacing useful operation feedback."""
        self._state = self._build_state()
        self.stateChanged.emit()

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
        legacy_active = self.application.active_project()
        selected_project_id = view.project_id or (
            f"repository:{legacy_active['id']}" if legacy_active else None
        )
        selected_charter = view.charter_detail
        all_tasks = self.application.tasks()
        scoped_tasks = (
            all_tasks
            if self._test_fixture and view.project_id is None
            else [
                item
                for item in all_tasks
                if selected_project_id
                and item.get("keeper_project_id") == selected_project_id
                and (
                    view.project_id is None
                    or (
                        item.get("keeper_charter_id")
                        == selected_charter.get("charter_id")
                        and item.get("keeper_charter_revision")
                        == selected_charter.get("revision")
                        and item.get("keeper_founder_approval_record_id")
                        == selected_charter.get("founder_approval_record_id")
                        and item.get("keeper_founder_approval_identity")
                        == selected_charter.get("founder_approval_identity")
                    )
                )
            ]
        )
        scoped_task_ids = {str(item.get("id", "")) for item in scoped_tasks}
        all_runs = self.application.store.list("runs")
        raw_runs = (
            all_runs
            if self._test_fixture and view.project_id is None
            else [
                item
                for item in all_runs
                if str(item.get("task_id", "")) in scoped_task_ids
            ]
        )
        runs = [_public_record(item) for item in raw_runs]
        projects = [_public_record(item) for item in self.application.projects()]
        live_run_by_task = {
            str(item.get("task_id", "")): item
            for item in raw_runs
            if str(item.get("status", "")).lower()
            not in {"completed", "rejected", "blocked", "cancelled"}
        }
        tasks = []
        for item in scoped_tasks:
            projected = _public_record(item)
            active_run = live_run_by_task.get(str(item.get("id", "")))
            if active_run is not None:
                projected["status"] = str(active_run.get("status", "RUNNING")).upper()
                projected["run_id"] = str(active_run.get("id", ""))
            tasks.append(projected)
        scoped_run_ids = {str(item.get("id", "")) for item in raw_runs}
        findings = [
            _public_record(item)
            for item in self.application.store.list("findings")
            if str(item.get("task_id", "")) in scoped_task_ids
            or str(item.get("run_id", "")) in scoped_run_ids
        ]
        authorizations = [
            _public_record(item)
            for item in self.application.store.list("authorizations")
            if str(item.get("task_id", "")) in scoped_task_ids
        ]
        active_charter = view.charter_detail
        founder_approval_id = active_charter.get("founder_approval_record_id")
        if founder_approval_id:
            authorizations.append(
                _public_record(
                    {
                        "id": founder_approval_id,
                        "capability": "charter approval receipt",
                        "scope": (
                            f"{view.project_title} — revision "
                            f"{active_charter.get('revision', 'unknown')}"
                        ),
                        "consumed_at": active_charter.get("approved_at")
                        or active_charter.get("activated_at")
                        or active_charter.get("updated_at")
                        or "recorded",
                        "revoked_at": None,
                    }
                )
            )
        recoveries = []
        for item in self.application.recovery_records():
            row = _public_record(item)
            recovery = item.get("recovery")
            recovery = recovery if isinstance(recovery, dict) else {}
            uncertain = (
                str(item.get("status", "")).upper() == "UNCERTAIN"
                or str(recovery.get("classification", "")).lower() == "uncertain"
            )
            row.update({
                "run_id": str(item.get("id", "")),
                "status": "UNCERTAIN" if uncertain else str(item.get("status", "UNKNOWN")).upper(),
                "recovery_action": "" if uncertain else item.get("recovery_action", ""),
                "reason": "External outcome uncertain; retry is blocked." if uncertain
                else "Paused worker can resume." if item.get("recovery_action") == "resume"
                else "Interrupted stage can be explicitly retried." if item.get("recovery_action") == "retry"
                else "Recovery requires inspection; no safe action is available.",
            })
            recoveries.append(row)
        uncertain_attempts = {
            item.assignment_id: item
            for item in self.pass_b.repository.list(AttemptRecord)
            if item.state == AttemptState.UNCERTAIN
            and item.uncertainty_kind
            == "EXTERNAL_EXECUTION_OUTCOME_AMBIGUOUS"
        }
        uncertain_assignments = [
            item
            for item in self.pass_b.repository.list(AssignmentRecord)
            if item.state == AssignmentState.UNCERTAIN
            and item.assignment_id in uncertain_attempts
        ]
        pass_b_uncertain = [
            _public_record(
                {
                    "id": item.assignment_id,
                    "assignment_id": item.assignment_id,
                    "attempt_id": uncertain_attempts[
                        item.assignment_id
                    ].attempt_id,
                    "project_id": item.project_id,
                    "workflow_id": item.workflow_id,
                    "work_item_id": item.work_item_id,
                    "provider_id": item.provider_id,
                    "source": "pass_b_uncertain_execution",
                    "status": "UNCERTAIN",
                    "reason": (
                        "External execution outcome remains possible. "
                        "Founder disposition is required; no result or retry "
                        "will be accepted."
                    ),
                }
            )
            for item in uncertain_assignments
        ]
        recoveries.extend(pass_b_uncertain)
        settings = self.application.store.get("settings", "application") or {}
        routing = self.application.store.get("settings", "routing") or {}
        conversation_providers = [
            {
                "provider_id": str(item.get("provider_id", "")),
                "name": str(item.get("name") or item.get("provider_id") or ""),
                "health": str(item.get("health", "UNAVAILABLE")),
            }
            for item in view.provider_cards
            if (
                str(item.get("health", "")).upper() == "READY"
                and str(item.get("composition", "")).upper() != "MOCK"
                and item.get("provider_id")
            )
        ]
        ready_provider_ids = {
            item["provider_id"] for item in conversation_providers
        }
        configured_conversation_provider = str(
            routing.get("conversation_provider_id") or ""
        )
        if configured_conversation_provider not in ready_provider_ids:
            configured_conversation_provider = (
                "codex"
                if "codex" in ready_provider_ids
                else (
                    conversation_providers[0]["provider_id"]
                    if conversation_providers
                    else ""
                )
            )
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
                "conversationProvider": configured_conversation_provider,
                "conversationProviders": conversation_providers,
            },
            "counts": {
                "projects": len(view.project_catalog),
                "workflows": len(view.workflow_rows),
                "tasks": len(tasks),
                "findings": len(findings),
                "approvals": int(view.approval_required),
                "providers": len(view.provider_cards),
                "evidence": len(view.evidence_cards) + len(view.evidence_reference_cards),
                "uncertain": sum(
                    1 for row in recoveries if str(row.get("status", "")).upper() == "UNCERTAIN"
                ),
                "projectUncertain": sum(
                    1
                    for row in recoveries
                    if row.get("run_id") in scoped_run_ids
                    and str(row.get("status", "")).upper() == "UNCERTAIN"
                )
                + sum(
                    1
                    for row in pass_b_uncertain
                    if row.get("project_id") == view.project_id
                ),
            },
        }
        return cast(dict[str, Any], _primitive(state))

    @Slot(str)
    def selectProject(self, project_id: str) -> None:
        self._run("Project selected", lambda: self.pass_b.select_project(project_id))

    @Slot()
    def startNewProject(self) -> None:
        self._new_project_intake = True
        self._status, self._error = "Describe the new project", ""
        self.statusChanged.emit()

    @Slot()
    def prepareDelegatedMode(self) -> None:
        project_id = self.pass_b.selected_project_id()
        if not project_id:
            self._fail("Select a Keeper project before enabling approved work.")
            return
        self._run(
            "Delegated-mode revision is ready for Founder approval",
            lambda: self.pass_b.conversation.revise(
                project_id, {"delegation_mode": "DELEGATED"}
            ),
        )

    @Slot(str)
    def sendAssistantMessage(self, message: str) -> None:
        clean = message.strip()
        if not clean:
            self._fail("Describe the project or ask Keeper a question first.")
            return
        self.saveConversationDraft(clean)
        project_id = self.pass_b.selected_project_id()

        if re.search(
            r"\b(current|approved|project)\b.*\b(status|summary|progress)\b|"
            r"\b(status|summary|progress)\b.*\b(project|approved)\b",
            clean.casefold(),
        ):
            project = self._state.get("project", {})
            workflows = self._state.get("workflows", [])
            completed = sum(
                str(item.get("status", "")).upper() == "COMPLETED"
                for item in workflows
            )
            reply = (
                f"{project.get('title') or 'The selected project'} is "
                f"{str(project.get('status') or 'not started').replace('_', ' ').lower()} "
                f"under approved charter revision "
                f"{project.get('charterRevision') or 'unknown'}. "
                f"Workflow progress is {completed} of {len(workflows)} stages complete. "
                f"There are {self._state.get('counts', {}).get('projectUncertain', 0)} "
                "uncertain outcomes awaiting recovery."
            )
            self._run_conversation(
                "Keeper is checking the approved project",
                "Keeper summarized the approved project",
                lambda: self.pass_b.conversation.respond(
                    project_id, clean, reply
                ),
            )
            return

        if self.pass_b.conversation.conversational_reply(clean) is not None:
            self._run_conversation(
                "Keeper is replying",
                "Keeper replied",
                lambda: self.pass_b.casual_conversation(project_id, clean),
            )
            return

        def begin_new_project() -> object:
            settings = self._state.get("settings", {})
            selected = str(settings.get("conversationProvider") or "")
            ready = tuple(
                str(item.get("provider_id"))
                for item in settings.get("conversationProviders", [])
                if item.get("provider_id")
            )
            approved = tuple(
                dict.fromkeys((selected, *ready))
            ) if selected else ready
            revisions = (
                {"approved_providers": approved}
                if approved
                else None
            )
            result = self.pass_b.begin_conversation(
                clean,
                founder_revisions=revisions,
            )
            self._new_project_intake = False
            return result

        operation: Callable[[], object] = (
            begin_new_project
            if self._new_project_intake or not project_id
            else lambda: self.pass_b.continue_conversation(project_id, clean)
        )
        self._run_conversation(
            "Keeper is developing the request",
            "Keeper recorded the conversation",
            operation,
        )

    @Slot(str)
    def saveConversationDraft(self, message: str) -> None:
        if message == self._conversation_draft:
            return
        self._conversation_draft = message
        if message:
            self.application.store.upsert(
                "settings",
                "conversation_draft",
                {"message": message},
            )
        else:
            self.application.store.delete("settings", "conversation_draft")
        self.conversationDraftChanged.emit()

    @Slot(str)
    def selectConversationProvider(self, provider_id: str) -> None:
        selected = provider_id.strip().lower()
        available = {
            str(item.get("provider_id", "")).lower()
            for item in self._state.get("settings", {}).get(
                "conversationProviders", []
            )
        }
        if selected not in available:
            self._fail(
                "The selected primary agent does not have a qualified READY session."
            )
            return

        def save() -> None:
            routing = self.application.store.get("settings", "routing") or {}
            routing["conversation_provider_id"] = selected
            self.application.store.upsert("settings", "routing", routing)

        self._run(f"{selected} selected as the primary agent", save)

    @Slot()
    def approveCurrentCharter(self) -> None:
        project_id = self.pass_b.selected_project_id()
        approval = self._state.get("project", {}).get("approvalCharter", {})
        if not project_id or not approval:
            self._fail("There is no current charter awaiting Founder approval.")
            return
        if self._busy:
            return
        self._busy = True
        self._status = "Waiting for Founder authentication"
        self._error = ""
        self.busyChanged.emit()
        self.statusChanged.emit()

        def worker() -> None:
            try:
                outcome = self.pass_b.approve_and_plan_current_charter(
                    project_id,
                    expected_charter_id=str(approval.get("charter_id")),
                    expected_charter_revision=int(approval.get("revision")),
                )
                charter = outcome.get("charter", {})
                mode = str(charter.get("delegation_mode", "ADVISORY")).upper()
                if mode in {"DELEGATED", "FULL_DELEGATION"}:
                    self._status = "Charter approved; Keeper is starting the project"
                    self.statusChanged.emit()
                    results = self.pass_b.run_delegated_completion(project_id)
                    status, error, success = _completion_feedback(results)
                    self._status = f"Charter approved. {status}"
                    self._error = error
                else:
                    self._status = (
                        "Advisory charter approved. Keeper will continue helping "
                        "through conversation without executing material work."
                    )
                    self._error = ""
                    success = True
            except Exception as error:  # UI boundary reports a safe failure.
                self._status = "Charter approval paused"
                self._error = _safe_error_message(error)
                success = False
            self._busy = False
            self.busyChanged.emit()
            self.statusChanged.emit()
            try:
                self._refresh_state_only()
            except Exception as refresh_error:
                self._status = "Project started, but the screen could not refresh"
                self._error = _safe_error_message(refresh_error)
                success = False
                self.statusChanged.emit()
            self.operationFinished.emit(self._status, success)

        threading.Thread(
            target=worker,
            name="keeper-charter-approval",
            daemon=True,
        ).start()

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
                results = self.pass_b.run_delegated_completion(project_id)
            except Exception as error:  # UI boundary reports a safe failure.
                self._status = "Completion paused"
                self._error = _safe_error_message(error)
                success = False
            else:
                self._status, self._error, success = _completion_feedback(results)
            self._busy = False
            self.busyChanged.emit()
            self.statusChanged.emit()
            try:
                self._refresh_state_only()
            except Exception as refresh_error:
                self._status = "Workflow advanced, but the screen could not refresh"
                self._error = _safe_error_message(refresh_error)
                success = False
                self.statusChanged.emit()
            self.operationFinished.emit(self._status, success)

        threading.Thread(target=worker, name="keeper-completion", daemon=True).start()

    @Slot(str, str)
    def addRepository(self, path_value: str, name: str) -> None:
        path = self._local_path(path_value)
        self._run("Repository added as a protected project", lambda: self.application.add_project(path, name or None))

    @Slot(str, str, str, str)
    def createTask(self, title: str, objective: str, baseline: str, branch: str) -> None:
        def create_bound_task() -> object:
            project_id = self.pass_b.selected_project_id()
            repository: str | None = None
            charter_identity: dict[str, object] = {}
            if project_id:
                repository = str(self._selected_project_repository(project_id))
                charter_identity = self._selected_project_charter_identity(
                    project_id
                )
            else:
                active = self.application.active_project()
                project_id = f"repository:{active['id']}" if active else None
                repository = str(active["repository"]) if active else None
            return self.application.create_task(
                {
                    "title": title,
                    "objective": objective,
                    "baseline": baseline,
                    "target_branch": branch,
                    "keeper_project_id": project_id,
                    "keeper_charter_id": charter_identity.get("charter_id"),
                    "keeper_charter_revision": charter_identity.get("revision"),
                    "keeper_founder_approval_record_id": charter_identity.get(
                        "founder_approval_record_id"
                    ),
                    "keeper_founder_approval_identity": charter_identity.get(
                        "founder_approval_identity"
                    ),
                    "repository": repository,
                    "allowed_actions": ["READ", "WRITE", "RUN_TESTS"],
                    "prohibited_actions": ["PUSH", "DEPLOY", "SPEND", "LIVE_TRADING"],
                }
            )

        self._run(
            "Task created",
            create_bound_task,
        )

    @Slot(str, str)
    def createSimpleTask(self, title: str, objective: str) -> None:
        clean_title = title.strip()
        clean_objective = objective.strip()
        slug = re.sub(r"[^a-z0-9]+", "-", clean_title.lower()).strip("-")
        branch = f"keeper/{slug or 'task'}-{uuid.uuid4().hex[:8]}"
        self.createTask(clean_title, clean_objective, "HEAD", branch)

    @Slot(str)
    def startTask(self, task_id: str) -> None:
        def start_bound_task() -> object:
            task = self.application.store.get("tasks", task_id)
            if task is None:
                raise LookupError("task not found")
            project_id = self.pass_b.selected_project_id()
            if project_id:
                repository = self._selected_project_repository(project_id)
                charter_identity = self._selected_project_charter_identity(
                    project_id
                )
                if (
                    task.get("keeper_project_id") != project_id
                    or Path(str(task.get("repository", ""))).resolve()
                    != repository
                    or task.get("keeper_charter_id")
                    != charter_identity["charter_id"]
                    or task.get("keeper_charter_revision")
                    != charter_identity["revision"]
                    or task.get("keeper_founder_approval_record_id")
                    != charter_identity["founder_approval_record_id"]
                    or task.get("keeper_founder_approval_identity")
                    != charter_identity["founder_approval_identity"]
                ):
                    raise PermissionError(
                        "task is not bound to the current approved Keeper charter"
                    )
            return self.application.start_task(task_id)

        self._run(
            "Task started through the validated workflow service",
            start_bound_task,
        )

    def _selected_project_repository(self, project_id: str) -> Path:
        snapshot = self.pass_b.product_snapshot(project_id)
        executive = snapshot.get("executive", {})
        charter = (
            executive.get("active_charter", {})
            if isinstance(executive, dict)
            else {}
        )
        workspaces = charter.get("workspaces", ()) if isinstance(charter, dict) else ()
        if not isinstance(workspaces, (list, tuple)) or len(workspaces) != 1:
            raise PermissionError(
                "selected Keeper project must have exactly one approved workspace"
            )
        repository = Path(str(workspaces[0])).resolve(strict=True)
        registered = next(
            (
                item
                for item in self.application.projects()
                if item.get("protected_original") is True
                and Path(str(item.get("repository", ""))).resolve()
                == repository
            ),
            None,
        )
        if registered is None:
            raise PermissionError(
                "selected Keeper project workspace is not a protected registered repository"
            )
        return repository

    def _selected_project_charter_identity(
        self, project_id: str
    ) -> dict[str, object]:
        snapshot = self.pass_b.product_snapshot(project_id)
        executive = snapshot.get("executive", {})
        charter = (
            executive.get("active_charter", {})
            if isinstance(executive, dict)
            else {}
        )
        if not isinstance(charter, dict):
            raise PermissionError("selected Keeper project has no active charter")
        identity = {
            "charter_id": charter.get("charter_id"),
            "revision": charter.get("revision"),
            "founder_approval_record_id": charter.get(
                "founder_approval_record_id"
            ),
            "founder_approval_identity": charter.get(
                "founder_approval_identity"
            ),
        }
        if (
            not isinstance(identity["charter_id"], str)
            or not identity["charter_id"]
            or type(identity["revision"]) is not int
            or not isinstance(identity["founder_approval_record_id"], str)
            or not identity["founder_approval_record_id"]
            or not isinstance(identity["founder_approval_identity"], str)
            or not identity["founder_approval_identity"]
        ):
            raise PermissionError(
                "selected Keeper project charter approval identity is incomplete"
            )
        return identity

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
    def resolveUncertainExecution(self, assignment_id: str) -> None:
        def dispose() -> object:
            reconciled = (
                self.pass_b.reconcile_completed_uncertain_execution(
                    assignment_id
                )
            )
            if reconciled is not None:
                return reconciled
            request = (
                self.pass_b.request_uncertain_execution_disposition_approval(
                    assignment_id
                )
            )
            challenge = FounderApprovalChallenge.from_dict(
                cast(dict[str, Any], request["challenge"])
            )
            confirmed = self.pass_b.confirm_recovery_action_approval(
                challenge
            )
            approval = cast(dict[str, Any], confirmed["approval"])
            return self.pass_b.apply_uncertain_execution_disposition_approval(
                assignment_id,
                observation_digest=str(request["observation_digest"]),
                approval_id=str(approval["approval_id"]),
            )

        self._run(
            "Recovery resolved from authenticated authority state",
            dispose,
        )

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

    def _run_conversation(
        self,
        pending: str,
        success: str,
        operation: Callable[[], object],
    ) -> None:
        if self._test_fixture:
            self._run(success, operation)
            if not self._error:
                self.saveConversationDraft("")
            return
        if self._busy:
            return
        self._busy = True
        self._status, self._error = pending, ""
        self.busyChanged.emit()
        self.statusChanged.emit()

        def worker() -> None:
            try:
                operation()
                state = self._build_state()
            except Exception as error:
                self._asyncFinished.emit(
                    None,
                    "Action could not be completed",
                    _safe_error_message(error),
                    False,
                )
                return
            self._asyncFinished.emit(state, success, "", True)

        threading.Thread(
            target=worker,
            name="keeper-conversation",
            daemon=True,
        ).start()

    @Slot(object, str, str, bool)
    def _finish_async(
        self,
        state: object,
        status: str,
        error: str,
        success: bool,
    ) -> None:
        if isinstance(state, dict):
            self._state = state
            self.stateChanged.emit()
        if success:
            self.saveConversationDraft("")
        self._busy = False
        self._status, self._error = status, error
        self.busyChanged.emit()
        self.statusChanged.emit()
        self.operationFinished.emit(status if success else error, success)

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
