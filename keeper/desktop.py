from __future__ import annotations

import argparse
import json
import threading
from functools import partial
from pathlib import Path
from typing import Any, Callable

from keeper.app.service import KeeperApplication
from keeper.ui.executive_desktop import KeeperExecutiveDesktop as KeeperProductDesktop


class KeeperViewModel:
    def __init__(self, application: KeeperApplication) -> None:
        self.application = application

    def dashboard(self) -> dict[str, Any]:
        return self.application.dashboard()

    def add_project(self, path: str) -> dict[str, Any]:
        return self.application.add_project(Path(path))

    def create_task(self, values: dict[str, Any]) -> dict[str, Any]:
        return self.application.create_task(values)

    def run_demo(self) -> dict[str, Any]:
        return self.application.run_mock_demo()

    def diagnostics(self) -> dict[str, Any]:
        return self.application.diagnostics()

    def complete_setup(self, evidence_directory: str | None = None) -> None:
        self.application.finish_setup(
            Path(evidence_directory) if evidence_directory else None
        )

    def create_authorization(self, values: dict[str, Any]) -> dict[str, Any]:
        return self.application.create_run_authorization(
            str(values["capability"]),
            str(values["run_id"]),
            str(values["approving_authority"]),
            int(values["minutes"]),
        )

    def authorization_preview(self, capability: str, run_id: str) -> dict[str, Any]:
        return self.application.authorization_preview(capability, run_id)

    def start_task(self, task_id: str) -> dict[str, Any]:
        return self.application.start_task(task_id)

    def run_status(self, run_id: str) -> dict[str, Any]:
        return self.application.run_status(run_id)

    def pause(self, run_id: str) -> None:
        self.application.pause_run(run_id)

    def resume(self, run_id: str) -> None:
        self.application.resume_run(run_id)

    def cancel(self, run_id: str) -> None:
        self.application.cancel_run(run_id)

    def approve(self, run_id: str, authority: str) -> None:
        self.application.approve_run(run_id, authority)

    def reject(self, run_id: str, authority: str, reason: str) -> None:
        self.application.reject_run(run_id, authority, reason)

    def evidence(self, run_id: str, kind: str) -> Path:
        return self.application.open_evidence(run_id, kind)

    def retry(self, run_id: str, reason: str) -> dict[str, Any]:
        return self.application.retry_run(run_id, reason)

    def revoke_authorization(self, authorization_id: str) -> None:
        self.application.revoke_authorization(authorization_id)

    def revoke_waiver(self, waiver_id: str) -> None:
        self.application.revoke_waiver(waiver_id)

    def evidence_details(self, run_id: str, category: str) -> dict[str, Any]:
        return self.application.evidence_details(run_id, category)


class FirstRunController:
    STEPS = ("boundaries", "storage", "repository", "providers", "diagnostics", "demo")

    def __init__(self, application: KeeperApplication) -> None:
        self.application = application
        self.index = 0
        self.evidence_directory = str(application.data_directory / "evidence")
        self.repository = ""
        routing = application.store.get("settings", "routing") or {}
        self.provider_policy = str(
            routing.get("default_provider_policy") or "automatic"
        )

    @property
    def step(self) -> str:
        return self.STEPS[self.index]

    def back(self) -> str:
        self.index = max(0, self.index - 1)
        return self.step

    def next(self) -> str:
        self._validate()
        self.index = min(len(self.STEPS) - 1, self.index + 1)
        return self.step

    def finish(self) -> None:
        if self.index != len(self.STEPS) - 1:
            raise ValueError("complete every setup step before finishing")
        self._validate()
        if self.repository:
            self.application.add_project(Path(self.repository))
        self.application.store.upsert(
            "settings", "routing", {"default_provider_policy": self.provider_policy}
        )
        self.application.finish_setup(Path(self.evidence_directory))

    def _validate(self) -> None:
        if self.step == "storage":
            target = Path(self.evidence_directory).resolve()
            target.mkdir(parents=True, exist_ok=True)
            probe = target / ".keeper-write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
        if self.step == "repository" and self.repository:
            self.application.git.inspect(Path(self.repository))


class KeeperDesktop:
    COLORS = {
        "black": "#0B0B0B",
        "gold": "#D4AF37",
        "gray": "#272727",
        "white": "#F5F5F5",
        "muted": "#B7B7B7",
    }

    def __init__(self, application: KeeperApplication) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.ttk = ttk
        self.application = application
        self.view_model = KeeperViewModel(application)
        self.root = tk.Tk()
        self.root.title("Keeper")
        self.root.geometry("1180x760")
        self.root.minsize(900, 600)
        self._configure_style()
        self.status = tk.StringVar(value="Ready")
        self.current_run_id: str | None = None
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=12)
        self._build_dashboard()
        self._build_projects()
        self._build_tasks()
        self._build_workflow()
        self._build_findings()
        self._build_authorizations()
        self._build_history()
        self._build_evidence_details()
        self._build_settings()
        ttk.Label(self.root, textvariable=self.status, anchor="w").pack(
            fill="x", padx=12, pady=(0, 8)
        )
        if not application.setup_complete():
            self.root.after(100, self._first_run)
        self.refresh()

    def run(self) -> None:
        self.root.mainloop()

    def _configure_style(self) -> None:
        style = self.ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure(".", background=self.COLORS["black"], foreground=self.COLORS["white"])
        style.configure("TFrame", background=self.COLORS["black"])
        style.configure("TLabel", background=self.COLORS["black"], foreground=self.COLORS["white"])
        style.configure("TButton", background=self.COLORS["gold"], foreground=self.COLORS["black"])
        style.configure("Treeview", background=self.COLORS["gray"], foreground=self.COLORS["white"], fieldbackground=self.COLORS["gray"])
        style.configure("TNotebook", background=self.COLORS["black"])
        style.configure("TNotebook.Tab", background=self.COLORS["gray"], foreground=self.COLORS["white"])
        style.map("TNotebook.Tab", background=[("selected", self.COLORS["gold"])], foreground=[("selected", self.COLORS["black"])])
        self.root.configure(background=self.COLORS["black"])

    def _tab(self, title: str) -> Any:
        frame = self.ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)
        return frame

    def _build_dashboard(self) -> None:
        frame = self._tab("Home")
        self.dashboard_text = self.tk.Text(
            frame, bg=self.COLORS["gray"], fg=self.COLORS["white"], wrap="word"
        )
        self.dashboard_text.pack(fill="both", expand=True, padx=8, pady=8)
        buttons = self.ttk.Frame(frame)
        buttons.pack(fill="x", padx=8, pady=8)
        self.refresh_button = self.ttk.Button(
            buttons, text="Refresh", command=self._refresh_from_ui
        )
        self.refresh_button.pack(side="left")
        self.ttk.Button(buttons, text="Run safe mock demonstration", command=self._run_demo).pack(side="left", padx=8)

    def _build_projects(self) -> None:
        frame = self._tab("Projects")
        self.project_path = self.tk.StringVar()
        self.ttk.Label(frame, text="Existing Git repository").pack(anchor="w", padx=8, pady=(8, 2))
        self.ttk.Entry(frame, textvariable=self.project_path).pack(fill="x", padx=8)
        self.ttk.Button(frame, text="Add and inspect repository", command=self._add_project).pack(anchor="w", padx=8, pady=8)
        self.projects_text = self.tk.Text(frame, bg=self.COLORS["gray"], fg=self.COLORS["white"])
        self.projects_text.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_tasks(self) -> None:
        frame = self._tab("Tasks")
        self.task_fields: dict[str, Any] = {}
        for label, key in (
            ("Title", "title"),
            ("Objective", "objective"),
            ("Included paths (comma-separated)", "included_paths"),
            ("Excluded paths", "excluded_paths"),
            ("Baseline commit", "baseline"),
            ("Target branch", "target_branch"),
            ("Risk", "risk"),
            ("Allowed actions", "allowed_actions"),
            ("Prohibited actions", "prohibited_actions"),
            ("Required validations", "required_validations"),
            ("Required reviewers", "required_reviewers"),
            ("Completion criteria", "completion_criteria"),
        ):
            self.ttk.Label(frame, text=label).pack(anchor="w", padx=8, pady=(5, 0))
            variable = self.tk.StringVar()
            self.task_fields[key] = variable
            self.ttk.Entry(frame, textvariable=variable).pack(fill="x", padx=8)
        routing = self.application.store.get("settings", "routing") or {}
        self.task_fields["provider_policy"] = self.tk.StringVar(
            value=str(routing.get("default_provider_policy") or "automatic")
        )
        self.ttk.Label(frame, text="Provider policy").pack(
            anchor="w", padx=8, pady=(5, 0)
        )
        self.ttk.Combobox(
            frame,
            textvariable=self.task_fields["provider_policy"],
            values=(
                "automatic",
                "local-only",
                "strongest",
                "codex",
                "claude",
                "ollama",
                "mock",
            ),
            state="readonly",
        ).pack(fill="x", padx=8)
        provider_status = [
            {
                "id": item["provider_id"],
                "available": item["available"],
                "verification": item["verification_status"],
            }
            for item in self.application.diagnostics()["providers"]
        ]
        self.ttk.Label(
            frame,
            text=json.dumps(provider_status, indent=2),
            justify="left",
        ).pack(anchor="w", padx=8, pady=4)
        self.ttk.Button(frame, text="Save task", command=self._create_task).pack(anchor="w", padx=8, pady=8)

    def _build_workflow(self) -> None:
        frame = self._tab("Workflow")
        controls = self.ttk.Frame(frame)
        controls.pack(fill="x", padx=8, pady=8)
        for label, command in (
            ("Start", self._start_task),
            ("Pause", lambda: self._run_control("pause")),
            ("Resume", lambda: self._run_control("resume")),
            ("Cancel", lambda: self._run_control("cancel")),
            ("Approve", lambda: self._run_control("approve")),
            ("Reject", lambda: self._run_control("reject")),
            ("Retry", lambda: self._run_control("retry")),
            ("Open logs", lambda: self._open_evidence("folder")),
            ("Open evidence", lambda: self._open_evidence("folder")),
            ("Open report", lambda: self._open_evidence("markdown")),
        ):
            self.ttk.Button(controls, text=label, command=command).pack(
                side="left", padx=2
            )
        self.workflow_text = self._readonly_text(frame)
        self._set_text(self.workflow_text, "No workflow is running.\nPause, resume, cancel, logs, retries, stages and artifacts appear here.")

    def _build_findings(self) -> None:
        frame = self._tab("Findings")
        self.findings_text = self._readonly_text(frame)
        self._set_text(self.findings_text, "No unresolved findings.")

    def _build_authorizations(self) -> None:
        frame = self._tab("Authorizations")
        form = self.ttk.Frame(frame)
        form.pack(fill="x", padx=8, pady=8)
        self.authorization_fields: dict[str, Any] = {}
        for label, key, default in (
            ("Action (commit/push)", "capability", "commit"),
            ("Approving user", "approving_authority", ""),
            ("Expires in minutes", "minutes", "15"),
        ):
            self.ttk.Label(form, text=label).pack(anchor="w")
            variable = self.tk.StringVar(value=default)
            self.authorization_fields[key] = variable
            self.ttk.Entry(form, textvariable=variable).pack(fill="x")
        self.ttk.Button(
            form, text="Preview exact current scope", command=self._preview_authorization
        ).pack(anchor="w", pady=4)
        self.ttk.Button(
            form, text="Grant scoped one-time authorization", command=self._authorize
        ).pack(anchor="w", pady=4)
        self.ttk.Label(form, text="Waiver ID to revoke").pack(anchor="w")
        self.waiver_id = self.tk.StringVar()
        self.ttk.Entry(form, textvariable=self.waiver_id).pack(fill="x")
        self.ttk.Button(
            form,
            text="Revoke active verification waiver",
            command=self._revoke_waiver,
        ).pack(anchor="w", pady=8)
        self.authorization_text = self._readonly_text(frame)
        self._set_text(self.authorization_text, "No pending authorization.")

    def _build_history(self) -> None:
        frame = self._tab("History & Evidence")
        self.history_text = self._readonly_text(frame)
        self._set_text(self.history_text, "Run history is empty.")

    def _build_evidence_details(self) -> None:
        frame = self._tab("Evidence Details")
        controls = self.ttk.Frame(frame)
        controls.pack(fill="x", padx=8, pady=8)
        for category in (
            "routing",
            "verification",
            "waivers",
            "authorizations",
            "findings",
            "logs",
            "hashes",
            "git",
        ):
            self.ttk.Button(
                controls,
                text=category.replace("_", " ").title(),
                command=partial(self._show_evidence_details, category),
            ).pack(side="left", padx=2)
        self.evidence_details_text = self._readonly_text(frame)
        self._set_text(
            self.evidence_details_text,
            "Select a run and an evidence category.",
        )

    def _build_settings(self) -> None:
        frame = self._tab("Settings")
        diagnostics = json.dumps(self.application.diagnostics(), indent=2)
        self.settings_text = self._readonly_text(frame)
        self._set_text(self.settings_text, diagnostics)

    def _readonly_text(self, frame: Any) -> Any:
        widget = self.tk.Text(frame, bg=self.COLORS["gray"], fg=self.COLORS["white"], wrap="word")
        widget.pack(fill="both", expand=True, padx=8, pady=8)
        return widget

    def refresh(self) -> None:
        dashboard = self.view_model.dashboard()
        self._set_text(self.dashboard_text, json.dumps(dashboard, indent=2))
        self._set_text(self.projects_text, json.dumps(self.application.projects(), indent=2))
        self._set_text(self.history_text, json.dumps(self.application.store.list("runs"), indent=2))
        self._set_text(self.authorization_text, json.dumps(self.application.store.list("authorizations"), indent=2))
        self._set_text(self.findings_text, json.dumps(self.application.store.list("findings"), indent=2))

    def _refresh_from_ui(self) -> None:
        self.refresh()
        self.status.set("Dashboard refreshed")

    def _first_run(self) -> None:
        diagnostics = self.application.diagnostics()
        controller = FirstRunController(self.application)
        wizard = self.tk.Toplevel(self.root)
        wizard.title("Keeper first-run setup")
        wizard.geometry("680x520")
        wizard.transient(self.root)
        wizard.grab_set()
        body = self.tk.Text(
            wizard, bg=self.COLORS["gray"], fg=self.COLORS["white"], wrap="word"
        )
        body.pack(fill="both", expand=True, padx=12, pady=12)
        provider_lines = "\n".join(
            f"- {item['display_name']}: "
            f"{'available' if item['available'] else 'optional / unavailable'}"
            for item in diagnostics["providers"]
        )
        evidence = self.tk.StringVar(value=controller.evidence_directory)
        repository = self.tk.StringVar()
        provider_policy = self.tk.StringVar(value=controller.provider_policy)

        def render() -> None:
            controller.evidence_directory = evidence.get()
            controller.repository = repository.get()
            controller.provider_policy = provider_policy.get()
            descriptions = {
                "boundaries": "Keeper cannot merge, force-push, deploy, trade, spend, or delete repositories.",
                "storage": f"Confirm evidence directory:\n{evidence.get()}",
                "repository": f"Optional first Git repository:\n{repository.get() or '(none yet)'}",
                "providers": f"Detected providers:\n{provider_lines}",
                "diagnostics": json.dumps(diagnostics, indent=2),
                "demo": "Finish setup, then use Home to run the unified mock demonstration.",
            }
            self._set_text(body, f"Step: {controller.step}\n\n{descriptions[controller.step]}")

        entries = self.ttk.Frame(wizard)
        entries.pack(fill="x", padx=12)
        self.ttk.Label(entries, text="Evidence directory").pack(anchor="w")
        self.ttk.Entry(entries, textvariable=evidence).pack(fill="x")
        self.ttk.Label(entries, text="First repository (optional)").pack(anchor="w")
        self.ttk.Entry(entries, textvariable=repository).pack(fill="x")
        self.ttk.Label(entries, text="Default provider policy").pack(anchor="w")
        self.ttk.Combobox(
            entries,
            textvariable=provider_policy,
            values=(
                "automatic",
                "local-only",
                "strongest",
                "codex",
                "claude",
                "ollama",
                "mock",
            ),
            state="readonly",
        ).pack(fill="x")

        def finish() -> None:
            controller.evidence_directory = evidence.get()
            controller.repository = repository.get()
            controller.provider_policy = provider_policy.get()
            controller.finish()
            wizard.destroy()
            self.status.set(
                "First-run setup completed. Add a repository or run the mock demonstration."
            )
            self.refresh()

        navigation = self.ttk.Frame(wizard)
        navigation.pack(pady=12)

        def move(direction: str) -> None:
            try:
                controller.back() if direction == "back" else controller.next()
                render()
            except Exception as error:
                self._show_error(str(error))

        self.ttk.Button(navigation, text="Back", command=lambda: move("back")).pack(side="left")
        self.ttk.Button(navigation, text="Next", command=lambda: move("next")).pack(side="left", padx=8)
        self.ttk.Button(navigation, text="Finish", command=finish).pack(side="left")
        render()

    def _add_project(self) -> None:
        self._handle(lambda: self.view_model.add_project(self.project_path.get()), "Repository added")

    def _create_task(self) -> None:
        values = {key: variable.get() for key, variable in self.task_fields.items()}
        values["requires_manual_approval"] = True
        for key in (
            "included_paths",
            "excluded_paths",
            "allowed_actions",
            "prohibited_actions",
            "required_validations",
            "required_reviewers",
            "completion_criteria",
        ):
            values[key] = [item.strip() for item in str(values[key]).split(",") if item.strip()]
        self._handle(lambda: self.view_model.create_task(values), "Task saved")

    def _authorize(self) -> None:
        if self.current_run_id is None:
            self._show_error("Select an active run before authorizing Git")
            return
        values = {key: variable.get() for key, variable in self.authorization_fields.items()}
        values["run_id"] = self.current_run_id
        self._handle(
            lambda: self.view_model.create_authorization(values),
            "Scoped authorization recorded",
        )

    def _preview_authorization(self) -> None:
        if self.current_run_id is None:
            self._show_error("Select an active run before previewing authorization")
            return
        capability = str(self.authorization_fields["capability"].get())
        try:
            preview = self.view_model.authorization_preview(
                capability, self.current_run_id
            )
            self._set_text(
                self.authorization_text,
                "Exact derived authorization scope:\n"
                + json.dumps(preview, indent=2),
            )
            self.status.set("Authorization scope previewed")
        except Exception as error:
            self._show_error(str(error))

    def _revoke_waiver(self) -> None:
        self._handle(
            lambda: self.view_model.revoke_waiver(self.waiver_id.get()),
            "Verification waiver revoked",
        )

    def _show_evidence_details(self, category: str) -> None:
        if self.current_run_id is None:
            self._show_error("No selected run")
            return
        try:
            detail = self.view_model.evidence_details(
                self.current_run_id, category
            )
            self._set_text(
                self.evidence_details_text, json.dumps(detail, indent=2)
            )
            self.status.set(f"Showing {category} evidence")
        except Exception as error:
            self._show_error(str(error))

    def _run_demo(self) -> None:
        self.status.set("Running deterministic mock workflow…")

        def work() -> None:
            try:
                result = self.view_model.run_demo()
                self.root.after(0, lambda: self._complete_async(f"Mock workflow: {result['status']}"))
            except Exception as error:
                self.root.after(0, lambda: self._show_error(str(error)))

        threading.Thread(target=work, daemon=True).start()

    def _start_task(self) -> None:
        tasks = self.application.tasks()
        if not tasks:
            self._show_error("Create a task first")
            return
        try:
            run = self.view_model.start_task(str(tasks[0]["id"]))
            self.current_run_id = str(run["id"])
            self.status.set(f"Run started: {self.current_run_id}")
            self.root.after(250, self._poll_run)
        except Exception as error:
            self._show_error(str(error))

    def _poll_run(self) -> None:
        if self.current_run_id is None:
            return
        try:
            run = self.view_model.run_status(self.current_run_id)
            self._set_text(self.workflow_text, json.dumps(run, indent=2))
            if str(run.get("status", "")).lower() in {
                "completed", "blocked", "cancelled", "rejected"
            }:
                self.refresh()
                return
        except Exception as error:
            self.status.set(str(error))
            return
        self.root.after(500, self._poll_run)

    def _run_control(self, action: str) -> None:
        if self.current_run_id is None:
            self._show_error("No active run")
            return
        operations: dict[str, Callable[[], Any]] = {
            "pause": lambda: self.view_model.pause(self.current_run_id or ""),
            "resume": lambda: self.view_model.resume(self.current_run_id or ""),
            "cancel": lambda: self.view_model.cancel(self.current_run_id or ""),
            "approve": lambda: self.view_model.approve(self.current_run_id or "", "Founder"),
            "reject": lambda: self.view_model.reject(
                self.current_run_id or "", "Founder", "Rejected in Keeper desktop"
            ),
            "retry": lambda: self._select_retried_run(
                self.view_model.retry(
                    self.current_run_id or "", "Explicit desktop retry"
                )
            ),
        }
        self._handle(operations[action], f"Run action completed: {action}")

    def _select_retried_run(self, run: dict[str, Any]) -> None:
        self.current_run_id = str(run["id"])
        self.root.after(250, self._poll_run)

    def _open_evidence(self, kind: str) -> None:
        if self.current_run_id is None:
            self._show_error("No selected run")
            return
        self._handle(
            lambda: self.view_model.evidence(self.current_run_id or "", kind),
            f"Opened {kind}",
        )

    def _handle(self, operation: Callable[[], Any], success: str) -> None:
        try:
            operation()
            self.status.set(success)
            self.refresh()
        except Exception as error:
            self._show_error(str(error))

    def _complete_async(self, message: str) -> None:
        self.status.set(message)
        self.refresh()

    def _show_error(self, message: str) -> None:
        from tkinter import messagebox

        self.status.set("Operation failed")
        messagebox.showerror("Keeper", message)

    @staticmethod
    def _set_text(widget: Any, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Keeper local desktop application")
    result.add_argument("--data-dir", type=Path)
    result.add_argument("--diagnostics", action="store_true")
    result.add_argument("--mock-demo", action="store_true")
    result.add_argument("--ui-smoke", action="store_true")
    result.add_argument("--screenshot-dir", type=Path)
    result.add_argument("--test-ui-fixture", action="store_true")
    result.add_argument("--legacy-tk", action="store_true")
    return result


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    application = KeeperApplication(options.data_dir)
    if options.diagnostics:
        print(json.dumps(application.diagnostics(), indent=2))
        return 0
    if options.mock_demo:
        print(json.dumps(application.run_mock_demo(), indent=2))
        return 0
    if options.legacy_tk:
        KeeperProductDesktop(application).run()
        return 0
    from keeper.ui_qml import run_desktop

    if options.ui_smoke:
        application.finish_setup()
    return run_desktop(
        application,
        smoke=options.ui_smoke,
        screenshot_directory=options.screenshot_dir,
        test_fixture=options.test_ui_fixture,
    )

if __name__ == "__main__":
    raise SystemExit(main())
