from __future__ import annotations

import json
import os
import tempfile
import threading
from functools import partial
from pathlib import Path
from typing import Any

from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.pass_b.application import PassBApplication
from keeper.pass_b.repository import validate_protected_workspace_tree
from keeper.ui.theme import THEME, configure_ttk
from keeper.ui.view_models import SETUP_STEPS, ProductViewModel, build_product_view


NAVIGATION = (
    "Home", "Conversation", "Projects", "Workflow",
    "Providers", "Evidence", "Safety", "Settings",
)


class ProductSetupController:
    def __init__(self, application: Any) -> None:
        self.application = application
        self.index = 0
        self.evidence_directory = str(application.data_directory / "evidence")
        self.repository = ""
        routing = application.store.get("settings", "routing") or {}
        self.provider_policy = str(routing.get("default_provider_policy") or "automatic")

    @property
    def step(self) -> str:
        return SETUP_STEPS[self.index][0]

    def back(self) -> str:
        self.index = max(0, self.index - 1)
        return self.step

    def next(self) -> str:
        self._validate()
        self.index = min(len(SETUP_STEPS) - 1, self.index + 1)
        return self.step

    def finish(self) -> None:
        if self.index != len(SETUP_STEPS) - 1:
            raise ValueError("Complete every setup step before finishing")
        if self.repository:
            self.application.add_project(Path(self.repository))
        self.application.store.upsert(
            "settings", "routing",
            {"default_provider_policy": self.provider_policy},
        )
        self.application.finish_setup(Path(self.evidence_directory))

    def _validate(self) -> None:
        if self.step == "storage":
            selected = Path(self.evidence_directory)
            validate_protected_workspace_tree(selected, require_exists=False)
            target = selected.resolve()
            target.mkdir(parents=True, exist_ok=True)
            validate_protected_workspace_tree(target)
            probe: Path | None = None
            try:
                descriptor, probe_name = tempfile.mkstemp(
                    prefix=".keeper-write-probe-",
                    suffix=".tmp",
                    dir=target,
                )
                probe = Path(probe_name)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(b"keeper-write-probe")
                    stream.flush()
                    os.fsync(stream.fileno())
                if probe.read_bytes() != b"keeper-write-probe":
                    raise OSError("evidence-directory write probe failed")
            finally:
                if probe is not None:
                    try:
                        probe.unlink(missing_ok=True)
                    except OSError:
                        pass
        if self.step == "repository" and self.repository:
            self.application.git.inspect(Path(self.repository))


class KeeperProductDesktop:
    """Conversation-first shell whose data comes from durable Keeper services."""

    def __init__(
        self, application: Any, *,
        pass_b_application: PassBApplication | None = None,
        authority_health_client: Any | None = None,
    ) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk = tk, ttk
        self.application = application
        self.pass_b = pass_b_application or _desktop_pass_b_application(
            application,
            authority_health_client=authority_health_client,
        )
        self._completion_running = False
        self.project_id: str | None = self.pass_b.selected_project_id()
        self.developer_details_enabled = False
        self.root = tk.Tk()
        self.root.title("DarkSage Keeper — Executive Control Center")
        self.root.geometry("1440x900")
        self.root.minsize(980, 680)
        configure_ttk(self.root, ttk)
        self.status = tk.StringVar(value="Ready")
        self.pages: dict[str, Any] = {}
        self.rail_values: dict[str, Any] = {}
        self.current_view: ProductViewModel | None = None
        self._build_shell()
        self._build_pages()
        self._show_page("Home")
        self.root.bind("<Configure>", self._responsive_layout)
        if not application.setup_complete():
            self.root.after(100, self._first_run)
        self.refresh()

    @property
    def navigation_pages(self) -> tuple[str, ...]:
        return NAVIGATION

    def run(self) -> None:
        self.root.mainloop()

    def _build_shell(self) -> None:
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        sidebar = self.ttk.Frame(self.root, style="Sidebar.TFrame", width=190)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        self.ttk.Label(
            sidebar, text="KEEPER", style="RailHeading.TLabel",
            font=("Segoe UI Semibold", 18),
        ).pack(anchor="w", padx=18, pady=(24, 2))
        self.ttk.Label(
            sidebar, text="Personal Executive", style="RailBody.TLabel",
        ).pack(anchor="w", padx=18, pady=(0, 24))
        for name in NAVIGATION:
            self.ttk.Button(
                sidebar, text=name, style="Nav.TButton",
                command=partial(self._show_page, name),
            ).pack(fill="x", padx=8, pady=1)
        self.composition_label = self.ttk.Label(
            sidebar, text="NOT_CONFIGURED", style="RailHeading.TLabel",
        )
        self.composition_label.pack(side="bottom", anchor="w", padx=18, pady=20)

        content = self.ttk.Frame(self.root, style="App.TFrame")
        content.grid(row=0, column=1, sticky="nsew", padx=22, pady=18)
        content.grid_rowconfigure(1, weight=1)
        content.grid_columnconfigure(0, weight=1)
        header = self.ttk.Frame(content, style="App.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        header.grid_columnconfigure(0, weight=1)
        self.page_title = self.ttk.Label(
            header, text="Home", style="Title.TLabel"
        )
        self.page_title.grid(row=0, column=0, sticky="w")
        self.project_choice = self.tk.StringVar(value="No project selected")
        self.project_selector = self.ttk.Combobox(
            header,
            textvariable=self.project_choice,
            state="readonly",
            width=38,
        )
        self.project_selector.grid(row=0, column=1, sticky="e")
        self.project_selector.bind(
            "<<ComboboxSelected>>", self._select_project_from_ui
        )
        self._project_labels: dict[str, str] = {}
        self.page_host = self.ttk.Frame(content, style="App.TFrame")
        self.page_host.grid(row=1, column=0, sticky="nsew")
        self.page_host.grid_rowconfigure(0, weight=1)
        self.page_host.grid_columnconfigure(0, weight=1)

        self.rail = self.ttk.Frame(self.root, style="Rail.TFrame", width=260)
        self.rail.grid(row=0, column=2, sticky="nsew")
        self.rail.grid_propagate(False)
        self.ttk.Label(
            self.rail, text="CONTROL ROOM", style="RailHeading.TLabel",
        ).pack(anchor="w", padx=18, pady=(24, 18))
        labels = (
            "Keeper", "Active project", "Assignments working",
            "Providers working", "Usage waits", "Approvals", "Uncertain",
            "Workspace conflicts", "KeeperAuthority", "Delegated mode",
        )
        for label in labels:
            holder = self.ttk.Frame(self.rail, style="Rail.TFrame")
            holder.pack(fill="x", padx=18, pady=5)
            self.ttk.Label(
                holder, text=label.upper(), style="RailHeading.TLabel",
                font=("Segoe UI Semibold", 8),
            ).pack(anchor="w")
            value = self.tk.StringVar(value="—")
            self.ttk.Label(
                holder, textvariable=value, style="RailBody.TLabel", wraplength=215,
            ).pack(anchor="w")
            self.rail_values[label] = value
        self.ttk.Label(
            self.rail,
            text="Authority is enforced by durable services, not UI widgets.",
            style="RailBody.TLabel", wraplength=220,
        ).pack(side="bottom", anchor="w", padx=18, pady=22)
        status_frame = self.ttk.Frame(self.root, style="Sidebar.TFrame")
        status_frame.grid(row=1, column=0, columnspan=3, sticky="ew")
        self.ttk.Label(
            status_frame, textvariable=self.status, style="RailBody.TLabel",
        ).pack(anchor="w", padx=18, pady=6)

    def _build_pages(self) -> None:
        for name in NAVIGATION:
            page = self.ttk.Frame(self.page_host, style="App.TFrame")
            page.grid(row=0, column=0, sticky="nsew")
            page.grid_rowconfigure(0, weight=1)
            page.grid_columnconfigure(0, weight=1)
            self.pages[name] = page
        self._build_home()
        self.home_timeline = self._timeline_page("Home")
        self.conversation_timeline = self._timeline_page("Conversation", replace=True)
        self.projects_text = self._text_page("Projects")
        self.workflow_tree = self._tree_page(
            "Workflow", ("stage", "role", "provider", "status", "usage")
        )
        self.providers_tree = self._tree_page(
            "Providers", ("provider", "composition", "health", "jobs", "capacity")
        )
        self.pages["Providers"].grid_rowconfigure(0, weight=3)
        self.pages["Providers"].grid_rowconfigure(1, weight=2)
        self.providers_tree.grid_configure(row=0, pady=(0, 8))
        self.usage_text = self._readonly_text(self.pages["Providers"], height=8)
        self.usage_text.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        self.evidence_tree = self._tree_page(
            "Evidence", ("evidence", "producer", "kind", "state", "review")
        )
        self.pages["Evidence"].grid_rowconfigure(0, weight=3)
        self.pages["Evidence"].grid_rowconfigure(1, weight=2)
        self.evidence_tree.grid_configure(row=0, pady=(0, 8))
        self.review_text = self._readonly_text(self.pages["Evidence"], height=8)
        self.review_text.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        self.safety_text = self._text_page("Safety")
        self._build_settings()

    def _build_home(self) -> None:
        page = self.pages["Home"]
        page.grid_columnconfigure(0, weight=3)
        page.grid_columnconfigure(1, weight=2)
        conversation = self._card(page)
        conversation.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.ttk.Label(
            conversation, text="Conversation", style="Heading.TLabel",
        ).pack(anchor="w", padx=14, pady=(14, 4))
        self.ttk.Label(
            conversation,
            text="Ideas become charters, workflows, evidence, and durable summaries.",
            style="Muted.TLabel",
        ).pack(anchor="w", padx=14, pady=(0, 8))
        self._home_conversation_host = conversation
        summary = self._card(page)
        summary.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        self.ttk.Label(summary, text="Current work", style="Heading.TLabel").pack(
            anchor="w", padx=14, pady=(14, 8)
        )
        self.home_summary = self._readonly_text(summary, height=16)
        self.home_summary.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        self.sage_label = self.ttk.Label(
            summary, text="Sage • listening", style="Gold.TLabel",
        )
        self.sage_label.pack(anchor="w", padx=14)
        self.sage_detail = self.ttk.Label(
            summary, text="Presentation only • authority effect NONE",
            style="Muted.TLabel", wraplength=320,
        )
        self.sage_detail.pack(anchor="w", padx=14, pady=(2, 8))
        self.approve_charter_button = self.ttk.Button(
            summary,
            text="Review Founder approval",
            style="Accent.TButton",
            command=self._review_charter_approval,
        )
        self.approve_charter_button.pack(
            anchor="w", padx=14, pady=(2, 8)
        )
        self.refresh_button = self.ttk.Button(
            summary, text="Refresh durable state", style="Quiet.TButton",
            command=self._refresh_from_ui,
        )
        self.refresh_button.pack(anchor="w", padx=14, pady=(0, 14))

    def _timeline_page(self, name: str, *, replace: bool = False) -> Any:
        if name == "Home":
            parent = self._home_conversation_host
        else:
            parent = self._card(self.pages[name])
            parent.grid(sticky="nsew")
        timeline = self._timeline(parent)
        timeline.pack(fill="both", expand=True, padx=14, pady=14)
        composer = self.ttk.Frame(parent, style="Card.TFrame")
        composer.pack(fill="x", padx=14, pady=(0, 14))
        entry = self.tk.Text(
            composer, height=3, bg=THEME.surface, fg=THEME.text,
            insertbackground=THEME.gold, relief="flat", wrap="word", padx=10, pady=8,
        )
        entry.pack(side="left", fill="x", expand=True)
        self.ttk.Button(
            composer, text="Send", style="Accent.TButton",
            command=partial(self._send, entry),
        ).pack(side="left", padx=(10, 0))
        if name == "Home":
            self.home_input = entry
        else:
            self.conversation_input = entry
        return timeline

    def _text_page(self, name: str) -> Any:
        widget = self._readonly_text(self.pages[name])
        widget.grid(sticky="nsew")
        return widget

    def _tree_page(self, name: str, columns: tuple[str, ...]) -> Any:
        tree = self.ttk.Treeview(
            self.pages[name], columns=columns, show="headings", style="Keeper.Treeview",
        )
        for column in columns:
            tree.heading(column, text=column.replace("_", " ").title())
            tree.column(column, width=145, minwidth=85, stretch=True)
        tree.grid(sticky="nsew")
        return tree

    def _build_settings(self) -> None:
        card = self._card(self.pages["Settings"])
        card.grid(sticky="nsew")
        self.ttk.Label(card, text="Application settings", style="Heading.TLabel").pack(
            anchor="w", padx=14, pady=(14, 4)
        )
        self.ttk.Label(
            card,
            text="Provider paths, evidence storage, appearance, Sage, and diagnostics. Security, service, payment, deployment, and trading toggles are unavailable.",
            style="Muted.TLabel", wraplength=760,
        ).pack(anchor="w", padx=14, pady=(0, 10))
        self.developer_toggle = self.tk.BooleanVar(value=False)
        self.ttk.Checkbutton(
            card, text="Show optional developer details",
            variable=self.developer_toggle, command=self._toggle_developer_details,
        ).pack(anchor="w", padx=14, pady=(0, 8))
        self.settings_summary = self._readonly_text(card, height=9)
        self.settings_summary.pack(fill="x", padx=14, pady=(0, 8))
        self.developer_text = self._readonly_text(card, height=14)

    def refresh(self) -> None:
        snapshot = self.pass_b.product_snapshot(self.project_id)
        view = build_product_view(
            snapshot, developer_details=self.developer_details_enabled
        )
        self.current_view = view
        self.project_id = view.project_id
        self._render_project_selector(view)
        self.composition_label.configure(text=view.composition)
        self._render_timeline(self.home_timeline, view)
        self._render_timeline(self.conversation_timeline, view)
        self._render_home(view)
        self._render_projects(view)
        self._render_workflow(view)
        self._render_providers(view)
        self._render_evidence(view)
        self._render_safety(view)
        self._render_settings(view)
        for label, value in view.right_rail:
            if label in self.rail_values:
                self.rail_values[label].set(value)
        self._render_sage(view.sage)
        self.approve_charter_button.configure(
            state=(
                "normal"
                if view.approval_required
                and bool(view.approval_charter_detail)
                else "disabled"
            )
        )
        self.status.set("Durable state refreshed")

    def _render_sage(self, sage: dict[str, Any]) -> None:
        if not bool(sage.get("visible")):
            self.sage_label.pack_forget()
            self.sage_detail.pack_forget()
            return
        if not self.sage_label.winfo_manager():
            self.sage_label.pack(
                anchor="w", padx=14, before=self.refresh_button
            )
        if not self.sage_detail.winfo_manager():
            self.sage_detail.pack(
                anchor="w", padx=14, pady=(2, 8),
                before=self.refresh_button,
            )
        self.sage_label.configure(
            text=f"Sage • {str(sage['mode']).casefold()} • "
            f"{str(sage['activity_state']).casefold()}"
        )
        self.sage_detail.configure(
            text=f"{sage['expression']} • {sage['mood']} • "
            "presentation only • authority effect NONE"
        )

    def _render_timeline(self, widget: Any, view: ProductViewModel) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        if not view.timeline:
            widget.insert(
                "end",
                "KEEPER\nStart with an idea. I?ll clarify scope and prepare a "
                "charter for explicit approval.\n",
                "keeper",
            )
        for item in view.timeline:
            widget.insert(
                "end", f"{item.title.upper()} • {item.state}\n", item.kind
            )
            widget.insert("end", f"{item.body}\n\n", "body")
        widget.configure(state="disabled")

    def _render_home(self, view: ProductViewModel) -> None:
        rail = dict(view.right_rail)
        recent = view.evidence_cards[-1] if view.evidence_cards else None
        lines = [
            "PROJECT", view.project_title,
            "", "STATUS", view.project_status,
            "", "WORKFLOW",
            f"{len(view.workflow_rows)} stages • "
            f"{rail.get('Assignments working', '0')} working",
            "", "USAGE",
            f"{rail.get('Usage waits', '0')} waiting for reset",
            "", "LATEST EVIDENCE",
            (
                f"{recent['state']} • {recent['kind']}"
                if recent else "No evidence yet"
            ),
        ]
        self._set_text(self.home_summary, "\n".join(lines))

    def _render_projects(self, view: ProductViewModel) -> None:
        if not view.project_cards:
            self._set_text(
                self.projects_text,
                "No project yet. Begin a conversation to create a charter proposal.",
            )
            return
        card = view.project_cards[0]
        lines = [
            str(card["title"]),
            f"Status: {card['status']}",
            f"Charter revision: {card['charter_revision']}",
            f"Delegation: {card['delegation_mode'] or 'Not configured'}",
            f"Budget: {card['budget_limit'] or 'No spend authorized'} "
            f"{card['budget_currency'] or ''}".rstrip(),
            f"Progress: {card['progress']}", "", "Goals",
            *[f"  • {item}" for item in card["goals"]],
            "", "Constraints",
            *[f"  • {item}" for item in card["constraints"]],
            "", "Exclusions",
            *[f"  • {item}" for item in card["exclusions"]],
            "", "Approved providers",
            *[f"  • {item}" for item in card["approved_providers"]],
            "", "Approved tools",
            *[f"  • {item}" for item in card["approved_tools"]],
            "", "Workspace boundaries",
            *[f"  • {item}" for item in card["workspaces"]],
            "", "Data classifications",
            *[f"  • {item}" for item in card["data_classifications"]],
            "", f"Work items: {len(view.workflow_rows)}",
            f"Evidence bundles: {len(view.evidence_cards)}",
            f"Reviews: {len(view.review_cards)}",
        ]
        self._set_text(self.projects_text, "\n".join(lines))

    def _render_workflow(self, view: ProductViewModel) -> None:
        self._clear_tree(self.workflow_tree)
        for row in view.workflow_rows:
            assignment = row.get("assignment") or {}
            self.workflow_tree.insert(
                "", "end",
                values=(
                    row.get("title"),
                    assignment.get("role") or row.get("role"),
                    assignment.get("provider_id") or "Unassigned",
                    assignment.get("state") or row.get("status"),
                    (
                        "WAITING_FOR_USAGE_RESET"
                        if assignment.get("state") == "WAITING_FOR_USAGE_RESET"
                        else "—"
                    ),
                ),
            )

    def _render_providers(self, view: ProductViewModel) -> None:
        self._clear_tree(self.providers_tree)
        for card in view.provider_cards:
            self.providers_tree.insert(
                "", "end",
                values=(
                    card["name"], card["composition"], card["health"],
                    card["active_jobs"], card["capacity"],
                ),
            )

        usage = [
            "USAGE POOLS",
            *[
                (
                    f"{card['pool_id']}: {card['status']} | "
                    f"reserved {card['reserved']} | remaining {card['remaining']} | "
                    f"reset {card['reset_at'] or 'unobserved'} | "
                    f"source {card['source'] or 'unobserved'} "
                    f"({card['confidence'] or 'unknown confidence'})"
                )
                for card in view.usage_cards
            ],
        ]
        if len(usage) == 1:
            usage.append("No usage pools configured")
        self._set_text(self.usage_text, "\n".join(usage))

    def _render_evidence(self, view: ProductViewModel) -> None:
        self._clear_tree(self.evidence_tree)
        for card in view.evidence_cards:
            review = card.get("review") or {}
            self.evidence_tree.insert(
                "", "end",
                values=(
                    card["evidence_id"], card["producer"],
                    ", ".join(card["kind"]), card["state"],
                    review.get("disposition") or review.get("state") or "Pending",
                ),
            )

        reviews = [
            "VALIDATED REVIEW RESULTS",
            *[
                (
                    f"{card.get('review_id')}: "
                    f"{card.get('disposition') or card.get('state') or 'Pending'} | "
                    f"reviewer {card.get('reviewer_assignment_id') or 'Unassigned'} | "
                    f"producer evidence {card.get('producer_evidence') or 'Missing'} | "
                    f"review evidence {card.get('reviewer_evidence') or 'Missing'}"
                )
                for card in view.review_cards
            ],
        ]
        if len(reviews) == 1:
            reviews.append("No validated review results yet")
        reviews.extend(
            [
                "",
                "TYPED EVIDENCE REFERENCES",
                *[
                    (
                        f"{card['reference_id']}: {card['classification']} | "
                        f"producer {card['source_producer'] or 'Unknown'} | "
                        f"reviewed {card['reviewed_assignment'] or 'Unknown'} | "
                        f"sha256 {card['digest']} | {card['size_bytes']} bytes | "
                        f"{card['validation_state']} | {card['review_state']}"
                    )
                    for card in view.evidence_reference_cards
                ],
            ]
        )
        if not view.evidence_reference_cards:
            reviews.append("No typed evidence references yet")
        self._set_text(self.review_text, "\n".join(reviews))

    def _render_safety(self, view: ProductViewModel) -> None:
        lines = ["SAFETY AND RECOVERY"]
        for row in view.safety_rows:
            lines.extend(["", f"{row['label']}: {row['value']}"])
        lines.extend([
            "",
            "Unavailable by design: force-push, history rewrite, deployment, "
            "spending, credentials, live trading, and service changes.",
        ])
        self._set_text(self.safety_text, "\n".join(lines))

    def _render_settings(self, view: ProductViewModel) -> None:
        diagnostics = self.pass_b.diagnostics()
        usage = "\n".join(
            f"{item['pool_id']}: {item['status']} • reserved {item['reserved']}"
            for item in view.usage_cards
        ) or "No usage pools configured"
        self._set_text(
            self.settings_summary,
            "\n".join([
                f"Evidence: {self.application.data_directory / 'evidence'}",
                f"Composition: {view.composition}",
                f"Providers / sessions: {diagnostics['providers']} / "
                f"{diagnostics['sessions']}",
                f"KeeperAuthority: {diagnostics['authority']['state']}",
                f"Sage: {view.sage['mode']} • authority effect NONE",
                "Paid fallback: unavailable", "", usage,
            ]),
        )
        if self.developer_details_enabled and view.developer_details is not None:
            self._set_text(
                self.developer_text,
                json.dumps(view.developer_details, indent=2, default=str),
            )
            if not self.developer_text.winfo_ismapped():
                self.developer_text.pack(
                    fill="both", expand=True, padx=14, pady=(0, 14)
                )
        elif self.developer_text.winfo_ismapped():
            self.developer_text.pack_forget()

    def _send(self, widget: Any) -> None:
        text = widget.get("1.0", "end").strip()
        if not text:
            return
        try:
            if self.project_id is None:
                outcome = self.pass_b.begin_conversation(text)
                self.project_id = outcome.project.project_id
            else:
                outcome = self.pass_b.continue_conversation(
                    self.project_id, text
                )
        except (OSError, PermissionError, RuntimeError, ValueError) as error:
            self.status.set(f"Conversation blocked: {error}")
            return
        widget.delete("1.0", "end")
        self.status.set(
            "Conversation recorded; review the current charter and project state"
        )
        self.refresh()

    def _render_project_selector(
        self, view: ProductViewModel
    ) -> None:
        labels: list[str] = []
        self._project_labels = {}
        selected_label = "No project selected"
        for item in view.project_catalog:
            project_id = str(item["project_id"])
            label = f"{item.get('title') or project_id}  •  {item.get('state')}"
            labels.append(label)
            self._project_labels[label] = project_id
            if project_id == view.project_id:
                selected_label = label
        self.project_selector.configure(values=tuple(labels))
        self.project_choice.set(selected_label)

    def _select_project_from_ui(self, _event: Any = None) -> None:
        project_id = self._project_labels.get(self.project_choice.get())
        if project_id is None:
            return
        try:
            self.pass_b.select_project(project_id)
        except (KeyError, PermissionError, RuntimeError, ValueError) as error:
            self.status.set(f"Project selection blocked: {error}")
            return
        self.project_id = project_id
        self.refresh()

    def _approve_displayed_charter(
        self, project_id: str, charter: dict[str, Any]
    ) -> dict[str, Any]:
        charter_id = charter.get("charter_id")
        charter_revision = charter.get("revision")
        if (
            not isinstance(charter_id, str)
            or not charter_id
            or type(charter_revision) is not int
        ):
            raise ValueError(
                "displayed charter lacks an exact durable identity"
            )
        return self.pass_b.approve_and_plan_current_charter(
            project_id,
            expected_charter_id=charter_id,
            expected_charter_revision=charter_revision,
        )

    def _review_charter_approval(self) -> None:
        view = self.current_view
        if view is None or view.project_id is None:
            self.status.set("No current charter is available for approval")
            return
        charter = view.approval_charter_detail
        if not charter:
            self.status.set("No exact pending charter is available for approval")
            return
        dialog = self.tk.Toplevel(self.root)
        dialog.title("Founder approval required")
        dialog.geometry("760x680")
        dialog.configure(background=THEME.background)
        dialog.transient(self.root)
        dialog.grab_set()
        self.ttk.Label(
            dialog,
            text="FOUNDER APPROVAL REQUIRED",
            style="Gold.TLabel",
            font=("Segoe UI Semibold", 16),
        ).pack(anchor="w", padx=24, pady=(24, 6))
        self.ttk.Label(
            dialog,
            text=(
                "Review the exact charter below. This window grants no "
                "authority; approval continues through Windows authentication."
            ),
            style="Muted.TLabel",
            wraplength=700,
        ).pack(anchor="w", padx=24, pady=(0, 12))
        detail = self.tk.Text(
            dialog,
            bg=THEME.surface_raised,
            fg=THEME.text,
            insertbackground=THEME.gold,
            relief="flat",
            wrap="word",
            padx=16,
            pady=16,
        )
        detail.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        fields = (
            ("Project", charter.get("title")),
            ("Revision", charter.get("revision")),
            ("Purpose", charter.get("purpose")),
            ("Deliverables", charter.get("deliverables")),
            ("Constraints", charter.get("constraints")),
            ("Non-goals", charter.get("non_goals")),
            ("Delegation", charter.get("delegation_mode")),
            (
                "Budget",
                f"{charter.get('budget_limit')} "
                f"{charter.get('budget_currency')}",
            ),
            ("Providers", charter.get("approved_providers")),
            ("Tools", charter.get("approved_tools")),
            ("Workspaces", charter.get("workspaces")),
            ("Evidence", charter.get("evidence_requirements")),
            ("Review", charter.get("review_requirements")),
            ("Unresolved questions", charter.get("unresolved_questions")),
        )
        detail.insert(
            "1.0",
            "\n\n".join(
                f"{label.upper()}\n"
                + (
                    "\n".join(f"• {item}" for item in value)
                    if isinstance(value, (list, tuple))
                    else str(value or "None")
                )
                for label, value in fields
            ),
        )
        detail.configure(state="disabled")

        def approve() -> None:
            dialog.destroy()
            try:
                result = self._approve_displayed_charter(
                    view.project_id or "", charter
                )
            except (OSError, PermissionError, RuntimeError, ValueError) as error:
                self.status.set(f"Founder approval blocked: {error}")
                self.refresh()
                return
            self.status.set(
                "Founder-approved charter activated; autonomous completion started "
                f"for {len(result['work_items'])} planned stages"
            )
            self.refresh()
            self._start_autonomous_completion(view.project_id or "")

        buttons = self.ttk.Frame(dialog, style="App.TFrame")
        buttons.pack(fill="x", padx=24, pady=(0, 20))
        self.ttk.Button(
            buttons, text="Not now", style="Quiet.TButton",
            command=dialog.destroy,
        ).pack(side="left")
        self.ttk.Button(
            buttons, text="Approve with Windows", style="Accent.TButton",
            command=approve,
        ).pack(side="right")

    def _show_page(self, name: str) -> None:
        self.pages[name].tkraise()
        self.page_title.configure(text=name)

    def _refresh_from_ui(self) -> None:
        self.refresh()
        self.status.set("Durable state refreshed")

    def _start_autonomous_completion(self, project_id: str) -> None:
        if not project_id or self._completion_running:
            return
        self._completion_running = True

        def worker() -> None:
            try:
                results = self.pass_b.run_delegated_completion(project_id)
                final = results[-1]
                message = f"{final.state}: {final.detail}"
            except (OSError, PermissionError, RuntimeError, ValueError) as error:
                message = f"Completion blocked: {error}"
            try:
                self.root.after(0, lambda: finish(message))
            except self.tk.TclError:
                self._completion_running = False

        def finish(message: str) -> None:
            self._completion_running = False
            self.status.set(message)
            self.refresh()

        threading.Thread(
            target=worker,
            name=f"keeper-completion-{project_id[:12]}",
            daemon=True,
        ).start()

    def _toggle_developer_details(self) -> None:
        self.developer_details_enabled = bool(self.developer_toggle.get())
        self.refresh()

    def _responsive_layout(self, event: Any) -> None:
        if event.widget is not self.root:
            return
        if event.width < 1180:
            self.rail.grid_remove()
        elif not self.rail.winfo_ismapped():
            self.rail.grid()

    def _card(self, parent: Any) -> Any:
        return self.ttk.Frame(parent, style="Card.TFrame")

    def _timeline(self, parent: Any) -> Any:
        widget = self.tk.Text(
            parent, bg=THEME.surface_raised, fg=THEME.text,
            insertbackground=THEME.gold, relief="flat", wrap="word",
            padx=4, pady=4,
        )
        tags = {
            "founder": THEME.gold, "keeper": THEME.text,
            "approval": THEME.warning, "warning": THEME.danger,
            "evidence": THEME.success, "review": THEME.success,
            "status": THEME.muted,
        }
        for name, color in tags.items():
            widget.tag_configure(
                name, foreground=color, font=("Segoe UI Semibold", 9)
            )
        widget.tag_configure("body", foreground=THEME.text, spacing3=8)
        return widget

    def _readonly_text(self, parent: Any, *, height: int = 20) -> Any:
        widget = self.tk.Text(
            parent, height=height, bg=THEME.surface, fg=THEME.text,
            insertbackground=THEME.gold, relief="flat", wrap="word",
            padx=14, pady=14,
        )
        widget.configure(state="disabled")
        return widget

    @staticmethod
    def _clear_tree(tree: Any) -> None:
        for item in tree.get_children():
            tree.delete(item)

    @staticmethod
    def _set_text(widget: Any, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _first_run(self) -> None:
        controller = ProductSetupController(self.application)
        diagnostics = self.application.diagnostics()
        pass_b_diagnostics = self.pass_b.diagnostics()
        wizard = self.tk.Toplevel(self.root)
        wizard.title("Keeper setup")
        wizard.geometry("760x600")
        wizard.configure(background=THEME.background)
        wizard.transient(self.root)
        wizard.grab_set()
        title = self.ttk.Label(wizard, text="", style="Title.TLabel")
        title.pack(anchor="w", padx=24, pady=(24, 8))
        body = self.tk.Text(
            wizard, bg=THEME.surface_raised, fg=THEME.text,
            insertbackground=THEME.gold, relief="flat", wrap="word",
            padx=16, pady=16,
        )
        body.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        fields = self.ttk.Frame(wizard, style="App.TFrame")
        fields.pack(fill="x", padx=24)
        evidence = self.tk.StringVar(value=controller.evidence_directory)
        repository = self.tk.StringVar()
        provider_policy = self.tk.StringVar(value=controller.provider_policy)
        for label, variable in (
            ("Evidence directory", evidence),
            ("First repository (optional)", repository),
        ):
            self.ttk.Label(
                fields, text=label, style="Title.TLabel",
                font=("Segoe UI", 10),
            ).pack(anchor="w")
            self.ttk.Entry(
                fields, textvariable=variable, style="Keeper.TEntry",
            ).pack(fill="x", pady=(2, 8))
        self.ttk.Label(
            fields, text="Default provider policy", style="Title.TLabel",
            font=("Segoe UI", 10),
        ).pack(anchor="w")
        self.ttk.Combobox(
            fields, textvariable=provider_policy,
            values=(
                "automatic", "local-only", "strongest", "ollama",
            ),
            state="readonly",
        ).pack(fill="x", pady=(2, 8))

        def render() -> None:
            controller.evidence_directory = evidence.get()
            controller.repository = repository.get()
            controller.provider_policy = provider_policy.get()
            title.configure(
                text=f"{controller.index + 1}. {SETUP_STEPS[controller.index][1]}"
            )
            providers = diagnostics.get("providers", [])
            descriptions = {
                "boundaries": (
                    "Keeper cannot force-push, rewrite history, deploy, spend, "
                    "access credentials, change services, or trade live without "
                    "a separate approved workflow."
                ),
                "storage": (
                    "Choose the durable evidence directory. Keeper only validates "
                    "local write access; it does not change machine configuration."
                ),
                "repository": (
                    "Optionally choose the first Git repository. Keeper inspects it; "
                    "it does not rewrite history or push."
                ),
                "providers": "Detected or configured providers:\n" + "\n".join(
                    f"• {item.get('display_name')}: "
                    f"{item.get('configured_executable') or item.get('detected_executable') or 'not configured'}"
                    for item in providers
                ),
                "provider_validation": "Provider verification:\n" + "\n".join(
                    f"• {item.get('display_name')}: "
                    f"{item.get('verification_status')} • "
                    f"{item.get('failure_reason') or 'ready'}"
                    for item in providers
                ),
                "authority": (
                    f"KeeperAuthority: {pass_b_diagnostics['authority']['state']}. "
                    "Setup does not start, stop, install, or reconfigure it."
                ),
                "finish": (
                    "Setup is ready. Finish to open the conversation-first "
                    "Keeper home screen."
                ),
            }
            self._set_text(body, descriptions[controller.step])

        def move(direction: str) -> None:
            try:
                controller.back() if direction == "back" else controller.next()
                render()
            except Exception as error:
                self.status.set(f"Setup blocked: {error}")

        def finish() -> None:
            controller.evidence_directory = evidence.get()
            controller.repository = repository.get()
            controller.provider_policy = provider_policy.get()
            try:
                controller.finish()
            except Exception as error:
                self.status.set(f"Setup blocked: {error}")
                return
            wizard.destroy()
            self.status.set("Setup completed")
            self.refresh()

        navigation = self.ttk.Frame(wizard, style="App.TFrame")
        navigation.pack(fill="x", padx=24, pady=(4, 20))
        self.ttk.Button(
            navigation, text="Back", style="Quiet.TButton",
            command=lambda: move("back"),
        ).pack(side="left")
        self.ttk.Button(
            navigation, text="Next", style="Quiet.TButton",
            command=lambda: move("next"),
        ).pack(side="left", padx=8)
        self.ttk.Button(
            navigation, text="Finish", style="Accent.TButton", command=finish,
        ).pack(side="right")
        render()


def _desktop_pass_b_application(
    application: Any,
    *,
    authority_health_client: Any | None = None,
) -> PassBApplication:
    legacy_path_call = isinstance(application, (str, Path))
    data_directory = (
        Path(application)
        if legacy_path_call
        else Path(application.data_directory)
    )
    health_client = authority_health_client
    if health_client is None:
        health_client = ProductionAuthorityServiceClient(timeout_seconds=0.25)
        bindings = () if legacy_path_call else _configured_authority_bindings(application)
        if bindings:
            from keeper.pass_b.provider_bridge import bridge_qualified_provider
            from keeper.pass_b.usage_authority import ProductionUsageResetVerifier

            result = PassBApplication(
                data_directory,
                authority_client=health_client,
                authority_health_client=health_client,
                provider_bindings=bindings,
                authority_exchange_root=data_directory / "authority-exchange",
                usage_reset_verifier=ProductionUsageResetVerifier.unavailable(),
            )
            for binding in bindings:
                bridge_qualified_provider(
                    result.orchestration, health_client, binding
                )
            return result
    return PassBApplication(
        data_directory,
        authority_health_client=health_client,
    )


def _configured_authority_bindings(
    application: Any,
) -> tuple[Any, ...]:
    from keeper.executive.authority_gateway import AuthorityProviderBinding

    registrations = application.provider_registrations()
    evidence = application.qualification_evidence()
    bindings: list[AuthorityProviderBinding] = []
    for registration in registrations.values():
        registration_id = registration.get("trusted_registration_id")
        if not isinstance(registration_id, str) or not registration_id:
            continue
        matches = [
            item
            for item in evidence.values()
            if item.get("registration_id") == registration_id
            and item.get("qualification_result") == "qualified"
            and isinstance(item.get("id"), str)
        ]
        if len(matches) != 1:
            continue
        bindings.append(
            AuthorityProviderBinding(
                registration_id, str(matches[0]["id"])
            )
        )
    return tuple(bindings)
