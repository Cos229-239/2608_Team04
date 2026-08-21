from __future__ import annotations

import json
from functools import partial
from typing import Any

from keeper.ui.desktop import KeeperProductDesktop as _LegacyProductDesktop
from keeper.ui.theme import THEME
from keeper.ui.view_models import ProductViewModel


COMMAND_CENTER_NAVIGATION = (
    "Dashboard",
    "Conversation",
    "Projects & Charters",
    "Workflows",
    "Approvals",
    "Providers",
    "Audit & Receipts",
    "Recovery",
    "Settings",
)

_NAV_ICONS = {
    "Dashboard": "◆",
    "Conversation": "◇",
    "Projects & Charters": "▣",
    "Workflows": "▷",
    "Approvals": "✓",
    "Providers": "⌬",
    "Audit & Receipts": "▤",
    "Recovery": "↻",
    "Settings": "⚙",
}

_GOOD_STATES = {
    "ACCEPTED",
    "ACTIVE",
    "APPROVED",
    "AVAILABLE",
    "COMPLETED",
    "READY",
    "RUNNING",
    "VALIDATED",
}
_WARNING_STATES = {
    "APPROVAL_REQUESTED",
    "BLOCKED",
    "PAUSED",
    "PROPOSED",
    "WAITING_FOR_USAGE_RESET",
}
_DANGER_STATES = {
    "CANCELED",
    "CANCELLED",
    "FAILED",
    "NOT_CONFIGURED",
    "REJECTED",
    "REVOKED",
    "UNCERTAIN",
    "UNAVAILABLE",
}


class KeeperExecutiveDesktop(_LegacyProductDesktop):
    """Premium desktop projection over durable Keeper services.

    The shell renders state and routes supported service actions. It owns no
    Founder, workflow, provider, review, recovery, or KeeperAuthority truth.
    """

    @property
    def navigation_pages(self) -> tuple[str, ...]:
        return COMMAND_CENTER_NAVIGATION

    def _build_shell(self) -> None:
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        banner = self.ttk.Frame(
            self.root, style="Banner.TFrame", height=84
        )
        banner.grid(row=0, column=0, columnspan=3, sticky="ew")
        banner.grid_propagate(False)
        banner.grid_columnconfigure(0, weight=1)
        brand = self.ttk.Frame(banner, style="Banner.TFrame")
        brand.grid(row=0, column=0, sticky="w", padx=22, pady=10)
        self.ttk.Label(
            brand, text="DARKSAGE KEEPER", style="Brand.TLabel"
        ).pack(anchor="w")
        self.ttk.Label(
            brand,
            text="FOUNDER • AUTHORITY • EXECUTION • ACCOUNTABILITY",
            style="BrandSub.TLabel",
        ).pack(anchor="w", pady=(1, 0))

        pillars = self.ttk.Frame(banner, style="Banner.TFrame")
        pillars.grid(row=0, column=1, sticky="e", padx=18, pady=8)
        self.banner_values: dict[str, Any] = {}
        for column, (key, title, subtitle) in enumerate(
            (
                ("Founder", "FOUNDER FIRST", "Explicit authority"),
                ("Authority", "SECURE BY DESIGN", "Every action verified"),
                ("Providers", "PROVIDERS MANAGED", "Execution you control"),
                ("Audit", "FULL AUDIT TRAIL", "Nothing hidden"),
                ("Offline", "LOCAL-FIRST", "Cloud never required"),
            )
        ):
            block = self.ttk.Frame(pillars, style="Banner.TFrame")
            block.grid(row=0, column=column, padx=12)
            value = self.tk.StringVar(value=title)
            self.ttk.Label(
                block, textvariable=value, style="BannerValue.TLabel"
            ).pack()
            self.ttk.Label(
                block,
                text=subtitle,
                style="BrandSub.TLabel",
            ).pack()
            self.banner_values[key] = value

        sidebar = self.ttk.Frame(
            self.root, style="Sidebar.TFrame", width=220
        )
        sidebar.grid(row=1, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        self.ttk.Label(
            sidebar, text="EXECUTIVE CONTROL", style="RailHeading.TLabel"
        ).pack(anchor="w", padx=18, pady=(22, 12))
        self.nav_buttons: dict[str, Any] = {}
        for name in COMMAND_CENTER_NAVIGATION:
            button = self.ttk.Button(
                sidebar,
                text=f"{_NAV_ICONS[name]}   {name}",
                style="Nav.TButton",
                command=partial(self._show_page, name),
            )
            button.pack(fill="x", padx=8, pady=1)
            self.nav_buttons[name] = button
        self.composition_label = self.ttk.Label(
            sidebar,
            text="NOT_CONFIGURED",
            style="RailHeading.TLabel",
        )
        self.composition_label.pack(
            side="bottom", anchor="w", padx=18, pady=(0, 18)
        )
        self.ttk.Label(
            sidebar,
            text="KEEPER COMPOSITION",
            style="BrandSub.TLabel",
        ).pack(side="bottom", anchor="w", padx=18)

        content = self.ttk.Frame(self.root, style="App.TFrame")
        content.grid(row=1, column=1, sticky="nsew", padx=18, pady=14)
        content.grid_rowconfigure(1, weight=1)
        content.grid_columnconfigure(0, weight=1)
        header = self.ttk.Frame(content, style="App.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        header.grid_columnconfigure(0, weight=1)
        title_block = self.ttk.Frame(header, style="App.TFrame")
        title_block.grid(row=0, column=0, sticky="w")
        self.page_eyebrow = self.ttk.Label(
            title_block,
            text="EXECUTIVE CONTROL CENTER",
            style="Title.TLabel",
            font=("Segoe UI Semibold", 8),
        )
        self.page_eyebrow.pack(anchor="w")
        self.page_title = self.ttk.Label(
            title_block, text="Dashboard", style="Title.TLabel"
        )
        self.page_title.pack(anchor="w")
        self.project_choice = self.tk.StringVar(
            value="No project selected"
        )
        self.project_selector = self.ttk.Combobox(
            header,
            textvariable=self.project_choice,
            state="readonly",
            width=40,
            style="Keeper.TCombobox",
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

        self.rail = self.ttk.Frame(
            self.root, style="Rail.TFrame", width=245
        )
        self.rail.grid(row=1, column=2, sticky="nsew")
        self.rail.grid_propagate(False)
        self.ttk.Label(
            self.rail, text="SYSTEM INTEGRITY", style="RailHeading.TLabel"
        ).pack(anchor="w", padx=16, pady=(22, 14))
        labels = (
            "Keeper",
            "Active project",
            "Assignments working",
            "Providers working",
            "Usage waits",
            "Approvals",
            "Uncertain",
            "Workspace conflicts",
            "KeeperAuthority",
            "Delegated mode",
        )
        self.rail_values: dict[str, Any] = {}
        for label in labels:
            holder = self.ttk.Frame(self.rail, style="Rail.TFrame")
            holder.pack(fill="x", padx=16, pady=4)
            self.ttk.Label(
                holder,
                text=label.upper(),
                style="RailHeading.TLabel",
                font=("Segoe UI Semibold", 7),
            ).pack(anchor="w")
            value = self.tk.StringVar(value="—")
            self.ttk.Label(
                holder,
                textvariable=value,
                style="RailBody.TLabel",
                wraplength=205,
            ).pack(anchor="w")
            self.rail_values[label] = value
        self.ttk.Label(
            self.rail,
            text=(
                "UI status never grants authority. Durable services remain "
                "the source of truth."
            ),
            style="RailBody.TLabel",
            wraplength=205,
        ).pack(side="bottom", anchor="w", padx=16, pady=18)

        status_frame = self.ttk.Frame(
            self.root, style="Sidebar.TFrame"
        )
        status_frame.grid(
            row=2, column=0, columnspan=3, sticky="ew"
        )
        self.ttk.Label(
            status_frame,
            textvariable=self.status,
            style="RailBody.TLabel",
        ).pack(side="left", padx=18, pady=5)
        self.ttk.Label(
            status_frame,
            text="Founder First  •  Systems Always  •  Truth in Every Action",
            style="RailHeading.TLabel",
        ).pack(side="right", padx=18, pady=5)

    def _build_pages(self) -> None:
        for name in COMMAND_CENTER_NAVIGATION:
            page = self.ttk.Frame(
                self.page_host, style="App.TFrame"
            )
            page.grid(row=0, column=0, sticky="nsew")
            page.grid_rowconfigure(0, weight=1)
            page.grid_columnconfigure(0, weight=1)
            self.pages[name] = page
        self._build_dashboard()
        self._build_conversation()
        self._build_projects()
        self._build_workflows()
        self._build_approvals()
        self._build_providers()
        self._build_audit()
        self._build_recovery()
        self._build_command_settings()

    def _build_dashboard(self) -> None:
        page = self.pages["Dashboard"]
        for column in range(4):
            page.grid_columnconfigure(column, weight=1)
        page.grid_rowconfigure(2, weight=1)
        welcome = self._card(page)
        welcome.grid(
            row=0, column=0, columnspan=4, sticky="ew", pady=(0, 10)
        )
        welcome.grid_columnconfigure(0, weight=1)
        self.welcome_project = self.tk.StringVar(
            value="Welcome, Founder"
        )
        self.ttk.Label(
            welcome,
            textvariable=self.welcome_project,
            style="Heading.TLabel",
            font=("Segoe UI Semibold", 15),
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 2))
        self.welcome_status = self.tk.StringVar(
            value="System status loading"
        )
        self.welcome_status_label = self.ttk.Label(
            welcome,
            textvariable=self.welcome_status,
            style="StatusSuccess.TLabel",
        )
        self.welcome_status_label.grid(
            row=1, column=0, sticky="w", padx=14, pady=(0, 12)
        )
        self.ttk.Label(
            welcome,
            text="FOUNDER MODE • AUTHORITY NEVER DELEGATED BY UI",
            style="Gold.TLabel",
        ).grid(
            row=0, column=1, rowspan=2, sticky="e", padx=14
        )

        self.metric_values: dict[str, Any] = {}
        for column, label in enumerate(
            (
                "ACTIVE PROJECTS",
                "WORKFLOW STAGES",
                "PENDING APPROVALS",
                "PROVIDERS READY",
            )
        ):
            card = self._card(page)
            card.grid(
                row=1,
                column=column,
                sticky="nsew",
                padx=(0 if column == 0 else 5, 0 if column == 3 else 5),
                pady=(0, 10),
            )
            self.ttk.Label(
                card, text=label, style="Eyebrow.TLabel"
            ).pack(anchor="w", padx=12, pady=(10, 0))
            value = self.tk.StringVar(value="0")
            self.ttk.Label(
                card, textvariable=value, style="Metric.TLabel"
            ).pack(anchor="w", padx=12, pady=(0, 10))
            self.metric_values[label] = value

        activity = self._card(page)
        activity.grid(
            row=2, column=0, columnspan=3, sticky="nsew", padx=(0, 5)
        )
        self.ttk.Label(
            activity, text="RECENT ACTIVITY", style="Heading.TLabel"
        ).pack(anchor="w", padx=14, pady=(12, 4))
        self.home_timeline = self._timeline(activity)
        self.home_timeline.pack(
            fill="both", expand=True, padx=14, pady=(0, 12)
        )

        integrity = self._card(page)
        integrity.grid(row=2, column=3, sticky="nsew", padx=(5, 0))
        self.ttk.Label(
            integrity, text="SYSTEM INTEGRITY", style="Heading.TLabel"
        ).pack(anchor="w", padx=14, pady=(12, 4))
        self.home_summary = self._readonly_text(integrity, height=13)
        self.home_summary.pack(
            fill="both", expand=True, padx=12, pady=(0, 4)
        )
        self.sage_label = self.ttk.Label(
            integrity, text="Sage • listening", style="Gold.TLabel"
        )
        self.sage_label.pack(anchor="w", padx=14)
        self.sage_detail = self.ttk.Label(
            integrity,
            text="Presentation only • authority effect NONE",
            style="Muted.TLabel",
            wraplength=240,
        )
        self.sage_detail.pack(anchor="w", padx=14, pady=(2, 6))
        actions = self.ttk.Frame(integrity, style="Card.TFrame")
        actions.pack(fill="x", padx=12, pady=(2, 12))
        self.approve_charter_button = self.ttk.Button(
            actions,
            text="Review Approval",
            style="Accent.TButton",
            command=self._review_charter_approval,
        )
        self.approve_charter_button.pack(fill="x", pady=(0, 5))
        self.refresh_button = self.ttk.Button(
            actions,
            text="System Check",
            style="Quiet.TButton",
            command=self._refresh_from_ui,
        )
        self.refresh_button.pack(fill="x")

    def _build_conversation(self) -> None:
        parent = self._card(self.pages["Conversation"])
        parent.grid(sticky="nsew")
        self.ttk.Label(
            parent,
            text="CONVERSATION & CHARTER INTAKE",
            style="Heading.TLabel",
        ).pack(anchor="w", padx=14, pady=(12, 2))
        self.ttk.Label(
            parent,
            text=(
                "Conversation is non-authoritative. Keeper turns intent into "
                "a durable charter for explicit Founder approval."
            ),
            style="Muted.TLabel",
        ).pack(anchor="w", padx=14, pady=(0, 8))
        self.conversation_timeline = self._timeline(parent)
        self.conversation_timeline.pack(
            fill="both", expand=True, padx=14, pady=(0, 10)
        )
        composer = self.ttk.Frame(parent, style="Card.TFrame")
        composer.pack(fill="x", padx=14, pady=(0, 14))
        self.conversation_input = self.tk.Text(
            composer,
            height=3,
            bg=THEME.surface,
            fg=THEME.text,
            insertbackground=THEME.gold,
            relief="flat",
            wrap="word",
            padx=10,
            pady=8,
        )
        self.conversation_input.pack(
            side="left", fill="x", expand=True
        )
        self.ttk.Button(
            composer,
            text="Send to Keeper",
            style="Accent.TButton",
            command=partial(self._send, self.conversation_input),
        ).pack(side="left", padx=(10, 0))

    def _build_projects(self) -> None:
        page = self.pages["Projects & Charters"]
        page.grid_columnconfigure(0, weight=3)
        page.grid_columnconfigure(1, weight=2)
        page.grid_rowconfigure(0, weight=1)
        left = self._card(page)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        right = self._card(page)
        right.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        self.ttk.Label(
            left, text="PROJECTS", style="Heading.TLabel"
        ).pack(anchor="w", padx=12, pady=(12, 6))
        self.project_tree = self._tree(
            left, ("project", "status", "charter", "progress")
        )
        self.project_tree.pack(
            fill="both", expand=True, padx=12, pady=(0, 12)
        )
        self.ttk.Label(
            right, text="CHARTER DETAILS", style="Heading.TLabel"
        ).pack(anchor="w", padx=12, pady=(12, 6))
        self.projects_text = self._readonly_text(right)
        self.projects_text.pack(
            fill="both", expand=True, padx=12, pady=(0, 12)
        )

    def _build_workflows(self) -> None:
        page = self.pages["Workflows"]
        page.grid_rowconfigure(1, weight=1)
        summary = self._card(page)
        summary.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self.ttk.Label(
            summary, text="ACTIVE WORKFLOW", style="Eyebrow.TLabel"
        ).pack(anchor="w", padx=12, pady=(10, 0))
        self.workflow_summary_text = self._readonly_text(
            summary, height=4
        )
        self.workflow_summary_text.pack(
            fill="x", padx=12, pady=(0, 10)
        )
        table = self._card(page)
        table.grid(row=1, column=0, sticky="nsew")
        self.workflow_tree = self._tree(
            table, ("stage", "role", "provider", "status", "usage")
        )
        self.workflow_tree.pack(
            fill="both", expand=True, padx=12, pady=12
        )

    def _build_approvals(self) -> None:
        page = self.pages["Approvals"]
        card = self._card(page)
        card.grid(sticky="nsew")
        self.ttk.Label(
            card, text="FOUNDER APPROVALS", style="Heading.TLabel"
        ).pack(anchor="w", padx=16, pady=(16, 4))
        self.ttk.Label(
            card,
            text=(
                "This page displays durable approval state. The desktop "
                "cannot authenticate or grant authority by itself."
            ),
            style="Muted.TLabel",
            wraplength=820,
        ).pack(anchor="w", padx=16, pady=(0, 10))
        self.approvals_text = self._readonly_text(card, height=20)
        self.approvals_text.pack(
            fill="both", expand=True, padx=16, pady=(0, 12)
        )
        self.approvals_approve_button = self.ttk.Button(
            card,
            text="Review Exact Charter",
            style="Accent.TButton",
            command=self._review_charter_approval,
        )
        self.approvals_approve_button.pack(
            anchor="e", padx=16, pady=(0, 16)
        )

    def _build_providers(self) -> None:
        page = self.pages["Providers"]
        page.grid_rowconfigure(0, weight=3)
        page.grid_rowconfigure(1, weight=2)
        table = self._card(page)
        table.grid(row=0, column=0, sticky="nsew", pady=(0, 5))
        self.providers_tree = self._tree(
            table,
            ("provider", "composition", "health", "jobs", "capacity"),
        )
        self.providers_tree.pack(
            fill="both", expand=True, padx=12, pady=12
        )
        lower = self.ttk.Frame(page, style="App.TFrame")
        lower.grid(row=1, column=0, sticky="nsew", pady=(5, 0))
        lower.grid_columnconfigure(0, weight=3)
        lower.grid_columnconfigure(1, weight=2)
        lower.grid_rowconfigure(0, weight=1)
        usage = self._card(lower)
        usage.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        detail = self._card(lower)
        detail.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        self.ttk.Label(
            usage, text="USAGE POOLS", style="Heading.TLabel"
        ).pack(anchor="w", padx=12, pady=(10, 2))
        self.usage_text = self._readonly_text(usage, height=8)
        self.usage_text.pack(
            fill="both", expand=True, padx=12, pady=(0, 10)
        )
        self.ttk.Label(
            detail, text="PROVIDER BOUNDARIES", style="Heading.TLabel"
        ).pack(anchor="w", padx=12, pady=(10, 2))
        self.provider_detail_text = self._readonly_text(
            detail, height=8
        )
        self.provider_detail_text.pack(
            fill="both", expand=True, padx=12, pady=(0, 10)
        )

    def _build_audit(self) -> None:
        page = self.pages["Audit & Receipts"]
        page.grid_rowconfigure(0, weight=3)
        page.grid_rowconfigure(1, weight=2)
        table = self._card(page)
        table.grid(row=0, column=0, sticky="nsew", pady=(0, 5))
        self.evidence_tree = self._tree(
            table, ("evidence", "producer", "kind", "state", "review")
        )
        self.evidence_tree.pack(
            fill="both", expand=True, padx=12, pady=12
        )
        receipts = self._card(page)
        receipts.grid(row=1, column=0, sticky="nsew", pady=(5, 0))
        self.ttk.Label(
            receipts,
            text="VALIDATED RECEIPTS & TYPED REFERENCES",
            style="Heading.TLabel",
        ).pack(anchor="w", padx=12, pady=(10, 2))
        self.review_text = self._readonly_text(receipts, height=9)
        self.review_text.pack(
            fill="both", expand=True, padx=12, pady=(0, 10)
        )

    def _build_recovery(self) -> None:
        page = self.pages["Recovery"]
        card = self._card(page)
        card.grid(sticky="nsew")
        self.ttk.Label(
            card, text="RECOVERY & RESILIENCE", style="Heading.TLabel"
        ).pack(anchor="w", padx=14, pady=(14, 4))
        self.ttk.Label(
            card,
            text=(
                "Uncertain external outcomes are preserved. Recovery requires "
                "supported service reconciliation; the UI never retries them."
            ),
            style="Muted.TLabel",
            wraplength=860,
        ).pack(anchor="w", padx=14, pady=(0, 8))
        self.safety_text = self._readonly_text(card)
        self.safety_text.pack(
            fill="both", expand=True, padx=14, pady=(0, 14)
        )

    def _build_command_settings(self) -> None:
        page = self.pages["Settings"]
        notebook = self.ttk.Notebook(
            page, style="Keeper.TNotebook"
        )
        notebook.grid(sticky="nsew")
        tabs: dict[str, Any] = {}
        for name in (
            "General",
            "Security",
            "Authority",
            "Providers",
            "Paths",
            "Logs",
        ):
            tab = self.ttk.Frame(notebook, style="Card.TFrame")
            notebook.add(tab, text=name)
            tabs[name] = tab

        self.settings_summary = self._settings_panel(
            tabs["General"], "PRODUCT COMPOSITION"
        )
        self._static_settings_panel(
            tabs["Security"],
            "SECURITY BOUNDARIES",
            (
                "Founder authentication remains required for authority-bearing "
                "actions.\n\nThe desktop cannot force-push, rewrite history, "
                "deploy, spend, access credentials, change services, or trade "
                "live.\n\nProvider output and evidence remain untrusted."
            ),
        )
        self.authority_health_text = self._static_settings_panel(
            tabs["Authority"],
            "KEEPERAUTHORITY HEALTH",
            (
                "Health is read through the supported diagnostic boundary. "
                "This page cannot start, stop, install, reconfigure, or grant "
                "execution authority to KeeperAuthority."
            ),
        )
        self._static_settings_panel(
            tabs["Providers"],
            "PROVIDER POLICY",
            (
                "Provider, account, session, model, privacy, cost, capability, "
                "usage, workspace, and role declarations are enforced by "
                "durable services. No paid fallback is available."
            ),
        )
        self._static_settings_panel(
            tabs["Paths"],
            "PROTECTED PATHS",
            (
                "Provider workspaces are canonicalized and isolated. Protected "
                "Keeper workflow state and pilot evidence never become provider "
                "workspace authority."
            ),
        )
        logs = tabs["Logs"]
        self.developer_toggle = self.tk.BooleanVar(value=False)
        self.ttk.Checkbutton(
            logs,
            text="Show redacted developer diagnostics",
            variable=self.developer_toggle,
            command=self._toggle_developer_details,
        ).pack(anchor="w", padx=14, pady=(14, 8))
        self.developer_text = self._readonly_text(logs, height=16)

    def _settings_panel(self, parent: Any, title: str) -> Any:
        self.ttk.Label(
            parent, text=title, style="Heading.TLabel"
        ).pack(anchor="w", padx=14, pady=(14, 6))
        widget = self._readonly_text(parent, height=18)
        widget.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        return widget

    def _static_settings_panel(
        self, parent: Any, title: str, body: str
    ) -> Any:
        widget = self._settings_panel(parent, title)
        self._set_text(widget, body)
        return widget

    def refresh(self) -> None:
        super().refresh()
        view = self.current_view
        if view is None:
            return
        self._render_executive_dashboard(view)
        self._render_project_table(view)
        self._render_workflow_header(view)
        self._render_provider_boundaries(view)
        self._render_approval_center(view)
        self._render_authority_health(view)
        self._retag_state_tables()

    def _render_executive_dashboard(self, view: ProductViewModel) -> None:
        rail = dict(view.right_rail)
        active_projects = sum(
            1
            for project in view.project_catalog
            if str(project.get("state", "")).upper()
            not in {"ARCHIVED", "CANCELED", "CANCELLED", "COMPLETED"}
        )
        providers_ready = sum(
            1
            for provider in view.provider_cards
            if str(provider.get("health", "")).upper()
            in {"AVAILABLE", "HEALTHY", "ONLINE", "READY"}
        )
        pending_approvals = self._integer_prefix(
            rail.get("Approvals", "0")
        )
        values = {
            "ACTIVE PROJECTS": active_projects,
            "WORKFLOW STAGES": len(view.workflow_rows),
            "PENDING APPROVALS": pending_approvals,
            "PROVIDERS READY": providers_ready,
        }
        for label, value in values.items():
            self.metric_values[label].set(str(value))
        self.welcome_project.set(
            f"Welcome, Founder  \u2022  {view.project_title}"
        )
        authority_state = rail.get("KeeperAuthority", "NOT_CONFIGURED")
        uncertain = self._integer_prefix(rail.get("Uncertain", "0"))
        self.welcome_status.set(
            f"KeeperAuthority {authority_state}  \u2022  "
            f"{uncertain} uncertain outcome(s) preserved"
        )
        self.welcome_status_label.configure(
            style=self._dashboard_status_style(
                authority_state, uncertain
            )
        )
        self.banner_values["Authority"].set(
            f"AUTHORITY {authority_state}"
        )
        self.banner_values["Providers"].set(
            f"PROVIDERS {providers_ready}/{len(view.provider_cards)}"
        )
        self.banner_values["Audit"].set(
            f"AUDIT {len(view.evidence_cards)} RECEIPTS"
        )
        self.banner_values["Offline"].set("LOCAL-FIRST READY")

    def _render_project_table(self, view: ProductViewModel) -> None:
        self._clear_tree(self.project_tree)
        for card in view.project_cards:
            state = str(card.get("status", "NOT_STARTED"))
            self._insert_stateful(
                self.project_tree,
                (
                    card.get("title"),
                    state,
                    card.get("charter_revision") or "Draft",
                    card.get("progress") or "Not started",
                ),
                state,
            )

    def _render_workflow_header(self, view: ProductViewModel) -> None:
        rail = dict(view.right_rail)
        self._set_text(
            self.workflow_summary_text,
            (
                f"{view.project_title}\n"
                f"Project {view.project_status}  \u2022  "
                f"Charter revision {view.charter_revision or 'Draft'}  \u2022  "
                f"{len(view.workflow_rows)} durable stage(s)  \u2022  "
                f"{rail.get('Assignments working', '0')} assignment(s) working\n"
                "Provider execution is Authority-bound; uncertain external "
                "effects are never retried by this UI."
            ),
        )

    def _render_provider_boundaries(self, view: ProductViewModel) -> None:
        host = view.provider_host
        lines = [
            "KEEPER PROVIDER HOST",
            (
                f"{host.get('state', 'NOT_CONFIGURED')}  •  "
                f"protocol {host.get('protocol') or 'NOT REPORTED'}  •  "
                f"provider {host.get('provider_state', 'UNAVAILABLE')}  •  "
                f"execution {host.get('execution_state', 'IDLE')}  •  "
                f"usage {host.get('usage_state', 'UNAVAILABLE')}"
            ),
            (
                "Founder action: "
                + str(host.get("founder_action_required") or "NONE")
            ),
            "",
            "PROVIDER / ACCOUNT DECLARATIONS",
            *[
                (
                    f"{card['name']}: {card['classification'] or 'UNCLASSIFIED'}"
                    f"  \u2022  cost {card['cost_mode'] or 'UNDECLARED'}"
                    f"  \u2022  privacy {card['privacy'] or 'UNDECLARED'}"
                    f"  \u2022  {len(card['sessions'])} session(s)"
                    f"\n    Auth {card['authentication_mode'] or 'UNDECLARED'}"
                    f"  \u2022  billing {card['billing_mode'] or 'UNDECLARED'}"
                    f"  \u2022  efforts {', '.join(card['effort_levels']) or 'NONE'}"
                    f"  \u2022  models {', '.join(card['model_allowlist']) or 'NONE'}"
                    f"\n    Usage {card['usage_state']}"
                    f"  \u2022  reviewer {card['reviewer_status']}"
                    f"  \u2022  API billing {card['api_billing']}"
                    f"  \u2022  paid fallback {card['paid_fallback']}"
                )
                for card in view.provider_cards
            ],
            "",
            "No automatic paid fallback, silent account switching, or "
            "capability widening is available.",
        ]
        if not view.provider_cards:
            lines.insert(1, "No providers configured")
        self._set_text(self.provider_detail_text, "\n".join(lines))

    def _render_approval_center(self, view: ProductViewModel) -> None:
        charter = view.approval_charter_detail
        approval_required = view.approval_required and bool(charter)
        approval_status = (
            "Founder approval required"
            if approval_required
            else (
                "Approval blocked: exact pending charter is unavailable"
                if view.approval_required
                else "No charter approval is currently requested"
            )
        )
        lines = [
            "AUTHORITY STATUS",
            approval_status,
            "",
            f"Project: {view.project_title}",
            f"Project state: {view.project_status}",
            f"Charter revision: {charter.get('revision') or 'Unavailable'}",
            f"Purpose: {charter.get('purpose') or 'Not specified'}",
            "",
            "Available controls:",
            *(
                [f"  \u2022 {control}" for control in view.controls]
                or ["  \u2022 No authority-bearing controls available"]
            ),
            "",
            "Approval is applied only after Windows Founder authentication and "
            "service validation of the exact charter displayed above.",
        ]
        self._set_text(self.approvals_text, "\n".join(lines))
        state = "normal" if approval_required else "disabled"
        for button in (
            self.approve_charter_button,
            self.approvals_approve_button,
        ):
            button.configure(state=state)

    def _render_settings(self, view: ProductViewModel) -> None:
        diagnostics = self.pass_b.diagnostics()
        authority = diagnostics.get("authority", {})
        authority_state = (
            authority.get("state", "NOT_CONFIGURED")
            if isinstance(authority, dict)
            else "NOT_CONFIGURED"
        )
        self._set_text(
            self.settings_summary,
            "\n".join(
                [
                    f"Composition: {view.composition}",
                    f"Project: {view.project_title}",
                    f"Providers / sessions: {diagnostics.get('providers', 0)} / "
                    f"{diagnostics.get('sessions', 0)}",
                    f"KeeperAuthority: {authority_state}",
                    f"Sage: {view.sage['mode']} ? authority effect NONE",
                    "Paid fallback: unavailable",
                    "Protected paths: enforced by durable workspace policy",
                ]
            ),
        )
        if self.developer_details_enabled:
            redacted = self._redacted_diagnostics(view, diagnostics)
            self._set_text(
                self.developer_text,
                json.dumps(redacted, indent=2, sort_keys=True),
            )
            if not self.developer_text.winfo_ismapped():
                self.developer_text.pack(
                    fill="both", expand=True, padx=14, pady=(0, 14)
                )
        elif self.developer_text.winfo_ismapped():
            self.developer_text.pack_forget()

    @staticmethod
    def _redacted_diagnostics(
        view: ProductViewModel, diagnostics: dict[str, Any]
    ) -> dict[str, Any]:
        authority_value = diagnostics.get("authority", {})
        authority = (
            authority_value if isinstance(authority_value, dict) else {}
        )
        return {
            "project": {
                "project_id": view.project_id,
                "status": view.project_status,
                "charter_revision": view.charter_revision,
            },
            "composition": view.composition,
            "counts": {
                "workflow_stages": len(view.workflow_rows),
                "providers": len(view.provider_cards),
                "usage_pools": len(view.usage_cards),
                "evidence_bundles": len(view.evidence_cards),
                "typed_references": len(view.evidence_reference_cards),
                "reviews": len(view.review_cards),
            },
            "authority": {
                "state": authority.get("state", "NOT_CONFIGURED"),
                "service_version": authority.get("service_version")
                or "NOT_REPORTED",
                "protocol_version": authority.get("protocol_version")
                or "NOT_REPORTED",
                "schema_version": authority.get("schema_version")
                or "NOT_REPORTED",
                "identity_state": authority.get("identity_state")
                or "NOT_REPORTED",
            },
            "sage": {
                "mode": view.sage.get("mode"),
                "authority_effect": "NONE",
            },
        }


    def _render_authority_health(self, view: ProductViewModel) -> None:
        diagnostics = self.pass_b.diagnostics().get("authority", {})
        lines = [
            f"State: {diagnostics.get('state', 'NOT_CONFIGURED')}",
            f"Composition: {view.composition}",
            f"Service version: {diagnostics.get('service_version') or 'NOT_REPORTED'}",
            f"Protocol version: {diagnostics.get('protocol_version') or 'NOT_REPORTED'}",
            f"Schema version: {diagnostics.get('schema_version') or 'NOT_REPORTED'}",
            f"Identity: {diagnostics.get('identity_state') or 'NOT_REPORTED'}",
            f"Last checked: {diagnostics.get('last_checked_at') or 'NOT_REPORTED'}",
            f"Failure: {diagnostics.get('failure_reason') or 'None'}",
            "",
            "Read-only health projection. Authority effect: NONE.",
        ]
        self._set_text(self.authority_health_text, "\n".join(lines))

    def _retag_state_tables(self) -> None:
        for tree, state_index in (
            (self.workflow_tree, 3),
            (self.providers_tree, 2),
            (self.evidence_tree, 3),
        ):
            for item in tree.get_children():
                values = tree.item(item, "values")
                state = (
                    str(values[state_index])
                    if len(values) > state_index
                    else ""
                )
                tree.item(item, tags=(self._state_tag(state),))

    def _show_page(self, name: str) -> None:
        aliases = {
            "Home": "Dashboard",
            "Projects": "Projects & Charters",
            "Workflow": "Workflows",
            "Evidence": "Audit & Receipts",
            "Safety": "Recovery",
        }
        selected = aliases.get(name, name)
        self.pages[selected].tkraise()
        self.page_title.configure(text=selected)
        for page, button in self.nav_buttons.items():
            button.configure(
                style=(
                    "ActiveNav.TButton"
                    if page == selected
                    else "Nav.TButton"
                )
            )

    def _tree(
        self, parent: Any, columns: tuple[str, ...]
    ) -> Any:
        tree = self.ttk.Treeview(
            parent,
            columns=columns,
            show="headings",
            style="Keeper.Treeview",
        )
        for index, column in enumerate(columns):
            tree.heading(column, text=column.replace("_", " ").upper())
            tree.column(
                column,
                width=185 if index == 0 else 125,
                minwidth=90,
                stretch=index == 0,
            )
        tree.tag_configure("good", foreground=THEME.success)
        tree.tag_configure("warning", foreground=THEME.warning)
        tree.tag_configure("danger", foreground=THEME.danger)
        tree.tag_configure("neutral", foreground=THEME.text)
        return tree
    @staticmethod
    def _dashboard_status_style(
        authority_state: str, uncertain: int
    ) -> str:
        normalized = authority_state.upper()
        if uncertain > 0 or normalized in _DANGER_STATES:
            return "StatusDanger.TLabel"
        if normalized in _GOOD_STATES:
            return "StatusSuccess.TLabel"
        return "StatusWarning.TLabel"


    @staticmethod
    def _integer_prefix(value: object) -> int:
        text = str(value).strip()
        try:
            return int(text.split()[0])
        except (IndexError, ValueError):
            return 0

    @staticmethod
    def _state_tag(state: str) -> str:
        normalized = state.upper()
        if normalized in _GOOD_STATES:
            return "good"
        if normalized in _WARNING_STATES:
            return "warning"
        if normalized in _DANGER_STATES:
            return "danger"
        return "neutral"

    def _insert_stateful(
        self, tree: Any, values: tuple[object, ...], state: str
    ) -> None:
        tree.insert(
            "", "end", values=values, tags=(self._state_tag(state),)
        )
