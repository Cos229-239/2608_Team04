from __future__ import annotations

import json
from typing import Any, Callable


class PassBDesktop:
    COLORS = {
        "black": "#090909",
        "gold": "#D4AF37",
        "gray": "#242424",
        "white": "#F5F5F5",
        "muted": "#A9A9A9",
        "danger": "#C86B6B",
    }

    def __init__(self, application: Any) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.ttk = ttk
        self.application = application
        self.project_id: str | None = None
        self.root = tk.Tk()
        self.root.title("Keeper ? Conversation and Control Room")
        self.root.geometry("1320x820")
        self.root.minsize(980, 640)
        self._style()
        self.status = tk.StringVar(value="Ready")
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=14, pady=14)
        self._build_conversation()
        self._build_control_room()
        self._build_project()
        self._build_providers()
        self._build_safety()
        ttk.Label(
            self.root,
            textvariable=self.status,
            anchor="w",
            style="Muted.TLabel",
        ).pack(fill="x", padx=14, pady=(0, 10))
        self.refresh()

    def run(self) -> None:
        self.root.mainloop()

    def refresh(self) -> None:
        snapshot = self.application.control_room.snapshot(
            self.project_id
        ).to_dict()
        self._set(self.conversation_history, snapshot["conversation"])
        self._set(self.control_room_text, snapshot["control_room"])
        self._set(self.project_text, snapshot["project"])
        self._set(self.providers_text, snapshot["providers"])
        self._set(self.safety_text, snapshot["safety"])
        self.presentation_label.configure(
            text=self._presentation_summary(snapshot["presentation"])
        )
        self.status.set("Durable state refreshed")

    def _style(self) -> None:
        style = self.ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure(
            ".",
            background=self.COLORS["black"],
            foreground=self.COLORS["white"],
        )
        style.configure("TFrame", background=self.COLORS["black"])
        style.configure(
            "TLabel",
            background=self.COLORS["black"],
            foreground=self.COLORS["white"],
        )
        style.configure(
            "Muted.TLabel",
            background=self.COLORS["black"],
            foreground=self.COLORS["muted"],
        )
        style.configure(
            "Title.TLabel",
            background=self.COLORS["black"],
            foreground=self.COLORS["gold"],
            font=("Segoe UI Semibold", 15),
        )
        style.configure(
            "TButton",
            background=self.COLORS["gold"],
            foreground=self.COLORS["black"],
        )
        style.configure("TNotebook", background=self.COLORS["black"])
        style.configure(
            "TNotebook.Tab",
            background=self.COLORS["gray"],
            foreground=self.COLORS["white"],
            padding=(14, 8),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.COLORS["gold"])],
            foreground=[("selected", self.COLORS["black"])],
        )
        self.root.configure(background=self.COLORS["black"])

    def _tab(self, title: str) -> Any:
        frame = self.ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)
        return frame

    def _text(self, parent: Any) -> Any:
        widget = self.tk.Text(
            parent,
            bg=self.COLORS["gray"],
            fg=self.COLORS["white"],
            insertbackground=self.COLORS["gold"],
            wrap="word",
            borderwidth=0,
            padx=12,
            pady=12,
        )
        return widget

    def _build_conversation(self) -> None:
        frame = self._tab("Conversation")
        self.ttk.Label(
            frame, text="Conversation with Keeper", style="Title.TLabel"
        ).pack(anchor="w", padx=10, pady=(10, 2))
        self.presentation_label = self.ttk.Label(
            frame, text="", style="Muted.TLabel"
        )
        self.presentation_label.pack(anchor="w", padx=10, pady=(0, 8))
        self.conversation_history = self._text(frame)
        self.conversation_history.pack(
            fill="both", expand=True, padx=10, pady=(0, 8)
        )
        composer = self.ttk.Frame(frame)
        composer.pack(fill="x", padx=10, pady=(0, 10))
        self.conversation_input = self.tk.Text(
            composer,
            height=4,
            bg=self.COLORS["gray"],
            fg=self.COLORS["white"],
            insertbackground=self.COLORS["gold"],
            wrap="word",
            borderwidth=0,
        )
        self.conversation_input.pack(side="left", fill="x", expand=True)
        self.ttk.Button(
            composer, text="Send", command=self._send
        ).pack(side="left", padx=(8, 0))

    def _build_control_room(self) -> None:
        frame = self._tab("Control Room")
        self.ttk.Label(
            frame, text="Operational overview", style="Title.TLabel"
        ).pack(anchor="w", padx=10, pady=10)
        self.control_room_text = self._text(frame)
        self.control_room_text.pack(fill="both", expand=True, padx=10, pady=8)
        self.ttk.Button(
            frame, text="Refresh", command=self.refresh
        ).pack(anchor="w", padx=10, pady=(0, 10))

    def _build_project(self) -> None:
        frame = self._tab("Project")
        self.ttk.Label(
            frame, text="Charter, workflow, evidence, and review", style="Title.TLabel"
        ).pack(anchor="w", padx=10, pady=10)
        self.project_text = self._text(frame)
        self.project_text.pack(fill="both", expand=True, padx=10, pady=8)

    def _build_providers(self) -> None:
        frame = self._tab("Providers")
        self.ttk.Label(
            frame, text="Providers, accounts, sessions, and usage", style="Title.TLabel"
        ).pack(anchor="w", padx=10, pady=10)
        self.providers_text = self._text(frame)
        self.providers_text.pack(fill="both", expand=True, padx=10, pady=8)

    def _build_safety(self) -> None:
        frame = self._tab("Safety")
        self.ttk.Label(
            frame, text="Authority, uncertainty, and reservations", style="Title.TLabel"
        ).pack(anchor="w", padx=10, pady=10)
        self.safety_text = self._text(frame)
        self.safety_text.pack(fill="both", expand=True, padx=10, pady=8)

    def _send(self) -> None:
        text = self.conversation_input.get("1.0", "end").strip()
        if not text:
            return
        try:
            outcome = self.application.begin_conversation(text)
        except (OSError, PermissionError, RuntimeError, ValueError) as error:
            self.status.set(f"Conversation blocked: {error}")
            return
        self.project_id = outcome.project.project_id
        self.conversation_input.delete("1.0", "end")
        self.status.set(
            "Charter proposal created; explicit Founder approval is required"
        )
        self.refresh()

    @staticmethod
    def _presentation_summary(value: dict[str, Any]) -> str:
        return (
            f"Sage presentation: {value.get('form', 'default')} ? "
            f"{value.get('mode', 'CONVERSATION')} ? "
            f"{value.get('expression', 'neutral')}. "
            "Presentation state has no authority effect."
        )

    @staticmethod
    def _set(widget: Any, value: object) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert(
            "1.0",
            json.dumps(value, indent=2, sort_keys=True, default=str),
        )
        widget.configure(state="disabled")


def run_desktop(factory: Callable[[], Any]) -> None:
    PassBDesktop(factory()).run()
