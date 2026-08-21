from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class KeeperTheme:
    background: str = "#07080A"
    sidebar: str = "#0A0B0D"
    surface: str = "#101216"
    surface_raised: str = "#171A1F"
    surface_alt: str = "#1D2127"
    border: str = "#4B3A19"
    border_bright: str = "#8A651D"
    gold: str = "#E0AD36"
    deep_gold: str = "#B98219"
    gold_hover: str = "#F1C45D"
    text: str = "#F7F7F5"
    muted: str = "#A4A7AC"
    subtle: str = "#74787F"
    success: str = "#45C86B"
    danger: str = "#E25A5A"
    warning: str = "#E0A636"
    info: str = "#69A9E6"


THEME = KeeperTheme()


def configure_ttk(root: Any, ttk: Any, theme: KeeperTheme = THEME) -> None:
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    root.configure(background=theme.background)
    style.configure(
        ".",
        background=theme.background,
        foreground=theme.text,
        font=("Segoe UI", 10),
    )
    style.configure("App.TFrame", background=theme.background)
    style.configure("Sidebar.TFrame", background=theme.sidebar)
    style.configure("Banner.TFrame", background=theme.sidebar)
    style.configure("Surface.TFrame", background=theme.surface)
    style.configure(
        "Card.TFrame",
        background=theme.surface_raised,
        bordercolor=theme.border,
        relief="solid",
        borderwidth=1,
    )
    style.configure(
        "AccentCard.TFrame",
        background=theme.surface_raised,
        bordercolor=theme.border_bright,
        relief="solid",
        borderwidth=1,
    )
    style.configure("Rail.TFrame", background=theme.sidebar)
    style.configure(
        "Title.TLabel",
        background=theme.background,
        foreground=theme.text,
        font=("Segoe UI Semibold", 20),
    )
    style.configure(
        "Brand.TLabel",
        background=theme.sidebar,
        foreground=theme.gold,
        font=("Georgia", 22, "bold"),
    )
    style.configure(
        "BrandSub.TLabel",
        background=theme.sidebar,
        foreground=theme.text,
        font=("Segoe UI Semibold", 8),
    )
    style.configure(
        "BannerValue.TLabel",
        background=theme.sidebar,
        foreground=theme.text,
        font=("Segoe UI Semibold", 9),
    )
    style.configure(
        "Eyebrow.TLabel",
        background=theme.surface_raised,
        foreground=theme.gold,
        font=("Segoe UI Semibold", 8),
    )
    style.configure(
        "Heading.TLabel",
        background=theme.surface_raised,
        foreground=theme.text,
        font=("Segoe UI Semibold", 12),
    )
    style.configure(
        "Metric.TLabel",
        background=theme.surface_raised,
        foreground=theme.text,
        font=("Segoe UI Semibold", 22),
    )
    style.configure(
        "StatusSuccess.TLabel",
        background=theme.surface_raised,
        foreground=theme.success,
        font=("Segoe UI Semibold", 9),
    )
    style.configure(
        "StatusWarning.TLabel",
        background=theme.surface_raised,
        foreground=theme.warning,
        font=("Segoe UI Semibold", 9),
    )
    style.configure(
        "StatusDanger.TLabel",
        background=theme.surface_raised,
        foreground=theme.danger,
        font=("Segoe UI Semibold", 9),
    )
    style.configure(
        "Body.TLabel",
        background=theme.surface_raised,
        foreground=theme.text,
    )
    style.configure(
        "Muted.TLabel",
        background=theme.surface_raised,
        foreground=theme.muted,
    )
    style.configure(
        "Gold.TLabel",
        background=theme.surface_raised,
        foreground=theme.gold,
        font=("Segoe UI Semibold", 10),
    )
    style.configure(
        "RailHeading.TLabel",
        background=theme.sidebar,
        foreground=theme.gold,
        font=("Segoe UI Semibold", 10),
    )
    style.configure(
        "RailBody.TLabel",
        background=theme.sidebar,
        foreground=theme.text,
    )
    style.configure(
        "Nav.TButton",
        background=theme.sidebar,
        foreground=theme.muted,
        borderwidth=0,
        anchor="w",
        padding=(18, 11),
    )
    style.map(
        "Nav.TButton",
        background=[("active", theme.surface_raised)],
        foreground=[("active", theme.text)],
    )
    style.configure(
        "ActiveNav.TButton",
        background=theme.deep_gold,
        foreground="#08090B",
        borderwidth=0,
        anchor="w",
        padding=(18, 11),
        font=("Segoe UI Semibold", 10),
    )
    style.map(
        "ActiveNav.TButton",
        background=[("active", theme.gold)],
        foreground=[("active", "#08090B")],
    )
    style.configure(
        "Accent.TButton",
        background=theme.gold,
        foreground="#111111",
        borderwidth=0,
        padding=(16, 9),
        font=("Segoe UI Semibold", 10),
    )
    style.map("Accent.TButton", background=[("active", theme.gold_hover)])
    style.configure(
        "Success.TButton",
        background="#176A31",
        foreground=theme.text,
        bordercolor=theme.success,
        padding=(14, 8),
        font=("Segoe UI Semibold", 9),
    )
    style.map(
        "Success.TButton",
        background=[("active", "#218A43")],
    )
    style.configure(
        "Danger.TButton",
        background="#671F24",
        foreground=theme.text,
        bordercolor=theme.danger,
        padding=(14, 8),
        font=("Segoe UI Semibold", 9),
    )
    style.map(
        "Danger.TButton",
        background=[("active", "#882A31")],
    )
    style.configure(
        "Quiet.TButton",
        background=theme.surface_raised,
        foreground=theme.text,
        bordercolor=theme.border,
        padding=(12, 8),
    )
    style.configure(
        "Keeper.TEntry",
        fieldbackground=theme.surface_raised,
        foreground=theme.text,
        insertcolor=theme.gold,
        bordercolor=theme.border,
        padding=9,
    )
    style.configure(
        "Keeper.TCombobox",
        fieldbackground=theme.surface_raised,
        foreground=theme.text,
        background=theme.surface_alt,
        arrowcolor=theme.gold,
        bordercolor=theme.border,
        padding=7,
    )
    style.configure(
        "Keeper.TNotebook",
        background=theme.surface,
        borderwidth=0,
    )
    style.configure(
        "Keeper.TNotebook.Tab",
        background=theme.surface_raised,
        foreground=theme.muted,
        borderwidth=0,
        padding=(14, 8),
    )
    style.map(
        "Keeper.TNotebook.Tab",
        background=[("selected", theme.deep_gold)],
        foreground=[("selected", "#08090B")],
    )
    style.configure(
        "Keeper.Treeview",
        background=theme.surface,
        fieldbackground=theme.surface,
        foreground=theme.text,
        rowheight=28,
        borderwidth=0,
        font=("Segoe UI", 9),
    )
    style.configure(
        "Keeper.Treeview.Heading",
        background=theme.surface_raised,
        foreground=theme.gold,
        relief="flat",
        font=("Segoe UI Semibold", 9),
    )
    style.map(
        "Keeper.Treeview",
        background=[("selected", theme.border)],
        foreground=[("selected", theme.text)],
    )
