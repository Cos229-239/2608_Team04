from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import keeper.desktop as desktop_module
import pytest
from keeper.ui.desktop import KeeperProductDesktop as LegacyDesktop
from keeper.ui.executive_desktop import (
    COMMAND_CENTER_NAVIGATION,
    KeeperExecutiveDesktop,
)
from keeper.ui.theme import THEME


class _Page:
    def __init__(self) -> None:
        self.raised = False

    def tkraise(self) -> None:
        self.raised = True


class _Configured:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}

    def configure(self, **values: object) -> None:
        self.values.update(values)


class _Tree:
    def __init__(self) -> None:
        self.inserted: list[dict[str, object]] = []

    def insert(self, parent: str, position: str, **values: object) -> None:
        self.inserted.append(
            {"parent": parent, "position": position, **values}
        )


def test_product_entrypoint_uses_executive_desktop_projection() -> None:
    assert getattr(desktop_module, "KeeperProductDesktop") is KeeperExecutiveDesktop
    assert issubclass(KeeperExecutiveDesktop, LegacyDesktop)


def test_executive_navigation_matches_command_center_information_architecture() -> None:
    assert COMMAND_CENTER_NAVIGATION == (
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


def test_executive_navigation_aliases_legacy_pages_and_marks_active_page() -> None:
    desktop: Any = object.__new__(KeeperExecutiveDesktop)
    desktop.pages = {
        name: _Page() for name in COMMAND_CENTER_NAVIGATION
    }
    desktop.nav_buttons = {
        name: _Configured() for name in COMMAND_CENTER_NAVIGATION
    }
    desktop.page_title = _Configured()

    desktop._show_page("Evidence")

    assert desktop.pages["Audit & Receipts"].raised
    assert desktop.page_title.values["text"] == "Audit & Receipts"
    assert (
        desktop.nav_buttons["Audit & Receipts"].values["style"]
        == "ActiveNav.TButton"
    )
    assert desktop.nav_buttons["Dashboard"].values["style"] == "Nav.TButton"


def test_executive_state_colors_preserve_uncertainty_and_failure_visibility() -> None:
    assert KeeperExecutiveDesktop._state_tag("RUNNING") == "good"
    assert KeeperExecutiveDesktop._state_tag("WAITING_FOR_USAGE_RESET") == "warning"
    assert KeeperExecutiveDesktop._state_tag("UNCERTAIN") == "danger"
    assert KeeperExecutiveDesktop._state_tag("unrecognized") == "neutral"


def test_stateful_insertion_uses_semantic_tag_without_mutating_values() -> None:
    desktop: Any = object.__new__(KeeperExecutiveDesktop)
    tree = _Tree()
    values = ("Review", "reviewer", "provider", "UNCERTAIN", "-")

    desktop._insert_stateful(tree, values, "UNCERTAIN")

    assert tree.inserted == [
        {
            "parent": "",
            "position": "end",
            "values": values,
            "tags": ("danger",),
        }
    ]


def test_metric_parser_fails_closed_for_non_numeric_projection() -> None:
    assert KeeperExecutiveDesktop._integer_prefix("3 pending") == 3
    assert KeeperExecutiveDesktop._integer_prefix("unavailable") == 0
    assert KeeperExecutiveDesktop._integer_prefix(None) == 0


def test_executive_theme_is_black_charcoal_gold_and_high_contrast() -> None:
    assert THEME.background == "#07080A"
    assert THEME.sidebar == "#0A0B0D"
    assert THEME.surface == "#101216"
    assert THEME.gold == "#E0AD36"
    assert THEME.text == "#F7F7F5"
    assert THEME.success != THEME.warning != THEME.danger


def test_executive_ui_exposes_no_direct_authority_or_execution_bypass() -> None:
    prohibited = {
        "approve",
        "accept_review",
        "execute_provider",
        "force_push",
        "deploy",
        "enable_paid_fallback",
        "change_service",
        "live_trade",
    }
    assert prohibited.isdisjoint(dir(KeeperExecutiveDesktop))


def test_dashboard_status_style_exposes_authority_and_uncertainty_failures() -> None:
    assert (
        KeeperExecutiveDesktop._dashboard_status_style("READY", 0)
        == "StatusSuccess.TLabel"
    )
    assert (
        KeeperExecutiveDesktop._dashboard_status_style("UNAVAILABLE", 0)
        == "StatusDanger.TLabel"
    )
    assert (
        KeeperExecutiveDesktop._dashboard_status_style("READY", 1)
        == "StatusDanger.TLabel"
    )


def test_developer_diagnostics_are_whitelisted_and_redacted() -> None:
    view = cast(Any, SimpleNamespace(
        project_id="project-1",
        project_status="ACTIVE",
        charter_revision=2,
        composition="PRODUCTION",
        workflow_rows=(),
        provider_cards=(),
        usage_cards=(),
        evidence_cards=(),
        evidence_reference_cards=(),
        review_cards=(),
        sage={"mode": "HIDDEN"},
        developer_details={
            "workspace": r"C:\protected\source",
            "owner_token": "owner-secret",
        },
    ))
    diagnostics = {
        "authority": {
            "state": "READY",
            "service_version": "1.0",
            "protocol_version": "6",
            "schema_version": "5",
            "identity_state": "VERIFIED",
            "failure_reason": "secret detail",
            "source_path": r"C:\protected\authority",
        },
        "reservations": [{"owner_token": "owner-secret"}],
    }

    redacted = KeeperExecutiveDesktop._redacted_diagnostics(view, diagnostics)
    rendered = json.dumps(redacted, sort_keys=True)

    assert redacted["authority"]["state"] == "READY"
    assert redacted["sage"]["authority_effect"] == "NONE"
    assert "C:\\protected" not in rendered
    assert "owner-secret" not in rendered
    assert "secret detail" not in rendered
    assert "reservations" not in redacted


class _ApprovalRecorder:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def approve_and_plan_current_charter(
        self, project_id: str, **values: object
    ) -> dict[str, object]:
        call = {"project_id": project_id, **values}
        self.calls.append(call)
        return call


def test_founder_approval_routes_exact_displayed_charter_identity() -> None:
    desktop: Any = object.__new__(KeeperExecutiveDesktop)
    desktop.pass_b = _ApprovalRecorder()

    result = desktop._approve_displayed_charter(
        "project-1", {"charter_id": "charter-2", "revision": 4}
    )

    assert result == {
        "project_id": "project-1",
        "expected_charter_id": "charter-2",
        "expected_charter_revision": 4,
    }
    assert desktop.pass_b.calls == [result]
