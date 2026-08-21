from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sqlite3

import pytest

from keeper.executive.service import KeeperExecutive
from keeper.executive.models import ProjectCharter, ProjectRecord
from keeper.pass_b.application import PassBApplication, _activate_and_reload_charter
from keeper.pass_b.conversation import DynamicWorkflowDesigner
from keeper.pass_b.models import (
    PassBRecord,
    WorkflowRecord,
    WorkItemRecord,
)
from keeper.pass_b.orchestration import authority_envelope_digest
from keeper.pass_b.pilot import PilotConversationExecutive


def _approved(
    root: Path,
) -> tuple[PassBApplication, ProjectCharter]:
    executive = PilotConversationExecutive(root / "keeper.db")
    application = PassBApplication(root, executive=executive)
    outcome = application.begin_conversation(
        "Build a software application in an isolated workspace. "
        "No spending, deployment, push, or live trading."
    )
    outcome = application.conversation.revise(
        outcome.project.project_id,
        {
            "success_criteria": ("independent evidence is accepted",),
            "approved_providers": ("local-builder", "local-reviewer"),
            "approved_tools": ("filesystem", "tests"),
            "workspaces": (str(root / "workspace"),),
        },
    )
    challenge = application.conversation.request_approval(
        outcome.project.project_id
    )
    _, charter = executive.approve_and_activate(challenge)
    application.conversation.record_approval(charter)
    return application, charter


def test_selected_project_is_durable_and_snapshot_is_project_scoped(
    tmp_path: Path,
) -> None:
    executive = PilotConversationExecutive(tmp_path / "keeper.db")
    application = PassBApplication(tmp_path, executive=executive)
    first = application.begin_conversation("Build project Alpha.")
    second = application.begin_conversation("Build project Beta.")

    application.select_project(first.project.project_id)
    restarted = PassBApplication(
        tmp_path,
        executive=PilotConversationExecutive(tmp_path / "keeper.db"),
    )
    snapshot = restarted.product_snapshot()

    assert restarted.selected_project_id() == first.project.project_id
    assert snapshot["project"]["project_id"] == first.project.project_id
    assert {
        item["project_id"] for item in snapshot["projects"]
    } == {first.project.project_id, second.project.project_id}
    assert all(
        message["project_id"] in {None, first.project.project_id}
        for message in snapshot["conversation"]["messages"]
    )


def test_atomic_workflow_plan_is_current_charter_bound_and_idempotent(
    tmp_path: Path,
) -> None:
    application, charter = _approved(tmp_path)
    blueprint = DynamicWorkflowDesigner().design(charter)
    digest = authority_envelope_digest(
        charter.authority_envelope.to_dict()
    )

    first, first_items = application.orchestration.create_workflow_plan(
        blueprint, authority_envelope_digest=digest
    )
    second, second_items = application.orchestration.create_workflow_plan(
        blueprint, authority_envelope_digest=digest
    )

    assert second == first
    assert second_items == first_items
    assert len(first_items) == len(blueprint.steps)
    by_title = {item.title: item for item in first_items}
    for step in blueprint.steps:
        assert by_title[step.title].dependencies == tuple(
            by_title[dependency].work_item_id
            for dependency in step.dependencies
        )


def test_atomic_workflow_plan_rolls_back_after_interrupted_insert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application, charter = _approved(tmp_path)
    blueprint = DynamicWorkflowDesigner().design(charter)
    digest = authority_envelope_digest(
        charter.authority_envelope.to_dict()
    )
    original = application.repository._insert
    work_items_seen = 0

    def interrupted(
        connection: sqlite3.Connection, record: PassBRecord
    ) -> None:
        nonlocal work_items_seen
        if isinstance(record, WorkItemRecord):
            work_items_seen += 1
            if work_items_seen == 2:
                raise OSError("simulated interruption")
        original(connection, record)

    monkeypatch.setattr(application.repository, "_insert", interrupted)
    with pytest.raises(OSError, match="simulated interruption"):
        application.orchestration.create_workflow_plan(
            blueprint, authority_envelope_digest=digest
        )

    assert application.repository.list(
        WorkflowRecord, project_id=charter.project_id
    ) == []
    assert application.repository.list(
        WorkItemRecord, project_id=charter.project_id
    ) == []


def test_approval_rejects_displayed_charter_identity_mismatch_before_auth(
    tmp_path: Path,
) -> None:
    executive = KeeperExecutive(tmp_path / "executive.db")
    application = PassBApplication(tmp_path, executive=executive)
    outcome = application.begin_conversation(
        "Build a local software project with no deployment or spending."
    )
    project_id = outcome.project.project_id
    context = application.conversation.current_context(project_id)

    with pytest.raises(
        PermissionError,
        match="displayed charter is not the current approval target",
    ):
        application.approve_and_plan_current_charter(
            project_id,
            expected_charter_id="different-charter",
            expected_charter_revision=context.charter_revision,
        )

    assert application.conversation.current_context(project_id).state == "PROPOSED"
    assert executive.status(project_id).pending_approvals == ()


def test_activation_returns_the_durable_active_charter(tmp_path: Path) -> None:
    application, active_charter = _approved(tmp_path)
    status = application.project_status(active_charter.project_id)
    project_data = status["project_summary"]
    assert isinstance(project_data, dict)
    project = ProjectRecord.from_dict(project_data)
    approved = replace(active_charter, status="APPROVED")
    activated_with: list[ProjectCharter] = []

    class Activator:
        @staticmethod
        def activate_charter(charter: ProjectCharter) -> ProjectRecord:
            activated_with.append(charter)
            return project

    durable_project, durable_charter = _activate_and_reload_charter(
        Activator(), application.project_status, approved
    )

    assert activated_with == [approved]
    assert durable_project == project
    assert durable_charter == active_charter
    assert durable_charter.status == "ACTIVE"
