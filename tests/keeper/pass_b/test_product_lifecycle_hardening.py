from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
from pathlib import Path
from typing import Any

import pytest

from keeper.pass_b.application import PassBApplication
from keeper.pass_b.conversation import DynamicWorkflowDesigner
from keeper.pass_b.models import WorkflowRecord, WorkItemRecord
from keeper.pass_b.orchestration import authority_envelope_digest
from keeper.pass_b.pilot import PilotConversationExecutive
from tests.keeper.pass_b.test_product_lifecycle_integration import _approved


def test_atomic_plan_rejects_forward_or_cyclic_dependency(
    tmp_path: Path,
) -> None:
    application, charter = _approved(tmp_path)
    blueprint = DynamicWorkflowDesigner().design(charter)
    first = replace(
        blueprint.steps[0],
        dependencies=(blueprint.steps[-1].title,),
    )
    cyclic = replace(
        blueprint,
        steps=(first, *blueprint.steps[1:]),
    )

    with pytest.raises(
        PermissionError, match="missing, cyclic, or cross-plan"
    ):
        application.orchestration.create_workflow_plan(
            cyclic,
            authority_envelope_digest=authority_envelope_digest(
                charter.authority_envelope.to_dict()
            ),
        )

    assert application.repository.list(
        WorkflowRecord, project_id=charter.project_id
    ) == []


def test_unavailable_authoritative_project_remains_visible_for_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application = PassBApplication(
        tmp_path,
        executive=PilotConversationExecutive(tmp_path / "keeper.db"),
    )
    outcome = application.begin_conversation("Build a software application.")

    def unavailable(_project_id: str) -> dict[str, Any]:
        raise RuntimeError("simulated unavailable durable state")

    monkeypatch.setattr(
        application, "project_status", unavailable
    )
    snapshot = application.product_snapshot(outcome.project.project_id)

    assert snapshot["projects"][0]["state"] == "RECOVERY_REQUIRED"
    assert (
        snapshot["executive"]["project_summary"]["state"]
        == "RECOVERY_REQUIRED"
    )
    assert snapshot["executive"]["controls"] == ()


def test_concurrent_plan_creation_has_one_durable_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application, charter = _approved(tmp_path)
    blueprint = DynamicWorkflowDesigner().design(charter)
    digest = authority_envelope_digest(
        charter.authority_envelope.to_dict()
    )
    original = application.repository.insert_workflow_plan
    ready = Barrier(2)

    def synchronized_insert(
        workflow: WorkflowRecord,
        work_items: tuple[WorkItemRecord, ...],
    ) -> bool:
        ready.wait(timeout=5)
        return original(workflow, work_items)

    monkeypatch.setattr(
        application.repository,
        "insert_workflow_plan",
        synchronized_insert,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                application.orchestration.create_workflow_plan,
                blueprint,
                authority_envelope_digest=digest,
            )
            for _ in range(2)
        ]
        results = [future.result(timeout=10) for future in futures]

    workflows = application.repository.list(
        WorkflowRecord, project_id=charter.project_id
    )
    work_items = application.repository.list(
        WorkItemRecord, project_id=charter.project_id
    )
    assert len(workflows) == 1
    assert len(work_items) == len(blueprint.steps)
    assert {result[0].workflow_id for result in results} == {
        workflows[0].workflow_id
    }
    assert all(
        tuple(item.work_item_id for item in result[1])
        == tuple(item.work_item_id for item in results[0][1])
        for result in results
    )
