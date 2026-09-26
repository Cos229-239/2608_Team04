import pytest

from tests.keeper.test_qml_desktop import controller


@pytest.mark.parametrize("operation_name", ["createRepair", "runAction", "exportRunReport", "revokeAuthorization", "setProviderPath"])
def test_accepted_action_refresh_failure_is_success_without_retry(controller, monkeypatch, tmp_path, operation_name):
    calls = []
    events = []
    conversation_events = []
    controller.operationFinished.connect(lambda message, success: events.append((message, success)))
    controller.conversationFinished.connect(lambda *args: conversation_events.append(args))
    previous = controller.state_snapshot()
    controller.stageConversationDraft("keep my unrelated draft")
    if operation_name == "createRepair":
        monkeypatch.setattr(controller.pass_b.orchestration, "create_repair_assignment", lambda value: calls.append(value))
        invoke = lambda: controller.createRepair("review-1")
    elif operation_name == "runAction":
        monkeypatch.setattr(controller.application, "pause_run", lambda value: calls.append(value))
        invoke = lambda: controller.runAction("run-1", "pause")
    elif operation_name == "exportRunReport":
        monkeypatch.setattr(controller.application, "export_run_report", lambda *args: calls.append(args))
        invoke = lambda: controller.exportRunReport("run-1", str(tmp_path / "report.json"))
    elif operation_name == "revokeAuthorization":
        monkeypatch.setattr(controller.application, "revoke_authorization", lambda value: calls.append(value))
        invoke = lambda: controller.revokeAuthorization("auth-1")
    else:
        exe = tmp_path / "provider.exe"
        exe.write_bytes(b"never execute")
        original = controller.application.save_provider_paths
        def save(value):
            calls.append(value)
            original(value)
        monkeypatch.setattr(controller.application, "save_provider_paths", save)
        invoke = lambda: controller.setProviderPath("codex", str(exe))

    def fail():
        raise OSError(r"C:\private\hidden-database")
    monkeypatch.setattr(controller, "_build_state", fail)
    invoke()
    assert len(calls) == 1
    assert len(events) == 1 and events[0][1] is True
    assert "view refresh failed" in controller.status
    assert "Do not repeat" in controller.error
    assert "private" not in controller.error
    assert controller.state_snapshot() is previous
    assert controller.conversationDraft == "keep my unrelated draft"
    assert conversation_events == []

    # Refresh reloads presentation, never repeats the original action.
    monkeypatch.setattr(controller, "_build_state", lambda: {"reloaded": True})
    controller.refresh()
    assert len(calls) == 1
    assert controller.state_snapshot() == {"reloaded": True}
    assert controller.error == ""


def test_service_failure_remains_failed_and_does_not_refresh(controller, monkeypatch):
    events = []
    controller.operationFinished.connect(lambda *args: events.append(args))
    monkeypatch.setattr(controller, "_build_state", lambda: pytest.fail("must not refresh after failure"))
    def fail():
        raise PermissionError("authorization required")
    controller._run("Success must not be claimed", fail)
    assert len(events) == 1 and events[0][1] is False
    assert controller.error == "authorization required"
    assert "Success must not" not in controller.status


def test_refresh_failure_does_not_claim_a_completed_action(controller, monkeypatch):
    def fail():
        raise RuntimeError("unavailable")
    monkeypatch.setattr(controller, "_build_state", fail)
    controller.refresh()
    assert controller.status == "Action could not be completed"
    assert "action completed" not in controller.error.lower()
