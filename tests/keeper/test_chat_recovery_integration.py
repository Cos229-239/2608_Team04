"""Exercise the real QML editor in an isolated GUI process, not source strings."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("PySide6")


def test_qml_chat_recovery_lifecycle(tmp_path: Path) -> None:
    script = r'''
import sys, threading, time
from pathlib import Path
from PySide6.QtCore import QObject, QMetaObject, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from keeper.app.service import KeeperApplication
from keeper.pass_b.application import PassBApplication
from keeper.ui_qml.controller import KeeperDesktopController

app = QGuiApplication([])
print("Qt initialized", flush=True)
app.setQuitOnLastWindowClosed(False)
service = KeeperApplication(Path(sys.argv[1]))
service.finish_setup()
# This test covers editor lifecycle, not installed-service IPC or executable
# discovery latency. Keep those external diagnostics deterministic.
diagnostics = service.diagnostics()
service.diagnostics = lambda: diagnostics
class Health:
    def require_live_identity(self):
        return {"service_version": "test-health-only", "protocol_version": 7,
                "schema_version": 6, "identity_state": "VERIFIED",
                "provenance_state": "TEST_INJECTION", "observer_available": True}
pass_b = PassBApplication(Path(sys.argv[1]), authority_health_client=Health())
controller = KeeperDesktopController(service, pass_b_application=pass_b, test_fixture=True)
print("Controller initialized", flush=True)
controller.navigate("Keeper")
engine = QQmlApplicationEngine()
engine.rootContext().setContextProperty("keeper", controller)
engine.rootContext().setContextProperty("keeperIcon", QUrl())
engine.load(QUrl.fromLocalFile(str(Path("keeper/ui_qml/qml/Main.qml").resolve())))
assert engine.rootObjects(), "QML must load"
root = engine.rootObjects()[0]
editor = root.findChild(QObject, "keeperChatInput")
assert editor is not None
print("QML loaded", flush=True)

def settle(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.005)
    assert predicate(), "GUI condition timed out"

original = controller.pass_b.casual_conversation
entered, release = threading.Event(), threading.Event()
def delayed(project_id, text):
    entered.set()
    assert release.wait(5)
    return original(project_id, text)
controller.pass_b.casual_conversation = delayed
controller._test_fixture = False
editor.setProperty("text", "hello keeper")
assert QMetaObject.invokeMethod(root, "sendKeeperConversation")
assert entered.wait(2)
assert root.property("pendingConversationText") == "hello keeper"
controller.refresh()
controller._fail("Unrelated action failed")
assert root.property("pendingConversationText") == "hello keeper"
editor.setProperty("text", "my newer draft")
release.set()
settle(lambda: not controller._get_busy())
assert root.property("pendingConversationText") == ""
assert editor.property("text") == "my newer draft"
assert controller._get_conversation_draft() == "my newer draft"
assert controller.flushConversationDraft()
restored = KeeperDesktopController(service, pass_b_application=pass_b, test_fixture=True)
assert restored._get_conversation_draft() == "my newer draft"
print("Async draft preserved", flush=True)

# A secondary composer must not claim ownership of the main editor draft.
controller.pass_b.casual_conversation = original
controller.sendAssistantMessage("hello keeper")
settle(lambda: not controller._get_busy())
assert editor.property("text") == "my newer draft"
assert controller._get_conversation_draft() == "my newer draft"

# Accepted durable recording followed by projection loss must not offer retry.
controller.pass_b.casual_conversation = original
build_state = controller._build_state
def lost_refresh():
    raise RuntimeError("simulated projection loss")
controller._build_state = lost_refresh
editor.setProperty("text", "hello keeper")
assert QMetaObject.invokeMethod(root, "sendKeeperConversation")
settle(lambda: not controller._get_busy())
assert root.property("failedConversationText") == ""
assert root.property("pendingConversationText") == ""
assert "do not resend" in controller._get_status()
controller._build_state = build_state
controller.refresh()
assert [i["body"] for i in controller.state_snapshot()["timeline"]].count("hello keeper") == 3

# The close event must flush the final edit before the debounce timer fires.
editor.setProperty("text", "last keystroke before close")
root.close()
assert not root.isVisible()
assert service.store.get("settings", "conversation_draft")["message"] == "last keystroke before close"

# A disk failure must cancel close and preserve the text for recovery.
root.show()
editor.setProperty("text", "retain on disk failure")
upsert = service.store.upsert
def unavailable(*args, **kwargs):
    raise OSError("disk unavailable")
service.store.upsert = unavailable
# A pre-send save failure must not clear the editor or leave a phantom send.
assert QMetaObject.invokeMethod(root, "sendKeeperConversation")
assert editor.property("text") == "retain on disk failure"
assert root.property("pendingConversationText") == ""
root.close()
assert root.isVisible()
assert editor.property("text") == "retain on disk failure"
service.store.upsert = upsert
root.close()
assert not root.isVisible()
assert service.store.get("settings", "conversation_draft")["message"] == "retain on disk failure"
print("QML recovery lifecycle passed")
'''
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path / "profile")],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
        text=True,
        capture_output=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "QML recovery lifecycle passed" in result.stdout
