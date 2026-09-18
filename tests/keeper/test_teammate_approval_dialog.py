"""Check teammate approval guidance fits without invoking authentication."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("PySide6")


def test_teammate_approval_dialog_fits_supported_windows(tmp_path: Path) -> None:
    script = r'''
import sys, time
from pathlib import Path
from PySide6.QtCore import QObject, QUrl
from PySide6.QtGui import QGuiApplication, QFontDatabase, QFont
from PySide6.QtQml import QQmlApplicationEngine
from keeper.app.service import KeeperApplication
from keeper.ui_qml.controller import KeeperDesktopController
app = QGuiApplication([])
font_path = Path("C:/Windows/Fonts/segoeui.ttf")
if font_path.is_file():
    QFontDatabase.addApplicationFont(str(font_path))
    app.setFont(QFont("Segoe UI"))
service = KeeperApplication(Path(sys.argv[1]) / "profile")
service.finish_setup()
controller = KeeperDesktopController(service, test_fixture=True)
controller._state["project"].update({"title": "Teammate integration", "charterRevision": 1,
    "approvalCharter": {"revision": 1, "approved_providers": ["codex"],
                        "constraints": ["No push", "No deployment"]}})
controller.navigate("Projects")
engine = QQmlApplicationEngine()
engine.rootContext().setContextProperty("keeper", controller)
engine.rootContext().setContextProperty("keeperIcon", QUrl.fromLocalFile(str(Path("keeper/assets/keeper-official.png").resolve())))
engine.load(QUrl.fromLocalFile(str(Path("keeper/ui_qml/qml/Main.qml").resolve())))
assert engine.rootObjects()
root = engine.rootObjects()[0]
summary = root.findChild(QObject, "founderApprovalDialog")
assert summary is not None
summary.open()
for name, width, height in [("wide", 1600, 960), ("minimum", 1120, 700)]:
    root.resize(width, height)
    end = time.monotonic() + .5
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(.01)
    assert summary.property("width") <= root.width()
    assert summary.property("height") <= root.height(), (summary.property("height"), root.height())
    assert root.grabWindow().save(str(Path(sys.argv[1]) / (name + "-approval.png")))
summary.close()
root.close()
'''
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
        text=True, capture_output=True, timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
