"""Render recorded project scope at supported sizes without granting authority."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("PySide6")


def test_long_scope_is_plain_text_and_scrollable(tmp_path: Path) -> None:
    script = r'''
import sys, time
from pathlib import Path
from PySide6.QtCore import QObject, QUrl
from PySide6.QtGui import QGuiApplication, QFontDatabase, QFont
from PySide6.QtQml import QQmlApplicationEngine
from keeper.app.service import KeeperApplication
from keeper.ui_qml.controller import KeeperDesktopController, _charter_summary
app = QGuiApplication([])
font_path = Path("C:/Windows/Fonts/segoeui.ttf")
if font_path.is_file():
    QFontDatabase.addApplicationFont(str(font_path))
    app.setFont(QFont("Segoe UI"))
service = KeeperApplication(Path(sys.argv[1]) / "profile")
service.finish_setup()
controller = KeeperDesktopController(service, test_fixture=True)
controller._state["project"].update({"title": "Audit scope display", "charterRevision": 1,
    "charterSummary": _charter_summary({"problem_or_opportunity": "Do not push or deploy. <b>Keep this literal</b>",
        "desired_outcome": "A readable checklist. " * 60,
        "deliverables": ["Checklist"], "success_criteria": ["Readable at both sizes"],
        "constraints": ["No push", "No deployment"]})})
controller.navigate("Projects")
engine = QQmlApplicationEngine()
engine.rootContext().setContextProperty("keeper", controller)
engine.rootContext().setContextProperty("keeperIcon", QUrl.fromLocalFile(str(Path("keeper/assets/keeper-official.png").resolve())))
engine.load(QUrl.fromLocalFile(str(Path("keeper/ui_qml/qml/Main.qml").resolve())))
assert engine.rootObjects()
root = engine.rootObjects()[0]
summary = root.findChild(QObject, "projectCharterSummary")
assert summary is not None
assert "Do not push or deploy" in summary.property("text")
assert "<b>Keep this literal</b>" in summary.property("text")
for name, width, height in [("wide", 1600, 960), ("minimum", 1120, 700)]:
    root.resize(width, height)
    end = time.monotonic() + .5
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(.01)
    assert summary.width() <= root.width()
    assert root.grabWindow().save(str(Path(sys.argv[1]) / (name + "-scope.png")))
root.close()
'''
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
        text=True, capture_output=True, timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
