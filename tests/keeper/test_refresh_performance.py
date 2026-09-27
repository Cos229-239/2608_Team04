import pytest
import os
import subprocess
import sys
from pathlib import Path

from tests.keeper.test_qml_desktop import controller


def test_measurement_times_exactly_one_refresh_without_assistant(controller, monkeypatch):
    controller.clearPerformanceSamples()
    clock = iter([1.0, 1.125])
    monkeypatch.setattr("keeper.ui_qml.controller.time.perf_counter", lambda: next(clock))
    calls = []
    monkeypatch.setattr(controller, "_build_state", lambda: calls.append("snapshot") or {"marker": "local"})
    monkeypatch.setattr(controller, "sendAssistantMessage", lambda *a: pytest.fail("must not call assistant"))
    controller.refresh()
    assert calls == ["snapshot"]
    assert controller.state_snapshot() == {"marker": "local"}
    assert controller.performance == {
        "sampleCount": 1, "completedCount": 1, "lastMilliseconds": 125.0,
        "lastSucceeded": True, "averageMilliseconds": 125.0, "maximumMilliseconds": 125.0,
    }


def test_failed_refresh_is_not_a_successful_timing(controller, monkeypatch):
    controller.clearPerformanceSamples()
    previous = controller.state_snapshot()
    def fail():
        raise RuntimeError("snapshot unavailable")
    monkeypatch.setattr(controller, "_build_state", fail)
    controller.refresh()
    assert controller.performance["sampleCount"] == 1
    assert controller.performance["lastSucceeded"] is False
    assert controller.performance["completedCount"] == 0
    assert controller.performance["averageMilliseconds"] is None
    assert controller.state_snapshot() is previous
    assert "unavailable" in controller.error


def test_timing_memory_is_bounded_and_clear_has_no_durable_effect(controller, monkeypatch):
    controller.clearPerformanceSamples()
    before = controller.application.store.list("settings")
    monkeypatch.setattr(controller, "_build_state", lambda: {})
    for _ in range(40):
        controller.refresh()
    assert len(controller._refresh_samples) == 32
    assert controller.performance["sampleCount"] == 32
    assert controller.application.store.list("settings") == before
    controller._error = "important warning"
    controller.clearPerformanceSamples()
    assert controller.performance["sampleCount"] == 0
    assert controller.performance["lastMilliseconds"] is None
    assert controller.error == "important warning"


def test_real_qml_timing_controls_and_readiness_label(tmp_path):
    script = r'''
import sys, time
from pathlib import Path
from PySide6.QtCore import QObject, QUrl, QMetaObject
from PySide6.QtGui import QGuiApplication, QFontDatabase, QFont
from PySide6.QtQml import QQmlApplicationEngine
from keeper.app.service import KeeperApplication
import keeper.app.service as service_module
from tests.keeper.authority_testkit import TestAuthorityClient
from keeper.pass_b.application import PassBApplication
from keeper.ui_qml.controller import KeeperDesktopController
from tests.keeper.test_qml_desktop import _HealthClient
service_module.authority_client_factory = TestAuthorityClient
app = QGuiApplication([])
font = Path('C:/Windows/Fonts/segoeui.ttf')
if font.exists():
    QFontDatabase.addApplicationFont(str(font))
    app.setFont(QFont('Segoe UI'))
directory = Path(sys.argv[1]) / 'profile'
service = KeeperApplication(directory)
service.finish_setup()
blocked = PassBApplication(directory, authority_health_client=_HealthClient())
blocked.startup_provider_block = 'Fixture: provider execution blocked; no authority.'
controller = KeeperDesktopController(service, pass_b_application=blocked, test_fixture=True)
engine = QQmlApplicationEngine()
engine.rootContext().setContextProperty('keeper', controller)
engine.rootContext().setContextProperty('keeperIcon', QUrl.fromLocalFile(str(Path('keeper/assets/keeper-official.png').resolve())))
engine.load(QUrl.fromLocalFile(str(Path('keeper/ui_qml/qml/Main.qml').resolve())))
assert engine.rootObjects()
root = engine.rootObjects()[0]
controller.navigate('Settings')
app.processEvents()
assert root.findChild(QObject,'authorityTrustStatus').property('label') == 'AUTHORITY UNAVAILABLE'
clear = root.findChild(QObject,'clearRefreshTimingButton')
assert QMetaObject.invokeMethod(clear,'clicked')
assert controller.performance['sampleCount'] == 0
measure = root.findChild(QObject,'measureRefreshButton')
assert QMetaObject.invokeMethod(measure,'clicked')
assert controller.performance['sampleCount'] == 1
assert 'completed' in root.findChild(QObject,'refreshPerformanceSummary').property('text')
for name,width,height in [('wide',1600,960),('minimum',1120,700)]:
    root.resize(width,height)
    end=time.monotonic()+.3
    while time.monotonic()<end:
        app.processEvents()
        time.sleep(.01)
    panel=root.findChild(QObject,'refreshPerformancePanel')
    assert panel.property('width') > 500
    assert root.grabWindow().save(str(Path(sys.argv[1])/(name+'-performance.png')))
root.close()
'''
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "QT_QPA_PLATFORM": os.environ.get("KEEPER_QA_PLATFORM", "offscreen")},
        capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
