"""Real QML paging regression with isolated, inert task projections."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("PySide6")


def test_task_pagination_reconciles_scope_filters_and_record_shrink(tmp_path):
    script = r'''
import sys, time
from pathlib import Path
from PySide6.QtCore import QObject, QUrl
from PySide6.QtGui import QGuiApplication, QFontDatabase, QFont
from PySide6.QtQml import QQmlApplicationEngine, QQmlExpression
import keeper.app.service as service_module
from keeper.app.service import KeeperApplication
from keeper.pass_b.application import PassBApplication
from keeper.ui_qml.controller import KeeperDesktopController
from tests.keeper.authority_testkit import TestAuthorityClient
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
controller = KeeperDesktopController(service, pass_b_application=PassBApplication(directory, authority_health_client=_HealthClient()), test_fixture=True)
rows = [{'id':str(i),'title':'Task %02d'%i,'status':'PAUSED'} for i in range(15)]
controller._state['tasks'] = rows
controller._state['project']['id'] = 'project-one'
engine = QQmlApplicationEngine()
engine.rootContext().setContextProperty('keeper',controller)
engine.rootContext().setContextProperty('keeperIcon',QUrl.fromLocalFile(str(Path('keeper/assets/keeper-official.png').resolve())))
engine.load(QUrl.fromLocalFile(str(Path('keeper/ui_qml/qml/Main.qml').resolve())))
assert engine.rootObjects()
root = engine.rootObjects()[0]
controller.navigate('Tasks')
app.processEvents()
root.setProperty('taskPage',2)
controller._state['tasks'] = rows[:2]
controller.stateChanged.emit()
app.processEvents()
assert root.property('taskPage') == 0, 'shrinking results must discard stale page, not merely hide it'
controller._state['tasks'] = rows
controller.stateChanged.emit()
app.processEvents()
assert root.property('taskPage') == 0, 'growing results must not resurrect stale page'
root.setProperty('taskPage',2)
controller._state['project']['id'] = 'project-two'
controller.stateChanged.emit()
app.processEvents()
assert root.property('taskPage') == 0, 'new project must begin on first page'
for key,value in [('taskSortKey','status'),('taskSortAscending',False),('taskStatusFilter','PAUSED'),('searchQuery','task')]:
    root.setProperty('taskPage',2)
    root.setProperty(key,value)
    app.processEvents()
    assert root.property('taskPage') == 0, key
assert root.findChild(QObject,'taskSortSelector').property('currentText') == 'Status'
root.setProperty('taskPage',-1)
expr=QQmlExpression(engine.rootContext(),root,'taskSafePage()')
assert expr.evaluate()[0] == 0
root.setProperty('taskPage',1)
assert controller._state['tasks'] == rows
assert service.tasks() == [], 'paging must not write fixture records'
for name,width,height in [('wide',1600,960),('minimum',1120,700)]:
    root.resize(width,height)
    end=time.monotonic()+.3
    while time.monotonic()<end:
        app.processEvents()
        time.sleep(.01)
    footer=root.findChild(QObject,'taskPaginationControls')
    bounds=QQmlExpression(engine.rootContext(),footer,'mapToItem(null, 0, height).y').evaluate()
    assert bounds[0] < height - 34, bounds
    assert root.grabWindow().save(str(Path(sys.argv[1])/(name+'-tasks.png')))
root.close()
'''
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "QT_QPA_PLATFORM": os.environ.get("KEEPER_QA_PLATFORM", "offscreen")},
        capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
