"""Distinguish hidden records from genuinely empty read-only projections."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("PySide6")


def test_filtered_empty_states_reset_only_presentation(tmp_path):
    script = r'''
import copy, sys, time
from pathlib import Path
from PySide6.QtCore import QObject, QUrl, QMetaObject
from PySide6.QtGui import QGuiApplication, QFontDatabase, QFont
from PySide6.QtQml import QQmlApplicationEngine
from keeper.app.service import KeeperApplication
from keeper.ui_qml.controller import KeeperDesktopController
app = QGuiApplication([])
font = Path('C:/Windows/Fonts/segoeui.ttf')
if font.exists():
    QFontDatabase.addApplicationFont(str(font))
    app.setFont(QFont('Segoe UI'))
service = KeeperApplication(Path(sys.argv[1]) / 'profile')
service.finish_setup()
controller = KeeperDesktopController(service, test_fixture=True)
controller._state['counts']['uncertain'] = 1
record = {'id':'fixture', 'project_id':'fixture', 'title':'Fixture record',
          'name':'Fixture record', 'state':'ACTIVE', 'status':'UNCERTAIN',
          'health':'UNAVAILABLE', 'recovery_action':'inspect'}
cases = [('Projects','Projects','catalog'), ('Repositories','Repositories','projects'),
         ('Workflows','Workflows','workflows'), ('Tasks','Tasks','tasks'),
         ('Findings','Findings','findings'), ('Authorizations','Authorizations','authorizations'),
         ('Evidence','Evidence','evidence'), ('Evidence','EvidenceReferences','evidenceReferences'),
         ('Evidence','RunEvidence','runs'), ('Reviews','Reviews','reviews'),
         ('Reports','Reports','runs'), ('Providers','Providers','providers'),
         ('Providers','Usage','usage'), ('Recovery','Recovery','recoveries')]
def set_records(key, records):
    if key == 'catalog': controller._state['project']['catalog'] = records
    else: controller._state[key] = records
    controller.stateChanged.emit()
for page, name, key in cases: set_records(key, [record.copy()])
engine = QQmlApplicationEngine()
engine.rootContext().setContextProperty('keeper', controller)
engine.rootContext().setContextProperty('keeperIcon', QUrl.fromLocalFile(str(Path('keeper/assets/keeper-official.png').resolve())))
engine.load(QUrl.fromLocalFile(str(Path('keeper/ui_qml/qml/Main.qml').resolve())))
assert engine.rootObjects()
root = engine.rootObjects()[0]
for page, name, key in cases:
    set_records(key, [record.copy()])
    controller.navigate(page)
    root.setProperty('searchQuery','no-record-can-match-this')
    app.processEvents()
    empty = root.findChild(QObject, 'empty'+name)
    assert empty is not None, name
    assert empty.property('visible'), name
    assert empty.property('displayedTitle') == 'No matching records', name
    before = copy.deepcopy(controller._state)
    button = empty.findChild(QObject, 'resetEmptyFilters')
    assert QMetaObject.invokeMethod(button,'clicked')
    app.processEvents()
    assert root.property('searchQuery') == ''
    assert not empty.property('visible'), name
    assert controller._state == before, name
    set_records(key, [])
    app.processEvents()
    assert empty.property('visible'), name
    assert empty.property('displayedTitle') == empty.property('title'), name
    assert not button.property('visible'), name
    set_records(key, [record.copy()])
# Dropdown labels must track reset, without resetting another page's filter.
controller.navigate('Projects')
root.setProperty('projectStateFilter','FAILED')
root.setProperty('taskStatusFilter','PAUSED')
app.processEvents()
empty = root.findChild(QObject,'emptyProjects')
assert empty.property('visible')
selector = root.findChild(QObject,'projectStateFilterSelector')
assert selector.property('currentText') == 'FAILED'
assert QMetaObject.invokeMethod(empty.findChild(QObject,'resetEmptyFilters'),'clicked')
app.processEvents()
assert selector.property('currentText') == 'ALL'
assert root.property('taskStatusFilter') == 'PAUSED'
controller.navigate('Recovery')
root.setProperty('recoveryStatusFilter','RESUMABLE')
app.processEvents()
empty = root.findChild(QObject,'emptyRecovery')
assert empty.property('visible')
assert empty.property('displayedTitle') == 'No matching records'
assert controller._state['counts']['uncertain'] == 1
for name, width, height in [('wide',1600,960),('minimum',1120,700)]:
    root.resize(width,height)
    end=time.monotonic()+.3
    while time.monotonic()<end:
        app.processEvents()
        time.sleep(.01)
    assert root.grabWindow().save(str(Path(sys.argv[1])/(name+'-filtered.png')))
root.close()
'''
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
        capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
