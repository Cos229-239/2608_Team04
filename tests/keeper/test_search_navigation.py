"""Exercise real QML search with fixture records; no provider operations."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("PySide6")


def test_search_routes_records_and_reports_misses(tmp_path):
    script = r'''
import sys, time
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
controller._state['project']['catalog'] = [{'id': 'project-search', 'title': 'Provider guide', 'state': 'ACTIVE'}]
for field, title in [('providers','opal-cli'), ('projects','orchid repository'),
                     ('findings','violet issue'), ('reviews','indigo assessment'),
                     ('authorizations','amber permission'), ('evidenceReferences','copper receipt'),
                     ('usage','silver pool')]:
    controller._state[field] = [{'id': title, 'name': title, 'title': title}]
engine = QQmlApplicationEngine()
engine.rootContext().setContextProperty('keeper', controller)
engine.rootContext().setContextProperty('keeperIcon', QUrl.fromLocalFile(str(Path('keeper/assets/keeper-official.png').resolve())))
engine.load(QUrl.fromLocalFile(str(Path('keeper/ui_qml/qml/Main.qml').resolve())))
assert engine.rootObjects()
root = engine.rootObjects()[0]
field = root.findChild(QObject, 'globalSearch')
def search(query):
    field.setProperty('text', query)
    assert QMetaObject.invokeMethod(root, 'openSearchResults')
    app.processEvents()
for query, expected in [('  PROVIDER GUIDE  ', 'Projects'), ('opal-cli', 'Providers'),
                        ('orchid repository', 'Repositories'), ('violet issue', 'Findings'),
                        ('indigo assessment', 'Reviews'), ('amber permission', 'Authorizations'),
                        ('copper receipt', 'Evidence'), ('silver pool', 'Providers')]:
    search(query)
    assert controller.currentPage == expected, (query, controller.currentPage, expected)
search('providers')
assert controller.currentPage == 'Providers'
assert root.property('searchQuery') == ''
assert field.property('text') == ''
search('<b>nothing matches this</b>')
assert controller.currentPage == 'Providers'
assert 'No matching records' in root.property('searchFeedback')
feedback = root.findChild(QObject, 'searchFeedback')
assert feedback is not None and feedback.property('visible')
for name, width, height in [('wide',1600,960), ('minimum',1120,700)]:
    root.resize(width,height)
    end = time.monotonic() + .3
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(.01)
    assert root.grabWindow().save(str(Path(sys.argv[1]) / (name + '-search.png')))
assert QMetaObject.invokeMethod(root, 'clearSearch')
app.processEvents()
assert root.property('searchQuery') == ''
assert root.property('searchFeedback') == ''
search('   ')
assert root.property('searchFeedback') == ''
root.close()
'''
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
        capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
