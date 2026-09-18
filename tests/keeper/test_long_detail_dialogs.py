"""Long untrusted text must remain literal, reachable, and within the window."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("PySide6")


@pytest.mark.parametrize("kind", ["approval"])
def test_long_dialogs_are_bounded_and_scrollable(tmp_path, kind):
    script = r'''
import sys, time
from pathlib import Path
from PySide6.QtCore import QObject, QUrl, QMetaObject, QPointF
from PySide6.QtGui import QGuiApplication, QFontDatabase, QFont
from PySide6.QtQuick import QQuickItem
from PySide6.QtQml import QQmlApplicationEngine, QQmlExpression
from keeper.app.service import KeeperApplication
from keeper.ui_qml.controller import KeeperDesktopController
app=QGuiApplication([])
font=Path('C:/Windows/Fonts/segoeui.ttf')
if font.exists():
    QFontDatabase.addApplicationFont(str(font))
    app.setFont(QFont('Segoe UI'))
service=KeeperApplication(Path(sys.argv[1])/'profile')
service.finish_setup()
controller=KeeperDesktopController(service,test_fixture=True)
long_text='<b>Literal constraints</b> ' + 'No publishing or spending. ' * 180 + 'END OF DETAILS'
controller._state['project'].update({'title':'Long approval test',
    'approvalCharter':{'revision':1,'constraints':[long_text],'approved_providers':['codex']}})
engine=QQmlApplicationEngine()
engine.rootContext().setContextProperty('keeper',controller)
engine.rootContext().setContextProperty('keeperIcon',QUrl.fromLocalFile(str(Path('keeper/assets/keeper-official.png').resolve())))
engine.load(QUrl.fromLocalFile(str(Path('keeper/ui_qml/qml/Main.qml').resolve())))
assert engine.rootObjects()
root=engine.rootObjects()[0]
kind=sys.argv[2]
root.setProperty('selectedRecord',{'title':'Long record test','description':long_text})
dialog=root.findChild(QObject,'founderApprovalDialog' if kind=='approval' else 'recordDetailsDialog')
scroll=root.findChild(QObject,'approvalDetailsScroll' if kind=='approval' else 'recordDetailsScroll')
text=root.findChild(QObject,'approvalConstraintsText' if kind=='approval' else 'recordDetailsText')
assert dialog is not None and scroll is not None and text is not None
def settle():
    end=time.monotonic()+.35
    while time.monotonic()<end:
        app.processEvents()
        time.sleep(.01)
for name,width,height in [('wide',1600,960),('minimum',1120,700)]:
    root.resize(width,height)
    dialog.open()
    settle()
    assert dialog.property('height') <= height-48
    assert '<b>Literal constraints</b>' in text.property('text')
    assert 'END OF DETAILS' in text.property('text')
    format_check = QQmlExpression(engine.rootContext(), text, 'textFormat === 0').evaluate()
    assert format_check[0] if isinstance(format_check, tuple) else format_check
    flick=scroll.property('contentItem')
    assert flick.property('contentHeight') > flick.property('height')
    if kind=='approval':
        button=root.findChild(QQuickItem,'confirmFounderApproval')
        top=button.mapToScene(QPointF(0,0)).y()
        assert 0 <= top and top+button.height() <= height
    else:
        assert text.property('readOnly') and text.property('selectByMouse')
        assert text.property('width') <= scroll.property('width')
        assert QMetaObject.invokeMethod(root.findChild(QObject,'selectAllRecordDetails'),'clicked')
        assert text.property('selectedText') == text.property('text')
        assert root.findChild(QObject,'copyRecordDetails').property('enabled')
        text.setProperty('cursorPosition',0)
        QMetaObject.invokeMethod(text,'deselect')
    flick.setProperty('contentY',max(0,flick.property('contentHeight')-flick.property('height')))
    settle()
    assert flick.property('contentY') > 0
    if kind=='approval': assert abs(button.mapToScene(QPointF(0,0)).y()-top)<1
    assert root.grabWindow().save(str(Path(sys.argv[1])/(name+'-'+kind+'.png')))
    dialog.close()
    settle()
    dialog.open()
    settle()
    assert abs(flick.property('contentY')) < 1
    dialog.close()
    settle()
root.close()
'''
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path), kind],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
        capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
