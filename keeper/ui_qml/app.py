from __future__ import annotations

import json
import os
import sys
from contextlib import ExitStack
from importlib.resources import as_file, files
from pathlib import Path
from typing import cast

from PySide6.QtCore import QCoreApplication, QTimer, QUrl
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuick import QQuickWindow

from keeper.app.service import KeeperApplication
from keeper.ui_qml.controller import KeeperDesktopController, NAVIGATION


def run_desktop(
    application: KeeperApplication,
    *,
    smoke: bool = False,
    screenshot_directory: Path | None = None,
    test_fixture: bool = False,
) -> int:
    if smoke and "QT_QPA_PLATFORM" not in os.environ:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
    QCoreApplication.setOrganizationName("Keeper")
    QCoreApplication.setApplicationName("Keeper")
    existing = QGuiApplication.instance()
    qt_app = (
        cast(QGuiApplication, existing) if existing else QGuiApplication(sys.argv[:1])
    )
    resources = ExitStack()
    icon_path = resources.enter_context(
        as_file(files("keeper").joinpath("assets", "keeper-official.png"))
    )
    qt_app.setWindowIcon(QIcon(str(icon_path)))
    engine = QQmlApplicationEngine()
    controller = KeeperDesktopController(application, test_fixture=test_fixture)
    engine.rootContext().setContextProperty("keeper", controller)
    engine.rootContext().setContextProperty(
        "keeperIcon", QUrl.fromLocalFile(str(icon_path))
    )
    qml_path = resources.enter_context(
        as_file(files("keeper.ui_qml").joinpath("qml", "Main.qml"))
    )
    engine.load(QUrl.fromLocalFile(str(qml_path)))
    if not engine.rootObjects():
        resources.close()
        return 70
    root = engine.rootObjects()[0]
    if smoke:
        target = (
            screenshot_directory or application.data_directory / "ui-smoke"
        ).resolve()
        target.mkdir(parents=True, exist_ok=True)
        captured: list[str] = []
        captured_frames: list[dict[str, object]] = []
        failure: list[str] = []
        finished = False
        variants = (
            ("wide", 1600, 960),
            ("minimum", 1120, 700),
        )
        frames = tuple(
            (variant, width, height, page)
            for variant, width, height in variants
            for page in NAVIGATION
        )

        def finish() -> None:
            nonlocal finished
            if finished:
                return
            finished = True
            evidence = {
                "ui_smoke": "failed" if failure else "passed",
                "rendered_pages": len(captured),
                "pages": captured,
                "rendered_frames": captured_frames,
                "supported_sizes": [
                    {"name": name, "width": width, "height": height}
                    for name, width, height in variants
                ],
                "environment": controller.state_snapshot().get("environment"),
                "output": str(target),
                "failure": failure[0] if failure else None,
            }
            (target / "ui-smoke-evidence.json").write_text(
                json.dumps(evidence, indent=2), encoding="utf-8"
            )
            print(json.dumps(evidence, sort_keys=True))
            qt_app.exit(1 if failure else 0)

        def capture(index: int = 0) -> None:
            if index >= len(frames):
                finish()
                return
            try:
                variant, width, height, page = frames[index]
                if not isinstance(root, QQuickWindow):
                    raise TypeError("QML root is not a QQuickWindow")
                root.resize(width, height)
                controller.navigate(page)
            except Exception as error:
                failure.append(str(error))
                finish()
                return

            def grab_settled_frame() -> None:
                try:
                    image = root.grabWindow()
                    safe_name = (
                        variant
                        + "-"
                        + page.lower().replace(" ", "-")
                        + ".png"
                    )
                    if image.isNull() or not image.save(str(target / safe_name)):
                        raise OSError(f"could not save rendered page: {page}")
                    captured.append(f"{variant}:{page}")
                    captured_frames.append(
                        {
                            "page": page,
                            "variant": variant,
                            "width": width,
                            "height": height,
                            "file": safe_name,
                        }
                    )
                except Exception as error:
                    failure.append(str(error))
                    finish()
                    return
                QTimer.singleShot(90, lambda: capture(index + 1))

            QTimer.singleShot(180, grab_settled_frame)

        # A callback exception must never leave a package smoke hanging forever.
        def timeout() -> None:
            if finished:
                return
            failure.append("UI smoke timed out")
            finish()

        QTimer.singleShot(30_000, timeout)
        QTimer.singleShot(350, capture)
    try:
        return int(qt_app.exec())
    finally:
        resources.close()


__all__ = ["run_desktop"]
