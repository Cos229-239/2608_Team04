[app]
title = Keeper
project_dir = @PROJECT_DIR@
input_file = keeper_desktop.py
exec_directory = @EXEC_DIRECTORY@
project_file =
icon = @ICON_PATH@

[python]
python_path = @PYTHON_PATH@
packages = Nuitka==4.1.3
android_packages =

[qt]
qml_files = keeper\ui_qml\qml\Main.qml
excluded_qml_plugins = QtCharts,QtQuick3D,QtSensors,QtTest,QtWebEngine
modules = Core,Gui,Qml,Quick,QuickControls2
plugins = generic,iconengines,imageformats,platforminputcontexts,platforms,styles

[android]
wheel_pyside =
wheel_shiboken =
plugins =

[nuitka]
macos.permissions =
mode = standalone
extra_args = --quiet --reproducible=yes --assume-yes-for-downloads --noinclude-qt-translations --windows-console-mode=disable --include-qt-plugins=qml --include-data-file=keeper/assets/keeper-official.png=keeper/assets/keeper-official.png --include-data-dir=keeper/ui_qml/qml=keeper/ui_qml/qml --nofollow-import-to=keeper.ui.desktop

[buildozer]
mode = debug
recipe_dir =
jars_dir =
ndk_path =
sdk_path =
local_libs =
arch =
