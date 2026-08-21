# Troubleshooting

- **Desktop does not open:** run `python -m keeper.ui_qml --diagnostics` from the development environment, or `Keeper.exe --diagnostics` from a standalone package. Confirm PySide6 6.10.1 is present only for source launches.
- **Packaged UI lacks text in an offscreen capture:** rerun the smoke with `QT_QPA_PLATFORM=windows`. Qt's offscreen Windows backend may not load the system font database; release evidence uses the normal Windows platform.
- **Provider unavailable:** configure its absolute executable path and rerun diagnostics. Detection is not qualification and cannot authorize production execution.
- **KeeperAuthority unavailable:** preserve the read-only failure report. The desktop never starts, installs, restarts, or reconfigures the service.
- **Git unsafe-directory error:** approve only the exact repository path; never add a global wildcard.
- **Interrupted or uncertain run:** resume only through the supported recovery control. Non-idempotent `UNCERTAIN` work is not retried automatically.
- **Integrity error:** preserve the data directory and use supported backup/restore procedures; do not overwrite evidence.
- **Package build failure:** verify the exact UI requirements, run `pyside6-qmllint`, and inspect the Nuitka report. Do not copy DLLs manually.
- **Lifecycle validation failure:** do not bypass the manifest. Rebuild the package and retry. Uninstall preserves `%LOCALAPPDATA%\Keeper` by design.
