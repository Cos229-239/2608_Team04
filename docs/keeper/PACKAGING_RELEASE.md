# Packaging and Release

The product desktop is built with the isolated PySide6/Nuitka toolchain:

```powershell
powershell -File scripts/build-keeper-desktop.ps1 `
  -PythonPath C:\path\to\venv\Scripts\python.exe `
  -OutputDirectory C:\tmp\keeper-desktop-package
```

The result contains:

- `Keeper.dist`, with `Keeper.exe`, the Qt runtime, the official Keeper icon, QML, and `keeper-package-manifest.json`;
- `install-keeper-desktop.ps1`, the single per-user install, repair, and upgrade entry point;
- `keeper-local-lifecycle.ps1`, the fail-closed lifecycle implementation; and
- `keeper-installer-release.json`, which binds the exact package manifest, installer, lifecycle script, source commit, and source tree.

Every runtime file is hashed. The installer validates all release-descriptor bindings before selecting install, same-manifest repair, or upgrade. Its lifecycle journal recovers an interrupted package swap before another action can proceed. Build-time Dependency Walker downloads are handled by Nuitka inside the disposable build cache selected by the script. No tool is installed machine-wide.

Verify the artifact through packaged diagnostics, deterministic mock workflow, Windows-platform rendered UI smoke, manifest and release-descriptor validation, interrupted-swap recovery tests, protected-content/secret/private-path scans, and the lifecycle tests. Generated build outputs are not committed. The current local installer is not Authenticode-signed; distribution outside the local development boundary requires a separately approved signing and public-release process.

The legacy `scripts/build-keeper.ps1` zipapp remains available for headless compatibility and recovery diagnostics; it is not the primary desktop product.

Per-user install, same-version repair, upgrade, one-generation rollback, status, and data-preserving uninstall are documented in [`DESKTOP_INSTALLATION.md`](DESKTOP_INSTALLATION.md). Publishing a tag or public release remains a separate Founder action.
