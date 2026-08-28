# Instructor inspection installer

Keeper's instructor build is a single Windows setup executable. It shows a
normal setup wizard, verifies the embedded release descriptor and package
manifest, and then uses Keeper's existing per-user lifecycle installer. It does
not require administrator access and does not overwrite the user's durable
Keeper data.

Build the standalone desktop package first, then compile the setup wrapper:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-keeper-desktop.ps1 `
  -PythonPath C:\path\to\build-environment\Scripts\python.exe
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-keeper-instructor-installer.ps1
```

The output is written to `dist/instructor-installer` with a matching SHA-256
checksum file. Until a trusted Authenticode certificate is supplied, the file
name contains `Unsigned` and Windows may show an unknown-publisher warning. The
unsigned label must not be removed merely to make the warning less visible.

The setup wrapper is intentionally not registered as a separate uninstaller.
Keeper's lifecycle script owns install, repair, upgrade, rollback, shortcuts,
and uninstall so that all entry points use the same verified package manifest.
