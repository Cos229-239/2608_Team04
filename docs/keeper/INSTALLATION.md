# Installation

## Requirements

- Windows 10 or later
- Python 3.12 or later with Tkinter
- Git

Keeper's lightweight verified release form is a standalone zipapp. From a clean checkout:

```powershell
powershell -NoProfile -File scripts/build-keeper.ps1 -PythonPath python -OutputDirectory C:\tmp\keeper-release
Get-FileHash -Algorithm SHA256 C:\tmp\keeper-release\keeper.pyz
python C:\tmp\keeper-release\keeper.pyz --diagnostics
python C:\tmp\keeper-release\keeper.pyz --mock-demo
python C:\tmp\keeper-release\keeper.pyz
```

The artifact can be copied atomically to a user-owned directory outside source
repositories and protected Keeper trees. Keep the prior artifact as the rollback
copy. Repair means replacing the current artifact with a byte-for-byte verified copy
having the recorded SHA-256. Rollback means restoring the previously recorded
artifact. Uninstall means removing only the launcher/artifact; these are deliberate
manual file operations, not machine-wide installation.

Application data defaults to `%LOCALAPPDATA%\Keeper`. Uninstall by removing the
launcher/artifact; data is intentionally retained until the user explicitly removes
it. Back up or export the database before manual data removal. Keeper does not modify
global `PATH`, the registry, scheduled tasks, firewall rules, or KeeperAuthority as
part of application packaging.

For the full desktop application and its single per-user local installer, use
[`DESKTOP_INSTALLATION.md`](DESKTOP_INSTALLATION.md). The local installer is
manifest-bound and supports install, repair, upgrade, rollback through the
lifecycle helper, and data-preserving uninstall. It does not install or alter the
KeeperAuthority service or Provider Host.
