# Keeper Desktop — Local Installation

Keeper Desktop is a local, per-user PySide6/Qt Quick application. It does not
install or reconfigure KeeperAuthority, add a machine-wide PATH entry, write the
registry, open firewall rules, deploy software, or enable paid providers.

## Build

Create an isolated Python 3.14 virtual environment, install the exact packages
from `requirements-keeper-ui.txt`, then run:

```powershell
powershell -File scripts/build-keeper-desktop.ps1 `
  -PythonPath C:\path\to\venv\Scripts\python.exe `
  -OutputDirectory C:\tmp\keeper-desktop-package
```

The build uses Qt for Python 6.10.1 and Nuitka 4.1.3 in standalone mode. The
result includes `Keeper.exe`, the official Keeper icon, QML, Qt runtime files,
and a hashed `keeper-package-manifest.json`. The output root also contains the
single local installer `install-keeper-desktop.ps1`, its exact lifecycle helper,
and `keeper-installer-release.json`, which binds both scripts, the package
manifest, and the exact source commit/tree. It contains no Keeper database,
credentials, `.ai-workflow` content, pilot evidence, or user data.

## Single local installer

From the verified build output, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  C:\tmp\keeper-desktop-package\install-keeper-desktop.ps1
```

The installer selects Install, same-manifest Repair, or Upgrade after validating
its release descriptor, its own bytes, the lifecycle helper, and every packaged
file. It is per-user and does not request UAC. Pass the independently recorded
manifest hash with `-ExpectedManifestSha256` when installing a transferred build.
This local bootstrapper is intentionally unsigned until a separately approved
code-signing certificate and public release process exist.

## Install, repair, upgrade, rollback, uninstall

All lifecycle operations default to `%LOCALAPPDATA%` and require no elevation:

```powershell
$package = 'C:\tmp\keeper-desktop-package\Keeper.dist'
$manifestSha = (Get-FileHash -Algorithm SHA256 `
  -LiteralPath "$package\keeper-package-manifest.json").Hash

powershell -File scripts/keeper-local-lifecycle.ps1 -Action Install `
  -PackageDirectory $package -ExpectedManifestSha256 $manifestSha

powershell -File scripts/keeper-local-lifecycle.ps1 -Action Repair `
  -PackageDirectory $package -ExpectedManifestSha256 $manifestSha

powershell -File scripts/keeper-local-lifecycle.ps1 -Action Upgrade `
  -PackageDirectory $package -ExpectedManifestSha256 $manifestSha

$status = powershell -File scripts/keeper-local-lifecycle.ps1 -Action Status |
  ConvertFrom-Json
powershell -File scripts/keeper-local-lifecycle.ps1 -Action Rollback `
  -ExpectedManifestSha256 $status.rollback_manifest_sha256

powershell -File scripts/keeper-local-lifecycle.ps1 -Action Uninstall
```

Application files live under `%LOCALAPPDATA%\Programs\Keeper`. Durable user
state remains under `%LOCALAPPDATA%\Keeper`; uninstall deliberately preserves
that directory. Desktop and Start Menu shortcuts point directly to the current verified
`Keeper.exe`. Every mutation requires the separately checked, approved manifest
SHA-256; exact manifest coverage, sizes, and file hashes are revalidated.
Rollback also requires the retained generation's hash reported by `Status`. A
single previous application generation is retained for rollback.

## First launch

The seven-step wizard records local safety boundaries, validates an evidence
directory using an exclusive random probe, optionally registers a protected
repository, records provider routing preferences, shows qualification status,
and performs a read-only KeeperAuthority health projection. Provider
registration and qualification remain separate Authority operations.

The application never automates Founder credential entry. Charter approval
opens the Keeper authorization dialog and waits for the configured Founder account.
