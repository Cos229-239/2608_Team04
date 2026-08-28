param([Parameter(Mandatory = $true)][string]$PayloadRoot)

$ErrorActionPreference = "Stop"
$PayloadRoot = [IO.Path]::GetFullPath($PayloadRoot)
$Python = Join-Path $PayloadRoot "runtime\python.exe"
$Source = Join-Path $PayloadRoot "source"
$HostRoot = Join-Path $PayloadRoot "provider-host"
$HostExe = Join-Path $HostRoot "KeeperProviderHost.exe"
$HostManifestPath = Join-Path $HostRoot "keeper-provider-host-package-manifest.json"
$HostManifest = Get-Content -LiteralPath $HostManifestPath -Raw | ConvertFrom-Json
# Match the protected enrollment client's compatibility path; do not migrate
# installed identity/state as part of an installer path fix.
$InstallRoot = Join-Path $env:LOCALAPPDATA "Programs\DarkSage\KeeperProviderHost"
$StartupRoot = [Environment]::GetFolderPath('Startup')
$env:PYTHONPATH = $Source
$HostCommand = if (Test-Path -LiteralPath (Join-Path $InstallRoot 'current.json')) { 'update' } else { 'install' }
$Arguments = @(
    '-m', 'keeper', '--root', $Source, 'provider-host', $HostCommand,
    '--install-root', $InstallRoot,
    '--startup-root', $StartupRoot,
    '--artifact', $HostExe,
    '--version', [string]$HostManifest.version,
    '--package-sha256', (Get-FileHash -LiteralPath $HostManifestPath -Algorithm SHA256).Hash
)
& $Python @Arguments
if ($LASTEXITCODE -ne 0) { throw "Keeper Provider Host installation failed" }
& $Python -m keeper --root $Source provider-host enroll --generation 1
if ($LASTEXITCODE -ne 0) { throw "Keeper Provider Host enrollment was not completed" }
& (Join-Path $PayloadRoot "desktop\install-keeper-desktop.ps1")
if ($LASTEXITCODE -ne 0) { throw "Keeper Desktop installation failed" }
