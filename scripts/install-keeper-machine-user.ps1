param([Parameter(Mandatory = $true)][string]$PayloadRoot)

$ErrorActionPreference = "Stop"
$PayloadRoot = [IO.Path]::GetFullPath($PayloadRoot)
$Python = Join-Path $PayloadRoot "runtime\python.exe"
$Source = Join-Path $PayloadRoot "source"
# Match the protected enrollment client's compatibility path; do not migrate
# installed identity/state as part of an installer path fix.
$InstallRoot = Join-Path $env:LOCALAPPDATA "Programs\DarkSage\KeeperProviderHost"
$StartupRoot = [Environment]::GetFolderPath('Startup')
$env:PYTHONPATH = $Source
$LogPath = Join-Path $env:TEMP ("Keeper-machine-user-{0}.log" -f [guid]::NewGuid())
Start-Transcript -LiteralPath $LogPath -NoClobber | Out-Null
try {
    & $Python (Join-Path $PayloadRoot 'keeper-machine-user-setup.py') --payload $PayloadRoot --install-root $InstallRoot --startup-root $StartupRoot
    if ($LASTEXITCODE -ne 0) { throw "Keeper Provider Host setup failed; see $LogPath" }
    & (Join-Path $PayloadRoot "desktop\install-keeper-desktop.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Keeper Desktop installation failed; see $LogPath" }
    Write-Output 'Keeper user components verified successfully'
} finally {
    Stop-Transcript | Out-Null
}
