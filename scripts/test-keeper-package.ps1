param(
    [string]$PythonPath = "python",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$Repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) ("keeper-smoke-" + [Guid]::NewGuid().ToString("N"))
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$Artifact = & (Join-Path $PSScriptRoot "build-keeper.ps1") -PythonPath $PythonPath -OutputDirectory $OutputDirectory
$Data = Join-Path $OutputDirectory "data"
$Diagnostics = & $PythonPath $Artifact --data-dir $Data --diagnostics
$DiagnosticsText = $Diagnostics -join "`n"
if ($LASTEXITCODE -ne 0 -or $DiagnosticsText -notmatch '"local_only": true') {
    throw "packaged diagnostics smoke test failed"
}
$Pilot = & $PythonPath $Artifact --data-dir $Data --mock-demo
$PilotText = $Pilot -join "`n"
if ($LASTEXITCODE -ne 0 -or $PilotText -notmatch '"status": "COMPLETED"') {
    throw "packaged mock workflow smoke test failed"
}
$UiSmoke = & $PythonPath $Artifact --data-dir $Data --ui-smoke
$UiExitCode = $LASTEXITCODE
$UiSmokeText = $UiSmoke -join "`n"
if ($UiExitCode -eq 78 -and $UiSmokeText -match '"ui_smoke": "unavailable"') {
    Write-Warning "Rendered Tk smoke unavailable in this Python runtime."
}
elseif ($UiExitCode -ne 0 -or $UiSmokeText -notmatch '"ui_smoke": "passed"') {
    throw "packaged rendered Tk smoke test failed"
}
Write-Output "Keeper package smoke test passed: $Artifact"
