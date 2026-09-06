param(
    [string]$PythonPath = "python",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"

function Assert-SmokeResult {
    param(
        [string]$Name,
        [string[]]$Output,
        [int]$ExitCode,
        [string]$ExpectedPattern,
        [string]$FailureMessage
    )

    $Text = $Output -join "`n"
    Write-Host "Checking $Name..."

    if ($ExitCode -ne 0 -or $Text -notmatch $ExpectedPattern) {
        $Details = @(
            "Smoke check failed: $Name",
            "Expected: $ExpectedPattern",
            "Exit code: $ExitCode",
            "Output:"
            $Text
        )
        throw ($Details -join "`n")
    }
}

function Wait-For-SmokeStep {
    param(
        [int]$Seconds = 1
    )

    Start-Sleep -Seconds $Seconds
}

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) ("keeper-smoke-" + [Guid]::NewGuid().ToString("N"))
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$Artifact = & (Join-Path $PSScriptRoot "build-keeper.ps1") -PythonPath $PythonPath -OutputDirectory $OutputDirectory
$Data = Join-Path $OutputDirectory "data"

$Diagnostics = & $PythonPath $Artifact --data-dir $Data --diagnostics
Assert-SmokeResult -Name "diagnostics" -Output $Diagnostics -ExitCode $LASTEXITCODE -ExpectedPattern '"local_only": true' -FailureMessage "packaged diagnostics smoke test failed"
Wait-For-SmokeStep

$Pilot = & $PythonPath $Artifact --data-dir $Data --mock-demo
Assert-SmokeResult -Name "mock-demo" -Output $Pilot -ExitCode $LASTEXITCODE -ExpectedPattern '"status": "COMPLETED"' -FailureMessage "packaged mock workflow smoke test failed"
Wait-For-SmokeStep

$UiSmoke = & $PythonPath $Artifact --data-dir $Data --ui-smoke
$UiExitCode = $LASTEXITCODE
$UiSmokeText = $UiSmoke -join "`n"
if ($UiExitCode -eq 78 -and $UiSmokeText -match '"ui_smoke": "unavailable"') {
    Write-Warning "Rendered Tk smoke unavailable in this Python runtime."
}
else {
    Assert-SmokeResult -Name "ui-smoke" -Output $UiSmoke -ExitCode $UiExitCode -ExpectedPattern '"ui_smoke": "passed"' -FailureMessage "packaged rendered Tk smoke test failed"
}

Write-Output "Keeper package smoke test passed: $Artifact"
