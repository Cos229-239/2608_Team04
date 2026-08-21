param(
    [string]$PythonPath = "python",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$Repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $Repository "dist"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$Stage = Join-Path ([IO.Path]::GetTempPath()) ("keeper-package-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Stage | Out-Null
try {
    Copy-Item -Recurse -LiteralPath (Join-Path $Repository "keeper") -Destination $Stage
    $StagePrefix = $Stage.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    Get-ChildItem -LiteralPath $Stage -Recurse -Directory -Filter "__pycache__" |
        Sort-Object { $_.FullName.Length } -Descending |
        ForEach-Object {
            $Candidate = [IO.Path]::GetFullPath($_.FullName)
            if (-not $Candidate.StartsWith($StagePrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "package cache cleanup escaped the isolated staging directory"
            }
            Remove-Item -Recurse -Force -LiteralPath $Candidate
        }
    Set-Content -LiteralPath (Join-Path $Stage "__main__.py") -Encoding UTF8 -Value @'
from keeper.desktop import main
raise SystemExit(main())
'@
    $Artifact = Join-Path $OutputDirectory "keeper.pyz"
    & $PythonPath -m zipapp $Stage -o $Artifact
    if ($LASTEXITCODE -ne 0) { throw "zipapp build failed" }
    & $PythonPath $Artifact --data-dir (Join-Path $Stage "diagnostic-data") --diagnostics | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "packaged diagnostics failed" }
    Write-Output $Artifact
}
finally {
    if ($Stage.StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -Recurse -Force -LiteralPath $Stage
    }
}
