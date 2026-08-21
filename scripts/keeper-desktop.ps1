param(
    [string]$DataDirectory = ""
)

$ErrorActionPreference = "Stop"
$Repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Python = Join-Path $Repository ".venv\Scripts\pythonw.exe"
if (-not (Test-Path -LiteralPath $Python)) {
    $Python = "pythonw"
}
$Arguments = @("-m", "keeper.ui_qml")
if ($DataDirectory) {
    $Arguments += @("--data-dir", [IO.Path]::GetFullPath($DataDirectory))
}
Start-Process -WindowStyle Hidden -FilePath $Python -ArgumentList $Arguments -WorkingDirectory $Repository
