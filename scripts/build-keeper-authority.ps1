param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) {
    throw "Output directory already exists: $output"
}
[System.IO.Directory]::CreateDirectory($output) | Out-Null
$package = Join-Path $output "keeper-authority.pyz"
$manifest = Join-Path $output "keeper-authority-package-manifest.json"

& $Python -m keeper.authority_service.service_package build `
    --source-root $root `
    --output $package `
    --manifest-output $manifest
if ($LASTEXITCODE -ne 0) { throw "KeeperAuthority package build failed" }

$expected = (Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).package_sha256
& $Python -m keeper.authority_service.service_package verify `
    --package $package `
    --expected-sha256 $expected
if ($LASTEXITCODE -ne 0) { throw "KeeperAuthority package verification failed" }
