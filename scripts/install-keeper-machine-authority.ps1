param([Parameter(Mandatory = $true)][string]$PayloadRoot)

$ErrorActionPreference = "Stop"
$PayloadRoot = [IO.Path]::GetFullPath($PayloadRoot)
$Python = Join-Path $PayloadRoot "runtime\python.exe"
$Source = Join-Path $PayloadRoot "source"
$Descriptor = Join-Path $PayloadRoot "keeper-machine-release.json"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "KeeperAuthority installation requires an administrator"
}
$Release = Get-Content -LiteralPath $Descriptor -Raw | ConvertFrom-Json
foreach ($Entry in $Release.files) {
    $Candidate = Join-Path $PayloadRoot ([string]$Entry.path)
    if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) { throw "Machine payload file is missing: $($Entry.path)" }
    $Actual = (Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash
    if (-not $Actual.Equals([string]$Entry.sha256, [StringComparison]::OrdinalIgnoreCase)) { throw "Machine payload file differs: $($Entry.path)" }
}
$env:PYTHONPATH = $Source
$Service = Get-Service -Name KeeperAuthority -ErrorAction SilentlyContinue
if (-not $Service) {
    & $Python -m keeper.authority_service.service_install --source-root $Source install
    if ($LASTEXITCODE -ne 0) { throw "KeeperAuthority installation failed" }
} else {
    & $Python -m keeper.authority_service.service_install --source-root $Source repair-permissions
    if ($LASTEXITCODE -ne 0) { throw "KeeperAuthority repair failed" }
}
& $Python -m keeper.authority_service.service_install --source-root $Source start
if ($LASTEXITCODE -ne 0 -and (Get-Service KeeperAuthority).Status -ne 'Running') { throw "KeeperAuthority failed to start" }
