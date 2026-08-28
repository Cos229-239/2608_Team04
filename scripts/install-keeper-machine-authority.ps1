param([Parameter(Mandatory = $true)][string]$PayloadRoot)

$ErrorActionPreference = "Stop"
$PayloadRoot = [IO.Path]::GetFullPath($PayloadRoot)
$Python = Join-Path $PayloadRoot "runtime\python.exe"
$Source = Join-Path $PayloadRoot "source"
$Descriptor = Join-Path $PayloadRoot "keeper-machine-release.json"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "KeeperAuthority installation requires an administrator"
}
$LogPath = Join-Path $env:TEMP ("Keeper-machine-authority-{0}.log" -f [guid]::NewGuid())
Start-Transcript -LiteralPath $LogPath -NoClobber | Out-Null
try {
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
        # Same-release setup is not an Authority upgrade or identity replacement.
        $InstalledPackage = Join-Path $env:ProgramData 'Keeper\AuthorityService\bin\keeper-authority.pyz'
        $BundledPackage = Join-Path $PayloadRoot 'authority\keeper-authority.pyz'
        if ((Get-FileHash -LiteralPath $InstalledPackage -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath $BundledPackage -Algorithm SHA256).Hash) {
            throw "Existing KeeperAuthority package differs. Use the supported Authority upgrade flow; setup will not overwrite it."
        }
        & $Python -m keeper.authority_service.service_install --source-root $Source repair-permissions
        if ($LASTEXITCODE -ne 0) { throw "KeeperAuthority repair failed" }
    }
    & $Python -m keeper.authority_service.service_install --source-root $Source start
    if ($LASTEXITCODE -ne 0 -and (Get-Service KeeperAuthority).Status -ne 'Running') { throw "KeeperAuthority failed to start" }
    Write-Output 'KeeperAuthority phase completed; existing identity and protected data preserved'
} finally {
    Stop-Transcript | Out-Null
}
