param(
    [string]$PackageDirectory = "",
    [string]$ReleaseDescriptor = "",
    [string]$ExpectedManifestSha256 = "",
    [string]$InstallRoot = "",
    [string]$DataDirectory = "",
    [switch]$SkipShortcuts,
    [switch]$Launch
)

$ErrorActionPreference = "Stop"
$InstallerPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$InstallerRoot = Split-Path -Parent $InstallerPath
$Lifecycle = Join-Path $InstallerRoot "keeper-local-lifecycle.ps1"

function Get-Sha256Hex([string]$PathValue) {
    $Stream = [IO.File]::Open(
        [IO.Path]::GetFullPath($PathValue),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $Hasher = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($Hasher.ComputeHash($Stream))).Replace("-", "")
        }
        finally {
            $Hasher.Dispose()
        }
    }
    finally {
        $Stream.Dispose()
    }
}

if (-not $ReleaseDescriptor) {
    $ReleaseDescriptor = Join-Path $InstallerRoot "keeper-installer-release.json"
}
$ReleaseDescriptor = [IO.Path]::GetFullPath($ReleaseDescriptor)
if (-not (Test-Path -LiteralPath $Lifecycle -PathType Leaf)) {
    throw "Keeper lifecycle script is unavailable beside the installer"
}
if (-not (Test-Path -LiteralPath $ReleaseDescriptor -PathType Leaf)) {
    throw "Keeper installer release descriptor is unavailable"
}
$Release = Get-Content -LiteralPath $ReleaseDescriptor -Raw | ConvertFrom-Json
$ExpectedFields = @(
    "schema_version",
    "product",
    "version",
    "package_directory",
    "package_manifest_sha256",
    "installer_sha256",
    "lifecycle_sha256",
    "source_commit",
    "source_tree"
)
$ActualFields = @($Release.PSObject.Properties.Name | Sort-Object)
if ((Compare-Object ($ExpectedFields | Sort-Object) $ActualFields)) {
    throw "Keeper installer release descriptor fields are invalid"
}
if ($Release.schema_version -ne 1 -or $Release.product -ne "Keeper") {
    throw "Keeper installer release descriptor identity is invalid"
}
foreach ($Hash in @(
    [string]$Release.package_manifest_sha256,
    [string]$Release.installer_sha256,
    [string]$Release.lifecycle_sha256
)) {
    if ($Hash -notmatch '^[A-Fa-f0-9]{64}$') {
        throw "Keeper installer release descriptor hash is malformed"
    }
}
foreach ($Identity in @(
    [string]$Release.source_commit,
    [string]$Release.source_tree
)) {
    if ($Identity -notmatch '^[a-f0-9]{40,64}$') {
        throw "Keeper installer source identity is malformed"
    }
}
if ((Get-Sha256Hex $InstallerPath) -ne
    [string]$Release.installer_sha256) {
    throw "Keeper installer bytes differ from the release descriptor"
}
if ((Get-Sha256Hex $Lifecycle) -ne
    [string]$Release.lifecycle_sha256) {
    throw "Keeper lifecycle bytes differ from the release descriptor"
}
if (-not $PackageDirectory) {
    if ([IO.Path]::IsPathRooted([string]$Release.package_directory) -or
        [string]$Release.package_directory -ne "Keeper.dist") {
        throw "Keeper installer package location is invalid"
    }
    $PackageDirectory = Join-Path $InstallerRoot ([string]$Release.package_directory)
}
$PackageDirectory = [IO.Path]::GetFullPath($PackageDirectory)
$ApprovedManifest = [string]$Release.package_manifest_sha256
if ($ExpectedManifestSha256) {
    if ($ExpectedManifestSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        -not $ExpectedManifestSha256.Equals(
            $ApprovedManifest,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Explicit Keeper manifest approval differs from the release descriptor"
    }
}
$Common = @("-SkipShortcuts")
if (-not $SkipShortcuts) { $Common = @() }
if ($InstallRoot) { $Common += @("-InstallRoot", $InstallRoot) }
if ($DataDirectory) { $Common += @("-DataDirectory", $DataDirectory) }
$StatusJson = & powershell -NoProfile -ExecutionPolicy Bypass -File $Lifecycle `
    -Action Status @Common
if ($LASTEXITCODE -ne 0) { throw "Keeper installed-state validation failed" }
$Status = $StatusJson | ConvertFrom-Json
$Action = if ($Status.installed -ne $true) {
    "Install"
}
elseif ([string]$Status.current_manifest_sha256 -eq $ApprovedManifest) {
    "Repair"
}
else {
    "Upgrade"
}
$ResultJson = & powershell -NoProfile -ExecutionPolicy Bypass -File $Lifecycle `
    -Action $Action -PackageDirectory $PackageDirectory `
    -ExpectedManifestSha256 $ApprovedManifest @Common
if ($LASTEXITCODE -ne 0) { throw "Keeper $Action failed" }
$Result = $ResultJson | ConvertFrom-Json
if (
    [string]$Result.manifest_sha256 -ne $ApprovedManifest -or
    [string]$Result.version -ne [string]$Release.version
) {
    throw "Installed Keeper result differs from the release descriptor"
}
if ($Launch) {
    $Executable = [IO.Path]::GetFullPath([string]$Result.executable)
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        throw "Installed Keeper executable is unavailable"
    }
    Start-Process -FilePath $Executable -WorkingDirectory (Split-Path -Parent $Executable)
}
[ordered]@{
    action = $Action
    version = [string]$Result.version
    manifest_sha256 = [string]$Result.manifest_sha256
    executable = [string]$Result.executable
    data_directory = [string]$Result.data_directory
    rollback_available = [bool]$Result.rollback_available
    launched = [bool]$Launch
} | ConvertTo-Json -Depth 4
