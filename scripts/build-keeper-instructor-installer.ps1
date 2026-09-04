param(
    [string]$PackageRoot = "",
    [string]$OutputDirectory = "",
    [string]$CompilerPath = ""
)

$ErrorActionPreference = "Stop"
$Repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $PackageRoot) {
    $PackageRoot = Join-Path $Repository "dist\keeper-desktop"
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $Repository "dist\instructor-installer"
}
$PackageRoot = [IO.Path]::GetFullPath($PackageRoot)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$DescriptorPath = Join-Path $PackageRoot "keeper-installer-release.json"
$InstallerScript = Join-Path $PackageRoot "install-keeper-desktop.ps1"
$LifecycleScript = Join-Path $PackageRoot "keeper-local-lifecycle.ps1"
$Distribution = Join-Path $PackageRoot "Keeper.dist"
$Executable = Join-Path $Distribution "Keeper.exe"
$Manifest = Join-Path $Distribution "keeper-package-manifest.json"
$SetupIcon = Join-Path $Repository "keeper\assets\icons\keeper.ico"

foreach ($Required in @(
    $DescriptorPath,
    $InstallerScript,
    $LifecycleScript,
    $Executable,
    $Manifest,
    $SetupIcon
)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "Keeper instructor package input is unavailable: $Required"
    }
}

$Descriptor = Get-Content -LiteralPath $DescriptorPath -Raw | ConvertFrom-Json
if (
    $Descriptor.schema_version -ne 1 -or
    $Descriptor.product -ne "Keeper" -or
    [string]$Descriptor.package_directory -ne "Keeper.dist"
) {
    throw "Keeper installer release descriptor is invalid"
}
$ManifestHash = (Get-FileHash -LiteralPath $Manifest -Algorithm SHA256).Hash
if (-not $ManifestHash.Equals(
    [string]$Descriptor.package_manifest_sha256,
    [StringComparison]::OrdinalIgnoreCase
)) {
    throw "Keeper package manifest differs from the release descriptor"
}

if (-not $CompilerPath) {
    $Candidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
        (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
    ) | Where-Object { $_ }
    $CompilerPath = $Candidates | Where-Object {
        Test-Path -LiteralPath $_ -PathType Leaf
    } | Select-Object -First 1
}
if (-not $CompilerPath -or -not (Test-Path -LiteralPath $CompilerPath -PathType Leaf)) {
    throw "Inno Setup 6 compiler is unavailable"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$Definition = Join-Path $Repository "packaging\windows\keeper-instructor.iss"
& $CompilerPath `
    "/DPackageRoot=$PackageRoot" `
    "/DOutputDir=$OutputDirectory" `
    "/DSetupIcon=$SetupIcon" `
    "/DAppVersion=$([string]$Descriptor.version)" `
    $Definition
if ($LASTEXITCODE -ne 0) {
    throw "Keeper instructor installer compilation failed"
}

$Setup = Get-ChildItem -LiteralPath $OutputDirectory -File `
    -Filter "Keeper-*-Instructor-Setup-Unsigned.exe" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $Setup) {
    throw "Keeper instructor setup executable was not produced"
}
$Signature = Get-AuthenticodeSignature -LiteralPath $Setup.FullName
$ChecksumPath = $Setup.FullName + ".sha256"
$Checksum = (Get-FileHash -LiteralPath $Setup.FullName -Algorithm SHA256).Hash
"$Checksum  $($Setup.Name)" | Set-Content -LiteralPath $ChecksumPath -Encoding ascii

[ordered]@{
    installer = $Setup.FullName
    version = [string]$Descriptor.version
    sha256 = $Checksum
    signature_status = [string]$Signature.Status
    signed = $Signature.Status -eq "Valid"
    source_commit = [string]$Descriptor.source_commit
    source_tree = [string]$Descriptor.source_tree
    package_manifest_sha256 = $ManifestHash
} | ConvertTo-Json -Depth 4
