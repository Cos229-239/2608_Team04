param(
    [Parameter(Mandatory = $true)][string]$PythonPath,
    [Parameter(Mandatory = $true)][string]$AuthorityPackageRoot,
    [Parameter(Mandatory = $true)][string]$ProviderHostRoot,
    [string]$DesktopPackageRoot = "",
    [string]$OutputDirectory = "",
    [string]$CompilerPath = "",
    [string]$CertificateThumbprint = ""
)

$ErrorActionPreference = "Stop"
$Repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $DesktopPackageRoot) { $DesktopPackageRoot = Join-Path $Repository "dist\keeper-desktop" }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $Repository "dist\machine-installer" }
$Python = (Resolve-Path -LiteralPath $PythonPath).Path
$AuthorityPackageRoot = (Resolve-Path -LiteralPath $AuthorityPackageRoot).Path
$ProviderHostRoot = (Resolve-Path -LiteralPath $ProviderHostRoot).Path
$DesktopPackageRoot = (Resolve-Path -LiteralPath $DesktopPackageRoot).Path
$Payload = Join-Path $OutputDirectory "payload"
if (Test-Path -LiteralPath $Payload) { throw "Machine installer payload already exists: $Payload" }
New-Item -ItemType Directory -Path $Payload,$OutputDirectory -Force | Out-Null

$SourceCommit = (& git -C $Repository rev-parse HEAD).Trim()
$SourceTree = (& git -C $Repository rev-parse 'HEAD^{tree}').Trim()
$SourceStatus = @(& git -C $Repository status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $SourceCommit -notmatch '^[0-9a-f]{40}$' -or $SourceTree -notmatch '^[0-9a-f]{40}$' -or $SourceStatus.Count -ne 0) {
    throw "Keeper Git source identity is invalid"
}
$DesktopManifestPath = Join-Path $DesktopPackageRoot 'Keeper.dist\keeper-package-manifest.json'
$HostProvenancePath = Join-Path (Split-Path -Parent $ProviderHostRoot) 'keeper-provider-host-build-provenance.json'
$AuthorityManifestPath = Join-Path $AuthorityPackageRoot 'keeper-authority-package-manifest.json'
foreach ($Required in @($DesktopManifestPath, $HostProvenancePath, $AuthorityManifestPath)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "Keeper release provenance is missing: $Required"
    }
}
$DesktopIdentity = Get-Content -LiteralPath $DesktopManifestPath -Raw | ConvertFrom-Json
$HostIdentity = Get-Content -LiteralPath $HostProvenancePath -Raw | ConvertFrom-Json
$AuthorityIdentity = Get-Content -LiteralPath $AuthorityManifestPath -Raw | ConvertFrom-Json
foreach ($Identity in @($DesktopIdentity, $HostIdentity, $AuthorityIdentity)) {
    if (
        [string]$Identity.source_commit -ne $SourceCommit -or
        [string]$Identity.source_tree -ne $SourceTree
    ) {
        throw "Keeper release artifact source identity differs from the installer source"
    }
}
$Version = (& $Python -c "from keeper.version import VERSION; print(VERSION)").Trim()
$Source = Join-Path $Payload "source"
New-Item -ItemType Directory -Path $Source | Out-Null
Copy-Item -LiteralPath (Join-Path $Repository "keeper") -Destination $Source -Recurse
Copy-Item -LiteralPath (Join-Path $Repository "keeper_provider_host.py") -Destination $Source
Get-ChildItem -LiteralPath $Source -Directory -Filter '__pycache__' -Recurse |
    Sort-Object FullName -Descending |
    Remove-Item -Recurse -Force
[ordered]@{ schema_version = 1; source_commit = $SourceCommit; source_tree = $SourceTree } |
    ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $Source "keeper-release-source.json") -Encoding utf8NoBOM

$BasePrefix = (& $Python -c "import sys; print(sys.base_prefix)").Trim()
$Runtime = Join-Path $Payload "runtime"
New-Item -ItemType Directory -Path $Runtime | Out-Null
foreach ($Name in @('python.exe','python3.dll',("python{0}{1}.dll" -f $([version]$(& $Python -c "import platform; print(platform.python_version())")).Major,$([version]$(& $Python -c "import platform; print(platform.python_version())")).Minor),'vcruntime140.dll','vcruntime140_1.dll','LICENSE.txt')) {
    $Item = Join-Path $BasePrefix $Name
    if (Test-Path -LiteralPath $Item -PathType Leaf) { Copy-Item -LiteralPath $Item -Destination $Runtime }
}
Copy-Item -LiteralPath (Join-Path $BasePrefix 'DLLs') -Destination $Runtime -Recurse
Copy-Item -LiteralPath (Join-Path $BasePrefix 'Lib') -Destination $Runtime -Recurse
$SitePackages = Join-Path $Runtime 'Lib\site-packages'
if (Test-Path -LiteralPath $SitePackages) { Remove-Item -LiteralPath $SitePackages -Recurse -Force }
Get-ChildItem -LiteralPath $Runtime -Directory -Filter '__pycache__' -Recurse |
    Sort-Object { $_.FullName.Length } -Descending |
    Remove-Item -Recurse -Force
Get-ChildItem -LiteralPath $Runtime -File -Include '*.pyc','*.pyo' -Recurse |
    Remove-Item -Force
foreach ($UnusedLibrary in @('ensurepip','idlelib','tkinter','test','turtledemo','venv')) {
    $UnusedPath = Join-Path $Runtime "Lib\$UnusedLibrary"
    if (Test-Path -LiteralPath $UnusedPath) {
        Remove-Item -LiteralPath $UnusedPath -Recurse -Force
    }
}

Copy-Item -LiteralPath $DesktopPackageRoot -Destination (Join-Path $Payload 'desktop') -Recurse
Copy-Item -LiteralPath $ProviderHostRoot -Destination (Join-Path $Payload 'provider-host') -Recurse
Copy-Item -LiteralPath $AuthorityPackageRoot -Destination (Join-Path $Payload 'authority') -Recurse
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install-keeper-machine-authority.ps1') -Destination (Join-Path $Payload 'install-machine-authority.ps1')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install-keeper-machine-user.ps1') -Destination (Join-Path $Payload 'install-user-components.ps1')

$Files = Get-ChildItem -LiteralPath $Payload -File -Recurse | Sort-Object FullName | ForEach-Object {
    [ordered]@{ path = $_.FullName.Substring($Payload.Length + 1).Replace('\','/'); size = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
}
[ordered]@{ schema_version = 1; product = 'Keeper Full Machine'; version = $Version; source_commit = $SourceCommit; source_tree = $SourceTree; files = @($Files) } |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $Payload 'keeper-machine-release.json') -Encoding utf8NoBOM

if (-not $CompilerPath) {
    $CompilerPath = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if (-not $CompilerPath) { throw "Inno Setup 6 compiler is unavailable" }
$Suffix = if ($CertificateThumbprint) { '' } else { '-Unsigned' }
& $CompilerPath "/DPayloadRoot=$Payload" "/DOutputDir=$OutputDirectory" "/DSetupIcon=$(Join-Path $Repository 'keeper\assets\icons\keeper.ico')" "/DAppVersion=$Version" "/DOutputSuffix=$Suffix" (Join-Path $Repository 'packaging\windows\keeper-machine.iss')
if ($LASTEXITCODE -ne 0) { throw "Keeper full-machine installer compilation failed" }
$Setup = Get-ChildItem -LiteralPath $OutputDirectory -Filter "Keeper-$Version-Full-Machine-Setup*.exe" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $Setup) { throw "Keeper full-machine setup was not produced" }
if ($CertificateThumbprint) {
    & (Join-Path $PSScriptRoot 'sign-keeper-release.ps1') -Path $Setup.FullName -CertificateThumbprint $CertificateThumbprint | Out-Null
}
$Signature = Get-AuthenticodeSignature -LiteralPath $Setup.FullName
[ordered]@{ installer = $Setup.FullName; sha256 = (Get-FileHash -LiteralPath $Setup.FullName -Algorithm SHA256).Hash; signature_status = [string]$Signature.Status; source_commit = $SourceCommit; source_tree = $SourceTree } | ConvertTo-Json
