param(
    [Parameter(Mandatory = $true)]
    [string]$PythonPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedPythonSha256,
    [Parameter(Mandatory = $true)]
    [string]$CompilerPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedCompilerSha256,
    [Parameter(Mandatory = $true)]
    [string]$DeveloperEnvironmentPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedDeveloperEnvironmentSha256,
    [Parameter(Mandatory = $true)]
    [string]$DependencyWalkerPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedDependencyWalkerSha256
)

$ErrorActionPreference = "Stop"
$Repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Python = (Resolve-Path -LiteralPath $PythonPath).Path
$Compiler = (Resolve-Path -LiteralPath $CompilerPath).Path
$DeveloperEnvironment = (Resolve-Path -LiteralPath $DeveloperEnvironmentPath).Path
$DependencyWalker = (Resolve-Path -LiteralPath $DependencyWalkerPath).Path
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

function Assert-Sha256 {
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [string]$Expected,
        [Parameter(Mandatory = $true)] [string]$Label
    )
    if ($Expected -notmatch '^[0-9A-Fa-f]{64}$') {
        throw "$Label expected SHA-256 is malformed"
    }
    $Actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if (-not $Actual.Equals($Expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label SHA-256 differs"
    }
    return $Actual.ToUpperInvariant()
}

$PythonSha256 = Assert-Sha256 $Python $ExpectedPythonSha256 "Python runtime"
$CompilerSha256 = Assert-Sha256 $Compiler $ExpectedCompilerSha256 "MSVC compiler"
$DeveloperEnvironmentSha256 = Assert-Sha256 `
    $DeveloperEnvironment `
    $ExpectedDeveloperEnvironmentSha256 `
    "Visual Studio developer environment"
$DependencyWalkerSha256 = Assert-Sha256 `
    $DependencyWalker $ExpectedDependencyWalkerSha256 "Dependency Walker"
$PythonSignature = (Get-AuthenticodeSignature -LiteralPath $Python).Status.ToString()
$CompilerSignature = (Get-AuthenticodeSignature -LiteralPath $Compiler).Status.ToString()
if ($PythonSignature -ne "Valid" -or $CompilerSignature -ne "Valid") {
    throw "Provider Host build requires signed Python and MSVC inputs"
}

$SourceCommit = (& git -C $Repository rev-parse HEAD).Trim()
$SourceTree = (& git -C $Repository rev-parse 'HEAD^{tree}').Trim()
$SourceStatus = @(& git -C $Repository status --porcelain=v1 --untracked-files=all)
if (
    $LASTEXITCODE -ne 0 -or
    $SourceCommit -notmatch '^[0-9a-f]{40}$' -or
    $SourceTree -notmatch '^[0-9a-f]{40}$' -or
    $SourceStatus.Count -ne 0
) {
    throw "Provider Host release builds require an exact clean Git source"
}

& $Python -c "from importlib.metadata import version; assert version('Nuitka') == '4.1.3'"
if ($LASTEXITCODE -ne 0) { throw "Nuitka 4.1.3 is required" }
$NuitkaVersion = (& $Python -c "from importlib.metadata import version; print(version('Nuitka'))").Trim()
$PythonVersion = (& $Python -c "import platform; print(platform.python_version())").Trim()

$TempRoot = Join-Path ([IO.Path]::GetTempPath()) ("keeper-provider-host-build-" + [Guid]::NewGuid().ToString("N"))
$SourceStage = Join-Path $TempRoot "source"
$BuildRoot = Join-Path $TempRoot "build"
New-Item -ItemType Directory -Path $SourceStage -Force | Out-Null
New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $Repository "keeper") -Destination $SourceStage -Recurse
    Copy-Item -LiteralPath (Join-Path $Repository "keeper_provider_host.py") -Destination $SourceStage
    Get-ChildItem -LiteralPath $SourceStage -Recurse -Directory -Filter "__pycache__" |
        Sort-Object { $_.FullName.Length } -Descending |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }

    $PreviousEnvironment = @{}
    Get-ChildItem Env: | ForEach-Object { $PreviousEnvironment[$_.Name] = $_.Value }
    $PreviousNuitkaCache = $env:NUITKA_CACHE_DIR
    try {
        $DeveloperOutput = & $env:ComSpec /d /s /c `
            "`"$DeveloperEnvironment`" -no_logo -arch=x64 -host_arch=x64 >nul && set"
        if ($LASTEXITCODE -ne 0) {
            throw "Visual Studio developer environment failed"
        }
        foreach ($Line in $DeveloperOutput) {
            $Separator = $Line.IndexOf("=")
            if ($Separator -gt 0) {
                [Environment]::SetEnvironmentVariable(
                    $Line.Substring(0, $Separator),
                    $Line.Substring($Separator + 1),
                    "Process"
                )
            }
        }
        $ResolvedCompiler = (Get-Command cl.exe -CommandType Application).Source
        if (
            -not [IO.Path]::GetFullPath($ResolvedCompiler).Equals(
                [IO.Path]::GetFullPath($Compiler),
                [StringComparison]::OrdinalIgnoreCase
            )
        ) {
            throw "Visual Studio environment selected a different compiler"
        }
        $env:Path = (Split-Path -Parent $Python) + ";" + $env:Path
        $env:NUITKA_CACHE_DIR = Join-Path $TempRoot "nuitka-cache"
        $PinnedDependencyWalker = Join-Path `
            $env:NUITKA_CACHE_DIR "downloads\depends\x86_64\depends.exe"
        New-Item -ItemType Directory -Path `
            (Split-Path -Parent $PinnedDependencyWalker) -Force | Out-Null
        Copy-Item -LiteralPath $DependencyWalker -Destination $PinnedDependencyWalker
        [void](Assert-Sha256 `
            $PinnedDependencyWalker `
            $ExpectedDependencyWalkerSha256 `
            "staged Dependency Walker")
        $BuildLog = Join-Path $OutputDirectory "keeper-provider-host-build.log"
        Push-Location $SourceStage
        try {
            $PreviousErrorAction = $ErrorActionPreference
            try {
                $ErrorActionPreference = "Continue"
                $BuildOutput = @("n") | & $Python -m nuitka `
                    --standalone `
                    --reproducible=yes `
                    --output-dir=$BuildRoot `
                    --output-filename=KeeperProviderHost.exe `
                    --nofollow-import-to=PySide6 `
                    --nofollow-import-to=tkinter `
                    keeper_provider_host.py 2>&1
                $BuildExitCode = $LASTEXITCODE
            }
            finally { $ErrorActionPreference = $PreviousErrorAction }
            [IO.File]::WriteAllLines(
                $BuildLog,
                @($BuildOutput | ForEach-Object { $_.ToString() }),
                (New-Object Text.UTF8Encoding($false))
            )
            $BuildOutput | ForEach-Object { Write-Output $_ }
            if ($BuildExitCode -ne 0) { throw "Provider Host build failed" }
            if ($BuildOutput -match '(?i)downloading|https?://') {
                throw "Provider Host build attempted an unapproved download"
            }
        }
        finally { Pop-Location }
    }
    finally {
        Get-ChildItem Env: | ForEach-Object {
            if (-not $PreviousEnvironment.ContainsKey($_.Name)) {
                [Environment]::SetEnvironmentVariable($_.Name, $null, "Process")
            }
        }
        foreach ($Entry in $PreviousEnvironment.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable(
                $Entry.Key, $Entry.Value, "Process"
            )
        }
        $env:NUITKA_CACHE_DIR = $PreviousNuitkaCache
    }

    $Distribution = Get-ChildItem -LiteralPath $BuildRoot -Recurse -Directory -Filter "*.dist" |
        Select-Object -First 1
    if (-not $Distribution) { throw "Provider Host build did not produce a standalone distribution" }
    $BuiltExecutable = Join-Path $Distribution.FullName "KeeperProviderHost.exe"
    if (-not (Test-Path -LiteralPath $BuiltExecutable -PathType Leaf)) {
        throw "Provider Host build did not produce the dedicated executable"
    }
    $PackageRoot = Join-Path $OutputDirectory "KeeperProviderHost.dist"
    if (Test-Path -LiteralPath $PackageRoot) {
        $Resolved = (Resolve-Path -LiteralPath $PackageRoot).Path
        $Prefix = $OutputDirectory.TrimEnd("\") + "\"
        if (-not $Resolved.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "refusing to replace Provider Host output outside the requested directory"
        }
        Remove-Item -LiteralPath $Resolved -Recurse -Force
    }
    Copy-Item -LiteralPath $Distribution.FullName -Destination $PackageRoot -Recurse
    $Forbidden = Get-ChildItem -LiteralPath $PackageRoot -Recurse -Force | Where-Object {
        $_.FullName -match '(?i)\.ai-workflow(\|$)|pilot-invocations|__pycache__' -or
        $_.Extension -in '.pyc', '.pyo' -or
        $_.Name -match '^(keeper\.db|.*\.key|.*\.pem|.*\.pfx)$'
    }
    if ($Forbidden) { throw "Provider Host package contains protected or secret material" }
    $Executable = Join-Path $PackageRoot "KeeperProviderHost.exe"
    $Version = (& $Python -c "from keeper.authority_service.core import SERVICE_VERSION; print(SERVICE_VERSION)").Trim()
    if ($LASTEXITCODE -ne 0 -or -not $Version) { throw "Provider Host version is unavailable" }
    $PackagePrefix = $PackageRoot.TrimEnd("\") + "\"
    $Files = @(Get-ChildItem -LiteralPath $PackageRoot -Recurse -File | ForEach-Object {
        if (-not $_.FullName.StartsWith($PackagePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Provider Host package file escaped the output root"
        }
        $Relative = $_.FullName.Substring($PackagePrefix.Length).Replace("\", "/")
        [ordered]@{
            path = $Relative
            size = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    } | Sort-Object { $_.path })
    $ManifestPath = Join-Path $PackageRoot "keeper-provider-host-package-manifest.json"
    $ManifestJson = [ordered]@{
        schema_version = 1
        product = "KeeperProviderHost"
        version = $Version
        files = $Files
    } | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText(
        $ManifestPath,
        $ManifestJson + [Environment]::NewLine,
        (New-Object Text.UTF8Encoding($false))
    )
    $ProvenancePath = Join-Path $OutputDirectory "keeper-provider-host-build-provenance.json"
    $ProvenanceJson = [ordered]@{
        schema_version = 1
        product = "KeeperProviderHost"
        version = $Version
        source_commit = $SourceCommit
        source_tree = $SourceTree
        python = [ordered]@{
            version = $PythonVersion
            sha256 = $PythonSha256
            authenticode = $PythonSignature
        }
        nuitka = [ordered]@{ version = $NuitkaVersion }
        compiler = [ordered]@{
            version = (Get-Item -LiteralPath $Compiler).VersionInfo.FileVersion
            sha256 = $CompilerSha256
            authenticode = $CompilerSignature
        }
        developer_environment = [ordered]@{
            sha256 = $DeveloperEnvironmentSha256
        }
        dependency_walker = [ordered]@{
            version = (Get-Item -LiteralPath $DependencyWalker).VersionInfo.FileVersion
            sha256 = $DependencyWalkerSha256
        }
        build_network = "DISALLOWED_NO_DOWNLOAD_OBSERVED"
        executable_sha256 = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
        package_manifest_sha256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash
    } | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText(
        $ProvenancePath,
        $ProvenanceJson + [Environment]::NewLine,
        (New-Object Text.UTF8Encoding($false))
    )
    $DefenderReportPath = Join-Path $OutputDirectory "keeper-provider-host-defender-verification.json"
    & (Join-Path $PSScriptRoot "verify-keeper-provider-host-defender.ps1") `
        -ArtifactPath $Executable `
        -ExpectedSha256 (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash `
        -ReportPath $DefenderReportPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Provider Host Defender release gate failed"
    }
    Write-Output ([ordered]@{
        package_root = $PackageRoot
        package_manifest = $ManifestPath
        package_sha256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash
        executable = $Executable
        executable_sha256 = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
        build_provenance = $ProvenancePath
        build_provenance_sha256 = (Get-FileHash -LiteralPath $ProvenancePath -Algorithm SHA256).Hash
        build_log = $BuildLog
        defender_verification = $DefenderReportPath
        defender_verification_sha256 = (Get-FileHash -LiteralPath $DefenderReportPath -Algorithm SHA256).Hash
        file_count = @(Get-ChildItem -LiteralPath $PackageRoot -Recurse -File).Count
    } | ConvertTo-Json -Depth 4)
}
finally {
    if (Test-Path -LiteralPath $TempRoot) {
        $ResolvedTemp = (Resolve-Path -LiteralPath $TempRoot).Path
        $TempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (-not $ResolvedTemp.StartsWith($TempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "refusing to remove Provider Host build state outside the temporary directory"
        }
        Remove-Item -LiteralPath $ResolvedTemp -Recurse -Force
    }
}
