param(
    [Parameter(Mandatory = $true)]
    [string]$PythonPath,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$Repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Python = (Resolve-Path -LiteralPath $PythonPath).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $Repository "dist\keeper-desktop"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$SourceIcon = Join-Path $Repository "keeper\assets\keeper-official.png"
$IconDirectory = Join-Path $Repository "keeper\assets\icons"
$Template = Join-Path $Repository "keeper\ui_qml\pysidedeploy.template.spec"

$Dirty = & git -C $Repository status --porcelain=v1 --untracked-files=all
if ($LASTEXITCODE -ne 0 -or $Dirty) {
    throw "Keeper desktop build requires a clean Git worktree"
}
$SourceCommit = (& git -C $Repository rev-parse --verify HEAD).Trim()
$SourceTree = (& git -C $Repository rev-parse --verify "HEAD^{tree}").Trim()
$SourceTimestamp = (& git -C $Repository show -s --format=%cI $SourceCommit).Trim()
if (
    $LASTEXITCODE -ne 0 -or
    $SourceCommit -notmatch '^[a-f0-9]{40,64}$' -or
    $SourceTree -notmatch '^[a-f0-9]{40,64}$' -or
    -not $SourceTimestamp
) {
    throw "Keeper desktop source identity is unavailable"
}

& $Python -c "import PySide6; assert PySide6.__version__ == '6.10.1'"
if ($LASTEXITCODE -ne 0) { throw "PySide6 6.10.1 is required" }
& $Python -c "from importlib.metadata import version; assert version('Nuitka') == '4.1.3'"
if ($LASTEXITCODE -ne 0) { throw "Nuitka 4.1.3 is required" }

& $Python (Join-Path $PSScriptRoot "build-keeper-icons.py") $SourceIcon $IconDirectory
if ($LASTEXITCODE -ne 0) { throw "Keeper icon generation failed" }

$Deploy = Join-Path (Split-Path -Parent $Python) "pyside6-deploy.exe"
if (-not (Test-Path -LiteralPath $Deploy -PathType Leaf)) {
    throw "pyside6-deploy.exe is unavailable beside the selected Python"
}
$Nuitka = Join-Path (Split-Path -Parent $Python) "nuitka.cmd"
if (-not (Test-Path -LiteralPath $Nuitka -PathType Leaf)) {
    throw "nuitka.cmd is unavailable beside the selected Python"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$TempRoot = Join-Path ([IO.Path]::GetTempPath()) ("keeper-desktop-build-" + [Guid]::NewGuid().ToString("N"))
$SourceStage = Join-Path $TempRoot "source"
New-Item -ItemType Directory -Path $SourceStage -Force | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $Repository "keeper") -Destination $SourceStage -Recurse
    Copy-Item -LiteralPath (Join-Path $Repository "keeper_desktop.py") -Destination $SourceStage
    Get-ChildItem -LiteralPath $SourceStage -Recurse -Directory -Filter "__pycache__" |
        Sort-Object { $_.FullName.Length } -Descending |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }

    $Spec = Join-Path $TempRoot "pysidedeploy.spec"
    $DeployOutput = Join-Path $TempRoot "output"
    New-Item -ItemType Directory -Path $DeployOutput -Force | Out-Null
    $Content = [IO.File]::ReadAllText($Template)
    $Content = $Content.Replace("@PROJECT_DIR@", $SourceStage)
    $Content = $Content.Replace("@EXEC_DIRECTORY@", $DeployOutput)
    $Content = $Content.Replace("@ICON_PATH@", (Join-Path $SourceStage "keeper\assets\icons\keeper.ico"))
    $Content = $Content.Replace("@PYTHON_PATH@", $Python)
    [IO.File]::WriteAllText($Spec, $Content, [Text.UTF8Encoding]::new($false))

    $PreviousPath = $env:Path
    $PreviousNuitkaCache = $env:NUITKA_CACHE_DIR
    try {
        $env:Path = (Split-Path -Parent $Python) + ";" + $env:Path
        $env:NUITKA_CACHE_DIR = Join-Path $TempRoot "nuitka-cache"
        Push-Location $SourceStage
        try {
            & $Deploy -c $Spec --force --mode standalone --name Keeper
            if ($LASTEXITCODE -ne 0) { throw "Qt desktop deployment failed" }
        }
        finally { Pop-Location }
    }
    finally {
        $env:Path = $PreviousPath
        $env:NUITKA_CACHE_DIR = $PreviousNuitkaCache
    }

    $Distribution = Get-ChildItem -LiteralPath $TempRoot -Recurse -Directory -Filter "*.dist" |
        Select-Object -First 1
    if (-not $Distribution) { throw "Qt deployment did not produce a standalone distribution" }
    $BuiltExecutable = Get-ChildItem -LiteralPath $Distribution.FullName -File -Filter "*.exe" |
        Where-Object { $_.Name -notmatch '^QtWebEngineProcess' } |
        Select-Object -First 1
    if (-not $BuiltExecutable) { throw "Qt deployment did not produce a desktop executable" }

    $PackageRoot = Join-Path $OutputDirectory "Keeper.dist"
    if (Test-Path -LiteralPath $PackageRoot) {
        $ResolvedPackage = (Resolve-Path -LiteralPath $PackageRoot).Path
        $OutputPrefix = $OutputDirectory.TrimEnd('\') + '\'
        if (-not $ResolvedPackage.StartsWith($OutputPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "refusing to replace package output outside the requested directory"
        }
        Remove-Item -LiteralPath $ResolvedPackage -Recurse -Force
    }
    Copy-Item -LiteralPath $Distribution.FullName -Destination $PackageRoot -Recurse
    $CopiedExecutable = Join-Path $PackageRoot $BuiltExecutable.Name
    $Executable = Join-Path $PackageRoot "Keeper.exe"
    if ($CopiedExecutable -ne $Executable) {
        Move-Item -LiteralPath $CopiedExecutable -Destination $Executable
    }

    $Forbidden = Get-ChildItem -LiteralPath $PackageRoot -Recurse -Force | Where-Object {
        $_.FullName -match '\\.ai-workflow(\\|$)' -or
        $_.FullName -match 'pilot-invocations' -or
        $_.Name -match '^(keeper\.db|.*\.key|.*\.pem|.*\.pfx)$'
    }
    if ($Forbidden) { throw "desktop package contains protected or secret material" }

    $Files = Get-ChildItem -LiteralPath $PackageRoot -Recurse -File | Sort-Object FullName
    $ManifestFiles = @($Files | ForEach-Object {
        $Relative = $_.FullName.Substring($PackageRoot.TrimEnd("\").Length + 1).Replace("\", "/")
        [ordered]@{
            path = $Relative
            size = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        }
    })
    $Manifest = [ordered]@{
        product = "Keeper"
        version = (& $Python -c "from keeper.version import VERSION; print(VERSION)")
        composition = "PRODUCTION_CAPABLE_LOCAL_CLIENT"
        built_at_utc = $SourceTimestamp
        source_commit = $SourceCommit
        source_tree = $SourceTree
        files = $ManifestFiles
    }
    $ManifestPath = Join-Path $PackageRoot "keeper-package-manifest.json"
    $Manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8
    $Installer = Join-Path $OutputDirectory "install-keeper-desktop.ps1"
    $Lifecycle = Join-Path $OutputDirectory "keeper-local-lifecycle.ps1"
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "install-keeper-desktop.ps1") -Destination $Installer
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "keeper-local-lifecycle.ps1") -Destination $Lifecycle
    $ReleaseDescriptor = Join-Path $OutputDirectory "keeper-installer-release.json"
    [ordered]@{
        schema_version = 1
        product = "Keeper"
        version = $Manifest.version
        package_directory = "Keeper.dist"
        package_manifest_sha256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash
        installer_sha256 = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash
        lifecycle_sha256 = (Get-FileHash -LiteralPath $Lifecycle -Algorithm SHA256).Hash
        source_commit = $SourceCommit
        source_tree = $SourceTree
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ReleaseDescriptor -Encoding UTF8
    Write-Output ([ordered]@{
        package_root = $PackageRoot
        executable = $Executable
        manifest = $ManifestPath
        manifest_sha256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash
        installer = $Installer
        release_descriptor = $ReleaseDescriptor
        release_descriptor_sha256 = (Get-FileHash -LiteralPath $ReleaseDescriptor -Algorithm SHA256).Hash
        file_count = $ManifestFiles.Count
    } | ConvertTo-Json -Depth 4)
}
finally {
    if (Test-Path -LiteralPath $TempRoot) {
        $ResolvedTemp = (Resolve-Path -LiteralPath $TempRoot).Path
        $TempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (-not $ResolvedTemp.StartsWith($TempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "refusing to remove build state outside the temporary directory"
        }
        Remove-Item -LiteralPath $ResolvedTemp -Recurse -Force
    }
}
