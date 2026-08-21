param(
    [ValidateSet("Install", "Repair", "Upgrade", "Rollback", "Uninstall", "Status")]
    [string]$Action = "Status",
    [string]$PackageDirectory = "",
    [string]$InstallRoot = "",
    [string]$DataDirectory = "",
    [string]$ExpectedManifestSha256 = "",
    [switch]$SkipShortcuts
)

$ErrorActionPreference = "Stop"
if (-not $InstallRoot) {
    $InstallRoot = Join-Path $env:LOCALAPPDATA "Programs\Keeper"
}
if (-not $DataDirectory) {
    $DataDirectory = Join-Path $env:LOCALAPPDATA "Keeper"
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$DataDirectory = [IO.Path]::GetFullPath($DataDirectory)
$Current = Join-Path $InstallRoot "current"
$Rollback = Join-Path $InstallRoot "rollback"
$RollbackJournal = Join-Path $InstallRoot ".keeper-rollback-transaction.json"
$InstallJournal = Join-Path $InstallRoot ".keeper-install-transaction.json"

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

function Assert-SafeRoot([string]$PathValue) {
    $Full = [IO.Path]::GetFullPath($PathValue)
    $Root = [IO.Path]::GetPathRoot($Full)
    if ($Full -eq $Root -or $Full.Length -lt ($Root.Length + 8)) {
        throw "Keeper lifecycle target is too broad: $Full"
    }
    if ($Full -match '(?i)\\.ai-workflow(\\|$)|pilot-invocations') {
        throw "Keeper lifecycle target intersects a protected workflow tree"
    }
}

function Test-PathWithinOrEqual([string]$Candidate, [string]$Container) {
    $CandidateFull = [IO.Path]::GetFullPath($Candidate).TrimEnd('\')
    $ContainerFull = [IO.Path]::GetFullPath($Container).TrimEnd('\')
    return (
        $CandidateFull.Equals($ContainerFull, [StringComparison]::OrdinalIgnoreCase) -or
        $CandidateFull.StartsWith(
            $ContainerFull + '\',
            [StringComparison]::OrdinalIgnoreCase
        )
    )
}

function Assert-DisjointPathTrees(
    [string]$Left,
    [string]$Right,
    [string]$Label = "Keeper lifecycle paths"
) {
    if ((Test-PathWithinOrEqual $Left $Right) -or
        (Test-PathWithinOrEqual $Right $Left)) {
        throw "$Label must be disjoint"
    }
}

function Assert-NoReparsePath([string]$PathValue) {
    $Candidate = [IO.Path]::GetFullPath($PathValue)
    while ($Candidate) {
        if (Test-Path -LiteralPath $Candidate) {
            $Item = Get-Item -LiteralPath $Candidate -Force
            if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Keeper lifecycle path contains a reparse point"
            }
        }
        $Parent = Split-Path -Parent $Candidate
        if (-not $Parent -or $Parent -eq $Candidate) { break }
        $Candidate = $Parent
    }
}

function Test-Package([string]$Root, [string]$ExpectedHash = "") {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "Package directory is unavailable: $Root"
    }
    $ManifestPath = Join-Path $Root "keeper-package-manifest.json"
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Package manifest is unavailable"
    }
    $ManifestHash = Get-Sha256Hex $ManifestPath
    if ($ExpectedHash) {
        if ($ExpectedHash -notmatch '^[A-Fa-f0-9]{64}$') {
            throw "Expected manifest SHA-256 is malformed"
        }
        if (-not $ManifestHash.Equals($ExpectedHash, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Package manifest identity does not match the approved SHA-256"
        }
    }
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    if ($Manifest.product -ne "Keeper") { throw "Package identity is not Keeper" }
    if ($Manifest.composition -ne "PRODUCTION_CAPABLE_LOCAL_CLIENT") {
        throw "Package composition is not the supported Keeper desktop client"
    }
    if (-not ([string]$Manifest.version).Trim()) { throw "Package version is missing" }
    $Listed = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($Item in $Manifest.files) {
        $Relative = ([string]$Item.path).Replace('\', '/')
        if (-not $Listed.Add($Relative)) { throw "Duplicate manifest path: $Relative" }
        if ([IO.Path]::IsPathRooted($Relative) -or $Relative -match '(^|/)\.\.(/|$)') {
            throw "Package manifest contains an escaping path"
        }
        if ($Relative -match '(?i)(^|/)\.ai-workflow(/|$)|pilot-invocations') {
            throw "Package manifest contains protected workflow content"
        }
        $File = [IO.Path]::GetFullPath((Join-Path $Root $Relative))
        $Prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
        if (-not $File.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Package file escaped its root"
        }
        if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
            throw "Package file is missing: $Relative"
        }
        if ((Get-Item -LiteralPath $File).Length -ne [long]$Item.size) {
            throw "Package size mismatch: $Relative"
        }
        if ((Get-Sha256Hex $File) -ne $Item.sha256) {
            throw "Package hash mismatch: $Relative"
        }
    }
    if (-not $Listed.Contains("Keeper.exe")) {
        throw "Package manifest does not contain the required Keeper.exe"
    }
    $Actual = @(Get-ChildItem -LiteralPath $Root -Recurse -File | ForEach-Object {
        $_.FullName.Substring([IO.Path]::GetFullPath($Root).TrimEnd('\').Length + 1).Replace('\', '/')
    } | Where-Object { $_ -ne "keeper-package-manifest.json" })
    if ($Actual.Count -ne $Listed.Count) {
        throw "Package contains unmanifested or missing files"
    }
    foreach ($Relative in $Actual) {
        if (-not $Listed.Contains($Relative)) {
            throw "Package contains an unmanifested file: $Relative"
        }
    }
    return [ordered]@{ Manifest = $Manifest; ManifestSha256 = $ManifestHash }
}
function New-RollbackJournal(
    [string]$Swap,
    [string]$CurrentManifestSha256,
    [string]$RollbackManifestSha256
) {
    $Record = [ordered]@{
        schema_version = 1
        operation = "Rollback"
        swap = [IO.Path]::GetFullPath($Swap)
        current_manifest_sha256 = $CurrentManifestSha256
        rollback_manifest_sha256 = $RollbackManifestSha256
    }
    $Temporary = $RollbackJournal + "." + [Guid]::NewGuid().ToString("N") + ".tmp"
    try {
        [IO.File]::WriteAllText(
            $Temporary,
            ($Record | ConvertTo-Json -Depth 3),
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $Temporary -Destination $RollbackJournal
    }
    finally {
        if (Test-Path -LiteralPath $Temporary) {
            Remove-Item -LiteralPath $Temporary -Force
        }
    }
}

function New-InstallJournal(
    [string]$Mode,
    [string]$Stage,
    [string]$NewManifestSha256,
    [string]$CurrentManifestSha256
) {
    $Record = [ordered]@{
        schema_version = 1
        operation = $Mode
        stage = [IO.Path]::GetFullPath($Stage)
        new_manifest_sha256 = $NewManifestSha256
        current_manifest_sha256 = if ($CurrentManifestSha256) { $CurrentManifestSha256 } else { $null }
    }
    $Temporary = $InstallJournal + "." + [Guid]::NewGuid().ToString("N") + ".tmp"
    try {
        [IO.File]::WriteAllText(
            $Temporary,
            ($Record | ConvertTo-Json -Depth 3),
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $Temporary -Destination $InstallJournal
    }
    finally {
        if (Test-Path -LiteralPath $Temporary) {
            Remove-Item -LiteralPath $Temporary -Force
        }
    }
}

function Recover-InterruptedInstall {
    if (-not (Test-Path -LiteralPath $InstallJournal -PathType Leaf)) { return }
    $Record = Get-Content -LiteralPath $InstallJournal -Raw | ConvertFrom-Json
    if ($Record.schema_version -ne 1 -or
        [string]$Record.operation -notin @("Install", "Repair", "Upgrade")) {
        throw "Keeper install transaction journal is invalid"
    }
    $NewHash = [string]$Record.new_manifest_sha256
    $OldHash = [string]$Record.current_manifest_sha256
    if ($NewHash -notmatch '^[A-Fa-f0-9]{64}$' -or
        ($OldHash -and $OldHash -notmatch '^[A-Fa-f0-9]{64}$')) {
        throw "Keeper install transaction hash is invalid"
    }
    $Stage = [IO.Path]::GetFullPath([string]$Record.stage)
    $ExpectedPrefix = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\') + '\.stage-'
    if (-not $Stage.StartsWith($ExpectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Keeper install transaction stage path is invalid"
    }
    Assert-NoReparsePath $Stage
    Assert-DisjointPathTrees $Stage $DataDirectory "Keeper stage and data paths"
    $HasCurrent = Test-Path -LiteralPath $Current -PathType Container
    $HasRollback = Test-Path -LiteralPath $Rollback -PathType Container
    $HasStage = Test-Path -LiteralPath $Stage -PathType Container
    if ($HasCurrent) {
        $CurrentHash = Get-Sha256Hex (Join-Path $Current "keeper-package-manifest.json")
        if ($CurrentHash -eq $NewHash) {
            Test-Package $Current $NewHash | Out-Null
            if ($HasStage) {
                Test-Package $Stage $NewHash | Out-Null
                Remove-Item -LiteralPath $Stage -Recurse -Force
            }
        }
        elseif ($OldHash -and $CurrentHash -eq $OldHash -and $HasStage) {
            Test-Package $Current $OldHash | Out-Null
            Test-Package $Stage $NewHash | Out-Null
            if ($HasRollback) { Remove-Item -LiteralPath $Rollback -Recurse -Force }
            Move-Item -LiteralPath $Current -Destination $Rollback
            Move-Item -LiteralPath $Stage -Destination $Current
        }
        else {
            throw "Keeper install transaction current generation is ambiguous"
        }
    }
    elseif ($HasStage -and (($OldHash -and $HasRollback) -or (-not $OldHash -and -not $HasRollback))) {
        Test-Package $Stage $NewHash | Out-Null
        if ($OldHash) { Test-Package $Rollback $OldHash | Out-Null }
        Move-Item -LiteralPath $Stage -Destination $Current
    }
    else {
        throw "Keeper install transaction state is ambiguous and was preserved"
    }
    Remove-Item -LiteralPath $InstallJournal -Force
}

function Recover-InterruptedRollback {
    if (-not (Test-Path -LiteralPath $RollbackJournal -PathType Leaf)) { return }
    $Record = Get-Content -LiteralPath $RollbackJournal -Raw | ConvertFrom-Json
    if ($Record.schema_version -ne 1 -or $Record.operation -ne "Rollback") {
        throw "Keeper rollback transaction journal is invalid"
    }
    foreach ($Hash in @(
        [string]$Record.current_manifest_sha256,
        [string]$Record.rollback_manifest_sha256
    )) {
        if ($Hash -notmatch '^[A-Fa-f0-9]{64}$') {
            throw "Keeper rollback transaction hash is invalid"
        }
    }
    $Swap = [IO.Path]::GetFullPath([string]$Record.swap)
    $ExpectedPrefix = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\') + '\.swap-'
    if (-not $Swap.StartsWith($ExpectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Keeper rollback transaction swap path is invalid"
    }
    Assert-NoReparsePath $Swap
    Assert-DisjointPathTrees $Swap $DataDirectory "Keeper swap and data paths"
    $HasCurrent = Test-Path -LiteralPath $Current -PathType Container
    $HasRollback = Test-Path -LiteralPath $Rollback -PathType Container
    $HasSwap = Test-Path -LiteralPath $Swap -PathType Container
    if (-not $HasCurrent -and $HasRollback -and $HasSwap) {
        Test-Package $Rollback ([string]$Record.rollback_manifest_sha256) | Out-Null
        Test-Package $Swap ([string]$Record.current_manifest_sha256) | Out-Null
        Move-Item -LiteralPath $Swap -Destination $Current
    }
    elseif ($HasCurrent -and -not $HasRollback -and $HasSwap) {
        Test-Package $Current ([string]$Record.rollback_manifest_sha256) | Out-Null
        Test-Package $Swap ([string]$Record.current_manifest_sha256) | Out-Null
        Move-Item -LiteralPath $Swap -Destination $Rollback
    }
    elseif ($HasCurrent -and $HasRollback -and -not $HasSwap) {
        $CurrentManifest = Join-Path $Current "keeper-package-manifest.json"
        $RollbackManifest = Join-Path $Rollback "keeper-package-manifest.json"
        if (-not (Test-Path -LiteralPath $CurrentManifest -PathType Leaf) -or
            -not (Test-Path -LiteralPath $RollbackManifest -PathType Leaf)) {
            throw "Keeper rollback transaction generation is incomplete"
        }
        $CurrentHash = Get-Sha256Hex $CurrentManifest
        $RollbackHash = Get-Sha256Hex $RollbackManifest
        $BeforeMove =
            $CurrentHash -eq [string]$Record.current_manifest_sha256 -and
            $RollbackHash -eq [string]$Record.rollback_manifest_sha256
        $AfterMove =
            $CurrentHash -eq [string]$Record.rollback_manifest_sha256 -and
            $RollbackHash -eq [string]$Record.current_manifest_sha256
        if (-not $BeforeMove -and -not $AfterMove) {
            throw "Keeper rollback transaction generations do not match the durable journal"
        }
        Test-Package $Current $CurrentHash | Out-Null
        Test-Package $Rollback $RollbackHash | Out-Null
    }
    else {
        throw "Keeper rollback transaction state is ambiguous and was preserved"
    }
    Remove-Item -LiteralPath $RollbackJournal -Force
}
function Set-KeeperShortcuts([string]$Executable) {
    if ($SkipShortcuts) { return }
    $Shell = New-Object -ComObject WScript.Shell
    $Desktop = [Environment]::GetFolderPath("Desktop")
    $Programs = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs"
    foreach ($ShortcutPath in @(
        (Join-Path $Desktop "Keeper.lnk"),
        (Join-Path $Programs "Keeper.lnk")
    )) {
        $Shortcut = $Shell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = $Executable
        $Shortcut.WorkingDirectory = Split-Path -Parent $Executable
        $Shortcut.IconLocation = "$Executable,0"
        $Shortcut.Description = "Keeper Executive Control Center"
        $Shortcut.Save()
    }
}

function Remove-KeeperShortcuts {
    if ($SkipShortcuts) { return }
    $Paths = @(
        (Join-Path ([Environment]::GetFolderPath("Desktop")) "Keeper.lnk"),
        (Join-Path (Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs") "Keeper.lnk")
    )
    foreach ($PathValue in $Paths) {
        if (Test-Path -LiteralPath $PathValue -PathType Leaf) {
            Remove-Item -LiteralPath $PathValue -Force
        }
    }
}

function Install-Package([string]$Mode) {
    if (-not $PackageDirectory) { throw "$Mode requires -PackageDirectory" }
    if (-not $ExpectedManifestSha256) {
        throw "$Mode requires -ExpectedManifestSha256 from the approved release"
    }
    $PackageRoot = [IO.Path]::GetFullPath($PackageDirectory)
    Assert-NoReparsePath $PackageRoot
    Assert-DisjointPathTrees $PackageRoot $InstallRoot "Keeper package and install paths"
    $PackageCheck = Test-Package $PackageRoot $ExpectedManifestSha256
    $Manifest = $PackageCheck.Manifest
    Assert-SafeRoot $InstallRoot
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
    Assert-NoReparsePath $InstallRoot
    Assert-NoReparsePath $DataDirectory
    $Stage = Join-Path $InstallRoot (".stage-" + [Guid]::NewGuid().ToString("N"))
    Copy-Item -LiteralPath $PackageRoot -Destination $Stage -Recurse
    try {
        Test-Package $Stage $ExpectedManifestSha256 | Out-Null
        $CurrentHash = ""
        if (Test-Path -LiteralPath $Current -PathType Container) {
            $CurrentManifest = Join-Path $Current "keeper-package-manifest.json"
            if (-not (Test-Path -LiteralPath $CurrentManifest -PathType Leaf)) {
                throw "Current Keeper generation has no package manifest"
            }
            $CurrentHash = Get-Sha256Hex $CurrentManifest
            Test-Package $Current $CurrentHash | Out-Null
        }
        New-InstallJournal $Mode $Stage $ExpectedManifestSha256 $CurrentHash
        if (Test-Path -LiteralPath $Rollback) {
            Assert-SafeRoot $Rollback
            Assert-NoReparsePath $Rollback
            Remove-Item -LiteralPath $Rollback -Recurse -Force
        }
        if (Test-Path -LiteralPath $Current) {
            Assert-NoReparsePath $Current
            Move-Item -LiteralPath $Current -Destination $Rollback
        }
        Assert-NoReparsePath $Stage
        Move-Item -LiteralPath $Stage -Destination $Current
        Remove-Item -LiteralPath $InstallJournal -Force
    }
    catch {
        $Failure = $_
        if (Test-Path -LiteralPath $InstallJournal -PathType Leaf) {
            try { Recover-InterruptedInstall }
            catch { throw "Keeper $Mode failed and conservative install recovery could not reconcile the preserved generations: $($_.Exception.Message)" }
            throw $Failure
        }
        if (Test-Path -LiteralPath $Stage) {
            Assert-SafeRoot $Stage
            Remove-Item -LiteralPath $Stage -Recurse -Force
        }
        if (-not (Test-Path -LiteralPath $Current) -and (Test-Path -LiteralPath $Rollback)) {
            Move-Item -LiteralPath $Rollback -Destination $Current
        }
        throw
    }
    $Executable = Join-Path $Current "Keeper.exe"
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        $Executable = (Get-ChildItem -LiteralPath $Current -Recurse -Filter "Keeper.exe" | Select-Object -First 1).FullName
    }
    if (-not $Executable) { throw "Installed Keeper executable is missing" }
    Set-KeeperShortcuts $Executable
    [ordered]@{
        action = $Mode
        version = $Manifest.version
        manifest_sha256 = $PackageCheck.ManifestSha256
        executable = $Executable
        data_directory = $DataDirectory
        rollback_available = (Test-Path -LiteralPath $Rollback)
    }
}

Assert-SafeRoot $InstallRoot
Assert-SafeRoot $DataDirectory
Assert-DisjointPathTrees $InstallRoot $DataDirectory "Keeper install and data roots"
Assert-NoReparsePath $InstallRoot
Assert-NoReparsePath $DataDirectory
Assert-NoReparsePath $Current
Assert-NoReparsePath $Rollback
Recover-InterruptedInstall
Recover-InterruptedRollback
$Result = switch ($Action) {
    "Install" { Install-Package "Install" }
    "Repair" { Install-Package "Repair" }
    "Upgrade" { Install-Package "Upgrade" }
    "Rollback" {
        if (-not (Test-Path -LiteralPath $Rollback -PathType Container)) {
            throw "No rollback generation is available"
        }
        if (-not $ExpectedManifestSha256) {
            throw "Rollback requires the approved rollback -ExpectedManifestSha256"
        }
        $RollbackCheck = Test-Package $Rollback $ExpectedManifestSha256
        $CurrentManifest = Join-Path $Current "keeper-package-manifest.json"
        if (-not (Test-Path -LiteralPath $CurrentManifest -PathType Leaf)) {
            throw "Current Keeper generation has no package manifest"
        }
        $CurrentHash = Get-Sha256Hex $CurrentManifest
        Test-Package $Current $CurrentHash | Out-Null
        $Swap = Join-Path $InstallRoot (".swap-" + [Guid]::NewGuid().ToString("N"))
        New-RollbackJournal $Swap $CurrentHash $RollbackCheck.ManifestSha256
        try {
            Move-Item -LiteralPath $Current -Destination $Swap
            Move-Item -LiteralPath $Rollback -Destination $Current
            Move-Item -LiteralPath $Swap -Destination $Rollback
            Remove-Item -LiteralPath $RollbackJournal -Force
        }
        catch {
            $Failure = $_
            try { Recover-InterruptedRollback }
            catch { throw "Rollback failed and conservative recovery could not reconcile the preserved generations: $($_.Exception.Message)" }
            throw $Failure
        }
        $Executable = (Get-ChildItem -LiteralPath $Current -Recurse -Filter "Keeper.exe" | Select-Object -First 1).FullName
        Set-KeeperShortcuts $Executable
        [ordered]@{ action = "Rollback"; version = $RollbackCheck.Manifest.version; manifest_sha256 = $RollbackCheck.ManifestSha256; executable = $Executable; data_directory = $DataDirectory }
    }
    "Uninstall" {
        Remove-KeeperShortcuts
        foreach ($Target in @($Current, $Rollback)) {
            if (Test-Path -LiteralPath $Target) {
                Assert-SafeRoot $Target
                Assert-NoReparsePath $Target
                Remove-Item -LiteralPath $Target -Recurse -Force
            }
        }
        [ordered]@{ action = "Uninstall"; data_preserved = (Test-Path -LiteralPath $DataDirectory); data_directory = $DataDirectory }
    }
    "Status" {
        $CurrentManifest = Join-Path $Current "keeper-package-manifest.json"
        $RollbackManifest = Join-Path $Rollback "keeper-package-manifest.json"
        $HasCurrent = Test-Path -LiteralPath $Current -PathType Container
        $HasRollback = Test-Path -LiteralPath $Rollback -PathType Container
        if ($HasCurrent -and -not (Test-Path -LiteralPath $CurrentManifest -PathType Leaf)) {
            throw "Current Keeper generation has no package manifest"
        }
        if ($HasRollback -and -not (Test-Path -LiteralPath $RollbackManifest -PathType Leaf)) {
            throw "Rollback Keeper generation has no package manifest"
        }
        $Executable = if ($HasCurrent) {
            Get-ChildItem -LiteralPath $Current -Recurse -Filter "Keeper.exe" -ErrorAction Stop | Select-Object -First 1
        } else { $null }
        $CurrentCheck = if (Test-Path -LiteralPath $CurrentManifest) {
            $Hash = Get-Sha256Hex $CurrentManifest
            Test-Package $Current $Hash
        } else { $null }
        $RollbackCheck = if (Test-Path -LiteralPath $RollbackManifest) {
            $Hash = Get-Sha256Hex $RollbackManifest
            Test-Package $Rollback $Hash
        } else { $null }
        [ordered]@{
            installed = [bool]($Executable -and $CurrentCheck)
            executable = if ($Executable) { $Executable.FullName } else { $null }
            current_manifest_sha256 = if ($CurrentCheck) { $CurrentCheck.ManifestSha256 } else { $null }
            rollback_available = [bool]$RollbackCheck
            rollback_manifest_sha256 = if ($RollbackCheck) { $RollbackCheck.ManifestSha256 } else { $null }
            data_directory = $DataDirectory
        }
    }
}
$Result | ConvertTo-Json -Depth 5
