param(
    [Parameter(Mandatory = $true)] [string]$ArtifactPath,
    [Parameter(Mandatory = $true)] [string]$ExpectedSha256,
    [Parameter(Mandatory = $true)] [string]$ReportPath
)

$ErrorActionPreference = "Stop"
$Artifact = (Resolve-Path -LiteralPath $ArtifactPath).Path
$ReportPath = [IO.Path]::GetFullPath($ReportPath)
if ($ExpectedSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
    throw "expected Provider Host SHA-256 is malformed"
}
$Before = (Get-FileHash -LiteralPath $Artifact -Algorithm SHA256).Hash
if (-not $Before.Equals($ExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Provider Host SHA-256 differs before Defender scan"
}
foreach ($Command in @("Get-MpComputerStatus", "Start-MpScan", "Get-MpThreatDetection")) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "Microsoft Defender verification command is unavailable"
    }
}
$Status = Get-MpComputerStatus
if (-not $Status.AntivirusEnabled -or -not $Status.RealTimeProtectionEnabled) {
    throw "Microsoft Defender protection is not enabled"
}
$Started = [DateTimeOffset]::Now
$Failure = $null
try {
    Start-MpScan -ScanType CustomScan -ScanPath $Artifact
    if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf)) {
        throw "Microsoft Defender removed or quarantined the Provider Host artifact"
    }
    $After = (Get-FileHash -LiteralPath $Artifact -Algorithm SHA256).Hash
    if (-not $After.Equals($Before, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Provider Host artifact changed during Defender verification"
    }
    $ArtifactNeedle = $Artifact.ToLowerInvariant()
    $Detections = @(Get-MpThreatDetection | Where-Object {
        $DetectionTime = $_.InitialDetectionTime
        $Resources = @($_.Resources | ForEach-Object { $_.ToString().ToLowerInvariant() })
        $DetectionTime -ge $Started.LocalDateTime.AddSeconds(-2) -and
        ($Resources | Where-Object { $_ -like "*$ArtifactNeedle*" })
    })
    if ($Detections.Count -ne 0) {
        throw "Microsoft Defender detected the Provider Host artifact"
    }
}
catch {
    $Failure = $_.Exception.Message
}
$Completed = [DateTimeOffset]::Now
$Report = [ordered]@{
    schema_version = 1
    product = "KeeperProviderHost"
    artifact_sha256 = $Before.ToUpperInvariant()
    artifact_size = (Get-Item -LiteralPath $Artifact -ErrorAction SilentlyContinue).Length
    defender = [ordered]@{
        antivirus_enabled = [bool]$Status.AntivirusEnabled
        realtime_enabled = [bool]$Status.RealTimeProtectionEnabled
        engine_version = [string]$Status.AMEngineVersion
        antivirus_signature_version = [string]$Status.AntivirusSignatureVersion
        scan_started_at = $Started.ToString("O")
        scan_completed_at = $Completed.ToString("O")
        result = if ($Failure) { "FAIL" } else { "PASS" }
        failure = $Failure
    }
} | ConvertTo-Json -Depth 5
$Parent = Split-Path -Parent $ReportPath
if ($Parent) { New-Item -ItemType Directory -Path $Parent -Force | Out-Null }
[IO.File]::WriteAllText(
    $ReportPath,
    $Report + [Environment]::NewLine,
    (New-Object Text.UTF8Encoding($false))
)
if ($Failure) { throw $Failure }
Write-Output $Report
