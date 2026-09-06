param(
    [Parameter(Mandatory = $true)][string[]]$Path,
    [string]$CertificateThumbprint = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$SignToolPath = ""
)

$ErrorActionPreference = "Stop"
if (-not $CertificateThumbprint) {
    throw "A trusted Authenticode certificate thumbprint is required"
}
$Certificate = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert |
    Where-Object Thumbprint -EQ $CertificateThumbprint |
    Select-Object -First 1
if (-not $Certificate -or -not $Certificate.HasPrivateKey) {
    throw "The requested code-signing certificate with a private key is unavailable"
}
$Chain = New-Object Security.Cryptography.X509Certificates.X509Chain
if (-not $Chain.Build($Certificate)) {
    throw "The code-signing certificate does not build to a trusted root"
}
if (-not $SignToolPath) {
    $SignToolPath = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
        -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object FullName -Match '\\x64\\signtool\.exe$' |
        Sort-Object FullName -Descending |
        Select-Object -ExpandProperty FullName -First 1
}
if (-not $SignToolPath -or -not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
    throw "Windows SDK signtool.exe is unavailable"
}

$Results = foreach ($Item in $Path) {
    $Resolved = (Resolve-Path -LiteralPath $Item).Path
    & $SignToolPath sign /sha1 $Certificate.Thumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $Resolved
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed: $Resolved" }
    & $SignToolPath verify /pa /all /v $Resolved | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed: $Resolved" }
    $Signature = Get-AuthenticodeSignature -LiteralPath $Resolved
    if ($Signature.Status -ne "Valid" -or $Signature.SignerCertificate.Thumbprint -ne $Certificate.Thumbprint) {
        throw "Signed artifact identity differs: $Resolved"
    }
    [ordered]@{
        path = $Resolved
        sha256 = (Get-FileHash -LiteralPath $Resolved -Algorithm SHA256).Hash
        signer_thumbprint = $Signature.SignerCertificate.Thumbprint
        signer_subject = $Signature.SignerCertificate.Subject
        signature_status = [string]$Signature.Status
    }
}
$Results | ConvertTo-Json -Depth 4
