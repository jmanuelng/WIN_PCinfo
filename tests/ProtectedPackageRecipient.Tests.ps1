[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ContractValidator.ps1')
. (Join-Path $repositoryRoot 'src/EvidenceWorkspace.ps1')
. (Join-Path $repositoryRoot 'src/RecipientSharing.ps1')
. (Join-Path $repositoryRoot 'src/ProtectedPackage.ps1')

$testRoot = Join-Path $repositoryRoot ".test-output/package-recipient-$([guid]::NewGuid().ToString('N'))"
$null = [System.IO.Directory]::CreateDirectory($testRoot)
$recipient = $null
$unrelated = $null
$recordBytes = $null
$reportBytes = $null
try {
    [byte[]] $recordBytes = [System.IO.File]::ReadAllBytes(
        (Join-Path $PSScriptRoot 'fixtures/contract-positive.json')
    )
    [byte[]] $reportBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        '<!doctype html><title>Synthetic recipient package</title>'
    )
    $artifacts = [ordered]@{
        'assessment-record.json' = $recordBytes
        'assessment-report.html' = $reportBytes
    }

    $localOnly = New-ProtectedEvidencePackage -DestinationDirectory $testRoot `
        -Artifacts $artifacts -AssessmentContractSetVersion '1.0.0' -Completeness Complete
    Assert-Equal $true $localOnly.verified 'zero-recipient packaging remains supported'
    $localHeader = Get-ProtectedPackageEnvelopeHeader $localOnly.packagePath
    Assert-Equal 'None' $localHeader.recipientKeyProtection `
        'a zero-recipient package declares no recipient key wrap'
    if ($null -ne $localHeader.recipientWrappedContentKey) {
        throw 'Zero-recipient packaging carried recipient ciphertext.'
    }
    Assert-Equal $true (Read-ProtectedEvidencePackage $localOnly.packagePath).verified `
        'the Local Package Protector retains access'

    $recipient = New-SyntheticRecipientCertificate -KeyBits 3072 -Validity NotCurrentlyValid
    $recipient.protectionLevel = 'WindowsUserBound'
    $publicRecipient = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $recipient.certificate.RawData
    )
    try {
        $recipientPackage = New-ProtectedEvidencePackage -DestinationDirectory $testRoot `
            -Artifacts $artifacts -AssessmentContractSetVersion '1.0.0' -Completeness Complete `
            -RecipientCertificate $publicRecipient -SyntheticAdmissionTime (
                [System.DateTimeOffset] $publicRecipient.NotAfter
            ).AddHours(-1)
    }
    finally { $publicRecipient.Dispose() }
    Assert-Equal $true $recipientPackage.verified 'one approved recipient is wrapped into the package'
    $header = Get-ProtectedPackageEnvelopeHeader $recipientPackage.packagePath
    Assert-Equal 'RSA-OAEP-SHA-256' $header.recipientKeyProtection `
        'recipient wrapping uses the fixed algorithm'
    Assert-Equal 512 $header.recipientWrappedContentKey.Length `
        'a 3072-bit OAEP ciphertext is present as 384 base64-encoded bytes'
    $serializedHeader = $header | ConvertTo-Json -Compress -Depth 10
    if ($serializedHeader -match '(?i)fingerprint|thumbprint|certificate|recipientLabel|subject|issuer') {
        throw 'The package envelope exposed stable recipient or certificate identity.'
    }
    Assert-Equal $true (Read-ProtectedEvidencePackage $recipientPackage.packagePath).verified `
        'local DPAPI access remains available when a recipient is present'

    # The certificate is intentionally expired at the current clock. Historical
    # opening must use the matching usable private key, not current validity.
    $historical = Read-ProtectedEvidencePackage $recipientPackage.packagePath `
        -RecipientCertificate $recipient.certificate
    Assert-Equal 'Verified' $historical.state `
        'the matching provider-held key opens a historical package after expiry'
    Assert-Equal $true $historical.verified 'recipient historical opening validates the full package'

    $unrelated = New-SyntheticRecipientCertificate -KeyBits 3072 -Validity CurrentlyValid
    $missing = Read-ProtectedEvidencePackage $recipientPackage.packagePath `
        -RecipientCertificate $unrelated.certificate
    Assert-Equal 'ProtectionUnavailable' $missing.state `
        'an unrelated private key cannot be substituted for the approved recipient'
    Assert-Equal $false $missing.verified 'missing matching key exposes no content'
    if ($null -ne $missing.artifacts) {
        throw 'Failed recipient opening returned plaintext artifacts.'
    }
}
finally {
    if ($null -ne $recipient) { $recipient.certificate.Dispose() }
    if ($null -ne $unrelated) { $unrelated.certificate.Dispose() }
    if ($null -ne $recordBytes) {
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($recordBytes)
    }
    if ($null -ne $reportBytes) {
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($reportBytes)
    }
    if ([System.IO.Directory]::Exists($testRoot)) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}

Assert-Equal $false ([System.IO.Directory]::Exists($testRoot)) `
    'recipient package validation leaves no certificate or file residue'
Write-Output 'PASS: one optional recipient and local DPAPI access coexist without envelope identity leakage.'
