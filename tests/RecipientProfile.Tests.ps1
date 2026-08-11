[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/EvidenceWorkspace.ps1')
. (Join-Path $repositoryRoot 'src/RecipientSharing.ps1')
. (Join-Path $repositoryRoot 'src/ProtectedPackage.ps1')

$testRoot = Join-Path $repositoryRoot ".test-output/recipient-profile-$([guid]::NewGuid().ToString('N'))"
$null = [System.IO.Directory]::CreateDirectory($testRoot)
try {
    foreach ($case in @(
        @{ Name = 'platform'; Level = 'UserAndDeviceBound' },
        @{ Name = 'software'; Level = 'WindowsUserBound' }
    )) {
        $profilePath = Join-Path $testRoot "$($case.Name).recipient.json"
        $setup = New-RecipientProfileSetup -Label 'Synthetic consulting recipient' `
            -OutputPath $profilePath -ConfirmSetup `
            -SyntheticProtectionLevel $case.Level
        Assert-Equal 'Created' $setup.state 'confirmed setup creates one Recipient Profile'
        Assert-Equal $true $setup.syntheticRoundTripVerified `
            'setup proves RSA-OAEP-SHA-256 with a synthetic content key'
        Assert-Equal $case.Level $setup.protectionLevel `
            'the actual protection boundary is labeled without overclaiming hardware'
        Assert-Equal $true (Test-Path -LiteralPath $profilePath -PathType Leaf) `
            'setup writes the non-secret portable profile'

        $profileJson = Get-Content -LiteralPath $profilePath -Raw
        Assert-Equal $true (Test-Json -Json $profileJson -SchemaFile (
            Join-Path $repositoryRoot 'schemas/recipient-profile.schema.json'
        )) 'the exported profile satisfies its closed schema'
        if ($profileJson -match '(?i)privateKey|pfx|password|credential|recoveryPhrase') {
            throw 'A Recipient Profile exposed prohibited private or recovery material.'
        }
        $profile = $profileJson | ConvertFrom-Json -Depth 10
        Assert-Equal 3072 $profile.rsaKeyBits 'setup defaults to RSA 3072'
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            [System.Convert]::FromBase64String([string] $profile.certificateDerBase64)
        )
        try { Assert-Equal $false $certificate.HasPrivateKey 'the profile exports only the public certificate' }
        finally { $certificate.Dispose() }

        $admission = Import-RecipientProfile -LiteralPath $profilePath `
            -ExpectedFingerprint $profile.fingerprint -ForNewPackage
        try {
            Assert-Equal 'Approved' $admission.state `
                'a valid profile with an out-of-band fingerprint match is admitted'
            Assert-Equal 'RECIPIENT.PROFILE_APPROVED' $admission.reasonCode `
                'profile admission has a stable reason'
        }
        finally { if ($null -ne $admission.certificate) { $admission.certificate.Dispose() } }

        $wrong = Import-RecipientProfile -LiteralPath $profilePath `
            -ExpectedFingerprint ('0' * 64) -ForNewPackage
        Assert-Equal 'Rejected' $wrong.state 'a wrong confirmed fingerprint fails closed'
        Assert-Equal 'RECIPIENT.FINGERPRINT_MISMATCH' $wrong.reasonCode `
            'the operator receives the specific fingerprint remediation reason'
    }

    $expiredPath = Join-Path $testRoot 'expired.recipient.json'
    $expiredSetup = New-RecipientProfileSetup -Label 'Synthetic expired recipient' `
        -OutputPath $expiredPath -ConfirmSetup -SyntheticProtectionLevel WindowsUserBound `
        -SyntheticValidity NotCurrentlyValid
    $expiredProfile = Get-Content -LiteralPath $expiredPath -Raw | ConvertFrom-Json -Depth 10
    $expired = Import-RecipientProfile -LiteralPath $expiredPath `
        -ExpectedFingerprint $expiredProfile.fingerprint -ForNewPackage
    Assert-Equal 'Rejected' $expired.state 'an expired certificate cannot enter a new package plan'
    Assert-Equal 'RECIPIENT.CERTIFICATE_NOT_CURRENT' $expired.reasonCode `
        'new-package validity failure has a stable reason'

    $minimumPath = Join-Path $testRoot 'minimum.recipient.json'
    $minimumSetup = New-RecipientProfileSetup -Label 'Synthetic minimum RSA recipient' `
        -OutputPath $minimumPath -ConfirmSetup -KeyBits 2048 `
        -SyntheticProtectionLevel WindowsUserBound
    Assert-Equal 'Created' $minimumSetup.state 'RSA 2048 is the admitted minimum'
    $minimumProfile = Get-Content -LiteralPath $minimumPath -Raw | ConvertFrom-Json -Depth 10
    Assert-Equal 2048 $minimumProfile.rsaKeyBits 'the minimum profile records its actual key size'
    $minimumAdmission = Import-RecipientProfile -LiteralPath $minimumPath `
        -ExpectedFingerprint $minimumProfile.fingerprint -ForNewPackage
    try { Assert-Equal 'Approved' $minimumAdmission.state 'RSA 2048 remains interoperable' }
    finally {
        if ($null -ne $minimumAdmission.certificate) { $minimumAdmission.certificate.Dispose() }
    }
    $belowMinimumPath = Join-Path $testRoot 'below-minimum.recipient.json'
    $belowMinimum = New-RecipientProfileSetup -Label 'Synthetic rejected RSA recipient' `
        -OutputPath $belowMinimumPath -ConfirmSetup -KeyBits 1024 `
        -SyntheticProtectionLevel WindowsUserBound
    Assert-Equal 'NotStarted' $belowMinimum.state 'RSA below 2048 is rejected before key creation'
    Assert-Equal $false ([System.IO.File]::Exists($belowMinimumPath)) `
        'rejected key size creates no profile'
}
finally {
    if ([System.IO.Directory]::Exists($testRoot)) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}

Assert-Equal $false ([System.IO.Directory]::Exists($testRoot)) `
    'synthetic profiles and certificates leave no test residue'
Write-Output 'PASS: Recipient Profile setup and admission preserve the certificate trust boundaries.'
