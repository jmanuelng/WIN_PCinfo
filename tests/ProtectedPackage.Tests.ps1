[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ContractValidator.ps1')
. (Join-Path $repositoryRoot 'src/EvidenceWorkspace.ps1')
. (Join-Path $repositoryRoot 'src/ProtectedPackage.ps1')

$knownAnswer = Test-ProtectedPackageKnownAnswer
Assert-Equal $true $knownAnswer.verified `
    'the AES-256-GCM implementation matches the fixed independent known-answer vector'
Assert-Equal 'cea7403d4d606b6e074ec5d3baf39d18' $knownAnswer.ciphertextHex `
    'the ciphertext matches the published zero-key vector'
Assert-Equal 'd0d1c8a799996bf0265b98b5d48ab919' $knownAnswer.tagHex `
    'the full 128-bit authentication tag matches the published vector'

$testRoot = Join-Path $repositoryRoot ".test-output/protected-package-$([guid]::NewGuid().ToString('N'))"
$null = [System.IO.Directory]::CreateDirectory($testRoot)
try {
    [byte[]] $recordBytes = [System.IO.File]::ReadAllBytes(
        (Join-Path $PSScriptRoot 'fixtures/contract-positive.json')
    )
    [byte[]] $reportBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        '<!doctype html><title>synthetic-private-report-marker</title>'
    )
    $artifacts = [ordered]@{
        'assessment-record.json' = $recordBytes
        'assessment-report.html' = $reportBytes
    }

    $first = New-ProtectedEvidencePackage -DestinationDirectory $testRoot `
        -Artifacts $artifacts `
        -AssessmentContractSetVersion '1.0.0' -Completeness 'Complete'
    Assert-Equal $true $first.verified 'a fully reopened package is verified before it is reported'
    Assert-Equal 'Verified' $first.state 'successful finalization has the lifecycle package state'
    Assert-Equal $true ([System.IO.File]::Exists($first.packagePath)) `
        'only the final package name exists after reopen validation'
    Assert-Equal $true ([System.IO.Path]::GetFileName($first.packagePath) -match `
        '^package-[0-9a-f]{32}\.winpcinfo$') `
        'the externally visible name is an opaque product-generated identifier'
    Assert-Equal $false ((Get-Command New-ProtectedEvidencePackage).Parameters.ContainsKey(
        'PackageName'
    )) 'a caller cannot place identity-bearing text in the package filename'
    Assert-Equal $false ([System.IO.File]::Exists("$($first.packagePath).partial")) `
        'no provisional ciphertext survives successful finalization'

    $persistedText = [System.Text.Encoding]::Latin1.GetString(
        [System.IO.File]::ReadAllBytes($first.packagePath)
    )
    if ($persistedText -match 'synthetic-private-report-marker|assessment-record|subject:synthetic') {
        throw 'The persistent envelope exposed plaintext assessment or report content.'
    }

    $opened = Read-ProtectedEvidencePackage -LiteralPath $first.packagePath
    Assert-Equal $true $opened.verified 'the local DPAPI protector can reopen the final package'
    Assert-Equal 'Complete' $opened.manifest.completeness `
        'the manifest preserves the exact completeness state'
    Assert-Equal 'EncryptedAuthenticated' $opened.manifest.protection.state `
        'the manifest records its protection state'
    Assert-Equal $false $opened.manifest.protection.authorshipClaim `
        'authenticated encryption is not misrepresented as authorship'
    Assert-Equal $false $opened.manifest.protection.durableTamperEvidenceClaim `
        'authenticated encryption is not misrepresented as durable tamper evidence'
    Assert-Equal 2 @($opened.manifest.contents).Count `
        'the manifest inventories every exact assessment artifact'
    Assert-Equal (Get-ProtectedPackageSha256 -Bytes $recordBytes) `
        ($opened.manifest.contents | Where-Object relativePath -eq 'assessment-record.json').sha256 `
        'the manifest digest binds the exact Assessment Record bytes'
    Assert-Equal '<!doctype html><title>synthetic-private-report-marker</title>' `
        ([System.Text.UTF8Encoding]::new($false, $true).GetString(
            [byte[]] $opened.artifacts['assessment-report.html'])) `
        'reopen returns the exact validated in-memory artifact'

    $second = New-ProtectedEvidencePackage -DestinationDirectory $testRoot `
        -Artifacts $artifacts `
        -AssessmentContractSetVersion '1.0.0' -Completeness 'Complete'
    $firstHeader = Get-ProtectedPackageEnvelopeHeader -LiteralPath $first.packagePath
    $secondHeader = Get-ProtectedPackageEnvelopeHeader -LiteralPath $second.packagePath
    Assert-Equal $false ($firstHeader.noncePrefix -eq $secondHeader.noncePrefix) `
        'each package receives a fresh random nonce prefix'
    Assert-Equal $false ($firstHeader.protectedContentKey -eq $secondHeader.protectedContentKey) `
        'each package receives a fresh independently protected content key'
    [byte[]] $firstKey = Unprotect-ProtectedPackageContentKey `
        ([System.Convert]::FromBase64String($firstHeader.protectedContentKey))
    [byte[]] $secondKey = Unprotect-ProtectedPackageContentKey `
        ([System.Convert]::FromBase64String($secondHeader.protectedContentKey))
    try {
        Assert-Equal $false ([System.Linq.Enumerable]::SequenceEqual[byte]($firstKey, $secondKey)) `
            'the underlying 256-bit content key itself is fresh for every package'
    }
    finally {
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($firstKey)
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($secondKey)
    }
    Assert-Equal $first.innerPackageSha256 $second.innerPackageSha256 `
        'the same artifacts produce identical deterministic inner-package bytes'
    Assert-Equal $false ((Get-ProtectedPackageSha256 -Bytes ([System.IO.File]::ReadAllBytes($first.packagePath))) -eq
        (Get-ProtectedPackageSha256 -Bytes ([System.IO.File]::ReadAllBytes($second.packagePath)))) `
        'fresh protection makes otherwise identical package envelopes differ'
}
finally {
    if ([System.IO.Directory]::Exists($testRoot)) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}

Write-Output 'PASS: Protected Package cryptography, deterministic contents, privacy, and reopen validation hold.'
