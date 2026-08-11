[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-protected-package.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/protected-package.schema.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policyJson = [System.IO.File]::ReadAllText(
    $policyPath, [System.Text.UTF8Encoding]::new($false, $true)
)
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the release Protected Package policy satisfies its closed schema'
$policy = $policyJson | ConvertFrom-Json -Depth 30

Assert-Equal 'win-pcinfo.protected-package/1.0.0' $policy.policyId `
    'package protection has one release-owned identity'
Assert-Equal 'AES-256-GCM' $policy.envelope.contentEncryption.algorithm `
    'content uses the required authenticated encryption algorithm'
Assert-Equal 32 $policy.envelope.contentEncryption.keyBytes `
    'every package content key is 256 bits'
Assert-Equal 16384 $policy.envelope.contentEncryption.chunkPlaintextBytes `
    'authenticated chunks have one bounded release size'
Assert-Equal 12 $policy.envelope.contentEncryption.nonceBytes `
    'AES-GCM nonces have the fixed 96-bit size'
Assert-Equal 16 $policy.envelope.contentEncryption.tagBytes `
    'each chunk retains the full 128-bit tag'
Assert-Equal 'DPAPI-CurrentUser' $policy.envelope.keyProtection.algorithm `
    'only the initiating Windows user can unwrap the local content key'
Assert-Equal $true $policy.envelope.associatedData.bindHeader `
    'the authenticated contract binds the whole envelope header'
Assert-Equal 'chunkIndex|plaintextLength|ciphertextLength|nonce' `
    (@($policy.envelope.associatedData.chunkFields) -join '|') `
    'per-chunk framing metadata is authenticated'
Assert-Equal 'formatVersion|algorithm|keyProtection|recipientKeyProtection|chunkPlaintextBytes|plaintextLength|chunkCount|noncePrefix|protectedContentKey|recipientWrappedContentKey' `
    (@($policy.envelope.outerMetadata.allowedFields) -join '|') `
    'outer metadata is a closed non-identifying set'
Assert-Equal 'assessment-record.json|assessment-report.html' `
    (@($policy.innerPackage.artifacts.relativePath) -join '|') `
    'the inner package admits only release-declared artifacts'
Assert-Equal $true $policy.finalization.reopenBeforeFinalName `
    'provisional ciphertext is reopened and fully validated before final naming'
Assert-Equal 'RequestedArtifactOnly' $policy.viewing.exposure `
    'a viewing session reveals only the deliberately requested artifact'
Assert-Equal $true $policy.viewing.recoveryJournalOnInterruption `
    'interrupted plaintext cleanup retains exact recovery ownership'

$requiredScenarios = @(
    'KnownAnswer', 'MaximumSize', 'Corruption', 'WrongUser', 'WrongDevice',
    'InterruptedWrite', 'DiskExhaustion', 'MalformedArchive', 'InvalidManifest',
    'ViewingCleanup'
)
Assert-Equal ($requiredScenarios -join '|') (@($policy.validationScenarios) -join '|') `
    'the release freezes every issue-required protection scenario'

Write-Output 'PASS: the release contract closes encryption, package, validation, and viewing behavior.'
