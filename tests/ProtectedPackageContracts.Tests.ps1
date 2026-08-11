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

[byte[]] $record = [System.IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
[byte[]] $report = [System.Text.UTF8Encoding]::new($false).GetBytes('<!doctype html><title>Synthetic</title>')
$inner = New-DeterministicAssessmentPackage -Artifacts ([ordered]@{
    'assessment-record.json' = $record; 'assessment-report.html' = $report
}) -AssessmentContractSetVersion '1.0.0' -Completeness Complete
$manifestJson = $inner.manifest | ConvertTo-Json -Compress -Depth 20
Assert-Equal $true (Test-Json -Json $manifestJson -SchemaFile (
    Join-Path $repositoryRoot 'schemas/assessment-package-manifest.schema.json')) `
    'the emitted manifest satisfies its closed public schema'

$testRoot = Join-Path $repositoryRoot ".test-output/package-contract-$([guid]::NewGuid().ToString('N'))"
$null = [System.IO.Directory]::CreateDirectory($testRoot)
try {
    $path = Join-Path $testRoot 'header.winpcinfo'
    $null = Write-ProtectedPackageEnvelope -Plaintext $inner.bytes -LiteralPath $path
    $header = Get-ProtectedPackageEnvelopeHeader $path
    $headerJson = $header | ConvertTo-Json -Compress -Depth 10
    Assert-Equal $true (Test-Json -Json $headerJson -SchemaFile (
        Join-Path $repositoryRoot 'schemas/protected-package-envelope.schema.json')) `
        'the emitted non-identifying header satisfies its closed public schema'
}
finally {
    [System.Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]] $inner.bytes)
    if ([System.IO.Directory]::Exists($testRoot)) { [System.IO.Directory]::Delete($testRoot, $true) }
}

Write-Output 'PASS: emitted manifests and envelope headers satisfy their release schemas.'
