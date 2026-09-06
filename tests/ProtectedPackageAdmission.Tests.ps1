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

$root = Join-Path $repositoryRoot ".test-output/package-admission-$([guid]::NewGuid().ToString('N'))"
$null = [IO.Directory]::CreateDirectory($root)
[byte[]] $record = $null
[byte[]] $report = $null
[byte[]] $ambiguousInner = $null
$inner = $null
try {
    [byte[]] $record = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
    [byte[]] $report = [Text.UTF8Encoding]::new($false).GetBytes('<html>synthetic admission report</html>')
    $inner = New-DeterministicAssessmentPackage -Artifacts ([ordered]@{
        'assessment-record.json' = $record; 'assessment-report.html' = $report
    }) -AssessmentContractSetVersion '1.0.0' -Completeness Complete
    $manifestJson = $inner.manifest | ConvertTo-Json -Depth 20 -Compress
    $ambiguousManifest = $manifestJson.Replace('"completeness":"Complete"',
        '"completeness":"RecoverablePartial","completeness":"Complete"')

    $canonical = New-ProtectedEvidencePackage -DestinationDirectory $root -Artifacts ([ordered]@{
        'assessment-record.json' = $record; 'assessment-report.html' = $report
    }) -AssessmentContractSetVersion '1.0.0' -Completeness Complete
    Assert-Equal $true $canonical.verified 'canonical paths still finalize through authenticated reopen'

    $before = @([IO.Directory]::EnumerateFileSystemEntries($root))
    $alias = New-ProtectedEvidencePackage -DestinationDirectory $root -Artifacts ([ordered]@{
        'assessment-record.json' = $record; 'ASSESSMENT-REPORT.HTML' = $report
    }) -AssessmentContractSetVersion '1.0.0' -Completeness Complete
    Assert-Equal 'IntegrityFailed' $alias.state 'case-aliased input fails before final naming'
    Assert-Equal $true ($null -eq $alias.packagePath) 'rejected finalization reports no package path'
    Assert-Equal ($before -join '|') (@([IO.Directory]::EnumerateFileSystemEntries($root)) -join '|') `
        'rejected finalization preserves the canonical package and creates no provisional or plaintext archive'

    foreach ($case in @(
        @{ Name = 'duplicate-manifest'; Manifest = $ambiguousManifest; AliasPath = '' },
        @{ Name = 'case-aliased-report'; Manifest = $manifestJson; AliasPath = 'assessment-report.html' },
        @{ Name = 'case-aliased-record'; Manifest = $manifestJson; AliasPath = 'assessment-record.json' },
        @{ Name = 'case-aliased-manifest'; Manifest = $manifestJson; AliasPath = 'package-manifest.json' }
    )) {
        $memory = [IO.MemoryStream]::new()
        try {
            $archive = [IO.Compression.ZipArchive]::new($memory, [IO.Compression.ZipArchiveMode]::Create, $true)
            try {
                $entries = [ordered]@{
                    'package-manifest.json' = [Text.UTF8Encoding]::new($false).GetBytes($case.Manifest)
                    'assessment-record.json' = $record
                    'assessment-report.html' = $report
                }
                foreach ($name in $entries.Keys) {
                    $entryName = if ($name -ceq $case.AliasPath) { $name.ToUpperInvariant() } else { $name }
                    $entry = $archive.CreateEntry($entryName, [IO.Compression.CompressionLevel]::NoCompression)
                    $stream = $entry.Open()
                    try { $stream.Write([byte[]] $entries[$name]) }
                    finally { $stream.Dispose() }
                }
            }
            finally { $archive.Dispose() }
            $ambiguousInner = $memory.ToArray()
        }
        finally { $memory.Dispose() }
        $path = Join-Path $root "$($case.Name).winpcinfo"
        $null = Write-ProtectedPackageEnvelope -Plaintext $ambiguousInner -LiteralPath $path
        $opened = Read-ProtectedEvidencePackage -LiteralPath $path
        Assert-Equal 'IntegrityFailed' $opened.state "$($case.Name) fails before artifact admission"
        Assert-Equal $true ($null -eq $opened.artifacts) 'invalid package exposes no decrypted artifacts'
        $before = @([IO.Directory]::EnumerateFileSystemEntries($root))
        $view = Open-EvidenceViewingSession -PackagePath $path -RequestedArtifact 'assessment-report.html' -ViewingBasePath $root
        Assert-Equal 'IntegrityFailed' $view.state "$($case.Name) cannot open a report"
        Assert-Equal ($before -join '|') (@([IO.Directory]::EnumerateFileSystemEntries($root)) -join '|') `
            'failed admission creates no viewing workspace or recovery journal'
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($ambiguousInner)
    }
}
finally {
    $innerBytes = if ($null -ne $inner) { $inner.bytes } else { $null }
    foreach ($buffer in @($record, $report, $innerBytes, $ambiguousInner)) {
        if ($null -ne $buffer) { [Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]] $buffer) }
    }
    $resolvedRoot = [IO.Path]::GetFullPath($root)
    $expectedParent = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))
    if ([IO.Path]::GetDirectoryName($resolvedRoot) -ne $expectedParent) { throw 'Test cleanup escaped its owned parent.' }
    if ([IO.Directory]::Exists($resolvedRoot)) { [IO.Directory]::Delete($resolvedRoot, $true) }
}
Write-Output 'PASS: canonical package finalizes; case aliases and ambiguous metadata cannot finalize, expose artifacts or open a view.'
