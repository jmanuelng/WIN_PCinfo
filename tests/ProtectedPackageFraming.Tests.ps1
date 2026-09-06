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

$root = Join-Path $repositoryRoot ".test-output/package-framing-$([guid]::NewGuid().ToString('N'))"
$null = [IO.Directory]::CreateDirectory($root)
[byte[]] $record = $null
[byte[]] $report = $null
try {
    $record = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
    $report = [Text.Encoding]::UTF8.GetBytes('<html>' + ('synthetic framing ' * 2500) + '</html>')
    $canonical = New-ProtectedEvidencePackage -DestinationDirectory $root -Artifacts ([ordered]@{
        'assessment-record.json' = $record; 'assessment-report.html' = $report
    }) -AssessmentContractSetVersion '1.0.0' -Completeness Complete
    Assert-Equal $true $canonical.verified 'a multi-chunk package finalizes and reopens before mutation'
    [byte[]] $original = [IO.File]::ReadAllBytes($canonical.packagePath)
    $header = Get-ProtectedPackageEnvelopeHeader -LiteralPath $canonical.packagePath
    Assert-Equal $true ($header.chunkCount -ge 3) 'the fixture has distinct first, middle and final chunks'

    # Decode the documented envelope framing only; do not recreate encryption,
    # compute expected authentication tags, or invoke internal AAD helpers.
    $headerLength = [BitConverter]::ToInt32($original, 8)
    $firstOffset = 12 + $headerLength
    $frames = @()
    $offset = $firstOffset
    for ($index = 0; $index -lt $header.chunkCount; $index++) {
        $cipherLength = [BitConverter]::ToInt32($original, $offset + 8)
        $frameLength = 12 + 12 + $cipherLength + 16
        $frames += [pscustomobject]@{ Offset = $offset; Length = $frameLength }
        $offset += $frameLength
    }
    Assert-Equal $original.Length $offset 'the positive fixture ends at its final authenticated frame'

    foreach ($name in @('header-aad', 'ciphertext', 'tag', 'nonce', 'chunk-index',
            'chunk-length', 'chunk-order', 'missing-final-chunk', 'trailing-byte')) {
        [byte[]] $changed = $original.Clone()
        switch ($name) {
            'header-aad' {
                # Whitespace leaves all parsed header values and framing intact.
                # Only exact authenticated header bytes change.
                $changed = [byte[]]::new($original.Length + 1)
                [Buffer]::BlockCopy($original, 0, $changed, 0, 12)
                [Buffer]::BlockCopy([BitConverter]::GetBytes($headerLength + 1), 0, $changed, 8, 4)
                $changed[12] = 0x20
                [Buffer]::BlockCopy($original, 12, $changed, 13, $original.Length - 12)
            }
            'ciphertext' { $changed[$firstOffset + 24] = $changed[$firstOffset + 24] -bxor 1 }
            'tag' { $changed[$firstOffset + $frames[0].Length - 1] = $changed[$firstOffset + $frames[0].Length - 1] -bxor 1 }
            'nonce' { $changed[$firstOffset + 12] = $changed[$firstOffset + 12] -bxor 1 }
            'chunk-index' { $changed[$firstOffset] = 1 }
            'chunk-length' { $changed[$firstOffset + 4] = $changed[$firstOffset + 4] -bxor 1 }
            'chunk-order' {
                [Buffer]::BlockCopy($original, $frames[1].Offset, $changed, $firstOffset, $frames[1].Length)
                [Buffer]::BlockCopy($original, $frames[0].Offset, $changed, $firstOffset + $frames[1].Length, $frames[0].Length)
            }
            'missing-final-chunk' { $changed = $original[0..($frames[-1].Offset - 1)] }
            'trailing-byte' { $changed = $original + [byte] 0x00 }
        }
        $path = Join-Path $root "$name.winpcinfo"
        [IO.File]::WriteAllBytes($path, $changed)
        if ($name -eq 'header-aad') {
            $parsed = Get-ProtectedPackageEnvelopeHeader -LiteralPath $path
            Assert-Equal ($header | ConvertTo-Json -Compress) ($parsed | ConvertTo-Json -Compress) `
                'AAD mutation passes structural header admission with exactly the same values'
        }
        $opened = Read-ProtectedEvidencePackage -LiteralPath $path
        Assert-Equal 'IntegrityFailed' $opened.state "$name fails closed at package reopening"
        Assert-Equal $false $opened.verified "$name is never a verified package"
        Assert-Equal $true ($null -eq $opened.artifacts) "$name exposes no plaintext artifacts"
        $before = @([IO.Directory]::EnumerateFileSystemEntries($root) | Sort-Object)
        $view = Open-EvidenceViewingSession -PackagePath $path `
            -RequestedArtifact 'assessment-report.html' -ViewingBasePath $root
        Assert-Equal 'IntegrityFailed' $view.state "$name cannot open a report"
        Assert-Equal ($before -join '|') (@([IO.Directory]::EnumerateFileSystemEntries($root) | Sort-Object) -join '|') `
            "$name creates no viewing directory, recovery journal or plaintext archive"
    }
    $reopened = Read-ProtectedEvidencePackage -LiteralPath $canonical.packagePath
    try {
        Assert-Equal $true $reopened.verified 'rejected mutations preserve the original verified package'
    }
    finally {
        if ($null -ne $reopened.artifacts) {
            foreach ($bytes in $reopened.artifacts.Values) {
                [Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]] $bytes)
            }
        }
    }
}
finally {
    foreach ($buffer in @($record, $report)) {
        if ($null -ne $buffer) { [Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]] $buffer) }
    }
    $resolvedRoot = [IO.Path]::GetFullPath($root)
    $expectedParent = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))
    if ([IO.Path]::GetDirectoryName($resolvedRoot) -ne $expectedParent) { throw 'Test cleanup escaped its owned parent.' }
    if ([IO.Directory]::Exists($resolvedRoot)) { [IO.Directory]::Delete($resolvedRoot, $true) }
}
Assert-Equal $false ([IO.Directory]::Exists($root)) 'framing validation removes its owned test files'
Write-Output 'PASS: nine AAD, ciphertext, tag, nonce, framing and finalization mutations refuse reopening and viewing without residue.'
