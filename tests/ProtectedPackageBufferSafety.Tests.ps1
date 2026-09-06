[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'PackageSafetyTestSupport.ps1')
$candidate = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$regions = [regex]::Matches([IO.File]::ReadAllText($candidate),
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach ($region in $regions) { . ([scriptblock]::Create($region.Groups[2].Value)) }
$packageSource = ($regions | Where-Object { $_.Groups[1].Value -eq 'ProtectedPackage.ps1' }).Groups[2].Value
$root = Join-Path $repositoryRoot ('.test-output/package-buffer-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$script:ObservedPackageBuffers = [Collections.Generic.List[object]]::new()
$recipient = $null
try {
    $record = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
    $report = [Text.Encoding]::UTF8.GetBytes('<html>synthetic buffer safety</html>')
    $inner = New-DeterministicAssessmentPackage -Artifacts ([ordered]@{
        'assessment-record.json' = $record; 'assessment-report.html' = $report
    }) -AssessmentContractSetVersion 1.0.0 -Completeness Complete
    $invalid = [Text.Encoding]::UTF8.GetBytes([Text.Encoding]::UTF8.GetString($record).Replace('"contractVersion": "1.0.0"', '"contractVersion": "99.0.0"'))
    Assert-Equal $false (Test-ProtectedPackageAssessmentRecord $invalid) 'the hostile authenticated record is incompatible'
    $hostileInner = New-AuthenticatedTestArchive -Record $invalid -Report $report -Manifest $inner.manifest
    $path = Join-Path $root 'incompatible.winpcinfo'
    $null = Write-ProtectedPackageEnvelope -Plaintext $hostileInner -LiteralPath $path
    . ([scriptblock]::Create((Add-PackageBufferObservation -Source $packageSource)))
    $script:ObservedPackageBuffers.Clear()
    $opened = Read-ProtectedEvidencePackage -LiteralPath $path
    Assert-Equal 'IntegrityFailed' $opened.state 'authenticated incompatible content is refused'
    Assert-PackageBuffersCleared -Because 'authenticated record admission failure'
    $goodPath = Join-Path $root 'valid.winpcinfo'
    foreach ($fault in @('SetupFailure', 'InterruptedWrite', 'DiskExhaustion', 'ChunkWriteFailure')) {
        $script:ObservedPackageBuffers.Clear()
        $failed = $false
        try { $null = Write-ProtectedPackageEnvelope -Plaintext $inner.bytes -LiteralPath $goodPath -SyntheticWriteFailure $fault }
        catch { $failed = $true }
        Assert-Equal $true $failed "$fault crosses a writer failure boundary"
        Assert-Equal $false ([IO.File]::Exists($goodPath)) "$fault leaves no provisional file"
        Assert-PackageBuffersCleared -Because $fault
    }
    $script:ObservedPackageBuffers.Clear()
    $null = Write-ProtectedPackageEnvelope -Plaintext $inner.bytes -LiteralPath $goodPath
    Assert-PackageBuffersCleared -Because 'successful encryption'
    $script:ObservedPackageBuffers.Clear()
    $valid = Read-ProtectedEvidencePackage -LiteralPath $goodPath
    Assert-Equal $true $valid.verified 'successful read transfers only admitted artifact buffers to its caller'
    Assert-PackageBuffersCleared -Because 'successful read' -Transferred @($valid.artifacts.Values)
    foreach ($buffer in $valid.artifacts.Values) { [Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]] $buffer) }
    Assert-PackageBuffersCleared -Because 'caller disposal after successful read'
    $corrupt = [IO.File]::ReadAllBytes($goodPath)
    $corrupt[-1] = $corrupt[-1] -bxor 1
    [IO.File]::WriteAllBytes($goodPath, $corrupt)
    $script:ObservedPackageBuffers.Clear()
    Assert-Equal 'IntegrityFailed' (Read-ProtectedEvidencePackage -LiteralPath $goodPath).state 'tag failure exposes no artifacts'
    Assert-PackageBuffersCleared -Because 'authentication failure'
    $recipient = New-SyntheticRecipientCertificate -KeyBits 2048 -Validity CurrentlyValid
    $key = [byte[]]::new(32)
    $recovered = $null
    [Security.Cryptography.RandomNumberGenerator]::Fill($key)
    try {
        $wrapped = Protect-RecipientContentKey -ContentKey $key -Certificate $recipient.certificate
        $recovered = Unprotect-RecipientContentKey -WrappedContentKey $wrapped -Certificate $recipient.certificate
        Assert-Equal $true ($recovered -is [byte[]]) 'recipient opening transfers one clearable content-key buffer without boxed-byte copies'
        Assert-Equal ([Convert]::ToBase64String($key)) ([Convert]::ToBase64String($recovered)) 'recipient unwrap preserves the content key'
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($key)
        if ($null -ne $recovered) { [Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]] $recovered) }
    }
    Write-Output 'PASS: authenticated record refusal clears all observed owned key, chunk, archive and decoded artifact buffers.'
}
finally {
    if ($null -ne $recipient) { $recipient.certificate.Dispose() }
    . ([scriptblock]::Create($packageSource))
    foreach ($allocation in $script:ObservedPackageBuffers) {
        $value = $allocation.Value
        if ($value -is [IO.MemoryStream]) { [Security.Cryptography.CryptographicOperations]::ZeroMemory($value.GetBuffer()) }
        elseif ($value -is [byte[]]) { [Security.Cryptography.CryptographicOperations]::ZeroMemory($value) }
    }
    $resolved = [IO.Path]::GetFullPath($root)
    if ([IO.Path]::GetDirectoryName($resolved) -ne [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))) { throw 'Buffer test cleanup escaped its parent.' }
    if ([IO.Directory]::Exists($resolved)) { [IO.Directory]::Delete($resolved, $true) }
}
