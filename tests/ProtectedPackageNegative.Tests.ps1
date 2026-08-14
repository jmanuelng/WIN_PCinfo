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

function Assert-IntegrityFailure {
    param([string] $Path, [string] $Because)
    $result = Read-ProtectedEvidencePackage -LiteralPath $Path
    Assert-Equal 'IntegrityFailed' $result.state $Because
    Assert-Equal $false $result.verified "$Because; verification is false"
    if ($null -ne $result.artifacts) { throw "$Because; plaintext artifacts were exposed." }
}

$root = Join-Path $repositoryRoot ".test-output/protected-negative-$([guid]::NewGuid().ToString('N'))"
$null = [System.IO.Directory]::CreateDirectory($root)
try {
    [byte[]] $record = [System.IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
    [byte[]] $report = [System.Text.UTF8Encoding]::new($false).GetBytes('<html>synthetic</html>')
    $artifacts=[ordered]@{'assessment-record.json'=$record;'assessment-report.html'=$report}
    $valid=New-ProtectedEvidencePackage -DestinationDirectory $root `
        -Artifacts $artifacts -AssessmentContractSetVersion 1.0.0 -Completeness Complete

    [byte[]] $maximumRecord = [byte[]]::new(2097152)
    [System.Buffer]::BlockCopy($record,0,$maximumRecord,0,$record.Length)
    [System.Array]::Fill[byte]($maximumRecord,[byte]0x20,$record.Length,$maximumRecord.Length-$record.Length)
    [byte[]] $maximumReport = [byte[]]::new(262144)
    [System.Array]::Fill[byte]($maximumReport, [byte]0x78)
    $maximum=New-ProtectedEvidencePackage -DestinationDirectory $root `
        -Artifacts ([ordered]@{'assessment-record.json'=$maximumRecord;'assessment-report.html'=$maximumReport}) `
        -AssessmentContractSetVersion 1.0.0 -Completeness Complete
    Assert-Equal $true $maximum.verified 'the exact maximum record and report sizes compose under the archive ceiling'
    $maximumHeader=Get-ProtectedPackageEnvelopeHeader $maximum.packagePath
    Assert-Equal $true ($maximumHeader.chunkCount -gt 140) 'the maximum artifact fixture exercises the upper authenticated chunk range'
    $stream=[IO.File]::OpenRead($maximum.packagePath);$reader=[IO.BinaryReader]::new($stream)
    try {
        $null=$reader.ReadBytes(8);$headerLength=$reader.ReadInt32();$null=$reader.ReadBytes($headerLength)
        $nonces=@()
        for($i=0;$i-lt$maximumHeader.chunkCount;$i++){
            $null=$reader.ReadInt32();$null=$reader.ReadInt32();$cipherLength=$reader.ReadInt32()
            $nonces+=[Convert]::ToBase64String($reader.ReadBytes(12))
            $null=$reader.ReadBytes($cipherLength);$null=$reader.ReadBytes(16)
        }
        Assert-Equal $maximumHeader.chunkCount @($nonces|Sort-Object -CaseSensitive -Unique).Count `
            'every authenticated chunk has a unique nonce'
    }
    finally {$reader.Dispose();$stream.Dispose()}

    [byte[]]$maximumPlaintext=[byte[]]::new(2621440)
    [System.Array]::Fill[byte]($maximumPlaintext,[byte]0x5a)
    $maximumEnvelopePath=Join-Path $root 'maximum-envelope.winpcinfo'
    $null=Write-ProtectedPackageEnvelope -Plaintext $maximumPlaintext -LiteralPath $maximumEnvelopePath
    $maximumEnvelopeHeader=Get-ProtectedPackageEnvelopeHeader $maximumEnvelopePath
    Assert-Equal 2621440 $maximumEnvelopeHeader.plaintextLength 'the exact envelope plaintext limit is admitted'
    Assert-Equal 160 $maximumEnvelopeHeader.chunkCount 'the exact envelope limit produces 160 chunks'
    $overEnvelopePath=Join-Path $root 'over-envelope.winpcinfo'
    $overEnvelopeRejected=$false
    try{Write-ProtectedPackageEnvelope -Plaintext ([byte[]]::new(2621441)) -LiteralPath $overEnvelopePath|Out-Null}catch{$overEnvelopeRejected=$_.Exception.Message -match 'plaintext exceeded'}
    Assert-Equal $true $overEnvelopeRejected 'one byte over the plaintext ceiling is rejected before writing'
    Assert-Equal $false ([IO.File]::Exists($overEnvelopePath)) 'an over-limit envelope creates no ciphertext'

    $oversizeRecord=[byte[]]::new(2097153)
    [System.Buffer]::BlockCopy($maximumRecord,0,$oversizeRecord,0,$maximumRecord.Length)
    $oversizeRecord[-1]=0x20
    $recordRejected=$false
    try{New-DeterministicAssessmentPackage -Artifacts ([ordered]@{'assessment-record.json'=$oversizeRecord;'assessment-report.html'=$report}) -AssessmentContractSetVersion 1.0.0 -Completeness Complete|Out-Null}catch{$recordRejected=$_.Exception.Message -match 'evidence bound'}
    Assert-Equal $true $recordRejected 'one byte over the Assessment Record ceiling is rejected'
    $reportRejected=$false
    try{New-DeterministicAssessmentPackage -Artifacts ([ordered]@{'assessment-record.json'=$record;'assessment-report.html'=([byte[]]::new(262145))}) -AssessmentContractSetVersion 1.0.0 -Completeness Complete|Out-Null}catch{$reportRejected=$_.Exception.Message -match 'evidence bound'}
    Assert-Equal $true $reportRejected 'one byte over the report ceiling is rejected'

    [byte[]]$historicalInner=New-SyntheticInvalidManifestInnerPackage `
        -RecordBytes $record -ReportBytes $report `
        -PackagePolicy 'win-pcinfo.protected-package/1.0.0' -ValidDigests
    $historicalPath=Join-Path $root 'historical-policy-1.0.winpcinfo'
    $null=Write-ProtectedPackageEnvelope -Plaintext $historicalInner -LiteralPath $historicalPath
    $historical=Read-ProtectedEvidencePackage $historicalPath
    Assert-Equal $true $historical.verified `
        'a valid historical policy-1.0 package remains decryptable under its frozen bounds'
    [byte[]]$historicalOversizeRecord=[byte[]]::new(524289)
    [System.Buffer]::BlockCopy($record,0,$historicalOversizeRecord,0,$record.Length)
    [System.Array]::Fill[byte]($historicalOversizeRecord,[byte]0x20,$record.Length,$historicalOversizeRecord.Length-$record.Length)
    [byte[]]$historicalOversizeInner=New-SyntheticInvalidManifestInnerPackage `
        -RecordBytes $historicalOversizeRecord -ReportBytes $report `
        -PackagePolicy 'win-pcinfo.protected-package/1.0.0' -ValidDigests
    $historicalOversizePath=Join-Path $root 'historical-policy-1.0-oversize.winpcinfo'
    $null=Write-ProtectedPackageEnvelope -Plaintext $historicalOversizeInner -LiteralPath $historicalOversizePath
    Assert-IntegrityFailure $historicalOversizePath `
        'a historical manifest cannot claim the larger policy-1.1 artifact bounds'

    foreach($name in 'corruption','truncation','unsupported'){
        [System.IO.File]::Copy($valid.packagePath,(Join-Path $root "$name.winpcinfo"))
    }
    $corruptPath=Join-Path $root 'corruption.winpcinfo'
    [byte[]]$corrupt=[IO.File]::ReadAllBytes($corruptPath); $corrupt[-1]=$corrupt[-1] -bxor 1; [IO.File]::WriteAllBytes($corruptPath,$corrupt)
    Assert-IntegrityFailure $corruptPath 'ciphertext corruption fails authentication'
    foreach($context in 'WrongUser','WrongDevice'){
        $contextFailure=Read-ProtectedEvidencePackage $valid.packagePath `
            -SyntheticProtectionContext $context
        Assert-Equal 'IntegrityFailed' $contextFailure.state `
            "$context DPAPI context cannot expose package content"
        if ($null -ne $contextFailure.artifacts) { throw "$context exposed plaintext artifacts." }
    }
    $truncatePath=Join-Path $root 'truncation.winpcinfo'
    [byte[]]$truncated=[IO.File]::ReadAllBytes($truncatePath); [IO.File]::WriteAllBytes($truncatePath,$truncated[0..($truncated.Length-8)])
    Assert-IntegrityFailure $truncatePath 'truncation fails before any content is exposed'
    $unsupportedPath=Join-Path $root 'unsupported.winpcinfo'
    [byte[]]$unsupported=[IO.File]::ReadAllBytes($unsupportedPath); $unsupported[7]=0; [IO.File]::WriteAllBytes($unsupportedPath,$unsupported)
    Assert-IntegrityFailure $unsupportedPath 'unsupported format bytes fail closed'

    $malformedPath=Join-Path $root 'malformed.winpcinfo'
    $null = Write-ProtectedPackageEnvelope `
        -Plaintext ([Text.UTF8Encoding]::new($false).GetBytes('not-a-zip')) `
        -LiteralPath $malformedPath
    Assert-IntegrityFailure $malformedPath 'an authenticated malformed archive remains invalid'
    [byte[]]$invalidInner=New-SyntheticInvalidManifestInnerPackage -RecordBytes $record -ReportBytes $report
    $invalidManifestPath=Join-Path $root 'invalid-manifest.winpcinfo'
    $null = Write-ProtectedPackageEnvelope -Plaintext $invalidInner -LiteralPath $invalidManifestPath
    Assert-IntegrityFailure $invalidManifestPath 'an authenticated archive with a false digest remains invalid'
}
finally { if([IO.Directory]::Exists($root)){[IO.Directory]::Delete($root,$true)} }

Write-Output 'PASS: package bounds and every negative integrity path fail closed without plaintext.'
