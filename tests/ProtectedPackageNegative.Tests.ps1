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

    [byte[]] $maximumReport = [byte[]]::new(262144)
    [System.Array]::Fill[byte]($maximumReport, [byte]0x78)
    $maximum=New-ProtectedEvidencePackage -DestinationDirectory $root `
        -Artifacts ([ordered]@{'assessment-record.json'=$record;'assessment-report.html'=$maximumReport}) `
        -AssessmentContractSetVersion 1.0.0 -Completeness Complete
    Assert-Equal $true $maximum.verified 'the exact maximum report size crosses multiple bounded chunks'
    $maximumHeader=Get-ProtectedPackageEnvelopeHeader $maximum.packagePath
    Assert-Equal $true ($maximumHeader.chunkCount -gt 1) 'the maximum fixture actually exercises chunking'
    $stream=[IO.File]::OpenRead($maximum.packagePath);$reader=[IO.BinaryReader]::new($stream)
    try {
        $null=$reader.ReadBytes(8);$headerLength=$reader.ReadInt32();$null=$reader.ReadBytes($headerLength)
        $nonces=@()
        for($i=0;$i-lt$maximumHeader.chunkCount;$i++){
            $null=$reader.ReadInt32();$null=$reader.ReadInt32();$cipherLength=$reader.ReadInt32()
            $nonces+=[Convert]::ToBase64String($reader.ReadBytes(12))
            $null=$reader.ReadBytes($cipherLength);$null=$reader.ReadBytes(16)
        }
        Assert-Equal $maximumHeader.chunkCount @($nonces|Sort-Object -Unique).Count `
            'every authenticated chunk has a unique nonce'
    }
    finally {$reader.Dispose();$stream.Dispose()}

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
