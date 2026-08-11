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

$root=Join-Path $repositoryRoot ".test-output/protected-write-$([guid]::NewGuid().ToString('N'))"
$null=[IO.Directory]::CreateDirectory($root)
try {
    [byte[]]$record=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
    [byte[]]$report=[Text.UTF8Encoding]::new($false).GetBytes('<html>synthetic</html>')
    $artifacts=[ordered]@{'assessment-record.json'=$record;'assessment-report.html'=$report}
    foreach($fault in 'InterruptedWrite','DiskExhaustion'){
        $result=New-ProtectedEvidencePackage -DestinationDirectory $root `
            -Artifacts $artifacts -AssessmentContractSetVersion 1.0.0 -Completeness Complete `
            -SyntheticWriteFailure $fault
        Assert-Equal 'IntegrityFailed' $result.state "$fault cannot report a package"
        Assert-Equal 0 @([IO.Directory]::EnumerateFiles($root)).Count `
            "$fault leaves neither final nor incomplete ciphertext"
    }

    $setupPath = Join-Path $root 'synthetic-setup-failure.winpcinfo.partial'
    $inner = New-DeterministicAssessmentPackage -Artifacts $artifacts `
        -AssessmentContractSetVersion 1.0.0 -Completeness Complete
    try {
        $setupFailed = $false
        try {
            $null = Write-ProtectedPackageEnvelope -Plaintext $inner.bytes `
                -LiteralPath $setupPath -SyntheticWriteFailure SetupFailure
        }
        catch { $setupFailed = $true }
        Assert-Equal $true $setupFailed `
            'a failure before writer construction crosses the setup-failure seam'
        Assert-Equal $false ([IO.File]::Exists($setupPath)) `
            'handle-owned rollback removes incomplete ciphertext after setup failure'
        $probe = [IO.FileStream]::new(
            $setupPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $probe.Dispose()
        [IO.File]::Delete($setupPath)
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]] $inner.bytes)
    }

    $removeOnCloseImplementation = (Get-Command `
        Remove-EvidenceWorkspaceOwnedStreamOnClose).ScriptBlock
    try {
        function Remove-EvidenceWorkspaceOwnedStreamOnClose {
            throw 'Synthetic owned-handle cleanup failure.'
        }
        $unverifiedCleanup = New-ProtectedEvidencePackage -DestinationDirectory $root `
            -Artifacts $artifacts -AssessmentContractSetVersion 1.0.0 `
            -Completeness Complete -SyntheticWriteFailure SetupFailure
        Assert-Equal 'CleanupIncomplete' $unverifiedCleanup.state `
            'an unverified handle cleanup cannot collapse to ordinary integrity failure'
        if ($null -ne $unverifiedCleanup.packagePath) {
            throw 'Incomplete ciphertext was reported as a package.'
        }
    }
    finally {
        Set-Item Function:\Remove-EvidenceWorkspaceOwnedStreamOnClose `
            $removeOnCloseImplementation
    }

    $missingJournal = Join-Path $root 'missing-recovery/run-recovery.json'
    $registrationFailure = New-ProtectedEvidencePackage -DestinationDirectory $root `
        -Artifacts $artifacts -AssessmentContractSetVersion 1.0.0 -Completeness Complete `
        -JournalPath $missingJournal
    Assert-Equal 'CleanupIncomplete' $registrationFailure.state `
        'failed recovery registration reports the honest non-success terminal state'
    Assert-Equal $true $registrationFailure.recoverable `
        'a fully reopened package remains recoverable after registration failure'
    Assert-Equal $true ([IO.File]::Exists($registrationFailure.packagePath)) `
        'rollback preserves a package that already passed full reopen validation'
    $preserved = Read-ProtectedEvidencePackage -LiteralPath $registrationFailure.packagePath
    Assert-Equal $true $preserved.verified `
        'the preserved final package remains locally reopenable and fully valid'
}
finally { if([IO.Directory]::Exists($root)){[IO.Directory]::Delete($root,$true)} }

Write-Output 'PASS: write rollback removes exact incomplete files and preserves fully validated packages.'
