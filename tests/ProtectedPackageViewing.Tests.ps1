[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ContractValidator.ps1')
. (Join-Path $repositoryRoot 'src/EvidenceWorkspace.ps1')
. (Join-Path $repositoryRoot 'src/ProtectedPackage.ps1')

$root=Join-Path $repositoryRoot ".test-output/protected-view-$([guid]::NewGuid().ToString('N'))"
$null=[IO.Directory]::CreateDirectory($root)
try {
    [byte[]]$record=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
    [byte[]]$report=[Text.UTF8Encoding]::new($false).GetBytes('<html>requested-synthetic-report</html>')
    $package=New-ProtectedEvidencePackage -DestinationDirectory $root `
        -Artifacts ([ordered]@{'assessment-record.json'=$record;'assessment-report.html'=$report}) `
        -AssessmentContractSetVersion 1.0.0 -Completeness Complete
    $session=Open-EvidenceViewingSession -PackagePath $package.packagePath `
        -RequestedArtifact 'assessment-report.html' -ViewingBasePath $root
    Assert-Equal 'Opened' $session.state 'a validated package opens one requested artifact'
    Assert-Equal $true (Test-EvidenceAccessBoundary -LiteralPath $session.workspacePath `
        -ExpectedOwnerSid ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) `
        'the viewing boundary has the protected initiating-user ACL'
    Assert-Equal 1 @([IO.Directory]::EnumerateFiles($session.workspacePath,'*',[IO.SearchOption]::AllDirectories)).Count `
        'only the requested artifact is materialized as plaintext'
    Assert-Equal '<html>requested-synthetic-report</html>' `
        ([Text.UTF8Encoding]::new($false,$true).GetString([IO.File]::ReadAllBytes($session.artifactPath))) `
        'the requested artifact bytes are exact'
    $journal=Read-RunRecoveryJournal $session.journalPath
    Assert-Equal 'Viewing' $journal.phase 'interruption leaves a viewing-specific recovery owner record'
    Assert-Equal $session.artifactPath `
        ($journal.artifacts|Where-Object kind -eq EvidenceViewingArtifact).path `
        'the recovery journal owns the exact plaintext path'
    $closed=Close-EvidenceViewingSession $session
    Assert-Equal 'Closed' $closed.state 'closing removes the plaintext viewing boundary'
    Assert-Equal $true $closed.verified 'close verifies plaintext and recovery-state absence'
    Assert-Equal $false ([IO.File]::Exists($session.artifactPath)) 'requested plaintext is absent after close'
    Assert-Equal $false ([IO.File]::Exists($session.journalPath)) 'recovery ownership is removed only after verified close'

    $interrupted=Open-EvidenceViewingSession -PackagePath $package.packagePath `
        -RequestedArtifact 'assessment-record.json' -ViewingBasePath $root
    Assert-Equal $true ([IO.File]::Exists($interrupted.journalPath)) `
        'an interrupted session has durable exact recovery ownership'
    Assert-Equal 'Closed' (Close-EvidenceViewingSession $interrupted).state `
        'the validation harness can later close the interrupted synthetic session without residue'

    [byte[]]$bad=[IO.File]::ReadAllBytes($package.packagePath); $bad[-1]=$bad[-1] -bxor 1
    $badPath=Join-Path $root 'bad.winpcinfo'; [IO.File]::WriteAllBytes($badPath,$bad)
    $before=@([IO.Directory]::EnumerateDirectories($root)).Count
    $rejected=Open-EvidenceViewingSession -PackagePath $badPath `
        -RequestedArtifact 'assessment-report.html' -ViewingBasePath $root
    Assert-Equal 'IntegrityFailed' $rejected.state 'corruption never creates a viewing boundary'
    Assert-Equal $before @([IO.Directory]::EnumerateDirectories($root)).Count `
        'failed verification exposes no content and creates no plaintext directory'
}
finally { if([IO.Directory]::Exists($root)){[IO.Directory]::Delete($root,$true)} }

Write-Output 'PASS: viewing exposes one requested artifact and closes or retains exact recovery ownership.'
