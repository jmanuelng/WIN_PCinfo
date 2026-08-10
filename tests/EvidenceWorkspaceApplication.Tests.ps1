[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request-stale-recovery.json'
$preparationPath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

function Get-ValidationResidueNames {
    $validationRoot = Join-Path (Split-Path -Parent $candidatePath) `
        '.evidence-workspace-validation'
    if (-not [System.IO.Directory]::Exists($validationRoot)) { return @() }
    @([System.IO.Directory]::EnumerateFileSystemEntries($validationRoot) |
        ForEach-Object { [System.IO.Path]::GetFileName($_) } | Sort-Object)
}

function Invoke-WorkspaceFixtureApplication {
    param([Parameter(Mandatory)] [string] $Name)

    Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation'
        '-RequestPath', $requestPath
        '-AcceptPreparation'
        '-PreparationFixturePath', $preparationPath
        '-EvidenceWorkspaceFixturePath', (Join-Path $PSScriptRoot "fixtures/$Name.json")
    )
}

$cases = @(
    @{ Name = 'workspace-eligible-destination'; Scenario = 'EligibleDestination'; State = 'Validated'; Reason = 'WORKSPACE.CREATED'; Outcome = 'NotStarted'; ExitCode = 20 }
    @{ Name = 'workspace-unsafe-destination'; Scenario = 'UnsafeDestination'; State = 'Rejected'; Reason = 'WORKSPACE.DESTINATION_NETWORK'; Outcome = 'NotStarted'; ExitCode = 20 }
    @{ Name = 'workspace-interrupted-temporary-evidence'; Scenario = 'InterruptedTemporaryEvidence'; State = 'Recovered'; Reason = 'RECOVERY.STALE_RESIDUE_REMOVED'; Outcome = 'NotStarted'; ExitCode = 20 }
    @{ Name = 'workspace-stale-owner'; Scenario = 'StaleOwner'; State = 'Recovered'; Reason = 'RECOVERY.STALE_RESIDUE_REMOVED'; Outcome = 'NotStarted'; ExitCode = 20 }
    @{ Name = 'workspace-live-owner'; Scenario = 'LiveOwner'; State = 'Deferred'; Reason = 'RECOVERY.LIVE_OWNER'; Outcome = 'NotStarted'; ExitCode = 20 }
    @{ Name = 'workspace-ambiguous-target'; Scenario = 'AmbiguousTarget'; State = 'CleanupIncomplete'; Reason = 'RECOVERY.OWNERSHIP_UNVERIFIED'; Outcome = 'CleanupIncomplete'; ExitCode = 60 }
    @{ Name = 'workspace-preserved-package'; Scenario = 'PreservedPackage'; State = 'Recovered'; Reason = 'RECOVERY.STALE_RESIDUE_REMOVED'; Outcome = 'NotStarted'; ExitCode = 20 }
    @{ Name = 'workspace-windows-feature-observation'; Scenario = 'WindowsFeatureObservation'; State = 'ObservedOnly'; Reason = 'RECOVERY.WINDOWS_FEATURE_OBSERVED'; Outcome = 'NotStarted'; ExitCode = 20 }
    @{ Name = 'workspace-cleanup-failure'; Scenario = 'CleanupFailure'; State = 'CleanupIncomplete'; Reason = 'RECOVERY.CLEANUP_FAILED'; Outcome = 'CleanupIncomplete'; ExitCode = 60 }
)

foreach ($case in $cases) {
    $beforeResidue = @(Get-ValidationResidueNames)
    $result = Invoke-WorkspaceFixtureApplication -Name $case.Name
    $afterResidue = @(Get-ValidationResidueNames)
    $workspaceRecords = @($result.Records | Where-Object {
        $_.recordType -eq 'win-pcinfo.evidence-workspace-validation'
    })
    $terminalRecords = @($result.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $workspaceRecords.Count "$($case.Scenario) emits one workspace result"
    Assert-Equal 1 $terminalRecords.Count "$($case.Scenario) emits one terminal result"
    $record = $workspaceRecords[0]
    $terminal = $terminalRecords[0]
    Assert-Equal $case.Scenario $record.scenario 'the release-owned fixture name is preserved'
    Assert-Equal $case.State $record.state "$($case.Scenario) reports the expected safety state"
    Assert-Equal $case.Reason $record.reasonCode "$($case.Scenario) reports one stable reason"
    Assert-Equal $case.Outcome $terminal.outcome "$($case.Scenario) reaches one honest terminal outcome"
    Assert-Equal $case.ExitCode $result.ExitCode "$($case.Scenario) returns the matching stable exit code"
    Assert-Equal $false $record.collectionStarted 'workspace validation cannot start collection'
    Assert-Equal $false $record.recovery.collectionResumed 'recovery remains cleanup-only'
    Assert-Equal $true $record.recovery.deliberatelyRequested `
        'the generated recovery path requires an explicit request choice'
    Assert-Equal $false $record.temporaryEvidence.secureErasureClaim `
        'validation never claims forensic secure erasure'
    Assert-Equal $false $record.windowsFeatures.changesAttempted `
        'no scenario changes a Windows Feature'
    Assert-Equal $true $record.validationCleanupVerified `
        'the synthetic validation harness removes even deliberately preserved or failed residue'
    Assert-Equal ($beforeResidue -join '|') ($afterResidue -join '|') `
        'the generated scenario leaves no validation workspace or journal'
    Assert-Equal $true $terminal.validationFixture `
        'synthetic workspace validation cannot look like a Product Capability run'
    if (($record | ConvertTo-Json -Compress -Depth 10) -match
        '(?i)synthetic-private|password|credential|recipientProfile|processId|initiatingUserSid|workspacePath|journalPath') {
        throw "$($case.Scenario) exposed restricted journal, evidence, identity, or path data."
    }
    if ($result.StandardError) { throw "$($case.Scenario) wrote stderr: $($result.StandardError)" }
}

$invalidRoot = Join-Path $repositoryRoot '.test-output/evidence-workspace-application'
$null = [System.IO.Directory]::CreateDirectory($invalidRoot)
$invalidPath = Join-Path $invalidRoot 'duplicate-scenario.json'
[System.IO.File]::WriteAllText(
    $invalidPath,
    '{"contractVersion":"1.0.0","scenario":"StaleOwner","scenario":"LiveOwner"}',
    [System.Text.UTF8Encoding]::new($false)
)
try {
    $invalid = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation'
        '-RequestPath', $requestPath
        '-AcceptPreparation'
        '-PreparationFixturePath', $preparationPath
        '-EvidenceWorkspaceFixturePath', $invalidPath
    )
    Assert-Equal 20 $invalid.ExitCode 'ambiguous fixture JSON fails before workspace creation'
    Assert-Equal 'WORKSPACE.FIXTURE_INVALID' $invalid.Records[-1].reasonCode `
        'invalid fixture input receives one sanitized reason'
}
finally {
    if ([System.IO.Directory]::Exists($invalidRoot)) {
        [System.IO.Directory]::Delete($invalidRoot, $true)
    }
}

$notAuthorized = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
    '-Mode', 'Automation'
    '-RequestPath', (Join-Path $PSScriptRoot 'fixtures/automation-request.json')
    '-AcceptPreparation'
    '-PreparationFixturePath', $preparationPath
    '-EvidenceWorkspaceFixturePath', (Join-Path $PSScriptRoot 'fixtures/workspace-stale-owner.json')
)
Assert-Equal 20 $notAuthorized.ExitCode `
    'stale recovery without the deliberate request choice remains NotStarted'
Assert-Equal 'WORKSPACE.RECOVERY_NOT_AUTHORIZED' $notAuthorized.Records[-1].reasonCode `
    'a hidden fixture cannot bypass the request authority boundary'
Assert-Equal $false $notAuthorized.Records[-1].collectionStarted `
    'unauthorized recovery creates no workspace or collection'

Write-Output 'PASS: the generated application exposes all nine Evidence Workspace and recovery safety cases without residue.'
