[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policy = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-azure-validation-round.json'
) -Raw | ConvertFrom-Json -Depth 20
$outcomeSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-round-outcome.schema.json'
$oneClientPath = Join-Path $PSScriptRoot 'fixtures/azure-validation-round-one-client.json'
$completeFixturePath = Join-Path $PSScriptRoot 'fixtures/azure-validation-round-execution-complete.json'
$failedFixturePath = Join-Path $PSScriptRoot 'fixtures/azure-validation-round-execution-assessment-failed.json'
$identityFixturePath = Join-Path $PSScriptRoot 'fixtures/azure-validation-round-execution-identity-unavailable.json'
$residueFixturePath = Join-Path $PSScriptRoot 'fixtures/azure-validation-round-execution-residue-remains.json'

$workRoot = Join-Path $repositoryRoot '.test-output/azure-validation-round-application'
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $workRoot -Force
$candidatePath = Join-Path $workRoot 'WIN-PCInfo.ps1'
$null = & (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath

function New-MarkedWorkspace {
    param([Parameter(Mandatory)] [string] $Name)
    $path = Join-Path ([System.IO.Path]::GetTempPath()) "win-pcinfo-azure-round-app-$Name"
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $path -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $path $policy.privacy.markerFileName),
        ($policy.privacy.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $path
}

try {
    $safeWorkspace = New-MarkedWorkspace -Name 'safe'
    $completed = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'RunValidationRound',
        '-ValidationRoundRequestPath', $oneClientPath,
        '-ValidationPrivateWorkspacePath', $safeWorkspace,
        '-ValidationRoundFixturePath', $completeFixturePath
    )
    Assert-Equal 0 $completed.ExitCode 'the generated application completes a synthetic zero-residue round'
    $progress = @($completed.Records | Where-Object recordType -eq 'win-pcinfo.progress')
    $outcome = @($completed.Records | Where-Object recordType -eq 'win-pcinfo.azure-validation-round')
    $terminal = @($completed.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 2 $progress.Count 'the round emits structured start and finish progress'
    Assert-Equal 'validation.round.started' $progress[0].messageId 'the round starts with a stable message'
    Assert-Equal 'validation.round.succeeded' $progress[1].messageId 'zero residue uses a stable success message'
    Assert-Equal 1 $outcome.Count 'the round emits one sanitized outcome'
    Assert-Equal 'ZeroResidueProven' $outcome[0].state 'the generated application reports ZeroResidueProven'
    Assert-Equal $true $outcome[0].zeroResidue 'the generated application proves zero residue'
    Assert-Equal $true $outcome[0].guestReady 'the generated application waited for VM Agent readiness'
    Assert-Equal $true $outcome[0].candidateVerified 'the generated application reverified the candidate'
    Assert-Equal $false $outcome[0].bootstrapCredentialExposed `
        'the generated application never returns a bootstrap credential'
    Assert-Equal $false $outcome[0].qualifyingEvidence `
        'the generated application does not treat this tracer as qualifying evidence'
    Assert-Equal $false $outcome[0].collectionStarted 'the round never starts host assessment collection'
    Assert-Equal $false $outcome[0].azureContacted `
        'the generated synthetic fixture does not contact Azure'
    Assert-Equal $false (Test-Path -LiteralPath (
        Join-Path $safeWorkspace $policy.workspace.renderedDirectoryName
    )) 'the generated application removes rendered admission files after zero residue'
    Assert-Equal $true (Test-Json -Json ($outcome[0] | ConvertTo-Json -Compress -Depth 20) `
        -SchemaFile $outcomeSchemaPath) 'the application outcome satisfies the public schema'
    Assert-Equal $false (($outcome[0] | ConvertTo-Json -Compress -Depth 20) -match [regex]::Escape($safeWorkspace)) `
        'the application outcome omits the private workspace path'
    Assert-Equal 1 $terminal.Count 'the round ends with one terminal record'
    Assert-Equal 'Completed' $terminal[0].outcome 'zero residue completes without host collection'
    Assert-Equal 'VALIDATION.ZERO_RESIDUE_PROVEN' $terminal[0].reasonCode `
        'the terminal reason matches the sanitized outcome'
    Assert-Equal $false $terminal[0].collectionStarted 'completed rounds never collect on the host'
    Remove-Item -LiteralPath $safeWorkspace -Recurse -Force

    $failedWorkspace = New-MarkedWorkspace -Name 'failed'
    $failed = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'RunValidationRound',
        '-ValidationRoundRequestPath', $oneClientPath,
        '-ValidationPrivateWorkspacePath', $failedWorkspace,
        '-ValidationRoundFixturePath', $failedFixturePath
    )
    Assert-Equal 10 $failed.ExitCode 'a bounded product failure ends CompletedWithGaps after cleanup'
    $failedOutcome = @($failed.Records | Where-Object recordType -eq 'win-pcinfo.azure-validation-round')
    $failedTerminal = @($failed.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 'FailedCleaned' $failedOutcome[0].state 'the generated application records the product failure'
    Assert-Equal $true $failedOutcome[0].teardownCompleted 'the generated application still tears down'
    Assert-Equal $true $failedOutcome[0].zeroResidue 'the generated application still proves zero residue'
    Assert-Equal 'CompletedWithGaps' $failedTerminal[0].outcome `
        'a cleaned product failure is not reported as complete success'
    Assert-Equal 'VALIDATION.ASSESSMENT_FAILED' $failedTerminal[0].reasonCode `
        'the terminal reason keeps the product failure visible'
    Remove-Item -LiteralPath $failedWorkspace -Recurse -Force

    $identityWorkspace = New-MarkedWorkspace -Name 'identity'
    $blocked = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'RunValidationRound',
        '-ValidationRoundRequestPath', $oneClientPath,
        '-ValidationPrivateWorkspacePath', $identityWorkspace,
        '-ValidationRoundFixturePath', $identityFixturePath
    )
    Assert-Equal 20 $blocked.ExitCode 'missing identity ends NotStarted'
    $blockedOutcome = @($blocked.Records | Where-Object recordType -eq 'win-pcinfo.azure-validation-round')
    $blockedTerminal = @($blocked.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 'Blocked' $blockedOutcome[0].state 'the generated application blocks missing identity'
    Assert-Equal $false $blockedOutcome[0].created 'missing identity never creates'
    Assert-Equal 'NotStarted' $blockedTerminal[0].outcome 'missing identity stays NotStarted'
    Assert-Equal 'VALIDATION.IDENTITY_UNAVAILABLE' $blockedTerminal[0].reasonCode `
        'the generated application uses the typed identity reason'
    Remove-Item -LiteralPath $identityWorkspace -Recurse -Force

    $residueWorkspace = New-MarkedWorkspace -Name 'residue'
    $residue = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'RunValidationRound',
        '-ValidationRoundRequestPath', $oneClientPath,
        '-ValidationPrivateWorkspacePath', $residueWorkspace,
        '-ValidationRoundFixturePath', $residueFixturePath
    )
    Assert-Equal 60 $residue.ExitCode 'remaining residue ends CleanupIncomplete'
    $residueOutcome = @($residue.Records | Where-Object recordType -eq 'win-pcinfo.azure-validation-round')
    $residueTerminal = @($residue.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 'ResidueRemains' $residueOutcome[0].state `
        'the generated application does not complete while residue remains'
    Assert-Equal $false $residueOutcome[0].zeroResidue `
        'the generated application does not invent zero residue'
    Assert-Equal $false $residueOutcome[0].terraformStateRemoved `
        'the generated application keeps private state while residue remains'
    Assert-Equal $false $residueOutcome[0].azureContacted `
        'the generated residue fixture does not contact Azure'
    Assert-Equal 'CleanupIncomplete' $residueTerminal[0].outcome `
        'remaining residue is CleanupIncomplete'
    Assert-Equal 'VALIDATION.RESIDUE_REMAINS' $residueTerminal[0].reasonCode `
        'the terminal reason keeps remaining residue visible'
    Assert-Equal $true (Test-Path -LiteralPath (
        Join-Path $residueWorkspace $policy.workspace.renderedDirectoryName
    )) 'the generated application keeps rendered admission files while residue remains'
    Remove-Item -LiteralPath $residueWorkspace -Recurse -Force

    $liveWorkspace = New-MarkedWorkspace -Name 'live'
    $live = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'RunValidationRound',
        '-ValidationRoundRequestPath', $oneClientPath,
        '-ValidationPrivateWorkspacePath', $liveWorkspace
    )
    $expectedLiveReason = if ([string]::IsNullOrWhiteSpace([string] $env:IDENTITY_ENDPOINT)) {
        'VALIDATION.IDENTITY_UNAVAILABLE'
    }
    else {
        'VALIDATION.TOOLING_UNRESOLVED'
    }
    Assert-Equal 20 $live.ExitCode 'live Azure without acquired tooling ends NotStarted'
    $liveOutcome = @($live.Records | Where-Object recordType -eq 'win-pcinfo.azure-validation-round')
    $liveTerminal = @($live.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal $expectedLiveReason $liveOutcome[0].reasonCode `
        'the generated live path stays NotStarted without identity and acquired tooling'
    Assert-Equal $false $liveOutcome[0].created 'the generated live path never creates'
    Assert-Equal $false $liveOutcome[0].azureContacted `
        'the generated live path does not contact Azure'
    Assert-Equal 'NotStarted' $liveTerminal[0].outcome 'the generated live path stays NotStarted'
    Remove-Item -LiteralPath $liveWorkspace -Recurse -Force

    $missing = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'RunValidationRound'
    )
    Assert-Equal 20 $missing.ExitCode 'a missing request ends NotStarted'
    $missingTerminal = @($missing.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 'NotStarted' $missingTerminal[0].outcome 'a missing request stays NotStarted'
    Assert-Equal 'VALIDATION.REQUEST_INVALID' $missingTerminal[0].reasonCode `
        'a missing request uses a stable reason'
}
finally {
    if (Test-Path -LiteralPath $workRoot) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
}

Write-Output 'PASS: generated-application validation rounds stay private, honest, and cleanup-first.'
