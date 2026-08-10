[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

function Invoke-SystemFixtureApplication {
    param([Parameter(Mandatory)] [string] $Name)

    Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation'
        '-RequestPath', $requestPath
        '-AcceptPreparation'
        '-PreparationFixturePath', $preparationPath
        '-SystemCollectionFixturePath', (Join-Path $PSScriptRoot "fixtures/$Name.json")
    )
}

$cases = @(
    @{ Name = 'system-synthetic-success'; System = 'Completed'; Reason = 'SYSTEM.COMPLETED'; Outcome = 'IntegrityFailed'; ExitCode = 50; Standard = $true }
    @{ Name = 'system-unknown-operation'; System = 'IntegrityFailed'; Reason = 'SYSTEM.OPERATION_INVALID'; Outcome = 'IntegrityFailed'; ExitCode = 50; Standard = $false }
    @{ Name = 'system-invalid-parameters'; System = 'IntegrityFailed'; Reason = 'SYSTEM.PARAMETERS_INVALID'; Outcome = 'IntegrityFailed'; ExitCode = 50; Standard = $false }
    @{ Name = 'system-activation-failure'; System = 'Unavailable'; Reason = 'SYSTEM.ACTIVATION_FAILED'; Outcome = 'IntegrityFailed'; ExitCode = 50; Standard = $true }
    @{ Name = 'system-worker-lost'; System = 'Failed'; Reason = 'SYSTEM.WORKER_LOST'; Outcome = 'IntegrityFailed'; ExitCode = 50; Standard = $true }
    @{ Name = 'system-cancellation'; System = 'Cancelled'; Reason = 'SYSTEM.CANCELLED'; Outcome = 'Cancelled'; ExitCode = 30; Standard = $false }
    @{ Name = 'system-timeout'; System = 'TimedOut'; Reason = 'SYSTEM.DEADLINE_EXCEEDED'; Outcome = 'IntegrityFailed'; ExitCode = 50; Standard = $true }
    @{ Name = 'system-denied'; System = 'Unavailable'; Reason = 'SYSTEM.ACTIVATION_DENIED'; Outcome = 'IntegrityFailed'; ExitCode = 50; Standard = $true }
    @{ Name = 'system-abnormal-cleanup'; System = 'Completed'; Reason = 'SYSTEM.COMPLETED'; Outcome = 'IntegrityFailed'; ExitCode = 50; Standard = $true }
)
foreach ($case in $cases) {
    $result = Invoke-SystemFixtureApplication -Name $case.Name
    $systemRecords = @($result.Records | Where-Object recordType -eq 'win-pcinfo.system-collection-phase')
    $terminalRecords = @($result.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $systemRecords.Count "$($case.Name) emits one sanitized SYSTEM result"
    Assert-Equal 1 $terminalRecords.Count "$($case.Name) emits exactly one terminal result"
    Assert-Equal $case.System $systemRecords[0].state `
        "$($case.Name) preserves the scoped SYSTEM outcome"
    Assert-Equal $case.Reason $systemRecords[0].reasonCode `
        "$($case.Name) preserves the stable SYSTEM reason"
    Assert-Equal $case.Outcome $terminalRecords[0].outcome `
        "$($case.Name) maps to one honest Assessment Run Outcome"
    Assert-Equal $case.ExitCode $result.ExitCode `
        "$($case.Name) returns the matching stable exit code"
    Assert-Equal $case.Standard $terminalRecords[0].scheduling.standardOperationStarted `
        "$($case.Name) confines scoped failures and closes scheduling on integrity or cancellation"
    Assert-Equal $true $terminalRecords[0].cleanup.verified `
        "$($case.Name) removes its task, worker tree, pipe, and synthetic process residue"
    Assert-Equal $true $terminalRecords[0].validationFixture `
        "$($case.Name) cannot look like real LocalSystem evidence"
    Assert-Equal 'Synthetic' $systemRecords[0].collectorResult.Envelope.executionContext `
        "$($case.Name) records honest synthetic execution provenance"
    Assert-Equal 'LocalSystem' $systemRecords[0].activation.requiredExecutionContext `
        "$($case.Name) retains the source's exact live execution requirement"
    Assert-Equal $false $systemRecords[0].activation.localSystemIdentityVerified `
        "$($case.Name) never claims live LocalSystem identity"
    if ($result.StandardError) { throw "$($case.Name) wrote stderr: $($result.StandardError)" }
}

$success = Invoke-SystemFixtureApplication -Name 'system-synthetic-success'
$successSystem = @($success.Records | Where-Object recordType -eq 'win-pcinfo.system-collection-phase')[0]
Assert-Equal 'collector:windows.mdm-bridge.device-manageability' `
    $successSystem.collectorResult.Envelope.collectorId `
    'the generated artifact returns SYSTEM evidence through the normal envelope shape'
Assert-Equal 'scope:device.mdm-policy.system' `
    $successSystem.collectorResult.Coverage[0].scopeId `
    'the generated artifact confines evidence to the declared SYSTEM scope'

$invalidRoot = Join-Path $repositoryRoot '.test-output/system-collection-plan-application'
$null = New-Item -ItemType Directory -Path $invalidRoot -Force
$invalidPath = Join-Path $invalidRoot 'duplicate-scenario.json'
[System.IO.File]::WriteAllText(
    $invalidPath,
    '{"contractVersion":"1.0.0","scenario":"Timeout","scenario":"Cancellation"}',
    [System.Text.UTF8Encoding]::new($false)
)
$invalid = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
    '-Mode', 'Automation'
    '-RequestPath', $requestPath
    '-AcceptPreparation'
    '-PreparationFixturePath', $preparationPath
    '-SystemCollectionFixturePath', $invalidPath
)
Assert-Equal 20 $invalid.ExitCode 'an ambiguous SYSTEM fixture fails before worker launch'
Assert-Equal 'SYSTEM.FIXTURE_INVALID' $invalid.Records[-1].reasonCode `
    'invalid SYSTEM fixture input has one sanitized reason'

Write-Output 'PASS: the generated application exposes all nine SYSTEM paths with scoped continuation and verified cleanup.'
