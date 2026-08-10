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

function Invoke-PrivilegeFixtureApplication {
    param([Parameter(Mandatory)] [string] $Name)

    Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation'
        '-RequestPath', $requestPath
        '-AcceptPreparation'
        '-PreparationFixturePath', $preparationPath
        '-PrivilegedFixturePath', (Join-Path $PSScriptRoot "fixtures/$Name.json")
    )
}

$cases = @(
    @{ Name = 'privilege-accepted-elevation'; Privilege = 'Completed'; Outcome = 'IntegrityFailed'; ExitCode = 50; StandardStarted = $true; Uac = 1 }
    @{ Name = 'privilege-already-elevated'; Privilege = 'Completed'; Outcome = 'IntegrityFailed'; ExitCode = 50; StandardStarted = $true; Uac = 0 }
    @{ Name = 'privilege-alternate-administrator'; Privilege = 'Completed'; Outcome = 'IntegrityFailed'; ExitCode = 50; StandardStarted = $true; Uac = 1 }
    @{ Name = 'privilege-elevation-denied'; Privilege = 'Unavailable'; Outcome = 'IntegrityFailed'; ExitCode = 50; StandardStarted = $true; Uac = 1 }
    @{ Name = 'privilege-wrong-pipe-client'; Privilege = 'IntegrityFailed'; Outcome = 'IntegrityFailed'; ExitCode = 50; StandardStarted = $false; Uac = 1 }
    @{ Name = 'privilege-altered-plan'; Privilege = 'IntegrityFailed'; Outcome = 'IntegrityFailed'; ExitCode = 50; StandardStarted = $false; Uac = 0 }
    @{ Name = 'privilege-lost-worker'; Privilege = 'IntegrityFailed'; Outcome = 'IntegrityFailed'; ExitCode = 50; StandardStarted = $false; Uac = 1 }
    @{ Name = 'privilege-timeout'; Privilege = 'TimedOut'; Outcome = 'TimedOut'; ExitCode = 40; StandardStarted = $false; Uac = 1 }
    @{ Name = 'privilege-cancellation'; Privilege = 'Cancelled'; Outcome = 'Cancelled'; ExitCode = 30; StandardStarted = $false; Uac = 1 }
)
foreach ($case in $cases) {
    $result = Invoke-PrivilegeFixtureApplication -Name $case.Name
    $privilegeRecords = @($result.Records | Where-Object recordType -eq 'win-pcinfo.privileged-phase')
    $terminalRecords = @($result.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $privilegeRecords.Count "$($case.Name) emits one sanitized privilege result"
    Assert-Equal 1 $terminalRecords.Count "$($case.Name) emits exactly one terminal result"
    Assert-Equal $case.Privilege $privilegeRecords[0].state `
        "$($case.Name) preserves the privilege outcome"
    Assert-Equal $case.Outcome $terminalRecords[0].outcome `
        "$($case.Name) maps to one honest Assessment Run Outcome"
    Assert-Equal $case.ExitCode $result.ExitCode `
        "$($case.Name) returns the matching stable exit code"
    Assert-Equal $case.StandardStarted $terminalRecords[0].scheduling.standardOperationStarted `
        "$($case.Name) schedules standard work only when the privilege result permits it"
    Assert-Equal $case.Uac $terminalRecords[0].privilege.uacInteractionCount `
        "$($case.Name) respects the one-UAC ceiling"
    Assert-Equal $true $terminalRecords[0].cleanup.verified `
        "$($case.Name) removes its worker, pipe, and synthetic process residue"
    Assert-Equal $true $terminalRecords[0].validationFixture `
        "$($case.Name) cannot look like real privileged evidence"
    if ($result.StandardError) { throw "$($case.Name) wrote stderr: $($result.StandardError)" }
}

$denied = Invoke-PrivilegeFixtureApplication -Name 'privilege-elevation-denied'
$deniedTerminal = @($denied.Records | Where-Object recordType -eq 'win-pcinfo.terminal')[0]
Assert-Equal 'Unavailable' $deniedTerminal.coverage[0].state `
    'elevation denial reports unavailable privileged coverage'
Assert-Equal 'Complete' $deniedTerminal.coverage[1].state `
    'elevation denial still permits unrelated safe standard-user evidence'

$invalidRoot = Join-Path $repositoryRoot '.test-output/privileged-plan-application'
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
    '-PrivilegedFixturePath', $invalidPath
)
Assert-Equal 20 $invalid.ExitCode 'an ambiguous privilege fixture fails before worker launch'
Assert-Equal 'PRIVILEGE.FIXTURE_INVALID' $invalid.Records[-1].reasonCode `
    'invalid privilege fixture input has one sanitized reason'

Write-Output 'PASS: the generated application exposes all nine synthetic privilege paths and denial continuation.'
