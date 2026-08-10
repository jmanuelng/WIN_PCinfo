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

function Invoke-RunFixtureApplication {
    param([Parameter(Mandatory)] [string] $Name)

    Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation'
        '-RequestPath', $requestPath
        '-AcceptPreparation'
        '-PreparationFixturePath', $preparationPath
        '-RunFixturePath', (Join-Path $PSScriptRoot "fixtures/$Name.json")
    )
}

$cases = @(
    @{ Name = 'run-timeout'; Outcome = 'TimedOut'; ExitCode = 40; Coverage = 'TimedOut' }
    @{ Name = 'run-cancellation'; Outcome = 'Cancelled'; ExitCode = 30; Coverage = 'Cancelled' }
    @{ Name = 'run-package-unavailable'; Outcome = 'IntegrityFailed'; ExitCode = 50; Coverage = 'Complete' }
)
foreach ($case in $cases) {
    $result = Invoke-RunFixtureApplication -Name $case.Name
    $terminalRecords = @($result.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $terminalRecords.Count "$($case.Name) emits exactly one terminal record"
    $terminal = $terminalRecords[0]
    Assert-Equal $case.ExitCode $result.ExitCode "$($case.Name) returns its matching stable exit code"
    Assert-Equal $case.Outcome $terminal.outcome "$($case.Name) preserves its terminal outcome"
    Assert-Equal $case.Coverage $terminal.coverage[0].state "$($case.Name) keeps terminal coverage consistent"
    Assert-Equal $true $terminal.validationFixture "$($case.Name) remains visibly synthetic"
    Assert-Equal $true $terminal.cleanup.verified "$($case.Name) verifies owned cleanup"
    if ($terminal.outcome -in @('Completed', 'CompletedWithGaps')) {
        throw 'The generated application exposed completion before the real Protected Package finalizer exists.'
    }
    if ($result.StandardError) { throw "Generated run fixture wrote stderr: $($result.StandardError)" }
}

$cancellation = Invoke-RunFixtureApplication -Name 'run-cancellation'
$acknowledgement = @($cancellation.Records | Where-Object {
    $_.recordType -eq 'win-pcinfo.progress' -and $_.state -eq 'Acknowledged'
})
Assert-Equal 1 $acknowledgement.Count 'generated cancellation emits one structured acknowledgement'
if ($cancellation.Records[-1].metrics.cancellationAcknowledgementMilliseconds -gt 2000) {
    throw 'Generated cancellation exceeded the two-second acknowledgement budget.'
}

$invalidFixtureRoot = Join-Path $repositoryRoot '.test-output/run-application'
$null = New-Item -ItemType Directory -Path $invalidFixtureRoot -Force
$duplicateFixturePath = Join-Path $invalidFixtureRoot 'duplicate-scenario.json'
[System.IO.File]::WriteAllText(
    $duplicateFixturePath,
    '{"contractVersion":"1.0.0","scenario":"Timeout","scenario":"Cancellation"}',
    [System.Text.UTF8Encoding]::new($false)
)
$duplicateFixture = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
    '-Mode', 'Automation'
    '-RequestPath', $requestPath
    '-AcceptPreparation'
    '-PreparationFixturePath', $preparationPath
    '-RunFixturePath', $duplicateFixturePath
)
Assert-Equal 20 $duplicateFixture.ExitCode 'duplicate fixture properties fail before collection'
Assert-Equal 'RUN.FIXTURE_INVALID' $duplicateFixture.Records[-1].reasonCode `
    'lexically ambiguous lifecycle fixtures have one sanitized reason'
Assert-Equal $false $duplicateFixture.Records[-1].collectionStarted `
    'an invalid lifecycle fixture cannot start the approved collector'

Write-Output 'PASS: the generated application exposes bounded synthetic lifecycle failures without claiming completion.'
