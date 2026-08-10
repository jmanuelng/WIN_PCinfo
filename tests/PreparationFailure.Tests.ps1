[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$testRoot = Join-Path $repositoryRoot '.test-output/preparation-failure'
$fixtureRoot = Join-Path $testRoot 'fixtures'
$workingRoot = Join-Path $testRoot 'work'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$null = New-Item -ItemType Directory -Path $fixtureRoot -Force
$null = New-Item -ItemType Directory -Path $workingRoot -Force
$sentinelPath = Join-Path $workingRoot 'sentinel.txt'
[System.IO.File]::WriteAllText($sentinelPath, 'synthetic public-safe sentinel', [System.Text.UTF8Encoding]::new($false))

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$cases = @(
    @{
        Name = 'missing-prerequisite'
        Facts = @{ contractVersion = '1.0.0'; definitionIntegrityValid = $true; criticalPrerequisitesAvailable = $false }
        Expected = 'PREPARATION.PREREQUISITE_UNRESOLVED'
        ExpectedSummaryCount = 1
        ExpectedDecision = 'Unavailable'
    }
    @{
        Name = 'integrity-failed'
        Facts = @{ contractVersion = '1.0.0'; definitionIntegrityValid = $false; criticalPrerequisitesAvailable = $true }
        Expected = 'PREPARATION.INTEGRITY_FAILED'
        ExpectedSummaryCount = 0
        ExpectedDecision = $null
    }
)

foreach ($case in $cases) {
    $fixturePath = Join-Path $fixtureRoot "$($case.Name).json"
    [System.IO.File]::WriteAllText(
        $fixturePath,
        ($case.Facts | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    $beforeNames = @(Get-ChildItem -LiteralPath $workingRoot -Force | Select-Object -ExpandProperty Name)
    $beforeDigest = (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath -WorkingDirectory $workingRoot `
        -Arguments @(
            '-Mode', 'Automation', '-RequestPath', $requestPath, '-AcceptPreparation',
            '-PreparationFixturePath', $fixturePath
        )
    $terminal = $result.Records[-1]
    $afterNames = @(Get-ChildItem -LiteralPath $workingRoot -Force | Select-Object -ExpandProperty Name)
    $afterDigest = (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash

    Assert-Equal 20 $result.ExitCode "$($case.Name) remains NotStarted"
    Assert-Equal $case.Expected $terminal.reasonCode "$($case.Name) has a stable fail-closed reason"
    Assert-Equal $false $terminal.collectionStarted "$($case.Name) cannot collect"
    Assert-Equal $true $terminal.validationFixture "$($case.Name) is explicitly validation-only"
    Assert-Equal $case.ExpectedSummaryCount `
        @($result.Records | Where-Object recordType -eq 'win-pcinfo.preparation-summary').Count `
        "$($case.Name) emits a summary only when its definition is trusted"
    Assert-Equal ($beforeNames -join '|') ($afterNames -join '|') "$($case.Name) creates no files"
    Assert-Equal $beforeDigest $afterDigest "$($case.Name) changes no pre-existing file"
    if ($null -ne $case.ExpectedDecision) {
        Assert-Equal $case.ExpectedDecision $terminal.preparationDecision `
            "$($case.Name) cannot be approved or bypassed"
    }
}

# Corrupt the actual embedded definition while preserving valid PowerShell. This
# proves the runtime digest gate itself, independently of the validation fixture.
$tamperedPath = Join-Path $testRoot 'WIN-PCInfo-tampered.ps1'
$candidateText = [System.IO.File]::ReadAllText($candidatePath)
$tamperedText = [regex]::Replace(
    $candidateText,
    "(?m)(PreparationDefinitionBase64 = ')([A-Za-z0-9+/])",
    '${1}A',
    1
)
if ($tamperedText -eq $candidateText) { throw 'The integrity test did not alter the generated definition.' }
[System.IO.File]::WriteAllText($tamperedPath, $tamperedText, [System.Text.UTF8Encoding]::new($true))
$tampered = Invoke-GeneratedApplication -CandidatePath $tamperedPath -WorkingDirectory $workingRoot `
    -Arguments @('-Mode', 'Automation', '-RequestPath', $requestPath, '-AcceptPreparation')
Assert-Equal 'PREPARATION.INTEGRITY_FAILED' $tampered.Records[-1].reasonCode `
    'an actual embedded-definition digest mismatch cannot be bypassed'
Assert-Equal $false $tampered.Records[-1].validationFixture `
    'the real digest gate does not depend on fixture labeling'
Assert-Equal $false $tampered.Records[-1].collectionStarted `
    'a corrupt governing definition cannot collect'

Write-Output 'PASS: missing prerequisites and integrity failure stop without side effects or collection.'
