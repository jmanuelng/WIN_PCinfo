[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationFixturePath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
$positiveFixturePath = Join-Path $PSScriptRoot 'fixtures/contract-positive.json'
$generatedFixtureRoot = Join-Path $repositoryRoot '.test-output/contract-semantic-matrix'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$null = New-Item -ItemType Directory -Path $generatedFixtureRoot -Force
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

function Write-DerivedSyntheticFixture {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [scriptblock] $Mutate
    )

    $record = Get-Content -LiteralPath $positiveFixturePath -Raw | ConvertFrom-Json -Depth 30
    & $Mutate $record
    $path = Join-Path $generatedFixtureRoot "$Name.json"
    [System.IO.File]::WriteAllText(
        $path,
        ($record | ConvertTo-Json -Compress -Depth 30),
        [System.Text.UTF8Encoding]::new($false)
    )
    $path
}

$cases = @(
    @{
        Name = 'incomplete-record'
        Expected = 'CONTRACT.SCHEMA_INVALID'
        Mutate = { param($record) $record.PSObject.Properties.Remove('findings') }
    }
    @{
        Name = 'ambiguous-subject-reference'
        Expected = 'CONTRACT.REFERENCE_AMBIGUOUS'
        Mutate = { param($record) $record.subjects += $record.subjects[0].PSObject.Copy() }
    }
    @{
        Name = 'observation-value-state-conflict'
        Expected = 'CONTRACT.OBSERVATION_STATE_INCONSISTENT'
        Mutate = { param($record) $record.observations[0].PSObject.Properties.Remove('value') }
    }
    @{
        Name = 'finding-state-conflict'
        Expected = 'CONTRACT.FINDING_STATE_INCONSISTENT'
        Mutate = { param($record) $record.findings[0].outcome = 'ExpectedCondition' }
    }
    @{
        Name = 'run-state-conflict'
        Expected = 'CONTRACT.RUN_STATE_INCONSISTENT'
        Mutate = { param($record) $record.run.outcome = 'Completed' }
    }
    @{
        Name = 'collector-coverage-conflict'
        Expected = 'CONTRACT.COVERAGE_INCONSISTENT'
        Mutate = { param($record) $record.collectorResults[0].coverageIds = @() }
    }
    @{
        Name = 'collector-provenance-conflict'
        Expected = 'CONTRACT.ENVELOPE_INCONSISTENT'
        Mutate = { param($record) $record.collectorResults[0].collectorId = 'collector:synthetic.other' }
    }
    @{
        Name = 'orphan-diagnostic'
        Expected = 'CONTRACT.COVERAGE_INCONSISTENT'
        Mutate = {
            param($record)
            $record.coverage[0].state = 'Partial'
            $record.coverage[0].reasonCode = 'COVERAGE.SYNTHETIC_PARTIAL'
            $record.coverage[0].diagnosticIds = @()
            $record.collectorResults[0].diagnosticIds = @()
        }
    }
    @{
        Name = 'field-type-conflict'
        Expected = 'CONTRACT.FIELD_TYPE_INVALID'
        Mutate = { param($record) $record.observations[0].value = $true }
    }
    @{
        Name = 'undeclared-scope'
        Expected = 'CONTRACT.COVERAGE_INCONSISTENT'
        Mutate = {
            param($record)
            $record.coverage[0].scopeId = 'scope:synthetic.renamed'
            $record.diagnostics[0].scopeId = 'scope:synthetic.renamed'
            $record.collectorResults[0].intendedScopeIds = @('scope:synthetic.renamed')
        }
    }
    @{
        Name = 'not-started-with-collected-evidence'
        Expected = 'CONTRACT.RUN_STATE_INCONSISTENT'
        Mutate = { param($record) $record.run.outcome = 'NotStarted' }
    }
    @{
        Name = 'cancelled-without-cancelled-coverage'
        Expected = 'CONTRACT.RUN_STATE_INCONSISTENT'
        Mutate = { param($record) $record.run.outcome = 'Cancelled' }
    }
    @{
        Name = 'timed-out-without-timed-out-coverage'
        Expected = 'CONTRACT.RUN_STATE_INCONSISTENT'
        Mutate = { param($record) $record.run.outcome = 'TimedOut' }
    }
    @{
        Name = 'integrity-failed-without-integrity-diagnostic'
        Expected = 'CONTRACT.RUN_STATE_INCONSISTENT'
        Mutate = { param($record) $record.run.outcome = 'IntegrityFailed' }
    }
    @{
        Name = 'cleanup-incomplete-without-cleanup-diagnostic'
        Expected = 'CONTRACT.RUN_STATE_INCONSISTENT'
        Mutate = { param($record) $record.run.outcome = 'CleanupIncomplete' }
    }
    @{
        Name = 'envelope-subject-conflict'
        Expected = 'CONTRACT.ENVELOPE_INCONSISTENT'
        Mutate = {
            param($record)
            $record.subjects += [pscustomobject][ordered]@{
                subjectId = 'subject:synthetic-device:other'
                kind = 'Device'
            }
            $record.collectorResults[0].subjectIds = @('subject:synthetic-device:other')
        }
    }
    @{
        Name = 'self-conflicting-recommendation'
        Expected = 'CONTRACT.GRAPH_INVALID'
        Mutate = {
            param($record)
            $record.recommendationRelationships = @(
                [pscustomobject][ordered]@{
                    relationshipId = 'relationship:synthetic:self-conflict'
                    fromRecommendationId = 'recommendation:synthetic-follow-up:001'
                    toRecommendationId = 'recommendation:synthetic-follow-up:001'
                    kind = 'ConflictsWith'
                }
            )
        }
    }
)

foreach ($case in $cases) {
    $fixturePath = Write-DerivedSyntheticFixture -Name $case.Name -Mutate $case.Mutate
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation',
        '-RequestPath', $requestPath,
        '-AcceptPreparation',
        '-PreparationFixturePath', $preparationFixturePath,
        '-ContractFixturePath', $fixturePath
    )
    $validation = @($result.Records | Where-Object recordType -eq 'win-pcinfo.contract-validation')[0]
    Assert-Equal $false $validation.accepted "$($case.Name) is rejected"
    Assert-Equal $case.Expected $validation.reasonCode "$($case.Name) has its stable semantic reason"
    Assert-Equal $false $result.Records[-1].collectionStarted "$($case.Name) cannot start collection"
}

$positive = Get-Content -LiteralPath $positiveFixturePath -Raw | ConvertFrom-Json -Depth 30
Assert-Equal 'fr-FR' $positive.provenance[0].sourceLocale 'the locale fixture is explicit and non-English'
if ([string] $positive.observations[0].value -notmatch '[^\x00-\x7F]') {
    throw 'The positive fixture must exercise non-ASCII Unicode.'
}

Write-Output "PASS: $($cases.Count) incomplete/state/reference fixtures fail closed and the locale fixture remains explicit."
