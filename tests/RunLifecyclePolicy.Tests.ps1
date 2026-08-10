[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-run-lifecycle.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/run-lifecycle.schema.json'
. (Join-Path $repositoryRoot 'src/RunLifecycle.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policyJson = [System.IO.File]::ReadAllText($policyPath)
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the release lifecycle policy satisfies its Draft 2020-12 schema'
$policy = $policyJson | ConvertFrom-Json -Depth 20

Assert-Equal 'win-pcinfo.run-lifecycle/1.0.0' $policy.policyId `
    'the generated and modular interfaces bind one versioned lifecycle policy'
Assert-Equal 'Global\WINPCInfo-AssessmentRun-v1' $policy.activeRunLock.name `
    'the Active Run Lock has one release-defined device-wide identity'
Assert-Equal 1 $policy.deadlines.operation.maximumAttempts `
    'the tracer-bullet operation cannot retry without bound'
Assert-Equal 7 @($policy.outcomes).Count 'all Assessment Run Outcomes have an exit mapping'
Assert-Equal 7 @($policy.outcomes.exitCode | Sort-Object -Unique).Count `
    'every Assessment Run Outcome has a distinct stable exit code'
foreach ($mapping in @($policy.outcomes)) {
    Assert-Equal $mapping.exitCode (Get-AssessmentRunExitCode -Outcome $mapping.outcome) `
        "$($mapping.outcome) uses the release-owned exit code"
}
foreach ($deadline in @(
    $policy.deadlines.run.maximumMilliseconds
    $policy.deadlines.operation.maximumMilliseconds
    $policy.deadlines.process.maximumMilliseconds
    $policy.deadlines.phases.maximumMilliseconds
)) {
    if ([int] $deadline -le 0) { throw 'Every lifecycle deadline must be finite and positive.' }
}

$collectorCatalog = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-approved-collectors.json'
) -Raw | ConvertFrom-Json -Depth 20
$operation = $collectorCatalog.collectors[0].operations[0]
Assert-Equal $operation.deadlineMilliseconds $policy.deadlines.process.maximumMilliseconds `
    'the lifecycle process deadline agrees with the approved collector contract'
Assert-Equal $operation.cancellationGraceMilliseconds `
    $policy.deadlines.process.cancellationGraceMilliseconds `
    'cooperative cancellation uses the approved process grace'
Assert-Equal $operation.terminationVerificationMilliseconds `
    $policy.deadlines.process.terminationVerificationMilliseconds `
    'hard termination verification uses the approved process bound'

Write-Output 'PASS: the release lifecycle policy closes locks, deadlines, retry, timing, and exit semantics.'
