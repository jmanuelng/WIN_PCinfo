[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-CatalogEqual {
    param($Expected, $Actual, [string] $Because)
    if ($Expected -ne $Actual) { throw "Expected '$Expected' but received '$Actual': $Because" }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$catalogPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-approved-collectors.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/approved-collector-catalog.schema.json'

$catalogJson = [System.IO.File]::ReadAllText($catalogPath, [System.Text.UTF8Encoding]::new($false, $true))
Assert-CatalogEqual $true (Test-Json -Json $catalogJson -SchemaFile $schemaPath) `
    'the release collector catalog satisfies its Draft 2020-12 schema'
$catalog = $catalogJson | ConvertFrom-Json -Depth 30

Assert-CatalogEqual '2.0.0-preview.1' $catalog.release 'the process contract is release-bound'
Assert-CatalogEqual 'ActivePowerShellHost' $catalog.collectors[0].executable.resolver `
    'PATH search and caller-selected executable paths are unavailable'
Assert-CatalogEqual 'pwsh.exe' $catalog.collectors[0].executable.fileName `
    'the literal resolved executable name is fixed'
Assert-CatalogEqual 'Microsoft Corporation' $catalog.collectors[0].executable.signerCommonName `
    'the approved publisher identity is explicit'
Assert-CatalogEqual $false $catalog.collectors[0].environment.inheritParent `
    'the collector cannot inherit ambient secrets or unbounded environment values'
Assert-CatalogEqual 'ActivePowerShellHome' $catalog.collectors[0].workingBoundary.kind `
    'the working directory resolves to the validated active PowerShell installation'
Assert-CatalogEqual 'EncodedReleaseSource' $catalog.collectors[0].payload.kind `
    'the collector payload crosses no writable script-path boundary'
Assert-CatalogEqual 'WindowsJobObjectRequired' $catalog.collectors[0].treeControl.mode `
    'the release does not claim a root-only process fallback'
Assert-CatalogEqual 'NotStarted' $catalog.collectors[0].treeControl.incompatibleDisposition `
    'Job incompatibility fails before collector code runs'
Assert-CatalogEqual 2 @($catalog.collectors).Count `
    'the legacy synthetic and real Device Readiness collectors have distinct identities'
Assert-CatalogEqual 1 @($catalog.collectors[0].operations).Count `
    'the synthetic collector exposes only its legacy probe'
Assert-CatalogEqual 8 @($catalog.validationFixtures).Count `
    'the eight negative and lifecycle fixtures accompany the approved success operation'

$operation = $catalog.collectors[0].operations[0]
Assert-CatalogEqual 'op:synthetic.windows.os.success' $operation.operationId `
    'the approved operation has a stable identity'
Assert-CatalogEqual 5000 $operation.deadlineMilliseconds 'the operation cannot wait indefinitely'
Assert-CatalogEqual 4096 $operation.standardOutputMaximumBytes 'stdout has an independent byte limit'
Assert-CatalogEqual 4096 $operation.standardErrorMaximumBytes 'stderr has an independent byte limit'
Assert-CatalogEqual 750 $operation.cancellationGraceMilliseconds `
    'cooperative cancellation has a bounded grace interval before hard termination'
Assert-CatalogEqual 2000 $operation.terminationVerificationMilliseconds `
    'hard termination verification cannot wait indefinitely'
$deviceOperation = $catalog.collectors[1].operations[0]
Assert-CatalogEqual 'collector:windows.device-readiness' $catalog.collectors[1].collectorId `
    'real device evidence never carries the synthetic collector identity'
Assert-CatalogEqual 'op:device.windows-readiness.collect' $deviceOperation.operationId `
    'Device Readiness has a separate stable approved operation identity'
Assert-CatalogEqual 8192 $deviceOperation.standardOutputMaximumBytes `
    'the larger structured device payload remains independently bounded'
if ($catalog.collectors[0].payload.sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'The staged synthetic collector payload needs an exact release identity.'
}

$fixtureIds = @($catalog.validationFixtures.fixtureId)
foreach ($requiredFixture in @(
    'wrong-executable', 'invalid-argument', 'excess-output', 'timeout',
    'cooperative-cancel', 'hard-cancel', 'child-process', 'incompatible-child'
)) {
    if ($requiredFixture -notin $fixtureIds) { throw "Required process fixture is missing: $requiredFixture" }
}

Write-Output 'PASS: the release catalog closes executable, arguments, environment, working boundary, timing, output, cancellation, and tree-control policy.'
