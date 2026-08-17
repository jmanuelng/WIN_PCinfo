[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-release-gates.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/release-gates.schema.json'
$packSchemaPath = Join-Path $repositoryRoot 'schemas/release-evidence-pack.schema.json'
$manifestSchemaPath = Join-Path $repositoryRoot 'schemas/release-evidence-manifest.schema.json'
$matrixSchemaPath = Join-Path $repositoryRoot 'schemas/preview-capability-matrix.schema.json'
$completePackPath = Join-Path $PSScriptRoot 'fixtures/release-evidence-pack-complete-presigning.json'
$finalPackPath = Join-Path $PSScriptRoot 'fixtures/release-evidence-pack-complete-final.json'

Assert-Equal $true (Test-Path -LiteralPath $policyPath -PathType Leaf) `
    'the release-gate contract is release-declared'
Assert-Equal $true (Test-Path -LiteralPath $schemaPath -PathType Leaf) `
    'the release-gate contract has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $packSchemaPath -PathType Leaf) `
    'the synthetic evidence pack has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $manifestSchemaPath -PathType Leaf) `
    'the Release Evidence Manifest has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $matrixSchemaPath -PathType Leaf) `
    'the Preview Capability Matrix has a closed public schema'

$policyJson = Get-Content -LiteralPath $policyPath -Raw
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the release-gate contract satisfies its exact schema'
$policy = $policyJson | ConvertFrom-Json -Depth 20

Assert-Equal 'win-pcinfo.release-gates/1.0.0' $policy.policyId `
    'the gate contract has a stable release identity'
Assert-Equal 'CAP-0030' $policy.productCapability `
    'the gate traces to automated deterministic release gates'
Assert-Equal $false $policy.sliceDeliversCapability `
    'this slice does not mark the Product Capability delivered'
Assert-Equal 'None' $policy.supportClaim 'the contract makes no support claim'
Assert-Equal 'None' $policy.previewOrStableClaim 'the contract makes no Preview claim'
Assert-Equal $false $policy.publicationAuthorized `
    'this slice cannot authorize publication'
Assert-Equal $false $policy.supportedPromotionPermitted `
    'Preview.1 cannot promote a Supported claim'
Assert-Equal '1.0.0' $policy.qualityBudget.version 'the quality budget version is frozen'
Assert-Equal 5000 $policy.qualityBudget.binding.firstProgressMilliseconds `
    'first structured progress is bound at five seconds'
Assert-Equal 10000 $policy.qualityBudget.binding.heartbeatGapMilliseconds `
    'the active heartbeat gap is bound at ten seconds'
Assert-Equal 2000 $policy.qualityBudget.binding.cancellationAckMilliseconds `
    'cancellation acknowledgement is bound at two seconds'
Assert-Equal 3 $policy.qualityBudget.previewCleanMeasurementCount `
    'Preview requires three clean measurements'
Assert-Equal 1 $policy.qualityBudget.infrastructureReplacementAttempts `
    'one infrastructure replacement is the maximum'
Assert-Equal $true $policy.qualityBudget.provisional.enforced `
    'provisional ceilings are still enforced'
Assert-Equal 30 $policy.freshness.clientVmValidationDays `
    'Client VM evidence expires after 30 days'
Assert-Equal 90 $policy.freshness.cloudIdentityManagementSecurityNetworkDays `
    'cloud and network evidence expires after 90 days'
Assert-Equal 365 $policy.freshness.physicalFirmwareOemBatteryPeripheralDays `
    'physical evidence expires after 12 months'
Assert-Equal $false $policy.waiver.manualPromotionAllowed `
    'missing or failed evidence cannot be waived'
Assert-Equal $true $policy.privacy.rejectNonSynthetic `
    'non-synthetic packs cannot enter the public gate'

$requiredResults = @(
    'Pass', 'ProductFail', 'InfrastructureInconclusive', 'NotRun', 'Expired', 'Invalidated'
)
foreach ($result in $requiredResults) {
    Assert-Equal $true ($result -in @($policy.evidenceResults)) `
        "the contract names the controlled result $result"
}

$releaseDefinition = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1.json'
) -Raw | ConvertFrom-Json -Depth 20
foreach ($requiredGate in @($releaseDefinition.requiredReleaseEvidence)) {
    Assert-Equal $true ($requiredGate -in @($policy.requiredGates)) `
        "the gate contract includes release-required evidence $requiredGate"
}

foreach ($fixturePath in @($completePackPath, $finalPackPath)) {
    $fixtureJson = Get-Content -LiteralPath $fixturePath -Raw
    Assert-Equal $true (Test-Json -Json $fixtureJson -SchemaFile $packSchemaPath) `
        "$(Split-Path -Leaf $fixturePath) satisfies the public pack schema"
    Assert-Equal $true ($fixtureJson -match '"synthetic"\s*:\s*true') `
        "$(Split-Path -Leaf $fixturePath) is marked synthetic"
    foreach ($needle in @(
        '(?i)/subscriptions/'
        '(?i)\btenant\b'
        '(?i)clientSecret'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)\.terraform'
        '(?i)\.tfstate'
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
    )) {
        Assert-Equal $false ($fixtureJson -match $needle) `
            "$(Split-Path -Leaf $fixturePath) contains no private identifier matching $needle"
    }
}

$operatorDoc = Get-Content -LiteralPath (Join-Path $repositoryRoot 'docs/release-gates.md') -Raw
Assert-Equal $true ($operatorDoc -match 'EvaluateReleaseGates') `
    'beginner documentation names the generated-application workflow'
Assert-Equal $true ($operatorDoc -match 'Pass, ProductFail, InfrastructureInconclusive, NotRun, Expired, and Invalidated') `
    'beginner documentation names every controlled evidence result'
Assert-Equal $true ($operatorDoc -match 'cannot be averaged or waived') `
    'beginner documentation states that missing evidence cannot be averaged or waived'
Assert-Equal $false ($operatorDoc -match '(?i)/subscriptions/') `
    'beginner documentation contains no Azure subscription path'

$projection = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/validation/issue-69-release-gates.md'
) -Raw
Assert-Equal $true ($projection -match 'identifier-free') `
    'the public validation projection stays identifier-free'
Assert-Equal $false ($projection -match '(?i)clientSecret') `
    'the public validation projection contains no secret material'

Write-Output 'PASS: release-gate policy, schemas, and beginner documentation are closed.'
