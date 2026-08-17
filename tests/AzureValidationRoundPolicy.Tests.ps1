[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-azure-validation-round.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-round.schema.json'
$fixtureSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-round-execution-request.schema.json'
$outcomeSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-round-outcome.schema.json'

Assert-Equal $true (Test-Path -LiteralPath $policyPath -PathType Leaf) `
    'the Azure validation-round contract is release-declared'
Assert-Equal $true (Test-Path -LiteralPath $schemaPath -PathType Leaf) `
    'the Azure validation-round contract has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $fixtureSchemaPath -PathType Leaf) `
    'the synthetic round fixture has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $outcomeSchemaPath -PathType Leaf) `
    'the sanitized round outcome has a closed public schema'

$policyJson = Get-Content -LiteralPath $policyPath -Raw
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the Azure validation-round contract satisfies its exact schema'
$policy = $policyJson | ConvertFrom-Json -Depth 20

Assert-Equal 'win-pcinfo.azure-validation-round/1.0.0' $policy.policyId `
    'the round contract has a stable release identity'
Assert-Equal 'CAP-0028' $policy.productCapability `
    'the round traces to Fresh Azure Client VM Validation'
Assert-Equal $false $policy.sliceDeliversCapability `
    'this slice does not mark the Product Capability delivered'
Assert-Equal 'None' $policy.supportClaim 'the contract makes no support claim'
Assert-Equal 'None' $policy.previewOrStableClaim 'the contract makes no Preview claim'
Assert-Equal 'ControllerDevTracer' $policy.trustClass `
    'this slice stays a controller or DEV tracer'
Assert-Equal $true $policy.qualifyingEvidenceRequiresAttestedOrSignedPath `
    'a passing infrastructure round is not qualifying evidence'
Assert-Equal 'ManagedIdentity' $policy.azure.contact `
    'live contact is the approved credentialless managed identity'
Assert-Equal 'NotStarted' $policy.azure.livePathWithoutIdentity `
    'live Azure stays NotStarted without the approved identity'
Assert-Equal $true $policy.azure.credentialless 'the identity must be credentialless'
Assert-Equal 'declared-not-acquired' $policy.azure.toolingAcquisition `
    'Terraform remains a declared identity, not a downloaded tool'
Assert-Equal 'VmAgentRunCommand' $policy.guest.control `
    'guest control is VM Agent Run Command'
Assert-Equal 'Prohibited' $policy.guest.bootstrapCredentialExposure `
    'the bootstrap credential must never reach WIN-PCInfo'
Assert-Equal 'Prohibited' $policy.guest.captureOrReuse `
    'a tested client cannot be captured or reused'
Assert-Equal $false $policy.guest.publicIp 'VM public IPs are forbidden'
Assert-Equal $true $policy.lifecycle.cleanupFirst 'admission is cleanup-first'
Assert-Equal $true $policy.lifecycle.testingFailureCannotBlockCleanup `
    'a product failure cannot skip teardown'
Assert-Equal $true $policy.lifecycle.completionRequiresZeroResidue `
    'completion requires independently proven zero residue'
Assert-Equal $true $policy.lifecycle.terraformStateRemovalOnlyAfterZeroResidue `
    'private Terraform state is removed only after zero residue'
Assert-Equal $true $policy.lifecycle.persistentScopePreserved `
    'the persistent Validation Resource Scope remains'

$requiredProbes = @(
    'Identity', 'Policy', 'Locks', 'Quota', 'Image', 'Sku', 'StandardSsd',
    'Tags', 'Expiry', 'SubnetCapacity', 'VmCount', 'CleanupRights',
    'EmptyTransientScope', 'ExclusiveLease', 'ArmedRecovery'
)
Assert-Equal ($requiredProbes -join '|') (@($policy.admissionProbes) -join '|') `
    'admission names every required live probe before creation'

$requiredScenarios = @(
    'CompleteZeroResidue'
    'CleanupFirst'
    'AssessmentFailed'
    'IdentityUnavailable'
    'AdmissionDenied'
    'ResidueRemains'
    'CaptureAttempted'
    'CredentialExposed'
)
foreach ($scenario in $requiredScenarios) {
    Assert-Equal $true ($scenario -in @($policy.scenarios)) `
        "the contract names the closed scenario $scenario"
}

foreach ($fixtureName in @(
    'azure-validation-round-execution-complete.json'
    'azure-validation-round-execution-assessment-failed.json'
    'azure-validation-round-execution-identity-unavailable.json'
)) {
    $fixturePath = Join-Path $PSScriptRoot "fixtures/$fixtureName"
    $fixtureJson = Get-Content -LiteralPath $fixturePath -Raw
    Assert-Equal $true (Test-Json -Json $fixtureJson -SchemaFile $fixtureSchemaPath) `
        "$fixtureName satisfies the public fixture schema"
    Assert-Equal $true ($fixtureJson -match '"synthetic"\s*:\s*true') `
        "$fixtureName is marked synthetic"
    foreach ($needle in @(
        '(?i)/subscriptions/'
        '(?i)\btenant\b'
        '(?i)clientSecret'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)\.terraform'
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
    )) {
        Assert-Equal $false ($fixtureJson -match $needle) `
            "$fixtureName contains no private identifier matching $needle"
    }
}

$operatorDoc = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/azure-validation-round.md'
) -Raw
Assert-Equal $true ($operatorDoc -match 'does not mark `CAP-0028` delivered') `
    'operator documentation refuses a Product Capability claim'
Assert-Equal $true ($operatorDoc -match 'RunValidationRound') `
    'operator documentation names the generated-application workflow'
Assert-Equal $true ($operatorDoc -match 'Zero Round Residue|zero residue') `
    'operator documentation teaches Zero Round Residue'
Assert-Equal $true ($operatorDoc -match 'VM Agent|Run Command') `
    'operator documentation names the guest-control path'
Assert-Equal $true ($operatorDoc -match 'managed identity') `
    'operator documentation names the credentialless identity'
Assert-Equal $true ($operatorDoc -match 'ControllerDevTracer|controller/DEV tracer|controller or DEV tracer') `
    'operator documentation states this is a controller tracer'
Assert-Equal $false ($operatorDoc -match '(?i)/subscriptions/') `
    'operator documentation contains no Azure subscription path'
Assert-Equal $false ($operatorDoc -match 'this slice delivers CAP-0028') `
    'operator documentation does not invent a capability claim'

$projection = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/validation/issue-72-azure-validation-round.md'
) -Raw
Assert-Equal $true ($projection -match 'identifier-free') `
    'the public validation projection stays identifier-free'
Assert-Equal $true ($projection -match 'IDENTITY_UNAVAILABLE|NotStarted') `
    'the public projection records that live Azure stays NotStarted without identity'
Assert-Equal $false ($projection -match '(?i)clientSecret') `
    'the public validation projection contains no secret material'

Write-Output 'PASS: Azure validation-round policy, schemas, and beginner documentation are closed.'
