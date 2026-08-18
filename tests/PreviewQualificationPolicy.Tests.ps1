[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-preview-qualification.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/preview-qualification.schema.json'
$requestSchemaPath = Join-Path $repositoryRoot 'schemas/preview-qualification-request.schema.json'
$packetSchemaPath = Join-Path $repositoryRoot 'schemas/preview-qualification-packet.schema.json'
$packSchemaPath = Join-Path $repositoryRoot 'schemas/release-evidence-pack.schema.json'
$completePath = Join-Path $PSScriptRoot 'fixtures/preview-qualification-complete-signed.json'

Assert-Equal $true (Test-Path -LiteralPath $policyPath -PathType Leaf) `
    'the Preview qualification contract is release-declared'
Assert-Equal $true (Test-Path -LiteralPath $schemaPath -PathType Leaf) `
    'the Preview qualification contract has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $requestSchemaPath -PathType Leaf) `
    'the synthetic qualification request has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $packetSchemaPath -PathType Leaf) `
    'the qualification decision packet has a closed public schema'

$policyJson = Get-Content -LiteralPath $policyPath -Raw
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the Preview qualification contract satisfies its exact schema'
$policy = $policyJson | ConvertFrom-Json -Depth 20

Assert-Equal 'win-pcinfo.preview-qualification/1.0.0' $policy.policyId `
    'the qualification contract has a stable release identity'
Assert-Equal 'CAP-0027' $policy.productCapability `
    'qualification traces to evidence-gated release promotion'
Assert-Equal $false $policy.sliceDeliversCapability `
    'this slice does not mark the Product Capability delivered'
Assert-Equal 'None' $policy.supportClaim 'the contract makes no support claim'
Assert-Equal 'None' $policy.previewOrStableClaim 'the contract makes no Preview claim'
Assert-Equal $false $policy.publicationAuthorized `
    'this slice cannot authorize publication'
Assert-Equal $false $policy.supportedPromotionPermitted `
    'Preview.1 cannot promote a Supported claim'
Assert-Equal $false $policy.attestedPreviewSatisfiesStableSigning `
    'an Attested Preview cannot satisfy the Stable signing gate'
Assert-Equal $true $policy.humanApprovalRequired `
    'a human must still accept the final decision packet'
Assert-Equal 'NotStarted' $policy.liveValidationInThisSlice `
    'live Azure validation stays NotStarted in this slice'
Assert-Equal 'None' $policy.azure.contact 'qualification does not contact Azure'
Assert-Equal $true $policy.decision.missingDenies 'missing evidence denies the packet'
Assert-Equal $true $policy.decision.failedDenies 'product failure denies the packet'
Assert-Equal $true $policy.decision.expiredDenies 'expired evidence denies the packet'
Assert-Equal $true $policy.decision.invalidatedDenies 'invalidated evidence denies the packet'
Assert-Equal $true $policy.decision.wrongCandidateDenies 'a wrong candidate denies the packet'
Assert-Equal $true $policy.decision.privacyUnsafeDenies 'privacy-unsafe evidence denies the packet'
Assert-Equal $true $policy.decision.cleanupPendingDenies 'cleanup-pending evidence denies the packet'
Assert-Equal $true $policy.decision.waiverDenies 'a requested waiver denies the packet'
Assert-Equal $false $policy.decision.manualPromotionAllowed `
    'missing or failed evidence cannot be waived'

$releaseDefinition = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1.json'
) -Raw | ConvertFrom-Json -Depth 20
foreach ($requiredGate in @($releaseDefinition.requiredReleaseEvidence)) {
    Assert-Equal $true ($requiredGate -in @($policy.requiredGates)) `
        "the qualification contract includes release-required evidence $requiredGate"
}

$completeJson = Get-Content -LiteralPath $completePath -Raw
Assert-Equal $true (Test-Json -Json $completeJson -SchemaFile $requestSchemaPath) `
    'the complete signed fixture satisfies the public request schema'
Assert-Equal $true ($completeJson -match '"synthetic"\s*:\s*true') `
    'the complete signed fixture is marked synthetic'
$complete = $completeJson | ConvertFrom-Json -Depth 30
Assert-Equal $true (Test-Json -Json ($complete.evidencePack | ConvertTo-Json -Depth 30) `
    -SchemaFile $packSchemaPath) 'the embedded evidence pack satisfies the pack schema'
Assert-Equal 'AuthenticodeSigned' $complete.trustPath `
    'the complete signed fixture uses the Authenticode trust path'
Assert-Equal 'win-pcinfo.authenticode-signed-package-identity' `
    $complete.bindings.finalDistributableIdentityKind `
    'the complete signed fixture binds a distinct signed package identity'

foreach ($needle in @(
    '(?i)/subscriptions/'
    '(?i)\btenant\b'
    '(?i)clientSecret'
    '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
    '(?i)\.terraform'
    '(?i)\.tfstate'
    '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
)) {
    Assert-Equal $false ($completeJson -match $needle) `
        "the complete signed fixture contains no private identifier matching $needle"
}

$operatorDoc = Get-Content -LiteralPath (Join-Path $repositoryRoot 'docs/preview-qualification.md') -Raw
Assert-Equal $true ($operatorDoc -match 'QualifyPreviewCandidate') `
    'beginner documentation names the generated-application workflow'
Assert-Equal $true ($operatorDoc -match 'approval or denial packet') `
    'beginner documentation names the decision packet'
Assert-Equal $true ($operatorDoc -match 'cannot be averaged or waived') `
    'beginner documentation states that missing evidence cannot be averaged or waived'
Assert-Equal $true ($operatorDoc -match 'Attested Preview') `
    'beginner documentation explains the governed unsigned fallback'
Assert-Equal $false ($operatorDoc -match '(?i)/subscriptions/') `
    'beginner documentation contains no Azure subscription path'

$projection = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/validation/issue-74-preview-qualification.md'
) -Raw
Assert-Equal $true ($projection -match 'identifier-free') `
    'the public validation projection stays identifier-free'
Assert-Equal $false ($projection -match '(?i)clientSecret') `
    'the public validation projection contains no secret material'
Assert-Equal $true ($projection -match 'NotStarted') `
    'the public projection records the live-path opening checkpoint'

Write-Output 'PASS: Preview qualification policy, schemas, and beginner documentation are closed.'
