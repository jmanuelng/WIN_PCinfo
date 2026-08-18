[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-preview-publication.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/preview-publication.schema.json'
$requestSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication-request.schema.json'
$previewSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication-preview.schema.json'
$resultSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication-result.schema.json'
$packetSchemaPath = Join-Path $repositoryRoot 'schemas/preview-qualification-packet.schema.json'
$completePath = Join-Path $PSScriptRoot 'fixtures/preview-publication-complete-signed.json'

Assert-Equal $true (Test-Path -LiteralPath $policyPath -PathType Leaf) `
    'the Preview publication contract is release-declared'
Assert-Equal $true (Test-Path -LiteralPath $schemaPath -PathType Leaf) `
    'the Preview publication contract has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $requestSchemaPath -PathType Leaf) `
    'the synthetic publication request has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $previewSchemaPath -PathType Leaf) `
    'the public release preview has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $resultSchemaPath -PathType Leaf) `
    'the publication result has a closed public schema'

$policyJson = Get-Content -LiteralPath $policyPath -Raw
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the Preview publication contract satisfies its exact schema'
$policy = $policyJson | ConvertFrom-Json -Depth 20

Assert-Equal 'win-pcinfo.preview-publication/1.0.0' $policy.policyId `
    'the publication contract has a stable release identity'
Assert-Equal 'CAP-0026' $policy.productCapability `
    'publication traces to Preview capability and support transparency'
Assert-Equal $false $policy.sliceDeliversCapability `
    'this slice does not mark the Product Capability delivered'
Assert-Equal 'None' $policy.supportClaim 'the contract makes no support claim'
Assert-Equal 'None' $policy.previewOrStableClaim 'the contract makes no Preview claim'
Assert-Equal $false $policy.publicationAuthorized `
    'this slice cannot authorize live publication'
Assert-Equal $false $policy.supportedPromotionPermitted `
    'Preview.1 cannot promote a Supported claim'
Assert-Equal $false $policy.attestedPreviewSatisfiesStableSigning `
    'an Attested Preview cannot satisfy the Stable signing gate'
Assert-Equal $true $policy.humanApprovalRequired `
    'a human must still approve the exact candidate'
Assert-Equal $true $policy.silentReplacementProhibited `
    'published tags cannot be replaced silently'
Assert-Equal $true $policy.syntheticCannotAuthorizePublication `
    'a synthetic rehearsal cannot create the GitHub release'
Assert-Equal 'v2.0.0-preview.1' $policy.immutableTag `
    'the public tag identity is frozen'
Assert-Equal 'Preview' $policy.releaseChannel 'the public channel is Preview'
Assert-Equal 'APPROVE-PREVIEW-PUBLICATION' $policy.confirmationPhrase `
    'human approval uses an exact confirmation phrase'
Assert-Equal 'None' $policy.github.contact 'publication does not contact GitHub in this slice'
Assert-Equal 'NotStarted' $policy.github.livePublicationInThisSlice `
    'live GitHub publication stays NotStarted in this slice'
Assert-Equal $true $policy.decision.missingApprovalDeniesPublication `
    'missing human approval cannot publish'
Assert-Equal $true $policy.decision.silentReplacementDenies `
    'silent replacement is denied'
Assert-Equal $true $policy.decision.syntheticCannotPublishGithub `
    'synthetic evidence cannot publish to GitHub'
Assert-Equal $false $policy.decision.manualPromotionAllowed `
    'missing or failed evidence cannot be waived'

$completeJson = Get-Content -LiteralPath $completePath -Raw
Assert-Equal $true (Test-Json -Json $completeJson -SchemaFile $requestSchemaPath) `
    'the complete signed fixture satisfies the public request schema'
Assert-Equal $true ($completeJson -match '"synthetic"\s*:\s*true') `
    'the complete signed fixture is marked synthetic'
$complete = $completeJson | ConvertFrom-Json -Depth 30
Assert-Equal $true (Test-Json -Json ($complete.qualificationPacket | ConvertTo-Json -Depth 30) `
    -SchemaFile $packetSchemaPath) 'the embedded qualification packet satisfies the packet schema'
Assert-Equal 'AuthenticodeSigned' $complete.trustPath `
    'the complete signed fixture uses the Authenticode trust path'
Assert-Equal 'win-pcinfo.authenticode-signed-package-identity' `
    $complete.bindings.finalDistributableIdentityKind `
    'the complete signed fixture binds a distinct signed package identity'
Assert-Equal 9 $complete.assets.Count 'the complete fixture names every required public asset'
Assert-Equal $true $complete.humanApproval.present `
    'the complete fixture includes the required human approval'
Assert-Equal 'APPROVE-PREVIEW-PUBLICATION' $complete.humanApproval.confirmationPhrase `
    'the complete fixture uses the frozen confirmation phrase'

foreach ($requiredAsset in @($policy.requiredAssets)) {
    Assert-Equal $true ($requiredAsset -in @($complete.assets.assetId)) `
        "the complete fixture includes required asset $requiredAsset"
}
foreach ($requiredLimitation in @($policy.requiredLimitations)) {
    Assert-Equal $true ($requiredLimitation -in @($complete.limitations)) `
        "the complete fixture includes required limitation $requiredLimitation"
}

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

$operatorDoc = Get-Content -LiteralPath (Join-Path $repositoryRoot 'docs/preview-publication.md') -Raw
Assert-Equal $true ($operatorDoc -match 'PublishPreviewRelease') `
    'beginner documentation names the generated-application workflow'
Assert-Equal $true ($operatorDoc -match 'APPROVE-PREVIEW-PUBLICATION') `
    'beginner documentation names the human confirmation phrase'
Assert-Equal $true ($operatorDoc -match 'cannot be averaged or waived') `
    'beginner documentation states that missing evidence cannot be averaged or waived'
Assert-Equal $true ($operatorDoc -match 'Attested Preview') `
    'beginner documentation explains the governed unsigned fallback'
Assert-Equal $true ($operatorDoc -match 'SILENT_REPLACEMENT') `
    'beginner documentation forbids silent replacement'
Assert-Equal $false ($operatorDoc -match '(?i)/subscriptions/') `
    'beginner documentation contains no Azure subscription path'

$projection = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/validation/issue-75-preview-publication.md'
) -Raw
Assert-Equal $true ($projection -match 'identifier-free') `
    'the public validation projection stays identifier-free'
Assert-Equal $false ($projection -match '(?i)clientSecret') `
    'the public validation projection contains no secret material'
Assert-Equal $true ($projection -match 'NotStarted') `
    'the public projection records the live-path opening checkpoint'

Write-Output 'PASS: Preview publication policy, schemas, and beginner documentation are closed.'
