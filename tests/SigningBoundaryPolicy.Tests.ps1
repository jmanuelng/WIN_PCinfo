[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-signing-boundary.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/signing-boundary.schema.json'
$requestSchemaPath = Join-Path $repositoryRoot 'schemas/signing-session-request.schema.json'
$resultSchemaPath = Join-Path $repositoryRoot 'schemas/signing-session-result.schema.json'
$eligiblePath = Join-Path $PSScriptRoot 'fixtures/signing-session-eligible.json'

Assert-Equal $true (Test-Path -LiteralPath $policyPath -PathType Leaf) `
    'the Signing Boundary contract is release-declared'
Assert-Equal $true (Test-Path -LiteralPath $schemaPath -PathType Leaf) `
    'the Signing Boundary contract has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $requestSchemaPath -PathType Leaf) `
    'the signing-session request has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $resultSchemaPath -PathType Leaf) `
    'the sanitized signing-session result has a closed public schema'

$policyJson = Get-Content -LiteralPath $policyPath -Raw
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the Signing Boundary contract satisfies its exact schema'
$policy = $policyJson | ConvertFrom-Json -Depth 20

Assert-Equal 'win-pcinfo.signing-boundary/1.0.0' $policy.policyId `
    'the Signing Boundary has a stable release identity'
Assert-Equal 'CAP-0025' $policy.productCapability `
    'the boundary traces to trusted release provenance'
Assert-Equal $false $policy.sliceDeliversCapability `
    'this slice does not mark the Product Capability delivered'
Assert-Equal 'None' $policy.supportClaim 'the contract makes no support claim'
Assert-Equal 'None' $policy.previewOrStableClaim 'the contract makes no Preview claim'
Assert-Equal $false $policy.publicationAuthorized `
    'this slice cannot authorize publication'
Assert-Equal $false $policy.trustedPublicationPermitted `
    'a synthetic or incomplete session cannot publish as Trusted'
Assert-Equal $false $policy.attestedFallback.satisfiesStableSigningGate `
    'Attested Preview cannot satisfy the Stable signing gate'
Assert-Equal $true $policy.attestedFallback.neverForConvenience `
    'fallback selection is never for convenience'
Assert-Equal $false $policy.identity.timestampedSigningByteReproducible `
    'timestamped signing is not claimed to be byte-reproducible'
Assert-Equal $true $policy.identity.finalMustBeDistinct `
    'the signed distributable must be a distinct identity'
Assert-Equal 'IndividualPublisher' $policy.publisher.kind `
    'signing uses the approved Individual Publisher kind'
Assert-Equal 'DedicatedSigningResourceScope' $policy.publisher.resourceScopeKind `
    'signing uses a dedicated Signing Resource Scope kind'
Assert-Equal 'None' $policy.azure.contact 'the contract forbids Azure contact in this slice'
Assert-Equal 'NotStarted' $policy.azure.livePathWithoutSetupAuthority `
    'live Artifact Signing stays NotStarted without setup authority'
Assert-Equal 'CONFIRM-CANDIDATE-DIGEST' $policy.humanApproval.confirmationPhrase `
    'human digest confirmation is an exact phrase'
Assert-Equal $true $policy.session.leastPrivilege 'temporary signing is least-privilege'
Assert-Equal $true $policy.session.timeBounded 'temporary signing is time-bounded'
Assert-Equal $true $policy.session.sessionSpecific 'temporary signing is session-specific'
Assert-Equal $true $policy.session.removeAfterTransaction `
    'temporary signing is removed after the transaction'
Assert-Equal 'Help' $policy.smoke.workflow 'smoke uses the Help discovery surface'
Assert-Equal $true $policy.smoke.collectionProhibited 'smoke cannot start collection'

$requiredScenarios = @(
    'EligibleSign'
    'WrongDigest'
    'ChangedContent'
    'InvalidSignature'
    'MissingSignature'
    'TimestampFailure'
    'PermissionDenied'
    'ServiceUnavailable'
    'UnexpectedlySigned'
    'WrongCandidate'
    'GatesNotPassed'
    'ApprovalMissing'
    'SetupAuthorityMissing'
)
foreach ($scenario in $requiredScenarios) {
    Assert-Equal $true ($scenario -in @($policy.scenarios)) `
        "the contract names the closed scenario $scenario"
}

$eligibleJson = Get-Content -LiteralPath $eligiblePath -Raw
Assert-Equal $true (Test-Json -Json $eligibleJson -SchemaFile $requestSchemaPath) `
    'the eligible fixture satisfies the public request schema'
Assert-Equal $true ($eligibleJson -match '"synthetic"\s*:\s*true') `
    'the eligible fixture is marked synthetic'
foreach ($needle in @(
    '(?i)/subscriptions/'
    '(?i)\btenant\b'
    '(?i)clientSecret'
    '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
    '(?i)\.terraform'
    '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
    '(?i)Microsoft\.CodeSigning'
    '(?i)transactionId'
)) {
    Assert-Equal $false ($eligibleJson -match $needle) `
        "the eligible fixture contains no private identifier matching $needle"
}

$operatorDoc = Get-Content -LiteralPath (Join-Path $repositoryRoot 'docs/signing-boundary.md') -Raw
Assert-Equal $true ($operatorDoc -match 'SignAndVerifyCandidate') `
    'beginner documentation names the generated-application workflow'
Assert-Equal $true ($operatorDoc -match 'CONFIRM-CANDIDATE-DIGEST') `
    'beginner documentation names the exact digest-confirmation phrase'
Assert-Equal $true ($operatorDoc -match 'does not mark `CAP-0025` delivered') `
    'beginner documentation refuses a Product Capability claim'
Assert-Equal $true ($operatorDoc -match 'cannot be published as Trusted') `
    'beginner documentation states that fail-closed artifacts cannot be Trusted'
Assert-Equal $true ($operatorDoc -match 'Attested Preview') `
    'beginner documentation names the governed outage fallback'
Assert-Equal $false ($operatorDoc -match '(?i)/subscriptions/') `
    'beginner documentation contains no Azure subscription path'
Assert-Equal $false ($operatorDoc -match 'Authenticode signing is complete') `
    'beginner documentation does not claim Authenticode signing is complete'

$projection = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/validation/issue-70-signing-boundary.md'
) -Raw
Assert-Equal $true ($projection -match 'identifier-free') `
    'the public validation projection stays identifier-free'
Assert-Equal $true ($projection -match 'SETUP_AUTHORITY_REQUIRED|NotStarted') `
    'the public projection records that live signing stays NotStarted without setup'
Assert-Equal $false ($projection -match '(?i)clientSecret') `
    'the public validation projection contains no secret material'

Write-Output 'PASS: Signing Boundary policy, schemas, and beginner documentation are closed.'
