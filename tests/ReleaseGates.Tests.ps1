[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/ReleaseGates.ps1')

$policy = Get-ReleaseGatesPolicy
$manifestSchemaPath = Join-Path $repositoryRoot 'schemas/release-evidence-manifest.schema.json'
$matrixSchemaPath = Join-Path $repositoryRoot 'schemas/preview-capability-matrix.schema.json'
$ledger = Get-Content -LiteralPath (Join-Path $repositoryRoot 'docs/spec/capability-ledger.json') -Raw |
    ConvertFrom-Json -Depth 30
$releaseDefinition = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1.json'
) -Raw | ConvertFrom-Json -Depth 30
$ledgerBytes = [System.IO.File]::ReadAllBytes(
    (Join-Path $repositoryRoot 'docs/spec/capability-ledger.json')
)
$ledgerDigest = Get-ReleaseGatesSha256 -Bytes $ledgerBytes
$now = [datetimeoffset]::Parse(
    '2026-08-17T00:00:00Z',
    [System.Globalization.CultureInfo]::InvariantCulture,
    [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
)

function Get-PackFromPath {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    Get-Content -LiteralPath $LiteralPath -Raw | ConvertFrom-Json -Depth 30
}

function Copy-Pack {
    param([Parameter(Mandatory)] $Pack)
    $Pack | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
}

function Set-PackLedgerDigest {
    param([Parameter(Mandatory)] $Pack)
    $Pack.bindings.ledgerSha256 = $ledgerDigest
    $Pack
}

function Assert-PublicProjection {
    param(
        [Parameter(Mandatory)] $Evaluation,
        [Parameter(Mandatory)] [string] $Because
    )
    $manifestJson = $Evaluation.Manifest | ConvertTo-Json -Compress -Depth 20
    $matrixJson = $Evaluation.Matrix | ConvertTo-Json -Compress -Depth 20
    Assert-Equal $true (Test-Json -Json $manifestJson -SchemaFile $manifestSchemaPath) `
        "$Because manifest satisfies the public schema"
    Assert-Equal $true (Test-Json -Json $matrixJson -SchemaFile $matrixSchemaPath) `
        "$Because matrix satisfies the public schema"
    Assert-Equal 'None' $Evaluation.Manifest.supportClaim "$Because makes no support claim"
    Assert-Equal 'None' $Evaluation.Manifest.previewOrStableClaim "$Because makes no Preview claim"
    Assert-Equal $false $Evaluation.Manifest.sliceDeliversCapability `
        "$Because does not deliver a Product Capability"
    Assert-Equal $false $Evaluation.Manifest.collectionStarted "$Because never starts collection"
    Assert-Equal $false $Evaluation.Manifest.promotion.publicationAuthorized `
        "$Because cannot authorize publication"
    Assert-Equal $false $Evaluation.Manifest.promotion.previewPromotionReady `
        "$Because cannot mark Preview promotion ready"
    Assert-Equal $false $Evaluation.Manifest.promotion.supportedPromotionReady `
        "$Because cannot mark Supported promotion ready"
    Assert-Equal $false $Evaluation.Manifest.promotion.waiverApplied `
        "$Because never applies a waiver"
    Assert-Equal $false $Evaluation.Matrix.handEdited "$Because matrix is not hand-edited"
    foreach ($needle in @(
        '(?i)/subscriptions/'
        '(?i)\btenant\b'
        '(?i)clientSecret'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)\.terraform'
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
    )) {
        Assert-Equal $false ($manifestJson -match $needle) `
            "$Because manifest must not match $needle"
        Assert-Equal $false ($matrixJson -match $needle) `
            "$Because matrix must not match $needle"
    }
}

function Invoke-Gate {
    param(
        [Parameter(Mandatory)] $Pack,
        [Parameter()] [string] $ExpectedGeneratedContentSha256,
        [Parameter()] [datetimeoffset] $At = $now,
        [Parameter()] [string] $WorkspacePath
    )
    $prepared = Set-PackLedgerDigest -Pack (Copy-Pack $Pack)
    $invoke = @{
        Pack = $prepared
        Policy = $policy
        Ledger = $ledger
        ReleaseDefinition = $releaseDefinition
        ExpectedLedgerSha256 = $ledgerDigest
        Now = $At
        RepositoryRoot = $repositoryRoot
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedGeneratedContentSha256)) {
        $invoke.ExpectedGeneratedContentSha256 = $ExpectedGeneratedContentSha256
    }
    if (-not [string]::IsNullOrWhiteSpace($WorkspacePath)) {
        $invoke.WorkspacePath = $WorkspacePath
    }
    Invoke-ReleaseGateEvaluation @invoke
}

$complete = Get-PackFromPath (Join-Path $PSScriptRoot 'fixtures/release-evidence-pack-complete-presigning.json')
$finalPack = Get-PackFromPath (Join-Path $PSScriptRoot 'fixtures/release-evidence-pack-complete-final.json')

$completeResult = Invoke-Gate -Pack $complete
Assert-PublicProjection $completeResult 'a complete pre-signing pack'
Assert-Equal 'Evaluated' $completeResult.State 'a complete pack is evaluated'
Assert-Equal 'Completed' $completeResult.ExitKind 'a complete pack completes'
Assert-Equal $true $completeResult.Manifest.unsignedContentQualified `
    'complete pre-signing evidence qualifies unsigned generated content'
Assert-Equal $false $completeResult.Manifest.finalArtifactQualified `
    'pre-signing does not qualify a final distributable'
Assert-Equal 'Preview' $completeResult.Manifest.promotion.derivedClaimState `
    'complete evidence derives a Preview state without publishing it'
Assert-Equal $true $completeResult.Manifest.qualityBudget.threeCleanPassed `
    'three independent clean measurements pass'
Assert-Equal 'Pass' $completeResult.Manifest.qualityBudget.outcome `
    'the quality-budget outcome is Pass'
Assert-Equal $true (
    'GATE.SYNTHETIC_EVIDENCE_NOT_PROMOTABLE' -in @($completeResult.Manifest.promotion.blockingReasons)
) 'synthetic evidence cannot authorize publication'
Assert-Equal $true (
    'GATE.FINAL_ARTIFACT_NOT_RUN' -in @($completeResult.Manifest.promotion.blockingReasons)
) 'pre-signing records that Final Artifact Validation has not run'
Assert-Equal 'Derived' $completeResult.Matrix.state 'the matrix is derived from the frozen ledger'
Assert-Equal $true $completeResult.Matrix.derivedFromFrozenLedger `
    'the matrix records frozen-ledger derivation'
$previewRows = @($completeResult.Matrix.rows | Where-Object supportState -eq 'Preview')
Assert-Equal $true ($previewRows.Count -gt 0) 'derived rows can be Preview when evidence passes'
Assert-Equal 0 @($completeResult.Matrix.rows | Where-Object supportState -eq 'Supported').Count `
    'the matrix never emits Supported for Preview.1'
Assert-Equal 2 $completeResult.Matrix.scenarioSnapshots.Count `
    'support snapshots exist for both claimed Windows scenarios'

$finalResult = Invoke-Gate -Pack $finalPack
Assert-PublicProjection $finalResult 'a complete final-artifact pack'
Assert-Equal $true $finalResult.Manifest.finalArtifactQualified `
    'a distinct derived final identity can qualify Final Artifact Validation'
Assert-Equal $true $finalResult.Manifest.unsignedContentQualified `
    'final validation still requires the unsigned generated-content identity'
Assert-Equal $false (
    'GATE.FINAL_ARTIFACT_NOT_RUN' -in @($finalResult.Manifest.promotion.blockingReasons)
) 'a complete final pack does not claim the final gate was skipped'

$missing = Copy-Pack $complete
$missing.gates = @($missing.gates | Where-Object {
    $_.gateId -ne 'privacy-secret-exclusion-and-evidence-protection-gates'
})
$missingResult = Invoke-Gate -Pack $missing
Assert-PublicProjection $missingResult 'a missing required gate'
Assert-Equal $false $missingResult.Manifest.unsignedContentQualified `
    'a missing required gate cannot qualify the candidate'
Assert-Equal $true (
    @($missingResult.Manifest.gates | Where-Object {
        $_.gateId -eq 'privacy-secret-exclusion-and-evidence-protection-gates' -and
        $_.result -eq 'NotRun'
    }).Count -eq 1
) 'a missing required gate is recorded as NotRun'
Assert-Equal $true (
    'GATE.MISSING' -in @($missingResult.Manifest.promotion.blockingReasons)
) 'missing evidence blocks promotion'

$failed = Copy-Pack $complete
@($failed.gates | Where-Object {
    $_.gateId -eq 'deterministic-contract-schema-and-artifact-gates'
})[0].result = 'ProductFail'
@($failed.gates | Where-Object {
    $_.gateId -eq 'deterministic-contract-schema-and-artifact-gates'
})[0].reasonCode = 'GATE.PRODUCT_FAIL'
$failedResult = Invoke-Gate -Pack $failed
Assert-PublicProjection $failedResult 'a product-failed gate'
Assert-Equal $false $failedResult.Manifest.unsignedContentQualified `
    'a ProductFail cannot be qualified'
Assert-Equal 'ProductFail' @($failedResult.Manifest.gates | Where-Object {
    $_.gateId -eq 'deterministic-contract-schema-and-artifact-gates'
})[0].result 'the failed gate stays ProductFail'

$expired = Copy-Pack $complete
$expiredNow = [datetimeoffset]::Parse(
    '2026-09-15T00:00:00Z',
    [System.Globalization.CultureInfo]::InvariantCulture,
    [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
)
$expiredResult = Invoke-Gate -Pack $expired -At $expiredNow
Assert-PublicProjection $expiredResult 'stale Client VM evidence'
Assert-Equal $false $expiredResult.Manifest.unsignedContentQualified `
    'expired Client VM evidence cannot qualify a claim'
Assert-Equal $true (@($expiredResult.Manifest.gates | Where-Object {
    $_.freshnessClass -eq 'ClientVmValidation' -and $_.result -eq 'Expired'
}).Count -ge 1) 'Client VM gates expire after 30 days'
Assert-Equal $true (@($expiredResult.Manifest.gates | Where-Object {
    $_.freshnessClass -eq 'Automated' -and $_.result -eq 'Pass'
}).Count -ge 1) 'automated gates do not expire by age'

$invalidated = Copy-Pack $complete
@($invalidated.gates | Where-Object {
    $_.gateId -eq 'zero-round-residue'
})[0].result = 'Invalidated'
@($invalidated.gates | Where-Object {
    $_.gateId -eq 'zero-round-residue'
})[0].reasonCode = 'GATE.INVALIDATED'
$invalidatedResult = Invoke-Gate -Pack $invalidated
Assert-PublicProjection $invalidatedResult 'invalidated evidence'
Assert-Equal $false $invalidatedResult.Manifest.unsignedContentQualified `
    'invalidated evidence cannot be waived into a pass'
Assert-Equal 'Invalidated' @($invalidatedResult.Manifest.gates | Where-Object {
    $_.gateId -eq 'zero-round-residue'
})[0].result 'the invalidated gate remains Invalidated'

$mismatch = Invoke-Gate -Pack $complete `
    -ExpectedGeneratedContentSha256 ('f' * 64)
Assert-PublicProjection $mismatch 'a mismatched generated-content identity'
Assert-Equal $false $mismatch.Manifest.unsignedContentQualified `
    'the running candidate must match the pack'
Assert-Equal $true (
    'GATE.CANDIDATE_MISMATCH' -in @($mismatch.Manifest.promotion.blockingReasons)
) 'wrong-candidate evidence blocks the claim'

$runtime = Copy-Pack $complete
$runtime.bindings.runtime.version = '8.0.0'
$runtimeResult = Invoke-Gate -Pack $runtime
Assert-PublicProjection $runtimeResult 'an unsupported runtime'
Assert-Equal $false $runtimeResult.Manifest.unsignedContentQualified `
    'PowerShell 8 cannot inherit a Preview.1 claim'
Assert-Equal $true (
    'GATE.UNSUPPORTED_RUNTIME' -in @($runtimeResult.Manifest.promotion.blockingReasons)
) 'an unsupported runtime is a blocking reason'

$locale = Copy-Pack $complete
$locale.locales = @('en-US', 'es-MX', 'tr-TR', 'ja-JP')
$localeResult = Invoke-Gate -Pack $locale
Assert-PublicProjection $localeResult 'missing locale coverage'
Assert-Equal $false $localeResult.Manifest.unsignedContentQualified `
    'language-neutral coverage requires every required culture'
Assert-Equal $true (
    'GATE.LOCALE_NON_NEUTRAL' -in @($localeResult.Manifest.promotion.blockingReasons)
) 'a missing required locale blocks the claim'

$secret = Copy-Pack $complete
$secret | Add-Member -NotePropertyName leak -NotePropertyValue 'clientSecret=not-a-real-secret' -Force
$secretResult = Invoke-ReleaseGateEvaluation -Pack $secret -Policy $policy -Ledger $ledger `
    -ReleaseDefinition $releaseDefinition -ExpectedLedgerSha256 $ledgerDigest -Now $now `
    -RepositoryRoot $repositoryRoot
Assert-PublicProjection $secretResult 'a privacy-violating pack'
Assert-Equal 'Rejected' $secretResult.State 'secrets fail closed before evaluation'
Assert-Equal 'NotStarted' $secretResult.ExitKind 'privacy rejection stays NotStarted'
Assert-Equal 'GATE.PRIVACY_REJECTED' $secretResult.ReasonCode `
    'the privacy gate uses a stable reason'

$real = Copy-Pack $complete
$real.synthetic = $false
$realResult = Invoke-Gate -Pack $real
Assert-Equal 'Rejected' $realResult.State 'non-synthetic packs cannot enter the public gate'
Assert-Equal 'GATE.PRIVACY_REJECTED' $realResult.ReasonCode `
    'real validation records stay outside public CI'

$waiver = Copy-Pack $complete
$waiver.waiverRequested = $true
$waiverResult = Invoke-Gate -Pack $waiver
Assert-PublicProjection $waiverResult 'a requested waiver'
Assert-Equal $false $waiverResult.Manifest.unsignedContentQualified `
    'a waiver cannot promote missing or failed evidence'
Assert-Equal $true (
    'GATE.WAIVER_REJECTED' -in @($waiverResult.Manifest.promotion.blockingReasons)
) 'manual waivers are rejected'

$averaged = Copy-Pack $complete
$averaged.qualityMeasurements[2].result = 'ProductFail'
$averaged.qualityMeasurements[2].reasonCode = 'GATE.PRODUCT_FAIL'
$averagedResult = Invoke-Gate -Pack $averaged
Assert-PublicProjection $averagedResult 'uneven quality measurements'
Assert-Equal $false $averagedResult.Manifest.qualityBudget.threeCleanPassed `
    'two passes and one product failure cannot be averaged'
Assert-Equal 'ProductFail' $averagedResult.Manifest.qualityBudget.outcome `
    'a product quality failure remains a failure'
Assert-Equal 0 @($averagedResult.Matrix.scenarioSnapshots | Where-Object supportState -eq 'Preview').Count `
    'scenario snapshots stay NotYetSupported when applicable gates did not all pass'

$cleanupBudget = Copy-Pack $complete
$cleanupBudget.qualityMeasurements[0].cancellationCleanupMilliseconds = 120001
$cleanupBudgetResult = Invoke-Gate -Pack $cleanupBudget
Assert-PublicProjection $cleanupBudgetResult 'a cancellation-cleanup ceiling miss'
Assert-Equal $false $cleanupBudgetResult.Manifest.qualityBudget.threeCleanPassed `
    'the two-minute cancellation cleanup ceiling is enforced'
Assert-Equal 'ProductFail' $cleanupBudgetResult.Manifest.qualityBudget.outcome `
    'an over-budget cleanup cannot be a clean measurement'

$deadline = Copy-Pack $complete
$deadline.qualityMeasurements[0].wallTimeMilliseconds = 3600001
$deadlineResult = Invoke-Gate -Pack $deadline
Assert-Equal $false $deadlineResult.Manifest.qualityBudget.threeCleanPassed `
    'the 60-minute absolute deadline is enforced'

$infra = Copy-Pack $complete
$infra.qualityMeasurements += [pscustomobject]@{
    attempt = 4
    result = 'InfrastructureInconclusive'
    reasonCode = 'GATE.INFRASTRUCTURE_INCONCLUSIVE'
    firstProgressMilliseconds = 100
    heartbeatGapMilliseconds = 1000
    cancellationAckMilliseconds = 200
    cancellationCleanupMilliseconds = 1000
    wallTimeMilliseconds = 120000
    peakPrivateMemoryBytes = 100000000
    peakWorkingSetBytes = 80000000
    peakWorkspaceBytes = 10000000
    packageBytes = 5000000
    reportBytes = 1000000
    cleanupVerified = $true
    localeNeutral = $true
    deterministicDerivation = $true
}
$infraResult = Invoke-Gate -Pack $infra
Assert-Equal $true $infraResult.Manifest.qualityBudget.threeCleanPassed `
    'one infrastructure replacement does not erase three clean measurements'
Assert-Equal 'Pass' $infraResult.Manifest.qualityBudget.outcome `
    'three clean measurements still pass beside one inconclusive replacement'

$sameFinal = Copy-Pack $finalPack
$sameFinal.finalDistributable.packageSha256 = $sameFinal.bindings.generatedContentSha256
$sameFinalResult = Invoke-Gate -Pack $sameFinal
Assert-Equal $false $sameFinalResult.Manifest.finalArtifactQualified `
    'the final distributable identity must be distinct from generated content'
Assert-Equal $true (
    'GATE.FINAL_IDENTITY_NOT_DISTINCT' -in @($sameFinalResult.Manifest.promotion.blockingReasons)
) 'reusing the generated-content digest is not Final Artifact Validation'

$underived = Copy-Pack $finalPack
$underived.finalDistributable.derivedFromGeneratedContentSha256 = ('3' * 64)
$underivedResult = Invoke-Gate -Pack $underived
Assert-Equal $false $underivedResult.Manifest.finalArtifactQualified `
    'the final identity must derive from the qualified generated content'
Assert-Equal $true (
    'GATE.FINAL_IDENTITY_NOT_DERIVED' -in @($underivedResult.Manifest.promotion.blockingReasons)
) 'a final identity that does not name the qualified content is rejected'

$ledgerMismatch = Invoke-ReleaseGateEvaluation -Pack (Set-PackLedgerDigest (Copy-Pack $complete)) `
    -Policy $policy -Ledger $ledger -ReleaseDefinition $releaseDefinition `
    -ExpectedLedgerSha256 ('9' * 64) -Now $now -RepositoryRoot $repositoryRoot
Assert-Equal $false $ledgerMismatch.Manifest.unsignedContentQualified `
    'a pack bound to the wrong ledger cannot qualify'
Assert-Equal $true (
    'GATE.LEDGER_MISMATCH' -in @($ledgerMismatch.Manifest.promotion.blockingReasons)
) 'wrong-ledger evidence is a blocking reason'

$missingLedger = Invoke-ReleaseGateEvaluation -Pack (Set-PackLedgerDigest (Copy-Pack $complete)) `
    -Policy $policy -Now $now -RepositoryRoot $repositoryRoot
Assert-Equal $false $missingLedger.Manifest.unsignedContentQualified `
    'missing ledger binding cannot qualify the candidate'
Assert-Equal $true (
    'GATE.LEDGER_MISMATCH' -in @($missingLedger.Manifest.promotion.blockingReasons)
) 'an unbound ledger is a blocking reason'
Assert-Equal 'Rejected' $missingLedger.Matrix.state `
    'the matrix is not derived without the frozen ledger'

$freshnessLie = Copy-Pack $complete
foreach ($gate in @($freshnessLie.gates)) {
    if ([string] $gate.freshnessClass -eq 'ClientVmValidation') {
        $gate.freshnessClass = 'Automated'
    }
}
$freshnessLieResult = Invoke-Gate -Pack $freshnessLie -At $expiredNow
Assert-PublicProjection $freshnessLieResult 'a misclassified Client VM gate'
Assert-Equal $false $freshnessLieResult.Manifest.unsignedContentQualified `
    'a Client VM gate cannot avoid expiry by labeling itself Automated'
Assert-Equal $true (@($freshnessLieResult.Manifest.gates | Where-Object {
    $_.freshnessClass -eq 'ClientVmValidation' -and $_.result -eq 'Pass'
}).Count -eq 0) 'the public record keeps the policy freshness class and does not pass it'

$cloudNow = [datetimeoffset]::Parse(
    '2026-11-15T00:00:00Z',
    [System.Globalization.CultureInfo]::InvariantCulture,
    [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
)
$cloudExpired = Invoke-Gate -Pack $complete -At $cloudNow
Assert-Equal $false $cloudExpired.Manifest.unsignedContentQualified `
    'cloud and network evidence expires after 90 days'
Assert-Equal $true (@($cloudExpired.Manifest.gates | Where-Object {
    $_.freshnessClass -eq 'CloudIdentityManagementSecurityNetwork' -and $_.result -eq 'Expired'
}).Count -ge 1) 'cloud-class gates expire after 90 days'

$stickyFail = Copy-Pack $complete
$failedGate = @($stickyFail.gates | Where-Object {
    $_.gateId -eq 'deterministic-contract-schema-and-artifact-gates'
})[0]
$failedGate.result = 'ProductFail'
$failedGate.reasonCode = 'GATE.PRODUCT_FAIL'
$failedGate.observedAt = '2026-07-31T00:00:00Z'
$stickyFail.gates += [pscustomobject]@{
    gateId = 'deterministic-contract-schema-and-artifact-gates'
    result = 'Pass'
    reasonCode = 'GATE.PASS'
    affectedClaimIds = @('CAP-0030')
    observedAt = '2026-08-02T00:00:00Z'
    freshnessClass = 'Automated'
    generatedContentSha256 = ('f' * 64)
    runtimeVersion = '7.6.0'
    architecture = 'x64'
    locale = 'en-US'
    cleanupVerified = $true
}
$stickyFailResult = Invoke-Gate -Pack $stickyFail
Assert-Equal 'ProductFail' @($stickyFailResult.Manifest.gates | Where-Object {
    $_.gateId -eq 'deterministic-contract-schema-and-artifact-gates'
})[0].result 'a later wrong-candidate row cannot erase ProductFail'
Assert-Equal $false $stickyFailResult.Manifest.unsignedContentQualified `
    'ProductFail remains a blocking result'

$mixedCandidate = Copy-Pack $complete
$mixedCandidate.gates += [pscustomobject]@{
    gateId = 'privacy-secret-exclusion-and-evidence-protection-gates'
    result = 'Pass'
    reasonCode = 'GATE.PASS'
    affectedClaimIds = @('CAP-0030')
    observedAt = '2026-08-02T00:00:00Z'
    freshnessClass = 'Automated'
    generatedContentSha256 = ('f' * 64)
    runtimeVersion = '7.6.0'
    architecture = 'x64'
    locale = 'en-US'
    cleanupVerified = $true
}
$mixedCandidateResult = Invoke-Gate -Pack $mixedCandidate
Assert-Equal $false $mixedCandidateResult.Manifest.unsignedContentQualified `
    'wrong-candidate evidence cannot be averaged with a later Pass'
Assert-Equal $true (
    'GATE.CANDIDATE_MISMATCH' -in @($mixedCandidateResult.Manifest.promotion.blockingReasons)
) 'a mixed-candidate gate set blocks the claim'

$restricted = Copy-Pack $complete
$restricted | Add-Member -NotePropertyName leak -NotePropertyValue 'win-pcinfo.assessment-record' -Force
$restrictedResult = Invoke-ReleaseGateEvaluation -Pack $restricted -Policy $policy -Ledger $ledger `
    -ReleaseDefinition $releaseDefinition -ExpectedLedgerSha256 $ledgerDigest -Now $now `
    -RepositoryRoot $repositoryRoot
Assert-Equal 'Rejected' $restrictedResult.State 'restricted evidence fails closed before evaluation'
Assert-Equal 'GATE.PRIVACY_REJECTED' $restrictedResult.ReasonCode `
    'Assessment Record material is not public Release Evidence'

$workspace = Join-Path ([System.IO.Path]::GetTempPath()) (
    'win-pcinfo-release-gates-' + [guid]::NewGuid().ToString('N')
)
$null = New-Item -ItemType Directory -Path $workspace -Force
try {
    $cleaned = Invoke-Gate -Pack $complete -WorkspacePath $workspace
    Assert-Equal $true $cleaned.CleanupVerified 'the gate removes its derived workspace file'
    Assert-Equal $false (
        Test-Path -LiteralPath (Join-Path $workspace 'derived-public-manifest.json')
    ) 'no derived public manifest remains after cleanup'
    Assert-Equal $true $cleaned.Manifest.cleanupVerified `
        'the public manifest records verified cleanup'
}
finally {
    if (Test-Path -LiteralPath $workspace) {
        Remove-Item -LiteralPath $workspace -Recurse -Force
    }
}

$repoWorkspace = Join-Path $repositoryRoot '.test-output/release-gates-forbidden'
$null = New-Item -ItemType Directory -Path $repoWorkspace -Force
try {
    $repoRejected = Invoke-Gate -Pack $complete -WorkspacePath $repoWorkspace
    Assert-Equal 'Rejected' $repoRejected.State 'a repository workspace is rejected'
    Assert-Equal 'GATE.PRIVACY_REJECTED' $repoRejected.ReasonCode `
        'in-repository gate residue is a privacy failure'
    Assert-Equal $false (
        Test-Path -LiteralPath (Join-Path $repoWorkspace 'derived-public-manifest.json')
    ) 'the gate does not write derived files into the repository'
}
finally {
    if (Test-Path -LiteralPath $repoWorkspace) {
        Remove-Item -LiteralPath $repoWorkspace -Recurse -Force
    }
}

Write-Output 'PASS: release-gate decisions cover complete, missing, failed, expired, and private packs.'
