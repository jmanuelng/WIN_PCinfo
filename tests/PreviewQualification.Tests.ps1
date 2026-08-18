[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/ReleaseGates.ps1')
. (Join-Path $repositoryRoot 'src/PreviewQualification.ps1')

$policy = Get-PreviewQualificationPolicy
$packetSchemaPath = Join-Path $repositoryRoot 'schemas/preview-qualification-packet.schema.json'
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
$ledgerDigest = Get-PreviewQualificationSha256 -Bytes $ledgerBytes
$now = [datetimeoffset]::Parse(
    '2026-08-17T00:00:00Z',
    [System.Globalization.CultureInfo]::InvariantCulture,
    [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
)

$workRoot = Join-Path $repositoryRoot '.test-output/preview-qualification-module'
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $workRoot -Force

$candidatePath = Join-Path $workRoot 'WIN-PCInfo.ps1'
$candidateLines = @(
    'param([string] $Workflow)'
    'Write-Output ''{"recordType":"win-pcinfo.product-help","collectionStarted":false}'''
    'Write-Output ''{"recordType":"win-pcinfo.terminal","outcome":"Completed","reasonCode":"HELP.DISCOVERY_COMPLETE","collectionStarted":false}'''
)
[System.IO.File]::WriteAllText(
    $candidatePath,
    ($candidateLines -join "`r`n") + "`r`n",
    [System.Text.UTF8Encoding]::new($false)
)
$candidateDigest = Get-PreviewQualificationSha256 -Bytes (
    [System.IO.File]::ReadAllBytes($candidatePath)
)
$finalDigest = Get-PreviewQualificationSha256 -Bytes (
    [System.Text.UTF8Encoding]::new($false).GetBytes("final:$candidateDigest")
)

function Get-RequestFromPath {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    Get-Content -LiteralPath $LiteralPath -Raw | ConvertFrom-Json -Depth 30
}

function Copy-Request {
    param([Parameter(Mandatory)] $Request)
    $Request | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
}

function Set-BoundDigests {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter()] [string] $ContentDigest = $candidateDigest,
        [Parameter()] [string] $PackageDigest = $finalDigest
    )
    $Request.bindings.generatedContentSha256 = $ContentDigest
    $Request.bindings.derivedFromGeneratedContentSha256 = $ContentDigest
    $Request.bindings.finalDistributableSha256 = $PackageDigest
    $Request.evidencePack.bindings.generatedContentSha256 = $ContentDigest
    $Request.evidencePack.bindings.ledgerSha256 = $ledgerDigest
    $Request.evidencePack.finalDistributable.packageSha256 = $PackageDigest
    $Request.evidencePack.finalDistributable.derivedFromGeneratedContentSha256 = $ContentDigest
    foreach ($gate in @($Request.evidencePack.gates)) {
        $gate.generatedContentSha256 = $ContentDigest
    }
    foreach ($scenario in @($Request.evidencePack.scenarios)) {
        $scenario.generatedContentSha256 = $ContentDigest
    }
    $Request
}

function New-MarkedWorkspace {
    param([Parameter(Mandatory)] [string] $Name)
    $path = Join-Path ([System.IO.Path]::GetTempPath()) "win-pcinfo-qualify-mod-$Name"
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $path -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $path $policy.workspace.markerFileName),
        ($policy.workspace.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $path
}

function Assert-PublicPacket {
    param(
        [Parameter(Mandatory)] $Evaluation,
        [Parameter(Mandatory)] [string] $Because
    )
    $packetJson = $Evaluation.Packet | ConvertTo-Json -Compress -Depth 20
    $manifestJson = $Evaluation.Manifest | ConvertTo-Json -Compress -Depth 20
    $matrixJson = $Evaluation.Matrix | ConvertTo-Json -Compress -Depth 20
    Assert-Equal $true (Test-Json -Json $packetJson -SchemaFile $packetSchemaPath) `
        "$Because packet satisfies the public schema"
    Assert-Equal $true (Test-Json -Json $manifestJson -SchemaFile $manifestSchemaPath) `
        "$Because manifest satisfies the public schema"
    Assert-Equal $true (Test-Json -Json $matrixJson -SchemaFile $matrixSchemaPath) `
        "$Because matrix satisfies the public schema"
    Assert-Equal 'None' $Evaluation.Packet.supportClaim "$Because makes no support claim"
    Assert-Equal 'None' $Evaluation.Packet.previewOrStableClaim "$Because makes no Preview claim"
    Assert-Equal $false $Evaluation.Packet.sliceDeliversCapability `
        "$Because does not deliver a Product Capability"
    Assert-Equal $false $Evaluation.Packet.collectionStarted "$Because never starts collection"
    Assert-Equal $false $Evaluation.Packet.publicationAuthorized `
        "$Because cannot authorize publication"
    Assert-Equal $true $Evaluation.Packet.humanApprovalRequired `
        "$Because still requires a human decision"
    Assert-Equal $false $Evaluation.Packet.attestedPreviewSatisfiesStableSigning `
        "$Because cannot satisfy Stable signing"
    Assert-Equal $false $Evaluation.Packet.liveAzureStarted "$Because never starts live Azure"
    foreach ($needle in @(
        '(?i)/subscriptions/'
        '(?i)\btenant\b'
        '(?i)clientSecret'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)\.terraform'
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
    )) {
        Assert-Equal $false ($packetJson -match $needle) "$Because packet must not match $needle"
    }
}

function Invoke-Qualify {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter()] [string] $Candidate = $candidatePath,
        [Parameter()] [datetimeoffset] $At = $now,
        [Parameter()] [string] $WorkspacePath,
        [Parameter()] [scriptblock] $Mutate
    )
    $contentDigest = Get-PreviewQualificationSha256 -Bytes (
        [System.IO.File]::ReadAllBytes($Candidate)
    )
    $packageDigest = Get-PreviewQualificationSha256 -Bytes (
        [System.Text.UTF8Encoding]::new($false).GetBytes("final:$contentDigest")
    )
    $prepared = Set-BoundDigests -Request (Copy-Request $Request) `
        -ContentDigest $contentDigest -PackageDigest $packageDigest
    if ($null -ne $Mutate) {
        & $Mutate $prepared
    }
    if ([string]::IsNullOrWhiteSpace($WorkspacePath)) {
        $WorkspacePath = New-MarkedWorkspace -Name ([guid]::NewGuid().ToString('N').Substring(0, 8))
    }
    Invoke-PreviewQualification -Request $prepared `
        -RequestText ($prepared | ConvertTo-Json -Depth 30) `
        -CandidatePath $Candidate -PrivateWorkspacePath $WorkspacePath `
        -RepositoryRoot $repositoryRoot -ApplicationDirectory $repositoryRoot `
        -Ledger $ledger -ReleaseDefinition $releaseDefinition `
        -ExpectedLedgerSha256 $ledgerDigest -Now $At
}

$complete = Get-RequestFromPath (
    Join-Path $PSScriptRoot 'fixtures/preview-qualification-complete-signed.json'
)

$approved = Invoke-Qualify -Request $complete
Assert-PublicPacket $approved 'a complete signed candidate'
Assert-Equal 'Approved' $approved.Packet.state 'a complete signed pack is approved'
Assert-Equal 'Qualify' $approved.Packet.decision 'a complete signed pack qualifies'
Assert-Equal 'Completed' $approved.ExitKind 'a complete signed pack completes'
Assert-Equal 'QUALIFY.APPROVED' $approved.ReasonCode 'the approval reason is stable'
Assert-Equal $true $approved.Packet.unsignedContentQualified `
    'unsigned generated content is qualified'
Assert-Equal $true $approved.Packet.finalArtifactQualified `
    'the distinct signed distributable is qualified'
Assert-Equal $true $approved.Packet.candidateBound 'the running candidate is bound'
Assert-Equal $true $approved.Packet.qualityThreeCleanPassed `
    'three independent clean measurements pass'
Assert-Equal $true $approved.Packet.cleanupVerified 'qualification cleanup is verified'
Assert-Equal $true $approved.Packet.zeroResidueVerified `
    'zero-residue evidence is recorded as verified'
Assert-Equal 'AuthenticodeSigned' $approved.Packet.trustPath `
    'the packet records the signed trust path'
Assert-Equal $true $approved.Packet.coverage.gatesComplete 'every required gate is present'
Assert-Equal $true $approved.Packet.coverage.privilegeComplete 'every privilege path is present'
Assert-Equal $true $approved.Packet.coverage.networkComplete 'both network behaviors are present'
Assert-Equal $true $approved.Packet.coverage.localeComplete 'every required locale is present'
Assert-Equal $true $approved.Packet.coverage.validationControlComplete `
    'restricted and full outbound controls are present'
Assert-Equal $true $approved.Packet.coverage.failureInjectionComplete `
    'every required failure injection is present'
Assert-Equal $true $approved.Packet.coverage.packageExerciseComplete `
    'every required package exercise is present'
Assert-Equal $true $approved.Packet.coverage.recoveryComplete 'stale recovery is present'
Assert-Equal 2 $approved.Packet.claimedScenarios.Count `
    'both claimed Windows Enterprise x64 scenarios are recorded'
Assert-Equal $true (@($approved.Packet.smokes | Where-Object smokeId -eq 'launch').Count -eq 1) `
    'launch Help smoke is recorded'
Assert-Equal 'Pass' @($approved.Packet.smokes | Where-Object smokeId -eq 'launch')[0].result `
    'Help smoke passes without collection'
Assert-Equal $false $approved.Packet.impactReview.completed `
    'human impact review remains incomplete'

$attested = Copy-Request $complete
$attested.scenario = 'CompleteAttestedFallback'
$attested.trustPath = 'AttestedPreview'
$attested.signingUnavailability = 'ArtifactSigningNotOperational'
$attested.bindings.finalDistributableIdentityKind =
    'win-pcinfo.unsigned-portable-package-identity'
$attested.evidencePack.finalDistributable.identityKind =
    'win-pcinfo.unsigned-portable-package-identity'
$attestedResult = Invoke-Qualify -Request $attested
Assert-PublicPacket $attestedResult 'a genuine Attested Preview fallback'
Assert-Equal 'Approved' $attestedResult.Packet.state `
    'a genuine attested fallback can still qualify the unsigned package'
Assert-Equal 'AttestedPreview' $attestedResult.Packet.trustPath `
    'the packet records the attested trust path'
Assert-Equal $false $attestedResult.Packet.attestedPreviewSatisfiesStableSigning `
    'attested qualification still cannot satisfy Stable'

$convenience = Copy-Request $attested
$convenience.scenario = 'AttestedConvenience'
$convenience.signingUnavailability = 'None'
$convenienceResult = Invoke-Qualify -Request $convenience
Assert-PublicPacket $convenienceResult 'Attested Preview chosen for convenience'
Assert-Equal 'Denied' $convenienceResult.Packet.state `
    'convenience cannot use the attested fallback'
Assert-Equal 'QUALIFY.ATTESTED_CONVENIENCE' $convenienceResult.ReasonCode `
    'convenience uses a stable denial reason'

$missing = Copy-Request $complete
$missing.scenario = 'MissingEvidence'
$missing.validationControls = @($missing.validationControls | Where-Object {
    $_.controlId -ne 'RestrictedOutbound'
})
$missingResult = Invoke-Qualify -Request $missing
Assert-PublicPacket $missingResult 'a missing required validation control'
Assert-Equal 'Denied' $missingResult.Packet.state 'missing coverage denies the packet'
Assert-Equal $true (
    'QUALIFY.EVIDENCE_INCOMPLETE' -in @($missingResult.Packet.blockingReasons)
) 'missing coverage is recorded as incomplete evidence'

$failed = Copy-Request $complete
$failed.scenario = 'ProductFail'
@($failed.evidencePack.gates | Where-Object {
    $_.gateId -eq 'deterministic-contract-schema-and-artifact-gates'
})[0].result = 'ProductFail'
@($failed.evidencePack.gates | Where-Object {
    $_.gateId -eq 'deterministic-contract-schema-and-artifact-gates'
})[0].reasonCode = 'GATE.PRODUCT_FAIL'
$failedResult = Invoke-Qualify -Request $failed
Assert-PublicPacket $failedResult 'a product-failed gate'
Assert-Equal 'Denied' $failedResult.Packet.state 'a ProductFail denies the packet'
Assert-Equal $false $failedResult.Packet.unsignedContentQualified `
    'a ProductFail cannot qualify the candidate'

$expired = Copy-Request $complete
$expired.scenario = 'ExpiredEvidence'
$expiredNow = [datetimeoffset]::Parse(
    '2026-09-15T00:00:00Z',
    [System.Globalization.CultureInfo]::InvariantCulture,
    [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
)
$expiredResult = Invoke-Qualify -Request $expired -At $expiredNow
Assert-PublicPacket $expiredResult 'stale Client VM evidence'
Assert-Equal 'Denied' $expiredResult.Packet.state 'expired Client VM evidence denies the packet'

$wrong = Copy-Request $complete
$wrong.scenario = 'WrongCandidate'
$wrongResult = Invoke-Qualify -Request $wrong -Mutate {
    param($Prepared)
    $Prepared.bindings.generatedContentSha256 =
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
}
Assert-PublicPacket $wrongResult 'a request bound to a different digest'
Assert-Equal 'Denied' $wrongResult.Packet.state 'a wrong candidate denies the packet'
Assert-Equal 'QUALIFY.CANDIDATE_MISMATCH' $wrongResult.ReasonCode `
    'the wrong candidate uses a stable reason'

$secretRequest = Copy-Request $complete
$secretText = ($secretRequest | ConvertTo-Json -Depth 30) + "`n`"leak`":`"clientSecret=not-a-real-secret`"`n"
$secretWorkspace = New-MarkedWorkspace -Name 'secret'
$secretResult = Invoke-PreviewQualification -Request $secretRequest -RequestText $secretText `
    -CandidatePath $candidatePath -PrivateWorkspacePath $secretWorkspace `
    -RepositoryRoot $repositoryRoot -ApplicationDirectory $repositoryRoot `
    -Ledger $ledger -ReleaseDefinition $releaseDefinition `
    -ExpectedLedgerSha256 $ledgerDigest -Now $now
Assert-PublicPacket $secretResult 'a privacy-violating request'
Assert-Equal 'Rejected' $secretResult.Packet.state 'a secret stays NotStarted'
Assert-Equal 'NotStarted' $secretResult.ExitKind 'privacy rejection does not evaluate'
Assert-Equal 'QUALIFY.PRIVACY_REJECTED' $secretResult.ReasonCode `
    'privacy rejection uses a stable reason'

$cleanup = Copy-Request $complete
$cleanup.scenario = 'CleanupPending'
$cleanup.cleanupPending = $true
$cleanupResult = Invoke-Qualify -Request $cleanup
Assert-PublicPacket $cleanupResult 'cleanup still pending'
Assert-Equal 'Denied' $cleanupResult.Packet.state 'cleanup-pending evidence denies the packet'
Assert-Equal 'QUALIFY.CLEANUP_PENDING' $cleanupResult.ReasonCode `
    'cleanup-pending uses a stable reason'

$waiver = Copy-Request $complete
$waiver.scenario = 'WaiverRequested'
$waiver.waiverRequested = $true
$waiver.evidencePack.waiverRequested = $true
$waiverResult = Invoke-Qualify -Request $waiver
Assert-PublicPacket $waiverResult 'a requested waiver'
Assert-Equal 'Denied' $waiverResult.Packet.state 'a waiver denies the packet'
Assert-Equal $true (
    'QUALIFY.WAIVER_REJECTED' -in @($waiverResult.Packet.blockingReasons)
) 'a waiver cannot promote the candidate'

$overclaim = Copy-Request $complete
$overclaim.scenario = 'AzureOverclaim'
$overclaim.liveAzureStarted = $true
$overclaimResult = Invoke-Qualify -Request $overclaim
Assert-PublicPacket $overclaimResult 'a live Azure overclaim'
Assert-Equal 'Denied' $overclaimResult.Packet.state 'claiming live Azure denies the packet'
Assert-Equal 'QUALIFY.AZURE_OVERCLAIM' $overclaimResult.ReasonCode `
    'an Azure overclaim uses a stable reason'

$unsignedAsFinal = Copy-Request $complete
$unsignedAsFinal.scenario = 'UnsignedAsFinal'
$unsignedAsFinalResult = Invoke-Qualify -Request $unsignedAsFinal -Mutate {
    param($Prepared)
    $Prepared.bindings.finalDistributableSha256 = $candidateDigest
    $Prepared.evidencePack.finalDistributable.packageSha256 = $candidateDigest
}
Assert-PublicPacket $unsignedAsFinalResult 'reusing the generated-content digest as the final identity'
Assert-Equal 'Denied' $unsignedAsFinalResult.Packet.state `
    'the generated script cannot be the final distributable'
Assert-Equal 'QUALIFY.FINAL_IDENTITY_NOT_DISTINCT' $unsignedAsFinalResult.ReasonCode `
    'a reused digest uses a stable reason'

$live = Copy-Request $complete
$live.scenario = 'LiveValidation'
$live.evidenceKind = 'LiveValidation'
$liveResult = Invoke-Qualify -Request $live
Assert-PublicPacket $liveResult 'a live-validation request on this host'
Assert-Equal 'Denied' $liveResult.Packet.state 'live validation stays unavailable'
Assert-Equal 'QUALIFY.LIVE_AZURE_NOT_STARTED' $liveResult.ReasonCode `
    'live Azure stays NotStarted without identity'

$brokenCandidate = Join-Path $workRoot 'broken.ps1'
[System.IO.File]::WriteAllText(
    $brokenCandidate,
    "throw 'broken'`r`n",
    [System.Text.UTF8Encoding]::new($false)
)
$broken = Copy-Request $complete
$brokenResult = Invoke-Qualify -Request $broken -Candidate $brokenCandidate
Assert-PublicPacket $brokenResult 'a candidate that cannot launch Help'
Assert-Equal 'Denied' $brokenResult.Packet.state 'a failed launch smoke denies the packet'
Assert-Equal 'QUALIFY.SMOKE_FAILED' $brokenResult.ReasonCode `
    'a failed Help smoke uses a stable reason'

$repoWorkspace = Join-Path $repositoryRoot '.test-output/preview-qualification-repo-ws'
if (Test-Path -LiteralPath $repoWorkspace) {
    Remove-Item -LiteralPath $repoWorkspace -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $repoWorkspace -Force
[System.IO.File]::WriteAllText(
    (Join-Path $repoWorkspace $policy.workspace.markerFileName),
    ($policy.workspace.markerContent + "`n"),
    [System.Text.UTF8Encoding]::new($false)
)
$repoResult = Invoke-Qualify -Request $complete -WorkspacePath $repoWorkspace
Assert-PublicPacket $repoResult 'a repository workspace'
Assert-Equal 'Rejected' $repoResult.Packet.state 'a repository workspace is rejected'
Assert-Equal 'NotStarted' $repoResult.ExitKind 'a repository workspace stays NotStarted'

Write-Output 'PASS: Preview qualification decision engine covers approval and every required denial.'
