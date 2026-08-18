[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/PreviewPublication.ps1')

$policy = Get-PreviewPublicationPolicy
$resultSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication-result.schema.json'
$previewSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication-preview.schema.json'

$workRoot = Join-Path $repositoryRoot '.test-output/preview-publication-module'
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
$candidateDigest = Get-PreviewPublicationSha256 -Bytes (
    [System.IO.File]::ReadAllBytes($candidatePath)
)

function Get-RequestFromPath {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    Get-Content -LiteralPath $LiteralPath -Raw | ConvertFrom-Json -Depth 30
}

function Copy-Request {
    param([Parameter(Mandatory)] $Request)
    $Request | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
}

function Set-BoundPublicationRequest {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter()] [string] $ContentDigest = $candidateDigest
    )

    $Request.bindings.generatedContentSha256 = $ContentDigest
    $Request.bindings.derivedFromGeneratedContentSha256 = $ContentDigest
    foreach ($asset in @($Request.assets)) {
        $asset.sha256 = Get-PreviewPublicationSha256 -Bytes (
            Get-PreviewPublicationSyntheticAssetBytes -AssetId ([string] $asset.assetId)
        )
        if ([string] $asset.assetId -eq 'portable-package') {
            $Request.bindings.finalDistributableSha256 = [string] $asset.sha256
        }
    }
    $Request.humanApproval.candidateDigest = $ContentDigest
    $Request.humanApproval.qualificationPacketDigest =
        Get-PreviewPublicationPacketDigest -Packet $Request.qualificationPacket
    $mergedLimitations = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($policy.requiredLimitations)) {
        $mergedLimitations.Add([string] $item)
    }
    foreach ($item in @($Request.limitations)) {
        if ([string] $item -notin @($mergedLimitations)) {
            $mergedLimitations.Add([string] $item)
        }
    }
    if ([string] $Request.trustPath -eq 'AttestedPreview' -and
        'attested-preview-not-trusted' -notin @($mergedLimitations)) {
        $mergedLimitations.Add('attested-preview-not-trusted')
    }
    $Request.humanApproval.limitationsDigest =
        Get-PreviewPublicationLimitationsDigest -Limitations @($mergedLimitations)
    $Request.humanApproval.publicAssetListDigest =
        Get-PreviewPublicationAssetListDigest -Assets $Request.assets
    $Request.humanApproval.trustPath = [string] $Request.trustPath
    $Request
}

function New-MarkedWorkspace {
    param([Parameter(Mandatory)] [string] $Name)
    $path = Join-Path ([System.IO.Path]::GetTempPath()) "win-pcinfo-publish-mod-$Name"
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

function Assert-PublicPublication {
    param(
        [Parameter(Mandatory)] $Evaluation,
        [Parameter(Mandatory)] [string] $Because
    )
    $resultJson = $Evaluation.Result | ConvertTo-Json -Compress -Depth 20
    $previewJson = $Evaluation.Preview | ConvertTo-Json -Compress -Depth 20
    Assert-Equal $true (Test-Json -Json $resultJson -SchemaFile $resultSchemaPath) `
        "$Because result satisfies the public schema"
    Assert-Equal $true (Test-Json -Json $previewJson -SchemaFile $previewSchemaPath) `
        "$Because preview satisfies the public schema"
    Assert-Equal 'None' $Evaluation.Result.supportClaim "$Because makes no support claim"
    Assert-Equal 'None' $Evaluation.Result.previewOrStableClaim "$Because makes no Preview claim"
    Assert-Equal $false $Evaluation.Result.sliceDeliversCapability `
        "$Because does not deliver a Product Capability"
    Assert-Equal $false $Evaluation.Result.collectionStarted "$Because never starts collection"
    Assert-Equal $false $Evaluation.Result.publicationAuthorized `
        "$Because cannot authorize live publication"
    Assert-Equal $false $Evaluation.Result.githubReleaseCreated `
        "$Because never creates a GitHub release"
    Assert-Equal $true $Evaluation.Result.humanApprovalRequired `
        "$Because still requires a human decision"
    Assert-Equal $false $Evaluation.Result.attestedPreviewSatisfiesStableSigning `
        "$Because cannot satisfy Stable signing"
    Assert-Equal $true $Evaluation.Preview.prerelease "$Because marks the public record as prerelease"
    Assert-Equal 'Preview' $Evaluation.Preview.channel "$Because labels the public channel Preview"
    Assert-Equal $true ($previewJson -match 'no Supported') `
        "$Because preview must deny a Supported claim"
    foreach ($needle in @(
        '(?i)/subscriptions/'
        '(?i)\btenant\b'
        '(?i)clientSecret'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)\.terraform'
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
    )) {
        Assert-Equal $false ($resultJson -match $needle) "$Because result must not match $needle"
        Assert-Equal $false ($previewJson -match $needle) "$Because preview must not match $needle"
    }
}

function Invoke-Publish {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter()] [string] $Candidate = $candidatePath,
        [Parameter()] [string] $WorkspacePath,
        [Parameter()] [scriptblock] $Mutate
    )
    $contentDigest = Get-PreviewPublicationSha256 -Bytes (
        [System.IO.File]::ReadAllBytes($Candidate)
    )
    $prepared = Set-BoundPublicationRequest -Request (Copy-Request $Request) `
        -ContentDigest $contentDigest
    if ($null -ne $Mutate) {
        & $Mutate $prepared
    }
    if ([string]::IsNullOrWhiteSpace($WorkspacePath)) {
        $WorkspacePath = New-MarkedWorkspace -Name ([guid]::NewGuid().ToString('N').Substring(0, 8))
    }
    Invoke-PreviewPublication -Request $prepared `
        -RequestText ($prepared | ConvertTo-Json -Depth 30) `
        -CandidatePath $Candidate -PrivateWorkspacePath $WorkspacePath `
        -RepositoryRoot $repositoryRoot -ApplicationDirectory $repositoryRoot
}

$complete = Get-RequestFromPath (
    Join-Path $PSScriptRoot 'fixtures/preview-publication-complete-signed.json'
)

$published = Invoke-Publish -Request $complete
Assert-PublicPublication $published 'a complete approved signed candidate'
Assert-Equal 'PublishedAndVerified' $published.Result.state `
    'a complete approved signed pack publishes synthetically'
Assert-Equal 'Publish' $published.Result.decision 'a complete approved pack decides Publish'
Assert-Equal 'Completed' $published.ExitKind 'a complete approved pack completes'
Assert-Equal 'PUBLISH.PUBLISHED_AND_VERIFIED' $published.ReasonCode `
    'the synthetic publication reason is stable'
Assert-Equal $true $published.Result.candidateBound 'the running candidate is bound'
Assert-Equal $true $published.Result.qualificationApproved 'the embedded packet is approved'
Assert-Equal $true $published.Result.assetsVerified 'every public asset digest is verified'
Assert-Equal $true $published.Result.downloadVerified `
    'the independent download matches the staged digests'
Assert-Equal $true $published.Result.humanApprovalPresent 'human approval was present'
Assert-Equal 'AuthenticodeSigned' $published.Result.trustPath `
    'the result records the signed trust path'
Assert-Equal $false $published.Preview.attestedPreviewWarning `
    'a signed path does not emit the attested warning'
Assert-Equal 'Pass' @($published.Result.smokes | Where-Object smokeId -eq 'launch')[0].result `
    'Help smoke passes without collection'
Assert-Equal 'Pass' @($published.Result.smokes | Where-Object smokeId -eq 'download')[0].result `
    'download smoke passes'
Assert-Equal 'Pass' @($published.Result.smokes | Where-Object smokeId -eq 'beginner-instructions')[0].result `
    'beginner-instruction smoke passes'
Assert-Equal $true ($published.Preview.notes -join ' ' -match 'no Supported') `
    'the public notes deny a Supported claim'
Assert-Equal $true ($published.Preview.notes -join ' ' -match 'best effort') `
    'the public notes state best-effort maintenance'

$attested = Copy-Request $complete
$attested.scenario = 'CompleteApprovedAttested'
$attested.trustPath = 'AttestedPreview'
$attested.signingUnavailability = 'ArtifactSigningNotOperational'
$attested.bindings.finalDistributableIdentityKind =
    'win-pcinfo.unsigned-portable-package-identity'
$attested.qualificationPacket.trustPath = 'AttestedPreview'
$attested.limitations = @($attested.limitations + @('attested-preview-not-trusted'))
$attestedResult = Invoke-Publish -Request $attested
Assert-PublicPublication $attestedResult 'a genuine Attested Preview fallback'
Assert-Equal 'PublishedAndVerified' $attestedResult.Result.state `
    'a genuine attested fallback can still publish synthetically'
Assert-Equal 'AttestedPreview' $attestedResult.Result.trustPath `
    'the result records the attested trust path'
Assert-Equal $true $attestedResult.Preview.attestedPreviewWarning `
    'the public record shows the attested warning'
Assert-Equal $true ($attestedResult.Preview.notes[0] -match 'UNSIGNED LIMITED-TRUST WARNING') `
    'the attested warning is the first public note'

$missingApproval = Copy-Request $complete
$missingApproval.scenario = 'HumanApprovalMissing'
$missingApproval.humanApproval.present = $false
$missingApproval.humanApproval.confirmationPhrase = ''
$missingResult = Invoke-Publish -Request $missingApproval
Assert-PublicPublication $missingResult 'a preview without human approval'
Assert-Equal 'Previewed' $missingResult.Result.state 'missing approval still previews'
Assert-Equal 'AwaitingHumanApproval' $missingResult.Result.decision `
    'missing approval waits for the human'
Assert-Equal 'PUBLISH.HUMAN_APPROVAL_REQUIRED' $missingResult.ReasonCode `
    'missing approval uses a stable reason'
Assert-Equal $false $missingResult.Result.downloadVerified `
    'missing approval does not publish'

$mismatch = Invoke-Publish -Request $complete -Mutate {
    param($Prepared)
    $Prepared.scenario = 'ApprovalMismatch'
    $Prepared.humanApproval.candidateDigest =
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
}
Assert-PublicPublication $mismatch 'a mismatched human approval'
Assert-Equal 'Denied' $mismatch.Result.state 'a mismatched approval denies publication'
Assert-Equal 'PUBLISH.APPROVAL_MISMATCH' $mismatch.ReasonCode `
    'a mismatched approval uses a stable reason'

$deniedPacket = Copy-Request $complete
$deniedPacket.scenario = 'QualificationDenied'
$deniedPacket.qualificationPacket.state = 'Denied'
$deniedPacket.qualificationPacket.decision = 'Deny'
$deniedPacket.qualificationPacket.reasonCode = 'QUALIFY.DENIED'
$deniedPacket.qualificationPacket.finalArtifactQualified = $false
$deniedResult = Invoke-Publish -Request $deniedPacket
Assert-PublicPublication $deniedResult 'a denied qualification packet'
Assert-Equal 'Denied' $deniedResult.Result.state 'a denied packet cannot publish'
Assert-Equal 'PUBLISH.QUALIFICATION_DENIED' $deniedResult.ReasonCode `
    'a denied packet uses a stable reason'

$wrong = Invoke-Publish -Request $complete -Mutate {
    param($Prepared)
    $Prepared.scenario = 'WrongCandidate'
    $Prepared.bindings.generatedContentSha256 =
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
}
Assert-PublicPublication $wrong 'a request bound to a different digest'
Assert-Equal 'Denied' $wrong.Result.state 'a wrong candidate denies publication'
Assert-Equal 'PUBLISH.CANDIDATE_MISMATCH' $wrong.ReasonCode `
    'the wrong candidate uses a stable reason'

$secretRequest = Set-BoundPublicationRequest -Request (Copy-Request $complete)
$secretText = ($secretRequest | ConvertTo-Json -Depth 30) +
    "`n`"leak`":`"clientSecret=not-a-real-secret`"`n"
$secretWorkspace = New-MarkedWorkspace -Name 'secret'
$secretResult = Invoke-PreviewPublication -Request $secretRequest -RequestText $secretText `
    -CandidatePath $candidatePath -PrivateWorkspacePath $secretWorkspace `
    -RepositoryRoot $repositoryRoot -ApplicationDirectory $repositoryRoot
Assert-PublicPublication $secretResult 'a privacy-violating request'
Assert-Equal 'Rejected' $secretResult.Result.state 'a secret stays NotStarted'
Assert-Equal 'NotStarted' $secretResult.ExitKind 'privacy rejection does not evaluate'
Assert-Equal 'PUBLISH.PRIVACY_REJECTED' $secretResult.ReasonCode `
    'privacy rejection uses a stable reason'

$replace = Copy-Request $complete
$replace.scenario = 'SilentReplacement'
$replace.publisher.replaceRequested = $true
$replaceResult = Invoke-Publish -Request $replace
Assert-PublicPublication $replaceResult 'a silent replacement request'
Assert-Equal 'Denied' $replaceResult.Result.state 'silent replacement is denied'
Assert-Equal 'PUBLISH.SILENT_REPLACEMENT_REJECTED' $replaceResult.ReasonCode `
    'silent replacement uses a stable reason'
Assert-Equal $true $replaceResult.Result.silentReplacementAttempted `
    'the result records that replacement was requested'

$github = Copy-Request $complete
$github.scenario = 'GithubAuthUnavailable'
$github.publisher.channel = 'GitHub'
$github.publisher.githubAuthAvailable = $false
$githubResult = Invoke-Publish -Request $github
Assert-PublicPublication $githubResult 'a GitHub request without authentication'
Assert-Equal 'Denied' $githubResult.Result.state 'GitHub without auth cannot publish'
Assert-Equal 'PUBLISH.GITHUB_AUTH_UNAVAILABLE' $githubResult.ReasonCode `
    'missing GitHub auth uses a stable reason'

$githubAuth = Copy-Request $complete
$githubAuth.publisher.channel = 'GitHub'
$githubAuth.publisher.githubAuthAvailable = $true
$githubAuthResult = Invoke-Publish -Request $githubAuth
Assert-PublicPublication $githubAuthResult 'a synthetic GitHub request with auth present'
Assert-Equal 'Denied' $githubAuthResult.Result.state `
    'synthetic evidence cannot create the GitHub release'
Assert-Equal 'PUBLISH.SYNTHETIC_CANNOT_PUBLISH_GITHUB' $githubAuthResult.ReasonCode `
    'synthetic GitHub publication uses a stable reason'
Assert-Equal $false $githubAuthResult.Result.githubReleaseCreated `
    'no GitHub release is created'

$exists = Copy-Request $complete
$exists.scenario = 'ImmutableTagExists'
$exists.publisher.existingTag = $true
$existsResult = Invoke-Publish -Request $exists
Assert-PublicPublication $existsResult 'an already published immutable tag'
Assert-Equal 'Denied' $existsResult.Result.state 'an existing tag cannot be republished'
Assert-Equal 'PUBLISH.IMMUTABLE_TAG_EXISTS' $existsResult.ReasonCode `
    'an existing tag uses a stable reason'

$tamper = Copy-Request $complete
$tamper.scenario = 'DownloadDigestMismatch'
$tamper.publisher.fault = 'TamperDownload'
$tamperResult = Invoke-Publish -Request $tamper
Assert-PublicPublication $tamperResult 'a tampered independent download'
Assert-Equal 'Denied' $tamperResult.Result.state 'a download mismatch denies publication'
Assert-Equal 'PUBLISH.DOWNLOAD_MISMATCH' $tamperResult.ReasonCode `
    'a download mismatch uses a stable reason'
Assert-Equal $false $tamperResult.Result.downloadVerified `
    'a tampered download is not verified'

$overclaim = Copy-Request $complete
$overclaim.qualificationPacket.publicationAuthorized = $true
$overclaimResult = Invoke-Publish -Request $overclaim
Assert-PublicPublication $overclaimResult 'a qualification packet that claims publication'
Assert-Equal 'Denied' $overclaimResult.Result.state 'an overclaiming packet is denied'
Assert-Equal 'PUBLISH.QUALIFICATION_OVERCLAIM' $overclaimResult.ReasonCode `
    'a publication overclaim uses a stable reason'

$convenience = Copy-Request $attested
$convenience.signingUnavailability = 'None'
$convenienceResult = Invoke-Publish -Request $convenience
Assert-PublicPublication $convenienceResult 'Attested Preview chosen for convenience'
Assert-Equal 'Denied' $convenienceResult.Result.state `
    'convenience cannot use the attested fallback'
Assert-Equal 'PUBLISH.ATTESTED_CONVENIENCE' $convenienceResult.ReasonCode `
    'convenience uses a stable reason'

$waiver = Copy-Request $complete
$waiver.waiverRequested = $true
$waiverResult = Invoke-Publish -Request $waiver
Assert-PublicPublication $waiverResult 'a requested waiver'
Assert-Equal 'Denied' $waiverResult.Result.state 'a waiver cannot publish'
Assert-Equal 'PUBLISH.WAIVER_REJECTED' $waiverResult.ReasonCode `
    'a waiver uses a stable reason'

$unboundPacket = Copy-Request $complete
$unboundPacket.qualificationPacket.candidateBound = $false
$unboundResult = Invoke-Publish -Request $unboundPacket
Assert-PublicPublication $unboundResult 'an approved packet that is not candidate-bound'
Assert-Equal 'Denied' $unboundResult.Result.state `
    'an unbound qualification packet cannot publish'
Assert-Equal 'PUBLISH.QUALIFICATION_DENIED' $unboundResult.ReasonCode `
    'an unbound packet uses a stable reason'

$repoWorkspace = Join-Path $repositoryRoot '.test-output/preview-publication-repo-ws'
if (Test-Path -LiteralPath $repoWorkspace) {
    Remove-Item -LiteralPath $repoWorkspace -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $repoWorkspace -Force
[System.IO.File]::WriteAllText(
    (Join-Path $repoWorkspace $policy.workspace.markerFileName),
    ($policy.workspace.markerContent + "`n"),
    [System.Text.UTF8Encoding]::new($false)
)
$repoResult = Invoke-Publish -Request $complete -WorkspacePath $repoWorkspace
Assert-PublicPublication $repoResult 'a repository workspace'
Assert-Equal 'Rejected' $repoResult.Result.state 'a repository workspace is rejected'
Assert-Equal 'NotStarted' $repoResult.ExitKind 'a repository workspace stays NotStarted'
Assert-Equal 'PUBLISH.WORKSPACE_REPOSITORY_PATH' $repoResult.ReasonCode `
    'a repository workspace uses a stable reason'

$misrootedWorkspace = Join-Path $repositoryRoot '.test-output/preview-publication-misrooted-ws'
if (Test-Path -LiteralPath $misrootedWorkspace) {
    Remove-Item -LiteralPath $misrootedWorkspace -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $misrootedWorkspace -Force
[System.IO.File]::WriteAllText(
    (Join-Path $misrootedWorkspace $policy.workspace.markerFileName),
    ($policy.workspace.markerContent + "`n"),
    [System.Text.UTF8Encoding]::new($false)
)
$misrootedPrepared = Set-BoundPublicationRequest -Request (Copy-Request $complete)
$misrootedResult = Invoke-PreviewPublication -Request $misrootedPrepared `
    -RequestText ($misrootedPrepared | ConvertTo-Json -Depth 30) `
    -CandidatePath $candidatePath -PrivateWorkspacePath $misrootedWorkspace `
    -RepositoryRoot (Join-Path $repositoryRoot 'docs') `
    -ApplicationDirectory $workRoot
Assert-PublicPublication $misrootedResult 'a repository workspace with a docs-only root'
Assert-Equal 'Rejected' $misrootedResult.Result.state `
    'a workspace under the real repository is rejected even when the caller passes docs'
Assert-Equal 'PUBLISH.WORKSPACE_REPOSITORY_PATH' $misrootedResult.ReasonCode `
    'the bound ledger root, not docs, owns the repository check'

$uncResult = Invoke-Publish -Request $complete -WorkspacePath '\\example\share\publish'
Assert-PublicPublication $uncResult 'a UNC workspace'
Assert-Equal 'Rejected' $uncResult.Result.state 'a UNC workspace is rejected'
Assert-Equal 'PUBLISH.WORKSPACE_UNC_PATH' $uncResult.ReasonCode `
    'a UNC workspace uses a stable reason'

$residueWorkspace = New-MarkedWorkspace -Name 'residue'
$residueResult = Invoke-Publish -Request $complete -WorkspacePath $residueWorkspace
Assert-PublicPublication $residueResult 'cleanup after a synthetic publication'
Assert-Equal 'PublishedAndVerified' $residueResult.Result.state `
    'the residue check uses a complete pack'
Assert-Equal $false (Test-Path -LiteralPath (
    Join-Path $residueWorkspace 'derived-publication-preview.json'
) -PathType Leaf) 'the derived preview does not remain'
Assert-Equal $false (Test-Path -LiteralPath (
    Join-Path $residueWorkspace 'staged-assets'
)) 'staged assets do not remain'
Assert-Equal $false (Test-Path -LiteralPath (
    Join-Path $residueWorkspace 'synthetic-publisher'
)) 'the synthetic publisher store does not remain'
Assert-Equal $false (Test-Path -LiteralPath (
    Join-Path $residueWorkspace 'downloaded-assets'
)) 'the independent download folder does not remain'
$residueLeft = @(Get-ChildItem -LiteralPath $residueWorkspace -Force | Where-Object {
    $_.Name -ne [string] $policy.workspace.markerFileName
})
Assert-Equal 0 $residueLeft.Count 'only the operator marker remains after publication'

$duplicate = Copy-Request $complete
$duplicate.assets = @($duplicate.assets + @($duplicate.assets[0]))
$duplicateResult = Invoke-Publish -Request $duplicate
Assert-PublicPublication $duplicateResult 'a request with a duplicated public asset'
Assert-Equal 'Denied' $duplicateResult.Result.state 'a duplicated asset cannot publish'
Assert-Equal 'PUBLISH.ASSET_INCOMPLETE' $duplicateResult.ReasonCode `
    'a duplicated asset uses a stable reason'

$escapeWorkspace = New-MarkedWorkspace -Name 'escape'
$escape = Invoke-Publish -Request $complete -WorkspacePath $escapeWorkspace -Mutate {
    param($Prepared)
    $Prepared.assets[0].fileName = '..\escape.txt'
}
Assert-PublicPublication $escape 'a path-escaping asset file name'
Assert-Equal 'Denied' $escape.Result.state 'a path-escaping file name is denied'
Assert-Equal 'PUBLISH.ASSET_INVALID' $escape.ReasonCode `
    'a path-escaping file name uses a stable reason'
Assert-Equal $false (Test-Path -LiteralPath (Join-Path $escapeWorkspace 'escape.txt')) `
    'a path-escaping name does not write beside the workspace marker'
Assert-Equal $false (Test-Path -LiteralPath (
    Join-Path $escapeWorkspace 'staged-assets\..\escape.txt'
)) 'a path-escaping name does not write through staged-assets'

$unknownChannel = Copy-Request $complete
$unknownChannel.publisher.channel = 'FileShare'
$unknownResult = Invoke-Publish -Request $unknownChannel
Assert-PublicPublication $unknownResult 'an unknown publisher channel'
Assert-Equal 'Denied' $unknownResult.Result.state 'an unknown channel cannot publish'
Assert-Equal 'PUBLISH.REQUEST_INVALID' $unknownResult.ReasonCode `
    'an unknown channel uses a stable reason'

Write-Output 'PASS: Preview publication evaluates staging, approval, immutability, and download verification.'
