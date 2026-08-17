[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/SigningBoundary.ps1')

$policy = Get-SigningBoundaryPolicy
$resultSchemaPath = Join-Path $repositoryRoot 'schemas/signing-session-result.schema.json'
$eligiblePath = Join-Path $PSScriptRoot 'fixtures/signing-session-eligible.json'

function Get-RequestFromPath {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    Get-Content -LiteralPath $LiteralPath -Raw | ConvertFrom-Json -Depth 20
}

function Copy-Request {
    param([Parameter(Mandatory)] $Request)
    $Request | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
}

function New-TinyCandidate {
    param([Parameter(Mandatory)] [string] $Directory)
    $path = Join-Path $Directory 'WIN-PCInfo.ps1'
    $text = @'
[CmdletBinding()]
param(
    [ValidateSet('Assessment', 'Help')]
    [string] $Workflow = 'Assessment'
)
if ($Workflow -eq 'Help') {
    Write-Output '{"recordType":"win-pcinfo.help","collectionStarted":false}'
    Write-Output '{"recordType":"win-pcinfo.terminal","outcome":"Completed","reasonCode":"HELP.DISCOVERY_COMPLETE","exitCode":0,"collectionStarted":false}'
    exit 0
}
Write-Output '{"recordType":"win-pcinfo.terminal","outcome":"NotStarted","reasonCode":"HELP.ONLY","exitCode":20,"collectionStarted":false}'
exit 20
'@
    [System.IO.File]::WriteAllText($path, $text, [System.Text.UTF8Encoding]::new($false))
    $path
}

function New-SigningWorkspace {
    param([Parameter(Mandatory)] [string] $Name)
    $root = Join-Path ([System.IO.Path]::GetTempPath()) "win-pcinfo-signing-$Name"
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $root -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $root $policy.workspace.markerFileName),
        ($policy.workspace.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $root
}

function Remove-SigningWorkspace {
    param([Parameter(Mandatory)] [string] $Path)
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function New-BoundRequest {
    param(
        [Parameter(Mandatory)] [string] $CandidatePath,
        [Parameter()] [string] $Scenario = 'EligibleSign',
        [Parameter()] [scriptblock] $Mutate
    )

    $request = Copy-Request (Get-RequestFromPath $eligiblePath)
    $digest = Get-SigningBoundarySha256 -Bytes ([System.IO.File]::ReadAllBytes($CandidatePath))
    $request.scenario = $Scenario
    $request.bindings.generatedContentSha256 = $digest
    $request.bindings.humanApproval.digestSha256 = $digest
    $request.bindings.unsignedContentQualified = $true
    $request.bindings.humanApproval.approved = $true
    $request.bindings.humanApproval.confirmation = [string] $policy.humanApproval.confirmationPhrase
    if ($null -ne $Mutate) {
        & $Mutate $request $digest
    }
    $request
}

function Invoke-Session {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] [string] $CandidatePath,
        [Parameter(Mandatory)] [string] $WorkspacePath
    )

    Invoke-SigningBoundarySession -Request $Request `
        -CandidatePath $CandidatePath `
        -PrivateWorkspacePath $WorkspacePath `
        -RepositoryRoot $repositoryRoot `
        -ApplicationDirectory (Split-Path -Parent $CandidatePath)
}

function Assert-PublicResult {
    param(
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)] [string] $Because,
        [Parameter()] [string] $WorkspacePath
    )

    $json = $Result | ConvertTo-Json -Compress -Depth 20
    Assert-Equal $true (Test-Json -Json $json -SchemaFile $resultSchemaPath) `
        "$Because result satisfies the public schema"
    Assert-Equal $false $Result.publicationAuthorized "$Because cannot authorize publication"
    Assert-Equal $false $Result.trustedPublicationPermitted "$Because cannot publish as Trusted"
    Assert-Equal $false $Result.satisfiesStableSigningGate "$Because cannot satisfy Stable"
    Assert-Equal $false $Result.sliceDeliversCapability "$Because does not deliver a capability"
    Assert-Equal $false $Result.collectionStarted "$Because never starts collection"
    Assert-Equal $false $Result.azureContacted "$Because does not contact Azure"
    Assert-Equal 'None' $Result.supportClaim "$Because makes no support claim"
    Assert-Equal $true $Result.sessionCapabilityRemoved "$Because removes the session capability"
    Assert-Equal $true $Result.sessionLeastPrivilege "$Because keeps least privilege"
    Assert-Equal $true $Result.sessionTimeBounded "$Because stays time-bounded"
    Assert-Equal $true $Result.sessionSpecific "$Because stays session-specific"
    if (-not [string]::IsNullOrWhiteSpace($WorkspacePath)) {
        Assert-Equal $false ($json -match [regex]::Escape($WorkspacePath)) `
            "$Because omits the workspace path"
    }
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
        Assert-Equal $false ($json -match $needle) "$Because must not match $needle"
    }
}

$workRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'win-pcinfo-signing-module-' + [guid]::NewGuid().ToString('N')
)
$null = New-Item -ItemType Directory -Path $workRoot -Force
$candidatePath = New-TinyCandidate -Directory $workRoot

try {
    $eligibleWorkspace = New-SigningWorkspace -Name 'eligible'
    $eligibleRequest = New-BoundRequest -CandidatePath $candidatePath
    $eligible = Invoke-Session -Request $eligibleRequest -CandidatePath $candidatePath `
        -WorkspacePath $eligibleWorkspace
    Assert-PublicResult $eligible 'eligible signing' -WorkspacePath $eligibleWorkspace
    Assert-Equal 'SignedAndVerified' $eligible.state 'eligible signing completes'
    Assert-Equal 'SIGNING.SIGNED_AND_VERIFIED' $eligible.reasonCode `
        'eligible signing uses the success reason'
    Assert-Equal $true $eligible.signed 'eligible signing produces a signed script'
    Assert-Equal $true $eligible.verified 'eligible signing verifies before smoke'
    Assert-Equal $true $eligible.smoked 'eligible signing smoke-runs Help'
    Assert-Equal $true $eligible.identitiesDistinct `
        'signed and final identities are distinct from the unsigned precursor'
    Assert-Equal $false $eligible.timestampedSigningByteReproducible `
        'timestamped signing is not claimed reproducible'
    Assert-Equal 'SyntheticSigningContract' $eligible.trustClass `
        'eligible synthetic signing stays on the synthetic trust class'
    Assert-Equal $true (
        $eligible.unsignedContentSha256 -ne $eligible.signedPrimaryScriptSha256
    ) 'Authenticode signing creates a distinct signed primary-script identity'
    Assert-Equal $true (
        $eligible.unsignedContentSha256 -ne $eligible.finalSignedDistributableSha256
    ) 'the final signed distributable is distinct from the unsigned content'
    $finalZip = Join-Path $eligibleWorkspace 'final/WIN-PCInfo-2.0.0-preview.1-signed.zip'
    Assert-Equal $true (Test-Path -LiteralPath $finalZip -PathType Leaf) `
        'eligible signing writes a finalized archive'
    $rebuild = Invoke-Session -Request $eligibleRequest -CandidatePath $candidatePath `
        -WorkspacePath $eligibleWorkspace
    Assert-Equal $eligible.finalSignedDistributableSha256 $rebuild.finalSignedDistributableSha256 `
        'final-package rebuild around the same signed input is deterministic'
    Remove-SigningWorkspace $eligibleWorkspace

    $wrongDigestWorkspace = New-SigningWorkspace -Name 'wrong-digest'
    $wrongDigestRequest = New-BoundRequest -CandidatePath $candidatePath -Mutate {
        param($Request)
        $Request.bindings.humanApproval.digestSha256 =
            'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    }
    $wrongDigest = Invoke-Session -Request $wrongDigestRequest -CandidatePath $candidatePath `
        -WorkspacePath $wrongDigestWorkspace
    Assert-PublicResult $wrongDigest 'wrong digest' -WorkspacePath $wrongDigestWorkspace
    Assert-Equal 'Rejected' $wrongDigest.state 'wrong digest is rejected'
    Assert-Equal 'SIGNING.WRONG_DIGEST' $wrongDigest.reasonCode 'wrong digest uses a stable reason'
    Assert-Equal $false $wrongDigest.signed 'wrong digest never signs'
    Assert-Equal $false $wrongDigest.smoked 'wrong digest never smokes'
    Remove-SigningWorkspace $wrongDigestWorkspace

    $wrongCandidateWorkspace = New-SigningWorkspace -Name 'wrong-candidate'
    $wrongCandidateRequest = New-BoundRequest -CandidatePath $candidatePath -Mutate {
        param($Request)
        $Request.bindings.generatedContentSha256 =
            'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
        $Request.bindings.humanApproval.digestSha256 =
            'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    }
    $wrongCandidate = Invoke-Session -Request $wrongCandidateRequest `
        -CandidatePath $candidatePath -WorkspacePath $wrongCandidateWorkspace
    Assert-PublicResult $wrongCandidate 'wrong candidate'
    Assert-Equal 'SIGNING.WRONG_CANDIDATE' $wrongCandidate.reasonCode `
        'a mismatched candidate cannot enter the session'
    Assert-Equal $false $wrongCandidate.signed 'wrong candidate never signs'
    Remove-SigningWorkspace $wrongCandidateWorkspace

    $changedWorkspace = New-SigningWorkspace -Name 'changed'
    $changedRequest = New-BoundRequest -CandidatePath $candidatePath -Scenario ChangedContent
    $changed = Invoke-Session -Request $changedRequest -CandidatePath $candidatePath `
        -WorkspacePath $changedWorkspace
    Assert-PublicResult $changed 'changed content'
    Assert-Equal 'SIGNING.CANDIDATE_CHANGED' $changed.reasonCode `
        'changed signed content fails closed'
    Assert-Equal $false $changed.verified 'changed content is not verified'
    Assert-Equal $false $changed.smoked 'changed content is not smoked'
    Remove-SigningWorkspace $changedWorkspace

    $invalidWorkspace = New-SigningWorkspace -Name 'invalid'
    $invalidRequest = New-BoundRequest -CandidatePath $candidatePath -Scenario InvalidSignature
    $invalid = Invoke-Session -Request $invalidRequest -CandidatePath $candidatePath `
        -WorkspacePath $invalidWorkspace
    Assert-PublicResult $invalid 'invalid signature'
    Assert-Equal 'SIGNING.INVALID_SIGNATURE' $invalid.reasonCode `
        'an invalid signature fails closed'
    Assert-Equal $false $invalid.verified 'an invalid signature is not verified'
    Remove-SigningWorkspace $invalidWorkspace

    $missingWorkspace = New-SigningWorkspace -Name 'missing'
    $missingRequest = New-BoundRequest -CandidatePath $candidatePath -Scenario MissingSignature
    $missing = Invoke-Session -Request $missingRequest -CandidatePath $candidatePath `
        -WorkspacePath $missingWorkspace
    Assert-PublicResult $missing 'missing signature'
    Assert-Equal 'SIGNING.UNSIGNED' $missing.reasonCode 'a missing signature fails closed'
    Assert-Equal 'NotSigned' $missing.signatureStatus 'missing signature is NotSigned'
    Assert-Equal $false $missing.smoked 'an unsigned artifact is not smoked'
    Remove-SigningWorkspace $missingWorkspace

    $timestampWorkspace = New-SigningWorkspace -Name 'timestamp'
    $timestampRequest = New-BoundRequest -CandidatePath $candidatePath -Scenario TimestampFailure
    $timestamp = Invoke-Session -Request $timestampRequest -CandidatePath $candidatePath `
        -WorkspacePath $timestampWorkspace
    Assert-PublicResult $timestamp 'timestamp failure'
    Assert-Equal 'SIGNING.TIMESTAMP_FAILED' $timestamp.reasonCode `
        'a timestamp failure fails closed'
    Assert-Equal $false $timestamp.verified 'a timestamp failure is not verified'
    Remove-SigningWorkspace $timestampWorkspace

    $deniedWorkspace = New-SigningWorkspace -Name 'denied'
    $deniedRequest = New-BoundRequest -CandidatePath $candidatePath -Scenario PermissionDenied
    $denied = Invoke-Session -Request $deniedRequest -CandidatePath $candidatePath `
        -WorkspacePath $deniedWorkspace
    Assert-PublicResult $denied 'permission denial'
    Assert-Equal 'SIGNING.PERMISSION_DENIED' $denied.reasonCode `
        'permission denial fails closed'
    Assert-Equal $true $denied.sessionCapabilityRemoved `
        'permission denial still removes the session'
    Assert-Equal $false $denied.signed 'permission denial never signs'
    Remove-SigningWorkspace $deniedWorkspace

    $outageWorkspace = New-SigningWorkspace -Name 'outage'
    $outageRequest = New-BoundRequest -CandidatePath $candidatePath -Scenario ServiceUnavailable
    $outage = Invoke-Session -Request $outageRequest -CandidatePath $candidatePath `
        -WorkspacePath $outageWorkspace
    Assert-PublicResult $outage 'service unavailability'
    Assert-Equal 'AttestedFallbackEligible' $outage.state `
        'a genuine outage follows the Attested Preview contract'
    Assert-Equal 'SIGNING.SERVICE_UNAVAILABLE' $outage.reasonCode `
        'service unavailability uses a stable reason'
    Assert-Equal $true $outage.attestedFallbackEligible `
        'an outage is eligible for the governed fallback'
    Assert-Equal 'ArtifactSigningNotOperational' $outage.fallbackReason `
        'the outage reason matches the Attested Preview contract'
    Assert-Equal $false $outage.satisfiesStableSigningGate `
        'an outage never satisfies the Stable signing gate'
    Assert-Equal 'AttestedPreview' $outage.trustClass `
        'an outage stays on the Attested Preview trust class'
    Assert-Equal $true $outage.sessionCapabilityRemoved `
        'an outage still removes the session'
    Remove-SigningWorkspace $outageWorkspace

    $unexpectedWorkspace = New-SigningWorkspace -Name 'unexpected'
    $alreadySigned = Join-Path $workRoot 'already-signed.ps1'
    [System.IO.File]::WriteAllText(
        $alreadySigned,
        ((Get-Content -LiteralPath $candidatePath -Raw) +
            "`n# SIG # Begin signature block`n# unexpected`n# SIG # End signature block`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $unexpectedRequest = New-BoundRequest -CandidatePath $alreadySigned -Scenario UnexpectedlySigned
    $unexpected = Invoke-Session -Request $unexpectedRequest -CandidatePath $alreadySigned `
        -WorkspacePath $unexpectedWorkspace
    Assert-PublicResult $unexpected 'unexpected signature'
    Assert-Equal 'SIGNING.UNEXPECTEDLY_SIGNED' $unexpected.reasonCode `
        'an already-signed precursor cannot enter the session'
    Assert-Equal $false $unexpected.signed 'unexpected signature does not re-sign'
    Remove-SigningWorkspace $unexpectedWorkspace

    $gatesWorkspace = New-SigningWorkspace -Name 'gates'
    $gatesRequest = New-BoundRequest -CandidatePath $candidatePath -Scenario GatesNotPassed -Mutate {
        param($Request)
        $Request.bindings.unsignedContentQualified = $false
    }
    $gates = Invoke-Session -Request $gatesRequest -CandidatePath $candidatePath `
        -WorkspacePath $gatesWorkspace
    Assert-PublicResult $gates 'gates not passed'
    Assert-Equal 'SIGNING.GATES_NOT_PASSED' $gates.reasonCode `
        'unqualified content cannot enter the session'
    Remove-SigningWorkspace $gatesWorkspace

    $approvalWorkspace = New-SigningWorkspace -Name 'approval'
    $approvalRequest = New-BoundRequest -CandidatePath $candidatePath -Scenario ApprovalMissing -Mutate {
        param($Request)
        $Request.bindings.humanApproval.approved = $false
    }
    $approval = Invoke-Session -Request $approvalRequest -CandidatePath $candidatePath `
        -WorkspacePath $approvalWorkspace
    Assert-PublicResult $approval 'approval missing'
    Assert-Equal 'SIGNING.APPROVAL_REQUIRED' $approval.reasonCode `
        'missing human digest approval cannot enter the session'
    Remove-SigningWorkspace $approvalWorkspace

    $setupWorkspace = New-SigningWorkspace -Name 'setup'
    $setupRequest = New-BoundRequest -CandidatePath $candidatePath -Scenario SetupAuthorityMissing
    $setup = Invoke-Session -Request $setupRequest -CandidatePath $candidatePath `
        -WorkspacePath $setupWorkspace
    Assert-PublicResult $setup 'setup authority missing'
    Assert-Equal 'SetupRequired' $setup.state 'live signing without setup stays SetupRequired'
    Assert-Equal 'SIGNING.SETUP_AUTHORITY_REQUIRED' $setup.reasonCode `
        'live signing without setup stays NotStarted'
    Assert-Equal $false $setup.signed 'setup-missing never signs'
    Remove-SigningWorkspace $setupWorkspace

    $repoWorkspace = Join-Path $workRoot 'forbidden-in-repo'
    $null = New-Item -ItemType Directory -Path $repoWorkspace -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $repoWorkspace $policy.workspace.markerFileName),
        ($policy.workspace.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $repoResult = Invoke-SigningBoundarySession -Request $eligibleRequest `
        -CandidatePath $candidatePath `
        -PrivateWorkspacePath $repoWorkspace `
        -RepositoryRoot $workRoot `
        -ApplicationDirectory $workRoot
    Assert-PublicResult $repoResult 'repository workspace'
    Assert-Equal 'SIGNING.WORKSPACE_REPOSITORY_PATH' $repoResult.reasonCode `
        'a repository workspace is rejected'
}
finally {
    if (Test-Path -LiteralPath $workRoot) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
}

Write-Output 'PASS: Signing Boundary eligibility, verification, cleanup, and fallback contracts hold.'
