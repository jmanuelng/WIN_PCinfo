[CmdletBinding()]
param([string] $CandidatePath, [string] $PreparedManifestPath, [string] $PreparedManifestSha256)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

function Assert-ReleaseApplicationTestPathAncestors {
    param([string] $Path)
    $cursor=[IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (([IO.Directory]::Exists($cursor) -or [IO.File]::Exists($cursor)) -and
            ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Owned application fixtures cannot use reparse paths.' }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
}

function Remove-OwnedReleaseApplicationTestRoot {
    param([string] $Path, [string] $ExpectedParent, [string] $Nonce, [string] $Kind)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $full=[IO.Path]::GetFullPath($Path)
    if (-not [IO.Path]::GetDirectoryName($full).Equals([IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($full) -cnotmatch ('^[a-z-]+-'+[regex]::Escape($Nonce)+'$')) { throw 'Owned application fixture boundary changed.' }
    # Only an explicitly missing entry is absent. Files, reparse entries and
    # unreadable/unknown entry types preserve the owning fixture as uncertain.
    $entry=$null
    try { $entry=Get-Item -LiteralPath $full -Force -ErrorAction Stop }
    catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -and
            $_.Exception -is [Management.Automation.ItemNotFoundException]) { return }
        throw
    }
    if ($entry -isnot [IO.DirectoryInfo] -or
        ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Owned application fixture root type or attributes changed.' }
    Assert-ReleaseApplicationTestPathAncestors -Path $full
    if (@(Get-ChildItem -LiteralPath $full -Recurse -Force | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count) { throw 'Owned application fixture contains a reparse entry.' }
    if ([IO.File]::ReadAllText((Join-Path $full 'fixture-owner.txt')) -cne ($Kind+'|'+$Nonce)) { throw 'Owned application fixture marker changed.' }
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
    if ([IO.Directory]::Exists($full) -or [IO.File]::Exists($full)) { throw 'Owned application fixture cleanup remains incomplete.' }
}

$candidateUseError=$null
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$fixtureOwner=[pscustomobject]@{Nonce=[Guid]::NewGuid().ToString('N');Unsafe=$false;WorkRoot=$null;PrivateRoot=$null;RepositoryParent=(Join-Path $repositoryRoot '.test-output');PrivateParent=[IO.Path]::GetTempPath()}
try {
. (Join-Path $repositoryRoot 'src/SigningBoundary.ps1')

$resultSchemaPath = Join-Path $repositoryRoot 'schemas/signing-session-result.schema.json'
$eligiblePath = Join-Path $PSScriptRoot 'fixtures/signing-session-eligible.json'
$policy = Get-SigningBoundaryPolicy
$workRoot = Join-Path $fixtureOwner.RepositoryParent ('signing-boundary-application-'+$fixtureOwner.Nonce)
$privateFixtureRoot = Join-Path $fixtureOwner.PrivateParent ('win-pcinfo-signing-boundary-application-fixtures-'+$fixtureOwner.Nonce)
foreach ($owned in @(@{Path=$workRoot;Kind='Repository'},@{Path=$privateFixtureRoot;Kind='Private'})) {
    Assert-ReleaseApplicationTestPathAncestors -Path $owned.Path
    if ([IO.Directory]::Exists($owned.Path) -or [IO.File]::Exists($owned.Path)) { throw 'Unique application fixture already exists.' }
    $null=[IO.Directory]::CreateDirectory($owned.Path)
    if ($owned.Kind -ceq 'Repository') { $fixtureOwner.WorkRoot=$owned.Path } else { $fixtureOwner.PrivateRoot=$owned.Path }
    [IO.File]::WriteAllText((Join-Path $owned.Path 'fixture-owner.txt'),($owned.Kind+'|'+$fixtureOwner.Nonce),[Text.UTF8Encoding]::new($false))
}
[IO.File]::WriteAllText((Join-Path $workRoot 'private-fixture-owner.json'),([ordered]@{contract='win-pcinfo.release-application-test-fixture/1.0.0';nonce=$fixtureOwner.Nonce;repositoryRoot=$workRoot;privateRoot=$privateFixtureRoot;candidatePath=$candidateContext.Path;candidateSha256=$candidateContext.Sha256;scope='Fixture ownership only; native lifetime evidence remains with the admitted supervisor.'}|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
$candidatePath = $candidateContext.Path
$candidateDigest = Get-SigningBoundarySha256 -Bytes ([System.IO.File]::ReadAllBytes($candidatePath))

function New-BoundRequestPath {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter()] [string] $Scenario = 'EligibleSign',
        [Parameter()] [scriptblock] $Mutate
    )

    $request = Get-Content -LiteralPath $eligiblePath -Raw | ConvertFrom-Json -Depth 20
    $request.scenario = $Scenario
    $request.bindings.generatedContentSha256 = $candidateDigest
    $request.bindings.humanApproval.digestSha256 = $candidateDigest
    $request.bindings.unsignedContentQualified = $true
    $request.bindings.humanApproval.approved = $true
    $request.bindings.humanApproval.confirmation = [string] $policy.humanApproval.confirmationPhrase
    if ($null -ne $Mutate) {
        & $Mutate $request
    }
    $path = Join-Path $workRoot $Name
    [System.IO.File]::WriteAllText(
        $path,
        ($request | ConvertTo-Json -Depth 20),
        [System.Text.UTF8Encoding]::new($false)
    )
    $path
}

function New-MarkedWorkspace {
    param([Parameter(Mandatory)] [string] $Name)
    $path = Join-Path $privateFixtureRoot $Name
    $null = New-Item -ItemType Directory -Path $path -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $path $policy.workspace.markerFileName),
        ($policy.workspace.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $path
}

$boundPath = New-BoundRequestPath -Name 'bound-eligible.json'
$secretPath = Join-Path $workRoot 'secret.json'
[System.IO.File]::WriteAllText(
    $secretPath,
    ((Get-Content -LiteralPath $boundPath -Raw) + "`n`"leak`":`"clientSecret=not-a-real-secret`"`n"),
    [System.Text.UTF8Encoding]::new($false)
)
$kindPath = New-BoundRequestPath -Name 'wrong-kind.json' -Mutate {
    param($Request)
    $Request.kind = 'win-pcinfo.assessment-run-request'
}

try {
    $safeWorkspace = New-MarkedWorkspace -Name 'safe'
    $evaluated = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'SignAndVerifyCandidate',
        '-SigningSessionRequestPath', $boundPath,
        '-SigningWorkspacePath', $safeWorkspace
    )
    Assert-Equal 0 $evaluated.ExitCode 'the generated application signs a bound eligible request'
    $progress = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.progress')
    $result = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.signing-session-result')
    $terminal = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 2 $progress.Count 'signing emits structured start and finish progress'
    Assert-Equal 'signing.session.started' $progress[0].messageId 'signing starts with a stable message'
    Assert-Equal 'signing.session.succeeded' $progress[1].messageId 'signing success uses a stable message'
    Assert-Equal 1 $result.Count 'signing emits one sanitized result'
    Assert-Equal 'SignedAndVerified' $result[0].state 'the generated application reports SignedAndVerified'
    Assert-Equal $true $result[0].signed 'the generated application produced a signed script'
    Assert-Equal $true $result[0].verified 'the generated application verified before smoke'
    Assert-Equal $true $result[0].smoked 'the generated application smoked Help'
    Assert-Equal $true $result[0].sessionCapabilityRemoved 'the generated application removed the session'
    Assert-Equal $true $result[0].identitiesDistinct 'signed identities are distinct'
    Assert-Equal $false $result[0].publicationAuthorized 'synthetic signing cannot authorize publication'
    Assert-Equal $false $result[0].trustedPublicationPermitted 'synthetic signing cannot publish as Trusted'
    Assert-Equal $false $result[0].satisfiesStableSigningGate 'synthetic signing cannot satisfy Stable'
    Assert-Equal $false $result[0].azureContacted 'the generated application does not contact Azure'
    Assert-Equal $false $result[0].collectionStarted 'signing never starts assessment collection'
    Assert-Equal $true (Test-Json -Json ($result[0] | ConvertTo-Json -Compress -Depth 20) `
        -SchemaFile $resultSchemaPath) 'the application result satisfies the public schema'
    Assert-Equal $false (($result[0] | ConvertTo-Json -Compress -Depth 20) -match [regex]::Escape($safeWorkspace)) `
        'the application result omits the workspace path'
    Assert-Equal 1 $terminal.Count 'signing ends with one terminal record'
    Assert-Equal 'Completed' $terminal[0].outcome 'eligible synthetic signing completes without collection'
    Assert-Equal 'SIGNING.SIGNED_AND_VERIFIED' $terminal[0].reasonCode `
        'the terminal reason records that signing finished'
    Assert-Equal $false $terminal[0].collectionStarted 'completed signing never collects'
    Assert-Equal $true (Test-Path -LiteralPath (
        Join-Path $safeWorkspace 'final/WIN-PCInfo-2.0.0-preview.1-signed.zip'
    )) 'the generated application finalizes the outer archive'

    $missing = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'SignAndVerifyCandidate'
    )
    Assert-Equal 20 $missing.ExitCode 'a missing request ends NotStarted'
    $missingTerminal = @($missing.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    $missingResult = @($missing.Records | Where-Object recordType -eq 'win-pcinfo.signing-session-result')
    Assert-Equal 'NotStarted' $missingTerminal[0].outcome 'a missing request stays NotStarted'
    Assert-Equal 'SIGNING.REQUEST_MISSING' $missingTerminal[0].reasonCode 'a missing request uses a stable reason'
    Assert-Equal 'Rejected' $missingResult[0].state 'a missing request is rejected'

    $secretWorkspace = New-MarkedWorkspace -Name 'secret'
    $secret = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'SignAndVerifyCandidate',
        '-SigningSessionRequestPath', $secretPath,
        '-SigningWorkspacePath', $secretWorkspace
    )
    Assert-Equal 20 $secret.ExitCode 'a privacy-violating request ends NotStarted'
    $secretTerminal = @($secret.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 'NotStarted' $secretTerminal[0].outcome 'privacy rejection stays NotStarted'
    Assert-Equal 'SIGNING.PRIVACY_REJECTED' $secretTerminal[0].reasonCode `
        'the generated application rejects secret material'
    Remove-Item -LiteralPath $secretWorkspace -Recurse -Force

    $wrongWorkspace = New-MarkedWorkspace -Name 'wrong'
    $unbound = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'SignAndVerifyCandidate',
        '-SigningSessionRequestPath', $eligiblePath,
        '-SigningWorkspacePath', $wrongWorkspace
    )
    Assert-Equal 20 $unbound.ExitCode 'a mismatched candidate ends NotStarted'
    $unboundResult = @($unbound.Records | Where-Object recordType -eq 'win-pcinfo.signing-session-result')
    Assert-Equal 'SIGNING.WRONG_CANDIDATE' $unboundResult[0].reasonCode `
        'the generated application rejects a mismatched candidate'
    Assert-Equal $false $unboundResult[0].signed 'a mismatched candidate is not signed'
    Remove-Item -LiteralPath $wrongWorkspace -Recurse -Force

    $outagePath = New-BoundRequestPath -Name 'outage.json' -Scenario ServiceUnavailable
    $outageWorkspace = New-MarkedWorkspace -Name 'outage'
    $outage = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'SignAndVerifyCandidate',
        '-SigningSessionRequestPath', $outagePath,
        '-SigningWorkspacePath', $outageWorkspace
    )
    Assert-Equal 20 $outage.ExitCode 'service unavailability stays NotStarted'
    $outageResult = @($outage.Records | Where-Object recordType -eq 'win-pcinfo.signing-session-result')
    Assert-Equal 'AttestedFallbackEligible' $outageResult[0].state `
        'the generated application follows the Attested Preview contract'
    Assert-Equal 'SIGNING.SERVICE_UNAVAILABLE' $outageResult[0].reasonCode `
        'the generated application records the outage'
    Assert-Equal $true $outageResult[0].attestedFallbackEligible `
        'an outage is eligible for the governed fallback'
    Assert-Equal $false $outageResult[0].satisfiesStableSigningGate `
        'an outage never satisfies the Stable signing gate'
    Remove-Item -LiteralPath $outageWorkspace -Recurse -Force

    $setupPath = New-BoundRequestPath -Name 'setup.json' -Scenario SetupAuthorityMissing
    $setupWorkspace = New-MarkedWorkspace -Name 'setup'
    $setup = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'SignAndVerifyCandidate',
        '-SigningSessionRequestPath', $setupPath,
        '-SigningWorkspacePath', $setupWorkspace
    )
    Assert-Equal 20 $setup.ExitCode 'missing setup authority stays NotStarted'
    $setupResult = @($setup.Records | Where-Object recordType -eq 'win-pcinfo.signing-session-result')
    Assert-Equal 'SetupRequired' $setupResult[0].state 'live signing without setup stays SetupRequired'
    Assert-Equal 'SIGNING.SETUP_AUTHORITY_REQUIRED' $setupResult[0].reasonCode `
        'the generated application records the setup-authority gap'
    Remove-Item -LiteralPath $setupWorkspace -Recurse -Force

    $kindWorkspace = New-MarkedWorkspace -Name 'kind'
    $kindRejected = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'SignAndVerifyCandidate',
        '-SigningSessionRequestPath', $kindPath,
        '-SigningWorkspacePath', $kindWorkspace
    )
    Assert-Equal 20 $kindRejected.ExitCode 'a wrong request kind ends NotStarted'
    $kindResult = @($kindRejected.Records | Where-Object recordType -eq 'win-pcinfo.signing-session-result')
    Assert-Equal 'SIGNING.REQUEST_INVALID' $kindResult[0].reasonCode `
        'the generated application rejects a request that fails the public schema'
    Remove-Item -LiteralPath $kindWorkspace -Recurse -Force

    $repoWorkspace = Join-Path $workRoot 'forbidden-in-repo'
    $null = New-Item -ItemType Directory -Path $repoWorkspace -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $repoWorkspace $policy.workspace.markerFileName),
        ($policy.workspace.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $repoRejected = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'SignAndVerifyCandidate',
        '-SigningSessionRequestPath', $boundPath,
        '-SigningWorkspacePath', $repoWorkspace
    )
    Assert-Equal 20 $repoRejected.ExitCode 'a repository workspace ends NotStarted'
    $repoResult = @($repoRejected.Records | Where-Object recordType -eq 'win-pcinfo.signing-session-result')
    Assert-Equal 'SIGNING.WORKSPACE_REPOSITORY_PATH' $repoResult[0].reasonCode `
        'the generated application rejects an in-repository workspace'
}
finally { }
}
catch {
    $candidateUseError=$_
    $fixtureOwner.Unsafe=Test-QualificationCleanupUnverified -Exception $_.Exception
}
finally {
    # The shared candidate finalizer receives an unsafe body to preserve an
    # owned standalone output. Ordinary body errors are retained once by the
    # outer finalizer; they do not become an unsafe cleanup by classification.
    $finalBodyError=if($fixtureOwner.Unsafe){$null}else{$candidateUseError}
    Complete-QualificationHarness -BodyError $finalBodyError -Cleanup @(
        {
            try { Close-TestCandidate -Candidate $candidateContext -BodyError $(if($fixtureOwner.Unsafe){$candidateUseError}else{$null}) }
            catch { $fixtureOwner.Unsafe=$true; throw }
        },
        {
            if (-not $fixtureOwner.Unsafe) {
                try { Remove-OwnedReleaseApplicationTestRoot -Path $fixtureOwner.PrivateRoot -ExpectedParent $fixtureOwner.PrivateParent -Nonce $fixtureOwner.Nonce -Kind Private }
                catch { $fixtureOwner.Unsafe=$true; throw }
            }
        },
        {
            if (-not $fixtureOwner.Unsafe) {
                try { Remove-OwnedReleaseApplicationTestRoot -Path $fixtureOwner.WorkRoot -ExpectedParent $fixtureOwner.RepositoryParent -Nonce $fixtureOwner.Nonce -Kind Repository }
                catch { $fixtureOwner.Unsafe=$true; throw }
            }
        }
    )
}
Write-Output 'PASS: the generated application signs, verifies, and rejects signing sessions privately.'
