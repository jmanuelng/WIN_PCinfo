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
. (Join-Path $repositoryRoot 'src/PreviewQualification.ps1')

$packetSchemaPath = Join-Path $repositoryRoot 'schemas/preview-qualification-packet.schema.json'
$manifestSchemaPath = Join-Path $repositoryRoot 'schemas/release-evidence-manifest.schema.json'
$completePath = Join-Path $PSScriptRoot 'fixtures/preview-qualification-complete-signed.json'
$policy = Get-PreviewQualificationPolicy
# Capture one test-generation instant. Only disposable synthetic requests receive
# relative observation times; the stored fixture and production UTC clock stay intact.
$syntheticFixtureNow = [datetimeoffset]::UtcNow
$workRoot = Join-Path $fixtureOwner.RepositoryParent ('preview-qualification-application-'+$fixtureOwner.Nonce)
$privateFixtureRoot = Join-Path $fixtureOwner.PrivateParent ('win-pcinfo-preview-qualification-application-fixtures-'+$fixtureOwner.Nonce)
foreach ($owned in @(@{Path=$workRoot;Kind='Repository'},@{Path=$privateFixtureRoot;Kind='Private'})) {
    Assert-ReleaseApplicationTestPathAncestors -Path $owned.Path
    if ([IO.Directory]::Exists($owned.Path) -or [IO.File]::Exists($owned.Path)) { throw 'Unique application fixture already exists.' }
    $null=[IO.Directory]::CreateDirectory($owned.Path)
    if ($owned.Kind -ceq 'Repository') { $fixtureOwner.WorkRoot=$owned.Path } else { $fixtureOwner.PrivateRoot=$owned.Path }
    [IO.File]::WriteAllText((Join-Path $owned.Path 'fixture-owner.txt'),($owned.Kind+'|'+$fixtureOwner.Nonce),[Text.UTF8Encoding]::new($false))
}
[IO.File]::WriteAllText((Join-Path $workRoot 'private-fixture-owner.json'),([ordered]@{contract='win-pcinfo.release-application-test-fixture/1.0.0';nonce=$fixtureOwner.Nonce;repositoryRoot=$workRoot;privateRoot=$privateFixtureRoot;candidatePath=$candidateContext.Path;candidateSha256=$candidateContext.Sha256;scope='Fixture ownership only; native lifetime evidence remains with the admitted supervisor.'}|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
$candidatePath = $candidateContext.Path

$candidateDigest = Get-PreviewQualificationSha256 -Bytes (
    [System.IO.File]::ReadAllBytes($candidatePath)
)
$ledgerDigest = Get-PreviewQualificationSha256 -Bytes ([System.IO.File]::ReadAllBytes(
    (Join-Path $repositoryRoot 'docs/spec/capability-ledger.json')
))
$finalDigest = Get-PreviewQualificationSha256 -Bytes (
    [System.Text.UTF8Encoding]::new($false).GetBytes("final:$candidateDigest")
)

function New-BoundRequestPath {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter()] [datetimeoffset] $SyntheticObservedAt = $syntheticFixtureNow.AddDays(-1),
        [Parameter()] [scriptblock] $Mutate
    )

    $request = Get-Content -LiteralPath $completePath -Raw | ConvertFrom-Json -Depth 30
    Assert-Equal $true $request.synthetic 'relative test dates require a synthetic request'
    Assert-Equal 'SyntheticProjection' $request.evidenceKind 'relative test dates require synthetic evidence'
    Assert-Equal $true $request.evidencePack.synthetic 'relative test dates require a synthetic pack'
    $observedAt = $SyntheticObservedAt.ToUniversalTime().ToString(
        'o', [System.Globalization.CultureInfo]::InvariantCulture
    )
    $request.evidencePack.observedAt = $observedAt
    $request.bindings.generatedContentSha256 = $candidateDigest
    $request.bindings.derivedFromGeneratedContentSha256 = $candidateDigest
    $request.bindings.finalDistributableSha256 = $finalDigest
    $request.evidencePack.bindings.generatedContentSha256 = $candidateDigest
    $request.evidencePack.bindings.ledgerSha256 = $ledgerDigest
    $request.evidencePack.finalDistributable.packageSha256 = $finalDigest
    $request.evidencePack.finalDistributable.derivedFromGeneratedContentSha256 = $candidateDigest
    foreach ($gate in @($request.evidencePack.gates)) {
        $gate.observedAt = $observedAt
        $gate.generatedContentSha256 = $candidateDigest
    }
    foreach ($scenario in @($request.evidencePack.scenarios)) {
        $scenario.observedAt = $observedAt
        $scenario.generatedContentSha256 = $candidateDigest
    }
    if ($null -ne $Mutate) {
        & $Mutate $request
    }
    $path = Join-Path $workRoot $Name
    [System.IO.File]::WriteAllText(
        $path,
        ($request | ConvertTo-Json -Depth 30),
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

$boundPath = New-BoundRequestPath -Name 'bound-complete.json'
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
        '-Workflow', 'QualifyPreviewCandidate',
        '-QualificationRequestPath', $boundPath,
        '-QualificationWorkspacePath', $safeWorkspace
    )
    Assert-Equal 0 $evaluated.ExitCode 'the generated application qualifies a bound complete request'
    $progress = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.progress')
    $manifest = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.release-evidence-manifest')
    $matrix = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.preview-capability-matrix')
    $packet = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.preview-qualification-packet')
    $terminal = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 2 $progress.Count 'qualification emits structured start and finish progress'
    Assert-Equal 'qualification.started' $progress[0].messageId 'qualification starts with a stable message'
    Assert-Equal 'qualification.succeeded' $progress[1].messageId 'qualification success uses a stable message'
    Assert-Equal 1 $manifest.Count 'qualification emits one sanitized manifest'
    Assert-Equal 1 $matrix.Count 'qualification emits one derived matrix'
    Assert-Equal 1 $packet.Count 'qualification emits one decision packet'
    Assert-Equal 'Approved' $packet[0].state 'the generated application reports Approved'
    Assert-Equal 'Qualify' $packet[0].decision 'the generated application qualifies the bound candidate'
    Assert-Equal $true $packet[0].unsignedContentQualified `
        'the running generated content matches the rewritten request'
    Assert-Equal $true $packet[0].finalArtifactQualified `
        'the distinct final identity is qualified'
    Assert-Equal $false $packet[0].collectionStarted 'qualification never starts assessment collection'
    Assert-Equal $false $packet[0].publicationAuthorized 'synthetic qualification cannot publish'
    Assert-Equal $true $packet[0].humanApprovalRequired 'a human must still accept the packet'
    Assert-Equal 'None' $packet[0].supportClaim 'the generated application makes no support claim'
    Assert-Equal $false $packet[0].liveAzureStarted 'the generated application does not start live Azure'
    Assert-Equal $true (Test-Json -Json ($packet[0] | ConvertTo-Json -Compress -Depth 20) `
        -SchemaFile $packetSchemaPath) 'the application packet satisfies the public schema'
    Assert-Equal $true (Test-Json -Json ($manifest[0] | ConvertTo-Json -Compress -Depth 20) `
        -SchemaFile $manifestSchemaPath) 'the application manifest satisfies the public schema'
    Assert-Equal $false (($packet[0] | ConvertTo-Json -Compress -Depth 20) -match [regex]::Escape($workRoot)) `
        'the application packet omits the workspace path'
    Assert-Equal 1 $terminal.Count 'qualification ends with one terminal record'
    Assert-Equal 'Completed' $terminal[0].outcome 'a complete synthetic request completes without collection'
    Assert-Equal 'QUALIFY.APPROVED' $terminal[0].reasonCode `
        'the terminal reason records that the packet is approved'
    Assert-Equal $false $terminal[0].collectionStarted 'completed qualification never collects'
    Assert-Equal $false (Test-Path -LiteralPath (
        Join-Path $safeWorkspace 'derived-qualification-packet.json'
    ) -PathType Leaf) 'the generated application leaves no derived packet'
    Assert-Equal $false (Test-Path -LiteralPath (
        Join-Path $safeWorkspace 'gate-derived'
    )) 'the generated application leaves no gate-derived residue'

    # Thirty-one days exceeds the existing 30-day Client VM freshness window.
    # Keep a full day of margin so neither case depends on midnight or elapsed seconds.
    $expiredPath = New-BoundRequestPath -Name 'expired-synthetic.json' `
        -SyntheticObservedAt $syntheticFixtureNow.AddDays(-31) -Mutate {
        param($Request)
        $Request.scenario = 'ExpiredEvidence'
    }
    $expiredWorkspace = New-MarkedWorkspace -Name 'expired'
    $expired = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'QualifyPreviewCandidate',
        '-QualificationRequestPath', $expiredPath,
        '-QualificationWorkspacePath', $expiredWorkspace
    )
    Assert-Equal 0 $expired.ExitCode 'expired evidence completes evaluation without collection'
    $expiredPacket = @($expired.Records | Where-Object recordType -eq 'win-pcinfo.preview-qualification-packet')
    $expiredManifest = @($expired.Records | Where-Object recordType -eq 'win-pcinfo.release-evidence-manifest')
    $expiredTerminal = @($expired.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $expiredPacket.Count 'expired evidence emits one decision packet'
    Assert-Equal 'Denied' $expiredPacket[0].state 'expired synthetic observations deny qualification'
    Assert-Equal 'Deny' $expiredPacket[0].decision 'expired evidence cannot qualify the candidate'
    Assert-Equal 'QUALIFY.EXPIRED' $expiredPacket[0].reasonCode 'expiry is the stable denial reason'
    Assert-Equal $true $expiredPacket[0].candidateBound 'expired evidence still binds the actual candidate'
    Assert-Equal $true $expiredPacket[0].syntheticEvidenceOnly 'expired evidence remains visibly synthetic'
    Assert-Equal $false $expiredPacket[0].unsignedContentQualified 'expired evidence cannot qualify content'
    Assert-Equal $false $expiredPacket[0].finalArtifactQualified 'expired evidence cannot qualify a final artifact'
    Assert-Equal $false $expiredPacket[0].publicationAuthorized 'expired evidence cannot authorize publication'
    Assert-Equal $false $expiredPacket[0].collectionStarted 'expired evidence never starts collection'
    Assert-Equal $true $expiredPacket[0].cleanupVerified 'expired evaluation verifies workspace cleanup'
    Assert-Equal 1 $expiredManifest.Count 'expired evidence emits one sanitized manifest'
    $expiredClientGates = @($expiredManifest[0].gates | Where-Object freshnessClass -eq 'ClientVmValidation')
    Assert-Equal 3 $expiredClientGates.Count 'the manifest retains all three required Client VM gates'
    foreach ($gate in $expiredClientGates) {
        Assert-Equal 'Expired' $gate.result 'each aged Client VM gate is expired in the manifest'
        Assert-Equal $true $gate.expired 'each aged Client VM gate carries an explicit expiry flag'
    }
    Assert-Equal 1 $expiredTerminal.Count 'expired evidence emits one terminal record'
    Assert-Equal 'Completed' $expiredTerminal[0].outcome 'denial is a completed evaluation'
    Assert-Equal 'QUALIFY.DENIED' $expiredTerminal[0].reasonCode 'the terminal records qualification denial'
    Assert-Equal $false $expiredTerminal[0].collectionStarted 'denied qualification never collects'
    Assert-Equal $false (Test-Path -LiteralPath (
        Join-Path $expiredWorkspace 'derived-qualification-packet.json'
    )) 'expired evaluation leaves no derived packet'
    Assert-Equal $false (Test-Path -LiteralPath (
        Join-Path $expiredWorkspace 'gate-derived'
    )) 'expired evaluation leaves no gate-derived residue'

    $missing = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'QualifyPreviewCandidate'
    )
    Assert-Equal 20 $missing.ExitCode 'a missing request ends NotStarted'
    $missingTerminal = @($missing.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    $missingPacket = @($missing.Records | Where-Object recordType -eq 'win-pcinfo.preview-qualification-packet')
    Assert-Equal 'NotStarted' $missingTerminal[0].outcome 'a missing request stays NotStarted'
    Assert-Equal 'QUALIFY.REQUEST_MISSING' $missingTerminal[0].reasonCode `
        'a missing request uses a stable reason'
    Assert-Equal 'Rejected' $missingPacket[0].state 'a missing request is rejected'

    $secretWorkspace = New-MarkedWorkspace -Name 'secret'
    $secret = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'QualifyPreviewCandidate',
        '-QualificationRequestPath', $secretPath,
        '-QualificationWorkspacePath', $secretWorkspace
    )
    Assert-Equal 20 $secret.ExitCode 'a privacy-violating request ends NotStarted'
    $secretTerminal = @($secret.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    $secretPacket = @($secret.Records | Where-Object recordType -eq 'win-pcinfo.preview-qualification-packet')
    Assert-Equal 'NotStarted' $secretTerminal[0].outcome 'a secret stays NotStarted'
    Assert-Equal 'QUALIFY.PRIVACY_REJECTED' $secretTerminal[0].reasonCode `
        'a secret uses a stable privacy reason'
    Assert-Equal 'Rejected' $secretPacket[0].state 'a secret is rejected'

    $kindWorkspace = New-MarkedWorkspace -Name 'kind'
    $wrongKind = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'QualifyPreviewCandidate',
        '-QualificationRequestPath', $kindPath,
        '-QualificationWorkspacePath', $kindWorkspace
    )
    Assert-Equal 20 $wrongKind.ExitCode 'a wrong-kind request ends NotStarted'
    $kindTerminal = @($wrongKind.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 'NotStarted' $kindTerminal[0].outcome 'a wrong-kind request stays NotStarted'
    Assert-Equal 'QUALIFY.REQUEST_INVALID' $kindTerminal[0].reasonCode `
        'a wrong-kind request uses a stable reason'

    $repoWorkspace = Join-Path $workRoot 'forbidden-in-repo'
    if (Test-Path -LiteralPath $repoWorkspace) {
        Remove-Item -LiteralPath $repoWorkspace -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $repoWorkspace -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $repoWorkspace $policy.workspace.markerFileName),
        ($policy.workspace.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $repoRejected = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'QualifyPreviewCandidate',
        '-QualificationRequestPath', $boundPath,
        '-QualificationWorkspacePath', $repoWorkspace
    )
    Assert-Equal 20 $repoRejected.ExitCode 'a repository workspace ends NotStarted'
    $repoTerminal = @($repoRejected.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 'NotStarted' $repoTerminal[0].outcome 'a repository workspace stays NotStarted'
    Assert-Equal 'QUALIFY.WORKSPACE_REPOSITORY_PATH' $repoTerminal[0].reasonCode `
        'the generated application rejects a workspace inside the repository'
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
Write-Output 'PASS: generated-application Preview qualification binds the candidate and stays fail-closed.'
