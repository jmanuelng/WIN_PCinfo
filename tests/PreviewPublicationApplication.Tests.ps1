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
. (Join-Path $repositoryRoot 'src/PreviewPublication.ps1')

$resultSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication-result.schema.json'
$previewSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication-preview.schema.json'
$completePath = Join-Path $PSScriptRoot 'fixtures/preview-publication-complete-signed.json'
$policy = Get-PreviewPublicationPolicy
$workRoot = Join-Path $fixtureOwner.RepositoryParent ('preview-publication-application-'+$fixtureOwner.Nonce)
$privateFixtureRoot = Join-Path $fixtureOwner.PrivateParent ('win-pcinfo-preview-publication-application-fixtures-'+$fixtureOwner.Nonce)
foreach ($owned in @(@{Path=$workRoot;Kind='Repository'},@{Path=$privateFixtureRoot;Kind='Private'})) {
    Assert-ReleaseApplicationTestPathAncestors -Path $owned.Path
    if ([IO.Directory]::Exists($owned.Path) -or [IO.File]::Exists($owned.Path)) { throw 'Unique application fixture already exists.' }
    $null=[IO.Directory]::CreateDirectory($owned.Path)
    if ($owned.Kind -ceq 'Repository') { $fixtureOwner.WorkRoot=$owned.Path } else { $fixtureOwner.PrivateRoot=$owned.Path }
    [IO.File]::WriteAllText((Join-Path $owned.Path 'fixture-owner.txt'),($owned.Kind+'|'+$fixtureOwner.Nonce),[Text.UTF8Encoding]::new($false))
}
[IO.File]::WriteAllText((Join-Path $workRoot 'private-fixture-owner.json'),([ordered]@{contract='win-pcinfo.release-application-test-fixture/1.0.0';nonce=$fixtureOwner.Nonce;repositoryRoot=$workRoot;privateRoot=$privateFixtureRoot;candidatePath=$candidateContext.Path;candidateSha256=$candidateContext.Sha256;scope='Fixture ownership only; native lifetime evidence remains with the admitted supervisor.'}|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
$candidatePath = $candidateContext.Path

$candidateDigest = Get-PreviewPublicationSha256 -Bytes (
    [System.IO.File]::ReadAllBytes($candidatePath)
)

function New-BoundPublicationPath {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter()] [scriptblock] $Mutate
    )

    $request = Get-Content -LiteralPath $completePath -Raw | ConvertFrom-Json -Depth 30
    $request.bindings.generatedContentSha256 = $candidateDigest
    $request.bindings.derivedFromGeneratedContentSha256 = $candidateDigest
    foreach ($asset in @($request.assets)) {
        $asset.sha256 = Get-PreviewPublicationSha256 -Bytes (
            Get-PreviewPublicationSyntheticAssetBytes -AssetId ([string] $asset.assetId)
        )
        if ([string] $asset.assetId -eq 'portable-package') {
            $request.bindings.finalDistributableSha256 = [string] $asset.sha256
        }
    }
    $request.humanApproval.candidateDigest = $candidateDigest
    $request.humanApproval.qualificationPacketDigest =
        Get-PreviewPublicationPacketDigest -Packet $request.qualificationPacket
    $mergedLimitations = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($policy.requiredLimitations)) {
        $mergedLimitations.Add([string] $item)
    }
    foreach ($item in @($request.limitations)) {
        if ([string] $item -notin @($mergedLimitations)) {
            $mergedLimitations.Add([string] $item)
        }
    }
    if ([string] $request.trustPath -eq 'AttestedPreview' -and
        'attested-preview-not-trusted' -notin @($mergedLimitations)) {
        $mergedLimitations.Add('attested-preview-not-trusted')
    }
    $request.humanApproval.limitationsDigest =
        Get-PreviewPublicationLimitationsDigest -Limitations @($mergedLimitations)
    $request.humanApproval.publicAssetListDigest =
        Get-PreviewPublicationAssetListDigest -Assets $request.assets
    $request.humanApproval.trustPath = [string] $request.trustPath
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

$boundPath = New-BoundPublicationPath -Name 'bound-complete.json'
$secretPath = Join-Path $workRoot 'secret.json'
[System.IO.File]::WriteAllText(
    $secretPath,
    ((Get-Content -LiteralPath $boundPath -Raw) + "`n`"leak`":`"clientSecret=not-a-real-secret`"`n"),
    [System.Text.UTF8Encoding]::new($false)
)
$kindPath = New-BoundPublicationPath -Name 'wrong-kind.json' -Mutate {
    param($Request)
    $Request.kind = 'win-pcinfo.assessment-run-request'
}

try {
    $safeWorkspace = New-MarkedWorkspace -Name 'safe'
    $evaluated = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'PublishPreviewRelease',
        '-PublicationRequestPath', $boundPath,
        '-PublicationWorkspacePath', $safeWorkspace
    )
    Assert-Equal 0 $evaluated.ExitCode 'the generated application publishes a bound complete request'
    $progress = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.progress')
    $preview = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.preview-publication-preview')
    $result = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.preview-publication-result')
    $terminal = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 2 $progress.Count 'publication emits structured start and finish progress'
    Assert-Equal 'publication.started' $progress[0].messageId 'publication starts with a stable message'
    Assert-Equal 'publication.succeeded' $progress[1].messageId 'publication success uses a stable message'
    Assert-Equal 1 $preview.Count 'publication emits one public release preview'
    Assert-Equal 1 $result.Count 'publication emits one decision result'
    Assert-Equal 'PublishedAndVerified' $result[0].state 'the generated application reports PublishedAndVerified'
    Assert-Equal 'Publish' $result[0].decision 'the generated application publishes the bound candidate'
    Assert-Equal $true $result[0].candidateBound `
        'the running generated content matches the rewritten request'
    Assert-Equal $true $result[0].qualificationApproved 'the embedded packet is approved'
    Assert-Equal $true $result[0].downloadVerified 'the independent download matches'
    Assert-Equal $false $result[0].collectionStarted 'publication never starts assessment collection'
    Assert-Equal $false $result[0].publicationAuthorized 'synthetic publication cannot authorize GitHub'
    Assert-Equal $false $result[0].githubReleaseCreated 'the generated application creates no GitHub release'
    Assert-Equal $true $result[0].humanApprovalRequired 'a human must still approve a live release'
    Assert-Equal 'None' $result[0].supportClaim 'the generated application makes no support claim'
    Assert-Equal 'None' $result[0].previewOrStableClaim 'the generated application makes no Preview claim'
    Assert-Equal $true ($preview[0].notes -join ' ' -match 'no Supported') `
        'the public preview denies a Supported claim'
    Assert-Equal $true (Test-Json -Json ($result[0] | ConvertTo-Json -Compress -Depth 20) `
        -SchemaFile $resultSchemaPath) 'the application result satisfies the public schema'
    Assert-Equal $true (Test-Json -Json ($preview[0] | ConvertTo-Json -Compress -Depth 20) `
        -SchemaFile $previewSchemaPath) 'the application preview satisfies the public schema'
    Assert-Equal $false (($result[0] | ConvertTo-Json -Compress -Depth 20) -match [regex]::Escape($workRoot)) `
        'the application result omits the workspace path'
    Assert-Equal 1 $terminal.Count 'publication ends with one terminal record'
    Assert-Equal 'Completed' $terminal[0].outcome 'a complete synthetic request completes without collection'
    Assert-Equal 'PUBLISH.PUBLISHED_AND_VERIFIED' $terminal[0].reasonCode `
        'the terminal reason records that the synthetic publication verified'
    Assert-Equal $false $terminal[0].collectionStarted 'completed publication never collects'
    Assert-Equal $false (Test-Path -LiteralPath (
        Join-Path $safeWorkspace 'derived-publication-preview.json'
    ) -PathType Leaf) 'the generated application leaves no derived preview'
    Assert-Equal $false (Test-Path -LiteralPath (
        Join-Path $safeWorkspace 'synthetic-publisher'
    )) 'the generated application leaves no publisher residue'

    $missing = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'PublishPreviewRelease'
    )
    Assert-Equal 20 $missing.ExitCode 'a missing request ends NotStarted'
    $missingTerminal = @($missing.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    $missingResult = @($missing.Records | Where-Object recordType -eq 'win-pcinfo.preview-publication-result')
    Assert-Equal 'NotStarted' $missingTerminal[0].outcome 'a missing request stays NotStarted'
    Assert-Equal 'PUBLISH.REQUEST_MISSING' $missingTerminal[0].reasonCode `
        'a missing request uses a stable reason'
    Assert-Equal 'Rejected' $missingResult[0].state 'a missing request is rejected'

    $secretWorkspace = New-MarkedWorkspace -Name 'secret'
    $secret = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'PublishPreviewRelease',
        '-PublicationRequestPath', $secretPath,
        '-PublicationWorkspacePath', $secretWorkspace
    )
    Assert-Equal 20 $secret.ExitCode 'a privacy-violating request ends NotStarted'
    $secretTerminal = @($secret.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    $secretResult = @($secret.Records | Where-Object recordType -eq 'win-pcinfo.preview-publication-result')
    Assert-Equal 'NotStarted' $secretTerminal[0].outcome 'a secret stays NotStarted'
    Assert-Equal 'PUBLISH.PRIVACY_REJECTED' $secretTerminal[0].reasonCode `
        'a secret uses a stable privacy reason'
    Assert-Equal 'Rejected' $secretResult[0].state 'a secret is rejected'

    $kindWorkspace = New-MarkedWorkspace -Name 'kind'
    $wrongKind = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'PublishPreviewRelease',
        '-PublicationRequestPath', $kindPath,
        '-PublicationWorkspacePath', $kindWorkspace
    )
    Assert-Equal 20 $wrongKind.ExitCode 'a wrong-kind request ends NotStarted'
    $kindTerminal = @($wrongKind.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 'NotStarted' $kindTerminal[0].outcome 'a wrong-kind request stays NotStarted'
    Assert-Equal 'PUBLISH.REQUEST_INVALID' $kindTerminal[0].reasonCode `
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
        '-Workflow', 'PublishPreviewRelease',
        '-PublicationRequestPath', $boundPath,
        '-PublicationWorkspacePath', $repoWorkspace
    )
    Assert-Equal 20 $repoRejected.ExitCode 'a repository workspace ends NotStarted'
    $repoTerminal = @($repoRejected.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 'NotStarted' $repoTerminal[0].outcome 'a repository workspace stays NotStarted'
    Assert-Equal 'PUBLISH.WORKSPACE_REPOSITORY_PATH' $repoTerminal[0].reasonCode `
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
Write-Output 'PASS: the generated application stages, previews, and synthetically publishes without collection.'
