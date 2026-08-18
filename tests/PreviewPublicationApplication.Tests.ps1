[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/PreviewPublication.ps1')

$resultSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication-result.schema.json'
$previewSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication-preview.schema.json'
$completePath = Join-Path $PSScriptRoot 'fixtures/preview-publication-complete-signed.json'
$policy = Get-PreviewPublicationPolicy
$workRoot = Join-Path $repositoryRoot '.test-output/preview-publication-application'
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $workRoot -Force
$candidatePath = Join-Path $workRoot 'WIN-PCInfo.ps1'
$null = & (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath

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
    $request.humanApproval.limitationsDigest =
        Get-PreviewPublicationLimitationsDigest -Limitations $request.limitations
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
    $path = Join-Path ([System.IO.Path]::GetTempPath()) "win-pcinfo-publish-app-$Name"
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

    $repoWorkspace = Join-Path $repositoryRoot '.test-output/preview-publication-app-repo-ws'
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
finally {
    foreach ($name in @('safe', 'secret', 'kind')) {
        $path = Join-Path ([System.IO.Path]::GetTempPath()) "win-pcinfo-publish-app-$name"
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
    $repoWorkspace = Join-Path $repositoryRoot '.test-output/preview-publication-app-repo-ws'
    if (Test-Path -LiteralPath $repoWorkspace) {
        Remove-Item -LiteralPath $repoWorkspace -Recurse -Force
    }
}

Write-Output 'PASS: the generated application stages, previews, and synthetically publishes without collection.'
