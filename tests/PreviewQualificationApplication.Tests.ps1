[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/PreviewQualification.ps1')

$packetSchemaPath = Join-Path $repositoryRoot 'schemas/preview-qualification-packet.schema.json'
$manifestSchemaPath = Join-Path $repositoryRoot 'schemas/release-evidence-manifest.schema.json'
$completePath = Join-Path $PSScriptRoot 'fixtures/preview-qualification-complete-signed.json'
$policy = Get-PreviewQualificationPolicy
$workRoot = Join-Path $repositoryRoot '.test-output/preview-qualification-application'
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $workRoot -Force
$candidatePath = Join-Path $workRoot 'WIN-PCInfo.ps1'
$null = & (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath

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
        [Parameter()] [scriptblock] $Mutate
    )

    $request = Get-Content -LiteralPath $completePath -Raw | ConvertFrom-Json -Depth 30
    $request.bindings.generatedContentSha256 = $candidateDigest
    $request.bindings.derivedFromGeneratedContentSha256 = $candidateDigest
    $request.bindings.finalDistributableSha256 = $finalDigest
    $request.evidencePack.bindings.generatedContentSha256 = $candidateDigest
    $request.evidencePack.bindings.ledgerSha256 = $ledgerDigest
    $request.evidencePack.finalDistributable.packageSha256 = $finalDigest
    $request.evidencePack.finalDistributable.derivedFromGeneratedContentSha256 = $candidateDigest
    foreach ($gate in @($request.evidencePack.gates)) {
        $gate.generatedContentSha256 = $candidateDigest
    }
    foreach ($scenario in @($request.evidencePack.scenarios)) {
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
    $path = Join-Path ([System.IO.Path]::GetTempPath()) "win-pcinfo-qualify-app-$Name"
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
}
finally {
    foreach ($name in @('safe', 'secret', 'kind')) {
        $path = Join-Path ([System.IO.Path]::GetTempPath()) "win-pcinfo-qualify-app-$name"
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Output 'PASS: generated-application Preview qualification binds the candidate and stays fail-closed.'
