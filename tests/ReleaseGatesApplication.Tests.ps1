[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/ReleaseGates.ps1')

$manifestSchemaPath = Join-Path $repositoryRoot 'schemas/release-evidence-manifest.schema.json'
$matrixSchemaPath = Join-Path $repositoryRoot 'schemas/preview-capability-matrix.schema.json'
$completePath = Join-Path $PSScriptRoot 'fixtures/release-evidence-pack-complete-presigning.json'
# Generate disposable synthetic observations relative to one captured UTC instant.
# The stored fixture and the generated application's evaluation clock are unchanged.
$syntheticFixtureNow = [datetimeoffset]::UtcNow
$workRoot = Join-Path $repositoryRoot '.test-output/release-gates-application'
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $workRoot -Force
$candidatePath = Join-Path $workRoot 'WIN-PCInfo.ps1'
$null = & (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath

$candidateDigest = Get-ReleaseGatesSha256 -Bytes ([System.IO.File]::ReadAllBytes($candidatePath))
$ledgerDigest = Get-ReleaseGatesSha256 -Bytes ([System.IO.File]::ReadAllBytes(
    (Join-Path $repositoryRoot 'docs/spec/capability-ledger.json')
))

function New-BoundPackPath {
    param(
        [Parameter(Mandatory)] [string] $SourcePath,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter()] [datetimeoffset] $SyntheticObservedAt = $syntheticFixtureNow.AddDays(-1),
        [Parameter()] [scriptblock] $Mutate
    )

    $pack = Get-Content -LiteralPath $SourcePath -Raw | ConvertFrom-Json -Depth 30
    Assert-Equal $true $pack.synthetic 'relative test dates require a synthetic pack'
    $observedAt = $SyntheticObservedAt.ToUniversalTime().ToString(
        'o', [System.Globalization.CultureInfo]::InvariantCulture
    )
    $pack.observedAt = $observedAt
    $pack.bindings.generatedContentSha256 = $candidateDigest
    $pack.bindings.ledgerSha256 = $ledgerDigest
    foreach ($gate in @($pack.gates)) {
        $gate.observedAt = $observedAt
        $gate.generatedContentSha256 = $candidateDigest
    }
    foreach ($scenario in @($pack.scenarios)) {
        $scenario.observedAt = $observedAt
        $scenario.generatedContentSha256 = $candidateDigest
    }
    if ($null -ne $Mutate) {
        & $Mutate $pack
    }
    $path = Join-Path $workRoot $Name
    [System.IO.File]::WriteAllText(
        $path,
        ($pack | ConvertTo-Json -Depth 30),
        [System.Text.UTF8Encoding]::new($false)
    )
    $path
}

$boundPath = New-BoundPackPath -SourcePath $completePath -Name 'bound-complete.json'
$secretPath = Join-Path $workRoot 'secret.json'
[System.IO.File]::WriteAllText(
    $secretPath,
    ((Get-Content -LiteralPath $boundPath -Raw) + "`n`"leak`":`"clientSecret=not-a-real-secret`"`n"),
    [System.Text.UTF8Encoding]::new($false)
)
$kindPath = New-BoundPackPath -SourcePath $completePath -Name 'wrong-kind.json' -Mutate {
    param($Pack)
    $Pack.kind = 'win-pcinfo.assessment-run-request'
}

try {
    $evaluated = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'EvaluateReleaseGates',
        '-ReleaseEvidencePackPath', $boundPath
    )
    Assert-Equal 0 $evaluated.ExitCode 'the generated application evaluates a bound synthetic pack'
    $progress = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.progress')
    $manifest = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.release-evidence-manifest')
    $matrix = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.preview-capability-matrix')
    $terminal = @($evaluated.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 2 $progress.Count 'evaluation emits structured start and finish progress'
    Assert-Equal 'release.gates.started' $progress[0].messageId 'evaluation starts with a stable message'
    Assert-Equal 'release.gates.succeeded' $progress[1].messageId 'evaluation success uses a stable message'
    Assert-Equal 1 $manifest.Count 'evaluation emits one sanitized manifest'
    Assert-Equal 1 $matrix.Count 'evaluation emits one derived matrix'
    Assert-Equal 'Evaluated' $manifest[0].state 'the generated application reports Evaluated'
    Assert-Equal $true $manifest[0].unsignedContentQualified `
        'the running generated content matches the rewritten pack'
    Assert-Equal $false $manifest[0].finalArtifactQualified `
        'pre-signing does not qualify a final distributable'
    Assert-Equal $false $manifest[0].collectionStarted 'evaluation never starts assessment collection'
    Assert-Equal 'None' $manifest[0].supportClaim 'the generated application makes no support claim'
    Assert-Equal 'Derived' $matrix[0].state `
        'the generated application derives the matrix from the frozen ledger'
    Assert-Equal $true $matrix[0].derivedFromFrozenLedger `
        'nested generated-application output still finds the reviewed ledger'
    Assert-Equal $true ($matrix[0].rows.Count -gt 0) `
        'derived rows are present when the ledger is found'
    Assert-Equal $true (Test-Json -Json ($manifest[0] | ConvertTo-Json -Compress -Depth 20) `
        -SchemaFile $manifestSchemaPath) 'the application manifest satisfies the public schema'
    Assert-Equal $true (Test-Json -Json ($matrix[0] | ConvertTo-Json -Compress -Depth 20) `
        -SchemaFile $matrixSchemaPath) 'the application matrix satisfies the public schema'
    Assert-Equal $false (($manifest[0] | ConvertTo-Json -Compress -Depth 20) -match [regex]::Escape($workRoot)) `
        'the application manifest omits the workspace path'
    Assert-Equal 1 $terminal.Count 'evaluation ends with one terminal record'
    Assert-Equal 'Completed' $terminal[0].outcome 'a complete synthetic pack completes without collection'
    Assert-Equal 'RELEASE.GATES_EVALUATED' $terminal[0].reasonCode `
        'the terminal reason records that the gate finished'
    Assert-Equal $false $terminal[0].collectionStarted 'completed evaluation never collects'

    # Exceed the existing 30-day Client VM window by a full day.
    $expiredPath = New-BoundPackPath -SourcePath $completePath -Name 'expired-synthetic.json' `
        -SyntheticObservedAt $syntheticFixtureNow.AddDays(-31)
    $expired = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'EvaluateReleaseGates',
        '-ReleaseEvidencePackPath', $expiredPath
    )
    Assert-Equal 0 $expired.ExitCode 'expired evidence completes gate evaluation'
    $expiredManifest = @($expired.Records | Where-Object recordType -eq 'win-pcinfo.release-evidence-manifest')
    $expiredTerminal = @($expired.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $expiredManifest.Count 'expired evidence emits one sanitized manifest'
    Assert-Equal $false $expiredManifest[0].unsignedContentQualified 'expired evidence cannot qualify content'
    Assert-Equal $false $expiredManifest[0].finalArtifactQualified 'expired evidence cannot qualify an artifact'
    Assert-Equal $true ('GATE.EXPIRED' -in @($expiredManifest[0].promotion.blockingReasons)) `
        'expired evidence records the stable gate expiry reason'
    Assert-Equal $true $expiredManifest[0].syntheticEvidenceOnly 'expired evidence stays visibly synthetic'
    Assert-Equal $false $expiredManifest[0].collectionStarted 'expired evaluation never collects'
    Assert-Equal $false $expiredManifest[0].promotion.previewPromotionReady 'expired evidence cannot promote a Preview'
    Assert-Equal $false $expiredManifest[0].promotion.publicationAuthorized 'expired evidence cannot authorize publication'
    $expiredClientGates = @($expiredManifest[0].gates | Where-Object freshnessClass -eq 'ClientVmValidation')
    Assert-Equal 3 $expiredClientGates.Count 'the manifest retains three required Client VM gates'
    foreach ($gate in $expiredClientGates) {
        Assert-Equal 'Expired' $gate.result 'each aged Client VM gate expires'
        Assert-Equal $true $gate.expired 'each aged Client VM gate has an explicit expiry flag'
        Assert-Equal $true $gate.candidateBound 'expired evidence still binds the actual candidate'
    }
    Assert-Equal 1 $expiredTerminal.Count 'expired evidence emits one terminal record'
    Assert-Equal 'Completed' $expiredTerminal[0].outcome 'expiry is a completed gate evaluation'
    Assert-Equal 'RELEASE.GATES_EVALUATED' $expiredTerminal[0].reasonCode `
        'expired evidence preserves the gate evaluation terminal contract'
    Assert-Equal $false $expiredTerminal[0].collectionStarted 'expired gate evaluation never collects'

    $missing = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'EvaluateReleaseGates'
    )
    Assert-Equal 20 $missing.ExitCode 'a missing pack ends NotStarted'
    $missingTerminal = @($missing.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    $missingManifest = @($missing.Records | Where-Object recordType -eq 'win-pcinfo.release-evidence-manifest')
    Assert-Equal 'NotStarted' $missingTerminal[0].outcome 'a missing pack stays NotStarted'
    Assert-Equal 'GATE.PACK_MISSING' $missingTerminal[0].reasonCode 'a missing pack uses a stable reason'
    Assert-Equal 'Rejected' $missingManifest[0].state 'a missing pack is rejected'

    $secret = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'EvaluateReleaseGates',
        '-ReleaseEvidencePackPath', $secretPath
    )
    Assert-Equal 20 $secret.ExitCode 'a privacy-violating pack ends NotStarted'
    $secretTerminal = @($secret.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 'NotStarted' $secretTerminal[0].outcome 'privacy rejection stays NotStarted'
    Assert-Equal 'GATE.PRIVACY_REJECTED' $secretTerminal[0].reasonCode `
        'the generated application rejects secret material'

    $unbound = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'EvaluateReleaseGates',
        '-ReleaseEvidencePackPath', $completePath
    )
    Assert-Equal 0 $unbound.ExitCode 'a mismatched candidate is still evaluated'
    $unboundManifest = @($unbound.Records | Where-Object recordType -eq 'win-pcinfo.release-evidence-manifest')
    Assert-Equal 'Evaluated' $unboundManifest[0].state 'wrong-candidate evidence is judged, not ignored'
    Assert-Equal $false $unboundManifest[0].unsignedContentQualified `
        'the generated application does not qualify a mismatched candidate'
    Assert-Equal $true (
        'GATE.CANDIDATE_MISMATCH' -in @($unboundManifest[0].promotion.blockingReasons)
    ) 'the generated application records the candidate mismatch'

    $kindRejected = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', 'EvaluateReleaseGates',
        '-ReleaseEvidencePackPath', $kindPath
    )
    Assert-Equal 20 $kindRejected.ExitCode 'a wrong request kind ends NotStarted'
    $kindManifest = @($kindRejected.Records | Where-Object recordType -eq 'win-pcinfo.release-evidence-manifest')
    Assert-Equal 'GATE.PACK_INVALID' $kindManifest[0].reasonCode `
        'the generated application rejects a pack that fails the public schema'
}
finally {
    if (Test-Path -LiteralPath $workRoot) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
}

Write-Output 'PASS: the generated application evaluates and rejects release-gate packs.'
