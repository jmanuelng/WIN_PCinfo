[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-privileged-collection-plan.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/privileged-collection-plan.schema.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')

$policyJson = [System.IO.File]::ReadAllText(
    $policyPath, [System.Text.UTF8Encoding]::new($false, $true)
)
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the release privilege contract satisfies its Draft 2020-12 schema'
$policy = $policyJson | ConvertFrom-Json -Depth 30

Assert-Equal 'win-pcinfo.privileged-collection-plan/1.0.0' $policy.policyId `
    'the privilege seam has one release-owned identity'
Assert-Equal 1 $policy.elevation.maximumUacInteractions `
    'a standard launch can request elevation only once'
Assert-Equal $false $policy.elevation.retryDeniedElevation `
    'denial cannot trigger another prompt'
Assert-Equal 'AlreadyElevatedNoPrompt' $policy.elevation.alreadyElevatedDisposition `
    'an eligible elevated launch does not request elevation again'
Assert-Equal 4 @($policy.operations).Count `
    'the worker accepts exactly the four Administrator operations in the immutable Privileged Collection Plan'
foreach ($operation in @($policy.operations)) {
    Assert-Equal 'Administrator' $operation.context `
        "$($operation.operationId) remains inside the Administrator phase"
    Assert-Equal 'ClosedEmptyObject' $operation.parameterContract `
        "$($operation.operationId) accepts no untyped or caller-selected parameters"
}
$preparationDefinition = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-preparation-plan.json'
) -Raw | ConvertFrom-Json -Depth 20
$preparedAdministratorIds = @($preparationDefinition.operations |
    Where-Object context -eq 'Administrator' | ForEach-Object operationId)
Assert-Equal (@($preparedAdministratorIds) -join ',') `
    (@($policy.operations.operationId) -join ',') `
    'the worker operation set exactly matches the approved Preparation Plan order'
Assert-Equal 1 $policy.channel.maximumServerInstances `
    'the run-bound channel admits only one client instance'
Assert-Equal 'InitiatingUserAndAdministrators' $policy.channel.acl `
    'the pipe ACL admits the coordinator and a selected alternate administrator only'
if ($policy.channel.maximumMessageUtf8Bytes -le 0 -or
    $policy.channel.maximumMessageUtf8Bytes -gt 32768) {
    throw 'Privilege-channel messages need a finite small byte ceiling.'
}
if ($policy.channel.nonceBytes -lt 32) {
    throw 'The privilege channel needs at least 256 bits of run-unique nonce material.'
}
Assert-Equal $true $policy.channel.requirePeerProcessId `
    'both peers bind the pipe handle to the expected process'
Assert-Equal $true $policy.channel.requireArtifactDigest `
    'both peers bind the handshake to reviewed worker source'
Assert-Equal 'FirmwareTpmLocalAdministratorsAndEffectivePolicyProjectionV1' $policy.channel.assessmentEvidenceContract `
    'only the two release-owned bounded privileged projections may cross the privilege channel'
$canonicalWorkerSource = (Get-PrivilegedCollectionWorkerSource).Replace("`r`n", "`n").Replace("`r", "`n")
$workerDigest = Get-PrivilegedCollectionPlanSha256 -Bytes (
    [System.Text.UTF8Encoding]::new($false).GetBytes($canonicalWorkerSource)
)
Assert-Equal $policy.worker.payloadSha256 $workerDigest `
    'the policy binds the exact canonical reviewed worker template'
Assert-Equal 9 @($policy.validationScenarios).Count `
    'all accepted, denial, hostile-channel, and lifecycle scenarios are release-defined'

$requiredScenarios = @(
    'AcceptedElevation', 'AlreadyElevated', 'AlternateAdministrator', 'ElevationDenied',
    'WrongPipeClient', 'AlteredPlan', 'LostWorker', 'Timeout', 'Cancellation'
)
foreach ($scenario in $requiredScenarios) {
    if ($scenario -notin @($policy.validationScenarios)) {
        throw "Required privilege scenario is missing: $scenario"
    }
}

Write-Output 'PASS: the release privilege contract closes elevation, plan, channel, identity, and validation policy.'
