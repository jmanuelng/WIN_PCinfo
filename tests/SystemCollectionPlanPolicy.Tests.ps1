[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-system-collection-plan.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/system-collection-plan.schema.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $repositoryRoot 'src/SystemCollectionPlan.ps1')

$policyJson = [System.IO.File]::ReadAllText(
    $policyPath, [System.Text.UTF8Encoding]::new($false, $true)
)
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the release SYSTEM sub-plan satisfies its Draft 2020-12 schema'
$policy = $policyJson | ConvertFrom-Json -Depth 30

Assert-Equal 'win-pcinfo.system-collection-plan/1.0.0' $policy.policyId `
    'the SYSTEM seam has one release-owned identity'
Assert-Equal 1 @($policy.operations).Count `
    'exactly one SYSTEM-only evidence operation is cataloged'
$operation = $policy.operations[0]
Assert-Equal 'op:windows.mdm-bridge.device-manageability' $operation.operationId `
    'the catalog exposes one stable operation ID rather than a command surface'
Assert-Equal 'LocalSystem' $operation.requiredExecutionContext `
    'the operation cannot run under the administrator identity'
Assert-Equal $false $operation.administratorSufficient `
    'the release explicitly records that administrator authority is insufficient'
Assert-Equal 'DeviceManageabilityAvailability' $operation.parameters.queryKind.const `
    'the only parameter is a bounded typed selector with one release value'
Assert-Equal $false $operation.parameters.additionalProperties `
    'scripts, commands, paths, and undeclared parameters cannot enter the plan'
Assert-Equal 'Root\cimv2\mdm\dmmap' $operation.source.namespace `
    'the fixed Windows source namespace is release-defined'
Assert-Equal 'MDM_DeviceManageability_Provider01_01' $operation.source.className `
    'the fixed device-level WMI Bridge class is release-defined'
Assert-Equal 'MicrosoftDocumentation' $operation.authorityProof.kind `
    'the SYSTEM-only decision cites a primary Windows source'
Assert-Equal $false $policy.channel.assessmentEvidenceAllowed `
    'the activation channel cannot transport arbitrary assessment evidence'
Assert-Equal $false $policy.security.assessmentUserContextAllowed `
    'SYSTEM cannot receive the Assessment User Context'
Assert-Equal $false $policy.security.localPackageProtectorAllowed `
    'SYSTEM cannot become or receive the Local Package Protector'
Assert-Equal $false $policy.security.recipientProfileAllowed `
    'SYSTEM cannot receive a Recipient Profile'
Assert-Equal $false $policy.security.packageKeyAllowed `
    'SYSTEM cannot receive package cryptographic authority'
Assert-Equal 'TransientTaskSchedulerCom' $policy.activation.kind `
    'the live activation mechanism is fixed and separately cleaned up'
Assert-Equal 'WindowsJobObjectRequired' $policy.treeControl.mode `
    'the SYSTEM worker and descendants must join the coordinator-owned Job Object'
Assert-Equal 'Global\WINPCInfo-SystemCollection-v1-' $policy.channel.jobNamePrefix `
    'the Job Object crosses the interactive-to-Task-Scheduler session boundary'
$canonicalWorkerSource = (Get-SystemCollectionWorkerSource).Replace("`r`n", "`n").Replace("`r", "`n")
$workerDigest = Get-SystemCollectionSha256 -Bytes (
    [System.Text.UTF8Encoding]::new($false).GetBytes($canonicalWorkerSource)
)
Assert-Equal $policy.activation.payloadSha256 $workerDigest `
    'the policy binds the exact reviewed SYSTEM worker template'
Assert-Equal 9 @($policy.validationScenarios).Count `
    'the allowed, rejection, loss, cancellation, timeout, denial, and cleanup cases are frozen'

$requiredScenarios = @(
    'SyntheticSuccess', 'UnknownOperation', 'InvalidParameters', 'ActivationFailure',
    'WorkerLost', 'Cancellation', 'Timeout', 'Denied', 'AbnormalCleanup'
)
foreach ($scenario in $requiredScenarios) {
    if ($scenario -notin @($policy.validationScenarios)) {
        throw "Required SYSTEM scenario is missing: $scenario"
    }
}

Write-Output 'PASS: the release SYSTEM catalog closes source, authority, plan, activation, privacy, and validation policy.'
