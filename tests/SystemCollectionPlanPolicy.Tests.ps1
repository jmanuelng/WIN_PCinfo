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
Assert-Equal 'OfflineOnly' $operation.networkBehavior `
    'the privileged operation cannot initiate network activity'
Assert-Equal 'ActiveMicrosoftSignedPowerShellHost' $operation.executable `
    'the operation is bound to the already verified active PowerShell host'
Assert-Equal 1 $operation.maximumAttempts `
    'the privileged read cannot be retried outside its one approved attempt'
Assert-Equal 5000 $operation.deadlineMilliseconds `
    'the operation carries its own frozen execution bound'
Assert-Equal 8192 $operation.maximumResultUtf8Bytes `
    'the restricted result cannot exceed the channel evidence ceiling'
Assert-Equal 'CoordinatorOwnedJobObjectTaskAndPipeVerifiedAbsent' $operation.cleanup `
    'the operation freezes the cleanup proof required at every terminal state'
Assert-Equal 'PolicyCspResultCatalogV1' $operation.parameters.queryKind.const `
    'the only parameter is a bounded typed selector with one release value'
Assert-Equal $false $operation.parameters.additionalProperties `
    'scripts, commands, paths, and undeclared parameters cannot enter the plan'
Assert-Equal 'Root\cimv2\mdm\dmmap' $operation.source.namespace `
    'the fixed Windows source namespace is release-defined'
Assert-Equal 'MDM_DeviceManageability_Provider01_01' $operation.source.className `
    'the fixed device-level WMI Bridge class is release-defined'
Assert-Equal 4 @($operation.supplementalSources).Count `
    'the build registry and the three approved Policy Result classes are frozen beside provider discovery'
Assert-Equal 'source:windows.registry.current-build-number' $operation.supplementalSources[0].sourceId `
    'OS catalog selection is bound to one read-only registry value'
Assert-Equal 'MDM_Policy_Result01_ControlPolicyConflict02' $operation.supplementalSources[1].className `
    'the ControlPolicyConflict result class is an approved privileged source'
Assert-Equal 'MDM_Policy_Result01_LocalPoliciesSecurityOptions02' $operation.supplementalSources[2].className `
    'the security-options result class is an approved privileged source'
Assert-Equal 'MDM_Policy_Result01_Update02' $operation.supplementalSources[3].className `
    'the Update result class is an approved privileged source'
Assert-Equal 7 @($operation.privateResultScopeIds).Count `
    'the operation separately freezes all seven restricted Policy CSP result scopes'
Assert-Equal 2 @($operation.policyResultCatalogs).Count `
    'Windows 10 and Windows 11 Policy CSP result catalogs are both frozen'
Assert-Equal 7 @($operation.policyResultCatalogs[0].resultFields).Count `
    'each build catalog allowlists exactly seven Policy CSP result fields'
Assert-Equal 'field:policy.mdm.control-policy-conflict.mdm-wins-over-gp' `
    $operation.policyResultCatalogs[0].resultFields[0].fieldId `
    'the fixed catalog includes the documented MDMWinsOverGP Policy CSP field'
Assert-Equal 'MDM_Policy_Result01_LocalPoliciesSecurityOptions02' `
    $operation.policyResultCatalogs[0].resultFields[1].className `
    'the fixed catalog reads only the release-approved LocalPoliciesSecurityOptions result class'
Assert-Equal './Vendor/MSFT/Policy/Result' `
    $operation.policyResultCatalogs[0].resultFields[0].parentId `
    'the catalog fixes the documented Policy Result parent node'
Assert-Equal 'ControlPolicyConflict' `
    $operation.policyResultCatalogs[0].resultFields[0].instanceId `
    'the catalog fixes the ControlPolicyConflict result node instead of dumping the class'
Assert-Equal 'LocalPoliciesSecurityOptions' `
    $operation.policyResultCatalogs[0].resultFields[1].instanceId `
    'the catalog fixes the LocalPoliciesSecurityOptions result node instead of dumping the class'
Assert-Equal 0 $operation.policyResultCatalogs[0].resultFields[1].minimumValue `
    'machine inactivity accepts no negative or wrapping value'
Assert-Equal 599940 $operation.policyResultCatalogs[0].resultFields[1].maximumValue `
    'machine inactivity is bounded to the documented Policy CSP range'
Assert-Equal 5 $operation.policyResultCatalogs[0].resultFields[3].maximumValue `
    'LM compatibility accepts only a documented option index'
Assert-Equal 'MDM_Policy_Result01_Update02' `
    $operation.policyResultCatalogs[0].resultFields[4].className `
    'the update catalog reads only the release-approved Update result class'
Assert-Equal 365 $operation.policyResultCatalogs[0].resultFields[4].maximumValue `
    'feature-update deferral is bounded to the documented Policy CSP range'
Assert-Equal 30 $operation.policyResultCatalogs[0].resultFields[5].maximumValue `
    'quality-update deferral is bounded to the documented Policy CSP range'
Assert-Equal 1 $operation.policyResultCatalogs[0].resultFields[6].maximumValue `
    'DisableDualScan remains a documented Boolean-like integer only'
Assert-Equal 'MicrosoftDocumentation' $operation.authorityProof.kind `
    'the SYSTEM-only decision cites a primary Windows source'
Assert-Equal 'PolicyCspResultCatalogV1' $policy.channel.assessmentEvidenceContract `
    'the SYSTEM channel admits only the frozen restricted Policy CSP result contract'
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
Assert-Equal 20 @($policy.validationScenarios).Count `
    'the allowed, malformed, rejection, loss, cancellation, timeout, denial, and cleanup cases are frozen'

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
