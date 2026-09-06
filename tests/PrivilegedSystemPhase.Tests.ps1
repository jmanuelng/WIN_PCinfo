[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
foreach ($name in @('Contracts','ContractValidator','PrivilegedCollectionPlan','SystemCollectionPlan')) {
    . (Join-Path $repositoryRoot "src/$name.ps1")
}
$plan = [pscustomobject][ordered]@{
    recordType='win-pcinfo.preparation-plan'; contractVersion='1.0.0'; release='2.0.0-preview.1'
    privilege=[pscustomobject][ordered]@{
        maximumUacInteractions=1; privilegedOperationsFrozen=$true
        privilegedOperations=@(
            foreach ($id in @('observe-firmware-tpm','observe-local-administrators','observe-effective-policy')) {
                [pscustomobject]@{operationId=$id; context='Administrator'; parameters=[pscustomobject]@{}}
            }
            [pscustomobject]@{operationId='observe-mdm-system-context'; context='LocalSystem'}
        )
    }
}
$digest = Get-ObjectDigest -Value $plan -ConvertToJsonCommand (Get-Command ConvertTo-Json -CommandType Cmdlet)
$systemPlan = New-SystemCollectionPlan -PreparationPlan $plan -PreparationPlanDigest $digest
$result = Invoke-PrivilegedCollectionPlan -PreparationPlan $plan -PlanDigest $digest `
    -AssessmentUserContext 'subject:synthetic-user:primary' -LocalPackageProtector 'protector:synthetic-initiator' `
    -ValidationScenario AcceptedElevation -SystemPlanResult $systemPlan -SystemValidationScenario SyntheticSuccess
Assert-Equal 'Completed' $result.state 'one administrator session completes'
Assert-Equal 'Completed' $result.PrivateSystemResult.state 'the same session activates the predefined SYSTEM sub-plan'
Assert-Equal 1 $result.elevation.uacInteractionCount 'SYSTEM activation reuses the one administrator authorization'
Assert-Equal $true $result.PrivateSystemResult.cleanup.verified 'SYSTEM worker and channel absence is verified'
Assert-Equal $true $result.cleanup.verified 'administrator worker and channel absence is verified'
Assert-Equal 'Synthetic' $result.PrivateSystemResult.collectorResult.Envelope.executionContext 'controlled workers never claim LocalSystem authority'
Assert-Equal 'protector:synthetic-initiator' $result.identity.localPackageProtector 'SYSTEM activation cannot transfer package ownership'
foreach ($case in @(
    @{Privilege='AlreadyElevated'; System='SyntheticSuccess'; Uac=0; State='Completed'},
    @{Privilege='AlternateAdministrator'; System='SyntheticSuccess'; Uac=1; State='Completed'},
    @{Privilege='AcceptedElevation'; System='Denied'; Uac=1; State='Unavailable'},
    @{Privilege='AcceptedElevation'; System='WorkerLost'; Uac=1; State='Failed'},
    @{Privilege='AcceptedElevation'; System='Timeout'; Uac=1; State='TimedOut'}
)) {
    $phase=Invoke-PrivilegedCollectionPlan -PreparationPlan $plan -PlanDigest $digest `
        -AssessmentUserContext 'subject:synthetic-user:primary' -LocalPackageProtector 'protector:synthetic-initiator' `
        -ValidationScenario $case.Privilege -SystemPlanResult $systemPlan -SystemValidationScenario $case.System
    Assert-Equal 'Completed' $phase.state 'source-scoped SYSTEM gaps do not corrupt the completed administrator phase'
    Assert-Equal $case.State $phase.PrivateSystemResult.state "$($case.System) preserves the SYSTEM disposition"
    Assert-Equal $case.Uac $phase.elevation.uacInteractionCount 'the shared phase never requests a second UAC'
    Assert-Equal $true $phase.PrivateSystemResult.cleanup.verified 'source failure still proves SYSTEM absence'
    Assert-Equal 'protector:synthetic-initiator' $phase.identity.localPackageProtector 'alternate authority does not change the protector'
}
$badPlan=$systemPlan|ConvertTo-Json -Depth 20|ConvertFrom-Json -Depth 20
$badPlan.Plan.operations[0].parameters|Add-Member -NotePropertyName localPackageProtector -NotePropertyValue 'protector:alternate-administrator'
$badPlan.Digest=Get-ObjectDigest -Value $badPlan.Plan -ConvertToJsonCommand (Get-Command ConvertTo-Json -CommandType Cmdlet)
$rejected=$false
try {
    $null=Invoke-PrivilegedCollectionPlan -PreparationPlan $plan -PlanDigest $digest `
        -AssessmentUserContext 'subject:synthetic-user:primary' -LocalPackageProtector 'protector:synthetic-initiator' `
        -ValidationScenario AcceptedElevation -SystemPlanResult $badPlan -SystemValidationScenario SyntheticSuccess
} catch { $rejected=$true }
Assert-Equal $true $rejected 'even a re-digested SYSTEM plan cannot transfer ownership through an undeclared parameter'
$originalPolicy=$script:PrivilegedCollectionPlanPolicyBase64; $originalDigest=$script:PrivilegedCollectionPlanPolicyDigest
try {
    $policy=Get-PrivilegedCollectionPlanPolicy
    $policy.worker.signerCommonName='Synthetic rejected signer'
    $bytes=[Text.Encoding]::UTF8.GetBytes(($policy|ConvertTo-Json -Depth 30 -Compress))
    $script:PrivilegedCollectionPlanPolicyBase64=[Convert]::ToBase64String($bytes)
    $script:PrivilegedCollectionPlanPolicyDigest=Get-PrivilegedCollectionPlanSha256 -Bytes $bytes
    $rejection=Invoke-PrivilegedCollectionPlan -PreparationPlan $plan -PlanDigest $digest `
        -AssessmentUserContext 'subject:synthetic-user:primary' -LocalPackageProtector 'protector:synthetic-initiator' `
        -ValidationScenario AcceptedElevation -SystemPlanResult $systemPlan -SystemValidationScenario SyntheticSuccess
    Assert-Equal 'PRIVILEGE.EXECUTABLE_IDENTITY_INVALID' $rejection.reasonCode 'the actual host signature must match the admitted signer'
    Assert-Equal 0 $rejection.elevation.uacInteractionCount 'signer rejection occurs before any elevation interaction'
    Assert-Equal 0 @($rejection.operations).Count 'signer rejection starts no privileged source'
} finally { $script:PrivilegedCollectionPlanPolicyBase64=$originalPolicy; $script:PrivilegedCollectionPlanPolicyDigest=$originalDigest }
Write-Output 'PASS: contiguous administrator and SYSTEM broker phase with controlled workers.'
