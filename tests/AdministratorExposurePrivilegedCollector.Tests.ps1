[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1')
. (Join-Path $repositoryRoot 'src/FirmwareReadiness.ps1')
. (Join-Path $repositoryRoot 'src/AdministratorExposure.ps1')
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$convertToJsonCommand=Get-Command ConvertTo-Json -CommandType Cmdlet
$administratorPolicy=Get-AdministratorExposurePolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
$plan=[pscustomobject][ordered]@{
    recordType='win-pcinfo.preparation-plan';contractVersion='1.0.0';release='2.0.0-preview.1'
    privilege=[pscustomobject][ordered]@{
        maximumUacInteractions=1;privilegedOperationsFrozen=$true
        privilegedOperations=@(
            [pscustomobject][ordered]@{operationId='observe-firmware-tpm';context='Administrator';parameters=[pscustomobject]@{}},
            [pscustomobject][ordered]@{operationId='observe-local-administrators';context='Administrator';parameters=[pscustomobject]@{}},
            [pscustomobject][ordered]@{operationId='observe-effective-policy';context='Administrator';parameters=[pscustomobject]@{}},
            [pscustomobject][ordered]@{operationId='observe-certificate-trust';context='Administrator';parameters=[pscustomobject]@{}}
        )
    }
}
$digest=Get-ObjectDigest -Value $plan -ConvertToJsonCommand $convertToJsonCommand
$workerSource=Get-PrivilegedCollectionWorkerSource
foreach($requiredSourceFragment in @(
    'new SecurityIdentifier("S-1-5-32-544")',
    'NetLocalGroupGetMembers(',
    'null, groupName, 0, out buffer',
    'DuplicateEntriesRemoved=duplicates',
    'State="Malformed"'
)){
    if(-not $workerSource.Contains($requiredSourceFragment)){
        throw "The live structured collector is missing: $requiredSourceFragment"
    }
}
if($workerSource -match '(?i)Get-LocalGroupMember|net\.exe|whoami\.exe'){
    throw 'The privileged source must not parse localized command output.'
}

foreach($scenario in @($administratorPolicy.validationScenarios|Where-Object {$_ -ne 'ElevationDenied'})){
    $result=Invoke-PrivilegedCollectionPlan -PreparationPlan $plan -PlanDigest $digest `
        -AssessmentUserContext 'subject:assessment-user:primary' `
        -LocalPackageProtector 'protector:initiating-windows-user' `
        -ValidationScenario $(if($scenario -eq 'AlternateAdministrator'){'AlternateAdministrator'}else{'AcceptedElevation'}) `
        -AdministratorScenario $scenario
    Assert-Equal 'Completed' $result.state "$scenario returns from one bounded privileged phase"
    Assert-Equal $true $result.cleanup.verified "$scenario proves the complete worker tree absent"
    if(-not $result.PSObject.Properties['PrivateAdministratorCollectorResult']){
        throw "$scenario did not return its private administrator collector result."
    }
    $private=$result.PrivateAdministratorCollectorResult
    Assert-Equal $true (Test-AdministratorExposureCollectorPayload -Payload $private.payload -Policy $administratorPolicy) `
        "$scenario crosses only the closed SID-based payload"
    Assert-Equal 'subject:assessment-user:primary' $result.identity.assessmentUserContext `
        "$scenario cannot replace the Assessment User Context"
    Assert-Equal 'protector:initiating-windows-user' $result.identity.localPackageProtector `
        "$scenario cannot replace package ownership"
}

$legacy=Invoke-PrivilegedCollectionPlan -PreparationPlan $plan -PlanDigest $digest `
    -AssessmentUserContext 'subject:assessment-user:primary' `
    -LocalPackageProtector 'protector:initiating-windows-user' -ValidationScenario AcceptedElevation
if($legacy.PSObject.Properties['PrivateAdministratorCollectorResult']){
    throw 'An unrequested administrator payload crossed the legacy privilege seam.'
}

Write-Output 'PASS: the privileged worker admits only the closed direct-membership collector result.'
