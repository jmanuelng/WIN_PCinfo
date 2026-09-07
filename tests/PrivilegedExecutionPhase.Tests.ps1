[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$candidate=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$regions=[regex]::Matches([IO.File]::ReadAllText($candidate),
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach($region in $regions){. ([scriptblock]::Create($region.Groups[2].Value))}
$script:phaseSource=Get-PrivilegedCollectionWorkerSource
$script:phasePolicy=Get-PrivilegedCollectionPlanPolicy
$script:caseSource=$script:phaseSource
function Get-PrivilegedCollectionWorkerSource { $script:caseSource }
function Get-PrivilegedCollectionPlanPolicy {
    $policy=$script:phasePolicy | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
    $source=$script:caseSource.Replace("`r`n","`n").Replace("`r","`n")
    $policy.worker.payloadSha256=Get-PrivilegedCollectionPlanSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($source))
    $policy
}
$plan=[pscustomobject]@{
    recordType='win-pcinfo.preparation-plan'; contractVersion='1.0.0'; release='2.0.0-preview.1'
    privilege=[pscustomobject]@{
    maximumUacInteractions=1; privilegedOperationsFrozen=$true
    privilegedOperations=@('observe-firmware-tpm','observe-local-administrators','observe-effective-policy' | ForEach-Object {
        [pscustomobject]@{ operationId=$_; context='Administrator'; parameters=[pscustomobject]@{} }
    })
} }
$digest=Get-ObjectDigest -Value $plan -ConvertToJsonCommand (Get-Command ConvertTo-Json -CommandType Cmdlet)
$send='Write-Frame -Stream $pipe -Json $execution -MaximumBytes $maximumBytes -Token $tokenSource.Token'
Assert-Equal 1 ([regex]::Matches($script:phaseSource,[regex]::Escape($send))).Count 'the controlled worker fault targets the actual execution message'
$cases=[ordered]@{
    wrongNonce='$execution=$execution.Replace([string]$configuration.nonce,(''0''*64))'
    wrongPlan='$execution=$execution.Replace([string]$configuration.planDigest,(''0''*64))'
    wrongPhase='$execution=$execution.Replace(''phase:privileged:primary'',''phase:privileged:other'')'
    wrongKind='$execution=$execution.Replace(''ExecutionStarted'',''executionstarted'')'
    wrongType='$execution=$execution.Replace(''"kind":"ExecutionStarted"'',''"kind":true'')'
    duplicate='$execution=$execution.Replace(''"kind":"ExecutionStarted"'',''"kind":"Other","kind":"ExecutionStarted"'')'
    extra='$execution=$execution.Replace(''"kind":"ExecutionStarted"'',''"extra":"Synthetic","kind":"ExecutionStarted"'')'
    earlyLoss='exit 71'
}
foreach($name in @($cases.Keys)+@('postStartLoss','wrongFinalPhase','success')) {
    $script:caseSource=$script:phaseSource
    if($cases.Contains($name)) { $script:caseSource=$script:caseSource.Replace($send,$cases[$name]+"`n"+$send) }
    if($name -eq 'postStartLoss') {
        $sourceCall='New-SyntheticFirmwareResult -Scenario ([string]$configuration.firmwareScenario)'
        Assert-Equal 1 ([regex]::Matches($script:caseSource,[regex]::Escape($sourceCall))).Count 'loss follows actual synthetic collection'
        $script:caseSource=$script:caseSource.Replace($sourceCall,'$null = '+$sourceCall+'; exit 71')
    }
    if($name -eq 'wrongFinalPhase') {
        $script:caseSource=$script:caseSource.Replace('$result = $resultBody | ConvertTo-Json',
            '$resultBody.phaseId=''phase:privileged:other''; $result = $resultBody | ConvertTo-Json')
    }
    $result=Invoke-PrivilegedCollectionPlan -PreparationPlan $plan -PlanDigest $digest `
        -AssessmentUserContext 'subject:synthetic-user:primary' -LocalPackageProtector 'protector:synthetic-initiator' `
        -ValidationScenario AcceptedElevation -FirmwareScenario Supported
    Assert-Equal $(if($name -eq 'success'){'Completed'}else{'IntegrityFailed'}) $result.state "$name retains protocol truth"
    Assert-Equal ($name -in @('postStartLoss','wrongFinalPhase','success')) $result.executionStarted "$name cannot invent or discard an authenticated execution transition"
    Assert-Equal $(if($name -eq 'success'){3}else{0}) @($result.operations).Count "$name cannot manufacture admitted operation envelopes"
    Assert-Equal $true $result.cleanup.verified "$name verifies absence of the actual owned worker tree and channel"
    if($name -in @('earlyLoss','postStartLoss')) {
        Assert-Equal 'PRIVILEGE.WORKER_LOST' $result.reasonCode 'actual channel loss is identified without scenario-specific reason substitution'
    }
    Write-Output "PASS: authenticated execution boundary $name."
}
