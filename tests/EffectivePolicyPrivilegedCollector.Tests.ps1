[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1')
. (Join-Path $repositoryRoot 'src/FirmwareReadiness.ps1')
. (Join-Path $repositoryRoot 'src/AdministratorExposure.ps1')
. (Join-Path $repositoryRoot 'src/EffectivePolicy.ps1')
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$convertToJsonCommand=Get-Command ConvertTo-Json -CommandType Cmdlet
$policy=Get-EffectivePolicyPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
$plan=[pscustomobject][ordered]@{
    recordType='win-pcinfo.preparation-plan';contractVersion='1.0.0';release='2.0.0-preview.1'
    privilege=[pscustomobject][ordered]@{
        maximumUacInteractions=1;privilegedOperationsFrozen=$true
        privilegedOperations=@(
            [pscustomobject][ordered]@{operationId='observe-firmware-tpm';context='Administrator';parameters=[pscustomobject]@{}},
            [pscustomobject][ordered]@{operationId='observe-local-administrators';context='Administrator';parameters=[pscustomobject]@{}},
            [pscustomobject][ordered]@{operationId='observe-effective-policy';context='Administrator';parameters=[pscustomobject]@{}}
        )
    }
}
$digest=Get-ObjectDigest -Value $plan -ConvertToJsonCommand $convertToJsonCommand
$workerSource=Get-PrivilegedCollectionWorkerSource
$reordered=New-EffectivePolicySyntheticPayload -Policy $policy -Scenario Workgroup
[array]::Reverse($reordered.scopeStates)
Assert-Equal $true (Test-EffectivePolicyCollectorPayload -Payload $reordered -Policy $policy) 'scope identity is independent of native source order'
$canonical=Copy-EffectivePolicyCollectorPayload -Payload $reordered -Policy $policy
Assert-Equal 'scope:policy.applied.user.identity' $canonical.scopeStates[0].scopeId 'copying restores the declared catalog order'
$reordered.scopeStates[0]=$reordered.scopeStates[1]
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $reordered -Policy $policy) 'a duplicate scope cannot replace a missing scope'
$collectorScopes=@(Get-EffectivePolicyCollectorScopes -Policy $policy)
Assert-Equal $collectorScopes.Count (@($policy.scopes|Where-Object { [string]$_.scopeId -notlike 'scope:policy.mdm.*' }).Count) `
    'the privileged worker scope catalog carries every non-MDM Effective Policy scope'
foreach($propertyName in @(
    'windowsUpdateSignals','legacyAuthenticationSignals','rdpState','winrmState',
    'smbState','bitLockerSystemVolume','bitLockerProtectors','deviceGuard',
    'wdacPolicies','appLockerGpCollections','appLockerCspCollections'
)){
    if(-not $workerSource.Contains($propertyName)){
        throw "The privileged worker base payload is missing: $propertyName"
    }
}
foreach($scopeId in @(
    'scope:policy.windows-update.defer-feature-updates',
    'scope:policy.windows-update.defer-quality-updates',
    'scope:policy.windows-update.disable-dual-scan',
    'scope:policy.legacy-auth.lm-compatibility-level',
    'scope:policy.legacy-auth.ntlm-minimum-session-security',
    'scope:policy.rdp.connections','scope:policy.rdp.service',
    'scope:policy.rdp.authentication','scope:policy.rdp.listener',
    'scope:policy.winrm.service','scope:policy.winrm.configuration',
    'scope:policy.winrm.authentication','scope:policy.winrm.listener',
    'scope:policy.smb.client','scope:policy.smb.server',
    'scope:policy.smb.smb1-feature'
)){
    if(-not (@($collectorScopes.scopeId) -contains $scopeId)){
        throw "The privileged worker dropped a release-owned scope: $scopeId"
    }
}
foreach($fragment in @(
    'RSOP_GPO','RSOP_GPLink','RSOP_PolicySetting','NetUserModalsGet(',
    'AuditQuerySystemPolicy(','LsaEnumerateAccountsWithUserRight(',
    'OpenSubKey(',"'root/RSOP/Computer'",'assessmentUserSid',
    'RSOP_RegistryPolicySetting','POLICY.RSOP_EXTENSION_UNSUPPORTED',
    'POLICY.RSOP_LINK_AMBIGUOUS','POLICY.RSOP_EVIDENCE_BOUND_EXCEEDED','Count -gt 8',
    'Test-PrivilegedCollectionSid $root.GetProperty(''assessmentUserSid'').GetString()',
    'WscGetSecurityProviderHealth(','ReadSecurityProviderHealth([uint32]$providerDefinition.providerValue)',
    '[DllImport("Wscapi.dll")]','New-Object -ComObject ''WSCProductList''',
    'Get-MpComputerStatus','Get-MpPreference',
    'Get-SecurityCommand Get-NetFirewallProfile','-PolicyStore ActiveStore',
    'AttackSurfaceReductionRules_Ids','AttackSurfaceReductionRules_Actions',
    'EnableNetworkProtection','IsTamperProtected',
    'MDM_Policy_Result01_Update02','DeferFeatureUpdatesPeriodInDays',
    'DeferQualityUpdatesPeriodInDays','DisableDualScan',
    'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate','NtlmMinClientSec',
    'NtlmMinServerSec','fDenyTSConnections','fEnableWinStation',
    'Win32_TSGeneralSetting','WSMan:\\localhost\\Service\\Auth',
    'WSMan:\\localhost\\Listener','Get-SmbClientConfiguration',
    'Get-SmbServerConfiguration','Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol',
    'Convert-EffectivePolicyRdpSecurityLayer',
    'Convert-EffectivePolicyRdpMinEncryptionLevel',
    'Convert-EffectivePolicyOptionalFeatureState',
    'Get-EffectivePolicyWsmanNodeValues'
)){
    if(-not $workerSource.Contains($fragment)){throw "The live structured policy collector is missing: $fragment"}
}
if($workerSource.Contains("namespace='root/RSOP/User'")){
    throw 'The elevated worker must not query an unbound generic user RSoP namespace.'
}
if($workerSource.Contains("'linkOrder'")){
    throw 'The worker must not read undeclared RSoP properties.'
}
foreach($fragment in @("GetProperty('assessmentUserSid')",'root/RSOP/User/','$assessmentUserSid')){
    if(-not $workerSource.Contains($fragment)){
        throw "The live user RSoP source is not bound through the protected request: $fragment"
    }
}
$coordinatorSource=Get-Content -LiteralPath (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1') -Raw
if($coordinatorSource -notmatch 'assessmentUserSid\s*=\s*\$AssessmentUserSid' -or
    $coordinatorSource -match 'assessmentUserSid\s*=\s*\$initiatingSid'){
    throw 'The protected request must use the verified Assessment User SID, not coordinator process identity.'
}
if($workerSource -match '(?i)gpresult|secedit|(?:^|[^A-Za-z])LGPO(?:\.exe)?(?:$|[^A-Za-z])|Get-GPO|auditpol(?:\.exe)?\s|net\.exe|PsExec'){
    throw 'The privileged policy source must not install tools or parse localized command output.'
}

foreach($scenario in @($policy.validationScenarios|Where-Object {$_ -ne 'DeniedSystem'})){
    $result=Invoke-PrivilegedCollectionPlan -PreparationPlan $plan -PlanDigest $digest `
        -AssessmentUserContext 'subject:assessment-user:primary' `
        -LocalPackageProtector 'protector:initiating-windows-user' `
        -ValidationScenario $(if($scenario -eq 'DeniedAdministrator'){'ElevationDenied'}else{'AcceptedElevation'}) `
        -EffectivePolicyScenario $scenario
    if($scenario -eq 'DeniedAdministrator'){
        Assert-Equal 'Unavailable' $result.state 'elevation denial stops before the policy worker'
        continue
    }
    Assert-Equal 'Completed' $result.state "$scenario returns from one bounded privileged phase"
    Assert-Equal $true $result.cleanup.verified "$scenario proves the complete worker tree absent"
    if(-not $result.PSObject.Properties['PrivateEffectivePolicyCollectorResult']){
        throw "$scenario did not return its private Effective Policy collector result."
    }
    Assert-Equal $true (Test-EffectivePolicyCollectorPayload `
        -Payload $result.PrivateEffectivePolicyCollectorResult.payload -Policy $policy) `
        "$scenario crosses only the closed three-layer payload"
}

$invalidLocalSamString=New-EffectivePolicySyntheticPayload -Policy $policy -Scenario Workgroup
$invalidLocalSamString.localSam.minimumPasswordLength='password=ForbiddenSecret123!'
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $invalidLocalSamString -Policy $policy) `
    'a secret-like string cannot cross an integer local-SAM field'

$invalidLocalSamObject=New-EffectivePolicySyntheticPayload -Policy $policy -Scenario Workgroup
$invalidLocalSamObject.localSam.lockoutThreshold=[pscustomobject]@{token='ForbiddenSecret123!'}
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $invalidLocalSamObject -Policy $policy) `
    'an object cannot cross an integer local-SAM field'

$invalidIntegerOption=New-EffectivePolicySyntheticPayload -Policy $policy -Scenario Workgroup
$invalidIntegerOption.securityOptions[0].value='token=ForbiddenSecret123!'
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $invalidIntegerOption -Policy $policy) `
    'a secret-like string cannot cross an Integer security-option catalog entry'

$invalidBooleanOption=New-EffectivePolicySyntheticPayload -Policy $policy -Scenario Workgroup
$invalidBooleanOption.securityOptions[1].value=[pscustomobject]@{credential='ForbiddenSecret123!'}
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $invalidBooleanOption -Policy $policy) `
    'an object cannot cross a Boolean security-option catalog entry'
if(-not $workerSource.Contains('function Convert-EffectivePolicyRegistryBooleanValue') -or
    -not $workerSource.Contains('function Convert-EffectivePolicyRegistryUnsignedIntegerValue')){
    throw 'The reviewed worker must carry explicit configured-signal normalization helpers.'
}
if($workerSource.Contains('[bool]([int]$value)') -or $workerSource.Contains('[bool]([int]$rawValue)')){
    throw 'The reviewed worker must not coerce registry integers into Boolean configured signals implicitly.'
}

$absentOptions=New-EffectivePolicySyntheticPayload -Policy $policy -Scenario Workgroup
$absentOptions.securityOptions[0].value=$null
$absentOptions.securityOptions[1].value=$null
Assert-Equal $true (Test-EffectivePolicyCollectorPayload -Payload $absentOptions -Policy $policy) `
    'missing Integer and Boolean registry values remain valid observed-absence inputs'
$copiedAbsentOptions=Copy-EffectivePolicyCollectorPayload -Payload $absentOptions -Policy $policy
if($null -ne $copiedAbsentOptions.securityOptions[0].value -or
    $null -ne $copiedAbsentOptions.securityOptions[1].value){
    throw 'The closed copy must preserve absent Integer and Boolean registry values as null.'
}

$invalidLocaleObject=New-EffectivePolicySyntheticPayload -Policy $policy -Scenario Workgroup
$invalidLocaleObject.sourceLocale=[pscustomobject]@{name='en-US'}
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $invalidLocaleObject -Policy $policy) `
    'an object cannot cross the canonical locale field'
$invalidLocaleOversize=New-EffectivePolicySyntheticPayload -Policy $policy -Scenario Workgroup
$invalidLocaleOversize.sourceLocale=('a' * 1000)
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $invalidLocaleOversize -Policy $policy) `
    'an oversized string cannot cross the canonical locale field'
$invalidLinkType=New-EffectivePolicySyntheticPayload -Policy $policy -Scenario Workgroup
$invalidLinkType.appliedPolicies[0].linkId=42
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $invalidLinkType -Policy $policy) `
    'an integer cannot cross the string link identity field'
foreach($badOrder in @($true,'1')){
    $invalidOrder=New-EffectivePolicySyntheticPayload -Policy $policy -Scenario Workgroup
    $invalidOrder.appliedPolicies[0].appliedOrder=$badOrder
    Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $invalidOrder -Policy $policy) `
        'only an exact integral primitive can cross applied order'
}
foreach($badPrecedence in @($true,'1')){
    $invalidPrecedence=New-EffectivePolicySyntheticPayload -Policy $policy -Scenario Workgroup
    $invalidPrecedence.policySettings[0].precedence=$badPrecedence
    Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $invalidPrecedence -Policy $policy) `
        'only an exact integral primitive can cross setting precedence'
}
foreach($badSid in @(
    ('S-1-5-' + ('1-' * 150) + '1'),
    'S-1-281474976710656-1',
    'S-1-5-4294967296'
)){
    $invalidRightSid=New-EffectivePolicySyntheticPayload -Policy $policy -Scenario Workgroup
    $invalidRightSid.userRights[0].directSids=@($badSid)
    Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $invalidRightSid -Policy $policy) `
        'oversized or out-of-range SID components cannot cross a user-right assignment'
    Assert-Equal $false (Test-PrivilegedCollectionSid $badSid) `
        'oversized or out-of-range Assessment User SIDs cannot enter the protected request'
    $requestRejected=$false
    try{
        Invoke-PrivilegedCollectionPlan -PreparationPlan $plan -PlanDigest $digest `
            -AssessmentUserContext 'subject:assessment-user:primary' -AssessmentUserSid $badSid `
            -LocalPackageProtector 'protector:initiating-windows-user' `
            -ValidationScenario AcceptedElevation -EffectivePolicyScenario Workgroup | Out-Null
    }catch{$requestRejected=$true}
    Assert-Equal $true $requestRejected `
        'the coordinator rejects an invalid Assessment User SID before starting elevation'
}

$legacy=Invoke-PrivilegedCollectionPlan -PreparationPlan $plan -PlanDigest $digest `
    -AssessmentUserContext 'subject:assessment-user:primary' `
    -LocalPackageProtector 'protector:initiating-windows-user' `
    -ValidationScenario AcceptedElevation
if($legacy.PSObject.Properties['PrivateEffectivePolicyCollectorResult']){
    throw 'An unrequested policy payload crossed the legacy privilege seam.'
}

Write-Output 'PASS: the privileged worker admits only the closed read-only Effective Policy projection.'
