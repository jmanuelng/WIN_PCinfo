Set-StrictMode -Version Latest

function Add-ControlledPlatformSources {
    param([string]$ModuleText,[string]$Scenario)
    . (Join-Path $PSScriptRoot 'IdentitySourceAdapters.ps1')
    $ModuleText=Add-ControlledSystemEnrollmentSources -ModuleText $ModuleText -Scenario MdmPlatform
    $cspAdapter=@'
        if (`$ClassName -like 'MDM_AppLocker_*') {
            if (`$Property -ne 'EnforcementMode') {throw 'Policy payload requested.'}
            if ('__CASE__' -in @('Denied','CspDenied')) {throw [UnauthorizedAccessException]::new()}
            if ('__CASE__' -eq 'Unsupported') {throw [PlatformNotSupportedException]::new()}
            if ('__CASE__' -eq 'Unavailable') {throw [InvalidOperationException]::new()}
            if ('__CASE__' -eq 'CspConflict') {return @([pscustomobject]@{EnforcementMode='AuditOnly'},[pscustomobject]@{EnforcementMode='Enabled'})}
            return [pscustomobject]@{EnforcementMode=`$(if('__CASE__' -eq 'CspMissing'){`$null}elseif('__CASE__' -eq 'CspMalformed'){'<bad>'}else{'AuditOnly'})}
        }
'@
    $ModuleText=$ModuleText.Replace('        if (`$Namespace -ne ''Root\cimv2\mdm\dmmap'')', $cspAdapter+"`n"+'        if (`$Namespace -ne ''Root\cimv2\mdm\dmmap'')')
    $ModuleText=$ModuleText.Replace('function Get-PrivilegedCollectionWorkerSource {','function Get-ControlledPlatformWorkerSource {')
    $ModuleText=$ModuleText.Replace('function Get-PrivilegedCollectionPlanPolicy {','function Get-ControlledPlatformWorkerPolicy {')
    $ModuleText=$ModuleText.Replace('$effectivePolicyPayload=if($validationFixture){','$effectivePolicyPayload=if($false){')
    $ModuleText=$ModuleText.Replace('function Add-EffectivePolicyEvidenceRecord {','function Add-ControlledPlatformEvidenceRecord {')
    $ModuleText=$ModuleText.Replace('$disposition = Get-SystemCollectionFailureDisposition', '$script:StatusDeskTransport.State.PlatformSourceFailure=$_.Exception.Message; $disposition = Get-SystemCollectionFailureDisposition')
    $composed=$ModuleText + @'
function Add-EffectivePolicyEvidenceRecord {
    param($Record,$CollectorResult,$Policy,$SystemResult)
    try { Add-ControlledPlatformEvidenceRecord @PSBoundParameters }
    catch {$script:StatusDeskTransport.State.PlatformSourceFailure=$_.Exception.Message+' '+$_.ScriptStackTrace;throw}
}
function Get-PrivilegedCollectionWorkerSource {
    $source=(Get-ControlledPlatformWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
    $live=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-LiveEffectivePolicyResult'},$false)
    $start=$live.Extent.Text.IndexOf('    # Platform protection sources')
    $end=$live.Extent.Text.IndexOf('    $groups=$result.policySettings')
    if($end -lt 0){throw 'Platform source boundary changed; refuse live fallback.'}
    $blocks=if($start -ge 0){$live.Extent.Text.Substring($start,$end-$start)}else{''}
    $baseline=New-EffectivePolicySyntheticPayload -Policy (Get-EffectivePolicyPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)) -Scenario Workgroup
    $json=($baseline|ConvertTo-Json -Depth 12 -Compress).Replace("'","''")
    $adapted='function Get-LiveEffectivePolicyResult { param($AssessmentUserSid) $result=ConvertFrom-Json -AsHashtable -InputObject '''+$json+''';' + "`n" +
        '$result.scopeStates=@(foreach($id in Get-EffectivePolicyScopeIds){$result.scopeStates|Where-Object scopeId -eq $id}); $result.deviceGuard=(New-EffectivePolicyBaseResult Failed).deviceGuard; $result.bitLockerSystemVolume=(New-EffectivePolicyBaseResult Failed).bitLockerSystemVolume; $result.bitLockerProtectors=@(); $result.appLockerGpCollections=@(); $result.wdacPolicies=@(); Set-EffectivePolicyScopeState $result @(41,42,43,44,45) Failed ''POLICY.SOURCE_NOT_EXECUTED'';' + "`n" + $blocks + "`n" + 'Complete-EffectivePolicyLayerStates $result }'
    $source=$source.Replace($live.Extent.Text,$adapted)
    $source=$source.Replace('New-SyntheticEffectivePolicyResult -Scenario ([string]$configuration.effectivePolicyScenario)','Get-LiveEffectivePolicyResult -AssessmentUserSid $assessmentUserSid')
    $source=$source.Replace('Microsoft.PowerShell.Core\Import-Module -Name $path','Import-ControlledPlatformModule -Name $path')
    $source=$source.Replace('function Read-CiToolJson {','function Read-UnusedCiToolJson {')
    $source=$source.Replace('[Environment]::OSVersion.Version.Build',$(if('__CASE__' -eq 'WdacOld'){'19045'}else{'26100'}))
    $prefix=@"
function Assert-ControlledPlatformAvailability {
    if('__CASE__' -eq 'Denied'){throw [UnauthorizedAccessException]::new()}
    if('__CASE__' -eq 'Unsupported'){throw [PlatformNotSupportedException]::new()}
    if('__CASE__' -eq 'Unavailable'){throw [IO.EndOfStreamException]::new()}
}
function Get-CimInstance {
    param(`$Namespace,`$ClassName,`$Property,`$ErrorAction,`$Filter)
    Assert-ControlledPlatformAvailability
    if(`$ClassName -eq 'Win32_EncryptableVolume'){return [pscustomobject]@{DeviceID='synthetic-volume'}}
    if(`$Namespace -ne 'root/Microsoft/Windows/DeviceGuard' -or `$ClassName -ne 'Win32_DeviceGuard'){throw 'Unapproved controlled platform source.'}
    `$item=[pscustomobject]@{VirtualizationBasedSecurityStatus=[uint32]2;SecurityServicesConfigured=@([uint32]1,[uint32]2);SecurityServicesRunning=@([uint32]1,[uint32]2);UsermodeCodeIntegrityPolicyEnforcementStatus=[uint32]2}
    if('__CASE__' -eq 'VbsPartial'){`$item.PSObject.Properties.Remove('SecurityServicesRunning')}
    if('__CASE__' -eq 'VbsMalformed'){`$item.VirtualizationBasedSecurityStatus='2'}
    if('__CASE__' -eq 'Configured'){`$item.VirtualizationBasedSecurityStatus=[uint32]1;`$item.SecurityServicesRunning=@([uint32]0)}
    `$item
}
function Import-ControlledPlatformModule {
    param(`$Name, [switch]`$PassThru, `$Scope, `$ErrorAction, [switch]`$SkipEditionCheck)
    Assert-ControlledPlatformAvailability
    if(`$Name -notmatch 'AppLocker[\\/]AppLocker.psd1$' -or -not `$SkipEditionCheck){throw 'Unapproved module import.'}
    [pscustomobject]@{ExportedCommands=@{'Get-AppLockerPolicy'=(Get-Command Get-ControlledAppLockerPolicy)}}
}
function Get-ControlledAppLockerPolicy {
    param([switch]`$Effective,`$ErrorAction)
    if(-not `$Effective){throw 'Only effective GP is approved.'}
    [pscustomobject]@{RuleCollections=@([pscustomobject]@{CollectionType='Exe';EnforcementMode=`$(if('__CASE__' -eq 'GpMalformed'){'<bad>'}else{'Enabled'});Policy='synthetic-excluded-policy-marker'})}
}
function Read-CiToolJson {
    Assert-ControlledPlatformAvailability
    if('__CASE__' -eq 'WdacOld'){throw 'Unsupported build must never launch CiTool.'}
    if('__CASE__' -eq 'WdacMalformed'){return '{"Policies":[{"IsEnforced":"enabled","IsSystemPolicy":false,"IsSignedPolicy":true}]}'}
    if('__CASE__' -eq 'WdacBound'){return '{"Policies":['+ ((1..9|ForEach-Object {'{"IsEnforced":true,"IsSystemPolicy":false,"IsSignedPolicy":true}'})-join ',')+']}'}
    '{"Policies":[{"IsEnforced":true,"IsSystemPolicy":false,"IsSignedPolicy":true,"Policy":"synthetic-excluded-policy-marker"}]}'
}
"@
    $prefix += @"
function Invoke-CimMethod {
    param(`$InputObject,`$MethodName,`$Arguments,`$ErrorAction)
    if(`$InputObject.DeviceID -ne 'synthetic-volume'){throw 'Unapproved volume.'}
    switch(`$MethodName){
        GetConversionStatus {[pscustomobject]@{ReturnValue=[uint32]0;ConversionStatus=`$(if('__CASE__' -eq 'Unencrypted'){[uint32]0}else{[uint32]1})}}
        GetProtectionStatus {[pscustomobject]@{ReturnValue=[uint32]0;ProtectionStatus=`$(if('__CASE__' -eq 'BitLockerPartial'){`$null}elseif('__CASE__' -eq 'Unencrypted'){[uint32]0}else{[uint32]1})}}
        GetEncryptionMethod {[pscustomobject]@{ReturnValue=[uint32]0;EncryptionMethod=`$(if('__CASE__' -eq 'Unencrypted'){[uint32]0}else{[uint32]7})}}
        GetLockStatus {[pscustomobject]@{ReturnValue=[uint32]0;LockStatus=[uint32]0}}
        GetKeyProtectors {
            if('__CASE__' -eq 'Unencrypted'){return [pscustomobject]@{ReturnValue=[uint32]2150694920}}
            [pscustomobject]@{ReturnValue=[uint32]0;VolumeKeyProtectorID=@(if('__CASE__' -eq 'ProtectorBound' -and `$Arguments.KeyProtectorType -eq 3){1..33|ForEach-Object {'synthetic-protector-id'}}elseif(`$Arguments.KeyProtectorType -in @(1,3)){'synthetic-protector-id'})}
        }
        default {throw 'Secret or mutating BitLocker method prohibited.'}
    }
}
"@
    $prefix + "`n" + $source
}
function Get-PrivilegedCollectionPlanPolicy {
    $policy=Get-ControlledPlatformWorkerPolicy
    $source=(Get-PrivilegedCollectionWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $policy.worker.payloadSha256=Get-PrivilegedCollectionPlanSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($source))
    $policy
}
'@
    $composed.Replace('__CASE__',$Scenario)
}

function Assert-PlatformSourceReport {
    param($Record,[string]$Html,[string]$Scenario)
    $states=@{'vbs.runtime'='Complete';'bitlocker.operating-system-volume'='Complete';'bitlocker.protectors'='Complete';'applocker.gp-channel'='Complete';'applocker.csp-channel'='Complete';'wdac.inventory'='Partial'}
    if($Scenario -in @('Denied','Unsupported','Unavailable')){foreach($key in @($states.Keys)){$states[$key]=$Scenario}}
    switch($Scenario){
        VbsPartial {$states['vbs.runtime']='Partial'}
        VbsMalformed {$states['vbs.runtime']='Malformed'}
        BitLockerPartial {$states['bitlocker.operating-system-volume']='Partial'}
        ProtectorBound {$states['bitlocker.protectors']='Partial'}
        GpMalformed {$states['applocker.gp-channel']='Malformed'}
        CspDenied {$states['applocker.csp-channel']='Denied'}
        CspMissing {$states['applocker.csp-channel']='Unavailable'}
        CspMalformed {$states['applocker.csp-channel']='Malformed'}
        CspConflict {$states['applocker.csp-channel']='Partial'}
        WdacOld {$states['wdac.inventory']='Unsupported'}
        WdacMalformed {$states['wdac.inventory']='Malformed'}
    }
    foreach($key in $states.Keys){Assert-Equal $states[$key] @($Record.coverage|Where-Object scopeId -eq "scope:policy.$key")[0].state "selected platform source preserves independent $key coverage"}
    $json=$Record|ConvertTo-Json -Depth 40 -Compress
    foreach($marker in @('synthetic-protector-id','synthetic-excluded-policy-marker')){
        Assert-Equal $false $json.Contains($marker) 'only approved state and counts enter evidence'
        Assert-Equal $false $Html.Contains($marker) 'restricted HTML contains no excluded source payload'
    }
    Assert-Equal $true $Html.Contains('Virtualization-based security and Credential Guard') 'platform evidence is readable in the protected HTML'
    if($Scenario -in @('Denied','Unsupported','Unavailable')){
        Assert-Equal 0 @($Record.observations|Where-Object {$_.fieldId -match '^field:policy\.(bitlocker|vbs|credential-guard|applocker|wdac)\.'}).Count 'unavailable controls never imply disabled or absent protection'
        return
    }
    if($Scenario -eq 'BitLockerPartial'){
        Assert-Equal 0 @($Record.observations|Where-Object fieldId -eq 'field:policy.bitlocker.protection-status').Count 'missing protection metadata cannot become observed absence'
    }else{Assert-Equal $(if($Scenario -eq 'Unencrypted'){'Off'}else{'On'}) @($Record.observations|Where-Object fieldId -eq 'field:policy.bitlocker.protection-status')[0].value 'BitLocker local protection is preserved'}
    if($Scenario -eq 'Unencrypted'){Assert-Equal 'ObservedAbsent' @($Record.observations|Where-Object fieldId -eq 'field:policy.bitlocker.protector-type')[0].valueState 'BitLocker not-activated is a documented empty protector result'}
    if($Scenario -in @('VbsPartial','VbsMalformed')){
        Assert-Equal 0 @($Record.observations|Where-Object fieldId -eq 'field:policy.credential-guard.state').Count 'missing runtime metadata cannot become observed absence'
    }else{Assert-Equal $(if($Scenario -eq 'Configured'){'Configured'}else{'Running'}) @($Record.observations|Where-Object fieldId -eq 'field:policy.credential-guard.state')[0].value 'configured and running Credential Guard remain distinct'}
    if($states['applocker.gp-channel'] -eq 'Complete'){Assert-Equal 'Enabled' @($Record.observations|Where-Object fieldId -eq 'field:policy.applocker.gp.enforcement-mode')[0].value 'GP mode remains channel-specific'}
    if($states['wdac.inventory'] -eq 'Partial'){
        Assert-Equal 'Active' @($Record.observations|Where-Object fieldId -eq 'field:policy.wdac.enforcement-state')[0].value 'CiTool active policy does not imply enforced deny rules'
        Assert-Equal 'Unknown' @($Record.observations|Where-Object fieldId -eq 'field:policy.wdac.deployment-channel')[0].value 'missing deployment channel remains unknown'
    }
    if($Scenario -eq 'WdacBound'){Assert-Equal 8 @($Record.observations|Where-Object fieldId -eq 'field:policy.wdac.enforcement-state').Count 'WDAC inventory respects its eight-policy bound'}
    if($states['applocker.csp-channel'] -eq 'Complete'){
        Assert-Equal 'AuditOnly' @($Record.observations|Where-Object fieldId -eq 'field:policy.applocker.csp.enforcement-mode')[0].value 'SYSTEM CSP evidence is distinct from GP'
        foreach($observation in @($Record.observations|Where-Object fieldId -like 'field:policy.applocker.csp.*')){
            $origin=@($Record.provenance|Where-Object provenanceId -eq $observation.provenanceId)[0]
            Assert-Equal 'collector:windows.mdm-bridge.device-manageability' $origin.collectorId 'CSP provenance belongs to the SYSTEM collector'
        }
    }
    Assert-Equal $(if($states['applocker.csp-channel'] -eq 'Complete' -and $states['applocker.gp-channel'] -eq 'Complete'){'NeedsAttention'}else{'Indeterminate'}) @($Record.findings|Where-Object ruleId -eq 'rule:policy.policy-csp-gpo-conflict/1.0.0')[0].outcome 'GP and CSP disagreements require independent evidence without choosing a winner'
}
