Set-StrictMode -Version Latest

# Test-only OS boundaries. The generated worker's actual RSoP normalization,
# typed record, rules, encryption, protected reopening and HTML remain active.
function Add-ControlledPolicySources {
    param([string] $ModuleText, [string] $Scenario)
    $ModuleText=$ModuleText.Replace('$initiatingIdentity.Dispose() }', '$initiatingIdentity.Dispose() }; $assessmentSid=''S-1-5-21-100-200-300-1001''')
    $ModuleText=$ModuleText.Replace('[Diagnostics.Process]::GetCurrentProcess().SessionId', '3')
    $ModuleText=$ModuleText.Replace('S-1-5-21-1000-1000-1000-1001', 'S-1-5-21-100-200-300-1001')
    if ($Scenario -eq 'LateIdentityChange') {
        $ModuleText=$ModuleText.Replace('Invoke-ControlledIdentityEnrollmentCollection -Policy $Policy -ValidationScenario StandardUser }', '$result=Invoke-ControlledIdentityEnrollmentCollection -Policy $Policy -ValidationScenario StandardUser; $result.privateAssessmentUserSid=''S-1-5-21-100-200-300-1002''; $result }')
    }
    $ModuleText=$ModuleText.Replace("if (`$scenario -eq '') { `$scenario = 'InvalidFixture' }", "`$script:StatusDeskTransport.State.PolicySourceFailure=(`$_.Exception.Message + ' ' + `$_.ScriptStackTrace); if (`$scenario -eq '') { `$scenario = 'InvalidFixture' }")
    $ModuleText=$ModuleText.Replace('$script:StatusDeskTransport.State.PrivilegeCompleted=$true; $result }', '$script:StatusDeskTransport.State.PrivilegeCompleted=$true; $script:StatusDeskTransport.State.PolicyPrivilegeReason=$result.reasonCode; $result }')
    $ModuleText=$ModuleText.Replace('function Get-PrivilegedCollectionWorkerSource {', 'function Get-ControlledOriginalPolicyWorkerSource {')
    $ModuleText=$ModuleText.Replace('function Get-PrivilegedCollectionPlanPolicy {', 'function Get-ControlledOriginalPolicyWorkerPolicy {')
    $ModuleText=$ModuleText.Replace('$effectivePolicyPayload=if($validationFixture){', '$effectivePolicyPayload=if($false){')
    $ModuleText=$ModuleText.Replace('$state = if ($failureStage -eq ''ELEVATION_DENIED'')', '$script:StatusDeskTransport.State.PolicySourceFailure=$_.Exception.Message; $state = if ($failureStage -eq ''ELEVATION_DENIED'')')
    $ModuleText = $ModuleText + @'

function Get-PrivilegedCollectionWorkerSource {
    $source=(Get-ControlledOriginalPolicyWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
    $live=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-LiveEffectivePolicyResult'}, $false)
    $adapted=$live.Extent.Text
    # Other capability owners keep their fixture coverage. The exact policy
    # blocks through RSoP, SAM, audit, rights and security options execute.
    $start=$adapted.IndexOf('    foreach($definition in @(' + "`n" + '        [ordered]@{signalIndex=0;scopeIndex=15;')
    if ($start -lt 0) { throw 'Controlled policy source anchor is absent.' }
    $end=$adapted.IndexOf('    $groups=$result.policySettings')
    $adapted=$adapted.Remove($start,$end-$start)
    $baseline=New-EffectivePolicySyntheticPayload -Policy (Get-EffectivePolicyPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)) -Scenario Workgroup
    foreach($field in $baseline.localSam.PSObject.Properties){$field.Value=$null}
    foreach($audit in $baseline.auditSubcategories){$audit.state='Failed';$audit.successEnabled=$null;$audit.failureEnabled=$null}
    foreach($right in $baseline.userRights){$right.state='Failed';$right.directSids=@()}
    foreach($option in $baseline.securityOptions){$option.state='Failed';$option.value=$null}
    $baselineJson=($baseline | ConvertTo-Json -Compress -Depth 12).Replace("'","''")
    $adapted=$adapted.Replace('$result=New-EffectivePolicyBaseResult Failed',
        ('$result=ConvertFrom-Json -AsHashtable -InputObject ''' + $baselineJson + '''; $result.appliedPolicies=@(); $result.policySettings=@()'))
    $source=$source.Replace($live.Extent.Text,$adapted)
    $source=$source.Replace('[WinPCInfoEffectivePolicyNativeSource]::ReadLocalSamPassword()', '(Get-ControlledSamPassword)')
    $source=$source.Replace('[WinPCInfoEffectivePolicyNativeSource]::ReadLocalSamLockout()', '(Get-ControlledSamLockout)')
    $source=$source.Replace('[WinPCInfoEffectivePolicyNativeSource]::ReadSystemAuditing()', '(Get-ControlledAudit)')
    $source=$source.Replace('[WinPCInfoEffectivePolicyNativeSource]::ReadUserRight([string]$result.userRights[$index].catalogId,8)', '(Get-ControlledUserRight $result.userRights[$index].catalogId)')
    $source=$source.Replace('[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($definition[1],$false)', '(Get-ControlledSecurityOptionKey)')
    $source=$source.Replace('New-SyntheticEffectivePolicyResult -Scenario ([string]$configuration.effectivePolicyScenario)',
        'Get-LiveEffectivePolicyResult -AssessmentUserSid $assessmentUserSid')
    $prefix=@"
function Get-CimInstance {
    param(`$Namespace, `$ClassName, `$Property, `$Query, `$ErrorAction)
    if (`$Namespace -like 'root/RSOP/User/*' -and `$Namespace -ne 'root/RSOP/User/S_1_5_21_100_200_300_1001') {
        throw [InvalidOperationException]::new('Synthetic namespace absent')
    }
    if (`$Namespace -notin @('root/RSOP/User/S_1_5_21_100_200_300_1001','root/RSOP/Computer')) { throw 'Unexpected policy source.' }
    if (`$ClassName -eq 'RSOP_GPO') {
        if ('__CASE__' -eq 'DomainPrecedence') { [pscustomobject]@{id='CN={6ac1786c-016f-11d2-945f-00c04fb984f9},CN=Policies,DC=synthetic';guidName='{6ac1786c-016f-11d2-945f-00c04fb984f9}';enabled=`$true;accessDenied=`$false;filterAllowed=`$true} }
        return [pscustomobject]@{id='LocalGPO';guidName='LocalGPO';enabled=`$true;accessDenied=`$false;filterAllowed=`$true}
    }
    if (`$ClassName -eq 'RSOP_GPLink') {
        if ('__CASE__' -eq 'ReferenceCollision') { return [pscustomobject]@{GPO='RSOP_GPO.id="LocalGPO-other"';SOM='synthetic-wrong-link';appliedOrder=1;enabled=`$true} }
        if ('__CASE__' -eq 'MalformedReference') { return [pscustomobject]@{GPO='unparseable-reference';SOM='unparseable-scope';appliedOrder=1;enabled=`$true} }
        if ('__CASE__' -eq 'DomainPrecedence') {
            return [pscustomobject]@{GPO='RSOP_GPO.id="CN={6ac1786c-016f-11d2-945f-00c04fb984f9},CN=Policies,DC=synthetic"';SOM='RSOP_SOM.id="synthetic-domain-scope"';appliedOrder=[uint32]1;enabled=`$true}
        }
        if ('__CASE__' -eq 'CimReference') {
            `$gpo=[Microsoft.Management.Infrastructure.CimInstance]::new('RSOP_GPO')
            `$gpo.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create('id','LocalGPO',[Microsoft.Management.Infrastructure.CimFlags]::Key))
            `$som=[Microsoft.Management.Infrastructure.CimInstance]::new('RSOP_SOM')
            `$som.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create('id','synthetic-local-scope',[Microsoft.Management.Infrastructure.CimFlags]::Key))
            return [pscustomobject]@{GPO=`$gpo;SOM=`$som;appliedOrder=[uint32]0;enabled=`$true}
        }
        return @()
    }
    if (`$Query -like '*RSOP_PolicySetting') {
        if ('__CASE__' -eq 'DomainPrecedence') {
            [pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='RSOP_RegistryPolicySetting'};id='synthetic-setting';GPOID='CN={6ac1786c-016f-11d2-945f-00c04fb984f9},CN=Policies,DC=synthetic';precedence=[uint32]1}
            [pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='RSOP_RegistryPolicySetting'};id='synthetic-setting';GPOID='LocalGPO';precedence=[uint32]2}
        }
        return
    }
    throw 'Unexpected policy projection.'
}
function Get-ControlledPolicyUserContext {
    if (-not (Get-Variable PolicyContextReads -Scope Script -ErrorAction SilentlyContinue)) { `$script:PolicyContextReads=0 }
    `$script:PolicyContextReads++
    [pscustomobject]@{UserError=`$(if ('__CASE__' -eq 'ContextDenied') {5}else{0});UserContextAvailable=`$('__CASE__' -ne 'ContextUnavailable');UserSid=`$(if ('__CASE__' -eq 'ContextMismatch' -or ('__CASE__' -eq 'ContextChanged' -and `$script:PolicyContextReads -gt 1)) {'S-1-5-21-100-200-300-1002'} else {'S-1-5-21-100-200-300-1001'});UserSessionId=`$(if ('__CASE__' -eq 'DifferentSession') {4}else{3})}
}
function Get-ControlledSamPassword {
    [pscustomobject]@{MinimumLength=14;MaximumAgeSeconds=3628800;MinimumAgeSeconds=86400;HistoryLength=24}
}
function Get-ControlledSamLockout {
    if ('__CASE__' -eq 'SecurityDenied') { throw [UnauthorizedAccessException]::new('Synthetic denied lockout source') }
    [pscustomobject]@{LockoutDurationSeconds=1800;LockoutWindowSeconds=1800;LockoutThreshold=5}
}
function Get-ControlledAudit {
    if ('__CASE__' -eq 'SecurityDenied') { throw [UnauthorizedAccessException]::new('Synthetic denied audit source') }
    foreach (`$id in @('audit:logon','audit:process-creation','audit:user-account-management')) {
        [pscustomobject]@{CatalogId=`$id;SuccessEnabled=`$true;FailureEnabled=`$false}
    }
}
function Get-ControlledUserRight {
    param(`$Id)
    [pscustomobject]@{CatalogId=`$Id;BoundExceeded=`$('__CASE__' -eq 'RightsBound');DirectSids=@('S-1-5-32-544')}
}
function Get-ControlledSecurityOptionKey {
    `$key=[pscustomobject]@{}
    `$key | Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
    `$key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
        param(`$Name,`$Default,`$Options)
        if ('__CASE__' -eq 'SecurityAbsent') { return `$null }
        switch (`$Name) { InactivityTimeoutSecs {900} DisableCAD {0} LmCompatibilityLevel {5} default {throw 'Unexpected registry projection.'} }
    }
    `$key
}
"@
    $source=$source.Replace("[WinPCInfo.IdentityEnrollment.NativeSources]::Read('UserContext')", '(Get-ControlledPolicyUserContext)')
    $source=$source.Replace('    Initialize-IdentityEnrollmentNativeSource', '    # Controlled context snapshot supplies the native boundary.')
    $source=$source.Replace('[Diagnostics.Process]::GetProcessById([int]$configuration.coordinatorProcessId).SessionId', '3')
    $prefix + "`n" + $source
}
function Get-PrivilegedCollectionPlanPolicy {
    $policy=Get-ControlledOriginalPolicyWorkerPolicy
    $source=(Get-PrivilegedCollectionWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $policy.worker.payloadSha256=Get-PrivilegedCollectionPlanSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($source))
    $policy
}
'@.Replace('__CASE__', $Scenario)
    if ($Scenario -like 'Mdm*') {
        . (Join-Path $PSScriptRoot 'IdentitySourceAdapters.ps1')
        $ModuleText=Add-ControlledSystemEnrollmentSources -ModuleText $ModuleText -Scenario $Scenario
    }
    $ModuleText
}

function Assert-PolicySourceReport {
    param($Record, [string] $Html, [string] $Scenario)
    $coverage=@($Record.coverage | Where-Object scopeId -eq 'scope:policy.applied.user.identity')[0]
    $expected=if($Scenario -eq 'ContextDenied'){'Denied'}elseif($Scenario -in @('ContextMismatch','ContextUnavailable','ContextChanged','DifferentSession','LateIdentityChange')){'Unavailable'}else{'Complete'}
    Assert-Equal $expected $coverage.state 'the actual user RSoP source requires the verified Assessment User namespace'
    Assert-Equal 'Complete' @($Record.coverage | Where-Object scopeId -eq 'scope:policy.applied.computer.identity')[0].state 'user limitations preserve independent computer policy evidence'
    Assert-Equal 14 @($Record.observations | Where-Object fieldId -eq 'field:policy.local-sam.minimum-authenticator-length')[0].value 'local SAM password evidence survives the actual native projection'
    foreach($scope in @('scope:policy.local-sam.lockout','scope:policy.local-audit')) {
        Assert-Equal $(if($Scenario -eq 'SecurityDenied'){'Denied'}else{'Complete'}) @($Record.coverage | Where-Object scopeId -eq $scope)[0].state 'denied security sources preserve field-specific coverage'
    }
    Assert-Equal $(if($Scenario -eq 'RightsBound'){'Partial'}else{'Complete'}) @($Record.coverage | Where-Object scopeId -eq 'scope:policy.local-user-rights')[0].state 'direct rights retain bounds without group expansion'
    if ($Scenario -eq 'SecurityAbsent') {
        Assert-Equal 'ObservedAbsent' @($Record.observations | Where-Object fieldId -eq 'field:policy.security-option.machine-inactivity-limit-seconds')[0].valueState 'successful missing registry values prove absence only for that configured signal'
    }
    if ($Scenario -like 'Mdm*') {
        $mdmState=switch($Scenario){MdmDenied {'Denied'} MdmAbsent {'Unsupported'} MdmUnsupportedBuild {'Unsupported'} MdmMissingProperty {'Unavailable'} MdmUnavailable {'Unavailable'} default {'Complete'}}
        Assert-Equal $mdmState @($Record.coverage | Where-Object scopeId -eq 'scope:policy.mdm.security-option.machine-inactivity-limit')[0].state 'the actual bounded SYSTEM CSP source preserves field-specific gaps'
        if ($Scenario -eq 'MdmDenied') {
            Assert-Equal 'POLICY.MDM_RESULT_QUERY_DENIED' @($Record.coverage | Where-Object scopeId -eq 'scope:policy.mdm.security-option.machine-inactivity-limit')[0].reasonCode 'field denial stays distinct from provider discovery denial'
            Assert-Equal $true $Html.Contains('POLICY.MDM_RESULT_QUERY_DENIED') 'protected HTML explains the denied field source'
        }
        $conflict=@($Record.findings | Where-Object ruleId -eq 'rule:policy.policy-csp-gpo-conflict/1.0.0')[0]
        if ($Scenario -eq 'MdmConflict') {
            Assert-Equal 30 @($Record.observations | Where-Object fieldId -eq 'field:policy.mdm.security-option.machine-inactivity-limit-seconds')[0].value 'the controlled SYSTEM result reaches the canonical observation unchanged'
        }
        Assert-Equal $(if($Scenario -eq 'MdmConflict'){'NeedsAttention'}elseif($mdmState -eq 'Complete'){'ExpectedCondition'}else{'Indeterminate'}) $conflict.outcome 'local disagreement produces advice without guessing winning policy or tenant intent'
    }
    if ($Scenario -eq 'ReferenceCollision') {
        Assert-Equal $false $Html.Contains('synthetic-wrong-link') 'a different policy reference cannot donate a link or precedence'
    }
    if ($Scenario -eq 'CimReference') {
        $links=@($Record.observations | Where-Object fieldId -eq 'field:policy.applied.link-id')
        Assert-Equal 'synthetic-local-scope' $links[0].value 'a CIM link reference retains its stable scope key, not display text'
    }
    if ($Scenario -eq 'DomainPrecedence') {
        Assert-Equal 'NeedsAttention' @($Record.findings | Where-Object ruleId -eq 'rule:policy.applied-order-conflict/1.0.0')[0].outcome 'same-setting domain and local precedence is explained as observed competing policy evidence'
        Assert-Equal $true $Html.Contains('synthetic-domain-scope') 'exact textual WMI references retain the observed domain link'
    }
    if ($Scenario -eq 'MalformedReference') {
        Assert-Equal 'Malformed' @($Record.coverage | Where-Object scopeId -eq 'scope:policy.applied.computer.link')[0].state 'an unreadable source reference cannot prove absence'
    }
    foreach ($layer in @('Applied Policy Evidence','Configured Policy Signals','Current Control State')) {
        Assert-Equal $true $Html.Contains($layer) 'policy layers remain distinct in protected HTML'
    }
}
