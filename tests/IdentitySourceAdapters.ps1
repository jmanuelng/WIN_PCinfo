Set-StrictMode -Version Latest

# Controlled OS adapters only: run the generated native normalization, rules,
# contract validation, encryption, report and Completion Summary unchanged.
function Add-ControlledIdentitySources {
    param([string] $ModuleText, [ValidateSet('SeparateUser','EntraJoined','MissingIdentifiers',
        'Workgroup','DomainJoined','Registered','DifferentSession','UserDenied','UserUnavailable',
        'WorkSchoolDenied','Unavailable','AadMalformed','NoJoinSuccess','UnknownJoin','Administrator','LocalSystem','SessionChanged',
        'AdminDenied','AdminUnavailable','AdminEmpty','AdminPartial','SystemDenied','SystemUnavailable','SystemAbsent')]
        [string] $Scenario)
    $ModuleText=$ModuleText.Replace("if (`$scenario -eq '') { `$scenario = 'InvalidFixture' }", "`$script:StatusDeskTransport.State.IdentitySourceFailure=(`$_.Exception.Message + ' ' + `$_.ScriptStackTrace); if (`$scenario -eq '') { `$scenario = 'InvalidFixture' }")
    $ModuleText=$ModuleText.Replace('$script:StatusDeskTransport.State.PrivilegeCompleted=$true; $result }', '$script:StatusDeskTransport.State.PrivilegeCompleted=$true; $script:StatusDeskTransport.State.IdentityPrivilegeReason=$result.reasonCode; $result }')
    if ($Scenario -like 'Admin*' -and $Scenario -ne 'Administrator') {
        $ModuleText=Add-ControlledAdministratorSources -ModuleText $ModuleText -Scenario $Scenario
    }
    if ($Scenario -like 'System*') {
        $ModuleText=Add-ControlledSystemEnrollmentSources -ModuleText $ModuleText -Scenario $Scenario
    }
    $ModuleText = $ModuleText.Replace('Invoke-ControlledIdentityEnrollmentCollection -Policy $Policy -ValidationScenario StandardUser',
        'Invoke-ControlledIdentityEnrollmentCollection -Policy $Policy -Live')
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($ModuleText,[ref]$tokens,[ref]$errors)
    $live=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-LiveIdentityEnrollmentPayload'}, $false)
    $processSid=switch ($Scenario) { SeparateUser {'S-1-5-21-100-200-300-1002'} LocalSystem {'S-1-5-18'} default {'S-1-5-21-100-200-300-1001'} }
    $adapted=$live.Extent.Text.Replace('[Security.Principal.WindowsIdentity]::GetCurrent()',
        "([pscustomobject]@{User=[pscustomobject]@{Value='$processSid'}})")
    $adapted=$adapted.Replace('[Security.Principal.WindowsPrincipal]::new($identity)', '$null')
    $admin=if ($Scenario -in @('Administrator','LocalSystem')) {'$true'} else {'$false'}
    $adapted=[regex]::Replace($adapted, '\$principal\.IsInRole\(\s*\[Security.Principal.WindowsBuiltInRole\]::Administrator\s*\)', $admin)
    $adapted=$adapted.Replace('[Diagnostics.Process]::GetCurrentProcess().SessionId', '3')
    $ModuleText=$ModuleText.Replace($live.Extent.Text,$adapted)
    $ModuleText=$ModuleText.Replace('function Initialize-IdentityEnrollmentNativeSource {', 'function Initialize-UnusedIdentityEnrollmentNativeSource {')
    $ModuleText + @'

function Initialize-IdentityEnrollmentNativeSource {
    Add-Type -TypeDefinition @"
namespace WinPCInfo.IdentityEnrollment {
 public sealed class NativeSnapshot {
  public int DomainError=0, DomainJoinStatus=2, AadError=0, AadJoinType=2, UserError=0, UserSessionId=3;
  public string DomainName=null, DeviceId="00000000-0000-4000-8000-000000000051", TenantId="00000000-0000-4000-8000-000000000052", JoinUserEmail="other@example.invalid", UserAccountName="SYNTHETIC\\assessment-user", UserSid="S-1-5-21-100-200-300-1001";
  public bool AadInfoPresent=true, UserContextAvailable=true;
 }
 public static class NativeSources {
  public static NativeSnapshot Read(string mode) {
   var result=new NativeSnapshot(); string scenario="__CASE__";
   if (scenario == "EntraJoined") result.AadJoinType=1;
   if (scenario == "MissingIdentifiers") { result.DeviceId=null; result.TenantId=null; result.JoinUserEmail=null; }
   if (scenario == "Workgroup" || scenario == "DomainJoined") { result.AadError=1; result.AadInfoPresent=false; result.AadJoinType=0; }
   if (scenario == "DomainJoined") { result.DomainJoinStatus=3; result.DomainName="SYNTHETIC-DOMAIN"; }
   if (scenario == "DifferentSession" || (scenario == "SessionChanged" && mode == "WorkSchool")) result.UserSessionId=4;
   if (scenario == "UserDenied") { result.UserError=5; result.UserContextAvailable=false; }
   if (scenario == "UserUnavailable") result.UserContextAvailable=false;
   if (scenario == "WorkSchoolDenied" && mode == "WorkSchool") result.AadError=unchecked((int)0x80070005);
   if (scenario == "Unavailable") result.AadError=1168;
   if (scenario == "AadMalformed") result.AadError=1;
   if (scenario == "NoJoinSuccess") { result.AadInfoPresent=false; result.AadJoinType=0; }
   if (scenario == "UnknownJoin") { result.DomainJoinStatus=2; result.AadJoinType=0; }
   return result;
  }
 }
}
"@
}
'@.Replace('__CASE__', $Scenario)
}

function Assert-IdentitySourceReport {
    param($Record, [string] $Html, [string] $Scenario)
    $userState=switch ($Scenario) { {$_ -in @('UserDenied','Administrator','LocalSystem')} {'Denied'} UserUnavailable {'Unavailable'} default {'Complete'} }
    $registrationState=switch ($Scenario) {
        {$_ -in @('SeparateUser','DifferentSession','UserDenied','UserUnavailable','Unavailable')} {'Unavailable'}
        {$_ -in @('Administrator','LocalSystem')} {'Denied'} AadMalformed {'Malformed'} default {'Complete'}
    }
    $workState=switch ($Scenario) {
        {$_ -in @('SeparateUser','DifferentSession','UserDenied','UserUnavailable','Unavailable','EntraJoined','UnknownJoin','SessionChanged')} {'Unavailable'}
        {$_ -in @('Administrator','LocalSystem','WorkSchoolDenied')} {'Denied'} AadMalformed {'Malformed'} default {'Complete'}
    }
    foreach ($pair in @(
        @('scope:identity.assessment-user-context',$userState),
        @('scope:device.registration-context',$registrationState),
        @('scope:device.work-school-registration-context',$workState)
    )) {
        $coverage=@($Record.coverage | Where-Object scopeId -eq $pair[0])[0]
        Assert-Equal $pair[1] $coverage.state "$Scenario actual source coverage survives validation and encryption"
        if ($coverage.state -ne 'Complete') {
            Assert-Equal $true ([bool]$coverage.reasonCode) 'source gaps retain stable reasons'
            Assert-Equal $true $Html.Contains($coverage.reasonCode) 'HTML explains each native context limitation'
        }
    }
    $userFinding=@($Record.findings | Where-Object ruleId -eq 'rule:identity.assessment-user-context/1.0.0')[0]
    Assert-Equal $(if($userState -eq 'Complete'){'ExpectedCondition'}else{'Indeterminate'}) $userFinding.outcome 'user verification has an evidence-backed advisory outcome'
    $enrollmentFinding=@($Record.findings | Where-Object ruleId -eq 'rule:identity.work-school-enrollment-context/1.0.0')[0]
    Assert-Equal $(if($workState -eq 'Complete' -and $Scenario -notin @('SystemDenied','SystemUnavailable')){'Informational'}else{'Indeterminate'}) $enrollmentFinding.outcome 'missing enrollment never becomes a negative observation'
    foreach ($task in @('confirm-tenant-device-assignment','confirm-tenant-compliance','confirm-tenant-licensing','confirm-organization-enrollment-intent','confirm-approved-administrator-context','confirm-recovery-escrow')) {
        Assert-Equal 1 @($Record.recommendations | Where-Object { $_.definitionId -eq "task:$task/1.0.0" -and $_.kind -eq 'TenantSideDiscoveryTask' }).Count 'unobservable organization facts stay tenant discovery tasks'
    }
    if ($Scenario -eq 'MissingIdentifiers') {
        foreach ($field in @('field:device.entra-registration.device-id','field:device.entra-registration.tenant-id','field:device.work-school-registration.identifier')) {
            Assert-Equal 'SourceReportedUnknown' @($Record.observations | Where-Object fieldId -eq $field)[0].valueState 'a successful source with missing identifiers preserves unknown values'
        }
        return
    }
    if ($workState -ne 'Complete') {
        Assert-Equal 0 @($Record.observations | Where-Object fieldId -like 'field:device.work-school-registration.*').Count 'unverified account data cannot enter protected evidence'
        Assert-Equal $false $Html.Contains('other@example.invalid') 'unrelated process account cannot appear in HTML'
    }
    if ($Scenario -eq 'UnknownJoin') {
        Assert-Equal 'Indeterminate' @($Record.findings | Where-Object ruleId -eq 'rule:identity.device-registration-context/1.0.0')[0].outcome 'unknown native join enums cannot imply an interpreted registration state'
    }
    if ($Scenario -in @('Workgroup','DomainJoined','NoJoinSuccess')) {
        Assert-Equal $false @($Record.observations | Where-Object fieldId -eq 'field:device.work-school-registration.present')[0].value 'only observed native absence establishes no work account'
    }
    if ($Scenario -like 'Admin*' -and $Scenario -ne 'Administrator') {
        $state=switch ($Scenario) { AdminDenied {'Denied'} AdminUnavailable {'Failed'} AdminPartial {'Partial'} default {'Complete'} }
        $coverage=@($Record.coverage | Where-Object scopeId -eq 'scope:device.local-administrators.direct-membership')[0]
        Assert-Equal $state $coverage.state 'actual administrator source failure stays scoped'
        Assert-Equal $(if($state -eq 'Complete'){'Informational'}else{'Indeterminate'}) @($Record.findings | Where-Object ruleId -eq 'rule:identity.local-administrator-exposure/1.0.0')[0].outcome 'direct membership advice follows actual coverage'
        if ($Scenario -eq 'AdminPartial') {
            Assert-Equal 'SourceReportedUnknown' @($Record.observations | Where-Object fieldId -eq 'field:principal.windows.account-name')[0].valueState 'SID-only enumeration does not establish that an account name is absent'
        }
    }
    if ($Scenario -like 'System*') {
        $state=switch ($Scenario) { SystemDenied {'Denied'} SystemUnavailable {'Unavailable'} default {'Complete'} }
        Assert-Equal $state @($Record.coverage | Where-Object scopeId -eq 'scope:device.mdm-policy.system')[0].state 'SYSTEM provider discovery preserves denied versus unavailable versus observed absence'
    }
}

function Add-ControlledSystemEnrollmentSources {
    param([string] $ModuleText, [string] $Scenario)
    $ModuleText=$ModuleText.Replace('function Get-SystemCollectionWorkerSource {', 'function Get-ControlledOriginalIdentitySystemSource {')
    $ModuleText=$ModuleText.Replace('function Get-SystemCollectionPlanPolicy {', 'function Get-ControlledOriginalIdentitySystemPolicy {')
    $ModuleText=$ModuleText.Replace('function Get-SystemActivationBrokerSource {', 'function Get-ControlledOriginalIdentityBrokerSource {')
    $ModuleText=$ModuleText.Replace('function Get-PrivilegedCollectionPlanPolicy {', 'function Get-ControlledOriginalSystemPrivilegePolicy {')
    $ModuleText + @'

function Get-SystemCollectionWorkerSource {
    $source=Get-ControlledOriginalIdentitySystemSource
    $source=$source.Replace('$providerAvailable = if ([bool] $configuration.validationFixture)', '$providerAvailable = if ($false)')
    $prefix=@"
function Get-CimInstance {
    param(`$Namespace, `$ClassName, `$ErrorAction)
    if (`$Namespace -ne 'Root\cimv2\mdm\dmmap' -or `$ClassName -ne 'MDM_DeviceManageability_Provider01_01') { throw 'Unexpected SYSTEM source projection.' }
    if ('__CASE__' -eq 'SystemDenied') { throw [UnauthorizedAccessException]::new('Synthetic denied provider') }
    if ('__CASE__' -eq 'SystemUnavailable') { throw [InvalidOperationException]::new('Synthetic unavailable provider') }
    @()
}
"@
    $prefix + "`n" + $source
}
function Get-SystemCollectionPlanPolicy {
    $policy=Get-ControlledOriginalIdentitySystemPolicy
    $source=(Get-SystemCollectionWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $policy.activation.payloadSha256=Get-SystemCollectionSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($source))
    $policy
}
function Get-SystemActivationBrokerSource {
    $source=Get-ControlledOriginalIdentityBrokerSource
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
    $node=$ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq 'Get-SystemCollectionWorkerSource'}, $false)
    $memory=[IO.MemoryStream]::new()
    $compressor=[IO.Compression.BrotliStream]::new($memory,[IO.Compression.CompressionLevel]::SmallestSize,$true)
    try { $bytes=[Text.Encoding]::UTF8.GetBytes((Get-SystemCollectionWorkerSource).Replace("`r`n","`n").Replace("`r","`n")); $compressor.Write($bytes,0,$bytes.Length) }
    finally { $compressor.Dispose() }
    $encoded=[Convert]::ToBase64String($memory.ToArray()); $memory.Dispose()
    $replacement="function Get-SystemCollectionWorkerSource { `$m=[IO.MemoryStream]::new([Convert]::FromBase64String('$encoded')); `$b=[IO.Compression.BrotliStream]::new(`$m,[IO.Compression.CompressionMode]::Decompress); `$r=[IO.StreamReader]::new(`$b,[Text.Encoding]::UTF8); try { `$r.ReadToEnd() } finally { `$r.Dispose(); `$b.Dispose(); `$m.Dispose() } }"
    $source.Replace($node.Extent.Text,$replacement)
}
function Get-PrivilegedCollectionPlanPolicy {
    $policy=Get-ControlledOriginalSystemPrivilegePolicy
    $source=(Get-PrivilegedCollectionWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $policy.worker.payloadSha256=Get-PrivilegedCollectionPlanSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($source))
    $policy
}
'@.Replace('__CASE__', $Scenario)
}

function Add-ControlledAdministratorSources {
    param([string] $ModuleText, [string] $Scenario)
    $ModuleText=$ModuleText.Replace('function Get-PrivilegedCollectionWorkerSource {', 'function Get-ControlledOriginalIdentityPrivilegeSource {')
    $ModuleText=$ModuleText.Replace('function Get-PrivilegedCollectionPlanPolicy {', 'function Get-ControlledOriginalIdentityPrivilegePolicy {')
    $ModuleText + @'

function Get-PrivilegedCollectionWorkerSource {
    $source=Get-ControlledOriginalIdentityPrivilegeSource
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
    foreach ($node in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Get-LiveEffectivePolicyResult','Get-LiveFirmwareResult')}, $false)) {
        $source=$source.Replace($node.Extent.Text, '')
    }
    $source=$source.Replace('[WinPCInfoLocalAdministratorsSource]::Read(8)', '(Get-ControlledAdministratorSnapshot)')
    $source=$source.Replace('New-SyntheticAdministratorResult -Scenario ([string]$configuration.administratorScenario)', 'Get-LiveAdministratorResult')
    $prefix=@"
function Get-ControlledAdministratorSnapshot {
    if ('__CASE__' -eq 'AdminDenied') { throw [UnauthorizedAccessException]::new('Synthetic denied source') }
    if ('__CASE__' -eq 'AdminUnavailable') { throw [InvalidOperationException]::new('Synthetic unavailable source') }
    if ('__CASE__' -eq 'AdminEmpty') { return [pscustomobject]@{State='Complete';Complete=`$true;SourceReturnedEntries=0;DuplicateEntriesRemoved=0;Sids=@()} }
    [pscustomobject]@{State='Partial';Complete=`$false;SourceReturnedEntries=9;DuplicateEntriesRemoved=0;Sids=@('S-1-5-21-100-200-300-1001')}
}
"@
    $prefix + "`n" + $source
}
function Get-PrivilegedCollectionPlanPolicy {
    $policy=Get-ControlledOriginalIdentityPrivilegePolicy
    $source=(Get-PrivilegedCollectionWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $policy.worker.payloadSha256=Get-PrivilegedCollectionPlanSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($source))
    $policy
}
'@.Replace('__CASE__', $Scenario)
}
