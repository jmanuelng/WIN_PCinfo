Set-StrictMode -Version Latest

# The actual generated security source blocks execute inside the authenticated
# worker. Only OS calls are replaced; other families retain synthetic coverage.
function Add-ControlledSecuritySources {
    param([string]$ModuleText,[string]$Scenario)
    $ModuleText=$ModuleText.Replace('function Get-PrivilegedCollectionWorkerSource {','function Get-ControlledOriginalSecurityWorkerSource {')
    $ModuleText=$ModuleText.Replace('function Get-PrivilegedCollectionPlanPolicy {','function Get-ControlledOriginalSecurityWorkerPolicy {')
    $ModuleText=$ModuleText.Replace('$effectivePolicyPayload=if($validationFixture){','$effectivePolicyPayload=if($false){')
    $ModuleText=$ModuleText.Replace('$state = if ($failureStage -eq ''ELEVATION_DENIED'')', '$script:StatusDeskTransport.State.SecuritySourceFailure=$_.Exception.Message; $state = if ($failureStage -eq ''ELEVATION_DENIED'')')
    $ModuleText + @'

function Get-PrivilegedCollectionWorkerSource {
    $source=(Get-ControlledOriginalSecurityWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
    $live=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-LiveEffectivePolicyResult'},$false)
    $start=$live.Extent.Text.IndexOf('    $preferenceCommand=')
    $end=$live.Extent.Text.IndexOf('    # Remote-management settings')
    if($start -lt 0 -or $end -le $start){throw 'Security source boundary changed; refuse live fallback.'}
    $blocks=$live.Extent.Text.Substring($start,$end-$start)
    $blocks=$blocks.Replace('[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey([string]$definition.path,$false)','(Get-ControlledSmartScreenKey)')
    $blocks=$blocks.Replace('[WinPCInfoEffectivePolicyNativeSource]::ReadSecurityProviderHealth([uint32]$providerDefinition.providerValue)',"'Good'")
    $blocks=$blocks.Replace("New-Object -ComObject 'WSCProductList'",'(Get-ControlledSecurityProductList)')
    $baseline=New-EffectivePolicySyntheticPayload -Policy (Get-EffectivePolicyPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)) -Scenario Workgroup
    $json=($baseline|ConvertTo-Json -Depth 12 -Compress).Replace("'","''")
    $adapted='function Get-LiveEffectivePolicyResult { param($AssessmentUserSid) $result=ConvertFrom-Json -AsHashtable -InputObject '''+$json+''';' + "`n" +
        '$result.sourceLocale=[Threading.Thread]::CurrentThread.CurrentCulture.Name; $result.defenderRuntime=@{runningMode=$null;antivirusEnabled=$null;realTimeProtectionEnabled=$null;tamperProtected=$null}; $result.defenderAsrRules=@(); $result.defenderNetworkProtection.value=$null; $result.scopeStates=@(foreach($id in Get-EffectivePolicyScopeIds){$result.scopeStates|Where-Object scopeId -eq $id}); $empty=New-EffectivePolicyBaseResult Failed; $result.firewallProfiles=$empty.firewallProfiles; $result.smartScreenSignals=$empty.smartScreenSignals;' + "`n" + $blocks + "`n" + 'Complete-EffectivePolicyLayerStates $result }'
    $source=$source.Replace($live.Extent.Text,$adapted)
    $source=$source.Replace('New-SyntheticEffectivePolicyResult -Scenario ([string]$configuration.effectivePolicyScenario)','Get-LiveEffectivePolicyResult -AssessmentUserSid $assessmentUserSid')
    $source=$source.Replace('Microsoft.PowerShell.Core\Import-Module -Name $path','Import-ControlledSecurityModule -Name $path')
    $prefix=@"
`$culture=if('__CASE__' -in @('es-MX','tr-TR','ja-JP','ar-SA')){'__CASE__'}else{'en-US'}
[Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo(`$culture)
[Threading.Thread]::CurrentThread.CurrentUICulture=[Globalization.CultureInfo]::GetCultureInfo(`$culture)
function Import-ControlledSecurityModule {
    param(`$Name, [switch]`$PassThru, `$Scope, `$ErrorAction)
    if('__CASE__' -eq 'Unsupported'){throw 'Synthetic inbox module unavailable.'}
    if(`$Name -notmatch 'WindowsPowerShell[\\/]v1.0[\\/]Modules[\\/](Defender[\\/]Defender|NetSecurity[\\/]NetSecurity)\.psd1$' -or -not `$PassThru -or `$Scope -ne 'Local'){throw 'Unexpected module source.'}
    `$commands=@{}
    foreach(`$operation in @('Get-MpPreference','Get-MpComputerStatus','Get-NetFirewallProfile')){`$commands[`$operation]=Microsoft.PowerShell.Core\Get-Command -Name ('Get-Controlled'+`$operation.Substring(4)) -CommandType Function}
    [pscustomobject]@{ExportedCommands=`$commands}
}
function Get-Command {
    param(`$Name,`$CommandType,`$ErrorAction)
    if(`$Name -in @('Get-MpPreference','Get-MpComputerStatus','Get-NetFirewallProfile')){
        if('Function' -notin @(`$CommandType) -or '__CASE__' -eq 'Unsupported'){return `$null}
        return Microsoft.PowerShell.Core\Get-Command -Name ('Get-Controlled'+`$Name.Substring(4)) -CommandType Function
    }
    Microsoft.PowerShell.Core\Get-Command @PSBoundParameters
}
function Get-ControlledMpPreference {
    param(`$ErrorAction)
    if('__CASE__' -eq 'Denied'){throw [UnauthorizedAccessException]::new('Synthetic source denied.')}
    if('__CASE__' -eq 'Unavailable'){return}
    if('__CASE__' -eq 'AsrEmpty'){return [pscustomobject]@{AttackSurfaceReductionRules_Ids=`$null;AttackSurfaceReductionRules_Actions=`$null;EnableNetworkProtection=[byte]2}}
    `$preferences=[pscustomobject]@{AttackSurfaceReductionRules_Ids=@('d4f940ab-401b-4efc-aadc-ad5f3c50688a');AttackSurfaceReductionRules_Actions=@([byte]1);EnableNetworkProtection=[byte]2}
    if('__CASE__' -eq 'AsrBound'){
        `$preferences.AttackSurfaceReductionRules_Ids=@(1..17|ForEach-Object {'00000000-0000-0000-0000-'+`$_.ToString('D12',[Globalization.CultureInfo]::InvariantCulture)})
        `$preferences.AttackSurfaceReductionRules_Actions=@(1..17|ForEach-Object {[byte]1})
    }
    if('__CASE__' -eq 'AsrMismatch'){`$preferences.AttackSurfaceReductionRules_Ids+=,'00000000-0000-0000-0000-000000000001'}
    if('__CASE__' -eq 'NetworkMissing'){`$preferences.PSObject.Properties.Remove('EnableNetworkProtection')}
    `$preferences
}
function Get-ControlledMpComputerStatus {
    param(`$ErrorAction)
    if('__CASE__' -eq 'Denied'){throw [UnauthorizedAccessException]::new('Synthetic source denied.')}
    if('__CASE__' -eq 'Unavailable'){return}
    if('__CASE__' -eq 'Passive'){return [pscustomobject]@{AMRunningMode='Passive Mode';AntivirusEnabled=`$false;RealTimeProtectionEnabled=`$false;IsTamperProtected=`$false}}
    [pscustomobject]@{AMRunningMode='Normal';AntivirusEnabled=`$true;RealTimeProtectionEnabled=`$(if('__CASE__' -eq 'MalformedRuntime'){'true'}else{`$true});IsTamperProtected=`$(if('__CASE__' -eq 'NullRuntime'){`$null}else{`$true})}
}
function Get-ControlledNetFirewallProfile {
    param(`$PolicyStore,`$ErrorAction)
    if(`$PolicyStore -ne 'ActiveStore'){throw 'Unapproved firewall store.'}
    if('__CASE__' -eq 'Denied'){throw [UnauthorizedAccessException]::new('Synthetic source denied.')}
    if('__CASE__' -eq 'Unavailable'){return}
    foreach(`$name in @('Domain','Private','Public')){
        `$profile=[pscustomobject]@{Name=`$name;Enabled=1;DefaultInboundAction=2;DefaultOutboundAction=1}
        if('__CASE__' -eq 'FirewallPartial' -and `$name -eq 'Public'){`$profile.PSObject.Properties.Remove('Enabled')}
        `$profile
    }
}
function Get-ControlledSmartScreenKey {
    if('__CASE__' -eq 'Denied'){throw [UnauthorizedAccessException]::new('Synthetic source denied.')}
    `$key=[pscustomobject]@{}
    `$key|Add-Member ScriptMethod Dispose {}
    `$key|Add-Member ScriptMethod GetValue {param(`$Name,`$Default,`$Options)
        if('__CASE__' -eq 'SmartScreenMissing'){return `$null}
        if('__CASE__' -eq 'SmartScreenMalformed'){return 'enabled'}
        [int]1
    }
    `$key
}
function Get-ControlledSecurityProductList {
    `$list=[pscustomobject]@{Count=1}
    `$list|Add-Member ScriptMethod Initialize {param(`$Kind)}
    `$list|Add-Member ScriptMethod Item {param(`$Index) [pscustomobject]@{ProductName='Synthetic 保護 proveedor'}}
    `$list
}
"@
    $prefix + "`n" + $source
}
function Get-PrivilegedCollectionPlanPolicy {
    $policy=Get-ControlledOriginalSecurityWorkerPolicy
    $source=(Get-PrivilegedCollectionWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $policy.worker.payloadSha256=Get-PrivilegedCollectionPlanSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($source))
    $policy
}
'@.Replace('__CASE__',$Scenario)
}

function Assert-SecuritySourceReport {
    param($Record,[string]$Html,[string]$Scenario)
    foreach($scope in @('defender.runtime','defender.asr','defender.network-protection','firewall.domain-profile','firewall.private-profile','firewall.public-profile','smartscreen.shell','smartscreen.app-install-control')){
        $expected=if($Scenario -eq 'NullRuntime' -and $scope -eq 'defender.runtime'){'Partial'}else{'Complete'}
        if($Scenario -eq 'MalformedRuntime' -and $scope -eq 'defender.runtime'){$expected='Malformed'}
        if($Scenario -eq 'FirewallPartial' -and $scope -eq 'firewall.public-profile'){$expected='Unavailable'}
        if($Scenario -eq 'Unavailable' -and $scope -notlike 'smartscreen.*'){$expected='Unavailable'}
        if($Scenario -eq 'Unsupported' -and $scope -notlike 'smartscreen.*'){$expected='Unsupported'}
        if($Scenario -eq 'Denied'){$expected='Denied'}
        if($Scenario -in @('AsrBound','AsrMismatch') -and $scope -eq 'defender.asr'){$expected='Partial'}
        if($Scenario -eq 'NetworkMissing' -and $scope -eq 'defender.network-protection'){$expected='Partial'}
        if($Scenario -eq 'SmartScreenMissing' -and $scope -like 'smartscreen.*'){$expected='Unavailable'}
        if($Scenario -eq 'SmartScreenMalformed' -and $scope -like 'smartscreen.*'){$expected='Malformed'}
        Assert-Equal $expected @($Record.coverage|Where-Object scopeId -eq "scope:policy.$scope")[0].state 'installed CDXML security sources execute and preserve independent coverage'
    }
    foreach($layer in @('Applied Policy Evidence','Configured Policy Signals','Current Control State')){Assert-Equal $true $Html.Contains($layer) 'protected HTML separates security evidence layers'}
    Assert-Equal 'Synthetic 保護 proveedor' @($Record.observations|Where-Object fieldId -eq 'field:policy.security-provider.name')[0].value 'bounded Unicode provider names survive protected evidence'
    Assert-Equal $true ([Net.WebUtility]::HtmlDecode($Html)).Contains('Synthetic 保護 proveedor') 'bounded Unicode provider names survive protected HTML'
    foreach($title in @('Defender Antivirus and tamper protection','Attack surface reduction','Network protection','SmartScreen','Firewall')){
        Assert-Equal $true $Html.Contains($title) 'every released security family has a readable report section'
    }
    $completeSecurity=$Scenario -in @('Active','Passive','AsrEmpty','es-MX','tr-TR','ja-JP','ar-SA')
    Assert-Equal $(if($completeSecurity){'Informational'}else{'Indeterminate'}) @($Record.findings|Where-Object ruleId -eq 'rule:policy.security-control-coverage/1.0.0')[0].outcome 'a coverage rule never invents a protection or compliance verdict'
    foreach($observation in @($Record.observations|Where-Object fieldId -like 'field:policy.defender.*')){
        $provenance=@($Record.provenance|Where-Object provenanceId -eq $observation.provenanceId)[0]
        $expectedSource=if($observation.fieldId -match '\.(asr\.|network-protection)'){'source:windows.defender.preferences'}else{'source:windows.defender.runtime-status'}
        Assert-Equal $expectedSource $provenance.sourceId 'security observations retain authoritative structured provenance'
        Assert-Equal $true ([bool]$provenance.collectedAt) 'security evidence retains collection time'
        Assert-Equal $(if($Scenario -in @('es-MX','tr-TR','ja-JP','ar-SA')){$Scenario}else{'en-US'}) $provenance.sourceLocale 'source culture cannot change stable security semantics'
    }
    if($Scenario -notin @('MalformedRuntime','Unavailable','Unsupported','Denied')){
        Assert-Equal $(if($Scenario -eq 'Passive'){'Passive Mode'}else{'Normal'}) @($Record.observations|Where-Object fieldId -eq 'field:policy.defender.running-mode')[0].value 'runtime is distinct from preferences'
    }
    if($Scenario -in @('Unavailable','Unsupported','Denied')){
        Assert-Equal 0 @($Record.observations|Where-Object fieldId -like 'field:policy.defender.*').Count 'no returned security data cannot imply a protection state'
        return
    }
    if($Scenario -eq 'NetworkMissing'){
        Assert-Equal 0 @($Record.observations|Where-Object fieldId -eq 'field:policy.defender.network-protection').Count 'a missing preference cannot imply disabled protection'
    }else{Assert-Equal 'AuditMode' @($Record.observations|Where-Object fieldId -eq 'field:policy.defender.network-protection')[0].value 'network protection remains configured audit mode'}
    $asr=@($Record.observations|Where-Object fieldId -eq 'field:policy.defender.asr.action')[0]
    if($Scenario -eq 'AsrEmpty'){
        Assert-Equal 'ObservedAbsent' $asr.valueState 'a successful empty preference array proves configured ASR absence only'
    }else{Assert-Equal 'Block' $asr.value 'ASR typed action survives package reopening'}
    if($Scenario -eq 'AsrBound'){
        Assert-Equal 16 @($Record.observations|Where-Object fieldId -eq 'field:policy.defender.asr.rule-id').Count 'the declared ASR bound is explicit and never silently raised'
        Assert-Equal $true $Html.Contains('POLICY.DEFENDER_ASR_EVIDENCE_BOUND_EXCEEDED') 'the report discloses the ASR evidence bound'
    }
    if($Scenario -in @('NullRuntime','MalformedRuntime')){
        Assert-Equal 0 @($Record.observations|Where-Object fieldId -eq 'field:policy.defender.tamper-protected').Count 'unknown tamper protection cannot become false or enabled'
    }else{
        Assert-Equal ($Scenario -ne 'Passive') @($Record.observations|Where-Object fieldId -eq 'field:policy.defender.tamper-protected')[0].value 'tamper constraint survives into evidence'
    }
    if($Scenario -eq 'Passive'){
        Assert-Equal 'ExpectedCondition' @($Record.findings|Where-Object ruleId -eq 'rule:policy.security-control-constraint/1.0.0')[0].outcome 'documented Passive Mode is explained as a constraint without a compliance claim'
    }
}
