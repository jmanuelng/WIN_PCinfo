Set-StrictMode -Version Latest

# Execute release source blocks in the authenticated worker. Replace only OS
# boundaries; the generated scheduler, validator, rules and protected package run.
function Add-ControlledRemoteSources {
    param([string]$ModuleText,[string]$Scenario)
    if($Scenario -in @('Windows10','UnknownContext')){
        . (Join-Path $PSScriptRoot 'ReadinessSourceAdapters.ps1')
        $ModuleText=Add-ControlledReadinessSources -ModuleText $ModuleText -Scenario Complete
        # Reuse only the device OS boundary, leaving the remote worker's source
        # intact. The readiness adapter otherwise removes unrelated live blocks.
        $tokens=$null;$errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseInput($ModuleText,[ref]$tokens,[ref]$errors)
        foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Get-PrivilegedCollectionWorkerSource','Get-PrivilegedCollectionPlanPolicy')},$false)){$ModuleText=$ModuleText.Replace($node.Extent.Text,'')}
        $ModuleText=$ModuleText.Replace('Get-ControlledOriginalPrivilegeWorkerSource','Get-PrivilegedCollectionWorkerSource').Replace('Get-ControlledOriginalPrivilegePolicy','Get-PrivilegedCollectionPlanPolicy')
        $ModuleText=$ModuleText.Replace('    $original = [Text.Encoding]::UTF8.GetString((Get-ControlledOriginalCollectorScriptBytes))',
            '    $prefix=$prefix.Replace("else{''26100''}","else{'''+$(if($Scenario -eq 'Windows10'){'19045'}else{'99999'})+'''}");'+"`n"+'    $original = [Text.Encoding]::UTF8.GetString((Get-ControlledOriginalCollectorScriptBytes))')
    }
    $ModuleText=$ModuleText.Replace('function Get-PrivilegedCollectionWorkerSource {','function Get-ControlledRemoteWorkerSource {')
    $ModuleText=$ModuleText.Replace('function Get-PrivilegedCollectionPlanPolicy {','function Get-ControlledRemoteWorkerPolicy {')
    $ModuleText=$ModuleText.Replace('$effectivePolicyPayload=if($validationFixture){','$effectivePolicyPayload=if($false){')
    $ModuleText=$ModuleText.Replace('$state = if ($failureStage -eq ''ELEVATION_DENIED'')', '$script:StatusDeskTransport.State.RemoteSourceFailure=$_.Exception.Message; $state = if ($failureStage -eq ''ELEVATION_DENIED'')')
    $ModuleText + @'
function Get-PrivilegedCollectionWorkerSource {
    $source=(Get-ControlledRemoteWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
    $live=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-LiveEffectivePolicyResult'},$false)
    $start=$live.Extent.Text.IndexOf('    foreach($definition in @('+"`n"+'        [ordered]@{signalIndex=0;scopeIndex=15;')
    $end=$live.Extent.Text.IndexOf('    $preferenceCommand=')
    $remoteStart=$live.Extent.Text.IndexOf('    # Remote-management settings')
    $remoteEnd=$live.Extent.Text.IndexOf('    # Platform protection sources')
    if($start -lt 0 -or $end -le $start -or $remoteEnd -le $remoteStart){throw 'Remote source boundary changed; refuse live fallback.'}
    $blocks=$live.Extent.Text.Substring($start,$end-$start)+$live.Extent.Text.Substring($remoteStart,$remoteEnd-$remoteStart)
    $blocks=$blocks.Replace('[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(', '(Open-ControlledRemoteKey ')
    $blocks=$blocks.Replace(',$false)', ' $false)')
    $blocks=$blocks.Replace('Open-ControlledRemoteKey [string]$definition.path','Open-ControlledRemoteKey ([string]$definition.path)')
    $baseline=New-EffectivePolicySyntheticPayload -Policy (Get-EffectivePolicyPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)) -Scenario Workgroup
    $json=($baseline|ConvertTo-Json -Depth 12 -Compress).Replace("'","''")
    $adapted='function Get-LiveEffectivePolicyResult { param($AssessmentUserSid) $result=ConvertFrom-Json -AsHashtable -InputObject '''+$json+''';' + "`n" +
        '$result.scopeStates=@(foreach($id in Get-EffectivePolicyScopeIds){$result.scopeStates|Where-Object scopeId -eq $id}); $empty=New-EffectivePolicyBaseResult Failed; foreach($name in @(''windowsUpdateSignals'',''legacyAuthenticationSignals'',''rdpState'',''winrmState'',''smbState'')){$result[$name]=$empty[$name]}; Set-EffectivePolicyScopeState $result @(15,16,17,18,19,30,31,32,33,34,35,36,37,38,39,40) Failed ''POLICY.SOURCE_NOT_EXECUTED'';' + "`n" + $blocks + "`n" + 'Complete-EffectivePolicyLayerStates $result }'
    $source=$source.Replace($live.Extent.Text,$adapted)
    $source=$source.Replace('New-SyntheticEffectivePolicyResult -Scenario ([string]$configuration.effectivePolicyScenario)','Get-LiveEffectivePolicyResult -AssessmentUserSid $assessmentUserSid')
    $source=$source.Replace('Microsoft.PowerShell.Core\Import-Module -Name $path','Import-ControlledRemoteModule -Name $path')
    $prefix=@"
[Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo(`$(if('__CASE__' -eq 'tr-TR'){'tr-TR'}else{'en-US'}))
function Assert-ControlledRemoteAvailability {
    if('__CASE__' -eq 'Denied'){throw [UnauthorizedAccessException]::new()}
    if('__CASE__' -eq 'Unsupported'){throw [PlatformNotSupportedException]::new()}
    if('__CASE__' -eq 'Unavailable'){throw [IO.EndOfStreamException]::new()}
}
function Import-ControlledRemoteModule {
    param(`$Name,[switch]`$PassThru,`$Scope,`$ErrorAction,[switch]`$SkipEditionCheck)
    Assert-ControlledRemoteAvailability
    if(`$Name -notmatch 'Modules[\\/](SmbShare[\\/]SmbShare|Dism[\\/]Dism).psd1$' -or -not `$SkipEditionCheck){throw 'Unapproved native module import.'}
    `$commands=@{}
    foreach(`$name in @('SmbClientConfiguration','SmbServerConfiguration','WindowsOptionalFeature')){`$commands['Get-'+`$name]=Microsoft.PowerShell.Core\Get-Command ('Get-Controlled'+`$name)}
    [pscustomobject]@{ExportedCommands=`$commands}
}
function Get-Command {
    param(`$Name,`$CommandType,`$ErrorAction)
    if(`$Name -in @('Get-SmbClientConfiguration','Get-SmbServerConfiguration')){return `$null}
    if(`$Name -eq 'Get-WindowsOptionalFeature'){return Microsoft.PowerShell.Core\Get-Command Get-ControlledWindowsOptionalFeature}
    Microsoft.PowerShell.Core\Get-Command @PSBoundParameters
}
function Open-ControlledRemoteKey {
    param(`$Path,`$Writable)
    Assert-ControlledRemoteAvailability
    if(`$Writable -or `$Path -notin @('SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate','SOFTWARE\Policies\Microsoft\Windows\WinRM\Service','SYSTEM\CurrentControlSet\Control\Lsa','SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0','SYSTEM\CurrentControlSet\Control\Terminal Server','SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp')){throw 'Unapproved registry access.'}
    `$key=[pscustomobject]@{}
    `$key|Add-Member ScriptMethod Dispose {}
    `$key|Add-Member ScriptMethod GetValue {param(`$Name,`$Default,`$Options)
        if('__CASE__' -eq 'Absent'){return `$null}
        if('__CASE__' -eq 'Malformed'){return '1'}
        switch(`$Name){
            DeferFeatureUpdatesPeriodInDays {[int]14}
            DeferQualityUpdatesPeriodInDays {[int]3}
            DisableDualScan {[int]1}
            LmCompatibilityLevel {[int]5}
            NtlmMinClientSec {[int]537395232}
            NtlmMinServerSec {if('__CASE__' -eq 'Partial'){throw [UnauthorizedAccessException]::new()};[int]537395200}
            fDenyTSConnections {[int]0}
            fEnableWinStation {[int]1}
            AllowUnencryptedTraffic {[int]0}
            AllowBasic {[int]0}
            AllowKerberos {[int]1}
            AllowNegotiate {[int]1}
            AllowCredSSP {if('__CASE__' -eq 'Partial'){return `$null};[int]0}
            default {throw 'Unapproved registry value.'}
        }
    }
    `$key
}
function Get-CimInstance {
    param(`$ClassName,`$Filter,`$Property,`$Namespace,`$ErrorAction)
    Assert-ControlledRemoteAvailability
    if('__CASE__' -eq 'Absent'){return}
    if(`$ClassName -eq 'Win32_Service'){
        if(`$Filter -notin @("Name='TermService'","Name='WinRM'")){throw 'Unapproved service.'}
        return [pscustomobject]@{StartMode='Auto';State=`$(if('__CASE__' -eq 'Stopped'){'Stopped'}elseif('__CASE__' -eq 'Malformed'){'bogus'}else{'Running'})}
    }
    if(`$ClassName -ne 'Win32_TSGeneralSetting' -or `$Namespace -ne 'Root\Cimv2\TerminalServices'){throw 'Unapproved WMI source.'}
    [pscustomobject]@{TerminalName='RDP-Tcp';UserAuthenticationRequired=[uint32]1;SecurityLayer=`$(if('__CASE__' -eq 'Malformed'){'2'}else{[uint32]2});MinEncryptionLevel=[uint32]3}
}
function Get-ChildItem {
    param(`$Path,`$ErrorAction)
    throw 'WSMan provider requests are prohibited, including localhost.'
}
function Get-ControlledSmbClientConfiguration {
    param(`$ErrorAction)
    Assert-ControlledRemoteAvailability
    if('__CASE__' -eq 'Absent'){return}
    `$item=[pscustomobject]@{RequireSecuritySignature=`$true;EnableSecuritySignature=`$true;EnableInsecureGuestLogons=`$false}
    if('__CASE__' -eq 'Partial'){`$item.PSObject.Properties.Remove('EnableInsecureGuestLogons')}
    if('__CASE__' -eq 'Malformed'){`$item.RequireSecuritySignature='true'}
    `$item
}
function Get-ControlledSmbServerConfiguration {
    param(`$ErrorAction)
    Assert-ControlledRemoteAvailability
    if('__CASE__' -eq 'Absent'){return}
    [pscustomobject]@{RequireSecuritySignature=`$true;EnableSecuritySignature=`$true;EncryptData=`$true;RejectUnencryptedAccess=`$true;EnableSMB1Protocol=`$false}
}
function Get-ControlledWindowsOptionalFeature {
    param([switch]`$Online,`$FeatureName,`$ErrorAction)
    Assert-ControlledRemoteAvailability
    if(-not `$Online -or `$FeatureName -ne 'SMB1Protocol'){throw 'Unapproved DISM operation.'}
    if('__CASE__' -eq 'Absent'){return}
    [pscustomobject]@{State=`$(if('__CASE__' -eq 'Malformed'){'bogus'}else{'Disabled'})}
}
"@
    $prefix + "`n" + $source
}
function Get-PrivilegedCollectionPlanPolicy {
    $policy=Get-ControlledRemoteWorkerPolicy
    $source=(Get-PrivilegedCollectionWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $policy.worker.payloadSha256=Get-PrivilegedCollectionPlanSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($source))
    $policy
}
'@.Replace('__CASE__',$Scenario)
}

function Assert-RemoteSourceReport {
    param($Record,[string]$Html,[string]$Scenario)
    $scopes=@('windows-update.defer-feature-updates','windows-update.defer-quality-updates','windows-update.disable-dual-scan','legacy-auth.lm-compatibility-level','legacy-auth.ntlm-minimum-session-security','rdp.connections','rdp.service','rdp.authentication','rdp.listener','winrm.service','winrm.configuration','winrm.authentication','winrm.listener','smb.client','smb.server','smb.smb1-feature')
    foreach($scope in $scopes){
        $expected='Complete'
        if($Scenario -in @('Denied','Unsupported')){$expected=$Scenario}
        if($Scenario -eq 'Unavailable'){$expected='Unavailable'}
        if($Scenario -eq 'Absent' -and $scope -notmatch '^(windows-update|legacy-auth)\.'){ $expected='Unavailable' }
        if($Scenario -eq 'Malformed' -and $scope -notin @('winrm.listener','smb.server','rdp.listener')){$expected='Malformed'}
        if($Scenario -eq 'Malformed' -and $scope -eq 'rdp.listener'){$expected='Malformed'}
        if($Scenario -eq 'Partial' -and $scope -in @('legacy-auth.ntlm-minimum-session-security','winrm.authentication','smb.client')){$expected='Partial'}
        if($scope -eq 'winrm.authentication' -and $expected -eq 'Complete'){$expected='Partial'}
        if($scope -eq 'winrm.listener'){$expected='Constrained'}
        Assert-Equal $expected @($Record.coverage|Where-Object scopeId -eq "scope:policy.$scope")[0].state "source disposition for $scope"
    }
    if($Scenario -eq 'Absent'){
        foreach($family in @('windows-update','legacy-auth')){
            $observations=@($Record.observations|Where-Object fieldId -like "field:policy.$family.*")
            Assert-Equal 3 $observations.Count 'successful registry absence remains explicit'
            Assert-Equal 0 @($observations|Where-Object valueState -ne ObservedAbsent).Count 'absent configuration cannot become disabled or zero'
        }
    }
    if($Scenario -in @('Configured','tr-TR')){
        Assert-Equal $true @($Record.observations|Where-Object fieldId -eq 'field:policy.smb.client-require-signing')[0].value 'SMB configuration survives protected reopening'
        Assert-Equal 14 @($Record.observations|Where-Object fieldId -eq 'field:policy.windows-update.defer-feature-updates-days')[0].value 'WUfB configured period survives protected reopening'
        Assert-Equal 537395232 @($Record.observations|Where-Object fieldId -eq 'field:policy.legacy-auth.ntlm-min-client-sec')[0].value 'NTLM masks retain exact configuration values'
        Assert-Equal 0 @($Record.observations|Where-Object fieldId -like 'field:policy.winrm.listener-*').Count 'no request is made to infer listener or reachability'
    }
    foreach($title in @('Windows Update and WUfB','RDP connection configuration','WinRM policy signals','SMB client configuration','Legacy authentication')){
        Assert-Equal $true $Html.Contains($title) 'each assigned family has readable source-backed HTML'
    }
    Assert-Equal $true $Html.Contains('update-remote-auth/1.0.0') 'guidance is versioned'
    if($Scenario -eq 'Windows10'){Assert-Equal $true $Html.Contains('Windows 10 guidance:') 'Windows 10 context selects its own conservative guidance'}
    if($Scenario -eq 'UnknownContext'){Assert-Equal $true $Html.Contains('Windows applicability is unknown') 'unknown Windows context cannot inherit a supported interpretation'}
    if($Scenario -eq 'Configured'){Assert-Equal $true $Html.Contains('Windows 11 guidance:') 'Windows 11 retained dual-scan configuration cannot imply supported scan behavior'}
    foreach($observation in @($Record.observations|Where-Object { $_.fieldId -match '^field:policy\.(windows-update|legacy-auth|rdp|winrm|smb)\.' })){
        $origin=@($Record.provenance|Where-Object provenanceId -eq $observation.provenanceId)[0]
        $expected=switch -Regex ($observation.fieldId){
            '\.windows-update\.' {'source:windows.update-policy-registry'}
            '\.legacy-auth\.' {'source:windows.legacy-authentication-registry'}
            '\.rdp\.' {'source:windows.rdp.configuration'}
            '\.winrm\.' {'source:windows.winrm.configuration'}
            '\.smb\.' {'source:windows.smb.configuration'}
        }
        Assert-Equal $expected $origin.sourceId 'each field keeps its declared structured source'
        Assert-Equal $true ([bool]$origin.collectedAt) 'collection time survives protected reopening'
        Assert-Equal $true $Html.Contains($observation.observationId) 'report retains resolvable source evidence references'
    }
    Assert-Equal 'Indeterminate' @($Record.findings|Where-Object ruleId -eq 'rule:policy.security-control-coverage/1.0.0')[0].outcome 'unimplemented listener/certificate sources prevent a completeness claim'
    Assert-Equal 0 @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.auth-certificate').Count 'unimplemented certificate authentication never becomes false'
    if($Scenario -eq 'Stopped'){
        Assert-Equal 'Stopped' @($Record.observations|Where-Object fieldId -eq 'field:policy.rdp.service-state')[0].value 'configured RDP can coexist with an observed stopped service'
        Assert-Equal $true @($Record.observations|Where-Object fieldId -eq 'field:policy.rdp.connections-allowed')[0].value 'service state cannot overwrite the separate configured signal'
    }
    if($Scenario -eq 'Partial'){
        Assert-Equal 2 @($Record.observations|Where-Object fieldId -like 'field:policy.smb.client-*').Count 'partial SMB fields stay useful without inventing the missing guest setting'
    }
    if($Scenario -in @('Configured','Stopped','Windows10','UnknownContext')){
        Assert-Equal 4 @($Record.observations|Where-Object fieldId -like 'field:policy.winrm.auth-*').Count 'four policy-backed auth values remain separate from unimplemented certificate authentication'
    }
}
