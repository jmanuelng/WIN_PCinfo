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
    $blocks=[regex]::Replace($blocks,'(\(Open-ControlledRemoteKey [^\r\n]*?),\$false\)', '$1 $$false)')
    $blocks=$blocks.Replace('Open-ControlledRemoteKey [string]$definition.path','Open-ControlledRemoteKey ([string]$definition.path)')
    $baseline=New-EffectivePolicySyntheticPayload -Policy (Get-EffectivePolicyPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)) -Scenario Workgroup
    $json=($baseline|ConvertTo-Json -Depth 12 -Compress).Replace("'","''")
    $adapted='function Get-LiveEffectivePolicyResult { param($AssessmentUserSid) $result=ConvertFrom-Json -AsHashtable -InputObject '''+$json+''';' + "`n" +
        '$result.scopeStates=@(foreach($id in Get-EffectivePolicyScopeIds){$result.scopeStates|Where-Object scopeId -eq $id}); $empty=New-EffectivePolicyBaseResult Failed; foreach($name in @(''windowsUpdateSignals'',''legacyAuthenticationSignals'',''rdpState'',''winrmState'',''smbState'')){$result[$name]=$empty[$name]}; Set-EffectivePolicyScopeState $result @(15,16,17,18,19,30,31,32,33,34,35,36,37,38,39,40) Failed ''POLICY.SOURCE_NOT_EXECUTED'';' + "`n" + $blocks + "`n" + 'if($script:ControlledUnsafeRead){throw ''Unbounded DWORD read.''}; if($script:ControlledUnsafeEnumeration){throw ''Unbounded listener enumeration during concurrent growth.''}; Complete-EffectivePolicyLayerStates $result }'
    $source=$source.Replace($live.Extent.Text,$adapted)
    $source=$source.Replace('Complete-EffectivePolicyLayerStates $result }',
        'if(''__CASE__'' -in @(''ListenerGrowth'',''ListenerLimit'') -and $script:ControlledEnumerationCalls -ne 33){throw ''The exact listener limit must execute one overflow probe.''}; Complete-EffectivePolicyLayerStates $result }')
    $source=$source.Replace('[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)', '(Open-ControlledRemoteBaseKey)')
    $nativeCalls=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -eq 'RegGetValue' -and $node.Expression.Extent.Text -eq '[WinPCInfoEffectivePolicyNativeSource]'},$true))
    if($nativeCalls.Count -ne 1){throw 'Typed registry boundary changed; refuse live fallback.'}
    $nativeCall=$nativeCalls[0]
    $arguments=@($nativeCall.Arguments|ForEach-Object {'('+$_.Extent.Text+')'}) -join ' '
    $source=$source.Replace($nativeCall.Extent.Text,'(Read-ControlledWinrmValue '+$arguments+')')
    $enumCalls=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -eq 'RegEnumKeyEx' -and $node.Expression.Extent.Text -eq '[WinPCInfoEffectivePolicyNativeSource]'},$true))
    if($enumCalls.Count -ne 1){throw 'Bounded enumeration boundary changed; refuse live fallback.'}
    $enumCall=$enumCalls[0]
    $arguments=@($enumCall.Arguments|ForEach-Object {'('+$_.Extent.Text+')'}) -join ' '
    $source=$source.Replace($enumCall.Extent.Text,'(Read-ControlledListenerName '+$arguments+')')
    $source=$source.Replace('New-SyntheticEffectivePolicyResult -Scenario ([string]$configuration.effectivePolicyScenario)','Get-LiveEffectivePolicyResult -AssessmentUserSid $assessmentUserSid')
    $source=$source.Replace('Microsoft.PowerShell.Core\Import-Module -Name $path','Import-ControlledRemoteModule -Name $path')
    $prefix=@"
`$script:ControlledUnsafeRead=`$false
`$script:ControlledBoundedRead=`$false
`$script:ControlledUnsafeEnumeration=`$false
`$script:ControlledEnumerationCalls=0
`$script:ControlledEnumerationBuffer=`$null
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
    if(`$Writable -or `$Path -notin @('SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate','SOFTWARE\Policies\Microsoft\Windows\WinRM\Service','SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service','SYSTEM\CurrentControlSet\Control\Lsa','SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0','SYSTEM\CurrentControlSet\Control\Terminal Server','SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp')){throw 'Unapproved registry access.'}
    `$key=[pscustomobject]@{}
    `$key|Add-Member ScriptMethod Dispose {}
    `$key|Add-Member ScriptMethod GetValueKind {param(`$Name) if(`$Name -ne 'auth_certificate'){throw 'Unapproved typed value.'}; if('__CASE__' -eq 'CertificateKind'){return [Microsoft.Win32.RegistryValueKind]::QWord}; [Microsoft.Win32.RegistryValueKind]::DWord}
    `$key|Add-Member ScriptMethod GetValue {param(`$Name,`$Default,`$Options)
        if('__CASE__' -eq 'DwordBound' -and `$Name -eq 'auth_certificate' -and -not `$script:ControlledBoundedRead){`$script:ControlledUnsafeRead=`$true}
        if('__CASE__' -eq 'RegistryDenied'){throw [UnauthorizedAccessException]::new()}
        if('__CASE__' -eq 'Absent'){return `$null}
        if('__CASE__' -eq 'Malformed'){return '1'}
        switch(`$Name){
            auth_certificate {
                if('__CASE__' -eq 'BooleanRange'){return [int]2}
                if('__CASE__' -eq 'CertificateAbsent'){return `$null}
                if('__CASE__' -eq 'CertificateDenied'){throw [UnauthorizedAccessException]::new()}
                if('__CASE__' -eq 'CertificateFalse'){return [int]0}
                [int]1
            }
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
function Open-ControlledRemoteBaseKey {
    Assert-ControlledRemoteAvailability
    `$key=[pscustomobject]@{}
    `$key|Add-Member ScriptMethod Dispose {}
    `$key|Add-Member ScriptMethod OpenSubKey {param(`$Path,`$Writable)
        if(`$Path -eq 'SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener'){
            if(`$Writable){throw 'Writable listener access.'}
            New-ControlledListenerKey
        }else{Open-ControlledRemoteKey `$Path `$Writable}
    }
    `$key
}
function New-ControlledListenerKey {
    if('__CASE__' -eq 'RegistryDenied'){throw [UnauthorizedAccessException]::new()}
    if('__CASE__' -eq 'Absent'){return `$null}
    `$key=[pscustomobject]@{SubKeyCount=`$(if('__CASE__' -eq 'ListenerBound'){33}else{1});Handle=[IntPtr]::new(145)}
    `$key|Add-Member ScriptMethod Dispose {}
    `$key|Add-Member ScriptMethod GetSubKeyNames {
        switch('__CASE__'){
            ListenerGrowth {`$script:ControlledUnsafeEnumeration=`$true;throw 'The source grew after the count check; bulk enumeration has no bound.'}
            ListenerBound {throw 'Enumeration must not run above bound.'}
            ListenerEmpty {return}
            ListenerUnknown {return '*+UNKNOWN'}
            ListenerHttps {return '*+HTTPS'}
            ListenerMultiple {return @('*+HTTP','*+HTTPS')}
            default {return '*+HTTP'}
        }
    }
    `$key|Add-Member ScriptMethod OpenSubKey {param(`$Name,`$Writable)
        if(`$Writable -or (`$Name -notin @('*+HTTP','*+HTTPS') -and `$Name -notmatch '^synthetic-([0-9]|[12][0-9]|3[01])\+HTTP$')){throw 'Unapproved listener selector.'}
        `$child=[pscustomobject]@{Selector=`$Name}
        `$child|Add-Member ScriptMethod Dispose {}
        `$child|Add-Member ScriptMethod GetValueKind {param(`$Name) if(`$Name -notin @('Port','enabled')){throw 'Unapproved listener kind.'};[Microsoft.Win32.RegistryValueKind]::DWord}
        `$child|Add-Member ScriptMethod GetValue {param(`$Name,`$Default,`$Options)
            if('__CASE__' -eq 'DwordBound' -and -not `$script:ControlledBoundedRead){`$script:ControlledUnsafeRead=`$true}
            if('__CASE__' -eq 'Malformed'){return '1'}
            if('__CASE__' -eq 'ListenerMissing'){return `$null}
            switch(`$Name){
                Port {if('__CASE__' -eq 'ListenerBadPort'){return [int]65536};if(`$this.Selector -eq '*+HTTPS'){return [int]5986};[int]47099}
                enabled {if('__CASE__' -eq 'BooleanRange'){return [int]2};if('__CASE__' -eq 'ListenerDisabled' -or ('__CASE__' -eq 'ListenerMultiple' -and `$this.Selector -eq '*+HTTPS')){return [int]0};[int]1}
                default {throw 'Prohibited listener property.'}
            }
        }
        `$child
    }
    `$key
}
function Read-ControlledListenerName {
    param(`$Handle,`$Index,`$Buffer,`$Length,`$Reserved,`$Class,`$ClassLength,`$LastWriteTime)
    # Keep the actual caller's buffer and arguments. A growth source can supply
    # arbitrarily many records, but may never induce bulk allocation or a retry.
    if(`$Handle.ToInt64() -ne 145 -or `$Index -ne `$script:ControlledEnumerationCalls -or
        `$Index -gt 32 -or `$Buffer -isnot [char[]] -or `$Buffer.Length -ne 256 -or `$Length.Value -ne 256 -or
        `$Reserved -ne [IntPtr]::Zero -or `$Class -ne [IntPtr]::Zero -or `$ClassLength -ne [IntPtr]::Zero -or `$LastWriteTime -ne [IntPtr]::Zero -or
        (`$null -ne `$script:ControlledEnumerationBuffer -and -not [object]::ReferenceEquals(`$Buffer,`$script:ControlledEnumerationBuffer))){
        `$script:ControlledUnsafeEnumeration=`$true;throw 'Enumeration exceeded its native safety boundary.'
    }
    `$script:ControlledEnumerationBuffer=`$Buffer
    `$script:ControlledEnumerationCalls++
    if('__CASE__' -eq 'ListenerBound'){`$script:ControlledUnsafeEnumeration=`$true;throw 'Enumeration ran despite known overflow.'}
    switch('__CASE__'){
        ListenerEnumDenied {return 5}
        ListenerEnumAbsent {return 2}
        ListenerNameOversize {`$Length.Value=[uint32]1048576;return 234}
        ListenerNameBadLength {`$Length.Value=[uint32]256;return 0}
    }
    if('__CASE__' -in @('ListenerGrowth','ListenerLimit')){
        # Initial SubKeyCount is 1; growth never ends. No large fixture array.
        if('__CASE__' -eq 'ListenerLimit' -and `$Index -eq 32){return 259}
        `$name='synthetic-'+`$Index+'+HTTP'
    }else{
        `$names=@((New-ControlledListenerKey).GetSubKeyNames())
        if(`$Index -ge `$names.Count){return 259}
        `$name=`$names[`$Index]
    }
    `$name.CopyTo(0,`$Buffer,0,`$name.Length);`$Length.Value=[uint32]`$name.Length
    return 0
}
function Read-ControlledWinrmValue {
    param(`$Hive,`$Path,`$Name,`$Flags,`$Type,`$Data,`$Size)
    if(`$Hive.ToInt64() -ne -2147483646 -or `$Flags -ne 0x20010010 -or `$Size.Value -ne 4){throw 'Unbounded or incorrectly typed registry call.'}
    Assert-ControlledRemoteAvailability
    if('__CASE__' -eq 'DwordOversize'){`$Size.Value=[uint32]1048576;return 234}
    `$key=`$null;`$root=`$null
    try {
        if(`$Path -eq 'SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service' -and `$Name -eq 'auth_certificate'){
            `$key=Open-ControlledRemoteKey `$Path `$false
        }elseif(`$Path -match '^SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Listener\\((?:\*|synthetic-(?:[0-9]|[12][0-9]|3[01]))\+HTTPS?)$' -and `$Name -in @('Port','enabled')){
            `$root=New-ControlledListenerKey
            if(`$null -eq `$root){return 2}
            `$key=`$root.OpenSubKey(`$Matches[1],`$false)
        }else{throw 'Unapproved typed registry source.'}
        if(`$key.GetValueKind(`$Name) -ne [Microsoft.Win32.RegistryValueKind]::DWord){return 1630}
        `$script:ControlledBoundedRead=`$true
        `$raw=`$key.GetValue(`$Name,`$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if(`$null -eq `$raw){return 2}
        if(`$raw -isnot [int]){return 1630}
        `$Type.Value=[uint32]4;`$Data.Value=[int]`$raw;`$Size.Value=[uint32]4
        return 0
    }catch{
        if((Get-PlatformFailureState `$_) -eq 'Denied'){return 5}
        throw
    }finally{
        `$script:ControlledBoundedRead=`$false
        if(`$null -ne `$key){`$key.Dispose()};if(`$null -ne `$root){`$root.Dispose()}
    }
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
        if($Scenario -eq 'RegistryDenied' -and ($scope -match '^(windows-update|legacy-auth)\.' -or $scope -in @('rdp.connections','rdp.listener','winrm.configuration','winrm.authentication'))){$expected='Denied'}
        if($Scenario -eq 'Absent' -and $scope -notmatch '^(windows-update|legacy-auth)\.'){ $expected='Unavailable' }
        if($Scenario -eq 'Malformed' -and $scope -notin @('winrm.listener','smb.server','rdp.listener')){$expected='Malformed'}
        if($Scenario -eq 'Malformed' -and $scope -eq 'rdp.listener'){$expected='Malformed'}
        if($Scenario -eq 'Partial' -and $scope -in @('legacy-auth.ntlm-minimum-session-security','winrm.authentication','smb.client')){$expected='Partial'}
        if($scope -eq 'winrm.authentication' -and $Scenario -in @('CertificateAbsent','CertificateDenied','CertificateKind','BooleanRange','DwordOversize')){$expected='Partial'}
        if($scope -eq 'winrm.listener'){
            $expected=switch($Scenario){
                {$_ -in @('Absent','ListenerEmpty','ListenerMissing','ListenerEnumAbsent','Unavailable')} {'Unavailable'}
                {$_ -in @('Denied','RegistryDenied','ListenerEnumDenied')} {'Denied'}
                Unsupported {'Unsupported'}
                {$_ -in @('Malformed','ListenerUnknown','ListenerBadPort','ListenerNameOversize','ListenerNameBadLength','BooleanRange','DwordOversize')} {'Malformed'}
                {$_ -in @('ListenerBound','ListenerGrowth')} {'Constrained'}
                default {'Partial'}
            }
        }
        Assert-Equal $expected @($Record.coverage|Where-Object scopeId -eq "scope:policy.$scope")[0].state "source disposition for $scope"
    }
    if($Scenario -eq 'Absent'){
        foreach($family in @('windows-update','legacy-auth')){
            $observations=@($Record.observations|Where-Object fieldId -like "field:policy.$family.*")
            Assert-Equal 3 $observations.Count 'successful registry absence remains explicit'
            Assert-Equal 0 @($observations|Where-Object valueState -ne ObservedAbsent).Count 'absent configuration cannot become disabled or zero'
        }
    }
    if($Scenario -in @('Configured','tr-TR','ListenerLimit')){
        Assert-Equal $true @($Record.observations|Where-Object fieldId -eq 'field:policy.smb.client-require-signing')[0].value 'SMB configuration survives protected reopening'
        Assert-Equal 14 @($Record.observations|Where-Object fieldId -eq 'field:policy.windows-update.defer-feature-updates-days')[0].value 'WUfB configured period survives protected reopening'
        Assert-Equal 537395232 @($Record.observations|Where-Object fieldId -eq 'field:policy.legacy-auth.ntlm-min-client-sec')[0].value 'NTLM masks retain exact configuration values'
        Assert-Equal 'ConfiguredEnabled' @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.listener-state')[0].value 'explicit listener configuration remains distinct from runtime state'
        Assert-Equal 'HTTP' @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.listener-transport')[0].value 'transport comes from the service selector'
        Assert-Equal 47099 @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.listener-port')[0].value 'custom port survives actual-source collection and protected reopening'
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
        $parts = [regex]::Match($Html, 'Prefix: <code>([^<]*)</code>; suffix: <code>([^<]*)</code>')
        $references = @([regex]::Matches($Html, '<tr><td>[^<]*<td>[^<]*<td>([^<]*)<td><a href="#ss\d+">') | ForEach-Object {
            $cell = [Net.WebUtility]::HtmlDecode($_.Groups[1].Value)
            if ($cell.StartsWith('Full: ', [StringComparison]::Ordinal)) { $cell.Substring(6) }
            else { [Net.WebUtility]::HtmlDecode($parts.Groups[1].Value) + $cell + [Net.WebUtility]::HtmlDecode($parts.Groups[2].Value) }
        })
        Assert-Equal $true ($observation.observationId -cin $references) 'report retains resolvable source evidence references'
    }
    Assert-Equal 'Indeterminate' @($Record.findings|Where-Object ruleId -eq 'rule:policy.security-control-coverage/1.0.0')[0].outcome 'local configuration cannot establish complete effective listener coverage'
    if($Scenario -eq 'Configured'){Assert-Equal $true @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.auth-certificate')[0].value 'explicit service certificate authentication survives actual-source collection and protected reopening'}
    if($Scenario -eq 'CertificateFalse'){Assert-Equal $false @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.auth-certificate')[0].value 'explicit zero stays observed false'}
    if($Scenario -in @('CertificateAbsent','CertificateDenied','CertificateKind','Absent','Denied','RegistryDenied','Malformed','BooleanRange','DwordOversize')){Assert-Equal 0 @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.auth-certificate').Count 'missing denied or malformed certificate state never becomes a default'}
    if($Scenario -eq 'ListenerHttps'){
        Assert-Equal 'HTTPS' @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.listener-transport')[0].value 'HTTPS identity survives'
        Assert-Equal 5986 @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.listener-port')[0].value 'explicit HTTPS port survives'
    }
    if($Scenario -eq 'ListenerDisabled'){Assert-Equal 'ConfiguredDisabled' @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.listener-state')[0].value 'disabled is a configured state'}
    if($Scenario -eq 'ListenerMultiple'){
        Assert-Equal 'ConfiguredMixed' @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.listener-state')[0].value 'mixed enabled settings remain explicit'
        Assert-Equal 1 @($Record.observations|Where-Object fieldId -like 'field:policy.winrm.listener-*').Count 'differing transports and ports cannot become a fabricated single endpoint'
    }
    if($Scenario -in @('ListenerEmpty','ListenerMissing','ListenerUnknown','ListenerBadPort','ListenerBound','ListenerGrowth','ListenerEnumAbsent','ListenerEnumDenied','ListenerNameOversize','ListenerNameBadLength','Absent','Denied','RegistryDenied','Malformed','BooleanRange','DwordOversize')){Assert-Equal 0 @($Record.observations|Where-Object fieldId -like 'field:policy.winrm.listener-*').Count 'unusable listener collection cannot donate successful observations'}
    Assert-Equal $true $Html.Contains('policy-created, compatibility and default listeners') 'report explains the explicit source completeness limit'
    if($Scenario -eq 'Stopped'){
        Assert-Equal 'Stopped' @($Record.observations|Where-Object fieldId -eq 'field:policy.rdp.service-state')[0].value 'configured RDP can coexist with an observed stopped service'
        Assert-Equal $true @($Record.observations|Where-Object fieldId -eq 'field:policy.rdp.connections-allowed')[0].value 'service state cannot overwrite the separate configured signal'
        Assert-Equal 'Stopped' @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.service-state')[0].value 'WinRM runtime remains the observed stopped state'
        Assert-Equal 'ConfiguredEnabled' @($Record.observations|Where-Object fieldId -eq 'field:policy.winrm.listener-state')[0].value 'stale or inactive WinRM configuration cannot imply a running listener'
    }
    if($Scenario -eq 'Partial'){
        Assert-Equal 2 @($Record.observations|Where-Object fieldId -like 'field:policy.smb.client-*').Count 'partial SMB fields stay useful without inventing the missing guest setting'
    }
    if($Scenario -in @('Configured','Stopped','Windows10','UnknownContext')){
        Assert-Equal 5 @($Record.observations|Where-Object fieldId -like 'field:policy.winrm.auth-*').Count 'policy and explicit service authentication values survive with source provenance'
    }
}
