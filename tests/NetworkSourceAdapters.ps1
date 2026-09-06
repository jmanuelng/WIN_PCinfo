Set-StrictMode -Version Latest

# Test-only Windows boundaries; execute the generated local source reducer and
# ordinary coordinator/record/package/report. No live source is authorized here.
function Add-ControlledNetworkSources {
    param([string]$ModuleText,[string]$Scenario)
    $ModuleText=$ModuleText.Replace('function Invoke-BoundedNetworkTopologySnapshot {','function Invoke-UnusedNetworkTopologySnapshot {')
    $ModuleText=$ModuleText.Replace('function Get-NetworkTopologyProcessDisposition {','function Get-UnusedNetworkTopologyProcessDisposition {')
    $ModuleText=$ModuleText.Replace('Invoke-ControlledNetworkTopologyCollection -Policy $Policy -ValidationScenario Empty -NetworkBehavior $NetworkBehavior',
        'Invoke-ControlledNetworkTopologyCollection -Policy $Policy -Live -AssessmentUserSid $AssessmentUserSid -NetworkBehavior $NetworkBehavior')
    $ModuleText=$ModuleText.Replace('Invoke-ControlledMicrosoftConnectivityCollection -Policy $Policy -ValidationScenario LocalOnly -NetworkBehavior LocalOnly',
        'Invoke-ControlledMicrosoftConnectivityCollection -Policy $Policy -Live -NetworkBehavior LocalOnly')
    $ModuleText += @'

function Replace-NetworkBoundary {
    param([string]$Text,[string]$Before,[string]$After)
    $first=$Text.IndexOf($Before,[StringComparison]::Ordinal)
    if ($first -lt 0 -or $first -ne $Text.LastIndexOf($Before,[StringComparison]::Ordinal)) {
        throw 'The controlled local network source boundary changed; do not execute it.'
    }
    $Text.Replace($Before,$After)
}
function Get-NetworkTopologyProcessDisposition { param($ProcessSid,$AssessmentUserSid,$IsAdministrator) }
function Invoke-BoundedNetworkTopologySnapshot {
    param($Policy,$AssessmentUserSid)
    $script:StatusDeskTransport.State.NetworkSourceExecuted=$true
    $source=Get-NetworkTopologyLiveSource
    $source=Replace-NetworkBoundary $source ('[Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()') ('(Get-ControlledInterfaces)')
    $source=Replace-NetworkBoundary $source ('$actualSid=[string]$identity.User.Value;') ('$actualSid="synthetic";')
    $source=Replace-NetworkBoundary $source ('$expectedSid=[string]$env:WINPCINFO_NETWORK_ASSESSMENT_SID') ('$expectedSid="synthetic"')
    $source=Replace-NetworkBoundary $source ('$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)') ('$false')
    $source=Replace-NetworkBoundary $source ('$maximum=[int]$env:WINPCINFO_NETWORK_MAXIMUM') ('$maximum=8')
    $source=Replace-NetworkBoundary $source ('[WinPCInfo.NetworkTopology.NetworkProfileReader]::Read($maximum,[ref]$exceeded,[ref]$malformed)') ('(Get-ControlledProfiles)')
    $source=Replace-NetworkBoundary $source ('[WinPCInfo.NetworkTopology.NativeRouteReader]::GetIpForwardTable($maximum,[ref]$exceeded,[ref]$malformed)') ('(Get-ControlledRoutes)')
    $source=Replace-NetworkBoundary $source ("[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Internet Settings',`$false)") ('(Get-ControlledProxy)')
    $source=Replace-NetworkBoundary $source ('[IO.File]::Exists($phonebook)') ('$true')
    $source=Replace-NetworkBoundary $source ('[IO.FileInfo]::new($phonebook)') ('[pscustomobject]@{Length=200}')
    $source=Replace-NetworkBoundary $source ('[IO.File]::ReadLines($phonebook,[Text.Encoding]::UTF8)') ('(Get-ControlledPhonebook)')
    $source=Replace-NetworkBoundary $source ('[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()') ('(Get-ControlledConnections)')
    $source=Replace-NetworkBoundary $source ('[Console]::Out.Write($json)') ('Write-Output $json')
    # Compile the release native types without calling Windows providers. Every
    # native invocation above is replaced; the reducer below is unchanged.
    $source=Replace-NetworkBoundary $source ("`$PSModuleAutoLoadingPreference='None'") ("`$PSModuleAutoLoadingPreference='None'`n" + (Get-ControlledNetworkBoundarySource))
    $started=[DateTimeOffset]::UtcNow
    $json=& ([scriptblock]::Create($source))
    [pscustomobject]@{succeeded=$true;payload=($json|ConvertFrom-Json);startedAt=$started;completedAt=[DateTimeOffset]::UtcNow;reasonCode=''}
}
function Invoke-MicrosoftConnectivityLiveProbe {
    param($Policy)
    $script:StatusDeskTransport.State.NetworkRequestAttempted=$true
    throw 'Local Only reached a network-capable nested adapter.'
}
function Get-ControlledNetworkBoundarySource {
@"
`$script:NetworkCase='__CASE__'
function Get-ControlledInterfaces {
    if (`$script:NetworkCase -eq 'Denied') { throw [UnauthorizedAccessException]::new('Synthetic denial') }
    `$properties=[pscustomobject]@{
        UnicastAddresses=@([pscustomobject]@{Address=[Net.IPAddress]::Parse('203.0.113.10');PrefixLength=24})
        GatewayAddresses=@([pscustomobject]@{Address=[Net.IPAddress]::Parse('203.0.113.1')})
        DnsAddresses=@([Net.IPAddress]::Parse('192.0.2.53'))
    }
    if (`$script:NetworkCase -eq 'Disconnected') { `$properties.UnicastAddresses=@();`$properties.GatewayAddresses=@();`$properties.DnsAddresses=@() }
    `$properties|Add-Member ScriptMethod GetIPv4Properties { [pscustomobject]@{Index=12} }
    `$properties|Add-Member ScriptMethod GetIPv6Properties { [pscustomobject]@{Index=12} }
    `$nic=[pscustomobject]@{Name='Réseau-東京';Description='Synthetic virtual Ethernet';Id='synthetic';OperationalStatus=[Net.NetworkInformation.OperationalStatus]::Up;Speed=1000000000L;NetworkInterfaceType=[Net.NetworkInformation.NetworkInterfaceType]::Ethernet;Properties=`$properties}
    if (`$script:NetworkCase -eq 'Disconnected') { `$nic.OperationalStatus=[Net.NetworkInformation.OperationalStatus]::Down }
    if (`$script:NetworkCase -eq 'MalformedInterface') { `$nic.Name='' }
    `$nic|Add-Member ScriptMethod GetIPProperties { `$this.Properties }
    if (`$script:NetworkCase -eq 'Partial') { 1..9|ForEach-Object { `$nic } } else { `$nic }
}
function Get-ControlledProfiles {
    if (`$script:NetworkCase -eq 'Disconnected') { return }
    [pscustomobject]@{name='Réseau-東京';category='Private';ipv4Connectivity='LocalNetwork';ipv6Connectivity='Disconnected';interfaceIndex=12}
}
function Get-ControlledRoutes {
    if (`$script:NetworkCase -eq 'Disconnected') { return }
    [pscustomobject]@{addressFamily='IPv4';destinationPrefix='0.0.0.0/0';nextHop='203.0.113.1';interfaceIndex=12;metric=25}
    [pscustomobject]@{addressFamily='IPv4';destinationPrefix='0.0.0.0/0';nextHop='198.51.100.1';interfaceIndex=13;metric=75}
}
function Get-ControlledProxy {
    if (`$script:NetworkCase -eq 'ProxyDenied') { throw [UnauthorizedAccessException]::new('Synthetic proxy denial') }
    `$key=[pscustomobject]@{}
    `$key|Add-Member ScriptMethod GetValue {
        param(`$name,`$default,`$options)
        switch (`$name) {
            ProxyEnable { if (`$script:NetworkCase -eq 'MalformedProxy') { return 2 }; return 1 }
            ProxyServer { if (`$script:NetworkCase -eq 'MalformedProxy') { return 42 }; return 'proxy.synthetic.invalid:8080' }
            AutoConfigURL { if (`$script:NetworkCase -eq 'ProxyOversize') { return ('x'*1025) }; return 'https://config.synthetic.invalid/東京.pac' }
        }
    }
    `$key|Add-Member ScriptMethod Dispose {}
    `$key
}
function Get-ControlledPhonebook { '[VPN-東京]'; 'Type=2'; 'PhoneNumber=vpn.synthetic.invalid'; 'VpnStrategy=7' }
function Get-ControlledConnections {
    `$value=[pscustomobject]@{}
    `$value|Add-Member ScriptMethod GetActiveTcpConnections { @() }
    `$value|Add-Member ScriptMethod GetActiveTcpListeners { @() }
    `$value
}
"@
}
'@.Replace('__CASE__',$Scenario)
    $ModuleText
}

function Assert-NetworkSourceReport {
    param($Record,[string]$Html,[string]$Scenario)
    function Coverage($scope) { @($Record.coverage|Where-Object scopeId -eq "scope:network.$scope")[0] }
    function Values($field) { @($Record.observations|Where-Object fieldId -eq "field:network.$field") }
    Assert-Equal 'Complete' (Coverage 'routes').state 'route coverage survives unrelated source gaps'
    if ($Scenario -ne 'Disconnected') {
        Assert-Equal '12,13' ((Values 'route.interface-index').value -join ',') 'multiple default routes retain typed interface identity'
        Assert-Equal 12 (Values 'profile.interface-index')[0].value 'profile context survives the protected record'
        Assert-Equal $true $Html.Contains('field:network.route.interface-index') 'offline HTML includes route interface provenance'
    }
    if ($Scenario -notin @('Denied','MalformedInterface','Disconnected')) {
        Assert-Equal 'SourceReportedUnknown' (Values 'adapter.hardware-interface')[0].valueState 'Ethernet type does not prove a hardware adapter'
        Assert-Equal 12 (Values 'resolver.interface-index')[0].value 'resolver context survives the protected record'
    }
    $adapterState=switch($Scenario){Denied{'Denied'};Partial{'Partial'};MalformedInterface{'Partial'};default{'Complete'}}
    Assert-Equal $adapterState (Coverage 'adapters').state 'native source preserves interface gaps'
    $proxyState=switch($Scenario){MalformedProxy{'Malformed'};ProxyOversize{'Malformed'};ProxyDenied{'Denied'};default{'Complete'}}
    Assert-Equal $proxyState (Coverage 'proxy').state 'malformed or denied proxy does not become disabled/absent'
    if ($proxyState -ne 'Complete') { Assert-Equal 0 @(Values 'proxy.enabled').Count 'unreadable proxy has no false disabled observation' }
    Assert-Equal 'Unsupported' (Coverage 'security-components').state 'unapproved security provider remains an explicit gap'
    Assert-Equal 'NETWORK.SECURITY_COMPONENT_OFFLINE_SOURCE_UNAVAILABLE' (Coverage 'security-components').reasonCode 'security source limitation remains traceable'
    Assert-Equal 'NotAttempted' @($Record.coverage|Where-Object scopeId -eq 'scope:connectivity.enrollment-dns')[0].state 'Local Only never resolves enrollment names'
    Assert-Equal 'NotAttempted' @($Record.coverage|Where-Object scopeId -eq 'scope:connectivity.tls')[0].state 'Local Only never retrieves remote TLS evidence'
    Assert-Equal $true (@($Record.observations|Where-Object fieldId -like 'field:device.*').Count -gt 0) 'unrelated local collection continues'
    Assert-Equal $false ([bool]($Html -match '(?i)<(?:script|img|link|iframe)[^>]+(?:src|href)\s*=\s*["''](?:https?:)?//|@import|url\(\s*["'']?(?:https?:)?//')) 'report loads no remote asset'
    Assert-Equal $true $Html.Contains('WinHTTP, service-account and effective PAC settings were not assessed') 'report explains the proxy context boundary'
    Assert-Equal $true $Html.Contains('third-party VPN registrations were not assessed') 'report explains the VPN source boundary'
}
