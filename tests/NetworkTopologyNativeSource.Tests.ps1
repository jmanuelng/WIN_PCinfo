[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1')
. (Join-Path $repositoryRoot 'src/NetworkTopology.ps1')
$policy=Get-NetworkTopologyPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)

$source=Get-NetworkTopologyLiveSource
foreach($required in @('[Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()','GetActiveTcpConnections()','[Microsoft.Win32.Registry]::CurrentUser','GetIpForwardTable','ConvertTo-Json')){
    if($source -notmatch [regex]::Escape($required)){throw "The live source omitted $required."}
}
foreach($prohibited in @('Get-Net','Get-CimInstance','Import-Module','Resolve-DnsName','Dns.GetHost','Test-NetConnection','Invoke-WebRequest','Invoke-RestMethod','HttpClient','TcpClient','[Net.Sockets.Socket]','ping','curl','Update-','Install-','Set-Net','New-Net','Remove-Net','Enable-Net','Disable-Net','Restart-Net','Packet','Capture','Credential','MacAddress','InterfaceGuid','CimSession','PSSerializer')){
    if($source -match [regex]::Escape($prohibited)){throw "Local Only admits a prohibited network or identity operation: $prohibited"}
}
if($source -match '\$rows\s*='){throw 'Provider inventories must stream through bounded reducers.'}
foreach($requiredSafetyShape in @('if(next==1)break','if(connectionNext==1)break','Check(next)','Check(connectionNext)','Marshal.OffsetOf<MIB_IPFORWARD_TABLE2>','Marshal.SizeOf<MIB_IPFORWARD_ROW2>','Marshal.PtrToStructure<MIB_IPFORWARD_ROW2>','^Type=(\d+)$','$entry.type -eq 2')){
    if($source -notmatch [regex]::Escape($requiredSafetyShape)){throw "The live source omitted its fail-closed native safety shape: $requiredSafetyShape"}
}
if($source -match 'const int rowSize=104|IntPtr.Size==8\?8:4'){
    throw 'The route reader must derive native row and table alignment from marshaled SDK-shaped structures.'
}

$workerEnvironment=Get-NetworkTopologyWorkerEnvironment -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -MaximumItems 8
Assert-Equal '1' $workerEnvironment['POWERSHELL_TELEMETRY_OPTOUT'] `
    'the supervised PowerShell host cannot activate PowerShell telemetry'
Assert-Equal '1' $workerEnvironment['DOTNET_CLI_TELEMETRY_OPTOUT'] `
    'the supervised .NET host cannot activate .NET CLI telemetry'
Assert-Equal 'Off' $workerEnvironment['POWERSHELL_UPDATECHECK'] `
    'the supervised PowerShell host cannot activate update checks'

function New-MaximumAdmittedNetworkTopologyPayload {
    param($Policy)
    # U+0001 occupies one admitted UTF-8 byte but six JSON bytes (\u0001), so
    # filling every free-text field with it exercises the serializer's maximum
    # escape expansion as well as every item/array/property framing allowance.
    $text={param([int]$length) ([string][char]1)*$length}
    $maximum=[int]$Policy.collector.maximumItemsPerScope
    $items=0..($maximum-1)
    $states=@($Policy.localScopes|ForEach-Object {[pscustomobject][ordered]@{scopeId=$_.scopeId;state='NotAttempted';reasonCode='A'*128}})+
        @($Policy.networkDependentScopes|ForEach-Object {[pscustomobject][ordered]@{scopeId=$_.scopeId;state=$_.localOnlyState;reasonCode=$_.reasonCode}})
    $payload=[pscustomobject][ordered]@{
        sourceLocale=&$text 35;assessmentUserContextVerified=$true;processRelationship='SameUser'
        networkBehavior='LocalOnly';outboundRequestCount=0
        adapters=@($items|ForEach-Object {[pscustomobject][ordered]@{name=&$text 256;description=&$text 512;status='Disconnected';interfaceIndex=[int]::MaxValue;linkSpeed=[long]::MaxValue;hardwareInterface=$false}})
        profiles=@($items|ForEach-Object {[pscustomobject][ordered]@{name=&$text 256;category='DomainAuthenticated';ipv4Connectivity=&$text 32;ipv6Connectivity=&$text 32;interfaceIndex=[int]::MaxValue}})
        ipConfigurations=@($items|ForEach-Object {[pscustomobject][ordered]@{interfaceIndex=[int]::MaxValue;addressFamily='IPv6';address=&$text 64;prefixLength=128;defaultGateway=&$text 64}})
        routes=@($items|ForEach-Object {[pscustomobject][ordered]@{addressFamily='IPv6';destinationPrefix=&$text 80;nextHop=&$text 64;interfaceIndex=[int]::MaxValue;metric=[int]::MinValue}})
        resolvers=@($items|ForEach-Object {[pscustomobject][ordered]@{interfaceIndex=[int]::MaxValue;addressFamily='IPv6';addresses=@(1..4|ForEach-Object {&$text 64})}})
        proxy=[pscustomobject][ordered]@{enabled=$false;server=&$text 1024;autoConfigUrl=&$text 1024}
        vpnComponents=@($items|ForEach-Object {[pscustomobject][ordered]@{name=&$text 256;serverAddress=&$text 512;tunnelType=&$text 64;connectionStatus=&$text 32}})
        securityComponents=@($items|ForEach-Object {[pscustomobject][ordered]@{kind='AntiVirus';name=&$text 256;stateCode=[int]::MinValue}})
        connections=@($items|ForEach-Object {[pscustomobject][ordered]@{state=&$text 32;localAddress=&$text 64;localPort=65535;remoteAddress=&$text 64;remotePort=65535}})
        scopeStates=$states
        executionContext='StandardUser'
    }
    if(-not (Test-NetworkTopologyCollectorPayload -Payload $payload -Policy $Policy)){
        throw 'The maximum admitted Network Topology fixture must itself pass the closed payload validator.'
    }
    $payload
}

$maximumPayload=New-MaximumAdmittedNetworkTopologyPayload -Policy $policy
$maximumPayloadJson=$maximumPayload|ConvertTo-Json -Compress -Depth 10
$maximumPayloadBytes=[Text.UTF8Encoding]::new($false).GetByteCount($maximumPayloadJson)
Write-Verbose "Maximum admitted Network Topology payload: $maximumPayloadBytes UTF-8 bytes."
Assert-Equal $policy.collector.resultBoundDerivation.maximumAdmittedPayloadUtf8Bytes $maximumPayloadBytes `
    'the release bound equals a closed maximum-item, maximum-string, maximum-escape JSON payload'

$maximum=[int]$policy.collector.resultMaximumUtf8Bytes
$minimal=New-NetworkTopologySyntheticPayload -Scenario Empty -Policy $policy
$minimalBytes=[Text.UTF8Encoding]::new($false).GetBytes(($minimal|ConvertTo-Json -Compress -Depth 10))
$exactBytes=[byte[]]::new($maximum);[Array]::Copy($minimalBytes,$exactBytes,$minimalBytes.Length)
for($index=$minimalBytes.Length;$index -lt $exactBytes.Length;$index++){$exactBytes[$index]=0x20}
$exact=ConvertFrom-NetworkTopologyTransport -Bytes $exactBytes -Policy $policy
Assert-Equal 'LocalOnly' $exact.networkBehavior `
    'an exact-bound valid UTF-8 JSON fixture passes the transport boundary'
$overBytes=[byte[]]::new($maximum+1);[Array]::Copy($exactBytes,$overBytes,$exactBytes.Length);$overBytes[-1]=0x20
$overRejected=$false
try{$null=ConvertFrom-NetworkTopologyTransport -Bytes $overBytes -Policy $policy}catch{$overRejected=$true}
Assert-Equal $true $overRejected `
    'a one-byte-over valid UTF-8 JSON fixture fails closed'

$gap=Invoke-NetworkTopologyCollection -Policy $policy -Live -NetworkBehavior LocalOnly `
    -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -ProcessContextOverride LocalSystem
Assert-Equal 'Denied' @($gap.payload.scopeStates|Where-Object scopeId -eq 'scope:network.adapters')[0].state `
    'SYSTEM is rejected before local source access'
Assert-Equal 0 $gap.payload.outboundRequestCount 'a denied context cannot attempt network activity'
Assert-Equal $true $gap.cleanupVerified 'a pre-source denial owns no child process'

Write-Output 'PASS: the local Network Topology source is bounded, read-only, identity-bound, and offline.'
