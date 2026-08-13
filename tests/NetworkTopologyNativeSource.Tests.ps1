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

$workerEnvironment=Get-NetworkTopologyWorkerEnvironment -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -MaximumItems 8
Assert-Equal '1' $workerEnvironment['POWERSHELL_TELEMETRY_OPTOUT'] `
    'the supervised PowerShell host cannot activate PowerShell telemetry'
Assert-Equal '1' $workerEnvironment['DOTNET_CLI_TELEMETRY_OPTOUT'] `
    'the supervised .NET host cannot activate .NET CLI telemetry'
Assert-Equal 'Off' $workerEnvironment['POWERSHELL_UPDATECHECK'] `
    'the supervised PowerShell host cannot activate update checks'

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
