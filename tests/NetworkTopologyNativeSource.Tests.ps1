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
foreach($required in @('Get-NetAdapter','Get-NetConnectionProfile','Get-NetIPAddress','Get-NetRoute','Get-DnsClientServerAddress','Get-VpnConnection','root/SecurityCenter2','Get-NetTCPConnection','[Microsoft.Win32.Registry]::CurrentUser')){
    if($source -notmatch [regex]::Escape($required)){throw "The live source omitted $required."}
}
foreach($prohibited in @('Resolve-DnsName','Dns.GetHost','Test-NetConnection','Invoke-WebRequest','Invoke-RestMethod','HttpClient','TcpClient','Socket','ping','curl','Update-','Install-','Set-Net','New-Net','Remove-Net','Enable-Net','Disable-Net','Restart-Net','Packet','Capture','Credential','MacAddress','InterfaceGuid','CimSession')){
    if($source -match [regex]::Escape($prohibited)){throw "Local Only admits a prohibited network or identity operation: $prohibited"}
}
if($source -match '\$rows\s*='){throw 'Provider inventories must stream through bounded reducers.'}

$gap=Invoke-NetworkTopologyCollection -Policy $policy -Live -NetworkBehavior LocalOnly `
    -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -ProcessContextOverride LocalSystem
Assert-Equal 'Denied' @($gap.payload.scopeStates|Where-Object scopeId -eq 'scope:network.adapters')[0].state `
    'SYSTEM is rejected before local source access'
Assert-Equal 0 $gap.payload.outboundRequestCount 'a denied context cannot attempt network activity'
Assert-Equal $true $gap.cleanupVerified 'a pre-source denial owns no child process'

Write-Output 'PASS: the local Network Topology source is bounded, read-only, identity-bound, and offline.'
