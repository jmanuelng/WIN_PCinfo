[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/NetworkTopology.ps1')
$policy=Get-NetworkTopologyPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)

$expectations=@(
    @{scenario='MultipleAdapters';adapters=2;profiles=2;routes=1;resolvers=1;vpn=0;security=0;connections=0;local='Complete'},
    @{scenario='IPv4IPv6';adapters=1;profiles=1;routes=2;resolvers=2;vpn=0;security=0;connections=0;local='Complete'},
    @{scenario='Disconnected';adapters=1;profiles=1;routes=0;resolvers=0;vpn=0;security=0;connections=0;local='Complete'},
    @{scenario='Routes';adapters=1;profiles=1;routes=2;resolvers=0;vpn=0;security=0;connections=0;local='Complete'},
    @{scenario='Resolvers';adapters=1;profiles=1;routes=0;resolvers=2;vpn=0;security=0;connections=0;local='Complete'},
    @{scenario='Proxy';adapters=1;profiles=1;routes=0;resolvers=0;vpn=0;security=0;connections=0;local='Complete'},
    @{scenario='VpnAndSecurity';adapters=1;profiles=1;routes=0;resolvers=0;vpn=1;security=2;connections=0;local='Complete'},
    @{scenario='ExistingConnections';adapters=1;profiles=1;routes=0;resolvers=0;vpn=0;security=0;connections=2;local='Complete'},
    @{scenario='Empty';adapters=0;profiles=0;routes=0;resolvers=0;vpn=0;security=0;connections=0;local='Complete'},
    @{scenario='Malformed';adapters=0;profiles=1;routes=0;resolvers=0;vpn=0;security=0;connections=0;local='Partial'},
    @{scenario='Denied';adapters=0;profiles=0;routes=0;resolvers=0;vpn=0;security=0;connections=0;local='Denied'},
    @{scenario='Partial';adapters=8;profiles=8;routes=8;resolvers=8;vpn=8;security=8;connections=8;local='Partial'},
    @{scenario='LocalOnly';adapters=1;profiles=1;routes=1;resolvers=1;vpn=0;security=0;connections=0;local='Complete'},
    @{scenario='Unicode';adapters=1;profiles=1;routes=1;resolvers=1;vpn=1;security=1;connections=1;local='Complete'}
)
foreach($case in $expectations){
    $result=Invoke-NetworkTopologyCollection -Policy $policy -ValidationScenario $case.scenario `
        -NetworkBehavior LocalOnly
    Assert-Equal 'Completed' $result.state "$($case.scenario) returns one closed collector result"
    Assert-Equal $true (Test-NetworkTopologyCollectorPayload -Payload $result.payload -Policy $policy) `
        "$($case.scenario) satisfies the closed payload contract"
    foreach($name in 'adapters','profiles','routes','resolvers','vpnComponents','securityComponents','connections'){
        $expectedName=if($name -eq 'vpnComponents'){'vpn'}elseif($name -eq 'securityComponents'){'security'}else{$name}
        Assert-Equal $case[$expectedName] @($result.payload.$name).Count "$($case.scenario) bounds $name"
    }
    Assert-Equal 0 $result.payload.outboundRequestCount "$($case.scenario) performs zero assessment network requests"
    Assert-Equal 3 @($result.payload.scopeStates|Where-Object state -eq NotAttempted).Count `
        "$($case.scenario) closes every Local Only network-dependent scope"
    $localStates=@($result.payload.scopeStates|Where-Object scopeId -in @($policy.localScopes.scopeId)|ForEach-Object state|Sort-Object -Unique)
    Assert-Equal $case.local $(if($localStates.Count -eq 1){$localStates[0]}else{'Partial'}) `
        "$($case.scenario) preserves local-source coverage"
}

$bad=Invoke-NetworkTopologyCollection -Policy $policy -ValidationScenario VpnAndSecurity -NetworkBehavior LocalOnly
$bad.payload.securityComponents[0]|Add-Member -NotePropertyName health -NotePropertyValue 'Healthy'
Assert-Equal $false (Test-NetworkTopologyCollectorPayload -Payload $bad.payload -Policy $policy) `
    'security product names cannot smuggle an inferred health claim'
$bad=Invoke-NetworkTopologyCollection -Policy $policy -ValidationScenario ExistingConnections -NetworkBehavior LocalOnly
$bad.payload.connections[0]|Add-Member -NotePropertyName owningProcess -NotePropertyValue 4000
Assert-Equal $false (Test-NetworkTopologyCollectorPayload -Payload $bad.payload -Policy $policy) `
    'connection evidence cannot expose a process identity channel'

$malformedAdapter=New-NetworkTopologySyntheticPayload -Scenario MultipleAdapters -Policy $policy
$malformedAdapter.adapters[0].name=''
Assert-Equal $false (Test-NetworkTopologyCollectorPayload -Payload $malformedAdapter -Policy $policy) `
    'an empty adapter name cannot cross the closed payload contract'
$isolatedAdapter=Copy-NetworkTopologyCollectorPayload -Payload $malformedAdapter -Policy $policy
Assert-Equal 1 @($isolatedAdapter.adapters).Count 'one malformed adapter does not discard an unrelated valid adapter'
Assert-Equal 'Partial' @($isolatedAdapter.scopeStates|Where-Object scopeId -eq 'scope:network.adapters')[0].state `
    'a malformed adapter remains an adapter-scope gap'
Assert-Equal 'Complete' @($isolatedAdapter.scopeStates|Where-Object scopeId -eq 'scope:network.connection-profiles')[0].state `
    'malformed adapter evidence does not degrade profile coverage'

$malformedVpn=New-NetworkTopologySyntheticPayload -Scenario VpnAndSecurity -Policy $policy
$malformedVpn.vpnComponents[0].tunnelType=''
$isolatedVpn=Copy-NetworkTopologyCollectorPayload -Payload $malformedVpn -Policy $policy
Assert-Equal 0 @($isolatedVpn.vpnComponents).Count 'a malformed VPN row is omitted rather than accepted'
Assert-Equal 'Partial' @($isolatedVpn.scopeStates|Where-Object scopeId -eq 'scope:network.vpn-components')[0].state `
    'a malformed VPN row remains a VPN-scope gap'
Assert-Equal 2 @($isolatedVpn.securityComponents).Count 'malformed VPN evidence does not discard security-component evidence'
Assert-Equal 'Complete' @($isolatedVpn.scopeStates|Where-Object scopeId -eq 'scope:network.security-components')[0].state `
    'malformed VPN evidence does not degrade security-component coverage'

$projection=New-NetworkTopologyPublicProjection -CollectorResult (
    Invoke-NetworkTopologyCollection -Policy $policy -ValidationScenario Unicode -NetworkBehavior LocalOnly
) -Policy $policy
Assert-Equal 'win-pcinfo.network-topology-validation' $projection.recordType 'public evidence has an explicit shape'
Assert-Equal 0 $projection.outboundRequestCount 'public evidence proves no Local Only request was attempted'
Assert-Equal $false $projection.networkIdentifiersPublished 'exact network identifiers remain Restricted'
Assert-Equal $false $projection.componentHealthInferred 'component inventory makes no health inference'
if(($projection|ConvertTo-Json -Depth 10 -Compress) -match '203\.0\.113|2001:db8|代理|شبكة|SYNTHETIC-VPN'){
    throw 'Restricted network evidence entered the public projection.'
}

Write-Output 'PASS: Network Topology fixtures preserve Local Only, coverage, bounds, and privacy.'
