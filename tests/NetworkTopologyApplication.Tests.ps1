[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$candidatePath=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath=Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath=Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath|Out-Null

$cases=@(
    @{scenario='MultipleAdapters';coverage='Complete';adapters=2;profiles=2;routes=1;resolvers=1;vpn=0;security=0;connections=0;configuration='Informational';components='Informational'},
    @{scenario='IPv4IPv6';coverage='Complete';adapters=1;profiles=1;routes=2;resolvers=2;vpn=0;security=0;connections=0;configuration='Informational';components='Informational'},
    @{scenario='Disconnected';coverage='Complete';adapters=1;profiles=1;routes=0;resolvers=0;vpn=0;security=0;connections=0;configuration='Informational';components='Informational'},
    @{scenario='Routes';coverage='Complete';adapters=1;profiles=1;routes=2;resolvers=0;vpn=0;security=0;connections=0;configuration='Informational';components='Informational'},
    @{scenario='Resolvers';coverage='Complete';adapters=1;profiles=1;routes=0;resolvers=2;vpn=0;security=0;connections=0;configuration='Informational';components='Informational'},
    @{scenario='Proxy';coverage='Complete';adapters=1;profiles=1;routes=0;resolvers=0;vpn=0;security=0;connections=0;configuration='Informational';components='Informational'},
    @{scenario='VpnAndSecurity';coverage='Complete';adapters=1;profiles=1;routes=0;resolvers=0;vpn=1;security=2;connections=0;configuration='Informational';components='Informational'},
    @{scenario='ExistingConnections';coverage='Complete';adapters=1;profiles=1;routes=0;resolvers=0;vpn=0;security=0;connections=2;configuration='Informational';components='Informational'},
    @{scenario='Empty';coverage='Complete';adapters=0;profiles=0;routes=0;resolvers=0;vpn=0;security=0;connections=0;configuration='Informational';components='Informational'},
    @{scenario='Malformed';coverage='Partial';adapters=0;profiles=1;routes=0;resolvers=0;vpn=0;security=0;connections=0;configuration='Indeterminate';components='Informational'},
    @{scenario='Denied';coverage='Denied';adapters=0;profiles=0;routes=0;resolvers=0;vpn=0;security=0;connections=0;configuration='Indeterminate';components='Indeterminate'},
    @{scenario='Partial';coverage='Partial';adapters=8;profiles=8;routes=8;resolvers=8;vpn=8;security=8;connections=8;configuration='Indeterminate';components='Indeterminate'},
    @{scenario='LocalOnly';coverage='Complete';adapters=1;profiles=1;routes=1;resolvers=1;vpn=0;security=0;connections=0;configuration='Informational';components='Informational'},
    @{scenario='Unicode';coverage='Complete';adapters=1;profiles=1;routes=1;resolvers=1;vpn=1;security=1;connections=1;configuration='Informational';components='Informational'}
)

foreach($case in $cases){
    $fixture=Join-Path $PSScriptRoot "fixtures/network-$($case.scenario.ToLowerInvariant()).json"
    $result=Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
        '-PreparationFixturePath',$preparationPath,'-NetworkTopologyFixturePath',$fixture
    )
    $validation=@($result.Records|Where-Object recordType -eq 'win-pcinfo.network-topology-validation')
    $terminal=@($result.Records|Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $validation.Count "$($case.scenario) emits one sanitized projection"
    Assert-Equal 1 $terminal.Count "$($case.scenario) emits one terminal"
    Assert-Equal 10 $result.ExitCode "$($case.scenario) reports the expected Local Only gaps"
    Assert-Equal 'CompletedWithGaps' $terminal[0].outcome "$($case.scenario) does not overclaim network-dependent coverage"
    Assert-Equal $case.coverage $validation[0].localScopeCoverage "$($case.scenario) preserves local-source coverage"
    Assert-Equal 'NotAttempted' $validation[0].networkDependentCoverage "$($case.scenario) preserves the Local Only probe state"
    Assert-Equal $case.adapters $validation[0].adapterCount "$($case.scenario) publishes only an adapter count"
    Assert-Equal $case.profiles $validation[0].profileCount "$($case.scenario) publishes only a profile count"
    Assert-Equal $case.routes $validation[0].routeCount "$($case.scenario) publishes only a route count"
    Assert-Equal $case.resolvers $validation[0].resolverSetCount "$($case.scenario) publishes only a resolver-set count"
    Assert-Equal $case.vpn $validation[0].vpnComponentCount "$($case.scenario) publishes only a VPN count"
    Assert-Equal $case.security $validation[0].securityComponentCount "$($case.scenario) publishes only a security-component count"
    Assert-Equal $case.connections $validation[0].connectionCount "$($case.scenario) publishes only a local-connection count"
    Assert-Equal $case.configuration $validation[0].networkConfigurationFinding "$($case.scenario) derives advisory configuration guidance"
    Assert-Equal $case.components $validation[0].networkComponentFinding "$($case.scenario) does not infer product health"
    Assert-Equal 0 $validation[0].outboundRequestCount "$($case.scenario) captures zero Local Only outbound requests"
    Assert-Equal $false $validation[0].networkIdentifiersPublished "$($case.scenario) keeps exact topology Restricted"
    Assert-Equal $false $validation[0].componentHealthInferred "$($case.scenario) does not infer health from product names"
    Assert-Equal $false $validation[0].packetCapturePerformed "$($case.scenario) performs no packet capture"
    Assert-Equal $false $validation[0].networkConfigurationChanged "$($case.scenario) performs no network change"
    Assert-Equal $true $validation[0].assessmentRecordValidated "$($case.scenario) validates the canonical record"
    Assert-Equal $true $validation[0].beginnerReportVerified "$($case.scenario) verifies the beginner report"
    Assert-Equal $true $validation[0].protectedPackageVerified "$($case.scenario) reopens the protected package"
    Assert-Equal $true $validation[0].validationCleanupVerified "$($case.scenario) proves fixture artifacts absent"
    if($result.StandardOutput -match '(?i)203\.0\.113|198\.51\.100|192\.0\.2|2001:db8|synthetic adapter|synthetic profile|synthetic-vpn|proxy\.synthetic|شبكة|東京'){
        throw "$($case.scenario) leaked Restricted topology evidence into public output."
    }
    if($result.StandardError){throw "$($case.scenario) wrote stderr: $($result.StandardError)"}
}

$invalid=Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
    '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
    '-PreparationFixturePath',$preparationPath,'-NetworkTopologyFixturePath',(
        Join-Path $PSScriptRoot 'fixtures/network-does-not-exist.json'
    )
)
Assert-Equal 1 @($invalid.Records|Where-Object recordType -eq 'win-pcinfo.terminal').Count 'an invalid network fixture retains one stable terminal path'
Assert-Equal 0 @($invalid.Records|Where-Object recordType -eq 'win-pcinfo.network-topology-validation').Count 'an invalid fixture cannot fabricate a topology projection'
if($invalid.StandardError){throw "Invalid fixture wrote stderr: $($invalid.StandardError)"}
Write-Output 'PASS: the generated application proves Local Only topology evidence, privacy, reporting, packaging, and cleanup.'
