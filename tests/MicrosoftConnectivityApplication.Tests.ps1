[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$candidatePath=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$enabledRequestPath=Join-Path $PSScriptRoot 'fixtures/automation-request-connectivity.json'
$localRequestPath=Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath=Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath|Out-Null

$cases=@(
    @{file='direct-outbound';scenario='DirectOutbound';behavior='MicrosoftConnectivityEnabled';reachable=3;requests=12;tls='NotObservedWithinCompletedTests'},
    @{file='windows-proxy';scenario='WindowsProxy';behavior='MicrosoftConnectivityEnabled';reachable=3;requests=12;tls='NotObservedWithinCompletedTests'},
    @{file='blocked';scenario='Blocked';behavior='MicrosoftConnectivityEnabled';reachable=0;requests=6;tls='Indeterminate'},
    @{file='partially-reachable';scenario='PartiallyReachable';behavior='MicrosoftConnectivityEnabled';reachable=1;requests=10;tls='Indeterminate'},
    @{file='dns-failure';scenario='DnsFailure';behavior='MicrosoftConnectivityEnabled';reachable=0;requests=3;tls='Indeterminate'},
    @{file='redirect';scenario='Redirect';behavior='MicrosoftConnectivityEnabled';reachable=0;requests=12;tls='NotObservedWithinCompletedTests'},
    @{file='timeout';scenario='Timeout';behavior='MicrosoftConnectivityEnabled';reachable=0;requests=3;tls='Indeterminate'},
    @{file='tls-inspection-confirmed';scenario='TlsInspectionConfirmed';behavior='MicrosoftConnectivityEnabled';reachable=3;requests=12;tls='Confirmed'},
    @{file='tls-inspection-suspected';scenario='TlsInspectionSuspected';behavior='MicrosoftConnectivityEnabled';reachable=3;requests=12;tls='Suspected'},
    @{file='invalid-chain';scenario='InvalidChain';behavior='MicrosoftConnectivityEnabled';reachable=0;requests=12;tls='Indeterminate'},
    @{file='http-metadata';scenario='HttpMetadata';behavior='MicrosoftConnectivityEnabled';reachable=3;requests=12;tls='NotObservedWithinCompletedTests'},
    @{file='local-only';scenario='LocalOnly';behavior='LocalOnly';reachable=0;requests=0;tls='Indeterminate'},
    @{file='endpoint-retired';scenario='EndpointRetired';behavior='MicrosoftConnectivityEnabled';reachable=2;requests=8;tls='NotObservedWithinCompletedTests'},
    @{file='unicode';scenario='Unicode';behavior='MicrosoftConnectivityEnabled';reachable=3;requests=12;tls='NotObservedWithinCompletedTests'}
)
foreach($case in $cases){
    $requestPath=if($case.behavior -eq 'LocalOnly'){$localRequestPath}else{$enabledRequestPath}
    $result=Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
        '-PreparationFixturePath',$preparationPath,
        '-MicrosoftConnectivityFixturePath',(Join-Path $PSScriptRoot "fixtures/microsoft-connectivity/$($case.file).json")
    )
    $validation=@($result.Records|Where-Object recordType -eq 'win-pcinfo.microsoft-connectivity-validation')
    $terminal=@($result.Records|Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $validation.Count "$($case.scenario) emits one sanitized connectivity projection"
    Assert-Equal 1 $terminal.Count "$($case.scenario) retains one terminal path"
    $expectedExit=if($case.scenario -in @('DirectOutbound','WindowsProxy',
        'TlsInspectionConfirmed','TlsInspectionSuspected','HttpMetadata','Unicode')){0}else{10}
    $expectedOutcome=if($expectedExit -eq 0){'Completed'}else{'CompletedWithGaps'}
    Assert-Equal $expectedExit $result.ExitCode "$($case.scenario) returns the honest coverage exit code"
    Assert-Equal $expectedOutcome $terminal[0].outcome `
        "$($case.scenario) preserves packaging while reporting related gaps"
    Assert-Equal $case.scenario $validation[0].scenario "$($case.scenario) crosses the release-owned validation seam"
    Assert-Equal $case.behavior $validation[0].networkBehavior "$($case.scenario) retains approved network behavior"
    Assert-Equal 3 $validation[0].endpointDefinitionCount "$($case.scenario) uses the exact versioned catalog"
    Assert-Equal $case.reachable $validation[0].reachableEndpointCount "$($case.scenario) preserves aggregate reachability"
    Assert-Equal $case.requests $validation[0].outboundRequestCount "$($case.scenario) preserves the bounded request count"
    Assert-Equal $case.tls $validation[0].tlsInspectionOutcome "$($case.scenario) reports bounded TLS inspection semantics"
    Assert-Equal $false $validation[0].restrictedEvidencePublished "$($case.scenario) keeps endpoint results Restricted"
    Assert-Equal $false $validation[0].credentialsTransmitted "$($case.scenario) sends no credentials"
    Assert-Equal $false $validation[0].tenantIdentifierTransmitted "$($case.scenario) sends no tenant identifier"
    Assert-Equal $false $validation[0].evidencePayloadTransmitted "$($case.scenario) sends no collected evidence"
    Assert-Equal 0 $validation[0].transmittedBodyBytes "$($case.scenario) sends no body"
    Assert-Equal $false $validation[0].packetCapturePerformed "$($case.scenario) captures no packets"
    Assert-Equal $false $validation[0].networkConfigurationChanged "$($case.scenario) changes no settings"
    Assert-Equal $true $validation[0].assessmentRecordValidated "$($case.scenario) enters the canonical Assessment Record"
    Assert-Equal $true $validation[0].beginnerReportVerified "$($case.scenario) derives the beginner report"
    Assert-Equal $true $validation[0].protectedPackageVerified "$($case.scenario) reopens the protected package"
    Assert-Equal $true $validation[0].validationCleanupVerified "$($case.scenario) leaves no validation artifact"
    if($result.StandardOutput -match '(?i)TLS_AES|synthetic-connectivity|certificate-fingerprint'){
        throw "$($case.scenario) leaked Restricted connectivity evidence into public output."
    }
    if($result.StandardError){throw "$($case.scenario) wrote stderr: $($result.StandardError)"}
}

# A fixture can never widen Local Only into outbound activity.
$collapsed=Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
    '-Mode','Automation','-RequestPath',$localRequestPath,'-AcceptPreparation',
    '-PreparationFixturePath',$preparationPath,
    '-MicrosoftConnectivityFixturePath',(Join-Path $PSScriptRoot 'fixtures/microsoft-connectivity/direct-outbound.json')
)
$collapsedProjection=@($collapsed.Records|Where-Object recordType -eq 'win-pcinfo.microsoft-connectivity-validation')[0]
Assert-Equal 'LocalOnly' $collapsedProjection.networkBehavior 'Local Only collapses an enabled validation scenario'
Assert-Equal 0 $collapsedProjection.outboundRequestCount 'Local Only performs zero outbound requests'

Write-Output 'PASS: the generated application proves bounded Microsoft connectivity, privacy, and Local Only.'
