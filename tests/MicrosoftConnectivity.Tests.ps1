[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/MicrosoftConnectivity.ps1')
$policy = Get-MicrosoftConnectivityPolicy -ConvertFromJsonCommand (
    Get-Command ConvertFrom-Json -CommandType Cmdlet
)

$cases = @(
    @{ scenario = 'DirectOutbound'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Complete'; requests = 12; succeeded = 3; inspection = 'NotObservedWithinCompletedTests' },
    @{ scenario = 'WindowsProxy'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Complete'; requests = 12; succeeded = 3; inspection = 'NotObservedWithinCompletedTests' },
    @{ scenario = 'Blocked'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Partial'; requests = 6; succeeded = 0; inspection = 'Indeterminate' },
    @{ scenario = 'PartiallyReachable'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Partial'; requests = 10; succeeded = 1; inspection = 'Indeterminate' },
    @{ scenario = 'DnsFailure'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Partial'; requests = 3; succeeded = 0; inspection = 'Indeterminate' },
    @{ scenario = 'Redirect'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Partial'; requests = 12; succeeded = 0; inspection = 'NotObservedWithinCompletedTests' },
    @{ scenario = 'Timeout'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Partial'; requests = 3; succeeded = 0; inspection = 'Indeterminate' },
    @{ scenario = 'TlsInspectionConfirmed'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Complete'; requests = 12; succeeded = 3; inspection = 'Confirmed' },
    @{ scenario = 'TlsInspectionSuspected'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Complete'; requests = 12; succeeded = 3; inspection = 'Suspected' },
    @{ scenario = 'InvalidChain'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Partial'; requests = 12; succeeded = 0; inspection = 'Indeterminate' },
    @{ scenario = 'HttpMetadata'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Complete'; requests = 12; succeeded = 3; inspection = 'NotObservedWithinCompletedTests' },
    @{ scenario = 'LocalOnly'; behavior = 'LocalOnly'; coverage = 'NotAttempted'; requests = 0; succeeded = 0; inspection = 'Indeterminate' },
    @{ scenario = 'EndpointRetired'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Partial'; requests = 8; succeeded = 2; inspection = 'NotObservedWithinCompletedTests' },
    @{ scenario = 'Unicode'; behavior = 'MicrosoftConnectivityEnabled'; coverage = 'Complete'; requests = 12; succeeded = 3; inspection = 'NotObservedWithinCompletedTests' }
)

foreach ($case in $cases) {
    $result = Invoke-MicrosoftConnectivityCollection -Policy $policy `
        -ValidationScenario $case.scenario -NetworkBehavior $case.behavior
    Assert-Equal 'Completed' $result.state "$($case.scenario) returns one closed collector result"
    Assert-Equal $true (Test-MicrosoftConnectivityPayload -Payload $result.payload -Policy $policy) `
        "$($case.scenario) satisfies the closed payload contract"
    Assert-Equal $case.requests $result.payload.outboundRequestCount `
        "$($case.scenario) accounts for every attempted assessment request"
    $scopeStates = @($result.payload.scopeStates | ForEach-Object state | Sort-Object -Unique)
    Assert-Equal $case.coverage $(if ($scopeStates.Count -eq 1) { $scopeStates[0] } else { 'Partial' }) `
        "$($case.scenario) preserves typed protocol coverage"
    $projection = New-MicrosoftConnectivityPublicProjection -CollectorResult $result -Policy $policy
    Assert-Equal $case.succeeded $projection.reachableEndpointCount `
        "$($case.scenario) publishes only the aggregate reachable count"
    Assert-Equal $case.inspection $projection.tlsInspectionOutcome `
        "$($case.scenario) preserves the controlled TLS-inspection conclusion"
    Assert-Equal $false $projection.restrictedEvidencePublished `
        "$($case.scenario) keeps per-endpoint and certificate evidence Restricted"
    Assert-Equal $false $projection.credentialsTransmitted `
        "$($case.scenario) transmits no credential or token"
    Assert-Equal 0 $projection.transmittedBodyBytes `
        "$($case.scenario) transmits no arbitrary HTTP body"
    Assert-Equal $false $projection.packetCapturePerformed `
        "$($case.scenario) performs no packet capture"
    Assert-Equal $false $projection.networkConfigurationChanged `
        "$($case.scenario) performs no settings change"
    if($case.scenario -eq 'HttpMetadata'){
        Assert-Equal ([int]$policy.collector.maximumHeaderEntries) `
            $result.payload.endpointResults[0].httpHeaderCount `
            'HTTP metadata reaches but does not exceed the frozen entry bound'
        Assert-Equal 204 $result.payload.endpointResults[0].httpStatusCode `
            'HTTP status remains typed separately from body content'
    }
}

$scopeIsolation=@{
    Blocked=@{'scope:connectivity.dns'='Complete';'scope:connectivity.tcp'='Partial';'scope:connectivity.enrollment-dns'='Complete'}
    DnsFailure=@{'scope:connectivity.dns'='Partial';'scope:connectivity.tcp'='Partial';'scope:connectivity.http'='Partial'}
    Redirect=@{'scope:connectivity.dns'='Complete';'scope:connectivity.tls'='Complete';'scope:connectivity.http'='Partial'}
    InvalidChain=@{'scope:connectivity.dns'='Complete';'scope:connectivity.tcp'='Complete';'scope:connectivity.certificate-chain'='Complete';'scope:connectivity.tls'='Partial'}
}
foreach($scenario in $scopeIsolation.Keys){
    $payload=New-MicrosoftConnectivitySyntheticPayload -Scenario $scenario `
        -Policy $policy -NetworkBehavior MicrosoftConnectivityEnabled
    foreach($scopeId in $scopeIsolation[$scenario].Keys){
        Assert-Equal $scopeIsolation[$scenario][$scopeId] `
            @($payload.scopeStates|Where-Object scopeId -eq $scopeId)[0].state `
            "$scenario affects only the related $scopeId coverage"
    }
}

$tampered = New-MicrosoftConnectivitySyntheticPayload -Scenario DirectOutbound `
    -Policy $policy -NetworkBehavior MicrosoftConnectivityEnabled
$tampered | Add-Member -NotePropertyName bearerToken -NotePropertyValue 'synthetic-secret-marker'
Assert-Equal $false (Test-MicrosoftConnectivityPayload -Payload $tampered -Policy $policy) `
    'an undeclared credential-shaped channel cannot cross the collector contract'

$certificateOnly = New-MicrosoftConnectivitySyntheticPayload -Scenario TlsInspectionSuspected `
    -Policy $policy -NetworkBehavior MicrosoftConnectivityEnabled
$certificateOnly.endpointResults[0].tlsInspectionCorroboration = 'CertificateDifferenceOnly'
Assert-Equal $false (Test-MicrosoftConnectivityPayload -Payload $certificateOnly -Policy $policy) `
    'certificate difference alone cannot confirm or corroborate TLS inspection'

$unsupportedConfirmation = New-MicrosoftConnectivitySyntheticPayload `
    -Scenario TlsInspectionConfirmed -Policy $policy `
    -NetworkBehavior MicrosoftConnectivityEnabled
$unsupportedConfirmation.endpointResults[0].proxyState='Bypassed'
$unsupportedConfirmation.endpointResults[0].transportMode='Direct'
Assert-Equal $false (Test-MicrosoftConnectivityPayload `
    -Payload $unsupportedConfirmation -Policy $policy) `
    'Confirmed requires independent Windows-proxy evidence as well as a path difference'

$liveLocalOnly = Invoke-MicrosoftConnectivityCollection -Policy $policy -Live `
    -NetworkBehavior LocalOnly
Assert-Equal 0 $liveLocalOnly.payload.outboundRequestCount `
    'the real collector returns before endpoint materialization in Local Only mode'
Assert-Equal 0 @($liveLocalOnly.payload.endpointResults).Count `
    'Local Only gives the live collector no endpoint to resolve or contact'

Write-Output 'PASS: Microsoft Connectivity fixtures preserve protocol separation, consent, bounds, privacy, and TLS-inspection honesty.'
