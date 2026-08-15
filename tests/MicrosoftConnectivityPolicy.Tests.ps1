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

Assert-Equal 'win-pcinfo.microsoft-connectivity-policy' $policy.kind `
    'the release freezes one Microsoft Connectivity policy'
Assert-Equal '2026-08-14' $policy.catalogVersion `
    'the endpoint catalog has a reviewed version rather than a live update path'
Assert-Equal 3 @($policy.endpoints).Count `
    'the tracer bullet admits only three exact Microsoft endpoints'
Assert-Equal 8 @($policy.scopes).Count `
    'DNS, TCP, TLS, chain, negotiation, proxy, HTTP, and enrollment DNS remain separate scopes'
Assert-Equal 14 @($policy.validationScenarios).Count `
    'the frozen scenarios cover every issue-defined safety seam'

foreach ($endpoint in @($policy.endpoints)) {
    if ([string]$endpoint.dnsName -match '[*{}]' -or
        [string]$endpoint.uri -match '[*{}]') {
        throw 'Endpoint definitions must be exact and cannot contain wildcards or placeholders.'
    }
    Assert-Equal 443 $endpoint.port "$($endpoint.endpointId) uses the approved TLS port"
    Assert-Equal 'HEAD' $endpoint.http.method "$($endpoint.endpointId) uses a metadata-only method"
    Assert-Equal 0 $endpoint.http.maximumResponseBodyBytes `
        "$($endpoint.endpointId) cannot retain a response body"
    Assert-Equal 0 $endpoint.http.maximumRedirects `
        "$($endpoint.endpointId) cannot follow an undeclared redirect"
}

foreach ($operation in @($policy.collector) + @($policy.operations) + @($policy.rules)) {
    Assert-Equal $false $operation.mayPrompt 'operations cannot prompt'
    Assert-Equal $false $operation.mayInstall 'operations cannot install'
    Assert-Equal $false $operation.mayDownload 'operations cannot download'
    Assert-Equal $false $operation.maySelfElevate 'operations cannot self-elevate'
    Assert-Equal $false $operation.writesAllowed 'operations cannot change network or security state'
    Assert-Equal 1 $operation.maximumAttempts 'operations have one bounded attempt'
    if ([int]$operation.deadlineMilliseconds -le 0) {
        throw 'Every operation needs a finite deadline.'
    }
    foreach($property in @('operationId','sourceId','executionContext','privilege',
        'networkBehavior','executable','dependency','cleanup')){
        if([string]::IsNullOrWhiteSpace([string]$operation.$property)){
            throw "Every operation must freeze $property before approval."
        }
    }
}
foreach($probe in @($policy.collector)+@($policy.operations)){
    if([int]$probe.maximumEndpoints -lt 1 -or
        [int]$probe.maximumResultUtf8Bytes -lt 1){
        throw 'Every collector or probe must freeze output and evidence bounds.'
    }
}
$proxyOperation = @($policy.operations | Where-Object operationId -eq `
    'op:microsoft-connectivity.proxy.observe')[0]
Assert-Equal 2048 $proxyOperation.maximumProxyServerUtf8Bytes `
    'static proxy input has a frozen UTF-8 bound'
Assert-Equal 4096 $proxyOperation.maximumProxyOverrideUtf8Bytes `
    'proxy bypass input has a frozen UTF-8 bound'
Assert-Equal 32 $proxyOperation.maximumProxyOverrideEntries `
    'proxy bypass evaluation has a frozen entry bound'
Assert-Equal $true $proxyOperation.cleanup.Contains('fail closed for PAC or WPAD') `
    'automatic proxy discovery cannot widen the endpoint catalog'

Write-Output 'PASS: the Microsoft Connectivity policy freezes exact endpoints, operations, bounds, and prohibitions.'
