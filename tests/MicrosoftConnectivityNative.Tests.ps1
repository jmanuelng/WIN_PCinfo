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

$offlinePolicy = New-MicrosoftConnectivityOfflineChainPolicy
Assert-Equal $true $offlinePolicy.DisableCertificateDownloads `
    'transport validation forbids undeclared AIA certificate downloads'
Assert-Equal 'NoCheck' ([string] $offlinePolicy.RevocationMode) `
    'transport validation cannot contact an undeclared revocation endpoint'
Assert-Equal ([TimeSpan]::Zero) $offlinePolicy.UrlRetrievalTimeout `
    'offline chain lookup has no URL retrieval allowance'

$tlsSource = ${function:Invoke-MicrosoftConnectivityTlsPhase}.ToString()
$httpSource = ${function:Invoke-MicrosoftConnectivityHttpPhase}.ToString()
Assert-Equal $true ($tlsSource.Contains('CertificateChainPolicy')) `
    'the direct TLS transport receives the offline chain policy before handshake'
Assert-Equal $true ($httpSource.Contains('CertificateChainPolicy')) `
    'the HTTP TLS transport receives the offline chain policy before send'
Assert-Equal $false ($tlsSource.Contains('X509Chain]::new')) `
    'no unbounded second chain build runs after the transport handshake'
Assert-Equal $false ($httpSource -match '(?m)^\s*[^#\r\n]*\.(GetProxy|IsBypassed)\s*\(') `
    'proxy policy is evaluated only inside the cancellable HTTP send'

$overflowStatuses = @(1..16 | ForEach-Object {
    [pscustomobject]@{ Status = ('ProviderStatus{0}{1}' -f $_, ('x' * 40)) }
})
$boundedStatuses = Get-MicrosoftConnectivityBoundedChainStatusCodes `
    -Statuses $overflowStatuses
Assert-Equal 'StatusSetTruncated' $boundedStatuses `
    'oversized provider chain status text maps to a bounded controlled value'
Assert-Equal $true ([Text.Encoding]::UTF8.GetByteCount($boundedStatuses) -le 256) `
    'mapped provider status evidence remains inside the payload contract'

$proxyFailure = New-MicrosoftConnectivityHttpFailureResult `
    -Exception ([TimeoutException]::new('synthetic timeout')) `
    -TransportMode WindowsProxy -ProxyState Evaluated
Assert-Equal 'TimedOut' $proxyFailure.state `
    'a bounded proxy send timeout remains a typed transport failure'
Assert-Equal 'WindowsProxy' $proxyFailure.transportMode `
    'a proxy failure cannot be relabeled as direct transport'
Assert-Equal 'Evaluated' $proxyFailure.proxyState `
    'failed sends preserve that Windows proxy policy participated'

$dns = Invoke-MicrosoftConnectivityDnsPhase -DnsName 'localhost' `
    -DeadlineMilliseconds 2000 -MaximumAddresses 8
Assert-Equal 'Succeeded' $dns.state `
    'the production DNS primitive completes against the local host database'
Assert-Equal $true ($dns.count -ge 1 -and $dns.count -le 8) `
    'the production DNS primitive applies its address bound'

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
try {
    $listener.Start()
    $port = ([Net.IPEndPoint] $listener.LocalEndpoint).Port
    $tcp = Invoke-MicrosoftConnectivityTcpPhase -DnsName '127.0.0.1' `
        -Port $port -DeadlineMilliseconds 2000
    Assert-Equal 'Succeeded' $tcp.state `
        'the production cancellable TCP primitive succeeds against a local listener'
}
finally { $listener.Stop() }

Write-Output 'PASS: Native connectivity primitives enforce offline trust, bounded provider evidence, cancellation, and proxy failure attribution.'
