[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/MicrosoftConnectivity.ps1')

if (-not ('WinPCInfo.Tests.TlsLoopbackServer' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace WinPCInfo.Tests {
    public static class CallbackThreadProbe {
        public static bool Run(object capture) {
            return Task.Run(() => {
                using (RSA key = RSA.Create(2048)) {
                    var request = new CertificateRequest("CN=callback.test", key,
                        HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    using (X509Certificate2 certificate = request.CreateSelfSigned(
                        DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(10)))
                    using (var chain = new X509Chain()) {
                        chain.ChainPolicy.DisableCertificateDownloads = true;
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        chain.Build(certificate);
                        object result = capture.GetType().GetMethod("Validate").Invoke(capture,
                            new object[] { null, certificate, chain,
                                SslPolicyErrors.RemoteCertificateChainErrors });
                        byte[] raw = (byte[])capture.GetType().GetProperty("RawData").GetValue(capture);
                        return result is bool && !(bool)result && raw != null && raw.Length > 0;
                    }
                }
            }).GetAwaiter().GetResult();
        }
    }

    public sealed class TlsLoopbackServer : IDisposable {
        private readonly TcpListener listener;
        private readonly RSA rsa;
        private readonly X509Certificate2 certificate;
        private readonly SslStreamCertificateContext certificateContext;
        private readonly Task worker;
        public int Port { get; }
        public string Error { get; private set; }

        public TlsLoopbackServer() {
            rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", rsa,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(10));
            certificateContext = SslStreamCertificateContext.Create(certificate, null);
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            worker = Task.Run(() => Serve());
        }

        private void Serve() {
            try {
                using (TcpClient client = listener.AcceptTcpClient())
                using (var stream = new SslStream(client.GetStream(), false)) {
                    stream.AuthenticateAsServer(new SslServerAuthenticationOptions {
                        ServerCertificateContext = certificateContext,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        ClientCertificateRequired = false
                    });
                    byte[] buffer = new byte[4096];
                    stream.ReadTimeout = 2000;
                    try { stream.Read(buffer, 0, buffer.Length); } catch { }
                    byte[] response = Encoding.ASCII.GetBytes(
                        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    stream.Write(response, 0, response.Length);
                }
            } catch (Exception ex) { Error = ex.ToString(); }
        }

        public void Dispose() {
            listener.Stop();
            try { worker.Wait(3000); } catch { }
            certificate.Dispose();
            rsa.Dispose();
        }
    }
}
'@ | Out-Null
}

$policy = Get-MicrosoftConnectivityPolicy -ConvertFromJsonCommand (
    Get-Command ConvertFrom-Json -CommandType Cmdlet
)

$threadCapture = New-MicrosoftConnectivityCertificateCapture -Policy $policy
Assert-Equal $true ([WinPCInfo.Tests.CallbackThreadProbe]::Run($threadCapture)) `
    'the compiled certificate callback runs on a thread-pool thread without a PowerShell runspace'
Assert-Equal 'Invalid' $threadCapture.ChainState `
    'the runspace-independent callback preserves the platform chain error'

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
    'HTTP transport never invokes automatic proxy or PAC resolution'
Assert-Equal $false ($tlsSource.Contains('RemoteCertificateValidationCallback] {')) `
    'the asynchronous direct TLS callback is not a PowerShell scriptblock'
Assert-Equal $false ($httpSource.Contains('RemoteCertificateValidationCallback = {')) `
    'the asynchronous HTTP TLS callback is not a PowerShell scriptblock'

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
    -TransportMode WindowsProxy -ProxyState Used
Assert-Equal 'TimedOut' $proxyFailure.state `
    'a bounded proxy send timeout remains a typed transport failure'
Assert-Equal 'WindowsProxy' $proxyFailure.transportMode `
    'a proxy failure cannot be relabeled as direct transport'
Assert-Equal 'Used' $proxyFailure.proxyState `
    'failed sends preserve that Windows proxy policy participated'

$endpointUri = [Uri]::new('https://login.microsoftonline.com/')
$directSelection = Resolve-MicrosoftConnectivityProxySelection `
    -EndpointUri $endpointUri -ProxyEnabled $false -ProxyServer $null `
    -ProxyOverride $null -AutomaticConfigurationPresent $false
Assert-Equal 'Direct' $directSelection.transportMode `
    'disabled static proxy settings select an explicit direct transport'
Assert-Equal 'Bypassed' $directSelection.proxyState `
    'the direct selection is distinguished from an unavailable proxy decision'
$bypassSelection = Resolve-MicrosoftConnectivityProxySelection `
    -EndpointUri $endpointUri -ProxyEnabled $true -ProxyServer '127.0.0.1:9' `
    -ProxyOverride '*.microsoftonline.com' -AutomaticConfigurationPresent $false
Assert-Equal 'Direct' $bypassSelection.transportMode `
    'a bounded local bypass pattern selects direct transport'
$automaticSelection = Resolve-MicrosoftConnectivityProxySelection `
    -EndpointUri $endpointUri -ProxyEnabled $false -ProxyServer $null `
    -ProxyOverride $null -AutomaticConfigurationPresent $true
Assert-Equal $false $automaticSelection.supported `
    'PAC or WPAD configuration fails closed before an undeclared lookup'
Assert-Equal 'Indeterminate' $automaticSelection.transportMode `
    'unsupported automatic configuration is not mislabeled direct or proxied'

$loopbackEndpoint = [pscustomobject]@{
    dnsName = 'localhost'; uri = $null; port = 0
    http = [pscustomobject]@{ maximumHeaderBytes = 16384 }
}
$tlsServer = [WinPCInfo.Tests.TlsLoopbackServer]::new()
try {
    $loopbackEndpoint.port = $tlsServer.Port
    $tls = Invoke-MicrosoftConnectivityTlsPhase -Endpoint $loopbackEndpoint `
        -DeadlineMilliseconds 5000 -Policy $policy
    Assert-Equal 'Failed' $tls.state `
        'the production TLS phase preserves platform rejection of a test certificate'
    Assert-Equal $true ($tls.chainState -in @('Invalid', 'Unavailable')) `
        'the production TLS phase returns a typed platform result on loopback'
}
finally { $tlsServer.Dispose() }

$httpServer = [WinPCInfo.Tests.TlsLoopbackServer]::new()
try {
    $loopbackEndpoint.uri = "https://localhost:$($httpServer.Port)/"
    $http = Invoke-MicrosoftConnectivityHttpPhase -Endpoint $loopbackEndpoint `
        -DeadlineMilliseconds 5000 -Policy $policy -ProxySelection $directSelection
    Assert-Equal 'Failed' $http.state `
        'the production HTTP phase preserves platform rejection of a test certificate'
    Assert-Equal 'Direct' $http.transportMode `
        'the production HTTP phase retains the injected direct route decision'
    Assert-Equal 'Bypassed' $http.proxyState `
        'the production HTTP phase does not silently consult system proxy policy'
}
finally { $httpServer.Dispose() }

$staticProxy = Resolve-MicrosoftConnectivityProxySelection `
    -EndpointUri $endpointUri -ProxyEnabled $true -ProxyServer '127.0.0.1:1' `
    -ProxyOverride $null -AutomaticConfigurationPresent $false
$proxyEndpoint = [pscustomobject]@{
    uri = 'https://login.microsoftonline.com/'
    http = [pscustomobject]@{ maximumHeaderBytes = 16384 }
}
$failedProxySend = Invoke-MicrosoftConnectivityHttpPhase -Endpoint $proxyEndpoint `
    -DeadlineMilliseconds 1000 -Policy $policy -ProxySelection $staticProxy
Assert-Equal 'WindowsProxy' $failedProxySend.transportMode `
    'an unavailable static proxy remains attributed to the proxy transport'
Assert-Equal 'Used' $failedProxySend.proxyState `
    'an unavailable static proxy is not relabeled as direct after send failure'

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
