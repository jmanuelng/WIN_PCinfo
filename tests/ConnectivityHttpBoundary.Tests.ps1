[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/MicrosoftConnectivity.ps1')
$policy=Get-MicrosoftConnectivityPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)
# Execute the production HTTP phase with objects at the .NET transport boundary.
# There is no socket, certificate, trust operation or live endpoint request.
$source=${function:Invoke-MicrosoftConnectivityHttpPhase}.ToString()
foreach($replacement in @(
    @('[Net.Http.SocketsHttpHandler]::new()','(New-ControlledHttpHandler)'),
    @('[Net.Http.HttpClient]::new($handler, $false)','(New-ControlledHttpClient $handler)'),
    @('New-MicrosoftConnectivityCertificateCapture -Policy $Policy','(New-ControlledCapture)'),
    @("[Delegate]::CreateDelegate(`n            [Net.Security.RemoteCertificateValidationCallback], `$capture, 'Validate'`n        )",'$null')
)) {
    $source=$source.Replace("`r`n","`n")
    if(-not $source.Contains($replacement[0])){throw 'The declared controlled HTTP boundary changed.'}
    $source=$source.Replace($replacement[0],$replacement[1])
}
. ([scriptblock]::Create('function Invoke-ControlledHttpPhase {'+$source+'}'))
function New-ControlledCapture { [pscustomobject]@{RawData=$null} }
function New-ControlledHttpHandler {
    $handler=[pscustomobject]@{UseProxy=$false;Proxy=$null;Credentials='not cleared';DefaultProxyCredentials='not cleared';UseCookies=$true;AllowAutoRedirect=$true;MaxResponseHeadersLength=0;SslOptions=$null}
    $handler|Add-Member ScriptMethod Dispose {$script:disposed++}
    $handler
}
function New-ControlledHttpClient {
    param($handler)
    $client=[pscustomobject]@{Handler=$handler;Timeout=$null}
    $client|Add-Member ScriptMethod Dispose {$script:disposed++}
    $client|Add-Member ScriptMethod SendAsync {
        param($request,$completion,$token)
        $script:sends++
        if($this.Handler.AllowAutoRedirect -or $this.Handler.UseCookies -or $null -ne $this.Handler.Credentials -or
            $null -ne $this.Handler.DefaultProxyCredentials -or $request.Method -ne 'HEAD' -or
            $null -ne $request.Content -or $completion -ne 'ResponseHeadersRead' -or
            -not $this.Handler.SslOptions.CertificateChainPolicy.DisableCertificateDownloads -or
            $this.Handler.SslOptions.CertificateChainPolicy.RevocationMode -ne 'NoCheck' -or
            $this.Handler.MaxResponseHeadersLength -ne 16){throw 'Unsafe transport options.'}
        if($script:caseStatus -eq 0){throw [TimeoutException]::new('Synthetic timeout')}
        $headers=@(1..$script:headerCount)
        $response=[pscustomobject]@{StatusCode=$script:caseStatus;Headers=$headers;Content=[pscustomobject]@{Headers=@()}}
        $response|Add-Member ScriptMethod Dispose {$script:disposed++}
        $task=[pscustomobject]@{Response=$response}
        $task|Add-Member ScriptMethod GetAwaiter { $this }
        $task|Add-Member ScriptMethod GetResult { $this.Response }
        $task
    }
    $client
}
$selection=[pscustomobject]@{supported=$true;transportMode='WindowsProxy';proxyState='Used';proxy=[Net.WebProxy]::new('http://192.0.2.80:8080/')}
foreach($case in @(
    @{status=407;expected='Blocked';headers=3},
    @{status=204;expected='Succeeded';headers=3},
    @{status=302;expected='RedirectRejected';headers=3},
    @{status=307;expected='RedirectRejected';headers=3},
    @{status=503;expected='Failed';headers=3},
    @{status=0;expected='TimedOut';headers=3},
    @{status=200;expected='Failed';headers=33}
)){
    $script:caseStatus=$case.status;$script:headerCount=$case.headers;$script:sends=0;$script:disposed=0
    $result=Invoke-ControlledHttpPhase -Endpoint $policy.endpoints[0] -DeadlineMilliseconds 5000 -Policy $policy -ProxySelection $selection
    Assert-Equal $case.expected $result.state 'actual HTTP reduction classifies status, bounds and timeout'
    Assert-Equal 1 $script:sends 'redirect/authentication/failure never initiates a second request'
    Assert-Equal $(if($case.status -eq 0){2}else{3}) $script:disposed 'all owned response and transport objects are disposed'
    Assert-Equal 'WindowsProxy' $result.transportMode 'transport failures retain approved proxy context'
}
Write-Output 'PASS: production HTTP phase enforces no credentials, cookies, body, redirect or chain retrieval, typed statuses, finite metadata and disposal.'
