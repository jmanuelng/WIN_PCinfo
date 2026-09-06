[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/CertificateTrust.ps1')
. (Join-Path $repositoryRoot 'src/MicrosoftConnectivity.ps1')

# Execute the release chain configuration/Build statement against a bounded
# certificate API adapter. No certificate, key, trust store or network is used.
$certificatePolicy=Get-CertificateTrustPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)
$source=Get-CertificateTrustLiveSource -Policy $certificatePolicy
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
$chainStatement=$ast.FindAll({param($node) $node -is [Management.Automation.Language.TryStatementAst] -and $node.Extent.Text.StartsWith('try{$chain.ChainPolicy.RevocationMode=')},$true)
Assert-Equal 1 @($chainStatement).Count 'one exact offline chain operation is exercised'
function Resolve-Chain { param($chain,$built) }
foreach ($downloadControlAvailable in @($true,$false)) {
    $script:attempts=0;$script:builds=0
    $chainPolicy=[pscustomobject]@{RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::Online}
    if ($downloadControlAvailable) { $chainPolicy|Add-Member NoteProperty DisableCertificateDownloads $false }
    $chain=[pscustomobject]@{ChainPolicy=$chainPolicy}
    $chain|Add-Member ScriptMethod Build {
        param($certificate)
        $script:builds++
        if (-not $this.ChainPolicy.PSObject.Properties['DisableCertificateDownloads'] -or
            -not $this.ChainPolicy.DisableCertificateDownloads -or
            $this.ChainPolicy.RevocationMode -ne [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck) { $script:attempts++ }
        $false
    }
    $chain|Add-Member ScriptMethod Dispose {}
    $certificate=$null
    try { & ([scriptblock]::Create($chainStatement[0].Extent.Text)) } catch {
        if ($downloadControlAvailable) { throw }
    }
    Assert-Equal 0 $script:attempts 'certificate chain configuration prevents hidden retrieval before Build'
    Assert-Equal $(if($downloadControlAvailable){1}else{0}) $script:builds 'missing offline capability stops before chain evaluation'
}

# The real LocalOnly collector branch must stop before DNS/TCP/TLS/proxy/HTTP
# adapter dispatch, including when callers explicitly select the Live path.
$script:attempts=0
function Invoke-MicrosoftConnectivityLiveProbe { param($Policy) $script:attempts++; throw 'Request boundary reached.' }
$policy=Get-MicrosoftConnectivityPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)
$result=Invoke-MicrosoftConnectivityCollection -Policy $policy -NetworkBehavior LocalOnly -Live
Assert-Equal 0 $script:attempts 'LocalOnly does not dispatch a request-capable adapter'
Assert-Equal 0 @($result.payload.endpointResults).Count 'LocalOnly produces no fabricated live probes'
Write-Output 'PASS: LocalOnly and offline chain evaluation prevent nested request adapter attempts.'
