[CmdletBinding()]
param([ValidateSet('Direct','WindowsProxy','ProxyOnly','ProxyInvalidChain','ProxyTlsFailure','Suspected','Blocked','Partial','DnsFailure','Timeout','InvalidChain','Redirect','ProxyBlocked','AutomaticProxy','ContextChanged','LocalOnly')]
    [string[]]$Scenario=@('Direct','WindowsProxy','ProxyOnly','ProxyInvalidChain','ProxyTlsFailure','Suspected','Blocked','Partial','DnsFailure','Timeout','InvalidChain','Redirect','ProxyBlocked','AutomaticProxy','ContextChanged','LocalOnly'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1')
foreach($case in $Scenario){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    & $hostPath -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -ConnectivitySourceScenario $case
    if($LASTEXITCODE -ne 0){throw "Generated connectivity source $case failed."}
    Write-Output ('PASS: connectivity source {0}; elapsed seconds {1:N1}.' -f $case,$watch.Elapsed.TotalSeconds)
}
