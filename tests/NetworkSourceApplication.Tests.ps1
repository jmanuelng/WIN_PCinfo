[CmdletBinding()]
param([ValidateSet('Complete','Disconnected','Denied','Partial','MalformedInterface','MalformedProxy','ProxyDenied','ProxyOversize')]
    [string[]]$Scenario=@('Complete','Disconnected','Denied','Partial','MalformedInterface','MalformedProxy','ProxyDenied','ProxyOversize'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1')
foreach ($case in $Scenario) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    & $hostPath -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -NetworkSourceScenario $case
    if ($LASTEXITCODE -ne 0) { throw "Generated network source scenario $case failed." }
    Write-Output ('PASS: network source {0}; elapsed seconds {1:N1}.' -f $case,$watch.Elapsed.TotalSeconds)
}
