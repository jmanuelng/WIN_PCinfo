[CmdletBinding()]
param([string[]]$Scenario=@('Configured','Absent','Denied','Unsupported','Malformed','Partial','Unavailable','UnknownContext','Windows10','Stopped','tr-TR'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path (Split-Path $PSScriptRoot) 'artifacts/WIN-PCInfo.ps1')
foreach($case in $Scenario){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    & $hostPath -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -RemoteSourceScenario $case
    if($LASTEXITCODE -ne 0){throw "Generated remote source scenario $case failed."}
    Write-Output ('PASS: update/remote/auth source {0}; elapsed seconds {1:N1}.' -f $case,$watch.Elapsed.TotalSeconds)
}
