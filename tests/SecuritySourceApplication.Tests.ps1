[CmdletBinding()]
param([string[]]$Scenario=@('Active','Passive','Unsupported','ImportDenied','Denied','Unavailable',
    'NullRuntime','MalformedRuntime','FirewallPartial','AsrEmpty','AsrBound',
    'AsrMismatch','NetworkMissing','SmartScreenMissing','SmartScreenMalformed',
    'es-MX','tr-TR','ja-JP','ar-SA'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path (Split-Path $PSScriptRoot) 'artifacts/WIN-PCInfo.ps1')
foreach($case in $Scenario){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    & $hostPath -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -SecuritySourceScenario $case
    if($LASTEXITCODE -ne 0){throw "Generated security source scenario $case failed."}
    Write-Output ('PASS: security source {0}; elapsed seconds {1:N1}.' -f $case,$watch.Elapsed.TotalSeconds)
}
