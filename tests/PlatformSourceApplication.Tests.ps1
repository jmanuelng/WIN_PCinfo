[CmdletBinding()]
param([string[]]$Scenario=@('Running','Unencrypted','Configured','VbsPartial','VbsMalformed','BitLockerPartial','ProtectorBound','GpMalformed','WdacOld','WdacMalformed','WdacBound','CspDenied','CspMissing','CspMalformed','CspConflict','Denied','Unsupported','Unavailable'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path (Split-Path $PSScriptRoot) 'artifacts/WIN-PCInfo.ps1')
foreach($case in $Scenario){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    & $hostPath -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -PlatformSourceScenario $case
    if($LASTEXITCODE -ne 0){throw "Generated platform source scenario $case failed."}
    Write-Output ('PASS: platform source {0}; elapsed seconds {1:N1}.' -f $case,$watch.Elapsed.TotalSeconds)
}
