[CmdletBinding()]
param([string[]]$Scenario=@('Complete','DeniedUser','DeniedAllUsers','MsiDenied','MsiCompilerDenied','AlternateAdministrator','Composite','Ambiguous','OrderReversed','Withdrawn','LogicalFailure'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path (Split-Path $PSScriptRoot) 'artifacts/WIN-PCInfo.ps1')
foreach($case in $Scenario){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    & $hostPath -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -SoftwareSourceScenario $case
    if($LASTEXITCODE -ne 0){throw "Generated software source scenario $case failed."}
    Write-Output ('PASS: software source {0}; elapsed seconds {1:N1}.' -f $case,$watch.Elapsed.TotalSeconds)
}
