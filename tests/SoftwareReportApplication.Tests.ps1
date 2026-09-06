[CmdletBinding()]
param([string[]]$Scenario=@('Maximum','Distinct','EscapedOverflow'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path (Split-Path $PSScriptRoot) 'artifacts/WIN-PCInfo.ps1')
foreach($case in $Scenario){
    & $hostPath -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -SoftwareReportScenario $case
    if($LASTEXITCODE -ne 0){throw "Generated software report case $case failed."}
    Write-Output "PASS: generated software report $case."
}
