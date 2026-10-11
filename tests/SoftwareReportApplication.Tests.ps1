[CmdletBinding()]
param([string[]]$Scenario=@('Maximum','Distinct','EscapedOverflow'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$hostPath=Get-TestAdmittedRuntimeHost
foreach($case in $Scenario){
    Invoke-QualificationTestProcess -HostPath $hostPath -Arguments @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-SoftwareReportScenario',$case)
    if($LASTEXITCODE -ne 0){throw "Generated software report case $case failed."}
    Write-Output "PASS: generated software report $case."
}
