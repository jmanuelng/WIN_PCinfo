[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$runtime = Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path (Split-Path $PSScriptRoot) 'artifacts/WIN-PCInfo.ps1')
foreach ($outcome in @('AcceptedElevation','ElevationDenied')) {
    $arguments = @{ ReportContract = $true; PrivilegeOutcome = $outcome }
    if ($outcome -eq 'AcceptedElevation') { $arguments.SoftwareReportScenario = 'Maximum' }
    & $runtime -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') @arguments
    if ($LASTEXITCODE -ne 0) { throw "Comprehensive report contract failed for $outcome." }
}
