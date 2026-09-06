[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$runtime = Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path (Split-Path $PSScriptRoot) 'artifacts/WIN-PCInfo.ps1')
foreach ($outcome in @('AcceptedElevation','ElevationDenied')) {
    & $runtime -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -ReportContract -PrivilegeOutcome $outcome
    if ($LASTEXITCODE -ne 0) { throw "Comprehensive report contract failed for $outcome." }
}
