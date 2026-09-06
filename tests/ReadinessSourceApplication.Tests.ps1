[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidate = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$hostPath = Resolve-WinPCInfoRuntime -ApplicationPath $candidate
$cases = @('Complete','Denied','NullLicense','MixedUnknownLicense','Bounded','Absent',
    'Unsupported','Malformed','Virtual','MicrosoftPhysical','FirmwareBounded',
    'TimedOut','MalformedOutput','OversizeOutput','Cancelled')
foreach ($case in $cases) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    & $hostPath -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -ReadinessSourceScenario $case
    if ($LASTEXITCODE -ne 0) { throw "Generated readiness source scenario $case failed." }
    Write-Output ('PASS: readiness source {0}; elapsed seconds {1:N1}.' -f $case, $watch.Elapsed.TotalSeconds)
}
