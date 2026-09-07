[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$root = Join-Path $repositoryRoot ('.test-output/assessment-safety-' + [guid]::NewGuid().ToString('N'))
try {
    & (Join-Path $PSScriptRoot 'Invoke-AssessmentSafetyQualification.ps1') -Mode Safety -ResultDirectory $root
    & (Join-Path $PSScriptRoot 'Invoke-AssessmentSafetyQualification.ps1') -Mode Workers -ResultDirectory $root
    & (Join-Path $PSScriptRoot 'Invoke-AssessmentSafetyQualification.ps1') -Mode Sources -ResultDirectory $root
    & (Join-Path $PSScriptRoot 'Invoke-AssessmentSafetyQualification.ps1') -Mode Cultures -ResultDirectory $root
}
finally {
    if ($env:WINPCINFO_TEST_EVIDENCE -and [IO.Directory]::Exists($root)) {
        # Summaries contain only the existing minimized scope/state projections,
        # never packages, observations, plaintext reports or prohibited markers.
        foreach ($summary in @(Get-ChildItem -LiteralPath $root -Filter '*-summary.json' -File)) {
            Copy-Item -LiteralPath $summary.FullName -Destination (Join-Path $env:WINPCINFO_TEST_EVIDENCE $summary.Name)
        }
    }
    $resolved = [IO.Path]::GetFullPath($root)
    if ([IO.Path]::GetDirectoryName($resolved) -ne [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))) { throw 'Assessment safety cleanup escaped its parent.' }
    if ([IO.Directory]::Exists($resolved)) { [IO.Directory]::Delete($resolved, $true) }
}
