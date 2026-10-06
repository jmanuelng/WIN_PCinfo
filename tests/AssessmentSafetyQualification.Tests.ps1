[CmdletBinding()]
param([string] $CandidatePath = '', [string] $PreparedManifestPath = '', [string] $PreparedManifestSha256 = '')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
Assert-QualificationCleanupReady
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$root = Join-Path $repositoryRoot ('.test-output/assessment-safety-' + [guid]::NewGuid().ToString('N'))
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidateUseError=$null
try {
if (-not $candidateContext.Prepared) {
    $PreparedManifestPath=Join-Path $candidateContext.OwnedDirectory 'prepared-test-candidate.json'
    [IO.File]::WriteAllText($PreparedManifestPath,((New-PreparedTestCandidateManifest -RepositoryRoot $repositoryRoot -CandidatePath $candidateContext.Path) | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    $PreparedManifestSha256=(Get-FileHash -LiteralPath $PreparedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
$preparedInput=@{CandidatePath=$candidateContext.Path; PreparedManifestPath=$PreparedManifestPath; PreparedManifestSha256=$PreparedManifestSha256}
$bodyError = $null
try {
    & (Join-Path $PSScriptRoot 'Invoke-AssessmentSafetyQualification.ps1') -Mode Safety -ResultDirectory $root @preparedInput
    & (Join-Path $PSScriptRoot 'Invoke-AssessmentSafetyQualification.ps1') -Mode Workers -ResultDirectory $root @preparedInput
    & (Join-Path $PSScriptRoot 'Invoke-AssessmentSafetyQualification.ps1') -Mode Sources -ResultDirectory $root @preparedInput
    & (Join-Path $PSScriptRoot 'Invoke-AssessmentSafetyQualification.ps1') -Mode Cultures -ResultDirectory $root @preparedInput
}
catch { $bodyError = $_ }
finally {
    Complete-QualificationHarness -BodyError $bodyError -RetainEvidence {
    if ($env:WINPCINFO_TEST_EVIDENCE -and [IO.Directory]::Exists($root)) {
        # Summaries contain only the existing minimized scope/state projections,
        # never packages, observations, plaintext reports or prohibited markers.
        foreach ($summary in @(Get-ChildItem -LiteralPath $root -Filter '*-summary.json' -File)) {
            Copy-Item -LiteralPath $summary.FullName -Destination (Join-Path $env:WINPCINFO_TEST_EVIDENCE $summary.Name)
        }
    }
    } -Cleanup @({
    if ($null -ne $bodyError -and (Test-QualificationCleanupUnverified -Exception $bodyError.Exception)) { throw 'Owned child cleanup remains unverified; preserve its qualification workspace.' }
    Assert-QualificationCleanupReady
    $resolved = [IO.Path]::GetFullPath($root)
    if ([IO.Path]::GetDirectoryName($resolved) -ne [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))) { throw 'Assessment safety cleanup escaped its parent.' }
    if ([IO.Directory]::Exists($resolved)) { [IO.Directory]::Delete($resolved, $true) }
    if ([IO.Directory]::Exists($resolved)) { throw 'Assessment safety owned directory absence could not be verified.' }
    })
}
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
