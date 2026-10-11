[CmdletBinding()]
param([string] $CandidatePath = '', [string] $PreparedManifestPath = '', [string] $PreparedManifestSha256 = '')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
Assert-QualificationCleanupReady
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidateUseError=$null
try {
if (-not $candidateContext.Prepared) {
    $PreparedManifestPath=Join-Path $candidateContext.OwnedDirectory 'prepared-test-candidate.json'
    [IO.File]::WriteAllText($PreparedManifestPath,((New-PreparedTestCandidateManifest -RepositoryRoot $repositoryRoot -CandidatePath $candidateContext.Path) | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    $PreparedManifestSha256=(Get-FileHash -LiteralPath $PreparedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-STA','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-Wpf',
    '-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
if ($LASTEXITCODE -ne 0) { throw 'The controlled generated WPF approval/report path failed.' }
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
