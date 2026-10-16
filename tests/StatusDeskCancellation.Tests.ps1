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
foreach ($stage in @('Identity','Resource')) {
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),('-CancelAfter'+$stage),'-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
    if ($LASTEXITCODE -ne 0) { throw "The controlled cancellation after $stage failed." }
}
Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-CancelDuringPrivilege','-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
if ($LASTEXITCODE -ne 0) { throw 'Controlled cancellation inside the active privileged worker lost its partial package.' }
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
