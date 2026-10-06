[CmdletBinding()]
param([ValidateSet('Bounded','BoundedMalformed','MissingEku','ValidTrusted','Expired','NotYetValid','Untrusted','IncompleteChain','MultipleCandidates','Denied','NativeDenied','Partial','AbsentPurpose','AlternateAdministrator')]
    [string[]]$Scenario=@('Bounded','BoundedMalformed','MissingEku','ValidTrusted','Expired','NotYetValid','Untrusted','IncompleteChain','MultipleCandidates','Denied','NativeDenied','Partial','AbsentPurpose','AlternateAdministrator'),
    [string]$CandidatePath='', [string]$PreparedManifestPath='', [string]$PreparedManifestSha256='')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
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
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath $candidateContext.Path
foreach($case in $Scenario){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    Invoke-QualificationTestProcess -HostPath $hostPath -Arguments @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-CertificateSourceScenario',$case,
        '-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
    if($LASTEXITCODE -ne 0){throw "Generated certificate source scenario $case failed."}
    Write-Output ('PASS: certificate source {0}; elapsed seconds {1:N1}.' -f $case,$watch.Elapsed.TotalSeconds)
}
}
catch { $candidateUseError=$_; throw }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
