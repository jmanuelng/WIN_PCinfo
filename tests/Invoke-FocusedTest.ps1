[CmdletBinding()]
param([Parameter(Mandatory)] [string] $RequestPath, [Parameter(Mandatory)] [string] $RequestSha256,
    [string] $CandidatePath, [string] $PreparedManifestPath, [string] $PreparedManifestSha256,
    [Parameter(Mandatory)] [DateTimeOffset] $AuthorityEnds,
    [long] $TimeoutMs=3600000, [long] $CleanupReserveMs=120000)

# Focused execution uses the same finite original-handle File root as the full
# gate. A selected driver result is always scoped and never full acceptance.
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'Run-Tests.ps1') -FocusedRequestPath $RequestPath -FocusedRequestSha256 $RequestSha256 `
    -CandidatePath $CandidatePath -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256 `
    -AuthorityEnds $AuthorityEnds -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs
