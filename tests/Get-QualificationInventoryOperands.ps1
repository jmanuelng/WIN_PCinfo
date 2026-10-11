[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ManifestPath,
    [Parameter(Mandatory)] [string] $CandidatePath,
    [Parameter(Mandatory)] [string] $HarnessPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QualificationDiskBounds.ps1')

# This diagnostic describes the two operands independently. It does not admit
# instrumentation, rebind the inventory, or execute either input file.
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$declared = @{}
foreach ($name in @('sourceIdentityKind', 'candidateSha256', 'harnessSha256')) {
    $property = $manifest.PSObject.Properties[$name]
    $declared[$name] = if ($null -ne $property) { $property.Value } else { $null }
}
$candidateActual = (Get-FileHash -LiteralPath $CandidatePath -Algorithm SHA256).Hash.ToLowerInvariant()
$harnessActual = Get-QualificationScriptIdentity -LiteralPath $HarnessPath
$candidateDeclarationValid = $declared.candidateSha256 -is [string] -and
    $declared.candidateSha256 -cmatch '^[0-9a-f]{64}$'
$harnessDeclarationValid = $declared.harnessSha256 -is [string] -and
    $declared.harnessSha256 -cmatch '^[0-9a-f]{64}$'
$kindMatches = $declared.sourceIdentityKind -is [string] -and
    $declared.sourceIdentityKind -ceq 'CanonicalUtf8LfSha256'
$candidateMatches = $candidateDeclarationValid -and $declared.candidateSha256 -ceq $candidateActual
$harnessMatches = $harnessDeclarationValid -and $declared.harnessSha256 -ceq $harnessActual
[pscustomobject][ordered]@{
    kind = 'QualificationInventoryOperandComparison'
    sourceIdentityKindMatches = [bool]$kindMatches
    candidateDeclarationValid = [bool]$candidateDeclarationValid
    candidateExpectedSha256 = $declared.candidateSha256
    candidateActualSha256 = $candidateActual
    candidateMatches = [bool]$candidateMatches
    harnessDeclarationValid = [bool]$harnessDeclarationValid
    harnessExpectedCanonicalSha256 = $declared.harnessSha256
    harnessActualCanonicalSha256 = $harnessActual
    harnessMatches = [bool]$harnessMatches
    identityOperandsMatch = [bool]($kindMatches -and $candidateMatches -and $harnessMatches)
    qualificationAccepted = $false
}
