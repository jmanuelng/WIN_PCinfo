[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('ArtifactSigningNotOperational', 'VerifiedServiceIncident')]
    [string] $FallbackReason,

    [Parameter()]
    [string] $CandidateArchivePath,

    [Parameter()]
    [string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Attested Preview is a governed unsigned fallback, not the ordinary build
# output. The threat is selecting it because signing is inconvenient or
# treating checksums as Authenticode. The mechanism is this separate entry
# script whose reason set admits only Artifact Signing outage or a verified
# service incident. The trust assumption is that the already built portable
# zip is the exact candidate and is not rewritten. Safe failure is to refuse
# the bundle; this script never mutates the zip and never claims Trusted,
# signed, or Supported.
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TextCanonicalization.ps1')
. (Join-Path $PSScriptRoot 'PortableDistribution.ps1')
. (Join-Path $PSScriptRoot 'AttestedPreview.ps1')

$portablePolicy = Get-PortableDistributionPolicy -RepositoryRoot $repositoryRoot
if ([string]::IsNullOrWhiteSpace($CandidateArchivePath)) {
    $CandidateArchivePath = Join-Path $repositoryRoot (
        'artifacts/' + [string] $portablePolicy.archiveFileName
    )
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot (
        'artifacts/' + [string] $portablePolicy.archiveRootName + '-attested-preview'
    )
}

New-AttestedPreviewBundle -FallbackReason $FallbackReason `
    -CandidateArchivePath $CandidateArchivePath `
    -OutputDirectory $OutputDirectory `
    -RepositoryRoot $repositoryRoot
