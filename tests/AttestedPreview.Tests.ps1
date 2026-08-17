[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'build/TextCanonicalization.ps1')

function Get-Sha256Hex {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Assert-True {
    param([bool] $Condition, [string] $Because)
    if (-not $Condition) { throw "Assertion failed: $Because" }
}

function Assert-NoRestrictedMaterial {
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [string] $Because)
    $needles = @(
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
        '(?i)\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+\\'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)\.terraform[/\\]'
        '(?i)AKIA[0-9A-Z]{16}'
        '(?i)clientSecret\s*[:=]\s*\S+'
    )
    foreach ($needle in $needles) {
        Assert-Equal $false ($Text -match $needle) "$Because must not contain restricted material matching $needle"
    }
}

$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-attested-preview.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/attested-preview.schema.json'
$attestationSchemaPath = Join-Path $repositoryRoot 'schemas/attested-preview-attestation.schema.json'
Assert-Equal $true (Test-Path -LiteralPath $policyPath -PathType Leaf) `
    'the Attested Preview contract is release-declared'
Assert-Equal $true (Test-Path -LiteralPath $schemaPath -PathType Leaf) `
    'the Attested Preview contract has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $attestationSchemaPath -PathType Leaf) `
    'the attestation document has a closed public schema'

$policyJson = Get-Content -LiteralPath $policyPath -Raw
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the Attested Preview contract satisfies its exact schema'
$policy = $policyJson | ConvertFrom-Json -Depth 20
Assert-Equal 'AttestedPreview' $policy.trustClass 'the fallback trust class is Attested Preview'
Assert-Equal $true $policy.unsigned 'the fallback remains unsigned'
Assert-Equal $true $policy.limitedTrust 'the fallback is limited-trust'
Assert-Equal $false $policy.signed 'the fallback is never labeled signed'
Assert-Equal $false $policy.trusted 'the fallback is never labeled Trusted'
Assert-Equal $false $policy.supported 'the fallback is never labeled Supported'
Assert-Equal $false $policy.satisfiesStableSigningGate `
    'an Attested Preview cannot satisfy the Stable signing gate'
Assert-Equal 'None' $policy.supportClaim 'the fallback makes no support claim'
Assert-Equal $true $policy.attestedPackageIsFinalDistributableIdentity `
    'the attested unsigned package is the final distributable identity'
Assert-Equal 'WIN-PCInfo-2.0.0-preview.1' $policy.archiveRootName `
    'the fallback names the portable archive root'
Assert-Equal $true $policy.fallback.neverForConvenience `
    'fallback selection is never permitted for convenience'
Assert-Equal 'ArtifactSigningNotOperational|VerifiedServiceIncident' `
    (@($policy.fallback.permittedReasons) -join '|') `
    'fallback is permitted only when Artifact Signing is not operational or during a verified service incident'
Assert-Equal $true $policy.warning.requiredBeforeLaunch `
    'the unsigned limited-trust warning is required before launch'

$entryScript = Get-Content -LiteralPath (Join-Path $repositoryRoot 'build/Attest-Preview.ps1') -Raw
Assert-Equal $true ($entryScript -match "ValidateSet\('ArtifactSigningNotOperational', 'VerifiedServiceIncident'\)") `
    'the attestation entry script admits only the two governed fallback reasons'
Assert-Equal $false ($entryScript -match 'Convenience') `
    'convenience is not an admitted fallback reason'

$workRoot = Join-Path $repositoryRoot '.test-output/attested-preview'
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $workRoot -Force

function Copy-IndependentBuildTree {
    param([Parameter(Mandatory)] [string] $DestinationRoot)
    $null = New-Item -ItemType Directory -Path $DestinationRoot -Force
    foreach ($directory in @('build', 'src', 'schemas', 'docs')) {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot $directory) `
            -Destination (Join-Path $DestinationRoot $directory) -Recurse
    }
    foreach ($file in @('SECURITY.md', 'CONTRIBUTING.md', 'README.md')) {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot $file) `
            -Destination (Join-Path $DestinationRoot $file)
    }
}

$firstRoot = Join-Path $workRoot 'work-a'
$secondRoot = Join-Path $workRoot 'work-b'
Copy-IndependentBuildTree -DestinationRoot $firstRoot
Copy-IndependentBuildTree -DestinationRoot $secondRoot

$firstApp = Join-Path $firstRoot 'out/WIN-PCInfo.ps1'
$secondApp = Join-Path $secondRoot 'out/WIN-PCInfo.ps1'
$first = & (Join-Path $firstRoot 'build/Build.ps1') -OutputPath $firstApp
$second = & (Join-Path $secondRoot 'build/Build.ps1') -OutputPath $secondApp

$firstZip = Join-Path (Split-Path -Parent $firstApp) ([string] $first.portablePackage.archiveFileName)
$secondZip = Join-Path (Split-Path -Parent $secondApp) ([string] $second.portablePackage.archiveFileName)
$firstZipBefore = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($firstZip))
$secondZipBefore = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($secondZip))
Assert-Equal $first.portablePackageIdentity.sha256 $firstZipBefore `
    'the portable candidate identity is the SHA-256 of the exact archive bytes'

$convenience = $null
try {
    $convenience = & (Join-Path $firstRoot 'build/Attest-Preview.ps1') `
        -FallbackReason 'Convenience' `
        -CandidateArchivePath $firstZip `
        -OutputDirectory (Join-Path $firstRoot 'out/attested-convenience')
}
catch {
    $convenience = $_
}
Assert-True ($null -ne $convenience) 'convenience fallback selection is rejected'
Assert-True (
    $convenience -is [System.Management.Automation.ErrorRecord] -or
        $convenience -is [System.Management.Automation.ParameterBindingException]
) 'convenience cannot produce an attestation bundle'

$overwriteCandidate = $null
try {
    $overwriteCandidate = & (Join-Path $firstRoot 'build/Attest-Preview.ps1') `
        -FallbackReason 'ArtifactSigningNotOperational' `
        -CandidateArchivePath $firstZip `
        -OutputDirectory $firstZip
}
catch {
    $overwriteCandidate = $_
}
Assert-True ($overwriteCandidate -is [System.Management.Automation.ErrorRecord]) `
    'attestation refuses an output path that is the candidate archive'
Assert-Equal $firstZipBefore (Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($firstZip))) `
    'a refused output path leaves the candidate archive unchanged'

$overwriteParent = $null
try {
    $overwriteParent = & (Join-Path $firstRoot 'build/Attest-Preview.ps1') `
        -FallbackReason 'ArtifactSigningNotOperational' `
        -CandidateArchivePath $firstZip `
        -OutputDirectory (Split-Path -Parent $firstZip)
}
catch {
    $overwriteParent = $_
}
Assert-True ($overwriteParent -is [System.Management.Automation.ErrorRecord]) `
    'attestation refuses an output directory that contains the candidate archive'
Assert-Equal $firstZipBefore (Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($firstZip))) `
    'a refused parent output directory leaves the candidate archive unchanged'

$firstAttest = & (Join-Path $firstRoot 'build/Attest-Preview.ps1') `
    -FallbackReason 'ArtifactSigningNotOperational' `
    -CandidateArchivePath $firstZip `
    -OutputDirectory (Join-Path $firstRoot 'out/attested')
$secondAttest = & (Join-Path $secondRoot 'build/Attest-Preview.ps1') `
    -FallbackReason 'ArtifactSigningNotOperational' `
    -CandidateArchivePath $secondZip `
    -OutputDirectory (Join-Path $secondRoot 'out/attested')

Assert-Equal $false $firstAttest.satisfiesStableSigningGate `
    'bundle evidence cannot satisfy the Stable signing gate'
Assert-Equal 'ArtifactSigningNotOperational' $firstAttest.fallbackReason `
    'the bundle records the governed fallback reason'
Assert-Equal $first.portablePackageIdentity.sha256 $firstAttest.candidateSha256 `
    'the bundle binds the exact portable candidate digest'
Assert-Equal $firstZipBefore (Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($firstZip))) `
    'attestation leaves the candidate archive bytes unchanged'
Assert-Equal $secondZipBefore (Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($secondZip))) `
    'a second independent attestation leaves its candidate unchanged'

$firstAttestationPath = Join-Path $firstAttest.bundleDirectory 'attestation.json'
$secondAttestationPath = Join-Path $secondAttest.bundleDirectory 'attestation.json'
$warningPath = Join-Path $firstAttest.bundleDirectory 'LIMITED-TRUST.md'
Assert-Equal $true (Test-Path -LiteralPath $firstAttestationPath -PathType Leaf) `
    'the bundle contains the attestation document'
Assert-Equal $true (Test-Path -LiteralPath $warningPath -PathType Leaf) `
    'the bundle contains the limited-trust warning page'
$firstAttestationBytes = [System.IO.File]::ReadAllBytes($firstAttestationPath)
$secondAttestationBytes = [System.IO.File]::ReadAllBytes($secondAttestationPath)
Assert-True ([System.Linq.Enumerable]::SequenceEqual[byte]($firstAttestationBytes, $secondAttestationBytes)) `
    'two clean independent work areas must produce identical attestation bytes'
Assert-Equal $firstAttest.attestationSha256 $secondAttest.attestationSha256 `
    'independent attestations record the same attestation digest'

$attestationJson = [System.Text.UTF8Encoding]::new($false, $true).GetString($firstAttestationBytes)
Assert-Equal $true (Test-Json -Json $attestationJson -SchemaFile $attestationSchemaPath) `
    'the attestation document satisfies its exact schema'
Assert-NoRestrictedMaterial -Text $attestationJson 'the attestation document'
$attestation = $attestationJson | ConvertFrom-Json -Depth 20
Assert-Equal 'win-pcinfo.attested-preview-attestation' $attestation.kind `
    'the attestation uses the Attested Preview kind'
Assert-Equal 'AttestedPreview' $attestation.trustClass 'the attestation trust class is Attested Preview'
Assert-Equal $true $attestation.unsigned 'the attestation remains unsigned'
Assert-Equal $true $attestation.limitedTrust 'the attestation is limited-trust'
Assert-Equal $false $attestation.signed 'the attestation is not signed'
Assert-Equal $false $attestation.trusted 'the attestation is not Trusted'
Assert-Equal $false $attestation.supported 'the attestation is not Supported'
Assert-Equal $false $attestation.satisfiesStableSigningGate `
    'the attestation cannot satisfy the Stable signing gate'
Assert-Equal 'None' $attestation.supportClaim 'the attestation makes no support claim'
Assert-Equal 'None' $attestation.previewOrStableClaim 'the attestation makes no Preview or Stable claim'
Assert-Equal $true $attestation.fallback.neverForConvenience `
    'the attestation records that convenience is forbidden'
Assert-Equal 'ArtifactSigningNotOperational' $attestation.fallback.reason `
    'the attestation records the selected governed reason'
Assert-Equal $first.portablePackageIdentity.sha256 $attestation.candidate.sha256 `
    'the attestation binds the unchanged portable-package identity'
Assert-Equal 'final-distributable-when-fallback-selected' $attestation.candidate.identityRole `
    'the attested unsigned package is the final distributable identity'
Assert-Equal $first.generatedContentIdentity.sha256 $attestation.generatedApplication.sha256 `
    'the attestation binds the generated application digest'
Assert-Equal $first.portablePackage.sourceRevisionSha256 $attestation.sourceRevision.sha256 `
    'the attestation binds the source revision'
Assert-Equal $true ($attestation.resourceManifest.sha256 -match '^[0-9a-f]{64}$') `
    'the attestation binds the resource manifest digest'
Assert-Equal $true ($attestation.checksums.sha256 -match '^[0-9a-f]{64}$') `
    'the attestation binds the checksum digest'
Assert-Equal $true ($attestation.dependencyInventory.sha256 -match '^[0-9a-f]{64}$') `
    'the attestation binds the dependency inventory digest'
Assert-Equal $true ($attestation.sbom.sha256 -match '^[0-9a-f]{64}$') `
    'the attestation binds the SBOM digest'
Assert-Equal $true ($attestation.buildProvenance.sha256 -match '^[0-9a-f]{64}$') `
    'the attestation binds build provenance'
Assert-Equal $first.buildTool.sha256 $attestation.buildProvenance.buildTool.sha256 `
    'the attestation binds the build-tool identity'
Assert-Equal $true ($attestationJson -match '"created":"1980-01-01T00:00:00Z"') `
    'the attestation uses the frozen precursor timestamp'

$warningText = Get-Content -LiteralPath $warningPath -Raw
Assert-Equal $true ($warningText -match [regex]::Escape([string] $policy.warning.title)) `
    'the warning page uses the contract warning title'
Assert-Equal $true ($warningText -match 'UNSIGNED LIMITED-TRUST WARNING') `
    'the warning page uses the unmistakable banner'
Assert-Equal $true ($warningText -match 'not Trusted') 'the warning page says the fallback is not Trusted'
Assert-Equal $true ($warningText -match 'not signed') 'the warning page says the fallback is not signed'
Assert-Equal $true ($warningText -match 'not Supported') 'the warning page says the fallback is not Supported'
Assert-Equal $true ($warningText -match 'cannot satisfy the Stable signing gate') `
    'the warning page refuses the Stable signing gate'
Assert-Equal $true (($warningText -match 'never') -and ($warningText -match 'convenience')) `
    'the warning page forbids convenience selection'
Assert-NoRestrictedMaterial -Text $warningText 'the limited-trust warning page'

$incident = & (Join-Path $firstRoot 'build/Attest-Preview.ps1') `
    -FallbackReason 'VerifiedServiceIncident' `
    -CandidateArchivePath $firstZip `
    -OutputDirectory (Join-Path $firstRoot 'out/attested-incident')
Assert-Equal 'VerifiedServiceIncident' $incident.fallbackReason `
    'a verified service incident is an admitted fallback reason'
$incidentJson = Get-Content -LiteralPath (Join-Path $incident.bundleDirectory 'attestation.json') -Raw
$incidentAttestation = $incidentJson | ConvertFrom-Json -Depth 20
Assert-Equal 'VerifiedServiceIncident' $incidentAttestation.fallback.reason `
    'the incident attestation records the verified-incident reason'

Write-Output "PASS: Attested Preview bundle $($firstAttest.attestationSha256) binds the unchanged candidate."
