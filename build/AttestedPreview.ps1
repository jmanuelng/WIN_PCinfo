function Get-AttestedPreviewPolicy {
    param([Parameter(Mandatory)] [string] $RepositoryRoot)

    $path = Join-Path $RepositoryRoot 'docs/spec/releases/2.0.0-preview.1-attested-preview.json'
    Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 20
}

function Get-AttestedPreviewLimitedTrustMarkdown {
    param([Parameter(Mandatory)] $Policy)

    @(
        '# UNSIGNED LIMITED-TRUST WARNING'
        ''
        'This Attested Preview is **not Trusted**, **not signed**, **not Supported**,'
        'and **not Authenticode**. It cannot satisfy the Stable signing gate.'
        ''
        'It is a governed unsigned fallback. Select it only when Artifact Signing is'
        'genuinely not operational or during a recorded verified service incident.'
        'Never select this fallback for convenience.'
        ''
        'The attested unsigned portable package remains the final distributable'
        'identity. Checksums and provenance bind that unchanged package. A missing,'
        'conflicting, substituted, or altered input fails verification. There is no'
        'run-anyway switch.'
        ''
        "Policy: $($Policy.policyId)"
        "Trust class: $($Policy.trustClass)"
        ''
    ) -join "`n"
}

function Get-AttestedPreviewZipEntryBytes {
    param(
        [Parameter(Mandatory)] [string] $ZipPath,
        [Parameter(Mandatory)] [string] $EntryName
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $entry = $archive.GetEntry($EntryName)
        if ($null -eq $entry) {
            return $null
        }
        $stream = $entry.Open()
        try {
            $memory = [System.IO.MemoryStream]::new()
            $stream.CopyTo($memory)
            , $memory.ToArray()
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }
}

function New-AttestedPreviewBundle {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ArtifactSigningNotOperational', 'VerifiedServiceIncident')]
        [string] $FallbackReason,
        [Parameter(Mandatory)] [string] $CandidateArchivePath,
        [Parameter(Mandatory)] [string] $OutputDirectory,
        [Parameter(Mandatory)] [string] $RepositoryRoot
    )

    # The threat is publishing an unsigned package as if it were signed, or
    # selecting this fallback because signing is inconvenient. The mechanism is
    # an explicit two-reason ValidateSet plus SHA-256 bindings of one already
    # built portable candidate. The trust assumption is that those candidate
    # bytes were produced by the deterministic build and are not rewritten
    # here. Safe failure is to refuse the bundle rather than emit a weaker
    # identity or mutate the zip.
    $policy = Get-AttestedPreviewPolicy -RepositoryRoot $RepositoryRoot
    if (-not (Test-Path -LiteralPath $CandidateArchivePath -PathType Leaf)) {
        throw 'The Attested Preview candidate archive is missing.'
    }

    $portablePolicyPath = Join-Path $RepositoryRoot `
        'docs/spec/releases/2.0.0-preview.1-portable-distribution.json'
    $portablePolicy = Get-Content -LiteralPath $portablePolicyPath -Raw | ConvertFrom-Json -Depth 20
    $archiveRoot = [string] $portablePolicy.archiveRootName
    $zipBytes = [System.IO.File]::ReadAllBytes($CandidateArchivePath)
    $candidateDigest = Get-PortableDistributionSha256 -Bytes $zipBytes

    $requiredEntries = [ordered]@{
        generatedApplication = "$archiveRoot/WIN-PCInfo.ps1"
        resourceManifest = "$archiveRoot/package-manifest.json"
        checksums = "$archiveRoot/checksums.sha256"
        buildProvenance = "$archiveRoot/provenance.json"
        dependencyInventory = "$archiveRoot/dependency-inventory.json"
        sbom = "$archiveRoot/sbom.spdx.json"
    }
    $entryBytes = @{}
    foreach ($key in @($requiredEntries.Keys)) {
        $bytes = Get-AttestedPreviewZipEntryBytes -ZipPath $CandidateArchivePath `
            -EntryName $requiredEntries[$key]
        if ($null -eq $bytes) {
            throw "The Attested Preview candidate is missing $($requiredEntries[$key])."
        }
        $entryBytes[$key] = [byte[]] $bytes
    }

    $manifest = [System.Text.UTF8Encoding]::new($false, $true).GetString(
        $entryBytes.resourceManifest
    ) | ConvertFrom-Json -Depth 20
    $provenance = [System.Text.UTF8Encoding]::new($false, $true).GetString(
        $entryBytes.buildProvenance
    ) | ConvertFrom-Json -Depth 20
    $applicationDigest = Get-PortableDistributionSha256 -Bytes $entryBytes.generatedApplication
    if ([string] $provenance.generatedContent.sha256 -ne $applicationDigest -or
        [string] $manifest.unsignedGeneratedContentIdentity.sha256 -ne $applicationDigest) {
        throw 'The candidate application digest conflicts with package provenance.'
    }
    $sourceRevision = [string] $provenance.sourceRevision.sha256
    if ([string] $manifest.sourceRevision.sha256 -ne $sourceRevision) {
        throw 'The candidate source revision conflicts between manifest and provenance.'
    }

    $warningText = Get-AttestedPreviewLimitedTrustMarkdown -Policy $policy
    $attestation = [pscustomobject][ordered]@{
        kind = 'win-pcinfo.attested-preview-attestation'
        contractVersion = '1.0.0'
        release = [string] $policy.release
        policyId = [string] $policy.policyId
        trustClass = 'AttestedPreview'
        unsigned = $true
        limitedTrust = $true
        signed = $false
        trusted = $false
        supported = $false
        satisfiesStableSigningGate = $false
        supportClaim = 'None'
        previewOrStableClaim = 'None'
        fallback = [pscustomobject][ordered]@{
            selected = $true
            permittedReasons = @($policy.fallback.permittedReasons)
            neverForConvenience = $true
            reason = $FallbackReason
        }
        candidate = [pscustomobject][ordered]@{
            kind = 'win-pcinfo.unsigned-portable-package-identity'
            archiveFileName = [string] $portablePolicy.archiveFileName
            sha256 = $candidateDigest
            identityRole = 'final-distributable-when-fallback-selected'
        }
        generatedApplication = [pscustomobject][ordered]@{
            path = 'WIN-PCInfo.ps1'
            sha256 = $applicationDigest
        }
        sourceRevision = [pscustomobject][ordered]@{
            kind = 'content-tree'
            sha256 = $sourceRevision
        }
        resourceManifest = [pscustomobject][ordered]@{
            path = 'package-manifest.json'
            sha256 = (Get-PortableDistributionSha256 -Bytes $entryBytes.resourceManifest)
        }
        checksums = [pscustomobject][ordered]@{
            path = 'checksums.sha256'
            sha256 = (Get-PortableDistributionSha256 -Bytes $entryBytes.checksums)
        }
        dependencyInventory = [pscustomobject][ordered]@{
            path = 'dependency-inventory.json'
            sha256 = (Get-PortableDistributionSha256 -Bytes $entryBytes.dependencyInventory)
        }
        sbom = [pscustomobject][ordered]@{
            path = 'sbom.spdx.json'
            sha256 = (Get-PortableDistributionSha256 -Bytes $entryBytes.sbom)
        }
        buildProvenance = [pscustomobject][ordered]@{
            path = 'provenance.json'
            sha256 = (Get-PortableDistributionSha256 -Bytes $entryBytes.buildProvenance)
            buildTool = [pscustomobject][ordered]@{
                path = [string] $provenance.buildTool.path
                sha256 = [string] $provenance.buildTool.sha256
            }
        }
        warning = [pscustomobject][ordered]@{
            required = $true
            id = 'UNSIGNED_LIMITED_TRUST'
            path = 'LIMITED-TRUST.md'
        }
        created = '1980-01-01T00:00:00Z'
    }

    $attestationSchemaPath = Join-Path $RepositoryRoot `
        'schemas/attested-preview-attestation.schema.json'
    $attestationJson = $attestation | ConvertTo-Json -Compress -Depth 40
    if (-not (Test-Json -Json $attestationJson -SchemaFile $attestationSchemaPath)) {
        throw 'The Attested Preview attestation does not satisfy its release schema.'
    }

    if (Test-Path -LiteralPath $OutputDirectory) {
        Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
    $attestationBytes = ConvertTo-DeterministicJsonBytes -Value $attestation
    $attestationPath = Join-Path $OutputDirectory 'attestation.json'
    $warningPath = Join-Path $OutputDirectory 'LIMITED-TRUST.md'
    [System.IO.File]::WriteAllBytes($attestationPath, [byte[]] $attestationBytes)
    [System.IO.File]::WriteAllBytes(
        $warningPath,
        [System.Text.UTF8Encoding]::new($false).GetBytes($warningText)
    )

    [pscustomobject]@{
        bundleDirectory = $OutputDirectory
        attestationPath = $attestationPath
        candidateSha256 = $candidateDigest
        attestationSha256 = Get-PortableDistributionSha256 -Bytes $attestationBytes
        fallbackReason = $FallbackReason
        satisfiesStableSigningGate = $false
    }
}
