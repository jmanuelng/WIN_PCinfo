# Build.ps1 replaces both sentinels with the release-bound Attested Preview
# policy and its SHA-256 digest. The running application treats that policy as
# the closed fallback contract.
$script:AttestedPreviewPolicyBase64 = '__ATTESTED_PREVIEW_POLICY_BASE64__'
$script:AttestedPreviewPolicyDigest = '__ATTESTED_PREVIEW_POLICY_SHA256__'

function Get-AttestedPreviewFileDigest {
    param([Parameter(Mandatory)] $Bytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        [System.Convert]::ToHexString($sha256.ComputeHash([byte[]] $Bytes)).ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-AttestedPreviewEmbeddedPolicy {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    # Adjacency to a zip is not a signature. The threat is a substituted
    # policy that relabels the fallback as Trusted or admits convenience.
    # The mechanism is an embedded path-free policy bound into the generated
    # application. The trust assumption is that those bytes were produced by
    # the deterministic build. Safe failure is to refuse verification.
    if ($script:AttestedPreviewPolicyBase64 -eq
        ('__ATTESTED_PREVIEW_POLICY_' + 'BASE64__')) {
        return [pscustomobject]@{ Valid = $false; Policy = $null }
    }

    try {
        $bytes = [System.Convert]::FromBase64String($script:AttestedPreviewPolicyBase64)
    }
    catch {
        return [pscustomobject]@{ Valid = $false; Policy = $null }
    }
    if ((Get-AttestedPreviewFileDigest -Bytes $bytes) -ne
        $script:AttestedPreviewPolicyDigest) {
        return [pscustomobject]@{ Valid = $false; Policy = $null }
    }

    try {
        $policy = & $ConvertFromJsonCommand -InputObject (
            [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        ) -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{ Valid = $false; Policy = $null }
    }

    [pscustomobject]@{ Valid = $true; Policy = $policy }
}

function Get-AttestedPreviewLimitedTrustWarning {
    param([Parameter()] $Policy)

    $title = if ($null -ne $Policy) {
        [string] $Policy.warning.title
    }
    else {
        'UNSIGNED LIMITED-TRUST WARNING — NOT TRUSTED, NOT SIGNED, NOT SUPPORTED'
    }
    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.limited-trust-warning'
        contractVersion = '1.0.0'
        severity = 'LimitedTrust'
        title = $title
        warning = 'This Attested Preview is not Trusted, not signed, not Supported, and not Authenticode. It cannot satisfy the Stable signing gate. Use it only when Artifact Signing is not operational or during a verified service incident, never for convenience.'
        unsigned = $true
        trusted = $false
        signed = $false
        supported = $false
        satisfiesStableSigningGate = $false
        trustClass = 'AttestedPreview'
        fallbackNeverForConvenience = $true
        collectionStarted = $false
    }
}

function Test-AttestedPreviewSatisfiesStableSigningGate {
    param([Parameter()] $Attestation)

    # Stable requires trusted Authenticode. Checksums, provenance, and this
    # unsigned fallback cannot become that gate. The threat is treating a
    # verified Attested Preview as a signed Stable artifact. The mechanism is
    # a function that is permanently false for this trust class. The trust
    # assumption is that later signing work uses Authenticode, not this
    # return value. Safe failure is to keep Stable unsatisfied.
    $false
}

function Get-AttestedPreviewArchiveEntryBytes {
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

function New-AttestedPreviewVerificationRecord {
    param(
        [Parameter(Mandatory)] [ValidateSet('Verified', 'Rejected')] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter()] $Attestation,
        [Parameter()] [bool] $EligibleForLaterSmokeOrValidation = $false
    )

    $record = [ordered]@{
        recordType = 'win-pcinfo.attested-preview-verification'
        contractVersion = '1.0.0'
        state = $State
        reasonCode = $ReasonCode
        trustClass = 'AttestedPreview'
        unsigned = $true
        limitedTrust = $true
        signed = $false
        trusted = $false
        supported = $false
        satisfiesStableSigningGate = $false
        supportClaim = 'None'
        previewOrStableClaim = 'None'
        fallbackNeverForConvenience = $true
        eligibleForLaterSmokeOrValidation = [bool] $EligibleForLaterSmokeOrValidation
        collectionStarted = $false
        guidance = [pscustomobject][ordered]@{
            nextStep = if ($State -eq 'Verified') {
                'This Attested Preview remains unsigned and limited-trust. It cannot satisfy the Stable signing gate. Only this exact verified candidate may proceed to later smoke or validation work.'
            }
            else {
                'Restore the exact attested candidate and bundle. There is no run-anyway switch. An Attested Preview is not Trusted, not signed, and not Supported.'
            }
        }
    }
    if ($null -ne $Attestation) {
        $record.fallbackReason = [string] $Attestation.fallback.reason
        $record.candidateSha256 = [string] $Attestation.candidate.sha256
        $record.generatedApplicationSha256 = [string] $Attestation.generatedApplication.sha256
        $record.sourceRevisionSha256 = [string] $Attestation.sourceRevision.sha256
        $record.resourceManifestSha256 = [string] $Attestation.resourceManifest.sha256
        $record.checksumsSha256 = [string] $Attestation.checksums.sha256
        $record.dependencyInventorySha256 = [string] $Attestation.dependencyInventory.sha256
        $record.sbomSha256 = [string] $Attestation.sbom.sha256
        $record.buildProvenanceSha256 = [string] $Attestation.buildProvenance.sha256
    }
    [pscustomobject] $record
}

function Test-AttestedPreviewLabelSafety {
    param([Parameter(Mandatory)] $Attestation)

    # Positive trust words in this document are claims, not English
    # description. The threat is relabeling an unsigned fallback as Trusted,
    # signed, or Supported so it could pass a later Stable gate. The
    # mechanism is a closed comparison of the recorded flags. The trust
    # assumption is that the operator reads the warning as well. Safe
    # failure is FORBIDDEN_CLAIM or STABLE_SIGNING_UNSATISFIED.
    if ([string] $Attestation.trustClass -ne 'AttestedPreview' -or
        [bool] $Attestation.signed -or
        [bool] $Attestation.trusted -or
        [bool] $Attestation.supported -or
        [string] $Attestation.supportClaim -eq 'Supported' -or
        [string] $Attestation.previewOrStableClaim -in @('Preview', 'Stable')) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.FORBIDDEN_CLAIM'
        }
    }
    if ([bool] $Attestation.satisfiesStableSigningGate -or
        (Test-AttestedPreviewSatisfiesStableSigningGate -Attestation $Attestation)) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.STABLE_SIGNING_UNSATISFIED'
        }
    }
    [pscustomobject]@{ Valid = $true; ReasonCode = 'ATTESTATION.VERIFIED' }
}

function Test-AttestedPreviewBundle {
    param(
        [Parameter()] [string] $AttestationBundlePath,
        [Parameter()] [string] $CandidateArchivePath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand
    )

    $policyResult = Get-AttestedPreviewEmbeddedPolicy -ConvertFromJsonCommand $ConvertFromJsonCommand
    if (-not $policyResult.Valid) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.INPUT_INVALID'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.INPUT_INVALID')
            Policy = $null
        }
    }
    $policy = $policyResult.Policy

    if ([string]::IsNullOrWhiteSpace($AttestationBundlePath) -or
        [string]::IsNullOrWhiteSpace($CandidateArchivePath)) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.INPUT_INVALID'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.INPUT_INVALID')
            Policy = $policy
        }
    }

    $attestationPath = Join-Path $AttestationBundlePath 'attestation.json'
    $warningPath = Join-Path $AttestationBundlePath 'LIMITED-TRUST.md'
    if (-not (Test-Path -LiteralPath $attestationPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $warningPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $CandidateArchivePath -PathType Leaf)) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.MISSING_INPUT'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.MISSING_INPUT')
            Policy = $policy
        }
    }

    try {
        $attestationText = [System.IO.File]::ReadAllText(
            $attestationPath,
            [System.Text.UTF8Encoding]::new($false, $true)
        )
        $attestation = & $ConvertFromJsonCommand -InputObject $attestationText -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.CONFLICTING_INPUT'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.CONFLICTING_INPUT')
            Policy = $policy
        }
    }

    $labelSafety = Test-AttestedPreviewLabelSafety -Attestation $attestation
    if (-not $labelSafety.Valid) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = $labelSafety.ReasonCode
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode $labelSafety.ReasonCode -Attestation $attestation)
            Policy = $policy
        }
    }

    $permitted = @($policy.fallback.permittedReasons)
    if (-not [bool] $attestation.fallback.neverForConvenience -or
        [string] $attestation.fallback.reason -notin $permitted) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.FALLBACK_REASON_INVALID'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.FALLBACK_REASON_INVALID' -Attestation $attestation)
            Policy = $policy
        }
    }

    $archiveRoot = 'WIN-PCInfo-2.0.0-preview.1'
    $boundFiles = @(
        [pscustomobject]@{
            Reason = 'ATTESTATION.APPLICATION_ALTERED'
            Entry = "$archiveRoot/WIN-PCInfo.ps1"
            Expected = [string] $attestation.generatedApplication.sha256
        }
        [pscustomobject]@{
            Reason = 'ATTESTATION.MANIFEST_ALTERED'
            Entry = "$archiveRoot/package-manifest.json"
            Expected = [string] $attestation.resourceManifest.sha256
        }
        [pscustomobject]@{
            Reason = 'ATTESTATION.CHECKSUM_ALTERED'
            Entry = "$archiveRoot/checksums.sha256"
            Expected = [string] $attestation.checksums.sha256
        }
        [pscustomobject]@{
            Reason = 'ATTESTATION.PROVENANCE_ALTERED'
            Entry = "$archiveRoot/provenance.json"
            Expected = [string] $attestation.buildProvenance.sha256
        }
        [pscustomobject]@{
            Reason = 'ATTESTATION.DEPENDENCY_INVENTORY_ALTERED'
            Entry = "$archiveRoot/dependency-inventory.json"
            Expected = [string] $attestation.dependencyInventory.sha256
        }
        [pscustomobject]@{
            Reason = 'ATTESTATION.SBOM_ALTERED'
            Entry = "$archiveRoot/sbom.spdx.json"
            Expected = [string] $attestation.sbom.sha256
        }
    )

    $entryBytes = @{}
    foreach ($bound in $boundFiles) {
        $bytes = Get-AttestedPreviewArchiveEntryBytes -ZipPath $CandidateArchivePath `
            -EntryName $bound.Entry
        if ($null -eq $bytes) {
            return [pscustomobject]@{
                Valid = $false
                ReasonCode = 'ATTESTATION.MISSING_INPUT'
                Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                    -ReasonCode 'ATTESTATION.MISSING_INPUT' -Attestation $attestation)
                Policy = $policy
            }
        }
        $entryBytes[$bound.Entry] = [byte[]] $bytes
        if ((Get-AttestedPreviewFileDigest -Bytes $bytes) -ne $bound.Expected) {
            return [pscustomobject]@{
                Valid = $false
                ReasonCode = $bound.Reason
                Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                    -ReasonCode $bound.Reason -Attestation $attestation)
                Policy = $policy
            }
        }
    }

    try {
        $manifest = & $ConvertFromJsonCommand -InputObject (
            [System.Text.UTF8Encoding]::new($false, $true).GetString(
                $entryBytes["$archiveRoot/package-manifest.json"]
            )
        ) -ErrorAction Stop
        $provenance = & $ConvertFromJsonCommand -InputObject (
            [System.Text.UTF8Encoding]::new($false, $true).GetString(
                $entryBytes["$archiveRoot/provenance.json"]
            )
        ) -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.CONFLICTING_INPUT'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.CONFLICTING_INPUT' -Attestation $attestation)
            Policy = $policy
        }
    }

    if ([string] $provenance.sourceRevision.sha256 -ne [string] $attestation.sourceRevision.sha256 -or
        [string] $manifest.sourceRevision.sha256 -ne [string] $attestation.sourceRevision.sha256) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.SOURCE_REVISION_ALTERED'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.SOURCE_REVISION_ALTERED' -Attestation $attestation)
            Policy = $policy
        }
    }

    if ([string] $provenance.generatedContent.sha256 -ne
        [string] $attestation.generatedApplication.sha256 -or
        [string] $manifest.unsignedGeneratedContentIdentity.sha256 -ne
        [string] $attestation.generatedApplication.sha256 -or
        [string] $provenance.buildTool.sha256 -ne
        [string] $attestation.buildProvenance.buildTool.sha256) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.CONFLICTING_INPUT'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.CONFLICTING_INPUT' -Attestation $attestation)
            Policy = $policy
        }
    }

    foreach ($resource in @($manifest.resources)) {
        $relative = [string] $resource.path
        $entryName = "$archiveRoot/$relative"
        $special = @(
            'WIN-PCInfo.ps1',
            'package-manifest.json',
            'checksums.sha256',
            'provenance.json',
            'dependency-inventory.json',
            'sbom.spdx.json'
        )
        if ($relative -in $special) {
            continue
        }
        $bytes = Get-AttestedPreviewArchiveEntryBytes -ZipPath $CandidateArchivePath `
            -EntryName $entryName
        if ($null -eq $bytes) {
            return [pscustomobject]@{
                Valid = $false
                ReasonCode = 'ATTESTATION.MISSING_INPUT'
                Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                    -ReasonCode 'ATTESTATION.MISSING_INPUT' -Attestation $attestation)
                Policy = $policy
            }
        }
        if ((Get-AttestedPreviewFileDigest -Bytes $bytes) -ne [string] $resource.sha256) {
            return [pscustomobject]@{
                Valid = $false
                ReasonCode = 'ATTESTATION.RESOURCE_ALTERED'
                Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                    -ReasonCode 'ATTESTATION.RESOURCE_ALTERED' -Attestation $attestation)
                Policy = $policy
            }
        }
    }

    $zipBytes = [System.IO.File]::ReadAllBytes($CandidateArchivePath)
    if ((Get-AttestedPreviewFileDigest -Bytes $zipBytes) -ne
        [string] $attestation.candidate.sha256) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.CANDIDATE_ALTERED'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.CANDIDATE_ALTERED' -Attestation $attestation)
            Policy = $policy
        }
    }

    [pscustomobject]@{
        Valid = $true
        ReasonCode = 'ATTESTATION.VERIFIED'
        Record = (New-AttestedPreviewVerificationRecord -State Verified `
            -ReasonCode 'ATTESTATION.VERIFIED' -Attestation $attestation `
            -EligibleForLaterSmokeOrValidation $true)
        Policy = $policy
    }
}
