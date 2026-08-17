# Build.ps1 replaces both sentinels with the release-bound Attested Preview
# policy and its SHA-256 digest. The running application treats that policy as
# the closed fallback contract.
$script:AttestedPreviewPolicyBase64 = '__ATTESTED_PREVIEW_POLICY_BASE64__'
$script:AttestedPreviewPolicyDigest = '__ATTESTED_PREVIEW_POLICY_SHA256__'

function Get-AttestedPreviewFileDigest {
    param([Parameter(Mandatory)] $Bytes)

    # SHA-256 is the only digest this fallback trusts. The threat is treating a
    # checksum as Authenticode or silently using a weaker hash. The mechanism is
    # a lowercase hex SHA-256 of the exact supplied bytes. The trust assumption
    # is that those bytes are the reviewed candidate or sidecar. Safe failure is
    # a mismatch, never a weaker algorithm.
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

function Get-AttestedPreviewLimitedTrustMarkdown {
    param([Parameter(Mandatory)] $Policy)

    # The sidecar page is an input, not decoration. The threat is swapping it
    # for text that calls the fallback Trusted or signed after a verified
    # result. The mechanism is a policy-derived UTF-8 page compared
    # byte-for-byte at verify time. The trust assumption is the embedded
    # policy, not the unsigned attestation document. Safe failure is
    # CONFLICTING_INPUT.
    @(
        "# $([string] $Policy.warning.title)"
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

function Get-AttestedPreviewLimitedTrustWarning {
    param([Parameter()] $Policy)

    $title = 'UNSIGNED LIMITED-TRUST WARNING — NOT TRUSTED, NOT SIGNED, NOT SUPPORTED'
    if ($null -ne $Policy) {
        try {
            $fromPolicy = [string] $Policy.warning.title
            if (-not [string]::IsNullOrWhiteSpace($fromPolicy)) {
                $title = $fromPolicy
            }
        }
        catch {
        }
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

function Get-AttestedPreviewNestedText {
    param(
        [Parameter()] $Value,
        [Parameter(Mandatory)] [string[]] $Names
    )

    $current = $Value
    foreach ($name in $Names) {
        if ($null -eq $current) {
            return $null
        }
        $property = $current.PSObject.Properties[$name]
        if ($null -eq $property) {
            return $null
        }
        $current = $property.Value
    }
    if ($null -eq $current) {
        return $null
    }
    [string] $current
}

function Get-AttestedPreviewArchiveEntryBytes {
    param(
        [Parameter(Mandatory)] [string] $ZipPath,
        [Parameter(Mandatory)] [string] $EntryName
    )

    # Zip entry names are exact identities. The threat is reading the wrong
    # member because a host rewrites separators or missing entries become
    # empty success. The mechanism is ZipFile.OpenRead plus a null return
    # when GetEntry misses. The trust assumption is the deterministic
    # portable archive layout. Safe failure is MISSING_INPUT.

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
        $optional = [ordered]@{
            fallbackReason = (Get-AttestedPreviewNestedText $Attestation @('fallback', 'reason'))
            candidateSha256 = (Get-AttestedPreviewNestedText $Attestation @('candidate', 'sha256'))
            generatedApplicationSha256 = (Get-AttestedPreviewNestedText $Attestation @('generatedApplication', 'sha256'))
            sourceRevisionSha256 = (Get-AttestedPreviewNestedText $Attestation @('sourceRevision', 'sha256'))
            resourceManifestSha256 = (Get-AttestedPreviewNestedText $Attestation @('resourceManifest', 'sha256'))
            checksumsSha256 = (Get-AttestedPreviewNestedText $Attestation @('checksums', 'sha256'))
            dependencyInventorySha256 = (Get-AttestedPreviewNestedText $Attestation @('dependencyInventory', 'sha256'))
            sbomSha256 = (Get-AttestedPreviewNestedText $Attestation @('sbom', 'sha256'))
            buildProvenanceSha256 = (Get-AttestedPreviewNestedText $Attestation @('buildProvenance', 'sha256'))
        }
        foreach ($name in @($optional.Keys)) {
            if ($null -ne $optional[$name]) {
                $record[$name] = $optional[$name]
            }
        }
    }
    [pscustomobject] $record
}

function Test-AttestedPreviewLabelSafety {
    param([Parameter(Mandatory)] $Attestation)

    # Positive trust words in this document are claims, not English
    # description. The threat is relabeling an unsigned fallback as Trusted,
    # signed, or Supported so it could pass a later Stable gate. The
    # mechanism is a closed comparison of kind, policy, and recorded flags.
    # The trust assumption is that the operator reads the warning as well.
    # Safe failure is FORBIDDEN_CLAIM, CONFLICTING_INPUT, or
    # STABLE_SIGNING_UNSATISFIED.
    try {
        $kind = [string] $Attestation.kind
        $policyId = [string] $Attestation.policyId
        $trustClass = [string] $Attestation.trustClass
        $unsigned = [bool] $Attestation.unsigned
        $limitedTrust = [bool] $Attestation.limitedTrust
        $signed = [bool] $Attestation.signed
        $trusted = [bool] $Attestation.trusted
        $supported = [bool] $Attestation.supported
        $supportClaim = [string] $Attestation.supportClaim
        $previewOrStableClaim = [string] $Attestation.previewOrStableClaim
        $candidateKind = [string] $Attestation.candidate.kind
        $identityRole = [string] $Attestation.candidate.identityRole
        $satisfiesStable = [bool] $Attestation.satisfiesStableSigningGate
    }
    catch {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.CONFLICTING_INPUT'
        }
    }

    if ($kind -ne 'win-pcinfo.attested-preview-attestation' -or
        $policyId -ne 'win-pcinfo.attested-preview/1.0.0' -or
        $candidateKind -ne 'win-pcinfo.unsigned-portable-package-identity' -or
        $identityRole -ne 'final-distributable-when-fallback-selected') {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.CONFLICTING_INPUT'
        }
    }
    if ($trustClass -ne 'AttestedPreview' -or
        -not $unsigned -or
        -not $limitedTrust -or
        $signed -or
        $trusted -or
        $supported -or
        $supportClaim -ne 'None' -or
        $previewOrStableClaim -ne 'None') {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.FORBIDDEN_CLAIM'
        }
    }
    if ($satisfiesStable -or
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
        $expectedWarningBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
            (Get-AttestedPreviewLimitedTrustMarkdown -Policy $policy)
        )
        $warningBytes = [System.IO.File]::ReadAllBytes($warningPath)
        if ((Get-AttestedPreviewFileDigest -Bytes $warningBytes) -ne
            (Get-AttestedPreviewFileDigest -Bytes $expectedWarningBytes)) {
            return [pscustomobject]@{
                Valid = $false
                ReasonCode = 'ATTESTATION.CONFLICTING_INPUT'
                Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                    -ReasonCode 'ATTESTATION.CONFLICTING_INPUT')
                Policy = $policy
            }
        }
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

    try {
        $permitted = @($policy.fallback.permittedReasons)
        $neverForConvenience = [bool] $attestation.fallback.neverForConvenience
        $fallbackReason = [string] $attestation.fallback.reason
        $archiveRoot = [string] $policy.archiveRootName
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
    if ([string]::IsNullOrWhiteSpace($archiveRoot)) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.INPUT_INVALID'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.INPUT_INVALID' -Attestation $attestation)
            Policy = $policy
        }
    }
    if (-not $neverForConvenience -or $fallbackReason -notin $permitted) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.FALLBACK_REASON_INVALID'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.FALLBACK_REASON_INVALID' -Attestation $attestation)
            Policy = $policy
        }
    }
    try {
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
        $attestedSourceRevision = [string] $attestation.sourceRevision.sha256
        $attestedApplication = [string] $attestation.generatedApplication.sha256
        $attestedBuildTool = [string] $attestation.buildProvenance.buildTool.sha256
        $attestedCandidate = [string] $attestation.candidate.sha256
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

    try {
        $provenanceSourceRevision = [string] $provenance.sourceRevision.sha256
        $manifestSourceRevision = [string] $manifest.sourceRevision.sha256
        $provenanceApplication = [string] $provenance.generatedContent.sha256
        $manifestApplication = [string] $manifest.unsignedGeneratedContentIdentity.sha256
        $provenanceBuildTool = [string] $provenance.buildTool.sha256
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

    if ($provenanceSourceRevision -ne $attestedSourceRevision -or
        $manifestSourceRevision -ne $attestedSourceRevision) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.SOURCE_REVISION_ALTERED'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.SOURCE_REVISION_ALTERED' -Attestation $attestation)
            Policy = $policy
        }
    }

    if ($provenanceApplication -ne $attestedApplication -or
        $manifestApplication -ne $attestedApplication -or
        $provenanceBuildTool -ne $attestedBuildTool) {
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
    if ((Get-AttestedPreviewFileDigest -Bytes $zipBytes) -ne $attestedCandidate) {
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
