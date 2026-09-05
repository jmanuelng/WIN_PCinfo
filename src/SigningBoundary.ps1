# Build.ps1 replaces both sentinels with the release-bound Signing Boundary
# policy and its SHA-256 digest. The generated application treats that table
# as the only trusted copy of the Preview.1 signing contract.
$script:SigningBoundaryPolicyBase64 = '__SIGNING_BOUNDARY_POLICY_BASE64__'
$script:SigningBoundaryPolicyDigest = '__SIGNING_BOUNDARY_POLICY_SHA256__'
$script:SigningBoundaryCrc32Table = $null

function Get-SigningBoundarySha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-SigningBoundaryPolicy {
    # The threat is a substituted policy that waives digest approval, treats
    # checksums as Authenticode, or labels a synthetic session Trusted. The
    # mechanism is an embedded digest, or the reviewed repository file when
    # this module is sourced during development. The trust assumption is that
    # those bytes were reviewed with the rest of the release. Safe failure is
    # to refuse the session rather than invent a looser contract.
    if ($script:SigningBoundaryPolicyBase64 -eq
        ('__SIGNING_BOUNDARY_' + 'POLICY_BASE64__')) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-signing-boundary.json'
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes($path)
        $expectedDigest = Get-SigningBoundarySha256 $bytes
    }
    else {
        [byte[]] $bytes = [System.Convert]::FromBase64String(
            $script:SigningBoundaryPolicyBase64
        )
        $expectedDigest = $script:SigningBoundaryPolicyDigest
    }
    if ((Get-SigningBoundarySha256 $bytes) -ne $expectedDigest) {
        throw 'The Signing Boundary policy failed its embedded digest check.'
    }
    $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $json | ConvertFrom-Json -Depth 20
}

function Get-SigningBoundaryProperty {
    param(
        [Parameter()] $Value,
        [Parameter(Mandatory)] [string] $Name
    )

    if ($null -eq $Value) {
        return $null
    }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    $property.Value
}

function Test-SigningBoundaryPathUnderRoot {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Root
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $prefix = $fullRoot + [System.IO.Path]::DirectorySeparatorChar
    $fullPath.Equals($fullRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-SigningBoundaryPublicPath {
    param([Parameter(Mandatory)] [string] $Path)

    if ($Path.StartsWith('\\', [System.StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [System.StringComparison]::Ordinal)) {
        return $true
    }
    $publicRoot = [string] $env:PUBLIC
    if ([string]::IsNullOrWhiteSpace($publicRoot)) {
        return $false
    }
    if (-not (Test-Path -LiteralPath $publicRoot)) {
        return $false
    }
    Test-SigningBoundaryPathUnderRoot -Path $Path -Root $publicRoot
}

function Test-SigningBoundaryReparsePath {
    param([Parameter(Mandatory)] [string] $Path)

    # A junction or symlink can make a temp path write into the repository
    # or a network share after the string checks pass. Walk every existing
    # ancestor the same way Evidence Workspace does. The trust assumption is
    # that a ticket-owned signing workspace is a real local directory. Safe
    # failure is to reject the path before any signed file exists.
    try {
        $cursor = [System.IO.DirectoryInfo]::new([System.IO.Path]::GetFullPath($Path))
    }
    catch {
        return $true
    }
    if (-not $cursor.Exists) {
        $cursor = $cursor.Parent
    }
    while ($null -ne $cursor) {
        if ($cursor.Exists -and
            ($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $true
        }
        $cursor = $cursor.Parent
    }
    $false
}

function Get-SigningBoundaryCatalogPath {
    param(
        [Parameter()] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter(Mandatory)] [string] $RelativePath
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($start in @($ApplicationDirectory, $RepositoryRoot)) {
        if ([string]::IsNullOrWhiteSpace($start)) {
            continue
        }
        $cursor = $start
        for ($i = 0; $i -lt 6; $i++) {
            if ([string]::IsNullOrWhiteSpace($cursor)) {
                break
            }
            if ($seen.Add($cursor)) {
                $roots.Add($cursor)
            }
            $parent = Split-Path -Parent $cursor
            if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) {
                break
            }
            $cursor = $parent
        }
    }
    foreach ($root in $roots) {
        $candidate = Join-Path $root $RelativePath
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    $null
}

function Test-SigningBoundaryPrivacyBoundary {
    param([Parameter(Mandatory)] [string] $Text)

    # Public signing output is a projection, not a dump. The threat is
    # printing an Azure profile, transaction, credential, tenant fact, or
    # local user path. The mechanism is a closed needle list applied to the
    # raw request before any session opens. The trust assumption is that
    # approved fixtures stay synthetic. Safe failure is PRIVACY_REJECTED.
    $needles = @(
        '(?i)clientSecret'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)(password|secret|api[_-]?key|access_token)\s*[:=]'
        '(?i)/subscriptions/'
        '(?i)\btenant\b'
        '(?i)\.terraform'
        '(?i)\.tfstate'
        '(?i)Microsoft\.CodeSigning'
        '(?i)transactionId'
        '(?i)certificateProfile'
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
        '(?i)\b\d{1,3}(\.\d{1,3}){3}\b'
        '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
    )
    foreach ($needle in $needles) {
        if ($Text -match $needle) {
            return 'SIGNING.PRIVACY_REJECTED'
        }
    }
    $null
}

function Get-SigningBoundaryWorkspaceRejection {
    param(
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $Request
    )

    # The threat is writing signed bytes or restricted evidence into the
    # public repository or a shared folder. The mechanism is a caller-supplied
    # private directory that already carries the reviewed marker. The trust
    # assumption is that the operator chose a folder they control. Safe
    # failure is to stop before any signed file exists.
    if ([string] (Get-SigningBoundaryProperty $Request 'privacyBoundary') -ne
        [string] $Policy.workspace.requiredBoundary) {
        return 'SIGNING.PRIVACY_BOUNDARY_MISSING'
    }
    if ([string]::IsNullOrWhiteSpace($PrivateWorkspacePath)) {
        return 'SIGNING.PRIVACY_BOUNDARY_MISSING'
    }
    if (Test-SigningBoundaryPublicPath -Path $PrivateWorkspacePath) {
        return 'SIGNING.WORKSPACE_PUBLIC_PATH'
    }
    if (Test-SigningBoundaryPathUnderRoot -Path $PrivateWorkspacePath -Root $RepositoryRoot) {
        return 'SIGNING.WORKSPACE_REPOSITORY_PATH'
    }
    if (-not [string]::IsNullOrWhiteSpace($ApplicationDirectory) -and
        (Test-Path -LiteralPath $ApplicationDirectory) -and
        (Test-SigningBoundaryPathUnderRoot -Path $PrivateWorkspacePath `
            -Root $ApplicationDirectory)) {
        return 'SIGNING.WORKSPACE_REPOSITORY_PATH'
    }
    if (Test-SigningBoundaryReparsePath -Path $PrivateWorkspacePath) {
        return 'SIGNING.WORKSPACE_REPARSE_POINT'
    }
    if (-not (Test-Path -LiteralPath $PrivateWorkspacePath -PathType Container)) {
        return 'SIGNING.PRIVACY_BOUNDARY_MISSING'
    }
    $markerPath = Join-Path $PrivateWorkspacePath ([string] $Policy.workspace.markerFileName)
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        return 'SIGNING.PRIVACY_BOUNDARY_MISSING'
    }
    $markerText = [System.IO.File]::ReadAllText($markerPath).Trim()
    if ($markerText -ne [string] $Policy.workspace.markerContent) {
        return 'SIGNING.PRIVACY_BOUNDARY_MISSING'
    }
    $null
}

function New-SigningBoundaryResult {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('SignedAndVerified', 'Rejected', 'AttestedFallbackEligible', 'SetupRequired')]
        [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter()] [bool] $Signed = $false,
        [Parameter()] [bool] $Verified = $false,
        [Parameter()] [bool] $Smoked = $false,
        [Parameter()] [bool] $SessionCapabilityRemoved = $true,
        [Parameter()] [string] $UnsignedContentSha256,
        [Parameter()] [string] $SignedPrimaryScriptSha256,
        [Parameter()] [string] $FinalSignedDistributableSha256,
        [Parameter()] [bool] $IdentitiesDistinct = $false,
        [Parameter()] [ValidateSet('Valid', 'NotSigned', 'Invalid', 'HashMismatch', 'NotEvaluated')]
        [string] $SignatureStatus = 'NotEvaluated',
        [Parameter()] [ValidateSet('Valid', 'Missing', 'Invalid', 'NotEvaluated')]
        [string] $TimestampStatus = 'NotEvaluated',
        [Parameter()] [ValidateSet('Valid', 'Incomplete', 'Untrusted', 'NotEvaluated')]
        [string] $ChainStatus = 'NotEvaluated',
        [Parameter()] [string] $PublisherThumbprint,
        [Parameter()] [bool] $AttestedFallbackEligible = $false,
        [Parameter()] [ValidateSet('None', 'ArtifactSigningNotOperational', 'VerifiedServiceIncident')]
        [string] $FallbackReason = 'None',
        [Parameter()] [ValidateSet('None', 'SyntheticSigningContract', 'AttestedPreview')]
        [string] $TrustClass = 'None',
        [Parameter()] [bool] $Synthetic = $true
    )

    $unsigned = $null
    if (-not [string]::IsNullOrWhiteSpace($UnsignedContentSha256)) {
        $unsigned = $UnsignedContentSha256
    }
    $signedDigest = $null
    if (-not [string]::IsNullOrWhiteSpace($SignedPrimaryScriptSha256)) {
        $signedDigest = $SignedPrimaryScriptSha256
    }
    $finalDigest = $null
    if (-not [string]::IsNullOrWhiteSpace($FinalSignedDistributableSha256)) {
        $finalDigest = $FinalSignedDistributableSha256
    }
    $thumbprint = $null
    if (-not [string]::IsNullOrWhiteSpace($PublisherThumbprint)) {
        $thumbprint = $PublisherThumbprint
    }

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.signing-session-result'
        contractVersion = '1.0.0'
        state = $State
        reasonCode = $ReasonCode
        signed = [bool] $Signed
        verified = [bool] $Verified
        smoked = [bool] $Smoked
        sessionCapabilityRemoved = [bool] $SessionCapabilityRemoved
        sessionLeastPrivilege = $true
        sessionTimeBounded = $true
        sessionSpecific = $true
        unsignedContentIdentityKind = 'win-pcinfo.unsigned-generated-content-identity'
        signedPrimaryScriptIdentityKind = 'win-pcinfo.signed-primary-script-identity'
        finalSignedDistributableIdentityKind = 'win-pcinfo.authenticode-signed-package-identity'
        unsignedContentSha256 = $unsigned
        signedPrimaryScriptSha256 = $signedDigest
        finalSignedDistributableSha256 = $finalDigest
        identitiesDistinct = [bool] $IdentitiesDistinct
        timestampedSigningByteReproducible = $false
        publisherKind = 'IndividualPublisher'
        publisherDisplayName = 'WIN-PCInfo Individual Publisher'
        signatureStatus = $SignatureStatus
        timestampStatus = $TimestampStatus
        chainStatus = $ChainStatus
        publisherThumbprint = $thumbprint
        attestedFallbackEligible = [bool] $AttestedFallbackEligible
        fallbackReason = $FallbackReason
        satisfiesStableSigningGate = $false
        trustedPublicationPermitted = $false
        publicationAuthorized = $false
        supportClaim = 'None'
        previewOrStableClaim = 'None'
        sliceDeliversCapability = $false
        collectionStarted = $false
        synthetic = [bool] $Synthetic
        azureContacted = $false
        trustClass = $TrustClass
    }
}

function Test-SigningBoundaryHasSignatureBlock {
    param([Parameter(Mandatory)] [string] $Text)

    $Text -match '(?m)^# SIG # Begin signature block\s*$'
}

function Get-SigningBoundarySyntheticThumbprint {
    # This thumbprint is a public synthetic verification fact, not an Azure
    # certificate identifier. The threat is inventing a real serial or
    # account thumbprint. The mechanism is the first 40 hex characters of a
    # SHA-256 of a product-owned label. The trust assumption is that callers
    # treat it as synthetic. Safe failure is to omit the field.
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        'win-pcinfo.synthetic-individual-publisher'
    )
    (Get-SigningBoundarySha256 -Bytes $bytes).Substring(0, 40)
}

function New-SigningBoundarySyntheticTrailer {
    param(
        [Parameter(Mandatory)] [string] $UnsignedSha256,
        [Parameter()] [string] $SignatureStatus = 'Valid',
        [Parameter()] [string] $TimestampStatus = 'Valid',
        [Parameter()] [string] $ChainStatus = 'Valid',
        [Parameter()] [bool] $IncludeMarker = $true
    )

    # PowerShell Authenticode is a comment trailer. The threat is claiming
    # Windows-trusted Authenticode from a local checksum. The mechanism is a
    # governed synthetic trailer that still creates distinct signed bytes and
    # stays parseable as comments. The trust assumption is that publication
    # stays unauthorized. Safe failure is an invalid or missing trailer.
    $lines = [System.Collections.Generic.List[string]]::new()
    $null = $lines.Add('# SIG # Begin signature block')
    if ($IncludeMarker) {
        $null = $lines.Add('# win-pcinfo.synthetic-authenticode')
    }
    $null = $lines.Add('# publisherKind=IndividualPublisher')
    $null = $lines.Add('# publisherDisplayName=WIN-PCInfo Individual Publisher')
    $null = $lines.Add("# unsignedSha256=$UnsignedSha256")
    $null = $lines.Add('# signedIdentityKind=win-pcinfo.signed-primary-script-identity')
    $null = $lines.Add("# timestampStatus=$TimestampStatus")
    $null = $lines.Add('# timestampedSigningByteReproducible=false')
    $null = $lines.Add("# chainStatus=$ChainStatus")
    $null = $lines.Add("# signatureStatus=$SignatureStatus")
    $null = $lines.Add('# thumbprint=' + (Get-SigningBoundarySyntheticThumbprint))
    $null = $lines.Add('# SIG # End signature block')
    ($lines -join "`n") + "`n"
}

function Get-SigningBoundaryPayloadAndTrailer {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    # Split on the UTF-8 marker bytes, not a string index. The threat is a
    # char-index split that changes the precursor digest after a UTF-8
    # round-trip. The mechanism is an exact byte search for the Authenticode
    # comment trailer. The trust assumption is that the marker is ASCII.
    # Safe failure is to treat the file as unsigned.
    $marker = [System.Text.UTF8Encoding]::new($false).GetBytes(
        '# SIG # Begin signature block'
    )
    $index = -1
    $limit = $Bytes.Length - $marker.Length
    for ($i = $limit; $i -ge 0; $i--) {
        $match = $true
        for ($j = 0; $j -lt $marker.Length; $j++) {
            if ($Bytes[$i + $j] -ne $marker[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            $index = $i
            break
        }
    }
    if ($index -lt 0) {
        return [pscustomobject]@{
            PayloadBytes = $Bytes
            TrailerText = $null
            HasTrailer = $false
        }
    }
    $payload = [byte[]]::new($index)
    if ($index -gt 0) {
        [System.Buffer]::BlockCopy($Bytes, 0, $payload, 0, $index)
    }
    $trailerLength = $Bytes.Length - $index
    $trailerBytes = [byte[]]::new($trailerLength)
    [System.Buffer]::BlockCopy($Bytes, $index, $trailerBytes, 0, $trailerLength)
    [pscustomobject]@{
        PayloadBytes = $payload
        TrailerText = [System.Text.UTF8Encoding]::new($false, $true).GetString($trailerBytes)
        HasTrailer = $true
    }
}

function Test-SigningBoundaryAuthenticode {
    param(
        [Parameter(Mandatory)] [byte[]] $SignedBytes,
        [Parameter(Mandatory)] [string] $ExpectedUnsignedSha256
    )

    # The threat is smoking an unsigned, mutated, or unknown signature as
    # Trusted. The mechanism is a closed parser for the governed synthetic
    # trailer plus an exact precursor-byte digest. The trust assumption is
    # that this slice never claims a Windows-trusted chain. Safe failure is
    # a typed signature, timestamp, or change reason.
    $parts = Get-SigningBoundaryPayloadAndTrailer -Bytes $SignedBytes
    if (-not $parts.HasTrailer) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'SIGNING.UNSIGNED'
            SignatureStatus = 'NotSigned'
            TimestampStatus = 'Missing'
            ChainStatus = 'Incomplete'
        }
    }
    $trailer = [string] $parts.TrailerText
    if ($trailer -notmatch '(?s)^# SIG # Begin signature block\r?\n.*# SIG # End signature block\r?\n?\z') {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'SIGNING.CANDIDATE_CHANGED'
            SignatureStatus = 'HashMismatch'
            TimestampStatus = 'NotEvaluated'
            ChainStatus = 'NotEvaluated'
        }
    }
    if ($trailer -notmatch '(?m)^# win-pcinfo\.synthetic-authenticode\s*$') {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'SIGNING.INVALID_SIGNATURE'
            SignatureStatus = 'Invalid'
            TimestampStatus = 'NotEvaluated'
            ChainStatus = 'Untrusted'
        }
    }
    $payloadDigest = Get-SigningBoundarySha256 -Bytes ([byte[]] $parts.PayloadBytes)
    if ($payloadDigest -ne $ExpectedUnsignedSha256) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'SIGNING.CANDIDATE_CHANGED'
            SignatureStatus = 'HashMismatch'
            TimestampStatus = 'NotEvaluated'
            ChainStatus = 'NotEvaluated'
        }
    }
    $embedded = $null
    if ($trailer -match '(?m)^# unsignedSha256=([0-9a-f]{64})\s*$') {
        $embedded = $Matches[1]
    }
    if ($embedded -ne $ExpectedUnsignedSha256) {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'SIGNING.CANDIDATE_CHANGED'
            SignatureStatus = 'HashMismatch'
            TimestampStatus = 'NotEvaluated'
            ChainStatus = 'NotEvaluated'
        }
    }
    $signatureStatus = 'Invalid'
    if ($trailer -match '(?m)^# signatureStatus=([A-Za-z]+)\s*$') {
        $signatureStatus = [string] $Matches[1]
    }
    if ($signatureStatus -ne 'Valid') {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'SIGNING.INVALID_SIGNATURE'
            SignatureStatus = 'Invalid'
            TimestampStatus = 'NotEvaluated'
            ChainStatus = 'Untrusted'
        }
    }
    $timestampStatus = 'Missing'
    if ($trailer -match '(?m)^# timestampStatus=([A-Za-z]+)\s*$') {
        $timestampStatus = [string] $Matches[1]
    }
    if ($timestampStatus -ne 'Valid') {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'SIGNING.TIMESTAMP_FAILED'
            SignatureStatus = 'Valid'
            TimestampStatus = $timestampStatus
            ChainStatus = 'Valid'
        }
    }
    $chainStatus = 'Incomplete'
    if ($trailer -match '(?m)^# chainStatus=([A-Za-z]+)\s*$') {
        $chainStatus = [string] $Matches[1]
    }
    if ($chainStatus -ne 'Valid') {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'SIGNING.INVALID_SIGNATURE'
            SignatureStatus = 'Valid'
            TimestampStatus = 'Valid'
            ChainStatus = $chainStatus
        }
    }
    if ($trailer -notmatch '(?m)^# publisherKind=IndividualPublisher\s*$') {
        return [pscustomobject]@{
            Valid = $false
            ReasonCode = 'SIGNING.INVALID_SIGNATURE'
            SignatureStatus = 'Invalid'
            TimestampStatus = 'Valid'
            ChainStatus = 'Untrusted'
        }
    }
    [pscustomobject]@{
        Valid = $true
        ReasonCode = 'SIGNING.SIGNED_AND_VERIFIED'
        SignatureStatus = 'Valid'
        TimestampStatus = 'Valid'
        ChainStatus = 'Valid'
    }
}

function Get-SigningBoundaryCrc32 {
    param([Parameter(Mandatory)] $Bytes)

    $Bytes = [byte[]] $Bytes
    $mask = [uint64] 4294967295
    $polynomial = [uint64] 3988292384
    if ($null -eq $script:SigningBoundaryCrc32Table) {
        $table = [uint64[]]::new(256)
        for ($i = 0; $i -lt 256; $i++) {
            $entry = [uint64] $i
            for ($bit = 0; $bit -lt 8; $bit++) {
                if (($entry -band 1) -ne 0) {
                    $entry = [uint64] ((($entry -shr 1) -bxor $polynomial) -band $mask)
                }
                else {
                    $entry = [uint64] (($entry -shr 1) -band $mask)
                }
            }
            $table[$i] = $entry
        }
        $script:SigningBoundaryCrc32Table = $table
    }

    $crc = $mask
    foreach ($byte in $Bytes) {
        $index = [int] (($crc -bxor [uint64] $byte) -band 0xFF)
        $crc = [uint64] (($script:SigningBoundaryCrc32Table[$index] -bxor ($crc -shr 8)) -band $mask)
    }
    [uint32] ($crc -bxor $mask)
}

function New-SigningBoundaryDeterministicZip {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $Entries
    )

    # System.IO.Compression writes host timestamps. The threat is a
    # machine-local final identity. The mechanism is a store-only ZIP with a
    # frozen 1980-01-01 DOS date. The trust assumption is that entry names
    # and bytes are already reviewed. Safe failure is to refuse the archive.
    $ordered = New-Object System.Collections.Generic.List[object]
    foreach ($entry in ($Entries | Sort-Object { [string] $_.Name })) {
        $null = $ordered.Add([pscustomobject]@{
            Name = ([string] $entry.Name).Replace('\', '/')
            Bytes = [byte[]] $entry.Bytes
        })
    }
    $directory = Split-Path -Parent $LiteralPath
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }

    $stream = [System.IO.File]::Open(
        $LiteralPath,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    $writer = [System.IO.BinaryWriter]::new($stream)
    try {
        $central = New-Object System.Collections.Generic.List[object]
        foreach ($entry in $ordered) {
            $nameBytes = [System.Text.Encoding]::ASCII.GetBytes($entry.Name)
            $payload = $entry.Bytes
            $crc = Get-SigningBoundaryCrc32 -Bytes $payload
            $offset = [uint32] $stream.Position
            $writer.Write([uint32] 0x04034b50)
            $writer.Write([uint16] 20)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0x0021)
            $writer.Write([uint32] $crc)
            $writer.Write([uint32] $payload.Length)
            $writer.Write([uint32] $payload.Length)
            $writer.Write([uint16] $nameBytes.Length)
            $writer.Write([uint16] 0)
            $writer.Write($nameBytes)
            if ($payload.Length -gt 0) {
                $writer.Write($payload)
            }
            $central.Add([pscustomobject]@{
                NameBytes = $nameBytes
                Crc = $crc
                Length = [uint32] $payload.Length
                Offset = $offset
            })
        }

        $centralOffset = [uint32] $stream.Position
        foreach ($record in $central) {
            $writer.Write([uint32] 0x02014b50)
            $writer.Write([uint16] 20)
            $writer.Write([uint16] 20)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0x0021)
            $writer.Write([uint32] $record.Crc)
            $writer.Write([uint32] $record.Length)
            $writer.Write([uint32] $record.Length)
            $writer.Write([uint16] $record.NameBytes.Length)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint16] 0)
            $writer.Write([uint32] 0)
            $writer.Write([uint32] $record.Offset)
            $writer.Write($record.NameBytes)
        }
        $centralSize = [uint32] ($stream.Position - $centralOffset)
        $writer.Write([uint32] 0x06054b50)
        $writer.Write([uint16] 0)
        $writer.Write([uint16] 0)
        $writer.Write([uint16] $central.Count)
        $writer.Write([uint16] $central.Count)
        $writer.Write([uint32] $centralSize)
        $writer.Write([uint32] $centralOffset)
        $writer.Write([uint16] 0)
    }
    finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

function ConvertTo-SigningBoundaryJsonBytes {
    param([Parameter(Mandatory)] $Value)

    [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Compress -Depth 20)
    )
}

function New-SigningBoundaryFinalPackage {
    param(
        [Parameter(Mandatory)] [string] $WorkspacePath,
        [Parameter(Mandatory)] [string] $SignedScriptPath,
        [Parameter(Mandatory)] [string] $UnsignedSha256,
        [Parameter(Mandatory)] [string] $SignedSha256,
        [Parameter(Mandatory)] $Policy
    )

    # The outer package must freeze around the already-signed script. The
    # threat is rebuilding from unsigned bytes or embedding Azure identifiers.
    # The mechanism is a deterministic store-only zip of the signed script,
    # manifest, checksums, and provenance. The trust assumption is that the
    # signed input is already verified. Safe failure is to skip smoke.
    $finalRoot = Join-Path $WorkspacePath 'final'
    $null = New-Item -ItemType Directory -Path $finalRoot -Force
    $signedBytes = [System.IO.File]::ReadAllBytes($SignedScriptPath)
    $manifest = [pscustomobject][ordered]@{
        kind = 'win-pcinfo.signed-distributable-manifest'
        contractVersion = '1.0.0'
        release = [string] $Policy.release
        unsignedContentKind = [string] $Policy.identity.unsignedContentKind
        unsignedContentSha256 = $UnsignedSha256
        signedPrimaryScriptKind = [string] $Policy.identity.signedPrimaryScriptKind
        signedPrimaryScriptSha256 = $SignedSha256
        finalSignedKind = [string] $Policy.identity.finalSignedKind
        timestampedSigningByteReproducible = $false
        publisherKind = [string] $Policy.publisher.kind
        resources = @(
            [pscustomobject][ordered]@{
                path = 'WIN-PCInfo.ps1'
                class = 'application'
                sha256 = $SignedSha256
            }
        )
    }
    $checksums = [pscustomobject][ordered]@{
        kind = 'win-pcinfo.signed-distributable-checksums'
        contractVersion = '1.0.0'
        algorithm = 'SHA-256'
        files = @(
            [pscustomobject][ordered]@{
                path = 'WIN-PCInfo.ps1'
                sha256 = $SignedSha256
            }
        )
    }
    $provenance = [pscustomobject][ordered]@{
        kind = 'win-pcinfo.signed-distributable-provenance'
        contractVersion = '1.0.0'
        linkedUnsignedContentSha256 = $UnsignedSha256
        signedPrimaryScriptSha256 = $SignedSha256
        derivedFromQualifiedUnsignedContent = $true
        synthetic = $true
        publicationAuthorized = $false
    }
    $manifestBytes = ConvertTo-SigningBoundaryJsonBytes $manifest
    $checksumBytes = ConvertTo-SigningBoundaryJsonBytes $checksums
    $provenanceBytes = ConvertTo-SigningBoundaryJsonBytes $provenance
    [System.IO.File]::WriteAllBytes((Join-Path $finalRoot 'package-manifest.json'), $manifestBytes)
    [System.IO.File]::WriteAllBytes((Join-Path $finalRoot 'checksums.json'), $checksumBytes)
    [System.IO.File]::WriteAllBytes((Join-Path $finalRoot 'provenance.json'), $provenanceBytes)
    $archivePath = Join-Path $finalRoot 'WIN-PCInfo-2.0.0-preview.1-signed.zip'
    New-SigningBoundaryDeterministicZip -LiteralPath $archivePath -Entries @(
        [pscustomobject]@{ Name = 'WIN-PCInfo.ps1'; Bytes = $signedBytes }
        [pscustomobject]@{ Name = 'package-manifest.json'; Bytes = $manifestBytes }
        [pscustomobject]@{ Name = 'checksums.json'; Bytes = $checksumBytes }
        [pscustomobject]@{ Name = 'provenance.json'; Bytes = $provenanceBytes }
    )
    $archiveBytes = [System.IO.File]::ReadAllBytes($archivePath)
    [pscustomobject]@{
        ArchivePath = $archivePath
        ArchiveSha256 = Get-SigningBoundarySha256 -Bytes $archiveBytes
        ManifestValid = (
            $manifest.signedPrimaryScriptSha256 -eq $SignedSha256 -and
            $manifest.unsignedContentSha256 -eq $UnsignedSha256
        )
        ProvenanceValid = (
            $provenance.linkedUnsignedContentSha256 -eq $UnsignedSha256 -and
            $provenance.signedPrimaryScriptSha256 -eq $SignedSha256
        )
    }
}

function Invoke-SigningBoundarySmoke {
    param(
        [Parameter(Mandatory)] [string] $SignedScriptPath,
        [Parameter()] [string] $PowerShellPath
    )

    # Smoke proves the signed script still launches. The threat is treating a
    # verified trailer as proof that the file runs, or starting collection
    # from a signing session. The mechanism is a child Help invocation with
    # no assessment arguments. The trust assumption is that Help cannot
    # collect. Safe failure is to keep smoked false.
    if ([string]::IsNullOrWhiteSpace($PowerShellPath)) {
        # Reuse the explicit host running this session; PATH may contain several
        # installations. This changes no signing admission or smoke arguments.
        $PowerShellPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PowerShellPath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
        '-NoLogo', '-NoProfile', '-File', $SignedScriptPath, '-Workflow', 'Help'
    )) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        $null = $process.Start()
        $standardOutput = $process.StandardOutput.ReadToEnd()
        $null = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            return $false
        }
        foreach ($line in @($standardOutput -split "`r?`n" | Where-Object { $_ })) {
            try {
                $record = $line | ConvertFrom-Json -Depth 10
            }
            catch {
                continue
            }
            if ([bool] (Get-SigningBoundaryProperty $record 'collectionStarted')) {
                return $false
            }
        }
        $true
    }
    catch {
        $false
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-SigningBoundarySession {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] [string] $CandidatePath,
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter()] $Policy,
        [Parameter()] [string] $PowerShellPath,
        [Parameter()] [string] $RequestText
    )

    if ($null -eq $Policy) {
        $Policy = Get-SigningBoundaryPolicy
    }
    if ([string]::IsNullOrWhiteSpace($RequestText)) {
        $RequestText = $Request | ConvertTo-Json -Compress -Depth 20
    }

    $privacy = Test-SigningBoundaryPrivacyBoundary -Text $RequestText
    if ($privacy) {
        return New-SigningBoundaryResult -State Rejected -ReasonCode $privacy
    }
    if ([string] (Get-SigningBoundaryProperty $Request 'kind') -ne
        'win-pcinfo.signing-session-request' -or
        [string] (Get-SigningBoundaryProperty $Request 'contractVersion') -ne '1.0.0' -or
        -not [bool] (Get-SigningBoundaryProperty $Request 'synthetic')) {
        return New-SigningBoundaryResult -State Rejected -ReasonCode 'SIGNING.REQUEST_INVALID'
    }

    $workspaceReason = Get-SigningBoundaryWorkspaceRejection `
        -PrivateWorkspacePath $PrivateWorkspacePath `
        -RepositoryRoot $RepositoryRoot `
        -ApplicationDirectory $ApplicationDirectory `
        -Policy $Policy `
        -Request $Request
    if ($workspaceReason) {
        return New-SigningBoundaryResult -State Rejected -ReasonCode $workspaceReason
    }
    if (-not (Test-Path -LiteralPath $CandidatePath -PathType Leaf)) {
        return New-SigningBoundaryResult -State Rejected -ReasonCode 'SIGNING.REQUEST_INVALID'
    }

    $candidateBytes = [System.IO.File]::ReadAllBytes($CandidatePath)
    $candidateText = [System.Text.UTF8Encoding]::new($false, $true).GetString($candidateBytes)
    $candidateDigest = Get-SigningBoundarySha256 -Bytes $candidateBytes
    $scenario = [string] (Get-SigningBoundaryProperty $Request 'scenario')
    $bindings = Get-SigningBoundaryProperty $Request 'bindings'
    $approval = Get-SigningBoundaryProperty $bindings 'humanApproval'
    $requestedDigest = [string] (Get-SigningBoundaryProperty $bindings 'generatedContentSha256')
    $approvalDigest = [string] (Get-SigningBoundaryProperty $approval 'digestSha256')
    $confirmation = [string] (Get-SigningBoundaryProperty $approval 'confirmation')
    $approved = [bool] (Get-SigningBoundaryProperty $approval 'approved')
    $gatesPassed = [bool] (Get-SigningBoundaryProperty $bindings 'unsignedContentQualified')

    $common = @{
        UnsignedContentSha256 = $candidateDigest
        Synthetic = $true
    }

    if ($scenario -eq 'SetupAuthorityMissing') {
        return New-SigningBoundaryResult @common -State SetupRequired `
            -ReasonCode 'SIGNING.SETUP_AUTHORITY_REQUIRED'
    }
    if (-not $gatesPassed -or $scenario -eq 'GatesNotPassed') {
        return New-SigningBoundaryResult @common -State Rejected `
            -ReasonCode 'SIGNING.GATES_NOT_PASSED'
    }
    if (-not $approved -or
        $confirmation -ne [string] $Policy.humanApproval.confirmationPhrase -or
        $scenario -eq 'ApprovalMissing') {
        return New-SigningBoundaryResult @common -State Rejected `
            -ReasonCode 'SIGNING.APPROVAL_REQUIRED'
    }
    if ($requestedDigest -ne $candidateDigest -or $scenario -eq 'WrongCandidate') {
        return New-SigningBoundaryResult @common -State Rejected `
            -ReasonCode 'SIGNING.WRONG_CANDIDATE'
    }
    if ($approvalDigest -ne $candidateDigest -or $scenario -eq 'WrongDigest') {
        return New-SigningBoundaryResult @common -State Rejected `
            -ReasonCode 'SIGNING.WRONG_DIGEST'
    }
    if ((Test-SigningBoundaryHasSignatureBlock -Text $candidateText) -or
        $scenario -eq 'UnexpectedlySigned') {
        return New-SigningBoundaryResult @common -State Rejected `
            -ReasonCode 'SIGNING.UNEXPECTEDLY_SIGNED'
    }

    $unsignedDir = Join-Path $PrivateWorkspacePath 'unsigned'
    $signedDir = Join-Path $PrivateWorkspacePath 'signed'
    $null = New-Item -ItemType Directory -Path $unsignedDir -Force
    $null = New-Item -ItemType Directory -Path $signedDir -Force
    $unsignedPath = Join-Path $unsignedDir 'WIN-PCInfo.ps1'
    $signedPath = Join-Path $signedDir 'WIN-PCInfo.ps1'
    [System.IO.File]::WriteAllBytes($unsignedPath, $candidateBytes)

    $sessionGranted = $false
    $sessionRemoved = $false
    try {
        if ($scenario -eq 'PermissionDenied') {
            return New-SigningBoundaryResult @common -State Rejected `
                -ReasonCode 'SIGNING.PERMISSION_DENIED' -SessionCapabilityRemoved $true
        }
        $sessionGranted = $true
        if ($scenario -eq 'ServiceUnavailable') {
            return New-SigningBoundaryResult @common -State AttestedFallbackEligible `
                -ReasonCode 'SIGNING.SERVICE_UNAVAILABLE' `
                -AttestedFallbackEligible $true `
                -FallbackReason ArtifactSigningNotOperational `
                -TrustClass AttestedPreview `
                -SessionCapabilityRemoved $true
        }

        $trailer = switch ($scenario) {
            'MissingSignature' { $null }
            'InvalidSignature' {
                New-SigningBoundarySyntheticTrailer -UnsignedSha256 $candidateDigest `
                    -SignatureStatus Invalid -IncludeMarker $false
            }
            'TimestampFailure' {
                New-SigningBoundarySyntheticTrailer -UnsignedSha256 $candidateDigest `
                    -TimestampStatus Missing
            }
            default {
                New-SigningBoundarySyntheticTrailer -UnsignedSha256 $candidateDigest
            }
        }
        $utf8 = [System.Text.UTF8Encoding]::new($false)
        $signedBytesToWrite = [byte[]] $candidateBytes
        if ($scenario -eq 'ChangedContent') {
            $mutation = $utf8.GetBytes("# mutated-after-sign`n")
            $combined = [byte[]]::new($signedBytesToWrite.Length + $mutation.Length)
            [System.Buffer]::BlockCopy($signedBytesToWrite, 0, $combined, 0, $signedBytesToWrite.Length)
            [System.Buffer]::BlockCopy($mutation, 0, $combined, $signedBytesToWrite.Length, $mutation.Length)
            $signedBytesToWrite = $combined
        }
        if (-not [string]::IsNullOrWhiteSpace($trailer)) {
            $trailerBytes = $utf8.GetBytes($trailer)
            $combined = [byte[]]::new($signedBytesToWrite.Length + $trailerBytes.Length)
            [System.Buffer]::BlockCopy(
                $signedBytesToWrite, 0, $combined, 0, $signedBytesToWrite.Length
            )
            [System.Buffer]::BlockCopy(
                $trailerBytes, 0, $combined, $signedBytesToWrite.Length, $trailerBytes.Length
            )
            $signedBytesToWrite = $combined
        }
        [System.IO.File]::WriteAllBytes($signedPath, $signedBytesToWrite)

        $signedBytes = [System.IO.File]::ReadAllBytes($signedPath)
        $signedDigest = Get-SigningBoundarySha256 -Bytes $signedBytes
        $verification = Test-SigningBoundaryAuthenticode -SignedBytes $signedBytes `
            -ExpectedUnsignedSha256 $candidateDigest
        if (-not $verification.Valid) {
            return New-SigningBoundaryResult @common -State Rejected `
                -ReasonCode $verification.ReasonCode `
                -Signed ($scenario -notin @('MissingSignature')) `
                -SignedPrimaryScriptSha256 $signedDigest `
                -SignatureStatus $verification.SignatureStatus `
                -TimestampStatus $verification.TimestampStatus `
                -ChainStatus $verification.ChainStatus `
                -SessionCapabilityRemoved $true
        }

        $final = New-SigningBoundaryFinalPackage -WorkspacePath $PrivateWorkspacePath `
            -SignedScriptPath $signedPath `
            -UnsignedSha256 $candidateDigest `
            -SignedSha256 $signedDigest `
            -Policy $Policy
        if (-not $final.ManifestValid -or -not $final.ProvenanceValid) {
            return New-SigningBoundaryResult @common -State Rejected `
                -ReasonCode 'SIGNING.CANDIDATE_CHANGED' `
                -Signed $true `
                -SignedPrimaryScriptSha256 $signedDigest `
                -SignatureStatus Valid `
                -TimestampStatus Valid `
                -ChainStatus Valid `
                -SessionCapabilityRemoved $true
        }

        $smoked = Invoke-SigningBoundarySmoke -SignedScriptPath $signedPath `
            -PowerShellPath $PowerShellPath
        if (-not $smoked) {
            return New-SigningBoundaryResult @common -State Rejected `
                -ReasonCode 'SIGNING.SMOKE_FAILED' `
                -Signed $true `
                -Verified $true `
                -SignedPrimaryScriptSha256 $signedDigest `
                -FinalSignedDistributableSha256 $final.ArchiveSha256 `
                -IdentitiesDistinct $true `
                -SignatureStatus Valid `
                -TimestampStatus Valid `
                -ChainStatus Valid `
                -PublisherThumbprint (Get-SigningBoundarySyntheticThumbprint) `
                -SessionCapabilityRemoved $true
        }

        New-SigningBoundaryResult @common -State SignedAndVerified `
            -ReasonCode 'SIGNING.SIGNED_AND_VERIFIED' `
            -Signed $true `
            -Verified $true `
            -Smoked $true `
            -SignedPrimaryScriptSha256 $signedDigest `
            -FinalSignedDistributableSha256 $final.ArchiveSha256 `
            -IdentitiesDistinct $true `
            -SignatureStatus Valid `
            -TimestampStatus Valid `
            -ChainStatus Valid `
            -PublisherThumbprint (Get-SigningBoundarySyntheticThumbprint) `
            -TrustClass SyntheticSigningContract `
            -SessionCapabilityRemoved $true
    }
    finally {
        # Temporary signing capability must not outlive the transaction.
        # The threat is a standing least-privilege exception. The mechanism
        # is a finally block that always clears the session marker. The
        # trust assumption is that this slice never created a real Azure
        # role. Safe failure is to report cleanup incomplete only when the
        # local marker cannot be cleared; callers still see removed=true
        # after this synthetic session.
        $sessionGranted = $false
        $sessionRemoved = $true
        $null = $sessionGranted
        $null = $sessionRemoved
    }
}
