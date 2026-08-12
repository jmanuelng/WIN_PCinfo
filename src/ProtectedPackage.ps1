$script:ProtectedPackagePolicyBase64 = '__PROTECTED_PACKAGE_POLICY_BASE64__'
$script:ProtectedPackagePolicyDigest = '__PROTECTED_PACKAGE_POLICY_SHA256__'
$script:ProtectedPackageEnvelopeSchemaBase64 = '__PROTECTED_PACKAGE_ENVELOPE_SCHEMA_BASE64__'
$script:ProtectedPackageEnvelopeSchemaDigest = '__PROTECTED_PACKAGE_ENVELOPE_SCHEMA_SHA256__'
$script:AssessmentPackageManifestSchemaBase64 = '__ASSESSMENT_PACKAGE_MANIFEST_SCHEMA_BASE64__'
$script:AssessmentPackageManifestSchemaDigest = '__ASSESSMENT_PACKAGE_MANIFEST_SCHEMA_SHA256__'
$script:ProtectedPackageJsonCommands = $null

function Get-ProtectedPackageSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-ProtectedPackagePolicy {
    if ($script:ProtectedPackagePolicyBase64 -eq '__PROTECTED_PACKAGE_POLICY_BASE64__') {
        $policyPath = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-protected-package.json'
        $bytes = [System.IO.File]::ReadAllBytes($policyPath)
        $expectedDigest = Get-ProtectedPackageSha256 -Bytes $bytes
    }
    else {
        $bytes = [System.Convert]::FromBase64String($script:ProtectedPackagePolicyBase64)
        $expectedDigest = $script:ProtectedPackagePolicyDigest
    }
    if ((Get-ProtectedPackageSha256 -Bytes $bytes) -ne $expectedDigest) {
        throw 'The Protected Package policy failed its embedded digest check.'
    }
    $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    & (Get-ProtectedPackageJsonCommands).ConvertFromJsonCommand -InputObject $json -Depth 30
}

function Get-ProtectedPackageJsonCommands {
    if ($null -ne $script:ProtectedPackageJsonCommands) {
        return $script:ProtectedPackageJsonCommands
    }
    if ($script:ProtectedPackagePolicyBase64 -ne '__PROTECTED_PACKAGE_POLICY_BASE64__') {
        if (-not (Get-Command Get-BuiltInModuleCompatibilityFacts -CommandType Function `
                -ErrorAction SilentlyContinue)) {
            throw 'The trusted JSON command boundary is unavailable.'
        }
        $facts = Get-BuiltInModuleCompatibilityFacts
        if (-not $facts.contractCommandProvenance) {
            throw 'The trusted JSON command boundary failed provenance validation.'
        }
        $script:ProtectedPackageJsonCommands = [pscustomobject]@{
            ConvertToJsonCommand = $facts.convertToJsonCommand
            ConvertFromJsonCommand = $facts.convertFromJsonCommand
            TestJsonCommand = $facts.testJsonCommand
        }
    }
    else {
        # Modular tests bind exact cmdlet objects. The generated application uses
        # the stricter signed-PSHOME provenance branch above.
        $script:ProtectedPackageJsonCommands = [pscustomobject]@{
            ConvertToJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
                'ConvertTo-Json', [System.Management.Automation.CommandTypes]::Cmdlet)
            ConvertFromJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
                'ConvertFrom-Json', [System.Management.Automation.CommandTypes]::Cmdlet)
            TestJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
                'Test-Json', [System.Management.Automation.CommandTypes]::Cmdlet)
        }
    }
    $script:ProtectedPackageJsonCommands
}

function Get-ProtectedPackageSchemaText {
    param([Parameter(Mandatory)] [ValidateSet('Envelope', 'Manifest')] [string] $Kind)

    if ($Kind -eq 'Envelope') {
        $base64 = $script:ProtectedPackageEnvelopeSchemaBase64
        $digest = $script:ProtectedPackageEnvelopeSchemaDigest
        $sentinel = '__PROTECTED_PACKAGE_ENVELOPE_SCHEMA_BASE64__'
        $relativePath = 'schemas/protected-package-envelope.schema.json'
    }
    else {
        $base64 = $script:AssessmentPackageManifestSchemaBase64
        $digest = $script:AssessmentPackageManifestSchemaDigest
        $sentinel = '__ASSESSMENT_PACKAGE_MANIFEST_SCHEMA_BASE64__'
        $relativePath = 'schemas/assessment-package-manifest.schema.json'
    }
    if ($base64 -eq $sentinel) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) $relativePath
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes($path)
        $digest = Get-ProtectedPackageSha256 $bytes
    }
    else { [byte[]] $bytes = [System.Convert]::FromBase64String($base64) }
    if ((Get-ProtectedPackageSha256 $bytes) -ne $digest) {
        throw 'A Protected Package schema failed its embedded digest check.'
    }
    [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
}

function Test-ProtectedPackageJsonSchema {
    param(
        [Parameter(Mandatory)] [string] $Json,
        [Parameter(Mandatory)] [ValidateSet('Envelope', 'Manifest')] [string] $Kind
    )

    $testJson = (Get-ProtectedPackageJsonCommands).TestJsonCommand
    $null -ne $testJson -and (& $testJson -Json $Json `
        -Schema (Get-ProtectedPackageSchemaText $Kind) -ErrorAction Stop)
}

function Test-ProtectedPackageKnownAnswer {
    # This is NIST AES-256-GCM test case 13: an all-zero 256-bit key, 96-bit
    # nonce, and 128-bit plaintext. Keeping the expected bytes outside the
    # implementation makes the test sensitive to accidental key-size, nonce,
    # associated-data, or tag-length changes.
    [byte[]] $key = [byte[]]::new(32)
    [byte[]] $nonce = [byte[]]::new(12)
    [byte[]] $plaintext = [byte[]]::new(16)
    [byte[]] $ciphertext = [byte[]]::new(16)
    [byte[]] $tag = [byte[]]::new(16)
    $aes = [System.Security.Cryptography.AesGcm]::new($key, 16)
    try {
        $aes.Encrypt($nonce, $plaintext, $ciphertext, $tag, [byte[]]::new(0))
        $ciphertextHex = [System.Convert]::ToHexString($ciphertext).ToLowerInvariant()
        $tagHex = [System.Convert]::ToHexString($tag).ToLowerInvariant()
        [pscustomobject][ordered]@{
            verified = $ciphertextHex -eq 'cea7403d4d606b6e074ec5d3baf39d18' -and
                $tagHex -eq 'd0d1c8a799996bf0265b98b5d48ab919'
            ciphertextHex = $ciphertextHex
            tagHex = $tagHex
        }
    }
    finally {
        $aes.Dispose()
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($key)
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($plaintext)
    }
}

function ConvertTo-ProtectedPackageJsonBytes {
    param([Parameter(Mandatory)] $Value)

    $command = (Get-ProtectedPackageJsonCommands).ConvertToJsonCommand
    [System.Text.UTF8Encoding]::new($false).GetBytes(
        (& $command -InputObject $Value -Compress -Depth 30)
    )
}

function Join-ProtectedPackageBytes {
    param([Parameter(Mandatory)] [object[]] $Segments)

    $stream = [System.IO.MemoryStream]::new()
    try {
        foreach ($segment in $Segments) {
            [byte[]] $bytes = $segment
            $stream.Write($bytes, 0, $bytes.Length)
        }
        $stream.ToArray()
    }
    finally { $stream.Dispose() }
}

function Test-ProtectedPackageBytesEqual {
    param(
        [Parameter(Mandatory)] [byte[]] $Left,
        [Parameter(Mandatory)] [byte[]] $Right
    )

    if ($Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor ($Left[$index] -bxor $Right[$index])
    }
    $difference -eq 0
}

function Get-ProtectedPackageUInt32Bytes {
    param([Parameter(Mandatory)] [uint32] $Value)

    [byte[]] $bytes = [System.BitConverter]::GetBytes($Value)
    if (-not [System.BitConverter]::IsLittleEndian) { [System.Array]::Reverse($bytes) }
    $bytes
}

function Get-ProtectedPackageNonce {
    param(
        [Parameter(Mandatory)] [byte[]] $Prefix,
        [Parameter(Mandatory)] [uint32] $ChunkIndex
    )

    # Threat: reusing an AES-GCM nonce with one content key can reveal plaintext
    # relationships and destroy authentication. A package receives a random
    # 64-bit prefix; the big-endian 32-bit chunk index makes each nonce inside
    # that package unique. We trust Windows' CSPRNG for prefix collision safety,
    # and reopening rejects any nonce that does not match this construction.
    if ($Prefix.Length -ne 8) { throw 'The nonce prefix must be exactly eight bytes.' }
    [byte[]] $indexBytes = [System.BitConverter]::GetBytes($ChunkIndex)
    if ([System.BitConverter]::IsLittleEndian) { [System.Array]::Reverse($indexBytes) }
    Join-ProtectedPackageBytes -Segments @($Prefix, $indexBytes)
}

function Get-ProtectedPackageChunkAssociatedData {
    param(
        [Parameter(Mandatory)] [byte[]] $HeaderBytes,
        [Parameter(Mandatory)] [uint32] $ChunkIndex,
        [Parameter(Mandatory)] [uint32] $PlaintextLength,
        [Parameter(Mandatory)] [uint32] $CiphertextLength,
        [Parameter(Mandatory)] [byte[]] $Nonce
    )

    # The AAD frame is exact and unambiguous: the complete header bytes, three
    # fixed-width UInt32 values, and the 12-byte nonce. It binds non-secret format
    # decisions and chunk placement without hiding them. Any altered header,
    # index, length, or nonce makes GCM fail before an artifact is returned.
    Join-ProtectedPackageBytes -Segments @(
        $HeaderBytes,
        (Get-ProtectedPackageUInt32Bytes $ChunkIndex),
        (Get-ProtectedPackageUInt32Bytes $PlaintextLength),
        (Get-ProtectedPackageUInt32Bytes $CiphertextLength),
        $Nonce
    )
}

function Protect-ProtectedPackageContentKey {
    param([Parameter(Mandatory)] [byte[]] $ContentKey)

    $policy = Get-ProtectedPackagePolicy
    [byte[]] $entropy = [System.Text.UTF8Encoding]::new($false).GetBytes(
        [string] $policy.envelope.keyProtection.additionalEntropyUtf8
    )
    try {
        # DPAPI CurrentUser delegates the local-protector boundary to Windows.
        # The ciphertext is bound to this Windows user profile and this device;
        # neither an elevated alternate administrator nor copied package bytes
        # can unwrap it. DPAPI authenticates the wrapped key and fails closed.
        [System.Security.Cryptography.ProtectedData]::Protect(
            $ContentKey, $entropy,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
    }
    finally { [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($entropy) }
}

function Unprotect-ProtectedPackageContentKey {
    param([Parameter(Mandatory)] [byte[]] $ProtectedContentKey)

    $policy = Get-ProtectedPackagePolicy
    [byte[]] $entropy = [System.Text.UTF8Encoding]::new($false).GetBytes(
        [string] $policy.envelope.keyProtection.additionalEntropyUtf8
    )
    try {
        [System.Security.Cryptography.ProtectedData]::Unprotect(
            $ProtectedContentKey, $entropy,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
    }
    finally { [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($entropy) }
}

function Test-ProtectedPackageAssessmentRecord {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    if (-not (Get-Command Test-AssessmentContract -CommandType Function -ErrorAction SilentlyContinue)) {
        return $false
    }
    $commands = Get-ProtectedPackageJsonCommands
    $validation = Test-AssessmentContract -Utf8Bytes $Bytes `
        -ConvertFromJsonCommand $commands.ConvertFromJsonCommand `
        -TestJsonCommand $commands.TestJsonCommand
    [bool] $validation.accepted
}

function New-DeterministicAssessmentPackage {
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Artifacts,
        [Parameter(Mandatory)] [string] $AssessmentContractSetVersion,
        [Parameter(Mandatory)] [ValidateSet('Complete', 'RecoverablePartial')] [string] $Completeness
    )

    $policy = Get-ProtectedPackagePolicy
    $definitions = @($policy.innerPackage.artifacts)
    $expectedPaths = @($definitions.relativePath)
    $actualPaths = @($Artifacts.Keys | ForEach-Object { [string] $_ })
    if ($actualPaths.Count -ne $expectedPaths.Count -or
        @($actualPaths | Where-Object { $_ -notin $expectedPaths }).Count -gt 0) {
        throw 'The inner package must contain exactly the release-declared artifacts.'
    }

    $contents = [System.Collections.Generic.List[object]]::new()
    $artifactBytes = [ordered]@{}
    foreach ($definition in $definitions) {
        $relativePath = [string] $definition.relativePath
        [byte[]] $bytes = $Artifacts[$relativePath]
        if ($null -eq $bytes -or $bytes.Length -gt [int] $definition.maximumBytes) {
            throw "The release evidence bound was exceeded for $relativePath."
        }
        if ($relativePath -eq 'assessment-record.json' -and
            -not (Test-ProtectedPackageAssessmentRecord -Bytes $bytes)) {
            throw 'The Assessment Record failed its exact structural and semantic Contract Set.'
        }
        $artifactBytes[$relativePath] = $bytes
        $contents.Add([pscustomobject][ordered]@{
            relativePath = $relativePath
            mediaType = [string] $definition.mediaType
            byteLength = $bytes.Length
            sha256 = Get-ProtectedPackageSha256 -Bytes $bytes
        })
    }

    $manifest = [pscustomobject][ordered]@{
        kind = 'win-pcinfo.assessment-package-manifest'
        contractVersion = '1.0.0'
        productRelease = [string] $policy.release
        assessmentContractSet = $AssessmentContractSetVersion
        packagePolicy = [string] $policy.policyId
        manifestContract = [string] $policy.innerPackage.manifestContract
        completeness = $Completeness
        protection = [pscustomobject][ordered]@{
            state = 'EncryptedAuthenticated'
            authorshipClaim = $false
            durableTamperEvidenceClaim = $false
        }
        contents = @($contents)
    }
    [byte[]] $manifestBytes = ConvertTo-ProtectedPackageJsonBytes -Value $manifest
    $entries = [ordered]@{ 'package-manifest.json' = $manifestBytes }
    foreach ($path in $expectedPaths) { $entries[$path] = [byte[]] $artifactBytes[$path] }

    $memory = [System.IO.MemoryStream]::new()
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $memory, [System.IO.Compression.ZipArchiveMode]::Create, $true,
            [System.Text.UTF8Encoding]::new($false)
        )
        try {
            foreach ($path in @($entries.Keys | Sort-Object)) {
                $entry = $archive.CreateEntry(
                    $path, [System.IO.Compression.CompressionLevel]::NoCompression
                )
                $entry.LastWriteTime = [System.DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [System.TimeSpan]::Zero)
                $entry.ExternalAttributes = 0
                $stream = $entry.Open()
                try {
                    [byte[]] $bytes = $entries[$path]
                    $stream.Write($bytes, 0, $bytes.Length)
                }
                finally { $stream.Dispose() }
            }
        }
        finally { $archive.Dispose() }
        [byte[]] $innerBytes = $memory.ToArray()
        if ($innerBytes.Length -gt [int] $policy.innerPackage.maximumArchiveBytes) {
            throw 'The deterministic inner package exceeded its release bound.'
        }
        [pscustomobject][ordered]@{ bytes = $innerBytes; manifest = $manifest }
    }
    finally { $memory.Dispose() }
}

function Read-ProtectedPackageZipEntry {
    param(
        [Parameter(Mandatory)] [System.IO.Compression.ZipArchiveEntry] $Entry,
        [Parameter(Mandatory)] [int] $MaximumBytes
    )

    if ($Entry.Length -lt 0 -or $Entry.Length -gt $MaximumBytes) {
        throw 'An inner-package entry exceeded its declared evidence bound.'
    }
    $input = $Entry.Open()
    $output = [System.IO.MemoryStream]::new()
    try {
        $input.CopyTo($output)
        if ($output.Length -gt $MaximumBytes) { throw 'An inner-package entry expanded beyond its bound.' }
        $output.ToArray()
    }
    finally { $input.Dispose(); $output.Dispose() }
}

function Test-AssessmentPackageManifest {
    param(
        [Parameter(Mandatory)] $Manifest,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Artifacts
    )

    $policy = Get-ProtectedPackagePolicy
    $expectedTop = @('assessmentContractSet','completeness','contents','contractVersion','kind',
        'manifestContract','packagePolicy','productRelease','protection')
    if ((@($Manifest.PSObject.Properties.Name | Sort-Object) -join '|') -ne ($expectedTop -join '|') -or
        $Manifest.kind -ne 'win-pcinfo.assessment-package-manifest' -or
        $Manifest.contractVersion -ne '1.0.0' -or $Manifest.productRelease -ne $policy.release -or
        $Manifest.packagePolicy -ne $policy.policyId -or
        $Manifest.manifestContract -ne $policy.innerPackage.manifestContract -or
        $Manifest.assessmentContractSet -notin @('1.0.0','1.1.0','1.2.0','1.3.0','1.4.0') -or
        $Manifest.completeness -notin @($policy.manifest.completenessStates)) { return $false }
    $protectionNames = @($Manifest.protection.PSObject.Properties.Name | Sort-Object)
    if (($protectionNames -join '|') -ne 'authorshipClaim|durableTamperEvidenceClaim|state' -or
        $Manifest.protection.state -ne 'EncryptedAuthenticated' -or
        [bool] $Manifest.protection.authorshipClaim -or
        [bool] $Manifest.protection.durableTamperEvidenceClaim) { return $false }
    $definitions = @($policy.innerPackage.artifacts)
    if (@($Manifest.contents).Count -ne $definitions.Count) { return $false }
    for ($index = 0; $index -lt $definitions.Count; $index++) {
        $content = @($Manifest.contents)[$index]
        $definition = $definitions[$index]
        if ((@($content.PSObject.Properties.Name | Sort-Object) -join '|') -ne
            'byteLength|mediaType|relativePath|sha256' -or
            $content.relativePath -ne $definition.relativePath -or
            $content.mediaType -ne $definition.mediaType -or
            -not $Artifacts.Contains([string] $content.relativePath)) { return $false }
        [byte[]] $bytes = $Artifacts[[string] $content.relativePath]
        if ([long] $content.byteLength -ne $bytes.Length -or
            [string] $content.sha256 -ne (Get-ProtectedPackageSha256 -Bytes $bytes)) { return $false }
    }
    # Package completeness describes whether this closed package contains the
    # complete release-declared artifact set. It is intentionally independent
    # of the Assessment Run Outcome: a valid CompletedWithGaps record can be a
    # complete, fully protected package whose evidence truthfully contains gaps.
    $true
}

function Read-DeterministicAssessmentPackage {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    $policy = Get-ProtectedPackagePolicy
    if ($Bytes.Length -gt [int] $policy.innerPackage.maximumArchiveBytes) {
        throw 'The inner package exceeded its release size bound.'
    }
    $memory = [System.IO.MemoryStream]::new($Bytes, $false)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $memory, [System.IO.Compression.ZipArchiveMode]::Read, $true,
            [System.Text.UTF8Encoding]::new($false, $true)
        )
        try {
            $entries = @($archive.Entries)
            $expectedNames = @('package-manifest.json') + @($policy.innerPackage.artifacts.relativePath)
            $actualNames = @($entries.FullName)
            if ($entries.Count -ne [int] $policy.innerPackage.maximumEntryCount -or
                @($actualNames | Sort-Object -Unique).Count -ne $actualNames.Count -or
                @($actualNames | Where-Object { $_ -notin $expectedNames }).Count -gt 0 -or
                @($expectedNames | Where-Object { $_ -notin $actualNames }).Count -gt 0) {
                throw 'The archive entry graph is not the closed release package.'
            }
            $manifestEntry = $entries | Where-Object FullName -eq 'package-manifest.json'
            [byte[]] $manifestBytes = Read-ProtectedPackageZipEntry -Entry $manifestEntry -MaximumBytes 32768
            $manifestJson = [System.Text.UTF8Encoding]::new($false, $true).GetString($manifestBytes)
            if (-not (Test-ProtectedPackageJsonSchema -Json $manifestJson -Kind Manifest)) {
                throw 'The Assessment Package Manifest failed its release schema.'
            }
            $manifest = & (Get-ProtectedPackageJsonCommands).ConvertFromJsonCommand `
                -InputObject $manifestJson -Depth 20
            $artifacts = [ordered]@{}
            foreach ($definition in @($policy.innerPackage.artifacts)) {
                $entry = $entries | Where-Object FullName -eq $definition.relativePath
                $artifacts[[string] $definition.relativePath] = Read-ProtectedPackageZipEntry `
                    -Entry $entry -MaximumBytes ([int] $definition.maximumBytes)
            }
            if (-not (Test-AssessmentPackageManifest -Manifest $manifest -Artifacts $artifacts) -or
                -not (Test-ProtectedPackageAssessmentRecord `
                    -Bytes ([byte[]] $artifacts['assessment-record.json']))) {
                throw 'The package manifest, digests, schema, or semantics are invalid.'
            }
            [pscustomobject][ordered]@{ manifest = $manifest; artifacts = $artifacts }
        }
        finally { $archive.Dispose() }
    }
    finally { $memory.Dispose() }
}

function Read-ProtectedPackageEnvelopeHeader {
    param([Parameter(Mandatory)] [System.IO.BinaryReader] $Reader)

    $policy = Get-ProtectedPackagePolicy
    [byte[]] $magic = $Reader.ReadBytes(8)
    if ([System.Text.Encoding]::ASCII.GetString($magic) -ne [string] $policy.envelope.magic) {
        throw 'The package magic is unsupported.'
    }
    $headerLength = $Reader.ReadInt32()
    if ($headerLength -lt 1 -or $headerLength -gt [int] $policy.envelope.maximumHeaderUtf8Bytes) {
        throw 'The package header length is invalid.'
    }
    [byte[]] $headerBytes = $Reader.ReadBytes($headerLength)
    if ($headerBytes.Length -ne $headerLength) { throw 'The package header is truncated.' }
    $headerJson = [System.Text.UTF8Encoding]::new($false, $true).GetString($headerBytes)
    if (-not (Test-ProtectedPackageJsonSchema -Json $headerJson -Kind Envelope)) {
        throw 'The package envelope header failed its release schema.'
    }
    $header = & (Get-ProtectedPackageJsonCommands).ConvertFromJsonCommand `
        -InputObject $headerJson -Depth 10
    $expectedNames = @($policy.envelope.outerMetadata.allowedFields | Sort-Object)
    if ((@($header.PSObject.Properties.Name | Sort-Object) -join '|') -ne
        ($expectedNames -join '|') -or -not (Test-ProtectedPackageHeader $header)) {
        throw 'The package header contains unknown, missing, or inconsistent metadata.'
    }
    [pscustomobject][ordered]@{ header = $header; headerBytes = $headerBytes }
}

function Get-ProtectedPackageEnvelopeHeader {
    param([Parameter(Mandatory)] [string] $LiteralPath)

    $stream = [System.IO.File]::Open($LiteralPath, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $reader = [System.IO.BinaryReader]::new($stream, [System.Text.UTF8Encoding]::new($false, $true), $true)
    try { (Read-ProtectedPackageEnvelopeHeader -Reader $reader).header }
    finally { $reader.Dispose(); $stream.Dispose() }
}

function Test-ProtectedPackageHeader {
    param([Parameter(Mandatory)] $Header)

    $policy = Get-ProtectedPackagePolicy
    if ($Header.formatVersion -ne 1 -or $Header.algorithm -ne 'AES-256-GCM' -or
        $Header.keyProtection -ne 'DPAPI-CurrentUser' -or
        $Header.recipientKeyProtection -notin @('None', 'RSA-OAEP-SHA-256') -or
        $Header.chunkPlaintextBytes -ne [int] $policy.envelope.contentEncryption.chunkPlaintextBytes -or
        $Header.plaintextLength -lt 1 -or
        $Header.plaintextLength -gt [int] $policy.envelope.maximumPlaintextBytes -or
        $Header.chunkCount -ne [Math]::Ceiling(
            $Header.plaintextLength / [double] $Header.chunkPlaintextBytes
        )) { return $false }
    try {
        [byte[]] $prefix = [System.Convert]::FromBase64String([string] $Header.noncePrefix)
        [byte[]] $protectedKey = [System.Convert]::FromBase64String([string] $Header.protectedContentKey)
        $recipientWrapValid = if ($Header.recipientKeyProtection -eq 'None') {
            $null -eq $Header.recipientWrappedContentKey
        }
        else {
            [byte[]] $recipientWrap = [System.Convert]::FromBase64String(
                [string] $Header.recipientWrappedContentKey
            )
            $recipientWrap.Length -ge 256 -and $recipientWrap.Length -le 2048
        }
        $prefix.Length -eq 8 -and $protectedKey.Length -gt 32 -and
            $protectedKey.Length -le 4096 -and $recipientWrapValid
    }
    catch { $false }
}

function Write-ProtectedPackageEnvelope {
    param(
        [Parameter(Mandatory)] [byte[]] $Plaintext,
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $RecipientCertificate,
        [Parameter(DontShow)]
        [System.DateTimeOffset] $SyntheticAdmissionTime = [System.DateTimeOffset]::UtcNow,
        [Parameter(DontShow)]
        [ValidateSet('None', 'SetupFailure', 'InterruptedWrite', 'DiskExhaustion')]
        [string] $SyntheticWriteFailure = 'None'
    )

    if (-not (Get-Command New-EvidenceWorkspaceOwnedWriteStream -CommandType Function `
            -ErrorAction SilentlyContinue)) {
        throw 'The exact owned-file write boundary is unavailable.'
    }
    $policy = Get-ProtectedPackagePolicy
    [byte[]] $contentKey = [byte[]]::new(32)
    [byte[]] $noncePrefix = [byte[]]::new(8)
    $fileSystemIdentity = ''
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($contentKey)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($noncePrefix)
    try {
        [byte[]] $protectedKey = Protect-ProtectedPackageContentKey -ContentKey $contentKey
        [byte[]] $recipientWrappedKey = if ($null -ne $RecipientCertificate) {
            if (-not (Get-Command Protect-RecipientContentKey -CommandType Function `
                    -ErrorAction SilentlyContinue)) {
                throw 'Recipient key protection is unavailable.'
            }
            Protect-RecipientContentKey -ContentKey $contentKey `
                -Certificate $RecipientCertificate -AdmissionTime $SyntheticAdmissionTime
        }
        else { $null }
        $chunkSize = [int] $policy.envelope.contentEncryption.chunkPlaintextBytes
        $chunkCount = [int] [Math]::Ceiling($Plaintext.Length / [double] $chunkSize)
        $header = [pscustomobject][ordered]@{
            formatVersion = 1
            algorithm = 'AES-256-GCM'
            keyProtection = 'DPAPI-CurrentUser'
            recipientKeyProtection = if ($null -eq $recipientWrappedKey) {
                'None'
            }
            else { 'RSA-OAEP-SHA-256' }
            chunkPlaintextBytes = $chunkSize
            plaintextLength = $Plaintext.Length
            chunkCount = $chunkCount
            noncePrefix = [System.Convert]::ToBase64String($noncePrefix)
            protectedContentKey = [System.Convert]::ToBase64String($protectedKey)
            recipientWrappedContentKey = if ($null -eq $recipientWrappedKey) {
                $null
            }
            else { [System.Convert]::ToBase64String($recipientWrappedKey) }
        }
        [byte[]] $headerBytes = ConvertTo-ProtectedPackageJsonBytes -Value $header
        if ($headerBytes.Length -gt [int] $policy.envelope.maximumHeaderUtf8Bytes) {
            throw 'The package header exceeded its release bound.'
        }
        $stream = $null
        $writer = $null
        $aes = $null
        $operationError = $null
        $cleanupError = $null
        try {
            # The native handle carries DELETE authority and denies delete sharing.
            # Identity is read from that same handle, so failure cleanup can mark
            # the exact created object for deletion without trusting its pathname.
            $stream = New-EvidenceWorkspaceOwnedWriteStream -LiteralPath $LiteralPath
            $fileSystemIdentity = Get-EvidenceWorkspaceOwnedStreamIdentity -Stream $stream
            if ($SyntheticWriteFailure -eq 'SetupFailure') {
                throw [System.InvalidOperationException]::new(
                    'Synthetic failure before package writer construction.'
                )
            }
            $writer = [System.IO.BinaryWriter]::new(
                $stream, [System.Text.UTF8Encoding]::new($false), $true
            )
            $aes = [System.Security.Cryptography.AesGcm]::new($contentKey, 16)
            $writer.Write([System.Text.Encoding]::ASCII.GetBytes([string] $policy.envelope.magic))
            $writer.Write([int] $headerBytes.Length)
            $writer.Write($headerBytes)
            if ($SyntheticWriteFailure -eq 'InterruptedWrite') {
                throw [System.OperationCanceledException]::new('Synthetic interrupted package write.')
            }
            if ($SyntheticWriteFailure -eq 'DiskExhaustion') {
                throw [System.IO.IOException]::new('Synthetic exhausted package destination.')
            }
            for ($index = 0; $index -lt $chunkCount; $index++) {
                $offset = $index * $chunkSize
                $length = [Math]::Min($chunkSize, $Plaintext.Length - $offset)
                [byte[]] $chunk = [byte[]]::new($length)
                [System.Buffer]::BlockCopy($Plaintext, $offset, $chunk, 0, $length)
                [byte[]] $ciphertext = [byte[]]::new($length)
                [byte[]] $tag = [byte[]]::new(16)
                [byte[]] $nonce = Get-ProtectedPackageNonce -Prefix $noncePrefix -ChunkIndex $index
                [byte[]] $aad = Get-ProtectedPackageChunkAssociatedData -HeaderBytes $headerBytes `
                    -ChunkIndex $index -PlaintextLength $length -CiphertextLength $length -Nonce $nonce
                try {
                    $aes.Encrypt($nonce, $chunk, $ciphertext, $tag, $aad)
                    $writer.Write([int] $index)
                    $writer.Write([int] $length)
                    $writer.Write([int] $ciphertext.Length)
                    $writer.Write($nonce)
                    $writer.Write($ciphertext)
                    $writer.Write($tag)
                }
                finally {
                    [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($chunk)
                    [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($aad)
                }
            }
            $writer.Flush()
            $stream.Flush($true)
        }
        catch { $operationError = $_ }
        finally {
            if ($null -ne $operationError -and $null -ne $stream) {
                try { Remove-EvidenceWorkspaceOwnedStreamOnClose -Stream $stream }
                catch { $cleanupError = $_ }
            }
            if ($null -ne $aes) { $aes.Dispose() }
            if ($null -ne $writer) { $writer.Dispose() }
            if ($null -ne $stream) { $stream.Dispose() }
        }
        if ($null -ne $cleanupError) {
            $exception = [System.InvalidOperationException]::new(
                'The incomplete package could not be proved absent.',
                $operationError.Exception
            )
            $exception.Data['WINPCInfoCleanupIncomplete'] = $true
            throw $exception
        }
        if ($null -ne $operationError) { throw $operationError }
        [pscustomobject][ordered]@{ fileSystemIdentity = $fileSystemIdentity }
    }
    catch { throw }
    finally {
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($contentKey)
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($noncePrefix)
    }
}

function Read-ProtectedEvidencePackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $RecipientCertificate,
        [Parameter(DontShow)]
        [ValidateSet('None', 'WrongUser', 'WrongDevice')]
        [string] $SyntheticProtectionContext = 'None'
    )

    $integrityFailure = [pscustomobject][ordered]@{
        state = 'IntegrityFailed'; verified = $false; manifest = $null
        artifacts = $null; innerPackageSha256 = $null
    }
    $protectionUnavailable = [pscustomobject][ordered]@{
        state = 'ProtectionUnavailable'; verified = $false; manifest = $null
        artifacts = $null; innerPackageSha256 = $null
    }
    [byte[]] $contentKey = $null
    [byte[]] $innerBytes = $null
    try {
        $policy = Get-ProtectedPackagePolicy
        $fullPath = [System.IO.Path]::GetFullPath($LiteralPath)
        $fileInfo = [System.IO.FileInfo]::new($fullPath)
        if (-not $fileInfo.Exists -or $fileInfo.Length -gt 2097152) { return $integrityFailure }
        $stream = [System.IO.File]::Open($fullPath, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $reader = [System.IO.BinaryReader]::new($stream, [System.Text.UTF8Encoding]::new($false, $true), $true)
        try {
            $parsedHeader = Read-ProtectedPackageEnvelopeHeader -Reader $reader
            $header = $parsedHeader.header
            [byte[]] $headerBytes = $parsedHeader.headerBytes
            [byte[]] $prefix = [System.Convert]::FromBase64String([string] $header.noncePrefix)
            [byte[]] $wrappedKey = [System.Convert]::FromBase64String([string] $header.protectedContentKey)
            if ($SyntheticProtectionContext -ne 'None') {
                # The closed synthetic seam models Windows refusing a DPAPI blob
                # in a different user or device context. It cannot provide a key,
                # user, SID, device identifier, or alternate unprotector.
                throw [System.Security.Cryptography.CryptographicException]::new(
                    'The synthetic DPAPI protection context does not match.'
                )
            }
            if ($null -ne $RecipientCertificate) {
                if ($header.recipientKeyProtection -ne 'RSA-OAEP-SHA-256' -or
                    $null -eq $header.recipientWrappedContentKey -or
                    -not (Get-Command Unprotect-RecipientContentKey -CommandType Function `
                        -ErrorAction SilentlyContinue)) {
                    return $protectionUnavailable
                }
                try {
                    [byte[]] $recipientWrappedKey = [System.Convert]::FromBase64String(
                        [string] $header.recipientWrappedContentKey
                    )
                    $contentKey = Unprotect-RecipientContentKey `
                        -WrappedContentKey $recipientWrappedKey -Certificate $RecipientCertificate
                }
                catch { return $protectionUnavailable }
            }
            else {
                $contentKey = Unprotect-ProtectedPackageContentKey -ProtectedContentKey $wrappedKey
            }
            if ($contentKey.Length -ne 32) { return $integrityFailure }
            $innerBytes = [byte[]]::new([int] $header.plaintextLength)
            $aes = [System.Security.Cryptography.AesGcm]::new($contentKey, 16)
            try {
                $offset = 0
                for ($expectedIndex = 0; $expectedIndex -lt [int] $header.chunkCount; $expectedIndex++) {
                    $index = $reader.ReadInt32()
                    $plainLength = $reader.ReadInt32()
                    $cipherLength = $reader.ReadInt32()
                    $expectedLength = [Math]::Min(
                        [int] $header.chunkPlaintextBytes,
                        [int] $header.plaintextLength - $offset
                    )
                    if ($index -ne $expectedIndex -or $plainLength -ne $expectedLength -or
                        $cipherLength -ne $expectedLength) { return $integrityFailure }
                    [byte[]] $nonce = $reader.ReadBytes(12)
                    [byte[]] $expectedNonce = Get-ProtectedPackageNonce -Prefix $prefix -ChunkIndex $expectedIndex
                    if ($nonce.Length -ne 12 -or
                        -not (Test-ProtectedPackageBytesEqual $nonce $expectedNonce)) {
                        return $integrityFailure
                    }
                    [byte[]] $ciphertext = $reader.ReadBytes($cipherLength)
                    [byte[]] $tag = $reader.ReadBytes(16)
                    if ($ciphertext.Length -ne $cipherLength -or $tag.Length -ne 16) { return $integrityFailure }
                    [byte[]] $chunk = [byte[]]::new($plainLength)
                    [byte[]] $aad = Get-ProtectedPackageChunkAssociatedData -HeaderBytes $headerBytes `
                        -ChunkIndex $index -PlaintextLength $plainLength `
                        -CiphertextLength $cipherLength -Nonce $nonce
                    try {
                        $aes.Decrypt($nonce, $ciphertext, $tag, $chunk, $aad)
                        [System.Buffer]::BlockCopy($chunk, 0, $innerBytes, $offset, $plainLength)
                    }
                    finally {
                        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($chunk)
                        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($aad)
                    }
                    $offset += $plainLength
                }
                if ($stream.Position -ne $stream.Length -or $offset -ne $innerBytes.Length) {
                    return $integrityFailure
                }
            }
            finally { $aes.Dispose() }
        }
        finally { $reader.Dispose(); $stream.Dispose() }

        $inner = Read-DeterministicAssessmentPackage -Bytes $innerBytes
        [pscustomobject][ordered]@{
            state = 'Verified'
            verified = $true
            manifest = $inner.manifest
            artifacts = $inner.artifacts
            innerPackageSha256 = Get-ProtectedPackageSha256 -Bytes $innerBytes
        }
    }
    catch { $integrityFailure }
    finally {
        if ($null -ne $contentKey) {
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($contentKey)
        }
        if ($null -ne $innerBytes) {
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($innerBytes)
        }
    }
}

function New-ProtectedEvidencePackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $DestinationDirectory,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Artifacts,
        [Parameter(Mandatory)] [ValidateSet('1.0.0','1.1.0','1.2.0','1.3.0','1.4.0')] [string] $AssessmentContractSetVersion,
        [Parameter(Mandatory)] [ValidateSet('Complete', 'RecoverablePartial')] [string] $Completeness,
        [Parameter()] [string] $JournalPath,
        [Parameter()] $ApprovedRecipient,
        [Parameter(DontShow)]
        [System.DateTimeOffset] $SyntheticAdmissionTime = [System.DateTimeOffset]::UtcNow,
        [Parameter(DontShow)]
        [ValidateSet('None', 'SetupFailure', 'InterruptedWrite', 'DiskExhaustion')]
        [string] $SyntheticWriteFailure = 'None'
    )

    $failure = [pscustomobject][ordered]@{
        state = 'IntegrityFailed'; verified = $false; protection = 'None'
        recoverable = $false; packagePath = $null; innerPackageSha256 = $null
    }
    $inner = $null
    $provisionalPath = $null
    $finalPath = $null
    $provisionalIdentity = ''
    $finalNamed = $false
    $ownedRecipientCertificate = $null
    try {
        $recipientCertificate = $null
        if ($null -ne $ApprovedRecipient) {
            if ([string] $ApprovedRecipient.state -cne 'Approved' -or
                [string] $ApprovedRecipient.admissionKind -cne 'ApprovedRecipientForPackage' -or
                [string]::IsNullOrWhiteSpace([string] $ApprovedRecipient.fingerprint)) {
                return $failure
            }
            $certificateProperty = $ApprovedRecipient.PSObject.Properties['certificate']
            $encodedCertificateProperty =
                $ApprovedRecipient.PSObject.Properties['certificateDerBase64']
            $recipientCertificate = if ($null -ne $certificateProperty -and
                $null -ne $certificateProperty.Value) {
                $certificateProperty.Value
            }
            elseif ($null -ne $encodedCertificateProperty -and
                -not [string]::IsNullOrWhiteSpace([string] $encodedCertificateProperty.Value)) {
                $ownedRecipientCertificate =
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                        [System.Convert]::FromBase64String(
                            [string] $encodedCertificateProperty.Value
                        )
                    )
                $ownedRecipientCertificate
            }
            else { return $failure }
            $certificateFingerprint = $recipientCertificate.GetCertHashString(
                [System.Security.Cryptography.HashAlgorithmName]::SHA256
            ).ToLowerInvariant()
            if ($certificateFingerprint -cne [string] $ApprovedRecipient.fingerprint -or
                -not (Test-RecipientCertificateForNewPackage `
                    -Certificate $recipientCertificate -Now $SyntheticAdmissionTime)) {
                return $failure
            }
        }
        $destination = [System.IO.Path]::GetFullPath($DestinationDirectory)
        if (-not [System.IO.Directory]::Exists($destination)) { return $failure }
        # A product-generated opaque name prevents assessment, user, device, or
        # organization labels from leaking outside the ciphertext envelope.
        $packageId = [guid]::NewGuid().ToString('N')
        $finalPath = Join-Path $destination "package-$packageId.winpcinfo"
        $provisionalPath = "$finalPath.partial"
        $inner = New-DeterministicAssessmentPackage -Artifacts $Artifacts `
            -AssessmentContractSetVersion $AssessmentContractSetVersion -Completeness $Completeness
        $writeResult = Write-ProtectedPackageEnvelope -Plaintext $inner.bytes -LiteralPath $provisionalPath `
            -RecipientCertificate $recipientCertificate -SyntheticAdmissionTime $SyntheticAdmissionTime `
            -SyntheticWriteFailure $SyntheticWriteFailure
        $provisionalIdentity = [string] $writeResult.fileSystemIdentity

        # Final naming is a trust boundary, not a cosmetic rename. Close and
        # flush the writer first, then reopen through DPAPI and validate every
        # authenticated chunk, archive entry, manifest reference, digest, schema,
        # and Assessment Contract semantic. A failed check removes the incomplete
        # ciphertext and no package path is reported.
        $verification = Read-ProtectedEvidencePackage -LiteralPath $provisionalPath
        if (-not $verification.verified -or
            $verification.innerPackageSha256 -ne (Get-ProtectedPackageSha256 -Bytes $inner.bytes)) {
            return $failure
        }
        foreach ($value in @($verification.artifacts.Values)) {
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]] $value)
        }
        if ((Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $provisionalPath) -ne
            $provisionalIdentity) {
            throw 'The validated provisional ciphertext identity changed before final naming.'
        }
        [System.IO.File]::Move($provisionalPath, $finalPath)
        $finalNamed = $true
        if (-not [string]::IsNullOrWhiteSpace($JournalPath)) {
            if (-not (Get-Command Register-FinalizedEvidencePackage -CommandType Function -ErrorAction SilentlyContinue)) {
                throw 'The finalized package cannot be registered for recovery.'
            }
            Register-FinalizedEvidencePackage -JournalPath $JournalPath -LiteralPath $finalPath
        }
        [pscustomobject][ordered]@{
            state = 'Verified'
            verified = $true
            protection = 'ProtectedEvidencePackage'
            recoverable = $true
            packagePath = $finalPath
            innerPackageSha256 = Get-ProtectedPackageSha256 -Bytes $inner.bytes
        }
    }
    catch {
        if ([bool] $_.Exception.Data['WINPCInfoCleanupIncomplete']) {
            return [pscustomobject][ordered]@{
                state = 'CleanupIncomplete'; verified = $false
                protection = 'None'; recoverable = $false
                packagePath = $null; innerPackageSha256 = $null
            }
        }
        if ($finalNamed) {
            return [pscustomobject][ordered]@{
                state = 'CleanupIncomplete'; verified = $false
                protection = 'ProtectedEvidencePackage'; recoverable = $true
                packagePath = $finalPath; innerPackageSha256 = $null
            }
        }
        $failure
    }
    finally {
        if ($null -ne $ownedRecipientCertificate) {
            $ownedRecipientCertificate.Dispose()
        }
        if ($null -ne $inner -and $null -ne $inner.bytes) {
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]] $inner.bytes)
        }
        if ($provisionalIdentity -and $null -ne $provisionalPath -and
            [System.IO.File]::Exists($provisionalPath) -and
            (Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $provisionalPath) -eq
                $provisionalIdentity) {
            [System.IO.File]::Delete($provisionalPath)
        }
    }
}

function Open-EvidenceViewingSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $PackagePath,
        [Parameter(Mandatory)] [ValidateSet('assessment-record.json', 'assessment-report.html')]
        [string] $RequestedArtifact,
        [Parameter(Mandatory)] [string] $ViewingBasePath
    )

    $failure = [pscustomobject][ordered]@{
        state = 'IntegrityFailed'; verified = $false; artifactPath = $null
        recoveryRegistered = $false; journalPath = $null
    }
    $opened = Read-ProtectedEvidencePackage -LiteralPath $PackagePath
    if (-not $opened.verified -or -not $opened.artifacts.Contains($RequestedArtifact)) {
        return $failure
    }
    $workspace = $null
    $journal = $null
    try {
        if (-not (Get-Command New-EvidenceWorkspace -CommandType Function -ErrorAction SilentlyContinue)) {
            return $failure
        }
        $sessionId = [guid]::NewGuid()
        $workspace = New-EvidenceWorkspace -RequestedBasePath $ViewingBasePath -RunId $sessionId
        if ($workspace.state -ne 'Created') { return $failure }
        $planDigest = Get-ProtectedPackageSha256 -Bytes ([System.IO.File]::ReadAllBytes(
            [System.IO.Path]::GetFullPath($PackagePath)
        ))
        $journal = New-RunRecoveryJournal -Workspace $workspace -RecoveryBasePath $ViewingBasePath `
            -PlanDigest $planDigest -Phase Viewing
        $content = [byte[]] $opened.artifacts[$RequestedArtifact]
        $registration = New-EvidenceViewingArtifact -JournalPath $journal.journalPath `
            -Content $content
        if ($registration.state -ne 'Registered') { throw 'Viewing plaintext registration failed.' }
        [pscustomobject][ordered]@{
            state = 'Opened'
            verified = $true
            requestedArtifact = $RequestedArtifact
            artifactId = [string] $registration.artifactId
            artifactPath = [string] $registration.literalPath
            workspacePath = [string] $workspace.workspacePath
            journalPath = [string] $journal.journalPath
            journalDirectory = [string] $journal.journalDirectory
            recoveryRegistered = $true
        }
    }
    catch {
        if ($null -ne $journal) {
            return [pscustomobject][ordered]@{
                state = 'CleanupIncomplete'; verified = $false; artifactPath = $null
                recoveryRegistered = $true; journalPath = [string] $journal.journalPath
            }
        }
        $failure
    }
    finally {
        if ($null -ne $opened.artifacts) {
            foreach ($value in @($opened.artifacts.Values)) {
                [System.Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]] $value)
            }
        }
    }
}

function Close-EvidenceViewingSession {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Session)

    $incomplete = [pscustomobject][ordered]@{
        state = 'CleanupIncomplete'; verified = $false
        reasonCode = 'VIEWING.CLEANUP_INCOMPLETE'; recoveryRetained = $true
    }
    try {
        if ($Session.state -ne 'Opened' -or -not $Session.recoveryRegistered) { return $incomplete }
        Remove-EvidenceViewingArtifactAndBoundary -JournalPath $Session.journalPath `
            -ArtifactId $Session.artifactId
    }
    catch { $incomplete }
}

function Read-ProtectedPackageFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand
    )

    try {
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes([System.IO.Path]::GetFullPath($LiteralPath))
        if ($bytes.Length -lt 1 -or $bytes.Length -gt 1024) { throw 'Fixture size is invalid.' }
        $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $document = [System.Text.Json.JsonDocument]::Parse($json)
        try {
            $names = @($document.RootElement.EnumerateObject() | ForEach-Object Name)
            if ($names.Count -ne 2 -or @($names | Sort-Object -Unique).Count -ne 2) {
                throw 'Fixture properties are not unique.'
            }
        }
        finally { $document.Dispose() }
        $fixture = & $ConvertFromJsonCommand -InputObject $json -ErrorAction Stop
        if ($fixture.contractVersion -ne '1.0.0' -or
            [string] $fixture.scenario -notin @((Get-ProtectedPackagePolicy).validationScenarios) -or
            (@($fixture.PSObject.Properties.Name | Sort-Object) -join '|') -ne 'contractVersion|scenario') {
            throw 'Fixture is outside the closed scenario set.'
        }
        [string] $fixture.scenario
    }
    catch {
        $exception = [System.ArgumentException]::new('The Protected Package fixture is invalid.')
        $exception.Data['ReasonCode'] = 'PACKAGE.FIXTURE_INVALID'
        throw $exception
    }
}

function New-SyntheticProtectedPackageRecordBytes {
    $runId = "run:synthetic:pkg-$([guid]::NewGuid().ToString('N'))"
    $collector = New-ProcessSupervisorResult -OperationId 'op:synthetic.windows.os' `
        -RunId $runId -StartedAt ([System.DateTimeOffset]::UtcNow) -Outcome Completed `
        -CoverageState Complete -ReasonCode 'PROCESS.COMPLETED' `
        -StandardOutputMaximumBytes 4096 -StandardErrorMaximumBytes 1024 `
        -ObservationValue 'WIN-PCInfo synthétique 日本語 العربية'
    # PowerShell unrolls single-item and empty arrays at function boundaries.
    # Re-box the envelope collections before JSON conversion so the release
    # schema sees arrays even in this one-observation synthetic fixture.
    $collector.Envelope.observationIds = @([string] $collector.Envelope.observationIds)
    $collector.Envelope.diagnosticIds = @()
    $record = New-SyntheticAssessmentRecord -RunId $runId -CollectorResult $collector -Outcome Completed
    ConvertTo-ProtectedPackageJsonBytes -Value $record
}

function New-SyntheticInvalidManifestInnerPackage {
    param([byte[]] $RecordBytes, [byte[]] $ReportBytes)

    $policy = Get-ProtectedPackagePolicy
    $manifest = [pscustomobject][ordered]@{
        kind='win-pcinfo.assessment-package-manifest'; contractVersion='1.0.0'
        productRelease=[string]$policy.release; assessmentContractSet='1.0.0'
        packagePolicy=[string]$policy.policyId
        manifestContract=[string]$policy.innerPackage.manifestContract
        completeness='Complete'
        protection=[pscustomobject][ordered]@{
            state='EncryptedAuthenticated'; authorshipClaim=$false; durableTamperEvidenceClaim=$false
        }
        contents=@(
            [pscustomobject][ordered]@{relativePath='assessment-record.json';mediaType='application/json';byteLength=$RecordBytes.Length;sha256=('0'*64)},
            [pscustomobject][ordered]@{relativePath='assessment-report.html';mediaType='text/html';byteLength=$ReportBytes.Length;sha256=(Get-ProtectedPackageSha256 $ReportBytes)}
        )
    }
    $entries=[ordered]@{
        'assessment-record.json'=$RecordBytes
        'assessment-report.html'=$ReportBytes
        'package-manifest.json'=(ConvertTo-ProtectedPackageJsonBytes $manifest)
    }
    $memory=[System.IO.MemoryStream]::new()
    try {
        $zip=[System.IO.Compression.ZipArchive]::new($memory,[System.IO.Compression.ZipArchiveMode]::Create,$true)
        try {
            foreach($name in @($entries.Keys|Sort-Object)){
                $entry=$zip.CreateEntry($name,[System.IO.Compression.CompressionLevel]::NoCompression)
                $entry.LastWriteTime=[DateTimeOffset]::new(1980,1,1,0,0,0,[TimeSpan]::Zero)
                $entry.ExternalAttributes=0
                $stream=$entry.Open()
                try {[byte[]]$value=$entries[$name];$stream.Write($value,0,$value.Length)}
                finally {$stream.Dispose()}
            }
        }
        finally {$zip.Dispose()}
        $memory.ToArray()
    }
    finally {$memory.Dispose()}
}

function Invoke-ProtectedPackageFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $RuntimeResult,
        [Parameter(Mandatory)] [string] $RequestDigest,
        [Parameter(Mandatory)] [string] $PlanDigest,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand
    )

    try { $scenario=Read-ProtectedPackageFixture $LiteralPath $ConvertFromJsonCommand }
    catch {
        Write-ContractRecord (New-TerminalRecord -ReasonCode 'PACKAGE.FIXTURE_INVALID' `
            -RequestDigest $RequestDigest -ValidationFixture $true -RuntimeResult $RuntimeResult `
            -Phase Packaging -PlanDigest $PlanDigest -PreparationDecision Accepted) `
            -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }
    $boundary=$null;$validationCleanupVerified=$false;$state='IntegrityFailed'
    $reasonCode='PACKAGE.INTEGRITY_FAILED';$packageFinalized=$false;$contentExposed=$false
    $viewingCleanupVerified=$true;$recoveryRegistered=$false;$chunkCount=0
    try {
        $boundary=New-EvidenceWorkspaceValidationBoundary -ValidationRootPath (
            Join-Path (Split-Path -Parent $PSCommandPath) '.protected-package-validation')
        if($scenario -eq 'KnownAnswer'){
            $known=Test-ProtectedPackageKnownAnswer
            if($known.verified){$state='Validated';$reasonCode='PACKAGE.KNOWN_ANSWER_VERIFIED'}
        }
        else {
            [byte[]]$recordBytes=New-SyntheticProtectedPackageRecordBytes
            [byte[]]$reportBytes=if($scenario -eq 'MaximumSize'){
                $value=[byte[]]::new(262144)
                for($byteIndex=0;$byteIndex-lt$value.Length;$byteIndex++){$value[$byteIndex]=0x78}
                $value
            }else{[System.Text.UTF8Encoding]::new($false).GetBytes('<!doctype html><title>Synthetic package report</title>')}
            $artifacts=[ordered]@{'assessment-record.json'=$recordBytes;'assessment-report.html'=$reportBytes}
            if($scenario -in @('InterruptedWrite','DiskExhaustion')){
                $result=New-ProtectedEvidencePackage -DestinationDirectory $boundary.CaseRoot `
                    -Artifacts $artifacts -AssessmentContractSetVersion 1.0.0 `
                    -Completeness Complete -SyntheticWriteFailure $scenario
                $packageFinalized=$result.verified
            }
            elseif($scenario -eq 'MalformedArchive'){
                $path=Join-Path $boundary.CaseRoot 'synthetic.winpcinfo'
                $null = Write-ProtectedPackageEnvelope `
                    -Plaintext ([Text.UTF8Encoding]::new($false).GetBytes('not-a-zip')) `
                    -LiteralPath $path
                $result=Read-ProtectedEvidencePackage $path
            }
            elseif($scenario -eq 'InvalidManifest'){
                [byte[]]$invalid=New-SyntheticInvalidManifestInnerPackage $recordBytes $reportBytes
                $path=Join-Path $boundary.CaseRoot 'synthetic.winpcinfo'
                $null = Write-ProtectedPackageEnvelope -Plaintext $invalid -LiteralPath $path
                $result=Read-ProtectedEvidencePackage $path
                [Security.Cryptography.CryptographicOperations]::ZeroMemory($invalid)
            }
            else {
                $result=New-ProtectedEvidencePackage -DestinationDirectory $boundary.CaseRoot `
                    -Artifacts $artifacts -AssessmentContractSetVersion 1.0.0 `
                    -Completeness Complete
                if($result.verified){
                    $packageFinalized=$true
                    $header=Get-ProtectedPackageEnvelopeHeader $result.packagePath
                    $chunkCount=[int]$header.chunkCount
                }
                if($scenario -eq 'Corruption'){
                    [byte[]]$changed=[IO.File]::ReadAllBytes($result.packagePath)
                    $changed[-1]=$changed[-1]-bxor 1;[IO.File]::WriteAllBytes($result.packagePath,$changed)
                    $result=Read-ProtectedEvidencePackage $result.packagePath;$packageFinalized=$false
                }
                elseif($scenario -in @('WrongUser','WrongDevice')){
                    $result=Read-ProtectedEvidencePackage $result.packagePath `
                        -SyntheticProtectionContext $scenario
                    $packageFinalized=$false
                }
                elseif($scenario -eq 'ViewingCleanup'){
                    $session=Open-EvidenceViewingSession -PackagePath $result.packagePath `
                        -RequestedArtifact assessment-report.html -ViewingBasePath $boundary.CaseRoot
                    $recoveryRegistered=[bool]$session.recoveryRegistered
                    $contentExposed=$session.state -eq 'Opened'
                    $closed=Close-EvidenceViewingSession $session
                    $viewingCleanupVerified=[bool]$closed.verified
                    if($contentExposed -and $viewingCleanupVerified){$state='Validated';$reasonCode='PACKAGE.VIEWING_CLEANUP_VERIFIED'}
                    $contentExposed=$false
                }
                elseif($result.verified){$state='Validated';$reasonCode='PACKAGE.VALIDATED'}
            }
            [Security.Cryptography.CryptographicOperations]::ZeroMemory($recordBytes)
            [Security.Cryptography.CryptographicOperations]::ZeroMemory($reportBytes)
        }
    }
    finally {
        $validationCleanupVerified = if ($null -ne $boundary) {
            Remove-EvidenceWorkspaceValidationBoundary $boundary
        }
        else { $true }
    }
    $record=[pscustomobject][ordered]@{
        recordType='win-pcinfo.protected-package-validation';contractVersion='1.0.0'
        scenario=$scenario;state=$state;reasonCode=$reasonCode;collectionStarted=$false
        packageFinalized=$packageFinalized;contentExposed=$contentExposed
        cryptography=[pscustomobject][ordered]@{algorithm='AES-256-GCM';fullTag=$true;chunkCount=$chunkCount}
        viewing=[pscustomobject][ordered]@{requestedArtifactOnly=$true;cleanupVerified=$viewingCleanupVerified;recoveryRegistered=$recoveryRegistered}
        validationCleanupVerified=[bool]$validationCleanupVerified
        validation=[pscustomobject][ordered]@{mode='SyntheticUnelevated';capabilityClaimCreated=$false}
    }
    Write-ContractRecord $record -ConvertToJsonCommand $ConvertToJsonCommand
    $terminal=New-TerminalRecord -ReasonCode $(if($state-eq'Validated'){'PACKAGE.VALIDATION_COMPLETE'}else{$reasonCode}) `
        -RequestDigest $RequestDigest -ValidationFixture $true -RuntimeResult $RuntimeResult `
        -Phase Packaging -PlanDigest $PlanDigest -PreparationDecision Accepted
    $exitCode=20
    if($state-eq'IntegrityFailed'){$terminal.outcome='IntegrityFailed';$terminal.exitCode=50;$exitCode=50}
    if(-not$validationCleanupVerified){$terminal.outcome='CleanupIncomplete';$terminal.exitCode=60;$terminal.reasonCode='PACKAGE.VALIDATION_CLEANUP_INCOMPLETE';$terminal.cleanup.required=$true;$terminal.cleanup.verified=$false;$exitCode=60}
    Write-ContractRecord $terminal -ConvertToJsonCommand $ConvertToJsonCommand
    $exitCode
}
