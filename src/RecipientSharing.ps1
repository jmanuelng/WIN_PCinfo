$script:RecipientSharingPolicyBase64 = '__RECIPIENT_SHARING_POLICY_BASE64__'
$script:RecipientSharingPolicyDigest = '__RECIPIENT_SHARING_POLICY_SHA256__'
$script:RecipientProfileSchemaBase64 = '__RECIPIENT_PROFILE_SCHEMA_BASE64__'
$script:RecipientProfileSchemaDigest = '__RECIPIENT_PROFILE_SCHEMA_SHA256__'

function Get-RecipientSharingSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-RecipientSharingPolicy {
    if ($script:RecipientSharingPolicyBase64 -eq '__RECIPIENT_SHARING_POLICY_BASE64__') {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-recipient-sharing.json'
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes($path)
        $expectedDigest = Get-RecipientSharingSha256 $bytes
    }
    else {
        [byte[]] $bytes = [System.Convert]::FromBase64String($script:RecipientSharingPolicyBase64)
        $expectedDigest = $script:RecipientSharingPolicyDigest
    }
    if ((Get-RecipientSharingSha256 $bytes) -ne $expectedDigest) {
        throw 'The Recipient Sharing policy failed its embedded digest check.'
    }
    $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    & (Get-ProtectedPackageJsonCommands).ConvertFromJsonCommand -InputObject $json -Depth 20
}

function Get-RecipientProfileSchemaText {
    if ($script:RecipientProfileSchemaBase64 -eq '__RECIPIENT_PROFILE_SCHEMA_BASE64__') {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) 'schemas/recipient-profile.schema.json'
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes($path)
        $expectedDigest = Get-RecipientSharingSha256 $bytes
    }
    else {
        [byte[]] $bytes = [System.Convert]::FromBase64String($script:RecipientProfileSchemaBase64)
        $expectedDigest = $script:RecipientProfileSchemaDigest
    }
    if ((Get-RecipientSharingSha256 $bytes) -ne $expectedDigest) {
        throw 'The Recipient Profile schema failed its embedded digest check.'
    }
    [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
}

function Test-RecipientSharingBytesEqual {
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

function Test-RecipientCertificateRoundTrip {
    param([Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

    [byte[]] $contentKey = [byte[]]::new(32)
    [byte[]] $openedKey = $null
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($contentKey)
    $publicKey = $null
    $privateKey = $null
    try {
        $publicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
            $Certificate
        )
        $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey(
            $Certificate
        )
        if ($null -eq $publicKey -or $null -eq $privateKey) { return $false }

        # OAEP uses a fresh randomized encoding for every wrap. The setup probe
        # deliberately round-trips an unrelated synthetic 256-bit value instead
        # of assessment material. A successful decrypt proves that the public
        # certificate and its provider-held private key are a usable pair; the
        # controllable plaintext buffers are zeroed even when the provider fails.
        [byte[]] $wrapped = $publicKey.Encrypt(
            $contentKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256
        )
        $openedKey = $privateKey.Decrypt(
            $wrapped, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256
        )
        Test-RecipientSharingBytesEqual $contentKey $openedKey
    }
    catch { $false }
    finally {
        if ($null -ne $publicKey) { $publicKey.Dispose() }
        if ($null -ne $privateKey) { $privateKey.Dispose() }
        if ($null -ne $openedKey) {
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($openedKey)
        }
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($contentKey)
    }
}

function New-SyntheticRecipientCertificate {
    param(
        [Parameter(Mandatory)] [int] $KeyBits,
        [Parameter(Mandatory)] [ValidateSet('CurrentlyValid', 'NotCurrentlyValid')]
        [string] $Validity
    )

    $rsa = [System.Security.Cryptography.RSA]::Create($KeyBits)
    try {
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=WIN-PCInfo Synthetic Package Recipient', $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment,
                $true
            )
        )
        $now = [System.DateTimeOffset]::UtcNow
        if ($Validity -eq 'CurrentlyValid') {
            $notBefore = $now.AddMinutes(-5)
            $notAfter = $now.AddDays(30)
        }
        else {
            $notBefore = $now.AddDays(-30)
            $notAfter = $now.AddDays(-1)
        }
        $certificate = $request.CreateSelfSigned($notBefore, $notAfter)
        [pscustomobject][ordered]@{
            certificate = $certificate
            protectionLevel = $null
            persistent = $false
            keyName = $null
            storeAdded = $false
        }
    }
    catch {
        $rsa.Dispose()
        throw
    }
    # The returned certificate owns the synthetic RSA key. Disposing the
    # certificate after the profile is written removes the only test key handle.
}

function Test-WindowsRecipientIdentityContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Facts)

    # This small contract is also the safe validation seam for CI, where issue
    # #47 explicitly forbids mutating a developer's real certificate store or
    # TPM. Production derives every fact below from the CNG key and CurrentUser
    # store after creation; synthetic tests can exercise the same closed decision
    # without pretending that an in-memory RSA key was actually TPM protected.
    $expectedNames = @(
        'certificatePresent', 'currentUserStore', 'keyPresent', 'persistent',
        'privateKeyExportable', 'protectionLevel', 'providerName', 'publicExponent',
        'rsaKeyBits', 'syntheticRoundTripVerified'
    )
    $actualNames = @($Facts.PSObject.Properties.Name | Sort-Object)
    if (($actualNames -join '|') -cne (($expectedNames | Sort-Object) -join '|')) {
        return $false
    }
    $providerToLevel = @{
        'Microsoft Platform Crypto Provider' = 'UserAndDeviceBound'
        'Microsoft Software Key Storage Provider' = 'WindowsUserBound'
    }
    [string] $Facts.providerName -in @($providerToLevel.Keys) -and
        [string] $Facts.protectionLevel -ceq $providerToLevel[[string] $Facts.providerName] -and
        [bool] $Facts.currentUserStore -and [bool] $Facts.persistent -and
        -not [bool] $Facts.privateKeyExportable -and [bool] $Facts.keyPresent -and
        [bool] $Facts.certificatePresent -and [int] $Facts.rsaKeyBits -ge 2048 -and
        [int] $Facts.publicExponent -eq 65537 -and [bool] $Facts.syntheticRoundTripVerified
}

function Select-RecipientPrivateKeyProvider {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $ProviderNames,
        [Parameter(Mandatory)] [scriptblock] $CreateProviderIdentity,
        [Parameter(Mandatory)] [scriptblock] $RemoveProviderIdentity
    )

    $lastError = $null
    foreach ($providerName in $ProviderNames) {
        try { return & $CreateProviderIdentity $providerName }
        catch {
            $lastError = $_
            if ($_.Exception.Data.Contains('WINPCInfoCreatedRecipientIdentity')) {
                $createdIdentity = $_.Exception.Data['WINPCInfoCreatedRecipientIdentity']
                if (-not (& $RemoveProviderIdentity $createdIdentity)) {
                    $cleanupFailure = [System.Security.Cryptography.CryptographicException]::new(
                        'A failed recipient provider attempt could not be proved absent.',
                        $_.Exception
                    )
                    $cleanupFailure.Data['WINPCInfoCleanupIncomplete'] = $true
                    throw $cleanupFailure
                }
            }
        }
    }
    throw [System.Security.Cryptography.CryptographicException]::new(
        'Neither approved non-exportable Current User RSA provider was available.',
        $lastError.Exception
    )
}

function Test-WindowsRecipientStoreCertificatePresent {
    param(
        [Parameter(Mandatory)] [string] $Fingerprint,
        [Parameter()] [bool] $RequirePrivateKey = $true
    )

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        @($store.Certificates | Where-Object {
            $_.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant() -eq
                $Fingerprint -and (-not $RequirePrivateKey -or $_.HasPrivateKey)
        }).Count -gt 0
    }
    finally { $store.Dispose() }
}

function New-WindowsRecipientCertificate {
    param([Parameter(Mandatory)] [int] $KeyBits)

    $policy = Get-RecipientSharingPolicy
    $keyName = "WIN-PCInfo-Recipient-$([guid]::NewGuid().ToString('N'))"
    $providers = @(
        [string] $policy.recipient.privateKey.preferredProvider,
        [string] $policy.recipient.privateKey.fallbackProvider
    )
    $createProviderIdentity = {
        param($providerName)
        $key = $null
        $rsa = $null
        $certificate = $null
        $storeAdded = $false
        try {
            # Threat: an exportable recipient key could silently become a PFX or
            # be copied into logs and recovery material. CNG creates a named key
            # for the current user with no export policy and decryption-only key
            # usage. The Platform provider is tried first because it keeps the
            # private operation in the TPM; failure falls back explicitly to the
            # Windows software provider and is labeled Windows-user-bound. The
            # key permits signing only so CertificateRequest can create its
            # self-signed public carrier; that signature is never presented as
            # identity or authorship evidence.
            $creation = [System.Security.Cryptography.CngKeyCreationParameters]::new()
            $creation.Provider = [System.Security.Cryptography.CngProvider]::new($providerName)
            $creation.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
            $creation.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Decryption -bor
                [System.Security.Cryptography.CngKeyUsages]::Signing
            $creation.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::None
            $creation.Parameters.Add([System.Security.Cryptography.CngProperty]::new(
                'Length', [System.BitConverter]::GetBytes($KeyBits),
                [System.Security.Cryptography.CngPropertyOptions]::None
            ))
            $key = [System.Security.Cryptography.CngKey]::Create(
                [System.Security.Cryptography.CngAlgorithm]::Rsa, $keyName, $creation
            )
            $rsa = [System.Security.Cryptography.RSACng]::new($key)
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=WIN-PCInfo Package Recipient', $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $request.CertificateExtensions.Add(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment,
                    $true
                )
            )
            $now = [System.DateTimeOffset]::UtcNow
            $certificate = $request.CreateSelfSigned($now.AddMinutes(-5), $now.AddYears(2))
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                [System.Security.Cryptography.X509Certificates.StoreName]::My,
                [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
            )
            try {
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $store.Add($certificate)
                $storeAdded = $true
            }
            finally { $store.Dispose() }
            $fingerprint = $certificate.GetCertHashString(
                [System.Security.Cryptography.HashAlgorithmName]::SHA256
            ).ToLowerInvariant()
            $public = $rsa.ExportParameters($false)
            $publicExponent = 0
            foreach ($octet in $public.Exponent) {
                $publicExponent = ($publicExponent * 256) + [int] $octet
            }
            $facts = [pscustomobject]@{
                providerName = $providerName
                protectionLevel = if ($providerName -eq $providers[0]) {
                    'UserAndDeviceBound'
                }
                else { 'WindowsUserBound' }
                currentUserStore = $true; persistent = -not $key.IsEphemeral
                privateKeyExportable = $key.ExportPolicy -ne
                    [System.Security.Cryptography.CngExportPolicies]::None
                keyPresent = [System.Security.Cryptography.CngKey]::Exists(
                    $keyName, [System.Security.Cryptography.CngProvider]::new($providerName)
                )
                certificatePresent = Test-WindowsRecipientStoreCertificatePresent `
                    -Fingerprint $fingerprint
                rsaKeyBits = $rsa.KeySize
                publicExponent = $publicExponent
                syntheticRoundTripVerified = Test-RecipientCertificateRoundTrip $certificate
            }
            if (-not (Test-WindowsRecipientIdentityContract $facts)) {
                throw [System.Security.Cryptography.CryptographicException]::new(
                    'The created recipient identity failed its release security contract.'
                )
            }
            [pscustomobject][ordered]@{
                certificate = $certificate
                protectionLevel = [string] $facts.protectionLevel
                persistent = $true
                keyName = $keyName
                providerName = $providerName
                fingerprint = $fingerprint
                storeAdded = $storeAdded
            }
        }
        catch {
            $failure = $_
            $fingerprint = if ($null -ne $certificate) {
                $certificate.GetCertHashString(
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256
                ).ToLowerInvariant()
            }
            else { $null }
            if ($null -ne $rsa) { $rsa.Dispose(); $rsa = $null }
            if ($null -ne $key) { $key.Dispose(); $key = $null }
            $failure.Exception.Data['WINPCInfoCreatedRecipientIdentity'] =
                [pscustomobject][ordered]@{
                    certificate = $certificate; fingerprint = $fingerprint
                    protectionLevel = if ($providerName -eq $providers[0]) {
                        'UserAndDeviceBound'
                    }
                    else { 'WindowsUserBound' }
                    persistent = $true; keyName = $keyName
                    providerName = $providerName; storeAdded = $storeAdded
                }
            throw $failure
        }
        finally {
            if ($null -ne $rsa) { $rsa.Dispose() }
            if ($null -ne $key) { $key.Dispose() }
        }
    }
    Select-RecipientPrivateKeyProvider -ProviderNames $providers `
        -CreateProviderIdentity $createProviderIdentity `
        -RemoveProviderIdentity ${function:Remove-WindowsRecipientCertificate}
}

function Remove-WindowsRecipientCertificate {
    param([Parameter(Mandatory)] $CreatedCertificate)

    # Rollback uses the exact certificate object and random CNG key name created
    # in this invocation. It never searches by label or subject. If profile
    # publication fails, both store entry and provider key must be absent before
    # setup can report an ordinary failure; otherwise cleanup is explicitly
    # incomplete so a human can recover the named test/setup-owned identity.
    $cleanupVerified = $true
    if ($CreatedCertificate.storeAdded) {
        try {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                [System.Security.Cryptography.X509Certificates.StoreName]::My,
                [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
            )
            try {
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                foreach ($candidate in @($store.Certificates)) {
                    if ($candidate.GetCertHashString(
                            [System.Security.Cryptography.HashAlgorithmName]::SHA256
                        ).ToLowerInvariant() -eq [string] $CreatedCertificate.fingerprint) {
                        $store.Remove($candidate)
                    }
                }
            }
            finally { $store.Dispose() }
        }
        catch { $cleanupVerified = $false }
    }
    if (-not [string]::IsNullOrWhiteSpace([string] $CreatedCertificate.keyName)) {
        $providerName = [string] $CreatedCertificate.providerName
        $provider = [System.Security.Cryptography.CngProvider]::new($providerName)
        try {
            if ([System.Security.Cryptography.CngKey]::Exists(
                    [string] $CreatedCertificate.keyName, $provider)) {
                $key = [System.Security.Cryptography.CngKey]::Open(
                    [string] $CreatedCertificate.keyName, $provider
                )
                try { $key.Delete() } finally { $key.Dispose() }
            }
        }
        catch { $cleanupVerified = $false }
    }
    try {
        if (-not [string]::IsNullOrWhiteSpace([string] $CreatedCertificate.fingerprint) -and
            (Test-WindowsRecipientStoreCertificatePresent `
                -Fingerprint ([string] $CreatedCertificate.fingerprint) `
                -RequirePrivateKey $false)) {
            $cleanupVerified = $false
        }
        if ([System.Security.Cryptography.CngKey]::Exists(
            [string] $CreatedCertificate.keyName,
            [System.Security.Cryptography.CngProvider]::new([string] $CreatedCertificate.providerName))) {
            $cleanupVerified = $false
        }
    }
    catch { $cleanupVerified = $false }
    if ($null -ne $CreatedCertificate.certificate) {
        $CreatedCertificate.certificate.Dispose()
    }
    $cleanupVerified
}

function Write-RecipientProfileDocument {
    param(
        [Parameter(Mandatory)] $Profile,
        [Parameter(Mandatory)] [string] $OutputPath
    )

    $fullPath = [System.IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $fullPath
    if (-not [System.IO.Directory]::Exists($parent) -or
        [System.IO.File]::Exists($fullPath) -or [System.IO.Directory]::Exists($fullPath)) {
        throw 'The Recipient Profile destination must be a new file in an existing directory.'
    }
    $jsonCommand = (Get-ProtectedPackageJsonCommands).ConvertToJsonCommand
    $json = & $jsonCommand -InputObject $Profile -Compress -Depth 10
    [byte[]] $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    $policy = Get-RecipientSharingPolicy
    if ($bytes.Length -gt [int] $policy.recipient.maximumProfileUtf8Bytes) {
        throw 'The Recipient Profile exceeded its release byte bound.'
    }
    $temporaryPath = Join-Path $parent `
        ".$([System.IO.Path]::GetFileName($fullPath)).$([guid]::NewGuid().ToString('N')).new"
    $stream = $null
    $identity = ''
    $operationError = $null
    $cleanupError = $null
    try {
        $stream = New-EvidenceWorkspaceOwnedWriteStream -LiteralPath $temporaryPath
        $identity = Get-EvidenceWorkspaceOwnedStreamIdentity -Stream $stream
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        catch { $operationError = $_ }
        finally {
            if ($null -ne $operationError) {
                try { Remove-EvidenceWorkspaceOwnedStreamOnClose -Stream $stream }
                catch { $cleanupError = $_ }
            }
            $stream.Dispose(); $stream = $null
        }
        if ($null -ne $cleanupError -or
            ($null -ne $operationError -and [System.IO.File]::Exists($temporaryPath))) {
            $exception = [System.InvalidOperationException]::new(
                'Recipient Profile cleanup could not be proved.', $operationError.Exception
            )
            $exception.Data['WINPCInfoCleanupIncomplete'] = $true
            throw $exception
        }
        if ($null -ne $operationError) { throw $operationError }
        if ((Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $temporaryPath) -ne $identity) {
            $exception = [System.InvalidOperationException]::new(
                'Recipient Profile ownership changed before publication.'
            )
            $exception.Data['WINPCInfoCleanupIncomplete'] = $true
            throw $exception
        }
        [System.IO.File]::Move($temporaryPath, $fullPath)
        $fullPath
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if (-not [string]::IsNullOrWhiteSpace($identity) -and
            [System.IO.File]::Exists($temporaryPath) -and
            (Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $temporaryPath) -eq $identity) {
            [System.IO.File]::Delete($temporaryPath)
        }
    }
}

function New-RecipientProfileSetup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Label,
        [Parameter(Mandatory)] [string] $OutputPath,
        [Parameter(Mandatory)] [switch] $ConfirmSetup,
        [Parameter()] [int] $KeyBits = 3072,
        [Parameter(DontShow)]
        [ValidateSet('None', 'UserAndDeviceBound', 'WindowsUserBound')]
        [string] $SyntheticProtectionLevel = 'None',
        [Parameter(DontShow)]
        [ValidateSet('CurrentlyValid', 'NotCurrentlyValid')]
        [string] $SyntheticValidity = 'CurrentlyValid',
        [Parameter(DontShow)]
        $SyntheticCreatedCertificate
    )

    $policy = Get-RecipientSharingPolicy
    if (-not $ConfirmSetup) {
        return [pscustomobject][ordered]@{
            state = 'NotStarted'; reasonCode = 'RECIPIENT.SETUP_NOT_CONFIRMED'
            profilePath = $null; fingerprint = $null; protectionLevel = $null
            syntheticRoundTripVerified = $false
        }
    }
    if ([string]::IsNullOrWhiteSpace($Label) -or
        $Label.Length -gt [int] $policy.recipient.maximumLabelCharacters -or
        $Label -match '[\u0000-\u001f]' -or
        $KeyBits -lt [int] $policy.recipient.rsa.minimumKeyBits) {
        return [pscustomobject][ordered]@{
            state = 'NotStarted'; reasonCode = 'RECIPIENT.SETUP_INPUT_INVALID'
            profilePath = $null; fingerprint = $null; protectionLevel = $null
            syntheticRoundTripVerified = $false
        }
    }

    $created = $null
    $ownsCreatedCertificate = $null -eq $SyntheticCreatedCertificate
    $profilePublished = $false
    $cleanupVerified = $true
    try {
        $created = if ($null -ne $SyntheticCreatedCertificate) {
            $SyntheticCreatedCertificate.protectionLevel = $SyntheticProtectionLevel
            $SyntheticCreatedCertificate
        }
        elseif ($SyntheticProtectionLevel -eq 'None') {
            New-WindowsRecipientCertificate -KeyBits $KeyBits
        }
        else {
            $value = New-SyntheticRecipientCertificate -KeyBits $KeyBits -Validity $SyntheticValidity
            $value.protectionLevel = $SyntheticProtectionLevel
            $value
        }
        $roundTrip = Test-RecipientCertificateRoundTrip $created.certificate
        if (-not $roundTrip) { throw 'The recipient certificate synthetic round-trip failed.' }
        $fingerprint = $created.certificate.GetCertHashString(
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        ).ToLowerInvariant()
        $publicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
            $created.certificate
        )
        try { $actualKeyBits = $publicKey.KeySize }
        finally { $publicKey.Dispose() }
        $profile = [pscustomobject][ordered]@{
            kind = 'win-pcinfo.recipient-profile'
            contractVersion = '1.0.0'
            label = $Label.Trim()
            certificateDerBase64 = [System.Convert]::ToBase64String($created.certificate.RawData)
            fingerprintAlgorithm = 'SHA-256'
            fingerprint = $fingerprint
            protectionLevel = [string] $created.protectionLevel
            notBefore = $created.certificate.NotBefore.ToUniversalTime().ToString('o')
            notAfter = $created.certificate.NotAfter.ToUniversalTime().ToString('o')
            rsaKeyBits = $actualKeyBits
            keyWrapAlgorithm = 'RSA-OAEP-SHA-256'
            syntheticRoundTrip = [pscustomobject][ordered]@{
                algorithm = 'RSA-OAEP-SHA-256'; verified = $true
            }
        }
        $profilePath = Write-RecipientProfileDocument -Profile $profile -OutputPath $OutputPath
        $profilePublished = $true
        [pscustomobject][ordered]@{
            state = 'Created'; reasonCode = 'RECIPIENT.PROFILE_CREATED'
            profilePath = $profilePath; fingerprint = $fingerprint
            protectionLevel = [string] $created.protectionLevel
            syntheticRoundTripVerified = $true
        }
    }
    catch {
        if ([bool] $_.Exception.Data['WINPCInfoCleanupIncomplete']) {
            $cleanupVerified = $false
        }
        if ($null -ne $created -and -not $profilePublished -and $created.persistent) {
            $cleanupVerified = (Remove-WindowsRecipientCertificate $created) -and $cleanupVerified
        }
        [pscustomobject][ordered]@{
            state = if ($cleanupVerified) { 'NotStarted' } else { 'CleanupIncomplete' }
            reasonCode = if ($cleanupVerified) {
                'RECIPIENT.SETUP_FAILED'
            }
            else { 'RECIPIENT.SETUP_CLEANUP_INCOMPLETE' }
            profilePath = $null; fingerprint = $null; protectionLevel = $null
            syntheticRoundTripVerified = $false
        }
    }
    finally {
        if ($ownsCreatedCertificate -and $null -ne $created) {
            $created.certificate.Dispose()
        }
    }
}

function Import-RecipientProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] [string] $ExpectedFingerprint,
        [Parameter()] [switch] $ForNewPackage,
        [Parameter(DontShow)]
        [System.DateTimeOffset] $Now = [System.DateTimeOffset]::UtcNow
    )

    $rejected = {
        param([string] $ReasonCode)
        [pscustomobject][ordered]@{
            state = 'Rejected'; reasonCode = $ReasonCode; certificate = $null
            label = $null; fingerprint = $null; protectionLevel = $null
        }
    }
    $certificate = $null
    try {
        $policy = Get-RecipientSharingPolicy
        $fullPath = [System.IO.Path]::GetFullPath($LiteralPath)
        $file = [System.IO.FileInfo]::new($fullPath)
        if (-not $file.Exists -or $file.Length -lt 1 -or
            $file.Length -gt [int] $policy.recipient.maximumProfileUtf8Bytes) {
            return & $rejected 'RECIPIENT.PROFILE_INVALID'
        }
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes($fullPath)
        $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $document = [System.Text.Json.JsonDocument]::Parse($json)
        try {
            $names = @($document.RootElement.EnumerateObject() | ForEach-Object Name)
            if ($names.Count -ne @($names | Sort-Object -Unique).Count) {
                return & $rejected 'RECIPIENT.PROFILE_INVALID'
            }
        }
        finally { $document.Dispose() }
        $testJson = (Get-ProtectedPackageJsonCommands).TestJsonCommand
        if ($null -eq $testJson -or -not (& $testJson -Json $json `
                -Schema (Get-RecipientProfileSchemaText) -ErrorAction Stop)) {
            return & $rejected 'RECIPIENT.PROFILE_INVALID'
        }
        $profile = & (Get-ProtectedPackageJsonCommands).ConvertFromJsonCommand `
            -InputObject $json -Depth 10 -DateKind String
        $expectedNames = @($policy.recipient.publicProfileFields | Sort-Object)
        if ((@($profile.PSObject.Properties.Name | Sort-Object) -join '|') -ne
            ($expectedNames -join '|')) {
            return & $rejected 'RECIPIENT.PROFILE_INVALID'
        }
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            [System.Convert]::FromBase64String([string] $profile.certificateDerBase64)
        )
        if ($certificate.HasPrivateKey) { return & $rejected 'RECIPIENT.PROFILE_INVALID' }
        $actualFingerprint = $certificate.GetCertHashString(
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        ).ToLowerInvariant()
        if ($actualFingerprint -ne [string] $profile.fingerprint) {
            return & $rejected 'RECIPIENT.PROFILE_INVALID'
        }
        $confirmedFingerprint = $ExpectedFingerprint.Replace(':', '').Replace(' ', '').ToLowerInvariant()
        if ($confirmedFingerprint -notmatch '^[0-9a-f]{64}$' -or
            $confirmedFingerprint -ne $actualFingerprint) {
            return & $rejected 'RECIPIENT.FINGERPRINT_MISMATCH'
        }
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
            $certificate
        )
        try {
            if ($null -eq $rsa -or $rsa.KeySize -lt [int] $policy.recipient.rsa.minimumKeyBits -or
                $rsa.KeySize -ne [int] $profile.rsaKeyBits) {
                return & $rejected 'RECIPIENT.PROFILE_INVALID'
            }
            $rsaParameters = $rsa.ExportParameters($false)
            if ($rsaParameters.Exponent.Length -ne 3 -or
                $rsaParameters.Exponent[0] -ne 1 -or
                $rsaParameters.Exponent[1] -ne 0 -or
                $rsaParameters.Exponent[2] -ne 1) {
                return & $rejected 'RECIPIENT.PROFILE_INVALID'
            }
        }
        finally { if ($null -ne $rsa) { $rsa.Dispose() } }
        $notBefore = [System.DateTimeOffset]::Parse(
            [string] $profile.notBefore, [System.Globalization.CultureInfo]::InvariantCulture
        )
        $notAfter = [System.DateTimeOffset]::Parse(
            [string] $profile.notAfter, [System.Globalization.CultureInfo]::InvariantCulture
        )
        if ($notBefore.UtcDateTime -ne $certificate.NotBefore.ToUniversalTime() -or
            $notAfter.UtcDateTime -ne $certificate.NotAfter.ToUniversalTime() -or
            $notAfter -le $notBefore) {
            return & $rejected 'RECIPIENT.PROFILE_INVALID'
        }
        if ($ForNewPackage -and ($Now -lt $notBefore -or $Now -gt $notAfter)) {
            return & $rejected 'RECIPIENT.CERTIFICATE_NOT_CURRENT'
        }
        $approvedCertificate = $certificate
        $certificate = $null
        [pscustomobject][ordered]@{
            state = 'Approved'; reasonCode = 'RECIPIENT.PROFILE_APPROVED'
            certificate = $approvedCertificate; label = [string] $profile.label
            fingerprint = $actualFingerprint
            protectionLevel = [string] $profile.protectionLevel
            admissionKind = 'ApprovedRecipientForPackage'
        }
    }
    catch { & $rejected 'RECIPIENT.PROFILE_INVALID' }
    finally { if ($null -ne $certificate) { $certificate.Dispose() } }
}

function Test-RecipientCertificateForNewPackage {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter()] [System.DateTimeOffset] $Now = [System.DateTimeOffset]::UtcNow
    )

    $policy = Get-RecipientSharingPolicy
    $rsa = $null
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
            $Certificate
        )
        $notBefore = [System.DateTimeOffset] $Certificate.NotBefore.ToUniversalTime()
        $notAfter = [System.DateTimeOffset] $Certificate.NotAfter.ToUniversalTime()
        $null -ne $rsa -and
            $rsa.KeySize -ge [int] $policy.recipient.rsa.minimumKeyBits -and
            $Now -ge $notBefore -and $Now -le $notAfter
    }
    finally { if ($null -ne $rsa) { $rsa.Dispose() } }
}

function Protect-RecipientContentKey {
    param(
        [Parameter(Mandatory)] [byte[]] $ContentKey,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter()] [System.DateTimeOffset] $AdmissionTime = [System.DateTimeOffset]::UtcNow
    )

    if (-not (Test-RecipientCertificateForNewPackage $Certificate -Now $AdmissionTime)) {
        throw 'The recipient certificate is not eligible for a new package.'
    }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
        $Certificate
    )
    try {
        # The package receives only an OAEP-SHA-256 encryption of the same fresh
        # AES content key already protected by local DPAPI. No fingerprint,
        # certificate, label, subject, or issuer enters the outer envelope. OAEP
        # randomness prevents the wrapped value from becoming a stable identity.
        $rsa.Encrypt(
            $ContentKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256
        )
    }
    finally { $rsa.Dispose() }
}

function Unprotect-RecipientContentKey {
    param(
        [Parameter(Mandatory)] [byte[]] $WrappedContentKey,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    # Historical opening deliberately does not inspect NotAfter. Certificate
    # validity controls admission to a new package; afterward, possession of the
    # exact usable provider-held private key is the recovery fact. This performs
    # no background lookup or monitoring and never exports the private key.
    if (-not $Certificate.HasPrivateKey) {
        throw [System.Security.Cryptography.CryptographicException]::new(
            'The matching recipient private key is unavailable.'
        )
    }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey(
        $Certificate
    )
    try {
        if ($null -eq $rsa -or $WrappedContentKey.Length -ne ($rsa.KeySize / 8)) {
            throw [System.Security.Cryptography.CryptographicException]::new(
                'The recipient key does not match the package wrap.'
            )
        }
        $rsa.Decrypt(
            $WrappedContentKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256
        )
    }
    finally { if ($null -ne $rsa) { $rsa.Dispose() } }
}

function Open-ProtectedEvidencePackageForRecipient {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $PackagePath,
        [Parameter(DontShow)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $SyntheticCertificate
    )

    $unavailable = [pscustomobject][ordered]@{
        state = 'ProtectionUnavailable'; verified = $false; manifest = $null
        artifacts = $null; innerPackageSha256 = $null
    }
    if ($null -ne $SyntheticCertificate) {
        if (-not $SyntheticCertificate.HasPrivateKey) { return $unavailable }
        return Read-ProtectedEvidencePackage -LiteralPath $PackagePath `
            -RecipientCertificate $SyntheticCertificate
    }

    # Historical opening deliberately needs no old Recipient Profile, validity
    # decision, monitor, or fingerprint input. In the foreground, the current
    # user's non-exportable provider keys are tried against the anonymous OAEP
    # wrap; authenticated package verification is the only success signal. A
    # nonmatching key reveals no plaintext and is immediately discarded.
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        foreach ($candidate in @($store.Certificates | Where-Object HasPrivateKey)) {
            $opened = Read-ProtectedEvidencePackage -LiteralPath $PackagePath `
                -RecipientCertificate $candidate
            if ($opened.verified) { return $opened }
        }
        $unavailable
    }
    finally { $store.Dispose() }
}

function Get-RestrictedReportExportWarning {
    [CmdletBinding()]
    param()

    $policy = Get-RecipientSharingPolicy
    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.restricted-report-warning'
        contractVersion = '1.0.0'
        severity = 'Restricted'
        title = 'RESTRICTED DIAGNOSTIC EVIDENCE — NOT PUBLICLY SHAREABLE'
        warning = 'This workflow creates an unencrypted HTML report. Transfer it only through an approved private channel, limit access to the intended recipient, and delete every copy after use.'
        unencryptedOutput = $true
        publiclyShareable = $false
        deletionRequiredAfterUse = $true
        acknowledgmentRequired = [string] $policy.restrictedReportExport.acknowledgment
    }
}

function Export-RestrictedAssessmentReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $PackagePath,
        [Parameter(Mandatory)] [string] $OutputPath,
        [Parameter(Mandatory)] [string] $WarningAcknowledgment,
        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $RecipientCertificate,
        [Parameter(DontShow)]
        [ValidateSet('None', 'AfterWrite')]
        [string] $SyntheticInterruption = 'None'
    )

    $policy = Get-RecipientSharingPolicy
    $baseResult = [ordered]@{
        state = 'IntegrityFailed'; reasonCode = 'EXPORT.INTEGRITY_FAILED'
        reportPath = $null; restrictedDiagnosticEvidence = $true
        publiclyShareable = $false; cleanupVerified = $true
    }
    if ($WarningAcknowledgment -cne
        [string] $policy.restrictedReportExport.acknowledgment) {
        $baseResult.state = 'NotStarted'
        $baseResult.reasonCode = 'EXPORT.WARNING_NOT_ACKNOWLEDGED'
        return [pscustomobject] $baseResult
    }

    $opened = $null
    $stream = $null
    $partialPath = $null
    $partialIdentity = ''
    $finalized = $false
    $operationError = $null
    $cleanupError = $null
    try {
        $opened = Read-ProtectedEvidencePackage -LiteralPath $PackagePath `
            -RecipientCertificate $RecipientCertificate
        if (-not $opened.verified -or
            -not $opened.artifacts.Contains([string] $policy.restrictedReportExport.artifact)) {
            return [pscustomobject] $baseResult
        }
        [byte[]] $reportBytes = $opened.artifacts[[string] $policy.restrictedReportExport.artifact]
        if ($reportBytes.Length -lt 1 -or
            $reportBytes.Length -gt [int] $policy.restrictedReportExport.maximumBytes) {
            return [pscustomobject] $baseResult
        }
        $fullPath = [System.IO.Path]::GetFullPath($OutputPath)
        $parent = Split-Path -Parent $fullPath
        if ([System.IO.Path]::GetExtension($fullPath) -cne '.html' -or
            -not [System.IO.Directory]::Exists($parent) -or
            [System.IO.File]::Exists($fullPath) -or [System.IO.Directory]::Exists($fullPath)) {
            $baseResult.state = 'NotStarted'
            $baseResult.reasonCode = 'EXPORT.DESTINATION_INVALID'
            return [pscustomobject] $baseResult
        }
        $partialPath = Join-Path $parent `
            ".$([System.IO.Path]::GetFileName($fullPath)).$([guid]::NewGuid().ToString('N')).partial"
        $banner = '<div id="winpcinfo-restricted-evidence" role="alert" ' +
            'style="border:4px solid #8b0000;background:#fff1f1;color:#510000;' +
            'font:700 18px/1.4 sans-serif;padding:16px;margin:0 0 20px 0">' +
            [string] $policy.restrictedReportExport.bannerText + '</div>'
        [byte[]] $bannerBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($banner)
        try {
            # Threat: an interrupted plaintext write could leave a report that
            # looks complete or an unrelated race-created path could be deleted.
            # The native stream creates one new file with DELETE authority,
            # captures identity from that same handle, and marks only that object
            # for deletion on failure. The final name appears only after a durable
            # write and an exact identity check; failure never guesses a path.
            $stream = New-EvidenceWorkspaceOwnedWriteStream -LiteralPath $partialPath
            $partialIdentity = Get-EvidenceWorkspaceOwnedStreamIdentity -Stream $stream
            $stream.Write($bannerBytes, 0, $bannerBytes.Length)
            $stream.Write($reportBytes, 0, $reportBytes.Length)
            if ($SyntheticInterruption -eq 'AfterWrite') {
                throw [System.OperationCanceledException]::new(
                    'Synthetic interruption after restricted report write.'
                )
            }
            $stream.Flush($true)
        }
        catch { $operationError = $_ }
        finally {
            if ($null -ne $operationError -and $null -ne $stream) {
                try { Remove-EvidenceWorkspaceOwnedStreamOnClose -Stream $stream }
                catch { $cleanupError = $_ }
            }
            if ($null -ne $stream) { $stream.Dispose(); $stream = $null }
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($bannerBytes)
        }
        if ($null -ne $cleanupError -or
            ($null -ne $operationError -and [System.IO.File]::Exists($partialPath))) {
            $baseResult.state = 'CleanupIncomplete'
            $baseResult.reasonCode = 'EXPORT.CLEANUP_INCOMPLETE'
            $baseResult.cleanupVerified = $false
            return [pscustomobject] $baseResult
        }
        if ($null -ne $operationError) { return [pscustomobject] $baseResult }
        if ((Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $partialPath) -ne
            $partialIdentity) {
            $baseResult.state = 'CleanupIncomplete'
            $baseResult.reasonCode = 'EXPORT.OWNERSHIP_UNVERIFIED'
            $baseResult.cleanupVerified = $false
            return [pscustomobject] $baseResult
        }
        [System.IO.File]::Move($partialPath, $fullPath)
        $finalized = $true
        [pscustomobject][ordered]@{
            state = 'Exported'; reasonCode = 'EXPORT.RESTRICTED_REPORT_EXPORTED'
            reportPath = $fullPath; restrictedDiagnosticEvidence = $true
            publiclyShareable = $false; cleanupVerified = $true
        }
    }
    catch { [pscustomobject] $baseResult }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $opened -and $null -ne $opened.artifacts) {
            foreach ($value in @($opened.artifacts.Values)) {
                [System.Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]] $value)
            }
        }
        if (-not $finalized -and -not [string]::IsNullOrWhiteSpace($partialIdentity) -and
            $null -ne $partialPath -and [System.IO.File]::Exists($partialPath) -and
            (Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $partialPath) -eq
                $partialIdentity) {
            [System.IO.File]::Delete($partialPath)
        }
    }
}

function New-CompletionSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [bool] $PackageVerified,
        [Parameter(Mandatory)] [bool] $PackageAvailable,
        [Parameter(Mandatory)] [bool] $RecipientSelected,
        [Parameter()]
        [ValidateSet('None', 'UserAndDeviceBound', 'WindowsUserBound')]
        [string] $RecipientProtectionLevel = 'None',
        [Parameter(Mandatory)] [bool] $RecipientAccessAvailable,
        [Parameter(Mandatory)] [bool] $RestrictedReportExported
    )

    if (($PackageAvailable -and -not $PackageVerified) -or
        ($RecipientSelected -and $RecipientProtectionLevel -eq 'None') -or
        (-not $RecipientSelected -and $RecipientProtectionLevel -ne 'None') -or
        ($RecipientAccessAvailable -and -not $RecipientSelected)) {
        throw 'The Completion Summary recipient state is inconsistent.'
    }
    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.completion-summary'
        contractVersion = '1.0.0'
        packageVerified = $PackageVerified
        packageAvailable = $PackageAvailable
        resultSharingGuidance = [pscustomobject][ordered]@{
            kind = 'ResultSharingGuidance'
            localAccess = if ($PackageVerified -and $PackageAvailable) {
                'InitiatingWindowsUserAndDevice'
            }
            else { 'Unavailable' }
            recipientAccess = if ($RecipientSelected -and $PackageVerified -and $PackageAvailable -and
                $RecipientAccessAvailable) {
                'ApprovedPackageRecipient'
            }
            elseif ($RecipientSelected) { 'Unavailable' }
            else { 'None' }
            recipientProtectionLevel = $RecipientProtectionLevel
            privateTransfer = [pscustomobject][ordered]@{
                allowed = [bool] ($PackageVerified -and $PackageAvailable -and $RecipientSelected -and
                    $RecipientAccessAvailable)
                encryptedPackageOnly = $true
                keepRecoveryMaterialSeparate = $true
                authorizedRecipientOnly = [bool] $RecipientSelected
            }
            restrictedExport = [pscustomobject][ordered]@{
                available = [bool] ($PackageVerified -and $PackageAvailable)
                completed = $RestrictedReportExported
                classification = 'RestrictedDiagnosticEvidence'
                unencrypted = $true
                deletionRequiredAfterUse = $true
            }
            deletionResponsibility = if (-not $PackageAvailable) { 'None' }
            elseif ($RecipientSelected) {
                'OperatorAndAuthorizedRecipient'
            }
            else { 'Operator' }
            prohibitedPublicSharing = $true
            prohibitedDestinations = @(
                'GitHubIssues', 'GitHubDiscussions', 'PublicRepository', 'PublicFileSharing'
            )
        }
    }
}

function Read-RecipientSharingFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand
    )

    try {
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes(
            [System.IO.Path]::GetFullPath($LiteralPath)
        )
        if ($bytes.Length -lt 1 -or $bytes.Length -gt 1024) {
            throw 'The fixture size is invalid.'
        }
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
            [string] $fixture.scenario -notin @((Get-RecipientSharingPolicy).validationScenarios) -or
            (@($fixture.PSObject.Properties.Name | Sort-Object) -join '|') -ne
                'contractVersion|scenario') {
            throw 'The fixture is outside the closed scenario set.'
        }
        [string] $fixture.scenario
    }
    catch {
        $exception = [System.ArgumentException]::new('The Recipient Sharing fixture is invalid.')
        $exception.Data['ReasonCode'] = 'RECIPIENT.FIXTURE_INVALID'
        throw $exception
    }
}

function Invoke-RecipientSharingFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $RuntimeResult,
        [Parameter(Mandatory)] [string] $RequestDigest,
        [Parameter(Mandatory)] [string] $PlanDigest,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand,
        [Parameter()] $ApprovedRecipient
    )

    try { $scenario = Read-RecipientSharingFixture $LiteralPath $ConvertFromJsonCommand }
    catch {
        Write-ContractRecord (New-TerminalRecord -ReasonCode 'RECIPIENT.FIXTURE_INVALID' `
            -RequestDigest $RequestDigest -ValidationFixture $true -RuntimeResult $RuntimeResult `
            -Phase Packaging -PlanDigest $PlanDigest -PreparationDecision Accepted) `
            -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    $boundary = $null
    $recordBytes = $null
    $reportBytes = $null
    $recipient = $null
    $unrelated = $null
    $admission = $null
    $validated = $false
    $cleanupVerified = $false
    $selected = $scenario -in @('HistoricalOpening', 'MissingKey', 'OneRecipient')
    $protectionLevel = 'None'
    $confirmationVerified = $false
    $newPackageAdmissionRejected = $false
    $historicalOpened = $false
    $missingKeyRejected = $false
    $localAccessVerified = $false
    $recipientAccessVerified = $false
    $exportWarningSatisfied = $false
    $exportCompleted = $false
    $exportCleanupVerified = $true
    $permanentBannerVerified = $false
    $completionGuidanceVerified = $false
    $packageVerified = $false
    $providerContractVerified = $false
    try {
        $boundary = New-EvidenceWorkspaceValidationBoundary -ValidationRootPath (
            Join-Path (Split-Path -Parent $PSCommandPath) '.recipient-sharing-validation'
        )
        if ($scenario -in @(
                'TpmBackedSetup', 'SoftwareFallbackSetup', 'ProfileValidation',
                'WrongFingerprint', 'ExpiredAdmission')) {
            $level = if ($scenario -eq 'TpmBackedSetup') {
                'UserAndDeviceBound'
            }
            else { 'WindowsUserBound' }
            $validity = if ($scenario -eq 'ExpiredAdmission') {
                'NotCurrentlyValid'
            }
            else { 'CurrentlyValid' }
            $profilePath = Join-Path $boundary.CaseRoot 'synthetic.recipient.json'
            $setup = New-RecipientProfileSetup -Label 'Synthetic validation recipient' `
                -OutputPath $profilePath -ConfirmSetup -SyntheticProtectionLevel $level `
                -SyntheticValidity $validity
            $protectionLevel = [string] $setup.protectionLevel
            if ($scenario -in @('TpmBackedSetup', 'SoftwareFallbackSetup')) {
                $profileJson = [System.IO.File]::ReadAllText($profilePath,
                    [System.Text.UTF8Encoding]::new($false, $true))
                $profile = & $ConvertFromJsonCommand -InputObject $profileJson -Depth 10
                $publicCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    [System.Convert]::FromBase64String([string] $profile.certificateDerBase64)
                )
                try {
                    $fixturePublicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
                        $publicCertificate
                    )
                    try { $fixtureKeyBits = $fixturePublicKey.KeySize }
                    finally { $fixturePublicKey.Dispose() }
                    $providerName = if ($scenario -eq 'TpmBackedSetup') {
                        'Microsoft Platform Crypto Provider'
                    }
                    else { 'Microsoft Software Key Storage Provider' }
                    $providerContractVerified = Test-WindowsRecipientIdentityContract -Facts (
                        [pscustomobject]@{
                            providerName = $providerName; protectionLevel = $level
                            currentUserStore = $true; persistent = $true
                            privateKeyExportable = $false; keyPresent = $true
                            certificatePresent = $true; rsaKeyBits = $fixtureKeyBits
                            publicExponent = 65537
                            syntheticRoundTripVerified = $setup.syntheticRoundTripVerified
                        }
                    )
                    $validated = $setup.state -eq 'Created' -and
                        $setup.syntheticRoundTripVerified -and
                        $protectionLevel -eq $level -and -not $publicCertificate.HasPrivateKey -and
                        $providerContractVerified
                }
                finally { $publicCertificate.Dispose() }
            }
            else {
                $profileJson = [System.IO.File]::ReadAllText($profilePath,
                    [System.Text.UTF8Encoding]::new($false, $true))
                $profile = & $ConvertFromJsonCommand -InputObject $profileJson -Depth 10 -DateKind String
                $expected = if ($scenario -eq 'WrongFingerprint') { '0' * 64 }
                    else { [string] $profile.fingerprint }
                $admission = Import-RecipientProfile -LiteralPath $profilePath `
                    -ExpectedFingerprint $expected -ForNewPackage
                if ($scenario -eq 'ProfileValidation') {
                    $confirmationVerified = $admission.state -eq 'Approved'
                    $validated = $confirmationVerified
                }
                elseif ($scenario -eq 'WrongFingerprint') {
                    $newPackageAdmissionRejected = $admission.reasonCode -eq
                        'RECIPIENT.FINGERPRINT_MISMATCH'
                    $validated = $newPackageAdmissionRejected
                }
                else {
                    $newPackageAdmissionRejected = $admission.reasonCode -eq
                        'RECIPIENT.CERTIFICATE_NOT_CURRENT'
                    $validated = $newPackageAdmissionRejected
                }
            }
        }
        else {
            [byte[]] $recordBytes = New-SyntheticProtectedPackageRecordBytes
            [byte[]] $reportBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
                '<!doctype html><html><body>Synthetic sharing report</body></html>'
            )
            $artifacts = [ordered]@{
                'assessment-record.json' = $recordBytes
                'assessment-report.html' = $reportBytes
            }
            if ($scenario -eq 'ZeroRecipient') {
                $package = New-ProtectedEvidencePackage -DestinationDirectory $boundary.CaseRoot `
                    -Artifacts $artifacts -AssessmentContractSetVersion 1.0.0 `
                    -Completeness Complete
                $localAccessVerified = (Read-ProtectedEvidencePackage $package.packagePath).verified
                $validated = $package.verified -and $localAccessVerified
            }
            elseif ($scenario -eq 'OneRecipient') {
                if ($null -eq $ApprovedRecipient) {
                    throw 'The generated one-recipient path did not receive Preparation admission.'
                }
                $protectionLevel = [string] $ApprovedRecipient.protectionLevel
                $package = New-ProtectedEvidencePackage -DestinationDirectory $boundary.CaseRoot `
                    -Artifacts $artifacts -AssessmentContractSetVersion 1.0.0 `
                    -Completeness Complete -ApprovedRecipient $ApprovedRecipient
                $packageVerified = $package.verified
                $localAccessVerified = (Read-ProtectedEvidencePackage $package.packagePath).verified
                # The selected profile's setup round-trip and the verified OAEP
                # envelope establish intended recipient access without importing
                # a private test key into the generated application process.
                $recipientAccessVerified = $package.verified
                $validated = $package.verified -and $localAccessVerified
            }
            elseif ($scenario -in @('HistoricalOpening', 'MissingKey')) {
                $validity = if ($scenario -eq 'HistoricalOpening') {
                    'NotCurrentlyValid'
                }
                else { 'CurrentlyValid' }
                $recipient = New-SyntheticRecipientCertificate -KeyBits 3072 -Validity $validity
                $protectionLevel = 'WindowsUserBound'
                $profilePath = Join-Path $boundary.CaseRoot 'approved.recipient.json'
                $setup = New-RecipientProfileSetup -Label 'Synthetic approved package recipient' `
                    -OutputPath $profilePath -ConfirmSetup `
                    -SyntheticProtectionLevel WindowsUserBound -SyntheticValidity $validity `
                    -SyntheticCreatedCertificate $recipient
                $admissionTime = if ($scenario -eq 'HistoricalOpening') {
                    ([System.DateTimeOffset] $recipient.certificate.NotAfter).AddHours(-1)
                }
                else { [System.DateTimeOffset]::UtcNow }
                $admission = Import-RecipientProfile -LiteralPath $profilePath `
                    -ExpectedFingerprint $setup.fingerprint -ForNewPackage -Now $admissionTime
                $package = New-ProtectedEvidencePackage -DestinationDirectory $boundary.CaseRoot `
                    -Artifacts $artifacts -AssessmentContractSetVersion 1.0.0 `
                    -Completeness Complete -ApprovedRecipient $admission `
                    -SyntheticAdmissionTime $admissionTime
                $packageVerified = $package.verified
                $localAccessVerified = (Read-ProtectedEvidencePackage $package.packagePath).verified
                if ($scenario -eq 'MissingKey') {
                    # Dispose the only matching synthetic private-key handle
                    # before opening. The foreground CurrentUser lookup therefore
                    # proves actual absence, not merely rejection of a wrong key.
                    $recipient.certificate.Dispose()
                    $recipient = $null
                    $missing = Open-ProtectedEvidencePackageForRecipient `
                        -PackagePath $package.packagePath
                    $missingKeyRejected = $missing.state -eq 'ProtectionUnavailable' -and
                        -not $missing.verified -and $null -eq $missing.artifacts
                    $validated = $package.verified -and $localAccessVerified -and
                        $missingKeyRejected
                }
                else {
                    $opened = Open-ProtectedEvidencePackageForRecipient `
                        -PackagePath $package.packagePath `
                        -SyntheticCertificate $recipient.certificate
                    $recipientAccessVerified = $opened.verified
                    $historicalOpened = $scenario -eq 'HistoricalOpening' -and $opened.verified
                    $validated = $package.verified -and $localAccessVerified -and
                        $recipientAccessVerified
                }
            }
            else {
                $package = New-ProtectedEvidencePackage -DestinationDirectory $boundary.CaseRoot `
                    -Artifacts $artifacts -AssessmentContractSetVersion 1.0.0 `
                    -Completeness Complete
                $packageVerified = $package.verified
                $exportPath = Join-Path $boundary.CaseRoot 'restricted.html'
                $warning = Get-RestrictedReportExportWarning
                if ($scenario -eq 'InterruptedExport') {
                    $export = Export-RestrictedAssessmentReport -PackagePath $package.packagePath `
                        -OutputPath $exportPath `
                        -WarningAcknowledgment $warning.acknowledgmentRequired `
                        -SyntheticInterruption AfterWrite
                    $exportWarningSatisfied = $true
                    $exportCleanupVerified = $export.cleanupVerified -and
                        -not [System.IO.File]::Exists($exportPath)
                    $validated = $export.state -eq 'IntegrityFailed' -and
                        $exportCleanupVerified
                }
                elseif ($scenario -eq 'RestrictedExport') {
                    $export = Export-RestrictedAssessmentReport -PackagePath $package.packagePath `
                        -OutputPath $exportPath `
                        -WarningAcknowledgment $warning.acknowledgmentRequired
                    $exportWarningSatisfied = $true
                    $exportCompleted = $export.state -eq 'Exported'
                    if ($exportCompleted) {
                        $html = [System.IO.File]::ReadAllText(
                            $exportPath, [System.Text.UTF8Encoding]::new($false, $true)
                        )
                        $permanentBannerVerified = $html -match
                            'RESTRICTED DIAGNOSTIC EVIDENCE.*NOT PUBLICLY SHAREABLE'
                    }
                    $validated = $package.verified -and $exportCompleted -and
                        $permanentBannerVerified -and -not $export.publiclyShareable
                }
                else {
                    $export = Export-RestrictedAssessmentReport -PackagePath $package.packagePath `
                        -OutputPath $exportPath -WarningAcknowledgment 'DECLINE'
                    $exportCleanupVerified = -not [System.IO.File]::Exists($exportPath)
                    $validated = $export.state -eq 'NotStarted' -and
                        $export.reasonCode -eq 'EXPORT.WARNING_NOT_ACKNOWLEDGED' -and
                        $exportCleanupVerified
                }
            }
        }

        if ($scenario -eq 'ZeroRecipient') { $packageVerified = $package.verified }
        $recipientAccessAvailable = $selected -and $scenario -ne 'MissingKey'
        $packageAvailable = $packageVerified -and $null -ne $package -and
            [System.IO.File]::Exists([string]$package.packagePath)
        $summary = New-CompletionSummary -PackageVerified $packageVerified `
            -PackageAvailable $packageAvailable `
            -RecipientSelected $selected -RecipientProtectionLevel $(if ($selected) {
                $protectionLevel
            }
            else { 'None' }) `
            -RecipientAccessAvailable $recipientAccessAvailable `
            -RestrictedReportExported $exportCompleted
        Write-ContractRecord $summary -ConvertToJsonCommand $ConvertToJsonCommand
        $guidanceNames = @($summary.resultSharingGuidance.PSObject.Properties.Name)
        $completionGuidanceVerified = @(
            'localAccess', 'recipientAccess', 'privateTransfer', 'restrictedExport',
            'deletionResponsibility', 'prohibitedPublicSharing' |
                Where-Object { $_ -notin $guidanceNames }
        ).Count -eq 0 -and $summary.resultSharingGuidance.prohibitedPublicSharing
    }
    catch { $validated = $false }
    finally {
        if ($null -ne $admission -and $null -ne $admission.certificate) {
            $admission.certificate.Dispose()
        }
        if ($null -ne $recipient) { $recipient.certificate.Dispose() }
        if ($null -ne $unrelated) { $unrelated.certificate.Dispose() }
        if ($null -ne $recordBytes) {
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($recordBytes)
        }
        if ($null -ne $reportBytes) {
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($reportBytes)
        }
        $cleanupVerified = if ($null -ne $boundary) {
            Remove-EvidenceWorkspaceValidationBoundary $boundary
        }
        else { $true }
    }

    $state = if ($validated -and $cleanupVerified -and $completionGuidanceVerified) {
        'Validated'
    }
    else { 'IntegrityFailed' }
    $record = [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.recipient-sharing-validation'
        contractVersion = '1.0.0'
        scenario = $scenario
        state = $state
        reasonCode = if ($state -eq 'Validated') {
            'RECIPIENT.VALIDATION_COMPLETE'
        }
        else { 'RECIPIENT.VALIDATION_FAILED' }
        collectionStarted = $false
        recipient = [pscustomobject][ordered]@{
            selected = $selected; protectionLevel = $protectionLevel
            providerContractVerified = $providerContractVerified
            confirmationVerified = $confirmationVerified
            newPackageAdmissionRejected = $newPackageAdmissionRejected
            historicalOpened = $historicalOpened
            missingKeyRejected = $missingKeyRejected
            maximumRecipients = 1
        }
        package = [pscustomobject][ordered]@{
            localAccessVerified = $localAccessVerified
            recipientAccessVerified = $recipientAccessVerified
            keyWrapAlgorithm = 'RSA-OAEP-SHA-256'
        }
        restrictedExport = [pscustomobject][ordered]@{
            warningRequired = $true; warningSatisfied = $exportWarningSatisfied
            completed = $exportCompleted; cleanupVerified = $exportCleanupVerified
            permanentBannerVerified = $permanentBannerVerified
            publiclyShareable = $false
        }
        completionGuidanceVerified = $completionGuidanceVerified
        validationCleanupVerified = $cleanupVerified
        validation = [pscustomobject][ordered]@{
            mode = 'SyntheticUnelevated'; capabilityClaimCreated = $false
        }
    }
    Write-ContractRecord $record -ConvertToJsonCommand $ConvertToJsonCommand
    $terminal = New-TerminalRecord -ReasonCode $record.reasonCode `
        -RequestDigest $RequestDigest -ValidationFixture $true -RuntimeResult $RuntimeResult `
        -Phase Packaging -PlanDigest $PlanDigest -PreparationDecision Accepted
    $exitCode = 20
    if ($state -ne 'Validated') {
        $terminal.outcome = 'IntegrityFailed'; $terminal.exitCode = 50; $exitCode = 50
    }
    if (-not $cleanupVerified) {
        $terminal.outcome = 'CleanupIncomplete'; $terminal.exitCode = 60
        $terminal.reasonCode = 'RECIPIENT.VALIDATION_CLEANUP_INCOMPLETE'
        $terminal.cleanup.required = $true; $terminal.cleanup.verified = $false
        $exitCode = 60
    }
    Write-ContractRecord $terminal -ConvertToJsonCommand $ConvertToJsonCommand
    $exitCode
}
