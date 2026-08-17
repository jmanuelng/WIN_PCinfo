# Build.ps1 replaces both sentinels with the release-bound governing-resource
# table and its SHA-256 digest. The running application treats that table as
# the trust root for explicit package files.
$script:PortableGoverningResourcesBase64 = '__PORTABLE_GOVERNING_RESOURCES_BASE64__'
$script:PortableGoverningResourcesDigest = '__PORTABLE_GOVERNING_RESOURCES_SHA256__'

function Get-PortableDistributionFileDigest {
    param([Parameter(Mandatory)] $Bytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        [System.Convert]::ToHexString($sha256.ComputeHash([byte[]] $Bytes)).ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-PortableGoverningResourceTable {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    # Adjacency to WIN-PCInfo.ps1 is not authentication. The threat is a
    # substituted schema, catalog, helper, or document that keeps the same
    # file name. The mechanism is an embedded path-and-digest table bound into
    # the generated application. The trust assumption is that those bytes were
    # produced by the deterministic build. Safe failure is NotStarted with
    # PREPARATION.INTEGRITY_FAILED and no verification override.
    if ($script:PortableGoverningResourcesBase64 -eq
        ('__PORTABLE_GOVERNING_RESOURCES_' + 'BASE64__')) {
        return [pscustomobject]@{ Valid = $false; Table = $null }
    }

    try {
        $bytes = [System.Convert]::FromBase64String($script:PortableGoverningResourcesBase64)
    }
    catch {
        return [pscustomobject]@{ Valid = $false; Table = $null }
    }
    if ((Get-PortableDistributionFileDigest -Bytes $bytes) -ne
        $script:PortableGoverningResourcesDigest) {
        return [pscustomobject]@{ Valid = $false; Table = $null }
    }

    try {
        $table = & $ConvertFromJsonCommand -InputObject (
            [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        ) -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{ Valid = $false; Table = $null }
    }

    [pscustomobject]@{ Valid = $true; Table = $table }
}

function Test-PortableDistributionIntegrity {
    param(
        [Parameter(Mandatory)] [string] $PackageRoot,
        [Parameter(Mandatory)] [ValidateSet('Optional', 'Required')] [string] $ManifestPresence,
        [Parameter(Mandatory)] $ConvertFromJsonCommand
    )

    $manifestPath = Join-Path $PackageRoot 'package-manifest.json'
    $manifestPresent = Test-Path -LiteralPath $manifestPath -PathType Leaf
    if (-not $manifestPresent) {
        if ($ManifestPresence -eq 'Required') {
            return [pscustomobject]@{
                Valid = $false
                PackageContext = $false
                ReasonCode = 'PREPARATION.INTEGRITY_FAILED'
            }
        }
        return [pscustomobject]@{
            Valid = $true
            PackageContext = $false
            ReasonCode = 'PACKAGE.NOT_PRESENT'
        }
    }

    $tableResult = Get-PortableGoverningResourceTable -ConvertFromJsonCommand $ConvertFromJsonCommand
    if (-not $tableResult.Valid) {
        return [pscustomobject]@{
            Valid = $false
            PackageContext = $true
            ReasonCode = 'PREPARATION.INTEGRITY_FAILED'
        }
    }

    foreach ($resource in @($tableResult.Table.resources)) {
        $relative = ([string] $resource.path).Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        $leaf = Join-Path $PackageRoot $relative
        if (-not (Test-Path -LiteralPath $leaf -PathType Leaf)) {
            return [pscustomobject]@{
                Valid = $false
                PackageContext = $true
                ReasonCode = 'PREPARATION.INTEGRITY_FAILED'
            }
        }
        $bytes = [System.IO.File]::ReadAllBytes($leaf)
        if ((Get-PortableDistributionFileDigest -Bytes $bytes) -ne [string] $resource.sha256) {
            return [pscustomobject]@{
                Valid = $false
                PackageContext = $true
                ReasonCode = 'PREPARATION.INTEGRITY_FAILED'
            }
        }
    }

    try {
        $manifestText = [System.IO.File]::ReadAllText(
            $manifestPath,
            [System.Text.UTF8Encoding]::new($false, $true)
        )
        $manifest = & $ConvertFromJsonCommand -InputObject $manifestText -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            Valid = $false
            PackageContext = $true
            ReasonCode = 'PREPARATION.INTEGRITY_FAILED'
        }
    }

    if ([string] $manifest.kind -ne 'win-pcinfo.portable-distribution-manifest' -or
        [string] $manifest.contractVersion -ne '1.0.0' -or
        [bool] $manifest.installsRuntime) {
        return [pscustomobject]@{
            Valid = $false
            PackageContext = $true
            ReasonCode = 'PREPARATION.INTEGRITY_FAILED'
        }
    }

    $listed = @{}
    foreach ($resource in @($manifest.resources)) {
        $listed[[string] $resource.path] = $resource
        $relative = ([string] $resource.path).Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        $leaf = Join-Path $PackageRoot $relative
        if (-not (Test-Path -LiteralPath $leaf -PathType Leaf)) {
            return [pscustomobject]@{
                Valid = $false
                PackageContext = $true
                ReasonCode = 'PREPARATION.INTEGRITY_FAILED'
            }
        }
        $bytes = [System.IO.File]::ReadAllBytes($leaf)
        if ((Get-PortableDistributionFileDigest -Bytes $bytes) -ne [string] $resource.sha256) {
            return [pscustomobject]@{
                Valid = $false
                PackageContext = $true
                ReasonCode = 'PREPARATION.INTEGRITY_FAILED'
            }
        }
    }

    foreach ($resource in @($tableResult.Table.resources)) {
        if (-not $listed.ContainsKey([string] $resource.path)) {
            return [pscustomobject]@{
                Valid = $false
                PackageContext = $true
                ReasonCode = 'PREPARATION.INTEGRITY_FAILED'
            }
        }
        $listedResource = $listed[[string] $resource.path]
        if ([string] $listedResource.sha256 -ne [string] $resource.sha256) {
            return [pscustomobject]@{
                Valid = $false
                PackageContext = $true
                ReasonCode = 'PREPARATION.INTEGRITY_FAILED'
            }
        }
    }

    [pscustomobject]@{
        Valid = $true
        PackageContext = $true
        ReasonCode = 'PACKAGE.VERIFIED'
        Table = $tableResult.Table
        Manifest = $manifest
    }
}

function New-PortableDistributionVerificationRecord {
    param(
        [Parameter(Mandatory)] [string] $GeneratedContentSha256,
        [Parameter(Mandatory)] [int] $ResourceCount
    )

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.portable-distribution-verification'
        contractVersion = '1.0.0'
        state = 'Verified'
        installsRuntime = $false
        unsignedGeneratedContentIdentity = $GeneratedContentSha256
        resourceCount = $ResourceCount
        supportClaim = 'None'
        previewOrStableClaim = 'None'
        collectionStarted = $false
    }
}
