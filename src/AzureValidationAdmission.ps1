# Build.ps1 replaces both sentinels with the release-bound admission policy
# and its SHA-256 digest. The generated application treats that table as the
# only trusted copy of the offline Azure validation contract.
$script:AzureValidationAdmissionPolicyBase64 = '__AZURE_VALIDATION_ADMISSION_POLICY_BASE64__'
$script:AzureValidationAdmissionPolicyDigest = '__AZURE_VALIDATION_ADMISSION_POLICY_SHA256__'

function Get-AzureValidationAdmissionSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-AzureValidationAdmissionPolicy {
    # Admission is a maintainer safety gate, not an Azure login. The threat is
    # a substituted policy that widens SKUs, lifetime, or the public/private
    # boundary. The mechanism is an embedded digest, or the reviewed repository
    # file when this module is sourced during development. The trust assumption
    # is that those bytes were reviewed with the rest of the release. Safe
    # failure is to refuse admission rather than invent a looser contract.
    if ($script:AzureValidationAdmissionPolicyBase64 -eq
        ('__AZURE_VALIDATION_ADMISSION_' + 'POLICY_BASE64__')) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-azure-validation-admission.json'
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes($path)
        $expectedDigest = Get-AzureValidationAdmissionSha256 $bytes
    }
    else {
        [byte[]] $bytes = [System.Convert]::FromBase64String(
            $script:AzureValidationAdmissionPolicyBase64
        )
        $expectedDigest = $script:AzureValidationAdmissionPolicyDigest
    }
    if ((Get-AzureValidationAdmissionSha256 $bytes) -ne $expectedDigest) {
        throw 'The Azure validation admission policy failed its embedded digest check.'
    }
    $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $json | ConvertFrom-Json -Depth 20
}

function Test-AzureValidationPathUnderRoot {
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

function Test-AzureValidationPublicPath {
    param([Parameter(Mandatory)] [string] $Path)

    if (Test-NetworkPathSyntax -Path $Path) {
        return $true
    }
    $publicRoot = [string] $env:PUBLIC
    if ([string]::IsNullOrWhiteSpace($publicRoot)) {
        return $false
    }
    if (-not (Test-Path -LiteralPath $publicRoot)) {
        return $false
    }
    Test-AzureValidationPathUnderRoot -Path $Path -Root $publicRoot
}

function Test-AzureValidationFloatingVersion {
    param([Parameter(Mandatory)] [string] $Version)

    $Version -match '[~><^]|,\s*\d'
}

function Test-AzureValidationReparsePath {
    param([Parameter(Mandatory)] [string] $Path)

    # A junction or symlink can make a temp path write into the repository
    # or a network share after the string checks pass. Walk every existing
    # ancestor the same way Evidence Workspace does. The trust assumption is
    # that a private workspace is a real local directory. Safe failure is to
    # reject the path before any rendered file exists.
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

function Test-AzureValidationPrivateSourceFile {
    param(
        [Parameter(Mandatory)] [string] $RelativePath,
        [Parameter(Mandatory)] [string] $FileName
    )

    if ($RelativePath -match '(?i)(^|[\\/])\.terraform([\\/]|$)') {
        return $false
    }
    if ($FileName -eq '.terraform.lock.hcl' -or
        $FileName -match '(?i)(\.tfstate(\.backup)?$|^crash(\..*)?\.log$|^override\.tf(\.json)?$|_override\.tf(\.json)?$)') {
        return $false
    }
    if ($FileName -match '(?i)\.tfvars(\.json)?$') {
        return $false
    }
    $true
}

function ConvertTo-AzureValidationHclBoolean {
    param([Parameter(Mandatory)] [bool] $Value)

    if ($Value) { 'true' } else { 'false' }
}

function ConvertTo-AzureValidationDateTimeOffset {
    param([Parameter(Mandatory)] $Value)

    # ConvertFrom-Json turns a Z timestamp into a local DateTime. Casting that
    # value to string and parsing it again would shift the admitted expiry by
    # the host offset. Prefer the DateTime/DateTimeOffset form and treat a
    # remaining string as UTC. Safe failure is LIFETIME_UNSAFE / render throw.
    if ($Value -is [datetimeoffset]) {
        return $Value.ToUniversalTime()
    }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) {
            return [datetimeoffset]::new($Value, [TimeSpan]::Zero)
        }
        return [datetimeoffset] $Value.ToUniversalTime()
    }
    [datetimeoffset]::Parse(
        [string] $Value,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
            [System.Globalization.DateTimeStyles]::AdjustToUniversal
    )
}

function ConvertTo-AzureValidationUtcStamp {
    param([Parameter(Mandatory)] $Value)

    (ConvertTo-AzureValidationDateTimeOffset -Value $Value).ToString(
        "yyyy-MM-ddTHH:mm:ss'Z'",
        [System.Globalization.CultureInfo]::InvariantCulture
    )
}

function Get-AzureValidationRequestSchemaPath {
    param(
        [Parameter()] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory
    )

    foreach ($root in @($ApplicationDirectory, $RepositoryRoot)) {
        if ([string]::IsNullOrWhiteSpace($root)) {
            continue
        }
        $candidate = Join-Path $root 'schemas/azure-validation-round-request.schema.json'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    $null
}

function Test-AzureValidationTagValueSafe {
    param(
        [Parameter(Mandatory)] [string] $Key,
        [Parameter(Mandatory)] [string] $Value
    )

    if ($Value -match '(?i)/subscriptions/|(?i)\btenant\b|(?i)\.terraform|(?i)clientSecret') {
        return $false
    }
    if ($Key -eq 'RoundCorrelation') {
        return $Value -match '^[A-Z0-9][A-Z0-9._-]{0,31}$'
    }
    $true
}

function New-AzureValidationAdmissionVerdict {
    param(
        [Parameter(Mandatory)] [ValidateSet('Admitted', 'Rejected')] [string] $State,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter()] [Nullable[int]] $ClientCount,
        [Parameter()] [bool] $Windows11ClaimingRoute = $false,
        [Parameter()] [bool] $NonClaimingDiagnosticPresent = $false,
        [Parameter()] [bool] $RequiredTagsPresent = $false,
        [Parameter()] [bool] $ToolingResolved = $false,
        [Parameter()] [ValidateSet('PrivateExternalWorkspace', 'Missing', 'Rejected')]
        [string] $PrivacyBoundary = 'Rejected',
        [Parameter()] [bool] $Rendered = $false
    )

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.azure-validation-admission'
        contractVersion = '1.0.0'
        state = $State
        reasonCode = $ReasonCode
        admitted = ($State -eq 'Admitted')
        rendered = [bool] $Rendered
        azureContacted = $false
        clientCount = $ClientCount
        windows11ClaimingRoute = [bool] $Windows11ClaimingRoute
        nonClaimingDiagnosticPresent = [bool] $NonClaimingDiagnosticPresent
        requiredTagsPresent = [bool] $RequiredTagsPresent
        toolingResolved = [bool] $ToolingResolved
        privacyBoundary = $PrivacyBoundary
        supportClaim = 'None'
        previewOrStableClaim = 'None'
    }
}

function Get-AzureValidationClientFacts {
    param([Parameter(Mandatory)] $Request)

    $clients = @($Request.clients)
    $claimingWindows11 = $false
    $nonClaimingDiagnostic = $false
    foreach ($client in $clients) {
        if ([string] $client.role -eq 'Windows11Validation' -and [bool] $client.claiming) {
            $claimingWindows11 = $true
        }
        if ([string] $client.role -eq 'NonClaimingDiagnostic') {
            $nonClaimingDiagnostic = $true
        }
    }
    [pscustomobject][ordered]@{
        Count = $clients.Count
        Windows11ClaimingRoute = $claimingWindows11
        NonClaimingDiagnosticPresent = $nonClaimingDiagnostic
    }
}

function Test-AzureValidationRequiredTags {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $Policy
    )

    $names = @($Request.tags.PSObject.Properties.Name)
    foreach ($required in @($Policy.requiredTagKeys)) {
        if ($required -notin $names) {
            return $false
        }
    }
    foreach ($fixed in @($Policy.requiredTagValues.PSObject.Properties)) {
        if ([string] $Request.tags.($fixed.Name) -ne [string] $fixed.Value) {
            return $false
        }
    }
    foreach ($property in @($Request.tags.PSObject.Properties)) {
        if (-not (Test-AzureValidationTagValueSafe -Key $property.Name -Value ([string] $property.Value))) {
            return $false
        }
    }
    $true
}

function Get-AzureValidationWorkspaceRejection {
    param(
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $Request
    )

    # The threat is writing plans, tfvars, or later state into the public
    # repository, a shared folder, or a package extract. The mechanism is a
    # caller-supplied private directory that already carries the reviewed
    # privacy marker. The trust assumption is that the operator chose a folder
    # they control outside this checkout. Safe failure is to stop before any
    # rendered file exists.
    if ([string] $Request.privacyBoundary -ne [string] $Policy.privacy.requiredBoundary) {
        return 'VALIDATION.PRIVACY_BOUNDARY_MISSING'
    }
    if ([string]::IsNullOrWhiteSpace($PrivateWorkspacePath)) {
        return 'VALIDATION.PRIVACY_BOUNDARY_MISSING'
    }
    if (Test-AzureValidationPublicPath -Path $PrivateWorkspacePath) {
        return 'VALIDATION.WORKSPACE_PUBLIC_PATH'
    }
    if (Test-AzureValidationPathUnderRoot -Path $PrivateWorkspacePath -Root $RepositoryRoot) {
        return 'VALIDATION.WORKSPACE_REPOSITORY_PATH'
    }
    if (-not [string]::IsNullOrWhiteSpace($ApplicationDirectory) -and
        (Test-Path -LiteralPath $ApplicationDirectory) -and
        (Test-AzureValidationPathUnderRoot -Path $PrivateWorkspacePath -Root $ApplicationDirectory)) {
        return 'VALIDATION.WORKSPACE_REPOSITORY_PATH'
    }
    if (Test-AzureValidationReparsePath -Path $PrivateWorkspacePath) {
        return 'VALIDATION.WORKSPACE_REPARSE_POINT'
    }
    if (-not (Test-Path -LiteralPath $PrivateWorkspacePath -PathType Container)) {
        return 'VALIDATION.PRIVACY_BOUNDARY_MISSING'
    }
    $markerPath = Join-Path $PrivateWorkspacePath ([string] $Policy.privacy.markerFileName)
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        return 'VALIDATION.PRIVACY_BOUNDARY_MISSING'
    }
    $markerText = [System.IO.File]::ReadAllText($markerPath).Trim()
    if ($markerText -ne [string] $Policy.privacy.markerContent) {
        return 'VALIDATION.PRIVACY_BOUNDARY_MISSING'
    }
    $null
}

function Get-AzureValidationPlanRejection {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $Policy
    )

    if ([string] $Request.kind -ne 'win-pcinfo.azure-validation-round-request' -or
        [string] $Request.contractVersion -ne '1.0.0') {
        return 'VALIDATION.REQUEST_INVALID'
    }

    if ([string] $Request.azureContact -ne [string] $Policy.azureContact) {
        return 'VALIDATION.AZURE_CONTACT_PROHIBITED'
    }

    $terraform = $Request.tooling.terraform
    $provider = $Request.tooling.provider
    $expectedTerraform = $Policy.tooling.terraform
    $expectedProvider = $Policy.tooling.provider
    if ([string] $terraform.name -ne [string] $expectedTerraform.name -or
        [string] $terraform.version -ne [string] $expectedTerraform.version -or
        [string] $terraform.source -ne [string] $expectedTerraform.source -or
        [string] $provider.name -ne [string] $expectedProvider.name -or
        [string] $provider.source -ne [string] $expectedProvider.source -or
        [string] $provider.version -ne [string] $expectedProvider.version -or
        (Test-AzureValidationFloatingVersion -Version ([string] $terraform.version)) -or
        (Test-AzureValidationFloatingVersion -Version ([string] $provider.version))) {
        return 'VALIDATION.TOOLING_UNRESOLVED'
    }

    $clientCount = @($Request.clients).Count
    if ($clientCount -lt [int] $Policy.clients.minimum -or
        $clientCount -gt [int] $Policy.clients.maximum) {
        return 'VALIDATION.CLIENT_COUNT_UNSAFE'
    }

    if ([int] $Request.round.cleanupReserveMinutes -lt [int] $Policy.lifetime.minimumCleanupReserveMinutes) {
        return 'VALIDATION.CLEANUP_RESERVE_MISSING'
    }
    $planned = [int] $Request.round.plannedDurationMinutes
    $reserve = [int] $Request.round.cleanupReserveMinutes
    $lifetime = [int] $Request.round.maximumLifetimeMinutes
    if ($planned -lt 1 -or
        $lifetime -gt [int] $Policy.lifetime.maximumMinutes -or
        ($planned + $reserve) -gt [int] $Policy.lifetime.maximumMinutes -or
        $lifetime -ne ($planned + $reserve)) {
        return 'VALIDATION.LIFETIME_UNSAFE'
    }
    try {
        $created = ConvertTo-AzureValidationDateTimeOffset -Value $Request.tags.CreatedUtc
        $expires = ConvertTo-AzureValidationDateTimeOffset -Value $Request.tags.ExpiresUtc
        if ([int] ($expires - $created).TotalMinutes -ne $lifetime) {
            return 'VALIDATION.LIFETIME_UNSAFE'
        }
    }
    catch {
        return 'VALIDATION.LIFETIME_UNSAFE'
    }

    if (-not (Test-AzureValidationRequiredTags -Request $Request -Policy $Policy)) {
        return 'VALIDATION.TAGS_MISSING'
    }

    $network = $Request.network
    $expectedNetwork = $Policy.network
    if ([bool] $network.roundVnet -ne [bool] $expectedNetwork.roundVnet -or
        [bool] $network.roundSubnet -ne [bool] $expectedNetwork.roundSubnet -or
        [bool] $network.privateNics -ne [bool] $expectedNetwork.privateNics -or
        [bool] $network.vmPublicIp -ne [bool] $expectedNetwork.vmPublicIp -or
        [bool] $network.natGateway -ne [bool] $expectedNetwork.natGateway -or
        [string] $network.natPublicIpSku -ne [string] $expectedNetwork.natPublicIpSku -or
        -not [bool] $network.peering.present -or
        [bool] $network.peering.allowForwardedTraffic -ne [bool] $expectedNetwork.peering.allowForwardedTraffic -or
        [bool] $network.peering.allowGatewayTransit -ne [bool] $expectedNetwork.peering.allowGatewayTransit -or
        [bool] $network.peering.useRemoteGateways -ne [bool] $expectedNetwork.peering.useRemoteGateways) {
        return 'VALIDATION.NETWORK_UNSAFE'
    }

    $allowedSkus = @($Policy.clients.allowedSkus)
    $claiming = $Policy.clients.windows11ClaimingRoute
    foreach ($client in @($Request.clients)) {
        if ([string] $client.diskType -ne [string] $Policy.clients.diskType) {
            return 'VALIDATION.DISK_UNSAFE'
        }
        if ([string] $client.sku -notin $allowedSkus) {
            return 'VALIDATION.PLAN_UNSAFE'
        }
        if ([bool] $client.claiming -and [string] $client.role -ne 'Windows11Validation') {
            return 'VALIDATION.SECURITY_UNSAFE'
        }
        $isClaimingWindows11 = [string] $client.role -eq 'Windows11Validation' -and [bool] $client.claiming
        $trustedLaunch = [string] $client.securityType -eq [string] $claiming.securityType -and
            [string] $client.hyperVGeneration -eq [string] $claiming.hyperVGeneration -and
            [bool] $client.secureBoot -eq [bool] $claiming.secureBoot -and
            [bool] $client.vtpm -eq [bool] $claiming.vtpm
        if ($isClaimingWindows11) {
            if (-not $trustedLaunch) {
                return 'VALIDATION.SECURITY_UNSAFE'
            }
        }
        elseif (-not $trustedLaunch) {
            if ([bool] $client.claiming -or [string] $client.role -ne 'NonClaimingDiagnostic') {
                return 'VALIDATION.SECURITY_UNSAFE'
            }
        }
        if ([string] $client.imageSourceKind -ne [string] $claiming.imageSourceKind) {
            return 'VALIDATION.IMAGE_UNSAFE'
        }
    }

    $null
}

function Get-AzureValidationTemplateRoot {
    param(
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter(Mandatory)] $Policy
    )

    $direct = Join-Path $RepositoryRoot ([string] $Policy.templateRootRelativePath)
    if (Test-Path -LiteralPath (Join-Path $direct 'versions.tf') -PathType Leaf) {
        return $direct
    }

    $cursor = $RepositoryRoot
    for ($i = 0; $i -lt 2; $i++) {
        $candidate = Join-Path $cursor ([string] $Policy.templateRootRelativePath)
        if (Test-Path -LiteralPath (Join-Path $candidate 'versions.tf') -PathType Leaf) {
            return $candidate
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) {
            break
        }
        $cursor = $parent
    }
    $null
}

function ConvertTo-AzureValidationRenderedTfvars {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $Policy
    )

    # The threat is writing a live gallery ID, password, or unmatched SKU into
    # the admitted plan. The mechanism is a closed HCL object built only from
    # already-validated allowlist tokens, booleans, and reformatted timestamps.
    # The trust assumption is that Get-AzureValidationPlanRejection already
    # accepted this request. Safe failure is to throw so the caller deletes the
    # partial tree and records Rejected with azureContacted=false.
    $allowedSkus = @($Policy.clients.allowedSkus)
    $allowedSecurity = @('TrustedLaunch', 'Standard')
    $clientLines = [System.Collections.Generic.List[string]]::new()
    $null = $clientLines.Add('clients = [')
    foreach ($client in @($Request.clients)) {
        $sku = [string] $client.sku
        $securityType = [string] $client.securityType
        if ($sku -notin $allowedSkus -or $securityType -notin $allowedSecurity) {
            throw 'The admitted client shape could not be rendered from allowlisted values.'
        }
        $null = $clientLines.Add('  {')
        $null = $clientLines.Add(('    sku           = "' + $sku + '"'))
        $null = $clientLines.Add(('    claiming      = ' + (ConvertTo-AzureValidationHclBoolean -Value ([bool] $client.claiming))))
        $null = $clientLines.Add(('    security_type = "' + $securityType + '"'))
        $null = $clientLines.Add(('    secure_boot   = ' + (ConvertTo-AzureValidationHclBoolean -Value ([bool] $client.secureBoot))))
        $null = $clientLines.Add(('    vtpm          = ' + (ConvertTo-AzureValidationHclBoolean -Value ([bool] $client.vtpm))))
        $null = $clientLines.Add('  },')
    }
    $null = $clientLines.Add(']')

    $createdStamp = ConvertTo-AzureValidationUtcStamp -Value $Request.tags.CreatedUtc
    $expiresStamp = ConvertTo-AzureValidationUtcStamp -Value $Request.tags.ExpiresUtc
    $roundCorrelation = [string] $Request.tags.RoundCorrelation
    if ($roundCorrelation -notmatch '^[A-Z0-9][A-Z0-9._-]{0,31}$') {
        throw 'The admitted RoundCorrelation token could not be rendered.'
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in @(
        '# Generated into a private workspace after offline admission.'
        '# This file is Restricted environment configuration. Do not commit it.'
        '# Gallery, host-network, and bootstrap-password values stay placeholders.'
        'location                    = "{{AZURE_LOCATION}}"'
        'resource_group_name         = "{{VALIDATION_RESOURCE_GROUP_NAME}}"'
        'host_vnet_id                = "{{HOST_VNET_ID}}"'
        'host_vnet_name              = "{{HOST_VNET_NAME}}"'
        'host_resource_group_name    = "{{HOST_RESOURCE_GROUP_NAME}}"'
        'approved_gallery_image_id   = "{{APPROVED_GALLERY_IMAGE_ID}}"'
        ('client_count                = ' + @($Request.clients).Count)
    )) {
        $null = $lines.Add($line)
    }
    foreach ($line in $clientLines) {
        $null = $lines.Add($line)
    }
    foreach ($line in @(
        ('maximum_lifetime_minutes    = ' + [int] $Request.round.maximumLifetimeMinutes)
        ('cleanup_reserve_minutes     = ' + [int] $Request.round.cleanupReserveMinutes)
        'nat_public_ip_sku           = "Standard"'
        'os_disk_storage_type        = "StandardSSD_LRS"'
        'assign_vm_public_ip         = false'
        'allow_gateway_transit       = false'
        'allow_forwarded_traffic     = false'
        'use_remote_gateways         = false'
        ('purpose_tag                 = "' + [string] $Policy.requiredTagValues.Purpose + '"')
        ('environment_tag             = "' + [string] $Policy.requiredTagValues.Environment + '"')
        ('lifecycle_tag               = "' + [string] $Policy.requiredTagValues.Lifecycle + '"')
        ('managing_tool_tag           = "' + [string] $Policy.requiredTagValues.ManagingTool + '"')
        ('round_correlation_tag       = "' + $roundCorrelation + '"')
        ('created_utc_tag             = "' + $createdStamp + '"')
        ('expires_utc_tag             = "' + $expiresStamp + '"')
    )) {
        $null = $lines.Add($line)
    }
    ($lines -join "`n") + "`n"
}

function Write-AzureValidationRenderedPlan {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] [string] $TemplateRoot,
        [Parameter(Mandatory)] $Policy
    )

    # Rendering is a local file copy. The threat is treating this as terraform
    # init/plan/apply, which would contact Azure and create private caches, or
    # leaving a half-written tree after a later throw is reported as
    # NotStarted. The mechanism is copying only reviewed generic source into a
    # temporary sibling directory, then renaming it. The trust assumption is
    # that the generic templates contain placeholders, not one environment.
    # Safe failure is to delete the partial tree and keep azureContacted=false.
    $tfvars = ConvertTo-AzureValidationRenderedTfvars -Request $Request -Policy $Policy
    $finalDestination = Join-Path $PrivateWorkspacePath ([string] $Policy.renderedDirectoryName)
    $partialDestination = Join-Path $PrivateWorkspacePath (
        [string] $Policy.renderedDirectoryName + '.partial'
    )
    if (Test-Path -LiteralPath $partialDestination) {
        Remove-Item -LiteralPath $partialDestination -Recurse -Force
    }
    try {
        $null = New-Item -ItemType Directory -Path $partialDestination -Force
        foreach ($item in @(Get-ChildItem -LiteralPath $TemplateRoot -Recurse -File)) {
            $relative = $item.FullName.Substring($TemplateRoot.Length).TrimStart('\', '/')
            if (-not (Test-AzureValidationPrivateSourceFile -RelativePath $relative -FileName $item.Name)) {
                continue
            }
            $target = Join-Path $partialDestination $relative
            $null = New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force
            Copy-Item -LiteralPath $item.FullName -Destination $target -Force
        }

        $tfvarsPath = Join-Path $partialDestination 'generated.auto.tfvars'
        [System.IO.File]::WriteAllText(
            $tfvarsPath,
            $tfvars,
            [System.Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $finalDestination) {
            Remove-Item -LiteralPath $finalDestination -Recurse -Force
        }
        Rename-Item -LiteralPath $partialDestination -NewName ([string] $Policy.renderedDirectoryName)
    }
    catch {
        if (Test-Path -LiteralPath $partialDestination) {
            Remove-Item -LiteralPath $partialDestination -Recurse -Force
        }
        throw
    }
    $finalDestination
}

function Invoke-AzureValidationAdmission {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter()] [string] $ApplicationDirectory
    )

    $policy = Get-AzureValidationAdmissionPolicy
    $facts = Get-AzureValidationClientFacts -Request $Request
    $tagsPresent = Test-AzureValidationRequiredTags -Request $Request -Policy $policy
    $toolingResolved = $false
    try {
        $toolingResolved = [string] $Request.tooling.terraform.version -eq [string] $policy.tooling.terraform.version -and
            [string] $Request.tooling.provider.version -eq [string] $policy.tooling.provider.version -and
            -not (Test-AzureValidationFloatingVersion -Version ([string] $Request.tooling.provider.version))
    }
    catch {
        $toolingResolved = $false
    }

    $requestSchemaPath = Get-AzureValidationRequestSchemaPath `
        -RepositoryRoot $RepositoryRoot `
        -ApplicationDirectory $ApplicationDirectory
    if (-not [string]::IsNullOrWhiteSpace($requestSchemaPath)) {
        $requestJson = $Request | ConvertTo-Json -Depth 20 -Compress
        $requestSchemaValid = $false
        try {
            $requestSchemaValid = Test-Json -Json $requestJson -SchemaFile $requestSchemaPath
        }
        catch {
            $requestSchemaValid = $false
        }
        if (-not $requestSchemaValid) {
            return New-AzureValidationAdmissionVerdict -State Rejected `
                -ReasonCode 'VALIDATION.REQUEST_INVALID' `
                -ClientCount $facts.Count `
                -Windows11ClaimingRoute:$facts.Windows11ClaimingRoute `
                -NonClaimingDiagnosticPresent:$facts.NonClaimingDiagnosticPresent `
                -RequiredTagsPresent:$tagsPresent `
                -ToolingResolved:$toolingResolved `
                -PrivacyBoundary Missing
        }
    }

    $workspaceReason = Get-AzureValidationWorkspaceRejection `
        -PrivateWorkspacePath $PrivateWorkspacePath `
        -RepositoryRoot $RepositoryRoot `
        -ApplicationDirectory $ApplicationDirectory `
        -Policy $policy `
        -Request $Request
    if ($workspaceReason) {
        $privacy = if ($workspaceReason -in @(
            'VALIDATION.PRIVACY_BOUNDARY_MISSING',
            'VALIDATION.WORKSPACE_REPARSE_POINT'
        )) {
            'Rejected'
        }
        elseif ([string] $Request.privacyBoundary -eq [string] $policy.privacy.requiredBoundary) {
            'PrivateExternalWorkspace'
        }
        else {
            'Rejected'
        }
        return New-AzureValidationAdmissionVerdict -State Rejected -ReasonCode $workspaceReason `
            -ClientCount $facts.Count `
            -Windows11ClaimingRoute:$facts.Windows11ClaimingRoute `
            -NonClaimingDiagnosticPresent:$facts.NonClaimingDiagnosticPresent `
            -RequiredTagsPresent:$tagsPresent `
            -ToolingResolved:$toolingResolved `
            -PrivacyBoundary $privacy
    }

    $planReason = Get-AzureValidationPlanRejection -Request $Request -Policy $policy
    if ($planReason) {
        return New-AzureValidationAdmissionVerdict -State Rejected -ReasonCode $planReason `
            -ClientCount $facts.Count `
            -Windows11ClaimingRoute:$facts.Windows11ClaimingRoute `
            -NonClaimingDiagnosticPresent:$facts.NonClaimingDiagnosticPresent `
            -RequiredTagsPresent:$tagsPresent `
            -ToolingResolved:$toolingResolved `
            -PrivacyBoundary 'PrivateExternalWorkspace'
    }

    $templateRoot = Get-AzureValidationTemplateRoot -RepositoryRoot $RepositoryRoot -Policy $policy
    if ([string]::IsNullOrWhiteSpace($templateRoot)) {
        return New-AzureValidationAdmissionVerdict -State Rejected `
            -ReasonCode 'VALIDATION.TEMPLATE_SOURCE_MISSING' `
            -ClientCount $facts.Count `
            -Windows11ClaimingRoute:$facts.Windows11ClaimingRoute `
            -NonClaimingDiagnosticPresent:$facts.NonClaimingDiagnosticPresent `
            -RequiredTagsPresent:$tagsPresent `
            -ToolingResolved:$true `
            -PrivacyBoundary 'PrivateExternalWorkspace'
    }

    $null = Write-AzureValidationRenderedPlan -Request $Request `
        -PrivateWorkspacePath $PrivateWorkspacePath `
        -TemplateRoot $templateRoot `
        -Policy $policy

    New-AzureValidationAdmissionVerdict -State Admitted -ReasonCode 'VALIDATION.ROUND_ADMITTED' `
        -ClientCount $facts.Count `
        -Windows11ClaimingRoute:$facts.Windows11ClaimingRoute `
        -NonClaimingDiagnosticPresent:$facts.NonClaimingDiagnosticPresent `
        -RequiredTagsPresent:$true `
        -ToolingResolved:$true `
        -PrivacyBoundary 'PrivateExternalWorkspace' `
        -Rendered:$true
}
