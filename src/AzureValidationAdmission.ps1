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
        $created = [datetimeoffset]::Parse(
            [string] $Request.tags.CreatedUtc,
            [System.Globalization.CultureInfo]::InvariantCulture
        )
        $expires = [datetimeoffset]::Parse(
            [string] $Request.tags.ExpiresUtc,
            [System.Globalization.CultureInfo]::InvariantCulture
        )
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
        $isClaimingWindows11 = [string] $client.role -eq 'Windows11Validation' -and [bool] $client.claiming
        $trustedLaunch = [string] $client.securityType -eq [string] $claiming.securityType -and
            [string] $client.hyperVGeneration -eq [string] $claiming.hyperVGeneration -and
            [bool] $client.secureBoot -eq [bool] $claiming.secureBoot -and
            [bool] $client.vtpm -eq [bool] $claiming.vtpm
        if ($isClaimingWindows11) {
            if (-not $trustedLaunch -or
                [string] $client.imageSourceKind -ne [string] $claiming.imageSourceKind) {
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
    for ($i = 0; $i -lt 6; $i++) {
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

function Write-AzureValidationRenderedPlan {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] [string] $PrivateWorkspacePath,
        [Parameter(Mandatory)] [string] $TemplateRoot,
        [Parameter(Mandatory)] $Policy
    )

    # Rendering is a local file copy. The threat is treating this as terraform
    # init/plan/apply, which would contact Azure and create private caches.
    # The mechanism is copying only reviewed generic .tf source plus one
    # tfvars file into the already-admitted private workspace. The trust
    # assumption is that the generic templates contain placeholders, not one
    # environment. Safe failure is to throw before a partial rendered tree is
    # treated as admitted; the caller records Rejected and azureContacted=false.
    $destination = Join-Path $PrivateWorkspacePath ([string] $Policy.renderedDirectoryName)
    $null = New-Item -ItemType Directory -Path $destination -Force
    foreach ($item in @(Get-ChildItem -LiteralPath $TemplateRoot -Recurse -File)) {
        $relative = $item.FullName.Substring($TemplateRoot.Length).TrimStart('\', '/')
        if ($relative -match '(?i)(^|[\\/])\.terraform([\\/]|$)') {
            continue
        }
        if ($item.Extension -in @('.tfstate', '.tfstate.backup')) {
            continue
        }
        $target = Join-Path $destination $relative
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force
        Copy-Item -LiteralPath $item.FullName -Destination $target -Force
    }

    $tfvars = @(
        '# Generated into a private workspace after offline admission.'
        '# This file is Restricted environment configuration. Do not commit it.'
        'location                    = "{{AZURE_LOCATION}}"'
        'resource_group_name         = "{{VALIDATION_RESOURCE_GROUP_NAME}}"'
        'host_vnet_id                = "{{HOST_VNET_ID}}"'
        'host_vnet_name              = "{{HOST_VNET_NAME}}"'
        'host_resource_group_name    = "{{HOST_RESOURCE_GROUP_NAME}}"'
        'approved_gallery_image_id   = "{{APPROVED_GALLERY_IMAGE_ID}}"'
        'temporary_admin_password    = "{{TEMPORARY_ADMIN_PASSWORD}}"'
        'client_count                = ' + @($Request.clients).Count
        'maximum_lifetime_minutes    = ' + [int] $Request.round.maximumLifetimeMinutes
        'cleanup_reserve_minutes     = ' + [int] $Request.round.cleanupReserveMinutes
        'nat_public_ip_sku           = "Standard"'
        'os_disk_storage_type        = "StandardSSD_LRS"'
        'assign_vm_public_ip         = false'
        'allow_gateway_transit       = false'
        'allow_forwarded_traffic     = false'
        'use_remote_gateways         = false'
    ) -join "`n"
    $tfvarsPath = Join-Path $destination 'generated.auto.tfvars'
    [System.IO.File]::WriteAllText(
        $tfvarsPath,
        ($tfvars + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $destination
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

    $workspaceReason = Get-AzureValidationWorkspaceRejection `
        -PrivateWorkspacePath $PrivateWorkspacePath `
        -RepositoryRoot $RepositoryRoot `
        -ApplicationDirectory $ApplicationDirectory `
        -Policy $policy `
        -Request $Request
    if ($workspaceReason) {
        $privacy = if ($workspaceReason -eq 'VALIDATION.PRIVACY_BOUNDARY_MISSING') {
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
