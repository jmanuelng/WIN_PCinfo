[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/AzureValidationAdmission.ps1')

$policy = Get-AzureValidationAdmissionPolicy
$requestSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-round-request.schema.json'
$verdictSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-admission-verdict.schema.json'
$oneClientPath = Join-Path $PSScriptRoot 'fixtures/azure-validation-round-one-client.json'
$fourClientPath = Join-Path $PSScriptRoot 'fixtures/azure-validation-round-four-clients.json'
$diagnosticPath = Join-Path $PSScriptRoot 'fixtures/azure-validation-round-nonclaiming-diagnostic.json'

function Get-RequestFromPath {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    Get-Content -LiteralPath $LiteralPath -Raw | ConvertFrom-Json -Depth 20
}

function Copy-Request {
    param([Parameter(Mandatory)] $Request)
    $Request | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
}

function New-PrivateWorkspace {
    param([Parameter(Mandatory)] [string] $Name)
    $root = Join-Path ([System.IO.Path]::GetTempPath()) "win-pcinfo-azure-admission-$Name"
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $root -Force
    $marker = Join-Path $root $policy.privacy.markerFileName
    [System.IO.File]::WriteAllText(
        $marker,
        ($policy.privacy.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $root
}

function Remove-PrivateWorkspace {
    param([Parameter(Mandatory)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        $item.Delete()
        return
    }
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Assert-SanitizedVerdict {
    param(
        [Parameter(Mandatory)] $Verdict,
        [Parameter(Mandatory)] [string] $Because,
        [Parameter()] [string] $WorkspacePath
    )
    $json = $Verdict | ConvertTo-Json -Compress -Depth 10
    Assert-Equal $true (Test-Json -Json $json -SchemaFile $verdictSchemaPath) `
        "${Because} verdict satisfies the public sanitized schema"
    Assert-Equal $false $Verdict.azureContacted "${Because} Azure was not contacted"
    Assert-Equal 'None' $Verdict.supportClaim "${Because} no support claim"
    Assert-Equal 'None' $Verdict.previewOrStableClaim "${Because} no Preview claim"
    $needles = @(
        '(?i)/subscriptions/'
        '(?i)tenant'
        '(?i)gallery'
        '(?i)\.terraform'
        '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY'
        '(?i)clientSecret'
        '(?i)\b\d{1,3}(\.\d{1,3}){3}\b'
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
    )
    foreach ($needle in $needles) {
        Assert-Equal $false ($json -match $needle) `
            "${Because} sanitized verdict must not match $needle"
    }
    if (-not [string]::IsNullOrWhiteSpace($WorkspacePath)) {
        $escaped = [regex]::Escape($WorkspacePath)
        Assert-Equal $false ($json -match $escaped) `
            "${Because} sanitized verdict must not record the private workspace path"
    }
}

function Invoke-Admission {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] [string] $WorkspacePath
    )
    Invoke-AzureValidationAdmission -Request $Request `
        -PrivateWorkspacePath $WorkspacePath `
        -RepositoryRoot $repositoryRoot `
        -ApplicationDirectory (Join-Path $repositoryRoot 'artifacts')
}

$ownedWorkspaces = New-Object System.Collections.Generic.List[string]
try {
    $safeWorkspace = New-PrivateWorkspace -Name 'safe'
    $ownedWorkspaces.Add($safeWorkspace)

    $one = Get-RequestFromPath -LiteralPath $oneClientPath
    $oneVerdict = Invoke-Admission -Request $one -WorkspacePath $safeWorkspace
    Assert-Equal 'Admitted' $oneVerdict.state 'a one-client synthetic plan is admitted'
    Assert-Equal 'VALIDATION.ROUND_ADMITTED' $oneVerdict.reasonCode `
        'the admitted reason is stable'
    Assert-Equal $true $oneVerdict.admitted 'one-client plan is admitted'
    Assert-Equal $true $oneVerdict.rendered 'admitted plans are rendered privately'
    Assert-Equal 1 $oneVerdict.clientCount 'one-client count is recorded'
    Assert-Equal $true $oneVerdict.windows11ClaimingRoute `
        'the Windows 11 claiming route is recorded without identifiers'
    Assert-Equal $false $oneVerdict.nonClaimingDiagnosticPresent `
        'no diagnostic VM is present'
    Assert-SanitizedVerdict -Verdict $oneVerdict -Because 'one-client admit' `
        -WorkspacePath $safeWorkspace
    $renderedRoot = Join-Path $safeWorkspace ([string] $policy.renderedDirectoryName)
    Assert-Equal $true (Test-Path -LiteralPath (Join-Path $renderedRoot 'versions.tf') -PathType Leaf) `
        'generic versions are copied only after admission'
    Assert-Equal $true (Test-Path -LiteralPath (Join-Path $renderedRoot 'generated.auto.tfvars') -PathType Leaf) `
        'rendered variable values stay in the private workspace'
    Assert-Equal $false (Test-Path -LiteralPath (Join-Path $renderedRoot '.terraform')) `
        'admission does not create a Terraform cache'
    Assert-Equal $false (Test-Path -LiteralPath (Join-Path $repositoryRoot 'generated.auto.tfvars')) `
        'rendered values are not written into the repository'
    $oneTfvars = [System.IO.File]::ReadAllText((Join-Path $renderedRoot 'generated.auto.tfvars'))
    Assert-Equal $true ($oneTfvars -match 'sku\s+=\s+"Standard_D2s_v5"') `
        'the one-client rendered plan binds the admitted SKU'
    Assert-Equal $true ($oneTfvars -match 'security_type\s+=\s+"TrustedLaunch"') `
        'the one-client rendered plan binds Trusted Launch'
    Assert-Equal $true ($oneTfvars -match 'round_correlation_tag\s+=\s+"SYNTHETIC-ROUND-001"') `
        'the rendered plan binds the required RoundCorrelation tag'
    Assert-Equal $true ($oneTfvars -match 'created_utc_tag\s+=\s+"2026-01-01T00:00:00Z"') `
        'the rendered plan binds CreatedUtc'
    Assert-Equal $true ($oneTfvars -match 'expires_utc_tag\s+=\s+"2026-01-01T03:30:00Z"') `
        'the rendered plan binds ExpiresUtc'
    Assert-Equal $true ($oneTfvars -match 'approved_gallery_image_id\s+=\s+"\{\{APPROVED_GALLERY_IMAGE_ID\}\}"') `
        'the rendered plan keeps the gallery reference as a placeholder'
    Assert-Equal $false ($oneTfvars -match 'temporary_admin_password') `
        'the gate does not write a bootstrap password'
    Assert-Equal $false (Test-Path -LiteralPath (Join-Path $renderedRoot 'generated.auto.tfvars.partial')) `
        'successful rendering does not leave a partial sibling'
    $clientModule = [System.IO.File]::ReadAllText(
        (Join-Path $renderedRoot 'modules/validation-client/main.tf')
    )
    Assert-Equal $true ($clientModule -match 'secure_boot_enabled\s+=\s+var\.secure_boot') `
        'the copied client module is parameterized for Secure Boot'

    $fourWorkspace = New-PrivateWorkspace -Name 'four'
    $ownedWorkspaces.Add($fourWorkspace)
    $four = Get-RequestFromPath -LiteralPath $fourClientPath
    $fourVerdict = Invoke-Admission -Request $four -WorkspacePath $fourWorkspace
    Assert-Equal 'Admitted' $fourVerdict.state 'a four-client synthetic plan is admitted'
    Assert-Equal 4 $fourVerdict.clientCount 'four-client count is recorded'
    Assert-SanitizedVerdict -Verdict $fourVerdict -Because 'four-client admit' `
        -WorkspacePath $fourWorkspace
    $fourTfvars = [System.IO.File]::ReadAllText(
        (Join-Path $fourWorkspace "$($policy.renderedDirectoryName)/generated.auto.tfvars")
    )
    foreach ($sku in @('Standard_D2s_v5', 'Standard_D2as_v5', 'Standard_B2ms', 'Standard_B2s')) {
        Assert-Equal $true ($fourTfvars -match [regex]::Escape("sku           = `"$sku`"")) `
            "the four-client rendered plan binds $sku"
    }

    $diagWorkspace = New-PrivateWorkspace -Name 'diag'
    $ownedWorkspaces.Add($diagWorkspace)
    $diagnostic = Get-RequestFromPath -LiteralPath $diagnosticPath
    $diagVerdict = Invoke-Admission -Request $diagnostic -WorkspacePath $diagWorkspace
    Assert-Equal 'Admitted' $diagVerdict.state `
        'a non-Trusted-Launch diagnostic VM is admitted only when non-claiming'
    Assert-Equal $true $diagVerdict.nonClaimingDiagnosticPresent `
        'the diagnostic VM is labeled non-claiming'
    Assert-Equal $true $diagVerdict.windows11ClaimingRoute `
        'the claiming Windows 11 client remains distinct'
    Assert-SanitizedVerdict -Verdict $diagVerdict -Because 'non-claiming diagnostic' `
        -WorkspacePath $diagWorkspace
    $diagTfvars = [System.IO.File]::ReadAllText(
        (Join-Path $diagWorkspace "$($policy.renderedDirectoryName)/generated.auto.tfvars")
    )
    Assert-Equal $true ($diagTfvars -match 'security_type = "Standard"') `
        'the rendered plan keeps a non-claiming diagnostic on Standard security'
    Assert-Equal $true ($diagTfvars -match 'claiming      = false') `
        'the rendered diagnostic client stays non-claiming'
    Assert-Equal $true ($diagTfvars -match 'security_type = "TrustedLaunch"') `
        'the claiming Windows 11 client remains Trusted Launch in the rendered plan'

    $fiveWorkspace = New-PrivateWorkspace -Name 'five'
    $ownedWorkspaces.Add($fiveWorkspace)
    $five = Copy-Request -Request $one
    $five.clients = @($one.clients[0], $one.clients[0], $one.clients[0], $one.clients[0], $one.clients[0])
    $fiveVerdict = Invoke-Admission -Request $five -WorkspacePath $fiveWorkspace
    Assert-Equal 'Rejected' $fiveVerdict.state 'a fifth client is rejected'
    Assert-Equal 'VALIDATION.CLIENT_COUNT_UNSAFE' $fiveVerdict.reasonCode `
        'the fifth-client reason is stable'
    Assert-Equal $false $fiveVerdict.rendered 'unsafe plans are not rendered'
    Assert-Equal $false (Test-Path -LiteralPath (Join-Path $fiveWorkspace $policy.renderedDirectoryName)) `
        'rejected fifth-client plans leave no rendered workspace'
    Assert-SanitizedVerdict -Verdict $fiveVerdict -Because 'fifth client' `
        -WorkspacePath $fiveWorkspace

    $overWorkspace = New-PrivateWorkspace -Name 'over'
    $ownedWorkspaces.Add($overWorkspace)
    $over = Copy-Request -Request $one
    $over.round.plannedDurationMinutes = 360
    $over.round.cleanupReserveMinutes = 30
    $over.round.maximumLifetimeMinutes = 390
    $overVerdict = Invoke-Admission -Request $over -WorkspacePath $overWorkspace
    Assert-Equal 'Rejected' $overVerdict.state 'an over-budget lifetime is rejected'
    Assert-Equal 'VALIDATION.LIFETIME_UNSAFE' $overVerdict.reasonCode `
        'the over-budget reason is stable'
    Assert-Equal $false $overVerdict.rendered 'over-budget plans are not rendered'
    Assert-SanitizedVerdict -Verdict $overVerdict -Because 'over-budget' `
        -WorkspacePath $overWorkspace

    $reserveWorkspace = New-PrivateWorkspace -Name 'reserve'
    $ownedWorkspaces.Add($reserveWorkspace)
    $reserve = Copy-Request -Request $one
    $reserve.round.cleanupReserveMinutes = 0
    $reserve.round.maximumLifetimeMinutes = 180
    $reserveVerdict = Invoke-Admission -Request $reserve -WorkspacePath $reserveWorkspace
    Assert-Equal 'Rejected' $reserveVerdict.state 'a missing cleanup reserve is rejected'
    Assert-Equal 'VALIDATION.CLEANUP_RESERVE_MISSING' $reserveVerdict.reasonCode `
        'the cleanup-reserve reason is stable'
    Assert-Equal $false $reserveVerdict.rendered 'plans without cleanup reserve are not rendered'

    $expiryWorkspace = New-PrivateWorkspace -Name 'expiry'
    $ownedWorkspaces.Add($expiryWorkspace)
    $expiry = Copy-Request -Request $one
    $expiry.tags.ExpiresUtc = '2026-01-01T05:00:00Z'
    $expiryVerdict = Invoke-Admission -Request $expiry -WorkspacePath $expiryWorkspace
    Assert-Equal 'Rejected' $expiryVerdict.state 'an expiry that does not match the lifetime is rejected'
    Assert-Equal 'VALIDATION.LIFETIME_UNSAFE' $expiryVerdict.reasonCode `
        'expiry mismatch uses the lifetime reason'
    Assert-Equal $false $expiryVerdict.rendered 'expiry-mismatch plans are not rendered'

    $kindWorkspace = New-PrivateWorkspace -Name 'kind'
    $ownedWorkspaces.Add($kindWorkspace)
    $kind = Copy-Request -Request $one
    $kind.kind = 'win-pcinfo.assessment-run-request'
    $kindVerdict = Invoke-Admission -Request $kind -WorkspacePath $kindWorkspace
    Assert-Equal 'Rejected' $kindVerdict.state 'a wrong request kind is rejected'
    Assert-Equal 'VALIDATION.REQUEST_INVALID' $kindVerdict.reasonCode `
        'request identity uses a stable invalid-request reason'
    Assert-Equal $false $kindVerdict.rendered 'wrong-kind requests are not rendered'

    $imageKindWorkspace = New-PrivateWorkspace -Name 'image-kind'
    $ownedWorkspaces.Add($imageKindWorkspace)
    $imageKind = Copy-Request -Request $one
    $imageKind.clients[0].imageSourceKind = 'AzureMarketplace'
    $imageKindVerdict = Invoke-Admission -Request $imageKind -WorkspacePath $imageKindWorkspace
    Assert-Equal 'Rejected' $imageKindVerdict.state 'a marketplace image declaration is rejected'
    Assert-Equal 'VALIDATION.IMAGE_UNSAFE' $imageKindVerdict.reasonCode `
        'unsafe image source uses a stable reason'
    Assert-Equal $false $imageKindVerdict.rendered 'unsafe image plans are not rendered'

    $repoVerdict = Invoke-Admission -Request $one -WorkspacePath $repositoryRoot
    Assert-Equal 'Rejected' $repoVerdict.state 'a repository workspace is rejected'
    Assert-Equal 'VALIDATION.WORKSPACE_REPOSITORY_PATH' $repoVerdict.reasonCode `
        'repository paths are rejected before rendering'
    Assert-Equal $false $repoVerdict.rendered 'repository paths never receive rendered files'
    Assert-SanitizedVerdict -Verdict $repoVerdict -Because 'repository path'

    $insideRepo = Join-Path $repositoryRoot '.test-output/azure-validation-forbidden'
    $null = New-Item -ItemType Directory -Path $insideRepo -Force
    $insideMarker = Join-Path $insideRepo $policy.privacy.markerFileName
    [System.IO.File]::WriteAllText(
        $insideMarker,
        ($policy.privacy.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    try {
        $insideVerdict = Invoke-Admission -Request $one -WorkspacePath $insideRepo
        Assert-Equal 'Rejected' $insideVerdict.state `
            'a workspace inside the repository is rejected even with a marker'
        Assert-Equal 'VALIDATION.WORKSPACE_REPOSITORY_PATH' $insideVerdict.reasonCode `
            'in-repo workspaces use the repository-path reason'
        Assert-Equal $false (Test-Path -LiteralPath (Join-Path $insideRepo $policy.renderedDirectoryName)) `
            'in-repo workspaces are not rendered'
    }
    finally {
        Remove-Item -LiteralPath $insideRepo -Recurse -Force
    }

    $publicRoot = [string] $env:PUBLIC
    if (-not [string]::IsNullOrWhiteSpace($publicRoot) -and (Test-Path -LiteralPath $publicRoot)) {
        $publicWorkspace = Join-Path $publicRoot ("win-pcinfo-azure-admission-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $publicWorkspace -Force
        $ownedWorkspaces.Add($publicWorkspace)
        $publicMarker = Join-Path $publicWorkspace $policy.privacy.markerFileName
        [System.IO.File]::WriteAllText(
            $publicMarker,
            ($policy.privacy.markerContent + "`n"),
            [System.Text.UTF8Encoding]::new($false)
        )
        $publicVerdict = Invoke-Admission -Request $one -WorkspacePath $publicWorkspace
        Assert-Equal 'Rejected' $publicVerdict.state 'a public path is rejected'
        Assert-Equal 'VALIDATION.WORKSPACE_PUBLIC_PATH' $publicVerdict.reasonCode `
            'public paths are rejected before rendering'
        Assert-Equal $false $publicVerdict.rendered 'public paths never receive rendered files'
    }

    $junctionRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        'win-pcinfo-azure-admission-junction-' + [guid]::NewGuid().ToString('N')
    )
    $junctionTarget = New-PrivateWorkspace -Name 'junction-target'
    $ownedWorkspaces.Add($junctionTarget)
    $null = New-Item -ItemType Junction -Path $junctionRoot -Target $junctionTarget
    $ownedWorkspaces.Add($junctionRoot)
    $junctionVerdict = Invoke-Admission -Request $one -WorkspacePath $junctionRoot
    Assert-Equal 'Rejected' $junctionVerdict.state 'a redirected workspace is rejected'
    Assert-Equal 'VALIDATION.WORKSPACE_REPARSE_POINT' $junctionVerdict.reasonCode `
        'reparse points use a distinct rejection'
    Assert-Equal $false $junctionVerdict.rendered 'redirected workspaces are not rendered'
    Assert-Equal 'Rejected' $junctionVerdict.privacyBoundary `
        'a redirected folder does not invent a privacy boundary'

    $uncVerdict = Invoke-Admission -Request $one -WorkspacePath '\\public-share\validation'
    Assert-Equal 'Rejected' $uncVerdict.state 'a UNC path is rejected'
    Assert-Equal 'VALIDATION.WORKSPACE_PUBLIC_PATH' $uncVerdict.reasonCode `
        'UNC paths are treated as public paths'
    Assert-Equal $false $uncVerdict.rendered 'UNC paths are not rendered'

    $unmarked = Join-Path ([System.IO.Path]::GetTempPath()) (
        'win-pcinfo-azure-admission-unmarked-' + [guid]::NewGuid().ToString('N')
    )
    $null = New-Item -ItemType Directory -Path $unmarked -Force
    $ownedWorkspaces.Add($unmarked)
    $unmarkedVerdict = Invoke-Admission -Request $one -WorkspacePath $unmarked
    Assert-Equal 'Rejected' $unmarkedVerdict.state 'a missing privacy marker is rejected'
    Assert-Equal 'VALIDATION.PRIVACY_BOUNDARY_MISSING' $unmarkedVerdict.reasonCode `
        'missing privacy boundary is a distinct rejection'
    Assert-Equal $false $unmarkedVerdict.rendered 'unmarked workspaces are not rendered'
    Assert-Equal 'Rejected' $unmarkedVerdict.privacyBoundary `
        'the sanitized verdict does not invent a privacy boundary'

    $boundary = Copy-Request -Request $one
    $boundary.privacyBoundary = 'SharedScratch'
    $boundaryWorkspace = New-PrivateWorkspace -Name 'boundary'
    $ownedWorkspaces.Add($boundaryWorkspace)
    $boundaryVerdict = Invoke-Admission -Request $boundary -WorkspacePath $boundaryWorkspace
    Assert-Equal 'Rejected' $boundaryVerdict.state 'an undeclared privacy boundary is rejected'
    Assert-Equal 'VALIDATION.PRIVACY_BOUNDARY_MISSING' $boundaryVerdict.reasonCode `
        'the request must declare the private-external boundary'

    $tooling = Copy-Request -Request $one
    $tooling.tooling.provider.version = '~> 4.0'
    $toolingWorkspace = New-PrivateWorkspace -Name 'tooling'
    $ownedWorkspaces.Add($toolingWorkspace)
    $toolingVerdict = Invoke-Admission -Request $tooling -WorkspacePath $toolingWorkspace
    Assert-Equal 'Rejected' $toolingVerdict.state 'a floating provider version is rejected'
    Assert-Equal 'VALIDATION.TOOLING_UNRESOLVED' $toolingVerdict.reasonCode `
        'unresolved provider identity is rejected before rendering'
    Assert-Equal $false $toolingVerdict.toolingResolved 'floating versions are unresolved'
    Assert-Equal $false $toolingVerdict.rendered 'unresolved tooling is not rendered'

    $contact = Copy-Request -Request $one
    $contact.azureContact = 'Plan'
    $contactWorkspace = New-PrivateWorkspace -Name 'contact'
    $ownedWorkspaces.Add($contactWorkspace)
    $contactVerdict = Invoke-Admission -Request $contact -WorkspacePath $contactWorkspace
    Assert-Equal 'Rejected' $contactVerdict.state 'a live plan request is rejected'
    Assert-Equal 'VALIDATION.AZURE_CONTACT_PROHIBITED' $contactVerdict.reasonCode `
        'Azure plan/apply is forbidden in this slice'
    Assert-Equal $false $contactVerdict.rendered 'Azure-contact requests are not rendered'

    $tags = Copy-Request -Request $one
    $tags.tags.PSObject.Properties.Remove('Purpose')
    $tagsWorkspace = New-PrivateWorkspace -Name 'tags'
    $ownedWorkspaces.Add($tagsWorkspace)
    $tagsVerdict = Invoke-Admission -Request $tags -WorkspacePath $tagsWorkspace
    Assert-Equal 'Rejected' $tagsVerdict.state 'missing required tags are rejected'
    Assert-Equal 'VALIDATION.TAGS_MISSING' $tagsVerdict.reasonCode `
        'missing tags use a stable reason'
    Assert-Equal $false $tagsVerdict.requiredTagsPresent 'missing tags are reported'
    Assert-Equal $false $tagsVerdict.rendered 'untagged plans are not rendered'

    $network = Copy-Request -Request $one
    $network.network.vmPublicIp = $true
    $networkWorkspace = New-PrivateWorkspace -Name 'network'
    $ownedWorkspaces.Add($networkWorkspace)
    $networkVerdict = Invoke-Admission -Request $network -WorkspacePath $networkWorkspace
    Assert-Equal 'Rejected' $networkVerdict.state 'a VM public IP is rejected'
    Assert-Equal 'VALIDATION.NETWORK_UNSAFE' $networkVerdict.reasonCode `
        'unsafe network declarations use a stable reason'
    Assert-Equal $false $networkVerdict.rendered 'unsafe networks are not rendered'

    $peering = Copy-Request -Request $one
    $peering.network.peering.allowGatewayTransit = $true
    $peeringWorkspace = New-PrivateWorkspace -Name 'peering'
    $ownedWorkspaces.Add($peeringWorkspace)
    $peeringVerdict = Invoke-Admission -Request $peering -WorkspacePath $peeringWorkspace
    Assert-Equal 'Rejected' $peeringVerdict.state 'transitive peering is rejected'
    Assert-Equal 'VALIDATION.NETWORK_UNSAFE' $peeringVerdict.reasonCode `
        'transitive peering is an unsafe network declaration'

    $nat = Copy-Request -Request $one
    $nat.network.natPublicIpSku = 'Basic'
    $natWorkspace = New-PrivateWorkspace -Name 'nat'
    $ownedWorkspaces.Add($natWorkspace)
    $natVerdict = Invoke-Admission -Request $nat -WorkspacePath $natWorkspace
    Assert-Equal 'Rejected' $natVerdict.state 'a Basic NAT public IP is rejected'
    Assert-Equal 'VALIDATION.NETWORK_UNSAFE' $natVerdict.reasonCode `
        'NAT must use a Standard public IP'

    $disk = Copy-Request -Request $one
    $disk.clients[0].diskType = 'Premium_LRS'
    $diskWorkspace = New-PrivateWorkspace -Name 'disk'
    $ownedWorkspaces.Add($diskWorkspace)
    $diskVerdict = Invoke-Admission -Request $disk -WorkspacePath $diskWorkspace
    Assert-Equal 'Rejected' $diskVerdict.state 'Premium SSD is rejected'
    Assert-Equal 'VALIDATION.DISK_UNSAFE' $diskVerdict.reasonCode `
        'unsafe disks use a stable reason'

    $image = Copy-Request -Request $one
    $image.clients[0].securityType = 'Standard'
    $image.clients[0].secureBoot = $false
    $image.clients[0].vtpm = $false
    $imageWorkspace = New-PrivateWorkspace -Name 'image'
    $ownedWorkspaces.Add($imageWorkspace)
    $imageVerdict = Invoke-Admission -Request $image -WorkspacePath $imageWorkspace
    Assert-Equal 'Rejected' $imageVerdict.state `
        'a claiming Windows 11 VM without Trusted Launch is rejected'
    Assert-Equal 'VALIDATION.SECURITY_UNSAFE' $imageVerdict.reasonCode `
        'unsafe claiming security uses a stable reason'
    Assert-Equal $false $imageVerdict.rendered 'unsafe claiming VMs are not rendered'

    $sku = Copy-Request -Request $one
    $sku.clients[0].sku = 'Standard_D8s_v5'
    $skuWorkspace = New-PrivateWorkspace -Name 'sku'
    $ownedWorkspaces.Add($skuWorkspace)
    $skuVerdict = Invoke-Admission -Request $sku -WorkspacePath $skuWorkspace
    Assert-Equal 'Rejected' $skuVerdict.state 'an oversized SKU is rejected'
    Assert-Equal 'VALIDATION.PLAN_UNSAFE' $skuVerdict.reasonCode `
        'non-allowlisted SKUs are unsafe plans'

    $claimingDiag = Copy-Request -Request $diagnostic
    $claimingDiag.clients[1].claiming = $true
    $claimingDiagWorkspace = New-PrivateWorkspace -Name 'claiming-diag'
    $ownedWorkspaces.Add($claimingDiagWorkspace)
    $claimingDiagVerdict = Invoke-Admission -Request $claimingDiag `
        -WorkspacePath $claimingDiagWorkspace
    Assert-Equal 'Rejected' $claimingDiagVerdict.state `
        'a claiming non-Trusted-Launch diagnostic VM is rejected'
    Assert-Equal 'VALIDATION.SECURITY_UNSAFE' $claimingDiagVerdict.reasonCode `
        'diagnostic VMs cannot become claiming evidence'

    $publicFiles = @(
        Get-ChildItem -LiteralPath (Join-Path $repositoryRoot $policy.templateRootRelativePath) -Recurse -File
        Get-Item -LiteralPath $oneClientPath
        Get-Item -LiteralPath $fourClientPath
        Get-Item -LiteralPath $diagnosticPath
    )
    foreach ($file in $publicFiles) {
        $text = [System.IO.File]::ReadAllText($file.FullName)
        Assert-Equal $false ($text -match '/subscriptions/') `
            "$($file.Name) is free of Azure subscription identifiers"
        Assert-Equal $false ($text -match '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+') `
            "$($file.Name) is free of local profile paths"
        Assert-Equal $false ($text -match '(?i)\.terraform[/\\]') `
            "$($file.Name) does not contain a private Terraform cache path"
    }
}
finally {
    foreach ($workspace in $ownedWorkspaces) {
        Remove-PrivateWorkspace -Path $workspace
    }
}

Write-Output 'PASS: offline Azure validation admission enforces the public/private boundary.'
