[CmdletBinding()]
param(
    [Parameter()]
    [string] $OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts/WIN-PCInfo.ps1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TextCanonicalization.ps1')
$sourcePaths = @(
    'src/ApplicationHeader.ps1'
    'src/Contracts.ps1'
    'src/ContractValidator.ps1'
    'src/RuntimeCompatibility.ps1'
    'src/Preparation.ps1'
    'src/ProcessSupervisor.ps1'
    'src/FirmwareReadiness.ps1'
    'src/PrivilegedCollectionPlan.ps1'
    'src/SystemCollectionPlan.ps1'
    'src/IdentityEnrollment.ps1'
    'src/AdministratorExposure.ps1'
    'src/EffectivePolicy.ps1'
    'src/ResourceDependencies.ps1'
    'src/NetworkTopology.ps1'
    'src/SoftwareInventory.ps1'
    'src/SoftwareRecognition.ps1'
    'src/EvidenceWorkspace.ps1'
    'src/RecipientSharing.ps1'
    'src/ProtectedPackage.ps1'
    'src/DeviceReadiness.ps1'
    'src/RunLifecycle.ps1'
    'src/LaunchEngine.ps1'
    'src/EntryAdapters.ps1'
    'src/ApplicationMain.ps1'
)

function Get-Sha256Hex {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

$releaseDefinitionPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1.json'
$capabilityLedgerPath = Join-Path $repositoryRoot 'docs/spec/capability-ledger.json'
$preparationPlanPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-preparation-plan.json'
$assessmentContractSetPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-contract-set.json'
$assessmentRecordSchemaPath = Join-Path $repositoryRoot 'schemas/assessment-record.schema.json'
$approvedCollectorCatalogPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-approved-collectors.json'
$approvedCollectorCatalogSchemaPath = Join-Path $repositoryRoot 'schemas/approved-collector-catalog.schema.json'
$runLifecyclePolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-run-lifecycle.json'
$runLifecycleSchemaPath = Join-Path $repositoryRoot 'schemas/run-lifecycle.schema.json'
$privilegedCollectionPlanPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-privileged-collection-plan.json'
$privilegedCollectionPlanSchemaPath = Join-Path $repositoryRoot 'schemas/privileged-collection-plan.schema.json'
$systemCollectionPlanPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-system-collection-plan.json'
$systemCollectionPlanSchemaPath = Join-Path $repositoryRoot 'schemas/system-collection-plan.schema.json'
$evidenceWorkspacePolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-evidence-workspace.json'
$evidenceWorkspaceSchemaPath = Join-Path $repositoryRoot 'schemas/evidence-workspace.schema.json'
$runRecoveryJournalSchemaPath = Join-Path $repositoryRoot 'schemas/run-recovery-journal.schema.json'
$protectedPackagePolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-protected-package.json'
$protectedPackageSchemaPath = Join-Path $repositoryRoot 'schemas/protected-package.schema.json'
$deviceReadinessPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-device-readiness.json'
$deviceReadinessSchemaPath = Join-Path $repositoryRoot 'schemas/device-readiness.schema.json'
$firmwareReadinessPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-firmware-readiness.json'
$firmwareReadinessSchemaPath = Join-Path $repositoryRoot 'schemas/firmware-readiness.schema.json'
$identityEnrollmentPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-identity-enrollment.json'
$identityEnrollmentSchemaPath = Join-Path $repositoryRoot 'schemas/identity-enrollment.schema.json'
$administratorExposurePolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-administrator-exposure.json'
$administratorExposureSchemaPath = Join-Path $repositoryRoot 'schemas/administrator-exposure.schema.json'
$effectivePolicyPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-effective-policy.json'
$effectivePolicySchemaPath = Join-Path $repositoryRoot 'schemas/effective-policy.schema.json'
$resourceDependenciesPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-resource-dependencies.json'
$resourceDependenciesSchemaPath = Join-Path $repositoryRoot 'schemas/resource-dependencies.schema.json'
$networkTopologyPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-network-topology.json'
$networkTopologySchemaPath = Join-Path $repositoryRoot 'schemas/network-topology.schema.json'
$softwareInventoryPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-software-inventory.json'
$softwareInventorySchemaPath = Join-Path $repositoryRoot 'schemas/software-inventory.schema.json'
$softwareRecognitionCatalogPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-software-recognition-catalog.json'
$softwareRecognitionCatalogSchemaPath = Join-Path $repositoryRoot 'schemas/software-recognition-catalog.schema.json'
$protectedPackageEnvelopeSchemaPath = Join-Path $repositoryRoot 'schemas/protected-package-envelope.schema.json'
$assessmentPackageManifestSchemaPath = Join-Path $repositoryRoot 'schemas/assessment-package-manifest.schema.json'
$recipientSharingPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-recipient-sharing.json'
$recipientProfileSchemaPath = Join-Path $repositoryRoot 'schemas/recipient-profile.schema.json'
$recipientSharingSchemaPath = Join-Path $repositoryRoot 'schemas/recipient-sharing.schema.json'
foreach ($requiredDefinitionPath in @(
    $releaseDefinitionPath, $capabilityLedgerPath, $preparationPlanPath,
    $assessmentContractSetPath, $assessmentRecordSchemaPath,
    $approvedCollectorCatalogPath, $approvedCollectorCatalogSchemaPath,
    $runLifecyclePolicyPath, $runLifecycleSchemaPath,
    $privilegedCollectionPlanPolicyPath, $privilegedCollectionPlanSchemaPath,
    $systemCollectionPlanPolicyPath, $systemCollectionPlanSchemaPath,
    $evidenceWorkspacePolicyPath, $evidenceWorkspaceSchemaPath,
    $runRecoveryJournalSchemaPath, $protectedPackagePolicyPath, $protectedPackageSchemaPath,
    $protectedPackageEnvelopeSchemaPath, $assessmentPackageManifestSchemaPath,
    $recipientSharingPolicyPath, $recipientProfileSchemaPath, $recipientSharingSchemaPath,
    $deviceReadinessPolicyPath, $deviceReadinessSchemaPath,
    $firmwareReadinessPolicyPath, $firmwareReadinessSchemaPath,
    $identityEnrollmentPolicyPath, $identityEnrollmentSchemaPath,
    $administratorExposurePolicyPath, $administratorExposureSchemaPath,
    $effectivePolicyPolicyPath, $effectivePolicySchemaPath,
    $resourceDependenciesPolicyPath, $resourceDependenciesSchemaPath,
    $networkTopologyPolicyPath, $networkTopologySchemaPath,
    $softwareInventoryPolicyPath, $softwareInventorySchemaPath,
    $softwareRecognitionCatalogPath, $softwareRecognitionCatalogSchemaPath
)) {
    if (-not (Test-Path -LiteralPath $requiredDefinitionPath -PathType Leaf)) {
        throw "Preparation definition input is missing: $requiredDefinitionPath"
    }
}
$releaseDefinition = Get-Content -LiteralPath $releaseDefinitionPath -Raw | ConvertFrom-Json -Depth 30
$capabilityLedger = Get-Content -LiteralPath $capabilityLedgerPath -Raw | ConvertFrom-Json -Depth 30
$preparationPlan = Get-Content -LiteralPath $preparationPlanPath -Raw | ConvertFrom-Json -Depth 30
$assessmentContractSetBytes = Get-Utf8LfBytes -LiteralPath $assessmentContractSetPath
$assessmentRecordSchemaBytes = Get-Utf8LfBytes -LiteralPath $assessmentRecordSchemaPath
$assessmentContractSetBase64 = [System.Convert]::ToBase64String($assessmentContractSetBytes)
$assessmentRecordSchemaBase64 = [System.Convert]::ToBase64String($assessmentRecordSchemaBytes)
$assessmentContractSetDigest = Get-Sha256Hex -Bytes $assessmentContractSetBytes
$assessmentRecordSchemaDigest = Get-Sha256Hex -Bytes $assessmentRecordSchemaBytes
$approvedCollectorCatalogBytes = Get-Utf8LfBytes -LiteralPath $approvedCollectorCatalogPath
$approvedCollectorCatalogBase64 = [System.Convert]::ToBase64String($approvedCollectorCatalogBytes)
$approvedCollectorCatalogDigest = Get-Sha256Hex -Bytes $approvedCollectorCatalogBytes
$approvedCollectorCatalogJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $approvedCollectorCatalogBytes
)
$runLifecyclePolicyBytes = Get-Utf8LfBytes -LiteralPath $runLifecyclePolicyPath
$runLifecyclePolicyBase64 = [System.Convert]::ToBase64String($runLifecyclePolicyBytes)
$runLifecyclePolicyDigest = Get-Sha256Hex -Bytes $runLifecyclePolicyBytes
$runLifecyclePolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $runLifecyclePolicyBytes
)
$privilegedCollectionPlanPolicyBytes = Get-Utf8LfBytes -LiteralPath $privilegedCollectionPlanPolicyPath
$privilegedCollectionPlanPolicyBase64 = [System.Convert]::ToBase64String($privilegedCollectionPlanPolicyBytes)
$privilegedCollectionPlanPolicyDigest = Get-Sha256Hex -Bytes $privilegedCollectionPlanPolicyBytes
$privilegedCollectionPlanPolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $privilegedCollectionPlanPolicyBytes
)
$systemCollectionPlanPolicyBytes = Get-Utf8LfBytes -LiteralPath $systemCollectionPlanPolicyPath
$systemCollectionPlanPolicyBase64 = [System.Convert]::ToBase64String($systemCollectionPlanPolicyBytes)
$systemCollectionPlanPolicyDigest = Get-Sha256Hex -Bytes $systemCollectionPlanPolicyBytes
$systemCollectionPlanPolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $systemCollectionPlanPolicyBytes
)
$evidenceWorkspacePolicyBytes = Get-Utf8LfBytes -LiteralPath $evidenceWorkspacePolicyPath
$evidenceWorkspacePolicyBase64 = [System.Convert]::ToBase64String($evidenceWorkspacePolicyBytes)
$evidenceWorkspacePolicyDigest = Get-Sha256Hex -Bytes $evidenceWorkspacePolicyBytes
$evidenceWorkspacePolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $evidenceWorkspacePolicyBytes
)
$runRecoveryJournalSchemaBytes = Get-Utf8LfBytes -LiteralPath $runRecoveryJournalSchemaPath
$runRecoveryJournalSchemaBase64 = [System.Convert]::ToBase64String($runRecoveryJournalSchemaBytes)
$runRecoveryJournalSchemaDigest = Get-Sha256Hex -Bytes $runRecoveryJournalSchemaBytes
$protectedPackagePolicyBytes = Get-Utf8LfBytes -LiteralPath $protectedPackagePolicyPath
$protectedPackagePolicyBase64 = [System.Convert]::ToBase64String($protectedPackagePolicyBytes)
$protectedPackagePolicyDigest = Get-Sha256Hex -Bytes $protectedPackagePolicyBytes
$protectedPackagePolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString($protectedPackagePolicyBytes)
$protectedPackageEnvelopeSchemaBytes = Get-Utf8LfBytes -LiteralPath $protectedPackageEnvelopeSchemaPath
$protectedPackageEnvelopeSchemaBase64 = [System.Convert]::ToBase64String($protectedPackageEnvelopeSchemaBytes)
$protectedPackageEnvelopeSchemaDigest = Get-Sha256Hex -Bytes $protectedPackageEnvelopeSchemaBytes
$assessmentPackageManifestSchemaBytes = Get-Utf8LfBytes -LiteralPath $assessmentPackageManifestSchemaPath
$assessmentPackageManifestSchemaBase64 = [System.Convert]::ToBase64String($assessmentPackageManifestSchemaBytes)
$assessmentPackageManifestSchemaDigest = Get-Sha256Hex -Bytes $assessmentPackageManifestSchemaBytes
$recipientSharingPolicyBytes = Get-Utf8LfBytes -LiteralPath $recipientSharingPolicyPath
$recipientSharingPolicyBase64 = [System.Convert]::ToBase64String($recipientSharingPolicyBytes)
$recipientSharingPolicyDigest = Get-Sha256Hex -Bytes $recipientSharingPolicyBytes
$recipientSharingPolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $recipientSharingPolicyBytes
)
$recipientProfileSchemaBytes = Get-Utf8LfBytes -LiteralPath $recipientProfileSchemaPath
$recipientProfileSchemaBase64 = [System.Convert]::ToBase64String($recipientProfileSchemaBytes)
$recipientProfileSchemaDigest = Get-Sha256Hex -Bytes $recipientProfileSchemaBytes
$deviceReadinessPolicyBytes = Get-Utf8LfBytes -LiteralPath $deviceReadinessPolicyPath
$deviceReadinessPolicyBase64 = [System.Convert]::ToBase64String($deviceReadinessPolicyBytes)
$deviceReadinessPolicyDigest = Get-Sha256Hex -Bytes $deviceReadinessPolicyBytes
$deviceReadinessPolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString($deviceReadinessPolicyBytes)
$firmwareReadinessPolicyBytes = Get-Utf8LfBytes -LiteralPath $firmwareReadinessPolicyPath
$firmwareReadinessPolicyBase64 = [System.Convert]::ToBase64String($firmwareReadinessPolicyBytes)
$firmwareReadinessPolicyDigest = Get-Sha256Hex -Bytes $firmwareReadinessPolicyBytes
$firmwareReadinessPolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $firmwareReadinessPolicyBytes
)
$identityEnrollmentPolicyBytes = Get-Utf8LfBytes -LiteralPath $identityEnrollmentPolicyPath
$identityEnrollmentPolicyBase64 = [System.Convert]::ToBase64String($identityEnrollmentPolicyBytes)
$identityEnrollmentPolicyDigest = Get-Sha256Hex -Bytes $identityEnrollmentPolicyBytes
$identityEnrollmentPolicyJson = [System.Text.UTF8Encoding]::new($false, $true).GetString(
    $identityEnrollmentPolicyBytes
)
$administratorExposurePolicyBytes = Get-Utf8LfBytes -LiteralPath $administratorExposurePolicyPath
$administratorExposurePolicyBase64 = [Convert]::ToBase64String($administratorExposurePolicyBytes)
$administratorExposurePolicyDigest = Get-Sha256Hex -Bytes $administratorExposurePolicyBytes
$administratorExposurePolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $administratorExposurePolicyBytes
)
$effectivePolicyPolicyBytes = Get-Utf8LfBytes -LiteralPath $effectivePolicyPolicyPath
$effectivePolicyPolicyBase64 = [Convert]::ToBase64String($effectivePolicyPolicyBytes)
$effectivePolicyPolicyDigest = Get-Sha256Hex -Bytes $effectivePolicyPolicyBytes
$resourceDependenciesPolicyBytes = Get-Utf8LfBytes -LiteralPath $resourceDependenciesPolicyPath
$resourceDependenciesPolicyBase64 = [System.Convert]::ToBase64String($resourceDependenciesPolicyBytes)
$resourceDependenciesPolicyDigest = Get-Sha256Hex -Bytes $resourceDependenciesPolicyBytes
$resourceDependenciesPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $resourceDependenciesPolicyBytes
)
$networkTopologyPolicyBytes = Get-Utf8LfBytes -LiteralPath $networkTopologyPolicyPath
$networkTopologyPolicyBase64 = [Convert]::ToBase64String($networkTopologyPolicyBytes)
$networkTopologyPolicyDigest = Get-Sha256Hex -Bytes $networkTopologyPolicyBytes
$networkTopologyPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $networkTopologyPolicyBytes
)
$softwareInventoryPolicyBytes = Get-Utf8LfBytes -LiteralPath $softwareInventoryPolicyPath
$softwareInventoryPolicyBase64 = [Convert]::ToBase64String($softwareInventoryPolicyBytes)
$softwareInventoryPolicyDigest = Get-Sha256Hex -Bytes $softwareInventoryPolicyBytes
$softwareInventoryPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $softwareInventoryPolicyBytes
)
$softwareRecognitionCatalogBytes = Get-Utf8LfBytes -LiteralPath $softwareRecognitionCatalogPath
$softwareRecognitionCatalogBase64 = [Convert]::ToBase64String($softwareRecognitionCatalogBytes)
$softwareRecognitionCatalogDigest = Get-Sha256Hex -Bytes $softwareRecognitionCatalogBytes
$softwareRecognitionCatalogJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $softwareRecognitionCatalogBytes
)
$softwareRecognitionSchemaBytes = Get-Utf8LfBytes `
    -LiteralPath $softwareRecognitionCatalogSchemaPath
$softwareRecognitionSchemaBase64 = [Convert]::ToBase64String($softwareRecognitionSchemaBytes)
$softwareRecognitionSchemaDigest = Get-Sha256Hex -Bytes $softwareRecognitionSchemaBytes
$effectivePolicyPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $effectivePolicyPolicyBytes
)
if (-not (Test-Json -Json $approvedCollectorCatalogJson -SchemaFile $approvedCollectorCatalogSchemaPath)) {
    throw 'The approved collector catalog does not satisfy its release schema.'
}
if (-not (Test-Json -Json $runLifecyclePolicyJson -SchemaFile $runLifecycleSchemaPath)) {
    throw 'The run lifecycle policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $privilegedCollectionPlanPolicyJson -SchemaFile $privilegedCollectionPlanSchemaPath)) {
    throw 'The Privileged Collection Plan policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $systemCollectionPlanPolicyJson -SchemaFile $systemCollectionPlanSchemaPath)) {
    throw 'The SYSTEM Collection sub-plan policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $evidenceWorkspacePolicyJson -SchemaFile $evidenceWorkspaceSchemaPath)) {
    throw 'The Evidence Workspace policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $protectedPackagePolicyJson -SchemaFile $protectedPackageSchemaPath)) {
    throw 'The Protected Package policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $recipientSharingPolicyJson -SchemaFile $recipientSharingSchemaPath)) {
    throw 'The Recipient Sharing policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $deviceReadinessPolicyJson -SchemaFile $deviceReadinessSchemaPath)) {
    throw 'The Device Readiness policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $firmwareReadinessPolicyJson -SchemaFile $firmwareReadinessSchemaPath)) {
    throw 'The Firmware Readiness policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $identityEnrollmentPolicyJson -SchemaFile $identityEnrollmentSchemaPath)) {
    throw 'The Identity and Enrollment policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $administratorExposurePolicyJson -SchemaFile $administratorExposureSchemaPath)) {
    throw 'The Administrator Exposure policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $effectivePolicyPolicyJson -SchemaFile $effectivePolicySchemaPath)) {
    throw 'The Effective Policy policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $resourceDependenciesPolicyJson -SchemaFile $resourceDependenciesSchemaPath)) {
    throw 'The Resource Dependencies policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $networkTopologyPolicyJson -SchemaFile $networkTopologySchemaPath)) {
    throw 'The Network Topology policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $softwareInventoryPolicyJson -SchemaFile $softwareInventorySchemaPath)) {
    throw 'The Software Inventory policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $softwareRecognitionCatalogJson -SchemaFile $softwareRecognitionCatalogSchemaPath)) {
    throw 'The Software Recognition Catalog does not satisfy its release schema.'
}
$selectedIds = @($releaseDefinition.profile.selectedCapabilityIds)
$releaseEnabledIds = @($releaseDefinition.releaseEnabledCapabilityIds)
$capabilitiesById = @{}
foreach ($capability in @($capabilityLedger.capabilities)) { $capabilitiesById[[string] $capability.id] = $capability }
if (@($releaseEnabledIds | Where-Object { -not $capabilitiesById.ContainsKey([string] $_) }).Count -gt 0) {
    throw 'The release definition refers to an unknown capability.'
}
$operationCapabilityIds = @($preparationPlan.operations.capabilityId)
if ($operationCapabilityIds.Count -ne $releaseEnabledIds.Count -or
    @($operationCapabilityIds | Sort-Object -Unique).Count -ne $releaseEnabledIds.Count -or
    @($releaseEnabledIds | Where-Object { $_ -notin $operationCapabilityIds }).Count -gt 0) {
    throw 'The preparation operation manifest must resolve every release-enabled capability exactly once.'
}
$dependencyIds = @($selectedIds | ForEach-Object { @($capabilitiesById[[string] $_].dependsOnCapabilityIds) } |
    Where-Object { $_ -notin $selectedIds } | Sort-Object -Unique)
$resolvedCapabilities = foreach ($capabilityId in $releaseEnabledIds) {
    $disposition = if ($capabilityId -in $selectedIds) { 'Selected' }
        elseif ($capabilityId -in $dependencyIds) { 'DependencyAdded' }
        else { 'ReleaseEnabledProductCapability' }
    [pscustomobject][ordered]@{
        id = [string] $capabilityId
        name = [string] $capabilitiesById[[string] $capabilityId].name
        disposition = $disposition
        dependsOnCapabilityIds = @($capabilitiesById[[string] $capabilityId].dependsOnCapabilityIds)
    }
}
$applicationResourcePaths = @($sourcePaths) + @(
    'build/Build.ps1'
    'build/TextCanonicalization.ps1'
    'schemas/assessment-run-request.schema.json'
    'schemas/preparation-plan.schema.json'
    'schemas/assessment-record.schema.json'
    'schemas/assessment-contract-set.schema.json'
    'schemas/approved-collector-catalog.schema.json'
    'schemas/run-lifecycle.schema.json'
    'schemas/privileged-collection-plan.schema.json'
    'schemas/system-collection-plan.schema.json'
    'schemas/evidence-workspace.schema.json'
    'schemas/run-recovery-journal.schema.json'
    'schemas/protected-package.schema.json'
    'schemas/protected-package-envelope.schema.json'
    'schemas/assessment-package-manifest.schema.json'
    'schemas/recipient-profile.schema.json'
    'schemas/recipient-sharing.schema.json'
    'schemas/device-readiness.schema.json'
    'schemas/firmware-readiness.schema.json'
    'schemas/identity-enrollment.schema.json'
    'schemas/administrator-exposure.schema.json'
    'schemas/effective-policy.schema.json'
    'schemas/resource-dependencies.schema.json'
    'schemas/network-topology.schema.json'
    'schemas/software-inventory.schema.json'
    'schemas/software-recognition-catalog.schema.json'
    'docs/spec/releases/2.0.0-preview.1-contract-set.json'
    'docs/spec/releases/2.0.0-preview.1-approved-collectors.json'
    'docs/spec/releases/2.0.0-preview.1-run-lifecycle.json'
    'docs/spec/releases/2.0.0-preview.1-privileged-collection-plan.json'
    'docs/spec/releases/2.0.0-preview.1-system-collection-plan.json'
    'docs/spec/releases/2.0.0-preview.1-evidence-workspace.json'
    'docs/spec/releases/2.0.0-preview.1-protected-package.json'
    'docs/spec/releases/2.0.0-preview.1-recipient-sharing.json'
    'docs/spec/releases/2.0.0-preview.1-device-readiness.json'
    'docs/spec/releases/2.0.0-preview.1-firmware-readiness.json'
    'docs/spec/releases/2.0.0-preview.1-identity-enrollment.json'
    'docs/spec/releases/2.0.0-preview.1-administrator-exposure.json'
    'docs/spec/releases/2.0.0-preview.1-effective-policy.json'
    'docs/spec/releases/2.0.0-preview.1-resource-dependencies.json'
    'docs/spec/releases/2.0.0-preview.1-network-topology.json'
    'docs/spec/releases/2.0.0-preview.1-software-inventory.json'
    'docs/spec/releases/2.0.0-preview.1-software-recognition-catalog.json'
)
$applicationResources = @(
    foreach ($path in $applicationResourcePaths) {
        # Git may materialize text as LF or CRLF. The application manifest binds
        # the reviewed logical text, while the generated signing representation
        # remains the separately fixed UTF-8-BOM/CRLF output below.
        $bytes = Get-Utf8LfBytes -LiteralPath (Join-Path $repositoryRoot $path)
        [pscustomobject][ordered]@{ path = $path; sha256 = Get-Sha256Hex -Bytes $bytes }
    }
)
$applicationManifestBody = [pscustomobject][ordered]@{
    contractVersion = '1.0.0'
    resources = $applicationResources
}
$applicationManifestBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
    ($applicationManifestBody | ConvertTo-Json -Compress -Depth 30)
)
$preparationDefinition = [pscustomobject][ordered]@{
    contractVersion = '1.0.0'
    release = [string] $releaseDefinition.release
    profileId = [string] $releaseDefinition.profile.id
    profileName = [string] $releaseDefinition.profile.name
    capabilities = @($resolvedCapabilities)
    operations = @($preparationPlan.operations)
    deviceReadiness = ($deviceReadinessPolicyJson | ConvertFrom-Json -Depth 20)
    firmwareReadiness = ($firmwareReadinessPolicyJson | ConvertFrom-Json -Depth 20)
    identityEnrollment = ($identityEnrollmentPolicyJson | ConvertFrom-Json -Depth 20)
    administratorExposure = ($administratorExposurePolicyJson | ConvertFrom-Json -Depth 20)
    effectivePolicy = ($effectivePolicyPolicyJson | ConvertFrom-Json -Depth 20)
    resourceDependencies = ($resourceDependenciesPolicyJson | ConvertFrom-Json -Depth 20)
    networkTopology = ($networkTopologyPolicyJson | ConvertFrom-Json -Depth 20)
    softwareInventory = ($softwareInventoryPolicyJson | ConvertFrom-Json -Depth 20)
    requiredFreeDiskMiB = [int] $preparationPlan.requiredFreeDiskMiB
    governingResources = @(
        foreach ($path in @(
            'docs/spec/releases/2.0.0-preview.1.json'
            'docs/spec/capability-ledger.json'
            'docs/spec/releases/2.0.0-preview.1-preparation-plan.json'
        )) {
            $bytes = Get-Utf8LfBytes -LiteralPath (Join-Path $repositoryRoot $path)
            [pscustomobject][ordered]@{ path = $path; sha256 = Get-Sha256Hex -Bytes $bytes }
        }
    )
    applicationManifest = [pscustomobject][ordered]@{
        contractVersion = $applicationManifestBody.contractVersion
        resources = $applicationManifestBody.resources
        sha256 = Get-Sha256Hex -Bytes $applicationManifestBytes
    }
}
$preparationJson = $preparationDefinition | ConvertTo-Json -Compress -Depth 30
$preparationBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($preparationJson)
$preparationBase64 = [System.Convert]::ToBase64String($preparationBytes)
$preparationDigest = Get-Sha256Hex -Bytes $preparationBytes

$sourceFiles = foreach ($relativePath in $sourcePaths) {
    $literalPath = Join-Path $repositoryRoot $relativePath
    if (-not (Test-Path -LiteralPath $literalPath -PathType Leaf)) {
        throw "Build input is missing: $relativePath"
    }
    $bytes = [System.IO.File]::ReadAllBytes($literalPath)
    [pscustomobject][ordered]@{
        path = $relativePath
        literalPath = $literalPath
        bytes = $bytes
        text = [System.IO.File]::ReadAllText($literalPath)
    }
}

$sourceInputs = foreach ($sourceFile in $sourceFiles) {
    [pscustomobject][ordered]@{
        path = $sourceFile.path
        sha256 = Get-Sha256Hex -Bytes $sourceFile.bytes
        byteLength = $sourceFile.bytes.Length
    }
}

$sections = foreach ($sourceFile in $sourceFiles) {
    $normalizedSource = $sourceFile.text -replace "`r`n", "`n" -replace "`r", "`n"
    if ($sourceFile.path -eq 'src/Preparation.ps1') {
        $normalizedSource = $normalizedSource.Replace('__PREPARATION_DEFINITION_BASE64__', $preparationBase64)
        $normalizedSource = $normalizedSource.Replace('__PREPARATION_DEFINITION_SHA256__', $preparationDigest)
    }
    if ($sourceFile.path -eq 'src/ContractValidator.ps1') {
        $normalizedSource = $normalizedSource.Replace('__ASSESSMENT_CONTRACT_SET_BASE64__', $assessmentContractSetBase64)
        $normalizedSource = $normalizedSource.Replace('__ASSESSMENT_CONTRACT_SET_SHA256__', $assessmentContractSetDigest)
        $normalizedSource = $normalizedSource.Replace('__ASSESSMENT_RECORD_SCHEMA_BASE64__', $assessmentRecordSchemaBase64)
        $normalizedSource = $normalizedSource.Replace('__ASSESSMENT_RECORD_SCHEMA_SHA256__', $assessmentRecordSchemaDigest)
    }
    if ($sourceFile.path -eq 'src/ProcessSupervisor.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__APPROVED_COLLECTOR_CATALOG_BASE64__', $approvedCollectorCatalogBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__APPROVED_COLLECTOR_CATALOG_SHA256__', $approvedCollectorCatalogDigest
        )
    }
    if ($sourceFile.path -eq 'src/RunLifecycle.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__RUN_LIFECYCLE_POLICY_BASE64__', $runLifecyclePolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__RUN_LIFECYCLE_POLICY_SHA256__', $runLifecyclePolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/PrivilegedCollectionPlan.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__PRIVILEGED_COLLECTION_PLAN_POLICY_BASE64__', $privilegedCollectionPlanPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__PRIVILEGED_COLLECTION_PLAN_POLICY_SHA256__', $privilegedCollectionPlanPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/SystemCollectionPlan.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__SYSTEM_COLLECTION_PLAN_POLICY_BASE64__', $systemCollectionPlanPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__SYSTEM_COLLECTION_PLAN_POLICY_SHA256__', $systemCollectionPlanPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/EvidenceWorkspace.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__EVIDENCE_WORKSPACE_POLICY_BASE64__', $evidenceWorkspacePolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__EVIDENCE_WORKSPACE_POLICY_SHA256__', $evidenceWorkspacePolicyDigest
        )
        $normalizedSource = $normalizedSource.Replace(
            '__RUN_RECOVERY_JOURNAL_SCHEMA_BASE64__', $runRecoveryJournalSchemaBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__RUN_RECOVERY_JOURNAL_SCHEMA_SHA256__', $runRecoveryJournalSchemaDigest
        )
    }
    if ($sourceFile.path -eq 'src/ProtectedPackage.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__PROTECTED_PACKAGE_POLICY_BASE64__', $protectedPackagePolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__PROTECTED_PACKAGE_POLICY_SHA256__', $protectedPackagePolicyDigest
        )
        $normalizedSource = $normalizedSource.Replace(
            '__PROTECTED_PACKAGE_ENVELOPE_SCHEMA_BASE64__', $protectedPackageEnvelopeSchemaBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__PROTECTED_PACKAGE_ENVELOPE_SCHEMA_SHA256__', $protectedPackageEnvelopeSchemaDigest
        )
        $normalizedSource = $normalizedSource.Replace(
            '__ASSESSMENT_PACKAGE_MANIFEST_SCHEMA_BASE64__', $assessmentPackageManifestSchemaBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__ASSESSMENT_PACKAGE_MANIFEST_SCHEMA_SHA256__', $assessmentPackageManifestSchemaDigest
        )
    }
    if ($sourceFile.path -eq 'src/RecipientSharing.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__RECIPIENT_SHARING_POLICY_BASE64__', $recipientSharingPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__RECIPIENT_SHARING_POLICY_SHA256__', $recipientSharingPolicyDigest
        )
        $normalizedSource = $normalizedSource.Replace(
            '__RECIPIENT_PROFILE_SCHEMA_BASE64__', $recipientProfileSchemaBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__RECIPIENT_PROFILE_SCHEMA_SHA256__', $recipientProfileSchemaDigest
        )
    }
    if ($sourceFile.path -eq 'src/DeviceReadiness.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__DEVICE_READINESS_POLICY_BASE64__', $deviceReadinessPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__DEVICE_READINESS_POLICY_SHA256__', $deviceReadinessPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/FirmwareReadiness.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__FIRMWARE_READINESS_POLICY_BASE64__', $firmwareReadinessPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__FIRMWARE_READINESS_POLICY_SHA256__', $firmwareReadinessPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/IdentityEnrollment.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__IDENTITY_ENROLLMENT_POLICY_BASE64__', $identityEnrollmentPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__IDENTITY_ENROLLMENT_POLICY_SHA256__', $identityEnrollmentPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/AdministratorExposure.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__ADMINISTRATOR_EXPOSURE_POLICY_BASE64__', $administratorExposurePolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__ADMINISTRATOR_EXPOSURE_POLICY_SHA256__', $administratorExposurePolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/EffectivePolicy.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__EFFECTIVE_POLICY_POLICY_BASE64__', $effectivePolicyPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__EFFECTIVE_POLICY_POLICY_SHA256__', $effectivePolicyPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/ResourceDependencies.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__RESOURCE_DEPENDENCIES_POLICY_BASE64__', $resourceDependenciesPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__RESOURCE_DEPENDENCIES_POLICY_SHA256__', $resourceDependenciesPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/NetworkTopology.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__NETWORK_TOPOLOGY_POLICY_BASE64__', $networkTopologyPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__NETWORK_TOPOLOGY_POLICY_SHA256__', $networkTopologyPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/SoftwareInventory.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__SOFTWARE_INVENTORY_POLICY_BASE64__', $softwareInventoryPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__SOFTWARE_INVENTORY_POLICY_SHA256__', $softwareInventoryPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/SoftwareRecognition.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__SOFTWARE_RECOGNITION_CATALOG_BASE64__', $softwareRecognitionCatalogBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__SOFTWARE_RECOGNITION_CATALOG_SHA256__', $softwareRecognitionCatalogDigest
        )
        $normalizedSource = $normalizedSource.Replace(
            '__SOFTWARE_RECOGNITION_SCHEMA_BASE64__', $softwareRecognitionSchemaBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__SOFTWARE_RECOGNITION_SCHEMA_SHA256__', $softwareRecognitionSchemaDigest
        )
    }
    "#region Generated from $($sourceFile.path)`n$($normalizedSource.TrimEnd("`n"))`n#endregion Generated from $($sourceFile.path)"
}

$generated = (@(
    '# This file is generated by build/Build.ps1. Do not edit it by hand.'
    '# Build format: WIN-PCInfo deterministic PowerShell application v1.'
    $sections
) -join "`n`n") -replace "`n", "`r`n"
$generated += "`r`n"

$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $resolvedOutput
$null = New-Item -ItemType Directory -Path $outputDirectory -Force

# The release signing contract requires UTF-8 with BOM and CRLF. Constructing the
# encoder explicitly avoids behavior changes between Windows PowerShell and pwsh.
$utf8WithBom = [System.Text.UTF8Encoding]::new($true)
[System.IO.File]::WriteAllText($resolvedOutput, $generated, $utf8WithBom)

$digest = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($resolvedOutput))
$buildToolPath = 'build/Build.ps1'
$buildToolDigest = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($PSCommandPath))

[pscustomobject]@{
    buildContract = 'win-pcinfo.build-evidence/1.0.0'
    outputPath = $resolvedOutput
    sha256 = $digest
    buildTool = [pscustomobject][ordered]@{
        path = $buildToolPath
        sha256 = $buildToolDigest
    }
    sourceInputs = $sourceInputs
    definitionInputs = @($preparationDefinition.governingResources)
    applicationManifest = $preparationDefinition.applicationManifest
    encoding = 'utf-8-bom'
    lineEndings = 'crlf'
}
