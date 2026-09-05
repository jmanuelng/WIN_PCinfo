[CmdletBinding()]
param(
    [Parameter()]
    [string] $OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts/WIN-PCInfo.ps1'),
    [Parameter()]
    [string] $SignedHelperPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TextCanonicalization.ps1')
. (Join-Path $PSScriptRoot 'DeterministicArchive.ps1')
. (Join-Path $PSScriptRoot 'PortableDistribution.ps1')
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
    'src/CertificateTrust.ps1'
    'src/MicrosoftConnectivity.ps1'
    'src/SoftwareRecognition.ps1'
    'src/CrossDomainGuidance.ps1'
    'src/EvidenceWorkspace.ps1'
    'src/RecipientSharing.ps1'
    'src/ProtectedPackage.ps1'
    'src/DeviceReadiness.ps1'
    'src/RunLifecycle.ps1'
    'src/LaunchEngine.ps1'
    'src/EntryAdapters.ps1'
    'src/ProductHelp.ps1'
    'src/PortableDistribution.ps1'
    'src/AttestedPreview.ps1'
    'src/AzureValidationAdmission.ps1'
    'src/AzureValidationRound.ps1'
    'src/ReleaseGates.ps1'
    'src/SigningBoundary.ps1'
    'src/PreviewQualification.ps1'
    'src/PreviewPublication.ps1'
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
$certificateTrustPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-certificate-trust.json'
$certificateTrustSchemaPath = Join-Path $repositoryRoot 'schemas/certificate-trust.schema.json'
$microsoftConnectivityPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-microsoft-connectivity.json'
$microsoftConnectivitySchemaPath = Join-Path $repositoryRoot 'schemas/microsoft-connectivity.schema.json'
$crossDomainGuidancePolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-cross-domain-guidance.json'
$crossDomainGuidanceSchemaPath = Join-Path $repositoryRoot 'schemas/cross-domain-guidance.schema.json'
$guidedRunwayPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-guided-runway.json'
$guidedRunwaySchemaPath = Join-Path $repositoryRoot 'schemas/guided-runway.schema.json'
$portableDistributionPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-portable-distribution.json'
$portableDistributionSchemaPath = Join-Path $repositoryRoot 'schemas/portable-distribution.schema.json'
$attestedPreviewPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-attested-preview.json'
$attestedPreviewSchemaPath = Join-Path $repositoryRoot 'schemas/attested-preview.schema.json'
$attestedPreviewAttestationSchemaPath = Join-Path $repositoryRoot 'schemas/attested-preview-attestation.schema.json'
$azureValidationAdmissionPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-azure-validation-admission.json'
$azureValidationAdmissionSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-admission.schema.json'
$azureValidationRoundRequestSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-round-request.schema.json'
$azureValidationAdmissionVerdictSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-admission-verdict.schema.json'
$azureValidationRoundPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-azure-validation-round.json'
$azureValidationRoundSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-round.schema.json'
$azureValidationRoundExecutionRequestSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-round-execution-request.schema.json'
$azureValidationRoundOutcomeSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-round-outcome.schema.json'
$releaseGatesPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-release-gates.json'
$releaseGatesSchemaPath = Join-Path $repositoryRoot 'schemas/release-gates.schema.json'
$signingBoundaryPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-signing-boundary.json'
$signingBoundarySchemaPath = Join-Path $repositoryRoot 'schemas/signing-boundary.schema.json'
$signingSessionRequestSchemaPath = Join-Path $repositoryRoot 'schemas/signing-session-request.schema.json'
$signingSessionResultSchemaPath = Join-Path $repositoryRoot 'schemas/signing-session-result.schema.json'
$previewQualificationPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-preview-qualification.json'
$previewQualificationSchemaPath = Join-Path $repositoryRoot 'schemas/preview-qualification.schema.json'
$previewQualificationRequestSchemaPath = Join-Path $repositoryRoot 'schemas/preview-qualification-request.schema.json'
$previewQualificationPacketSchemaPath = Join-Path $repositoryRoot 'schemas/preview-qualification-packet.schema.json'
$previewPublicationPolicyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-preview-publication.json'
$previewPublicationSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication.schema.json'
$previewPublicationRequestSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication-request.schema.json'
$previewPublicationPreviewSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication-preview.schema.json'
$previewPublicationResultSchemaPath = Join-Path $repositoryRoot 'schemas/preview-publication-result.schema.json'
$releaseEvidencePackSchemaPath = Join-Path $repositoryRoot 'schemas/release-evidence-pack.schema.json'
$releaseEvidenceManifestSchemaPath = Join-Path $repositoryRoot 'schemas/release-evidence-manifest.schema.json'
$previewCapabilityMatrixSchemaPath = Join-Path $repositoryRoot 'schemas/preview-capability-matrix.schema.json'
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
    $certificateTrustPolicyPath, $certificateTrustSchemaPath,
    $microsoftConnectivityPolicyPath, $microsoftConnectivitySchemaPath,
    $crossDomainGuidancePolicyPath, $crossDomainGuidanceSchemaPath,
    $guidedRunwayPolicyPath, $guidedRunwaySchemaPath,
    $portableDistributionPolicyPath, $portableDistributionSchemaPath,
    $attestedPreviewPolicyPath, $attestedPreviewSchemaPath,
    $attestedPreviewAttestationSchemaPath,
    $azureValidationAdmissionPolicyPath, $azureValidationAdmissionSchemaPath,
    $azureValidationRoundRequestSchemaPath, $azureValidationAdmissionVerdictSchemaPath,
    $azureValidationRoundPolicyPath, $azureValidationRoundSchemaPath,
    $azureValidationRoundExecutionRequestSchemaPath, $azureValidationRoundOutcomeSchemaPath,
    $releaseGatesPolicyPath, $releaseGatesSchemaPath,
    $signingBoundaryPolicyPath, $signingBoundarySchemaPath,
    $signingSessionRequestSchemaPath, $signingSessionResultSchemaPath,
    $previewQualificationPolicyPath, $previewQualificationSchemaPath,
    $previewQualificationRequestSchemaPath, $previewQualificationPacketSchemaPath,
    $previewPublicationPolicyPath, $previewPublicationSchemaPath,
    $previewPublicationRequestSchemaPath, $previewPublicationPreviewSchemaPath,
    $previewPublicationResultSchemaPath,
    $releaseEvidencePackSchemaPath, $releaseEvidenceManifestSchemaPath,
    $previewCapabilityMatrixSchemaPath,
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
$certificateTrustPolicyBytes = Get-Utf8LfBytes -LiteralPath $certificateTrustPolicyPath
$certificateTrustPolicyBase64 = [Convert]::ToBase64String($certificateTrustPolicyBytes)
$certificateTrustPolicyDigest = Get-Sha256Hex -Bytes $certificateTrustPolicyBytes
$certificateTrustPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $certificateTrustPolicyBytes
)
$microsoftConnectivityPolicyBytes = Get-Utf8LfBytes -LiteralPath $microsoftConnectivityPolicyPath
$microsoftConnectivityPolicyBase64 = [Convert]::ToBase64String($microsoftConnectivityPolicyBytes)
$microsoftConnectivityPolicyDigest = Get-Sha256Hex -Bytes $microsoftConnectivityPolicyBytes
$microsoftConnectivityPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $microsoftConnectivityPolicyBytes
)
$crossDomainGuidancePolicyBytes = Get-Utf8LfBytes -LiteralPath $crossDomainGuidancePolicyPath
$crossDomainGuidancePolicyBase64 = [Convert]::ToBase64String($crossDomainGuidancePolicyBytes)
$crossDomainGuidancePolicyDigest = Get-Sha256Hex -Bytes $crossDomainGuidancePolicyBytes
$crossDomainGuidancePolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $crossDomainGuidancePolicyBytes
)
$guidedRunwayPolicyBytes = Get-Utf8LfBytes -LiteralPath $guidedRunwayPolicyPath
$guidedRunwayPolicyBase64 = [Convert]::ToBase64String($guidedRunwayPolicyBytes)
$guidedRunwayPolicyDigest = Get-Sha256Hex -Bytes $guidedRunwayPolicyBytes
$guidedRunwayPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $guidedRunwayPolicyBytes
)
$portableDistributionPolicyBytes = Get-Utf8LfBytes -LiteralPath $portableDistributionPolicyPath
$portableDistributionPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $portableDistributionPolicyBytes
)
$attestedPreviewPolicyBytes = Get-Utf8LfBytes -LiteralPath $attestedPreviewPolicyPath
$attestedPreviewPolicyBase64 = [Convert]::ToBase64String($attestedPreviewPolicyBytes)
$attestedPreviewPolicyDigest = Get-Sha256Hex -Bytes $attestedPreviewPolicyBytes
$attestedPreviewPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $attestedPreviewPolicyBytes
)
$azureValidationAdmissionPolicyBytes = Get-Utf8LfBytes -LiteralPath $azureValidationAdmissionPolicyPath
$azureValidationAdmissionPolicyBase64 = [Convert]::ToBase64String($azureValidationAdmissionPolicyBytes)
$azureValidationAdmissionPolicyDigest = Get-Sha256Hex -Bytes $azureValidationAdmissionPolicyBytes
$azureValidationAdmissionPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $azureValidationAdmissionPolicyBytes
)
$azureValidationRoundPolicyBytes = Get-Utf8LfBytes -LiteralPath $azureValidationRoundPolicyPath
$azureValidationRoundPolicyBase64 = [Convert]::ToBase64String($azureValidationRoundPolicyBytes)
$azureValidationRoundPolicyDigest = Get-Sha256Hex -Bytes $azureValidationRoundPolicyBytes
$azureValidationRoundPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $azureValidationRoundPolicyBytes
)
$releaseGatesPolicyBytes = Get-Utf8LfBytes -LiteralPath $releaseGatesPolicyPath
$releaseGatesPolicyBase64 = [Convert]::ToBase64String($releaseGatesPolicyBytes)
$releaseGatesPolicyDigest = Get-Sha256Hex -Bytes $releaseGatesPolicyBytes
$releaseGatesPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $releaseGatesPolicyBytes
)
$signingBoundaryPolicyBytes = Get-Utf8LfBytes -LiteralPath $signingBoundaryPolicyPath
$signingBoundaryPolicyBase64 = [Convert]::ToBase64String($signingBoundaryPolicyBytes)
$signingBoundaryPolicyDigest = Get-Sha256Hex -Bytes $signingBoundaryPolicyBytes
$signingBoundaryPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $signingBoundaryPolicyBytes
)
$previewQualificationPolicyBytes = Get-Utf8LfBytes -LiteralPath $previewQualificationPolicyPath
$previewQualificationPolicyBase64 = [Convert]::ToBase64String($previewQualificationPolicyBytes)
$previewQualificationPolicyDigest = Get-Sha256Hex -Bytes $previewQualificationPolicyBytes
$previewQualificationPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $previewQualificationPolicyBytes
)
$previewPublicationPolicyBytes = Get-Utf8LfBytes -LiteralPath $previewPublicationPolicyPath
$previewPublicationPolicyBase64 = [Convert]::ToBase64String($previewPublicationPolicyBytes)
$previewPublicationPolicyDigest = Get-Sha256Hex -Bytes $previewPublicationPolicyBytes
$previewPublicationPolicyJson = [Text.UTF8Encoding]::new($false,$true).GetString(
    $previewPublicationPolicyBytes
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
if (-not (Test-Json -Json $certificateTrustPolicyJson -SchemaFile $certificateTrustSchemaPath)) {
    throw 'The Certificate Trust policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $microsoftConnectivityPolicyJson -SchemaFile $microsoftConnectivitySchemaPath)) {
    throw 'The Microsoft Connectivity policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $crossDomainGuidancePolicyJson -SchemaFile $crossDomainGuidanceSchemaPath)) {
    throw 'The Cross-domain Guidance policy does not satisfy its release schema.'
}
if (-not (Test-Json -Json $guidedRunwayPolicyJson -SchemaFile $guidedRunwaySchemaPath)) {
    throw 'The Guided Runway content contract does not satisfy its release schema.'
}
if (-not (Test-Json -Json $portableDistributionPolicyJson -SchemaFile $portableDistributionSchemaPath)) {
    throw 'The portable distribution contract does not satisfy its release schema.'
}
if (-not (Test-Json -Json $attestedPreviewPolicyJson -SchemaFile $attestedPreviewSchemaPath)) {
    throw 'The Attested Preview contract does not satisfy its release schema.'
}
if (-not (Test-Json -Json $azureValidationAdmissionPolicyJson -SchemaFile $azureValidationAdmissionSchemaPath)) {
    throw 'The Azure validation admission contract does not satisfy its release schema.'
}
if (-not (Test-Json -Json $azureValidationRoundPolicyJson -SchemaFile $azureValidationRoundSchemaPath)) {
    throw 'The Azure validation-round contract does not satisfy its release schema.'
}
if (-not (Test-Json -Json $releaseGatesPolicyJson -SchemaFile $releaseGatesSchemaPath)) {
    throw 'The release-gate contract does not satisfy its release schema.'
}
if (-not (Test-Json -Json $signingBoundaryPolicyJson -SchemaFile $signingBoundarySchemaPath)) {
    throw 'The Signing Boundary contract does not satisfy its release schema.'
}
if (-not (Test-Json -Json $previewPublicationPolicyJson -SchemaFile $previewPublicationSchemaPath)) {
    throw 'The Preview publication contract does not satisfy its release schema.'
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
    'build/DeterministicArchive.ps1'
    'build/PortableDistribution.ps1'
    'build/AttestedPreview.ps1'
    'build/Attest-Preview.ps1'
    'build/Start-WIN-PCInfo.ps1'
    'build/RuntimeHost.ps1'
    'build/Start-WIN-PCInfo.cmd'
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
    'schemas/certificate-trust.schema.json'
    'schemas/microsoft-connectivity.schema.json'
    'schemas/cross-domain-guidance.schema.json'
    'schemas/guided-runway.schema.json'
    'schemas/portable-distribution.schema.json'
    'schemas/attested-preview.schema.json'
    'schemas/attested-preview-attestation.schema.json'
    'schemas/azure-validation-admission.schema.json'
    'schemas/azure-validation-round-request.schema.json'
    'schemas/azure-validation-admission-verdict.schema.json'
    'schemas/azure-validation-round.schema.json'
    'schemas/azure-validation-round-execution-request.schema.json'
    'schemas/azure-validation-round-outcome.schema.json'
    'schemas/release-gates.schema.json'
    'schemas/signing-boundary.schema.json'
    'schemas/signing-session-request.schema.json'
    'schemas/signing-session-result.schema.json'
    'schemas/preview-qualification.schema.json'
    'schemas/preview-qualification-request.schema.json'
    'schemas/preview-qualification-packet.schema.json'
    'schemas/preview-publication.schema.json'
    'schemas/preview-publication-request.schema.json'
    'schemas/preview-publication-preview.schema.json'
    'schemas/preview-publication-result.schema.json'
    'schemas/release-evidence-pack.schema.json'
    'schemas/release-evidence-manifest.schema.json'
    'schemas/preview-capability-matrix.schema.json'
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
    'docs/spec/releases/2.0.0-preview.1-certificate-trust.json'
    'docs/spec/releases/2.0.0-preview.1-microsoft-connectivity.json'
    'docs/spec/releases/2.0.0-preview.1-cross-domain-guidance.json'
    'docs/spec/releases/2.0.0-preview.1-guided-runway.json'
    'docs/spec/releases/2.0.0-preview.1-portable-distribution.json'
    'docs/spec/releases/2.0.0-preview.1-attested-preview.json'
    'docs/spec/releases/2.0.0-preview.1-azure-validation-admission.json'
    'docs/spec/releases/2.0.0-preview.1-azure-validation-round.json'
    'docs/spec/releases/2.0.0-preview.1-release-gates.json'
    'docs/spec/releases/2.0.0-preview.1-signing-boundary.json'
    'docs/spec/releases/2.0.0-preview.1-preview-qualification.json'
    'docs/spec/releases/2.0.0-preview.1-preview-publication.json'
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
    certificateTrust = ($certificateTrustPolicyJson | ConvertFrom-Json -Depth 20)
    microsoftConnectivity = ($microsoftConnectivityPolicyJson | ConvertFrom-Json -Depth 20)
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

$buildToolDigestForPackage = Get-Sha256Hex -Bytes (Get-Utf8LfBytes -LiteralPath $PSCommandPath)
$portablePolicy = $portableDistributionPolicyJson | ConvertFrom-Json -Depth 20
$portableGoverning = Get-PortableGoverningResources -RepositoryRoot $repositoryRoot `
    -Policy $portablePolicy -BuildToolDigest $buildToolDigestForPackage -SignedHelperPath $SignedHelperPath
$portableGoverningBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
    ($portableGoverning.EmbeddedTable | ConvertTo-Json -Compress -Depth 30)
)
$portableGoverningBase64 = [System.Convert]::ToBase64String($portableGoverningBytes)
$portableGoverningDigest = Get-Sha256Hex -Bytes $portableGoverningBytes

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
    if ($sourceFile.path -eq 'src/CertificateTrust.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__CERTIFICATE_TRUST_POLICY_BASE64__', $certificateTrustPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__CERTIFICATE_TRUST_POLICY_SHA256__', $certificateTrustPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/MicrosoftConnectivity.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__MICROSOFT_CONNECTIVITY_POLICY_BASE64__', $microsoftConnectivityPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__MICROSOFT_CONNECTIVITY_POLICY_SHA256__', $microsoftConnectivityPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/CrossDomainGuidance.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__CROSS_DOMAIN_GUIDANCE_POLICY_BASE64__', $crossDomainGuidancePolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__CROSS_DOMAIN_GUIDANCE_POLICY_SHA256__', $crossDomainGuidancePolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/ProductHelp.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__GUIDED_RUNWAY_POLICY_BASE64__', $guidedRunwayPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__GUIDED_RUNWAY_POLICY_SHA256__', $guidedRunwayPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/AzureValidationAdmission.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__AZURE_VALIDATION_ADMISSION_POLICY_BASE64__', $azureValidationAdmissionPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__AZURE_VALIDATION_ADMISSION_POLICY_SHA256__', $azureValidationAdmissionPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/AzureValidationRound.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__AZURE_VALIDATION_ROUND_POLICY_BASE64__', $azureValidationRoundPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__AZURE_VALIDATION_ROUND_POLICY_SHA256__', $azureValidationRoundPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/ReleaseGates.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__RELEASE_GATES_POLICY_BASE64__', $releaseGatesPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__RELEASE_GATES_POLICY_SHA256__', $releaseGatesPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/SigningBoundary.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__SIGNING_BOUNDARY_POLICY_BASE64__', $signingBoundaryPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__SIGNING_BOUNDARY_POLICY_SHA256__', $signingBoundaryPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/PreviewQualification.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__PREVIEW_QUALIFICATION_POLICY_BASE64__', $previewQualificationPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__PREVIEW_QUALIFICATION_POLICY_SHA256__', $previewQualificationPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/PreviewPublication.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__PREVIEW_PUBLICATION_POLICY_BASE64__', $previewPublicationPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__PREVIEW_PUBLICATION_POLICY_SHA256__', $previewPublicationPolicyDigest
        )
    }
    if ($sourceFile.path -eq 'src/PortableDistribution.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__PORTABLE_GOVERNING_RESOURCES_BASE64__', $portableGoverningBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__PORTABLE_GOVERNING_RESOURCES_SHA256__', $portableGoverningDigest
        )
    }
    if ($sourceFile.path -eq 'src/AttestedPreview.ps1') {
        $normalizedSource = $normalizedSource.Replace(
            '__ATTESTED_PREVIEW_POLICY_BASE64__', $attestedPreviewPolicyBase64
        )
        $normalizedSource = $normalizedSource.Replace(
            '__ATTESTED_PREVIEW_POLICY_SHA256__', $attestedPreviewPolicyDigest
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

$applicationBytes = [System.IO.File]::ReadAllBytes($resolvedOutput)
$digest = Get-Sha256Hex -Bytes $applicationBytes
$buildToolPath = 'build/Build.ps1'
$buildToolDigest = $buildToolDigestForPackage
$portablePackage = New-PortableDistributionPackage `
    -OutputDirectory $outputDirectory `
    -ApplicationBytes $applicationBytes `
    -ApplicationDigest $digest `
    -Governing $portableGoverning `
    -BuildTool ([pscustomobject][ordered]@{
        path = $buildToolPath
        sha256 = $buildToolDigest
    })

[pscustomobject]@{
    buildContract = 'win-pcinfo.build-evidence/1.0.0'
    outputPath = $resolvedOutput
    sha256 = $digest
    generatedContentIdentity = [pscustomobject][ordered]@{
        kind = 'win-pcinfo.unsigned-generated-content-identity'
        sha256 = $digest
        encoding = 'utf-8-bom'
        lineEndings = 'crlf'
    }
    portablePackageIdentity = [pscustomobject][ordered]@{
        kind = 'win-pcinfo.unsigned-portable-package-identity'
        sha256 = [string] $portablePackage.sha256
        archiveFormat = 'zip'
        compression = 'store'
    }
    portablePackage = [pscustomobject][ordered]@{
        installsRuntime = $false
        archiveFileName = [string] $portablePackage.archiveFileName
        unpackedRootName = [string] $portablePackage.unpackedRootName
        sourceRevisionSha256 = [string] $portablePackage.sourceRevisionSha256
    }
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
