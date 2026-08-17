if ($PSVersionTable.PSEdition -ne 'Core') {
    # Windows PowerShell cannot be trusted to provide the v2 JSON/validator
    # stack. Emit only this fixed public contract record; no ambient serializer,
    # profile function, collection, or relaunch is permitted on the wrong host.
    Write-BootstrapTerminal -ReasonCode 'RUNTIME.EDITION_UNSUPPORTED'
    exit 20
}

$moduleFacts = Get-BuiltInModuleCompatibilityFacts
if (-not $moduleFacts.contractCommandProvenance) {
    # A structured failure must not invoke an ambient JSON command after the
    # trusted serializer boundary fails. This literal contains only fixed public
    # contract values; it cannot include request or machine-controlled text.
    $bootstrapReason = if ($moduleFacts.moduleLoading) {
        'RUNTIME.VALIDATOR_PROVENANCE_INVALID'
    }
    else {
        'RUNTIME.MODULE_LOADING_INCOMPATIBLE'
    }
    Write-BootstrapTerminal -ReasonCode $bootstrapReason
    exit 20
}
$convertToJsonCommand = $moduleFacts.convertToJsonCommand
$convertFromJsonCommand = $moduleFacts.convertFromJsonCommand
$artifactTrustValid = Test-ApplicationArtifactTrust -LiteralPath $PSCommandPath `
    -AuthenticodeCommand $moduleFacts.authenticodeCommand

# A portable package keeps schemas, catalogs, helpers, and documentation as
# explicit files. The threat is a substituted adjacent file that keeps the
# authentic script name. The mechanism is the embedded governing-resource
# table plus the package manifest. The trust assumption is that those bytes
# came from the deterministic build. Safe failure is NotStarted with no
# integrity override, including when a preparation fixture is supplied.
$packageManifestPresence = if ($Workflow -eq 'Verify') { 'Required' } else { 'Optional' }
$packageIntegrity = Test-PortableDistributionIntegrity `
    -PackageRoot (Split-Path -Parent $PSCommandPath) `
    -ManifestPresence $packageManifestPresence `
    -ConvertFromJsonCommand $convertFromJsonCommand
if (-not $packageIntegrity.Valid) {
    Write-ContractRecord (New-TerminalRecord -ReasonCode 'PREPARATION.INTEGRITY_FAILED' `
        -Phase 'Preparation') -ConvertToJsonCommand $convertToJsonCommand
    exit 20
}

if ($Workflow -eq 'Verify') {
    $generatedBytes = [System.IO.File]::ReadAllBytes($PSCommandPath)
    $generatedDigest = Get-PortableDistributionFileDigest -Bytes $generatedBytes
    $resourceCount = @($packageIntegrity.Manifest.resources).Count
    Write-ContractRecord (New-PortableDistributionVerificationRecord `
        -GeneratedContentSha256 $generatedDigest `
        -ResourceCount $resourceCount) -ConvertToJsonCommand $convertToJsonCommand
    $terminal = New-TerminalRecord -ReasonCode 'PACKAGE.VERIFIED' -Phase 'Verify'
    $terminal.outcome = 'Completed'
    $terminal.exitCode = 0
    Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
    exit 0
}

if ($Workflow -eq 'VerifyAttestation') {
    # The warning is an observable launch step, not text hidden in Help.
    # The threat is launching later smoke or validation without seeing that
    # this fallback is unsigned and limited-trust. The mechanism is emitting
    # the warning first, then verifying exact candidate bindings. The trust
    # assumption is SHA-256 of the reviewed zip, not Authenticode. Safe
    # failure is NotStarted with a typed attestation reason and no bypass.
    $attestationPolicy = Get-AttestedPreviewEmbeddedPolicy `
        -ConvertFromJsonCommand $convertFromJsonCommand
    Write-ContractRecord (Get-AttestedPreviewLimitedTrustWarning `
        -Policy $attestationPolicy.Policy) -ConvertToJsonCommand $convertToJsonCommand
    $attestationResult = Test-AttestedPreviewBundle `
        -AttestationBundlePath $AttestationBundlePath `
        -CandidateArchivePath $CandidateArchivePath `
        -ConvertFromJsonCommand $convertFromJsonCommand
    Write-ContractRecord $attestationResult.Record -ConvertToJsonCommand $convertToJsonCommand
    $terminal = New-TerminalRecord -ReasonCode $attestationResult.ReasonCode `
        -Phase 'VerifyAttestation'
    if ($attestationResult.Valid) {
        $terminal.outcome = 'Completed'
        $terminal.exitCode = 0
        Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
        exit 0
    }
    Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
    exit 20
}

if ($Workflow -eq 'Help' -or $Workflow -eq 'About') {
    # Discovery must remain available on an unsigned development artifact.
    # Requiring Authenticode here would hide the repository from the people
    # most likely to open Help. The workflow still uses the verified JSON
    # command, starts no collection, and makes no network request.
    $helpRecord = Get-ProductHelpRecord -Surface $Workflow
    Write-ContractRecord $helpRecord -ConvertToJsonCommand $convertToJsonCommand
    $terminal = New-TerminalRecord -ReasonCode 'HELP.DISCOVERY_COMPLETE' -Phase $Workflow
    $terminal.outcome = 'Completed'
    $terminal.exitCode = 0
    Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
    exit 0
}

if ($Workflow -ne 'Assessment') {
    $workflowRuntime = Test-RuntimeCompatibility -Facts (
        Get-ActiveRuntimeFacts -ModuleFacts $moduleFacts
    )
    if (-not $workflowRuntime.Eligible -or -not $artifactTrustValid) {
        $reason = if (-not $workflowRuntime.Eligible) {
            [string] $workflowRuntime.ReasonCode
        }
        else { 'PREPARATION.INTEGRITY_FAILED' }
        Write-ContractRecord (New-TerminalRecord -ReasonCode $reason `
            -RuntimeResult $workflowRuntime -Phase $Workflow) `
            -ConvertToJsonCommand $convertToJsonCommand
        exit 20
    }
    if ($Workflow -eq 'RecipientProfileSetup') {
        $workflowResult = if ([string]::IsNullOrWhiteSpace($RecipientLabel) -or
            [string]::IsNullOrWhiteSpace($RecipientProfileOutputPath)) {
            [pscustomobject][ordered]@{
                state = 'NotStarted'; reasonCode = 'RECIPIENT.SETUP_INPUT_INVALID'
                profilePath = $null; fingerprint = $null; protectionLevel = $null
                syntheticRoundTripVerified = $false
            }
        }
        else {
            New-RecipientProfileSetup -Label $RecipientLabel `
                -OutputPath $RecipientProfileOutputPath `
                -ConfirmSetup:$ConfirmRecipientSetup
        }
        Write-ContractRecord ([pscustomobject][ordered]@{
            recordType = 'win-pcinfo.recipient-profile-setup'
            contractVersion = '1.0.0'
            state = $workflowResult.state
            reasonCode = $workflowResult.reasonCode
            profilePath = $workflowResult.profilePath
            fingerprint = $workflowResult.fingerprint
            protectionLevel = $workflowResult.protectionLevel
            syntheticRoundTripVerified = $workflowResult.syntheticRoundTripVerified
            privateKeyExported = $false
        }) -ConvertToJsonCommand $convertToJsonCommand
        $terminal = New-TerminalRecord -ReasonCode $workflowResult.reasonCode `
            -RuntimeResult $workflowRuntime -Phase RecipientProfileSetup
        $exitCode = 20
        if ($workflowResult.state -eq 'Created') {
            $terminal.outcome = 'Completed'; $terminal.exitCode = 0; $exitCode = 0
        }
        elseif ($workflowResult.state -eq 'CleanupIncomplete') {
            $terminal.outcome = 'CleanupIncomplete'; $terminal.exitCode = 60
            $terminal.cleanup.required = $true; $terminal.cleanup.verified = $false
            $exitCode = 60
        }
        Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
        exit $exitCode
    }
    # The warning is an observable workflow step, not text hidden in help or in
    # the resulting HTML. It is emitted before checking the deliberate phrase,
    # so declining or mistyping still proves that no plaintext write preceded
    # the prominent Restricted consequences and deletion instructions.
    Write-ContractRecord (Get-RestrictedReportExportWarning) `
        -ConvertToJsonCommand $convertToJsonCommand
    $workflowResult = if ([string]::IsNullOrWhiteSpace($ProtectedPackagePath) -or
        [string]::IsNullOrWhiteSpace($RestrictedReportOutputPath) -or
        $null -eq $RestrictedReportWarningAcknowledgment) {
        [pscustomobject][ordered]@{
            state = 'NotStarted'; reasonCode = 'EXPORT.INPUT_INVALID'
            reportPath = $null; restrictedDiagnosticEvidence = $true
            publiclyShareable = $false; cleanupVerified = $true
        }
    }
    else {
        Export-RestrictedAssessmentReport `
            -PackagePath $ProtectedPackagePath -OutputPath $RestrictedReportOutputPath `
            -WarningAcknowledgment $RestrictedReportWarningAcknowledgment
    }
    Write-ContractRecord ([pscustomobject][ordered]@{
        recordType = 'win-pcinfo.restricted-report-export'
        contractVersion = '1.0.0'
        state = $workflowResult.state
        reasonCode = $workflowResult.reasonCode
        reportPath = $workflowResult.reportPath
        restrictedDiagnosticEvidence = $true
        publiclyShareable = $false
        cleanupVerified = $workflowResult.cleanupVerified
    }) -ConvertToJsonCommand $convertToJsonCommand
    $terminal = New-TerminalRecord -ReasonCode $workflowResult.reasonCode `
        -RuntimeResult $workflowRuntime -Phase RestrictedReportExport
    $exitCode = 20
    if ($workflowResult.state -eq 'Exported') {
        $terminal.outcome = 'Completed'; $terminal.exitCode = 0; $exitCode = 0
    }
    elseif ($workflowResult.state -eq 'IntegrityFailed') {
        $terminal.outcome = 'IntegrityFailed'; $terminal.exitCode = 50; $exitCode = 50
    }
    elseif ($workflowResult.state -eq 'CleanupIncomplete') {
        $terminal.outcome = 'CleanupIncomplete'; $terminal.exitCode = 60
        $terminal.cleanup.required = $true; $terminal.cleanup.verified = $false
        $exitCode = 60
    }
    Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
    exit $exitCode
}

Write-ContractRecord (New-ProgressRecord -Sequence 1 -Phase 'RequestValidation' -State 'Started' `
    -MessageId 'request.validation.started' -CompletedUnits 0 -TotalUnits 2) `
    -ConvertToJsonCommand $convertToJsonCommand
try {
    $request = if ($Mode -eq 'Automation') {
        if (-not [string]::IsNullOrWhiteSpace($AssessmentRecipientProfilePath) -or
            -not [string]::IsNullOrWhiteSpace($AssessmentRecipientFingerprintConfirmation)) {
            $exception = [System.ArgumentException]::new(
                'Guided recipient parameters cannot modify an automation request.'
            )
            $exception.Data['ReasonCode'] = 'REQUEST.RECIPIENT_SELECTION_INVALID'
            throw $exception
        }
        if ([string]::IsNullOrWhiteSpace($RequestPath)) {
            $exception = [System.ArgumentException]::new('Automation mode requires -RequestPath.')
            $exception.Data['ReasonCode'] = 'REQUEST.PATH_REQUIRED'
            throw $exception
        }
        Get-AutomationRequest -LiteralPath $RequestPath -ConvertFromJsonCommand $convertFromJsonCommand
    }
    else {
        Get-GuidedRequest -RecipientProfilePath $AssessmentRecipientProfilePath `
            -RecipientFingerprintConfirmation $AssessmentRecipientFingerprintConfirmation
    }
}
catch {
    $reasonCode = if ($_.Exception.Data.Contains('ReasonCode')) {
        [string] $_.Exception.Data['ReasonCode']
    }
    else {
        'REQUEST.UNREADABLE'
    }
    Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'RequestValidation' -State 'Failed' `
        -MessageId 'request.validation.failed' -CompletedUnits 0 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord (New-TerminalRecord -ReasonCode $reasonCode -Phase 'RequestValidation') `
        -ConvertToJsonCommand $convertToJsonCommand
    exit 20
}
Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'RequestValidation' -State 'Succeeded' `
    -MessageId 'request.validation.succeeded' -CompletedUnits 1 -TotalUnits 2) `
    -ConvertToJsonCommand $convertToJsonCommand

$usingRuntimeFixture = -not [string]::IsNullOrWhiteSpace($RuntimeFixturePath)
$runtimeFacts = if ($usingRuntimeFixture) {
    Read-RuntimeFixture -LiteralPath $RuntimeFixturePath -ConvertFromJsonCommand $convertFromJsonCommand
}
else {
    Get-ActiveRuntimeFacts -ModuleFacts $moduleFacts
}

$usingPreparationFixture = -not [string]::IsNullOrWhiteSpace($PreparationFixturePath)
$usingContractFixture = -not [string]::IsNullOrWhiteSpace($ContractFixturePath)
$usingRunFixture = -not [string]::IsNullOrWhiteSpace($RunFixturePath)
$usingPrivilegedCollectionFixture = -not [string]::IsNullOrWhiteSpace($PrivilegedCollectionFixturePath)
$usingSystemCollectionFixture = -not [string]::IsNullOrWhiteSpace($SystemCollectionFixturePath)
$usingEvidenceWorkspaceFixture = -not [string]::IsNullOrWhiteSpace($EvidenceWorkspaceFixturePath)
$usingProtectedPackageFixture = -not [string]::IsNullOrWhiteSpace($ProtectedPackageFixturePath)
$usingRecipientSharingFixture = -not [string]::IsNullOrWhiteSpace($RecipientSharingFixturePath)
$usingDeviceReadinessFixture = -not [string]::IsNullOrWhiteSpace($DeviceReadinessFixturePath)
$usingIdentityEnrollmentFixture = -not [string]::IsNullOrWhiteSpace($IdentityEnrollmentFixturePath)
$usingAdministratorExposureFixture = -not [string]::IsNullOrWhiteSpace($AdministratorExposureFixturePath)
$usingEffectivePolicyFixture = -not [string]::IsNullOrWhiteSpace($EffectivePolicyFixturePath)
$usingResourceDependenciesFixture = -not [string]::IsNullOrWhiteSpace($ResourceDependenciesFixturePath)
$usingNetworkTopologyFixture = -not [string]::IsNullOrWhiteSpace($NetworkTopologyFixturePath)
$usingSoftwareInventoryFixture = -not [string]::IsNullOrWhiteSpace($SoftwareInventoryFixturePath)
$usingCertificateTrustFixture = -not [string]::IsNullOrWhiteSpace($CertificateTrustFixturePath)
$usingMicrosoftConnectivityFixture = -not [string]::IsNullOrWhiteSpace($MicrosoftConnectivityFixturePath)
$validationContext = [pscustomobject][ordered]@{
    PreparationFixturePath = $PreparationFixturePath
    ContractFixturePath = $ContractFixturePath
    RunFixturePath = $RunFixturePath
    PrivilegedCollectionFixturePath = $PrivilegedCollectionFixturePath
    SystemCollectionFixturePath = $SystemCollectionFixturePath
    EvidenceWorkspaceFixturePath = $EvidenceWorkspaceFixturePath
    ProtectedPackageFixturePath = $ProtectedPackageFixturePath
    RecipientSharingFixturePath = $RecipientSharingFixturePath
    DeviceReadinessFixturePath = $DeviceReadinessFixturePath
    IdentityEnrollmentFixturePath = $IdentityEnrollmentFixturePath
    AdministratorExposureFixturePath = $AdministratorExposureFixturePath
    EffectivePolicyFixturePath = $EffectivePolicyFixturePath
    ResourceDependenciesFixturePath = $ResourceDependenciesFixturePath
    NetworkTopologyFixturePath = $NetworkTopologyFixturePath
    SoftwareInventoryFixturePath = $SoftwareInventoryFixturePath
    CertificateTrustFixturePath = $CertificateTrustFixturePath
    MicrosoftConnectivityFixturePath = $MicrosoftConnectivityFixturePath
    IsFixture = ($usingRuntimeFixture -or $usingPreparationFixture -or
        $usingContractFixture -or $usingRunFixture -or $usingPrivilegedCollectionFixture -or
        $usingSystemCollectionFixture -or $usingEvidenceWorkspaceFixture -or
        $usingProtectedPackageFixture -or $usingRecipientSharingFixture -or
        $usingDeviceReadinessFixture -or $usingIdentityEnrollmentFixture -or
        $usingAdministratorExposureFixture -or $usingEffectivePolicyFixture -or
        $usingResourceDependenciesFixture -or $usingNetworkTopologyFixture -or
        $usingSoftwareInventoryFixture -or $usingCertificateTrustFixture -or
        $usingMicrosoftConnectivityFixture)
}
$applicationExitCode = Invoke-WinPCInfoLaunch -Request $request -RuntimeFacts $runtimeFacts `
    -Mode $Mode -AcceptPreparation:$AcceptPreparation -ValidationContext $validationContext `
    -ArtifactTrustValid $artifactTrustValid `
    -ConvertFromJsonCommand $convertFromJsonCommand -ConvertToJsonCommand $convertToJsonCommand `
    -TestJsonCommand $moduleFacts.testJsonCommand
exit $applicationExitCode
