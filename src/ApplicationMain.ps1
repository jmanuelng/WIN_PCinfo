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

if ($Workflow -eq 'VerifyAttestation') {
    # The warning is an observable launch step of this fallback, not text
    # hidden in Help and not a label for an ordinary unsigned local build.
    # The threat is launching later smoke or validation without seeing that
    # this fallback is unsigned and limited-trust, or treating a later
    # package-integrity failure as a reason to skip the warning. The
    # mechanism is emitting the warning first, then verifying exact
    # candidate bindings. The trust assumption is SHA-256 of the reviewed
    # zip, not Authenticode. Safe failure is NotStarted with a typed
    # attestation reason and no bypass.
    $attestationPolicy = Get-AttestedPreviewEmbeddedPolicy `
        -ConvertFromJsonCommand $convertFromJsonCommand
    Write-ContractRecord (Get-AttestedPreviewLimitedTrustWarning `
        -Policy $attestationPolicy.Policy) -ConvertToJsonCommand $convertToJsonCommand
    try {
        $attestationResult = Test-AttestedPreviewBundle `
            -AttestationBundlePath $AttestationBundlePath `
            -CandidateArchivePath $CandidateArchivePath `
            -ConvertFromJsonCommand $convertFromJsonCommand
    }
    catch {
        $attestationResult = [pscustomobject]@{
            Valid = $false
            ReasonCode = 'ATTESTATION.CONFLICTING_INPUT'
            Record = (New-AttestedPreviewVerificationRecord -State Rejected `
                -ReasonCode 'ATTESTATION.CONFLICTING_INPUT')
        }
    }
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

if ($Workflow -eq 'AdmitValidationRound') {
    # Admission is a local maintainer gate. The threat is hiding the unsigned
    # precursor behind Authenticode while still needing to test template
    # rendering. The mechanism is the same trusted JSON commands as Help, with
    # no Azure, Terraform, or certificate work. The trust assumption is that
    # the request and private workspace are caller-supplied. Safe failure is
    # NotStarted without rendering.
    Write-ContractRecord (New-ProgressRecord -Sequence 1 -Phase 'ValidationAdmission' -State 'Started' `
        -MessageId 'validation.admission.started' -CompletedUnits 0 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    $admissionResult = if ([string]::IsNullOrWhiteSpace($ValidationRoundRequestPath) -or
        [string]::IsNullOrWhiteSpace($ValidationPrivateWorkspacePath)) {
        New-AzureValidationAdmissionVerdict -State Rejected `
            -ReasonCode 'VALIDATION.REQUEST_INVALID' -PrivacyBoundary Missing
    }
    else {
        try {
            $admissionRequestText = [System.IO.File]::ReadAllText(
                $ValidationRoundRequestPath,
                [System.Text.UTF8Encoding]::new($false, $true)
            )
            $admissionRequest = & $convertFromJsonCommand -InputObject $admissionRequestText `
                -ErrorAction Stop
            $admissionRepositoryRoot = Split-Path -Parent $PSCommandPath
            $admissionApplicationDirectory = Split-Path -Parent $PSCommandPath
            if (-not (Test-Path -LiteralPath (
                Join-Path $admissionRepositoryRoot 'infra/azure-validation/versions.tf'
            ))) {
                $admissionRepositoryRoot = Split-Path -Parent $admissionRepositoryRoot
            }
            $admissionRequestSchema = Get-AzureValidationRequestSchemaPath `
                -RepositoryRoot $admissionRepositoryRoot `
                -ApplicationDirectory $admissionApplicationDirectory
            $admissionRequestSchemaValid = $true
            if (-not [string]::IsNullOrWhiteSpace($admissionRequestSchema)) {
                try {
                    $admissionRequestSchemaValid = Test-Json -Json $admissionRequestText `
                        -SchemaFile $admissionRequestSchema
                }
                catch {
                    $admissionRequestSchemaValid = $false
                }
            }
            if (-not $admissionRequestSchemaValid) {
                New-AzureValidationAdmissionVerdict -State Rejected `
                    -ReasonCode 'VALIDATION.REQUEST_INVALID' -PrivacyBoundary Missing
            }
            else {
                Invoke-AzureValidationAdmission -Request $admissionRequest `
                    -PrivateWorkspacePath $ValidationPrivateWorkspacePath `
                    -RepositoryRoot $admissionRepositoryRoot `
                    -ApplicationDirectory $admissionApplicationDirectory
            }
        }
        catch {
            New-AzureValidationAdmissionVerdict -State Rejected `
                -ReasonCode 'VALIDATION.REQUEST_INVALID' -PrivacyBoundary Missing
        }
    }
    Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'ValidationAdmission' `
        -State $(if ($admissionResult.admitted) { 'Succeeded' } else { 'Failed' }) `
        -MessageId $(if ($admissionResult.admitted) {
            'validation.admission.succeeded'
        } else {
            'validation.admission.failed'
        }) -CompletedUnits 1 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord $admissionResult -ConvertToJsonCommand $convertToJsonCommand
    $terminal = New-TerminalRecord -ReasonCode $admissionResult.reasonCode `
        -Phase ValidationAdmission
    $exitCode = 20
    if ($admissionResult.admitted) {
        $terminal.outcome = 'Completed'
        $terminal.exitCode = 0
        $exitCode = 0
    }
    Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
    exit $exitCode
}

if ($Workflow -eq 'EvaluateReleaseGates') {
    # Pre-signing gates must run on the unsigned generated candidate. The
    # threat is hiding a failed or private pack behind Authenticode, or
    # treating this workflow as collection. The mechanism is the same trusted
    # JSON commands as Help, with no Azure, signing, or assessment work. The
    # trust assumption is that the pack is synthetic. Safe failure is
    # NotStarted without derived residue.
    Write-ContractRecord (New-ProgressRecord -Sequence 1 -Phase 'ReleaseGates' -State 'Started' `
        -MessageId 'release.gates.started' -CompletedUnits 0 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    $gatePolicy = Get-ReleaseGatesPolicy
    $gateEvaluation = $null
    if ([string]::IsNullOrWhiteSpace($ReleaseEvidencePackPath)) {
        $gateEvaluation = Get-ReleaseGatesRejectedEvaluation -ReasonCode 'GATE.PACK_MISSING' `
            -Policy $gatePolicy
    }
    else {
        try {
            $gatePackText = [System.IO.File]::ReadAllText(
                $ReleaseEvidencePackPath,
                [System.Text.UTF8Encoding]::new($false, $true)
            )
            $gatePrivacy = Test-ReleaseGatesPrivacyBoundary -Text $gatePackText
            if ($gatePrivacy) {
                $gateEvaluation = Get-ReleaseGatesRejectedEvaluation -ReasonCode $gatePrivacy `
                    -Policy $gatePolicy
            }
            else {
                $gateRepositoryRoot = Split-Path -Parent $PSCommandPath
                $gateApplicationDirectory = Split-Path -Parent $PSCommandPath
                if (-not (Test-Path -LiteralPath (
                    Join-Path $gateRepositoryRoot 'docs/spec/capability-ledger.json'
                ))) {
                    $gateRepositoryRoot = Split-Path -Parent $gateRepositoryRoot
                }
                $gatePackSchema = Get-ReleaseGatesCatalogPath `
                    -RepositoryRoot $gateRepositoryRoot `
                    -ApplicationDirectory $gateApplicationDirectory `
                    -RelativePath 'schemas/release-evidence-pack.schema.json'
                $gatePackSchemaValid = $true
                if (-not [string]::IsNullOrWhiteSpace($gatePackSchema)) {
                    try {
                        $gatePackSchemaValid = Test-Json -Json $gatePackText `
                            -SchemaFile $gatePackSchema
                    }
                    catch {
                        $gatePackSchemaValid = $false
                    }
                }
                if (-not $gatePackSchemaValid) {
                    $gateEvaluation = Get-ReleaseGatesRejectedEvaluation `
                        -ReasonCode 'GATE.PACK_INVALID' -Policy $gatePolicy
                }
                else {
                    $gatePack = & $convertFromJsonCommand -InputObject $gatePackText `
                        -ErrorAction Stop
                    $gateCandidateBytes = [System.IO.File]::ReadAllBytes($PSCommandPath)
                    $gateCandidateDigest = Get-ReleaseGatesSha256 -Bytes $gateCandidateBytes
                    $gateLedgerPath = Get-ReleaseGatesCatalogPath `
                        -RepositoryRoot $gateRepositoryRoot `
                        -ApplicationDirectory $gateApplicationDirectory `
                        -RelativePath 'docs/spec/capability-ledger.json'
                    $gateReleasePath = Get-ReleaseGatesCatalogPath `
                        -RepositoryRoot $gateRepositoryRoot `
                        -ApplicationDirectory $gateApplicationDirectory `
                        -RelativePath 'docs/spec/releases/2.0.0-preview.1.json'
                    $gateLedger = $null
                    $gateReleaseDefinition = $null
                    $gateLedgerDigest = $null
                    if (-not [string]::IsNullOrWhiteSpace($gateLedgerPath)) {
                        $gateLedgerBytes = [System.IO.File]::ReadAllBytes($gateLedgerPath)
                        $gateLedgerDigest = Get-ReleaseGatesSha256 -Bytes $gateLedgerBytes
                        $gateLedgerText = [System.Text.UTF8Encoding]::new($false, $true).GetString(
                            $gateLedgerBytes
                        )
                        $gateLedger = & $convertFromJsonCommand -InputObject $gateLedgerText `
                            -ErrorAction Stop
                    }
                    if (-not [string]::IsNullOrWhiteSpace($gateReleasePath)) {
                        $gateReleaseText = [System.IO.File]::ReadAllText(
                            $gateReleasePath,
                            [System.Text.UTF8Encoding]::new($false, $true)
                        )
                        $gateReleaseDefinition = & $convertFromJsonCommand `
                            -InputObject $gateReleaseText -ErrorAction Stop
                    }
                    $gateWorkspace = $ReleaseGateWorkspacePath
                    $gateOwnedWorkspace = $false
                    if ([string]::IsNullOrWhiteSpace($gateWorkspace)) {
                        $gateWorkspace = Join-Path ([System.IO.Path]::GetTempPath()) (
                            'win-pcinfo-release-gates-' + [guid]::NewGuid().ToString('N')
                        )
                        $null = New-Item -ItemType Directory -Path $gateWorkspace -Force
                        $gateOwnedWorkspace = $true
                    }
                    try {
                        $gateEvaluation = Invoke-ReleaseGateEvaluation -Pack $gatePack `
                            -Policy $gatePolicy -Ledger $gateLedger `
                            -ReleaseDefinition $gateReleaseDefinition `
                            -PackText $gatePackText `
                            -ExpectedGeneratedContentSha256 $gateCandidateDigest `
                            -ExpectedLedgerSha256 $gateLedgerDigest `
                            -WorkspacePath $gateWorkspace `
                            -RepositoryRoot $gateRepositoryRoot `
                            -ApplicationDirectory $gateApplicationDirectory
                    }
                    finally {
                        if ($gateOwnedWorkspace -and (Test-Path -LiteralPath $gateWorkspace)) {
                            Remove-Item -LiteralPath $gateWorkspace -Recurse -Force `
                                -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        }
        catch {
            $gateEvaluation = Get-ReleaseGatesRejectedEvaluation -ReasonCode 'GATE.PACK_INVALID' `
                -Policy $gatePolicy
        }
    }
    Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'ReleaseGates' `
        -State $(if ($gateEvaluation.State -eq 'Evaluated') { 'Succeeded' } else { 'Failed' }) `
        -MessageId $(if ($gateEvaluation.State -eq 'Evaluated') {
            'release.gates.succeeded'
        } else {
            'release.gates.failed'
        }) -CompletedUnits 1 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord $gateEvaluation.Manifest -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord $gateEvaluation.Matrix -ConvertToJsonCommand $convertToJsonCommand
    $terminalReason = if ($gateEvaluation.State -eq 'Evaluated' -and
        $gateEvaluation.ExitKind -eq 'Completed') {
        'RELEASE.GATES_EVALUATED'
    }
    else {
        $gateEvaluation.ReasonCode
    }
    $terminal = New-TerminalRecord -ReasonCode $terminalReason -Phase ReleaseGates
    $exitCode = 20
    if ($gateEvaluation.ExitKind -eq 'Completed') {
        $terminal.outcome = 'Completed'
        $terminal.exitCode = 0
        $exitCode = 0
    }
    elseif ($gateEvaluation.ExitKind -eq 'CleanupIncomplete') {
        $terminal.outcome = 'CleanupIncomplete'
        $terminal.exitCode = 60
        $terminal.cleanup.required = $true
        $terminal.cleanup.verified = $false
        $exitCode = 60
    }
    Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
    exit $exitCode
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
