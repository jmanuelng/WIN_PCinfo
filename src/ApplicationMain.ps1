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
# The portable bootstrap probes this exact generated application's policy.
# This branch has no request, fixture, preparation, or assessment authority.
if ($Workflow -eq 'CheckRuntime') {
    $runtimeCheck = Test-RuntimeCompatibility -Facts (Get-ActiveRuntimeFacts -ModuleFacts $moduleFacts)
    $terminal = New-TerminalRecord -ReasonCode $runtimeCheck.ReasonCode -RuntimeResult $runtimeCheck -Phase 'RuntimeCompatibility'
    if ($runtimeCheck.Eligible) { $terminal.outcome = 'Completed'; $terminal.exitCode = 0 }
    Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
    exit $terminal.exitCode
}
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

if ($Mode -eq 'Gui') {
    # The Status desk adapter is owned by #137. Never silently fall through to
    # guided assessment while that adapter is unavailable.
    Write-ContractRecord (New-TerminalRecord -ReasonCode 'GUI.ADAPTER_UNAVAILABLE' -Phase 'Launch') `
        -ConvertToJsonCommand $convertToJsonCommand
    exit 20
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

if ($Workflow -eq 'RunValidationRound') {
    # A Validation Round is a maintainer controller, not an assessment of
    # this host. The threat is treating a synthetic fixture as live Azure,
    # exposing a bootstrap password, or reporting completion while residue
    # remains. The mechanism is the same trusted JSON commands as Help,
    # cleanup-first admission, and VM Agent-only guest control. The trust
    # assumption is that live Azure uses the approved managed identity.
    # Safe failure is NotStarted before create, or CleanupIncomplete while
    # any exact target remains.
    Write-ContractRecord (New-ProgressRecord -Sequence 1 -Phase 'ValidationRound' -State 'Started' `
        -MessageId 'validation.round.started' -CompletedUnits 0 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    $roundResult = if ([string]::IsNullOrWhiteSpace($ValidationRoundRequestPath) -or
        [string]::IsNullOrWhiteSpace($ValidationPrivateWorkspacePath)) {
        New-AzureValidationRoundOutcome -State Rejected `
            -ReasonCode 'VALIDATION.REQUEST_INVALID' -PrivacyBoundary Missing
    }
    else {
        try {
            $roundPlanText = [System.IO.File]::ReadAllText(
                $ValidationRoundRequestPath,
                [System.Text.UTF8Encoding]::new($false, $true)
            )
            $roundPrivacy = Test-AzureValidationRoundPrivacyBoundary -Text $roundPlanText
            if ($roundPrivacy) {
                New-AzureValidationRoundOutcome -State Rejected `
                    -ReasonCode $roundPrivacy -PrivacyBoundary Rejected
            }
            else {
                $roundPlan = & $convertFromJsonCommand -InputObject $roundPlanText `
                    -ErrorAction Stop
                $roundRepositoryRoot = Split-Path -Parent $PSCommandPath
                $roundApplicationDirectory = Split-Path -Parent $PSCommandPath
                if (-not (Test-Path -LiteralPath (
                    Join-Path $roundRepositoryRoot 'infra/azure-validation/versions.tf'
                ))) {
                    $roundRepositoryRoot = Split-Path -Parent $roundRepositoryRoot
                }
                $roundScenario = $null
                $roundFixtureText = $null
                if (-not [string]::IsNullOrWhiteSpace($ValidationRoundFixturePath)) {
                    $roundFixtureText = [System.IO.File]::ReadAllText(
                        $ValidationRoundFixturePath,
                        [System.Text.UTF8Encoding]::new($false, $true)
                    )
                    $roundFixturePrivacy = Test-AzureValidationRoundPrivacyBoundary `
                        -Text $roundFixtureText
                    if ($roundFixturePrivacy) {
                        New-AzureValidationRoundOutcome -State Rejected `
                            -ReasonCode $roundFixturePrivacy -PrivacyBoundary Rejected
                    }
                    else {
                        $roundFixtureSchema = Get-AzureValidationRoundCatalogPath `
                            -RepositoryRoot $roundRepositoryRoot `
                            -ApplicationDirectory $roundApplicationDirectory `
                            -RelativePath 'schemas/azure-validation-round-execution-request.schema.json'
                        $roundFixtureValid = $false
                        if (-not [string]::IsNullOrWhiteSpace($roundFixtureSchema)) {
                            try {
                                $roundFixtureValid = Test-Json -Json $roundFixtureText `
                                    -SchemaFile $roundFixtureSchema
                            }
                            catch {
                                $roundFixtureValid = $false
                            }
                        }
                        if (-not $roundFixtureValid) {
                            New-AzureValidationRoundOutcome -State Rejected `
                                -ReasonCode 'VALIDATION.REQUEST_INVALID' `
                                -PrivacyBoundary Rejected
                        }
                        else {
                            $roundFixture = & $convertFromJsonCommand `
                                -InputObject $roundFixtureText -ErrorAction Stop
                            $roundScenario = [string] $roundFixture.scenario
                            Invoke-AzureValidationRound -Plan $roundPlan `
                                -Scenario $roundScenario `
                                -PrivateWorkspacePath $ValidationPrivateWorkspacePath `
                                -RepositoryRoot $roundRepositoryRoot `
                                -ApplicationDirectory $roundApplicationDirectory `
                                -FixtureText $roundFixtureText
                        }
                    }
                }
                else {
                    Invoke-AzureValidationRound -Plan $roundPlan `
                        -PrivateWorkspacePath $ValidationPrivateWorkspacePath `
                        -RepositoryRoot $roundRepositoryRoot `
                        -ApplicationDirectory $roundApplicationDirectory
                }
            }
        }
        catch {
            New-AzureValidationRoundOutcome -State Rejected `
                -ReasonCode 'VALIDATION.REQUEST_INVALID' -PrivacyBoundary Missing
        }
    }
    $roundSucceeded = $roundResult.state -eq 'ZeroResidueProven'
    Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'ValidationRound' `
        -State $(if ($roundSucceeded) { 'Succeeded' } else { 'Failed' }) `
        -MessageId $(if ($roundSucceeded) {
            'validation.round.succeeded'
        } else {
            'validation.round.failed'
        }) -CompletedUnits 1 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord $roundResult -ConvertToJsonCommand $convertToJsonCommand
    $terminal = New-TerminalRecord -ReasonCode $roundResult.reasonCode `
        -Phase ValidationRound
    $exitCode = 20
    if ($roundResult.state -eq 'ZeroResidueProven') {
        $terminal.outcome = 'Completed'
        $terminal.exitCode = 0
        $terminal.cleanup.required = $true
        $terminal.cleanup.verified = $true
        $exitCode = 0
    }
    elseif ($roundResult.state -eq 'FailedCleaned') {
        $terminal.outcome = 'CompletedWithGaps'
        $terminal.exitCode = 10
        $terminal.cleanup.required = $true
        $terminal.cleanup.verified = $true
        $exitCode = 10
    }
    elseif ($roundResult.state -eq 'ResidueRemains') {
        $terminal.outcome = 'CleanupIncomplete'
        $terminal.exitCode = 60
        $terminal.cleanup.required = $true
        $terminal.cleanup.verified = $false
        $exitCode = 60
    }
    Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
    exit $exitCode
}

if ($Workflow -eq 'RecoverValidationRound') {
    # Independent recovery is a later process. The threat is requiring the
    # initiating laptop, or deleting whatever remains in a subscription.
    # The mechanism is a synthetic resident recovery record plus the same
    # trusted JSON commands as Help. The trust assumption is that the
    # record lists only privately recorded tokens. Safe failure is
    # CleanupIncomplete while any exact owned target remains.
    Write-ContractRecord (New-ProgressRecord -Sequence 1 -Phase 'ValidationRound' -State 'Started' `
        -MessageId 'validation.recovery.started' -CompletedUnits 0 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    $recoveryResult = if ([string]::IsNullOrWhiteSpace($ValidationRoundFixturePath)) {
        New-AzureValidationRoundOutcome -State Rejected `
            -ReasonCode 'VALIDATION.REQUEST_INVALID' -PrivacyBoundary Missing
    }
    else {
        try {
            $recoveryFixtureText = [System.IO.File]::ReadAllText(
                $ValidationRoundFixturePath,
                [System.Text.UTF8Encoding]::new($false, $true)
            )
            $recoveryPrivacy = Test-AzureValidationRoundPrivacyBoundary -Text $recoveryFixtureText
            if ($recoveryPrivacy) {
                New-AzureValidationRoundOutcome -State Rejected `
                    -ReasonCode $recoveryPrivacy -PrivacyBoundary Rejected
            }
            else {
                $recoveryRepositoryRoot = Split-Path -Parent $PSCommandPath
                $recoveryApplicationDirectory = Split-Path -Parent $PSCommandPath
                if (-not (Test-Path -LiteralPath (
                    Join-Path $recoveryRepositoryRoot 'infra/azure-validation/versions.tf'
                ))) {
                    $recoveryRepositoryRoot = Split-Path -Parent $recoveryRepositoryRoot
                }
                $recoveryFixtureSchema = Get-AzureValidationRoundCatalogPath `
                    -RepositoryRoot $recoveryRepositoryRoot `
                    -ApplicationDirectory $recoveryApplicationDirectory `
                    -RelativePath 'schemas/azure-validation-round-execution-request.schema.json'
                $recoveryFixtureValid = $false
                if (-not [string]::IsNullOrWhiteSpace($recoveryFixtureSchema)) {
                    try {
                        $recoveryFixtureValid = Test-Json -Json $recoveryFixtureText `
                            -SchemaFile $recoveryFixtureSchema
                    }
                    catch {
                        $recoveryFixtureValid = $false
                    }
                }
                if (-not $recoveryFixtureValid) {
                    New-AzureValidationRoundOutcome -State Rejected `
                        -ReasonCode 'VALIDATION.REQUEST_INVALID' `
                        -PrivacyBoundary Rejected
                }
                else {
                    $recoveryFixture = & $convertFromJsonCommand `
                        -InputObject $recoveryFixtureText -ErrorAction Stop
                    $recoveryScenario = [string] $recoveryFixture.scenario
                    $recoveryPlatform = New-AzureValidationRoundPlatform -Scenario $recoveryScenario
                    $recoveryPolicy = Get-AzureValidationRoundPolicy
                    $recoveryWorkspaceRejection = $null
                    if ([string]::IsNullOrWhiteSpace($ValidationPrivateWorkspacePath)) {
                        $recoveryWorkspaceRejection = 'VALIDATION.PRIVACY_BOUNDARY_MISSING'
                    }
                    else {
                        $recoveryWorkspaceProbe = [pscustomobject]@{
                            privacyBoundary = 'PrivateExternalWorkspace'
                        }
                        $recoveryWorkspaceRejection = Get-AzureValidationWorkspaceRejection `
                            -PrivateWorkspacePath $ValidationPrivateWorkspacePath `
                            -RepositoryRoot $recoveryRepositoryRoot `
                            -ApplicationDirectory $recoveryApplicationDirectory `
                            -Policy $recoveryPolicy `
                            -Request $recoveryWorkspaceProbe
                    }
                    if ($recoveryWorkspaceRejection) {
                        New-AzureValidationRoundOutcome -State Rejected `
                            -ReasonCode $recoveryWorkspaceRejection `
                            -PrivacyBoundary $(if ([string]::IsNullOrWhiteSpace(
                                $ValidationPrivateWorkspacePath
                            )) { 'Missing' } else { 'Rejected' }) `
                            -RecoveryIndependent:$true
                    }
                    else {
                        $recoveryCommon = @{
                            ClientCount = $null
                            Windows11ClaimingRoute = $false
                            TrustClass = 'ControllerDevTracer'
                            PersistentScopePreserved = $true
                            HostPeeringAbsent = $false
                            TagSweepEmpty = $false
                            UnprotectedLocalMaterialAbsent = $false
                            CleanupMode = 'None'
                            Cancelled = $false
                            CancelPhase = 'None'
                            ExpiryReached = $false
                            CleanupReserveActive = $false
                            CleanupReserveMinutes = [int] $recoveryPolicy.lifetime.minimumCleanupReserveMinutes
                            NewTestsStopped = $true
                            EvidenceExportStopped = $true
                            ExclusiveLeaseHeld = $false
                            LiveTaggedVmCount = $null
                            ResultingTotalExceedsMaximum = $false
                            RecoveryIndependent = $true
                            UnresolvedTargetPreserved = $false
                            UnrelatedTargetPreserved = $false
                            CleanupPending = $false
                            OperationsRecordRetained = $false
                            DocumentedIncident = $false
                            Synthetic = $true
                            PlatformKind = 'Synthetic'
                            AzureContacted = $false
                            PrivacyBoundary = 'PrivateExternalWorkspace'
                            Admitted = $true
                        }
                        Invoke-AzureValidationRoundRecovery -Platform $recoveryPlatform `
                            -Policy $recoveryPolicy `
                            -PrivateWorkspacePath $ValidationPrivateWorkspacePath `
                            -Common $recoveryCommon
                    }
                }
            }
        }
        catch {
            New-AzureValidationRoundOutcome -State Rejected `
                -ReasonCode 'VALIDATION.REQUEST_INVALID' -PrivacyBoundary Missing
        }
    }
    $recoveryCleaned = $recoveryResult.zeroResidue -eq $true
    Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'ValidationRound' `
        -State $(if ($recoveryCleaned) { 'Succeeded' } else { 'Failed' }) `
        -MessageId $(if ($recoveryCleaned) {
            'validation.recovery.succeeded'
        } else {
            'validation.recovery.failed'
        }) -CompletedUnits 1 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord $recoveryResult -ConvertToJsonCommand $convertToJsonCommand
    $terminal = New-TerminalRecord -ReasonCode $recoveryResult.reasonCode `
        -Phase ValidationRound
    $exitCode = 20
    if (($recoveryResult.state -eq 'FailedCleaned' -or
        $recoveryResult.state -eq 'ZeroResidueProven') -and $recoveryResult.zeroResidue) {
        # Leftover cleanup is never a product pass, even when residue is gone.
        $terminal.outcome = 'CompletedWithGaps'
        $terminal.exitCode = 10
        $terminal.cleanup.required = $true
        $terminal.cleanup.verified = $true
        $exitCode = 10
    }
    elseif ($recoveryResult.state -eq 'ResidueRemains') {
        $terminal.outcome = 'CleanupIncomplete'
        $terminal.exitCode = 60
        $terminal.cleanup.required = $true
        $terminal.cleanup.verified = $false
        $exitCode = 60
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
                $gateApplicationDirectory = Split-Path -Parent $PSCommandPath
                $gateLedgerPath = Get-ReleaseGatesCatalogPath `
                    -ApplicationDirectory $gateApplicationDirectory `
                    -RelativePath 'docs/spec/capability-ledger.json'
                $gateRepositoryRoot = $gateApplicationDirectory
                if (-not [string]::IsNullOrWhiteSpace($gateLedgerPath)) {
                    $gateRepositoryRoot = [System.IO.Path]::GetFullPath(
                        (Join-Path (Split-Path -Parent $gateLedgerPath) '..\..')
                    )
                }
                $gatePackSchema = Get-ReleaseGatesCatalogPath `
                    -RepositoryRoot $gateRepositoryRoot `
                    -ApplicationDirectory $gateApplicationDirectory `
                    -RelativePath 'schemas/release-evidence-pack.schema.json'
                $gatePackSchemaValid = $false
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

if ($Workflow -eq 'SignAndVerifyCandidate') {
    # Signing must run on the unsigned generated candidate. The threat is
    # treating a synthetic trailer as a published Trusted release, or hiding
    # a failed gate behind Authenticode. The mechanism is the same trusted
    # JSON commands as Help, with no Azure account or assessment work. The
    # trust assumption is that the request is synthetic. Safe failure is
    # NotStarted without a Trusted label.
    Write-ContractRecord (New-ProgressRecord -Sequence 1 -Phase 'SigningBoundary' -State 'Started' `
        -MessageId 'signing.session.started' -CompletedUnits 0 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    $signingResult = $null
    if ([string]::IsNullOrWhiteSpace($SigningSessionRequestPath) -or
        [string]::IsNullOrWhiteSpace($SigningWorkspacePath)) {
        $signingResult = New-SigningBoundaryResult -State Rejected `
            -ReasonCode 'SIGNING.REQUEST_MISSING'
    }
    else {
        try {
            $signingRequestText = [System.IO.File]::ReadAllText(
                $SigningSessionRequestPath,
                [System.Text.UTF8Encoding]::new($false, $true)
            )
            $signingPrivacy = Test-SigningBoundaryPrivacyBoundary -Text $signingRequestText
            if ($signingPrivacy) {
                $signingResult = New-SigningBoundaryResult -State Rejected `
                    -ReasonCode $signingPrivacy
            }
            else {
                $signingApplicationDirectory = Split-Path -Parent $PSCommandPath
                $signingRepositoryRoot = $signingApplicationDirectory
                $signingPolicyPath = Get-SigningBoundaryCatalogPath `
                    -ApplicationDirectory $signingApplicationDirectory `
                    -RelativePath 'docs/spec/releases/2.0.0-preview.1-signing-boundary.json'
                if (-not [string]::IsNullOrWhiteSpace($signingPolicyPath)) {
                    $signingRepositoryRoot = [System.IO.Path]::GetFullPath(
                        (Join-Path (Split-Path -Parent $signingPolicyPath) '..\..')
                    )
                }
                $signingRequestSchema = Get-SigningBoundaryCatalogPath `
                    -RepositoryRoot $signingRepositoryRoot `
                    -ApplicationDirectory $signingApplicationDirectory `
                    -RelativePath 'schemas/signing-session-request.schema.json'
                $signingRequestSchemaValid = $false
                if (-not [string]::IsNullOrWhiteSpace($signingRequestSchema)) {
                    try {
                        $signingRequestSchemaValid = Test-Json -Json $signingRequestText `
                            -SchemaFile $signingRequestSchema
                    }
                    catch {
                        $signingRequestSchemaValid = $false
                    }
                }
                if (-not $signingRequestSchemaValid) {
                    $signingResult = New-SigningBoundaryResult -State Rejected `
                        -ReasonCode 'SIGNING.REQUEST_INVALID'
                }
                else {
                    $signingRequest = & $convertFromJsonCommand -InputObject $signingRequestText `
                        -ErrorAction Stop
                    $signingResult = Invoke-SigningBoundarySession -Request $signingRequest `
                        -RequestText $signingRequestText `
                        -CandidatePath $PSCommandPath `
                        -PrivateWorkspacePath $SigningWorkspacePath `
                        -RepositoryRoot $signingRepositoryRoot `
                        -ApplicationDirectory $signingApplicationDirectory
                }
            }
        }
        catch {
            $signingResult = New-SigningBoundaryResult -State Rejected `
                -ReasonCode 'SIGNING.REQUEST_INVALID'
        }
    }
    $signingSucceeded = $signingResult.state -eq 'SignedAndVerified'
    Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'SigningBoundary' `
        -State $(if ($signingSucceeded) { 'Succeeded' } else { 'Failed' }) `
        -MessageId $(if ($signingSucceeded) {
            'signing.session.succeeded'
        } else {
            'signing.session.failed'
        }) -CompletedUnits 1 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord $signingResult -ConvertToJsonCommand $convertToJsonCommand
    $terminal = New-TerminalRecord -ReasonCode $signingResult.reasonCode `
        -Phase SigningBoundary
    $exitCode = 20
    if ($signingSucceeded) {
        $terminal.outcome = 'Completed'
        $terminal.exitCode = 0
        $exitCode = 0
    }
    Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
    exit $exitCode
}

if ($Workflow -eq 'QualifyPreviewCandidate') {
    # Qualification must run on the exact generated candidate. The
    # threat is hiding a failed or private pack behind Authenticode,
    # treating this workflow as collection, or claiming live Azure
    # that never started. The mechanism is the same trusted JSON
    # commands as Help, with no Azure create and no assessment work.
    # The trust assumption is that the request is synthetic. Safe
    # failure is NotStarted without derived residue.
    Write-ContractRecord (New-ProgressRecord -Sequence 1 -Phase 'PreviewQualification' `
        -State 'Started' -MessageId 'qualification.started' -CompletedUnits 0 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    $qualifyPolicy = Get-PreviewQualificationPolicy
    $qualifyEvaluation = $null
    if ([string]::IsNullOrWhiteSpace($QualificationRequestPath) -or
        [string]::IsNullOrWhiteSpace($QualificationWorkspacePath)) {
        $qualifyEvaluation = Get-PreviewQualificationRejectedEvaluation `
            -ReasonCode 'QUALIFY.REQUEST_MISSING' -Policy $qualifyPolicy
    }
    else {
        try {
            $qualifyRequestText = [System.IO.File]::ReadAllText(
                $QualificationRequestPath,
                [System.Text.UTF8Encoding]::new($false, $true)
            )
            $qualifyPrivacy = Test-PreviewQualificationPrivacyBoundary -Text $qualifyRequestText
            if ($qualifyPrivacy) {
                $qualifyEvaluation = Get-PreviewQualificationRejectedEvaluation `
                    -ReasonCode $qualifyPrivacy -Policy $qualifyPolicy
            }
            else {
                $qualifyApplicationDirectory = Split-Path -Parent $PSCommandPath
                $qualifyLedgerPath = Get-PreviewQualificationCatalogPath `
                    -ApplicationDirectory $qualifyApplicationDirectory `
                    -RelativePath 'docs/spec/capability-ledger.json'
                $qualifyRepositoryRoot = $qualifyApplicationDirectory
                if (-not [string]::IsNullOrWhiteSpace($qualifyLedgerPath)) {
                    $qualifyRepositoryRoot = [System.IO.Path]::GetFullPath(
                        (Join-Path (Split-Path -Parent $qualifyLedgerPath) '..\..')
                    )
                }
                $qualifyRequestSchema = Get-PreviewQualificationCatalogPath `
                    -RepositoryRoot $qualifyRepositoryRoot `
                    -ApplicationDirectory $qualifyApplicationDirectory `
                    -RelativePath 'schemas/preview-qualification-request.schema.json'
                $qualifyRequestSchemaValid = $false
                if (-not [string]::IsNullOrWhiteSpace($qualifyRequestSchema)) {
                    try {
                        $qualifyRequestSchemaValid = Test-Json -Json $qualifyRequestText `
                            -SchemaFile $qualifyRequestSchema
                    }
                    catch {
                        $qualifyRequestSchemaValid = $false
                    }
                }
                if (-not $qualifyRequestSchemaValid) {
                    $qualifyEvaluation = Get-PreviewQualificationRejectedEvaluation `
                        -ReasonCode 'QUALIFY.REQUEST_INVALID' -Policy $qualifyPolicy
                }
                else {
                    $qualifyRequest = & $convertFromJsonCommand -InputObject $qualifyRequestText `
                        -ErrorAction Stop
                    $qualifyReleasePath = Get-PreviewQualificationCatalogPath `
                        -RepositoryRoot $qualifyRepositoryRoot `
                        -ApplicationDirectory $qualifyApplicationDirectory `
                        -RelativePath 'docs/spec/releases/2.0.0-preview.1.json'
                    $qualifyLedger = $null
                    $qualifyReleaseDefinition = $null
                    $qualifyLedgerDigest = $null
                    if (-not [string]::IsNullOrWhiteSpace($qualifyLedgerPath)) {
                        $qualifyLedgerBytes = [System.IO.File]::ReadAllBytes($qualifyLedgerPath)
                        $qualifyLedgerDigest = Get-PreviewQualificationSha256 `
                            -Bytes $qualifyLedgerBytes
                        $qualifyLedgerText = [System.Text.UTF8Encoding]::new($false, $true).GetString(
                            $qualifyLedgerBytes
                        )
                        $qualifyLedger = & $convertFromJsonCommand -InputObject $qualifyLedgerText `
                            -ErrorAction Stop
                    }
                    if (-not [string]::IsNullOrWhiteSpace($qualifyReleasePath)) {
                        $qualifyReleaseText = [System.IO.File]::ReadAllText(
                            $qualifyReleasePath,
                            [System.Text.UTF8Encoding]::new($false, $true)
                        )
                        $qualifyReleaseDefinition = & $convertFromJsonCommand `
                            -InputObject $qualifyReleaseText -ErrorAction Stop
                    }
                    $qualifyEvaluation = Invoke-PreviewQualification -Request $qualifyRequest `
                        -RequestText $qualifyRequestText -CandidatePath $PSCommandPath `
                        -PrivateWorkspacePath $QualificationWorkspacePath `
                        -RepositoryRoot $qualifyRepositoryRoot `
                        -ApplicationDirectory $qualifyApplicationDirectory `
                        -Ledger $qualifyLedger `
                        -ReleaseDefinition $qualifyReleaseDefinition `
                        -ExpectedLedgerSha256 $qualifyLedgerDigest
                }
            }
        }
        catch {
            $qualifyEvaluation = Get-PreviewQualificationRejectedEvaluation `
                -ReasonCode 'QUALIFY.REQUEST_INVALID' -Policy $qualifyPolicy
        }
    }
    $qualifySucceeded = $qualifyEvaluation.State -in @('Approved', 'Denied') -and
        $qualifyEvaluation.ExitKind -eq 'Completed'
    Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'PreviewQualification' `
        -State $(if ($qualifySucceeded) { 'Succeeded' } else { 'Failed' }) `
        -MessageId $(if ($qualifySucceeded) {
            'qualification.succeeded'
        } else {
            'qualification.failed'
        }) -CompletedUnits 1 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord $qualifyEvaluation.Manifest -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord $qualifyEvaluation.Matrix -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord $qualifyEvaluation.Packet -ConvertToJsonCommand $convertToJsonCommand
    $terminalReason = if ($qualifyEvaluation.State -eq 'Approved') {
        'QUALIFY.APPROVED'
    }
    elseif ($qualifyEvaluation.State -eq 'Denied' -and
        $qualifyEvaluation.ExitKind -eq 'Completed') {
        'QUALIFY.DENIED'
    }
    else {
        $qualifyEvaluation.ReasonCode
    }
    $terminal = New-TerminalRecord -ReasonCode $terminalReason -Phase PreviewQualification
    $exitCode = 20
    if ($qualifyEvaluation.ExitKind -eq 'Completed') {
        $terminal.outcome = 'Completed'
        $terminal.exitCode = 0
        $exitCode = 0
    }
    elseif ($qualifyEvaluation.ExitKind -eq 'CleanupIncomplete') {
        $terminal.outcome = 'CleanupIncomplete'
        $terminal.exitCode = 60
        $terminal.cleanup.required = $true
        $terminal.cleanup.verified = $false
        $exitCode = 60
    }
    Write-ContractRecord $terminal -ConvertToJsonCommand $convertToJsonCommand
    exit $exitCode
}

if ($Workflow -eq 'PublishPreviewRelease') {
    # Publication must run on the exact generated candidate. The
    # threat is hiding a failed or private pack behind Authenticode,
    # treating this workflow as collection, or creating a live GitHub
    # release from synthetic evidence. The mechanism is the same
    # trusted JSON commands as Help, with no GitHub write and no
    # assessment work. The trust assumption is that the request is
    # synthetic. Safe failure is NotStarted without derived residue.
    Write-ContractRecord (New-ProgressRecord -Sequence 1 -Phase 'PreviewPublication' `
        -State 'Started' -MessageId 'publication.started' -CompletedUnits 0 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    $publishPolicy = Get-PreviewPublicationPolicy
    $publishEvaluation = $null
    if ([string]::IsNullOrWhiteSpace($PublicationRequestPath) -or
        [string]::IsNullOrWhiteSpace($PublicationWorkspacePath)) {
        $publishEvaluation = Get-PreviewPublicationRejectedEvaluation `
            -ReasonCode 'PUBLISH.REQUEST_MISSING' -Policy $publishPolicy
    }
    else {
        try {
            $publishRequestText = [System.IO.File]::ReadAllText(
                $PublicationRequestPath,
                [System.Text.UTF8Encoding]::new($false, $true)
            )
            $publishPrivacy = Test-PreviewPublicationPrivacyBoundary -Text $publishRequestText
            if ($publishPrivacy) {
                $publishEvaluation = Get-PreviewPublicationRejectedEvaluation `
                    -ReasonCode $publishPrivacy -Policy $publishPolicy
            }
            else {
                $publishApplicationDirectory = Split-Path -Parent $PSCommandPath
                $publishLedgerPath = Get-PreviewPublicationCatalogPath `
                    -ApplicationDirectory $publishApplicationDirectory `
                    -RelativePath 'docs/spec/capability-ledger.json'
                $publishRepositoryRoot = $publishApplicationDirectory
                if (-not [string]::IsNullOrWhiteSpace($publishLedgerPath)) {
                    $publishRepositoryRoot = [System.IO.Path]::GetFullPath(
                        (Join-Path (Split-Path -Parent $publishLedgerPath) '..\..')
                    )
                }
                $publishRequestSchema = Get-PreviewPublicationCatalogPath `
                    -RepositoryRoot $publishRepositoryRoot `
                    -ApplicationDirectory $publishApplicationDirectory `
                    -RelativePath 'schemas/preview-publication-request.schema.json'
                $publishRequestSchemaValid = $false
                if (-not [string]::IsNullOrWhiteSpace($publishRequestSchema)) {
                    try {
                        $publishRequestSchemaValid = Test-Json -Json $publishRequestText `
                            -SchemaFile $publishRequestSchema
                    }
                    catch {
                        $publishRequestSchemaValid = $false
                    }
                }
                if (-not $publishRequestSchemaValid) {
                    $publishEvaluation = Get-PreviewPublicationRejectedEvaluation `
                        -ReasonCode 'PUBLISH.REQUEST_INVALID' -Policy $publishPolicy
                }
                else {
                    $publishRequest = & $convertFromJsonCommand -InputObject $publishRequestText `
                        -ErrorAction Stop
                    $publishEvaluation = Invoke-PreviewPublication -Request $publishRequest `
                        -RequestText $publishRequestText -CandidatePath $PSCommandPath `
                        -PrivateWorkspacePath $PublicationWorkspacePath `
                        -RepositoryRoot $publishRepositoryRoot `
                        -ApplicationDirectory $publishApplicationDirectory
                }
            }
        }
        catch {
            $publishEvaluation = Get-PreviewPublicationRejectedEvaluation `
                -ReasonCode 'PUBLISH.REQUEST_INVALID' -Policy $publishPolicy
        }
    }
    $publishSucceeded = $publishEvaluation.State -in @(
        'Previewed', 'PublishedAndVerified', 'Denied'
    ) -and $publishEvaluation.ExitKind -eq 'Completed'
    Write-ContractRecord (New-ProgressRecord -Sequence 2 -Phase 'PreviewPublication' `
        -State $(if ($publishSucceeded) { 'Succeeded' } else { 'Failed' }) `
        -MessageId $(if ($publishSucceeded) {
            'publication.succeeded'
        } else {
            'publication.failed'
        }) -CompletedUnits 1 -TotalUnits 2) `
        -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord $publishEvaluation.Preview -ConvertToJsonCommand $convertToJsonCommand
    Write-ContractRecord $publishEvaluation.Result -ConvertToJsonCommand $convertToJsonCommand
    $publishTerminalReason = $publishEvaluation.ReasonCode
    $terminal = New-TerminalRecord -ReasonCode $publishTerminalReason -Phase PreviewPublication
    $exitCode = 20
    if ($publishEvaluation.ExitKind -eq 'Completed') {
        $terminal.outcome = 'Completed'
        $terminal.exitCode = 0
        $exitCode = 0
    }
    elseif ($publishEvaluation.ExitKind -eq 'CleanupIncomplete') {
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
