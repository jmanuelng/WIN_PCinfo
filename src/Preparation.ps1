# Build.ps1 replaces both sentinels with a release-bound, UTF-8 JSON definition
# and its SHA-256 digest. The runtime verifies the digest before the definition
# can influence scope, privilege, network, or package-protection decisions.
$script:PreparationDefinitionBase64 = '__PREPARATION_DEFINITION_BASE64__'
$script:PreparationDefinitionDigest = '__PREPARATION_DEFINITION_SHA256__'

function Test-ApplicationArtifactTrust {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $AuthenticodeCommand
    )

    # The running generated application, not modular source or an embedded
    # checksum, is the trust object. Authenticode binds every script byte to the
    # external Windows trust decision, so editing code and its embedded digest
    # together cannot preserve eligibility. Unsigned development builds fail
    # closed; synthetic fixtures may model trust only in validation-only runs.
    try {
        $signature = & $AuthenticodeCommand -LiteralPath ([System.IO.Path]::GetFullPath($LiteralPath)) -ErrorAction Stop
        [string] $signature.Status -eq 'Valid' -and $null -ne $signature.SignerCertificate
    }
    catch { $false }
}

function Get-PreparationDefinition {
    param(
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand
    )

    try {
        $bytes = [System.Convert]::FromBase64String($script:PreparationDefinitionBase64)
    }
    catch {
        return [pscustomobject]@{ Valid = $false; ReasonCode = 'PREPARATION.INTEGRITY_FAILED' }
    }

    if ((Get-BytesDigest -Bytes $bytes) -ne $script:PreparationDefinitionDigest) {
        return [pscustomobject]@{ Valid = $false; ReasonCode = 'PREPARATION.INTEGRITY_FAILED' }
    }

    try {
        $definition = & $ConvertFromJsonCommand -InputObject (
            [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        ) -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{ Valid = $false; ReasonCode = 'PREPARATION.INTEGRITY_FAILED' }
    }

    $manifestBody = [pscustomobject][ordered]@{
        contractVersion = $definition.applicationManifest.contractVersion
        resources = @($definition.applicationManifest.resources)
    }
    if ((Get-ObjectDigest -Value $manifestBody -ConvertToJsonCommand $ConvertToJsonCommand) -ne
        [string] $definition.applicationManifest.sha256) {
        return [pscustomobject]@{ Valid = $false; ReasonCode = 'PREPARATION.INTEGRITY_FAILED' }
    }

    [pscustomobject]@{ Valid = $true; ReasonCode = 'PREPARATION.READY'; Definition = $definition }
}

function Read-PreparationFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand
    )

    try {
        $text = [System.IO.File]::ReadAllText(
            [System.IO.Path]::GetFullPath($LiteralPath),
            [System.Text.UTF8Encoding]::new($false, $true)
        )
        $fixture = & $ConvertFromJsonCommand -InputObject $text -ErrorAction Stop
    }
    catch {
        $exception = [System.ArgumentException]::new('The preparation fixture is unreadable.')
        $exception.Data['ReasonCode'] = 'PREPARATION.FIXTURE_INVALID'
        throw $exception
    }

    $fields = @(
        'contractVersion', 'artifactTrustValid', 'definitionIntegrityValid',
        'outputDestinationEligible', 'requiredFreeDiskAvailable',
        'localPackageProtectorAvailable', 'recipientProfileResolved',
        'windowsFeatureChangeNotRequired', 'resolvedOutputDestination'
    )
    $actual = @($fixture.PSObject.Properties.Name)
    if (@($actual | Where-Object { $_ -notin $fields }).Count -gt 0 -or
        @($fields | Where-Object { $_ -notin $actual }).Count -gt 0 -or
        [string] $fixture.contractVersion -ne '1.0.0' -or
        @($fields[1..7] | Where-Object { $fixture.$_ -isnot [bool] }).Count -gt 0 -or
        $fixture.resolvedOutputDestination -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string] $fixture.resolvedOutputDestination)) {
        $exception = [System.ArgumentException]::new('The preparation fixture contract is invalid.')
        $exception.Data['ReasonCode'] = 'PREPARATION.FIXTURE_INVALID'
        throw $exception
    }

    [pscustomobject][ordered]@{
        artifactTrustValid = [bool] $fixture.artifactTrustValid
        definitionIntegrityValid = [bool] $fixture.definitionIntegrityValid
        resolvedOutputDestination = [string] $fixture.resolvedOutputDestination
        prerequisiteChecks = @(
            [pscustomobject][ordered]@{ id = 'output-destination-eligible'; resolved = [bool] $fixture.outputDestinationEligible }
            [pscustomobject][ordered]@{ id = 'required-free-disk-available'; resolved = [bool] $fixture.requiredFreeDiskAvailable }
            [pscustomobject][ordered]@{ id = 'local-package-protector-available'; resolved = [bool] $fixture.localPackageProtectorAvailable }
            [pscustomobject][ordered]@{ id = 'recipient-profile-resolved'; resolved = [bool] $fixture.recipientProfileResolved }
            [pscustomobject][ordered]@{ id = 'windows-feature-change-not-required'; resolved = [bool] $fixture.windowsFeatureChangeNotRequired }
        )
    }
}

function Get-ActivePreparationFacts {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $Definition,
        [Parameter(Mandatory)] [bool] $ArtifactTrustValid
    )

    $outputPathResolved = $false
    $freeDiskAvailable = $false
    $resolvedOutput = ''
    try {
        # Full-path and drive resolution is metadata-only: it creates neither
        # the Evidence Workspace nor its destination. The summary exposes only
        # the boolean result, never the host's drive identity or free-byte count.
        $resolvedOutput = [System.IO.Path]::GetFullPath([string] $Request.outputDestination)
        $root = [System.IO.Path]::GetPathRoot($resolvedOutput)
        $networkPath = Test-NetworkPathSyntax -Path $resolvedOutput
        if (-not $networkPath -and -not [string]::IsNullOrWhiteSpace($root)) {
            $drive = [System.IO.DriveInfo]::new($root)
            # DriveType consults the local Windows volume map. IsReady and free
            # space are read only after Fixed proves that UNC and mapped-network
            # storage cannot trigger SMB or another storage request preapproval.
            if ($drive.DriveType -eq [System.IO.DriveType]::Fixed) {
                $outputPathResolved = $drive.IsReady -and -not [System.IO.File]::Exists($resolvedOutput)
                $requiredBytes = [int64] $Definition.requiredFreeDiskMiB * 1MB
                $freeDiskAvailable = $outputPathResolved -and $drive.AvailableFreeSpace -ge $requiredBytes
            }
        }
    }
    catch {
        $outputPathResolved = $false
        $freeDiskAvailable = $false
    }

    # This slice has no initiating-user-bound Local Package Protector. Generic
    # runtime cryptography is not substituted for that domain component: the
    # real prerequisite remains unresolved without creating a key, package,
    # protected file, or recipient material.
    [pscustomobject][ordered]@{
        artifactTrustValid = $ArtifactTrustValid
        definitionIntegrityValid = $true
        resolvedOutputDestination = $resolvedOutput
        prerequisiteChecks = @(
            [pscustomobject][ordered]@{ id = 'output-destination-eligible'; resolved = $outputPathResolved }
            [pscustomobject][ordered]@{ id = 'required-free-disk-available'; resolved = $freeDiskAvailable }
            [pscustomobject][ordered]@{
                id = 'local-package-protector-available'
                # The cryptographic primitive alone is not the initiating-user-
                # bound Local Package Protector. That component is delivered by
                # a later slice, so a real run remains NotStarted until it exists.
                resolved = $false
            }
            [pscustomobject][ordered]@{ id = 'recipient-profile-resolved'; resolved = $true }
            [pscustomobject][ordered]@{ id = 'windows-feature-change-not-required'; resolved = $true }
        )
    }
}

function Resolve-PreparationRecipientSelection {
    param([Parameter(Mandatory)] $Request)

    if ($Request.recipientSelection.mode -eq 'None') {
        return [pscustomobject][ordered]@{
            resolved = $true; mode = 'None'; label = $null; fingerprint = $null
            protectionLevel = $null; profileValidated = $true
            fingerprintConfirmed = $false; reasonCode = 'RECIPIENT.NONE_SELECTED'
            approvedRecipient = $null
        }
    }
    if (-not (Get-Command Import-RecipientProfile -CommandType Function `
            -ErrorAction SilentlyContinue)) {
        return [pscustomobject][ordered]@{
            resolved = $false; mode = 'Profile'; label = $null; fingerprint = $null
            protectionLevel = $null; profileValidated = $false
            fingerprintConfirmed = $false; reasonCode = 'RECIPIENT.PROFILE_VALIDATOR_UNAVAILABLE'
            approvedRecipient = $null
        }
    }
    $admission = Import-RecipientProfile -LiteralPath $Request.recipientSelection.profilePath `
        -ExpectedFingerprint $Request.recipientSelection.fingerprintConfirmation `
        -ForNewPackage
    try {
        [pscustomobject][ordered]@{
            resolved = $admission.state -eq 'Approved'
            mode = 'Profile'
            label = if ($admission.state -eq 'Approved') { [string] $admission.label } else { $null }
            fingerprint = if ($admission.state -eq 'Approved') {
                [string] $admission.fingerprint
            }
            else { $null }
            protectionLevel = if ($admission.state -eq 'Approved') {
                [string] $admission.protectionLevel
            }
            else { $null }
            profileValidated = $admission.state -eq 'Approved'
            fingerprintConfirmed = $admission.state -eq 'Approved'
            reasonCode = [string] $admission.reasonCode
            # The execution fact freezes the exact admitted public certificate,
            # not merely its display label. New-ProtectedEvidencePackage accepts
            # this closed admission object and rechecks the fingerprint/validity
            # before OAEP wrapping. New-PreparationPlan intentionally projects
            # only the human-review fields into the public summary.
            approvedRecipient = if ($admission.state -eq 'Approved') {
                [pscustomobject][ordered]@{
                    state = 'Approved'; admissionKind = 'ApprovedRecipientForPackage'
                    fingerprint = [string] $admission.fingerprint
                    label = [string] $admission.label
                    protectionLevel = [string] $admission.protectionLevel
                    certificateDerBase64 = [System.Convert]::ToBase64String(
                        $admission.certificate.RawData
                    )
                }
            }
            else { $null }
        }
    }
    finally { if ($null -ne $admission.certificate) { $admission.certificate.Dispose() } }
}

function New-PreparationPlan {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $Definition,
        [Parameter(Mandatory)] $PreparationFacts,
        [Parameter(Mandatory)] $ConvertToJsonCommand
    )

    # Network consent is an exact two-state Windows assessment boundary. The
    # enabled state names protocol classes and purposes; it does not authorize
    # arbitrary internet access, authenticated tenant access, or Azure control-
    # plane activity. Local Only therefore materializes as a literal empty list.
    $networkRequests = if ($Request.networkBehavior -eq 'MicrosoftConnectivityEnabled') {
        @(
            [pscustomobject][ordered]@{ protocol = 'DNS'; purpose = 'Resolve release-bound Microsoft service endpoints' }
            [pscustomobject][ordered]@{ protocol = 'TCP-TLS-HTTP'; purpose = 'Measure unauthenticated Microsoft service reachability' }
        )
    }
    else { @() }

    $planBody = [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.preparation-plan'
        contractVersion = '1.0.0'
        release = [string] $Definition.release
        requestDigest = Get-ObjectDigest -Value $Request -ConvertToJsonCommand $ConvertToJsonCommand
        scope = [pscustomobject][ordered]@{
            profileId = [string] $Definition.profileId
            profileName = [string] $Definition.profileName
            capabilities = @($Definition.capabilities)
        }
        operations = @($Definition.operations)
        # This is the exact release-owned operation contract approved before
        # collection. It freezes the executable, structured sources, context,
        # privilege, network behavior, bounds, and safe-failure restrictions;
        # the collector cannot renegotiate any of them after approval.
        deviceReadiness = $Definition.deviceReadiness
        # Firmware, Secure Boot, and TPM use the Administrator operation that
        # is already present in the immutable Privileged Collection Plan. This
        # second release policy freezes its sources, exact evidence fields,
        # deadlines, interpretation rules, and no-write boundary before the
        # single preparation approval and before Windows may display UAC.
        firmwareReadiness = $Definition.firmwareReadiness
        # Registration and enrollment use two standard-user native API
        # projections and the one preapproved SYSTEM sub-plan. Freezing their
        # complete release policy here prevents a later source, context, tenant
        # request, or identifier field from being introduced after approval.
        identityEnrollment = $Definition.identityEnrollment
        # This is a declaration, not elevation. A later execution slice may
        # create at most one Windows administrator boundary and may use SYSTEM
        # only for the predefined evidence sources frozen into that same plan.
        # No command line or script text is accepted from the request.
        privilege = [pscustomobject][ordered]@{
            elevationRequired = $true
            maximumUacInteractions = 1
            standardUserPreparation = $true
            privilegedOperationsFrozen = $true
            systemContext = 'PredefinedRequiredOperationsOnly'
            laterPromptsAllowed = $false
            approvalBoundary = 'PreparationSummary'
            elevationConsent = 'IncludedInPreparationApproval'
            elevationPromptAfterApprovalAllowed = $false
            privilegedOperations = @($Definition.operations | Where-Object {
                $_.context -in @('Administrator', 'LocalSystem')
            })
        }
        dependencies = [pscustomobject][ordered]@{
            runtime = 'Stable PowerShell 7.6 or later 7.x'
            builtInModulesOnly = $true
            installations = @()
            agreements = @()
        }
        estimates = [pscustomobject][ordered]@{
            durationMinutes = 30
            workspaceDiskMiB = 256
            protectedPackageDiskMiB = 100
        }
        network = [pscustomobject][ordered]@{
            behavior = [string] $Request.networkBehavior
            automaticTelemetry = $false
            authenticatedCloudCollection = $false
            plannedRequests = @($networkRequests)
        }
        # Evidence protection is fixed before collection so plaintext or a new
        # recipient cannot become a late escape hatch. The plan carries only the
        # verified public profile facts needed for human review; the private
        # profile path and all private-key/provider material remain outside it.
        output = [pscustomobject][ordered]@{
            requestedDestination = [string] $Request.outputDestination
            destination = [string] $PreparationFacts.resolvedOutputDestination
            protection = [pscustomobject][ordered]@{
                mode = 'LocalPackageProtector'
                plaintextSharingArtifactAllowed = $false
            }
            recipientProfile = [pscustomobject][ordered]@{
                mode = [string] $PreparationFacts.recipientSelection.mode
                selectedBeforeCollection = $true
                maximumRecipients = 1
                label = $PreparationFacts.recipientSelection.label
                fingerprint = $PreparationFacts.recipientSelection.fingerprint
                protectionLevel = $PreparationFacts.recipientSelection.protectionLevel
                profileValidated = [bool] $PreparationFacts.recipientSelection.profileValidated
                fingerprintConfirmed = [bool] $PreparationFacts.recipientSelection.fingerprintConfirmed
            }
        }
        windowsFeatures = [pscustomobject][ordered]@{
            observationsPlanned = $true
            changes = @()
        }
        # Fresh Azure Client VM Validation is release evidence, never an action
        # performed by a customer Assessment Run. Keeping support promotion out
        # of this plan prevents local approval from becoming Azure authority.
        limitations = @(
            'Preview support claims require separate qualifying validation evidence.'
            'No tenant intent, compliance certification, overall score, or automatic remediation is produced.'
            'Unknown context becomes Indeterminate and tenant-only gaps become discovery tasks.'
        )
        # Preparation invokes no collector and starts no child process. Process
        # control, deadlines, cancellation, and child termination belong to the
        # future frozen execution plan and cannot be inferred from approval here.
        sideEffects = [pscustomobject][ordered]@{
            performedDuringPreparation = $false
            afterApproval = @('CreateEvidenceWorkspace', 'ExecuteFrozenStandardPlan', 'ExecutePrivilegedCollectionPlan', 'ProtectEvidencePackage')
            deviceConfigurationChanges = @()
        }
        cleanup = [pscustomobject][ordered]@{
            requiredAfterExecution = $true
            planned = @('RemoveTemporaryDependencyState', 'RemoveEvidenceWorkspaceAfterPackaging', 'VerifyNoTemporaryResidue')
            staleRunRecovery = [pscustomobject][ordered]@{
                requested = [bool] $Request.automationChoices.allowStaleRecovery
                mode = 'CleanupOnly'
                collectionResumeAllowed = $false
            }
        }
        governingResources = @($Definition.governingResources)
        integrity = [pscustomobject][ordered]@{
            embeddedDefinitionSha256 = $script:PreparationDefinitionDigest
            applicationManifestSha256 = [string] $Definition.applicationManifest.sha256
            applicationResources = @($Definition.applicationManifest.resources)
        }
    }

    $digest = Get-ObjectDigest -Value $planBody -ConvertToJsonCommand $ConvertToJsonCommand
    [pscustomobject][ordered]@{
        Plan = $planBody
        Digest = $digest
    }
}

function New-PreparationSummary {
    param(
        [Parameter(Mandatory)] $PlanResult,
        [Parameter(Mandatory)] [object[]] $PrerequisiteChecks
    )

    $unresolved = @($PrerequisiteChecks | Where-Object { -not $_.resolved } | ForEach-Object { $_.id })
    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.preparation-summary'
        contractVersion = '1.0.0'
        planDigest = $PlanResult.Digest
        requestDigest = $PlanResult.Plan.requestDigest
        readyForApproval = $unresolved.Count -eq 0
        criticalPrerequisites = [pscustomobject][ordered]@{
            resolved = $unresolved.Count -eq 0
            checks = @($PrerequisiteChecks)
            unresolved = $unresolved
        }
        plan = $PlanResult.Plan
        approval = [pscustomobject][ordered]@{
            instruction = 'Approve this plan and its frozen elevation boundary once; no later prompt may add scope, authority, agreement, elevation, or a recipient.'
            automationSwitch = '-AcceptPreparation'
            guidedToken = 'APPROVE'
            runAnywayAvailable = $false
        }
    }
}

function Invoke-PreparationGate {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $RuntimeResult,
        [Parameter(Mandatory)] [bool] $ArtifactTrustValid,
        [Parameter(Mandatory)] [ValidateSet('Guided', 'Automation')] [string] $Mode,
        [Parameter(Mandatory)] [bool] $AcceptPreparation,
        [Parameter(Mandatory)] $ValidationContext,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand,
        [Parameter(Mandatory)] $TestJsonCommand
    )

    $preparationFixturePath = [string] $ValidationContext.PreparationFixturePath
    $contractFixturePath = [string] $ValidationContext.ContractFixturePath
    $runFixturePath = [string] $ValidationContext.RunFixturePath
    $privilegedCollectionFixturePath = [string] $ValidationContext.PrivilegedCollectionFixturePath
    $systemCollectionFixturePath = [string] $ValidationContext.SystemCollectionFixturePath
    $evidenceWorkspaceFixturePath = [string] $ValidationContext.EvidenceWorkspaceFixturePath
    $protectedPackageFixturePath = [string] $ValidationContext.ProtectedPackageFixturePath
    $recipientSharingFixturePath = [string] $ValidationContext.RecipientSharingFixturePath
    $deviceReadinessFixturePath = [string] $ValidationContext.DeviceReadinessFixturePath
    $identityEnrollmentFixturePath = [string] $ValidationContext.IdentityEnrollmentFixturePath
    $validationFixture = [bool] $ValidationContext.IsFixture
    $requestDigest = Get-RequestDigest -Request $Request -ConvertToJsonCommand $ConvertToJsonCommand
    $definitionResult = Get-PreparationDefinition -ConvertFromJsonCommand $ConvertFromJsonCommand `
        -ConvertToJsonCommand $ConvertToJsonCommand
    if (-not $definitionResult.Valid) {
        Write-ContractRecord (New-TerminalRecord -ReasonCode 'PREPARATION.INTEGRITY_FAILED' `
            -RequestDigest $requestDigest -ValidationFixture $ValidationFixture -RuntimeResult $RuntimeResult `
            -Phase 'Preparation') -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    try {
        $facts = if ([string]::IsNullOrWhiteSpace($PreparationFixturePath)) {
            Get-ActivePreparationFacts -Request $Request -Definition $definitionResult.Definition `
                -ArtifactTrustValid $ArtifactTrustValid
        }
        else {
            Read-PreparationFixture -LiteralPath $PreparationFixturePath `
                -ConvertFromJsonCommand $ConvertFromJsonCommand
        }
    }
    catch {
        $fixtureReason = if ($_.Exception.Data.Contains('ReasonCode')) {
            [string] $_.Exception.Data['ReasonCode']
        }
        else { 'PREPARATION.FIXTURE_INVALID' }
        Write-ContractRecord (New-TerminalRecord -ReasonCode $fixtureReason -RequestDigest $requestDigest `
            -ValidationFixture $true -RuntimeResult $RuntimeResult -Phase 'Preparation') `
            -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    $recipientSelection = Resolve-PreparationRecipientSelection -Request $Request
    $recipientCheck = @($facts.prerequisiteChecks | Where-Object id -eq 'recipient-profile-resolved')[0]
    $recipientCheck.resolved = [bool] $recipientCheck.resolved -and
        [bool] $recipientSelection.resolved
    $facts | Add-Member -MemberType NoteProperty -Name recipientSelection `
        -Value $recipientSelection -Force

    # Fixtures can only reduce trust. They cannot make corrupt embedded bytes,
    # an application manifest, or a governing resource valid and cannot create
    # a Verification Override for a signature, digest, manifest, or attestation.
    if (-not $facts.artifactTrustValid -or -not $facts.definitionIntegrityValid) {
        Write-ContractRecord (New-TerminalRecord -ReasonCode 'PREPARATION.INTEGRITY_FAILED' `
            -RequestDigest $requestDigest -ValidationFixture $ValidationFixture -RuntimeResult $RuntimeResult `
            -Phase 'Preparation') -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    $planResult = New-PreparationPlan -Request $Request -Definition $definitionResult.Definition `
        -PreparationFacts $facts `
        -ConvertToJsonCommand $ConvertToJsonCommand
    $summary = New-PreparationSummary -PlanResult $planResult -PrerequisiteChecks $facts.prerequisiteChecks
    Write-ContractRecord $summary -ConvertToJsonCommand $ConvertToJsonCommand

    if (-not $summary.readyForApproval) {
        Write-ContractRecord (New-TerminalRecord -ReasonCode 'PREPARATION.PREREQUISITE_UNRESOLVED' `
            -RequestDigest $requestDigest -ValidationFixture $ValidationFixture -RuntimeResult $RuntimeResult `
            -Phase 'Preparation' -PlanDigest $planResult.Digest -PreparationDecision 'Unavailable') `
            -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    $accepted = if ($Mode -eq 'Automation') {
        $AcceptPreparation
    }
    else {
        [string]::Equals([System.Console]::In.ReadLine(), 'APPROVE', [System.StringComparison]::Ordinal)
    }
    $decision = if ($accepted) { 'Accepted' } else { 'Declined' }
    $selectedExecutionFixtures = @(
        @($contractFixturePath, $runFixturePath, $privilegedCollectionFixturePath,
            $systemCollectionFixturePath, $evidenceWorkspaceFixturePath,
            $protectedPackageFixturePath, $recipientSharingFixturePath,
            $deviceReadinessFixturePath, $identityEnrollmentFixturePath) |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) }
    )
    if ($accepted -and $selectedExecutionFixtures.Count -gt 1) {
        Write-ContractRecord (New-TerminalRecord -ReasonCode 'PREPARATION.FIXTURE_CONFLICT' `
            -RequestDigest $requestDigest -ValidationFixture $true -RuntimeResult $RuntimeResult `
            -Phase 'Preparation' -PlanDigest $planResult.Digest -PreparationDecision $decision) `
            -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }
    if ($accepted -and -not [string]::IsNullOrWhiteSpace($ContractFixturePath)) {
        return Invoke-ContractFixtureValidation -LiteralPath $ContractFixturePath `
            -RuntimeResult $RuntimeResult -RequestDigest $requestDigest -PlanDigest $planResult.Digest `
            -ConvertFromJsonCommand $ConvertFromJsonCommand -ConvertToJsonCommand $ConvertToJsonCommand `
            -TestJsonCommand $TestJsonCommand
    }
    if ($accepted -and -not [string]::IsNullOrWhiteSpace($RunFixturePath)) {
        return Invoke-RunLifecycleFixture -LiteralPath $RunFixturePath `
            -ConvertFromJsonCommand $ConvertFromJsonCommand `
            -ConvertToJsonCommand $ConvertToJsonCommand
    }
    if ($accepted -and -not [string]::IsNullOrWhiteSpace($privilegedCollectionFixturePath)) {
        return Invoke-PrivilegedCollectionPlanFixture -LiteralPath $privilegedCollectionFixturePath `
            -PreparationPlan $planResult.Plan -PlanDigest $planResult.Digest `
            -ConvertFromJsonCommand $ConvertFromJsonCommand `
            -ConvertToJsonCommand $ConvertToJsonCommand
    }
    if ($accepted -and -not [string]::IsNullOrWhiteSpace($systemCollectionFixturePath)) {
        return Invoke-SystemCollectionPlanFixture -LiteralPath $systemCollectionFixturePath `
            -PreparationPlan $planResult.Plan -PreparationPlanDigest $planResult.Digest `
            -ConvertFromJsonCommand $ConvertFromJsonCommand `
            -ConvertToJsonCommand $ConvertToJsonCommand
    }
    if ($accepted -and -not [string]::IsNullOrWhiteSpace($evidenceWorkspaceFixturePath)) {
        return Invoke-EvidenceWorkspaceFixture -LiteralPath $evidenceWorkspaceFixturePath `
            -RuntimeResult $RuntimeResult -RequestDigest $requestDigest `
            -PlanDigest $planResult.Digest -ConvertFromJsonCommand $ConvertFromJsonCommand `
            -ConvertToJsonCommand $ConvertToJsonCommand `
            -RecoveryAuthorized ([bool] $Request.automationChoices.allowStaleRecovery)
    }
    if ($accepted -and -not [string]::IsNullOrWhiteSpace($protectedPackageFixturePath)) {
        return Invoke-ProtectedPackageFixture -LiteralPath $protectedPackageFixturePath `
            -RuntimeResult $RuntimeResult -RequestDigest $requestDigest `
            -PlanDigest $planResult.Digest -ConvertFromJsonCommand $ConvertFromJsonCommand `
            -ConvertToJsonCommand $ConvertToJsonCommand
    }
    if ($accepted -and -not [string]::IsNullOrWhiteSpace($recipientSharingFixturePath)) {
        return Invoke-RecipientSharingFixture -LiteralPath $recipientSharingFixturePath `
            -RuntimeResult $RuntimeResult -RequestDigest $requestDigest `
            -PlanDigest $planResult.Digest -ConvertFromJsonCommand $ConvertFromJsonCommand `
            -ConvertToJsonCommand $ConvertToJsonCommand `
            -ApprovedRecipient $recipientSelection.approvedRecipient
    }
    if ($accepted -and -not [string]::IsNullOrWhiteSpace($deviceReadinessFixturePath)) {
        return Invoke-DeviceReadinessSlice -LiteralPath $deviceReadinessFixturePath `
            -PreparationPlan $planResult.Plan `
            -ApprovedOutputDestination ([string]$planResult.Plan.output.destination) `
            -ApprovedRecipient $recipientSelection.approvedRecipient `
            -RequestDigest $requestDigest -PlanDigest $planResult.Digest `
            -ConvertFromJsonCommand $ConvertFromJsonCommand `
            -ConvertToJsonCommand $ConvertToJsonCommand -TestJsonCommand $TestJsonCommand
    }
    if ($accepted -and -not [string]::IsNullOrWhiteSpace($identityEnrollmentFixturePath)) {
        return Invoke-DeviceReadinessSlice `
            -IdentityEnrollmentLiteralPath $identityEnrollmentFixturePath `
            -PreparationPlan $planResult.Plan `
            -ApprovedOutputDestination ([string]$planResult.Plan.output.destination) `
            -ApprovedRecipient $recipientSelection.approvedRecipient `
            -RequestDigest $requestDigest -PlanDigest $planResult.Digest `
            -ConvertFromJsonCommand $ConvertFromJsonCommand `
            -ConvertToJsonCommand $ConvertToJsonCommand -TestJsonCommand $TestJsonCommand
    }
    if ($accepted -and -not $ValidationFixture) {
        return Invoke-DeviceReadinessSlice `
            -PreparationPlan $planResult.Plan `
            -ApprovedOutputDestination ([string]$planResult.Plan.output.destination) `
            -ApprovedRecipient $recipientSelection.approvedRecipient `
            -RequestDigest $requestDigest -PlanDigest $planResult.Digest `
            -ConvertFromJsonCommand $ConvertFromJsonCommand `
            -ConvertToJsonCommand $ConvertToJsonCommand -TestJsonCommand $TestJsonCommand
    }
    $reasonCode = if ($accepted -and $ValidationFixture) {
        # Synthetic facts can prove resolution but can never reach collectors.
        'PREPARATION.VALIDATION_ONLY'
    }
    elseif ($accepted) {
        'SLICE.POST_APPROVAL_EXECUTION_NOT_IMPLEMENTED'
    }
    else { 'PREPARATION.DECLINED' }
    Write-ContractRecord (New-TerminalRecord -ReasonCode $reasonCode -RequestDigest $requestDigest `
        -ValidationFixture $ValidationFixture -RuntimeResult $RuntimeResult -Phase 'Preparation' `
        -PlanDigest $planResult.Digest -PreparationDecision $decision) `
        -ConvertToJsonCommand $ConvertToJsonCommand
    return 20
}
