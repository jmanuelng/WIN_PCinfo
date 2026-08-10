# Build.ps1 replaces both sentinels with a release-bound, UTF-8 JSON definition
# and its SHA-256 digest. The runtime verifies the digest before the definition
# can influence scope, privilege, network, or package-protection decisions.
$script:PreparationDefinitionBase64 = '__PREPARATION_DEFINITION_BASE64__'
$script:PreparationDefinitionDigest = '__PREPARATION_DEFINITION_SHA256__'

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

    $fields = @('contractVersion', 'definitionIntegrityValid', 'criticalPrerequisitesAvailable')
    $actual = @($fixture.PSObject.Properties.Name)
    if (@($actual | Where-Object { $_ -notin $fields }).Count -gt 0 -or
        @($fields | Where-Object { $_ -notin $actual }).Count -gt 0 -or
        [string] $fixture.contractVersion -ne '1.0.0' -or
        $fixture.definitionIntegrityValid -isnot [bool] -or
        $fixture.criticalPrerequisitesAvailable -isnot [bool]) {
        $exception = [System.ArgumentException]::new('The preparation fixture contract is invalid.')
        $exception.Data['ReasonCode'] = 'PREPARATION.FIXTURE_INVALID'
        throw $exception
    }

    [pscustomobject][ordered]@{
        definitionIntegrityValid = [bool] $fixture.definitionIntegrityValid
        prerequisiteChecks = @(
            [pscustomobject][ordered]@{
                id = 'synthetic-critical-prerequisites'
                resolved = [bool] $fixture.criticalPrerequisitesAvailable
            }
        )
    }
}

function Get-ActivePreparationFacts {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $RuntimeFacts,
        [Parameter(Mandatory)] $Definition
    )

    $outputPathResolved = $false
    $freeDiskAvailable = $false
    try {
        # Full-path and drive resolution is metadata-only: it creates neither
        # the Evidence Workspace nor its destination. The summary exposes only
        # the boolean result, never the host's drive identity or free-byte count.
        $resolvedOutput = [System.IO.Path]::GetFullPath([string] $Request.outputDestination)
        $root = [System.IO.Path]::GetPathRoot($resolvedOutput)
        $drive = [System.IO.DriveInfo]::new($root)
        $outputPathResolved = -not [string]::IsNullOrWhiteSpace($root) -and $drive.IsReady -and
            -not [System.IO.File]::Exists($resolvedOutput)
        $requiredBytes = [int64] $Definition.requiredFreeDiskMiB * 1MB
        $freeDiskAvailable = $outputPathResolved -and $drive.AvailableFreeSpace -ge $requiredBytes
    }
    catch {
        $outputPathResolved = $false
        $freeDiskAvailable = $false
    }

    # RuntimeCompatibility already proved exact cryptographic behavior using
    # disposable synthetic buffers. Preparation consumes only that boolean; it
    # creates no key, evidence package, protected file, or recipient material.
    $packageProtectionPlanned = @($Definition.operations | Where-Object {
        $_.operationId -eq 'protect-evidence-package'
    }).Count -eq 1
    [pscustomobject][ordered]@{
        definitionIntegrityValid = $true
        prerequisiteChecks = @(
            [pscustomobject][ordered]@{ id = 'output-destination-eligible'; resolved = $outputPathResolved }
            [pscustomobject][ordered]@{ id = 'required-free-disk-available'; resolved = $freeDiskAvailable }
            [pscustomobject][ordered]@{
                id = 'local-package-protection-compatible'
                resolved = [bool] $RuntimeFacts.cryptography -and $packageProtectionPlanned
            }
            [pscustomobject][ordered]@{ id = 'recipient-profile-resolved'; resolved = $true }
            [pscustomobject][ordered]@{ id = 'windows-feature-change-not-required'; resolved = $true }
        )
    }
}

function New-PreparationPlan {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] $Definition,
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
        # recipient cannot become a late escape hatch. The Local Package
        # Protector owns local cryptographic access; a future verified Recipient
        # Profile may add zero or one recipient through a new reviewed plan.
        output = [pscustomobject][ordered]@{
            destination = [string] $Request.outputDestination
            protection = [pscustomobject][ordered]@{
                mode = 'LocalPackageProtector'
                plaintextSharingArtifactAllowed = $false
            }
            recipientProfile = [pscustomobject][ordered]@{
                mode = 'None'
                selectedBeforeCollection = $true
                maximumRecipients = 1
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
            afterApproval = @('CreateEvidenceWorkspace', 'ExecuteFrozenStandardPlan', 'ExecuteFrozenPrivilegedPlan', 'ProtectEvidencePackage')
            deviceConfigurationChanges = @()
        }
        cleanup = [pscustomobject][ordered]@{
            requiredAfterExecution = $true
            planned = @('RemoveTemporaryDependencyState', 'RemoveEvidenceWorkspaceAfterPackaging', 'VerifyNoTemporaryResidue')
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
        [Parameter(Mandatory)] $RuntimeFacts,
        [Parameter(Mandatory)] $RuntimeResult,
        [Parameter(Mandatory)] [ValidateSet('Guided', 'Automation')] [string] $Mode,
        [Parameter(Mandatory)] [bool] $AcceptPreparation,
        [Parameter()] [AllowEmptyString()] [string] $PreparationFixturePath,
        [Parameter(Mandatory)] [bool] $ValidationFixture,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand
    )

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
            Get-ActivePreparationFacts -Request $Request -RuntimeFacts $RuntimeFacts `
                -Definition $definitionResult.Definition
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

    # Fixtures can only reduce trust. They cannot make corrupt embedded bytes,
    # an application manifest, or a governing resource valid and cannot create
    # a Verification Override for a signature, digest, manifest, or attestation.
    if (-not $facts.definitionIntegrityValid) {
        Write-ContractRecord (New-TerminalRecord -ReasonCode 'PREPARATION.INTEGRITY_FAILED' `
            -RequestDigest $requestDigest -ValidationFixture $ValidationFixture -RuntimeResult $RuntimeResult `
            -Phase 'Preparation') -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    $planResult = New-PreparationPlan -Request $Request -Definition $definitionResult.Definition `
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
