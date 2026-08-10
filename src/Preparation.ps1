# Build.ps1 replaces both sentinels with a release-bound, UTF-8 JSON definition
# and its SHA-256 digest. The runtime verifies the digest before the definition
# can influence scope, privilege, network, or package-protection decisions.
$script:PreparationDefinitionBase64 = '__PREPARATION_DEFINITION_BASE64__'
$script:PreparationDefinitionDigest = '__PREPARATION_DEFINITION_SHA256__'

function Get-Sha256HexFromBytes {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        (($sha256.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-PreparationDefinition {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    try {
        $bytes = [System.Convert]::FromBase64String($script:PreparationDefinitionBase64)
    }
    catch {
        return [pscustomobject]@{ Valid = $false; ReasonCode = 'PREPARATION.INTEGRITY_FAILED' }
    }

    if ((Get-Sha256HexFromBytes -Bytes $bytes) -ne $script:PreparationDefinitionDigest) {
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
        criticalPrerequisitesAvailable = [bool] $fixture.criticalPrerequisitesAvailable
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
            afterApproval = @('CreateEvidenceWorkspace', 'RequestOneElevation', 'RunFrozenCollectors', 'ProtectEvidencePackage')
            deviceConfigurationChanges = @()
        }
        cleanup = [pscustomobject][ordered]@{
            requiredAfterExecution = $true
            planned = @('RemoveTemporaryDependencyState', 'RemoveEvidenceWorkspaceAfterPackaging', 'VerifyNoTemporaryResidue')
        }
        governingResources = @($Definition.governingResources)
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
        [Parameter(Mandatory)] [bool] $CriticalPrerequisitesAvailable
    )

    $plan = $PlanResult.Plan
    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.preparation-summary'
        contractVersion = '1.0.0'
        planDigest = $PlanResult.Digest
        requestDigest = $plan.requestDigest
        readyForApproval = $CriticalPrerequisitesAvailable
        criticalPrerequisites = [pscustomobject][ordered]@{
            resolved = $CriticalPrerequisitesAvailable
            unresolved = if ($CriticalPrerequisitesAvailable) { @() } else { @('PREPARATION_FIXTURE_CRITICAL_PREREQUISITE') }
        }
        scope = $plan.scope
        privilege = $plan.privilege
        dependencies = $plan.dependencies
        estimates = $plan.estimates
        network = $plan.network
        output = $plan.output
        windowsFeatures = $plan.windowsFeatures
        limitations = $plan.limitations
        sideEffects = $plan.sideEffects
        cleanup = $plan.cleanup
        approval = [pscustomobject][ordered]@{
            instruction = 'Approve exactly this plan once; any later scope, authority, agreement, elevation, or recipient change requires a new run.'
            automationSwitch = '-AcceptPreparation'
            guidedToken = 'APPROVE'
            runAnywayAvailable = $false
        }
    }
}
