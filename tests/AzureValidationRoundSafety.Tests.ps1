[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/AzureValidationAdmission.ps1')
. (Join-Path $repositoryRoot 'src/AzureValidationRound.ps1')

$policy = Get-AzureValidationRoundPolicy
$outcomeSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-round-outcome.schema.json'
$oneClientPath = Join-Path $PSScriptRoot 'fixtures/azure-validation-round-one-client.json'
$fourClientPath = Join-Path $PSScriptRoot 'fixtures/azure-validation-round-four-clients.json'
$plan = Get-Content -LiteralPath $oneClientPath -Raw | ConvertFrom-Json -Depth 20
$fourPlan = Get-Content -LiteralPath $fourClientPath -Raw | ConvertFrom-Json -Depth 20

function New-RoundWorkspace {
    param([Parameter(Mandatory)] [string] $Name)
    $root = Join-Path ([System.IO.Path]::GetTempPath()) "win-pcinfo-azure-safety-$Name"
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $root -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $root $policy.privacy.markerFileName),
        ($policy.privacy.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $root
}

function Remove-RoundWorkspace {
    param([Parameter(Mandatory)] [string] $Path)
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Invoke-SafetyRound {
    param(
        [Parameter(Mandatory)] [string] $Scenario,
        [Parameter(Mandatory)] [string] $WorkspacePath,
        [Parameter()] $PlanObject = $plan,
        [Parameter()] $Platform
    )

    $arguments = @{
        Plan = $PlanObject
        Scenario = $Scenario
        PrivateWorkspacePath = $WorkspacePath
        RepositoryRoot = $repositoryRoot
        ApplicationDirectory = (Join-Path $repositoryRoot 'artifacts')
    }
    if ($null -ne $Platform) {
        $arguments.Platform = $Platform
    }
    Invoke-AzureValidationRound @arguments
}

function Assert-PublicSafetyOutcome {
    param(
        [Parameter(Mandatory)] $Outcome,
        [Parameter(Mandatory)] [string] $Because,
        [Parameter()] [string] $WorkspacePath
    )

    $json = $Outcome | ConvertTo-Json -Compress -Depth 20
    Assert-Equal $true (Test-Json -Json $json -SchemaFile $outcomeSchemaPath) `
        "$Because outcome satisfies the public sanitized schema"
    Assert-Equal 360 $Outcome.hardExpiryMinutes "$Because shows the six-hour hard expiry"
    Assert-Equal 7 $Outcome.completedRecordRetentionDays `
        "$Because shows the seven-day completed-record ceiling"
    Assert-Equal $false $Outcome.qualifyingEvidence "$Because is not qualifying evidence"
    Assert-Equal $false $Outcome.sliceDeliversCapability "$Because does not deliver a capability"
    Assert-Equal $false $Outcome.azureContacted "$Because does not contact Azure"
    if (-not [string]::IsNullOrWhiteSpace($WorkspacePath)) {
        Assert-Equal $false ($json -match [regex]::Escape($WorkspacePath)) `
            "$Because omits the private workspace path"
    }
    foreach ($needle in @(
        '(?i)/subscriptions/'
        '(?i)\btenant\b'
        '(?i)clientSecret'
        '(?i)temporary_admin_password'
        '(?i)\.terraform'
        '(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+'
    )) {
        Assert-Equal $false ($json -match $needle) "$Because must not match $needle"
    }
}

$owned = New-Object System.Collections.Generic.List[string]
try {
    $leaseWorkspace = New-RoundWorkspace -Name 'lease-busy'
    $owned.Add($leaseWorkspace)
    $leaseBusy = Invoke-SafetyRound -Scenario LeaseBusy -WorkspacePath $leaseWorkspace
    Assert-PublicSafetyOutcome $leaseBusy 'busy exclusive lease' -WorkspacePath $leaseWorkspace
    Assert-Equal 'VALIDATION.LEASE_UNAVAILABLE' $leaseBusy.reasonCode `
        'a held exclusive lease rejects the next admission'
    Assert-Equal $false $leaseBusy.created 'a busy lease never creates'
    Assert-Equal $false $leaseBusy.exclusiveLeaseHeld 'the rejected caller does not hold the lease'

    $liveFourWorkspace = New-RoundWorkspace -Name 'live-four'
    $owned.Add($liveFourWorkspace)
    $liveFourPlatform = New-AzureValidationRoundPlatform -Scenario CompleteZeroResidue
    foreach ($token in @(
        'synthetic-live-tagged-01'
        'synthetic-live-tagged-02'
        'synthetic-live-tagged-03'
        'synthetic-live-tagged-04'
    )) {
        $null = $liveFourPlatform.LiveTaggedVms.Add($token)
    }
    $fifthByCount = Invoke-SafetyRound -Scenario CompleteZeroResidue `
        -WorkspacePath $liveFourWorkspace -Platform $liveFourPlatform
    Assert-PublicSafetyOutcome $fifthByCount 'four live plus one requested' `
        -WorkspacePath $liveFourWorkspace
    Assert-Equal 'VALIDATION.VM_COUNT_UNSAFE' $fifthByCount.reasonCode `
        'four live tagged VMs plus one requested client is a fifth VM'
    Assert-Equal $true $fifthByCount.resultingTotalExceedsMaximum `
        'the resulting total is reported as over the ceiling'
    Assert-Equal 4 $fifthByCount.liveTaggedVmCount 'the lease recounts four live tagged VMs'
    Assert-Equal $false $fifthByCount.created 'a fifth resulting VM is never created'

    $liveThreeWorkspace = New-RoundWorkspace -Name 'live-three'
    $owned.Add($liveThreeWorkspace)
    $twoPlan = $fourPlan | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
    $twoPlan.clients = @($fourPlan.clients[0], $fourPlan.clients[1])
    $liveThreePlatform = New-AzureValidationRoundPlatform -Scenario CompleteZeroResidue
    foreach ($token in @(
        'synthetic-live-tagged-01'
        'synthetic-live-tagged-02'
        'synthetic-live-tagged-03'
    )) {
        $null = $liveThreePlatform.LiveTaggedVms.Add($token)
    }
    $threePlusTwo = Invoke-SafetyRound -Scenario CompleteZeroResidue `
        -WorkspacePath $liveThreeWorkspace -PlanObject $twoPlan -Platform $liveThreePlatform
    Assert-Equal 'VALIDATION.VM_COUNT_UNSAFE' $threePlusTwo.reasonCode `
        'three live tagged VMs plus two requested clients is a fifth VM'
    Assert-Equal $true $threePlusTwo.resultingTotalExceedsMaximum `
        'three plus two is reported as over the ceiling'
    Assert-Equal $false $threePlusTwo.created 'three plus two never creates'

    $pendingWorkspace = New-RoundWorkspace -Name 'cleanup-pending'
    $owned.Add($pendingWorkspace)
    $pending = Invoke-SafetyRound -Scenario CleanupPending -WorkspacePath $pendingWorkspace
    Assert-PublicSafetyOutcome $pending 'cleanup pending blocks admission' `
        -WorkspacePath $pendingWorkspace
    Assert-Equal 'VALIDATION.CLEANUP_PENDING' $pending.reasonCode `
        'Cleanup Pending rejects a new admission'
    Assert-Equal $false $pending.created 'Cleanup Pending never creates'
    Assert-Equal $true $pending.cleanupPending 'Cleanup Pending is visible on the outcome'
    Assert-Equal $true $pending.operationsRecordRetained `
        'restricted operations data is kept while Cleanup Pending remains'

    $incidentWorkspace = New-RoundWorkspace -Name 'documented-incident'
    $owned.Add($incidentWorkspace)
    $incidentPlatform = New-AzureValidationRoundPlatform -Scenario CleanupPending
    $incidentPlatform.DocumentedIncident = $true
    $incident = Invoke-SafetyRound -Scenario CleanupPending `
        -WorkspacePath $incidentWorkspace -Platform $incidentPlatform
    Assert-Equal 'VALIDATION.CLEANUP_PENDING' $incident.reasonCode `
        'a documented incident does not invent a residue-free admission'
    Assert-Equal $false $incident.operationsRecordRetained `
        'a documented incident ends controller retention of restricted operations data'
    Assert-Equal $true $incident.documentedIncident 'the documented incident remains visible'

    foreach ($phase in @(
        @{ Scenario = 'CancelDuringCreate'; Phase = 'Create' }
        @{ Scenario = 'CancelDuringReadiness'; Phase = 'Readiness' }
        @{ Scenario = 'CancelDuringTransfer'; Phase = 'Transfer' }
        @{ Scenario = 'CancelDuringExecution'; Phase = 'Execution' }
        @{ Scenario = 'CancelDuringRetrieval'; Phase = 'Retrieval' }
        @{ Scenario = 'CancelDuringTeardown'; Phase = 'Teardown' }
    )) {
        $cancelWorkspace = New-RoundWorkspace -Name ('cancel-' + $phase.Phase.ToLowerInvariant())
        $owned.Add($cancelWorkspace)
        $cancelled = Invoke-SafetyRound -Scenario ([string] $phase.Scenario) `
            -WorkspacePath $cancelWorkspace
        Assert-PublicSafetyOutcome $cancelled "cancel during $($phase.Phase)" `
            -WorkspacePath $cancelWorkspace
        Assert-Equal 'FailedCleaned' $cancelled.state `
            "cancellation during $($phase.Phase) is not a product pass"
        Assert-Equal 'VALIDATION.CANCELLED' $cancelled.reasonCode `
            "cancellation during $($phase.Phase) uses the typed reason"
        Assert-Equal $true $cancelled.cancelled "cancellation during $($phase.Phase) is recorded"
        Assert-Equal ([string] $phase.Phase) $cancelled.cancelPhase `
            "cancellation during $($phase.Phase) names the phase"
        Assert-Equal 'RoundCleanupMode' $cancelled.cleanupMode `
            "cancellation during $($phase.Phase) enters Round Cleanup Mode"
        Assert-Equal $true $cancelled.newTestsStopped `
            "cancellation during $($phase.Phase) stops new tests"
        Assert-Equal $true $cancelled.evidenceExportStopped `
            "cancellation during $($phase.Phase) stops evidence export"
        Assert-Equal $true $cancelled.zeroResidue `
            "cancellation during $($phase.Phase) still reaches zero residue"
        Assert-Equal $true $cancelled.created `
            "cancellation during $($phase.Phase) still created admitted resources first"
        Assert-Equal $true $cancelled.nextRoundEligible `
            "cancellation during $($phase.Phase) unlocks the next round only after zero residue"
        Assert-Equal $true $cancelled.teardownCompleted `
            "cancellation during $($phase.Phase) still tears down"
    }

    $irreversibleWorkspace = New-RoundWorkspace -Name 'irreversible'
    $owned.Add($irreversibleWorkspace)
    $irreversiblePlatform = New-AzureValidationRoundPlatform -Scenario CancelDuringCreate
    $firstCancel = Invoke-SafetyRound -Scenario CancelDuringCreate `
        -WorkspacePath $irreversibleWorkspace -Platform $irreversiblePlatform
    Assert-Equal 'RoundCleanupMode' $firstCancel.cleanupMode `
        'the first cancellation enters Round Cleanup Mode'
    $irreversiblePlatform.CleanupMode = 'RoundCleanupMode'
    $irreversiblePlatform.ResidentRecoveryRecord = New-AzureValidationRoundResidentRecord `
        -Platform $irreversiblePlatform
    $secondAttempt = Invoke-SafetyRound -Scenario CompleteZeroResidue `
        -WorkspacePath $irreversibleWorkspace -Platform $irreversiblePlatform
    Assert-Equal $true $secondAttempt.recoveryIndependent `
        'a later invoke in cleanup mode recovers instead of expanding'
    Assert-Equal $false $secondAttempt.guestReady `
        'Round Cleanup Mode does not resume guest tests'
    Assert-Equal $true $secondAttempt.newTestsStopped `
        'Round Cleanup Mode keeps new tests stopped'

    $expiryWorkspace = New-RoundWorkspace -Name 'expiry'
    $owned.Add($expiryWorkspace)
    $expired = Invoke-SafetyRound -Scenario Expiry -WorkspacePath $expiryWorkspace
    Assert-PublicSafetyOutcome $expired 'hard expiry' -WorkspacePath $expiryWorkspace
    Assert-Equal 'VALIDATION.EXPIRY_REACHED' $expired.reasonCode `
        'crossing the hard expiry enters cleanup'
    Assert-Equal $true $expired.expiryReached 'expiry is visible on the outcome'
    Assert-Equal 'RoundCleanupMode' $expired.cleanupMode 'expiry enters Round Cleanup Mode'
    Assert-Equal $true $expired.newTestsStopped 'expiry stops new tests'
    Assert-Equal $true $expired.evidenceExportStopped 'expiry stops evidence export'
    Assert-Equal $true $expired.zeroResidue 'expiry still reaches zero residue'
    Assert-Equal 'FailedCleaned' $expired.state 'expiry is not a product pass'

    $reserveWorkspace = New-RoundWorkspace -Name 'reserve'
    $owned.Add($reserveWorkspace)
    $reserve = Invoke-SafetyRound -Scenario CleanupReserve -WorkspacePath $reserveWorkspace
    Assert-PublicSafetyOutcome $reserve 'cleanup reserve' -WorkspacePath $reserveWorkspace
    Assert-Equal 'VALIDATION.CLEANUP_RESERVE_ACTIVE' $reserve.reasonCode `
        'Cleanup Reserve stops new tests and export'
    Assert-Equal $true $reserve.cleanupReserveActive 'Cleanup Reserve is visible'
    Assert-Equal 30 $reserve.cleanupReserveMinutes 'the reserve minutes remain visible'
    Assert-Equal $true $reserve.newTestsStopped 'Cleanup Reserve stops new tests'
    Assert-Equal $true $reserve.evidenceExportStopped 'Cleanup Reserve stops evidence export'
    Assert-Equal 'RoundCleanupMode' $reserve.cleanupMode `
        'Cleanup Reserve enters Round Cleanup Mode'
    Assert-Equal $true $reserve.zeroResidue 'Cleanup Reserve still reaches zero residue'

    $partialWorkspace = New-RoundWorkspace -Name 'partial'
    $owned.Add($partialWorkspace)
    $partial = Invoke-SafetyRound -Scenario PartialProvisioning -WorkspacePath $partialWorkspace
    Assert-Equal 'VALIDATION.PARTIAL_PROVISIONING' $partial.reasonCode `
        'partial provisioning enters cleanup instead of retrying'
    Assert-Equal 'RoundCleanupMode' $partial.cleanupMode `
        'partial provisioning is irreversible cleanup'
    Assert-Equal $true $partial.created 'partial provisioning still records that create began'
    Assert-Equal $true $partial.zeroResidue 'partial provisioning still reaches zero residue'
    Assert-Equal $false $partial.guestReady 'partial provisioning does not invent guest readiness'

    $sharedWorkspace = New-RoundWorkspace -Name 'shared-safety'
    $owned.Add($sharedWorkspace)
    $shared = Invoke-SafetyRound -Scenario SharedSafetyFailure -WorkspacePath $sharedWorkspace
    Assert-Equal 'VALIDATION.SHARED_SAFETY_FAILED' $shared.reasonCode `
        'a shared-safety failure enters cleanup instead of expanding'
    Assert-Equal 'RoundCleanupMode' $shared.cleanupMode `
        'a shared-safety failure is irreversible cleanup'
    Assert-Equal $true $shared.zeroResidue 'a shared-safety failure still reaches zero residue'

    $hostLossWorkspace = New-RoundWorkspace -Name 'host-loss'
    $owned.Add($hostLossWorkspace)
    $hostLoss = Invoke-SafetyRound -Scenario HostLoss -WorkspacePath $hostLossWorkspace
    Assert-PublicSafetyOutcome $hostLoss 'host loss' -WorkspacePath $hostLossWorkspace
    Assert-Equal 'VALIDATION.HOST_LOST' $hostLoss.reasonCode `
        'host loss uses the resident recovery path'
    Assert-Equal $true $hostLoss.recoveryIndependent `
        'host loss recovery does not need the initiating local files'
    Assert-Equal 'RoundCleanupMode' $hostLoss.cleanupMode 'host loss enters Round Cleanup Mode'
    Assert-Equal $true $hostLoss.zeroResidue 'host loss still reaches zero residue'
    Assert-Equal 'FailedCleaned' $hostLoss.state 'host loss is not a product pass'
    Assert-Equal $false (Test-Path -LiteralPath (
        Join-Path $hostLossWorkspace $policy.workspace.recoveryDirectoryName
    )) 'host-loss recovery removes the journal after zero residue'

    $recoveryWorkspace = New-RoundWorkspace -Name 'independent-recovery'
    $owned.Add($recoveryWorkspace)
    $recovered = Invoke-SafetyRound -Scenario IndependentRecovery -WorkspacePath $recoveryWorkspace
    Assert-PublicSafetyOutcome $recovered 'independent recovery' -WorkspacePath $recoveryWorkspace
    Assert-Equal 'VALIDATION.RECOVERY_COMPLETED' $recovered.reasonCode `
        'independent recovery completes from the resident record'
    Assert-Equal $true $recovered.recoveryIndependent `
        'independent recovery does not use the initiating process files'
    Assert-Equal $true $recovered.zeroResidue 'independent recovery proves zero residue'
    Assert-Equal $false $recovered.created `
        'independent recovery does not create a new client'
    Assert-Equal 'FailedCleaned' $recovered.state `
        'independent recovery is not converted into a product pass'

    $emptyRecovery = New-RoundWorkspace -Name 'empty-recovery-workspace'
    $owned.Add($emptyRecovery)
    $noLocalPlatform = New-AzureValidationRoundPlatform -Scenario IndependentRecovery
    Remove-Item -LiteralPath $emptyRecovery -Recurse -Force
    $null = New-Item -ItemType Directory -Path $emptyRecovery -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $emptyRecovery $policy.privacy.markerFileName),
        ($policy.privacy.markerContent + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    Assert-Equal $false (Test-Path -LiteralPath (
        Join-Path $emptyRecovery $policy.workspace.recoveryDirectoryName
    )) 'the recovery worker starts without a local journal'
    $noLocal = Invoke-AzureValidationRoundRecovery -Platform $noLocalPlatform `
        -Policy $policy -PrivateWorkspacePath $emptyRecovery -Common @{
            ClientCount = 1
            Windows11ClaimingRoute = $true
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
            CleanupReserveMinutes = 30
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
    Assert-Equal 'VALIDATION.RECOVERY_COMPLETED' $noLocal.reasonCode `
        'recovery from the resident record does not need local files'
    Assert-Equal $true $noLocal.zeroResidue 'recovery without local files still proves zero residue'

    $unrelatedWorkspace = New-RoundWorkspace -Name 'unrelated'
    $owned.Add($unrelatedWorkspace)
    $unrelatedPlatform = New-AzureValidationRoundPlatform -Scenario CompleteZeroResidue
    $null = $unrelatedPlatform.Resources.Add('synthetic-persistent-control-plane')
    $unrelated = Invoke-SafetyRound -Scenario CompleteZeroResidue `
        -WorkspacePath $unrelatedWorkspace -Platform $unrelatedPlatform
    Assert-Equal $true $unrelated.unrelatedTargetPreserved `
        'cleanup never deletes an unrelated control-plane token'
    Assert-Equal $true $unrelated.persistentScopePreserved `
        'persistent controls remain after cleanup'
    Assert-Equal $true $unrelated.zeroResidue `
        'unrelated tokens do not block zero round residue'

    $unresolvedWorkspace = New-RoundWorkspace -Name 'unresolved'
    $owned.Add($unresolvedWorkspace)
    $unresolvedPlatform = New-AzureValidationRoundPlatform -Scenario CompleteZeroResidue
    $null = $unresolvedPlatform.UnresolvedResources.Add('synthetic-round-vm-01')
    $unresolved = Invoke-SafetyRound -Scenario CompleteZeroResidue `
        -WorkspacePath $unresolvedWorkspace -Platform $unresolvedPlatform
    Assert-Equal $true $unresolved.unresolvedTargetPreserved `
        'cleanup never deletes an unresolved token'
    Assert-Equal 'ResidueRemains' $unresolved.state `
        'an unresolved owned token is not converted into a product pass'
    Assert-Equal 'VALIDATION.RESIDUE_REMAINS' $unresolved.reasonCode `
        'unresolved residue stays visible'

    $idempotentPlatform = New-AzureValidationRoundPlatform -Scenario CompleteZeroResidue
    Initialize-AzureValidationRoundResources -Platform $idempotentPlatform -ClientCount 1
    $firstDestroy = Invoke-AzureValidationRoundDestroy -Platform $idempotentPlatform
    $secondDestroy = Invoke-AzureValidationRoundDestroy -Platform $idempotentPlatform
    Assert-Equal $true $firstDestroy 'the first destroy removes owned tokens'
    Assert-Equal $true $secondDestroy 'the second destroy is idempotent'
    Assert-Equal 0 @($idempotentPlatform.Resources | Where-Object {
        Test-AzureValidationRoundRoundOwnedToken -Platform $idempotentPlatform -Token $_
    }).Count 'owned tokens stay absent after a second destroy'

    $retentionWorkspace = New-RoundWorkspace -Name 'retention'
    $owned.Add($retentionWorkspace)
    $retentionPlatform = New-AzureValidationRoundPlatform -Scenario CompleteZeroResidue
    $null = $retentionPlatform.OperationsRecords.Add([pscustomobject]@{
        Kind = 'Completed'
        AgeDays = 8
    })
    $null = $retentionPlatform.OperationsRecords.Add([pscustomobject]@{
        Kind = 'Completed'
        AgeDays = 1
    })
    $retention = Invoke-SafetyRound -Scenario CompleteZeroResidue `
        -WorkspacePath $retentionWorkspace -Platform $retentionPlatform
    Assert-Equal $true $retention.zeroResidue 'retention sweep still proves zero residue'
    $ages = @($retentionPlatform.OperationsRecords | ForEach-Object { [int] $_.AgeDays })
    Assert-Equal $false (8 -in $ages) 'completed records older than seven days are removed'
    Assert-Equal $true ((1 -in $ages) -or (0 -in $ages)) `
        'a completed record inside seven days is kept until the ceiling'

    $fiveLiveWorkspace = New-RoundWorkspace -Name 'live-five'
    $owned.Add($fiveLiveWorkspace)
    $fiveLivePlatform = New-AzureValidationRoundPlatform -Scenario CompleteZeroResidue
    foreach ($token in @(
        'synthetic-live-tagged-01'
        'synthetic-live-tagged-02'
        'synthetic-live-tagged-03'
        'synthetic-live-tagged-04'
        'synthetic-live-tagged-05'
    )) {
        $null = $fiveLivePlatform.LiveTaggedVms.Add($token)
    }
    $fiveLive = Invoke-SafetyRound -Scenario CompleteZeroResidue `
        -WorkspacePath $fiveLiveWorkspace -Platform $fiveLivePlatform
    Assert-PublicSafetyOutcome $fiveLive 'five live tagged VMs' -WorkspacePath $fiveLiveWorkspace
    Assert-Equal 'VALIDATION.VM_COUNT_UNSAFE' $fiveLive.reasonCode `
        'five live tagged VMs plus one requested client is reported honestly'
    Assert-Equal 5 $fiveLive.liveTaggedVmCount `
        'an over-limit recount remains visible on the public outcome'
    Assert-Equal $true $fiveLive.resultingTotalExceedsMaximum `
        'five live plus one requested exceeds the ceiling'
    Assert-Equal $false $fiveLive.created 'five live tagged VMs never create another client'

    $foreignWorkspace = New-RoundWorkspace -Name 'foreign-token'
    $owned.Add($foreignWorkspace)
    $foreignPlatform = New-AzureValidationRoundPlatform -Scenario CompleteZeroResidue
    $null = $foreignPlatform.Resources.Add('synthetic-foreign-disk')
    $foreign = Invoke-SafetyRound -Scenario CompleteZeroResidue `
        -WorkspacePath $foreignWorkspace -Platform $foreignPlatform
    Assert-Equal $true $foreign.zeroResidue `
        'an unknown token does not count as round residue'
    Assert-Equal $true $foreign.unrelatedTargetPreserved `
        'cleanup never deletes a token outside the owned allowlist'
    Assert-Equal $true ('synthetic-foreign-disk' -in @($foreignPlatform.Resources)) `
        'the unknown token remains after destroy'

    $pendingDropWorkspace = New-RoundWorkspace -Name 'pending-drop'
    $owned.Add($pendingDropWorkspace)
    $pendingDropPlatform = New-AzureValidationRoundPlatform -Scenario CompleteZeroResidue
    $null = $pendingDropPlatform.OperationsRecords.Add([pscustomobject]@{
        Kind = 'CleanupPending'
        AgeDays = 0
    })
    $pendingDrop = Invoke-SafetyRound -Scenario CompleteZeroResidue `
        -WorkspacePath $pendingDropWorkspace -Platform $pendingDropPlatform
    Assert-Equal $true $pendingDrop.zeroResidue 'dropping pending records still proves zero residue'
    Assert-Equal $false $pendingDrop.operationsRecordRetained `
        'Cleanup Pending records are not kept after zero residue'
    Assert-Equal 0 @($pendingDropPlatform.OperationsRecords | Where-Object {
        [string] $_.Kind -eq 'CleanupPending'
    }).Count 'Cleanup Pending records are removed when residue is gone'

    $journalWorkspace = New-RoundWorkspace -Name 'leftover-journal'
    $owned.Add($journalWorkspace)
    $residue = Invoke-SafetyRound -Scenario ResidueRemains -WorkspacePath $journalWorkspace
    Assert-Equal 'VALIDATION.RESIDUE_REMAINS' $residue.reasonCode `
        'the first invoke leaves residue and the private journal'
    $blockedByJournal = Invoke-SafetyRound -Scenario CompleteZeroResidue `
        -WorkspacePath $journalWorkspace
    Assert-Equal 'VALIDATION.CLEANUP_PENDING' $blockedByJournal.reasonCode `
        'a leftover private recovery journal blocks the next admission'
    Assert-Equal $false $blockedByJournal.created `
        'a leftover journal never creates another client'

    $fileLeaseWorkspace = New-RoundWorkspace -Name 'file-lease'
    $owned.Add($fileLeaseWorkspace)
    Assert-Equal $true (New-AzureValidationRoundExclusiveLease `
        -PrivateWorkspacePath $fileLeaseWorkspace) 'the first workspace lease is acquired'
    $blockedByFileLease = Invoke-SafetyRound -Scenario CompleteZeroResidue `
        -WorkspacePath $fileLeaseWorkspace
    Assert-Equal 'VALIDATION.LEASE_UNAVAILABLE' $blockedByFileLease.reasonCode `
        'an existing private-workspace lease serializes the next admission'
    Assert-Equal $false $blockedByFileLease.created `
        'a held workspace lease never creates'
    Assert-Equal $false $blockedByFileLease.exclusiveLeaseHeld `
        'the rejected caller does not hold the exclusive lease'
}
finally {
    foreach ($path in $owned) {
        Remove-RoundWorkspace $path
    }
}

Write-Output 'PASS: Azure validation-round safety proves lease, cancellation, expiry, recovery, and four-VM admission.'
