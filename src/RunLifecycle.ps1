$script:RunLifecyclePolicyBase64 = '__RUN_LIFECYCLE_POLICY_BASE64__'
$script:RunLifecyclePolicyDigest = '__RUN_LIFECYCLE_POLICY_SHA256__'

function Get-RunLifecyclePolicyDigest {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-AssessmentRunLifecyclePolicy {
    if ($script:RunLifecyclePolicyBase64 -eq '__RUN_LIFECYCLE_POLICY_BASE64__') {
        $repositoryRoot = Split-Path -Parent $PSScriptRoot
        $text = [System.IO.File]::ReadAllText(
            (Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-run-lifecycle.json'),
            [System.Text.UTF8Encoding]::new($false, $true)
        ).Replace("`r`n", "`n").Replace("`r", "`n")
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($text)
        $expectedDigest = Get-RunLifecyclePolicyDigest -Bytes $bytes
    }
    else {
        $bytes = [System.Convert]::FromBase64String($script:RunLifecyclePolicyBase64)
        $expectedDigest = $script:RunLifecyclePolicyDigest
    }
    if ((Get-RunLifecyclePolicyDigest -Bytes $bytes) -ne $expectedDigest) {
        throw 'The embedded Assessment Run lifecycle policy failed integrity validation.'
    }
    $convertFromJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
        'ConvertFrom-Json', [System.Management.Automation.CommandTypes]::Cmdlet
    )
    if ($null -eq $convertFromJsonCommand -or
        $convertFromJsonCommand.ModuleName -ne 'Microsoft.PowerShell.Utility') {
        throw 'The lifecycle policy JSON command does not have built-in provenance.'
    }
    $policy = & $convertFromJsonCommand -InputObject (
        [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    ) -Depth 20
    if ($policy.kind -ne 'win-pcinfo.run-lifecycle-policy' -or
        $policy.contractVersion -ne '1.0.0' -or $policy.release -ne '2.0.0-preview.1' -or
        $policy.policyId -ne 'win-pcinfo.run-lifecycle/1.0.0' -or
        @($policy.outcomes).Count -ne 7 -or
        @($policy.outcomes.outcome | Sort-Object -Unique).Count -ne 7 -or
        @($policy.outcomes.exitCode | Sort-Object -Unique).Count -ne 7 -or
        @($policy.deadlines.phases.phase | Sort-Object -Unique).Count -ne 4) {
        throw 'The Assessment Run lifecycle policy is not semantically closed.'
    }
    $policy
}

function Get-AssessmentRunExitCode {
    param([Parameter(Mandatory)] [string] $Outcome)

    $mapping = @(Get-AssessmentRunLifecyclePolicy | Select-Object -ExpandProperty outcomes |
        Where-Object outcome -eq $Outcome)
    if ($mapping.Count -ne 1) { throw "Unknown Assessment Run Outcome: $Outcome" }
    [int] $mapping[0].exitCode
}

function Get-AssessmentRunDeadlinePolicy {
    $policy = Get-AssessmentRunLifecyclePolicy
    [pscustomobject][ordered]@{
        policyId = $policy.policyId
        run = $policy.deadlines.run
        phases = @($policy.deadlines.phases)
        operation = $policy.deadlines.operation
        process = $policy.deadlines.process
        progress = $policy.deadlines.progress
    }
}

function New-AssessmentProgressEvent {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9._:/-]{0,127}$')]
        [string] $RunId,
        [Parameter(Mandatory)] [int] $Sequence,
        [Parameter(Mandatory)] [string] $Phase,
        [Parameter(Mandatory)] [string] $State,
        [Parameter(Mandatory)] [string] $MessageId,
        [Parameter(Mandatory)] [int] $CompletedUnits,
        [Parameter(Mandatory)] [int] $TotalUnits
    )

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.progress'
        contractVersion = '1.0.0'
        runId = $RunId
        sequence = $Sequence
        phase = $Phase
        state = $State
        time = [System.DateTimeOffset]::UtcNow.ToString(
            'o', [System.Globalization.CultureInfo]::InvariantCulture
        )
        completion = [pscustomobject][ordered]@{
            completedUnits = $CompletedUnits
            totalUnits = $TotalUnits
            unit = 'AssessmentOperation'
        }
        messageId = $MessageId
    }
}

function New-SyntheticAssessmentRecord {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9._:/-]{0,127}$')]
        [string] $RunId,
        [Parameter(Mandatory)] $CollectorResult,
        [Parameter(Mandatory)] [string] $Outcome
    )

    $observation = @($CollectorResult.Observations)[0]
    $envelope = $CollectorResult.Envelope
    $provenanceId = "provenance:synthetic-os:$RunId"
    $coverage = [ordered]@{
        coverageId = $CollectorResult.Coverage[0].coverageId
        scopeId = $CollectorResult.Coverage[0].scopeId
        state = $CollectorResult.Coverage[0].state
        observationIds = @($CollectorResult.Coverage[0].observationIds)
        diagnosticIds = @($CollectorResult.Coverage[0].diagnosticIds)
    }
    if ($coverage.state -ne 'Complete') {
        $coverage.reasonCode = [string] $CollectorResult.Coverage[0].reasonCode
    }
    $finding = [ordered]@{
        findingId = "finding:synthetic-os-observed:$RunId"
        ruleId = 'rule:synthetic.os-observed/1.0.0'
        targetSubjectId = $observation.subjectId
        outcome = if ($Outcome -eq 'Completed') { 'Informational' } else { 'Indeterminate' }
        evidenceReferences = @([pscustomobject][ordered]@{
            observationId = $observation.observationId
            fieldId = $observation.fieldId
            subjectId = $observation.subjectId
        })
    }
    if ($Outcome -ne 'Completed') { $finding.reasonCode = 'FINDING.COVERAGE_INCOMPLETE' }

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.assessment-record'
        contractVersion = '1.0.0'
        requiredFeatures = @(
            'closed-scope-coverage'
            'evidence-references'
            'prohibited-material-omission'
        )
        run = [pscustomobject][ordered]@{
            runId = $RunId
            outcome = $Outcome
            validationFixture = $true
        }
        subjects = @([pscustomobject][ordered]@{
            subjectId = 'subject:synthetic-device:primary'
            kind = 'Device'
        })
        provenance = @([pscustomobject][ordered]@{
            provenanceId = $provenanceId
            fieldId = $observation.fieldId
            subjectId = $observation.subjectId
            sourceId = 'source:synthetic.windows.os'
            collectorId = $envelope.collectorId
            collectorVersion = $envelope.collectorVersion
            executionContext = 'Synthetic'
            collectedAt = $envelope.completedAt
            sourceLocale = 'en-US'
        })
        observations = @([pscustomobject][ordered]@{
            observationId = $observation.observationId
            fieldId = $observation.fieldId
            subjectId = $observation.subjectId
            provenanceId = $provenanceId
            valueState = $observation.valueState
            value = $observation.value
        })
        coverage = @([pscustomobject] $coverage)
        diagnostics = @($CollectorResult.Diagnostics)
        collectorResults = @($envelope)
        findings = @([pscustomobject] $finding)
        recommendations = @()
        recommendationRelationships = @()
    }
}

function ConvertTo-SanitizedCleanupState {
    param($Result)

    if ($null -ne $Result -and $Result.PSObject.Properties['verified'] -and
        [bool] $Result.verified) {
        return [pscustomobject][ordered]@{
            state = 'VerifiedAbsent'
            verified = $true
            reasonCode = 'CLEANUP.VERIFIED'
        }
    }
    [pscustomobject][ordered]@{
        state = 'ResidueUncertain'
        verified = $false
        reasonCode = 'CLEANUP.OWNED_RESIDUE_UNCERTAIN'
    }
}

function ConvertTo-SanitizedPackageState {
    param(
        $Result,
        [Parameter(Mandatory)] [string] $RequiredState
    )

    if ($null -ne $Result -and $Result.PSObject.Properties['verified'] -and
        $Result.PSObject.Properties['state'] -and [bool] $Result.verified -and
        [string] $Result.state -eq $RequiredState) {
        return [pscustomobject][ordered]@{
            state = $RequiredState
            verified = $true
            protection = if ([string] $Result.protection -eq 'InjectedSyntheticTestFinalizer') {
                'InjectedSyntheticTestFinalizer'
            }
            else {
                'ProtectedEvidencePackage'
            }
            recoverable = $Result.PSObject.Properties['recoverable'] -and [bool] $Result.recoverable
        }
    }
    [pscustomobject][ordered]@{
        state = 'IntegrityFailed'
        verified = $false
        protection = 'None'
        recoverable = $false
    }
}

function Invoke-AssessmentRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9._:/-]{0,127}$')]
        [string] $RunId,
        [Parameter(Mandatory)] [scriptblock] $CollectorAdapter,
        [Parameter(Mandatory)] [scriptblock] $FinalizerAdapter,
        [Parameter(Mandatory)] [scriptblock] $CleanupAdapter,
        [Parameter()] [scriptblock] $ProgressAdapter,
        [Parameter()] [System.Threading.CancellationToken] $CancellationToken =
            [System.Threading.CancellationToken]::None
    )

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $deadlinePolicy = Get-AssessmentRunDeadlinePolicy
    $records = [System.Collections.Generic.List[object]]::new()
    $progressTimes = [System.Collections.Generic.List[long]]::new()
    $progressState = [pscustomobject]@{ Sequence = 0 }
    $addProgress = {
        param([string] $Phase, [string] $State, [string] $MessageId, [int] $Completed, [int] $Total)
        $progressState.Sequence++
        $progressTimes.Add($watch.ElapsedMilliseconds)
        $progressRecord = New-AssessmentProgressEvent -RunId $RunId -Sequence $progressState.Sequence `
            -Phase $Phase -State $State -MessageId $MessageId `
            -CompletedUnits $Completed -TotalUnits $Total
        $records.Add($progressRecord)
        if ($null -ne $ProgressAdapter) { & $ProgressAdapter $progressRecord }
    }

    & $addProgress 'RunControl' 'Started' 'run.accepted' 0 3
    $mutex = $null
    $lockOwned = $false
    $abandonedOwner = $false
    $lockState = 'NotAcquired'
    $assessmentRecord = $null
    $contractValidation = $null
    $collectorResult = $null
    $startedOperationCount = 0
    $cancellationAcknowledgementMilliseconds = -1L
    $finalizationRequired = $false
    $requiredPackageState = ''
    $runCancellation = [System.Threading.CancellationTokenSource]::CreateLinkedTokenSource(
        $CancellationToken
    )
    $runCancellation.CancelAfter([int] $deadlinePolicy.run.maximumMilliseconds)
    $package = [pscustomobject][ordered]@{
        state = 'Unavailable'
        verified = $false
        protection = 'None'
        recoverable = $false
    }
    $cleanup = [pscustomobject][ordered]@{
        state = 'NotRequired'
        verified = $true
        reasonCode = 'CLEANUP.NOT_REQUIRED'
    }
    $outcome = 'IntegrityFailed'
    $reasonCode = 'RUN.INTEGRITY_FAILED'
    $collectionStarted = $false
    try {
        # Threat: two sessions could otherwise both believe they own device-wide
        # collection and cleanup. A Global named mutex is kernel-enforced and has
        # no writable pathname. The trust assumption is that Windows preserves
        # named-kernel-object ownership; failure to acquire means no work starts.
        $lifecyclePolicy = Get-AssessmentRunLifecyclePolicy
        $mutex = [System.Threading.Mutex]::new(
            $false, [string] $lifecyclePolicy.activeRunLock.name
        )
        try { $lockOwned = $mutex.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] {
            $lockOwned = $true
            $abandonedOwner = $true
        }
        if (-not $lockOwned) {
            $lockState = 'OwnedByAnotherRun'
            $outcome = 'NotStarted'
            $reasonCode = 'RUN.ACTIVE_LOCK_HELD'
        }
        elseif ($abandonedOwner) {
            # An abandoned mutex proves that the prior owning thread ended, but
            # it does not prove where that run stopped or that its side effects
            # are safe to reuse. Recovery is therefore cleanup-only. It never
            # restarts a collector or treats the stale run as a resumable job.
            $lockState = 'AbandonedOwnerRecovered'
            $outcome = 'NotStarted'
            $reasonCode = 'RUN.STALE_OWNER_RECOVERED'
            $package = [pscustomobject][ordered]@{
                state = 'NotRequired'
                verified = $true
                protection = 'None'
                recoverable = $false
            }
            & $addProgress 'Recovery' 'Started' 'recovery.stale-owner-detected' 0 3
        }
        else {
            $lockState = 'OwnedByThisRun'
            & $addProgress 'Collection' 'Started' 'collection.synthetic.started' 1 3
            $collectionStarted = $true
            $startedOperationCount++
            $collectionCancellation = [System.Threading.CancellationTokenSource]::CreateLinkedTokenSource(
                $runCancellation.Token
            )
            $collectionCancellation.CancelAfter(
                [int] ($deadlinePolicy.phases | Where-Object phase -eq 'Collection')[0].maximumMilliseconds
            )
            try {
                $collectorResult = & $CollectorAdapter $collectionCancellation.Token
            }
            finally {
                $collectionCancellation.Dispose()
            }
            # The current approved process contract returns within five seconds,
            # below the ten-second heartbeat ceiling. Emitting at the process
            # seam closes that active interval; later collectors that can run
            # longer must provide interim callbacks before this bound expires.
            & $addProgress 'Collection' 'Heartbeat' 'run.active' 1 3
            if ($null -eq $collectorResult -or
                $collectorResult.Supervision.outcome -notin @(
                    'Completed', 'Failed', 'Cancelled', 'TimedOut'
                ) -or
                ($collectorResult.Supervision.outcome -eq 'Failed' -and
                    @($collectorResult.Observations).Count -eq 0) -or
                -not $collectorResult.Supervision.completeOwnedTreeAbsent -or
                -not $collectorResult.Supervision.temporaryArtifactsAbsent) {
                throw 'The collector did not return a complete clean synthetic result.'
            }
            $recordOutcome = switch ($collectorResult.Supervision.outcome) {
                'Completed' { 'Completed' }
                'Failed' { 'CompletedWithGaps' }
                'Cancelled' { 'Cancelled' }
                'TimedOut' { 'TimedOut' }
            }
            if ($recordOutcome -eq 'Cancelled') {
                $cancellationAcknowledgementMilliseconds = $watch.ElapsedMilliseconds
                & $addProgress 'Cancellation' 'Acknowledged' 'cancellation.acknowledged' 1 3
            }
            $collectionMessage = switch ($recordOutcome) {
                'Completed' { 'collection.synthetic.succeeded' }
                'CompletedWithGaps' { 'collection.synthetic.isolated-failure' }
                'Cancelled' { 'collection.synthetic.cancelled' }
                'TimedOut' { 'collection.synthetic.timed-out' }
            }
            & $addProgress 'Collection' `
                $(if ($recordOutcome -eq 'Completed') { 'Succeeded' } else { 'Failed' }) `
                $collectionMessage 2 3

            if (@($collectorResult.Observations).Count -eq 0 -and
                $recordOutcome -in @('Cancelled', 'TimedOut')) {
                # No normalized evidence crossed the collector seam, so there is
                # nothing the package finalizer is permitted to protect. This is
                # distinct from losing recoverable evidence: the explicit state
                # prevents a cancellation from claiming that a package exists.
                $package = [pscustomobject][ordered]@{
                    state = 'NotRequired'
                    verified = $true
                    protection = 'None'
                    recoverable = $false
                }
                $outcome = $recordOutcome
                $reasonCode = if ($outcome -eq 'Cancelled') {
                    'RUN.CANCELLED'
                }
                else {
                    'RUN.TIMED_OUT'
                }
            }
            else {
                $assessmentRecord = New-SyntheticAssessmentRecord -RunId $RunId `
                    -CollectorResult $collectorResult -Outcome $recordOutcome
                $convertFromJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
                    'ConvertFrom-Json', [System.Management.Automation.CommandTypes]::Cmdlet
                )
                $convertToJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
                    'ConvertTo-Json', [System.Management.Automation.CommandTypes]::Cmdlet
                )
                $testJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
                    'Test-Json', [System.Management.Automation.CommandTypes]::Cmdlet
                )
                $assessmentBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
                    (& $convertToJsonCommand -InputObject $assessmentRecord -Compress -Depth 30)
                )
                $contractValidation = Test-AssessmentContract -Utf8Bytes $assessmentBytes `
                    -ConvertFromJsonCommand $convertFromJsonCommand -TestJsonCommand $testJsonCommand
                if (-not $contractValidation.accepted) {
                    $reasonCode = 'RUN.ASSESSMENT_RECORD_INVALID'
                    $assessmentRecord = $null
                    $package = ConvertTo-SanitizedPackageState -Result $null `
                        -RequiredState 'Verified'
                }
                else {
                    $requiredPackageState = if ($recordOutcome -in @('Cancelled', 'TimedOut')) {
                        'RecoverableProtected'
                    }
                    else {
                        'Verified'
                    }
                    $finalizationRequired = $true
                    $outcome = $recordOutcome
                    $reasonCode = switch ($outcome) {
                        'Completed' { 'RUN.COMPLETED' }
                        'CompletedWithGaps' { 'RUN.COMPLETED_WITH_GAPS' }
                        'Cancelled' { 'RUN.CANCELLED' }
                        'TimedOut' { 'RUN.TIMED_OUT' }
                    }
                }
            }
        }
    }
    catch {
        $outcome = 'IntegrityFailed'
        $reasonCode = if ($_.Exception.Data.Contains('ReasonCode') -and
            [string] $_.Exception.Data['ReasonCode'] -eq 'RUN.WORKER_LOST') {
            'RUN.WORKER_LOST'
        }
        else {
            'RUN.EXECUTION_INTEGRITY_FAILED'
        }
        $diagnosticId = "diagnostic:run-integrity:$RunId"
        $coverageId = "coverage:synthetic-device-os:$RunId"
        $collectorResult = [pscustomobject][ordered]@{
            Coverage = @([pscustomobject][ordered]@{
                coverageId = $coverageId
                scopeId = 'scope:synthetic.device.os'
                state = 'Failed'
                reasonCode = $reasonCode
                observationIds = @()
                diagnosticIds = @($diagnosticId)
            })
        }
        $package = [pscustomobject][ordered]@{
            state = 'NotRequired'
            verified = $true
            protection = 'None'
            recoverable = $false
        }
        & $addProgress 'Collection' 'Failed' 'collection.worker-lost' 1 3
    }
    finally {
        if ($lockOwned) {
            try {
                $cleanup = ConvertTo-SanitizedCleanupState -Result (& $CleanupAdapter $RunId)
            }
            catch {
                $cleanup = ConvertTo-SanitizedCleanupState -Result $null
            }
        }
        if (-not [bool] $cleanup.verified) {
            $outcome = 'CleanupIncomplete'
            $reasonCode = 'RUN.CLEANUP_INCOMPLETE'
        }
    }

    if ($finalizationRequired) {
        if (-not [bool] $cleanup.verified) {
            # Cleanup is part of the Assessment Run Outcome, not an afterthought.
            # The finalizer therefore receives the cleanup-aware record only
            # after exact owned-resource absence has been checked. This prevents
            # a trustworthy package from preserving a provisional success while
            # the public terminal record truthfully reports residue uncertainty.
            $cleanupDiagnosticId = "diagnostic:cleanup:$RunId"
            $assessmentRecord.run.outcome = 'CleanupIncomplete'
            $assessmentRecord.coverage[0].state = 'Partial'
            if ($assessmentRecord.coverage[0].PSObject.Properties['reasonCode']) {
                $assessmentRecord.coverage[0].reasonCode = 'RUN.CLEANUP_INCOMPLETE'
            }
            else {
                $assessmentRecord.coverage[0] | Add-Member -NotePropertyName reasonCode `
                    -NotePropertyValue 'RUN.CLEANUP_INCOMPLETE'
            }
            $assessmentRecord.coverage[0].diagnosticIds = @(
                @($assessmentRecord.coverage[0].diagnosticIds) + $cleanupDiagnosticId |
                    Sort-Object -Unique
            )
            $assessmentRecord.collectorResults[0].diagnosticIds = @(
                @($assessmentRecord.collectorResults[0].diagnosticIds) + $cleanupDiagnosticId |
                    Sort-Object -Unique
            )
            $assessmentRecord.diagnostics = @($assessmentRecord.diagnostics) +
                [pscustomobject][ordered]@{
                    diagnosticId = $cleanupDiagnosticId
                    scopeId = 'scope:synthetic.device.os'
                    phase = 'Cleanup'
                    reasonCode = 'RUN.CLEANUP_INCOMPLETE'
                    operatorMessageId = 'cleanup.incomplete'
                }
            $assessmentRecord.findings[0].outcome = 'Indeterminate'
            if (-not $assessmentRecord.findings[0].PSObject.Properties['reasonCode']) {
                $assessmentRecord.findings[0] | Add-Member -NotePropertyName reasonCode `
                    -NotePropertyValue 'FINDING.COVERAGE_INCOMPLETE'
            }
            $assessmentBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
                (& $convertToJsonCommand -InputObject $assessmentRecord -Compress -Depth 30)
            )
            $contractValidation = Test-AssessmentContract -Utf8Bytes $assessmentBytes `
                -ConvertFromJsonCommand $convertFromJsonCommand -TestJsonCommand $testJsonCommand
        }

        if (-not $contractValidation.accepted) {
            $outcome = if ([bool] $cleanup.verified) { 'IntegrityFailed' } else { 'CleanupIncomplete' }
            $reasonCode = if ([bool] $cleanup.verified) {
                'RUN.ASSESSMENT_RECORD_INVALID'
            }
            else {
                'RUN.CLEANUP_INCOMPLETE'
            }
        }
        else {
            & $addProgress 'Packaging' 'Started' 'package.finalization.started' 2 3
            try {
                $package = ConvertTo-SanitizedPackageState `
                    -Result (& $FinalizerAdapter $assessmentRecord) `
                    -RequiredState $requiredPackageState
            }
            catch {
                $package = ConvertTo-SanitizedPackageState -Result $null `
                    -RequiredState $requiredPackageState
            }
            if ($null -eq $package -or -not [bool] $package.verified -or
                $package.state -ne $requiredPackageState) {
                & $addProgress 'Packaging' 'Failed' 'package.finalization.failed' 2 3
                if ([bool] $cleanup.verified) {
                    $outcome = 'IntegrityFailed'
                    $reasonCode = 'RUN.PACKAGE_INTEGRITY_FAILED'
                    $assessmentRecord = $null
                }
            }
            else {
                & $addProgress 'Packaging' 'Succeeded' 'package.finalization.verified' 2 3
            }
        }
    }

    # The device-wide lock remains owned through cleanup and finalization. A
    # second run therefore cannot begin while this run is still protecting its
    # final record. Releasing the mutex is the last owned coordination action;
    # failure remains CleanupIncomplete rather than being hidden by success.
    if ($lockOwned) {
        try { $mutex.ReleaseMutex() }
        catch {
            $cleanup = [pscustomobject][ordered]@{
                state = 'LockReleaseUncertain'
                verified = $false
                reasonCode = 'CLEANUP.LOCK_RELEASE_UNCERTAIN'
            }
            $outcome = 'CleanupIncomplete'
            $reasonCode = 'RUN.CLEANUP_INCOMPLETE'
        }
    }
    if ($null -ne $mutex) { $mutex.Dispose() }
    & $addProgress 'Cleanup' $(if ($cleanup.verified) { 'Succeeded' } else { 'Failed' }) `
        $(if ($cleanup.verified) { 'cleanup.verified' } else { 'cleanup.incomplete' }) 3 3
    $runCancellation.Dispose()

    if ($null -ne $assessmentRecord) { $records.Add($assessmentRecord) }
    $terminal = [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.terminal'
        contractVersion = '1.0.0'
        runId = $RunId
        outcome = $outcome
        exitCode = Get-AssessmentRunExitCode -Outcome $outcome
        reasonCode = $reasonCode
        phase = 'Terminal'
        collectionStarted = $collectionStarted
        validationFixture = $true
        coverage = if ($null -ne $assessmentRecord) {
            @($assessmentRecord.coverage)
        }
        elseif ($null -ne $collectorResult) {
            @($collectorResult.Coverage)
        }
        else {
            @()
        }
        package = $package
        cleanup = $cleanup
        lock = [pscustomobject][ordered]@{
            state = $lockState
            scope = 'DeviceWide'
            interference = 'None'
        }
        integrity = [pscustomobject][ordered]@{
            state = if ($outcome -eq 'IntegrityFailed') {
                'Failed'
            }
            elseif ([bool] $package.verified) {
                'Verified'
            }
            else {
                'NotApplicable'
            }
            reasonCode = if ($outcome -eq 'IntegrityFailed') {
                $reasonCode
            }
            elseif ([bool] $package.verified) {
                'INTEGRITY.VERIFIED'
            }
            else {
                'INTEGRITY.NOT_APPLICABLE'
            }
        }
        deadlines = $deadlinePolicy
        scheduling = [pscustomobject][ordered]@{
            plannedOperationCount = 1
            startedOperationCount = $startedOperationCount
            schedulingClosed = $true
        }
        recovery = [pscustomobject][ordered]@{
            staleOwnerDetected = $abandonedOwner
            collectionResumed = $false
        }
    }
    $records.Add($terminal)

    $maximumGap = 0L
    for ($index = 1; $index -lt $progressTimes.Count; $index++) {
        $maximumGap = [Math]::Max($maximumGap, $progressTimes[$index] - $progressTimes[$index - 1])
    }
    $metrics = [pscustomobject][ordered]@{
        firstProgressMilliseconds = $progressTimes[0]
        maximumHeartbeatGapMilliseconds = $maximumGap
        cancellationAcknowledgementMilliseconds = $cancellationAcknowledgementMilliseconds
    }
    $terminal | Add-Member -NotePropertyName metrics -NotePropertyValue $metrics
    [pscustomobject][ordered]@{
        ExitCode = $terminal.exitCode
        Records = $records.ToArray()
        Terminal = $terminal
        AssessmentRecord = $assessmentRecord
        ContractValidation = $contractValidation
        Metrics = $metrics
    }
}

function Read-RunLifecycleFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand
    )

    try {
        $resolved = [System.IO.Path]::GetFullPath($LiteralPath)
        $file = [System.IO.FileInfo]::new($resolved)
        if (-not $file.Exists -or $file.Length -gt 1024) { throw 'Fixture unavailable or oversize.' }
        $json = [System.IO.File]::ReadAllText(
            $resolved, [System.Text.UTF8Encoding]::new($false, $true)
        )
        $parseOptions = [System.Text.Json.JsonDocumentOptions]::new()
        $parseOptions.MaxDepth = 4
        $document = [System.Text.Json.JsonDocument]::Parse($json, $parseOptions)
        try {
            if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) {
                throw 'Fixture root is not an object.'
            }
            $lexicalNames = @(
                $document.RootElement.EnumerateObject() | ForEach-Object { $_.Name }
            )
            if ($lexicalNames.Count -ne 2 -or
                @($lexicalNames | Sort-Object -Unique).Count -ne 2) {
                throw 'Fixture properties are not lexically unique and closed.'
            }
        }
        finally {
            $document.Dispose()
        }
        $fixture = & $ConvertFromJsonCommand -InputObject $json -ErrorAction Stop
        $properties = @($fixture.PSObject.Properties.Name | Sort-Object)
        if ($fixture.contractVersion -ne '1.0.0' -or
            @($properties).Count -ne 2 -or $properties[0] -ne 'contractVersion' -or
            $properties[1] -ne 'scenario' -or
            $fixture.scenario -notin @(
                (Get-AssessmentRunLifecyclePolicy).validationScenarios
            )) {
            throw 'Fixture is outside the release-owned scenario set.'
        }
        $fixture
    }
    catch {
        $exception = [System.InvalidOperationException]::new(
            'The synthetic lifecycle fixture is invalid.'
        )
        $exception.Data['ReasonCode'] = 'RUN.FIXTURE_INVALID'
        throw $exception
    }
}

function Invoke-RunLifecycleFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand
    )

    try {
        $fixture = Read-RunLifecycleFixture -LiteralPath $LiteralPath `
            -ConvertFromJsonCommand $ConvertFromJsonCommand
    }
    catch {
        $terminal = New-TerminalRecord -ReasonCode 'RUN.FIXTURE_INVALID' `
            -ValidationFixture $true -Phase 'RunControl'
        Write-ContractRecord $terminal -ConvertToJsonCommand $ConvertToJsonCommand
        return 20
    }

    $scenario = [string] $fixture.scenario
    $collectorAdapter = {
        param([System.Threading.CancellationToken] $CancellationToken)

        switch ($scenario) {
            'Timeout' {
                Invoke-ApprovedCollectorProcess -OperationId 'fixture:synthetic.timeout' `
                    -CancellationToken $CancellationToken
            }
            'Cancellation' {
                $fixtureCancellation =
                    [System.Threading.CancellationTokenSource]::CreateLinkedTokenSource(
                        $CancellationToken
                    )
                try {
                    $fixtureCancellation.CancelAfter(200)
                    Invoke-ApprovedCollectorProcess `
                        -OperationId 'fixture:synthetic.cooperative-cancel' `
                        -CancellationToken $fixtureCancellation.Token
                }
                finally {
                    $fixtureCancellation.Dispose()
                }
            }
            'PackageUnavailable' {
                Invoke-ApprovedCollectorProcess -OperationId 'op:synthetic.windows.os.success' `
                    -CancellationToken $CancellationToken
            }
        }
    }.GetNewClosure()
    $unavailableFinalizer = {
        param($AssessmentRecord)

        # Ticket #46 supplies the real Protected Package finalizer. Until then,
        # the generated artifact must fail integrity instead of manufacturing a
        # completion claim from a test double or an unprotected record.
        [pscustomobject][ordered]@{
                state = 'IntegrityFailed'
                verified = $false
                protection = 'None'
                recoverable = $false
        }
    }
    $verifiedCleanup = {
        param([string] $RunId)

        [pscustomobject][ordered]@{
            state = 'VerifiedAbsent'
            verified = $true
            reasonCode = 'CLEANUP.VERIFIED'
        }
    }
    $runId = "run:synthetic:$([System.Guid]::NewGuid().ToString('N'))"
    $progressAdapter = {
        param($ProgressRecord)
        Write-ContractRecord $ProgressRecord -ConvertToJsonCommand $ConvertToJsonCommand
    }.GetNewClosure()
    $result = Invoke-AssessmentRun -RunId $runId -CollectorAdapter $collectorAdapter `
        -FinalizerAdapter $unavailableFinalizer -CleanupAdapter $verifiedCleanup `
        -ProgressAdapter $progressAdapter
    foreach ($record in @($result.Records | Where-Object recordType -ne 'win-pcinfo.progress')) {
        Write-ContractRecord $record -ConvertToJsonCommand $ConvertToJsonCommand
    }
    [int] $result.ExitCode
}
