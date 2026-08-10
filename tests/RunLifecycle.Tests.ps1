[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-RunEqual {
    param(
        [Parameter(Mandatory)] $Expected,
        [Parameter(Mandatory)] $Actual,
        [Parameter(Mandatory)] [string] $Because
    )

    if ($Expected -ne $Actual) {
        throw "Expected '$Expected' but received '$Actual': $Because"
    }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ContractValidator.ps1')
. (Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1')
. (Join-Path $repositoryRoot 'src/RunLifecycle.ps1')

$uncooperativeAdapter = {
    param($InputValue, [System.Threading.CancellationToken] $CancellationToken)

    [System.Threading.Thread]::Sleep(5000)
    [pscustomobject]@{ verified = $true }
}
$boundaryWatch = [System.Diagnostics.Stopwatch]::StartNew()
$boundaryResult = Invoke-BoundedLifecycleAdapter -Adapter $uncooperativeAdapter `
    -InputValue 'synthetic-boundary-probe' `
    -RunCancellationToken ([System.Threading.CancellationToken]::None) `
    -MaximumMilliseconds 1000 -TerminationMilliseconds 500
$boundaryWatch.Stop()

Assert-RunEqual $false $boundaryResult.completed `
    'an uncooperative adapter cannot outlive its operation and be called complete'
Assert-RunEqual $true $boundaryResult.terminationVerified `
    'the Job Object must prove the complete uncooperative adapter tree absent'
if ($boundaryWatch.ElapsedMilliseconds -ge 1500) {
    throw "The uncooperative adapter boundary took $($boundaryWatch.ElapsedMilliseconds) ms."
}

Write-Output 'PASS: an uncooperative adapter tree is forcibly terminated and proved absent inside its deadline.'

$collector = {
    param([System.Threading.CancellationToken] $CancellationToken)

    [pscustomobject][ordered]@{
        Envelope = [pscustomobject][ordered]@{
            envelopeId = 'envelope:synthetic-windows-os:lifecycle'
            collectorId = 'collector:synthetic.windows.os'
            collectorVersion = '1.0.0'
            operationId = 'op:synthetic.windows.os.success'
            intendedScopeIds = @('scope:synthetic.device.os')
            subjectIds = @('subject:synthetic-device:primary')
            startedAt = '2000-01-01T00:00:00Z'
            completedAt = '2000-01-01T00:00:01Z'
            executionContext = 'Synthetic'
            attempts = 1
            observationIds = @('observation:synthetic-os-name:lifecycle')
            coverageIds = @('coverage:synthetic-device-os:lifecycle')
            diagnosticIds = @()
        }
        Observations = @([pscustomobject][ordered]@{
            observationId = 'observation:synthetic-os-name:lifecycle'
            fieldId = 'field:device.os.display-name'
            subjectId = 'subject:synthetic-device:primary'
            valueState = 'ObservedValue'
            value = 'WIN-PCInfo synthetic lifecycle'
        })
        Coverage = @([pscustomobject][ordered]@{
            coverageId = 'coverage:synthetic-device-os:lifecycle'
            scopeId = 'scope:synthetic.device.os'
            state = 'Complete'
            reasonCode = 'COLLECTION.COMPLETE'
            observationIds = @('observation:synthetic-os-name:lifecycle')
            diagnosticIds = @()
        })
        Diagnostics = @()
        Supervision = [pscustomobject][ordered]@{
            outcome = 'Completed'
            reasonCode = 'PROCESS.COMPLETED'
            completeOwnedTreeAbsent = $true
            temporaryArtifactsAbsent = $true
        }
    }
}
$testFinalizer = {
    param($AssessmentRecord, [System.Threading.CancellationToken] $CancellationToken)

    [pscustomobject][ordered]@{
        state = 'Verified'
        verified = $true
        protection = 'InjectedSyntheticTestFinalizer'
        packageId = "package:synthetic:$($AssessmentRecord.run.runId)"
        recoverable = $true
        privateDetail = 'password=synthetic-must-not-cross'
    }
}
$cleanup = {
    param([string] $RunId, [System.Threading.CancellationToken] $CancellationToken)

    [pscustomobject][ordered]@{
        state = 'VerifiedAbsent'
        verified = $true
        reasonCode = 'CLEANUP.VERIFIED'
        privateDetail = 'credential=synthetic-must-not-cross'
    }
}

$completed = Invoke-AssessmentRun -RunId 'run:synthetic:lifecycle-complete' `
    -CollectorAdapter $collector -FinalizerAdapter $testFinalizer -CleanupAdapter $cleanup

Assert-RunEqual 0 $completed.ExitCode 'Completed has one stable process exit code'
Assert-RunEqual 1 @($completed.Records | Where-Object recordType -eq 'win-pcinfo.terminal').Count `
    'an accepted request reaches exactly one terminal record'
Assert-RunEqual 'Completed' $completed.Terminal.outcome `
    'verified complete evidence reaches the Completed Assessment Run Outcome'
Assert-RunEqual 'Verified' $completed.Terminal.package.state `
    'completion is impossible without a verified Protected Evidence Package result'
Assert-RunEqual $true $completed.Terminal.cleanup.verified `
    'the terminal outcome includes verified run-owned cleanup'
Assert-RunEqual 'Complete' $completed.Terminal.coverage[0].state `
    'terminal coverage agrees with the Assessment Record'
Assert-RunEqual $true $completed.ContractValidation.accepted `
    'the lifecycle validates its Assessment Record before finalization'
if (@($completed.Records | Where-Object {
    $_.recordType -eq 'win-pcinfo.progress' -and $_.state -eq 'Heartbeat'
}).Count -eq 0) {
    throw 'An active Assessment Run must emit a structured heartbeat.'
}
if ($completed.Metrics.firstProgressMilliseconds -gt 5000) {
    throw "First progress took $($completed.Metrics.firstProgressMilliseconds) ms."
}
if ($completed.Metrics.maximumHeartbeatGapMilliseconds -gt 10000) {
    throw "The active heartbeat gap reached $($completed.Metrics.maximumHeartbeatGapMilliseconds) ms."
}
if (($completed.Records | ConvertTo-Json -Compress -Depth 30) -match '(?i)password|credential|token') {
    throw 'Structured progress or terminal output included a prohibited secret-shaped name.'
}

Write-Output 'PASS: accepted lifecycle completion requires validated evidence, a verified package, cleanup, and one terminal outcome.'

$partialCollector = {
    param([System.Threading.CancellationToken] $CancellationToken)

    $result = & $collector $CancellationToken
    $diagnosticId = 'diagnostic:synthetic-collector-failure:lifecycle'
    $result.Supervision.outcome = 'Failed'
    $result.Supervision.reasonCode = 'PROCESS.OUTPUT_LIMIT_EXCEEDED'
    $result.Coverage[0].state = 'Partial'
    $result.Coverage[0].reasonCode = 'COLLECTION.ISOLATED_FAILURE'
    $result.Coverage[0].diagnosticIds = @($diagnosticId)
    $result.Envelope.diagnosticIds = @($diagnosticId)
    $result.Diagnostics = @([pscustomobject][ordered]@{
        diagnosticId = $diagnosticId
        scopeId = 'scope:synthetic.device.os'
        phase = 'Collection'
        reasonCode = 'COLLECTION.ISOLATED_FAILURE'
        operatorMessageId = 'collection.isolated-failure'
    })
    $result
}

$completedWithGaps = Invoke-AssessmentRun -RunId 'run:synthetic:lifecycle-gaps' `
    -CollectorAdapter $partialCollector -FinalizerAdapter $testFinalizer -CleanupAdapter $cleanup

Assert-RunEqual 10 $completedWithGaps.ExitCode `
    'CompletedWithGaps has a stable exit code distinct from complete success'
Assert-RunEqual 'CompletedWithGaps' $completedWithGaps.Terminal.outcome `
    'an isolated collector failure remains visible despite useful partial evidence'
Assert-RunEqual 'Partial' $completedWithGaps.Terminal.coverage[0].state `
    'terminal coverage preserves the collector gap'
Assert-RunEqual 'Verified' $completedWithGaps.Terminal.package.state `
    'useful partial evidence is protected before CompletedWithGaps is exposed'
Assert-RunEqual $true $completedWithGaps.ContractValidation.accepted `
    'the partial Assessment Record is validated before finalization'
Assert-RunEqual 1 @($completedWithGaps.Records | Where-Object recordType -eq 'win-pcinfo.terminal').Count `
    'partial completion still has exactly one terminal outcome'

Write-Output 'PASS: isolated collector failure produces protected, validated CompletedWithGaps evidence.'

$cancelledCollector = {
    param([System.Threading.CancellationToken] $CancellationToken)

    $result = & $collector $CancellationToken
    $diagnosticId = 'diagnostic:synthetic-cancelled:lifecycle'
    $result.Supervision.outcome = 'Cancelled'
    $result.Supervision.reasonCode = 'PROCESS.CANCELLED_COOPERATIVELY'
    $result.Coverage[0].state = 'Cancelled'
    $result.Coverage[0].reasonCode = 'COLLECTION.CANCELLED'
    $result.Coverage[0].observationIds = @()
    $result.Coverage[0].diagnosticIds = @($diagnosticId)
    $result.Envelope.observationIds = @()
    $result.Envelope.diagnosticIds = @($diagnosticId)
    $result.Observations = @()
    $result.Diagnostics = @([pscustomobject][ordered]@{
        diagnosticId = $diagnosticId
        scopeId = 'scope:synthetic.device.os'
        phase = 'Collection'
        reasonCode = 'COLLECTION.CANCELLED'
        operatorMessageId = 'collection.cancelled'
    })
    $result
}
$recoverableFinalizer = {
    param($AssessmentRecord, [System.Threading.CancellationToken] $CancellationToken)

    [pscustomobject][ordered]@{
        state = 'RecoverableProtected'
        verified = $true
        protection = 'InjectedSyntheticTestFinalizer'
        packageId = "package:synthetic:$($AssessmentRecord.run.runId)"
        recoverable = $true
    }
}

$operatorCancellation = [System.Threading.CancellationTokenSource]::new()
$externallyCancelledCollector = {
    param([System.Threading.CancellationToken] $CancellationToken)

    if (-not $CancellationToken.WaitHandle.WaitOne(1000)) {
        throw 'The external cancellation did not reach active collection.'
    }
    & $cancelledCollector $CancellationToken
}.GetNewClosure()
$operatorCancellation.CancelAfter(25)
try {
    $cancelled = Invoke-AssessmentRun -RunId 'run:synthetic:lifecycle-cancelled' `
        -CollectorAdapter $externallyCancelledCollector -FinalizerAdapter $recoverableFinalizer `
        -CleanupAdapter $cleanup -CancellationToken $operatorCancellation.Token
}
finally { $operatorCancellation.Dispose() }

Assert-RunEqual 30 $cancelled.ExitCode 'Cancelled has one stable exit code'
Assert-RunEqual 'Cancelled' $cancelled.Terminal.outcome `
    'one deliberate cancellation remains distinct from failure or timeout'
Assert-RunEqual 'Cancelled' $cancelled.Terminal.coverage[0].state `
    'cancelled collection has matching Evidence Coverage State'
Assert-RunEqual 'NotRequired' $cancelled.Terminal.package.state `
    'the terminal record states honestly that this fixture returned no recoverable evidence'
Assert-RunEqual 1 $cancelled.Terminal.scheduling.startedOperationCount `
    'cancellation stops any new operation from being scheduled'
Assert-RunEqual 1 @($cancelled.Records | Where-Object {
    $_.recordType -eq 'win-pcinfo.progress' -and $_.state -eq 'Acknowledged'
}).Count 'cancellation has one structured acknowledgement'
if ($cancelled.Metrics.cancellationAcknowledgementMilliseconds -gt 2000) {
    throw "Cancellation acknowledgement took $($cancelled.Metrics.cancellationAcknowledgementMilliseconds) ms."
}
Assert-RunEqual $true $cancelled.Terminal.cleanup.verified `
    'cancellation proceeds to cleanup without another prompt'

Write-Output 'PASS: cancellation stops scheduling, protects recoverable evidence, acknowledges promptly, and cleans up.'

$timedOutCollector = {
    param([System.Threading.CancellationToken] $CancellationToken)

    $result = & $collector $CancellationToken
    $diagnosticId = 'diagnostic:synthetic-timeout:lifecycle'
    $result.Supervision.outcome = 'TimedOut'
    $result.Supervision.reasonCode = 'PROCESS.DEADLINE_EXCEEDED'
    $result.Coverage[0].state = 'TimedOut'
    $result.Coverage[0].reasonCode = 'COLLECTION.TIMED_OUT'
    $result.Coverage[0].observationIds = @()
    $result.Coverage[0].diagnosticIds = @($diagnosticId)
    $result.Envelope.observationIds = @()
    $result.Envelope.diagnosticIds = @($diagnosticId)
    $result.Observations = @()
    $result.Diagnostics = @([pscustomobject][ordered]@{
        diagnosticId = $diagnosticId
        scopeId = 'scope:synthetic.device.os'
        phase = 'Collection'
        reasonCode = 'COLLECTION.TIMED_OUT'
        operatorMessageId = 'collection.timed-out'
    })
    $result
}

$timedOut = Invoke-AssessmentRun -RunId 'run:synthetic:lifecycle-timeout' `
    -CollectorAdapter $timedOutCollector -FinalizerAdapter $testFinalizer -CleanupAdapter $cleanup

Assert-RunEqual 40 $timedOut.ExitCode 'TimedOut has one stable exit code'
Assert-RunEqual 'TimedOut' $timedOut.Terminal.outcome `
    'an operation deadline remains distinct from cancellation or failure'
Assert-RunEqual 'TimedOut' $timedOut.Terminal.coverage[0].state `
    'the terminal timeout agrees with Evidence Coverage State'
Assert-RunEqual 'win-pcinfo.run-lifecycle/1.0.0' $timedOut.Terminal.deadlines.policyId `
    'the terminal result binds the release-owned lifecycle deadline policy'
Assert-RunEqual 1 $timedOut.Terminal.deadlines.operation.maximumAttempts `
    'the synthetic operation permits no unbounded retry'
if ($timedOut.Terminal.deadlines.run.maximumMilliseconds -le 0 -or
    $timedOut.Terminal.deadlines.process.maximumMilliseconds -le 0 -or
    @($timedOut.Terminal.deadlines.phases | Where-Object maximumMilliseconds -le 0).Count -gt 0) {
    throw 'Every run, process, and phase requires an explicit finite deadline.'
}

Write-Output 'PASS: timeout is typed and every lifecycle layer has a finite release-owned deadline and bounded attempts.'

$lostWorker = {
    param([System.Threading.CancellationToken] $CancellationToken)

    $exception = [System.InvalidOperationException]::new(
        'synthetic private worker detail must not cross the public run interface'
    )
    $exception.Data['ReasonCode'] = 'RUN.WORKER_LOST'
    throw $exception
}

$workerLoss = Invoke-AssessmentRun -RunId 'run:synthetic:lifecycle-worker-loss' `
    -CollectorAdapter $lostWorker -FinalizerAdapter $testFinalizer -CleanupAdapter $cleanup

Assert-RunEqual 50 $workerLoss.ExitCode 'worker loss uses the stable IntegrityFailed exit code'
Assert-RunEqual 'IntegrityFailed' $workerLoss.Terminal.outcome `
    'loss of the owned worker cannot become a useful partial completion'
Assert-RunEqual 'RUN.WORKER_LOST' $workerLoss.Terminal.reasonCode `
    'worker loss has a stable sanitized reason'
Assert-RunEqual 'Failed' $workerLoss.Terminal.coverage[0].state `
    'worker loss preserves an explicit failed Evidence Coverage State'
Assert-RunEqual 'NotRequired' $workerLoss.Terminal.package.state `
    'no package is claimed when no normalized evidence was recovered'
if (($workerLoss.Records | ConvertTo-Json -Compress -Depth 30) -match 'private worker detail') {
    throw 'Private worker exception text crossed the sanitized public interface.'
}

Write-Output 'PASS: worker loss fails integrity with explicit coverage and no private diagnostic text.'

$failedCleanup = {
    param([string] $RunId, [System.Threading.CancellationToken] $CancellationToken)

    throw 'synthetic private cleanup failure detail'
}

$cleanupIncomplete = Invoke-AssessmentRun -RunId 'run:synthetic:lifecycle-cleanup' `
    -CollectorAdapter $collector -FinalizerAdapter $testFinalizer -CleanupAdapter $failedCleanup

Assert-RunEqual 60 $cleanupIncomplete.ExitCode `
    'CleanupIncomplete has the highest stable exit code in this lifecycle contract'
Assert-RunEqual 'CleanupIncomplete' $cleanupIncomplete.Terminal.outcome `
    'uncertain cleanup overrides otherwise useful complete evidence'
Assert-RunEqual 'CleanupIncomplete' $cleanupIncomplete.AssessmentRecord.run.outcome `
    'the finalized Assessment Record agrees with the terminal cleanup outcome'
Assert-RunEqual $true $cleanupIncomplete.ContractValidation.accepted `
    'cleanup failure is represented by a semantically valid Assessment Record'
Assert-RunEqual 'Verified' $cleanupIncomplete.Terminal.package.state `
    'the trustworthy package preserves the final cleanup-incomplete record'
Assert-RunEqual $false $cleanupIncomplete.Terminal.cleanup.verified `
    'uncertain residue remains visible and is never called verified'
if (($cleanupIncomplete.Records | ConvertTo-Json -Compress -Depth 30) -match 'private cleanup') {
    throw 'Private cleanup exception text crossed the sanitized public interface.'
}

Write-Output 'PASS: cleanup failure takes precedence and the protected Assessment Record agrees with the terminal outcome.'

$blockingCleanup = {
    param([string] $RunId, [System.Threading.CancellationToken] $CancellationToken)

    [System.Threading.Thread]::Sleep(30000)
    throw 'an over-budget cleanup must never reach this point'
}
$cleanupDeadlineWatch = [System.Diagnostics.Stopwatch]::StartNew()
$cleanupDeadline = Invoke-AssessmentRun -RunId 'run:synthetic:lifecycle-cleanup-deadline' `
    -CollectorAdapter $collector -FinalizerAdapter $testFinalizer -CleanupAdapter $blockingCleanup
$cleanupDeadlineWatch.Stop()

Assert-RunEqual 60 $cleanupDeadline.ExitCode 'an over-budget cleanup remains CleanupIncomplete'
Assert-RunEqual $false $cleanupDeadline.Terminal.cleanup.verified `
    'a stopped cleanup adapter cannot claim that owned residue is absent'
if ($cleanupDeadlineWatch.ElapsedMilliseconds -ge 6000) {
    throw "Bounded cleanup took $($cleanupDeadlineWatch.ElapsedMilliseconds) ms."
}

Write-Output 'PASS: cleanup cancellation and hard stop are bounded by the release phase deadline.'

$failedFinalizer = {
    param($AssessmentRecord, [System.Threading.CancellationToken] $CancellationToken)

    throw 'synthetic private package failure detail'
}

$integrityFailed = Invoke-AssessmentRun -RunId 'run:synthetic:lifecycle-integrity' `
    -CollectorAdapter $collector -FinalizerAdapter $failedFinalizer -CleanupAdapter $cleanup

Assert-RunEqual 50 $integrityFailed.ExitCode 'IntegrityFailed has one stable exit code'
Assert-RunEqual 'IntegrityFailed' $integrityFailed.Terminal.outcome `
    'package verification failure overrides complete collected evidence'
Assert-RunEqual 'RUN.PACKAGE_INTEGRITY_FAILED' $integrityFailed.Terminal.reasonCode `
    'package verification failure has one stable sanitized reason'
Assert-RunEqual 'Failed' $integrityFailed.Terminal.integrity.state `
    'the terminal record exposes the failed final integrity gate'
Assert-RunEqual 0 @($integrityFailed.Records | Where-Object recordType -eq 'win-pcinfo.assessment-record').Count `
    'an unprotected provisional Assessment Record is not emitted as a completed artifact'
Assert-RunEqual $true $integrityFailed.Terminal.cleanup.verified `
    'integrity failure does not hide independently verified cleanup'
if (($integrityFailed.Records | ConvertTo-Json -Compress -Depth 30) -match 'private package') {
    throw 'Private package exception text crossed the sanitized public interface.'
}

Write-Output 'PASS: package integrity failure takes precedence and no provisional record is exposed as complete.'

$blockingFinalizer = {
    param($AssessmentRecord, [System.Threading.CancellationToken] $CancellationToken)

    [System.Threading.Thread]::Sleep(30000)
    throw 'an over-budget finalizer must never reach this point'
}
$packageDeadlineWatch = [System.Diagnostics.Stopwatch]::StartNew()
$packageDeadline = Invoke-AssessmentRun -RunId 'run:synthetic:lifecycle-package-deadline' `
    -CollectorAdapter $collector -FinalizerAdapter $blockingFinalizer -CleanupAdapter $cleanup
$packageDeadlineWatch.Stop()

Assert-RunEqual 50 $packageDeadline.ExitCode 'an over-budget finalizer fails package integrity'
Assert-RunEqual 'IntegrityFailed' $packageDeadline.Terminal.outcome `
    'package deadline expiry cannot expose a useful completion'
Assert-RunEqual 0 @($packageDeadline.Records | Where-Object {
    $_.recordType -eq 'win-pcinfo.assessment-record'
}).Count 'a timed-out finalizer cannot expose its provisional Assessment Record'
if ($packageDeadlineWatch.ElapsedMilliseconds -ge 6000) {
    throw "Bounded packaging took $($packageDeadlineWatch.ElapsedMilliseconds) ms."
}

Write-Output 'PASS: package cancellation and hard stop are bounded by the release phase deadline.'

$lockReadyName = "Local\WINPCInfo-Lifecycle-Ready-$([System.Guid]::NewGuid().ToString('N'))"
$lockReleaseName = "Local\WINPCInfo-Lifecycle-Release-$([System.Guid]::NewGuid().ToString('N'))"
[bool] $createdReady = $false
[bool] $createdRelease = $false
$lockReady = [System.Threading.EventWaitHandle]::new(
    $false, [System.Threading.EventResetMode]::ManualReset, $lockReadyName, [ref] $createdReady
)
$lockRelease = [System.Threading.EventWaitHandle]::new(
    $false, [System.Threading.EventResetMode]::ManualReset, $lockReleaseName, [ref] $createdRelease
)
$lockOwner = $null
try {
    $ownerScript = @"
`$mutex = [System.Threading.Mutex]::new(`$false, 'Global\WINPCInfo-AssessmentRun-v1')
`$owned = `$mutex.WaitOne(0)
`$ready = [System.Threading.EventWaitHandle]::OpenExisting('$lockReadyName')
`$release = [System.Threading.EventWaitHandle]::OpenExisting('$lockReleaseName')
`$ready.Set() | Out-Null
`$signalled = `$release.WaitOne(5000)
if (`$owned) { `$mutex.ReleaseMutex() }
`$ready.Dispose(); `$release.Dispose(); `$mutex.Dispose()
if (-not `$owned -or -not `$signalled) { exit 1 }
"@
    $ownerPayload = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes($ownerScript)
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command pwsh -CommandType Application).Source
    $startInfo.UseShellExecute = $false
    $null = $startInfo.ArgumentList.Add('-NoLogo')
    $null = $startInfo.ArgumentList.Add('-NoProfile')
    $null = $startInfo.ArgumentList.Add('-NonInteractive')
    $null = $startInfo.ArgumentList.Add('-EncodedCommand')
    $null = $startInfo.ArgumentList.Add($ownerPayload)
    $lockOwner = [System.Diagnostics.Process]::Start($startInfo)
    if (-not $lockReady.WaitOne(2000)) { throw 'The synthetic live lock owner did not become ready.' }

    $concurrent = Invoke-AssessmentRun -RunId 'run:synthetic:lifecycle-concurrent' `
        -CollectorAdapter $collector -FinalizerAdapter $testFinalizer -CleanupAdapter $cleanup

    Assert-RunEqual 20 $concurrent.ExitCode 'a second launch uses the stable NotStarted exit code'
    Assert-RunEqual 'NotStarted' $concurrent.Terminal.outcome `
        'a second launch does not join a live Assessment Run'
    Assert-RunEqual 'RUN.ACTIVE_LOCK_HELD' $concurrent.Terminal.reasonCode `
        'the live owner is represented by one stable reason'
    Assert-RunEqual 'OwnedByAnotherRun' $concurrent.Terminal.lock.state `
        'the terminal result identifies the device-wide ownership boundary'
    Assert-RunEqual 0 $concurrent.Terminal.scheduling.startedOperationCount `
        'a second launch schedules no collection'
    Assert-RunEqual 'None' $concurrent.Terminal.lock.interference `
        'the second launch neither signals nor terminates the owner'
}
finally {
    $null = $lockRelease.Set()
    if ($null -ne $lockOwner) {
        if (-not $lockOwner.WaitForExit(3000)) { throw 'The synthetic lock owner did not exit.' }
        Assert-RunEqual 0 $lockOwner.ExitCode 'the second launch did not disrupt the live owner'
        $lockOwner.Dispose()
    }
    $lockReady.Dispose()
    $lockRelease.Dispose()
}

Write-Output 'PASS: a concurrent launch neither joins nor disrupts the live device-wide run owner.'

$abandonedReadyName = "Local\WINPCInfo-Lifecycle-Abandoned-$([System.Guid]::NewGuid().ToString('N'))"
[bool] $createdAbandonedReady = $false
$abandonedReady = [System.Threading.EventWaitHandle]::new(
    $false, [System.Threading.EventResetMode]::ManualReset,
    $abandonedReadyName, [ref] $createdAbandonedReady
)
$abandonedProbe = [System.Threading.Mutex]::new(
    $false, 'Global\WINPCInfo-AssessmentRun-v1'
)
$abandonedOwner = $null
try {
    $abandonedScript = @"
`$mutex = [System.Threading.Mutex]::new(`$false, 'Global\WINPCInfo-AssessmentRun-v1')
`$owned = `$mutex.WaitOne(0)
`$ready = [System.Threading.EventWaitHandle]::OpenExisting('$abandonedReadyName')
`$ready.Set() | Out-Null
`$ready.Dispose()
if (-not `$owned) { exit 1 }
# Deliberately exit without ReleaseMutex to model interruption at the lock seam.
exit 0
"@
    $abandonedPayload = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes($abandonedScript)
    )
    $abandonedStartInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $abandonedStartInfo.FileName = (Get-Command pwsh -CommandType Application).Source
    $abandonedStartInfo.UseShellExecute = $false
    foreach ($argument in @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $abandonedPayload
    )) {
        $null = $abandonedStartInfo.ArgumentList.Add($argument)
    }
    $abandonedOwner = [System.Diagnostics.Process]::Start($abandonedStartInfo)
    if (-not $abandonedReady.WaitOne(2000)) { throw 'The synthetic abandoned owner did not become ready.' }
    if (-not $abandonedOwner.WaitForExit(2000)) { throw 'The synthetic abandoned owner did not exit.' }
    Assert-RunEqual 0 $abandonedOwner.ExitCode 'the synthetic owner reached the crash boundary'

    $recovery = Invoke-AssessmentRun -RunId 'run:synthetic:lifecycle-recovery' `
        -CollectorAdapter $collector -FinalizerAdapter $testFinalizer -CleanupAdapter $cleanup

    Assert-RunEqual 20 $recovery.ExitCode 'safe stale-owner recovery remains NotStarted'
    Assert-RunEqual 'RUN.STALE_OWNER_RECOVERED' $recovery.Terminal.reasonCode `
        'abandoned ownership has a stable recovery reason'
    Assert-RunEqual 'AbandonedOwnerRecovered' $recovery.Terminal.lock.state `
        'the terminal result distinguishes recovery from ordinary acquisition'
    Assert-RunEqual 0 $recovery.Terminal.scheduling.startedOperationCount `
        'collection never resumes after interruption'
    Assert-RunEqual $false $recovery.Terminal.recovery.collectionResumed `
        'the recovery contract explicitly forbids resuming collection'
    Assert-RunEqual $true $recovery.Terminal.cleanup.verified `
        'recovery returns only after registered synthetic residue is verified absent'
}
finally {
    if ($null -ne $abandonedOwner) { $abandonedOwner.Dispose() }
    $abandonedProbe.Dispose()
    $abandonedReady.Dispose()
}

Write-Output 'PASS: an abandoned run enters cleanup-only recovery and never resumes collection.'
