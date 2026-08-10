[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ContractValidator.ps1')
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $repositoryRoot 'src/SystemCollectionPlan.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$convertToJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
    'ConvertTo-Json', [System.Management.Automation.CommandTypes]::Cmdlet
)
$preparationPlan = [pscustomobject][ordered]@{
    recordType = 'win-pcinfo.preparation-plan'
    contractVersion = '1.0.0'
    release = '2.0.0-preview.1'
    privilege = [pscustomobject][ordered]@{
        privilegedOperationsFrozen = $true
        privilegedOperations = @(
            [pscustomobject][ordered]@{
                operationId = 'observe-mdm-system-context'
                context = 'LocalSystem'
            }
        )
    }
}
$preparationDigest = Get-ObjectDigest -Value $preparationPlan `
    -ConvertToJsonCommand $convertToJsonCommand
$planResult = New-SystemCollectionPlan -PreparationPlan $preparationPlan `
    -PreparationPlanDigest $preparationDigest

Assert-Equal 1 @($planResult.Plan.operations).Count `
    'the separate frozen sub-plan contains exactly one SYSTEM operation'
Assert-Equal 'op:windows.mdm-bridge.device-manageability' `
    $planResult.Plan.operations[0].operationId `
    'the preparation operation maps to one release-owned SYSTEM operation ID'
Assert-Equal 'DeviceManageabilityAvailability' `
    $planResult.Plan.operations[0].parameters.queryKind `
    'the frozen plan carries only the closed typed query selector'

$accepted = Invoke-SystemCollectionPlan -Plan $planResult.Plan `
    -PlanDigest $planResult.Digest -ValidationScenario 'SyntheticSuccess'

Assert-Equal 'Completed' $accepted.state `
    'the release-owned synthetic SYSTEM sub-plan completes at the exported seam'
Assert-Equal 'SYSTEM.COMPLETED' $accepted.reasonCode `
    'success has one stable sanitized reason'
Assert-Equal 1 @($accepted.collectorResult.Envelope).Count `
    'SYSTEM evidence returns through one normal Collector Result Envelope'
Assert-Equal 'collector:windows.mdm-bridge.device-manageability' `
    $accepted.collectorResult.Envelope.collectorId `
    'the envelope carries the release-owned collector identity'
Assert-Equal 'Synthetic' $accepted.collectorResult.Envelope.executionContext `
    'unelevated validation never claims real LocalSystem execution provenance'
Assert-Equal 'LocalSystem' $accepted.activation.requiredExecutionContext `
    'the result retains the exact context required by the live source'
Assert-Equal $false $accepted.activation.localSystemIdentityVerified `
    'synthetic validation cannot claim a verified LocalSystem token'
Assert-Equal 'Complete' $accepted.collectorResult.Coverage[0].state `
    'the synthetic source closes only its declared Evidence Scope'
Assert-Equal $true $accepted.cleanup.verified `
    'the worker, task, pipe, and process tree are absent before return'
Assert-Equal $true $accepted.cleanup.workerTreeAbsent `
    'Job Object ownership proves the synthetic worker tree absent'
Assert-Equal $true $accepted.cleanup.taskAbsent `
    'no scheduled task survives the synthetic terminal path'
Assert-Equal $true $accepted.cleanup.pipeAbsent `
    'the one-use SYSTEM channel is disposed before return'
Assert-Equal 'SyntheticUnelevated' $accepted.validation.mode `
    'the exported result identifies the controlled-client validation limitation'
Assert-Equal 'SYSTEM.LIVE_ACTIVATION_VALIDATION_UNAVAILABLE' `
    $accepted.validation.environmentalLimitation.reasonCode `
    'missing live SYSTEM validation has one public-safe typed reason'
Assert-Equal $true $accepted.standardUserWorkMayContinue `
    'successful SYSTEM collection leaves unrelated safe work schedulable'
Assert-Equal 1 @($accepted.collectorResult.Provenance).Count `
    'the collector result includes the normal observation provenance object'
Assert-Equal $accepted.collectorResult.Envelope.executionContext `
    $accepted.collectorResult.Provenance[0].executionContext `
    'envelope and observation provenance agree on the exact execution context'
$attemptStarted = [System.DateTimeOffset]::Parse($accepted.collectorResult.Envelope.startedAt)
$attemptCompleted = [System.DateTimeOffset]::Parse($accepted.collectorResult.Envelope.completedAt)
$observationCollected = [System.DateTimeOffset]::Parse(
    $accepted.collectorResult.Provenance[0].collectedAt
)
if ($attemptStarted -gt $observationCollected -or
    $observationCollected -gt $attemptCompleted) {
    throw 'SYSTEM timing does not enclose the actual accepted observation.'
}

$systemAssessment = New-SystemAssessmentRecord -SystemResult $accepted
$testJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
    'Test-Json', [System.Management.Automation.CommandTypes]::Cmdlet
)
$assessmentReason = Get-SystemAssessmentRecordValidationReason `
    -Record $systemAssessment -Policy (Get-SystemCollectionPlanPolicy) `
    -ConvertFromJsonCommand (Get-Command ConvertFrom-Json) `
    -ConvertToJsonCommand $convertToJsonCommand -TestJsonCommand $testJsonCommand
if ($assessmentReason) {
    throw "The SYSTEM envelope was rejected inside its Assessment Record: $assessmentReason"
}

$liveAssessment = $systemAssessment | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
$liveAssessment.run.validationFixture = $false
$liveAssessment.provenance[0].executionContext = 'LocalSystem'
$liveAssessment.collectorResults[0].executionContext = 'LocalSystem'
$liveReason = Get-SystemAssessmentRecordValidationReason -Record $liveAssessment `
    -Policy (Get-SystemCollectionPlanPolicy) `
    -ConvertFromJsonCommand (Get-Command ConvertFrom-Json) `
    -ConvertToJsonCommand $convertToJsonCommand -TestJsonCommand $testJsonCommand
if ($liveReason) {
    throw "The normal Assessment Record rejected LocalSystem provenance: $liveReason"
}

$serialized = $accepted | ConvertTo-Json -Compress -Depth 30
if ($serialized -match '(?i)recipientProfile|localPackageProtector|assessmentUserContext|packageKey|credential|password|secret|scriptText|commandText|executablePath|taskName|pipeName') {
    throw 'The SYSTEM result exposed authority, secret, identity, or activation mechanics.'
}

$unknownPlan = $planResult.Plan | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
$unknownPlan.operations[0].operationId = 'op:caller.system.command'
$unknownDigest = Get-ObjectDigest -Value $unknownPlan -ConvertToJsonCommand $convertToJsonCommand
$unknown = Invoke-SystemCollectionPlan -Plan $unknownPlan -PlanDigest $unknownDigest `
    -ValidationScenario 'UnknownOperation'
Assert-Equal 'IntegrityFailed' $unknown.state `
    'an unknown operation ID fails before SYSTEM activation'
Assert-Equal 'SYSTEM.OPERATION_INVALID' $unknown.reasonCode `
    'unknown operation rejection has one stable reason'
Assert-Equal 'NotAttempted' $unknown.collectorResult.Coverage[0].state `
    'unknown input cannot create a misleading collection attempt'
Assert-Equal $true $unknown.runIntegrityCompromised `
    'a recomputed but unauthorized plan digest cannot preserve run integrity'
Assert-Equal $true $unknown.cleanup.verified `
    'unknown input creates no task, process, channel, or artifact'

$liveStopped = New-SystemCollectionStoppedResult -State 'Unavailable' `
    -ReasonCode 'SYSTEM.ACTIVATION_FAILED' -CoverageState 'Unavailable' -Context @{
        Policy = Get-SystemCollectionPlanPolicy
        Plan = $planResult.Plan
        PlanDigest = $planResult.Digest
        ObservedExecutionContext = 'NotStarted'
    }
Assert-Equal 'NotStarted' $liveStopped.collectorResult.Envelope.executionContext `
    'a live pre-hello failure does not fabricate LocalSystem provenance'
Assert-Equal $false $liveStopped.activation.localSystemIdentityVerified `
    'a live pre-hello failure explicitly reports that SYSTEM identity was not verified'

$protocolFailure = Get-SystemCollectionFailureDisposition -FailureStage 'RESULT_PROTOCOL' `
    -Exception ([System.FormatException]::new('synthetic malformed result'))
Assert-Equal 'IntegrityFailed' $protocolFailure.state `
    'malformed authenticated result content compromises run integrity'
Assert-Equal 'SYSTEM.CHANNEL_INTEGRITY_FAILED' $protocolFailure.reasonCode `
    'protocol corruption cannot be mislabeled as ordinary worker loss'
Assert-Equal $true $protocolFailure.runIntegrityCompromised `
    'protocol corruption closes unrelated scheduling'

$lostDisposition = Get-SystemCollectionFailureDisposition -FailureStage 'RESULT_READ' `
    -Exception ([System.IO.EndOfStreamException]::new()) -WorkerExited $true
Assert-Equal 'SYSTEM.WORKER_LOST' $lostDisposition.reasonCode `
    'EOF plus verified worker exit remains the narrow worker-loss outcome'

$invalidParameterPlan = $planResult.Plan | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
$invalidParameterPlan.operations[0].parameters | Add-Member -NotePropertyName command `
    -NotePropertyValue 'synthetic-prohibited-marker'
$invalidParameterDigest = Get-ObjectDigest -Value $invalidParameterPlan `
    -ConvertToJsonCommand $convertToJsonCommand
$invalidParameters = Invoke-SystemCollectionPlan -Plan $invalidParameterPlan `
    -PlanDigest $invalidParameterDigest -ValidationScenario 'InvalidParameters'
Assert-Equal 'IntegrityFailed' $invalidParameters.state `
    'an extra command-shaped parameter fails before SYSTEM activation'
Assert-Equal 'SYSTEM.PARAMETERS_INVALID' $invalidParameters.reasonCode `
    'closed typed parameter rejection has one stable reason'
Assert-Equal $true $invalidParameters.cleanup.verified `
    'parameter rejection creates no activation residue'

$activationFailure = Invoke-SystemCollectionPlan -Plan $planResult.Plan `
    -PlanDigest $planResult.Digest -ValidationScenario 'ActivationFailure'
Assert-Equal 'Unavailable' $activationFailure.state `
    'SYSTEM activation failure remains confined to the declared source'
Assert-Equal 'SYSTEM.ACTIVATION_FAILED' $activationFailure.reasonCode `
    'activation failure has a sanitized stable reason'
Assert-Equal 'Unavailable' $activationFailure.collectorResult.Coverage[0].state `
    'activation failure cannot look like source absence'
Assert-Equal $true $activationFailure.standardUserWorkMayContinue `
    'unrelated safe collection may continue after activation failure'
Assert-Equal $true $activationFailure.cleanup.verified `
    'activation failure leaves no task or channel'

$lostWorker = Invoke-SystemCollectionPlan -Plan $planResult.Plan `
    -PlanDigest $planResult.Digest -ValidationScenario 'WorkerLost'
Assert-Equal 'Failed' $lostWorker.state `
    'worker loss affects the SYSTEM scope without fabricating evidence'
Assert-Equal 'SYSTEM.WORKER_LOST' $lostWorker.reasonCode `
    'worker loss is distinct from activation or plan failure'
Assert-Equal 'Failed' $lostWorker.collectorResult.Coverage[0].state `
    'worker loss produces failed scope coverage'
Assert-Equal $true $lostWorker.standardUserWorkMayContinue `
    'verified worker loss remains confined to its Evidence Scope'
Assert-Equal $true $lostWorker.cleanup.verified `
    'the lost worker tree and channel are absent before return'

$cancellationSource = [System.Threading.CancellationTokenSource]::new()
try {
    $cancellationSource.CancelAfter(200)
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $cancelled = Invoke-SystemCollectionPlan -Plan $planResult.Plan `
        -PlanDigest $planResult.Digest -ValidationScenario 'Cancellation' `
        -CancellationToken $cancellationSource.Token
    $watch.Stop()
}
finally { $cancellationSource.Dispose() }
Assert-Equal 'Cancelled' $cancelled.state `
    'operator cancellation stops the SYSTEM worker tree'
Assert-Equal 'SYSTEM.CANCELLED' $cancelled.reasonCode `
    'cancellation has one stable reason'
Assert-Equal 'Cancelled' $cancelled.collectorResult.Coverage[0].state `
    'cancelled SYSTEM evidence cannot look complete'
Assert-Equal $false $cancelled.standardUserWorkMayContinue `
    'operator cancellation closes new scheduling'
Assert-Equal $true $cancelled.cleanup.verified `
    'cancellation proves worker, task, and IPC absence'
if ($watch.ElapsedMilliseconds -gt 3000) {
    throw "SYSTEM cancellation exceeded its bounded acknowledgement window: $($watch.ElapsedMilliseconds) ms."
}

$timeoutWatch = [System.Diagnostics.Stopwatch]::StartNew()
$timedOut = Invoke-SystemCollectionPlan -Plan $planResult.Plan `
    -PlanDigest $planResult.Digest -ValidationScenario 'Timeout'
$timeoutWatch.Stop()
Assert-Equal 'TimedOut' $timedOut.state `
    'the SYSTEM operation deadline is distinct from worker loss'
Assert-Equal 'SYSTEM.DEADLINE_EXCEEDED' $timedOut.reasonCode `
    'deadline expiry has one stable reason'
Assert-Equal 'TimedOut' $timedOut.collectorResult.Coverage[0].state `
    'deadline expiry is confined to the SYSTEM Evidence Scope'
Assert-Equal $true $timedOut.standardUserWorkMayContinue `
    'a verified scoped timeout does not destroy unrelated evidence'
Assert-Equal $true $timedOut.cleanup.verified `
    'timeout kills the complete owned worker tree and removes IPC'
if ($timeoutWatch.ElapsedMilliseconds -gt 3000) {
    throw "SYSTEM timeout exceeded its bounded termination window: $($timeoutWatch.ElapsedMilliseconds) ms."
}

$denied = Invoke-SystemCollectionPlan -Plan $planResult.Plan `
    -PlanDigest $planResult.Digest -ValidationScenario 'Denied'
Assert-Equal 'Unavailable' $denied.state `
    'denied SYSTEM activation remains a scoped evidence gap'
Assert-Equal 'SYSTEM.ACTIVATION_DENIED' $denied.reasonCode `
    'access denial has one stable reason'
Assert-Equal 'Denied' $denied.collectorResult.Coverage[0].state `
    'denial is distinguishable from environmental unavailability'
Assert-Equal $true $denied.standardUserWorkMayContinue `
    'denial does not end unrelated safe collection'
Assert-Equal $true $denied.cleanup.verified `
    'denial leaves no activation residue'

$abnormalCleanup = Invoke-SystemCollectionPlan -Plan $planResult.Plan `
    -PlanDigest $planResult.Digest -ValidationScenario 'AbnormalCleanup'
Assert-Equal 'Completed' $abnormalCleanup.state `
    'one injected cleanup failure is recovered by the bounded idempotent retry'
Assert-Equal 1 $abnormalCleanup.cleanup.retries `
    'abnormal cleanup consumes exactly one release-owned retry'
Assert-Equal $true $abnormalCleanup.cleanup.verified `
    'retry success is reported only after every owned object is absent'
Assert-Equal $true $abnormalCleanup.cleanup.taskAbsent `
    'no transient task survives abnormal cleanup recovery'
Assert-Equal $true $abnormalCleanup.cleanup.workerTreeAbsent `
    'no worker descendant survives abnormal cleanup recovery'

$cleanupProbeName = "Local\WINPCInfo-SystemCollection-Test-$([guid]::NewGuid().ToString('N'))"
$cleanupProbe = Invoke-SystemCollectionSyntheticCleanupProbe -Name $cleanupProbeName `
    -MaximumMilliseconds 1000
Assert-Equal 1 $cleanupProbe.Retries `
    'the abnormal-cleanup probe really consumes its single retry'
Assert-Equal $true $cleanupProbe.Absent `
    'the abnormal-cleanup probe proves its owned IPC object absent'
$openedProbe = $null
$probeSurvived = [System.Threading.EventWaitHandle]::TryOpenExisting(
    $cleanupProbeName, [ref] $openedProbe
)
if ($null -ne $openedProbe) { $openedProbe.Dispose() }
Assert-Equal $false $probeSurvived `
    'the exact injected-cleanup IPC name cannot be reopened after return'

# Simulate a live task engine that never joined the Job and ignores the task
# stop request. Deleting its registration and losing the scheduler instance is
# insufficient: cleanup must retain the captured EnginePID and fail closed
# while that exact process is alive.
$engineStart = [System.Diagnostics.ProcessStartInfo]::new()
$engineStart.FileName = Join-Path $PSHOME 'pwsh.exe'
$engineStart.UseShellExecute = $false
$null = $engineStart.ArgumentList.Add('-NoLogo')
$null = $engineStart.ArgumentList.Add('-NoProfile')
$null = $engineStart.ArgumentList.Add('-Command')
$null = $engineStart.ArgumentList.Add('[System.Threading.Thread]::Sleep(30000)')
$script:systemCleanupEngine = [System.Diagnostics.Process]::Start($engineStart)
$script:systemCleanupInstanceActive = $true
$script:systemCleanupRegistered = $true
$script:systemCleanupInstance = [pscustomobject]@{
    InstanceGuid = [guid]::NewGuid().ToString('B')
    EnginePID = $script:systemCleanupEngine.Id
}
$script:systemCleanupInstance | Add-Member -MemberType ScriptMethod -Name Stop -Value {}
$service = [pscustomobject]@{}
$service | Add-Member -MemberType ScriptMethod -Name GetRunningTasks -Value {
    param($Flags)
    $collection = [pscustomobject]@{ Count = if ($script:systemCleanupInstanceActive) { 1 } else { 0 } }
    $collection | Add-Member -MemberType ScriptMethod -Name Item -Value {
        param($Index)
        $script:systemCleanupInstance
    }
    $collection
}
$folder = [pscustomobject]@{}
$folder | Add-Member -MemberType ScriptMethod -Name DeleteTask -Value {
    param($Name, $Flags)
    $script:systemCleanupRegistered = $false
    $script:systemCleanupInstanceActive = $false
}
$folder | Add-Member -MemberType ScriptMethod -Name GetTask -Value {
    param($Name)
    if (-not $script:systemCleanupRegistered) { throw 'Task not found.' }
    [pscustomobject]@{}
}
try {
    $preJobCleanup = Remove-SystemCollectionTransientTask -Activation ([pscustomobject]@{
        Service = $service
        Folder = $folder
        RunningTask = $script:systemCleanupInstance
        InstanceGuid = $script:systemCleanupInstance.InstanceGuid
    }) -TaskName "WINPCInfo-SystemCollection-v1-$([guid]::NewGuid().ToString('N'))" `
        -MaximumMilliseconds 150
    Assert-Equal $false $preJobCleanup.Absent `
        'a surviving pre-Job task engine cannot be reported absent'
    Assert-Equal $false $preJobCleanup.EngineProcessAbsent `
        'cleanup records the exact captured task EnginePID as surviving'
}
finally {
    if (-not $script:systemCleanupEngine.HasExited) {
        $script:systemCleanupEngine.Kill($true)
        $script:systemCleanupEngine.WaitForExit()
    }
    $script:systemCleanupEngine.Dispose()
}

Write-Output 'PASS: all nine SYSTEM sub-plan cases enforce catalog, parameters, provenance, confinement, lifecycle, and cleanup contracts.'
