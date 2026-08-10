[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
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

Write-Output 'PASS: all nine SYSTEM sub-plan cases enforce catalog, parameters, provenance, confinement, lifecycle, and cleanup contracts.'
