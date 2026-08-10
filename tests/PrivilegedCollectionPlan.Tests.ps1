[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$convertToJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
    'ConvertTo-Json', [System.Management.Automation.CommandTypes]::Cmdlet
)
$preparationPlan = [pscustomobject][ordered]@{
    recordType = 'win-pcinfo.preparation-plan'
    contractVersion = '1.0.0'
    release = '2.0.0-preview.1'
    privilege = [pscustomobject][ordered]@{
        maximumUacInteractions = 1
        privilegedOperationsFrozen = $true
        privilegedOperations = @(
            [pscustomobject][ordered]@{ operationId = 'observe-firmware-tpm'; context = 'Administrator'; parameters = [pscustomobject]@{} }
            [pscustomobject][ordered]@{ operationId = 'observe-local-administrators'; context = 'Administrator'; parameters = [pscustomobject]@{} }
            [pscustomobject][ordered]@{ operationId = 'observe-effective-policy'; context = 'Administrator'; parameters = [pscustomobject]@{} }
            [pscustomobject][ordered]@{ operationId = 'observe-certificate-trust'; context = 'Administrator'; parameters = [pscustomobject]@{} }
        )
    }
}
$planDigest = Get-ObjectDigest -Value $preparationPlan -ConvertToJsonCommand $convertToJsonCommand
$assessmentUserContext = 'subject:synthetic-user:primary'
$localPackageProtector = 'protector:synthetic-initiator'

$accepted = Invoke-PrivilegedCollectionPlan -PreparationPlan $preparationPlan `
    -PlanDigest $planDigest -AssessmentUserContext $assessmentUserContext `
    -LocalPackageProtector $localPackageProtector -ValidationScenario 'AcceptedElevation'

Assert-Equal 'Completed' $accepted.state `
    'one accepted synthetic elevation completes the immutable Privileged Collection Plan'
Assert-Equal 'PRIVILEGE.COMPLETED' $accepted.reasonCode `
    'accepted elevation returns a stable sanitized reason'
Assert-Equal 1 $accepted.elevation.uacInteractionCount `
    'a normal launch makes exactly one front-loaded elevation request'
Assert-Equal 4 @($accepted.operations).Count `
    'every Privileged Collection Plan operation executes inside one contiguous phase'
Assert-Equal 1 @($accepted.operations.phaseId | Sort-Object -Unique).Count `
    'all Administrator operations share one Privileged Collection Phase identity'
Assert-Equal $true $accepted.channel.oneInstance `
    'the local channel uses exactly one server instance'
Assert-Equal $true $accepted.channel.aclProtected `
    'the channel is created with its release-defined access restriction'
Assert-Equal $true $accepted.channel.nonceVerified `
    'the worker proves possession of the run-unique nonce'
Assert-Equal $true $accepted.channel.schemaValidated `
    'both messages pass the closed privilege protocol'
Assert-Equal $true $accepted.channel.peerProcessVerified `
    'the coordinator binds the connected client to its worker process'
Assert-Equal $true $accepted.channel.peerArtifactVerified `
    'the worker source identity agrees with the release policy'
Assert-Equal $false $accepted.channel.assessmentEvidenceCrossed `
    'no assessment evidence enters either privilege-channel frame'
Assert-Equal $assessmentUserContext $accepted.identity.assessmentUserContext `
    'elevation does not substitute the Assessment User Context'
Assert-Equal $localPackageProtector $accepted.identity.localPackageProtector `
    'elevation does not substitute the Local Package Protector'
Assert-Equal $true $accepted.cleanup.verified `
    'the worker and one-use IPC are absent before the result returns'
Assert-Equal 'SyntheticUnelevated' $accepted.validation.mode `
    'automated elevation fixtures identify their unelevated validation seam'
Assert-Equal 'NotStarted' $accepted.validation.environmentalLimitation.state `
    'controlled live UAC validation is reported as a typed environmental limitation'
Assert-Equal 'PRIVILEGE.LIVE_ELEVATION_VALIDATION_UNAVAILABLE' `
    $accepted.validation.environmentalLimitation.reasonCode `
    'the missing controlled live-client path has a stable public-safe reason'
$extraFieldResult = [pscustomobject][ordered]@{
    operationId = 'observe-firmware-tpm'
    state = 'Completed'
    phaseId = $accepted.operations[0].phaseId
    assessmentEvidence = 'synthetic-but-prohibited'
}
Assert-Equal $false (Test-PrivilegedCollectionOperationResult `
    -Operation $extraFieldResult -ExpectedOperationId 'observe-firmware-tpm' `
    -ExpectedPhaseId $accepted.operations[0].phaseId) `
    'a worker result cannot smuggle assessment evidence through an operation object'
if (($accepted | ConvertTo-Json -Compress -Depth 20) -match
    '(?i)script(text)?|command(text)?|credential|secret|executablePath|pipeName') {
    throw 'The privilege result exposed a prohibited channel or launch value.'
}

$alreadyElevated = Invoke-PrivilegedCollectionPlan -PreparationPlan $preparationPlan `
    -PlanDigest $planDigest -AssessmentUserContext $assessmentUserContext `
    -LocalPackageProtector $localPackageProtector -ValidationScenario 'AlreadyElevated'
Assert-Equal 'Completed' $alreadyElevated.state `
    'an already-elevated eligible launch executes the same fixed plan'
Assert-Equal 0 $alreadyElevated.elevation.uacInteractionCount `
    'an already-elevated launch makes no second elevation request'
Assert-Equal $true $alreadyElevated.elevation.alreadyElevated `
    'the result distinguishes a reused eligible administrator token from UAC'

$alternateAdministrator = Invoke-PrivilegedCollectionPlan -PreparationPlan $preparationPlan `
    -PlanDigest $planDigest -AssessmentUserContext $assessmentUserContext `
    -LocalPackageProtector $localPackageProtector -ValidationScenario 'AlternateAdministrator'
Assert-Equal 'Completed' $alternateAdministrator.state `
    'a selected alternate administrator may host the fixed synthetic worker'
Assert-Equal 'AlternateAdministrator' `
    $alternateAdministrator.identity.workerPrincipalRelationship `
    'the result distinguishes the worker principal without publishing an account identity'
Assert-Equal $assessmentUserContext $alternateAdministrator.identity.assessmentUserContext `
    'the alternate administrator cannot replace the Assessment User Context'
Assert-Equal $localPackageProtector $alternateAdministrator.identity.localPackageProtector `
    'the alternate administrator cannot replace the Local Package Protector'

$denied = Invoke-PrivilegedCollectionPlan -PreparationPlan $preparationPlan `
    -PlanDigest $planDigest -AssessmentUserContext $assessmentUserContext `
    -LocalPackageProtector $localPackageProtector -ValidationScenario 'ElevationDenied'
Assert-Equal 'Unavailable' $denied.state `
    'declined UAC leaves privileged collection explicitly unavailable'
Assert-Equal 'PRIVILEGE.ELEVATION_DENIED' $denied.reasonCode `
    'elevation denial has one stable sanitized reason'
Assert-Equal 'Unavailable' $denied.coverage[0].state `
    'denial cannot look like successful or negative privileged evidence'
Assert-Equal 1 $denied.elevation.uacInteractionCount `
    'denial consumes the one permitted elevation interaction'
Assert-Equal $false $denied.elevation.retryAllowed `
    'denial cannot schedule another prompt'
Assert-Equal $true $denied.standardUserWorkMayContinue `
    'unrelated safe standard-user collection remains schedulable'
Assert-Equal $true $denied.cleanup.verified `
    'denial leaves no privileged worker or one-use channel residue'

$wrongClient = Invoke-PrivilegedCollectionPlan -PreparationPlan $preparationPlan `
    -PlanDigest $planDigest -AssessmentUserContext $assessmentUserContext `
    -LocalPackageProtector $localPackageProtector -ValidationScenario 'WrongPipeClient'
Assert-Equal 'IntegrityFailed' $wrongClient.state `
    'a different same-machine pipe client cannot impersonate the worker'
Assert-Equal 'PRIVILEGE.PEER_IDENTITY_INVALID' $wrongClient.reasonCode `
    'kernel peer-process mismatch has one sanitized reason'
Assert-Equal $false $wrongClient.channel.peerProcessVerified `
    'the result never overstates peer verification after a hostile connection'
Assert-Equal $true $wrongClient.cleanup.verified `
    'the rejected client and expected worker are absent before return'

$alteredPlan = Invoke-PrivilegedCollectionPlan -PreparationPlan $preparationPlan `
    -PlanDigest $planDigest -AssessmentUserContext $assessmentUserContext `
    -LocalPackageProtector $localPackageProtector -ValidationScenario 'AlteredPlan'
Assert-Equal 'IntegrityFailed' $alteredPlan.state `
    'a plan altered after approval cannot reach the worker'
Assert-Equal 'PRIVILEGE.PLAN_INTEGRITY_INVALID' $alteredPlan.reasonCode `
    'altered plan rejection has one stable reason'
Assert-Equal 0 $alteredPlan.elevation.uacInteractionCount `
    'plan integrity fails before UAC or worker launch'
Assert-Equal 0 @($alteredPlan.operations).Count `
    'no operation runs from an altered plan'

$mutatedPlan = $preparationPlan | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
$mutatedPlan.privilege.privilegedOperations[0].operationId = 'observe-not-approved'
$digestMismatch = Invoke-PrivilegedCollectionPlan -PreparationPlan $mutatedPlan `
    -PlanDigest $planDigest -AssessmentUserContext $assessmentUserContext `
    -LocalPackageProtector $localPackageProtector -ValidationScenario 'AcceptedElevation'
Assert-Equal 'PRIVILEGE.PLAN_INTEGRITY_INVALID' $digestMismatch.reasonCode `
    'a real post-approval mutation fails the full Preparation Plan digest check'
Assert-Equal 0 $digestMismatch.elevation.uacInteractionCount `
    'digest mismatch is rejected before any elevation side effect'

$lostWorker = Invoke-PrivilegedCollectionPlan -PreparationPlan $preparationPlan `
    -PlanDigest $planDigest -AssessmentUserContext $assessmentUserContext `
    -LocalPackageProtector $localPackageProtector -ValidationScenario 'LostWorker'
Assert-Equal 'IntegrityFailed' $lostWorker.state `
    'a worker lost during the phase cannot produce partial success'
Assert-Equal 'PRIVILEGE.WORKER_LOST' $lostWorker.reasonCode `
    'worker loss is distinct from plan or peer rejection'
Assert-Equal $true $lostWorker.cleanup.verified `
    'worker loss still removes the one-use channel and proves the process absent'

$timeoutWatch = [System.Diagnostics.Stopwatch]::StartNew()
$timedOut = Invoke-PrivilegedCollectionPlan -PreparationPlan $preparationPlan `
    -PlanDigest $planDigest -AssessmentUserContext $assessmentUserContext `
    -LocalPackageProtector $localPackageProtector -ValidationScenario 'Timeout'
$timeoutWatch.Stop()
Assert-Equal 'TimedOut' $timedOut.state `
    'the Privileged Collection Phase deadline is distinct from integrity failure'
Assert-Equal 'TimedOut' $timedOut.coverage[0].state `
    'deadline expiry yields honest timed-out privileged coverage'
Assert-Equal $true $timedOut.cleanup.verified `
    'timeout terminates the synthetic worker before return'
if ($timeoutWatch.ElapsedMilliseconds -gt 9000) {
    throw "Privilege timeout exceeded its bounded termination window: $($timeoutWatch.ElapsedMilliseconds) ms."
}

$operatorCancellation = [System.Threading.CancellationTokenSource]::new()
try {
    $operatorCancellation.CancelAfter(200)
    $cancelWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $cancelled = Invoke-PrivilegedCollectionPlan -PreparationPlan $preparationPlan `
        -PlanDigest $planDigest -AssessmentUserContext $assessmentUserContext `
        -LocalPackageProtector $localPackageProtector -ValidationScenario 'Cancellation' `
        -CancellationToken $operatorCancellation.Token
    $cancelWatch.Stop()
}
finally { $operatorCancellation.Dispose() }
Assert-Equal 'Cancelled' $cancelled.state `
    'operator cancellation stops the active Privileged Collection Phase'
Assert-Equal 'Cancelled' $cancelled.coverage[0].state `
    'cancelled privileged scope cannot look complete or unavailable'
Assert-Equal $true $cancelled.cleanup.verified `
    'cancellation escalates to bounded worker termination and channel cleanup'
if ($cancelWatch.ElapsedMilliseconds -gt 3000) {
    throw "Privilege cancellation exceeded its bounded acknowledgement window: $($cancelWatch.ElapsedMilliseconds) ms."
}

Write-Output 'PASS: all nine Privileged Collection Plan scenarios enforce plan, peer, deadline, cancellation, identity, and cleanup contracts.'
