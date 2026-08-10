[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-SupervisorEqual {
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
. (Join-Path $repositoryRoot 'build/TextCanonicalization.ps1')
. (Join-Path $repositoryRoot 'src/RuntimeCompatibility.ps1')
. (Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1')

$supervisorSource = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1'
) -Raw
if ($supervisorSource -match 'GetAwaiter\(\)\.GetResult\(\)|System\.Threading\.Tasks') {
    throw 'Process supervision must not depend on an unbounded asynchronous pipe-drain task.'
}

$catalogBytes = Get-Utf8LfBytes -LiteralPath (
    Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-approved-collectors.json'
)
$expectedCatalogDigest = Get-Sha256ForSupervisorBytes -Bytes $catalogBytes

$result = Invoke-ApprovedCollectorProcess -OperationId 'op:synthetic.windows.os.success'

Assert-SupervisorEqual 'collector:synthetic.windows.os' $result.Envelope.collectorId `
    'the release-owned collector identity is returned in its Collector Result Envelope'
Assert-SupervisorEqual 'op:synthetic.windows.os.success' $result.Envelope.operationId `
    'the envelope binds the predefined operation rather than caller-supplied command text'
Assert-SupervisorEqual 'Complete' $result.Coverage[0].state `
    'a successful synthetic observation closes its release-defined Evidence Scope'
Assert-SupervisorEqual 'WIN-PCInfo synthétique 日本語 العربية' $result.Observations[0].value `
    'strict UTF-8 output is normalized into the synthetic observation without locale loss'
Assert-SupervisorEqual 'Completed' $result.Supervision.outcome `
    'the process result reports a completed collector attempt'
Assert-SupervisorEqual 'WindowsJobObject' $result.Supervision.treeControlMode `
    'compatible execution starts suspended and enters the run-owned Job Object before running'
Assert-SupervisorEqual 'ActivePowerShellHome' $result.Supervision.workingBoundaryKind `
    'the collector uses the validated release-defined non-writing working boundary'
Assert-SupervisorEqual $expectedCatalogDigest $result.Supervision.policyDigest `
    'the result binds the exact canonical release collector catalog'
Assert-SupervisorEqual '1e0bd6ec3ea4dbe51eee1ac32500fde79b84a9899997181e1f8db4213e1e469c' `
    $result.Supervision.payloadDigest `
    'the encoded collector source matches the release-owned payload identity'
Assert-SupervisorEqual $false $result.Supervision.standardOutput.exceeded `
    'standard output stays within its independent byte bound'
Assert-SupervisorEqual $false $result.Supervision.standardError.exceeded `
    'standard error stays within its independent byte bound'
Assert-SupervisorEqual $true $result.Supervision.completeOwnedTreeAbsent `
    'the complete owned process tree is absent before the result is returned'
Assert-SupervisorEqual $true $result.Supervision.temporaryArtifactsAbsent `
    'the run-owned cancellation event is absent and the collector created no file artifact'

$terminationIncompleteWithOverflow = [pscustomobject]@{
    StandardOutputExceeded = $true
    StandardErrorExceeded = $false
    FailureStage = [WinPCInfo.ProcessSupervisor.NativeFailureStage]::TerminationIncomplete
}
Assert-SupervisorEqual 'PROCESS.TERMINATION_INCOMPLETE' (
    Get-NativeSupervisorReasonCode -NativeResult $terminationIncompleteWithOverflow
) 'unproved tree cleanup takes precedence over the triggering output failure'

$wrongExecutable = Invoke-ApprovedCollectorProcess `
    -OperationId 'fixture:synthetic.wrong-executable'
Assert-SupervisorEqual 'NotStarted' $wrongExecutable.Supervision.outcome `
    'an executable outside the release identity never starts'
Assert-SupervisorEqual 'PROCESS.EXECUTABLE_IDENTITY_INVALID' $wrongExecutable.Supervision.reasonCode `
    'executable substitution has a stable sanitized reason'
Assert-SupervisorEqual $false $wrongExecutable.Supervision.processStarted `
    'wrong-executable validation fails before CreateProcess'
Assert-SupervisorEqual $true $wrongExecutable.Supervision.completeOwnedTreeAbsent `
    'a rejected executable leaves no owned process tree'
Assert-SupervisorEqual $true $wrongExecutable.Supervision.temporaryArtifactsAbsent `
    'wrong-executable rejection releases the run-owned cancellation event'

$invalidArgument = Invoke-ApprovedCollectorProcess `
    -OperationId 'fixture:synthetic.invalid-argument'
Assert-SupervisorEqual 'NotStarted' $invalidArgument.Supervision.outcome `
    'an invalid release fixture cannot begin collection'
Assert-SupervisorEqual 'PROCESS.ARGUMENT_INVALID' $invalidArgument.Supervision.reasonCode `
    'secret-shaped or otherwise unapproved arguments have one stable rejection reason'
Assert-SupervisorEqual $false $invalidArgument.Supervision.processStarted `
    'argument validation finishes before CreateProcess'
Assert-SupervisorEqual $true $invalidArgument.Supervision.completeOwnedTreeAbsent `
    'invalid arguments leave no owned process tree'

$excessOutput = Invoke-ApprovedCollectorProcess `
    -OperationId 'fixture:synthetic.excess-output'
Assert-SupervisorEqual 'Failed' $excessOutput.Supervision.outcome `
    'output overflow is a failed collector attempt rather than NotStarted'
Assert-SupervisorEqual 'PROCESS.OUTPUT_LIMIT_EXCEEDED' $excessOutput.Supervision.reasonCode `
    'output overflow has a stable sanitized reason'
Assert-SupervisorEqual $true $excessOutput.Supervision.standardOutput.exceeded `
    'standard output enforces its own release bound'
Assert-SupervisorEqual $true $excessOutput.Supervision.standardError.exceeded `
    'standard error enforces its own release bound'
Assert-SupervisorEqual $true $excessOutput.Supervision.completeOwnedTreeAbsent `
    'overflow cannot leave the collector tree running'
Assert-SupervisorEqual $true $excessOutput.Supervision.temporaryArtifactsAbsent `
    'overflow cleanup removes ticket-owned process artifacts'
$excessPublicJson = $excessOutput | ConvertTo-Json -Compress -Depth 20
if ($excessPublicJson -match 'OOOOOOOO|EEEEEEEE') {
    throw 'Raw untrusted standard output or error entered the returned process diagnostic.'
}

$timeoutWatch = [System.Diagnostics.Stopwatch]::StartNew()
$timedOut = Invoke-ApprovedCollectorProcess `
    -OperationId 'fixture:synthetic.timeout'
$timeoutWatch.Stop()
Assert-SupervisorEqual 'TimedOut' $timedOut.Supervision.outcome `
    'a deadline is distinct from a generic collector failure'
Assert-SupervisorEqual 'PROCESS.DEADLINE_EXCEEDED' $timedOut.Supervision.reasonCode `
    'deadline expiry has a stable sanitized reason'
Assert-SupervisorEqual 'TimedOut' $timedOut.Coverage[0].state `
    'deadline expiry produces honest Evidence Coverage State'
Assert-SupervisorEqual $true $timedOut.Supervision.completeOwnedTreeAbsent `
    'deadline escalation terminates the complete Job Object tree'
Assert-SupervisorEqual $true $timedOut.Supervision.temporaryArtifactsAbsent `
    'deadline cleanup removes ticket-owned process artifacts'
if ($timeoutWatch.ElapsedMilliseconds -gt 5000) {
    throw "The 200 ms synthetic deadline returned after $($timeoutWatch.ElapsedMilliseconds) ms."
}

$cooperativeCancellation = [System.Threading.CancellationTokenSource]::new()
try {
    $cooperativeCancellation.CancelAfter(200)
    $cooperativeWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $cooperativelyCancelled = Invoke-ApprovedCollectorProcess `
        -OperationId 'fixture:synthetic.cooperative-cancel' `
        -CancellationToken $cooperativeCancellation.Token
    $cooperativeWatch.Stop()
}
finally {
    $cooperativeCancellation.Dispose()
}
Assert-SupervisorEqual 'Cancelled' $cooperativelyCancelled.Supervision.outcome `
    'cooperative cancellation is distinct from timeout or failure'
Assert-SupervisorEqual 'PROCESS.CANCELLED_COOPERATIVELY' $cooperativelyCancelled.Supervision.reasonCode `
    'the fixed named-event protocol reports a stable cooperative reason'
Assert-SupervisorEqual 'Cooperative' $cooperativelyCancelled.Supervision.terminationMode `
    'the result does not claim hard termination when the collector cooperated'
Assert-SupervisorEqual 'Cancelled' $cooperativelyCancelled.Coverage[0].state `
    'cooperative cancellation produces honest Evidence Coverage State'
Assert-SupervisorEqual $true $cooperativelyCancelled.Supervision.completeOwnedTreeAbsent `
    'cooperative cancellation still proves the complete Job Object tree absent'
Assert-SupervisorEqual $true $cooperativelyCancelled.Supervision.temporaryArtifactsAbsent `
    'the cooperative cancellation event is removed'
if ($cooperativeWatch.ElapsedMilliseconds -gt 2000) {
    throw "Cooperative cancellation acknowledgement took $($cooperativeWatch.ElapsedMilliseconds) ms."
}

$hardCancellation = [System.Threading.CancellationTokenSource]::new()
try {
    $hardCancellation.CancelAfter(200)
    $hardWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $hardCancelled = Invoke-ApprovedCollectorProcess `
        -OperationId 'fixture:synthetic.hard-cancel' `
        -CancellationToken $hardCancellation.Token
    $hardWatch.Stop()
}
finally {
    $hardCancellation.Dispose()
}
Assert-SupervisorEqual 'Cancelled' $hardCancelled.Supervision.outcome `
    'hard cancellation remains a cancelled collector attempt'
Assert-SupervisorEqual 'PROCESS.CANCELLED_HARD' $hardCancelled.Supervision.reasonCode `
    'grace expiry has a distinct stable reason'
Assert-SupervisorEqual 'Hard' $hardCancelled.Supervision.terminationMode `
    'the result states that cooperative shutdown did not succeed'
Assert-SupervisorEqual $true $hardCancelled.Supervision.completeOwnedTreeAbsent `
    'hard termination proves the complete Job Object tree absent'
Assert-SupervisorEqual $true $hardCancelled.Supervision.temporaryArtifactsAbsent `
    'the hard-cancel event is removed'
if ($hardWatch.ElapsedMilliseconds -gt 2000) {
    throw "Hard cancellation acknowledgement took $($hardWatch.ElapsedMilliseconds) ms."
}

$childProcess = Invoke-ApprovedCollectorProcess `
    -OperationId 'fixture:synthetic.child-process'
Assert-SupervisorEqual 'Completed' $childProcess.Supervision.outcome `
    'an approved child process does not turn valid evidence into a failure'
if ($childProcess.Supervision.peakActiveProcesses -lt 2) {
    throw 'The child-process fixture was not accounted as a two-process owned Job Object tree.'
}
Assert-SupervisorEqual $true $childProcess.Supervision.completeOwnedTreeAbsent `
    'the supervisor removes a descendant that outlives the collector root'
Assert-SupervisorEqual $true $childProcess.Supervision.temporaryArtifactsAbsent `
    'child-process cleanup releases the run-owned cancellation event'

$incompatibleChild = Invoke-ApprovedCollectorProcess `
    -OperationId 'fixture:synthetic.incompatible-child'
Assert-SupervisorEqual 'NotStarted' $incompatibleChild.Supervision.outcome `
    'Job-incompatible execution fails closed instead of claiming root-only control'
Assert-SupervisorEqual 'PROCESS.JOB_INCOMPATIBLE' $incompatibleChild.Supervision.reasonCode `
    'Job assignment incompatibility has a stable sanitized reason'
Assert-SupervisorEqual $false $incompatibleChild.Supervision.processStarted `
    'the suspended candidate never executes collector code'
Assert-SupervisorEqual 'IncompatibleNoLaunch' $incompatibleChild.Supervision.treeControlMode `
    'the fallback states its lack of tree control without overstating guarantees'
Assert-SupervisorEqual $true $incompatibleChild.Supervision.completeOwnedTreeAbsent `
    'the incompatible suspended process is absent before return'
Assert-SupervisorEqual $true $incompatibleChild.Supervision.temporaryArtifactsAbsent `
    'incompatibility cleanup releases the run-owned cancellation event'

$legacyTemporaryRoot = [System.IO.Path]::Combine(
    [System.IO.Path]::GetTempPath(), 'WIN-PCInfo', 'ProcessSupervisor'
)
if ([System.IO.Directory]::Exists($legacyTemporaryRoot)) {
    throw 'The Process Supervisor left a temporary product root after its fixture matrix.'
}

Write-Output 'PASS: the exported Process Supervisor passed all nine required process-contract fixtures.'
