[CmdletBinding()]
param([string] $CandidatePath = '', [string] $PreparedManifestPath = '', [string] $PreparedManifestSha256 = '')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidate=$candidateContext.Path
$candidateUseError=$null
try {
$generated = [IO.File]::ReadAllText($candidate)
$regions = [regex]::Matches($generated,
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach ($region in $regions) { . ([scriptblock]::Create($region.Groups[2].Value)) }
$transport = New-StatusDeskTransport
Assert-Equal 128 $transport.Events.BoundedCapacity 'progress transport has a fixed memory bound'
$summary = [pscustomobject]@{ recordType = 'win-pcinfo.preparation-summary'; planDigest = ('a' * 64) }
Send-StatusDeskRecord -Transport $transport -Record $summary
for ($index = 0; $index -lt 300; $index++) {
    Send-StatusDeskRecord -Transport $transport -Record (New-ProgressRecord -Sequence $index -State Started -MessageId 'collection.active' -CompletedUnits 0 -TotalUnits 1)
}
Assert-Equal 128 $transport.Events.Count 'a stalled UI cannot grow the queue'
Assert-Equal ('a' * 64) ($transport.State.Preparation | ConvertFrom-Json).planDigest 'progress overflow cannot lose preparation'
foreach ($outcome in @('Completed','CompletedWithGaps','NotStarted','Cancelled','TimedOut','IntegrityFailed','CleanupIncomplete')) {
    $terminal = [pscustomobject]@{ recordType='win-pcinfo.terminal'; outcome=$outcome; exitCode=20 }
    Send-StatusDeskRecord -Transport $transport -Record $terminal
    Assert-Equal $outcome ($transport.State.Terminal | ConvertFrom-Json).outcome 'all seven terminals remain authoritative'
}
$transport.Cancellation.Dispose()
$transport.DecisionReady.Dispose()
$transport.Events.Dispose()
$script:StatusDeskTransport = New-StatusDeskTransport
$script:StatusDeskTransport.Cancellation.Cancel()
$cancelled = $false
try { Enter-AssessmentCollectionStage -Stage Device } catch { $cancelled = $_.Exception.Data['ReasonCode'] -eq 'RUN.CANCELLED' }
Assert-Equal $true $cancelled 'cancellation stops the next real scheduling boundary'
$script:StatusDeskTransport.Cancellation.Dispose()
$script:StatusDeskTransport.DecisionReady.Dispose()
$script:StatusDeskTransport.Events.Dispose()
Remove-Variable -Name StatusDeskTransport -Scope Script
$moduleText = ($regions | ForEach-Object { $_.Groups[2].Value }) -join "`n"
$request = Get-AutomationRequest -LiteralPath (Join-Path $PSScriptRoot 'fixtures/automation-request.json') `
    -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
$context = @{ IsFixture = $true }
foreach ($name in @('Preparation','Contract','Run','PrivilegedCollection','SystemCollection',
    'EvidenceWorkspace','ProtectedPackage','RecipientSharing','DeviceReadiness','IdentityEnrollment',
    'AdministratorExposure','EffectivePolicy','ResourceDependencies','NetworkTopology',
    'SoftwareInventory','CertificateTrust','MicrosoftConnectivity')) { $context[$name + 'FixturePath'] = '' }
$context.PreparationFixturePath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
$parameters = @{
    Request=$request; RuntimeFacts=(Get-ActiveRuntimeFacts -ModuleFacts (Get-BuiltInModuleCompatibilityFacts))
    ArtifactTrustValid=$false; ValidationContext=[pscustomobject]$context
}
# The responsive controller must report launch/waiting activity even while
# exact generated worker definitions are still loading. No collection is approved.
$delayedSession = Start-StatusDeskSession -ModuleText ('[Threading.Thread]::Sleep(6000)' + "`n" + $moduleText) -LaunchParameters $parameters
$delayedBodyError = $null
try {
    $controllerWatch = [Diagnostics.Stopwatch]::StartNew()
    while ($controllerWatch.ElapsedMilliseconds -lt 5500) {
        $null = Complete-StatusDeskSession $delayedSession
        Start-Sleep -Milliseconds 100
    }
    Assert-Equal $true ($delayedSession.Transport.State.FirstProgressMilliseconds -ge 0 -and
        $delayedSession.Transport.State.FirstProgressMilliseconds -le 5000) 'actual controller reports first launch activity before slow worker initialization finishes'
    Assert-Equal $true ($delayedSession.Transport.State.ProgressSequence -ge 2) 'polling controller reports waiting activity without claiming source progress'
    Assert-Equal $false $delayedSession.Transport.State.CollectionStarted 'controller activity does not authorize collection'
    $activity = @($delayedSession.Transport.Events.ToArray() | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-Equal $true (@($activity | Where-Object { $_.recordType -eq 'win-pcinfo.progress' -and $_.state -eq 'Heartbeat' -and $_.messageId -eq 'controller.waiting-for-worker' }).Count -gt 0) 'controller heartbeat remains explicit waiting activity'
} catch { $delayedBodyError = $_ }
finally {
    Complete-QualificationHarness -BodyError $delayedBodyError -Cleanup @(
        { Set-StatusDeskDecision -Session $delayedSession -Approve $false -PlanDigest 'test-decline' },
        {
            $finishWatch = [Diagnostics.Stopwatch]::StartNew()
            while (-not (Complete-StatusDeskSession $delayedSession) -and $finishWatch.ElapsedMilliseconds -lt 45000) { Start-Sleep -Milliseconds 50 }
            if (-not $delayedSession.Completed) { throw 'Owned delayed worker completion remains unverified.' }
        },
        {
            if (-not $delayedSession.Completed) { throw 'Preserve handles for the still-active delayed worker.' }
            try { $delayedSession.Transport.Cancellation.Dispose() }
            finally { try { $delayedSession.Transport.DecisionReady.Dispose() } finally { $delayedSession.Transport.Events.Dispose() } }
        }
    )
}

$session = Start-StatusDeskSession -ModuleText $moduleText -LaunchParameters $parameters
$deadline = [Diagnostics.Stopwatch]::StartNew()
while (-not $session.Transport.State.Preparation -and -not $session.Completed -and $deadline.Elapsed.TotalSeconds -lt 30) {
    $null = Complete-StatusDeskSession $session
    Start-Sleep -Milliseconds 20
}
Assert-Equal $true ([bool]$session.Transport.State.Preparation) 'generated worker reaches frozen preparation'
$preparation = $session.Transport.State.Preparation | ConvertFrom-Json
Set-StatusDeskDecision -Session $session -Approve $false -PlanDigest $preparation.planDigest
while (-not (Complete-StatusDeskSession $session) -and $deadline.Elapsed.TotalSeconds -lt 45) { Start-Sleep -Milliseconds 20 }
$terminal = $session.Transport.State.Terminal | ConvertFrom-Json
Assert-Equal 'PREPARATION.DECLINED' $terminal.reasonCode 'decline is consumed by the ordinary preparation gate'
Assert-Equal $false $terminal.collectionStarted 'decline schedules no collector'
try {
    Assert-Equal $true $session.Completed 'finished worker completion is authoritative'
    Assert-Equal $true ($null -eq $session.Worker) 'completion releases the disposed worker and its retained definition graph'
    Assert-Equal $true ($null -eq $session.Runspace) 'completion releases the disposed runspace'
    Assert-Equal $true ($null -eq $session.Pending) 'completion releases the completed asynchronous invocation'
    Assert-Equal $true (Complete-StatusDeskSession $session) 'repeated completion stays safe after owned references are released'
    Assert-Equal 'PREPARATION.DECLINED' ($session.Transport.State.Terminal | ConvertFrom-Json).reasonCode 'released worker retains the authoritative terminal'
}
finally {
    $session.Transport.Cancellation.Dispose()
    $session.Transport.DecisionReady.Dispose()
    $session.Transport.Events.Dispose()
}
Write-Output 'PASS: Status desk transport is bounded and preserves preparation and terminal records.'

# Finalization attempts both exact-owned disposals even if EndInvoke or Dispose fails.
foreach ($faultCase in @(
    @{ end=$true; worker=$true; runspace=$true; failures=3 },
    @{ end=$false; worker=$true; runspace=$false; failures=1 },
    @{ end=$false; worker=$false; runspace=$true; failures=1 }
)) {
    $fakeWorker=[pscustomobject]@{ EndFault=$faultCase.end; DisposeFault=$faultCase.worker; DisposeCalled=$false; EndCalls=0 }
    $fakeWorker | Add-Member ScriptMethod EndInvoke { param($pending) $this.EndCalls++; if($this.EndFault){throw 'Synthetic primary EndInvoke failure'}; 10 }
    $fakeWorker | Add-Member ScriptMethod Dispose { $this.DisposeCalled=$true; if($this.DisposeFault){throw 'Synthetic worker disposal failure'} }
    $fakeRunspace=[pscustomobject]@{ DisposeFault=$faultCase.runspace; DisposeCalled=$false }
    $fakeRunspace | Add-Member ScriptMethod Dispose { $this.DisposeCalled=$true; if($this.DisposeFault){throw 'Synthetic runspace disposal failure'} }
    $fakeSession=[pscustomobject]@{ Completed=$false; Stage='Running'; OpeningTask=$null; Pending=[pscustomobject]@{ IsCompleted=$true }; Worker=$fakeWorker; Runspace=$fakeRunspace; ExitCode=20 }
    $failure=$null
    try { Complete-StatusDeskSession $fakeSession | Out-Null } catch { $failure=$_.Exception }
    Assert-Equal $true ($null -ne $failure) 'a finalization fault cannot report completion'
    Assert-Equal $true $fakeWorker.DisposeCalled 'worker disposal is attempted despite an EndInvoke fault'
    Assert-Equal $true $fakeRunspace.DisposeCalled 'runspace disposal is attempted despite a worker disposal fault'
    Assert-Equal $false $fakeSession.Completed 'unverified disposal preserves finalization state'
    Assert-Equal $true ($failure -is [AggregateException]) 'uncertain finalization preserves an aggregate failure'
    Assert-Equal $faultCase.failures $failure.InnerExceptions.Count 'primary and independent disposal failures are all preserved'
    Assert-Equal $true ([bool]$failure.Data['OwnedCleanupUnverified']) 'unverified exact-owned disposal propagates the stop boundary'
    if ($faultCase.end) { Assert-Equal $true $failure.InnerExceptions[0].Message.Contains('Synthetic primary EndInvoke failure') 'the primary invocation failure remains first' }
    # Clear fake faults and retry: do not consume EndInvoke or dispose a known-
    # disposed handle again. These fakes own no native resources.
    $fakeWorker.DisposeFault=$false; $fakeRunspace.DisposeFault=$false
    try { Complete-StatusDeskSession $fakeSession | Out-Null } catch {
        Assert-Equal $true $faultCase.end 'only the preserved primary invocation error may remain after verified disposal'
    }
    Assert-Equal 1 $fakeWorker.EndCalls 'retry never consumes the completed invocation twice'
    Assert-Equal $true $fakeSession.Completed 'retry completes after both exact-owned disposals are verified'
}
Write-Output 'PASS: completion preserves primary failure, attempts independent disposal and safely retries exact-owned handles.'
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
