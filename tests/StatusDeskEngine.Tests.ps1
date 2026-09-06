[CmdletBinding()]
param([switch] $CancelAfterIdentity, [switch] $CancelAfterResource, [switch] $CancelDuringPrivilege,
    [switch] $DeclinePreparation,
    [switch] $Wpf, [switch] $HoldRunLock,
    [ValidateSet('None','Cancel','Close')] [string] $ActiveAction = 'None',
    [ValidateSet('Privilege','System','NativeCooperative','NativeHard')] [string] $ActiveWorker = 'Privilege',
    [switch] $RequireRecoveryJournal, [switch] $RequireFrontLoadedPrivilege,
    [string] $ReadinessSourceScenario = '',
    [string] $IdentitySourceScenario = '',
    [string] $PolicySourceScenario = '',
    [string] $NetworkSourceScenario = '',
    [ValidateSet('AcceptedElevation','AlreadyElevated','AlternateAdministrator','ElevationDenied')]
    [string] $PrivilegeOutcome = 'AcceptedElevation',
    [string] $RecoveryDestination = '', [string] $RecoveryExpectedReason = '',
    [switch] $RecoveryAuthorized, [string] $InterruptHandoffPath = '',
    [ValidateSet('None','Integrity','Cleanup')] [string] $FailureKind = 'None')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$regions = [regex]::Matches([IO.File]::ReadAllText($candidate),
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach ($region in $regions) { . ([scriptblock]::Create($region.Groups[2].Value)) }
$moduleText = ($regions | ForEach-Object { $_.Groups[2].Value }) -join "`n"
# Controlled adapters substitute every OS collector boundary, never the engine,
# canonical validation, rules, report, encryption or reopening. This test invokes
# the ordinary non-fixture scheduler; no fixture or adapter CLI is shipped.
$names = @('IdentityEnrollmentCollection','ResourceDependenciesCollection','NetworkTopologyCollection',
    'SoftwareInventoryCollection','CertificateTrustCollection','MicrosoftConnectivityCollection',
    'PrivilegedCollectionPlan','SystemCollectionPlan','ApprovedCollectorProcess')
foreach ($name in $names) {
    $moduleText = $moduleText.Replace("function Invoke-$name {", "function Invoke-Controlled$name {")
}
$moduleText += @'

function Invoke-IdentityEnrollmentCollection { param($Policy, [switch]$Live)
    Invoke-ControlledIdentityEnrollmentCollection -Policy $Policy -ValidationScenario StandardUser }
function Invoke-ResourceDependenciesCollection { param($Policy, [switch]$Live, $AssessmentUserSid)
    Invoke-ControlledResourceDependenciesCollection -Policy $Policy -ValidationScenario Empty }
function Invoke-NetworkTopologyCollection { param($Policy, [switch]$Live, $AssessmentUserSid, $NetworkBehavior)
    if ($NetworkBehavior -ne 'LocalOnly') { throw 'Unexpected assessment network authority.' }
    Invoke-ControlledNetworkTopologyCollection -Policy $Policy -ValidationScenario Empty -NetworkBehavior $NetworkBehavior }
function Invoke-SoftwareInventoryCollection { param($Policy, [switch]$Live, $AssessmentUserSid)
    Invoke-ControlledSoftwareInventoryCollection -Policy $Policy -ValidationScenario Empty }
function Invoke-CertificateTrustCollection { param($Policy, [switch]$Live, $AssessmentUserSid)
    Invoke-ControlledCertificateTrustCollection -Policy $Policy -ValidationScenario ValidTrusted }
function Invoke-MicrosoftConnectivityCollection { param($Policy, [switch]$Live, $NetworkBehavior, $AssessmentUserSid)
    if ($NetworkBehavior -ne 'LocalOnly') { throw 'Unexpected assessment network authority.' }
    Invoke-ControlledMicrosoftConnectivityCollection -Policy $Policy -ValidationScenario LocalOnly -NetworkBehavior LocalOnly }
function Invoke-PrivilegedCollectionPlan { param($PreparationPlan, $PlanDigest, $AssessmentUserContext,
    $AssessmentUserSid, $LocalPackageProtector, $ValidationScenario, $FirmwareScenario,
    $AdministratorScenario, $EffectivePolicyScenario, $CancellationToken, $SystemPlanResult, $SystemValidationScenario)
    $result=Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan $PreparationPlan -PlanDigest $PlanDigest `
        -AssessmentUserContext $AssessmentUserContext -AssessmentUserSid 'S-1-5-21-100-200-300-1001' `
        -LocalPackageProtector $LocalPackageProtector -ValidationScenario AcceptedElevation `
        -FirmwareScenario Supported -AdministratorScenario LocalPrincipal -EffectivePolicyScenario Workgroup -CancellationToken $CancellationToken `
        -SystemPlanResult $SystemPlanResult -SystemValidationScenario SyntheticSuccess
    $script:StatusDeskTransport.State.PrivilegeCompleted=$true; $result }
function Invoke-SystemCollectionPlan { param($Plan, $PlanDigest, $ValidationScenario, $CancellationToken, $PrivilegeChannel)
    $script:StatusDeskTransport.State.SystemInvoked=$true
    Invoke-ControlledSystemCollectionPlan -Plan $Plan -PlanDigest $PlanDigest -ValidationScenario SyntheticSuccess -CancellationToken $CancellationToken -PrivilegeChannel $PrivilegeChannel }
function Invoke-ApprovedCollectorProcess { param($OperationId, $DeviceReadinessScenario, $CancellationToken)
    Invoke-ControlledApprovedCollectorProcess -OperationId $OperationId -DeviceReadinessScenario Complete -CancellationToken $CancellationToken }
'@
if ($PrivilegeOutcome -ne 'AcceptedElevation') {
    $moduleText=$moduleText.Replace('-ValidationScenario AcceptedElevation', '-ValidationScenario ' + $PrivilegeOutcome)
}
if ($RequireFrontLoadedPrivilege) {
    $moduleText=$moduleText.Replace('Invoke-ControlledIdentityEnrollmentCollection -Policy',
        'if (-not $script:StatusDeskTransport.State.ContainsKey("PrivilegeCompleted")) { throw "Collection preceded privilege authorization." }; Invoke-ControlledIdentityEnrollmentCollection -Policy')
}
if ($CancelAfterIdentity) {
    $moduleText = $moduleText.Replace('Invoke-ControlledIdentityEnrollmentCollection -Policy $Policy -ValidationScenario StandardUser }',
        'Invoke-ControlledIdentityEnrollmentCollection -Policy $Policy -ValidationScenario StandardUser; $script:StatusDeskTransport.Cancellation.Cancel() }')
}
if ($CancelAfterResource) {
    $moduleText = $moduleText.Replace('Invoke-ControlledResourceDependenciesCollection -Policy $Policy -ValidationScenario Empty }',
        'Invoke-ControlledResourceDependenciesCollection -Policy $Policy -ValidationScenario Empty; $script:StatusDeskTransport.Cancellation.Cancel() }')
}
if ($CancelDuringPrivilege) {
    $moduleText = $moduleText.Replace('Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan',
        '$script:StatusDeskTransport.Cancellation.CancelAfter(1500); Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan')
    $moduleText = $moduleText.Replace('-LocalPackageProtector $LocalPackageProtector -ValidationScenario AcceptedElevation',
        '-LocalPackageProtector $LocalPackageProtector -ValidationScenario Cancellation')
}
if ($ActiveAction -ne 'None') {
    $moduleText = $moduleText.Replace('Invoke-ControlledResourceDependenciesCollection -Policy',
        '[Threading.Thread]::Sleep(11500); Invoke-ControlledResourceDependenciesCollection -Policy')
    if ($ActiveWorker -eq 'Privilege') {
        $moduleText = $moduleText.Replace('$result=Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan',
            '$script:StatusDeskTransport.State.ControlledWorkerStarted=[Diagnostics.Stopwatch]::GetTimestamp(); $result=Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan')
        $moduleText = $moduleText.Replace('$script:StatusDeskTransport.State.PrivilegeCompleted=$true; $result }',
            '$script:StatusDeskTransport.State.PrivilegeCompleted=$true; $script:StatusDeskTransport.State.ControlledWorkerCleanup=$result.cleanup.verified; $result }')
        $moduleText = $moduleText.Replace('-LocalPackageProtector $LocalPackageProtector -ValidationScenario AcceptedElevation',
            '-LocalPackageProtector $LocalPackageProtector -ValidationScenario Cancellation')
    }
    elseif ($ActiveWorker -eq 'System') {
        $moduleText = $moduleText.Replace('Invoke-ControlledSystemCollectionPlan -Plan $Plan -PlanDigest $PlanDigest -ValidationScenario SyntheticSuccess -CancellationToken $CancellationToken -PrivilegeChannel $PrivilegeChannel }',
            '$script:StatusDeskTransport.State.ControlledWorkerStarted=[Diagnostics.Stopwatch]::GetTimestamp(); $result=Invoke-ControlledSystemCollectionPlan -Plan $Plan -PlanDigest $PlanDigest -ValidationScenario Cancellation -CancellationToken $CancellationToken -PrivilegeChannel $PrivilegeChannel; $script:StatusDeskTransport.State.ControlledWorkerCleanup=$result.cleanup.verified -and $result.cleanup.taskAbsent -and $result.cleanup.workerTreeAbsent -and $result.cleanup.pipeAbsent; $result }')
    }
    else {
        $fixture = if ($ActiveWorker -eq 'NativeCooperative') { 'cooperative-cancel' } else { 'hard-cancel' }
        $moduleText = $moduleText.Replace('Invoke-ControlledApprovedCollectorProcess -OperationId $OperationId -DeviceReadinessScenario Complete -CancellationToken $CancellationToken }',
            ('$script:StatusDeskTransport.State.ControlledWorkerStarted=[Diagnostics.Stopwatch]::GetTimestamp(); $result=Invoke-ControlledApprovedCollectorProcess -OperationId fixture:synthetic.' + $fixture + ' -CancellationToken $CancellationToken; $script:StatusDeskTransport.State.ControlledWorkerCleanup=$result.Supervision.completeOwnedTreeAbsent -and $result.Supervision.temporaryArtifactsAbsent; $script:StatusDeskTransport.State.TerminationMode=$result.Supervision.terminationMode; $result }'))
    }
}
if ($RequireRecoveryJournal) {
    $moduleText = $moduleText.Replace('$result=Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan',
        '$script:StatusDeskTransport.State.JournalObserved=(Test-Path -LiteralPath $Parameters.Request.outputDestination) -and @(Get-ChildItem -LiteralPath $Parameters.Request.outputDestination -Filter WINPCInfo-Recovery-v1-* -Directory).Count -eq 1; $result=Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan')
}
if ($InterruptHandoffPath) {
    $handoffLiteral = "'" + $InterruptHandoffPath.Replace("'", "''") + "'"
    $moduleText = $moduleText.Replace('Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan',
        "[IO.File]::WriteAllText($handoffLiteral, 'registered-before-supervised-worker'); Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan")
    $moduleText = $moduleText.Replace('-LocalPackageProtector $LocalPackageProtector -ValidationScenario AcceptedElevation',
        '-LocalPackageProtector $LocalPackageProtector -ValidationScenario Cancellation')
}
if ($FailureKind -eq 'Integrity') {
    $moduleText = $moduleText.Replace('-LocalPackageProtector $LocalPackageProtector -ValidationScenario AcceptedElevation',
        '-LocalPackageProtector $LocalPackageProtector -ValidationScenario AlteredPlan')
}
elseif ($FailureKind -eq 'Cleanup') {
    $moduleText = $moduleText.Replace('Invoke-ControlledResourceDependenciesCollection -Policy $Policy -ValidationScenario Empty }',
        '$result=Invoke-ControlledResourceDependenciesCollection -Policy $Policy -ValidationScenario Empty; $temporary=Add-TemporaryEvidence -JournalPath $script:AssessmentRunJournalPath -Content ([Text.Encoding]::UTF8.GetBytes("synthetic locked residue")); $script:StatusDeskTransport.State.SyntheticLock=[IO.File]::Open($temporary.literalPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None); $result }')
}
if ($ReadinessSourceScenario) {
    . (Join-Path $PSScriptRoot 'ReadinessSourceAdapters.ps1')
    $moduleText = Add-ControlledReadinessSources -ModuleText $moduleText -Scenario $ReadinessSourceScenario
}
if ($IdentitySourceScenario) {
    . (Join-Path $PSScriptRoot 'IdentitySourceAdapters.ps1')
    $moduleText = Add-ControlledIdentitySources -ModuleText $moduleText -Scenario $IdentitySourceScenario
}
if ($PolicySourceScenario) {
    $sessionSource=(Get-Command Start-StatusDeskSession).Definition.Replace(
        '# Never copy an exception (potentially Restricted) into GUI activity.',
        '$Transport.State.PolicySourceFailure=$_.Exception.Message + '' '' + $_.ScriptStackTrace')
    . ([scriptblock]::Create('function Start-StatusDeskSession {' + $sessionSource + '}'))
    . (Join-Path $PSScriptRoot 'PolicySourceAdapters.ps1')
    $moduleText = Add-ControlledPolicySources -ModuleText $moduleText -Scenario $PolicySourceScenario
}
if ($NetworkSourceScenario) {
    . (Join-Path $PSScriptRoot 'NetworkSourceAdapters.ps1')
    $moduleText=Add-ControlledNetworkSources -ModuleText $moduleText -Scenario $NetworkSourceScenario
}
$testRoot = Join-Path $repositoryRoot ('.test-output/status-desk-' + [guid]::NewGuid().ToString('N'))
if ($RecoveryDestination) { $testRoot = [IO.Path]::GetFullPath($RecoveryDestination) }
$ownedParent = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
if (-not [IO.Path]::GetFullPath($testRoot).StartsWith($ownedParent, [StringComparison]::OrdinalIgnoreCase)) { throw 'Test output must remain in its owned test boundary.' }
$request = Get-AutomationRequest -LiteralPath (Join-Path $PSScriptRoot 'fixtures/automation-request.json') `
    -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
$request.outputDestination = $testRoot
$request.automationChoices.allowStaleRecovery = [bool]$RecoveryAuthorized
$context = @{ IsFixture = $false }
foreach ($name in @('Preparation','Contract','Run','PrivilegedCollection','SystemCollection',
    'EvidenceWorkspace','ProtectedPackage','RecipientSharing','DeviceReadiness','IdentityEnrollment',
    'AdministratorExposure','EffectivePolicy','ResourceDependencies','NetworkTopology',
    'SoftwareInventory','CertificateTrust','MicrosoftConnectivity')) { $context[$name + 'FixturePath'] = '' }
$session = $null
$runLock = $null
$runLockOwned = $false
try {
    if ($HoldRunLock) {
        $runLock = [Threading.Mutex]::new($false, [string](Get-AssessmentRunLifecyclePolicy).activeRunLock.name)
        $runLockOwned = $runLock.WaitOne(0)
        if (-not $runLockOwned) { throw 'Synthetic lock ownership could not be established.' }
    }
    $launch = @{
        Request=$request; RuntimeFacts=(Get-ActiveRuntimeFacts -ModuleFacts (Get-BuiltInModuleCompatibilityFacts))
        ArtifactTrustValid=$true; ValidationContext=[pscustomobject]$context
    }
    if ($Wpf) {
        Add-Type -AssemblyName PresentationFramework
        $null = [System.Windows.Window]
        $uiState = @{ Session=$null; Window=$null; Clicked=$false; ReportClicked=$false; ReportObserved=$false; Failure=''; ActionSent=$false; ResponsiveTicks=0; Acknowledged=$false; AcknowledgmentMilliseconds=-1; PeakPrivateBytes=0L; PeakWorkingSetBytes=0L }
        $driver = [System.Windows.Threading.DispatcherTimer]::new()
        $driver.Interval = [TimeSpan]::FromMilliseconds(100)
        $reportCloser = [System.Windows.Threading.DispatcherTimer]::new()
        $reportCloser.Interval = [TimeSpan]::FromMilliseconds(200)
        $uiWatch = [Diagnostics.Stopwatch]::StartNew()
        $reportCloser.Add_Tick({
            if ($null -ne $uiState.Window -and $uiState.Window.OwnedWindows.Count -gt 0) {
                $reportWindow=$uiState.Window.OwnedWindows[0]
                $document=$reportWindow.Content.Document
                if ($null -ne $document -and $null -ne $document.body -and
                    [string]$document.body.innerText -like '*WIN-PCInfo Comprehensive Local Assessment*') {
                    $uiState.ReportObserved=$true
                    $reportWindow.Close()
                }
            }
            if ($uiWatch.Elapsed.TotalSeconds -gt 90 -and $null -ne $uiState.Window) {
                $uiState.Failure='WPF test exceeded its deadline.'
                $uiState.Window.Close()
            }
        }.GetNewClosure())
        $driver.Add_Tick({
            $window=$uiState.Window
            if ($null -eq $window) { return }
            $ownProcess=[Diagnostics.Process]::GetCurrentProcess()
            try {
                $uiState.PeakPrivateBytes=[Math]::Max($uiState.PeakPrivateBytes,$ownProcess.PrivateMemorySize64)
                $uiState.PeakWorkingSetBytes=[Math]::Max($uiState.PeakWorkingSetBytes,$ownProcess.WorkingSet64)
            } finally { $ownProcess.Dispose() }
            if ($window.FindName('Approve').IsEnabled -and -not $uiState.Clicked) {
                $uiState.Clicked=$true
                $window.FindName('Approve').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
            }
            if ($ActiveAction -ne 'None' -and -not $uiState.ActionSent -and
                $uiState.Session.Transport.State.ContainsKey('ControlledWorkerStarted') -and
                [Diagnostics.Stopwatch]::GetElapsedTime($uiState.Session.Transport.State.ControlledWorkerStarted).TotalMilliseconds -ge 1500) {
                $uiState.ActionSent=$true
                $actionWatch=[Diagnostics.Stopwatch]::StartNew()
                if ($ActiveAction -eq 'Close') { $window.Close() }
                else { $window.FindName('Cancel').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)) }
                $uiState.Acknowledged=$actionWatch.ElapsedMilliseconds -le 2000 -and $window.FindName('Status').Text -match 'Cancelling|Closing'
                $uiState.AcknowledgmentMilliseconds=$actionWatch.ElapsedMilliseconds
            }
            if ($uiState.ActionSent -and -not $uiState.Session.Completed) { $uiState.ResponsiveTicks++ }
            if ($ActiveAction -eq 'Close' -and -not $uiState.Session.Completed) { return }
            if ($window.FindName('OpenReport').IsEnabled -and -not $uiState.ReportClicked) {
                $uiState.ReportClicked=$true
                $window.FindName('OpenReport').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
            }
            elseif ($uiState.ReportObserved) { $window.Close() }
            elseif ($uiState.Session.Completed -and -not $window.FindName('OpenReport').IsEnabled) {
                $uiState.Failure=$window.FindName('Details').Text
                $window.Close()
            }
        }.GetNewClosure())
        try {
            $null = Invoke-StatusDesk -ModuleText $moduleText -LaunchParameters $launch -ViewReady {
                param($window, $workerSession)
                $window.Opacity=0; $window.ShowInTaskbar=$false
                $uiState.Window=$window; $uiState.Session=$workerSession
                $reportCloser.Start(); $driver.Start()
            }.GetNewClosure()
        }
        finally { $driver.Stop(); $reportCloser.Stop() }
        $session=$uiState.Session
        Assert-Equal $true $uiState.Clicked 'actual STA WPF approval control starts the same worker'
        if ($FailureKind -ne 'None') {
            Assert-Equal $false $uiState.ReportClicked 'failure disables the actual report control'
            Assert-Equal $(if($FailureKind -eq 'Integrity'){'IntegrityFailed'}else{'CleanupIncomplete'}) $uiState.Window.FindName('Status').Text 'GUI displays the authoritative failure precedence'
        }
        elseif ($ActiveAction -eq 'None') { Assert-Equal $true $uiState.ReportObserved ('actual Open report opens the protected HTML window: ' + $uiState.Failure) }
        else {
            Assert-Equal $true $uiState.ActionSent 'active action reaches the actual waiting privileged worker'
            Assert-Equal $true $uiState.Acknowledged 'actual control acknowledges cancellation within two seconds'
            Assert-Equal $true ($uiState.ResponsiveTicks -ge 3) 'dispatcher remains responsive throughout supervised finalization'
            Assert-Equal $true $session.Transport.State.ControlledWorkerCleanup 'active action verifies owned privileged process tree and channel absence'
            Assert-Equal $true ($session.Transport.State.FirstProgressMilliseconds -le 5000) 'first generated application progress arrives within five seconds'
            Assert-Equal $true ($session.Transport.State.MaximumProgressGapMilliseconds -le 10000) 'sustained generated application progress gaps stay within ten seconds'
            if ($ActiveWorker -like 'Native*') { Assert-Equal $(if ($ActiveWorker -eq 'NativeCooperative') {'Cooperative'}else{'Hard'}) $session.Transport.State.TerminationMode 'native worker uses the expected cooperative or bounded hard stop' }
            Write-Output ('TIMING: action={0}; worker={1}; first={2}ms; maximumGap={3}ms; acknowledgment={4}ms; cancellationToTerminal={5}ms; sampledPrivateMiB={6}; sampledWorkingSetMiB={7}' -f $ActiveAction,$ActiveWorker,$session.Transport.State.FirstProgressMilliseconds,$session.Transport.State.MaximumProgressGapMilliseconds,$uiState.AcknowledgmentMilliseconds,($session.Transport.State.TerminalMilliseconds-$session.Transport.State.CancellationRequestedMilliseconds),[Math]::Round($uiState.PeakPrivateBytes/1MB),[Math]::Round($uiState.PeakWorkingSetBytes/1MB))
        }
    }
    else { $session = Start-StatusDeskSession -ModuleText $moduleText -LaunchParameters $launch }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while (-not $session.Transport.State.Preparation -and -not $session.Pending.IsCompleted -and $watch.Elapsed.TotalSeconds -lt 30) { Start-Sleep -Milliseconds 25 }
    Assert-Equal $true ([bool]$session.Transport.State.Preparation) 'actual preparation runs inside the generated worker'
    $preparation = $session.Transport.State.Preparation | ConvertFrom-Json
    Assert-Equal $true $preparation.readyForApproval 'synthetic controlled run has ready local protection'
    Assert-Equal 0 @($preparation.plan.network.plannedRequests).Count 'Local Only freezes no requests'
    if ($NetworkSourceScenario) {
        Assert-Equal $false $session.Transport.State.ContainsKey('NetworkSourceExecuted') 'preparation executes no topology source before approval'
        Assert-Equal $false $session.Transport.State.ContainsKey('NetworkRequestAttempted') 'preparation invokes no network request adapter'
    }
    if (-not $Wpf) { Set-StatusDeskDecision -Session $session -Approve (-not $DeclinePreparation) -PlanDigest $preparation.planDigest }
    while (-not (Complete-StatusDeskSession $session) -and $watch.Elapsed.TotalSeconds -lt 120) { Start-Sleep -Milliseconds 25 }
    Assert-Equal $true $session.Completed 'ordinary collector chain reaches bounded completion'
    if ($IdentitySourceScenario -and $session.Transport.State.ContainsKey('IdentitySourceFailure')) { throw ($session.Transport.State.IdentitySourceFailure + ' ' + $session.Transport.State.IdentityPrivilegeReason) }
    if ($PolicySourceScenario -and $session.Transport.State.ContainsKey('PolicySourceFailure')) { throw ($session.Transport.State.PolicySourceFailure + ' ' + $session.Transport.State.PolicyPrivilegeReason) }
    $terminal = $session.Transport.State.Terminal | ConvertFrom-Json
    if ($DeclinePreparation) {
        Assert-Equal 'NotStarted' $terminal.outcome 'declined preparation starts no assessment'
        Assert-Equal $false $terminal.collectionStarted 'declined preparation executes no local collector'
        Assert-Equal $false $session.Transport.State.ContainsKey('NetworkSourceExecuted') 'declined preparation reaches no nested topology source'
        Assert-Equal $false $session.Transport.State.ContainsKey('NetworkRequestAttempted') 'declined preparation reaches no network adapter'
        Assert-Equal '' $session.Transport.State.PackagePath 'declined preparation invents no protected report'
        return
    }
    if ($FailureKind -ne 'None') {
        $expectedOutcome=if($FailureKind -eq 'Integrity'){'IntegrityFailed'}else{'CleanupIncomplete'}
        Assert-Equal $expectedOutcome $terminal.outcome 'structured terminal preserves integrity/cleanup precedence'
        Assert-Equal $(if($FailureKind -eq 'Integrity'){50}else{60}) $session.ExitCode 'exit status preserves integrity/cleanup precedence'
        $completion=$session.Transport.State.Completion | ConvertFrom-Json
        Assert-Equal $expectedOutcome $completion.assessment.outcome 'completion record agrees with GUI and exit'
        Assert-Equal '' $session.Transport.State.PackagePath 'failure exposes no unverified report action'
        if ($FailureKind -eq 'Cleanup') {
            Assert-Equal $false $terminal.cleanup.verified 'surviving locked residue is not cleanup success'
            Assert-Equal 1 @(Get-ChildItem -LiteralPath $testRoot -Filter WINPCInfo-Recovery-v1-* -Directory).Count 'cleanup uncertainty preserves durable recovery state'
        }
        return
    }
    if ($RecoveryExpectedReason) {
        Assert-Equal $RecoveryExpectedReason $terminal.reasonCode 'ordinary generated recovery has the expected truthful terminal'
        Assert-Equal $false $terminal.collectionStarted 'recovery never starts or resumes collection'
        Assert-Equal '' $session.Transport.State.PackagePath 'recovery exposes no newly collected report'
        return
    }
    if ($HoldRunLock) {
        Assert-Equal 'NotStarted' $terminal.outcome 'the actual scheduler refuses a concurrent run'
        Assert-Equal 'RUN.ACTIVE_LOCK_HELD' $terminal.reasonCode 'lock contention has an honest terminal reason'
        Assert-Equal $false $terminal.collectionStarted 'lock contention starts no collector'
        return
    }
    Assert-Equal $(if($CancelAfterIdentity -or $CancelAfterResource -or $CancelDuringPrivilege -or $ActiveAction -ne 'None' -or $ReadinessSourceScenario -eq 'Cancelled'){'Cancelled'}else{'CompletedWithGaps'}) $terminal.outcome ('controlled ordinary engine: ' + $terminal.reasonCode)
    Assert-Equal $true $terminal.collectionStarted 'ordinary collection actually executed'
    if ($RequireRecoveryJournal) {
        Assert-Equal $true $session.Transport.State.JournalObserved 'ordinary assessment registers durable ownership before the first source executes'
        Assert-Equal 0 @(Get-ChildItem -LiteralPath $testRoot -Filter WINPCInfo-Recovery-v1-* -Directory).Count 'successful finalization removes the journal after owned transient absence'
    }
    Assert-Equal $preparation.planDigest $terminal.planDigest 'approval and terminal bind the same frozen plan'
    $summary = $session.Transport.State.Completion | ConvertFrom-Json
    if (($CancelDuringPrivilege -or ($ActiveAction -ne 'None' -and $ActiveWorker -in @('Privilege','System'))) -and
        $summary.packageAvailability -eq 'VerifiedAbsent') {
        Assert-Equal '' $session.Transport.State.PackagePath 'cancellation before useful evidence does not invent a report'
        Assert-Equal $true $terminal.cleanup.verified 'early cancellation verifies both privilege and SYSTEM cleanup'
        if ($CancelDuringPrivilege -or $ActiveWorker -eq 'Privilege') {
            Assert-Equal $false $session.Transport.State.ContainsKey('SystemInvoked') 'cancelled administrator work cannot launch SYSTEM'
        }
        return
    }
    Assert-Equal 'Available' $summary.packageAvailability 'a usable protected result survives completion'
    Assert-Equal $true ([bool]$session.Transport.State.PackagePath) 'Open report receives the exact verified package'
    $opened = Read-ProtectedEvidencePackage -LiteralPath $session.Transport.State.PackagePath
    Assert-Equal $true $opened.verified 'actual encryption boundary reopens the generated result'
    $record = [Text.Encoding]::UTF8.GetString($opened.artifacts['assessment-record.json']) | ConvertFrom-Json
    Assert-Equal $true (@($record.observations).Count -gt 0) 'real engine carries controlled source observations'
    Assert-Equal $true (@($record.findings).Count -gt 0) 'rules derive evidence-linked advisory interpretation'
    Assert-Equal $true (@($record.recommendations).Count -gt 0) 'report retains useful follow-up'
    if ($PrivilegeOutcome -eq 'ElevationDenied') {
        Assert-Equal $false $session.Transport.State.ContainsKey('SystemInvoked') 'denied UAC cannot activate SYSTEM'
        Assert-Equal $true (@($record.coverage | Where-Object state -eq Complete).Count -gt 0) 'unrelated standard-user coverage survives denial'
        Assert-Equal $true (@($record.coverage | Where-Object state -in @('Denied','Unavailable')).Count -gt 0) 'denied privilege remains an explicit coverage gap'
    }
    if ($CancelDuringPrivilege) {
        Assert-Equal $false $session.Transport.State.ContainsKey('SystemInvoked') 'privileged cancellation schedules no later SYSTEM worker'
        Assert-Equal $true (@($record.coverage | Where-Object state -eq Cancelled).Count -ge 4) 'stopped prerequisites stay explicitly Cancelled'
        $policyFinding=@($record.findings | Where-Object ruleId -eq 'rule:cross-domain.policy-modernization/1.0.0')[0]
        Assert-Equal 'Indeterminate' $policyFinding.outcome 'uncollected policy evidence never becomes a successful negative'
        Assert-Equal 0 @($policyFinding.evidenceReferences).Count 'absent policy references remain a valid empty list'
    }
    $html = [Text.Encoding]::UTF8.GetString($opened.artifacts['assessment-report.html'])
    if ($NetworkSourceScenario) {
        Assert-Equal $true $session.Transport.State.NetworkSourceExecuted 'actual generated local reducer executed'
        Assert-Equal $false $session.Transport.State.ContainsKey('NetworkRequestAttempted') 'Local Only never enters the nested network request adapter'
        Assert-NetworkSourceReport -Record $record -Html $html -Scenario $NetworkSourceScenario
    }
    if ($ReadinessSourceScenario) {
        Assert-ReadinessSourceReport -Record $record -Html $html -Scenario $ReadinessSourceScenario
    }
    if ($IdentitySourceScenario) {
        Assert-IdentitySourceReport -Record $record -Html $html -Scenario $IdentitySourceScenario
    }
    if ($PolicySourceScenario) {
        Assert-PolicySourceReport -Record $record -Html $html -Scenario $PolicySourceScenario
    }
    if (-not ($CancelAfterIdentity -or $CancelAfterResource)) { Assert-Equal $true $html.Contains('Local Only') 'offline report preserves network choice' }
    $viewing = Open-EvidenceViewingSession -PackagePath $session.Transport.State.PackagePath `
        -RequestedArtifact assessment-report.html -ViewingBasePath $testRoot
    Assert-Equal 'Opened' $viewing.state 'Open report uses a registered protected viewing boundary'
    Assert-Equal $true (Close-EvidenceViewingSession $viewing).verified 'closing report verifies owned plaintext cleanup'
    foreach ($bytes in $opened.artifacts.Values) { [Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]]$bytes) }
}
finally {
    if ($null -ne $session -and $session.Transport.State.ContainsKey('SyntheticLock')) { $session.Transport.State.SyntheticLock.Dispose() }
    if ($null -ne $runLock) { if ($runLockOwned) { $runLock.ReleaseMutex() }; $runLock.Dispose() }
    if ($null -ne $session -and -not $session.Completed) {
        $session.Transport.Cancellation.Cancel()
        Set-StatusDeskDecision -Session $session -Approve $false -PlanDigest 'test-cleanup'
        $cleanupWatch=[Diagnostics.Stopwatch]::StartNew()
        while (-not (Complete-StatusDeskSession $session) -and $cleanupWatch.Elapsed.TotalSeconds -lt 120) { Start-Sleep -Milliseconds 50 }
        if (-not $session.Completed) { throw 'Owned test worker is still active; preserve its evidence and recovery directory.' }
    }
    if (-not $Wpf -and $null -ne $session -and $session.Completed) {
        $session.Transport.Cancellation.Dispose(); $session.Transport.DecisionReady.Dispose(); $session.Transport.Events.Dispose()
    }
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $ownedParent = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($ownedParent, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected synthetic cleanup target.' }
    if (-not $RecoveryDestination -and (Test-Path -LiteralPath $resolved)) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
Write-Output 'PASS: generated Status desk worker executes controlled comprehensive collectors, protects a useful offline report, and cleans viewing.'
