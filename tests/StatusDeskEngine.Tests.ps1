[CmdletBinding()]
param([switch] $CancelAfterIdentity, [switch] $CancelAfterResource, [switch] $CancelDuringPrivilege,
    [switch] $Wpf, [switch] $HoldRunLock)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
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
    $AdministratorScenario, $EffectivePolicyScenario, $CancellationToken)
    Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan $PreparationPlan -PlanDigest $PlanDigest `
        -AssessmentUserContext $AssessmentUserContext -AssessmentUserSid 'S-1-5-21-100-200-300-1001' `
        -LocalPackageProtector $LocalPackageProtector -ValidationScenario AcceptedElevation `
        -FirmwareScenario Supported -AdministratorScenario LocalPrincipal -EffectivePolicyScenario Workgroup -CancellationToken $CancellationToken }
function Invoke-SystemCollectionPlan { param($Plan, $PlanDigest, $ValidationScenario)
    $script:StatusDeskTransport.State.SystemInvoked=$true
    Invoke-ControlledSystemCollectionPlan -Plan $Plan -PlanDigest $PlanDigest -ValidationScenario SyntheticSuccess }
function Invoke-ApprovedCollectorProcess { param($OperationId, $DeviceReadinessScenario, $CancellationToken)
    Invoke-ControlledApprovedCollectorProcess -OperationId $OperationId -DeviceReadinessScenario Complete -CancellationToken $CancellationToken }
'@
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
$testRoot = Join-Path $repositoryRoot ('.test-output/status-desk-' + [guid]::NewGuid().ToString('N'))
$request = Get-AutomationRequest -LiteralPath (Join-Path $PSScriptRoot 'fixtures/automation-request.json') `
    -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
$request.outputDestination = $testRoot
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
        $uiState = @{ Session=$null; Window=$null; Clicked=$false; ReportClicked=$false; ReportObserved=$false; Failure='' }
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
            if ($window.FindName('Approve').IsEnabled -and -not $uiState.Clicked) {
                $uiState.Clicked=$true
                $window.FindName('Approve').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
            }
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
        Assert-Equal $true $uiState.ReportObserved ('actual Open report opens the protected HTML window: ' + $uiState.Failure)
    }
    else { $session = Start-StatusDeskSession -ModuleText $moduleText -LaunchParameters $launch }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while (-not $session.Transport.State.Preparation -and -not $session.Pending.IsCompleted -and $watch.Elapsed.TotalSeconds -lt 30) { Start-Sleep -Milliseconds 25 }
    Assert-Equal $true ([bool]$session.Transport.State.Preparation) 'actual preparation runs inside the generated worker'
    $preparation = $session.Transport.State.Preparation | ConvertFrom-Json
    Assert-Equal $true $preparation.readyForApproval 'synthetic controlled run has ready local protection'
    Assert-Equal 0 @($preparation.plan.network.plannedRequests).Count 'Local Only freezes no requests'
    if (-not $Wpf) { Set-StatusDeskDecision -Session $session -Approve $true -PlanDigest $preparation.planDigest }
    while (-not (Complete-StatusDeskSession $session) -and $watch.Elapsed.TotalSeconds -lt 120) { Start-Sleep -Milliseconds 25 }
    Assert-Equal $true $session.Completed 'ordinary collector chain reaches bounded completion'
    $terminal = $session.Transport.State.Terminal | ConvertFrom-Json
    if ($HoldRunLock) {
        Assert-Equal 'NotStarted' $terminal.outcome 'the actual scheduler refuses a concurrent run'
        Assert-Equal 'RUN.ACTIVE_LOCK_HELD' $terminal.reasonCode 'lock contention has an honest terminal reason'
        Assert-Equal $false $terminal.collectionStarted 'lock contention starts no collector'
        return
    }
    Assert-Equal $(if($CancelAfterIdentity -or $CancelAfterResource -or $CancelDuringPrivilege){'Cancelled'}else{'CompletedWithGaps'}) $terminal.outcome ('controlled ordinary engine: ' + $terminal.reasonCode)
    Assert-Equal $true $terminal.collectionStarted 'ordinary collection actually executed'
    Assert-Equal $preparation.planDigest $terminal.planDigest 'approval and terminal bind the same frozen plan'
    $summary = $session.Transport.State.Completion | ConvertFrom-Json
    Assert-Equal 'Available' $summary.packageAvailability 'a usable protected result survives completion'
    Assert-Equal $true ([bool]$session.Transport.State.PackagePath) 'Open report receives the exact verified package'
    $opened = Read-ProtectedEvidencePackage -LiteralPath $session.Transport.State.PackagePath
    Assert-Equal $true $opened.verified 'actual encryption boundary reopens the generated result'
    $record = [Text.Encoding]::UTF8.GetString($opened.artifacts['assessment-record.json']) | ConvertFrom-Json
    Assert-Equal $true (@($record.observations).Count -gt 0) 'real engine carries controlled source observations'
    Assert-Equal $true (@($record.findings).Count -gt 0) 'rules derive evidence-linked advisory interpretation'
    Assert-Equal $true (@($record.recommendations).Count -gt 0) 'report retains useful follow-up'
    if ($CancelDuringPrivilege) {
        Assert-Equal $false $session.Transport.State.ContainsKey('SystemInvoked') 'privileged cancellation schedules no later SYSTEM worker'
        Assert-Equal $true (@($record.coverage | Where-Object state -eq Cancelled).Count -ge 4) 'stopped prerequisites stay explicitly Cancelled'
        $policyFinding=@($record.findings | Where-Object ruleId -eq 'rule:cross-domain.policy-modernization/1.0.0')[0]
        Assert-Equal 'Indeterminate' $policyFinding.outcome 'uncollected policy evidence never becomes a successful negative'
        Assert-Equal 0 @($policyFinding.evidenceReferences).Count 'absent policy references remain a valid empty list'
    }
    $html = [Text.Encoding]::UTF8.GetString($opened.artifacts['assessment-report.html'])
    if (-not ($CancelAfterIdentity -or $CancelAfterResource)) { Assert-Equal $true $html.Contains('Local Only') 'offline report preserves network choice' }
    $viewing = Open-EvidenceViewingSession -PackagePath $session.Transport.State.PackagePath `
        -RequestedArtifact assessment-report.html -ViewingBasePath $testRoot
    Assert-Equal 'Opened' $viewing.state 'Open report uses a registered protected viewing boundary'
    Assert-Equal $true (Close-EvidenceViewingSession $viewing).verified 'closing report verifies owned plaintext cleanup'
    foreach ($bytes in $opened.artifacts.Values) { [Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]]$bytes) }
}
finally {
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
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
Write-Output 'PASS: generated Status desk worker executes controlled comprehensive collectors, protects a useful offline report, and cleans viewing.'
