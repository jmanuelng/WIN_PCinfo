Set-StrictMode -Version Latest

function New-StatusDeskTransport {
    [pscustomobject]@{
        Events = [Collections.Concurrent.BlockingCollection[string]]::new(128)
        State = [hashtable]::Synchronized(@{
            Preparation = ''; Completion = ''; Terminal = ''; PackagePath = ''
            ApprovedDigest = ''; Decision = 'Declined'; CollectionStarted = $false
            FirstProgressMilliseconds = -1L; LastProgressMilliseconds = 0L
            MaximumProgressGapMilliseconds = 0L; ProgressSequence = 0
            CancellationRequestedMilliseconds = -1L; TerminalMilliseconds = -1L
        })
        Clock = [Diagnostics.Stopwatch]::StartNew()
        RecordGate = [object]::new()
        DecisionReady = [Threading.ManualResetEventSlim]::new($false)
        Cancellation = [Threading.CancellationTokenSource]::new()
    }
}

function Send-StatusDeskRecord {
    param([Parameter(Mandatory)] $Transport, [Parameter(Mandatory)] $Record)
    [Threading.Monitor]::Enter($Transport.RecordGate)
    try {
        if ($Record.recordType -eq 'win-pcinfo.terminal') {
            $Transport.State.TerminalMilliseconds = $Transport.Clock.ElapsedMilliseconds
            $Transport.State.MaximumProgressGapMilliseconds = [Math]::Max($Transport.State.MaximumProgressGapMilliseconds,
                $Transport.Clock.ElapsedMilliseconds - $Transport.State.LastProgressMilliseconds)
        }
        if ($Record.recordType -eq 'win-pcinfo.progress') {
            $elapsed = $Transport.Clock.ElapsedMilliseconds
            if ($Transport.State.FirstProgressMilliseconds -lt 0) { $Transport.State.FirstProgressMilliseconds = $elapsed }
            else {
                $Transport.State.MaximumProgressGapMilliseconds = [Math]::Max(
                    $Transport.State.MaximumProgressGapMilliseconds, $elapsed - $Transport.State.LastProgressMilliseconds)
            }
            $Transport.State.LastProgressMilliseconds = $elapsed
            $Transport.State.ProgressSequence++
            $Record.sequence = $Transport.State.ProgressSequence
        }
        $json = Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Record -Compress -Depth 30
        switch ([string] $Record.recordType) {
            'win-pcinfo.preparation-summary' { $Transport.State.Preparation = $json }
            'win-pcinfo.completion-summary' { $Transport.State.Completion = $json }
            'win-pcinfo.terminal' { $Transport.State.Terminal = $json }
        }
        # Serialized worker and UI activity writers; immutable strings cross the thread boundary. Terminal
        # and approval slots are independent of lossy, bounded activity history.
        if (-not $Transport.Events.TryAdd($json)) {
            [string] $discarded = ''
            $null = $Transport.Events.TryTake([ref] $discarded)
            $null = $Transport.Events.TryAdd($json)
        }
    }
    finally { [Threading.Monitor]::Exit($Transport.RecordGate) }
}

function Request-StatusDeskCancellation {
    param([Parameter(Mandatory)] $Session)
    if ($Session.Transport.Cancellation.IsCancellationRequested) { return }
    $Session.Transport.State.CancellationRequestedMilliseconds = $Session.Transport.Clock.ElapsedMilliseconds
    $Session.Transport.Cancellation.Cancel()
    Send-StatusDeskRecord -Transport $Session.Transport -Record (New-ProgressRecord -Sequence 0 `
        -Phase Cancellation -State Acknowledged -MessageId cancellation.acknowledged -CompletedUnits 0 -TotalUnits 1)
}


function Start-StatusDeskSession {
    param(
        [Parameter(Mandatory)] [string] $ModuleText,
        [Parameter(Mandatory)] [hashtable] $LaunchParameters
    )
    $transport = New-StatusDeskTransport
    $runspace = [RunspaceFactory]::CreateRunspace()
    $runspace.ApartmentState = 'MTA'
    $runspace.ThreadOptions = 'ReuseThread'
    $runspace.Open()
    $worker = [PowerShell]::Create()
    $worker.Runspace = $runspace
    $null = $worker.AddScript({
        param($Definitions, $ParameterJson, $Transport)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        . ([scriptblock]::Create($Definitions))
        $script:StatusDeskTransport = $Transport
        try {
            $parameterObject = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $ParameterJson -Depth 40
            $Parameters = @{}
            foreach ($property in $parameterObject.PSObject.Properties) { $Parameters[$property.Name] = $property.Value }
            $Parameters.ConvertFromJsonCommand = Get-Command ConvertFrom-Json -CommandType Cmdlet
            $Parameters.ConvertToJsonCommand = Get-Command ConvertTo-Json -CommandType Cmdlet
            $Parameters.TestJsonCommand = Get-Command Test-Json -CommandType Cmdlet
            $Parameters.Mode = 'Gui'
            $Parameters.AcceptPreparation = $false
            Invoke-WinPCInfoLaunch @Parameters
        }
        catch {
            # Never copy an exception (potentially Restricted) into GUI activity.
            $started = [bool]$Transport.State.CollectionStarted
            $exitCode = if ($started) { 60 } else { 20 }
            Send-StatusDeskRecord -Transport $Transport -Record ([pscustomobject]@{
                recordType='win-pcinfo.terminal'; contractVersion='1.0.0'
                outcome=if($started){'CleanupIncomplete'}else{'NotStarted'}; exitCode=$exitCode
                reasonCode='GUI.WORKER_FAILED'; collectionStarted=$started
                cleanup=[pscustomobject]@{required=$started;verified=(-not $started)}
            })
            $exitCode
        }
    }.ToString()).AddArgument($ModuleText).AddArgument(
        (Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $LaunchParameters -Compress -Depth 40)
    ).AddArgument($transport)
    [pscustomobject]@{
        Transport = $transport; Worker = $worker; Runspace = $runspace
        Pending = $worker.BeginInvoke(); Completed = $false; ExitCode = 20
    }
}

function New-StatusDeskWindow {
    if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw 'The Status desk requires its owning STA thread.'
    }
    Add-Type -AssemblyName PresentationFramework
    [xml] $layout = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="WIN-PCInfo — Status desk" Width="1040" Height="800" MinWidth="760" MinHeight="600" Background="#F3F5F8" FontFamily="Segoe UI" FontSize="14" WindowStartupLocation="CenterScreen">
 <Window.Resources><Style TargetType="Button"><Setter Property="Margin" Value="0,0,10,0"/><Setter Property="Padding" Value="18,10"/><Setter Property="Background" Value="#1765AE"/><Setter Property="Foreground" Value="White"/></Style></Window.Resources>
 <Grid Margin="26"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="160"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
 <StackPanel><TextBlock Text="WIN-PCInfo" Foreground="#1765AE" FontSize="28" FontWeight="SemiBold"/><TextBlock Text="Status desk · Advisory assessment of this Windows device" Margin="0,5,0,20"/></StackPanel>
 <UniformGrid Grid.Row="1" Columns="4" Margin="0,0,0,18">
  <Border Background="White" Padding="12" Margin="0,0,8,0"><StackPanel><TextBlock Text="ASSESSMENT" FontWeight="Bold"/><TextBlock Name="ScopeFact" Text="Comprehensive Local Assessment" TextWrapping="Wrap"/></StackPanel></Border>
  <Border Background="White" Padding="12" Margin="0,0,8,0"><StackPanel><TextBlock Text="AUTHORITY" FontWeight="Bold"/><TextBlock Name="AuthorityFact" Text="Frozen administrator and SYSTEM operations" TextWrapping="Wrap"/></StackPanel></Border>
  <Border Background="White" Padding="12" Margin="0,0,8,0"><StackPanel><TextBlock Text="NETWORK" FontWeight="Bold"/><TextBlock Name="NetworkFact" Text="Preparing" TextWrapping="Wrap"/></StackPanel></Border>
  <Border Background="White" Padding="12"><StackPanel><TextBlock Text="RESULTS" FontWeight="Bold"/><TextBlock Name="OutputFact" Text="Protected for the initiating user" TextWrapping="Wrap"/></StackPanel></Border>
 </UniformGrid>
 <DockPanel Grid.Row="2" Margin="0,0,0,14"><TextBlock Name="Elapsed" DockPanel.Dock="Right" Text="Elapsed 00:00"/><TextBlock Name="Status" Text="Checking preparation…" FontSize="20" FontWeight="SemiBold"/></DockPanel>
 <ScrollViewer Grid.Row="3" VerticalScrollBarVisibility="Auto" Background="White" Padding="16"><TextBlock Name="Details" TextWrapping="Wrap" Text="Checking the installed runtime, frozen definition and local protection. No assessment collection has started."/></ScrollViewer>
 <GroupBox Grid.Row="4" Header="Activity" Margin="0,14,0,14"><ListBox Name="Timeline" Background="White" BorderThickness="0"/></GroupBox>
 <WrapPanel Grid.Row="5"><Button Name="Approve" Content="_Approve and start" IsEnabled="False"/><Button Name="Decline" Content="_Decline"/><Button Name="Cancel" Content="_Cancel assessment" IsEnabled="False"/><Button Name="OpenReport" Content="_Open report" IsEnabled="False"/><Button Name="Recover" Content="_Recover owned residue" Visibility="Collapsed"/><Button Name="Close" Content="C_lose"/></WrapPanel>
 </Grid>
</Window>
'@
    [System.Windows.Markup.XamlReader]::Load([Xml.XmlNodeReader]::new($layout))
}

function Get-StatusDeskPreparationText {
    param([Parameter(Mandatory)] $Summary)
    $plan = $Summary.plan
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('Review this complete frozen plan before approving once.')
    $lines.Add('')
    $lines.Add('Scope: ' + $plan.scope.profileName)
    foreach ($capability in $plan.scope.capabilities) { $lines.Add('  ' + $capability.name + ' (' + $capability.disposition + ')') }
    $lines.Add('')
    $lines.Add('Planned operations and execution context:')
    foreach ($operation in $plan.operations | Where-Object kind -ne 'ReleaseControl') {
        $lines.Add('  ' + $operation.operationId.Replace('-', ' ') + ' · ' + $operation.context + ' · network: ' + $operation.network)
    }
    $lines.Add('Release validation and publication capabilities are separate maintainer gates, not actions on this device.')
    $lines.Add('')
    $lines.Add('Privileges: one frozen administrator boundary; only predefined SYSTEM operations. No later approval expands authority.')
    $lines.Add('Network: ' + $plan.network.behavior + '. No telemetry or authenticated cloud collection.')
    foreach ($request in $plan.network.plannedRequests) { $lines.Add('  ' + $request.protocol + ': ' + $request.purpose) }
    if($plan.network.behavior -eq 'MicrosoftConnectivityEnabled'){
        $lines.Add('  Uses the active Windows resolver and the frozen current-user static proxy or direct route. Changed context stops new requests; automatic PAC/WPAD is unavailable.')
        foreach($endpoint in $plan.microsoftConnectivity.endpoints){
            $lines.Add('  DNS ' + $endpoint.dnsName + '; direct TCP/TLS port ' + $endpoint.port + '; HEAD ' + $endpoint.uri)
        }
        $lines.Add('  At most 12 logical protocol attempts, 5 seconds each within 45 seconds. No redirects, response bodies, credentials, cookies, automatic certificate downloads or retries.')
    }
    $lines.Add('Output destination: ' + $plan.output.destination)
    $lines.Add('Protection: encrypted package for the initiating Windows user/device. No automatic plaintext export.')
    $lines.Add('Additional recipient: ' + $plan.output.recipientProfile.mode)
    if ($plan.output.recipientProfile.mode -ne 'None') {
        $lines.Add('  ' + $plan.output.recipientProfile.label + ' · ' + $plan.output.recipientProfile.protectionLevel)
        $lines.Add('  Confirmed fingerprint: ' + $plan.output.recipientProfile.fingerprint)
    }
    $lines.Add('Dependencies: ' + $plan.dependencies.runtime + '; built-in modules only. No installation or agreements.')
    $lines.Add('Planning estimate: ' + $plan.estimates.durationMinutes + ' minutes; workspace ' + $plan.estimates.workspaceDiskMiB + ' MiB; protected package ' + $plan.estimates.protectedPackageDiskMiB + ' MiB. These are estimates, not a countdown.')
    $lines.Add('Windows feature and device configuration changes: none.')
    $lines.Add('Cleanup: remove owned temporary state and verify absence; retain protected results. Recovery is cleanup only, never collection resume.')
    if ($plan.cleanup.staleRunRecovery.requested) {
        $lines.Add('This invocation requests recovery only. It will inspect registered residue in this destination and end without starting collection. Foreign or ambiguous resources remain untouched.')
    }
    foreach ($limitation in $plan.limitations) { $lines.Add([string]$limitation) }
    if (-not $Summary.readyForApproval) { $lines.Add('Unresolved prerequisites: ' + ($Summary.criticalPrerequisites.unresolved -join ', ')) }
    $lines.Add('')
    $lines.Add('Approval applies only to plan ' + $Summary.planDigest + '.')
    $lines -join "`n"
}

function Show-StatusDeskReport {
    param([Parameter(Mandatory)] [string] $PackagePath, [Parameter(Mandatory)] $Owner)
    $view = Open-EvidenceViewingSession -PackagePath $PackagePath `
        -RequestedArtifact assessment-report.html -ViewingBasePath ([IO.Path]::GetDirectoryName($PackagePath))
    if (-not $view.verified) { return $view }
    $browser = $null
    $viewFailed = $false
    try {
        $window = [System.Windows.Window]::new()
        $window.Title = 'WIN-PCInfo — Restricted offline report'
        $window.Width = 1100; $window.Height = 800; $window.Owner = $Owner
        $browser = [System.Windows.Controls.WebBrowser]::new()
        $window.Content = $browser
        $allowedPath = [IO.Path]::GetFullPath($view.artifactPath)
        $browser.Add_Navigating({
            param($sender, $eventArgs)
            if ($null -ne $eventArgs.Uri -and $eventArgs.Uri.AbsoluteUri -ne 'about:blank' -and
                (-not $eventArgs.Uri.IsFile -or $eventArgs.Uri.LocalPath -cne $allowedPath)) {
                $eventArgs.Cancel = $true
            }
        })
        $browser.Navigate([uri]::new($allowedPath))
        $null = $window.ShowDialog()
    }
    catch { $viewFailed = $true }
    finally {
        if ($null -ne $browser) { $browser.Dispose() }
        $cleanup = Close-EvidenceViewingSession -Session $view
    }
    if ($viewFailed -and $cleanup.verified) {
        return [pscustomobject]@{ state='NotStarted'; verified=$false; cleanupVerified=$true }
    }
    $cleanup
}

function Invoke-StatusDesk {
    param([Parameter(Mandatory)] [string] $ModuleText, [Parameter(Mandatory)] [hashtable] $LaunchParameters,
        [Parameter()] [scriptblock] $ViewReady)
    $window = New-StatusDeskWindow
    $controls = @{}
    foreach ($name in @('ScopeFact','AuthorityFact','NetworkFact','OutputFact','Elapsed','Status',
        'Details','Timeline','Approve','Decline','Cancel','OpenReport','Recover','Close')) { $controls[$name] = $window.FindName($name) }
    $session = Start-StatusDeskSession -ModuleText $ModuleText -LaunchParameters $LaunchParameters
    $state = @{ Preparation=''; Closing=$false; TerminalShown=$false; ViewingCleanupFailed=$false; RecoveryRequested=$false }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromMilliseconds(100)
    # Handlers run synchronously on this STA while ShowDialog keeps this scope
    # alive. A dynamic closure module would lose the generated script's helpers.
    $controls.Approve.Add_Click({
        if ($state.Preparation) {
            $summary = $state.Preparation | ConvertFrom-Json
            Set-StatusDeskDecision -Session $session -Approve $true -PlanDigest $summary.planDigest
            $controls.Approve.IsEnabled=$false; $controls.Decline.IsEnabled=$false; $controls.Cancel.IsEnabled=$true
            $controls.Status.Text='Assessment running'
        }
    })
    $controls.Decline.Add_Click({
        Set-StatusDeskDecision -Session $session -Approve $false -PlanDigest 'declined'
        $controls.Approve.IsEnabled=$false; $controls.Decline.IsEnabled=$false
    })
    $controls.Cancel.Add_Click({ Request-StatusDeskCancellation $session; $controls.Status.Text='Cancelling — stopping owned work and finalizing safely…'; $controls.Cancel.IsEnabled=$false })
    $controls.Close.Add_Click({ $window.Close() })
    $controls.Recover.Add_Click({ $state.RecoveryRequested=$true; $window.Close() })
    $controls.OpenReport.Add_Click({
        $result = Show-StatusDeskReport -PackagePath $session.Transport.State.PackagePath -Owner $window
        if (-not $result.verified) {
            if ($result.state -eq 'CleanupIncomplete') {
                $controls.Status.Text='CleanupIncomplete — report viewing needs attention'
                $controls.Details.Text='The viewing operation did not verify safe closure. Retain the protected package and recovery record for cleanup. Ordinary deletion is not forensic erasure.'
                $state.ViewingCleanupFailed=$true; $session.ExitCode=60
            }
            elseif ($result.state -eq 'IntegrityFailed') {
                $controls.Status.Text='IntegrityFailed — protected report could not be verified'
                $controls.Details.Text='No report was opened. Preserve the protected package; there is no integrity override.'
                $session.ExitCode=50
            }
            else { $controls.Status.Text='Report unavailable — temporary viewing cleanup verified' }
            $controls.OpenReport.IsEnabled=$false
        }
    })
    $window.Add_Closing({
        param($sender, $eventArgs)
        if (-not $session.Completed) {
            $eventArgs.Cancel=$true; $state.Closing=$true
            Request-StatusDeskCancellation $session
            Set-StatusDeskDecision -Session $session -Approve $false -PlanDigest 'closing'
            $controls.Status.Text='Closing — waiting for owned work and cleanup…'
        }
    })
    $timer.Add_Tick({
        $controls.Elapsed.Text='Elapsed ' + $watch.Elapsed.ToString('hh\:mm\:ss')
        if (-not $session.Pending.IsCompleted -and
            $session.Transport.Clock.ElapsedMilliseconds - $session.Transport.State.LastProgressMilliseconds -ge 2500) {
            # This heartbeat proves the controller is responsive while waiting;
            # it never asserts that a blocked source made collection progress.
            Send-StatusDeskRecord -Transport $session.Transport -Record (New-ProgressRecord -Sequence 0 `
                -Phase RunControl -State Heartbeat -MessageId controller.waiting-for-worker -CompletedUnits 0 -TotalUnits 1)
        }
        if ($session.Transport.State.Preparation -and -not $state.Preparation) {
            $state.Preparation=$session.Transport.State.Preparation
            $summary=$state.Preparation | ConvertFrom-Json
            $controls.ScopeFact.Text=$summary.plan.scope.profileName
            $controls.NetworkFact.Text=$summary.plan.network.behavior
            $controls.OutputFact.Text='Encrypted · recipient ' + $summary.plan.output.recipientProfile.mode
            $controls.Details.Text=Get-StatusDeskPreparationText $summary
            if ($summary.plan.cleanup.staleRunRecovery.requested) { $controls.Approve.Content='_Approve recovery only' }
            $controls.Status.Text=if($summary.readyForApproval){'Ready for your approval'}else{'Preparation unavailable'}
            $controls.Approve.IsEnabled=$summary.readyForApproval -and -not $session.Transport.DecisionReady.IsSet
        }
        [string]$json=''
        for ($index=0; $index -lt 32 -and $session.Transport.Events.TryTake([ref]$json); $index++) {
            $record=$json | ConvertFrom-Json
            if ($record.recordType -eq 'win-pcinfo.progress') {
                $null=$controls.Timeline.Items.Add($record.phase + ' · ' + $record.state + ' · ' + $record.messageId)
                if ($controls.Timeline.Items.Count -gt 64) { $controls.Timeline.Items.RemoveAt(0) }
            }
        }
        if ((Complete-StatusDeskSession $session) -and -not $state.TerminalShown) {
            $state.TerminalShown=$true; $watch.Stop()
            $terminal=$session.Transport.State.Terminal | ConvertFrom-Json
            $controls.Status.Text=$terminal.outcome
            $controls.Details.Text='Outcome: ' + $terminal.outcome + "`nReason: " + $terminal.reasonCode + "`nCleanup verified: " + $terminal.cleanup.verified
            $controls.Approve.IsEnabled=$false; $controls.Decline.IsEnabled=$false; $controls.Cancel.IsEnabled=$false
            if ($session.Transport.State.Completion) {
                $summary=$session.Transport.State.Completion | ConvertFrom-Json
                $controls.Details.Text += "`nProtected package: " + $summary.packageAvailability + "`nLocal access: " + $summary.resultSharingGuidance.localAccess + "`nRecipient access: " + $summary.resultSharingGuidance.recipientAccess + "`nResults are Restricted Diagnostic Evidence. Do not publish them."
                $controls.OpenReport.IsEnabled=$terminal.outcome -ne 'IntegrityFailed' -and $summary.packageVerified -and $summary.packageAvailability -eq 'Available' -and [bool]$session.Transport.State.PackagePath
            }
            else { $controls.Details.Text += "`nNo usable package or report is available." }
            if ($terminal.reasonCode -like 'RECOVERY.*' -and -not $terminal.cleanup.verified) {
                $controls.Recover.Visibility='Visible'
                $controls.Details.Text += "`nRecovery inspects only registered residue in the approved destination. Preserve protected packages and recovery records. Foreign or ambiguous paths need deliberate inspection. No collection resumes."
            }
            if ($state.Closing -and $terminal.cleanup.verified) { $window.Close() }
        }
    })
    try {
        if ($null -ne $ViewReady) { & $ViewReady $window $session }
        $timer.Start(); $null=$window.ShowDialog()
    }
    finally {
        $timer.Stop()
        if ($session.Completed) {
            $session.Transport.Cancellation.Dispose(); $session.Transport.DecisionReady.Dispose(); $session.Transport.Events.Dispose()
        }
    }
    if ($state.RecoveryRequested) {
        $nextLaunch = $LaunchParameters.Clone()
        $nextLaunch.Request = $LaunchParameters.Request | ConvertTo-Json -Depth 40 | ConvertFrom-Json -Depth 40
        $nextLaunch.Request.automationChoices.allowStaleRecovery = $true
        return Invoke-StatusDesk -ModuleText $ModuleText -LaunchParameters $nextLaunch -ViewReady $ViewReady
    }
    $session.ExitCode
}

function Set-StatusDeskDecision {
    param([Parameter(Mandatory)] $Session, [Parameter(Mandatory)] [bool] $Approve,
        [Parameter(Mandatory)] [string] $PlanDigest)
    if ($Session.Transport.DecisionReady.IsSet) { return }
    $Session.Transport.State.ApprovedDigest = $PlanDigest
    $Session.Transport.State.Decision = if ($Approve) { 'Accepted' } else { 'Declined' }
    $Session.Transport.DecisionReady.Set()
}

function Complete-StatusDeskSession {
    param([Parameter(Mandatory)] $Session)
    if (-not $Session.Pending.IsCompleted) { return $false }
    if (-not $Session.Completed) {
        try {
            $result = @($Session.Worker.EndInvoke($Session.Pending))
            if ($result.Count -gt 0) { $Session.ExitCode = [int] $result[-1] }
        }
        finally {
            $Session.Worker.Dispose()
            $Session.Runspace.Dispose()
            $Session.Completed = $true
        }
    }
    $true
}
