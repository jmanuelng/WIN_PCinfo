# PROTOTYPE — throwaway decision evidence for issue 132. No device collection occurs.
# Three PowerShell WPF variants, switchable in the running window, paired with
# three self-contained synthetic HTML report directions.
[CmdletBinding()]
param(
    [switch] $ValidateOnly,
    [string] $CaptureDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'This WPF prototype runs only on Windows.'
}
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    throw 'Start this prototype in an STA PowerShell process. Use: npm run prototype:gui-report'
}

Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase

$script:prototypeRoot = Split-Path -Parent $PSCommandPath
$script:reports = @{
    A = Join-Path $script:prototypeRoot 'Issue132.SampleReport.Guided.html'
    B = Join-Path $script:prototypeRoot 'Issue132.SampleReport.Desk.html'
    C = Join-Path $script:prototypeRoot 'Issue132.SampleReport.Focus.html'
}
$script:variantMetadata = [ordered]@{
    A = 'Guided journey'
    B = 'Status desk'
    C = 'Focus first'
}
$script:state = [ordered]@{
    Variant = 'A'
    Scenario = 'Gaps'
    Running = $false
    StepIndex = -1
    StepCount = 0
    Phase = 'Preparation'
    Terminal = 'NotStarted'
    Status = 'Ready to review'
    Detail = 'Nothing has run. Review the synthetic scope and choose a scenario.'
    History = [System.Collections.Generic.List[string]]::new()
}
$script:controls = @{}
$script:window = $null
$script:variantHost = $null
$script:variantLabel = $null
$script:timer = [System.Windows.Threading.DispatcherTimer]::new()
$script:timer.Interval = [TimeSpan]::FromMilliseconds(650)

function ConvertFrom-PrototypeXaml {
    param([Parameter(Mandatory)] [string] $Xaml)

    [System.Windows.Markup.XamlReader]::Parse($Xaml)
}

function Get-SimulationSteps {
    param([Parameter(Mandatory)] [ValidateSet('Gaps', 'Complete', 'Failure')] [string] $Scenario)

    switch ($Scenario) {
        'Complete' {
            @(
                [pscustomobject]@{ Phase = 'Preparation'; Status = 'Plan approved'; Detail = 'The synthetic Local Only plan is frozen. No network access is planned.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Collection'; Status = 'Reading Windows baseline'; Detail = 'Simulating bounded device and operating-system observations.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Collection'; Status = 'Checking firmware readiness'; Detail = 'Simulating Secure Boot and TPM observations.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Interpretation'; Status = 'Explaining advisory results'; Detail = 'Separating observations, findings, and recommended follow-up.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Packaging'; Status = 'Protecting results'; Detail = 'Simulating package validation and cleanup.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Terminal'; Status = 'Assessment completed'; Detail = 'Synthetic package verified. Report actions are now available.'; Terminal = 'Completed' }
            )
        }
        'Failure' {
            @(
                [pscustomobject]@{ Phase = 'Preparation'; Status = 'Plan approved'; Detail = 'The synthetic plan is frozen and ready.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Collection'; Status = 'Reading Windows baseline'; Detail = 'Simulating bounded local observations.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Packaging'; Status = 'Package verification failed'; Detail = 'Useful observations cannot override an unverified package.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Terminal'; Status = 'Results unavailable'; Detail = 'Integrity failed safely. No report is offered; review the next-step guidance.'; Terminal = 'IntegrityFailed' }
            )
        }
        default {
            @(
                [pscustomobject]@{ Phase = 'Preparation'; Status = 'Plan approved'; Detail = 'The synthetic Local Only plan is frozen. No network access is planned.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Collection'; Status = 'Reading Windows baseline'; Detail = 'Simulating bounded device and operating-system observations.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Collection'; Status = 'Checking firmware readiness'; Detail = 'Simulating Secure Boot and TPM observations.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Collection'; Status = 'Identity evidence constrained'; Detail = 'A security policy denied one source. This is a visible coverage gap, not a clean result.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Interpretation'; Status = 'Explaining advisory results'; Detail = 'Adding a tenant-side discovery task for the unanswered identity question.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Packaging'; Status = 'Protecting partial results'; Detail = 'Simulating package validation and verified cleanup.'; Terminal = $null }
                [pscustomobject]@{ Phase = 'Terminal'; Status = 'Assessment completed with gaps'; Detail = 'Useful results are ready, with the denied identity evidence called out explicitly.'; Terminal = 'CompletedWithGaps' }
            )
        }
    }
}

function Get-VariantXaml {
    param([Parameter(Mandatory)] [ValidateSet('A', 'B', 'C')] [string] $Variant)

    if ($Variant -eq 'A') {
        return @'
<UserControl xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <Grid Background="#F3F6F8">
    <Grid.ColumnDefinitions><ColumnDefinition Width="220"/><ColumnDefinition Width="*"/><ColumnDefinition Width="300"/></Grid.ColumnDefinitions>
    <Border Grid.Column="0" Background="#15354A" Padding="24">
      <StackPanel>
        <TextBlock Text="YOUR JOURNEY" Foreground="#8FD5CA" FontWeight="Bold" FontSize="12" Margin="0,0,0,24"/>
        <TextBlock Text="1  Review" Foreground="White" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,18"/>
        <TextBlock Text="2  Approve once" Foreground="#BCD0DB" FontSize="16" Margin="0,0,0,18"/>
        <TextBlock Text="3  Assessment" Foreground="#BCD0DB" FontSize="16" Margin="0,0,0,18"/>
        <TextBlock Text="4  Understand" Foreground="#BCD0DB" FontSize="16" Margin="0,0,0,18"/>
        <TextBlock Text="5  Share privately" Foreground="#BCD0DB" FontSize="16"/>
        <Border Background="#244B61" CornerRadius="8" Padding="14" Margin="0,34,0,0">
          <TextBlock TextWrapping="Wrap" Foreground="#DCE8EE" Text="Nothing is changed automatically. You approve one frozen plan before this simulation begins."/>
        </Border>
      </StackPanel>
    </Border>
    <ScrollViewer Grid.Column="1" VerticalScrollBarVisibility="Auto">
      <StackPanel Margin="34,28">
        <TextBlock Text="Prepare this assessment" FontSize="29" FontWeight="SemiBold" Foreground="#102B3A"/>
        <TextBlock Text="A short, guided route for someone running WIN-PCInfo for the first time." Margin="0,7,0,24" Foreground="#4D6472" FontSize="15"/>
        <Border Background="White" CornerRadius="10" Padding="22" BorderBrush="#D8E0E5" BorderThickness="1">
          <StackPanel>
            <TextBlock Text="What this synthetic run covers" FontSize="18" FontWeight="SemiBold"/>
            <TextBlock Margin="0,10,0,0" TextWrapping="Wrap" Text="Device and Windows readiness • Firmware, Secure Boot, and TPM • Identity and enrollment context • Explained findings and next steps"/>
            <Grid Margin="0,20,0,0"><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition/></Grid.ColumnDefinitions>
              <StackPanel Grid.Column="0"><TextBlock Text="Network" Foreground="#60717C"/><TextBlock Text="Local only — zero requests" FontWeight="SemiBold"/></StackPanel>
              <StackPanel Grid.Column="1"><TextBlock Text="Output" Foreground="#60717C"/><TextBlock Text="Protected package + HTML" FontWeight="SemiBold"/></StackPanel>
            </Grid>
          </StackPanel>
        </Border>
        <Border Background="#FFF7E2" CornerRadius="10" Padding="18" Margin="0,16,0,0" BorderBrush="#E9C873" BorderThickness="1">
          <StackPanel><TextBlock Text="Choose a terminal state to inspect" FontWeight="SemiBold"/><ComboBox x:Name="ScenarioSelector" Margin="0,9,0,0" MinHeight="34">
            <ComboBoxItem Tag="Gaps" Content="Completed with gaps — recommended review case"/><ComboBoxItem Tag="Complete" Content="Completed"/><ComboBoxItem Tag="Failure" Content="Integrity failed safely"/>
          </ComboBox></StackPanel>
        </Border>
        <StackPanel Orientation="Horizontal" Margin="0,20,0,0">
          <Button x:Name="RunButton" Content="Approve and start simulation" Padding="18,10" Background="#087F75" Foreground="White" FontWeight="SemiBold" BorderThickness="0"/>
          <Button x:Name="CancelButton" Content="Cancel safely" Padding="18,10" Margin="10,0,0,0"/>
        </StackPanel>
        <ProgressBar x:Name="ProgressBar" Height="8" Margin="0,24,0,0" Maximum="100" Foreground="#087F75"/>
        <TextBlock x:Name="PhaseText" Margin="0,12,0,0" FontWeight="Bold" Foreground="#087F75"/>
        <TextBlock x:Name="StatusText" FontSize="22" FontWeight="SemiBold" Margin="0,4,0,0"/>
        <TextBlock x:Name="DetailText" TextWrapping="Wrap" Foreground="#4D6472" Margin="0,5,0,0"/>
      </StackPanel>
    </ScrollViewer>
    <Border Grid.Column="2" Background="White" Padding="24" BorderBrush="#D8E0E5" BorderThickness="1,0,0,0">
      <StackPanel>
        <TextBlock Text="Run state" FontSize="18" FontWeight="SemiBold"/>
        <TextBlock x:Name="StateText" FontFamily="Consolas" TextWrapping="Wrap" Background="#EEF2F4" Padding="12" Margin="0,10,0,18"/>
        <TextBlock Text="Activity" FontSize="18" FontWeight="SemiBold"/>
        <ListBox x:Name="TimelineList" Height="205" Margin="0,10,0,18" BorderBrush="#D8E0E5"/>
        <TextBlock Text="Result actions" FontSize="18" FontWeight="SemiBold"/>
        <Button x:Name="OpenReportButton" Content="Open report" Padding="12,9" Margin="0,10,0,0" Background="#15354A" Foreground="White"/>
        <Button x:Name="SaveReportButton" Content="Save HTML for my consultant" Padding="12,9" Margin="0,8,0,0"/>
        <TextBlock TextWrapping="Wrap" Foreground="#6C5960" FontSize="12" Margin="0,10,0,0" Text="A real saved HTML report is unencrypted Restricted Diagnostic Evidence and requires a deliberate warning."/>
      </StackPanel>
    </Border>
  </Grid>
</UserControl>
'@
    }

    if ($Variant -eq 'B') {
        return @'
<UserControl xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <Grid Background="#0C1821" Margin="0">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Grid Margin="24,20,24,14"><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition/><ColumnDefinition/><ColumnDefinition/></Grid.ColumnDefinitions>
      <Border Grid.Column="0" Background="#142733" Padding="14" Margin="0,0,8,0"><StackPanel><TextBlock Text="PROFILE" Foreground="#7F9AA9" FontSize="11"/><TextBlock Text="Local readiness" Foreground="White" FontSize="18"/></StackPanel></Border>
      <Border Grid.Column="1" Background="#142733" Padding="14" Margin="0,0,8,0"><StackPanel><TextBlock Text="NETWORK" Foreground="#7F9AA9" FontSize="11"/><TextBlock Text="0 planned requests" Foreground="#64D8CB" FontSize="18"/></StackPanel></Border>
      <Border Grid.Column="2" Background="#142733" Padding="14" Margin="0,0,8,0"><StackPanel><TextBlock Text="APPROVAL" Foreground="#7F9AA9" FontSize="11"/><TextBlock Text="One frozen plan" Foreground="White" FontSize="18"/></StackPanel></Border>
      <Border Grid.Column="3" Background="#142733" Padding="14"><StackPanel><TextBlock Text="OUTPUT" Foreground="#7F9AA9" FontSize="11"/><TextBlock Text="Protected + HTML" Foreground="White" FontSize="18"/></StackPanel></Border>
    </Grid>
    <Grid Grid.Row="1" Margin="24,0,24,16"><Grid.ColumnDefinitions><ColumnDefinition Width="310"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <Border Grid.Column="0" Background="#F0F4F5" Padding="20" Margin="0,0,12,0">
        <StackPanel>
          <TextBlock Text="Run controls" FontSize="23" FontWeight="SemiBold" Foreground="#102B3A"/>
          <TextBlock Text="Inspect happy, partial, and safe-failure states without collecting anything." TextWrapping="Wrap" Foreground="#4D6472" Margin="0,5,0,18"/>
          <TextBlock Text="SIMULATED OUTCOME" FontSize="11" FontWeight="Bold"/>
          <ComboBox x:Name="ScenarioSelector" Margin="0,7,0,16" MinHeight="34"><ComboBoxItem Tag="Gaps" Content="Completed with gaps"/><ComboBoxItem Tag="Complete" Content="Completed"/><ComboBoxItem Tag="Failure" Content="Integrity failed"/></ComboBox>
          <Button x:Name="RunButton" Content="Approve plan / Run" Padding="14,10" Background="#0B897D" Foreground="White" FontWeight="SemiBold"/>
          <Button x:Name="CancelButton" Content="Cancel safely" Padding="14,9" Margin="0,8,0,0"/>
          <Separator Margin="0,18"/>
          <TextBlock Text="EXPOSED PROTOTYPE STATE" FontSize="11" FontWeight="Bold"/>
          <TextBlock x:Name="StateText" FontFamily="Consolas" TextWrapping="Wrap" Margin="0,8,0,0"/>
        </StackPanel>
      </Border>
      <Grid Grid.Column="1"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
        <Border Background="#142733" Padding="20"><StackPanel>
          <TextBlock x:Name="PhaseText" Foreground="#64D8CB" FontWeight="Bold"/>
          <TextBlock x:Name="StatusText" Foreground="White" FontSize="27" FontWeight="SemiBold" Margin="0,3,0,0"/>
          <TextBlock x:Name="DetailText" Foreground="#BBD0DA" TextWrapping="Wrap" Margin="0,5,0,0"/>
          <ProgressBar x:Name="ProgressBar" Height="7" Margin="0,16,0,0" Maximum="100" Foreground="#64D8CB"/>
        </StackPanel></Border>
        <Border Grid.Row="1" Background="#F8FAFA" Padding="20"><StackPanel><TextBlock Text="EVENT TIMELINE" FontSize="12" FontWeight="Bold" Foreground="#506773"/><ListBox x:Name="TimelineList" Margin="0,10,0,0" BorderThickness="0" Background="Transparent"/></StackPanel></Border>
        <Border Grid.Row="2" Background="#E5EBED" Padding="16"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
          <TextBlock Text="Report actions unlock only for usable terminal results." VerticalAlignment="Center" Foreground="#4D6472"/>
          <Button x:Name="OpenReportButton" Grid.Column="1" Content="Open report" Padding="14,8" Margin="8,0" Background="#15354A" Foreground="White"/>
          <Button x:Name="SaveReportButton" Grid.Column="2" Content="Save HTML for consultant" Padding="14,8"/>
        </Grid></Border>
      </Grid>
    </Grid>
    <TextBlock Grid.Row="2" Text="Dense operational direction • optimized for repeat operators and consultant handoff" Foreground="#7F9AA9" Margin="24,0,24,14"/>
  </Grid>
</UserControl>
'@
    }

    @'
<UserControl xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <Grid Background="#FAF7F0">
    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="330"/></Grid.ColumnDefinitions>
    <ScrollViewer Grid.Column="0" VerticalScrollBarVisibility="Auto">
      <StackPanel Margin="54,36" MaxWidth="760">
        <TextBlock Text="One careful step at a time" Foreground="#8A4A32" FontSize="13" FontWeight="Bold"/>
        <TextBlock Text="Understand what will happen before anything begins." FontFamily="Georgia" FontSize="34" TextWrapping="Wrap" Foreground="#2D2926" Margin="0,8,0,12"/>
        <TextBlock Text="This synthetic prototype keeps the immediate decision large and the technical detail nearby, but secondary." TextWrapping="Wrap" FontSize="16" Foreground="#655F59"/>
        <Border Background="White" CornerRadius="4" Padding="26" Margin="0,28,0,0" BorderBrush="#DED7CC" BorderThickness="1">
          <StackPanel>
            <TextBlock x:Name="PhaseText" Text="PREPARATION" Foreground="#8A4A32" FontWeight="Bold" FontSize="12"/>
            <TextBlock x:Name="StatusText" Text="Ready to review" FontFamily="Georgia" FontSize="27" Margin="0,7,0,0"/>
            <TextBlock x:Name="DetailText" TextWrapping="Wrap" Foreground="#655F59" Margin="0,8,0,0" FontSize="15"/>
            <ProgressBar x:Name="ProgressBar" Height="6" Margin="0,22,0,0" Maximum="100" Foreground="#A55B40" Background="#EEE8DF"/>
          </StackPanel>
        </Border>
        <Grid Margin="0,18,0,0"><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition/></Grid.ColumnDefinitions>
          <Border Grid.Column="0" Background="#F2EADF" Padding="18" Margin="0,0,8,0"><StackPanel><TextBlock Text="Local only" FontWeight="SemiBold"/><TextBlock Text="No assessment network requests" TextWrapping="Wrap" Foreground="#655F59"/></StackPanel></Border>
          <Border Grid.Column="1" Background="#F2EADF" Padding="18" Margin="8,0,0,0"><StackPanel><TextBlock Text="You stay in control" FontWeight="SemiBold"/><TextBlock Text="Approve once; cancel safely" TextWrapping="Wrap" Foreground="#655F59"/></StackPanel></Border>
        </Grid>
        <TextBlock Text="Choose a state to explore" Margin="0,24,0,7" FontWeight="SemiBold"/>
        <ComboBox x:Name="ScenarioSelector" MinHeight="35"><ComboBoxItem Tag="Gaps" Content="Useful result with an honest evidence gap"/><ComboBoxItem Tag="Complete" Content="Complete result"/><ComboBoxItem Tag="Failure" Content="Safe integrity failure"/></ComboBox>
        <StackPanel Orientation="Horizontal" Margin="0,18,0,0"><Button x:Name="RunButton" Content="I understand — begin" Padding="20,11" Background="#8A4A32" Foreground="White"/><Button x:Name="CancelButton" Content="Cancel" Padding="20,11" Margin="10,0,0,0"/></StackPanel>
        <StackPanel Orientation="Horizontal" Margin="0,18,0,0"><Button x:Name="OpenReportButton" Content="Read my report" Padding="18,9"/><Button x:Name="SaveReportButton" Content="Prepare private HTML for my consultant" Padding="18,9" Margin="10,0,0,0"/></StackPanel>
      </StackPanel>
    </ScrollViewer>
    <Border Grid.Column="1" Background="#332F2B" Padding="28">
      <StackPanel>
        <TextBlock Text="Why this matters" Foreground="#E8BCA8" FontFamily="Georgia" FontSize="24"/>
        <TextBlock TextWrapping="Wrap" Foreground="#E9E4DE" Margin="0,12,0,20" Text="An unavailable source does not mean the expected condition was observed. The report keeps facts, interpretations, and missing evidence separate."/>
        <TextBlock Text="WHAT THE APP KNOWS" Foreground="#B8ADA3" FontSize="11" FontWeight="Bold"/>
        <TextBlock x:Name="StateText" FontFamily="Consolas" Foreground="White" TextWrapping="Wrap" Margin="0,8,0,22"/>
        <TextBlock Text="WHAT HAS HAPPENED" Foreground="#B8ADA3" FontSize="11" FontWeight="Bold"/>
        <ListBox x:Name="TimelineList" Margin="0,8,0,0" Height="260" Background="#413C37" Foreground="White" BorderThickness="0"/>
        <Border Background="#514943" Padding="14" Margin="0,20,0,0"><TextBlock TextWrapping="Wrap" Foreground="#E9E4DE" FontSize="12" Text="The real report is Restricted Diagnostic Evidence. Opening is temporary; saving is a separate, warned private-handling action."/></Border>
      </StackPanel>
    </Border>
  </Grid>
</UserControl>
'@
}

function Set-ScenarioSelection {
    $selector = $script:controls.ScenarioSelector
    $index = switch ($script:state.Scenario) { 'Complete' { 1 } 'Failure' { 2 } default { 0 } }
    $selector.SelectedIndex = $index
}

function Update-PrototypeView {
    if ($script:controls.Count -eq 0) { return }

    $progress = if ($script:state.StepCount -le 0) { 0 } else {
        [Math]::Min(100, [Math]::Round((($script:state.StepIndex + 1) / $script:state.StepCount) * 100))
    }
    $usable = $script:state.Terminal -in @('Completed', 'CompletedWithGaps')
    $script:controls.PhaseText.Text = $script:state.Phase.ToUpperInvariant()
    $script:controls.StatusText.Text = $script:state.Status
    $script:controls.DetailText.Text = $script:state.Detail
    $script:controls.ProgressBar.Value = $progress
    $script:controls.RunButton.IsEnabled = -not $script:state.Running
    $script:controls.CancelButton.IsEnabled = $script:state.Running
    $script:controls.ScenarioSelector.IsEnabled = -not $script:state.Running
    $script:controls.OpenReportButton.IsEnabled = $usable
    $script:controls.SaveReportButton.IsEnabled = $usable
    $script:controls.StateText.Text = @(
        "variant: $($script:state.Variant) — $($script:variantMetadata[$script:state.Variant])"
        "scenario: $($script:state.Scenario)"
        "phase: $($script:state.Phase)"
        "terminal: $($script:state.Terminal)"
        "reportAvailable: $($usable.ToString().ToLowerInvariant())"
    ) -join [Environment]::NewLine
    $script:controls.TimelineList.Items.Clear()
    foreach ($entry in $script:state.History) {
        [void] $script:controls.TimelineList.Items.Add($entry)
    }
    if ($script:controls.TimelineList.Items.Count -gt 0) {
        $script:controls.TimelineList.ScrollIntoView(
            $script:controls.TimelineList.Items[$script:controls.TimelineList.Items.Count - 1]
        )
    }
}

function Start-SyntheticRun {
    $steps = @(Get-SimulationSteps -Scenario $script:state.Scenario)
    $script:state.History.Clear()
    $script:state.Running = $true
    $script:state.StepIndex = -1
    $script:state.StepCount = $steps.Count
    $script:state.Phase = 'Preparation'
    $script:state.Terminal = 'Running'
    $script:state.Status = 'Freezing the approved plan'
    $script:state.Detail = 'Synthetic events will advance without blocking the WPF UI thread.'
    $script:timer.Tag = $steps
    Update-PrototypeView
    $script:timer.Start()
}

function Stop-SyntheticRun {
    if (-not $script:state.Running) { return }
    $script:timer.Stop()
    $script:state.Running = $false
    $script:state.Phase = 'Terminal'
    $script:state.Terminal = 'Cancelled'
    $script:state.Status = 'Cancelled safely'
    $script:state.Detail = 'No new work will start. Synthetic cleanup is verified and no report is offered.'
    $script:state.History.Add('Terminal · Cancelled safely · cleanup verified')
    Update-PrototypeView
}

function Open-SampleReport {
    if ($script:state.Terminal -notin @('Completed', 'CompletedWithGaps')) { return }
    Start-Process -FilePath $script:reports[$script:state.Variant]
}

function Show-ExportWarningPrototype {
    if ($script:state.Terminal -notin @('Completed', 'CompletedWithGaps')) { return }

    $dialog = ConvertFrom-PrototypeXaml @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="Private HTML export — prototype" Width="560" Height="430" WindowStartupLocation="CenterOwner" ResizeMode="NoResize" Background="#F6F2EC">
  <Grid Margin="28"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <StackPanel><TextBlock Text="Before you save an HTML report" FontSize="25" FontWeight="SemiBold"/><TextBlock Text="RESTRICTED DIAGNOSTIC EVIDENCE" Foreground="#A1332B" FontWeight="Bold" Margin="0,10,0,0"/></StackPanel>
    <StackPanel Grid.Row="1" Margin="0,18,0,0">
      <TextBlock TextWrapping="Wrap" FontSize="15" Text="A real exported report is unencrypted. It may identify a device, person, organization, or network. It is not publicly shareable."/>
      <TextBlock TextWrapping="Wrap" Margin="0,14,0,0" Text="Use a new file in a private local location, transfer it only to an authorized consultant, limit access, and delete it when its purpose ends."/>
      <CheckBox x:Name="Acknowledge" Margin="0,22,0,0" FontWeight="SemiBold" Content="I understand this must be handled as restricted evidence."/>
      <Border Background="#FFF4D6" Padding="12" Margin="0,18,0,0"><TextBlock TextWrapping="Wrap" Text="Prototype behavior: the next button demonstrates the decision point only. No file will be created."/></Border>
    </StackPanel>
    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right"><Button x:Name="Cancel" Content="Go back" Padding="16,9"/><Button x:Name="Continue" Content="Choose private location…" IsEnabled="False" Margin="10,0,0,0" Padding="16,9" Background="#15354A" Foreground="White"/></StackPanel>
  </Grid>
</Window>
'@
    $dialog.Owner = $script:window
    $acknowledge = $dialog.FindName('Acknowledge')
    $continue = $dialog.FindName('Continue')
    $cancel = $dialog.FindName('Cancel')
    $acknowledge.Add_Checked({ $continue.IsEnabled = $true })
    $acknowledge.Add_Unchecked({ $continue.IsEnabled = $false })
    $cancel.Add_Click({ $dialog.DialogResult = $false })
    $continue.Add_Click({
        [void] [System.Windows.MessageBox]::Show(
            $dialog,
            'Prototype only: no HTML file was written. The product flow would now ask for a new private local .html path.',
            'No file created',
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information
        )
        $dialog.DialogResult = $true
    })
    [void] $dialog.ShowDialog()
}

function Register-VariantEvents {
    Set-ScenarioSelection
    $script:controls.ScenarioSelector.Add_SelectionChanged({
        if ($script:state.Running -or $null -eq $script:controls.ScenarioSelector.SelectedItem) { return }
        $script:state.Scenario = [string] $script:controls.ScenarioSelector.SelectedItem.Tag
        $script:state.Terminal = 'NotStarted'
        $script:state.StepIndex = -1
        $script:state.StepCount = 0
        $script:state.Status = 'Ready to review'
        $script:state.Detail = 'Nothing has run. Review the synthetic scope and approve once when ready.'
        $script:state.History.Clear()
        Update-PrototypeView
    })
    $script:controls.RunButton.Add_Click({ Start-SyntheticRun })
    $script:controls.CancelButton.Add_Click({ Stop-SyntheticRun })
    $script:controls.OpenReportButton.Add_Click({ Open-SampleReport })
    $script:controls.SaveReportButton.Add_Click({ Show-ExportWarningPrototype })
}

function Show-Variant {
    param([Parameter(Mandatory)] [ValidateSet('A', 'B', 'C')] [string] $Variant)

    $script:state.Variant = $Variant
    $view = ConvertFrom-PrototypeXaml (Get-VariantXaml -Variant $Variant)
    $requiredNames = @(
        'ScenarioSelector', 'RunButton', 'CancelButton', 'ProgressBar', 'PhaseText',
        'StatusText', 'DetailText', 'TimelineList', 'OpenReportButton',
        'SaveReportButton', 'StateText'
    )
    $script:controls = @{}
    foreach ($name in $requiredNames) {
        $control = $view.FindName($name)
        if ($null -eq $control) { throw "Variant $Variant is missing required control $name." }
        $script:controls[$name] = $control
    }
    Register-VariantEvents
    $script:variantHost.Content = $view
    $script:variantLabel.Text = "$Variant — $($script:variantMetadata[$Variant])"
    Update-PrototypeView
}

function Move-Variant {
    param([Parameter(Mandatory)] [ValidateSet(-1, 1)] [int] $Direction)

    $variants = @('A', 'B', 'C')
    $current = [Array]::IndexOf($variants, $script:state.Variant)
    $next = ($current + $Direction + $variants.Count) % $variants.Count
    Show-Variant -Variant $variants[$next]
}

function Move-SyntheticRunOneStep {
    $steps = @($script:timer.Tag)
    $script:state.StepIndex++
    if ($script:state.StepIndex -ge $steps.Count) {
        $script:timer.Stop()
        $script:state.Running = $false
        Update-PrototypeView
        return
    }
    $step = $steps[$script:state.StepIndex]
    $script:state.Phase = $step.Phase
    $script:state.Status = $step.Status
    $script:state.Detail = $step.Detail
    if ($null -ne $step.Terminal) {
        $script:state.Terminal = $step.Terminal
        $script:state.Running = $false
        $script:timer.Stop()
    }
    $script:state.History.Add("$($step.Phase) · $($step.Status)")
    Update-PrototypeView
}

$script:timer.Add_Tick({ Move-SyntheticRunOneStep })

$script:window = ConvertFrom-PrototypeXaml @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="WIN-PCInfo experience prototype — synthetic only" Width="1220" Height="790" MinWidth="980" MinHeight="680" WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" Background="#F3F6F8">
  <Grid><Grid.RowDefinitions><RowDefinition Height="70"/><RowDefinition Height="*"/><RowDefinition Height="58"/></Grid.RowDefinitions>
    <Border Background="#102B3A" Padding="24,0"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
      <StackPanel VerticalAlignment="Center"><TextBlock Text="WIN-PCInfo" Foreground="White" FontSize="22" FontWeight="SemiBold"/><TextBlock Text="PowerShell GUI + consultant report experience" Foreground="#B9CDD7"/></StackPanel>
      <Border Grid.Column="1" Background="#F4C95D" CornerRadius="13" Padding="12,5" VerticalAlignment="Center"><TextBlock Text="SYNTHETIC PROTOTYPE — NO COLLECTION" FontWeight="Bold" FontSize="11" Foreground="#302813"/></Border>
    </Grid></Border>
    <ContentControl x:Name="VariantHost" Grid.Row="1"/>
    <Border Grid.Row="2" Background="#111A20" Padding="18,8"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/><ColumnDefinition/></Grid.ColumnDefinitions>
      <TextBlock Text="Prototype switcher • ← / →" Foreground="#92A7B1" VerticalAlignment="Center"/>
      <StackPanel Grid.Column="1" Orientation="Horizontal"><Button x:Name="PreviousVariant" Content="←" Width="44" FontSize="18"/><Border Background="#25343D" Padding="20,8" MinWidth="190"><TextBlock x:Name="VariantLabel" Foreground="White" HorizontalAlignment="Center" FontWeight="SemiBold"/></Border><Button x:Name="NextVariant" Content="→" Width="44" FontSize="18"/></StackPanel>
      <TextBlock Grid.Column="2" Text="Esc cancels an active simulation" Foreground="#92A7B1" HorizontalAlignment="Right" VerticalAlignment="Center"/>
    </Grid></Border>
  </Grid>
</Window>
'@
$script:variantHost = $script:window.FindName('VariantHost')
$script:variantLabel = $script:window.FindName('VariantLabel')
$previousVariant = $script:window.FindName('PreviousVariant')
$nextVariant = $script:window.FindName('NextVariant')
$previousVariant.Add_Click({ Move-Variant -Direction -1 })
$nextVariant.Add_Click({ Move-Variant -Direction 1 })
$script:window.Add_PreviewKeyDown({
    param($sender, $eventArgs)
    if ($eventArgs.OriginalSource -is [System.Windows.Controls.TextBox] -or
        $eventArgs.OriginalSource -is [System.Windows.Controls.ComboBox] -or
        $eventArgs.OriginalSource -is [System.Windows.Controls.ComboBoxItem]) {
        return
    }
    switch ($eventArgs.Key) {
        'Left' { Move-Variant -Direction -1; $eventArgs.Handled = $true }
        'Right' { Move-Variant -Direction 1; $eventArgs.Handled = $true }
        'Escape' { Stop-SyntheticRun; $eventArgs.Handled = $true }
    }
})
$script:window.Add_Closed({ $script:timer.Stop() })

Show-Variant -Variant 'A'

if (-not [string]::IsNullOrWhiteSpace($CaptureDirectory)) {
    $captureRoot = [System.IO.Path]::GetFullPath($CaptureDirectory)
    [void] [System.IO.Directory]::CreateDirectory($captureRoot)
    $script:window.Show()
    try {
        foreach ($variant in @('A', 'B', 'C')) {
            Show-Variant -Variant $variant
            $script:window.UpdateLayout()
            $script:window.Dispatcher.Invoke(
                [System.Action] {},
                [System.Windows.Threading.DispatcherPriority]::Render
            )
            $width = [Math]::Max(1, [int] [Math]::Ceiling($script:window.ActualWidth))
            $height = [Math]::Max(1, [int] [Math]::Ceiling($script:window.ActualHeight))
            $bitmap = [System.Windows.Media.Imaging.RenderTargetBitmap]::new(
                $width, $height, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32
            )
            $bitmap.Render($script:window)
            $encoder = [System.Windows.Media.Imaging.PngBitmapEncoder]::new()
            $encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
            $outputPath = Join-Path $captureRoot "issue-132-variant-$variant.png"
            $stream = [System.IO.File]::Open(
                $outputPath,
                [System.IO.FileMode]::Create,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None
            )
            try { $encoder.Save($stream) } finally { $stream.Dispose() }
        }
    }
    finally {
        $script:window.Close()
    }
    [pscustomobject]@{
        captureDirectory = $captureRoot
        variants = @('A', 'B', 'C')
        collection = 'None'
    } | ConvertTo-Json -Depth 2
    exit 0
}

if ($ValidateOnly) {
    foreach ($variant in @('A', 'B', 'C')) {
        Show-Variant -Variant $variant
        if (-not (Test-Path -LiteralPath $script:reports[$variant] -PathType Leaf)) {
            throw "Variant $variant sample report is missing."
        }
    }
    $expectedOutcomes = [ordered]@{
        Gaps = 'CompletedWithGaps'
        Complete = 'Completed'
        Failure = 'IntegrityFailed'
    }
    foreach ($scenario in $expectedOutcomes.Keys) {
        $script:state.Scenario = $scenario
        Start-SyntheticRun
        while ($script:state.Running) { Move-SyntheticRunOneStep }
        if ($script:state.Terminal -ne $expectedOutcomes[$scenario]) {
            throw "Scenario $scenario ended as $($script:state.Terminal), expected $($expectedOutcomes[$scenario])."
        }
    }
    $script:state.Scenario = 'Gaps'
    Start-SyntheticRun
    Move-SyntheticRunOneStep
    Stop-SyntheticRun
    if ($script:state.Terminal -ne 'Cancelled') {
        throw "Cancellation ended as $($script:state.Terminal), expected Cancelled."
    }
    [pscustomobject]@{
        prototype = 'issue-132-gui-report-experience'
        variants = @($script:variantMetadata.Keys)
        reports = @($script:reports.Values | ForEach-Object { Split-Path -Leaf $_ })
        outcomes = @($expectedOutcomes.Values) + @('Cancelled')
        validation = 'Passed'
        collection = 'None'
    } | ConvertTo-Json -Depth 3
    exit 0
}

[void] $script:window.ShowDialog()
