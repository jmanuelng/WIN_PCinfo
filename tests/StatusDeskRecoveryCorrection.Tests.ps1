[CmdletBinding()]
param([switch]$StaChild)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $StaChild){
    & (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -STA -File $PSCommandPath -StaChild
    if($LASTEXITCODE -ne 0){throw 'Generated failure-to-correction workflow failed.'};return
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
$candidate=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$regions=[regex]::Matches([IO.File]::ReadAllText($candidate),'(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach($region in $regions){. ([scriptblock]::Create($region.Groups[2].Value))}
$moduleText=($regions | ForEach-Object {$_.Groups[2].Value}) -join "`n"
# The real generated preparation resolves an unavailable profile. Any accidental
# approval must fail before a live collector can execute.
foreach($name in @('IdentityEnrollmentCollection','ResourceDependenciesCollection','NetworkTopologyCollection',
    'SoftwareInventoryCollection','CertificateTrustCollection','MicrosoftConnectivityCollection',
    'PrivilegedCollectionPlan','SystemCollectionPlan','ApprovedCollectorProcess')){
    $moduleText += "`nfunction Invoke-$name { throw 'Unexpected collection in correction regression.' }"
}
$request=Get-GuidedRequest
$request.recipientSelection=[pscustomobject]@{mode='Profile';profilePath=(Join-Path $repositoryRoot 'artifacts/nonexistent-synthetic-recipient.json');fingerprintConfirmation=('0'*64)}
$original=$request | ConvertTo-Json -Depth 40 -Compress
$context=@{IsFixture=$true}
foreach($name in @('Preparation','Contract','Run','PrivilegedCollection','SystemCollection','EvidenceWorkspace','ProtectedPackage',
    'RecipientSharing','DeviceReadiness','IdentityEnrollment','AdministratorExposure','EffectivePolicy','ResourceDependencies',
    'NetworkTopology','SoftwareInventory','CertificateTrust','MicrosoftConnectivity')){$context[$name+'FixturePath']=''}
$context.PreparationFixturePath=Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
$state=@{Window=$null;Session=$null;Step=0;TerminalTicks=0;Failure='';Invocations=0;FreshApprovals=0;Finished=$false}
$watch=[Diagnostics.Stopwatch]::StartNew()
$driver=[System.Windows.Threading.DispatcherTimer]::new()
$driver.Interval=[TimeSpan]::FromMilliseconds(100)
$dialogs=[System.Windows.Threading.DispatcherTimer]::new()
$dialogs.Interval=[TimeSpan]::FromMilliseconds(100)
$dialogs.Add_Tick({
    foreach($source in @([System.Windows.PresentationSource]::CurrentSources)){
        $dialog=$source.RootVisual
        if($dialog -isnot [System.Windows.Window]){continue}
        if($watch.Elapsed.TotalSeconds -gt 35){$state.Failure='Controlled GUI exceeded its deadline.';$dialog.Close();continue}
        if($dialog.Title -eq 'WIN-PCInfo — Assessment choices'){
            $dialog.FindName('NetworkChoice').SelectedIndex=1
            $dialog.FindName('OutputPath').Text=$repositoryRoot
            $dialog.FindName('ConfirmChoices').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
        }
        if($dialog.Title -eq 'WIN-PCInfo — Recipient selection'){
            $dialog.FindName('NoRecipient').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
        }
    }
}.GetNewClosure())
$driver.Add_Tick({
    try {
        $window=$state.Window
        if($null -eq $window){return}
        Assert-Equal $false $state.Session.Transport.State.CollectionStarted 'correction never carries collection authority'
        if($state.Step -lt 2){
            if(-not $state.Session.Completed -or $window.FindName('Status').Text -ne 'NotStarted'){return}
            # Wait beyond terminal rendering; correction must not depend on a race.
            $state.TerminalTicks++
            if($state.TerminalTicks -lt 5){return}
            Assert-Equal $true ($window.FindName('Details').Text -match 'Unresolved prerequisites:.*recipient-profile-resolved') 'terminal keeps the actionable unavailable-recipient prerequisite'
            Assert-Equal $false $window.FindName('Approve').IsEnabled 'failed preparation cannot be approved'
            foreach($name in @('SelectRecipient','ChangeChoices','Retry')){
                Assert-Equal $true $window.FindName($name).IsEnabled "$name permits deliberate correction only after verified cleanup"
            }
            $action=if($state.Step -eq 0){'ChangeChoices'}else{'SelectRecipient'}
            $state.Step++;$state.TerminalTicks=0
            $window.FindName($action).RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
            return
        }
        if($window.FindName('Approve').IsEnabled){
            $summary=$state.Session.Transport.State.Preparation | ConvertFrom-Json
            Assert-Equal $false $state.Session.Transport.DecisionReady.IsSet 'corrected preparation needs a fresh operator decision'
            Assert-Equal 'MicrosoftConnectivityEnabled' $summary.plan.network.behavior 'corrected network choice reaches the fresh frozen plan'
            Assert-Equal $repositoryRoot $summary.plan.output.requestedDestination 'corrected destination reaches the fresh frozen plan (resolution uses the declared fixture)'
            Assert-Equal $false $summary.plan.cleanup.staleRunRecovery.requested 'correction carries no stale-recovery authority'
            Assert-Equal 'None' $summary.plan.output.recipientProfile.mode 'operator can deliberately remove the unavailable recipient'
            $state.FreshApprovals++
            $window.FindName('Decline').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
            return
        }
        if($state.Session.Completed -and $window.FindName('Status').Text -eq 'NotStarted'){
            if($state.Step -eq 2){
                Assert-Equal $true $window.FindName('ChangeChoices').IsEnabled 'a completed decision does not prevent correcting the next request'
                $state.Step++
                $window.FindName('ChangeChoices').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                return
            }
            $state.Finished=$true;$window.Close()
        }
    } catch {$state.Failure=$_.Exception.Message;$state.Window.Close()}
}.GetNewClosure())
try {
    $driver.Start();$dialogs.Start()
    $exitCode=Invoke-StatusDesk -ModuleText $moduleText -LaunchParameters @{
        Request=$request;RuntimeFacts=(Get-ActiveRuntimeFacts -ModuleFacts (Get-BuiltInModuleCompatibilityFacts));ArtifactTrustValid=$true;ValidationContext=[pscustomobject]$context
    } -ViewReady {
        param($window,$session)
        $window.Opacity=0;$window.ShowInTaskbar=$false
        $state.Window=$window;$state.Session=$session;$state.Invocations++
    }.GetNewClosure()
} finally {$driver.Stop();$dialogs.Stop()}
Assert-Equal '' $state.Failure 'generated failure-to-correction controls finish without hidden input'
Assert-Equal $true $state.Finished 'the corrected request finishes through deliberate decline'
Assert-Equal 4 $state.Invocations 'each correction starts a fresh invocation'
Assert-Equal 2 $state.FreshApprovals 'both corrected preparations require a fresh decision'
Assert-Equal 20 $exitCode 'declining preserves the application exit contract'
Assert-Equal $original ($request | ConvertTo-Json -Depth 40 -Compress) 'correction never mutates the original frozen request'
Write-Output 'PASS: unavailable recipient details survive terminal rendering; network/output and recipient correction require fresh preparation and approval.'
