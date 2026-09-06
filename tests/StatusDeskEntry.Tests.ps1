[CmdletBinding()]
param([switch] $StaChild, [switch] $Choices)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (-not $StaChild) {
    & (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -STA -File $PSCommandPath -StaChild -Choices:$Choices
    if ($LASTEXITCODE -ne 0) { throw 'The exact generated Gui entry/decline path failed.' }
    return
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
Add-Type -AssemblyName PresentationFramework
$null=[System.Windows.Window]
$entryTest=@{SawPreparation=$false;Declined=$false;Terminal=$false;Failed=$false;Changed=$false;Retried=$false;NewPlan=$false;HelpSeen=$false;HelpOpened=$false;LastStatus='';Reason=''}
$watch=[Diagnostics.Stopwatch]::StartNew()
$driver=[System.Windows.Threading.DispatcherTimer]::new()
$driver.Interval=[TimeSpan]::FromMilliseconds(100)
$dialogDriver=[System.Windows.Threading.DispatcherTimer]::new()
$dialogDriver.Interval=[TimeSpan]::FromMilliseconds(100)
$dialogDriver.Add_Tick({
    foreach($source in @([System.Windows.PresentationSource]::CurrentSources)) {
        $window=$source.RootVisual
        if($window -is [System.Windows.Window] -and $watch.Elapsed.TotalSeconds -gt 40){$entryTest.Failed=$true;$window.Close();continue}
        if($Choices -and $window -is [System.Windows.Window]){
            if($window.Title -eq 'WIN-PCInfo — Assessment choices'){
                $window.FindName('NetworkChoice').SelectedIndex=1
                $window.FindName('ConfirmChoices').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                continue
            }
            if($window.Title -eq 'WIN-PCInfo — Help'){
                $entryTest.HelpSeen=$window.Content.Text.Contains('Choose → Verify')
                $window.Close();continue
            }
        }
    }
}.GetNewClosure())
$driver.Add_Tick({
    foreach($source in @([System.Windows.PresentationSource]::CurrentSources)) {
        $window=$source.RootVisual
        if($window -isnot [System.Windows.Window] -or $window.Title -ne 'WIN-PCInfo — Status desk'){continue}
        $window.Opacity=0;$window.ShowInTaskbar=$false
        $entryTest.LastStatus=$window.FindName('Status').Text
        $entryTest.Reason=([regex]::Match($window.FindName('Details').Text,'Reason: ([A-Z0-9_.]+)')).Value
        if($window.FindName('Approve').IsEnabled -and -not $entryTest.Declined){
            if($Choices -and -not $entryTest.HelpOpened){
                $entryTest.HelpOpened=$true
                $window.FindName('Help').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                return
            }
            if($Choices -and -not $entryTest.Changed){
                $entryTest.Changed=$true
                $window.FindName('ChangeChoices').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                return
            }
            if($Choices){
                $entryTest.NewPlan=$window.FindName('Details').Text.Contains('Network: MicrosoftConnectivityEnabled')
                Assert-Equal $true ([IO.Path]::IsPathFullyQualified($window.FindName('Details').Text.Split("`n").Where({$_ -like 'Output destination:*'})[0].Substring(20))) 'replacement retains a resolved output destination'
            }
            $entryTest.SawPreparation=$window.FindName('Details').Text.Contains('Review this complete frozen plan')
            $entryTest.Declined=$true
            $window.FindName('Decline').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
        }
        if($window.FindName('Status').Text -eq 'NotStarted'){
            $entryTest.Terminal=$window.FindName('Details').Text.Contains('PREPARATION.DECLINED') -and -not $window.FindName('OpenReport').IsEnabled
            if($Choices -and -not $entryTest.Retried){
                $entryTest.Retried=$true;$entryTest.Declined=$false
                $window.FindName('Retry').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                return
            }
            $window.Close()
        }
        if($watch.Elapsed.TotalSeconds -gt 40){$entryTest.Failed=$true;$window.Close()}
    }
}.GetNewClosure())
try {
    $driver.Start();$dialogDriver.Start()
    if($Choices){
        $regions=[regex]::Matches([IO.File]::ReadAllText($candidate),'(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
        foreach($region in $regions){. ([scriptblock]::Create($region.Groups[2].Value))}
        $moduleText=($regions | ForEach-Object {$_.Groups[2].Value}) -join "`n"
        $context=@{IsFixture=$true}
        foreach($name in @('Preparation','Contract','Run','PrivilegedCollection','SystemCollection','EvidenceWorkspace','ProtectedPackage','RecipientSharing','DeviceReadiness','IdentityEnrollment','AdministratorExposure','EffectivePolicy','ResourceDependencies','NetworkTopology','SoftwareInventory','CertificateTrust','MicrosoftConnectivity')){$context[$name+'FixturePath']=''}
        $context.PreparationFixturePath=Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
        [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
        $exitCode=Invoke-StatusDesk -ModuleText $moduleText -LaunchParameters @{
            Request=(Get-GuidedRequest);RuntimeFacts=(Get-ActiveRuntimeFacts -ModuleFacts (Get-BuiltInModuleCompatibilityFacts));ArtifactTrustValid=$true;ValidationContext=[pscustomobject]$context
        } -ViewReady {param($testWindow,$testSession);$entryTest.Session=$testSession}.GetNewClosure()
        $entryTest.Remove('Session')
        Assert-Equal 20 $exitCode 'Gui decline preserves its exit code'
    }else{
        & $candidate -Mode Gui -PreparationFixturePath (Join-Path $PSScriptRoot 'fixtures/preparation-ready.json')
        Assert-Equal 20 $LASTEXITCODE 'Gui decline preserves the generated application exit code'
    }
}
finally {$driver.Stop();$dialogDriver.Stop()}
Assert-Equal $true $entryTest.SawPreparation 'the unchanged generated ApplicationMain loads the production WPF adapter'
Assert-Equal $true $entryTest.Terminal ('the actual generated Gui entry declines with no usable artifacts: '+($entryTest|ConvertTo-Json -Compress))
Assert-Equal $false $entryTest.Failed 'the exact generated entry remains responsive'
if($Choices){
    Assert-Equal $true $entryTest.Changed 'network choices replace the old preparation'
    Assert-Equal $true $entryTest.NewPlan 'both replacement and retry display the changed frozen plan'
    Assert-Equal $true $entryTest.Retried 'declined preparation can start fresh after cleanup'
    Assert-Equal $true $entryTest.HelpSeen 'the real Help button opens passive local guidance'
}
if($Choices){Write-Output 'PASS: generated GUI Help, changed preparation and retry require fresh approval and decline without collection.'}
else{Write-Output 'PASS: unchanged generated Gui entry displays frozen preparation and declines without collection.'}
