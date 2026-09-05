[CmdletBinding()]
param([switch] $StaChild)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (-not $StaChild) {
    & (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -STA -File $PSCommandPath -StaChild
    if ($LASTEXITCODE -ne 0) { throw 'The exact generated Gui entry/decline path failed.' }
    return
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
Add-Type -AssemblyName PresentationFramework
$null=[System.Windows.Window]
$state=@{SawPreparation=$false;Declined=$false;Terminal=$false;Failed=$false}
$watch=[Diagnostics.Stopwatch]::StartNew()
$driver=[System.Windows.Threading.DispatcherTimer]::new()
$driver.Interval=[TimeSpan]::FromMilliseconds(100)
$driver.Add_Tick({
    foreach($source in @([System.Windows.PresentationSource]::CurrentSources)) {
        $window=$source.RootVisual
        if($window -isnot [System.Windows.Window] -or $window.Title -ne 'WIN-PCInfo — Status desk'){continue}
        $window.Opacity=0;$window.ShowInTaskbar=$false
        if($window.FindName('Approve').IsEnabled -and -not $state.Declined){
            $state.SawPreparation=$window.FindName('Details').Text.Contains('Review this complete frozen plan')
            $state.Declined=$true
            $window.FindName('Decline').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
        }
        if($window.FindName('Status').Text -eq 'NotStarted'){
            $state.Terminal=$window.FindName('Details').Text.Contains('PREPARATION.DECLINED') -and -not $window.FindName('OpenReport').IsEnabled
            $window.Close()
        }
        if($watch.Elapsed.TotalSeconds -gt 40){$state.Failed=$true;$window.Close()}
    }
}.GetNewClosure())
try {
    $driver.Start()
    & $candidate -Mode Gui -PreparationFixturePath (Join-Path $PSScriptRoot 'fixtures/preparation-ready.json')
    Assert-Equal 20 $LASTEXITCODE 'Gui decline preserves the generated application exit code'
}
finally {$driver.Stop()}
Assert-Equal $true $state.SawPreparation 'the unchanged generated ApplicationMain loads the production WPF adapter'
Assert-Equal $true $state.Terminal 'the actual generated Gui entry declines with no usable artifacts'
Assert-Equal $false $state.Failed 'the exact generated entry remains responsive'
Write-Output 'PASS: unchanged generated Gui entry displays frozen preparation and declines without collection.'
