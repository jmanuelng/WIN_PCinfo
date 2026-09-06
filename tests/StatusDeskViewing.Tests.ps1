[CmdletBinding()]
param([switch]$StaChild)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (-not $StaChild) {
    & (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -STA -File $PSCommandPath -StaChild
    if ($LASTEXITCODE -ne 0) { throw 'Generated WPF report viewing failed.' }
    return
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$regions=[regex]::Matches([IO.File]::ReadAllText($candidate),'(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach($region in $regions){. ([scriptblock]::Create($region.Groups[2].Value))}
$root=Join-Path ([IO.Path]::GetTempPath()) ('winpcinfo-view-ui-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($root)
Add-Type -AssemblyName PresentationFramework
$state=@{ExplicitClose=$false;SawView=$false;TimedOut=$false}
$watch=[Diagnostics.Stopwatch]::StartNew()
$driver=[System.Windows.Threading.DispatcherTimer]::new()
$driver.Interval=[TimeSpan]::FromMilliseconds(100)
$driver.Add_Tick({
    foreach($source in @([System.Windows.PresentationSource]::CurrentSources)) {
        $window=$source.RootVisual
        if($watch.Elapsed.TotalSeconds -gt 20 -and $window -is [System.Windows.Window]){$state.TimedOut=$true;$window.Close();continue}
        if($window -isnot [System.Windows.Window] -or $window.Title -ne 'WIN-PCInfo — Restricted offline report'){continue}
        $state.SawView=$true
        $button=$window.FindName('CloseViewing')
        if($null -ne $button){$state.ExplicitClose=$true;$button.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))}
        else{$window.Close()}
    }
}.GetNewClosure())
try {
    $package=New-ProtectedEvidencePackage -DestinationDirectory $root -Artifacts ([ordered]@{
        'assessment-record.json'=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
        'assessment-report.html'=[Text.Encoding]::UTF8.GetBytes('<html><body>Synthetic partial report</body></html>')
    }) -AssessmentContractSetVersion 1.0.0 -Completeness RecoverablePartial
    $driver.Start()
    $result=Show-StatusDeskReport -PackagePath $package.packagePath
    Assert-Equal $false $state.TimedOut 'the controlled view finishes within its test deadline'
    Assert-Equal $true $state.SawView 'a historical package opens in the production WPF view'
    Assert-Equal $true $state.ExplicitClose 'the report has an explicit Close viewing action'
    Assert-Equal $true $result.verified 'the GUI closes and verifies owned plaintext removal'
    Assert-Equal 0 @([IO.Directory]::EnumerateDirectories($root)).Count 'the GUI leaves no viewing or recovery residue'
}
finally {
    $driver.Stop()
    $resolved=[IO.Path]::GetFullPath($root)
    if(-not $resolved.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe test cleanup.'}
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
}
Write-Output 'PASS: generated WPF report exposes explicit close and verifies plaintext cleanup.'
