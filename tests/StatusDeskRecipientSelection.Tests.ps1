[CmdletBinding()]
param([switch]$StaChild)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $StaChild){
    & (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -STA -File $PSCommandPath -StaChild
    if($LASTEXITCODE -ne 0){throw 'Recipient selection GUI failed.'};return
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$regions=[regex]::Matches([IO.File]::ReadAllText($candidate),'(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach($region in $regions){. ([scriptblock]::Create($region.Groups[2].Value))}
$root=Join-Path ([IO.Path]::GetTempPath()) ('winpcinfo-selection-ui-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($root)
Add-Type -AssemblyName PresentationFramework
$driver=[System.Windows.Threading.DispatcherTimer]::new()
$driver.Interval=[TimeSpan]::FromMilliseconds(100)
$state=@{Rejected=$false;Selected=$false;TimedOut=$false}
$watch=[Diagnostics.Stopwatch]::StartNew()
try {
    $setup=New-RecipientProfileSetup -Label 'Synthetic selection' -OutputPath (Join-Path $root 'recipient.json') -ConfirmSetup -SyntheticProtectionLevel WindowsUserBound
    $driver.Add_Tick({
        foreach($source in @([System.Windows.PresentationSource]::CurrentSources)) {
            $window=$source.RootVisual
            if($watch.Elapsed.TotalSeconds -gt 20 -and $window -is [System.Windows.Window]){$state.TimedOut=$true;$window.Close();continue}
            if($window -isnot [System.Windows.Window] -or $window.Title -ne 'WIN-PCInfo — Recipient selection'){continue}
            $window.FindName('ProfilePath').Text=$setup.profilePath
            $window.FindName('Fingerprint').Text=if($state.Rejected){$setup.fingerprint}else{'0'*64}
            $window.FindName('ConfirmRecipient').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
            if(-not $state.Rejected){$state.Rejected=$window.FindName('RecipientStatus').Text.Contains('RECIPIENT.FINGERPRINT_MISMATCH')}
            else{$state.Selected=$true}
        }
    }.GetNewClosure())
    $driver.Start()
    $selection=Show-StatusDeskRecipientDialog -Purpose Selection
    Assert-Equal $false $state.TimedOut 'the controlled recipient dialog finishes within its test deadline'
    Assert-Equal $true $state.Rejected 'incorrect fingerprint keeps the selection dialog open'
    Assert-Equal $true $state.Selected 'operator confirms the fingerprint before selection'
    Assert-Equal 'Profile' $selection.mode 'GUI selects exactly one admitted profile'
    Assert-Equal $setup.fingerprint $selection.fingerprintConfirmation 'the confirmed identity enters the subsequent frozen request'
}
finally {
    $driver.Stop()
    $resolved=[IO.Path]::GetFullPath($root)
    if(-not $resolved.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe cleanup.'}
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
}
Write-Output 'PASS: production recipient GUI rejects mismatched confirmation before selecting one profile.'
