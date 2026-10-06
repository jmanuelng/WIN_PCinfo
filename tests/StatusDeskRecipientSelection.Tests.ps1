[CmdletBinding()]
param([switch]$StaChild,
    [string] $CandidatePath = '', [string] $PreparedManifestPath = '', [string] $PreparedManifestSha256 = '')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidateUseError=$null
try {
if(-not $StaChild){
    if (-not $candidateContext.Prepared) {
        $PreparedManifestPath=Join-Path $candidateContext.OwnedDirectory 'prepared-test-candidate.json'
        [IO.File]::WriteAllText($PreparedManifestPath,((New-PreparedTestCandidateManifest -RepositoryRoot $repositoryRoot -CandidatePath $candidateContext.Path) | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
        $PreparedManifestSha256=(Get-FileHash -LiteralPath $PreparedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-STA','-File',$PSCommandPath,'-StaChild',
        '-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
    if($LASTEXITCODE -ne 0){throw 'Recipient selection GUI failed.'};return
}
$candidate=$candidateContext.Path
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
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
