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
$rootOwned=$false;$driver=$null;$fixtureError=$null
$fixtureCleanupState=@{DriverStopped=$false}
try {
$null=New-Item -ItemType Directory -Path $root -ErrorAction Stop
$rootOwned=$true
Add-Type -AssemblyName PresentationFramework
$driver=[System.Windows.Threading.DispatcherTimer]::new()
$driver.Interval=[TimeSpan]::FromMilliseconds(100)
$state=@{Rejected=$false;Selected=$false;TimedOut=$false}
$watch=[Diagnostics.Stopwatch]::StartNew()
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
    $driver.Stop()
    $malformedPath=Join-Path $root 'malformed.recipient.json'
    [IO.File]::WriteAllText($malformedPath,'{}',[Text.UTF8Encoding]::new($false))
    $pickerObservation=@{Calls=0;Owner=$null}
    function New-CancelledRecipientSelectionPicker {
        $picker=[pscustomobject]@{Filter='';FileName='Unused cancelled destination';Observation=$pickerObservation}
        $picker | Add-Member -MemberType ScriptMethod -Name ShowDialog -Value {
            param($Owner)
            $this.Observation.Calls++;$this.Observation.Owner=$Owner
            $false
        }
        $picker
    }
    $originalDialog=${function:Show-StatusDeskRecipientDialog}
    foreach($case in @(
        @{Name='EmptyProfile';Path='';Fingerprint=$setup.fingerprint;Reason='Provide both fields before confirming.'},
        @{Name='EmptyFingerprint';Path=$setup.profilePath;Fingerprint='';Reason='Provide both fields before confirming.'},
        @{Name='BothEmpty';Path='';Fingerprint='';Reason='Provide both fields before confirming.'},
        @{Name='MissingProfile';Path=(Join-Path $root 'missing.recipient.json');Fingerprint=$setup.fingerprint;Reason='RECIPIENT.PROFILE_INVALID'},
        @{Name='MalformedProfile';Path=$malformedPath;Fingerprint=$setup.fingerprint;Reason='RECIPIENT.PROFILE_INVALID'},
        @{Name='MalformedFingerprint';Path=$setup.profilePath;Fingerprint='invalid';Reason='RECIPIENT.FINGERPRINT_MISMATCH'},
        @{Name='Cancel';Path=$setup.profilePath;Fingerprint=$setup.fingerprint;Reason=''},
        @{Name='NoRecipient';Path=$setup.profilePath;Fingerprint=$setup.fingerprint;Reason=''},
        @{Name='BrowseCancel';Path=$setup.profilePath;Fingerprint=$setup.fingerprint;Reason=''}
    )){
        $caseState=@{Finished=$false;TimedOut=$false;Refused=$false;BrowsePreserved=$false}
        $caseWatch=[Diagnostics.Stopwatch]::StartNew()
        $caseDriver=[System.Windows.Threading.DispatcherTimer]::new()
        $caseDriver.Interval=[TimeSpan]::FromMilliseconds(100)
        $caseDriver.Add_Tick({
            foreach($source in @([System.Windows.PresentationSource]::CurrentSources)){
                $window=$source.RootVisual
                if($window -isnot [System.Windows.Window] -or $window.Title -ne 'WIN-PCInfo — Recipient selection'){continue}
                if($caseWatch.Elapsed.TotalSeconds -gt 20){$caseState.TimedOut=$true;$window.Close();continue}
                $window.FindName('ProfilePath').Text=$case.Path
                $window.FindName('Fingerprint').Text=$case.Fingerprint
                if($case.Reason){
                    $window.FindName('ConfirmRecipient').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                    $caseState.Refused=$window.IsVisible -and $window.FindName('RecipientStatus').Text.Contains($case.Reason)
                }
                if($case.Name -eq 'BrowseCancel'){
                    $window.FindName('Browse').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                    $caseState.BrowsePreserved=$window.FindName('ProfilePath').Text -ceq $case.Path -and $window.FindName('Fingerprint').Text -ceq $case.Fingerprint
                }
                $button=if($case.Name -eq 'NoRecipient'){'NoRecipient'}else{'CancelRecipient'}
                $caseState.Finished=$true
                $window.FindName($button).RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
            }
        }.GetNewClosure())
        try {
            if($case.Name -eq 'BrowseCancel'){
                # Substitute only chooser creation; this fixture proves its cancel
                # callback, not actual native chooser interaction or geometry.
                $dialogText=$originalDialog.ToString()
                $pickerText='[Microsoft.Win32.OpenFileDialog]::new()'
                Assert-Equal $true $dialogText.Contains($pickerText) 'Browse substitution binds the existing selection picker factory'
                . ([scriptblock]::Create('function Show-StatusDeskRecipientDialog {'+$dialogText.Replace($pickerText,'(New-CancelledRecipientSelectionPicker)')+'}'))
            }
            $caseDriver.Start()
            $caseSelection=Show-StatusDeskRecipientDialog -Purpose Selection
            Assert-Equal $false $caseState.TimedOut "$($case.Name) finishes within its original twenty-second dialog deadline"
            Assert-Equal $true $caseState.Finished "$($case.Name) reaches its deliberate dialog action"
            if($case.Reason){Assert-Equal $true $caseState.Refused "$($case.Name) keeps the dialog open with its actual refusal reason"}
            if($case.Name -eq 'NoRecipient'){
                Assert-Equal 'None' $caseSelection.mode 'explicit local-only protection replaces recipient selection'
                Assert-Equal $true ($null -eq $caseSelection.profilePath -and $null -eq $caseSelection.fingerprintConfirmation) 'no-recipient selection carries no profile or fingerprint'
            }else{Assert-Equal $true ($null -eq $caseSelection) "$($case.Name) cancels without replacing the previous choice"}
            if($case.Name -eq 'BrowseCancel'){
                Assert-Equal 1 $pickerObservation.Calls 'Browse cancellation is explicitly observed once'
                Assert-Equal $true ($null -ne $pickerObservation.Owner) 'Browse forwards its dialog owner'
                Assert-Equal $true $caseState.BrowsePreserved 'Browse cancellation preserves both typed inputs'
            }
        }
        finally {
            try {$caseDriver.Stop()}
            catch {
                $stopError=[InvalidOperationException]::new('Recipient selection case timer cleanup remains unverified.',$_.Exception)
                $stopError.Data['OwnedCleanupUnverified']=$true
                throw $stopError
            }
            finally {${function:Show-StatusDeskRecipientDialog}=$originalDialog}
        }
    }
}
catch {$fixtureError=$_}
finally {
    Complete-QualificationHarness -BodyError $fixtureError -Cleanup @(
        {if($null -ne $driver){$driver.Stop()};$fixtureCleanupState.DriverStopped=$true},
        {
            if($rootOwned -and $fixtureCleanupState.DriverStopped -and -not ($null -ne $fixtureError -and (Test-QualificationCleanupUnverified $fixtureError.Exception))){
                $resolved=[IO.Path]::GetFullPath($root)
                $parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)
                if(-not [IO.Path]::GetDirectoryName($resolved).Equals($parent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -cnotmatch '^winpcinfo-selection-ui-[a-f0-9]{32}$'){throw 'Unsafe cleanup.'}
                if([IO.Directory]::Exists($resolved)){
                    if(([IO.File]::GetAttributes($resolved) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Redirected recipient selection fixture.'}
                    [IO.Directory]::Delete($resolved,$true)
                }
                if([IO.Directory]::Exists($resolved)){throw 'Recipient selection fixture cleanup remains incomplete.'}
            }
        }
    )
}
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
Write-Output 'PASS: production recipient selection preserves wrong/valid confirmation, refusal, cancellation, local-only choice and controlled Browse cancellation; actual keyboard/scaling remains separate.'
