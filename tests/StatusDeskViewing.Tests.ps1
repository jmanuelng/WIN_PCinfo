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
if (-not $StaChild) {
    if (-not $candidateContext.Prepared) {
        $PreparedManifestPath=Join-Path $candidateContext.OwnedDirectory 'prepared-test-candidate.json'
        [IO.File]::WriteAllText($PreparedManifestPath,((New-PreparedTestCandidateManifest -RepositoryRoot $repositoryRoot -CandidatePath $candidateContext.Path) | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
        $PreparedManifestSha256=(Get-FileHash -LiteralPath $PreparedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-STA','-File',$PSCommandPath,'-StaChild',
        '-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
    if ($LASTEXITCODE -ne 0) { throw 'Generated WPF report viewing failed.' }
    return
}
$candidate=$candidateContext.Path
$regions=[regex]::Matches([IO.File]::ReadAllText($candidate),'(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach($region in $regions){. ([scriptblock]::Create($region.Groups[2].Value))}
$root=Join-Path ([IO.Path]::GetTempPath()) ('winpcinfo-view-ui-'+[guid]::NewGuid().ToString('N'))
$state=@{ExplicitClose=$false;SawView=$false;TimedOut=$false;Unsafe=$false;FixtureCreated=$false;
    Owner=$null;OwnerClosed=$false;OwnerClosedHandler=$null;OwnerHandlerAttempted=$false;OwnerHandlerRemoved=$false;
    Report=$null;ReportClosed=$false;ReportClosedHandler=$null;ReportHandlerAttempted=$false;ReportHandlerRemoved=$false;
    ReportCloseAttempted=$false;Driver=$null;TickHandler=$null;TickRegistrationAttempted=$false;TickHandlerRemoved=$false;
    CallbackError=$null;BodyError=$null;ProductInvocationAttempted=$false;Result=$null;
    CloseErrors=[Collections.Generic.List[Management.Automation.ErrorRecord]]::new()}
$markViewingUnsafe={
    param([Exception]$Failure)
    $state.Unsafe=$true
    $Failure.Data['OwnedCleanupUnverified']=$true
    $Failure.Data['ViewingFixtureOwners']=$state
}.GetNewClosure()
$closeExactReport={
    if($null -eq $state.Report -or $state.ReportClosed -or $state.ReportCloseAttempted){return}
    if(-not [object]::ReferenceEquals($state.Report.Owner,$state.Owner) -or
        -not [object]::ReferenceEquals($state.Report.Dispatcher,$state.Owner.Dispatcher) -or
        $state.Report.OwnedWindows.Count -ne 0){
        $failure=[InvalidOperationException]::new('Exact report attribution changed or an unregistered owned modal remains; preserve owners.')
        & $markViewingUnsafe $failure
        throw $failure
    }
    $state.ReportCloseAttempted=$true
    $state.Report.Close()
}.GetNewClosure()
$watch=[Diagnostics.Stopwatch]::StartNew()
try {
    if([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)){throw 'Report fixture path must be absent before allocation; preserve foreign residue.'}
    $null=[IO.Directory]::CreateDirectory($root)
    if(((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Owned report fixture cannot use a redirected directory.'}
    $state.FixtureCreated=$true
    Add-Type -AssemblyName PresentationFramework
    # Existing File -> STA Case ownership encloses both exact managed windows.
    # This fixture owner is shown once, then hidden; it is not an app screenshot.
    $state.Owner=[System.Windows.Window]::new()
    $state.Owner.Title='WIN-PCInfo controlled report-view fixture owner'
    $state.Owner.Width=1;$state.Owner.Height=1;$state.Owner.ShowInTaskbar=$false
    $state.OwnerClosedHandler=[EventHandler]({$state.OwnerClosed=$true}.GetNewClosure())
    $state.OwnerHandlerAttempted=$true
    $state.Owner.Add_Closed($state.OwnerClosedHandler)
    $state.Owner.Show()
    $state.Owner.Hide()
    $state.Driver=[System.Windows.Threading.DispatcherTimer]::new()
    $state.Driver.Interval=[TimeSpan]::FromMilliseconds(100)
    $state.TickHandler=[EventHandler]({
        if($null -ne $state.CallbackError){return}
        try {
            $owned=@($state.Owner.OwnedWindows)
            if($owned.Count -gt 1){
                $failure=[InvalidOperationException]::new('Controlled report owner acquired more than one unregistered window; preserve owners.')
                & $markViewingUnsafe $failure
                throw $failure
            }
            if($null -eq $state.Report -and $owned.Count -eq 1){
                # Register the exact object before inspecting controls or dispatching Close.
                $state.Report=$owned[0]
                if(-not [object]::ReferenceEquals($state.Report.Owner,$state.Owner) -or
                    -not [object]::ReferenceEquals($state.Report.Dispatcher,$state.Owner.Dispatcher)){
                    $failure=[InvalidOperationException]::new('Controlled report has no exact fixture-owner/dispatcher attribution.')
                    & $markViewingUnsafe $failure
                    throw $failure
                }
                $state.ReportClosedHandler=[EventHandler]({$state.ReportClosed=$true}.GetNewClosure())
                $state.ReportHandlerAttempted=$true
                $state.Report.Add_Closed($state.ReportClosedHandler)
            }
            if($watch.Elapsed.TotalSeconds -gt 20){
                $state.TimedOut=$true
                if($null -eq $state.Report){throw 'Report deadline reached without an exact registered report window.'}
                & $closeExactReport
                return
            }
            if($null -eq $state.Report -or -not $state.Report.IsVisible){return}
            if($owned.Count -ne 1 -or -not [object]::ReferenceEquals($owned[0],$state.Report)){
                $failure=[InvalidOperationException]::new('Controlled owner no longer contains exactly its registered report window.')
                & $markViewingUnsafe $failure
                throw $failure
            }
            if($state.Report.Title -cne 'WIN-PCInfo — Restricted offline report'){throw 'Owned report has the wrong production report title.'}
            $state.SawView=$true
            $button=$state.Report.FindName('CloseViewing')
            if($null -eq $button){throw 'Owned report has no explicit Close viewing action.'}
            $state.ExplicitClose=$true
            $button.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
        }
        catch {
            if($null -eq $state.CallbackError){$state.CallbackError=$_}
            try {& $closeExactReport}
            catch {& $markViewingUnsafe $_.Exception;$state.CloseErrors.Add($_)}
        }
    }.GetNewClosure())
    $state.TickRegistrationAttempted=$true
    $state.Driver.Add_Tick($state.TickHandler)
    $package=New-ProtectedEvidencePackage -DestinationDirectory $root -Artifacts ([ordered]@{
        'assessment-record.json'=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
        'assessment-report.html'=[Text.Encoding]::UTF8.GetBytes('<html><body>Synthetic partial report</body></html>')
    }) -AssessmentContractSetVersion 1.0.0 -Completeness RecoverablePartial
    $state.Driver.Start()
    $state.ProductInvocationAttempted=$true
    $result=Show-StatusDeskReport -PackagePath $package.packagePath -Owner $state.Owner
    $state.Result=$result
    if($null -ne $state.CallbackError){throw $state.CallbackError}
    Assert-Equal $false $state.TimedOut 'the controlled view finishes within its test deadline'
    Assert-Equal $true $state.SawView 'a historical package opens in the production WPF view'
    Assert-Equal $true $state.ExplicitClose 'the report has an explicit Close viewing action'
    Assert-Equal $true $result.verified 'the GUI closes and verifies owned plaintext removal'
    Assert-Equal 0 @([IO.Directory]::EnumerateDirectories($root)).Count 'the GUI leaves no viewing or recovery residue'
}
catch {$state.BodyError=$_}
finally {
    $viewingBodyError=$state.BodyError
    if($null -ne $state.CallbackError){
        $viewingBodyError=$state.CallbackError
        if($null -ne $state.BodyError -and -not [object]::ReferenceEquals($state.CallbackError,$state.BodyError)){
            $failure=[AggregateException]::new('Report callback failed before independent body failure.',[Exception[]]@($state.CallbackError.Exception,$state.BodyError.Exception))
            $failure.Data['OriginalCallbackError']=$state.CallbackError;$failure.Data['OriginalBodyError']=$state.BodyError
            $viewingBodyError=[Management.Automation.ErrorRecord]::new($failure,'OwnedReportCallbackAndBodyFailure',[Management.Automation.ErrorCategory]::InvalidResult,$state)
        }
    }
    Complete-QualificationHarness -BodyError $viewingBodyError -Cleanup @(
        {
            try {if($null -ne $state.Driver){$state.Driver.Stop();if($state.Driver.IsEnabled){throw 'Exact report driver remains enabled.'}}}
            catch {& $markViewingUnsafe $_.Exception;throw}
        },
        {
            try {
                if($state.TickRegistrationAttempted){$state.Driver.Remove_Tick($state.TickHandler)}
                $state.TickHandlerRemoved=$true
            }
            catch {& $markViewingUnsafe $_.Exception;throw}
        },
        {
            try {
                if($state.CloseErrors.Count){throw [AggregateException]::new('Exact report close failed.',[Exception[]]@($state.CloseErrors.ToArray() | ForEach-Object Exception))}
                if($null -ne $state.Report){
                    & $closeExactReport
                    if(-not $state.ReportClosed -or $state.Report.IsVisible){throw 'Exact report Closed event/absence remains unverified.'}
                }
                if($null -ne $state.Owner -and $state.Owner.OwnedWindows.Count -ne 0){throw 'Fixture owner retains unregistered or incomplete owned windows.'}
            }
            catch {& $markViewingUnsafe $_.Exception;throw}
        },
        {
            try {
                if($state.ReportHandlerAttempted){$state.Report.Remove_Closed($state.ReportClosedHandler)}
                $state.ReportHandlerRemoved=$true
            }
            catch {& $markViewingUnsafe $_.Exception;throw}
        },
        {
            try {
                if($null -ne $state.Owner){
                    if($state.Owner.OwnedWindows.Count -ne 0){throw 'Do not close fixture owner with incomplete or unattributed dependent windows.'}
                    if(-not $state.OwnerClosed){$state.Owner.Close()}
                    if(-not $state.OwnerClosed -or $state.Owner.IsVisible){throw 'Exact fixture-owner Closed event/absence remains unverified.'}
                }
            }
            catch {& $markViewingUnsafe $_.Exception;throw}
        },
        {
            try {
                if($state.OwnerHandlerAttempted){$state.Owner.Remove_Closed($state.OwnerClosedHandler)}
                $state.OwnerHandlerRemoved=$true
            }
            catch {& $markViewingUnsafe $_.Exception;throw}
        },
        {
            try {
                if($state.ProductInvocationAttempted -and ($null -eq $state.Result -or -not $state.Result.verified)){
                    throw 'Product report-view plaintext cleanup is not verified; preserve owned fixture.'
                }
                if($state.Unsafe){throw 'Owned report fixture cleanup is unverified; preserve exact owner references and fixture.'}
                if(-not $state.FixtureCreated){
                    if([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)){throw 'Fixture allocation did not complete; preserve unexpected or partially allocated residue.'}
                    return
                }
                $resolved=[IO.Path]::GetFullPath($root)
                $parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
                if(-not $resolved.StartsWith($parent,[StringComparison]::OrdinalIgnoreCase) -or
                    [IO.Path]::GetFileName($resolved) -cnotmatch '^winpcinfo-view-ui-[a-f0-9]{32}$'){throw 'Unsafe owned report test cleanup path.'}
                if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
                if([IO.Directory]::Exists($resolved)){throw 'Exact report fixture remains after cleanup.'}
            }
            catch {& $markViewingUnsafe $_.Exception;throw}
        }
    )
}
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
Write-Output 'PASS: generated WPF report exposes explicit close and verifies plaintext cleanup.'
