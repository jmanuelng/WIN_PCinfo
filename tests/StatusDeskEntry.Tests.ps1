[CmdletBinding()]
param([switch] $StaChild, [switch] $Choices,
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
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-STA','-File',$PSCommandPath,'-StaChild',('-Choices:'+([string][bool]$Choices)),
        '-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
    if ($LASTEXITCODE -ne 0) { throw 'The exact generated Gui entry/decline path failed.' }
    return
}
$candidate=$candidateContext.Path
Add-Type -AssemblyName PresentationFramework
$null=[System.Windows.Window]
$entryTest=@{SawPreparation=$false;Declined=$false;Terminal=$false;Failed=$false;Changed=$false;Retried=$false;NewPlan=$false;HelpSeen=$false;HelpOpened=$false;LastStatus='';Reason=''}
$watch=[Diagnostics.Stopwatch]::StartNew()
$driver=[System.Windows.Threading.DispatcherTimer]::new()
$driver.Interval=[TimeSpan]::FromMilliseconds(100)
$dialogDriver=[System.Windows.Threading.DispatcherTimer]::new()
$dialogDriver.Interval=[TimeSpan]::FromMilliseconds(100)
# SOURCE-ONLY fixture correction: actual helper blocks are captured before dynamic closures.
# The ordinary candidate branch has no ViewReady owner seam and is unchanged.
$entryAssertEqual=${function:Assert-Equal}
$entryCompleteHarness=${function:Complete-QualificationHarness}
$entryWindowOwners=[Collections.Generic.List[object]]::new()
$entryOwnerState=@{CallbackError=$null;BodyError=$null;Unsafe=$false;CloseErrors=[Collections.Generic.List[Exception]]::new();InvocationErrors=[Collections.Generic.List[Exception]]::new()}
$markEntryOwnerUnverified={
    param([Exception]$Failure)
    $entryOwnerState.Unsafe=$true
    $Failure.Data['OwnedCleanupUnverified']=$true
    $Failure.Data['EntryFixtureOwners']=$entryWindowOwners
}.GetNewClosure()
$requestEntryOwnerClose={
    param($Pair)
    # Reference identity, not a title or a global presentation-source sweep.
    if(@($entryWindowOwners|Where-Object {[object]::ReferenceEquals($_,$Pair)}).Count -ne 1){throw 'Entry close requires its registered exact controller pair.'}
    $unattributed=$false
    foreach($modal in @($Pair.Window.OwnedWindows)) {
        if(-not [object]::ReferenceEquals($modal.Owner,$Pair.Window) -or
            -not [object]::ReferenceEquals($modal.Dispatcher,$Pair.Window.Dispatcher)) {
            $failure=[InvalidOperationException]::new('Entry observed an unattributed owned window; preserve it.')
            & $markEntryOwnerUnverified $failure
            $entryOwnerState.CloseErrors.Add($failure)
            $unattributed=$true
            continue
        }
        if(@($Pair.Modals|Where-Object {[object]::ReferenceEquals($_.Window,$modal)}).Count -eq 0){
            $Pair.Modals.Add([pscustomobject]@{Window=$modal;CloseAttempted=$false})
        }
    }
    foreach($modalOwner in $Pair.Modals.ToArray()) {
        if($modalOwner.CloseAttempted -or -not $modalOwner.Window.IsVisible){continue}
        if(-not [object]::ReferenceEquals($modalOwner.Window.Owner,$Pair.Window) -or
            -not [object]::ReferenceEquals($modalOwner.Window.Dispatcher,$Pair.Window.Dispatcher)){
            $failure=[InvalidOperationException]::new('Entry retained modal attribution changed; preserve it.')
            & $markEntryOwnerUnverified $failure
            $entryOwnerState.CloseErrors.Add($failure)
            $unattributed=$true
            continue
        }
        $modalOwner.CloseAttempted=$true
        try {$modalOwner.Window.Close()}
        catch {& $markEntryOwnerUnverified $_.Exception;$entryOwnerState.CloseErrors.Add($_.Exception)}
    }
    if(-not $unattributed -and -not $Pair.CloseRequested -and $Pair.Window.IsVisible) {
        # The product Closing handler requests cancellation/decline; its timer remains active.
        # No repeated close, wait, task disposal or forced termination is added here.
        $Pair.CloseRequested=$true
        try {$Pair.Window.Close()}
        catch {& $markEntryOwnerUnverified $_.Exception;$entryOwnerState.CloseErrors.Add($_.Exception)}
    }
}.GetNewClosure()
$retainEntryCallbackFailure={
    param([Management.Automation.ErrorRecord]$Failure)
    if($null -eq $entryOwnerState.CallbackError){$entryOwnerState.CallbackError=$Failure}
    foreach($pair in $entryWindowOwners.ToArray()) {
        try {& $requestEntryOwnerClose $pair}
        catch {& $markEntryOwnerUnverified $_.Exception;$entryOwnerState.CloseErrors.Add($_.Exception)}
    }
}.GetNewClosure()
if($Choices) {
    $dialogDriver.Add_Tick({
        try {
            if($watch.Elapsed.TotalSeconds -gt 40){
                $entryTest.Failed=$true
                foreach($pair in $entryWindowOwners.ToArray()){& $requestEntryOwnerClose $pair}
                return
            }
            if($null -ne $entryOwnerState.CallbackError){return}
            foreach($pair in $entryWindowOwners.ToArray()) {
                foreach($modal in @($pair.Window.OwnedWindows)) {
                    if(-not [object]::ReferenceEquals($modal.Owner,$pair.Window) -or
                        -not [object]::ReferenceEquals($modal.Dispatcher,$pair.Window.Dispatcher)){throw 'Entry modal attribution differs from its registered controller.'}
                    if(@($pair.Modals|Where-Object {[object]::ReferenceEquals($_.Window,$modal)}).Count -eq 0){
                        $pair.Modals.Add([pscustomobject]@{Window=$modal;CloseAttempted=$false})
                    }
                    if($modal.Title -eq 'WIN-PCInfo — Assessment choices'){
                        $modal.FindName('NetworkChoice').SelectedIndex=1
                        $modal.FindName('ConfirmChoices').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                        continue
                    }
                    if($modal.Title -eq 'WIN-PCInfo — Help'){
                        $entryTest.HelpSeen=$modal.Content.Text.Contains('Choose → Verify')
                        $modal.Close();continue
                    }
                }
            }
        }
        catch {& $retainEntryCallbackFailure $_}
    }.GetNewClosure())
    $driver.Add_Tick({
        try {
            if($watch.Elapsed.TotalSeconds -gt 40){
                $entryTest.Failed=$true
                foreach($pair in $entryWindowOwners.ToArray()){& $requestEntryOwnerClose $pair}
                return
            }
            if($null -ne $entryOwnerState.CallbackError){return}
            foreach($pair in $entryWindowOwners.ToArray()) {
                $window=$pair.Window
                if(-not $window.IsVisible){continue}
                $window.Opacity=0;$window.ShowInTaskbar=$false
                $entryTest.LastStatus=$window.FindName('Status').Text
                $entryTest.Reason=([regex]::Match($window.FindName('Details').Text,'Reason: ([A-Z0-9_.]+)')).Value
                if($window.FindName('Approve').IsEnabled -and -not $entryTest.Declined){
                    if(-not $entryTest.HelpOpened){
                        $entryTest.HelpOpened=$true
                        $window.FindName('Help').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                        return
                    }
                    if(-not $entryTest.Changed){
                        $entryTest.Changed=$true
                        $window.FindName('ChangeChoices').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                        return
                    }
                    $entryTest.NewPlan=$window.FindName('Details').Text.Contains('Network: MicrosoftConnectivityEnabled')
                    & $entryAssertEqual $true ([IO.Path]::IsPathFullyQualified($window.FindName('Details').Text.Split("`n").Where({$_ -like 'Output destination:*'})[0].Substring(20))) 'replacement retains a resolved output destination'
                    $entryTest.SawPreparation=$window.FindName('Details').Text.Contains('Review this complete frozen plan')
                    $entryTest.Declined=$true
                    $window.FindName('Decline').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                }
                if($window.FindName('Status').Text -eq 'NotStarted'){
                    $entryTest.Terminal=$window.FindName('Details').Text.Contains('PREPARATION.DECLINED') -and -not $window.FindName('OpenReport').IsEnabled
                    if(-not $entryTest.Retried){
                        $entryTest.Retried=$true;$entryTest.Declined=$false
                        $window.FindName('Retry').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                        return
                    }
                    $window.Close()
                }
            }
        }
        catch {& $retainEntryCallbackFailure $_}
    }.GetNewClosure())
} else {
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
}
try {
    $driver.Start();$dialogDriver.Start()
    if($Choices){
        $regions=[regex]::Matches([IO.File]::ReadAllText($candidate),'(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
        foreach($region in $regions){. ([scriptblock]::Create($region.Groups[2].Value))}
        $tokens=$null;$errors=$null
        $candidateAst=[Management.Automation.Language.Parser]::ParseFile($candidate,[ref]$tokens,[ref]$errors)
        Assert-Equal 0 $errors.Count 'the actual choice/retry candidate parses'
        $initializers=@($candidateAst.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Initialize-WinPCInfoDefinitions'})
        Assert-Equal 1 $initializers.Count 'choice/retry uses the actual candidate initializer'
        $definitionInitializer=$initializers[0].Body.GetScriptBlock()
        $context=@{IsFixture=$true}
        foreach($name in @('Preparation','Contract','Run','PrivilegedCollection','SystemCollection','EvidenceWorkspace','ProtectedPackage','RecipientSharing','DeviceReadiness','IdentityEnrollment','AdministratorExposure','EffectivePolicy','ResourceDependencies','NetworkTopology','SoftwareInventory','CertificateTrust','MicrosoftConnectivity')){$context[$name+'FixturePath']=''}
        $context.PreparationFixturePath=Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
        [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
        try {
        $exitCode=Invoke-StatusDesk -DefinitionInitializer $definitionInitializer -LaunchParameters @{
            Request=(Get-GuidedRequest);RuntimeFacts=(Get-ActiveRuntimeFacts -ModuleFacts (Get-BuiltInModuleCompatibilityFacts));ArtifactTrustValid=$true;ValidationContext=[pscustomobject]$context
        } -ViewReady {
            param($testWindow,$testSession)
            # Register references first, before validation or any timer callback mutation.
            $pair=[pscustomobject]@{Window=$testWindow;Session=$testSession;CloseRequested=$false;Modals=[Collections.Generic.List[object]]::new()}
            $entryWindowOwners.Add($pair)
            if($null -eq $testWindow -or $null -eq $testSession -or
                @($entryWindowOwners|Where-Object {[object]::ReferenceEquals($_.Window,$testWindow)}).Count -ne 1 -or
                @($entryWindowOwners|Where-Object {[object]::ReferenceEquals($_.Session,$testSession)}).Count -ne 1){
                $failure=[InvalidOperationException]::new('Entry ViewReady must register one exact unique window/session pair.')
                & $markEntryOwnerUnverified $failure
                throw $failure
            }
        }.GetNewClosure()
        }
        catch {& $markEntryOwnerUnverified $_.Exception;$entryOwnerState.InvocationErrors.Add($_.Exception);throw}
        if($null -ne $entryOwnerState.CallbackError){throw $entryOwnerState.CallbackError}
        Assert-Equal 20 $exitCode 'Gui decline preserves its exit code'
    }else{
        & $candidate -Mode Gui -PreparationFixturePath (Join-Path $PSScriptRoot 'fixtures/preparation-ready.json')
        Assert-Equal 20 $LASTEXITCODE 'Gui decline preserves the generated application exit code'
    }
}
catch {
    if(-not $Choices){throw}
    $entryOwnerState.BodyError=if($null -ne $entryOwnerState.CallbackError){$entryOwnerState.CallbackError}else{$_}
}
finally {
    if(-not $Choices){$driver.Stop();$dialogDriver.Stop()}
    else {
        & $entryCompleteHarness -BodyError $entryOwnerState.BodyError -Cleanup @(
            {try{$driver.Stop()}catch{& $markEntryOwnerUnverified $_.Exception;throw}},
            {try{$dialogDriver.Stop()}catch{& $markEntryOwnerUnverified $_.Exception;throw}},
            {
                if($entryOwnerState.InvocationErrors.Count){throw [AggregateException]::new('Entry product invocation ownership remains unverified.',$entryOwnerState.InvocationErrors.ToArray())}
            },
            {
                foreach($pair in $entryWindowOwners.ToArray()) {
                    try{& $requestEntryOwnerClose $pair}
                    catch{& $markEntryOwnerUnverified $_.Exception;$entryOwnerState.CloseErrors.Add($_.Exception)}
                }
                if($entryOwnerState.CloseErrors.Count){
                    $failure=[AggregateException]::new('Entry exact window close remains unverified.',$entryOwnerState.CloseErrors.ToArray())
                    & $markEntryOwnerUnverified $failure
                    throw $failure
                }
            },
            {
                $failures=[Collections.Generic.List[Exception]]::new()
                foreach($pair in $entryWindowOwners.ToArray()) {
                    try {
                        if($pair.Window.IsVisible -or $pair.Window.OwnedWindows.Count -ne 0 -or
                            @($pair.Modals|Where-Object {$_.Window.IsVisible}).Count){throw 'Entry exact controller/modal remains visible.'}
                    } catch {& $markEntryOwnerUnverified $_.Exception;$failures.Add($_.Exception)}
                }
                if($failures.Count){throw [AggregateException]::new('Entry owned window verification failed.',$failures.ToArray())}
            },
            {
                $failures=[Collections.Generic.List[Exception]]::new()
                foreach($pair in $entryWindowOwners.ToArray()) {
                    try {
                        # Verify existing product finalization; never Dispose an incomplete task/session here.
                        $session=$pair.Session
                        if($session.Completed -isnot [bool] -or -not $session.Completed -or
                            ($session.Finalization.WorkerAllocated -and -not $session.Finalization.WorkerDisposed) -or
                            ($session.Finalization.RunspaceAllocated -and -not $session.Finalization.RunspaceDisposed) -or
                            $null -ne $session.Worker -or $null -ne $session.Runspace -or $null -ne $session.Pending -or
                            $null -ne $session.OpeningTask -or $null -ne $session.DefinitionInitializer -or
                            $null -ne $session.ParameterJson){throw 'Entry exact Status desk session finalization remains unverified.'}
                    } catch {& $markEntryOwnerUnverified $_.Exception;$failures.Add($_.Exception)}
                }
                if($failures.Count){throw [AggregateException]::new('Entry owned session verification failed.',$failures.ToArray())}
            },
            {
                if($entryOwnerState.Unsafe){
                    $failure=[InvalidOperationException]::new('Entry fixture ownership uncertainty remains latched.')
                    & $markEntryOwnerUnverified $failure
                    throw $failure
                }
            }
        )
    }
}
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
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
