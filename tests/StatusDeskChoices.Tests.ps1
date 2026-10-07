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
if (-not $candidateContext.Prepared) {
    $PreparedManifestPath=Join-Path $candidateContext.OwnedDirectory 'prepared-test-candidate.json'
    [IO.File]::WriteAllText($PreparedManifestPath,((New-PreparedTestCandidateManifest -RepositoryRoot $repositoryRoot -CandidatePath $candidateContext.Path) | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    $PreparedManifestSha256=(Get-FileHash -LiteralPath $PreparedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
if(-not $StaChild){
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-STA','-File',$PSCommandPath,'-StaChild',
        '-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
    if($LASTEXITCODE -ne 0){throw 'Status desk choices failed.'};return
}
$candidate=$candidateContext.Path
$regions=[regex]::Matches([IO.File]::ReadAllText($candidate),'(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach($region in $regions){. ([scriptblock]::Create($region.Groups[2].Value))}
$window=New-StatusDeskWindow
foreach($name in @('ChangeChoices','Retry','Help','About')){
    Assert-Equal $true ($null -ne $window.FindName($name)) "$name is discoverable without console input"
}
Assert-Equal $false $window.FindName('Retry').IsEnabled 'retry cannot interrupt active preparation'
# #132 accepted Status desk structure, checked on the existing constructed WPF tree.
# These layout assertions supplement the original workload; they are not client acceptance.
$window.Content.Measure([System.Windows.Size]::new($window.Width,$window.Height))
$window.Content.Arrange([System.Windows.Rect]::new(0,0,$window.Width,$window.Height))
$approvalControl=$window.FindName('Approve')
$detailsControl=$window.FindName('Details')
$timelineControl=$window.FindName('Timeline')
$openControl=$window.FindName('OpenReport')
$saveControl=$window.FindName('SaveHtml')
$approvalOrigin=$approvalControl.TranslatePoint([System.Windows.Point]::new(0,0),$window.Content)
$detailsOrigin=$detailsControl.TranslatePoint([System.Windows.Point]::new(0,0),$window.Content)
$timelineOrigin=$timelineControl.TranslatePoint([System.Windows.Point]::new(0,0),$window.Content)
$openOrigin=$openControl.TranslatePoint([System.Windows.Point]::new(0,0),$window.Content)
Assert-Equal $true ([object]::ReferenceEquals($approvalControl.Parent,$window.FindName('Status').Parent)) 'run controls and exposed state share the accepted left rail'
Assert-Equal $true ($approvalOrigin.X+$approvalControl.ActualWidth -le $detailsOrigin.X) 'run controls are left of the main preparation and activity workspace'
Assert-Equal $true ([object]::ReferenceEquals($openControl.Parent.Parent.Parent.Parent,$timelineControl.Parent.Parent)) 'report actions are adjacent to results in the same main workspace'
Assert-Equal $true ($openOrigin.Y -ge $timelineOrigin.Y+$timelineControl.ActualHeight) 'report actions follow the main event timeline'
Assert-Equal $true ($openControl.Background.Color.ToString() -eq '#FF1765AE' -and $saveControl.Background.Color -ne $openControl.Background.Color) 'Open report is the primary blue action and private HTML saving is secondary'
Assert-Equal $true ([object]::ReferenceEquals($window.FindName('ScopeFact').Parent.Parent.Parent.Parent,$window.Content)) 'four preparation facts remain outside the scrolling work panes'
$request=Get-AutomationRequest -LiteralPath (Join-Path $PSScriptRoot 'fixtures/automation-request.json') -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
$request.outputDestination=$repositoryRoot
$original=$request | ConvertTo-Json -Depth 40 -Compress
$driver=[System.Windows.Threading.DispatcherTimer]::new()
$driver.Interval=[TimeSpan]::FromMilliseconds(100)
$state=@{Seen=$false;Failed='';Ticks=0}
$driver.Add_Tick({
    try{
        $state.Ticks++
        foreach($source in @([System.Windows.PresentationSource]::CurrentSources)){
            $dialog=$source.RootVisual
            if($dialog -isnot [System.Windows.Window] -or $dialog.Title -ne 'WIN-PCInfo — Assessment choices'){continue}
            if($state.Ticks -gt 50){$state.Failed='Dialog did not finish';$dialog.Close();return}
            $dialog.FindName('NetworkChoice').SelectedIndex=1
            $dialog.FindName('OutputPath').Text=$repositoryRoot
            $state.Seen=$true
            $dialog.FindName('ConfirmChoices').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
        }
    }catch{$state.Failed=$_.Exception.Message}
}.GetNewClosure())
try{$driver.Start();$selection=Show-StatusDeskChoicesDialog -Request $request}
finally{$driver.Stop()}
Assert-Equal '' $state.Failed 'choices finish without a hidden prompt'
Assert-Equal $true $state.Seen 'generated choices dialog was exercised'
Assert-Equal 'MicrosoftConnectivityEnabled' $selection.networkBehavior 'the operator can select the second approved network behavior'
Assert-Equal $repositoryRoot $selection.outputDestination 'the operator can select the private output destination'
Assert-Equal $original ($request | ConvertTo-Json -Depth 40 -Compress) 'choices never mutate the already frozen request'
foreach($surface in @('Help','About')){
    $text=Get-StatusDeskHelpText -Surface $surface
    Assert-Equal $true ($text -match 'Choose.*Verify.*Prepare.*Run.*Interpret.*Troubleshoot.*Share') 'help exposes the complete runway'
    Assert-Equal $true ($text -match 'MIT' -and $text -match 'DCO' -and $text -match 'no SLA') 'passive discovery retains governance'
    Assert-Equal $true ($text -match 'CleanupIncomplete' -and $text -match 'private key') 'help explains recovery and key retention'
}
$heartbeat=Get-StatusDeskActivityText -Record ([pscustomobject]@{phase='RunControl';state='Heartbeat';messageId='controller.waiting-for-worker'})
Assert-Equal $true ($heartbeat -match 'Waiting for owned work' -and $heartbeat -match 'not source progress') 'heartbeat English does not imply collection progress'
Write-Output 'PASS: generated GUI choices and passive help are operable without console input.'
Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEntry.Tests.ps1'),'-Choices',
    '-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
if($LASTEXITCODE -ne 0){throw 'Generated GUI choice replacement and retry failed.'}
# SOURCE-ONLY DRAFT: new observations run only after the entire original workload.
# MoveFocus and routed Cancel below are synthetic inputs, not physical keys.
Assert-TestNativeRoleReady -NativeRole GeneratedApplication -RepositoryRoot $repositoryRoot
function Assert-ChoicesModalCaseBinding {
    param($Context,[string]$RepositoryRoot,[string]$TestPath,[string]$InheritedEvidence,[string]$InheritedAuthority)
    if ($Context.Parent.Pending.nativeRole -cne 'QualificationCase' -or $Context.Parent.Admission.sta -isnot [bool] -or
        -not $Context.Parent.Admission.sta -or $Context.Parent.Admission.testPath -ine $TestPath -or
        $Context.Root.Admission.repositoryRoot -ine $RepositoryRoot) {throw 'Modal evidence requires the exact current owning Choices STA Case.'}
    $expectedEvidence=[IO.Path]::GetFullPath($Context.Root.Admission.suiteEvidenceRoot)
    if ([IO.Path]::GetFullPath($InheritedEvidence) -ine $expectedEvidence) {throw 'Modal evidence differs from the admitted root suite evidence.'}
    $expectedAuthority=[DateTimeOffset]::Parse($Context.Parent.Pending.authorityEnds).AddMilliseconds(-$Context.Parent.Pending.cleanupReserveMs-2000)
    if ($InheritedAuthority -cne $expectedAuthority.ToString('o')) {throw 'Modal body authority differs from the exact current Case reservation.'}
    [pscustomobject]@{EvidenceRoot=$expectedEvidence;AuthorityEnds=$expectedAuthority}
}
if (-not $candidateContext.Prepared -or [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA' -or
    [string]::IsNullOrWhiteSpace($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC)) {
    throw 'Modal observations require the existing prepared owning STA Case.'
}
$probeContext=Get-TestNativeAdmissionContext -RepositoryRoot $repositoryRoot -SelfIdentity (Get-TestNativeSelfIdentity)
$probeBinding=Assert-ChoicesModalCaseBinding -Context $probeContext -RepositoryRoot $repositoryRoot -TestPath $PSCommandPath `
    -InheritedEvidence $env:WINPCINFO_TEST_EVIDENCE -InheritedAuthority $env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC
$probeAuthority=$probeBinding.AuthorityEnds
$probeStart=[DateTimeOffset]::UtcNow
if (($probeAuthority-$probeStart).TotalMilliseconds -lt 150000) {
    throw 'Modal observations require 120 seconds plus 30 seconds of remaining body authority after the original workload.'
}
$probeEnd=$probeStart.AddSeconds(120)
$probeParent=$probeBinding.EvidenceRoot
if ([IO.Path]::GetDirectoryName($probeParent) -ine (Join-Path $repositoryRoot '.test-output') -or
    [IO.Path]::GetFileName($probeParent) -cnotmatch '^suite-[a-f0-9]{32}$' -or
    ((Get-Item -LiteralPath $probeParent -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Modal evidence requires the original private suite evidence boundary.'
}
$probeDirectory=Join-Path $probeParent ('gui-modal-focus-'+[guid]::NewGuid().ToString('N'))
$probeState=@{Owner=$window;Modal=$null;Timer=$null;ModalTimer=$null;TimerHandler=$null;ModalTimerHandler=$null;TimerRegistrationAttempted=$false;ModalTimerRegistrationAttempted=$false;TimerHandlerRemoved=$false;ModalTimerHandlerRemoved=$false;Busy=$false;Next=0;AwaitReturn=$false;
    Expected='';Trigger=$null;ModalEnds=$probeEnd;BodyError=$null;StopError=$null;ModalStopError=$null;
    CloseErrors=[Collections.Generic.List[Exception]]::new();RetentionErrors=[Collections.Generic.List[Exception]]::new();
    EvidenceDirectory=$probeDirectory;DirectoryAllocationAttempted=$false;DirectoryCreated=$false;Frames=0;CaptureBytes=0L;
    Observations=[Collections.Generic.List[object]]::new();InitialObserved=$false;
    Unsafe=$false;Artifacts=[Collections.Generic.List[object]]::new();FinalArtifactInventory=$null}
$probeBodyError=$null
$probeCases=@(
    @{Name='Choices';Title='WIN-PCInfo — Assessment choices';Trigger='ChangeChoices';Initial='NetworkChoice';Cancel='CancelChoices'},
    @{Name='Help';Title='WIN-PCInfo — Help';Trigger='Help';Initial='';Cancel=''},
    @{Name='About';Title='WIN-PCInfo — About';Trigger='About';Initial='';Cancel=''},
    @{Name='Selection';Title='WIN-PCInfo — Recipient selection';Trigger='SelectRecipient';Initial='ProfilePath';Cancel='CancelRecipient'},
    @{Name='Setup';Title='WIN-PCInfo — Separate recipient setup';Trigger='SetupRecipient';Initial='ProfilePath';Cancel='CancelRecipient'}
)
function Set-ChoicesModalOwnershipUnverified {
    param([Exception]$Failure)
    # In-memory admission closure precedes every fallible retention operation.
    $probeState.Unsafe=$true
    $Failure.Data['OwnedCleanupUnverified']=$true
    $Failure.Data['ChoicesModalOwner']=$probeState
}
function Register-ChoicesModalArtifact {
    param([string]$Name,[switch]$Buffer)
    $jsonNames=@('scope.json','observations.json','scope-outcome.json','windows-finalized.json','callback-failure.json')
    $pngNames=@('Owner.png','Choices.png','Help.png','Selection.png','Setup.png')
    if ($Name -cnotin ($jsonNames+$pngNames)) {throw 'Modal artifact name is outside the fixed evidence inventory.'}
    $kind=if($Buffer){'Buffer'}else{'File'}
    if (@($probeState.Artifacts | Where-Object {$_.Name -ceq $Name -and $_.Kind -ceq $kind}).Count) {throw 'Modal artifact intent was already registered; no retry or replacement is permitted.'}
    $full=[IO.Path]::GetFullPath((Join-Path $probeDirectory $Name))
    if ([IO.Path]::GetDirectoryName($full) -ine [IO.Path]::GetFullPath($probeDirectory)) {throw 'Modal artifact escaped the exact owned directory.'}
    $artifact=[pscustomobject]@{Name=$Name;Kind=$kind;Path=$full;Stream=$null;Backing=$null;AllocationAttempted=$false;
        Allocated=$false;CloseAttempted=$false;Disposed=$false;ObservedLength=$null;TerminalError=$null;Owner=$probeState}
    $probeState.Artifacts.Add($artifact)
    $artifact
}
function Close-ChoicesModalArtifact {
    param($Artifact)
    if (-not $Artifact.AllocationAttempted) {return}
    if ($Artifact.Disposed) {return}
    if ($Artifact.CloseAttempted -or $null -eq $Artifact.Stream) {
        $failure=[InvalidOperationException]::new('Modal allocated artifact disposal remains unverified.',$Artifact.TerminalError)
        Set-ChoicesModalOwnershipUnverified -Failure $failure
        throw $failure
    }
    $Artifact.CloseAttempted=$true
    try {$Artifact.Stream.Dispose();$Artifact.Disposed=$true}
    catch {
        $Artifact.TerminalError=$_.Exception
        Set-ChoicesModalOwnershipUnverified -Failure $_.Exception
        throw
    }
}
function Assert-ChoicesModalArtifactsFinalized {
    foreach($artifact in $probeState.Artifacts) {
        if ($artifact.AllocationAttempted -and -not $artifact.Disposed) {
            $failure=[InvalidOperationException]::new('Modal registry retains an unverified allocated owner.',$artifact.TerminalError)
            Set-ChoicesModalOwnershipUnverified -Failure $failure
            throw $failure
        }
    }
    if ($probeState.Unsafe) {
        $failure=[InvalidOperationException]::new('Modal ownership uncertainty remains latched.')
        Set-ChoicesModalOwnershipUnverified -Failure $failure
        throw $failure
    }
}
function Get-ChoicesModalArtifactInventory {
    Assert-ChoicesModalArtifactsFinalized
    $entries=@(Get-ChildItem -LiteralPath $probeDirectory -Force -ErrorAction Stop | Select-Object -First 11 | Sort-Object Name -CaseSensitive)
    $expected=@($probeState.Artifacts | Where-Object {$_.Kind -ceq 'File' -and $_.Allocated})
    $inventory=[Collections.Generic.List[object]]::new()
    foreach($entry in $entries) {
        $holders=@($expected | Where-Object Path -IEQ $entry.FullName)
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $holders.Count -ne 1 -or
            ($holders.Count -eq 1 -and $entry.Name -cne $holders[0].Name)) {
            $failure=[InvalidOperationException]::new('Modal evidence contains an unexpected or redirected entry; no deletion is permitted.')
            Set-ChoicesModalOwnershipUnverified -Failure $failure
            throw $failure
        }
        $inventory.Add([ordered]@{name=$entry.Name;bytes=$entry.Length;
            sha256=(Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();
            partial=($null -eq $holders[0].ObservedLength -or $entry.Length -ne $holders[0].ObservedLength)})
    }
    if ($entries.Count -gt 10 -or $entries.Count -ne $expected.Count) {throw 'Modal retained file inventory is incomplete or excessive; absence is not ownership proof.'}
    $inventory.ToArray()
}
function Write-ChoicesModalObservationRecord {
    param([string]$Name,$Value)
    $artifact=Register-ChoicesModalArtifact -Name $Name
    $writeError=$null
    try {
    if ($Name -ceq 'observations.json') {
        if (@($Value).Count -gt 7) {throw 'Modal observation source cardinality exceeds seven rows.'}
        foreach($row in $Value) {
            if (@($row.syntheticTraversal).Count -gt 48) {throw 'Modal traversal source cardinality exceeds forty-eight moves.'}
            foreach($move in $row.syntheticTraversal) {
                if ($move.type.Length -gt 512 -or $move.name.Length -gt 128) {throw 'Modal traversal source text exceeds its bounded projection.'}
            }
        }
    }
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 10))
    if ($bytes.Length -gt 1MB) {throw 'Modal observation record exceeds its bound.'}
        $artifact.AllocationAttempted=$true
        try {$artifact.Stream=[IO.File]::Open($artifact.Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);$artifact.Allocated=$true}
        catch {$artifact.TerminalError=$_.Exception;Set-ChoicesModalOwnershipUnverified -Failure $_.Exception;throw}
        $artifact.Stream.Write($bytes);$artifact.Stream.Flush($true);$artifact.ObservedLength=$artifact.Stream.Length
    }
    catch {$writeError=$_}
    finally {Complete-QualificationHarness -BodyError $writeError -Cleanup @({Close-ChoicesModalArtifact -Artifact $artifact})}
}
function Write-ChoicesModalPng {
    param([string]$Surface,$Bitmap)
    $name=$Surface+'.png'
    $fileArtifact=Register-ChoicesModalArtifact -Name $name
    $bufferArtifact=Register-ChoicesModalArtifact -Name $name -Buffer
    $bufferError=$null
    try {
        $capacity=20MB-$probeState.CaptureBytes
        if ($capacity -lt 1 -or $probeState.Frames -ge 5) {throw 'Owned WPF capture allowance is exhausted.'}
        $bufferArtifact.AllocationAttempted=$true
        try {
            $bufferArtifact.Backing=[byte[]]::new($capacity)
            $bufferArtifact.Stream=[IO.MemoryStream]::new($bufferArtifact.Backing,0,$capacity,$true,$true)
            $bufferArtifact.Allocated=$true
        }
        catch {$bufferArtifact.TerminalError=$_.Exception;Set-ChoicesModalOwnershipUnverified -Failure $_.Exception;throw}
        # Fixed backing is non-expandable: encoder writes cannot grow past the remaining total.
        $bufferArtifact.Stream.SetLength(0)
        $encoder=[System.Windows.Media.Imaging.PngBitmapEncoder]::new()
        $encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($Bitmap))
        $encoder.Save($bufferArtifact.Stream)
        $bufferArtifact.ObservedLength=$bufferArtifact.Stream.Length
        if ($probeState.CaptureBytes+$bufferArtifact.ObservedLength -gt 20MB) {throw 'Owned WPF capture total exceeds 20 MiB.'}
        $fileError=$null
        try {
            $fileArtifact.AllocationAttempted=$true
            try {$fileArtifact.Stream=[IO.File]::Open($fileArtifact.Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);$fileArtifact.Allocated=$true}
            catch {$fileArtifact.TerminalError=$_.Exception;Set-ChoicesModalOwnershipUnverified -Failure $_.Exception;throw}
            $bufferArtifact.Stream.Position=0;$bufferArtifact.Stream.CopyTo($fileArtifact.Stream)
            $fileArtifact.Stream.Flush($true);$fileArtifact.ObservedLength=$fileArtifact.Stream.Length
        }
        catch {$fileError=$_}
        finally {Complete-QualificationHarness -BodyError $fileError -Cleanup @({Close-ChoicesModalArtifact -Artifact $fileArtifact})}
    }
    catch {$bufferError=$_}
    finally {Complete-QualificationHarness -BodyError $bufferError -Cleanup @({Close-ChoicesModalArtifact -Artifact $bufferArtifact})}
    $probeState.CaptureBytes+=$bufferArtifact.ObservedLength;$probeState.Frames++
}
function Observe-ChoicesOwnedWindow {
    param($ObservedWindow,[string]$Surface,[bool]$Capture)
    $ObservedWindow.UpdateLayout()
    $dpi=[System.Windows.Media.VisualTreeHelper]::GetDpi($ObservedWindow)
    $area=[System.Windows.SystemParameters]::WorkArea
    Assert-Equal $true ($ObservedWindow.IsVisible -and $ObservedWindow.ActualWidth -gt 0 -and $ObservedWindow.ActualHeight -gt 0) "$Surface is genuinely rendered"
    Assert-Equal $true ($ObservedWindow.ActualWidth -le $area.Width+1 -and $ObservedWindow.ActualHeight -le $area.Height+1) "$Surface dimensions fit the actual work area"
    $moves=[Collections.Generic.List[object]]::new()
    foreach ($direction in @('Next','Previous')) {
        for ($step=0;$step -lt 24;$step++) {
            $focus=[System.Windows.Input.Keyboard]::FocusedElement
            if ($null -eq $focus -or $focus -isnot [System.Windows.UIElement]) {throw "$Surface has no traversable UI focus."}
            $moved=$focus.MoveFocus([System.Windows.Input.TraversalRequest]::new([System.Windows.Input.FocusNavigationDirection]::$direction))
            $next=[System.Windows.Input.Keyboard]::FocusedElement
            Assert-Equal $true ($null -ne $next -and $next -is [System.Windows.UIElement] -and $next.IsVisible -and $next.IsEnabled) "$Surface synthetic traversal stays on a visible enabled element"
            Assert-Equal $true ([object]::ReferenceEquals([System.Windows.Window]::GetWindow($next),$ObservedWindow)) "$Surface traversal retains its exact window"
            $bounds=$null
            if ($next -is [System.Windows.FrameworkElement]) {
                $next.BringIntoView();$ObservedWindow.UpdateLayout()
                $rect=$next.TransformToAncestor($ObservedWindow).TransformBounds([System.Windows.Rect]::new(0,0,$next.ActualWidth,$next.ActualHeight))
                $bounds=[ordered]@{x=$rect.X;y=$rect.Y;width=$rect.Width;height=$rect.Height}
                Assert-Equal $true ($rect.Left -ge -1 -and $rect.Top -ge -1 -and $rect.Right -le $ObservedWindow.ActualWidth+1 -and $rect.Bottom -le $ObservedWindow.ActualHeight+1) "$Surface focused element is reachable within its rendered window after synthetic scrolling"
            }
            $moves.Add([ordered]@{direction=$direction;moved=$moved;type=$next.GetType().FullName;
                name=if($next -is [System.Windows.FrameworkElement]){$next.Name}else{''};bounds=$bounds})
        }
    }
    $probeState.Observations.Add([ordered]@{surface=$Surface;actualWidth=$ObservedWindow.ActualWidth;
        actualHeight=$ObservedWindow.ActualHeight;workAreaWidth=$area.Width;workAreaHeight=$area.Height;
        dpiX=$dpi.PixelsPerInchX;dpiY=$dpi.PixelsPerInchY;syntheticTraversal=$moves.ToArray();physicalKeyboardAccepted=$false})
    if ($Capture -and $probeState.Frames -lt 5) {
        $scale=[Math]::Min(1,[Math]::Min(1920/($ObservedWindow.ActualWidth*$dpi.DpiScaleX),1080/($ObservedWindow.ActualHeight*$dpi.DpiScaleY)))
        $width=[Math]::Max(1,[int][Math]::Ceiling($ObservedWindow.ActualWidth*$dpi.DpiScaleX*$scale))
        $height=[Math]::Max(1,[int][Math]::Ceiling($ObservedWindow.ActualHeight*$dpi.DpiScaleY*$scale))
        $bitmap=[System.Windows.Media.Imaging.RenderTargetBitmap]::new($width,$height,$dpi.PixelsPerInchX*$scale,$dpi.PixelsPerInchY*$scale,[System.Windows.Media.PixelFormats]::Pbgra32)
        $bitmap.Render($ObservedWindow)
        Write-ChoicesModalPng -Surface $Surface -Bitmap $bitmap
    }
}
try {
    # A failed/uncertain allocation is retained, never deleted or relabeled owned.
    try {$probeState.DirectoryAllocationAttempted=$true;$null=New-Item -ItemType Directory -Path $probeDirectory -ErrorAction Stop;$probeState.DirectoryCreated=$true}
    catch {Set-ChoicesModalOwnershipUnverified -Failure $_.Exception;$_.Exception.Data['ObservationAllocationPath']=$probeDirectory;throw}
    Write-ChoicesModalObservationRecord -Name 'scope.json' -Value ([ordered]@{
        scope='Controlled owned WPF modals only';candidateSha256=$candidateContext.Sha256;
        preparedManifestSha256=$PreparedManifestSha256;bodyAuthorityEnds=$probeAuthority.ToString('o');
        observationEnds=$probeEnd.ToString('o');cleanupReserveMilliseconds=30000;
        syntheticInputs=@('MoveFocus Next/Previous','Cancel routed Click','long Details and Timeline text','owned-window resize');
        physicalKeyboardAccepted=$false;displayScaleChanged=$false;clientAcceptance=$false})
    $window.FindName('Details').Text=('Synthetic layout-only text; no preparation or collection. '+('Long private fixture detail '*120))
    $null=$window.FindName('Timeline').Items.Add('Synthetic activity text, not source progress.')
    $probeState.Timer=[System.Windows.Threading.DispatcherTimer]::new()
    $probeState.Timer.Interval=[TimeSpan]::FromMilliseconds(100)
    # A distinct timer can observe and cancel while the initiating Tick is inside
    # the product's synchronous ShowDialog nested dispatcher frame.
    $probeState.ModalTimer=[System.Windows.Threading.DispatcherTimer]::new()
    $probeState.ModalTimer.Interval=[TimeSpan]::FromMilliseconds(100)
    $probeState.ModalTimerHandler=[EventHandler]{
        try {
            if ($null -ne $probeState.BodyError) {return}
            if ([DateTimeOffset]::UtcNow -ge $probeEnd) {throw 'Owned modal observation deadline expired.'}
            if ($probeState.Busy) {
                if ([DateTimeOffset]::UtcNow -ge $probeState.ModalEnds) {throw 'Owned modal exceeded its twenty-second deadline.'}
                $owned=@($window.OwnedWindows | Where-Object IsVisible)
                if ($owned.Count -eq 0) {return}
                if ($owned.Count -ne 1 -or $owned[0].Title -cne $probeState.Expected) {
                    $ambiguity=[InvalidOperationException]::new('Owned modal set is ambiguous; no unknown window may be closed.')
                    Set-ChoicesModalOwnershipUnverified -Failure $ambiguity;throw $ambiguity
                }
                $modal=$owned[0];$probeState.Modal=$modal
                Assert-Equal $true ([object]::ReferenceEquals($modal.Owner,$window) -and [object]::ReferenceEquals($modal.Dispatcher,$window.Dispatcher)) 'modal belongs to the exact owning window/STA'
                Assert-Equal $true ($modal.IsActive -and -not $window.IsActive) 'the owned modal holds active focus'
                $case=$probeCases[$probeState.Next]
                if ($case.Initial) {Assert-Equal $true $modal.FindName($case.Initial).IsKeyboardFocusWithin "$($case.Name) initial field receives actual focus"}
                if ($case.Name -eq 'Setup') {
                    Assert-Equal 'Collapsed' $modal.FindName('NoRecipient').Visibility.ToString() 'Setup hides selection-only protection choice'
                    Assert-Equal $true $modal.FindName('Explanation').Text.Contains('non-exportable Current User') 'Setup displays its real protection guidance'
                }
                Observe-ChoicesOwnedWindow -ObservedWindow $modal -Surface $case.Name -Capture ($case.Name -ne 'About')
                if ($case.Cancel) {$modal.FindName($case.Cancel).RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))}
                else {$modal.Close()}
                return
            }
        }
        catch {
            if ($null -eq $probeState.BodyError) {$probeState.BodyError=$_}
            try {Write-ChoicesModalObservationRecord -Name 'callback-failure.json' -Value ([ordered]@{
                type=$probeState.BodyError.Exception.GetType().FullName;case=$probeState.Next;
                cleanupUnverified=(Test-QualificationCleanupUnverified $probeState.BodyError.Exception);
                nativeDispositionPending=$true})} catch {$probeState.RetentionErrors.Add($_.Exception)}
            try {$probeState.Timer.Stop()} catch {$probeState.StopError=$_;Set-ChoicesModalOwnershipUnverified -Failure $_.Exception}
            try {if ($null -ne $probeState.ModalTimer) {$probeState.ModalTimer.Stop()}} catch {$probeState.ModalStopError=$_;Set-ChoicesModalOwnershipUnverified -Failure $_.Exception}
            # Retain ambiguity: never close a modal we could not attribute.
            if (Test-QualificationCleanupUnverified $probeState.BodyError.Exception) {
                [Console]::Out.WriteLine('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED');[Console]::Out.Flush()
            } else {
                try {if ($null -ne $probeState.Modal -and $probeState.Modal.IsVisible) {$probeState.Modal.Close()}} catch {$probeState.CloseErrors.Add($_.Exception);Set-ChoicesModalOwnershipUnverified -Failure $_.Exception}
                try {if ($window.OwnedWindows.Count -eq 0) {$window.Close()}} catch {$probeState.CloseErrors.Add($_.Exception);Set-ChoicesModalOwnershipUnverified -Failure $_.Exception}
            }
        }
    }
    $probeState.ModalTimerRegistrationAttempted=$true
    try {$probeState.ModalTimer.Add_Tick($probeState.ModalTimerHandler)}
    catch {Set-ChoicesModalOwnershipUnverified -Failure $_.Exception;throw}
    $probeState.TimerHandler=[EventHandler]{
        try {
            if ($null -ne $probeState.BodyError) {return}
            if ([DateTimeOffset]::UtcNow -ge $probeEnd) {throw 'Owned modal observation deadline expired.'}
            if ($probeState.Busy) {return}
            if (-not $probeState.InitialObserved) {
                Assert-Equal $true $window.FindName('ChangeChoices').IsKeyboardFocusWithin 'visible Status desk starts on Change choices'
                foreach($name in @('ScopeFact','AuthorityFact','NetworkFact','OutputFact')) {
                    Assert-Equal $true $window.FindName($name).IsVisible 'the four persistent facts are rendered'
                }
                Observe-ChoicesOwnedWindow -ObservedWindow $window -Surface 'Owner' -Capture $true
                if ($null -ne $probeState.BodyError) {return}
                $window.Width=$window.MinWidth;$window.Height=$window.MinHeight
                $window.UpdateLayout()
                if ($null -ne $probeState.BodyError) {return}
                Observe-ChoicesOwnedWindow -ObservedWindow $window -Surface 'OwnerMinimumSize' -Capture $false
                if ($null -ne $probeState.BodyError) {return}
                $probeState.InitialObserved=$true
            }
            if ($probeState.AwaitReturn) {
                Assert-Equal $true ($window.IsActive -and $probeState.Trigger.IsKeyboardFocusWithin) 'closing the real modal restores its originating owner focus'
                $probeState.AwaitReturn=$false
            }
            if ($probeState.Next -ge $probeCases.Count) {$window.Close();return}
            $case=$probeCases[$probeState.Next]
            $probeState.Trigger=$window.FindName($case.Trigger)
            $null=$probeState.Trigger.Focus()
            if ($null -ne $probeState.BodyError) {return}
            Assert-Equal $true $probeState.Trigger.IsKeyboardFocusWithin 'the originating control is focused before opening its modal'
            $probeState.Expected=$case.Title;$probeState.Modal=$null;$probeState.Busy=$true
            $probeState.ModalEnds=[DateTimeOffset]::UtcNow.AddSeconds(20)
            $modalStart=[Diagnostics.Stopwatch]::StartNew()
            switch ($case.Name) {
                'Choices' {$cancelled=Show-StatusDeskChoicesDialog -Owner $window -Request $request;if ($null -ne $probeState.BodyError) {return};Assert-Equal $true ($null -eq $cancelled) 'owned Choices cancel leaves the request unchanged'}
                'Help' {Show-StatusDeskHelp -Owner $window -Surface Help}
                'About' {Show-StatusDeskHelp -Owner $window -Surface About}
                'Selection' {$cancelled=Show-StatusDeskRecipientDialog -Owner $window -Purpose Selection;if ($null -ne $probeState.BodyError) {return};Assert-Equal $true ($null -eq $cancelled) 'owned selection cancels without provider activity'}
                'Setup' {$cancelled=Show-StatusDeskRecipientDialog -Owner $window -Purpose Setup;if ($null -ne $probeState.BodyError) {return};Assert-Equal $true ($null -eq $cancelled) 'owned setup cancels without generating a key'}
            }
            if ($null -ne $probeState.BodyError) {return}
            Assert-Equal $true ($modalStart.Elapsed.TotalSeconds -le 20) 'each controlled modal finishes within twenty seconds'
            Assert-Equal $original ($request | ConvertTo-Json -Depth 40 -Compress) 'owned modal observations never mutate the original request'
            $probeState.Busy=$false;$probeState.AwaitReturn=$true;$probeState.Next++
        }
        catch {
            if ($null -eq $probeState.BodyError) {$probeState.BodyError=$_}
            try {Write-ChoicesModalObservationRecord -Name 'callback-failure.json' -Value ([ordered]@{
                type=$probeState.BodyError.Exception.GetType().FullName;case=$probeState.Next;
                cleanupUnverified=(Test-QualificationCleanupUnverified $probeState.BodyError.Exception);
                nativeDispositionPending=$true})} catch {$probeState.RetentionErrors.Add($_.Exception)}
            try {$probeState.Timer.Stop()} catch {$probeState.StopError=$_;Set-ChoicesModalOwnershipUnverified -Failure $_.Exception}
            try {if ($null -ne $probeState.ModalTimer) {$probeState.ModalTimer.Stop()}} catch {$probeState.ModalStopError=$_;Set-ChoicesModalOwnershipUnverified -Failure $_.Exception}
            # Retain ambiguity: never close a modal we could not attribute.
            if (Test-QualificationCleanupUnverified $probeState.BodyError.Exception) {
                [Console]::Out.WriteLine('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED');[Console]::Out.Flush()
            } else {
                try {if ($null -ne $probeState.Modal -and $probeState.Modal.IsVisible) {$probeState.Modal.Close()}} catch {$probeState.CloseErrors.Add($_.Exception);Set-ChoicesModalOwnershipUnverified -Failure $_.Exception}
                try {if ($window.OwnedWindows.Count -eq 0) {$window.Close()}} catch {$probeState.CloseErrors.Add($_.Exception);Set-ChoicesModalOwnershipUnverified -Failure $_.Exception}
            }
        }
    }
    $probeState.TimerRegistrationAttempted=$true
    try {$probeState.Timer.Add_Tick($probeState.TimerHandler)}
    catch {Set-ChoicesModalOwnershipUnverified -Failure $_.Exception;throw}
    $probeState.ModalTimer.Start()
    $probeState.Timer.Start()
    $null=$window.ShowDialog()
    if ($null -ne $probeState.BodyError) {throw $probeState.BodyError}
    Assert-Equal $probeCases.Count $probeState.Next 'all five owned modal cases completed'
    Assert-Equal $false $probeState.AwaitReturn 'the final modal return was observed before closing the owner'
    Write-ChoicesModalObservationRecord -Name 'observations.json' -Value $probeState.Observations.ToArray()
}
catch {$probeBodyError=$_;if(Test-QualificationCleanupUnverified $_.Exception){Set-ChoicesModalOwnershipUnverified -Failure $_.Exception}}
finally {
    if ($probeState.Unsafe -and $null -eq $probeBodyError) {
        $latched=[InvalidOperationException]::new('Modal ownership uncertainty remains latched before retention.')
        Set-ChoicesModalOwnershipUnverified -Failure $latched
        $probeBodyError=[Management.Automation.ErrorRecord]::new($latched,'ChoicesModalOwnershipUnverified',[Management.Automation.ErrorCategory]::InvalidOperation,$probeState)
    }
    Complete-QualificationHarness -BodyError $probeBodyError -RetainEvidence {
        if ($probeState.DirectoryCreated) {
            Write-ChoicesModalObservationRecord -Name 'scope-outcome.json' -Value ([ordered]@{
                completedCases=$probeState.Next;bodyFailed=($null -ne $probeBodyError);
                bodyType=if($null -ne $probeBodyError){$probeBodyError.Exception.GetType().FullName}else{''};
                observationCount=$probeState.Observations.Count;frames=$probeState.Frames;captureBytes=$probeState.CaptureBytes;
                candidateFinalizationStillPending=$true;nativeLifetimeCertificationStillPending=$true;clientAcceptance=$false})
        }
        if ($probeState.RetentionErrors.Count) {throw [AggregateException]::new('Callback error retention failed.',$probeState.RetentionErrors.ToArray())}
    } -Cleanup @(
        {
            try {
                if ($null -ne $probeState.Timer) {$probeState.Timer.Stop();if ($probeState.Timer.IsEnabled) {throw 'Exact initiating timer remains enabled.'}}
                if ($null -ne $probeState.StopError) {throw $probeState.StopError}
            }
            catch {Set-ChoicesModalOwnershipUnverified -Failure $_.Exception;throw}
        },
        {
            try {
                if ($probeState.TimerRegistrationAttempted) {
                    if ($null -eq $probeState.Timer -or $null -eq $probeState.TimerHandler) {throw 'Exact initiating timer handler ownership is incomplete.'}
                    $probeState.Timer.Remove_Tick($probeState.TimerHandler)
                }
                $probeState.TimerHandlerRemoved=$true;$probeState.TimerHandler=$null
            }
            catch {Set-ChoicesModalOwnershipUnverified -Failure $_.Exception;throw}
        },
        {
            try {
                if ($null -ne $probeState.ModalTimer) {$probeState.ModalTimer.Stop();if ($probeState.ModalTimer.IsEnabled) {throw 'Exact modal observation timer remains enabled.'}}
                if ($null -ne $probeState.ModalStopError) {throw $probeState.ModalStopError}
            }
            catch {Set-ChoicesModalOwnershipUnverified -Failure $_.Exception;throw}
        },
        {
            try {
                if ($probeState.ModalTimerRegistrationAttempted) {
                    if ($null -eq $probeState.ModalTimer -or $null -eq $probeState.ModalTimerHandler) {throw 'Exact modal observation timer handler ownership is incomplete.'}
                    $probeState.ModalTimer.Remove_Tick($probeState.ModalTimerHandler)
                }
                $probeState.ModalTimerHandlerRemoved=$true;$probeState.ModalTimerHandler=$null
            }
            catch {Set-ChoicesModalOwnershipUnverified -Failure $_.Exception;throw}
        },
        {
            if ($probeState.CloseErrors.Count) {
                $failure=[AggregateException]::new('Observed owned window close failures.',$probeState.CloseErrors.ToArray())
                Set-ChoicesModalOwnershipUnverified -Failure $failure
                throw $failure
            }
        },
        {
            $artifactCleanupFailures=[Collections.Generic.List[Exception]]::new()
            foreach($artifact in $probeState.Artifacts) {
                # No failed Dispose is retried. All independently closable owners are attempted.
                if ($artifact.AllocationAttempted -and -not $artifact.Disposed -and -not $artifact.CloseAttempted -and $null -ne $artifact.Stream) {
                    try {Close-ChoicesModalArtifact -Artifact $artifact} catch {$artifactCleanupFailures.Add($_.Exception)}
                }
            }
            try {Assert-ChoicesModalArtifactsFinalized} catch {$artifactCleanupFailures.Add($_.Exception)}
            if ($artifactCleanupFailures.Count) {
                $failure=[AggregateException]::new('Modal registered artifact cleanup remains unverified.',$artifactCleanupFailures.ToArray())
                Set-ChoicesModalOwnershipUnverified -Failure $failure
                throw $failure
            }
        },
        {
            try {
                if ($null -ne $probeState.Modal -and $probeState.Modal.IsVisible) {$probeState.Modal.Close()}
                if ($window.OwnedWindows.Count -ne 0) {throw 'Unattributed owned modal remains; preserve evidence and refuse success.'}
                if ($window.IsVisible) {$window.Close()}
                if ($window.IsVisible -or ($null -ne $probeState.Modal -and $probeState.Modal.IsVisible)) {throw 'Exact controlled windows remain visible.'}
            }
            catch {Set-ChoicesModalOwnershipUnverified -Failure $_.Exception;throw}
        }
    ) -RetainCleanupEvidence {
        if (-not $probeState.TimerHandlerRemoved -or -not $probeState.ModalTimerHandlerRemoved -or
            $null -ne $probeState.TimerHandler -or $null -ne $probeState.ModalTimerHandler -or
            ($null -ne $probeState.Timer -and $probeState.Timer.IsEnabled) -or
            ($null -ne $probeState.ModalTimer -and $probeState.ModalTimer.IsEnabled)) {
            $failure=[InvalidOperationException]::new('Exact modal driver timer finalization remains unverified.')
            Set-ChoicesModalOwnershipUnverified -Failure $failure
            throw $failure
        }
        Assert-ChoicesModalArtifactsFinalized
        $beforeFinalRecord=@(Get-ChoicesModalArtifactInventory)
        Write-ChoicesModalObservationRecord -Name 'windows-finalized.json' -Value ([ordered]@{ownerVisible=$window.IsVisible;
            knownModalVisible=($null -ne $probeState.Modal -and $probeState.Modal.IsVisible);ownedWindows=$window.OwnedWindows.Count;
            previouslyClosedFiles=$beforeFinalRecord;thisRecordDisposalStillPending=$true;
            candidateFinalizationStillPending=$true;nativeLifetimeCertificationStillPending=$true;clientAcceptance=$false})
        Assert-ChoicesModalArtifactsFinalized
        $probeState.FinalArtifactInventory=@(Get-ChoicesModalArtifactInventory)
        Write-Output ('GUI-MODAL-PRIVATE-FILES: '+($probeState.FinalArtifactInventory|ConvertTo-Json -Depth 5 -Compress))
    }
}

}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
