[CmdletBinding()]
param([switch]$StaChild, [ValidateSet('RecoveryEarly','RecoveryReady','Viewing','Export')][string]$Scenario='RecoveryEarly')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $StaChild){
    foreach($case in @('RecoveryEarly','RecoveryReady','Viewing','Export')){
        & (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -STA -File $PSCommandPath -StaChild -Scenario $case
        if($LASTEXITCODE -ne 0){throw "Status desk cleanup gate failed: $case"}
    }
    return
}
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$regions=[regex]::Matches([IO.File]::ReadAllText($candidate),'(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
$moduleText=($regions | ForEach-Object {$_.Groups[2].Value}) -join "`n"
foreach($region in $regions){. ([scriptblock]::Create($region.Groups[2].Value))}
Add-Type -AssemblyName PresentationFramework
# Substitute only native user choices. All WPF handlers, preparation, package
# admission, viewing, export and recovery execute the generated implementation.
class CleanupGatePicker {
    static [string]$PackagePath
    static [string]$Root
    static [string]$ExportPath
    [string]$Title
    [string]$Filter
    [string]$FileName
    [string]$FolderName
    [string]$InitialDirectory
    [bool] ShowDialog([object]$owner){
        $this.FolderName=[CleanupGatePicker]::Root
        $this.FileName=if($this.Title -like 'Save restricted*'){[CleanupGatePicker]::ExportPath}else{[CleanupGatePicker]::PackagePath}
        return $true
    }
}
class CleanupGateMessage {
    static [string] Show([object]$owner,[string]$message,[string]$title,[string]$buttons,[string]$icon){
        if($buttons -eq 'YesNoCancel'){return 'Yes'}
        return 'OK'
    }
}
$uiSource=(Get-Command Invoke-StatusDesk).Definition.Replace('[Microsoft.Win32.OpenFileDialog]::new()','[CleanupGatePicker]::new()').Replace(
    '[Microsoft.Win32.OpenFolderDialog]::new()','[CleanupGatePicker]::new()').Replace(
    '[Microsoft.Win32.SaveFileDialog]::new()','[CleanupGatePicker]::new()').Replace(
    '[System.Windows.MessageBox]::Show','[CleanupGateMessage]::Show')
. ([scriptblock]::Create('function Invoke-StatusDesk {'+$uiSource+'}'))
# A regression may approve incorrectly, but must never reach live OS collection.
foreach($name in @('IdentityEnrollmentCollection','ResourceDependenciesCollection','NetworkTopologyCollection',
    'SoftwareInventoryCollection','CertificateTrustCollection','MicrosoftConnectivityCollection',
    'PrivilegedCollectionPlan','SystemCollectionPlan','ApprovedCollectorProcess')){
    $moduleText += "`nfunction Invoke-$name { throw 'Unexpected collection in cleanup gate regression.' }"
}
# Hold preparation long enough to exercise a failure before its UI timer update.
$moduleText='[Threading.Thread]::Sleep(1200)' + "`n" + $moduleText
$root=Join-Path ([IO.Path]::GetTempPath()) ('winpcinfo-cleanup-gate-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($root)
$test=@{Window=$null;Session=$null;Lock=$null;Failure='';ActionSent=$false;ActionFinished=$false;Checked=$false;Ticks=0;SawView=$false}
$watch=[Diagnostics.Stopwatch]::StartNew()
$driver=[System.Windows.Threading.DispatcherTimer]::new()
$driver.Interval=[TimeSpan]::FromMilliseconds(100)
$closer=[System.Windows.Threading.DispatcherTimer]::new()
$closer.Interval=[TimeSpan]::FromMilliseconds(100)
try {
    $package=New-ProtectedEvidencePackage -DestinationDirectory $root -Artifacts ([ordered]@{
        'assessment-record.json'=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
        'assessment-report.html'=[Text.Encoding]::UTF8.GetBytes('<html><body>Synthetic cleanup gate report</body></html>')
    }) -AssessmentContractSetVersion 1.0.0 -Completeness RecoverablePartial
    Assert-Equal $true $package.verified 'the existing synthetic package is fully admitted'
    [CleanupGatePicker]::PackagePath=$package.packagePath
    [CleanupGatePicker]::Root=$root
    $private=New-EvidenceWorkspace -RequestedBasePath $root -RunId ([guid]::NewGuid())
    [CleanupGatePicker]::ExportPath=Join-Path $private.workspacePath 'restricted.html'
    if($Scenario -like 'Recovery*'){
        $view=Open-EvidenceViewingSession -PackagePath $package.packagePath -RequestedArtifact assessment-report.html -ViewingBasePath $root
        Assert-Equal $true $view.verified 'recovery starts with registered synthetic plaintext'
        Set-EvidenceWorkspaceFixtureOwnerStale -JournalPath $view.journalPath
        $test.Lock=[IO.File]::Open($view.artifactPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    }
    if($Scenario -eq 'Export'){
        # Simulate an OS file-identity race on the exact owned export. The real
        # export must report uncertainty and preserve that unverified object.
        $identitySource=(Get-Command Get-EvidenceWorkspaceFileSystemIdentity).Definition
        . ([scriptblock]::Create('function Get-CleanupGateRealIdentity {'+$identitySource+'}'))
        function Get-EvidenceWorkspaceFileSystemIdentity {
            param([string]$LiteralPath)
            $identity=Get-CleanupGateRealIdentity -LiteralPath $LiteralPath
            if($LiteralPath.StartsWith([IO.Path]::GetDirectoryName([CleanupGatePicker]::ExportPath)+'\') -and $LiteralPath.EndsWith('.partial')){return 'synthetic-raced-file-identity'}
            $identity
        }
    }
    $request=Get-AutomationRequest -LiteralPath (Join-Path $PSScriptRoot 'fixtures/automation-request.json') -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
    $request.outputDestination=Join-Path $root 'different-assessment-destination'
    $context=@{IsFixture=$false}
    foreach($name in @('Preparation','Contract','Run','PrivilegedCollection','SystemCollection','EvidenceWorkspace','ProtectedPackage',
        'RecipientSharing','DeviceReadiness','IdentityEnrollment','AdministratorExposure','EffectivePolicy','ResourceDependencies',
        'NetworkTopology','SoftwareInventory','CertificateTrust','MicrosoftConnectivity')){$context[$name+'FixturePath']=''}
    $launch=@{Request=$request;RuntimeFacts=(Get-ActiveRuntimeFacts -ModuleFacts (Get-BuiltInModuleCompatibilityFacts));ArtifactTrustValid=$true;ValidationContext=[pscustomobject]$context}
    $closer.Add_Tick({
        if($watch.Elapsed.TotalSeconds -gt 25){
            $test.Failure='Controlled GUI exceeded its deadline.'
            if($null -ne $test.Window){foreach($child in @($test.Window.OwnedWindows)){$child.Close()};$test.Window.Close()}
            return
        }
        if($null -eq $test.Window){return}
        foreach($child in @($test.Window.OwnedWindows)){
            if($child.Title -ne 'WIN-PCInfo — Restricted offline report'){continue}
            $test.SawView=$true
            if($Scenario -eq 'Viewing' -and $null -eq $test.Lock){
                $paths=@([IO.Directory]::EnumerateFiles($root,'*.view',[IO.SearchOption]::AllDirectories))
                Assert-Equal 1 $paths.Count 'the existing package exposes only one temporary report'
                $path=$paths[0]
                $test.Lock=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            }
            $child.FindName('CloseViewing').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
        }
    }.GetNewClosure())
    $driver.Add_Tick({
        try {
            $window=$test.Window
            if($test.ActionSent -and -not $test.ActionFinished){return}
            if(-not $test.ActionSent){
                if($Scenario -eq 'RecoveryReady' -and -not $window.FindName('Approve').IsEnabled){return}
                $test.ActionSent=$true
                $action=if($Scenario -like 'Recovery*'){'RecoverViews'}else{'OpenExisting'}
                $window.FindName($action).RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                if($Scenario -eq 'Export'){$window.FindName('SaveHtml').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))}
                Assert-Equal $true ($window.FindName('Status').Text -like 'CleanupIncomplete*') ('the failed action reports cleanup uncertainty: '+$window.FindName('Status').Text+'; view observed: '+$test.SawView)
                foreach($name in @('Approve','SelectRecipient','SetupRecipient','OpenExisting','OpenReport','SaveHtml')){
                    Assert-Equal $false $window.FindName($name).IsEnabled "$name cannot start new work after cleanup failure"
                }
                # A routed click cannot bypass the disabled approval control.
                $window.FindName('Approve').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                $test.ActionFinished=$true
            }
            $test.Ticks++
            if($test.Ticks -lt 20){return}
            Assert-Equal $false $window.FindName('Approve').IsEnabled 'later preparation and terminal ticks cannot reopen approval'
            Assert-Equal $true ($window.FindName('Status').Text -like 'CleanupIncomplete*') 'cleanup failure remains the truthful visible terminal state'
            Assert-Equal $false $test.Session.Transport.State.CollectionStarted 'no collection starts even to another destination'
            Assert-Equal $true $window.FindName('RecoverViews').IsEnabled 'deliberate cleanup recovery stays available'
            Assert-Equal $true $window.FindName('Close').IsEnabled 'application close stays available'
            if($Scenario -eq 'RecoveryEarly'){
                Assert-Equal $true ([IO.File]::Exists($view.artifactPath)) 'failed recovery retains registered plaintext for deliberate cleanup'
                $test.Lock.Dispose();$test.Lock=$null
                $window.FindName('RecoverViews').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                Assert-Equal $false ([IO.File]::Exists($view.artifactPath)) 'the preserved recovery action can remove the unlocked owned plaintext'
                Assert-Equal $false $window.FindName('Approve').IsEnabled 'successful recovery still requires a fresh invocation before assessment'
            }
            $test.Checked=$true
            $window.Close()
        }
        catch {$test.Failure=$_.Exception.Message;$test.Window.Close()}
    }.GetNewClosure())
    try {
        $exitCode=Invoke-StatusDesk -ModuleText $moduleText -LaunchParameters $launch -ViewReady {
            param($window,$session)
            $window.Opacity=0;$window.ShowInTaskbar=$false
            $test.Window=$window;$test.Session=$session
            $driver.Start();$closer.Start()
        }.GetNewClosure()
    }
    finally {$driver.Stop();$closer.Stop()}
    Assert-Equal '' $test.Failure 'controlled public GUI cleanup gate assertions'
    Assert-Equal $true $test.Checked 'the failure stays sticky across later dispatcher ticks'
    Assert-Equal 60 $exitCode 'cleanup failure governs the application exit code'
    Assert-Equal $false $test.Session.Transport.State.CollectionStarted 'closing never schedules collection'
    Assert-Equal $false ([IO.Directory]::Exists($request.outputDestination)) 'no new assessment destination is written'
    Assert-Equal $true ([IO.File]::Exists($package.packagePath)) 'existing protected evidence is retained'
    if($Scenario -in @('Viewing','Export')){Assert-Equal $true $test.SawView 'reopening uses the production report window'}
}
finally {
    $driver.Stop();$closer.Stop()
    if($null -ne $test.Lock){$test.Lock.Dispose()}
    $resolved=[IO.Path]::GetFullPath($root)
    if(-not $resolved.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe synthetic cleanup.'}
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
}
Write-Output "PASS: $Scenario blocks collection after cleanup failure while preserving recovery and close."
