[CmdletBinding()]
param([ValidateSet('None','IgnoreWaitBoolean','SkipIndependentCleanup','DisposeBeforeRetention','IgnoreRawRetention')] [string] $FixtureFault='None')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'QualificationCapabilityProcess.ps1')
function Assert-CapabilityControl {param([bool] $Condition,[string] $Message);if(-not $Condition){throw $Message};$script:controls++}

# Disclosed substitutions: admission, creator identity, ACL and original Process
# are synthetic. The actual owner, finite observer, record writer and finalizer
# run in-process; no Windows process/Job/pipe/event/mutex is created or queried.
function Get-QualificationFixtureAdmission {
    param($RepositoryRoot)
    if($script:admissionRefusal){throw 'Disclosed admission refusal.'}
    [pscustomobject]@{Ends=[DateTimeOffset]::UtcNow.AddMilliseconds($script:admissionBudget);Creator=[pscustomobject]@{
        Pid=123;CreationUtc='2030-01-01T00:00:00.0000000Z';OwnerSid='synthetic-sid';HostPath=(Join-Path $PSHOME 'pwsh.exe')};Parent=$script:context.Parent}
}
function Get-TestNativeAdmissionContext {param($RepositoryRoot,$SelfIdentity);$script:context}
function Set-TestNativePrivateDirectory {param($Path);'synthetic-sid'}
function Get-QualificationFixtureOriginalIdentity {
    param($Process)
    if($Process.Mode -ceq 'IdentityFailure'){throw 'Disclosed identity failure.'}
    [pscustomobject]@{Handle=$Process.SafeHandle;Record=[ordered]@{pid=456;fullBirthUtc='2030-01-01T00:00:00.1234567Z';
        originalSafeHandleValue=789;handleProvenance='Disclosed pure original handle.'}}
}
$originalWriter=${function:Write-QualificationFixtureRecord}
function Write-QualificationFixtureRecord {
    param($Path,$Value)
    if([IO.Path]::GetFileName($Path) -ceq $script:retentionFault){throw 'Disclosed raw retention failure.'}
    & $originalWriter -Path $Path -Value $Value
}

if($FixtureFault -ceq 'IgnoreWaitBoolean'){
    $text=${function:Wait-QualificationCapabilityTerminal}.ToString().Replace("if (`$terminal -isnot [bool] -or -not `$terminal) { throw 'Capability original handle terminal completion is unverified.' }",'')
    Set-Item Function:Wait-QualificationCapabilityTerminal ([scriptblock]::Create($text))
}
if($FixtureFault -ceq 'SkipIndependentCleanup'){
    $text=${function:Complete-QualificationCapabilityProcess}.ToString().Replace('foreach ($action in $Cleanup)','foreach ($action in @($Cleanup | Select-Object -First 1))')
    Set-Item Function:Complete-QualificationCapabilityProcess ([scriptblock]::Create($text))
}
if($FixtureFault -ceq 'DisposeBeforeRetention'){
    $text=${function:Close-QualificationCapabilityProcess}.ToString().Replace("foreach (`$name in @('original-terminal.json','terminal.json'))", "if (`$Owner.Started) { `$Owner.Process.Dispose() };foreach (`$name in @('original-terminal.json','terminal.json'))")
    Set-Item Function:Close-QualificationCapabilityProcess ([scriptblock]::Create($text))
}
if($FixtureFault -ceq 'IgnoreRawRetention'){
    $text=${function:Close-QualificationCapabilityProcess}.ToString().Replace("@('original-terminal.json','terminal.json')","@('terminal.json')")
    Set-Item Function:Close-QualificationCapabilityProcess ([scriptblock]::Create($text))
}

$script:controls=0;$script:admissionRefusal=$false;$script:admissionBudget=20000;$script:retentionFault=''
$root=Join-Path (Split-Path -Parent $PSScriptRoot) ('.test-output/product-capability-controls-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($root)
function Get-QualificationCleanupBlockerPath {Join-Path $root 'synthetic-blocker.json'}
function New-ControlOwner {
    param([string] $Profile='SystemWorkerPeer',[string] $CreatorFault='')
    $repo=Join-Path $root ([guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory((Join-Path $repo 'tests'))
    $name=if($Profile -ceq 'SystemWorkerPeer'){'SystemWorkerPeer.Tests.ps1'}else{'RunLifecycle.Tests.ps1'}
    $test=Join-Path $repo ('tests/'+$name)
    [IO.File]::WriteAllText($test,'# Disclosed pure named-source input.')
    $script:context=[pscustomobject]@{Parent=[pscustomobject]@{Admission=[pscustomobject]@{testPath=$test};Pending=[ordered]@{authorityEnds='2030-01-01T00:00:00.0000000Z';cleanupReserveMs=1000}};
        Root=[pscustomobject]@{Admission=[pscustomobject]@{inputs=@([pscustomobject]@{path=$test})}}}
    $start=[Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh.exe'));$start.UseShellExecute=$false
    foreach($arg in @('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('# Disclosed pure payload, never launched.')))){$start.ArgumentList.Add($arg)}
    switch($CreatorFault){WrongHost{$start.FileName='unadmitted.exe'};WrongArg{$start.ArgumentList[2]='-Interactive'};
        WrongSource{$script:context.Parent.Admission.testPath='other.Tests.ps1'};MissingCohort{$script:context.Root.Admission.inputs=@()};
        Redirect{$start.RedirectStandardOutput=$true};AlternateUser{$start.UserName='unadmitted'};InvalidPayload{$start.ArgumentList[4]='***'}}
    New-QualificationCapabilityProcessOwner -RepositoryRoot $repo -Profile $Profile -StartInfo $start
}
function New-ControlProcess {
    param([string] $Mode='Terminal')
    $value=[pscustomobject]@{Mode=$Mode;Events=[Collections.Generic.List[string]]::new();ExitCode=0;Directory='';
        SafeHandle=[pscustomobject]@{IsInvalid=$false;IsClosed=$false};DisposedBeforeRetention=$false;Waits=[Collections.Generic.List[int]]::new()}
    if($Mode -ceq 'UnknownExit'){$value.ExitCode=$null}
    $value|Add-Member ScriptMethod WaitForExit {param([int]$Milliseconds);$this.Events.Add('wait');$this.Waits.Add($Milliseconds);
        if($this.Mode -ceq 'WaitThrows'){throw 'Disclosed wait failure.'};if($this.Mode -ceq 'WaitString'){return 'false'};return ($this.Mode -cne 'WaitFalse')}
    $value|Add-Member ScriptMethod Dispose {
        $this.Events.Add('dispose')
        if(-not [IO.File]::Exists((Join-Path $this.Directory 'original-terminal.json')) -or -not [IO.File]::Exists((Join-Path $this.Directory 'terminal.json'))){$this.DisposedBeforeRetention=$true}
        if($this.Mode -ceq 'DisposeThrows'){throw 'Disclosed disposal failure.'}
    }
    $value
}
function Start-ControlOwner {
    param($Owner,[string]$Mode='Terminal')
    Assert-QualificationCapabilityCreation -Owner $Owner
    $process=New-ControlProcess -Mode $Mode;$process.Directory=$Owner.Directory
    Register-QualificationCapabilityProcess -Owner $Owner -Process $process
    $process
}
function Get-ActualCapabilityFinally {
    param([string] $Name,[string] $OwnerVariable)
    $parseErrors=$null;$tokens=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $Name),[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count){throw 'Owning source must parse before pure finalizer replay.'}
    $matches=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.TryStatementAst] -and
        $null -ne $node.Finally -and $node.Finally.Extent.Text.Contains('-Owner $'+$OwnerVariable)},$true))
    if($matches.Count -ne 1){throw 'Actual owning finalizer must be uniquely selected.'}
    $text=$matches[0].Finally.Extent.Text
    [scriptblock]::Create($text.Substring(1,$text.Length-2))
}
function New-ControlResource {
    param([string]$Name,[bool]$Failure=$false)
    $value=[pscustomobject]@{Name=$Name;Failure=$Failure;Events=$script:resourceEvents}
    $value|Add-Member ScriptMethod Dispose {$this.Events.Add($this.Name+'.Dispose');if($this.Failure){throw ('Disclosed '+$this.Name+' disposal failure.')}}
    $value|Add-Member ScriptMethod Set {$this.Events.Add($this.Name+'.Set');if($this.Failure){throw ('Disclosed '+$this.Name+' signal failure.')};$true}
    $value|Add-Member ScriptMethod Terminate {$this.Events.Add($this.Name+'.Terminate');$true}
    $value
}
function Assert-RunEqual {param($Expected,$Actual,$Because);if($Expected -ne $Actual){throw $Because}}
try {
    foreach($profile in @('SystemWorkerPeer','RunLifecycleLiveMutex','RunLifecycleAbandonedMutex')){
        $owner=New-ControlOwner -Profile $profile;$process=Start-ControlOwner -Owner $owner
        $originalPending=[IO.File]::ReadAllBytes((Join-Path $owner.Directory 'original-pending.json'))
        Complete-QualificationCapabilityProcess -Owner $owner -Process $process
        $cap=if($profile -ceq 'SystemWorkerPeer'){5000}elseif($profile -ceq 'RunLifecycleLiveMutex'){3000}else{2000}
        Assert-CapabilityControl ($process.Waits.Count -eq 1 -and $process.Waits[0] -eq $cap) 'Original profile wait cap must be used exactly once.'
        Assert-CapabilityControl ($owner.SafeHandle -eq $process.SafeHandle -and $owner.Disposed -and -not $process.DisposedBeforeRetention) 'Original handle must remain pinned until independent terminal evidence.'
        Assert-CapabilityControl (-not [IO.File]::Exists((Join-Path $owner.Directory 'owned-pending.json'))) 'Verified original lifetime releases only its exact pending marker.'
        Assert-CapabilityControl ([Convert]::ToHexString($originalPending) -ceq [Convert]::ToHexString([IO.File]::ReadAllBytes((Join-Path $owner.Directory 'original-pending.json')))) 'Original pending argv/creator bytes cannot be rebound by completion.'
        $raw=Get-Content -LiteralPath (Join-Path $owner.Directory 'original-terminal.json') -Raw|ConvertFrom-Json -DateKind String
        Assert-CapabilityControl ($raw.identity.fullBirthUtc -ceq '2030-01-01T00:00:00.1234567Z' -and $raw.exitCode -is [long] -and $raw.exitCode -eq 0 -and -not $raw.processTreeAbsenceClaim) 'Raw original identity/outcome must survive retention without absence inference.'
    }
    foreach($fault in @('WrongHost','WrongArg','WrongSource','MissingCohort','Redirect','AlternateUser','InvalidPayload')){
        $caught=$false;try{$null=New-ControlOwner -CreatorFault $fault}catch{$caught=$true}
        Assert-CapabilityControl $caught ($fault+' must refuse before any original Start.')
    }
    $script:admissionRefusal=$true;$caught=$false;try{$null=New-ControlOwner}catch{$caught=$true};$script:admissionRefusal=$false
    Assert-CapabilityControl $caught 'Missing actual File/Case admission must refuse.'
    $script:admissionBudget=6000;$caught=$false;try{$null=New-ControlOwner}catch{$caught=$true};$script:admissionBudget=20000
    Assert-CapabilityControl $caught 'Insufficient unchanged authority must refuse before creation.'
    foreach($mode in @('WaitFalse','WaitString','WaitThrows','UnknownExit','DisposeThrows')){
        $owner=New-ControlOwner;$process=Start-ControlOwner -Owner $owner -Mode $mode
        $caught=$null;try{$null=Complete-QualificationCapabilityProcess -Owner $owner -Process $process}catch{$caught=$_}
        Assert-CapabilityControl ($null -ne $caught -and (Test-QualificationCleanupUnverified -Exception $caught.Exception)) ($mode+' must stay unsafe.')
        Assert-CapabilityControl ([IO.File]::Exists((Join-Path $owner.Directory 'owned-pending.json')) -and -not $process.DisposedBeforeRetention) ($mode+' must retain exact pending and raw evidence before disposal.')
        Assert-CapabilityControl ($process.Waits.Count -eq 1) 'An unchanged terminal failure cannot renew its wait.'
    }
    $owner=New-ControlOwner -Profile RunLifecycleAbandonedMutex;$process=Start-ControlOwner -Owner $owner -Mode WaitFalse
    $body=$null;try{Wait-QualificationCapabilityTerminal -Owner $owner}catch{$body=$_}
    $caught=$null;try{$null=Complete-QualificationCapabilityProcess -Owner $owner -Process $process -BodyError $body}catch{$caught=$_}
    Assert-CapabilityControl ($null -ne $caught -and $process.Waits.Count -eq 1 -and -not $owner.Disposed) 'A failed actual body observation cannot gain another cleanup wait.'
    $owner=New-ControlOwner;$owner.BudgetMs=6000;$caught=$false
    try{Assert-QualificationCapabilityCreation -Owner $owner}catch{$caught=$true}
    Assert-CapabilityControl ($caught -and -not $owner.StartRequested) 'Elapsed preparation must be charged before the existing Start.'
    $owner=New-ControlOwner;$process=Start-ControlOwner -Owner $owner;$owner.BudgetMs=1800
    Complete-QualificationCapabilityProcess -Owner $owner -Process $process
    Assert-CapabilityControl ($process.Waits[0] -gt 0 -and $process.Waits[0] -le 800) 'Original wait must clip to unchanged authority plus retention reserve.'
    $owner=New-ControlOwner;$process=Start-ControlOwner -Owner $owner;$owner.BudgetMs=900
    $caught=$null;try{$null=Complete-QualificationCapabilityProcess -Owner $owner -Process $process}catch{$caught=$_}
    Assert-CapabilityControl ($null -ne $caught -and $process.Waits.Count -eq 0 -and -not $owner.Disposed) 'Exhausted reserve cannot start another wait or dispose.'
    foreach($name in @('original-terminal.json','terminal.json')){
        $owner=New-ControlOwner;$process=Start-ControlOwner -Owner $owner;$script:retentionFault=$name
        $caught=$null;try{$null=Complete-QualificationCapabilityProcess -Owner $owner -Process $process}catch{$caught=$_};$script:retentionFault=''
        $other=if($name -ceq 'original-terminal.json'){'terminal.json'}else{'original-terminal.json'}
        Assert-CapabilityControl ($null -ne $caught -and [IO.File]::Exists((Join-Path $owner.Directory $other)) -and -not $owner.Disposed) 'A failed raw copy must not skip the independent copy or dispose.'
    }
    $owner=New-ControlOwner;$process=Start-ControlOwner -Owner $owner;$events=[Collections.Generic.List[string]]::new()
    $body=$null;try{throw 'Disclosed original body failure.'}catch{$body=$_}
    $caught=$null;try{$null=Complete-QualificationCapabilityProcess -Owner $owner -Process $process -BodyError $body -Cleanup @(
        {$events.Add('first');throw 'Disclosed first cleanup failure.'},{$events.Add('second')},{$events.Add('third')})}catch{$caught=$_}
    Assert-CapabilityControl (($events -join ',') -ceq 'first,second,third') 'A failed cleanup must not skip independent actions.'
    Assert-CapabilityControl ($null -ne $caught -and $caught.Exception.ToString().Contains('Disclosed original body failure.') -and $caught.Exception.ToString().Contains('Disclosed first cleanup failure.')) 'Body and cleanup causes must remain independently reachable.'
    Assert-CapabilityControl ($owner.TerminalVerified -and -not $owner.Disposed -and [IO.File]::Exists((Join-Path $owner.Directory 'original-terminal.json'))) 'Cleanup uncertainty retains terminal evidence and the original handle.'
    $owner=New-ControlOwner;Assert-QualificationCapabilityCreation -Owner $owner
    $caught=$null;try{$null=Complete-QualificationCapabilityProcess -Owner $owner}catch{$caught=$_}
    Assert-CapabilityControl ($null -ne $caught -and -not $owner.TerminalVerified) 'Requested creation without the actual original result remains unknown.'
    $owner=New-ControlOwner;$process=New-ControlProcess -Mode IdentityFailure;$process.Directory=$owner.Directory
    Assert-QualificationCapabilityCreation -Owner $owner;$body=$null;try{Register-QualificationCapabilityProcess -Owner $owner -Process $process}catch{$body=$_}
    $caught=$null;try{$null=Complete-QualificationCapabilityProcess -Owner $owner -Process $process -BodyError $body}catch{$caught=$_}
    Assert-CapabilityControl ($owner.SafeHandle -eq $process.SafeHandle -and $null -ne $caught -and -not $owner.Disposed) 'Fallible identity acquisition must retain the actual original creator handle.'
    # Replay only actual owning finally blocks with fake original resources.
    # Their creators/capability/product bodies are never invoked by these controls.
    $script:resourceEvents=[Collections.Generic.List[string]]::new()
    $workerOwner=New-ControlOwner;$worker=Start-ControlOwner -Owner $workerOwner;$bodyError=$null
    $server=New-ControlResource -Name server -Failure $true;$job=New-ControlResource -Name job
    $deadline=New-ControlResource -Name deadline;$otherJob=New-ControlResource -Name otherJob
    $caught=$null;try{$null=. (Get-ActualCapabilityFinally -Name SystemWorkerPeer.Tests.ps1 -OwnerVariable workerOwner)}catch{$caught=$_}
    Assert-CapabilityControl (($script:resourceEvents -join ',') -ceq 'server.Dispose,job.Terminate,deadline.Dispose,job.Dispose,otherJob.Dispose') 'Actual peer finally must still terminate its Job and attempt every independent disposal after server failure.'
    Assert-CapabilityControl ($null -ne $caught -and $workerOwner.TerminalVerified -and -not $workerOwner.Disposed) 'Actual peer cleanup failure retains the original worker lifetime.'
    $script:resourceEvents=[Collections.Generic.List[string]]::new()
    $lockOwnerObservation=New-ControlOwner -Profile RunLifecycleLiveMutex;$lockOwner=Start-ControlOwner -Owner $lockOwnerObservation;$lockBodyError=$null
    $lockRelease=New-ControlResource -Name release -Failure $true;$lockReady=New-ControlResource -Name ready
    $caught=$null;try{$null=. (Get-ActualCapabilityFinally -Name RunLifecycle.Tests.ps1 -OwnerVariable lockOwnerObservation)}catch{$caught=$_}
    Assert-CapabilityControl (($script:resourceEvents -join ',') -ceq 'release.Set,ready.Dispose,release.Dispose') 'Actual live mutex finally independently disposes both events after release failure.'
    Assert-CapabilityControl ($null -ne $caught -and $lockOwner.Waits.Count -eq 1 -and $lockOwner.Waits[0] -eq 3000 -and -not $lockOwnerObservation.Disposed) 'Actual live mutex keeps natural wait and cannot invent a forced success.'
    $script:resourceEvents=[Collections.Generic.List[string]]::new()
    $abandonedOwnerObservation=New-ControlOwner -Profile RunLifecycleAbandonedMutex;$abandonedOwner=Start-ControlOwner -Owner $abandonedOwnerObservation;$abandonedBodyError=$null
    $abandonedProbe=New-ControlResource -Name probe -Failure $true;$abandonedReady=New-ControlResource -Name abandonedReady
    $caught=$null;try{$null=. (Get-ActualCapabilityFinally -Name RunLifecycle.Tests.ps1 -OwnerVariable abandonedOwnerObservation)}catch{$caught=$_}
    Assert-CapabilityControl (($script:resourceEvents -join ',') -ceq 'probe.Dispose,abandonedReady.Dispose') 'Actual abandoned mutex finally independently disposes its event after probe failure.'
    Assert-CapabilityControl ($null -ne $caught -and $abandonedOwner.Waits.Count -eq 1 -and $abandonedOwner.Waits[0] -eq 2000 -and -not $abandonedOwnerObservation.Disposed) 'Actual abandoned owner requires original natural terminal witness before disposal.'
    Write-Output ('PASS: '+$script:controls+' child-free original capability owner controls.')
}
finally {
    # Only synthetic fixture bytes/objects were created. This is not native recovery.
    $boundary=[IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $PSScriptRoot) '.test-output')).TrimEnd('\')+'\'
    if(-not [IO.Path]::GetFullPath($root).StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)){throw 'Pure cleanup escaped its exact root.'}
    if(@(Get-ChildItem -LiteralPath $root -Directory -Recurse -Force|Where-Object{($_.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0}).Count){throw 'Pure cleanup refuses a reparse point.'}
    [IO.Directory]::Delete($root,$true)
}
