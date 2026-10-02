[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'RecoveryProcessOwnership.ps1')
$parent=[Diagnostics.Process]::GetCurrentProcess()
$child=$null
$held=$null
try {
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=Join-Path $PSHOME 'pwsh.exe'
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    foreach($argument in @('-NoLogo','-NoProfile','-NonInteractive','-Command','[Threading.Thread]::Sleep(30000)')){$start.ArgumentList.Add($argument)}
    $child=[Diagnostics.Process]::Start($start)
    $null=$child.Handle
    $entries=@(Get-CimInstance Win32_Process -Filter ('ProcessId = '+$child.Id))
    Assert-Equal 1 $entries.Count 'only the explicitly created child PID is observed'
    $entry=$entries[0]
    $observed=[datetime]::UtcNow
    $held=Open-VerifiedRecoveryProcess -Entry $entry -Parent $parent -ExpectedImage $start.FileName -ObservedAtUtc $observed
    Assert-Equal $child.Id $held.Id 'the held process matches the actual recorded child'
    foreach($fault in @('Pid','Parent','Image','MissingImage','Creation','MissingCreation','FutureSnapshot')) {
        $changed=[pscustomobject]@{ProcessId=$entry.ProcessId;ParentProcessId=$entry.ParentProcessId;ExecutablePath=$entry.ExecutablePath;CreationDate=$entry.CreationDate}
        $at=$observed
        switch($fault) {
            'Pid' {$changed.ProcessId=$parent.Id}
            'Parent' {$changed.ParentProcessId=0}
            'Image' {$changed.ExecutablePath=Join-Path $PSHOME 'unapproved-synthetic.exe'}
            'MissingImage' {$changed.ExecutablePath=''}
            'Creation' {$changed.CreationDate=([datetime]$entry.CreationDate).AddSeconds(-1)}
            'MissingCreation' {$changed.CreationDate=$null}
            'FutureSnapshot' {$at=$child.StartTime.ToUniversalTime().AddSeconds(-1)}
        }
        Assert-Equal $false (Test-RecoveryProcessObservation -Entry $changed -Process $held -Parent $parent -ExpectedImage $start.FileName -ObservedAtUtc $at) "$fault cannot establish descendant ownership"
    }
    $child.Kill()
    Assert-Equal $true $child.WaitForExit(5000) 'the exact benign test child stops'
    Assert-Equal $false (Test-RecoveryProcessObservation -Entry $entry -Process $held -Parent $parent -ExpectedImage $start.FileName -ObservedAtUtc $observed) 'an exited lifetime cannot be admitted as a live descendant'
}
finally {
    if($null -ne $child){
        if(-not $child.HasExited){$child.Kill()}
        if(-not $child.WaitForExit(5000)){throw 'Exact-owned metadata test child absence remains unverified.'}
        $child.Dispose()
    }
    if($null -ne $held){$held.Dispose()}
    $parent.Dispose()
}

# Exercise the failed-admission finalizer against a real parent with a child
# outside product Job ownership. Parent-only stop must leave that held child
# alive; this test then terminates the independently admitted child itself.
$ownedRoot = Join-Path (Split-Path -Parent $PSScriptRoot) ('.test-output/recovery-stop-' + [guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($ownedRoot)
$witness=Join-Path $ownedRoot 'nested-ready'
$root=$null;$nested=$null;$rootOutput=$null;$rootError=$null;$stopBodyError=$null;$stopCleanupVerified=$false
try {
    $code=@'
$start=[Diagnostics.ProcessStartInfo]::new()
$start.FileName=Join-Path $PSHOME 'pwsh.exe'
$start.UseShellExecute=$false;$start.CreateNoWindow=$true
foreach($argument in @('-NoLogo','-NoProfile','-NonInteractive','-Command','[Threading.Thread]::Sleep(30000)')){$start.ArgumentList.Add($argument)}
$nested=[Diagnostics.Process]::Start($start)
[IO.File]::WriteAllText('__WITNESS__',$nested.Id.ToString())
[Threading.Thread]::Sleep(30000)
'@.Replace('__WITNESS__',$witness.Replace("'","''"))
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=Join-Path $PSHOME 'pwsh.exe'
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    foreach($argument in @('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code)))){$start.ArgumentList.Add($argument)}
    $root=[Diagnostics.Process]::Start($start);$null=$root.Handle
    $rootOutput=$root.StandardOutput.ReadToEndAsync();$rootError=$root.StandardError.ReadToEndAsync()
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while(-not [IO.File]::Exists($witness)-and -not $root.HasExited-and $watch.ElapsedMilliseconds-lt5000){Start-Sleep -Milliseconds 25}
    Assert-Equal $true ([IO.File]::Exists($witness)) 'controlled parent created its nested child'
    $nestedId=[int][IO.File]::ReadAllText($witness)
    $entries=@(Get-CimInstance Win32_Process -Filter ('ProcessId = '+$nestedId))
    Assert-Equal 1 $entries.Count 'only the recorded nested child PID is observed'
    $nested=Open-VerifiedRecoveryProcess -Entry $entries[0] -Parent $root -ExpectedImage $start.FileName -ObservedAtUtc ([datetime]::UtcNow)
    $bad=[pscustomobject]@{ProcessId=$entries[0].ProcessId;ParentProcessId=$entries[0].ParentProcessId;ExecutablePath='';CreationDate=$entries[0].CreationDate}
    $rejected=$false
    try {$unexpected=Open-VerifiedRecoveryProcess -Entry $bad -Parent $root -ExpectedImage $start.FileName -ObservedAtUtc ([datetime]::UtcNow);$unexpected.Dispose()}catch{$rejected=$true}
    Assert-Equal $true $rejected 'failed descendant admission exercises the recovery stop path'
    Stop-RecoveryApplication -Process $root
    Assert-Equal $false ($nested.WaitForExit(100)) 'failed admission cannot recursively terminate a separately held descendant'
}
catch {$stopBodyError=$_}
finally {
    Complete-QualificationHarness -BodyError $stopBodyError -Cleanup @(
        {
            if($null-ne$root){Stop-RecoveryApplication -Process $root}
        },
        {
            if($null-eq$nested-and [IO.File]::Exists($witness)){throw 'Preserve stopped-parent witness because nested child admission was incomplete.'}
            if($null-ne$nested){
                if(-not$nested.HasExited){$nested.Kill()}
                if(-not$nested.WaitForExit(5000)){throw 'Verified nested fixture child remains active.'}
            }
            $script:stopCleanupVerified=$true
        },
        {
            if($null-ne$root){
                if(-not$rootOutput.Wait(5000)-or -not$rootError.Wait(5000)){throw 'Exact-owned fixture output remains open.'}
            }
        },
        {
            if(-not$stopCleanupVerified){throw 'Preserve incomplete nested-child observation.'}
            [IO.File]::Delete($witness)
            [IO.Directory]::Delete($ownedRoot,$false)
        },
        {
            if($null-ne$nested){$nested.Dispose()}
            if($null-ne$root){$root.Dispose()}
        }
    )
}

Write-Output 'PASS: exact-owned metadata rejects mismatches and exited lifetimes; failed admission stops only the held application and preserves a separately held child.'
