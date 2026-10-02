[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$testRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot ('.test-output/status-recovery-' + [guid]::NewGuid().ToString('N'))))
$allowedRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
if (-not $testRoot.StartsWith($allowedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid synthetic recovery boundary.' }
$null = [IO.Directory]::CreateDirectory($testRoot)
$destination = Join-Path $testRoot 'assessment'
$handoffPath = Join-Path $testRoot 'worker-ready'
$child = $null
$recoveryBodyError = $null
$recoveryCleanup = @{ childOutputVerified=$false; descendantsAbsent=$false }
$interrupted = $false
$ownedProcesses = [Collections.Generic.List[Diagnostics.Process]]::new()
function Assert-GeneratedRecovery {
    param([string] $Reason, [switch] $Authorized)
    $arguments=@('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-RecoveryDestination',$destination,'-RecoveryExpectedReason',$Reason)
    if ($Authorized) { $arguments += '-RecoveryAuthorized' }
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments $arguments
    if ($LASTEXITCODE -ne 0) { throw 'Generated recovery failed its terminal/no-collection assertions.' }
}
try {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $PSHOME 'pwsh.exe'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),
        '-RecoveryDestination',$destination,'-InterruptHandoffPath',$handoffPath)) { $start.ArgumentList.Add($argument) }
    $child = [Diagnostics.Process]::Start($start)
    $childOutput = $child.StandardOutput.ReadToEndAsync()
    $childError = $child.StandardError.ReadToEndAsync()
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while (-not [IO.File]::Exists($handoffPath) -and -not $child.HasExited -and $watch.Elapsed.TotalSeconds -lt 45) { Start-Sleep -Milliseconds 25 }
    if ($child.HasExited) {
        # Parent exit alone does not close inherited output pipes. Inspect their
        # completion only within the bounded owned finalization below.
        throw 'Controlled child exited before owned worker observation.'
    }
    Assert-Equal $true ([IO.File]::Exists($handoffPath)) 'ordinary generated run reached the controlled supervised worker'
    # Observe only descendants of this exact owned test process. Keep process
    # handles, not reusable PIDs, for absence verification after parent loss.
    $probe = [Diagnostics.Stopwatch]::StartNew()
    while ($ownedProcesses.Count -lt 2 -and $probe.ElapsedMilliseconds -lt 4000) {
        $roots = @(Get-CimInstance Win32_Process -Filter ('ParentProcessId = ' + $child.Id))
        foreach ($root in $roots) {
            $descendants = @($root) + @(Get-CimInstance Win32_Process -Filter ('ParentProcessId = ' + $root.ProcessId))
            foreach ($entry in $descendants) {
                if (@($ownedProcesses | Where-Object Id -eq $entry.ProcessId).Count -eq 0) {
                    $process = [Diagnostics.Process]::GetProcessById([int]$entry.ProcessId)
                    $null = $process.Handle
                    $ownedProcesses.Add($process)
                }
            }
        }
        if ($ownedProcesses.Count -lt 2) { Start-Sleep -Milliseconds 25 }
    }
    Assert-Equal $true ($ownedProcesses.Count -ge 2) 'actual controlled privilege worker and nested child executed before interruption'
    $interrupted = $true
    $child.Kill() # Deliberately kill only the app; product Job ownership must stop its tree.
    Assert-Equal $true $child.WaitForExit(5000) 'interrupted application process is absent'
    foreach ($process in $ownedProcesses) { Assert-Equal $true $process.WaitForExit(5000) 'parent loss closes the owned Job and leaves no supervised child' }
    $journals = @(Get-ChildItem -LiteralPath $destination -Filter 'WINPCInfo-Recovery-v1-*' -Directory)
    Assert-Equal 1 $journals.Count 'interrupted ordinary run retains exactly its durable journal'
    $journalPath = Join-Path $journals[0].FullName 'run-recovery.json'
    $original = [IO.File]::ReadAllText($journalPath)
    Assert-GeneratedRecovery RECOVERY.DELIBERATE_ACTION_REQUIRED
    Assert-Equal $true ([IO.File]::Exists($journalPath)) 'unapproved recovery preserves residue'
    # An otherwise valid journal cannot redirect cleanup outside the selected
    # assessment destination, even when a same-user sibling has a matching name.
    $journal = $original | ConvertFrom-Json
    $foreignPath = Join-Path $testRoot ([IO.Path]::GetFileName($journal.artifacts[0].path))
    $journal.artifacts[0].path = $foreignPath
    [IO.File]::WriteAllText($journalPath, ($journal | ConvertTo-Json -Depth 12))
    Assert-GeneratedRecovery RECOVERY.OWNERSHIP_UNVERIFIED -Authorized
    Assert-Equal $true ([IO.File]::Exists($journalPath)) 'foreign cleanup refusal retains the journal'
    [IO.File]::WriteAllText($journalPath, $original)
    Assert-GeneratedRecovery RECOVERY.STALE_RESIDUE_REMOVED -Authorized
    Assert-Equal 0 @(Get-ChildItem -LiteralPath $destination -Force).Count 'recovery proves all registered transient objects absent'
    Assert-GeneratedRecovery RECOVERY.NO_RESIDUE -Authorized
}
catch { $recoveryBodyError=$_ }
finally {
    Complete-QualificationHarness -BodyError $recoveryBodyError -Cleanup @(
        {
            if ($null -ne $child) {
                if (-not $child.HasExited) { $interrupted=$true; $child.Kill($true) }
                if (-not $child.WaitForExit(5000)) { throw 'Owned recovery application remains active.' }
                if (-not $childOutput.Wait(5000) -or -not $childError.Wait(5000)) { throw 'Owned child output did not close within its finalization bound.' }
                $finalOutput=@($childOutput.GetAwaiter().GetResult(),$childError.GetAwaiter().GetResult())
                Assert-QualificationCleanupSignal -Output $finalOutput
                if (-not $interrupted) { Assert-QualificationTestProcessResult -Output $finalOutput -ExitCode $child.ExitCode }
            }
            $recoveryCleanup.childOutputVerified=$true
        },
        {
            foreach ($process in $ownedProcesses) {
                if (-not $process.WaitForExit(5000)) { throw 'Owned recovery descendant remains active.' }
            }
            $recoveryCleanup.descendantsAbsent=$true
        },
        {
            if (-not $recoveryCleanup.childOutputVerified -or -not $recoveryCleanup.descendantsAbsent) { throw 'Preserve recovery state until child output and descendant absence are verified.' }
            if ($null -ne $recoveryBodyError -and (Test-QualificationCleanupUnverified -Exception $recoveryBodyError.Exception)) { throw 'Preserve unverified child recovery state.' }
            if ($null -ne $child -and -not $child.HasExited) { throw 'Preserve active application recovery state.' }
            foreach ($process in $ownedProcesses) {
                if (-not $process.HasExited) { throw 'Preserve active descendant recovery state.' }
            }
            $resolved=[IO.Path]::GetFullPath($testRoot)
            if (-not $resolved.StartsWith($allowedRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Recovery cleanup escaped its owned parent.' }
            if ([IO.Directory]::Exists($resolved)) { Remove-Item -LiteralPath $resolved -Recurse -Force }
            if ([IO.Directory]::Exists($resolved)) { throw 'Owned recovery directory absence remains unverified.' }
        },
        {
            if ($null -ne $child) { $child.Dispose() }
            foreach ($process in $ownedProcesses) { $process.Dispose() }
        }
    )
}
Write-Output 'PASS: generated ordinary interruption stops its nested process tree; deliberate recovery refuses foreign paths and never resumes collection.'
