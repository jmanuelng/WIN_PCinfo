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
$ownedProcesses = [Collections.Generic.List[Diagnostics.Process]]::new()
function Assert-GeneratedRecovery {
    param([string] $Reason, [switch] $Authorized)
    & (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') `
        -RecoveryDestination $destination -RecoveryExpectedReason $Reason -RecoveryAuthorized:$Authorized
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
    if (-not [IO.File]::Exists($handoffPath) -and $child.HasExited) { throw ('Controlled child did not reach its worker: ' + $childError.GetAwaiter().GetResult() + $childOutput.GetAwaiter().GetResult()) }
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
finally {
    if ($null -ne $child) { if (-not $child.HasExited) { $child.Kill($true); $null=$child.WaitForExit(5000) }; $child.Dispose() }
    foreach ($process in $ownedProcesses) { $process.Dispose() }
    if ([IO.Directory]::Exists($testRoot)) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
Write-Output 'PASS: generated ordinary interruption stops its nested process tree; deliberate recovery refuses foreign paths and never resumes collection.'
