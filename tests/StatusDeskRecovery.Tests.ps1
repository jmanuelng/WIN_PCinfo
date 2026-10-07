[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'QualificationFixtureProcess.ps1')
. (Join-Path $PSScriptRoot 'RecoveryProcessOwnership.ps1')
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$testRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot ('.test-output/status-recovery-' + [guid]::NewGuid().ToString('N'))))
$allowedRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
if (-not $testRoot.StartsWith($allowedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid synthetic recovery boundary.' }
$null = [IO.Directory]::CreateDirectory($testRoot)
$destination = Join-Path $testRoot 'assessment'
$handoffPath = Join-Path $testRoot 'worker-ready'
$child = $null
$recoveryBodyError = $null
$recoveryCleanup = @{ childOutputVerified=$false; descendantsAbsent=$false; observationComplete=$false }
$interrupted = $false
$ownedProcesses = [Collections.Generic.List[Diagnostics.Process]]::new()
$observations = [Collections.Generic.List[object]]::new()
$observationPath = Join-Path $allowedRoot ('recovery-observation-' + [IO.Path]::GetFileName($testRoot) + '.json')
$consoleImage = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32/conhost.exe'
function Save-RecoveryObservations {
    [IO.File]::WriteAllText($observationPath, ($observations.ToArray() | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
}
function Get-RecoveryChildren {
    param([Diagnostics.Process] $Parent)
    $entries = @(Get-CimInstance Win32_Process -Filter ('ParentProcessId = ' + $Parent.Id))
    $at = [datetime]::UtcNow
    # Persist the complete scope before any image or lifetime admission.
    $observations.Add([pscustomobject]@{kind='ScopedSnapshot';atUtc=$at.ToString('o');parentPid=$Parent.Id;
        parentStartUtc=$Parent.StartTime.ToUniversalTime().ToString('o');entries=@($entries | Select-Object ProcessId,ParentProcessId,CreationDate,ExecutablePath)})
    Save-RecoveryObservations
    foreach ($entry in $entries) {
        $expected = if ([string]::Equals([string]$entry.ExecutablePath, $start.FileName, [StringComparison]::OrdinalIgnoreCase)) { $start.FileName }
            elseif ([string]::Equals([string]$entry.ExecutablePath, $consoleImage, [StringComparison]::OrdinalIgnoreCase)) { $consoleImage }
            else { throw 'Recovery observation contains an image outside the fixed PowerShell and console-helper allowlist.' }
        $known = @($ownedProcesses | Where-Object Id -eq $entry.ProcessId)
        if ($known.Count -eq 0) {
            $held=Open-VerifiedRecoveryProcess -Entry $entry -Parent $Parent -ExpectedImage $expected -ObservedAtUtc $at
            $ownedProcesses.Add($held)
        }
        elseif (-not (Test-RecoveryProcessObservation -Entry $entry -Process $known[0] -Parent $Parent -ExpectedImage $expected -ObservedAtUtc $at)) {
            throw 'Previously held recovery descendant no longer matches its observed lifetime.'
        }
    }
    return $entries
}
function Assert-GeneratedRecovery {
    param([string] $Reason, [switch] $Authorized)
    $arguments=@('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-RecoveryDestination',$destination,'-RecoveryExpectedReason',$Reason)
    if ($Authorized) { $arguments += '-RecoveryAuthorized' }
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments $arguments
    if ($LASTEXITCODE -ne 0) { throw 'Generated recovery failed its terminal/no-collection assertions.' }
}
try {
    $statusNonce=[guid]::NewGuid().ToString('N');$statusDirectory=Join-Path $repositoryRoot ('.test-output/original-creator/'+$statusNonce)
    $statusContext=Get-TestNativeAdmissionContext -RepositoryRoot $repositoryRoot -SelfIdentity (Get-TestNativeSelfIdentity)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $PSHOME 'pwsh.exe'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),
        '-RecoveryDestination',$destination,'-InterruptHandoffPath',$handoffPath,'-RecoveryCreatorDirectory',$statusDirectory,
        '-CandidatePath',$statusContext.Root.Admission.candidatePath,'-PreparedManifestPath',$statusContext.Root.Admission.preparedManifestPath,'-PreparedManifestSha256',$statusContext.Root.Admission.preparedManifestSha256)) { $start.ArgumentList.Add($argument) }
    $statusOwner=New-QualificationOriginalCreatorOwner -RepositoryRoot $repositoryRoot -TestPath $PSCommandPath -Profile StatusRecoveryParent -StartInfo $start -Nonce $statusNonce
    Assert-QualificationOriginalCreatorCreation $statusOwner
    $child = [Diagnostics.Process]::Start($start)
    Register-QualificationFixtureProcess -Owner $statusOwner -Process $child
    $null = $child.Handle
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
    $witness = [IO.File]::ReadAllText($handoffPath)
    if ($witness -notmatch '^([0-9]+):([0-9]+)$') { throw 'Recovery worker witness has an invalid closed shape.' }
    $workerId = [int]$Matches[1]
    $nestedId = [int]$Matches[2]
    $roots = @(Get-RecoveryChildren -Parent $child)
    $worker = @($ownedProcesses | Where-Object Id -eq $workerId)
    Assert-Equal 1 $worker.Count 'the witness worker is an admitted direct child of the application'
    $nestedEntries = @(Get-RecoveryChildren -Parent $worker[0])
    $nested = @($ownedProcesses | Where-Object Id -eq $nestedId)
    Assert-Equal 1 $nested.Count 'the witness nested child has a verified held lifetime'
    Assert-Equal $true (@($nestedEntries | Where-Object { $_.ProcessId -eq $nestedId -and $_.ParentProcessId -eq $workerId }).Count -eq 1) 'actual worker parentage binds the nested child'
    foreach ($process in @($worker[0], $nested[0])) {
        Assert-Equal $start.FileName $process.MainModule.FileName 'both controlled worker and nested child use the verified PowerShell image'
    }
    # Console helpers count for cleanup, never for the nested-worker assertion.
    foreach ($root in $roots) {
        if ($root.ProcessId -ne $workerId) {
            $held = @($ownedProcesses | Where-Object Id -eq $root.ProcessId)[0]
            $null = @(Get-RecoveryChildren -Parent $held)
        }
    }
    $null = @(Get-RecoveryChildren -Parent $nested[0])
    $recoveryCleanup.observationComplete=$true
    $interrupted = $true
    Stop-RecoveryApplication -Process $child # Product Job closure must stop its tree.
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
    $null = [IO.Directory]::CreateDirectory($foreignPath)
    $foreignSentinel = Join-Path $foreignPath 'unrelated-sentinel.txt'
    $foreignText = 'Synthetic unrelated object must survive assessment recovery.'
    [IO.File]::WriteAllText($foreignSentinel, $foreignText, [Text.UTF8Encoding]::new($false))
    $journal.artifacts[0].path = $foreignPath
    [IO.File]::WriteAllText($journalPath, ($journal | ConvertTo-Json -Depth 12))
    Assert-GeneratedRecovery RECOVERY.OWNERSHIP_UNVERIFIED -Authorized
    Assert-Equal $true ([IO.File]::Exists($journalPath)) 'foreign cleanup refusal retains the journal'
    Assert-Equal $foreignText ([IO.File]::ReadAllText($foreignSentinel)) 'foreign-path refusal preserves the unrelated object byte content'
    [IO.File]::WriteAllText($journalPath, $original)
    Assert-GeneratedRecovery RECOVERY.STALE_RESIDUE_REMOVED -Authorized
    Assert-Equal 0 @(Get-ChildItem -LiteralPath $destination -Force).Count 'recovery proves all registered transient objects absent'
    Assert-GeneratedRecovery RECOVERY.NO_RESIDUE -Authorized
    Assert-Equal $foreignText ([IO.File]::ReadAllText($foreignSentinel)) 'authorized cleanup and second launch preserve the unrelated object'
}
catch {
    $recoveryBodyError=$_
    $observations.Add([pscustomobject]@{kind='Failure';atUtc=[datetime]::UtcNow.ToString('o');reason=$_.Exception.Message})
    Save-RecoveryObservations
}
finally {
    Complete-QualificationHarness -BodyError $recoveryBodyError -Cleanup @(
        {
            if ($null -ne $child) {
                if (-not $child.HasExited) { $interrupted=$true; Stop-RecoveryApplication -Process $child }
                if (-not $child.WaitForExit(5000)) { throw 'Owned recovery application remains active.' }
                if (-not $childOutput.Wait(5000) -or -not $childError.Wait(5000)) { throw 'Owned child output did not close within its finalization bound.' }
                $finalOutput=@($childOutput.GetAwaiter().GetResult(),$childError.GetAwaiter().GetResult())
                $retainedStatusOwner=Get-Variable statusOwner -ValueOnly -ErrorAction SilentlyContinue
                if($null-ne$retainedStatusOwner){Save-QualificationOriginalCreatorTerminal -Owner $statusOwner -Disposition OriginalJobClosureRecovery -Forced $interrupted -StandardOutput $finalOutput[0] -StandardError $finalOutput[1] -StreamContract OriginalReadToEndStrings}
                Assert-QualificationCleanupSignal -Output $finalOutput
                if (-not $interrupted) { Assert-QualificationTestProcessResult -Output $finalOutput -ExitCode $child.ExitCode }
            }
            $recoveryCleanup.childOutputVerified=$true
        },
        {
            foreach ($process in $ownedProcesses) {
                if (-not $process.WaitForExit(5000)) { throw 'Owned recovery descendant remains active.' }
            }
            if (-not $recoveryCleanup.observationComplete) {
                throw 'Preserve recovery state because exact-owned descendant observation was incomplete.'
            }
            $retainedStatusOwner=Get-Variable statusOwner -ValueOnly -ErrorAction SilentlyContinue
            if($null-ne$retainedStatusOwner){
            Save-QualificationRecoveryOriginalTerminal -Owner $statusOwner -Role StatusWorker -Process $worker[0] -CreatorProcess $child -Disposition OriginalProductJobClosureAfterParentLoss
            Save-QualificationRecoveryOriginalTerminal -Owner $statusOwner -Role StatusNested -Process $nested[0] -CreatorProcess $worker[0] -Disposition OriginalProductJobClosureAfterParentLoss
            $unmapped=@($ownedProcesses|Where-Object {$_.Id-ne$worker[0].Id-and$_.Id-ne$nested[0].Id}|ForEach-Object{[ordered]@{pid=$_.Id;fullBirthUtc=$_.StartTime.ToUniversalTime().ToString('o');source='Original OS helper creator custody unavailable; recovery observation only.'}})
            Write-QualificationFixtureRecord -Path (Join-Path $statusOwner.Directory 'recovery-extra-observations.json') -Value ([ordered]@{contract='win-pcinfo.recovery-observation-coverage/1.0.0';observations=$unmapped;originalCreatorClaim=$false})
            }
            $recoveryCleanup.descendantsAbsent=$true
        },
        {
            if ($null -ne $child -and -not $child.HasExited) { throw 'Preserve active application recovery state.' }
            foreach ($process in $ownedProcesses) {
                if (-not $process.HasExited) { throw 'Preserve active descendant recovery state.' }
            }
            if ($null -ne $child) { $child.Dispose() }
            foreach ($process in $ownedProcesses) { $process.Dispose() }
            $retainedStatusOwner=Get-Variable statusOwner -ValueOnly -ErrorAction SilentlyContinue
            if($null-ne$retainedStatusOwner){
                Complete-QualificationRecoveryOriginalTerminal -Owner $statusOwner -Role StatusWorker
                Complete-QualificationRecoveryOriginalTerminal -Owner $statusOwner -Role StatusNested
                Complete-QualificationOriginalCreatorOwner $statusOwner
            }
        },
        {
            $retainedStatusOwner=Get-Variable statusOwner -ValueOnly -ErrorAction SilentlyContinue
            if ($null-ne$retainedStatusOwner-and(-not $retainedStatusOwner.Disposed -or $retainedStatusOwner.Unsafe)) { throw 'Preserve original crash custody before fixture deletion.' }
            if (-not $recoveryCleanup.childOutputVerified -or -not $recoveryCleanup.descendantsAbsent) { throw 'Preserve recovery state until child output and descendant absence are verified.' }
            if ($null -ne $recoveryBodyError -and (Test-QualificationCleanupUnverified -Exception $recoveryBodyError.Exception)) { throw 'Preserve unverified child recovery state.' }

            $resolved=[IO.Path]::GetFullPath($testRoot)
            if (-not $resolved.StartsWith($allowedRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Recovery cleanup escaped its owned parent.' }
            if ([IO.Directory]::Exists($resolved)) { Remove-Item -LiteralPath $resolved -Recurse -Force }
            if ([IO.Directory]::Exists($resolved)) { throw 'Owned recovery directory absence remains unverified.' }
        }
    )
}
Write-Output 'PASS: generated ordinary interruption stops its nested process tree; deliberate recovery refuses foreign paths and never resumes collection.'
