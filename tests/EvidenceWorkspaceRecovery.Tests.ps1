[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ContractValidator.ps1')
. (Join-Path $repositoryRoot 'src/EvidenceWorkspace.ps1')

$testRoot = [System.IO.Path]::GetFullPath((
    Join-Path $repositoryRoot ".test-output/evidence-recovery-$([guid]::NewGuid().ToString('N'))"
))
$allowedRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))
if (-not $testRoot.StartsWith($allowedRoot + [System.IO.Path]::DirectorySeparatorChar,
    [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The isolated recovery test root escaped .test-output.'
}
$null = [System.IO.Directory]::CreateDirectory($testRoot)

function New-RecoveryTestContext {
    $caseRoot = Join-Path $testRoot ([guid]::NewGuid().ToString('N'))
    $null = [System.IO.Directory]::CreateDirectory($caseRoot)
    New-EvidenceWorkspaceFixtureContext -Boundary ([pscustomobject]@{ CaseRoot = $caseRoot })
}

try {
    $live = New-RecoveryTestContext
    if ($live -is [array] -or $live.Journal.journalPath -isnot [string] -or
        -not [System.IO.Directory]::Exists([string] $live.Workspace.workspacePath) -or
        -not [System.IO.File]::Exists([string] $live.Journal.journalPath)) {
        throw 'The live recovery fixture did not produce one stable context.'
    }
    $liveTemporary = Add-TemporaryEvidence -JournalPath $live.Journal.journalPath `
        -Content ([System.Text.Encoding]::UTF8.GetBytes('live-owner-marker'))
    $liveResult = Invoke-StaleRunRecovery -JournalPath $live.Journal.journalPath
    Assert-Equal 'NotStarted' $liveResult.outcome `
        'a live owner prevents another run from entering cleanup'
    Assert-Equal 'RECOVERY.LIVE_OWNER' $liveResult.reasonCode `
        'live ownership has one stable no-action reason'
    Assert-Equal $false $liveResult.collectionResumed `
        'recovery never resumes collection, even for a live journal'
    Assert-Equal $true ([System.IO.File]::Exists($liveTemporary.literalPath)) `
        'the live owner temporary artifact is not disturbed'
    Assert-Equal $true ([System.IO.File]::Exists($live.Journal.journalPath)) `
        'the live owner journal remains available to its owner'

    $crashCaseRoot = Join-Path $testRoot 'crash-injection'
    $handoffPath = Join-Path $testRoot 'crash-handoff.json'
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $PSHOME 'pwsh.exe'
    $start.UseShellExecute = $false
    $null = $start.ArgumentList.Add('-NoLogo')
    $null = $start.ArgumentList.Add('-NoProfile')
    $null = $start.ArgumentList.Add('-File')
    $null = $start.ArgumentList.Add((Join-Path $PSScriptRoot `
        'helpers/Register-TemporaryEvidenceThenWait.ps1'))
    $null = $start.ArgumentList.Add('-RepositoryRoot')
    $null = $start.ArgumentList.Add($repositoryRoot)
    $null = $start.ArgumentList.Add('-CaseRoot')
    $null = $start.ArgumentList.Add($crashCaseRoot)
    $null = $start.ArgumentList.Add('-HandoffPath')
    $null = $start.ArgumentList.Add($handoffPath)
    $crashProcess = [System.Diagnostics.Process]::Start($start)
    try {
        $handoffDeadline = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not [System.IO.File]::Exists($handoffPath) -and
            -not $crashProcess.HasExited -and $handoffDeadline.ElapsedMilliseconds -lt 10000) {
            [System.Threading.Thread]::Sleep(25)
        }
        if (-not [System.IO.File]::Exists($handoffPath)) {
            throw 'The crash-injection child did not reach the registered-before-write seam.'
        }
        $crashProcess.Kill($true)
        $crashProcess.WaitForExit()
    }
    finally {
        if (-not $crashProcess.HasExited) {
            $crashProcess.Kill($true)
            $crashProcess.WaitForExit()
        }
        $crashProcess.Dispose()
    }
    $interrupted = Get-Content -LiteralPath $handoffPath -Raw | ConvertFrom-Json
    Assert-Equal 0 ([System.IO.FileInfo]::new([string] $interrupted.temporaryPath).Length) `
        'the child was stopped after registration and before the first evidence write'
    $staleResult = Invoke-StaleRunRecovery -JournalPath $interrupted.journalPath
    Assert-Equal 'NotStarted' $staleResult.outcome `
        'verified stale cleanup ends preflight without starting a new collection'
    Assert-Equal 'RECOVERY.STALE_RESIDUE_REMOVED' $staleResult.reasonCode `
        'successful stale cleanup has one stable terminal reason'
    Assert-Equal $true $staleResult.cleanup.verified `
        'success is returned only after every cleanup target is absent'
    Assert-Equal $false $staleResult.collectionResumed `
        'stale recovery is cleanup-only'
    Assert-Equal $false ([System.IO.File]::Exists([string] $interrupted.temporaryPath)) `
        'interrupted Temporary Evidence is removed by exact registration'
    Assert-Equal $false ([System.IO.Directory]::Exists([string] $interrupted.workspacePath)) `
        'the empty registered workspace is verified absent'
    Assert-Equal $false ([System.IO.File]::Exists([string] $interrupted.journalPath)) `
        'the journal is removed last after absence proof'

    $ambiguous = New-RecoveryTestContext
    $ambiguousTemporary = Add-TemporaryEvidence -JournalPath $ambiguous.Journal.journalPath `
        -Content ([System.Text.Encoding]::UTF8.GetBytes('original-marker'))
    $movedOriginal = $ambiguousTemporary.literalPath + '.moved'
    [System.IO.File]::Move($ambiguousTemporary.literalPath, $movedOriginal)
    [System.IO.File]::WriteAllText($ambiguousTemporary.literalPath, 'replacement-marker')
    Set-EvidenceWorkspaceFixtureOwnerStale -JournalPath $ambiguous.Journal.journalPath
    $ambiguousResult = Invoke-StaleRunRecovery -JournalPath $ambiguous.Journal.journalPath
    Assert-Equal 'CleanupIncomplete' $ambiguousResult.outcome `
        'a path whose filesystem identity changed cannot be guessed as owned'
    Assert-Equal 'RECOVERY.OWNERSHIP_UNVERIFIED' $ambiguousResult.reasonCode `
        'ambiguous ownership provides one actionable cleanup reason'
    Assert-Equal $true ([System.IO.File]::Exists($ambiguousTemporary.literalPath)) `
        'the unverifiable replacement remains untouched'
    Assert-Equal $true ([System.IO.File]::Exists($ambiguous.Journal.journalPath)) `
        'the journal remains until ambiguity is resolved'

    $preserved = New-RecoveryTestContext
    $packagePath = Join-Path $preserved.Workspace.workspacePath 'assessment.winpci'
    [System.IO.File]::WriteAllBytes($packagePath, [byte[]](1, 2, 3, 4))
    Register-FinalizedEvidencePackage -JournalPath $preserved.Journal.journalPath `
        -LiteralPath $packagePath | Out-Null
    Set-EvidenceWorkspaceFixtureOwnerStale -JournalPath $preserved.Journal.journalPath
    $preservedResult = Invoke-StaleRunRecovery -JournalPath $preserved.Journal.journalPath
    Assert-Equal 'CleanupIncomplete' $preservedResult.outcome `
        'registered preserved objects prevent a false verified-cleanup claim'
    Assert-Equal 'RECOVERY.FINALIZED_PACKAGE_PRESERVED' $preservedResult.reasonCode `
        'package preservation has a stable operator-action reason'
    Assert-Equal $false $preservedResult.cleanup.verified `
        'the journal cannot disappear while registered objects remain'
    Assert-Equal $true ([System.IO.File]::Exists($packagePath)) `
        'recovery never removes a finalized Protected Evidence Package'
    Assert-Equal $true ([System.IO.Directory]::Exists($preserved.Workspace.workspacePath)) `
        'the access-restricted workspace remains around its preserved package'
    Assert-Equal $true ([System.IO.File]::Exists($preserved.Journal.journalPath)) `
        'the journal remains while the finalized package and workspace stay registered'
    Assert-Equal 'ObserveOnly' $preservedResult.windowsFeatures.action `
        'stale recovery treats Windows Feature state as observation only'
    Assert-Equal $false $preservedResult.windowsFeatures.changesAttempted `
        'recovery never disables an existing Windows Feature'

    $handledPackagePath = Join-Path $testRoot `
        ('handled-' + [guid]::NewGuid().ToString('N') + '.winpci')
    [System.IO.File]::Move($packagePath, $handledPackagePath)
    $preservedRetry = Invoke-StaleRunRecovery -JournalPath $preserved.Journal.journalPath
    Assert-Equal 'NotStarted' $preservedRetry.outcome `
        'deliberately moving the preserved package makes the documented retry recoverable'
    Assert-Equal 'RECOVERY.STALE_RESIDUE_REMOVED' $preservedRetry.reasonCode `
        'the retry removes only the now-empty registered workspace and journal'
    Assert-Equal $true ([System.IO.File]::Exists($handledPackagePath)) `
        'recovery never deletes the finalized package moved by the operator'
    Assert-Equal $false ([System.IO.Directory]::Exists($preserved.Workspace.workspacePath)) `
        'the empty workspace is absent after the preserved-package retry'
    Assert-Equal $false ([System.IO.File]::Exists($preserved.Journal.journalPath)) `
        'the journal is removed only after all registered paths are absent'

    $interruptedJournal = New-RecoveryTestContext
    $interruptedJournalTemporary = Add-TemporaryEvidence `
        -JournalPath $interruptedJournal.Journal.journalPath `
        -Content ([System.Text.Encoding]::UTF8.GetBytes('journal-interruption-marker'))
    Set-EvidenceWorkspaceFixtureOwnerStale `
        -JournalPath $interruptedJournal.Journal.journalPath
    $pendingJournalPath = $interruptedJournal.Journal.journalPath + '.new'
    [System.IO.File]::WriteAllText($pendingJournalPath, '{"interrupted":true}')
    $interruptedJournalResult = Invoke-StaleRunRecovery `
        -JournalPath $interruptedJournal.Journal.journalPath
    Assert-Equal 'CleanupIncomplete' $interruptedJournalResult.outcome `
        'an interrupted atomic journal write cannot escape the terminal contract'
    Assert-Equal 'RECOVERY.JOURNAL_WRITE_INTERRUPTED' $interruptedJournalResult.reasonCode `
        'the ambiguous sibling receives one actionable stable reason'
    Assert-Equal $true ([System.IO.File]::Exists($pendingJournalPath)) `
        'recovery does not guess whether the interrupted journal sibling is safe to delete'
    Assert-Equal $true ([System.IO.File]::Exists($interruptedJournalTemporary.literalPath)) `
        'no registered evidence is touched while journal state is ambiguous'

    $initialWriteJournal = New-RecoveryTestContext
    $initialWriteTemporary = Add-TemporaryEvidence `
        -JournalPath $initialWriteJournal.Journal.journalPath `
        -Content ([System.Text.Encoding]::UTF8.GetBytes('initial-journal-interruption'))
    Set-EvidenceWorkspaceFixtureOwnerStale `
        -JournalPath $initialWriteJournal.Journal.journalPath
    $initialPendingPath = $initialWriteJournal.Journal.journalPath + '.new'
    [System.IO.File]::Copy($initialWriteJournal.Journal.journalPath, $initialPendingPath)
    [System.IO.File]::Delete($initialWriteJournal.Journal.journalPath)
    $initialWriteResult = Invoke-StaleRunRecovery `
        -JournalPath $initialWriteJournal.Journal.journalPath
    Assert-Equal 'CleanupIncomplete' $initialWriteResult.outcome `
        'a crash before the first journal rename still reaches a terminal result'
    Assert-Equal 'RECOVERY.JOURNAL_WRITE_INTERRUPTED' $initialWriteResult.reasonCode `
        'an initial-write sibling receives the same actionable interruption reason'
    Assert-Equal $true ([System.IO.File]::Exists($initialPendingPath)) `
        'the uncommitted initial journal remains untouched for deliberate inspection'
    Assert-Equal $true ([System.IO.File]::Exists($initialWriteTemporary.literalPath)) `
        'initial-write ambiguity cannot authorize evidence cleanup'

    $blocked = New-RecoveryTestContext
    $blockedTemporary = Add-TemporaryEvidence -JournalPath $blocked.Journal.journalPath `
        -Content ([System.Text.Encoding]::UTF8.GetBytes('locked-marker'))
    $lock = [System.IO.FileStream]::new(
        $blockedTemporary.literalPath, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::None
    )
    Set-EvidenceWorkspaceFixtureOwnerStale -JournalPath $blocked.Journal.journalPath
    try {
        $blockedResult = Invoke-StaleRunRecovery -JournalPath $blocked.Journal.journalPath
    }
    finally { $lock.Dispose() }
    Assert-Equal 'CleanupIncomplete' $blockedResult.outcome `
        'a removal that stays blocked cannot be reported as successful cleanup'
    Assert-Equal 'RECOVERY.CLEANUP_FAILED' $blockedResult.reasonCode `
        'cleanup failure has actionable stable guidance'
    Assert-Equal 2 $blockedResult.cleanup.attempts `
        'cleanup performs exactly one bounded idempotent retry'
    Assert-Equal $true ([System.IO.File]::Exists($blockedTemporary.literalPath)) `
        'failed cleanup leaves the exact artifact and journal for deliberate recovery'
    Assert-Equal $true ([System.IO.File]::Exists($blocked.Journal.journalPath)) `
        'the journal cannot disappear while a registered cleanup target survives'
}
finally {
    if ([System.IO.Directory]::Exists($testRoot)) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}

Write-Output 'PASS: live, stale, ambiguous, preserved-package, feature, interruption, and cleanup-failure recovery paths are fail-safe.'
