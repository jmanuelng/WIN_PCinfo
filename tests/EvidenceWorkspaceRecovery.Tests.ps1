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
    param([Parameter()] [switch] $StaleOwner)

    $caseRoot = Join-Path $testRoot ([guid]::NewGuid().ToString('N'))
    $workspaceBase = Join-Path $caseRoot 'workspace-base'
    $recoveryBase = Join-Path $caseRoot 'recovery-base'
    $null = [System.IO.Directory]::CreateDirectory($workspaceBase)
    $null = [System.IO.Directory]::CreateDirectory($recoveryBase)
    $workspace = New-EvidenceWorkspace -RequestedBasePath $workspaceBase `
        -RunId ([guid]::NewGuid())

    $ownerProcess = $null
    if ($StaleOwner) {
        $start = [System.Diagnostics.ProcessStartInfo]::new()
        $start.FileName = Join-Path $PSHOME 'pwsh.exe'
        $start.UseShellExecute = $false
        $null = $start.ArgumentList.Add('-NoLogo')
        $null = $start.ArgumentList.Add('-NoProfile')
        $null = $start.ArgumentList.Add('-Command')
        $null = $start.ArgumentList.Add('[System.Threading.Thread]::Sleep(30000)')
        $ownerProcess = [System.Diagnostics.Process]::Start($start)
    }
    try {
        $journal = New-RunRecoveryJournal -Workspace $workspace `
            -RecoveryBasePath $recoveryBase -PlanDigest ('b' * 64) `
            -Phase 'Collection' -OwnerProcess $ownerProcess
    }
    finally {
        if ($null -ne $ownerProcess) {
            if (-not $ownerProcess.HasExited) {
                $ownerProcess.Kill($true)
                $ownerProcess.WaitForExit()
            }
            $ownerProcess.Dispose()
        }
    }
    [pscustomobject]@{
        Workspace = $workspace
        Journal = $journal
    }
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

    $stale = New-RecoveryTestContext -StaleOwner
    $interrupted = Add-TemporaryEvidence -JournalPath $stale.Journal.journalPath `
        -Content ([System.Text.Encoding]::UTF8.GetBytes('interrupted-marker'))
    $staleResult = Invoke-StaleRunRecovery -JournalPath $stale.Journal.journalPath
    Assert-Equal 'NotStarted' $staleResult.outcome `
        'verified stale cleanup ends preflight without starting a new collection'
    Assert-Equal 'RECOVERY.STALE_RESIDUE_REMOVED' $staleResult.reasonCode `
        'successful stale cleanup has one stable terminal reason'
    Assert-Equal $true $staleResult.cleanup.verified `
        'success is returned only after every cleanup target is absent'
    Assert-Equal $false $staleResult.collectionResumed `
        'stale recovery is cleanup-only'
    Assert-Equal $false ([System.IO.File]::Exists($interrupted.literalPath)) `
        'interrupted Temporary Evidence is removed by exact registration'
    Assert-Equal $false ([System.IO.Directory]::Exists($stale.Workspace.workspacePath)) `
        'the empty registered workspace is verified absent'
    Assert-Equal $false ([System.IO.File]::Exists($stale.Journal.journalPath)) `
        'the journal is removed last after absence proof'

    $ambiguous = New-RecoveryTestContext -StaleOwner
    $ambiguousTemporary = Add-TemporaryEvidence -JournalPath $ambiguous.Journal.journalPath `
        -Content ([System.Text.Encoding]::UTF8.GetBytes('original-marker'))
    $movedOriginal = $ambiguousTemporary.literalPath + '.moved'
    [System.IO.File]::Move($ambiguousTemporary.literalPath, $movedOriginal)
    [System.IO.File]::WriteAllText($ambiguousTemporary.literalPath, 'replacement-marker')
    $ambiguousResult = Invoke-StaleRunRecovery -JournalPath $ambiguous.Journal.journalPath
    Assert-Equal 'CleanupIncomplete' $ambiguousResult.outcome `
        'a path whose filesystem identity changed cannot be guessed as owned'
    Assert-Equal 'RECOVERY.OWNERSHIP_UNVERIFIED' $ambiguousResult.reasonCode `
        'ambiguous ownership provides one actionable cleanup reason'
    Assert-Equal $true ([System.IO.File]::Exists($ambiguousTemporary.literalPath)) `
        'the unverifiable replacement remains untouched'
    Assert-Equal $true ([System.IO.File]::Exists($ambiguous.Journal.journalPath)) `
        'the journal remains until ambiguity is resolved'

    $preserved = New-RecoveryTestContext -StaleOwner
    $packagePath = Join-Path $preserved.Workspace.workspacePath 'assessment.winpci'
    [System.IO.File]::WriteAllBytes($packagePath, [byte[]](1, 2, 3, 4))
    Register-FinalizedEvidencePackage -JournalPath $preserved.Journal.journalPath `
        -LiteralPath $packagePath | Out-Null
    $preservedResult = Invoke-StaleRunRecovery -JournalPath $preserved.Journal.journalPath
    Assert-Equal 'NotStarted' $preservedResult.outcome `
        'a finalized package is compatible with verified cleanup-only recovery'
    Assert-Equal $true $preservedResult.cleanup.verified `
        'preservation is verified without treating the package as residue'
    Assert-Equal $true ([System.IO.File]::Exists($packagePath)) `
        'recovery never removes a finalized Protected Evidence Package'
    Assert-Equal $true ([System.IO.Directory]::Exists($preserved.Workspace.workspacePath)) `
        'the access-restricted workspace remains around its preserved package'
    Assert-Equal $false ([System.IO.File]::Exists($preserved.Journal.journalPath)) `
        'the journal is removable after preserved-object identity and cleanup absence are verified'
    Assert-Equal 'ObserveOnly' $preservedResult.windowsFeatures.action `
        'stale recovery treats Windows Feature state as observation only'
    Assert-Equal $false $preservedResult.windowsFeatures.changesAttempted `
        'recovery never disables an existing Windows Feature'

    $blocked = New-RecoveryTestContext -StaleOwner
    $blockedTemporary = Add-TemporaryEvidence -JournalPath $blocked.Journal.journalPath `
        -Content ([System.Text.Encoding]::UTF8.GetBytes('locked-marker'))
    $lock = [System.IO.FileStream]::new(
        $blockedTemporary.literalPath, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::None
    )
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
