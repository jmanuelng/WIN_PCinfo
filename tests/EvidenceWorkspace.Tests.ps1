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
    Join-Path $repositoryRoot ".test-output/evidence-workspace-$([guid]::NewGuid().ToString('N'))"
))
$allowedRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))
if (-not $testRoot.StartsWith($allowedRoot + [System.IO.Path]::DirectorySeparatorChar,
    [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The isolated Evidence Workspace test root escaped .test-output.'
}
$null = [System.IO.Directory]::CreateDirectory($testRoot)

try {
    $eligibleBase = Join-Path $testRoot 'eligible'
    $null = [System.IO.Directory]::CreateDirectory($eligibleBase)
    $runId = [guid]::NewGuid().ToString('D')
    $workspace = New-EvidenceWorkspace -RequestedBasePath $eligibleBase -RunId $runId

    Assert-Equal 'Created' $workspace.state `
        'an eligible local destination creates one new per-run workspace'
    Assert-Equal $true ([System.IO.Directory]::Exists($workspace.workspacePath)) `
        'the exported result names a workspace that actually exists'
    Assert-Equal $runId $workspace.runId `
        'the workspace retains only its run-scoped identity'

    $acl = Get-Acl -LiteralPath $workspace.workspacePath
    Assert-Equal $true $acl.AreAccessRulesProtected `
        'the workspace does not inherit ambient access'
    $initiatingSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Assert-Equal $initiatingSid $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value `
        'the initiating Windows user owns the Evidence Workspace'
    $actualSids = @($acl.Access | ForEach-Object {
        $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } | Sort-Object -Unique)
    Assert-Equal (($initiatingSid, 'S-1-5-18' | Sort-Object) -join '|') `
        (($actualSids | Sort-Object) -join '|') `
        'only the initiating user and LocalSystem are granted access'

    $unsafe = New-EvidenceWorkspace -RequestedBasePath '\\synthetic.invalid\share' `
        -RunId ([guid]::NewGuid().ToString('D'))
    Assert-Equal 'Rejected' $unsafe.state `
        'a network location is rejected before workspace creation'
    Assert-Equal 'WORKSPACE.DESTINATION_NETWORK' $unsafe.reasonCode `
        'unsafe destination guidance states the exact restriction'
    Assert-Equal ([System.Environment]::GetFolderPath('LocalApplicationData')) `
        $unsafe.safeAlternative `
        'rejection supplies one local per-user alternative'

    $missing = New-EvidenceWorkspace -RequestedBasePath (Join-Path $testRoot 'missing') `
        -RunId ([guid]::NewGuid())
    Assert-Equal 'WORKSPACE.DESTINATION_NOT_FOUND' $missing.reasonCode `
        'a nonexistent destination receives its specific restriction'
    $rootDestination = New-EvidenceWorkspace -RequestedBasePath (
        [System.IO.Path]::GetPathRoot($testRoot)
    ) -RunId ([guid]::NewGuid())
    Assert-Equal 'WORKSPACE.DESTINATION_ROOT' $rootDestination.reasonCode `
        'a volume root receives its specific restriction'
    $alternativeDecision = Test-EvidenceWorkspaceDestination `
        -RequestedBasePath $unsafe.safeAlternative -RunId ([guid]::NewGuid())
    Assert-Equal $true $alternativeDecision.eligible `
        'the offered safe alternative is itself immediately eligible'

    $recoveryBase = Join-Path $testRoot 'recovery-base'
    $null = [System.IO.Directory]::CreateDirectory($recoveryBase)
    $journalResult = New-RunRecoveryJournal -Workspace $workspace `
        -RecoveryBasePath $recoveryBase -PlanDigest ('a' * 64) -Phase 'Collection'
    Assert-Equal 'Created' $journalResult.state `
        'an accepted workspace creates one access-restricted recovery journal'
    $journalJson = [System.IO.File]::ReadAllText(
        $journalResult.journalPath, [System.Text.UTF8Encoding]::new($false, $true)
    )
    Assert-Equal $true (Test-Json -Json $journalJson `
        -SchemaFile (Join-Path $repositoryRoot 'schemas/run-recovery-journal.schema.json')) `
        'the journal satisfies its closed non-secret schema'
    $journal = $journalJson | ConvertFrom-Json -Depth 20
    Assert-Equal 'Collection' $journal.phase `
        'the journal records the lifecycle phase needed by cleanup'
    Assert-Equal 1 @($journal.artifacts).Count `
        'the new workspace is the only initially registered cleanup artifact'
    Assert-Equal 'Workspace' $journal.artifacts[0].kind `
        'the journal records an exact owned workspace, not generic evidence'
    if ($journalJson -match '(?i)observation|assessmentRecord|credential|password|secret|recipientProfile|crossRun') {
        throw 'The recovery journal exposed evidence, a secret channel, or cross-run identity.'
    }

    $privateMarker = [System.Text.UTF8Encoding]::new($false).GetBytes(
        'synthetic-private-evidence-marker'
    )
    $temporary = Add-TemporaryEvidence -JournalPath $journalResult.journalPath `
        -Content $privateMarker
    Assert-Equal 'Registered' $temporary.state `
        'bounded Temporary Evidence is registered before it can survive interruption'
    Assert-Equal $true ([System.IO.File]::Exists($temporary.literalPath)) `
        'the temporary artifact exists only inside the Evidence Workspace'
    $registeredJournalText = [System.IO.File]::ReadAllText($journalResult.journalPath)
    if ($registeredJournalText.Contains('synthetic-private-evidence-marker')) {
        throw 'Temporary Evidence content entered the non-secret recovery journal.'
    }

    $ingestedDigest = ''
    $ingested = Complete-TemporaryEvidenceIngestion -JournalPath $journalResult.journalPath `
        -ArtifactId $temporary.artifactId -IngestAction {
            param([byte[]] $Bytes)
            $script:ingestedDigest = Get-EvidenceWorkspaceSha256 -Bytes $Bytes
        }
    Assert-Equal 'IngestedAndRemoved' $ingested.state `
        'same-run ingestion removes the unprotected artifact after the consumer accepts it'
    Assert-Equal '0de0367f6137df6109a8b4c2bb280aa5637ccb932e9496391219ab6ad25dc47d' `
        $ingestedDigest 'the ingestion seam receives the exact synthetic bytes'
    Assert-Equal $false ([System.IO.File]::Exists($temporary.literalPath)) `
        'ingested Temporary Evidence is absent before success is returned'

    $tooLarge = Add-TemporaryEvidence -JournalPath $journalResult.journalPath `
        -Content ([byte[]]::new(1048577))
    Assert-Equal 'Rejected' $tooLarge.state `
        'an artifact above the release byte ceiling is rejected before file creation'
    Assert-Equal 'TEMPORARY_EVIDENCE.SIZE_EXCEEDED' $tooLarge.reasonCode `
        'the evidence bound has one actionable stable reason'

    $ownerMismatchTemporary = Add-TemporaryEvidence -JournalPath $journalResult.journalPath `
        -Content ([System.Text.Encoding]::UTF8.GetBytes('same-run-owner-marker'))
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $PSHOME 'pwsh.exe'
    $start.UseShellExecute = $false
    $null = $start.ArgumentList.Add('-NoLogo')
    $null = $start.ArgumentList.Add('-NoProfile')
    $null = $start.ArgumentList.Add('-Command')
    $null = $start.ArgumentList.Add('[System.Threading.Thread]::Sleep(30000)')
    $otherOwner = [System.Diagnostics.Process]::Start($start)
    try {
        $ownerMismatchJournal = Read-RunRecoveryJournal -LiteralPath $journalResult.journalPath
        $ownerMismatchJournal.owner.processId = $otherOwner.Id
        $ownerMismatchJournal.owner.processStartUtc = `
            $otherOwner.StartTime.ToUniversalTime().ToString('O')
        Write-RunRecoveryJournal -Journal $ownerMismatchJournal `
            -LiteralPath $journalResult.journalPath
        $ownerMismatch = Complete-TemporaryEvidenceIngestion `
            -JournalPath $journalResult.journalPath `
            -ArtifactId $ownerMismatchTemporary.artifactId `
            -IngestAction { throw 'A later process must not receive the bytes.' }
        Assert-Equal 'IngestionFailed' $ownerMismatch.state `
            'a different process cannot ingest evidence from the prior run'
        Assert-Equal 'TEMPORARY_EVIDENCE.RUN_OWNER_MISMATCH' $ownerMismatch.reasonCode `
            'same-user process reuse has one stable rejection reason'
        Assert-Equal $true ([System.IO.File]::Exists($ownerMismatchTemporary.literalPath)) `
            'owner mismatch leaves evidence registered for cleanup rather than exposing it'
    }
    finally {
        if (-not $otherOwner.HasExited) {
            $otherOwner.Kill($true)
            $otherOwner.WaitForExit()
        }
        $otherOwner.Dispose()
    }
}
finally {
    if ([System.IO.Directory]::Exists($testRoot)) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}

Write-Output 'PASS: eligible workspaces receive an exact protected ACL and unsafe destinations fail with a safe alternative.'
