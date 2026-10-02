Set-StrictMode -Version Latest

function Get-QualificationCleanupBlockerPath {
    Join-Path (Split-Path -Parent $PSScriptRoot) '.test-output/qualification-cleanup-blocked.json'
}

function Assert-QualificationCleanupReady {
    if ([IO.File]::Exists((Get-QualificationCleanupBlockerPath))) {
        throw 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: verify the preserved owned state before starting another test.'
    }
}

function Complete-QualificationHarness {
    param(
        [AllowNull()] [Management.Automation.ErrorRecord] $BodyError,
        [scriptblock] $RetainEvidence,
        [Parameter(Mandatory)] [scriptblock[]] $Cleanup,
        [scriptblock] $RetainCleanupEvidence
    )
    $failures=[Collections.Generic.List[Exception]]::new()
    if ($null -ne $BodyError) { $failures.Add($BodyError.Exception) }
    if ($null -ne $RetainEvidence) {
        try { . $RetainEvidence }
        catch { $failures.Add([InvalidOperationException]::new('Qualification evidence retention failed.', $_.Exception)) }
    }
    $cleanupFailed=$false
    foreach ($action in $Cleanup) {
        try { & $action }
        catch {
            $cleanupFailed=$true
            $failures.Add([InvalidOperationException]::new('Qualification owned cleanup failed.', $_.Exception))
        }
    }
    if ($cleanupFailed) {
        # Keep a durable, identifier-free inter-process stop signal. The owned
        # workspace is preserved by its cleanup action when a worker survives.
        try {
            [IO.File]::WriteAllText((Get-QualificationCleanupBlockerPath), '{"state":"OwnedCleanupUnverified"}', [Text.UTF8Encoding]::new($false))
        }
        catch { $failures.Add([InvalidOperationException]::new('Qualification cleanup blocker retention failed.', $_.Exception)) }
    }
    elseif ($null -ne $RetainCleanupEvidence) {
        try { & $RetainCleanupEvidence }
        catch { $failures.Add([InvalidOperationException]::new('Qualification cleanup evidence retention failed.', $_.Exception)) }
    }
    if ($failures.Count) {
        $message=if ($cleanupFailed) {'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: further test execution is blocked.'} else {'Qualification failed; body and evidence failures are retained.'}
        $exception=[AggregateException]::new($message, $failures.ToArray())
        $exception.Data['OwnedCleanupUnverified']=$cleanupFailed
        throw $exception
    }
}
