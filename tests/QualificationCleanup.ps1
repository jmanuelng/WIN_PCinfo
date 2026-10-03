Set-StrictMode -Version Latest

function Get-QualificationCleanupBlockerPath {
    Join-Path (Split-Path -Parent $PSScriptRoot) '.test-output/qualification-cleanup-blocked.json'
}

function Assert-QualificationCleanupReady {
    $blocker=Get-QualificationCleanupBlockerPath
    if ([IO.File]::Exists($blocker) -or [IO.Directory]::Exists($blocker)) {
        throw 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: verify the preserved owned state before starting another test.'
    }
}

function Test-QualificationCleanupUnverified {
    param([AllowNull()] [Exception] $Exception)
    if ($null -eq $Exception) { return $false }
    if ($Exception.Data['OwnedCleanupUnverified'] -eq $true) { return $true }
    if ($Exception -is [AggregateException]) {
        foreach ($inner in $Exception.InnerExceptions) {
            if (Test-QualificationCleanupUnverified -Exception $inner) { return $true }
        }
    }
    if ($null -ne $Exception.InnerException) {
        return (Test-QualificationCleanupUnverified -Exception $Exception.InnerException)
    }
    return $false
}

function Assert-QualificationCleanupSignal {
    param([AllowEmptyCollection()] [object[]] $Output)
    if (@($Output | ForEach-Object { $_.ToString() -split '\r?\n' } | Where-Object { $_ -eq 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED' }).Count) {
        $exception=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: native child cleanup remains unverified.')
        $exception.Data['OwnedCleanupUnverified']=$true
        throw $exception
    }
}

function Assert-QualificationTestProcessResult {
    param([AllowEmptyCollection()] [object[]] $Output, [int] $ExitCode)
    Assert-QualificationCleanupSignal -Output $Output
    if ($ExitCode -ne 0) { throw "Assessment qualification child failed with exit code $ExitCode." }
    Assert-QualificationCleanupReady
}

function Invoke-QualificationTestProcess {
    param([Parameter(Mandatory)] [string] $HostPath, [Parameter(Mandatory)] [string[]] $Arguments)
    Assert-QualificationCleanupReady
    $caseOutput=@(& $HostPath @Arguments 2>&1)
    $caseExitCode=$LASTEXITCODE
    foreach ($line in $caseOutput) { Write-Output $line }
    Assert-QualificationTestProcessResult -Output $caseOutput -ExitCode $caseExitCode
}


function Assert-QualificationOwnedCleanupResult {
    param([AllowNull()] [object] $Result)
    # Inspect actual controller cleanup before behavior assertions can obscure
    # the unsafe state. Missing fields or a non-Boolean value fail inside the
    # shared finalizer, retaining its durable and in-process stop signals.
    Complete-QualificationHarness -Cleanup @({
        if ($null -eq $Result -or
            ($Result.PSObject.BaseObject -isnot [Collections.IDictionary] -and
             $Result.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject])) {
            throw 'Actual owned controller result is not a scalar record.'
        }
        $cleanup=$Result.cleanup
        if ($null -eq $cleanup -or
            ($cleanup.PSObject.BaseObject -isnot [Collections.IDictionary] -and
             $cleanup.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject]) -or
            $cleanup.verified -isnot [bool] -or -not $cleanup.verified) {
            throw 'Actual owned controller cleanup is not strictly verified.'
        }
    })
}

function Complete-QualificationHarness {
    param(
        [AllowNull()] [Management.Automation.ErrorRecord] $BodyError,
        [scriptblock] $RetainEvidence,
        [scriptblock[]] $Cleanup = @(),
        [scriptblock] $RetainCleanupEvidence
    )
    $failures=[Collections.Generic.List[Exception]]::new()
    if ($null -ne $BodyError) { $failures.Add($BodyError.Exception) }
    if ($null -ne $RetainEvidence) {
        try { . $RetainEvidence }
        catch { $failures.Add([InvalidOperationException]::new('Qualification evidence retention failed.', $_.Exception)) }
    }
    $cleanupFailed=($null -ne $BodyError -and (Test-QualificationCleanupUnverified -Exception $BodyError.Exception))
    foreach ($action in $Cleanup) {
        try { & $action }
        catch {
            $cleanupFailed=$true
            $failures.Add([InvalidOperationException]::new('Qualification owned cleanup failed.', $_.Exception))
        }
    }
    if ($cleanupFailed) {
        # A native parent can observe this stable signal even if persisting the
        # blocker fails. It must propagate the unsafe state with the exception.
        Write-Output 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED'
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
