Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'QualificationFixtureProcess.ps1')

# Original-handle observation only: callers retain their reviewed Process.Start,
# owned Job, pipe/token admission and mutex operations. This is not a launcher.
function New-QualificationCapabilityProcessOwner {
    param([Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter(Mandatory)] [ValidateSet('SystemWorkerPeer','RunLifecycleLiveMutex','RunLifecycleAbandonedMutex')] [string] $Profile,
        [Parameter(Mandatory)] [Diagnostics.ProcessStartInfo] $StartInfo)
    $admission=Get-QualificationFixtureAdmission -RepositoryRoot $RepositoryRoot
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $RepositoryRoot -SelfIdentity $admission.Creator
    if ((Get-TestNativeDigest -Value $admission.Parent.Pending) -cne (Get-TestNativeDigest -Value $context.Parent.Pending)) {
        throw 'Capability admission changed between authority and source binding.'
    }
    $testName=if ($Profile -ceq 'SystemWorkerPeer') {'SystemWorkerPeer.Tests.ps1'} else {'RunLifecycle.Tests.ps1'}
    $testPath=Join-Path ([IO.Path]::GetFullPath($RepositoryRoot)) ('tests/'+$testName)
    if ($context.Parent.Admission.testPath -isnot [string] -or $context.Parent.Admission.testPath -ine $testPath -or
        @($context.Root.Admission.inputs | Where-Object path -IEQ $testPath).Count -ne 1) {
        throw 'Capability observer requires its exact currently admitted named source.'
    }
    $expectedHost=if ($Profile -ceq 'SystemWorkerPeer') {Join-Path $PSHOME 'pwsh.exe'} else {$admission.Creator.HostPath}
    $arguments=@($StartInfo.ArgumentList)
    if ($StartInfo.FileName -ine $expectedHost -or $StartInfo.UseShellExecute -or
        $StartInfo.RedirectStandardOutput -or $StartInfo.RedirectStandardError -or $StartInfo.RedirectStandardInput -or
        -not [string]::IsNullOrEmpty($StartInfo.UserName) -or $arguments.Count -ne 5 -or
        $arguments[0] -cne '-NoLogo' -or $arguments[1] -cne '-NoProfile' -or
        $arguments[2] -cne '-NonInteractive' -or $arguments[3] -cne '-EncodedCommand' -or
        [string]::IsNullOrEmpty($arguments[4])) { throw 'Capability observer creator differs from its closed profile.' }
    $decoded=[Text.UnicodeEncoding]::new($false,$false,$true).GetString([Convert]::FromBase64String($arguments[4]))
    if ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($decoded)) -cne $arguments[4]) {
        throw 'Capability observer encoded payload is not canonical.'
    }
    $budget=[long][Math]::Floor([Math]::Min(20000,($admission.Ends-[DateTimeOffset]::UtcNow).TotalMilliseconds))
    if ($budget -lt 7000) { throw 'Capability observer requires unchanged creation and retention reserve.' }
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $parent=Join-Path ([IO.Path]::GetFullPath($RepositoryRoot)) '.test-output/capability-process'
    $null=[IO.Directory]::CreateDirectory($parent)
    foreach ($path in @($parent,(Split-Path -Parent $parent))) {
        if (((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Capability evidence parent cannot be redirected.' }
    }
    foreach ($existing in @(Get-ChildItem -LiteralPath $parent -Directory -Force)) {
        if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            [IO.File]::Exists((Join-Path $existing.FullName 'owned-pending.json'))) {
            throw 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: capability ownership requires root recovery.'
        }
    }
    $directory=Join-Path $parent ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $directory
    $null=Set-TestNativePrivateDirectory -Path $directory
    $pending=[ordered]@{contract='win-pcinfo.capability-process/1.0.0';profile=$Profile;testPath=$testPath;
        testSha256=(Get-FileHash -LiteralPath $testPath).Hash.ToLowerInvariant();creator=$admission.Creator;
        hostPath=$StartInfo.FileName;hostSha256=(Get-FileHash -LiteralPath $StartInfo.FileName).Hash.ToLowerInvariant();arguments=$arguments;
        workingDirectory=$StartInfo.WorkingDirectory;inheritedWorkingDirectory=[Environment]::CurrentDirectory;
        createNoWindow=$StartInfo.CreateNoWindow;inputChannelRequested=$false;
        sidProvenance='Original creator token; no alternate ProcessStartInfo user.';
        authorityEnds=$admission.Ends.ToString('o');localBudgetMs=$budget;retentionReserveMs=1000;
        admittedParentPendingCanonicalSha256=(Get-TestNativeDigest -Value $context.Parent.Pending);
        originalProcessIdentity=$null;processTreeAbsenceClaim=$false}
    Write-QualificationFixtureRecord -Path (Join-Path $directory 'original-pending.json') -Value $pending
    Write-QualificationFixtureRecord -Path (Join-Path $directory 'owned-pending.json') -Value $pending
    $maximum=if ($Profile -ceq 'SystemWorkerPeer') {5000} elseif ($Profile -ceq 'RunLifecycleLiveMutex') {3000} else {2000}
    $owner=[pscustomobject]@{Directory=$directory;Pending=$pending;Clock=$clock;BudgetMs=$budget;
        MaximumWaitMs=$maximum;StartRequested=$false;Started=$false;Process=$null;SafeHandle=$null;Identity=$null;
        TerminalObservationAttempted=$false;TerminalVerified=$false;TerminalRetained=$false;ExitCode=$null;Disposed=$false;Unsafe=$false}
    if ($null -eq (Get-Variable QualificationCapabilityOwners -Scope Script -ErrorAction SilentlyContinue)) {
        $script:QualificationCapabilityOwners=[Collections.Generic.List[object]]::new()
    }
    $script:QualificationCapabilityOwners.Add($owner) # Strong references do not survive host death.
    $owner
}

function Assert-QualificationCapabilityCreation {
    param([Parameter(Mandatory)] $Owner)
    if ($Owner.StartRequested -or (Get-QualificationFixtureRemainingMs -Owner $Owner) -lt 7000) {
        throw 'Capability process requires unchanged creation and retention reserve.'
    }
    Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory 'original-creation-request.json') -Value ([ordered]@{
        originalPendingSha256=(Get-TestNativeDigest -Value $Owner.Pending);creationRequested=$true})
    $Owner.StartRequested=$true
}

function Register-QualificationCapabilityProcess {
    param([Parameter(Mandatory)] $Owner,[Parameter(Mandatory)] $Process)
    Register-QualificationFixtureProcess -Owner $Owner -Process $Process
}

function Wait-QualificationCapabilityTerminal {
    param([Parameter(Mandatory)] $Owner)
    if ($Owner.TerminalVerified) { return }
    try {
        if ($Owner.TerminalObservationAttempted) { throw 'Capability original terminal observation failed; no unchanged retry is permitted.' }
        if (-not $Owner.Started -or $null -eq $Owner.SafeHandle -or $Owner.SafeHandle.IsInvalid -or $Owner.SafeHandle.IsClosed) {
            throw 'Capability original creator handle is unavailable.'
        }
        $wait=[int][Math]::Min($Owner.MaximumWaitMs,(Get-QualificationFixtureRemainingMs -Owner $Owner)-1000)
        if ($wait -lt 1) { throw 'Capability terminal observation has no retention reserve.' }
        $Owner.TerminalObservationAttempted=$true
        $terminal=$Owner.Process.WaitForExit($wait)
        if ($terminal -isnot [bool] -or -not $terminal) { throw 'Capability original handle terminal completion is unverified.' }
        $exit=$Owner.Process.ExitCode
        if ($exit -isnot [int]) { throw 'Capability original native exit code is unknown.' }
        $Owner.ExitCode=$exit
        $Owner.TerminalVerified=$true
    }
    catch { $Owner.Unsafe=$true; throw }
}

function Close-QualificationCapabilityProcess {
    param([Parameter(Mandatory)] $Owner,[AllowNull()] $Process)
    if ($null -ne $Process -and $null -eq $Owner.Process) { $Owner.Process=$Process;$Owner.Started=$true;$Owner.Unsafe=$true }
    $failures=[Collections.Generic.List[Exception]]::new()
    try {
        if ($Owner.Started) { Wait-QualificationCapabilityTerminal -Owner $Owner }
        elseif ($Owner.StartRequested) { throw 'Capability creation was requested but its original outcome is unknown.' }
        else { $Owner.TerminalVerified=$true }
    }
    catch { $Owner.Unsafe=$true;$failures.Add($_.Exception) }
    $record=[ordered]@{identity=$Owner.Identity;creator=$Owner.Pending.creator;hostPath=$Owner.Pending.hostPath;
        hostSha256=$Owner.Pending.hostSha256;arguments=$Owner.Pending.arguments;profile=$Owner.Pending.profile;
        started=$Owner.Started;originalHandleTerminalVerified=$Owner.TerminalVerified;exitCode=$Owner.ExitCode;
        unsafeBeforeTerminalRetention=$Owner.Unsafe;disposed=$false;processTreeAbsenceClaim=$false}
    foreach ($name in @('original-terminal.json','terminal.json')) {
        try { Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory $name) -Value $record }
        catch { $Owner.Unsafe=$true;$failures.Add($_.Exception) }
    }
    $Owner.TerminalRetained=$failures.Count -eq 0
    if ((Get-QualificationFixtureRemainingMs -Owner $Owner) -lt 0) {
        $Owner.Unsafe=$true;$failures.Add([InvalidOperationException]::new('Capability retention exceeded unchanged authority.'))
    }
    if (-not $Owner.Unsafe -and $Owner.TerminalVerified -and $Owner.TerminalRetained) {
        try {
            if ($Owner.Started) { $Owner.Process.Dispose();$Owner.Disposed=$true }
            [IO.File]::Delete((Join-Path $Owner.Directory 'owned-pending.json'))
            if ([IO.File]::Exists((Join-Path $Owner.Directory 'owned-pending.json'))) { throw 'Capability pending marker remains.' }
        }
        catch { $Owner.Unsafe=$true;$failures.Add($_.Exception) }
    }
    if ($Owner.Unsafe -or $failures.Count) {
        $exception=[AggregateException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: original capability state is retained.',$failures.ToArray())
        $exception.Data['OwnedCleanupUnverified']=$true
        throw $exception
    }
}

function Complete-QualificationCapabilityProcess {
    param([AllowNull()] $Owner,[AllowNull()] $Process,
        [AllowNull()] [Management.Automation.ErrorRecord] $BodyError,[scriptblock[]] $Cleanup=@())
    if ($null -ne $Owner -and $null -ne $BodyError -and (Test-QualificationCleanupUnverified -Exception $BodyError.Exception)) { $Owner.Unsafe=$true }
    $actions=[Collections.Generic.List[scriptblock]]::new()
    foreach ($action in $Cleanup) {
        $actions.Add({try { & $action } catch { if ($null -ne $Owner) {$Owner.Unsafe=$true};throw }}.GetNewClosure())
    }
    $actions.Add({if ($null -ne $Owner) {Close-QualificationCapabilityProcess -Owner $Owner -Process $Process}})
    Complete-QualificationHarness -BodyError $BodyError -Cleanup $actions.ToArray()
}
