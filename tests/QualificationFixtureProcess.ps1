Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'GeneratedApplicationNative.ps1')

# This owner is only for the three closed, child-free Sleep(30000) fixtures.
# Admission is inherited from the verified File/Case bootstrap. It grants no
# original-handle ownership; that is established separately after Process.Start.
function Get-QualificationFixtureAdmission {
    param([Parameter(Mandatory)] [string] $RepositoryRoot)
    if ($null -eq (Get-Command Get-TestNativeAdmissionContext -ErrorAction SilentlyContinue)) {
        throw 'Fixture process requires the reviewed File/Case admission API.'
    }
    Assert-TestNativeRoleReady -NativeRole GeneratedApplication -RepositoryRoot $RepositoryRoot
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $RepositoryRoot -SelfIdentity (Get-TestNativeSelfIdentity)
    if ($null -eq $context.Parent) { throw 'Fixture process requires an admitted File/Case parent.' }
    $end=[DateTimeOffset]::ParseExact($context.Parent.Pending.authorityEnds,'o',[Globalization.CultureInfo]::InvariantCulture)
    $end=$end.AddMilliseconds(-[long]$context.Parent.Pending.cleanupReserveMs-2000)
    if ([string]::IsNullOrEmpty($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC)) { throw 'Fixture process inherited deadline is missing.' }
    $inherited=[DateTimeOffset]::ParseExact($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC,'o',[Globalization.CultureInfo]::InvariantCulture)
    if ($inherited.Offset -ne [TimeSpan]::Zero -or $end.Offset -ne [TimeSpan]::Zero) { throw 'Fixture process deadline must be UTC.' }
    if ($inherited -lt $end) { $end=$inherited }
    [pscustomobject]@{Ends=$end; Parent=$context.Parent; Creator=(Get-TestNativeSelfIdentity)}
}

function Write-QualificationFixtureRecord {
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] $Value)
    $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes(($Value | ConvertTo-Json -Depth 12))
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $stream.Write($bytes); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Get-QualificationFixtureRemainingMs {
    param([Parameter(Mandatory)] $Owner)
    [long][Math]::Floor($Owner.BudgetMs-$Owner.Clock.Elapsed.TotalMilliseconds)
}

function Assert-QualificationFixtureProcessAdmission {
    param([Parameter(Mandatory)] $Owner)
    if ($Owner.Started -or (Get-QualificationFixtureRemainingMs -Owner $Owner) -lt 7000) {
        throw 'Fixture process requires at least 7000 ms of unchanged admitted authority before creation.'
    }
}

function New-QualificationFixtureProcessOwner {
    param([Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter(Mandatory)] [Diagnostics.ProcessStartInfo] $StartInfo)
    $admission=Get-QualificationFixtureAdmission -RepositoryRoot $RepositoryRoot
    $arguments=@($StartInfo.ArgumentList)
    if ($StartInfo.FileName -ine (Join-Path $PSHOME 'pwsh.exe') -or $StartInfo.UseShellExecute -or
        $StartInfo.RedirectStandardOutput -or $StartInfo.RedirectStandardError -or
        -not [string]::IsNullOrEmpty($StartInfo.UserName) -or $arguments.Count -ne 4 -or
        $arguments[0] -cne '-NoLogo' -or $arguments[1] -cne '-NoProfile' -or $arguments[2] -cne '-Command' -or
        $arguments[3] -cnotin @('[System.Threading.Thread]::Sleep(30000)','[Threading.Thread]::Sleep(30000)')) {
        throw 'Fixture process owner accepts only the exact closed sleeper creator.'
    }
    $now=[DateTimeOffset]::UtcNow
    $budget=[long][Math]::Floor([Math]::Min(35000,($admission.Ends-$now).TotalMilliseconds))
    if ($budget -lt 7000) { throw 'Fixture process has insufficient creation and retention reserve.' }
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $parent=[IO.Path]::GetFullPath((Join-Path $RepositoryRoot '.test-output/fixture-process'))
    $null=[IO.Directory]::CreateDirectory($parent)
    if (((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ((Get-Item -LiteralPath (Split-Path -Parent $parent)).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Fixture process evidence parent cannot be redirected.'
    }
    foreach ($existing in @(Get-ChildItem -LiteralPath $parent -Directory -Force)) {
        if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            [IO.File]::Exists((Join-Path $existing.FullName 'owned-pending.json'))) {
            throw 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: fixture ownership requires root recovery.'
        }
    }
    $directory=Join-Path $parent ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    $null=Set-TestNativePrivateDirectory -Path $directory
    $pending=[ordered]@{contract='win-pcinfo.fixture-process/1.0.0'; scope='OriginalChildFreeSleeperOnly';
        creationRequested=$false; originalProcessIdentity=$null; creator=$admission.Creator;
        sidProvenance='Original creator Windows token; ProcessStartInfo supplies no alternate user.';
        hostPath=$StartInfo.FileName; hostSha256=(Get-FileHash -LiteralPath $StartInfo.FileName -Algorithm SHA256).Hash.ToLowerInvariant();
        arguments=$arguments; authorityEnds=$admission.Ends.ToString('o'); localBudgetMs=$budget;
        admittedParentPendingCanonicalSha256=(Get-TestNativeDigest -Value $admission.Parent.Pending);
        cleanupMaximumMs=5000; retentionReserveMs=1000; processTreeAbsenceClaim=$false}
    Write-QualificationFixtureRecord -Path (Join-Path $directory 'original-pending.json') -Value $pending
    Write-QualificationFixtureRecord -Path (Join-Path $directory 'owned-pending.json') -Value $pending
    $owner=[pscustomobject]@{Directory=$directory; Pending=$pending; Clock=$clock; BudgetMs=$budget;
        Process=$null; SafeHandle=$null; Identity=$null; Started=$false; TerminalVerified=$false;
        TerminalRetained=$false; Disposed=$false; Unsafe=$false}
    # Keep original handles reachable even when a test terminates with an unsafe
    # exception. This in-process reference cannot survive death of its host.
    if ($null -eq (Get-Variable QualificationFixtureOwners -Scope Script -ErrorAction SilentlyContinue)) {
        $script:QualificationFixtureOwners=[Collections.Generic.List[object]]::new()
    }
    $script:QualificationFixtureOwners.Add($owner)
    Assert-QualificationFixtureProcessAdmission -Owner $owner
    $owner
}

function Get-QualificationFixtureOriginalIdentity {
    param([Parameter(Mandatory)] $Process)
    if ($Process -isnot [Diagnostics.Process]) { throw 'Fixture identity requires its actual original creator Process.' }
    $handle=$Process.SafeHandle
    if ($handle.IsClosed -or $handle.IsInvalid) { throw 'Original fixture process handle is not valid.' }
    [pscustomobject]@{Handle=$handle; Record=[ordered]@{pid=$Process.Id;
        fullBirthUtc=$Process.StartTime.ToUniversalTime().ToString('o');
        originalSafeHandleValue=$handle.DangerousGetHandle().ToInt64();
        handleProvenance='SafeHandle of the original Process.Start result; no PID reopen.'}}
}

function Register-QualificationFixtureProcess {
    param([Parameter(Mandatory)] $Owner, [Parameter(Mandatory)] $Process)
    # Set this before any fallible observation/retention so finally still owns the
    # actual creator result if full identity acquisition fails.
    $Owner.Process=$Process
    $Owner.Started=$true
    try {
        $Owner.SafeHandle=$Process.SafeHandle
        $identity=Get-QualificationFixtureOriginalIdentity -Process $Process
        $Owner.SafeHandle=$identity.Handle
        $Owner.Identity=$identity.Record
        Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory 'original-identity.json') -Value ([ordered]@{
            identity=$Owner.Identity; creator=$Owner.Pending.creator; hostPath=$Owner.Pending.hostPath;
            hostSha256=$Owner.Pending.hostSha256; arguments=$Owner.Pending.arguments; sidProvenance=$Owner.Pending.sidProvenance})
    }
    catch { $Owner.Unsafe=$true; throw }
}

function Close-QualificationFixtureProcess {
    param([Parameter(Mandatory)] $Owner, [AllowNull()] $Process)
    $failures=[Collections.Generic.List[Exception]]::new()
    $exitCode=$null
    if ($null -ne $Process -and $null -eq $Owner.Process) { $Owner.Process=$Process; $Owner.Started=$true; $Owner.Unsafe=$true }
    try {
        if ($Owner.Started) {
            if ($null -eq $Owner.SafeHandle -or $Owner.SafeHandle.IsClosed -or $Owner.SafeHandle.IsInvalid) {
                $Owner.Unsafe=$true
                throw 'Original fixture handle could not be pinned; terminal ownership is unknown.'
            }
            $terminal=$Owner.Process.WaitForExit(0)
            if ($terminal -isnot [bool]) { throw 'Fixture terminal observation is not Boolean.' }
            if (-not $terminal) {
                $remaining=Get-QualificationFixtureRemainingMs -Owner $Owner
                if ($remaining -le 1000) { throw 'Fixture cleanup authority is exhausted; original state is retained.' }
                $Owner.Process.Kill() # Parent only; exact closed sleeper cannot create children.
                $wait=[int][Math]::Min(5000,(Get-QualificationFixtureRemainingMs -Owner $Owner)-1000)
                if ($wait -lt 1) { throw 'Fixture terminal wait has no retention reserve.' }
                $terminal=$Owner.Process.WaitForExit($wait)
                if ($terminal -isnot [bool] -or -not $terminal) { throw 'Fixture original process terminal completion is unverified.' }
            }
            $Owner.TerminalVerified=$true
            $exitCode=$Owner.Process.ExitCode
        }
        else { $Owner.TerminalVerified=$true }
    }
    catch { $Owner.Unsafe=$true; $failures.Add($_.Exception) }
    $terminalRecord=[ordered]@{identity=$Owner.Identity; creator=$Owner.Pending.creator;
        started=$Owner.Started; originalHandleTerminalVerified=$Owner.TerminalVerified;
        exitCode=$exitCode; unsafeBeforeTerminalRetention=$Owner.Unsafe; disposed=$false;
        cleanupAcceptanceClaim=$false; processTreeAbsenceClaim=$false}
    # Independent immutable copies are attempted before Dispose or root deletion.
    foreach ($name in @('original-terminal.json','terminal.json')) {
        try { Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory $name) -Value $terminalRecord }
        catch { $Owner.Unsafe=$true; $failures.Add($_.Exception) }
    }
    $Owner.TerminalRetained=$failures.Count -eq 0
    if ((Get-QualificationFixtureRemainingMs -Owner $Owner) -lt 0) {
        $Owner.Unsafe=$true
        $failures.Add([InvalidOperationException]::new('Fixture retention exceeded its unchanged authority.'))
    }
    if (-not $Owner.Unsafe -and $Owner.TerminalVerified -and $Owner.TerminalRetained) {
        try {
            if ($Owner.Started) { $Owner.Process.Dispose(); $Owner.Disposed=$true }
            [IO.File]::Delete((Join-Path $Owner.Directory 'owned-pending.json'))
            if ([IO.File]::Exists((Join-Path $Owner.Directory 'owned-pending.json'))) { throw 'Fixture pending marker remains.' }
        }
        catch { $Owner.Unsafe=$true; $failures.Add($_.Exception) }
    }
    if ($Owner.Unsafe -or $failures.Count) {
        $exception=[AggregateException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: original fixture state is retained.',$failures.ToArray())
        $exception.Data['OwnedCleanupUnverified']=$true
        throw $exception
    }
}

function Complete-QualificationFixtureProcess {
    param([Parameter(Mandatory)] $Owner, [AllowNull()] $Process,
        [AllowNull()] [Management.Automation.ErrorRecord] $BodyError)
    if ($null -ne $BodyError -and (Test-QualificationCleanupUnverified -Exception $BodyError.Exception)) { $Owner.Unsafe=$true }
    Complete-QualificationHarness -BodyError $BodyError -Cleanup @({ Close-QualificationFixtureProcess -Owner $Owner -Process $Process })
}

function Remove-QualificationFixtureRoot {
    param([Parameter(Mandatory)] [string] $Root, [Parameter(Mandatory)] [string] $AllowedRoot,
        [Parameter(Mandatory)] [bool] $Created,
        [AllowNull()] $Owner, [AllowNull()] [Management.Automation.ErrorRecord] $BodyError)
    if (-not $Created) { return }
    if (($null -ne $BodyError -and (Test-QualificationCleanupUnverified -Exception $BodyError.Exception)) -or
        ($null -ne $Owner -and ($Owner.Unsafe -or -not $Owner.TerminalVerified -or -not $Owner.TerminalRetained))) { return }
    $path=[IO.Path]::GetFullPath($Root)
    $boundary=[IO.Path]::GetFullPath($AllowedRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
    if (-not $path.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)) { throw 'Fixture cleanup root escaped its owned boundary.' }
    if ([IO.Directory]::Exists($path)) {
        $item=Get-Item -LiteralPath $path
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            @(Get-ChildItem -LiteralPath $path -Directory -Recurse -Force | Where-Object {($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0}).Count) { throw 'Fixture cleanup cannot traverse a reparse point.' }
        [IO.Directory]::Delete($path,$true)
    }
    if ([IO.Directory]::Exists($path) -or [IO.File]::Exists($path)) { throw 'Fixture root cleanup could not verify absence.' }
}
