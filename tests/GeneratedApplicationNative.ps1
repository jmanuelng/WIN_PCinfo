Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')

function Initialize-GeneratedApplicationNativeSupervisor {
    $path=Join-Path $PSScriptRoot 'GeneratedApplicationNativeSupervisor.cs'
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $type='WinPCInfoTestGeneratedApplicationNativeSupervisor' -as [type]
    if ($null -ne $type) {
        if ($type::SourceIdentity -cne $hash) { throw 'Generated application supervisor source changed in this host; use a fresh test host.' }
        return
    }
    $source=[IO.File]::ReadAllText($path,[Text.UTF8Encoding]::new($false,$true))
    Add-Type -TypeDefinition $source.Replace('__TEST_NATIVE_SOURCE_ID__',$hash) -ErrorAction Stop
}

function Assert-GeneratedApplicationNativeReady {
    param([Parameter(Mandatory)] [string] $EvidenceParent)
    Assert-QualificationCleanupReady
    if ([IO.Directory]::Exists($EvidenceParent)) {
        $parent=Get-Item -LiteralPath $EvidenceParent -ErrorAction Stop
        if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Generated application evidence cannot use a reparse point.' }
        foreach ($directory in @(Get-ChildItem -LiteralPath $EvidenceParent -Directory -Force -ErrorAction Stop)) {
            if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                [IO.File]::Exists((Join-Path $directory.FullName 'owned-pending.json')) -or
                [IO.Directory]::Exists((Join-Path $directory.FullName 'owned-pending.json'))) {
                throw 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: preserved generated application ownership requires root recovery.'
            }
        }
    }
}

function Get-GeneratedApplicationNativeBudget {
    param([long] $TimeoutMs, [long] $CleanupReserveMs, [DateTimeOffset] $AuthorityEnds,
        [DateTimeOffset] $Now = [DateTimeOffset]::UtcNow)
    if ($TimeoutMs -lt 1 -or $CleanupReserveMs -lt 1) { throw 'Generated application requires a finite execution and cleanup reservation.' }
    $defaultEnd=$Now.AddMilliseconds($TimeoutMs).AddMilliseconds($CleanupReserveMs)
    if ($AuthorityEnds -eq [DateTimeOffset]::MinValue -or $AuthorityEnds -gt $defaultEnd) { $AuthorityEnds=$defaultEnd }
    if ($AuthorityEnds -le $Now.AddMilliseconds($CleanupReserveMs+100)) { throw 'Generated application has insufficient authority for execution and cleanup.' }
    [pscustomobject]@{AuthorityEnds=$AuthorityEnds; TimeoutMs=$TimeoutMs; CleanupReserveMs=$CleanupReserveMs}
}

function Save-GeneratedApplicationNativeOutcome {
    param([Parameter(Mandatory)] [string] $Directory, [Parameter(Mandatory)] $Identity,
        [AllowNull()] $Outcome, [Parameter(Mandatory)] [AllowEmptyCollection()] [Collections.Generic.List[Exception]] $Failures,
        [scriptblock] $ObserveTerminal)
    $terminal=if ($null -ne $Outcome) { $Outcome | Select-Object -Property * -ExcludeProperty Lines } else {
        [ordered]@{Started=$Identity.Started; NativeTerminalObserved=$false}
    }
    # An admitted observer can flush the actual handle outcome before fallible
    # retention. Its pipeline output is suppressed; normal callers get no new
    # console metadata or return values. Observer failures cannot erase exit.
    if ($null -ne $Outcome -and $null -ne $ObserveTerminal) {
        try { & $ObserveTerminal $Identity $Outcome | Out-Null } catch { $Failures.Add($_.Exception) }
    }
    $record=[ordered]@{identity=$Identity; outcome=$terminal}
    foreach ($name in @('original-native-outcome.json','terminal.json')) {
        try {
            $value=if ($name -eq 'terminal.json') { $terminal } else { $record }
            [IO.File]::WriteAllText((Join-Path $Directory $name),($value | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
        } catch { $Failures.Add($_.Exception) }
    }
    # errors.json receives the same actual in-memory snapshot as an independent
    # retention fallback. Nothing reloads these files to infer native completion.
    [pscustomobject]$record
}

function Invoke-GeneratedApplicationNative {
    param([Parameter(Mandatory)] [string] $HostPath,
        [Parameter(Mandatory)] [string] $WorkingDirectory,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [AllowEmptyString()] [string] $StandardInput = '',
        [long] $TimeoutMs = 3600000, [long] $CleanupReserveMs = 120000,
        [DateTimeOffset] $AuthorityEnds = [DateTimeOffset]::MinValue,
        [int] $MaximumLines = 65536, [int] $MaximumLineCharacters = 16777216,
        [int] $MaximumTotalCharacters = 33554432,
        [scriptblock] $ObserveStartup, [scriptblock] $ObserveTerminal)

    # Test execution is separate from product collection limits. The default
    # reserves the product's 60-minute ceiling plus two minutes for termination
    # and retention; an outer authority can only shorten this invocation.
    if (-not [string]::IsNullOrWhiteSpace($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC)) {
        $outer=[DateTimeOffset]::ParseExact($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC,'o',[Globalization.CultureInfo]::InvariantCulture)
        if ($AuthorityEnds -eq [DateTimeOffset]::MinValue -or $outer -lt $AuthorityEnds) { $AuthorityEnds=$outer }
    }
    $budget=Get-GeneratedApplicationNativeBudget -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs -AuthorityEnds $AuthorityEnds
    foreach ($path in @($HostPath,$WorkingDirectory)) {
        if (-not [IO.Path]::IsPathFullyQualified($path)) { throw 'Generated application native paths must be absolute.' }
    }
    if (-not [IO.File]::Exists($HostPath) -or -not [IO.Directory]::Exists($WorkingDirectory)) { throw 'Generated application native host or working directory is unavailable.' }
    $repository=Split-Path -Parent $PSScriptRoot
    $outputRoot=Join-Path $repository '.test-output'
    if ([IO.Directory]::Exists($outputRoot) -and ((Get-Item -LiteralPath $outputRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Generated application output root cannot use a reparse point.' }
    $parent=Join-Path $outputRoot 'generated-native'
    Assert-GeneratedApplicationNativeReady -EvidenceParent $parent
    Initialize-GeneratedApplicationNativeSupervisor
    $owner=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::new($HostPath,$WorkingDirectory,$Arguments,$StandardInput,
        $MaximumLines,$MaximumLineCharacters,$MaximumTotalCharacters)
    $nonce=[guid]::NewGuid().ToString('N')
    $directory=Join-Path $parent $nonce
    $null=[IO.Directory]::CreateDirectory($parent)
    $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    # Raw argv, native streams and failure messages stay in this private test
    # directory. No inherited broad ACL is allowed when collection may start.
    $currentIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try { $sid=$currentIdentity.User } finally { $currentIdentity.Dispose() }
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner($sid)
    foreach ($identity in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $rule=[Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $null=$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $directory -AclObject $acl
    $pendingPath=Join-Path $directory 'owned-pending.json'
    $parentProcess=[Diagnostics.Process]::GetCurrentProcess()
    try { $parentBirth=$parentProcess.StartTime.ToUniversalTime().ToString('o') } finally { $parentProcess.Dispose() }
    $pending=[ordered]@{contract='win-pcinfo.test-owned-native/1.0.0'; nonce=$nonce;
        requestedAt=[DateTimeOffset]::UtcNow.ToString('o'); authorityEnds=$budget.AuthorityEnds.ToString('o');
        timeoutMs=$TimeoutMs; cleanupReserveMs=$CleanupReserveMs;
        parent=[ordered]@{pid=$PID; creationUtc=$parentBirth; ownerSid=$sid.Value; arguments=[Environment]::GetCommandLineArgs()};
        hostSha256=(Get-FileHash -LiteralPath $HostPath -Algorithm SHA256).Hash.ToLowerInvariant();
        supervisorSha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'GeneratedApplicationNativeSupervisor.cs') -Algorithm SHA256).Hash.ToLowerInvariant();
        childCreationRequested=$false; child=$null}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($pending | ConvertTo-Json -Depth 8 -Compress))
    $file=[IO.File]::Open($pendingPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $file.Write($bytes); $file.Flush($true) } finally { $file.Dispose() }
    $failures=[Collections.Generic.List[Exception]]::new()
    $outcome=$null
    $wait=$null
    $startRequested=$false
    try {
        # Arm durable ownership before requesting process creation. A parent
        # crash leaves admission blocked even before a child identity is saved.
        $pending.childCreationRequested=$true
        [IO.File]::WriteAllText($pendingPath,($pending | ConvertTo-Json -Depth 8 -Compress),[Text.UTF8Encoding]::new($false))
        $startRequested=$true
        $owner.Start()
        $wait=$owner.BeginWait($budget.AuthorityEnds,$CleanupReserveMs,$TimeoutMs)
        try {
            $pending.child=$owner.StartedIdentity
            [IO.File]::WriteAllText($pendingPath,($pending | ConvertTo-Json -Depth 8 -Compress),[Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText((Join-Path $directory 'startup.json'),($pending | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
            if ($null -ne $ObserveStartup) { & $ObserveStartup $directory $owner.StartedIdentity | Out-Null }
        } catch { $failures.Add($_.Exception) }
        $outcome=$wait.GetAwaiter().GetResult()
    }
    catch {
        $failures.Add($_.Exception)
        if ($owner.StartedIdentity.Started) {
            try {
                if ($null -eq $wait) { $wait=$owner.BeginWait($budget.AuthorityEnds,$CleanupReserveMs,$TimeoutMs) }
                $outcome=$wait.GetAwaiter().GetResult()
            } catch { $failures.Add($_.Exception) }
        }
    }
    # Each terminal/stream/error write is attempted independently after the
    # actual original-handle outcome; files never substitute for native exit.
    $original=Save-GeneratedApplicationNativeOutcome -Directory $directory -Identity $owner.StartedIdentity -Outcome $outcome `
        -Failures $failures -ObserveTerminal $ObserveTerminal
    try {
        if ($null -ne $outcome) {
            $writer=[IO.StreamWriter]::new((Join-Path $directory 'streams.jsonl'),$false,[Text.UTF8Encoding]::new($false,$true))
            try { foreach ($line in $outcome.Lines) { $writer.WriteLine(($line | ConvertTo-Json -Compress)); } } finally { $writer.Dispose() }
        }
    } catch { $failures.Add($_.Exception) }
    try {
        $errorRecord=[ordered]@{startRequested=$startRequested; started=$owner.StartedIdentity.Started; original=$original;
            failures=@($failures | ForEach-Object { [ordered]@{type=$_.GetType().FullName; message=$_.Message} })}
        [IO.File]::WriteAllText((Join-Path $directory 'errors.json'),($errorRecord | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
    } catch { $failures.Add($_.Exception) }
    $safe=$null -ne $outcome -and $outcome.NativeTerminalObserved -and -not $outcome.OwnedCleanupUnverified -and $failures.Count -eq 0
    if ($safe) {
        try {
            $raw=[IO.File]::ReadAllBytes($pendingPath)
            $record=[Text.UTF8Encoding]::new($false,$true).GetString($raw) | ConvertFrom-Json
            if ($record.nonce -cne $nonce) { throw 'Generated application pending identity changed.' }
            $archive=Join-Path $directory 'exact-pending-before-release.json'
            $archiveFile=[IO.File]::Open($archive,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            try { $archiveFile.Write($raw); $archiveFile.Flush($true) } finally { $archiveFile.Dispose() }
            if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $pendingPath -Algorithm SHA256).Hash) { throw 'Generated application pending archive identity differs.' }
            [IO.File]::Delete($pendingPath)
            if ([IO.File]::Exists($pendingPath)) { throw 'Generated application pending release failed.' }
        } catch { $failures.Add($_.Exception); $safe=$false }
    }
    if (-not $safe) {
        # Keep the original owner reachable if its native terminal is unknown.
        # Forced parent termination makes descendant cleanup unverified; this
        # helper never claims or kills descendants from an invented identity.
        if (-not (Get-Variable -Name GeneratedApplicationUnverifiedOwners -Scope Script -ErrorAction SilentlyContinue)) {
            $script:GeneratedApplicationUnverifiedOwners=[Collections.Generic.List[object]]::new()
        }
        $script:GeneratedApplicationUnverifiedOwners.Add($owner)
        $exception=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: generated application native ownership or evidence is incomplete.')
        $exception.Data['OwnedCleanupUnverified']=$true
        try { [IO.File]::WriteAllText((Get-QualificationCleanupBlockerPath),'{"state":"OwnedCleanupUnverified"}',[Text.UTF8Encoding]::new($false)) } catch { }
        Write-Output 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED'
        throw $exception
    }
    $owner.Dispose()
    # Natural nonzero exits are part of the existing negative-test contract.
    # Behavior assertions, including JSON parsing, run only after ownership is
    # retained and safely released. Their failure cannot erase native evidence.
    $stdout=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::Reconstruct($outcome.Lines,'stdout')
    $stderr=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::Reconstruct($outcome.Lines,'stderr')
    [pscustomobject]@{ExitCode=$outcome.NativeExitCode; StandardOutput=$stdout; StandardError=$stderr}
}
