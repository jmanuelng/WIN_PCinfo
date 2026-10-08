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

# Closed original creator observation. Native Start/Kill/Wait, Jobs and pipes
# stay at their original test source seam; this API grants no launch authority.
function New-QualificationOriginalCreatorOwner {
    param([Parameter(Mandatory)][string]$RepositoryRoot,[Parameter(Mandatory)][string]$TestPath,
        [Parameter(Mandatory)][ValidateSet('CiToolValid','CiToolBound','CiToolDenied','CiToolTimeout','CiToolNonUtf8',
            'EvidenceCrash','RecoveryMetadata','RecoveryFixtureParent','StatusRecoveryParent','CleanupHandoff','CleanupPipe')][string]$Profile,
        [Parameter(Mandatory)][Diagnostics.ProcessStartInfo]$StartInfo,[ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce=[guid]::NewGuid().ToString('N'))
    $admission=Get-QualificationFixtureAdmission -RepositoryRoot $RepositoryRoot
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $RepositoryRoot -SelfIdentity $admission.Creator
    $testName=switch($Profile) {
        {$_ -like 'CiTool*'} {'CiToolSourceBoundary.Tests.ps1'}
        'EvidenceCrash' {'EvidenceWorkspaceRecovery.Tests.ps1'}
        {$_ -like 'Recovery*'} {'RecoveryProcessOwnership.Tests.ps1'}
        'StatusRecoveryParent' {'StatusDeskRecovery.Tests.ps1'}
        {$_ -like 'Cleanup*'} {'QualificationCleanup.Tests.ps1'}
    }
    $test=[IO.Path]::GetFullPath((Join-Path $RepositoryRoot ('tests/'+$testName)))
    if($TestPath -ine $test -or $context.Parent.Admission.testPath -ine $test -or
        $StartInfo.UseShellExecute -or -not [string]::IsNullOrEmpty($StartInfo.UserName) -or
        $StartInfo.FileName -ine $context.Root.Admission.hostPath -or -not [string]::IsNullOrEmpty($StartInfo.Arguments)){
        throw 'Original creator observer differs from its closed source/host/current File or Case.'
    }
    # Inherit the actual finite File/Case deadline; retain every original workload.
    # Individual source waits remain at their original closed bounds.
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $maximum=[long][Math]::Floor(($admission.Ends-[DateTimeOffset]::UtcNow).TotalMilliseconds)
    $budget=$maximum
    if($budget -lt 7000){throw 'Original creator lacks finite creation/retention reserve.'}
    $parent=Join-Path $RepositoryRoot '.test-output/original-creator'
    $null=[IO.Directory]::CreateDirectory($parent)
    foreach($entry in @($parent,(Split-Path -Parent $parent))){
        if(((Get-Item -LiteralPath $entry).Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'Original creator retention parent is redirected.'}
    }
    foreach($entry in @(Get-ChildItem -LiteralPath $parent -Directory -Force)){
        if(($entry.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0 -or [IO.File]::Exists((Join-Path $entry.FullName 'owned-pending.json'))){
            throw 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: prior original creator remains pending.'
        }
    }
    $nonce=$Nonce;$directory=Join-Path $parent $nonce
    $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop;$null=Set-TestNativePrivateDirectory -Path $directory
    Write-QualificationFixtureRecord -Path (Join-Path $directory 'owned-pending.json') -Value ([ordered]@{
        contract='win-pcinfo.original-creator-preparation/1.0.0';nonce=$nonce;profile=$Profile;creator=$admission.Creator;nativeCreationRequested=$false})
    $owner=[pscustomobject]@{Directory=$directory;Pending=$null;Clock=$clock;BudgetMs=$budget;
        Process=$null;SafeHandle=$null;Identity=$null;InputStream=$null;NestedHeld=@{};Started=$false;TerminalVerified=$false;TerminalRetained=$false;Disposed=$false;Unsafe=$false}
    if($null-eq(Get-Variable QualificationOriginalCreatorOwners -Scope Script -ErrorAction SilentlyContinue)){$script:QualificationOriginalCreatorOwners=[Collections.Generic.List[object]]::new()}
    $script:QualificationOriginalCreatorOwners.Add($owner)
    $inputStream=$null;$inputPin=$null
    $arguments=@($StartInfo.ArgumentList)
    if($arguments.Count -ge 4 -and $arguments[0] -ceq '-NoLogo' -and $arguments[1] -ceq '-NoProfile' -and $arguments[2] -ceq '-File'){
        $inputPath=[IO.Path]::GetFullPath($arguments[3]);Assert-PortableEntryCmdOrdinaryPath -Path $inputPath
        $inputStream=[IO.File]::Open($inputPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $owner.InputStream=$inputStream; $archive=Join-Path $directory 'original-consumed-script.retained'
        $archiveStream=[IO.File]::Open($archive,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{
            $length=$inputStream.Length;$remaining=$length;$buffer=[byte[]]::new(81920)
            while($remaining-gt0){if((Get-QualificationFixtureRemainingMs $owner)-lt2000){throw 'Original script retention lacks unchanged release reserve.'};$read=$inputStream.Read($buffer,0,[int][Math]::Min($remaining,$buffer.Length));if($read-lt1){throw 'Original consumed script ended early.'};$archiveStream.Write($buffer,0,$read);$remaining-=$read}
            if($inputStream.ReadByte()-ne-1){throw 'Original consumed script grew.'};$archiveStream.Flush($true)
        }catch{$owner.Unsafe=$true;$failure=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: original creator preparation retains pending input.', $_.Exception);$failure.Data['OwnedCleanupUnverified']=$true;throw $failure}
        finally{$archiveStream.Dispose();$inputStream.Position=0}
        $inputPin=[ordered]@{path=$inputPath;bytes=$length;sha256=(Get-FileHash -LiteralPath $archive).Hash.ToLowerInvariant();retainedPath=$archive}
    }
    $pending=[ordered]@{contract='win-pcinfo.original-creator/1.0.0';nonce=$nonce;profile=$Profile;testPath=$test;
        testSha256=(Get-FileHash -LiteralPath $test).Hash.ToLowerInvariant();repositoryRoot=$RepositoryRoot;directory=$directory;
        creator=$admission.Creator;sidProvenance='Original creator Windows token; ProcessStartInfo supplies no alternate user.';parentNonce=$context.Parent.Pending.nonce;rootNonce=$context.Root.Pending.nonce;
        parentPendingSha256=(Get-TestNativeDigest $context.Parent.Pending);cohortSha256=$context.Root.Admission.cohortSha256;
        hostPath=$StartInfo.FileName;hostSha256=(Get-FileHash -LiteralPath $StartInfo.FileName).Hash.ToLowerInvariant();
        arguments=@($StartInfo.ArgumentList);workingDirectory=$StartInfo.WorkingDirectory;inheritedWorkingDirectory=[Environment]::CurrentDirectory;
        inputRedirected=$StartInfo.RedirectStandardInput;stdoutRedirected=$StartInfo.RedirectStandardOutput;stderrRedirected=$StartInfo.RedirectStandardError;
        authorityEnds=$admission.Ends.ToString('o');localBudgetMs=$budget;localMaximumMs=$maximum;retentionReserveMs=1000;
        consumedScriptInput=$inputPin;originalOperationPreserved=$true;processTreeAbsenceClaim=$false;ordinaryNativePassClaim=$false}
    $owner.Pending=$pending
    Write-QualificationFixtureRecord -Path (Join-Path $directory 'original-pending.json') -Value $pending
    [IO.File]::WriteAllText((Join-Path $directory 'owned-pending.json'),($pending|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
    $owner
}

function Save-QualificationOriginalCreatorTerminal {
    param([Parameter(Mandatory)]$Owner,[Parameter(Mandatory)][string]$Disposition,[Parameter(Mandatory)][bool]$Forced,
        [AllowNull()][string]$StandardOutput,[AllowNull()][string]$StandardError,[AllowNull()][byte[]]$RawStandardOutput,
        [Parameter(Mandatory)][string]$StreamContract,
        [AllowNull()]$ExpectedOriginalProcess,[AllowNull()]$CallerHasExitedObservation,
        [AllowNull()][Management.Automation.ErrorRecord]$CallerBodyErrorRecord,
        [AllowNull()][Management.Automation.ErrorRecord]$CallerCleanupErrorRecord)
    $retentionStage='ValidateOriginalHandleAndReserve'
    $observedTerminal=$null;$observedExit=$null
    $originalWaitResult=$null;$originalWaitResultType=$null;$expectedOriginalProcessReferenceMatches=$null
    try {
        if($Owner.TerminalRetained -or -not $Owner.Started -or $null -eq $Owner.SafeHandle -or
            $Owner.SafeHandle.IsClosed -or $Owner.SafeHandle.IsInvalid -or (Get-QualificationFixtureRemainingMs $Owner)-lt 1000){
            throw 'Original creator terminal lacks original handle or unchanged retention reserve.'
        }
        if($null -ne $ExpectedOriginalProcess){
            $expectedOriginalProcessReferenceMatches=[object]::ReferenceEquals($Owner.Process,$ExpectedOriginalProcess)
            if(-not $expectedOriginalProcessReferenceMatches){throw 'Original terminal owner differs from the exact caller Process reference.'}
        }
        $retentionStage='ObserveOriginalTerminal'
        $terminal=$Owner.Process.WaitForExit(0)
        $originalWaitResult=$terminal
        if($null -ne $terminal){$originalWaitResultType=$terminal.GetType().FullName}
        if($terminal -isnot [bool] -or -not $terminal){throw 'Original creator native terminal remains unknown.'}
        $observedTerminal=$true;$retentionStage='ReadOriginalNativeExit'
        $exit=$Owner.Process.ExitCode;if($exit -isnot [int]){throw 'Original creator native exit is unknown.'}
        $observedExit=$exit;$retentionStage='BuildOriginalTerminalRecord'
        $record=[ordered]@{contract='win-pcinfo.original-creator-terminal/1.0.0';identity=$Owner.Identity;
            pendingSha256=(Get-FileHash -LiteralPath (Join-Path $Owner.Directory 'original-pending.json')).Hash.ToLowerInvariant();
            disposition=$Disposition;forced=$Forced;nativeTerminalObserved=$true;nativeExitCode=$exit;disposed=$false;
            streamContract=$StreamContract;standardOutput=$StandardOutput;standardError=$StandardError;
            rawStandardOutput=$(if($null -eq $RawStandardOutput){$null}else{[Convert]::ToBase64String($RawStandardOutput)});
            ordinaryNativePassClaim=$false;processTreeAbsenceClaim=$false}
        $retentionStage='WriteOriginalTerminal'
        Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory 'original-terminal.json') -Value $record
        $retentionStage='WriteTerminalMirror'
        Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory 'terminal.json') -Value $record
        $Owner.TerminalVerified=$true;$Owner.TerminalRetained=$true
    }catch{
        $originalRetentionError=$_;$Owner.Unsafe=$true
        $diagnosticFailures=[Collections.Generic.List[Management.Automation.ErrorRecord]]::new()
        $diagnosticPath=Join-Path $Owner.Directory 'original-terminal-retention-error.json'
        $diagnosticStream=$null;$diagnosticDisposeUncertain=$false
        try{
            # Bounded diagnostic views are not serialized original ErrorRecords.
            $message=[string]$originalRetentionError.Exception.Message
            $errorId=[string]$originalRetentionError.FullyQualifiedErrorId
            $stack=[string]$originalRetentionError.ScriptStackTrace
            $callerErrorViews=[Collections.Generic.List[object]]::new()
            foreach($callerRole in @('Body','Cleanup')){
                $callerRecord=if($callerRole -ceq 'Body'){$CallerBodyErrorRecord}else{$CallerCleanupErrorRecord}
                if($null -ne $callerRecord){
                    $callerMessage=[string]$callerRecord.Exception.Message;$callerId=[string]$callerRecord.FullyQualifiedErrorId;$callerStack=[string]$callerRecord.ScriptStackTrace
                    $callerErrorViews.Add([ordered]@{role=$callerRole;errorType=$callerRecord.Exception.GetType().FullName;
                        message=$callerMessage.Substring(0,[Math]::Min(1024,$callerMessage.Length));fullyQualifiedErrorId=$callerId.Substring(0,[Math]::Min(256,$callerId.Length));scriptStackTrace=$callerStack.Substring(0,[Math]::Min(2048,$callerStack.Length));
                        messageTruncated=($callerMessage.Length -gt 1024);errorIdTruncated=($callerId.Length -gt 256);stackTruncated=($callerStack.Length -gt 2048);originalErrorRecordGraphRetained=$false})
                }
            }
            $view=[ordered]@{
                contract='win-pcinfo.original-creator-terminal-retention-error/1.0.0';
                stage=$retentionStage;profile=$Owner.Pending.profile;identity=$Owner.Identity;
                errorType=$originalRetentionError.Exception.GetType().FullName;
                message=$message.Substring(0,[Math]::Min(4096,$message.Length));
                fullyQualifiedErrorId=$errorId.Substring(0,[Math]::Min(512,$errorId.Length));
                scriptStackTrace=$stack.Substring(0,[Math]::Min(4096,$stack.Length));
                actualTerminalObserved=$observedTerminal;actualNativeExit=$observedExit;
                originalWaitResultType=$originalWaitResultType;
                originalWaitResultBoolean=$(if($originalWaitResult -is [bool]){$originalWaitResult}else{$null});
                expectedOriginalProcessSupplied=($null -ne $ExpectedOriginalProcess);expectedOriginalProcessReferenceMatches=$expectedOriginalProcessReferenceMatches;
                callerHasExitedObservation=$(if($CallerHasExitedObservation -is [bool]){$CallerHasExitedObservation}else{$null});callerHasExitedObservationIsBoolean=($CallerHasExitedObservation -is [bool]);
                forcedRequested=$Forced;originalCallerErrorViews=$callerErrorViews.ToArray();
                originalTerminalRetentionAccepted=$false;originalClosureAccepted=$false;
                ownedCleanupUnverified=$true;originalErrorRecordGraphRetained=$false;
                messageTruncated=($message.Length -gt 4096);errorIdTruncated=($errorId.Length -gt 512);
                stackTruncated=($stack.Length -gt 4096)
            }
            $diagnosticBytes=[Text.UTF8Encoding]::new($false,$true).GetBytes(($view|ConvertTo-Json -Depth 6))
            if($diagnosticBytes.Length -gt 32768){throw 'Original creator diagnostic exceeds its closed byte bound.'}
            $diagnosticStream=[IO.File]::Open($diagnosticPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            $diagnosticStream.Write($diagnosticBytes);$diagnosticStream.Flush($true)
        }catch{$diagnosticFailures.Add($_)}
        if($null -ne $diagnosticStream){
            try{$diagnosticStream.Dispose()}
            catch{$diagnosticDisposeUncertain=$true;$diagnosticFailures.Add($_)}
        }
        $exception=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: original creator terminal retention failed.', $originalRetentionError.Exception)
        $exception.Data['OriginalErrorRecord']=$originalRetentionError
        $exception.Data['CallerBodyErrorRecord']=$CallerBodyErrorRecord;$exception.Data['CallerCleanupErrorRecord']=$CallerCleanupErrorRecord
        $exception.Data['RetentionStage']=$retentionStage
        $exception.Data['DiagnosticRetentionFailures']=$diagnosticFailures.ToArray()
        $exception.Data['DiagnosticPath']=$diagnosticPath
        $exception.Data['DiagnosticDisposeUncertain']=$diagnosticDisposeUncertain
        if($diagnosticDisposeUncertain){$exception.Data['StrongDiagnosticStreamReference']=$diagnosticStream}
        $exception.Data['StrongOriginalCreatorOwner']=$Owner
        $exception.Data['OwnedCleanupUnverified']=$true
        throw $exception
    }
}

function Complete-QualificationOriginalCreatorOwner {
    param([Parameter(Mandatory)]$Owner)
    try {
        if($Owner.Unsafe -or -not $Owner.TerminalVerified -or -not $Owner.TerminalRetained -or
            $Owner.SafeHandle.IsClosed -isnot [bool] -or -not $Owner.SafeHandle.IsClosed -or
            (Get-QualificationFixtureRemainingMs $Owner)-lt 1000){throw 'Original caller disposal/terminal/retention remains unverified.'}
        if($null -ne $Owner.InputStream){
            $Owner.InputStream.Position=0
            $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Owner.InputStream)).ToLowerInvariant()
            if($Owner.InputStream.Length -ne $Owner.Pending.consumedScriptInput.bytes -or $hash -cne $Owner.Pending.consumedScriptInput.sha256){throw 'Original consumed script changed before release.'}
            $Owner.InputStream.Dispose()
            if($Owner.InputStream.CanRead){throw 'Original consumed script stream remains open.'}
        }
        $roles=switch($Owner.Pending.profile){'RecoveryFixtureParent'{@('RecoveryNested')}'StatusRecoveryParent'{@('StatusWorker','StatusNested')}default{@()}}
        foreach($role in $roles){
            foreach($suffix in @('request','creation','terminal','close')){
                if(-not [IO.File]::Exists((Join-Path $Owner.Directory ('recovery-'+$role+'-'+$suffix+'.json')))){throw ('Original recovery '+$role+' '+$suffix+' is missing.')}
            }
        }
        Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory 'original-close-proof.json') -Value ([ordered]@{
            contract='win-pcinfo.original-creator-close/1.0.0';
            originalTerminalSha256=(Get-FileHash -LiteralPath (Join-Path $Owner.Directory 'original-terminal.json')).Hash.ToLowerInvariant();
            disposedOriginalHandle=$true;originalConsumedScriptClosed=$(if($null -eq $Owner.InputStream){$null}else{-not $Owner.InputStream.CanRead});ordinaryNativePassClaim=$false;processTreeAbsenceClaim=$false})
        if((Get-QualificationFixtureRemainingMs $Owner)-lt 1000){throw 'Original close retention consumed release reserve.'}
        [IO.File]::Delete((Join-Path $Owner.Directory 'owned-pending.json'))
        if([IO.File]::Exists((Join-Path $Owner.Directory 'owned-pending.json'))){throw 'Original creator pending release failed.'}
        $Owner.Disposed=$true
    }catch{$Owner.Unsafe=$true;$exception=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: original creator closure failed.', $_.Exception);$exception.Data['OwnedCleanupUnverified']=$true;throw $exception}
}
function Assert-QualificationOriginalCreatorCreation {
    param([Parameter(Mandatory)]$Owner)
    Assert-QualificationFixtureProcessAdmission $Owner
    Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory 'original-creation-request.json') -Value ([ordered]@{
        originalPendingSha256=(Get-FileHash -LiteralPath (Join-Path $Owner.Directory 'original-pending.json')).Hash.ToLowerInvariant();
        creationRequested=$true;ordinaryNativePassClaim=$false;processTreeAbsenceClaim=$false})
}
function Get-QualificationRecoveryCreatorProtocol {
    @'
function Write-RecoveryOriginalRecord {
    param([string]$Path,$Value)
    $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes(($Value|ConvertTo-Json -Depth 12))
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$stream.Write($bytes);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Begin-RecoveryOriginalCreation {
    param([string]$Directory,[ValidateSet('RecoveryNested','StatusWorker','StatusNested')][string]$Role,[Diagnostics.ProcessStartInfo]$StartInfo,
        [AllowNull()]$WorkerConfiguration,[AllowNull()][string]$WorkerTemplateSha256)
    $pending=Get-Content -LiteralPath (Join-Path $Directory 'original-pending.json') -Raw|ConvertFrom-Json -AsHashtable
    if($pending.contract -cne 'win-pcinfo.original-creator/1.0.0' -or
        $pending.profile -cnotin @('RecoveryFixtureParent','StatusRecoveryParent') -or
        $StartInfo.UseShellExecute -or $StartInfo.UserName -or $StartInfo.Arguments -or
        $StartInfo.FileName -ine $pending.hostPath -or $script:RecoveryOriginalProtocolSha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Closed recovery creator binding differs.'}
    $boundary=[IO.Path]::GetFullPath((Join-Path $pending.repositoryRoot ('.test-output/original-creator/'+$pending.nonce)))
    if([IO.Path]::GetFullPath($Directory) -cne $boundary -or
        ((Get-Item -LiteralPath $Directory).Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'Recovery owner directory differs.'}
    $end=[DateTimeOffset]::Parse($pending.authorityEnds)
    if(($end-[DateTimeOffset]::UtcNow).TotalMilliseconds -lt 7000){throw 'Recovery creator has insufficient unchanged reserve.'}
    $parentPath=if($Role -ceq 'StatusNested'){Join-Path $Directory 'recovery-StatusWorker-creation.json'}else{Join-Path $Directory 'original-identity.json'}
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while(-not [IO.File]::Exists($parentPath)-and $watch.ElapsedMilliseconds-lt5000-and ($end-[DateTimeOffset]::UtcNow).TotalMilliseconds-ge7000){[Threading.Thread]::Sleep(10)}
    $parent=Get-Content -LiteralPath $parentPath -Raw|ConvertFrom-Json -AsHashtable
    $expected=if($Role -ceq 'StatusNested'){$parent.child}else{$parent.identity}
    $self=[Diagnostics.Process]::GetCurrentProcess()
    try{$creator=[ordered]@{pid=$self.Id;fullBirthUtc=$self.StartTime.ToUniversalTime().ToString('o');hostPath=$self.MainModule.FileName;ownerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}}
    finally{$self.Dispose()}
    if($creator.pid -ne $expected.pid -or $creator.fullBirthUtc -cne $expected.fullBirthUtc -or $creator.hostPath -ine $pending.hostPath -or $creator.ownerSid -cne $pending.creator.OwnerSid){throw 'Original recovery creator does not match original parent custody.'}
    $request=[ordered]@{contract='win-pcinfo.recovery-original-request/1.0.0';role=$Role;creator=$creator;
        outerPendingSha256=(Get-FileHash -LiteralPath (Join-Path $Directory 'original-pending.json')).Hash.ToLowerInvariant();
        parentOriginalCreationSha256=(Get-FileHash -LiteralPath $parentPath).Hash.ToLowerInvariant();protocolSha256=$script:RecoveryOriginalProtocolSha256;
        hostPath=$StartInfo.FileName;hostSha256=(Get-FileHash -LiteralPath $StartInfo.FileName).Hash.ToLowerInvariant();
        arguments=@($StartInfo.ArgumentList);workingDirectory=$StartInfo.WorkingDirectory;inheritedWorkingDirectory=[Environment]::CurrentDirectory;
        stdoutRedirected=$StartInfo.RedirectStandardOutput;stderrRedirected=$StartInfo.RedirectStandardError;inputRedirected=$StartInfo.RedirectStandardInput;
        environment=@($StartInfo.Environment.GetEnumerator()|ForEach-Object{[ordered]@{name=$_.Key;value=$_.Value}});
        workerConfiguration=$WorkerConfiguration;workerTemplateSha256=$WorkerTemplateSha256;
        authorityEnds=$pending.authorityEnds;creationRequested=$true;ordinaryNativePassClaim=$false;processTreeAbsenceClaim=$false}
    Write-RecoveryOriginalRecord (Join-Path $Directory ('recovery-'+$Role+'-request.json')) $request
    [pscustomobject]@{Directory=$Directory;Role=$Role;Request=$request;Ends=$end}
}
function Save-RecoveryOriginalCreation {
    param($Request,[Diagnostics.Process]$Process)
    if(($Request.Ends-[DateTimeOffset]::UtcNow).TotalMilliseconds-lt1000){throw 'Recovery original creation consumed retention reserve.'}
    $handle=$Process.SafeHandle
    if($handle.IsClosed-or $handle.IsInvalid){throw 'Original recovery Process.Start result unavailable.'}
    $child=[ordered]@{pid=$Process.Id;fullBirthUtc=$Process.StartTime.ToUniversalTime().ToString('o');hostPath=$Process.MainModule.FileName;
        ownerSid=$Request.Request.creator.ownerSid;originalSafeHandleValue=$handle.DangerousGetHandle().ToInt64();
        sidProvenance='Original creator Windows token; ProcessStartInfo supplies no alternate user.';
        handleProvenance='SafeHandle of the original Process.Start result; no PID reopen.'}
    if($child.hostPath -ine $Request.Request.hostPath){throw 'Original recovery child image differs.'}
    Write-RecoveryOriginalRecord (Join-Path $Request.Directory ('recovery-'+$Request.Role+'-creation.json')) ([ordered]@{
        contract='win-pcinfo.recovery-original-creation/1.0.0';child=$child;creator=$Request.Request.creator;
        requestSha256=(Get-FileHash -LiteralPath (Join-Path $Request.Directory ('recovery-'+$Request.Role+'-request.json'))).Hash.ToLowerInvariant();
        originalHandleRetainedAtCreation=$true;creatorInterruptionPermitted=$true;ordinaryNativePassClaim=$false;processTreeAbsenceClaim=$false})
    if($null-eq(Get-Variable RecoveryOriginalCreatorHandles -Scope Script -ErrorAction SilentlyContinue)){$script:RecoveryOriginalCreatorHandles=[Collections.Generic.List[object]]::new()}
    $script:RecoveryOriginalCreatorHandles.Add([pscustomobject]@{Process=$Process;SafeHandle=$handle;Request=$Request;Identity=$child})
}
'@
}

function Save-QualificationRecoveryOriginalTerminal {
    param([Parameter(Mandatory)]$Owner,[Parameter(Mandatory)][ValidateSet('RecoveryNested','StatusWorker','StatusNested')][string]$Role,
        [Parameter(Mandatory)][Diagnostics.Process]$Process,[Parameter(Mandatory)][Diagnostics.Process]$CreatorProcess,
        [Parameter(Mandatory)][ValidateSet('ParentOnlyStopThenSeparateHeldChildStop','OriginalProductJobClosureAfterParentLoss')][string]$Disposition)
    try {
        $creationPath=Join-Path $Owner.Directory ('recovery-'+$Role+'-creation.json')
        $creation=Get-Content -LiteralPath $creationPath -Raw|ConvertFrom-Json -AsHashtable
        $handle=$Process.SafeHandle
        if($handle.IsClosed-or$handle.IsInvalid-or(Get-QualificationFixtureRemainingMs $Owner)-lt1000-or
            $Process.Id -ne $creation.child.pid-or$Process.StartTime.ToUniversalTime().ToString('o')-cne$creation.child.fullBirthUtc-or
            $CreatorProcess.Id-ne$creation.creator.pid-or$CreatorProcess.StartTime.ToUniversalTime().ToString('o')-cne$creation.creator.fullBirthUtc-or
            -not$Process.WaitForExit(0)-or-not$CreatorProcess.WaitForExit(0)){throw 'Retained original creator and previously admitted recovery terminal custody differ.'}
        $record=[ordered]@{contract='win-pcinfo.recovery-original-terminal/1.0.0';role=$Role;
            originalCreationSha256=(Get-FileHash -LiteralPath $creationPath).Hash.ToLowerInvariant();
            originalChild=$creation.child;originalCreator=$creation.creator;disposition=$Disposition;
            observedNativeTerminal=$true;observedCreatorNativeTerminal=$true;nativeExitCode=$Process.ExitCode;
            recoverySafeHandleValue=$handle.DangerousGetHandle().ToInt64();disposedRecoveryHandle=$false;
            terminalCustody='Previously admitted recovery handle; not original creator SafeHandle.';
            originalCreatorInterruptionExpected=$true;ordinaryNativePassClaim=$false;appCleanupAcceptanceClaim=$false;processTreeAbsenceClaim=$false}
        Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory ('recovery-'+$Role+'-terminal.json')) -Value $record
        $Owner.NestedHeld[$Role]=$handle
    }catch{$Owner.Unsafe=$true;$failure=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: original recovery creator/terminal retention failed.', $_.Exception);$failure.Data['OwnedCleanupUnverified']=$true;throw $failure}
}
function Complete-QualificationRecoveryOriginalTerminal {
    param([Parameter(Mandatory)]$Owner,[Parameter(Mandatory)][ValidateSet('RecoveryNested','StatusWorker','StatusNested')][string]$Role)
    try {
        if(-not$Owner.NestedHeld.ContainsKey($Role)-or-not$Owner.NestedHeld[$Role].IsClosed-or(Get-QualificationFixtureRemainingMs $Owner)-lt1000){throw 'Previously admitted recovery handle disposal remains unverified.'}
        Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory ('recovery-'+$Role+'-close.json')) -Value ([ordered]@{
            contract='win-pcinfo.recovery-original-close/1.0.0';role=$Role;
            terminalSha256=(Get-FileHash -LiteralPath (Join-Path $Owner.Directory ('recovery-'+$Role+'-terminal.json'))).Hash.ToLowerInvariant();
            disposedRecoveryHandle=$true;originalCreatorHandleDisposalClaim=$false;ordinaryNativePassClaim=$false;appCleanupAcceptanceClaim=$false})
    }catch{$Owner.Unsafe=$true;$failure=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: recovery observer close retention failed.', $_.Exception);$failure.Data['OwnedCleanupUnverified']=$true;throw $failure}
}