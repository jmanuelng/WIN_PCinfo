Set-StrictMode -Version Latest
# Closed synthetic EOF regression owner. The outer launcher intentionally keeps
# stdin OPEN/EMPTY; this is not an ordinary File/Case child lease or a launcher API.
function Get-InputLauncherSelfArguments { @([Environment]::GetCommandLineArgs()|Select-Object -Skip 1) }
function Get-InputLauncherRemainingMs {
    param([Parameter(Mandatory)]$Owner)
    [long][Math]::Floor([Math]::Min(($Owner.Ends-[DateTimeOffset]::UtcNow).TotalMilliseconds,
        $Owner.BudgetMs-$Owner.Clock.Elapsed.TotalMilliseconds))
}
function New-InputLauncherUnsafe {
    param([string]$Message)
    $error=[InvalidOperationException]::new($Message)
    $error.Data['OwnedCleanupUnverified']=$true
    $error
}
function Get-InputLauncherWaitMs {
    param([Parameter(Mandatory)]$Owner,[long]$MaximumMs,[long]$ReserveMs)
    $remaining=Get-InputLauncherRemainingMs -Owner $Owner
    $bound=[long][Math]::Min($MaximumMs,$remaining-$ReserveMs)
    if($MaximumMs-lt 1 -or $MaximumMs-gt 5000 -or $ReserveMs-lt 1000 -or $bound-lt 1){
        $Owner.Unsafe=$true;throw (New-InputLauncherUnsafe 'Input launcher refuses a nonpositive or renewed finite wait.')
    }
    $bound
}
function Get-InputLauncherScripts {
    param([Parameter(Mandatory)][string]$SourcePath)
    $ast=Assert-TestFileExecutableProtocol -Path $SourcePath
    $scripts=[ordered]@{}
    foreach($name in @('candidatePath','launcherPath')){
        $sites=@($ast.FindAll({param($node)
            $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Static -and
            $node.Expression.Extent.Text-ceq '[IO.File]' -and $node.Member.Extent.Text-ceq 'WriteAllText' -and
            $node.Arguments.Count-eq 3 -and $node.Arguments[0].Extent.Text-ceq ('$'+$name)
        },$true))
        if($sites.Count-ne 1 -or $sites[0].Arguments[1] -isnot [Management.Automation.Language.StringConstantExpressionAst] -or
            $sites[0].Arguments[1].StringConstantType-ne [Management.Automation.Language.StringConstantType]::SingleQuotedHereString -or
            $sites[0].Arguments[2].Extent.Text-cne '[Text.UTF8Encoding]::new($false)'){
            throw 'Input launcher accepts only its exact owning source literal scripts.'
        }
        $scripts[$name]=[string]$sites[0].Arguments[1].Value
    }
    $scripts
}
function Assert-InputLauncherRecord {
    param([Parameter(Mandatory)][string]$RepositoryRoot,[Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)]$Record,[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow)
    $root=[IO.Path]::GetFullPath($RepositoryRoot)
    $expectedParent=Join-Path $root '.test-output/input-launcher-native'
    foreach($name in @('contract','nonce','repositoryRoot','fixtureRoot','case','sourcePath','candidatePath','launcherPath','witnessPath','harnessPath','fileNonce','caseNonce','parentPendingPath','parentPendingSha256','hostPath','authorityEnds')){
        if($Record.$name-isnot [string]){throw 'Input launcher record boundary values must be actual strings.'}
    }
    if($Record.contract-cne 'win-pcinfo.input-launcher/1.0.0' -or $Record.nonce-cnotmatch '^[a-f0-9]{32}$' -or
        [IO.Path]::GetFullPath($Directory)-ine (Join-Path $expectedParent $Record.nonce) -or
        $Record.repositoryRoot-ine $root -or $Record.case-cnotin @('Omitted','Empty','Approve','Decline') -or
        $Record.creationRequested-isnot [bool] -or -not $Record.creationRequested){throw 'Input launcher pending boundary is malformed.'}
    foreach($path in @($Directory,$expectedParent,(Join-Path $root '.test-output'),$Record.fixtureRoot)){
        $item=Get-Item -LiteralPath $path
        if(-not $item.PSIsContainer -or ($item.Attributes-band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'Input launcher directories cannot be redirected.'}
    }
    if([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Record.fixtureRoot))-ine (Join-Path $root '.test-output') -or
        [IO.Path]::GetFileName($Record.fixtureRoot)-cnotmatch '^generated-input-[a-f0-9]{32}$' -or
        $Record.sourcePath-ine (Join-Path $root 'tests/GeneratedApplicationInput.Tests.ps1') -or
        $Record.candidatePath-ine (Join-Path $Record.fixtureRoot 'candidate.ps1') -or
        $Record.launcherPath-ine (Join-Path $Record.fixtureRoot 'launcher.ps1') -or
        $Record.witnessPath-ine (Join-Path $Record.fixtureRoot ($Record.case+'-witness.json')) -or
        $Record.harnessPath-ine (Join-Path $root 'tests/TestHarness.ps1')){throw 'Input launcher source or fixture paths changed.'}
    $fileNonce=$env:WINPCINFO_TEST_FILE_LEASE;$caseNonce=$env:WINPCINFO_TEST_CASE_LEASE
    if($fileNonce-cne $Record.fileNonce -or [string]$caseNonce-cne [string]$Record.caseNonce){throw 'Input launcher lost its exact inherited creator chain.'}
    # Reauthenticate the RECORDED original File/Case creator, separately from
    # the current launcher self. No global self substitution or lease delegation.
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $root -SelfIdentity $Record.creator -Now $Now
    if($context.Root.Admission.testPath-ine $Record.sourcePath -or
        $context.Parent.PendingPath-ine $Record.parentPendingPath -or
        (Get-TestNativeDigest -Value $context.Parent.Pending)-cne $Record.parentPendingSha256 -or
        $context.Root.Admission.hostPath-ine $Record.hostPath){throw 'Input launcher creator differs from its authenticated named File/Case.'}
    foreach($required in @($Record.sourcePath,$Record.harnessPath,(Join-Path $root 'tests/QualificationInputLauncher.ps1'),
        (Join-Path $root 'tests/GeneratedApplicationNative.ps1'))){
        if(@($context.Root.Admission.inputs|Where-Object path -IEQ $required).Count-ne 1){throw 'Input launcher source closure is absent from the original cohort.'}
    }
    $end=[DateTimeOffset]::ParseExact($Record.authorityEnds,'o',[Globalization.CultureInfo]::InvariantCulture)
    $parentEnd=[DateTimeOffset]::ParseExact($context.Parent.Pending.authorityEnds,'o',[Globalization.CultureInfo]::InvariantCulture).AddMilliseconds(-[long]$context.Parent.Pending.cleanupReserveMs-2000)
    $inherited=[DateTimeOffset]::ParseExact($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC,'o',[Globalization.CultureInfo]::InvariantCulture)
    if($end.Offset-ne [TimeSpan]::Zero -or $inherited.Offset-ne [TimeSpan]::Zero -or $end-gt $parentEnd -or
        $end-gt $inherited -or $end-le $Now.AddMilliseconds(1000) -or $Record.localBudgetMs-isnot [long] -and $Record.localBudgetMs-isnot [int] -or
        $Record.localBudgetMs-lt 27000 -or $Record.localBudgetMs-gt 35000){throw 'Input launcher has no finite unchanged retention authority.'}
    $paths=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($pin in $Record.pins){
        if($pin.path-isnot [string] -or $pin.sha256-isnot [string] -or
            $pin.bytes-isnot [long] -and $pin.bytes-isnot [int] -or $pin.bytes-lt 0 -or
            -not $paths.Add($pin.path) -or $pin.sha256-cnotmatch '^[a-f0-9]{64}$'){throw 'Input launcher pins are malformed.'}
        $item=Get-Item -LiteralPath $pin.path
        if($item.PSIsContainer -or ($item.Attributes-band [IO.FileAttributes]::ReparsePoint)-ne 0 -or
            $item.Length-ne $pin.bytes -or (Get-FileHash -LiteralPath $pin.path -Algorithm SHA256).Hash.ToLowerInvariant()-cne $pin.sha256){throw 'Input launcher exact bytes changed.'}
    }
    $expectedPaths=@($Record.sourcePath,$Record.harnessPath,$Record.hostPath,$Record.candidatePath,$Record.launcherPath,
        (Join-Path $root 'tests/QualificationInputLauncher.ps1'),(Join-Path $root 'tests/GeneratedApplicationNative.ps1'))
    if($paths.Count-ne $expectedPaths.Count){throw 'Input launcher pin inventory changed.'}
    foreach($path in $expectedPaths){if(-not $paths.Contains($path)){throw 'Input launcher omits an executable source pin.'}}
    $scripts=Get-InputLauncherScripts -SourcePath $Record.sourcePath
    foreach($pair in @(@('candidatePath',$Record.candidatePath),@('launcherPath',$Record.launcherPath))){
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes($scripts[$pair[0]])
        if([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()-cne
            (Get-FileHash -LiteralPath $pair[1] -Algorithm SHA256).Hash.ToLowerInvariant()){
            throw 'Input launcher generated bytes differ from the admitted source literals.'
        }
    }
    $expectedArgs=@('-NoLogo','-NoProfile','-File',$Record.launcherPath,'-HarnessPath',$Record.harnessPath,
        '-CandidatePath',$Record.candidatePath,'-HostPath',$Record.hostPath,'-WitnessPath',$Record.witnessPath,'-Case',$Record.case,
        '-InputLauncherOwnerDirectory',$Directory)
    if((Get-TestNativeDigest -Value @($Record.arguments))-cne (Get-TestNativeDigest -Value $expectedArgs)){
        throw 'Input launcher original argv differs from its closed source profile.'
    }
    [pscustomobject]@{Context=$context;Ends=$end;PendingPath=(Join-Path $Directory 'owned-pending.json');Arguments=$expectedArgs}
}
function New-InputLauncherOwner {
    param([Parameter(Mandatory)][string]$RepositoryRoot,[Parameter(Mandatory)][string]$FixtureRoot,
        [Parameter(Mandatory)][string]$Case,[Parameter(Mandatory)][Diagnostics.ProcessStartInfo]$StartInfo)
    Assert-TestNativeRoleReady -NativeRole GeneratedApplication -RepositoryRoot $RepositoryRoot
    $creator=Get-TestNativeSelfIdentity
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $RepositoryRoot -SelfIdentity $creator
    $end=[DateTimeOffset]::ParseExact($context.Parent.Pending.authorityEnds,'o',[Globalization.CultureInfo]::InvariantCulture).AddMilliseconds(-[long]$context.Parent.Pending.cleanupReserveMs-2000)
    $inherited=[DateTimeOffset]::ParseExact($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC,'o',[Globalization.CultureInfo]::InvariantCulture)
    if($inherited-lt $end){$end=$inherited}
    $now=[DateTimeOffset]::UtcNow;$local=$now.AddMilliseconds(35000);if($local-lt $end){$end=$local}
    $budget=[long][Math]::Floor(($end-$now).TotalMilliseconds)
    if($budget-lt 27000){throw 'Input launcher refuses creation without 27000 ms execution/drain/cleanup/retention authority.'}
    if($StartInfo.FileName-ine $context.Root.Admission.hostPath -or $StartInfo.UseShellExecute -or
        -not $StartInfo.RedirectStandardInput -or -not $StartInfo.RedirectStandardOutput -or -not $StartInfo.RedirectStandardError -or
        $StartInfo.CreateNoWindow -or -not [string]::IsNullOrEmpty($StartInfo.UserName) -or
        -not [string]::IsNullOrEmpty($StartInfo.WorkingDirectory)) {throw 'Input launcher changed its original creator flags.'}
    $directory=Join-Path $RepositoryRoot ('.test-output/input-launcher-native/'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory((Split-Path $directory));$null=New-Item -ItemType Directory -Path $directory
    $null=Set-TestNativePrivateDirectory -Path $directory
    $source=Join-Path $RepositoryRoot 'tests/GeneratedApplicationInput.Tests.ps1'
    $harness=Join-Path $RepositoryRoot 'tests/TestHarness.ps1'
    $candidate=Join-Path $FixtureRoot 'candidate.ps1';$launcher=Join-Path $FixtureRoot 'launcher.ps1';$witness=Join-Path $FixtureRoot ($Case+'-witness.json')
    $arguments=@($StartInfo.ArgumentList)+@('-InputLauncherOwnerDirectory',$directory)
    $pins=@(foreach($path in @($source,$harness,$StartInfo.FileName,$candidate,$launcher,(Join-Path $RepositoryRoot 'tests/QualificationInputLauncher.ps1'),(Join-Path $RepositoryRoot 'tests/GeneratedApplicationNative.ps1'))){
        [ordered]@{path=$path;bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
    $record=[ordered]@{contract='win-pcinfo.input-launcher/1.0.0';nonce=(Split-Path -Leaf $directory);repositoryRoot=$RepositoryRoot;
        fixtureRoot=$FixtureRoot;case=$Case;sourcePath=$source;harnessPath=$harness;hostPath=$StartInfo.FileName;
        candidatePath=$candidate;launcherPath=$launcher;witnessPath=$witness;arguments=$arguments;pins=$pins;
        creator=$creator;fileNonce=$env:WINPCINFO_TEST_FILE_LEASE;caseNonce=[string]$env:WINPCINFO_TEST_CASE_LEASE;
        parentPendingPath=$context.Parent.PendingPath;parentPendingSha256=(Get-TestNativeDigest -Value $context.Parent.Pending);
        authorityEnds=$end.ToString('o');localBudgetMs=$budget;creationRequested=$true;
        scope='OriginalRawLauncherWithOpenEmptyStdinOnly';processTreeAbsenceClaim=$false}
    $null=Assert-InputLauncherRecord -RepositoryRoot $RepositoryRoot -Directory $directory -Record $record
    Write-TestNativeNewRecord -Path (Join-Path $directory 'owned-pending.json') -Value $record
    Write-TestNativeNewRecord -Path (Join-Path $directory 'original-pending.json') -Value $record
    foreach($arg in @('-InputLauncherOwnerDirectory',$directory)){$null=$StartInfo.ArgumentList.Add($arg)}
    $owner=[pscustomobject]@{Directory=$directory;Record=$record;Ends=$end;BudgetMs=$budget;Clock=[Diagnostics.Stopwatch]::StartNew();
        Process=$null;SafeHandle=$null;Identity=$null;Started=$false;Unsafe=$false;Terminal=$null;TerminalRetained=$false;Disposed=$false;Closed=$false}
    if($null-eq (Get-Variable InputLauncherOwners -Scope Script -ErrorAction SilentlyContinue)){$script:InputLauncherOwners=[Collections.Generic.List[object]]::new()}
    $script:InputLauncherOwners.Add($owner)
    $owner
}
function Register-InputLauncherOriginal {
    param([Parameter(Mandatory)]$Owner,[Parameter(Mandatory)][Diagnostics.Process]$Process)
    # Capture custody BEFORE identity reads/retention can fail. No PID reopen.
    $Owner.Process=$Process;$Owner.Started=$true;$Owner.SafeHandle=$Process.SafeHandle
    try {
        if($Owner.SafeHandle.IsClosed -or $Owner.SafeHandle.IsInvalid){throw 'Input launcher original native handle unavailable.'}
        $start=$Process.StartInfo
        if($start.FileName-ine $Owner.Record.hostPath -or $start.UseShellExecute -or
            -not $start.RedirectStandardInput -or -not $start.RedirectStandardOutput -or -not $start.RedirectStandardError -or
            $start.CreateNoWindow -or -not [string]::IsNullOrEmpty($start.UserName) -or -not [string]::IsNullOrEmpty($start.WorkingDirectory) -or
            (Get-TestNativeDigest -Value @($start.ArgumentList))-cne (Get-TestNativeDigest -Value @($Owner.Record.arguments))){
            throw 'Input launcher original creator flags/argv changed after prearming.'
        }
        $Owner.Identity=[pscustomobject]@{Pid=$Process.Id;CreationUtc=$Process.StartTime.ToUniversalTime().ToString('o');
            OwnerSid=$Owner.Record.creator.OwnerSid;HostPath=$Owner.Record.hostPath;ExactOriginalHandleRetained=$true;
            SidProvenance='Original creator token, no alternate credentials; child observes its own token separately.'}
        $startup=[ordered]@{contract='win-pcinfo.input-launcher-startup/1.0.0';nonce=$Owner.Record.nonce;identity=$Owner.Identity}
        $startupPath=Join-Path $Owner.Directory 'startup.json';Write-TestNativeNewRecord -Path $startupPath -Value $startup
        Write-TestNativeNewRecord -Path (Join-Path $Owner.Directory 'startup-ack.json') -Value ([ordered]@{
            contract='win-pcinfo.input-launcher-ack/1.0.0';nonce=$Owner.Record.nonce;
            pendingSha256=(Get-FileHash -LiteralPath (Join-Path $Owner.Directory 'owned-pending.json') -Algorithm SHA256).Hash.ToLowerInvariant();
            startupSha256=(Get-FileHash -LiteralPath $startupPath -Algorithm SHA256).Hash.ToLowerInvariant()})
    }
    catch {$Owner.Unsafe=$true;throw (New-InputLauncherUnsafe ('Input launcher startup retention failed: '+$_.Exception.Message))}
}
function Get-InputLauncherContext {
    param([Parameter(Mandatory)][string]$RepositoryRoot,[Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)]$SelfIdentity,[Parameter(Mandatory)][string[]]$SelfArguments,[switch]$CreateClaim,
        [DateTimeOffset]$Now=[DateTimeOffset]::UtcNow)
    $pendingPath=Join-Path $Directory 'owned-pending.json';$record=Read-TestNativeRecord -Path $pendingPath
    $binding=Assert-InputLauncherRecord -RepositoryRoot $RepositoryRoot -Directory $Directory -Record $record -Now $Now
    $startup=Read-TestNativeRecord -Path (Join-Path $Directory 'startup.json')
    $ackPath=Join-Path $Directory 'startup-ack.json';$ack=Read-TestNativeRecord -Path $ackPath
    $identity=$startup.identity
    foreach($name in @('CreationUtc','OwnerSid','HostPath')){
        if($identity.$name-isnot [string] -or $SelfIdentity.$name-isnot [string]){throw 'Input launcher lifetime requires exact string observations.'}
    }
    if($identity.Pid-isnot [long] -and $identity.Pid-isnot [int] -or $identity.Pid-lt 1 -or
        $SelfIdentity.Pid-isnot [long] -and $SelfIdentity.Pid-isnot [int] -or $SelfIdentity.Pid-lt 1){throw 'Input launcher PID observation is not an exact positive integer.'}
    if($startup.contract-cne 'win-pcinfo.input-launcher-startup/1.0.0' -or $ack.contract-cne 'win-pcinfo.input-launcher-ack/1.0.0' -or
        $startup.nonce-cne $record.nonce -or $ack.nonce-cne $record.nonce -or
        $ack.pendingSha256-cne (Get-FileHash -LiteralPath $pendingPath -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $ack.startupSha256-cne (Get-FileHash -LiteralPath (Join-Path $Directory 'startup.json') -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $identity.ExactOriginalHandleRetained-isnot [bool] -or -not $identity.ExactOriginalHandleRetained -or
        $identity.Pid-ne $SelfIdentity.Pid -or $identity.CreationUtc-cne $SelfIdentity.CreationUtc -or
        $identity.OwnerSid-cne $SelfIdentity.OwnerSid -or $identity.OwnerSid-cne $record.creator.OwnerSid -or
        $identity.HostPath-ine $SelfIdentity.HostPath -or $identity.HostPath-ine $record.hostPath -or
        (Get-TestNativeDigest -Value $SelfArguments)-cne (Get-TestNativeDigest -Value $binding.Arguments)){
        throw 'Input launcher startup or current self differs from the original creator handle identity/argv.'
    }
    $claimPath=Join-Path $Directory 'launcher.claim'
    if($CreateClaim){Write-TestNativeNewRecord -Path $claimPath -Value ([ordered]@{
        contract='win-pcinfo.input-launcher-claim/1.0.0';nonce=$record.nonce;
        ackSha256=(Get-FileHash -LiteralPath $ackPath -Algorithm SHA256).Hash.ToLowerInvariant();identity=$SelfIdentity})}
    $claim=Read-TestNativeRecord -Path $claimPath
    if($claim.contract-cne 'win-pcinfo.input-launcher-claim/1.0.0' -or $claim.nonce-cne $record.nonce -or
        $claim.ackSha256-cne (Get-FileHash -LiteralPath $ackPath -Algorithm SHA256).Hash.ToLowerInvariant() -or
        (Get-TestNativeDigest -Value $claim.identity)-cne (Get-TestNativeDigest -Value $SelfIdentity)){
        throw 'Input launcher one-use claim differs from the current distinct lifetime.'
    }
    [pscustomobject]@{Record=$record;CreatorContext=$binding.Context;Ends=$binding.Ends;PendingPath=$pendingPath;Directory=$Directory}
}
function Enter-InputLauncher {
    param([Parameter(Mandatory)][string]$RepositoryRoot,[Parameter(Mandatory)][string]$Directory)
    $record=Read-TestNativeRecord -Path (Join-Path $Directory 'owned-pending.json')
    $binding=Assert-InputLauncherRecord -RepositoryRoot $RepositoryRoot -Directory $Directory -Record $record
    $wait=[Diagnostics.Stopwatch]::StartNew()
    while(-not [IO.File]::Exists((Join-Path $Directory 'startup-ack.json'))){
        if($wait.ElapsedMilliseconds-ge 2000 -or ($binding.Ends-[DateTimeOffset]::UtcNow).TotalMilliseconds-lt 16000){
            throw (New-InputLauncherUnsafe 'Input launcher exact startup was not retained within its original finite authority.')
        }
        [Threading.Thread]::Sleep(10)
    }
    # These are observations of the current child, not a native creation handle.
    $self=Get-TestNativeSelfIdentity
    $argv=Get-InputLauncherSelfArguments
    Get-InputLauncherContext -RepositoryRoot $RepositoryRoot -Directory $Directory -SelfIdentity $self -SelfArguments $argv -CreateClaim
}
function Assert-InputLauncherNativeInvocation {
    param([Parameter(Mandatory)]$Binding,[Parameter(Mandatory)][string]$HostPath,[Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][string[]]$Arguments,[AllowEmptyString()][string]$StandardInput,[long]$TimeoutMs,[long]$CleanupReserveMs)
    $record=$Binding.Record
    $stdin=switch($record.case){Approve{"APPROVE`n"} Decline{"decline`n"} default{''}}
    $expected=@('-NoLogo','-NoProfile','-File',$record.candidatePath,'-WitnessPath',$record.witnessPath)
    if($HostPath-ine $record.hostPath -or [IO.Path]::GetFullPath($WorkingDirectory)-ine $record.repositoryRoot -or
        (Get-TestNativeDigest -Value $Arguments)-cne (Get-TestNativeDigest -Value $expected) -or
        $StandardInput-cne $stdin -or $TimeoutMs-ne 10000 -or $CleanupReserveMs-ne 5000){throw 'Input launcher native request is outside the four closed EOF cases.'}
}
function Open-InputLauncherNativeBinding {
    param([Parameter(Mandatory)][string]$RepositoryRoot,[Parameter(Mandatory)][string]$Directory)
    $binding=Get-InputLauncherContext -RepositoryRoot $RepositoryRoot -Directory $Directory -SelfIdentity (Get-TestNativeSelfIdentity) `
        -SelfArguments (Get-InputLauncherSelfArguments)
    $streams=[Collections.Generic.List[object]]::new()
    $binding|Add-Member Streams $streams
    $errorRecord=$null
    try {
        foreach($pin in $binding.Record.pins){
            $stream=[IO.File]::Open($pin.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            $streams.Add($stream)
            if($stream.Length-ne $pin.bytes -or [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()-cne $pin.sha256){
                throw 'Input launcher locked source bytes differ from original pins.'
            }
        }
    }
    catch {$errorRecord=$_}
    if($errorRecord){Close-InputLauncherNativeBinding -Binding $binding -BodyError $errorRecord}
    $binding
}
function Close-InputLauncherNativeBinding {
    param([Parameter(Mandatory)]$Binding,[AllowNull()][Management.Automation.ErrorRecord]$BodyError)
    try {Complete-QualificationHarness -BodyError $BodyError -Cleanup @($Binding.Streams|ForEach-Object {$s=$_;{$s.Dispose()}.GetNewClosure()})}
    catch {
        if(Test-QualificationCleanupUnverified -Exception $_.Exception){
            if($null-eq (Get-Variable InputLauncherUnverifiedBindings -Scope Script -ErrorAction SilentlyContinue)){$script:InputLauncherUnverifiedBindings=[Collections.Generic.List[object]]::new()}
            $script:InputLauncherUnverifiedBindings.Add($Binding)
        }
        throw
    }
}
function Save-InputLauncherTerminal {
    param([Parameter(Mandatory)]$Owner,[Parameter(Mandatory)][bool]$TerminalObserved,
        [Parameter(Mandatory)][bool]$StreamsDrained,[Parameter(Mandatory)][bool]$Forced,
        [AllowNull()][string]$StandardOutput,[AllowNull()][string]$StandardError)
    try {
        if($Owner.TerminalRetained){throw 'Input launcher terminal observation cannot be rewritten.'}
        $exitCode=$null;if($TerminalObserved){$exitCode=$Owner.Process.ExitCode;if($exitCode-isnot [int]){throw 'Input launcher original exit is unknown.'}}
        $Owner.Terminal=[ordered]@{identity=$Owner.Identity;nativeTerminalObserved=$TerminalObserved;nativeExitCode=$exitCode;
            streamsDrained=$StreamsDrained;forced=$Forced;openEmptyInputRequested=$true;inputEOFClaim=$false;
            processTreeAbsenceClaim=$false;authorityEnds=$Owner.Ends.ToString('o');standardOutput=$StandardOutput;standardError=$StandardError}
        if(-not $TerminalObserved -or -not $StreamsDrained -or $Forced){$Owner.Unsafe=$true}
        Write-TestNativeNewRecord -Path (Join-Path $Owner.Directory 'original-terminal.json') -Value $Owner.Terminal
        $Owner.TerminalRetained=$true
    }
    catch {$Owner.Unsafe=$true;throw (New-InputLauncherUnsafe ('Input launcher original terminal retention failed: '+$_.Exception.Message))}
}
function Complete-InputLauncherOwner {
    param([Parameter(Mandatory)]$Owner,[Parameter(Mandatory)][bool]$ExactFixtureCleanupVerified)
    try {
        if(-not $ExactFixtureCleanupVerified -or $Owner.Unsafe -or -not $Owner.TerminalRetained -or
            -not $Owner.Terminal.nativeTerminalObserved -or -not $Owner.Terminal.streamsDrained -or $Owner.Terminal.forced -or
            (Get-InputLauncherRemainingMs -Owner $Owner)-lt 1000){throw 'Input launcher closure requires retained natural terminal, streams and exact fixture cleanup with reserve.'}
        Write-TestNativeNewRecord -Path (Join-Path $Owner.Directory 'original-close-proof.json') -Value ([ordered]@{
            terminalSha256=(Get-FileHash -LiteralPath (Join-Path $Owner.Directory 'original-terminal.json') -Algorithm SHA256).Hash.ToLowerInvariant();
            exactFixtureCleanupVerified=$true;ordinaryForcedAcceptance=$false})
        # Retention may consume time. Release only after a fresh actual bound.
        if((Get-InputLauncherRemainingMs -Owner $Owner)-lt 1000){throw 'Input launcher close retention consumed its unchanged authority.'}
        if(-not $Owner.Disposed){$Owner.Process.Dispose();$Owner.Disposed=$true}
        if((Get-InputLauncherRemainingMs -Owner $Owner)-lt 1000){throw 'Input launcher original disposal consumed its unchanged release authority.'}
        [IO.File]::Delete((Join-Path $Owner.Directory 'owned-pending.json'));$Owner.Closed=$true
    }
    catch {$Owner.Unsafe=$true;throw (New-InputLauncherUnsafe ('Input launcher closure remains pending: '+$_.Exception.Message))}
}
