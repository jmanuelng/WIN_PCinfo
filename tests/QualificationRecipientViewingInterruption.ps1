Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'QualificationFixtureProcess.ps1')

# UNADMITTED DRAFT. One closed real-view fixture, never a general launcher,
# normal Case completion exception, PID reopen or descendant cleanup claim.
function New-RecipientViewingInterruptionOwner {
    param([string]$RepositoryRoot,$Candidate,[string]$PreparedManifestPath,[string]$PreparedManifestSha256,
        [Diagnostics.ProcessStartInfo]$StartInfo,[string]$PackagePath,[string]$FixtureRoot)
    $admission=Get-QualificationFixtureAdmission -RepositoryRoot $RepositoryRoot
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $RepositoryRoot -SelfIdentity $admission.Creator
    $governing=$context.Root.Admission;$test=Join-Path $RepositoryRoot 'tests/RecipientViewingApplication.Tests.ps1'
    if($context.Parent.Admission.testPath -isnot [string] -or $context.Parent.Admission.testPath -cne $test -or
        @($governing.inputs|Where-Object path -CEQ $test).Count -ne 1 -or
        (Get-TestNativeDigest $admission.Parent.Pending) -cne (Get-TestNativeDigest $context.Parent.Pending)) {throw 'Recipient interruption requires its actual named File/Case parent.'}
    if($Candidate.Prepared -isnot [bool] -or -not $Candidate.Prepared -or -not $Candidate.Stream.CanRead -or
        $Candidate.Path -isnot [string] -or $Candidate.Path -cne $governing.candidatePath -or
        $PreparedManifestPath -cne $governing.preparedManifestPath -or $PreparedManifestSha256 -cne $governing.preparedManifestSha256 -or
        $governing.hostPath -isnot [string]){throw 'Recipient interruption requires its immutable root prepared triple and host.'}
    foreach($pair in @(@($Candidate.Path,$Candidate.Sha256),@($PreparedManifestPath,$PreparedManifestSha256),@($governing.hostPath,(Get-FileHash $governing.hostPath).Hash.ToLowerInvariant()))){
        $pin=@($governing.inputs|Where-Object path -CEQ $pair[0]);if($pin.Count -ne 1 -or $pin[0].sha256 -cne $pair[1]){throw 'Recipient interruption input differs from its cohort.'}
    }
    $root=[IO.Path]::GetFullPath($FixtureRoot);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if($FixtureRoot -cne $root -or [IO.Path]::GetDirectoryName($root).TrimEnd('\')+'\' -cne $temp -or
        [IO.Path]::GetFileName($root) -cnotmatch '^winpcinfo-recipient-view-[a-f0-9]{32}$' -or
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($PackagePath)) -cne $root){throw 'Recipient interruption fixture or protected package escaped its exact owner.'}
    for($cursor=[IO.DirectoryInfo]::new($root);$null -ne $cursor;$cursor=$cursor.Parent){if(($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'Recipient interruption refuses redirected ancestors.'}}
    $expected=@('-NoLogo','-NoProfile','-File',$test,'-ViewChild','-ChildPackagePath',$PackagePath,'-ChildRoot',$root,
        '-CandidatePath',$Candidate.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
    $actual=@($StartInfo.ArgumentList)
    if($StartInfo.FileName -cne $governing.hostPath -or $StartInfo.UseShellExecute -or -not $StartInfo.CreateNoWindow -or
        $StartInfo.RedirectStandardInput -or $StartInfo.RedirectStandardOutput -or $StartInfo.RedirectStandardError -or
        -not [string]::IsNullOrEmpty($StartInfo.Arguments) -or -not [string]::IsNullOrEmpty($StartInfo.UserName) -or
        $actual.Count -ne $expected.Count){throw 'Recipient interruption creator differs from the closed original flags and argv.'}
    for($index=0;$index -lt $actual.Count;$index++){if($actual[$index] -cne $expected[$index]){throw 'Recipient interruption argv changed.'}}
    $budget=[long][Math]::Floor([Math]::Min(40000,($admission.Ends-[DateTimeOffset]::UtcNow).TotalMilliseconds))
    if($budget -lt 30000){throw 'Recipient interruption lacks readiness, terminal, recovery and retention reserve.'}
    $startedAt=[DateTimeOffset]::UtcNow;$clock=[Diagnostics.Stopwatch]::StartNew();$nonce=[guid]::NewGuid().ToString('N')
    $localEnd=$startedAt.AddMilliseconds($budget)
    if($localEnd -gt $admission.Ends){$localEnd=$admission.Ends}
    $directory=Join-Path $RepositoryRoot ('.test-output/recipient-interruption-'+$nonce)
    $null=New-Item -ItemType Directory -Path $directory;$null=Set-TestNativePrivateDirectory -Path $directory
    $StartInfo.ArgumentList.Add('-InterruptionOwnerDirectory');$StartInfo.ArgumentList.Add($directory)
    $actual=@($StartInfo.ArgumentList)
    $pending=[ordered]@{contract='win-pcinfo.recipient-view-interruption-draft/1.0.0';nonce=$nonce;testPath=$test;creator=$admission.Creator;
        hostPath=$StartInfo.FileName;hostSha256=(Get-FileHash $StartInfo.FileName).Hash.ToLowerInvariant();arguments=$actual;
        sidProvenance='Original creator token; exact closed child uses no alternate identity.';parentPendingSha256=(Get-TestNativeDigest $context.Parent.Pending);
        cohortSha256=$governing.cohortSha256;candidatePath=$Candidate.Path;candidateSha256=$Candidate.Sha256;
        manifestPath=$PreparedManifestPath;manifestSha256=$PreparedManifestSha256;fixtureRoot=$root;packagePath=$PackagePath;
        directory=$directory;repositoryRoot=$RepositoryRoot;localAuthorityEnds=$localEnd.ToUniversalTime().ToString('o');
        rootNonce=$context.Root.Pending.nonce;parentNonce=$context.Parent.Pending.nonce;
        packageSha256=(Get-FileHash $PackagePath).Hash.ToLowerInvariant();authorityEnds=$admission.Ends.ToString('o');
        readinessMaximumMs=20000;terminalMaximumMs=5000;localMaximumMs=40000;processTreeAbsenceClaim=$false}
    Write-QualificationFixtureRecord -Path (Join-Path $directory 'original-pending.json') -Value $pending
    Write-QualificationFixtureRecord -Path (Join-Path $directory 'owned-pending.json') -Value $pending
    $owner=[pscustomobject]@{Directory=$directory;Pending=$pending;BudgetMs=$budget;Clock=$clock;Candidate=$Candidate;
        StartInfo=$StartInfo;StartRequested=$false;Started=$false;Process=$null;SafeHandle=$null;Identity=$null;Ready=$null;
        Deliberate=$false;Forced=$false;TerminalVerified=$false;TerminalRetained=$false;ExitCode=$null;
        RecoveryVerified=$false;Unsafe=$false;Disposed=$false}
    if($null -eq (Get-Variable RecipientInterruptionOwners -Scope Script -ErrorAction SilentlyContinue)){$script:RecipientInterruptionOwners=[Collections.Generic.List[object]]::new()}
    $script:RecipientInterruptionOwners.Add($owner)
    $owner
}

function Get-RecipientViewingInterruptionRemainingMs {
    param($Owner)
    $local=[DateTimeOffset]::ParseExact($Owner.Pending.localAuthorityEnds,'o',[Globalization.CultureInfo]::InvariantCulture)
    $absolute=[DateTimeOffset]::ParseExact($Owner.Pending.authorityEnds,'o',[Globalization.CultureInfo]::InvariantCulture)
    $inherited=[DateTimeOffset]::ParseExact($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC,'o',[Globalization.CultureInfo]::InvariantCulture)
    if($local.Offset -ne [TimeSpan]::Zero -or $absolute.Offset -ne [TimeSpan]::Zero -or $inherited.Offset -ne [TimeSpan]::Zero){throw 'Recipient remaining authority must be exact original UTC.'}
    $now=[DateTimeOffset]::UtcNow
    [long][Math]::Floor([Math]::Min((Get-QualificationFixtureRemainingMs $Owner),[Math]::Min(($local-$now).TotalMilliseconds,[Math]::Min(($absolute-$now).TotalMilliseconds,($inherited-$now).TotalMilliseconds))))
}
function Assert-RecipientViewingInterruptionCreation {
    param($Owner)
    if($Owner.StartRequested -or (Get-RecipientViewingInterruptionRemainingMs $Owner) -lt 30000){throw 'Recipient interruption creation reserve expired.'}
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $Owner.Pending.repositoryRoot -SelfIdentity $Owner.Pending.creator
    if((Get-TestNativeDigest $context.Parent.Pending) -cne $Owner.Pending.parentPendingSha256 -or
        $context.Root.Admission.cohortSha256 -cne $Owner.Pending.cohortSha256 -or
        $context.Root.Admission.hostPath -cne $Owner.Pending.hostPath -or
        $context.Root.Admission.candidatePath -cne $Owner.Pending.candidatePath -or
        $context.Root.Admission.preparedManifestPath -cne $Owner.Pending.manifestPath -or
        $context.Root.Admission.preparedManifestSha256 -cne $Owner.Pending.manifestSha256 -or
        $Owner.StartInfo.FileName -cne $Owner.Pending.hostPath -or ($Owner.StartInfo.ArgumentList -join '|') -cne ($Owner.Pending.arguments -join '|') -or
        $Owner.StartInfo.UseShellExecute -or -not $Owner.StartInfo.CreateNoWindow -or
        $Owner.StartInfo.RedirectStandardInput -or $Owner.StartInfo.RedirectStandardOutput -or $Owner.StartInfo.RedirectStandardError){throw 'Recipient creation changed its authenticated parent, cohort or exact original creator.'}
    Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory 'original-creation-request.json') -Value $Owner.Pending
    $Owner.StartRequested=$true
}

function Register-RecipientViewingInterruptionProcess {
    param($Owner,$Process)
    try{
        Register-QualificationFixtureProcess -Owner $Owner -Process $Process
        Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory 'startup-ack.json') -Value ([ordered]@{
            contract='win-pcinfo.recipient-interruption-startup-draft/1.0.0';nonce=$Owner.Pending.nonce;
            pendingSha256=(Get-FileHash (Join-Path $Owner.Directory 'owned-pending.json')).Hash.ToLowerInvariant();
            identitySha256=(Get-FileHash (Join-Path $Owner.Directory 'original-identity.json')).Hash.ToLowerInvariant();
            child=$Owner.Identity;childOwnerSid=$Owner.Pending.creator.OwnerSid;hostPath=$Owner.Pending.hostPath;
            observation='Original parent-held creation result; child self observation grants no creation-handle authority.'})
    }catch{$Owner.Unsafe=$true;throw}
}

function Assert-RecipientViewingInterruptionChild {
    param([string]$RepositoryRoot,[string]$OwnerDirectory,$Candidate,[string]$PreparedManifestPath,[string]$PreparedManifestSha256,
        [string]$ChildRoot,[string]$ChildPackagePath)
    $boundary=Join-Path $RepositoryRoot '.test-output'
    if([string]::IsNullOrEmpty($OwnerDirectory) -or [IO.Path]::GetDirectoryName($OwnerDirectory) -cne $boundary -or
        [IO.Path]::GetFileName($OwnerDirectory) -cnotmatch '^recipient-interruption-[a-f0-9]{32}$' -or
        ((Get-Item -LiteralPath $OwnerDirectory).Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'Direct ViewChild has no exact original-owner envelope.'}
    $pendingPath=Join-Path $OwnerDirectory 'owned-pending.json';$pending=Read-TestNativeRecord $pendingPath
    foreach($name in @('contract','nonce','directory','repositoryRoot','testPath','rootNonce','parentNonce','parentPendingSha256',
        'cohortSha256','hostPath','candidatePath','candidateSha256','manifestPath','manifestSha256','fixtureRoot','packagePath','packageSha256','localAuthorityEnds')){
        if($pending.$name -isnot [string]){throw 'Recipient child envelope requires strict scalar ownership fields.'}
    }
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $RepositoryRoot -SelfIdentity $pending.creator
    # Validate the original parent using the shared authenticated reader. This
    # creates neither an ordinary File/Case lease nor native authority for self.
    if($pending.contract -cne 'win-pcinfo.recipient-view-interruption-draft/1.0.0' -or $pending.nonce -cnotmatch '^[a-f0-9]{32}$' -or
        $pending.directory -cne $OwnerDirectory -or $pending.repositoryRoot -cne $RepositoryRoot -or
        $pending.testPath -cne (Join-Path $RepositoryRoot 'tests/RecipientViewingApplication.Tests.ps1') -or
        $env:WINPCINFO_TEST_FILE_LEASE -cne $context.Root.Pending.nonce -or
        ($context.Parent.Pending.nativeRole -ceq 'QualificationCase' -and $env:WINPCINFO_TEST_CASE_LEASE -cne $context.Parent.Pending.nonce) -or
        ($context.Parent.Pending.nativeRole -ceq 'TestFile' -and -not [string]::IsNullOrEmpty($env:WINPCINFO_TEST_CASE_LEASE)) -or
        $pending.rootNonce -cne $context.Root.Pending.nonce -or $pending.parentNonce -cne $context.Parent.Pending.nonce -or
        (Get-TestNativeDigest $context.Parent.Pending) -cne $pending.parentPendingSha256 -or
        $context.Parent.Admission.testPath -cne $pending.testPath -or $context.Root.Admission.cohortSha256 -cne $pending.cohortSha256 -or
        $context.Root.Admission.hostPath -cne $pending.hostPath -or $context.Root.Admission.candidatePath -cne $pending.candidatePath -or
        $context.Root.Admission.preparedManifestPath -cne $pending.manifestPath -or $context.Root.Admission.preparedManifestSha256 -cne $pending.manifestSha256 -or
        $Candidate.Prepared -isnot [bool] -or -not $Candidate.Prepared -or -not $Candidate.Stream.CanRead -or
        $Candidate.Path -cne $pending.candidatePath -or $Candidate.Sha256 -cne $pending.candidateSha256 -or
        $PreparedManifestPath -cne $pending.manifestPath -or $PreparedManifestSha256 -cne $pending.manifestSha256 -or
        $ChildRoot -cne $pending.fixtureRoot -or $ChildPackagePath -cne $pending.packagePath -or
        (Get-FileHash $ChildPackagePath).Hash.ToLowerInvariant() -cne $pending.packageSha256){throw 'Recipient child changed its actual parent, envelope, prepared inputs, root or package.'}
    $arguments=@(Get-RecipientViewingChildArguments)
    if($arguments.Count -ne $pending.arguments.Count){throw 'Recipient child command line differs from its original creator.'}
    for($index=0;$index -lt $arguments.Count;$index++){if($arguments[$index] -cne $pending.arguments[$index]){throw 'Recipient child command line differs from its original creator.'}}
    $end=[DateTimeOffset]::ParseExact($pending.localAuthorityEnds,'o',[Globalization.CultureInfo]::InvariantCulture)
    $parentEnd=[DateTimeOffset]::ParseExact($context.Parent.Pending.authorityEnds,'o',[Globalization.CultureInfo]::InvariantCulture).AddMilliseconds(-$context.Parent.Pending.cleanupReserveMs-2000)
    $inherited=[DateTimeOffset]::ParseExact($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC,'o',[Globalization.CultureInfo]::InvariantCulture)
    if($end.Offset -ne [TimeSpan]::Zero -or $parentEnd.Offset -ne [TimeSpan]::Zero -or $inherited.Offset -ne [TimeSpan]::Zero -or
        $end -gt $parentEnd -or $end -gt $inherited -or $end.AddMilliseconds(-10000) -le [DateTimeOffset]::UtcNow){throw 'Recipient child envelope has no decreasing original UTC authority.'}
    $watch=[Diagnostics.Stopwatch]::StartNew();$ackPath=Join-Path $OwnerDirectory 'startup-ack.json'
    while(-not [IO.File]::Exists($ackPath)){if($watch.ElapsedMilliseconds -ge 5000 -or [DateTimeOffset]::UtcNow -ge $end.AddMilliseconds(-10000)){throw 'Recipient original-startup acknowledgement exceeded its finite reserve.'};Start-Sleep -Milliseconds 25}
    $ack=Read-TestNativeRecord $ackPath;$self=Get-TestNativeSelfIdentity
    if($ack.contract -isnot [string] -or $ack.nonce -isnot [string] -or $ack.child.fullBirthUtc -isnot [string] -or
        ($ack.child.pid -isnot [int] -and $ack.child.pid -isnot [long]) -or $ack.childOwnerSid -isnot [string] -or $ack.hostPath -isnot [string] -or
        $ack.contract -cne 'win-pcinfo.recipient-interruption-startup-draft/1.0.0' -or $ack.nonce -cne $pending.nonce -or
        $ack.pendingSha256 -cne (Get-FileHash $pendingPath).Hash.ToLowerInvariant() -or
        $ack.identitySha256 -cne (Get-FileHash (Join-Path $OwnerDirectory 'original-identity.json')).Hash.ToLowerInvariant() -or
        $ack.child.pid -ne $self.Pid -or $ack.child.fullBirthUtc -cne $self.CreationUtc -or
        $ack.childOwnerSid -cne $self.OwnerSid -or $ack.hostPath -cne $self.HostPath){throw 'Recipient child self observation does not match the originally started child.'}
    Write-QualificationFixtureRecord -Path (Join-Path $OwnerDirectory 'child-special-claim.json') -Value ([ordered]@{
        nonce=$pending.nonce;ackSha256=(Get-FileHash $ackPath).Hash.ToLowerInvariant();pid=$self.Pid;fullBirthUtc=$self.CreationUtc;
        ownerSid=$self.OwnerSid;nativeDelegationGranted=$false;creationHandleOwnedByParent=$true})
}

function Get-RecipientViewingChildArguments {
    @([Environment]::GetCommandLineArgs()|Select-Object -Skip 1)
}

function Wait-RecipientViewingInterruptionReady {
    param($Owner)
    try{
        if(-not $Owner.Started -or $Owner.SafeHandle.IsClosed -or $Owner.SafeHandle.IsInvalid -or $null -ne $Owner.Ready){throw 'Recipient readiness lacks its unused original handle.'}
        $watch=[Diagnostics.Stopwatch]::StartNew();$path=Join-Path $Owner.Pending.fixtureRoot 'view-ready.json'
        while(-not [IO.File]::Exists($path)){
            $terminal=$Owner.Process.WaitForExit(0)
            if($terminal -isnot [bool] -or $terminal -or $watch.ElapsedMilliseconds -ge 20000 -or (Get-RecipientViewingInterruptionRemainingMs $Owner) -le 10000){throw 'Recipient real-view readiness was not established inside its finite reserve.'}
            Start-Sleep -Milliseconds 50
        }
        $ready=Read-TestNativeRecord -Path $path
        $claim=Read-TestNativeRecord -Path (Join-Path $Owner.Directory 'child-special-claim.json')
        if($claim.nonce -cne $Owner.Pending.nonce -or $claim.pid -ne $Owner.Identity.pid -or
            $claim.fullBirthUtc -cne $Owner.Identity.fullBirthUtc -or $claim.ownerSid -cne $Owner.Pending.creator.OwnerSid -or
            $claim.ackSha256 -cne (Get-FileHash (Join-Path $Owner.Directory 'startup-ack.json')).Hash.ToLowerInvariant() -or
            $claim.nativeDelegationGranted -isnot [bool] -or $claim.nativeDelegationGranted){throw 'Recipient ready state lacks its exact original-child special claim.'}
        if($ready.verified -isnot [bool] -or -not $ready.verified -or $ready.state -cne 'Opened' -or
            $ready.recoveryRegistered -isnot [bool] -or -not $ready.recoveryRegistered -or
            $ready.requestedArtifact -cne 'assessment-report.html'){throw 'Recipient readiness is not the original real registered HTML view.'}
        foreach($target in @($ready.workspacePath,$ready.artifactPath,$ready.journalPath)){
            if($target -isnot [string] -or -not [IO.Path]::GetFullPath($target).StartsWith($Owner.Pending.fixtureRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Recipient readiness paths escaped their exact fixture.'}
            if(([IO.File]::GetAttributes($target)-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'Recipient readiness target was redirected.'}
        }
        $journal=Read-RunRecoveryJournal -LiteralPath $ready.journalPath
        $artifact=@($journal.artifacts|Where-Object{ $_.kind -ceq 'EvidenceViewingArtifact' -and $_.artifactId -ceq $ready.artifactId -and $_.path -ceq $ready.artifactPath -and $_.cleanupAction -ceq 'Remove'})
        $workspace=@($journal.artifacts|Where-Object{ $_.kind -ceq 'Workspace' -and $_.path -ceq $ready.workspacePath})
        if($journal.phase -cne 'Viewing' -or $journal.owner.processId -ne $Owner.Identity.pid -or
            [DateTimeOffset]::Parse($journal.owner.processStartUtc).UtcTicks -ne [DateTimeOffset]::Parse($Owner.Identity.fullBirthUtc).UtcTicks -or
            $journal.owner.initiatingUserSid -cne $Owner.Pending.creator.OwnerSid -or $journal.planDigest -cne $Owner.Pending.packageSha256 -or
            $artifact.Count -ne 1 -or $workspace.Count -ne 1 -or -not [IO.File]::Exists($ready.artifactPath)){throw 'Recipient readiness journal does not identify its original child, package and real plaintext.'}
        Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory 'original-ready.json') -Value $ready
        $Owner.Ready=$ready;$ready
    }catch{$Owner.Unsafe=$true;throw}
}

function Interrupt-RecipientViewingOriginalProcess {
    param($Owner)
    try{
        if($Owner.Unsafe -or $null -eq $Owner.Ready -or $Owner.Forced -or $Owner.SafeHandle.IsClosed -or $Owner.SafeHandle.IsInvalid -or
            (Get-RecipientViewingInterruptionRemainingMs $Owner) -le 10000){throw 'Deliberate recipient interruption requires verified ready state and original reserve.'}
        Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory 'original-interruption-request.json') -Value ([ordered]@{identity=$Owner.Identity;ready=$Owner.Ready;deliberate=$true})
        $Owner.Deliberate=$true;$Owner.Forced=$true
        $Owner.Process.Kill() # Original parent-only operation, never an unadmitted tree.
        $wait=[int][Math]::Min(5000,(Get-RecipientViewingInterruptionRemainingMs $Owner)-5000)
        if($wait -lt 1){throw 'Recipient terminal reservation expired.'}
        $terminal=$Owner.Process.WaitForExit($wait)
        if($terminal -isnot [bool] -or -not $terminal){throw 'Recipient original terminal Boolean is unverified.'}
        $exit=$Owner.Process.ExitCode;if($exit -isnot [int]){throw 'Recipient interrupted native exit is unknown.'}
        $Owner.ExitCode=$exit;$Owner.TerminalVerified=$true
        Save-RecipientViewingInterruptionTerminal -Owner $Owner
    }catch{$Owner.Unsafe=$true;throw}
}

function Save-RecipientViewingInterruptionTerminal {
    param($Owner)
    $record=[ordered]@{identity=$Owner.Identity;arguments=$Owner.Pending.arguments;deliberate=$Owner.Deliberate;forced=$Owner.Forced;
        nativeTerminalObserved=$Owner.TerminalVerified;nativeExitCode=$Owner.ExitCode;unsafe=$Owner.Unsafe;
        classification='DeliberateInterruptionPendingRecovery';ordinaryNativePass=$false;processTreeAbsenceClaim=$false}
    $failures=[Collections.Generic.List[Exception]]::new()
    foreach($name in @('original-terminal.json','terminal.json')){try{Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory $name) -Value $record}catch{$failures.Add($_.Exception)}}
    if($failures.Count){$Owner.Unsafe=$true;throw [AggregateException]::new('Recipient original outcome retention failed.',$failures.ToArray())}
    $Owner.TerminalRetained=$true
}

function Confirm-RecipientViewingInterruptionRecovery {
    param($Owner,$Recovery)
    try{
        if($Owner.Unsafe -or -not $Owner.Deliberate -or -not $Owner.Forced -or -not $Owner.TerminalVerified -or -not $Owner.TerminalRetained -or
            $null -eq $Owner.Ready -or $Recovery.cleanup.verified -isnot [bool] -or -not $Recovery.cleanup.verified -or
            [IO.File]::Exists($Owner.Ready.artifactPath) -or [IO.Directory]::Exists($Owner.Ready.workspacePath) -or
            [IO.File]::Exists($Owner.Ready.journalPath) -or -not [IO.File]::Exists($Owner.Pending.packagePath) -or
            (Get-FileHash $Owner.Pending.packagePath).Hash.ToLowerInvariant() -cne $Owner.Pending.packageSha256 -or
            (Get-RecipientViewingInterruptionRemainingMs $Owner) -lt 1000){throw 'Recipient recovery cannot replace original terminal, absence, preservation or retention proof.'}
        Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory 'original-recovery-proof.json') -Value ([ordered]@{
            originalTerminalSha256=(Get-FileHash (Join-Path $Owner.Directory 'original-terminal.json')).Hash.ToLowerInvariant();
            recovery=$Recovery;plaintextAbsent=$true;workspaceAbsent=$true;journalAbsent=$true;packageSha256=$Owner.Pending.packageSha256;
            classification='DeliberateInterruptionRecovered';ordinaryNativePass=$false;processTreeAbsenceClaim=$false})
        $Owner.RecoveryVerified=$true
    }catch{$Owner.Unsafe=$true;throw}
}

function Complete-RecipientViewingInterruption {
    param($Owner,$Process,[AllowNull()][Management.Automation.ErrorRecord]$BodyError,[scriptblock[]]$Cleanup=@())
    if($null -ne $BodyError -and (Test-QualificationCleanupUnverified $BodyError.Exception)){$Owner.Unsafe=$true}
    $actions=@({try{
        if($null -ne $Process -and $null -eq $Owner.Process){$Owner.Process=$Process;$Owner.Started=$true;$Owner.Unsafe=$true}
        if($Owner.Started -and -not $Owner.TerminalVerified){
            $Owner.Unsafe=$true
            $fallbackError=$null
            try{
                if($null -eq $Owner.SafeHandle -or $Owner.SafeHandle.IsClosed -or $Owner.SafeHandle.IsInvalid -or (Get-RecipientViewingInterruptionRemainingMs $Owner) -le 1000){throw 'Recipient fallback lacks its original handle or reserve.'}
                $terminal=$Owner.Process.WaitForExit(0);if($terminal -isnot [bool]){throw 'Recipient fallback observation is not Boolean.'}
                if(-not $terminal){
                    $Owner.Forced=$true;$Owner.Process.Kill()
                    $wait=[int][Math]::Min(5000,(Get-RecipientViewingInterruptionRemainingMs $Owner)-1000)
                    if($wait -lt 1){throw 'Recipient fallback terminal wait lacks positive original authority and retention reserve.'}
                    $terminal=$Owner.Process.WaitForExit($wait)
                }
                if($terminal -isnot [bool] -or -not $terminal -or $Owner.Process.ExitCode -isnot [int]){throw 'Recipient fallback terminal remains unverified.'}
                $Owner.TerminalVerified=$true;$Owner.ExitCode=$Owner.Process.ExitCode
            }catch{$fallbackError=$_}
            Complete-QualificationHarness -BodyError $fallbackError -Cleanup @({if(-not $Owner.TerminalRetained){Save-RecipientViewingInterruptionTerminal $Owner}})
        }
        if($Owner.StartRequested -and -not $Owner.Started){$Owner.Unsafe=$true}
        if($Owner.Started -and (-not $Owner.RecoveryVerified -or -not $Owner.TerminalRetained)){$Owner.Unsafe=$true}
        if($Owner.Unsafe){$exception=[InvalidOperationException]::new('Recipient interruption uncertainty retains the exact original fixture and outcome.');$exception.Data['OwnedCleanupUnverified']=$true;throw $exception}
        if((Get-RecipientViewingInterruptionRemainingMs $Owner) -lt 1000){throw 'Recipient final disposition authority expired.'}
        if($Owner.Started){$Owner.Process.Dispose();$Owner.Disposed=$true}
        Write-QualificationFixtureRecord -Path (Join-Path $Owner.Directory 'original-close-proof.json') -Value ([ordered]@{recoveryVerified=$Owner.RecoveryVerified;disposed=$Owner.Disposed;forced=$Owner.Forced;ordinaryNativePass=$false})
        if((Get-RecipientViewingInterruptionRemainingMs $Owner) -lt 1000){throw 'Recipient close-proof retention exhausted original authority.'}
        [IO.File]::Delete((Join-Path $Owner.Directory 'owned-pending.json'))
        if([IO.File]::Exists((Join-Path $Owner.Directory 'owned-pending.json'))){throw 'Recipient special owner pending release failed.'}
        if((Get-RecipientViewingInterruptionRemainingMs $Owner) -lt 0){
            $Owner.Unsafe=$true
            [IO.File]::Copy((Join-Path $Owner.Directory 'original-pending.json'),(Join-Path $Owner.Directory 'owned-pending.json'),$false)
            throw 'Recipient pending release exceeded original authority; original bytes restored.'
        }
    }catch{$Owner.Unsafe=$true;throw}})+$Cleanup
    Complete-QualificationHarness -BodyError $BodyError -Cleanup $actions
}
