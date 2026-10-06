[CmdletBinding()]
param([ValidateSet('None','IgnoreTerminalBoolean','AcceptUnknownExit','SkipTerminalRetention','PrematureDispose','SuppressIndependentCleanup')][string]$FixtureFault='None',[ValidateSet('Both','Expiry','Clipped','None')][string]$ResidualControl='Both',[string]$ObservationDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'QualificationRecipientViewingInterruption.ps1')
# Disclosed substitutions: File/Case admission, SID/ACL, original Process and
# product journal/recovery are synthetic. No Process.Start/Kill, native runtime,
# provider, certificate, key, trust, WPF or process query is executed.
$script:controls=0;$script:budget=60000;$script:writeFault=''
$originalFileLease=$env:WINPCINFO_TEST_FILE_LEASE;$originalCaseLease=$env:WINPCINFO_TEST_CASE_LEASE;$originalAuthority=$env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC
$script:childSelf=$null;$script:childArguments=@();$script:expireAtClose=$null
$script:denyParent=$false;$script:admissionEnds=$null
function Assert-RecipientControl {param([bool]$Condition,[string]$Message);if(-not $Condition){throw $Message};$script:controls++}
function Write-RecipientResidualControlObservation {
    param([string]$Name,$Observation)
    if ([string]::IsNullOrEmpty($ObservationDirectory)) { return }
    if (-not [IO.Path]::IsPathFullyQualified($ObservationDirectory)) { throw 'Residual observations require an explicit absolute output directory.' }
    $directory=$ObservationDirectory;$null=[IO.Directory]::CreateDirectory($directory)
    $record=[ordered]@{contract='disclosed-child-free-recipient-residual-control/1.0.0';name=$Name;helperSha256=(Get-FileHash (Join-Path $PSScriptRoot 'QualificationRecipientViewingInterruption.ps1')).Hash.ToLowerInvariant();observation=$Observation}
    [IO.File]::WriteAllText((Join-Path $directory ($Name+'-'+[guid]::NewGuid().ToString('N')+'.json')),($record|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
}
if($FixtureFault -ceq 'IgnoreTerminalBoolean'){
    $text=${function:Interrupt-RecipientViewingOriginalProcess}.ToString().Replace('if($terminal -isnot [bool] -or -not $terminal)','if($false)')
    Set-Item Function:Interrupt-RecipientViewingOriginalProcess ([scriptblock]::Create($text))
}
if($FixtureFault -ceq 'AcceptUnknownExit'){
    $text=${function:Interrupt-RecipientViewingOriginalProcess}.ToString().Replace('if($exit -isnot [int])','if($false)')
    Set-Item Function:Interrupt-RecipientViewingOriginalProcess ([scriptblock]::Create($text))
}
if($FixtureFault -ceq 'SkipTerminalRetention'){
    $text=${function:Interrupt-RecipientViewingOriginalProcess}.ToString().Replace('Save-RecipientViewingInterruptionTerminal -Owner $Owner','')
    Set-Item Function:Interrupt-RecipientViewingOriginalProcess ([scriptblock]::Create($text))
}
if($FixtureFault -ceq 'PrematureDispose'){
    $text=${function:Interrupt-RecipientViewingOriginalProcess}.ToString().Replace('Save-RecipientViewingInterruptionTerminal -Owner $Owner','$Owner.Process.Dispose();Save-RecipientViewingInterruptionTerminal -Owner $Owner')
    Set-Item Function:Interrupt-RecipientViewingOriginalProcess ([scriptblock]::Create($text))
}
if($FixtureFault -ceq 'SuppressIndependentCleanup'){
    $text=${function:Complete-QualificationHarness}.ToString().Replace('foreach ($action in $Cleanup)','foreach ($action in @($Cleanup|Select-Object -First 1))')
    Set-Item Function:Complete-QualificationHarness ([scriptblock]::Create($text))
}
$pureRoot=Join-Path (Split-Path -Parent $PSScriptRoot) ('pure-controls-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($pureRoot);$fixtures=[Collections.Generic.List[object]]::new()
function Get-QualificationCleanupBlockerPath {Join-Path $pureRoot 'synthetic-blocker.json'}
function Get-TestNativeSelfIdentity {if($null -ne $script:childSelf){return $script:childSelf};[pscustomobject]@{Pid=123;CreationUtc='2030-01-01T00:00:00.0000000Z';OwnerSid='synthetic-pure-sid';HostPath=$script:context.Root.Admission.hostPath}}
function Get-RecipientViewingChildArguments {$script:childArguments}
function Get-QualificationFixtureAdmission {param($RepositoryRoot);[pscustomobject]@{Ends=$(if($null -ne $script:admissionEnds){$script:admissionEnds}else{[DateTimeOffset]::UtcNow.AddMilliseconds($script:budget)});Parent=$script:context.Parent;Creator=(Get-TestNativeSelfIdentity)}}
function Get-TestNativeAdmissionContext {param($RepositoryRoot,$SelfIdentity);if($script:denyParent){throw 'Disclosed missing authenticated parent.'};$script:context}
function Set-TestNativePrivateDirectory {param($Path);'synthetic-pure-sid'}
function Get-QualificationFixtureOriginalIdentity {param($Process);[pscustomobject]@{Handle=$Process.SafeHandle;Record=[ordered]@{pid=456;fullBirthUtc='2030-01-01T00:00:00.1234567Z';originalSafeHandleValue=789}}}
function Read-RunRecoveryJournal {param($LiteralPath);[IO.File]::ReadAllText($LiteralPath)|ConvertFrom-Json -DateKind String}
$actualRecordWriter=${function:Write-QualificationFixtureRecord}
function Write-QualificationFixtureRecord {param($Path,$Value);if([IO.Path]::GetFileName($Path) -ceq $script:writeFault){throw 'Disclosed private retention failure.'};& $actualRecordWriter -Path $Path -Value $Value;if([IO.Path]::GetFileName($Path) -ceq 'original-close-proof.json' -and $null -ne $script:expireAtClose){$script:expireAtClose.BudgetMs=0}}
function New-RecipientControlFixture {
    param([string]$AdmissionFault='',[string]$Mode='Known',[switch]$SkipChildClaim)
    $script:childSelf=$null
    $repo=Join-Path $pureRoot ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory((Join-Path $repo 'tests'))
    $source=Join-Path $repo 'tests/RecipientViewingApplication.Tests.ps1';[IO.File]::Copy((Join-Path $PSScriptRoot 'RecipientViewingApplication.Tests.ps1'),$source)
    $runtimePath=Join-Path $repo 'pwsh.exe';[IO.File]::WriteAllText($runtimePath,'Disclosed synthetic host; never executed.')
    $candidatePath=Join-Path $repo 'WIN-PCInfo.ps1';[IO.File]::WriteAllText($candidatePath,'# Disclosed synthetic candidate; never invoked.')
    $manifest=Join-Path $repo 'prepared.json';[IO.File]::WriteAllText($manifest,'{"synthetic":true}')
    $candidate=[pscustomobject]@{Path=$candidatePath;Sha256=(Get-FileHash $candidatePath).Hash.ToLowerInvariant();Prepared=$true;
        OwnedDirectory=$null;Stream=[IO.File]::Open($candidatePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}
    $root=Join-Path ([IO.Path]::GetTempPath()) ('winpcinfo-recipient-view-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($root)
    $package=Join-Path $root 'synthetic.winpcinfo';[IO.File]::WriteAllText($package,'Disclosed synthetic protected-package stand-in; no key/protector.')
    $pins=@($source,$runtimePath,$candidatePath,$manifest)|ForEach-Object{[pscustomobject]@{path=$_;sha256=(Get-FileHash $_).Hash.ToLowerInvariant()}}
    $admission=[pscustomobject]@{testPath=$source;hostPath=$runtimePath;candidatePath=$candidatePath;preparedManifestPath=$manifest;
        preparedManifestSha256=(Get-FileHash $manifest).Hash.ToLowerInvariant();inputs=$pins;cohortSha256=(Get-TestNativeDigest $pins)}
    $parentPending=[ordered]@{nonce=('f'*32);nativeRole='TestFile';authorityEnds='2030-01-01T00:00:00.0000000Z';cleanupReserveMs=1000}
    $script:context=[pscustomobject]@{Parent=[pscustomobject]@{Admission=$admission;Pending=$parentPending};Root=[pscustomobject]@{Admission=$admission;Pending=$parentPending}}
    $env:WINPCINFO_TEST_FILE_LEASE=$parentPending.nonce;$env:WINPCINFO_TEST_CASE_LEASE=$null;$env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC=$(if($null -ne $script:admissionEnds){$script:admissionEnds.ToString('o')}else{[DateTimeOffset]::UtcNow.AddMilliseconds($script:budget).ToString('o')})
    $start=[Diagnostics.ProcessStartInfo]::new($runtimePath);$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    foreach($arg in @('-NoLogo','-NoProfile','-File',$source,'-ViewChild','-ChildPackagePath',$package,'-ChildRoot',$root,
        '-CandidatePath',$candidatePath,'-PreparedManifestPath',$manifest,'-PreparedManifestSha256',$admission.preparedManifestSha256)){$start.ArgumentList.Add($arg)}
    switch($AdmissionFault){WrongSource{$admission.testPath+='x'};WrongHost{$start.FileName+='x'};WrongArg{$start.ArgumentList[4]='-Other'};
        WrongCandidate{$candidate.Path+='x'};NotPrepared{$candidate.Prepared=$false};WrongPin{$pins[1].sha256='0'*64};Shell{$start.UseShellExecute=$true}}
    $fixture=[pscustomobject]@{Repository=$repo;Root=$root;Candidate=$candidate;Start=$start;Package=$package;Manifest=$manifest;Owner=$null;Process=$null;Ready=$null}
    $fixtures.Add($fixture)
    $owner=New-RecipientViewingInterruptionOwner -RepositoryRoot $repo -Candidate $candidate -PreparedManifestPath $manifest -PreparedManifestSha256 $admission.preparedManifestSha256 -StartInfo $start -PackagePath $package -FixtureRoot $root
    $fixture.Owner=$owner
    Assert-RecipientViewingInterruptionCreation $owner
    $process=[pscustomobject]@{Mode=$Mode;SafeHandle=[pscustomobject]@{IsClosed=$false;IsInvalid=$false};ExitCode=$(if($Mode -ceq 'UnknownExit'){$null}else{137});
        Killed=$false;Disposed=$false;Waits=[Collections.Generic.List[int]]::new();Directory=$owner.Directory;Owner=$owner}
    $process|Add-Member ScriptMethod Kill {$this.Killed=$true;if($this.Mode -ceq 'KillExpires'){$this.Owner.BudgetMs=$this.Owner.Clock.ElapsedMilliseconds+999}}
    $process|Add-Member ScriptMethod WaitForExit {param([int]$Milliseconds);$this.Waits.Add($Milliseconds);if($this.Mode -ceq 'NonBoolean'){return 'true'};if($this.Mode -ceq 'FalseTerminal'){return $false};return $this.Killed}
    $process|Add-Member ScriptMethod Dispose {if(-not [IO.File]::Exists((Join-Path $this.Directory 'original-terminal.json')) -or -not [IO.File]::Exists((Join-Path $this.Directory 'original-recovery-proof.json'))){throw 'Original handle disposed before terminal and actual recovery proof.'};$this.Disposed=$true}
    $fixture.Process=$process;Register-RecipientViewingInterruptionProcess -Owner $owner -Process $process
    $script:childArguments=@($start.ArgumentList)
    if(-not $SkipChildClaim){
        $script:childSelf=[pscustomobject]@{Pid=456;CreationUtc='2030-01-01T00:00:00.1234567Z';OwnerSid='synthetic-pure-sid';HostPath=$runtimePath}
        Assert-RecipientViewingInterruptionChild -RepositoryRoot $repo -OwnerDirectory $owner.Directory -Candidate $candidate -PreparedManifestPath $manifest -PreparedManifestSha256 $admission.preparedManifestSha256 -ChildRoot $root -ChildPackagePath $package
        $script:childSelf=$null
    }
    $workspace=Join-Path $root ('WINPCInfo-Workspace-'+[guid]::NewGuid().ToString('D'));$null=[IO.Directory]::CreateDirectory($workspace)
    $artifact=Join-Path $workspace 'synthetic.view';[IO.File]::WriteAllText($artifact,'Disclosed plaintext fixture.')
    $journalRoot=Join-Path $root ('WINPCInfo-Recovery-v1-'+[guid]::NewGuid().ToString('D'));$null=[IO.Directory]::CreateDirectory($journalRoot)
    $journalPath=Join-Path $journalRoot 'run-recovery.json';$id=[guid]::NewGuid().ToString('D')
    $journal=[ordered]@{phase='Viewing';owner=[ordered]@{processId=456;processStartUtc='2030-01-01T00:00:00.1234567Z';initiatingUserSid='synthetic-pure-sid'};
        planDigest=$owner.Pending.packageSha256;artifacts=@([ordered]@{kind='Workspace';path=$workspace},[ordered]@{kind='EvidenceViewingArtifact';artifactId=$id;path=$artifact;cleanupAction='Remove'})}
    [IO.File]::WriteAllText($journalPath,($journal|ConvertTo-Json -Depth 8))
    $ready=[ordered]@{state='Opened';verified=$true;requestedArtifact='assessment-report.html';recoveryRegistered=$true;
        workspacePath=$workspace;artifactPath=$artifact;journalPath=$journalPath;artifactId=$id}
    [IO.File]::WriteAllText((Join-Path $root 'view-ready.json'),($ready|ConvertTo-Json -Depth 8));$fixture.Ready=$ready
    $fixture
}
function Invoke-RecipientControlRecovery {
    param($Fixture)
    # This disclosed fixture deletion is not product recovery certification.
    [IO.File]::Delete($Fixture.Ready.artifactPath);[IO.Directory]::Delete($Fixture.Ready.workspacePath)
    [IO.File]::Delete($Fixture.Ready.journalPath);[IO.Directory]::Delete([IO.Path]::GetDirectoryName($Fixture.Ready.journalPath))
    [pscustomobject]@{cleanup=[pscustomobject]@{verified=$true};reasonCode='DisclosedSyntheticRecovery'}
}
function Invoke-RecipientActualOwningFinalization {
    param($Fixture,$OriginalError)
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'RecipientViewingApplication.Tests.ps1'),[ref]$tokens,[ref]$errors)
    $nodes=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.TryStatementAst] -and $null -ne $node.Finally},$true))
    $fixtureNode=@($nodes|Where-Object{$_.Finally.Extent.Text.Contains('$approved.certificate.Dispose()')})
    $candidateNode=@($nodes|Where-Object{$_.Finally.Extent.Text.Contains('Close-TestCandidate -Candidate $candidateContext -BodyError $candidateError')})
    if($errors.Count -or $fixtureNode.Count -ne 1 -or $candidateNode.Count -ne 1){throw 'Actual owning finalizers must remain unique.'}
    $harness=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'TestHarness.ps1'),[ref]$tokens,[ref]$errors)
    $close=@($harness.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Close-TestCandidate'},$false))
    if($errors.Count -or $close.Count -ne 1){throw 'Actual candidate close definition must remain unique.'}
    . ([scriptblock]::Create($close[0].Extent.Text))
    $safe=[pscustomobject]@{};$safe|Add-Member ScriptMethod Dispose {}
    $approved=[pscustomobject]@{certificate=$safe};$recipient=[pscustomobject]@{certificate=$safe}
    $root=$Fixture.Root;$owner=$Fixture.Owner;$candidateContext=$Fixture.Candidate;$bodyError=$OriginalError
    $fixtureCleanup=[pscustomobject]@{Unverified=$false;CandidateCloseAttempted=$false};$candidateError=$null
    try{$null=. ([scriptblock]::Create($fixtureNode[0].Finally.Extent.Text.Trim().TrimStart('{').TrimEnd('}')))}catch{$candidateError=$_}
    $caught=$null;try{$null=. ([scriptblock]::Create($candidateNode[0].Finally.Extent.Text.Trim().TrimStart('{').TrimEnd('}')))}catch{$caught=$_}
    [pscustomobject]@{Error=$caught;RootRetained=[IO.Directory]::Exists($root);CandidateClosed=(-not $candidateContext.Stream.CanRead);CandidateAttempted=$fixtureCleanup.CandidateCloseAttempted}
}
try{
    if($ResidualControl -cin @('Both','Expiry')){
        $fixture=New-RecipientControlFixture -Mode KillExpires
        $caught=$null;try{$null=Complete-RecipientViewingInterruption -Owner $fixture.Owner -Process $fixture.Process}catch{$caught=$_}
        Write-RecipientResidualControlObservation 'post-kill-expiry' ([ordered]@{waits=@($fixture.Process.Waits);terminalVerified=$fixture.Owner.TerminalVerified;unsafe=$fixture.Owner.Unsafe;disposed=$fixture.Process.Disposed;error=$(if($null -ne $caught){$caught.Exception.ToString()}else{$null})})
        Assert-RecipientControl ($fixture.Process.Killed -and $fixture.Process.Waits.Count -eq 1 -and $fixture.Process.Waits[0] -eq 0) 'Post-Kill exhausted reserve must refuse every terminal wait; no zero, negative or infinite wait is admitted.'
        Assert-RecipientControl ($null -ne $caught -and $fixture.Owner.Unsafe -and -not $fixture.Owner.TerminalVerified -and -not $fixture.Process.Disposed -and
            [IO.File]::Exists((Join-Path $fixture.Owner.Directory 'original-terminal.json')) -and [IO.File]::Exists((Join-Path $fixture.Owner.Directory 'owned-pending.json')) -and [IO.File]::Exists($fixture.Package)) 'Post-Kill expiry independently retains unknown original outcome, pending, handle and package without claiming a terminal.'
    }
    if($ResidualControl -cin @('Both','Clipped')){
        # Disclosed deterministic substitution in the actual constructor only:
        # its two UTC observations differ by 10ms; no native clock or lease renews.
        $originalConstructor=${function:New-RecipientViewingInterruptionOwner}
        $script:budgetClock=[DateTimeOffset]::UtcNow;$script:startedClock=$script:budgetClock.AddMilliseconds(10)
        $script:admissionEnds=$script:budgetClock.AddMilliseconds(35000)
        $constructorText=$originalConstructor.ToString()
        $budgetAnchor='($admission.Ends-[DateTimeOffset]::UtcNow)';$startedAnchor='$startedAt=[DateTimeOffset]::UtcNow;'
        if(([regex]::Matches($constructorText,[regex]::Escape($budgetAnchor))).Count -ne 1 -or ([regex]::Matches($constructorText,[regex]::Escape($startedAnchor))).Count -ne 1){throw 'Disclosed constructor UTC anchors must remain exact and unique.'}
        Set-Item Function:New-RecipientViewingInterruptionOwner ([scriptblock]::Create($constructorText.Replace($budgetAnchor,'($admission.Ends-$script:budgetClock)').Replace($startedAnchor,'$startedAt=$script:startedClock;')))
        try{
            $fixture=New-RecipientControlFixture -SkipChildClaim
            $local=[DateTimeOffset]::ParseExact($fixture.Owner.Pending.localAuthorityEnds,'o',[Globalization.CultureInfo]::InvariantCulture)
            Write-RecipientResidualControlObservation 'clipped-parent' ([ordered]@{budgetClock=$script:budgetClock.ToString('o');startedClock=$script:startedClock.ToString('o');originalEnd=$script:admissionEnds.ToString('o');localEnd=$local.ToString('o');budgetMs=$fixture.Owner.BudgetMs})
            Assert-RecipientControl ($local -eq $script:admissionEnds -and $local.Offset -eq [TimeSpan]::Zero -and $fixture.Owner.BudgetMs -eq 35000) 'Clipped constructor retains the exact original UTC admission end despite a later startup observation.'
            $script:childSelf=[pscustomobject]@{Pid=456;CreationUtc='2030-01-01T00:00:00.1234567Z';OwnerSid='synthetic-pure-sid';HostPath=$fixture.Start.FileName}
            Assert-RecipientViewingInterruptionChild -RepositoryRoot $fixture.Repository -OwnerDirectory $fixture.Owner.Directory -Candidate $fixture.Candidate -PreparedManifestPath $fixture.Manifest -PreparedManifestSha256 $script:context.Root.Admission.preparedManifestSha256 -ChildRoot $fixture.Root -ChildPackagePath $fixture.Package
            Assert-RecipientControl ([IO.File]::Exists((Join-Path $fixture.Owner.Directory 'child-special-claim.json'))) 'Actual special child guard accepts the positive clipped-parent envelope without extending original authority.'
        }finally{Set-Item Function:New-RecipientViewingInterruptionOwner $originalConstructor;$script:admissionEnds=$null;$script:childSelf=$null}
    }
    foreach($fault in @('Positive','NoOwner','NoParent','WrongFileEnvironment','WrongCaseEnvironment','WrongPid','WrongBirth','WrongSid','WrongHost',
        'WrongNonce','TypedNonce','ChangedRoot','ChangedPackage','ChangedHash','ChangedManifest','ChangedArgv','ExpiredDeadline','MissingAck','ClaimRetention')){
        $fixture=New-RecipientControlFixture -SkipChildClaim
        $directory=$fixture.Owner.Directory;$childRoot=$fixture.Root;$childPackage=$fixture.Package;$manifestSha=$script:context.Root.Admission.preparedManifestSha256
        $script:childSelf=[pscustomobject]@{Pid=456;CreationUtc='2030-01-01T00:00:00.1234567Z';OwnerSid='synthetic-pure-sid';HostPath=$fixture.Start.FileName}
        switch($fault){
            NoOwner{$directory=$null};NoParent{$script:denyParent=$true};WrongFileEnvironment{$env:WINPCINFO_TEST_FILE_LEASE='0'*32};WrongCaseEnvironment{$env:WINPCINFO_TEST_CASE_LEASE='0'*32};
            WrongPid{$script:childSelf.Pid=999};WrongBirth{$script:childSelf.CreationUtc='2030-01-01T00:00:00.1234568Z'};
            WrongSid{$script:childSelf.OwnerSid='other'};WrongHost{$script:childSelf.HostPath+='x'};
            WrongNonce{$ack=Read-TestNativeRecord (Join-Path $directory 'startup-ack.json');$ack.nonce='0'*32;[IO.File]::WriteAllText((Join-Path $directory 'startup-ack.json'),($ack|ConvertTo-Json -Depth 10))};
            TypedNonce{$pending=Read-TestNativeRecord (Join-Path $directory 'owned-pending.json');$pending.nonce=@($pending.nonce);[IO.File]::WriteAllText((Join-Path $directory 'owned-pending.json'),($pending|ConvertTo-Json -Depth 10))};
            ChangedRoot{$childRoot+='x'};ChangedPackage{$childPackage+='x'};ChangedHash{[IO.File]::AppendAllText($fixture.Package,'changed')};
            ChangedManifest{$manifestSha='0'*64};ChangedArgv{$script:childArguments[0]='-Other'};
            ExpiredDeadline{$pending=Read-TestNativeRecord (Join-Path $directory 'owned-pending.json');$pending.localAuthorityEnds=[DateTimeOffset]::UtcNow.AddMilliseconds(-1).ToString('o');[IO.File]::WriteAllText((Join-Path $directory 'owned-pending.json'),($pending|ConvertTo-Json -Depth 10))};
            MissingAck{[IO.File]::Delete((Join-Path $directory 'startup-ack.json'));$env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC=[DateTimeOffset]::UtcNow.AddMilliseconds(-1).ToString('o')};
            ClaimRetention{$script:writeFault='child-special-claim.json'}
        }
        $caught=$null;try{Assert-RecipientViewingInterruptionChild -RepositoryRoot $fixture.Repository -OwnerDirectory $directory -Candidate $fixture.Candidate -PreparedManifestPath $fixture.Manifest -PreparedManifestSha256 $manifestSha -ChildRoot $childRoot -ChildPackagePath $childPackage}catch{$caught=$_}
        $script:denyParent=$false;$script:writeFault='';$script:childSelf=$null
        $claim=Join-Path $fixture.Owner.Directory 'child-special-claim.json'
        if($fault -ceq 'Positive'){
            Assert-RecipientControl ($null -eq $caught -and [IO.File]::Exists($claim) -and -not (Read-TestNativeRecord $claim).nativeDelegationGranted -and $env:WINPCINFO_TEST_FILE_LEASE -ceq $fixture.Owner.Pending.rootNonce) 'Actual special child binding verifies self observation and original creator without assigning an ordinary native lease.'
        }else{Assert-RecipientControl ($null -ne $caught -and -not [IO.File]::Exists($claim)) 'Bare/missing/changed parent, self, envelope, source operands, deadline or retention cannot admit viewing/provider work.'}
    }
    foreach($fault in @('WrongSource','WrongHost','WrongArg','WrongCandidate','NotPrepared','WrongPin','Shell')){
        $caught=$null;try{$null=New-RecipientControlFixture -AdmissionFault $fault}catch{$caught=$_}
        Assert-RecipientControl ($null -ne $caught) 'Changed source/host/argv/candidate/pin/flags must refuse before creator admission.'
    }
    $script:budget=29999;$caught=$null;try{$null=New-RecipientControlFixture}catch{$caught=$_};$script:budget=60000
    Assert-RecipientControl ($null -ne $caught) 'Creation without complete finite reserve must refuse.'
    $fixture=New-RecipientControlFixture;$ready=Wait-RecipientViewingInterruptionReady $fixture.Owner
    Assert-RecipientControl ([IO.File]::Exists($ready.artifactPath) -and $fixture.Owner.Ready -eq $ready) 'Actual readiness binds the existing registered plaintext and original process journal.'
    Interrupt-RecipientViewingOriginalProcess $fixture.Owner
    Assert-RecipientControl ($fixture.Owner.Forced -and $fixture.Owner.Deliberate -and $fixture.Owner.TerminalVerified -and $fixture.Owner.TerminalRetained -and $fixture.Owner.ExitCode -eq 137 -and -not $fixture.Process.Disposed) 'Deliberate interruption retains its actual forced nonzero outcome before disposal.'
    $terminal=Read-TestNativeRecord (Join-Path $fixture.Owner.Directory 'original-terminal.json')
    Assert-RecipientControl ($terminal.ordinaryNativePass -is [bool] -and -not $terminal.ordinaryNativePass -and -not $terminal.processTreeAbsenceClaim -and $terminal.forced) 'Interrupted child cannot masquerade as ordinary native success or tree absence.'
    $recovery=Invoke-RecipientControlRecovery $fixture;Confirm-RecipientViewingInterruptionRecovery $fixture.Owner $recovery
    $null=Complete-RecipientViewingInterruption -Owner $fixture.Owner -Process $fixture.Process
    Assert-RecipientControl ($fixture.Process.Disposed -and $fixture.Owner.RecoveryVerified -and -not [IO.File]::Exists((Join-Path $fixture.Owner.Directory 'owned-pending.json')) -and [IO.File]::Exists($fixture.Package)) 'Special owner closes only after original terminal plus absence/package preservation proof.'
    foreach($fault in @('ExpiredBeforeClose','ShortenedInheritedAtClose','ExpiredDuringCloseProof','CloseProofRetention','PendingDelete')){
        $fixture=New-RecipientControlFixture;$null=Wait-RecipientViewingInterruptionReady $fixture.Owner;Interrupt-RecipientViewingOriginalProcess $fixture.Owner
        $recovery=Invoke-RecipientControlRecovery $fixture;Confirm-RecipientViewingInterruptionRecovery $fixture.Owner $recovery
        $pendingLock=$null
        switch($fault){ExpiredBeforeClose{$fixture.Owner.BudgetMs=0};ShortenedInheritedAtClose{$env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC=[DateTimeOffset]::UtcNow.AddMilliseconds(-1).ToString('o')};ExpiredDuringCloseProof{$script:expireAtClose=$fixture.Owner};
            CloseProofRetention{$script:writeFault='original-close-proof.json'};
            PendingDelete{$pendingLock=[IO.File]::Open((Join-Path $fixture.Owner.Directory 'owned-pending.json'),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}}
        $caught=$null;try{$null=Complete-RecipientViewingInterruption -Owner $fixture.Owner -Process $fixture.Process}catch{$caught=$_}
        if($null -ne $pendingLock){$pendingLock.Dispose()};$script:expireAtClose=$null;$script:writeFault=''
        Assert-RecipientControl ($null -ne $caught -and $fixture.Owner.Unsafe -and [IO.File]::Exists((Join-Path $fixture.Owner.Directory 'owned-pending.json')) -and [IO.Directory]::Exists($fixture.Root) -and [IO.File]::Exists($fixture.Package)) 'Expired authority or fallible close-proof/pending release retains unsafe owner, exact pending and recovered fixture/package.'
        if($fault -cin @('ExpiredBeforeClose','ShortenedInheritedAtClose')){Assert-RecipientControl (-not $fixture.Process.Disposed) 'Expired original authority refuses disposal and release before touching the exact original handle.'}
        $owning=Invoke-RecipientActualOwningFinalization -Fixture $fixture -OriginalError $caught
        Assert-RecipientControl ($null -ne $owning.Error -and $owning.RootRetained -and $owning.CandidateClosed -and $owning.CandidateAttempted -and [IO.File]::Exists($fixture.Package)) 'Actual owning finalizers retain fixture/package after close-proof/delete/deadline failure while independently closing candidate exactly once.'
    }
    foreach($mode in @('FalseTerminal','NonBoolean','UnknownExit')){
        $fixture=New-RecipientControlFixture -Mode $mode;$null=Wait-RecipientViewingInterruptionReady $fixture.Owner
        $caught=$null;try{Interrupt-RecipientViewingOriginalProcess $fixture.Owner}catch{$caught=$_}
        Assert-RecipientControl ($null -ne $caught -and $fixture.Owner.Unsafe -and -not $fixture.Owner.TerminalVerified -and -not $fixture.Process.Disposed) 'False/non-Boolean terminal or unknown actual exit cannot become verified interruption.'
    }
    $fixture=New-RecipientControlFixture;$fixture.Owner.BudgetMs=9000;[IO.File]::Delete((Join-Path $fixture.Root 'view-ready.json'))
    $caught=$null;try{$null=Wait-RecipientViewingInterruptionReady $fixture.Owner}catch{$caught=$_}
    Assert-RecipientControl ($null -ne $caught -and $fixture.Owner.Unsafe -and -not $fixture.Process.Killed) 'Readiness deadline failure never becomes the deliberate interruption path.'
    foreach($fault in @('WrongOwner','WrongArtifact','WrongDigest','TypedVerified')){
        $fixture=New-RecipientControlFixture
        if($fault -ceq 'TypedVerified'){$fixture.Ready.verified='true';[IO.File]::WriteAllText((Join-Path $fixture.Root 'view-ready.json'),($fixture.Ready|ConvertTo-Json))}
        else{$journal=Read-RunRecoveryJournal $fixture.Ready.journalPath;switch($fault){WrongOwner{$journal.owner.processId=999};WrongArtifact{$journal.artifacts[1].path+='x'};WrongDigest{$journal.planDigest='0'*64}};[IO.File]::WriteAllText($fixture.Ready.journalPath,($journal|ConvertTo-Json -Depth 8))}
        $caught=$null;try{$null=Wait-RecipientViewingInterruptionReady $fixture.Owner}catch{$caught=$_}
        Assert-RecipientControl ($null -ne $caught -and $fixture.Owner.Unsafe) 'Changed ready owner/artifact/package or wrong-typed verification cannot authorize interruption.'
    }
    $fixture=New-RecipientControlFixture;$null=Wait-RecipientViewingInterruptionReady $fixture.Owner;$script:writeFault='original-terminal.json'
    $caught=$null;try{Interrupt-RecipientViewingOriginalProcess $fixture.Owner}catch{$caught=$_};$script:writeFault=''
    Assert-RecipientControl ($null -ne $caught -and $fixture.Owner.Unsafe -and -not $fixture.Process.Disposed -and [IO.File]::Exists((Join-Path $fixture.Owner.Directory 'terminal.json'))) 'Failed original retention attempts the independent terminal copy and retains the original handle.'
    foreach($fault in @('NoRecovery','PlaintextPresent','ChangedPackage','StringVerified')){
        $fixture=New-RecipientControlFixture;$null=Wait-RecipientViewingInterruptionReady $fixture.Owner;Interrupt-RecipientViewingOriginalProcess $fixture.Owner
        $recovery=[pscustomobject]@{cleanup=[pscustomobject]@{verified=$true}}
        if($fault -cin @('ChangedPackage','StringVerified')){$recovery=Invoke-RecipientControlRecovery $fixture}
        switch($fault){NoRecovery{$recovery.cleanup.verified=$false};ChangedPackage{[IO.File]::AppendAllText($fixture.Package,'changed')};StringVerified{$recovery.cleanup.verified='true'}}
        $caught=$null;try{Confirm-RecipientViewingInterruptionRecovery $fixture.Owner $recovery}catch{$caught=$_}
        Assert-RecipientControl ($null -ne $caught -and $fixture.Owner.Unsafe -and -not $fixture.Owner.RecoveryVerified) 'Recovery flags cannot substitute exact plaintext absence and unchanged protected bytes.'
    }
    $fixture=New-RecipientControlFixture;$null=Wait-RecipientViewingInterruptionReady $fixture.Owner;Interrupt-RecipientViewingOriginalProcess $fixture.Owner
    $script:cleanupAttempts=[Collections.Generic.List[string]]::new();$body=$null;try{throw 'Disclosed original body failure.'}catch{$body=$_}
    $caught=$null;try{$null=Complete-RecipientViewingInterruption -Owner $fixture.Owner -Process $fixture.Process -BodyError $body -Cleanup @(
        {$script:cleanupAttempts.Add('certificate-one');throw 'Disclosed first certificate cleanup failure.'},
        {$script:cleanupAttempts.Add('certificate-two');throw 'Disclosed second certificate cleanup failure.'})}catch{$caught=$_}
    Assert-RecipientControl ($script:cleanupAttempts.Count -eq 2 -and $null -ne $caught -and $caught.Exception.ToString().Contains('Disclosed original body failure.') -and $caught.Exception.ToString().Contains('Disclosed first certificate cleanup failure.') -and $caught.Exception.ToString().Contains('Disclosed second certificate cleanup failure.') -and (Test-QualificationCleanupUnverified $caught.Exception)) 'Original body and all independent owner/certificate cleanup errors must remain retained and unsafe.'
    Assert-RecipientControl (-not $fixture.Process.Disposed -and [IO.Directory]::Exists($fixture.Root) -and [IO.File]::Exists((Join-Path $fixture.Owner.Directory 'owned-pending.json'))) 'Missing actual recovery proof retains fixture, original handle and pending bytes.'
    $fixture=New-RecipientControlFixture -Mode FalseTerminal;$script:writeFault='original-terminal.json'
    $caught=$null;try{$null=Complete-RecipientViewingInterruption -Owner $fixture.Owner -Process $fixture.Process}catch{$caught=$_};$script:writeFault=''
    Assert-RecipientControl ($null -ne $caught -and $caught.Exception.ToString().Contains('Recipient fallback terminal remains unverified.') -and
        $caught.Exception.ToString().Contains('Disclosed private retention failure.') -and [IO.File]::Exists((Join-Path $fixture.Owner.Directory 'terminal.json'))) 'Fallback terminal failure and independent retention failure cannot replace one another.'
    # Replay the actual owning certificate/root and candidate finally bodies;
    # never execute its certificate setup, product body or Process.Start.
    $tokens=$null;$errors=$null
    $owningAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'RecipientViewingApplication.Tests.ps1'),[ref]$tokens,[ref]$errors)
    $finalizers=@($owningAst.FindAll({param($node)$node -is [Management.Automation.Language.TryStatementAst] -and $null -ne $node.Finally},$true))
    $fixtureFinally=@($finalizers|Where-Object{$_.Finally.Extent.Text.Contains('$approved.certificate.Dispose()')})
    $candidateFinally=@($finalizers|Where-Object{$_.Finally.Extent.Text.Contains('Close-TestCandidate -Candidate $candidateContext -BodyError $candidateError')})
    if($errors.Count -or $fixtureFinally.Count -ne 1 -or $candidateFinally.Count -ne 1){throw 'Actual owning finalizer seams must be unique.'}
    $harnessAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'TestHarness.ps1'),[ref]$tokens,[ref]$errors)
    $closeNode=@($harnessAst.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Close-TestCandidate'},$false))
    if($errors.Count -or $closeNode.Count -ne 1){throw 'Actual candidate finalizer must be unique.'}
    . ([scriptblock]::Create($closeNode[0].Extent.Text))
    $fixture=New-RecipientControlFixture;$root=$fixture.Root;$owner=$fixture.Owner;$owner.Unsafe=$true
    $candidateContext=$fixture.Candidate;$script:certificateAttempts=[Collections.Generic.List[string]]::new()
    $first=[pscustomobject]@{};$first|Add-Member ScriptMethod Dispose {$script:certificateAttempts.Add('first');throw 'Disclosed first actual-finally certificate failure.'}
    $second=[pscustomobject]@{};$second|Add-Member ScriptMethod Dispose {$script:certificateAttempts.Add('second');throw 'Disclosed second actual-finally certificate failure.'}
    $approved=[pscustomobject]@{certificate=$first};$recipient=[pscustomobject]@{certificate=$second}
    $fixtureCleanup=[pscustomobject]@{Unverified=$false;CandidateCloseAttempted=$false}
    $bodyError=$null;try{throw 'Disclosed actual-finally original body failure.'}catch{$bodyError=$_}
    $candidateError=$null;try{$null=. ([scriptblock]::Create($fixtureFinally[0].Finally.Extent.Text.Trim().TrimStart('{').TrimEnd('}')))}catch{$candidateError=$_}
    $caught=$null;try{$null=. ([scriptblock]::Create($candidateFinally[0].Finally.Extent.Text.Trim().TrimStart('{').TrimEnd('}')))}catch{$caught=$_}
    Assert-RecipientControl ($script:certificateAttempts.Count -eq 2 -and $null -ne $caught -and
        $caught.Exception.ToString().Contains('Disclosed actual-finally original body failure.') -and
        $caught.Exception.ToString().Contains('Disclosed first actual-finally certificate failure.') -and
        $caught.Exception.ToString().Contains('Disclosed second actual-finally certificate failure.') -and
        (Test-QualificationCleanupUnverified $caught.Exception)) 'Actual owning finalizers retain body and both independent certificate failures.'
    Assert-RecipientControl (-not $candidateContext.Stream.CanRead -and [IO.Directory]::Exists($root)) 'Actual candidate finalization still runs after failed fixture/certificate cleanup while uncertain root stays retained.'
    $fixture=New-RecipientControlFixture;$null=Wait-RecipientViewingInterruptionReady $fixture.Owner;Interrupt-RecipientViewingOriginalProcess $fixture.Owner
    $recovery=Invoke-RecipientControlRecovery $fixture;Confirm-RecipientViewingInterruptionRecovery $fixture.Owner $recovery
    $null=Complete-RecipientViewingInterruption -Owner $fixture.Owner -Process $fixture.Process
    $root=$fixture.Root;$owner=$fixture.Owner;$candidateContext=$fixture.Candidate;$candidateContext.Sha256='0'*64
    $safeCertificate=[pscustomobject]@{};$safeCertificate|Add-Member ScriptMethod Dispose {}
    $approved=[pscustomobject]@{certificate=$safeCertificate};$recipient=[pscustomobject]@{certificate=$safeCertificate}
    $fixtureCleanup=[pscustomobject]@{Unverified=$false;CandidateCloseAttempted=$false};$bodyError=$null;$candidateError=$null
    try{$null=. ([scriptblock]::Create($fixtureFinally[0].Finally.Extent.Text.Trim().TrimStart('{').TrimEnd('}')))}catch{$candidateError=$_}
    $caught=$null;try{$null=. ([scriptblock]::Create($candidateFinally[0].Finally.Extent.Text.Trim().TrimStart('{').TrimEnd('}')))}catch{$caught=$_}
    Assert-RecipientControl ($null -ne $caught -and [IO.Directory]::Exists($root) -and -not $candidateContext.Stream.CanRead) 'Actual candidate finalizer failure must retain the otherwise recovered fixture before any root deletion.'
}
finally{
    $env:WINPCINFO_TEST_FILE_LEASE=$originalFileLease;$env:WINPCINFO_TEST_CASE_LEASE=$originalCaseLease;$env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC=$originalAuthority
    # Exact synthetic roots only; this deletion is never real native recovery.
    foreach($fixture in $fixtures){$fixture.Candidate.Stream.Dispose();if([IO.Directory]::Exists($fixture.Root)){if([IO.Path]::GetDirectoryName($fixture.Root).TrimEnd('\') -cne [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') -or [IO.Path]::GetFileName($fixture.Root) -cnotmatch '^winpcinfo-recipient-view-[a-f0-9]{32}$'){throw 'Pure fixture deletion escaped its known synthetic root.'};[IO.Directory]::Delete($fixture.Root,$true)}}
    $boundary=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')+'\'
    if(-not [IO.Path]::GetFullPath($pureRoot).StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)){throw 'Pure evidence deletion escaped its draft.'}
    [IO.Directory]::Delete($pureRoot,$true)
}
Write-Output ('PASS: '+$script:controls+' child-free actual recipient interruption owning-seam controls; unadmitted draft only.')
