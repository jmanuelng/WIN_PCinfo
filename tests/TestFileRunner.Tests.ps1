[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Invoke-TestFile.ps1')
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Run-Tests.ps1'),[ref]$null,[ref]$null)
$core=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-TestSuiteFiles'},$true)
. ([scriptblock]::Create($core.Extent.Text))
$finalizer=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Complete-TestSuiteFinalization'},$true)
. ([scriptblock]::Create($finalizer.Extent.Text))
$checks=0
function Assert-RunnerControl {
    param([bool] $Condition,[string] $Because)
    if (-not $Condition) { throw "Runner pure control failed: $Because" }
    $script:checks++
}
function Assert-RunnerRefusal {
    param([scriptblock] $Action,[string] $Because)
    $rejected=$false
    try { & $Action | Out-Null } catch { $rejected=$true }
    Assert-RunnerControl $rejected $Because
}
$fixture=Join-Path (Split-Path $PSScriptRoot) ('.test-output/runner-pure-'+[guid]::NewGuid().ToString('N'))
$repository=Join-Path $fixture 'repository'
$nonce='a'*32
$directory=Join-Path $repository ('.test-output/test-file-native/'+$nonce)
$suiteRoot=Join-Path $repository ('.test-output/suite-'+('b'*32))
$null=[IO.Directory]::CreateDirectory((Join-Path $repository 'tests'))
$null=[IO.Directory]::CreateDirectory($directory)
$null=[IO.Directory]::CreateDirectory($suiteRoot)
try {
    # All identities and native outcomes below are disclosed contrived data.
    # These controls never start or query a process, task, application or CIM.
    $testPath=Join-Path $repository 'tests/A.Tests.ps1'
    $bootstrap=Join-Path $repository 'tests/Invoke-TestFile.ps1'
    $hostPath=Join-Path $repository 'fixture-host.exe'
    $inventoryPath=Join-Path $suiteRoot 'suite-inventory.json'
    foreach ($path in @($testPath,$bootstrap,$hostPath,$inventoryPath)) { [IO.File]::WriteAllText($path,'synthetic input') }
    $inputs=@(@($testPath,$bootstrap,$hostPath,$inventoryPath) | Sort-Object -CaseSensitive | ForEach-Object {
        [pscustomobject][ordered]@{path=$_; bytes=(Get-Item -LiteralPath $_).Length; sha256=(Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant()}
    })
    $admission=[ordered]@{contract='win-pcinfo.test-file-admission/1.0.0'; repositoryRoot=$repository;
        testPath=$testPath; testSha256=(Get-FileHash -LiteralPath $testPath).Hash.ToLowerInvariant(); bootstrapPath=$bootstrap;
        hostPath=$hostPath; inventoryPath=$inventoryPath; suiteEvidenceRoot=$suiteRoot;
        candidatePath=''; preparedManifestPath=''; preparedManifestSha256=''; inputs=$inputs; cohortSha256=(Get-TestNativeDigest -Value $inputs)}
    Assert-TestFileLauncher -Admission $admission -RepositoryRoot $repository -HostPath $hostPath -WorkingDirectory $repository -Arguments @('-NoLogo','-NoProfile','-File',$bootstrap)
    Assert-RunnerControl $true 'actual role launcher admits the fixed repository working directory'
    Assert-RunnerRefusal { Assert-TestFileLauncher -Admission $admission -RepositoryRoot $repository -HostPath $hostPath -WorkingDirectory $fixture -Arguments @('-NoLogo','-NoProfile','-File',$bootstrap) } 'wrong working directory refuses before prearm or child request'
    foreach ($scriptText in @('exit 1','exit 0','if ($true) { exit 1 }')) {
        [IO.File]::WriteAllText($testPath,$scriptText)
        Assert-RunnerRefusal { Assert-TestFileExecutableProtocol -Path $testPath } 'actual shim protocol refuses executable exits instead of falsely passing or interpreting residual native status'
    }
    foreach ($scriptText in @('throw ''synthetic body assertion''','$childScript = ''exit 7''; & $hostPath -Command $childScript; if ($LASTEXITCODE -ne 7) { throw ''negative control'' }')) {
        [IO.File]::WriteAllText($testPath,$scriptText)
        $null=Assert-TestFileExecutableProtocol -Path $testPath
        Assert-RunnerControl $true 'ordinary body throws and intentional child exit fixture strings retain their completion protocol'
    }
    [IO.File]::WriteAllText($testPath,'synthetic input')
    $self=[pscustomobject]@{Pid=123; CreationUtc='2026-10-06T12:00:00.0000000Z'; OwnerSid='S-1-5-21-111'; HostPath=$hostPath}
    $pending=[ordered]@{nativeRole='TestFile'; nonce=$nonce; authorityEnds='2026-10-06T13:00:00Z'; childCreationRequested=$true;
        child=[ordered]@{Started=$true; ExactStartedProcessHandlePinned=$true; ObservationFailure=''; Pid=$self.Pid;
            CreationUtc=$self.CreationUtc; OwnerSid=$self.OwnerSid; HostPath=$hostPath}; admission=$admission}
    $pendingPath=Join-Path $directory 'owned-pending.json'
    $ackPath=Join-Path $directory 'startup-ack.json'
    $claimPath=Join-Path $directory 'child-admission.claim'
    function Save-LeaseFixture {
        foreach ($path in @($pendingPath,(Join-Path $directory 'startup.json'),$ackPath,$claimPath)) { if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) } }
        Write-TestNativeNewRecord -Path $pendingPath -Value $pending
        Write-TestNativeNewRecord -Path (Join-Path $directory 'startup.json') -Value $pending
        $ack=[ordered]@{contract='win-pcinfo.test-file-startup/1.0.0'; nonce=$nonce; directory=$directory;
            pendingSha256=(Get-FileHash -LiteralPath $pendingPath).Hash.ToLowerInvariant();
            startupSha256=(Get-FileHash -LiteralPath (Join-Path $directory 'startup.json')).Hash.ToLowerInvariant();
            admissionSha256=(Get-TestNativeDigest -Value $admission)}
        Write-TestNativeNewRecord -Path $ackPath -Value $ack
        Write-TestNativeNewRecord -Path $claimPath -Value ([ordered]@{contract='win-pcinfo.test-file-claim/1.0.0'; nonce=$nonce;
            ackSha256=(Get-FileHash -LiteralPath $ackPath).Hash.ToLowerInvariant(); pid=$self.Pid;
            creationUtc=$self.CreationUtc; ownerSid=$self.OwnerSid})
    }
    function Read-FixtureLease {
        Read-TestFileLease -RepositoryRoot $repository -Nonce $nonce -SelfIdentity $self -RequireClaim -Now ([DateTimeOffset]::Parse('2026-10-06T12:30:00Z'))
    }
    Save-LeaseFixture
    $lease=Read-FixtureLease
    Assert-RunnerControl ($lease.Admission.testPath -ceq $testPath) 'valid disclosed lease binds its actual fixture file'
    $protocolOutcome=[pscustomobject]@{NativeTerminalObserved=$true; NativeExitCode=0; OwnedCleanupUnverified=$false; StreamsDrained=$true; StreamFailure=$false; OutputOverflow=$false}
    $protocolCompletion=[ordered]@{contract='win-pcinfo.test-file-result/1.0.0'; nonce=$nonce; testPath=$testPath; testSha256=$admission.testSha256; completed=$true; cleanupVerified=$true; result='Pass'}
    $fileResultPath=Join-Path $directory 'file-result.json'
    Write-TestNativeNewRecord -Path $fileResultPath -Value $protocolCompletion
    $protocolErrors=[Collections.Generic.List[Exception]]::new()
    function Confirm-FixtureFileRetention {
        Confirm-TestFileNativeRetention -RepositoryRoot $repository -Directory $directory -Nonce $nonce -Admission $admission -NativeIdentity $self -NativeOutcome $protocolOutcome -Failures $protocolErrors -Now ([DateTimeOffset]::Parse('2026-10-06T12:30:00Z'))
    }
    $confirmed=Confirm-FixtureFileRetention
    Assert-RunnerControl ($confirmed -and $protocolErrors.Count -eq 0) 'actual file pre-release boundary accepts complete claimed natural zero'
    [IO.File]::Delete($claimPath); $protocolErrors.Clear()
    $confirmed=Confirm-FixtureFileRetention
    Assert-RunnerControl (-not $confirmed -and $protocolErrors.Count -gt 0 -and $protocolOutcome.NativeExitCode -eq 0 -and [IO.File]::Exists($pendingPath)) 'missing file claim blocks release without replacing actual zero or deleting hold'
    Save-LeaseFixture
    [IO.File]::Delete($fileResultPath); $protocolErrors.Clear()
    $confirmed=Confirm-FixtureFileRetention
    Assert-RunnerControl (-not $confirmed -and $protocolErrors.Count -gt 0 -and $protocolOutcome.NativeExitCode -eq 0 -and [IO.File]::Exists($pendingPath)) 'lost file completion blocks release while independently retained original zero remains zero'
    $protocolCompletion.cleanupVerified=$false
    Write-TestNativeNewRecord -Path $fileResultPath -Value $protocolCompletion
    $protocolErrors.Clear(); $confirmed=Confirm-FixtureFileRetention
    Assert-RunnerControl (-not $confirmed -and $protocolErrors.Count -gt 0 -and [IO.File]::Exists($pendingPath)) 'cleanup-unverified file completion preserves operative pending hold'
    $protocolCompletion.cleanupVerified=$true; $protocolCompletion.result='Fail'; $protocolOutcome.NativeExitCode=1
    [IO.File]::Delete($fileResultPath); Write-TestNativeNewRecord -Path $fileResultPath -Value $protocolCompletion
    $protocolErrors.Clear(); $confirmed=Confirm-FixtureFileRetention
    Assert-RunnerControl ($confirmed -and $protocolErrors.Count -eq 0 -and $protocolOutcome.NativeExitCode -eq 1) 'claimed ordinary file assertion failure retains its original nonzero before valid release'
    Assert-RunnerRefusal { Read-TestFileLease -RepositoryRoot $repository -Nonce '../escape' -SelfIdentity $self } 'malformed nonce cannot fall back to standalone'
    Assert-RunnerRefusal { Write-TestNativeNewRecord -Path $claimPath -Value @{} } 'one-use claim cannot be replaced'
    foreach ($field in @('Pid','CreationUtc','OwnerSid','HostPath')) {
        $saved=$self.$field
        try {
            $self.$field=$(if ($field -eq 'Pid') {124} else {$saved+'different'})
            Assert-RunnerRefusal { Read-FixtureLease } "exact child $field must match even when other lifetime fields agree"
        } finally { $self.$field=$saved }
    }
    [IO.File]::Delete($claimPath)
    Assert-RunnerRefusal { Read-FixtureLease } 'missing one-use claim cannot grant inherited admission'
    Save-LeaseFixture
    [IO.File]::WriteAllText($claimPath,'{"contract":"stale"}')
    Assert-RunnerRefusal { Read-FixtureLease } 'stale claim does not grant inherited admission'
    Save-LeaseFixture
    [IO.File]::WriteAllText($ackPath,'{"contract":"stale"}')
    Assert-RunnerRefusal { Read-FixtureLease } 'stale startup acknowledgement refuses'
    Save-LeaseFixture
    [IO.File]::WriteAllText($ackPath,'{invalid')
    Assert-RunnerRefusal { Read-FixtureLease } 'malformed acknowledgement refuses'
    [IO.File]::Delete($ackPath)
    $null=[IO.Directory]::CreateDirectory($ackPath)
    Assert-RunnerRefusal { Write-TestNativeNewRecord -Path $ackPath -Value @{} } 'startup acknowledgement retention failure cannot grant a child admission'
    Assert-RunnerRefusal { Read-FixtureLease } 'a directory at the acknowledgement path cannot be an acknowledgement'
    [IO.Directory]::Delete($ackPath)
    Save-LeaseFixture
    [IO.File]::WriteAllText($testPath,'changed fixture')
    Assert-RunnerRefusal { Read-FixtureLease } 'leaf source drift refuses despite a valid identity claim'
    [IO.File]::WriteAllText($testPath,'synthetic input')
    $saved=$admission.cohortSha256
    $admission.cohortSha256='0'*64
    Save-LeaseFixture
    Assert-RunnerRefusal { Read-FixtureLease } 'wrong cohort refuses even with refreshed acknowledgement hashes'
    $admission.cohortSha256=$saved
    Save-LeaseFixture
    Assert-RunnerRefusal { Read-TestFileLease -RepositoryRoot $repository -Nonce $nonce -SelfIdentity $self -RequireClaim -Now ([DateTimeOffset]::Parse('2026-10-06T14:00:00Z')) } 'expired lease cannot be restarted'
    $original=$env:WINPCINFO_TEST_FILE_LEASE
    try {
        $env:WINPCINFO_TEST_FILE_LEASE='malformed'
        Assert-RunnerRefusal { Assert-TestNativeRoleReady -NativeRole TestFile -RepositoryRoot $repository } 'inherited file lease cannot delegate another file launch'
    } finally { $env:WINPCINFO_TEST_FILE_LEASE=$original }

    $inventory=@([pscustomobject]@{file='A.Tests.ps1'; sha256=('a'*64)},[pscustomobject]@{file='B.Tests.ps1'; sha256=('b'*64)})
    $pass=[pscustomobject]@{file='A.Tests.ps1'; sha256=('a'*64); result='Pass'; elapsedMilliseconds=1;
        nativeExitCode=0; completed=$true; cleanupVerified=$true}
    Assert-TestSuiteAccounting -Inventory $inventory -Results @($pass)
    Assert-RunnerControl $true 'valid partial ordered accounting is retained'
    foreach ($mutation in @('duplicate','unexpected','drift','missing','nonzero')) {
        $row=$pass | Select-Object *
        $second=$pass | Select-Object *
        $second.file='B.Tests.ps1'; $second.sha256='b'*64
        $rows=@($row,$second)
        switch ($mutation) {
            duplicate {$rows=@($row,$row)}
            unexpected {$row.file='Unexpected.Tests.ps1'}
            drift {$row.sha256='0'*64}
            missing {$rows=@($row)}
            nonzero {$row.nativeExitCode=7}
        }
        Assert-RunnerRefusal { Assert-TestSuiteAccounting -Inventory $inventory -Results $rows -Complete } "complete accounting refuses $mutation"
    }
    $script:invoked=[Collections.Generic.List[string]]::new()
    $normal={param($Expected) $script:invoked.Add($Expected.file); [ordered]@{file=$Expected.file; sha256=$Expected.sha256;
        result=$(if ($Expected.file -eq 'A.Tests.ps1') {'Fail'} else {'Pass'}); elapsedMilliseconds=1;
        nativeExitCode=$(if ($Expected.file -eq 'A.Tests.ps1') {1} else {0}); completed=$true; cleanupVerified=$true}}
    $suite=Invoke-TestSuiteFiles -Inventory $inventory -InvokeFile $normal -RetainResults {param($Rows,$Final)}
    Assert-RunnerControl (-not $suite.Stopped -and $suite.Results[0].result -eq 'Fail' -and $suite.Results[1].result -eq 'Pass' -and $invoked.Count -eq 2) 'verified assertion nonzero continues and remains failed'
    $crash=Invoke-TestSuiteFiles -Inventory $inventory -InvokeFile {throw 'synthetic worker crash'} -RetainResults {param($Rows,$Final)}
    Assert-RunnerControl ($crash.Stopped -and $crash.Results[0].result -eq 'Fail' -and $crash.Results[1].result -eq 'Blocked') 'crash blocks every remaining file'
    $originalZero=Invoke-TestSuiteFiles -Inventory $inventory -InvokeFile {
        $error=[InvalidOperationException]::new('synthetic terminal retention failure')
        $error.Data['OriginalNativeOutcome']=[pscustomobject]@{NativeTerminalObserved=$true; NativeExitCode=0}
        throw $error
    } -RetainResults {param($Rows,$Final)}
    Assert-RunnerControl ($originalZero.Stopped -and $originalZero.Results[0].nativeExitCode -eq 0 -and
        $originalZero.Results[0].result -eq 'Fail' -and $originalZero.Results[1].result -eq 'Blocked') 'a retention exception preserves original native zero and blocks the remainder'
    $script:attempts=0
    $lost=Invoke-TestSuiteFiles -Inventory $inventory -InvokeFile $normal -RetainResults {param($Rows,$Final) $script:attempts++; if (-not $Final) {throw 'synthetic partial retention loss'}}
    Assert-RunnerControl ($lost.Stopped -and $lost.Results[0].result -eq 'Fail' -and $lost.Results[1].result -eq 'Blocked' -and $lost.RetentionFailures.Count -eq 2 -and $attempts -eq 3) 'independent final write does not erase lost partial retention or failed row'
    $completion=[pscustomobject]@{contract='win-pcinfo.test-file-result/1.0.0'; nonce=$nonce; testPath=$testPath;
        testSha256=$admission.testSha256; result='Pass'; completed=$true; cleanupVerified=$true}
    $native=[pscustomobject]@{NativeTerminalObserved=$true; NativeExitCode=0; OwnedCleanupUnverified=$false;
        StreamsDrained=$true; StreamFailure=$false; OutputOverflow=$false}
    Assert-TestFileCompletion -Completion $completion -Admission $admission -Nonce $nonce -NativeOutcome $native
    Assert-RunnerControl $true 'typed completion is compared to supplied original native outcome'
    foreach ($flag in @('OwnedCleanupUnverified','StreamFailure','OutputOverflow')) {
        $native.$flag=$true
        Assert-RunnerRefusal { Assert-TestFileCompletion -Completion $completion -Admission $admission -Nonce $nonce -NativeOutcome $native } "unsafe native $flag cannot become a passing file"
        $native.$flag=$false
    }
    $native.NativeTerminalObserved=$false
    Assert-RunnerRefusal { Assert-TestFileCompletion -Completion $completion -Admission $admission -Nonce $nonce -NativeOutcome $native } 'file data cannot substitute for native terminal'
    foreach ($cause in @('suite stop','partial retention failure','full inventory changed')) {
        $script:finalizationOrder=[Collections.Generic.List[string]]::new()
        $body=$null
        try { throw "synthetic $cause" } catch { $body=$_ }
        $observed=$null
        try {
            Complete-TestSuiteFinalization -Candidate ([pscustomobject]@{Prepared=$true}) -BodyError $body -Unsafe $true `
                -PersistBlocker {$script:finalizationOrder.Add('blocker')} -ObserveUnsafe {$script:finalizationOrder.Add('signal')} `
                -CloseCandidate {param($Context,$Failure) $script:finalizationOrder.Add('close'); throw $Failure.Exception}
        } catch { $observed=$_.Exception }
        Assert-RunnerControl (($finalizationOrder -join '|') -ceq 'blocker|signal|close' -and
            $observed.Data['OwnedCleanupUnverified'] -eq $true -and $observed.InnerExceptions.Contains($body.Exception)) "explicit prepared candidate retains $cause before Close rethrows"
    }
    $script:finalizationOrder=[Collections.Generic.List[string]]::new()
    $observed=$null
    try {
        Complete-TestSuiteFinalization -Candidate ([pscustomobject]@{Prepared=$true}) -BodyError $body -Unsafe $true `
            -PersistBlocker {$script:finalizationOrder.Add('blocker'); throw 'synthetic blocker write denial'} `
            -ObserveUnsafe {$script:finalizationOrder.Add('signal'); throw 'synthetic observer denial'} `
            -CloseCandidate {param($Context,$Failure) $script:finalizationOrder.Add('close'); throw $Failure.Exception}
    } catch { $observed=$_.Exception }
    Assert-RunnerControl (($finalizationOrder -join '|') -ceq 'blocker|signal|close' -and $observed.InnerExceptions.Count -eq 3 -and
        $observed.InnerExceptions.Contains($body.Exception)) 'blocker and marker failures aggregate independently while retaining original body and attempting Close'
}
finally {
    $parent=[IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot) '.test-output'))
    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($fixture)) -ine $parent) { throw 'Runner pure cleanup escaped its owned fixture boundary.' }
    [IO.Directory]::Delete($fixture,$true)
}
# These additional controls substitute synthetic children at InvokeMember.
# They exercise real private files, locks, receipts and coordinator interfaces;
# no native child, application or overlap query runs through this adapter.
$pairFixture=Join-Path (Split-Path $PSScriptRoot) ('.test-output/runner-pair-pure-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($pairFixture)
$pairFixtureContexts=[Collections.Generic.List[object]]::new()
$pairFixtureBodyError=$null
$pairFixtureCleanupErrors=[Collections.Generic.List[Exception]]::new()
$pairFixtureParent=Get-TestNativeSelfIdentity
function New-RunnerPairFixture {
    $root=Join-Path $pairFixture ('repository-'+[guid]::NewGuid().ToString('N'))
    $suite=Join-Path $root ('.test-output/suite-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory((Join-Path $root 'tests'))
    $null=[IO.Directory]::CreateDirectory($suite)
    $files=@(foreach ($name in @('GuidedRunwayPolicy.Tests.ps1','RecipientSharingPolicy.Tests.ps1')) {
        $path=Join-Path $root ('tests/'+$name)
        [IO.File]::Copy((Join-Path $PSScriptRoot $name),$path,$false)
        $pin=Get-TestFilePairPin -Path $path
        [pscustomobject]@{file=$name; path=$path; bytes=$pin.bytes; sha256=$pin.sha256}
    })
    $bootstrap=Join-Path $root 'tests/Invoke-TestFile.ps1'
    [IO.File]::WriteAllText($bootstrap,'# Synthetic bootstrap pin; never executed.')
    $inventoryPath=Join-Path $suite 'suite-inventory.json'
    $suiteEnd=[DateTimeOffset]::UtcNow.AddMinutes(15)
    Write-TestNativeNewRecord -Path $inventoryPath -Value ([ordered]@{scope='Full'; authorityEnds=$suiteEnd.ToString('o'); expectedFiles=2; files=$files})
    $inputs=@(@($files.path)+@($bootstrap,(Join-Path $PSHOME 'pwsh.exe'),$inventoryPath) | Sort-Object -CaseSensitive | ForEach-Object {Get-TestFilePairPin -Path $_})
    $admissions=@(foreach ($file in $files) {
        [ordered]@{contract='win-pcinfo.test-file-admission/1.0.0'; repositoryRoot=$root; testPath=$file.path; testSha256=$file.sha256;
            bootstrapPath=$bootstrap; hostPath=(Join-Path $PSHOME 'pwsh.exe'); inventoryPath=$inventoryPath; suiteEvidenceRoot=$suite;
            candidatePath=''; preparedManifestPath=''; preparedManifestSha256=''; scope='Full'; namedParameters=[ordered]@{};
            focusedRequestPath=''; focusedRequestSha256=''; inputs=$inputs; cohortSha256=(Get-TestNativeDigest -Value $inputs)}
    })
    $nonce=[guid]::NewGuid().ToString('N')
    $directory=Join-Path $root ('.test-output/file-pair-native/'+$nonce)
    $null=[IO.Directory]::CreateDirectory($directory)
    $null=Set-TestNativePrivateDirectory -Path $directory
    $members=@(for ($index=0; $index -lt 2; $index++) {
        [ordered]@{file=$files[$index].file; path=$files[$index].path; bytes=$files[$index].bytes; sha256=$files[$index].sha256;
            nonce=[guid]::NewGuid().ToString('N'); admissionCoreSha256=(Get-TestNativeDigest -Value $admissions[$index])}
    })
    $descriptor=[ordered]@{contract='win-pcinfo.test-file-pair/1.0.0'; nonce=$nonce; repositoryRoot=$root;
        suiteEvidenceRoot=$suite; cohortSha256=$admissions[0].cohortSha256; parent=$pairFixtureParent;
        authorityEnds=[DateTimeOffset]::UtcNow.AddSeconds(70).ToString('o'); coordinationEnds=$suiteEnd.ToString('o');
        timeoutMs=60000; cleanupReserveMs=10000; members=$members}
    $path=Join-Path $directory 'descriptor.json'
    Write-TestNativeNewRecord -Path $path -Value $descriptor
    $pin=Get-TestFilePairPin -Path $path
    $lockFile=[IO.File]::Open((Join-Path $directory 'coordination.lock'),'CreateNew','Write','None'); $lockFile.Dispose()
    $pending=Join-Path $directory 'owned-pending.json'
    Write-TestNativeNewRecord -Path $pending -Value ([ordered]@{contract='win-pcinfo.test-file-pair-owned/1.0.0'; descriptorSha256=$pin.sha256; parent=$pairFixtureParent})
    $pendingPin=Get-TestFilePairPin -Path $pending
    $references=@(foreach ($member in $members) {[pscustomobject]@{path=$pin.path; bytes=$pin.bytes; sha256=$pin.sha256; pendingSha256=$pendingPin.sha256; memberNonce=$member.nonce}})
    $held=[IO.File]::Open($path,'Open','Read','Read')
    $context=[pscustomobject]@{Directory=$directory; Descriptor=$descriptor; DescriptorPin=$pin; DescriptorStream=$held; DescriptorHandle=$held.SafeFileHandle;
        PendingPin=$pendingPin; References=$references; Admissions=$admissions; OutcomePin=$null; OverlapPin=$null; Closed=$false}
    $pairFixtureContexts.Add($context)
    $context
}
function Open-RunnerPairMember {
    param($Context,[int] $Index)
    $admission=Copy-TestFilePairAdmissionCore -Admission $Context.Admissions[$Index]
    $admission.filePair=$Context.References[$Index]
    $binding=Read-TestFilePairBinding -Reference $Context.References[$Index] -Admission $admission -CoordinatorIdentity $pairFixtureParent
    $lockFile=Enter-TestFilePairMemberStartup -Binding $binding
    try {
        $member=$Context.Descriptor.members[$Index]
        $directory=Join-Path $Context.Descriptor.repositoryRoot ('.test-output/test-file-native/'+$member.nonce)
        $null=[IO.Directory]::CreateDirectory($directory)
        $child=[ordered]@{Started=$true; Pid=(70000001+$Index); CreationUtc=[DateTime]::UtcNow.ToString('o'); OwnerSid=$pairFixtureParent.OwnerSid;
            HostPath=$admission.hostPath; ExactStartedProcessHandlePinned=$true; ObservationFailure=$null}
        $pending=[ordered]@{contract='win-pcinfo.test-owned-native/1.0.0'; nonce=$member.nonce; nativeRole='TestFile'; admission=$admission;
            parent=$pairFixtureParent; childCreationRequested=$true; child=$child;
            authorityEnds=$Context.Descriptor.authorityEnds; timeoutMs=60000; cleanupReserveMs=10000}
        Write-TestNativeNewRecord -Path (Join-Path $directory 'owned-pending.json') -Value $pending
        Write-TestNativeNewRecord -Path (Join-Path $directory 'startup.json') -Value $pending
        Write-TestNativeNewRecord -Path (Join-Path $directory 'startup-ack.json') -Value ([ordered]@{
            contract='win-pcinfo.test-file-startup/1.0.0'; nonce=$member.nonce; directory=$directory;
            pendingSha256=(Get-TestFilePairPin -Path (Join-Path $directory 'owned-pending.json')).sha256;
            startupSha256=(Get-TestFilePairPin -Path (Join-Path $directory 'startup.json')).sha256; admissionSha256=(Get-TestNativeDigest -Value $admission)})
        [pscustomobject]@{Binding=$binding; Directory=$directory; Child=$child; Admission=$admission; Pending=$pending}
    }
    finally { $lockFile.Dispose() }
}
function Save-RunnerPairSyntheticCompletion {
    param($Context,$Peer,[string] $Result='Pass',[int] $NativeExit=0)
    $directory=$Peer.Directory; $nonce=$Peer.Pending.nonce
    $outcome=[ordered]@{NativeTerminalObserved=$true; NativeExitCode=$NativeExit; OwnedCleanupUnverified=$false;
        StreamsDrained=$true; StreamFailure=$false; OutputOverflow=$false}
    Write-TestNativeNewRecord -Path (Join-Path $directory 'original-native-outcome.json') -Value ([ordered]@{identity=$Peer.Child; outcome=$outcome})
    Write-TestNativeNewRecord -Path (Join-Path $directory 'file-result.json') -Value ([ordered]@{
        contract='win-pcinfo.test-file-result/1.0.0'; nonce=$nonce; testPath=$Peer.Admission.testPath; testSha256=$Peer.Admission.testSha256;
        result=$Result; completed=$true; cleanupVerified=$true})
    Write-TestNativeNewRecord -Path (Join-Path $directory 'child-admission.claim') -Value ([ordered]@{
        contract='win-pcinfo.test-file-claim/1.0.0'; nonce=$nonce; pid=$Peer.Child.Pid; creationUtc=$Peer.Child.CreationUtc; ownerSid=$Peer.Child.OwnerSid;
        ackSha256=(Get-TestFilePairPin -Path (Join-Path $directory 'startup-ack.json')).sha256})
    [IO.File]::WriteAllText((Join-Path $directory 'streams.jsonl'),'')
    Write-TestNativeNewRecord -Path (Join-Path $directory 'errors.json') -Value @{synthetic=$true; failures=@()}
    $receipt=[ordered]@{contract='win-pcinfo.test-file-pair-member-retention/1.0.0'; nonce=$nonce;
        descriptorSha256=$Context.DescriptorPin.sha256; originalOwnerDisposed=$true;
        pendingSha256=(Get-TestFilePairPin -Path (Join-Path $directory 'owned-pending.json')).sha256;
        originalOutcomeSha256=(Get-TestFilePairPin -Path (Join-Path $directory 'original-native-outcome.json')).sha256;
        completionSha256=(Get-TestFilePairPin -Path (Join-Path $directory 'file-result.json')).sha256;
        claimSha256=(Get-TestFilePairPin -Path (Join-Path $directory 'child-admission.claim')).sha256;
        ackSha256=(Get-TestFilePairPin -Path (Join-Path $directory 'startup-ack.json')).sha256;
        streamsSha256=(Get-TestFilePairPin -Path (Join-Path $directory 'streams.jsonl')).sha256;
        errorsSha256=(Get-TestFilePairPin -Path (Join-Path $directory 'errors.json')).sha256}
    $receiptPath=Join-Path $directory 'file-pair-member-retention.json'
    Write-TestNativeNewRecord -Path $receiptPath -Value $receipt
    [pscustomobject]@{Row=[ordered]@{file=[IO.Path]::GetFileName($Peer.Admission.testPath); sha256=$Peer.Admission.testSha256;
        result=$Result; elapsedMilliseconds=1; completed=$true; cleanupVerified=$true; nativeExitCode=$NativeExit; nativeEvidence=$directory};
        Native=[pscustomobject]@{Nonce=$nonce; EvidenceDirectory=$directory; NativeOutcome=$outcome; NativeIdentity=$Peer.Child;
            PairHoldDisposition='AwaitingCoordinatorRelease'; PairReceiptPin=(Get-TestFilePairPin -Path $receiptPath); PairCallbackFailure=$null}}
}
try {
    $context=New-RunnerPairFixture
    $peer=Open-RunnerPairMember -Context $context -Index 0
    $lockFile=Enter-TestFilePairLock -Binding $peer.Binding
    try {
        Assert-RunnerControl (@(Assert-TestFilePairOwnershipLocked -Binding $peer.Binding).Count -eq 1) 'one acknowledged member is visible through the real pair lock'
        foreach ($field in @('childCreationRequested','Started','ExactStartedProcessHandlePinned','Pid')) {
            $pendingPath=Join-Path $peer.Directory 'owned-pending.json'; $startupPath=Join-Path $peer.Directory 'startup.json'; $ackPath=Join-Path $peer.Directory 'startup-ack.json'
            $original=@{}; foreach ($path in @($pendingPath,$startupPath,$ackPath)) {$original[$path]=[IO.File]::ReadAllBytes($path)}
            try {
                $changed=Read-TestNativeRecord -Path $pendingPath
                if ($field -ceq 'childCreationRequested') {$changed.childCreationRequested='true'} else {$changed.child.$field=$(if ($field -ceq 'Pid') {'70000001'} else {'true'})}
                [IO.File]::WriteAllText($pendingPath,($changed|ConvertTo-Json -Depth 14 -Compress))
                [IO.File]::WriteAllText($startupPath,($changed|ConvertTo-Json -Depth 14 -Compress))
                $ack=Read-TestNativeRecord -Path $ackPath
                $ack.pendingSha256=(Get-TestFilePairPin -Path $pendingPath).sha256; $ack.startupSha256=(Get-TestFilePairPin -Path $startupPath).sha256
                [IO.File]::WriteAllText($ackPath,($ack|ConvertTo-Json -Depth 14 -Compress))
                Assert-RunnerRefusal {Assert-TestFilePairOwnershipLocked -Binding $peer.Binding} "peer $field refuses malformed truthy/string type even with corresponding startup and acknowledgement"
            }
            finally {foreach ($path in $original.Keys) {[IO.File]::WriteAllBytes($path,$original[$path])}}
        }
        $end=$peer.Binding.Record.authorityEnds
        try {
            $peer.Binding.Record.authorityEnds=[DateTimeOffset]::UtcNow.AddMilliseconds(10080).ToString('o')
            Assert-RunnerRefusal {Enter-TestFilePairLock -Binding $peer.Binding} 'contended lock refuses within a shortened existing authority instead of extending it'
        }
        finally {$peer.Binding.Record.authorityEnds=$end}
    }
    finally {$lockFile.Dispose()}
    Assert-RunnerRefusal {Enter-TestFilePairMemberStartup -Binding $peer.Binding} 'duplicate arming cannot replay an acknowledged member'
    Assert-RunnerRefusal {Assert-TestFilePairCoordinatorReady -RepositoryRoot $context.Descriptor.repositoryRoot -Binding $null} 'coordinator crash marker blocks an unrelated or restarted suite without relying on inherited file state'
    $admission=Copy-TestFilePairAdmissionCore -Admission $context.Admissions[0]; $admission.filePair=$context.References[0]
    $wrongParent=$pairFixtureParent | Select-Object *; $wrongParent.Pid++
    Assert-RunnerRefusal {Read-TestFilePairBinding -Reference $context.References[0] -Admission $admission -CoordinatorIdentity $wrongParent} 'a restarted coordinator cannot adopt an earlier exact pair capability'
    foreach ($mode in @('Pass','Nonzero','Unsafe','LostStreams','LostMemberReceipt','DuplicateResults','MissingResults','LostObserverReceipt','BlockerWriteDenied','ContextRetentionDenied','ErrorReceiptWriteDenied')) {
        $pairControlContext=New-RunnerPairFixture
        $pairControlEvents=[Collections.Generic.List[string]]::new()
        $pairControlMode=$mode
        $adapter={
            param($Admission,$Reference,$AfterAcknowledged,$ObserveStartup)
            $index=if ($Reference.memberNonce -ceq $pairControlContext.Descriptor.members[0].nonce) {0} else {1}
            $peer=Open-RunnerPairMember -Context $pairControlContext -Index $index
            $pairControlEvents.Add('ack'+$index)
            if ($null -ne $ObserveStartup) {
                # Disclosed observer replacement: no process lookup or overlap claim.
                $path=Join-Path $pairControlContext.Directory 'overlap-observation.json'
                Write-TestNativeNewRecord -Path $path -Value @{synthetic=$true; positiveCoexistence=$false; noNativeQueries=$true}
                $pairControlContext.OverlapPin=Get-TestFilePairPin -Path $path
            }
            if ($null -ne $AfterAcknowledged) {& $AfterAcknowledged $peer.Directory $peer.Child}
            $pairControlEvents.Add('retain'+$index)
            if ($index -eq 1 -and $pairControlMode -in @('Unsafe','LostStreams')) {
                $exception=[InvalidOperationException]::new('synthetic sibling ownership/stream loss')
                $exception.Data['OriginalNativeOutcome']=[pscustomobject]@{NativeTerminalObserved=$true; NativeExitCode=0; OwnedCleanupUnverified=$true;
                    StreamFailure=($pairControlMode -ceq 'LostStreams')}
                $exception.Data['NativeEvidenceDirectory']=$peer.Directory
                Write-TestNativeNewRecord -Path (Join-Path $peer.Directory 'original-native-outcome.json') -Value ([ordered]@{
                    identity=$peer.Child; outcome=$exception.Data['OriginalNativeOutcome']; synthetic=$true})
                throw $exception
            }
            $value=Save-RunnerPairSyntheticCompletion -Context $pairControlContext -Peer $peer `
                -Result $(if ($index -eq 1 -and $pairControlMode -ceq 'Nonzero') {'Fail'} else {'Pass'}) `
                -NativeExit $(if ($index -eq 1 -and $pairControlMode -ceq 'Nonzero') {1} else {0})
            if ($index -eq 1 -and $pairControlMode -ceq 'LostMemberReceipt') {
                Write-TestNativeNewRecord -Path (Join-Path $pairControlContext.Directory ($Reference.memberNonce+'.result.json')) -Value @{syntheticWriteConflict=$true}
            }
            if ($index -eq 0 -and $pairControlMode -ceq 'DuplicateResults') {$value.Row.file=$pairControlContext.Descriptor.members[1].file}
            if ($index -eq 0 -and $pairControlMode -in @('LostObserverReceipt','BlockerWriteDenied','ContextRetentionDenied','ErrorReceiptWriteDenied')) {
                [IO.File]::WriteAllText($pairControlContext.OverlapPin.path,'changed synthetic observer')
            }
            if ($index -eq 1 -and $pairControlMode -ceq 'MissingResults') {return $null}
            $value
        }
        if ($mode -ceq 'BlockerWriteDenied') {
            $null=[IO.Directory]::CreateDirectory((Join-Path $pairControlContext.Descriptor.repositoryRoot '.test-output/qualification-cleanup-blocked.json'))
        }
        if ($mode -ceq 'ErrorReceiptWriteDenied') {
            $null=[IO.Directory]::CreateDirectory((Join-Path $pairControlContext.Directory 'pair-coordination-errors.json'))
        }
        $retainedContexts=Get-Variable TestFilePairUnverifiedContexts -Scope Script -ErrorAction SilentlyContinue
        # Direct assignment preserves this mutable list object. Pipeline output
        # from an if-expression would enumerate it into a fixed-size array.
        $originalRetainedContexts=$null
        if ($null -ne $retainedContexts) {$originalRetainedContexts=$retainedContexts.Value}
        try {
            if ($mode -ceq 'ContextRetentionDenied') {$script:TestFilePairUnverifiedContexts=[object]::new()}
            $pair=Invoke-TestFilePair -Context $pairControlContext -InvokeMember $adapter
        }
        finally {
            if ($mode -ceq 'ContextRetentionDenied') {$script:TestFilePairUnverifiedContexts=$originalRetainedContexts}
        }
        if ($mode -ceq 'ContextRetentionDenied') {
            Assert-RunnerControl ([object]::ReferenceEquals($script:TestFilePairUnverifiedContexts,$originalRetainedContexts)) 'fault adapter restores the original mutable context list by reference'
        }
        Assert-RunnerControl (($pairControlEvents -join '|') -ceq 'ack0|ack1|retain1|retain0') "$mode uses after-ACK sibling and independently drains the original first adapter"
        if ($mode -in @('Pass','Nonzero')) {
            Assert-RunnerControl (-not $pair.Stopped -and $pairControlContext.Closed -and $pairControlContext.DescriptorHandle.IsClosed) "$mode jointly releases complete owned members and original descriptor handle"
            Assert-RunnerControl (-not [IO.File]::Exists($pairControlContext.PendingPin.path)) "$mode archives coordinator hold only after finalization"
            if ($mode -ceq 'Nonzero') {Assert-RunnerControl ($pair.Results[0].Row.result -ceq 'Pass' -and $pair.Results[1].Row.nativeExitCode -eq 1 -and $pair.Results[1].Row.result -ceq 'Fail') 'ordinary sibling nonzero preserves each actual synthetic outcome'}
        }
        else {
            Assert-RunnerControl ($pair.Stopped -and [IO.File]::Exists($pairControlContext.PendingPin.path)) "$mode preserves coordinator hold instead of claiming complete pair cleanup"
            Assert-RunnerControl ($null -ne $pair.Results[0] -and $pair.Results[0].Row.nativeExitCode -eq 0) "$mode preserves first original zero independently of sibling or retention failure"
            if ($mode -in @('BlockerWriteDenied','ContextRetentionDenied','ErrorReceiptWriteDenied')) {
                Assert-RunnerControl ($pair.Failures.Count -ge 2 -and $pair.Results[1].Row.nativeExitCode -eq 0 -and
                    $pair.Results[0].Row.result -ceq 'Pass' -and $pair.Results[1].Row.result -ceq 'Pass') "$mode returns both original rows despite post-outcome retention failure"
                Assert-RunnerControl (($null -ne $pair.ErrorPin) -eq ($mode -cne 'ErrorReceiptWriteDenied')) "$mode independently retains errors or exposes failed error retention in memory"
            }
            if ($mode -ceq 'BlockerWriteDenied') {
                $first=$pair.Results[0].Row; $second=$pair.Results[1].Row
                $first.stopDispatch=$true
                $canonical=@([pscustomobject]@{file=$first.file;sha256=$first.sha256},[pscustomobject]@{file='Unstarted.Tests.ps1';sha256=('e'*64)},[pscustomobject]@{file=$second.file;sha256=$second.sha256})
                $executed=@{}; $executed[$second.file]=$second
                $accounted=Invoke-TestSuiteFiles -Inventory $canonical -PreviouslyExecuted $executed -InvokeFile {param($Expected) $first} -RetainResults {param($Rows,$Final)}
                Assert-RunnerControl ($accounted.Stopped -and $accounted.Results[0].result -ceq 'Pass' -and $accounted.Results[0].nativeExitCode -eq 0 -and
                    $accounted.Results[1].result -ceq 'Blocked' -and $accounted.Results[2].result -ceq 'Pass' -and $accounted.Results[2].nativeExitCode -eq 0 -and
                    -not $accounted.RetentionFailures.Count) 'blocker-path directory fault preserves both executed rows in canonical accounting and blocks only the unstarted file'
            }
        }
    }
    $inventory=@([pscustomobject]@{file='A.Tests.ps1';sha256=('a'*64)},[pscustomobject]@{file='B.Tests.ps1';sha256=('b'*64)},[pscustomobject]@{file='C.Tests.ps1';sha256=('c'*64)})
    $cache=@{'C.Tests.ps1'=[ordered]@{file='C.Tests.ps1';sha256=('c'*64);result='Fail';elapsedMilliseconds=1;nativeExitCode=1;completed=$true;cleanupVerified=$true}}
    $suite=Invoke-TestSuiteFiles -Inventory $inventory -PreviouslyExecuted $cache -InvokeFile {
        param($Expected) [ordered]@{file=$Expected.file;sha256=$Expected.sha256;result='Pass';elapsedMilliseconds=1;nativeExitCode=0;completed=$true;cleanupVerified=$true;stopDispatch=$true}
    } -RetainResults {param($Rows,$Final)}
    Assert-RunnerControl ($suite.Stopped -and $suite.Results[0].result -ceq 'Pass' -and $suite.Results[1].result -ceq 'Blocked' -and
        $suite.Results[2].result -ceq 'Fail' -and $suite.Results[2].nativeExitCode -eq 1 -and -not $suite.RetentionFailures.Count) 'canonical accounting blocks only unstarted files and retains already executed sibling nonzero after a stop'
}
catch {$pairFixtureBodyError=$_}
finally {
    foreach ($context in $pairFixtureContexts) {
        try {
            $context.DescriptorStream.Dispose()
            if (-not $context.DescriptorHandle.IsClosed) {throw 'Pair pure fixture descriptor handle remains open.'}
        }
        catch {$pairFixtureCleanupErrors.Add($_.Exception)}
        try {
            $held=Get-Variable TestFilePairUnverifiedContexts -Scope Script -ErrorAction SilentlyContinue
            if ($null -ne $held) {$null=$held.Value.Remove($context)}
        }
        catch {$pairFixtureCleanupErrors.Add($_.Exception)}
    }
    try {
        $parent=[IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot) '.test-output'))
        if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($pairFixture)) -ine $parent) {throw 'Pair pure cleanup escaped its owned fixture boundary.'}
        [IO.Directory]::Delete($pairFixture,$true)
    }
    catch {$pairFixtureCleanupErrors.Add($_.Exception)}
}
if ($null -ne $pairFixtureBodyError -or $pairFixtureCleanupErrors.Count) {
    $errors=[Collections.Generic.List[Exception]]::new()
    if ($null -ne $pairFixtureBodyError) {$errors.Add($pairFixtureBodyError.Exception)}
    foreach ($errorValue in $pairFixtureCleanupErrors) {$errors.Add($errorValue)}
    $exception=[AggregateException]::new('Pair pure body and independent fixture cleanup failures retained.',$errors.ToArray())
    if ($null -ne $pairFixtureBodyError) {$exception.Data['OriginalTestError']=$pairFixtureBodyError}
    throw $exception
}
Write-Output "PASS: $checks runner/lease pure controls; synthetic children and observer, actual parent identity and file locks; no native child starts or queries."
