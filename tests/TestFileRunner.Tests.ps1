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
Write-Output "PASS: $checks runner/lease pure controls; contrived identities, no native starts or queries."
