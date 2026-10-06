[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'GeneratedApplicationNative.ps1')
$checks=0
function Assert-CaseControl { param([bool] $Condition,[string] $Because) if (-not $Condition) { throw "Case pure control failed: $Because" }; $script:checks++ }
function Assert-CaseRefusal { param([scriptblock] $Action,[string] $Because) $refused=$false; try { & $Action | Out-Null } catch { $refused=$true }; Assert-CaseControl $refused $Because }
$fixture=Join-Path (Split-Path $PSScriptRoot) ('.test-output/case-pure-'+[guid]::NewGuid().ToString('N'))
$repository=Join-Path $fixture 'repository'
$rootNonce='a'*32; $caseNonces=@(('b'*32),('c'*32),('d'*32))
$suiteRoot=Join-Path $repository ('.test-output/suite-'+('e'*32))
$rootDirectory=Join-Path $repository ('.test-output/test-file-native/'+$rootNonce)
$null=[IO.Directory]::CreateDirectory((Join-Path $repository 'tests'))
$null=[IO.Directory]::CreateDirectory($rootDirectory)
$null=[IO.Directory]::CreateDirectory($suiteRoot)
$now=[DateTimeOffset]::Parse('2026-10-06T12:00:00Z')
$savedFile=$env:WINPCINFO_TEST_FILE_LEASE; $savedCase=$env:WINPCINFO_TEST_CASE_LEASE
try {
    # Contrived files, identities and original-handle outcomes only. This
    # fixture never starts or queries a native process, task or application.
    $leaf=Join-Path $repository 'tests/StatusDeskEntry.Tests.ps1'
    [IO.File]::WriteAllText($leaf,'param([switch]$Choices,[switch]$StaChild,[string]$Name,[string[]]$Items)')
    $test=Join-Path $repository 'tests/A.Tests.ps1'; [IO.File]::WriteAllText($test,'# contrived file root')
    $bootstrap=Join-Path $repository 'tests/Invoke-TestFile.ps1'; [IO.File]::WriteAllText($bootstrap,'# contrived bootstrap')
    $caseBootstrap=Join-Path $repository 'tests/Invoke-QualificationCase.ps1'; [IO.File]::WriteAllText($caseBootstrap,'# contrived case bootstrap')
    $driver=Join-Path $repository 'tests/Invoke-AssessmentSafetyQualification.ps1'; [IO.File]::WriteAllText($driver,'param([switch]$Enabled,[string]$Mode)')
    $hostPath=Join-Path $repository 'fixture-host.exe'; [IO.File]::WriteAllText($hostPath,'contrived host')
    $inventoryPath=Join-Path $suiteRoot 'suite-inventory.json'; [IO.File]::WriteAllText($inventoryPath,'contrived full inventory')
    $inputs=@(@($leaf,$test,$bootstrap,$caseBootstrap,$driver,$hostPath,$inventoryPath) | Sort-Object -CaseSensitive | ForEach-Object {
        [pscustomobject][ordered]@{path=$_; bytes=(Get-Item -LiteralPath $_).Length; sha256=(Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant()}
    })
    $rootAdmission=[ordered]@{contract='win-pcinfo.test-file-admission/1.0.0'; repositoryRoot=$repository;
        testPath=$test; testSha256=(Get-FileHash -LiteralPath $test).Hash.ToLowerInvariant(); bootstrapPath=$bootstrap;
        hostPath=$hostPath; inventoryPath=$inventoryPath; suiteEvidenceRoot=$suiteRoot;
        candidatePath=''; preparedManifestPath=''; preparedManifestSha256=''; inputs=$inputs; cohortSha256=(Get-TestNativeDigest -Value $inputs)}
    $identities=@(0..3 | ForEach-Object { [pscustomobject]@{Pid=(100+$_); CreationUtc=('2026-10-06T11:0'+$_+':00.0000000Z'); OwnerSid='S-1-5-21-111'; HostPath=$hostPath} })
    function Save-CaseLeaseFixture {
        param($Directory,$Pending,[string]$Role)
        foreach ($name in @('owned-pending.json','startup.json','startup-ack.json','child-admission.claim')) {
            $path=Join-Path $Directory $name
            if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
        }
        Write-TestNativeNewRecord -Path (Join-Path $Directory 'owned-pending.json') -Value $Pending
        Write-TestNativeNewRecord -Path (Join-Path $Directory 'startup.json') -Value $Pending
        $prefix=if ($Role -eq 'TestFile') {'test-file'} else {'qualification-case'}
        Write-TestNativeNewRecord -Path (Join-Path $Directory 'startup-ack.json') -Value ([ordered]@{
            contract=('win-pcinfo.'+$prefix+'-startup/1.0.0'); nonce=$Pending.nonce; directory=$Directory;
            pendingSha256=(Get-FileHash -LiteralPath (Join-Path $Directory 'owned-pending.json')).Hash.ToLowerInvariant();
            startupSha256=(Get-FileHash -LiteralPath (Join-Path $Directory 'startup.json')).Hash.ToLowerInvariant();
            admissionSha256=(Get-TestNativeDigest -Value $Pending.admission)})
        Write-TestNativeNewRecord -Path (Join-Path $Directory 'child-admission.claim') -Value ([ordered]@{
            contract=('win-pcinfo.'+$prefix+'-claim/1.0.0'); nonce=$Pending.nonce;
            ackSha256=(Get-FileHash -LiteralPath (Join-Path $Directory 'startup-ack.json')).Hash.ToLowerInvariant();
            pid=$Pending.child.Pid; creationUtc=$Pending.child.CreationUtc; ownerSid=$Pending.child.OwnerSid})
    }
    function New-CaseChildIdentity { param($Self) [ordered]@{Started=$true; ExactStartedProcessHandlePinned=$true; ObservationFailure=''; Pid=$Self.Pid; CreationUtc=$Self.CreationUtc; OwnerSid=$Self.OwnerSid; HostPath=$Self.HostPath} }
    $rootPending=[ordered]@{nativeRole='TestFile'; nonce=$rootNonce; authorityEnds='2026-10-06T13:00:00.0000000Z'; cleanupReserveMs=10000;
        childCreationRequested=$true; child=(New-CaseChildIdentity $identities[0]); admission=$rootAdmission}
    Save-CaseLeaseFixture $rootDirectory $rootPending TestFile
    $parent=Read-TestFileLease -RepositoryRoot $repository -Nonce $rootNonce -SelfIdentity $identities[0] -RequireClaim -Now $now
    $root=$parent; $pendingCases=@(); $directories=@()
    for ($depth=1; $depth -le 3; $depth++) {
        $directory=Join-Path $repository ('.test-output/qualification-case-native/'+$caseNonces[$depth-1]); $null=[IO.Directory]::CreateDirectory($directory)
        $original=@('-NoLogo','-NoProfile','-STA','-File',$leaf,'-Choices:false','-StaChild','-Name','','-Items','one')
        $invocation=ConvertTo-QualificationCaseInvocation -RepositoryRoot $repository -Arguments $original
        $admission=[ordered]@{contract='win-pcinfo.qualification-case-admission/1.0.0'; repositoryRoot=$repository;
            testPath=$leaf; bootstrapPath=$caseBootstrap; hostPath=$hostPath; originalArguments=$original;
            originalNamedParameters=$invocation.NamedParameters; namedParameters=$invocation.NamedParameters; sta=$true;
            parentRole=$parent.Pending.nativeRole; parentNonce=$parent.Pending.nonce; depth=$depth; rootNonce=$rootNonce;
            cohortSha256=$rootAdmission.cohortSha256; parentPendingSha256=(Get-FileHash -LiteralPath $parent.PendingPath).Hash.ToLowerInvariant();
            parentClaimSha256=(Get-FileHash -LiteralPath (Join-Path $parent.Directory 'child-admission.claim')).Hash.ToLowerInvariant();
            rootPendingSha256=(Get-FileHash -LiteralPath $root.PendingPath).Hash.ToLowerInvariant()}
        $pending=[ordered]@{nativeRole='QualificationCase'; nonce=$caseNonces[$depth-1]; authorityEnds=$now.AddMinutes(55-$depth*5).ToString('o');
            cleanupReserveMs=10000; childCreationRequested=$true; child=(New-CaseChildIdentity $identities[$depth]);
            parent=$identities[$depth-1]; admission=$admission}
        Save-CaseLeaseFixture $directory $pending QualificationCase
        $parent=Read-QualificationCaseLease -RepositoryRoot $repository -Nonce $pending.nonce -SelfIdentity $identities[$depth] -RequireClaim -Now $now
        Assert-CaseControl ($parent.Admission.depth -eq $depth -and $parent.AllowedCasePendingPaths.Count -eq $depth) "exact immediate-owner chain at depth $depth"
        $pendingCases+=@($pending); $directories+=@($directory)
    }
    $last=$pendingCases[2]; $lastDirectory=$directories[2]
    function Read-LastCaseFixture { Read-QualificationCaseLease -RepositoryRoot $repository -Nonce $caseNonces[2] -SelfIdentity $identities[3] -RequireClaim -Now $now }
    foreach ($field in @('Pid','CreationUtc','OwnerSid','HostPath')) {
        $saved=$identities[3].$field
        try { $identities[3].$field=$(if ($field -eq 'Pid') {999} else {$saved+'wrong'}); Assert-CaseRefusal { Read-LastCaseFixture } "case current $field differs" }
        finally { $identities[3].$field=$saved }
    }
    foreach ($field in @('rootNonce','cohortSha256','parentNonce','parentPendingSha256','parentClaimSha256','rootPendingSha256','depth')) {
        $saved=$last.admission[$field]
        try {
            $last.admission[$field]=$(if ($field -eq 'depth') {4} else {'f'*32})
            Save-CaseLeaseFixture $lastDirectory $last QualificationCase
            Assert-CaseRefusal { Read-LastCaseFixture } "repinned wrong admission field $field refuses"
        }
        finally { $last.admission[$field]=$saved; Save-CaseLeaseFixture $lastDirectory $last QualificationCase }
    }
    $saved=$last.authorityEnds
    try { $last.authorityEnds='2026-10-06T13:00:00.0000000Z'; Save-CaseLeaseFixture $lastDirectory $last QualificationCase; Assert-CaseRefusal { Read-LastCaseFixture } 'child cannot enlarge parent deadline' }
    finally { $last.authorityEnds=$saved; Save-CaseLeaseFixture $lastDirectory $last QualificationCase }
    Assert-CaseRefusal { Read-QualificationCaseLease -RepositoryRoot $repository -Nonce $caseNonces[2] -SelfIdentity $identities[3] -RequireClaim -Now $now.AddHours(2) } 'expired chain refuses'
    $claimPath=Join-Path $lastDirectory 'child-admission.claim'
    [IO.File]::Delete($claimPath); Assert-CaseRefusal { Read-LastCaseFixture } 'missing case claim refuses'
    Save-CaseLeaseFixture $lastDirectory $last QualificationCase
    Assert-CaseRefusal { Write-TestNativeNewRecord -Path $claimPath -Value @{} } 'duplicate case claim refuses'
    [IO.File]::WriteAllText($claimPath,'{"contract":"stale"}'); Assert-CaseRefusal { Read-LastCaseFixture } 'stale case claim refuses'
    Save-CaseLeaseFixture $lastDirectory $last QualificationCase
    $ackPath=Join-Path $lastDirectory 'startup-ack.json'
    [IO.File]::Delete($ackPath); $null=[IO.Directory]::CreateDirectory($ackPath)
    Assert-CaseRefusal { Write-TestNativeNewRecord -Path $ackPath -Value @{} } 'startup retention failure cannot grant admission'
    Assert-CaseRefusal { Read-LastCaseFixture } 'acknowledgement directory refuses'
    [IO.Directory]::Delete($ackPath); Save-CaseLeaseFixture $lastDirectory $last QualificationCase
    $env:WINPCINFO_TEST_FILE_LEASE=$rootNonce; $env:WINPCINFO_TEST_CASE_LEASE=$caseNonces[2]
    $context=Get-TestNativeAdmissionContext -RepositoryRoot $repository -SelfIdentity $identities[3] -Now $now
    Assert-CaseControl ($context.Depth -eq 3 -and $context.Root.Pending.nonce -ceq $rootNonce) 'current case preserves its exact file root'
    $env:WINPCINFO_TEST_FILE_LEASE='f'*32
    Assert-CaseRefusal { Get-TestNativeAdmissionContext -RepositoryRoot $repository -SelfIdentity $identities[3] -Now $now } 'wrong inherited file nonce refuses even with valid case'
    $env:WINPCINFO_TEST_CASE_LEASE='invalid'
    Assert-CaseRefusal { Get-TestNativeAdmissionContext -RepositoryRoot $repository -SelfIdentity $identities[3] -Now $now } 'malformed case cannot fall back to a file lease'
    $env:WINPCINFO_TEST_FILE_LEASE=$null; $env:WINPCINFO_TEST_CASE_LEASE=$null
    Assert-CaseRefusal { Get-TestNativeAdmissionContext -RepositoryRoot $repository -SelfIdentity $identities[0] -Now $now } 'standalone wrapper requires focused entrypoint'
    $caseParent=Join-Path $repository '.test-output/qualification-case-native'
    Assert-GeneratedApplicationNativeReady -EvidenceParent $caseParent -AllowedPendingPaths $context.AllowedCasePendingPaths
    Assert-CaseControl $true 'only exact validated chain holds coexist'
    $unrelated=Join-Path $caseParent ('f'*32); $null=[IO.Directory]::CreateDirectory($unrelated); [IO.File]::WriteAllText((Join-Path $unrelated 'owned-pending.json'),'{}')
    Assert-CaseRefusal { Assert-GeneratedApplicationNativeReady -EvidenceParent $caseParent -AllowedPendingPaths $context.AllowedCasePendingPaths } 'unrelated active case hold refuses'
    $binding=ConvertTo-QualificationCaseInvocation -RepositoryRoot $repository -Arguments @('-NoLogo','-NoProfile','-File',$leaf,'-Choices:false','-Name','','-Items','one')
    $typed=$binding.NamedParameters
    $bound=& {param([switch]$Choices,[string]$Name,[string[]]$Items) [pscustomobject]@{Present=$PSBoundParameters.ContainsKey('Choices'); Value=[bool]$Choices; Name=$Name; Items=$Items}} @typed
    Assert-CaseControl ($bound.Present -and -not $bound.Value -and $bound.Name -ceq '' -and $bound.Items.Count -eq 1) 'explicit false switch, empty scalar and named array bind without positional argv reinterpretation'
    foreach ($arguments in @(@('-NoLogo','-NoProfile','-Command','exit 0'),@('-NoLogo','-NoProfile','-EncodedCommand','AA=='),@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$leaf),@('-NoLogo','-NoProfile','-File',$leaf,'-Cho'),@('-NoLogo','-NoProfile','-File',$leaf,'-Choices','-Choices:false'),@('-NoLogo','-NoProfile','-File',$leaf,'-Name:true'))) {
        Assert-CaseRefusal { ConvertTo-QualificationCaseInvocation -RepositoryRoot $repository -Arguments $arguments } 'unknown host grammar or leaf binding refuses'
    }
    Assert-CaseRefusal { Get-QualificationCaseProfile -RepositoryRoot $repository -Path $test } 'arbitrary ordinary test is not a delegated case profile'
    $nativeOutcome=[pscustomobject]@{NativeTerminalObserved=$true; NativeExitCode=0; OwnedCleanupUnverified=$false; StreamsDrained=$true; StreamFailure=$false; OutputOverflow=$false}
    $completion=[ordered]@{contract='win-pcinfo.qualification-case-result/1.0.0'; nonce=$caseNonces[2]; admissionSha256=(Get-TestNativeDigest -Value $last.admission);
        completed=$true; cleanupVerified=$true; result='Pass'}
    Assert-QualificationCaseCompletion -Completion $completion -Admission $last.admission -Nonce $caseNonces[2] -NativeOutcome $nativeOutcome
    Assert-CaseControl $true 'retained natural-zero case completion matches actual contrived outcome'
    foreach ($field in @('completed','cleanupVerified','nonce','admissionSha256')) {
        $saved=$completion[$field]
        try { $completion[$field]=$(if ($field -in @('completed','cleanupVerified')) {$false} else {'wrong'}); Assert-CaseRefusal { Assert-QualificationCaseCompletion -Completion $completion -Admission $last.admission -Nonce $caseNonces[2] -NativeOutcome $nativeOutcome } "mismatched completion $field refuses before pending release" }
        finally { $completion[$field]=$saved }
    }
    foreach ($field in @('OwnedCleanupUnverified','StreamFailure','OutputOverflow','NativeTerminalObserved','StreamsDrained')) {
        $saved=$nativeOutcome.$field
        try { $nativeOutcome.$field=(-not $saved); Assert-CaseRefusal { Assert-QualificationCaseCompletion -Completion $completion -Admission $last.admission -Nonce $caseNonces[2] -NativeOutcome $nativeOutcome } "unsafe or unknown original $field cannot be filled from completion files" }
        finally { $nativeOutcome.$field=$saved }
    }
    $nativeOutcome.NativeExitCode=1; $completion.result='Fail'
    Assert-QualificationCaseCompletion -Completion $completion -Admission $last.admission -Nonce $caseNonces[2] -NativeOutcome $nativeOutcome
    Assert-CaseControl $true 'natural nonzero assertion completion stays nonzero'
    $completion.result='Pass'; $nativeOutcome.NativeExitCode=0
    $completionPath=Join-Path $lastDirectory 'case-result.json'
    Write-TestNativeNewRecord -Path $completionPath -Value $completion
    $retentionErrors=[Collections.Generic.List[Exception]]::new()
    $confirmed=Confirm-QualificationCaseNativeRetention -RepositoryRoot $repository -Directory $lastDirectory -Nonce $caseNonces[2] -Admission $last.admission -NativeIdentity $identities[3] -NativeOutcome $nativeOutcome -Failures $retentionErrors -Now $now
    Assert-CaseControl ($confirmed -and $retentionErrors.Count -eq 0) 'actual pre-release protocol boundary accepts complete retained natural zero'
    [IO.File]::Delete($claimPath)
    $retentionErrors.Clear()
    $confirmed=Confirm-QualificationCaseNativeRetention -RepositoryRoot $repository -Directory $lastDirectory -Nonce $caseNonces[2] -Admission $last.admission -NativeIdentity $identities[3] -NativeOutcome $nativeOutcome -Failures $retentionErrors -Now $now
    Assert-CaseControl (-not $confirmed -and $retentionErrors.Count -gt 0 -and $nativeOutcome.NativeExitCode -eq 0 -and [IO.File]::Exists((Join-Path $lastDirectory 'owned-pending.json'))) 'missing claim blocks release without replacing actual zero or deleting its hold'
    Save-CaseLeaseFixture $lastDirectory $last QualificationCase
    [IO.File]::Delete($completionPath)
    $retentionErrors.Clear()
    $confirmed=Confirm-QualificationCaseNativeRetention -RepositoryRoot $repository -Directory $lastDirectory -Nonce $caseNonces[2] -Admission $last.admission -NativeIdentity $identities[3] -NativeOutcome $nativeOutcome -Failures $retentionErrors -Now $now
    Assert-CaseControl (-not $confirmed -and $retentionErrors.Count -gt 0 -and $nativeOutcome.NativeExitCode -eq 0 -and [IO.File]::Exists((Join-Path $lastDirectory 'owned-pending.json'))) 'lost completion blocks release while independently retained original zero remains zero'
    $requestPath=Join-Path $fixture 'focused.json'
    $request=[ordered]@{contract='win-pcinfo.focused-test-request/1.0.0'; repositoryRoot=$repository; scope='FocusedSafetyDriver'; testPath=$driver;
        testSha256=(Get-FileHash -LiteralPath $driver).Hash.ToLowerInvariant(); namedParameters=[ordered]@{Enabled=$false; Mode='Culture'}}
    Write-TestNativeNewRecord -Path $requestPath -Value $request
    $requestHash=(Get-FileHash -LiteralPath $requestPath).Hash.ToLowerInvariant()
    $focused=Read-FocusedTestRequest -RepositoryRoot $repository -Path $requestPath -Sha256 $requestHash
    Assert-CaseControl ($focused.Scope -ceq 'FocusedSafetyDriver' -and -not $focused.NamedParameters.Enabled) 'focused safety driver retains explicit false and scoped result'
    $focusedAdmission=$rootAdmission | ConvertTo-Json -Depth 14 | ConvertFrom-Json -AsHashtable -Depth 14 -DateKind String
    $focusedAdmission.testPath=$driver; $focusedAdmission.testSha256=$request.testSha256
    $focusedAdmission.scope='FocusedSafetyDriver'; $focusedAdmission.namedParameters=[ordered]@{Enabled=$false; Mode='Culture'}
    $focusedAdmission.focusedRequestPath=$requestPath; $focusedAdmission.focusedRequestSha256=$requestHash
    $focusedAdmission.inputs=@($focusedAdmission.inputs)+@([ordered]@{path=$requestPath; bytes=(Get-Item -LiteralPath $requestPath).Length; sha256=$requestHash})
    $focusedAdmission.cohortSha256=Get-TestNativeDigest -Value $focusedAdmission.inputs
    Assert-TestFileAdmissionInputs -Admission $focusedAdmission
    Assert-CaseControl $true 'enumerated focused driver admission closes request and full root provenance'
    $focusedAdmission.namedParameters.Enabled=$true
    Assert-CaseRefusal { Assert-TestFileAdmissionInputs -Admission $focusedAdmission } 'focused caller cannot change parameters after request admission'
    $focusedAdmission.namedParameters.Enabled=$false; $focusedAdmission.scope='Full'
    Assert-CaseRefusal { Assert-TestFileAdmissionInputs -Admission $focusedAdmission } 'focused driver cannot become a full-discovery file'
    $focusedAdmission.scope='FocusedSafetyDriver'; $focusedAdmission.focusedRequestSha256='0'*64
    Assert-CaseRefusal { Assert-TestFileAdmissionInputs -Admission $focusedAdmission } 'focused pinned request mismatch refuses'
    Assert-CaseRefusal { Read-FocusedTestRequest -RepositoryRoot $repository -Path $requestPath -Sha256 ('0'*64) } 'stale focused request refuses'
    $request.namedParameters.Enabled='false'; [IO.File]::WriteAllText($requestPath,($request | ConvertTo-Json))
    Assert-CaseRefusal { Read-FocusedTestRequest -RepositoryRoot $repository -Path $requestPath -Sha256 ((Get-FileHash -LiteralPath $requestPath).Hash.ToLowerInvariant()) } 'repinned string switch refuses typed admission'
    $buildRoot=Join-Path $repository 'build'; $null=[IO.Directory]::CreateDirectory($buildRoot)
    $build=Join-Path $buildRoot 'Build.ps1'; [IO.File]::WriteAllText($build,'param([string]$OutputPath,[string]$SignedHelperPath)')
    $ownedOutput=Join-Path $repository ('.test-output/candidate-'+('f'*32)); $null=[IO.Directory]::CreateDirectory($ownedOutput)
    $output=Join-Path $ownedOutput 'WIN-PCInfo.ps1'
    $null=ConvertTo-QualificationCaseInvocation -RepositoryRoot $repository -Arguments @('-NoLogo','-NoProfile','-File',$build,'-OutputPath',$output)
    Assert-CaseControl $true 'standalone mutator accepts only its explicit unique output profile'
    Assert-CaseRefusal { ConvertTo-QualificationCaseInvocation -RepositoryRoot $repository -Arguments @('-NoLogo','-NoProfile','-File',$build,'-OutputPath',(Join-Path $repository 'artifacts/WIN-PCInfo.ps1')) } 'shared candidate output is not a delegated build target'
    Assert-CaseRefusal { ConvertTo-QualificationCaseInvocation -RepositoryRoot $repository -Arguments @('-NoLogo','-NoProfile','-File',$build,'-OutputPath',$output,'-SignedHelperPath','synthetic') } 'qualification fallback cannot introduce signing inputs'
    # Disclosed pure native-result substitution verifies public compatibility;
    # actual File->Case->leaf ownership remains a separate root native gate.
    & {
        function Invoke-OwnedQualificationCase { [pscustomobject]@{ExitCode=7; StreamRecords=@([pscustomobject]@{Sequence=1; Text='ordinary nonzero'})} }
        $caught=$false; try { Invoke-QualificationTestProcess -HostPath $hostPath -Arguments @('synthetic') | Out-Null } catch { $caught=$true }
        Assert-CaseControl ($caught -and $LASTEXITCODE -eq 7) 'caller observes original native nonzero despite assertion failure'
    }
    & {
        function Invoke-OwnedQualificationCase { [pscustomobject]@{ExitCode=0; StreamRecords=@([pscustomobject]@{Sequence=1; Text='ordinary zero'})} }
        $output=@(Invoke-QualificationTestProcess -HostPath $hostPath -Arguments @('synthetic'))
        Assert-CaseControl ($LASTEXITCODE -eq 0 -and $output[0] -ceq 'ordinary zero') 'natural zero and output contract survive the finite adapter'
    }
    Write-Output "PASS: $checks case/focused pure controls; contrived identities and native-result stubs, no native starts or queries."
}
finally {
    $env:WINPCINFO_TEST_FILE_LEASE=$savedFile; $env:WINPCINFO_TEST_CASE_LEASE=$savedCase
    $allowed=[IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot) '.test-output'))+[IO.Path]::DirectorySeparatorChar
    if (-not [IO.Path]::GetFullPath($fixture).StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected case pure fixture cleanup path.' }
    if ([IO.Directory]::Exists($fixture)) { [IO.Directory]::Delete($fixture,$true) }
}
