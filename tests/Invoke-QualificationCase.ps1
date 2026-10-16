[CmdletBinding()]
param([string] $NativeLeaseId)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'GeneratedApplicationNative.ps1')
if ($MyInvocation.InvocationName -eq '.') { return }

$repository=Split-Path -Parent $PSScriptRoot
$directory=$null; $lease=$null; $result=$null; $unsafe=$false
$failures=[Collections.Generic.List[object]]::new()
$watch=[Diagnostics.Stopwatch]::StartNew()
try {
    if ($NativeLeaseId -cnotmatch '^[a-f0-9]{32}$') { throw 'Qualification bootstrap requires its original creator nonce.' }
    $directory=Join-Path $repository ('.test-output/qualification-case-native/'+$NativeLeaseId)
    $prearm=Read-TestNativeRecord -Path (Join-Path $directory 'owned-pending.json')
    $startupEnd=[DateTimeOffset]::Parse($prearm.authorityEnds).AddMilliseconds(-$prearm.cleanupReserveMs)
    $ackWait=[Diagnostics.Stopwatch]::StartNew()
    while (-not [IO.File]::Exists((Join-Path $directory 'startup-ack.json'))) {
        if ($ackWait.ElapsedMilliseconds -ge 10000 -or [DateTimeOffset]::UtcNow -ge $startupEnd) { throw 'Qualification startup acknowledgement exceeded its finite reservation.' }
        Start-Sleep -Milliseconds 25
    }
    $self=Get-TestNativeSelfIdentity
    $lease=Read-QualificationCaseLease -RepositoryRoot $repository -Nonce $NativeLeaseId -SelfIdentity $self
    if ($env:WINPCINFO_TEST_FILE_LEASE -cne $lease.Root.Pending.nonce -or
        ($lease.Admission.parentRole -eq 'TestFile' -and -not [string]::IsNullOrEmpty($env:WINPCINFO_TEST_CASE_LEASE)) -or
        ($lease.Admission.parentRole -eq 'QualificationCase' -and $env:WINPCINFO_TEST_CASE_LEASE -cne $lease.Admission.parentNonce)) { throw 'Qualification inherited admission differs from its immediate creator.' }
    Write-TestNativeNewRecord -Path (Join-Path $directory 'child-admission.claim') -Value ([ordered]@{
        contract='win-pcinfo.qualification-case-claim/1.0.0'; nonce=$NativeLeaseId;
        ackSha256=(Get-FileHash -LiteralPath $lease.AckPath).Hash.ToLowerInvariant(); pid=$self.Pid;
        creationUtc=$self.CreationUtc; ownerSid=$self.OwnerSid})
    $null=Read-QualificationCaseLease -RepositoryRoot $repository -Nonce $NativeLeaseId -SelfIdentity $self -RequireClaim
    $env:WINPCINFO_TEST_CASE_LEASE=$NativeLeaseId
    Assert-TestNativeRoleReady -NativeRole GeneratedApplication -RepositoryRoot $repository
    $authority=[DateTimeOffset]::Parse($lease.Pending.authorityEnds).AddMilliseconds(-$lease.Pending.cleanupReserveMs-2000)
    if ($authority -le [DateTimeOffset]::UtcNow) { throw 'Qualification case lacks a body and nested cleanup reservation.' }
    $env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC=$authority.ToString('o')
    $env:WINPCINFO_TEST_EVIDENCE=$lease.Root.Admission.suiteEvidenceRoot
    [Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
    [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
    $global:OutputEncoding=[Text.UTF8Encoding]::new($false)
    $parameters=ConvertFrom-TestNamedParameterRecord -Parameters $lease.Admission.namedParameters
    $ast=Assert-TestFileExecutableProtocol -Path $lease.Admission.testPath
    Assert-TestNamedParameterRecord -Ast $ast -Parameters $parameters
    $caseResult='Pass'
    try { & $lease.Admission.testPath @parameters }
    catch { $caseResult='Fail'; $unsafe=Test-QualificationCleanupUnverified -Exception $_.Exception; $failures.Add([ordered]@{type=$_.Exception.GetType().FullName; message=$_.Exception.Message}) }
    $blocker=Get-QualificationCleanupBlockerPath
    $unsafe=$unsafe -or [IO.File]::Exists($blocker) -or [IO.Directory]::Exists($blocker)
    try {
        $null=Read-QualificationCaseLease -RepositoryRoot $repository -Nonce $NativeLeaseId -SelfIdentity $self -RequireClaim
        Assert-TestNativeRoleReady -NativeRole GeneratedApplication -RepositoryRoot $repository
    }
    catch { $unsafe=$true; $failures.Add([ordered]@{type=$_.Exception.GetType().FullName; message=$_.Exception.Message}) }
    $result=[ordered]@{contract='win-pcinfo.qualification-case-result/1.0.0'; nonce=$NativeLeaseId;
        admissionSha256=(Get-TestNativeDigest -Value $lease.Admission); result=$caseResult;
        completed=$true; cleanupVerified=(-not $unsafe); elapsedMilliseconds=$watch.ElapsedMilliseconds; failures=$failures.ToArray()}
    Write-TestNativeNewRecord -Path (Join-Path $directory 'case-result.json') -Value $result
}
catch { $unsafe=$true; $failures.Add([ordered]@{type=$_.Exception.GetType().FullName; message=$_.Exception.Message}) }
if ($unsafe) {
    try { Write-TestNativeNewRecord -Path (Join-Path $directory 'bootstrap-errors.json') -Value $failures.ToArray() } catch { }
    try { [IO.File]::WriteAllText((Get-QualificationCleanupBlockerPath),'{"state":"OwnedCleanupUnverified"}',[Text.UTF8Encoding]::new($false)) } catch { }
    [Console]::Out.WriteLine('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED'); [Console]::Out.Flush()
    exit 1
}
if ($result.result -eq 'Fail') { exit 1 }
exit 0
