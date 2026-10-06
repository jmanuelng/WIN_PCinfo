[CmdletBinding()]
param([string] $NativeLeaseId)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'GeneratedApplicationNative.ps1')

function Get-TestFileInventory {
    param([Parameter(Mandatory)] [string] $RepositoryRoot)
    $root=[IO.Path]::GetFullPath($RepositoryRoot)
    $testRoot=Join-Path $root 'tests'
    foreach ($item in @(Get-ChildItem -LiteralPath $testRoot -Recurse -Force -ErrorAction Stop | Sort-Object FullName -CaseSensitive)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Test inventory cannot contain reparse points.' }
        if (-not $item.PSIsContainer) {
            [pscustomobject][ordered]@{path=$item.FullName; bytes=$item.Length;
                sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
    }
}

function Assert-TestSuiteAccounting {
    param([Parameter(Mandatory)] [object[]] $Inventory,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results, [switch] $Complete)
    if ($Inventory.Count -lt 1 -or $Results.Count -gt $Inventory.Count -or ($Complete -and $Results.Count -ne $Inventory.Count)) { throw 'Suite result inventory is incomplete or unexpected.' }
    $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    for ($index=0; $index -lt $Results.Count; $index++) {
        $expected=$Inventory[$index]; $actual=$Results[$index]
        if (-not $names.Add($actual.file) -or $actual.file -cne $expected.file -or $actual.sha256 -cne $expected.sha256 -or
            $actual.result -cnotin @('Pass','Fail','Blocked') -or $actual.elapsedMilliseconds -lt 0) { throw 'Suite results differ from the admitted ordered inventory.' }
        if ($actual.result -eq 'Blocked') {
            if ($actual.elapsedMilliseconds -ne 0) { throw 'Unexecuted suite rows cannot report execution time.' }
        }
        elseif ($actual.result -eq 'Pass' -and ($actual.nativeExitCode -ne 0 -or -not $actual.completed -or -not $actual.cleanupVerified)) { throw 'A passing suite row lacks complete natural-zero evidence.' }
    }
}

function Assert-TestFileCompletion {
    param([Parameter(Mandatory)] $Completion, [Parameter(Mandatory)] $Admission,
        [Parameter(Mandatory)] [string] $Nonce, [Parameter(Mandatory)] $NativeOutcome)
    if ($Completion.contract -cne 'win-pcinfo.test-file-result/1.0.0' -or $Completion.nonce -cne $Nonce -or
        $Completion.testPath -ine $Admission.testPath -or $Completion.testSha256 -cne $Admission.testSha256 -or
        $Completion.completed -isnot [bool] -or -not $Completion.completed -or
        $Completion.cleanupVerified -isnot [bool] -or -not $Completion.cleanupVerified -or
        $Completion.result -cnotin @('Pass','Fail') -or
        -not $NativeOutcome.NativeTerminalObserved -or $NativeOutcome.OwnedCleanupUnverified -or
        -not $NativeOutcome.StreamsDrained -or $NativeOutcome.StreamFailure -or $NativeOutcome.OutputOverflow -or
        ($Completion.result -eq 'Pass' -and $NativeOutcome.NativeExitCode -ne 0) -or
        ($Completion.result -eq 'Fail' -and $NativeOutcome.NativeExitCode -ne 1)) { throw 'Test file completion differs from its original native outcome or admission.' }
}

# Dot sourcing supplies the pure inventory/accounting functions to the suite
# and fixture controls; executing the shim always requires a one-use lease.
if ($MyInvocation.InvocationName -eq '.') { return }
$repository=Split-Path -Parent $PSScriptRoot
$lease=$null
$directory=$null
$result=$null
$unsafe=$false
$failures=[Collections.Generic.List[object]]::new()
$watch=[Diagnostics.Stopwatch]::StartNew()
try {
    if ($NativeLeaseId -cnotmatch '^[a-f0-9]{32}$' -or -not [string]::IsNullOrEmpty($env:WINPCINFO_TEST_FILE_LEASE)) { throw 'Test file bootstrap requires a fresh nondelegated lease.' }
    $directory=Join-Path $repository ('.test-output/test-file-native/'+$NativeLeaseId)
    # Wait only for the startup identity acknowledgement, never for a file to
    # infer native completion. The original parent owns the finite native wait.
    $ackWait=[Diagnostics.Stopwatch]::StartNew()
    $prearm=Read-TestNativeRecord -Path (Join-Path $directory 'owned-pending.json')
    $startupEnd=[DateTimeOffset]::Parse($prearm.authorityEnds).AddMilliseconds(-$prearm.cleanupReserveMs)
    while (-not [IO.File]::Exists((Join-Path $directory 'startup-ack.json'))) {
        if ($ackWait.ElapsedMilliseconds -ge 10000 -or [DateTimeOffset]::UtcNow -ge $startupEnd) { throw 'Test file startup acknowledgement was not retained within its finite reservation.' }
        Start-Sleep -Milliseconds 25
    }
    $self=Get-TestNativeSelfIdentity
    $lease=Read-TestFileLease -RepositoryRoot $repository -Nonce $NativeLeaseId -SelfIdentity $self
    Write-TestNativeNewRecord -Path (Join-Path $directory 'child-admission.claim') -Value ([ordered]@{
        contract='win-pcinfo.test-file-claim/1.0.0'; nonce=$NativeLeaseId;
        ackSha256=(Get-FileHash -LiteralPath $lease.AckPath -Algorithm SHA256).Hash.ToLowerInvariant();
        pid=$self.Pid; creationUtc=$self.CreationUtc; ownerSid=$self.OwnerSid})
    $null=Read-TestFileLease -RepositoryRoot $repository -Nonce $NativeLeaseId -SelfIdentity $self -RequireClaim
    $env:WINPCINFO_TEST_FILE_LEASE=$NativeLeaseId
    Assert-TestNativeRoleReady -NativeRole GeneratedApplication -RepositoryRoot $repository
    $env:WINPCINFO_TEST_EVIDENCE=$lease.Admission.suiteEvidenceRoot
    $authority=[DateTimeOffset]::Parse($lease.Pending.authorityEnds).AddMilliseconds(-$lease.Pending.cleanupReserveMs-2000)
    if ($authority -le [DateTimeOffset]::UtcNow) { throw 'Test file admission lacks a body and inner cleanup reservation.' }
    $env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC=$authority.ToString('o')
    [Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
    [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
    $global:OutputEncoding=[Text.UTF8Encoding]::new($false)
    $parameters=@{}
    $ast=Assert-TestFileExecutableProtocol -Path $lease.Admission.testPath
    $names=if ($null -ne $ast.ParamBlock) {@($ast.ParamBlock.Parameters.Name.VariablePath.UserPath)} else {@()}
    $preparedNames=@('CandidatePath','PreparedManifestPath','PreparedManifestSha256')
    $declared=@($preparedNames | Where-Object { $_ -in $names }).Count
    if ($declared -ne 0 -and $declared -ne 3) { throw 'Test file declares an incomplete prepared input interface.' }
    if ($declared -eq 3 -and -not [string]::IsNullOrEmpty($lease.Admission.candidatePath)) {
        $parameters=@{CandidatePath=$lease.Admission.candidatePath; PreparedManifestPath=$lease.Admission.preparedManifestPath;
            PreparedManifestSha256=$lease.Admission.preparedManifestSha256}
    }
    $fileResult='Pass'
    try { & $lease.Admission.testPath @parameters }
    catch {
        $fileResult='Fail'
        $unsafe=Test-QualificationCleanupUnverified -Exception $_.Exception
        $failures.Add([ordered]@{type=$_.Exception.GetType().FullName; message=$_.Exception.Message})
    }
    $blocker=Get-QualificationCleanupBlockerPath
    $unsafe=$unsafe -or [IO.File]::Exists($blocker) -or [IO.Directory]::Exists($blocker)
    try {
        Assert-TestFileAdmissionInputs -Admission $lease.Admission
        Assert-TestNativeRoleReady -NativeRole GeneratedApplication -RepositoryRoot $repository
    }
    catch { $unsafe=$true; $failures.Add([ordered]@{type=$_.Exception.GetType().FullName; message=$_.Exception.Message}) }
    $result=[ordered]@{contract='win-pcinfo.test-file-result/1.0.0'; nonce=$NativeLeaseId;
        testPath=$lease.Admission.testPath; testSha256=$lease.Admission.testSha256;
        result=$fileResult; completed=$true; cleanupVerified=(-not $unsafe);
        elapsedMilliseconds=$watch.ElapsedMilliseconds; failures=$failures.ToArray()}
    Write-TestNativeNewRecord -Path (Join-Path $directory 'file-result.json') -Value $result
}
catch {
    $unsafe=$true
    $failures.Add([ordered]@{type=$_.Exception.GetType().FullName; message=$_.Exception.Message})
}
if ($unsafe) {
    try { Write-TestNativeNewRecord -Path (Join-Path $directory 'bootstrap-errors.json') -Value $failures.ToArray() } catch { }
    try { [IO.File]::WriteAllText((Get-QualificationCleanupBlockerPath),'{"state":"OwnedCleanupUnverified"}',[Text.UTF8Encoding]::new($false)) } catch { }
    [Console]::Out.WriteLine('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED'); [Console]::Out.Flush()
    exit 1
}
if ($result.result -eq 'Fail') { exit 1 }
exit 0
