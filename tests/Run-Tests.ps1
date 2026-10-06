[CmdletBinding()]
param([string] $CandidatePath, [string] $PreparedManifestPath, [string] $PreparedManifestSha256,
    [DateTimeOffset] $AuthorityEnds=[DateTimeOffset]::MinValue,
    [long] $TimeoutMs=25200000, [long] $CleanupReserveMs=120000,
    [string] $FocusedRequestPath, [string] $FocusedRequestSha256)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Invoke-TestFile.ps1')

function Invoke-TestSuiteFiles {
    param([Parameter(Mandatory)] [object[]] $Inventory,
        [Parameter(Mandatory)] [scriptblock] $InvokeFile, [Parameter(Mandatory)] [scriptblock] $RetainResults)
    $results=[Collections.Generic.List[object]]::new()
    $stop=$false
    $retentionFailures=[Collections.Generic.List[Exception]]::new()
    foreach ($expected in $Inventory) {
        if ($stop) {
            $row=[ordered]@{file=$expected.file; result='Blocked'; elapsedMilliseconds=0; sha256=$expected.sha256;
                completed=$false; cleanupVerified=$false; nativeExitCode=$null}
        }
        else {
            try { $row=& $InvokeFile $expected }
            catch {
                $original=$_.Exception.Data['OriginalNativeOutcome']
                $row=[ordered]@{file=$expected.file; result='Fail'; elapsedMilliseconds=0; sha256=$expected.sha256;
                    completed=$false; cleanupVerified=$false;
                    nativeExitCode=$(if ($null -ne $original -and $original.NativeTerminalObserved) {$original.NativeExitCode} else {$null});
                    nativeEvidence=$_.Exception.Data['NativeEvidenceDirectory']; failure=$_.Exception.Message}
            }
            # Preserve the actual failed/native row before accounting or disk
            # operations. Integrity failures cannot delete or replace it.
            if (-not $row.completed -or -not $row.cleanupVerified) { $stop=$true }
        }
        $results.Add($row)
        try { Assert-TestSuiteAccounting -Inventory $Inventory -Results $results.ToArray() }
        catch { $stop=$true; $retentionFailures.Add($_.Exception) }
        try { & $RetainResults $results.ToArray() $false | Out-Null }
        catch { $stop=$true; $retentionFailures.Add($_.Exception) }
    }
    try { Assert-TestSuiteAccounting -Inventory $Inventory -Results $results.ToArray() -Complete }
    catch { $retentionFailures.Add($_.Exception) }
    # Final retention is independent of all earlier attempts. Its success
    # never substitutes for a lost earlier snapshot or a native outcome.
    try { & $RetainResults $results.ToArray() $true | Out-Null }
    catch { $retentionFailures.Add($_.Exception) }
    [pscustomobject]@{Results=$results.ToArray(); Stopped=$stop; RetentionFailures=$retentionFailures.ToArray()}
}

function Complete-TestSuiteFinalization {
    param([AllowNull()] $Candidate, [AllowNull()] [Management.Automation.ErrorRecord] $BodyError,
        [bool] $Unsafe, [Parameter(Mandatory)] [scriptblock] $PersistBlocker,
        [Parameter(Mandatory)] [scriptblock] $ObserveUnsafe, [Parameter(Mandatory)] [scriptblock] $CloseCandidate)
    $failures=[Collections.Generic.List[Exception]]::new()
    if ($null -ne $BodyError) { $failures.Add($BodyError.Exception) }
    $retainUnsafe={
        try { & $PersistBlocker | Out-Null } catch { $failures.Add($_.Exception) }
        try { & $ObserveUnsafe | Out-Null } catch { $failures.Add($_.Exception) }
    }
    # Close-TestCandidate propagates a supplied body error. Retain the suite
    # stop independently before calling it, including when retention fails.
    if ($Unsafe) { & $retainUnsafe }
    if ($null -ne $Candidate) {
        try { & $CloseCandidate $Candidate $BodyError | Out-Null }
        catch {
            if (-not $failures.Contains($_.Exception)) { $failures.Add($_.Exception) }
            if (-not $Unsafe -and (Test-QualificationCleanupUnverified -Exception $_.Exception)) {
                $Unsafe=$true
                & $retainUnsafe
            }
        }
    }
    if ($failures.Count) {
        $exception=[AggregateException]::new('Suite body, ownership and evidence failures are retained.', $failures.ToArray())
        $exception.Data['OwnedCleanupUnverified']=$Unsafe
        throw $exception
    }
}

Assert-QualificationCleanupReady
$repository=Split-Path -Parent $PSScriptRoot
Assert-TestNativeRoleReady -NativeRole TestFile -RepositoryRoot $repository
$budget=Get-GeneratedApplicationNativeBudget -TimeoutMs $TimeoutMs -CleanupReserveMs $CleanupReserveMs -AuthorityEnds $AuthorityEnds
if (-not [string]::IsNullOrEmpty($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC)) {
    $inherited=[DateTimeOffset]::ParseExact($env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC,'o',[Globalization.CultureInfo]::InvariantCulture)
    if ($inherited -lt $budget.AuthorityEnds) { $budget.AuthorityEnds=$inherited }
}
$testFiles=@(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.Tests.ps1' -File | Sort-Object Name)
if ($testFiles.Count -eq 0) { throw 'No test files were found.' }
$fullDiscovery=@($testFiles | ForEach-Object { [pscustomobject]@{file=$_.Name; path=$_.FullName; sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()} })
$scope='Full'; $focused=$null
if (-not [string]::IsNullOrEmpty($FocusedRequestPath) -or -not [string]::IsNullOrEmpty($FocusedRequestSha256)) {
    $focused=Read-FocusedTestRequest -RepositoryRoot $repository -Path $FocusedRequestPath -Sha256 $FocusedRequestSha256
    $scope=$focused.Scope
    $testFiles=@(Get-Item -LiteralPath $focused.TestPath)
}
$inventory=@($testFiles | ForEach-Object { [pscustomobject][ordered]@{file=$_.Name; path=$_.FullName;
    bytes=$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} })
$inputInventory=@(Get-TestFileInventory -RepositoryRoot $repository)
$outputRoot=Join-Path $repository '.test-output'
if ([IO.Directory]::Exists($outputRoot) -and ((Get-Item -LiteralPath $outputRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Suite evidence cannot use a redirected output root.' }
$evidenceRoot=Join-Path $repository ('.test-output/suite-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($evidenceRoot)
if (((Get-Item -LiteralPath $evidenceRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Suite evidence cannot use a reparse point.' }
$null=Set-TestNativePrivateDirectory -Path $evidenceRoot
$inventoryPath=Join-Path $evidenceRoot 'suite-inventory.json'
Write-TestNativeNewRecord -Path $inventoryPath -Value ([ordered]@{contract='win-pcinfo.test-suite-inventory/1.0.0';
    authorityEnds=$budget.AuthorityEnds.ToString('o'); scope=$scope; fullDiscovery=$fullDiscovery;
    expectedFiles=$inventory.Count; files=$inventory; inputs=$inputInventory})
$watch=[Diagnostics.Stopwatch]::StartNew()
Write-Output "EVIDENCE: $evidenceRoot"
$candidate=$null
$bodyError=$null
$suite=$null
try {
    $inputs=[Collections.Generic.List[object]]::new()
    foreach ($inputPin in $inputInventory) { $inputs.Add($inputPin) }
    . (Join-Path $PSScriptRoot 'TestHarness.ps1')
    # Standalone builds consume the same closed source/package/resource input
    # inventory as prepared candidates. Output destinations remain unique.
    $sourceInputs=@(Get-TestCandidateInputInventory -RepositoryRoot $repository)
    foreach ($inputPin in $sourceInputs) {
        $path=Join-Path $repository $inputPin.path
        if ($path -notin $inputs.path) { $inputs.Add([pscustomobject][ordered]@{path=$path; bytes=$inputPin.bytes; sha256=$inputPin.sha256}) }
    }
    if (-not [string]::IsNullOrEmpty($CandidatePath) -or -not [string]::IsNullOrEmpty($PreparedManifestPath) -or -not [string]::IsNullOrEmpty($PreparedManifestSha256)) {
        $candidate=Open-TestCandidate -RepositoryRoot $repository -CandidatePath $CandidatePath -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
        $manifest=Read-TestNativeRecord -Path $PreparedManifestPath
        foreach ($inputPin in $manifest.inputs) {
            $path=Join-Path $repository $inputPin.path
            if ($path -notin $inputs.path) { $inputs.Add([pscustomobject][ordered]@{path=$path; bytes=$inputPin.bytes; sha256=$inputPin.sha256}) }
        }
    }
    foreach ($path in @((Join-Path $PSHOME 'pwsh.exe'),$inventoryPath,$CandidatePath,$PreparedManifestPath,$FocusedRequestPath)) {
        if (-not [string]::IsNullOrEmpty($path) -and $path -notin $inputs.path) {
            $item=Get-Item -LiteralPath ([IO.Path]::GetFullPath($path))
            $inputs.Add([pscustomobject][ordered]@{path=$item.FullName; bytes=$item.Length;
                sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()})
        }
    }
    $closedInputs=@($inputs | Sort-Object path -CaseSensitive)
    $cohort=Get-TestNativeDigest -Value $closedInputs
    $invoke={
        param($Expected)
        [Console]::Out.WriteLine(('RUN: '+$Expected.file))
        $fileWatch=[Diagnostics.Stopwatch]::StartNew()
        $admission=[ordered]@{contract='win-pcinfo.test-file-admission/1.0.0'; repositoryRoot=$repository;
            testPath=$Expected.path; testSha256=$Expected.sha256; bootstrapPath=(Join-Path $PSScriptRoot 'Invoke-TestFile.ps1');
            hostPath=(Join-Path $PSHOME 'pwsh.exe'); inventoryPath=$inventoryPath; suiteEvidenceRoot=$evidenceRoot;
            candidatePath=$CandidatePath; preparedManifestPath=$PreparedManifestPath; preparedManifestSha256=$PreparedManifestSha256;
            scope=$scope; namedParameters=$(if ($null -ne $focused) {$focused.NamedParameters} else {[ordered]@{}});
            focusedRequestPath=$FocusedRequestPath; focusedRequestSha256=$FocusedRequestSha256;
            inputs=$closedInputs; cohortSha256=$cohort}
        Assert-TestFileAdmissionInputs -Admission $admission
        $native=Invoke-GeneratedApplicationNative -NativeRole TestFile -TestFileAdmission $admission -HostPath $admission.hostPath -WorkingDirectory $repository -Arguments @('-NoLogo','-NoProfile','-File',$admission.bootstrapPath) -TimeoutMs $TimeoutMs -CleanupReserveMs 10000 -AuthorityEnds $budget.AuthorityEnds.AddMilliseconds(-$CleanupReserveMs)
        try {
            $completion=Read-TestNativeRecord -Path (Join-Path $native.EvidenceDirectory 'file-result.json')
            Assert-TestFileCompletion -Completion $completion -Admission $admission -Nonce $native.Nonce -NativeOutcome $native.NativeOutcome
            Assert-TestFileAdmissionInputs -Admission $admission
        }
        catch {
            $_.Exception.Data['OriginalNativeOutcome']=$native.NativeOutcome
            $_.Exception.Data['NativeEvidenceDirectory']=$native.EvidenceDirectory
            throw
        }
        # Test streams and assertion messages remain in protected native
        # evidence. Public progress contains only file and outcome.
        [Console]::Out.WriteLine(($completion.result.ToUpperInvariant()+': '+$Expected.file))
        [ordered]@{file=$Expected.file; result=$completion.result; elapsedMilliseconds=$fileWatch.ElapsedMilliseconds;
            sha256=$Expected.sha256; nativeExitCode=$native.ExitCode; completed=$completion.completed;
            cleanupVerified=$completion.cleanupVerified; nativeEvidence=$native.EvidenceDirectory}
    }
    $retain={
        param($Rows,$Final)
        $snapshot=[ordered]@{elapsedMilliseconds=$watch.ElapsedMilliseconds; expectedFiles=$inventory.Count;
            scope=$scope; fullDiscoveryCount=$fullDiscovery.Count;
            inventorySha256=(Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256).Hash.ToLowerInvariant();
            results=@($Rows); final=[bool]$Final}
        $failures=[Collections.Generic.List[Exception]]::new()
        $names=if ($Final) {@('suite-final-summary.json','suite-summary.json')} else {@('suite-partial-summary.json','suite-summary.json')}
        foreach ($name in $names) {
            try { [IO.File]::WriteAllText((Join-Path $evidenceRoot $name),($snapshot | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false)) }
            catch { $failures.Add($_.Exception) }
        }
        if ($failures.Count) { throw [AggregateException]::new('Suite result retention failed.', $failures.ToArray()) }
    }
    $suite=Invoke-TestSuiteFiles -Inventory $inventory -InvokeFile $invoke -RetainResults $retain
    $current=@(Get-TestFileInventory -RepositoryRoot $repository)
    if ((Get-TestNativeDigest -Value $current) -cne (Get-TestNativeDigest -Value $inputInventory)) { throw 'Full test input inventory changed during execution.' }
    if ((Get-TestNativeDigest -Value @(Get-TestCandidateInputInventory -RepositoryRoot $repository)) -cne (Get-TestNativeDigest -Value $sourceInputs)) { throw 'Full source and packaged input inventory changed during execution.' }
    if ($suite.Stopped -or $suite.RetentionFailures.Count) { throw 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: suite evidence or file ownership is incomplete.' }
    $failed=@($suite.Results | Where-Object result -eq Fail)
    if ($failed.Count) { throw "$scope gate failed: $($failed.Count) of $($inventory.Count) selected files failed; all selected files executed. Evidence: $evidenceRoot" }
}
catch { $bodyError=$_ }
$unsafe=$null -ne $bodyError -and ($null -eq $suite -or $suite.Stopped -or $suite.RetentionFailures.Count -or
    $bodyError.Exception.Message -like '*inventory changed*' -or (Test-QualificationCleanupUnverified -Exception $bodyError.Exception))
Complete-TestSuiteFinalization -Candidate $candidate -BodyError $bodyError -Unsafe $unsafe -PersistBlocker {
    [IO.File]::WriteAllText((Get-QualificationCleanupBlockerPath),'{"state":"OwnedCleanupUnverified"}',[Text.UTF8Encoding]::new($false))
} -ObserveUnsafe {
    [Console]::Out.WriteLine('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED'); [Console]::Out.Flush()
} -CloseCandidate {param($Context,$Failure) Close-TestCandidate -Candidate $Context -BodyError $Failure}
if ($scope -eq 'Full') { Write-Output "PASS: $($inventory.Count) test files completed." }
else { Write-Output "PASS: $scope completed; full discovery contains $($fullDiscovery.Count) files and has not been executed by this focused run." }
