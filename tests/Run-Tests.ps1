[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')
Assert-QualificationCleanupReady

# Generated-application tests inherit this console. A default Windows OEM
# 437 code page fails the documented UTF-8 contract with
# RUNTIME.ENCODING_INCOMPATIBLE, so the independent Sandcastle gate and a
# local `pwsh -File ./tests/Run-Tests.ps1` look like product regressions.
# Set the host encoding before any test file runs.
try {
    $null = cmd /c "chcp 65001 >NUL"
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
    $global:OutputEncoding = [System.Text.UTF8Encoding]::new($false)
}
catch {
    Write-Output 'WARN: could not switch the test host to UTF-8; generated-application tests may fail closed.'
}

$testFiles = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.Tests.ps1' -File | Sort-Object Name)
if ($testFiles.Count -eq 0) {
    throw 'No test files were found.'
}

$evidenceRoot = Join-Path (Split-Path $PSScriptRoot) ('.test-output/suite-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($evidenceRoot)
$previousEvidenceRoot = $env:WINPCINFO_TEST_EVIDENCE
$env:WINPCINFO_TEST_EVIDENCE = $evidenceRoot
$suiteResults = [Collections.Generic.List[object]]::new()
$suiteWatch = [Diagnostics.Stopwatch]::StartNew()
Write-Output "EVIDENCE: $evidenceRoot"
try {
    foreach ($testFile in $testFiles) {
        Write-Output "RUN: $($testFile.Name)"
        $fileWatch = [Diagnostics.Stopwatch]::StartNew()
        $fileResult = 'Pass'
        try { & $testFile.FullName }
        catch {
            $fileResult = 'Fail'
            Write-Output "FAIL: $($testFile.Name): $($_.Exception.Message)"
        }
        $suiteResults.Add([ordered]@{ file=$testFile.Name; result=$fileResult;
            elapsedMilliseconds=$fileWatch.ElapsedMilliseconds;
            sha256=(Get-FileHash -LiteralPath $testFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant() })
        $cleanupBlocked=[IO.File]::Exists((Get-QualificationCleanupBlockerPath))
        if ($cleanupBlocked) {
            foreach ($unexecuted in $testFiles | Select-Object -Skip $suiteResults.Count) {
                $suiteResults.Add([ordered]@{file=$unexecuted.Name; result='Blocked'; elapsedMilliseconds=0;
                    sha256=(Get-FileHash -LiteralPath $unexecuted.FullName -Algorithm SHA256).Hash.ToLowerInvariant()})
            }
        }
        [IO.File]::WriteAllText((Join-Path $evidenceRoot 'suite-summary.json'),
            ([ordered]@{ elapsedMilliseconds=$suiteWatch.ElapsedMilliseconds; expectedFiles=$testFiles.Count;
                results=$suiteResults.ToArray() } | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
        if ($cleanupBlocked) { throw 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: remaining test files were blocked and preserved in the inventory.' }
    }
}
finally { $env:WINPCINFO_TEST_EVIDENCE = $previousEvidenceRoot }
$failedFiles = @($suiteResults | Where-Object result -eq Fail)
if ($failedFiles.Count) { throw "Full gate failed: $($failedFiles.Count) of $($testFiles.Count) files failed; all files executed. Evidence: $evidenceRoot" }
Write-Output "PASS: $($testFiles.Count) test files completed."
