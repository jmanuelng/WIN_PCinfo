[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

foreach ($testFile in $testFiles) {
    Write-Output "RUN: $($testFile.Name)"
    & $testFile.FullName
}

Write-Output "PASS: $($testFiles.Count) test files completed."
