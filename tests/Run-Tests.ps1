[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$testFiles = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.Tests.ps1' -File | Sort-Object Name)
if ($testFiles.Count -eq 0) {
    throw 'No test files were found.'
}

foreach ($testFile in $testFiles) {
    Write-Output "RUN: $($testFile.Name)"
    & $testFile.FullName
}

Write-Output "PASS: $($testFiles.Count) test files completed."
