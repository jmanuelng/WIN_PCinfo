[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    Write-Output 'SKIP: Windows PowerShell host validation requires Windows.'
    return
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$windowsPowerShell = Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $windowsPowerShell
$startInfo.UseShellExecute = $false
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
foreach ($argument in @('-NoLogo', '-NoProfile', '-File', $candidatePath, '-Mode', 'Guided')) {
    $null = $startInfo.ArgumentList.Add($argument)
}

$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $startInfo
$null = $process.Start()
$stdout = $process.StandardOutput.ReadToEnd()
$stderr = $process.StandardError.ReadToEnd()
$process.WaitForExit()
$records = @($stdout -split "`r?`n" | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json -Depth 20 })

if ($process.ExitCode -ne 20) { throw "Windows PowerShell returned $($process.ExitCode) instead of 20. $stderr" }
if ($records[-1].reasonCode -ne 'RUNTIME.EDITION_UNSUPPORTED') {
    throw "Windows PowerShell did not return the stable wrong-edition reason. $stderr"
}
if ($records[-1].guidance.microsoftUrl -ne 'https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows') {
    throw 'Windows PowerShell did not return official Microsoft installation guidance.'
}
if ($records[-1].collectionStarted) { throw 'Windows PowerShell began collection before eligibility.' }

Write-Output 'PASS: generated application stopped Windows PowerShell 5.1 through the structured runtime contract.'
