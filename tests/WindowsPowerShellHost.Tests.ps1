[CmdletBinding()]
param([string] $CandidatePath, [string] $PreparedManifestPath, [string] $PreparedManifestSha256)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    Write-Output 'SKIP: Windows PowerShell host validation requires Windows.'
    return
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidatePath=$candidateContext.Path
$candidateSuccessMessages=[Collections.Generic.List[string]]::new()
$candidateUseError=$null
try {

$windowsPowerShell = Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
$result = Invoke-GeneratedApplication -CandidatePath $candidatePath -PowerShellPath $windowsPowerShell `
    -Arguments @('-Mode', 'Guided')

if ($result.ExitCode -ne 20) { throw "Windows PowerShell returned $($result.ExitCode) instead of 20. $($result.StandardError)" }
if ($result.Records[-1].reasonCode -ne 'RUNTIME.EDITION_UNSUPPORTED') {
    throw "Windows PowerShell did not return the stable wrong-edition reason. $($result.StandardError)"
}
if ($result.Records[-1].guidance.microsoftUrl -ne 'https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows') {
    throw 'Windows PowerShell did not return official Microsoft installation guidance.'
}
if ($result.Records[-1].collectionStarted) { throw 'Windows PowerShell began collection before eligibility.' }

$candidateSuccessMessages.Add('PASS: generated application stopped Windows PowerShell 5.1 through the structured runtime contract.')

}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
foreach ($candidateSuccessMessage in $candidateSuccessMessages) { Write-Output $candidateSuccessMessage }
