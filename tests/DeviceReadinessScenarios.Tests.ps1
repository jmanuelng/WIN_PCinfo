[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$cases = @(
    @{scenario='Partial';exit=10;terminal='CompletedWithGaps';coverage='Partial';finding='Indeterminate';record=$true;package=$true},
    @{scenario='Unavailable';exit=10;terminal='CompletedWithGaps';coverage='Unavailable';finding='Indeterminate';record=$true;package=$true},
    @{scenario='Malformed';exit=10;terminal='CompletedWithGaps';coverage='Malformed';finding='Indeterminate';record=$true;package=$true},
    @{scenario='Oversize';exit=10;terminal='CompletedWithGaps';coverage='Unavailable';finding='Indeterminate';record=$true;package=$true},
    @{scenario='Virtual';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';record=$true;package=$true},
    @{scenario='Unicode';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';record=$true;package=$true},
    @{scenario='NonEnglish';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';record=$true;package=$true}
)
$validationRoot = Join-Path (Split-Path -Parent $candidatePath) '.device-readiness-validation'
foreach ($case in $cases) {
    $name = [string]$case.scenario
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode','Automation','-RequestPath',(Join-Path $PSScriptRoot 'fixtures/automation-request.json'),
        '-AcceptPreparation','-PreparationFixturePath',(Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'),
        '-DeviceReadinessFixturePath',(Join-Path $PSScriptRoot "fixtures/device-$($name.ToLowerInvariant()).json")
    )
    $record = @($result.Records | Where-Object recordType -eq 'win-pcinfo.device-readiness-validation')
    $terminal = @($result.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $record.Count "$name emits one sanitized validation record"
    Assert-Equal 1 $terminal.Count "$name emits one terminal record"
    Assert-Equal $case.exit $result.ExitCode "$name uses the stable lifecycle exit code"
    Assert-Equal $case.terminal $terminal[0].outcome "$name has an honest terminal outcome"
    Assert-Equal $case.coverage $record[0].coverageState "$name reports explicit coverage"
    Assert-Equal $case.finding $record[0].findingOutcome "$name gates the readiness rule on evidence"
    Assert-Equal $case.record $record[0].assessmentRecordValidated "$name record availability is honest"
    Assert-Equal $case.record $record[0].beginnerReportVerified "$name report availability is honest"
    Assert-Equal $case.package $record[0].protectedPackageVerified "$name package availability is honest"
    Assert-Equal $true $record[0].validationCleanupVerified "$name verifies exact cleanup"
    Assert-Equal $false ([System.IO.Directory]::Exists($validationRoot)) "$name leaves no validation root"
    if ($result.StandardOutput -match '(?i)Fabrikam|Model-48|Synthetic Processor|Microsoft Corporation|Virtual Machine|Modèle|Processeur') {
        throw "$name leaked Restricted Diagnostic Evidence into public output."
    }
    if ($result.StandardError) { throw "$name wrote stderr: $($result.StandardError)" }
}

Write-Output 'PASS: all eight generated Device Readiness scenarios preserve evidence, privacy, and cleanup semantics.'
