[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$cases = @(
    @{scenario='Partial';exit=10;terminal='CompletedWithGaps';coverage='Partial';finding='Indeterminate';activation='Unknown';virtual='NotDetected';form='Desktop';battery='Absent'},
    @{scenario='Unavailable';exit=10;terminal='CompletedWithGaps';coverage='Unavailable';finding='Indeterminate';activation='Unknown';virtual='Unknown';form='Unknown';battery='Unknown'},
    @{scenario='Malformed';exit=10;terminal='CompletedWithGaps';coverage='Malformed';finding='Indeterminate';activation='Unknown';virtual='Unknown';form='Unknown';battery='Unknown'},
    @{scenario='Oversize';exit=10;terminal='CompletedWithGaps';coverage='Unavailable';finding='Indeterminate';activation='Unknown';virtual='Unknown';form='Unknown';battery='Unknown'},
    @{scenario='Virtual';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';activation='Activated';virtual='Detected';form='Virtual';battery='Absent';platformFinding='Informational'},
    @{scenario='Unicode';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';activation='Activated';virtual='NotDetected';form='Desktop';battery='Absent'},
    @{scenario='NonEnglish';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';activation='Activated';virtual='NotDetected';form='Desktop';battery='Absent'},
    @{scenario='Activated';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';activation='Activated';virtual='NotDetected';form='Desktop';battery='Absent'},
    @{scenario='Physical';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';activation='Activated';virtual='NotDetected';form='Desktop';battery='Absent';platformFinding='Indeterminate'},
    @{scenario='Desktop';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';activation='Activated';virtual='NotDetected';form='Desktop';battery='Absent'},
    @{scenario='BatteryAbsent';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';activation='Activated';virtual='NotDetected';form='Desktop';battery='Absent'},
    @{scenario='Unactivated';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';activation='NotActivated';virtual='NotDetected';form='Desktop';battery='Absent';activationFinding='NeedsAttention'},
    @{scenario='Laptop';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';activation='Activated';virtual='NotDetected';form='Laptop';battery='Absent'},
    @{scenario='BatteryPresent';exit=0;terminal='Completed';coverage='Complete';finding='ExpectedCondition';activation='Activated';virtual='NotDetected';form='Laptop';battery='Present';powerFinding='Informational'},
    @{scenario='BatteryUnavailable';exit=10;terminal='CompletedWithGaps';coverage='Partial';finding='ExpectedCondition';activation='Activated';virtual='NotDetected';form='Desktop';battery='Unknown'},
    @{scenario='Denied';exit=10;terminal='CompletedWithGaps';coverage='Partial';finding='ExpectedCondition';activation='Unknown';virtual='NotDetected';form='Desktop';battery='Unknown';accessDiagnostics='COLLECTION.ACTIVATION_ACCESS_DENIED|COLLECTION.BATTERY_ACCESS_DENIED|COLLECTION.CHASSIS_ACCESS_DENIED'},
    @{scenario='ProhibitedMaterial';exit=10;terminal='CompletedWithGaps';coverage='ProhibitedMaterialBlocked';finding='Indeterminate';activation='Unknown';virtual='Unknown';form='Unknown';battery='Unknown'}
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
    Assert-Equal $case.activation $record[0].activationContext "$name reports bounded activation context"
    Assert-Equal $case.virtual $record[0].virtualizationContext "$name reports bounded virtualization context"
    Assert-Equal $case.form $record[0].formFactor "$name reports bounded form context"
    Assert-Equal $case.battery $record[0].batteryPresence "$name reports bounded battery context"
    if ($case.ContainsKey('activationFinding')) {
        Assert-Equal $case.activationFinding $record[0].activationFindingOutcome `
            "$name emits the evidence-referenced activation finding"
    }
    if ($case.ContainsKey('platformFinding')) {
        Assert-Equal $case.platformFinding $record[0].platformFindingOutcome `
            "$name distinguishes virtual evidence from an unproven physical classification"
    }
    if ($case.ContainsKey('powerFinding')) {
        Assert-Equal $case.powerFinding $record[0].powerFindingOutcome `
            "$name emits the evidence-referenced power finding"
    }
    if ($case.ContainsKey('accessDiagnostics')) {
        Assert-Equal $case.accessDiagnostics $record[0].sourceAccessDiagnostics `
            "$name preserves per-source access denial through the generated application"
    }
    Assert-Equal $false $record[0].physicalClaimsAllowed "$name cannot authorize physical-device claims"
    Assert-Equal $true $record[0].assessmentRecordValidated "$name record availability is honest"
    Assert-Equal $true $record[0].beginnerReportVerified "$name report availability is honest"
    Assert-Equal $true $record[0].protectedPackageVerified "$name package availability is honest"
    Assert-Equal $true $record[0].validationCleanupVerified "$name verifies exact cleanup"
    Assert-Equal $false ([System.IO.Directory]::Exists($validationRoot)) "$name leaves no validation root"
    if ($result.StandardOutput -match '(?i)Fabrikam|Model-4[89]|Synthetic Processor|Microsoft Corporation|Virtual Machine|Modèle|Processeur|synthetic-prohibited-marker|partial.?product.?key') {
        throw "$name leaked Restricted Diagnostic Evidence into public output."
    }
    if ($result.StandardError) { throw "$name wrote stderr: $($result.StandardError)" }
}

Write-Output 'PASS: all generated device-context scenarios preserve evidence, privacy, advisory limits, and cleanup semantics.'
