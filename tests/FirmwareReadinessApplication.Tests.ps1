[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$cases = @(
    @{name='firmware-supported';exit=0;outcome='Completed';firmware='Complete';secure='Complete';tpm='Complete';firmwareFinding='ExpectedCondition';secureFinding='ExpectedCondition';tpmFinding='ExpectedCondition';uac=1;tasks=0},
    @{name='firmware-disabled';exit=0;outcome='Completed';firmware='Complete';secure='Complete';tpm='Complete';firmwareFinding='ExpectedCondition';secureFinding='NeedsAttention';tpmFinding='NeedsAttention';uac=0;tasks=0},
    @{name='firmware-absent';exit=0;outcome='Completed';firmware='Complete';secure='Complete';tpm='Complete';firmwareFinding='ExpectedCondition';secureFinding='ExpectedCondition';tpmFinding='NeedsAttention';uac=0;tasks=0},
    @{name='firmware-virtual';exit=0;outcome='Completed';firmware='Complete';secure='Complete';tpm='Complete';firmwareFinding='ExpectedCondition';secureFinding='ExpectedCondition';tpmFinding='Indeterminate';uac=1;tasks=1},
    @{name='firmware-nonuefi';exit=10;outcome='CompletedWithGaps';firmware='Complete';secure='Unsupported';tpm='Complete';firmwareFinding='NeedsAttention';secureFinding='NotApplicable';tpmFinding='ExpectedCondition';uac=0;tasks=1},
    @{name='firmware-accessdenied';exit=10;outcome='CompletedWithGaps';firmware='Denied';secure='Denied';tpm='Denied';firmwareFinding='Indeterminate';secureFinding='Indeterminate';tpmFinding='Indeterminate';uac=1;tasks=0},
    @{name='firmware-unsupported';exit=10;outcome='CompletedWithGaps';firmware='Complete';secure='Unsupported';tpm='Unsupported';firmwareFinding='ExpectedCondition';secureFinding='Indeterminate';tpmFinding='Indeterminate';uac=0;tasks=1},
    @{name='firmware-malformed';exit=10;outcome='CompletedWithGaps';firmware='Malformed';secure='Malformed';tpm='Malformed';firmwareFinding='Indeterminate';secureFinding='Indeterminate';tpmFinding='Indeterminate';uac=0;tasks=0},
    @{name='firmware-timeout';exit=10;outcome='CompletedWithGaps';firmware='TimedOut';secure='TimedOut';tpm='TimedOut';firmwareFinding='Indeterminate';secureFinding='Indeterminate';tpmFinding='Indeterminate';uac=1;tasks=0},
    @{name='firmware-collectorfailure';exit=10;outcome='CompletedWithGaps';firmware='Failed';secure='Failed';tpm='Failed';firmwareFinding='Indeterminate';secureFinding='Indeterminate';tpmFinding='Indeterminate';uac=0;tasks=0}
)

foreach ($case in $cases) {
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
        '-PreparationFixturePath',$preparationPath,
        '-DeviceReadinessFixturePath',(Join-Path $PSScriptRoot "fixtures/$($case.name).json")
    )
    $validation = @($result.Records | Where-Object {
        $_.recordType -eq 'win-pcinfo.device-readiness-validation'
    })
    $terminal = @($result.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $validation.Count "$($case.name) emits one sanitized validation projection"
    Assert-Equal 1 $terminal.Count "$($case.name) emits exactly one terminal result"
    Assert-Equal $case.exit $result.ExitCode "$($case.name) uses its stable exit code"
    Assert-Equal $case.outcome $terminal[0].outcome "$($case.name) preserves the run outcome"
    Assert-Equal 'Completed' $validation[0].privilegeState `
        "$($case.name) finishes the one immutable privileged phase"
    Assert-Equal $case.uac $validation[0].privilegeUacInteractionCount `
        "$($case.name) respects the single-UAC ceiling"
    Assert-Equal $case.firmware $validation[0].firmwareCoverageState `
        "$($case.name) retains firmware coverage"
    Assert-Equal $case.secure $validation[0].secureBootCoverageState `
        "$($case.name) retains Secure Boot coverage"
    Assert-Equal $case.tpm $validation[0].tpmCoverageState `
        "$($case.name) retains TPM coverage"
    Assert-Equal $case.firmwareFinding $validation[0].firmwareFindingOutcome `
        "$($case.name) derives the bounded firmware finding"
    Assert-Equal $case.secureFinding $validation[0].secureBootFindingOutcome `
        "$($case.name) derives the bounded Secure Boot finding"
    Assert-Equal $case.tpmFinding $validation[0].tpmFindingOutcome `
        "$($case.name) derives the bounded TPM finding"
    Assert-Equal $case.tasks $validation[0].tenantDiscoveryTaskCount `
        "$($case.name) creates only the required follow-up discovery"
    Assert-Equal $false $validation[0].physicalTpmAttestationEstablished `
        "$($case.name) never turns guest-visible evidence into physical attestation"
    Assert-Equal $false $validation[0].platformSecurityStateChanged `
        "$($case.name) remains observational"
    Assert-Equal $true $validation[0].assessmentRecordValidated `
        "$($case.name) packages only an accepted canonical record"
    Assert-Equal $true $validation[0].beginnerReportVerified `
        "$($case.name) carries beginner firmware guidance"
    Assert-Equal $true $validation[0].protectedPackageVerified `
        "$($case.name) reopens and validates its encrypted package"
    Assert-Equal $true $validation[0].validationCleanupVerified `
        "$($case.name) proves package, worker, channel, and staging residue absent"
    if ($result.StandardError) { throw "$($case.name) wrote stderr: $($result.StandardError)" }
}

Write-Output 'PASS: the generated application exercises all ten firmware, Secure Boot, and TPM states.'
