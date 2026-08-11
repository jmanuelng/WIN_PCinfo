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

$validationRoot = Join-Path (Split-Path -Parent $candidatePath) '.device-readiness-validation'
if ([System.IO.Directory]::Exists($validationRoot)) {
    $preexisting = @([System.IO.Directory]::EnumerateFileSystemEntries($validationRoot))
    if ($preexisting.Count -gt 0) {
        throw 'Device Readiness validation found pre-existing residue and refused to delete it.'
    }
    [System.IO.Directory]::Delete($validationRoot)
}

$result = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
    '-Mode', 'Automation', '-RequestPath', $requestPath, '-AcceptPreparation',
    '-PreparationFixturePath', $preparationPath,
    '-DeviceReadinessFixturePath', (Join-Path $PSScriptRoot 'fixtures/device-complete.json')
)
$records = @($result.Records | Where-Object `
    recordType -eq 'win-pcinfo.device-readiness-validation')
$terminals = @($result.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
$summary = @($result.Records | Where-Object recordType -eq 'win-pcinfo.preparation-summary')[0]

Assert-Equal 1 $records.Count 'Complete emits one sanitized Device Readiness result'
Assert-Equal 1 $terminals.Count 'Complete emits one terminal result'
Assert-Equal 0 $result.ExitCode 'Complete uses the stable Completed exit code'
Assert-Equal 'Completed' $terminals[0].outcome 'Complete reaches one honest terminal outcome'
Assert-Equal $summary.requestDigest $terminals[0].requestDigest `
    'the terminal remains bound to the accepted request'
Assert-Equal $summary.planDigest $terminals[0].planDigest `
    'the terminal remains bound to the immutable Preparation Plan'
Assert-Equal 'Accepted' $terminals[0].preparationDecision `
    'post-approval execution preserves the accepted preparation decision'
Assert-Equal 'Complete' $records[0].scenario 'the release-owned fixture identity is preserved'
Assert-Equal 'Complete' $records[0].coverageState 'all expected device evidence is explicit'
Assert-Equal 'ExpectedCondition' $records[0].findingOutcome `
    'validated complete observations can support the advisory readiness finding'
Assert-Equal 'Activated' $records[0].activationContext `
    'Windows activation context is represented without a product key or entitlement claim'
Assert-Equal 'NotDetected' $records[0].virtualizationContext `
    'absence of a virtual signal is explicit without claiming the device is physically verified'
Assert-Equal 'Desktop' $records[0].formFactor `
    'structured chassis and system-type evidence supports the desktop form classification'
Assert-Equal 'Absent' $records[0].batteryPresence `
    'a completed physical fixture represents the observed absence of a battery explicitly'
Assert-Equal $false $records[0].physicalClaimsAllowed `
    'the preview never promotes context evidence into physical firmware, TPM, OEM, or performance claims'
Assert-Equal $true $records[0].assessmentRecordValidated `
    'the canonical typed Assessment Record passes exact contract validation'
Assert-Equal $true $records[0].beginnerReportVerified `
    'the derived report starts with outcome and progressively discloses provenance'
Assert-Equal $true $records[0].protectedPackageVerified `
    'the report and canonical record end in a reopened Protected Evidence Package'
Assert-Equal $true $records[0].validationCleanupVerified `
    'the generated application removes every test-owned workspace and package'
Assert-Equal $false ([System.IO.Directory]::Exists($validationRoot)) `
    'the generated application leaves no Device Readiness validation root'
if ($result.StandardOutput -match '(?i)Fabrikam|Model-4[89]|Synthetic Processor|product.?key|entitlement|purchase') {
    throw 'Restricted synthetic device-identifying values entered public progress or validation output.'
}
if ($result.StandardError) { throw "Complete wrote stderr: $($result.StandardError)" }

Write-Output 'PASS: the generated application completes the Device and Windows readiness slice.'
