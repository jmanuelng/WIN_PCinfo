[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
foreach ($source in @('Contracts','ContractValidator','RuntimeCompatibility','ProcessSupervisor',
    'EvidenceWorkspace','ProtectedPackage','DeviceReadiness')) {
    . (Join-Path $repositoryRoot "src/$source.ps1")
}
$moduleFacts = Get-BuiltInModuleCompatibilityFacts
$policy = Get-DeviceReadinessPolicy -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand

function Test-ReadinessRecord {
    param($Record)
    [byte[]]$bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Record | ConvertTo-Json -Compress -Depth 30)
    )
    Test-AssessmentContract -Utf8Bytes $bytes `
        -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand `
        -TestJsonCommand $moduleFacts.testJsonCommand
}

$collector = Invoke-ApprovedCollectorProcess -OperationId $policy.collector.operationId `
    -DeviceReadinessScenario Complete
$evidence = ConvertTo-NormalizedDeviceReadinessEvidence -Payload $collector.PrivatePayload
$record = New-DeviceReadinessAssessmentRecord `
    -RunId "run:device:$([guid]::NewGuid().ToString('N'))" -Evidence $evidence `
    -CollectorResult $collector -Policy $policy -ValidationFixture $true
$sourceValidation = Test-ReadinessRecord $record
Assert-Equal $true $sourceValidation.accepted `
    'source observations cross the contract before any readiness rule evaluates'
Assert-Equal 'Indeterminate' $record.findings[0].outcome `
    'the pre-validation record cannot contain a success or negative readiness claim'
$record = Complete-ValidatedDeviceReadinessAssessmentRecord -ValidatedRecord $record `
    -Policy $policy -ContractValidation $sourceValidation
$finalValidation = Test-ReadinessRecord $record
Assert-Equal $true $finalValidation.accepted 'the derived final record crosses the contract a second time'
Assert-Equal 'ExpectedCondition' $record.findings[0].outcome `
    'only validated complete source observations can support the advisory success'

$missingField = $record | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
$removed = @($missingField.observations | Where-Object fieldId -eq 'field:device.manufacturer')[0]
$missingField.observations = @($missingField.observations | Where-Object observationId -ne $removed.observationId)
$missingField.provenance = @($missingField.provenance | Where-Object provenanceId -ne $removed.provenanceId)
$missingField.coverage[0].observationIds = @($missingField.coverage[0].observationIds |
    Where-Object { $_ -ne $removed.observationId })
$missingField.collectorResults[0].observationIds = @(
    $missingField.collectorResults[0].observationIds | Where-Object { $_ -ne $removed.observationId }
)
$missingValidation = Test-ReadinessRecord $missingField
Assert-Equal 'CONTRACT.COVERAGE_INCONSISTENT' $missingValidation.reasonCode `
    'Complete coverage requires the exact eight-field Device Readiness profile'

$partialCollector = Invoke-ApprovedCollectorProcess -OperationId $policy.collector.operationId `
    -DeviceReadinessScenario Partial
$partialEvidence = ConvertTo-NormalizedDeviceReadinessEvidence -Payload $partialCollector.PrivatePayload
$partialRecord = New-DeviceReadinessAssessmentRecord `
    -RunId "run:device:$([guid]::NewGuid().ToString('N'))" -Evidence $partialEvidence `
    -CollectorResult $partialCollector -Policy $policy -ValidationFixture $true
$partialSourceValidation = Test-ReadinessRecord $partialRecord
$partialRecord = Complete-ValidatedDeviceReadinessAssessmentRecord -ValidatedRecord $partialRecord `
    -Policy $policy -ContractValidation $partialSourceValidation
Assert-Equal 'Indeterminate' $partialRecord.findings[0].outcome `
    'missing memory evidence cannot create a negative or successful claim'

foreach ($case in @(
    @{started=$false;reason='PROCESS.SUPERVISOR_FAILED';outcome='NotStarted';exit=20},
    @{started=$true;reason='PROCESS.DEADLINE_EXCEEDED';outcome='TimedOut';exit=40},
    @{started=$true;reason='PROCESS.CANCELLED_HARD';outcome='Cancelled';exit=30},
    @{started=$true;reason='PROCESS.TERMINATION_INCOMPLETE';outcome='CleanupIncomplete';exit=60},
    @{started=$true;reason='PROCESS.SUPERVISOR_FAILED';outcome='IntegrityFailed';exit=50}
)) {
    $disposition = Get-DeviceReadinessNoPayloadDisposition -Supervision ([pscustomobject]@{
        processStarted=$case.started; reasonCode=$case.reason
    }) -ValidationFixture $false
    Assert-Equal $false $disposition.buildCanonicalRecord `
        "$($case.reason) cannot create a report or package without evidence"
    Assert-Equal $case.outcome $disposition.outcome "$($case.reason) retains its lifecycle outcome"
    Assert-Equal $case.exit $disposition.exitCode "$($case.reason) retains its stable exit code"
}

foreach ($scenario in @('Malformed','Oversize')) {
    $prelaunch = Get-DeviceReadinessNoPayloadDisposition -Supervision ([pscustomobject]@{
        processStarted=$false; reasonCode='PROCESS.EXECUTABLE_IDENTITY_INVALID'
    }) -ValidationFixture $true -Scenario $scenario
    Assert-Equal $false $prelaunch.buildCanonicalRecord `
        "$scenario cannot override a genuine pre-launch failure"
    Assert-Equal 'NotStarted' $prelaunch.outcome `
        "$scenario preserves the safe pre-launch default"
}

$malformedAttempt = Get-DeviceReadinessNoPayloadDisposition -Supervision ([pscustomobject]@{
    processStarted=$true; reasonCode='PROCESS.PAYLOAD_MALFORMED'
}) -ValidationFixture $true -Scenario Malformed
Assert-Equal $true $malformedAttempt.buildCanonicalRecord `
    'the release-owned malformed attempt may produce a typed gap record'

$unavailableCollector = Invoke-ApprovedCollectorProcess -OperationId $policy.collector.operationId `
    -DeviceReadinessScenario Unavailable
$unavailableEvidence = [pscustomobject]@{sourceLocale='und'}
$unavailableRecord = New-DeviceReadinessAssessmentRecord `
    -RunId "run:device:$([guid]::NewGuid().ToString('N'))" -Evidence $unavailableEvidence `
    -CollectorResult $unavailableCollector -Policy $policy -ValidationFixture $true `
    -CoverageStateOverride Unavailable -CoverageReasonCode COLLECTION.SOURCE_UNAVAILABLE
Assert-Equal 0 @($unavailableRecord.observations).Count `
    'a source-wide failure fabricates no field observation'
Assert-Equal 0 @($unavailableRecord.provenance).Count `
    'a source-wide failure fabricates no field provenance'
$unavailableValidation = Test-ReadinessRecord $unavailableRecord
Assert-Equal $true $unavailableValidation.accepted `
    'coverage, diagnostics, and the collector envelope carry source-wide failure evidence'

Write-Output 'PASS: Device Readiness validates source observations before rules and enforces exact field closure.'
