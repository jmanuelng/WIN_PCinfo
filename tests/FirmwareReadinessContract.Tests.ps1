[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
foreach ($source in @(
    'Contracts','ContractValidator','RuntimeCompatibility','ProcessSupervisor',
    'DeviceReadiness','FirmwareReadiness'
)) { . (Join-Path $repositoryRoot "src/$source.ps1") }

$moduleFacts = Get-BuiltInModuleCompatibilityFacts
$devicePolicy = Get-DeviceReadinessPolicy `
    -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand
$firmwarePolicy = Get-FirmwareReadinessPolicy `
    -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand

function Test-CanonicalRecord {
    param($Record)
    [byte[]]$bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Record | ConvertTo-Json -Compress -Depth 30)
    )
    Test-AssessmentContract -Utf8Bytes $bytes `
        -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand `
        -TestJsonCommand $moduleFacts.testJsonCommand
}

$deviceCollector = Invoke-ApprovedCollectorProcess `
    -OperationId $devicePolicy.collector.operationId `
    -DeviceReadinessScenario Complete
$deviceEvidence = ConvertTo-NormalizedDeviceReadinessEvidence `
    -Payload $deviceCollector.PrivatePayload
$record = New-DeviceReadinessAssessmentRecord `
    -RunId "run:firmware:$([guid]::NewGuid().ToString('N'))" `
    -Evidence $deviceEvidence -CollectorResult $deviceCollector `
    -Policy $devicePolicy -ValidationFixture $true
$deviceValidation = Test-CanonicalRecord $record
$record = Complete-ValidatedDeviceReadinessAssessmentRecord `
    -ValidatedRecord $record -Policy $devicePolicy `
    -ContractValidation $deviceValidation
Assert-Equal $true (Test-CanonicalRecord $record).accepted `
    'the prerequisite Device Context record is accepted before firmware composition'

$completedAt = [DateTimeOffset]::UtcNow
$firmwareCollector = [pscustomobject][ordered]@{
    state = 'Completed'
    reasonCode = 'FIRMWARE.COLLECTION_COMPLETED'
    validationFixture = $true
    envelope = [pscustomobject][ordered]@{
        startedAt = $completedAt.AddMilliseconds(-5).ToString('o')
        completedAt = $completedAt.ToString('o')
        attempts = 1
    }
    payload = [pscustomobject][ordered]@{
        sourceLocale = 'und'
        firmwareState = 'Complete'
        firmwareType = 'Uefi'
        biosVersion = 'SYNTHETIC-UEFI-1.0'
        smbiosVersion = '3.4'
        secureBootState = 'Complete'
        secureBootEnabled = $true
        tpmState = 'Complete'
        tpmPresent = $true
        tpmEnabled = $true
        tpmActivated = $true
        tpmSpecification = '1.2, 2.0'
    }
}

$record = Add-FirmwareReadinessEvidenceRecord -Record $record `
    -CollectorResult $firmwareCollector -Policy $firmwarePolicy
$firmwareSourceValidation = Test-CanonicalRecord $record
Assert-Equal $true $firmwareSourceValidation.accepted `
    'privileged source observations cross the contract before firmware rules evaluate'
Assert-Equal 4 @($record.findings).Count `
    'the firmware source pass cannot fabricate a firmware-security finding'
Assert-Equal 'CONTRACT.ACCEPTED' $firmwareSourceValidation.reasonCode `
    'the firmware source pass retains the stable accepted reason'
$record = Complete-ValidatedFirmwareReadinessAssessmentRecord -Record $record `
    -Policy $firmwarePolicy -ContractValidation $firmwareSourceValidation
$validation = Test-CanonicalRecord $record
Assert-Equal $true $validation.accepted `
    'the combined Device and Firmware Readiness record crosses the release contract'
Assert-Equal 'profile:device-and-firmware-readiness' $record.run.evidenceProfileId `
    'the record declares the exact combined release profile'
Assert-Equal 4 @($record.coverage).Count `
    'Device Context, firmware, Secure Boot, and TPM coverage remain independent'
Assert-Equal 'Complete|Complete|Complete|Complete' `
    (@($record.coverage.state) -join '|') `
    'the supported fixture closes every expected field without a gap'
Assert-Equal 25 @($record.observations).Count `
    'the combined profile carries seventeen device and eight firmware-security observations'
Assert-Equal 7 @($record.findings).Count `
    'the three firmware-security rules each add exactly one finding'
Assert-Equal 7 @($record.findings.ruleId | Sort-Object -Unique).Count `
    'one Rule Evaluation cannot masquerade as multiple findings'
Assert-Equal 'ExpectedCondition|ExpectedCondition|ExpectedCondition' (
    @($record.findings | Where-Object {
        $_.findingId -match '^finding:(firmware-context|secure-boot-readiness|tpm-readiness):'
    } |
        ForEach-Object outcome) -join '|'
) 'supported structured evidence produces three bounded advisory outcomes'

$virtualRecord = $record | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
$virtualObservation = @($virtualRecord.observations | Where-Object {
    $_.fieldId -eq 'field:device.virtualization.detected'
})[0]
$virtualObservation.value = $true
$virtualRecord.findings = @($virtualRecord.findings | Where-Object {
    $_.findingId -notlike 'finding:firmware-context:*' -and
    $_.findingId -notlike 'finding:secure-boot-readiness:*' -and
    $_.findingId -notlike 'finding:tpm-readiness:*'
})
$virtualRecord.recommendations = @()
Assert-Equal 4 @($virtualRecord.findings).Count `
    'the virtual rule probe starts from the four device-context findings'
$virtualRecord = Complete-ValidatedFirmwareReadinessAssessmentRecord -Record $virtualRecord `
    -Policy $firmwarePolicy -ContractValidation $firmwareSourceValidation
$virtualValidation = Test-CanonicalRecord $virtualRecord
Assert-Equal 'CONTRACT.ACCEPTED' $virtualValidation.reasonCode `
    'the bounded physical-attestation task remains part of a valid canonical record'
$virtualReport = [Text.UTF8Encoding]::new($false,$true).GetString(
    (New-DeviceReadinessReportBytes -Record $virtualRecord -FirmwarePolicy $firmwarePolicy)
)
if (-not $virtualReport.Contains('EndpointSecurityOrHardwareOwner') -or
    -not $virtualReport.Contains('AuthorizedTenantOrOEMManagementBoundary') -or
    -not $virtualReport.Contains('without exporting TPM secrets')) {
    throw 'The beginner report omitted actionable, bounded physical-attestation follow-up.'
}
$unknownTpmRecord = $record | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
$unknownTpmRecord.findings = @($unknownTpmRecord.findings | Where-Object {
    $_.findingId -notlike 'finding:firmware-context:*' -and
    $_.findingId -notlike 'finding:secure-boot-readiness:*' -and
    $_.findingId -notlike 'finding:tpm-readiness:*'
})
$unknownTpmRecord.recommendations = @()
$specObservation = @($unknownTpmRecord.observations | Where-Object {
    $_.fieldId -eq 'field:device.tpm.specification'
})[0]
$specObservation.valueState = 'SourceReportedUnknown'
$specObservation.PSObject.Properties.Remove('value')
$unknownTpmValidation = Test-CanonicalRecord $unknownTpmRecord
Assert-Equal $true $unknownTpmValidation.accepted `
    'a successfully examined but unknown TPM specification remains valid evidence'
Assert-Equal 4 @($unknownTpmRecord.findings).Count `
    'the unknown TPM probe starts from the four device-context findings'
$unknownTpmRecord = Complete-ValidatedFirmwareReadinessAssessmentRecord `
    -Record $unknownTpmRecord -Policy $firmwarePolicy `
    -ContractValidation $unknownTpmValidation
$unknownTpmFinding = @($unknownTpmRecord.findings | Where-Object {
    $_.findingId -like 'finding:tpm-readiness:*'
})[0]
Assert-Equal 'Indeterminate' $unknownTpmFinding.outcome `
    'unknown TPM detail cannot become a negative readiness finding'

$firmwareEnvelope = @($record.collectorResults | Where-Object {
    $_.collectorId -eq 'collector:windows.firmware-security'
})
Assert-Equal 1 $firmwareEnvelope.Count `
    'the exact privileged collector attempt has one honest result envelope'
Assert-Equal 'Synthetic' $firmwareEnvelope[0].executionContext `
    'the unelevated fixture never pretends it exercised an Administrator token'
Assert-Equal 8 @($firmwareEnvelope[0].observationIds).Count `
    'the envelope binds only its closed eight-field result'
foreach ($item in @($record.provenance | Where-Object {
    $_.collectorId -eq 'collector:windows.firmware-security'
})) {
    Assert-Equal 'Synthetic' $item.executionContext `
        'every fixture provenance item records the actual synthetic context'
}
if (($record | ConvertTo-Json -Compress -Depth 30) -match
    '(?i)ownerAuthorization|endorsementSecret|privateKey|recoveryData|serialNumber') {
    throw 'The canonical record contains prohibited TPM secret or unbounded identity material.'
}

foreach ($case in @(
    @{reason='FIRMWARE.PRIVILEGE_TIMED_OUT';outcome='TimedOut';exit=40},
    @{reason='FIRMWARE.PRIVILEGE_CANCELLED';outcome='Cancelled';exit=30},
    @{reason='FIRMWARE.PRIVILEGE_CLEANUP_INCOMPLETE';outcome='CleanupIncomplete';exit=60}
)) {
    $disposition = Get-DeviceReadinessFailureDisposition `
        -ReasonCode $case.reason -CollectionStarted $true
    Assert-Equal $case.outcome $disposition.outcome `
        'privilege lifecycle failures retain their distinct terminal outcome'
    Assert-Equal $case.exit $disposition.exitCode `
        'privilege lifecycle failures retain their stable exit code'
}

Write-Output 'PASS: Firmware Readiness composes closed observations, coverage, provenance, and findings.'
