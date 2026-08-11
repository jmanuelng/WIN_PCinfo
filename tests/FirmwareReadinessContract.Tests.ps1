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

Write-Output 'PASS: Firmware Readiness composes closed observations, coverage, provenance, and findings.'
