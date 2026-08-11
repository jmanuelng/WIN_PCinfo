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

$cleanupIncompletePackage = [pscustomobject]@{
    state = 'CleanupIncomplete'; verified = $false; packagePath = $null
}
$cleanupDisposition = Get-DeviceReadinessPackageDisposition `
    -Package $cleanupIncompletePackage -ValidationFixture $false `
    -ValidationCleanupVerified $true
Assert-Equal 'Uncertain' $cleanupDisposition.packageAvailability `
    'typed package cleanup failure is never mislabeled VerifiedAbsent'
Assert-Equal 'CleanupIncomplete' $cleanupDisposition.outcome `
    'typed package cleanup failure preserves the cleanup terminal outcome'
Assert-Equal 60 $cleanupDisposition.exitCode `
    'typed package cleanup failure preserves the stable cleanup exit code'

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
Assert-Equal 0 @($record.findings).Count `
    'the source-observation pass contains no finding before rule evaluation'
Assert-Equal 0 @($record.observations | Where-Object fieldId -in @(
    'field:device.virtualization.detected','field:device.form-factor'
)).Count 'pending classifier outputs are not fabricated as source-reported unknown observations'
Assert-Equal 15 @($record.observations).Count `
    'the source pass carries only the fifteen fields actually examined before derivation'
Assert-Equal 1 @($record.collectorResults).Count `
    'the source pass has only the honest completed Windows collector envelope'
$record = Complete-ValidatedDeviceReadinessAssessmentRecord -ValidatedRecord $record `
    -Policy $policy -ContractValidation $sourceValidation
$finalValidation = Test-ReadinessRecord $record
Assert-Equal $true $finalValidation.accepted 'the derived final record crosses the contract a second time'
Assert-Equal 'ExpectedCondition' $record.findings[0].outcome `
    'only validated complete source observations can support the advisory success'
Assert-Equal 4 @($record.findings).Count `
    'the release rule emits readiness, activation, platform, and power findings'
Assert-Equal 4 @($record.findings.ruleId | Sort-Object -Unique).Count `
    'each Rule Evaluation produces exactly one canonical Assessment Finding'
$activationFinding = @($record.findings | Where-Object findingId -like 'finding:activation-context:*')[0]
$platformFinding = @($record.findings | Where-Object findingId -like 'finding:platform-context:*')[0]
$powerFinding = @($record.findings | Where-Object findingId -like 'finding:power-context:*')[0]
Assert-Equal 'ExpectedCondition' $activationFinding.outcome `
    'validated activated evidence supports only the bounded activation finding'
Assert-Equal 'Indeterminate' $platformFinding.outcome `
    'absence of a virtual signal never becomes a physical-device finding'
Assert-Equal 'FINDING.PHYSICAL_DEVICE_NOT_ESTABLISHED' $platformFinding.reasonCode `
    'the physical fixture preserves the advisory classification limit'
Assert-Equal 'Informational' $powerFinding.outcome `
    'validated battery absence supports an informational power-context finding'
Assert-Equal 1 @($activationFinding.evidenceReferences).Count `
    'the activation finding references its exact admitted observation'
if (@($platformFinding.evidenceReferences.fieldId | Where-Object {
    $_ -notin @('field:device.manufacturer','field:device.model',
        'field:device.virtualization.detected','field:device.system-type-code',
        'field:device.chassis.type-codes','field:device.form-factor')
}).Count -gt 0) {
    throw 'The platform finding widened beyond its release-owned evidence.'
}
Assert-Equal 17 @($record.observations).Count `
    'the expanded device-context scope closes over exactly seventeen bounded fields'
$derivedObservations = @($record.observations | Where-Object fieldId -in @(
    'field:device.virtualization.detected','field:device.form-factor'
))
Assert-Equal 2 $derivedObservations.Count `
    'the classifiers append their two derived observations only after the source contract pass'
Assert-Equal 3 @($record.collectorResults).Count `
    'each approved classifier attempt has its own result envelope after the Windows collector'
$windowsEnvelope = @($record.collectorResults | Where-Object {
    $_.collectorId -eq 'collector:windows.device-context'
})[0]
$classifierEnvelopes = @($record.collectorResults | Where-Object {
    $_.collectorId -eq 'collector:win-pcinfo.device-context-classifier'
})
Assert-Equal 15 @($windowsEnvelope.observationIds).Count `
    'the completed Windows envelope is never rewritten with later classifier output'
Assert-Equal 2 $classifierEnvelopes.Count `
    'virtualization and form classifiers are two separately timed approved attempts'
Assert-Equal 1 @($classifierEnvelopes[0].observationIds).Count `
    'each classifier envelope owns exactly one derived observation'
Assert-Equal 1 @($classifierEnvelopes[1].observationIds).Count `
    'each classifier envelope owns exactly one derived observation'
foreach ($classifierEnvelope in $classifierEnvelopes) {
    Assert-Equal 'InProcessValidatedAssessmentRecord' ([string]$classifierEnvelope.executionContext) `
        'classifier envelopes retain their frozen and actual in-process context'
    if ([DateTimeOffset]::Parse([string]$classifierEnvelope.startedAt) -lt
        [DateTimeOffset]::Parse([string]$windowsEnvelope.completedAt)) {
        throw 'A classifier attempt was backdated into the completed Windows collector interval.'
    }
    $derivedId = [string]$classifierEnvelope.observationIds[0]
    $derivedObservation = @($record.observations | Where-Object observationId -eq $derivedId)[0]
    $derivedProvenance = @($record.provenance | Where-Object {
        $_.provenanceId -eq $derivedObservation.provenanceId
    })[0]
    Assert-Equal ([string]$classifierEnvelope.completedAt) ([string]$derivedProvenance.collectedAt) `
        'derived provenance uses its actual classifier completion time'
    Assert-Equal 'InProcessValidatedAssessmentRecord' ([string]$derivedProvenance.executionContext) `
        'derived provenance retains the classifier context rather than the source process context'
}
Assert-Equal 2 @($record.provenance | Where-Object {
    $_.collectorId -eq 'collector:win-pcinfo.device-context-classifier'
}).Count 'derived provenance identifies the actual in-process classifier'
$activation = @($record.observations | Where-Object {
    $_.fieldId -eq 'field:device.windows.activation-state'
})[0]
Assert-Equal 'Activated' $activation.value `
    'the complete fixture carries only the normalized Windows activation state'
foreach ($batteryField in @('field:device.battery.status',
    'field:device.battery.charge-percent',
    'field:device.battery.estimated-runtime-minutes')) {
    $batteryObservation = @($record.observations | Where-Object fieldId -eq $batteryField)[0]
    Assert-Equal 'ObservedAbsent' $batteryObservation.valueState `
        'battery detail is explicit absence when the bounded source reports no battery'
}
if (@($record.observations.fieldId | Where-Object {
    [string]$_ -match '(?i)(product.?key|license.?key|private.?key|secret|token)'
}).Count -gt 0) {
    throw 'A prohibited key-like field crossed the observation admission boundary.'
}

$missingField = $record | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
$removed = @($missingField.observations | Where-Object fieldId -eq 'field:device.manufacturer')[0]
$missingField.observations = @($missingField.observations | Where-Object observationId -ne $removed.observationId)
$missingField.provenance = @($missingField.provenance | Where-Object provenanceId -ne $removed.provenanceId)
$missingField.coverage[0].observationIds = @($missingField.coverage[0].observationIds |
    Where-Object { $_ -ne $removed.observationId })
$missingField.collectorResults[0].observationIds = @(
    $missingField.collectorResults[0].observationIds | Where-Object { $_ -ne $removed.observationId }
)
foreach ($candidateFinding in @($missingField.findings)) {
    $candidateFinding.evidenceReferences = @($candidateFinding.evidenceReferences |
        Where-Object observationId -ne $removed.observationId)
}
$missingValidation = Test-ReadinessRecord $missingField
Assert-Equal 'CONTRACT.COVERAGE_INCONSISTENT' $missingValidation.reasonCode `
    'Complete coverage requires the exact seventeen-field device-context profile'

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

$batteryUnavailableCollector = Invoke-ApprovedCollectorProcess `
    -OperationId $policy.collector.operationId -DeviceReadinessScenario BatteryUnavailable
$batteryUnavailableEvidence = ConvertTo-NormalizedDeviceReadinessEvidence `
    -Payload $batteryUnavailableCollector.PrivatePayload
$batteryUnavailableRecord = New-DeviceReadinessAssessmentRecord `
    -RunId "run:device:$([guid]::NewGuid().ToString('N'))" `
    -Evidence $batteryUnavailableEvidence -CollectorResult $batteryUnavailableCollector `
    -Policy $policy -ValidationFixture $true
Assert-Equal 0 @($batteryUnavailableRecord.observations | Where-Object {
    $_.fieldId -like 'field:device.battery.*'
}).Count 'an inaccessible battery source fabricates no battery observation'
Assert-Equal 0 @($batteryUnavailableRecord.provenance | Where-Object {
    $_.sourceId -eq 'source:windows.cim.battery'
}).Count 'an inaccessible battery source fabricates no battery provenance'

$deniedCollector = Invoke-ApprovedCollectorProcess -OperationId $policy.collector.operationId `
    -DeviceReadinessScenario Denied
$deniedEvidence = ConvertTo-NormalizedDeviceReadinessEvidence -Payload $deniedCollector.PrivatePayload
$deniedRecord = New-DeviceReadinessAssessmentRecord `
    -RunId "run:device:$([guid]::NewGuid().ToString('N'))" -Evidence $deniedEvidence `
    -CollectorResult $deniedCollector -Policy $policy -ValidationFixture $true
$deniedReasons = @($deniedRecord.diagnostics.reasonCode | Sort-Object)
Assert-Equal 3 $deniedReasons.Count `
    'each denied source is represented independently in the canonical record'
Assert-Equal (@(
    'COLLECTION.ACTIVATION_ACCESS_DENIED',
    'COLLECTION.BATTERY_ACCESS_DENIED',
    'COLLECTION.CHASSIS_ACCESS_DENIED'
) -join '|') ($deniedReasons -join '|') `
    'denial remains distinct from ordinary source unavailability'
$deniedValidation = Test-ReadinessRecord $deniedRecord
Assert-Equal $true $deniedValidation.accepted `
    'per-source denial diagnostics retain closed coverage references'

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
$unavailableEvidence = [pscustomobject]@{
    sourceLocale='und';manufacturer=$null;model=$null;processorName=$null
    memoryBytes=$null;windowsEdition=$null;build=$null;architecture=$null
    activationState=$null;activationAvailability='Unavailable';systemTypeCode=$null
    hypervisorPresent=$null;chassisTypeCodes=$null;chassisAvailability='Unavailable'
    virtualizationDetected=$null;formFactor=$null;batteryAvailability='Unavailable'
    batteryPresence=$null;batteryStatus=$null;batteryChargePercent=$null
    batteryRuntimeMinutes=$null
}
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

$blockedCollector = Invoke-ApprovedCollectorProcess -OperationId $policy.collector.operationId `
    -DeviceReadinessScenario ProhibitedMaterial
Assert-Equal 'PROCESS.PROHIBITED_MATERIAL_BLOCKED' $blockedCollector.Supervision.reasonCode `
    'a key-like output field is rejected before a private payload can be admitted'
if ($blockedCollector.PSObject.Properties['PrivatePayload']) {
    throw 'The prohibited-material process result retained its rejected payload.'
}
$blockedEvidence = $unavailableEvidence
$blockedRecord = New-DeviceReadinessAssessmentRecord `
    -RunId "run:device:$([guid]::NewGuid().ToString('N'))" -Evidence $blockedEvidence `
    -CollectorResult $blockedCollector -Policy $policy -ValidationFixture $true `
    -CoverageStateOverride ProhibitedMaterialBlocked `
    -CoverageReasonCode COLLECTION.PROHIBITED_MATERIAL_BLOCKED
Assert-Equal 0 @($blockedRecord.observations).Count `
    'blocked material creates no observation, including no key-shaped placeholder'
Assert-Equal $false $blockedRecord.diagnostics[0].prohibitedMaterial.retained `
    'the typed diagnostic proves the rejected material was not retained'
Assert-Equal $false $blockedRecord.diagnostics[0].prohibitedMaterial.hashed `
    'the typed diagnostic proves the rejected material was not hashed'
$blockedValidation = Test-ReadinessRecord $blockedRecord
Assert-Equal $true $blockedValidation.accepted `
    'the no-value prohibited-material record retains closed references and coverage'

Write-Output 'PASS: Device Readiness validates source observations before rules and enforces exact field closure.'
