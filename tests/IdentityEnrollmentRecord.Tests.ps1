[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
foreach ($source in @(
    'Contracts','ContractValidator','RuntimeCompatibility','ProcessSupervisor',
    'DeviceReadiness','FirmwareReadiness','SystemCollectionPlan','IdentityEnrollment'
)) { . (Join-Path $repositoryRoot "src/$source.ps1") }

$moduleFacts = Get-BuiltInModuleCompatibilityFacts
$devicePolicy = Get-DeviceReadinessPolicy -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand
$firmwarePolicy = Get-FirmwareReadinessPolicy -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand
$identityPolicy = Get-IdentityEnrollmentPolicy -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand
$systemPolicy = Get-SystemCollectionPlanPolicy

$deadlineRejected=$false
try {
    Invoke-IdentityEnrollmentRuleEvaluation -Rule $identityPolicy.rules[0] `
        -Inputs ([pscustomobject]@{verifiedState='ObservedValue';verifiedValue=$true}) `
        -SimulateUncooperativeRule
} catch {$deadlineRejected=$true}
Assert-Equal $true $deadlineRejected `
    'an uncooperative identity rule is terminated at its frozen deadline'
$assignmentCleanupFailure=[pscustomobject]@{
    Started=$false;CompleteOwnedTreeAbsent=$false
    FailureStage=[WinPCInfo.ProcessSupervisor.NativeFailureStage]::TerminationIncomplete
}
Assert-Equal 'IDENTITY.RULE_CLEANUP_INCOMPLETE' `
    (Get-IdentityRuleNativeFailureReason -NativeResult $assignmentCleanupFailure) `
    'failed pre-resume Job assignment with unverified termination remains CleanupIncomplete'

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
    -OperationId $devicePolicy.collector.operationId -DeviceReadinessScenario Complete
$record = New-DeviceReadinessAssessmentRecord `
    -RunId "run:identity:$([guid]::NewGuid().ToString('N'))" `
    -Evidence (ConvertTo-NormalizedDeviceReadinessEvidence -Payload $deviceCollector.PrivatePayload) `
    -CollectorResult $deviceCollector -Policy $devicePolicy -ValidationFixture $true
$record = Complete-ValidatedDeviceReadinessAssessmentRecord -ValidatedRecord $record `
    -Policy $devicePolicy -ContractValidation (Test-CanonicalRecord $record)

$now = [DateTimeOffset]::UtcNow
$firmwareCollector = [pscustomobject][ordered]@{
    state='Completed';reasonCode='FIRMWARE.COLLECTION_COMPLETED';validationFixture=$true
    envelope=[pscustomobject][ordered]@{
        startedAt=$now.AddMilliseconds(-5).ToString('o');completedAt=$now.ToString('o');attempts=1
    }
    payload=[pscustomobject][ordered]@{
        sourceLocale='und';firmwareState='Complete';firmwareType='Uefi'
        biosVersion='SYNTHETIC-UEFI-1.0';smbiosVersion='3.4'
        secureBootState='Complete';secureBootEnabled=$true;tpmState='Complete'
        tpmPresent=$true;tpmEnabled=$true;tpmActivated=$true;tpmSpecification='2.0'
    }
}
$record = Add-FirmwareReadinessEvidenceRecord -Record $record `
    -CollectorResult $firmwareCollector -Policy $firmwarePolicy
$record = Complete-ValidatedFirmwareReadinessAssessmentRecord -Record $record `
    -Policy $firmwarePolicy -ContractValidation (Test-CanonicalRecord $record)

$identityCollector = Invoke-IdentityEnrollmentCollection -Policy $identityPolicy `
    -ValidationScenario Mixed
$systemPlan = [pscustomobject][ordered]@{ recordType='synthetic-system-plan' }
$systemResult = New-SystemCollectorResult -Policy $systemPolicy -Plan $systemPlan `
    -PlanDigest 'synthetic-system-plan-digest' -State 'Completed' `
    -ReasonCode 'SYSTEM.COLLECTION_COMPLETED' -CoverageState 'Complete' `
    -ObservedExecutionContext 'Synthetic' -LocalSystemIdentityVerified $false `
    -CleanupVerified $true -TaskAbsent $true -PipeAbsent $true -WorkerTreeAbsent $true `
    -ProviderAvailable $true

$record = Add-IdentityEnrollmentEvidenceRecord -Record $record `
    -CollectorResult $identityCollector -SystemResult $systemResult -Policy $identityPolicy
$sourceValidation = Test-CanonicalRecord $record
Assert-Equal $true $sourceValidation.accepted `
    "identity and SYSTEM source observations cross the contract before rules evaluate ($($sourceValidation.reasonCode))"
Assert-Equal 7 @($record.findings).Count `
    'the identity source pass cannot fabricate findings'

$record = Complete-ValidatedIdentityEnrollmentAssessmentRecord -Record $record `
    -Policy $identityPolicy -ContractValidation $sourceValidation
$validation = Test-CanonicalRecord $record
Assert-Equal 'CONTRACT.ACCEPTED' $validation.reasonCode `
    'the combined Device, Firmware, Identity, and Enrollment record is canonical'
Assert-Equal 'profile:device-firmware-and-identity-readiness' $record.run.evidenceProfileId `
    'the record selects the exact additive evidence profile'
Assert-Equal 8 @($record.coverage).Count `
    'device, firmware, user, registration, work-school, and SYSTEM coverage remain distinct'
Assert-Equal 36 @($record.observations).Count `
    'the combined profile carries only its closed field set'
Assert-Equal 10 @($record.findings).Count `
    'three identity rules each produce exactly one additional finding'
Assert-Equal 2 @($record.subjects).Count `
    'the verified Assessment User Context is a separate package-local subject'
Assert-Equal 'Device|User' (@($record.subjects.kind) -join '|') `
    'device evidence and user-scoped evidence cannot share an identity role'

$userFinding = @($record.findings | Where-Object {
    $_.findingId -like 'finding:assessment-user-context:*'
})[0]
Assert-Equal 'ExpectedCondition' $userFinding.outcome `
    'a uniquely verified interactive session establishes the Assessment User Context'
Assert-Equal 4 @($record.recommendations | Where-Object {
    $_.kind -eq 'TenantSideDiscoveryTask'
}).Count 'local Entra and MDM evidence creates bounded tenant questions, not tenant claims'
Assert-Equal 1 @($record.coverage | Where-Object {
    $_.scopeId -eq 'scope:device.work-school-registration-context'
}).Count 'the default Entra join result remains device context, not Assessment User evidence'

$systemEnvelope = @($record.collectorResults | Where-Object {
    $_.collectorId -eq 'collector:windows.mdm-bridge.device-manageability'
})[0]
Assert-Equal 'Synthetic' $systemEnvelope.executionContext `
    'the fixture cannot claim it executed as LocalSystem'
Assert-Equal 1 @($systemEnvelope.observationIds).Count `
    'the SYSTEM envelope binds only its predefined provider-presence field'
foreach ($item in @($record.provenance | Where-Object {
    $_.fieldId -ne 'field:device.mdm-bridge.provider-available' -and
    $_.fieldId -like 'field:*assessment-user*' -or $_.fieldId -like 'field:*registration*' -or
    $_.fieldId -like 'field:device.work-school*' -or $_.fieldId -like 'field:device.domain-join*'
})) {
    if ($item.executionContext -eq 'LocalSystem') {
        throw 'SYSTEM provenance leaked onto a standard-user identity field.'
    }
}

$restrictedValues = @{
    'field:device.domain-join.name'='SYNTHETIC-DOMAIN'
    'field:device.entra-registration.device-id'='00000000-0000-4000-8000-000000000055'
    'field:device.entra-registration.tenant-id'='00000000-0000-4000-8000-000000000056'
    'field:identity.assessment-user.account-name'='SYNTHETIC\assessment-user'
}
foreach ($fieldId in $restrictedValues.Keys) {
    $observation = @($record.observations | Where-Object fieldId -eq $fieldId)[0]
    Assert-Equal $restrictedValues[$fieldId] $observation.value `
        'the canonical Restricted record retains its promised synthetic identifier'
}

Write-Output 'PASS: Identity and Enrollment compose canonical subjects, coverage, provenance, findings, and tasks.'
