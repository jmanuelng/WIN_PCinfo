[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
foreach ($source in @(
    'Contracts','ContractValidator','RuntimeCompatibility','ProcessSupervisor','DeviceReadiness',
    'FirmwareReadiness','SystemCollectionPlan','IdentityEnrollment','AdministratorExposure'
)) { . (Join-Path $repositoryRoot "src/$source.ps1") }

$moduleFacts = Get-BuiltInModuleCompatibilityFacts
$devicePolicy = Get-DeviceReadinessPolicy -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand
$firmwarePolicy = Get-FirmwareReadinessPolicy -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand
$identityPolicy = Get-IdentityEnrollmentPolicy -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand
$administratorPolicy = Get-AdministratorExposurePolicy -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand
$systemPolicy = Get-SystemCollectionPlanPolicy

function Test-CanonicalRecord {
    param($Record)
    [byte[]]$bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Record | ConvertTo-Json -Compress -Depth 30)
    )
    Test-AssessmentContract -Utf8Bytes $bytes `
        -ConvertFromJsonCommand $moduleFacts.convertFromJsonCommand `
        -TestJsonCommand $moduleFacts.testJsonCommand
}

function New-IdentityReadyRecord {
    $deviceCollector = Invoke-ApprovedCollectorProcess `
        -OperationId $devicePolicy.collector.operationId -DeviceReadinessScenario Complete
    $record = New-DeviceReadinessAssessmentRecord `
        -RunId "run:administrator:$([guid]::NewGuid().ToString('N'))" `
        -Evidence (ConvertTo-NormalizedDeviceReadinessEvidence -Payload $deviceCollector.PrivatePayload) `
        -CollectorResult $deviceCollector -Policy $devicePolicy -ValidationFixture $true
    $record = Complete-ValidatedDeviceReadinessAssessmentRecord -ValidatedRecord $record `
        -Policy $devicePolicy -ContractValidation (Test-CanonicalRecord $record)
    $now=[DateTimeOffset]::UtcNow
    $firmwareCollector=[pscustomobject][ordered]@{
        state='Completed';reasonCode='FIRMWARE.COLLECTION_COMPLETED';validationFixture=$true
        envelope=[pscustomobject][ordered]@{startedAt=$now.AddMilliseconds(-5).ToString('o');completedAt=$now.ToString('o');attempts=1}
        payload=[pscustomobject][ordered]@{
            sourceLocale='und';firmwareState='Complete';firmwareType='Uefi';biosVersion='SYNTHETIC-UEFI-1.0';smbiosVersion='3.4'
            secureBootState='Complete';secureBootEnabled=$true;tpmState='Complete';tpmPresent=$true;tpmEnabled=$true;tpmActivated=$true;tpmSpecification='2.0'
        }
    }
    $record=Add-FirmwareReadinessEvidenceRecord -Record $record -CollectorResult $firmwareCollector -Policy $firmwarePolicy
    $record=Complete-ValidatedFirmwareReadinessAssessmentRecord -Record $record -Policy $firmwarePolicy `
        -ContractValidation (Test-CanonicalRecord $record)
    $identityCollector=Invoke-IdentityEnrollmentCollection -Policy $identityPolicy -ValidationScenario Mixed
    $systemResult=New-SystemCollectorResult -Policy $systemPolicy -Plan ([pscustomobject]@{recordType='synthetic-system-plan'}) `
        -PlanDigest 'synthetic-system-plan-digest' -State Completed -ReasonCode 'SYSTEM.COLLECTION_COMPLETED' `
        -CoverageState Complete -ObservedExecutionContext Synthetic -LocalSystemIdentityVerified $false `
        -CleanupVerified $true -TaskAbsent $true -PipeAbsent $true -WorkerTreeAbsent $true -ProviderAvailable $true
    $record=Add-IdentityEnrollmentEvidenceRecord -Record $record -CollectorResult $identityCollector `
        -SystemResult $systemResult -Policy $identityPolicy
    $record=Complete-ValidatedIdentityEnrollmentAssessmentRecord -Record $record -Policy $identityPolicy `
        -ContractValidation (Test-CanonicalRecord $record)
    $record
}

$record=New-IdentityReadyRecord
$collector=Invoke-AdministratorExposureCollection -Policy $administratorPolicy -ValidationScenario NestedGroup
$record=Add-AdministratorExposureEvidenceRecord -Record $record -CollectorResult $collector -Policy $administratorPolicy
$sourceValidation=Test-CanonicalRecord $record
Assert-Equal $true $sourceValidation.accepted `
    "direct privileged membership crosses the canonical contract before interpretation ($($sourceValidation.reasonCode))"
Assert-Equal 10 @($record.findings).Count 'source admission cannot fabricate the administrator finding'

$record=Complete-ValidatedAdministratorExposureAssessmentRecord -Record $record `
    -Policy $administratorPolicy -ContractValidation $sourceValidation
$validation=Test-CanonicalRecord $record
Assert-Equal 'CONTRACT.ACCEPTED' $validation.reasonCode `
    'the combined Device, Firmware, Identity, Enrollment, and Administrator record is canonical'
Assert-Equal 'profile:device-firmware-identity-and-administrator-readiness' $record.run.evidenceProfileId `
    'the record selects the exact additive evidence profile'
Assert-Equal 9 @($record.coverage).Count 'administrator coverage remains distinct'
Assert-Equal 4 @($record.subjects).Count 'each direct principal is a separate package-local subject'
Assert-Equal 'Device|User|SecurityPrincipal|SecurityPrincipal' (@($record.subjects.kind) -join '|') `
    'membership relationships retain typed principal subjects'
Assert-Equal 'subject:security-principal:0|subject:security-principal:1' `
    (@($record.subjects|Where-Object kind -eq SecurityPrincipal|ForEach-Object subjectId) -join '|') `
    'principal graph identities are package-local positions, not cross-run SID derivatives'
Assert-Equal 11 @($record.findings).Count 'one bounded rule produces exactly one finding'

$coverage=@($record.coverage|Where-Object scopeId -eq 'scope:device.local-administrators.direct-membership')[0]
Assert-Equal 'Complete' $coverage.state 'complete enumeration remains distinct from empty membership'
$finding=@($record.findings|Where-Object findingId -like 'finding:local-administrator-exposure:*')[0]
Assert-Equal 'Informational' $finding.outcome `
    'observed direct membership is advisory and does not declare compromise'
Assert-Equal $false ($record.recommendations.Count -gt 0 -and @($record.recommendations|Where-Object {
    $_.definitionId -match '(?i)remove|disable'
}).Count -gt 0) 'the rule never performs or recommends automatic removal'

$memberEnvelopes=@($record.collectorResults|Where-Object collectorId -eq 'collector:windows.local-administrators.direct-members')
Assert-Equal 1 $memberEnvelopes.Count 'one approved collector attempt owns membership evidence'
Assert-Equal 'Synthetic' $memberEnvelopes[0].executionContext 'the fixture never claims real elevation'
Assert-Equal 2 @($record.subjects|Where-Object kind -eq SecurityPrincipal).Count `
    'nested membership is not expanded into guessed effective principals'

$denied=New-IdentityReadyRecord
$deniedCollector=Invoke-AdministratorExposureCollection -Policy $administratorPolicy -ValidationScenario Denied
$denied=Add-AdministratorExposureEvidenceRecord -Record $denied -CollectorResult $deniedCollector -Policy $administratorPolicy
$deniedSource=Test-CanonicalRecord $denied
Assert-Equal $true $deniedSource.accepted 'denied enumeration remains a valid source-wide gap'
$denied=Complete-ValidatedAdministratorExposureAssessmentRecord -Record $denied -Policy $administratorPolicy `
    -ContractValidation $deniedSource
Assert-Equal 'Denied' (@($denied.coverage|Where-Object scopeId -like 'scope:device.local-administrators*')[0].state) `
    'denied enumeration is never reported as an empty Administrators group'
Assert-Equal 'Indeterminate' (@($denied.findings|Where-Object findingId -like 'finding:local-administrator*')[0].outcome) `
    'denied evidence cannot become a negative conclusion'
Assert-Equal 0 @($denied.observations|Where-Object {
    $_.fieldId -like 'field:*local-administrator*' -or $_.fieldId -like 'field:principal*'
}).Count `
    'source-wide denial fabricates no observations or identities'

Write-Output 'PASS: Administrator Exposure composes canonical direct membership, coverage, subjects, and bounded interpretation.'
