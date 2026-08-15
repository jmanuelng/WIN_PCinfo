[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
foreach($source in @(
    'Contracts','ContractValidator','RuntimeCompatibility','ProcessSupervisor','DeviceReadiness',
    'FirmwareReadiness','SystemCollectionPlan','IdentityEnrollment','AdministratorExposure','EffectivePolicy'
)){. (Join-Path $repositoryRoot "src/$source.ps1")}

$facts=Get-BuiltInModuleCompatibilityFacts
$devicePolicy=Get-DeviceReadinessPolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand
$firmwarePolicy=Get-FirmwareReadinessPolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand
$identityPolicy=Get-IdentityEnrollmentPolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand
$administratorPolicy=Get-AdministratorExposurePolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand
$effectivePolicy=Get-EffectivePolicyPolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand
$systemPolicy=Get-SystemCollectionPlanPolicy

function Test-CanonicalRecord($Record){
    [byte[]]$bytes=[Text.UTF8Encoding]::new($false).GetBytes(
        ($Record|ConvertTo-Json -Compress -Depth 30)
    )
    Test-AssessmentContract -Utf8Bytes $bytes `
        -ConvertFromJsonCommand $facts.convertFromJsonCommand `
        -TestJsonCommand $facts.testJsonCommand
}

function New-AdministratorReadyRecord {
    $deviceCollector=Invoke-ApprovedCollectorProcess -OperationId $devicePolicy.collector.operationId `
        -DeviceReadinessScenario Complete
    $record=New-DeviceReadinessAssessmentRecord -RunId "run:policy:$([guid]::NewGuid().ToString('N'))" `
        -Evidence (ConvertTo-NormalizedDeviceReadinessEvidence -Payload $deviceCollector.PrivatePayload) `
        -CollectorResult $deviceCollector -Policy $devicePolicy -ValidationFixture $true
    $record=Complete-ValidatedDeviceReadinessAssessmentRecord -ValidatedRecord $record `
        -Policy $devicePolicy -ContractValidation (Test-CanonicalRecord $record)
    $now=[DateTimeOffset]::UtcNow
    $firmware=[pscustomobject][ordered]@{
        state='Completed';reasonCode='FIRMWARE.COLLECTION_COMPLETED';validationFixture=$true
        envelope=[pscustomobject][ordered]@{startedAt=$now.AddMilliseconds(-5).ToString('o');completedAt=$now.ToString('o');attempts=1}
        payload=[pscustomobject][ordered]@{sourceLocale='und';firmwareState='Complete';firmwareType='Uefi';biosVersion='SYNTHETIC-UEFI-1.0';smbiosVersion='3.4';secureBootState='Complete';secureBootEnabled=$true;tpmState='Complete';tpmPresent=$true;tpmEnabled=$true;tpmActivated=$true;tpmSpecification='2.0'}
    }
    $record=Add-FirmwareReadinessEvidenceRecord -Record $record -CollectorResult $firmware -Policy $firmwarePolicy
    $record=Complete-ValidatedFirmwareReadinessAssessmentRecord -Record $record -Policy $firmwarePolicy `
        -ContractValidation (Test-CanonicalRecord $record)
    $identity=Invoke-IdentityEnrollmentCollection -Policy $identityPolicy -ValidationScenario Mixed
    $system=New-SystemCollectorResult -Policy $systemPolicy -Plan ([pscustomobject]@{recordType='synthetic-system-plan'}) `
        -PlanDigest 'synthetic-system-plan-digest' -State Completed -ReasonCode 'SYSTEM.COLLECTION_COMPLETED' `
        -CoverageState Complete -ObservedExecutionContext Synthetic -LocalSystemIdentityVerified $false `
        -CleanupVerified $true -TaskAbsent $true -PipeAbsent $true -WorkerTreeAbsent $true -ProviderAvailable $true
    $record=Add-IdentityEnrollmentEvidenceRecord -Record $record -CollectorResult $identity -SystemResult $system -Policy $identityPolicy
    $record=Complete-ValidatedIdentityEnrollmentAssessmentRecord -Record $record -Policy $identityPolicy `
        -ContractValidation (Test-CanonicalRecord $record)
    $administrator=Invoke-AdministratorExposureCollection -Policy $administratorPolicy -ValidationScenario NestedGroup
    $record=Add-AdministratorExposureEvidenceRecord -Record $record -CollectorResult $administrator -Policy $administratorPolicy
    Complete-ValidatedAdministratorExposureAssessmentRecord -Record $record -Policy $administratorPolicy `
        -ContractValidation (Test-CanonicalRecord $record)
}

$record=New-AdministratorReadyRecord
$collector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario UserAndComputerRsop
$record=Add-EffectivePolicyEvidenceRecord -Record $record -CollectorResult $collector -Policy $effectivePolicy
$sourceValidation=Test-CanonicalRecord $record
Assert-Equal $true $sourceValidation.accepted `
    "the three policy layers cross the canonical contract before interpretation ($($sourceValidation.reasonCode))"
Assert-Equal 11 @($record.findings).Count 'source admission cannot fabricate policy findings'

$record=Complete-ValidatedEffectivePolicyAssessmentRecord -Record $record -Policy $effectivePolicy `
    -ContractValidation $sourceValidation
$validation=Test-CanonicalRecord $record
Assert-Equal 'CONTRACT.ACCEPTED' $validation.reasonCode `
    'the combined Device, Firmware, Identity, Administrator, and Effective Policy record is canonical'
Assert-Equal '1.0.0' $record.contractVersion `
    'the record shape remains backward-compatible while Contract Set 1.4 adds policy definitions'
Assert-Equal 'profile:device-firmware-identity-administrator-and-policy-readiness' $record.run.evidenceProfileId `
    'the record selects the exact additive policy evidence profile'
Assert-Equal 63 @($record.coverage).Count 'all fifty-four policy scopes remain independently closed'
Assert-Equal 18 @($record.findings).Count 'seven bounded rules each produce one finding'
Assert-Equal 1 @($record.collectorResults|Where-Object collectorId -eq 'collector:windows.effective-policy').Count `
    'one approved attempt owns all policy source coverage'
Assert-Equal 'Informational' (@($record.findings|Where-Object ruleId -eq 'rule:policy.applied-policy-coverage/1.0.0')[0].outcome) `
    'complete cached RSoP produces an informational coverage finding'

$workgroup=New-AdministratorReadyRecord
$workgroupCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario Workgroup
$workgroup=Add-EffectivePolicyEvidenceRecord -Record $workgroup -CollectorResult $workgroupCollector -Policy $effectivePolicy
$absentLinks=@($workgroup.observations|Where-Object {
    $_.fieldId -eq 'field:policy.applied.link-id' -and $_.valueState -eq 'ObservedAbsent' -and
        $_.subjectId -like 'subject:policy-object:*'
})
Assert-Equal 1 $absentLinks.Count 'a genuinely absent enabled link is ObservedAbsent, never a sentinel string'

$absentOptions=New-AdministratorReadyRecord
$absentOptionsCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario Workgroup
$absentOptionsCollector.payload.securityOptions[0].value=$null
$absentOptionsCollector.payload.securityOptions[1].value=$null
$absentOptions=Add-EffectivePolicyEvidenceRecord -Record $absentOptions `
    -CollectorResult $absentOptionsCollector -Policy $effectivePolicy
foreach($fieldId in @(
    'field:policy.security-option.machine-inactivity-limit-seconds',
    'field:policy.security-option.disable-cad'
)){
    $observation=@($absentOptions.observations|Where-Object fieldId -eq $fieldId)[0]
    Assert-Equal 'ObservedAbsent' $observation.valueState `
        "a missing optional registry signal remains canonical ObservedAbsent for $fieldId"
    if($observation.PSObject.Properties['value']){
        throw "ObservedAbsent must not carry a fabricated value for $fieldId."
    }
}

$conflict=New-AdministratorReadyRecord
$conflictCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario AppliedOrderConflict
$conflict=Add-EffectivePolicyEvidenceRecord -Record $conflict -CollectorResult $conflictCollector -Policy $effectivePolicy
$conflict=Complete-ValidatedEffectivePolicyAssessmentRecord -Record $conflict -Policy $effectivePolicy `
    -ContractValidation (Test-CanonicalRecord $conflict)
Assert-Equal 'NeedsAttention' (@($conflict.findings|Where-Object ruleId -eq 'rule:policy.applied-order-conflict/1.0.0')[0].outcome) `
    'observed competing precedence becomes an advisory conflict finding'

$crossTarget=New-AdministratorReadyRecord
$crossTargetCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario UserAndComputerRsop
$sharedObject='6ac1786c-016f-11d2-945f-00c04fb984f9'
$sharedSetting='registry:44444444-4444-4444-8444-444444444444'
$crossTargetCollector.payload.appliedPolicies[0].objectId=$sharedObject
$crossTargetCollector.payload.appliedPolicies[1].objectId=$sharedObject
$crossTargetCollector.payload.policySettings[0].objectId=$sharedObject
$crossTargetCollector.payload.policySettings[0].settingId=$sharedSetting
$crossTargetCollector.payload.policySettings[1].objectId=$sharedObject
$crossTargetCollector.payload.policySettings[1].settingId=$sharedSetting
$crossTarget=Add-EffectivePolicyEvidenceRecord -Record $crossTarget `
    -CollectorResult $crossTargetCollector -Policy $effectivePolicy
$crossTarget=Complete-ValidatedEffectivePolicyAssessmentRecord -Record $crossTarget `
    -Policy $effectivePolicy -ContractValidation (Test-CanonicalRecord $crossTarget)
$crossTargetSubjects=@($crossTarget.subjects|Where-Object kind -eq PolicyObject)
Assert-Equal 3 $crossTargetSubjects.Count `
    'one policy object applied to user and computer remains two target-specific subjects'
Assert-Equal 'ExpectedCondition' (@($crossTarget.findings|Where-Object ruleId -eq 'rule:policy.applied-order-conflict/1.0.0')[0].outcome) `
    'the same setting in user and computer policy does not fabricate a precedence conflict'

$missing=New-AdministratorReadyRecord
$missingCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario MissingRsop
$missing=Add-EffectivePolicyEvidenceRecord -Record $missing -CollectorResult $missingCollector -Policy $effectivePolicy
$missing=Complete-ValidatedEffectivePolicyAssessmentRecord -Record $missing -Policy $effectivePolicy `
    -ContractValidation (Test-CanonicalRecord $missing)
Assert-Equal 'Indeterminate' (@($missing.findings|Where-Object ruleId -eq 'rule:policy.applied-policy-coverage/1.0.0')[0].outcome) `
    'a missing RSoP namespace cannot become proof that no policy applied'
Assert-Equal 0 @($missing.observations|Where-Object fieldId -like 'field:policy.applied.*').Count `
    'source-wide RSoP failure fabricates no applied-policy observations'

$systemProvenanceRecord=New-AdministratorReadyRecord
$systemProvenanceCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy `
    -ValidationScenario MdmWinsOverGpScoped
$systemEnvelope=@($systemProvenanceRecord.collectorResults|Where-Object {
    $_.collectorId -eq 'collector:windows.mdm-bridge.device-manageability'
})[0]
$missingEnvelopeRejected=$false
try {
    Add-EffectivePolicyEvidenceRecord -Record $systemProvenanceRecord `
        -CollectorResult $systemProvenanceCollector -Policy $effectivePolicy `
        -SystemResult ([pscustomobject]@{
            PrivatePolicyCspResults=New-EffectivePolicySyntheticPolicyCspResults `
                -Scenario MdmWinsOverGpScoped
        }) | Out-Null
}
catch {$missingEnvelopeRejected=$_.Exception.Message -match 'exact SYSTEM attempt'}
Assert-Equal $true $missingEnvelopeRejected `
    'restricted Policy CSP results cannot fall back to an unrelated record envelope'

foreach($identityMutation in @(
    @{property='envelopeId';value='envelope:system:different'},
    @{property='collectorVersion';value='9.9.9'},
    @{property='attempts';value=2}
)) {
    $mismatchedEnvelope=$systemEnvelope|ConvertTo-Json -Depth 10|ConvertFrom-Json -Depth 10
    $mismatchedEnvelope.($identityMutation.property)=$identityMutation.value
    $mismatchRejected=$false
    try {
        Add-EffectivePolicyEvidenceRecord -Record $systemProvenanceRecord `
            -CollectorResult $systemProvenanceCollector -Policy $effectivePolicy `
            -SystemResult ([pscustomobject]@{
                PrivatePolicyCspResults=New-EffectivePolicySyntheticPolicyCspResults `
                    -Scenario MdmWinsOverGpScoped
                collectorResult=[pscustomobject]@{Envelope=$mismatchedEnvelope}
            }) | Out-Null
    }
    catch {$mismatchRejected=$_.Exception.Message -match 'different SYSTEM attempt'}
    Assert-Equal $true $mismatchRejected `
        "SYSTEM attempt identity includes $($identityMutation.property)"
}
$systemProvenanceResult=[pscustomobject]@{
    PrivatePolicyCspResults=New-EffectivePolicySyntheticPolicyCspResults `
        -Scenario MdmWinsOverGpScoped
    collectorResult=[pscustomobject]@{Envelope=$systemEnvelope}
}
$systemProvenanceRecord=Add-EffectivePolicyEvidenceRecord -Record $systemProvenanceRecord `
    -CollectorResult $systemProvenanceCollector -Policy $effectivePolicy `
    -SystemResult $systemProvenanceResult
$mdmObservation=@($systemProvenanceRecord.observations|Where-Object `
    fieldId -eq 'field:policy.mdm.control-policy-conflict.mdm-wins-over-gp')[0]
$mdmProvenance=@($systemProvenanceRecord.provenance|Where-Object `
    provenanceId -eq $mdmObservation.provenanceId)[0]
Assert-Equal 'collector:windows.mdm-bridge.device-manageability' $mdmProvenance.collectorId `
    'Policy CSP values retain their originating SYSTEM collector provenance'
Assert-Equal 'Synthetic' $mdmProvenance.executionContext `
    'synthetic SYSTEM evidence never claims Administrator or live LocalSystem execution'
$mdmEnvelope=@($systemProvenanceRecord.collectorResults|Where-Object {
    $_.operationId -eq 'op:windows.mdm-bridge.device-manageability' -and
    $mdmObservation.observationId -in @($_.observationIds)
})
Assert-Equal 1 $mdmEnvelope.Count `
    'the SYSTEM Policy CSP observation is owned by one matching collector envelope'
Assert-Equal 0 @($systemProvenanceRecord.collectorResults|Where-Object {
    $_.collectorId -eq 'collector:windows.effective-policy' -and
    $mdmObservation.observationId -in @($_.observationIds)
}).Count 'the Administrator Effective Policy envelope cannot claim SYSTEM observations'
Assert-Equal 1 @($systemProvenanceRecord.collectorResults|Where-Object {
    $_.collectorId -eq 'collector:windows.mdm-bridge.device-manageability'
}).Count 'one approved SYSTEM attempt remains one collector envelope after policy composition'

$nonMdm=New-AdministratorReadyRecord
@($nonMdm.observations|Where-Object `
    fieldId -eq 'field:device.mdm-bridge.provider-available')[0].value=$false
$nonMdmCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario NonMdm
$nonMdmEnvelope=@($nonMdm.collectorResults|Where-Object {
    $_.collectorId -eq 'collector:windows.mdm-bridge.device-manageability'
})[0]
$nonMdmSystem=[pscustomobject]@{
    PrivatePolicyCspResults=New-EffectivePolicySyntheticPolicyCspResults -Scenario NonMdm
    collectorResult=[pscustomobject]@{Envelope=$nonMdmEnvelope}
}
$nonMdm=Add-EffectivePolicyEvidenceRecord -Record $nonMdm `
    -CollectorResult $nonMdmCollector -Policy $effectivePolicy -SystemResult $nonMdmSystem
$nonMdm=Complete-ValidatedEffectivePolicyAssessmentRecord -Record $nonMdm `
    -Policy $effectivePolicy -ContractValidation (Test-CanonicalRecord $nonMdm)
Assert-Equal 'Indeterminate' (@($nonMdm.findings|Where-Object `
    ruleId -eq 'rule:policy.mdm-policy-csp-coverage/1.0.0')[0].outcome) `
    'an absent MDM provider remains incomplete source coverage'
Assert-Equal 2 @($nonMdm.recommendations|Where-Object {
    $_.kind -eq 'TenantSideDiscoveryTask' -and
    $_.definitionId -in @($effectivePolicy.discoveryTasks.definitionId)
}).Count `
    'an absent MDM provider emits the two frozen tenant-side discovery tasks'

$partialRecord=New-AdministratorReadyRecord
$partialCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario PartialChannel
$partialRecord=Add-EffectivePolicyEvidenceRecord -Record $partialRecord -CollectorResult $partialCollector -Policy $effectivePolicy
$partialValidation=Test-CanonicalRecord $partialRecord
Assert-Equal $true $partialValidation.accepted `
    "field-specific failures and bounded overflow remain canonical ($($partialValidation.reasonCode))"

$tamperRecord=New-AdministratorReadyRecord
$tamperCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario TamperProtected
$tamperRecord=Add-EffectivePolicyEvidenceRecord -Record $tamperRecord -CollectorResult $tamperCollector -Policy $effectivePolicy
$tamperRecord=Complete-ValidatedEffectivePolicyAssessmentRecord -Record $tamperRecord -Policy $effectivePolicy `
    -ContractValidation (Test-CanonicalRecord $tamperRecord)
Assert-Equal 'ExpectedCondition' (@($tamperRecord.findings|Where-Object `
    ruleId -eq 'rule:policy.security-control-constraint/1.0.0')[0].outcome) `
    'tamper protection is reported as a bounded security-control constraint'

$bitLockerRecord=New-AdministratorReadyRecord
$bitLockerCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario BitLockerEncrypted
$bitLockerRecord=Add-EffectivePolicyEvidenceRecord -Record $bitLockerRecord -CollectorResult $bitLockerCollector -Policy $effectivePolicy
$bitLockerRecord=Complete-ValidatedEffectivePolicyAssessmentRecord -Record $bitLockerRecord -Policy $effectivePolicy `
    -ContractValidation (Test-CanonicalRecord $bitLockerRecord)
Assert-Equal 'ExpectedCondition' (@($bitLockerRecord.findings|Where-Object `
    ruleId -eq 'rule:policy.security-control-constraint/1.0.0')[0].outcome) `
    'local BitLocker protection becomes a bounded discovery constraint rather than an escrow claim'
Assert-Equal 0 @($bitLockerRecord.observations|Where-Object {
    $_.fieldId -match '(?i)recovery|password|protector-id|key'
}).Count 'BitLocker evidence excludes recovery secrets and unnecessary protector identifiers'

$wdacRecord=New-AdministratorReadyRecord
$wdacCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario WdacWindows10Unsupported
$wdacRecord=Add-EffectivePolicyEvidenceRecord -Record $wdacRecord -CollectorResult $wdacCollector -Policy $effectivePolicy
$wdacRecord=Complete-ValidatedEffectivePolicyAssessmentRecord -Record $wdacRecord -Policy $effectivePolicy `
    -ContractValidation (Test-CanonicalRecord $wdacRecord)
Assert-Equal 'Indeterminate' (@($wdacRecord.findings|Where-Object `
    ruleId -eq 'rule:policy.security-control-coverage/1.0.0')[0].outcome) `
    'unsupported Windows 10 WDAC inventory becomes explicit incomplete coverage'

$appLockerConflictRecord=New-AdministratorReadyRecord
$appLockerConflictCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario AppLockerGpCspConflict
$appLockerConflictRecord=Add-EffectivePolicyEvidenceRecord -Record $appLockerConflictRecord `
    -CollectorResult $appLockerConflictCollector -Policy $effectivePolicy
$appLockerConflictRecord=Complete-ValidatedEffectivePolicyAssessmentRecord -Record $appLockerConflictRecord `
    -Policy $effectivePolicy -ContractValidation (Test-CanonicalRecord $appLockerConflictRecord)
Assert-Equal 'NeedsAttention' (@($appLockerConflictRecord.findings|Where-Object `
    ruleId -eq 'rule:policy.policy-csp-gpo-conflict/1.0.0')[0].outcome) `
    'conflicting AppLocker GP and CSP channels become a bounded advisory conflict'
$appLockerGpObservation=@($appLockerConflictRecord.observations|Where-Object {
    $_.fieldId -eq 'field:policy.applocker.gp.rule-collection'
})[0]
$appLockerCspObservation=@($appLockerConflictRecord.observations|Where-Object {
    $_.fieldId -eq 'field:policy.applocker.csp.rule-collection'
})[0]
$appLockerGpProvenance=@($appLockerConflictRecord.provenance|Where-Object {
    $_.provenanceId -eq $appLockerGpObservation.provenanceId
})[0]
$appLockerCspProvenance=@($appLockerConflictRecord.provenance|Where-Object {
    $_.provenanceId -eq $appLockerCspObservation.provenanceId
})[0]
Assert-Equal 'source:windows.applocker.gp-effective-policy' $appLockerGpProvenance.sourceId `
    'AppLocker GP evidence keeps the GP-only source provenance'
Assert-Equal 'source:windows.applocker.csp-policy' $appLockerCspProvenance.sourceId `
    'AppLocker CSP evidence keeps the CSP-only source provenance'

$appLockerIncompleteRecord=New-AdministratorReadyRecord
$appLockerIncompleteCollector=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario AppLockerChannelIncomplete
$appLockerIncompleteRecord=Add-EffectivePolicyEvidenceRecord -Record $appLockerIncompleteRecord `
    -CollectorResult $appLockerIncompleteCollector -Policy $effectivePolicy
$appLockerIncompleteRecord=Complete-ValidatedEffectivePolicyAssessmentRecord -Record $appLockerIncompleteRecord `
    -Policy $effectivePolicy -ContractValidation (Test-CanonicalRecord $appLockerIncompleteRecord)
Assert-Equal 'Indeterminate' (@($appLockerIncompleteRecord.findings|Where-Object `
    ruleId -eq 'rule:policy.policy-csp-gpo-conflict/1.0.0')[0].outcome) `
    'incomplete AppLocker channel coverage cannot guess a winning deployment channel'

Write-Output 'PASS: Effective Policy composes canonical three-layer evidence, closed coverage, and bounded findings.'
