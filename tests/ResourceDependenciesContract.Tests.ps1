[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
foreach($source in @(
    'Contracts','ContractValidator','RuntimeCompatibility','ProcessSupervisor','DeviceReadiness',
    'FirmwareReadiness','SystemCollectionPlan','IdentityEnrollment','AdministratorExposure',
    'EffectivePolicy','ResourceDependencies'
)){. (Join-Path $repositoryRoot "src/$source.ps1")}
$facts=Get-BuiltInModuleCompatibilityFacts
$devicePolicy=Get-DeviceReadinessPolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand
$firmwarePolicy=Get-FirmwareReadinessPolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand
$identityPolicy=Get-IdentityEnrollmentPolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand
$administratorPolicy=Get-AdministratorExposurePolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand
$effectivePolicy=Get-EffectivePolicyPolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand
$resourcePolicy=Get-ResourceDependenciesPolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand
$systemPolicy=Get-SystemCollectionPlanPolicy

function Test-CanonicalRecord($Record){
    [byte[]]$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Compress -Depth 30))
    Test-AssessmentContract -Utf8Bytes $bytes -ConvertFromJsonCommand $facts.convertFromJsonCommand `
        -TestJsonCommand $facts.testJsonCommand
}
function New-PolicyReadyRecord {
    $deviceCollector=Invoke-ApprovedCollectorProcess -OperationId $devicePolicy.collector.operationId -DeviceReadinessScenario Complete
    $record=New-DeviceReadinessAssessmentRecord -RunId "run:resource:$([guid]::NewGuid().ToString('N'))" `
        -Evidence (ConvertTo-NormalizedDeviceReadinessEvidence -Payload $deviceCollector.PrivatePayload) `
        -CollectorResult $deviceCollector -Policy $devicePolicy -ValidationFixture $true
    $record=Complete-ValidatedDeviceReadinessAssessmentRecord -ValidatedRecord $record -Policy $devicePolicy -ContractValidation (Test-CanonicalRecord $record)
    $now=[DateTimeOffset]::UtcNow
    $firmware=[pscustomobject][ordered]@{state='Completed';reasonCode='FIRMWARE.COLLECTION_COMPLETED';validationFixture=$true;envelope=[pscustomobject][ordered]@{startedAt=$now.AddMilliseconds(-5).ToString('o');completedAt=$now.ToString('o');attempts=1};payload=[pscustomobject][ordered]@{sourceLocale='und';firmwareState='Complete';firmwareType='Uefi';biosVersion='SYNTHETIC-UEFI-1.0';smbiosVersion='3.4';secureBootState='Complete';secureBootEnabled=$true;tpmState='Complete';tpmPresent=$true;tpmEnabled=$true;tpmActivated=$true;tpmSpecification='2.0'}}
    $record=Add-FirmwareReadinessEvidenceRecord -Record $record -CollectorResult $firmware -Policy $firmwarePolicy
    $record=Complete-ValidatedFirmwareReadinessAssessmentRecord -Record $record -Policy $firmwarePolicy -ContractValidation (Test-CanonicalRecord $record)
    $identity=Invoke-IdentityEnrollmentCollection -Policy $identityPolicy -ValidationScenario StandardUser
    $system=New-SystemCollectorResult -Policy $systemPolicy -Plan ([pscustomobject]@{recordType='synthetic-system-plan'}) -PlanDigest 'synthetic-system-plan-digest' -State Completed -ReasonCode 'SYSTEM.COLLECTION_COMPLETED' -CoverageState Complete -ObservedExecutionContext Synthetic -LocalSystemIdentityVerified $false -CleanupVerified $true -TaskAbsent $true -PipeAbsent $true -WorkerTreeAbsent $true -ProviderAvailable $true
    $record=Add-IdentityEnrollmentEvidenceRecord -Record $record -CollectorResult $identity -SystemResult $system -Policy $identityPolicy
    $record=Complete-ValidatedIdentityEnrollmentAssessmentRecord -Record $record -Policy $identityPolicy -ContractValidation (Test-CanonicalRecord $record)
    $administrator=Invoke-AdministratorExposureCollection -Policy $administratorPolicy -ValidationScenario LocalPrincipal
    $record=Add-AdministratorExposureEvidenceRecord -Record $record -CollectorResult $administrator -Policy $administratorPolicy
    $record=Complete-ValidatedAdministratorExposureAssessmentRecord -Record $record -Policy $administratorPolicy -ContractValidation (Test-CanonicalRecord $record)
    $effective=Invoke-EffectivePolicyCollection -Policy $effectivePolicy -ValidationScenario Workgroup
    $record=Add-EffectivePolicyEvidenceRecord -Record $record -CollectorResult $effective -Policy $effectivePolicy
    Complete-ValidatedEffectivePolicyAssessmentRecord -Record $record -Policy $effectivePolicy -ContractValidation (Test-CanonicalRecord $record)
}

$record=New-PolicyReadyRecord
$collector=Invoke-ResourceDependenciesCollection -Policy $resourcePolicy -ValidationScenario PortsAndDrivers
$record=Add-ResourceDependenciesEvidenceRecord -Record $record -CollectorResult $collector -Policy $resourcePolicy
$sourceValidation=Test-CanonicalRecord $record
Assert-Equal $true $sourceValidation.accepted "resource source evidence crosses the canonical contract before interpretation ($($sourceValidation.reasonCode))"
Assert-Equal 18 @($record.findings).Count 'source admission cannot fabricate resource findings'
$record=Complete-ValidatedResourceDependenciesAssessmentRecord -Record $record -Policy $resourcePolicy -ContractValidation $sourceValidation
$validation=Test-CanonicalRecord $record
Assert-Equal 'CONTRACT.ACCEPTED' $validation.reasonCode 'the combined resource dependency record remains canonical'
Assert-Equal $resourcePolicy.evidenceProfileId $record.run.evidenceProfileId 'the record selects the additive resource dependency profile'
Assert-Equal 43 @($record.coverage).Count 'all five resource scopes remain independently closed'
Assert-Equal 21 @($record.findings).Count 'three resource rules each produce exactly one finding'
Assert-Equal 1 @($record.collectorResults|Where-Object collectorId -eq $resourcePolicy.collector.collectorId).Count 'one approved attempt owns the five resource scopes'
Assert-Equal 'NeedsAttention' @($record.findings|Where-Object ruleId -eq 'rule:resource.user-migration-dependencies/1.0.0')[0].outcome 'observed printer dependencies produce advisory attention'
Assert-Equal 'subject:assessment-user:primary' @($record.findings|Where-Object ruleId -eq 'rule:resource.user-migration-dependencies/1.0.0')[0].targetSubjectId 'user-resource interpretation stays bound to the verified Assessment User'
Assert-Equal 1 @($record.recommendations|Where-Object definitionId -eq 'recommendation:resource.validate-user-resources/1.0.0').Count 'observed user resources receive one bounded next step'

$empty=New-PolicyReadyRecord
$emptyCollector=Invoke-ResourceDependenciesCollection -Policy $resourcePolicy -ValidationScenario Empty
$empty=Add-ResourceDependenciesEvidenceRecord -Record $empty -CollectorResult $emptyCollector -Policy $resourcePolicy
$empty=Complete-ValidatedResourceDependenciesAssessmentRecord -Record $empty -Policy $resourcePolicy -ContractValidation (Test-CanonicalRecord $empty)
Assert-Equal 'Informational' @($empty.findings|Where-Object ruleId -eq 'rule:resource.user-migration-dependencies/1.0.0')[0].outcome 'complete empty resource scopes establish bounded absence without a compatibility promise'
$absent=@($empty.observations|Where-Object {$_.fieldId -like 'field:resource.*' -and $_.valueState -eq 'ObservedAbsent'})
Assert-Equal 24 $absent.Count 'complete empty scopes explicitly close every defined field as absent'

$denied=New-PolicyReadyRecord
$deniedCollector=Invoke-ResourceDependenciesCollection -Policy $resourcePolicy -ValidationScenario AlternateAdministrator
$denied=Add-ResourceDependenciesEvidenceRecord -Record $denied -CollectorResult $deniedCollector -Policy $resourcePolicy
$denied=Complete-ValidatedResourceDependenciesAssessmentRecord -Record $denied -Policy $resourcePolicy -ContractValidation (Test-CanonicalRecord $denied)
Assert-Equal 'Indeterminate' @($denied.findings|Where-Object ruleId -eq 'rule:resource.dependency-coverage/1.0.0')[0].outcome 'alternate context denial remains insufficient evidence'
Assert-Equal 0 @($denied.observations|Where-Object fieldId -like 'field:resource.*').Count 'denied collection fabricates no resource observations'

$partial=New-PolicyReadyRecord
$partialCollector=Invoke-ResourceDependenciesCollection -Policy $resourcePolicy -ValidationScenario Partial
$partial=Add-ResourceDependenciesEvidenceRecord -Record $partial -CollectorResult $partialCollector -Policy $resourcePolicy
$partialValidation=Test-CanonicalRecord $partial
Assert-Equal $true $partialValidation.accepted "bounded Partial resource evidence remains canonical ($($partialValidation.reasonCode))"

foreach($failedScopeId in @($resourcePolicy.scopes.scopeId)){
    $isolated=New-PolicyReadyRecord
    $isolatedCollector=Invoke-ResourceDependenciesCollection -Policy $resourcePolicy -ValidationScenario Empty
    $failedState=@($isolatedCollector.payload.scopeStates|Where-Object scopeId -eq $failedScopeId)[0]
    $failedState.state='Unavailable';$failedState.reasonCode='RESOURCE.SOURCE_UNAVAILABLE'
    $isolated=Add-ResourceDependenciesEvidenceRecord -Record $isolated `
        -CollectorResult $isolatedCollector -Policy $resourcePolicy
    $isolatedValidation=Test-CanonicalRecord $isolated
    Assert-Equal $true $isolatedValidation.accepted "$failedScopeId remains canonical as one isolated source gap"
    Assert-Equal 1 @($isolated.coverage|Where-Object {$_.scopeId -eq $failedScopeId -and $_.state -eq 'Unavailable'}).Count "$failedScopeId preserves its own unavailable coverage"
    Assert-Equal 4 @($isolated.coverage|Where-Object {$_.scopeId -in @($resourcePolicy.scopes.scopeId) -and $_.state -eq 'Complete'}).Count "$failedScopeId does not erase unrelated completed sources"
}

Write-Output 'PASS: Resource Dependencies compose canonical bounded evidence, findings, and recommendations.'
