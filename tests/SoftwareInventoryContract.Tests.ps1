[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'NetworkTopologyContract.Tests.ps1')
. (Join-Path $repositoryRoot 'src/SoftwareInventory.ps1')
. (Join-Path $repositoryRoot 'src/SoftwareRecognition.ps1')
$softwarePolicy=Get-SoftwareInventoryPolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand

$enabledSelection=Get-DeviceReadinessSliceSelection -DeviceFixture $false -IdentityFixture $false `
    -AdministratorFixture $false -EffectivePolicyFixture $false -ResourceFixture $false `
    -NetworkFixture $false -SoftwareFixture $false -NetworkBehavior MicrosoftConnectivityEnabled
Assert-Equal $true $enabledSelection.networkRequested 'enabled network behavior still composes the local network evidence profile before Software Inventory'
$enabledNetwork=Invoke-NetworkTopologyCollection -Policy $networkPolicy -ValidationScenario Empty `
    -NetworkBehavior MicrosoftConnectivityEnabled
Assert-Equal 'MicrosoftConnectivityEnabled' $enabledNetwork.payload.networkBehavior `
    'the approved enabled choice is preserved at execution'
Assert-Equal 3 @($enabledNetwork.payload.scopeStates|Where-Object {
    $_.state -eq 'NotAttempted' -and $_.reasonCode -eq 'NETWORK.CONNECTIVITY_OPERATIONS_NOT_IMPLEMENTED'
}).Count 'unimplemented enabled operations remain explicit gaps instead of silently becoming Local Only'

$cleanupDisposition=Get-DeviceReadinessFailureDisposition -ReasonCode 'SOFTWARE.COLLECTOR_CLEANUP_INCOMPLETE' -CollectionStarted $true
Assert-Equal 'CleanupIncomplete' $cleanupDisposition.outcome 'software worker cleanup uncertainty takes terminal precedence'
Assert-Equal 60 $cleanupDisposition.exitCode 'software cleanup uncertainty uses the stable cleanup exit code'
Assert-Equal $false $cleanupDisposition.cleanupVerified 'software cleanup uncertainty cannot claim verified absence'

function New-NetworkReadyRecord {
    $record=New-ResourceReadyRecord
    $network=Invoke-NetworkTopologyCollection -Policy $networkPolicy -ValidationScenario Empty -NetworkBehavior LocalOnly
    $record=Add-NetworkTopologyEvidenceRecord $record $network $networkPolicy
    Complete-ValidatedNetworkTopologyAssessmentRecord $record $networkPolicy (Test-CanonicalRecord $record)
}

$record=New-NetworkReadyRecord
$collector=Invoke-SoftwareInventoryCollection -Policy $softwarePolicy -ValidationScenario MsiStates
$record=Add-SoftwareInventoryEvidenceRecord -Record $record -CollectorResult $collector -Policy $softwarePolicy
$contractSet=Get-Content -Raw (Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-contract-set.json')|ConvertFrom-Json
foreach($definition in @($contractSet.fieldDefinitions|Where-Object fieldId -like 'field:software.*')){
    $matching=@($record.observations|Where-Object fieldId -eq $definition.fieldId)
    foreach($group in @($matching|Group-Object subjectId)){
        Assert-Equal $true ($group.Count -le [int]$definition.bounds.maximumOccurrencesPerSubject) "$($definition.fieldId) stays within its per-subject occurrence bound"
    }
    foreach($observation in @($matching|Where-Object valueState -eq ObservedValue)){
        Assert-Equal $true ([Text.Encoding]::UTF8.GetByteCount([string]$observation.value) -le [int]$definition.bounds.maximumUtf8Bytes) "$($definition.fieldId) stays within its UTF-8 value bound"
    }
}
$sourceValidation=Test-CanonicalRecord $record
Assert-Equal 'CONTRACT.ACCEPTED' $sourceValidation.reasonCode 'MSI installed and advertised states cross the canonical field contract'
$record=Complete-ValidatedSoftwareInventoryAssessmentRecord $record $softwarePolicy $sourceValidation
$recognitionCatalog=Get-SoftwareRecognitionCatalog `
    -ConvertFromJsonCommand $facts.convertFromJsonCommand
$findingCountBeforeRecognition=@($record.findings).Count
$record=Add-SoftwareRecognitionAnnotations -Record $record `
    -Entries @($collector.payload.entries) `
    -CatalogResult $recognitionCatalog
$validation=Test-CanonicalRecord $record
Assert-Equal 'CONTRACT.ACCEPTED' $validation.reasonCode `
    'the final Software Inventory record with recognition annotations remains canonical'
Assert-Equal 2 @($record.subjects|Where-Object kind -eq Application).Count 'separate MSI products retain separate source identities'
Assert-Equal 2 @($record.softwareRecognition).Count `
    'every authoritative software subject receives exactly one recognition outcome'
Assert-Equal $findingCountBeforeRecognition @($record.findings).Count `
    'a Software Recognition Outcome never creates an Assessment Finding by itself'
Assert-Equal 'Advertised|Installed' ((@($record.observations|Where-Object fieldId -eq 'field:software.msi.installer-state').value|Sort-Object)-join '|') 'MSI provider states remain distinct bounded evidence'

$denied=New-NetworkReadyRecord
$deniedCollector=Invoke-SoftwareInventoryCollection -Policy $softwarePolicy -ValidationScenario DeniedUser
$denied=Add-SoftwareInventoryEvidenceRecord -Record $denied -CollectorResult $deniedCollector -Policy $softwarePolicy
$deniedSourceValidation=Test-CanonicalRecord $denied
Assert-Equal 'CONTRACT.ACCEPTED' $deniedSourceValidation.reasonCode 'Assessment User denial remains valid source coverage'
$denied=Complete-ValidatedSoftwareInventoryAssessmentRecord $denied $softwarePolicy $deniedSourceValidation
$deniedValidation=Test-CanonicalRecord $denied
Assert-Equal 'CONTRACT.ACCEPTED' $deniedValidation.reasonCode 'Assessment User denial produces canonical indeterminate findings'
Assert-Equal 'Indeterminate' @($denied.findings|Where-Object ruleId -eq 'rule:software.assessment-user-inventory/1.0.0')[0].outcome 'denied user evidence cannot become a negative finding'

$maximumRecord=New-NetworkReadyRecord
$maximumCollector=Invoke-SoftwareInventoryCollection -Policy $softwarePolicy -ValidationScenario AggregateMaximum
$maximumRecord=Add-SoftwareInventoryEvidenceRecord -Record $maximumRecord `
    -CollectorResult $maximumCollector -Policy $softwarePolicy
$maximumRecord=Complete-ValidatedSoftwareInventoryAssessmentRecord $maximumRecord $softwarePolicy `
    (Test-CanonicalRecord $maximumRecord)
$maximumReport=New-DeviceReadinessReportBytes -Record $maximumRecord `
    -FirmwarePolicy $firmwarePolicy -IdentityEnrollmentPolicy $identityPolicy `
    -AdministratorExposurePolicy $administratorPolicy -EffectivePolicyPolicy $effectivePolicy `
    -ResourceDependenciesPolicy $resourcePolicy -NetworkTopologyPolicy $networkPolicy `
    -SoftwareInventoryPolicy $softwarePolicy
Assert-Equal $true ($maximumReport.Length -le 262144) `
    "all 128 registrations with every admitted text field at its maximum compose under the report/export bound (actual $($maximumReport.Length) bytes)"

Write-Output 'PASS: Software Inventory composes canonical source identities and MSI states.'
