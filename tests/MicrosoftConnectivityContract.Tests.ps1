[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'SoftwareInventoryContract.Tests.ps1')
. (Join-Path $repositoryRoot 'src/CertificateTrust.ps1')
. (Join-Path $repositoryRoot 'src/MicrosoftConnectivity.ps1')
$jsonCommand = $facts.convertFromJsonCommand
$testJsonCommand = $facts.testJsonCommand
$certificatePolicy = Get-CertificateTrustPolicy -ConvertFromJsonCommand $jsonCommand
$connectivityPolicy = Get-MicrosoftConnectivityPolicy -ConvertFromJsonCommand $jsonCommand

function New-CertificateReadyRecord {
    $record = New-NetworkReadyRecord
    $software = Invoke-SoftwareInventoryCollection -Policy $softwarePolicy `
        -ValidationScenario Empty
    $record = Add-SoftwareInventoryEvidenceRecord -Record $record `
        -CollectorResult $software -Policy $softwarePolicy
    $record = Complete-ValidatedSoftwareInventoryAssessmentRecord -Record $record `
        -Policy $softwarePolicy -ContractValidation (Test-CanonicalRecord $record)
    $catalog = Get-SoftwareRecognitionCatalog -ConvertFromJsonCommand $jsonCommand `
        -TestJsonCommand $testJsonCommand
    $record = Add-SoftwareRecognitionAnnotations -Record $record `
        -Entries @($software.payload.entries) -CatalogResult $catalog
    $certificate = Invoke-CertificateTrustCollection -Policy $certificatePolicy `
        -ValidationScenario ValidTrusted
    $record = Add-CertificateTrustEvidenceRecord -Record $record `
        -CollectorResult $certificate -Policy $certificatePolicy
    Complete-ValidatedCertificateTrustAssessmentRecord -Record $record `
        -Policy $certificatePolicy -ContractValidation (Test-CanonicalRecord $record)
}

$record = New-CertificateReadyRecord
$collector = Invoke-MicrosoftConnectivityCollection -Policy $connectivityPolicy `
    -ValidationScenario DirectOutbound -NetworkBehavior MicrosoftConnectivityEnabled
$record = Add-MicrosoftConnectivityEvidenceRecord -Record $record `
    -CollectorResult $collector -Policy $connectivityPolicy
$sourceValidation = Test-CanonicalRecord $record
Assert-Equal 'CONTRACT.ACCEPTED' $sourceValidation.reasonCode `
    'separate connectivity protocol observations cross the canonical contract'
$record = Complete-ValidatedMicrosoftConnectivityAssessmentRecord -Record $record `
    -Policy $connectivityPolicy -ContractValidation $sourceValidation
$validation = Test-CanonicalRecord $record
Assert-Equal 'CONTRACT.ACCEPTED' $validation.reasonCode `
    'the interpreted Microsoft Connectivity record remains canonical'
Assert-Equal 8 @($record.coverage | Where-Object scopeId -like 'scope:connectivity.*').Count `
    'the canonical record closes eight independent connectivity scopes'
Assert-Equal 0 @($record.coverage | Where-Object scopeId -in @(
    'scope:network.microsoft-connectivity', 'scope:network.enrollment-dns',
    'scope:network.tls-trust'
)).Count 'the implemented scopes replace the three prior deferred placeholders'
Assert-Equal 3 @($record.observations | Where-Object {
    $_.fieldId -eq 'field:connectivity.dns.state'
}).Count 'each endpoint retains its own DNS observation'
Assert-Equal 3 @($record.observations | Where-Object {
    $_.fieldId -eq 'field:connectivity.tcp.state'
}).Count 'TCP remains independent from DNS'
Assert-Equal 3 @($record.observations | Where-Object {
    $_.fieldId -eq 'field:connectivity.tls.state'
}).Count 'TLS remains independent from TCP'
Assert-Equal 3 @($record.observations | Where-Object {
    $_.fieldId -eq 'field:connectivity.http.state'
}).Count 'bounded HTTP metadata remains independent from TLS'
Assert-Equal 'ExpectedCondition' @($record.findings | Where-Object {
    $_.ruleId -eq 'rule:microsoft-connectivity.reachability/1.0.0'
})[0].outcome `
    'completed endpoint evidence produces an advisory expected-condition finding'
Assert-Equal 'ExpectedCondition' @($record.findings | Where-Object {
    $_.ruleId -eq 'rule:microsoft-connectivity.tls-inspection/1.0.0'
})[0].outcome `
    'matching completed paths support only the not-observed TLS-inspection result'

$localOnlyRecord = New-CertificateReadyRecord
$localOnlyCollector = Invoke-MicrosoftConnectivityCollection -Policy $connectivityPolicy `
    -ValidationScenario LocalOnly -NetworkBehavior LocalOnly
$localOnlyRecord = Add-MicrosoftConnectivityEvidenceRecord -Record $localOnlyRecord `
    -CollectorResult $localOnlyCollector -Policy $connectivityPolicy
$localOnlyValidation = Test-CanonicalRecord $localOnlyRecord
$localOnlyRecord = Complete-ValidatedMicrosoftConnectivityAssessmentRecord `
    -Record $localOnlyRecord -Policy $connectivityPolicy `
    -ContractValidation $localOnlyValidation
Assert-Equal 8 @($localOnlyRecord.coverage | Where-Object {
    $_.scopeId -like 'scope:connectivity.*' -and $_.state -eq 'NotAttempted'
}).Count 'Local Only records every connectivity scope without observations'
Assert-Equal 0 @($localOnlyRecord.observations | Where-Object {
    $_.fieldId -like 'field:connectivity.*'
}).Count 'Local Only fabricates no endpoint result'
Assert-Equal 'Indeterminate' @($localOnlyRecord.findings | Where-Object {
    $_.ruleId -eq 'rule:microsoft-connectivity.reachability/1.0.0'
})[0].outcome `
    'Local Only is not misreported as successful connectivity'

Write-Output 'PASS: Microsoft Connectivity composes canonical typed evidence and honest Local Only findings.'
