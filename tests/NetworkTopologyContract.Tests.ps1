[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'ResourceDependenciesContract.Tests.ps1')
. (Join-Path $repositoryRoot 'src/NetworkTopology.ps1')
$networkPolicy=Get-NetworkTopologyPolicy -ConvertFromJsonCommand $facts.convertFromJsonCommand

function New-ResourceReadyRecord {
    $record=New-PolicyReadyRecord
    $resource=Invoke-ResourceDependenciesCollection -Policy $resourcePolicy -ValidationScenario Empty
    $record=Add-ResourceDependenciesEvidenceRecord $record $resource $resourcePolicy
    Complete-ValidatedResourceDependenciesAssessmentRecord $record $resourcePolicy (Test-CanonicalRecord $record)
}

$record=New-ResourceReadyRecord
$collector=Invoke-NetworkTopologyCollection -Policy $networkPolicy -ValidationScenario IPv4IPv6 -NetworkBehavior LocalOnly
$record=Add-NetworkTopologyEvidenceRecord $record $collector $networkPolicy
$sourceValidation=Test-CanonicalRecord $record
Assert-Equal $true $sourceValidation.accepted "network source evidence crosses the canonical contract ($($sourceValidation.reasonCode))"
$record=Complete-ValidatedNetworkTopologyAssessmentRecord $record $networkPolicy $sourceValidation
$validation=Test-CanonicalRecord $record
Assert-Equal 'CONTRACT.ACCEPTED' $validation.reasonCode 'the combined Network Topology record remains canonical'
Assert-Equal $networkPolicy.evidenceProfileId $record.run.evidenceProfileId 'the additive profile preserves historical scopes'
Assert-Equal 55 @($record.coverage).Count 'nine local and three deferred network scopes are independently closed'
Assert-Equal 3 @($record.coverage|Where-Object {$_.scopeId -in @($networkPolicy.networkDependentScopes.scopeId) -and $_.state -eq 'NotAttempted'}).Count 'Local Only records each network-dependent scope as not attempted'
Assert-Equal 0 @($record.observations|Where-Object fieldId -like '*.result').Count 'Local Only fabricates no probe observations'
Assert-Equal 1 @($record.collectorResults|Where-Object collectorId -eq $networkPolicy.collector.collectorId).Count 'one approved offline attempt owns only the nine local scopes'
Assert-Equal 'Indeterminate' @($record.findings|Where-Object ruleId -eq 'rule:network.local-only-coverage/1.0.0')[0].outcome 'Local Only does not produce a false connectivity conclusion'

$denied=New-ResourceReadyRecord
$deniedCollector=Invoke-NetworkTopologyCollection -Policy $networkPolicy -ValidationScenario Denied -NetworkBehavior LocalOnly
$denied=Add-NetworkTopologyEvidenceRecord $denied $deniedCollector $networkPolicy
$denied=Complete-ValidatedNetworkTopologyAssessmentRecord $denied $networkPolicy (Test-CanonicalRecord $denied)
Assert-Equal 0 @($denied.observations|Where-Object fieldId -like 'field:network.*').Count 'denied local sources fabricate no observations'
Assert-Equal 'Indeterminate' @($denied.findings|Where-Object ruleId -eq 'rule:network.local-configuration/1.0.0')[0].outcome 'denied local evidence stays indeterminate'

Write-Output 'PASS: Network Topology composes canonical offline evidence and honest Local Only findings.'
