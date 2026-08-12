[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/RuntimeCompatibility.ps1')
. (Join-Path $repositoryRoot 'src/ResourceDependencies.ps1')

$policyPath=Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-resource-dependencies.json'
$schemaPath=Join-Path $repositoryRoot 'schemas/resource-dependencies.schema.json'
if(-not (Test-Json -Json (Get-Content -LiteralPath $policyPath -Raw) -SchemaFile $schemaPath)){
    throw 'The Resource Dependencies policy does not satisfy its closed schema.'
}
$policy=Get-ResourceDependenciesPolicy -ConvertFromJsonCommand (
    Get-Command ConvertFrom-Json -CommandType Cmdlet
)
Assert-Equal 'win-pcinfo.resource-dependencies/1.0.0' $policy.policyId 'the release policy identity is frozen'
Assert-Equal 'observe-user-dependencies' $policy.collector.operationId 'the Preparation operation is reused exactly'
Assert-Equal 'StandardUser' $policy.collector.executionContext 'the collector is bound to the Assessment User process context'
Assert-Equal 'OfflineOnly' $policy.collector.networkBehavior 'the collector cannot make a network request'
Assert-Equal 1 $policy.collector.maximumAttempts 'collection has one bounded attempt'
Assert-Equal 5000 $policy.collector.deadlineMilliseconds 'collection has a finite five-second deadline'
Assert-Equal 8 $policy.collector.maximumPeripherals 'common peripheral evidence is bounded before collection'
Assert-Equal $false $policy.collector.mayPrompt 'collection cannot prompt'
Assert-Equal $false $policy.collector.mayInstall 'collection cannot install'
Assert-Equal $false $policy.collector.mayDownload 'collection cannot download'
Assert-Equal $false $policy.collector.maySelfElevate 'collection cannot self-elevate'
Assert-Equal $false $policy.collector.writesAllowed 'collection cannot write device state'
Assert-Equal $false (@($policy.sourceCatalog.approvedProperties) -contains 'UserName') 'stored account names are outside the source catalog'
Assert-Equal $false (@($policy.sourceCatalog.approvedProperties) -contains 'PNPDeviceID') 'device identifiers and embedded serials are outside the source catalog'
Assert-Equal 5 @($policy.scopes).Count 'five Evidence Scopes remain distinct'
Assert-Equal 3 @($policy.rules).Count 'three advisory interpretations are frozen'
foreach($rule in $policy.rules){
    Assert-Equal $false $rule.mayPrompt "$($rule.findingKind) cannot prompt"
    Assert-Equal $false $rule.mayInstall "$($rule.findingKind) cannot install"
    Assert-Equal $false $rule.mayDownload "$($rule.findingKind) cannot download"
    Assert-Equal $false $rule.maySelfElevate "$($rule.findingKind) cannot self-elevate"
    Assert-Equal $false $rule.writesAllowed "$($rule.findingKind) cannot write"
}

Write-Output 'PASS: Resource Dependency authority is frozen before approval.'
