[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/RuntimeCompatibility.ps1')
. (Join-Path $repositoryRoot 'src/SoftwareInventory.ps1')

$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-software-inventory.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/software-inventory.schema.json'
if (-not (Test-Json -Json (Get-Content -LiteralPath $policyPath -Raw) -SchemaFile $schemaPath)) {
    throw 'The Software Inventory policy does not satisfy its closed schema.'
}
$policy = Get-SoftwareInventoryPolicy -ConvertFromJsonCommand (
    Get-Command ConvertFrom-Json -CommandType Cmdlet
)

Assert-Equal 'win-pcinfo.software-inventory/1.0.0' $policy.policyId `
    'the release policy identity is frozen'
Assert-Equal 'observe-installed-software' $policy.collector.operationId `
    'the existing Preparation operation is reused exactly'
Assert-Equal 'StandardUser' $policy.collector.executionContext `
    'the collector runs only as the verified Assessment User'
Assert-Equal 'OfflineOnly' $policy.collector.networkBehavior `
    'inventory cannot make a network request'
Assert-Equal 1 $policy.collector.maximumAttempts 'collection has one bounded attempt'
Assert-Equal 10000 $policy.collector.deadlineMilliseconds `
    'the combined structured source attempt has a finite deadline'
Assert-Equal 64 $policy.collector.maximumEntriesPerScope `
    'every source scope has a finite evidence ceiling'
Assert-Equal 128 $policy.collector.maximumTotalEntries `
    'the aggregate ceiling keeps every admitted payload composable into Contract Set 1.7'
Assert-Equal 3 @($policy.sourceCatalog).Count `
    'only source identities actually bound to release scopes are declared'
Assert-Equal 8 @($policy.scopes).Count `
    'registry views, MSI contexts, and MSIX contexts remain separately covered'
Assert-Equal 'Registry32|Registry64' (@($policy.registryViews) -join '|') `
    'both applicable uninstall registration views are explicit'
Assert-Equal 'Machine|AssessmentUser' (@($policy.registrationContexts) -join '|') `
    'only machine and verified Assessment User registrations are authorized'

foreach ($operation in @($policy.collector) + @($policy.rules)) {
    Assert-Equal $false $operation.mayPrompt "$($operation.operationId) cannot prompt"
    Assert-Equal $false $operation.mayInstall "$($operation.operationId) cannot install"
    Assert-Equal $false $operation.mayDownload "$($operation.operationId) cannot download"
    Assert-Equal $false $operation.maySelfElevate "$($operation.operationId) cannot self-elevate"
    Assert-Equal $false $operation.writesAllowed "$($operation.operationId) cannot write device state"
}

$sourceText = Get-Content -LiteralPath (Join-Path $repositoryRoot 'src/SoftwareInventory.ps1') -Raw
foreach ($prohibited in @(
    'Win32_Product', 'Get-WmiObject', 'ConsistencyCheck', 'MsiConfigureProduct',
    'MsiReinstallProduct', 'MsiProvideComponent', 'InstallLocation',
    'UninstallString', 'QuietUninstallString', 'DigitalSignature', 'FileHash',
    'ProductKey', 'LicenseKey'
)) {
    if ($sourceText -match [regex]::Escape($prohibited)) {
        throw "The Software Inventory implementation admits prohibited material or behavior: $prohibited"
    }
}

Write-Output 'PASS: Software Inventory authority is frozen before approval.'
