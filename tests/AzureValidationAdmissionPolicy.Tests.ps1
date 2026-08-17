[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-azure-validation-admission.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-admission.schema.json'
$requestSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-round-request.schema.json'
$verdictSchemaPath = Join-Path $repositoryRoot 'schemas/azure-validation-admission-verdict.schema.json'

Assert-Equal $true (Test-Path -LiteralPath $policyPath -PathType Leaf) `
    'the Azure validation admission contract is release-declared'
Assert-Equal $true (Test-Path -LiteralPath $schemaPath -PathType Leaf) `
    'the Azure validation admission contract has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $requestSchemaPath -PathType Leaf) `
    'the Azure validation round request has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $verdictSchemaPath -PathType Leaf) `
    'the sanitized admission verdict has a closed public schema'

$policyJson = Get-Content -LiteralPath $policyPath -Raw
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $schemaPath) `
    'the Azure validation admission contract satisfies its exact schema'
$policy = $policyJson | ConvertFrom-Json -Depth 20

Assert-Equal 'win-pcinfo.azure-validation-admission/1.0.0' $policy.policyId `
    'the admission contract has a stable release identity'
Assert-Equal 'CAP-0028' $policy.productCapability `
    'admission traces to Fresh Azure Client VM Validation'
Assert-Equal $false $policy.sliceDeliversCapability `
    'this slice does not mark the Product Capability delivered'
Assert-Equal 'None' $policy.azureContact 'the contract forbids Azure contact'
Assert-Equal 'None' $policy.supportClaim 'admission makes no support claim'
Assert-Equal 'None' $policy.previewOrStableClaim 'admission makes no Preview claim'
Assert-Equal 1 $policy.clients.minimum 'one client is the floor'
Assert-Equal 4 $policy.clients.maximum 'four clients is the ceiling'
Assert-Equal 360 $policy.lifetime.maximumMinutes 'six hours is the lifetime ceiling'
Assert-Equal 30 $policy.lifetime.minimumCleanupReserveMinutes `
    'cleanup reserve is mandatory'
Assert-Equal 'StandardSSD_LRS' $policy.clients.diskType 'only Standard SSD is allowed'
Assert-Equal 'TrustedLaunch' $policy.clients.windows11ClaimingRoute.securityType `
    'the Windows 11 claiming route requires Trusted Launch'
Assert-Equal $false $policy.network.vmPublicIp 'VM public IPs are forbidden'
Assert-Equal 'Standard' $policy.network.natPublicIpSku `
    'NAT uses a Standard public IP'
Assert-Equal $false $policy.network.peering.allowGatewayTransit `
    'peering is non-transitive'
Assert-Equal 'declared-not-acquired' $policy.tooling.terraform.acquisition `
    'Terraform is a declared identity, not a downloaded tool'
Assert-Equal 'declared-not-acquired' $policy.tooling.provider.acquisition `
    'the Azure provider is a declared identity, not a downloaded tool'

foreach ($fixtureName in @(
    'azure-validation-round-one-client.json'
    'azure-validation-round-four-clients.json'
    'azure-validation-round-nonclaiming-diagnostic.json'
)) {
    $fixturePath = Join-Path $PSScriptRoot "fixtures/$fixtureName"
    $fixtureJson = Get-Content -LiteralPath $fixturePath -Raw
    Assert-Equal $true (Test-Json -Json $fixtureJson -SchemaFile $requestSchemaPath) `
        "$fixtureName satisfies the public round-request schema"
    Assert-Equal $false ($fixtureJson -match '/subscriptions/') `
        "$fixtureName contains no Azure subscription path"
    Assert-Equal $false ($fixtureJson -match '(?i)tenant') `
        "$fixtureName contains no tenant identifier"
}

$templateRoot = Join-Path $repositoryRoot ([string] $policy.templateRootRelativePath)
Assert-Equal $true (Test-Path -LiteralPath (Join-Path $templateRoot 'versions.tf') -PathType Leaf) `
    'generic Terraform versions are published as source'
$exampleText = Get-Content -LiteralPath (Join-Path $templateRoot 'examples/synthetic-round.tfvars.example') -Raw
Assert-Equal $true ($exampleText -match 'clients\s*=\s*\[') `
    'the public example parameterizes per-client SKU and security'
Assert-Equal $true ($exampleText -match 'round_correlation_tag') `
    'the public example includes the required RoundCorrelation tag'
Assert-Equal $true ($exampleText -match '\{\{APPROVED_GALLERY_IMAGE_ID\}\}') `
    'the public example uses only placeholders'

$operatorDoc = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/azure-validation-admission.md'
) -Raw
Assert-Equal $true ($operatorDoc -match 'does not mark `CAP-0028` delivered') `
    'operator documentation refuses a Product Capability claim'
Assert-Equal $true ($operatorDoc -match 'does not log in to Azure') `
    'operator documentation states that Azure login does not occur'
Assert-Equal $true ($operatorDoc -match 'AdmitValidationRound') `
    'operator documentation names the generated-application workflow'
Assert-Equal $true ($operatorDoc -match 'VALIDATION.ROUND_ADMITTED|fifth client') `
    'operator documentation matches the implemented reject-or-admit behavior'
Assert-Equal $false ($operatorDoc -match 'this slice creates a Preview/Supported capability claim') `
    'operator documentation does not invent a Preview claim'

Write-Output 'PASS: Azure validation admission policy is closed and environment-free.'
