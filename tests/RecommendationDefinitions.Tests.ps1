[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$root = Split-Path $PSScriptRoot
foreach ($family in @('resource-dependencies','network-topology','software-inventory','certificate-trust','microsoft-connectivity','cross-domain-guidance')) {
    $text = Get-Content (Join-Path $root "docs/spec/releases/2.0.0-preview.1-$family.json") -Raw
    $schema = Get-Content (Join-Path $root "schemas/$family.schema.json") -Raw
    $policy = $text | ConvertFrom-Json
    foreach ($recommendation in $policy.recommendations) {
        foreach ($field in @('purpose','prerequisites','caution','responsibleRole','verification','authoritativeReferences')) {
            Assert-Equal $true ([bool]$recommendation.PSObject.Properties[$field]) "$family recommendations declare $field"
            $negative = $text | ConvertFrom-Json
            $negative.recommendations[0].PSObject.Properties.Remove($field)
            Assert-Equal $false (Test-Json -Json ($negative | ConvertTo-Json -Depth 50) -Schema $schema -ErrorAction SilentlyContinue) `
                "$family refuses missing recommendation $field"
        }
    }
    Assert-Equal $true (Test-Json -Json $text -Schema $schema) "$family exact portable definitions validate"
}
Write-Output 'PASS: portable recommendations require complete consulting metadata.'
