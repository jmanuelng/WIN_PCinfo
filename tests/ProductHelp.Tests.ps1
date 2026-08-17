[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/ProductHelp.ps1')

$policy = Get-ProductHelpPolicy
Assert-Equal 'win-pcinfo.guided-runway/1.0.0' $policy.policyId `
    'Help loads the release Guided Runway content contract'

foreach ($surface in @('Help', 'About')) {
    $record = Get-ProductHelpRecord -Surface $surface
    Assert-Equal 'win-pcinfo.product-help' $record.recordType `
        "$surface emits the public product-help contract"
    Assert-Equal '1.0.0' $record.contractVersion "$surface uses the frozen help contract version"
    Assert-Equal $surface $record.surface "$surface identifies itself"
    Assert-Equal 'WIN-PCInfo' $record.productName "$surface names the product"
    Assert-Equal '2.0.0-preview.1' $record.release "$surface names the planned release identity"
    Assert-Equal 'None' $record.supportClaim "$surface makes no support claim"
    Assert-Equal 'None' $record.previewOrStableClaim "$surface makes no Preview or Stable claim"
    Assert-Equal $false $record.collectionStarted "$surface never starts collection"
    Assert-Equal $false $record.feedbackPrompted "$surface does not ask for feedback"
    Assert-Equal $false $record.networkRequested "$surface stays offline"
    Assert-Equal $true $record.learningConsultingBoundary `
        "$surface restates the learning and consulting boundary"
    Assert-Equal 'BestEffortNoSla' $record.maintenance "$surface states best-effort maintenance"
    Assert-Equal 7 @($record.runway).Count "$surface lists the seven runway stages"
    Assert-Equal 'https://github.com/jmanuelng/WIN_PCinfo' $record.discovery.repository `
        "$surface exposes the repository only when opened"
    Assert-Equal 'https://github.com/jmanuelng/WIN_PCinfo/issues' $record.discovery.feedback `
        "$surface exposes the feedback route only when opened"
    Assert-Equal 'https://github.com/jmanuelng/WIN_PCinfo/blob/main/CONTRIBUTING.md' `
        $record.discovery.contribution "$surface exposes the contribution route only when opened"
    Assert-Equal 'https://github.com/jmanuelng/WIN_PCinfo/security/advisories/new' `
        $record.discovery.vulnerabilityReporting `
        "$surface exposes private vulnerability reporting only when opened"
    Assert-Equal $false $record.fieldValidation.automaticFromOrdinaryUse `
        "$surface refuses automatic Field Validation"
    Assert-Equal $true $record.fieldValidation.requiresDeliberateConsent `
        "$surface requires deliberate Field Validation consent"
    foreach ($name in @('deviceName', 'packagePath', 'fingerprint', 'tenantId', 'ipAddress')) {
        Assert-Equal $false ($record.PSObject.Properties.Name -contains $name) `
            "$surface does not carry restricted $name material"
    }
}

Write-Output 'PASS: Product Help and About records stay passive, offline, and identifier-free.'
