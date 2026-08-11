[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policyPath = Join-Path $repositoryRoot `
    'docs/spec/releases/2.0.0-preview.1-recipient-sharing.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/recipient-profile.schema.json'
$policySchemaPath = Join-Path $repositoryRoot 'schemas/recipient-sharing.schema.json'

Assert-Equal $true (Test-Path -LiteralPath $policyPath -PathType Leaf) `
    'recipient selection and restricted export are release-declared'
Assert-Equal $true (Test-Path -LiteralPath $schemaPath -PathType Leaf) `
    'the portable non-secret Recipient Profile has a closed public schema'
Assert-Equal $true (Test-Path -LiteralPath $policySchemaPath -PathType Leaf) `
    'the Recipient Sharing release policy has a closed public schema'

$policyJson = Get-Content -LiteralPath $policyPath -Raw
Assert-Equal $true (Test-Json -Json $policyJson -SchemaFile $policySchemaPath) `
    'the release policy satisfies its exact schema'
$policy = $policyJson | ConvertFrom-Json -Depth 20
Assert-Equal 'win-pcinfo.recipient-sharing/1.0.0' $policy.policyId `
    'the sharing policy has a stable release identity'
Assert-Equal 1 $policy.recipient.maximumRecipients `
    'at most one recipient may be fixed before collection'
Assert-Equal 3072 $policy.recipient.rsa.defaultKeyBits `
    'new recipient keys default to RSA 3072'
Assert-Equal 2048 $policy.recipient.rsa.minimumKeyBits `
    'recipient admission never accepts RSA below 2048 bits'
Assert-Equal 'RSA-OAEP-SHA-256' $policy.recipient.keyWrapAlgorithm `
    'the recipient content-key wrap is fixed to OAEP SHA-256'
Assert-Equal $true $policy.recipient.privateKey.nonExportable `
    'recipient setup requires a non-exportable key'
Assert-Equal 'CurrentUser' $policy.recipient.privateKey.storeLocation `
    'recipient setup is confined to the current Windows user'
Assert-Equal 'UserAndDeviceBound' $policy.recipient.protectionLevels[0] `
    'TPM-backed user-and-device protection is preferred'
Assert-Equal 'WindowsUserBound' $policy.recipient.protectionLevels[1] `
    'the software fallback is labeled only as Windows-user-bound'
Assert-Equal $true $policy.recipient.admission.requireCurrentValidity `
    'certificate validity gates new package creation'
Assert-Equal $false $policy.recipient.historicalOpening.requireCurrentValidity `
    'historical opening depends on the usable matching private key'
Assert-Equal $true $policy.restrictedReportExport.warningAcknowledgmentRequired `
    'plaintext report export requires an explicit warning acknowledgment'
Assert-Equal $true $policy.restrictedReportExport.permanentRestrictedBanner `
    'every exported report carries a permanent Restricted banner'
Assert-Equal $false $policy.restrictedReportExport.publiclyShareable `
    'restricted exports never become publicly shareable'
Assert-Equal 0 @($policy.restrictedReportExport.backgroundServices).Count `
    'export creates no upload, retention, scheduler, cleaner, or monitor'

Write-Output 'PASS: recipient sharing and restricted export are closed by release policy.'
