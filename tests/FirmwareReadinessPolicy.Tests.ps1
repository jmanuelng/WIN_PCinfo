[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-firmware-readiness.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/firmware-readiness.schema.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

if (-not (Test-Json -Json (Get-Content -LiteralPath $policyPath -Raw) `
        -SchemaFile $schemaPath)) {
    throw 'The release Firmware Readiness policy does not satisfy its schema.'
}

$policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json -Depth 20
Assert-Equal 'win-pcinfo.firmware-readiness/1.0.0' $policy.policyId `
    'the firmware slice has one immutable release identity'
Assert-Equal 'observe-firmware-tpm' $policy.collector.operationId `
    'the collector uses the operation already frozen into the privileged plan'
Assert-Equal 'Administrator' $policy.collector.executionContext `
    'firmware security evidence stays inside the one approved Administrator phase'
Assert-Equal 'OfflineOnly' $policy.collector.networkBehavior `
    'firmware collection cannot gain network authority'
Assert-Equal $false $policy.collector.mayPrompt `
    'the collector cannot introduce a second prompt'
Assert-Equal $false $policy.collector.mayInstall `
    'the collector cannot install a helper or Windows Feature'
Assert-Equal $false $policy.collector.mayDownload `
    'the collector cannot download code or definitions'
Assert-Equal $false $policy.collector.maySelfElevate `
    'the collector cannot widen its approved privilege'
Assert-Equal $false $policy.collector.writesAllowed `
    'the collector is observational and cannot change platform security state'
Assert-Equal 1 $policy.collector.maximumAttempts `
    'the collector has one bounded, non-retrying attempt'
Assert-Equal 5000 $policy.collector.deadlineMilliseconds `
    'the privileged firmware attempt has an explicit finite deadline'

$expectedScopes = @(
    'scope:device.firmware-context',
    'scope:device.secure-boot',
    'scope:device.tpm-readiness'
)
Assert-Equal ($expectedScopes -join '|') (@($policy.scopes.scopeId) -join '|') `
    'firmware, Secure Boot, and TPM retain independently honest coverage'

$expectedRules = @{
    'firmware-context' = 'op:rule.firmware-context.evaluate'
    'secure-boot-readiness' = 'op:rule.secure-boot-readiness.evaluate'
    'tpm-readiness' = 'op:rule.tpm-readiness.evaluate'
}
Assert-Equal 3 @($policy.rules).Count `
    'each release rule produces exactly one firmware-security finding'
foreach ($rule in @($policy.rules)) {
    Assert-Equal $expectedRules[[string]$rule.findingKind] ([string]$rule.operationId) `
        'the rule operation identity is release-owned'
    Assert-Equal 'InProcessValidatedAssessmentRecord' ([string]$rule.executionContext) `
        'rules evaluate only the admitted canonical record'
    Assert-Equal 1 ([int]$rule.maximumAttempts) 'rules do not retry interpretation'
    Assert-Equal 100 ([int]$rule.deadlineMilliseconds) 'rules have a finite deadline'
    Assert-Equal 1 ([int]$rule.maximumOutputFindings) 'one rule produces one finding'
}

$expectedScenarios = @(
    'Supported','Disabled','Absent','Virtual','NonUefi','AccessDenied',
    'Unsupported','Malformed','Timeout','CollectorFailure'
)
Assert-Equal ($expectedScenarios -join '|') (@($policy.validationScenarios) -join '|') `
    'the public firmware validation matrix is closed and complete'

$policyText = Get-Content -LiteralPath $policyPath -Raw
if ($policyText -match '(?i)ownerAuthorization|endorsementSecret|privateKey|recoveryData|serialNumber') {
    throw 'The firmware policy admits prohibited TPM secret or unbounded identity material.'
}

Write-Output 'PASS: Firmware Readiness authority, sources, bounds, rules, and scenarios are release-defined.'
