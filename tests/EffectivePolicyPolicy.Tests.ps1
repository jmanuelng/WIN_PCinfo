[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-effective-policy.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/effective-policy.schema.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

if (-not (Test-Json -Json (Get-Content -LiteralPath $policyPath -Raw) -SchemaFile $schemaPath)) {
    throw 'The release Effective Policy policy does not satisfy its schema.'
}

$policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json -Depth 30
Assert-Equal 'win-pcinfo.effective-policy/1.0.0' $policy.policyId `
    'the effective-policy slice has one immutable release identity'
Assert-Equal 1 @($policy.collectors).Count `
    'one approved privileged attempt owns the bounded policy scopes'
$collector = $policy.collectors[0]
Assert-Equal 'observe-effective-policy' $collector.operationId `
    'the slice uses the already frozen privileged operation'
Assert-Equal 'Administrator' $collector.executionContext `
    'the read-only policy projection uses the approved privileged worker'
Assert-Equal 'OfflineOnly' $collector.networkBehavior `
    'cached local policy sources cannot contact a controller'
Assert-Equal 1 $collector.maximumAttempts 'the policy attempt never retries'
Assert-Equal 5000 $collector.deadlineMilliseconds 'the policy attempt is finite'
foreach ($flag in @('mayPrompt','mayInstall','mayDownload','maySelfElevate','writesAllowed')) {
    Assert-Equal $false ([bool]$collector.$flag) "the collector cannot widen authority through $flag"
}

$sourceIds = @($policy.sourceCatalog.sourceId)
$expectedSources = @(
    'source:windows.rsop.logging-mode',
    'source:windows.local-sam-policy',
    'source:windows.system-audit-policy',
    'source:windows.lsa-user-rights',
    'source:windows.local-security-option-signals'
)
Assert-Equal ($expectedSources -join '|') ($sourceIds -join '|') `
    'the structured source catalog is finite and ordered'
Assert-Equal 'RSOP_GPO,RSOP_GPLink,RSOP_PolicySetting,RSOP_RegistryPolicySetting' `
    (@($policy.sourceCatalog[0].classes) -join ',') `
    'applied-policy identity, links, and precedence use RSoP classes'
Assert-Equal 'RSOP_RegistryPolicySetting' $policy.sourceCatalog[0].supportedSettingClasses[0] `
    'only one finite derived setting class can produce stable setting evidence'
Assert-Equal 'root\RSOP\User\{AssessmentUserSid}' $policy.sourceCatalog[0].namespaces[0] `
    'user RSoP is frozen to the verified Assessment User SID namespace template'
Assert-Equal 'NetUserModalsGet(NULL,0|3)' $policy.sourceCatalog[1].interface `
    'local account policy is explicitly local SAM policy'

Assert-Equal 3 @($policy.auditSubcategories).Count `
    'the release owns a finite audit subcategory catalog'
Assert-Equal 3 @($policy.userRights).Count `
    'the release owns a finite user-right catalog'
Assert-Equal 3 @($policy.securityOptions).Count `
    'the release owns a finite security-option catalog'
Assert-Equal 'DirectAssignmentsOnly' $policy.userRightSemantics `
    'direct SID assignments are never expanded into effective group access'
Assert-Equal 'LocalSamAccountsOnly' $policy.localAccountPolicySemantics `
    'local account policy is never mislabeled as domain policy'

$layers = @($policy.layers.layerId)
Assert-Equal 'AppliedPolicyEvidence|ConfiguredPolicySignals|CurrentControlState' `
    ($layers -join '|') 'the three evidence layers remain distinct'
Assert-Equal 3 @($policy.rules).Count 'three rules each produce one finding'
foreach ($rule in $policy.rules) {
    foreach ($flag in @('mayPrompt','mayInstall','mayDownload','maySelfElevate','writesAllowed')) {
        Assert-Equal $false ([bool]$rule.$flag) `
            "the $($rule.ruleId) operation freezes $flag as false"
    }
}
Assert-Equal 15 @($policy.scopes).Count `
    'field-specific applied and local-policy coverage is release-closed'
$expectedScenarios = @(
    'Workgroup','Domain','UserAndComputerRsop','MissingRsop','StaleRegistry',
    'DeniedAdministrator','DeniedSystem','NonEnglish','AppliedOrderConflict',
    'AccountLockout','AuditPolicy','UserRights','SecurityOptions','PartialChannel'
)
Assert-Equal ($expectedScenarios -join '|') (@($policy.validationScenarios) -join '|') `
    'the ticket validation matrix is release-closed'

$text = Get-Content -LiteralPath $policyPath -Raw
if ($text -match '(?i)gpresult|secedit|net\.exe|LGPO|RSAT|GPMC|PsExec|mayInstall"\s*:\s*true') {
    throw 'The Effective Policy policy admits a presentation parser or prohibited tool.'
}

Write-Output 'PASS: Effective Policy layers, sources, bounds, catalogs, and scenarios are release-defined.'
