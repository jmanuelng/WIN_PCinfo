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
    'source:windows.local-configured-signals',
    'source:windows.security-center.providers',
    'source:windows.defender.runtime-status',
    'source:windows.defender.preferences',
    'source:windows.firewall.activestore-profiles',
    'source:windows.mdm-policy-csp-results',
    'source:windows.bitlocker.volume-status',
    'source:windows.device-guard.status',
    'source:windows.app-control.citool',
    'source:windows.applocker.gp-effective-policy',
    'source:windows.applocker.csp-policy'
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
Assert-Equal 'Get-BitLockerVolume' $policy.sourceCatalog[10].interface `
    'BitLocker evidence uses the bounded structured volume cmdlet'
Assert-Equal 'Get-CimInstance Win32_DeviceGuard' $policy.sourceCatalog[11].interface `
    'VBS and Credential Guard use the device-reported structured class'
Assert-Equal 'CiTool -lp -json' $policy.sourceCatalog[12].interface `
    'WDAC inventory is structured and never parsed from legacy text'
Assert-Equal 'Get-AppLockerPolicy -Effective' $policy.sourceCatalog[13].interface `
    'Group Policy AppLocker state stays on the GP-only surface'
Assert-Equal 'Get-CimInstance MDM_AppLocker_*' $policy.sourceCatalog[14].interface `
    'AppLocker CSP state stays on the separate WMI Bridge surface'

Assert-Equal 3 @($policy.auditSubcategories).Count `
    'the release owns a finite audit subcategory catalog'
Assert-Equal 3 @($policy.userRights).Count `
    'the release owns a finite user-right catalog'
Assert-Equal 3 @($policy.securityOptions).Count `
    'the release owns a finite local security-option catalog'
Assert-Equal 2 @($policy.discoveryTasks).Count `
    'tenant-side follow-up for incomplete MDM coverage is finite and release-owned'
Assert-Equal 'DirectAssignmentsOnly' $policy.userRightSemantics `
    'direct SID assignments are never expanded into effective group access'
Assert-Equal 'LocalSamAccountsOnly' $policy.localAccountPolicySemantics `
    'local account policy is never mislabeled as domain policy'

$layers = @($policy.layers.layerId)
Assert-Equal 'AppliedPolicyEvidence|ConfiguredPolicySignals|CurrentControlState' `
    ($layers -join '|') 'the three evidence layers remain distinct'
Assert-Equal 7 @($policy.rules).Count 'local policy, MDM conflict, and security-control rules each produce one finding'
foreach ($rule in $policy.rules) {
    foreach ($flag in @('mayPrompt','mayInstall','mayDownload','maySelfElevate','writesAllowed')) {
        Assert-Equal $false ([bool]$rule.$flag) `
            "the $($rule.ruleId) operation freezes $flag as false"
    }
}
Assert-Equal 35 @($policy.scopes).Count `
    'field-specific policy, platform-protection, app-control, and Policy CSP coverage is release-closed'
$expectedMdmScopes = @(
    'scope:policy.mdm.control-policy-conflict',
    'scope:policy.mdm.security-option.machine-inactivity-limit',
    'scope:policy.mdm.security-option.disable-cad',
    'scope:policy.mdm.security-option.lm-compatibility-level'
)
Assert-Equal ($expectedMdmScopes -join '|') (@($policy.scopes | Where-Object {
    $_.scopeId -like 'scope:policy.mdm.*'
} | ForEach-Object scopeId) -join '|') `
    'the MDM Policy CSP result scopes are explicit and finite'
$expectedSecurityScopes = @(
    'scope:policy.bitlocker.operating-system-volume',
    'scope:policy.bitlocker.protectors',
    'scope:policy.vbs.runtime',
    'scope:policy.wdac.inventory',
    'scope:policy.applocker.gp-channel',
    'scope:policy.applocker.csp-channel'
)
Assert-Equal ($expectedSecurityScopes -join '|') (@($policy.scopes | Where-Object {
    $_.scopeId -in $expectedSecurityScopes
} | ForEach-Object scopeId) -join '|') `
    'the new platform-protection and application-control scopes are explicit and finite'
$appLockerGpScope=@($policy.scopes|Where-Object {
    $_.scopeId -eq 'scope:policy.applocker.gp-channel'
})[0]
$appLockerCspScope=@($policy.scopes|Where-Object {
    $_.scopeId -eq 'scope:policy.applocker.csp-channel'
})[0]
Assert-Equal 'field:policy.applocker.gp.rule-collection|field:policy.applocker.gp.enforcement-mode' `
    (@($appLockerGpScope.fieldIds) -join '|') `
    'the GP AppLocker scope retains channel-specific field identities'
Assert-Equal 'field:policy.applocker.csp.rule-collection|field:policy.applocker.csp.enforcement-mode' `
    (@($appLockerCspScope.fieldIds) -join '|') `
    'the CSP AppLocker scope retains channel-specific field identities'
$expectedScenarios = @(
    'Workgroup','Domain','UserAndComputerRsop','MissingRsop','StaleRegistry',
    'DeniedAdministrator','DeniedSystem','NonEnglish','AppliedOrderConflict',
    'AccountLockout','AuditPolicy','UserRights','SecurityOptions','PartialChannel',
    'NonMdm','UnsupportedMdmBuild','MissingMdmClass','MissingMdmProperty',
    'MdmPolicyConflict','MdmWinsOverGpScoped','ThirdPartyRegistration',
    'DefenderDisabled','DefenderUnavailable','AmbiguousSecurityCenter',
    'TamperProtected','MissingDefenderProperty','FirewallProfiles','AsrRulePairs',
    'BitLockerEncrypted','BitLockerUnencrypted','BitLockerUnknown',
    'VbsCredentialGuardRunning','VbsConfiguredNotRunning','WdacWindows11Policies',
    'WdacWindows10Unsupported','AppLockerGpOnly','AppLockerCspOnly',
    'AppLockerGpCspConflict','AppLockerChannelIncomplete','VirtualMachineSecurity'
)
Assert-Equal ($expectedScenarios -join '|') (@($policy.validationScenarios) -join '|') `
    'the ticket validation matrix is release-closed'

$text = Get-Content -LiteralPath $policyPath -Raw
if ($text -match '(?i)gpresult|secedit|net\.exe|LGPO|RSAT|GPMC|PsExec|mayInstall"\s*:\s*true') {
    throw 'The Effective Policy policy admits a presentation parser or prohibited tool.'
}

Write-Output 'PASS: Effective Policy layers, sources, bounds, catalogs, and scenarios are release-defined.'
