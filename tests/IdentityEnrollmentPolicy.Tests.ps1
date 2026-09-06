[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-identity-enrollment.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/identity-enrollment.schema.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

if (-not (Test-Json -Json (Get-Content -LiteralPath $policyPath -Raw) `
        -SchemaFile $schemaPath)) {
    throw 'The release Identity and Enrollment policy does not satisfy its schema.'
}

$policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json -Depth 20
Assert-Equal 'win-pcinfo.identity-enrollment/1.0.0' $policy.policyId `
    'the identity slice has one immutable release identity'
Assert-Equal 'profile:device-firmware-and-identity-readiness' $policy.evidenceProfileId `
    'the generated application has one closed combined evidence profile'

$expectedCollectors = @{
    'observe-device-registration' = 'StandardUser'
    'observe-enrollment-context' = 'StandardUser'
    'observe-mdm-system-context' = 'LocalSystem'
}
Assert-Equal 3 @($policy.collectors).Count `
    'registration, user-scoped enrollment, and SYSTEM MDM context retain separate authority'
foreach ($collector in @($policy.collectors)) {
    Assert-Equal $expectedCollectors[[string]$collector.operationId] ([string]$collector.executionContext) `
        'every collector has the exact execution context frozen before approval'
    Assert-Equal 'OfflineOnly' ([string]$collector.networkBehavior) `
        'identity collection never authenticates or contacts a tenant'
    Assert-Equal $false ([bool]$collector.mayPrompt) 'collection cannot prompt'
    Assert-Equal $false ([bool]$collector.mayInstall) 'collection cannot install'
    Assert-Equal $false ([bool]$collector.mayDownload) 'collection cannot download'
    Assert-Equal $false ([bool]$collector.maySelfElevate) 'collection cannot self-elevate'
    Assert-Equal $false ([bool]$collector.writesAllowed) 'collection cannot modify join or enrollment state'
    Assert-Equal 1 ([int]$collector.maximumAttempts) 'collection does not retry identity sources'
    Assert-Equal 5000 ([int]$collector.deadlineMilliseconds) 'every source attempt has a finite deadline'
}
foreach ($collector in @($policy.collectors | Select-Object -First 2)) {
    Assert-Equal 'ActiveMicrosoftSignedPowerShellHost' ([string]$collector.executable) `
        'standard identity APIs run in a supervisor-owned deadline boundary'
    Assert-Equal 'CoordinatorOwnedJobObjectAndWorkerVerifiedAbsent' ([string]$collector.cleanup) `
        'timeout proves the complete native-source worker absent'
}

Assert-Equal 'Windows NetGetJoinInformation API' $policy.collectors[0].dependencies[0] `
    'domain join never depends on localized command output'
Assert-Equal 'Windows NetGetAadJoinInformation API' $policy.collectors[0].dependencies[1] `
    'Entra registration uses a structured Windows API'
Assert-Equal 'Windows Terminal Services session APIs' $policy.collectors[0].dependencies[2] `
    'Assessment User Context is verified independently from process identity'
Assert-Equal 'Windows LSA logon session APIs' $policy.collectors[0].dependencies[3] `
    'the active session is bound to a Windows security principal, not a display name'

$expectedScopes = @(
    'scope:identity.assessment-user-context',
    'scope:device.registration-context',
    'scope:device.work-school-registration-context',
    'scope:device.mdm-policy.system'
)
Assert-Equal ($expectedScopes -join '|') (@($policy.scopes.scopeId) -join '|') `
    'user, registration, work-school, and enrollment gaps cannot substitute for one another'

Assert-Equal 3 @($policy.rules).Count `
    'each release rule produces exactly one identity or enrollment finding'
foreach ($rule in @($policy.rules)) {
    Assert-Equal 'SupervisedValidatedAssessmentRecord' ([string]$rule.executionContext) `
        'rules evaluate only bounded inputs projected from the admitted canonical record'
    Assert-Equal 'ActiveMicrosoftSignedPowerShellHost' ([string]$rule.executable) `
        'a hung release rule has an owned process termination boundary'
    Assert-Equal 2000 ([int]$rule.deadlineMilliseconds) `
        'each rule has enough bounded startup and termination time'
    Assert-Equal 'Indeterminate' ([string]$rule.missingEvidenceOutcome) `
        'missing identity evidence cannot become a negative conclusion'
    Assert-Equal 1 ([int]$rule.maximumOutputFindings) 'one rule produces one finding'
}

$expectedTasks = @(
    'task:confirm-tenant-device-assignment/1.0.0',
    'task:confirm-tenant-compliance/1.0.0',
    'task:confirm-tenant-licensing/1.0.0',
    'task:confirm-organization-enrollment-intent/1.0.0',
    'task:confirm-approved-administrator-context/1.0.0',
    'task:confirm-recovery-escrow/1.0.0'
)
Assert-Equal ($expectedTasks -join '|') (@($policy.discoveryTasks.definitionId) -join '|') `
    'tenant-only questions remain bounded discovery tasks rather than local claims'

$expectedScenarios = @(
    'Workgroup','DomainJoined','EntraJoined','Registered','Mixed','Unenrolled',
    'UserContextUnavailable','StandardUser','Administrator','LocalSystem',
    'NonEnglish','Malformed','Denied'
)
Assert-Equal ($expectedScenarios -join '|') (@($policy.validationScenarios) -join '|') `
    'the issue-defined identity and enrollment validation matrix is closed'

$policyText = Get-Content -LiteralPath $policyPath -Raw
if ($policyText -match '(?i)dsregcmd|password|accessToken|refreshToken|privateKey|recoveryKey') {
    throw 'The identity policy admits localized text parsing or prohibited secret material.'
}

Write-Output 'PASS: Identity and Enrollment sources, contexts, bounds, rules, and scenarios are release-defined.'
