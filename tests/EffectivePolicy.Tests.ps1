[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/EffectivePolicy.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$policy = Get-EffectivePolicyPolicy -ConvertFromJsonCommand (
    Get-Command ConvertFrom-Json -CommandType Cmdlet
)
$expected = @{
    Workgroup = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false }
    Domain = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false }
    UserAndComputerRsop = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=3; conflict=$false }
    MissingRsop = @{ applied='Unsupported'; configured='Complete'; local='Complete'; policies=0; conflict=$false }
    StaleRegistry = @{ applied='Complete'; configured='Partial'; local='Complete'; policies=2; conflict=$false }
    DeniedAdministrator = @{ applied='Denied'; configured='Denied'; local='Denied'; policies=0; conflict=$false }
    DeniedSystem = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false }
    NonEnglish = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false }
    AppliedOrderConflict = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$true }
    AccountLockout = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false }
    AuditPolicy = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false }
    UserRights = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false }
    SecurityOptions = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false }
    PartialChannel = @{ applied='Partial'; configured='Partial'; local='Partial'; policies=8; conflict=$false }
    NonMdm = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false }
    UnsupportedMdmBuild = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false }
    MissingMdmClass = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false }
    MissingMdmProperty = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false }
    MdmPolicyConflict = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false }
    MdmWinsOverGpScoped = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false }
}

$partial = (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario PartialChannel).payload
Assert-Equal 'Complete' $partial.scopeStates[4].state `
    'a missing RSoP link class does not erase successful object identity'
Assert-Equal 'Partial' $partial.scopeStates[6].state `
    'multiple enabled RSoP links remain ambiguous instead of selecting one'
Assert-Equal 'POLICY.RSOP_EXTENSION_UNSUPPORTED' $partial.scopeStates[3].reasonCode `
    'an unsupported RSoP extension remains outside the finite setting catalog'
Assert-Equal 'POLICY.RSOP_EVIDENCE_BOUND_EXCEEDED' $partial.scopeStates[7].reasonCode `
    'a ninth source setting is omitted only with explicit bounded Partial coverage'
Assert-Equal 8 @($partial.policySettings).Count `
    'the overflow seam retains only the frozen setting bound'
Assert-Equal 'Complete' $partial.scopeStates[8].state `
    'a failed lockout NetAPI level preserves successful password-policy evidence'
Assert-Equal 'Failed' $partial.scopeStates[9].state `
    'the failed lockout NetAPI level remains a field-specific gap'
$inconsistent=(Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario PartialChannel).payload
$inconsistent.layerStates.AppliedPolicyEvidence='Complete'
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $inconsistent -Policy $policy) `
    'a worker cannot contradict field-specific scope gaps with an affirmative layer state'
$openExtension=(Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario Workgroup).payload
$openExtension.policySettings[0].settingId='extension-relative-id'
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $openExtension -Policy $policy) `
    'an unapproved extension-relative setting identity cannot enter the finite catalog'

foreach ($scenario in $policy.validationScenarios) {
    $result = Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario $scenario
    Assert-Equal 'Completed' $result.state "$scenario returns one bounded collector result"
    Assert-Equal $true (Test-EffectivePolicyCollectorPayload -Payload $result.payload -Policy $policy) `
        "$scenario satisfies the closed structured projection"
    Assert-Equal $expected[$scenario].applied $result.payload.layerStates.AppliedPolicyEvidence `
        "$scenario keeps applied-policy coverage explicit"
    Assert-Equal $expected[$scenario].configured $result.payload.layerStates.ConfiguredPolicySignals `
        "$scenario keeps configured signals separate from current control state"
    Assert-Equal $expected[$scenario].local $result.payload.layerStates.CurrentControlState `
        "$scenario keeps current local-control coverage explicit"
    Assert-Equal $expected[$scenario].policies @($result.payload.appliedPolicies).Count `
        "$scenario preserves the bounded applied-policy count"
    Assert-Equal $expected[$scenario].conflict ([bool]$result.payload.appliedOrderConflict) `
        "$scenario does not infer an order conflict from missing evidence"
    Assert-Equal 3 @($result.payload.auditSubcategories).Count `
        "$scenario retains the exact audit catalog"
    Assert-Equal 3 @($result.payload.userRights).Count `
        "$scenario retains the exact direct-rights catalog"
    Assert-Equal 3 @($result.payload.securityOptions).Count `
        "$scenario retains the exact security-option catalog"
    Assert-Equal 'LocalSamAccountsOnly' $result.payload.localAccountPolicySemantics `
        "$scenario never labels local SAM policy as domain policy"
    Assert-Equal 'DirectAssignmentsOnly' $result.payload.userRightSemantics `
        "$scenario never expands SID rights through group membership"
}

$invalid = (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario Workgroup).payload
$invalid.appliedPolicies[0].objectId = 'localized display name'
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $invalid -Policy $policy) `
    'localized or unstable applied-policy identities are rejected'
$smuggled = (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario Workgroup).payload
$smuggled.appliedPolicies[0] | Add-Member -NotePropertyName credential -NotePropertyValue 'must-not-cross'
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $smuggled -Policy $policy) `
    'undeclared nested worker properties fail the closed collector contract'

$failedSources = (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario Workgroup).payload
$failedSources.auditSubcategories[0].state = 'Failed'
$failedSources.auditSubcategories[0].successEnabled = $null
$failedSources.auditSubcategories[0].failureEnabled = $null
$failedSources.userRights[0].state = 'Failed'
$failedSources.securityOptions[0].state = 'Failed'
$failedSources.securityOptions[0].value = $null
Assert-Equal $true (Test-EffectivePolicyCollectorPayload -Payload $failedSources -Policy $policy) `
    'typed generic provider failures remain valid gaps instead of corrupting the whole payload'
$boundedRight = (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario Workgroup).payload
$boundedRight.userRights[0].state='Partial'
$boundedRight.userRights[0].directSids=@('S-1-5-32-544')
$boundedRight.scopeStates[11].state='Partial'
$boundedRight.scopeStates[11].reasonCode='POLICY.USER_RIGHTS_EVIDENCE_BOUND_EXCEEDED'
$boundedRight.layerStates.CurrentControlState='Partial'
Assert-Equal $true (Test-EffectivePolicyCollectorPayload -Payload $boundedRight -Policy $policy) `
    'a bounded direct-right subset remains evidence only under explicit Partial coverage'

$projection = New-EffectivePolicyPublicProjection -CollectorResult (
    Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario NonEnglish
)
Assert-Equal 'win-pcinfo.effective-policy-validation' $projection.recordType `
    'the public validation projection is explicitly synthetic'
Assert-Equal 2 $projection.appliedPolicyCount 'the public projection carries only a safe count'
if (($projection | ConvertTo-Json -Depth 10) -match '(?i)SYNTHETIC-DOMAIN|ÉQUIPE|[0-9a-f]{8}-[0-9a-f]{4}-') {
    throw 'Restricted policy identity or localized evidence entered the public projection.'
}
$seeded=Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario Domain
$seeded.payload.appliedPolicies[0].objectId='deadbeef-dead-4eef-8eef-deadbeef0001'
$seeded.payload.appliedPolicies[0].linkId='restricted-arbitrary-link'
$seeded.payload.policySettings[0].objectId='deadbeef-dead-4eef-8eef-deadbeef0001'
$seeded.payload.policySettings[0].settingId='registry:restricted-arbitrary-setting'
$seedProjection=New-EffectivePolicyPublicProjection -CollectorResult $seeded
if(($seedProjection|ConvertTo-Json -Compress -Depth 10) -match 'deadbeef|restricted-arbitrary'){
    throw 'An arbitrary Restricted policy identifier entered the public projection.'
}

Write-Output 'PASS: Effective Policy fixtures preserve three-layer semantics, bounded catalogs, and privacy.'
