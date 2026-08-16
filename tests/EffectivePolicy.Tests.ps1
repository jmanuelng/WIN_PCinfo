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
    Workgroup = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    Domain = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    UserAndComputerRsop = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=3; conflict=$false; firewalls=1 }
    MissingRsop = @{ applied='Unsupported'; configured='Complete'; local='Complete'; policies=0; conflict=$false; firewalls=1 }
    StaleRegistry = @{ applied='Complete'; configured='Partial'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    DeniedAdministrator = @{ applied='Denied'; configured='Denied'; local='Denied'; policies=0; conflict=$false; firewalls=0 }
    DeniedSystem = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    NonEnglish = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    AppliedOrderConflict = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$true; firewalls=1 }
    AccountLockout = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    AuditPolicy = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    UserRights = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    SecurityOptions = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    PartialChannel = @{ applied='Partial'; configured='Partial'; local='Partial'; policies=8; conflict=$false; firewalls=1 }
    NonMdm = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    UnsupportedMdmBuild = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    MissingMdmClass = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    MissingMdmProperty = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    MdmPolicyConflict = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    MdmWinsOverGpScoped = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    WindowsUpdatePolicy = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    RemoteManagementCombinations = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    SmbPosture = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    LegacyAuthMasks = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=2; conflict=$false; firewalls=1 }
    ThirdPartyRegistration = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    DefenderDisabled = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    DefenderUnavailable = @{ applied='Complete'; configured='Partial'; local='Partial'; policies=1; conflict=$false; firewalls=1 }
    AmbiguousSecurityCenter = @{ applied='Complete'; configured='Complete'; local='Partial'; policies=1; conflict=$false; firewalls=1 }
    TamperProtected = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    MissingDefenderProperty = @{ applied='Complete'; configured='Complete'; local='Partial'; policies=1; conflict=$false; firewalls=1 }
    FirewallProfiles = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    AsrRulePairs = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    BitLockerEncrypted = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    BitLockerUnencrypted = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    BitLockerUnknown = @{ applied='Complete'; configured='Complete'; local='Partial'; policies=1; conflict=$false; firewalls=1 }
    VbsCredentialGuardRunning = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    VbsConfiguredNotRunning = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    WdacWindows11Policies = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    WdacWindows10Unsupported = @{ applied='Complete'; configured='Partial'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    AppLockerGpOnly = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    AppLockerCspOnly = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    AppLockerGpCspConflict = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    AppLockerChannelIncomplete = @{ applied='Complete'; configured='Partial'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
    VirtualMachineSecurity = @{ applied='Complete'; configured='Complete'; local='Complete'; policies=1; conflict=$false; firewalls=1 }
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
    Assert-Equal $expected[$scenario].firewalls @($result.payload.firewallProviders).Count `
        "$scenario retains the expected firewall-provider evidence volume"
    Assert-Equal $true $result.payload.PSObject.Properties.Name.Contains('bitLockerSystemVolume') `
        "$scenario includes the bounded BitLocker system-volume projection"
    Assert-Equal $true $result.payload.PSObject.Properties.Name.Contains('bitLockerProtectors') `
        "$scenario includes the bounded BitLocker protector-type projection"
    Assert-Equal $true $result.payload.PSObject.Properties.Name.Contains('deviceGuard') `
        "$scenario includes the bounded VBS and Credential Guard projection"
    Assert-Equal $true $result.payload.PSObject.Properties.Name.Contains('wdacPolicies') `
        "$scenario includes the bounded WDAC inventory projection"
    Assert-Equal $true $result.payload.PSObject.Properties.Name.Contains('appLockerGpCollections') `
        "$scenario includes the separate AppLocker GP projection"
    Assert-Equal $true $result.payload.PSObject.Properties.Name.Contains('appLockerCspCollections') `
        "$scenario includes the separate AppLocker CSP projection"
    Assert-Equal $true $result.payload.PSObject.Properties.Name.Contains('windowsUpdateSignals') `
        "$scenario includes the finite Windows Update and WUfB registry projection"
    Assert-Equal $true $result.payload.PSObject.Properties.Name.Contains('legacyAuthenticationSignals') `
        "$scenario includes the finite legacy-auth registry projection"
    Assert-Equal $true $result.payload.PSObject.Properties.Name.Contains('rdpState') `
        "$scenario includes the structured RDP projection"
    Assert-Equal $true $result.payload.PSObject.Properties.Name.Contains('winrmState') `
        "$scenario includes the structured WinRM projection"
    Assert-Equal $true $result.payload.PSObject.Properties.Name.Contains('smbState') `
        "$scenario includes the structured SMB projection"
    Assert-Equal 3 @($result.payload.smartScreenSignals).Count `
        "$scenario retains the exact SmartScreen signal catalog"
    Assert-Equal 3 @($result.payload.firewallProfiles.PSObject.Properties).Count `
        "$scenario retains the exact firewall ActiveStore profile catalog"
    Assert-Equal 'LocalSamAccountsOnly' $result.payload.localAccountPolicySemantics `
        "$scenario never labels local SAM policy as domain policy"
    Assert-Equal 'DirectAssignmentsOnly' $result.payload.userRightSemantics `
        "$scenario never expands SID rights through group membership"
}

Assert-Equal 2 @(Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario AmbiguousSecurityCenter).payload.antivirusProviders.Count `
    'ambiguous Security Center registration preserves both bounded provider identities privately'
Assert-Equal $true (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario TamperProtected).payload.defenderRuntime.tamperProtected `
    'tamper protection remains a typed constraint signal instead of a generic failure'
Assert-Equal 2 @(Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario AsrRulePairs).payload.defenderAsrRules.Count `
    'ASR rule GUID-action pairs remain bounded and distinct'
Assert-Equal 'On' (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario BitLockerEncrypted).payload.bitLockerSystemVolume.protectionStatus `
    'encrypted BitLocker state preserves bounded protection status only'
Assert-Equal 'Off' (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario BitLockerUnencrypted).payload.bitLockerSystemVolume.protectionStatus `
    'unencrypted BitLocker state remains explicit instead of inferred from protectors'
Assert-Equal 0 @(Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario WdacWindows10Unsupported).payload.wdacPolicies.Count `
    'unsupported WDAC inventory publishes no fabricated policy rows'
Assert-Equal 1 @(Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario AppLockerGpOnly).payload.appLockerGpCollections.Count `
    'AppLocker GP-only evidence stays in the GP channel only'
Assert-Equal 1 @(Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario AppLockerCspOnly).payload.appLockerCspCollections.Count `
    'AppLocker CSP-only evidence stays in the CSP channel only'
Assert-Equal 'EnabledAndRunning' (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario VbsCredentialGuardRunning).payload.deviceGuard.virtualizationBasedSecurityStatus `
    'VBS running state uses the device-reported structured value'
Assert-Equal 3 @(Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario WindowsUpdatePolicy).payload.windowsUpdateSignals.Count `
    'Windows Update registry mappings remain a finite configured-signal catalog'
Assert-Equal 'Https5986Only' (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario RemoteManagementCombinations).payload.winrmState.listenerState `
    'WinRM listener posture stays separate from remote reachability'
Assert-Equal 'Ssl' (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario RemoteManagementCombinations).payload.rdpState.securityLayer `
    'RDP authentication state stays on the documented listener configuration seam'
Assert-Equal 'Disabled' (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario SmbPosture).payload.smbState.smb1FeatureState `
    'SMB1 feature state remains explicit instead of inferred from shares or sessions'
Assert-Equal 3 @(Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario LegacyAuthMasks).payload.legacyAuthenticationSignals.Count `
    'legacy-auth evidence remains a finite registry-name and mask catalog'

$invalid = (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario Workgroup).payload
$invalid.appliedPolicies[0].objectId = 'localized display name'
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $invalid -Policy $policy) `
    'localized or unstable applied-policy identities are rejected'
$smuggled = (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario Workgroup).payload
$smuggled.appliedPolicies[0] | Add-Member -NotePropertyName credential -NotePropertyValue 'must-not-cross'
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $smuggled -Policy $policy) `
    'undeclared nested worker properties fail the closed collector contract'
$bitlockerSecrets = (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario BitLockerEncrypted).payload
$bitlockerSecrets.bitLockerSystemVolume | Add-Member -NotePropertyName recoveryPassword -NotePropertyValue '123456-123456-123456-123456-123456-123456-123456-123456'
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $bitlockerSecrets -Policy $policy) `
    'BitLocker recovery material cannot enter the collector payload'
$bitlockerProtectorIdentifier = (Invoke-EffectivePolicyCollection -Policy $policy -ValidationScenario BitLockerEncrypted).payload
$bitlockerProtectorIdentifier.bitLockerProtectors[0] | Add-Member -NotePropertyName protectorId -NotePropertyValue '{synthetic-protector-guid}'
Assert-Equal $false (Test-EffectivePolicyCollectorPayload -Payload $bitlockerProtectorIdentifier -Policy $policy) `
    'BitLocker protector identifiers cannot cross the bounded payload'

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
Assert-Equal $true $projection.PSObject.Properties.Name.Contains('bitLockerProtectorTypeCount') `
    'the public projection carries only a safe BitLocker protector count'
Assert-Equal $true $projection.PSObject.Properties.Name.Contains('wdacPolicyCount') `
    'the public projection carries only a safe WDAC policy count'
Assert-Equal $true $projection.PSObject.Properties.Name.Contains('appLockerGpCollectionCount') `
    'the public projection carries only a safe AppLocker GP count'
Assert-Equal $true $projection.PSObject.Properties.Name.Contains('appLockerCspCollectionCount') `
    'the public projection carries only a safe AppLocker CSP count'
Assert-Equal $true $projection.PSObject.Properties.Name.Contains('windowsUpdateSignalCoverage') `
    'the public projection carries only the safe Windows Update signal coverage state'
Assert-Equal $true $projection.PSObject.Properties.Name.Contains('remoteManagementCoverage') `
    'the public projection carries only the safe remote-management coverage state'
Assert-Equal $true $projection.PSObject.Properties.Name.Contains('smbCoverage') `
    'the public projection carries only the safe SMB coverage state'
Assert-Equal $true $projection.PSObject.Properties.Name.Contains('legacyAuthenticationCoverage') `
    'the public projection carries only the safe legacy-auth coverage state'
Assert-Equal $true $projection.PSObject.Properties.Name.Contains('updateScanAttempted') `
    'the public projection explicitly records that no update scan was attempted'
Assert-Equal $false $projection.updateScanAttempted `
    'the public projection never claims an update scan was attempted'
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
