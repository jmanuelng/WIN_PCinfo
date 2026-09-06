$script:EffectivePolicyPolicyBase64 = '__EFFECTIVE_POLICY_POLICY_BASE64__'
$script:EffectivePolicyPolicyDigest = '__EFFECTIVE_POLICY_POLICY_SHA256__'

function Get-EffectivePolicySha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function New-EffectivePolicySecurityReportSection {
    param([Parameter(Mandatory)]$Record)
    # The caller has validated this record. Coverage binds each observation to
    # its scope; display labels never select evidence or change rule outcomes.
    $titles=[ordered]@{
        'defender.runtime'='Defender Antivirus and tamper protection'
        'defender.asr'='Attack surface reduction'
        'defender.network-protection'='Network protection'
        'smartscreen.shell'='SmartScreen shell signals'
        'smartscreen.app-install-control'='SmartScreen application-install signal'
        'firewall.domain-profile'='Firewall: Domain profile'
        'firewall.private-profile'='Firewall: Private profile'
        'firewall.public-profile'='Firewall: Public profile'
        'security-center.antivirus-providers'='Registered antivirus providers'
        'security-center.firewall-providers'='Registered firewall providers'
        'vbs.runtime'='Virtualization-based security and Credential Guard'
        'bitlocker.operating-system-volume'='BitLocker operating-system volume'
        'bitlocker.protectors'='BitLocker protector types and counts'
        'applocker.gp-channel'='AppLocker Group Policy channel'
        'applocker.csp-channel'='AppLocker CSP channel'
        'wdac.inventory'='App Control for Business (WDAC) inventory'
        'windows-update.defer-feature-updates'='Windows Update and WUfB: feature-update deferral signal'
        'windows-update.defer-quality-updates'='Windows Update and WUfB: quality-update deferral signal'
        'windows-update.disable-dual-scan'='Windows Update and WUfB: legacy dual-scan signal'
        'rdp.connections'='RDP connection configuration'
        'rdp.service'='RDP service configuration and observed state'
        'rdp.authentication'='RDP authentication configuration'
        'rdp.listener'='RDP listener configuration'
        'winrm.service'='WinRM service configuration and observed state'
        'winrm.configuration'='WinRM policy signals: unencrypted traffic'
        'winrm.authentication'='WinRM authentication configuration'
        'winrm.listener'='WinRM local listener configuration'
        'smb.client'='SMB client configuration'
        'smb.server'='SMB server configuration'
        'smb.smb1-feature'='SMB1 optional-feature state'
        'legacy-auth.lm-compatibility-level'='Legacy authentication: LAN Manager compatibility signal'
        'legacy-auth.ntlm-minimum-session-security'='Legacy authentication: NTLM session-security masks'
    }
    $observations=@{};foreach($item in $Record.observations){$observations[[string]$item.observationId]=$item}
    $provenance=@{};foreach($item in $Record.provenance){$provenance[[string]$item.provenanceId]=$item}
    # Share only identical provenance tuples; each observation keeps its own
    # reference and field. Distinct subjects, sources and collection times
    # always receive separate entries, irrespective of displayed values.
    $sourceIndex=[Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
    $sourceRows=[Collections.Generic.List[string]]::new()
    $contextIndex=[Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
    $contextRows=[Collections.Generic.List[string]]::new()
    $observationPrefix = 'observation:policy-'
    $observationSuffix = ':' + [string]$Record.run.runId
    $sections=foreach($key in $titles.Keys){
        $scope=@($Record.coverage|Where-Object scopeId -eq "scope:policy.$key")[0]
        $layer=if($key -like 'smartscreen.*' -or $key -like 'applocker.*' -or $key -in @('defender.asr','defender.network-protection','wdac.inventory')){'Configured Policy Signals'}else{'Current Control State'}
        if($key -like 'windows-update.*' -or $key -like 'legacy-auth.*' -or $key -in @('rdp.connections','rdp.authentication','rdp.listener','winrm.configuration','winrm.authentication','winrm.listener','smb.client','smb.server')){$layer='Configured Policy Signals'}
        if($key -in @('rdp.service','winrm.service')){$layer='Start mode is configuration; service state is Current Control State'}
        $reason=if($scope.PSObject.Properties['reasonCode']){' ('+[Net.WebUtility]::HtmlEncode([string]$scope.reasonCode)+')'}else{''}
        $rows=foreach($id in $scope.observationIds){
            $observation=$observations[[string]$id];$origin=$provenance[[string]$observation.provenanceId]
            $sourceValues=@([string]$observation.subjectId,[string]$origin.sourceId,
                [string]$origin.executionContext,[string]$origin.collectedAt,[string]$origin.sourceLocale)
            $sourceKey=($sourceValues|ForEach-Object {$_.Length.ToString()+':'+$_}) -join ''
            if(-not $sourceIndex.ContainsKey($sourceKey)){
                $sourceNumber=$sourceRows.Count+1;$sourceIndex.Add($sourceKey,$sourceNumber)
                $encoded=@($sourceValues|ForEach-Object {[Net.WebUtility]::HtmlEncode($_)})
                $contextValues=@($sourceValues[0])+$sourceValues[2..4]
                $contextKey=($contextValues|ForEach-Object {$_.Length.ToString()+':'+$_}) -join ''
                if(-not $contextIndex.ContainsKey($contextKey)){
                    $contextNumber=$contextRows.Count+1;$contextIndex.Add($contextKey,$contextNumber)
                    $contextRows.Add('<li id="sc'+$contextNumber+'">Context '+$contextNumber+
                        '<br>Subject: '+$encoded[0]+'<br>Execution context: '+$encoded[2]+
                        '<br>Collected: '+$encoded[3]+'<br>Source locale: '+$encoded[4]+'</li>')
                }
                $sourceRows.Add('<li id="ss'+$sourceNumber+'">Source '+$sourceNumber+
                    ': '+$encoded[1]+'; <a href="#sc'+$contextIndex[$contextKey]+
                    '">Context '+$contextIndex[$contextKey]+'</a></li>')
            }
            $sourceNumber=$sourceIndex[$sourceKey]
            $value=switch([string]$observation.valueState){
                ObservedValue {[Convert]::ToString($observation.value,[Globalization.CultureInfo]::InvariantCulture)}
                ObservedAbsent {'Observed absent in this source scope'}
                SourceReportedUnknown {'Source reported unknown'}
            }
            $reference = if (([string]$id).StartsWith($observationPrefix, [StringComparison]::Ordinal) -and
                ([string]$id).EndsWith($observationSuffix, [StringComparison]::Ordinal)) {
                ([string]$id).Substring($observationPrefix.Length, ([string]$id).Length - $observationPrefix.Length - $observationSuffix.Length)
            } else { 'Full: ' + [string]$id }
            $field = [string]$observation.fieldId
            $field = if ($field.StartsWith('field:policy.', [StringComparison]::Ordinal)) { $field.Substring(13) } else { 'Full: ' + $field }
            '<tr><td>'+[Net.WebUtility]::HtmlEncode($field)+
                '<td>'+[Net.WebUtility]::HtmlEncode($value)+
                '<td>'+[Net.WebUtility]::HtmlEncode($reference)+
                '<td><a href="#ss'+$sourceNumber+'">'+$sourceNumber+'</a></tr>'
        }
        $evidence=if(@($rows).Count){$rows -join ''}else{'<tr><td colspan="4">No usable observation was returned for this scope. Review its coverage reason; do not infer enabled or disabled protection.</tr>'}
        '<tbody><tr><th colspan="4" scope="rowgroup"><h3>'+[Net.WebUtility]::HtmlEncode([string]$titles[$key])+'</h3><p>'+ $layer+
            '. Coverage: '+[Net.WebUtility]::HtmlEncode([string]$scope.state)+$reason+'</p></th></tr>'+$evidence+'</tbody>'
    }
    '<section aria-label="Security control evidence"><h2>Security and platform protection</h2>'+
        '<p>These are local, source-backed observations. Defender preferences and SmartScreen registry signals do not prove applied organizational policy or current enforcement. Firewall ActiveStore describes each profile, not reachability. Registration names and category health do not identify a winning antivirus product.</p>'+
        '<p>BitLocker status describes the local OS volume; protector types and counts do not prove recovery escrow. VBS distinguishes configured services from running services. AppLocker Group Policy and CSP remain separate channels, and configured enforcement does not prove an application was blocked. CiTool reports whether a WDAC policy is active; this does not identify its audit options or deployment channel. Unknown channel and incomplete evidence require discovery with the policy owner.</p>'+
        (New-EffectivePolicyRemoteGuidance -Record $Record)+
        '<details><summary>Security observations and coverage</summary><div class="evidence-table" tabindex="0" role="region" aria-label="Security evidence"><table><caption>Field prefix: field:policy. except cells marked Full. Observation ID = prefix + cell + suffix, except cells marked Full. Prefix: <code>'+ $observationPrefix +
        '</code>; suffix: <code>' + [Net.WebUtility]::HtmlEncode($observationSuffix) + '</code>.</caption><thead><tr><th scope="col">Field</th><th scope="col">Value</th><th scope="col">Observation</th><th scope="col">Source</th></tr></thead>'+($sections -join '')+'</table></div></details>'+
        '<h3>Security evidence sources</h3><ul>'+($sourceRows -join '')+'</ul>'+
        '<h3>Security collection contexts</h3><ul>'+($contextRows -join '')+'</ul>'+
        '<p>Use the versioned advisory findings and next steps in this report to plan follow-up with the device and security-policy owners. Confirm current state, intended policy, applicable Windows and Defender versions, and tenant-side assignments before considering a change. Passive mode and tamper protection are constraints to investigate, not collection failures or compliance verdicts. Missing or bounded evidence remains a gap. WIN-PCInfo does not change these controls.</p></section>'
}

function New-EffectivePolicyRemoteGuidance {
    param([Parameter(Mandatory)]$Record)
    $build=@($Record.observations|Where-Object { $_.fieldId -eq 'field:device.windows.build' -and $_.valueState -eq 'ObservedValue' })
    $context='Windows applicability is unknown or outside this guidance catalog. Confirm the OS build and edition before interpreting configuration.'
    if($build.Count -eq 1){
        if([long]$build[0].value -in @(19041,19042,19043,19044,19045)){
            $context='Windows 10 guidance: DisableDualScan is a legacy signal replaced by the scan-source policy; confirm the intended update source with the policy owner.'
        }elseif([long]$build[0].value -in @(22000,22621,22631,26100,26200)){
            $context='Windows 11 guidance: DisableDualScan is not supported. A retained registry value is a potentially stale signal, not evidence of scan behavior.'
        }
    }
    '<aside aria-label="Update and remote-management guidance"><h3>Update and remote-management follow-up</h3><p>Guidance: update-remote-auth/1.0.0. '+$context+'</p>'+
        '<p>Registry values may outlive the policy that wrote them. Deferral periods alone do not establish an active update ring, successful updates, tenant assignments or organization-wide enforcement. Missing values do not establish defaults. Applied Policy Evidence, configured signals and service runtime remain separate.</p>'+
        '<p>RDP listener configuration does not establish reachability or use. WinRM reads Service policy signals, explicit local certificate-authentication and listener configuration, and separate service state. Listener coverage stays partial: policy-created, compatibility and default listeners, configuration freshness, overrides and current listening are not established. Multiple local records retain only a shared transport or port; differing values remain unknown. Missing registry values never imply disabled authentication or no listener. No WSMan request is permitted by this collector in either network mode.</p>'+
        '<p>SMB client and server signing, encryption and guest settings describe configuration only. EnableSecuritySignature is ignored by SMB2 and newer; it does not prove negotiated signing. SMB1 feature state does not prove use. LAN Manager compatibility and NTLM security masks do not prove authentication traffic, dependencies or organization-wide restrictions.</p>'+
        '<p>Before migration, ask the device and policy owners to compare these fields with approved policy and separately authorized protocol-use discovery. Verify Windows edition/build applicability, update source, remote-access dependencies and legacy authentication consumers before planning any change. WIN-PCInfo does not enable services, probe endpoints or change these settings.</p></aside>'
}

function Get-EffectivePolicyPolicy {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    if ($script:EffectivePolicyPolicyBase64 -eq ('__EFFECTIVE_POLICY_' + 'POLICY_BASE64__')) {
        $repositoryRoot = Split-Path -Parent $PSScriptRoot
        $text = [IO.File]::ReadAllText(
            (Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-effective-policy.json'),
            [Text.UTF8Encoding]::new($false, $true)
        ).Replace("`r`n", "`n").Replace("`r", "`n")
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
        $expectedDigest = Get-EffectivePolicySha256 -Bytes $bytes
    }
    else {
        $bytes = [Convert]::FromBase64String($script:EffectivePolicyPolicyBase64)
        $expectedDigest = $script:EffectivePolicyPolicyDigest
    }
    if ((Get-EffectivePolicySha256 -Bytes $bytes) -ne $expectedDigest) {
        throw 'The embedded Effective Policy policy failed integrity validation.'
    }
    $policy = & $ConvertFromJsonCommand -InputObject (
        [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    ) -Depth 30 -ErrorAction Stop
    if ($policy.kind -ne 'win-pcinfo.effective-policy-policy' -or
        $policy.contractVersion -ne '1.0.0' -or
        $policy.policyId -ne 'win-pcinfo.effective-policy/1.0.0' -or
        @($policy.layers).Count -ne 3 -or @($policy.scopes).Count -ne 54 -or
        @($policy.sourceCatalog).Count -ne 20 -or @($policy.rules).Count -ne 7 -or
        @($policy.discoveryTasks).Count -ne 2 -or
        @($policy.validationScenarios).Count -ne 44) {
        throw 'The Effective Policy policy is not semantically closed.'
    }
    $policy
}

function Read-EffectivePolicyFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $Policy
    )
    try {
        $bytes = [IO.File]::ReadAllBytes($LiteralPath)
        if ($bytes.Length -gt 1024) { throw 'The Effective Policy fixture exceeds its byte bound.' }
        $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $document = [Text.Json.JsonDocument]::Parse($json)
        try {
            $names = @($document.RootElement.EnumerateObject() | ForEach-Object Name)
            if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object -or
                $names.Count -ne 2 -or @($names | Sort-Object -Unique).Count -ne 2) {
                throw 'The Effective Policy fixture is not lexically closed.'
            }
        }
        finally { $document.Dispose() }
        $fixture = & $ConvertFromJsonCommand -InputObject $json -ErrorAction Stop
        if ($fixture.contractVersion -ne '1.0.0' -or
            [string]$fixture.scenario -notin @($Policy.validationScenarios)) {
            throw 'The Effective Policy fixture is outside the release scenario set.'
        }
        [string]$fixture.scenario
    }
    catch {
        throw [InvalidOperationException]::new('The synthetic Effective Policy fixture is invalid.', $_.Exception)
    }
}

function New-EffectivePolicyScopeState {
    param([string]$ScopeId,[string]$State,[string]$ReasonCode='')
    [pscustomobject][ordered]@{scopeId=$ScopeId;state=$State;reasonCode=$ReasonCode}
}

function Get-EffectivePolicyCollectorScopes {
    param([Parameter(Mandatory)]$Policy)
    @($Policy.scopes | Where-Object { [string]$_.scopeId -notlike 'scope:policy.mdm.*' })
}

function Get-EffectivePolicyWindowsUpdateDefinitions {
    @(
        [pscustomobject]@{
            catalogId='windows-update:defer-feature-updates'
            scopeId='scope:policy.windows-update.defer-feature-updates'
            fieldId='field:policy.windows-update.defer-feature-updates-days'
            valueType='Integer'
        },
        [pscustomobject]@{
            catalogId='windows-update:defer-quality-updates'
            scopeId='scope:policy.windows-update.defer-quality-updates'
            fieldId='field:policy.windows-update.defer-quality-updates-days'
            valueType='Integer'
        },
        [pscustomobject]@{
            catalogId='windows-update:disable-dual-scan'
            scopeId='scope:policy.windows-update.disable-dual-scan'
            fieldId='field:policy.windows-update.disable-dual-scan'
            valueType='Boolean'
        }
    )
}

function Get-EffectivePolicyLegacyAuthenticationDefinitions {
    @(
        [pscustomobject]@{
            catalogId='legacy-auth:lm-compatibility-level'
            scopeId='scope:policy.legacy-auth.lm-compatibility-level'
            fieldId='field:policy.legacy-auth.lm-compatibility-level'
            valueType='Integer'
        },
        [pscustomobject]@{
            catalogId='legacy-auth:ntlm-min-client-sec'
            scopeId='scope:policy.legacy-auth.ntlm-minimum-session-security'
            fieldId='field:policy.legacy-auth.ntlm-min-client-sec'
            valueType='Integer'
        },
        [pscustomobject]@{
            catalogId='legacy-auth:ntlm-min-server-sec'
            scopeId='scope:policy.legacy-auth.ntlm-minimum-session-security'
            fieldId='field:policy.legacy-auth.ntlm-min-server-sec'
            valueType='Integer'
        }
    )
}

function Get-EffectivePolicyLayerState {
    param(
        [Parameter(Mandatory)] [object[]] $ScopeStates,
        [Parameter(Mandatory)] [string[]] $ScopeIds
    )
    $states=@($ScopeStates|Where-Object { [string]$_.scopeId -in $ScopeIds }|ForEach-Object state)
    if($states.Count -ne $ScopeIds.Count){throw 'An Effective Policy layer is missing release-owned scope state.'}
    if(@($states|Where-Object {$_ -ne 'Complete'}).Count -eq 0){return 'Complete'}
    if(@($states|Select-Object -Unique).Count -eq 1){return [string]$states[0]}
    'Partial'
}

function New-EffectivePolicySyntheticPayload {
    param([Parameter(Mandatory)]$Policy,[Parameter(Mandatory)][string]$Scenario)

    if ($Scenario -notin @($Policy.validationScenarios)) {
        throw 'The Effective Policy validation scenario is not release-defined.'
    }
    $localScenario = switch ($Scenario) {
        'NonMdm' { 'Workgroup' }
        'UnsupportedMdmBuild' { 'Domain' }
        'MissingMdmClass' { 'Domain' }
        'MissingMdmProperty' { 'Domain' }
        'MdmPolicyConflict' { 'Domain' }
        'MdmWinsOverGpScoped' { 'Domain' }
        default { $Scenario }
    }
    $sourceLocale = if ($localScenario -eq 'NonEnglish') { 'fr-FR' } else { 'en-US' }
    $localObject = 'LocalGPO'
    $domainObject = '6ac1786c-016f-11d2-945f-00c04fb984f9'
    $userObject = '7f7d1f60-8f2a-4ae5-bb3f-0bdc4a0ef111'
    $policies = @([pscustomobject][ordered]@{
        target='Computer';origin='Local';objectId=$localObject;applicable=$true
        linkId=$null;appliedOrder=$null
    })
    if ($localScenario -in @(
        'Domain','StaleRegistry','DeniedSystem','NonEnglish','AppliedOrderConflict',
        'WindowsUpdatePolicy','RemoteManagementCombinations','SmbPosture','LegacyAuthMasks'
    )) {
        $policies = @(
            [pscustomobject][ordered]@{target='Computer';origin='Domain';objectId=$domainObject;applicable=$true;linkId='synthetic-domain-link';appliedOrder=1},
            [pscustomobject][ordered]@{target='Computer';origin='Local';objectId=$localObject;applicable=$false;linkId=$null;appliedOrder=$null}
        )
    }
    elseif ($localScenario -eq 'UserAndComputerRsop') {
        $policies = @(
            [pscustomobject][ordered]@{target='User';origin='Domain';objectId=$userObject;applicable=$true;linkId='synthetic-user-link';appliedOrder=1},
            [pscustomobject][ordered]@{target='Computer';origin='Domain';objectId=$domainObject;applicable=$true;linkId='synthetic-computer-link';appliedOrder=1},
            [pscustomobject][ordered]@{target='Computer';origin='Local';objectId=$localObject;applicable=$true;linkId='local-machine';appliedOrder=2}
        )
    }

    $settings = @([pscustomobject][ordered]@{
        target='Computer';settingId='registry:11111111-1111-4111-8111-111111111111'
        objectId=$localObject;precedence=1
    })
    $conflict = $false
    if ($localScenario -eq 'AppliedOrderConflict') {
        $conflict = $true
        $settings = @(
            [pscustomobject][ordered]@{target='Computer';settingId='registry:22222222-2222-4222-8222-222222222222';objectId=$domainObject;precedence=1},
            [pscustomobject][ordered]@{target='Computer';settingId='registry:22222222-2222-4222-8222-222222222222';objectId=$localObject;precedence=2}
        )
    }
    elseif ($localScenario -eq 'UserAndComputerRsop') {
        $settings = @(
            [pscustomobject][ordered]@{target='User';settingId='registry:33333333-3333-4333-8333-333333333333';objectId=$userObject;precedence=1},
            [pscustomobject][ordered]@{target='Computer';settingId='registry:11111111-1111-4111-8111-111111111111';objectId=$domainObject;precedence=1}
        )
    }

    $sam = [pscustomobject][ordered]@{
        minimumPasswordLength=14;maximumPasswordAgeSeconds=3628800
        minimumPasswordAgeSeconds=86400;passwordHistoryLength=24
        lockoutDurationSeconds=900;lockoutWindowSeconds=900;lockoutThreshold=10
    }
    if ($localScenario -eq 'AccountLockout') {
        $sam.lockoutDurationSeconds=1800;$sam.lockoutWindowSeconds=1800;$sam.lockoutThreshold=5
    }
    $audits = @($Policy.auditSubcategories | ForEach-Object {
        [pscustomobject][ordered]@{catalogId=[string]$_.catalogId;state='Complete';successEnabled=$true;failureEnabled=$false}
    })
    if ($localScenario -eq 'AuditPolicy') {
        $audits[0].failureEnabled=$true;$audits[1].successEnabled=$false
    }
    $rights = @($Policy.userRights | ForEach-Object {
        [pscustomobject][ordered]@{catalogId=[string]$_.catalogId;state='Complete';directSids=@()}
    })
    if ($localScenario -eq 'UserRights') {
        $rights[0].directSids=@('S-1-5-32-544')
        $rights[1].directSids=@('S-1-5-32-546')
        $rights[2].directSids=@('S-1-5-20')
    }
    $options = @(
        [pscustomobject][ordered]@{catalogId='security-option:machine-inactivity-limit-seconds';state='Complete';value=900;sourceAttribution='Unproven'},
        [pscustomobject][ordered]@{catalogId='security-option:disable-cad';state='Complete';value=$false;sourceAttribution='Unproven'},
        [pscustomobject][ordered]@{catalogId='security-option:lm-compatibility-level';state='Complete';value=5;sourceAttribution='Unproven'}
    )
    if ($localScenario -eq 'SecurityOptions') {
        $options[0].value=600;$options[1].value=$true;$options[2].value=3
    }
    $windowsUpdateSignals = @(
        [pscustomobject][ordered]@{catalogId='windows-update:defer-feature-updates';state='Complete';value=14;sourceAttribution='Unproven'},
        [pscustomobject][ordered]@{catalogId='windows-update:defer-quality-updates';state='Complete';value=3;sourceAttribution='Unproven'},
        [pscustomobject][ordered]@{catalogId='windows-update:disable-dual-scan';state='Complete';value=$false;sourceAttribution='Unproven'}
    )
    $legacyAuthenticationSignals = @(
        [pscustomobject][ordered]@{catalogId='legacy-auth:lm-compatibility-level';state='Complete';value=5;sourceAttribution='Unproven'},
        [pscustomobject][ordered]@{catalogId='legacy-auth:ntlm-min-client-sec';state='Complete';value=537395200;sourceAttribution='Unproven'},
        [pscustomobject][ordered]@{catalogId='legacy-auth:ntlm-min-server-sec';state='Complete';value=537395200;sourceAttribution='Unproven'}
    )
    $antivirusProviders = @(
        [pscustomobject][ordered]@{name='Microsoft Defender Antivirus';health='Good'}
    )
    $firewallProviders = @(
        [pscustomobject][ordered]@{name='Microsoft Defender Firewall';health='Good'}
    )
    $defenderRuntime = [pscustomobject][ordered]@{
        runningMode='Normal';antivirusEnabled=$true;realTimeProtectionEnabled=$true
        tamperProtected=$false
    }
    $defenderNetworkProtection = [pscustomobject][ordered]@{
        state='Complete';value='Enabled';sourceAttribution='Unproven'
    }
    $defenderAsrRules = @()
    $smartScreenSignals = @(
        [pscustomobject][ordered]@{catalogId='smartscreen:enable-in-shell';state='Complete';value=$true;sourceAttribution='Unproven'},
        [pscustomobject][ordered]@{catalogId='smartscreen:prevent-override-for-files';state='Complete';value=$false;sourceAttribution='Unproven'},
        [pscustomobject][ordered]@{catalogId='smartscreen:app-install-control';state='Complete';value=0;sourceAttribution='Unproven'}
    )
    $firewallProfiles = [pscustomobject][ordered]@{
        domain=[pscustomobject][ordered]@{state='Complete';enabled=$true;defaultInboundAction='Block';defaultOutboundAction='Allow'}
        private=[pscustomobject][ordered]@{state='Complete';enabled=$true;defaultInboundAction='Block';defaultOutboundAction='Allow'}
        public=[pscustomobject][ordered]@{state='Complete';enabled=$true;defaultInboundAction='Block';defaultOutboundAction='Allow'}
    }
    $rdpState = [pscustomobject][ordered]@{
        connectionsAllowed=$false
        serviceStartMode='Manual'
        serviceState='Stopped'
        userAuthenticationRequired=$true
        securityLayer='Negotiate'
        minimumEncryptionLevel='High'
        listenerState='Present'
        listenerName='RDP-Tcp'
    }
    $winrmState = [pscustomobject][ordered]@{
        serviceStartMode='Manual'
        serviceState='Stopped'
        allowUnencrypted=$false
        basicAuthentication=$false
        kerberosAuthentication=$true
        negotiateAuthentication=$true
        certificateAuthentication=$false
        credSspAuthentication=$false
        listenerState='Http5985Only'
        listenerTransport='HTTP'
        listenerPort=5985
    }
    $smbState = [pscustomobject][ordered]@{
        clientRequireSigning=$true
        clientEnableSigning=$true
        clientEnableInsecureGuestLogons=$false
        serverRequireSigning=$true
        serverEnableSigning=$true
        serverEncryptData=$true
        serverRejectUnencryptedAccess=$true
        serverEnableSmb1=$false
        smb1FeatureState='Disabled'
    }
    $bitLockerSystemVolume = [pscustomobject][ordered]@{
        conversionStatus='FullyDecrypted';protectionStatus='Off';encryptionMethod='None';lockStatus='Unlocked'
    }
    $bitLockerProtectors = @()
    $deviceGuard = [pscustomobject][ordered]@{
        virtualizationBasedSecurityStatus='Disabled';credentialGuardState='Disabled'
        memoryIntegrityState='Disabled';userModeCodeIntegrityState='Off'
    }
    $wdacPolicies = @()
    $appLockerGpCollections = @()
    $appLockerCspCollections = @()

    $states = @(Get-EffectivePolicyCollectorScopes -Policy $Policy | ForEach-Object {
        New-EffectivePolicyScopeState -ScopeId ([string]$_.scopeId) -State Complete
    })
    function Set-ScopeState([string]$ScopeId,[string]$State,[string]$ReasonCode){
        $scope=@($states|Where-Object scopeId -eq $ScopeId)[0]
        $scope.state=$State
        $scope.reasonCode=if($State -eq 'Complete'){''}else{$ReasonCode}
    }
    if ($localScenario -eq 'MissingRsop') {
        $policies=@();$settings=@()
        foreach($scopeId in @($Policy.layers[0].scopeIds)){Set-ScopeState $scopeId 'Unsupported' 'POLICY.RSOP_NAMESPACE_UNAVAILABLE'}
    }
    elseif ($localScenario -eq 'StaleRegistry') {
        Set-ScopeState 'scope:policy.security-option.machine-inactivity-limit' 'Unavailable' 'POLICY.CONFIGURED_SIGNAL_STALE'
        $options[0].state='Stale';$options[0].value=$null
    }
    elseif ($localScenario -eq 'DeniedAdministrator') {
        $policies=@();$settings=@();$sam.PSObject.Properties|ForEach-Object {$_.Value=$null}
        $audits|ForEach-Object {$_.state='Denied';$_.successEnabled=$null;$_.failureEnabled=$null}
        $rights|ForEach-Object {$_.state='Denied';$_.directSids=@()}
        $options|ForEach-Object {$_.state='Unavailable';$_.value=$null}
        $windowsUpdateSignals|ForEach-Object {$_.state='Unavailable';$_.value=$null}
        $legacyAuthenticationSignals|ForEach-Object {$_.state='Unavailable';$_.value=$null}
        $antivirusProviders=@();$firewallProviders=@()
        $defenderRuntime.runningMode=$null;$defenderRuntime.antivirusEnabled=$null
        $defenderRuntime.realTimeProtectionEnabled=$null;$defenderRuntime.tamperProtected=$null
        $defenderNetworkProtection.state='Unavailable';$defenderNetworkProtection.value=$null
        $smartScreenSignals|ForEach-Object {$_.state='Unavailable';$_.value=$null}
        $firewallProfiles.domain.state='Denied';$firewallProfiles.domain.enabled=$null;$firewallProfiles.domain.defaultInboundAction=$null;$firewallProfiles.domain.defaultOutboundAction=$null
        $firewallProfiles.private.state='Denied';$firewallProfiles.private.enabled=$null;$firewallProfiles.private.defaultInboundAction=$null;$firewallProfiles.private.defaultOutboundAction=$null
        $firewallProfiles.public.state='Denied';$firewallProfiles.public.enabled=$null;$firewallProfiles.public.defaultInboundAction=$null;$firewallProfiles.public.defaultOutboundAction=$null
        $rdpState.connectionsAllowed=$null;$rdpState.serviceStartMode=$null;$rdpState.serviceState=$null
        $rdpState.userAuthenticationRequired=$null;$rdpState.securityLayer=$null;$rdpState.minimumEncryptionLevel=$null
        $rdpState.listenerState=$null;$rdpState.listenerName=$null
        $winrmState.serviceStartMode=$null;$winrmState.serviceState=$null;$winrmState.allowUnencrypted=$null
        $winrmState.basicAuthentication=$null;$winrmState.kerberosAuthentication=$null;$winrmState.negotiateAuthentication=$null
        $winrmState.certificateAuthentication=$null;$winrmState.credSspAuthentication=$null
        $winrmState.listenerState=$null;$winrmState.listenerTransport=$null;$winrmState.listenerPort=$null
        $smbState.clientRequireSigning=$null;$smbState.clientEnableSigning=$null;$smbState.clientEnableInsecureGuestLogons=$null
        $smbState.serverRequireSigning=$null;$smbState.serverEnableSigning=$null;$smbState.serverEncryptData=$null
        $smbState.serverRejectUnencryptedAccess=$null;$smbState.serverEnableSmb1=$null;$smbState.smb1FeatureState=$null
        $bitLockerSystemVolume.conversionStatus=$null;$bitLockerSystemVolume.protectionStatus=$null
        $bitLockerSystemVolume.encryptionMethod=$null;$bitLockerSystemVolume.lockStatus=$null
        $bitLockerProtectors=@()
        $deviceGuard.virtualizationBasedSecurityStatus=$null;$deviceGuard.credentialGuardState=$null
        $deviceGuard.memoryIntegrityState=$null;$deviceGuard.userModeCodeIntegrityState=$null
        $wdacPolicies=@();$appLockerGpCollections=@();$appLockerCspCollections=@()
        foreach($state in $states){$state.state='Denied';$state.reasonCode='POLICY.ADMINISTRATOR_SOURCE_DENIED'}
    }
    elseif ($localScenario -eq 'PartialChannel') {
        $policies=@(1..8|ForEach-Object {
            $suffix=$_.ToString('00000000')
            [pscustomobject][ordered]@{target='Computer';origin='Domain';objectId="$suffix-0000-4000-8000-$($_.ToString('000000000000'))";applicable=$true;linkId="bounded-link-$_";appliedOrder=$_}
        })
        $settings=@(1..8|ForEach-Object {
            $suffix=$_.ToString('00000000')
            [pscustomobject][ordered]@{target='Computer';settingId="registry:bounded-setting-$_";objectId="$suffix-0000-4000-8000-$($_.ToString('000000000000'))";precedence=$_}
        })
        Set-ScopeState 'scope:policy.applied.user.precedence' 'Unsupported' 'POLICY.RSOP_EXTENSION_UNSUPPORTED'
        Set-ScopeState 'scope:policy.applied.computer.link' 'Partial' 'POLICY.RSOP_LINK_AMBIGUOUS'
        Set-ScopeState 'scope:policy.applied.computer.precedence' 'Partial' 'POLICY.RSOP_EVIDENCE_BOUND_EXCEEDED'
        Set-ScopeState 'scope:policy.local-sam.lockout' 'Failed' 'POLICY.LOCAL_SAM_LOCKOUT_FAILED'
        Set-ScopeState 'scope:policy.local-audit' 'Failed' 'POLICY.AUDIT_FAILED'
        Set-ScopeState 'scope:policy.local-user-rights' 'Unsupported' 'POLICY.USER_RIGHTS_UNSUPPORTED'
        Set-ScopeState 'scope:policy.security-option.lm-compatibility-level' 'Unavailable' 'POLICY.SECURITY_OPTION_UNAVAILABLE'
        Set-ScopeState 'scope:policy.defender.asr' 'Unsupported' 'POLICY.DEFENDER_ASR_UNSUPPORTED'
        Set-ScopeState 'scope:policy.defender.runtime' 'Partial' 'POLICY.DEFENDER_PROPERTY_UNAVAILABLE'
        Set-ScopeState 'scope:policy.firewall.public-profile' 'Failed' 'POLICY.FIREWALL_PROFILE_FAILED'
        $sam.lockoutDurationSeconds=$null;$sam.lockoutWindowSeconds=$null;$sam.lockoutThreshold=$null
        $audits|ForEach-Object {$_.state='Failed';$_.successEnabled=$null;$_.failureEnabled=$null}
        $rights|ForEach-Object {$_.state='Unsupported';$_.directSids=@()}
        $options[2].state='Unavailable';$options[2].value=$null
        $defenderRuntime.tamperProtected=$null
        $firewallProfiles.public.state='Failed';$firewallProfiles.public.enabled=$null;$firewallProfiles.public.defaultInboundAction=$null;$firewallProfiles.public.defaultOutboundAction=$null
    }

    switch ($localScenario) {
        'ThirdPartyRegistration' {
            $antivirusProviders=@([pscustomobject][ordered]@{name='Contoso Endpoint Protection';health='Good'})
            $defenderRuntime.runningMode='Passive';$defenderRuntime.antivirusEnabled=$false
            $defenderRuntime.realTimeProtectionEnabled=$false
        }
        'DefenderDisabled' {
            $antivirusProviders=@()
            $defenderRuntime.runningMode='Disabled';$defenderRuntime.antivirusEnabled=$false
            $defenderRuntime.realTimeProtectionEnabled=$false
        }
        'DefenderUnavailable' {
            Set-ScopeState 'scope:policy.defender.asr' 'Unsupported' 'POLICY.DEFENDER_MODULE_UNAVAILABLE'
            Set-ScopeState 'scope:policy.defender.network-protection' 'Unsupported' 'POLICY.DEFENDER_MODULE_UNAVAILABLE'
            Set-ScopeState 'scope:policy.defender.runtime' 'Unsupported' 'POLICY.DEFENDER_MODULE_UNAVAILABLE'
            $defenderRuntime.runningMode=$null;$defenderRuntime.antivirusEnabled=$null
            $defenderRuntime.realTimeProtectionEnabled=$null;$defenderRuntime.tamperProtected=$null
            $defenderNetworkProtection.state='Unsupported';$defenderNetworkProtection.value=$null
        }
        'AmbiguousSecurityCenter' {
            $antivirusProviders=@(
                [pscustomobject][ordered]@{name='Microsoft Defender Antivirus';health='Good'},
                [pscustomobject][ordered]@{name='Contoso Endpoint Protection';health='Good'}
            )
            Set-ScopeState 'scope:policy.security-center.antivirus-providers' 'Partial' 'POLICY.SECURITY_PROVIDER_MULTIPLE_REGISTRATIONS'
        }
        'TamperProtected' {
            $defenderRuntime.tamperProtected=$true
        }
        'MissingDefenderProperty' {
            Set-ScopeState 'scope:policy.defender.runtime' 'Partial' 'POLICY.DEFENDER_PROPERTY_UNAVAILABLE'
            $defenderRuntime.tamperProtected=$null
        }
        'FirewallProfiles' {
            $firewallProfiles.domain.defaultInboundAction='Allow'
            $firewallProfiles.private.enabled=$false
            $firewallProfiles.public.defaultOutboundAction='Block'
        }
        'AsrRulePairs' {
            $defenderAsrRules=@(
                [pscustomobject][ordered]@{ruleId='26190899-1602-49e8-8b27-eb1d0a1ce869';action='Block'},
                [pscustomobject][ordered]@{ruleId='3b576869-a4ec-4529-8536-b80a7769e899';action='Audit'}
            )
        }
        'WindowsUpdatePolicy' {
            $windowsUpdateSignals[0].value=30
            $windowsUpdateSignals[1].value=7
            $windowsUpdateSignals[2].value=$true
        }
        'RemoteManagementCombinations' {
            $rdpState.connectionsAllowed=$true
            $rdpState.serviceStartMode='Automatic'
            $rdpState.serviceState='Running'
            $rdpState.userAuthenticationRequired=$true
            $rdpState.securityLayer='Ssl'
            $rdpState.minimumEncryptionLevel='ClientCompatible'
            $rdpState.listenerState='Present'
            $winrmState.serviceStartMode='Automatic'
            $winrmState.serviceState='Running'
            $winrmState.certificateAuthentication=$true
            $winrmState.listenerState='Https5986Only'
            $winrmState.listenerTransport='HTTPS'
            $winrmState.listenerPort=5986
        }
        'SmbPosture' {
            $smbState.clientRequireSigning=$true
            $smbState.clientEnableSigning=$true
            $smbState.clientEnableInsecureGuestLogons=$false
            $smbState.serverRequireSigning=$true
            $smbState.serverEnableSigning=$true
            $smbState.serverEncryptData=$true
            $smbState.serverRejectUnencryptedAccess=$true
            $smbState.serverEnableSmb1=$false
            $smbState.smb1FeatureState='Disabled'
        }
        'LegacyAuthMasks' {
            $legacyAuthenticationSignals[0].value=3
            $legacyAuthenticationSignals[1].value=537395232
            $legacyAuthenticationSignals[2].value=537395200
        }
        'NonEnglish' {
            $antivirusProviders=@([pscustomobject][ordered]@{name='Antivirus Microsoft Defender';health='Good'})
            $firewallProviders=@([pscustomobject][ordered]@{name='Pare-feu Microsoft Defender';health='Good'})
        }
        'BitLockerEncrypted' {
            $bitLockerSystemVolume.conversionStatus='FullyEncrypted'
            $bitLockerSystemVolume.protectionStatus='On'
            $bitLockerSystemVolume.encryptionMethod='XtsAes256'
            $bitLockerSystemVolume.lockStatus='Unlocked'
            $bitLockerProtectors=@(
                [pscustomobject][ordered]@{protectorType='Tpm';count=1},
                [pscustomobject][ordered]@{protectorType='RecoveryPassword';count=1}
            )
        }
        'BitLockerUnknown' {
            Set-ScopeState 'scope:policy.bitlocker.operating-system-volume' 'Unavailable' 'POLICY.BITLOCKER_VOLUME_UNAVAILABLE'
            Set-ScopeState 'scope:policy.bitlocker.protectors' 'Unavailable' 'POLICY.BITLOCKER_PROTECTORS_UNAVAILABLE'
            $bitLockerSystemVolume.conversionStatus=$null
            $bitLockerSystemVolume.protectionStatus=$null
            $bitLockerSystemVolume.encryptionMethod=$null
            $bitLockerSystemVolume.lockStatus=$null
            $bitLockerProtectors=@()
        }
        'VbsCredentialGuardRunning' {
            $deviceGuard.virtualizationBasedSecurityStatus='EnabledAndRunning'
            $deviceGuard.credentialGuardState='Running'
            $deviceGuard.memoryIntegrityState='Running'
            $deviceGuard.userModeCodeIntegrityState='Enforced'
        }
        'VbsConfiguredNotRunning' {
            $deviceGuard.virtualizationBasedSecurityStatus='EnabledNotRunning'
            $deviceGuard.credentialGuardState='Configured'
            $deviceGuard.memoryIntegrityState='Configured'
            $deviceGuard.userModeCodeIntegrityState='Audit'
        }
        'WdacWindows11Policies' {
            $wdacPolicies=@(
                [pscustomobject][ordered]@{deploymentChannel='ApplicationControlCsp';enforcementState='Enforced';platformPolicy=$false;signedPolicy=$true},
                [pscustomobject][ordered]@{deploymentChannel='Platform';enforcementState='Enforced';platformPolicy=$true;signedPolicy=$true}
            )
        }
        'WdacWindows10Unsupported' {
            Set-ScopeState 'scope:policy.wdac.inventory' 'Unsupported' 'POLICY.WDAC_WINDOWS10_JSON_UNSUPPORTED'
            $wdacPolicies=@()
        }
        'AppLockerGpOnly' {
            $appLockerGpCollections=@(
                [pscustomobject][ordered]@{ruleCollection='EXE';enforcementMode='Enabled'}
            )
        }
        'AppLockerCspOnly' {
            $appLockerCspCollections=@(
                [pscustomobject][ordered]@{ruleCollection='EXE';enforcementMode='Enabled'}
            )
        }
        'AppLockerGpCspConflict' {
            $appLockerGpCollections=@(
                [pscustomobject][ordered]@{ruleCollection='EXE';enforcementMode='AuditOnly'}
            )
            $appLockerCspCollections=@(
                [pscustomobject][ordered]@{ruleCollection='EXE';enforcementMode='Enabled'}
            )
        }
        'AppLockerChannelIncomplete' {
            Set-ScopeState 'scope:policy.applocker.csp-channel' 'Unavailable' 'POLICY.APPLOCKER_CSP_UNAVAILABLE'
            $appLockerGpCollections=@(
                [pscustomobject][ordered]@{ruleCollection='EXE';enforcementMode='Enabled'}
            )
            $appLockerCspCollections=@()
        }
        'VirtualMachineSecurity' {
            $bitLockerSystemVolume.conversionStatus='FullyEncrypted'
            $bitLockerSystemVolume.protectionStatus='On'
            $bitLockerSystemVolume.encryptionMethod='XtsAes128'
            $bitLockerSystemVolume.lockStatus='Unlocked'
            $bitLockerProtectors=@(
                [pscustomobject][ordered]@{protectorType='Tpm';count=1}
            )
            $deviceGuard.virtualizationBasedSecurityStatus='EnabledAndRunningInVirtualMachine'
            $deviceGuard.credentialGuardState='Running'
            $deviceGuard.memoryIntegrityState='Running'
            $deviceGuard.userModeCodeIntegrityState='Enforced'
        }
    }

    $layers=@{}
    foreach($layer in $Policy.layers){
        $layers[[string]$layer.layerId]=Get-EffectivePolicyLayerState `
            -ScopeStates $states -ScopeIds @($layer.scopeIds)
    }

    [pscustomobject][ordered]@{
        sourceLocale=$sourceLocale
        layerStates=[pscustomobject][ordered]@{
            AppliedPolicyEvidence=[string]$layers.AppliedPolicyEvidence
            ConfiguredPolicySignals=[string]$layers.ConfiguredPolicySignals
            CurrentControlState=[string]$layers.CurrentControlState
        }
        scopeStates=@($states);appliedPolicies=@($policies);policySettings=@($settings)
        localSam=$sam;auditSubcategories=@($audits);userRights=@($rights);securityOptions=@($options)
        windowsUpdateSignals=@($windowsUpdateSignals)
        legacyAuthenticationSignals=@($legacyAuthenticationSignals)
        antivirusProviders=@($antivirusProviders);firewallProviders=@($firewallProviders)
        defenderRuntime=$defenderRuntime;defenderNetworkProtection=$defenderNetworkProtection
        defenderAsrRules=@($defenderAsrRules);smartScreenSignals=@($smartScreenSignals)
        firewallProfiles=$firewallProfiles
        rdpState=$rdpState;winrmState=$winrmState;smbState=$smbState
        bitLockerSystemVolume=$bitLockerSystemVolume;bitLockerProtectors=@($bitLockerProtectors)
        deviceGuard=$deviceGuard;wdacPolicies=@($wdacPolicies)
        appLockerGpCollections=@($appLockerGpCollections);appLockerCspCollections=@($appLockerCspCollections)
        appliedOrderConflict=[bool]$conflict
        localAccountPolicySemantics='LocalSamAccountsOnly';userRightSemantics='DirectAssignmentsOnly'
    }
}

function New-EffectivePolicySyntheticPolicyCspResults {
    param([Parameter(Mandatory)][string]$Scenario)

    $results = [pscustomobject][ordered]@{
        catalogId = 'catalog:policy-csp-result.windows10/1.0.0'
        fields = @(
            [pscustomobject][ordered]@{
                fieldId='field:policy.mdm.control-policy-conflict.mdm-wins-over-gp'
                scopeId='scope:policy.mdm.control-policy-conflict'
                state='Complete';reasonCode='';valueState='ObservedValue';value=$false
            },
            [pscustomobject][ordered]@{
                fieldId='field:policy.mdm.security-option.machine-inactivity-limit-seconds'
                scopeId='scope:policy.mdm.security-option.machine-inactivity-limit'
                state='Complete';reasonCode='';valueState='ObservedValue';value=900
            },
            [pscustomobject][ordered]@{
                fieldId='field:policy.mdm.security-option.disable-cad'
                scopeId='scope:policy.mdm.security-option.disable-cad'
                state='Complete';reasonCode='';valueState='ObservedValue';value=$false
            },
            [pscustomobject][ordered]@{
                fieldId='field:policy.mdm.security-option.lm-compatibility-level'
                scopeId='scope:policy.mdm.security-option.lm-compatibility-level'
                state='Complete';reasonCode='';valueState='ObservedValue';value=5
            },
            [pscustomobject][ordered]@{
                fieldId='field:policy.mdm.update.defer-feature-updates-days'
                scopeId='scope:policy.mdm.update.defer-feature-updates'
                state='Complete';reasonCode='';valueState='ObservedValue';value=14
            },
            [pscustomobject][ordered]@{
                fieldId='field:policy.mdm.update.defer-quality-updates-days'
                scopeId='scope:policy.mdm.update.defer-quality-updates'
                state='Complete';reasonCode='';valueState='ObservedValue';value=3
            },
            [pscustomobject][ordered]@{
                fieldId='field:policy.mdm.update.disable-dual-scan'
                scopeId='scope:policy.mdm.update.disable-dual-scan'
                state='Complete';reasonCode='';valueState='ObservedValue';value=$false
            }
        )
    }
    switch ($Scenario) {
        'NonMdm' {
            $results.catalogId = ''
            foreach ($field in $results.fields) {
                $field.state='Unsupported';$field.reasonCode='POLICY.MDM_PROVIDER_UNAVAILABLE'
                $field.valueState='ObservedAbsent';$field.value=$null
            }
        }
        'UnsupportedMdmBuild' {
            $results.catalogId = ''
            foreach ($field in $results.fields) {
                $field.state='Unsupported';$field.reasonCode='POLICY.MDM_BUILD_UNSUPPORTED'
                $field.valueState='ObservedAbsent';$field.value=$null
            }
        }
        'MissingMdmClass' {
            foreach ($field in $results.fields) {
                $field.state='Unsupported';$field.reasonCode='POLICY.MDM_RESULT_CLASS_UNSUPPORTED'
                $field.valueState='ObservedAbsent';$field.value=$null
            }
        }
        'MissingMdmProperty' {
            $results.fields[2].state='Unavailable'
            $results.fields[2].reasonCode='POLICY.MDM_RESULT_PROPERTY_UNAVAILABLE'
            $results.fields[2].valueState='ObservedAbsent'
            $results.fields[2].value=$null
        }
        'MdmPolicyConflict' {
            $results.fields[0].value=$true
            $results.fields[1].value=600
            $results.fields[2].value=$true
            $results.fields[3].value=3
        }
        'MdmWinsOverGpScoped' {
            $results.fields[0].value=$true
        }
        'WindowsUpdatePolicy' {
            $results.fields[4].value=30
            $results.fields[5].value=7
            $results.fields[6].value=$true
        }
    }
    $results
}

function Test-EffectivePolicyCollectorPayload {
    param([Parameter(Mandatory)]$Payload,[Parameter(Mandatory)]$Policy)
    try {
        function Test-ExactProperties($Value,[string[]]$Expected){
            ((@($Value.PSObject.Properties.Name|Sort-Object)-join '|') -eq (@($Expected|Sort-Object)-join '|'))
        }
        function Test-BoundedUnsignedInteger($Value,[uint64]$Maximum){
        if($null -eq $Value -or $Value -is [bool] -or $Value.GetType() -notin @(
            [byte],[sbyte],[int16],[uint16],[int32],[uint32],[int64],[uint64]
        )){return $false}
            $number=[decimal]$Value
            ($number -ge 0 -and $number -le [decimal]$Maximum)
        }
        function Test-BoundedString($Value,[int]$MaximumUtf8Bytes,[string]$Pattern=''){
            if($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or
                [Text.Encoding]::UTF8.GetByteCount($Value) -gt $MaximumUtf8Bytes){return $false}
            ([string]::IsNullOrEmpty($Pattern) -or $Value -match $Pattern)
        }
        function Test-BoundedSid($Value){
            if($Value -isnot [string] -or [Text.Encoding]::UTF8.GetByteCount($Value) -gt 184){return $false}
            try{
                $sid=[System.Security.Principal.SecurityIdentifier]::new($Value)
                $sid.Value -ceq $Value
            }catch{return $false}
        }
        function Test-NullableBoundedString($Value,[int]$MaximumUtf8Bytes,[string]$Pattern=''){
            ($null -eq $Value) -or (Test-BoundedString $Value $MaximumUtf8Bytes $Pattern)
        }
        $names=@($Payload.PSObject.Properties.Name|Sort-Object)
        $expected=@(
            'antivirusProviders','appLockerCspCollections','appLockerGpCollections',
            'appliedOrderConflict','appliedPolicies','auditSubcategories',
            'bitLockerProtectors','bitLockerSystemVolume','defenderAsrRules',
            'defenderNetworkProtection','defenderRuntime','deviceGuard','firewallProfiles',
            'legacyAuthenticationSignals',
            'firewallProviders','layerStates','localAccountPolicySemantics','localSam',
            'policySettings','rdpState','scopeStates','securityOptions','smartScreenSignals',
            'smbState','sourceLocale','userRights','userRightSemantics','wdacPolicies',
            'windowsUpdateSignals','winrmState'
        )|Sort-Object
        if(($names -join '|') -ne ($expected -join '|') -or
            $Payload.localAccountPolicySemantics -isnot [string] -or $Payload.userRightSemantics -isnot [string] -or
            [string]$Payload.localAccountPolicySemantics -ne 'LocalSamAccountsOnly' -or
            [string]$Payload.userRightSemantics -ne 'DirectAssignmentsOnly' -or
            -not (Test-BoundedString $Payload.sourceLocale 32 '^(?:und|[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*)$') -or
            @($Payload.scopeStates).Count -ne @(Get-EffectivePolicyCollectorScopes -Policy $Policy).Count -or
            @($Payload.appliedPolicies).Count -gt 16 -or @($Payload.policySettings).Count -gt 16 -or
            @($Payload.auditSubcategories).Count -ne 3 -or @($Payload.userRights).Count -ne 3 -or
            @($Payload.securityOptions).Count -ne 3 -or
            @($Payload.windowsUpdateSignals).Count -ne 3 -or
            @($Payload.legacyAuthenticationSignals).Count -ne 3 -or
            @($Payload.antivirusProviders).Count -gt [int]$Policy.collectors[0].maximumSecurityProvidersPerCategory -or
            @($Payload.firewallProviders).Count -gt [int]$Policy.collectors[0].maximumSecurityProvidersPerCategory -or
            @($Payload.defenderAsrRules).Count -gt [int]$Policy.collectors[0].maximumAsrRules -or
            @($Payload.bitLockerProtectors).Count -gt 8 -or @($Payload.wdacPolicies).Count -gt 8 -or
            @($Payload.appLockerGpCollections).Count -gt 8 -or
            @($Payload.appLockerCspCollections).Count -gt 8 -or
            @($Payload.smartScreenSignals).Count -ne 3){return $false}
        $expectedScopeIds=@((Get-EffectivePolicyCollectorScopes -Policy $Policy).scopeId)
        # Source order is not evidence identity. Require the exact scope set
        # (including multiplicity), then copy it in release-catalog order.
        if((@($Payload.scopeStates.scopeId|Sort-Object)-join '|') -ne
            (@($expectedScopeIds|Sort-Object)-join '|')){return $false}
        if(-not (Test-ExactProperties $Payload.layerStates @('AppliedPolicyEvidence','ConfiguredPolicySignals','CurrentControlState'))){return $false}
        foreach($scope in $Payload.scopeStates){
            if(-not (Test-ExactProperties $scope @('scopeId','state','reasonCode'))){return $false}
            if($scope.scopeId -isnot [string] -or $scope.state -isnot [string] -or
                [string]$scope.state -notin @('Complete','Partial','Unavailable','Unsupported','Denied','Malformed','TimedOut','Cancelled','Constrained','Failed') -or
                ($scope.state -ne 'Complete' -and -not (Test-BoundedString $scope.reasonCode 128 '^[A-Z0-9._-]+$')) -or
                ($scope.state -eq 'Complete' -and ($scope.reasonCode -isnot [string] -or -not [string]::IsNullOrEmpty($scope.reasonCode)))){return $false}
        }
        foreach($layer in @('AppliedPolicyEvidence','ConfiguredPolicySignals','CurrentControlState')){
            if($Payload.layerStates.$layer -isnot [string] -or [string]$Payload.layerStates.$layer -notin @('Complete','Partial','Unavailable','Unsupported','Denied','Malformed','TimedOut','Cancelled','Constrained','Failed')){return $false}
        }
        foreach($layer in $Policy.layers){
            if([string]$Payload.layerStates.([string]$layer.layerId) -ne
                (Get-EffectivePolicyLayerState -ScopeStates @($Payload.scopeStates) -ScopeIds @($layer.scopeIds))){return $false}
        }
        foreach($target in @('User','Computer')){
            if(@($Payload.appliedPolicies|Where-Object target -eq $target).Count -gt [int]$Policy.collectors[0].maximumAppliedPoliciesPerTarget -or
                @($Payload.policySettings|Where-Object target -eq $target).Count -gt [int]$Policy.collectors[0].maximumPolicySettingsPerTarget){return $false}
        }
        foreach($item in $Payload.appliedPolicies){
            if(-not (Test-ExactProperties $item @('target','origin','objectId','applicable','linkId','appliedOrder')) -or
                $item.target -isnot [string] -or $item.origin -isnot [string] -or $item.objectId -isnot [string] -or
                [string]$item.target -notin @('User','Computer') -or [string]$item.origin -notin @('Local','Domain') -or
                [string]$item.objectId -notmatch '^(?:LocalGPO|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$' -or
                ($null -ne $item.applicable -and $item.applicable -isnot [bool]) -or
                ($null -ne $item.linkId -and -not (Test-BoundedString $item.linkId 256)) -or
                ($null -ne $item.appliedOrder -and -not (Test-BoundedUnsignedInteger $item.appliedOrder 64))){return $false}
        }
        foreach($item in $Payload.policySettings){
            if(-not (Test-ExactProperties $item @('target','settingId','objectId','precedence')) -or
                $item.target -isnot [string] -or $item.settingId -isnot [string] -or $item.objectId -isnot [string] -or
                [string]$item.target -notin @('User','Computer') -or
                [string]$item.settingId -notmatch '^registry:[A-Za-z0-9._/{}-]{1,119}$' -or
                [string]$item.objectId -notmatch '^(?:LocalGPO|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$' -or
                -not (Test-BoundedUnsignedInteger $item.precedence 64) -or [decimal]$item.precedence -lt 1){return $false}
        }
        $samNames=@($Payload.localSam.PSObject.Properties.Name|Sort-Object)
        $expectedSam=@('lockoutDurationSeconds','lockoutThreshold','lockoutWindowSeconds','maximumPasswordAgeSeconds','minimumPasswordAgeSeconds','minimumPasswordLength','passwordHistoryLength')|Sort-Object
        if(($samNames-join '|') -ne ($expectedSam-join '|')){return $false}
        $samFields=@(
            [pscustomobject]@{name='minimumPasswordLength';maximum=[uint64]999;scopeId='scope:policy.local-sam.password'},
            [pscustomobject]@{name='maximumPasswordAgeSeconds';maximum=[uint64]4294967295;scopeId='scope:policy.local-sam.password'},
            [pscustomobject]@{name='minimumPasswordAgeSeconds';maximum=[uint64]4294967295;scopeId='scope:policy.local-sam.password'},
            [pscustomobject]@{name='passwordHistoryLength';maximum=[uint64]999;scopeId='scope:policy.local-sam.password'},
            [pscustomobject]@{name='lockoutDurationSeconds';maximum=[uint64]4294967295;scopeId='scope:policy.local-sam.lockout'},
            [pscustomobject]@{name='lockoutWindowSeconds';maximum=[uint64]4294967295;scopeId='scope:policy.local-sam.lockout'},
            [pscustomobject]@{name='lockoutThreshold';maximum=[uint64]4294967295;scopeId='scope:policy.local-sam.lockout'}
        )
        foreach($field in $samFields){
            $value=$Payload.localSam.([string]$field.name)
            $scopeState=@($Payload.scopeStates|Where-Object scopeId -eq ([string]$field.scopeId))[0].state
            if($scopeState -eq 'Complete'){
                if(-not (Test-BoundedUnsignedInteger $value ([uint64]$field.maximum))){return $false}
            }
            elseif($null -ne $value){return $false}
        }
        $auditIds=@($Policy.auditSubcategories.catalogId);$rightIds=@($Policy.userRights.catalogId);$optionIds=@($Policy.securityOptions.catalogId)
        if((@($Payload.auditSubcategories.catalogId)-join '|') -ne ($auditIds-join '|') -or
            (@($Payload.userRights.catalogId)-join '|') -ne ($rightIds-join '|') -or
            (@($Payload.securityOptions.catalogId)-join '|') -ne ($optionIds-join '|')){return $false}
        foreach($audit in $Payload.auditSubcategories){
            if(-not (Test-ExactProperties $audit @('catalogId','state','successEnabled','failureEnabled')) -or $audit.catalogId -isnot [string] -or $audit.state -isnot [string] -or
                [string]$audit.state -notin @('Complete','Unavailable','Unsupported','Denied','Malformed','Failed') -or
                ($audit.state -eq 'Complete' -and ($audit.successEnabled -isnot [bool] -or $audit.failureEnabled -isnot [bool])) -or
                ($audit.state -ne 'Complete' -and ($null -ne $audit.successEnabled -or $null -ne $audit.failureEnabled))){return $false}
        }
        foreach($right in $Payload.userRights){
            if(-not (Test-ExactProperties $right @('catalogId','state','directSids')) -or $right.catalogId -isnot [string] -or $right.state -isnot [string] -or
                [string]$right.state -notin @('Complete','Partial','Unavailable','Unsupported','Denied','Malformed','Failed') -or @($right.directSids).Count -gt 8 -or
                ($right.state -notin @('Complete','Partial') -and @($right.directSids).Count -ne 0)){return $false}
            foreach($sid in @($right.directSids)){if(-not (Test-BoundedSid $sid)){return $false}}
        }
        foreach($option in $Payload.securityOptions){
            if(-not (Test-ExactProperties $option @('catalogId','state','value','sourceAttribution')) -or $option.catalogId -isnot [string] -or $option.state -isnot [string] -or $option.sourceAttribution -isnot [string] -or
                [string]$option.state -notin @('Complete','Stale','Unavailable','Unsupported','Denied','Malformed','Failed') -or
                [string]$option.sourceAttribution -ne 'Unproven' -or ($option.state -ne 'Complete' -and $null -ne $option.value)){return $false}
            if($option.state -eq 'Complete' -and $null -ne $option.value){
                $definition=@($Policy.securityOptions|Where-Object catalogId -eq ([string]$option.catalogId))[0]
                if(([string]$definition.valueType -eq 'Boolean' -and $option.value -isnot [bool]) -or
                    ([string]$definition.valueType -eq 'Integer' -and -not (Test-BoundedUnsignedInteger $option.value ([uint64]4294967295)) )){return $false}
            }
        }
        $updateIds=@((Get-EffectivePolicyWindowsUpdateDefinitions).catalogId)
        if((@($Payload.windowsUpdateSignals.catalogId)-join '|') -ne ($updateIds-join '|')){return $false}
        foreach($signal in $Payload.windowsUpdateSignals){
            if(-not (Test-ExactProperties $signal @('catalogId','state','value','sourceAttribution')) -or
                [string]$signal.state -notin @('Complete','Unavailable','Unsupported','Denied','Malformed','Failed') -or
                [string]$signal.sourceAttribution -ne 'Unproven' -or
                ($signal.state -ne 'Complete' -and $null -ne $signal.value)){return $false}
            if([string]$signal.state -eq 'Complete' -and $null -ne $signal.value){
                if([string]$signal.catalogId -eq 'windows-update:disable-dual-scan'){
                    if($signal.value -isnot [bool]){return $false}
                } elseif(-not (Test-BoundedUnsignedInteger $signal.value $(if($signal.catalogId -eq 'windows-update:defer-quality-updates'){[uint64]30}else{[uint64]365}))){return $false}
            }
        }
        $legacyIds=@((Get-EffectivePolicyLegacyAuthenticationDefinitions).catalogId)
        if((@($Payload.legacyAuthenticationSignals.catalogId)-join '|') -ne ($legacyIds-join '|')){return $false}
        foreach($signal in $Payload.legacyAuthenticationSignals){
            if(-not (Test-ExactProperties $signal @('catalogId','state','value','sourceAttribution')) -or
                [string]$signal.state -notin @('Complete','Unavailable','Unsupported','Denied','Malformed','Failed') -or
                [string]$signal.sourceAttribution -ne 'Unproven' -or
                ($signal.state -ne 'Complete' -and $null -ne $signal.value)){return $false}
            if([string]$signal.state -eq 'Complete' -and $null -ne $signal.value -and -not (Test-BoundedUnsignedInteger $signal.value $(if($signal.catalogId -eq 'legacy-auth:lm-compatibility-level'){[uint64]5}else{[uint64]4294967295}))){return $false}
        }
        foreach($provider in @($Payload.antivirusProviders)+@($Payload.firewallProviders)){
            if(-not (Test-ExactProperties $provider @('name','health')) -or
                -not (Test-BoundedString $provider.name 256) -or
                [string]$provider.health -notin @('Good','Poor','Snooze','NotMonitored')){return $false}
        }
        if(-not (Test-ExactProperties $Payload.defenderRuntime @(
            'runningMode','antivirusEnabled','realTimeProtectionEnabled','tamperProtected'
        ))){return $false}
        $runtimeScopeState=@($Payload.scopeStates|Where-Object scopeId -eq 'scope:policy.defender.runtime')[0].state
        if($runtimeScopeState -eq 'Complete'){
            if(-not (Test-BoundedString $Payload.defenderRuntime.runningMode 64 '^[A-Za-z ]+$') -or
                $Payload.defenderRuntime.antivirusEnabled -isnot [bool] -or
                $Payload.defenderRuntime.realTimeProtectionEnabled -isnot [bool] -or
                $Payload.defenderRuntime.tamperProtected -isnot [bool]){return $false}
        } elseif($runtimeScopeState -eq 'Partial'){
            if(-not (Test-NullableBoundedString $Payload.defenderRuntime.runningMode 64 '^[A-Za-z ]+$') -or
                ($null -ne $Payload.defenderRuntime.antivirusEnabled -and $Payload.defenderRuntime.antivirusEnabled -isnot [bool]) -or
                ($null -ne $Payload.defenderRuntime.realTimeProtectionEnabled -and $Payload.defenderRuntime.realTimeProtectionEnabled -isnot [bool]) -or
                ($null -ne $Payload.defenderRuntime.tamperProtected -and $Payload.defenderRuntime.tamperProtected -isnot [bool])){return $false}
        } elseif($null -ne $Payload.defenderRuntime.runningMode -or $null -ne $Payload.defenderRuntime.antivirusEnabled -or
            $null -ne $Payload.defenderRuntime.realTimeProtectionEnabled -or $null -ne $Payload.defenderRuntime.tamperProtected){return $false}
        if(-not (Test-ExactProperties $Payload.defenderNetworkProtection @('state','value','sourceAttribution')) -or
            [string]$Payload.defenderNetworkProtection.state -notin @('Complete','Unavailable','Unsupported','Denied','Malformed','Failed') -or
            [string]$Payload.defenderNetworkProtection.sourceAttribution -ne 'Unproven'){return $false}
        if([string]$Payload.defenderNetworkProtection.state -eq 'Complete'){
            if(-not (Test-BoundedString $Payload.defenderNetworkProtection.value 32 '^(?:Disabled|Enabled|AuditMode|NotConfigured)$')){return $false}
        } elseif($null -ne $Payload.defenderNetworkProtection.value){return $false}
        foreach($rule in $Payload.defenderAsrRules){
            if(-not (Test-ExactProperties $rule @('ruleId','action')) -or
                -not (Test-BoundedString $rule.ruleId 64 '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') -or
                [string]$rule.action -notin @('Disabled','Block','Audit','NotConfigured','Warn')){return $false}
        }
        $smartScreenIds=@($Policy.smartScreenSignals.catalogId)
        if((@($Payload.smartScreenSignals.catalogId)-join '|') -ne ($smartScreenIds-join '|')){return $false}
        foreach($signal in $Payload.smartScreenSignals){
            if(-not (Test-ExactProperties $signal @('catalogId','state','value','sourceAttribution')) -or
                [string]$signal.state -notin @('Complete','Unavailable','Unsupported','Denied','Malformed','Failed') -or
                [string]$signal.sourceAttribution -ne 'Unproven'){return $false}
            if([string]$signal.state -eq 'Complete'){
                switch ([string]$signal.catalogId) {
                    'smartscreen:app-install-control' {
                        if(-not (Test-BoundedUnsignedInteger $signal.value ([uint64]3))){return $false}
                    }
                    default {
                        if($signal.value -isnot [bool]){return $false}
                    }
                }
            } elseif($null -ne $signal.value){return $false}
        }
        if(-not (Test-ExactProperties $Payload.firewallProfiles @('domain','private','public'))){return $false}
        foreach($profileName in @('domain','private','public')){
            $profile=$Payload.firewallProfiles.$profileName
            if(-not (Test-ExactProperties $profile @('state','enabled','defaultInboundAction','defaultOutboundAction')) -or
                [string]$profile.state -notin @('Complete','Unavailable','Unsupported','Denied','Malformed','Failed')){return $false}
            if([string]$profile.state -eq 'Complete'){
                if($profile.enabled -isnot [bool] -or
                    [string]$profile.defaultInboundAction -notin @('Allow','Block','NotConfigured') -or
                    [string]$profile.defaultOutboundAction -notin @('Allow','Block','NotConfigured')){return $false}
            } elseif($null -ne $profile.enabled -or $null -ne $profile.defaultInboundAction -or $null -ne $profile.defaultOutboundAction){return $false}
        }
        if(-not (Test-ExactProperties $Payload.rdpState @(
            'connectionsAllowed','listenerName','listenerState','minimumEncryptionLevel',
            'securityLayer','serviceStartMode','serviceState','userAuthenticationRequired'
        ))){return $false}
        if(($null -ne $Payload.rdpState.connectionsAllowed -and $Payload.rdpState.connectionsAllowed -isnot [bool]) -or
            ($null -ne $Payload.rdpState.userAuthenticationRequired -and $Payload.rdpState.userAuthenticationRequired -isnot [bool]) -or
            -not (Test-NullableBoundedString $Payload.rdpState.serviceStartMode 32 '^[A-Za-z]+$') -or
            -not (Test-NullableBoundedString $Payload.rdpState.serviceState 32 '^[A-Za-z]+$') -or
            -not (Test-NullableBoundedString $Payload.rdpState.securityLayer 32 '^[A-Za-z]+$') -or
            -not (Test-NullableBoundedString $Payload.rdpState.minimumEncryptionLevel 32 '^[A-Za-z]+$') -or
            -not (Test-NullableBoundedString $Payload.rdpState.listenerState 32 '^[A-Za-z0-9]+$') -or
            -not (Test-NullableBoundedString $Payload.rdpState.listenerName 64 '^[A-Za-z0-9-]+$')){return $false}
        if(-not (Test-ExactProperties $Payload.winrmState @(
            'allowUnencrypted','basicAuthentication','certificateAuthentication','credSspAuthentication',
            'kerberosAuthentication','listenerPort','listenerState','listenerTransport',
            'negotiateAuthentication','serviceStartMode','serviceState'
        ))){return $false}
        if(($null -ne $Payload.winrmState.allowUnencrypted -and $Payload.winrmState.allowUnencrypted -isnot [bool]) -or
            ($null -ne $Payload.winrmState.basicAuthentication -and $Payload.winrmState.basicAuthentication -isnot [bool]) -or
            ($null -ne $Payload.winrmState.kerberosAuthentication -and $Payload.winrmState.kerberosAuthentication -isnot [bool]) -or
            ($null -ne $Payload.winrmState.negotiateAuthentication -and $Payload.winrmState.negotiateAuthentication -isnot [bool]) -or
            ($null -ne $Payload.winrmState.certificateAuthentication -and $Payload.winrmState.certificateAuthentication -isnot [bool]) -or
            ($null -ne $Payload.winrmState.credSspAuthentication -and $Payload.winrmState.credSspAuthentication -isnot [bool]) -or
            ($null -ne $Payload.winrmState.listenerPort -and -not (Test-BoundedUnsignedInteger $Payload.winrmState.listenerPort ([uint64]65535))) -or
            -not (Test-NullableBoundedString $Payload.winrmState.serviceStartMode 32 '^[A-Za-z]+$') -or
            -not (Test-NullableBoundedString $Payload.winrmState.serviceState 32 '^[A-Za-z]+$') -or
            -not (Test-NullableBoundedString $Payload.winrmState.listenerState 32 '^[A-Za-z0-9]+$') -or
            -not (Test-NullableBoundedString $Payload.winrmState.listenerTransport 16 '^(?:HTTP|HTTPS)$')){return $false}
        if(-not (Test-ExactProperties $Payload.smbState @(
            'clientEnableInsecureGuestLogons','clientEnableSigning','clientRequireSigning',
            'serverEnableSigning','serverEnableSmb1','serverEncryptData',
            'serverRejectUnencryptedAccess','serverRequireSigning','smb1FeatureState'
        ))){return $false}
        foreach($property in @(
            'clientRequireSigning','clientEnableSigning','clientEnableInsecureGuestLogons',
            'serverRequireSigning','serverEnableSigning','serverEncryptData',
            'serverRejectUnencryptedAccess','serverEnableSmb1'
        )){
            if($null -ne $Payload.smbState.$property -and $Payload.smbState.$property -isnot [bool]){return $false}
        }
        if(-not (Test-NullableBoundedString $Payload.smbState.smb1FeatureState 32 '^[A-Za-z]+$')){return $false}
        # A Complete group must contain every declared value. Partial groups
        # may retain typed values, but a failed source cannot donate them.
        foreach($group in @(
            @{scope='rdp.connections';target=$Payload.rdpState;properties=@('connectionsAllowed')},
            @{scope='rdp.service';target=$Payload.rdpState;properties=@('serviceStartMode','serviceState')},
            @{scope='rdp.authentication';target=$Payload.rdpState;properties=@('userAuthenticationRequired','securityLayer','minimumEncryptionLevel')},
            @{scope='rdp.listener';target=$Payload.rdpState;properties=@('listenerName','listenerState')},
            @{scope='winrm.service';target=$Payload.winrmState;properties=@('serviceStartMode','serviceState')},
            @{scope='winrm.configuration';target=$Payload.winrmState;properties=@('allowUnencrypted')},
            @{scope='winrm.authentication';target=$Payload.winrmState;properties=@('basicAuthentication','kerberosAuthentication','negotiateAuthentication','certificateAuthentication','credSspAuthentication')},
            @{scope='winrm.listener';target=$Payload.winrmState;properties=@('listenerState','listenerTransport','listenerPort')},
            @{scope='smb.client';target=$Payload.smbState;properties=@('clientRequireSigning','clientEnableSigning','clientEnableInsecureGuestLogons')},
            @{scope='smb.server';target=$Payload.smbState;properties=@('serverRequireSigning','serverEnableSigning','serverEncryptData','serverRejectUnencryptedAccess','serverEnableSmb1')},
            @{scope='smb.smb1-feature';target=$Payload.smbState;properties=@('smb1FeatureState')}
        )){
            $state=@($Payload.scopeStates|Where-Object scopeId -eq ('scope:policy.'+$group.scope))[0].state
            foreach($name in $group.properties){
                if($state -eq 'Complete' -and $null -eq $group.target.$name){return $false}
                if($state -notin @('Complete','Partial') -and $null -ne $group.target.$name){return $false}
            }
        }
        if(-not (Test-ExactProperties $Payload.bitLockerSystemVolume @(
            'conversionStatus','protectionStatus','encryptionMethod','lockStatus'
        ))){return $false}
        $bitLockerVolumeScopeState=@($Payload.scopeStates|Where-Object scopeId -eq 'scope:policy.bitlocker.operating-system-volume')[0].state
        if($bitLockerVolumeScopeState -eq 'Complete'){
            if(-not (Test-BoundedString $Payload.bitLockerSystemVolume.conversionStatus 64 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-BoundedString $Payload.bitLockerSystemVolume.protectionStatus 32 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-BoundedString $Payload.bitLockerSystemVolume.encryptionMethod 32 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-BoundedString $Payload.bitLockerSystemVolume.lockStatus 32 '^[A-Za-z][A-Za-z0-9]+$')){return $false}
        } elseif($bitLockerVolumeScopeState -eq 'Partial'){
            if(-not (Test-NullableBoundedString $Payload.bitLockerSystemVolume.conversionStatus 64 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-NullableBoundedString $Payload.bitLockerSystemVolume.protectionStatus 32 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-NullableBoundedString $Payload.bitLockerSystemVolume.encryptionMethod 32 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-NullableBoundedString $Payload.bitLockerSystemVolume.lockStatus 32 '^[A-Za-z][A-Za-z0-9]+$')){return $false}
        } elseif($null -ne $Payload.bitLockerSystemVolume.conversionStatus -or
            $null -ne $Payload.bitLockerSystemVolume.protectionStatus -or
            $null -ne $Payload.bitLockerSystemVolume.encryptionMethod -or
            $null -ne $Payload.bitLockerSystemVolume.lockStatus){return $false}
        $bitLockerProtectorScopeState=@($Payload.scopeStates|Where-Object scopeId -eq 'scope:policy.bitlocker.protectors')[0].state
        foreach($protector in @($Payload.bitLockerProtectors)){
            if(-not (Test-ExactProperties $protector @('protectorType','count')) -or
                -not (Test-BoundedString $protector.protectorType 64 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-BoundedUnsignedInteger $protector.count ([uint64]32)) -or
                [decimal]$protector.count -lt 1){return $false}
        }
        if($bitLockerProtectorScopeState -notin @('Complete','Partial') -and @($Payload.bitLockerProtectors).Count -ne 0){return $false}
        if(-not (Test-ExactProperties $Payload.deviceGuard @(
            'virtualizationBasedSecurityStatus','credentialGuardState',
            'memoryIntegrityState','userModeCodeIntegrityState'
        ))){return $false}
        $deviceGuardScopeState=@($Payload.scopeStates|Where-Object scopeId -eq 'scope:policy.vbs.runtime')[0].state
        if($deviceGuardScopeState -eq 'Complete'){
            if(-not (Test-BoundedString $Payload.deviceGuard.virtualizationBasedSecurityStatus 64 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-BoundedString $Payload.deviceGuard.credentialGuardState 64 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-BoundedString $Payload.deviceGuard.memoryIntegrityState 64 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-BoundedString $Payload.deviceGuard.userModeCodeIntegrityState 64 '^[A-Za-z][A-Za-z0-9]+$')){return $false}
        } elseif($deviceGuardScopeState -eq 'Partial'){
            if(-not (Test-NullableBoundedString $Payload.deviceGuard.virtualizationBasedSecurityStatus 64 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-NullableBoundedString $Payload.deviceGuard.credentialGuardState 64 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-NullableBoundedString $Payload.deviceGuard.memoryIntegrityState 64 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-NullableBoundedString $Payload.deviceGuard.userModeCodeIntegrityState 64 '^[A-Za-z][A-Za-z0-9]+$')){return $false}
        } elseif($null -ne $Payload.deviceGuard.virtualizationBasedSecurityStatus -or
            $null -ne $Payload.deviceGuard.credentialGuardState -or
            $null -ne $Payload.deviceGuard.memoryIntegrityState -or
            $null -ne $Payload.deviceGuard.userModeCodeIntegrityState){return $false}
        $wdacScopeState=@($Payload.scopeStates|Where-Object scopeId -eq 'scope:policy.wdac.inventory')[0].state
        foreach($policyItem in @($Payload.wdacPolicies)){
            if(-not (Test-ExactProperties $policyItem @(
                'deploymentChannel','enforcementState','platformPolicy','signedPolicy'
            )) -or
                -not (Test-BoundedString $policyItem.deploymentChannel 64 '^[A-Za-z][A-Za-z0-9]+$') -or
                -not (Test-BoundedString $policyItem.enforcementState 64 '^[A-Za-z][A-Za-z0-9]+$') -or
                $policyItem.platformPolicy -isnot [bool] -or
                $policyItem.signedPolicy -isnot [bool]){return $false}
        }
        if($wdacScopeState -notin @('Complete','Partial') -and @($Payload.wdacPolicies).Count -ne 0){return $false}
        foreach($collectionSet in @(
            @{scopeId='scope:policy.applocker.gp-channel';items=@($Payload.appLockerGpCollections)},
            @{scopeId='scope:policy.applocker.csp-channel';items=@($Payload.appLockerCspCollections)}
        )){
            foreach($collection in @($collectionSet.items)){
                if(-not (Test-ExactProperties $collection @('ruleCollection','enforcementMode')) -or
                    -not (Test-BoundedString $collection.ruleCollection 32 '^[A-Za-z]+$') -or
                    -not (Test-BoundedString $collection.enforcementMode 32 '^[A-Za-z]+$')){return $false}
            }
            $collectionScopeState=@($Payload.scopeStates|Where-Object scopeId -eq $collectionSet.scopeId)[0].state
            if($collectionScopeState -notin @('Complete','Partial') -and @($collectionSet.items).Count -ne 0){return $false}
        }
        $computedConflict=@($Payload.policySettings|Group-Object target,settingId|Where-Object {
            @($_.Group.objectId|Select-Object -Unique).Count -gt 1
        }).Count -gt 0
        if($Payload.appliedOrderConflict -isnot [bool] -or [bool]$Payload.appliedOrderConflict -ne $computedConflict){return $false}
        return $true
    }
    catch{return $false}
}

function Confirm-EffectivePolicyAssessmentUser {
    param([Parameter(Mandatory)]$CollectorResult, [Parameter(Mandatory)]$IdentityCollector,
        [Parameter(Mandatory)]$Policy, [AllowEmptyString()][string]$RequestedSid, [int]$SessionId)
    if($IdentityCollector.payload.userContextState -eq 'Complete' -and
        $IdentityCollector.payload.assessmentUserVerified -eq $true -and
        $IdentityCollector.privateAssessmentUserSid -ceq $RequestedSid -and
        $IdentityCollector.payload.assessmentUserSessionId -eq $SessionId){return}
    $payload=$CollectorResult.payload
    if(@($payload.appliedPolicies|Where-Object target -eq 'User').Count -eq 0 -and
        @($payload.scopeStates|Where-Object {$_.scopeId -like 'scope:policy.applied.user.*' -and $_.state -eq 'Complete'}).Count -eq 0){return}
    # A later identity result cannot relabel the earlier user's policy. Remove
    # only that target before canonical evidence/provenance is constructed.
    $payload.appliedPolicies=@($payload.appliedPolicies|Where-Object target -ne 'User')
    $payload.policySettings=@($payload.policySettings|Where-Object target -ne 'User')
    foreach($scope in $payload.scopeStates|Where-Object scopeId -like 'scope:policy.applied.user.*'){
        $scope.state=if($IdentityCollector.payload.userContextState -eq 'Denied'){'Denied'}else{'Unavailable'}
        $scope.reasonCode='POLICY.ASSESSMENT_USER_CONTEXT_CHANGED'
    }
    $payload.appliedOrderConflict=@($payload.policySettings|Group-Object target,settingId|Where-Object {@($_.Group.objectId|Select-Object -Unique).Count -gt 1}).Count -gt 0
    $payload.layerStates.AppliedPolicyEvidence=Get-EffectivePolicyLayerState -ScopeStates @($payload.scopeStates) -ScopeIds @($Policy.layers[0].scopeIds)
}

function Copy-EffectivePolicyCollectorPayload {
    param([Parameter(Mandatory)]$Payload,[Parameter(Mandatory)]$Policy)
    if(-not (Test-EffectivePolicyCollectorPayload -Payload $Payload -Policy $Policy)){
        throw 'Only a closed Effective Policy payload can cross the privilege boundary.'
    }
    [pscustomobject][ordered]@{
        sourceLocale=[string]$Payload.sourceLocale
        layerStates=[pscustomobject][ordered]@{
            AppliedPolicyEvidence=[string]$Payload.layerStates.AppliedPolicyEvidence
            ConfiguredPolicySignals=[string]$Payload.layerStates.ConfiguredPolicySignals
            CurrentControlState=[string]$Payload.layerStates.CurrentControlState
        }
        scopeStates=@(foreach($scope in Get-EffectivePolicyCollectorScopes -Policy $Policy){
            $entry=@($Payload.scopeStates|Where-Object scopeId -eq $scope.scopeId)[0]
            [pscustomobject][ordered]@{scopeId=[string]$entry.scopeId;state=[string]$entry.state;reasonCode=[string]$entry.reasonCode}
        })
        appliedPolicies=@($Payload.appliedPolicies|ForEach-Object {[pscustomobject][ordered]@{target=[string]$_.target;origin=[string]$_.origin;objectId=[string]$_.objectId;applicable=$_.applicable;linkId=$_.linkId;appliedOrder=$_.appliedOrder}})
        policySettings=@($Payload.policySettings|ForEach-Object {[pscustomobject][ordered]@{target=[string]$_.target;settingId=[string]$_.settingId;objectId=[string]$_.objectId;precedence=[int]$_.precedence}})
        localSam=[pscustomobject][ordered]@{
            minimumPasswordLength=$(if($null -eq $Payload.localSam.minimumPasswordLength){$null}else{[long]$Payload.localSam.minimumPasswordLength})
            maximumPasswordAgeSeconds=$(if($null -eq $Payload.localSam.maximumPasswordAgeSeconds){$null}else{[long]$Payload.localSam.maximumPasswordAgeSeconds})
            minimumPasswordAgeSeconds=$(if($null -eq $Payload.localSam.minimumPasswordAgeSeconds){$null}else{[long]$Payload.localSam.minimumPasswordAgeSeconds})
            passwordHistoryLength=$(if($null -eq $Payload.localSam.passwordHistoryLength){$null}else{[long]$Payload.localSam.passwordHistoryLength})
            lockoutDurationSeconds=$(if($null -eq $Payload.localSam.lockoutDurationSeconds){$null}else{[long]$Payload.localSam.lockoutDurationSeconds})
            lockoutWindowSeconds=$(if($null -eq $Payload.localSam.lockoutWindowSeconds){$null}else{[long]$Payload.localSam.lockoutWindowSeconds})
            lockoutThreshold=$(if($null -eq $Payload.localSam.lockoutThreshold){$null}else{[long]$Payload.localSam.lockoutThreshold})
        }
        auditSubcategories=@($Payload.auditSubcategories|ForEach-Object {[pscustomobject][ordered]@{catalogId=[string]$_.catalogId;state=[string]$_.state;successEnabled=$_.successEnabled;failureEnabled=$_.failureEnabled}})
        userRights=@($Payload.userRights|ForEach-Object {[pscustomobject][ordered]@{catalogId=[string]$_.catalogId;state=[string]$_.state;directSids=@($_.directSids|ForEach-Object {[string]$_})}})
        securityOptions=@($Payload.securityOptions|ForEach-Object {
            $definition=@($Policy.securityOptions|Where-Object catalogId -eq ([string]$_.catalogId))[0]
            $value=if($null -eq $_.value){$null}elseif([string]$definition.valueType -eq 'Boolean'){[bool]$_.value}else{[long]$_.value}
            [pscustomobject][ordered]@{catalogId=[string]$_.catalogId;state=[string]$_.state;value=$value;sourceAttribution=[string]$_.sourceAttribution}
        })
        windowsUpdateSignals=@($Payload.windowsUpdateSignals|ForEach-Object {
            $value=if($null -eq $_.value){$null}elseif([string]$_.catalogId -eq 'windows-update:disable-dual-scan'){[bool]$_.value}else{[long]$_.value}
            [pscustomobject][ordered]@{catalogId=[string]$_.catalogId;state=[string]$_.state;value=$value;sourceAttribution=[string]$_.sourceAttribution}
        })
        legacyAuthenticationSignals=@($Payload.legacyAuthenticationSignals|ForEach-Object {
            [pscustomobject][ordered]@{catalogId=[string]$_.catalogId;state=[string]$_.state;value=$(if($null -eq $_.value){$null}else{[long]$_.value});sourceAttribution=[string]$_.sourceAttribution}
        })
        antivirusProviders=@($Payload.antivirusProviders|ForEach-Object {
            [pscustomobject][ordered]@{name=[string]$_.name;health=[string]$_.health}
        })
        firewallProviders=@($Payload.firewallProviders|ForEach-Object {
            [pscustomobject][ordered]@{name=[string]$_.name;health=[string]$_.health}
        })
        defenderRuntime=[pscustomobject][ordered]@{
            runningMode=$(if($null -eq $Payload.defenderRuntime.runningMode){$null}else{[string]$Payload.defenderRuntime.runningMode})
            antivirusEnabled=$Payload.defenderRuntime.antivirusEnabled
            realTimeProtectionEnabled=$Payload.defenderRuntime.realTimeProtectionEnabled
            tamperProtected=$Payload.defenderRuntime.tamperProtected
        }
        defenderNetworkProtection=[pscustomobject][ordered]@{
            state=[string]$Payload.defenderNetworkProtection.state
            value=$(if($null -eq $Payload.defenderNetworkProtection.value){$null}else{[string]$Payload.defenderNetworkProtection.value})
            sourceAttribution=[string]$Payload.defenderNetworkProtection.sourceAttribution
        }
        defenderAsrRules=@($Payload.defenderAsrRules|ForEach-Object {
            [pscustomobject][ordered]@{ruleId=[string]$_.ruleId;action=[string]$_.action}
        })
        smartScreenSignals=@($Payload.smartScreenSignals|ForEach-Object {
            $value = if ($null -eq $_.value) { $null }
            elseif ([string]$_.catalogId -eq 'smartscreen:app-install-control') { [long]$_.value }
            else { [bool]$_.value }
            [pscustomobject][ordered]@{
                catalogId=[string]$_.catalogId;state=[string]$_.state
                value=$value;sourceAttribution=[string]$_.sourceAttribution
            }
        })
        firewallProfiles=[pscustomobject][ordered]@{
            domain=[pscustomobject][ordered]@{
                state=[string]$Payload.firewallProfiles.domain.state
                enabled=$Payload.firewallProfiles.domain.enabled
                defaultInboundAction=$(if($null -eq $Payload.firewallProfiles.domain.defaultInboundAction){$null}else{[string]$Payload.firewallProfiles.domain.defaultInboundAction})
                defaultOutboundAction=$(if($null -eq $Payload.firewallProfiles.domain.defaultOutboundAction){$null}else{[string]$Payload.firewallProfiles.domain.defaultOutboundAction})
            }
            private=[pscustomobject][ordered]@{
                state=[string]$Payload.firewallProfiles.private.state
                enabled=$Payload.firewallProfiles.private.enabled
                defaultInboundAction=$(if($null -eq $Payload.firewallProfiles.private.defaultInboundAction){$null}else{[string]$Payload.firewallProfiles.private.defaultInboundAction})
                defaultOutboundAction=$(if($null -eq $Payload.firewallProfiles.private.defaultOutboundAction){$null}else{[string]$Payload.firewallProfiles.private.defaultOutboundAction})
            }
            public=[pscustomobject][ordered]@{
                state=[string]$Payload.firewallProfiles.public.state
                enabled=$Payload.firewallProfiles.public.enabled
                defaultInboundAction=$(if($null -eq $Payload.firewallProfiles.public.defaultInboundAction){$null}else{[string]$Payload.firewallProfiles.public.defaultInboundAction})
                defaultOutboundAction=$(if($null -eq $Payload.firewallProfiles.public.defaultOutboundAction){$null}else{[string]$Payload.firewallProfiles.public.defaultOutboundAction})
            }
        }
        rdpState=[pscustomobject][ordered]@{
            connectionsAllowed=$Payload.rdpState.connectionsAllowed
            serviceStartMode=$(if($null -eq $Payload.rdpState.serviceStartMode){$null}else{[string]$Payload.rdpState.serviceStartMode})
            serviceState=$(if($null -eq $Payload.rdpState.serviceState){$null}else{[string]$Payload.rdpState.serviceState})
            userAuthenticationRequired=$Payload.rdpState.userAuthenticationRequired
            securityLayer=$(if($null -eq $Payload.rdpState.securityLayer){$null}else{[string]$Payload.rdpState.securityLayer})
            minimumEncryptionLevel=$(if($null -eq $Payload.rdpState.minimumEncryptionLevel){$null}else{[string]$Payload.rdpState.minimumEncryptionLevel})
            listenerState=$(if($null -eq $Payload.rdpState.listenerState){$null}else{[string]$Payload.rdpState.listenerState})
            listenerName=$(if($null -eq $Payload.rdpState.listenerName){$null}else{[string]$Payload.rdpState.listenerName})
        }
        winrmState=[pscustomobject][ordered]@{
            serviceStartMode=$(if($null -eq $Payload.winrmState.serviceStartMode){$null}else{[string]$Payload.winrmState.serviceStartMode})
            serviceState=$(if($null -eq $Payload.winrmState.serviceState){$null}else{[string]$Payload.winrmState.serviceState})
            allowUnencrypted=$Payload.winrmState.allowUnencrypted
            basicAuthentication=$Payload.winrmState.basicAuthentication
            kerberosAuthentication=$Payload.winrmState.kerberosAuthentication
            negotiateAuthentication=$Payload.winrmState.negotiateAuthentication
            certificateAuthentication=$Payload.winrmState.certificateAuthentication
            credSspAuthentication=$Payload.winrmState.credSspAuthentication
            listenerState=$(if($null -eq $Payload.winrmState.listenerState){$null}else{[string]$Payload.winrmState.listenerState})
            listenerTransport=$(if($null -eq $Payload.winrmState.listenerTransport){$null}else{[string]$Payload.winrmState.listenerTransport})
            listenerPort=$(if($null -eq $Payload.winrmState.listenerPort){$null}else{[long]$Payload.winrmState.listenerPort})
        }
        smbState=[pscustomobject][ordered]@{
            clientRequireSigning=$Payload.smbState.clientRequireSigning
            clientEnableSigning=$Payload.smbState.clientEnableSigning
            clientEnableInsecureGuestLogons=$Payload.smbState.clientEnableInsecureGuestLogons
            serverRequireSigning=$Payload.smbState.serverRequireSigning
            serverEnableSigning=$Payload.smbState.serverEnableSigning
            serverEncryptData=$Payload.smbState.serverEncryptData
            serverRejectUnencryptedAccess=$Payload.smbState.serverRejectUnencryptedAccess
            serverEnableSmb1=$Payload.smbState.serverEnableSmb1
            smb1FeatureState=$(if($null -eq $Payload.smbState.smb1FeatureState){$null}else{[string]$Payload.smbState.smb1FeatureState})
        }
        bitLockerSystemVolume=[pscustomobject][ordered]@{
            conversionStatus=$(if($null -eq $Payload.bitLockerSystemVolume.conversionStatus){$null}else{[string]$Payload.bitLockerSystemVolume.conversionStatus})
            protectionStatus=$(if($null -eq $Payload.bitLockerSystemVolume.protectionStatus){$null}else{[string]$Payload.bitLockerSystemVolume.protectionStatus})
            encryptionMethod=$(if($null -eq $Payload.bitLockerSystemVolume.encryptionMethod){$null}else{[string]$Payload.bitLockerSystemVolume.encryptionMethod})
            lockStatus=$(if($null -eq $Payload.bitLockerSystemVolume.lockStatus){$null}else{[string]$Payload.bitLockerSystemVolume.lockStatus})
        }
        bitLockerProtectors=@($Payload.bitLockerProtectors|ForEach-Object {
            [pscustomobject][ordered]@{
                protectorType=[string]$_.protectorType
                count=[long]$_.count
            }
        })
        deviceGuard=[pscustomobject][ordered]@{
            virtualizationBasedSecurityStatus=$(if($null -eq $Payload.deviceGuard.virtualizationBasedSecurityStatus){$null}else{[string]$Payload.deviceGuard.virtualizationBasedSecurityStatus})
            credentialGuardState=$(if($null -eq $Payload.deviceGuard.credentialGuardState){$null}else{[string]$Payload.deviceGuard.credentialGuardState})
            memoryIntegrityState=$(if($null -eq $Payload.deviceGuard.memoryIntegrityState){$null}else{[string]$Payload.deviceGuard.memoryIntegrityState})
            userModeCodeIntegrityState=$(if($null -eq $Payload.deviceGuard.userModeCodeIntegrityState){$null}else{[string]$Payload.deviceGuard.userModeCodeIntegrityState})
        }
        wdacPolicies=@($Payload.wdacPolicies|ForEach-Object {
            [pscustomobject][ordered]@{
                deploymentChannel=[string]$_.deploymentChannel
                enforcementState=[string]$_.enforcementState
                platformPolicy=[bool]$_.platformPolicy
                signedPolicy=[bool]$_.signedPolicy
            }
        })
        appLockerGpCollections=@($Payload.appLockerGpCollections|ForEach-Object {
            [pscustomobject][ordered]@{
                ruleCollection=[string]$_.ruleCollection
                enforcementMode=[string]$_.enforcementMode
            }
        })
        appLockerCspCollections=@($Payload.appLockerCspCollections|ForEach-Object {
            [pscustomobject][ordered]@{
                ruleCollection=[string]$_.ruleCollection
                enforcementMode=[string]$_.enforcementMode
            }
        })
        appliedOrderConflict=[bool]$Payload.appliedOrderConflict
        localAccountPolicySemantics=[string]$Payload.localAccountPolicySemantics
        userRightSemantics=[string]$Payload.userRightSemantics
    }
}

function Invoke-EffectivePolicyCollection {
    param([Parameter(Mandatory)]$Policy,[Parameter(Mandatory)][string]$ValidationScenario)
    $startedAt=[DateTimeOffset]::UtcNow
    $payload=New-EffectivePolicySyntheticPayload -Policy $Policy -Scenario $ValidationScenario
    if(-not (Test-EffectivePolicyCollectorPayload -Payload $payload -Policy $Policy)){
        throw 'The synthetic Effective Policy payload violates its release contract.'
    }
    [pscustomobject][ordered]@{
        state='Completed';reasonCode='EFFECTIVE_POLICY.COLLECTION_COMPLETED'
        validationScenario=$ValidationScenario;validationFixture=$true
        envelope=[pscustomobject][ordered]@{
            startedAt=$startedAt.ToString('o');completedAt=[DateTimeOffset]::UtcNow.ToString('o')
            attempts=1;executionContext='Synthetic'
        }
        payload=$payload
    }
}

function New-EffectivePolicyPublicProjection {
    param([Parameter(Mandatory)]$CollectorResult)
    $payload=$CollectorResult.payload
    $windowsUpdateCoverage=Get-EffectivePolicyLayerState -ScopeStates @($payload.scopeStates) -ScopeIds @(
        'scope:policy.windows-update.defer-feature-updates',
        'scope:policy.windows-update.defer-quality-updates',
        'scope:policy.windows-update.disable-dual-scan'
    )
    $remoteManagementCoverage=Get-EffectivePolicyLayerState -ScopeStates @($payload.scopeStates) -ScopeIds @(
        'scope:policy.rdp.connections','scope:policy.rdp.service','scope:policy.rdp.authentication','scope:policy.rdp.listener',
        'scope:policy.winrm.service','scope:policy.winrm.configuration','scope:policy.winrm.authentication','scope:policy.winrm.listener'
    )
    $smbCoverage=Get-EffectivePolicyLayerState -ScopeStates @($payload.scopeStates) -ScopeIds @(
        'scope:policy.smb.client','scope:policy.smb.server','scope:policy.smb.smb1-feature'
    )
    $legacyCoverage=Get-EffectivePolicyLayerState -ScopeStates @($payload.scopeStates) -ScopeIds @(
        'scope:policy.legacy-auth.lm-compatibility-level','scope:policy.legacy-auth.ntlm-minimum-session-security'
    )
    [pscustomobject][ordered]@{
        recordType='win-pcinfo.effective-policy-validation';contractVersion='1.0.0'
        scenario=[string]$CollectorResult.validationScenario
        appliedPolicyCoverage=[string]$payload.layerStates.AppliedPolicyEvidence
        configuredSignalCoverage=[string]$payload.layerStates.ConfiguredPolicySignals
        currentControlCoverage=[string]$payload.layerStates.CurrentControlState
        windowsUpdateSignalCoverage=[string]$windowsUpdateCoverage
        remoteManagementCoverage=[string]$remoteManagementCoverage
        smbCoverage=[string]$smbCoverage
        legacyAuthenticationCoverage=[string]$legacyCoverage
        appliedPolicyCount=@($payload.appliedPolicies).Count
        appliedOrderConflict=[bool]$payload.appliedOrderConflict
        auditCatalogCount=@($payload.auditSubcategories).Count
        userRightCatalogCount=@($payload.userRights).Count
        securityOptionCatalogCount=@($payload.securityOptions).Count
        antivirusProviderCount=@($payload.antivirusProviders).Count
        firewallProfileCount=3
        asrRuleCount=@($payload.defenderAsrRules).Count
        bitLockerProtectorTypeCount=@($payload.bitLockerProtectors).Count
        wdacPolicyCount=@($payload.wdacPolicies).Count
        appLockerGpCollectionCount=@($payload.appLockerGpCollections).Count
        appLockerCspCollectionCount=@($payload.appLockerCspCollections).Count
        directRightsOnly=([string]$payload.userRightSemantics -eq 'DirectAssignmentsOnly')
        localSamOnly=([string]$payload.localAccountPolicySemantics -eq 'LocalSamAccountsOnly')
        policyIdentifiersPublished=$false
        policyValuesPublished=$false
        bitLockerSecretsPublished=$false
        applicationControlPoliciesPublished=$false
        updateScanAttempted=$false
        remoteReachabilityTested=$false
        smbSharesEnumerated=$false
        smbSessionsEnumerated=$false
        legacyProtocolUseInferred=$false
        policyStateChanged=$false
        policyRefreshAttempted=$false
        toolInstalled=$false
    }
}

function Get-EffectivePolicyMdmSystemFieldIds {
    @(
        'field:policy.mdm.control-policy-conflict.mdm-wins-over-gp',
        'field:policy.mdm.security-option.machine-inactivity-limit-seconds',
        'field:policy.mdm.security-option.disable-cad',
        'field:policy.mdm.security-option.lm-compatibility-level',
        'field:policy.mdm.update.defer-feature-updates-days',
        'field:policy.mdm.update.defer-quality-updates-days',
        'field:policy.mdm.update.disable-dual-scan'
    )
}

function New-EffectivePolicyPrivilegeGapResult {
    param(
        [Parameter(Mandatory)]$PrivilegeResult,
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][bool]$ValidationFixture
    )
    $state=if([string]$PrivilegeResult.state -eq 'Cancelled'){'Cancelled'}elseif([string]$PrivilegeResult.state -eq 'Unavailable'){'Denied'}else{'Failed'}
    $reason=if($state -eq 'Cancelled'){'POLICY.ADMINISTRATOR_SOURCE_CANCELLED'}elseif($state -eq 'Denied'){'POLICY.ADMINISTRATOR_SOURCE_DENIED'}else{'POLICY.ADMINISTRATOR_SOURCE_FAILED'}
    $payload=New-EffectivePolicySyntheticPayload -Policy $Policy -Scenario 'DeniedAdministrator'
    foreach($scope in $payload.scopeStates){$scope.state=$state;$scope.reasonCode=$reason}
    foreach($layer in $payload.layerStates.PSObject.Properties){$layer.Value=$state}
    $now=[DateTimeOffset]::UtcNow.ToString('o')
    [pscustomobject][ordered]@{
        state='CompletedWithGaps';reasonCode=[string]$PrivilegeResult.reasonCode
        validationScenario=if($ValidationFixture){'DeniedAdministrator'}else{'Denied'}
        validationFixture=$ValidationFixture
        envelope=[pscustomobject][ordered]@{
            startedAt=$now;completedAt=$now;attempts=1
            executionContext=if($ValidationFixture){'Synthetic'}else{'Administrator'}
        }
        payload=$payload
    }
}

function Get-EffectivePolicySourceId {
    param([Parameter(Mandatory)][string]$FieldId)
    if($FieldId -like 'field:policy.applied.*'){'source:windows.rsop.logging-mode'}
    elseif($FieldId -like 'field:policy.local-sam.*'){'source:windows.local-sam-policy'}
    elseif($FieldId -like 'field:policy.audit.*'){'source:windows.system-audit-policy'}
    elseif($FieldId -like 'field:policy.user-right.*'){'source:windows.lsa-user-rights'}
    elseif($FieldId -like 'field:policy.security-provider.*'){'source:windows.security-center.providers'}
    elseif($FieldId -like 'field:policy.windows-update.*'){'source:windows.update-policy-registry'}
    elseif($FieldId -like 'field:policy.legacy-auth.*'){'source:windows.legacy-authentication-registry'}
    elseif($FieldId -like 'field:policy.defender.running-mode' -or
        $FieldId -like 'field:policy.defender.antivirus-enabled' -or
        $FieldId -like 'field:policy.defender.real-time-protection-enabled' -or
        $FieldId -like 'field:policy.defender.tamper-protected'){'source:windows.defender.runtime-status'}
    elseif($FieldId -like 'field:policy.defender.asr.*' -or
        $FieldId -eq 'field:policy.defender.network-protection'){'source:windows.defender.preferences'}
    elseif($FieldId -like 'field:policy.firewall.*'){'source:windows.firewall.activestore-profiles'}
    elseif($FieldId -like 'field:policy.rdp.*'){'source:windows.rdp.configuration'}
    elseif($FieldId -like 'field:policy.winrm.*'){'source:windows.winrm.configuration'}
    elseif($FieldId -like 'field:policy.smb.*'){'source:windows.smb.configuration'}
    elseif($FieldId -like 'field:policy.bitlocker.*'){'source:windows.bitlocker.volume-status'}
    elseif($FieldId -like 'field:policy.vbs.*' -or
        $FieldId -like 'field:policy.credential-guard.*' -or
        $FieldId -like 'field:policy.memory-integrity.*' -or
        $FieldId -like 'field:policy.user-mode-code-integrity.*'){'source:windows.device-guard.status'}
    elseif($FieldId -like 'field:policy.wdac.*'){'source:windows.app-control.citool'}
    elseif($FieldId -like 'field:policy.applocker.gp.*'){'source:windows.applocker.gp-effective-policy'}
    elseif($FieldId -like 'field:policy.applocker.csp.*'){'source:windows.applocker.csp-policy'}
    elseif($FieldId -like 'field:policy.mdm.*'){'source:windows.mdm-policy-csp-results'}
    else{'source:windows.local-configured-signals'}
}

function New-EffectivePolicyObservationPair {
    param(
        [Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$Suffix,
        [Parameter(Mandatory)][string]$FieldId,[Parameter(Mandatory)][string]$SubjectId,
        [Parameter(Mandatory)]$Collector,[Parameter(Mandatory)][string]$ObservedExecutionContext,
        [Parameter(Mandatory)][string]$CollectedAt,[Parameter(Mandatory)][string]$SourceLocale,
        [Parameter()]$Value,[Parameter()][string]$SourceId,[Parameter()][switch]$ObservedAbsent
    )
    $observationId="observation:policy-$Suffix`:$RunId"
    $provenanceId="provenance:policy-$Suffix`:$RunId"
    $observation=[ordered]@{
        observationId=$observationId;fieldId=$FieldId;subjectId=$SubjectId
        provenanceId=$provenanceId;valueState=if($ObservedAbsent){'ObservedAbsent'}else{'ObservedValue'}
    }
    if(-not $ObservedAbsent){$observation.value=$Value}
    [pscustomobject][ordered]@{
        observation=[pscustomobject]$observation
        provenance=[pscustomobject][ordered]@{
            provenanceId=$provenanceId;fieldId=$FieldId;subjectId=$SubjectId
            sourceId=$(if([string]::IsNullOrEmpty($SourceId)){Get-EffectivePolicySourceId -FieldId $FieldId}else{$SourceId})
            collectorId=[string]$Collector.collectorId;collectorVersion=[string]$Collector.collectorVersion
            executionContext=$ObservedExecutionContext;collectedAt=$CollectedAt;sourceLocale=$SourceLocale
        }
    }
}

function Add-EffectivePolicyEvidenceRecord {
    param(
        [Parameter(Mandatory)]$Record,[Parameter(Mandatory)]$CollectorResult,
        [Parameter(Mandatory)]$Policy,
        [Parameter()]$SystemResult
    )
    if([string]$Record.run.evidenceProfileId -ne 'profile:device-firmware-identity-and-administrator-readiness'){
        throw 'Effective Policy evidence requires the accepted administrator-ready evidence profile.'
    }
    if(@($Record.findings|Where-Object {$_.ruleId -in @($Policy.rules.ruleId)}).Count -ne 0){
        throw 'Effective Policy source evidence cannot be added after its Rule Evaluations.'
    }
    if(-not (Test-EffectivePolicyCollectorPayload -Payload $CollectorResult.payload -Policy $Policy)){
        throw 'Effective Policy evidence requires a closed collector result.'
    }
    $runId=[string]$Record.run.runId;$payload=$CollectorResult.payload;$collector=$Policy.collectors[0]
    $collectedAt=[string]$CollectorResult.envelope.completedAt
    $observedExecutionContext=[string]$CollectorResult.envelope.executionContext
    $observations=[Collections.Generic.List[object]]::new()
    $provenance=[Collections.Generic.List[object]]::new()
    $newSubjects=[Collections.Generic.List[object]]::new()
    $envelopeSubjects=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $null=$envelopeSubjects.Add('subject:device:primary')
    $scopeObservationIds=@{}
    foreach($scope in $Policy.scopes){$scopeObservationIds[[string]$scope.scopeId]=[Collections.Generic.List[string]]::new()}
    $existingSystemEnvelopes=@($Record.collectorResults|Where-Object {
        $_.collectorId -eq 'collector:windows.mdm-bridge.device-manageability' -and
        $_.operationId -eq 'op:windows.mdm-bridge.device-manageability'
    })
    if($existingSystemEnvelopes.Count -ne 1){
        throw 'Effective Policy evidence requires exactly one composed SYSTEM collector attempt.'
    }
    $existingSystemEnvelope=$existingSystemEnvelopes[0]
    $providedSystemEnvelope = if ($null -ne $SystemResult -and
        $SystemResult.PSObject.Properties['collectorResult'] -and
        $null -ne $SystemResult.collectorResult -and
        $SystemResult.collectorResult.PSObject.Properties['Envelope']) {
        $SystemResult.collectorResult.Envelope
    }
    else { $null }
    $hasPrivateSystemResults=$null -ne $SystemResult -and
        $SystemResult.PSObject.Properties['PrivatePolicyCspResults'] -and
        $null -ne $SystemResult.PrivatePolicyCspResults
    if($hasPrivateSystemResults -and $null -eq $providedSystemEnvelope){
        throw 'Effective Policy restricted evidence requires its exact SYSTEM attempt envelope.'
    }
    if($null -ne $providedSystemEnvelope -and
        ([string]$providedSystemEnvelope.envelopeId -ne [string]$existingSystemEnvelope.envelopeId -or
         [string]$providedSystemEnvelope.collectorId -ne [string]$existingSystemEnvelope.collectorId -or
         [string]$providedSystemEnvelope.collectorVersion -ne [string]$existingSystemEnvelope.collectorVersion -or
         [string]$providedSystemEnvelope.operationId -ne [string]$existingSystemEnvelope.operationId -or
         [string]$providedSystemEnvelope.startedAt -ne [string]$existingSystemEnvelope.startedAt -or
         [string]$providedSystemEnvelope.completedAt -ne [string]$existingSystemEnvelope.completedAt -or
         [string]$providedSystemEnvelope.executionContext -ne [string]$existingSystemEnvelope.executionContext -or
         [int]$providedSystemEnvelope.attempts -ne [int]$existingSystemEnvelope.attempts -or
         (@($providedSystemEnvelope.intendedScopeIds)-join '|') -ne
            (@($existingSystemEnvelope.intendedScopeIds)-join '|') -or
         (@($providedSystemEnvelope.subjectIds)-join '|') -ne
            (@($existingSystemEnvelope.subjectIds)-join '|'))){
        throw 'Effective Policy evidence cannot attach results from a different SYSTEM attempt.'
    }
    $systemEnvelope=$existingSystemEnvelope
    $hasSystemCsp=$hasPrivateSystemResults -and $null -ne $SystemResult.PrivatePolicyCspResults.PSObject.Properties['appLockerCsp']
    if($hasSystemCsp){
        $payload=$payload|ConvertTo-Json -Depth 12|ConvertFrom-Json -Depth 12
        $csp=$SystemResult.PrivatePolicyCspResults.appLockerCsp
        $payload.appLockerCspCollections=@($csp.collections)
        $scope=@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.applocker.csp-channel')[0]
        $scope.state=[string]$csp.state;$scope.reasonCode=[string]$csp.reasonCode
    }elseif($observedExecutionContext -ne 'Synthetic'){
        $payload=Copy-EffectivePolicyCollectorPayload -Payload $payload -Policy $Policy
        $payload.appLockerCspCollections=@()
        $scope=@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.applocker.csp-channel')[0]
        $scope.state='Unavailable';$scope.reasonCode='POLICY.APPLOCKER_CSP_UNAVAILABLE'
    }

    function Add-PolicyObservation {
        param(
            [string]$ScopeId,[string]$Suffix,[string]$FieldId,[string]$SubjectId,$Value,
            [bool]$Absent=$false,$EvidenceCollector=$null,
            [string]$EvidenceExecutionContext='',[string]$EvidenceCollectedAt='',
            [string]$EvidenceSourceLocale='',[string]$EvidenceSourceId=''
        )
        if($ScopeId -eq 'scope:policy.applocker.csp-channel'){
            $EvidenceCollector=$existingSystemEnvelope
            $EvidenceExecutionContext=[string]$existingSystemEnvelope.executionContext
            $EvidenceCollectedAt=[string]$existingSystemEnvelope.completedAt
            $EvidenceSourceLocale='und'
        }
        if($null -eq $EvidenceCollector){$EvidenceCollector=$collector}
        if([string]::IsNullOrEmpty($EvidenceExecutionContext)){$EvidenceExecutionContext=$observedExecutionContext}
        if([string]::IsNullOrEmpty($EvidenceCollectedAt)){$EvidenceCollectedAt=$collectedAt}
        if([string]::IsNullOrEmpty($EvidenceSourceLocale)){$EvidenceSourceLocale=[string]$payload.sourceLocale}
        $arguments=@{RunId=$runId;Suffix=$Suffix;FieldId=$FieldId;SubjectId=$SubjectId;Collector=$EvidenceCollector;ObservedExecutionContext=$EvidenceExecutionContext;CollectedAt=$EvidenceCollectedAt;SourceLocale=$EvidenceSourceLocale;SourceId=$EvidenceSourceId;Value=$Value}
        if($Absent){$arguments.ObservedAbsent=$true}
        $pair=New-EffectivePolicyObservationPair @arguments
        $observations.Add($pair.observation);$provenance.Add($pair.provenance)
        $scopeObservationIds[$ScopeId].Add([string]$pair.observation.observationId)
        $null=$envelopeSubjects.Add($SubjectId)
    }
    function Test-PolicyScopeCarriesEvidence([string]$ScopeId){
        [string]@($payload.scopeStates|Where-Object scopeId -eq $ScopeId)[0].state -in @('Complete','Partial')
    }

    $policySubjectByObject=@{};$policyIndex=0
    foreach($item in @($payload.appliedPolicies)){
        $subjectId="subject:policy-object:$policyIndex"
        $newSubjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='PolicyObject'})
        $policySubjectByObject["$([string]$item.target)|$([string]$item.objectId)"]=$subjectId
        $target=([string]$item.target).ToLowerInvariant()
        $identityScope="scope:policy.applied.$target.identity"
        if(Test-PolicyScopeCarriesEvidence $identityScope){
            Add-PolicyObservation $identityScope "object-$policyIndex-id" 'field:policy.applied.object-id' $subjectId ([string]$item.objectId)
            Add-PolicyObservation $identityScope "object-$policyIndex-target" 'field:policy.applied.target' $subjectId ([string]$item.target)
            Add-PolicyObservation $identityScope "object-$policyIndex-origin" 'field:policy.applied.origin' $subjectId ([string]$item.origin)
        }
        $applicabilityScope="scope:policy.applied.$target.applicability"
        if(Test-PolicyScopeCarriesEvidence $applicabilityScope){
            if($null -eq $item.applicable){
                Add-PolicyObservation $applicabilityScope "object-$policyIndex-applicable" 'field:policy.applied.applicable' $subjectId $null $true
            }else{
                Add-PolicyObservation $applicabilityScope "object-$policyIndex-applicable" 'field:policy.applied.applicable' $subjectId ([bool]$item.applicable)
            }
        }
        $linkScope="scope:policy.applied.$target.link"
        if(Test-PolicyScopeCarriesEvidence $linkScope){
            if($null -eq $item.linkId){
                Add-PolicyObservation $linkScope "object-$policyIndex-link" 'field:policy.applied.link-id' $subjectId $null $true
            }else{
                Add-PolicyObservation $linkScope "object-$policyIndex-link" 'field:policy.applied.link-id' $subjectId ([string]$item.linkId)
            }
        }
        $policyIndex++
    }
    $settingIndex=0
    foreach($item in @($payload.policySettings)){
        $policyKey="$([string]$item.target)|$([string]$item.objectId)"
        if(-not $policySubjectByObject.ContainsKey($policyKey)){
            throw 'An RSoP setting does not bind to an admitted policy object.'
        }
        $subjectId=[string]$policySubjectByObject[$policyKey]
        $scope="scope:policy.applied.$(([string]$item.target).ToLowerInvariant()).precedence"
        if(Test-PolicyScopeCarriesEvidence $scope){
            Add-PolicyObservation $scope "setting-$settingIndex-id" 'field:policy.applied.setting-id' $subjectId ([string]$item.settingId)
            Add-PolicyObservation $scope "setting-$settingIndex-precedence" 'field:policy.applied.precedence' $subjectId ([int]$item.precedence)
        }
        $settingIndex++
    }

    # A successfully queried empty RSoP channel is not a failure. Each empty
    # field is represented as ObservedAbsent on the applicable device/user
    # subject so Complete coverage proves the bounded absence without inventing
    # a policy object. Unsupported or denied channels produce no observations.
    foreach($target in @('user','computer')){
        $fallbackSubject=if($target -eq 'user'){'subject:assessment-user:primary'}else{'subject:device:primary'}
        foreach($scope in @($Policy.scopes|Where-Object {$_.scopeId -like "scope:policy.applied.$target.*"})){
            $state=@($payload.scopeStates|Where-Object scopeId -eq $scope.scopeId)[0]
            if($state.state -ne 'Complete'){continue}
            $present=@($scopeObservationIds[[string]$scope.scopeId]|ForEach-Object {
                $id=$_;[string]@($observations|Where-Object observationId -eq $id)[0].fieldId
            }|Sort-Object -Unique)
            foreach($fieldId in @($scope.fieldIds|Where-Object {$_ -notin $present})){
                Add-PolicyObservation ([string]$scope.scopeId) "absent-$target-$($fieldId.Split('.')[-1])" ([string]$fieldId) $fallbackSubject $null $true
            }
        }
    }

    $samFields=@{
        'field:policy.local-sam.minimum-authenticator-length'='minimumPasswordLength'
        'field:policy.local-sam.maximum-authenticator-age-seconds'='maximumPasswordAgeSeconds'
        'field:policy.local-sam.minimum-authenticator-age-seconds'='minimumPasswordAgeSeconds'
        'field:policy.local-sam.authenticator-history-length'='passwordHistoryLength'
        'field:policy.local-sam.lockout-duration-seconds'='lockoutDurationSeconds'
        'field:policy.local-sam.lockout-window-seconds'='lockoutWindowSeconds'
        'field:policy.local-sam.lockout-threshold'='lockoutThreshold'
    }
    foreach($scope in @($Policy.scopes|Where-Object {$_.scopeId -like 'scope:policy.local-sam.*'})){
        $state=@($payload.scopeStates|Where-Object scopeId -eq $scope.scopeId)[0]
        if($state.state -notin @('Complete','Partial')){continue}
        foreach($fieldId in $scope.fieldIds){
            $property=$samFields[[string]$fieldId];$value=$payload.localSam.$property
            if($null -ne $value){Add-PolicyObservation ([string]$scope.scopeId) "sam-$property" ([string]$fieldId) 'subject:device:primary' ([int]$value)}
        }
    }
    $auditIndex=0
    foreach($audit in @($payload.auditSubcategories)){
        if($audit.state -eq 'Complete'){
            Add-PolicyObservation 'scope:policy.local-audit' "audit-$auditIndex-id" 'field:policy.audit.subcategory-id' 'subject:device:primary' ([string]$audit.catalogId)
            Add-PolicyObservation 'scope:policy.local-audit' "audit-$auditIndex-success" 'field:policy.audit.success-enabled' 'subject:device:primary' ([bool]$audit.successEnabled)
            Add-PolicyObservation 'scope:policy.local-audit' "audit-$auditIndex-failure" 'field:policy.audit.failure-enabled' 'subject:device:primary' ([bool]$audit.failureEnabled)
        }
        $auditIndex++
    }
    $rightIndex=0;$principalIndex=0
    foreach($right in @($payload.userRights)){
        if($right.state -in @('Complete','Partial')){
            Add-PolicyObservation 'scope:policy.local-user-rights' "right-$rightIndex-id" 'field:policy.user-right.catalog-id' 'subject:device:primary' ([string]$right.catalogId)
            foreach($sid in @($right.directSids)){
                $subjectId="subject:policy-principal:$principalIndex"
                $newSubjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='SecurityPrincipal'})
                Add-PolicyObservation 'scope:policy.local-user-rights' "right-$rightIndex-principal-$principalIndex-catalog" 'field:policy.user-right.catalog-id' $subjectId ([string]$right.catalogId)
                Add-PolicyObservation 'scope:policy.local-user-rights' "right-$rightIndex-principal-$principalIndex" 'field:policy.user-right.direct-principal-sid' $subjectId ([string]$sid)
                Add-PolicyObservation 'scope:policy.local-user-rights' "right-$rightIndex-direct-$principalIndex" 'field:policy.user-right.direct-assignment' $subjectId $true
                $principalIndex++
            }
        }
        $rightIndex++
    }
    $rightsState=@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.local-user-rights')[0]
    if($rightsState.state -eq 'Complete'){
        foreach($fieldId in @('field:policy.user-right.direct-principal-sid','field:policy.user-right.direct-assignment')){
            $present=@($observations|Where-Object fieldId -eq $fieldId)
            if($present.Count -eq 0){Add-PolicyObservation 'scope:policy.local-user-rights' "rights-absent-$($fieldId.Split('.')[-1])" $fieldId 'subject:device:primary' $null $true}
        }
    }
    $optionScope=@{
        'security-option:machine-inactivity-limit-seconds'='scope:policy.security-option.machine-inactivity-limit'
        'security-option:disable-cad'='scope:policy.security-option.disable-cad'
        'security-option:lm-compatibility-level'='scope:policy.security-option.lm-compatibility-level'
    }
    $optionField=@{};foreach($definition in $Policy.securityOptions){$optionField[[string]$definition.catalogId]=[string]$definition.fieldId}
    $optionIndex=0
    foreach($option in @($payload.securityOptions)){
        if($option.state -eq 'Complete'){
            if($null -eq $option.value){
                Add-PolicyObservation $optionScope[[string]$option.catalogId] "security-option-$optionIndex" $optionField[[string]$option.catalogId] 'subject:device:primary' $null $true
            }else{
                Add-PolicyObservation $optionScope[[string]$option.catalogId] "security-option-$optionIndex" $optionField[[string]$option.catalogId] 'subject:device:primary' $option.value
            }
        }
        $optionIndex++
    }
    $updateIndex=0
    foreach($signal in @($payload.windowsUpdateSignals)){
        $definition=@(Get-EffectivePolicyWindowsUpdateDefinitions|Where-Object catalogId -eq ([string]$signal.catalogId))[0]
        if($signal.state -eq 'Complete'){
            if($null -eq $signal.value){
                Add-PolicyObservation ([string]$definition.scopeId) "windows-update-$updateIndex" ([string]$definition.fieldId) 'subject:device:primary' $null $true
            } else {
                Add-PolicyObservation ([string]$definition.scopeId) "windows-update-$updateIndex" ([string]$definition.fieldId) 'subject:device:primary' $signal.value
            }
        }
        $updateIndex++
    }
    $legacyIndex=0
    foreach($signal in @($payload.legacyAuthenticationSignals)){
        $definition=@(Get-EffectivePolicyLegacyAuthenticationDefinitions|Where-Object catalogId -eq ([string]$signal.catalogId))[0]
        if($signal.state -eq 'Complete'){
            if($null -eq $signal.value){
                Add-PolicyObservation ([string]$definition.scopeId) "legacy-auth-$legacyIndex" ([string]$definition.fieldId) 'subject:device:primary' $null $true
            } else {
                Add-PolicyObservation ([string]$definition.scopeId) "legacy-auth-$legacyIndex" ([string]$definition.fieldId) 'subject:device:primary' ([long]$signal.value)
            }
        }
        $legacyIndex++
    }
    $providerIndex=0
    foreach($provider in @($payload.antivirusProviders)){
        $subjectId="subject:policy-antivirus-provider:$providerIndex"
        $newSubjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='OtherSynthetic'})
        Add-PolicyObservation 'scope:policy.security-center.antivirus-providers' "antivirus-provider-$providerIndex-name" 'field:policy.security-provider.name' $subjectId ([string]$provider.name)
        Add-PolicyObservation 'scope:policy.security-center.antivirus-providers' "antivirus-provider-$providerIndex-health" 'field:policy.security-provider.health' $subjectId ([string]$provider.health)
        $providerIndex++
    }
    $providerIndex=0
    foreach($provider in @($payload.firewallProviders)){
        $subjectId="subject:policy-firewall-provider:$providerIndex"
        $newSubjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='OtherSynthetic'})
        Add-PolicyObservation 'scope:policy.security-center.firewall-providers' "firewall-provider-$providerIndex-name" 'field:policy.security-provider.name' $subjectId ([string]$provider.name)
        Add-PolicyObservation 'scope:policy.security-center.firewall-providers' "firewall-provider-$providerIndex-health" 'field:policy.security-provider.health' $subjectId ([string]$provider.health)
        $providerIndex++
    }
    if(@($payload.antivirusProviders).Count -eq 0 -and
        @($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.security-center.antivirus-providers')[0].state -eq 'Complete'){
        Add-PolicyObservation 'scope:policy.security-center.antivirus-providers' 'antivirus-provider-name-absent' 'field:policy.security-provider.name' 'subject:device:primary' $null $true
        Add-PolicyObservation 'scope:policy.security-center.antivirus-providers' 'antivirus-provider-health-absent' 'field:policy.security-provider.health' 'subject:device:primary' $null $true
    }
    if(@($payload.firewallProviders).Count -eq 0 -and
        @($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.security-center.firewall-providers')[0].state -eq 'Complete'){
        Add-PolicyObservation 'scope:policy.security-center.firewall-providers' 'firewall-provider-name-absent' 'field:policy.security-provider.name' 'subject:device:primary' $null $true
        Add-PolicyObservation 'scope:policy.security-center.firewall-providers' 'firewall-provider-health-absent' 'field:policy.security-provider.health' 'subject:device:primary' $null $true
    }
    $runtimeScope=@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.defender.runtime')[0]
    if($runtimeScope.state -in @('Complete','Partial')){
        if($null -ne $payload.defenderRuntime.runningMode){
            Add-PolicyObservation 'scope:policy.defender.runtime' 'defender-runtime-mode' 'field:policy.defender.running-mode' 'subject:device:primary' ([string]$payload.defenderRuntime.runningMode)
        }
        foreach($property in @(
            @{name='antivirusEnabled';fieldId='field:policy.defender.antivirus-enabled'},
            @{name='realTimeProtectionEnabled';fieldId='field:policy.defender.real-time-protection-enabled'},
            @{name='tamperProtected';fieldId='field:policy.defender.tamper-protected'}
        )){
            $value=$payload.defenderRuntime.([string]$property.name)
            if($null -ne $value){
                Add-PolicyObservation 'scope:policy.defender.runtime' "defender-runtime-$($property.name)" ([string]$property.fieldId) 'subject:device:primary' ([bool]$value)
            }
        }
    }
    if($payload.defenderNetworkProtection.state -eq 'Complete'){
        if($null -eq $payload.defenderNetworkProtection.value){
            Add-PolicyObservation 'scope:policy.defender.network-protection' 'defender-network-protection' 'field:policy.defender.network-protection' 'subject:device:primary' $null $true
        } else {
            Add-PolicyObservation 'scope:policy.defender.network-protection' 'defender-network-protection' 'field:policy.defender.network-protection' 'subject:device:primary' ([string]$payload.defenderNetworkProtection.value)
        }
    }
    $asrIndex=0
    foreach($rule in @($payload.defenderAsrRules)){
        $subjectId="subject:policy-defender-asr:$asrIndex"
        $newSubjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='OtherSynthetic'})
        Add-PolicyObservation 'scope:policy.defender.asr' "defender-asr-$asrIndex-id" 'field:policy.defender.asr.rule-id' $subjectId ([string]$rule.ruleId)
        Add-PolicyObservation 'scope:policy.defender.asr' "defender-asr-$asrIndex-action" 'field:policy.defender.asr.action' $subjectId ([string]$rule.action)
        $asrIndex++
    }
    if(@($payload.defenderAsrRules).Count -eq 0 -and
        @($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.defender.asr')[0].state -eq 'Complete'){
        Add-PolicyObservation 'scope:policy.defender.asr' 'defender-asr-id-absent' 'field:policy.defender.asr.rule-id' 'subject:device:primary' $null $true
        Add-PolicyObservation 'scope:policy.defender.asr' 'defender-asr-action-absent' 'field:policy.defender.asr.action' 'subject:device:primary' $null $true
    }
    $smartScreenScope=@{
        'smartscreen:enable-in-shell'='scope:policy.smartscreen.shell'
        'smartscreen:prevent-override-for-files'='scope:policy.smartscreen.shell'
        'smartscreen:app-install-control'='scope:policy.smartscreen.app-install-control'
    }
    $smartScreenField=@{}
    foreach($definition in $Policy.smartScreenSignals){$smartScreenField[[string]$definition.catalogId]=[string]$definition.fieldId}
    $smartScreenIndex=0
    foreach($signal in @($payload.smartScreenSignals)){
        if($signal.state -eq 'Complete'){
            if($null -eq $signal.value){
                Add-PolicyObservation $smartScreenScope[[string]$signal.catalogId] "smartscreen-$smartScreenIndex" $smartScreenField[[string]$signal.catalogId] 'subject:device:primary' $null $true
            } else {
                Add-PolicyObservation $smartScreenScope[[string]$signal.catalogId] "smartscreen-$smartScreenIndex" $smartScreenField[[string]$signal.catalogId] 'subject:device:primary' $signal.value
            }
        }
        $smartScreenIndex++
    }
    foreach($profileName in @('domain','private','public')){
        $profile=$payload.firewallProfiles.$profileName
        $scopeId="scope:policy.firewall.$profileName-profile"
        $subjectId="subject:policy-firewall-profile:$profileName"
        $newSubjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='OtherSynthetic'})
        if($profile.state -eq 'Complete'){
            Add-PolicyObservation $scopeId "firewall-$profileName-enabled" 'field:policy.firewall.enabled' $subjectId ([bool]$profile.enabled)
            Add-PolicyObservation $scopeId "firewall-$profileName-inbound" 'field:policy.firewall.default-inbound-action' $subjectId ([string]$profile.defaultInboundAction)
            Add-PolicyObservation $scopeId "firewall-$profileName-outbound" 'field:policy.firewall.default-outbound-action' $subjectId ([string]$profile.defaultOutboundAction)
        }
    }
    if(@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.rdp.connections')[0].state -eq 'Complete'){
        Add-PolicyObservation 'scope:policy.rdp.connections' 'rdp-connections' 'field:policy.rdp.connections-allowed' 'subject:device:primary' ([bool]$payload.rdpState.connectionsAllowed)
    }
    if(@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.rdp.service')[0].state -eq 'Complete'){
        Add-PolicyObservation 'scope:policy.rdp.service' 'rdp-service-mode' 'field:policy.rdp.service-start-mode' 'subject:device:primary' ([string]$payload.rdpState.serviceStartMode)
        Add-PolicyObservation 'scope:policy.rdp.service' 'rdp-service-state' 'field:policy.rdp.service-state' 'subject:device:primary' ([string]$payload.rdpState.serviceState)
    }
    if(@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.rdp.authentication')[0].state -eq 'Complete'){
        Add-PolicyObservation 'scope:policy.rdp.authentication' 'rdp-auth-required' 'field:policy.rdp.user-authentication-required' 'subject:device:primary' ([bool]$payload.rdpState.userAuthenticationRequired)
        Add-PolicyObservation 'scope:policy.rdp.authentication' 'rdp-security-layer' 'field:policy.rdp.security-layer' 'subject:device:primary' ([string]$payload.rdpState.securityLayer)
        Add-PolicyObservation 'scope:policy.rdp.authentication' 'rdp-min-encryption' 'field:policy.rdp.minimum-encryption-level' 'subject:device:primary' ([string]$payload.rdpState.minimumEncryptionLevel)
    }
    if(@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.rdp.listener')[0].state -eq 'Complete'){
        Add-PolicyObservation 'scope:policy.rdp.listener' 'rdp-listener-state' 'field:policy.rdp.listener-state' 'subject:device:primary' ([string]$payload.rdpState.listenerState)
        Add-PolicyObservation 'scope:policy.rdp.listener' 'rdp-listener-name' 'field:policy.rdp.listener-name' 'subject:device:primary' ([string]$payload.rdpState.listenerName)
    }
    if(@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.winrm.service')[0].state -eq 'Complete'){
        if($null -ne $payload.winrmState.serviceStartMode){Add-PolicyObservation 'scope:policy.winrm.service' 'winrm-service-mode' 'field:policy.winrm.service-start-mode' 'subject:device:primary' ([string]$payload.winrmState.serviceStartMode)}
        if($null -ne $payload.winrmState.serviceState){Add-PolicyObservation 'scope:policy.winrm.service' 'winrm-service-state' 'field:policy.winrm.service-state' 'subject:device:primary' ([string]$payload.winrmState.serviceState)}
    }
    if(@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.winrm.configuration')[0].state -eq 'Complete'){
        if($null -ne $payload.winrmState.allowUnencrypted){Add-PolicyObservation 'scope:policy.winrm.configuration' 'winrm-allow-unencrypted' 'field:policy.winrm.allow-unencrypted' 'subject:device:primary' ([bool]$payload.winrmState.allowUnencrypted)}
    }
    if(@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.winrm.authentication')[0].state -in @('Complete','Partial')){
        if($null -ne $payload.winrmState.basicAuthentication){Add-PolicyObservation 'scope:policy.winrm.authentication' 'winrm-auth-basic' 'field:policy.winrm.auth-basic' 'subject:device:primary' ([bool]$payload.winrmState.basicAuthentication)}
        if($null -ne $payload.winrmState.kerberosAuthentication){Add-PolicyObservation 'scope:policy.winrm.authentication' 'winrm-auth-kerberos' 'field:policy.winrm.auth-kerberos' 'subject:device:primary' ([bool]$payload.winrmState.kerberosAuthentication)}
        if($null -ne $payload.winrmState.negotiateAuthentication){Add-PolicyObservation 'scope:policy.winrm.authentication' 'winrm-auth-negotiate' 'field:policy.winrm.auth-negotiate' 'subject:device:primary' ([bool]$payload.winrmState.negotiateAuthentication)}
        if($null -ne $payload.winrmState.certificateAuthentication){Add-PolicyObservation 'scope:policy.winrm.authentication' 'winrm-auth-certificate' 'field:policy.winrm.auth-certificate' 'subject:device:primary' ([bool]$payload.winrmState.certificateAuthentication)}
        if($null -ne $payload.winrmState.credSspAuthentication){Add-PolicyObservation 'scope:policy.winrm.authentication' 'winrm-auth-credssp' 'field:policy.winrm.auth-credssp' 'subject:device:primary' ([bool]$payload.winrmState.credSspAuthentication)}
    }
    if(@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.winrm.listener')[0].state -in @('Complete','Partial')){
        if($null -ne $payload.winrmState.listenerState){Add-PolicyObservation 'scope:policy.winrm.listener' 'winrm-listener-state' 'field:policy.winrm.listener-state' 'subject:device:primary' ([string]$payload.winrmState.listenerState)}
        if($null -ne $payload.winrmState.listenerTransport){Add-PolicyObservation 'scope:policy.winrm.listener' 'winrm-listener-transport' 'field:policy.winrm.listener-transport' 'subject:device:primary' ([string]$payload.winrmState.listenerTransport)}
        if($null -ne $payload.winrmState.listenerPort){Add-PolicyObservation 'scope:policy.winrm.listener' 'winrm-listener-port' 'field:policy.winrm.listener-port' 'subject:device:primary' ([int]$payload.winrmState.listenerPort)}
    }
    if(@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.smb.client')[0].state -in @('Complete','Partial')){
        if($null -ne $payload.smbState.clientRequireSigning){Add-PolicyObservation 'scope:policy.smb.client' 'smb-client-require-signing' 'field:policy.smb.client-require-signing' 'subject:device:primary' ([bool]$payload.smbState.clientRequireSigning)}
        if($null -ne $payload.smbState.clientEnableSigning){Add-PolicyObservation 'scope:policy.smb.client' 'smb-client-enable-signing' 'field:policy.smb.client-enable-signing' 'subject:device:primary' ([bool]$payload.smbState.clientEnableSigning)}
        if($null -ne $payload.smbState.clientEnableInsecureGuestLogons){Add-PolicyObservation 'scope:policy.smb.client' 'smb-client-insecure-guest' 'field:policy.smb.client-enable-insecure-guest-logons' 'subject:device:primary' ([bool]$payload.smbState.clientEnableInsecureGuestLogons)}
    }
    if(@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.smb.server')[0].state -in @('Complete','Partial')){
        if($null -ne $payload.smbState.serverRequireSigning){Add-PolicyObservation 'scope:policy.smb.server' 'smb-server-require-signing' 'field:policy.smb.server-require-signing' 'subject:device:primary' ([bool]$payload.smbState.serverRequireSigning)}
        if($null -ne $payload.smbState.serverEnableSigning){Add-PolicyObservation 'scope:policy.smb.server' 'smb-server-enable-signing' 'field:policy.smb.server-enable-signing' 'subject:device:primary' ([bool]$payload.smbState.serverEnableSigning)}
        if($null -ne $payload.smbState.serverEncryptData){Add-PolicyObservation 'scope:policy.smb.server' 'smb-server-encrypt-data' 'field:policy.smb.server-encrypt-data' 'subject:device:primary' ([bool]$payload.smbState.serverEncryptData)}
        if($null -ne $payload.smbState.serverRejectUnencryptedAccess){Add-PolicyObservation 'scope:policy.smb.server' 'smb-server-reject-unencrypted' 'field:policy.smb.server-reject-unencrypted-access' 'subject:device:primary' ([bool]$payload.smbState.serverRejectUnencryptedAccess)}
        if($null -ne $payload.smbState.serverEnableSmb1){Add-PolicyObservation 'scope:policy.smb.server' 'smb-server-enable-smb1' 'field:policy.smb.server-enable-smb1' 'subject:device:primary' ([bool]$payload.smbState.serverEnableSmb1)}
    }
    if(@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.smb.smb1-feature')[0].state -eq 'Complete'){
        if($null -ne $payload.smbState.smb1FeatureState){Add-PolicyObservation 'scope:policy.smb.smb1-feature' 'smb1-feature-state' 'field:policy.smb.smb1-feature-state' 'subject:device:primary' ([string]$payload.smbState.smb1FeatureState)}
    }
    $bitLockerVolumeScope=@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.bitlocker.operating-system-volume')[0]
    if($bitLockerVolumeScope.state -in @('Complete','Partial')){
        foreach($field in @(
            @{property='conversionStatus';fieldId='field:policy.bitlocker.conversion-status'},
            @{property='protectionStatus';fieldId='field:policy.bitlocker.protection-status'},
            @{property='encryptionMethod';fieldId='field:policy.bitlocker.encryption-method'},
            @{property='lockStatus';fieldId='field:policy.bitlocker.lock-status'}
        )){
            $value=$payload.bitLockerSystemVolume.([string]$field.property)
            if($null -ne $value){
                Add-PolicyObservation 'scope:policy.bitlocker.operating-system-volume' "bitlocker-volume-$($field.property)" ([string]$field.fieldId) 'subject:device:primary' ([string]$value)
            }
        }
    }
    $protectorIndex=0
    foreach($protector in @($payload.bitLockerProtectors)){
        $subjectId="subject:policy-bitlocker-protector:$protectorIndex"
        $newSubjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='OtherSynthetic'})
        Add-PolicyObservation 'scope:policy.bitlocker.protectors' "bitlocker-protector-$protectorIndex-type" 'field:policy.bitlocker.protector-type' $subjectId ([string]$protector.protectorType)
        Add-PolicyObservation 'scope:policy.bitlocker.protectors' "bitlocker-protector-$protectorIndex-count" 'field:policy.bitlocker.protector-count' $subjectId ([int]$protector.count)
        $protectorIndex++
    }
    if(@($payload.bitLockerProtectors).Count -eq 0 -and
        @($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.bitlocker.protectors')[0].state -eq 'Complete'){
        Add-PolicyObservation 'scope:policy.bitlocker.protectors' 'bitlocker-protector-type-absent' 'field:policy.bitlocker.protector-type' 'subject:device:primary' $null $true
        Add-PolicyObservation 'scope:policy.bitlocker.protectors' 'bitlocker-protector-count-absent' 'field:policy.bitlocker.protector-count' 'subject:device:primary' $null $true
    }
    $deviceGuardScope=@($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.vbs.runtime')[0]
    if($deviceGuardScope.state -in @('Complete','Partial')){
        foreach($field in @(
            @{property='virtualizationBasedSecurityStatus';fieldId='field:policy.vbs.status'},
            @{property='credentialGuardState';fieldId='field:policy.credential-guard.state'},
            @{property='memoryIntegrityState';fieldId='field:policy.memory-integrity.state'},
            @{property='userModeCodeIntegrityState';fieldId='field:policy.user-mode-code-integrity.state'}
        )){
            $value=$payload.deviceGuard.([string]$field.property)
            if($null -ne $value){
                Add-PolicyObservation 'scope:policy.vbs.runtime' "vbs-$($field.property)" ([string]$field.fieldId) 'subject:device:primary' ([string]$value)
            }
        }
    }
    $wdacIndex=0
    foreach($policyItem in @($payload.wdacPolicies)){
        $subjectId="subject:policy-wdac:$wdacIndex"
        $newSubjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='OtherSynthetic'})
        Add-PolicyObservation 'scope:policy.wdac.inventory' "wdac-$wdacIndex-channel" 'field:policy.wdac.deployment-channel' $subjectId ([string]$policyItem.deploymentChannel)
        Add-PolicyObservation 'scope:policy.wdac.inventory' "wdac-$wdacIndex-enforcement" 'field:policy.wdac.enforcement-state' $subjectId ([string]$policyItem.enforcementState)
        Add-PolicyObservation 'scope:policy.wdac.inventory' "wdac-$wdacIndex-platform" 'field:policy.wdac.platform-policy' $subjectId ([bool]$policyItem.platformPolicy)
        Add-PolicyObservation 'scope:policy.wdac.inventory' "wdac-$wdacIndex-signed" 'field:policy.wdac.signed-policy' $subjectId ([bool]$policyItem.signedPolicy)
        $wdacIndex++
    }
    if(@($payload.wdacPolicies).Count -eq 0 -and
        @($payload.scopeStates|Where-Object scopeId -eq 'scope:policy.wdac.inventory')[0].state -eq 'Complete'){
        foreach($fieldId in @(
            'field:policy.wdac.deployment-channel','field:policy.wdac.enforcement-state',
            'field:policy.wdac.platform-policy','field:policy.wdac.signed-policy'
        )){
            Add-PolicyObservation 'scope:policy.wdac.inventory' "wdac-absent-$($fieldId.Split('.')[-1])" $fieldId 'subject:device:primary' $null $true
        }
    }
    foreach($channel in @(
        @{
            scopeId='scope:policy.applocker.gp-channel';items=@($payload.appLockerGpCollections);prefix='gp'
            collectionField='field:policy.applocker.gp.rule-collection'
            modeField='field:policy.applocker.gp.enforcement-mode'
        },
        @{
            scopeId='scope:policy.applocker.csp-channel';items=@($payload.appLockerCspCollections);prefix='csp'
            collectionField='field:policy.applocker.csp.rule-collection'
            modeField='field:policy.applocker.csp.enforcement-mode'
        }
    )){
        $collectionIndex=0
        foreach($collection in @($channel.items)){
            $subjectId="subject:policy-applocker-$($channel.prefix):$collectionIndex"
            $newSubjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='OtherSynthetic'})
            # AppLocker GP and CSP can report the same rule collection names, so
            # the admitted field identity must carry the originating channel.
            # Keeping the field IDs distinct prevents later provenance collapse
            # if a consumer looks at field identity before subject naming.
            Add-PolicyObservation ([string]$channel.scopeId) "applocker-$($channel.prefix)-$collectionIndex-collection" ([string]$channel.collectionField) $subjectId ([string]$collection.ruleCollection)
            Add-PolicyObservation ([string]$channel.scopeId) "applocker-$($channel.prefix)-$collectionIndex-mode" ([string]$channel.modeField) $subjectId ([string]$collection.enforcementMode)
            $collectionIndex++
        }
        if(@($channel.items).Count -eq 0 -and
            @($payload.scopeStates|Where-Object scopeId -eq ([string]$channel.scopeId))[0].state -eq 'Complete'){
            $subjectId="subject:policy-applocker-$($channel.prefix):none"
            $newSubjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='OtherSynthetic'})
            Add-PolicyObservation ([string]$channel.scopeId) "applocker-$($channel.prefix)-collection-absent" ([string]$channel.collectionField) $subjectId $null $true
            Add-PolicyObservation ([string]$channel.scopeId) "applocker-$($channel.prefix)-mode-absent" ([string]$channel.modeField) $subjectId $null $true
        }
    }

    $coverage=[Collections.Generic.List[object]]::new();$diagnostics=[Collections.Generic.List[object]]::new()
    foreach($scopeState in $payload.scopeStates){
        $suffix=([string]$scopeState.scopeId).Substring('scope:policy.'.Length).Replace('.','-')
        $coverageId="coverage:policy-$suffix`:$runId";$diagnosticIds=@()
        $entry=[ordered]@{coverageId=$coverageId;scopeId=[string]$scopeState.scopeId;state=[string]$scopeState.state;observationIds=@($scopeObservationIds[[string]$scopeState.scopeId]);diagnosticIds=@()}
        if($scopeState.state -ne 'Complete'){
            $diagnosticId="diagnostic:policy-$suffix`:$runId";$diagnosticIds=@($diagnosticId)
            $entry.reasonCode=[string]$scopeState.reasonCode;$entry.diagnosticIds=$diagnosticIds
            $diagnostics.Add([pscustomobject][ordered]@{diagnosticId=$diagnosticId;scopeId=[string]$scopeState.scopeId;phase='Collection';reasonCode=[string]$scopeState.reasonCode;operatorMessageId='effective-policy.collection.incomplete'})
        }
        $coverage.Add([pscustomobject]$entry)
    }

    $mdmFields = if ($null -ne $SystemResult -and
        $SystemResult.PSObject.Properties['PrivatePolicyCspResults'] -and
        $null -ne $SystemResult.PrivatePolicyCspResults -and
        $SystemResult.PrivatePolicyCspResults.PSObject.Properties['fields']) {
        @($SystemResult.PrivatePolicyCspResults.fields)
    }
    else {
        @(Get-EffectivePolicyMdmSystemFieldIds | ForEach-Object {
            $fieldId=[string]$_
            $scopeDefinition=@($Policy.scopes|Where-Object {
                $fieldId -in @($_.fieldIds)
            })[0]
            [pscustomobject][ordered]@{
                fieldId=$fieldId
                scopeId=[string]$scopeDefinition.scopeId
                state='Unavailable'
                reasonCode='POLICY.MDM_SYSTEM_RESULTS_UNAVAILABLE'
                valueState='ObservedAbsent'
                value=$null
            }
        })
    }
    foreach ($field in @($mdmFields)) {
        $scopeId=[string]$field.scopeId
        if ($field.state -eq 'Complete') {
            # These values crossed the separate LocalSystem trust boundary.
            # Keeping the SYSTEM collector, context, and timestamp prevents a
            # protected report from falsely attributing them to the elevated
            # Administrator worker that collected the local GPO signals.
            $suffix=$scopeId.Substring('scope:policy.'.Length).Replace('.','-')
            $systemCollector=[pscustomobject]@{
                collectorId=if($null -ne $systemEnvelope){[string]$systemEnvelope.collectorId}else{'collector:windows.mdm-bridge.device-manageability'}
                collectorVersion=if($null -ne $systemEnvelope){[string]$systemEnvelope.collectorVersion}else{'1.0.0'}
            }
            Add-PolicyObservation $scopeId "mdm-$suffix" ([string]$field.fieldId) 'subject:device:primary' `
                $(if($field.valueState -eq 'ObservedAbsent'){$null}else{$field.value}) `
                -Absent:([string]$field.valueState -eq 'ObservedAbsent') `
                -EvidenceCollector $systemCollector `
                -EvidenceExecutionContext $(if($null -ne $systemEnvelope){[string]$systemEnvelope.executionContext}else{'Synthetic'}) `
                -EvidenceCollectedAt $(if($null -ne $systemEnvelope){[string]$systemEnvelope.completedAt}else{$collectedAt}) `
                -EvidenceSourceLocale 'und'
        }
        if (@($coverage | Where-Object scopeId -eq $scopeId).Count -eq 0) {
            $coverageId="coverage:policy-$($scopeId.Substring('scope:policy.'.Length).Replace('.','-'))`:$runId"
            $observationIds=@($scopeObservationIds[$scopeId])
            $diagnosticIds=@()
            $entry=[ordered]@{
                coverageId=$coverageId;scopeId=$scopeId;state=[string]$field.state
                observationIds=$observationIds;diagnosticIds=@()
            }
            if ([string]$field.state -ne 'Complete') {
                $diagnosticId="diagnostic:policy-$($scopeId.Substring('scope:policy.'.Length).Replace('.','-'))`:$runId"
                $diagnosticIds=@($diagnosticId)
                $entry.reasonCode=[string]$field.reasonCode
                $entry.diagnosticIds=$diagnosticIds
                $diagnostics.Add([pscustomobject][ordered]@{
                    diagnosticId=$diagnosticId;scopeId=$scopeId;phase='Collection'
                    reasonCode=[string]$field.reasonCode
                    operatorMessageId='effective-policy.collection.incomplete'
                })
            }
            $coverage.Add([pscustomobject]$entry)
        }
    }
    $Record.subjects=@($Record.subjects)+@($newSubjects)
    $Record.observations=@($Record.observations)+@($observations)
    $Record.provenance=@($Record.provenance)+@($provenance)
    $Record.coverage=@($Record.coverage)+@($coverage)
    $Record.diagnostics=@($Record.diagnostics)+@($diagnostics)
    $mdmScopes=@($Policy.scopes.scopeId|Where-Object {$_ -like 'scope:policy.mdm.*' -or $_ -eq 'scope:policy.applocker.csp-channel'})
    $effectiveScopes=@($Policy.scopes.scopeId|Where-Object {$_ -notin $mdmScopes})
    $systemObservationIds=@(foreach($scopeId in $mdmScopes){$scopeObservationIds[$scopeId]})
    $effectiveObservations=@($observations|Where-Object observationId -notin $systemObservationIds)
    $mdmObservations=@($observations|Where-Object observationId -in $systemObservationIds)
    $effectiveCoverage=@($coverage|Where-Object scopeId -notin $mdmScopes)
    $mdmCoverageEntries=@($coverage|Where-Object scopeId -in $mdmScopes)
    $effectiveDiagnostics=@($diagnostics|Where-Object scopeId -notin $mdmScopes)
    $mdmDiagnostics=@($diagnostics|Where-Object scopeId -in $mdmScopes)
    # Collector envelopes are trust statements, not presentation groupings.
    # The derived policy slice may compare both sources, but it must not merge
    # their provenance into one Administrator-owned attempt.
    $Record.collectorResults=@($Record.collectorResults)+[pscustomobject][ordered]@{
        envelopeId="envelope:effective-policy:$runId";collectorId=[string]$collector.collectorId
        collectorVersion=[string]$collector.collectorVersion;operationId=[string]$collector.operationId
        intendedScopeIds=$effectiveScopes;subjectIds=@($envelopeSubjects)
        startedAt=[string]$CollectorResult.envelope.startedAt;completedAt=$collectedAt
        executionContext=$observedExecutionContext;attempts=1
        observationIds=@($effectiveObservations|ForEach-Object observationId)
        coverageIds=@($effectiveCoverage|ForEach-Object coverageId);diagnosticIds=@($effectiveDiagnostics|ForEach-Object diagnosticId)
    }
    $existingSystemEnvelope.intendedScopeIds=@(
        @($existingSystemEnvelope.intendedScopeIds)+$mdmScopes|Select-Object -Unique
    )
    $existingSystemEnvelope.subjectIds=@(@($existingSystemEnvelope.subjectIds)+@($mdmObservations|ForEach-Object subjectId)|Select-Object -Unique)
    $existingSystemEnvelope.observationIds=@(
        @($existingSystemEnvelope.observationIds)+@($mdmObservations|ForEach-Object observationId)|Select-Object -Unique
    )
    $existingSystemEnvelope.coverageIds=@(
        @($existingSystemEnvelope.coverageIds)+@($mdmCoverageEntries|ForEach-Object coverageId)|Select-Object -Unique
    )
    $existingSystemEnvelope.diagnosticIds=@(
        @($existingSystemEnvelope.diagnosticIds)+@($mdmDiagnostics|ForEach-Object diagnosticId)|Select-Object -Unique
    )
    $Record.run.evidenceProfileId=[string]$Policy.evidenceProfileId
    $Record.run.outcome=if(@($Record.coverage|Where-Object state -ne Complete).Count -eq 0){'Completed'}else{'CompletedWithGaps'}
    $Record
}

function Invoke-EffectivePolicyRule {
    param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)][scriptblock]$Evaluation)
    $watch=[Diagnostics.Stopwatch]::StartNew();$results=@(& $Evaluation);$watch.Stop()
    if($watch.ElapsedMilliseconds -gt [int]$Rule.deadlineMilliseconds -or $results.Count -ne 1 -or
        [string]$results[0].outcome -notin @('ExpectedCondition','NeedsAttention','Informational','Indeterminate')){
        throw "The release-owned $($Rule.operationId) rule violated its finite result contract."
    }
    $results[0]
}

function Complete-ValidatedEffectivePolicyAssessmentRecord {
    param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)]$Policy,[Parameter(Mandatory)]$ContractValidation)
    if(-not [bool]$ContractValidation.accepted -or $ContractValidation.reasonCode -ne 'CONTRACT.ACCEPTED' -or
        [string]$Record.run.evidenceProfileId -ne [string]$Policy.evidenceProfileId -or
        @($Record.findings|Where-Object {$_.ruleId -in @($Policy.rules.ruleId)}).Count -ne 0){
        throw 'Effective Policy rules require an accepted source-only combined record.'
    }
    $rules=@{};foreach($rule in $Policy.rules){$rules[[string]$rule.findingKind]=$rule}
    $appliedCoverage=@($Record.coverage|Where-Object {$_.scopeId -like 'scope:policy.applied.*'})
    $localCoverage=@($Record.coverage|Where-Object {$_.scopeId -like 'scope:policy.local-*' -or $_.scopeId -like 'scope:policy.security-option.*'})
    $securityCoverage=@($Record.coverage|Where-Object {
        $_.scopeId -like 'scope:policy.windows-update.*' -or
        $_.scopeId -like 'scope:policy.legacy-auth.*' -or
        $_.scopeId -like 'scope:policy.defender.*' -or
        $_.scopeId -like 'scope:policy.smartscreen.*' -or
        $_.scopeId -like 'scope:policy.security-center.*' -or
        $_.scopeId -like 'scope:policy.firewall.*' -or
        $_.scopeId -like 'scope:policy.rdp.*' -or
        $_.scopeId -like 'scope:policy.winrm.*' -or
        $_.scopeId -like 'scope:policy.smb.*' -or
        $_.scopeId -like 'scope:policy.bitlocker.*' -or
        $_.scopeId -like 'scope:policy.vbs.*' -or
        $_.scopeId -like 'scope:policy.wdac.*' -or
        $_.scopeId -like 'scope:policy.applocker.*'
    })
    $mdmCoverage=@($Record.coverage|Where-Object {$_.scopeId -like 'scope:policy.mdm.*'})
    $constraintCoverage=@($Record.coverage|Where-Object {
        $_.scopeId -eq 'scope:policy.security-center.antivirus-providers' -or
        $_.scopeId -eq 'scope:policy.defender.runtime' -or
        $_.scopeId -like 'scope:policy.bitlocker.*' -or
        $_.scopeId -eq 'scope:policy.vbs.runtime'
    })
    $appliedReferences=@($Record.observations|Where-Object {$_.fieldId -like 'field:policy.applied.*'}|Select-Object -First 16|ForEach-Object {[pscustomobject][ordered]@{observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId}})
    $localReferences=@($Record.observations|Where-Object {$_.fieldId -like 'field:policy.local-*' -or $_.fieldId -like 'field:policy.audit.*' -or $_.fieldId -like 'field:policy.user-right.*' -or $_.fieldId -like 'field:policy.security-option.*'}|Select-Object -First 16|ForEach-Object {[pscustomobject][ordered]@{observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId}})
    $securityReferences=@($Record.observations|Where-Object {
        $_.fieldId -like 'field:policy.windows-update.*' -or
        $_.fieldId -like 'field:policy.legacy-auth.*' -or
        $_.fieldId -like 'field:policy.security-provider.*' -or
        $_.fieldId -like 'field:policy.defender.*' -or
        $_.fieldId -like 'field:policy.smartscreen.*' -or
        $_.fieldId -like 'field:policy.firewall.*' -or
        $_.fieldId -like 'field:policy.rdp.*' -or
        $_.fieldId -like 'field:policy.winrm.*' -or
        $_.fieldId -like 'field:policy.smb.*' -or
        $_.fieldId -like 'field:policy.bitlocker.*' -or
        $_.fieldId -like 'field:policy.vbs.*' -or
        $_.fieldId -like 'field:policy.credential-guard.*' -or
        $_.fieldId -like 'field:policy.memory-integrity.*' -or
        $_.fieldId -like 'field:policy.user-mode-code-integrity.*' -or
        $_.fieldId -like 'field:policy.wdac.*' -or
        $_.fieldId -like 'field:policy.applocker.*'
    }|Select-Object -First 16|ForEach-Object {[pscustomobject][ordered]@{observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId}})
    $mdmReferences=@($Record.observations|Where-Object {$_.fieldId -like 'field:policy.mdm.*'}|Select-Object -First 16|ForEach-Object {[pscustomobject][ordered]@{observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId}})
    $appliedResult=Invoke-EffectivePolicyRule -Rule $rules['applied-policy-coverage'] -Evaluation {
        if(@($appliedCoverage|Where-Object state -ne Complete).Count -eq 0){[pscustomobject]@{outcome='Informational'}}else{[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.APPLIED_POLICY_INCOMPLETE'}}
    }
    $localResult=Invoke-EffectivePolicyRule -Rule $rules['local-security-policy-coverage'] -Evaluation {
        if(@($localCoverage|Where-Object state -ne Complete).Count -eq 0){[pscustomobject]@{outcome='Informational'}}else{[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.LOCAL_SECURITY_POLICY_INCOMPLETE'}}
    }
    $securityCoverageResult=Invoke-EffectivePolicyRule -Rule $rules['security-control-coverage'] -Evaluation {
        if(@($securityCoverage|Where-Object state -ne Complete).Count -eq 0){[pscustomobject]@{outcome='Informational'}}else{[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.SECURITY_CONTROL_INCOMPLETE'}}
    }
    $settingObservations=@($Record.observations|Where-Object {
        $_.fieldId -eq 'field:policy.applied.setting-id' -and $_.valueState -eq 'ObservedValue'
    })
    $targetBySubject=@{}
    foreach($targetObservation in @($Record.observations|Where-Object {
        $_.fieldId -eq 'field:policy.applied.target' -and $_.valueState -eq 'ObservedValue'
    })){
        $targetBySubject[[string]$targetObservation.subjectId]=[string]$targetObservation.value
    }
    $settingTargetKeys=@($settingObservations|ForEach-Object {
        [pscustomobject]@{target=[string]$targetBySubject[[string]$_.subjectId];settingId=[string]$_.value}
    })
    $duplicateSettingIds=@($settingTargetKeys|Group-Object target,settingId|Where-Object Count -gt 1)
    $precedenceCoverage=@($Record.coverage|Where-Object {$_.scopeId -like 'scope:policy.applied.*.precedence'})
    $conflictResult=Invoke-EffectivePolicyRule -Rule $rules['applied-policy-order-conflict'] -Evaluation {
        if(@($precedenceCoverage|Where-Object state -ne Complete).Count -gt 0){[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.APPLIED_PRECEDENCE_INCOMPLETE'}}
        elseif($duplicateSettingIds.Count -gt 0){[pscustomobject]@{outcome='NeedsAttention'}}
        else{[pscustomobject]@{outcome='ExpectedCondition'}}
    }
    $observationByField=@{}
    foreach($observation in @($Record.observations)){
        if(-not $observationByField.ContainsKey([string]$observation.fieldId)){
            $observationByField[[string]$observation.fieldId]=$observation
        }
    }
    $providerObservation=$observationByField['field:device.mdm-bridge.provider-available']
    $providerAbsent=$null -ne $providerObservation -and
        $providerObservation.valueState -eq 'ObservedValue' -and -not [bool]$providerObservation.value
    $constraintResult=Invoke-EffectivePolicyRule -Rule $rules['security-control-constraint'] -Evaluation {
        if(@($constraintCoverage|Where-Object state -ne Complete).Count -gt 0){
            [pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.SECURITY_CONTROL_CONSTRAINT_INCOMPLETE'}
        } else {
            $passive=$false;$tamperProtected=$false
            $bitLockerProtected=$false;$virtualizedVbs=$false
            foreach($observation in @($Record.observations)){
                if($observation.fieldId -eq 'field:policy.defender.running-mode' -and
                    $observation.valueState -eq 'ObservedValue' -and
                    [string]$observation.value -in @('Passive','Passive Mode','SxS Passive Mode')){
                    $passive=$true
                }
                elseif($observation.fieldId -eq 'field:policy.defender.tamper-protected' -and
                    $observation.valueState -eq 'ObservedValue' -and [bool]$observation.value){
                    $tamperProtected=$true
                }
                elseif($observation.fieldId -eq 'field:policy.bitlocker.protection-status' -and
                    $observation.valueState -eq 'ObservedValue' -and [string]$observation.value -eq 'On'){
                    $bitLockerProtected=$true
                }
                elseif($observation.fieldId -eq 'field:policy.vbs.status' -and
                    $observation.valueState -eq 'ObservedValue' -and
                    [string]$observation.value -eq 'EnabledAndRunningInVirtualMachine'){
                    $virtualizedVbs=$true
                }
            }
            if($passive -or $tamperProtected -or $bitLockerProtected -or $virtualizedVbs){
                [pscustomobject]@{outcome='ExpectedCondition'}
            } else {
                [pscustomobject]@{outcome='Informational'}
            }
        }
    }
    $mdmCoverageResult=Invoke-EffectivePolicyRule -Rule $rules['mdm-policy-csp-coverage'] -Evaluation {
        if(@($mdmCoverage|Where-Object state -ne Complete).Count -eq 0){[pscustomobject]@{outcome='Informational'}}
        else{[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.MDM_POLICY_CSP_INCOMPLETE'}}
    }
    $policyMappings=@(
        @{local='field:policy.security-option.machine-inactivity-limit-seconds';mdm='field:policy.mdm.security-option.machine-inactivity-limit-seconds'},
        @{local='field:policy.security-option.disable-cad';mdm='field:policy.mdm.security-option.disable-cad'},
        @{local='field:policy.security-option.lm-compatibility-level';mdm='field:policy.mdm.security-option.lm-compatibility-level'},
        @{local='field:policy.windows-update.defer-feature-updates-days';mdm='field:policy.mdm.update.defer-feature-updates-days'},
        @{local='field:policy.windows-update.defer-quality-updates-days';mdm='field:policy.mdm.update.defer-quality-updates-days'},
        @{local='field:policy.windows-update.disable-dual-scan';mdm='field:policy.mdm.update.disable-dual-scan'}
    )
    $channelConflictDetected=$false
    $channelConflictReferences=[Collections.Generic.List[object]]::new()
    foreach($mapping in $policyMappings){
        $localObservation=$observationByField[[string]$mapping.local]
        $mdmObservation=$observationByField[[string]$mapping.mdm]
        foreach($candidate in @($localObservation,$mdmObservation)){
            if($null -ne $candidate -and $candidate.valueState -eq 'ObservedValue'){
                $channelConflictReferences.Add([pscustomobject][ordered]@{
                    observationId=$candidate.observationId;fieldId=$candidate.fieldId;subjectId=$candidate.subjectId
                })
            }
        }
        if($null -ne $localObservation -and $null -ne $mdmObservation -and
            $localObservation.valueState -eq 'ObservedValue' -and
            $mdmObservation.valueState -eq 'ObservedValue' -and
            [string]$localObservation.value -ne [string]$mdmObservation.value){
            $channelConflictDetected=$true
        }
    }
    $localSignalCoverage=@($Record.coverage|Where-Object {
        $_.scopeId -like 'scope:policy.security-option.*' -or
        $_.scopeId -like 'scope:policy.windows-update.*'
    })
    $appLockerGpCoverage=@($Record.coverage|Where-Object {$_.scopeId -eq 'scope:policy.applocker.gp-channel'})
    $appLockerCspCoverage=@($Record.coverage|Where-Object {$_.scopeId -eq 'scope:policy.applocker.csp-channel'})
    $appLockerByChannel=@{gp=@{};csp=@{}}
    $appLockerChannelFields=@{
        gp=@{
            collection='field:policy.applocker.gp.rule-collection'
            mode='field:policy.applocker.gp.enforcement-mode'
        }
        csp=@{
            collection='field:policy.applocker.csp.rule-collection'
            mode='field:policy.applocker.csp.enforcement-mode'
        }
    }
    foreach($observation in @($Record.observations|Where-Object {
        $_.fieldId -in @(
            $appLockerChannelFields.gp.collection,$appLockerChannelFields.gp.mode,
            $appLockerChannelFields.csp.collection,$appLockerChannelFields.csp.mode
        ) -and $_.valueState -eq 'ObservedValue'
    })){
        $channel=if([string]$observation.subjectId -like 'subject:policy-applocker-gp:*'){'gp'}
            elseif([string]$observation.subjectId -like 'subject:policy-applocker-csp:*'){'csp'}
            else{''}
        if([string]::IsNullOrEmpty($channel)){continue}
        $subjectId=[string]$observation.subjectId
        if(-not $appLockerByChannel[$channel].ContainsKey($subjectId)){
            $appLockerByChannel[$channel][$subjectId]=[ordered]@{}
        }
        $appLockerByChannel[$channel][$subjectId][[string]$observation.fieldId]=$observation
        $channelConflictReferences.Add([pscustomobject][ordered]@{
            observationId=$observation.observationId;fieldId=$observation.fieldId;subjectId=$observation.subjectId
        })
    }
    $gpCollections=@{}
    foreach($entry in @($appLockerByChannel.gp.Values)){
        if($entry.Contains($appLockerChannelFields.gp.collection) -and
            $entry.Contains($appLockerChannelFields.gp.mode)){
            $gpCollections[[string]$entry[$appLockerChannelFields.gp.collection].value]=[string]$entry[$appLockerChannelFields.gp.mode].value
        }
    }
    foreach($entry in @($appLockerByChannel.csp.Values)){
        if($entry.Contains($appLockerChannelFields.csp.collection) -and
            $entry.Contains($appLockerChannelFields.csp.mode)){
            $collectionName=[string]$entry[$appLockerChannelFields.csp.collection].value
            if($gpCollections.ContainsKey($collectionName) -and
                [string]$gpCollections[$collectionName] -ne [string]$entry[$appLockerChannelFields.csp.mode].value){
                $channelConflictDetected=$true
            }
        }
    }
    $channelConflictResult=Invoke-EffectivePolicyRule -Rule $rules['policy-csp-gpo-conflict'] -Evaluation {
        $mdmChannelIncomplete=@($mdmCoverage|Where-Object state -ne Complete).Count -gt 0 -or
            @($localSignalCoverage|Where-Object state -ne Complete).Count -gt 0
        $appLockerChannelIncomplete=@($appLockerGpCoverage|Where-Object state -ne Complete).Count -gt 0 -or
            @($appLockerCspCoverage|Where-Object state -ne Complete).Count -gt 0
        if($channelConflictDetected){[pscustomobject]@{outcome='NeedsAttention'}}
        elseif($mdmChannelIncomplete -or $appLockerChannelIncomplete){
            [pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.POLICY_CSP_GPO_CONFLICT_INCOMPLETE'}
        }
        else{[pscustomobject]@{outcome='ExpectedCondition'}}
    }
    $findingDefinitions=@(
        @{kind='applied-policy-coverage';result=$appliedResult;references=$appliedReferences},
        @{kind='local-security-policy-coverage';result=$localResult;references=$localReferences},
        @{kind='applied-policy-order-conflict';result=$conflictResult;references=@($settingObservations|Select-Object -First 16|ForEach-Object {[pscustomobject][ordered]@{observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId}})},
        @{kind='security-control-coverage';result=$securityCoverageResult;references=$securityReferences},
        @{kind='security-control-constraint';result=$constraintResult;references=$securityReferences},
        @{kind='mdm-policy-csp-coverage';result=$mdmCoverageResult;references=$mdmReferences},
        @{kind='policy-csp-gpo-conflict';result=$channelConflictResult;references=@($channelConflictReferences|Select-Object -First 16)}
    )
    foreach($definition in $findingDefinitions){
        $rule=$rules[$definition.kind];$finding=[ordered]@{
            findingId="finding:$($definition.kind):$($Record.run.runId)";ruleId=[string]$rule.ruleId
            targetSubjectId='subject:device:primary';outcome=[string]$definition.result.outcome
            evidenceReferences=@($definition.references)
        }
        if($definition.result.PSObject.Properties['reasonCode']){$finding.reasonCode=[string]$definition.result.reasonCode}
        $Record.findings=@($Record.findings)+[pscustomobject]$finding
    }
    $effectivePolicyFindingIds=@($Record.findings|Where-Object {
        $_.ruleId -in @('rule:policy.mdm-policy-csp-coverage/1.0.0','rule:policy.policy-csp-gpo-conflict/1.0.0')
    }|ForEach-Object findingId)
    if($mdmCoverageResult.outcome -eq 'Indeterminate' -or
        $channelConflictResult.outcome -in @('Indeterminate','NeedsAttention')){
        $Record.recommendations=@($Record.recommendations)+@($Policy.discoveryTasks|ForEach-Object {
            [pscustomobject][ordered]@{
                recommendationId="recommendation:$(([string]$_.definitionId).Substring(5).Replace('/','-')):$($Record.run.runId)"
                definitionId=[string]$_.definitionId;kind='TenantSideDiscoveryTask'
                findingIds=$effectivePolicyFindingIds
            }
        })
    }
    $Record.run.outcome=if(@($Record.coverage|Where-Object state -ne Complete).Count -eq 0){'Completed'}else{'CompletedWithGaps'}
    $Record
}
