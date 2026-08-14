$script:EffectivePolicyPolicyBase64 = '__EFFECTIVE_POLICY_POLICY_BASE64__'
$script:EffectivePolicyPolicyDigest = '__EFFECTIVE_POLICY_POLICY_SHA256__'

function Get-EffectivePolicySha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
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
        @($policy.layers).Count -ne 3 -or @($policy.scopes).Count -ne 15 -or
        @($policy.sourceCatalog).Count -ne 5 -or @($policy.rules).Count -ne 3 -or
        @($policy.validationScenarios).Count -ne 14) {
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
    $sourceLocale = if ($Scenario -eq 'NonEnglish') { 'fr-FR' } else { 'en-US' }
    $localObject = 'LocalGPO'
    $domainObject = '6ac1786c-016f-11d2-945f-00c04fb984f9'
    $userObject = '7f7d1f60-8f2a-4ae5-bb3f-0bdc4a0ef111'
    $policies = @([pscustomobject][ordered]@{
        target='Computer';origin='Local';objectId=$localObject;applicable=$true
        linkId=$null;appliedOrder=$null
    })
    if ($Scenario -in @('Domain','StaleRegistry','DeniedSystem','NonEnglish','AppliedOrderConflict')) {
        $policies = @(
            [pscustomobject][ordered]@{target='Computer';origin='Domain';objectId=$domainObject;applicable=$true;linkId='synthetic-domain-link';appliedOrder=1},
            [pscustomobject][ordered]@{target='Computer';origin='Local';objectId=$localObject;applicable=$false;linkId=$null;appliedOrder=$null}
        )
    }
    elseif ($Scenario -eq 'UserAndComputerRsop') {
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
    if ($Scenario -eq 'AppliedOrderConflict') {
        $conflict = $true
        $settings = @(
            [pscustomobject][ordered]@{target='Computer';settingId='registry:22222222-2222-4222-8222-222222222222';objectId=$domainObject;precedence=1},
            [pscustomobject][ordered]@{target='Computer';settingId='registry:22222222-2222-4222-8222-222222222222';objectId=$localObject;precedence=2}
        )
    }
    elseif ($Scenario -eq 'UserAndComputerRsop') {
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
    if ($Scenario -eq 'AccountLockout') {
        $sam.lockoutDurationSeconds=1800;$sam.lockoutWindowSeconds=1800;$sam.lockoutThreshold=5
    }
    $audits = @($Policy.auditSubcategories | ForEach-Object {
        [pscustomobject][ordered]@{catalogId=[string]$_.catalogId;state='Complete';successEnabled=$true;failureEnabled=$false}
    })
    if ($Scenario -eq 'AuditPolicy') {
        $audits[0].failureEnabled=$true;$audits[1].successEnabled=$false
    }
    $rights = @($Policy.userRights | ForEach-Object {
        [pscustomobject][ordered]@{catalogId=[string]$_.catalogId;state='Complete';directSids=@()}
    })
    if ($Scenario -eq 'UserRights') {
        $rights[0].directSids=@('S-1-5-32-544')
        $rights[1].directSids=@('S-1-5-32-546')
        $rights[2].directSids=@('S-1-5-20')
    }
    $options = @(
        [pscustomobject][ordered]@{catalogId='security-option:machine-inactivity-limit-seconds';state='Complete';value=900;sourceAttribution='Unproven'},
        [pscustomobject][ordered]@{catalogId='security-option:disable-cad';state='Complete';value=$false;sourceAttribution='Unproven'},
        [pscustomobject][ordered]@{catalogId='security-option:lm-compatibility-level';state='Complete';value=5;sourceAttribution='Unproven'}
    )
    if ($Scenario -eq 'SecurityOptions') {
        $options[0].value=600;$options[1].value=$true;$options[2].value=3
    }

    $states = @($Policy.scopes | ForEach-Object {
        New-EffectivePolicyScopeState -ScopeId ([string]$_.scopeId) -State Complete
    })
    if ($Scenario -eq 'MissingRsop') {
        $policies=@();$settings=@()
        foreach($state in $states[0..7]){$state.state='Unsupported';$state.reasonCode='POLICY.RSOP_NAMESPACE_UNAVAILABLE'}
    }
    elseif ($Scenario -eq 'StaleRegistry') {
        $states[12].state='Unavailable';$states[12].reasonCode='POLICY.CONFIGURED_SIGNAL_STALE'
        $options[0].state='Stale';$options[0].value=$null
    }
    elseif ($Scenario -eq 'DeniedAdministrator') {
        $policies=@();$settings=@();$sam.PSObject.Properties|ForEach-Object {$_.Value=$null}
        $audits|ForEach-Object {$_.state='Denied';$_.successEnabled=$null;$_.failureEnabled=$null}
        $rights|ForEach-Object {$_.state='Denied';$_.directSids=@()}
        $options|ForEach-Object {$_.state='Unavailable';$_.value=$null}
        foreach($state in $states){$state.state='Denied';$state.reasonCode='POLICY.ADMINISTRATOR_SOURCE_DENIED'}
    }
    elseif ($Scenario -eq 'PartialChannel') {
        $policies=@(1..8|ForEach-Object {
            $suffix=$_.ToString('00000000')
            [pscustomobject][ordered]@{target='Computer';origin='Domain';objectId="$suffix-0000-4000-8000-$($_.ToString('000000000000'))";applicable=$true;linkId="bounded-link-$_";appliedOrder=$_}
        })
        $settings=@(1..8|ForEach-Object {
            $suffix=$_.ToString('00000000')
            [pscustomobject][ordered]@{target='Computer';settingId="registry:bounded-setting-$_";objectId="$suffix-0000-4000-8000-$($_.ToString('000000000000'))";precedence=$_}
        })
        $states[3].state='Unsupported';$states[3].reasonCode='POLICY.RSOP_EXTENSION_UNSUPPORTED'
        $states[6].state='Partial';$states[6].reasonCode='POLICY.RSOP_LINK_AMBIGUOUS'
        $states[7].state='Partial';$states[7].reasonCode='POLICY.RSOP_EVIDENCE_BOUND_EXCEEDED'
        $states[9].state='Failed';$states[9].reasonCode='POLICY.LOCAL_SAM_LOCKOUT_FAILED'
        $states[10].state='Failed';$states[10].reasonCode='POLICY.AUDIT_FAILED'
        $states[11].state='Unsupported';$states[11].reasonCode='POLICY.USER_RIGHTS_UNSUPPORTED'
        $states[14].state='Unavailable';$states[14].reasonCode='POLICY.SECURITY_OPTION_UNAVAILABLE'
        $sam.lockoutDurationSeconds=$null;$sam.lockoutWindowSeconds=$null;$sam.lockoutThreshold=$null
        $audits|ForEach-Object {$_.state='Failed';$_.successEnabled=$null;$_.failureEnabled=$null}
        $rights|ForEach-Object {$_.state='Unsupported';$_.directSids=@()}
        $options[2].state='Unavailable';$options[2].value=$null
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
        appliedOrderConflict=[bool]$conflict
        localAccountPolicySemantics='LocalSamAccountsOnly';userRightSemantics='DirectAssignmentsOnly'
    }
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
        $names=@($Payload.PSObject.Properties.Name|Sort-Object)
        $expected=@('appliedOrderConflict','appliedPolicies','auditSubcategories','layerStates','localAccountPolicySemantics','localSam','policySettings','scopeStates','securityOptions','sourceLocale','userRights','userRightSemantics')|Sort-Object
        if(($names -join '|') -ne ($expected -join '|') -or
            $Payload.localAccountPolicySemantics -isnot [string] -or $Payload.userRightSemantics -isnot [string] -or
            [string]$Payload.localAccountPolicySemantics -ne 'LocalSamAccountsOnly' -or
            [string]$Payload.userRightSemantics -ne 'DirectAssignmentsOnly' -or
            -not (Test-BoundedString $Payload.sourceLocale 32 '^(?:und|[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*)$') -or
            @($Payload.scopeStates).Count -ne 15 -or
            @($Payload.appliedPolicies).Count -gt 16 -or @($Payload.policySettings).Count -gt 16 -or
            @($Payload.auditSubcategories).Count -ne 3 -or @($Payload.userRights).Count -ne 3 -or
            @($Payload.securityOptions).Count -ne 3){return $false}
        $expectedScopeIds=@($Policy.scopes.scopeId)
        if((@($Payload.scopeStates.scopeId)-join '|') -ne ($expectedScopeIds-join '|')){return $false}
        if(-not (Test-ExactProperties $Payload.layerStates @('AppliedPolicyEvidence','ConfiguredPolicySignals','CurrentControlState'))){return $false}
        foreach($scope in $Payload.scopeStates){
            if(-not (Test-ExactProperties $scope @('scopeId','state','reasonCode'))){return $false}
            if($scope.scopeId -isnot [string] -or $scope.state -isnot [string] -or
                [string]$scope.state -notin @('Complete','Partial','Unavailable','Unsupported','Denied','Malformed','TimedOut','Cancelled','Failed') -or
                ($scope.state -ne 'Complete' -and -not (Test-BoundedString $scope.reasonCode 128 '^[A-Z0-9._-]+$')) -or
                ($scope.state -eq 'Complete' -and ($scope.reasonCode -isnot [string] -or -not [string]::IsNullOrEmpty($scope.reasonCode)))){return $false}
        }
        foreach($layer in @('AppliedPolicyEvidence','ConfiguredPolicySignals','CurrentControlState')){
            if($Payload.layerStates.$layer -isnot [string] -or [string]$Payload.layerStates.$layer -notin @('Complete','Partial','Unavailable','Unsupported','Denied','Malformed','TimedOut','Cancelled','Failed')){return $false}
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
        $computedConflict=@($Payload.policySettings|Group-Object target,settingId|Where-Object {
            @($_.Group.objectId|Select-Object -Unique).Count -gt 1
        }).Count -gt 0
        if($Payload.appliedOrderConflict -isnot [bool] -or [bool]$Payload.appliedOrderConflict -ne $computedConflict){return $false}
        return $true
    }
    catch{return $false}
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
        scopeStates=@($Payload.scopeStates|ForEach-Object {[pscustomobject][ordered]@{scopeId=[string]$_.scopeId;state=[string]$_.state;reasonCode=[string]$_.reasonCode}})
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
    [pscustomobject][ordered]@{
        recordType='win-pcinfo.effective-policy-validation';contractVersion='1.0.0'
        scenario=[string]$CollectorResult.validationScenario
        appliedPolicyCoverage=[string]$payload.layerStates.AppliedPolicyEvidence
        configuredSignalCoverage=[string]$payload.layerStates.ConfiguredPolicySignals
        currentControlCoverage=[string]$payload.layerStates.CurrentControlState
        appliedPolicyCount=@($payload.appliedPolicies).Count
        appliedOrderConflict=[bool]$payload.appliedOrderConflict
        auditCatalogCount=@($payload.auditSubcategories).Count
        userRightCatalogCount=@($payload.userRights).Count
        securityOptionCatalogCount=@($payload.securityOptions).Count
        directRightsOnly=([string]$payload.userRightSemantics -eq 'DirectAssignmentsOnly')
        localSamOnly=([string]$payload.localAccountPolicySemantics -eq 'LocalSamAccountsOnly')
    }
}

function New-EffectivePolicyPrivilegeGapResult {
    param(
        [Parameter(Mandatory)]$PrivilegeResult,
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][bool]$ValidationFixture
    )
    $state=if([string]$PrivilegeResult.state -eq 'Unavailable'){'Denied'}else{'Failed'}
    $reason=if($state -eq 'Denied'){'POLICY.ADMINISTRATOR_SOURCE_DENIED'}else{'POLICY.ADMINISTRATOR_SOURCE_FAILED'}
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
    else{'source:windows.local-security-option-signals'}
}

function New-EffectivePolicyObservationPair {
    param(
        [Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$Suffix,
        [Parameter(Mandatory)][string]$FieldId,[Parameter(Mandatory)][string]$SubjectId,
        [Parameter(Mandatory)]$Collector,[Parameter(Mandatory)][string]$ObservedExecutionContext,
        [Parameter(Mandatory)][string]$CollectedAt,[Parameter(Mandatory)][string]$SourceLocale,
        [Parameter()]$Value,[Parameter()][switch]$ObservedAbsent
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
            sourceId=Get-EffectivePolicySourceId -FieldId $FieldId
            collectorId=[string]$Collector.collectorId;collectorVersion=[string]$Collector.collectorVersion
            executionContext=$ObservedExecutionContext;collectedAt=$CollectedAt;sourceLocale=$SourceLocale
        }
    }
}

function Add-EffectivePolicyEvidenceRecord {
    param(
        [Parameter(Mandatory)]$Record,[Parameter(Mandatory)]$CollectorResult,
        [Parameter(Mandatory)]$Policy
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

    function Add-PolicyObservation {
        param([string]$ScopeId,[string]$Suffix,[string]$FieldId,[string]$SubjectId,$Value,[bool]$Absent=$false)
        $arguments=@{RunId=$runId;Suffix=$Suffix;FieldId=$FieldId;SubjectId=$SubjectId;Collector=$collector;ObservedExecutionContext=$observedExecutionContext;CollectedAt=$collectedAt;SourceLocale=[string]$payload.sourceLocale;Value=$Value}
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
    $Record.subjects=@($Record.subjects)+@($newSubjects)
    $Record.observations=@($Record.observations)+@($observations)
    $Record.provenance=@($Record.provenance)+@($provenance)
    $Record.coverage=@($Record.coverage)+@($coverage)
    $Record.diagnostics=@($Record.diagnostics)+@($diagnostics)
    $Record.collectorResults=@($Record.collectorResults)+[pscustomobject][ordered]@{
        envelopeId="envelope:effective-policy:$runId";collectorId=[string]$collector.collectorId
        collectorVersion=[string]$collector.collectorVersion;operationId=[string]$collector.operationId
        intendedScopeIds=@($Policy.scopes.scopeId);subjectIds=@($envelopeSubjects)
        startedAt=[string]$CollectorResult.envelope.startedAt;completedAt=$collectedAt
        executionContext=$observedExecutionContext;attempts=1
        observationIds=@($observations|ForEach-Object observationId)
        coverageIds=@($coverage|ForEach-Object coverageId);diagnosticIds=@($diagnostics|ForEach-Object diagnosticId)
    }
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
    $appliedReferences=@($Record.observations|Where-Object {$_.fieldId -like 'field:policy.applied.*'}|Select-Object -First 16|ForEach-Object {[pscustomobject][ordered]@{observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId}})
    $localReferences=@($Record.observations|Where-Object {$_.fieldId -like 'field:policy.local-*' -or $_.fieldId -like 'field:policy.audit.*' -or $_.fieldId -like 'field:policy.user-right.*' -or $_.fieldId -like 'field:policy.security-option.*'}|Select-Object -First 16|ForEach-Object {[pscustomobject][ordered]@{observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId}})
    $appliedResult=Invoke-EffectivePolicyRule -Rule $rules['applied-policy-coverage'] -Evaluation {
        if(@($appliedCoverage|Where-Object state -ne Complete).Count -eq 0){[pscustomobject]@{outcome='Informational'}}else{[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.APPLIED_POLICY_INCOMPLETE'}}
    }
    $localResult=Invoke-EffectivePolicyRule -Rule $rules['local-security-policy-coverage'] -Evaluation {
        if(@($localCoverage|Where-Object state -ne Complete).Count -eq 0){[pscustomobject]@{outcome='Informational'}}else{[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.LOCAL_SECURITY_POLICY_INCOMPLETE'}}
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
    $findingDefinitions=@(
        @{kind='applied-policy-coverage';result=$appliedResult;references=$appliedReferences},
        @{kind='local-security-policy-coverage';result=$localResult;references=$localReferences},
        @{kind='applied-policy-order-conflict';result=$conflictResult;references=@($settingObservations|Select-Object -First 16|ForEach-Object {[pscustomobject][ordered]@{observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId}})}
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
    $Record.run.outcome=if(@($Record.coverage|Where-Object state -ne Complete).Count -eq 0){'Completed'}else{'CompletedWithGaps'}
    $Record
}
