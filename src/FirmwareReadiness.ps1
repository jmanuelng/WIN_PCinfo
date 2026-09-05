$script:FirmwareReadinessPolicyBase64 = '__FIRMWARE_READINESS_POLICY_BASE64__'
$script:FirmwareReadinessPolicyDigest = '__FIRMWARE_READINESS_POLICY_SHA256__'

function Get-FirmwareReadinessPolicy {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    if ($script:FirmwareReadinessPolicyBase64 -eq ('__FIRMWARE_READINESS_' + 'POLICY_BASE64__')) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-firmware-readiness.json'
        $bytes = Get-CanonicalSupervisorTextBytes -LiteralPath $path
        $expectedDigest = Get-Sha256ForSupervisorBytes -Bytes $bytes
    }
    else {
        $bytes = [Convert]::FromBase64String($script:FirmwareReadinessPolicyBase64)
        $expectedDigest = $script:FirmwareReadinessPolicyDigest
    }
    if ((Get-Sha256ForSupervisorBytes -Bytes $bytes) -ne $expectedDigest) {
        throw 'The Firmware Readiness policy failed integrity validation.'
    }
    $policy = & $ConvertFromJsonCommand -InputObject (
        [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    ) -Depth 20 -ErrorAction Stop
    if ($policy.kind -ne 'win-pcinfo.firmware-readiness-policy' -or
        $policy.policyId -ne 'win-pcinfo.firmware-readiness/1.0.0' -or
        $policy.collector.operationId -ne 'observe-firmware-tpm' -or
        @($policy.scopes).Count -ne 3 -or @($policy.rules).Count -ne 3 -or
        @($policy.discoveryTasks).Count -ne 2 -or
        @($policy.validationScenarios).Count -ne 10) {
        throw 'The Firmware Readiness policy is not the closed release policy.'
    }
    $policy
}

function Test-FirmwareReadinessCollectorPayload {
    param([Parameter(Mandatory)] $Payload)

    $allowedNames = @(
        'sourceLocale','firmwareState','firmwareType','biosVersion','smbiosVersion',
        'secureBootState','secureBootEnabled','tpmState','tpmPresent','tpmEnabled',
        'tpmActivated','tpmSpecification'
    )
    $names = @($Payload.PSObject.Properties.Name)
    if ($names.Count -ne $allowedNames.Count -or
        (@($names | Sort-Object) -join '|') -ne (@($allowedNames | Sort-Object) -join '|')) {
        return $false
    }
    $states = @('Complete','Unavailable','Denied','Unsupported','Malformed','TimedOut','Failed','Cancelled')
    if ([string]$Payload.firmwareState -notin $states -or
        [string]$Payload.secureBootState -notin $states -or
        [string]$Payload.tpmState -notin $states) {
        return $false
    }
    if ([Text.Encoding]::UTF8.GetByteCount([string]$Payload.sourceLocale) -gt 32 -or
        $Payload.sourceLocale -notmatch '^(?:und|[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*)$') {
        return $false
    }
    if ($Payload.firmwareState -eq 'Complete') {
        if ([string]$Payload.firmwareType -notin @('Uefi','LegacyBios','Unknown') -or
            ($null -ne $Payload.biosVersion -and (
                [string]::IsNullOrWhiteSpace([string]$Payload.biosVersion) -or
                [Text.Encoding]::UTF8.GetByteCount([string]$Payload.biosVersion) -gt 128
            )) -or ($null -ne $Payload.smbiosVersion -and (
                [string]::IsNullOrWhiteSpace([string]$Payload.smbiosVersion) -or
                [Text.Encoding]::UTF8.GetByteCount([string]$Payload.smbiosVersion) -gt 16
            ))) {
            return $false
        }
    }
    elseif ($null -ne $Payload.firmwareType -or $null -ne $Payload.biosVersion -or
        $null -ne $Payload.smbiosVersion) { return $false }
    if ($Payload.secureBootState -eq 'Complete') {
        if ($Payload.secureBootEnabled -isnot [bool]) { return $false }
    }
    elseif ($null -ne $Payload.secureBootEnabled) { return $false }
    if ($Payload.tpmState -eq 'Complete') {
        if ($Payload.tpmPresent -isnot [bool] -or
            [Text.Encoding]::UTF8.GetByteCount([string]$Payload.tpmSpecification) -gt 32) {
            return $false
        }
        if ([bool]$Payload.tpmPresent) {
            if ($Payload.tpmEnabled -isnot [bool] -or
                $Payload.tpmActivated -isnot [bool] -or
                ($null -ne $Payload.tpmSpecification -and (
                    [string]::IsNullOrWhiteSpace([string]$Payload.tpmSpecification) -or
                    [Text.Encoding]::UTF8.GetByteCount([string]$Payload.tpmSpecification) -gt 32
                ))) { return $false }
        }
        elseif ($null -ne $Payload.tpmEnabled -or $null -ne $Payload.tpmActivated -or
            $null -ne $Payload.tpmSpecification) { return $false }
    }
    elseif ($null -ne $Payload.tpmPresent -or $null -ne $Payload.tpmEnabled -or
        $null -ne $Payload.tpmActivated -or $null -ne $Payload.tpmSpecification) {
        return $false
    }
    $true
}

function New-FirmwareReadinessPrivilegeGapResult {
    param(
        [Parameter(Mandatory)] $PrivilegeResult,
        [Parameter(Mandatory)] [bool] $ValidationFixture
    )
    $state = switch ([string]$PrivilegeResult.state) {
        'Unavailable' { 'Unavailable' }
        'TimedOut' { 'TimedOut' }
        'Cancelled' { 'Cancelled' }
        default { 'Failed' }
    }
    $now = [DateTimeOffset]::UtcNow.ToString('o')
    [pscustomobject][ordered]@{
        state='Completed';reasonCode=[string]$PrivilegeResult.reasonCode
        validationFixture=$ValidationFixture
        envelope=[pscustomobject][ordered]@{
            startedAt=$now;completedAt=$now;attempts=1
        }
        payload=[pscustomobject][ordered]@{
            sourceLocale='und';firmwareState=$state;firmwareType=$null
            biosVersion=$null;smbiosVersion=$null;secureBootState=$state
            secureBootEnabled=$null;tpmState=$state;tpmPresent=$null
            tpmEnabled=$null;tpmActivated=$null;tpmSpecification=$null
        }
    }
}

function Get-FirmwareCoverageReason {
    param(
        [Parameter(Mandatory)] [string] $ScopeKind,
        [Parameter(Mandatory)] [string] $State
    )

    $prefix = $ScopeKind.ToUpperInvariant().Replace('-', '_')
    switch ($State) {
        'Denied' { "COLLECTION.$prefix`_ACCESS_DENIED" }
        'Unsupported' { "COLLECTION.$prefix`_SOURCE_UNSUPPORTED" }
        'Malformed' { "COLLECTION.$prefix`_PAYLOAD_MALFORMED" }
        'TimedOut' { "COLLECTION.$prefix`_DEADLINE_EXCEEDED" }
        'Cancelled' { "COLLECTION.$prefix`_CANCELLED" }
        'Failed' { "COLLECTION.$prefix`_COLLECTOR_FAILED" }
        default { "COLLECTION.$prefix`_SOURCE_UNAVAILABLE" }
    }
}

function Add-FirmwareReadinessEvidenceRecord {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $CollectorResult,
        [Parameter(Mandatory)] $Policy
    )

    if ([string]$CollectorResult.state -ne 'Completed' -or
        $null -eq $CollectorResult.PSObject.Properties['payload'] -or
        -not (Test-FirmwareReadinessCollectorPayload -Payload $CollectorResult.payload)) {
        throw 'The privileged firmware collector result is not release-shaped.'
    }
    if ([string]$Record.run.evidenceProfileId -ne 'profile:device-windows-context' -or
        @($Record.coverage).Count -ne 1 -or @($Record.findings).Count -ne 4) {
        throw 'Firmware evidence requires one completed Device Context prerequisite record.'
    }
    $payload = $CollectorResult.payload
    $runId = [string]$Record.run.runId
    $subjectId = [string]@($Record.subjects)[0].subjectId
    $provenanceContext = if ([bool]$CollectorResult.validationFixture) {
        'Synthetic'
    } else { 'Administrator' }
    $sourceLocale = [string]$payload.sourceLocale
    $fieldSpecs = @{
        firmware = @(
            @{id='field:device.firmware.type';source='source:windows.api.get-firmware-type';property='firmwareType'},
            @{id='field:device.firmware.bios-version';source='source:windows.cim.bios';property='biosVersion'},
            @{id='field:device.firmware.smbios-version';source='source:windows.cim.bios';property='smbiosVersion'}
        )
        'secure-boot' = @(
            @{id='field:device.secure-boot.enabled';source='source:windows.secure-boot.confirm';property='secureBootEnabled'}
        )
        tpm = @(
            @{id='field:device.tpm.present';source='source:windows.cim.tpm';property='tpmPresent'},
            @{id='field:device.tpm.enabled';source='source:windows.cim.tpm';property='tpmEnabled';detail=$true},
            @{id='field:device.tpm.activated';source='source:windows.cim.tpm';property='tpmActivated';detail=$true},
            @{id='field:device.tpm.specification';source='source:windows.cim.tpm';property='tpmSpecification';detail=$true}
        )
    }
    $scopeSpecs = @(
        @{kind='firmware';scopeId='scope:device.firmware-context';state=[string]$payload.firmwareState},
        @{kind='secure-boot';scopeId='scope:device.secure-boot';state=[string]$payload.secureBootState},
        @{kind='tpm';scopeId='scope:device.tpm-readiness';state=[string]$payload.tpmState}
    )
    $newProvenance = [Collections.Generic.List[object]]::new()
    $newObservations = [Collections.Generic.List[object]]::new()
    $newCoverage = [Collections.Generic.List[object]]::new()
    $newDiagnostics = [Collections.Generic.List[object]]::new()
    foreach ($scope in $scopeSpecs) {
        $scopeObservationIds = [Collections.Generic.List[string]]::new()
        if ($scope.state -eq 'Complete') {
            foreach ($field in @($fieldSpecs[[string]$scope.kind])) {
                $suffix = ([string]$field.id).Substring(6).Replace('.', '-')
                $observationId = "observation:$suffix`:$runId"
                $provenanceId = "provenance:$suffix`:$runId"
                $value = $payload.([string]$field.property)
                $valueState = if ($field.ContainsKey('detail') -and
                    $payload.tpmPresent -eq $false) { 'ObservedAbsent' }
                    elseif ($null -eq $value) { 'SourceReportedUnknown' }
                    else { 'ObservedValue' }
                $observation = [ordered]@{
                    observationId=$observationId;fieldId=[string]$field.id
                    subjectId=$subjectId;provenanceId=$provenanceId;valueState=$valueState
                }
                if ($valueState -eq 'ObservedValue') { $observation.value = $value }
                $newObservations.Add([pscustomobject]$observation)
                $newProvenance.Add([pscustomobject][ordered]@{
                    provenanceId=$provenanceId;fieldId=[string]$field.id;subjectId=$subjectId
                    sourceId=[string]$field.source
                    collectorId=[string]$Policy.collector.collectorId
                    collectorVersion=[string]$Policy.collector.collectorVersion
                    executionContext=$provenanceContext
                    collectedAt=[string]$CollectorResult.envelope.completedAt
                    sourceLocale=$sourceLocale
                })
                $scopeObservationIds.Add($observationId)
            }
        }
        $coverageId = "coverage:$(([string]$scope.scopeId).Substring(6).Replace('.', '-')):$runId"
        $coverage = [ordered]@{
            coverageId=$coverageId;scopeId=[string]$scope.scopeId;state=[string]$scope.state
            observationIds=@($scopeObservationIds);diagnosticIds=@()
        }
        if ($scope.state -ne 'Complete') {
            $reason = Get-FirmwareCoverageReason -ScopeKind ([string]$scope.kind) `
                -State ([string]$scope.state)
            $diagnosticId = "diagnostic:$(([string]$scope.kind)):$runId"
            $coverage.reasonCode = $reason
            $coverage.diagnosticIds = @($diagnosticId)
            $newDiagnostics.Add([pscustomobject][ordered]@{
                diagnosticId=$diagnosticId;scopeId=[string]$scope.scopeId;phase='Collection'
                reasonCode=$reason
                operatorMessageId="firmware.$(([string]$scope.kind)).$(([string]$scope.state).ToLowerInvariant())"
            })
        }
        $newCoverage.Add([pscustomobject]$coverage)
    }
    $Record.run.evidenceProfileId = [string]$Policy.evidenceProfileId
    $Record.provenance = @($Record.provenance) + @($newProvenance)
    $Record.observations = @($Record.observations) + @($newObservations)
    $Record.coverage = @($Record.coverage) + @($newCoverage)
    $Record.diagnostics = @($Record.diagnostics) + @($newDiagnostics)
    $Record.collectorResults = @($Record.collectorResults) + [pscustomobject][ordered]@{
        envelopeId="envelope:firmware-security:$runId"
        collectorId=[string]$Policy.collector.collectorId
        collectorVersion=[string]$Policy.collector.collectorVersion
        operationId=[string]$Policy.collector.operationId
        intendedScopeIds=@($newCoverage | ForEach-Object { [string]$_.scopeId })
        subjectIds=@($subjectId)
        startedAt=[string]$CollectorResult.envelope.startedAt
        completedAt=[string]$CollectorResult.envelope.completedAt
        executionContext=$provenanceContext;attempts=[int]$CollectorResult.envelope.attempts
        observationIds=@($newObservations | ForEach-Object { [string]$_.observationId })
        coverageIds=@($newCoverage | ForEach-Object { [string]$_.coverageId })
        diagnosticIds=@($newDiagnostics | ForEach-Object { [string]$_.diagnosticId })
    }
    if (@($Record.coverage | Where-Object state -ne 'Complete').Count -gt 0) {
        $Record.run.outcome = 'CompletedWithGaps'
    }
    $Record
}

function New-FirmwareReadinessFinding {
    param(
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter(Mandatory)] [string] $RuleId,
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] [string[]] $FieldIds
    )

    $runId = [string]$Record.run.runId
    $subjectId = [string]@($Record.subjects)[0].subjectId
    [pscustomobject][ordered]@{
        findingId="finding:$Kind`:$runId";ruleId=$RuleId;targetSubjectId=$subjectId
        outcome='Indeterminate';reasonCode='FINDING.EVALUATION_PENDING'
        evidenceReferences=@($Record.observations | Where-Object fieldId -in $FieldIds |
            ForEach-Object { [pscustomobject][ordered]@{
                observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId
            } })
    }
}

function Invoke-FirmwareReadinessRule {
    param(
        [Parameter(Mandatory)] $Rule,
        [Parameter(Mandatory)] [scriptblock] $Evaluation
    )
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $result = @(& $Evaluation)
    $watch.Stop()
    if ($watch.ElapsedMilliseconds -gt [int]$Rule.deadlineMilliseconds -or
        $result.Count -ne 1 -or [string]$result[0].outcome -notin @(
            'ExpectedCondition','NeedsAttention','Informational','Indeterminate','NotApplicable'
        )) {
        throw "The $($Rule.operationId) Rule Evaluation violated its frozen bound."
    }
    $result[0]
}

function Set-FirmwareReadinessFinding {
    param([Parameter(Mandatory)] $Finding, [Parameter(Mandatory)] $Result)
    $Finding.outcome = [string]$Result.outcome
    if ($Result.PSObject.Properties['reasonCode']) {
        $Finding.reasonCode = [string]$Result.reasonCode
    } else { $Finding.PSObject.Properties.Remove('reasonCode') }
}

function Complete-ValidatedFirmwareReadinessAssessmentRecord {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $ContractValidation
    )
    if (-not [bool]$ContractValidation.accepted -or
        $ContractValidation.reasonCode -ne 'CONTRACT.ACCEPTED' -or
        @($Record.findings).Count -ne 4) {
        throw 'Firmware rules require an accepted source-only combined record.'
    }
    $rules = @{}
    foreach ($rule in @($Policy.rules)) { $rules[[string]$rule.findingKind] = $rule }
    $firmware = New-FirmwareReadinessFinding -Kind 'firmware-context' `
        -RuleId $rules['firmware-context'].ruleId -Record $Record -FieldIds @(
            'field:device.firmware.type','field:device.firmware.bios-version',
            'field:device.firmware.smbios-version'
        )
    $secureBoot = New-FirmwareReadinessFinding -Kind 'secure-boot-readiness' `
        -RuleId $rules['secure-boot-readiness'].ruleId -Record $Record -FieldIds @(
            'field:device.firmware.type','field:device.secure-boot.enabled'
        )
    $tpm = New-FirmwareReadinessFinding -Kind 'tpm-readiness' `
        -RuleId $rules['tpm-readiness'].ruleId -Record $Record -FieldIds @(
            'field:device.tpm.present','field:device.tpm.enabled',
            'field:device.tpm.activated','field:device.tpm.specification',
            'field:device.virtualization.detected'
        )
    foreach ($pair in @(
        @{finding=$firmware;rule=$rules['firmware-context']},
        @{finding=$secureBoot;rule=$rules['secure-boot-readiness']},
        @{finding=$tpm;rule=$rules['tpm-readiness']}
    )) {
        if (@($pair.finding.evidenceReferences).Count -gt
            [int]$pair.rule.maximumInputObservations) {
            throw 'A firmware rule widened beyond its frozen evidence bound.'
        }
    }
    $byField = @{}
    foreach ($observation in @($Record.observations)) {
        $byField[[string]$observation.fieldId] = $observation
    }
    $firmwareType = $byField['field:device.firmware.type']
    Set-FirmwareReadinessFinding -Finding $firmware -Result (
        Invoke-FirmwareReadinessRule -Rule $rules['firmware-context'] -Evaluation {
            if ($null -eq $firmwareType -or $firmwareType.valueState -ne 'ObservedValue') {
                [pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.FIRMWARE_EVIDENCE_INCOMPLETE'}
            } elseif ([string]$firmwareType.value -eq 'Uefi') {
                [pscustomobject]@{outcome='ExpectedCondition'}
            } elseif ([string]$firmwareType.value -eq 'LegacyBios') {
                [pscustomobject]@{outcome='NeedsAttention'}
            } else {
                [pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.FIRMWARE_TYPE_UNKNOWN'}
            }
        }
    )
    $secureBootEnabled = $byField['field:device.secure-boot.enabled']
    Set-FirmwareReadinessFinding -Finding $secureBoot -Result (
        Invoke-FirmwareReadinessRule -Rule $rules['secure-boot-readiness'] -Evaluation {
            if ($null -ne $secureBootEnabled -and
                $secureBootEnabled.valueState -eq 'ObservedValue') {
                [pscustomobject]@{outcome=if([bool]$secureBootEnabled.value){'ExpectedCondition'}else{'NeedsAttention'}}
            } elseif ($null -ne $firmwareType -and $firmwareType.valueState -eq 'ObservedValue' -and
                [string]$firmwareType.value -eq 'LegacyBios') {
                [pscustomobject]@{outcome='NotApplicable';reasonCode='FINDING.SECURE_BOOT_NOT_APPLICABLE_NON_UEFI'}
            } else {
                [pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.SECURE_BOOT_EVIDENCE_INCOMPLETE'}
            }
        }
    )
    $tpmPresent = $byField['field:device.tpm.present']
    $tpmEnabled = $byField['field:device.tpm.enabled']
    $tpmActivated = $byField['field:device.tpm.activated']
    $tpmSpecification = $byField['field:device.tpm.specification']
    $virtual = $byField['field:device.virtualization.detected']
    Set-FirmwareReadinessFinding -Finding $tpm -Result (
        Invoke-FirmwareReadinessRule -Rule $rules['tpm-readiness'] -Evaluation {
            if ($null -ne $virtual -and $virtual.valueState -eq 'ObservedValue' -and
                [bool]$virtual.value) {
                [pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.VIRTUAL_TPM_PHYSICAL_ATTESTATION_UNPROVEN'}
            } elseif ($null -eq $tpmPresent -or $tpmPresent.valueState -ne 'ObservedValue') {
                [pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.TPM_EVIDENCE_INCOMPLETE'}
            } elseif (-not [bool]$tpmPresent.value) {
                [pscustomobject]@{outcome='NeedsAttention'}
            } elseif (($null -ne $tpmEnabled -and
                    $tpmEnabled.valueState -eq 'ObservedValue' -and
                    -not [bool]$tpmEnabled.value) -or
                ($null -ne $tpmActivated -and
                    $tpmActivated.valueState -eq 'ObservedValue' -and
                    -not [bool]$tpmActivated.value)) {
                [pscustomobject]@{outcome='NeedsAttention'}
            } elseif ($null -eq $tpmEnabled -or $tpmEnabled.valueState -ne 'ObservedValue' -or
                $null -eq $tpmActivated -or $tpmActivated.valueState -ne 'ObservedValue' -or
                $null -eq $tpmSpecification -or
                $tpmSpecification.valueState -ne 'ObservedValue') {
                [pscustomobject]@{
                    outcome='Indeterminate';reasonCode='FINDING.TPM_DETAILS_INCOMPLETE'
                }
            } elseif ($null -ne $tpmEnabled -and $tpmEnabled.valueState -eq 'ObservedValue' -and
                [bool]$tpmEnabled.value -and $null -ne $tpmActivated -and
                $tpmActivated.valueState -eq 'ObservedValue' -and [bool]$tpmActivated.value -and
                $null -ne $tpmSpecification -and $tpmSpecification.valueState -eq 'ObservedValue' -and
                [string]$tpmSpecification.value -match '(?:^|,\s*)2\.0(?:\s*,|$)') {
                [pscustomobject]@{outcome='ExpectedCondition'}
            } else { [pscustomobject]@{outcome='NeedsAttention'} }
        }
    )
    $Record.findings = @($Record.findings) + @($firmware,$secureBoot,$tpm)
    $recommendations = [Collections.Generic.List[object]]::new()
    $firmwareReason = if ($firmware.PSObject.Properties['reasonCode']) {
        [string]$firmware.reasonCode
    } else { '' }
    $secureBootReason = if ($secureBoot.PSObject.Properties['reasonCode']) {
        [string]$secureBoot.reasonCode
    } else { '' }
    $tpmReason = if ($tpm.PSObject.Properties['reasonCode']) {
        [string]$tpm.reasonCode
    } else { '' }
    if ($tpmReason -eq 'FINDING.VIRTUAL_TPM_PHYSICAL_ATTESTATION_UNPROVEN') {
        $recommendations.Add([pscustomobject][ordered]@{
            recommendationId="recommendation:physical-tpm:$($Record.run.runId)"
            definitionId='task:confirm-physical-tpm-attestation/1.0.0'
            kind='TenantSideDiscoveryTask';findingIds=@([string]$tpm.findingId)
        })
    }
    $secureBootCoverage = @($Record.coverage | Where-Object {
        $_.scopeId -eq 'scope:device.secure-boot'
    })[0]
    if ($firmwareReason -eq 'FINDING.FIRMWARE_TYPE_UNKNOWN' -or
        $secureBootReason -eq 'FINDING.SECURE_BOOT_NOT_APPLICABLE_NON_UEFI' -or
        [string]$secureBootCoverage.state -eq 'Unsupported') {
        $recommendations.Add([pscustomobject][ordered]@{
            recommendationId="recommendation:oem-firmware:$($Record.run.runId)"
            definitionId='task:confirm-oem-firmware-support/1.0.0'
            kind='TenantSideDiscoveryTask'
            findingIds=@($firmware,$secureBoot | Where-Object outcome -in @('Indeterminate','NotApplicable') |
                ForEach-Object { [string]$_.findingId })
        })
    }
    $Record.recommendations = @($Record.recommendations) + @($recommendations)
    $Record.run.outcome = if (@($Record.coverage | Where-Object state -ne 'Complete').Count -eq 0) {
        'Completed'
    } else { 'CompletedWithGaps' }
    $Record
}
