$script:DeviceReadinessPolicyBase64 = '__DEVICE_READINESS_POLICY_BASE64__'
$script:DeviceReadinessPolicyDigest = '__DEVICE_READINESS_POLICY_SHA256__'

function Get-DeviceReadinessPolicy {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    if ($script:DeviceReadinessPolicyBase64 -eq '__DEVICE_READINESS_POLICY_BASE64__') {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-device-readiness.json'
        $bytes = Get-CanonicalSupervisorTextBytes -LiteralPath $path
        $expectedDigest = Get-Sha256ForSupervisorBytes -Bytes $bytes
    }
    else {
        $bytes = [System.Convert]::FromBase64String($script:DeviceReadinessPolicyBase64)
        $expectedDigest = $script:DeviceReadinessPolicyDigest
    }
    if ((Get-Sha256ForSupervisorBytes -Bytes $bytes) -ne $expectedDigest) {
        throw 'The Device Readiness policy failed integrity validation.'
    }
    $policy = & $ConvertFromJsonCommand -InputObject (
        [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    ) -Depth 20 -ErrorAction Stop
    $ruleOperations = @($policy.rules | ForEach-Object { [string]$_.operationId })
    $derivationOperations = @($policy.derivations | ForEach-Object { [string]$_.operationId })
    if ($policy.kind -ne 'win-pcinfo.device-readiness-policy' -or
        $policy.release -ne '2.0.0-preview.1' -or
        $policy.collector.operationId -ne 'op:device.windows-context.collect' -or
        @($policy.derivations).Count -ne 2 -or
        ($derivationOperations -join '|') -ne
            'op:device.virtualization.classify|op:device.form-factor.classify' -or
        @($policy.derivations | Where-Object {
            $_.deadlineMilliseconds -ne 100 -or $_.maximumOutputObservations -ne 1
        }).Count -gt 0 -or
        @($policy.rules).Count -ne 4 -or
        ($ruleOperations -join '|') -ne (
            'op:rule.device-readiness.evaluate|op:rule.windows-activation-context.evaluate|' +
            'op:rule.device-platform-context.evaluate|op:rule.device-power-context.evaluate'
        ) -or
        @($policy.rules | Where-Object {
            $_.deadlineMilliseconds -ne 100 -or $_.maximumOutputFindings -ne 1
        }).Count -gt 0 -or
        @($policy.fieldIds).Count -ne 17 -or @($policy.validationScenarios).Count -ne 18) {
        throw 'The Device Readiness policy is not the closed release policy.'
    }
    $policy
}

function Read-DeviceReadinessFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $FirmwarePolicy
    )

    try {
        [byte[]] $bytes = [System.IO.File]::ReadAllBytes([System.IO.Path]::GetFullPath($LiteralPath))
        if ($bytes.Length -lt 1 -or $bytes.Length -gt 1024) { throw 'Fixture size is invalid.' }
        $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $document = [System.Text.Json.JsonDocument]::Parse($json)
        try {
            $names = @($document.RootElement.EnumerateObject() | ForEach-Object Name)
            $shape = @($names | Sort-Object) -join '|'
            if ($shape -notin @(
                'contractVersion|scenario',
                'contractVersion|firmwareScenario|privilegeScenario|scenario'
            )) { throw 'Fixture shape is invalid.' }
        }
        finally { $document.Dispose() }
        $fixture = & $ConvertFromJsonCommand -InputObject $json -Depth 5 -ErrorAction Stop
        $firmwareScenario = if ($fixture.PSObject.Properties['firmwareScenario']) {
            [string]$fixture.firmwareScenario
        } else { 'None' }
        $privilegeScenario = if ($fixture.PSObject.Properties['privilegeScenario']) {
            [string]$fixture.privilegeScenario
        } else { 'None' }
        if ($fixture.contractVersion -ne '1.0.0' -or
            [string]$fixture.scenario -notin @($Policy.validationScenarios) -or
            $firmwareScenario -notin (@('None') + @($FirmwarePolicy.validationScenarios)) -or
            $privilegeScenario -notin @('None','AcceptedElevation','AlreadyElevated')) {
            throw 'Fixture scenario is not release-owned.'
        }
        [pscustomobject][ordered]@{
            DeviceScenario=[string]$fixture.scenario
            FirmwareScenario=$firmwareScenario
            PrivilegeScenario=$privilegeScenario
        }
    }
    catch {
        $exception = [System.ArgumentException]::new('The Device Readiness fixture is invalid.')
        $exception.Data['ReasonCode'] = 'DEVICE_READINESS.FIXTURE_INVALID'
        throw $exception
    }
}

function Get-NormalizedWindowsEdition {
    param([Parameter(Mandatory)] [int] $OperatingSystemSku)

    # Windows exposes a numeric PRODUCT_* identifier through
    # OperatingSystemSKU. Mapping that number here makes the stored value stable
    # across display languages; an unknown number remains explicit instead of
    # guessing from localized marketing text.
    switch ($OperatingSystemSku) {
        4 { 'Enterprise' }
        27 { 'EnterpriseN' }
        48 { 'Professional' }
        49 { 'ProfessionalN' }
        101 { 'Home' }
        98 { 'HomeN' }
        121 { 'Education' }
        122 { 'EducationN' }
        125 { 'EnterpriseS' }
        default { "Sku-$OperatingSystemSku" }
    }
}

function Get-NormalizedWindowsActivationState {
    param($LicenseStatus)

    # SoftwareLicensingProduct exposes many tempting identity and key-adjacent
    # properties. The approved child process projects LicenseStatus only. This
    # mapper therefore receives one bounded numeric state, never a product key,
    # partial key, product identifier, or free-form licensing description.
    if ($null -eq $LicenseStatus) { return $null }
    switch ([int] $LicenseStatus) {
        1 { 'Activated' }
        { $_ -in 0,2,3,4,5,6 } { 'NotActivated'; break }
        default { $null }
    }
}

function Get-NormalizedBatteryStatus {
    param($BatteryStatus)

    if ($null -eq $BatteryStatus) { return $null }
    switch ([int] $BatteryStatus) {
        1 { 'Discharging' }
        2 { 'ExternalPower' }
        3 { 'FullyCharged' }
        4 { 'Low' }
        5 { 'Critical' }
        6 { 'Charging' }
        7 { 'ChargingHigh' }
        8 { 'ChargingLow' }
        9 { 'ChargingCritical' }
        10 { 'Undefined' }
        11 { 'PartiallyCharged' }
        default { $null }
    }
}

function New-DeviceContextFinding {
    param(
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter(Mandatory)] [string] $RunId,
        [Parameter(Mandatory)] [string] $RuleId,
        [Parameter(Mandatory)] [string] $SubjectId,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Observations,
        [Parameter(Mandatory)] [string[]] $FieldIds
    )

    # Findings never reach back into collector output. Each one freezes the
    # exact admitted observations it may interpret, which keeps activation,
    # platform, and power advice independently auditable when another source is
    # unavailable or denied.
    $evidence = @($Observations | Where-Object fieldId -in $FieldIds)
    [pscustomobject][ordered]@{
        findingId = "finding:$Kind`:$RunId"
        ruleId = $RuleId
        targetSubjectId = $SubjectId
        outcome = 'Indeterminate'
        reasonCode = 'FINDING.EVALUATION_PENDING'
        evidenceReferences = @($evidence | ForEach-Object {
            [pscustomobject][ordered]@{
                observationId = $_.observationId
                fieldId = $_.fieldId
                subjectId = $_.subjectId
            }
        })
    }
}

function ConvertTo-NormalizedDeviceReadinessEvidence {
    param([Parameter(Mandatory)] $Payload)

    $locale = [string] $Payload.sourceLocale
    if ($locale -notmatch '^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$') { $locale = 'und' }
    $architecture = if ($null -eq $Payload.architecture) { $null } else {
        switch -Regex ([string] $Payload.architecture) {
            '^(?i:x64|amd64)$' { 'X64'; break }
            '^(?i:arm64)$' { 'Arm64'; break }
            '^(?i:x86)$' { 'X86'; break }
            default { $null }
        }
    }
    [pscustomobject][ordered]@{
        sourceLocale = $locale
        manufacturer = if ($null -eq $Payload.manufacturer) { $null } else { ([string]$Payload.manufacturer).Trim() }
        model = if ($null -eq $Payload.model) { $null } else { ([string]$Payload.model).Trim() }
        processorName = if ($null -eq $Payload.processorName) { $null } else { ([string]$Payload.processorName).Trim() }
        memoryBytes = if ($null -eq $Payload.memoryBytes) { $null } else { [long] $Payload.memoryBytes }
        windowsEdition = if ($null -eq $Payload.operatingSystemSku) { $null } else {
            Get-NormalizedWindowsEdition -OperatingSystemSku ([int] $Payload.operatingSystemSku)
        }
        build = if ($null -eq $Payload.build) { $null } else { ([string]$Payload.build).Trim() }
        architecture = $architecture
        activationState = Get-NormalizedWindowsActivationState -LicenseStatus $Payload.activationStatus
        activationAvailability = [string] $Payload.activationAvailability
        systemTypeCode = if ($null -eq $Payload.computerSystemType) { $null } else {
            [int] $Payload.computerSystemType
        }
        hypervisorPresent = if ($null -eq $Payload.hypervisorPresent) { $null } else {
            [bool] $Payload.hypervisorPresent
        }
        chassisTypeCodes = if ($null -eq $Payload.chassisTypeCodes) { $null } else {
            ([string] $Payload.chassisTypeCodes).Trim()
        }
        chassisAvailability = [string] $Payload.chassisAvailability
        virtualizationDetected = $null
        formFactor = $null
        batteryAvailability = [string] $Payload.batteryAvailability
        batteryPresence = if ($null -eq $Payload.batteryPresent) { $null } else {
            [bool] $Payload.batteryPresent
        }
        batteryStatus = Get-NormalizedBatteryStatus -BatteryStatus $Payload.batteryStatus
        batteryChargePercent = if ($null -eq $Payload.batteryChargePercent) { $null } else {
            [int] $Payload.batteryChargePercent
        }
        batteryRuntimeMinutes = if ($null -eq $Payload.batteryRuntimeMinutes) { $null } else {
            [int] $Payload.batteryRuntimeMinutes
        }
    }
}

function New-DeviceReadinessAssessmentRecord {
    param(
        [Parameter(Mandatory)] [string] $RunId,
        [Parameter(Mandatory)] $Evidence,
        [Parameter(Mandatory)] $CollectorResult,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [bool] $ValidationFixture,
        [Parameter()] [ValidateSet('', 'Partial', 'Unavailable', 'Malformed', 'Failed',
            'Denied', 'ProhibitedMaterialBlocked')]
        [string] $CoverageStateOverride = '',
        [Parameter()] [string] $CoverageReasonCode = ''
    )

    $subjectId = 'subject:device:primary'
    $fieldSpecs = @(
        @{ id='field:device.manufacturer'; source='source:windows.cim.computer-system'; property='manufacturer' },
        @{ id='field:device.model'; source='source:windows.cim.computer-system'; property='model' },
        @{ id='field:device.processor.name'; source='source:windows.cim.processor'; property='processorName' },
        @{ id='field:device.memory.physical-bytes'; source='source:windows.cim.computer-system'; property='memoryBytes' },
        @{ id='field:device.windows.edition'; source='source:windows.cim.operating-system'; property='windowsEdition' },
        @{ id='field:device.windows.build'; source='source:windows.cim.operating-system'; property='build' },
        @{ id='field:device.architecture'; source='source:dotnet.runtime-information'; property='architecture' },
        @{ id='field:device.windows.activation-state'; source='source:windows.cim.software-licensing-product'; property='activationState' },
        @{ id='field:device.system-type-code'; source='source:windows.cim.computer-system'; property='systemTypeCode' },
        @{ id='field:device.hypervisor-present'; source='source:windows.cim.computer-system'; property='hypervisorPresent' },
        @{ id='field:device.chassis.type-codes'; source='source:windows.cim.system-enclosure'; property='chassisTypeCodes' },
        @{ id='field:device.battery.presence'; source='source:windows.cim.battery'; property='batteryPresence' },
        @{ id='field:device.battery.status'; source='source:windows.cim.battery'; property='batteryStatus'; batteryDetail=$true },
        @{ id='field:device.battery.charge-percent'; source='source:windows.cim.battery'; property='batteryChargePercent'; batteryDetail=$true },
        @{ id='field:device.battery.estimated-runtime-minutes'; source='source:windows.cim.battery'; property='batteryRuntimeMinutes'; batteryDetail=$true }
    )
    $observations = [System.Collections.Generic.List[object]]::new()
    $provenance = [System.Collections.Generic.List[object]]::new()
    $collectionExaminedFields = $CoverageStateOverride -notin @(
        'Unavailable', 'Malformed', 'Failed', 'ProhibitedMaterialBlocked'
    )
    if ($collectionExaminedFields) {
        foreach ($field in $fieldSpecs) {
            # A source-access failure is coverage and diagnostic evidence, not
            # a field examination. Skip that source's observations entirely so
            # SourceReportedUnknown keeps its domain meaning: Windows actually
            # examined the field and reported no usable value.
            if (([string]$field.source -eq 'source:windows.cim.software-licensing-product' -and
                    $Evidence.activationAvailability -ne 'Available') -or
                ([string]$field.source -eq 'source:windows.cim.system-enclosure' -and
                    $Evidence.chassisAvailability -ne 'Available') -or
                ([string]$field.source -eq 'source:windows.cim.battery' -and
                    $Evidence.batteryAvailability -ne 'Available')) {
                continue
            }
            $suffix = ([string] $field.id).Substring('field:'.Length).Replace('.', '-')
            $observationId = "observation:$suffix`:$RunId"
            $provenanceId = "provenance:$suffix`:$RunId"
            $value = $Evidence.([string] $field.property)
            $provenance.Add([pscustomobject][ordered]@{
                provenanceId = $provenanceId; fieldId = [string] $field.id; subjectId = $subjectId
                sourceId = [string] $field.source; collectorId = [string] $Policy.collector.collectorId
                collectorVersion = [string] $Policy.collector.collectorVersion
                executionContext = if ($ValidationFixture) { 'Synthetic' } else { 'StandardUser' }
                collectedAt = [string] $CollectorResult.Envelope.completedAt
                sourceLocale = [string] $Evidence.sourceLocale
            })
            $valueState = if ($field.ContainsKey('batteryDetail') -and
                $Evidence.batteryPresence -eq $false) {
                'ObservedAbsent'
            }
            elseif ($null -eq $value) { 'SourceReportedUnknown' }
            else { 'ObservedValue' }
            $observation = [ordered]@{
                observationId = $observationId; fieldId = [string] $field.id
                subjectId = $subjectId; provenanceId = $provenanceId
                valueState = $valueState
            }
            if ($valueState -eq 'ObservedValue') { $observation.value = $value }
            $observations.Add([pscustomobject] $observation)
        }
    }

    # The first contract pass omits derived fields altogether. Absence here is
    # not a source-reported unknown: the classifiers have not run yet. They may
    # append their own observations only after these source facts are accepted.
    $availabilitySpecs = @(
        @{ kind='activation'; state=[string]$Evidence.activationAvailability },
        @{ kind='chassis'; state=[string]$Evidence.chassisAvailability },
        @{ kind='battery'; state=[string]$Evidence.batteryAvailability }
    )
    $availabilityGap = @($availabilitySpecs | Where-Object state -ne 'Available').Count -gt 0
    $requiredSourceGap = @(
        $Evidence.manufacturer, $Evidence.model, $Evidence.processorName,
        $Evidence.memoryBytes, $Evidence.windowsEdition, $Evidence.build,
        $Evidence.architecture | Where-Object { $null -eq $_ }
    ).Count -gt 0
    $coverageState = if ($CoverageStateOverride) { $CoverageStateOverride } else { 'Partial' }
    if (-not $CoverageReasonCode) {
        $CoverageReasonCode = if (@($availabilitySpecs | Where-Object state -eq 'Denied').Count -gt 0) {
            'COLLECTION.FIELD_INACCESSIBLE'
        }
            elseif ($availabilityGap) { 'COLLECTION.FIELD_UNAVAILABLE' }
            elseif ($requiredSourceGap) { 'COLLECTION.FIELD_UNAVAILABLE' }
            else { 'COLLECTION.DERIVATION_PENDING' }
    }
    $diagnostics = [System.Collections.Generic.List[object]]::new()
    if ($CoverageStateOverride -or -not $availabilityGap) {
        $diagnostics.Add([pscustomobject][ordered]@{
            diagnosticId = "diagnostic:device-field-unavailable:$RunId"
            scopeId = [string] $Policy.scopeId; phase = 'Collection'
            reasonCode = $CoverageReasonCode
            operatorMessageId = switch ($CoverageReasonCode) {
                'COLLECTION.SOURCE_UNAVAILABLE' { 'device.readiness.source-unavailable' }
                'COLLECTION.PAYLOAD_MALFORMED' { 'device.readiness.payload-malformed' }
                'COLLECTION.OUTPUT_LIMIT_EXCEEDED' { 'device.readiness.output-limit-exceeded' }
                'COLLECTION.PROHIBITED_MATERIAL_BLOCKED' { 'device.context.prohibited-material-blocked' }
                'COLLECTION.DERIVATION_PENDING' { 'device.readiness.derivation-pending' }
                default { 'device.readiness.field-unavailable' }
            }
        })
    }
    else {
        foreach ($availability in @($availabilitySpecs | Where-Object state -ne 'Available')) {
            $upperKind = ([string]$availability.kind).ToUpperInvariant()
            $isDenied = [string]$availability.state -eq 'Denied'
            $diagnostics.Add([pscustomobject][ordered]@{
                diagnosticId = "diagnostic:device-$($availability.kind)-access:$RunId"
                scopeId = [string] $Policy.scopeId; phase = 'Collection'
                reasonCode = if ($isDenied) { "COLLECTION.$upperKind`_ACCESS_DENIED" }
                    else { "COLLECTION.$upperKind`_SOURCE_UNAVAILABLE" }
                operatorMessageId = if ($isDenied) { "device.context.$($availability.kind)-access-denied" }
                    else { "device.context.$($availability.kind)-source-unavailable" }
            })
        }
    }
    if ($CoverageStateOverride -eq 'ProhibitedMaterialBlocked') {
        $diagnostics[0] | Add-Member -NotePropertyName prohibitedMaterial -NotePropertyValue (
            [pscustomobject][ordered]@{ encountered=$true; retained=$false; hashed=$false }
        )
    }
    $coverageId = "coverage:device-windows-context:$RunId"
    $observationIds = @($observations | ForEach-Object { [string]$_.observationId })
    $diagnosticIds = @($diagnostics | ForEach-Object { [string] $_.diagnosticId })

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.assessment-record'; contractVersion = '1.0.0'
        requiredFeatures = @('closed-scope-coverage','evidence-references','prohibited-material-omission')
        run = [pscustomobject][ordered]@{
            runId = $RunId
            outcome = 'CompletedWithGaps'
            validationFixture = $ValidationFixture
            evidenceProfileId = 'profile:device-windows-context'
        }
        subjects = @([pscustomobject][ordered]@{ subjectId=$subjectId; kind='Device' })
        provenance = @($provenance)
        observations = @($observations)
        coverage = @([pscustomobject][ordered]@{
            coverageId=$coverageId; scopeId=[string]$Policy.scopeId; state=$coverageState
            reasonCode=$CoverageReasonCode
            observationIds=$observationIds; diagnosticIds=$diagnosticIds
        })
        diagnostics = @($diagnostics)
        collectorResults = @([pscustomobject][ordered]@{
            envelopeId="envelope:device-windows-context:$RunId"
            collectorId=[string]$Policy.collector.collectorId
            collectorVersion=[string]$Policy.collector.collectorVersion
            operationId=[string]$Policy.collector.operationId
            intendedScopeIds=@([string]$Policy.scopeId); subjectIds=@($subjectId)
            startedAt=[string]$CollectorResult.Envelope.startedAt
            completedAt=[string]$CollectorResult.Envelope.completedAt
            executionContext=if($ValidationFixture){'Synthetic'}else{'StandardUser'}
            attempts=1; observationIds=$observationIds; coverageIds=@($coverageId)
            diagnosticIds=$diagnosticIds
        })
        findings = @()
        recommendations = @(); recommendationRelationships = @()
    }
}

function Invoke-DeviceContextRuleEvaluation {
    param(
        [Parameter(Mandatory)] $Rule,
        [Parameter(Mandatory)] [scriptblock] $Evaluation
    )

    # A Rule Evaluation has one declared operation and returns one outcome for
    # one finding. Keeping the stopwatch here makes the four finite boundaries
    # executable rather than treating their policy deadlines as documentation.
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $results = @(& $Evaluation)
    $watch.Stop()
    if ($watch.ElapsedMilliseconds -gt [int]$Rule.deadlineMilliseconds) {
        throw "The release-owned $($Rule.operationId) rule exceeded its finite deadline."
    }
    if ($results.Count -ne 1 -or [string]$results[0].outcome -notin @(
        'ExpectedCondition','NeedsAttention','Informational','Indeterminate','NotApplicable'
    )) {
        throw "The release-owned $($Rule.operationId) rule returned an invalid result."
    }
    $results[0]
}

function Set-DeviceContextFindingResult {
    param(
        [Parameter(Mandatory)] $Finding,
        [Parameter(Mandatory)] $Result
    )

    $Finding.outcome = [string]$Result.outcome
    if ($null -ne $Result.PSObject.Properties['reasonCode'] -and
        -not [string]::IsNullOrWhiteSpace([string]$Result.reasonCode)) {
        $Finding.reasonCode = [string]$Result.reasonCode
    }
    else {
        $Finding.PSObject.Properties.Remove('reasonCode')
    }
}

function Invoke-DeviceContextDerivation {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $Definition,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $InputObservations,
        [Parameter(Mandatory)] [scriptblock] $Evaluation,
        [Parameter(Mandatory)] [hashtable] $ByField
    )

    if ($InputObservations.Count -gt [int]$Definition.maximumInputObservations) {
        throw "The $($Definition.operationId) classifier input exceeded its frozen bound."
    }
    $startedAt = [System.DateTimeOffset]::UtcNow
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $results = @(& $Evaluation)
    $watch.Stop()
    $completedAt = [System.DateTimeOffset]::UtcNow
    $expectedFieldId = if ([string]$Definition.derivedKind -eq 'virtualization') {
        'field:device.virtualization.detected'
    } else { 'field:device.form-factor' }
    if ($watch.ElapsedMilliseconds -gt [int]$Definition.deadlineMilliseconds) {
        throw "The $($Definition.operationId) classifier exceeded its finite deadline."
    }
    if ($results.Count -ne [int]$Definition.maximumOutputObservations -or
        [string]$results[0].fieldId -ne $expectedFieldId) {
        throw "The $($Definition.operationId) classifier returned an invalid output."
    }

    # A classifier has its own identity and real timing. Its output is never
    # backdated into the already-completed Windows collector attempt.
    $derived = $results[0]
    $subjectId = [string]@($Record.subjects)[0].subjectId
    $runId = [string]$Record.run.runId
    $suffix = $expectedFieldId.Substring('field:'.Length).Replace('.', '-')
    $observationId = "observation:$suffix`:$runId"
    $provenanceId = "provenance:$suffix`:$runId"
    $sourceLocale = if (@($Record.provenance).Count -gt 0) {
        [string]@($Record.provenance)[0].sourceLocale
    } else { 'und' }
    $provenance = [pscustomobject][ordered]@{
        provenanceId=$provenanceId;fieldId=$expectedFieldId;subjectId=$subjectId
        sourceId=[string]$Definition.sourceId;collectorId=[string]$Definition.collectorId
        collectorVersion=[string]$Definition.collectorVersion
        executionContext=[string]$Definition.executionContext
        collectedAt=$completedAt.ToString('o');sourceLocale=$sourceLocale
    }
    $observation = [ordered]@{
        observationId=$observationId;fieldId=$expectedFieldId
        subjectId=$subjectId;provenanceId=$provenanceId
        valueState=if($null -eq $derived.value){'SourceReportedUnknown'}else{'ObservedValue'}
    }
    if ($null -ne $derived.value) { $observation.value = $derived.value }
    $observation = [pscustomobject]$observation
    $Record.provenance = @($Record.provenance) + $provenance
    $Record.observations = @($Record.observations) + $observation
    $Record.coverage[0].observationIds = @($Record.coverage[0].observationIds) + $observationId
    $Record.collectorResults = @($Record.collectorResults) + [pscustomobject][ordered]@{
        envelopeId="envelope:$($Definition.derivedKind):$runId"
        collectorId=[string]$Definition.collectorId
        collectorVersion=[string]$Definition.collectorVersion
        operationId=[string]$Definition.operationId
        intendedScopeIds=@([string]$Record.coverage[0].scopeId);subjectIds=@($subjectId)
        startedAt=$startedAt.ToString('o');completedAt=$completedAt.ToString('o')
        executionContext=[string]$Definition.executionContext;attempts=1
        observationIds=@($observationId)
        coverageIds=@([string]$Record.coverage[0].coverageId);diagnosticIds=@()
    }
    $ByField[$expectedFieldId] = $observation
}

function Add-ValidatedDeviceContextDerivations {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [hashtable] $ByField
    )

    $definitions = @{}
    foreach ($definition in @($Policy.derivations)) {
        $definitions[[string]$definition.derivedKind] = $definition
    }
    $manufacturer = $ByField['field:device.manufacturer']
    $model = $ByField['field:device.model']
    Invoke-DeviceContextDerivation -Record $Record -Definition $definitions.virtualization `
        -InputObservations @($manufacturer,$model | Where-Object { $null -ne $_ }) `
        -ByField $ByField -Evaluation {
        $value = if ($null -ne $manufacturer -and $manufacturer.valueState -eq 'ObservedValue' -and
            $null -ne $model -and $model.valueState -eq 'ObservedValue') {
            [bool]([string]$manufacturer.value -match
                '(?i)Microsoft Corporation|VMware|Xen|QEMU|VirtualBox' -or
                [string]$model.value -match '(?i)Virtual Machine|VMware|VirtualBox|KVM|HVM')
        } else { $null }
        [pscustomobject]@{fieldId='field:device.virtualization.detected';value=$value}
    }

    $virtualization = $ByField['field:device.virtualization.detected']
    $systemType = $ByField['field:device.system-type-code']
    $chassis = $ByField['field:device.chassis.type-codes']
    Invoke-DeviceContextDerivation -Record $Record -Definition $definitions['form-factor'] `
        -InputObservations @($virtualization,$systemType,$chassis | Where-Object { $null -ne $_ }) `
        -ByField $ByField -Evaluation {
        $codes = if ($null -ne $chassis -and $chassis.valueState -eq 'ObservedValue') {
            @(([string]$chassis.value -split ',') | ForEach-Object { [int]$_ })
        } else { @() }
        $systemCode = if ($null -ne $systemType -and $systemType.valueState -eq 'ObservedValue') {
            [int]$systemType.value
        } else { -1 }
        $value = if ($virtualization.valueState -eq 'ObservedValue' -and
            [bool]$virtualization.value) { 'Virtual' }
            elseif (@($codes | Where-Object { $_ -in 30,31,32 }).Count -gt 0 -or
                $systemCode -eq 8) { 'Tablet' }
            elseif (@($codes | Where-Object { $_ -in 8,9,10,11,14 }).Count -gt 0 -or
                $systemCode -eq 2) { 'Laptop' }
            elseif (@($codes | Where-Object { $_ -in 3,4,5,6,7,13,15,16,23 }).Count -gt 0 -or
                $systemCode -eq 1) { 'Desktop' }
            elseif ($codes.Count -gt 0 -or $systemCode -ge 0) { 'Other' }
            else { $null }
        [pscustomobject]@{fieldId='field:device.form-factor';value=$value}
    }
}

function Complete-ValidatedDeviceReadinessAssessmentRecord {
    param(
        [Parameter(Mandatory)] $ValidatedRecord,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $ContractValidation
    )

    if (-not $ContractValidation.accepted -or
        $ContractValidation.reasonCode -ne 'CONTRACT.ACCEPTED') {
        throw 'Device Readiness rules require an accepted source-observation contract pass.'
    }
    $rulesByKind = @{}
    foreach ($rule in @($Policy.rules)) { $rulesByKind[[string]$rule.findingKind] = $rule }
    if (@($ValidatedRecord.observations).Count -gt 15 -or
        @($ValidatedRecord.findings).Count -ne 0) {
        throw 'The source pass contains output that belongs after rule admission.'
    }

    $byField = @{}
    foreach ($observation in @($ValidatedRecord.observations)) {
        $byField[[string]$observation.fieldId] = $observation
    }
    $coverage = @($ValidatedRecord.coverage)[0]
    $sourceFailureState = [string]$coverage.state -in @(
        'Unavailable','Malformed','Failed','Denied','ProhibitedMaterialBlocked'
    )
    if (-not $sourceFailureState) {
        Add-ValidatedDeviceContextDerivations -Record $ValidatedRecord -Policy $Policy `
            -ByField $byField
    }

    $runId = [string]$ValidatedRecord.run.runId
    $subjectId = [string]@($ValidatedRecord.subjects)[0].subjectId
    $ValidatedRecord.findings = @(
        New-DeviceContextFinding -Kind 'device-readiness' -RunId $runId `
            -RuleId ([string]$rulesByKind['device-readiness'].ruleId) -SubjectId $subjectId `
            -Observations @($ValidatedRecord.observations) -FieldIds @(
                'field:device.memory.physical-bytes','field:device.windows.build',
                'field:device.architecture'
            )
        New-DeviceContextFinding -Kind 'activation-context' -RunId $runId `
            -RuleId ([string]$rulesByKind['activation-context'].ruleId) -SubjectId $subjectId `
            -Observations @($ValidatedRecord.observations) `
            -FieldIds @('field:device.windows.activation-state')
        New-DeviceContextFinding -Kind 'platform-context' -RunId $runId `
            -RuleId ([string]$rulesByKind['platform-context'].ruleId) -SubjectId $subjectId `
            -Observations @($ValidatedRecord.observations) -FieldIds @(
                'field:device.manufacturer','field:device.model',
                'field:device.virtualization.detected','field:device.system-type-code',
                'field:device.chassis.type-codes','field:device.form-factor'
            )
        New-DeviceContextFinding -Kind 'power-context' -RunId $runId `
            -RuleId ([string]$rulesByKind['power-context'].ruleId) -SubjectId $subjectId `
            -Observations @($ValidatedRecord.observations) -FieldIds @(
                'field:device.battery.presence','field:device.battery.status',
                'field:device.battery.charge-percent',
                'field:device.battery.estimated-runtime-minutes'
            )
    )
    foreach ($findingToCheck in @($ValidatedRecord.findings)) {
        $matchingRules = @($Policy.rules | Where-Object ruleId -eq $findingToCheck.ruleId)
        if ($matchingRules.Count -ne 1 -or
            @($findingToCheck.evidenceReferences).Count -gt
                [int]$matchingRules[0].maximumInputObservations -or
            [string]$findingToCheck.findingId -notlike
                "finding:$([string]$matchingRules[0].findingKind):*") {
            throw 'A Device Context Rule Evaluation is not bound to exactly one finite finding.'
        }
    }

    # Each declared rule now reads only completed observations and produces
    # exactly one result for its one canonical finding.
    $readinessFinding = @($ValidatedRecord.findings | Where-Object {
        $_.findingId -like 'finding:device-readiness:*'
    })[0]
    $activationFinding = @($ValidatedRecord.findings | Where-Object {
        $_.findingId -like 'finding:activation-context:*'
    })[0]
    $platformFinding = @($ValidatedRecord.findings | Where-Object {
        $_.findingId -like 'finding:platform-context:*'
    })[0]
    $powerFinding = @($ValidatedRecord.findings | Where-Object {
        $_.findingId -like 'finding:power-context:*'
    })[0]
    $virtualization = $byField['field:device.virtualization.detected']
    $platformResult = Invoke-DeviceContextRuleEvaluation `
        -Rule $rulesByKind['platform-context'] -Evaluation {
        if ($null -ne $virtualization -and $virtualization.valueState -eq 'ObservedValue' -and
            [bool]$virtualization.value) {
            [pscustomobject]@{outcome='Informational'}
        }
        elseif ($null -ne $virtualization -and $virtualization.valueState -eq 'ObservedValue') {
            [pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.PHYSICAL_DEVICE_NOT_ESTABLISHED'}
        }
        else {
            [pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.PLATFORM_EVIDENCE_INCOMPLETE'}
        }
    }
    Set-DeviceContextFindingResult -Finding $platformFinding -Result $platformResult

    if (-not $sourceFailureState -and
        [string]$coverage.reasonCode -eq 'COLLECTION.DERIVATION_PENDING') {
        $coverage.state = 'Complete'
        $coverage.PSObject.Properties.Remove('reasonCode')
        $coverage.diagnosticIds = @()
        $ValidatedRecord.diagnostics = @()
        $ValidatedRecord.collectorResults[0].diagnosticIds = @()
        $ValidatedRecord.run.outcome = 'Completed'
    }

    $memory = $byField['field:device.memory.physical-bytes']
    $build = $byField['field:device.windows.build']
    $architecture = $byField['field:device.architecture']
    $readinessResult = Invoke-DeviceContextRuleEvaluation `
        -Rule $rulesByKind['device-readiness'] -Evaluation {
        if ($null -ne $memory -and $memory.valueState -eq 'ObservedValue' -and
            $null -ne $build -and $build.valueState -eq 'ObservedValue' -and
            $null -ne $architecture -and $architecture.valueState -eq 'ObservedValue') {
            $rule = $rulesByKind['device-readiness']
            $ready = [long]$memory.value -ge [long]$rule.minimumMemoryBytes -and
                [long]$build.value -ge [long]$rule.minimumWindowsBuild -and
                [string]$architecture.value -in @($rule.supportedArchitectures)
            [pscustomobject]@{outcome=if($ready){'ExpectedCondition'}else{'NeedsAttention'}}
        }
        else { [pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.EVIDENCE_INCOMPLETE'} }
    }
    Set-DeviceContextFindingResult -Finding $readinessFinding -Result $readinessResult

    $activation = $byField['field:device.windows.activation-state']
    $activationResult = Invoke-DeviceContextRuleEvaluation `
        -Rule $rulesByKind['activation-context'] -Evaluation {
        if ($null -ne $activation -and $activation.valueState -eq 'ObservedValue') {
            [pscustomobject]@{outcome=if([string]$activation.value -eq 'Activated'){
                'ExpectedCondition'
            }else{'NeedsAttention'}}
        }
        else { [pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.ACTIVATION_EVIDENCE_INCOMPLETE'} }
    }
    Set-DeviceContextFindingResult -Finding $activationFinding -Result $activationResult

    $batteryPresence = $byField['field:device.battery.presence']
    $powerResult = Invoke-DeviceContextRuleEvaluation `
        -Rule $rulesByKind['power-context'] -Evaluation {
        if ($null -ne $batteryPresence -and $batteryPresence.valueState -eq 'ObservedValue') {
            [pscustomobject]@{outcome='Informational'}
        }
        else { [pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.POWER_EVIDENCE_INCOMPLETE'} }
    }
    Set-DeviceContextFindingResult -Finding $powerFinding -Result $powerResult
    $ValidatedRecord
}

function New-BoundedDiscoveryGuidanceHtml {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Tasks,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Definitions,
        [Parameter(Mandatory)] [string] $EmptyMessage
    )
    if($Tasks.Count -eq 0){return '<p>'+[Net.WebUtility]::HtmlEncode($EmptyMessage)+'</p>'}
    $byId=@{};foreach($definition in $Definitions){$byId[[string]$definition.definitionId]=$definition}
    $items=@($Tasks|ForEach-Object{
        $definition=$byId[[string]$_.definitionId]
        if($null -eq $definition){throw 'A discovery task does not resolve to its frozen definition.'}
        '<li><strong>Purpose:</strong> '+[Net.WebUtility]::HtmlEncode([string]$definition.purpose)+
        '<br><strong>Owner:</strong> '+[Net.WebUtility]::HtmlEncode([string]$definition.requiredRole)+
        '<br><strong>Approved destination:</strong> '+[Net.WebUtility]::HtmlEncode([string]$definition.approvedDestination)+
        '<br><strong>Expected safe result:</strong> '+[Net.WebUtility]::HtmlEncode([string]$definition.expectedSafeResult)+'</li>'
    })
    '<h3>Safe follow-up</h3><ul>'+($items -join '')+'</ul>'
}

function New-DeviceReadinessReportBytes {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter()] $FirmwarePolicy,
        [Parameter()] $IdentityEnrollmentPolicy,
        [Parameter()] $AdministratorExposurePolicy,
        [Parameter()] $EffectivePolicyPolicy,
        [Parameter()] $ResourceDependenciesPolicy
    )

    $finding = @($Record.findings | Where-Object findingId -like 'finding:device-readiness:*')[0]
    $activationFinding = @($Record.findings | Where-Object {
        $_.findingId -like 'finding:activation-context:*'
    })[0]
    $platformFinding = @($Record.findings | Where-Object {
        $_.findingId -like 'finding:platform-context:*'
    })[0]
    $powerFinding = @($Record.findings | Where-Object {
        $_.findingId -like 'finding:power-context:*'
    })[0]
    $firmwareFinding = $Record.findings | Where-Object {
        $_.findingId -like 'finding:firmware-context:*'
    } | Select-Object -First 1
    $secureBootFinding = $Record.findings | Where-Object {
        $_.findingId -like 'finding:secure-boot-readiness:*'
    } | Select-Object -First 1
    $tpmFinding = $Record.findings | Where-Object {
        $_.findingId -like 'finding:tpm-readiness:*'
    } | Select-Object -First 1
    $coverage = @($Record.coverage)[0]
    $values = @{}
    foreach ($fieldId in @(
        'field:device.manufacturer', 'field:device.model', 'field:device.processor.name',
        'field:device.memory.physical-bytes', 'field:device.windows.edition',
        'field:device.windows.build', 'field:device.architecture',
        'field:device.windows.activation-state', 'field:device.system-type-code',
        'field:device.hypervisor-present', 'field:device.chassis.type-codes',
        'field:device.virtualization.detected', 'field:device.form-factor',
        'field:device.battery.presence', 'field:device.battery.status',
        'field:device.battery.charge-percent',
        'field:device.battery.estimated-runtime-minutes'
    )) { $values[$fieldId] = 'Not available' }
    foreach ($observation in @($Record.observations)) {
        $values[[string]$observation.fieldId] = if ($observation.valueState -eq 'ObservedValue') {
            [System.Net.WebUtility]::HtmlEncode([string]$observation.value)
        } else { 'Not available' }
    }
    $summary = switch ([string]$finding.outcome) {
        'ExpectedCondition' { 'The available device facts meet this preview readiness check.' }
        'NeedsAttention' { 'One or more available device facts need attention.' }
        default { 'There is not enough evidence to make a readiness claim.' }
    }
    $activation = $values['field:device.windows.activation-state']
    $virtualization = $values['field:device.virtualization.detected']
    $formFactor = $values['field:device.form-factor']
    $batteryPresence = $values['field:device.battery.presence']
    $accessDiagnostics = @($Record.diagnostics | Where-Object {
        $_.reasonCode -match '^COLLECTION\.(ACTIVATION|CHASSIS|BATTERY)_(ACCESS_DENIED|SOURCE_UNAVAILABLE)$'
    } |
        ForEach-Object { [string]$_.reasonCode } | Sort-Object)
    $accessSummary = if ($accessDiagnostics.Count -eq 0) {
        'No source-specific access limitation was recorded.'
    }
    else {
        'Source limitations: ' + [System.Net.WebUtility]::HtmlEncode(($accessDiagnostics -join ', ')) + '.'
    }
    $virtualLimitation = if ($virtualization -eq 'True') {
        'Windows evidence identifies this as virtual. Guest-visible battery and hardware values cannot support physical battery, firmware, TPM-attestation, OEM, or performance claims.'
    }
    else {
        'No virtual signal was detected by this bounded rule. That does not prove the device is physical or establish firmware, TPM-attestation, OEM, or performance facts.'
    }
    $firmwareSection = if ($null -ne $firmwareFinding) {
        $firmwareCoverage = @($Record.coverage | Where-Object {
            $_.scopeId -eq 'scope:device.firmware-context'
        })[0]
        $secureBootCoverage = @($Record.coverage | Where-Object {
            $_.scopeId -eq 'scope:device.secure-boot'
        })[0]
        $tpmCoverage = @($Record.coverage | Where-Object {
            $_.scopeId -eq 'scope:device.tpm-readiness'
        })[0]
        $firmwareDefinitionIds=@($FirmwarePolicy.discoveryTasks.definitionId)
        $discoveryTasks = @($Record.recommendations | Where-Object {
            $_.kind -eq 'TenantSideDiscoveryTask' -and $_.definitionId -in $firmwareDefinitionIds
        })
        $discoveryCount = $discoveryTasks.Count
        $discoveryGuidance = if ($discoveryCount -eq 0) {
            '<p>No external firmware or physical-attestation follow-up is required by these rules.</p>'
        }
        else {
            if ($null -eq $FirmwarePolicy) {
                throw 'Firmware discovery guidance requires its frozen policy definitions.'
            }
            New-BoundedDiscoveryGuidanceHtml -Tasks $discoveryTasks `
                -Definitions @($FirmwarePolicy.discoveryTasks) `
                -EmptyMessage 'No external firmware follow-up is required.'
        }
        @"
<h2>Firmware, Secure Boot, and TPM readiness</h2>
<p>These are bounded, read-only Windows observations. Disabled is different from absent; unsupported, denied, malformed, timed-out, and failed sources remain explicit coverage gaps.</p>
<dl><dt>Firmware coverage</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$firmwareCoverage.state))</dd>
<dt>Firmware interface</dt><dd>$($values['field:device.firmware.type'])</dd>
<dt>BIOS/firmware version</dt><dd>$($values['field:device.firmware.bios-version'])</dd>
<dt>SMBIOS version</dt><dd>$($values['field:device.firmware.smbios-version'])</dd>
<dt>Firmware finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$firmwareFinding.outcome))</dd>
<dt>Secure Boot coverage</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$secureBootCoverage.state))</dd>
<dt>Secure Boot enabled</dt><dd>$($values['field:device.secure-boot.enabled'])</dd>
<dt>Secure Boot finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$secureBootFinding.outcome))</dd>
<dt>TPM coverage</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$tpmCoverage.state))</dd>
<dt>TPM present</dt><dd>$($values['field:device.tpm.present'])</dd>
<dt>TPM enabled</dt><dd>$($values['field:device.tpm.enabled'])</dd>
<dt>TPM activated</dt><dd>$($values['field:device.tpm.activated'])</dd>
<dt>TPM specification</dt><dd>$($values['field:device.tpm.specification'])</dd>
<dt>TPM finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$tpmFinding.outcome))</dd></dl>
<p>A virtual machine can expose a vTPM and guest-visible Secure Boot. Those signals cannot establish physical TPM attestation, the host's hardware state, or universal OEM behavior. WIN-PCInfo creates a Tenant-side Discovery Task when that context needs authorized follow-up. Discovery tasks in this result: $discoveryCount.</p>
$discoveryGuidance
<p>No owner authorization, endorsement secret, key, recovery data, TPM provisioning action, Secure Boot variable write, or firmware change is requested or retained.</p>
"@
    } else { '' }
    $identityFinding=$Record.findings|Where-Object {
        $_.findingId -like 'finding:assessment-user-context:*'
    }|Select-Object -First 1
    $identitySection=if($null -ne $identityFinding){
        if($null -eq $IdentityEnrollmentPolicy){
            throw 'Identity guidance requires its frozen policy definitions.'
        }
        $registrationFinding=$Record.findings|Where-Object {
            $_.findingId -like 'finding:device-registration-context:*'
        }|Select-Object -First 1
        $enrollmentFinding=$Record.findings|Where-Object {
            $_.findingId -like 'finding:work-school-enrollment-context:*'
        }|Select-Object -First 1
        $identityDefinitionIds=@($IdentityEnrollmentPolicy.discoveryTasks.definitionId)
        $identityTasks=@($Record.recommendations|Where-Object {
            $_.kind -eq 'TenantSideDiscoveryTask' -and $_.definitionId -in $identityDefinitionIds
        })
        $identityGuidance=New-BoundedDiscoveryGuidanceHtml -Tasks $identityTasks `
            -Definitions @($IdentityEnrollmentPolicy.discoveryTasks) `
            -EmptyMessage 'No tenant-side identity follow-up is required by these local rules.'
        $userCoverage=@($Record.coverage|Where-Object scopeId -eq 'scope:identity.assessment-user-context')[0]
        $registrationCoverage=@($Record.coverage|Where-Object scopeId -eq 'scope:device.registration-context')[0]
        $workSchoolCoverage=@($Record.coverage|Where-Object scopeId -eq 'scope:device.work-school-registration-context')[0]
        $systemCoverage=@($Record.coverage|Where-Object scopeId -eq 'scope:device.mdm-policy.system')[0]
@"
<h2>Registration, join, and enrollment context</h2>
<p>WIN-PCInfo verifies the Assessment User Context separately from the process, initiating operator, alternate administrator, privileged worker, and SYSTEM. Missing user context is a coverage gap and is never replaced with one of those identities.</p>
<dl><dt>Assessment User Context coverage</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$userCoverage.state))</dd>
<dt>Assessment User Context finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$identityFinding.outcome))</dd>
<dt>Verified local account</dt><dd>$($values['field:identity.assessment-user.account-name'])</dd>
<dt>Domain join coverage</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$registrationCoverage.state))</dd>
<dt>Domain join state</dt><dd>$($values['field:device.domain-join.state'])</dd>
<dt>Domain name</dt><dd>$($values['field:device.domain-join.name'])</dd>
<dt>Microsoft Entra registration type</dt><dd>$($values['field:device.entra-registration.type'])</dd>
<dt>Registration finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$registrationFinding.outcome))</dd>
<dt>Work-or-school coverage</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$workSchoolCoverage.state))</dd>
<dt>Device-default work-or-school registration observed</dt><dd>$($values['field:device.work-school-registration.present'])</dd>
<dt>SYSTEM MDM-source coverage</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$systemCoverage.state))</dd>
<dt>Enrollment-context finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$enrollmentFinding.outcome))</dd></dl>
<p>These locale-neutral local sources cannot establish tenant assignment, compliance, licensing, or organizational intent. They do not authenticate to Microsoft Entra or Intune and do not join, register, enroll, disconnect, or modify an account.</p>
$identityGuidance
"@
    }else{''}
    $administratorFinding=$Record.findings|Where-Object {
        $_.findingId -like 'finding:local-administrator-exposure:*'
    }|Select-Object -First 1
    $administratorSection=if($null -ne $administratorFinding){
        if($null -eq $AdministratorExposurePolicy){
            throw 'Administrator guidance requires its frozen policy definition.'
        }
        $administratorCoverage=@($Record.coverage|Where-Object {
            $_.scopeId -eq 'scope:device.local-administrators.direct-membership'
        })[0]
        $principalSubjects=@($Record.subjects|Where-Object kind -eq 'SecurityPrincipal')
        $principalRows=@($principalSubjects|ForEach-Object {
            $memberSubjectId=[string]$_.subjectId;$memberValues=@{}
            foreach($item in @($Record.observations|Where-Object subjectId -eq $memberSubjectId)){
                $memberValues[[string]$item.fieldId]=if($item.valueState -eq 'ObservedValue'){
                    [Net.WebUtility]::HtmlEncode([string]$item.value)
                }else{'Not resolved'}
            }
            '<li><strong>SID:</strong> '+$memberValues['field:principal.windows.sid']+
                '<br><strong>Account label:</strong> '+$memberValues['field:principal.windows.account-name']+
                '<br><strong>Kind:</strong> '+$memberValues['field:principal.windows.kind']+
                '<br><strong>Origin:</strong> '+$memberValues['field:principal.windows.origin']+'</li>'
        })
@"
<h2>Local administrator exposure</h2>
<p>Coverage: $([Net.WebUtility]::HtmlEncode([string]$administratorCoverage.state)). Finding: $([Net.WebUtility]::HtmlEncode([string]$administratorFinding.outcome)). Direct members observed: $($principalSubjects.Count).</p>
<p>The built-in Administrators group is selected by its stable SID, not an English display name. Only direct members are reported. A group listed below may contain additional effective administrators, but WIN-PCInfo does not recursively expand or guess those identities.</p>
<ul>$($principalRows -join '')</ul>
<p>Membership alone does not prove compromise or that an account is unexpected. Confirm the organization's approved administrator-account context with the responsible device owner. WIN-PCInfo does not remove accounts, change group membership, collect credentials, or expose these Restricted identifiers outside the protected package.</p>
"@
    }else{''}
    $policyFinding=$Record.findings|Where-Object {
        $_.ruleId -eq 'rule:policy.applied-policy-coverage/1.0.0'
    }|Select-Object -First 1
    $effectivePolicySection=if($null -ne $policyFinding){
        if($null -eq $EffectivePolicyPolicy){throw 'Effective Policy guidance requires its frozen policy definition.'}
        $localFinding=@($Record.findings|Where-Object ruleId -eq 'rule:policy.local-security-policy-coverage/1.0.0')[0]
        $orderFinding=@($Record.findings|Where-Object ruleId -eq 'rule:policy.applied-order-conflict/1.0.0')[0]
        $layerById=@{};foreach($layer in $EffectivePolicyPolicy.layers){$layerById[[string]$layer.layerId]=$layer}
        $policySubjects=@($Record.subjects|Where-Object kind -eq 'PolicyObject')
        $policyRows=@($policySubjects|ForEach-Object {
            $subjectId=[string]$_.subjectId;$items=@($Record.observations|Where-Object subjectId -eq $subjectId)
            $byField=@{};foreach($item in $items){if($item.valueState -eq 'ObservedValue'){$byField[[string]$item.fieldId]=[Net.WebUtility]::HtmlEncode([string]$item.value)}}
            $settingIds=@($items|Where-Object {$_.fieldId -eq 'field:policy.applied.setting-id' -and $_.valueState -eq 'ObservedValue'}|ForEach-Object {[Net.WebUtility]::HtmlEncode([string]$_.value)})
            $precedence=@($items|Where-Object {$_.fieldId -eq 'field:policy.applied.precedence' -and $_.valueState -eq 'ObservedValue'}|ForEach-Object {[Net.WebUtility]::HtmlEncode([string]$_.value)})
            $settingRows=@(for($index=0;$index -lt $settingIds.Count;$index++){
                $rank=if($index -lt $precedence.Count){$precedence[$index]}else{'Not available'}
                '<br><strong>Setting / precedence:</strong> '+$settingIds[$index]+' / '+$rank
            })
            '<li><strong>Object:</strong> '+$byField['field:policy.applied.object-id']+
                '<br><strong>Target / origin:</strong> '+$byField['field:policy.applied.target']+' / '+$byField['field:policy.applied.origin']+
                '<br><strong>Applicable:</strong> '+$byField['field:policy.applied.applicable']+
                '<br><strong>Link:</strong> '+$byField['field:policy.applied.link-id']+
                ($settingRows -join '')+'</li>'
        })
        $devicePolicyObservations=@($Record.observations|Where-Object subjectId -eq 'subject:device:primary')
        $auditIds=@($devicePolicyObservations|Where-Object fieldId -eq 'field:policy.audit.subcategory-id')
        $auditSuccess=@($devicePolicyObservations|Where-Object fieldId -eq 'field:policy.audit.success-enabled')
        $auditFailure=@($devicePolicyObservations|Where-Object fieldId -eq 'field:policy.audit.failure-enabled')
        $auditRows=@(for($index=0;$index -lt $auditIds.Count;$index++){
            $success=if($index -lt $auditSuccess.Count){[Net.WebUtility]::HtmlEncode([string]$auditSuccess[$index].value)}else{'Not available'}
            $failure=if($index -lt $auditFailure.Count){[Net.WebUtility]::HtmlEncode([string]$auditFailure[$index].value)}else{'Not available'}
            '<li>'+[Net.WebUtility]::HtmlEncode([string]$auditIds[$index].value)+': success='+$success+', failure='+$failure+'</li>'
        })
        $rightRows=@($Record.subjects|Where-Object {$_.subjectId -like 'subject:policy-principal:*'}|ForEach-Object {
            $subjectId=[string]$_.subjectId;$items=@($Record.observations|Where-Object subjectId -eq $subjectId)
            $right=@($items|Where-Object fieldId -eq 'field:policy.user-right.catalog-id')[0]
            $sid=@($items|Where-Object fieldId -eq 'field:policy.user-right.direct-principal-sid')[0]
            '<li>'+[Net.WebUtility]::HtmlEncode([string]$right.value)+': '+[Net.WebUtility]::HtmlEncode([string]$sid.value)+' (direct assignment)</li>'
        })
@"
<h2>Applied Group Policy and local security policy</h2>
<p>This section keeps three different questions separate: cached Applied Policy Evidence, configured registry Policy Signals, and Current Control State. A configured value does not prove which authority set it or that the related control is currently enforced.</p>
<dl><dt>Applied Policy Evidence coverage</dt><dd>$([Net.WebUtility]::HtmlEncode((Get-EffectivePolicyLayerState -ScopeStates $Record.coverage -ScopeIds @($layerById.AppliedPolicyEvidence.scopeIds))))</dd>
<dt>Configured Policy Signals coverage</dt><dd>$([Net.WebUtility]::HtmlEncode((Get-EffectivePolicyLayerState -ScopeStates $Record.coverage -ScopeIds @($layerById.ConfiguredPolicySignals.scopeIds))))</dd>
<dt>Current Control State coverage</dt><dd>$([Net.WebUtility]::HtmlEncode((Get-EffectivePolicyLayerState -ScopeStates $Record.coverage -ScopeIds @($layerById.CurrentControlState.scopeIds))))</dd>
<dt>Applied-policy finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$policyFinding.outcome))</dd>
<dt>Local-security finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$localFinding.outcome))</dd>
<dt>Applied-order conflict finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$orderFinding.outcome))</dd></dl>
<h3>Cached applied policy objects</h3><ul>$($policyRows -join '')</ul>
<h3>Current local account and lockout state</h3>
<dl><dt>Minimum authenticator length</dt><dd>$($values['field:policy.local-sam.minimum-authenticator-length'])</dd>
<dt>Maximum authenticator age (seconds)</dt><dd>$($values['field:policy.local-sam.maximum-authenticator-age-seconds'])</dd>
<dt>Minimum authenticator age (seconds)</dt><dd>$($values['field:policy.local-sam.minimum-authenticator-age-seconds'])</dd>
<dt>Authenticator history length</dt><dd>$($values['field:policy.local-sam.authenticator-history-length'])</dd>
<dt>Lockout threshold</dt><dd>$($values['field:policy.local-sam.lockout-threshold'])</dd>
<dt>Lockout duration / observation window (seconds)</dt><dd>$($values['field:policy.local-sam.lockout-duration-seconds']) / $($values['field:policy.local-sam.lockout-window-seconds'])</dd></dl>
<h3>Current audit subcategories</h3><ul>$($auditRows -join '')</ul>
<h3>Direct user-right assignments</h3><ul>$($rightRows -join '')</ul>
<h3>Configured registry signals</h3>
<dl><dt>Machine inactivity limit (seconds)</dt><dd>$($values['field:policy.security-option.machine-inactivity-limit-seconds'])</dd>
<dt>Disable Ctrl+Alt+Del signal</dt><dd>$($values['field:policy.security-option.disable-cad'])</dd>
<dt>LAN Manager compatibility signal</dt><dd>$($values['field:policy.security-option.lm-compatibility-level'])</dd></dl>
<p>RSoP is read only and uses cached locale-neutral classes; WIN-PCInfo does not refresh policy or parse a localized report. Local SAM values apply only to local accounts. User-right entries are direct SID assignments only and do not expand nested groups. Missing, denied, stale, unsupported, malformed, or incomplete sources remain explicit gaps.</p>
"@
    }else{''}
    $resourceFinding=$Record.findings|Where-Object {
        $_.ruleId -eq 'rule:resource.user-migration-dependencies/1.0.0'
    }|Select-Object -First 1
    $resourceSection=if($null -ne $resourceFinding){
        if($null -eq $ResourceDependenciesPolicy){
            throw 'Resource Dependency guidance requires its frozen policy definition.'
        }
        $peripheralRuleFinding=@($Record.findings|Where-Object ruleId -eq 'rule:resource.peripheral-migration-dependencies/1.0.0')[0]
        $userCoverage=Get-ResourceDependencyLayerState -ScopeStates $Record.coverage -ScopeIds @($ResourceDependenciesPolicy.layers[0].scopeIds)
        $deviceCoverage=Get-ResourceDependencyLayerState -ScopeStates $Record.coverage -ScopeIds @($ResourceDependenciesPolicy.layers[1].scopeIds)
        $resourceSubjects=@($Record.subjects|Where-Object {$_.subjectId -like 'subject:mapped-drive:*' -or $_.subjectId -like 'subject:unc-resource:*' -or $_.subjectId -like 'subject:printer:*' -or $_.subjectId -like 'subject:printer-driver:*' -or $_.subjectId -like 'subject:peripheral:*'})
        $rows=@($resourceSubjects|ForEach-Object {
            $subjectId=[string]$_.subjectId;$items=@($Record.observations|Where-Object subjectId -eq $subjectId)
            $lines=@($items|Where-Object valueState -eq ObservedValue|ForEach-Object {
                '<strong>'+[Net.WebUtility]::HtmlEncode([string]$_.fieldId)+':</strong> '+
                    [Net.WebUtility]::HtmlEncode([string]$_.value)
            })
            '<li>'+($lines -join '<br>')+'</li>'
        })
        $guidance=@($Record.recommendations|Where-Object {
            $_.definitionId -in @($ResourceDependenciesPolicy.recommendations.definitionId)
        }|ForEach-Object {
            $definitionId=[string]$_.definitionId
            $definition=@($ResourceDependenciesPolicy.recommendations|Where-Object definitionId -eq $definitionId)[0]
            '<li><strong>'+[Net.WebUtility]::HtmlEncode([string]$definition.purpose)+'</strong><br>'+[Net.WebUtility]::HtmlEncode([string]$definition.verification)+'<br><strong>Caution:</strong> '+[Net.WebUtility]::HtmlEncode([string]$definition.caution)+'</li>'
        })
@"
<h2>User resources and peripheral migration dependencies</h2>
<p>User-resource coverage: $([Net.WebUtility]::HtmlEncode($userCoverage)). Peripheral coverage: $([Net.WebUtility]::HtmlEncode($deviceCoverage)). User finding: $([Net.WebUtility]::HtmlEncode([string]$resourceFinding.outcome)). Peripheral finding: $([Net.WebUtility]::HtmlEncode([string]$peripheralRuleFinding.outcome)).</p>
<p>These are bounded advisory dependencies from the verified Assessment User Context. WIN-PCInfo does not connect a resource, enumerate share contents, documents, print jobs, credentials, or Wi-Fi keys, print, install or update a driver, or collect PnP identifiers and unrelated serial numbers.</p>
<ul>$($rows -join '')</ul>
<h3>Migration next steps</h3><ul>$($guidance -join '')</ul>
<p>Observed local drivers and devices do not promise universal peripheral compatibility. Confirm each retained dependency against the target Windows, management, network, and vendor-support design before migration.</p>
"@
    }else{''}
    $html = @"
<!doctype html><html lang="en"><meta charset="utf-8"><title>WIN-PCInfo device readiness</title>
<h1>Device, Windows, activation, and power context</h1><p>$summary</p>
<p>This is advisory information, not a compliance result or a guarantee that every application or future update will work.</p>
<dl><dt>Coverage</dt><dd>$([System.Net.WebUtility]::HtmlEncode([string]$coverage.state))</dd>
<dt>Windows edition</dt><dd>$($values['field:device.windows.edition'])</dd>
<dt>Windows build</dt><dd>$($values['field:device.windows.build'])</dd>
<dt>Architecture</dt><dd>$($values['field:device.architecture'])</dd></dl>
<h2>Activation context</h2><p>Windows-reported state: $activation.</p>
<p>Advisory finding: $([System.Net.WebUtility]::HtmlEncode([string]$activationFinding.outcome)).</p>
<p>This point-in-time status contains no product key and cannot establish legal entitlement, license ownership, purchasing need, or purchasing guidance.</p>
<h2>Form and virtualization context</h2><dl><dt>Form</dt><dd>$formFactor</dd>
<dt>Virtualization detected</dt><dd>$virtualization</dd></dl>
<p>Advisory finding: $([System.Net.WebUtility]::HtmlEncode([string]$platformFinding.outcome)). $virtualLimitation</p>
<h2>Bounded battery and power context</h2><dl><dt>Guest-visible battery</dt><dd>$batteryPresence</dd>
<dt>Status</dt><dd>$($values['field:device.battery.status'])</dd>
<dt>Charge percent</dt><dd>$($values['field:device.battery.charge-percent'])</dd>
<dt>Estimated runtime minutes</dt><dd>$($values['field:device.battery.estimated-runtime-minutes'])</dd></dl>
<p>Advisory finding: $([System.Net.WebUtility]::HtmlEncode([string]$powerFinding.outcome)).</p>
<p>These are bounded Windows observations, not a battery-health, calibration, capacity, or performance test. WIN-PCInfo does not change the active power plan.</p>
$firmwareSection
$identitySection
$administratorSection
$effectivePolicySection
$resourceSection
<h2>Evidence limitations</h2><p>$accessSummary</p>
<details><summary>Device details and where they came from</summary>
<p>These identifying values are Restricted Diagnostic Evidence and stay inside this protected package.</p>
<dl><dt>Manufacturer</dt><dd>$($values['field:device.manufacturer'])</dd>
<dt>Model</dt><dd>$($values['field:device.model'])</dd>
<dt>Processor</dt><dd>$($values['field:device.processor.name'])</dd>
<dt>Physical memory (bytes)</dt><dd>$($values['field:device.memory.physical-bytes'])</dd>
<dt>Windows system type code</dt><dd>$($values['field:device.system-type-code'])</dd>
<dt>Chassis type codes</dt><dd>$($values['field:device.chassis.type-codes'])</dd></dl>
<p>Provenance: explicit Windows property projections normalized by WIN-PCInfo; see assessment-record.json for canonical typed evidence.</p>
</details></html>
"@
    [System.Text.UTF8Encoding]::new($false).GetBytes($html.Replace("`r`n", "`n"))
}

function Write-DeviceReadinessTerminal {
    param(
        [Parameter(Mandatory)] [string] $Outcome,
        [Parameter(Mandatory)] [int] $ExitCode,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [bool] $CollectionStarted,
        [Parameter(Mandatory)] [bool] $ValidationFixture,
        [Parameter(Mandatory)] [bool] $CleanupVerified,
        [Parameter(Mandatory)] [string] $RequestDigest,
        [Parameter(Mandatory)] [string] $PlanDigest,
        [Parameter(Mandatory)] $ConvertToJsonCommand
    )
    Write-ContractRecord ([pscustomobject][ordered]@{
        recordType='win-pcinfo.terminal'; contractVersion='1.0.0'; outcome=$Outcome
        exitCode=$ExitCode; reasonCode=$ReasonCode; phase='DeviceReadiness'
        collectionStarted=$CollectionStarted; requestDigest=$RequestDigest
        planDigest=$PlanDigest; preparationDecision='Accepted'
        validationFixture=$ValidationFixture
        cleanup=[pscustomobject][ordered]@{required=$true;verified=$CleanupVerified}
    }) -ConvertToJsonCommand $ConvertToJsonCommand
}

function Get-DeviceReadinessNoPayloadDisposition {
    param(
        [Parameter(Mandatory)] $Supervision,
        [Parameter(Mandatory)] [bool] $ValidationFixture,
        [Parameter()] [string] $Scenario = ''
    )

    # Malformed and over-limit fixtures are approved evidence-attempt seams.
    # Every other missing payload is a lifecycle failure, not evidence that may
    # be repackaged as a successful run with gaps.
    $recognizedAttemptFailure = [bool]$Supervision.processStarted -and (
        ($Scenario -eq 'Malformed' -and [string]$Supervision.reasonCode -eq
            'PROCESS.PAYLOAD_MALFORMED') -or
        ($Scenario -eq 'Oversize' -and [string]$Supervision.reasonCode -eq
            'PROCESS.OUTPUT_LIMIT_EXCEEDED') -or
        ($Scenario -eq 'ProhibitedMaterial' -and [string]$Supervision.reasonCode -eq
            'PROCESS.PROHIBITED_MATERIAL_BLOCKED')
    )
    if ($ValidationFixture -and $recognizedAttemptFailure) {
        return [pscustomobject][ordered]@{
            buildCanonicalRecord = $true
            coverageState = if ($Scenario -eq 'Malformed') { 'Malformed' }
                elseif ($Scenario -eq 'ProhibitedMaterial') { 'ProhibitedMaterialBlocked' }
                else { 'Unavailable' }
            coverageReasonCode = if ($Scenario -eq 'Malformed') {
                'COLLECTION.PAYLOAD_MALFORMED'
            }
            elseif ($Scenario -eq 'ProhibitedMaterial') {
                'COLLECTION.PROHIBITED_MATERIAL_BLOCKED'
            }
            else { 'COLLECTION.OUTPUT_LIMIT_EXCEEDED' }
            outcome = 'CompletedWithGaps'; exitCode = 10
            reasonCode = 'DEVICE_READINESS.COMPLETED_WITH_GAPS'
        }
    }

    $reason = [string]$Supervision.reasonCode
    if (-not [bool]$Supervision.processStarted) {
        $outcome = 'NotStarted'; $exitCode = 20; $terminalReason = 'DEVICE_READINESS.NOT_STARTED'
    }
    elseif ($reason -eq 'PROCESS.DEADLINE_EXCEEDED') {
        $outcome = 'TimedOut'; $exitCode = 40; $terminalReason = 'DEVICE_READINESS.TIMED_OUT'
    }
    elseif ($reason -like 'PROCESS.CANCELLED_*') {
        $outcome = 'Cancelled'; $exitCode = 30; $terminalReason = 'DEVICE_READINESS.CANCELLED'
    }
    elseif ($reason -eq 'PROCESS.TERMINATION_INCOMPLETE') {
        $outcome = 'CleanupIncomplete'; $exitCode = 60
        $terminalReason = 'DEVICE_READINESS.COLLECTOR_CLEANUP_INCOMPLETE'
    }
    else {
        $outcome = 'IntegrityFailed'; $exitCode = 50
        $terminalReason = 'DEVICE_READINESS.COLLECTOR_FAILED'
    }
    [pscustomobject][ordered]@{
        buildCanonicalRecord = $false; coverageState = 'Unavailable'
        coverageReasonCode = ''; outcome = $outcome; exitCode = $exitCode
        reasonCode = $terminalReason
    }
}

function Get-DeviceReadinessPackageDisposition {
    param(
        [Parameter()] $Package,
        [Parameter(Mandatory)] [bool] $ValidationFixture,
        [Parameter(Mandatory)] [bool] $ValidationCleanupVerified,
        [Parameter(Mandatory)] [bool] $FinalVerificationSucceeded
    )

    $packageState = if ($null -ne $Package -and $Package.PSObject.Properties['state']) {
        [string]$Package.state
    }
    else { 'NotCreated' }
    $packageCreatedVerified = $null -ne $Package -and
        $Package.PSObject.Properties['verified'] -and [bool]$Package.verified
    $packagePath = if ($null -ne $Package -and $Package.PSObject.Properties['packagePath']) {
        [string]$Package.packagePath
    }
    else { '' }

    $cleanupUncertain = $packageState -eq 'CleanupIncomplete' -or
        ($ValidationFixture -and -not $ValidationCleanupVerified) -or
        ($FinalVerificationSucceeded -and -not $ValidationFixture -and
            ([string]::IsNullOrWhiteSpace($packagePath) -or
                -not [System.IO.File]::Exists($packagePath)))
    if ($cleanupUncertain) {
        return [pscustomobject][ordered]@{
            packageAvailability = 'Uncertain'; outcome = 'CleanupIncomplete'
            exitCode = 60; reasonCode = 'DEVICE_READINESS.PACKAGE_CLEANUP_INCOMPLETE'
        }
    }
    if ($FinalVerificationSucceeded) {
        return [pscustomobject][ordered]@{
            packageAvailability = if ($ValidationFixture) { 'VerifiedAbsent' } else { 'Available' }
            outcome = ''; exitCode = -1; reasonCode = ''
        }
    }
    if ($packageCreatedVerified) {
        return [pscustomobject][ordered]@{
            packageAvailability = 'Uncertain'; outcome = 'IntegrityFailed'
            exitCode = 50; reasonCode = 'DEVICE_READINESS.PACKAGE_INVALID'
        }
    }
    [pscustomobject][ordered]@{
        packageAvailability = 'VerifiedAbsent'; outcome = 'IntegrityFailed'
        exitCode = 50; reasonCode = 'DEVICE_READINESS.PACKAGE_INVALID'
    }
}

function Get-DeviceReadinessFailureDisposition {
    param(
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [bool] $CollectionStarted
    )

    switch ($ReasonCode) {
        'FIRMWARE.PRIVILEGE_TIMED_OUT' {
            [pscustomobject]@{outcome='TimedOut';exitCode=40;reasonCode=$ReasonCode;cleanupVerified=$true}
        }
        'FIRMWARE.PRIVILEGE_CANCELLED' {
            [pscustomobject]@{outcome='Cancelled';exitCode=30;reasonCode=$ReasonCode;cleanupVerified=$true}
        }
        'FIRMWARE.PRIVILEGE_CLEANUP_INCOMPLETE' {
            [pscustomobject]@{outcome='CleanupIncomplete';exitCode=60;reasonCode=$ReasonCode;cleanupVerified=$false}
        }
        'IDENTITY.SYSTEM_CLEANUP_INCOMPLETE' {
            [pscustomobject]@{outcome='CleanupIncomplete';exitCode=60;reasonCode=$ReasonCode;cleanupVerified=$false}
        }
        'IDENTITY.RULE_CLEANUP_INCOMPLETE' {
            [pscustomobject]@{outcome='CleanupIncomplete';exitCode=60;reasonCode=$ReasonCode;cleanupVerified=$false}
        }
        'IDENTITY.COLLECTOR_CLEANUP_INCOMPLETE' {
            [pscustomobject]@{outcome='CleanupIncomplete';exitCode=60;reasonCode=$ReasonCode;cleanupVerified=$false}
        }
        'RESOURCE.COLLECTOR_CLEANUP_INCOMPLETE' {
            [pscustomobject]@{outcome='CleanupIncomplete';exitCode=60;reasonCode=$ReasonCode;cleanupVerified=$false}
        }
        default {
            [pscustomobject]@{
                outcome=if($CollectionStarted){'IntegrityFailed'}else{'NotStarted'}
                exitCode=if($CollectionStarted){50}else{20};reasonCode=$ReasonCode;cleanupVerified=$true
            }
        }
    }
}

function Invoke-DeviceReadinessSlice {
    param(
        [Parameter()] [string] $LiteralPath,
        [Parameter()] [string] $IdentityEnrollmentLiteralPath,
        [Parameter()] [string] $AdministratorExposureLiteralPath,
        [Parameter()] [string] $EffectivePolicyLiteralPath,
        [Parameter()] [string] $ResourceDependenciesLiteralPath,
        [Parameter(Mandatory)] $PreparationPlan,
        [Parameter(Mandatory)] [string] $ApprovedOutputDestination,
        [Parameter()] $ApprovedRecipient,
        [Parameter(Mandatory)] [string] $RequestDigest,
        [Parameter(Mandatory)] [string] $PlanDigest,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand,
        [Parameter(Mandatory)] $TestJsonCommand
    )

    $isDeviceFixture = -not [string]::IsNullOrWhiteSpace($LiteralPath)
    $isIdentityFixture = -not [string]::IsNullOrWhiteSpace($IdentityEnrollmentLiteralPath)
    $isAdministratorFixture = -not [string]::IsNullOrWhiteSpace($AdministratorExposureLiteralPath)
    $isEffectivePolicyFixture = -not [string]::IsNullOrWhiteSpace($EffectivePolicyLiteralPath)
    $isResourceDependenciesFixture = -not [string]::IsNullOrWhiteSpace($ResourceDependenciesLiteralPath)
    $isFixture = $isDeviceFixture -or $isIdentityFixture -or $isAdministratorFixture -or
        $isEffectivePolicyFixture -or $isResourceDependenciesFixture
    $scenario = if ($isFixture) { '' } else { 'Actual' }
    $firmwareScenario = if ($isFixture) { 'None' } else { 'Live' }
    $privilegeScenario = if ($isFixture) { 'None' } else { 'Live' }
    $policy = $null; $firmwarePolicy = $null; $identityPolicy = $null
    $administratorPolicy=$null;$administratorCollector=$null
    $effectivePolicy=$null;$effectivePolicyCollector=$null
    $resourcePolicy=$null;$resourceCollector=$null
    $privilegeResult = $null; $identityCollector = $null; $systemResult = $null
    $firmwareCollector = $null; $boundary = $null; $opened = $null; $package = $null
    $cleanupVerified = $true; $recordAccepted = $false; $reportVerified = $false
    $packageVerified = $false; $coverageState = 'Unavailable'; $findingOutcome = 'Indeterminate'
    $activationFindingOutcome = 'Indeterminate'; $platformFindingOutcome = 'Indeterminate'
    $powerFindingOutcome = 'Indeterminate'; $sourceAccessDiagnostics = ''
    $activationContext = 'Unknown'; $virtualizationContext = 'Unknown'
    $formFactor = 'Unknown'; $batteryPresence = 'Unknown'
    $recipientKeyProtection = 'None'
    $privilegeState = 'NotAttempted'; $privilegeUacInteractionCount = 0
    $firmwareCoverageState = 'NotAttempted'; $secureBootCoverageState = 'NotAttempted'
    $tpmCoverageState = 'NotAttempted'; $firmwareFindingOutcome = 'Indeterminate'
    $secureBootFindingOutcome = 'Indeterminate'; $tpmFindingOutcome = 'Indeterminate'
    $tenantDiscoveryTaskCount = 0
    $identityScenario = if($isIdentityFixture){''}else{'Live'}
    $processRelationship='Unavailable';$assessmentUserCoverageState='NotAttempted'
    $registrationCoverageState='NotAttempted';$workSchoolCoverageState='NotAttempted'
    $systemEnrollmentCoverageState='NotAttempted';$assessmentUserFindingOutcome='Indeterminate'
    $administratorScenario=if($isAdministratorFixture){''}else{'Live'}
    $administratorCoverageState='NotAttempted';$administratorFindingOutcome='Indeterminate'
    $administratorDirectMemberCount=0;$administratorDirectGroupCount=0
    $administratorUnresolvedCount=0;$administratorDuplicateCount=0
    $administratorEnumerationComplete=$false;$administratorProcessRelationship='NotStarted'
    $effectivePolicyScenario=if($isEffectivePolicyFixture){''}else{'Live'}
    $appliedPolicyCoverage='NotAttempted';$configuredPolicyCoverage='NotAttempted'
    $currentControlCoverage='NotAttempted';$appliedPolicyCount=0
    $appliedPolicyFinding='Indeterminate';$localSecurityFinding='Indeterminate'
    $appliedOrderFinding='Indeterminate'
    $resourceScenario=if($isResourceDependenciesFixture){''}else{'Live'}
    $userResourceCoverage='NotAttempted';$peripheralCoverage='NotAttempted'
    $mappedDriveCount=0;$uncConnectionCount=0;$printerCount=0
    $printerDriverCount=0;$peripheralCount=0
    $userResourceFinding='Indeterminate';$peripheralFinding='Indeterminate'
    $collectionStarted = $false
    $sliceStage='POLICY'
    $outcome = 'CompletedWithGaps'; $exitCode = 10; $reasonCode = 'DEVICE_READINESS.EVIDENCE_UNAVAILABLE'
    try {
        $policy = Get-DeviceReadinessPolicy -ConvertFromJsonCommand $ConvertFromJsonCommand
        $firmwarePolicy = Get-FirmwareReadinessPolicy `
            -ConvertFromJsonCommand $ConvertFromJsonCommand
        $identityPolicy = Get-IdentityEnrollmentPolicy `
            -ConvertFromJsonCommand $ConvertFromJsonCommand
        $administratorPolicy=Get-AdministratorExposurePolicy `
            -ConvertFromJsonCommand $ConvertFromJsonCommand
        $effectivePolicy=Get-EffectivePolicyPolicy `
            -ConvertFromJsonCommand $ConvertFromJsonCommand
        $resourcePolicy=Get-ResourceDependenciesPolicy `
            -ConvertFromJsonCommand $ConvertFromJsonCommand
        $sliceStage='FIXTURE'
        if ($isDeviceFixture) {
            $fixtureSelection = Read-DeviceReadinessFixture -LiteralPath $LiteralPath `
                -ConvertFromJsonCommand $ConvertFromJsonCommand -Policy $policy `
                -FirmwarePolicy $firmwarePolicy
            $scenario = [string]$fixtureSelection.DeviceScenario
            $firmwareScenario = [string]$fixtureSelection.FirmwareScenario
            $privilegeScenario = [string]$fixtureSelection.PrivilegeScenario
        }
        elseif($isIdentityFixture){
            $scenario='Complete';$firmwareScenario='Supported';$privilegeScenario='AcceptedElevation'
            $identityScenario=Read-IdentityEnrollmentFixture `
                -LiteralPath $IdentityEnrollmentLiteralPath `
                -ConvertFromJsonCommand $ConvertFromJsonCommand -Policy $identityPolicy
        }
        elseif($isAdministratorFixture){
            $scenario='Complete';$firmwareScenario='Supported';$identityScenario='StandardUser'
            $administratorScenario=Read-AdministratorExposureFixture `
                -LiteralPath $AdministratorExposureLiteralPath `
                -ConvertFromJsonCommand $ConvertFromJsonCommand -Policy $administratorPolicy
            $privilegeScenario=if($administratorScenario -eq 'ElevationDenied'){
                'ElevationDenied'
            }elseif($administratorScenario -eq 'AlternateAdministrator'){
                'AlternateAdministrator'
            }else{'AcceptedElevation'}
        }
        elseif($isEffectivePolicyFixture){
            $scenario='Complete';$firmwareScenario='Supported';$identityScenario='StandardUser'
            $administratorScenario='LocalPrincipal';$privilegeScenario='AcceptedElevation'
            $effectivePolicyScenario=Read-EffectivePolicyFixture `
                -LiteralPath $EffectivePolicyLiteralPath `
                -ConvertFromJsonCommand $ConvertFromJsonCommand -Policy $effectivePolicy
            if($effectivePolicyScenario -eq 'DeniedAdministrator'){
                $privilegeScenario='ElevationDenied'
            }
        }
        elseif($isResourceDependenciesFixture){
            $scenario='Complete';$firmwareScenario='Supported';$identityScenario='StandardUser'
            $administratorScenario='LocalPrincipal';$effectivePolicyScenario='Workgroup'
            $privilegeScenario='AcceptedElevation'
            $resourceScenario=Read-ResourceDependenciesFixture `
                -LiteralPath $ResourceDependenciesLiteralPath `
                -ConvertFromJsonCommand $ConvertFromJsonCommand -Policy $resourcePolicy
        }
        $identityRequested=$isIdentityFixture -or $isAdministratorFixture -or $isEffectivePolicyFixture -or $isResourceDependenciesFixture -or -not $isFixture
        $administratorRequested=$isAdministratorFixture -or $isEffectivePolicyFixture -or $isResourceDependenciesFixture -or -not $isFixture
        $effectivePolicyRequested=$isEffectivePolicyFixture -or $isResourceDependenciesFixture -or -not $isFixture
        $resourceRequested=$isResourceDependenciesFixture -or -not $isFixture
        $firmwareRequested = -not $isFixture -or $firmwareScenario -ne 'None'
        if($identityRequested){
            $sliceStage='IDENTITY'
            $identityCollector=if($isIdentityFixture -or $isAdministratorFixture -or $isEffectivePolicyFixture -or $isResourceDependenciesFixture){
                Invoke-IdentityEnrollmentCollection -Policy $identityPolicy `
                    -ValidationScenario $identityScenario
            }else{Invoke-IdentityEnrollmentCollection -Policy $identityPolicy -Live}
            $processRelationship=[string]$identityCollector.processRelationship
            $collectionStarted=$true
        }
        if($resourceRequested){
            $sliceStage='RESOURCE_DEPENDENCIES'
            $resourceCollector=if($isResourceDependenciesFixture){
                Invoke-ResourceDependenciesCollection -Policy $resourcePolicy `
                    -ValidationScenario $resourceScenario
            }else{
                Invoke-ResourceDependenciesCollection -Policy $resourcePolicy -Live `
                    -AssessmentUserSid $(if($null -ne $identityCollector){
                        [string]$identityCollector.privateAssessmentUserSid
                    }else{''})
            }
            $collectionStarted=$true
            if(-not [bool]$resourceCollector.cleanupVerified){
                $exception=[InvalidOperationException]::new(
                    'The Resource Dependencies worker cleanup was not verified.'
                );$exception.Data['ReasonCode']='RESOURCE.COLLECTOR_CLEANUP_INCOMPLETE';throw $exception
            }
        }
        $sliceStage='PRIVILEGE'
        if ($firmwareRequested -or $administratorRequested -or $effectivePolicyRequested) {
            $privilegeResult = Invoke-PrivilegedCollectionPlan `
                -PreparationPlan $PreparationPlan -PlanDigest $PlanDigest `
                -AssessmentUserContext 'subject:assessment-user:primary' `
                -AssessmentUserSid $(if($null -ne $identityCollector){
                    [string]$identityCollector.privateAssessmentUserSid
                }else{''}) `
                -LocalPackageProtector 'protector:initiating-windows-user' `
                -ValidationScenario $privilegeScenario -FirmwareScenario $firmwareScenario `
                -AdministratorScenario $(if($administratorRequested){$administratorScenario}else{'None'}) `
                -EffectivePolicyScenario $(if($effectivePolicyRequested){$effectivePolicyScenario}else{'None'})
            $privilegeState = [string]$privilegeResult.state
            $privilegeUacInteractionCount = [int]$privilegeResult.elevation.uacInteractionCount
            $collectionStarted = $collectionStarted -or @($privilegeResult.operations).Count -gt 0
            if ($privilegeResult.state -in @('TimedOut','Cancelled')) {
                # These states are produced only after the bounded worker path
                # begins. Preserve that lifecycle fact even though a failed
                # worker cannot return its four operation envelopes.
                $collectionStarted = $true
            }
            if (-not [bool]$privilegeResult.cleanup.verified) {
                $exception = [InvalidOperationException]::new(
                    'The privileged worker cleanup was not verified.'
                )
                $exception.Data['ReasonCode'] = 'FIRMWARE.PRIVILEGE_CLEANUP_INCOMPLETE'
                throw $exception
            }
            if($firmwareRequested){
                if ($privilegeResult.PSObject.Properties['PrivateFirmwareCollectorResult']) {
                    $firmwareCollector = $privilegeResult.PrivateFirmwareCollectorResult
                }
                elseif ($privilegeResult.state -eq 'Unavailable') {
                    $firmwareCollector = New-FirmwareReadinessPrivilegeGapResult `
                        -PrivilegeResult $privilegeResult -ValidationFixture $isFixture
                }
                else {
                    $exception = [InvalidOperationException]::new(
                        'The privileged firmware phase did not return a usable collector result.'
                    )
                    $exception.Data['ReasonCode'] = switch ([string]$privilegeResult.state) {
                        'TimedOut' { 'FIRMWARE.PRIVILEGE_TIMED_OUT' }
                        'Cancelled' { 'FIRMWARE.PRIVILEGE_CANCELLED' }
                        default { 'FIRMWARE.PRIVILEGE_INTEGRITY_FAILED' }
                    }
                    throw $exception
                }
            }
            if($administratorRequested){
                if($privilegeResult.PSObject.Properties['PrivateAdministratorCollectorResult']){
                    $administratorCollector=$privilegeResult.PrivateAdministratorCollectorResult
                }elseif($privilegeResult.state -eq 'Unavailable'){
                    $administratorCollector=New-AdministratorExposurePrivilegeGapResult `
                        -PrivilegeResult $privilegeResult -ValidationFixture $isFixture
                }else{
                    $exception=[InvalidOperationException]::new(
                        'The privileged administrator phase did not return a usable collector result.'
                    )
                    $exception.Data['ReasonCode']='ADMINISTRATOR_EXPOSURE.PRIVILEGE_FAILED'
                    throw $exception
                }
                $administratorProcessRelationship=[string]$administratorCollector.processRelationship
            }
            if($effectivePolicyRequested){
                if($privilegeResult.PSObject.Properties['PrivateEffectivePolicyCollectorResult']){
                    $effectivePolicyCollector=$privilegeResult.PrivateEffectivePolicyCollectorResult
                }elseif($privilegeResult.state -eq 'Unavailable'){
                    $effectivePolicyCollector=New-EffectivePolicyPrivilegeGapResult `
                        -PrivilegeResult $privilegeResult -Policy $effectivePolicy `
                        -ValidationFixture $isFixture
                }else{
                    $exception=[InvalidOperationException]::new(
                        'The privileged Effective Policy phase did not return a usable collector result.'
                    )
                    $exception.Data['ReasonCode']='EFFECTIVE_POLICY.PRIVILEGE_FAILED';throw $exception
                }
            }
        }
        if($identityRequested){
            $sliceStage='SYSTEM_IDENTITY'
            $systemPlanResult=New-SystemCollectionPlan -PreparationPlan $PreparationPlan `
                -PreparationPlanDigest $PlanDigest
            $systemResult=Invoke-SystemCollectionPlan -Plan $systemPlanResult.Plan `
                -PlanDigest $systemPlanResult.Digest `
                -ValidationScenario $(if($isEffectivePolicyFixture -and $effectivePolicyScenario -eq 'DeniedSystem'){
                    'Denied'
                }elseif($isIdentityFixture -or $isAdministratorFixture -or $isEffectivePolicyFixture -or $isResourceDependenciesFixture){
                    'SyntheticSuccess'
                }else{''})
            if(-not [bool]$systemResult.cleanup.verified){
                $exception=[InvalidOperationException]::new(
                    'The predefined SYSTEM enrollment source cleanup was not verified.'
                )
                $exception.Data['ReasonCode']='IDENTITY.SYSTEM_CLEANUP_INCOMPLETE';throw $exception
            }
            if([bool]$systemResult.runIntegrityCompromised){
                $exception=[InvalidOperationException]::new(
                    'The predefined SYSTEM enrollment source lost run integrity.'
                )
                $exception.Data['ReasonCode']='IDENTITY.SYSTEM_INTEGRITY_FAILED';throw $exception
            }
        }
        $collectorScenario = if ($isFixture) { $scenario } else { '' }
        $sliceStage='DEVICE_COLLECTOR'
        $collector = Invoke-ApprovedCollectorProcess -OperationId ([string]$policy.collector.operationId) `
            -DeviceReadinessScenario $collectorScenario
        $collectionStarted = $collectionStarted -or [bool]$collector.Supervision.processStarted
        if (-not $collector.Supervision.completeOwnedTreeAbsent -or
            -not $collector.Supervision.temporaryArtifactsAbsent) {
            $outcome='CleanupIncomplete';$exitCode=60;$reasonCode='DEVICE_READINESS.COLLECTOR_CLEANUP_INCOMPLETE'
        }
        else {
            $coverageOverride = ''
            $coverageReason = ''
            $buildCanonicalRecord = $true
            if (-not $collector.PSObject.Properties['PrivatePayload']) {
                $disposition = Get-DeviceReadinessNoPayloadDisposition `
                    -Supervision $collector.Supervision -ValidationFixture $isFixture -Scenario $scenario
                $buildCanonicalRecord = [bool]$disposition.buildCanonicalRecord
                $coverageOverride = [string]$disposition.coverageState
                $coverageReason = [string]$disposition.coverageReasonCode
                if (-not $buildCanonicalRecord) {
                    $outcome = [string]$disposition.outcome
                    $exitCode = [int]$disposition.exitCode
                    $reasonCode = [string]$disposition.reasonCode
                }
                $evidence = [pscustomobject][ordered]@{
                    sourceLocale='und';manufacturer=$null;model=$null;processorName=$null
                    memoryBytes=$null;windowsEdition=$null;build=$null;architecture=$null
                    activationState=$null;activationAvailability='Unavailable'
                    systemTypeCode=$null;hypervisorPresent=$null;chassisTypeCodes=$null
                    chassisAvailability='Unavailable';virtualizationDetected=$null;formFactor=$null
                    batteryAvailability='Unavailable';batteryPresence=$null;batteryStatus=$null
                    batteryChargePercent=$null;batteryRuntimeMinutes=$null
                }
            }
            elseif ($collector.PrivatePayload.PSObject.Properties['availability']) {
                $coverageOverride = 'Unavailable'
                $coverageReason = 'COLLECTION.SOURCE_UNAVAILABLE'
                $evidence = [pscustomobject][ordered]@{
                    sourceLocale='und';manufacturer=$null;model=$null;processorName=$null
                    memoryBytes=$null;windowsEdition=$null;build=$null;architecture=$null
                    activationState=$null;activationAvailability='Unavailable'
                    systemTypeCode=$null;hypervisorPresent=$null;chassisTypeCodes=$null
                    chassisAvailability='Unavailable';virtualizationDetected=$null;formFactor=$null
                    batteryAvailability='Unavailable';batteryPresence=$null;batteryStatus=$null
                    batteryChargePercent=$null;batteryRuntimeMinutes=$null
                }
            }
            else {
                $evidence = ConvertTo-NormalizedDeviceReadinessEvidence -Payload $collector.PrivatePayload
            }
            if ($buildCanonicalRecord) {
                $sliceStage='RECORD'
                $runId = "run:device:$([guid]::NewGuid().ToString('N'))"
                $record = New-DeviceReadinessAssessmentRecord -RunId $runId -Evidence $evidence `
                    -CollectorResult $collector -Policy $policy -ValidationFixture $isFixture `
                    -CoverageStateOverride $coverageOverride -CoverageReasonCode $coverageReason
                [byte[]]$candidateBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
                    (& $ConvertToJsonCommand -InputObject $record -Compress -Depth 30)
                )
                $sourceValidation = Test-AssessmentContract -Utf8Bytes $candidateBytes `
                    -ConvertFromJsonCommand $ConvertFromJsonCommand -TestJsonCommand $TestJsonCommand
                if ([bool]$sourceValidation.accepted) {
                    $record = Complete-ValidatedDeviceReadinessAssessmentRecord `
                        -ValidatedRecord $record -Policy $policy -ContractValidation $sourceValidation
                }
                if ($null -ne $firmwareCollector) {
                    # Privileged source evidence crosses the same canonical
                    # contract before any firmware rule runs. The worker's
                    # private payload is never trusted as a finding or report
                    # input until exact fields, provenance, coverage, and its
                    # one Collector Result Envelope are accepted here.
                    $record = Add-FirmwareReadinessEvidenceRecord -Record $record `
                        -CollectorResult $firmwareCollector -Policy $firmwarePolicy
                    [byte[]]$firmwareSourceBytes = [Text.UTF8Encoding]::new($false).GetBytes(
                        (& $ConvertToJsonCommand -InputObject $record -Compress -Depth 30)
                    )
                    $firmwareSourceValidation = Test-AssessmentContract `
                        -Utf8Bytes $firmwareSourceBytes `
                        -ConvertFromJsonCommand $ConvertFromJsonCommand `
                        -TestJsonCommand $TestJsonCommand
                    if ([bool]$firmwareSourceValidation.accepted) {
                        $record = Complete-ValidatedFirmwareReadinessAssessmentRecord `
                            -Record $record -Policy $firmwarePolicy `
                            -ContractValidation $firmwareSourceValidation
                    }
                    $sourceValidation = $firmwareSourceValidation
                }
                if($null -ne $identityCollector){
                    $record=Add-IdentityEnrollmentEvidenceRecord -Record $record `
                        -CollectorResult $identityCollector -SystemResult $systemResult `
                        -Policy $identityPolicy
                    [byte[]]$identitySourceBytes=[Text.UTF8Encoding]::new($false).GetBytes(
                        (& $ConvertToJsonCommand -InputObject $record -Compress -Depth 30)
                    )
                    $identitySourceValidation=Test-AssessmentContract `
                        -Utf8Bytes $identitySourceBytes `
                        -ConvertFromJsonCommand $ConvertFromJsonCommand `
                        -TestJsonCommand $TestJsonCommand
                    if([bool]$identitySourceValidation.accepted){
                        $record=Complete-ValidatedIdentityEnrollmentAssessmentRecord `
                            -Record $record -Policy $identityPolicy `
                            -ContractValidation $identitySourceValidation
                    }
                    $sourceValidation=$identitySourceValidation
                }
                if($null -ne $administratorCollector){
                    $sliceStage='ADMIN_SOURCE'
                    $record=Add-AdministratorExposureEvidenceRecord -Record $record `
                        -CollectorResult $administratorCollector -Policy $administratorPolicy
                    $sliceStage='ADMIN_VALIDATE'
                    [byte[]]$administratorSourceBytes=[Text.UTF8Encoding]::new($false).GetBytes(
                        (& $ConvertToJsonCommand -InputObject $record -Compress -Depth 30)
                    )
                    $administratorSourceValidation=Test-AssessmentContract `
                        -Utf8Bytes $administratorSourceBytes `
                        -ConvertFromJsonCommand $ConvertFromJsonCommand `
                        -TestJsonCommand $TestJsonCommand
                    if([bool]$administratorSourceValidation.accepted){
                        $sliceStage='ADMIN_RULE'
                        $record=Complete-ValidatedAdministratorExposureAssessmentRecord `
                            -Record $record -Policy $administratorPolicy `
                            -ContractValidation $administratorSourceValidation
                    }
                    $sourceValidation=$administratorSourceValidation
                }
                if($null -ne $effectivePolicyCollector){
                    $sliceStage='EFFECTIVE_POLICY_SOURCE'
                    $record=Add-EffectivePolicyEvidenceRecord -Record $record `
                        -CollectorResult $effectivePolicyCollector -Policy $effectivePolicy
                    [byte[]]$effectivePolicySourceBytes=[Text.UTF8Encoding]::new($false).GetBytes(
                        (& $ConvertToJsonCommand -InputObject $record -Compress -Depth 30)
                    )
                    $effectivePolicySourceValidation=Test-AssessmentContract `
                        -Utf8Bytes $effectivePolicySourceBytes `
                        -ConvertFromJsonCommand $ConvertFromJsonCommand `
                        -TestJsonCommand $TestJsonCommand
                    if([bool]$effectivePolicySourceValidation.accepted){
                        $sliceStage='EFFECTIVE_POLICY_RULES'
                        $record=Complete-ValidatedEffectivePolicyAssessmentRecord `
                            -Record $record -Policy $effectivePolicy `
                            -ContractValidation $effectivePolicySourceValidation
                    }
                    $sourceValidation=$effectivePolicySourceValidation
                }
                if($null -ne $resourceCollector){
                    $sliceStage='RESOURCE_DEPENDENCIES_SOURCE'
                    $record=Add-ResourceDependenciesEvidenceRecord -Record $record `
                        -CollectorResult $resourceCollector -Policy $resourcePolicy
                    [byte[]]$resourceSourceBytes=[Text.UTF8Encoding]::new($false).GetBytes(
                        (& $ConvertToJsonCommand -InputObject $record -Compress -Depth 30)
                    )
                    $resourceSourceValidation=Test-AssessmentContract `
                        -Utf8Bytes $resourceSourceBytes `
                        -ConvertFromJsonCommand $ConvertFromJsonCommand `
                        -TestJsonCommand $TestJsonCommand
                    if([bool]$resourceSourceValidation.accepted){
                        $sliceStage='RESOURCE_DEPENDENCIES_RULES'
                        $record=Complete-ValidatedResourceDependenciesAssessmentRecord `
                            -Record $record -Policy $resourcePolicy `
                            -ContractValidation $resourceSourceValidation
                    }
                    $sourceValidation=$resourceSourceValidation
                }
                $sliceStage='FINAL_SERIALIZE'
                [byte[]]$recordBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
                    (& $ConvertToJsonCommand -InputObject $record -Compress -Depth 30)
                )
                $sliceStage='FINAL_CONTRACT'
                $finalValidation = Test-AssessmentContract -Utf8Bytes $recordBytes `
                    -ConvertFromJsonCommand $ConvertFromJsonCommand -TestJsonCommand $TestJsonCommand
                $sliceStage='FINAL_ACCEPTANCE'
                $recordAccepted = [bool]$sourceValidation.accepted -and [bool]$finalValidation.accepted
                $coverageState = [string]@($record.coverage)[0].state
                if ($null -ne $firmwareCollector) {
                    $sliceStage='FIRMWARE_METRICS'
                    $firmwareCoverageState = [string]@($record.coverage | Where-Object {
                        $_.scopeId -eq 'scope:device.firmware-context'
                    })[0].state
                    $secureBootCoverageState = [string]@($record.coverage | Where-Object {
                        $_.scopeId -eq 'scope:device.secure-boot'
                    })[0].state
                    $tpmCoverageState = [string]@($record.coverage | Where-Object {
                        $_.scopeId -eq 'scope:device.tpm-readiness'
                    })[0].state
                    $firmwareFindingOutcome = [string]@($record.findings | Where-Object {
                        $_.findingId -like 'finding:firmware-context:*'
                    })[0].outcome
                    $secureBootFindingOutcome = [string]@($record.findings | Where-Object {
                        $_.findingId -like 'finding:secure-boot-readiness:*'
                    })[0].outcome
                    $tpmFindingOutcome = [string]@($record.findings | Where-Object {
                        $_.findingId -like 'finding:tpm-readiness:*'
                    })[0].outcome
                    $tenantDiscoveryTaskCount = @($record.recommendations | Where-Object {
                        $_.kind -eq 'TenantSideDiscoveryTask'
                    }).Count
                }
                if($null -ne $identityCollector){
                    $sliceStage='IDENTITY_METRICS'
                    $assessmentUserCoverage=@($record.coverage|Where-Object {
                        $_.scopeId -eq 'scope:identity.assessment-user-context'
                    })
                    $registrationCoverage=@($record.coverage|Where-Object {
                        $_.scopeId -eq 'scope:device.registration-context'
                    })
                    $workSchoolCoverage=@($record.coverage|Where-Object {
                        $_.scopeId -eq 'scope:device.work-school-registration-context'
                    })
                    $systemEnrollmentCoverage=@($record.coverage|Where-Object {
                        $_.scopeId -eq 'scope:device.mdm-policy.system'
                    })
                    $assessmentUserFindings=@($record.findings|Where-Object {
                        $_.findingId -like 'finding:assessment-user-context:*'
                    })
                    if($assessmentUserCoverage.Count -eq 1){
                        $assessmentUserCoverageState=[string]$assessmentUserCoverage[0].state
                    }
                    if($registrationCoverage.Count -eq 1){
                        $registrationCoverageState=[string]$registrationCoverage[0].state
                    }
                    if($workSchoolCoverage.Count -eq 1){
                        $workSchoolCoverageState=[string]$workSchoolCoverage[0].state
                    }
                    if($systemEnrollmentCoverage.Count -eq 1){
                        $systemEnrollmentCoverageState=[string]$systemEnrollmentCoverage[0].state
                    }
                    if($assessmentUserFindings.Count -eq 1){
                        $assessmentUserFindingOutcome=[string]$assessmentUserFindings[0].outcome
                    }
                    $tenantDiscoveryTaskCount=@($record.recommendations|Where-Object {
                        $_.kind -eq 'TenantSideDiscoveryTask'
                    }).Count
                }
                if($null -ne $administratorCollector){
                    $sliceStage='ADMIN_METRICS'
                    $administratorCoverage=@($record.coverage|Where-Object {
                        $_.scopeId -eq 'scope:device.local-administrators.direct-membership'
                    })
                    $administratorFindings=@($record.findings|Where-Object {
                        $_.findingId -like 'finding:local-administrator-exposure:*'
                    })
                    if($administratorCoverage.Count -eq 1){
                        $administratorCoverageState=[string]$administratorCoverage[0].state
                    }
                    if($administratorFindings.Count -eq 1){
                        $administratorFindingOutcome=[string]$administratorFindings[0].outcome
                    }
                    $administratorEnumerationComplete=[bool]$administratorCollector.payload.enumerationComplete
                    $administratorDirectMemberCount=@($administratorCollector.payload.directMembers).Count
                    $administratorDirectGroupCount=@($administratorCollector.payload.directMembers|Where-Object {
                        $_.principalKind -eq 'Group'
                    }).Count
                    $administratorUnresolvedCount=@($administratorCollector.payload.directMembers|Where-Object {
                        $_.origin -eq 'Unresolved'
                    }).Count
                    $administratorDuplicateCount=[int]$administratorCollector.payload.duplicateEntriesRemoved
                }
                if($null -ne $effectivePolicyCollector){
                    $sliceStage='EFFECTIVE_POLICY_METRICS'
                    $layerById=@{};foreach($layer in $effectivePolicy.layers){$layerById[[string]$layer.layerId]=$layer}
                    $appliedPolicyCoverage=Get-EffectivePolicyLayerState -ScopeStates $record.coverage -ScopeIds @($layerById.AppliedPolicyEvidence.scopeIds)
                    $configuredPolicyCoverage=Get-EffectivePolicyLayerState -ScopeStates $record.coverage -ScopeIds @($layerById.ConfiguredPolicySignals.scopeIds)
                    $currentControlCoverage=Get-EffectivePolicyLayerState -ScopeStates $record.coverage -ScopeIds @($layerById.CurrentControlState.scopeIds)
                    $appliedPolicyCount=@($effectivePolicyCollector.payload.appliedPolicies).Count
                    $appliedPolicyFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:policy.applied-policy-coverage/1.0.0')[0].outcome
                    $localSecurityFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:policy.local-security-policy-coverage/1.0.0')[0].outcome
                    $appliedOrderFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:policy.applied-order-conflict/1.0.0')[0].outcome
                }
                if($null -ne $resourceCollector){
                    $sliceStage='RESOURCE_DEPENDENCIES_METRICS'
                    $userResourceCoverage=Get-ResourceDependencyLayerState `
                        -ScopeStates $resourceCollector.payload.scopeStates `
                        -ScopeIds @($resourcePolicy.layers[0].scopeIds)
                    $peripheralCoverage=Get-ResourceDependencyLayerState `
                        -ScopeStates $resourceCollector.payload.scopeStates `
                        -ScopeIds @($resourcePolicy.layers[1].scopeIds)
                    $mappedDriveCount=@($resourceCollector.payload.mappedDrives).Count
                    $uncConnectionCount=@($resourceCollector.payload.uncConnections).Count
                    $printerCount=@($resourceCollector.payload.printers).Count
                    $printerDriverCount=@($resourceCollector.payload.printerDrivers).Count
                    $peripheralCount=@($resourceCollector.payload.peripherals).Count
                    $userResourceFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:resource.user-migration-dependencies/1.0.0')[0].outcome
                    $peripheralFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:resource.peripheral-migration-dependencies/1.0.0')[0].outcome
                }
                $findingOutcome = [string]@($record.findings | Where-Object {
                    $_.findingId -like 'finding:device-readiness:*'
                })[0].outcome
                $activationFindingOutcome = [string]@($record.findings | Where-Object {
                    $_.findingId -like 'finding:activation-context:*'
                })[0].outcome
                $platformFindingOutcome = [string]@($record.findings | Where-Object {
                    $_.findingId -like 'finding:platform-context:*'
                })[0].outcome
                $powerFindingOutcome = [string]@($record.findings | Where-Object {
                    $_.findingId -like 'finding:power-context:*'
                })[0].outcome
                $sourceAccessDiagnostics = @($record.diagnostics | Where-Object {
                    $_.reasonCode -match '^COLLECTION\.(ACTIVATION|CHASSIS|BATTERY)_(ACCESS_DENIED|SOURCE_UNAVAILABLE)$'
                } |
                    ForEach-Object { [string]$_.reasonCode } | Sort-Object) -join '|'
                $contextByField = @{}
                foreach ($contextObservation in @($record.observations)) {
                    $contextByField[[string]$contextObservation.fieldId] = $contextObservation
                }
                $activationObservation = $contextByField['field:device.windows.activation-state']
                if ($null -ne $activationObservation -and
                    $activationObservation.valueState -eq 'ObservedValue') {
                    $activationContext = [string]$activationObservation.value
                }
                $virtualizationObservation = $contextByField['field:device.virtualization.detected']
                if ($null -ne $virtualizationObservation -and
                    $virtualizationObservation.valueState -eq 'ObservedValue') {
                    $virtualizationContext = if ([bool]$virtualizationObservation.value) {
                        'Detected'
                    } else { 'NotDetected' }
                }
                $formObservation = $contextByField['field:device.form-factor']
                if ($null -ne $formObservation -and $formObservation.valueState -eq 'ObservedValue') {
                    $formFactor = [string]$formObservation.value
                }
                $batteryObservation = $contextByField['field:device.battery.presence']
                if ($null -ne $batteryObservation -and
                    $batteryObservation.valueState -eq 'ObservedValue') {
                    $batteryPresence = if ([bool]$batteryObservation.value) { 'Present' } else { 'Absent' }
                }
                if (-not $recordAccepted) {
                    $outcome='IntegrityFailed';$exitCode=50;$reasonCode='DEVICE_READINESS.CONTRACT_INVALID'
                }
                else {
                    $sliceStage='REPORT'
                    [byte[]]$reportBytes = New-DeviceReadinessReportBytes -Record $record `
                        -FirmwarePolicy $(if ($null -ne $firmwareCollector) {
                            $firmwarePolicy
                        } else { $null }) `
                        -IdentityEnrollmentPolicy $(if($null -ne $identityCollector){
                            $identityPolicy
                        }else{$null}) `
                        -AdministratorExposurePolicy $(if($null -ne $administratorCollector){
                            $administratorPolicy
                        }else{$null}) `
                        -EffectivePolicyPolicy $(if($null -ne $effectivePolicyCollector){
                            $effectivePolicy
                        }else{$null}) `
                        -ResourceDependenciesPolicy $(if($null -ne $resourceCollector){
                            $resourcePolicy
                        }else{$null})
                    $reportText = [System.Text.UTF8Encoding]::new($false,$true).GetString($reportBytes)
                    $reportVerified = $reportText.StartsWith('<!doctype html>') -and
                        $reportText.Contains('Device, Windows, activation, and power context') -and
                        $reportText.Contains('<details><summary>Device details and where they came from</summary>') -and
                        $reportText.Contains('canonical typed evidence')
                    if ($null -ne $firmwareCollector) {
                        $reportVerified = $reportVerified -and
                            $reportText.Contains('Firmware, Secure Boot, and TPM readiness') -and
                            $reportText.Contains('cannot establish physical TPM attestation')
                    }
                    if($null -ne $identityCollector){
                        $reportVerified=$reportVerified -and
                            $reportText.Contains('Registration, join, and enrollment context') -and
                            $reportText.Contains('cannot establish tenant assignment, compliance, licensing, or organizational intent')
                    }
                    if($null -ne $administratorCollector){
                        $reportVerified=$reportVerified -and
                            $reportText.Contains('Local administrator exposure') -and
                            $reportText.Contains('does not recursively expand or guess') -and
                            $reportText.Contains('does not prove compromise')
                    }
                    if($null -ne $effectivePolicyCollector){
                        $reportVerified=$reportVerified -and
                            $reportText.Contains('Applied Group Policy and local security policy') -and
                            $reportText.Contains('Configured Policy Signals') -and
                            $reportText.Contains('does not refresh policy') -and
                            $reportText.Contains('direct SID assignments only')
                    }
                    if($null -ne $resourceCollector){
                        $reportVerified=$reportVerified -and
                            $reportText.Contains('User resources and peripheral migration dependencies') -and
                            $reportText.Contains('does not connect a resource') -and
                            $reportText.Contains('do not promise universal peripheral compatibility')
                    }
                    if (-not $reportVerified) { throw 'The beginner report projection failed verification.' }
                    $sliceStage='PACKAGE'
                    if ($isFixture) {
                        $boundary = New-EvidenceWorkspaceValidationBoundary -ValidationRootPath (
                            Join-Path (Split-Path -Parent $PSCommandPath) '.device-readiness-validation'
                        )
                        $destination = $boundary.CaseRoot
                    }
                    else {
                        # Use the exact destination frozen into the approved plan,
                        # not the caller's earlier relative request text. That
                        # closes working-directory drift between approval and
                        # packaging without inventing a new destination.
                        $destination = [System.IO.Path]::GetFullPath($ApprovedOutputDestination)
                        $null = [System.IO.Directory]::CreateDirectory($destination)
                    }
                    $artifacts = [ordered]@{
                        'assessment-record.json'=$recordBytes
                        'assessment-report.html'=$reportBytes
                    }
                    $packageCompleteness = if (@($record.coverage | Where-Object {
                        $_.state -ne 'Complete'
                    }).Count -eq 0) {
                        'Complete'
                    }
                    else { 'RecoverablePartial' }
                    $package = New-ProtectedEvidencePackage -DestinationDirectory $destination `
                        -Artifacts $artifacts -AssessmentContractSetVersion $(if($null -ne $resourceCollector){
                            '1.5.0'
                        }elseif($null -ne $effectivePolicyCollector){
                            '1.4.0'
                        }elseif($null -ne $administratorCollector){
                            '1.3.0'
                        }elseif($null -ne $identityCollector){'1.2.0'}else{'1.1.0'}) `
                        -Completeness $packageCompleteness -ApprovedRecipient $ApprovedRecipient
                    if ($package.verified) {
                        $recipientKeyProtection = [string](
                            Get-ProtectedPackageEnvelopeHeader $package.packagePath
                        ).recipientKeyProtection
                        $opened = Read-ProtectedEvidencePackage -LiteralPath $package.packagePath
                        $packageVerified = [bool]$opened.verified -and
                            $opened.artifacts.Contains('assessment-record.json') -and
                            $opened.artifacts.Contains('assessment-report.html')
                    }
                    if (-not $packageVerified) {
                        $packageDisposition = Get-DeviceReadinessPackageDisposition `
                            -Package $package -ValidationFixture $isFixture `
                            -ValidationCleanupVerified $true `
                            -FinalVerificationSucceeded $packageVerified
                        $outcome=[string]$packageDisposition.outcome
                        $exitCode=[int]$packageDisposition.exitCode
                        $reasonCode=[string]$packageDisposition.reasonCode
                    }
                    elseif (@($record.coverage | Where-Object {
                        $_.state -ne 'Complete'
                    }).Count -eq 0) {
                        $outcome='Completed';$exitCode=0;$reasonCode='DEVICE_READINESS.COMPLETED'
                    }
                    else {
                        $outcome='CompletedWithGaps';$exitCode=10;$reasonCode='DEVICE_READINESS.COMPLETED_WITH_GAPS'
                    }
                }
            }
        }
    }
    catch {
        if ($scenario -eq '') { $scenario = 'InvalidFixture' }
        $failureReasonCode = if ($_.Exception.Data['ReasonCode']) {
            [string]$_.Exception.Data['ReasonCode']
        } else { "DEVICE_READINESS.$sliceStage`_FAILED" }
        $failureDisposition = Get-DeviceReadinessFailureDisposition `
            -ReasonCode $failureReasonCode -CollectionStarted $collectionStarted
        $outcome=[string]$failureDisposition.outcome
        $exitCode=[int]$failureDisposition.exitCode
        $reasonCode=[string]$failureDisposition.reasonCode
        $cleanupVerified=$cleanupVerified -and [bool]$failureDisposition.cleanupVerified
    }
    finally {
        if ($null -ne $opened -and $null -ne $opened.artifacts) {
            foreach ($bytes in @($opened.artifacts.Values)) {
                [System.Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]]$bytes)
            }
        }
        if ($null -ne $boundary) {
            $cleanupVerified = Remove-EvidenceWorkspaceValidationBoundary -Boundary $boundary
            if (-not $cleanupVerified) {
                $outcome='CleanupIncomplete';$exitCode=60;$reasonCode='DEVICE_READINESS.CLEANUP_INCOMPLETE'
            }
        }
    }
    if ($isFixture) {
        Write-ContractRecord ([pscustomobject][ordered]@{
            recordType='win-pcinfo.device-readiness-validation';contractVersion='1.0.0'
            scenario=$scenario;coverageState=$coverageState;findingOutcome=$findingOutcome
            activationContext=$activationContext;virtualizationContext=$virtualizationContext
            formFactor=$formFactor;batteryPresence=$batteryPresence;physicalClaimsAllowed=$false
            activationFindingOutcome=$activationFindingOutcome
            platformFindingOutcome=$platformFindingOutcome;powerFindingOutcome=$powerFindingOutcome
            sourceAccessDiagnostics=$sourceAccessDiagnostics
            firmwareScenario=$firmwareScenario;privilegeState=$privilegeState
            privilegeUacInteractionCount=$privilegeUacInteractionCount
            firmwareCoverageState=$firmwareCoverageState
            secureBootCoverageState=$secureBootCoverageState;tpmCoverageState=$tpmCoverageState
            firmwareFindingOutcome=$firmwareFindingOutcome
            secureBootFindingOutcome=$secureBootFindingOutcome;tpmFindingOutcome=$tpmFindingOutcome
            tenantDiscoveryTaskCount=$tenantDiscoveryTaskCount
            physicalTpmAttestationEstablished=$false;platformSecurityStateChanged=$false
            assessmentRecordValidated=$recordAccepted;beginnerReportVerified=$reportVerified
            protectedPackageVerified=$packageVerified;validationCleanupVerified=$cleanupVerified
            recipientKeyProtection=$recipientKeyProtection
        }) -ConvertToJsonCommand $ConvertToJsonCommand
    }
    if($isIdentityFixture){
        Write-ContractRecord ([pscustomobject][ordered]@{
            recordType='win-pcinfo.identity-enrollment-validation';contractVersion='1.0.0'
            scenario=$identityScenario;processRelationship=$processRelationship
            assessmentUserCoverageState=$assessmentUserCoverageState
            registrationCoverageState=$registrationCoverageState
            workSchoolCoverageState=$workSchoolCoverageState
            systemEnrollmentCoverageState=$systemEnrollmentCoverageState
            assessmentUserFindingOutcome=$assessmentUserFindingOutcome
            tenantDiscoveryTaskCount=$tenantDiscoveryTaskCount
            tenantAuthenticated=$false;identityStateChanged=$false
            assessmentRecordValidated=$recordAccepted;beginnerReportVerified=$reportVerified
            protectedPackageVerified=$packageVerified;validationCleanupVerified=$cleanupVerified
        }) -ConvertToJsonCommand $ConvertToJsonCommand
    }
    if($isAdministratorFixture){
        Write-ContractRecord ([pscustomobject][ordered]@{
            recordType='win-pcinfo.local-privilege-validation';contractVersion='1.0.0'
            scenario=$administratorScenario;coverageState=$administratorCoverageState
            enumerationComplete=$administratorEnumerationComplete
            directMemberCount=$administratorDirectMemberCount
            directGroupCount=$administratorDirectGroupCount
            unresolvedPrincipalCount=$administratorUnresolvedCount
            duplicateEntriesRemoved=$administratorDuplicateCount
            findingOutcome=$administratorFindingOutcome
            processRelationship=$administratorProcessRelationship
            nestedExpansionAttempted=$false
            assessmentUserContextPreserved=$null -ne $administratorCollector -and
                $administratorCollector.assessmentUserContext -eq 'subject:assessment-user:primary'
            localPackageProtectorPreserved=$null -ne $administratorCollector -and
                $administratorCollector.localPackageProtector -eq 'protector:initiating-windows-user'
            identifiersPublished=$false;credentialMaterialCollected=$false
            identityStateChanged=$false;automaticRemovalAttempted=$false
            assessmentRecordValidated=$recordAccepted;beginnerReportVerified=$reportVerified
            protectedPackageVerified=$packageVerified;validationCleanupVerified=$cleanupVerified
        }) -ConvertToJsonCommand $ConvertToJsonCommand
    }
    if($isEffectivePolicyFixture){
        # This is Public Security Evidence: only bounded states and counts leave
        # the protected package. GPO identifiers, link paths, setting IDs,
        # registry values, account-policy values, and principal SIDs do not.
        Write-ContractRecord ([pscustomobject][ordered]@{
            recordType='win-pcinfo.effective-policy-validation';contractVersion='1.0.0'
            scenario=$effectivePolicyScenario
            appliedPolicyCoverage=$appliedPolicyCoverage
            configuredSignalCoverage=$configuredPolicyCoverage
            currentControlCoverage=$currentControlCoverage
            appliedPolicyCount=$appliedPolicyCount
            appliedPolicyFinding=$appliedPolicyFinding
            localSecurityFinding=$localSecurityFinding
            appliedOrderFinding=$appliedOrderFinding
            directRightsOnly=$null -ne $effectivePolicyCollector -and
                $effectivePolicyCollector.payload.userRightSemantics -eq 'DirectAssignmentsOnly'
            localSamOnly=$null -ne $effectivePolicyCollector -and
                $effectivePolicyCollector.payload.localAccountPolicySemantics -eq 'LocalSamAccountsOnly'
            policyIdentifiersPublished=$false;policyValuesPublished=$false
            policyStateChanged=$false;policyRefreshAttempted=$false;toolInstalled=$false
            assessmentRecordValidated=$recordAccepted;beginnerReportVerified=$reportVerified
            protectedPackageVerified=$packageVerified;validationCleanupVerified=$cleanupVerified
        }) -ConvertToJsonCommand $ConvertToJsonCommand
    }
    if($isResourceDependenciesFixture -and $null -ne $resourceCollector){
        $projection=New-ResourceDependenciesPublicProjection `
            -CollectorResult $resourceCollector -Policy $resourcePolicy
        $projection|Add-Member -NotePropertyName scenario -NotePropertyValue $resourceScenario
        $projection|Add-Member -NotePropertyName userResourceFinding -NotePropertyValue $userResourceFinding
        $projection|Add-Member -NotePropertyName peripheralFinding -NotePropertyValue $peripheralFinding
        $projection|Add-Member -NotePropertyName assessmentRecordValidated -NotePropertyValue $recordAccepted
        $projection|Add-Member -NotePropertyName beginnerReportVerified -NotePropertyValue $reportVerified
        $projection|Add-Member -NotePropertyName protectedPackageVerified -NotePropertyValue $packageVerified
        $projection|Add-Member -NotePropertyName validationCleanupVerified -NotePropertyValue $cleanupVerified
        Write-ContractRecord $projection -ConvertToJsonCommand $ConvertToJsonCommand
    }
    $recipientSelected = $null -ne $ApprovedRecipient
    $recipientProtectionLevel = if ($recipientSelected) {
        [string]$ApprovedRecipient.protectionLevel
    }
    else { 'None' }
    $recipientAccessAvailable = $packageVerified -and
        $recipientKeyProtection -eq 'RSA-OAEP-SHA-256'
    $packageDisposition = Get-DeviceReadinessPackageDisposition `
        -Package $package -ValidationFixture $isFixture `
        -ValidationCleanupVerified $cleanupVerified `
        -FinalVerificationSucceeded $packageVerified
    $packageAvailability = [string]$packageDisposition.packageAvailability
    if ($packageDisposition.outcome -eq 'CleanupIncomplete') {
        $outcome=[string]$packageDisposition.outcome
        $exitCode=[int]$packageDisposition.exitCode
        $reasonCode=[string]$packageDisposition.reasonCode
    }
    Write-ContractRecord (New-CompletionSummary -PackageVerified $packageVerified `
        -PackageAvailability $packageAvailability `
        -RecipientSelected $recipientSelected `
        -RecipientProtectionLevel $recipientProtectionLevel `
        -RecipientAccessAvailable $recipientAccessAvailable `
        -RestrictedReportExported $false) -ConvertToJsonCommand $ConvertToJsonCommand
    Write-DeviceReadinessTerminal -Outcome $outcome -ExitCode $exitCode -ReasonCode $reasonCode `
        -CollectionStarted $collectionStarted `
        -ValidationFixture $isFixture -CleanupVerified $cleanupVerified `
        -RequestDigest $RequestDigest -PlanDigest $PlanDigest `
        -ConvertToJsonCommand $ConvertToJsonCommand
    $exitCode
}
