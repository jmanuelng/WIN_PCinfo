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

function New-DeviceReadinessReportBytes {
    param([Parameter(Mandatory)] $Record)

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
        $discoveryCount = @($Record.recommendations | Where-Object {
            $_.kind -eq 'TenantSideDiscoveryTask'
        }).Count
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
<p>No owner authorization, endorsement secret, key, recovery data, TPM provisioning action, Secure Boot variable write, or firmware change is requested or retained.</p>
"@
    } else { '' }
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

function Invoke-DeviceReadinessSlice {
    param(
        [Parameter()] [string] $LiteralPath,
        [Parameter(Mandatory)] $PreparationPlan,
        [Parameter(Mandatory)] [string] $ApprovedOutputDestination,
        [Parameter()] $ApprovedRecipient,
        [Parameter(Mandatory)] [string] $RequestDigest,
        [Parameter(Mandatory)] [string] $PlanDigest,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand,
        [Parameter(Mandatory)] $TestJsonCommand
    )

    $isFixture = -not [string]::IsNullOrWhiteSpace($LiteralPath)
    $scenario = if ($isFixture) { '' } else { 'Actual' }
    $firmwareScenario = if ($isFixture) { 'None' } else { 'Live' }
    $privilegeScenario = if ($isFixture) { 'None' } else { 'Live' }
    $policy = $null; $firmwarePolicy = $null; $privilegeResult = $null
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
    $collectionStarted = $false
    $outcome = 'CompletedWithGaps'; $exitCode = 10; $reasonCode = 'DEVICE_READINESS.EVIDENCE_UNAVAILABLE'
    try {
        $policy = Get-DeviceReadinessPolicy -ConvertFromJsonCommand $ConvertFromJsonCommand
        $firmwarePolicy = Get-FirmwareReadinessPolicy `
            -ConvertFromJsonCommand $ConvertFromJsonCommand
        if ($isFixture) {
            $fixtureSelection = Read-DeviceReadinessFixture -LiteralPath $LiteralPath `
                -ConvertFromJsonCommand $ConvertFromJsonCommand -Policy $policy `
                -FirmwarePolicy $firmwarePolicy
            $scenario = [string]$fixtureSelection.DeviceScenario
            $firmwareScenario = [string]$fixtureSelection.FirmwareScenario
            $privilegeScenario = [string]$fixtureSelection.PrivilegeScenario
        }
        $firmwareRequested = -not $isFixture -or $firmwareScenario -ne 'None'
        if ($firmwareRequested) {
            $privilegeResult = Invoke-PrivilegedCollectionPlan `
                -PreparationPlan $PreparationPlan -PlanDigest $PlanDigest `
                -AssessmentUserContext 'subject:assessment-user:primary' `
                -LocalPackageProtector 'protector:initiating-windows-user' `
                -ValidationScenario $privilegeScenario -FirmwareScenario $firmwareScenario
            $privilegeState = [string]$privilegeResult.state
            $privilegeUacInteractionCount = [int]$privilegeResult.elevation.uacInteractionCount
            $collectionStarted = @($privilegeResult.operations).Count -gt 0
            if (-not [bool]$privilegeResult.cleanup.verified) {
                $exception = [InvalidOperationException]::new(
                    'The privileged firmware worker cleanup was not verified.'
                )
                $exception.Data['ReasonCode'] = 'FIRMWARE.PRIVILEGE_CLEANUP_INCOMPLETE'
                throw $exception
            }
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
        $collectorScenario = if ($isFixture) { $scenario } else { '' }
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
                [byte[]]$recordBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
                    (& $ConvertToJsonCommand -InputObject $record -Compress -Depth 30)
                )
                $finalValidation = Test-AssessmentContract -Utf8Bytes $recordBytes `
                    -ConvertFromJsonCommand $ConvertFromJsonCommand -TestJsonCommand $TestJsonCommand
                $recordAccepted = [bool]$sourceValidation.accepted -and [bool]$finalValidation.accepted
                $coverageState = [string]@($record.coverage)[0].state
                if ($null -ne $firmwareCollector) {
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
                    [byte[]]$reportBytes = New-DeviceReadinessReportBytes -Record $record
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
                    if (-not $reportVerified) { throw 'The beginner report projection failed verification.' }
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
                        -Artifacts $artifacts -AssessmentContractSetVersion '1.1.0' `
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
        $outcome=if($collectionStarted){'IntegrityFailed'}else{'NotStarted'}
        $exitCode=if($collectionStarted){50}else{20}
        $reasonCode=if($_.Exception.Data['ReasonCode']){
            [string]$_.Exception.Data['ReasonCode']
        }else{'DEVICE_READINESS.INTEGRITY_FAILED'}
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
