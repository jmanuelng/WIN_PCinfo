$script:DeviceReadinessPolicyBase64 = '__DEVICE_READINESS_POLICY_BASE64__'
$script:DeviceReadinessPolicyDigest = '__DEVICE_READINESS_POLICY_SHA256__'

function Get-DeviceReadinessPolicy {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    if ($script:DeviceReadinessPolicyBase64 -eq ('__DEVICE_READINESS_' + 'POLICY_BASE64__')) {
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
            'Denied', 'ProhibitedMaterialBlocked', 'Cancelled', 'TimedOut', 'Constrained')]
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
        'Unavailable', 'Malformed', 'Failed', 'ProhibitedMaterialBlocked', 'Cancelled', 'TimedOut', 'Constrained'
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
                    elseif ($availability.state -eq 'Constrained') { "COLLECTION.$upperKind`_OUTPUT_LIMIT_EXCEEDED" }
                    elseif ($availability.state -eq 'Unsupported') { "COLLECTION.$upperKind`_SOURCE_UNSUPPORTED" }
                    elseif ($availability.state -eq 'Malformed') { "COLLECTION.$upperKind`_PAYLOAD_MALFORMED" }
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
                '(?i)VMware|Xen|QEMU|VirtualBox' -or
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
        'Unavailable','Malformed','Failed','Denied','ProhibitedMaterialBlocked','Cancelled','TimedOut','Constrained'
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

function Get-CrossDomainGuidancePriorityCount {
    param(
        [Parameter(Mandatory)] $Model,
        [Parameter(Mandatory)] [string] $Priority
    )

    @($Model.pathRecommendations | Where-Object priority -eq $Priority).Count
}

function Get-AssessmentReportOutcomeLabel {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'Completed',
            'CompletedWithGaps',
            'NotStarted',
            'Cancelled',
            'TimedOut',
            'IntegrityFailed',
            'CleanupIncomplete'
        )]
        [string] $Outcome
    )

    switch ($Outcome) {
        'Completed' { 'Completed' }
        'CompletedWithGaps' { 'Completed with gaps' }
        'NotStarted' { 'Not started' }
        'Cancelled' { 'Cancelled' }
        'TimedOut' { 'Timed out' }
        'IntegrityFailed' { 'Integrity failed' }
        'CleanupIncomplete' { 'Cleanup incomplete' }
        default { [string] $Outcome }
    }
}

function Get-AssessmentReportCompleteness {
    param([Parameter(Mandatory)] $Record)

    if ([string] $Record.run.outcome -eq 'Completed' -and
        @($Record.coverage | Where-Object state -ne 'Complete').Count -eq 0) {
        return 'Complete'
    }
    'RecoverablePartial'
}

function Get-AssessmentReportDefinitionLookup {
    param(
        [Parameter()] $FirmwarePolicy,
        [Parameter()] $IdentityEnrollmentPolicy,
        [Parameter()] $EffectivePolicyPolicy,
        [Parameter()] $ResourceDependenciesPolicy,
        [Parameter()] $NetworkTopologyPolicy,
        [Parameter()] $SoftwareInventoryPolicy,
        [Parameter()] $CertificateTrustPolicy,
        [Parameter()] $MicrosoftConnectivityPolicy,
        [Parameter()] $CrossDomainPolicy
    )

    $lookup = @{}
    $definitionSets = @(
        @($FirmwarePolicy, 'discoveryTasks'),
        @($IdentityEnrollmentPolicy, 'discoveryTasks'),
        @($EffectivePolicyPolicy, 'discoveryTasks'),
        @($ResourceDependenciesPolicy, 'recommendations'),
        @($NetworkTopologyPolicy, 'recommendations'),
        @($SoftwareInventoryPolicy, 'recommendations'),
        @($CertificateTrustPolicy, 'recommendations'),
        @($MicrosoftConnectivityPolicy, 'recommendations'),
        @($CrossDomainPolicy, 'recommendations'),
        @($CrossDomainPolicy, 'discoveryTasks')
    )
    foreach ($set in $definitionSets) {
        $policy = $set[0]
        $propertyName = [string] $set[1]
        if ($null -eq $policy -or -not $policy.PSObject.Properties[$propertyName]) { continue }
        foreach ($definition in @($policy.$propertyName)) {
            if ($null -eq $definition -or
                [string]::IsNullOrWhiteSpace([string] $definition.definitionId)) {
                continue
            }
            $lookup[[string] $definition.definitionId] = [pscustomobject][ordered]@{
                definitionId = [string] $definition.definitionId
                title = if ($definition.PSObject.Properties['title']) {
                    [string] $definition.title
                }
                else { $null }
                purpose = if ($definition.PSObject.Properties['purpose']) {
                    [string] $definition.purpose
                }
                else { $null }
                priority = if ($definition.PSObject.Properties['priority']) {
                    [string] $definition.priority
                }
                else { $null }
                priorityExplanation = if ($definition.PSObject.Properties['priorityExplanation']) {
                    [string] $definition.priorityExplanation
                }
                else { $null }
                responsibleRole = if ($definition.PSObject.Properties['responsibleRole']) {
                    [string] $definition.responsibleRole
                }
                else { $null }
                requiredRole = if ($definition.PSObject.Properties['requiredRole']) {
                    [string] $definition.requiredRole
                }
                else { $null }
                verification = if ($definition.PSObject.Properties['verification']) {
                    [string] $definition.verification
                }
                else { $null }
                caution = if ($definition.PSObject.Properties['caution']) {
                    [string] $definition.caution
                }
                else { $null }
            }
        }
    }
    $lookup
}

function Get-AssessmentReportRecommendationDetails {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $DefinitionLookup,
        [Parameter(Mandatory)] [ValidateSet('AssessmentRecommendation', 'TenantSideDiscoveryTask')]
        [string] $Kind
    )

    @(
        foreach ($recommendation in @($Record.recommendations | Where-Object kind -eq $Kind)) {
            $definition = $DefinitionLookup[[string] $recommendation.definitionId]
            [pscustomobject][ordered]@{
                recommendationId = [string] $recommendation.recommendationId
                definitionId = [string] $recommendation.definitionId
                title = if ($null -ne $definition -and $definition.title) {
                    [string] $definition.title
                }
                elseif ($null -ne $definition -and $definition.purpose) {
                    [string] $definition.purpose
                }
                else { [string] $recommendation.definitionId }
                purpose = if ($null -ne $definition) { [string] $definition.purpose } else { '' }
                priority = if ($null -ne $definition) { [string] $definition.priority } else { '' }
                priorityExplanation = if ($null -ne $definition) {
                    [string] $definition.priorityExplanation
                }
                else { '' }
                role = if ($null -ne $definition -and $definition.responsibleRole) {
                    [string] $definition.responsibleRole
                }
                elseif ($null -ne $definition -and $definition.requiredRole) {
                    [string] $definition.requiredRole
                }
                else { '' }
                verification = if ($null -ne $definition) {
                    [string] $definition.verification
                }
                else { '' }
                caution = if ($null -ne $definition) { [string] $definition.caution } else { '' }
            }
        }
    )
}

function Get-AssessmentReportPrioritizedResults {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter()] $CrossDomainModel
    )

    if ($null -ne $CrossDomainModel -and @($CrossDomainModel.pathRecommendations).Count -gt 0) {
        return @(
            $CrossDomainModel.pathRecommendations | ForEach-Object {
                [pscustomobject][ordered]@{
                    title = [string] $_.title
                    finding = [string] $_.findingOutcome
                    severity = if ($null -eq $_.severity) { 'Not assigned' } else { [string] $_.severity }
                    confidence = if ($null -eq $_.confidence) { 'Unspecified' } else { [string] $_.confidence }
                    recommendation = [string] $_.purpose
                }
            }
        )
    }

    $findingTitles = @{}
    foreach ($finding in @($Record.findings)) {
        $findingTitles[[string] $finding.findingId] = [string] $finding.ruleId
    }
    @(
        foreach ($finding in @($Record.findings | Where-Object outcome -in @(
                    'NeedsAttention', 'Indeterminate', 'ExpectedCondition'
                ) | Select-Object -First 5)) {
            [pscustomobject][ordered]@{
                title = $findingTitles[[string] $finding.findingId]
                finding = [string] $finding.outcome
                severity = if ([string] $finding.outcome -eq 'NeedsAttention') {
                    'Advisory'
                }
                elseif ([string] $finding.outcome -eq 'Indeterminate') {
                    'CoverageGap'
                }
                else { 'Informational' }
                confidence = if ([string] $finding.outcome -eq 'Indeterminate') {
                    'Unspecified'
                }
                else { 'High' }
                recommendation = 'Review the detailed section and related recommendation before changing device or tenant state.'
            }
        }
    )
}

function Test-AssessmentReportBytesEqual {
    param(
        [Parameter(Mandatory)] [byte[]] $Left,
        [Parameter(Mandatory)] [byte[]] $Right
    )

    if ($Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) { return $false }
    }
    $true
}

function Test-AssessmentReportContract {
    param(
        [Parameter(Mandatory)] [byte[]] $ReportBytes,
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] [bool] $ExpectUnicode
    )

    $result = [ordered]@{
        verified = $false
        executiveSummaryVerified = $false
        categorySeparationVerified = $false
        offlineSafeVerified = $false
        keyboardNavigationVerified = $false
        printLayoutVerified = $false
        utf8Verified = $false
        unicodePreservedVerified = $false
        renderedCompleteness = Get-AssessmentReportCompleteness -Record $Record
    }
    try {
        $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($ReportBytes)
        $result.utf8Verified = $true
    }
    catch {
        return [pscustomobject] $result
    }

    $headings = @(
        '<h2>Outcome</h2>',
        '<h2>Scope</h2>',
        '<h2>Completeness</h2>',
        '<h2>Limitations</h2>',
        '<h2>Prioritized advisory results</h2>',
        '<h2>Next steps</h2>',
        '<h2>Evidence and provenance</h2>'
    )
    $headingIndexes = @()
    foreach ($heading in $headings) {
        $headingIndexes += $text.IndexOf($heading, [System.StringComparison]::Ordinal)
    }
    $result.executiveSummaryVerified = $headingIndexes -notcontains -1 -and (
        $headingIndexes[0] -lt $headingIndexes[1] -and
        $headingIndexes[1] -lt $headingIndexes[2] -and
        $headingIndexes[2] -lt $headingIndexes[3] -and
        $headingIndexes[3] -lt $headingIndexes[4] -and
        $headingIndexes[4] -lt $headingIndexes[5] -and
        $headingIndexes[5] -lt $headingIndexes[6]
    )

    $result.categorySeparationVerified = @(
        '<strong>Observations:</strong>',
        '<strong>Finding:</strong>',
        '<strong>Severity:</strong>',
        '<strong>Confidence:</strong>',
        '<h2>Limitations</h2>',
        '<h3>Assessment Recommendations</h3>',
        '<h3>Diagnostics</h3>',
        '<h3>Tenant-side Discovery Tasks</h3>'
    ) | Where-Object { $text.Contains($_) } | Measure-Object | Select-Object -ExpandProperty Count
    $result.categorySeparationVerified = $result.categorySeparationVerified -eq 8

    $result.offlineSafeVerified = (
        $text.Contains('<meta charset="utf-8">') -and
        $text -notmatch '(?i)<script\b' -and
        $text -notmatch '(?i)\son[a-z]+\s*=' -and
        $text -notmatch '(?i)\b(?:src|href)\s*=\s*"(?:https?:|//)' -and
        $text -notmatch '(?i)<(?:img|iframe|audio|video)\b' -and
        $text -notmatch '(?i)@import' -and
        $text -notmatch '(?i)url\s*\('
    )
    $navigationLabels = @(
        '>Executive summary<',
        '>Next steps<',
        '>Diagnostics<',
        '>Evidence and provenance<'
    )
    # This report is intentionally plain HTML: without script hooks, positive
    # tabindex overrides, or access keys, the navigation stays predictable for
    # keyboard users and cannot create a custom focus trap.
    $result.keyboardNavigationVerified = (
        $text.Contains('Skip to report content') -and
        $text.Contains('<nav aria-label="Primary report navigation">') -and
        $text.Contains('id="report-content"') -and
        $text.Contains(':focus-visible') -and
        (@($navigationLabels | Where-Object { $text.Contains($_) }).Count -eq
            $navigationLabels.Count) -and
        $text -notmatch '(?i)\baccesskey\s*=' -and
        $text -notmatch '(?i)\btabindex\s*=\s*"[1-9]'
    )
    $result.printLayoutVerified = $text.Contains('@page') -and $text.Contains('@media print')
    $result.unicodePreservedVerified = if ($ExpectUnicode) {
        [regex]::IsMatch($text, '[^\u0000-\u007F]') -or
            [regex]::IsMatch($text, '&#(?:x[0-9A-Fa-f]+|\d+);')
    }
    else { $false }
    $result.verified = $result.executiveSummaryVerified -and
        $result.categorySeparationVerified -and $result.offlineSafeVerified -and
        $result.keyboardNavigationVerified -and $result.printLayoutVerified -and
        $result.utf8Verified -and ($result.unicodePreservedVerified -eq $ExpectUnicode)
    [pscustomobject] $result
}

function Test-AssessmentPackageManifestConsistency {
    param(
        [Parameter(Mandatory)] $Manifest,
        [Parameter(Mandatory)] [byte[]] $RecordBytes,
        [Parameter(Mandatory)] [byte[]] $ReportBytes,
        [Parameter(Mandatory)] [string] $ExpectedCompleteness
    )

    if ($null -eq $Manifest -or [string] $Manifest.completeness -ne $ExpectedCompleteness) {
        return $false
    }
    if (@($Manifest.contents).Count -ne 2) { return $false }
    $recordContent = @($Manifest.contents | Where-Object relativePath -eq 'assessment-record.json')
    $reportContent = @($Manifest.contents | Where-Object relativePath -eq 'assessment-report.html')
    if ($recordContent.Count -ne 1 -or $reportContent.Count -ne 1) { return $false }
    [string] $recordContent[0].sha256 -eq (Get-ProtectedPackageSha256 $RecordBytes) -and
        [int] $recordContent[0].byteLength -eq $RecordBytes.Length -and
        [string] $reportContent[0].sha256 -eq (Get-ProtectedPackageSha256 $ReportBytes) -and
        [int] $reportContent[0].byteLength -eq $ReportBytes.Length
}

function Test-AssessmentCompletionSummaryConsistency {
    param(
        [Parameter(Mandatory)] $Summary,
        [Parameter(Mandatory)] $Terminal,
        [Parameter(Mandatory)] $Manifest,
        [Parameter(Mandatory)] [bool] $PackageVerified,
        [Parameter(Mandatory)] [bool] $CleanupVerified,
        [Parameter(Mandatory)] [ValidateSet('Complete', 'RecoverablePartial')]
        [string] $RenderedCompleteness
    )

    if ($null -eq $Summary -or $null -eq $Terminal -or $null -eq $Manifest) { return $false }
    if (-not $Summary.PSObject.Properties['assessment']) { return $false }
    $assessment = $Summary.assessment
    $guidance = $Summary.resultSharingGuidance
    $packageAvailability = [string] $Summary.packageAvailability
    $packageAvailable = $packageAvailability -eq 'Available'
    $packageUncertain = $packageAvailability -eq 'Uncertain'
    $expectedLocalAccess = if ($PackageVerified -and $packageAvailable) {
        'InitiatingWindowsUserAndDevice'
    }
    elseif ($packageUncertain) { 'Uncertain' }
    else { 'Unavailable' }
    [bool] $Summary.packageVerified -eq $PackageVerified -and
        [string] $assessment.outcome -eq [string] $Terminal.outcome -and
        [string] $assessment.packageCompleteness -eq [string] $Manifest.completeness -and
        [string] $assessment.renderedCompleteness -eq $RenderedCompleteness -and
        [bool] $assessment.cleanupVerified -eq $CleanupVerified -and
        [string] $assessment.reportArtifact -eq 'assessment-report.html' -and
        [string] $assessment.manifestArtifact -eq 'package-manifest.json' -and
        $null -ne $guidance -and
        [string] $guidance.kind -eq 'ResultSharingGuidance' -and
        [string] $guidance.localAccess -eq $expectedLocalAccess -and
        [bool] $guidance.privateTransfer.allowed -eq (
            [string] $guidance.recipientAccess -eq 'ApprovedPackageRecipient'
        ) -and
        [bool] $guidance.restrictedExport.available -eq ($PackageVerified -and $packageAvailable) -and
        [bool] $guidance.prohibitedPublicSharing
}

function New-DeviceReadinessReportBytes {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter()] $FirmwarePolicy,
        [Parameter()] $IdentityEnrollmentPolicy,
        [Parameter()] $AdministratorExposurePolicy,
        [Parameter()] $EffectivePolicyPolicy,
        [Parameter()] $ResourceDependenciesPolicy,
        [Parameter()] $NetworkTopologyPolicy,
        [Parameter()] $SoftwareInventoryPolicy,
        [Parameter()] $CertificateTrustPolicy,
        [Parameter()] $MicrosoftConnectivityPolicy
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
        $_.reasonCode -match '^COLLECTION\.(ACTIVATION|CHASSIS|BATTERY)_(ACCESS_DENIED|SOURCE_UNAVAILABLE|SOURCE_UNSUPPORTED|OUTPUT_LIMIT_EXCEEDED|PAYLOAD_MALFORMED)$'
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
    elseif ($virtualization -eq 'False') {
        'No virtual signal was detected by this bounded rule. That does not prove the device is physical or establish firmware, TPM-attestation, OEM, or performance facts.'
    }
    else {
        'Virtualization could not be determined from the available evidence. Physical hardware, firmware, TPM-attestation, OEM, and performance claims remain unproven.'
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
<dt>Assessment User default work-or-school registration observed</dt><dd>$($values['field:device.work-school-registration.present'])</dd>
<dt>SYSTEM MDM-source coverage</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$systemCoverage.state))</dd>
<dt>Enrollment-context finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$enrollmentFinding.outcome))</dd></dl>
<p>The default work-account query describes only the verified user's context. A device join can hide separate work accounts; unavailable coverage does not mean no account or enrollment. SYSTEM provider availability is a local dependency signal and does not prove enrollment.</p>
<p>These locale-neutral local sources cannot establish tenant assignment, compliance, licensing, recovery escrow, or organizational intent. The discovery tasks below assign those checks to authorized roles without retrieving recovery secrets. WIN-PCInfo does not authenticate to Microsoft Entra or Intune and does not join, register, enroll, disconnect, or modify an account.</p>
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
        $mdmCoverageFinding=@($Record.findings|Where-Object ruleId -eq 'rule:policy.mdm-policy-csp-coverage/1.0.0')[0]
        $channelConflictFinding=@($Record.findings|Where-Object ruleId -eq 'rule:policy.policy-csp-gpo-conflict/1.0.0')[0]
        $policyDiscoveryTaskCount=@(@($Record.recommendations|Where-Object {
            $_.kind -eq 'TenantSideDiscoveryTask' -and
            $_.definitionId -in @($EffectivePolicyPolicy.discoveryTasks.definitionId)
        })).Count
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
<dt>Applied-order conflict finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$orderFinding.outcome))</dd>
<dt>Policy CSP coverage finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$mdmCoverageFinding.outcome))</dd>
<dt>Policy CSP versus local signal finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$channelConflictFinding.outcome))</dd>
<dt>Tenant-side discovery tasks</dt><dd>$policyDiscoveryTaskCount</dd></dl>
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
<p>RSoP is read only and uses cached locale-neutral classes; WIN-PCInfo does not refresh policy or parse a localized report. Local SAM values apply only to local accounts. User-right entries are direct SID assignments only and do not expand nested groups. `MDMWinsOverGP` is reported only for its documented Policy CSP scope and is never generalized to every management channel. Missing, denied, stale, unsupported, malformed, or incomplete sources remain explicit gaps, and tenant-side discovery tasks replace a guessed assignment or precedence conclusion.</p>
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
    $networkFinding=$Record.findings|Where-Object {
        $_.ruleId -eq 'rule:network.local-configuration/1.0.0'
    }|Select-Object -First 1
    $networkSection=if($null -ne $networkFinding){
        if($null -eq $NetworkTopologyPolicy){throw 'Network Topology guidance requires its frozen policy definition.'}
        $componentFinding=@($Record.findings|Where-Object ruleId -eq 'rule:network.component-inventory/1.0.0')[0]
        $localOnlyFinding=@($Record.findings|Where-Object ruleId -eq 'rule:network.local-only-coverage/1.0.0')|Select-Object -First 1
        $localCoverage=@($Record.coverage|Where-Object scopeId -in @($NetworkTopologyPolicy.localScopes.scopeId))
        $networkCoverage=@($Record.coverage|Where-Object scopeId -in @($NetworkTopologyPolicy.networkDependentScopes.scopeId))
        $connectivityImplemented = $null -ne ($Record.findings|Where-Object ruleId -eq 'rule:microsoft-connectivity.reachability/1.0.0'|Select-Object -First 1)
        $connectivityEnabled = @($networkCoverage | Where-Object reasonCode -eq 'NETWORK.CONNECTIVITY_OPERATIONS_NOT_IMPLEMENTED').Count -gt 0
        $networkModeHeading = if($connectivityImplemented){'Local network topology'}elseif($connectivityEnabled){'Local network topology and Microsoft Connectivity Enabled coverage'}else{'Local network topology and Local Only coverage'}
        $networkModeSummary = if($connectivityImplemented){
            'Microsoft service connectivity is reported separately below. Local topology remains distinct from remote reachability.'
        }elseif($connectivityEnabled){
            'The operator approved Microsoft Connectivity Enabled, but this release does not implement those bounded operations. WIN-PCInfo made zero DNS, TCP, TLS, HTTP, catalog, update, or telemetry requests and records each operation as NotAttempted.'
        }else{
            'In Local Only mode WIN-PCInfo made zero DNS, TCP, TLS, HTTP, catalog, update, or telemetry requests. Network-dependent checks remain explicitly NotAttempted rather than being reported as successful or absent.'
        }
        $networkCoverageLabel = if($connectivityImplemented){'Connectivity coverage'}elseif($connectivityEnabled){'Enabled-operation coverage finding'}else{'Local Only coverage finding'}
        $networkCoverageOutcome=if($null -ne $localOnlyFinding){[string]$localOnlyFinding.outcome}else{'Reported separately'}
        $topologyRows=@($Record.observations|Where-Object fieldId -like 'field:network.*'|ForEach-Object {
            $renderedValue=if($_.valueState -eq 'ObservedValue'){
                [Net.WebUtility]::HtmlEncode([string]$_.value)
            }else{[Net.WebUtility]::HtmlEncode([string]$_.valueState)}
            '<li><strong>'+[Net.WebUtility]::HtmlEncode([string]$_.fieldId)+
                '</strong>: '+$renderedValue+'</li>'
        })
        $probeRows=@($networkCoverage|ForEach-Object {
            '<li>'+[Net.WebUtility]::HtmlEncode([string]$_.scopeId)+': '+
                [Net.WebUtility]::HtmlEncode([string]$_.state)+' ('+
                [Net.WebUtility]::HtmlEncode([string]$_.reasonCode)+')</li>'
        })
@"
<h2>$networkModeHeading</h2>
<p>WIN-PCInfo observed only release-cataloged local Windows state. $networkModeSummary</p>
<dl><dt>Local scopes</dt><dd>$($localCoverage.Count)</dd><dt>Network-dependent scopes</dt><dd>$($networkCoverage.Count)</dd>
<dt>Local configuration finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$networkFinding.outcome))</dd>
<dt>Network component finding</dt><dd>$([Net.WebUtility]::HtmlEncode([string]$componentFinding.outcome))</dd>
<dt>$networkCoverageLabel</dt><dd>$([Net.WebUtility]::HtmlEncode($networkCoverageOutcome))</dd></dl>
<h3>Network-dependent checks not attempted</h3><ul>$($probeRows -join '')</ul>
<details><summary>Restricted local topology evidence</summary><ul>$($topologyRows -join '')</ul></details>
<p>Interface indices connect adapter, address, profile, route and resolver observations. Names are display evidence. Multiple routes do not establish which path a future connection will use. Hardware classification remains unknown when the observed interface type cannot establish it.</p>
<p>Proxy evidence covers the initiating user's Internet Settings only. WinHTTP, service-account and effective PAC settings were not assessed. Configured resolver addresses and PAC URLs were read without name resolution or script retrieval. VPN evidence covers the bounded current-user RAS phonebook only; all-user and third-party VPN registrations were not assessed. Security-component coverage remains Unsupported when no approved offline source is available.</p>
<p>Product or component names are inventory evidence only. They do not establish health, approval, reachability, trust, compliance, or future compatibility. WIN-PCInfo does not change an adapter, route, resolver, proxy, VPN, firewall, connection, or other network configuration.</p>
"@
    }else{''}
    $softwareFinding=$Record.findings|Where-Object ruleId -eq 'rule:software.machine-inventory/1.0.0'|Select-Object -First 1
    $softwareSection=if($null -ne $softwareFinding){
        if($null -eq $SoftwareInventoryPolicy){throw 'Software Inventory guidance requires its frozen policy definition.'}
        $userFinding=@($Record.findings|Where-Object ruleId -eq 'rule:software.assessment-user-inventory/1.0.0')[0]
        $softwareCoverage=@($Record.coverage|Where-Object scopeId -in @($SoftwareInventoryPolicy.scopes.scopeId))
        $softwareSubjects=@($Record.subjects|Where-Object subjectId -like 'subject:software:*')
        $hasRecognition=$null -ne $Record.PSObject.Properties['softwareRecognition']
        $recognitionItems=if($hasRecognition){@($Record.softwareRecognition)}else{@()}
        $rows=@($softwareSubjects|ForEach-Object {
            $subjectId=[string]$_.subjectId;$items=@($Record.observations|Where-Object subjectId -eq $subjectId)
            # PackageFullName remains in the canonical protected record. The
            # report uses the stable family identity instead, preserving room
            # for a bounded recognition explanation at the 128-entry ceiling.
            $lines=@($items|Where-Object {
                $_.valueState -eq 'ObservedValue' -and
                $_.fieldId -ne 'field:software.msix.package-full-name'
            }|ForEach-Object {[Net.WebUtility]::HtmlEncode([string]$_.fieldId)+': '+[Net.WebUtility]::HtmlEncode([string]$_.value)})
            if(-not $hasRecognition){return '<li>'+($lines -join '<br>')+'</li>'}
            $annotation=$recognitionItems|Where-Object subjectId -eq $subjectId|Select-Object -First 1
            if($null -eq $annotation){$annotation=[pscustomobject]@{outcome='NotEvaluated';familyLabel=$null;roles=@();matchStrengthExplanation='';catalogRevision=0;catalogRelease='2.0.0-preview.1';matcherTypes=@();provenance=@()}}
            if([string]$annotation.outcome -eq 'Unrecognized'){
                return '<li>'+($lines -join '<br>')+'<br><strong>Recognition</strong>: Unrecognized (catalog revision '+[Net.WebUtility]::HtmlEncode([string]$annotation.catalogRevision)+').</li>'
            }
            if([string]$annotation.outcome -eq 'NotEvaluated'){
                return '<li>'+($lines -join '<br>')+'<br><strong>Recognition</strong>: Not evaluated; inventory remains authoritative.</li>'
            }
            $recognitionText=switch([string]$annotation.outcome){
                'RecognizedExact' { 'Recognized family: '+[Net.WebUtility]::HtmlEncode([string]$annotation.familyLabel)+'. Roles: '+[Net.WebUtility]::HtmlEncode((@($annotation.roles)-join ', '))+'. '+[Net.WebUtility]::HtmlEncode([string]$annotation.matchStrengthExplanation)+'.' }
                'RecognizedComposite' { 'Recognized family: '+[Net.WebUtility]::HtmlEncode([string]$annotation.familyLabel)+'. Roles: '+[Net.WebUtility]::HtmlEncode((@($annotation.roles)-join ', '))+'. '+[Net.WebUtility]::HtmlEncode([string]$annotation.matchStrengthExplanation)+'.' }
                'Ambiguous' { 'Ambiguous: more than one reviewed family matched. WIN-PCInfo did not choose by catalog order; review the observed registration in its authorized context.' }
                'NotEvaluated' { 'Not evaluated; the observed inventory remains authoritative.' }
                default { 'Unrecognized in catalog revision '+[Net.WebUtility]::HtmlEncode([string]$annotation.catalogRevision)+'; this is not a warning or suspicion.' }
            }
            $sourceRows=@($annotation.provenance|ForEach-Object {
                '<li>'+[Net.WebUtility]::HtmlEncode([string]$_.sourceType)+': '+
                [Net.WebUtility]::HtmlEncode([string]$_.owner)+' ('+
                [Net.WebUtility]::HtmlEncode([string]$_.url)+'), verified '+
                [Net.WebUtility]::HtmlEncode([string]$_.verifiedOn)+'</li>'
            })
            $technicalDetail=if(@($annotation.matcherTypes).Count -gt 0 -or $sourceRows.Count -gt 0){
                '<details><summary>Catalog revision and provenance</summary><p>Catalog revision '+
                [Net.WebUtility]::HtmlEncode([string]$annotation.catalogRevision)+', release '+
                [Net.WebUtility]::HtmlEncode([string]$annotation.catalogRelease)+'. Matcher types: '+
                [Net.WebUtility]::HtmlEncode((@($annotation.matcherTypes)-join ', '))+'.</p><ul>'+($sourceRows -join '')+'</ul></details>'
            }else{''}
            '<li><strong>Observed application</strong><br>'+($lines -join '<br>')+
            '<br><strong>Recognition</strong>: '+$recognitionText+$technicalDetail+'</li>'
        })
@"
<h2>Installed software and application migration inventory</h2>
<p>Machine finding: $([Net.WebUtility]::HtmlEncode([string]$softwareFinding.outcome)). Assessment User finding: $([Net.WebUtility]::HtmlEncode([string]$userFinding.outcome)). Covered source contexts: $($softwareCoverage.Count). Distinct registrations: $($softwareSubjects.Count).</p>
<p>WIN-PCInfo reads explicit 32-bit and 64-bit uninstall registration views, inventory-only Windows Installer APIs, and Windows package identities. It never invokes Win32_Product, a consistency check, repair, install, uninstall, package-content inspection, binary hashing, profile loading, or network lookup.</p>
<p>Software recognition is an annotation, not an Assessment Finding. It adds a conservative family and migration-role label without claiming compatibility, health, licensing, safety, support, Intune readiness, Defender readiness, or deployment success. Unrecognized is not a warning or suspicion; NotEvaluated leaves ordinary inventory authoritative. Catalog revision and provenance appear with identity matches. Live WinGet package availability is not evaluated in Preview.1.</p>
<details><summary>Restricted installed-software evidence</summary><ul>$($rows -join '')</ul></details>
<p>Display name and publisher are metadata, not identity. Versions are preserved as provider text without semantic-version assumptions. An observed registration does not prove compatibility, support, licensing, safety, health, approval, or migration success; confirm retained dependencies against the target design.</p>
"@
    }else{''}
    $certificateFinding=$Record.findings|Where-Object ruleId -eq 'rule:certificate.presence/1.0.0'|Select-Object -First 1
    $certificateSection=if($null -ne $certificateFinding){
        if($null -eq $CertificateTrustPolicy){throw 'Certificate Trust guidance requires its frozen policy definition.'}
        $purposeRows=@($CertificateTrustPolicy.purposes|ForEach-Object {
            $purpose=$_;$purposeCoverage=@($Record.coverage|Where-Object scopeId -eq $purpose.scopeId)[0]
            $scopeSuffix=([string]$purpose.scopeId).Substring('scope:certificate.'.Length)
            $presenceOutcome=[string]@($Record.findings|Where-Object findingId -like "finding:certificate-presence-$scopeSuffix`:*")[0].outcome
            $validityOutcome=[string]@($Record.findings|Where-Object findingId -like "finding:certificate-validity-$scopeSuffix`:*")[0].outcome
            $trustOutcome=[string]@($Record.findings|Where-Object findingId -like "finding:certificate-trust-$scopeSuffix`:*")[0].outcome
            $keyOutcome=[string]@($Record.findings|Where-Object findingId -like "finding:certificate-key-protection-$scopeSuffix`:*")[0].outcome
            $storeContext=if(@($purpose.stores).Count){' Selected stores: '+(@($purpose.stores)-join ', ')+'.'}else{' No attributable store or service target is selected.'}
            $coverageReason=if($purposeCoverage.state -ne 'Complete'){' Coverage reason: '+[string]$purposeCoverage.reasonCode+'.'}else{''}
            '<li><strong>'+[Net.WebUtility]::HtmlEncode([string]$purpose.purposeId)+':</strong> '+
                [Net.WebUtility]::HtmlEncode([string]$purposeCoverage.state)+'. Presence: '+
                [Net.WebUtility]::HtmlEncode($presenceOutcome)+'. Validity: '+
                [Net.WebUtility]::HtmlEncode($validityOutcome)+'. Chain and trust: '+
                [Net.WebUtility]::HtmlEncode($trustOutcome)+'. Key protection: '+
                [Net.WebUtility]::HtmlEncode($keyOutcome)+'. '+
                [Net.WebUtility]::HtmlEncode([string]$purpose.limitation+$storeContext+$coverageReason)+'</li>'
        })
        $certificateSubjects=@($Record.subjects|Where-Object kind -eq Certificate)
        $certificateRows=@($certificateSubjects|ForEach-Object {
            $subjectId=[string]$_.subjectId;$items=@($Record.observations|Where-Object subjectId -eq $subjectId)
            $lines=@($items|Where-Object valueState -eq ObservedValue|ForEach-Object {
                '<strong>'+[Net.WebUtility]::HtmlEncode([string]$_.fieldId)+':</strong> '+[Net.WebUtility]::HtmlEncode([string]$_.value)
            });'<li>'+($lines -join '<br>')+'</li>'
        })
@"
<h2>Purpose-bound certificates and local trust</h2>
<p>Presence, validity dates, offline chain completeness, Windows trust, and key-protection metadata are separate observations. Each conclusion applies only to management, authentication, device identity, code trust, TLS inspection, or service connectivity as declared below; it is not a universal trust verdict.</p>
<h3>Purpose coverage and limitations</h3><ul>$($purposeRows -join '')</ul>
<details><summary>Restricted certificate metadata</summary><ul>$($certificateRows -join '')</ul></details>
<p>An inaccessible store, incomplete chain, expired certificate, or absent purpose remains an explicit coverage or advisory state. Offline evaluation disables certificate downloads and makes no revocation or remote-service claim.</p>
<p>Assessment certificate observations do not configure signing trust or Package Recipient setup. A locally trusted candidate does not approve this application or establish package-decryption access. Constrained coverage means the purpose exceeded its candidate limit; additional matching certificates were not evaluated.</p>
<p>WIN-PCInfo opens only release-selected stores as read-only. It does not request a private-key handle, export a certificate or PFX, collect a password or recovery value, import or delete a certificate, enroll or renew, or change any trust configuration. Certificate values and fingerprints remain Restricted inside this protected package.</p>
"@
    }else{''}
    $connectivityFinding=$Record.findings|Where-Object ruleId -eq 'rule:microsoft-connectivity.reachability/1.0.0'|Select-Object -First 1
    $connectivitySection=if($null -ne $connectivityFinding){
        if($null -eq $MicrosoftConnectivityPolicy){throw 'Microsoft Connectivity guidance requires its frozen policy definition.'}
        $inspectionFinding=@($Record.findings|Where-Object ruleId -eq 'rule:microsoft-connectivity.tls-inspection/1.0.0')[0]
        $connectivityCoverage=@($Record.coverage|Where-Object scopeId -in @($MicrosoftConnectivityPolicy.scopes.scopeId))
        $endpointRows=@($MicrosoftConnectivityPolicy.endpoints|ForEach-Object {
            '<li><strong>'+[Net.WebUtility]::HtmlEncode([string]$_.service)+'</strong>: '+
                [Net.WebUtility]::HtmlEncode([string]$_.dnsName)+':'+[Net.WebUtility]::HtmlEncode([string]$_.port)+
                ' ('+[Net.WebUtility]::HtmlEncode([string]$_.uri)+') using '+
                [Net.WebUtility]::HtmlEncode([string]$_.http.method)+'</li>'
        })
        $resultRows=@($Record.subjects|Where-Object subjectId -like 'subject:connectivity-endpoint:*'|ForEach-Object {
            $subjectId=[string]$_.subjectId
            $items=@($Record.observations|Where-Object subjectId -eq $subjectId)
            '<li>'+(@($items|ForEach-Object {
                [Net.WebUtility]::HtmlEncode([string]$_.fieldId)+': '+
                [Net.WebUtility]::HtmlEncode($(if($_.valueState -eq 'ObservedValue'){[string]$_.value}else{[string]$_.valueState}))
            }) -join '<br>')+'</li>'
        })
@"
<h2>Microsoft service connectivity and enrollment discovery</h2>
<p>Catalog version $([Net.WebUtility]::HtmlEncode([string]$MicrosoftConnectivityPolicy.catalogVersion)). Connectivity finding: $([Net.WebUtility]::HtmlEncode([string]$connectivityFinding.outcome)). TLS inspection finding: $([Net.WebUtility]::HtmlEncode([string]$inspectionFinding.outcome)). Covered protocol scopes: $($connectivityCoverage.Count).</p>
<p>DNS, TCP, TLS negotiation, offline certificate-chain evaluation, Windows proxy behavior, bounded HTTP metadata, and enrollment-discovery evidence are separate observations. A failure in one layer is not relabeled as a failure in another.</p>
<p>The separate DNS/TCP/TLS and chain fields describe the direct path. HTTP state describes the selected direct or static-proxy HEAD path: CertificateChainInvalid preserves that path's certificate rejection; TlsAuthenticationFailed preserves other TLS authentication failures. These do not overwrite direct-path evidence or imply a tenant authorization result.</p>
<p>Approval binds the active Windows resolver choice and a private snapshot of visible active-interface DNS servers and current-user static proxy routes. Each new protocol operation checks that snapshot again. Changed or unavailable context stops new requests. Automatic PAC/WPAD, WinHTTP/service proxy context and tenant-specific resolver policy are not inferred. Windows owns name resolution; the count describes logical protocol attempts, not packets or all delegated resolver traffic.</p>
<h3>Exact generic targets approved before collection</h3><ul>$($endpointRows -join '')</ul>
<details><summary>Restricted per-endpoint connectivity evidence</summary><ul>$($resultRows -join '')</ul></details>
<p>TLS inspection is Confirmed only with independent proxy-policy and certificate-path corroboration; Suspected, NotObservedWithinCompletedTests, and Indeterminate remain distinct. A certificate difference alone is not confirmation.</p>
<p>The probes send no credentials, tenant identifier, collected evidence, cookies, or request body; follow no redirects; perform no packet capture; and change no network setting. Local Only materializes no endpoint and performs zero outbound requests.</p>
<p>These generic probes do not test a tenant-specific enrollment CNAME, authenticate to Microsoft, prove enrollment or compliance, cover every regional Microsoft service endpoint, or guarantee future reachability.</p>
"@
    }else{''}
    $crossDomainPolicy = $null
    $crossDomainModel = $null
    $crossDomainSection = if (@($Record.findings | Where-Object ruleId -like 'rule:cross-domain.*').Count -gt 0) {
        if ($null -eq $MicrosoftConnectivityPolicy) {
            throw 'Cross-domain guidance requires the full-profile policy set.'
        }
        $crossDomainPolicy = Get-CrossDomainGuidancePolicy -ConvertFromJsonCommand (
            $ExecutionContext.InvokeCommand.GetCommand(
                'ConvertFrom-Json',
                [System.Management.Automation.CommandTypes]::Cmdlet
            )
        )
        $crossDomainModel = Get-CrossDomainGuidanceModel -Record $Record -Policy $crossDomainPolicy
        New-CrossDomainGuidanceHtml -Record $Record -Policy $crossDomainPolicy
    }
    else { '' }
    $definitionLookup = Get-AssessmentReportDefinitionLookup `
        -FirmwarePolicy $FirmwarePolicy `
        -IdentityEnrollmentPolicy $IdentityEnrollmentPolicy `
        -EffectivePolicyPolicy $EffectivePolicyPolicy `
        -ResourceDependenciesPolicy $ResourceDependenciesPolicy `
        -NetworkTopologyPolicy $NetworkTopologyPolicy `
        -SoftwareInventoryPolicy $SoftwareInventoryPolicy `
        -CertificateTrustPolicy $CertificateTrustPolicy `
        -MicrosoftConnectivityPolicy $MicrosoftConnectivityPolicy `
        -CrossDomainPolicy $crossDomainPolicy
    $assessmentRecommendations = Get-AssessmentReportRecommendationDetails `
        -Record $Record -DefinitionLookup $definitionLookup -Kind AssessmentRecommendation
    $tenantTasks = Get-AssessmentReportRecommendationDetails `
        -Record $Record -DefinitionLookup $definitionLookup -Kind TenantSideDiscoveryTask
    $prioritizedResults = Get-AssessmentReportPrioritizedResults -Record $Record `
        -CrossDomainModel $crossDomainModel
    $reportOutcome = Get-AssessmentReportOutcomeLabel -Outcome ([string] $Record.run.outcome)
    $reportCompleteness = Get-AssessmentReportCompleteness -Record $Record
    $incompleteCoverage = @($Record.coverage | Where-Object state -ne 'Complete')
    $limitationItems = @(
        'This report uses only the validated local Assessment Record plus release-defined rendering inputs. It is advisory and does not provide a compliance verdict, overall score, or automatic remediation.'
        $(if ($incompleteCoverage.Count -gt 0) {
                "$($incompleteCoverage.Count) coverage scope(s) were not complete. Review Diagnostics and the detailed evidence sections before changing device or tenant state."
            }
            else {
                'All admitted coverage scopes completed, but the report still preserves bounded platform limitations and confidence notes.'
            })
        $(if ($null -ne $MicrosoftConnectivityPolicy -and
                @($Record.coverage | Where-Object scopeId -eq 'scope:microsoft-connectivity.tcp').Count -gt 0 -and
                @($Record.observations | Where-Object {
                    $_.fieldId -like 'field:microsoft-connectivity.endpoint*'
                }).Count -eq 0) {
                'The approved network behavior was Local Only, so Microsoft service reachability was not attempted and remains separate from local device findings.'
            }
            else {
                'Tenant-specific cloud identity, enrollment ownership, licensing, and organization intent remain outside the local evidence boundary.'
            })
    )
    $limitationRows = @($limitationItems | ForEach-Object {
        '<li>' + [Net.WebUtility]::HtmlEncode([string] $_) + '</li>'
    })
    $priorityRows = if (@($prioritizedResults).Count -gt 0) {
        @($prioritizedResults | ForEach-Object {
            '<li><strong>' + [Net.WebUtility]::HtmlEncode([string] $_.title) + '</strong>' +
                '<br><strong>Finding:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.finding) +
                '<br><strong>Severity:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.severity) +
                '<br><strong>Confidence:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.confidence) +
                '<br><strong>Recommendation:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.recommendation) + '</li>'
        })
    }
    else {
        @('<li><strong>No prioritized advisory result was derived.</strong><br><strong>Finding:</strong> Informational<br><strong>Severity:</strong> Not assigned<br><strong>Confidence:</strong> High<br><strong>Recommendation:</strong> Review the detailed sections only if you need the underlying evidence.</li>')
    }
    $assessmentRecommendationRows = if (@($assessmentRecommendations).Count -gt 0) {
        @($assessmentRecommendations | ForEach-Object {
            '<li><strong>' + [Net.WebUtility]::HtmlEncode([string] $_.title) + '</strong>' +
                '<br><strong>Purpose:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.purpose) +
                $(if ($_.priority) {
                        '<br><strong>Priority:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.priority)
                    }
                    else { '' }) +
                $(if ($_.priorityExplanation) {
                        '<br><strong>Why now:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.priorityExplanation)
                    }
                    else { '' }) +
                $(if ($_.role) {
                        '<br><strong>Owner:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.role)
                    }
                    else { '' }) +
                $(if ($_.verification) {
                        '<br><strong>Verification:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.verification)
                    }
                    else { '' }) +
                $(if ($_.caution) {
                        '<br><strong>Caution:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.caution)
                    }
                    else { '' }) + '</li>'
        })
    }
    else { @('<li>No additional Assessment Recommendation is required by the current findings.</li>') }
    $tenantTaskRows = if (@($tenantTasks).Count -gt 0) {
        @($tenantTasks | ForEach-Object {
            '<li><strong>' + [Net.WebUtility]::HtmlEncode([string] $_.title) + '</strong>' +
                '<br><strong>Purpose:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.purpose) +
                $(if ($_.role) {
                        '<br><strong>Owner:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.role)
                    }
                    else { '' }) + '</li>'
        })
    }
    else { @('<li>No Tenant-side Discovery Task is currently required.</li>') }
    $diagnosticRows = if (@($Record.diagnostics).Count -gt 0) {
        @($Record.diagnostics | ForEach-Object {
            '<li>' + [Net.WebUtility]::HtmlEncode([string] $_.reasonCode) + '</li>'
        })
    }
    else { @('<li>No diagnostic reason code was recorded.</li>') }
    $scopeSummary = 'Comprehensive Local Assessment for one Windows client across device, identity, privilege, policy, applications, user dependencies, network, certificate trust, Microsoft connectivity, and cautious migration guidance.'
    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WIN-PCInfo Comprehensive Local Assessment</title>
<style>
:root { color-scheme: light; font-family: "Segoe UI", Tahoma, sans-serif; line-height: 1.45; }
body { margin: 0 auto; max-width: 8.5in; padding: 1.25rem; color: #14213d; background: #f7f4ea; }
a { color: #0a558c; }
.skip-link { position: absolute; left: 0.75rem; top: -3rem; background: #ffffff; padding: 0.5rem 0.75rem; border: 2px solid #14213d; }
.skip-link:focus-visible { top: 0.75rem; }
nav { margin: 1rem 0; padding: 0.75rem 1rem; border: 1px solid #c8b88a; background: #fffdf6; }
nav ul { margin: 0; padding-left: 1.25rem; }
section, details, nav, header { margin-bottom: 1rem; }
h1, h2, h3 { color: #1d3557; }
details { border: 1px solid #d4c39b; background: #fffdf8; padding: 0.5rem 0.75rem; }
summary { cursor: pointer; font-weight: 600; }
:focus-visible { outline: 3px solid #b85c38; outline-offset: 2px; }
@page { margin: 12mm; }
@media print {
  body { max-width: none; background: #ffffff; color: #000000; padding: 0; font-size: 10pt; }
  nav { border: 1px solid #555555; background: #ffffff; }
  details { break-inside: avoid; border-color: #777777; }
}
</style>
</head>
<body>
<a class="skip-link" href="#report-content">Skip to report content</a>
<header>
<p>WIN-PCInfo report format: self-contained English HTML for offline viewing and print.</p>
<h1>WIN-PCInfo Comprehensive Local Assessment</h1>
<p>$summary</p>
<p>This report preserves observations, findings, confidence, severity, limitations, recommendations, diagnostics, and Tenant-side Discovery Tasks as separate categories. It remains usable without scripting and does not load external assets or services.</p>
</header>
<nav aria-label="Primary report navigation">
<ul>
<li><a href="#overview">Executive summary</a></li>
<li><a href="#next-steps">Next steps</a></li>
<li><a href="#diagnostics">Diagnostics</a></li>
<li><a href="#evidence">Evidence and provenance</a></li>
</ul>
</nav>
<main id="report-content">
<section id="overview">
<h2>Outcome</h2>
<p>$([Net.WebUtility]::HtmlEncode($reportOutcome))</p>
<h2>Scope</h2>
<p>$([Net.WebUtility]::HtmlEncode($scopeSummary))</p>
<h2>Completeness</h2>
<p>$([Net.WebUtility]::HtmlEncode($reportCompleteness))</p>
<h2>Limitations</h2>
<ul>$($limitationRows -join '')</ul>
<h2>Prioritized advisory results</h2>
<ul>$($priorityRows -join '')</ul>
<h2>Next steps</h2>
<h3>Assessment Recommendations</h3>
<ul>$($assessmentRecommendationRows -join '')</ul>
<h3>Tenant-side Discovery Tasks</h3>
<ul>$($tenantTaskRows -join '')</ul>
</section>
<section id="diagnostics">
<h3>Diagnostics</h3>
<ul>$($diagnosticRows -join '')</ul>
</section>
<section id="evidence">
<h2>Evidence and provenance</h2>
<p><strong>Observations:</strong> The detailed sections below preserve bounded Windows observations and provenance without relabeling them as findings.</p>
<h2>Device, Windows, activation, and power context</h2><p>$summary</p>
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
$networkSection
$softwareSection
$certificateSection
$connectivitySection
$crossDomainSection
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
</details>
</section>
</main>
</body>
</html>
"@
    [System.Text.UTF8Encoding]::new($false).GetBytes($html.Replace("`r`n", "`n"))
}

function New-DeviceReadinessTerminalRecord {
    param(
        [Parameter(Mandatory)] [string] $Outcome,
        [Parameter(Mandatory)] [int] $ExitCode,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [bool] $CollectionStarted,
        [Parameter(Mandatory)] [bool] $ValidationFixture,
        [Parameter(Mandatory)] [bool] $CleanupVerified,
        [Parameter(Mandatory)] [string] $RequestDigest,
        [Parameter(Mandatory)] [string] $PlanDigest
    )

    [pscustomobject][ordered]@{
        recordType='win-pcinfo.terminal'; contractVersion='1.0.0'; outcome=$Outcome
        exitCode=$ExitCode; reasonCode=$ReasonCode; phase='DeviceReadiness'
        collectionStarted=$CollectionStarted; requestDigest=$RequestDigest
        planDigest=$PlanDigest; preparationDecision='Accepted'
        validationFixture=$ValidationFixture
        cleanup=[pscustomobject][ordered]@{required=$true;verified=$CleanupVerified}
    }
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
    Write-ContractRecord (New-DeviceReadinessTerminalRecord `
        -Outcome $Outcome -ExitCode $ExitCode -ReasonCode $ReasonCode `
        -CollectionStarted $CollectionStarted -ValidationFixture $ValidationFixture `
        -CleanupVerified $CleanupVerified -RequestDigest $RequestDigest `
        -PlanDigest $PlanDigest) -ConvertToJsonCommand $ConvertToJsonCommand
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
        [Parameter(Mandatory)] [Alias('ValidationCleanupVerified')] [bool] $CleanupVerified,
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
        (-not $CleanupVerified) -or
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
        'RUN.CANCELLED' {
            [pscustomobject]@{outcome='Cancelled';exitCode=30;reasonCode=$ReasonCode;cleanupVerified=$true}
        }
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
        'NETWORK.COLLECTOR_CLEANUP_INCOMPLETE' {
            [pscustomobject]@{outcome='CleanupIncomplete';exitCode=60;reasonCode=$ReasonCode;cleanupVerified=$false}
        }
        'SOFTWARE.COLLECTOR_CLEANUP_INCOMPLETE' {
            [pscustomobject]@{outcome='CleanupIncomplete';exitCode=60;reasonCode=$ReasonCode;cleanupVerified=$false}
        }
        'CERTIFICATE.COLLECTOR_CLEANUP_INCOMPLETE' {
            [pscustomobject]@{outcome='CleanupIncomplete';exitCode=60;reasonCode=$ReasonCode;cleanupVerified=$false}
        }
        'CONNECTIVITY.COLLECTOR_CLEANUP_INCOMPLETE' {
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

function Get-DeviceReadinessSliceSelection {
    param(
        [bool]$DeviceFixture,[bool]$IdentityFixture,[bool]$AdministratorFixture,
        [bool]$EffectivePolicyFixture,[bool]$ResourceFixture,[bool]$NetworkFixture,[bool]$SoftwareFixture,[bool]$CertificateFixture,[bool]$ConnectivityFixture,
        [string]$NetworkBehavior
    )
    $isFixture=$DeviceFixture -or $IdentityFixture -or $AdministratorFixture -or
        $EffectivePolicyFixture -or $ResourceFixture -or $NetworkFixture -or $SoftwareFixture -or $CertificateFixture -or $ConnectivityFixture
    $dependentFixture=$IdentityFixture -or $AdministratorFixture -or
        $EffectivePolicyFixture -or $ResourceFixture -or $NetworkFixture -or $SoftwareFixture -or $CertificateFixture -or $ConnectivityFixture
    [pscustomobject][ordered]@{
        isFixture=$isFixture;usesSyntheticPrerequisites=$dependentFixture
        identityRequested=$dependentFixture -or -not $isFixture
        administratorRequested=$AdministratorFixture -or $EffectivePolicyFixture -or
            $ResourceFixture -or $NetworkFixture -or $SoftwareFixture -or $CertificateFixture -or $ConnectivityFixture -or -not $isFixture
        effectivePolicyRequested=$EffectivePolicyFixture -or $ResourceFixture -or
            $NetworkFixture -or $SoftwareFixture -or $CertificateFixture -or $ConnectivityFixture -or -not $isFixture
        resourceRequested=$ResourceFixture -or $NetworkFixture -or $SoftwareFixture -or $CertificateFixture -or $ConnectivityFixture -or -not $isFixture
        networkRequested=$NetworkFixture -or $SoftwareFixture -or $CertificateFixture -or $ConnectivityFixture -or -not $isFixture
        softwareRequested=$SoftwareFixture -or $CertificateFixture -or $ConnectivityFixture -or -not $isFixture
        certificateRequested=$CertificateFixture -or $ConnectivityFixture -or -not $isFixture
        connectivityRequested=$ConnectivityFixture -or -not $isFixture
    }
}

function Get-CombinedAssessmentContractSetVersion {
    param($ConnectivityCollector,$CertificateCollector,$SoftwareCollector,$NetworkCollector,$ResourceCollector,$EffectivePolicyCollector,$AdministratorCollector,$IdentityCollector)
    if($null -ne $ConnectivityCollector){'1.13.0'}
    elseif($null -ne $CertificateCollector){'1.13.0'}
    elseif($null -ne $SoftwareCollector){'1.13.0'}
    elseif($null -ne $NetworkCollector){'1.13.0'}
    elseif($null -ne $ResourceCollector){'1.13.0'}
    elseif($null -ne $EffectivePolicyCollector){'1.13.0'}
    elseif($null -ne $AdministratorCollector){'1.3.0'}
    elseif($null -ne $IdentityCollector){'1.2.0'}else{'1.1.0'}
}

function Invoke-DeviceReadinessSlice {
    param(
        [Parameter()] [string] $LiteralPath,
        [Parameter()] [string] $IdentityEnrollmentLiteralPath,
        [Parameter()] [string] $AdministratorExposureLiteralPath,
        [Parameter()] [string] $EffectivePolicyLiteralPath,
        [Parameter()] [string] $ResourceDependenciesLiteralPath,
        [Parameter()] [string] $NetworkTopologyLiteralPath,
        [Parameter()] [string] $SoftwareInventoryLiteralPath,
        [Parameter()] [string] $CertificateTrustLiteralPath,
        [Parameter()] [string] $MicrosoftConnectivityLiteralPath,
        [Parameter()] $ConnectivityContext,
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
    $isNetworkTopologyFixture = -not [string]::IsNullOrWhiteSpace($NetworkTopologyLiteralPath)
    $isSoftwareInventoryFixture = -not [string]::IsNullOrWhiteSpace($SoftwareInventoryLiteralPath)
    $isCertificateTrustFixture = -not [string]::IsNullOrWhiteSpace($CertificateTrustLiteralPath)
    $isMicrosoftConnectivityFixture = -not [string]::IsNullOrWhiteSpace($MicrosoftConnectivityLiteralPath)
    $sliceSelection=Get-DeviceReadinessSliceSelection `
        -DeviceFixture $isDeviceFixture -IdentityFixture $isIdentityFixture `
        -AdministratorFixture $isAdministratorFixture `
        -EffectivePolicyFixture $isEffectivePolicyFixture `
        -ResourceFixture $isResourceDependenciesFixture `
        -NetworkFixture $isNetworkTopologyFixture `
        -SoftwareFixture $isSoftwareInventoryFixture `
        -CertificateFixture $isCertificateTrustFixture `
        -ConnectivityFixture $isMicrosoftConnectivityFixture `
        -NetworkBehavior ([string]$PreparationPlan.network.behavior)
    $isFixture=[bool]$sliceSelection.isFixture
    $scenario = if ($isFixture) { '' } else { 'Actual' }
    $firmwareScenario = if ($isFixture) { 'None' } else { 'Live' }
    $privilegeScenario = if ($isFixture) { 'None' } else { 'Live' }
    $policy = $null; $firmwarePolicy = $null; $identityPolicy = $null
    $administratorPolicy=$null;$administratorCollector=$null
    $effectivePolicy=$null;$effectivePolicyCollector=$null
    $resourcePolicy=$null;$resourceCollector=$null
    $networkPolicy=$null;$networkCollector=$null
    $softwarePolicy=$null;$softwareCollector=$null
    $certificatePolicy=$null;$certificateCollector=$null
    $connectivityPolicy=$null;$connectivityCollector=$null
    $crossDomainPolicy = $null
    $recognitionCatalogResult=$null
    $privilegeResult = $null; $identityCollector = $null; $systemResult = $null
    $firmwareCollector = $null; $boundary = $null; $opened = $null; $package = $null
    $cleanupVerified = $true; $recordAccepted = $false; $reportVerified = $false
    $packageVerified = $false; $coverageState = 'Unavailable'; $findingOutcome = 'Indeterminate'
    $reportDeterministic = $false; $reportExecutiveSummaryVerified = $false
    $reportCategorySeparationVerified = $false; $reportOfflineSafeVerified = $false
    $reportKeyboardNavigationVerified = $false; $reportPrintLayoutVerified = $false
    $reportUtf8Verified = $false; $reportUnicodePreservedVerified = $false
    $reportRenderedCompleteness = 'RecoverablePartial'
    $reportWithinPackageBound = $false; $packageManifestConsistent = $false
    $completionSummaryConsistent = $false
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
    $securityControlFinding='Indeterminate';$securityControlConstraintFinding='Indeterminate'
    $antivirusProviderCount=0;$firewallProfileCount=0;$asrRuleCount=0
    $bitLockerProtectorTypeCount=0;$wdacPolicyCount=0
    $appLockerGpCollectionCount=0;$appLockerCspCollectionCount=0
    $mdmPolicyCspFinding='Indeterminate';$policyCspGpoConflictFinding='Indeterminate'
    $policyDiscoveryTaskCount=0
    $resourceScenario=if($isResourceDependenciesFixture){''}else{'Live'}
    $userResourceCoverage='NotAttempted';$peripheralCoverage='NotAttempted'
    $mappedDriveCount=0;$uncConnectionCount=0;$printerCount=0
    $printerDriverCount=0;$peripheralCount=0
    $userResourceFinding='Indeterminate';$peripheralFinding='Indeterminate'
    $networkScenario=if($isNetworkTopologyFixture){''}else{'Live'}
    $softwareScenario=if($isSoftwareInventoryFixture){''}else{'Live'}
    $certificateScenario=if($isCertificateTrustFixture){''}else{'Live'}
    $connectivityScenario=if($isMicrosoftConnectivityFixture){''}else{'Live'}
    $softwareMachineCoverage='NotAttempted';$softwareUserCoverage='NotAttempted'
    $softwareMachineFinding='Indeterminate';$softwareUserFinding='Indeterminate'
    $softwareContractReason='NotEvaluated'
    $certificatePurposeCoverage='NotAttempted';$certificatePresenceFinding='Indeterminate'
    $certificateValidityFinding='Indeterminate';$certificateTrustFinding='Indeterminate'
    $recognitionScenario='Evaluate';$recognitionAnnotationCount=0
    $recognizedExactCount=0;$recognizedCompositeCount=0;$ambiguousCount=0
    $unrecognizedCount=0;$notEvaluatedCount=0
    $localNetworkCoverage='NotAttempted';$networkDependentCoverage='NotAttempted'
    $networkConfigurationFinding='Indeterminate';$networkComponentFinding='Indeterminate'
    $networkAdapterCount=0;$networkProfileCount=0;$networkRouteCount=0;$networkResolverCount=0
    $vpnComponentCount=0;$securityComponentCount=0;$localConnectionCount=0;$outboundRequestCount=0
    $collectionStarted = $false
    $packageCompleteness = 'RecoverablePartial'
    $completionSummary = $null
    $terminalRecord = $null
    $sliceStage='POLICY'
    $outcome = 'CompletedWithGaps'; $exitCode = 10; $reasonCode = 'DEVICE_READINESS.EVIDENCE_UNAVAILABLE'
    $activeLock = $null
    $lockOwned = $false
    $runJournal = $null
    $runWorkspace = $null
    $abandonedLock = $false
    $script:AssessmentCollectionSequence = 4
    try {
        $activeLock = [Threading.Mutex]::new($false, [string](Get-AssessmentRunLifecyclePolicy).activeRunLock.name)
        $lockOwned = $false
        try { $lockOwned = $activeLock.WaitOne(0) }
        catch [Threading.AbandonedMutexException] {
            # Windows transferred the abandoned lock to this thread. Keep it
            # while inspecting durable ownership, never silently resume collection.
            $lockOwned = $true
            $abandonedLock = $true
        }
        if (-not $lockOwned) {
            # The common finally disposes the lock.
            Write-DeviceReadinessTerminal -Outcome NotStarted -ExitCode 20 -ReasonCode 'RUN.ACTIVE_LOCK_HELD' `
                -CollectionStarted $false -ValidationFixture $false -CleanupVerified $true `
                -RequestDigest $RequestDigest -PlanDigest $PlanDigest -ConvertToJsonCommand $ConvertToJsonCommand
            return 20
        }
        if (-not $isFixture) {
            $destination = [IO.Path]::GetFullPath($ApprovedOutputDestination)
            $recovery = Invoke-AssessmentRecoveryGate -Destination $destination `
                -Authorized ([bool]$PreparationPlan.cleanup.staleRunRecovery.requested)
            if ($abandonedLock -and $null -eq $recovery) {
                $recovery = New-StaleRunRecoveryResult -Outcome CleanupIncomplete -ReasonCode RECOVERY.OWNER_UNVERIFIED `
                    -CleanupVerified $false -CleanupAttempts 0
            }
            if ($null -ne $recovery) {
                $recoveryExit = if ($recovery.outcome -eq 'CleanupIncomplete') { 60 } else { 20 }
                Write-DeviceReadinessTerminal -Outcome $recovery.outcome -ExitCode $recoveryExit -ReasonCode $recovery.reasonCode `
                    -CollectionStarted $false -ValidationFixture $false -CleanupVerified $recovery.cleanup.verified `
                    -RequestDigest $RequestDigest -PlanDigest $PlanDigest -ConvertToJsonCommand $ConvertToJsonCommand
                return $recoveryExit
            }
            $null = [IO.Directory]::CreateDirectory($destination)
            $runWorkspace = New-EvidenceWorkspace -RequestedBasePath $destination -RunId ([guid]::NewGuid())
            if ($runWorkspace.state -ne 'Created') { throw 'The approved Evidence Workspace could not be created.' }
            $runJournal = New-RunRecoveryJournal -Workspace $runWorkspace -RecoveryBasePath $destination `
                -PlanDigest $PlanDigest -Phase Collection
            $script:AssessmentRunJournalPath = [string]$runJournal.journalPath
        }
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
        $networkPolicy=Get-NetworkTopologyPolicy -ConvertFromJsonCommand $ConvertFromJsonCommand
        $softwarePolicy=Get-SoftwareInventoryPolicy -ConvertFromJsonCommand $ConvertFromJsonCommand
        $certificatePolicy=Get-CertificateTrustPolicy -ConvertFromJsonCommand $ConvertFromJsonCommand
        $connectivityPolicy=Get-MicrosoftConnectivityPolicy -ConvertFromJsonCommand $ConvertFromJsonCommand
        $crossDomainPolicy=Get-CrossDomainGuidancePolicy -ConvertFromJsonCommand $ConvertFromJsonCommand
        $recognitionCatalogResult=Get-SoftwareRecognitionCatalog `
            -ConvertFromJsonCommand $ConvertFromJsonCommand `
            -TestJsonCommand $TestJsonCommand
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
        elseif($isNetworkTopologyFixture){
            $scenario='Complete';$firmwareScenario='Supported';$identityScenario='StandardUser'
            $administratorScenario='LocalPrincipal';$effectivePolicyScenario='Workgroup'
            $resourceScenario='Empty';$privilegeScenario='AcceptedElevation'
            $networkScenario=Read-NetworkTopologyFixture -LiteralPath $NetworkTopologyLiteralPath `
                -ConvertFromJsonCommand $ConvertFromJsonCommand -Policy $networkPolicy
        }
        elseif($isSoftwareInventoryFixture){
            $scenario='Complete';$firmwareScenario='Supported';$identityScenario='StandardUser'
            $administratorScenario='LocalPrincipal';$effectivePolicyScenario='Workgroup'
            $resourceScenario='Empty';$networkScenario='Empty';$privilegeScenario='AcceptedElevation'
            $softwareFixtureSelection=Read-SoftwareInventoryFixture -LiteralPath $SoftwareInventoryLiteralPath `
                -ConvertFromJsonCommand $ConvertFromJsonCommand -Policy $softwarePolicy
            $softwareScenario=[string]$softwareFixtureSelection.inventoryScenario
            $recognitionScenario=[string]$softwareFixtureSelection.recognitionScenario
            if($recognitionScenario -eq 'LogicalFailure'){
                $recognitionCatalogResult.logicalLoadValid=$false
            }
        }
        elseif($isCertificateTrustFixture){
            $firmwareScenario='Supported';$identityScenario='StandardUser'
            $administratorScenario='LocalPrincipal';$effectivePolicyScenario='Workgroup'
            $resourceScenario='Empty';$networkScenario='Empty';$softwareScenario='Empty'
            $privilegeScenario='AcceptedElevation'
            $certificateScenario=Read-CertificateTrustFixture -LiteralPath $CertificateTrustLiteralPath `
                -ConvertFromJsonCommand $ConvertFromJsonCommand -Policy $certificatePolicy
            $scenario=if($certificateScenario -eq 'VirtualDevice'){'Virtual'}else{'Complete'}
        }
        elseif($isMicrosoftConnectivityFixture){
            $scenario='Complete';$firmwareScenario='Supported';$identityScenario='StandardUser'
            $administratorScenario='LocalPrincipal';$effectivePolicyScenario='Workgroup'
            $resourceScenario='Empty';$networkScenario='Empty';$softwareScenario='Empty'
            $certificateScenario='ValidTrusted';$privilegeScenario='AcceptedElevation'
            $connectivityScenario=Read-MicrosoftConnectivityFixture `
                -LiteralPath $MicrosoftConnectivityLiteralPath `
                -ConvertFromJsonCommand $ConvertFromJsonCommand -Policy $connectivityPolicy
        }
        $identityRequested=[bool]$sliceSelection.identityRequested
        $administratorRequested=[bool]$sliceSelection.administratorRequested
        $effectivePolicyRequested=[bool]$sliceSelection.effectivePolicyRequested
        $resourceRequested=[bool]$sliceSelection.resourceRequested
        $networkRequested=[bool]$sliceSelection.networkRequested
        $softwareRequested=[bool]$sliceSelection.softwareRequested
        $certificateRequested=[bool]$sliceSelection.certificateRequested
        $connectivityRequested=[bool]$sliceSelection.connectivityRequested
        $firmwareRequested = -not $isFixture -or $firmwareScenario -ne 'None'
        $sliceStage='PRIVILEGE'
        if (($firmwareRequested -or $administratorRequested -or $effectivePolicyRequested) -and (Enter-AssessmentCollectionStageIfActive -Stage Privilege)) {
            $systemPlanResult=if ($identityRequested) {
                New-SystemCollectionPlan -PreparationPlan $PreparationPlan -PreparationPlanDigest $PlanDigest
            } else { $null }
            # Resolve only the coordination identity before collection. An
            # elevated or SYSTEM coordinator cannot invent a standard user.
            $initiatingIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
            try {
                $initiatingPrincipal=[Security.Principal.WindowsPrincipal]::new($initiatingIdentity)
                $assessmentSid=if ($initiatingIdentity.User.Value -ne 'S-1-5-18' -and
                    -not $initiatingPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                    [string]$initiatingIdentity.User.Value
                } else { '' }
            } finally { $initiatingIdentity.Dispose() }
            $privilegeResult = Invoke-PrivilegedCollectionPlan `
                -PreparationPlan $PreparationPlan -PlanDigest $PlanDigest `
                -AssessmentUserContext 'subject:assessment-user:primary' `
                -AssessmentUserSid $assessmentSid `
                -LocalPackageProtector 'protector:initiating-windows-user' `
                -ValidationScenario $privilegeScenario -FirmwareScenario $firmwareScenario -CancellationToken (Get-AssessmentCancellationToken) `
                -AdministratorScenario $(if($administratorRequested){$administratorScenario}else{'None'}) `
                -EffectivePolicyScenario $(if($effectivePolicyRequested){$effectivePolicyScenario}else{'None'}) `
                -SystemPlanResult $systemPlanResult -SystemValidationScenario $(
                    if($isEffectivePolicyFixture -and $effectivePolicyScenario -eq 'DeniedSystem'){'Denied'}
                    elseif([bool]$sliceSelection.usesSyntheticPrerequisites){'SyntheticSuccess'}else{''})
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
                elseif ($privilegeResult.state -in @('Unavailable','Cancelled')) {
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
                }elseif($privilegeResult.state -in @('Unavailable','Cancelled')){
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
                }elseif($privilegeResult.state -in @('Unavailable','Cancelled')){
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
        if($identityRequested -and $null -ne $privilegeResult){
            $sliceStage='SYSTEM_IDENTITY'
            if ($privilegeResult.PSObject.Properties['PrivateSystemResult']) {
                $systemResult=$privilegeResult.PrivateSystemResult
            } else {
                $systemResult=New-SystemCollectionStoppedResult `
                    -State $(if($privilegeResult.state -eq 'Cancelled'){'Cancelled'}else{'Unavailable'}) `
                    -ReasonCode $(if($privilegeResult.state -eq 'Cancelled'){'SYSTEM.CANCELLED_BEFORE_ACTIVATION'}else{'SYSTEM.ACTIVATION_DENIED'}) `
                    -CoverageState $(if($privilegeResult.state -eq 'Cancelled'){'Cancelled'}else{'Denied'}) -Context @{
                        Policy=(Get-SystemCollectionPlanPolicy); Plan=$systemPlanResult.Plan
                        PlanDigest=$systemPlanResult.Digest; ObservedExecutionContext='NotStarted'
                    }
            }
            if($isEffectivePolicyFixture -and $null -ne $systemResult -and
                $systemResult.state -in @('Completed','CompletedWithGaps')){
                $systemResult.PrivatePolicyCspResults =
                    New-EffectivePolicySyntheticPolicyCspResults -Scenario $effectivePolicyScenario
            }
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
        if($identityRequested -and (Enter-AssessmentCollectionStageIfActive -Stage identity)){
            $sliceStage='IDENTITY'
            $identityCollector=if([bool]$sliceSelection.usesSyntheticPrerequisites){
                Invoke-IdentityEnrollmentCollection -Policy $identityPolicy `
                    -ValidationScenario $identityScenario
            }else{Invoke-IdentityEnrollmentCollection -Policy $identityPolicy -Live}
            $processRelationship=[string]$identityCollector.processRelationship
            $collectionStarted=$true
            if($null -ne $effectivePolicyCollector -and -not [bool]$sliceSelection.usesSyntheticPrerequisites){
                Confirm-EffectivePolicyAssessmentUser -CollectorResult $effectivePolicyCollector `
                    -IdentityCollector $identityCollector -Policy $effectivePolicy -RequestedSid $assessmentSid `
                    -SessionId ([Diagnostics.Process]::GetCurrentProcess().SessionId)
            }
        }
        if($resourceRequested -and (Enter-AssessmentCollectionStageIfActive -Stage resource)){
            $sliceStage='RESOURCE_DEPENDENCIES'
            $resourceCollector=if([bool]$sliceSelection.usesSyntheticPrerequisites){
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
        if($networkRequested -and (Enter-AssessmentCollectionStageIfActive -Stage network)){
            $sliceStage='NETWORK_TOPOLOGY'
            $networkCollector=if([bool]$sliceSelection.usesSyntheticPrerequisites){
                Invoke-NetworkTopologyCollection -Policy $networkPolicy `
                    -ValidationScenario $networkScenario `
                    -NetworkBehavior ([string]$PreparationPlan.network.behavior)
            }else{
                Invoke-NetworkTopologyCollection -Policy $networkPolicy -Live `
                    -NetworkBehavior ([string]$PreparationPlan.network.behavior) `
                    -AssessmentUserSid $(if($null -ne $identityCollector){[string]$identityCollector.privateAssessmentUserSid}else{''})
            }
            $collectionStarted=$true
            if(-not [bool]$networkCollector.cleanupVerified){$exception=[InvalidOperationException]::new('The Network Topology worker cleanup was not verified.');$exception.Data['ReasonCode']='NETWORK.COLLECTOR_CLEANUP_INCOMPLETE';throw $exception}
        }
        if($softwareRequested -and (Enter-AssessmentCollectionStageIfActive -Stage software)){
            $sliceStage='SOFTWARE_INVENTORY'
            $softwareCollector=if([bool]$sliceSelection.usesSyntheticPrerequisites){
                Invoke-SoftwareInventoryCollection -Policy $softwarePolicy -ValidationScenario $softwareScenario
            }else{
                Invoke-SoftwareInventoryCollection -Policy $softwarePolicy -Live `
                    -AssessmentUserSid $(if($null -ne $identityCollector){[string]$identityCollector.privateAssessmentUserSid}else{''})
            }
            $collectionStarted=$true
            if(-not [bool]$softwareCollector.cleanupVerified){$exception=[InvalidOperationException]::new('The Software Inventory worker cleanup was not verified.');$exception.Data['ReasonCode']='SOFTWARE.COLLECTOR_CLEANUP_INCOMPLETE';throw $exception}
        }
        if($certificateRequested -and (Enter-AssessmentCollectionStageIfActive -Stage certificate)){
            $sliceStage='CERTIFICATE_TRUST'
            $certificateCollector=if([bool]$sliceSelection.usesSyntheticPrerequisites){
                Invoke-CertificateTrustCollection -Policy $certificatePolicy -ValidationScenario $certificateScenario
            }else{
                Invoke-CertificateTrustCollection -Policy $certificatePolicy -Live `
                    -AssessmentUserSid $(if($null -ne $identityCollector){[string]$identityCollector.privateAssessmentUserSid}else{''})
            }
            $collectionStarted=$true
            if(-not [bool]$certificateCollector.cleanupVerified){$exception=[InvalidOperationException]::new('The Certificate Trust cleanup was not verified.');$exception.Data['ReasonCode']='CERTIFICATE.COLLECTOR_CLEANUP_INCOMPLETE';throw $exception}
        }
        if($connectivityRequested -and (Enter-AssessmentCollectionStageIfActive -Stage connectivity)){
            $sliceStage='MICROSOFT_CONNECTIVITY'
            $connectivityCollector=if([bool]$sliceSelection.usesSyntheticPrerequisites){
                Invoke-MicrosoftConnectivityCollection -Policy $connectivityPolicy `
                    -ValidationScenario $connectivityScenario `
                    -NetworkBehavior ([string]$PreparationPlan.network.behavior)
            }else{
                Invoke-MicrosoftConnectivityCollection -Policy $connectivityPolicy -Live `
                    -ConnectivityContext $ConnectivityContext `
                    -ContextDigest $(if($null -ne $PreparationPlan.network.context){[string]$PreparationPlan.network.context.snapshotDigest}else{''}) `
                    -NetworkBehavior ([string]$PreparationPlan.network.behavior)
            }
            $collectionStarted=$collectionStarted -or
                [string]$PreparationPlan.network.behavior -ne 'LocalOnly'
            if(-not [bool]$connectivityCollector.cleanupVerified){
                $exception=[InvalidOperationException]::new('The Microsoft Connectivity cleanup was not verified.')
                $exception.Data['ReasonCode']='CONNECTIVITY.COLLECTOR_CLEANUP_INCOMPLETE';throw $exception
            }
        }
        if ((Get-AssessmentCancellationToken).IsCancellationRequested -and $null -ne $identityCollector) {
            $stoppedPrivilege = [pscustomobject]@{
                state='Cancelled'; reasonCode='RUN.CANCELLED'
                identity=[pscustomobject]@{ assessmentUserContext='subject:assessment-user:primary'; localPackageProtector='protector:initiating-windows-user' }
            }
            if ($null -eq $firmwareCollector) {
                $firmwareCollector = New-FirmwareReadinessPrivilegeGapResult -PrivilegeResult $stoppedPrivilege -ValidationFixture $isFixture
            }
            if ($null -eq $systemResult) {
                $stoppedPlan = New-SystemCollectionPlan -PreparationPlan $PreparationPlan -PreparationPlanDigest $PlanDigest
                $systemResult = New-SystemCollectionStoppedResult -State Cancelled -ReasonCode 'SYSTEM.CANCELLED_BEFORE_ACTIVATION' `
                    -CoverageState Cancelled -Context @{
                        Policy=(Get-SystemCollectionPlanPolicy); Plan=$stoppedPlan.Plan
                        PlanDigest=$stoppedPlan.Digest; ObservedExecutionContext='StandardUser'
                    }
            }
            if ($null -ne $resourceCollector) {
                if ($null -eq $administratorCollector) {
                    $administratorCollector = New-AdministratorExposurePrivilegeGapResult -PrivilegeResult $stoppedPrivilege -ValidationFixture $isFixture
                }
                if ($null -eq $effectivePolicyCollector) {
                    $effectivePolicyCollector = New-EffectivePolicyPrivilegeGapResult -PrivilegeResult $stoppedPrivilege -Policy $effectivePolicy -ValidationFixture $isFixture
                }
            }
        }
        $collectorScenario = if ($isFixture) { $scenario } else { '' }
        $sliceStage='DEVICE_COLLECTOR'
        $collector = Invoke-ApprovedCollectorProcess -OperationId ([string]$policy.collector.operationId) `
            -DeviceReadinessScenario $collectorScenario -CancellationToken (Get-AssessmentCancellationToken)
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
                $collectorCancelled = [string]$collector.Supervision.reasonCode -like 'PROCESS.CANCELLED_*'
                if ($collectorCancelled -and
                    $null -ne $identityCollector) {
                    # Earlier normalized source envelopes remain recoverable.
                    # The cancelled device envelope supplies explicit missing
                    # coverage; protect the evidence already obtained.
                    $buildCanonicalRecord = $true
                }
                $coverageOverride = [string]$disposition.coverageState
                $coverageReason = [string]$disposition.coverageReasonCode
                if ($null -ne $identityCollector -and $collector.Supervision.processStarted -and
                    [string]$collector.Supervision.reasonCode -in @(
                        'PROCESS.DEADLINE_EXCEEDED','PROCESS.PAYLOAD_MALFORMED','PROCESS.OUTPUT_LIMIT_EXCEEDED')) {
                    # A failed source attempt does not invalidate already collected,
                    # normalized evidence. Ownership cleanup was verified above;
                    # retain that evidence and describe the failed device scope.
                    $buildCanonicalRecord = $true
                    $coverageOverride = switch ([string]$collector.Supervision.reasonCode) {
                        'PROCESS.DEADLINE_EXCEEDED' { 'TimedOut' }
                        'PROCESS.OUTPUT_LIMIT_EXCEEDED' { 'Constrained' }
                        default { 'Malformed' }
                    }
                    $coverageReason = ([string]$collector.Supervision.reasonCode).Replace('PROCESS.', 'COLLECTION.')
                }
                if ((Get-AssessmentCancellationToken).IsCancellationRequested -and $buildCanonicalRecord) {
                    $coverageOverride = 'Cancelled'
                    $coverageReason = 'COLLECTION.CANCELLED'
                }
                if (-not $buildCanonicalRecord) {
                    $outcome = [string]$disposition.outcome
                    $exitCode = [int]$disposition.exitCode
                    $reasonCode = [string]$disposition.reasonCode
                    if ($collectorCancelled) { $outcome='Cancelled'; $exitCode=30; $reasonCode='RUN.CANCELLED' }
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
                        -CollectorResult $effectivePolicyCollector -Policy $effectivePolicy `
                        -SystemResult $systemResult
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
                if($null -ne $networkCollector){
                    $sliceStage='NETWORK_TOPOLOGY_SOURCE'
                    $record=Add-NetworkTopologyEvidenceRecord -Record $record `
                        -CollectorResult $networkCollector -Policy $networkPolicy
                    [byte[]]$networkSourceBytes=[Text.UTF8Encoding]::new($false).GetBytes(
                        (& $ConvertToJsonCommand -InputObject $record -Compress -Depth 30)
                    )
                    $networkSourceValidation=Test-AssessmentContract `
                        -Utf8Bytes $networkSourceBytes `
                        -ConvertFromJsonCommand $ConvertFromJsonCommand `
                        -TestJsonCommand $TestJsonCommand
                    if([bool]$networkSourceValidation.accepted){
                        $sliceStage='NETWORK_TOPOLOGY_RULES'
                        $record=Complete-ValidatedNetworkTopologyAssessmentRecord `
                            -Record $record -Policy $networkPolicy `
                            -ContractValidation $networkSourceValidation
                    }
                    $sourceValidation=$networkSourceValidation
                }
                if($null -ne $softwareCollector){
                    $sliceStage='SOFTWARE_INVENTORY_SOURCE'
                    $record=Add-SoftwareInventoryEvidenceRecord -Record $record `
                        -CollectorResult $softwareCollector -Policy $softwarePolicy
                    [byte[]]$softwareSourceBytes=[Text.UTF8Encoding]::new($false).GetBytes(
                        (& $ConvertToJsonCommand -InputObject $record -Compress -Depth 30)
                    )
                    $softwareSourceValidation=Test-AssessmentContract `
                        -Utf8Bytes $softwareSourceBytes `
                        -ConvertFromJsonCommand $ConvertFromJsonCommand `
                        -TestJsonCommand $TestJsonCommand
                    $softwareContractReason=[string]$softwareSourceValidation.reasonCode
                    if([bool]$softwareSourceValidation.accepted){
                        $sliceStage='SOFTWARE_INVENTORY_RULES'
                        $record=Complete-ValidatedSoftwareInventoryAssessmentRecord `
                            -Record $record -Policy $softwarePolicy `
                            -ContractValidation $softwareSourceValidation
                        $sliceStage='SOFTWARE_RECOGNITION'
                        $record=Add-SoftwareRecognitionAnnotations -Record $record `
                            -Entries @($softwareCollector.payload.entries) `
                            -CatalogResult $recognitionCatalogResult
                    }
                    $sourceValidation=$softwareSourceValidation
                }
                if($null -ne $certificateCollector){
                    $sliceStage='CERTIFICATE_TRUST_SOURCE'
                    $record=Add-CertificateTrustEvidenceRecord -Record $record `
                        -CollectorResult $certificateCollector -Policy $certificatePolicy
                    [byte[]]$certificateSourceBytes=[Text.UTF8Encoding]::new($false).GetBytes(
                        (& $ConvertToJsonCommand -InputObject $record -Compress -Depth 30)
                    )
                    $certificateSourceValidation=Test-AssessmentContract `
                        -Utf8Bytes $certificateSourceBytes `
                        -ConvertFromJsonCommand $ConvertFromJsonCommand `
                        -TestJsonCommand $TestJsonCommand
                    if([bool]$certificateSourceValidation.accepted){
                        $sliceStage='CERTIFICATE_TRUST_RULES'
                        $record=Complete-ValidatedCertificateTrustAssessmentRecord `
                            -Record $record -Policy $certificatePolicy `
                            -ContractValidation $certificateSourceValidation
                    }
                    $sourceValidation=$certificateSourceValidation
                }
                if($null -ne $connectivityCollector){
                    $sliceStage='MICROSOFT_CONNECTIVITY_SOURCE'
                    $record=Add-MicrosoftConnectivityEvidenceRecord -Record $record `
                        -CollectorResult $connectivityCollector -Policy $connectivityPolicy
                    [byte[]]$connectivitySourceBytes=[Text.UTF8Encoding]::new($false).GetBytes(
                        (& $ConvertToJsonCommand -InputObject $record -Compress -Depth 30)
                    )
                    $connectivitySourceValidation=Test-AssessmentContract `
                        -Utf8Bytes $connectivitySourceBytes `
                        -ConvertFromJsonCommand $ConvertFromJsonCommand `
                        -TestJsonCommand $TestJsonCommand
                    if([bool]$connectivitySourceValidation.accepted){
                        $sliceStage='MICROSOFT_CONNECTIVITY_RULES'
                        $record=Complete-ValidatedMicrosoftConnectivityAssessmentRecord `
                            -Record $record -Policy $connectivityPolicy `
                            -ContractValidation $connectivitySourceValidation
                    }
                    $sourceValidation=$connectivitySourceValidation
                }
                if($null -ne $connectivityCollector){
                    $sliceStage='CROSS_DOMAIN_GUIDANCE'
                    $record = Add-CrossDomainGuidanceToAssessmentRecord `
                        -Record $record -Policy $crossDomainPolicy
                }
                $sliceStage='FINAL_SERIALIZE'
                if ((Get-AssessmentCancellationToken).IsCancellationRequested) {
                    $record.run.outcome = 'Cancelled'
                }
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
                    $securityControlFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:policy.security-control-coverage/1.0.0')[0].outcome
                    $securityControlConstraintFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:policy.security-control-constraint/1.0.0')[0].outcome
                    $antivirusProviderCount=@($effectivePolicyCollector.payload.antivirusProviders).Count
                    $firewallProfileCount=@($effectivePolicyCollector.payload.firewallProfiles.PSObject.Properties).Count
                    $asrRuleCount=@($effectivePolicyCollector.payload.defenderAsrRules).Count
                    $bitLockerProtectorTypeCount=@($effectivePolicyCollector.payload.bitLockerProtectors).Count
                    $wdacPolicyCount=@($effectivePolicyCollector.payload.wdacPolicies).Count
                    $appLockerGpCollectionCount=@($effectivePolicyCollector.payload.appLockerGpCollections).Count
                    $appLockerCspCollectionCount=@($effectivePolicyCollector.payload.appLockerCspCollections).Count
                    $mdmPolicyCspFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:policy.mdm-policy-csp-coverage/1.0.0')[0].outcome
                    $policyCspGpoConflictFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:policy.policy-csp-gpo-conflict/1.0.0')[0].outcome
                    $policyDiscoveryTaskCount=@($record.recommendations|Where-Object {
                        $_.kind -eq 'TenantSideDiscoveryTask' -and
                        $_.definitionId -in @($effectivePolicy.discoveryTasks.definitionId)
                    }).Count
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
                if($null -ne $networkCollector){
                    $sliceStage='NETWORK_TOPOLOGY_METRICS'
                    $localStates=@($networkCollector.payload.scopeStates|Where-Object scopeId -in @($networkPolicy.localScopes.scopeId))
                    $localNetworkCoverage=if(@($localStates|Where-Object state -eq 'Denied').Count){'Denied'}elseif(@($localStates|Where-Object state -ne 'Complete').Count){'Partial'}else{'Complete'}
                    $networkDependentCoverage='NotAttempted'
                    $networkConfigurationFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:network.local-configuration/1.0.0')[0].outcome
                    $networkComponentFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:network.component-inventory/1.0.0')[0].outcome
                    $networkAdapterCount=@($networkCollector.payload.adapters).Count
                    $networkProfileCount=@($networkCollector.payload.profiles).Count
                    $networkRouteCount=@($networkCollector.payload.routes).Count
                    $networkResolverCount=@($networkCollector.payload.resolvers).Count
                    $vpnComponentCount=@($networkCollector.payload.vpnComponents).Count
                    $securityComponentCount=@($networkCollector.payload.securityComponents).Count
                    $localConnectionCount=@($networkCollector.payload.connections).Count
                    $outboundRequestCount=[int]$networkCollector.payload.outboundRequestCount
                }
                if($null -ne $softwareCollector -and [bool]$sourceValidation.accepted){
                    $sliceStage='SOFTWARE_INVENTORY_METRICS'
                    $machineScopeIds=@($softwarePolicy.scopes|Where-Object scopeId -like '*.machine*'|ForEach-Object scopeId)
                    $userScopeIds=@($softwarePolicy.scopes|Where-Object scopeId -like '*.assessment-user*'|ForEach-Object scopeId)
                    $softwareMachineCoverage=if(@($softwareCollector.payload.scopeStates|Where-Object {$_.scopeId -in $machineScopeIds -and $_.state -eq 'Denied'}).Count){'Denied'}elseif(@($softwareCollector.payload.scopeStates|Where-Object {$_.scopeId -in $machineScopeIds -and $_.state -ne 'Complete'}).Count){'Partial'}else{'Complete'}
                    $softwareUserCoverage=if(@($softwareCollector.payload.scopeStates|Where-Object {$_.scopeId -in $userScopeIds -and $_.state -eq 'Denied'}).Count){'Denied'}elseif(@($softwareCollector.payload.scopeStates|Where-Object {$_.scopeId -in $userScopeIds -and $_.state -ne 'Complete'}).Count){'Partial'}else{'Complete'}
                    $softwareMachineFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:software.machine-inventory/1.0.0')[0].outcome
                    $softwareUserFinding=[string]@($record.findings|Where-Object ruleId -eq 'rule:software.assessment-user-inventory/1.0.0')[0].outcome
                    $recognitionAnnotationCount=@($record.softwareRecognition).Count
                    $recognizedExactCount=@($record.softwareRecognition|Where-Object outcome -eq RecognizedExact).Count
                    $recognizedCompositeCount=@($record.softwareRecognition|Where-Object outcome -eq RecognizedComposite).Count
                    $ambiguousCount=@($record.softwareRecognition|Where-Object outcome -eq Ambiguous).Count
                    $unrecognizedCount=@($record.softwareRecognition|Where-Object outcome -eq Unrecognized).Count
                    $notEvaluatedCount=@($record.softwareRecognition|Where-Object outcome -eq NotEvaluated).Count
                }
                if($null -ne $certificateCollector -and [bool]$sourceValidation.accepted){
                    $sliceStage='CERTIFICATE_TRUST_METRICS'
                    $applicableCertificateStates=@($certificateCollector.payload.scopeStates|Where-Object state -ne NotApplicable)
                    $certificatePurposeCoverage=Get-CertificateTrustPurposeCoverage $certificateCollector.payload
                    $fixtureScope=if($applicableCertificateStates.Count){[string]$applicableCertificateStates[0].scopeId}else{[string]$certificatePolicy.purposes[0].scopeId}
                    $fixtureScopeSuffix=$fixtureScope.Substring('scope:certificate.'.Length)
                    $certificatePresenceFinding=[string]@($record.findings|Where-Object findingId -like "finding:certificate-presence-$fixtureScopeSuffix`:*")[0].outcome
                    $certificateValidityFinding=[string]@($record.findings|Where-Object findingId -like "finding:certificate-validity-$fixtureScopeSuffix`:*")[0].outcome
                    $certificateTrustFinding=[string]@($record.findings|Where-Object findingId -like "finding:certificate-trust-$fixtureScopeSuffix`:*")[0].outcome
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
                        }else{$null}) `
                        -NetworkTopologyPolicy $(if($null -ne $networkCollector){
                            $networkPolicy
                        }else{$null}) `
                        -SoftwareInventoryPolicy $(if($null -ne $softwareCollector){
                            $softwarePolicy
                        }else{$null}) `
                        -CertificateTrustPolicy $(if($null -ne $certificateCollector){
                            $certificatePolicy
                        }else{$null}) `
                        -MicrosoftConnectivityPolicy $(if($null -ne $connectivityCollector){
                            $connectivityPolicy
                        }else{$null})
                    $reportText = [System.Text.UTF8Encoding]::new($false,$true).GetString($reportBytes)
                    $reportContract = Test-AssessmentReportContract -ReportBytes $reportBytes `
                        -Record $record `
                        -ExpectUnicode ([string] $scenario -eq 'Unicode' -or
                            [string] $softwareScenario -eq 'Unicode' -or
                            [string] $resourceScenario -eq 'LongUnicode' -or
                            [string] $certificateScenario -eq 'Unicode' -or
                            [string] $connectivityScenario -eq 'Unicode')
                    $reportDeterministic = Test-AssessmentReportBytesEqual `
                        -Left ([byte[]] (New-DeviceReadinessReportBytes -Record $record `
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
                            }else{$null}) `
                            -NetworkTopologyPolicy $(if($null -ne $networkCollector){
                                $networkPolicy
                            }else{$null}) `
                            -SoftwareInventoryPolicy $(if($null -ne $softwareCollector){
                                $softwarePolicy
                            }else{$null}) `
                            -CertificateTrustPolicy $(if($null -ne $certificateCollector){
                                $certificatePolicy
                            }else{$null}) `
                            -MicrosoftConnectivityPolicy $(if($null -ne $connectivityCollector){
                                $connectivityPolicy
                            }else{$null}))) `
                        -Right ([byte[]] $reportBytes)
                    $reportExecutiveSummaryVerified = [bool] $reportContract.executiveSummaryVerified
                    $reportCategorySeparationVerified = [bool] $reportContract.categorySeparationVerified
                    $reportOfflineSafeVerified = [bool] $reportContract.offlineSafeVerified
                    $reportKeyboardNavigationVerified = [bool] $reportContract.keyboardNavigationVerified
                    $reportPrintLayoutVerified = [bool] $reportContract.printLayoutVerified
                    $reportUtf8Verified = [bool] $reportContract.utf8Verified
                    $reportUnicodePreservedVerified = [bool] $reportContract.unicodePreservedVerified
                    $reportRenderedCompleteness = [string] $reportContract.renderedCompleteness
                    $reportWithinPackageBound = $reportBytes.Length -le 262144
                    $reportVerified = [bool] $reportContract.verified -and $reportDeterministic -and
                        $reportWithinPackageBound -and
                        $reportText.StartsWith('<!doctype html>') -and
                        $reportText.Contains('WIN-PCInfo Comprehensive Local Assessment') -and
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
                            $reportText.Contains('cannot establish tenant assignment, compliance, licensing, recovery escrow, or organizational intent')
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
                    if($null -ne $networkCollector){
                        $enabledNetworkReport = [string]$networkCollector.payload.networkBehavior -eq 'MicrosoftConnectivityEnabled'
                        if($null -ne $connectivityCollector){
                            $reportVerified=$reportVerified -and
                                $reportText.Contains('<h2>Local network topology</h2>') -and
                                $reportText.Contains('Local topology remains distinct from remote reachability')
                        }else{
                            $reportVerified=$reportVerified -and
                                $reportText.Contains($(if($enabledNetworkReport){'Local network topology and Microsoft Connectivity Enabled coverage'}else{'Local network topology and Local Only coverage'})) -and
                                $reportText.Contains('made zero DNS, TCP, TLS, HTTP, catalog, update, or telemetry requests') -and
                                $(if($enabledNetworkReport){$reportText.Contains('does not implement those bounded operations') -and -not $reportText.Contains('In Local Only mode')}else{$true})
                        }
                        $reportVerified=$reportVerified -and
                            $reportText.Contains('do not establish health, approval, reachability, trust, compliance, or future compatibility')
                    }
                    if($null -ne $softwareCollector){
                        $reportVerified=$reportVerified -and
                            $reportText.Contains('Installed software and application migration inventory') -and
                            $reportText.Contains('never invokes Win32_Product') -and
                            $reportText.Contains('Display name and publisher are metadata, not identity') -and
                            $reportText.Contains('Software recognition is an annotation, not an Assessment Finding') -and
                            $reportText.Contains('Catalog revision')
                    }
                    if($null -ne $certificateCollector){
                        $reportVerified=$reportVerified -and
                            $reportText.Contains('Purpose-bound certificates and local trust') -and
                            $reportText.Contains('not a universal trust verdict') -and
                            $reportText.Contains('does not request a private-key handle') -and
                            $reportText.Contains('Certificate values and fingerprints remain Restricted')
                    }
                    if($null -ne $connectivityCollector){
                        $reportVerified=$reportVerified -and
                            $reportText.Contains('Microsoft service connectivity and enrollment discovery') -and
                            $reportText.Contains('A failure in one layer is not relabeled as a failure in another') -and
                            $reportText.Contains('Local Only materializes no endpoint and performs zero outbound requests') -and
                            $reportText.Contains('do not test a tenant-specific enrollment CNAME')
                        $reportVerified=$reportVerified -and
                            $reportText.Contains('Cross-domain findings and cautious migration path') -and
                            $reportText.Contains('Ordered Microsoft Zero Trust migration path') -and
                            $reportText.Contains('ImmediateReview') -and
                            $reportText.Contains('PlanNext') -and
                            $reportText.Contains('ConsiderLater') -and
                            $reportText.Contains('does not produce a score, compliance verdict, fixed schedule, or automatic remediation plan')
                    }
                    if (-not $reportVerified) { throw 'The comprehensive report projection failed verification.' }
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
                        $destination = [string]$runWorkspace.workspacePath
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
                    $contractSetVersion=Get-CombinedAssessmentContractSetVersion `
                        -ConnectivityCollector $connectivityCollector `
                        -CertificateCollector $certificateCollector `
                        -SoftwareCollector $softwareCollector `
                        -NetworkCollector $networkCollector -ResourceCollector $resourceCollector `
                        -EffectivePolicyCollector $effectivePolicyCollector `
                        -AdministratorCollector $administratorCollector -IdentityCollector $identityCollector
                    $package = New-ProtectedEvidencePackage -DestinationDirectory $destination `
                        -Artifacts $artifacts -AssessmentContractSetVersion $contractSetVersion `
                        -Completeness $packageCompleteness -ApprovedRecipient $ApprovedRecipient `
                        -JournalPath $(if ($null -ne $runJournal) { [string]$runJournal.journalPath } else { '' })
                    if ($package.verified) {
                        $recipientKeyProtection = [string](
                            Get-ProtectedPackageEnvelopeHeader $package.packagePath
                        ).recipientKeyProtection
                        $opened = Read-ProtectedEvidencePackage -LiteralPath $package.packagePath
                        $packageVerified = [bool]$opened.verified -and
                            $opened.artifacts.Contains('assessment-record.json') -and
                            $opened.artifacts.Contains('assessment-report.html')
                        if ($packageVerified) {
                            $packageManifestConsistent = Test-AssessmentPackageManifestConsistency `
                                -Manifest $opened.manifest -RecordBytes $recordBytes `
                                -ReportBytes $reportBytes -ExpectedCompleteness $packageCompleteness
                            $reportVerified = $reportVerified -and $packageManifestConsistent
                        }
                    }
                    if (-not $packageVerified) {
                        $packageDisposition = Get-DeviceReadinessPackageDisposition `
                            -Package $package -ValidationFixture $isFixture `
                            -CleanupVerified $true `
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
                    if ($packageVerified -and $record.run.outcome -eq 'Cancelled') {
                        $outcome='Cancelled';$exitCode=30;$reasonCode='RUN.CANCELLED'
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
        if ($null -ne $runJournal -and $cleanupVerified) {
            try {
                if ($packageVerified) {
                    # The verified protected result is retained outside the
                    # transient workspace before its journal can be retired.
                    $retainedPath = Join-Path ([IO.Path]::GetFullPath($ApprovedOutputDestination)) ([IO.Path]::GetFileName($package.packagePath))
                    [IO.File]::Move($package.packagePath, $retainedPath)
                    $package.packagePath = $retainedPath
                }
                $cleanup = Invoke-StaleRunRecovery -JournalPath $runJournal.journalPath -CurrentRunCleanup
                $cleanupVerified = [bool]$cleanup.cleanup.verified
            }
            catch { $cleanupVerified = $false }
        }
        elseif ($null -eq $runJournal -and $null -ne $runWorkspace -and $runWorkspace.state -eq 'Created') {
            # Journal creation failed. Preserve the unregistered boundary;
            # guessing ownership here would defeat interruption recovery.
            $cleanupVerified = $false
        }
        if (-not $cleanupVerified) { $outcome='CleanupIncomplete'; $exitCode=60; $reasonCode='RUN.CLEANUP_INCOMPLETE' }
        Remove-Variable -Name AssessmentRunJournalPath -Scope Script -ErrorAction SilentlyContinue
        if ($lockOwned) { $activeLock.ReleaseMutex() }
        if ($null -ne $activeLock) { $activeLock.Dispose() }
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
        $projection = if($null -ne $effectivePolicyCollector){
            New-EffectivePolicyPublicProjection -CollectorResult $effectivePolicyCollector
        }
        else {
            [pscustomobject][ordered]@{
                recordType='win-pcinfo.effective-policy-validation';contractVersion='1.0.0'
                appliedPolicyCoverage=$appliedPolicyCoverage
                configuredSignalCoverage=$configuredPolicyCoverage
                currentControlCoverage=$currentControlCoverage
                windowsUpdateSignalCoverage='NotAttempted'
                remoteManagementCoverage='NotAttempted'
                smbCoverage='NotAttempted'
                legacyAuthenticationCoverage='NotAttempted'
                appliedPolicyCount=$appliedPolicyCount
                antivirusProviderCount=$antivirusProviderCount
                firewallProfileCount=$firewallProfileCount
                asrRuleCount=$asrRuleCount
                bitLockerProtectorTypeCount=$bitLockerProtectorTypeCount
                wdacPolicyCount=$wdacPolicyCount
                appLockerGpCollectionCount=$appLockerGpCollectionCount
                appLockerCspCollectionCount=$appLockerCspCollectionCount
                directRightsOnly=$false
                localSamOnly=$false
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
        $projection|Add-Member -NotePropertyName scenario -NotePropertyValue $effectivePolicyScenario -Force
        $projection|Add-Member -NotePropertyName appliedPolicyFinding -NotePropertyValue $appliedPolicyFinding -Force
        $projection|Add-Member -NotePropertyName localSecurityFinding -NotePropertyValue $localSecurityFinding -Force
        $projection|Add-Member -NotePropertyName appliedOrderFinding -NotePropertyValue $appliedOrderFinding -Force
        $projection|Add-Member -NotePropertyName securityControlFinding -NotePropertyValue $securityControlFinding -Force
        $projection|Add-Member -NotePropertyName securityControlConstraintFinding -NotePropertyValue $securityControlConstraintFinding -Force
        $projection|Add-Member -NotePropertyName mdmPolicyCspFinding -NotePropertyValue $mdmPolicyCspFinding -Force
        $projection|Add-Member -NotePropertyName policyCspGpoConflictFinding -NotePropertyValue $policyCspGpoConflictFinding -Force
        $projection|Add-Member -NotePropertyName policyDiscoveryTaskCount -NotePropertyValue $policyDiscoveryTaskCount -Force
        $projection|Add-Member -NotePropertyName assessmentRecordValidated -NotePropertyValue $recordAccepted -Force
        $projection|Add-Member -NotePropertyName beginnerReportVerified -NotePropertyValue $reportVerified -Force
        $projection|Add-Member -NotePropertyName protectedPackageVerified -NotePropertyValue $packageVerified -Force
        $projection|Add-Member -NotePropertyName validationCleanupVerified -NotePropertyValue $cleanupVerified -Force
        Write-ContractRecord $projection -ConvertToJsonCommand $ConvertToJsonCommand
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
    if($isNetworkTopologyFixture -and $null -ne $networkCollector){
        $projection=New-NetworkTopologyPublicProjection `
            -CollectorResult $networkCollector -Policy $networkPolicy
        $projection|Add-Member -NotePropertyName scenario -NotePropertyValue $networkScenario
        $projection|Add-Member -NotePropertyName localScopeCoverage -NotePropertyValue $localNetworkCoverage -Force
        $projection|Add-Member -NotePropertyName networkConfigurationFinding -NotePropertyValue $networkConfigurationFinding
        $projection|Add-Member -NotePropertyName networkComponentFinding -NotePropertyValue $networkComponentFinding
        $projection|Add-Member -NotePropertyName assessmentRecordValidated -NotePropertyValue $recordAccepted
        $projection|Add-Member -NotePropertyName beginnerReportVerified -NotePropertyValue $reportVerified
        $projection|Add-Member -NotePropertyName protectedPackageVerified -NotePropertyValue $packageVerified
        $projection|Add-Member -NotePropertyName validationCleanupVerified -NotePropertyValue $cleanupVerified
        Write-ContractRecord $projection -ConvertToJsonCommand $ConvertToJsonCommand
    }
    if($isSoftwareInventoryFixture -and $null -ne $softwareCollector){
        $projection=New-SoftwareInventoryPublicProjection -CollectorResult $softwareCollector
        $projection|Add-Member -NotePropertyName scenario -NotePropertyValue $softwareScenario
        $projection|Add-Member -NotePropertyName machineScopeCoverage -NotePropertyValue $softwareMachineCoverage
        $projection|Add-Member -NotePropertyName assessmentUserScopeCoverage -NotePropertyValue $softwareUserCoverage
        $projection|Add-Member -NotePropertyName machineFinding -NotePropertyValue $softwareMachineFinding
        $projection|Add-Member -NotePropertyName assessmentUserFinding -NotePropertyValue $softwareUserFinding
        $projection|Add-Member -NotePropertyName contractReasonCode -NotePropertyValue $softwareContractReason
        $projection|Add-Member -NotePropertyName recognitionAnnotationCount -NotePropertyValue $recognitionAnnotationCount
        $projection|Add-Member -NotePropertyName recognizedExactCount -NotePropertyValue $recognizedExactCount
        $projection|Add-Member -NotePropertyName recognizedCompositeCount -NotePropertyValue $recognizedCompositeCount
        $projection|Add-Member -NotePropertyName ambiguousCount -NotePropertyValue $ambiguousCount
        $projection|Add-Member -NotePropertyName unrecognizedCount -NotePropertyValue $unrecognizedCount
        $projection|Add-Member -NotePropertyName notEvaluatedCount -NotePropertyValue $notEvaluatedCount
        $projection|Add-Member -NotePropertyName recognitionCreatedAssessmentFinding -NotePropertyValue $false
        $projection|Add-Member -NotePropertyName assessmentRecordValidated -NotePropertyValue $recordAccepted
        $projection|Add-Member -NotePropertyName beginnerReportVerified -NotePropertyValue $reportVerified
        $projection|Add-Member -NotePropertyName protectedPackageVerified -NotePropertyValue $packageVerified
        $projection|Add-Member -NotePropertyName validationCleanupVerified -NotePropertyValue $cleanupVerified
        Write-ContractRecord $projection -ConvertToJsonCommand $ConvertToJsonCommand
    }
    if($isCertificateTrustFixture -and $null -ne $certificateCollector){
        $projection=New-CertificateTrustPublicProjection -CollectorResult $certificateCollector
        $projection|Add-Member -NotePropertyName scenario -NotePropertyValue $certificateScenario
        $projection|Add-Member -NotePropertyName purposeCoverage -NotePropertyValue $certificatePurposeCoverage -Force
        $projection|Add-Member -NotePropertyName presenceFinding -NotePropertyValue $certificatePresenceFinding
        $projection|Add-Member -NotePropertyName validityFinding -NotePropertyValue $certificateValidityFinding
        $projection|Add-Member -NotePropertyName trustFinding -NotePropertyValue $certificateTrustFinding
        $projection|Add-Member -NotePropertyName assessmentRecordValidated -NotePropertyValue $recordAccepted
        $projection|Add-Member -NotePropertyName beginnerReportVerified -NotePropertyValue $reportVerified
        $projection|Add-Member -NotePropertyName protectedPackageVerified -NotePropertyValue $packageVerified
        $projection|Add-Member -NotePropertyName validationCleanupVerified -NotePropertyValue $cleanupVerified
        Write-ContractRecord $projection -ConvertToJsonCommand $ConvertToJsonCommand
    }
    if($isMicrosoftConnectivityFixture -and $null -ne $connectivityCollector){
        $projection=New-MicrosoftConnectivityPublicProjection `
            -CollectorResult $connectivityCollector -Policy $connectivityPolicy
        $projection|Add-Member -NotePropertyName scenario -NotePropertyValue $(
            if([string]$connectivityCollector.payload.networkBehavior -eq 'LocalOnly'){'LocalOnly'}else{$connectivityScenario}
        )
        $projection|Add-Member -NotePropertyName assessmentRecordValidated -NotePropertyValue $recordAccepted
        $projection|Add-Member -NotePropertyName beginnerReportVerified -NotePropertyValue $reportVerified
        $projection|Add-Member -NotePropertyName protectedPackageVerified -NotePropertyValue $packageVerified
        $projection|Add-Member -NotePropertyName validationCleanupVerified -NotePropertyValue $cleanupVerified
        Write-ContractRecord $projection -ConvertToJsonCommand $ConvertToJsonCommand

        $crossDomainModel = Get-CrossDomainGuidanceModel -Record $record -Policy $crossDomainPolicy
        if(@($crossDomainModel.findings).Count -gt 0){
            $overallFinding = $crossDomainModel.findings | Where-Object findingKind -eq 'zero-trust-path' | Select-Object -First 1
            $identityFinding = $crossDomainModel.findings | Where-Object findingKind -eq 'identity-foundation' | Select-Object -First 1
            $managementFinding = $crossDomainModel.findings | Where-Object findingKind -eq 'management-plane' | Select-Object -First 1
            $dependencyFinding = $crossDomainModel.findings | Where-Object findingKind -eq 'dependency-transition' | Select-Object -First 1
            $policyFinding = $crossDomainModel.findings | Where-Object findingKind -eq 'policy-modernization' | Select-Object -First 1
            Write-ContractRecord ([pscustomobject][ordered]@{
                recordType = 'win-pcinfo.cross-domain-guidance-validation'
                contractVersion = '1.0.0'
                scenario = if([string]$connectivityCollector.payload.networkBehavior -eq 'LocalOnly'){
                    'LocalOnly'
                }else{$connectivityScenario}
                overallFindingOutcome = [string]$overallFinding.outcome
                identityFoundationOutcome = [string]$identityFinding.outcome
                managementPlaneOutcome = [string]$managementFinding.outcome
                dependencyTransitionOutcome = [string]$dependencyFinding.outcome
                policyModernizationOutcome = [string]$policyFinding.outcome
                orderedRecommendationCount = @($crossDomainModel.pathRecommendations).Count
                immediateReviewCount = Get-CrossDomainGuidancePriorityCount -Model $crossDomainModel -Priority 'ImmediateReview'
                planNextCount = Get-CrossDomainGuidancePriorityCount -Model $crossDomainModel -Priority 'PlanNext'
                considerLaterCount = Get-CrossDomainGuidancePriorityCount -Model $crossDomainModel -Priority 'ConsiderLater'
                relationshipCount = @($crossDomainModel.relationships).Count
                discoveryTaskCount = @($crossDomainModel.tasks).Count
                scoreProduced = $false
                automaticRemediationAttempted = $false
                reportSectionVerified = $reportVerified
                assessmentRecordValidated = $recordAccepted
                beginnerReportVerified = $reportVerified
                protectedPackageVerified = $packageVerified
                validationCleanupVerified = $cleanupVerified
            }) -ConvertToJsonCommand $ConvertToJsonCommand
        }
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
        -CleanupVerified $cleanupVerified `
        -FinalVerificationSucceeded $packageVerified
    $packageAvailability = [string]$packageDisposition.packageAvailability
    $statusTransport = Get-Variable -Name StatusDeskTransport -Scope Script -ErrorAction SilentlyContinue
    if ($null -ne $statusTransport -and $packageAvailability -eq 'Available' -and $packageVerified) {
        $statusTransport.Value.State.PackagePath = [string] $package.packagePath
    }
    if ($packageDisposition.outcome -eq 'CleanupIncomplete') {
        $outcome=[string]$packageDisposition.outcome
        $exitCode=[int]$packageDisposition.exitCode
        $reasonCode=[string]$packageDisposition.reasonCode
    }
    $completionSummary = New-CompletionSummary -PackageVerified $packageVerified `
        -PackageAvailability $packageAvailability `
        -RecipientSelected $recipientSelected `
        -RecipientProtectionLevel $recipientProtectionLevel `
        -RecipientAccessAvailable $recipientAccessAvailable `
        -RestrictedReportExported $false -AssessmentOutcome $outcome `
        -AssessmentCoverageState $(if($packageCompleteness -eq 'Complete'){'Complete'}else{'Gapped'}) `
        -PackageCompleteness $packageCompleteness `
        -RenderedCompleteness $reportRenderedCompleteness `
        -CleanupVerified $cleanupVerified
    $terminalRecord = New-DeviceReadinessTerminalRecord -Outcome $outcome `
        -ExitCode $exitCode -ReasonCode $reasonCode -CollectionStarted $collectionStarted `
        -ValidationFixture $isFixture -CleanupVerified $cleanupVerified `
        -RequestDigest $RequestDigest -PlanDigest $PlanDigest
    if ($packageVerified -and $null -ne $opened) {
        $completionSummaryConsistent = Test-AssessmentCompletionSummaryConsistency `
            -Summary $completionSummary -Terminal $terminalRecord -Manifest $opened.manifest `
            -PackageVerified $packageVerified -CleanupVerified $cleanupVerified `
            -RenderedCompleteness $reportRenderedCompleteness
    }
    if ($isFixture) {
        Write-ContractRecord ([pscustomobject][ordered]@{
            recordType = 'win-pcinfo.comprehensive-report-validation'
            contractVersion = '1.0.0'
            scenario = if($isMicrosoftConnectivityFixture){
                if([string]$connectivityCollector.payload.networkBehavior -eq 'LocalOnly'){
                    'LocalOnly'
                }else{$connectivityScenario}
            }elseif($isSoftwareInventoryFixture){
                $softwareScenario
            }elseif($isCertificateTrustFixture){
                $certificateScenario
            }elseif($isResourceDependenciesFixture){
                $resourceScenario
            }elseif($isIdentityFixture){
                $identityScenario
            }else{$scenario}
            networkBehavior = [string] $PreparationPlan.network.behavior
            renderedCompleteness = $reportRenderedCompleteness
            executiveSummaryVerified = $reportExecutiveSummaryVerified
            categorySeparationVerified = $reportCategorySeparationVerified
            deterministicVerified = $reportDeterministic
            offlineSafeVerified = $reportOfflineSafeVerified
            keyboardNavigationVerified = $reportKeyboardNavigationVerified
            printLayoutVerified = $reportPrintLayoutVerified
            utf8Verified = $reportUtf8Verified
            unicodePreservedVerified = $reportUnicodePreservedVerified
            reportWithinPackageBound = $reportWithinPackageBound
            packageManifestConsistent = $packageManifestConsistent
            completionSummaryConsistent = $completionSummaryConsistent
            assessmentRecordValidated = $recordAccepted
            protectedPackageVerified = $packageVerified
            validationCleanupVerified = $cleanupVerified
        }) -ConvertToJsonCommand $ConvertToJsonCommand
    }
    Write-ContractRecord $completionSummary -ConvertToJsonCommand $ConvertToJsonCommand
    Write-ContractRecord $terminalRecord -ConvertToJsonCommand $ConvertToJsonCommand
    $exitCode
}
