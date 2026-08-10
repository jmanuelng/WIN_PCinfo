$script:AssessmentContractSetBase64 = '__ASSESSMENT_CONTRACT_SET_BASE64__'
$script:AssessmentContractSetDigest = '__ASSESSMENT_CONTRACT_SET_SHA256__'
$script:AssessmentRecordSchemaBase64 = '__ASSESSMENT_RECORD_SCHEMA_BASE64__'
$script:AssessmentRecordSchemaDigest = '__ASSESSMENT_RECORD_SCHEMA_SHA256__'

function Get-EmbeddedAssessmentContractSet {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    # Threat: a schema or field catalog could drift away from the generated
    # application and silently change what evidence it accepts. Build embeds the
    # reviewed UTF-8/LF bytes and their SHA-256 identities, then the already-run
    # application trust gate supplies the publisher/integrity boundary. These
    # digests detect substitution inside that trusted artifact; they do not let
    # modified code self-attest. Any mismatch stops validation and collection.
    $contractBytes = [System.Convert]::FromBase64String($script:AssessmentContractSetBase64)
    $schemaBytes = [System.Convert]::FromBase64String($script:AssessmentRecordSchemaBase64)
    if ((Get-BytesDigest -Bytes $contractBytes) -ne $script:AssessmentContractSetDigest -or
        (Get-BytesDigest -Bytes $schemaBytes) -ne $script:AssessmentRecordSchemaDigest) {
        throw 'The embedded Assessment Contract Set failed its integrity check.'
    }

    [pscustomobject]@{
        Definition = & $ConvertFromJsonCommand -InputObject ([System.Text.UTF8Encoding]::new($false, $true).GetString($contractBytes))
        AssessmentRecordSchema = [System.Text.UTF8Encoding]::new($false, $true).GetString($schemaBytes)
    }
}

function Get-JsonLexicalSafetyReason {
    param(
        [Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element,
        [Parameter(Mandatory)] $Limits,
        [Parameter()] [int] $Depth = 1
    )

    if ($Depth -gt [int] $Limits.maximumJsonDepth) { return 'CONTRACT.DEPTH_EXCEEDED' }

    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $names = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($property in $Element.EnumerateObject()) {
            try { $propertyName = $property.Name } catch { return 'CONTRACT.UNICODE_INVALID' }
            if ([System.Text.Encoding]::UTF8.GetByteCount($propertyName) -gt [int] $Limits.maximumStringUtf8Bytes) {
                return 'CONTRACT.SIZE_EXCEEDED'
            }
            if (-not $names.Add($propertyName)) {
                return 'CONTRACT.DUPLICATE_PROPERTY'
            }
            $nestedReason = Get-JsonLexicalSafetyReason -Element $property.Value `
                -Limits $Limits -Depth ($Depth + 1)
            if ($nestedReason) { return $nestedReason }
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            $nestedReason = Get-JsonLexicalSafetyReason -Element $item `
                -Limits $Limits -Depth ($Depth + 1)
            if ($nestedReason) { return $nestedReason }
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
        try { $value = $Element.GetString() } catch { return 'CONTRACT.UNICODE_INVALID' }
        if ([System.Text.Encoding]::UTF8.GetByteCount($value) -gt [int] $Limits.maximumStringUtf8Bytes) {
            return 'CONTRACT.SIZE_EXCEEDED'
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Number) {
        $numberText = $Element.GetRawText()
        if ($numberText -match '^-?(?:0|[1-9][0-9]*)$') {
            try {
                $integer = [System.Numerics.BigInteger]::Parse(
                    $numberText,
                    [System.Globalization.CultureInfo]::InvariantCulture
                )
                $maximum = [System.Numerics.BigInteger]::new([long] $Limits.maximumSafeInteger)
                if ([System.Numerics.BigInteger]::Abs($integer) -gt $maximum) {
                    return 'CONTRACT.NUMBER_INVALID'
                }
            }
            catch { return 'CONTRACT.NUMBER_INVALID' }
        }
        else {
            try {
                $floatingPoint = [double]::Parse(
                    $numberText,
                    [System.Globalization.NumberStyles]::Float,
                    [System.Globalization.CultureInfo]::InvariantCulture
                )
                if (-not [double]::IsFinite($floatingPoint)) { return 'CONTRACT.NUMBER_INVALID' }
            }
            catch { return 'CONTRACT.NUMBER_INVALID' }
        }
    }

    return $null
}

function Get-AssessmentReferenceReason {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $ContractDefinition
    )

    $identitySets = @{}
    $identityCollections = @(
        @{ Name = 'subjects'; Items = @($Record.subjects); Property = 'subjectId' }
        @{ Name = 'provenance'; Items = @($Record.provenance); Property = 'provenanceId' }
        @{ Name = 'observations'; Items = @($Record.observations); Property = 'observationId' }
        @{ Name = 'coverage'; Items = @($Record.coverage); Property = 'coverageId' }
        @{ Name = 'diagnostics'; Items = @($Record.diagnostics); Property = 'diagnosticId' }
        @{ Name = 'collectorResults'; Items = @($Record.collectorResults); Property = 'envelopeId' }
        @{ Name = 'findings'; Items = @($Record.findings); Property = 'findingId' }
        @{ Name = 'recommendations'; Items = @($Record.recommendations); Property = 'recommendationId' }
        @{ Name = 'recommendationRelationships'; Items = @($Record.recommendationRelationships); Property = 'relationshipId' }
    )
    foreach ($collection in $identityCollections) {
        $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($item in $collection.Items) {
            if (-not $set.Add([string] $item.($collection.Property))) {
                return 'CONTRACT.REFERENCE_AMBIGUOUS'
            }
        }
        $identitySets[$collection.Name] = $set
    }

    $fieldDefinitions = @{}
    foreach ($definition in @($ContractDefinition.fieldDefinitions)) {
        if ($fieldDefinitions.ContainsKey([string] $definition.fieldId)) {
            return 'CONTRACT.REFERENCE_AMBIGUOUS'
        }
        $fieldDefinitions[[string] $definition.fieldId] = $definition
    }
    $provenanceById = @{}
    foreach ($item in @($Record.provenance)) { $provenanceById[[string] $item.provenanceId] = $item }
    $observationById = @{}
    foreach ($item in @($Record.observations)) { $observationById[[string] $item.observationId] = $item }
    $coverageById = @{}
    foreach ($item in @($Record.coverage)) { $coverageById[[string] $item.coverageId] = $item }
    $scopeDefinitionById = @{}
    foreach ($item in @($ContractDefinition.scopeDefinitions)) {
        $scopeDefinitionById[[string] $item.scopeId] = $item
    }
    $coverageScopes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($item in @($Record.coverage)) {
        if (-not $coverageScopes.Add([string] $item.scopeId)) {
            return 'CONTRACT.REFERENCE_AMBIGUOUS'
        }
    }

    foreach ($item in @($Record.provenance)) {
        if (-not $fieldDefinitions.ContainsKey([string] $item.fieldId) -or
            -not $identitySets.subjects.Contains([string] $item.subjectId)) {
            return 'CONTRACT.REFERENCE_INVALID'
        }
        $fieldDefinition = $fieldDefinitions[[string] $item.fieldId]
        if ([string] $item.sourceId -ne [string] $fieldDefinition.source.sourceId) {
            return 'CONTRACT.REFERENCE_INVALID'
        }
    }
    foreach ($item in @($Record.observations)) {
        if (-not $fieldDefinitions.ContainsKey([string] $item.fieldId) -or
            -not $identitySets.subjects.Contains([string] $item.subjectId) -or
            -not $identitySets.provenance.Contains([string] $item.provenanceId)) {
            return 'CONTRACT.REFERENCE_INVALID'
        }
        $origin = $provenanceById[[string] $item.provenanceId]
        if ([string] $origin.fieldId -ne [string] $item.fieldId -or
            [string] $origin.subjectId -ne [string] $item.subjectId) {
            return 'CONTRACT.REFERENCE_INVALID'
        }
    }
    foreach ($item in @($Record.coverage)) {
        if (@($item.observationIds | Where-Object { -not $identitySets.observations.Contains([string] $_) }).Count -gt 0 -or
            @($item.diagnosticIds | Where-Object { -not $identitySets.diagnostics.Contains([string] $_) }).Count -gt 0) {
            return 'CONTRACT.REFERENCE_INVALID'
        }
    }
    foreach ($item in @($Record.diagnostics)) {
        if (-not $coverageScopes.Contains([string] $item.scopeId)) {
            return 'CONTRACT.REFERENCE_INVALID'
        }
    }
    foreach ($item in @($Record.collectorResults)) {
        if (@($item.intendedScopeIds | Where-Object { -not $coverageScopes.Contains([string] $_) }).Count -gt 0 -or
            @($item.subjectIds | Where-Object { -not $identitySets.subjects.Contains([string] $_) }).Count -gt 0 -or
            @($item.observationIds | Where-Object { -not $identitySets.observations.Contains([string] $_) }).Count -gt 0 -or
            @($item.coverageIds | Where-Object { -not $identitySets.coverage.Contains([string] $_) }).Count -gt 0 -or
            @($item.diagnosticIds | Where-Object { -not $identitySets.diagnostics.Contains([string] $_) }).Count -gt 0) {
            return 'CONTRACT.REFERENCE_INVALID'
        }
        foreach ($scopeId in @($item.intendedScopeIds)) {
            $scopeDefinition = $scopeDefinitionById[[string] $scopeId]
            if ($null -ne $scopeDefinition -and
                [string] $item.collectorId -notin @($scopeDefinition.collectorIds)) {
                return 'CONTRACT.ENVELOPE_INCONSISTENT'
            }
        }
        foreach ($coverageId in @($item.coverageIds)) {
            $coverage = $coverageById[[string] $coverageId]
            $scopeDefinition = $scopeDefinitionById[[string] $coverage.scopeId]
            if ($null -eq $scopeDefinition) { continue }
            foreach ($observationId in @($coverage.observationIds)) {
                $observation = $observationById[[string] $observationId]
                if ([string] $observation.fieldId -notin @($scopeDefinition.fieldIds)) {
                    return 'CONTRACT.ENVELOPE_INCONSISTENT'
                }
            }
        }
        $envelopeSubjects = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($subjectId in @($item.subjectIds)) {
            $null = $envelopeSubjects.Add([string] $subjectId)
        }
        foreach ($observationId in @($item.observationIds)) {
            $observation = $observationById[[string] $observationId]
            $origin = $provenanceById[[string] $observation.provenanceId]
            if ([string] $origin.collectorId -ne [string] $item.collectorId -or
                [string] $origin.collectorVersion -ne [string] $item.collectorVersion -or
                -not $envelopeSubjects.Contains([string] $origin.subjectId)) {
                return 'CONTRACT.ENVELOPE_INCONSISTENT'
            }
        }
    }
    $envelopedObservations = @(
        $Record.collectorResults | ForEach-Object { @($_.observationIds) }
    )
    if ($envelopedObservations.Count -ne @($Record.observations).Count -or
        @($envelopedObservations | Sort-Object -Unique).Count -ne @($Record.observations).Count) {
        return 'CONTRACT.ENVELOPE_INCONSISTENT'
    }
    foreach ($item in @($Record.findings)) {
        if (-not $identitySets.subjects.Contains([string] $item.targetSubjectId)) {
            return 'CONTRACT.REFERENCE_INVALID'
        }
        foreach ($reference in @($item.evidenceReferences)) {
            if (-not $identitySets.observations.Contains([string] $reference.observationId)) {
                return 'CONTRACT.REFERENCE_INVALID'
            }
            $observation = $observationById[[string] $reference.observationId]
            if ([string] $observation.fieldId -ne [string] $reference.fieldId -or
                [string] $observation.subjectId -ne [string] $reference.subjectId) {
                return 'CONTRACT.REFERENCE_INVALID'
            }
        }
    }
    foreach ($item in @($Record.recommendations)) {
        if (@($item.findingIds | Where-Object { -not $identitySets.findings.Contains([string] $_) }).Count -gt 0) {
            return 'CONTRACT.REFERENCE_INVALID'
        }
    }
    foreach ($item in @($Record.recommendationRelationships)) {
        if (-not $identitySets.recommendations.Contains([string] $item.fromRecommendationId) -or
            -not $identitySets.recommendations.Contains([string] $item.toRecommendationId)) {
            return 'CONTRACT.REFERENCE_INVALID'
        }
    }

    return $null
}

function Get-RecommendationGraphReason {
    param([Parameter(Mandatory)] $Record)

    $adjacency = @{}
    $inDegree = @{}
    foreach ($recommendation in @($Record.recommendations)) {
        $id = [string] $recommendation.recommendationId
        $adjacency[$id] = [System.Collections.Generic.List[string]]::new()
        $inDegree[$id] = 0
    }
    foreach ($relationship in @($Record.recommendationRelationships)) {
        $from = [string] $relationship.fromRecommendationId
        $to = [string] $relationship.toRecommendationId
        if ($from -eq $to) { return 'CONTRACT.GRAPH_INVALID' }
        if ([string] $relationship.kind -eq 'ConflictsWith') { continue }
        $adjacency[$from].Add($to)
        $inDegree[$to] = [int] $inDegree[$to] + 1
    }

    $ready = [System.Collections.Generic.Queue[string]]::new()
    foreach ($id in @($inDegree.Keys)) {
        if ([int] $inDegree[$id] -eq 0) { $ready.Enqueue([string] $id) }
    }
    $visited = 0
    while ($ready.Count -gt 0) {
        $id = $ready.Dequeue()
        $visited++
        foreach ($target in $adjacency[$id]) {
            $inDegree[$target] = [int] $inDegree[$target] - 1
            if ([int] $inDegree[$target] -eq 0) { $ready.Enqueue($target) }
        }
    }
    if ($visited -ne $inDegree.Count) { return 'CONTRACT.GRAPH_INVALID' }

    return $null
}

function Get-AssessmentStateReason {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $ContractDefinition
    )

    $declaredScopes = @($ContractDefinition.scopeDefinitions.scopeId | ForEach-Object { [string] $_ } | Sort-Object -Unique)
    $reportedScopes = @($Record.coverage.scopeId | ForEach-Object { [string] $_ } | Sort-Object -Unique)
    if (@(Compare-Object -ReferenceObject $declaredScopes -DifferenceObject $reportedScopes).Count -gt 0) {
        return 'CONTRACT.COVERAGE_INCONSISTENT'
    }

    $diagnosticById = @{}
    foreach ($diagnostic in @($Record.diagnostics)) {
        $diagnosticById[[string] $diagnostic.diagnosticId] = $diagnostic
    }
    $coverageById = @{}
    foreach ($coverage in @($Record.coverage)) {
        $coverageById[[string] $coverage.coverageId] = $coverage
    }
    foreach ($item in @($Record.coverage)) {
        $hasReason = $null -ne $item.PSObject.Properties['reasonCode'] -and
            -not [string]::IsNullOrWhiteSpace([string] $item.reasonCode)
        if ([string] $item.state -eq 'Complete') {
            if ($hasReason -or @($item.diagnosticIds).Count -gt 0) {
                return 'CONTRACT.COVERAGE_INCONSISTENT'
            }
        }
        elseif (-not $hasReason) {
            return 'CONTRACT.COVERAGE_INCONSISTENT'
        }
        if ([string] $item.state -in @(
            'NotApplicable', 'Unavailable', 'Unsupported', 'Denied', 'TimedOut',
            'Cancelled', 'Failed', 'NotAttempted'
        ) -and @($item.observationIds).Count -gt 0) {
            return 'CONTRACT.COVERAGE_INCONSISTENT'
        }
        if ([string] $item.state -eq 'ProhibitedMaterialBlocked') {
            $approvedMarkers = @(
                $item.diagnosticIds | ForEach-Object { $diagnosticById[[string] $_] } |
                    Where-Object {
                        $null -ne $_ -and
                        $_.PSObject.Properties['prohibitedMaterial'] -and
                        [bool] $_.prohibitedMaterial.encountered -and
                        -not [bool] $_.prohibitedMaterial.retained -and
                        -not [bool] $_.prohibitedMaterial.hashed
                    }
            )
            if ($approvedMarkers.Count -eq 0) { return 'CONTRACT.COVERAGE_INCONSISTENT' }
        }
    }

    foreach ($envelope in @($Record.collectorResults)) {
        $coveredScopes = @(
            $envelope.coverageIds |
                ForEach-Object { [string] $coverageById[[string] $_].scopeId } |
                Sort-Object -Unique
        )
        $intendedScopes = @($envelope.intendedScopeIds | ForEach-Object { [string] $_ } | Sort-Object -Unique)
        if (@(Compare-Object -ReferenceObject $intendedScopes -DifferenceObject $coveredScopes).Count -gt 0) {
            return 'CONTRACT.COVERAGE_INCONSISTENT'
        }
    }
    $envelopedCoverage = @(
        $Record.collectorResults | ForEach-Object { @($_.coverageIds) }
    )
    if ($envelopedCoverage.Count -ne @($Record.coverage).Count -or
        @($envelopedCoverage | Sort-Object -Unique).Count -ne @($Record.coverage).Count) {
        return 'CONTRACT.COVERAGE_INCONSISTENT'
    }
    $coveredObservations = @(
        $Record.coverage | ForEach-Object { @($_.observationIds) }
    )
    if ($coveredObservations.Count -ne @($Record.observations).Count -or
        @($coveredObservations | Sort-Object -Unique).Count -ne @($Record.observations).Count) {
        return 'CONTRACT.COVERAGE_INCONSISTENT'
    }
    $coveredDiagnostics = @(
        $Record.coverage | ForEach-Object { @($_.diagnosticIds) }
    )
    $envelopedDiagnostics = @(
        $Record.collectorResults | ForEach-Object { @($_.diagnosticIds) }
    )
    if ($coveredDiagnostics.Count -ne @($Record.diagnostics).Count -or
        @($coveredDiagnostics | Sort-Object -Unique).Count -ne @($Record.diagnostics).Count -or
        $envelopedDiagnostics.Count -ne @($Record.diagnostics).Count -or
        @($envelopedDiagnostics | Sort-Object -Unique).Count -ne @($Record.diagnostics).Count) {
        return 'CONTRACT.COVERAGE_INCONSISTENT'
    }

    foreach ($item in @($Record.observations)) {
        $hasValue = $null -ne $item.PSObject.Properties['value']
        if (([string] $item.valueState -eq 'ObservedValue') -ne $hasValue) {
            return 'CONTRACT.OBSERVATION_STATE_INCONSISTENT'
        }
    }
    foreach ($item in @($Record.findings)) {
        $hasReason = $null -ne $item.PSObject.Properties['reasonCode'] -and
            -not [string]::IsNullOrWhiteSpace([string] $item.reasonCode)
        if ([string] $item.outcome -in @('Indeterminate', 'NotApplicable')) {
            if (-not $hasReason) { return 'CONTRACT.FINDING_STATE_INCONSISTENT' }
        }
        elseif ($hasReason) {
            return 'CONTRACT.FINDING_STATE_INCONSISTENT'
        }
    }

    $hasCoverageGap = @($Record.coverage | Where-Object state -ne 'Complete').Count -gt 0
    switch ([string] $Record.run.outcome) {
        'Completed' {
            if ($hasCoverageGap) { return 'CONTRACT.RUN_STATE_INCONSISTENT' }
        }
        'CompletedWithGaps' {
            if (-not $hasCoverageGap) { return 'CONTRACT.RUN_STATE_INCONSISTENT' }
        }
        'NotStarted' {
            $postStartRecords = @($Record.subjects).Count + @($Record.provenance).Count +
                @($Record.observations).Count + @($Record.collectorResults).Count +
                @($Record.findings).Count + @($Record.recommendations).Count +
                @($Record.recommendationRelationships).Count
            if ($postStartRecords -gt 0 -or
                @($Record.coverage | Where-Object state -ne 'NotAttempted').Count -gt 0) {
                return 'CONTRACT.RUN_STATE_INCONSISTENT'
            }
        }
        'Cancelled' {
            if (@($Record.coverage | Where-Object state -eq 'Cancelled').Count -eq 0) {
                return 'CONTRACT.RUN_STATE_INCONSISTENT'
            }
        }
        'TimedOut' {
            if (@($Record.coverage | Where-Object state -eq 'TimedOut').Count -eq 0) {
                return 'CONTRACT.RUN_STATE_INCONSISTENT'
            }
        }
        'IntegrityFailed' {
            if (@($Record.diagnostics | Where-Object reasonCode -match '(^|\.)INTEGRITY([_.]|$)').Count -eq 0) {
                return 'CONTRACT.RUN_STATE_INCONSISTENT'
            }
        }
        'CleanupIncomplete' {
            if (@($Record.diagnostics | Where-Object phase -eq 'Cleanup').Count -eq 0) {
                return 'CONTRACT.RUN_STATE_INCONSISTENT'
            }
        }
        default { return 'CONTRACT.RUN_STATE_INCONSISTENT' }
    }

    return $null
}

function Get-AssessmentFieldReason {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $ContractDefinition
    )

    foreach ($definition in @($ContractDefinition.fieldDefinitions)) {
        $matching = @(
            $Record.observations |
                Where-Object { [string] $_.fieldId -eq [string] $definition.fieldId }
        )
        $groups = @($matching | Group-Object -Property subjectId)
        if (@($groups | Where-Object {
            $_.Count -gt [int] $definition.bounds.maximumOccurrencesPerSubject
        }).Count -gt 0) {
            return 'CONTRACT.FIELD_BOUND_EXCEEDED'
        }
        foreach ($observation in $matching) {
            if ([string] $observation.valueState -ne 'ObservedValue') { continue }
            $typeAccepted = switch ([string] $definition.valueType) {
                'String' { $observation.value -is [string] }
                'Boolean' { $observation.value -is [bool] }
                'Integer' { $observation.value -is [int] -or $observation.value -is [long] }
                default { $false }
            }
            if (-not $typeAccepted) { return 'CONTRACT.FIELD_TYPE_INVALID' }
            $encodedValue = [System.Text.Encoding]::UTF8.GetBytes([string] $observation.value)
            if ($encodedValue.Length -gt [int] $definition.bounds.maximumUtf8Bytes) {
                return 'CONTRACT.FIELD_BOUND_EXCEEDED'
            }
        }
    }

    return $null
}

function New-ContractValidationRecord {
    param(
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter()] [bool] $Accepted = $false,
        [Parameter()] [string] $SchemaDraft = '2020-12'
    )

    [pscustomobject][ordered]@{
        recordType = 'win-pcinfo.contract-validation'
        contractVersion = '1.0.0'
        accepted = $Accepted
        reasonCode = $ReasonCode
        documentKind = 'AssessmentRecord'
        schemaDraft = $SchemaDraft
        validationFixture = $true
    }
}

function Test-AssessmentContract {
    param(
        [Parameter(Mandatory)] [byte[]] $Utf8Bytes,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $TestJsonCommand
    )

    try {
        $contract = Get-EmbeddedAssessmentContractSet -ConvertFromJsonCommand $ConvertFromJsonCommand
        if ($Utf8Bytes.Length -gt [int] $contract.Definition.limits.maximumDocumentUtf8Bytes) {
            return New-ContractValidationRecord -ReasonCode 'CONTRACT.SIZE_EXCEEDED' `
                -SchemaDraft ([string] $contract.Definition.schemaDraft)
        }
        try {
            $json = [System.Text.UTF8Encoding]::new($false, $true).GetString($Utf8Bytes)
        }
        catch {
            return New-ContractValidationRecord -ReasonCode 'CONTRACT.UTF8_INVALID' `
                -SchemaDraft ([string] $contract.Definition.schemaDraft)
        }
        try {
            $parseOptions = [System.Text.Json.JsonDocumentOptions]::new()
            # Each nested container needs at least one opening and one closing UTF-8 byte.
            $maximumRepresentableJsonDepth = [int] [Math]::Floor(
                [int] $contract.Definition.limits.maximumDocumentUtf8Bytes / 2
            )
            $parseOptions.MaxDepth = $maximumRepresentableJsonDepth
            $document = [System.Text.Json.JsonDocument]::Parse($json, $parseOptions)
        }
        catch {
            return New-ContractValidationRecord -ReasonCode 'CONTRACT.JSON_INVALID' `
                -SchemaDraft ([string] $contract.Definition.schemaDraft)
        }
        $duplicateReason = Get-JsonLexicalSafetyReason -Element $document.RootElement `
            -Limits $contract.Definition.limits
        $document.Dispose()
        if ($duplicateReason) {
            return New-ContractValidationRecord -ReasonCode $duplicateReason `
                -SchemaDraft ([string] $contract.Definition.schemaDraft)
        }
        $schemaAccepted = & $TestJsonCommand -Json $json -Schema $contract.AssessmentRecordSchema `
            -ErrorAction SilentlyContinue
        if (-not $schemaAccepted) {
            return New-ContractValidationRecord -ReasonCode 'CONTRACT.SCHEMA_INVALID' `
                -SchemaDraft ([string] $contract.Definition.schemaDraft)
        }
        $record = & $ConvertFromJsonCommand -InputObject $json -Depth 30
        try {
            $recordVersion = [version] [string] $record.contractVersion
            $contractVersion = [version] [string] $contract.Definition.contractVersion
        }
        catch {
            $recordVersion = $null
            $contractVersion = [version] '1.0.0'
        }
        if ($null -eq $recordVersion -or $recordVersion.Major -ne $contractVersion.Major) {
            return New-ContractValidationRecord -ReasonCode 'CONTRACT.VERSION_INCOMPATIBLE' `
                -SchemaDraft ([string] $contract.Definition.schemaDraft)
        }
        $unsupportedFeatures = @(
            $record.requiredFeatures |
                Where-Object { [string] $_ -notin @($contract.Definition.requiredFeatures) }
        )
        if ($unsupportedFeatures.Count -gt 0) {
            return New-ContractValidationRecord -ReasonCode 'CONTRACT.REQUIRED_FEATURE_UNSUPPORTED' `
                -SchemaDraft ([string] $contract.Definition.schemaDraft)
        }
        # Threat: a collector or future producer could label credential material
        # as an ordinary observation and thereby create a second copy in the
        # Assessment Record. The validator checks the release-managed field
        # identity before resolving ordinary references. Its trust assumption is
        # deliberately narrow: only field identities in the embedded Contract Set
        # may be admitted. A secret-bearing identity fails closed with a public
        # marker; neither the value nor a digest of it is returned or logged.
        $prohibitedFieldPattern = '(?i)(?:^|[.:/_-])(?:password|passphrase|credential|token|private[-_]?key|recovery[-_]?key|license[-_]?key|pfx|secret)(?:$|[.:/_-])'
        if (@($record.observations | Where-Object { [string] $_.fieldId -match $prohibitedFieldPattern }).Count -gt 0) {
            return New-ContractValidationRecord -ReasonCode 'CONTRACT.PRIVACY_VIOLATION' `
                -SchemaDraft ([string] $contract.Definition.schemaDraft)
        }
        $referenceReason = Get-AssessmentReferenceReason -Record $record `
            -ContractDefinition $contract.Definition
        if ($referenceReason) {
            return New-ContractValidationRecord -ReasonCode $referenceReason `
                -SchemaDraft ([string] $contract.Definition.schemaDraft)
        }
        $graphReason = Get-RecommendationGraphReason -Record $record
        if ($graphReason) {
            return New-ContractValidationRecord -ReasonCode $graphReason `
                -SchemaDraft ([string] $contract.Definition.schemaDraft)
        }
        $stateReason = Get-AssessmentStateReason -Record $record `
            -ContractDefinition $contract.Definition
        if ($stateReason) {
            return New-ContractValidationRecord -ReasonCode $stateReason `
                -SchemaDraft ([string] $contract.Definition.schemaDraft)
        }
        $fieldReason = Get-AssessmentFieldReason -Record $record `
            -ContractDefinition $contract.Definition
        if ($fieldReason) {
            return New-ContractValidationRecord -ReasonCode $fieldReason `
                -SchemaDraft ([string] $contract.Definition.schemaDraft)
        }
    }
    catch {
        return New-ContractValidationRecord -ReasonCode 'CONTRACT.VALIDATOR_FAILED'
    }

    New-ContractValidationRecord -ReasonCode 'CONTRACT.ACCEPTED' -Accepted $true `
        -SchemaDraft ([string] $contract.Definition.schemaDraft)
}

function Invoke-ContractFixtureValidation {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $RuntimeResult,
        [Parameter(Mandatory)] [string] $RequestDigest,
        [Parameter(Mandatory)] [string] $PlanDigest,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $ConvertToJsonCommand,
        [Parameter(Mandatory)] $TestJsonCommand
    )

    # This is a release-validation path, not a collector. It accepts only a
    # schema-marked synthetic record after preparation approval, emits a
    # minimized public result, and always terminates NotStarted. That process
    # boundary prevents test data from acquiring device authority, workspace
    # access, package protection, network access, elevation, or Azure access.
    try {
        $bytes = [System.IO.File]::ReadAllBytes([System.IO.Path]::GetFullPath($LiteralPath))
        $validation = Test-AssessmentContract -Utf8Bytes $bytes `
            -ConvertFromJsonCommand $ConvertFromJsonCommand -TestJsonCommand $TestJsonCommand
    }
    catch {
        $validation = New-ContractValidationRecord -ReasonCode 'CONTRACT.UNREADABLE'
    }

    Write-ContractRecord $validation -ConvertToJsonCommand $ConvertToJsonCommand
    $terminalReason = if ($validation.accepted) {
        'SLICE.CONTRACT_VALIDATION_COMPLETE'
    }
    else {
        'SLICE.CONTRACT_VALIDATION_REJECTED'
    }
    Write-ContractRecord (New-TerminalRecord -ReasonCode $terminalReason -RequestDigest $RequestDigest `
        -ValidationFixture $true -RuntimeResult $RuntimeResult -Phase 'ContractValidation' `
        -PlanDigest $PlanDigest -PreparationDecision 'Accepted') `
        -ConvertToJsonCommand $ConvertToJsonCommand
    return 20
}
