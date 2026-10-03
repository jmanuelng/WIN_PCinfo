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
    if ($script:AssessmentContractSetBase64 -eq ('__ASSESSMENT_CONTRACT_' + 'SET_BASE64__')) {
        # Modular source tests use the reviewed repository resources. The
        # deterministic build replaces these sentinels with the exact canonical
        # bytes and digests, so the generated application never trusts mutable
        # sidecars. This branch is a developer test seam, not runtime discovery.
        $repositoryRoot = Split-Path -Parent $PSScriptRoot
        $contractText = [System.IO.File]::ReadAllText(
            (Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-contract-set.json'),
            [System.Text.UTF8Encoding]::new($false, $true)
        ).Replace("`r`n", "`n").Replace("`r", "`n")
        $schemaText = [System.IO.File]::ReadAllText(
            (Join-Path $repositoryRoot 'schemas/assessment-record.schema.json'),
            [System.Text.UTF8Encoding]::new($false, $true)
        ).Replace("`r`n", "`n").Replace("`r", "`n")
        $contractBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($contractText)
        $schemaBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($schemaText)
        $expectedContractDigest = Get-BytesDigest -Bytes $contractBytes
        $expectedSchemaDigest = Get-BytesDigest -Bytes $schemaBytes
    }
    else {
        $contractBytes = [System.Convert]::FromBase64String($script:AssessmentContractSetBase64)
        $schemaBytes = [System.Convert]::FromBase64String($script:AssessmentRecordSchemaBase64)
        $expectedContractDigest = $script:AssessmentContractSetDigest
        $expectedSchemaDigest = $script:AssessmentRecordSchemaDigest
    }
    if ((Get-BytesDigest -Bytes $contractBytes) -ne $expectedContractDigest -or
        (Get-BytesDigest -Bytes $schemaBytes) -ne $expectedSchemaDigest) {
        throw 'The embedded Assessment Contract Set failed its integrity check.'
    }

    [pscustomobject]@{
        Definition = & $ConvertFromJsonCommand -InputObject ([System.Text.UTF8Encoding]::new($false, $true).GetString($contractBytes))
        AssessmentRecordSchema = [System.Text.UTF8Encoding]::new($false, $true).GetString($schemaBytes)
    }
}

function Initialize-ContractLexicalSafetyType {
    if ('WinPCInfo.ContractValidation.LexicalSafety' -as [type]) {
        if (-not ('WinPCInfo.ContractValidation.SchemaPartition' -as [type])) {
            throw 'The loaded contract helpers do not belong to the same implementation.'
        }
        return
    }

    # Walk the existing System.Text.Json document within the same depth, UTF-8,
    # duplicate-name and numeric limits. A PowerShell call for every JSON node
    # created hundreds of MiB of temporary pipeline state per bounded record.
    # This helper accepts no paths, collectors or mutable policy sidecars.
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WinPCInfo.ContractValidation
{
    public static class LexicalSafety
    {
        public static string GetReason(JsonElement element, int maximumDepth,
            int maximumStringBytes, long maximumSafeInteger, int depth)
        {
            if (depth > maximumDepth) return "CONTRACT.DEPTH_EXCEEDED";
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    var names = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var property in element.EnumerateObject())
                    {
                        string name;
                        try { name = property.Name; }
                        catch { return "CONTRACT.UNICODE_INVALID"; }
                        if (Encoding.UTF8.GetByteCount(name) > maximumStringBytes)
                            return "CONTRACT.SIZE_EXCEEDED";
                        if (!names.Add(name)) return "CONTRACT.DUPLICATE_PROPERTY";
                        var reason = GetReason(property.Value, maximumDepth,
                            maximumStringBytes, maximumSafeInteger, depth + 1);
                        if (reason != null) return reason;
                    }
                    break;
                case JsonValueKind.Array:
                    foreach (var item in element.EnumerateArray())
                    {
                        var reason = GetReason(item, maximumDepth,
                            maximumStringBytes, maximumSafeInteger, depth + 1);
                        if (reason != null) return reason;
                    }
                    break;
                case JsonValueKind.String:
                    string value;
                    try { value = element.GetString(); }
                    catch { return "CONTRACT.UNICODE_INVALID"; }
                    if (Encoding.UTF8.GetByteCount(value) > maximumStringBytes)
                        return "CONTRACT.SIZE_EXCEEDED";
                    break;
                case JsonValueKind.Number:
                    var text = element.GetRawText();
                    // JsonDocument already established JSON number syntax.
                    // Preserve integer literals versus finite decimals/exponents.
                    var integerLiteral = true;
                    foreach (var character in text)
                        if (character == '.' || character == 'e' || character == 'E')
                        { integerLiteral = false; break; }
                    try
                    {
                        if (integerLiteral)
                        {
                            var integer = BigInteger.Parse(text, CultureInfo.InvariantCulture);
                            if (BigInteger.Abs(integer) > new BigInteger(maximumSafeInteger))
                                return "CONTRACT.NUMBER_INVALID";
                        }
                        else
                        {
                            var number = double.Parse(text, NumberStyles.Float,
                                CultureInfo.InvariantCulture);
                            if (!double.IsFinite(number)) return "CONTRACT.NUMBER_INVALID";
                        }
                    }
                    catch { return "CONTRACT.NUMBER_INVALID"; }
                    break;
            }
            return null;
        }
    }
    public static class SchemaPartition
    {
        private const int BatchSize = 64;
        private static readonly string[] ArrayNames = {
            "subjects", "provenance", "observations", "coverage", "diagnostics",
            "collectorResults", "findings", "recommendations",
            "recommendationRelationships", "softwareRecognition"
        };

        public static Dictionary<string, string> Schemas(string text)
        {
            var root = JsonNode.Parse(text).AsObject();
            var properties = root["properties"].AsObject();
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var name in ArrayNames)
            {
                var definition = properties[name].AsObject();
                var wrapper = new JsonObject();
                wrapper["$schema"] = root["$schema"].DeepClone();
                wrapper["$id"] = JsonValue.Create(root["$id"].GetValue<string>() + "/bounded/" + name);
                wrapper["$defs"] = root["$defs"].DeepClone();
                wrapper["type"] = JsonValue.Create("array");
                wrapper["maxItems"] = JsonValue.Create(BatchSize);
                wrapper["items"] = definition["items"].DeepClone();
                result.Add(name, wrapper.ToJsonString());
                definition["items"] = JsonValue.Create(true);
            }
            result.Add("skeleton", root.ToJsonString());
            return result;
        }

        public static string SkeletonInput(JsonElement root, IEnumerable<string> names)
        {
            if (root.ValueKind != JsonValueKind.Object) return root.GetRawText();
            var split = new HashSet<string>(names, StringComparer.Ordinal);
            split.Remove("skeleton");
            var text = new StringBuilder("{");
            int count = 0;
            foreach (var property in root.EnumerateObject())
            {
                if (count++ != 0) text.Append(',');
                text.Append(JsonSerializer.Serialize(property.Name));
                text.Append(':');
                if (split.Contains(property.Name) && property.Value.ValueKind == JsonValueKind.Array)
                {
                    text.Append('[');
                    int length = property.Value.GetArrayLength();
                    for (int index = 0; index < length; index++)
                    {
                        if (index != 0) text.Append(',');
                        text.Append("null");
                    }
                    text.Append(']');
                }
                else text.Append(property.Value.GetRawText());
            }
            text.Append('}');
            return text.ToString();
        }

        public static IEnumerable<string> Batches(JsonElement array)
        {
            var text = new StringBuilder("[");
            int count = 0;
            int seen = 0;
            foreach (var item in array.EnumerateArray())
            {
                if (count != 0) text.Append(',');
                text.Append(item.GetRawText());
                count++;
                seen++;
                if (count == BatchSize)
                {
                    text.Append(']');
                    yield return text.ToString();
                    text.Clear();
                    text.Append('[');
                    count = 0;
                }
            }
            if (count != 0)
            {
                text.Append(']');
                yield return text.ToString();
            }
            if (seen != array.GetArrayLength())
                throw new InvalidOperationException("Partition enumeration incomplete.");
        }
    }
}
'@ | Out-Null
}

function Get-JsonLexicalSafetyReason {
    param(
        [Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element,
        [Parameter(Mandatory)] $Limits,
        [Parameter()] [int] $Depth = 1
    )

    Initialize-ContractLexicalSafetyType
    [WinPCInfo.ContractValidation.LexicalSafety]::GetReason($Element,
        [int] $Limits.maximumJsonDepth, [int] $Limits.maximumStringUtf8Bytes,
        [long] $Limits.maximumSafeInteger, $Depth)
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
    if ($Record.PSObject.Properties['softwareRecognition']) {
        $identityCollections += @{
            Name = 'softwareRecognition'
            Items = @($Record.softwareRecognition)
            Property = 'annotationId'
        }
    }
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
    if ($Record.PSObject.Properties['softwareRecognition']) {
        $applicationSubjects = @($Record.subjects | Where-Object {
            $_.kind -eq 'Application' -and [string]$_.subjectId -match '^subject:software:[0-9]+$'
        })
        $applicationSubjectIds = @($applicationSubjects | ForEach-Object { [string]$_.subjectId })
        $annotationSubjects = @($Record.softwareRecognition | ForEach-Object { [string]$_.subjectId })
        if ('software-recognition-annotations' -notin @($Record.requiredFeatures) -or
            $annotationSubjects.Count -ne $applicationSubjects.Count -or
            @($annotationSubjects | Sort-Object -Unique).Count -ne $annotationSubjects.Count -or
            @($annotationSubjects | Where-Object {
                -not $identitySets.subjects.Contains($_) -or
                $_ -notin $applicationSubjectIds
            }).Count -gt 0 -or
            @($applicationSubjectIds | Where-Object { $_ -notin $annotationSubjects }).Count -gt 0) {
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

    $evidenceProfileId = if ($Record.run.PSObject.Properties['evidenceProfileId']) {
        [string] $Record.run.evidenceProfileId
    }
    else { 'profile:synthetic-contract-tracer' }
    $profileScopeDefinitions = @($ContractDefinition.scopeDefinitions | Where-Object {
        $evidenceProfileId -in @($_.profileIds)
    })
    if ($profileScopeDefinitions.Count -eq 0) { return 'CONTRACT.COVERAGE_INCONSISTENT' }
    $declaredScopes = @($profileScopeDefinitions.scopeId | ForEach-Object { [string] $_ } | Sort-Object -Unique)
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
    $observationById = @{}
    foreach ($observation in @($Record.observations)) {
        $observationById[[string] $observation.observationId] = $observation
    }
    foreach ($item in @($Record.coverage)) {
        $hasReason = $null -ne $item.PSObject.Properties['reasonCode'] -and
            -not [string]::IsNullOrWhiteSpace([string] $item.reasonCode)
        if ([string] $item.state -eq 'Complete') {
            if ($hasReason -or @($item.diagnosticIds).Count -gt 0) {
                return 'CONTRACT.COVERAGE_INCONSISTENT'
            }
            $scopeDefinition = @($profileScopeDefinitions | Where-Object scopeId -eq $item.scopeId)[0]
            $coveredFieldIds = @($item.observationIds | ForEach-Object {
                [string] $observationById[[string] $_].fieldId
            } | Sort-Object -Unique)
            $expectedFieldIds = @($scopeDefinition.fieldIds | ForEach-Object { [string] $_ } |
                Sort-Object -Unique)
            if ($item.scopeId -eq 'scope:device.local-administrators.direct-membership') {
                $scopeObservations=@($item.observationIds | ForEach-Object { $observationById[[string]$_] })
                $emptyCount=@($scopeObservations | Where-Object {
                    $_.fieldId -eq 'field:device.local-administrators.direct-member-count' -and
                    $_.valueState -eq 'ObservedValue' -and $_.value -eq 0
                })
                $completeEnumeration=@($scopeObservations | Where-Object {
                    $_.fieldId -eq 'field:device.local-administrators.enumeration-complete' -and
                    $_.valueState -eq 'ObservedValue' -and $_.value -eq $true
                })
                # A complete empty group has no principal subject to invent.
                # Require explicit count/completion evidence; retained principal
                # fields still fail the exact field-set comparison below.
                if ($emptyCount.Count -eq 1 -and $completeEnumeration.Count -eq 1) {
                    $expectedFieldIds=@($expectedFieldIds | Where-Object { $_ -notlike 'field:principal.*' })
                }
            }
            if (@(Compare-Object -ReferenceObject $expectedFieldIds `
                    -DifferenceObject $coveredFieldIds).Count -gt 0) {
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
    # Coverage is scope-level aggregate state. Multiple approved collectors may
    # contribute disjoint observations to the same scope and therefore bind the
    # same final coverage identity; every coverage item still has to be bound at
    # least once, while observation ownership below remains exactly once.
    # A NotAttempted scope has no collector attempt and therefore no Collector
    # Result Envelope. Requiring an envelope would falsify both its attempts and
    # timing. Every scope for which work did start remains envelope-bound.
    $attemptedCoverage = @($Record.coverage | Where-Object state -ne 'NotAttempted')
    $attemptedCoverageIds = @($attemptedCoverage.coverageId | Sort-Object -Unique)
    $uniqueEnvelopedCoverage = @($envelopedCoverage | Sort-Object -Unique)
    if ($uniqueEnvelopedCoverage.Count -ne $attemptedCoverage.Count -or
        @(Compare-Object -ReferenceObject $attemptedCoverageIds `
            -DifferenceObject $uniqueEnvelopedCoverage).Count -gt 0) {
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
    $attemptedDiagnosticIds = @(
        $attemptedCoverage | ForEach-Object { @($_.diagnosticIds) }
    )
    $uniqueEnvelopedDiagnostics = @($envelopedDiagnostics | Sort-Object -Unique)
    if ($coveredDiagnostics.Count -ne @($Record.diagnostics).Count -or
        @($coveredDiagnostics | Sort-Object -Unique).Count -ne @($Record.diagnostics).Count -or
        $envelopedDiagnostics.Count -ne $attemptedDiagnosticIds.Count -or
        $uniqueEnvelopedDiagnostics.Count -ne $attemptedDiagnosticIds.Count -or
        @(Compare-Object -ReferenceObject @($attemptedDiagnosticIds | Sort-Object -Unique) `
            -DifferenceObject $uniqueEnvelopedDiagnostics).Count -gt 0) {
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
                @($Record.recommendationRelationships).Count +
                $(if($Record.PSObject.Properties['softwareRecognition']){
                    @($Record.softwareRecognition).Count
                }else{0})
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

    # Index each observation once. Repeated pipelines over the entire record
    # for every field allocated far beyond the frozen application memory budget
    # at the maximum software workload. Field and subject bounds are unchanged;
    # definition order still determines the first rejection reason.
    $observationsByField = @{}
    foreach ($observation in @($Record.observations)) {
        $fieldId = [string] $observation.fieldId
        if (-not $observationsByField.ContainsKey($fieldId)) {
            $observationsByField[$fieldId] = [Collections.Generic.List[object]]::new()
        }
        $observationsByField[$fieldId].Add($observation)
    }
    foreach ($definition in @($ContractDefinition.fieldDefinitions)) {
        $matching = if ($observationsByField.ContainsKey([string] $definition.fieldId)) {
            $observationsByField[[string] $definition.fieldId].ToArray()
        } else { @() }
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

function Test-AssessmentCalendarFormat {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Value,
        [Parameter()] [switch] $Timestamp)

    # RFC 3339 sections 5.6-5.7: ASCII wire grammar and Gregorian dates,
    # independent of the operator's culture/calendar. Do not round fractions,
    # cap offsets at DateTimeOffset's 14 hours, or reject the four-digit year 0.
    $pattern = '\A([0-9]{4})-([0-9]{2})-([0-9]{2})'
    if ($Timestamp) {
        $pattern += '[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(?:\.[0-9]+)?([Zz]|([+-])([01][0-9]|2[0-3]):([0-5][0-9]))'
    }
    $match = [regex]::Match($Value, $pattern + '\z', [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) { return $false }
    $year = [int]$match.Groups[1].Value
    $month = [int]$match.Groups[2].Value
    $day = [int]$match.Groups[3].Value
    # Gregorian leap years repeat every 400 years; this also permits year 0000.
    $calendarYear = 2000 + ($year % 400)
    if ($month -lt 1 -or $month -gt 12 -or $day -lt 1 -or
        $day -gt [datetime]::DaysInMonth($calendarYear, $month)) { return $false }
    if ($Timestamp -and $match.Groups[6].Value -eq '60') {
        $offsetMinutes = if ($match.Groups[8].Success) {
            ([int]$match.Groups[9].Value * 60 + [int]$match.Groups[10].Value) *
                $(if ($match.Groups[8].Value -eq '-') { -1 } else { 1 })
        } else { 0 }
        $utc = [datetime]::new($calendarYear, $month, $day,
            [int]$match.Groups[4].Value, [int]$match.Groups[5].Value, 59).AddMinutes(-$offsetMinutes)
        # Leap seconds occur at a UTC month end, even when the local offset
        # puts them on another day. No changing external leap-second table is
        # fetched, and no claim about announced future insertions is made.
        return $utc.Hour -eq 23 -and $utc.Minute -eq 59 -and
            $utc.Day -eq [datetime]::DaysInMonth($utc.Year, $utc.Month)
    }
    return $true
}

function Test-AssessmentRecognitionUriFormat {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Value)

    # RFC 3986 sections 2-3. The record schema already requires https://.
    # Validate the original URI, never a Uri object's repaired/escaped string.
    # Keep generic URI syntax (including IPvFuture and an unbounded digit port)
    # separate from network reachability or a new publisher allowlist.
    $atom = '(?:[A-Za-z0-9._~!$&''()*+,;=-]|%[0-9A-Fa-f]{2})'
    $pattern = '\Ahttps://(?:' + $atom + '|:)*@'
    $withoutUser = [regex]::Replace($Value, $pattern, 'https://')
    $parts = [regex]::Match($withoutUser,
        '\Ahttps://(?<host>\[[^\]]+\]|' + $atom + '*)(?::[0-9]*)?' +
        '(?:/(?:' + $atom + '|[:@/])*)?(?:\?(?:' + $atom + '|[:@/?])*)?(?:#(?:' + $atom + '|[:@/?])*)?\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $parts.Success) { return $false }
    $hostText = $parts.Groups['host'].Value
    if ($hostText.StartsWith('[')) {
        $literal = $hostText.Substring(1, $hostText.Length - 2)
        if ([regex]::IsMatch($literal, '\A[vV][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&''()*+,;=:-]+\z')) { return $true }
        if ($literal -notmatch '\A[0-9A-Fa-f:.]+\z') { return $false }
        if ($literal.Contains('.')) {
            $ipv4 = $literal.Substring($literal.LastIndexOf(':') + 1)
            $octets = $ipv4.Split('.')
            if ($octets.Count -ne 4) { return $false }
            foreach ($octet in $octets) {
                if ($octet -notmatch '\A(?:0|[1-9][0-9]{0,2})\z' -or [int]$octet -gt 255) { return $false }
            }
        }
        $address = $null
        return [Net.IPAddress]::TryParse($literal, [ref]$address) -and
            $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6
    }
    return $true
}

function Get-AssessmentFormatReason {
    param([Parameter(Mandatory)] $Record)

    foreach ($origin in @($Record.provenance)) {
        if (-not (Test-AssessmentCalendarFormat -Value $origin.collectedAt -Timestamp)) { return 'CONTRACT.FORMAT_INVALID' }
    }
    foreach ($envelope in @($Record.collectorResults)) {
        if (-not (Test-AssessmentCalendarFormat -Value $envelope.startedAt -Timestamp) -or
            -not (Test-AssessmentCalendarFormat -Value $envelope.completedAt -Timestamp)) { return 'CONTRACT.FORMAT_INVALID' }
    }
    if ($Record.PSObject.Properties['softwareRecognition']) {
        foreach ($annotation in @($Record.softwareRecognition)) {
            foreach ($origin in @($annotation.provenance)) {
                if (-not (Test-AssessmentCalendarFormat -Value $origin.verifiedOn) -or
                    -not (Test-AssessmentRecognitionUriFormat -Value $origin.url)) { return 'CONTRACT.FORMAT_INVALID' }
            }
        }
    }
    return $null
}

function Get-AssessmentRecordSemanticReason {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $ContractDefinition
    )

    # Schema validation establishes shape; this shared semantic pass proves the
    # graph is closed over the selected release-owned field and scope profile.
    # Keeping it generic lets narrow collector slices validate a normal
    # Assessment Record without weakening the earlier tracer-bullet profile.
    $prohibitedFieldPattern = '(?i)(?:^|[.:/_-])(?:password|passphrase|credential(?!-guard)|token|private[-_]?key|recovery[-_]?key|license[-_]?key|pfx|secret)(?:$|[.:/_-])'
    if (@($Record.observations | Where-Object {
        [string] $_.fieldId -match $prohibitedFieldPattern
    }).Count -gt 0) {
        return 'CONTRACT.PRIVACY_VIOLATION'
    }
    $reason = Get-AssessmentFormatReason -Record $Record
    if ($reason) { return $reason }
    $reason = Get-AssessmentReferenceReason -Record $Record `
        -ContractDefinition $ContractDefinition
    if ($reason) { return $reason }
    $reason = Get-RecommendationGraphReason -Record $Record
    if ($reason) { return $reason }
    $reason = Get-AssessmentStateReason -Record $Record `
        -ContractDefinition $ContractDefinition
    if ($reason) { return $reason }
    $reason = Get-AssessmentFieldReason -Record $Record `
        -ContractDefinition $ContractDefinition
    if ($reason) { return $reason }
    $null
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

# Threat: partitioning a changed schema could omit a whole-array or root
# dependency. Only the exact reviewed canonical shape may be decomposed after
# the embedded-resource integrity check. Keep original root/cardinality rules,
# every raw item and the same trusted Test-Json engine. Each invocation must
# return exactly one Boolean; only normal schema-rejection errors accompany a
# false decision. Command errors and missing/extra results never qualify.
function Invoke-AssessmentStructuralSchemaPass {
    param(
        [Parameter(Mandatory)] [string] $Json,
        [Parameter(Mandatory)] [string] $Schema,
        [Parameter(Mandatory)] $TestJsonCommand
    )

    $schemaErrors = @()
    $results = @(& $TestJsonCommand -Json $Json -Schema $Schema `
        -ErrorAction SilentlyContinue -ErrorVariable schemaErrors)
    if ($results.Count -ne 1 -or $results[0] -isnot [bool]) {
        throw 'Invalid structural validator output.'
    }
    foreach ($errorRecord in $schemaErrors) {
        if ($results[0] -or $errorRecord.FullyQualifiedErrorId -cne
            'InvalidJsonAgainstSchemaDetailed,Microsoft.PowerShell.Commands.TestJsonCommand') {
            throw 'Structural validator command failed.'
        }
    }
    return $results[0]
}

function Test-AssessmentStructuralSchema {
    param(
        [Parameter(Mandatory)] [string] $Json,
        [Parameter(Mandatory)] [string] $CanonicalSchema,
        [Parameter(Mandatory)] $TestJsonCommand
    )

    $identity = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($CanonicalSchema))).ToLowerInvariant()
    if ($identity -cne 'c550ad7fcb86bb6d476f4da18c431b1c432f833ab5bbe34bfb5d4f1e5d327351') {
        throw 'Unqualified canonical schema shape.'
    }
    Initialize-ContractLexicalSafetyType
    $schemas = [WinPCInfo.ContractValidation.SchemaPartition]::Schemas($CanonicalSchema)
    [GC]::Collect(2, [GCCollectionMode]::Aggressive, $true, $true)
    $document = [System.Text.Json.JsonDocument]::Parse($Json)
    try {
        $skeletonInput = [WinPCInfo.ContractValidation.SchemaPartition]::SkeletonInput(
            $document.RootElement, $schemas.Keys)
        if (-not (Invoke-AssessmentStructuralSchemaPass -Json $skeletonInput `
            -Schema $schemas['skeleton'] -TestJsonCommand $TestJsonCommand)) { return $false }
        $skeletonInput = $null
        [GC]::Collect(2, [GCCollectionMode]::Aggressive, $true, $true)
        foreach ($name in $schemas.Keys) {
            if ($name -eq 'skeleton') { continue }
            [System.Text.Json.JsonElement] $items = [System.Text.Json.JsonElement]::new()
            if (-not $document.RootElement.TryGetProperty($name, [ref] $items)) { continue }
            $expected = [int] [Math]::Ceiling($items.GetArrayLength() / 64.0)
            $seen = 0
            foreach ($batch in [WinPCInfo.ContractValidation.SchemaPartition]::Batches($items)) {
                if (-not (Invoke-AssessmentStructuralSchemaPass -Json $batch `
                    -Schema $schemas[$name] -TestJsonCommand $TestJsonCommand)) { return $false }
                $seen++
                $batch = $null
                [GC]::Collect(2, [GCCollectionMode]::Aggressive, $true, $true)
            }
            if ($seen -ne $expected) { throw 'Incomplete structural validation.' }
        }
        return $true
    }
    finally { $document.Dispose() }
}

function Test-AssessmentContract {
    param(
        [Parameter(Mandatory)] [byte[]] $Utf8Bytes,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $TestJsonCommand
    )

    # Large PowerShell JSON pipelines retain temporary generation-two heap
    # segments beyond a validation boundary. Reclaim that inactive memory in
    # the current process; never trim the OS working set or alter evidence.
    [GC]::Collect(2, [GCCollectionMode]::Aggressive, $true, $true)
    try {
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
            try {
                $duplicateReason = Get-JsonLexicalSafetyReason -Element $document.RootElement `
                    -Limits $contract.Definition.limits
            }
            finally { $document.Dispose() }
            if ($duplicateReason) {
                return New-ContractValidationRecord -ReasonCode $duplicateReason `
                    -SchemaDraft ([string] $contract.Definition.schemaDraft)
            }
            # Small records retain whole-record evaluation. Large records use
            # equivalent bounded passes to avoid one retained full result tree.
            $schemaAccepted = if ($Utf8Bytes.Length -lt 524288) {
                Invoke-AssessmentStructuralSchemaPass -Json $json -Schema $contract.AssessmentRecordSchema `
                    -TestJsonCommand $TestJsonCommand
            }
            else {
                Test-AssessmentStructuralSchema -Json $json -CanonicalSchema $contract.AssessmentRecordSchema `
                    -TestJsonCommand $TestJsonCommand
            }
            if (-not $schemaAccepted) {
                return New-ContractValidationRecord -ReasonCode 'CONTRACT.SCHEMA_INVALID' `
                    -SchemaDraft ([string] $contract.Definition.schemaDraft)
            }
            [GC]::Collect(2, [GCCollectionMode]::Aggressive, $true, $true)
            $record = & $ConvertFromJsonCommand -InputObject $json -Depth 30 -DateKind String
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
            $semanticReason = Get-AssessmentRecordSemanticReason -Record $record `
                -ContractDefinition $contract.Definition
            if ($semanticReason) {
                return New-ContractValidationRecord -ReasonCode $semanticReason `
                    -SchemaDraft ([string] $contract.Definition.schemaDraft)
            }
        }
        catch {
            return New-ContractValidationRecord -ReasonCode 'CONTRACT.VALIDATOR_FAILED'
        }

        New-ContractValidationRecord -ReasonCode 'CONTRACT.ACCEPTED' -Accepted $true `
            -SchemaDraft ([string] $contract.Definition.schemaDraft)
    }
    finally {
        $record = $null
        $contract = $null
        $document = $null
        $json = $null
        [GC]::Collect(2, [GCCollectionMode]::Aggressive, $true, $true)
    }
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
