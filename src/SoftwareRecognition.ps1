$script:SoftwareRecognitionCatalogBase64 = '__SOFTWARE_RECOGNITION_CATALOG_BASE64__'
$script:SoftwareRecognitionCatalogDigest = '__SOFTWARE_RECOGNITION_CATALOG_SHA256__'
$script:SoftwareRecognitionSchemaBase64 = '__SOFTWARE_RECOGNITION_SCHEMA_BASE64__'
$script:SoftwareRecognitionSchemaDigest = '__SOFTWARE_RECOGNITION_SCHEMA_SHA256__'

function Get-SoftwareRecognitionSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Test-SoftwareRecognitionText {
    param($Value, [int] $Minimum, [int] $Maximum, [switch] $AllowNull)
    if ($null -eq $Value) { return [bool]$AllowNull }
    if ($Value -isnot [string]) { return $false }
    $length = [Text.Encoding]::UTF8.GetByteCount([string]$Value)
    $length -ge $Minimum -and $length -le $Maximum
}

function Test-SoftwareRecognitionDate {
    param($Value)
    if ($Value -isnot [string]) { return $false }
    $parsed = [DateTime]::MinValue
    [DateTime]::TryParseExact(
        [string]$Value, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None, [ref]$parsed
    )
}

function Get-SoftwareRecognitionOrdinalStrings {
    param([AllowEmptyCollection()] [object[]] $Values)
    $set = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($value in $Values) { $null = $set.Add([string]$value) }
    [string[]]$items = @($set)
    [Array]::Sort($items, [StringComparer]::Ordinal)
    $items
}

function Get-SoftwareRecognitionResultMaximumUtf8Bytes {
    param([Parameter(Mandatory)] [object[]] $Annotations)

    # JsonEncodedText gives the exact escaped UTF-8 length of string values. The
    # fixed allowance deliberately overcounts property names, quotes, commas,
    # arrays, numbers, booleans, and object delimiters. This keeps enforcement
    # independent of the ambient PowerShell command table while guaranteeing the
    # serialized annotation result stays below the release operation ceiling.
    $encodedLength = {
        param($Value)
        if ($null -eq $Value) { return 4 }
        2 + [Text.Encoding]::UTF8.GetByteCount(
            [Text.Json.JsonEncodedText]::Encode([string]$Value).Value
        )
    }
    [long]$total = 512
    foreach ($annotation in $Annotations) {
        $total += 1024
        foreach ($value in @(
            $annotation.outcome, $annotation.familyId, $annotation.familyLabel,
            $annotation.matchStrengthExplanation, $annotation.reasonCode,
            $annotation.catalogRelease, $annotation.catalogDigest
        )) { $total += & $encodedLength $value }
        foreach ($value in @($annotation.roles) + @($annotation.matcherIds) +
            @($annotation.matcherTypes)) { $total += & $encodedLength $value }
        foreach ($source in @($annotation.provenance)) {
            $total += 512
            foreach ($value in @(
                $source.sourceType, $source.owner, $source.url, $source.verifiedOn,
                $source.reviewer, $source.pinnedCommit, $source.manifestPath
            )) { $total += & $encodedLength $value }
        }
    }
    $total
}

function Test-SoftwareRecognitionCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Catalog)

    try {
        if ([string]$Catalog.kind -ne 'win-pcinfo.software-recognition-catalog' -or
            [int]$Catalog.schemaVersion -ne 1 -or
            [int]$Catalog.catalogRevision -lt 1 -or
            [string]$Catalog.release -ne '2.0.0-preview.1' -or
            @($Catalog.families).Count -lt 1 -or @($Catalog.families).Count -gt 16) {
            return $false
        }
        if (-not (Test-SoftwareRecognitionText $Catalog.sourceRevision 1 128) -or
            @($Catalog.roles).Count -lt 1 -or @($Catalog.roles).Count -gt 16 -or
            @(Get-SoftwareRecognitionOrdinalStrings @($Catalog.roles)).Count -ne
                @($Catalog.roles).Count) { return $false }
        $knownRoles = @('EndpointSecurity','DeviceManagement','VpnOrZeroTrustNetworkAccess',
            'DataLossPrevention','Encryption','RemoteSupport',
            'AuthenticationOrCredentialProvider','Browser','PatchOrUpdateAgent',
            'BackupOrRecoveryAgent','OtherMigrationDependency')
        if (@($Catalog.roles | Where-Object { [string]$_ -notin $knownRoles }).Count -gt 0) {
            return $false
        }
        $licenseReview = $Catalog.licenseReview
        if (-not (Test-SoftwareRecognitionDate $licenseReview.reviewedOn) -or
            -not (Test-SoftwareRecognitionText $licenseReview.reviewer 1 128) -or
            -not (Test-SoftwareRecognitionText $licenseReview.reuseBasis 1 512) -or
            $licenseReview.thirdPartyAssetsIncluded -isnot [bool] -or
            [bool]$licenseReview.thirdPartyAssetsIncluded -or
            $licenseReview.unlicensedCatalogDataIncluded -isnot [bool] -or
            [bool]$licenseReview.unlicensedCatalogDataIncluded) { return $false }
        $operation = $Catalog.operation
        if ([string]$operation.operationId -ne 'annotate-software-recognition' -or
            [string]$operation.executionContext -ne 'InProcessValidatedAssessmentRecord' -or
            [string]$operation.privilege -ne 'StandardUser' -or
            [string]$operation.networkBehavior -ne 'OfflineOnly' -or
            [string]$operation.executableOrDependency -ne 'GeneratedWIN-PCInfoPowerShell' -or
            [int]$operation.deadlineMilliseconds -lt 1 -or
            [int]$operation.deadlineMilliseconds -gt 5000 -or
            [int]$operation.maximumInputEntries -ne 128 -or
            [int]$operation.maximumOutputAnnotations -ne 128 -or
            [int]$operation.maximumEvidenceUtf8Bytes -ne 262144 -or
            [string]$operation.cleanup -ne 'InMemoryOnly') { return $false }
        foreach ($flag in @('mayPrompt','mayInstall','mayDownload','maySelfElevate',
            'mayWidenScope','mayRequestAuthority','writesAllowed')) {
            if ($operation.$flag -isnot [bool] -or [bool]$operation.$flag) { return $false }
        }

        $allowedRoles = @($Catalog.roles)
        $familyIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $matcherIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($family in @($Catalog.families)) {
            if (-not $familyIds.Add([string]$family.familyId) -or
                [string]$family.familyId -notmatch '^[A-Za-z][A-Za-z0-9._:/-]*$' -or
                -not (Test-SoftwareRecognitionText $family.label 1 128) -or
                @($family.roles).Count -lt 1 -or @($family.roles).Count -gt 8 -or
                @(Get-SoftwareRecognitionOrdinalStrings @($family.roles)).Count -ne
                    @($family.roles).Count -or
                @($family.roles | Where-Object { [string]$_ -notin $allowedRoles }).Count -gt 0 -or
                @($family.sources).Count -lt 1 -or @($family.sources).Count -gt 8 -or
                @($family.matchers).Count -gt 16) { return $false }
            $state = [string]$family.lifecycle.state
            if ($state -eq 'active') {
                if (@($family.matchers).Count -lt 1 -or
                    $null -ne $family.lifecycle.reason -or
                    $null -ne $family.lifecycle.replacementFamilyId) { return $false }
            }
            elseif ($state -in @('superseded','withdrawn')) {
                if (@($family.matchers).Count -ne 0 -or
                    [string]::IsNullOrWhiteSpace([string]$family.lifecycle.reason)) {
                    return $false
                }
            }
            else { return $false }
            foreach ($source in @($family.sources)) {
                $uri = $null
                if (-not (Test-SoftwareRecognitionText $source.url 1 2048) -or
                    -not [Uri]::TryCreate([string]$source.url,[UriKind]::Absolute,[ref]$uri) -or
                    [string]$uri.Scheme -cne 'https' -or
                    -not (Test-SoftwareRecognitionText $source.owner 1 128) -or
                    -not (Test-SoftwareRecognitionDate $source.verifiedOn) -or
                    -not (Test-SoftwareRecognitionText $source.reviewer 1 128) -or
                    [string]$source.sourceType -notin @(
                        'PrimaryPublisherDocumentation','ControlledFreshInstallation',
                        'PinnedWinGetManifest'
                    )) { return $false }
                if ([string]$source.sourceType -eq 'PinnedWinGetManifest' -and
                    ([string]$source.pinnedCommit -notmatch '^[0-9a-f]{40}$' -or
                     [string]::IsNullOrWhiteSpace([string]$source.manifestPath))) {
                    return $false
                }
            }
            foreach ($matcher in @($family.matchers)) {
                if (-not (Test-SoftwareRecognitionText $matcher.matcherId 1 128) -or
                    [string]$matcher.matcherId -notmatch '^[A-Za-z][A-Za-z0-9._:/-]*$' -or
                    -not $matcherIds.Add([string]$matcher.matcherId)) { return $false }
                switch ([string]$matcher.type) {
                    'ExactPackageFamilyName' {
                        if (-not (Test-SoftwareRecognitionText $matcher.value 1 256) -or
                            [string]$matcher.value -notmatch '^[^_]+_[A-Za-z0-9]+$') {
                            return $false
                        }
                    }
                    { $_ -in @('ExactMsiProductCode','ExactMsiUpgradeCode') } {
                        if (-not (Test-SoftwareRecognitionText $matcher.value 38 38) -or
                            [string]$matcher.value -notmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') {
                            return $false
                        }
                    }
                    'CompositeRegistration' {
                        $names = @($matcher.fields.PSObject.Properties.Name)
                        if ([string]$matcher.registrationContext -notin @('Machine','AssessmentUser') -or
                            [string]$matcher.registryView -notin @('Registry32','Registry64') -or
                            'registrationId' -notin $names -or $names.Count -lt 2 -or
                            @($names | Where-Object {
                                $_ -notin @('registrationId','displayName','publisher','version','packageType')
                            }).Count -gt 0) { return $false }
                        foreach ($name in $names) {
                            $maximum = if ($name -eq 'version') { 256 } else { 512 }
                            if (-not (Test-SoftwareRecognitionText $matcher.fields.$name 1 $maximum)) {
                                return $false
                            }
                        }
                    }
                    default { return $false }
                }
            }
        }
        $true
    }
    catch { $false }
}

function Get-SoftwareRecognitionCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $TestJsonCommand
    )

    # The generated application embeds the reviewed bytes and a build-computed
    # digest. A digest mismatch means an authenticated release resource changed:
    # it is not an ordinary parse problem and cannot be bypassed or downgraded to
    # an unknown-product result. The caller loads this boundary before any device
    # collector, so the only safe response is a typed NotStarted terminal.
    $developmentSentinel = '__SOFTWARE_RECOGNITION_' + 'CATALOG_BASE64__'
    if ($script:SoftwareRecognitionCatalogBase64 -eq $developmentSentinel) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-software-recognition-catalog.json'
        $text = [IO.File]::ReadAllText($path, [Text.UTF8Encoding]::new($false, $true)).
            Replace("`r`n", "`n").Replace("`r", "`n")
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
        $expectedDigest = Get-SoftwareRecognitionSha256 -Bytes $bytes
        $schemaPath = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'schemas/software-recognition-catalog.schema.json'
        $schemaText = [IO.File]::ReadAllText(
            $schemaPath, [Text.UTF8Encoding]::new($false, $true)
        ).Replace("`r`n", "`n").Replace("`r", "`n")
        $schemaBytes = [Text.UTF8Encoding]::new($false).GetBytes($schemaText)
        $expectedSchemaDigest = Get-SoftwareRecognitionSha256 -Bytes $schemaBytes
    }
    else {
        try {
            $bytes = [Convert]::FromBase64String($script:SoftwareRecognitionCatalogBase64)
            $schemaBytes = [Convert]::FromBase64String($script:SoftwareRecognitionSchemaBase64)
        }
        catch {
            $exception = [Security.SecurityException]::new(
                'The embedded Software Recognition Catalog is not authentic.', $_.Exception
            )
            $exception.Data['ReasonCode'] = 'SOFTWARE_RECOGNITION.INTEGRITY_FAILED'
            throw $exception
        }
        $expectedDigest = $script:SoftwareRecognitionCatalogDigest
        $expectedSchemaDigest = $script:SoftwareRecognitionSchemaDigest
    }
    $actualDigest = Get-SoftwareRecognitionSha256 -Bytes $bytes
    $actualSchemaDigest = Get-SoftwareRecognitionSha256 -Bytes $schemaBytes
    if ($actualDigest -ne $expectedDigest -or
        $actualSchemaDigest -ne $expectedSchemaDigest) {
        $exception = [Security.SecurityException]::new(
            'The embedded Software Recognition Catalog failed digest validation.'
        )
        $exception.Data['ReasonCode'] = 'SOFTWARE_RECOGNITION.INTEGRITY_FAILED'
        throw $exception
    }

    # Authentication and logical usability are deliberately separate. Validly
    # authenticated bytes can still contain a schema or semantic defect. That
    # defect must not erase software already observed, so it becomes a confined
    # NotEvaluated annotation after collection rather than a run-level failure.
    try {
        $catalogText = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $schemaText = [Text.UTF8Encoding]::new($false, $true).GetString($schemaBytes)
        $catalog = & $ConvertFromJsonCommand -InputObject $catalogText `
            -Depth 30 -ErrorAction Stop
        $logicalLoadValid = [bool](& $TestJsonCommand -Json $catalogText `
            -Schema $schemaText -ErrorAction Stop) -and
            (Test-SoftwareRecognitionCatalog -Catalog $catalog)
    }
    catch {
        $catalog = $null
        $logicalLoadValid = $false
    }
    [pscustomobject][ordered]@{
        catalog = $catalog
        digest = $actualDigest
        logicalLoadValid = $logicalLoadValid
    }
}

function Test-SoftwareRecognitionComposite {
    param([Parameter(Mandatory)] $Entry, [Parameter(Mandatory)] $Matcher)

    if ([string]$Entry.registrationContext -ne [string]$Matcher.registrationContext -or
        [string]$Entry.registryView -ne [string]$Matcher.registryView) {
        return $false
    }
    $fieldNames = @($Matcher.fields.PSObject.Properties.Name)
    if ($fieldNames.Count -lt 2 -or
        @($fieldNames | Where-Object {
            $_ -notin @('registrationId','displayName','publisher','version','packageType')
        }).Count -gt 0) {
        return $false
    }
    foreach ($fieldName in $fieldNames) {
        if (-not [string]::Equals(
            [string]$Entry.$fieldName,
            [string]$Matcher.fields.$fieldName,
            [StringComparison]::Ordinal
        )) { return $false }
    }
    $true
}

function Get-SoftwareRecognitionEntryValue {
    param(
        [Parameter(Mandatory)] $Entry,
        [Parameter(Mandatory)] [string] $PropertyName
    )

    $property = $Entry.PSObject.Properties[$PropertyName]
    if ($null -eq $property -or $null -eq $property.Value) { return $null }
    [string]$property.Value
}

function Invoke-SoftwareRecognition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Entries,
        [Parameter(Mandatory)] $Catalog,
        [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{64}$')] [string] $CatalogDigest
    )

    if (-not (Test-SoftwareRecognitionCatalog -Catalog $Catalog)) {
        throw 'The Software Recognition Catalog is not logically usable.'
    }

    $annotations = foreach ($entry in $Entries) {
        $matchedRecords = @(
            foreach ($family in @($Catalog.families)) {
                if ([string]$family.lifecycle.state -ne 'active') { continue }
                foreach ($matcher in @($family.matchers)) {
                    if ([string]$matcher.type -eq 'CompositeRegistration') {
                        if (Test-SoftwareRecognitionComposite -Entry $entry -Matcher $matcher) {
                            [pscustomobject]@{ family = $family; matcher = $matcher }
                        }
                        continue
                    }
                    $observedProperty = switch ([string]$matcher.type) {
                        'ExactPackageFamilyName' { 'packageFamilyName' }
                        'ExactMsiProductCode' { 'productCode' }
                        'ExactMsiUpgradeCode' { 'upgradeCode' }
                        default { $null }
                    }
                    $observedIdentity = if ($null -ne $observedProperty) {
                        Get-SoftwareRecognitionEntryValue -Entry $entry `
                            -PropertyName $observedProperty
                    } else { $null }
                    if ($null -ne $observedIdentity -and
                        -not [string]::IsNullOrWhiteSpace($observedIdentity) -and
                        [string]::Equals($observedIdentity, [string]$matcher.value,
                            [StringComparison]::OrdinalIgnoreCase)) {
                        [pscustomobject]@{ family = $family; matcher = $matcher }
                    }
                }
            }
        )
        # Keep this as an explicit array even when exactly one family matches.
        # PowerShell otherwise unwraps the single string produced by an `if`
        # expression, and indexing that string would select its first character.
        [string[]]$matchedFamilyIds = @()
        if ($matchedRecords.Count -gt 0) {
            $matchedFamilyIds = @(Get-SoftwareRecognitionOrdinalStrings `
                -Values @($matchedRecords.family.familyId))
        }
        if ($matchedFamilyIds.Count -eq 1) {
            $familyMatches = @($matchedRecords | Where-Object {
                [string]::Equals([string]$_.family.familyId,
                    [string]$matchedFamilyIds[0],[StringComparison]::Ordinal)
            })
            $selectedMatch = $null
            foreach ($type in @('ExactPackageFamilyName','ExactMsiProductCode',
                'ExactMsiUpgradeCode','CompositeRegistration')) {
                $typeMatches = @($familyMatches | Where-Object {
                    [string]$_.matcher.type -ceq $type
                })
                if ($typeMatches.Count -eq 0) { continue }
                $selectedId = @(Get-SoftwareRecognitionOrdinalStrings `
                    -Values @($typeMatches.matcher.matcherId))[0]
                $selectedMatch = $typeMatches | Where-Object {
                    [string]::Equals([string]$_.matcher.matcherId,$selectedId,
                        [StringComparison]::Ordinal)
                } | Select-Object -First 1
                break
            }
            [pscustomobject][ordered]@{
                subjectId = $null
                outcome = if ([string]$selectedMatch.matcher.type -eq 'CompositeRegistration') {
                    'RecognizedComposite'
                } else { 'RecognizedExact' }
                familyId = [string]$selectedMatch.family.familyId
                familyLabel = [string]$selectedMatch.family.label
                roles = @($selectedMatch.family.roles)
                matcherIds = @(Get-SoftwareRecognitionOrdinalStrings `
                    -Values @($familyMatches.matcher.matcherId))
                matcherTypes = @(Get-SoftwareRecognitionOrdinalStrings `
                    -Values @($familyMatches.matcher.type))
                matchStrengthExplanation = switch ([string]$selectedMatch.matcher.type) {
                    'ExactPackageFamilyName' { 'Exact package family name' }
                    'ExactMsiProductCode' { 'Exact MSI ProductCode' }
                    'ExactMsiUpgradeCode' { 'Exact MSI UpgradeCode' }
                    'CompositeRegistration' {
                        "Exact registration-field composite in $([string]$selectedMatch.matcher.registrationContext) $([string]$selectedMatch.matcher.registryView) context"
                    }
                }
                reasonCode = $null
                catalogRevision = [int]$Catalog.catalogRevision
                catalogRelease = [string]$Catalog.release
                catalogDigest = $CatalogDigest
                provenance = @($selectedMatch.family.sources)
            }
        }
        elseif ($matchedFamilyIds.Count -gt 1) {
            [pscustomobject][ordered]@{
                subjectId = $null
                outcome = 'Ambiguous'
                familyId = $null
                familyLabel = $null
                roles = @()
                matcherIds = @(Get-SoftwareRecognitionOrdinalStrings `
                    -Values @($matchedRecords.matcher.matcherId))
                matcherTypes = @(Get-SoftwareRecognitionOrdinalStrings `
                    -Values @($matchedRecords.matcher.type))
                matchStrengthExplanation = 'More than one catalog family matched; WIN-PCInfo did not choose by catalog order.'
                reasonCode = 'SOFTWARE_RECOGNITION.MULTIPLE_FAMILIES_MATCHED'
                catalogRevision = [int]$Catalog.catalogRevision
                catalogRelease = [string]$Catalog.release
                catalogDigest = $CatalogDigest
                provenance = @()
            }
        }
        else {
            [pscustomobject][ordered]@{
                subjectId = $null
                outcome = 'Unrecognized'
                familyId = $null
                familyLabel = $null
                roles = @()
                matcherIds = @()
                matcherTypes = @()
                matchStrengthExplanation = 'No release-catalog identity matched the observed registration.'
                reasonCode = 'SOFTWARE_RECOGNITION.NO_MATCH'
                catalogRevision = [int]$Catalog.catalogRevision
                catalogRelease = [string]$Catalog.release
                catalogDigest = $CatalogDigest
                provenance = @()
            }
        }
    }
    if ((Get-SoftwareRecognitionResultMaximumUtf8Bytes -Annotations @($annotations)) -gt
        [int]$Catalog.operation.maximumEvidenceUtf8Bytes) {
        throw 'The Software Recognition annotation output exceeds its frozen UTF-8 ceiling.'
    }
    [pscustomobject][ordered]@{
        state = 'Evaluated'
        reasonCode = 'SOFTWARE_RECOGNITION.EVALUATED'
        annotations = @($annotations)
    }
}

function Add-SoftwareRecognitionAnnotations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Entries,
        [Parameter(Mandatory)] $CatalogResult
    )

    if ($Record.PSObject.Properties['softwareRecognition']) {
        throw 'Software Recognition annotations cannot be added twice.'
    }
    $applicationSubjects = @($Record.subjects | Where-Object kind -eq 'Application' |
        Sort-Object { [int]([string]$_.subjectId).Substring('subject:software:'.Length) })
    if ($Entries.Count -ne $applicationSubjects.Count -or $Entries.Count -gt 128) {
        throw 'Software Recognition requires one authoritative application subject per input entry.'
    }
    $evaluation = if ([bool]$CatalogResult.logicalLoadValid) {
        Invoke-SoftwareRecognitionSafely -Entries $Entries -Catalog $CatalogResult.catalog `
            -CatalogDigest ([string]$CatalogResult.digest)
    }
    else {
        Invoke-SoftwareRecognitionSafely -Entries $Entries `
            -Catalog ([pscustomobject]@{ kind = 'authenticated-logical-load-failure' }) `
            -CatalogDigest ([string]$CatalogResult.digest)
    }
    if (@($evaluation.annotations).Count -ne $Entries.Count) {
        throw 'Software Recognition did not account for every authoritative inventory entry.'
    }
    $runId = [string]$Record.run.runId
    $annotations = @(
        for ($index = 0; $index -lt $Entries.Count; $index++) {
            $source = $evaluation.annotations[$index]
            [pscustomobject][ordered]@{
                annotationId = "annotation:software-recognition-$index`:$runId"
                subjectId = [string]$applicationSubjects[$index].subjectId
                outcome = [string]$source.outcome
                familyId = $source.familyId
                familyLabel = $source.familyLabel
                roles = @($source.roles)
                matcherIds = @($source.matcherIds)
                matcherTypes = @($source.matcherTypes)
                matchStrengthExplanation = [string]$source.matchStrengthExplanation
                reasonCode = $source.reasonCode
                catalogRevision = [int]$source.catalogRevision
                catalogRelease = [string]$source.catalogRelease
                catalogDigest = [string]$source.catalogDigest
                provenance = @($source.provenance)
            }
        }
    )
    $Record | Add-Member -NotePropertyName softwareRecognition -NotePropertyValue $annotations
    if ('software-recognition-annotations' -notin @($Record.requiredFeatures)) {
        $Record.requiredFeatures = @($Record.requiredFeatures) + 'software-recognition-annotations'
    }
    $Record
}

function Invoke-SoftwareRecognitionSafely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Entries,
        [Parameter(Mandatory)] $Catalog,
        [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{64}$')] [string] $CatalogDigest
    )

    try {
        Invoke-SoftwareRecognition -Entries $Entries -Catalog $Catalog `
            -CatalogDigest $CatalogDigest
    }
    catch {
        [pscustomobject][ordered]@{
            state = 'NotEvaluated'
            reasonCode = 'SOFTWARE_RECOGNITION.CATALOG_LOGICAL_FAILURE'
            annotations = @(
                foreach ($entry in $Entries) {
                    [pscustomobject][ordered]@{
                        subjectId = $null
                        outcome = 'NotEvaluated'
                        familyId = $null
                        familyLabel = $null
                        roles = @()
                        matcherIds = @()
                        matcherTypes = @()
                        matchStrengthExplanation = 'The release catalog could not be evaluated; ordinary inventory remains authoritative.'
                        reasonCode = 'SOFTWARE_RECOGNITION.CATALOG_LOGICAL_FAILURE'
                        catalogRevision = 0
                        catalogRelease = '2.0.0-preview.1'
                        catalogDigest = $CatalogDigest
                        provenance = @()
                    }
                }
            )
        }
    }
}
