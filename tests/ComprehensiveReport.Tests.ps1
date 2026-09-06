[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ContractValidator.ps1')
foreach ($source in @('RuntimeCompatibility', 'ProcessSupervisor',
    'EvidenceWorkspace', 'ProtectedPackage', 'DeviceReadiness')) {
    . (Join-Path $repositoryRoot "src/$source.ps1")
}

$convertFromJson = $ExecutionContext.InvokeCommand.GetCommand(
    'ConvertFrom-Json', [System.Management.Automation.CommandTypes]::Cmdlet
)
$convertToJson = $ExecutionContext.InvokeCommand.GetCommand(
    'ConvertTo-Json', [System.Management.Automation.CommandTypes]::Cmdlet
)
$testJson = $ExecutionContext.InvokeCommand.GetCommand(
    'Test-Json', [System.Management.Automation.CommandTypes]::Cmdlet
)

$policy = Get-DeviceReadinessPolicy -ConvertFromJsonCommand $convertFromJson
$collector = Invoke-ApprovedCollectorProcess -OperationId ([string] $policy.collector.operationId) `
    -DeviceReadinessScenario 'Complete'
$evidence = ConvertTo-NormalizedDeviceReadinessEvidence -Payload $collector.PrivatePayload
$record = New-DeviceReadinessAssessmentRecord -RunId 'run:report:test' -Evidence $evidence `
    -CollectorResult $collector -Policy $policy -ValidationFixture $true
$recordBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
    (& $convertToJson -InputObject $record -Compress -Depth 30)
)
$validation = Test-AssessmentContract -Utf8Bytes $recordBytes `
    -ConvertFromJsonCommand $convertFromJson -TestJsonCommand $testJson
$baseRecord = Complete-ValidatedDeviceReadinessAssessmentRecord `
    -ValidatedRecord $record -Policy $policy -ContractValidation $validation

$originalBytes = New-DeviceReadinessReportBytes -Record $baseRecord
$originalHash = Get-ProtectedPackageSha256 -Bytes $originalBytes
$originalRecord = $baseRecord | ConvertTo-Json -Depth 30 -Compress
$derivedBytes = New-DeviceReadinessReportBytes -Record $baseRecord -DerivationKind ReEvaluated -SourceReportSha256 $originalHash
$derivedText = [Text.Encoding]::UTF8.GetString($derivedBytes)
Assert-Equal $true $derivedText.Contains('ReEvaluated') 'explicit re-evaluation remains distinguishable from the original report'
Assert-Equal $true $derivedText.Contains($originalHash) 'derived HTML identifies the original report by digest'
Assert-Equal $originalRecord ($baseRecord | ConvertTo-Json -Depth 30 -Compress) 'rendering preserves the original canonical record'
foreach ($invalidInputs in @(@{ DerivationKind = 'ReRendered' }, @{ SourceReportSha256 = $originalHash })) {
    $refused = $false
    try { $null = New-DeviceReadinessReportBytes -Record $baseRecord @invalidInputs } catch { $refused = $true }
    Assert-Equal $true $refused 'ambiguous original/derived provenance is refused'
}

function Copy-TestRecord {
    param([Parameter(Mandatory)] $Record)

    $Record | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
}

function Set-TestObservationValue {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] [string] $FieldId,
        [Parameter(Mandatory)] [string] $Value
    )

    $observation = @($Record.observations | Where-Object fieldId -eq $FieldId)[0]
    if ($null -eq $observation) {
        throw "The test record did not contain observation '$FieldId'."
    }
    $observation.value = $Value
}

$cases = @(
    @{ outcome = 'Completed'; completeness = 'Complete' }
    @{ outcome = 'CompletedWithGaps'; completeness = 'RecoverablePartial' }
    @{ outcome = 'Cancelled'; completeness = 'RecoverablePartial' }
    @{ outcome = 'TimedOut'; completeness = 'RecoverablePartial' }
    @{ outcome = 'IntegrityFailed'; completeness = 'RecoverablePartial' }
    @{ outcome = 'CleanupIncomplete'; completeness = 'RecoverablePartial' }
)

foreach ($case in $cases) {
    $variant = Copy-TestRecord -Record $baseRecord
    $variant.run.outcome = $case.outcome
    if ($case.outcome -ne 'Completed') {
        $variant.coverage[0].state = 'Partial'
        if ($variant.coverage[0].PSObject.Properties['reasonCode']) {
            $variant.coverage[0].reasonCode = "RUN.$($case.outcome.ToUpperInvariant())"
        }
        else {
            $variant.coverage[0] | Add-Member -NotePropertyName reasonCode `
                -NotePropertyValue "RUN.$($case.outcome.ToUpperInvariant())"
        }
    }
    [byte[]] $firstBytes = New-DeviceReadinessReportBytes -Record $variant
    [byte[]] $secondBytes = New-DeviceReadinessReportBytes -Record $variant
    $firstText = [System.Text.UTF8Encoding]::new($false, $true).GetString($firstBytes)
    foreach ($scope in $variant.coverage) {
        Assert-Equal $true $firstText.Contains([Net.WebUtility]::HtmlEncode([string]$scope.scopeId)) 'every admitted scope has an explicit report coverage entry'
    }
    foreach ($link in [regex]::Matches($firstText, 'href="#([^"]+)"')) {
        Assert-Equal $true $firstText.Contains('id="' + $link.Groups[1].Value + '"') `
            'every offline navigation link resolves without scripting'
    }
    Assert-Equal $true $firstText.Contains([Net.WebUtility]::HtmlEncode([string]$variant.run.evidenceProfileId)) `
        'the overview identifies the actual selected evidence profile'
    $contract = Test-AssessmentReportContract -ReportBytes $firstBytes -Record $variant `
        -ExpectUnicode $false

    Assert-Equal $true ([System.Linq.Enumerable]::SequenceEqual[byte]($firstBytes, $secondBytes)) `
        "$($case.outcome) remains byte-identical across repeated renders"
    Assert-Equal $true $contract.executiveSummaryVerified `
        "$($case.outcome) keeps the executive summary ahead of evidence"
    Assert-Equal $true $contract.categorySeparationVerified `
        "$($case.outcome) keeps report categories distinct"
    Assert-Equal $true $contract.offlineSafeVerified `
        "$($case.outcome) remains self-contained and scripting-free"
    Assert-Equal $true $contract.keyboardNavigationVerified `
        "$($case.outcome) keeps keyboard navigation visible"
    Assert-Equal $true $contract.printLayoutVerified `
        "$($case.outcome) keeps print layout rules"
    Assert-Equal $true $contract.utf8Verified `
        "$($case.outcome) stays valid UTF-8 HTML"
    Assert-Equal $case.completeness $contract.renderedCompleteness `
        "$($case.outcome) maps to the expected report completeness label"
    if (-not $firstText.Contains('WIN-PCInfo Comprehensive Local Assessment')) {
        throw "$($case.outcome) did not render the comprehensive report title."
    }
    if (-not $firstText.Contains((Get-AssessmentReportOutcomeLabel -Outcome $case.outcome))) {
        throw "$($case.outcome) did not render its outcome label."
    }
}

$localeCases = @(
    @{ locale = 'en-US'; model = 'Baseline Device'; expectUnicode = $false }
    @{ locale = 'es-MX'; model = 'Estación México'; expectUnicode = $true }
    @{ locale = 'tr-TR'; model = 'İstanbul İstemcisi'; expectUnicode = $true }
    @{ locale = 'ja-JP'; model = '東京端末'; expectUnicode = $true }
    @{ locale = 'ar-SA'; model = 'جهاز-الرياض'; expectUnicode = $true }
)

foreach ($case in $localeCases) {
    $variant = Copy-TestRecord -Record $baseRecord
    foreach ($provenance in @($variant.provenance)) {
        $provenance.sourceLocale = $case.locale
    }
    Set-TestObservationValue -Record $variant -FieldId 'field:device.model' -Value $case.model
    [byte[]] $bytes = New-DeviceReadinessReportBytes -Record $variant
    $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $contract = Test-AssessmentReportContract -ReportBytes $bytes -Record $variant `
        -ExpectUnicode $case.expectUnicode

    Assert-Equal $true $contract.verified `
        "$($case.locale) remains a valid comprehensive report render"
    $encodedModel = [System.Net.WebUtility]::HtmlEncode($case.model)
    if (-not ($text.Contains($case.model) -or $text.Contains($encodedModel))) {
        throw "$($case.locale) did not preserve its locale fixture content in the report."
    }
}

$maximumRecord = Copy-TestRecord -Record $baseRecord
$unknownRecord = Copy-TestRecord -Record $baseRecord
$unknownObservation = @($unknownRecord.observations | Where-Object fieldId -eq 'field:device.processor.name')[0]
$unknownObservation.valueState = 'SourceReportedUnknown'
$unknownObservation.PSObject.Properties.Remove('value')
$unknownText = [Text.Encoding]::UTF8.GetString((New-DeviceReadinessReportBytes -Record $unknownRecord))
Assert-Equal $true $unknownText.Contains('SourceReportedUnknown') 'source-reported unknown remains distinct from uncollected or absent evidence'
[byte[]] $maximumBytes = $null
for ($length = 220000; $length -ge 120000; $length -= 10000) {
    $maximumRecord = Copy-TestRecord -Record $baseRecord
    Set-TestObservationValue -Record $maximumRecord -FieldId 'field:device.processor.name' `
        -Value ('P' * $length)
    [byte[]] $candidateBytes = New-DeviceReadinessReportBytes -Record $maximumRecord
    if ($candidateBytes.Length -le 262144 -and $candidateBytes.Length -ge 200000) {
        $maximumBytes = $candidateBytes
        break
    }
}
if ($null -eq $maximumBytes) {
    throw 'The maximum-size synthetic record did not reach the report stress threshold.'
}
[byte[]] $maximumBytesRepeat = New-DeviceReadinessReportBytes -Record $maximumRecord
$maximumContract = Test-AssessmentReportContract -ReportBytes $maximumBytes -Record $maximumRecord `
    -ExpectUnicode $false

Assert-Equal $true ([System.Linq.Enumerable]::SequenceEqual[byte]($maximumBytes, $maximumBytesRepeat)) `
    'the maximum-size synthetic record remains byte-identical across repeated renders'
Assert-Equal $true ($maximumBytes.Length -le 262144) `
    'the maximum-size synthetic record stays within the protected-package report bound'
Assert-Equal $true $maximumContract.verified `
    'the maximum-size synthetic record still satisfies the comprehensive report contract'

Write-Output 'PASS: the comprehensive report renderer preserves deterministic executive summaries, locale fixtures, and bounded maximum-size output.'
