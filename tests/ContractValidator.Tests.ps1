[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationFixturePath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
$contractFixturePath = Join-Path $PSScriptRoot 'fixtures/contract-positive.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

function Invoke-ContractFixture {
    param([Parameter(Mandatory)] [string] $LiteralPath)

    $run = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation',
        '-RequestPath', $requestPath,
        '-AcceptPreparation',
        '-PreparationFixturePath', $preparationFixturePath,
        '-ContractFixturePath', $LiteralPath
    )
    $records = @($run.Records | Where-Object recordType -eq 'win-pcinfo.contract-validation')
    [pscustomobject]@{
        Run = $run
        Records = $records
        Validation = if ($records.Count -eq 1) { $records[0] } else { $null }
    }
}

$positive = Invoke-ContractFixture -LiteralPath $contractFixturePath
$result = $positive.Run

Assert-Equal 20 $result.ExitCode 'contract fixtures never authorize real collection'
$validation = $positive.Records
Assert-Equal 1 $validation.Count 'the exported Contract Validator emits one public result'
Assert-Equal $true $validation[0].accepted 'the complete multilingual synthetic record is accepted'
Assert-Equal 'CONTRACT.ACCEPTED' $validation[0].reasonCode 'acceptance uses a stable project semantic reason'
Assert-Equal '2020-12' $validation[0].schemaDraft 'the release Contract Set uses Draft 2020-12'

$terminal = $result.Records[-1]
Assert-Equal 'ContractValidation' $terminal.phase 'the generated application exposes the validator after preparation'
Assert-Equal 'SLICE.CONTRACT_VALIDATION_COMPLETE' $terminal.reasonCode `
    'the tracer bullet ends honestly without a Product Capability claim'
Assert-Equal $false $terminal.collectionStarted 'synthetic validation cannot start device collection'
Assert-Equal $true $terminal.validationFixture 'synthetic validation remains visibly fixture-only'

Write-Output 'PASS: one multilingual synthetic Assessment Record crosses the exported Contract Validator seam.'

$malformedPath = Join-Path $PSScriptRoot 'fixtures/contract-malformed.json'
$malformed = Invoke-ContractFixture -LiteralPath $malformedPath
$malformedValidation = $malformed.Validation
Assert-Equal $false $malformedValidation.accepted 'malformed JSON is rejected before interpretation'
Assert-Equal 'CONTRACT.JSON_INVALID' $malformedValidation.reasonCode `
    'malformed JSON has a stable project reason instead of parser text'

Write-Output 'PASS: malformed JSON fails closed at the exported Contract Validator seam.'

$duplicatePath = Join-Path $PSScriptRoot 'fixtures/contract-duplicate-property.json'
$duplicate = Invoke-ContractFixture -LiteralPath $duplicatePath
$duplicateValidation = $duplicate.Validation
Assert-Equal $false $duplicateValidation.accepted 'duplicate property names are never last-value-wins'
Assert-Equal 'CONTRACT.DUPLICATE_PROPERTY' $duplicateValidation.reasonCode `
    'duplicate property rejection is stable and independent of the JSON converter'

Write-Output 'PASS: duplicate JSON property names fail closed before conversion.'

$generatedFixtureRoot = Join-Path $repositoryRoot '.test-output/contract-validator'
$null = New-Item -ItemType Directory -Path $generatedFixtureRoot -Force
$invalidUtf8Path = Join-Path $generatedFixtureRoot 'invalid-utf8.json'
[System.IO.File]::WriteAllBytes($invalidUtf8Path, [byte[]] @(0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d))
$invalidUtf8 = Invoke-ContractFixture -LiteralPath $invalidUtf8Path
$invalidUtf8Validation = $invalidUtf8.Validation
Assert-Equal $false $invalidUtf8Validation.accepted 'non-UTF-8 bytes are rejected'
Assert-Equal 'CONTRACT.UTF8_INVALID' $invalidUtf8Validation.reasonCode `
    'encoding failure is distinguished from malformed JSON'

Write-Output 'PASS: invalid UTF-8 fails closed before JSON parsing.'

$invalidUnicodePath = Join-Path $PSScriptRoot 'fixtures/contract-invalid-unicode.json'
$invalidUnicode = Invoke-ContractFixture -LiteralPath $invalidUnicodePath
$invalidUnicodeValidation = $invalidUnicode.Validation
Assert-Equal $false $invalidUnicodeValidation.accepted 'unpaired Unicode surrogates are rejected'
Assert-Equal 'CONTRACT.UNICODE_INVALID' $invalidUnicodeValidation.reasonCode `
    'invalid Unicode is distinguished from valid multilingual content'

Write-Output 'PASS: invalid Unicode fails closed while multilingual UTF-8 remains accepted.'

$oversizePath = Join-Path $generatedFixtureRoot 'oversize.json'
$oversizeText = '{"syntheticPadding":"' + ('x' * 32768) + '"}'
[System.IO.File]::WriteAllText($oversizePath, $oversizeText, [System.Text.UTF8Encoding]::new($false))
$oversize = Invoke-ContractFixture -LiteralPath $oversizePath
$oversizeValidation = $oversize.Validation
Assert-Equal $false $oversizeValidation.accepted 'oversize input is rejected before full parsing'
Assert-Equal 'CONTRACT.SIZE_EXCEEDED' $oversizeValidation.reasonCode `
    'the release-owned byte ceiling has a stable reason'

Write-Output 'PASS: the Contract Validator enforces its release-owned UTF-8 byte ceiling.'

$depthPath = Join-Path $generatedFixtureRoot 'depth-exceeded.json'
$depthText = ('{"x":' * 17) + 'true' + ('}' * 17)
[System.IO.File]::WriteAllText($depthPath, $depthText, [System.Text.UTF8Encoding]::new($false))
$depth = Invoke-ContractFixture -LiteralPath $depthPath
$depthValidation = $depth.Validation
Assert-Equal $false $depthValidation.accepted 'deeply nested input is rejected'
Assert-Equal 'CONTRACT.DEPTH_EXCEEDED' $depthValidation.reasonCode `
    'the release-owned depth ceiling has a stable reason'

Write-Output 'PASS: the Contract Validator enforces its release-owned JSON depth ceiling.'

$numberPath = Join-Path $generatedFixtureRoot 'unsafe-number.json'
[System.IO.File]::WriteAllText($numberPath, '{"syntheticNumber":9007199254740992}', [System.Text.UTF8Encoding]::new($false))
$number = Invoke-ContractFixture -LiteralPath $numberPath
$numberValidation = $number.Validation
Assert-Equal $false $numberValidation.accepted 'integers outside the I-JSON interoperable range are rejected'
Assert-Equal 'CONTRACT.NUMBER_INVALID' $numberValidation.reasonCode `
    'unsafe numeric precision has a stable reason'

Write-Output 'PASS: the Contract Validator enforces its I-JSON-style numeric range.'

$incompatibleMajorPath = Join-Path $generatedFixtureRoot 'incompatible-major.json'
$incompatibleMajorRecord = Get-Content -LiteralPath $contractFixturePath -Raw | ConvertFrom-Json -Depth 30
$incompatibleMajorRecord.contractVersion = '2.0.0'
[System.IO.File]::WriteAllText(
    $incompatibleMajorPath,
    ($incompatibleMajorRecord | ConvertTo-Json -Compress -Depth 30),
    [System.Text.UTF8Encoding]::new($false)
)
$incompatibleMajor = Invoke-ContractFixture -LiteralPath $incompatibleMajorPath
$incompatibleMajorValidation = $incompatibleMajor.Validation
Assert-Equal $false $incompatibleMajorValidation.accepted 'an incompatible major version is rejected'
Assert-Equal 'CONTRACT.VERSION_INCOMPATIBLE' $incompatibleMajorValidation.reasonCode `
    'major-version incompatibility is distinct from malformed shape'

Write-Output 'PASS: incompatible Assessment Contract Set major versions fail closed.'

$unsupportedFeaturePath = Join-Path $generatedFixtureRoot 'unsupported-feature.json'
$unsupportedFeatureRecord = Get-Content -LiteralPath $contractFixturePath -Raw | ConvertFrom-Json -Depth 30
$unsupportedFeatureRecord.requiredFeatures += 'future-meaning-required'
[System.IO.File]::WriteAllText(
    $unsupportedFeaturePath,
    ($unsupportedFeatureRecord | ConvertTo-Json -Compress -Depth 30),
    [System.Text.UTF8Encoding]::new($false)
)
$unsupportedFeature = Invoke-ContractFixture -LiteralPath $unsupportedFeaturePath
$unsupportedFeatureValidation = $unsupportedFeature.Validation
Assert-Equal $false $unsupportedFeatureValidation.accepted 'unknown required meaning is not ignored'
Assert-Equal 'CONTRACT.REQUIRED_FEATURE_UNSUPPORTED' $unsupportedFeatureValidation.reasonCode `
    'unsupported Required Contract Features fail independently of version syntax'

Write-Output 'PASS: unsupported Required Contract Features fail closed.'

$prohibitedSecretPath = Join-Path $generatedFixtureRoot 'prohibited-secret.json'
$prohibitedSecretRecord = Get-Content -LiteralPath $contractFixturePath -Raw | ConvertFrom-Json -Depth 30
$prohibitedSecretRecord.observations[0].fieldId = 'field:security.wifi.password'
$prohibitedSecretRecord.observations[0].value = 'SYNTHETIC-SECRET-LIKE-DO-NOT-USE'
[System.IO.File]::WriteAllText(
    $prohibitedSecretPath,
    ($prohibitedSecretRecord | ConvertTo-Json -Compress -Depth 30),
    [System.Text.UTF8Encoding]::new($false)
)
$prohibitedSecret = Invoke-ContractFixture -LiteralPath $prohibitedSecretPath
$prohibitedSecretValidation = $prohibitedSecret.Validation
Assert-Equal $false $prohibitedSecretValidation.accepted 'a secret-bearing field cannot enter evidence'
Assert-Equal 'CONTRACT.PRIVACY_VIOLATION' $prohibitedSecretValidation.reasonCode `
    'Prohibited Secret Material is rejected without copying or hashing it into output'
if ($prohibitedSecret.Run.StandardOutput -match 'SYNTHETIC-SECRET-LIKE-DO-NOT-USE') {
    throw 'The public validation stream copied the rejected secret-like fixture value.'
}

Write-Output 'PASS: prohibited secret-like evidence is omitted and represented only by a stable rejection.'

$invalidReferencePath = Join-Path $generatedFixtureRoot 'invalid-reference.json'
$invalidReferenceRecord = Get-Content -LiteralPath $contractFixturePath -Raw | ConvertFrom-Json -Depth 30
$invalidReferenceRecord.findings[0].evidenceReferences[0].observationId = 'observation:synthetic-missing:999'
[System.IO.File]::WriteAllText(
    $invalidReferencePath,
    ($invalidReferenceRecord | ConvertTo-Json -Compress -Depth 30),
    [System.Text.UTF8Encoding]::new($false)
)
$invalidReference = Invoke-ContractFixture -LiteralPath $invalidReferencePath
$invalidReferenceValidation = $invalidReference.Validation
Assert-Equal $false $invalidReferenceValidation.accepted 'dangling evidence references are rejected'
Assert-Equal 'CONTRACT.REFERENCE_INVALID' $invalidReferenceValidation.reasonCode `
    'reference failure is distinct from a missing observation value'

Write-Output 'PASS: every Assessment Evidence Reference must resolve exactly.'

$invalidGraphPath = Join-Path $generatedFixtureRoot 'invalid-graph.json'
$invalidGraphRecord = Get-Content -LiteralPath $contractFixturePath -Raw | ConvertFrom-Json -Depth 30
$invalidGraphRecord.recommendations += [pscustomobject][ordered]@{
    recommendationId = 'recommendation:synthetic-follow-up:002'
    definitionId = 'recommendation:synthetic-follow-up/1.0.0'
    kind = 'TenantSideDiscoveryTask'
    findingIds = @('finding:synthetic-os-observed:001')
}
$invalidGraphRecord.recommendationRelationships = @(
    [pscustomobject][ordered]@{
        relationshipId = 'relationship:synthetic:001'
        fromRecommendationId = 'recommendation:synthetic-follow-up:001'
        toRecommendationId = 'recommendation:synthetic-follow-up:002'
        kind = 'Requires'
    }
    [pscustomobject][ordered]@{
        relationshipId = 'relationship:synthetic:002'
        fromRecommendationId = 'recommendation:synthetic-follow-up:002'
        toRecommendationId = 'recommendation:synthetic-follow-up:001'
        kind = 'Requires'
    }
)
[System.IO.File]::WriteAllText(
    $invalidGraphPath,
    ($invalidGraphRecord | ConvertTo-Json -Compress -Depth 30),
    [System.Text.UTF8Encoding]::new($false)
)
$invalidGraph = Invoke-ContractFixture -LiteralPath $invalidGraphPath
$invalidGraphValidation = $invalidGraph.Validation
Assert-Equal $false $invalidGraphValidation.accepted 'cyclic recommendation dependencies are rejected'
Assert-Equal 'CONTRACT.GRAPH_INVALID' $invalidGraphValidation.reasonCode `
    'a valid-reference graph can still fail its acyclic semantic contract'

Write-Output 'PASS: recommendation dependency graphs must be acyclic.'

$inconsistentCoveragePath = Join-Path $generatedFixtureRoot 'inconsistent-coverage.json'
$inconsistentCoverageRecord = Get-Content -LiteralPath $contractFixturePath -Raw | ConvertFrom-Json -Depth 30
$inconsistentCoverageRecord.coverage[0].state = 'Complete'
[System.IO.File]::WriteAllText(
    $inconsistentCoveragePath,
    ($inconsistentCoverageRecord | ConvertTo-Json -Compress -Depth 30),
    [System.Text.UTF8Encoding]::new($false)
)
$inconsistentCoverage = Invoke-ContractFixture -LiteralPath $inconsistentCoveragePath
$inconsistentCoverageValidation = $inconsistentCoverage.Validation
Assert-Equal $false $inconsistentCoverageValidation.accepted 'Complete coverage cannot retain a failure reason and diagnostic'
Assert-Equal 'CONTRACT.COVERAGE_INCONSISTENT' $inconsistentCoverageValidation.reasonCode `
    'coverage inconsistency is not collapsed into observation or run state'

Write-Output 'PASS: Evidence Coverage State remains closed and internally consistent.'

$fieldBoundPath = Join-Path $generatedFixtureRoot 'field-bound-exceeded.json'
$fieldBoundRecord = Get-Content -LiteralPath $contractFixturePath -Raw | ConvertFrom-Json -Depth 30
$fieldBoundRecord.observations[0].value = 'x' * 257
[System.IO.File]::WriteAllText(
    $fieldBoundPath,
    ($fieldBoundRecord | ConvertTo-Json -Compress -Depth 30),
    [System.Text.UTF8Encoding]::new($false)
)
$fieldBound = Invoke-ContractFixture -LiteralPath $fieldBoundPath
$fieldBoundValidation = $fieldBound.Validation
Assert-Equal $false $fieldBoundValidation.accepted 'an admitted field cannot exceed its own release bound'
Assert-Equal 'CONTRACT.FIELD_BOUND_EXCEEDED' $fieldBoundValidation.reasonCode `
    'field bounds are enforced separately from the whole-document safety ceiling'

Write-Output 'PASS: Evidence Field Definition bounds are enforced on admitted observations.'
