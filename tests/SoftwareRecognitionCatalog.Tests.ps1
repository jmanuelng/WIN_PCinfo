[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/SoftwareRecognition.ps1')

$catalogPath = Join-Path $repositoryRoot `
    'docs/spec/releases/2.0.0-preview.1-software-recognition-catalog.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/software-recognition-catalog.schema.json'
$catalogJson = Get-Content -Raw -LiteralPath $catalogPath
Assert-Equal $true (Test-Json -Json $catalogJson -SchemaFile $schemaPath) `
    'the release snapshot satisfies its strict Draft 2020-12 data-only schema'

$catalogResult = Get-SoftwareRecognitionCatalog `
    -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet) `
    -TestJsonCommand (Get-Command Test-Json -CommandType Cmdlet)
$catalog = $catalogResult.catalog
Assert-Equal '2.0.0-preview.1' $catalog.release 'the catalog belongs to one product release'
Assert-Equal 1 $catalog.catalogRevision 'the catalog revision is monotonically explicit'
Assert-Equal 3 @($catalog.families).Count 'the initial seed is deliberately small'
Assert-Equal $true (Test-SoftwareRecognitionCatalog -Catalog $catalog) `
    'the seed is semantically closed beyond JSON shape validation'
Assert-Equal 'annotate-software-recognition' $catalog.operation.operationId `
    'the in-process operation identity is frozen before approval'
foreach ($property in @(
    'mayPrompt','mayInstall','mayDownload','maySelfElevate','mayWidenScope',
    'mayRequestAuthority','writesAllowed'
)) {
    Assert-Equal $false $catalog.operation.$property `
        "the recognition operation cannot use $property as a late authority path"
}
Assert-Equal 'OfflineOnly' $catalog.operation.networkBehavior `
    'recognition has no live catalog, reputation, or package-availability request'
Assert-Equal $false $catalog.licenseReview.thirdPartyAssetsIncluded `
    'the seed redistributes no third-party installer, image, logo, or marketing asset'
Assert-Equal $false $catalog.licenseReview.unlicensedCatalogDataIncluded `
    'the seed does not copy an external software catalog'

$duplicate = $catalog | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
$duplicate.families = @($duplicate.families) + @($duplicate.families[0])
Assert-Equal $false (Test-SoftwareRecognitionCatalog -Catalog $duplicate) `
    'duplicate family and matcher identities invalidate the logical snapshot'

$withdrawn = $catalog | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
$withdrawn.families[0].lifecycle.state = 'withdrawn'
$withdrawn.families[0].lifecycle.reason = 'Synthetic withdrawal fixture.'
$withdrawn.families[0].matchers = @()
Assert-Equal $true (Test-SoftwareRecognitionCatalog -Catalog $withdrawn) `
    'a withdrawn family survives only as a reasoned matcher-free tombstone'

$invalidWithdrawn = $catalog | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
$invalidWithdrawn.families[0].lifecycle.state = 'withdrawn'
$invalidWithdrawn.families[0].lifecycle.reason = 'Synthetic invalid tombstone.'
Assert-Equal $false (Test-SoftwareRecognitionCatalog -Catalog $invalidWithdrawn) `
    'a withdrawn family cannot continue recognizing new inventory'

$forbiddenMatcher = $catalog | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
$forbiddenMatcher.families[0].matchers[0].type = 'DisplayNameSubstring'
$forbiddenMatcher.families[0].matchers[0].value = 'Company Portal'
Assert-Equal $false (Test-SoftwareRecognitionCatalog -Catalog $forbiddenMatcher) `
    'display-name substring recognition is outside the closed matcher vocabulary'

$runtimeSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot `
    'src/SoftwareRecognition.ps1')
Assert-Equal $false ([regex]::IsMatch($runtimeSource, '(?im)&\s*winget|Start-Process\s+winget')) `
    'the runtime does not perform live WinGet package availability or catalog lookup'

$savedBase64 = $script:SoftwareRecognitionCatalogBase64
$savedDigest = $script:SoftwareRecognitionCatalogDigest
$savedSchemaBase64 = $script:SoftwareRecognitionSchemaBase64
$savedSchemaDigest = $script:SoftwareRecognitionSchemaDigest
try {
    $schemaJson = Get-Content -Raw -LiteralPath $schemaPath
    $schemaBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        $schemaJson.Replace("`r`n", "`n").Replace("`r", "`n")
    )
    $script:SoftwareRecognitionSchemaBase64 = [Convert]::ToBase64String($schemaBytes)
    $script:SoftwareRecognitionSchemaDigest = Get-SoftwareRecognitionSha256 `
        -Bytes $schemaBytes
    $malformedText = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot `
        'fixtures/software-recognition/malformed-catalog.json')
    $malformedBytes = [Text.UTF8Encoding]::new($false).GetBytes($malformedText)
    $script:SoftwareRecognitionCatalogBase64 = [Convert]::ToBase64String($malformedBytes)
    $script:SoftwareRecognitionCatalogDigest = Get-SoftwareRecognitionSha256 -Bytes $malformedBytes
    $malformedResult = Get-SoftwareRecognitionCatalog `
        -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet) `
        -TestJsonCommand (Get-Command Test-Json -CommandType Cmdlet)
    Assert-Equal $false $malformedResult.logicalLoadValid `
        'authenticated but malformed JSON is a confined logical-load failure'

    $schemaInvalid = $catalog | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
    $schemaInvalid.families[0].sources[0] | Add-Member `
        -NotePropertyName extra -NotePropertyValue 'rejected'
    $schemaInvalidText = $schemaInvalid | ConvertTo-Json -Depth 30 -Compress
    $schemaInvalidBytes = [Text.UTF8Encoding]::new($false).GetBytes($schemaInvalidText)
    $script:SoftwareRecognitionCatalogBase64 = [Convert]::ToBase64String($schemaInvalidBytes)
    $script:SoftwareRecognitionCatalogDigest = Get-SoftwareRecognitionSha256 `
        -Bytes $schemaInvalidBytes
    $schemaInvalidResult = Get-SoftwareRecognitionCatalog `
        -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet) `
        -TestJsonCommand (Get-Command Test-Json -CommandType Cmdlet)
    Assert-Equal $false $schemaInvalidResult.logicalLoadValid `
        'authenticated parseable input that violates the strict schema is confined'

    $catalogBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        $catalogJson.Replace("`r`n", "`n").Replace("`r", "`n")
    )
    $script:SoftwareRecognitionCatalogBase64 = [Convert]::ToBase64String($catalogBytes)
    $script:SoftwareRecognitionCatalogDigest = '0' * 64
    $integrityFailed = $false
    try {
        $null = Get-SoftwareRecognitionCatalog `
            -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet) `
            -TestJsonCommand (Get-Command Test-Json -CommandType Cmdlet)
    }
    catch {
        $integrityFailed = $_.Exception.Data['ReasonCode'] -eq `
            'SOFTWARE_RECOGNITION.INTEGRITY_FAILED'
    }
    Assert-Equal $true $integrityFailed `
        'an authenticated-resource digest mismatch has one typed no-bypass failure'

    $script:SoftwareRecognitionCatalogDigest = Get-SoftwareRecognitionSha256 `
        -Bytes $catalogBytes
    $script:SoftwareRecognitionSchemaDigest = '0' * 64
    $schemaIntegrityFailed = $false
    try {
        $null = Get-SoftwareRecognitionCatalog `
            -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet) `
            -TestJsonCommand (Get-Command Test-Json -CommandType Cmdlet)
    }
    catch {
        $schemaIntegrityFailed = $_.Exception.Data['ReasonCode'] -eq `
            'SOFTWARE_RECOGNITION.INTEGRITY_FAILED'
    }
    Assert-Equal $true $schemaIntegrityFailed `
        'an embedded schema digest mismatch has the same typed no-bypass failure'
}
finally {
    $script:SoftwareRecognitionCatalogBase64 = $savedBase64
    $script:SoftwareRecognitionCatalogDigest = $savedDigest
    $script:SoftwareRecognitionSchemaBase64 = $savedSchemaBase64
    $script:SoftwareRecognitionSchemaDigest = $savedSchemaDigest
}

$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$build = & (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath
$candidateText = Get-Content -Raw -LiteralPath $candidatePath
Assert-Equal $true ($candidateText.Contains('#region Generated from src/SoftwareRecognition.ps1')) `
    'the deterministic public application contains the recognition evaluator'
Assert-Equal $false ($candidateText.Contains('__SOFTWARE_RECOGNITION_CATALOG_BASE64__')) `
    'the public application contains authenticated catalog bytes rather than a source sentinel'
Assert-Equal $true ('schemas/software-recognition-catalog.schema.json' -in `
    @($build.applicationManifest.resources.path)) `
    'the generated application manifest authenticates the catalog schema'
Assert-Equal $true ('docs/spec/releases/2.0.0-preview.1-software-recognition-catalog.json' -in `
    @($build.applicationManifest.resources.path)) `
    'the generated application manifest authenticates the reviewed seed snapshot'

Write-Output 'PASS: the release Software Recognition Catalog is strict, bounded, authenticated, and lifecycle-safe.'
