[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$contractSetPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-contract-set.json'
$contractSetSchemaPath = Join-Path $repositoryRoot 'schemas/assessment-contract-set.schema.json'
$assessmentRecordSchemaPath = Join-Path $repositoryRoot 'schemas/assessment-record.schema.json'
$positiveFixturePath = Join-Path $PSScriptRoot 'fixtures/contract-positive.json'
$releaseDefinitionPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$contractSetJson = [System.IO.File]::ReadAllText($contractSetPath)
if (-not (Test-Json -Json $contractSetJson -SchemaFile $contractSetSchemaPath)) {
    throw 'The release Assessment Contract Set does not satisfy its Draft 2020-12 schema.'
}
$contractSet = $contractSetJson | ConvertFrom-Json -Depth 30
Assert-Equal '2020-12' $contractSet.schemaDraft 'the Contract Set identifies the exact schema draft'
Assert-Equal 1 @($contractSet.fieldDefinitions).Count 'this narrow tracer bullet admits one field'
Assert-Equal 1 @($contractSet.scopeDefinitions).Count 'this narrow tracer bullet declares one closed Evidence Scope'

$definition = $contractSet.fieldDefinitions[0]
Assert-Equal 'field:device.os.display-name' $definition.fieldId 'the admitted field identity is release-bound'
Assert-Equal 'CAP-0001' $definition.capabilityIds[0] 'the field has an explicit Product Capability purpose'
Assert-Equal 'SyntheticContractFixture' $definition.source.kind 'the source cannot be mistaken for device collection'
Assert-Equal 'String' $definition.valueType 'the field type is explicit'
Assert-Equal 'RestrictedDiagnosticEvidence' $definition.sensitivity 'the evidence sensitivity is explicit'
Assert-Equal 'OmitProhibitedMaterial' $definition.redaction.behavior 'secret handling omits rather than masks or hashes'
Assert-Equal $true $definition.publicEligibility.definition 'the reusable definition is public'
Assert-Equal $false $definition.publicEligibility.values 'record values remain restricted even when synthetic tests are public'
if ($definition.bounds.maximumUtf8Bytes -le 0 -or $definition.bounds.maximumOccurrencesPerSubject -le 0) {
    throw 'Every admitted field requires positive release-owned size and occurrence bounds.'
}
$releaseDefinition = Get-Content -LiteralPath $releaseDefinitionPath -Raw | ConvertFrom-Json -Depth 30
if (@($definition.capabilityIds | Where-Object { $_ -notin $releaseDefinition.releaseEnabledCapabilityIds }).Count -gt 0) {
    throw 'Every Evidence Field Definition must resolve to a release-enabled Product Capability.'
}
$scopeDefinition = $contractSet.scopeDefinitions[0]
Assert-Equal 'scope:synthetic.device.os' $scopeDefinition.scopeId 'coverage is bound to a release-declared Evidence Scope'
Assert-Equal $definition.fieldId $scopeDefinition.fieldIds[0] 'the scope resolves its admitted field'
Assert-Equal $definition.source.sourceId.Replace('source:', 'collector:') $scopeDefinition.collectorIds[0] `
    'the scope resolves its approved synthetic collector'
$schemaKinds = @($contractSet.schemas.documentKind | Sort-Object -Unique)
Assert-Equal 2 $schemaKinds.Count 'schema document kinds are unambiguous'
foreach ($schemaResource in @($contractSet.schemas)) {
    if (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot $schemaResource.path) -PathType Leaf)) {
        throw "Contract Set schema reference does not resolve: $($schemaResource.path)"
    }
}

$recordSchema = Get-Content -LiteralPath $assessmentRecordSchemaPath -Raw | ConvertFrom-Json -Depth 50
Assert-Equal 'https://json-schema.org/draft/2020-12/schema' $recordSchema.'$schema' `
    'the canonical Assessment Record schema declares Draft 2020-12'
$positiveJson = [System.IO.File]::ReadAllText($positiveFixturePath)
Assert-Equal $true (Test-Json -Json $positiveJson -SchemaFile $assessmentRecordSchemaPath) `
    'the public positive fixture validates using the actual release schema'

# This small official-dialect probe uses `prefixItems`, whose array semantics
# belong to Draft 2020-12. It proves the exact trusted Test-Json path used by
# this repository applies the declared dialect; it is intentionally not a claim
# that WIN-PCInfo reruns the entire upstream JSON Schema conformance suite.
$draft202012Probe = '{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"array","prefixItems":[{"const":1}],"items":false}'
Assert-Equal $true (Test-Json -Json '[1]' -Schema $draft202012Probe) `
    'Draft 2020-12 prefixItems accepts the declared first item'
Assert-Equal $false (Test-Json -Json '[2]' -Schema $draft202012Probe -ErrorAction SilentlyContinue) `
    'Draft 2020-12 prefixItems rejects a conflicting first item'

Write-Output 'PASS: the release Contract Set binds one safe synthetic field and scope, vocabularies, and Draft 2020-12 schema.'
