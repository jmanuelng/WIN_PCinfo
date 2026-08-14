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
Assert-Equal '1.8.0' $contractSet.contractVersion `
    'the additive Certificate Trust contract has an explicit version'
Assert-Equal 2097152 $contractSet.limits.maximumDocumentUtf8Bytes `
    'the combined profile has a finite release-owned 2 MiB document ceiling'
Assert-Equal 6144 $contractSet.limits.maximumArrayItems `
    'the bounded per-scope software inventory fits the deliberate finite array ceiling'
Assert-Equal 161 @($contractSet.fieldDefinitions).Count `
    'historical fields remain while bounded certificate fields are admitted'
Assert-Equal 57 @($contractSet.scopeDefinitions).Count `
    'historical through purpose-bound certificate scopes remain distinct'
$certificateFields = @($contractSet.fieldDefinitions | Where-Object fieldId -like 'field:certificate.*')
Assert-Equal 12 $certificateFields.Count `
    'presence, purpose, identity, store, dates, validity, chain, trust, and key protection remain explicit fields'
foreach ($certificateField in $certificateFields) {
    Assert-Equal 'CAP-0014' $certificateField.capabilityIds[0] `
        'every certificate field traces to the release certificate capability'
    Assert-Equal 'RestrictedDiagnosticEvidence' $certificateField.sensitivity `
        'certificate values and fingerprints remain Restricted Diagnostic Evidence'
    Assert-Equal $false $certificateField.publicEligibility.values `
        'no certificate field value is eligible for public output'
}
$certificateScopes = @($contractSet.scopeDefinitions | Where-Object scopeId -like 'scope:certificate.*')
Assert-Equal 6 $certificateScopes.Count `
    'management, authentication, device identity, code trust, TLS inspection, and service connectivity stay independent'
foreach ($certificateScope in $certificateScopes) {
    Assert-Equal 12 @($certificateScope.fieldIds).Count `
        'every purpose scope can distinguish all certificate evidence states'
    Assert-Equal 'collector:windows.purpose-bound-certificate-trust' $certificateScope.collectorIds[0] `
        'certificate scopes resolve only to the purpose-bound read-only collector'
}
$certificateProfile = 'profile:device-firmware-identity-administrator-policy-software-resource-network-and-certificate-trust-readiness'
Assert-Equal 55 @($contractSet.scopeDefinitions | Where-Object profileIds -contains $certificateProfile).Count `
    'the additive certificate profile inherits every earlier scope and adds six purpose scopes'

$definition = @($contractSet.fieldDefinitions | Where-Object fieldId -eq 'field:device.os.display-name')[0]
Assert-Equal 'field:device.os.display-name' $definition.fieldId 'the admitted field identity is release-bound'
Assert-Equal 'CAP-0001' $definition.capabilityIds[0] 'the field has an explicit Product Capability purpose'
Assert-Equal 'SyntheticContractFixture' $definition.source.kind 'the source cannot be mistaken for device collection'
Assert-Equal 'String' $definition.valueType 'the field type is explicit'
Assert-Equal 'RestrictedDiagnosticEvidence' $definition.sensitivity 'the evidence sensitivity is explicit'
Assert-Equal 'OmitProhibitedMaterial' $definition.redaction.behavior 'secret handling omits rather than masks or hashes'
Assert-Equal $true $definition.publicEligibility.definition 'the reusable definition is public'
Assert-Equal $false $definition.publicEligibility.values 'record values remain restricted even when synthetic tests are public'
$releaseDefinition = Get-Content -LiteralPath $releaseDefinitionPath -Raw | ConvertFrom-Json -Depth 30
foreach ($fieldDefinition in @($contractSet.fieldDefinitions)) {
    if ($fieldDefinition.bounds.maximumUtf8Bytes -le 0 -or
        $fieldDefinition.bounds.maximumOccurrencesPerSubject -le 0) {
        throw 'Every admitted field requires positive release-owned size and occurrence bounds.'
    }
    Assert-Equal 'RestrictedDiagnosticEvidence' $fieldDefinition.sensitivity `
        'every Device Readiness value remains restricted'
    Assert-Equal $false $fieldDefinition.publicEligibility.values `
        'no Device Readiness value is eligible for public output'
    if (@($fieldDefinition.capabilityIds | Where-Object {
        $_ -notin $releaseDefinition.releaseEnabledCapabilityIds
    }).Count -gt 0) {
        throw 'Every Evidence Field Definition must resolve to a release-enabled Product Capability.'
    }
}
$scopeDefinition = $contractSet.scopeDefinitions[0]
Assert-Equal 'scope:synthetic.device.os' $scopeDefinition.scopeId 'coverage is bound to a release-declared Evidence Scope'
Assert-Equal 1 @($scopeDefinition.fieldIds).Count 'the legacy scope retains only its admitted field'
Assert-Equal $definition.source.sourceId.Replace('source:', 'collector:') $scopeDefinition.collectorIds[0] `
    'the scope resolves its approved synthetic collector'
$deviceScope = @($contractSet.scopeDefinitions | Where-Object scopeId -eq 'scope:device.windows-readiness')[0]
Assert-Equal 8 @($deviceScope.fieldIds).Count 'the Device Readiness scope resolves exactly eight fields'
Assert-Equal 'collector:windows.device-readiness' $deviceScope.collectorIds[0] `
    'real evidence resolves only to the real approved collector'
$contextScope = @($contractSet.scopeDefinitions | Where-Object {
    $_.scopeId -eq 'scope:device.windows-context'
})[0]
Assert-Equal 17 @($contextScope.fieldIds).Count `
    'the versioned expanded scope resolves exactly seventeen context fields'
Assert-Equal 'collector:windows.device-context' $contextScope.collectorIds[0] `
    'the expanded scope resolves its release-approved Windows collector'
Assert-Equal 'collector:win-pcinfo.device-context-classifier' $contextScope.collectorIds[1] `
    'the expanded scope resolves its release-approved post-validation classifier'
$firmwareScope = @($contractSet.scopeDefinitions | Where-Object {
    $_.scopeId -eq 'scope:device.firmware-context'
})[0]
$secureBootScope = @($contractSet.scopeDefinitions | Where-Object {
    $_.scopeId -eq 'scope:device.secure-boot'
})[0]
$tpmScope = @($contractSet.scopeDefinitions | Where-Object {
    $_.scopeId -eq 'scope:device.tpm-readiness'
})[0]
Assert-Equal 3 @($firmwareScope.fieldIds).Count `
    'firmware context resolves its exact three-field projection'
Assert-Equal 1 @($secureBootScope.fieldIds).Count `
    'Secure Boot remains a distinct one-field scope'
Assert-Equal 4 @($tpmScope.fieldIds).Count `
    'TPM readiness resolves only its four non-secret readiness fields'
foreach ($scope in @($firmwareScope, $secureBootScope, $tpmScope)) {
    Assert-Equal 'collector:windows.firmware-security' $scope.collectorIds[0] `
        'each privileged scope resolves only to the approved firmware collector'
    if ('profile:device-and-firmware-readiness' -notin @($scope.profileIds)) {
        throw 'Every firmware scope must belong to the combined evidence profile.'
    }
}
$identityScopes=@($contractSet.scopeDefinitions|Where-Object {
    $_.scopeId -in @('scope:identity.assessment-user-context','scope:device.registration-context',
        'scope:device.work-school-registration-context','scope:device.mdm-policy.system')
})
Assert-Equal 4 $identityScopes.Count `
    'the combined identity profile keeps four independently covered source contexts'
foreach($scope in $identityScopes){
    if('profile:device-firmware-and-identity-readiness' -notin @($scope.profileIds)){
        throw 'Every identity scope must belong to the additive combined evidence profile.'
    }
}
$administratorScope=@($contractSet.scopeDefinitions|Where-Object {
    $_.scopeId -eq 'scope:device.local-administrators.direct-membership'
})[0]
Assert-Equal 8 @($administratorScope.fieldIds).Count `
    'direct membership retains exact group, completeness, count, identity, kind, origin, and relationship fields'
Assert-Equal 'collector:windows.local-administrators.direct-members' $administratorScope.collectorIds[0] `
    'the administrator scope resolves only to the approved SID-based collector'
if (@($contextScope.fieldIds | Where-Object {
    [string]$_ -match '(?i)(product.?key|license.?key|private.?key|secret|token)'
}).Count -gt 0) {
    throw 'The release Contract Set admitted a prohibited key-like field identity.'
}
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

Write-Output 'PASS: Contract Set 1.8 binds historical through Certificate Trust scopes to Draft 2020-12 contracts.'
