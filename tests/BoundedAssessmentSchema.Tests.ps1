[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidate = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$regions = [regex]::Matches([IO.File]::ReadAllText($candidate),
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach ($region in $regions) { . ([scriptblock]::Create($region.Groups[2].Value)) }
$trustedTestJson = Get-Command Test-Json -CommandType Cmdlet
$trustedConverter = Get-Command ConvertFrom-Json -CommandType Cmdlet
$contract = Get-EmbeddedAssessmentContractSet -ConvertFromJsonCommand $trustedConverter
$schema = $contract.AssessmentRecordSchema
$positiveJson = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/contract-positive.json'))
$splitNames = @('subjects','provenance','observations','coverage','diagnostics','collectorResults',
    'findings','recommendations','recommendationRelationships','softwareRecognition')
$caseCount = 0
function Assert-BoundedEquivalent {
    param([string]$Name, [string]$Json, [bool]$Expected)
    $whole = & $trustedTestJson -Json $Json -Schema $schema -ErrorAction SilentlyContinue
    Assert-Equal $Expected $whole "$Name has an independently specified whole-schema result"
    $bounded = Test-AssessmentStructuralSchema -Json $Json -CanonicalSchema $schema -TestJsonCommand $trustedTestJson
    Assert-Equal $whole $bounded "$Name preserves the canonical structural decision"
    $script:caseCount++
}
function Assert-BoundedMutation {
    param([string]$Name, [scriptblock]$Mutate, [bool]$Expected = $false)
    $record = $positiveJson | ConvertFrom-Json -AsHashtable -Depth 30 -DateKind String
    & $Mutate $record
    Assert-BoundedEquivalent -Name $Name -Json ($record | ConvertTo-Json -Depth 30 -Compress) -Expected $Expected
}
function Assert-BoundedThrows {
    param([string]$Name, [scriptblock]$Action)
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert-Equal $true $rejected "$Name cannot qualify a record"
}
Assert-BoundedEquivalent -Name 'multilingual baseline' -Json $positiveJson -Expected $true
foreach ($name in $splitNames) {
    Assert-BoundedMutation "$name wrong type" { param($record) $record[$name] = 'invalid' }.GetNewClosure()
    Assert-BoundedMutation "$name explicit null" { param($record) $record[$name] = $null }.GetNewClosure()
    Assert-BoundedMutation "$name invalid actual item" { param($record) $record[$name] = @(@{ unexpected = $true }) }.GetNewClosure()
}
Assert-BoundedMutation 'missing required array' { param($r) $r.Remove('subjects') | Out-Null }
Assert-BoundedMutation 'empty required array' { param($r) $r.subjects = @() }
Assert-BoundedMutation 'optional absent' { param($r) $r.Remove('softwareRecognition') | Out-Null } $true
Assert-BoundedMutation 'optional empty' { param($r) $r.softwareRecognition = @() } $true
Assert-BoundedMutation 'unknown root array' { param($r) $r.unknownArray = @() }
Assert-BoundedMutation 'case variant root array' { param($r) $r.SUBJECTS = $r.subjects; $r.Remove('subjects') | Out-Null }
Assert-BoundedMutation 'requiredFeatures whole-array uniqueness' { param($r) $r.requiredFeatures += $r.requiredFeatures[0] }
foreach ($length in @(63,64,65,130,1024)) {
    Assert-BoundedMutation "subject count $length" { param($r) $r.subjects = @($r.subjects[0]) * $length }.GetNewClosure() $true
}
Assert-BoundedMutation 'subject maximum plus one' { param($r) $r.subjects = @($r.subjects[0]) * 1025 }
foreach ($index in @(0,63,64,129)) {
    Assert-BoundedMutation "invalid subject at batch boundary $index" {
        param($r) $r.subjects = @($r.subjects[0]) * 130; $r.subjects[$index] = @{ subjectId = 'subject:synthetic:bad'; kind = 'InvalidKind' }
    }.GetNewClosure()
}
$recognition = @{
    annotationId='annotation:synthetic:001'; subjectId='subject:synthetic-device:primary'; outcome='Unrecognized'
    familyId=$null; familyLabel=$null; roles=@(); matcherIds=@(); matcherTypes=@(); matchStrengthExplanation='Synthetic no match'
    reasonCode='SOFTWARE.SYNTHETIC_UNRECOGNIZED'; catalogRevision=1; catalogRelease='2.0.0-preview.1'; catalogDigest=('0'*64); provenance=@()
}
Assert-BoundedMutation 'valid item-local conditional' { param($r) $r.softwareRecognition = @($recognition) }.GetNewClosure() $true
Assert-BoundedMutation 'recognized conditional missing family' { param($r) $r.softwareRecognition = @($recognition.Clone()); $r.softwareRecognition[0].outcome='RecognizedExact' }.GetNewClosure()
Assert-BoundedMutation 'nested duplicate matcher IDs' { param($r) $r.softwareRecognition = @($recognition.Clone()); $r.softwareRecognition[0].matcherIds=@('matcher:synthetic:001','matcher:synthetic:001') }.GetNewClosure()
Assert-BoundedMutation 'simultaneous root and item failures' { param($r) $r.unknown=$true; $r.subjects[0].kind='InvalidKind' }
foreach ($root in @('null','[]','true','42','"synthetic"')) {
    Assert-BoundedEquivalent "wrong root $root" $root $false
}
# Distinct raw numeric spellings and Unicode stay on the original item path.
foreach ($value in @('0','1.0','1e0','-0','9007199254740991','"界\u00e9"')) {
    $r = $positiveJson | ConvertFrom-Json -AsHashtable -Depth 30 -DateKind String
    $r.observations[0].value = '__RAW_VALUE__'
    $json = ($r | ConvertTo-Json -Depth 30 -Compress).Replace('"__RAW_VALUE__"',$value)
    Assert-BoundedEquivalent "raw value $value" $json $true
}
Write-Output "PASS: $caseCount independent canonical/bounded structural comparisons."

# Inject defects at one invocation boundary, never substitute the production engine.
function Invoke-BoundedFaultingSchemaCommand {
    [CmdletBinding()]
    param([string]$Json, [string]$Schema)
    $script:faultCalls++
    if ($script:faultCalls -eq $script:faultPass) {
        switch ($script:faultKind) {
            'Empty' { return }
            'String' { return 'true' }
            'MultipleTrue' { return $true,$true }
            'MultipleFalse' { return $false,$false }
            'ErrorAndTrue' { Write-Error 'Synthetic command failure'; return $true }
            'Throw' { throw 'Synthetic command failure' }
            'OmitThenCompensate' { return }
        }
    }
    if ($script:faultKind -eq 'OmitThenCompensate' -and $script:faultCalls -eq ($script:faultPass+1)) { return $true,$true }
    & $trustedTestJson -Json $Json -Schema $Schema -ErrorAction SilentlyContinue
}
$r = $positiveJson | ConvertFrom-Json -AsHashtable -Depth 30 -DateKind String
$r.subjects = @($r.subjects[0]) * 130
$batchJson = $r | ConvertTo-Json -Depth 30 -Compress
foreach ($pass in @(1,2,3,4)) {
    foreach ($fault in @('Empty','String','MultipleTrue','MultipleFalse','ErrorAndTrue','Throw','OmitThenCompensate')) {
        $script:faultCalls=0; $script:faultPass=$pass; $script:faultKind=$fault
        Assert-BoundedThrows "$fault on skeleton/first/middle/final subject pass $pass" {
            Test-AssessmentStructuralSchema -Json $batchJson -CanonicalSchema $schema -TestJsonCommand (Get-Command Invoke-BoundedFaultingSchemaCommand)
        }
    }
}
Assert-BoundedThrows 'changed schema admission' {
    Test-AssessmentStructuralSchema -Json $positiveJson -CanonicalSchema ($schema+' ') -TestJsonCommand $trustedTestJson
}
# A failed derivation/command propagates to the existing public validator boundary.
Write-Output 'PASS: per-invocation errors, output cardinality/type, omitted/compensated results and schema drift fail closed.'

# Large inputs prove lexical checks still precede every projected item.
$r = $positiveJson | ConvertFrom-Json -AsHashtable -Depth 30 -DateKind String
$r.observations[0].value = 'x' * 900
$r.observations = @($r.observations[0]) * 768
$largeJson = $r | ConvertTo-Json -Depth 30 -Compress
Assert-Equal $true ([Text.Encoding]::UTF8.GetByteCount($largeJson) -ge 524288) 'lexical negatives exercise the large-record scheduling threshold'
Assert-Equal $true ([Text.Encoding]::UTF8.GetByteCount($largeJson) -le [int]$contract.Definition.limits.maximumDocumentUtf8Bytes) 'large-record lexical fixture stays within the document byte bound'
$lexicalCases = @(
    @{ name='duplicate item name'; json=$largeJson.Replace('"kind":"Device"','"kind":"Device","kind":"Device"'); reason='CONTRACT.DUPLICATE_PROPERTY' },
    @{ name='unsafe numeric value'; json=$largeJson.Insert($largeJson.Length-1, ',"lexicalProbe":9007199254740992'); reason='CONTRACT.NUMBER_INVALID' },
    @{ name='excessive projected-item string'; json=$largeJson.Replace('"kind":"Device"', '"kind":"' + ('x' * ([int]$contract.Definition.limits.maximumStringUtf8Bytes+1)) + '"'); reason='CONTRACT.SIZE_EXCEEDED' },
    @{ name='excessive depth'; json=$largeJson.Insert($largeJson.Length-1, ',"lexicalProbe":' + ('['*20) + '0' + (']'*20)); reason='CONTRACT.DEPTH_EXCEEDED' }
)
foreach ($case in $lexicalCases) {
    $result=Test-AssessmentContract -Utf8Bytes ([Text.Encoding]::UTF8.GetBytes($case.json)) -ConvertFromJsonCommand $trustedConverter -TestJsonCommand $trustedTestJson
    Assert-Equal $case.reason $result.reasonCode "$($case.name) rejects before projection with the stable public reason"
}
$invalidLarge = $largeJson.Replace('"kind":"Device"','"kind":"InvalidKind"')
$result=Test-AssessmentContract -Utf8Bytes ([Text.Encoding]::UTF8.GetBytes($invalidLarge)) -ConvertFromJsonCommand $trustedConverter -TestJsonCommand $trustedTestJson
Assert-Equal 'CONTRACT.SCHEMA_INVALID' $result.reasonCode 'ordinary trusted schema rejection keeps its public reason'
$script:faultCalls=0; $script:faultPass=1; $script:faultKind='ErrorAndTrue'
$result=Test-AssessmentContract -Utf8Bytes ([Text.Encoding]::UTF8.GetBytes($largeJson)) -ConvertFromJsonCommand $trustedConverter -TestJsonCommand (Get-Command Invoke-BoundedFaultingSchemaCommand)
Assert-Equal 'CONTRACT.VALIDATOR_FAILED' $result.reasonCode 'a command error plus success cannot qualify the public large-record boundary'
Write-Output 'PASS: large-record lexical safety and public schema/command reasons precede any projected acceptance.'
