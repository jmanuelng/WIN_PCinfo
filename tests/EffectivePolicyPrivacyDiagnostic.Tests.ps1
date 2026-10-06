[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot 'EffectivePolicyApplication.Tests.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Policy application test does not parse.' }
$definition=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-EffectivePolicyPrivacyDiagnostic'
},$true))
if ($definition.Count -ne 1) { throw 'Private diagnostic definition is not unique.' }
. ([scriptblock]::Create($definition[0].Extent.Text))
$patterns=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value.StartsWith('(?i)6ac1786c|')
},$true))
if ($patterns.Count -ne 1) { throw 'Policy privacy assertion pattern is not unique.' }
$pattern=$patterns[0].Value
$safe='{"recordType":"win-pcinfo.effective-policy-validation","appliedPolicyCount":1,"auditCatalogCount":2,"policyIdentifiersPublished":false}'
$unsafe='{"recordType":"synthetic.public-record","nested":{"items":["safe","LocalGPO"]},"port":5985}'
$stdout=$safe+"`r`n"+$unsafe+"`r`n"
$diagnostic=Get-EffectivePolicyPrivacyDiagnostic -Scenario 'SyntheticDiagnosticControl' -StandardOutput $stdout -Pattern $pattern
if ($diagnostic.matchingPublicRecords.Count -ne 1) { throw 'Only the matching public record should be captured.' }
$record=$diagnostic.matchingPublicRecords[0]
if ($record.recordOrdinal -ne 1 -or $record.recordType -cne 'synthetic.public-record' -or $record.rawPublicRecord -cne $unsafe) {
    throw 'Diagnostic does not retain its exact producing public record.'
}
if (($record.exactMatches.value -join ',') -cne 'LocalGPO,5985') { throw 'Diagnostic changed the original assertion matches.' }
if (($record.propertyPaths.path -join ',') -cne '$["nested"]["items"][1],$["port"]') { throw 'Diagnostic did not locate nested and numeric property paths.' }
foreach ($match in $record.exactMatches) {
    if ($stdout.Substring($match.stdoutOffset,$match.length) -cne $match.value) { throw 'Diagnostic match offset does not bind the original stdout.' }
}
$clean=Get-EffectivePolicyPrivacyDiagnostic -Scenario 'SyntheticSafeControl' -StandardOutput $safe -Pattern $pattern
if ($clean.matchingPublicRecords.Count) { throw 'Safe coverage and count fields became a privacy match.' }
$name='{"recordType":"synthetic.public-record","PolicyXml":"safe"}'
$named=Get-EffectivePolicyPrivacyDiagnostic -Scenario 'SyntheticPropertyNameControl' -StandardOutput $name -Pattern $pattern
if ($named.matchingPublicRecords[0].propertyPaths[0].kind -cne 'PropertyName' -or
    $named.matchingPublicRecords[0].propertyPaths[0].path -cne '$["PolicyXml"]') { throw 'Matching property names must be identified distinctly.' }

function Get-PrivacyControlDefinition([string] $File, [string] $Name) {
    $controlErrors=$null; $controlTokens=$null
    $controlAst=[Management.Automation.Language.Parser]::ParseFile($File,[ref]$controlTokens,[ref]$controlErrors)
    if ($controlErrors.Count) { throw 'Public privacy control source does not parse.' }
    $functions=@($controlAst.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name
    }.GetNewClosure(),$true))
    if ($functions.Count -ne 1) { throw 'Public privacy control source definition is not unique.' }
    $functions[0].Extent.Text
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. ([scriptblock]::Create((Get-PrivacyControlDefinition -File $path -Name 'Test-EffectivePolicyPublicOutputPrivacy')))
$contracts=Join-Path $repositoryRoot 'src/Contracts.ps1'
. ([scriptblock]::Create((Get-PrivacyControlDefinition -File $contracts -Name 'Write-ContractRecord')))
$serializer=Get-Command Microsoft.PowerShell.Utility\ConvertTo-Json -CommandType Cmdlet
function Convert-PrivacyControlRecord($Record) {
    $previous=[Console]::Out
    $writer=[IO.StringWriter]::new([Globalization.CultureInfo]::InvariantCulture)
    try {
        [Console]::SetOut($writer)
        Write-ContractRecord -Record $Record -ConvertToJsonCommand $serializer
        $writer.ToString()
    }
    finally { [Console]::SetOut($previous); $writer.Dispose() }
}
$progressDefinition=Get-PrivacyControlDefinition -File $contracts -Name 'New-ProgressRecord'
$clockAnchor='[System.DateTimeOffset]::UtcNow'
if ([regex]::Matches($progressDefinition,[regex]::Escape($clockAnchor)).Count -ne 1) { throw 'Progress clock substitution anchor changed.' }
$controls=[Collections.Generic.List[object]]::new()
foreach ($fraction in @('5985000','5986000')) {
    # Exactly one clock expression changes; the real producer and serializer
    # retain their original public shape. This is a deterministic control, not
    # a replay of the historical failure's unavailable generated stdout.
    $fixedClock="[System.DateTimeOffset]::Parse('2026-10-06T00:00:00.$fraction+00:00', [Globalization.CultureInfo]::InvariantCulture)"
    . ([scriptblock]::Create($progressDefinition.Replace($clockAnchor,$fixedClock)))
    $progress=New-ProgressRecord -Sequence 7 -Phase Collection -State Started `
        -MessageId effective-policy.collection.started -CompletedUnits 0 -TotalUnits 1 -Unit EffectivePolicy
    $publicOutput=Convert-PrivacyControlRecord -Record $progress
    $captured=Get-EffectivePolicyPrivacyDiagnostic -Scenario ('DeterministicProgressClock'+$fraction) -StandardOutput $publicOutput -Pattern $pattern
    $controls.Add([ordered]@{control='ActualProgressProducerWithOneDisclosedClockSubstitution';timestamp=$progress.time;privacyMatched=($publicOutput -match $pattern);diagnostic=$captured})
}
. ([scriptblock]::Create((Get-PrivacyControlDefinition -File $contracts -Name 'Get-BytesDigest')))
. ([scriptblock]::Create((Get-PrivacyControlDefinition -File $contracts -Name 'Get-ObjectDigest')))
. ([scriptblock]::Create((Get-PrivacyControlDefinition -File (Join-Path $repositoryRoot 'src/DeviceReadiness.ps1') -Name 'New-DeviceReadinessTerminalRecord')))
# The disclosed synthetic hash input produces a real SHA-256 containing 5986;
# only the terminal's admitted digest inputs are substituted, never its shape.
$controlDigest=Get-ObjectDigest -Value ([ordered]@{syntheticPrivacyControl=890}) -ConvertToJsonCommand $serializer
if ($controlDigest -cne '99a65490136fd90dc3b9a47c0a7fd4de8cac4624fbaf598661a44224ee8b87a3') { throw 'Deterministic hash control identity changed.' }
$terminal=New-DeviceReadinessTerminalRecord -Outcome Completed -ExitCode 0 -ReasonCode RUN.COMPLETED `
    -CollectionStarted $true -ValidationFixture $true -CleanupVerified $true -RequestDigest $controlDigest -PlanDigest $controlDigest
$publicOutput=Convert-PrivacyControlRecord -Record $terminal
$captured=Get-EffectivePolicyPrivacyDiagnostic -Scenario 'DeterministicTerminalDigest' -StandardOutput $publicOutput -Pattern $pattern
$controls.Add([ordered]@{control='ActualTerminalProducerWithDisclosedSyntheticDigestInputs';digest=$controlDigest;privacyMatched=($publicOutput -match $pattern);diagnostic=$captured})
foreach ($count in @(5985,5986)) {
    $progress=New-ProgressRecord -Sequence $count -Phase Collection -State Started `
        -MessageId effective-policy.collection.started -CompletedUnits $count -TotalUnits $count -Unit EffectivePolicy
    $publicOutput=Convert-PrivacyControlRecord -Record $progress
    $captured=Get-EffectivePolicyPrivacyDiagnostic -Scenario ('DeterministicProgressCounters'+$count) -StandardOutput $publicOutput -Pattern $pattern
    $controls.Add([ordered]@{control='ActualProgressProducerWithDisclosedCounterInputs';count=$count;privacyMatched=($publicOutput -match $pattern);diagnostic=$captured})
}
if ($env:WINPCINFO_TEST_EVIDENCE) {
    [IO.File]::WriteAllText((Join-Path $env:WINPCINFO_TEST_EVIDENCE 'effective-policy-public-metadata-controls.json'),
        ($controls.ToArray() | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
}
foreach ($control in $controls) {
    if (-not $control.privacyMatched) { throw 'Original assertion must remain red for each deterministic metadata control.' }
    foreach ($record in $control.diagnostic.matchingPublicRecords) {
        if (Test-EffectivePolicyPublicOutputPrivacy -StandardOutput $record.rawPublicRecord -Pattern $pattern) {
            throw 'Ownership-aware privacy assertion rejected legitimate actual producer metadata.'
        }
    }
}

$negativeControls=[Collections.Generic.List[object]]::new()
foreach ($port in @(5985,5986)) {
    # Inject restricted fields into the actual progress producer, retaining its
    # legitimate clock/counters. Metadata exceptions must not waive siblings.
    foreach ($restricted in @($port,[string]$port)) {
        $progress=New-ProgressRecord -Sequence $port -Phase Collection -State Started `
            -MessageId effective-policy.collection.started -CompletedUnits $port -TotalUnits $port -Unit EffectivePolicy
        $progress | Add-Member -NotePropertyName configuredPort -NotePropertyValue $restricted
        $negativeControls.Add($progress)
    }
    $negativeControls.Add([ordered]@{recordType='win-pcinfo.progress';contractVersion='1.0.0';sequence=[string]$port})
    $negativeControls.Add([ordered]@{recordType='win-pcinfo.progress';contractVersion='1.0.0';sequence=-$port})
    $negativeControls.Add([ordered]@{recordType='win-pcinfo.progress';contractVersion='1.0.0';sequence=([double]$port+0.5)})
    $negativeControls.Add([ordered]@{recordType='win-pcinfo.progress';contractVersion='1.0.0';elapsedMilliseconds=$port})
    $negativeControls.Add([ordered]@{recordType='win-pcinfo.progress';contractVersion='2.0.0';sequence=$port})
    $negativeControls.Add([ordered]@{recordType='synthetic.public-record';contractVersion='1.0.0';sequence=$port})
    $negativeControls.Add([ordered]@{recordType='win-pcinfo.effective-policy-validation';contractVersion='1.0.0';policyValues=@{port=$port}})
    $negativeControls.Add([ordered]@{recordType='win-pcinfo.progress';contractVersion='1.0.0';('port'+$port)='safe'})
}
foreach ($time in @('2026-99-06T00:00:00.5985000+00:00','2026-10-06T00:00:00.5986000','5985')) {
    $negativeControls.Add([ordered]@{recordType='win-pcinfo.progress';contractVersion='1.0.0';time=$time})
}
foreach ($digest in @('5985',('g'+$controlDigest.Substring(1)),($controlDigest+'x'))) {
    $negativeControls.Add([ordered]@{recordType='win-pcinfo.terminal';contractVersion='1.0.0';planDigest=$digest})
}
foreach ($type in @('win-pcinfo.progress','win-pcinfo.terminal')) {
    foreach ($version in @('2.0.0',$null)) {
        $negativeControls.Add([ordered]@{recordType=$type;contractVersion=$version;time='2026-10-06T00:00:00.5985000+00:00';planDigest=$controlDigest})
    }
}
$negativeControls.Add([ordered]@{recordType='synthetic.public-record';contractVersion='1.0.0';time='2026-10-06T00:00:00.5985000+00:00';planDigest=$controlDigest})
foreach ($record in $negativeControls) {
    if (-not (Test-EffectivePolicyPublicOutputPrivacy -StandardOutput (Convert-PrivacyControlRecord $record) -Pattern $pattern)) {
        throw 'Ownership-aware privacy assertion waived restricted, unknown or invalidly shaped output.'
    }
}
# Every original non-port alternative still rejects raw stdout, including
# substrings in otherwise valid, explicitly owned public digest metadata.
$restrictedValues=@('6ac1786c','7f7d1f60','LocalGPO','synthetic-domain-link','synthetic-user-link','synthetic-computer-link',
    'local-machine','bounded-link-1','registry:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','registry:bounded-setting-1',
    'S-1-5-18','S-1-5-19','S-1-5-20','S-1-5-21-1-2-3','S-1-5-32-544','S-1-5-32-546',
    'RecoveryPassword','NumericalPassword','TpmPin','XtsAes','XtsAes128','XtsAes256','PolicyXml','RuleCollectionXml',
    'DisableDualScan','NtlmMinClientSec','NtlmMinServerSec')
foreach ($value in $restrictedValues) {
    $record=[ordered]@{recordType='win-pcinfo.progress';contractVersion='1.0.0';payload=$value}
    if (-not (Test-EffectivePolicyPublicOutputPrivacy -StandardOutput (Convert-PrivacyControlRecord $record) -Pattern $pattern)) {
        throw 'An original non-port privacy alternative no longer rejects public output.'
    }
}
$record=[ordered]@{recordType='win-pcinfo.terminal';contractVersion='1.0.0';planDigest=('6ac1786c'+('a'*56))}
if (-not (Test-EffectivePolicyPublicOutputPrivacy -StandardOutput (Convert-PrivacyControlRecord $record) -Pattern $pattern)) {
    throw 'A valid owned digest waived an original non-port raw alternative.'
}
foreach ($port in @(5985,5986)) {
    $record=[ordered]@{recordType='win-pcinfo.effective-policy-validation';contractVersion='1.0.0';auditCatalogCount=$port}
    if (Test-EffectivePolicyPublicOutputPrivacy -StandardOutput (Convert-PrivacyControlRecord $record) -Pattern $pattern) { throw 'Owned policy catalog count rejected.' }
}
$summary=[ordered]@{recordType='win-pcinfo.preparation-summary';contractVersion='1.0.0';requestDigest=$controlDigest;planDigest=$controlDigest;
    plan=@{requestDigest=$controlDigest;network=@{context=@{snapshotDigest=$controlDigest}};
        governingResources=@(@{path='synthetic-resource';sha256=$controlDigest});
        integrity=@{embeddedDefinitionSha256=$controlDigest;applicationManifestSha256=$controlDigest;
            applicationResources=@(@{path='synthetic-resource';sha256=$controlDigest})}}}
if (Test-EffectivePolicyPublicOutputPrivacy -StandardOutput (Convert-PrivacyControlRecord $summary) -Pattern $pattern) {
    throw 'Exact preparation metadata digest paths rejected.'
}
$summary.plan.integrity.applicationResources[0].port=5985
if (-not (Test-EffectivePolicyPublicOutputPrivacy -StandardOutput (Convert-PrivacyControlRecord $summary) -Pattern $pattern)) {
    throw 'Preparation digest exceptions waived restricted sibling fields.'
}
Write-Output 'PASS: actual producer metadata controls are red under the original assertion and green under exact ownership checks; restricted ports, invalid shapes/owners and every original non-port alternative remain rejected.'
