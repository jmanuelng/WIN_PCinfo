[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-administrator-exposure.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/administrator-exposure.schema.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

if (-not (Test-Json -Json (Get-Content -LiteralPath $policyPath -Raw) -SchemaFile $schemaPath)) {
    throw 'The release Administrator Exposure policy does not satisfy its schema.'
}

$policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json -Depth 20
Assert-Equal 'win-pcinfo.administrator-exposure/1.0.0' $policy.policyId `
    'the administrator slice has one immutable release identity'
Assert-Equal 'BuiltinAdministratorsAlias' $policy.administratorsGroup.identity `
    'the public plan freezes a non-sensitive alias while reviewed source owns the stable SID'
Assert-Equal 'DirectMembersOnly' $policy.membershipSemantics `
    'the collector never guesses nested effective access'
Assert-Equal 1 @($policy.collectors).Count 'one approved attempt owns the direct membership scope'
$collector = $policy.collectors[0]
Assert-Equal 'observe-local-administrators' $collector.operationId `
    'the slice reuses the frozen administrator-plan operation'
Assert-Equal 'Administrator' $collector.executionContext 'membership collection runs only in the approved elevated worker'
Assert-Equal 'OfflineOnly' $collector.networkBehavior 'membership collection never contacts a domain controller'
Assert-Equal 'Windows NetLocalGroupGetMembers API' $collector.dependencies[0] `
    'membership is a structured Windows API projection, not command text'
Assert-Equal 1 $collector.maximumAttempts 'membership collection never retries'
Assert-Equal 5000 $collector.deadlineMilliseconds 'membership collection is finite'
Assert-Equal 8 $collector.maximumDirectMembers 'the evidence bound is explicit'
foreach ($flag in @('mayPrompt','mayInstall','mayDownload','maySelfElevate','writesAllowed')) {
    Assert-Equal $false ([bool]$collector.$flag) "the collector cannot widen authority through $flag"
}
Assert-Equal 1 @($policy.rules).Count 'one rule produces one administrator-exposure finding'
Assert-Equal 'Indeterminate' $policy.rules[0].missingEvidenceOutcome `
    'denied or partial membership never becomes an empty group'
$expected = @(
    'LocalPrincipal','DomainPrincipal','NestedGroup','UnresolvedSid','DuplicateMembership',
    'AlternateAdministrator','Denied','Partial','NonEnglish','ElevationDenied'
)
Assert-Equal ($expected -join '|') (@($policy.validationScenarios) -join '|') `
    'the ticket validation matrix is release-closed'

$text = Get-Content -LiteralPath $policyPath -Raw
if ($text -match '(?i)net localgroup|password|credential|accessToken|privateKey') {
    throw 'The administrator policy admits parsed commands or prohibited material.'
}

Write-Output 'PASS: Administrator Exposure identity, bounds, semantics, and scenarios are release-defined.'
