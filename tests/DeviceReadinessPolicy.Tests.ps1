[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-device-readiness.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/device-readiness.schema.json'
$catalogPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-approved-collectors.json'
$sourcePath = Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1'

if (-not (Test-Json -Json (Get-Content $policyPath -Raw) -SchemaFile $schemaPath)) {
    throw 'The release Device Readiness policy does not satisfy its schema.'
}
$policy = Get-Content $policyPath -Raw | ConvertFrom-Json -Depth 20
$catalog = Get-Content $catalogPath -Raw | ConvertFrom-Json -Depth 20
$deviceCollector = @($catalog.collectors | Where-Object collectorId -eq $policy.collector.collectorId)
if ($deviceCollector.Count -ne 1) { throw 'The real Device Readiness collector identity is not unique.' }
$operation = @($deviceCollector[0].operations | Where-Object operationId -eq $policy.collector.operationId)
if ($operation.Count -ne 1) { throw 'The approved catalog must contain the frozen Device Readiness operation exactly once.' }
if ($operation[0].deadlineMilliseconds -ne $policy.collector.deadlineMilliseconds -or
    $operation[0].standardOutputMaximumBytes -ne $policy.collector.standardOutputMaximumBytes -or
    $operation[0].standardErrorMaximumBytes -ne $policy.collector.standardErrorMaximumBytes) {
    throw 'The supervisor and Device Readiness policies have divergent bounds.'
}
$source = Get-Content $sourcePath -Raw
foreach ($projection in @(
    'Manufacturer, Model, TotalPhysicalMemory', 'Win32_Processor -Property Name',
    'OperatingSystemSKU, BuildNumber', 'RuntimeInformation]::OSArchitecture'
)) {
    if (-not $source.Contains($projection)) { throw "The structured source projection is missing: $projection" }
}
if ($source -match '(?i)select\s+\*|Win32_OperatingSystem[^\r\n]+Caption') {
    throw 'The collector contains a broad projection or localized Caption identifier.'
}
if ($policy.collector.mayPrompt -or $policy.collector.mayInstall -or
    $policy.collector.mayDownload -or $policy.collector.maySelfElevate -or
    $policy.collector.networkBehavior -ne 'OfflineOnly') {
    throw 'The frozen operation gained authority after preparation.'
}
if ($policy.rule.operationId -ne 'op:rule.device-windows-readiness.evaluate' -or
    $policy.rule.executionContext -ne 'InProcessValidatedAssessmentRecord' -or
    $policy.rule.networkBehavior -ne 'OfflineOnly' -or $policy.rule.maximumAttempts -ne 1 -or
    $policy.rule.deadlineMilliseconds -ne 100 -or $policy.rule.maximumInputObservations -ne 8 -or
    $policy.rule.maximumOutputFindings -ne 1 -or $policy.rule.cleanup -ne 'NoArtifacts' -or
    $policy.rule.mayPrompt -or $policy.rule.mayInstall -or $policy.rule.mayDownload -or
    $policy.rule.maySelfElevate -or $policy.rule.writesAllowed) {
    throw 'The readiness rule does not retain its closed, finite in-process authority.'
}

Write-Output 'PASS: Device Readiness sources, authority, and process bounds are release-defined and closed.'
