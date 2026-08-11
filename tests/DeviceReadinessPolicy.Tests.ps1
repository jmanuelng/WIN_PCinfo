[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-device-readiness.json'
$schemaPath = Join-Path $repositoryRoot 'schemas/device-readiness.schema.json'
$catalogPath = Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-approved-collectors.json'
$sourcePath = Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1'
. $sourcePath

if (-not (Test-Json -Json (Get-Content $policyPath -Raw) -SchemaFile $schemaPath)) {
    throw 'The release Device Readiness policy does not satisfy its schema.'
}
$policy = Get-Content $policyPath -Raw | ConvertFrom-Json -Depth 20
$policyJson = Get-Content $policyPath -Raw
foreach ($mutation in @(
    { param($value) $value.collector.source = 'caller supplied' },
    { param($value) $value.collector.dependencies = @('download') },
    { param($value) $value.collector.deadlineMilliseconds = 6000 },
    { param($value) $value.collector.standardOutputMaximumBytes = 32768 },
    { param($value) $value.collector.standardErrorMaximumBytes = 8192 },
    { param($value) $value.fieldIds = @('field:widened') },
    { param($value) $value.derivations[0].sourceId = 'source:caller-supplied' },
    { param($value) $value.derivations[1].maximumInputObservations = 99 },
    { param($value) $value.rules[0].minimumWindowsBuild = 1 },
    { param($value) $value.rules[1].operationId = 'op:caller-supplied' },
    { param($value) $value.rules[2].maximumOutputFindings = 2 },
    { param($value) $value.validationScenarios = @('CallerSupplied') }
)) {
    $mutated = $policyJson | ConvertFrom-Json -Depth 20
    & $mutation $mutated
    $mutatedJson = $mutated | ConvertTo-Json -Compress -Depth 20
    if (Test-Json -Json $mutatedJson -SchemaFile $schemaPath -ErrorAction SilentlyContinue) {
        throw 'The public policy schema accepted widened post-approval device-context authority.'
    }
}
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
    "'Manufacturer','Model','TotalPhysicalMemory','PCSystemType','HypervisorPresent'",
    '-Property $ComputerSystemProperties',
    'Win32_Processor -Property Name', 'OperatingSystemSKU, BuildNumber',
    'SoftwareLicensingProduct', '-Property LicenseStatus',
    'Win32_SystemEnclosure', '-Property ChassisTypes', 'Win32_Battery',
    'BatteryStatus, EstimatedChargeRemaining, EstimatedRunTime',
    'RuntimeInformation]::OSArchitecture'
)) {
    if (-not $source.Contains($projection)) { throw "The structured source projection is missing: $projection" }
}
if ($source -match '(?i)select\s+\*|Win32_OperatingSystem[^\r\n]+Caption|powercfg|slmgr|Set-CimInstance|Invoke-CimMethod|Enable-WindowsOptionalFeature|Disable-WindowsOptionalFeature|dism\.exe') {
    throw 'The collector contains a broad projection or localized Caption identifier.'
}
$collectorBytes = Get-SyntheticCollectorScriptBytes
$collectorText = [System.Text.UTF8Encoding]::new($false, $true).GetString($collectorBytes)
foreach ($prohibitedProjection in @('PartialProductKey', 'ProductKeyID', 'LicenseFamily')) {
    if ($collectorText.Contains($prohibitedProjection)) {
        throw "The executable collector projects prohibited licensing material: $prohibitedProjection"
    }
}
if ($collectorBytes.Length -gt 11264) {
    throw 'The compact, release-hashed collector exceeded its bounded command-line design size.'
}
if ($policy.collector.mayPrompt -or $policy.collector.mayInstall -or
    $policy.collector.mayDownload -or $policy.collector.maySelfElevate -or
    $policy.collector.networkBehavior -ne 'OfflineOnly') {
    throw 'The frozen operation gained authority after preparation.'
}
if (@($policy.rules).Count -ne 4) {
    throw 'The release must declare exactly one bounded rule for each canonical finding.'
}
if (@($policy.derivations).Count -ne 2) {
    throw 'The release must declare the virtualization and form classifier operations.'
}
$expectedDerivations = @{
    'virtualization' = @{op='op:device.virtualization.classify';inputs=2}
    'form-factor' = @{op='op:device.form-factor.classify';inputs=3}
}
foreach ($derivation in @($policy.derivations)) {
    $expected = $expectedDerivations[[string]$derivation.derivedKind]
    if ($null -eq $expected -or $derivation.collectorId -ne
        'collector:win-pcinfo.device-context-classifier' -or
        $derivation.operationId -ne $expected.op -or
        $derivation.maximumInputObservations -ne $expected.inputs -or
        $derivation.maximumOutputObservations -ne 1 -or
        $derivation.deadlineMilliseconds -ne 100 -or
        $derivation.maximumAttempts -ne 1 -or $derivation.cleanup -ne 'NoArtifacts') {
        throw 'A classifier operation is not release-frozen to one bounded output.'
    }
}
$expectedRules = @{
    'device-readiness' = @{id='rule:device.readiness/1.0.0';op='op:rule.device-readiness.evaluate';inputs=3}
    'activation-context' = @{id='rule:windows.activation-context/1.0.0';op='op:rule.windows-activation-context.evaluate';inputs=1}
    'platform-context' = @{id='rule:device.platform-context/1.0.0';op='op:rule.device-platform-context.evaluate';inputs=6}
    'power-context' = @{id='rule:device.power-context/1.0.0';op='op:rule.device-power-context.evaluate';inputs=4}
}
foreach ($rule in @($policy.rules)) {
    $expected = $expectedRules[[string]$rule.findingKind]
    if ($null -eq $expected -or $rule.ruleId -ne $expected.id -or
        $rule.operationId -ne $expected.op -or
        $rule.executionContext -ne 'InProcessValidatedAssessmentRecord' -or
        $rule.networkBehavior -ne 'OfflineOnly' -or $rule.maximumAttempts -ne 1 -or
        $rule.deadlineMilliseconds -ne 100 -or
        $rule.maximumInputObservations -ne $expected.inputs -or
        $rule.maximumOutputFindings -ne 1 -or $rule.cleanup -ne 'NoArtifacts' -or
        $rule.mayPrompt -or $rule.mayInstall -or $rule.mayDownload -or
        $rule.maySelfElevate -or $rule.writesAllowed) {
        throw 'A finding rule does not retain its closed, finite, one-output authority.'
    }
}

Write-Output 'PASS: Device Readiness sources, authority, and process bounds are release-defined and closed.'
