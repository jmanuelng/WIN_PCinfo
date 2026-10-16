[CmdletBinding()]
param([string] $CandidatePath, [string] $PreparedManifestPath, [string] $PreparedManifestSha256)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'AssessmentQualificationSupport.ps1')
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidate=$candidateContext.Path
$candidateSuccessMessages=[Collections.Generic.List[string]]::new()
$candidateUseError=$null
try {
$regions = [regex]::Matches([IO.File]::ReadAllText($candidate),
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach ($region in $regions) { . ([scriptblock]::Create($region.Groups[2].Value)) }
$root = Join-Path $repositoryRoot ('.test-output/device-prohibited-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$supervisorSource = ($regions | Where-Object { $_.Groups[1].Value -eq 'ProcessSupervisor.ps1' }).Groups[2].Value
$script:ProhibitedNativeBuffers = [Collections.Generic.List[object]]::new()
[byte[]]$recordBytes=$null
[byte[]]$reportBytes=$null
$opened=$null
try {
    # Observe owned native transport arrays without substituting the supervisor.
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($supervisorSource,[ref]$tokens,[ref]$errors)
    $assignments=$ast.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$native' -and $node.Right.Extent.Text -match 'NativeRunner\]::Run'},$true)
    $observed=$supervisorSource
    foreach($node in @($assignments|Sort-Object {$_.Extent.EndOffset} -Descending)){
        $observed=$observed.Insert($node.Extent.EndOffset,'; $script:ProhibitedNativeBuffers.Add($native.StandardOutput); $script:ProhibitedNativeBuffers.Add($native.StandardError)')
    }
    . ([scriptblock]::Create($observed))
    $commands=Get-BuiltInModuleCompatibilityFacts
    $policy=Get-DeviceReadinessPolicy -ConvertFromJsonCommand $commands.convertFromJsonCommand
    $collector=Invoke-ApprovedCollectorProcess -OperationId $policy.collector.operationId -DeviceReadinessScenario ProhibitedMaterial
    Assert-Equal 'PROCESS.PROHIBITED_MATERIAL_BLOCKED' $collector.Supervision.reasonCode 'actual native JSON secret input is refused before payload admission'
    Assert-Equal $false ([bool]$collector.PSObject.Properties['PrivatePayload']) 'no rejected payload crosses the collector boundary'
    Assert-Equal $true ($script:ProhibitedNativeBuffers.Count -gt 0) 'the native byte transport actually executed'
    foreach($bytes in $script:ProhibitedNativeBuffers){
        Assert-Equal 0 @($bytes|Where-Object {$_ -ne 0}).Count 'owned native input/error buffers are cleared after prohibited input'
    }
    $evidence=[pscustomobject]@{
        sourceLocale='und';manufacturer=$null;model=$null;processorName=$null;memoryBytes=$null
        windowsEdition=$null;build=$null;architecture=$null;activationState=$null;activationAvailability='Unavailable'
        systemTypeCode=$null;hypervisorPresent=$null;chassisTypeCodes=$null;chassisAvailability='Unavailable'
        virtualizationDetected=$null;formFactor=$null;batteryAvailability='Unavailable';batteryPresence=$null
        batteryStatus=$null;batteryChargePercent=$null;batteryRuntimeMinutes=$null
    }
    $record=New-DeviceReadinessAssessmentRecord -RunId 'run:device:synthetic-prohibited-154' -Evidence $evidence `
        -CollectorResult $collector -Policy $policy -ValidationFixture $true `
        -CoverageStateOverride ProhibitedMaterialBlocked -CoverageReasonCode COLLECTION.PROHIBITED_MATERIAL_BLOCKED
    $recordBytes=[Text.Encoding]::UTF8.GetBytes(($record|ConvertTo-Json -Depth 30 -Compress))
    $validation=Test-AssessmentContract -Utf8Bytes $recordBytes -ConvertFromJsonCommand $commands.convertFromJsonCommand -TestJsonCommand $commands.testJsonCommand
    $record=Complete-ValidatedDeviceReadinessAssessmentRecord -ValidatedRecord $record -Policy $policy -ContractValidation $validation
    $recordBytes=[Text.Encoding]::UTF8.GetBytes(($record|ConvertTo-Json -Depth 30 -Compress))
    $finalValidation=Test-AssessmentContract -Utf8Bytes $recordBytes -ConvertFromJsonCommand $commands.convertFromJsonCommand -TestJsonCommand $commands.testJsonCommand
    Assert-Equal $true $finalValidation.accepted 'marker-only interpreted record is valid before rendering'
    $reportBytes=New-DeviceReadinessReportBytes -Record $record
    $package=New-ProtectedEvidencePackage -DestinationDirectory $root -Artifacts ([ordered]@{
        'assessment-record.json'=$recordBytes; 'assessment-report.html'=$reportBytes
    }) -AssessmentContractSetVersion $record.contractVersion -Completeness Complete
    Assert-Equal $true $package.verified 'marker-only evidence passes authenticated finalization'
    $opened=Read-ProtectedEvidencePackage -LiteralPath $package.packagePath
    Assert-Equal $true $opened.verified 'marker-only package reopens'
    $reopened=[Text.Encoding]::UTF8.GetString($opened.artifacts['assessment-record.json'])|ConvertFrom-Json
    Assert-Equal 0 @($reopened.observations).Count 'prohibited material becomes no observation'
    Assert-Equal $false $reopened.diagnostics[0].prohibitedMaterial.retained 'marker declares no retained material'
    Assert-Equal $false $reopened.diagnostics[0].prohibitedMaterial.hashed 'marker declares no hash of prohibited material'
    foreach($bytes in $opened.artifacts.Values){
        Assert-QualificationMarkerAbsent -Text ([Text.Encoding]::UTF8.GetString($bytes)) -Marker 'synthetic-prohibited-marker'
        [Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]]$bytes)
    }
    Assert-QualificationMarkerAbsent -Text ($collector|ConvertTo-Json -Depth 30) -Marker 'synthetic-prohibited-marker'
    Assert-Equal 1 @(Get-ChildItem -LiteralPath $root -Recurse -File).Count 'only the protected package persists, with no plaintext transport, report or archive'
}
finally {
    foreach($buffer in @($recordBytes,$reportBytes)) {
        if($null -ne $buffer){[Security.Cryptography.CryptographicOperations]::ZeroMemory($buffer)}
    }
    if($null -ne $opened -and $opened.verified) {
        foreach($buffer in $opened.artifacts.Values){[Security.Cryptography.CryptographicOperations]::ZeroMemory($buffer)}
    }
    . ([scriptblock]::Create($supervisorSource))
    $resolved=[IO.Path]::GetFullPath($root)
    if([IO.Path]::GetDirectoryName($resolved) -ne [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))){throw 'Prohibited-material cleanup escaped its parent.'}
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
}
$candidateSuccessMessages.Add('PASS: native prohibited input is cleared; only false-retained/false-hashed markers reach the authenticated record/report.')

}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
foreach ($candidateSuccessMessage in $candidateSuccessMessages) { Write-Output $candidateSuccessMessage }
