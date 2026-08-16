[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ContractValidator.ps1')
foreach ($source in @('RuntimeCompatibility', 'ProcessSupervisor',
    'EvidenceWorkspace', 'ProtectedPackage', 'DeviceReadiness')) {
    . (Join-Path $repositoryRoot "src/$source.ps1")
}

$convertFromJson = $ExecutionContext.InvokeCommand.GetCommand(
    'ConvertFrom-Json', [System.Management.Automation.CommandTypes]::Cmdlet
)
$convertToJson = $ExecutionContext.InvokeCommand.GetCommand(
    'ConvertTo-Json', [System.Management.Automation.CommandTypes]::Cmdlet
)
$testJson = $ExecutionContext.InvokeCommand.GetCommand(
    'Test-Json', [System.Management.Automation.CommandTypes]::Cmdlet
)

$policy = Get-DeviceReadinessPolicy -ConvertFromJsonCommand $convertFromJson
$collector = Invoke-ApprovedCollectorProcess -OperationId ([string] $policy.collector.operationId) `
    -DeviceReadinessScenario 'Complete'
$evidence = ConvertTo-NormalizedDeviceReadinessEvidence -Payload $collector.PrivatePayload
$record = New-DeviceReadinessAssessmentRecord -RunId 'run:report:test' -Evidence $evidence `
    -CollectorResult $collector -Policy $policy -ValidationFixture $true
$recordBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
    (& $convertToJson -InputObject $record -Compress -Depth 30)
)
$validation = Test-AssessmentContract -Utf8Bytes $recordBytes `
    -ConvertFromJsonCommand $convertFromJson -TestJsonCommand $testJson
$baseRecord = Complete-ValidatedDeviceReadinessAssessmentRecord `
    -ValidatedRecord $record -Policy $policy -ContractValidation $validation

$cases = @(
    @{ outcome = 'Completed'; completeness = 'Complete' }
    @{ outcome = 'CompletedWithGaps'; completeness = 'RecoverablePartial' }
    @{ outcome = 'Cancelled'; completeness = 'RecoverablePartial' }
    @{ outcome = 'TimedOut'; completeness = 'RecoverablePartial' }
    @{ outcome = 'IntegrityFailed'; completeness = 'RecoverablePartial' }
    @{ outcome = 'CleanupIncomplete'; completeness = 'RecoverablePartial' }
)

foreach ($case in $cases) {
    $variant = $baseRecord | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
    $variant.run.outcome = $case.outcome
    if ($case.outcome -ne 'Completed') {
        $variant.coverage[0].state = 'Partial'
        if ($variant.coverage[0].PSObject.Properties['reasonCode']) {
            $variant.coverage[0].reasonCode = "RUN.$($case.outcome.ToUpperInvariant())"
        }
        else {
            $variant.coverage[0] | Add-Member -NotePropertyName reasonCode `
                -NotePropertyValue "RUN.$($case.outcome.ToUpperInvariant())"
        }
    }
    [byte[]] $firstBytes = New-DeviceReadinessReportBytes -Record $variant
    [byte[]] $secondBytes = New-DeviceReadinessReportBytes -Record $variant
    $firstText = [System.Text.UTF8Encoding]::new($false, $true).GetString($firstBytes)
    $contract = Test-AssessmentReportContract -ReportBytes $firstBytes -Record $variant `
        -NetworkBehavior 'MicrosoftConnectivityEnabled' -ExpectUnicode $false

    Assert-Equal $true ([System.Linq.Enumerable]::SequenceEqual[byte]($firstBytes, $secondBytes)) `
        "$($case.outcome) remains byte-identical across repeated renders"
    Assert-Equal $true $contract.executiveSummaryVerified `
        "$($case.outcome) keeps the executive summary ahead of evidence"
    Assert-Equal $true $contract.categorySeparationVerified `
        "$($case.outcome) keeps report categories distinct"
    Assert-Equal $true $contract.offlineSafeVerified `
        "$($case.outcome) remains self-contained and scripting-free"
    Assert-Equal $true $contract.keyboardNavigationVerified `
        "$($case.outcome) keeps keyboard navigation visible"
    Assert-Equal $true $contract.printLayoutVerified `
        "$($case.outcome) keeps print layout rules"
    Assert-Equal $true $contract.utf8Verified `
        "$($case.outcome) stays valid UTF-8 HTML"
    Assert-Equal $case.completeness $contract.renderedCompleteness `
        "$($case.outcome) maps to the expected report completeness label"
    if (-not $firstText.Contains('WIN-PCInfo Comprehensive Local Assessment')) {
        throw "$($case.outcome) did not render the comprehensive report title."
    }
    if (-not $firstText.Contains((Get-AssessmentReportOutcomeLabel -Outcome $case.outcome))) {
        throw "$($case.outcome) did not render its outcome label."
    }
}

Write-Output 'PASS: the comprehensive report renderer preserves deterministic executive summaries for every synthetic outcome state.'
