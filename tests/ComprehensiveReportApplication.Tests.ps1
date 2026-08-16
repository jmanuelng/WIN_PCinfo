[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$enabledRequestPath = Join-Path $PSScriptRoot 'fixtures/automation-request-connectivity.json'
$localRequestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$cases = @(
    @{
        scenario = 'DirectOutbound'
        requestPath = $enabledRequestPath
        arguments = @(
            '-MicrosoftConnectivityFixturePath',
            (Join-Path $PSScriptRoot 'fixtures/microsoft-connectivity/direct-outbound.json')
        )
        networkMode = 'MicrosoftConnectivityEnabled'
        unicode = $false
    }
    @{
        scenario = 'LocalOnly'
        requestPath = $localRequestPath
        arguments = @(
            '-MicrosoftConnectivityFixturePath',
            (Join-Path $PSScriptRoot 'fixtures/microsoft-connectivity/local-only.json')
        )
        networkMode = 'LocalOnly'
        unicode = $false
    }
    @{
        scenario = 'Unicode'
        requestPath = $enabledRequestPath
        arguments = @(
            '-MicrosoftConnectivityFixturePath',
            (Join-Path $PSScriptRoot 'fixtures/microsoft-connectivity/unicode.json')
        )
        networkMode = 'MicrosoftConnectivityEnabled'
        unicode = $true
    }
    @{
        scenario = 'Redirect'
        requestPath = $enabledRequestPath
        arguments = @(
            '-MicrosoftConnectivityFixturePath',
            (Join-Path $PSScriptRoot 'fixtures/microsoft-connectivity/redirect.json')
        )
        networkMode = 'MicrosoftConnectivityEnabled'
        unicode = $false
    }
)

foreach ($case in $cases) {
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments (
        @(
            '-Mode', 'Automation', '-RequestPath', $case.requestPath, '-AcceptPreparation',
            '-PreparationFixturePath', $preparationPath
        ) + $case.arguments
    )

    $validation = @($result.Records | Where-Object {
        $_.recordType -eq 'win-pcinfo.comprehensive-report-validation'
    })
    $completion = @($result.Records | Where-Object {
        $_.recordType -eq 'win-pcinfo.completion-summary'
    })
    $terminal = @($result.Records | Where-Object {
        $_.recordType -eq 'win-pcinfo.terminal'
    })

    Assert-Equal 1 $validation.Count "$($case.scenario) emits one comprehensive report validation record"
    Assert-Equal 1 $completion.Count "$($case.scenario) emits one Completion Summary"
    Assert-Equal 1 $terminal.Count "$($case.scenario) emits one terminal record"

    Assert-Equal $case.scenario $validation[0].scenario "$($case.scenario) preserves the report scenario"
    Assert-Equal $case.networkMode $validation[0].networkBehavior "$($case.scenario) preserves the rendered network mode"
    Assert-Equal $true $validation[0].executiveSummaryVerified "$($case.scenario) starts with the executive summary sections"
    Assert-Equal $true $validation[0].categorySeparationVerified "$($case.scenario) keeps report categories visibly distinct"
    Assert-Equal $true $validation[0].deterministicVerified "$($case.scenario) renders deterministically for identical inputs"
    Assert-Equal $true $validation[0].offlineSafeVerified "$($case.scenario) remains self-contained and offline-safe"
    Assert-Equal $true $validation[0].keyboardNavigationVerified "$($case.scenario) exposes keyboard-operable primary navigation"
    Assert-Equal $true $validation[0].printLayoutVerified "$($case.scenario) carries print-specific layout rules"
    Assert-Equal $true $validation[0].utf8Verified "$($case.scenario) declares and preserves UTF-8"
    Assert-Equal $true $validation[0].reportWithinPackageBound "$($case.scenario) keeps the report within the package bound"
    Assert-Equal $true $validation[0].packageManifestConsistent "$($case.scenario) keeps the report consistent with the package manifest"
    Assert-Equal $true $validation[0].completionSummaryConsistent "$($case.scenario) keeps the Completion Summary aligned with package and terminal facts"
    Assert-Equal $case.unicode $validation[0].unicodePreservedVerified "$($case.scenario) preserves multilingual Unicode only when expected"
    Assert-Equal $true $validation[0].assessmentRecordValidated "$($case.scenario) still validates the canonical Assessment Record"
    Assert-Equal $true $validation[0].protectedPackageVerified "$($case.scenario) still reopens the protected package"
    Assert-Equal $true $validation[0].validationCleanupVerified "$($case.scenario) still removes validation artifacts"

    Assert-Equal $terminal[0].outcome $completion[0].assessment.outcome `
        "$($case.scenario) carries the terminal outcome into the Completion Summary"
    Assert-Equal $validation[0].renderedCompleteness $completion[0].assessment.renderedCompleteness `
        "$($case.scenario) carries report completeness into the Completion Summary"
    Assert-Equal $terminal[0].cleanup.verified $completion[0].assessment.cleanupVerified `
        "$($case.scenario) carries cleanup verification into the Completion Summary"

    if ($result.StandardError) { throw "$($case.scenario) wrote stderr: $($result.StandardError)" }
}

Write-Output 'PASS: the generated application validates the comprehensive deterministic report contract.'
