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
        file = 'direct-outbound'
        scenario = 'DirectOutbound'
        request = $enabledRequestPath
        overall = 'NeedsAttention'
        management = 'NeedsAttention'
        discoveryTasks = 2
    }
    @{
        file = 'local-only'
        scenario = 'LocalOnly'
        request = $localRequestPath
        overall = 'Indeterminate'
        management = 'Indeterminate'
        discoveryTasks = 3
    }
)

foreach ($case in $cases) {
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation', '-RequestPath', $case.request, '-AcceptPreparation',
        '-PreparationFixturePath', $preparationPath,
        '-MicrosoftConnectivityFixturePath', (Join-Path $PSScriptRoot "fixtures/microsoft-connectivity/$($case.file).json")
    )
    $validation = @($result.Records | Where-Object {
        $_.recordType -eq 'win-pcinfo.cross-domain-guidance-validation'
    })
    $terminal = @($result.Records | Where-Object recordType -eq 'win-pcinfo.terminal')

    Assert-Equal 1 $validation.Count "$($case.scenario) emits one sanitized cross-domain projection"
    Assert-Equal 1 $terminal.Count "$($case.scenario) retains one terminal path"
    Assert-Equal $case.scenario $validation[0].scenario "$($case.scenario) preserves the release-owned full-profile scenario"
    Assert-Equal $case.overall $validation[0].overallFindingOutcome "$($case.scenario) derives the cautious migration-path outcome"
    Assert-Equal $case.management $validation[0].managementPlaneOutcome "$($case.scenario) derives the management-plane outcome"
    Assert-Equal 5 $validation[0].orderedRecommendationCount "$($case.scenario) keeps a fixed ordered path"
    Assert-Equal 2 $validation[0].immediateReviewCount "$($case.scenario) preserves the fixed ImmediateReview tier"
    Assert-Equal 2 $validation[0].planNextCount "$($case.scenario) preserves the fixed PlanNext tier"
    Assert-Equal 1 $validation[0].considerLaterCount "$($case.scenario) preserves the fixed ConsiderLater tier"
    Assert-Equal 4 $validation[0].relationshipCount "$($case.scenario) preserves the relationship graph"
    Assert-Equal $case.discoveryTasks $validation[0].discoveryTaskCount "$($case.scenario) materializes the expected tenant-side tasks"
    Assert-Equal $false $validation[0].scoreProduced "$($case.scenario) never invents a score"
    Assert-Equal $false $validation[0].automaticRemediationAttempted "$($case.scenario) never attempts remediation"
    Assert-Equal $true $validation[0].reportSectionVerified "$($case.scenario) verifies the new report section"
    Assert-Equal $true $validation[0].assessmentRecordValidated "$($case.scenario) enters the canonical Assessment Record"
    Assert-Equal $true $validation[0].beginnerReportVerified "$($case.scenario) verifies the beginner report"
    Assert-Equal $true $validation[0].protectedPackageVerified "$($case.scenario) reopens the protected package"
    Assert-Equal $true $validation[0].validationCleanupVerified "$($case.scenario) leaves no validation residue"
    $projectionJson = $validation[0] | ConvertTo-Json -Depth 10 -Compress
    if ($projectionJson -match '(?i)tenant-id|device-id|thumbprint|proxy-server|certificate-fingerprint|synthetic-connectivity|tls_aes') {
        throw "$($case.scenario) leaked Restricted evidence into public output."
    }
    if ($result.StandardError) { throw "$($case.scenario) wrote stderr: $($result.StandardError)" }
}

Write-Output 'PASS: the generated application derives a cautious cross-domain migration path without exposing Restricted evidence.'
