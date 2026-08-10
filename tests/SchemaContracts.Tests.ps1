[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestSchemaPath = Join-Path $repositoryRoot 'schemas/assessment-run-request.schema.json'
$planSchemaPath = Join-Path $repositoryRoot 'schemas/preparation-plan.schema.json'
$localRequestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$connectivityRequestPath = Join-Path $PSScriptRoot 'fixtures/automation-request-connectivity.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

foreach ($requestPath in @($localRequestPath, $connectivityRequestPath)) {
    $requestJson = [System.IO.File]::ReadAllText($requestPath)
    if (-not (Test-Json -Json $requestJson -SchemaFile $requestSchemaPath)) {
        throw "$requestPath does not satisfy the public request schema."
    }
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath `
        -Arguments @('-Mode', 'Automation', '-RequestPath', $requestPath, '-AcceptPreparation')
    $summary = @($result.Records | Where-Object recordType -eq 'win-pcinfo.preparation-summary')[0]
    $plan = $summary.plan
    $planJson = $plan | ConvertTo-Json -Compress -Depth 30
    if (-not (Test-Json -Json $planJson -SchemaFile $planSchemaPath)) {
        throw "The generated $($summary.plan.network.behavior) plan does not satisfy the public plan schema."
    }

    Assert-Equal $plan.requestDigest $summary.requestDigest 'summary is bound to the schema-valid request'
    Assert-Equal $plan.scope.capabilities.Count $summary.plan.scope.capabilities.Count `
        'summary discloses the entire schema-valid plan scope'
    if ($summary.plan.network.behavior -eq 'LocalOnly') {
        Assert-Equal 0 $summary.plan.network.plannedRequests.Count 'Local Only plans zero assessment requests'
    }
    else {
        Assert-Equal 2 $summary.plan.network.plannedRequests.Count `
            'Microsoft Connectivity Enabled names its bounded request classes before approval'
    }
}

Write-Output 'PASS: request and immutable-plan schemas cover both approved network behaviors.'
