[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$fixtureDirectory = Join-Path $repositoryRoot '.test-output/request-validation'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$null = New-Item -ItemType Directory -Path $fixtureDirectory -Force
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

function New-ValidRequestFixture {
    [ordered]@{
        contractVersion = '1.0.0'
        profile = 'ComprehensiveLocalAssessment'
        outputDestination = './WIN-PCInfo-Results'
        networkBehavior = 'LocalOnly'
        updateChoice = 'NoUpdateCheck'
        diagnosticLevel = 'Standard'
        automationChoices = [ordered]@{
            allowAssessmentNetwork = $false
            allowElevation = $true
            allowInstallation = $false
            allowPersistentChanges = $false
            allowStaleRecovery = $false
            verificationOverride = 'None'
        }
    }
}

$cases = @(
    @{ Name = 'invalid-json'; Json = '{'; Expected = 'REQUEST.JSON_INVALID' }
    @{ Name = 'unknown-security-field'; Mutate = { param($r) $r['skipRuntimeCheck'] = $true }; Expected = 'REQUEST.UNKNOWN_FIELD' }
    @{ Name = 'unsupported-major'; Mutate = { param($r) $r.contractVersion = '2.0.0' }; Expected = 'REQUEST.CONTRACT_VERSION_UNSUPPORTED' }
    @{ Name = 'missing-required-field'; Mutate = { param($r) $r.Remove('automationChoices') }; Expected = 'REQUEST.REQUIRED_FIELD_MISSING' }
    @{ Name = 'unsupported-network-mode'; Mutate = { param($r) $r.networkBehavior = 'FullOutbound' }; Expected = 'REQUEST.NETWORK_MODE_UNSUPPORTED' }
    @{ Name = 'local-only-network-conflict'; Mutate = { param($r) $r.automationChoices.allowAssessmentNetwork = $true }; Expected = 'REQUEST.NETWORK_CONFLICT' }
    @{ Name = 'connectivity-network-conflict'; Mutate = { param($r) $r.networkBehavior = 'MicrosoftConnectivityEnabled' }; Expected = 'REQUEST.NETWORK_CONFLICT' }
    @{ Name = 'run-anyway-override'; Mutate = { param($r) $r.automationChoices.verificationOverride = 'RunAnyway' }; Expected = 'REQUEST.VERIFICATION_OVERRIDE_UNSUPPORTED' }
    @{ Name = 'missing-elevation-authority'; Mutate = { param($r) $r.automationChoices.allowElevation = $false }; Expected = 'REQUEST.AUTHORITY_CONFLICT' }
    @{ Name = 'installation-authority-expansion'; Mutate = { param($r) $r.automationChoices.allowInstallation = $true }; Expected = 'REQUEST.AUTHORITY_CONFLICT' }
    @{ Name = 'wrong-field-type'; Mutate = { param($r) $r.outputDestination = 42 }; Expected = 'REQUEST.FIELD_TYPE_INVALID' }
    @{ Name = 'unc-output-destination'; Mutate = { param($r) $r.outputDestination = '\\server\share\results' }; Expected = 'REQUEST.OUTPUT_DESTINATION_NETWORK_UNSUPPORTED' }
)

foreach ($case in $cases) {
    $requestPath = Join-Path $fixtureDirectory "$($case.Name).json"
    $json = if ($case.ContainsKey('Json')) {
        $case.Json
    }
    else {
        $requestFixture = New-ValidRequestFixture
        & $case.Mutate $requestFixture
        $requestFixture | ConvertTo-Json -Compress -Depth 10
    }
    [System.IO.File]::WriteAllText($requestPath, $json, [System.Text.UTF8Encoding]::new($false))
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath `
        -Arguments @('-Mode', 'Automation', '-RequestPath', $requestPath)
    $terminal = $result.Records[-1]

    Assert-Equal 20 $result.ExitCode "$($case.Name) has the stable NotStarted exit"
    Assert-Equal 'NotStarted' $terminal.outcome "$($case.Name) does not begin collection"
    Assert-Equal $case.Expected $terminal.reasonCode "$($case.Name) has a stable request reason"
    Assert-Equal 'RequestValidation' $terminal.phase "$($case.Name) stops at request validation"
    Assert-Equal $false $terminal.collectionStarted "$($case.Name) cannot collect"
}

Write-Output "PASS: generated application rejected $($cases.Count) invalid automation requests through the terminal contract."
