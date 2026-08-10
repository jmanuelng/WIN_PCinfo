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

$cases = @(
    @{
        Name = 'unknown-security-field'
        Json = '{"contractVersion":"1.0.0","profile":"ComprehensiveLocalAssessment","outputDestination":"./WIN-PCInfo-Results","networkBehavior":"LocalOnly","updateChoice":"NoUpdateCheck","diagnosticLevel":"Standard","automationChoices":{"allowAssessmentNetwork":false,"allowElevation":true,"allowInstallation":false,"allowPersistentChanges":false,"allowStaleRecovery":false,"verificationOverride":"None"},"skipRuntimeCheck":true}'
        Expected = 'REQUEST.UNKNOWN_FIELD'
    }
    @{
        Name = 'unsupported-major'
        Json = '{"contractVersion":"2.0.0","profile":"ComprehensiveLocalAssessment","outputDestination":"./WIN-PCInfo-Results","networkBehavior":"LocalOnly","updateChoice":"NoUpdateCheck","diagnosticLevel":"Standard","automationChoices":{"allowAssessmentNetwork":false,"allowElevation":true,"allowInstallation":false,"allowPersistentChanges":false,"allowStaleRecovery":false,"verificationOverride":"None"}}'
        Expected = 'REQUEST.CONTRACT_VERSION_UNSUPPORTED'
    }
    @{
        Name = 'missing-required-field'
        Json = '{"contractVersion":"1.0.0","profile":"ComprehensiveLocalAssessment","outputDestination":"./WIN-PCInfo-Results","networkBehavior":"LocalOnly","updateChoice":"NoUpdateCheck","diagnosticLevel":"Standard"}'
        Expected = 'REQUEST.REQUIRED_FIELD_MISSING'
    }
    @{
        Name = 'unsupported-network-mode'
        Json = '{"contractVersion":"1.0.0","profile":"ComprehensiveLocalAssessment","outputDestination":"./WIN-PCInfo-Results","networkBehavior":"FullOutbound","updateChoice":"NoUpdateCheck","diagnosticLevel":"Standard","automationChoices":{"allowAssessmentNetwork":false,"allowElevation":true,"allowInstallation":false,"allowPersistentChanges":false,"allowStaleRecovery":false,"verificationOverride":"None"}}'
        Expected = 'REQUEST.NETWORK_MODE_UNSUPPORTED'
    }
    @{
        Name = 'local-only-network-conflict'
        Json = '{"contractVersion":"1.0.0","profile":"ComprehensiveLocalAssessment","outputDestination":"./WIN-PCInfo-Results","networkBehavior":"LocalOnly","updateChoice":"NoUpdateCheck","diagnosticLevel":"Standard","automationChoices":{"allowAssessmentNetwork":true,"allowElevation":true,"allowInstallation":false,"allowPersistentChanges":false,"allowStaleRecovery":false,"verificationOverride":"None"}}'
        Expected = 'REQUEST.NETWORK_CONFLICT'
    }
    @{
        Name = 'connectivity-network-conflict'
        Json = '{"contractVersion":"1.0.0","profile":"ComprehensiveLocalAssessment","outputDestination":"./WIN-PCInfo-Results","networkBehavior":"MicrosoftConnectivityEnabled","updateChoice":"NoUpdateCheck","diagnosticLevel":"Standard","automationChoices":{"allowAssessmentNetwork":false,"allowElevation":true,"allowInstallation":false,"allowPersistentChanges":false,"allowStaleRecovery":false,"verificationOverride":"None"}}'
        Expected = 'REQUEST.NETWORK_CONFLICT'
    }
    @{
        Name = 'run-anyway-override'
        Json = '{"contractVersion":"1.0.0","profile":"ComprehensiveLocalAssessment","outputDestination":"./WIN-PCInfo-Results","networkBehavior":"LocalOnly","updateChoice":"NoUpdateCheck","diagnosticLevel":"Standard","automationChoices":{"allowAssessmentNetwork":false,"allowElevation":true,"allowInstallation":false,"allowPersistentChanges":false,"allowStaleRecovery":false,"verificationOverride":"RunAnyway"}}'
        Expected = 'REQUEST.VERIFICATION_OVERRIDE_UNSUPPORTED'
    }
    @{
        Name = 'missing-elevation-authority'
        Json = '{"contractVersion":"1.0.0","profile":"ComprehensiveLocalAssessment","outputDestination":"./WIN-PCInfo-Results","networkBehavior":"LocalOnly","updateChoice":"NoUpdateCheck","diagnosticLevel":"Standard","automationChoices":{"allowAssessmentNetwork":false,"allowElevation":false,"allowInstallation":false,"allowPersistentChanges":false,"allowStaleRecovery":false,"verificationOverride":"None"}}'
        Expected = 'REQUEST.AUTHORITY_CONFLICT'
    }
    @{
        Name = 'installation-authority-expansion'
        Json = '{"contractVersion":"1.0.0","profile":"ComprehensiveLocalAssessment","outputDestination":"./WIN-PCInfo-Results","networkBehavior":"LocalOnly","updateChoice":"NoUpdateCheck","diagnosticLevel":"Standard","automationChoices":{"allowAssessmentNetwork":false,"allowElevation":true,"allowInstallation":true,"allowPersistentChanges":false,"allowStaleRecovery":false,"verificationOverride":"None"}}'
        Expected = 'REQUEST.AUTHORITY_CONFLICT'
    }
    @{
        Name = 'wrong-field-type'
        Json = '{"contractVersion":"1.0.0","profile":"ComprehensiveLocalAssessment","outputDestination":42,"networkBehavior":"LocalOnly","updateChoice":"NoUpdateCheck","diagnosticLevel":"Standard","automationChoices":{"allowAssessmentNetwork":false,"allowElevation":true,"allowInstallation":false,"allowPersistentChanges":false,"allowStaleRecovery":false,"verificationOverride":"None"}}'
        Expected = 'REQUEST.FIELD_TYPE_INVALID'
    }
)

foreach ($case in $cases) {
    $requestPath = Join-Path $fixtureDirectory "$($case.Name).json"
    [System.IO.File]::WriteAllText($requestPath, $case.Json, [System.Text.UTF8Encoding]::new($false))
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
