[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$testOutput = Join-Path $repositoryRoot '.test-output/runtime-matrix'
$fixtureDirectory = Join-Path $testOutput 'fixtures'
$workingDirectory = Join-Path $testOutput 'work'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$null = New-Item -ItemType Directory -Path $fixtureDirectory -Force
$null = New-Item -ItemType Directory -Path $workingDirectory -Force
$sentinelPath = Join-Path $workingDirectory 'pre-existing-sentinel.txt'
[System.IO.File]::WriteAllText($sentinelPath, 'pre-existing test-owned content', [System.Text.UTF8Encoding]::new($false))

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$eligibleFacts = [ordered]@{
    hostPresent = $true
    psEdition = 'Core'
    version = '7.6.4'
    prereleaseLabel = $null
    architecture = 'X64'
    requiredCommands = $true
    validatorProvenance = $true
    encoding = $true
    cryptography = $true
    moduleLoading = $true
    processControl = $true
}

$matrix = @(
    @{ Name = 'eligible'; Change = @{}; Expected = 'SLICE.COLLECTION_NOT_IMPLEMENTED' }
    @{ Name = 'later-stable-7x'; Change = @{ version = '7.99.0' }; Expected = 'SLICE.COLLECTION_NOT_IMPLEMENTED' }
    @{ Name = 'missing'; Change = @{ hostPresent = $false }; Expected = 'RUNTIME.HOST_MISSING' }
    @{ Name = 'prerelease'; Change = @{ version = '7.7.0-preview.1'; prereleaseLabel = 'preview.1' }; Expected = 'RUNTIME.PRERELEASE_UNSUPPORTED' }
    @{ Name = 'wrong-edition'; Change = @{ psEdition = 'Desktop' }; Expected = 'RUNTIME.EDITION_UNSUPPORTED' }
    @{ Name = 'wrong-major'; Change = @{ version = '8.0.0' }; Expected = 'RUNTIME.MAJOR_UNSUPPORTED' }
    @{ Name = 'too-old'; Change = @{ version = '7.5.9' }; Expected = 'RUNTIME.VERSION_TOO_OLD' }
    @{ Name = 'wrong-architecture'; Change = @{ architecture = 'S390x' }; Expected = 'RUNTIME.ARCHITECTURE_UNSUPPORTED' }
    @{ Name = 'commands'; Change = @{ requiredCommands = $false }; Expected = 'RUNTIME.REQUIRED_COMMAND_MISSING' }
    @{ Name = 'validator'; Change = @{ validatorProvenance = $false }; Expected = 'RUNTIME.VALIDATOR_PROVENANCE_INVALID' }
    @{ Name = 'encoding'; Change = @{ encoding = $false }; Expected = 'RUNTIME.ENCODING_INCOMPATIBLE' }
    @{ Name = 'cryptography'; Change = @{ cryptography = $false }; Expected = 'RUNTIME.CRYPTOGRAPHY_INCOMPATIBLE' }
    @{ Name = 'module-loading'; Change = @{ moduleLoading = $false }; Expected = 'RUNTIME.MODULE_LOADING_INCOMPATIBLE' }
    @{ Name = 'behavior-incompatible'; Change = @{ processControl = $false }; Expected = 'RUNTIME.PROCESS_CONTROL_INCOMPATIBLE' }
)

foreach ($case in $matrix) {
    $facts = [ordered]@{}
    foreach ($key in $eligibleFacts.Keys) { $facts[$key] = $eligibleFacts[$key] }
    foreach ($key in $case.Change.Keys) { $facts[$key] = $case.Change[$key] }

    $fixturePath = Join-Path $fixtureDirectory "$($case.Name).json"
    [System.IO.File]::WriteAllText(
        $fixturePath,
        ($facts | ConvertTo-Json -Depth 5),
        [System.Text.UTF8Encoding]::new($false)
    )

    $before = @(Get-ChildItem -LiteralPath $workingDirectory -Force)
    $sentinelDigestBefore = (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath -WorkingDirectory $workingDirectory `
        -Arguments @(
            '-Mode', 'Automation', '-RequestPath', $requestPath,
            '-RuntimeFixturePath', $fixturePath
        )
    $after = @(Get-ChildItem -LiteralPath $workingDirectory -Force)
    $sentinelDigestAfter = (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash
    $terminal = $result.Records[-1]

    Assert-Equal 20 $result.ExitCode "$($case.Name) must use the NotStarted exit code"
    Assert-Equal 'NotStarted' $terminal.outcome "$($case.Name) must stop before collection"
    Assert-Equal $case.Expected $terminal.reasonCode "$($case.Name) must have a stable reason"
    Assert-Equal $false $terminal.collectionStarted "$($case.Name) must not collect"
    Assert-Equal $true $terminal.validationFixture "$($case.Name) cannot authorize a real run"
    Assert-Equal $before.Count $after.Count "$($case.Name) must not mutate its working directory"
    Assert-Equal $sentinelDigestBefore $sentinelDigestAfter "$($case.Name) must preserve pre-existing working files"

    if ($case.Expected -like 'RUNTIME.*') {
        Assert-Equal 'https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows' `
            $terminal.guidance.microsoftUrl "$($case.Name) provides official Microsoft guidance"
        if ($terminal.guidance.retryStep -notmatch 'PowerShell 7\.6') {
            throw "$($case.Name) must provide a clear PowerShell 7.6 retry step."
        }
    }
}

Write-Output "PASS: generated application enforced $($matrix.Count) runtime fixtures without collection or working-directory mutation."
