[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Equal {
    param($Expected, $Actual, [string] $Because)
    if ($Expected -ne $Actual) { throw "Expected '$Expected' but received '$Actual': $Because" }
}

function Invoke-InvalidRequest {
    param([string] $CandidatePath, [string] $RequestPath)

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command pwsh -CommandType Application).Source
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @('-NoLogo', '-NoProfile', '-File', $CandidatePath, '-Mode', 'Automation', '-RequestPath', $RequestPath)) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $null = $process.Start()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    [pscustomobject]@{
        ExitCode = $process.ExitCode
        Records = @($stdout -split "`r?`n" | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json -Depth 20 })
        StandardError = $stderr
    }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$fixtureDirectory = Join-Path $repositoryRoot '.test-output/request-validation'
$null = New-Item -ItemType Directory -Path $fixtureDirectory -Force
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$cases = @(
    @{
        Name = 'unknown-security-field'
        Json = '{"contractVersion":"1.0.0","profile":"ComprehensiveLocalAssessment","networkMode":"LocalOnly","acceptPreparation":false,"skipRuntimeCheck":true}'
        Expected = 'REQUEST.UNKNOWN_FIELD'
    }
    @{
        Name = 'unsupported-major'
        Json = '{"contractVersion":"2.0.0","profile":"ComprehensiveLocalAssessment","networkMode":"LocalOnly","acceptPreparation":false}'
        Expected = 'REQUEST.CONTRACT_VERSION_UNSUPPORTED'
    }
    @{
        Name = 'missing-required-field'
        Json = '{"contractVersion":"1.0.0","profile":"ComprehensiveLocalAssessment","networkMode":"LocalOnly"}'
        Expected = 'REQUEST.REQUIRED_FIELD_MISSING'
    }
    @{
        Name = 'unsupported-network-mode'
        Json = '{"contractVersion":"1.0.0","profile":"ComprehensiveLocalAssessment","networkMode":"FullOutbound","acceptPreparation":false}'
        Expected = 'REQUEST.NETWORK_MODE_UNSUPPORTED'
    }
)

foreach ($case in $cases) {
    $requestPath = Join-Path $fixtureDirectory "$($case.Name).json"
    [System.IO.File]::WriteAllText($requestPath, $case.Json, [System.Text.UTF8Encoding]::new($false))
    $result = Invoke-InvalidRequest -CandidatePath $candidatePath -RequestPath $requestPath
    $terminal = $result.Records[-1]

    Assert-Equal 20 $result.ExitCode "$($case.Name) has the stable NotStarted exit"
    Assert-Equal 'NotStarted' $terminal.outcome "$($case.Name) does not begin collection"
    Assert-Equal $case.Expected $terminal.reasonCode "$($case.Name) has a stable request reason"
    Assert-Equal 'RequestValidation' $terminal.phase "$($case.Name) stops at request validation"
    Assert-Equal $false $terminal.collectionStarted "$($case.Name) cannot collect"
}

Write-Output "PASS: generated application rejected $($cases.Count) invalid automation requests through the terminal contract."
