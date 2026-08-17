[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

function Assert-NoDiscoveryLeak {
    param(
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)] [string] $Because
    )

    $helpRecords = @($Result.Records | Where-Object recordType -eq 'win-pcinfo.product-help')
    Assert-Equal 0 $helpRecords.Count "$Because does not emit Help or About"
    $leaks = @(
        'security/advisories'
        'CONTRIBUTING.md'
        'please send feedback'
        'was this helpful'
        'rate this assessment'
        'post-run validation'
    )
    foreach ($leak in $leaks) {
        Assert-Equal $false ($Result.StandardOutput -match [regex]::Escape($leak)) `
            "$Because does not leak '$leak'"
    }
}

foreach ($surface in @('Help', 'About')) {
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Workflow', $surface
    )
    Assert-Equal 0 $result.ExitCode "unsigned local $surface discovery completes"
    $help = @($result.Records | Where-Object recordType -eq 'win-pcinfo.product-help')
    $terminal = @($result.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $help.Count "$surface emits one product-help record"
    Assert-Equal 1 $terminal.Count "$surface emits one terminal record"
    Assert-Equal $surface $help[0].surface "generated $surface identifies the opened surface"
    Assert-Equal $false $help[0].collectionStarted "generated $surface does not collect"
    Assert-Equal $false $help[0].feedbackPrompted "generated $surface does not prompt"
    Assert-Equal $false $help[0].networkRequested "generated $surface stays offline"
    Assert-Equal 'https://github.com/jmanuelng/WIN_PCinfo' $help[0].discovery.repository `
        "generated $surface exposes the repository"
    Assert-Equal 'https://github.com/jmanuelng/WIN_PCinfo/issues' $help[0].discovery.feedback `
        "generated $surface exposes feedback"
    Assert-Equal 'https://github.com/jmanuelng/WIN_PCinfo/blob/main/CONTRIBUTING.md' `
        $help[0].discovery.contribution "generated $surface exposes contribution"
    Assert-Equal 'https://github.com/jmanuelng/WIN_PCinfo/security/advisories/new' `
        $help[0].discovery.vulnerabilityReporting "generated $surface exposes private reporting"
    Assert-Equal 'Completed' $terminal[0].outcome "generated $surface ends Completed"
    Assert-Equal 'HELP.DISCOVERY_COMPLETE' $terminal[0].reasonCode `
        "generated $surface uses the discovery reason"
    Assert-Equal $false $terminal[0].collectionStarted "generated $surface terminal stays non-collecting"
    if ($result.StandardError) { throw "Generated $surface wrote stderr: $($result.StandardError)" }
}

$declined = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
    '-Mode', 'Automation',
    '-RequestPath', $requestPath
)
Assert-NoDiscoveryLeak -Result $declined -Because 'an ordinary declined assessment'

$fixtureRun = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
    '-Mode', 'Automation',
    '-RequestPath', $requestPath,
    '-AcceptPreparation',
    '-PreparationFixturePath', $preparationPath,
    '-MicrosoftConnectivityFixturePath',
    (Join-Path $PSScriptRoot 'fixtures/microsoft-connectivity/local-only.json')
)
Assert-NoDiscoveryLeak -Result $fixtureRun -Because 'a synthetic full-profile assessment'

Write-Output 'PASS: generated Help and About are passive, and assessment runs never prompt for feedback.'
