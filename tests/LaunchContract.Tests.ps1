[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Equal {
    param(
        [Parameter(Mandatory)] $Expected,
        [Parameter(Mandatory)] $Actual,
        [Parameter(Mandatory)] [string] $Because
    )

    if ($Expected -ne $Actual) {
        throw "Expected '$Expected' but received '$Actual': $Because"
    }
}

function Invoke-GeneratedApplication {
    param([Parameter(Mandatory)] [string[]] $Arguments)

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command pwsh -CommandType Application).Source
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    foreach ($argument in @('-NoLogo', '-NoProfile', '-File', $script:CandidatePath) + $Arguments) {
        $null = $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $null = $process.Start()
    $standardOutput = $process.StandardOutput.ReadToEnd()
    $standardError = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    $records = @($standardOutput -split "`r?`n" | Where-Object { $_ } | ForEach-Object {
        $_ | ConvertFrom-Json -Depth 20
    })

    [pscustomobject]@{
        ExitCode = $process.ExitCode
        Records = $records
        StandardError = $standardError
    }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$script:CandidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $script:CandidatePath | Out-Null

$guided = Invoke-GeneratedApplication -Arguments @('-Mode', 'Guided')
$automation = Invoke-GeneratedApplication -Arguments @('-Mode', 'Automation', '-RequestPath', $requestPath)

$guidedTerminal = $guided.Records[-1]
$automationTerminal = $automation.Records[-1]

Assert-Equal 20 $guided.ExitCode 'the tracer bullet must not claim that collection completed'
Assert-Equal $guided.ExitCode $automation.ExitCode 'both entry adapters use one exit contract'
Assert-Equal 'win-pcinfo.terminal' $guidedTerminal.recordType 'the generated application emits the public terminal contract'
Assert-Equal $guidedTerminal.contractVersion $automationTerminal.contractVersion 'both entry adapters use one contract version'
Assert-Equal $guidedTerminal.outcome $automationTerminal.outcome 'both entry adapters use one terminal outcome'
Assert-Equal $guidedTerminal.reasonCode $automationTerminal.reasonCode 'both entry adapters reach the same engine boundary'
Assert-Equal $guidedTerminal.requestDigest $automationTerminal.requestDigest 'equivalent guided and automation requests normalize identically'

Write-Output 'PASS: generated guided and automation launches share request and terminal contracts.'
