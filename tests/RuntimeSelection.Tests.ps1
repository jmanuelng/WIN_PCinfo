[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

# Inventory is an OS boundary. Repeated application matches must still reach
# the generated application through one literal executable, without profiles.
$script:installedHost = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
function Get-Command {
    param($Name, $CommandType, $ErrorAction, [switch] $All)
    if ($Name -eq 'pwsh') {
        [pscustomobject]@{ Source = (Join-Path $repositoryRoot '.test-output/missing-host/pwsh.exe') }
        [pscustomobject]@{ Source = $script:installedHost }
        [pscustomobject]@{ Source = $script:installedHost }
    }
    else { Microsoft.PowerShell.Core\Get-Command @PSBoundParameters }
}
try {
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation', '-RequestPath', (Join-Path $PSScriptRoot 'fixtures/automation-request.json'),
        '-PreparationFixturePath', (Join-Path $PSScriptRoot 'fixtures/preparation-ready.json')
    )
    Assert-Equal 20 $result.ExitCode 'multiple inventory entries must reach the application decline'
    Assert-Equal 'PREPARATION.DECLINED' $result.Records[-1].reasonCode 'the application actually executes'
    Assert-Equal $true $result.Records[-1].runtime.eligible 'the installed host passes live safety probes'
    Assert-Equal $false $result.Records[-1].collectionStarted 'this controlled launch cannot collect'
}
finally { Remove-Item Function:\Get-Command }

Write-Output 'PASS: multiple host matches reach generated application execution.'
