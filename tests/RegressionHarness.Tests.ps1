[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$root = Join-Path (Split-Path $PSScriptRoot) ('.test-output/harness-' + [guid]::NewGuid().ToString('N'))
try {
    $testDirectory = Join-Path $root 'tests'
    $null = [IO.Directory]::CreateDirectory($testDirectory)
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Run-Tests.ps1') -Destination $testDirectory
    [IO.File]::WriteAllText((Join-Path $testDirectory 'A.Tests.ps1'), "throw 'Synthetic expected failure'")
    [IO.File]::WriteAllText((Join-Path $testDirectory 'B.Tests.ps1'), "Write-Output 'SYNTHETIC_SECOND_FILE_EXECUTED'")
    $output = & (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -File (Join-Path $testDirectory 'Run-Tests.ps1') 2>&1
    $exitCode = $LASTEXITCODE
    Assert-Equal $true ($exitCode -ne 0) 'a failed test file keeps the complete gate failed'
    Assert-Equal $true (($output -join "`n").Contains('SYNTHETIC_SECOND_FILE_EXECUTED')) 'a failing file cannot exclude subsequent test files'
    $summaryFiles = @(Get-ChildItem -LiteralPath (Join-Path $root '.test-output') -Filter suite-summary.json -Recurse)
    Assert-Equal 1 $summaryFiles.Count 'one gate retains one result inventory'
    $summary = Get-Content -LiteralPath $summaryFiles[0].FullName -Raw | ConvertFrom-Json
    Assert-Equal 'Fail' $summary.results[0].result 'the first failure survives in evidence'
    Assert-Equal 'Pass' $summary.results[1].result 'the subsequent executed file is independently recorded'

    $samplerPath = Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'
    $samplerAst = [Management.Automation.Language.Parser]::ParseFile($samplerPath, [ref]$null, [ref]$null)
    $sampler = $samplerAst.Find({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Measure-QualificationWorkload'
    }, $true)
    . ([scriptblock]::Create($sampler.Extent.Text))
    $testRoot = $root
    $quality = [ordered]@{ sampledPrivateBytes=0L; sampledWorkingSetBytes=0L; sampledWorkspaceBytes=42L; workspaceSamplingLosses=0L }
    function Get-ChildItem { param($LiteralPath, [switch]$File, [switch]$Recurse) throw $samplerFault }
    foreach ($samplerFault in @(
        [IO.DirectoryNotFoundException]::new('Synthetic owned directory removal'),
        [IO.FileNotFoundException]::new('Synthetic owned file removal'),
        [Management.Automation.ItemNotFoundException]::new('Synthetic owned item removal')
    )) {
        $previousLosses = $quality.workspaceSamplingLosses
        Measure-QualificationWorkload
        Assert-Equal ($previousLosses + 1) $quality.workspaceSamplingLosses 'owned path removal is counted as a lost sample'
        Assert-Equal 42L $quality.sampledWorkspaceBytes 'a lost sample preserves the previous observed maximum'
    }
    $samplerFault = [UnauthorizedAccessException]::new('Synthetic unexpected access denial')
    $denialPropagated = $false
    try { Measure-QualificationWorkload }
    catch [UnauthorizedAccessException] { $denialPropagated = $true }
    Assert-Equal $true $denialPropagated 'unexpected sampler errors still fail the test'
    Assert-Equal 3L $quality.workspaceSamplingLosses 'access denial is not relabeled as owned cleanup'
}
finally {
    $resolved = [IO.Path]::GetFullPath($root)
    $parent = [IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot) '.test-output'))
    if ([IO.Path]::GetDirectoryName($resolved) -ne $parent) { throw 'Harness cleanup escaped its owned parent.' }
    if ([IO.Directory]::Exists($resolved)) { [IO.Directory]::Delete($resolved, $true) }
}
Write-Output 'PASS: full gate retains failure and executes the next file.'
