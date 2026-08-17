[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

function Get-Sha256Hex {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Invoke-WindowsPowerShellFile {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [Parameter()] [hashtable] $Environment
    )

    $windowsPowerShell = Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $windowsPowerShell
    $startInfo.WorkingDirectory = Split-Path -Parent $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    if ($PSBoundParameters.ContainsKey('Environment')) {
        $startInfo.Environment.Clear()
        foreach ($key in $Environment.Keys) {
            $startInfo.Environment[$key] = [string] $Environment[$key]
        }
    }
    foreach ($argument in @('-NoLogo', '-NoProfile', '-File', $FilePath) + $Arguments) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        $null = $process.Start()
        $standardOutput = $process.StandardOutput.ReadToEnd()
        $standardError = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        $records = @(
            $standardOutput -split "`r?`n" | Where-Object { $_ } | ForEach-Object {
                $_ | ConvertFrom-Json -Depth 20
            }
        )
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            Records = $records
            StandardOutput = $standardOutput
            StandardError = $standardError
        }
    }
    finally {
        $process.Dispose()
    }
}

$workRoot = Join-Path $repositoryRoot '.test-output/portable-distribution-application'
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $workRoot -Force

$appPath = Join-Path $workRoot 'WIN-PCInfo.ps1'
$build = & (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $appPath
$policy = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-portable-distribution.json'
) -Raw | ConvertFrom-Json -Depth 20

$extractA = Join-Path $workRoot 'extract-a'
$extractB = Join-Path $workRoot 'extract-b'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipPath = Join-Path $workRoot ([string] $policy.archiveFileName)
[System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractA)
[System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractB)
$packageA = Join-Path $extractA ([string] $policy.archiveRootName)
$packageB = Join-Path $extractB ([string] $policy.archiveRootName)
$candidateA = Join-Path $packageA 'WIN-PCInfo.ps1'
$candidateB = Join-Path $packageB 'WIN-PCInfo.ps1'

foreach ($pair in @(
    @{ Name = 'extract-a'; Candidate = $candidateA }
    @{ Name = 'extract-b'; Candidate = $candidateB }
)) {
    $verified = Invoke-GeneratedApplication -CandidatePath $pair.Candidate -Arguments @(
        '-Workflow', 'Verify'
    )
    Assert-Equal 0 $verified.ExitCode "$($pair.Name) first-run verification succeeds"
    $record = @($verified.Records | Where-Object recordType -eq 'win-pcinfo.portable-distribution-verification')
    $terminal = @($verified.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $record.Count "$($pair.Name) emits one verification record"
    Assert-Equal 'Verified' $record[0].state "$($pair.Name) reports Verified"
    Assert-Equal $false $record[0].installsRuntime "$($pair.Name) verification does not install a runtime"
    Assert-Equal $build.generatedContentIdentity.sha256 $record[0].unsignedGeneratedContentIdentity `
        "$($pair.Name) verification restates the generated-content identity"
    Assert-Equal $false ($record[0].PSObject.Properties.Name -contains 'packagePath') `
        "$($pair.Name) verification does not expose a local package path"
    Assert-Equal 1 $terminal.Count "$($pair.Name) verification ends with one terminal record"
    Assert-Equal 'Completed' $terminal[0].outcome "$($pair.Name) verification is Completed"
    Assert-Equal 'PACKAGE.VERIFIED' $terminal[0].reasonCode "$($pair.Name) uses the verified reason"

    $help = Invoke-GeneratedApplication -CandidatePath $pair.Candidate -Arguments @(
        '-Workflow', 'Help'
    )
    Assert-Equal 0 $help.ExitCode "$($pair.Name) Help still works after package authentication"
}

$mutations = @(
    @{ Class = 'application'; RelativePath = 'WIN-PCInfo.ps1' }
    @{ Class = 'schema'; RelativePath = 'schemas/assessment-record.schema.json' }
    @{ Class = 'catalog'; RelativePath = 'docs/spec/releases/2.0.0-preview.1-software-recognition-catalog.json' }
    @{ Class = 'definition'; RelativePath = 'docs/spec/releases/2.0.0-preview.1.json' }
    @{ Class = 'documentation'; RelativePath = 'docs/guided-runway.md' }
    @{ Class = 'helper'; RelativePath = 'Start-WIN-PCInfo.ps1' }
    @{ Class = 'manifest'; RelativePath = 'package-manifest.json' }
)
foreach ($mutation in $mutations) {
    $mutationRoot = Join-Path $workRoot "mutate-$($mutation.Class)"
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $mutationRoot)
    $mutatedPackage = Join-Path $mutationRoot ([string] $policy.archiveRootName)
    $target = Join-Path $mutatedPackage (
        ($mutation.RelativePath -split '/') -join [System.IO.Path]::DirectorySeparatorChar
    )
    $original = [System.IO.File]::ReadAllBytes($target)
    if ($mutation.Class -eq 'application') {
        $tampered = [byte[]]::new($original.Length + 1)
        [System.Buffer]::BlockCopy($original, 0, $tampered, 0, $original.Length)
        $tampered[$tampered.Length - 1] = 0x0A
    }
    else {
        $tampered = [byte[]]::new($original.Length)
        [System.Buffer]::BlockCopy($original, 0, $tampered, 0, $original.Length)
        $index = [Math]::Min(32, $tampered.Length - 1)
        $tampered[$index] = [byte] (($tampered[$index] + 1) -band 0xFF)
    }
    [System.IO.File]::WriteAllBytes($target, $tampered)
    $mutatedCandidate = Join-Path $mutatedPackage 'WIN-PCInfo.ps1'
    if ($mutation.Class -eq 'application') {
        $mutatedCandidate = $target
    }

    $verify = Invoke-GeneratedApplication -CandidatePath $mutatedCandidate -Arguments @(
        '-Workflow', 'Verify'
    )
    Assert-Equal 20 $verify.ExitCode "mutating $($mutation.Class) fails first-run verification"
    Assert-Equal 'NotStarted' $verify.Records[-1].outcome `
        "mutating $($mutation.Class) stays NotStarted"
    Assert-Equal 'PREPARATION.INTEGRITY_FAILED' $verify.Records[-1].reasonCode `
        "mutating $($mutation.Class) has no integrity override"
    Assert-Equal $false $verify.Records[-1].collectionStarted `
        "mutating $($mutation.Class) never starts collection"

    $fixture = Invoke-GeneratedApplication -CandidatePath $mutatedCandidate -Arguments @(
        '-Mode', 'Automation',
        '-RequestPath', (Join-Path $PSScriptRoot 'fixtures/automation-request.json'),
        '-AcceptPreparation',
        '-PreparationFixturePath', (Join-Path $PSScriptRoot 'fixtures/preparation-ready.json')
    )
    Assert-Equal 20 $fixture.ExitCode "a preparation fixture cannot override a mutated $($mutation.Class)"
    Assert-Equal 'PREPARATION.INTEGRITY_FAILED' $fixture.Records[-1].reasonCode `
        "fixtures cannot authenticate a mutated $($mutation.Class)"
}

$missingRoot = Join-Path $workRoot 'mutate-missing-schema'
[System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $missingRoot)
$missingPackage = Join-Path $missingRoot ([string] $policy.archiveRootName)
Remove-Item -LiteralPath (Join-Path $missingPackage 'schemas/assessment-record.schema.json') -Force
$missing = Invoke-GeneratedApplication -CandidatePath (Join-Path $missingPackage 'WIN-PCInfo.ps1') `
    -Arguments @('-Workflow', 'Verify')
Assert-Equal 20 $missing.ExitCode 'a missing governing schema fails first-run verification'
Assert-Equal 'PREPARATION.INTEGRITY_FAILED' $missing.Records[-1].reasonCode `
    'a missing governing resource has no integrity override'

$standaloneVerify = Invoke-GeneratedApplication -CandidatePath $appPath -Arguments @(
    '-Workflow', 'Verify'
)
Assert-Equal 20 $standaloneVerify.ExitCode 'Verify on a developer artifact without a package fails closed'
Assert-Equal 'PREPARATION.INTEGRITY_FAILED' $standaloneVerify.Records[-1].reasonCode `
    'a missing package manifest cannot be overridden'

if (-not $IsWindows) {
    Write-Output 'PASS: portable package authentication holds; Windows PowerShell launch skipped.'
    return
}

$windowsPowerShell = Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
$direct = Invoke-GeneratedApplication -CandidatePath $candidateA `
    -PowerShellPath $windowsPowerShell -Arguments @('-Workflow', 'Help')
Assert-Equal 20 $direct.ExitCode 'the generated application still refuses to assess on Windows PowerShell'
Assert-Equal 'RUNTIME.EDITION_UNSUPPORTED' $direct.Records[-1].reasonCode `
    'direct Windows PowerShell invocation of the generated application does not relaunch'
Assert-Equal 'https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows' `
    $direct.Records[-1].guidance.microsoftUrl 'direct Windows PowerShell failure includes official guidance'

$bootstrap = Join-Path $packageA 'Start-WIN-PCInfo.ps1'
$relaunched = Invoke-WindowsPowerShellFile -FilePath $bootstrap -Arguments @('-Workflow', 'Help')
Assert-Equal 0 $relaunched.ExitCode 'the Windows PowerShell helper launches an eligible pwsh host'
$helpRecords = @($relaunched.Records | Where-Object recordType -eq 'win-pcinfo.product-help')
Assert-Equal 1 $helpRecords.Count 'the relaunched host completes Help from the extracted package'

$emptyRoot = Join-Path $workRoot 'no-pwsh'
$null = New-Item -ItemType Directory -Path $emptyRoot -Force
$isolated = Invoke-WindowsPowerShellFile -FilePath $bootstrap -Arguments @('-Workflow', 'Help') `
    -Environment @{
        PATH = (Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0')
        SystemRoot = $env:SystemRoot
        WINDIR = $env:WINDIR
        ProgramFiles = $emptyRoot
        'ProgramFiles(x86)' = $emptyRoot
        LOCALAPPDATA = $emptyRoot
        USERPROFILE = $emptyRoot
        ComSpec = (Join-Path $env:WINDIR 'System32/cmd.exe')
        PATHEXT = '.COM;.EXE;.BAT;.CMD'
    }
Assert-Equal 20 $isolated.ExitCode 'a missing eligible host ends before collection'
Assert-Equal 'RUNTIME.HOST_MISSING' $isolated.Records[-1].reasonCode `
    'the helper reports the stable missing-host reason'
Assert-Equal 'https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows' `
    $isolated.Records[-1].guidance.microsoftUrl 'the helper repeats official Microsoft installation guidance'
Assert-Equal $false $isolated.Records[-1].collectionStarted 'the helper never starts collection'

Write-Output 'PASS: extracted portable package authenticates resources and launches through eligible and ineligible hosts.'
