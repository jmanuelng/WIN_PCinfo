[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$application = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $application | Out-Null
$extractRoot = Join-Path $repositoryRoot ('.test-output/portable-entry-' + [guid]::NewGuid().ToString('N'))
[IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $repositoryRoot 'artifacts/WIN-PCInfo-2.0.0-preview.1-portable.zip'), $extractRoot)
$packageRoot = Join-Path $extractRoot 'WIN-PCInfo-2.0.0-preview.1'
$application = Join-Path $packageRoot 'WIN-PCInfo.ps1'
. (Join-Path $packageRoot 'Start-WIN-PCInfo.ps1')
$hostPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$validSignature = { param($Path) [pscustomobject]@{ Status = 'Valid' } }
$eligibleProbe = { param($Path, $Application) [pscustomobject]@{ Eligible = $true } }
$launchObservation = {
    param($Executable, $Arguments)
    Assert-Equal $hostPath $Executable 'portable entry chooses one literal executable'
    Assert-Equal '-NoProfile' $Arguments[1] 'GUI launch excludes profiles'
    Assert-Equal '-STA' $Arguments[2] 'GUI launch requests STA'
    Assert-Equal 'Gui' $Arguments[-1] 'double-click dispatches the GUI mode'
    [pscustomobject]@{ ExitCode = 20; StandardOutput = ''; StandardError = ''; ReasonCode = 'GUI.ADAPTER_UNAVAILABLE' }
}
$result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui `
    -CandidatePaths @($hostPath) -ReadSignature $validSignature -Probe $eligibleProbe -Launch $launchObservation
Assert-Equal 20 $result.ExitCode 'unavailable GUI remains a visible NotStarted boundary'
Assert-Equal 'GUI.ADAPTER_UNAVAILABLE' $result.ReasonCode 'the next owning slice is explicit'

$mustNotLaunch = { throw 'Unexpected application launch at a rejected boundary.' }
$originalOutput = [Console]::Out
$capturedOutput = [IO.StringWriter]::new()
try {
    [Console]::SetOut($capturedOutput)
    $terminalExit = Write-WinPCInfoLaunchResult -Gui -ShowGuidance { param($Text) } -Result ([pscustomobject]@{
        ExitCode = 50; ReasonCode = ''; StandardError = ''
        StandardOutput = '{"recordType":"win-pcinfo.terminal","outcome":"CleanupIncomplete","exitCode":50,"reasonCode":"CLEANUP.INCOMPLETE","collectionStarted":true,"cleanup":{"verified":false}}'
    })
}
finally { [Console]::SetOut($originalOutput) }
$preserved = @($capturedOutput.ToString().Trim() -split "`r?`n" | ConvertFrom-Json)
$capturedOutput.Dispose()
Assert-Equal 1 $preserved.Count 'GUI failure must emit exactly one existing terminal'
Assert-Equal 'CleanupIncomplete' $preserved[0].outcome 'GUI guidance cannot rewrite the outcome'
Assert-Equal $true $preserved[0].collectionStarted 'GUI guidance cannot deny prior collection'
Assert-Equal $false $preserved[0].cleanup.verified 'GUI guidance cannot invent cleanup success'
Assert-Equal 50 $terminalExit 'GUI preserves the application exit code'
$result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui `
    -CandidatePaths @($hostPath) -ReadSignature $validSignature `
    -Probe { [pscustomobject]@{ Eligible = $false; ReasonCode = 'LAUNCH.POLICY_REJECTED' } } -Launch $mustNotLaunch
Assert-Equal 'LAUNCH.POLICY_REJECTED' $result.ReasonCode 'policy-blocked runtime probing is not missing installation'
foreach ($case in @(
    @{ Name = 'absent'; Paths = @(); Signature = $validSignature; Reason = 'RUNTIME.HOST_MISSING' }
    @{ Name = 'signature'; Paths = @($hostPath); Signature = { [pscustomobject]@{ Status = 'HashMismatch' } }; Reason = 'LAUNCH.SIGNATURE_INVALID' }
)) {
    $result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui `
        -CandidatePaths $case.Paths -ReadSignature $case.Signature `
        -Probe { [pscustomobject]@{ Eligible = $false } } -Launch $mustNotLaunch
    Assert-Equal 20 $result.ExitCode "$($case.Name) cannot start assessment"
    Assert-Equal $case.Reason $result.ReasonCode "$($case.Name) has visible stable retry guidance"
}
$result = Invoke-WinPCInfoPortableEntry -ApplicationPath (Join-Path $packageRoot 'missing.ps1') `
    -CandidatePaths @() -Launch $mustNotLaunch
Assert-Equal 'LAUNCH.APPLICATION_MISSING' $result.ReasonCode 'missing application is distinct from missing runtime'
$result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui `
    -CandidatePaths @($hostPath) -ReadSignature $validSignature -Probe $eligibleProbe `
    -Launch { throw [System.Security.SecurityException]::new('Synthetic policy rejection') }
Assert-Equal 'LAUNCH.POLICY_REJECTED' $result.ReasonCode 'policy rejection remains visible without bypass'

# Synthetic admission can exercise only a generated validation invocation.
# The real eligible executable and the complete packaged application run here;
# preparation fixtures prevent these tests from authorizing collection.
foreach ($mode in @('Guided', 'Automation')) {
    $arguments = @('-Mode', $mode, '-PreparationFixturePath', (Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'))
    if ($mode -eq 'Automation') { $arguments += @('-RequestPath', (Join-Path $PSScriptRoot 'fixtures/automation-request.json')) }
    $result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -ApplicationArguments $arguments `
        -CandidatePaths @('C:\synthetic\rejected\pwsh.exe', $hostPath, $hostPath) `
        -ReadSignature $validSignature -Probe ${function:Invoke-WinPCInfoRuntimeProbe} -Launch {
            param($Executable, $Arguments)
            Invoke-GeneratedApplication -PowerShellPath $Executable -CandidatePath $Arguments[3] -Arguments $Arguments[4..($Arguments.Count - 1)]
        }
    Assert-Equal 20 $result.ExitCode "$mode preserves generated application exit code"
    Assert-Equal 'PREPARATION.DECLINED' $result.Records[-1].reasonCode "$mode reaches the generated preparation boundary"
    Assert-Equal $true $result.Records[-1].validationFixture "$mode is explicitly synthetic"
    Assert-Equal $false $result.Records[-1].collectionStarted "$mode cannot authorize live collection"
}

$runtimeOnly = Invoke-GeneratedApplication -PowerShellPath $hostPath -CandidatePath $application -Arguments @(
    '-Workflow', 'CheckRuntime', '-RuntimeFixturePath', (Join-Path $packageRoot 'missing-fixture.json'), '-AcceptPreparation'
)
Assert-Equal 0 $runtimeOnly.ExitCode 'runtime probe cannot load a fixture or accept preparation'
Assert-Equal 'RUNTIME.ELIGIBLE' $runtimeOnly.Records[-1].reasonCode 'the generated policy passes on the real installed host'
Assert-Equal $false $runtimeOnly.Records[-1].collectionStarted 'runtime probe has no assessment authority'

$cmdProcess = [Diagnostics.Process]::new()
$cmdProcess.StartInfo = [Diagnostics.ProcessStartInfo]::new()
$cmdProcess.StartInfo.FileName = Join-Path $env:WINDIR 'System32/cmd.exe'
$cmdProcess.StartInfo.Arguments = '/d /c ""' + (Join-Path $packageRoot 'Start-WIN-PCInfo.cmd') + '" -Workflow Help"'
$cmdProcess.StartInfo.UseShellExecute = $false
$cmdProcess.StartInfo.RedirectStandardOutput = $true
$cmdProcess.StartInfo.RedirectStandardError = $true
try {
    $null = $cmdProcess.Start()
    $cmdOut = $cmdProcess.StandardOutput.ReadToEndAsync()
    $cmdError = $cmdProcess.StandardError.ReadToEndAsync()
    $cmdProcess.WaitForExit()
    Assert-Equal '' $cmdError.GetAwaiter().GetResult() 'the generated double-click entry executes without shell errors'
    Assert-Equal 0 $cmdProcess.ExitCode 'explicit passive Help preserves its successful exit through CMD'
    $cmdRecords = @($cmdOut.GetAwaiter().GetResult().Trim() -split "`r?`n" | ConvertFrom-Json)
    Assert-Equal 'HELP.DISCOVERY_COMPLETE' $cmdRecords[-1].reasonCode 'CMD reaches the real generated application'
}
finally { $cmdProcess.Dispose() }

# Remove only this test's newly created extraction, after resolving ownership.
$ownedRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
if (-not [IO.Path]::GetFullPath($extractRoot).StartsWith($ownedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe cleanup target.' }
Remove-Item -LiteralPath $extractRoot -Recurse -Force
Write-Output 'PASS: portable GUI entry selects one host with NoProfile/STA.'
