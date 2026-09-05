[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'build/Start-WIN-PCInfo.ps1')
$application = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $application | Out-Null
$hostPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$work = Join-Path $repositoryRoot ('.test-output/runtime-inventory-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work
$syntheticHost = Join-Path $work 'pwsh.exe'
[IO.File]::WriteAllText($syntheticHost, 'Inert synthetic inventory entry. Never executable.')
$fixture = Join-Path $work 'runtime.json'
$facts = [ordered]@{
    hostPresent = $true; psEdition = 'Core'; version = '7.7.0-preview.1'; prereleaseLabel = 'preview.1'
    architecture = 'X64'; requiredCommands = $true; validatorProvenance = $true
    encoding = $true; cryptography = $true; moduleLoading = $true; processControl = $true
}
[IO.File]::WriteAllText($fixture, ($facts | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
$script:probeExecution = {
    param($Executable, $ApplicationPath)
    # The OS process adapter executes the real generated app against a synthetic
    # runtime description, and presents its actual terminal to candidate probing.
    $response = Invoke-GeneratedApplication -PowerShellPath $hostPath -CandidatePath $ApplicationPath -Arguments @(
        '-Mode', 'Automation', '-RequestPath', (Join-Path $PSScriptRoot 'fixtures/automation-request.json'),
        '-RuntimeFixturePath', $fixture
    )
    [pscustomobject]@{
        ExitCode = $response.ExitCode; StandardError = $response.StandardError
        StandardOutput = ($response.Records[-1] | ConvertTo-Json -Depth 8 -Compress)
    }
}
$probeAdapter = {
    param($Executable, $ApplicationPath)
    if ($Executable -eq $hostPath) { return (Invoke-WinPCInfoRuntimeProbe -Executable $Executable -ApplicationPath $ApplicationPath) }
    Invoke-WinPCInfoRuntimeProbe -Executable $Executable -ApplicationPath $ApplicationPath `
        -ReadSignature $script:hostSignature -RunProbe $script:probeExecution
}
$script:hostSignature = { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = @{ Subject = 'CN=Microsoft Corporation, synthetic' } } }
foreach ($case in @(
    @{ Change = @{ version = '7.7.0-preview.1'; prereleaseLabel = 'preview.1' }; Reason = 'RUNTIME.PRERELEASE_UNSUPPORTED' }
    @{ Change = @{ version = '7.5.9' }; Reason = 'RUNTIME.VERSION_TOO_OLD' }
    @{ Change = @{ version = '8.0.0' }; Reason = 'RUNTIME.MAJOR_UNSUPPORTED' }
    @{ Change = @{ psEdition = 'Desktop' }; Reason = 'RUNTIME.EDITION_UNSUPPORTED' }
    @{ Change = @{ architecture = 'S390x' }; Reason = 'RUNTIME.ARCHITECTURE_UNSUPPORTED' }
    @{ Change = @{ validatorProvenance = $false }; Reason = 'RUNTIME.VALIDATOR_PROVENANCE_INVALID' }
    @{ Change = @{ encoding = $false }; Reason = 'RUNTIME.ENCODING_INCOMPATIBLE' }
    @{ Change = @{ cryptography = $false }; Reason = 'RUNTIME.CRYPTOGRAPHY_INCOMPATIBLE' }
    @{ Change = @{ moduleLoading = $false }; Reason = 'RUNTIME.MODULE_LOADING_INCOMPATIBLE' }
    @{ Change = @{ processControl = $false }; Reason = 'RUNTIME.PROCESS_CONTROL_INCOMPATIBLE' }
)) {
    $current = [ordered]@{}
    foreach ($key in $facts.Keys) { $current[$key] = $facts[$key] }
    $current.version = '7.6.5'; $current.prereleaseLabel = $null
    foreach ($key in $case.Change.Keys) { $current[$key] = $case.Change[$key] }
    [IO.File]::WriteAllText($fixture, ($current | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui -CandidatePaths @($syntheticHost) `
        -ReadSignature { [pscustomobject]@{ Status = 'Valid' } } -Probe $probeAdapter `
        -Launch { throw 'Rejected inventory must never launch assessment.' }
    Assert-Equal $case.Reason $result.ReasonCode 'the actual generated runtime rejection survives portable selection'
}
$script:hostSignature = { [pscustomobject]@{ Status = 'HashMismatch'; SignerCertificate = $null } }
$result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui -CandidatePaths @($syntheticHost) `
    -ReadSignature { [pscustomobject]@{ Status = 'Valid' } } -Probe $probeAdapter
Assert-Equal 'RUNTIME.HOST_REJECTED' $result.ReasonCode 'executable provenance rejection occurs before its runtime probe'
$script:hostSignature = { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = @{ Subject = 'CN=Microsoft Corporation, synthetic' } } }
$script:probeExecution = { [pscustomobject]@{ ExitCode = 1; StandardOutput = ''; StandardError = 'Synthetic PSSecurityException: UnauthorizedAccess' } }
$result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui -CandidatePaths @($syntheticHost, (Join-Path $work 'absent/pwsh.exe')) `
    -ReadSignature { [pscustomobject]@{ Status = 'Valid' } } -Probe $probeAdapter
Assert-Equal 'LAUNCH.POLICY_REJECTED' $result.ReasonCode 'real probe-process policy rejection stays visible after later candidates'
$result = Invoke-WinPCInfoPortableEntry -ApplicationPath $application -Gui -CandidatePaths @($syntheticHost, $hostPath) `
    -ReadSignature { [pscustomobject]@{ Status = 'Valid' } } -Probe $probeAdapter -Launch {
        param($Executable, $Arguments)
        Invoke-GeneratedApplication -PowerShellPath $Executable -CandidatePath $application -Arguments @('-Workflow', 'CheckRuntime')
    }
Assert-Equal 'RUNTIME.ELIGIBLE' $result.Records[-1].reasonCode 'a later eligible host actually executes the generated application'
Assert-Equal $false $result.Records[-1].collectionStarted 'selection test does not collect'

$ownedRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
if (-not [IO.Path]::GetFullPath($work).StartsWith($ownedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe cleanup target.' }
Remove-Item -LiteralPath $work -Recurse -Force
Write-Output 'PASS: portable inventory selection translates actual generated runtime rejection.'
