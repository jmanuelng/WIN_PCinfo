Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The build embeds the shared host boundary here, covered by this helper's
# signature and package digest, without loading an unauthenticated sidecar.
# __RUNTIME_HOST_FUNCTIONS__

function Invoke-WinPCInfoApplicationProcess {
    param([string] $Executable, [string[]] $Arguments)
    $process = New-WinPCInfoHostProcess -Executable $Executable -Arguments $Arguments
    $captureOutput = '-STA' -in $Arguments
    if (-not $captureOutput) {
        # Preserve interactive prompts, redirected progress and inherited stdin.
        $process.StartInfo.RedirectStandardOutput = $false
        $process.StartInfo.RedirectStandardError = $false
        $process.StartInfo.StandardOutputEncoding = $null
        $process.StartInfo.StandardErrorEncoding = $null
        $process.StartInfo.CreateNoWindow = $false
    }
    try {
        $null = $process.Start()
        if ($captureOutput) {
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
        }
        $process.WaitForExit()
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            StandardOutput = if ($captureOutput) { $stdout.GetAwaiter().GetResult() } else { '' }
            StandardError = if ($captureOutput) { $stderr.GetAwaiter().GetResult() } else { '' }
            ReasonCode = if ($process.ExitCode -eq 1) { 'LAUNCH.POLICY_REJECTED' } else { '' }
        }
    }
    finally { $process.Dispose() }
}

function Invoke-WinPCInfoPortableEntry {
    param(
        [Parameter(Mandatory)] [string] $ApplicationPath,
        [switch] $Gui,
        [string[]] $ApplicationArguments = @(),
        [AllowEmptyCollection()] [string[]] $CandidatePaths = @(Get-WinPCInfoRuntimeCandidates),
        [scriptblock] $ReadSignature = { param($Path) Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $Path },
        [scriptblock] $Probe = ${function:Invoke-WinPCInfoRuntimeProbe},
        [scriptblock] $Launch = ${function:Invoke-WinPCInfoApplicationProcess}
    )
    $reason = ''
    $executable = $null
    if (-not [IO.File]::Exists($ApplicationPath)) { $reason = 'LAUNCH.APPLICATION_MISSING' }
    else {
        try {
            # An unsigned or altered application must not execute even a probe.
            # Source-only tests inject OS adapters here; the shipped command has
            # no fixture or trust-override argument and never grants authority.
            $signature = & $ReadSignature $ApplicationPath
            $passiveUnsigned = -not $Gui -and $ApplicationArguments.Count -eq 2 -and
                $ApplicationArguments[0] -eq '-Workflow' -and
                $ApplicationArguments[1] -in @('Help', 'About', 'Verify', 'CheckRuntime') -and
                [string] $signature.Status -eq 'NotSigned'
            if ([string] $signature.Status -ne 'Valid' -and -not $passiveUnsigned) {
                $reason = 'LAUNCH.SIGNATURE_INVALID'
            }
        }
        catch { $reason = 'LAUNCH.SIGNATURE_INVALID' }
    }
    if (-not $reason) {
        try { $executable = Resolve-WinPCInfoRuntime -ApplicationPath $ApplicationPath -CandidatePaths $CandidatePaths -Probe $Probe }
        catch {
            $reason = if ($_.Exception.Data['ReasonCode'] -eq 'LAUNCH.POLICY_REJECTED' -or
                [string] $_.Exception.Data['ReasonCode'] -match '^RUNTIME\.[A-Z_]{1,64}$') {
                [string] $_.Exception.Data['ReasonCode']
            } else { 'RUNTIME.HOST_MISSING' }
        }
    }
    if (-not $reason) {
        $launchArguments = @('-NoLogo', '-NoProfile')
        if ($Gui) { $launchArguments += '-STA' }
        $launchArguments += @('-File', $ApplicationPath)
        if ($Gui) { $launchArguments += @('-Mode', 'Gui') }
        else { $launchArguments += $ApplicationArguments }
        try { return (& $Launch $executable $launchArguments) }
        catch { $reason = 'LAUNCH.POLICY_REJECTED' }
    }
    [pscustomobject]@{ ExitCode = 20; ReasonCode = $reason; StandardOutput = ''; StandardError = '' }
}

function Write-WinPCInfoLaunchResult {
    param(
        [Parameter(Mandatory)] $Result,
        [switch] $Gui,
        [scriptblock] $ShowGuidance = {
            param($Text)
            Add-Type -AssemblyName PresentationFramework
            $null = [System.Windows.MessageBox]::Show($Text, 'WIN-PCInfo cannot start')
        }
    )
    if ($result.StandardOutput) { [Console]::Out.Write($result.StandardOutput) }
    if ($result.StandardError) { [Console]::Error.Write($result.StandardError) }
    $hasApplicationTerminal = $false
    if ($result.StandardOutput) {
        try {
            $terminalLine = @($result.StandardOutput.Trim() -split "`r?`n")[-1]
            $terminal = $terminalLine | Microsoft.PowerShell.Utility\ConvertFrom-Json
            if ($terminal.recordType -eq 'win-pcinfo.terminal') {
                $hasApplicationTerminal = $true
                if ($result.ExitCode -ne 0) { $result.ReasonCode = [string] $terminal.reasonCode }
            }
        }
        catch { if ($gui -and $result.ExitCode -ne 0) { $result.ReasonCode = 'LAUNCH.APPLICATION_REJECTED' } }
    }
    if ($result.ReasonCode) {
        $guidance = 'Verify the complete application and its signature, select stable Microsoft PowerShell 7.6 or later 7.x, and retry under your existing policy. Do not change execution policy or unblock files automatically.'
        if (-not $hasApplicationTerminal) {
        $record = [ordered]@{
            recordType = 'win-pcinfo.terminal'; contractVersion = '1.0.0'; outcome = 'NotStarted'
            exitCode = 20; reasonCode = $result.ReasonCode; phase = 'Launch'; collectionStarted = $false
            requestDigest = ''; validationFixture = $false
            cleanup = @{ required = $false; verified = $true }
            guidance = @{
                microsoftUrl = 'https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows'
                retryStep = $guidance
            }
        }
        [Console]::Out.WriteLine(($record | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 5 -Compress))
        }
        if ($gui) {
            try { $null = & $ShowGuidance ($result.ReasonCode + "`n`n" + $guidance) }
            catch { [Console]::Error.WriteLine($guidance) }
        }
        if (-not $hasApplicationTerminal) { return 20 }
    }
    return $result.ExitCode
}

if ($MyInvocation.InvocationName -eq '.') { return }
$gui = $args.Count -eq 0
$result = Invoke-WinPCInfoPortableEntry -ApplicationPath (Join-Path $PSScriptRoot 'WIN-PCInfo.ps1') `
    -Gui:$gui -ApplicationArguments $args
exit (Write-WinPCInfoLaunchResult -Result $result -Gui:$gui)
