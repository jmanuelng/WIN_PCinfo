Set-StrictMode -Version Latest

# A redirected Windows PowerShell child may inherit PowerShell 7's module path.
# Load the bootstrap's own built-ins from literal manifests, never ambient
# PSModulePath. The installed Windows bootstrap remains the trust anchor.
foreach ($moduleName in @('Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Utility')) {
    $manifest = Join-Path $PSHOME ('Modules/' + $moduleName + '/' + $moduleName + '.psd1')
    $null = Microsoft.PowerShell.Core\Import-Module -Name $manifest -ErrorAction Stop
}

function Get-WinPCInfoRuntimeCandidates {
    # Discovery order is PATH applications, then documented installation roots.
    # A discovered name grants no trust; every candidate must pass the probe.
    foreach ($command in @(Get-Command -Name pwsh -CommandType Application -All -ErrorAction SilentlyContinue)) {
        if ($command.Source) { [string] $command.Source }
    }
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($root) { Join-Path $root 'PowerShell\7\pwsh.exe' }
    }
}

function New-WinPCInfoHostProcess {
    param([string] $Executable, [string[]] $Arguments)
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $info.StandardErrorEncoding = New-Object System.Text.UTF8Encoding($false)
    # Windows PowerShell 5.1 lacks ArgumentList. Quote literal argv using the
    # Windows backslash/quote rules; never invoke cmd or interpolate a command.
    $info.Arguments = (@($Arguments | ForEach-Object {
        '"' + (($_ -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
    }) -join ' ')
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    $process
}

function Invoke-WinPCInfoRuntimeProbeProcess {
    param([string] $Executable, [string] $ApplicationPath)
    $process = $null
    try {
        $process = New-WinPCInfoHostProcess -Executable $Executable -Arguments @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $ApplicationPath, '-Workflow', 'CheckRuntime'
        )
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) {
            $process.Kill()
            $null = $process.WaitForExit(5000)
            throw 'Runtime probe exceeded its deadline.'
        }
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            StandardOutput = $stdout.GetAwaiter().GetResult()
            StandardError = $stderr.GetAwaiter().GetResult()
        }
    }
    finally { if ($null -ne $process) { $process.Dispose() } }
}

function Invoke-WinPCInfoRuntimeProbe {
    param(
        [string] $Executable, [string] $ApplicationPath,
        [scriptblock] $ReadSignature = { param($Path) Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $Path },
        [scriptblock] $RunProbe = ${function:Invoke-WinPCInfoRuntimeProbeProcess}
    )
    $rejected = [pscustomobject]@{ Eligible = $false; ReasonCode = 'RUNTIME.HOST_REJECTED' }
    try {
        if (-not [IO.Path]::IsPathRooted($Executable) -or $Executable.StartsWith('\\') -or
            [IO.Path]::GetFileName($Executable) -ne 'pwsh.exe' -or
            -not [IO.File]::Exists($Executable)) {
            return [pscustomobject]@{ Eligible = $false; ReasonCode = 'RUNTIME.HOST_MISSING' }
        }
        # Verify executable provenance before even a diagnostic probe. The
        # trust anchor is Windows Authenticode and the installed bootstrap.
        $signature = & $ReadSignature $Executable
        if ([string] $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
            $signature.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') { return $rejected }
        $probeResult = & $RunProbe $Executable $ApplicationPath
        $output = [string] $probeResult.StandardOutput
        $errorOutput = [string] $probeResult.StandardError
        if ($output.Length -gt 8192 -or $errorOutput.Length -gt 8192) { return $rejected }
        if ($probeResult.ExitCode -eq 1 -and [string]::IsNullOrWhiteSpace($output)) {
            return [pscustomobject]@{ Eligible = $false; ReasonCode = 'LAUNCH.POLICY_REJECTED' }
        }
        $record = $output.Trim() | Microsoft.PowerShell.Utility\ConvertFrom-Json
        if ($probeResult.ExitCode -eq 0 -and $record.recordType -eq 'win-pcinfo.terminal' -and
            $record.reasonCode -eq 'RUNTIME.ELIGIBLE' -and -not $record.collectionStarted -and
            $record.runtime.eligible) {
            return [pscustomobject]@{ Eligible = $true; ReasonCode = 'RUNTIME.ELIGIBLE' }
        }
        if ($record.recordType -eq 'win-pcinfo.terminal' -and -not $record.collectionStarted -and
            [string] $record.reasonCode -match '^RUNTIME\.[A-Z_]{1,64}$') {
            return [pscustomobject]@{ Eligible = $false; ReasonCode = [string] $record.reasonCode }
        }
        return $rejected
    }
    catch { return $rejected }
}

function Resolve-WinPCInfoRuntime {
    param(
        [Parameter(Mandatory)] [string] $ApplicationPath,
        [AllowEmptyCollection()] [string[]] $CandidatePaths = @(Get-WinPCInfoRuntimeCandidates),
        [scriptblock] $Probe = ${function:Invoke-WinPCInfoRuntimeProbe}
    )
    $seen = @{}
    $failureReason = 'RUNTIME.HOST_MISSING'
    foreach ($candidate in $CandidatePaths) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        try { $literalPath = [IO.Path]::GetFullPath($candidate) } catch { continue }
        if ($seen.ContainsKey($literalPath)) { continue }
        $seen[$literalPath] = $true
        $result = & $Probe $literalPath $ApplicationPath
        if ($result.Eligible) { return $literalPath }
        if ($result.PSObject.Properties['ReasonCode'] -and
            ($result.ReasonCode -eq 'LAUNCH.POLICY_REJECTED' -or
                ($failureReason -ne 'LAUNCH.POLICY_REJECTED' -and $result.ReasonCode -ne 'RUNTIME.HOST_MISSING' -and
                    [string] $result.ReasonCode -match '^RUNTIME\.[A-Z_]{1,64}$'))) {
            $failureReason = $result.ReasonCode
        }
    }
    $exception = [InvalidOperationException]::new($failureReason + ': Verify the application and installed Microsoft stable PowerShell 7.6 or later 7.x; retry under existing policy. https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows')
    $exception.Data['ReasonCode'] = $failureReason
    throw $exception
}
