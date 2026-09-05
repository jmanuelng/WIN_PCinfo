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

function Invoke-WinPCInfoRuntimeProbe {
    param([string] $Executable, [string] $ApplicationPath)
    $rejected = [pscustomobject]@{ Eligible = $false; ReasonCode = 'RUNTIME.HOST_REJECTED' }
    $process = $null
    try {
        if (-not [IO.Path]::IsPathRooted($Executable) -or $Executable.StartsWith('\\') -or
            [IO.Path]::GetFileName($Executable) -ne 'pwsh.exe' -or
            -not [IO.File]::Exists($Executable)) { return $rejected }
        # Verify executable provenance before even a diagnostic probe. The
        # trust anchor is Windows Authenticode and the installed bootstrap.
        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $Executable
        if ([string] $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
            $signature.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') { return $rejected }
        $process = New-WinPCInfoHostProcess -Executable $Executable -Arguments @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $ApplicationPath, '-Workflow', 'CheckRuntime'
        )
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) {
            $process.Kill()
            $null = $process.WaitForExit(5000)
            return $rejected
        }
        $output = $stdout.GetAwaiter().GetResult()
        $errorOutput = $stderr.GetAwaiter().GetResult()
        if ($output.Length -gt 8192 -or $errorOutput.Length -gt 8192) { return $rejected }
        $record = $output.Trim() | Microsoft.PowerShell.Utility\ConvertFrom-Json
        if ($process.ExitCode -eq 0 -and $record.recordType -eq 'win-pcinfo.terminal' -and
            $record.reasonCode -eq 'RUNTIME.ELIGIBLE' -and -not $record.collectionStarted -and
            $record.runtime.eligible) {
            return [pscustomobject]@{ Eligible = $true; ReasonCode = 'RUNTIME.ELIGIBLE' }
        }
        return $rejected
    }
    catch { return $rejected }
    finally { if ($null -ne $process) { $process.Dispose() } }
}

function Resolve-WinPCInfoRuntime {
    param(
        [Parameter(Mandatory)] [string] $ApplicationPath,
        [AllowEmptyCollection()] [string[]] $CandidatePaths = @(Get-WinPCInfoRuntimeCandidates),
        [scriptblock] $Probe = ${function:Invoke-WinPCInfoRuntimeProbe}
    )
    $seen = @{}
    foreach ($candidate in $CandidatePaths) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        try { $literalPath = [IO.Path]::GetFullPath($candidate) } catch { continue }
        if ($seen.ContainsKey($literalPath)) { continue }
        $seen[$literalPath] = $true
        $result = & $Probe $literalPath $ApplicationPath
        if ($result.Eligible) { return $literalPath }
    }
    throw 'RUNTIME.HOST_MISSING: Select a verified Microsoft stable PowerShell 7.6 or later 7.x installation and retry. https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows'
}
