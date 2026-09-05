Set-StrictMode -Version Latest
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'build/RuntimeHost.ps1')

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
    param(
        [Parameter(Mandatory)] [string] $CandidatePath,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [Parameter()] [AllowEmptyString()] [string] $StandardInput,
        [Parameter()] [string] $PowerShellPath,
        [Parameter()] [string] $WorkingDirectory = (Get-Location).Path
    )

    if ([string]::IsNullOrWhiteSpace($PowerShellPath)) {
        # Reuse selection within this test file only for identical application
        # bytes. Every application invocation still runs its own safety checks.
        $candidateIdentity = (Get-FileHash -LiteralPath $CandidatePath -Algorithm SHA256).Hash
        $cache = Get-Variable -Name WinPCInfoTestHostCache -Scope Script -ErrorAction SilentlyContinue
        if ($null -ne $cache -and $cache.Value.Identity -eq $candidateIdentity) {
            $PowerShellPath = $cache.Value.Executable
        }
        else {
            $PowerShellPath = Resolve-WinPCInfoRuntime -ApplicationPath $CandidatePath
            $script:WinPCInfoTestHostCache = @{ Identity = $candidateIdentity; Executable = $PowerShellPath }
        }
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PowerShellPath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $startInfo.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    $startInfo.RedirectStandardInput = $PSBoundParameters.ContainsKey('StandardInput')
    foreach ($argument in @('-NoLogo', '-NoProfile', '-File', $CandidatePath) + $Arguments) {
        $null = $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        $null = $process.Start()
        if ($PSBoundParameters.ContainsKey('StandardInput')) {
            $process.StandardInput.Write($StandardInput)
            $process.StandardInput.Close()
        }
        $standardOutput = $process.StandardOutput.ReadToEnd()
        $standardError = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            Records = @($standardOutput -split "`r?`n" | Where-Object { $_ } | ForEach-Object {
                $_ | ConvertFrom-Json -Depth 20
            })
            StandardOutput = $standardOutput
            StandardError = $standardError
        }
    }
    finally {
        $process.Dispose()
    }
}
