Set-StrictMode -Version Latest

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
        [Parameter()] [string] $PowerShellPath = (Get-Command pwsh -CommandType Application).Source,
        [Parameter()] [string] $WorkingDirectory = (Get-Location).Path
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PowerShellPath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
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
