# Windows PowerShell 5.1 may only locate an eligible PowerShell 7 host or
# publish official retry guidance. The threat is treating Windows PowerShell
# as a second assessment engine: its JSON, validator, and encoding stack is
# not the v2 contract. The mechanism is a host search of PATH and the two
# documented Program Files locations, then a relaunch of WIN-PCInfo.ps1.
# The trust assumption is that the operator already installed pwsh from
# Microsoft. Safe failure is NotStarted with RUNTIME.HOST_MISSING and no
# collection, elevation, download, or execution-policy change.
$ErrorActionPreference = 'Stop'

function Find-WinPCInfoEligibleHost {
    $command = Get-Command -Name pwsh -CommandType Application -ErrorAction SilentlyContinue
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string] $command.Source)) {
        return [string] $command.Source
    }

    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)})
    foreach ($root in $roots) {
        if ([string]::IsNullOrWhiteSpace([string] $root)) { continue }
        $candidate = Join-Path $root 'PowerShell\7\pwsh.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    return $null
}

$pwsh = Find-WinPCInfoEligibleHost
if ([string]::IsNullOrWhiteSpace([string] $pwsh)) {
    $terminalTemplate = '{"recordType":"win-pcinfo.terminal","contractVersion":"1.0.0","outcome":"NotStarted","exitCode":20,"reasonCode":"RUNTIME.HOST_MISSING","phase":"RuntimeCompatibility","collectionStarted":false,"requestDigest":"","validationFixture":false,"cleanup":{"required":false,"verified":true},"guidance":{"microsoftUrl":"https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows","retryStep":"Install or select stable PowerShell 7.6 or later 7.x from Microsoft, then rerun the same WIN-PCInfo command."}}'
    [System.Console]::Out.WriteLine($terminalTemplate)
    exit 20
}

$application = Join-Path $PSScriptRoot 'WIN-PCInfo.ps1'
if (-not (Test-Path -LiteralPath $application -PathType Leaf)) {
    $terminalTemplate = '{"recordType":"win-pcinfo.terminal","contractVersion":"1.0.0","outcome":"NotStarted","exitCode":20,"reasonCode":"RUNTIME.HOST_MISSING","phase":"RuntimeCompatibility","collectionStarted":false,"requestDigest":"","validationFixture":false,"cleanup":{"required":false,"verified":true},"guidance":{"microsoftUrl":"https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows","retryStep":"Install or select stable PowerShell 7.6 or later 7.x from Microsoft, then rerun the same WIN-PCInfo command."}}'
    [System.Console]::Out.WriteLine($terminalTemplate)
    exit 20
}

if ($args.Count -gt 0) {
    & $pwsh -NoLogo -NoProfile -File $application @args
}
else {
    & $pwsh -NoLogo -NoProfile -File $application
}
exit $LASTEXITCODE
