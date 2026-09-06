[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
foreach ($json in @('{"kind":"SystemActivated","workerProcessId":1,"workerProcessId":2}',
    '{"kind":"PlanResult","operations":[{"state":"Complete","state":"Failed"}]}')) {
    $stream=[IO.MemoryStream]::new()
    try {
        Write-BoundedCollectionChannelFrame -Stream $stream -Json $json -MaximumBytes 8192 -CancellationToken ([Threading.CancellationToken]::None)
        $stream.Position=0; $rejected=$false
        try { $null=Read-BoundedCollectionChannelFrame -Stream $stream -MaximumBytes 8192 -CancellationToken ([Threading.CancellationToken]::None) } catch { $rejected=$true }
        Assert-Equal $true $rejected 'duplicate identity or nested result properties fail at the actual framed reader'
    } finally { $stream.Dispose() }
}
foreach ($bytes in @(
    [BitConverter]::GetBytes([int]0), [BitConverter]::GetBytes([int]-1), [BitConverter]::GetBytes([int]8193),
    ([BitConverter]::GetBytes([int]8) + [Text.Encoding]::UTF8.GetBytes('{}')),
    ([BitConverter]::GetBytes([int]2) + [byte[]]@(0xc0,0xaf))
)) {
    $stream=[IO.MemoryStream]::new([byte[]]$bytes)
    try {
        $rejected=$false
        try { $null=Read-BoundedCollectionChannelFrame -Stream $stream -MaximumBytes 8192 -CancellationToken ([Threading.CancellationToken]::None) } catch { $rejected=$true }
        Assert-Equal $true $rejected 'invalid length, incomplete frame and invalid UTF-8 cannot enter a collector result'
    } finally { $stream.Dispose() }
}
Write-Output 'PASS: ambiguous broker frames cannot collapse into accepted identity or evidence.'
