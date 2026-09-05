[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
foreach ($stage in @('Identity','Resource')) {
    & (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') ('-CancelAfter' + $stage)
    if ($LASTEXITCODE -ne 0) { throw "The controlled cancellation after $stage failed." }
}
