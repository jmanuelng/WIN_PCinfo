[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
& (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -HoldRunLock
if ($LASTEXITCODE -ne 0) { throw 'The ordinary generated assessment scheduler did not enforce the Active Run Lock.' }
Write-Output 'PASS: the generated Status desk scheduler refuses concurrent collection.'
