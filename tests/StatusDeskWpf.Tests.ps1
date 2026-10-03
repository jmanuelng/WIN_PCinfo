[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')
Assert-QualificationCleanupReady
Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-STA','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-Wpf')
if ($LASTEXITCODE -ne 0) { throw 'The controlled generated WPF approval/report path failed.' }
