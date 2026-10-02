[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')
Assert-QualificationCleanupReady
foreach ($stage in @('Identity','Resource')) {
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),('-CancelAfter'+$stage))
    if ($LASTEXITCODE -ne 0) { throw "The controlled cancellation after $stage failed." }
}
Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-CancelDuringPrivilege')
if ($LASTEXITCODE -ne 0) { throw 'Controlled cancellation inside the active privileged worker lost its partial package.' }
