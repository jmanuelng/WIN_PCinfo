[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')
Assert-QualificationCleanupReady
foreach ($boundary in @('BeforeExecution','DelayedAfterExecution')) {
    foreach ($action in @('Cancel','Close')) {
        Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @(
            '-NoLogo','-NoProfile','-STA','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),
            '-Wpf','-ActiveAction',$action,'-ActiveWorker','Privilege',
            '-ActivePrivilegeBoundary',$boundary,'-RequireRecoveryJournal')
        if ($LASTEXITCODE -ne 0) { throw "Privilege $boundary $action failed." }
    }
}
Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @(
    '-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),
    '-CancelDuringPrivilege','-DelayPrivilegeStartup')
if ($LASTEXITCODE -ne 0) { throw 'Automatic privilege cancellation with delayed startup failed.' }
Write-Output 'PASS: actual WPF Cancel/Close and automatic active cancellation preserve truthful privilege execution admission through delayed startup and owned cleanup.'
