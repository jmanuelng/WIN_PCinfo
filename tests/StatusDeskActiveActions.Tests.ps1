[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')
Assert-QualificationCleanupReady
foreach ($case in @(
    @{ Action='Cancel'; Worker='Privilege' }, @{ Action='Close'; Worker='Privilege' },
    @{ Action='Cancel'; Worker='System' }, @{ Action='Close'; Worker='System' },
    @{ Action='Cancel'; Worker='NativeCooperative' }, @{ Action='Close'; Worker='NativeHard' }
)) {
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-STA','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-Wpf','-ActiveAction',$case.Action,'-ActiveWorker',$case.Worker,'-RequireRecoveryJournal')
    if ($LASTEXITCODE -ne 0) { throw "Active $($case.Action) failed for $($case.Worker)." }
}
foreach ($failure in @('Integrity','Cleanup')) {
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-STA','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-Wpf','-FailureKind',$failure)
    if ($LASTEXITCODE -ne 0) { throw "Generated $failure precedence failed." }
}
