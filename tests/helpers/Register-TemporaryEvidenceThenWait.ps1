[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $RepositoryRoot,
    [Parameter(Mandatory)] [string] $CaseRoot,
    [Parameter(Mandatory)] [string] $HandoffPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $RepositoryRoot 'src/Contracts.ps1')
. (Join-Path $RepositoryRoot 'src/ContractValidator.ps1')
. (Join-Path $RepositoryRoot 'src/EvidenceWorkspace.ps1')

$workspaceBase = Join-Path $CaseRoot 'workspace-base'
$recoveryBase = Join-Path $CaseRoot 'recovery-base'
$null = [System.IO.Directory]::CreateDirectory($workspaceBase)
$null = [System.IO.Directory]::CreateDirectory($recoveryBase)
$workspace = New-EvidenceWorkspace -RequestedBasePath $workspaceBase -RunId ([guid]::NewGuid())
if ($workspace.state -ne 'Created') { throw 'Crash fixture workspace creation failed.' }
$journal = New-RunRecoveryJournal -Workspace $workspace -RecoveryBasePath $recoveryBase `
    -PlanDigest ('d' * 64) -Phase 'Collection'
$registration = New-TemporaryEvidenceRegistration -JournalPath $journal.journalPath `
    -ExpectedContentLength 32
if ($registration.state -ne 'Registered') { throw 'Crash fixture registration failed.' }

# This handoff is test control data under ignored .test-output, never product
# telemetry. The parent kills this process after seeing it, proving a real stop
# between journal registration and the first evidence write.
$handoff = [pscustomobject][ordered]@{
    journalPath = $journal.journalPath
    workspacePath = $workspace.workspacePath
    temporaryPath = $registration.literalPath
}
[System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath($HandoffPath),
    ($handoff | ConvertTo-Json -Compress),
    [System.Text.UTF8Encoding]::new($false)
)
[System.Threading.Thread]::Sleep(30000)
