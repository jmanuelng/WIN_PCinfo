[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidate = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$regions = [regex]::Matches([IO.File]::ReadAllText($candidate), '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach ($region in $regions) { . ([scriptblock]::Create($region.Groups[2].Value)) }
$testRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot ('.test-output/task-recovery-' + [guid]::NewGuid().ToString('N'))))
$allowedRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
if (-not $testRoot.StartsWith($allowedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid synthetic recovery root.' }
$null = [IO.Directory]::CreateDirectory($testRoot)
$script:taskDefinition = [pscustomobject]@{
    RegistrationInfo=[pscustomobject]@{ Description='Synthetic owned SYSTEM task' }
    Principal=[pscustomobject]@{ UserId='SYSTEM'; LogonType=5; RunLevel=1 }
    Settings=[pscustomobject]@{ ExecutionTimeLimit='PT10S'; MultipleInstances=2 }
    Triggers=[pscustomobject]@{ Count=0 }
    Actions=[pscustomobject]@{ Count=1 }
}
$script:taskDefinition.Actions | Add-Member ScriptMethod Item { param($Index); [pscustomobject]@{ Path='C:\Synthetic\pwsh.exe'; Arguments='synthetic-fixed-command'; WorkingDirectory='C:\Synthetic' } }
$script:taskPresent=$true
$script:taskDeleted=$false
$script:recoveryTask=[pscustomobject]@{ Definition=$script:taskDefinition }
$script:recoveryTask | Add-Member ScriptMethod GetSecurityDescriptor { param($Flags); $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "D:P(A;;GA;;;SY)(A;;GA;;;$sid)" }
$script:recoveryTask | Add-Member ScriptMethod GetInstances { param($Flags); [pscustomobject]@{ Count=0 } }
$script:recoveryTask | Add-Member ScriptMethod Stop { param($Flags) }
$script:recoveryFolder=[pscustomobject]@{}
$script:recoveryFolder | Add-Member ScriptMethod GetTask { param($Name); if (-not $script:taskPresent) { throw [Runtime.InteropServices.COMException]::new('Synthetic task absent.',-2147024894) }; $script:recoveryTask }
$script:recoveryFolder | Add-Member ScriptMethod DeleteTask { param($Name,$Flags); $script:taskPresent=$false; $script:taskDeleted=$true }
# Task Scheduler COM is the sole substituted boundary. Journal, ownership,
# stale-owner admission and cleanup all use the actual generated implementation.
function Get-SystemTaskRecoveryFolder { $script:recoveryFolder }
try {
    $context=New-EvidenceWorkspaceFixtureContext -Boundary ([pscustomobject]@{CaseRoot=$testRoot})
    Register-SystemCollectionTaskOwnership -JournalPath $context.Journal.journalPath `
        -TaskName ('WINPCInfo-SystemCollection-v1-' + [guid]::NewGuid().ToString('N')) -Definition $script:taskDefinition
    Set-EvidenceWorkspaceFixtureOwnerStale -JournalPath $context.Journal.journalPath
    $script:taskDefinition.RegistrationInfo.Description='Foreign replacement'
    $foreign=Invoke-StaleRunRecovery -JournalPath $context.Journal.journalPath
    Assert-Equal 'CleanupIncomplete' $foreign.outcome 'a replaced SYSTEM task is never guessed as owned'
    Assert-Equal $false $script:taskDeleted 'foreign task refusal issues no deletion'
    Assert-Equal $true ([IO.File]::Exists($context.Journal.journalPath)) 'unverified task state retains its journal'
    $script:taskDefinition.RegistrationInfo.Description='Synthetic owned SYSTEM task'
    $recovered=Invoke-StaleRunRecovery -JournalPath $context.Journal.journalPath
    Assert-Equal $true $recovered.cleanup.verified 'registered exact task absence precedes removal of the journal'
    Assert-Equal $true $script:taskDeleted 'deliberate recovery removes the conclusively owned task'
    Assert-Equal $false ([IO.File]::Exists($context.Journal.journalPath)) 'journal retirement follows task and workspace absence'
}
finally { if ([IO.Directory]::Exists($testRoot)) { Remove-Item -LiteralPath $testRoot -Recurse -Force } }
Write-Output 'PASS: generated stale recovery preserves foreign SYSTEM tasks and verifies exact owned task absence before retiring its journal.'
