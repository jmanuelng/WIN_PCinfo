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
function Get-SystemTaskRecoveryInstances { param($TaskName); @() }
try {
    $context=New-EvidenceWorkspaceFixtureContext -Boundary ([pscustomobject]@{CaseRoot=$testRoot})
    Register-SystemCollectionTaskOwnership -JournalPath $context.Journal.journalPath `
        -TaskName ('WINPCInfo-SystemCollection-v1-' + [guid]::NewGuid().ToString('N')) -Definition $script:taskDefinition
    Set-EvidenceWorkspaceFixtureOwnerStale -JournalPath $context.Journal.journalPath
    $engineStart=[Diagnostics.ProcessStartInfo]::new()
    $engineStart.FileName=Join-Path $PSHOME 'pwsh.exe'; $engineStart.UseShellExecute=$false; $engineStart.CreateNoWindow=$true
    foreach($argument in @('-NoLogo','-NoProfile','-Command','[Threading.Thread]::Sleep(30000)')) { $engineStart.ArgumentList.Add($argument) }
    $engine=[Diagnostics.Process]::Start($engineStart)
    try {
        $script:taskPresent=$false
        $missing=Invoke-StaleRunRecovery -JournalPath $context.Journal.journalPath
        Assert-Equal 'CleanupIncomplete' $missing.outcome 'interrupted deletion without a durable engine-absence witness retains uncertainty'
        Assert-Equal $true ([IO.File]::Exists($context.Journal.journalPath)) 'registration absence alone cannot retire the journal while a controlled engine survives'
        Assert-Equal $false $engine.HasExited 'recovery never guesses which unregistered engine to kill'
    }
    finally { if(-not $engine.HasExited){$engine.Kill();$null=$engine.WaitForExit(5000)}; $engine.Dispose(); $script:taskPresent=$true }
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
    # A durable absence witness is necessary but cannot waive a new independent
    # running-instance observation when the registration itself is missing.
    $script:taskPresent=$true
    $secondRoot=Join-Path $testRoot 'witness-check'
    $null=[IO.Directory]::CreateDirectory($secondRoot)
    $second=New-EvidenceWorkspaceFixtureContext -Boundary ([pscustomobject]@{CaseRoot=$secondRoot})
    $taskName='WINPCInfo-SystemCollection-v1-' + [guid]::NewGuid().ToString('N')
    Register-SystemCollectionTaskOwnership -JournalPath $second.Journal.journalPath -TaskName $taskName -Definition $script:taskDefinition
    $journal=Read-RunRecoveryJournal -LiteralPath $second.Journal.journalPath
    Set-SystemCollectionTaskAbsenceVerified -Journal $journal -JournalPath $second.Journal.journalPath -TaskName $taskName
    Set-EvidenceWorkspaceFixtureOwnerStale -JournalPath $second.Journal.journalPath
    $script:taskPresent=$false
    function Get-SystemTaskRecoveryInstances { param($TaskName); [pscustomobject]@{Path=('\'+$TaskName)} }
    $survivingInstance=Invoke-StaleRunRecovery -JournalPath $second.Journal.journalPath
    Assert-Equal 'CleanupIncomplete' $survivingInstance.outcome 'a currently observed instance overrides an older absence witness'
    function Get-SystemTaskRecoveryInstances { param($TaskName); @() }
    Assert-Equal $true (Invoke-StaleRunRecovery -JournalPath $second.Journal.journalPath).cleanup.verified 'durable process proof plus independent current task/instance absence permits retirement'
    $alternateRoot=Join-Path $testRoot 'alternate-administrator'
    $null=[IO.Directory]::CreateDirectory($alternateRoot)
    $alternate=New-EvidenceWorkspaceFixtureContext -Boundary ([pscustomobject]@{CaseRoot=$alternateRoot})
    $activationSid='S-1-5-21-100-200-300-1002'
    Register-SystemCollectionTaskOwnership -JournalPath $alternate.Journal.journalPath `
        -TaskName ('WINPCInfo-SystemCollection-v1-'+[guid]::NewGuid().ToString('N')) `
        -Definition $script:taskDefinition -ActivationSid $activationSid
    Set-EvidenceWorkspaceFixtureOwnerStale -JournalPath $alternate.Journal.journalPath
    $script:taskPresent=$true; $script:taskDeleted=$false
    $script:recoveryTask | Add-Member -Force ScriptMethod GetSecurityDescriptor {
        param($Flags); $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        "D:P(A;;GA;;;SY)(A;;GA;;;$sid)(A;;GA;;;S-1-5-21-100-200-300-9999)"
    }
    Assert-Equal 'CleanupIncomplete' (Invoke-StaleRunRecovery -JournalPath $alternate.Journal.journalPath).outcome 'an unrecorded administrator cannot acquire recovery ownership'
    Assert-Equal $false $script:taskDeleted 'unexpected task authority prevents deletion'
    $script:recoveryTask | Add-Member -Force ScriptMethod GetSecurityDescriptor {
        param($Flags); $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        "D:P(A;;GA;;;SY)(A;;GA;;;$sid)(A;;GA;;;S-1-5-21-100-200-300-1002)"
    }
    Assert-Equal $true (Invoke-StaleRunRecovery -JournalPath $alternate.Journal.journalPath).cleanup.verified 'the durably authenticated alternate administrator task remains recoverable by the initiator'
    Assert-Equal $true $script:taskDeleted 'exact alternate-administrator ownership permits cleanup'
}
finally { if ([IO.Directory]::Exists($testRoot)) { Remove-Item -LiteralPath $testRoot -Recurse -Force } }
Write-Output 'PASS: generated stale recovery preserves foreign SYSTEM tasks and verifies exact owned task absence before retiring its journal.'
