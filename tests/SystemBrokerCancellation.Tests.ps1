[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$regions=[regex]::Matches([IO.File]::ReadAllText($candidate),'(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach($region in $regions){. ([scriptblock]::Create($region.Groups[2].Value))}
$testRoot=[IO.Path]::GetFullPath((Join-Path $repositoryRoot ('.test-output/broker-cancel-'+[guid]::NewGuid().ToString('N'))))
$allowedRoot=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
if(-not $testRoot.StartsWith($allowedRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'Invalid test root.'}
$null=[IO.Directory]::CreateDirectory($testRoot)
$script:cancel=[Threading.CancellationTokenSource]::new()
$script:frames=[Collections.Generic.List[string]]::new()
$script:reads=0
# Only the administrator transport is controlled. The exported coordinator
# creates/disposes its real pipe and Job, with a real empty run-owned journal.
# Cancellation precedes readiness, so no scheduler API is ever reachable.
function Write-BoundedCollectionChannelFrame { param($Stream,$Json,$MaximumBytes,$CancellationToken); $script:frames.Add($Json) }
function Read-BoundedCollectionChannelFrame {
    param($Stream,$MaximumBytes,$CancellationToken)
    $script:reads++
    if($script:reads -eq 1){$script:cancel.Cancel(); throw [OperationCanceledException]::new()}
    '{"kind":"SystemReleased","absent":true,"reason":"ProtocolRejected"}'
}
function Get-SystemTaskRecoveryInstances { param($TaskName); @() }
try {
    $context=New-EvidenceWorkspaceFixtureContext -Boundary ([pscustomobject]@{CaseRoot=$testRoot})
    $script:AssessmentRunJournalPath=$context.Journal.journalPath
    $preparation=[pscustomobject]@{recordType='win-pcinfo.preparation-plan';contractVersion='1.0.0';release='2.0.0-preview.1';privilege=[pscustomobject]@{privilegedOperationsFrozen=$true;privilegedOperations=@([pscustomobject]@{operationId='observe-mdm-system-context';context='LocalSystem'})}}
    $digest=Get-ObjectDigest -Value $preparation -ConvertToJsonCommand (Get-Command ConvertTo-Json -CommandType Cmdlet)
    $plan=New-SystemCollectionPlan -PreparationPlan $preparation -PreparationPlanDigest $digest
    $stream=[IO.MemoryStream]::new()
    try {$result=Invoke-SystemCollectionPlan -Plan $plan.Plan -PlanDigest $plan.Digest -PrivilegeChannel ([pscustomobject]@{Stream=$stream;Activated=$false}) -CancellationToken $script:cancel.Token}
    finally {$stream.Dispose()}
    Assert-Equal 'Cancelled' $result.state 'cancellation before intent retains its actual disposition'
    Assert-Equal $true $result.cleanup.verified 'broker-confirmed preactivation absence requires no nonexistent journal witness'
    Assert-Equal 0 @((Read-RunRecoveryJournal -LiteralPath $context.Journal.journalPath).systemTasks).Count 'no task intent was registered'
    Assert-Equal 0 @($script:frames|Where-Object {$_ -match 'SystemActivationAuthorized'}).Count 'no persistent activation was authorized'
}
finally {
    $script:cancel.Dispose()
    Remove-Variable AssessmentRunJournalPath -Scope Script -ErrorAction SilentlyContinue
    if([IO.Directory]::Exists($testRoot)){Remove-Item -LiteralPath $testRoot -Recurse -Force}
}
Write-Output 'PASS: cancellation before SYSTEM intent proves absence without a false cleanup failure.'
