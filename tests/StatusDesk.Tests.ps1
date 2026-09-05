[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$generated = [IO.File]::ReadAllText($candidate)
$regions = [regex]::Matches($generated,
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach ($region in $regions) { . ([scriptblock]::Create($region.Groups[2].Value)) }
$transport = New-StatusDeskTransport
Assert-Equal 128 $transport.Events.BoundedCapacity 'progress transport has a fixed memory bound'
$summary = [pscustomobject]@{ recordType = 'win-pcinfo.preparation-summary'; planDigest = ('a' * 64) }
Send-StatusDeskRecord -Transport $transport -Record $summary
for ($index = 0; $index -lt 300; $index++) {
    Send-StatusDeskRecord -Transport $transport -Record (New-ProgressRecord -Sequence $index -State Started -MessageId 'collection.active' -CompletedUnits 0 -TotalUnits 1)
}
Assert-Equal 128 $transport.Events.Count 'a stalled UI cannot grow the queue'
Assert-Equal ('a' * 64) ($transport.State.Preparation | ConvertFrom-Json).planDigest 'progress overflow cannot lose preparation'
foreach ($outcome in @('Completed','CompletedWithGaps','NotStarted','Cancelled','TimedOut','IntegrityFailed','CleanupIncomplete')) {
    $terminal = [pscustomobject]@{ recordType='win-pcinfo.terminal'; outcome=$outcome; exitCode=20 }
    Send-StatusDeskRecord -Transport $transport -Record $terminal
    Assert-Equal $outcome ($transport.State.Terminal | ConvertFrom-Json).outcome 'all seven terminals remain authoritative'
}
$transport.Cancellation.Dispose()
$transport.DecisionReady.Dispose()
$transport.Events.Dispose()
$script:StatusDeskTransport = New-StatusDeskTransport
$script:StatusDeskTransport.Cancellation.Cancel()
$cancelled = $false
try { Enter-AssessmentCollectionStage -Stage Device } catch { $cancelled = $_.Exception.Data['ReasonCode'] -eq 'RUN.CANCELLED' }
Assert-Equal $true $cancelled 'cancellation stops the next real scheduling boundary'
$script:StatusDeskTransport.Cancellation.Dispose()
$script:StatusDeskTransport.DecisionReady.Dispose()
$script:StatusDeskTransport.Events.Dispose()
Remove-Variable -Name StatusDeskTransport -Scope Script
$moduleText = ($regions | ForEach-Object { $_.Groups[2].Value }) -join "`n"
$request = Get-AutomationRequest -LiteralPath (Join-Path $PSScriptRoot 'fixtures/automation-request.json') `
    -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
$context = @{ IsFixture = $true }
foreach ($name in @('Preparation','Contract','Run','PrivilegedCollection','SystemCollection',
    'EvidenceWorkspace','ProtectedPackage','RecipientSharing','DeviceReadiness','IdentityEnrollment',
    'AdministratorExposure','EffectivePolicy','ResourceDependencies','NetworkTopology',
    'SoftwareInventory','CertificateTrust','MicrosoftConnectivity')) { $context[$name + 'FixturePath'] = '' }
$context.PreparationFixturePath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
$parameters = @{
    Request=$request; RuntimeFacts=(Get-ActiveRuntimeFacts -ModuleFacts (Get-BuiltInModuleCompatibilityFacts))
    ArtifactTrustValid=$false; ValidationContext=[pscustomobject]$context
}
$session = Start-StatusDeskSession -ModuleText $moduleText -LaunchParameters $parameters
$deadline = [Diagnostics.Stopwatch]::StartNew()
while (-not $session.Transport.State.Preparation -and -not $session.Pending.IsCompleted -and $deadline.Elapsed.TotalSeconds -lt 30) {
    Start-Sleep -Milliseconds 20
}
Assert-Equal $true ([bool]$session.Transport.State.Preparation) 'generated worker reaches frozen preparation'
$preparation = $session.Transport.State.Preparation | ConvertFrom-Json
Set-StatusDeskDecision -Session $session -Approve $false -PlanDigest $preparation.planDigest
while (-not (Complete-StatusDeskSession $session) -and $deadline.Elapsed.TotalSeconds -lt 45) { Start-Sleep -Milliseconds 20 }
$terminal = $session.Transport.State.Terminal | ConvertFrom-Json
Assert-Equal 'PREPARATION.DECLINED' $terminal.reasonCode 'decline is consumed by the ordinary preparation gate'
Assert-Equal $false $terminal.collectionStarted 'decline schedules no collector'
$session.Transport.Cancellation.Dispose()
$session.Transport.DecisionReady.Dispose()
$session.Transport.Events.Dispose()
Write-Output 'PASS: Status desk transport is bounded and preserves preparation and terminal records.'
