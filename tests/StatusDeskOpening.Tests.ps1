[CmdletBinding()]
param([string] $EvidencePath = '', [switch] $ColdProcess,
    [string] $CandidatePath = '', [string] $PreparedManifestPath = '', [string] $PreparedManifestSha256 = '')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidateUseError=$null
try {
# This regression must compile the helper on first use even when earlier
# suite files have already loaded it in the shared test process.
if (-not $ColdProcess) {
    if (-not $candidateContext.Prepared) {
        $PreparedManifestPath=Join-Path $candidateContext.OwnedDirectory 'prepared-test-candidate.json'
        [IO.File]::WriteAllText($PreparedManifestPath,((New-PreparedTestCandidateManifest -RepositoryRoot $repositoryRoot -CandidatePath $candidateContext.Path) | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
        $PreparedManifestSha256=(Get-FileHash -LiteralPath $PreparedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $arguments = @('-NoLogo','-NoProfile','-File',$PSCommandPath,'-ColdProcess')
    if ($EvidencePath) { $arguments += @('-EvidencePath',$EvidencePath) }
    $arguments += @('-CandidatePath',$candidateContext.Path,'-PreparedManifestPath',$PreparedManifestPath,'-PreparedManifestSha256',$PreparedManifestSha256)
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments $arguments
    return
}
$candidate = $candidateContext.Path
$tokens = $null; $parseErrors = $null
$application = [Management.Automation.Language.Parser]::ParseFile($candidate,[ref]$tokens,[ref]$parseErrors)
Assert-Equal 0 $parseErrors.Count 'current generated definitions parse'
$initializer = @($application.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Initialize-WinPCInfoDefinitions'
})[0].Body.GetScriptBlock()
Assert-Equal $true ($null -eq ('WinPCInfoOwnedRunspaceOpening' -as [type])) 'this regression starts in a cold process'
$definitionOutput = @(. $initializer)
Assert-Equal 0 $definitionOutput.Count 'passive initialization has no output'
Assert-Equal $true ($null -eq ('WinPCInfoOwnedRunspaceOpening' -as [type])) 'passive initialization does not compile the GUI helper'
$root = Join-Path $repositoryRoot ('.test-output/status-desk-opening-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$sessions = [Collections.Generic.List[object]]::new()
$cases = [Collections.Generic.List[object]]::new()
$originalStart = (Get-Command Start-StatusDeskSession).ScriptBlock
$originalAddType = Get-Command Add-Type -CommandType Cmdlet
$bodyError = $null

function Finish-OpeningFixture {
    param($Session)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Complete-StatusDeskSession $Session) -and $watch.ElapsedMilliseconds -lt 30000) {
        Start-Sleep -Milliseconds 25
    }
    if (-not $Session.Completed) {
        $failure = [InvalidOperationException]::new('Exact opening session remains owned and incomplete.')
        $failure.Data['OwnedCleanupUnverified'] = $true
        throw $failure
    }
}

function Save-OpeningFixture {
    param([string] $Name, $Session, $Extra)
    Assert-Equal 'Completed' $Session.Stage 'completion advances the explicit stage'
    foreach ($handle in @('Worker','Runspace','Pending','OpeningTask','DefinitionInitializer','ParameterJson')) {
        Assert-Equal $true ($null -eq $Session.$handle) 'completed ownership releases every reference'
    }
    $terminal = $Session.Transport.State.Terminal | ConvertFrom-Json
    Assert-Equal $false $terminal.collectionStarted 'opening lifecycle tests grant no collection authority'
    Assert-Equal $false $Session.Transport.State.CollectionStarted 'transport agrees with the terminal'
    $cases.Add([ordered]@{
        name=$Name; exitCode=$Session.ExitCode; stage=$Session.Stage; terminal=$terminal
        finalization=$Session.Finalization.Clone(); maximumProgressGap=$Session.Transport.State.MaximumProgressGapMilliseconds
        startupCause=if ($Session.StartupFailure) { $Session.StartupFailure.ToString() } else { $null }
        extra=$Extra
    })
}

function Set-RealOpeningFixture {
    param([string] $Name, [int] $Delay, [bool] $Fault)
    $script:openingEntry = Join-Path $root ($Name + '-entry.json')
    $script:openingExit = Join-Path $root ($Name + '-exit.json')
    $startup = Join-Path $root ($Name + '-startup.ps1')
    $text = @'
[IO.File]::WriteAllText('__ENTRY__',([ordered]@{timestamp=[Diagnostics.Stopwatch]::GetTimestamp()}|ConvertTo-Json -Compress))
[Threading.Thread]::Sleep(__DELAY__)
[IO.File]::WriteAllText('__EXIT__',([ordered]@{timestamp=[Diagnostics.Stopwatch]::GetTimestamp()}|ConvertTo-Json -Compress))
__THROW__
'@
    $text = $text.Replace('__ENTRY__',$script:openingEntry.Replace("'","''")).Replace('__EXIT__',$script:openingExit.Replace("'","''")).Replace('__DELAY__',[string]$Delay).Replace('__THROW__',$(if ($Fault) { "throw 'REAL.OPENING.REGRESSION.FAULT'" } else { '' }))
    [IO.File]::WriteAllText($startup,$text)
    $script:OpeningFixtureInitialState = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $script:OpeningFixtureInitialState.ThrowOnRunspaceOpenError = $true
    [void] $script:OpeningFixtureInitialState.StartupScripts.Add($startup)
    # The only Start interposition changes its real runspace factory overload.
    # All ownership, compilation, task, configuration and finalization code is current product code.
    $originalText = $originalStart.ToString()
    $anchor = '[RunspaceFactory]::CreateRunspace()'
    Assert-Equal 1 ([regex]::Matches($originalText,[regex]::Escape($anchor)).Count) 'the original factory seam is unique'
    $changed = $originalText.Replace($anchor,'[RunspaceFactory]::CreateRunspace($script:OpeningFixtureInitialState)')
    Assert-Equal $originalText ($changed.Replace('[RunspaceFactory]::CreateRunspace($script:OpeningFixtureInitialState)',$anchor)) 'reversing the disclosed factory seam restores all current Start bytes'
    Set-Item -LiteralPath Function:script:Start-StatusDeskSession -Value ([scriptblock]::Create($changed))
}

# Full current definitions remain isolated in the original worker. Only launch
# is a disclosed benign replacement that reports the immutable parameter snapshot
# and declines a stale digest; no collector or consent grant runs in this test.
$benignLaunch = @'
function Invoke-WinPCInfoLaunch {
    param($ConvertFromJsonCommand,$ConvertToJsonCommand,$TestJsonCommand,[string]$Mode,[bool]$AcceptPreparation,[string]$OpeningFixtureToken)
    $transport = $script:StatusDeskTransport
    if ($Mode -cne 'Gui' -or $AcceptPreparation) { throw 'Worker authority binding changed' }
    $transport.State.OpeningFixtureToken = $OpeningFixtureToken
    $transport.State.OpeningFixtureCulture = [Globalization.CultureInfo]::CurrentCulture.Name
    $transport.State.OpeningFixtureDefinitions = $script:OpeningFixtureDefinitionCount
    if (-not $transport.DecisionReady.Wait(10000)) { throw 'Benign decline was not provided' }
    if ($transport.State.Decision -cne 'Declined') { throw 'Benign opening test may only decline' }
    Send-StatusDeskRecord -Transport $transport -Record ([pscustomobject]@{
        recordType='win-pcinfo.terminal';contractVersion='1.0.0';outcome='NotStarted';exitCode=20
        reasonCode='PREPARATION.DECLINED';collectionStarted=$false;cleanup=[pscustomobject]@{required=$false;verified=$true}
    })
    20
}
'@
$definitionCounter = @'
$initializations = Get-Variable -Name OpeningFixtureDefinitionCount -Scope Script -ErrorAction SilentlyContinue
$script:OpeningFixtureDefinitionCount = if ($null -eq $initializations) { 1 } else { $initializations.Value + 1 }
'@
$definitions = $definitionCounter + [Environment]::NewLine + $initializer.ToString() + [Environment]::NewLine + $benignLaunch
try {
    # Compiler failure must be handled by the same owned session before either
    # native runspace or pipeline exists, without changing passive initialization.
    function Add-Type { throw 'INJECTED.OPENING.COMPILER.FAILURE' }
    try {
        $session = Start-StatusDeskSession -ModuleText $definitions -LaunchParameters @{}
        $sessions.Add($session)
    } finally { Remove-Item -LiteralPath Function:Add-Type }
    Assert-Equal 'Finalizing' $session.Stage 'compiler failure retains a session for terminal finalization'
    Assert-Equal $true (Complete-StatusDeskSession $session) 'never-allocated startup finalizes without native handles'
    Assert-Equal $false $session.Finalization.RunspaceAllocated 'compiler failure allocated no runspace'
    Assert-Equal $false $session.Finalization.WorkerAllocated 'compiler failure allocated no pipeline'
    Assert-Equal $false $session.Finalization.InvocationConsumed 'never-created invocation cannot be consumed'
    Assert-Equal $true ($session.StartupFailure.ToString().Contains('INJECTED.OPENING.COMPILER.FAILURE')) 'internal startup cause is retained'
    Assert-Equal $false $session.Transport.State.Terminal.Contains('INJECTED') 'terminal sanitizes compiler details'
    Save-OpeningFixture 'ColdCompilerFailure' $session @{}

    Set-RealOpeningFixture 'DelayedOpening' 10500 $false
    $payload = @{OpeningFixtureToken='captured-before-opening'}
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $session = Start-StatusDeskSession -DefinitionInitializer ([scriptblock]::Create($definitions)) -LaunchParameters $payload
    $sessions.Add($session)
    $startMilliseconds = $watch.ElapsedMilliseconds
    $payload.OpeningFixtureToken = 'mutated-after-start'
    Assert-Equal $true ($startMilliseconds -lt 5000) 'cold compilation and Start return before the real delayed opening finishes'
    Assert-Equal $true ($null -ne ('WinPCInfoOwnedRunspaceOpening' -as [type])) 'the GUI first use compiles the actual C# callback'
    $incompleteObservations = 0
    $openingTask = $session.OpeningTask
    $openingWatch = [Diagnostics.Stopwatch]::StartNew()
    while (-not $openingTask.IsCompleted -and $openingWatch.ElapsedMilliseconds -lt 30000) {
        $pollCompleted = Complete-StatusDeskSession $session
        if ($session.Stage -eq 'Opening' -and -not $openingTask.IsCompleted) {
            Assert-Equal $false $pollCompleted 'incomplete exact opening remains polled'
            Assert-Equal $true ($null -eq $session.Worker -and $null -eq $session.Pending) 'state alone cannot admit worker creation'
            $incompleteObservations++
        }
        Start-Sleep -Milliseconds 25
    }
    Assert-Equal $true $openingTask.IsCompleted 'bounded real opening actually completed'
    Assert-Equal $true ([IO.File]::Exists($script:openingEntry) -and [IO.File]::Exists($script:openingExit)) 'actual ISS entry and exit both exist'
    $entry = Get-Content -LiteralPath $script:openingEntry -Raw | ConvertFrom-Json
    $exit = Get-Content -LiteralPath $script:openingExit -Raw | ConvertFrom-Json
    $openingMilliseconds = 1000.0 * ($exit.timestamp - $entry.timestamp) / [Diagnostics.Stopwatch]::Frequency
    Assert-Equal $true ($openingMilliseconds -ge 10000) 'real opening exceeded the unchanged progress budget'
    Set-StatusDeskDecision -Session $session -Approve $false -PlanDigest 'stale-not-authorized'
    Finish-OpeningFixture $session
    Assert-Equal 'Declined' $session.Transport.State.Decision 'opening preserves an explicit decline'
    Assert-Equal 'stale-not-authorized' $session.Transport.State.ApprovedDigest 'opening preserves the stale declined digest'
    Assert-Equal 'captured-before-opening' $session.Transport.State.OpeningFixtureToken 'worker receives the immutable start-time parameter snapshot'
    Assert-Equal 1 $session.Transport.State.OpeningFixtureDefinitions 'the actual worker initializes full definitions once'
    Assert-Equal ([Globalization.CultureInfo]::CurrentCulture.Name) $session.Transport.State.OpeningFixtureCulture 'same runspace preserves the caller culture'
    Assert-Equal $true ($session.Transport.State.ProgressSequence -ge 4) 'caller polling publishes truthful waiting heartbeats'
    Assert-Equal $true ($session.Transport.State.MaximumProgressGapMilliseconds -le 10000) 'opening cannot starve the original progress scalar'
    Assert-Equal $true ($session.Finalization.OpeningConsumed -and $session.Finalization.InvocationConsumed -and $session.Finalization.WorkerDisposed -and $session.Finalization.RunspaceDisposed) 'opening, invocation and both disposals completed'
    Save-OpeningFixture 'ColdRealDelayedOpeningDecline' $session @{startMilliseconds=$startMilliseconds;openingMilliseconds=$openingMilliseconds;incompleteObservations=$incompleteObservations;disclosedBenignLaunch=$true}

    Set-RealOpeningFixture 'OpeningFault' 250 $true
    $session = Start-StatusDeskSession -ModuleText $definitions -LaunchParameters @{}
    $sessions.Add($session)
    Finish-OpeningFixture $session
    Assert-Equal $true $session.StartupFailure.ToString().Contains('REAL.OPENING.REGRESSION.FAULT') 'actual ISS exception remains internal'
    Assert-Equal $false $session.Finalization.WorkerAllocated 'failed actual opening never allocates a worker'
    Assert-Equal $false $session.Finalization.InvocationConsumed 'failed opening never consumes an invocation'
    Assert-Equal $true ($session.Finalization.OpeningConsumed -and $session.Finalization.RunspaceDisposed) 'failed full opening is observed and disposed'
    Save-OpeningFixture 'RealOpeningFault' $session @{}

    Set-RealOpeningFixture 'CancelOpening' 1000 $false
    $session = Start-StatusDeskSession -ModuleText $definitions -LaunchParameters @{}
    $sessions.Add($session)
    Assert-Equal $false $session.OpeningTask.IsCompleted 'cancel occurs during actual incomplete opening'
    $session.Transport.Cancellation.Cancel()
    $watch.Restart()
    Assert-Equal $false (Complete-StatusDeskSession $session) 'cancel does not synchronously dispose active opening'
    Assert-Equal $true ($watch.ElapsedMilliseconds -lt 500) 'cancellation polling returns promptly'
    Finish-OpeningFixture $session
    Assert-Equal 30 $session.ExitCode 'opening cancellation remains a truthful cancelled terminal'
    Assert-Equal $false $session.Finalization.WorkerAllocated 'cancel before opening completion prevents worker creation'
    Assert-Equal $false $session.Finalization.InvocationConsumed 'cancelled opening created no invocation'
    Save-OpeningFixture 'RealOpeningCancellation' $session @{}
} catch { $bodyError = $_ }
finally {
    Set-Item -LiteralPath Function:Start-StatusDeskSession -Value $originalStart
    $finish = (Get-Command Finish-OpeningFixture).ScriptBlock
    $cleanup = @(foreach ($session in $sessions) {
        $owned = $session
        { if (-not $owned.Completed) { $owned.Transport.Cancellation.Cancel(); & $finish $owned } }.GetNewClosure()
    })
    $cleanup += @(foreach ($session in $sessions) {
        foreach ($name in @('Cancellation','DecisionReady','Events')) {
            $owned = $session; $handle = $session.Transport.$name
            { if (-not $owned.Completed) { $failure=[InvalidOperationException]::new('Preserve incomplete session transport');$failure.Data['OwnedCleanupUnverified']=$true;throw $failure }; $handle.Dispose() }.GetNewClosure()
        }
    })
    Complete-QualificationHarness -BodyError $bodyError -Cleanup $cleanup -RetainEvidence {
        if ($EvidencePath) {
            [IO.File]::WriteAllText($EvidencePath,([ordered]@{
                kind='CurrentProductionOpeningRegression';bodyPassed=($null -eq $bodyError)
                cases=$cases.ToArray();allAssociatedSessionsCompleted=(@($sessions|Where-Object {-not $_.Completed}).Count -eq 0)
                failure=if ($bodyError) {$bodyError.ToString()} else {$null};qualificationAccepted=$false
            }|ConvertTo-Json -Depth 14),[Text.UTF8Encoding]::new($false))
        }
    } -RetainCleanupEvidence {
        if ($EvidencePath) {
            [IO.File]::WriteAllText(($EvidencePath + '.cleanup.json'),([ordered]@{
                kind='CurrentProductionOpeningAfterCleanup'
                sessions=@($sessions|ForEach-Object {@{completed=$_.Completed;stage=$_.Stage;finalization=$_.Finalization.Clone();ownedReferencesReleased=($null-eq$_.Worker-and$null-eq$_.Runspace-and$null-eq$_.Pending-and$null-eq$_.OpeningTask-and$null-eq$_.DefinitionInitializer-and$null-eq$_.ParameterJson)}})
                allAssociatedSessionsCompleted=(@($sessions|Where-Object {-not $_.Completed}).Count -eq 0)
                qualificationAccepted=$false
            }|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
        }
    }
    $boundary = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
    $resolved = [IO.Path]::GetFullPath($root)
    if (-not $resolved.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)) { throw 'Opening fixture escaped its owned boundary.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    Assert-Equal $false ([IO.Directory]::Exists($resolved)) 'owned real opening fixtures are absent'
}
Write-Output 'PASS: cold GUI compilation, real delayed opening, internal startup failure and cancellation preserve owned completion and no collection authority.'
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
