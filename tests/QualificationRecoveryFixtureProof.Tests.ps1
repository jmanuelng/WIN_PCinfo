[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'QualificationRecoveryFixtureProof.ps1')
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/EvidenceWorkspace.ps1')
$tokens=$null;$errors=$null
$existingAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'QualificationCleanup.Tests.ps1'),[ref]$tokens,[ref]$errors)
Assert-Equal 0 $errors.Count 'existing finalizer regression helpers parse'
$script:RecoveryProofTestDirectory=$PSScriptRoot
foreach($name in @('Get-HarnessFinalization','Invoke-ExpectedQualificationHarnessFault')){
    $definitions=@($existingAst.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$name}.GetNewClosure(),$false))
    Assert-Equal 1 $definitions.Count 'actual finalizer replay helper is unique'
    . ([scriptblock]::Create($definitions[0].Extent.Text.Replace('$PSScriptRoot','$script:RecoveryProofTestDirectory')))
}
# Pure finalizer replay supplies no native worker and no actual sampler.
function Measure-QualificationWorkload {}
function Complete-StatusDeskSession { param($Session) throw 'Synthetic incomplete session cannot finalize.' }
function Set-StatusDeskDecision { param($Session,$Approve,$PlanDigest) }
$ownedParent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+'\'
$outer=Join-Path $ownedParent ('recovery-proof-regression-'+[guid]::NewGuid().ToString('N'))
$bodyError=$null
$records=Join-Path $ownedParent ('recovery-proof-records-'+[guid]::NewGuid().ToString('N'))
try{
    $null=[IO.Directory]::CreateDirectory($records)
    $null=[IO.Directory]::CreateDirectory($outer)
    # Derive the first interrupted launch destination from its actual parent
    # caller, then replay the actual harness snapshot-acquisition statement.
    $callerTokens=$null;$callerErrors=$null
    $callerAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'StatusDeskRecovery.Tests.ps1'),[ref]$callerTokens,[ref]$callerErrors)
    Assert-Equal 0 $callerErrors.Count 'actual recovery parent caller parses'
    $testRoot=Join-Path $outer 'fresh-interrupted-parent';$null=[IO.Directory]::CreateDirectory($testRoot)
    foreach($variable in @('destination','handoffPath')){
        $assignments=@($callerAst.FindAll({param($n)
            $n-is[Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left-is[Management.Automation.Language.VariableExpressionAst] -and
            $n.Left.VariablePath.UserPath-ceq$variable
        }.GetNewClosure(),$true))
        Assert-Equal 1 $assignments.Count 'actual first-run parent destination assignment is unique'
        . ([scriptblock]::Create($assignments[0].Extent.Text))
    }
    $RecoveryDestination=$destination;$InterruptHandoffPath=$handoffPath;$RecoveryExpectedReason=''
    $recoveryFixtureInvocationId=[guid]::NewGuid().ToString('N');$recoveryFixtureSnapshot=$null
    $harnessTokens=$null;$harnessErrors=$null
    $harnessAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),[ref]$harnessTokens,[ref]$harnessErrors)
    Assert-Equal 0 $harnessErrors.Count 'actual harness snapshot prefix parses'
    $snapshotCalls=@($harnessAst.FindAll({param($n)
        $n-is[Management.Automation.Language.CommandAst] -and $n.GetCommandName()-ceq'Get-QualificationRecoveryFixtureSnapshot'
    },$true))
    Assert-Equal 1 $snapshotCalls.Count 'actual pre-invocation snapshot acquisition is unique'
    $snapshotStatement=$snapshotCalls[0].Parent
    while($null-ne$snapshotStatement -and $snapshotStatement-isnot[Management.Automation.Language.IfStatementAst]){$snapshotStatement=$snapshotStatement.Parent}
    Assert-Equal $true ($null-ne$snapshotStatement) 'actual snapshot acquisition is conditionally guarded'
    . ([scriptblock]::Create($snapshotStatement.Extent.Text))
    Assert-Equal $true ($null-eq$recoveryFixtureSnapshot) 'actual interrupted first-run prefix requires no pre-existing snapshot'
    Assert-Equal $false ([IO.Directory]::Exists($RecoveryDestination)) 'first-run prefix preserves product-owned destination creation'
    $RecoveryExpectedReason='RECOVERY.NO_RESIDUE';$recoveryFixtureSnapshot=$null
    . ([scriptblock]::Create($snapshotStatement.Extent.Text))
    Assert-Equal $true ($null-eq$recoveryFixtureSnapshot) 'successful no-residue recovery needs no retained-refusal snapshot'
    foreach($fault in @('None','AuthorizedForeign','MissingSnapshot','LateSnapshot','WrongInvocation','ChangedContent','ReplacedFile','ExtraEntry',
        'WrongReason','WrongOutcome','WrongExit','StringExit','MissingTerminalExit','StringTerminalExit','ArrayTerminalExit','ContradictoryTerminalExit','NullTerminalExit','FractionalTerminalExit','TerminalCollection','StringTerminalCollection','TransportCollection','StringTransportCollection',
        'OversizedFile','ReparseEntry','DirectoryReplacement','MissingFinalization','StringDisposal','StringSnapshotTime','ExistingMarker','Package','FreshWorker','UnclearedWorker','Incomplete','FinalizationError','FinalizationDisposal','UnsafeBody','OrdinaryBody','DisposalFailure','MalformedTerminal')){
        $fixture=Join-Path $outer $fault;$null=[IO.Directory]::CreateDirectory($fixture)
        $RecoveryDestination=Join-Path $fixture 'assessment';$null=[IO.Directory]::CreateDirectory($RecoveryDestination)
        $testRoot=$RecoveryDestination
        $journal=Join-Path $RecoveryDestination 'run-recovery.json'
        [IO.File]::WriteAllText($journal,'Synthetic retained recovery journal')
        $QualificationPath=Join-Path $fixture 'evidence.json'
        $blocker=Join-Path $fixture 'expected-cleanup-blocked.json'
        $RecoveryExpectedReason=if($fault-ceq'AuthorizedForeign'){'RECOVERY.OWNERSHIP_UNVERIFIED'}else{'RECOVERY.DELIBERATE_ACTION_REQUIRED'}
        $RecoveryAuthorized=$fault-ceq'AuthorizedForeign'
        $recoveryFixtureInvocationId=[guid]::NewGuid().ToString('N')
        $recoveryFixtureSnapshot=Get-QualificationRecoveryFixtureSnapshot -Destination $RecoveryDestination -OwnedParent $ownedParent -InvocationId $recoveryFixtureInvocationId
        $recoveryFixtureInvocationTimestamp=[Diagnostics.Stopwatch]::GetTimestamp()
        $terminal=@{recordType='win-pcinfo.terminal';outcome=$(if($RecoveryAuthorized){'CleanupIncomplete'}else{'NotStarted'});reasonCode=$RecoveryExpectedReason;exitCode=$(if($RecoveryAuthorized){60}else{20});collectionStarted=$false;cleanup=@{verified=$false}}
        $session=[pscustomobject]@{Completed=$true;Stage='Completed';OpeningTask=$null;Worker=$null;Runspace=$null;Pending=$null;ExitCode=$(if($RecoveryAuthorized){60}else{20});
            Finalization=@{PrimaryError=$null;WorkerDisposed=$true;RunspaceDisposed=$true};Transport=@{
                State=@{CollectionStarted=$false;PackagePath='';Terminal='';FirstProgressMilliseconds=1L;MaximumProgressGapMilliseconds=1L;TerminalMilliseconds=2L;CancellationRequestedMilliseconds=-1L}
                Cancellation=[Threading.CancellationTokenSource]::new()
                DecisionReady=[Threading.ManualResetEventSlim]::new();Events=[Threading.ManualResetEventSlim]::new()
            }}
        $body='';$junction=''
        switch($fault){
            'MissingSnapshot'{$recoveryFixtureSnapshot=$null}
            'LateSnapshot'{$recoveryFixtureSnapshot.capturedTimestamp=$recoveryFixtureInvocationTimestamp+1L}
            'WrongInvocation'{$recoveryFixtureSnapshot.invocationId='foreign'}
            'ChangedContent'{[IO.File]::WriteAllText($journal,'Changed synthetic journal')}
            'ReplacedFile'{Remove-Item -LiteralPath $journal;[IO.File]::WriteAllText($journal,'Synthetic retained recovery journal')}
            'ExtraEntry'{[IO.File]::WriteAllText((Join-Path $RecoveryDestination 'new-worker-file'),'new')}
            'WrongReason'{$terminal.reasonCode='RECOVERY.UNKNOWN'}
            'WrongOutcome'{$terminal.outcome='CompletedWithGaps'}
            'WrongExit'{$session.ExitCode=0}
            'StringExit'{$session.ExitCode='20'}
            'MissingTerminalExit'{$terminal.Remove('exitCode')}
            'StringTerminalExit'{$terminal.exitCode='20'}
            'ArrayTerminalExit'{$terminal.exitCode=@(20)}
            'ContradictoryTerminalExit'{$terminal.exitCode=60}
            'NullTerminalExit'{$terminal.exitCode=$null}
            'FractionalTerminalExit'{$terminal.exitCode=20.5}
            'TerminalCollection'{$terminal.collectionStarted=$true}
            'StringTerminalCollection'{$terminal.collectionStarted='false'}
            'TransportCollection'{$session.Transport.State.CollectionStarted=$true}
            'StringTransportCollection'{$session.Transport.State.CollectionStarted='false'}
            'OversizedFile'{[IO.File]::WriteAllBytes((Join-Path $RecoveryDestination 'oversized'),[byte[]]::new(1MB+1))}
            'ReparseEntry'{
                $target=Join-Path $fixture 'owned-link-target';$null=[IO.Directory]::CreateDirectory($target)
                [IO.File]::WriteAllText((Join-Path $target 'sentinel'),'Owned target survives refused reparse snapshot')
                $junction=Join-Path $RecoveryDestination 'refused-junction'
                $null=New-Item -ItemType Junction -Path $junction -Target $target
            }
            'DirectoryReplacement'{
                $moved=Join-Path $fixture 'old-assessment'
                $prefix=[IO.Path]::GetFullPath($fixture)+'\'
                foreach($path in @($RecoveryDestination,$moved)){if(-not [IO.Path]::GetFullPath($path).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'Synthetic directory replacement escapes fixture.'}}
                [IO.Directory]::Move($RecoveryDestination,$moved)
                $null=[IO.Directory]::CreateDirectory($RecoveryDestination)
                [IO.File]::WriteAllText($journal,'Synthetic retained recovery journal')
            }
            'MissingFinalization'{$session.PSObject.Properties.Remove('Finalization')}
            'StringDisposal'{$session.Finalization.WorkerDisposed='true'}
            'StringSnapshotTime'{$recoveryFixtureSnapshot.capturedTimestamp='1'}
            'ExistingMarker'{[IO.File]::WriteAllText($blocker,'Pre-existing scoped marker survives')}
            'Package'{$session.Transport.State.PackagePath='synthetic-new-package'}
            'FreshWorker'{$session.Transport.State.SystemInvoked=$true}
            'UnclearedWorker'{$session.Worker='synthetic-handle'}
            'Incomplete'{$session.Completed=$false;$session.Stage='Running'}
            'FinalizationError'{$session.Finalization.PrimaryError=[InvalidOperationException]::new('Synthetic finalization failure')}
            'FinalizationDisposal'{$session.Finalization.WorkerDisposed=$false}
            'UnsafeBody'{$body='$failure=[InvalidOperationException]::new("Synthetic unsafe child state");$failure.Data["OwnedCleanupUnverified"]=$true;throw $failure'}
            'OrdinaryBody'{$body='throw "Synthetic ordinary assertion"'}
            'DisposalFailure'{
                $session.Transport.Cancellation.Dispose()
                $session.Transport.Cancellation=[pscustomobject]@{}
                $session.Transport.Cancellation|Add-Member ScriptMethod Dispose {throw 'Synthetic transport disposal failure'}
            }
        }
        $session.Transport.State.Terminal=$terminal|ConvertTo-Json -Depth 6 -Compress
        if($fault-ceq'MalformedTerminal'){$session.Transport.State.Terminal='{'}
        $FailureKind='None';$QualificationPlanFault='';$qualificationFailed=$false;$qualificationBodyError=$null
        $ActiveAction='None';$ActiveWorker='Privilege';$CancelDuringPrivilege=$false
        $RequireQualityBudgets=$false;$assessmentQuality=$null
        $quality=[ordered]@{packageBytes=0L;htmlBytes=0L};$qualityWatch=[Diagnostics.Stopwatch]::StartNew()
        $qualificationArguments=[ordered]@{};$projection=[ordered]@{cleanupVerified=$false}
        $Wpf=$false;$runLock=$null;$runLockOwned=$false;$diskInstrumentationAccepted=$false;$memoryCalibrationAccepted=$false
        $memoryCalibrationSha256='';$candidate=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
        try{
            $observation=Invoke-ExpectedQualificationHarnessFault -BlockerPath $blocker -Program (Get-HarnessFinalization -File 'StatusDeskEngine.Tests.ps1' -Body $body)
            [ordered]@{fault=$fault;failure=if($null-ne$observation.failure){$observation.failure.Exception.ToString()}else{''};blocked=$observation.blocked;productCleanupVerified=$false;nativeWorkerStarted=$false} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $records ($fault+'.json')) -Encoding utf8
            $valid=$fault-cin@('None','AuthorizedForeign','ExistingMarker')
            if($valid){
                Assert-Equal $true ($null-eq$observation.failure) 'completed fresh refusal retains the pre-existing fixture without unsafe cleanup'
                Assert-Equal ($fault-ceq'ExistingMarker') $observation.blocked 'valid retention never removes an existing scheduling stop'
                Assert-Equal ($fault-ceq'ExistingMarker') ([IO.File]::Exists($blocker)) 'valid fixture proof creates no scheduling stop'
                if($fault-ceq'ExistingMarker'){Assert-Equal 'Pre-existing scoped marker survives' ([IO.File]::ReadAllText($blocker)) 'foreign marker bytes remain untouched'}
                $evidence=Get-Content -LiteralPath $QualificationPath -Raw|ConvertFrom-Json
                Assert-Equal 'RetainedForRecoveryTest' $evidence.testCleanup 'actual finalizer records only harness retention'
                Assert-Equal $false $evidence.cleanupVerified 'product cleanup remains honestly false'
                Assert-Equal 'Synthetic retained recovery journal' ([IO.File]::ReadAllText($journal)) 'original bytes remain for parent recovery'
            }else{
                Assert-Equal $true ($null-ne$observation.failure) 'invalid retained proof remains a finalizer failure'
                Assert-Equal $true $observation.blocked 'unsafe or ambiguous fixture state remains a scheduling stop'
                Assert-Equal $true ([IO.File]::Exists($blocker)) 'invalid retained proof persists its private scoped blocker'
                Assert-Equal $true ([IO.Directory]::Exists($RecoveryDestination)) 'failed proof preserves fixture evidence'
            }
        }finally{
            if($junction -and (Test-Path -LiteralPath $junction)){
                if(-not [IO.Path]::GetFullPath($junction).StartsWith([IO.Path]::GetFullPath($RecoveryDestination)+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected synthetic junction cleanup target.'}
                Remove-Item -LiteralPath $junction -Force
                if(Test-Path -LiteralPath $junction){throw 'Synthetic junction absence unverified.'}
                Assert-Equal 'Owned target survives refused reparse snapshot' ([IO.File]::ReadAllText((Join-Path $target 'sentinel'))) 'refused reparse never changes its target'
            }
            try{$session.Transport.Cancellation.Dispose()}catch{}
            $session.Transport.DecisionReady.Dispose();$session.Transport.Events.Dispose()
        }
    }
}catch{$bodyError=$_}
finally{
    Complete-QualificationHarness -BodyError $bodyError -Cleanup @({
        $resolved=[IO.Path]::GetFullPath($outer)
        if(-not $resolved.StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase)){throw 'Regression fixture cleanup escaped its owned parent.'}
        if([IO.Directory]::Exists($resolved)){
            foreach($entry in Get-ChildItem -LiteralPath $resolved -Force -Recurse){
                if(($entry.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'Regression cleanup refuses unexpected reparse object.'}
            }
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
        if([IO.Directory]::Exists($resolved)){throw 'Owned regression fixture absence unverified.'}
    })
}
Write-Output 'PASS: actual terminal finalizer recognizes unchanged pre-existing recovery fixtures, preserves false product cleanup, and blocks ambiguous fresh invocation states.'
