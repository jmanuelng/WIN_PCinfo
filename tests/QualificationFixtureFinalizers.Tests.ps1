[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')
Assert-QualificationCleanupReady
$originalBlockerFunction=(Get-Command Get-QualificationCleanupBlockerPath -CommandType Function).ScriptBlock
function Read-FixtureAst([string]$Name) {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $Name),[ref]$tokens,[ref]$errors)
    if(@($errors).Count){throw 'Actual fixture source did not parse.'}
    return $ast
}
$assertAst=@((Read-FixtureAst 'TestHarness.ps1').FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-Equal'
},$true))[0]
. ([scriptblock]::Create($assertAst.Extent.Text))
function Get-FixtureFinalizer([string]$FunctionName) {
    $functionAst=@((Read-FixtureAst 'QualificationCleanup.Tests.ps1').FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $FunctionName
    },$true))[0]
    $tryAst=@($functionAst.Body.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[-1]
    $text=$tryAst.Finally.Extent.Text
    return [scriptblock]::Create($text.Substring(1,$text.Length-2))
}
$metadataTry=@((Read-FixtureAst 'RecoveryProcessOwnership.Tests.ps1').EndBlock.Statements |
    Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[0]
$metadataText=$metadataTry.Finally.Extent.Text
$metadataFinalizer=[scriptblock]::Create($metadataText.Substring(1,$metadataText.Length-2))
$treeTry=@((Read-FixtureAst 'RecoveryProcessOwnership.Tests.ps1').EndBlock.Statements |
    Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[1]
$treeText=$treeTry.Finally.Extent.Text
$treeFinalizer=[scriptblock]::Create($treeText.Substring(1,$treeText.Length-2))
function Stop-RecoveryApplication {
    param($Process)
    if($Process.StopThrows){throw 'Injected exact-owned parent stop failure.'}
    $Process.Kill()
}

$handoffFinalizer=Get-FixtureFinalizer 'Test-RecoveryChildFailureAfterHandoff'
$pipeFinalizer=Get-FixtureFinalizer 'Test-RecoveryExitedChildWithIncompleteOutput'
$controllerLoop=@((Read-FixtureAst 'PrivilegedExecutionPhase.Tests.ps1').EndBlock.Statements |
    Where-Object {$_ -is [Management.Automation.Language.ForEachStatementAst] -and $_.Variable.Extent.Text -eq '$name'})[0]
$controllerStatements=@($controllerLoop.Body.Statements)
$controllerInvocationIndex=-1
for($index=0;$index-lt$controllerStatements.Count;$index++){
    if($controllerStatements[$index] -is [Management.Automation.Language.AssignmentStatementAst] -and
        $controllerStatements[$index].Left.Extent.Text -eq '$result'){
        if($controllerInvocationIndex-ge0){throw 'Actual controller assignment is ambiguous.'}
        $controllerInvocationIndex=$index
    }
}
if($controllerInvocationIndex-lt0){throw 'Actual controller assignment was not found.'}
$controllerTail=[scriptblock]::Create([string]::Join([Environment]::NewLine,
    @($controllerStatements | Select-Object -Skip ($controllerInvocationIndex+1) | ForEach-Object {$_.Extent.Text})))
function New-InjectedProcess {
    $process=[pscustomobject]@{HasExited=$false;WaitResult=$true;KillThrows=$false;DisposeThrows=$false;DisposeCount=0;KillCount=0;WaitCount=0;StopThrows=$false}
    $process | Add-Member ScriptMethod Kill {
        param($EntireTree)
        $this.KillCount++
        if($this.KillThrows){throw 'Injected exact-owned stop failure.'}
        if($this.WaitResult){$this.HasExited=$true}
    }
    $process | Add-Member ScriptMethod WaitForExit {param($Milliseconds) $this.WaitCount++;return $this.WaitResult}
    $process | Add-Member ScriptMethod Dispose {
        $this.DisposeCount++
        if($this.DisposeThrows){throw 'Injected owned handle disposal failure.'}
    }
    return $process
}
function New-InjectedOutput {
    $output=[pscustomobject]@{WaitResult=$true;WaitCount=0}
    $output | Add-Member ScriptMethod Wait {param($Milliseconds) $this.WaitCount++;return $this.WaitResult}
    return $output
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$fixtureRoot=Join-Path $repositoryRoot ('.test-output/fixture-finalizers-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($fixtureRoot)
function Get-QualificationCleanupBlockerPath { Join-Path $script:replayCaseRoot 'blocked.json' }
$replayResults=[Collections.Generic.List[object]]::new()
$replayBodyError=$null
try {
    $cases=@(
        @{name='MetadataKillFailure';kind='Metadata';unsafe=$true},
        @{name='MetadataWaitTimeout';kind='Metadata';unsafe=$true},
        @{name='MetadataChildDisposeFailure';kind='Metadata';unsafe=$true},
        @{name='MetadataHeldDisposeFailure';kind='Metadata';unsafe=$true},
        @{name='MetadataBodyFailure';kind='Metadata';unsafe=$false;bodyFailure=$true},
        @{name='MetadataSafe';kind='Metadata';unsafe=$false},
        @{name='HandoffKillFailure';kind='Handoff';unsafe=$true},
        @{name='HandoffWaitTimeout';kind='Handoff';unsafe=$true},
        @{name='HandoffDisposeFailure';kind='Handoff';unsafe=$true},
        @{name='HandoffPendingOutput';kind='Handoff';unsafe=$true},
        @{name='HandoffBodyFailure';kind='Handoff';unsafe=$false;bodyFailure=$true},
        @{name='HandoffSafeForeignMarker';kind='Handoff';unsafe=$false;foreignMarker=$true},
        @{name='PipeKillFailure';kind='Pipe';unsafe=$true},
        @{name='PipeWaitTimeout';kind='Pipe';unsafe=$true},
        @{name='PipePendingError';kind='Pipe';unsafe=$true},
        @{name='PipeSafe';kind='Pipe';unsafe=$false},
        @{name='HandoffKillAfterExit';kind='Handoff';unsafe=$true},
        @{name='PipeKillAfterExit';kind='Pipe';unsafe=$true},
        @{name='TreeParentStopFailure';kind='Tree';unsafe=$true},
        @{name='TreeParentWaitTimeout';kind='Tree';unsafe=$true},
        @{name='TreeNestedStopFailure';kind='Tree';unsafe=$true},
        @{name='TreeOutputPending';kind='Tree';unsafe=$true},
        @{name='TreeNestedDisposeFailure';kind='Tree';unsafe=$true},
        @{name='TreeBodyFailure';kind='Tree';unsafe=$false;bodyFailure=$true},
        @{name='TreeSafe';kind='Tree';unsafe=$false},
        @{name='TreeMissingNestedAndWitness';kind='Tree';unsafe=$true},
        @{name='TreeMissingNestedWithWitness';kind='Tree';unsafe=$true}
    )
    $cleanupShapes=@(
        @{name='True';value=$true;unsafe=$false},
        @{name='False';value=$false;unsafe=$true},
        @{name='Null';value=$null;unsafe=$true},
        @{name='String';value='true';unsafe=$true},
        @{name='Integer';value=1;unsafe=$true},
        @{name='Array';value=@($true);unsafe=$true},
        @{name='MissingVerified';unsafe=$true},
        @{name='MissingCleanup';unsafe=$true},
        @{name='MissingResult';unsafe=$true},
        @{name='ResultSingleton';unsafe=$true},
        @{name='CleanupSingleton';unsafe=$true},
        @{name='ResultMixed';unsafe=$true},
        @{name='CleanupMixed';unsafe=$true},
        @{name='OrderedMap';unsafe=$false}
    )
    foreach($shape in $cleanupShapes){$cases+=@{name='Controller'+$shape.name;kind='Controller';unsafe=$shape.unsafe;shape=$shape}}
    foreach($case in $cases) {
        $script:replayCaseRoot=Join-Path $fixtureRoot $case.name
        $null=[IO.Directory]::CreateDirectory($script:replayCaseRoot)
        $caught=$null;$originalBodyError=$null
        $replayOutput=[Collections.Generic.List[object]]::new()
        $metadataBodyError=$null;$handoffFixtureBodyError=$null;$pipeFixtureBodyError=$null;$stopBodyError=$null
        $child=New-InjectedProcess;$held=New-InjectedProcess;$parent=New-InjectedProcess;$repro=New-InjectedProcess
        $treeParent=New-InjectedProcess;$nested=New-InjectedProcess;$rootOutput=New-InjectedOutput;$rootError=New-InjectedOutput
        $childOutput=New-InjectedOutput;$childError=New-InjectedOutput
        $output=New-InjectedOutput;$errorOutput=New-InjectedOutput
        $ownedStateRoot=Join-Path $script:replayCaseRoot 'owned-state'
        $null=[IO.Directory]::CreateDirectory($ownedStateRoot)
        $testRoot=$ownedStateRoot;$root=$ownedStateRoot
        $handoffFixtureCleanup=@{stopCompleted=$false;childAbsent=$true;outputClosed=$false;errorClosed=$false;handleDisposed=$false}
        $pipeFixtureCleanup=@{stopCompleted=$false;childAbsent=$true;outputClosed=$false;errorClosed=$false;handleDisposed=$false}
        if($case.ContainsKey('bodyFailure')) {
            try {throw 'Injected original fixture body failure.'}catch{$originalBodyError=$_}
            $metadataBodyError=$originalBodyError;$handoffFixtureBodyError=$originalBodyError;$pipeFixtureBodyError=$originalBodyError;$stopBodyError=$originalBodyError
        }
        if($case.name-eq'MetadataKillFailure'){$child.KillThrows=$true}
        if($case.name-eq'MetadataWaitTimeout'){$child.WaitResult=$false}
        if($case.name-eq'MetadataChildDisposeFailure'){$child.DisposeThrows=$true}
        if($case.name-eq'MetadataHeldDisposeFailure'){$held.DisposeThrows=$true}
        if($case.name-in@('HandoffKillFailure','HandoffWaitTimeout')) {
            $handoffFixtureCleanup.childAbsent=$false;$child.WaitResult=$false
            $child.KillThrows=$case.name-eq'HandoffKillFailure'
        }
        if($case.name-eq'HandoffDisposeFailure'){$child.DisposeThrows=$true}
        if($case.name-eq'HandoffPendingOutput'){$childOutput.WaitResult=$false}
        if($case.name-in@('PipeKillFailure','PipeWaitTimeout')) {
            $pipeFixtureCleanup.childAbsent=$false;$repro.WaitResult=$false
            $repro.KillThrows=$case.name-eq'PipeKillFailure'
        }
        if($case.name-eq'PipePendingError'){$errorOutput.WaitResult=$false}
        if($case.name-eq'HandoffKillAfterExit'){$handoffFixtureCleanup.childAbsent=$false;$child.KillThrows=$true}
        if($case.name-eq'PipeKillAfterExit'){$pipeFixtureCleanup.childAbsent=$false;$repro.KillThrows=$true}
        if($case.kind-eq'Tree'){
            $ownedRoot=$ownedStateRoot;$witness=Join-Path $ownedRoot 'nested-witness'
            [IO.File]::WriteAllText($witness,'synthetic-owned-child')
            $root=$treeParent
            $stopFixtureCleanup=@{parentStop=$false;parentAbsent=$false;nestedStop=$false;nestedAbsent=$false;outputClosed=$false;errorClosed=$false;nestedDisposed=$false;parentDisposed=$false}
            if($case.name-eq'TreeParentStopFailure'){$root.StopThrows=$true}
            if($case.name-eq'TreeParentWaitTimeout'){$root.WaitResult=$false}
            if($case.name-eq'TreeNestedStopFailure'){$nested.KillThrows=$true}
            if($case.name-eq'TreeOutputPending'){$rootOutput.WaitResult=$false}
            if($case.name-eq'TreeNestedDisposeFailure'){$nested.DisposeThrows=$true}
            if($case.name-in@('TreeMissingNestedAndWitness','TreeMissingNestedWithWitness')){$nested=$null}
            if($case.name-eq'TreeMissingNestedAndWitness'){[IO.File]::Delete($witness)}
        }

        if($case.ContainsKey('foreignMarker')) {
            [IO.File]::WriteAllText((Get-QualificationCleanupBlockerPath),'synthetic-unrelated-marker')
        }
        try {
            switch($case.kind) {
                'Metadata' {. $metadataFinalizer | ForEach-Object { $replayOutput.Add($_) }}
                'Handoff' {. $handoffFinalizer | ForEach-Object { $replayOutput.Add($_) }}
                'Pipe' {. $pipeFinalizer | ForEach-Object { $replayOutput.Add($_) }}
                'Tree' {. $treeFinalizer | ForEach-Object { $replayOutput.Add($_) }}
                'Controller' {
                    $name='success'
                    $result=[pscustomobject]@{state=$(if($case.unsafe){'Unexpected'}else{'Completed'});executionStarted=$true;operations=@(1,2,3);cleanup=[pscustomobject]@{}}
                    if($case.shape.ContainsKey('value')){$result.cleanup | Add-Member NoteProperty verified $case.shape.value}
                    if($case.shape.name-eq'MissingCleanup'){$result.PSObject.Properties.Remove('cleanup')}
                    if($case.shape.name-eq'MissingResult'){$result=$null}
                    if($case.shape.name-in@('ResultSingleton','CleanupSingleton','ResultMixed','CleanupMixed')){
                        $result.cleanup | Add-Member NoteProperty verified $true
                    }
                    if($case.shape.name-eq'ResultSingleton'){$result=@($result)}
                    if($case.shape.name-eq'CleanupSingleton'){$result.cleanup=@($result.cleanup)}
                    if($case.shape.name-eq'ResultMixed'){$result=@($result,[pscustomobject]@{})}
                    if($case.shape.name-eq'CleanupMixed'){$result.cleanup=@($result.cleanup,[pscustomobject]@{})}
                    if($case.shape.name-eq'OrderedMap'){$result=[ordered]@{state='Completed';executionStarted=$true;operations=@(1,2,3);cleanup=[ordered]@{verified=$true}}}
                    # Unsafe cleanup must win over the preset wrong behavior
                    # state; replay includes the actual pre-assertion guard.
                    . $controllerTail | ForEach-Object { $replayOutput.Add($_) }
                }
            }
        }catch{$caught=$_}
        $unsafe=$null-ne$caught-and(Test-QualificationCleanupUnverified -Exception $caught.Exception)
        Assert-Equal $case.unsafe $unsafe ($case.name+' preserves actual shared unsafe disposition')
        # Consume only this injected invocation's success stream, including the
        # sentinel emitted before its terminating exception. Real outer cleanup
        # remains unredirected and the parent native guard remains fail closed.
        $signals=@($replayOutput | Where-Object { $_.ToString() -ceq 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED' })
        Assert-Equal $(if($case.unsafe){1}else{0}) $signals.Count ($case.name+' retains the expected injected cleanup signal locally')
        if($case.unsafe){Assert-Equal $true ([IO.File]::Exists((Get-QualificationCleanupBlockerPath))) 'unsafe result retains durable scheduling stop'}
        elseif(-not$case.ContainsKey('foreignMarker')){Assert-Equal $false ([IO.File]::Exists((Get-QualificationCleanupBlockerPath))) 'safe cleanup creates no stop marker'}
        if($null-ne$originalBodyError){
            Assert-Equal $true ($null-ne$caught-and$caught.Exception.ToString().Contains('Injected original fixture body failure.')) 'original body error is retained with cleanup result'
        }elseif(-not$case.unsafe){Assert-Equal $true ($null-eq$caught) 'safe path does not invent a failure'}
        if($case.kind-eq'Metadata'){
            Assert-Equal 1 $child.WaitCount 'bounded absence verification still runs after a metadata stop fault'
            Assert-Equal 1 $child.DisposeCount 'exact child disposal is attempted independently'
            Assert-Equal 1 $held.DisposeCount 'independent held handle disposal is attempted'
            Assert-Equal 1 $parent.DisposeCount 'parent handle disposal is attempted independently'
        }
        if($case.kind-in@('Handoff','Pipe')){
            $process=if($case.kind-eq'Handoff'){$child}else{$repro}
            $stdout=if($case.kind-eq'Handoff'){$childOutput}else{$output}
            $stderr=if($case.kind-eq'Handoff'){$childError}else{$errorOutput}
            Assert-Equal 1 $process.DisposeCount 'actual fixture attempts handle disposal despite earlier cleanup failure'
            Assert-Equal 1 $stdout.WaitCount 'stdout closure is independently observed'
            Assert-Equal 1 $stderr.WaitCount 'stderr closure is independently observed'
            Assert-Equal $case.unsafe ([IO.Directory]::Exists($ownedStateRoot)) 'owned state survives any missing cleanup proof and is deleted only after all proofs'
        }
        if($case.kind-eq'Tree'){
            Assert-Equal 1 $root.WaitCount 'parent absence is independently observed after stop failure'
            if($null-ne$nested){Assert-Equal 1 $nested.WaitCount 'nested absence is independently observed after stop failure'}
            Assert-Equal 1 $rootOutput.WaitCount 'parent stdout check is independent'
            Assert-Equal 1 $rootError.WaitCount 'parent stderr check is independent'
            if($null-ne$nested){Assert-Equal 1 $nested.DisposeCount 'nested handle disposal is attempted'}
            Assert-Equal 1 $root.DisposeCount 'parent handle disposal survives nested disposal failure'
            Assert-Equal $case.unsafe ([IO.Directory]::Exists($ownedStateRoot)) 'all parent, nested, stream and disposal proofs gate owned state deletion'
        }
        if($case.kind-eq'Handoff'-and$case.name-in@('HandoffKillFailure','HandoffWaitTimeout','HandoffKillAfterExit')){
            Assert-Equal 1 $child.WaitCount 'handoff bounded absence observation survives stop failure'
        }
        if($case.kind-eq'Pipe'-and$case.name-in@('PipeKillFailure','PipeWaitTimeout','PipeKillAfterExit')){
            Assert-Equal 1 $repro.WaitCount 'pipe bounded absence observation survives stop failure'
        }
        if($case.ContainsKey('foreignMarker')){
            Assert-Equal 'synthetic-unrelated-marker' ([IO.File]::ReadAllText((Get-QualificationCleanupBlockerPath))) 'verified fixture cannot clear an unrelated suite marker'
        }
        $replayResults.Add([ordered]@{case=$case.name;result='Pass';expectedUnsafe=$case.unsafe;actualUnsafe=$unsafe;capturedUnsafeSignals=$signals.Count;nativeProcessesStarted=0;bodyFailureRetained=$null-ne$originalBodyError})
    }
    $evidence=[ordered]@{recordType='win-pcinfo.actual-fixture-finalizer-replays';result='Pass';scope='Actual AST finalizers/controller assertion suffix under injected process/output faults only';nativeProcessesStarted=0;productionControllerExecuted=$false;cases=$replayResults.ToArray();inputs=@(
        'RecoveryProcessOwnership.Tests.ps1','PrivilegedExecutionPhase.Tests.ps1','QualificationCleanup.Tests.ps1','QualificationCleanup.ps1'
    ) | ForEach-Object {[ordered]@{file=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $_) -Algorithm SHA256).Hash.ToLowerInvariant()}}}
    if($env:WINPCINFO_TEST_EVIDENCE){
        [IO.File]::WriteAllText((Join-Path $env:WINPCINFO_TEST_EVIDENCE 'fixture-finalizer-replays.json'),($evidence | ConvertTo-Json -Depth 7),[Text.UTF8Encoding]::new($false))
    }
    Write-Output ('PASS: '+$replayResults.Count+' actual fixture cleanup replays; no native child or production controller execution.')
}
catch {$replayBodyError=$_}
finally {
    Set-Item -LiteralPath 'Function:Get-QualificationCleanupBlockerPath' -Value $originalBlockerFunction
    # These roots contain only this test's injected objects and synthetic data;
    # no native process was created by this replay.
    Complete-QualificationHarness -BodyError $replayBodyError -Cleanup @({
        $allowed=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
        $resolved=[IO.Path]::GetFullPath($fixtureRoot)
        if(-not$resolved.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Replay cleanup escaped its owned test root.'}
        if([IO.Directory]::Exists($resolved)){
            if(([IO.File]::GetAttributes($resolved)-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'Replay cleanup root is a reparse point.'}
            [IO.Directory]::Delete($resolved,$true)
        }
        if([IO.Directory]::Exists($resolved)){throw 'Injected replay root remains unverified.'}
    })
}
