[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

# Replay the actual harness finalization boundary, substituting only its expensive
# assessment body and controlled worker adapter. No generated application starts.
function Get-HarnessFinalization {
    param([string] $File, [string] $Body)
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $File),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Qualification harness did not parse.' }
    $statement=@($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] -and $null -ne $_.Finally })[-1]
    $source=$statement.Extent.Text
    $offset=$statement.Body.Extent.StartOffset-$statement.Extent.StartOffset
    [scriptblock]::Create($source.Remove($offset,$statement.Body.Extent.Text.Length).Insert($offset,'{'+$Body+'}'))
}

function Invoke-ExpectedQualificationHarnessFault {
    param([Parameter(Mandatory)][scriptblock] $Program,
          [Parameter(Mandatory)][string] $BlockerPath)
    $observed=@{failure=$null;blocked=$false}
    $null = & {
        function Get-QualificationCleanupBlockerPath { $BlockerPath }
        try { . $Program } catch { $observed.failure=$_ }
        try { Assert-QualificationCleanupReady } catch { $observed.blocked=$true }
    }
    # The private override has ended before the caller's real outer cleanup.
    return $observed
}

function Test-CompletedSessionCleanupFault {
    param([ValidateSet('UnsafeBody','UnsafeTerminal','MissingTerminal','InvalidRecord','MalformedTerminal','StringVerified','ArrayTerminal','NullTerminal','ArrayRecordType','ArrayOutcome','NullOutcome')][string]$Fault='UnsafeBody')
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $ownedParent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
    $testRoot=Join-Path $repositoryRoot ('.test-output/completed-unsafe-'+[guid]::NewGuid().ToString('N'))
    $resolvedRoot=[IO.Path]::GetFullPath($testRoot)
    if(-not $resolvedRoot.StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected replay cleanup root.'}
    $null=[IO.Directory]::CreateDirectory($testRoot)
    $syntheticBlocker=Join-Path $testRoot 'expected-cleanup-blocked.json'
    $journal=Join-Path $testRoot 'owned-recovery-journal.txt'
    [IO.File]::WriteAllText($journal,'synthetic owned recovery evidence')
    $FailureKind='None'
    $QualificationPath='';$qualificationFailed=$false;$qualificationBodyError=$null
    $RequireQualityBudgets=$false;$assessmentQuality=$null;$quality=[ordered]@{}
    $qualityWatch=[Diagnostics.Stopwatch]::StartNew();$qualificationArguments=[ordered]@{}
    $projection=[ordered]@{coverage=@()};$Wpf=$false;$runLock=$null;$runLockOwned=$false;$RecoveryDestination=''
    $terminalJson=if($Fault -ceq 'UnsafeTerminal'){
        '{"recordType":"win-pcinfo.terminal","outcome":"CleanupIncomplete","cleanup":{"verified":false}}'
    }else{'{"recordType":"win-pcinfo.terminal","outcome":"IntegrityFailed","cleanup":{"verified":true}}'}
    $session=[pscustomobject]@{Completed=$true;Transport=@{
        State=@{Terminal=$terminalJson}
        Cancellation=[Threading.CancellationTokenSource]::new()
        DecisionReady=[Threading.ManualResetEventSlim]::new()
        Events=[Threading.ManualResetEventSlim]::new()
    }}
    if($Fault -ceq 'MissingTerminal'){$session.Transport.State.Remove('Terminal')}
    if($Fault -ceq 'InvalidRecord'){$session.Transport.State.Terminal='{"recordType":"unexpected","outcome":"Completed","cleanup":{"verified":true}}'}
    if($Fault -ceq 'MalformedTerminal'){$session.Transport.State.Terminal='{'}
    if($Fault -ceq 'StringVerified'){$session.Transport.State.Terminal='{"recordType":"win-pcinfo.terminal","outcome":"Completed","cleanup":{"verified":"true"}}'}
    if($Fault -ceq 'ArrayTerminal'){$session.Transport.State.Terminal='[{"recordType":"win-pcinfo.terminal","outcome":"Completed","cleanup":{"verified":true}}]'}
    if($Fault -ceq 'NullTerminal'){$session.Transport.State.Terminal=$null}
    if($Fault -ceq 'ArrayRecordType'){$session.Transport.State.Terminal='{"recordType":["win-pcinfo.terminal"],"outcome":"Completed","cleanup":{"verified":true}}'}
    if($Fault -ceq 'ArrayOutcome'){$session.Transport.State.Terminal='{"recordType":"win-pcinfo.terminal","outcome":["Completed"],"cleanup":{"verified":true}}'}
    if($Fault -ceq 'NullOutcome'){$session.Transport.State.Terminal='{"recordType":"win-pcinfo.terminal","outcome":null,"cleanup":{"verified":true}}'}
    $caught=$null
    try{
        try{
            $body=if($Fault -ceq 'UnsafeBody'){
                '$failure=[InvalidOperationException]::new("Synthetic completed child cleanup uncertainty");$failure.Data["OwnedCleanupUnverified"]=$true;throw $failure'
            }else{'throw "Synthetic assertion before local terminal parsing"'}
            $observation=Invoke-ExpectedQualificationHarnessFault -BlockerPath $syntheticBlocker -Program (Get-HarnessFinalization -File 'StatusDeskEngine.Tests.ps1' -Body $body)
            $caught=$observation.failure
        }catch{$caught=$_}
        Assert-Equal $true ([IO.Directory]::Exists($testRoot)) 'a completed runspace cannot erase an unverified child recovery workspace'
        Assert-Equal 'synthetic owned recovery evidence' ([IO.File]::ReadAllText($journal)) 'unsafe body metadata preserves the exact recovery journal'
        Assert-Equal $true (Test-QualificationCleanupUnverified -Exception $caught.Exception) 'completed unsafe child metadata remains a scheduling blocker'
        Assert-Equal $true ([IO.File]::Exists($syntheticBlocker)) 'completed unsafe body produces a durable scheduling stop'
    }finally{
        $session.Transport.Cancellation.Dispose();$session.Transport.DecisionReady.Dispose();$session.Transport.Events.Dispose()
        # This replay creates no process and owns exactly this fresh synthetic root.
        if(-not [IO.Path]::GetFullPath($testRoot).StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected replay cleanup root.'}
        if([IO.Directory]::Exists($testRoot)){[IO.Directory]::Delete($testRoot,$true)}
        if([IO.Directory]::Exists($testRoot)){throw 'Controlled replay directory absence not verified.'}
        if([IO.File]::Exists($syntheticBlocker)){[IO.File]::Delete($syntheticBlocker)}
    }
}
Test-CompletedSessionCleanupFault
Test-CompletedSessionCleanupFault -Fault UnsafeTerminal
Test-CompletedSessionCleanupFault -Fault MissingTerminal
Test-CompletedSessionCleanupFault -Fault InvalidRecord
Test-CompletedSessionCleanupFault -Fault MalformedTerminal
Test-CompletedSessionCleanupFault -Fault StringVerified
Test-CompletedSessionCleanupFault -Fault ArrayTerminal
Test-CompletedSessionCleanupFault -Fault NullTerminal
Test-CompletedSessionCleanupFault -Fault ArrayRecordType
Test-CompletedSessionCleanupFault -Fault ArrayOutcome
Test-CompletedSessionCleanupFault -Fault NullOutcome

function Test-LateSessionCleanupUncertainty {
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $ownedParent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
    $testRoot=Join-Path $repositoryRoot ('.test-output/late-finalization-'+[guid]::NewGuid().ToString('N'))
    if(-not [IO.Path]::GetFullPath($testRoot).StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected replay cleanup root.'}
    $null=[IO.Directory]::CreateDirectory($testRoot)
    $syntheticBlocker=Join-Path $testRoot 'expected-cleanup-blocked.json'
    $journal=Join-Path $testRoot 'owned-recovery-journal.txt'
    [IO.File]::WriteAllText($journal,'synthetic late cleanup recovery')
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repositoryRoot 'src/StatusDesk.ps1'),[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count){throw 'Actual session finalization source did not parse.'}
    foreach($name in @('Set-StatusDeskDecision','Complete-StatusDeskSession')){
        $definition=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$false)
        if($null -eq $definition){throw 'Actual finalization function is missing.'}
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    $runspace=[RunspaceFactory]::CreateRunspace();$runspace.Open()
    $worker=[PowerShell]::Create();$worker.Runspace=$runspace
    $null=$worker.AddScript('$failure=[InvalidOperationException]::new("Synthetic late EndInvoke cleanup uncertainty");$failure.Data["OwnedCleanupUnverified"]=$true;throw $failure')
    $pending=$worker.BeginInvoke()
    $QualificationPath='';$qualificationFailed=$false;$qualificationBodyError=$null;$FailureKind='None'
    $RequireQualityBudgets=$false;$assessmentQuality=$null;$quality=[ordered]@{}
    $qualityWatch=[Diagnostics.Stopwatch]::StartNew();$qualificationArguments=[ordered]@{}
    $projection=[ordered]@{coverage=@()};$Wpf=$false;$runLock=$null;$runLockOwned=$false;$RecoveryDestination=''
    $session=[pscustomobject]@{Completed=$false;ExitCode=0;Worker=$worker;Runspace=$runspace;Pending=$pending;Transport=@{
        State=@{Terminal='{"recordType":"win-pcinfo.terminal","outcome":"Completed","cleanup":{"verified":true}}'}
        Cancellation=[Threading.CancellationTokenSource]::new()
        DecisionReady=[Threading.ManualResetEventSlim]::new()
        Events=[Threading.ManualResetEventSlim]::new()
    }}
    $caught=$null
    try{
        if(-not $pending.AsyncWaitHandle.WaitOne(5000)){throw 'Owned synthetic runspace did not finish within its bound.'}
        try{$observation=Invoke-ExpectedQualificationHarnessFault -BlockerPath $syntheticBlocker -Program (Get-HarnessFinalization -File 'StatusDeskEngine.Tests.ps1' -Body 'throw "Synthetic early ordinary assertion"'); $caught=$observation.failure}catch{$caught=$_}
        Assert-Equal $true $session.Completed 'actual EndInvoke consumes its result and disposes both exact owned handles'
        Assert-Equal $true $session.Finalization.WorkerDisposed 'late cleanup uncertainty does not skip worker disposal'
        Assert-Equal $true $session.Finalization.RunspaceDisposed 'late cleanup uncertainty does not skip runspace disposal'
        Assert-Equal $true ([IO.Directory]::Exists($testRoot)) 'unsafe EndInvoke metadata discovered during finalization preserves recovery root'
        Assert-Equal 'synthetic late cleanup recovery' ([IO.File]::ReadAllText($journal)) 'late uncertainty retains the exact recovery journal'
        Assert-Equal $true (Test-QualificationCleanupUnverified -Exception $caught.Exception) 'late unsafe result remains explicitly blocked'
        Assert-Equal $true ($caught.Exception.ToString().Contains('Synthetic early ordinary assertion')) 'early body failure remains independently retained'
        Assert-Equal $true ($caught.Exception.ToString().Contains('Synthetic late EndInvoke cleanup uncertainty')) 'late worker failure remains independently retained'
        Assert-Equal $true ([IO.File]::Exists($syntheticBlocker)) 'late unsafe result emits a durable blocker'
    }finally{
        $worker.Dispose();$runspace.Dispose()
        $session.Transport.Cancellation.Dispose();$session.Transport.DecisionReady.Dispose();$session.Transport.Events.Dispose()
        if(-not [IO.Path]::GetFullPath($testRoot).StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected replay cleanup root.'}
        if([IO.Directory]::Exists($testRoot)){[IO.Directory]::Delete($testRoot,$true)}
        if([IO.Directory]::Exists($testRoot)){throw 'Controlled replay directory absence not verified.'}
        if([IO.File]::Exists($syntheticBlocker)){[IO.File]::Delete($syntheticBlocker)}
    }
}
Test-LateSessionCleanupUncertainty

function Test-VerifiedSyntheticCleanupRelease {
    param([ValidateSet('None','Privilege','System','Standard','MissingProof','StringProof','WrongPath','InvalidPath','MemoryStream','UnsafeBody','VerifiedTerminal')][string]$Fault='None')
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $ownedParent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
    $testRoot=Join-Path $repositoryRoot ('.test-output/known-cleanup-'+[guid]::NewGuid().ToString('N'))
    if(-not [IO.Path]::GetFullPath($testRoot).StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected replay cleanup root.'}
    $null=[IO.Directory]::CreateDirectory($testRoot)
    $syntheticBlocker=Join-Path $testRoot 'expected-cleanup-blocked.json'
    $journal=Join-Path $testRoot 'synthetic-owned-evidence.txt'
    [IO.File]::WriteAllText($journal,'synthetic known file lock')
    $syntheticLock=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    $QualificationPath='';$qualificationFailed=$false;$qualificationBodyError=$null
    $RequireQualityBudgets=$false;$assessmentQuality=$null;$quality=[ordered]@{}
    $qualityWatch=[Diagnostics.Stopwatch]::StartNew();$qualificationArguments=[ordered]@{}
    $projection=[ordered]@{coverage=@()};$Wpf=$false;$runLock=$null;$runLockOwned=$false;$RecoveryDestination=''
    $FailureKind='Cleanup'
    $session=[pscustomobject]@{Completed=$true;Transport=@{
        State=@{
            Terminal='{"recordType":"win-pcinfo.terminal","outcome":"CleanupIncomplete","cleanup":{"verified":false}}'
            SyntheticLock=$syntheticLock;SyntheticLockPath=$journal
            SyntheticPrivilegeAbsent=$true;SyntheticSystemAbsent=$true;SyntheticStandardAbsent=$true
        }
        Cancellation=[Threading.CancellationTokenSource]::new()
        DecisionReady=[Threading.ManualResetEventSlim]::new()
        Events=[Threading.ManualResetEventSlim]::new()
    }}
    if($Fault -in @('Privilege','System','Standard')){$session.Transport.State['Synthetic'+$Fault+'Absent']=$false}
    if($Fault -ceq 'MissingProof'){$session.Transport.State.Remove('SyntheticSystemAbsent')}
    if($Fault -ceq 'StringProof'){$session.Transport.State.SyntheticPrivilegeAbsent='true'}
    if($Fault -ceq 'WrongPath'){$session.Transport.State.SyntheticLockPath=Join-Path $testRoot 'different-lock.txt'}
    if($Fault -ceq 'InvalidPath'){$session.Transport.State.SyntheticLockPath='invalid'+[char]0+'path'}
    if($Fault -ceq 'MemoryStream'){$syntheticLock.Dispose();$syntheticLock=[IO.MemoryStream]::new();$session.Transport.State.SyntheticLock=$syntheticLock}
    if($Fault -ceq 'VerifiedTerminal'){
        $FailureKind='None'
        $session.Transport.State.Terminal='{"recordType":"win-pcinfo.terminal","outcome":"Completed","cleanup":{"verified":true}}'
    }
    $unsafe=$Fault -notin @('None','VerifiedTerminal')
    $body=if($Fault -ceq 'UnsafeBody'){
        '$failure=[InvalidOperationException]::new("Synthetic unsafe child despite known lock release");$failure.Data["OwnedCleanupUnverified"]=$true;throw $failure'
    }else{'$null=0'}
    $caught=$null
    try{
        try{$observation=Invoke-ExpectedQualificationHarnessFault -BlockerPath $syntheticBlocker -Program (Get-HarnessFinalization -File 'StatusDeskEngine.Tests.ps1' -Body $body)
            $caught=$observation.failure}catch{$caught=$_}
        Assert-Equal $false $syntheticLock.CanRead 'the exact fixture FileStream is closed'
        Assert-Equal $unsafe ([IO.Directory]::Exists($testRoot)) 'only exact lock release with every independent native absence proof permits fixture cleanup'
        Assert-Equal (-not $unsafe) ($null -eq $caught) 'missing, false or mistyped proofs and unsafe body metadata block further scheduling'
        Assert-Equal $unsafe ([IO.File]::Exists($syntheticBlocker)) 'unsafe fixture recovery stays durably blocked'
        if($unsafe){
            Assert-Equal $true (Test-QualificationCleanupUnverified -Exception $caught.Exception) 'unsafe fixture cleanup is explicitly unverified'
            Assert-Equal 'synthetic known file lock' ([IO.File]::ReadAllText($journal)) 'unsafe fixture preserves its exact recovery evidence'
        }
    }finally{
        $syntheticLock.Dispose()
        $session.Transport.Cancellation.Dispose();$session.Transport.DecisionReady.Dispose();$session.Transport.Events.Dispose()
        if(-not [IO.Path]::GetFullPath($testRoot).StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected replay cleanup root.'}
        if([IO.Directory]::Exists($testRoot)){[IO.Directory]::Delete($testRoot,$true)}
        if([IO.Directory]::Exists($testRoot)){throw 'Controlled replay directory absence not verified.'}
        if([IO.File]::Exists($syntheticBlocker)){[IO.File]::Delete($syntheticBlocker)}
    }
}
Test-VerifiedSyntheticCleanupRelease
foreach($fault in @('Privilege','System','Standard','MissingProof','StringProof','WrongPath','InvalidPath','MemoryStream','UnsafeBody','VerifiedTerminal')){
    Test-VerifiedSyntheticCleanupRelease -Fault $fault
}

function Test-StatusDeskRetentionFailure {
    param([ValidateSet('Write','Sampling','Serialization','Worker')] [string] $Fault = 'Write')
    # Match the actual harness's ordinary plan-fault parameter default.
    $QualificationPlanFault=''
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $testRoot=Join-Path $repositoryRoot ('.test-output/cleanup-negative-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($testRoot)
    $syntheticBlocker=Join-Path $testRoot 'expected-cleanup-blocked.json'
    $sentinel=Join-Path $testRoot 'owned.txt'
    [IO.File]::WriteAllText($sentinel,'synthetic owned fixture')
    # Opening a directory as a file gives a real access-denial write failure.
    $QualificationPath=Join-Path $testRoot 'denied-output'
    $null=[IO.Directory]::CreateDirectory($QualificationPath)
    $qualificationFailed=$false; $projection=[ordered]@{coverage=@()}
    $qualificationBodyError=$null
    $RequireQualityBudgets=$false; $assessmentQuality=$null
    $memoryCalibrationAccepted=$false; $diskInstrumentationAccepted=$false; $memoryCalibrationSha256=''
    $qualificationArguments=[ordered]@{}; $qualityWatch=[Diagnostics.Stopwatch]::StartNew()
    $quality=[ordered]@{}; $Wpf=$false; $RecoveryDestination=''
    $runLock=[Threading.Mutex]::new($false); $runLockOwned=$runLock.WaitOne(0)
    $syntheticLock=[IO.MemoryStream]::new()
    $session=[pscustomobject]@{Completed=$false; Transport=@{
        State=@{SyntheticLock=$syntheticLock}; Cancellation=[Threading.CancellationTokenSource]::new()
        DecisionReady=[Threading.ManualResetEventSlim]::new(); Events=[Threading.ManualResetEventSlim]::new()
    }}
    $witness=@{cancelled=$false; completed=$false}
    function Measure-QualificationWorkload {
        if ($Fault -eq 'Sampling') { throw [UnauthorizedAccessException]::new('Synthetic sampler access denial') }
    }
    function ConvertTo-Json {
        [CmdletBinding()]
        param([Parameter(ValueFromPipeline)] $InputObject, [int] $Depth)
        process {
            if ($Fault -eq 'Serialization') { throw [InvalidOperationException]::new('Synthetic serialization failure') }
            Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $InputObject -Depth $Depth
        }
    }
    function Set-StatusDeskDecision { param($Session,$Approve,$PlanDigest) }
    function Complete-StatusDeskSession {
        param($Session)
        $witness.cancelled=$Session.Transport.Cancellation.IsCancellationRequested
        if ($Fault -eq 'Worker') { throw 'Synthetic owned worker remains active' }
        # This adapter creates no process and reports its proved synthetic
        # completion explicitly; production deletion requires terminal evidence.
        $Session.Transport.State.Terminal='{"recordType":"win-pcinfo.terminal","outcome":"IntegrityFailed","cleanup":{"verified":true}}'
        $witness.completed=$true; $Session.Completed=$true; return $true
    }
    $errorRecord=$null
    try {
        $observation=Invoke-ExpectedQualificationHarnessFault -BlockerPath $syntheticBlocker -Program (Get-HarnessFinalization -File 'StatusDeskEngine.Tests.ps1' -Body "throw 'Synthetic body failure'")
        $errorRecord=$observation.failure
    }
    catch { $errorRecord=$_ }
    try {
        if ($Fault -eq 'Worker') {
            Assert-Equal $true ([IO.Directory]::Exists($testRoot)) 'an unverified worker preserves its recovery workspace'
            Assert-Equal $true ([IO.File]::Exists($syntheticBlocker)) 'unverified cleanup creates a durable stop signal'
            $blocked=$observation.blocked
            Assert-Equal $true $blocked 'unverified cleanup blocks further qualification execution'
            Assert-Equal $true ($errorRecord.Exception.ToString().Contains('Synthetic owned worker remains active')) 'cleanup failure survives alongside body and evidence failures'
            Assert-Equal $true ($errorRecord.Exception.ToString().Contains('Synthetic body failure')) 'unverified cleanup preserves the original body failure'
            Assert-Equal $true ($errorRecord.Exception.ToString().Contains('evidence retention failed')) 'unverified cleanup preserves the evidence failure'
            return
        }
        Assert-Equal $false ([IO.Directory]::Exists($testRoot)) 'retention failure still removes its owned test workspace'
        Assert-Equal $true $witness.cancelled 'retention failure still requests owned worker cancellation'
        Assert-Equal $true $witness.completed 'retention failure still waits for owned worker completion'
        Assert-Equal $false $syntheticLock.CanRead 'retention failure still disposes its synthetic lock'
        $mutexDisposed=$false
        try { $null=$runLock.WaitOne(0) } catch [ObjectDisposedException] { $mutexDisposed=$true }
        Assert-Equal $true $mutexDisposed 'retention failure still releases and disposes its owned mutex'
        Assert-Equal $true ($null -ne $errorRecord) 'retention failure cannot become a passing qualification'
        Assert-Equal $true ($errorRecord.Exception -is [AggregateException]) 'body and retention errors remain independently inspectable'
        Assert-Equal $true ($errorRecord.Exception.ToString().Contains('Synthetic body failure')) 'retention failure does not mask the body failure'
        Assert-Equal $true ($errorRecord.Exception.ToString().Contains('evidence retention failed')) 'retention failure is recorded alongside the body failure'
    }
    finally {
        $session.Transport.Cancellation.Dispose(); $session.Transport.DecisionReady.Dispose(); $session.Transport.Events.Dispose()
        $syntheticLock.Dispose(); $runLock.Dispose()
        if ([IO.Directory]::Exists($testRoot)) { [IO.Directory]::Delete($testRoot,$true) }
        if ($Fault -eq 'Worker') {
            # The controlled worker adapter creates no process. Its owned handles
            # and directory have now been verified absent before removing its flag.
            if ([IO.Directory]::Exists($testRoot)) { throw 'Synthetic worker cleanup remains unverified.' }
            if([IO.File]::Exists($syntheticBlocker)){[IO.File]::Delete($syntheticBlocker)}
        }
    }
}

Test-StatusDeskRetentionFailure
Test-StatusDeskRetentionFailure -Fault Sampling
Test-StatusDeskRetentionFailure -Fault Serialization
Test-StatusDeskRetentionFailure -Fault Worker
function Test-WrapperRetentionFailure {
    param([string] $File, [switch] $UnsafeChild)
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $root=Join-Path $repositoryRoot ('.test-output/wrapper-negative-'+[guid]::NewGuid().ToString('N'))
    $resultRoot=$root; $null=[IO.Directory]::CreateDirectory($root)
    $syntheticBlocker=Join-Path $root 'expected-cleanup-blocked.json'
    $resultPath=Join-Path $root 'synthetic-summary.json'
    [IO.File]::WriteAllText($resultPath,'{"synthetic":true}')
    $blockedDestination=Join-Path $root 'not-a-directory'
    [IO.File]::WriteAllText($blockedDestination,'synthetic destination blocker')
    $previousEvidence=$env:WINPCINFO_TEST_EVIDENCE
    $env:WINPCINFO_TEST_EVIDENCE=$blockedDestination
    $bodyError=$null; $errorRecord=$null
    try {
        $body=if ($UnsafeChild) { '$failure=[InvalidOperationException]::new("Synthetic wrapper body failure"); $failure.Data["OwnedCleanupUnverified"]=$true; throw $failure' } else { "throw 'Synthetic wrapper body failure'" }
        try { $observation=Invoke-ExpectedQualificationHarnessFault -BlockerPath $syntheticBlocker -Program (Get-HarnessFinalization -File $File -Body $body); $errorRecord=$observation.failure }
        catch { $errorRecord=$_ }
        Assert-Equal ([bool]$UnsafeChild) ([IO.Directory]::Exists($root)) "$File preserves unsafe child state and otherwise removes its owned workspace"
        Assert-Equal $true ($null -ne $errorRecord) "$File cannot pass after retention failure"
        Assert-Equal $true ($errorRecord.Exception.ToString().Contains('Synthetic wrapper body failure')) "$File preserves its body failure"
        Assert-Equal $true ($errorRecord.Exception.ToString().Contains('evidence retention failed')) "$File preserves its retention failure"
    }
    finally {
        $env:WINPCINFO_TEST_EVIDENCE=$previousEvidence
        if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root,$true) }
        if ($UnsafeChild) {
            if ([IO.Directory]::Exists($root)) { throw 'Controlled wrapper cleanup remains unverified.' }
            if([IO.File]::Exists($syntheticBlocker)){[IO.File]::Delete($syntheticBlocker)}
        }
    }
}
Test-WrapperRetentionFailure -File 'AssessmentSafetyQualification.Tests.ps1'
Test-WrapperRetentionFailure -File 'OfficialSchemaQualification.Tests.ps1'
Test-WrapperRetentionFailure -File 'AssessmentSafetyQualification.Tests.ps1' -UnsafeChild
Test-WrapperRetentionFailure -File 'OfficialSchemaQualification.Tests.ps1' -UnsafeChild

function Test-StatusDeskCleanupProjection {
    param([switch] $Recovery)
    # Match the actual harness's ordinary plan-fault parameter default.
    $QualificationPlanFault=''
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $testRoot=Join-Path $repositoryRoot ('.test-output/projection-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($testRoot)
    $QualificationPath=$testRoot+'.json'
    $neighbor=$testRoot+'.neighbor'; $null=[IO.Directory]::CreateDirectory($neighbor)
    $neighborFile=Join-Path $neighbor 'unrelated.txt'; [IO.File]::WriteAllText($neighborFile,'unrelated synthetic content')
    $qualificationFailed=$false; $qualificationBodyError=$null
    $RequireQualityBudgets=$false; $assessmentQuality=$null
    $memoryCalibrationAccepted=$false; $diskInstrumentationAccepted=$false; $memoryCalibrationSha256=''
    $projection=[ordered]@{coverage=@()}; $qualificationArguments=[ordered]@{}
    $qualityWatch=[Diagnostics.Stopwatch]::StartNew(); $quality=[ordered]@{htmlBytes=0L}
    $Wpf=$false; $session=$null; $runLock=$null; $runLockOwned=$false; $RecoveryDestination=''
    if ($Recovery) { $RecoveryDestination=$testRoot }
    function Measure-QualificationWorkload {}
    try {
        . (Get-HarnessFinalization -File 'StatusDeskEngine.Tests.ps1' -Body '$html="Synthetic report"')
        $evidence=Get-Content -LiteralPath $QualificationPath -Raw | ConvertFrom-Json
        Assert-Equal 16 $evidence.quality.htmlBytes 'retained qualification records the exact nonzero report size'
        Assert-Equal $(if ($Recovery) {'RetainedForRecoveryTest'} else {'VerifiedAbsent'}) $evidence.testCleanup 'cleanup evidence preserves its exact recovery or absence disposition'
        Assert-Equal ([bool]$Recovery) ([IO.Directory]::Exists($testRoot)) 'only the explicit recovery case retains its owned workspace'
        Assert-Equal 'unrelated synthetic content' ([IO.File]::ReadAllText($neighborFile)) 'owned cleanup leaves an unrelated neighboring directory intact'
    }
    finally {
        if ([IO.Directory]::Exists($testRoot)) { [IO.Directory]::Delete($testRoot,$true) }
        [IO.File]::Delete($QualificationPath)
        [IO.Directory]::Delete($neighbor,$true)
    }
}
Test-StatusDeskCleanupProjection
Test-StatusDeskCleanupProjection -Recovery

function Test-NativeCleanupFailure {
    $nativeRoot=Join-Path (Split-Path $PSScriptRoot) ('.test-output/native-cleanup-'+[guid]::NewGuid().ToString('N'))
    $nativeTests=Join-Path $nativeRoot 'tests'; $null=[IO.Directory]::CreateDirectory($nativeTests)
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'QualificationCleanup.ps1') -Destination $nativeTests
    $childPath=Join-Path $nativeTests 'child.ps1'
    [IO.File]::WriteAllText($childPath, @'
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')
# A file in place of the parent makes marker retention fail without leaving a
# marker file or marker directory. No application or worker process is started.
$nativeOutput=Join-Path (Split-Path $PSScriptRoot) '.test-output'
$null=[IO.Directory]::CreateDirectory($nativeOutput)
[IO.File]::WriteAllText((Join-Path $nativeOutput 'blocked-parent'),'synthetic parent collision')
function Get-QualificationCleanupBlockerPath { Join-Path (Split-Path $PSScriptRoot) '.test-output/blocked-parent/marker.json' }
Complete-QualificationHarness -Cleanup @({throw 'Synthetic native cleanup failure'})
'@)
    try {
        $failure=$null
        try { Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-File',$childPath) | Out-Null }
        catch { $failure=$_ }
        Assert-Equal $true ($null -ne $failure) 'a native cleanup failure cannot become a passing case'
        Assert-Equal $true (Test-QualificationCleanupUnverified -Exception $failure.Exception) 'native cleanup state propagates even when no stop marker can be retained'

        # Exercise an existing wrapper and the actual suite runner, substituting
        # only build/runtime discovery and the child assessment boundary.
        Copy-Item -LiteralPath $childPath -Destination (Join-Path $nativeTests 'StatusDeskEngine.Tests.ps1')
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'CertificateSourceApplication.Tests.ps1') -Destination (Join-Path $nativeTests 'A.Tests.ps1')
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Run-Tests.ps1') -Destination $nativeTests
        [IO.File]::WriteAllText((Join-Path $nativeTests 'TestHarness.ps1'), @'
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')
Assert-QualificationCleanupReady
function Resolve-WinPCInfoRuntime { param($ApplicationPath) Join-Path $PSHOME 'pwsh.exe' }
'@)
        $nativeBuild=Join-Path $nativeRoot 'build'; $null=[IO.Directory]::CreateDirectory($nativeBuild)
        [IO.File]::WriteAllText((Join-Path $nativeBuild 'Build.ps1'),'param($OutputPath)')
        [IO.File]::WriteAllText((Join-Path $nativeTests 'B.Tests.ps1'),"Write-Output 'SYNTHETIC_NEXT_WRAPPER_EXECUTED'")
        $suiteOutput=& (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -File (Join-Path $nativeTests 'Run-Tests.ps1') 2>&1
        Assert-Equal $true ($LASTEXITCODE -ne 0) 'unsafe cleanup from an existing wrapper fails the suite'
        Assert-Equal $false (($suiteOutput -join "`n").Contains('SYNTHETIC_NEXT_WRAPPER_EXECUTED')) 'an existing native wrapper blocks the next suite test despite unavailable marker persistence'
        [IO.File]::WriteAllText((Join-Path $nativeTests 'StatusDeskEngine.Tests.ps1'),"Write-Output 'PASS: Synthetic child assessment boundary'")
        $suiteOutput=& (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -File (Join-Path $nativeTests 'Run-Tests.ps1') 2>&1
        Assert-Equal 0 $LASTEXITCODE 'the existing wrapper still completes successful native cases'
        Assert-Equal $true (($suiteOutput -join "`n").Contains('SYNTHETIC_NEXT_WRAPPER_EXECUTED')) 'verified native completion permits subsequent suite tests'
    }
    finally { if ([IO.Directory]::Exists($nativeRoot)) { [IO.Directory]::Delete($nativeRoot,$true) } }
}
Test-NativeCleanupFailure

function Test-RecoveryParentCleanupFailure {
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $allowedRoot=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
    $testRoot=Join-Path $repositoryRoot ('.test-output/recovery-parent-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($testRoot)
    $syntheticBlocker=Join-Path $testRoot 'expected-cleanup-blocked.json'
    $child=$null; $ownedProcesses=[Collections.Generic.List[Diagnostics.Process]]::new(); $recoveryBodyError=$null
    $recoveryCleanup=@{childOutputVerified=$false;descendantsAbsent=$false}; $interrupted=$false
    $failure=$null
    try {
        try {
            $observation=Invoke-ExpectedQualificationHarnessFault -BlockerPath $syntheticBlocker -Program (Get-HarnessFinalization -File 'StatusDeskRecovery.Tests.ps1' -Body '$failure=[InvalidOperationException]::new("Synthetic recovery child failure"); $failure.Data["OwnedCleanupUnverified"]=$true; throw $failure')
            $failure=$observation.failure
        }
        catch { $failure=$_ }
        Assert-Equal $true ([IO.Directory]::Exists($testRoot)) 'recovery parent preserves unverified child recovery state'
        Assert-Equal $true (Test-QualificationCleanupUnverified -Exception $failure.Exception) 'recovery parent keeps unsafe state through its own finalization'
        Assert-Equal $true ($failure.Exception.ToString().Contains('Synthetic recovery child failure')) 'recovery cleanup does not erase the body failure'
    }
    finally {
        if ([IO.Directory]::Exists($testRoot)) { [IO.Directory]::Delete($testRoot,$true) }
        if ([IO.Directory]::Exists($testRoot)) { throw 'Controlled recovery-parent cleanup remains unverified.' }
        if([IO.File]::Exists($syntheticBlocker)){[IO.File]::Delete($syntheticBlocker)}
    }
}
Test-RecoveryParentCleanupFailure

function Test-RecoveryChildFailureAfterHandoff {
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $allowedRoot=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
    $testRoot=Join-Path $repositoryRoot ('.test-output/recovery-handoff-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($testRoot)
    $handoffPath=Join-Path $testRoot 'synthetic-handoff'
    $childPath=Join-Path $testRoot 'child.ps1'
    [IO.File]::WriteAllText($childPath, @'
param([string] $HandoffPath)
[IO.File]::WriteAllText($HandoffPath,'synthetic handoff')
Write-Output 'QUALIFICATION.OWNED_CLEANUP_UNVERIFIED'
exit 1
'@)
    $start=[Diagnostics.ProcessStartInfo]::new(); $start.FileName=Join-Path $PSHOME 'pwsh.exe'
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    foreach ($argument in @('-NoLogo','-NoProfile','-File',$childPath,'-HandoffPath',$handoffPath)) { $start.ArgumentList.Add($argument) }
    $child=$null; $childOutput=$null; $childError=$null
    $handoffFixtureBodyError=$null
    $handoffFixtureCleanup=@{stopCompleted=$false;childAbsent=$false;outputClosed=$false;errorClosed=$false;handleDisposed=$false}
    $ownedProcesses=[Collections.Generic.List[Diagnostics.Process]]::new(); $recoveryBodyError=$null
    $recoveryCleanup=@{childOutputVerified=$false;descendantsAbsent=$false}; $interrupted=$false
    try {
        $child=[Diagnostics.Process]::Start($start)
        $childOutput=$child.StandardOutput.ReadToEndAsync(); $childError=$child.StandardError.ReadToEndAsync()
        Assert-Equal $true $child.WaitForExit(5000) 'controlled child completes without a live application'
        $handoffFixtureCleanup.childAbsent=$true
        Assert-Equal $true ([IO.File]::Exists($handoffPath)) 'controlled child creates its handoff before failing'
        $expectedHandoff=@{failure=$null}
        # Confine the intentionally unsafe signal to this fixture's owned root.
        # Real outer cleanup failures still use the suite's global stop marker.
        $null = & {
            function Get-QualificationCleanupBlockerPath { Join-Path $testRoot 'expected-cleanup-blocked.json' }
            try { . (Get-HarnessFinalization -File 'StatusDeskRecovery.Tests.ps1' -Body "throw 'Synthetic recovery discovery failure'") }
            catch { $expectedHandoff.failure=$_ }
        }
        $failure=$expectedHandoff.failure
        Assert-Equal $true ([IO.Directory]::Exists($testRoot)) 'post-handoff unsafe cleanup retains recovery state'
        Assert-Equal $true (Test-QualificationCleanupUnverified -Exception $failure.Exception) 'post-handoff unsafe signal blocks subsequent execution'
    }
    catch {$handoffFixtureBodyError=$_}
    finally {
        Complete-QualificationHarness -BodyError $handoffFixtureBodyError -Cleanup @(
            {
                # The inner finalizer can dispose this handle after the body
                # has proved exit; retain that actual observation explicitly.
                if (-not $handoffFixtureCleanup.childAbsent) {
                    if ($null -eq $child) { throw 'Controlled handoff child admission remains unverified.' }
                    if (-not $child.HasExited) { $child.Kill($true) }
                }
                $handoffFixtureCleanup.stopCompleted=$true
            },
            {
                if (-not $handoffFixtureCleanup.childAbsent) {
                    if ($null -eq $child -or -not $child.WaitForExit(5000)) { throw 'Controlled handoff child remains active.' }
                    $handoffFixtureCleanup.childAbsent=$true
                }
            },
            {
                if ($null -eq $childOutput -or -not $childOutput.Wait(5000)) {
                    throw 'Controlled handoff child output remains unverified.'
                }
                $handoffFixtureCleanup.outputClosed=$true
            },
            {
                if ($null -eq $childError -or -not $childError.Wait(5000)) {
                    throw 'Controlled handoff child error output remains unverified.'
                }
                $handoffFixtureCleanup.errorClosed=$true
            },
            {
                if ($null -ne $child) {$child.Dispose()}
                $handoffFixtureCleanup.handleDisposed=$true
            },
            {
                if (-not $handoffFixtureCleanup.stopCompleted -or -not $handoffFixtureCleanup.childAbsent -or -not $handoffFixtureCleanup.outputClosed -or
                    -not $handoffFixtureCleanup.errorClosed -or -not $handoffFixtureCleanup.handleDisposed) {
                    throw 'Preserve unverified handoff fixture recovery state.'
                }
                if ([IO.Directory]::Exists($testRoot)) { [IO.Directory]::Delete($testRoot,$true) }
                if ([IO.Directory]::Exists($testRoot)) { throw 'Controlled handoff fixture cleanup remains unverified.' }
            }
        )
    }
}
Test-RecoveryChildFailureAfterHandoff

function Test-RecoveryExitedChildWithIncompleteOutput {
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $root=Join-Path $repositoryRoot ('.test-output/recovery-pipe-'+[guid]::NewGuid().ToString('N'))
    $testRoot=Join-Path $root 'assessment'; $null=[IO.Directory]::CreateDirectory($testRoot)
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'StatusDeskRecovery.Tests.ps1'),[ref]$null,[ref]$null)
    $mainTry=@($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })[-1]
    $early=@($mainTry.Body.Statements | Where-Object { $_ -is [Management.Automation.Language.IfStatementAst] -and $_.Clauses[0].Item1.Extent.Text -match '^\$child.HasExited$' })
    if ($early.Count -ne 1) { throw 'Recovery exited-child boundary is not unique.' }
    $boundary=(Get-HarnessFinalization -File 'StatusDeskRecovery.Tests.ps1' -Body $early[0].Extent.Text).ToString()
    $source=@'
$ErrorActionPreference='Stop'
. '__HELPER__'
function Get-QualificationCleanupBlockerPath { '__BLOCKER__' }
$testRoot='__ROOT__'; $allowedRoot='__ALLOWED__'
$recoveryBodyError=$null; $recoveryCleanup=@{childOutputVerified=$false;descendantsAbsent=$false}; $interrupted=$false
$ownedProcesses=[Collections.Generic.List[Diagnostics.Process]]::new()
$child=[pscustomobject]@{HasExited=$true;ExitCode=1}
$child | Add-Member ScriptMethod WaitForExit {param($Milliseconds) $true}
$child | Add-Member ScriptMethod Dispose {}
$pending=[Threading.Tasks.TaskCompletionSource[string]]::new()
$childOutput=$pending.Task; $childError=[Threading.Tasks.Task]::FromResult[string]('')
$handoffPath=Join-Path $testRoot 'handoff'; [IO.File]::WriteAllText($handoffPath,'synthetic')
try {
__BOUNDARY__
} catch {
    if (-not (Test-QualificationCleanupUnverified -Exception $_.Exception)) { throw }
    if (-not [IO.Directory]::Exists($testRoot)) { throw 'Incomplete output lost its owned recovery state.' }
    Write-Output 'SYNTHETIC_INCOMPLETE_PIPE_BLOCKED'
}
'@
    foreach ($replacement in @{
        '__HELPER__'=(Join-Path $PSScriptRoot 'QualificationCleanup.ps1').Replace("'","''")
        '__BLOCKER__'=(Join-Path $root 'blocked.json').Replace("'","''")
        '__ROOT__'=$testRoot.Replace("'","''")
        '__ALLOWED__'=([IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar).Replace("'","''")
        '__BOUNDARY__'=$boundary
    }.GetEnumerator()) { $source=$source.Replace($replacement.Key,$replacement.Value) }
    $reproPath=Join-Path $root 'repro.ps1'; [IO.File]::WriteAllText($reproPath,$source)
    $start=[Diagnostics.ProcessStartInfo]::new(); $start.FileName=Join-Path $PSHOME 'pwsh.exe'
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    foreach ($argument in @('-NoLogo','-NoProfile','-File',$reproPath)) { $start.ArgumentList.Add($argument) }
    $repro=$null; $output=$null; $errorOutput=$null
    $pipeFixtureBodyError=$null
    $pipeFixtureCleanup=@{stopCompleted=$false;childAbsent=$false;outputClosed=$false;errorClosed=$false;handleDisposed=$false}
    try {
        $repro=[Diagnostics.Process]::Start($start)
        $output=$repro.StandardOutput.ReadToEndAsync(); $errorOutput=$repro.StandardError.ReadToEndAsync()
        Assert-Equal $true $repro.WaitForExit(8000) 'exited child with incomplete output reaches bounded cleanup instead of hanging before finally'
        $pipeFixtureCleanup.childAbsent=$true
        Assert-Equal $true $errorOutput.Wait(5000) 'pipe fixture error output closes before reading its result'
        Assert-Equal $true $output.Wait(5000) 'pipe fixture standard output closes before reading its result'
        Assert-Equal 0 $repro.ExitCode ('incomplete-output boundary completes honestly: '+$errorOutput.GetAwaiter().GetResult())
        Assert-Equal $true ($output.GetAwaiter().GetResult().Contains('SYNTHETIC_INCOMPLETE_PIPE_BLOCKED')) 'bounded output loss blocks further execution'
    }
    catch {$pipeFixtureBodyError=$_}
    finally {
        Complete-QualificationHarness -BodyError $pipeFixtureBodyError -Cleanup @(
            {
                if (-not $pipeFixtureCleanup.childAbsent) {
                    if ($null -eq $repro) { throw 'Owned pipe fixture child admission remains unverified.' }
                    if (-not $repro.HasExited) { $repro.Kill($true) }
                }
                $pipeFixtureCleanup.stopCompleted=$true
            },
            {
                if (-not $pipeFixtureCleanup.childAbsent) {
                    if ($null -eq $repro -or -not $repro.WaitForExit(5000)) { throw 'Owned pipe regression remains active.' }
                    $pipeFixtureCleanup.childAbsent=$true
                }
            },
            {
                if ($null -eq $output -or -not $output.Wait(5000)) {
                    throw 'Owned pipe fixture output remains unverified.'
                }
                $pipeFixtureCleanup.outputClosed=$true
            },
            {
                if ($null -eq $errorOutput -or -not $errorOutput.Wait(5000)) {
                    throw 'Owned pipe fixture error output remains unverified.'
                }
                $pipeFixtureCleanup.errorClosed=$true
            },
            {
                if ($null -ne $repro) {$repro.Dispose()}
                $pipeFixtureCleanup.handleDisposed=$true
            },
            {
                if (-not $pipeFixtureCleanup.stopCompleted -or -not $pipeFixtureCleanup.childAbsent -or -not $pipeFixtureCleanup.outputClosed -or
                    -not $pipeFixtureCleanup.errorClosed -or -not $pipeFixtureCleanup.handleDisposed) {
                    throw 'Preserve unverified pipe fixture recovery state.'
                }
                if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root,$true) }
                if ([IO.Directory]::Exists($root)) { throw 'Owned pipe fixture recovery state remains present.' }
            }
        )
    }
}
Test-RecoveryExitedChildWithIncompleteOutput
Write-Output 'PASS: evidence retention failure cannot bypass owned qualification cleanup.'


function Test-ExpectedFaultMarkersPreserveForeignHold {
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $allowed=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
    $sentinelRoot=Join-Path $repositoryRoot ('.test-output/foreign-hold-'+[guid]::NewGuid().ToString('N'))
    if(-not [IO.Path]::GetFullPath($sentinelRoot).StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected sentinel root.'}
    $null=[IO.Directory]::CreateDirectory($sentinelRoot)
    $foreignHold=Join-Path $sentinelRoot 'qualification-cleanup-blocked.json'
    $sentinelBytes=[Text.UTF8Encoding]::new($false).GetBytes('{"owner":"synthetic-unrelated-review","state":"ReviewHold"}')
    [IO.File]::WriteAllBytes($foreignHold,$sentinelBytes)
    $sentinelBodyError=$null
    try {
        $null = & {
            function Get-QualificationCleanupBlockerPath { $foreignHold }
            $programs=@(
                { Test-CompletedSessionCleanupFault },
                { Test-LateSessionCleanupUncertainty },
                { Test-VerifiedSyntheticCleanupRelease -Fault UnsafeBody },
                { Test-StatusDeskRetentionFailure -Fault Worker },
                { Test-WrapperRetentionFailure -File 'AssessmentSafetyQualification.Tests.ps1' -UnsafeChild },
                { Test-RecoveryParentCleanupFailure }
            )
            foreach($program in $programs){
                & $program
                Assert-Equal $true ([IO.File]::Exists($foreignHold)) 'actual expected-fault caller preserves a foreign hold'
                Assert-Equal ([Convert]::ToBase64String($sentinelBytes)) ([Convert]::ToBase64String([IO.File]::ReadAllBytes($foreignHold))) 'foreign hold bytes remain exact'
                Assert-Equal $foreignHold (Get-QualificationCleanupBlockerPath) 'expected-fault scope restores the caller marker path'
                $blocked=$false
                try { Assert-QualificationCleanupReady } catch { $blocked=$_.Exception.Message.StartsWith('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED:') }
                Assert-Equal $true $blocked 'foreign hold still blocks scheduling after expected-fault replay'
            }
        }
        Write-Output 'PASS: all six actual expected-fault callers preserve an unrelated scheduling hold.'
    } catch { $sentinelBodyError=$_ }
    finally {
        # Only this fresh synthetic sentinel root is owned. The child override
        # has ended, so an unexpected cleanup failure blocks the real suite.
        Complete-QualificationHarness -BodyError $sentinelBodyError -Cleanup @({
            $resolved=[IO.Path]::GetFullPath($sentinelRoot)
            if(-not $resolved.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected sentinel cleanup root.'}
            if([IO.Directory]::Exists($resolved)){
                if(([IO.File]::GetAttributes($resolved)-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'Sentinel root is a reparse point.'}
                [IO.Directory]::Delete($resolved,$true)
            }
            if([IO.Directory]::Exists($resolved)){throw 'Synthetic sentinel root remains.'}
        })
    }
}
Test-ExpectedFaultMarkersPreserveForeignHold
