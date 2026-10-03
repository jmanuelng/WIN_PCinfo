[CmdletBinding()]
param(
 [string]$RepositoryRoot=(Split-Path -Parent $PSScriptRoot),
 [string]$HarnessPath=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $RepositoryRoot 'tests\TestHarness.ps1')
if(-not$HarnessPath){$HarnessPath=Join-Path $RepositoryRoot 'tests\StatusDeskEngine.Tests.ps1'}
function Get-PreparationWaitActualAst {
 param([string]$Path)
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'Actual preparation wait source must parse.'}
 $loops=@($ast.FindAll({param($n)
  $n-is[Management.Automation.Language.WhileStatementAst]-and
  $n.Condition.Extent.Text.Contains('$session.Transport.State.Preparation')-and
  $n.Condition.Extent.Text.Contains('$watch.Elapsed.TotalSeconds')
 },$true))
 if($loops.Count-ne1){throw 'Actual preparation wait loop must be uniquely admitted.'}
 $commands=@($loops[0].FindAll({param($n)$n-is[Management.Automation.Language.CommandAst]},$true))
 foreach($command in $commands){
  if($command.GetCommandName()-cnotin@('Start-Sleep','Complete-StatusDeskSession')){
   throw 'Preparation wait regression refuses an unexpected command boundary.'
  }
 }
 [scriptblock]::Create($loops[0].Extent.Text)
}
function Import-PreparationWaitActualFunction {
 param([string]$Path,[string]$Name)
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'Actual controller regression source must parse.'}
 $functions=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$Name}.GetNewClosure(),$false))
 if($functions.Count-ne1){throw 'Actual controller regression function must be unique.'}
 $functions[0].Extent.Text
}
foreach($name in @('Send-StatusDeskRecord','Complete-StatusDeskSession')){
 . ([scriptblock]::Create((Import-PreparationWaitActualFunction -Path (Join-Path $RepositoryRoot 'src\StatusDesk.ps1') -Name $name)))
}
. ([scriptblock]::Create((Import-PreparationWaitActualFunction -Path (Join-Path $RepositoryRoot 'src\Contracts.ps1') -Name 'New-ProgressRecord')))
$actualWait=Get-PreparationWaitActualAst -Path $HarnessPath
function Invoke-PreparationWaitActualCase {
 param([scriptblock]$WaitBlock,[ValidateSet('DelayedPreparation','EarlyCompletion','UnsafeCompletion','TimeoutWithoutPreparation')][string]$Mode)
 $clock=[pscustomobject]@{ElapsedMilliseconds=0L}
 $watch=[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=0.0}}
 $events=[Collections.Concurrent.BlockingCollection[string]]::new(128)
 $transport=[pscustomobject]@{Events=$events;Clock=$clock;RecordGate=[object]::new();State=[hashtable]::Synchronized(@{Preparation='';Terminal='';CollectionStarted=$false;FirstProgressMilliseconds=-1L;LastProgressMilliseconds=0L;MaximumProgressGapMilliseconds=0L;ProgressSequence=0})}
 $worker=[pscustomobject]@{DisposeCalls=0;EndInvokeCalls=0;ThrowDispose=($Mode-ceq'UnsafeCompletion')}
 $worker|Add-Member -MemberType ScriptMethod -Name EndInvoke -Value {param($pending)$this.EndInvokeCalls++;20}
 $worker|Add-Member -MemberType ScriptMethod -Name Dispose -Value {$this.DisposeCalls++;if($this.ThrowDispose){throw 'Synthetic exact-owned disposal failure.'}}
 $runspace=[pscustomobject]@{DisposeCalls=0}
 $runspace|Add-Member -MemberType ScriptMethod -Name Dispose -Value {$this.DisposeCalls++}
 $session=[pscustomobject]@{Transport=$transport;Worker=$worker;Runspace=$runspace;Pending=[pscustomobject]@{IsCompleted=$false};Completed=$false;ExitCode=20}
 $steps=[pscustomobject]@{Count=0}
 function Start-Sleep {
  param([int]$Milliseconds)
  Assert-Equal 25 $Milliseconds 'actual preparation wait uses its existing sleep interval'
  $steps.Count++
  if($steps.Count-gt31){throw 'Synthetic preparation wait exceeded its finite iteration guard.'}
  $clock.ElapsedMilliseconds+=1000L
  $watch.Elapsed.TotalSeconds=$clock.ElapsedMilliseconds/1000.0
  if($Mode-ceq'DelayedPreparation'-and$clock.ElapsedMilliseconds-ge11000){
   Send-StatusDeskRecord -Transport $transport -Record ([pscustomobject]@{recordType='win-pcinfo.preparation-summary';readyForApproval=$true})
  }elseif($Mode-cin@('EarlyCompletion','UnsafeCompletion')){
   $session.Pending.IsCompleted=$true
  }
 }
 $actualError=$null
 try{
  Send-StatusDeskRecord -Transport $transport -Record (New-ProgressRecord -Sequence 0 -Phase RunControl -State Started -MessageId controller.starting-worker -CompletedUnits 0 -TotalUnits 1)
  try{& $WaitBlock}catch{$actualError=$_}
  if($Mode-ceq'UnsafeCompletion'){
   Assert-Equal $true ($null-ne$actualError) 'actual wait propagates controller finalization failure'
   Assert-Equal $true (Test-QualificationCleanupUnverified -Exception $actualError.Exception) 'actual unsafe finalization retains its cleanup-stop metadata'
   Assert-Equal 1 $worker.DisposeCalls 'actual controller attempts worker disposal'
   Assert-Equal 1 $runspace.DisposeCalls 'actual controller independently attempts runspace disposal'
   Assert-Equal $false $session.Completed 'failed disposal cannot claim completion'
  }else{
   if($null-ne$actualError){throw $actualError}
   if($Mode-ceq'EarlyCompletion'){
    Assert-Equal $true $session.Completed 'actual wait polls completion even before preparation'
    Assert-Equal $true ($null-eq$session.Pending) 'completion releases the owned pending handle'
    Assert-Equal 1 $worker.EndInvokeCalls 'the completed invocation is consumed exactly once'
    Assert-Equal 1 $worker.DisposeCalls 'the completed worker is disposed once'
    Assert-Equal 1 $runspace.DisposeCalls 'the completed runspace is disposed once'
    Assert-Equal 1 $steps.Count 'wait stops immediately after observed completion without rereading a released handle'
   }else{
    Send-StatusDeskRecord -Transport $transport -Record (New-ProgressRecord -Sequence 0 -Phase RunControl -State Heartbeat -MessageId controller.waiting-for-worker -CompletedUnits 0 -TotalUnits 1)
    $records=@($events.ToArray()|ForEach-Object{$_|ConvertFrom-Json})
    $heartbeats=@($records|Where-Object {$_.recordType-ceq'win-pcinfo.progress'-and$_.state-ceq'Heartbeat'})
    Assert-Equal $true ($heartbeats.Count-ge3) 'actual wait publishes controller heartbeats while preparation is pending'
    Assert-Equal $true ($transport.State.MaximumProgressGapMilliseconds-le10000) 'actual wait retains the original ten-second progress bound'
    if($Mode-ceq'DelayedPreparation'){
     Assert-Equal $true ([bool]$transport.State.Preparation) 'actual wait observes delayed preparation'
     Assert-Equal 11 $steps.Count 'eleven simulated seconds reach the original failure interval without wall-clock delay'
    }else{
     Assert-Equal '' $transport.State.Preparation 'timeout does not fabricate preparation'
     Assert-Equal 30 $steps.Count 'actual wait retains its thirty-second deadline'
    }
   }
  }
  Assert-Equal $false $transport.State.CollectionStarted 'waiting and finalization start no assessment collection'
  Write-Output ('PASS: actual preparation wait '+$Mode)
 }finally{$events.Dispose()}
}
foreach($mode in @('DelayedPreparation','EarlyCompletion','UnsafeCompletion','TimeoutWithoutPreparation')){
 Invoke-PreparationWaitActualCase -WaitBlock $actualWait -Mode $mode
}
Write-Output 'PASS: 4 actual-AST preparation wait regressions; synthetic clock/handles only, no workers or OS collection.'
