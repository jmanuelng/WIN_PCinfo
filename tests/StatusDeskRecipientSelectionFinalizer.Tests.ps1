[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Replay the actual nested case/fixture/candidate owning finalizers. Only the
# dialog body, timers, restoration and candidate API are recorded substitutes.
# No WPF, STA/native child, build, key/certificate, trust or process observation.
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')
function Assert-SelectionFinalizer {
    param([bool]$Condition,[string]$Message)
    if(-not $Condition){throw ('Recipient selection finalizer: '+$Message)}
}
function Test-SelectionFinalizerCause {
    param([Exception]$Outer,[Exception]$Cause)
    if([object]::ReferenceEquals($Outer,$Cause)){return $true}
    if($Outer -is [AggregateException]){foreach($inner in $Outer.InnerExceptions){if(Test-SelectionFinalizerCause $inner $Cause){return $true}}}
    if($Outer.InnerException){return (Test-SelectionFinalizerCause $Outer.InnerException $Cause)}
    $false
}
function Get-QualificationCleanupBlockerPath {Join-Path $probe.caseRoot 'pure-owned-cleanup-blocked.json'}
function Set-Item {
    param($LiteralPath,$Value,$ErrorAction)
    $probe.restores++
    Assert-SelectionFinalizer ($LiteralPath -ceq 'Function:script:Show-StatusDeskRecipientDialog' -and [object]::ReferenceEquals($Value,$originalDialog) -and $ErrorAction -ceq 'Stop') 'Restoration targets the exact original dialog in script scope.'
    if($probe.restoreFails){throw $probe.restoreError}
}
function Close-TestCandidate {
    param($Candidate,[AllowNull()][Management.Automation.ErrorRecord]$BodyError)
    $probe.closes++;$probe.closedBody=$BodyError
    Assert-SelectionFinalizer ([object]::ReferenceEquals($Candidate,$candidateContext)) 'Outer candidate closes its exact owned context.'
    if($BodyError){throw $BodyError.Exception}
}
function Replace-SelectionFinalizerBody {
    param($Ast,[string]$Body)
    $Ast.Extent.Text.Remove($Ast.Body.Extent.StartOffset-$Ast.Extent.StartOffset,$Ast.Body.Extent.EndOffset-$Ast.Body.Extent.StartOffset).Insert($Ast.Body.Extent.StartOffset-$Ast.Extent.StartOffset,$Body)
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$parent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))
$controlRoot=Join-Path $parent ('recipient-selection-finalizer-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $controlRoot -ErrorAction Stop
$controls=0;$outcomes=[Collections.Generic.List[object]]::new()
try {
    $path=Join-Path $PSScriptRoot 'StatusDeskRecipientSelection.Tests.ps1';$tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Assert-SelectionFinalizer ($errors.Count -eq 0) 'Actual GUI fixture parses.'
    $all=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.TryStatementAst] -and $null -ne $node.Finally},$true))
    $case=@($all | Where-Object {$_.Finally.Extent.Text.Contains('-BodyError $caseBodyError')})
    $fixture=@($all | Where-Object {$_.Finally.Extent.Text.Contains('-BodyError $fixtureError')})
    $candidate=@($all | Where-Object {$_.Finally.Extent.Text.Contains('Close-TestCandidate')})
    Assert-SelectionFinalizer ($case.Count -eq 1 -and $fixture.Count -eq 1 -and $candidate.Count -eq 1 -and $case[0].CatchClauses.Count -eq 1 -and $case[0].CatchClauses[0].Body.Extent.Text -ceq '{$caseBodyError=$_}') 'Actual case/fixture/candidate owners are unique and capture the original ErrorRecord.'
    $caseText=Replace-SelectionFinalizerBody $case[0] '{ if($probe.bodyFails){throw $probe.bodyError} }'
    $caseReplay=[scriptblock]::Create($caseText)
    $fixtureText=Replace-SelectionFinalizerBody $fixture[0] '{ & $caseReplay }'
    $fixtureText=$fixtureText.Replace('[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)','$probe.caseRoot')
    $fixtureReplay=[scriptblock]::Create($fixtureText)
    $candidateText=Replace-SelectionFinalizerBody $candidate[0] '{ & $fixtureReplay }'
    $pass=@($ast.EndBlock.Statements | Where-Object {$_.Extent.Text.StartsWith("Write-Output 'PASS:")})
    Assert-SelectionFinalizer ($pass.Count -eq 1) 'The actual caller has one PASS statement after owning finalization.'
    $control=[scriptblock]::Create($candidateText+[Environment]::NewLine+$pass[0].Extent.Text)
    foreach($mode in @('Success','BodyFailure','StopFailure','BodyStopFailure','RestoreFailure','BodyStopRestoreFailure','UnsafeBodyFailure')){
        $caseRoot=Join-Path $controlRoot ('case-'+($controls+1));$null=[IO.Directory]::CreateDirectory($caseRoot)
        $probe=[pscustomobject]@{caseRoot=$caseRoot;bodyFails=($mode -in @('BodyFailure','BodyStopFailure','BodyStopRestoreFailure','UnsafeBodyFailure'));stopFails=($mode -in @('StopFailure','BodyStopFailure','BodyStopRestoreFailure'));restoreFails=($mode -in @('RestoreFailure','BodyStopRestoreFailure'));
            stops=0;rootStops=0;restores=0;closes=0;closedBody=$null;bodyError=[InvalidOperationException]::new('Disclosed original dialog body error.');stopError=[InvalidOperationException]::new('Disclosed original case timer stop error.');restoreError=[InvalidOperationException]::new('Disclosed original dialog restoration error.')}
        if($mode -eq 'UnsafeBodyFailure'){$probe.bodyError.Data['OwnedCleanupUnverified']=$true}
        $caseDriver=[pscustomobject]@{Probe=$probe};$caseDriver | Add-Member ScriptMethod Stop {$this.Probe.stops++;if($this.Probe.stopFails){throw $this.Probe.stopError}}
        $driver=[pscustomobject]@{Probe=$probe};$driver | Add-Member ScriptMethod Stop {$this.Probe.rootStops++}
        $originalDialog={ 'Disclosed original dialog definition.' };$candidateContext=[pscustomobject]@{PureOwnedContext=$true}
        $root=Join-Path $caseRoot ('winpcinfo-selection-ui-'+[guid]::NewGuid().ToString('N'))
        $null=[IO.Directory]::CreateDirectory($root);[IO.File]::WriteAllText((Join-Path $root 'owned-fixture.txt'),'Owned pure fixture bytes.')
        $rootOwned=$true;$caseBodyError=$null;$fixtureError=$null;$candidateUseError=$null;$fixtureCleanupState=@{DriverStopped=$false}
        $failure=$null;$output=[Collections.Generic.List[object]]::new()
        try{& $control | ForEach-Object {$output.Add($_)}}catch{$failure=$_}
        $controls++
        $unsafe=$probe.stopFails -or $probe.restoreFails -or $mode -eq 'UnsafeBodyFailure'
        Assert-SelectionFinalizer ($probe.stops -eq 1 -and $probe.restores -eq 1 -and $probe.rootStops -eq 1 -and $probe.closes -eq 1) 'Both per-case cleanup actions and both outer owners are attempted exactly once despite body/Stop failure.'
        if($probe.bodyFails){Assert-SelectionFinalizer ($null -ne $failure -and (Test-SelectionFinalizerCause $failure.Exception $probe.bodyError)) 'Original dialog body cause survives timer, restoration and outer finalizers.'}
        if($probe.stopFails){Assert-SelectionFinalizer ($null -ne $failure -and (Test-SelectionFinalizerCause $failure.Exception $probe.stopError)) 'Original timer Stop cause survives combined finalization.'}
        if($probe.restoreFails){Assert-SelectionFinalizer ($null -ne $failure -and (Test-SelectionFinalizerCause $failure.Exception $probe.restoreError)) 'Original restoration cause survives combined finalization.'}
        Assert-SelectionFinalizer ([IO.Directory]::Exists($root) -eq $unsafe) 'Unsafe timer/body/restoration retains the exact fixture; verified ordinary cleanup removes it.'
        if($unsafe){
            Assert-SelectionFinalizer ((Test-QualificationCleanupUnverified $failure.Exception) -and [IO.File]::Exists((Get-QualificationCleanupBlockerPath)) -and [IO.File]::ReadAllText((Join-Path $root 'owned-fixture.txt')) -ceq 'Owned pure fixture bytes.') 'Unsafe marker, durable stop signal and original fixture bytes survive.'
        }
        Assert-SelectionFinalizer (@($output | Where-Object {$_ -like 'PASS:*'}).Count -eq $(if($mode -eq 'Success'){1}else{0}) -and ($null -eq $failure) -eq ($mode -eq 'Success')) 'No body or finalizer failure can emit early PASS.'
        if($mode -ne 'Success'){Assert-SelectionFinalizer ($probe.closedBody -is [Management.Automation.ErrorRecord]) 'Outer Close receives the actual captured ErrorRecord.'}
        $outcomes.Add([pscustomobject]@{mode=$mode;bodyRetained=$(if($probe.bodyFails){Test-SelectionFinalizerCause $failure.Exception $probe.bodyError}else{$null});stopRetained=$(if($probe.stopFails){Test-SelectionFinalizerCause $failure.Exception $probe.stopError}else{$null});unsafe=$unsafe;fixtureRetained=[IO.Directory]::Exists($root);passItems=@($output | Where-Object {$_ -like 'PASS:*'}).Count})
    }
}
finally {
    $resolved=[IO.Path]::GetFullPath($controlRoot)
    if(-not [IO.Path]::GetDirectoryName($resolved).Equals($parent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -cnotmatch '^recipient-selection-finalizer-[a-f0-9]{32}$'){throw 'Pure finalizer fixture cleanup escaped its owned parent.'}
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
    if([IO.Directory]::Exists($resolved)){throw 'Pure finalizer fixture cleanup remains incomplete.'}
}
Write-Output ('PASS: '+$controls+' pure actual nested recipient-selection owner controls; original body/Stop/restoration causes, unsafe fixture retention and no early PASS; native GUI pending.')
