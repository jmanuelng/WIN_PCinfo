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

function Test-StatusDeskRetentionFailure {
    param([ValidateSet('Write','Sampling','Serialization','Worker')] [string] $Fault = 'Write')
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $testRoot=Join-Path $repositoryRoot ('.test-output/cleanup-negative-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($testRoot)
    $sentinel=Join-Path $testRoot 'owned.txt'
    [IO.File]::WriteAllText($sentinel,'synthetic owned fixture')
    # Opening a directory as a file gives a real access-denial write failure.
    $QualificationPath=Join-Path $testRoot 'denied-output'
    $null=[IO.Directory]::CreateDirectory($QualificationPath)
    $qualificationFailed=$false; $projection=[ordered]@{coverage=@()}
    $qualificationBodyError=$null
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
        $witness.completed=$true; $Session.Completed=$true; return $true
    }
    $errorRecord=$null
    try {
        . (Get-HarnessFinalization -File 'StatusDeskEngine.Tests.ps1' -Body "throw 'Synthetic body failure'")
    }
    catch { $errorRecord=$_ }
    try {
        if ($Fault -eq 'Worker') {
            Assert-Equal $true ([IO.Directory]::Exists($testRoot)) 'an unverified worker preserves its recovery workspace'
            Assert-Equal $true ([IO.File]::Exists((Get-QualificationCleanupBlockerPath))) 'unverified cleanup creates a durable stop signal'
            $blocked=$false
            try { Assert-QualificationCleanupReady } catch { $blocked=$true }
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
            [IO.File]::Delete((Get-QualificationCleanupBlockerPath))
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
    $resultPath=Join-Path $root 'synthetic-summary.json'
    [IO.File]::WriteAllText($resultPath,'{"synthetic":true}')
    $blockedDestination=Join-Path $root 'not-a-directory'
    [IO.File]::WriteAllText($blockedDestination,'synthetic destination blocker')
    $previousEvidence=$env:WINPCINFO_TEST_EVIDENCE
    $env:WINPCINFO_TEST_EVIDENCE=$blockedDestination
    $bodyError=$null; $errorRecord=$null
    try {
        $body=if ($UnsafeChild) { '$failure=[InvalidOperationException]::new("Synthetic wrapper body failure"); $failure.Data["OwnedCleanupUnverified"]=$true; throw $failure' } else { "throw 'Synthetic wrapper body failure'" }
        try { . (Get-HarnessFinalization -File $File -Body $body) }
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
            [IO.File]::Delete((Get-QualificationCleanupBlockerPath))
        }
    }
}
Test-WrapperRetentionFailure -File 'AssessmentSafetyQualification.Tests.ps1'
Test-WrapperRetentionFailure -File 'OfficialSchemaQualification.Tests.ps1'
Test-WrapperRetentionFailure -File 'AssessmentSafetyQualification.Tests.ps1' -UnsafeChild
Test-WrapperRetentionFailure -File 'OfficialSchemaQualification.Tests.ps1' -UnsafeChild

function Test-StatusDeskCleanupProjection {
    param([switch] $Recovery)
    $repositoryRoot=Split-Path -Parent $PSScriptRoot
    $testRoot=Join-Path $repositoryRoot ('.test-output/projection-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($testRoot)
    $QualificationPath=$testRoot+'.json'
    $neighbor=$testRoot+'.neighbor'; $null=[IO.Directory]::CreateDirectory($neighbor)
    $neighborFile=Join-Path $neighbor 'unrelated.txt'; [IO.File]::WriteAllText($neighborFile,'unrelated synthetic content')
    $qualificationFailed=$false; $qualificationBodyError=$null
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
    $child=$null; $ownedProcesses=[Collections.Generic.List[Diagnostics.Process]]::new(); $recoveryBodyError=$null
    $recoveryCleanup=@{childOutputVerified=$false;descendantsAbsent=$false}; $interrupted=$false
    $failure=$null
    try {
        try {
            . (Get-HarnessFinalization -File 'StatusDeskRecovery.Tests.ps1' -Body '$failure=[InvalidOperationException]::new("Synthetic recovery child failure"); $failure.Data["OwnedCleanupUnverified"]=$true; throw $failure')
        }
        catch { $failure=$_ }
        Assert-Equal $true ([IO.Directory]::Exists($testRoot)) 'recovery parent preserves unverified child recovery state'
        Assert-Equal $true (Test-QualificationCleanupUnverified -Exception $failure.Exception) 'recovery parent keeps unsafe state through its own finalization'
        Assert-Equal $true ($failure.Exception.ToString().Contains('Synthetic recovery child failure')) 'recovery cleanup does not erase the body failure'
    }
    finally {
        if ([IO.Directory]::Exists($testRoot)) { [IO.Directory]::Delete($testRoot,$true) }
        if ([IO.Directory]::Exists($testRoot)) { throw 'Controlled recovery-parent cleanup remains unverified.' }
        [IO.File]::Delete((Get-QualificationCleanupBlockerPath))
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
    $child=[Diagnostics.Process]::Start($start)
    $childOutput=$child.StandardOutput.ReadToEndAsync(); $childError=$child.StandardError.ReadToEndAsync()
    $ownedProcesses=[Collections.Generic.List[Diagnostics.Process]]::new(); $recoveryBodyError=$null
    $recoveryCleanup=@{childOutputVerified=$false;descendantsAbsent=$false}; $interrupted=$false
    try {
        Assert-Equal $true $child.WaitForExit(5000) 'controlled child completes without a live application'
        Assert-Equal $true ([IO.File]::Exists($handoffPath)) 'controlled child creates its handoff before failing'
        $failure=$null
        try { . (Get-HarnessFinalization -File 'StatusDeskRecovery.Tests.ps1' -Body "throw 'Synthetic recovery discovery failure'") }
        catch { $failure=$_ }
        Assert-Equal $true ([IO.Directory]::Exists($testRoot)) 'post-handoff unsafe cleanup retains recovery state'
        Assert-Equal $true (Test-QualificationCleanupUnverified -Exception $failure.Exception) 'post-handoff unsafe signal blocks subsequent execution'
    }
    finally {
        # Finalization may already have disposed the exact child handle.
        $child.Dispose()
        if ([IO.Directory]::Exists($testRoot)) { [IO.Directory]::Delete($testRoot,$true) }
        if ([IO.Directory]::Exists($testRoot)) { throw 'Controlled handoff fixture cleanup remains unverified.' }
        [IO.File]::Delete((Get-QualificationCleanupBlockerPath))
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
    $repro=[Diagnostics.Process]::Start($start)
    $output=$repro.StandardOutput.ReadToEndAsync(); $errorOutput=$repro.StandardError.ReadToEndAsync()
    try {
        Assert-Equal $true $repro.WaitForExit(8000) 'exited child with incomplete output reaches bounded cleanup instead of hanging before finally'
        Assert-Equal 0 $repro.ExitCode ('incomplete-output boundary completes honestly: '+$errorOutput.GetAwaiter().GetResult())
        Assert-Equal $true ($output.GetAwaiter().GetResult().Contains('SYNTHETIC_INCOMPLETE_PIPE_BLOCKED')) 'bounded output loss blocks further execution'
    }
    finally {
        if (-not $repro.HasExited) { $repro.Kill($true); if (-not $repro.WaitForExit(5000)) { throw 'Owned pipe regression remains active.' } }
        $repro.Dispose()
        if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root,$true) }
    }
}
Test-RecoveryExitedChildWithIncompleteOutput
Write-Output 'PASS: evidence retention failure cannot bypass owned qualification cleanup.'
