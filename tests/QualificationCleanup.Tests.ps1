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
    param([string] $File)
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
        try { . (Get-HarnessFinalization -File $File -Body "throw 'Synthetic wrapper body failure'") }
        catch { $errorRecord=$_ }
        Assert-Equal $false ([IO.Directory]::Exists($root)) "$File retention failure still removes the owned workspace"
        Assert-Equal $true ($null -ne $errorRecord) "$File cannot pass after retention failure"
        Assert-Equal $true ($errorRecord.Exception.ToString().Contains('Synthetic wrapper body failure')) "$File preserves its body failure"
        Assert-Equal $true ($errorRecord.Exception.ToString().Contains('evidence retention failed')) "$File preserves its retention failure"
    }
    finally {
        $env:WINPCINFO_TEST_EVIDENCE=$previousEvidence
        if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root,$true) }
    }
}
Test-WrapperRetentionFailure -File 'AssessmentSafetyQualification.Tests.ps1'
Test-WrapperRetentionFailure -File 'OfficialSchemaQualification.Tests.ps1'
Write-Output 'PASS: evidence retention failure cannot bypass owned qualification cleanup.'
