[CmdletBinding()]
param([ValidateSet('None','IgnoreWaitBoolean','IgnoreTerminalRetention','AllowUnsafeRootDeletion')] [string] $FixtureFault='None')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'QualificationFixtureProcess.ps1')

function Assert-FixtureControl { param([bool] $Condition,[string] $Message); if (-not $Condition) { throw $Message } }

# Disclosed pure boundaries: no File/Case lease, Windows SID/ACL query or actual
# process is created. Actual owning functions and filesystem retention run.
$originalAdmission=${function:Get-QualificationFixtureAdmission}
$originalWrite=${function:Write-QualificationFixtureRecord}
function Assert-TestNativeRoleReady { param($NativeRole,$RepositoryRoot); $script:admissionCalls++ }
function Get-TestNativeSelfIdentity { [pscustomobject]@{Pid=123;CreationUtc='2030-01-01T00:00:00.0000000Z';OwnerSid='synthetic-private-sid';HostPath='synthetic-creator'} }
function Get-TestNativeAdmissionContext {
    param($RepositoryRoot,$SelfIdentity)
    if ($script:refuseAdmission) { throw 'Disclosed pure admission refusal.' }
    [pscustomobject]@{Parent=[pscustomobject]@{Pending=[pscustomobject]@{authorityEnds=$script:parentEnd.ToString('o');cleanupReserveMs=1000}}}
}
function Set-TestNativePrivateDirectory { param($Path); 'synthetic-private-sid' }
function Get-QualificationFixtureOriginalIdentity {
    param($Process)
    if ($Process.Mode -eq 'IdentityFailure') { throw 'Disclosed pure original-identity failure.' }
    [pscustomobject]@{Handle=$Process.Handle;Record=[ordered]@{pid=1234;fullBirthUtc='2030-01-01T00:00:00.1234567Z';originalSafeHandleValue=555;handleProvenance='Disclosed in-process fake original handle.'}}
}
function Write-QualificationFixtureRecord {
    param($Path,$Value)
    if ([IO.Path]::GetFileName($Path) -ceq $script:failRetentionName) { throw 'Disclosed independent retention failure.' }
    & $originalWrite -Path $Path -Value $Value
}
function New-PureFixtureProcess {
    param([string] $Mode)
    $events=[Collections.Generic.List[object]]::new()
    $process=[pscustomobject]@{Mode=$Mode;Events=$events;ExitCode=42;Disposed=$false;DisposedBeforeRetention=$false;Directory='';
        Handle=[pscustomobject]@{IsClosed=$false;IsInvalid=$false}}
    if ($Mode -eq 'ExitUnknown') { $process.ExitCode=$null }
    $process | Add-Member -MemberType NoteProperty -Name SafeHandle -Value $process.Handle
    $process | Add-Member ScriptMethod WaitForExit {
        param([int] $Milliseconds)
        $this.Events.Add([pscustomobject]@{operation='wait';milliseconds=$Milliseconds})
        if ($this.Mode -eq 'WaitThrows') { throw 'Disclosed wait failure.' }
        if ($Milliseconds -eq 0) { return ($this.Mode -eq 'AlreadyTerminal') }
        if ($this.Mode -eq 'WaitNonBoolean') { return 'false' }
        return ($this.Mode -ne 'WaitFalse')
    }
    $process | Add-Member ScriptMethod Kill {
        if ($args.Count) { throw 'Tree termination is forbidden for the closed fixture.' }
        $this.Events.Add([pscustomobject]@{operation='kill';milliseconds=0})
        if ($this.Mode -eq 'KillThrows') { throw 'Disclosed parent-only kill failure.' }
    }
    $process | Add-Member ScriptMethod Dispose {
        if (-not [IO.File]::Exists((Join-Path $this.Directory 'original-terminal.json')) -or
            -not [IO.File]::Exists((Join-Path $this.Directory 'terminal.json'))) {
            $this.DisposedBeforeRetention=$true
        }
        $this.Events.Add([pscustomobject]@{operation='dispose';milliseconds=0})
        $this.Disposed=$true
    }
    $process
}

# Explicit red controls mutate only actual helper function text in this host.
if ($FixtureFault -eq 'IgnoreWaitBoolean') {
    $text=${function:Close-QualificationFixtureProcess}.ToString().Replace("`r`n","`n").Replace(
        "if (`$terminal -isnot [bool] -or -not `$terminal) { throw 'Fixture original process terminal completion is unverified.' }",
        '# Disclosed red mutation: ignores false terminal wait.')
    Set-Item Function:Close-QualificationFixtureProcess -Value ([scriptblock]::Create($text))
}
if ($FixtureFault -eq 'IgnoreTerminalRetention') {
    $text=${function:Close-QualificationFixtureProcess}.ToString().Replace("`r`n","`n").Replace(
        'catch { $Owner.Unsafe=$true; $failures.Add($_.Exception) }'+"`n    }`n    `$Owner.TerminalRetained",
        'catch { }'+"`n    }`n    `$Owner.TerminalRetained")
    Set-Item Function:Close-QualificationFixtureProcess -Value ([scriptblock]::Create($text))
}
if ($FixtureFault -eq 'AllowUnsafeRootDeletion') {
    $text=${function:Remove-QualificationFixtureRoot}.ToString().Replace('if (($null -ne $BodyError', 'if (($false -and $null -ne $BodyError').Replace(
        '($null -ne $Owner -and ($Owner.Unsafe','($false -and $null -ne $Owner -and ($Owner.Unsafe')
    Set-Item Function:Remove-QualificationFixtureRoot -Value ([scriptblock]::Create($text))
}

$repositoryRoot=Split-Path -Parent $PSScriptRoot
$testRoot=[IO.Path]::GetFullPath((Join-Path $repositoryRoot ('.test-output/fixture-process-pure-'+[guid]::NewGuid().ToString('N'))))
$allowed=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
if (-not $testRoot.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)) { throw 'Pure fixture root escaped its boundary.' }
$null=New-Item -ItemType Directory -Path $testRoot -ErrorAction Stop
function Get-QualificationCleanupBlockerPath { Join-Path $testRoot 'pure-only-cleanup-blocker.json' }
$originalEnv=$env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC
$script:failRetentionName=''
$script:refuseAdmission=$false
$script:admissionCalls=0
$script:parentEnd=[DateTimeOffset]::UtcNow.AddMinutes(2)
$env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC=$script:parentEnd.ToString('o')
$controls=0
try {
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=Join-Path $PSHOME 'pwsh.exe'; $start.UseShellExecute=$false
    foreach ($argument in @('-NoLogo','-NoProfile','-Command','[Threading.Thread]::Sleep(30000)')) { $start.ArgumentList.Add($argument) }
    foreach ($mode in @('Safe','AlreadyTerminal','WaitFalse','WaitNonBoolean','WaitThrows','KillThrows','IdentityFailure','RetentionFailure','ExpiredCleanup','ClippedCleanup','ExitUnknown','BodyFailure','BodyUnsafe')) {
        $caseRoot=Join-Path $testRoot $mode
        $owner=New-QualificationFixtureProcessOwner -RepositoryRoot $caseRoot -StartInfo $start
        $pendingPath=Join-Path $owner.Directory 'original-pending.json'
        $pendingHash=(Get-FileHash -LiteralPath $pendingPath -Algorithm SHA256).Hash
        $process=New-PureFixtureProcess -Mode $mode
        $process.Directory=$owner.Directory
        $bodyError=$null
        try {
            Register-QualificationFixtureProcess -Owner $owner -Process $process
            if ($mode -eq 'ExpiredCleanup') { $owner.BudgetMs=500 }
            if ($mode -eq 'ClippedCleanup') { $owner.BudgetMs=2000 }
            if ($mode -in @('BodyFailure','BodyUnsafe')) {
                $exception=[InvalidOperationException]::new('Disclosed original body failure.')
                if ($mode -eq 'BodyUnsafe') { $exception.Data['OwnedCleanupUnverified']=$true }
                throw $exception
            }
        } catch { $bodyError=$_ }
        if ($mode -eq 'RetentionFailure') { $script:failRetentionName='original-terminal.json' }
        $errorResult=$null
        try { Complete-QualificationFixtureProcess -Owner $owner -Process $process -BodyError $bodyError | Out-Null }
        catch { $errorResult=$_ }
        $script:failRetentionName=''
        $unsafe=$mode -in @('WaitFalse','WaitNonBoolean','WaitThrows','KillThrows','IdentityFailure','RetentionFailure','ExpiredCleanup','BodyUnsafe')
        Assert-FixtureControl ($owner.Unsafe -eq $unsafe) "Actual owner unsafe state differs for $mode."
        Assert-FixtureControl ($process.Disposed -eq (-not $unsafe)) "Original handle disposal differs for $mode."
        Assert-FixtureControl (-not $process.DisposedBeforeRetention) 'Original handle was disposed before independent terminal retention.'
        Assert-FixtureControl ((Get-FileHash -LiteralPath $pendingPath -Algorithm SHA256).Hash -ceq $pendingHash) 'Original pending bytes changed.'
        Assert-FixtureControl ([IO.File]::Exists((Join-Path $owner.Directory 'terminal.json'))) 'Independent terminal retention was lost.'
        Assert-FixtureControl ([object]::ReferenceEquals($owner.SafeHandle,$process.SafeHandle)) 'Original SafeHandle reference was replaced or lost.'
        $terminal=Get-Content -LiteralPath (Join-Path $owner.Directory 'terminal.json') -Raw | ConvertFrom-Json -DateKind String
        if ($mode -ne 'IdentityFailure') { Assert-FixtureControl ($terminal.identity.fullBirthUtc -ceq '2030-01-01T00:00:00.1234567Z') 'Original full birth bytes were normalized.' }
        if ($mode -eq 'ExitUnknown') { Assert-FixtureControl ($null -eq $terminal.exitCode) 'Unknown native exit was normalized to a success value.' }
        Assert-FixtureControl ([IO.File]::Exists((Join-Path $owner.Directory 'owned-pending.json')) -eq $unsafe) 'Pending ownership marker differs from safety.'
        foreach ($wait in @($process.Events | Where-Object operation -eq 'wait')) {
            Assert-FixtureControl ($wait.milliseconds -ge 0 -and $wait.milliseconds -le 5000) 'Original fixture wait exceeded finite cap.'
            if ($mode -eq 'ClippedCleanup') { Assert-FixtureControl ($wait.milliseconds -le 1000) 'Cleanup wait consumed the explicit retention reserve.' }
        }
        if ($mode -eq 'AlreadyTerminal') { Assert-FixtureControl (@($process.Events | Where-Object operation -eq 'kill').Count -eq 0) 'Already-terminal original was killed.' }
        if ($mode -eq 'ExpiredCleanup') { Assert-FixtureControl (@($process.Events | Where-Object operation -eq 'kill').Count -eq 0) 'Expired authority still killed a fixture.' }
        if ($unsafe) { Assert-FixtureControl (Test-QualificationCleanupUnverified -Exception $errorResult.Exception) 'Unsafe exception signal was lost.' }
        if ($mode -in @('BodyFailure','BodyUnsafe')) { Assert-FixtureControl ($errorResult.Exception.ToString().Contains('Disclosed original body failure.')) 'Original body failure was lost.' }
        $root=Join-Path $caseRoot 'owned-root'; $null=[IO.Directory]::CreateDirectory($root)
        [IO.File]::WriteAllText((Join-Path $root 'journal.json'),'synthetic-private-state')
        Remove-QualificationFixtureRoot -Root $root -AllowedRoot $caseRoot -Created $true -Owner $owner -BodyError $bodyError
        Assert-FixtureControl ([IO.Directory]::Exists($root) -eq $unsafe) 'Unsafe fixture journal/root was deleted or safe root remained.'
        $controls++
    }
    # Admission refusal, inherited shortening and local creation reservation.
    $script:refuseAdmission=$true
    $refused=$false
    try { New-QualificationFixtureProcessOwner -RepositoryRoot (Join-Path $testRoot 'Refuse') -StartInfo $start | Out-Null } catch { $refused=$true }
    Assert-FixtureControl $refused 'Unadmitted fixture was accepted.'
    $script:refuseAdmission=$false
    $env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC=[DateTimeOffset]::UtcNow.AddSeconds(6).ToString('o')
    $refused=$false
    try { New-QualificationFixtureProcessOwner -RepositoryRoot (Join-Path $testRoot 'Reserve') -StartInfo $start | Out-Null } catch { $refused=$true }
    Assert-FixtureControl $refused 'Insufficient reserve still admitted creation.'
    Assert-FixtureControl (-not [IO.Directory]::Exists((Join-Path $testRoot 'Reserve'))) 'Refusal created fixture evidence before reserve admission.'
    $env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC=[DateTimeOffset]::UtcNow.AddSeconds(12).ToString('o')
    $owner=New-QualificationFixtureProcessOwner -RepositoryRoot (Join-Path $testRoot 'Shorten') -StartInfo $start
    Assert-FixtureControl ($owner.BudgetMs -le 12000 -and $owner.BudgetMs -ge 7000) 'Inherited absolute deadline was renewed or ignored.'
    $owner.BudgetMs=500
    $refused=$false
    try { Assert-QualificationFixtureProcessAdmission -Owner $owner } catch { $refused=$true }
    Assert-FixtureControl $refused 'Creation was not rechecked after fallible pending retention.'
    Complete-QualificationFixtureProcess -Owner $owner -Process $null | Out-Null
    $controls+=4
    $uncreated=Join-Path $testRoot 'uncreated-root'; $null=[IO.Directory]::CreateDirectory($uncreated)
    Remove-QualificationFixtureRoot -Root $uncreated -AllowedRoot $testRoot -Created $false
    Assert-FixtureControl ([IO.Directory]::Exists($uncreated)) 'Uncreated root was guessed as owned.'
    $env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC='malformed-deadline'
    $refused=$false
    try { New-QualificationFixtureProcessOwner -RepositoryRoot (Join-Path $testRoot 'Malformed') -StartInfo $start | Out-Null } catch { $refused=$true }
    Assert-FixtureControl $refused 'Malformed inherited absolute authority was accepted.'
    $env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC=$null
    $refused=$false
    try { New-QualificationFixtureProcessOwner -RepositoryRoot (Join-Path $testRoot 'Missing') -StartInfo $start | Out-Null } catch { $refused=$true }
    Assert-FixtureControl $refused 'Missing inherited absolute authority was accepted.'
    $controls+=3

    # Replay each actual live fixture's admission/creator/register/catch/finally.
    # Substitute the native creator and entire capability workload explicitly;
    # these controls validate ownership wiring, not product capability acceptance.
    foreach ($name in @('EvidenceWorkspace.Tests.ps1','SystemCollectionPlan.Tests.ps1','SystemTaskRecovery.Tests.ps1')) {
        $tokens=$null; $errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$errors)
        Assert-FixtureControl ($errors.Count -eq 0) 'Actual live consumer did not parse.'
        $seams=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.TryStatementAst] -and
            $null -ne $node.Finally -and $node.Finally.Extent.Text.Contains('Complete-QualificationFixtureProcess')},$true))
        Assert-FixtureControl ($seams.Count -eq 1) 'Actual live fixture ownership seam is not unique.'
        $seam=$seams[0]
        Assert-FixtureControl ($seam.Body.Statements[0].Extent.Text.StartsWith('Assert-QualificationFixtureProcessAdmission')) 'Original creator is not guarded before Start.'
        Assert-FixtureControl ($seam.Body.Statements[2].Extent.Text.StartsWith('Register-QualificationFixtureProcess')) 'Original creator is not registered immediately.'
        $creator=$seam.Body.Statements[1].Extent.Text
        $creator=[regex]::Replace($creator,'\[(?:System\.)?Diagnostics\.Process\]::Start\(\$(?:start|engineStart)\)',"(New-PureFixtureProcess -Mode 'Safe')")
        Assert-FixtureControl (-not $creator.Contains('::Start')) 'Pure creator substitution did not remove native creation.'
        foreach ($failBody in @($false,$true)) {
            $env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC=$script:parentEnd.ToString('o')
            $fixtureOwner=New-QualificationFixtureProcessOwner -RepositoryRoot (Join-Path $testRoot ($name+$failBody)) -StartInfo $start
            $fixtureError=$null
            $script:systemCleanupEngine=$null; $otherOwner=$null; $engine=$null
            $body='{'+$seam.Body.Statements[0].Extent.Text+"`n"+$creator+"`n"+$seam.Body.Statements[1].Left.Extent.Text+".Directory=`$fixtureOwner.Directory`n"+$seam.Body.Statements[2].Extent.Text+"`nif (`$failBody) { throw 'Disclosed capability body failure.' }`n}"
            $text=$seam.Extent.Text.Replace($seam.Body.Extent.Text,$body)
            $observed=$null
            try { . ([scriptblock]::Create($text)) | Out-Null } catch { $observed=$_ }
            Assert-FixtureControl $fixtureOwner.Disposed 'Actual consumer finalizer did not dispose its terminal original.'
            Assert-FixtureControl (($null -ne $observed) -eq $failBody) 'Actual consumer catch/finally lost original body outcome.'
            $controls++
        }
        $fixtureOwner=New-QualificationFixtureProcessOwner -RepositoryRoot (Join-Path $testRoot ($name+'ExpiredBeforeStart')) -StartInfo $start
        $fixtureOwner.BudgetMs=500
        $fixtureError=$null; $failBody=$false
        $script:systemCleanupEngine=$null; $otherOwner=$null; $engine=$null
        $observed=$null
        try { . ([scriptblock]::Create($text)) | Out-Null } catch { $observed=$_ }
        Assert-FixtureControl ($null -ne $observed -and -not $fixtureOwner.Started -and $null -eq $otherOwner -and $null -eq $engine -and $null -eq $script:systemCleanupEngine) 'Actual creator ignored exhausted reserve before Start.'
        $controls++
    }
    # Actual SystemTaskRecovery prepared admission/catch/finally, with generated
    # module and recovery work omitted; this never builds a candidate.
    function Open-TestCandidate {
        param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
        $probe.Events.Add('open')
        $probe.Arguments=@($CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
        if ($probe.Mode -eq 'Refuse') { throw 'Disclosed prepared admission refusal.' }
        $probe.Context=[pscustomobject]@{Path='synthetic-locked-candidate'}
        $probe.Context
    }
    function Close-TestCandidate {
        param($Candidate,$BodyError)
        $probe.Events.Add('close'); $probe.Closed=$Candidate; $probe.BodyError=$BodyError
        if ($null -ne $BodyError) { throw $BodyError.Exception }
    }
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'SystemTaskRecovery.Tests.ps1'),[ref]$tokens,[ref]$errors)
    $outer=@($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] -and $_.Finally.Extent.Text.Contains('Close-TestCandidate') })[0]
    $open=@($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Extent.Text.Contains('Open-TestCandidate') })[0]
    $selection=@($outer.Body.Statements | Where-Object { $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Right.Extent.Text -ceq '$candidateContext.Path' })[0]
    foreach ($mode in @('Prepared','Standalone','Refuse','BodyFailure')) {
        $probe=[pscustomobject]@{Mode=$mode;Events=[Collections.Generic.List[string]]::new();Arguments=$null;Context=$null;Closed=$null;BodyError=$null;Used=$null}
        $CandidatePath='candidate';$PreparedManifestPath='manifest';$PreparedManifestSha256='a'*64
        if ($mode -eq 'Standalone') { $CandidatePath='';$PreparedManifestPath='';$PreparedManifestSha256='' }
        $body='{'+$selection.Extent.Text+"`n`$probe.Used=`$candidate`nif (`$mode -eq 'BodyFailure') { throw 'Disclosed prepared body failure.' }`n}"
        $replay=$open.Extent.Text+"`n`$candidateError=`$null`n"+$outer.Extent.Text.Replace($outer.Body.Extent.Text,$body)
        $failure=$null
        try { . ([scriptblock]::Create($replay)) } catch { $failure=$_ }
        if ($mode -eq 'Refuse') { Assert-FixtureControl ($probe.Events.Count -eq 1 -and $null -ne $failure) 'Prepared refusal reached work or finalization without an owned context.' }
        else {
            Assert-FixtureControl ($probe.Events -join ',' -ceq 'open,close') 'Actual prepared context was not closed exactly once.'
            Assert-FixtureControl ([object]::ReferenceEquals($probe.Context,$probe.Closed)) 'Finalizer closed another candidate context.'
            Assert-FixtureControl ($probe.Used -ceq $probe.Context.Path) 'Actual recovery still consumed a shared artifact.'
            Assert-FixtureControl (($null -ne $failure) -eq ($mode -eq 'BodyFailure')) 'Prepared finalizer lost its original body outcome.'
        }
        $controls++
    }
    Write-Output "PASS: $controls pure original-fixture ownership controls; native creation, SID/ACL and admission boundaries were explicitly substituted."
}
finally {
    $env:WINPCINFO_TEST_AUTHORITY_ENDS_UTC=$originalEnv
    # Only fake owners were created here. This cleanup is not a native safety
    # claim and is restricted to the uniquely owned pure-control directory.
    if (-not $testRoot.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)) { throw 'Pure cleanup root escaped its boundary.' }
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
