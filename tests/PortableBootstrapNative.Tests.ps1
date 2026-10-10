[CmdletBinding()]
param([ValidateSet('None','IgnoreEnvironmentClear','AllowChangedTarget','SuppressUnsafeOutcome','SkipIndependentDisposal')] [string] $BootstrapFault='None')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'GeneratedApplicationNative.ps1')
function Assert-BootstrapControl { param([bool] $Condition,[string] $Message); if (-not $Condition) { throw $Message } }

# Compile the actual shared supervisor in-process; the red option changes only
# this host's source string. No native Start/Wait or native identity query runs.
$sourcePath=Join-Path $PSScriptRoot 'GeneratedApplicationNativeSupervisor.cs'
$source=[IO.File]::ReadAllText($sourcePath)
if ($BootstrapFault -eq 'IgnoreEnvironmentClear') {
    $source=$source.Replace('process.StartInfo.Environment.Clear();','/* disclosed red control: inherited entries leak */')
}
$sha=(Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
Add-Type -TypeDefinition $source.Replace('__TEST_NATIVE_SOURCE_ID__',$sha)
$controls=0
$originalSynthetic=$env:WINPCINFO_PURE_BOOTSTRAP_AMBIENT
$env:WINPCINFO_PURE_BOOTSTRAP_AMBIENT='synthetic-inherited-value'
try {
    $old=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::new('','',[string[]]@(),'',32,512,4096)
    $inherited=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::new('','',[string[]]@(),'',32,512,4096,$false,$null,$false)
    $map=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($key in @('PATH','SystemRoot','WINDIR','ProgramFiles','ProgramFiles(x86)','LOCALAPPDATA','USERPROFILE','ComSpec','PATHEXT')) { $map.Add($key,'synthetic-'+$key) }
    $cleared=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::new('','',[string[]]@(),'',32,512,4096,$true,$map,$false)
    try {
        Assert-BootstrapControl ($old.StartedIdentity.RedirectStandardInput -and $old.StartedIdentity.EnvironmentMode -ceq 'Inherited') 'Original constructor default behavior changed.'
        Assert-BootstrapControl (-not $inherited.StartedIdentity.RedirectStandardInput -and -not $cleared.StartedIdentity.RedirectStandardInput) 'Portable helper changed its original stdin flag.'
        Assert-BootstrapControl ($inherited.CaptureEnvironmentFixture(@('WINPCINFO_PURE_BOOTSTRAP_AMBIENT'))['WINPCINFO_PURE_BOOTSTRAP_AMBIENT'] -ceq 'synthetic-inherited-value') 'Default bootstrap environment lost inheritance.'
        Assert-BootstrapControl ($cleared.ConfiguredEnvironmentCountFixture -eq 9 -and $cleared.CaptureEnvironmentFixture(@('WINPCINFO_PURE_BOOTSTRAP_AMBIENT','WINPCINFO_TEST_FILE_LEASE','WINPCINFO_TEST_CASE_LEASE')).Count -eq 0) 'Explicit map leaked inherited environment or a nonce.'
        $snapshot=$cleared.CaptureEnvironmentFixture([string[]]@($map.Keys))
        foreach ($key in $map.Keys) { Assert-BootstrapControl ($snapshot[$key] -ceq $map[$key]) 'Exact supplied environment value changed.'; $controls++ }
        $snapshot['PATH']='changed-synthetic-copy'
        Assert-BootstrapControl ($cleared.CaptureEnvironmentFixture(@('PATH'))['PATH'] -ceq 'synthetic-PATH') 'Pure snapshot can mutate native configuration.'
        foreach ($owner in @($old,$inherited,$cleared)) {
            Assert-BootstrapControl (-not $owner.StartedIdentity.Started -and -not $owner.StartedIdentity.UseShellExecute -and
                $owner.StartedIdentity.StdoutRedirected -and $owner.StartedIdentity.StderrRedirected -and -not $owner.StartedIdentity.CreateNoWindow) 'Original non-stdin process flags changed.'
            $utf8=[Text.UTF8Encoding]::new($false,$true)
            $capture=$owner.CaptureFixture($utf8.GetBytes("日本語`r`n"),$utf8.GetBytes("error`n"))
            Assert-BootstrapControl ([WinPCInfoTestGeneratedApplicationNativeSupervisor]::Reconstruct($capture.Lines,'stdout') -ceq "日本語`r`n" -and
                [WinPCInfoTestGeneratedApplicationNativeSupervisor]::Reconstruct($capture.Lines,'stderr') -ceq "error`n") 'Shared strict UTF8 concurrent capture lost exact streams.'
            $controls+=2
        }
        $controls+=5
    }
    finally { $old.Dispose();$inherited.Dispose();$cleared.Dispose() }
    foreach ($configuration in @(@($true,$null,$false),@($false,$map,$false))) {
        $refused=$false
        try { $bad=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::new('','',[string[]]@(),'',32,512,4096,$configuration[0],$configuration[1],$configuration[2]);$bad.Dispose() } catch { $refused=$true }
        Assert-BootstrapControl $refused 'Malformed explicit environment mode was accepted.'
        $controls++
    }
    $refused=$false
    try { $bad=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::new('','',[string[]]@(),'synthetic-unrequested-input',32,512,4096,$false,$null,$false);$bad.Dispose() } catch { $refused=$true }
    Assert-BootstrapControl $refused 'No-input configuration silently fabricated delivery/EOF.'
    $controls++
}
finally { $env:WINPCINFO_PURE_BOOTSTRAP_AMBIENT=$originalSynthetic }

$repositoryRoot=Split-Path -Parent $PSScriptRoot
$workRoot=[IO.Path]::GetFullPath((Join-Path $repositoryRoot ('.test-output/portable-distribution-application-'+[guid]::NewGuid().ToString('N'))))
$allowedRoot=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
if (-not $workRoot.StartsWith($allowedRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Pure bootstrap root escaped .test-output.' }
$null=New-Item -ItemType Directory -Path $workRoot -ErrorAction Stop
$originalWindir=$env:WINDIR;$originalSystemRoot=$env:SystemRoot
try {
    function Get-QualificationCleanupBlockerPath { Join-Path $workRoot 'pure-only-binding-blocker.json' }
    if ($BootstrapFault -eq 'SkipIndependentDisposal') {
        $text=${function:Complete-PortableBootstrapNativeBinding}.ToString().Replace(
            "Complete-QualificationHarness -BodyError `$BodyError -Cleanup @(`r`n            {if (`$null -ne `$Binding.TargetStream) { `$Binding.TargetStream.Dispose() }},`r`n            {if (`$null -ne `$Binding.HostStream) { `$Binding.HostStream.Dispose() }}`r`n        )",
            'if ($null -ne $Binding.TargetStream) { $Binding.TargetStream.Dispose() }; if ($null -ne $Binding.HostStream) { $Binding.HostStream.Dispose() }; if ($null -ne $BodyError) { throw $BodyError.Exception }')
        if ($text -ceq ${function:Complete-PortableBootstrapNativeBinding}.ToString()) {
            $text=[regex]::Replace($text,'(?s)Complete-QualificationHarness -BodyError \$BodyError -Cleanup @\(\s*\{if \(\$null -ne \$Binding.TargetStream\) \{ \$Binding.TargetStream.Dispose\(\) \}\},\s*\{if \(\$null -ne \$Binding.HostStream\) \{ \$Binding.HostStream.Dispose\(\) \}\}\s*\)',
                'if ($null -ne $Binding.TargetStream) { $Binding.TargetStream.Dispose() }; if ($null -ne $Binding.HostStream) { $Binding.HostStream.Dispose() }; if ($null -ne $BodyError) { throw $BodyError.Exception }')
        }
        Set-Item Function:Complete-PortableBootstrapNativeBinding -Value ([scriptblock]::Create($text))
    }
    foreach ($mode in @('NoDisposalFailure','TargetDisposalFailure','HostDisposalFailure','BothDisposalFailures')) {
        $events=[Collections.Generic.List[string]]::new()
        $targetFake=[pscustomobject]@{Name='target';Fail=$mode -in @('TargetDisposalFailure','BothDisposalFailures');Events=$events}
        $hostFake=[pscustomobject]@{Name='host';Fail=$mode -in @('HostDisposalFailure','BothDisposalFailures');Events=$events}
        foreach ($fake in @($targetFake,$hostFake)) {
            $fake | Add-Member ScriptMethod Dispose {$this.Events.Add($this.Name);if($this.Fail){throw ('Disclosed '+$this.Name+' disposal failure.')}}
        }
        $originalCause=[InvalidOperationException]::new('Disclosed original binding cause.')
        try { throw $originalCause } catch { $bindingError=$_ }
        $binding=[pscustomobject]@{TargetStream=$targetFake;HostStream=$hostFake;Phase='DisclosedPureBindingFailure'}
        $observed=$null
        try { Complete-PortableBootstrapNativeBinding -Binding $binding -BodyError $bindingError | Out-Null } catch { $observed=$_ }
        Assert-BootstrapControl (($events -join '|') -ceq 'target|host') 'Target failure skipped independent host disposal.'
        $originalRetained=[object]::ReferenceEquals($observed.Exception,$originalCause)
        if ($observed.Exception -is [AggregateException]) {
            $originalRetained=@($observed.Exception.Flatten().InnerExceptions | Where-Object {[object]::ReferenceEquals($_,$originalCause)}).Count -eq 1
        }
        Assert-BootstrapControl $originalRetained 'Binding finalizer replaced the original admission cause.'
        Assert-BootstrapControl ((Test-QualificationCleanupUnverified -Exception $observed.Exception) -eq ($mode -ne 'NoDisposalFailure')) 'Binding cleanup failure lost unsafe classification.'
        if ($mode -ne 'NoDisposalFailure') { Assert-BootstrapControl (@($script:PortableBootstrapUnverifiedBindings | Where-Object {[object]::ReferenceEquals($_,$binding)}).Count -eq 1) 'Uncertain original binding references were lost.' }
        $controls+=3
    }
    # Disclosed identity/admission substitution: actual lease validation and ACL
    # behavior remain root native certification gates. The target is produced
    # only by the actual builder's pure canonicalization owner, with no Build.
    $env:WINDIR=Join-Path $workRoot 'synthetic-windows';$env:SystemRoot=$env:WINDIR
    $hostPath=Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $null=[IO.Directory]::CreateDirectory((Split-Path -Parent $hostPath))
    [IO.File]::WriteAllText($hostPath,'synthetic-host-not-executable')
    $policy=Read-TestNativeRecord -Path (Join-Path $repositoryRoot 'docs/spec/releases/2.0.0-preview.1-portable-distribution.json')
    $package=Join-Path (Join-Path $workRoot 'extract-a') $policy.archiveRootName
    $null=[IO.Directory]::CreateDirectory($package)
    $target=Join-Path $package 'Start-WIN-PCInfo.ps1'
    $targetBytes=[byte[]](Get-PortableBootstrapSourceBytes -RepositoryRoot $repositoryRoot)
    [IO.File]::WriteAllBytes($target,$targetBytes)
    $emptyRoot=Join-Path $workRoot 'no-pwsh';$null=[IO.Directory]::CreateDirectory($emptyRoot)
    $exact=@{PATH=(Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0');SystemRoot=$env:SystemRoot;WINDIR=$env:WINDIR;
        ProgramFiles=$emptyRoot;'ProgramFiles(x86)'=$emptyRoot;LOCALAPPDATA=$emptyRoot;USERPROFILE=$emptyRoot;
        ComSpec=(Join-Path $env:WINDIR 'System32/cmd.exe');PATHEXT='.COM;.EXE;.BAT;.CMD'}
    $testPath=Join-Path $repositoryRoot 'tests/PortableDistributionApplication.Tests.ps1'
    $script:parentTestPath=$testPath;$script:cohort=@([pscustomobject]@{path=$testPath});$script:refuseParent=$false
    function Get-TestNativeSelfIdentity { [pscustomobject]@{Pid=123;CreationUtc='synthetic-private-birth';OwnerSid='synthetic-private-sid';HostPath='synthetic-private-host'} }
    function Get-TestNativeAdmissionContext {
        param($RepositoryRoot,$SelfIdentity)
        if ($script:refuseParent) { throw 'Disclosed File/Case validation refusal.' }
        [pscustomobject]@{Parent=[pscustomobject]@{Admission=[pscustomobject]@{testPath=$script:parentTestPath};
            Pending=[pscustomobject]@{authorityEnds=[DateTimeOffset]::UtcNow.AddMinutes(2).ToString('o');cleanupReserveMs=10000}};
            Root=[pscustomobject]@{Admission=[pscustomobject]@{inputs=$script:cohort}}}
    }
    if ($BootstrapFault -eq 'AllowChangedTarget') {
        $text=${function:Open-PortableBootstrapNativeBinding}.ToString()
        $text=[regex]::Replace($text,'(?s)if \(\$targetStream.Length -ne \$expectedBytes.Length -or \$targetSha -cne\s*\[Convert\]::ToHexString\(\[Security.Cryptography.SHA256\]::HashData\(\[byte\[\]\]\$expectedBytes\)\).ToLowerInvariant\(\)\)','if ($false)')
        Set-Item Function:Open-PortableBootstrapNativeBinding -Value ([scriptblock]::Create($text))
    }
    $arguments=[string[]]@('-NoLogo','-NoProfile','-File',$target,'-Workflow','Help')
    foreach ($explicit in @($false,$true)) {
        $parameters=@{RepositoryRoot=$repositoryRoot;HostPath=$hostPath;WorkingDirectory=$package;Arguments=$arguments}
        if ($explicit) { $parameters.ExactEnvironment=$exact }
        $binding=Open-PortableBootstrapNativeBinding @parameters
        try {
            Assert-BootstrapControl ($binding.ClearEnvironment -eq $explicit -and $binding.Record.redirectStandardInput -eq $false) 'Binding changed environment mode or stdin configuration.'
            Assert-BootstrapControl ($binding.Record.hostSha256 -ceq (Get-FileHash -LiteralPath $hostPath).Hash.ToLowerInvariant() -and
                $binding.Record.targetSha256 -ceq (Get-FileHash -LiteralPath $target).Hash.ToLowerInvariant()) 'Actual locked host/target operands were not retained.'
            Assert-BootstrapControl (($binding.Record.arguments -join '|') -ceq ($arguments -join '|')) 'Closed Help argv changed.'
            Assert-BootstrapControl (-not $binding.Record.processTreeAbsenceClaim) 'Binding fabricated descendant absence.'
            $locked=$false
            try { $writer=[IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite);$writer.Dispose() } catch { $locked=$true }
            Assert-BootstrapControl $locked 'Original target lock does not deny mutation during consumption.'
            $controls+=5
        }
        finally { $binding.TargetStream.Dispose();$binding.HostStream.Dispose() }
    }
    foreach ($fault in @('ParentRefused','WrongParent','MissingCohort','MissingHost','ChangedHost','MissingTarget','ChangedTarget','WrongCwd','WrongFlags','WrongWorkflow','ChangedMap','ExtraNonce','MissingMapEntry')) {
        $parameters=@{RepositoryRoot=$repositoryRoot;HostPath=$hostPath;WorkingDirectory=$package;Arguments=$arguments;ExactEnvironment=$exact.Clone()}
        switch ($fault) {
            ParentRefused { $script:refuseParent=$true }
            WrongParent { $script:parentTestPath=Join-Path $repositoryRoot 'tests/Other.Tests.ps1' }
            MissingCohort { $script:cohort=@() }
            MissingHost { [IO.File]::Move($hostPath,$hostPath+'.held') }
            ChangedHost { $parameters.HostPath=$target }
            MissingTarget { [IO.File]::Move($target,$target+'.held') }
            ChangedTarget { [IO.File]::WriteAllText($target,'synthetic-changed-target') }
            WrongCwd { $parameters.WorkingDirectory=$workRoot }
            WrongFlags { $parameters.Arguments=@('-NoLogo','-NoProfile','-Command',$target,'-Workflow','Help') }
            WrongWorkflow { $parameters.Arguments=@('-NoLogo','-NoProfile','-File',$target,'-Workflow','Verify') }
            ChangedMap { $parameters.ExactEnvironment.PATH='synthetic-unreviewed-path' }
            ExtraNonce { $parameters.ExactEnvironment.WINPCINFO_TEST_FILE_LEASE='synthetic-nonce' }
            MissingMapEntry { $parameters.ExactEnvironment.Remove('PATH') }
        }
        $refused=$false
        try { $binding=Open-PortableBootstrapNativeBinding @parameters;$binding.TargetStream.Dispose();$binding.HostStream.Dispose() } catch { $refused=$true }
        Assert-BootstrapControl $refused "Closed portable binding did not refuse $fault."
        $script:refuseParent=$false;$script:parentTestPath=$testPath;$script:cohort=@([pscustomobject]@{path=$testPath})
        if ($fault -eq 'MissingHost') { [IO.File]::Move($hostPath+'.held',$hostPath) }
        if ($fault -eq 'MissingTarget') { [IO.File]::Move($target+'.held',$target) }
        if ($fault -eq 'ChangedTarget') { [IO.File]::WriteAllBytes($target,$targetBytes) }
        $controls++
    }
    # Replay the actual native retention/finally state machine. Replace only
    # C# creation, admitted binding, ACL/identity and repository/evidence boundary;
    # these are declared fake owners, never native completion evidence.
    $nativeText=${function:Invoke-GeneratedApplicationNative}.ToString()
    $nativeTokens=$null;$nativeErrors=$null
    $nativeAst=[Management.Automation.Language.Parser]::ParseInput($nativeText,[ref]$nativeTokens,[ref]$nativeErrors)
    $factories=@($nativeAst.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$owner' -and $node.Right.Extent.Text.Contains('[WinPCInfoTestGeneratedApplicationNativeSupervisor]::new')},$true))
    Assert-BootstrapControl ($factories.Count -eq 2) 'Actual shared owner factories are not the expected two compatible branches.'
    foreach ($factory in $factories) { $nativeText=$nativeText.Replace($factory.Extent.Text,'$owner=New-PureBootstrapOwner') }
    $nativeText=$nativeText.Replace('$repository=Split-Path -Parent $PSScriptRoot','$repository=$pureNativeRoot')
    $pureSourceRoot=$PSScriptRoot
    $nativeText=$nativeText.Replace('$PSScriptRoot','$pureSourceRoot')
    $nativeReplay=[scriptblock]::Create($nativeText)
    function Assert-TestNativeRoleReady { param($NativeRole,$RepositoryRoot) }
    function Set-TestNativePrivateDirectory { param($Path);[pscustomobject]@{Value='synthetic-private-sid'} }
    function Open-PortableBootstrapNativeBinding {
        param($RepositoryRoot,$HostPath,$WorkingDirectory,$Arguments,$ExactEnvironment)
        $script:retentionBinding=[pscustomobject]@{HostStream=[IO.File]::OpenRead($HostPath);TargetStream=[IO.File]::OpenRead($Arguments[3]);
            Closed=$false;ClearEnvironment=$false;Environment=$null;AuthorityEnds=[DateTimeOffset]::UtcNow.AddMinutes(2);
            Record=[ordered]@{contract='disclosed-pure-binding';processTreeAbsenceClaim=$false}}
        $script:retentionBinding
    }
    function New-PureBootstrapOwner {
        $identity=[WinPCInfoTestGeneratedApplicationNativeSupervisor+Identity]::new()
        $identity.Pid=123;$identity.CreationUtc='2030-01-01T00:00:00.1234567Z';$identity.OwnerSid='synthetic-private-sid';
        $identity.HostPath=$hostPath;$identity.RedirectStandardInput=$false;$identity.ExactStartedProcessHandlePinned=$true
        $captureOwner=[WinPCInfoTestGeneratedApplicationNativeSupervisor]::new('','',[string[]]@(),'',32,512,4096)
        try { $outcome=$captureOwner.CaptureFixture([Text.Encoding]::UTF8.GetBytes("{`"value`":42}`r`n"),[Text.Encoding]::UTF8.GetBytes("error`n")) } finally { $captureOwner.Dispose() }
        $outcome.Started=$true;$outcome.NativeTerminalObserved=$true;$outcome.NativeExitCode=20;$outcome.InputCompleted=$true;$outcome.InputChannelRequested=$false
        if ($script:retentionMode -eq 'Timeout') { $outcome.DeadlineReached=$true;$outcome.TerminationAttempted=$true;$outcome.OwnedCleanupUnverified=$true }
        if ($script:retentionMode -eq 'StreamLoss') { $outcome.StreamsDrained=$false;$outcome.StreamFailure=$true;$outcome.OwnedCleanupUnverified=$true }
        $owner=[pscustomobject]@{StartedIdentity=$identity;Outcome=$outcome;Disposed=$false;Mode=$script:retentionMode}
        $owner | Add-Member ScriptMethod Start { $this.StartedIdentity.Started=$true }
        $owner | Add-Member ScriptMethod BeginWait { param($Ends,$Reserve,$Timeout);[Threading.Tasks.Task]::FromResult($this.Outcome) }
        $owner | Add-Member ScriptMethod Dispose { if ($this.Mode -eq 'DisposeFailure') { throw 'Disclosed original-owner disposal failure.' };$this.Disposed=$true }
        $script:retentionOwner=$owner
        $owner
    }
    function Get-QualificationCleanupBlockerPath { Join-Path $pureNativeRoot 'pure-only-blocker.json' }
    foreach ($mode in @('NaturalNonzero','Timeout','StreamLoss','TerminalRetentionFailure','DisposeFailure')) {
        $script:retentionMode=$mode;$pureNativeRoot=Join-Path $workRoot ('pure-native-'+$mode);$null=[IO.Directory]::CreateDirectory($pureNativeRoot)
        $startup={param($Directory,$Identity);if($mode -eq 'TerminalRetentionFailure'){$null=[IO.Directory]::CreateDirectory((Join-Path $Directory 'original-native-outcome.json'))}}
        $observed=$null;$nativeResult=$null
        try { $nativeResult=& $nativeReplay -HostPath $hostPath -WorkingDirectory $package -Arguments $arguments -PortableBootstrap -TimeoutMs 60000 -CleanupReserveMs 10000 -ObserveStartup $startup }
        catch { $observed=$_ }
        $unsafe=$mode -ne 'NaturalNonzero'
        Assert-BootstrapControl (($null -ne $observed) -eq $unsafe) ('Actual shared state machine lost native unsafe/retention outcome: '+$mode+$(if($null -ne $observed){' '+$observed.Exception.Message+' '+$observed.ScriptStackTrace}else{''}))
        if ($unsafe) { Assert-BootstrapControl (Test-QualificationCleanupUnverified -Exception $observed.Exception) 'Actual native unsafe classification was lost.' }
        else { Assert-BootstrapControl ($nativeResult.ExitCode -eq 20 -and $nativeResult.StandardOutput -ceq "{`"value`":42}`r`n") 'Actual shared state machine normalized nonzero or lost a stream.' }
        $directory=@(Get-ChildItem -LiteralPath (Join-Path $pureNativeRoot '.test-output/generated-native') -Directory)[0].FullName
        $terminal=Read-TestNativeRecord -Path (Join-Path $directory 'terminal.json')
        Assert-BootstrapControl ($terminal.NativeExitCode -eq 20 -and $terminal.InputChannelRequested -eq $false) 'Independent terminal outcome or no-input declaration was erased.'
        Assert-BootstrapControl ([IO.File]::Exists((Join-Path $directory 'streams.jsonl'))) 'Actual stream retention was lost.'
        Assert-BootstrapControl ($script:retentionBinding.TargetStream.CanRead -eq $unsafe -and $script:retentionBinding.HostStream.CanRead -eq $unsafe) 'Unsafe original binding locks were released, or safe locks leaked.'
        $script:retentionBinding.TargetStream.Dispose();$script:retentionBinding.HostStream.Dispose()
        $controls+=4
    }

    # Load the actual Windows PowerShell adapter function without any package
    # workload. Substitute only its native boundary; full package coverage stays.
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($testPath,[ref]$tokens,[ref]$errors)
    Assert-BootstrapControl ($errors.Count -eq 0) 'Portable consumer does not parse.'
    $adapter=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-WindowsPowerShellFile'},$true))[0]
    $text=$adapter.Extent.Text
    if ($BootstrapFault -eq 'SuppressUnsafeOutcome') {
        $text=$text.Replace('$native=Invoke-GeneratedApplicationNative @nativeArguments',"try { `$native=Invoke-GeneratedApplicationNative @nativeArguments } catch { `$native=[pscustomobject]@{ExitCode=0;StandardOutput='';StandardError=''} }")
    }
    . ([scriptblock]::Create($text))
    function Invoke-GeneratedApplicationNative {
        param($HostPath,$WorkingDirectory,$Arguments,$PortableBootstrap,$TimeoutMs,$CleanupReserveMs,$ExactEnvironment)
        $probe=[pscustomobject]@{HostPath=$HostPath;WorkingDirectory=$WorkingDirectory;Arguments=$Arguments;PortableBootstrap=$PortableBootstrap;
            TimeoutMs=$TimeoutMs;CleanupReserveMs=$CleanupReserveMs;HasExact=$PSBoundParameters.ContainsKey('ExactEnvironment');Environment=$ExactEnvironment}
        $script:forwarded=$probe
        if ($script:unsafeMode) { $exception=[InvalidOperationException]::new('Disclosed '+$script:unsafeMode+' outcome.');$exception.Data['OwnedCleanupUnverified']=$true;throw $exception }
        [pscustomobject]@{ExitCode=20;StandardOutput="{`"recordType`":`"synthetic-public`"}`r`n";StandardError="synthetic-error`n"}
    }
    $script:unsafeMode=''
    foreach ($explicit in @($false,$true)) {
        $parameters=@{FilePath=$target;Arguments=@('-Workflow','Help')};if($explicit){$parameters.Environment=$exact}
        $result=Invoke-WindowsPowerShellFile @parameters
        Assert-BootstrapControl (($result.PSObject.Properties.Name -join '|') -ceq 'ExitCode|Records|StandardOutput|StandardError' -and $result.ExitCode -eq 20 -and $result.Records.Count -eq 1) 'Original portable adapter result shape changed.'
        Assert-BootstrapControl ($result.StandardOutput -ceq "{`"recordType`":`"synthetic-public`"}`r`n" -and $result.StandardError -ceq "synthetic-error`n") 'Portable adapter lost exact stream contents.'
        Assert-BootstrapControl ($script:forwarded.HasExact -eq $explicit -and $script:forwarded.PortableBootstrap -and $script:forwarded.TimeoutMs -eq 60000 -and $script:forwarded.CleanupReserveMs -eq 10000) 'Portable adapter changed supplied environment presence or finite bounds.'
        Assert-BootstrapControl (($script:forwarded.Arguments -join '|') -ceq ($arguments -join '|') -and $script:forwarded.HostPath -ieq $hostPath -and $script:forwarded.WorkingDirectory -ieq $package) 'Original portable host/argv/CWD changed.'
        $controls+=4
    }
    foreach ($unsafeMode in @('Timeout','StreamLoss','TerminalRetentionFailure')) {
        $script:unsafeMode=$unsafeMode;$observed=$null
        try { Invoke-WindowsPowerShellFile -FilePath $target -Arguments @('-Workflow','Help') | Out-Null } catch { $observed=$_ }
        Assert-BootstrapControl ($null -ne $observed -and (Test-QualificationCleanupUnverified -Exception $observed.Exception)) 'Portable adapter suppressed actual unsafe timeout/loss/retention outcome.'
        $controls++
    }
    # Actual cleanup block on private synthetic roots: unsafe/never-created state
    # is preserved, verified safe state is removed. No native absence is inferred.
    $cleanup=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Complete-QualificationHarness'},$true))[0].CommandElements |
        Where-Object { $_ -is [Management.Automation.Language.ArrayExpressionAst] }
    # Extract the real scriptblock by type rather than reconstruct its guards.
    $cleanupBlock=@($cleanup.FindAll({param($node) $node -is [Management.Automation.Language.ScriptBlockExpressionAst]},$true))[0].ScriptBlock.GetScriptBlock()
    foreach ($mode in @('Unsafe','Uncreated','Safe')) {
        $owned=Join-Path $workRoot ('portable-distribution-application-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($owned)
        $actualWorkRoot=$workRoot;$workRoot=$owned;$actualAllowed=$allowedRoot;$allowedRoot=$actualWorkRoot+[IO.Path]::DirectorySeparatorChar
        $workRootCreated=$mode -ne 'Uncreated';$workError=$null
        if ($mode -eq 'Unsafe') { try {$exception=[InvalidOperationException]::new('Disclosed unsafe root.');$exception.Data['OwnedCleanupUnverified']=$true;throw $exception} catch {$workError=$_} }
        & $cleanupBlock
        Assert-BootstrapControl ([IO.Directory]::Exists($owned) -eq ($mode -ne 'Safe')) 'Actual portable finalizer deleted unsafe/uncreated state or failed verified cleanup.'
        $workRoot=$actualWorkRoot;$allowedRoot=$actualAllowed;$controls++
    }
    Write-Output "PASS: $controls pure portable bootstrap controls; native creation, identities and File/Case admission were explicitly substituted."
}
finally {
    $env:WINDIR=$originalWindir;$env:SystemRoot=$originalSystemRoot
    if (-not $workRoot.StartsWith($allowedRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Pure bootstrap cleanup escaped its boundary.' }
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
