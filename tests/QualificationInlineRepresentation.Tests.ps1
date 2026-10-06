[CmdletBinding()]
param([ValidateSet('None','IgnoreOperandClosure','ChangePayload','RelaxLaunchCeiling','IgnoreHostBinding','SuppressProbeUnsafe','AcceptForcedShell','IgnoreShellCleanupWait')] [string] $FixtureFault='None')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'QualificationInlineRepresentation.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'build/RuntimeHost.ps1')
function Assert-InlineControl {param([bool]$Condition,[string]$Message);if(-not $Condition){throw $Message};$script:controls++}
if ($FixtureFault -ceq 'IgnoreOperandClosure') {
    $text=${function:Get-QualificationInlineRepresentationProfile}.ToString().Replace('if ($Inputs.psbase.Count -ne $keys.Count -or @($Inputs.psbase.Keys | Where-Object {$_ -isnot [string] -or $_ -cnotin $keys}).Count)','if ($false)')
    Set-Item Function:Get-QualificationInlineRepresentationProfile ([scriptblock]::Create($text))
}
if ($FixtureFault -ceq 'ChangePayload') {
    $text=${function:Get-QualificationInlineRepresentationProfile}.ToString().Replace("`$source=`"'`$literal'`"","`$source=`"'changed-padding'`"")
    Set-Item Function:Get-QualificationInlineRepresentationProfile ([scriptblock]::Create($text))
}
if ($FixtureFault -ceq 'RelaxLaunchCeiling') {
    $text=${function:Get-QualificationInlineRepresentationProfile}.ToString().Replace('$command.Length -gt 32500','$command.Length -gt 65536')
    Set-Item Function:Get-QualificationInlineRepresentationProfile ([scriptblock]::Create($text))
}
if ($FixtureFault -ceq 'IgnoreHostBinding') {
    $text=${function:Assert-QualificationInlineRepresentationBinding}.ToString().Replace('$HostPath -cne $Binding.HostPath -or','')
    Set-Item Function:Assert-QualificationInlineRepresentationBinding ([scriptblock]::Create($text))
}
if ($FixtureFault -ceq 'SuppressProbeUnsafe') {
    $text=${function:Resolve-QualificationInlineRuntime}.ToString().Replace('if ($null -ne $Binding.UnsafeError)','if ($false)')
    Set-Item Function:Resolve-QualificationInlineRuntime ([scriptblock]::Create($text))
}
if ($FixtureFault -ceq 'AcceptForcedShell') {
    $text=${function:Close-QualificationCapabilityProcess}.ToString().Replace('if (-not $Owner.Unsafe -and $Owner.TerminalVerified -and $Owner.TerminalRetained)', '$Owner.Unsafe=$false;if (-not $Owner.Unsafe -and $Owner.TerminalVerified -and $Owner.TerminalRetained)')
    Set-Item Function:Close-QualificationCapabilityProcess ([scriptblock]::Create($text))
}
if ($FixtureFault -ceq 'IgnoreShellCleanupWait') {
    $text=${function:Observe-QualificationInlineShellCleanup}.ToString().Replace("if (`$terminal -isnot [bool] -or -not `$terminal) { throw 'Inline ShellExecute original post-termination completion is unverified.' }",'')
    Set-Item Function:Observe-QualificationInlineShellCleanup ([scriptblock]::Create($text))
}
$script:controls=0
$bytes=[Security.Cryptography.RandomNumberGenerator]::GetBytes(25000)
$hash=Get-QualificationInlineRepresentationProfile -Profile Hash -Inputs @{Bytes=$bytes}
$literal=[Convert]::ToBase64String($bytes)
$originalHashSource='[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String('''+$literal+'''))).ToLowerInvariant()'
Assert-InlineControl ($hash.Source -ceq $originalHashSource -and $hash.Arguments[4] -ceq (ConvertTo-PrivilegedCollectionInlineCommand -Source $originalHashSource)) 'The actual 25000-byte high-entropy source and packed command must be unchanged.'
Assert-InlineControl (($hash.Arguments[0..3] -join '|') -ceq '-NoLogo|-NoProfile|-NonInteractive|-Command' -and $hash.Arguments.Count -eq 5 -and $hash.Arguments[4].Length -le 32500) 'The original flags and Windows UTF16 launch ceiling remain exact.'
Assert-InlineControl ($hash.ExpectedStandardOutput -ceq (Get-PrivilegedCollectionPlanSha256 $bytes)) 'The original high-entropy expected digest remains exact.'
foreach ($count in 1..9) {
    $profile=Get-QualificationInlineRepresentationProfile -Profile Padding -Inputs @{Count=$count}
    $literal=[Convert]::ToBase64String([byte[]](1..$count))
    Assert-InlineControl ($profile.Source -ceq "'$literal'" -and $profile.Arguments[4] -ceq (ConvertTo-PrivilegedCollectionInlineCommand -Source "'$literal'") -and $profile.ExpectedStandardOutput -ceq $literal) 'Every original padding source/command/expected output must remain exact.'
}
foreach ($culture in @('en-US','es-MX','tr-TR','ja-JP','ar-SA')) {
    $profile=Get-QualificationInlineRepresentationProfile -Profile Culture -Inputs @{Culture=$culture}
    $source="[Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo('$culture');'Synthetic 漢字 O''Brien'"
    Assert-InlineControl ($profile.Source -ceq $source -and $profile.Arguments[4] -ceq (ConvertTo-PrivilegedCollectionInlineCommand -Source $source) -and $profile.ExpectedStandardOutput -ceq "Synthetic 漢字 O'Brien") 'Every original culture, apostrophe and Unicode source/argv must remain exact.'
}
$original=ConvertTo-PrivilegedCollectionInlineCommand -Source "'synthetic-not-executed'"
$match=[regex]::Match($original,'[\u4000-\u5080]+')
$malformed=$original.Remove($match.Index,1).Insert($match.Index,([char]0x3000).ToString())
$profile=Get-QualificationInlineRepresentationProfile -Profile Malformed -Inputs @{}
Assert-InlineControl ($profile.Arguments[4] -ceq $malformed -and $profile.ExpectedNaturalNonzero -and $null -eq $profile.ExpectedStandardOutput) 'The one original malformed BMP character must retain its negative native contract.'

foreach ($case in @(
    @{Profile=@('Padding');Inputs=@{Count=1}},@{Profile='Other';Inputs=@{}},@{Profile='padding';Inputs=@{Count=1}},
    @{Profile='Padding';Inputs=@{Count='1'}},@{Profile='Padding';Inputs=@{Count=[long]1}},@{Profile='Padding';Inputs=@{Count=0}},
    @{Profile='Padding';Inputs=@{Count=10}},@{Profile='Padding';Inputs=@{Count=@(1)}},@{Profile='Padding';Inputs=@{count=1}},
    @{Profile='Padding';Inputs=@{Count=1;Source="'unadmitted'"}},@{Profile='Padding';Inputs=[pscustomobject]@{Count=1}},
    @{Profile='Culture';Inputs=@{Culture='en-us'}},@{Profile='Culture';Inputs=@{Culture='fr-FR'}},@{Profile='Culture';Inputs=@{Culture=@('en-US')}},
    @{Profile='Malformed';Inputs=@{Command='arbitrary'}},@{Profile='Hash';Inputs=@{Bytes=[byte[]](1,2,3)}},
    @{Profile='Hash';Inputs=@{Bytes=@(1,2,3)}},@{Profile='Hash';Inputs=@{Bytes=$bytes;HostPath='unadmitted.exe'}}
)) {
    $caught=$false;try{$null=Get-QualificationInlineRepresentationProfile @case}catch{$caught=$true}
    Assert-InlineControl $caught 'Wrong typed, unknown or additional operands cannot widen the closed profile.'
}
$converter=${function:ConvertTo-PrivilegedCollectionInlineCommand}
try {
    # Disclosed serializer substitution exercises the actual profile's refusal;
    # it creates no command/process and cannot change the production converter.
    function ConvertTo-PrivilegedCollectionInlineCommand {param($Source);'x'*32501}
    $caught=$false;try{$null=Get-QualificationInlineRepresentationProfile -Profile Hash -Inputs @{Bytes=$bytes}}catch{$caught=$true}
    Assert-InlineControl $caught 'An over-ceiling converter result cannot be admitted by the profile.'
}
finally {Set-Item Function:ConvertTo-PrivilegedCollectionInlineCommand $converter}
$large=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(70000))
$caught=$false;try{$null=ConvertTo-PrivilegedCollectionInlineCommand -Source "'$large'"}catch{$caught=$_.Exception.Message -ceq 'The reviewed privilege worker exceeds the Windows launch bound.'}
Assert-InlineControl $caught 'The original oversize source must keep its exact refusal without native execution.'

# All following native-facing boundaries are disclosed in-process substitutes.
# Actual binding/RuntimeHost discovery/parser/owner/finalizer functions run, but
# no signature query, native Process, Job, pipe or shell launch occurs.
$actualRuntimeProbe=${function:Invoke-WinPCInfoRuntimeProbe}
function Invoke-WinPCInfoRuntimeProbe {
    param($Executable,$ApplicationPath,$RunProbe)
    $script:signatureReads.Add($Executable)
    & $actualRuntimeProbe -Executable $Executable -ApplicationPath $ApplicationPath -RunProbe $RunProbe -ReadSignature {
        param($Path);[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Microsoft Corporation, synthetic pure signature'}}
    }
}
function Get-WinPCInfoRuntimeCandidates {$script:runtimeCandidates}
function Get-TestNativeSelfIdentity {[pscustomobject]@{Pid=123;CreationUtc='2030-01-01T00:00:00.0000000Z';OwnerSid='synthetic-pure-sid';HostPath=$script:context.Root.Admission.hostPath}}
function Get-QualificationFixtureAdmission {
    param($RepositoryRoot)
    [pscustomobject]@{Ends=[DateTimeOffset]::UtcNow.AddMilliseconds($script:authorityBudget);Parent=$script:context.Parent;Creator=(Get-TestNativeSelfIdentity)}
}
function Get-TestNativeAdmissionContext {param($RepositoryRoot,$SelfIdentity);$script:context}
function Assert-TestNativeRoleReady {param($NativeRole,$RepositoryRoot)}
function Set-TestNativePrivateDirectory {param($Path);'synthetic-pure-sid'}
function Get-QualificationFixtureOriginalIdentity {
    param($Process)
    [pscustomobject]@{Handle=$Process.SafeHandle;Record=[ordered]@{pid=456;fullBirthUtc='2030-01-01T00:00:00.1234567Z';
        originalSafeHandleValue=789;handleProvenance='Disclosed pure ShellExecute original handle.'}}
}
$actualCapabilityRegister=${function:Register-QualificationCapabilityProcess}
function Register-QualificationCapabilityProcess {
    param($Owner,$Process)
    # This field exists only on the fake Process for its disposal sensitivity.
    $Process.Directory=$Owner.Directory
    & $actualCapabilityRegister -Owner $Owner -Process $Process
}
$pureRoot=Join-Path (Split-Path -Parent $PSScriptRoot) ('.test-output/inline-native-controls-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($pureRoot)
function Get-QualificationCleanupBlockerPath {Join-Path $pureRoot 'synthetic-blocker.json'}
$script:authorityBudget=60000;$script:nativeFault='';$script:shellMode='Natural';$script:retentionFault=''
$script:nativeCalls=[Collections.Generic.List[object]]::new();$script:signatureReads=[Collections.Generic.List[string]]::new()
$actualRecordWriter=${function:Write-QualificationFixtureRecord}
function Write-QualificationFixtureRecord {
    param($Path,$Value)
    if([IO.Path]::GetFileName($Path) -ceq $script:retentionFault){throw 'Disclosed ShellExecute raw retention failure.'}
    & $actualRecordWriter -Path $Path -Value $Value
}
function New-InlineControlBinding {
    param([string]$Fault='')
    $repo=Join-Path $pureRoot ([guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory((Join-Path $repo 'tests'));$null=[IO.Directory]::CreateDirectory((Join-Path $repo 'runtime'))
    $testPath=Join-Path $repo 'tests/PrivilegedInlineRepresentation.Tests.ps1';[IO.File]::WriteAllText($testPath,'# Disclosed pure named source.')
    $hostPath=Join-Path $repo 'runtime/pwsh.exe';[IO.File]::WriteAllText($hostPath,'Disclosed synthetic bytes, never executed.')
    $candidatePath=Join-Path $repo 'WIN-PCInfo.ps1';[IO.File]::WriteAllText($candidatePath,'# Disclosed synthetic candidate, never invoked.')
    $manifestPath=Join-Path $repo 'prepared.json';[IO.File]::WriteAllText($manifestPath,'{"synthetic":true}')
    $pins=@($testPath,$hostPath,$candidatePath,$manifestPath)|ForEach-Object{[pscustomobject]@{path=$_;sha256=(Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $_).Length}}
    $manifestSha=(Get-FileHash -LiteralPath $manifestPath).Hash.ToLowerInvariant()
    $candidate=[pscustomobject]@{Path=$candidatePath;Sha256=(Get-FileHash -LiteralPath $candidatePath).Hash.ToLowerInvariant();Prepared=$true;OwnedDirectory=$null;
        Stream=[IO.File]::Open($candidatePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}
    $admission=[pscustomobject]@{testPath=$testPath;hostPath=$hostPath;candidatePath=$candidatePath;preparedManifestPath=$manifestPath;
        preparedManifestSha256=$manifestSha;inputs=$pins;cohortSha256=(Get-TestNativeDigest -Value $pins)}
    $script:context=[pscustomobject]@{Parent=[pscustomobject]@{Admission=$admission;Pending=[ordered]@{nonce='synthetic';authorityEnds='2030-01-01T00:00:00.0000000Z';cleanupReserveMs=1000}};
        Root=[pscustomobject]@{Admission=$admission}}
    switch($Fault){WrongSource{$admission.testPath=Join-Path $repo 'tests/Other.Tests.ps1'};
        WrongCandidate{$candidate.Path=Join-Path $repo 'substituted.ps1'};CandidateArray{$candidate.Path=@($candidate.Path)};
        WrongDigest{$candidate.Sha256='0'*64};WrongManifest{$admission.preparedManifestSha256='0'*64};
        MissingHostPin{$admission.inputs=@($pins|Where-Object path -CNE $hostPath)};WrongHostPin{($pins|Where-Object path -CEQ $hostPath).sha256='0'*64};
        HostArray{$admission.hostPath=@($hostPath)};NotPrepared{$candidate.Prepared=$false};DuplicateHost{$admission.inputs=@($pins)+@($pins|Where-Object path -CEQ $hostPath)}}
    try {Open-QualificationInlineRepresentationBinding -RepositoryRoot $repo -Candidate $candidate -PreparedManifestPath $manifestPath -PreparedManifestSha256 $manifestSha}
    catch {$candidate.Stream.Dispose();throw}
}
function Invoke-GeneratedApplicationNative {
    param($HostPath,$WorkingDirectory,$Arguments,$TimeoutMs,$CleanupReserveMs,$AuthorityEnds,$MaximumLines,$MaximumLineCharacters,$MaximumTotalCharacters,$ObserveStartup)
    $script:nativeCalls.Add([pscustomobject]@{HostPath=$HostPath;WorkingDirectory=$WorkingDirectory;Arguments=@($Arguments);TimeoutMs=$TimeoutMs;CleanupReserveMs=$CleanupReserveMs;AuthorityEnds=$AuthorityEnds})
    if($script:nativeFault -cin @('Timeout','StreamLoss','Retention')){
        $exception=[InvalidOperationException]::new('Disclosed native '+$script:nativeFault+' failure.');$exception.Data['OwnedCleanupUnverified']=$true;throw $exception
    }
    $directory=Join-Path $pureRoot ('fake-native-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($directory)
    & $ObserveStartup $directory ([pscustomobject]@{Started=$false;synthetic=$true})
    $exit=0;$output='';$errorOutput=''
    if($Arguments[3] -ceq '-File'){
        $output='{"recordType":"win-pcinfo.terminal","reasonCode":"RUNTIME.ELIGIBLE","collectionStarted":false,"runtime":{"eligible":true}}'
        if($script:nativeFault -ceq 'RuntimeRejected'){$exit=1;$output=''}
    }
    else {
        # The closed profile emits only the original arithmetic/hash/culture
        # expressions. This fake runs those expressions in this same host.
        try{$output=@(& ([scriptblock]::Create($Arguments[4]))) -join "`n"}catch{$exit=1;$errorOutput='Disclosed expected malformed representation rejection.'}
    }
    if($script:nativeFault -ceq 'UnknownExit'){$exit=$null}
    $lines=if($output.Length){@([pscustomobject]@{Stream='stdout';Sequence=1;Text=$output;Terminator="`n"})}else{@()}
    [pscustomobject]@{ExitCode=$exit;StandardOutput=$output;StandardError=$errorOutput;StreamRecords=$lines;EvidenceDirectory=$directory}
}
function New-InlineControlShellProcess {
    param($Start)
    $value=[pscustomobject]@{Mode=$script:shellMode;ExitCode=0;Waits=[Collections.Generic.List[int]]::new();KillRequested=$false;Disposed=$false;Directory='';
        SafeHandle=[pscustomobject]@{IsClosed=$false;IsInvalid=$false}}
    if($value.Mode -ceq 'Natural'){$null=& ([scriptblock]::Create($Start.ArgumentList[4]))}
    $value|Add-Member ScriptMethod WaitForExit {
        param([int]$Milliseconds);$this.Waits.Add($Milliseconds)
        if($this.Mode -ceq 'Natural'){return $true}
        if($this.Mode -ceq 'LateNatural' -and $Milliseconds -eq 0){return $true}
        if($Milliseconds -eq 0){return $false}
        if($this.KillRequested){return ($this.Mode -cne 'CleanupWaitFalse')}
        return $false
    }
    $value|Add-Member ScriptMethod Kill {param([bool]$EntireProcessTree);if(-not $EntireProcessTree){throw 'Original ShellExecute kill flag changed.'};$this.KillRequested=$true}
    $value|Add-Member ScriptMethod Dispose {
        if(-not [IO.File]::Exists((Join-Path $this.Directory 'original-terminal.json')) -or -not [IO.File]::Exists((Join-Path $this.Directory 'terminal.json'))){throw 'ShellExecute disposed before independent raw retention.'}
        $this.Disposed=$true
    }
    $script:lastShellProcess=$value
    $value
}
function Get-InlineActualOwningReplay {
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'PrivilegedInlineRepresentation.Tests.ps1'),[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count){throw 'Actual owning inline source must parse.'}
    $matches=@($ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.TryStatementAst] -and $_.Body.Extent.Text.Contains('$candidate=Open-TestCandidate')})
    if($matches.Count -ne 1){throw 'The actual owning inline body must be unique.'}
    $text=$matches[0].Extent.Text
    if(([regex]::Matches($text,'\[Diagnostics\.Process\]::Start\(\$start\)')).Count -ne 1){throw 'Actual ShellExecute creator substitution must be exact.'}
    [scriptblock]::Create($text.Replace('[Diagnostics.Process]::Start($start)','(New-InlineControlShellProcess -Start $start)'))
}
function Open-TestCandidate {
    param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    if($RepositoryRoot -ceq $script:replayCandidateRoot -and $null -eq $CandidatePath -and
        $null -eq $PreparedManifestPath -and $null -eq $PreparedManifestSha256){
        # Disclosed unique standalone preparation substitute; never a build.
        $script:standalonePreparationObserved=$true
        $script:replayCandidate.Prepared=$false
        return $script:replayCandidate
    }
    if($RepositoryRoot -cne $script:replayCandidateRoot -or $CandidatePath -cne $script:replayCandidate.Path -or
        $PreparedManifestPath -cne $script:context.Root.Admission.preparedManifestPath -or
        $PreparedManifestSha256 -cne $script:context.Root.Admission.preparedManifestSha256){throw 'Disclosed candidate admission substitution received changed inputs.'}
    $script:replayCandidate
}
# Import only actual assertion/candidate finalizer definitions, never harness
# startup/build code. The Open boundary above is explicitly substituted.
$harnessTokens=$null;$harnessErrors=$null
$harnessAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'TestHarness.ps1'),[ref]$harnessTokens,[ref]$harnessErrors)
foreach($name in @('Assert-Equal','Close-TestCandidate')){
    $nodes=@($harnessAst.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
    if($harnessErrors.Count -or $nodes.Count -ne 1){throw 'Actual owning support definition must be unique.'}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function New-InlineControlShellOwner {
    param($Binding,[string]$Fault='')
    $output=Join-Path $Binding.Directory ('result-'+[guid]::NewGuid().ToString('N')+'.txt')
    $spec=Get-QualificationInlineShellSpecification -RepositoryRoot $Binding.RepositoryRoot -OutputPath $output
    $start=[Diagnostics.ProcessStartInfo]::new($Binding.HostPath);$start.UseShellExecute=$true;$start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    foreach($argument in $spec.Arguments){$start.ArgumentList.Add($argument)}
    switch($Fault){Window{$start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Normal};Verb{$start.Verb='runas'};
        Credential{$start.UserName='synthetic'};Domain{$start.Domain='synthetic'};Redirect{$start.RedirectStandardOutput=$true};
        ChangedCommand{$start.ArgumentList[4]="'unadmitted'"};RawArguments{$start.Arguments='-Command arbitrary'};
        WrongOutput{$output=Join-Path $Binding.RepositoryRoot 'other/result.txt'}}
    $owner=New-QualificationCapabilityProcessOwner -RepositoryRoot $Binding.RepositoryRoot -Profile PrivilegedInlineShellExecute -StartInfo $start -OutputPath $output
    Assert-QualificationCapabilityCreation -Owner $owner
    $process=New-InlineControlShellProcess -Start $start;$process.Directory=$owner.Directory
    Register-QualificationCapabilityProcess -Owner $owner -Process $process
    [pscustomobject]@{Owner=$owner;Process=$process;Output=$output;Start=$start}
}
$bindings=[Collections.Generic.List[object]]::new()
$originalCulture=[Threading.Thread]::CurrentThread.CurrentCulture
try {
    foreach($fault in @('WrongSource','WrongCandidate','CandidateArray','WrongDigest','WrongManifest','MissingHostPin','WrongHostPin','HostArray','NotPrepared','DuplicateHost')){
        $caught=$false;try{$null=New-InlineControlBinding -Fault $fault}catch{$caught=$true}
        Assert-InlineControl $caught 'Changed source/candidate/manifest or unpinned typed host must refuse before native creation.'
    }
    $binding=New-InlineControlBinding;$bindings.Add($binding);$script:runtimeCandidates=@($binding.HostPath)
    $resolved=Resolve-QualificationInlineRuntime -Binding $binding
    Assert-InlineControl ($resolved -ceq $binding.HostPath -and $script:signatureReads.Count -eq 1) 'Actual discovery/signature/parser contract must execute over the finite exact candidate probe.'
    Assert-InlineControl (($script:nativeCalls[0].Arguments -join '|') -ceq (@('-NoLogo','-NoProfile','-NonInteractive','-File',$binding.Candidate.Path,'-Workflow','CheckRuntime') -join '|')) 'The finite runtime probe retains all seven original argv entries.'
    $before=$script:nativeCalls.Count;$caught=$false
    try{$null=Invoke-QualificationInlineRuntimeProbe -Binding $binding -Executable (Join-Path $binding.RepositoryRoot 'other/pwsh.exe') -ApplicationPath $binding.Candidate.Path}catch{$caught=$true}
    Assert-InlineControl ($caught -and $script:nativeCalls.Count -eq $before) 'An alternate discovered executable cannot gain native creation authority.'
    $binding=New-InlineControlBinding;$bindings.Add($binding);$binding.HostPath=Join-Path $binding.RepositoryRoot 'other/pwsh.exe'
    $before=$script:nativeCalls.Count;$caught=$false
    try{$null=Invoke-QualificationInlineRepresentationNative -Binding $binding -Profile Hash -Inputs @{Bytes=$bytes}}catch{$caught=$true}
    Assert-InlineControl ($caught -and $script:nativeCalls.Count -eq $before) 'A changed binding record cannot substitute a new host under the original host read lock.'
    foreach($fault in @('Timeout','StreamLoss','Retention')){
        $script:nativeFault=$fault;$binding=New-InlineControlBinding;$bindings.Add($binding)
        $other=Join-Path $binding.RepositoryRoot 'other/pwsh.exe';$null=[IO.Directory]::CreateDirectory((Split-Path -Parent $other));[IO.File]::WriteAllText($other,'Disclosed alternate synthetic host, never executed.')
        $script:runtimeCandidates=@($binding.HostPath,$other);$beforeSignature=$script:signatureReads.Count
        $before=$script:nativeCalls.Count;$caught=$null;try{$null=Resolve-QualificationInlineRuntime -Binding $binding}catch{$caught=$_}
        Assert-InlineControl ($null -ne $caught -and (Test-QualificationCleanupUnverified -Exception $caught.Exception) -and $script:nativeCalls.Count -eq ($before+1) -and $script:signatureReads.Count -eq ($beforeSignature+1)) 'Actual runtime catch-all must not downgrade unsafe ownership or admit another candidate.'
    }
    $script:nativeFault='RuntimeRejected';$binding=New-InlineControlBinding;$bindings.Add($binding);$script:runtimeCandidates=@($binding.HostPath)
    $caught=$null;try{$null=Resolve-QualificationInlineRuntime -Binding $binding}catch{$caught=$_}
    Assert-InlineControl ($null -ne $caught -and -not (Test-QualificationCleanupUnverified -Exception $caught.Exception) -and $caught.Exception.Data['ReasonCode'] -ceq 'LAUNCH.POLICY_REJECTED') 'A normal policy rejection keeps its original sanitized reason.'
    $script:nativeFault='';$binding=New-InlineControlBinding;$bindings.Add($binding)
    $observed=Invoke-QualificationInlineRepresentationNative -Binding $binding -Profile Hash -Inputs @{Bytes=$bytes}
    Assert-InlineControl ($LASTEXITCODE -eq 0 -and $observed -ceq (Get-PrivilegedCollectionPlanSha256 $bytes)) 'Actual closed adapter preserves stdout and known native status.'
    $null=Invoke-QualificationInlineRepresentationNative -Binding $binding -Profile Malformed -Inputs @{}
    Assert-InlineControl ($LASTEXITCODE -ne 0 -and -not $binding.Unsafe) 'Natural malformed nonzero remains a safe negative fixture outcome.'
    $script:nativeFault='UnknownExit';$binding=New-InlineControlBinding;$bindings.Add($binding)
    $caught=$null;try{$null=Invoke-QualificationInlineRepresentationNative -Binding $binding -Profile Hash -Inputs @{Bytes=$bytes}}catch{$caught=$_}
    Assert-InlineControl ($null -ne $caught -and (Test-QualificationCleanupUnverified -Exception $caught.Exception) -and $binding.Unsafe) 'Unknown actual native status cannot normalize to zero or safe release.'
    $script:nativeFault=''
    foreach($fault in @('Window','Verb','Credential','Domain','Redirect','ChangedCommand','RawArguments','WrongOutput')){
        $binding=New-InlineControlBinding;$bindings.Add($binding);$caught=$false
        try{$null=New-InlineControlShellOwner -Binding $binding -Fault $fault}catch{$caught=$true}
        Assert-InlineControl $caught 'Changed ShellExecute OS flags, credentials, payload or output path cannot gain fixture creation.'
    }
    $binding=New-InlineControlBinding;$bindings.Add($binding);$shell=New-InlineControlShellOwner -Binding $binding
    $terminal=Wait-QualificationInlineShellBody -Owner $shell.Owner
    Complete-QualificationCapabilityProcess -Owner $shell.Owner -Process $shell.Process
    Assert-InlineControl ($terminal -and $shell.Process.Waits.Count -eq 1 -and $shell.Process.Waits[0] -eq 10000 -and $shell.Process.Disposed) 'Natural genuine ShellExecute profile keeps its exact original body cap and verified disposal.'
    Assert-InlineControl ([IO.File]::ReadAllText($shell.Output) -ceq "Synthetic 漢字 O'Brien") 'Original Shell writer source remains exact UTF8, quotes and Unicode under disclosed in-process replay.'
    $script:authorityBudget=11900;$caught=$false;try{$null=New-InlineControlShellOwner -Binding $binding}catch{$caught=$true};$script:authorityBudget=60000
    Assert-InlineControl $caught 'Shell creation requires twelve seconds of original body/cleanup/retention reserve.'
    $binding=New-InlineControlBinding;$bindings.Add($binding);$shell=New-InlineControlShellOwner -Binding $binding;$shell.Owner.BudgetMs=4000
    $null=Wait-QualificationInlineShellBody -Owner $shell.Owner
    Complete-QualificationCapabilityProcess -Owner $shell.Owner -Process $shell.Process
    Assert-InlineControl ($shell.Process.Waits[0] -gt 0 -and $shell.Process.Waits[0] -le 2000) 'Original Shell body wait clips to unchanged authority with both cleanup and retention reserves.'
    foreach($mode in @('Forced','CleanupWaitFalse')){
        $binding=New-InlineControlBinding;$bindings.Add($binding);$script:shellMode=$mode;$shell=New-InlineControlShellOwner -Binding $binding
        $body=$null;try{if(-not (Wait-QualificationInlineShellBody -Owner $shell.Owner)){throw 'Disclosed original false body witness.'}}catch{$body=$_}
        $caught=$null;try{$null=Complete-QualificationCapabilityProcess -Owner $shell.Owner -Process $shell.Process -BodyError $body}catch{$caught=$_}
        Assert-InlineControl ($null -ne $caught -and (Test-QualificationCleanupUnverified -Exception $caught.Exception) -and $shell.Owner.Unsafe -and $shell.Owner.Forced -and -not $shell.Process.Disposed) 'Forced ShellExecute cleanup cannot become functional acceptance after eventual native exit.'
        Assert-InlineControl ($shell.Process.Waits.Count -eq 3 -and $shell.Process.Waits[0] -eq 10000 -and $shell.Process.Waits[1] -eq 0 -and $shell.Process.Waits[2] -eq 1000) 'Shell material cleanup has only its original checked finite one-second observation.'
        Assert-InlineControl ($shell.Owner.TerminalVerified -eq ($mode -ceq 'Forced')) 'A false post-termination witness must remain unverified.'
        $raw=Get-Content -LiteralPath (Join-Path $shell.Owner.Directory 'original-terminal.json') -Raw|ConvertFrom-Json -DateKind String
        Assert-InlineControl ($raw.forced -and $raw.originalBodyWait -eq $false -and -not $raw.processTreeAbsenceClaim -and [IO.File]::Exists((Join-Path $shell.Owner.Directory 'owned-pending.json'))) 'Raw original body/forced outcome and exact pending bytes remain retained without descendant absence inference.'
    }
    $binding=New-InlineControlBinding;$bindings.Add($binding);$script:shellMode='LateNatural';$shell=New-InlineControlShellOwner -Binding $binding
    $null=Wait-QualificationInlineShellBody -Owner $shell.Owner
    $caught=$null;try{$null=Complete-QualificationCapabilityProcess -Owner $shell.Owner -Process $shell.Process}catch{$caught=$_}
    Assert-InlineControl ($null -ne $caught -and $shell.Owner.TerminalVerified -and $shell.Owner.Unsafe -and -not $shell.Owner.Forced -and -not $shell.Process.Disposed) 'Late natural terminal cannot erase the original false body witness.'
    $binding=New-InlineControlBinding;$bindings.Add($binding);$script:shellMode='Forced';$shell=New-InlineControlShellOwner -Binding $binding
    $null=Wait-QualificationInlineShellBody -Owner $shell.Owner;$shell.Owner.BudgetMs=1500
    $caught=$null;try{$null=Complete-QualificationCapabilityProcess -Owner $shell.Owner -Process $shell.Process}catch{$caught=$_}
    Assert-InlineControl ($null -ne $caught -and $shell.Process.KillRequested -and $shell.Process.Waits[2] -gt 0 -and $shell.Process.Waits[2] -le 500) 'The original one-second cleanup wait clips to its unchanged retention reserve.'
    $binding=New-InlineControlBinding;$bindings.Add($binding);$shell=New-InlineControlShellOwner -Binding $binding
    $null=Wait-QualificationInlineShellBody -Owner $shell.Owner;$shell.Owner.BudgetMs=900
    $caught=$null;try{$null=Complete-QualificationCapabilityProcess -Owner $shell.Owner -Process $shell.Process}catch{$caught=$_}
    Assert-InlineControl ($null -ne $caught -and -not $shell.Process.KillRequested -and -not $shell.Process.Disposed) 'Exhausted original authority cannot issue a new termination or fabricate cleanup.'
    $script:shellMode='Natural';$binding=New-InlineControlBinding;$bindings.Add($binding);$shell=New-InlineControlShellOwner -Binding $binding
    $null=Wait-QualificationInlineShellBody -Owner $shell.Owner;$script:retentionFault='original-terminal.json'
    $caught=$null;try{$null=Complete-QualificationCapabilityProcess -Owner $shell.Owner -Process $shell.Process}catch{$caught=$_};$script:retentionFault=''
    Assert-InlineControl ($null -ne $caught -and -not $shell.Process.Disposed -and [IO.File]::Exists((Join-Path $shell.Owner.Directory 'terminal.json'))) 'A failed Shell raw copy cannot skip the independent copy or dispose the original handle.'
    $preparedBinding=New-InlineControlBinding;$bindings.Add($preparedBinding)
    $script:replayCandidateRoot=$preparedBinding.RepositoryRoot;$script:replayCandidate=$preparedBinding.Candidate
    $repositoryRoot=$preparedBinding.RepositoryRoot;$CandidatePath=$null;$PreparedManifestPath=$null;$PreparedManifestSha256=$null
    $candidate=$null;$binding=$null;$bodyError=$null;$script:standalonePreparationObserved=$false
    $before=$script:nativeCalls.Count;$caught=$null
    try{$null=. (Get-InlineActualOwningReplay)}catch{$caught=$_}
    Assert-InlineControl ($script:standalonePreparationObserved -and $null -ne $caught -and $null -eq $binding -and $script:nativeCalls.Count -eq $before) 'Actual bare standalone body may prepare its unique candidate but cannot grant runtime or inline native authority.'
    foreach($mode in @('Natural','Forced')){
        $preparedBinding=New-InlineControlBinding;$bindings.Add($preparedBinding)
        $script:replayCandidateRoot=$preparedBinding.RepositoryRoot;$script:replayCandidate=$preparedBinding.Candidate
        $repositoryRoot=$preparedBinding.RepositoryRoot;$CandidatePath=$preparedBinding.Candidate.Path
        $PreparedManifestPath=$script:context.Root.Admission.preparedManifestPath;$PreparedManifestSha256=$script:context.Root.Admission.preparedManifestSha256
        $candidate=$null;$binding=$null;$bodyError=$null;$script:shellMode=$mode;$script:runtimeCandidates=@($preparedBinding.HostPath)
        $before=$script:nativeCalls.Count;$caught=$null
        try{$null=. (Get-InlineActualOwningReplay)}catch{$caught=$_}
        if($null -ne $binding){$bindings.Add($binding)}
        Assert-InlineControl ($script:nativeCalls.Count -eq ($before+17)) 'Actual owning body must execute one finite probe and all sixteen original inline cases.'
        if($mode -ceq 'Natural'){
            if($null -ne $caught){throw [InvalidOperationException]::new('Actual natural owning replay failed.', $caught.Exception)}
            Assert-InlineControl ($null -eq $caught -and $script:lastShellProcess.Disposed -and -not [IO.File]::Exists($outputPath)) 'Actual owning body preserves every assertion and deletes only independently verified natural writer output.'
        }
        else {
            Assert-InlineControl ($null -ne $caught -and (Test-QualificationCleanupUnverified -Exception $caught.Exception) -and -not $script:lastShellProcess.Disposed -and $binding.Unsafe -and [IO.Directory]::Exists($ownedRoot)) 'Actual owning body retains forced original handle, fixture and typed unsafe outcome.'
        }
    }
}
finally {
    [Threading.Thread]::CurrentThread.CurrentCulture=$originalCulture
    foreach($binding in $bindings){$binding.HostStream.Dispose();$binding.Candidate.Stream.Dispose()}
    $boundary=[IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $PSScriptRoot) '.test-output')).TrimEnd('\')+'\'
    if(-not [IO.Path]::GetFullPath($pureRoot).StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)){throw 'Pure cleanup escaped its exact synthetic root.'}
    if(@(Get-ChildItem -LiteralPath $pureRoot -Directory -Recurse -Force|Where-Object{($_.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0}).Count){throw 'Pure cleanup refuses a reparse point.'}
    [IO.Directory]::Delete($pureRoot,$true)
}
Write-Output ('PASS: '+$script:controls+' child-free closed inline profile controls; sixteen original command forms preserved.')
