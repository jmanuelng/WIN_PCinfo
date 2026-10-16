[CmdletBinding()]
param([ValidateSet('All','Valid','ValidCloseRetentionFailure')][string]$CreatorPrerequisite='All')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $PSScriptRoot 'QualificationFixtureProcess.ps1')
$hostPath=Get-TestAdmittedRuntimeHost
# Optional creator proof is bound by the real focused File admission, never a
# standalone test-path alias or an unclaimed synthetic Case.
if($CreatorPrerequisite -cne 'All'){
    $proofContext=Get-TestNativeAdmissionContext -RepositoryRoot $repositoryRoot -SelfIdentity (Get-TestNativeSelfIdentity)
    $proofAdmission=$proofContext.Parent.Admission
    $proofParameters=ConvertFrom-TestNamedParameterRecord -Parameters $proofAdmission.namedParameters
    if($proofContext.Depth -ne 0 -or $proofAdmission.scope -cne 'FocusedTestFile' -or
        $proofAdmission.testPath -ine $PSCommandPath -or
        $proofParameters -isnot [Collections.IDictionary] -or
        $proofParameters.Count -ne 1 -or
        -not $proofParameters.Contains('CreatorPrerequisite') -or
        $proofParameters.CreatorPrerequisite -cne $CreatorPrerequisite){
        throw 'Creator prerequisite requires the exact original focused File and one admitted selector.'
    }
}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput((Get-PrivilegedCollectionWorkerSource),[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq 'Read-CiToolJson'},$false)
$source=$node.Extent.Text.Replace('[IO.File]::Exists($path)','(Test-ControlledCiToolPath $path)').Replace('[IO.File]::GetAttributes($path)','[IO.FileAttributes]::Normal').Replace('[Diagnostics.Process]::Start($start)','(Start-ControlledCiTool $start)')
$source=$source.Replace('$child.Kill($true)','$script:ciToolForced=$true;$child.Kill($true)')
# Preserve original caller causes before finalization; waits and operation bounds remain unchanged.
$originalCiToolFinalizer='try {if(-not $child.HasExited){$script:ciToolForced=$true;$child.Kill($true);if(-not $child.WaitForExit(1000)){throw ''CiTool termination unverified.''}}}finally{$child.Dispose()}'
$retainedCiToolFinalizer='try {$script:ciToolObservedHasExited=$child.HasExited;if(-not $script:ciToolObservedHasExited){$script:ciToolForced=$true;$child.Kill($true);if(-not $child.WaitForExit(1000)){throw ''CiTool termination unverified.''}}}catch{$script:ciToolCallerCleanupError=$_;throw}finally{
    $ciToolRetentionError=$null;$ciToolDisposeError=$null;$ciToolCompletionError=$null
    try{Save-QualificationOriginalCreatorTerminal -Owner $script:ciToolOwner -Disposition OriginalCiToolSourceBoundary -Forced $script:ciToolForced -RawStandardOutput $(if($length){[byte[]]$buffer[0..($length-1)]}else{[byte[]]@()}) -StreamContract RawStdoutBound65537OriginalStderrUnread -ExpectedOriginalProcess $child -CallerHasExitedObservation $script:ciToolObservedHasExited -CallerBodyErrorRecord $script:ciToolOperationError -CallerCleanupErrorRecord $script:ciToolCallerCleanupError}catch{$ciToolRetentionError=$_;$script:ciToolOwner.Unsafe=$true}
    try{$child.Dispose()}catch{$ciToolDisposeError=$_;$script:ciToolOwner.Unsafe=$true}
    if($null -eq $ciToolRetentionError -and $null -eq $ciToolDisposeError -and $null -eq $script:ciToolCallerCleanupError){try{Complete-QualificationOriginalCreatorOwner $script:ciToolOwner}catch{$ciToolCompletionError=$_;$script:ciToolOwner.Unsafe=$true}}
    if($null -ne $script:ciToolCallerCleanupError -or $null -ne $ciToolRetentionError -or $null -ne $ciToolDisposeError -or $null -ne $ciToolCompletionError){
        $script:ciToolOwner.Unsafe=$true
        $ciToolFailureRecords=[Collections.Generic.List[Management.Automation.ErrorRecord]]::new()
        foreach($ciToolFailureRecord in @($script:ciToolOperationError,$script:ciToolCallerCleanupError,$ciToolRetentionError,$ciToolDisposeError,$ciToolCompletionError)){if($null -ne $ciToolFailureRecord){$ciToolFailureRecords.Add($ciToolFailureRecord)}}
        $ciToolFailureCauses=[Collections.Generic.List[Exception]]::new();foreach($ciToolFailureRecord in $ciToolFailureRecords){$ciToolFailureCauses.Add($ciToolFailureRecord.Exception)}
        $ciToolFailure=[AggregateException]::new(''QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: original CiTool caller and finalization failures retained.'',$ciToolFailureCauses.ToArray())
        $ciToolFailure.Data[''OriginalErrorRecord'']=$ciToolFailureRecords[0];$ciToolFailure.Data[''OriginalBodyErrorRecord'']=$script:ciToolOperationError;$ciToolFailure.Data[''CallerCleanupErrorRecord'']=$script:ciToolCallerCleanupError
        $ciToolFailure.Data[''TerminalRetentionErrorRecord'']=$ciToolRetentionError;$ciToolFailure.Data[''DisposeErrorRecord'']=$ciToolDisposeError;$ciToolFailure.Data[''CompletionErrorRecord'']=$ciToolCompletionError;$ciToolFailure.Data[''OrderedErrorRecords'']=$ciToolFailureRecords.ToArray()
        $ciToolFailure.Data[''StrongOriginalCreatorOwner'']=$script:ciToolOwner;$ciToolFailure.Data[''StrongOriginalProcessReference'']=$child;$ciToolFailure.Data[''OwnedCleanupUnverified'']=$true;$ciToolFailure.Data[''RetentionCleanupUncertain'']=($null -ne $ciToolDisposeError)
        throw $ciToolFailure
    }
}'
if($source.Split([string[]]@($originalCiToolFinalizer),[StringSplitOptions]::None).Count -ne 2){throw 'Exact original CiTool cleanup/disposal clause differs.'}
$source=$source.Replace($originalCiToolFinalizer,$retainedCiToolFinalizer)
$originalCiToolBodyFinally='} finally {'
if($source.Split([string[]]@($originalCiToolBodyFinally),[StringSplitOptions]::None).Count -ne 2){throw 'Exact original CiTool protected body/finally differs.'}
$source=$source.Replace($originalCiToolBodyFinally,'} catch {$script:ciToolOperationError=$_;throw} finally {')
if($CreatorPrerequisite -ceq 'ValidCloseRetentionFailure'){
    $script:ciToolFaultSetupError=$null
    # Install the fault only after the original caller has acquired its child,
    # inside Read-CiToolJson's existing protected try/finally.
    $assignment='$child=(Start-ControlledCiTool $start)'
    if($source.Split([string[]]@($assignment),[StringSplitOptions]::None).Count -ne 2){
        throw 'Exact original protected child assignment differs.'
    }
    $source=$source.Replace($assignment,$assignment+';Initialize-ControlledCiToolCloseRetentionFault')
}
. ([scriptblock]::Create($source))
function Test-ControlledCiToolPath($Path){
    Assert-Equal ([IO.Path]::Combine([Environment]::SystemDirectory,'CiTool.exe')) $Path 'CiTool cannot resolve through PATH or caller input'
    $true
}
function Initialize-ControlledCiToolCloseRetentionFault {
    if($CreatorPrerequisite -ceq 'ValidCloseRetentionFailure'){
        # Real filesystem refusal at the existing close-proof CreateNew writer.
        # The directory is inside this actual private owner and is never removed
        # here. Original terminal/disposal/unsafe pending records stay authoritative.
        try{
            $closePath=Join-Path $script:ciToolOwner.Directory 'original-close-proof.json'
            if([IO.File]::Exists($closePath) -or [IO.Directory]::Exists($closePath) -or
                (Get-QualificationFixtureRemainingMs $script:ciToolOwner) -lt 2000){
                throw 'Exact close-retention failure target or reserve differs.'
            }
            Write-QualificationFixtureRecord -Path (Join-Path $script:ciToolOwner.Directory 'close-retention-fault-intent.json') -Value ([ordered]@{
                contract='win-pcinfo.original-creator-close-retention-fault-intent/1.0.0';
                selector=$CreatorPrerequisite;profile='CiToolValid';testPath=$PSCommandPath;
                parentNonce=$script:ciToolOwner.Pending.parentNonce;rootNonce=$script:ciToolOwner.Pending.rootNonce;
                childIdentity=$script:ciToolOwner.Identity;exactTarget=$closePath;
                mechanism='OrdinaryDirectoryBlocksExistingCloseProofCreateNew';
                childAlreadyRegistered=$true;originalFailureMustPropagate=$true;
                originalCleanupAccepted=$false;applicationAcceptance=$false})
            $null=New-Item -ItemType Directory -Path $closePath -ErrorAction Stop
        }catch{
            $script:ciToolFaultSetupError=$_
            $script:ciToolOwner.Unsafe=$true
            $failure=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: actual creator fault setup is incomplete.', $_.Exception)
            $failure.Data['OriginalErrorRecord']=$_;$failure.Data['StrongOriginalCreatorOwner']=$script:ciToolOwner
            $failure.Data['OwnedCleanupUnverified']=$true
            throw $failure
        }
    }
}
$children=[Collections.Generic.List[int]]::new()
function Start-ControlledCiTool($Start){
    Assert-Equal '-lp,-json' ($Start.ArgumentList -join ',') 'only the fixed JSON inventory switches may execute'
    Assert-Equal $false $Start.UseShellExecute 'listing uses the owned direct process path'
    $Start.FileName=$hostPath;$Start.ArgumentList.Clear()
    foreach($argument in $script:ciToolPreparedArguments){$Start.ArgumentList.Add($argument)}
    # Preparation is outside the product operation clock; actual Start and
    # immediate registration remain inside its original protected caller.
    if($null -eq $script:ciToolOwner -or $script:ciToolPreparedCase -cne $case -or
        $script:ciToolOwner.Pending.profile -cne ('CiTool'+$case) -or
        $script:ciToolOwner.Pending.testPath -ine $PSCommandPath -or
        $script:ciToolOwner.Pending.hostPath -ine $hostPath -or $Start.FileName -ine $hostPath -or
        (ConvertTo-Json -InputObject @($Start.ArgumentList) -Compress) -cne $script:ciToolPreparedArgumentsJson -or
        (ConvertTo-Json -InputObject @($script:ciToolOwner.Pending.arguments) -Compress) -cne $script:ciToolPreparedArgumentsJson -or
        $Start.CreateNoWindow -ne $true -or $Start.RedirectStandardOutput -ne $true -or
        $Start.RedirectStandardError -ne $true -or $Start.RedirectStandardInput -ne $false -or
        -not [string]::IsNullOrEmpty($Start.UserName) -or -not [string]::IsNullOrEmpty($Start.Arguments) -or
        $Start.WorkingDirectory -cne $script:ciToolOwner.Pending.workingDirectory){
        if($null -ne $script:ciToolOwner){$script:ciToolOwner.Unsafe=$true}
        $failure=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: prepared original creator does not match its exact case and StartInfo.')
        $failure.Data['OwnedCleanupUnverified']=$true;$failure.Data['StrongOriginalCreatorOwner']=$script:ciToolOwner
        throw $failure
    }
    try{Assert-QualificationFixtureProcessAdmission -Owner $script:ciToolOwner}catch{
        $preparedAdmissionError=$_;$script:ciToolOwner.Unsafe=$true
        $failure=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: prepared original creator admission is no longer valid.', $preparedAdmissionError.Exception)
        $failure.Data['OriginalErrorRecord']=$preparedAdmissionError
        $failure.Data['StrongOriginalCreatorOwner']=$script:ciToolOwner
        $failure.Data['OwnedCleanupUnverified']=$true
        throw $failure
    }
    $script:ciToolForced=$false
    $child=[Diagnostics.Process]::Start($Start)
    Register-QualificationFixtureProcess -Owner $script:ciToolOwner -Process $child
    $children.Add($child.Id);$child
}
$cases=if($CreatorPrerequisite -ceq 'All'){@('Valid','Bound','Denied','Timeout','NonUtf8')}else{@('Valid')}
foreach($case in $cases){
    # Keep fixture admission/ACL/durable preparation out of the unchanged
    # 2000ms native operation. No child is started by this preparation.
    $script:ciToolOwner=$null;$script:ciToolPreparationError=$null
    $script:ciToolPreparedCase=$case
    $scriptText=switch($case){
        Valid {'[Console]::Write(''{"Policies":[]}'')'}
        Bound {'[Console]::Write((''x''*65537))'}
        Denied {'exit 5'}
        Timeout {'[Threading.Thread]::Sleep(10000)'}
        NonUtf8 {'[Console]::OpenStandardOutput().WriteByte(255)'}
    }
    $script:ciToolPreparedArguments=[string[]]@('-NoLogo','-NoProfile','-NonInteractive','-Command',$scriptText)
    # The string snapshot is immutable even if an argument array is changed.
    $script:ciToolPreparedArgumentsJson=ConvertTo-Json -InputObject @($script:ciToolPreparedArguments) -Compress
    $preparedStart=[Diagnostics.ProcessStartInfo]::new($hostPath)
    $preparedStart.UseShellExecute=$false;$preparedStart.CreateNoWindow=$true
    $preparedStart.RedirectStandardOutput=$true;$preparedStart.RedirectStandardError=$true
    foreach($argument in $script:ciToolPreparedArguments){$preparedStart.ArgumentList.Add($argument)}
    try{
        $script:ciToolOwner=New-QualificationOriginalCreatorOwner -RepositoryRoot $repositoryRoot -TestPath $PSCommandPath -Profile ('CiTool'+$case) -StartInfo $preparedStart
        Assert-QualificationOriginalCreatorCreation $script:ciToolOwner
    }catch{
        $script:ciToolPreparationError=$_
        if($null -ne $script:ciToolOwner){$script:ciToolOwner.Unsafe=$true}
        $failure=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: original creator preparation failed before the operation.', $_.Exception)
        $failure.Data['OriginalErrorRecord']=$script:ciToolPreparationError
        $failure.Data['StrongOriginalCreatorOwner']=$script:ciToolOwner
        $preparedOwners=Get-Variable QualificationOriginalCreatorOwners -Scope Script -ErrorAction SilentlyContinue
        if($null -ne $preparedOwners){$failure.Data['StrongOriginalCreatorOwners']=$preparedOwners.Value}
        $failure.Data['OwnedCleanupUnverified']=$true
        throw $failure
    }
    $script:ciToolOperationError=$null;$script:ciToolCallerCleanupError=$null;$script:ciToolObservedHasExited=$null
    $watch=[Diagnostics.Stopwatch]::StartNew();$failed=$false;$value=$null
    try {$value=Read-CiToolJson}catch{
        if($CreatorPrerequisite -ceq 'ValidCloseRetentionFailure' -and $null -ne $script:ciToolFaultSetupError){
            $ciToolCaughtError=$_
            $failure=[AggregateException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: original creator fault setup and caller finalization failed.',
                [Exception[]]@($script:ciToolFaultSetupError.Exception,$ciToolCaughtError.Exception))
            $failure.Data['OriginalErrorRecord']=$script:ciToolFaultSetupError
            $failure.Data['SetupErrorRecord']=$script:ciToolFaultSetupError
            $failure.Data['CaughtFinalizationErrorRecord']=$ciToolCaughtError
            $failure.Data['StrongOriginalCreatorOwner']=$script:ciToolOwner
            $failure.Data['OwnedCleanupUnverified']=$true
            throw $failure
        }
        if(Test-QualificationCleanupUnverified $_.Exception){throw};$failed=$true
    }
    if($CreatorPrerequisite -ceq 'ValidCloseRetentionFailure'){
        $failure=[InvalidOperationException]::new('QUALIFICATION.OWNED_CLEANUP_UNVERIFIED: expected actual close-retention refusal did not propagate.')
        $failure.Data['OwnedCleanupUnverified']=$true;$failure.Data['StrongOriginalCreatorOwner']=$script:ciToolOwner
        throw $failure
    }
    Assert-Equal ($case -ne 'Valid') $failed 'native output, errors and deadlines remain bounded before parsing'
    if($case -eq 'Valid'){Assert-Equal '{"Policies":[]}' $value 'the native boundary preserves exact JSON bytes'}
    Assert-Equal $true ($watch.Elapsed.TotalSeconds -lt 5) 'native listing and cleanup stay within the operation budget'
    foreach($childId in $children){Assert-Equal 0 @(Get-Process -Id $childId -ErrorAction SilentlyContinue).Count 'no controlled CiTool child survives source completion'}
}
if($CreatorPrerequisite -ceq 'All'){
Write-Output 'PASS: real controlled child I/O, byte bound, denied exit, deadline, UTF-8 refusal, and owned child absence; no CiTool executed.'
}else{
    Write-Output 'PASS: one real finite CiToolValid creator, original terminal/close custody and owned child absence; scoped prerequisite only, no CiTool executed.'
}
