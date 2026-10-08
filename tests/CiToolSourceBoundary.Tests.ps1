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
    if($proofContext.Depth -ne 0 -or $proofAdmission.scope -cne 'FocusedTestFile' -or
        $proofAdmission.testPath -ine $PSCommandPath -or
        $proofAdmission.namedParameters -isnot [Collections.IDictionary] -or
        $proofAdmission.namedParameters.Count -ne 1 -or
        -not $proofAdmission.namedParameters.Contains('CreatorPrerequisite') -or
        $proofAdmission.namedParameters.CreatorPrerequisite -cne $CreatorPrerequisite){
        throw 'Creator prerequisite requires the exact original focused File and one admitted selector.'
    }
}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput((Get-PrivilegedCollectionWorkerSource),[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq 'Read-CiToolJson'},$false)
$source=$node.Extent.Text.Replace('[IO.File]::Exists($path)','(Test-ControlledCiToolPath $path)').Replace('[IO.File]::GetAttributes($path)','[IO.FileAttributes]::Normal').Replace('[Diagnostics.Process]::Start($start)','(Start-ControlledCiTool $start)')
$source=$source.Replace('$child.Kill($true)','$script:ciToolForced=$true;$child.Kill($true)')
$source=$source.Replace('finally{$child.Dispose()}','finally{try{Save-QualificationOriginalCreatorTerminal -Owner $script:ciToolOwner -Disposition OriginalCiToolSourceBoundary -Forced $script:ciToolForced -RawStandardOutput $(if($length){[byte[]]$buffer[0..($length-1)]}else{[byte[]]@()}) -StreamContract RawStdoutBound65537OriginalStderrUnread}finally{$child.Dispose()};Complete-QualificationOriginalCreatorOwner $script:ciToolOwner}')
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
    $scriptText=switch($case){
        Valid {'[Console]::Write(''{"Policies":[]}'')'}
        Bound {'[Console]::Write((''x''*65537))'}
        Denied {'exit 5'}
        Timeout {'[Threading.Thread]::Sleep(10000)'}
        NonUtf8 {'[Console]::OpenStandardOutput().WriteByte(255)'}
    }
    $Start.FileName=$hostPath;$Start.ArgumentList.Clear()
    foreach($argument in @('-NoLogo','-NoProfile','-NonInteractive','-Command',$scriptText)){$Start.ArgumentList.Add($argument)}
    $script:ciToolOwner=New-QualificationOriginalCreatorOwner -RepositoryRoot $repositoryRoot -TestPath $PSCommandPath -Profile ('CiTool'+$case) -StartInfo $Start
    Assert-QualificationOriginalCreatorCreation $script:ciToolOwner
    $script:ciToolForced=$false
    $child=[Diagnostics.Process]::Start($Start)
    Register-QualificationFixtureProcess -Owner $script:ciToolOwner -Process $child
    $children.Add($child.Id);$child
}
$cases=if($CreatorPrerequisite -ceq 'All'){@('Valid','Bound','Denied','Timeout','NonUtf8')}else{@('Valid')}
foreach($case in $cases){
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
