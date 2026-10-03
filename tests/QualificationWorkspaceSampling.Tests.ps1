[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$draftRoot=Split-Path $PSScriptRoot
$writer=$draftRoot
. (Join-Path $writer 'src/EvidenceWorkspace.ps1')
. (Join-Path $PSScriptRoot 'QualificationWorkspaceSampling.ps1')
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),[ref]$null,[ref]$null)
$functionAst=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Measure-QualificationWorkload'},$true)
. ([scriptblock]::Create($functionAst.Extent.Text))
$script:Assertions=0
function Assert-Sampler {param([bool]$Condition,[string]$Because) $script:Assertions++;if(-not $Condition){throw $Because}}
$parent=[IO.Path]::GetFullPath((Join-Path $writer '.test-output/sampler-native-unit'))
$owned=[IO.Path]::GetFullPath((Join-Path $parent ([guid]::NewGuid().ToString('N'))))
if(-not $owned.StartsWith($parent+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'TEST.SCOPE_INVALID'}
$RequireQualityBudgets=$false
$qualityWatch=[Diagnostics.Stopwatch]::StartNew()
$quality=[ordered]@{sampledPrivateBytes=0L;sampledWorkingSetBytes=0L;sampledWorkspaceBytes=0L;workspaceSamplingLosses=0L;sampleCount=0L;maximumSampleGapMilliseconds=0L;firstSampleMilliseconds=-1L;lastSampleMilliseconds=0L}
$qualificationWorkspaceDirectoryIdentities=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
function New-DenialRecord {param([AllowNull()]$Target) [Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new('Synthetic sampler access denied'),'DirUnauthorizedAccessError',[Management.Automation.ErrorCategory]::PermissionDenied,$Target)}
try{
    $testRoot=Join-Path $owned 'case'
    $target=Join-Path $testRoot 'synthetic-recovery'
    $null=[IO.Directory]::CreateDirectory($target)
    [IO.File]::WriteAllText((Join-Path $target 'synthetic.json'),('x'*42))
    Measure-QualificationWorkload
    Assert-Sampler ($quality.sampledWorkspaceBytes -eq 42 -and $qualificationWorkspaceDirectoryIdentities.ContainsKey($target) -and $qualificationWorkspaceDirectoryIdentities.ContainsKey($testRoot)) 'Successful sampler did not record exact owned identities or byte total.'
    $record=New-DenialRecord $target
    Assert-Sampler (-not (Test-QualificationWorkspaceDirectoryDisappeared -Failure $record -Root $testRoot -Known $qualificationWorkspaceDirectoryIdentities)) 'Present directory was mislabeled absent.'
    # An observed replacement cannot inherit a cached identity. Keep the
    # old directory alive to guarantee that the file ID cannot be recycled.
    $originalId=$qualificationWorkspaceDirectoryIdentities[$target]
    $renamed=Join-Path $owned 'original-directory'
    [IO.Directory]::Move($target,$renamed)
    $null=[IO.Directory]::CreateDirectory($target)
    [IO.File]::WriteAllText((Join-Path $target 'replacement.json'),'replacement')
    $replacementError=$null
    try{Measure-QualificationWorkload}catch{$replacementError=$_.Exception.Message}
    Assert-Sampler ($replacementError -ceq 'QUALIFICATION.WORKSPACE_IDENTITY_CHANGED') 'Cached directory replacement passed a successful sample.'
    Assert-Sampler ($qualificationWorkspaceDirectoryIdentities[$target] -ceq $originalId -and $quality.workspaceSamplingLosses -eq 0 -and $quality.sampledWorkspaceBytes -eq 42) 'Replacement refreshed provenance or changed observer evidence.'
    [IO.Directory]::Delete($target,$true)
    [IO.Directory]::Move($renamed,$target)
    # Delete exactly the previously observed directory, then inject the same
    # structured UnauthorizedAccess error shape observed in the real race.
    [IO.Directory]::Delete($target,$true)
    Assert-Sampler (Test-QualificationWorkspaceDirectoryDisappeared -Failure $record -Root $testRoot -Known $qualificationWorkspaceDirectoryIdentities) 'Exact observed disappearance did not prove native absence and stable parent.'
    function Get-ChildItem {[CmdletBinding()]param($LiteralPath,[switch]$File,[switch]$Recurse) $PSCmdlet.ThrowTerminatingError($record)}
    $previousMaximum=$quality.sampledWorkspaceBytes
    Measure-QualificationWorkload
    Assert-Sampler ($quality.workspaceSamplingLosses -eq 1 -and $quality.sampledWorkspaceBytes -eq $previousMaximum) 'Proved disappearance did not disclose a loss and preserve the observed maximum.'
    $unknown=Join-Path $testRoot 'never-observed'
    foreach($badTarget in @($unknown,(Join-Path $owned 'outside-case'),($testRoot+'\..\outside-case'),$null)){
        $bad=New-DenialRecord $badTarget
        Assert-Sampler (-not (Test-QualificationWorkspaceDirectoryDisappeared -Failure $bad -Root $testRoot -Known $qualificationWorkspaceDirectoryIdentities)) 'Unknown, outside or noncanonical target bypassed access denial.'
    }
    # A replaced parent must not inherit the previous parent's absence proof.
    $parentIdentity=$qualificationWorkspaceDirectoryIdentities[$testRoot]
    $qualificationWorkspaceDirectoryIdentities[$testRoot]='00000000:00000000:00000000'
    Assert-Sampler (-not (Test-QualificationWorkspaceDirectoryDisappeared -Failure $record -Root $testRoot -Known $qualificationWorkspaceDirectoryIdentities)) 'Replaced parent identity bypassed denial.'
    $qualificationWorkspaceDirectoryIdentities[$testRoot]=$parentIdentity
    # A recreated target is present, irrespective of its current identity.
    $null=[IO.Directory]::CreateDirectory($target)
    Assert-Sampler (-not (Test-QualificationWorkspaceDirectoryDisappeared -Failure $record -Root $testRoot -Known $qualificationWorkspaceDirectoryIdentities)) 'Recreated target was incorrectly considered disappeared.'
    $denial=$null;try{Measure-QualificationWorkload}catch{$denial=$_.Exception}
    Assert-Sampler ($denial -is [UnauthorizedAccessException] -and $quality.workspaceSamplingLosses -eq 1 -and $quality.sampledWorkspaceBytes -eq 42) 'Present target access denial was swallowed or mislabeled a lost sample.'
    # Arbitrary observer errors have no structured exact-owned target.
    $record=New-DenialRecord $null
    $denial=$null;try{Measure-QualificationWorkload}catch{$denial=$_.Exception}
    Assert-Sampler ($denial -is [UnauthorizedAccessException] -and $quality.workspaceSamplingLosses -eq 1) 'Arbitrary access denial became cleanup.'
    Remove-Item Function:\Get-ChildItem
    # A real persistent denied directory must remain a failure, even though
    # its name and parent were previously observed inside this owned fixture.
    $fixtureIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{$fixtureActor=$fixtureIdentity.User.Value}finally{$fixtureIdentity.Dispose()}
    [IO.File]::WriteAllText((Join-Path $target 'denied.json'),'synthetic')
    $savedTargetAcl=Get-Acl -LiteralPath $target
    $deniedTargetAcl=Get-Acl -LiteralPath $target
    $deniedTargetAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($fixtureActor),
        [Security.AccessControl.FileSystemRights]::ListDirectory,
        [Security.AccessControl.InheritanceFlags]::None,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Deny))
    try{
        Set-Acl -LiteralPath $target -AclObject $deniedTargetAcl
        $denial=$null;try{Measure-QualificationWorkload}catch{$denial=$_.Exception}
        Assert-Sampler ($denial -is [UnauthorizedAccessException] -and $quality.workspaceSamplingLosses -eq 1 -and $quality.sampledWorkspaceBytes -eq 42) 'Real persistent access denial was swallowed or counted as cleanup.'
    }finally{Set-Acl -LiteralPath $target -AclObject $savedTargetAcl}
    [IO.File]::Delete((Join-Path $target 'denied.json'))
    # Successful parent enumeration is independent of native missing. Deny
    # only parent listing temporarily; restore its exact ACL before cleanup.
    [IO.Directory]::Delete($target)
    $savedParentAcl=Get-Acl -LiteralPath $testRoot
    $deniedParentAcl=Get-Acl -LiteralPath $testRoot
    $deniedParentAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($fixtureActor),
        [Security.AccessControl.FileSystemRights]::ListDirectory,
        [Security.AccessControl.InheritanceFlags]::None,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Deny))
    try{
        Set-Acl -LiteralPath $testRoot -AclObject $deniedParentAcl
        Assert-Sampler (-not (Test-QualificationWorkspaceDirectoryDisappeared -Failure (New-DenialRecord $target) -Root $testRoot -Known $qualificationWorkspaceDirectoryIdentities)) 'Denied parent listing proved absence without successful enumeration.'
    }finally{Set-Acl -LiteralPath $testRoot -AclObject $savedParentAcl}
    $boundFiles=@()
    try{
        foreach($index in 1..129){
            $boundFile=Join-Path $testRoot ('bound-'+$index+'.txt')
            [IO.File]::WriteAllText($boundFile,'')
            $boundFiles+=$boundFile
        }
        Assert-Sampler (-not (Test-QualificationWorkspaceDirectoryDisappeared -Failure (New-DenialRecord $target) -Root $testRoot -Known $qualificationWorkspaceDirectoryIdentities)) 'Parent enumeration beyond the proof bound authorized absence.'
    }finally{foreach($boundFile in $boundFiles){[IO.File]::Delete($boundFile)}}
    $null=[IO.Directory]::CreateDirectory($target)
    # Reparse/refusal ordering is exercised using an owned local directory
    # link; no network address or remote path is part of this fixture.
    $link=Join-Path $testRoot 'synthetic-link'
    $destination=Join-Path $owned 'local-link-destination';$null=[IO.Directory]::CreateDirectory($destination)
    $linkChild=Join-Path $destination 'gone'
    $null=[IO.Directory]::CreateDirectory($linkChild)
    $null=New-Item -ItemType Junction -Path $link -Target $destination
    $linkTarget=Join-Path $link 'gone'
    $qualificationWorkspaceDirectoryIdentities[$link]=Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $link
    $qualificationWorkspaceDirectoryIdentities[$linkTarget]=Get-EvidenceWorkspaceFileSystemIdentity -LiteralPath $linkTarget
    [IO.Directory]::Delete($linkChild)
    Assert-Sampler (-not (Test-QualificationWorkspaceDirectoryDisappeared -Failure (New-DenialRecord $linkTarget) -Root $testRoot -Known $qualificationWorkspaceDirectoryIdentities)) 'Reparse ancestor allowed disappearance classification.'
    [IO.Directory]::Delete($link)
    # A reparse at the failed target itself must never trigger followed
    # identity I/O. Its previously cached identity does not authorize a link.
    $targetLink=Join-Path $testRoot 'synthetic-target-link'
    $qualificationWorkspaceDirectoryIdentities[$targetLink]='00000000:00000000:00000000'
    $null=New-Item -ItemType Junction -Path $targetLink -Target $destination
    Assert-Sampler (-not (Test-QualificationWorkspaceDirectoryDisappeared -Failure (New-DenialRecord $targetLink) -Root $testRoot -Known $qualificationWorkspaceDirectoryIdentities)) 'Failed target junction was followed by the absence probe.'
    [IO.Directory]::Delete($targetLink)
    # A failed parent/native proof always preserves original denial.
    $actualProbe=(Get-Command Get-EvidenceWorkspaceFileSystemIdentity -CommandType Function).ScriptBlock
    function Get-EvidenceWorkspaceFileSystemIdentity {param($LiteralPath) throw [ComponentModel.Win32Exception]::new(5)}
    [IO.Directory]::Delete($target)
    Assert-Sampler (-not (Test-QualificationWorkspaceDirectoryDisappeared -Failure (New-DenialRecord $target) -Root $testRoot -Known $qualificationWorkspaceDirectoryIdentities)) 'Native permission denial falsely proved disappearance.'
    Set-Item Function:\Get-EvidenceWorkspaceFileSystemIdentity $actualProbe
    # Missing attributes do not override a native access-denied status.
    function Get-EvidenceWorkspaceFileSystemIdentity {
        param($LiteralPath)
        if($LiteralPath -ceq $target){throw [ComponentModel.Win32Exception]::new(5)}
        & $actualProbe -LiteralPath $LiteralPath
    }
    Assert-Sampler (-not (Test-QualificationWorkspaceDirectoryDisappeared -Failure (New-DenialRecord $target) -Root $testRoot -Known $qualificationWorkspaceDirectoryIdentities)) 'Native target access denial was relabeled missing.'
    Set-Item Function:\Get-EvidenceWorkspaceFileSystemIdentity $actualProbe
}
finally{
    $resolved=[IO.Path]::GetFullPath($owned)
    if(-not $resolved.StartsWith($parent+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'TEST.SCOPE_INVALID'}
    if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
[ordered]@{recordType='win-pcinfo.local-workspace-sampling-tests';result='Pass';assertions=$script:Assertions;nonQualifying=$true;generatedApplicationRuns=0;scope='Extracted real sampler and exact-owned local disappearance proofs; no qualified budget or application acceptance'}|ConvertTo-Json -Compress|Write-Output
