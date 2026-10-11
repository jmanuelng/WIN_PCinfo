[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Pure replay retains actual parent STA launch and both candidate finalizers.
# Only TestHarness APIs and the GUI workload are substituted; no child, build,
# native adapter, process observation, role lease or GUI is executed.
function Assert-PassiveContext {
    param([bool]$Condition,[string]$Message)
    if(-not $Condition){throw $Message}
}
function Open-TestCandidate {
    param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $entry=[pscustomobject]@{root=$RepositoryRoot;candidate=$CandidatePath;manifest=$PreparedManifestPath;sha256=$PreparedManifestSha256;context=$null}
    $probe.opens.Add($entry)
    if(($probe.mode -eq 'ParentRefuse' -and $probe.opens.Count -eq 1) -or
        ($probe.mode -eq 'ChildRefuse' -and $probe.opens.Count -eq 2)){throw $probe.bodyFailure}
    $prepared=-not [string]::IsNullOrEmpty($CandidatePath)
    $owned=if($prepared){$null}else{Join-Path $controlRoot ('candidate-'+[guid]::NewGuid().ToString('N'))}
    if($owned){$null=[IO.Directory]::CreateDirectory($owned)}
    $entry.context=[pscustomobject]@{id=$probe.opens.Count;Prepared=$prepared;OwnedDirectory=$owned;
        Path=$(if($prepared){$CandidatePath}else{Join-Path $owned 'WIN-PCInfo.ps1'})}
    $entry.context
}
function New-PreparedTestCandidateManifest {
    param($RepositoryRoot,$CandidatePath)
    $probe.manifests++
    Assert-PassiveContext ($RepositoryRoot -ceq $repositoryRoot -and $CandidatePath -ceq $probe.opens[0].context.Path) 'Manifest must bind the original admitted candidate.'
    [ordered]@{contract='disclosed-pure-passive-context';candidate=$CandidatePath}
}
function Close-TestCandidate {
    param($Candidate,$BodyError)
    $probe.closes.Add([pscustomobject]@{context=$Candidate;error=$BodyError})
    if($BodyError){throw $BodyError.Exception}
    if(($probe.mode -eq 'ChildCloseFailure' -and $Candidate.id -eq 2) -or
        ($probe.mode -eq 'ParentCloseFailure' -and $Candidate.id -eq 1)){throw $probe.closeFailure}
}
function Invoke-QualificationTestProcess {
    param($HostPath,[string[]]$Arguments)
    $probe.launches.Add([pscustomobject]@{host=$HostPath;arguments=$Arguments})
    if($probe.mode -eq 'ParentExitFailure'){$global:LASTEXITCODE=1;return}
    $child=@{StaChild=$true;CandidatePath=$Arguments[7];PreparedManifestPath=$Arguments[9];PreparedManifestSha256=$Arguments[11]}
    & $control @child|Out-Null
    $global:LASTEXITCODE=0
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$ownedParent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
$controlRoot=Join-Path $ownedParent ('passive-candidate-context-'+[guid]::NewGuid().ToString('N'))
Assert-PassiveContext ([IO.Path]::GetFullPath($controlRoot).StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase)) 'Pure fixture root must stay within its owned parent.'
$null=[IO.Directory]::CreateDirectory($controlRoot)
$controls=0;$workloads=0
try{
foreach($name in @('StatusDeskRecipientSelection.Tests.ps1','StatusDeskViewing.Tests.ps1')){
    $path=Join-Path $PSScriptRoot $name
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Assert-PassiveContext ($errors.Count -eq 0) 'Actual passive GUI wrapper must parse.'
    $outer=@($ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.TryStatementAst] -and $null -ne $_.Finally -and $_.Finally.Extent.Text.Contains('Close-TestCandidate')})
    $imports=@($ast.EndBlock.Statements|Where-Object{$_.Extent.Text -ceq ". (Join-Path `$PSScriptRoot 'TestHarness.ps1')"})
    Assert-PassiveContext ($outer.Count -eq 1 -and $imports.Count -eq 1) 'Candidate lifecycle and harness import must be unique.'
    $candidate=@($outer[0].Body.Statements|Where-Object{$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Extent.Text -ceq '$candidate=$candidateContext.Path'})
    Assert-PassiveContext ($candidate.Count -eq 1) 'GUI must consume the admitted candidate path.'
    $start=$candidate[0].Extent.EndOffset;$end=$outer[0].Body.Extent.EndOffset-1
    $workload=@'

    $probe.work.Add([pscustomobject]@{candidate=$candidate;context=$candidateContext})
    if($probe.mode -like '*WorkFailure' -or $probe.mode -eq 'Unsafe'){throw $probe.bodyFailure}

'@
    $source=$ast.Extent.Text.Remove($start,$end-$start).Insert($start,$workload).
        Replace($imports[0].Extent.Text,'# Pure API stubs inherited from this fixture.')
    $replayTokens=$null;$replayErrors=$null
    $replayAst=[Management.Automation.Language.Parser]::ParseInput($source,$path,[ref]$replayTokens,[ref]$replayErrors)
    Assert-PassiveContext ($replayErrors.Count -eq 0) 'Actual lifecycle replay must parse.'
    $control=$replayAst.GetScriptBlock()
    foreach($mode in @('PreparedSuccess','StandaloneSuccess','ParentRefuse','ChildRefuse',
        'WorkFailure','StandaloneWorkFailure','Unsafe','ParentExitFailure','ChildCloseFailure','ParentCloseFailure')){
        $probe=[pscustomobject]@{mode=$mode;manifests=0;opens=[Collections.Generic.List[object]]::new();
            closes=[Collections.Generic.List[object]]::new();launches=[Collections.Generic.List[object]]::new();work=[Collections.Generic.List[object]]::new();
            bodyFailure=[InvalidOperationException]::new('Disclosed pure passive body refusal.');
            closeFailure=[InvalidOperationException]::new('Disclosed pure passive candidate close refusal.')}
        if($mode -eq 'Unsafe'){$probe.bodyFailure.Data['OwnedCleanupUnverified']=$true}
        $parameters=if($mode -like 'Standalone*'){@{}}else{@{CandidatePath=(Join-Path $controlRoot 'explicit-candidate.ps1');PreparedManifestPath=(Join-Path $controlRoot 'explicit-manifest.json');PreparedManifestSha256=('a'*64)}}
        $failure=$null
        try{& $control @parameters|Out-Null}catch{$failure=$_}
        $controls++;$workloads+=$probe.work.Count
        if($mode -eq 'ParentRefuse'){
            Assert-PassiveContext ($probe.opens.Count -eq 1 -and $probe.closes.Count -eq 0 -and $probe.launches.Count -eq 0 -and $null -ne $failure) 'Parent refusal must not launch or close an unowned context.'
            continue
        }
        Assert-PassiveContext ($probe.launches.Count -eq 1) 'Parent must launch exactly one STA child.'
        $parent=$probe.opens[0].context
        $manifest=if($mode -like 'Standalone*'){Join-Path $parent.OwnedDirectory 'prepared-test-candidate.json'}else{$parameters.PreparedManifestPath}
        $manifestHash=if($mode -like 'Standalone*'){(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()}else{$parameters.PreparedManifestSha256}
        $expected=@('-NoLogo','-NoProfile','-STA','-File',$path,'-StaChild','-CandidatePath',$parent.Path,'-PreparedManifestPath',$manifest,'-PreparedManifestSha256',$manifestHash)
        Assert-PassiveContext (($probe.launches[0].arguments|ConvertTo-Json -Compress) -ceq ($expected|ConvertTo-Json -Compress) -and $probe.launches[0].host -ceq (Join-Path $PSHOME 'pwsh.exe')) 'Exact STA self-launch and immutable bindings must be forwarded without authority flags.'
        Assert-PassiveContext ($probe.manifests -eq $(if($mode -like 'Standalone*'){1}else{0})) 'Only standalone parent creates one manifest.'
        foreach($entry in $probe.opens){Assert-PassiveContext ($entry.root -ceq $repositoryRoot) 'Every read context must retain repository ownership.'}
        if($mode -eq 'ParentExitFailure'){
            Assert-PassiveContext ($probe.opens.Count -eq 1 -and $probe.closes.Count -eq 1 -and $probe.work.Count -eq 0 -and $null -ne $failure) 'Original child exit failure must stop before GUI work and close parent.'
        }
        else{
            Assert-PassiveContext ($probe.opens.Count -eq 2) 'Explicit child must independently admit its read context.'
            $child=$probe.opens[1]
            Assert-PassiveContext ($child.candidate -ceq $parent.Path -and $child.manifest -ceq $manifest -and $child.sha256 -ceq $manifestHash) 'Child admission must consume the same pinned candidate and manifest.'
            if($mode -eq 'ChildRefuse'){
                Assert-PassiveContext ($probe.closes.Count -eq 1 -and $probe.work.Count -eq 0 -and $null -ne $failure) 'Refused child must not close an unowned context or reach GUI work.'
            }
            else{
                Assert-PassiveContext ($child.context.Prepared -and $probe.closes.Count -eq 2 -and $probe.work.Count -eq 1 -and $probe.work[0].candidate -ceq $parent.Path) 'Child must use immutable input, execute once and close both read contexts.'
                Assert-PassiveContext ([object]::ReferenceEquals($probe.closes[0].context,$child.context) -and [object]::ReferenceEquals($probe.closes[1].context,$parent)) 'Child closes first, then exact parent context.'
            }
        }
        if($mode -like '*Success'){Assert-PassiveContext ($null -eq $failure -and $null -eq $probe.closes[-1].error) 'Success must close before returning.'}
        else{
            Assert-PassiveContext ($null -ne $failure) 'Body, exit or close failure cannot fall through to success.'
            if($mode -ne 'ParentCloseFailure'){
                Assert-PassiveContext ($null -ne $probe.closes[-1].error -and [object]::ReferenceEquals($probe.closes[-1].error.Exception,$failure.Exception)) 'Parent close must receive the unchanged propagated body failure.'
            }
            if($mode -eq 'Unsafe'){Assert-PassiveContext ($failure.Exception.Data['OwnedCleanupUnverified'] -eq $true) 'Unsafe ownership flag must survive both finalizers.'}
        }
    }
}
}
finally{
    $resolved=[IO.Path]::GetFullPath($controlRoot)
    if(-not $resolved.StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -cnotmatch '\Apassive-candidate-context-[a-f0-9]{32}\z'){
        throw 'Pure fixture cleanup escaped its exact owned parent.'
    }
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
    if([IO.Directory]::Exists($resolved)){throw 'Pure fixture cleanup remains incomplete.'}
}
Write-Output ('PASS: {0} pure passive context controls; {1} substituted GUI workloads; exact STA bindings, independent reads and failure finalization.' -f $controls,$workloads)
