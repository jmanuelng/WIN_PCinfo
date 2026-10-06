[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Pure replay retains actual ColdProcess recursion guard and context finalizers.
# TestHarness APIs, product compilation/session work and cold-type queries are
# disclosed substitutes. No child, compiler, sampler, native adapter or GUI runs.
function Assert-OpeningContext {
    param([bool]$Condition,[string]$Message)
    if(-not $Condition){throw $Message}
}
function Assert-Equal {
    param($Expected,$Actual,$Message)
    $probe.coldAssertions.Add($Message)
    Assert-OpeningContext ($Expected -ceq $Actual) 'Replayed cold assertion must preserve its expected value.'
}
function Open-TestCandidate {
    param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $entry=[pscustomobject]@{root=$RepositoryRoot;candidate=$CandidatePath;manifest=$PreparedManifestPath;sha256=$PreparedManifestSha256;context=$null}
    $probe.opens.Add($entry)
    if(($probe.mode -eq 'ParentRefuse' -and $probe.opens.Count -eq 1) -or ($probe.mode -eq 'ChildRefuse' -and $probe.opens.Count -eq 2)){throw $probe.bodyFailure}
    $prepared=-not [string]::IsNullOrEmpty($CandidatePath)
    $owned=if($prepared){$null}else{Join-Path $controlRoot ('candidate-'+[guid]::NewGuid().ToString('N'))}
    if($owned){$null=[IO.Directory]::CreateDirectory($owned)}
    $entry.context=[pscustomobject]@{id=$probe.opens.Count;Prepared=$prepared;OwnedDirectory=$owned;Path=$(if($prepared){$CandidatePath}else{Join-Path $owned 'WIN-PCInfo.ps1'})}
    $entry.context
}
function New-PreparedTestCandidateManifest {
    param($RepositoryRoot,$CandidatePath)
    $probe.manifests++
    Assert-OpeningContext ($RepositoryRoot -ceq $repositoryRoot -and $CandidatePath -ceq $probe.opens[0].context.Path) 'Manifest must bind admitted root and candidate.'
    [ordered]@{contract='disclosed-pure-opening-context';candidate=$CandidatePath}
}
function Close-TestCandidate {
    param($Candidate,$BodyError)
    $probe.closes.Add([pscustomobject]@{context=$Candidate;error=$BodyError})
    if($BodyError){throw $BodyError.Exception}
    if(($probe.mode -eq 'ChildCloseFailure' -and $Candidate.id -eq 2) -or ($probe.mode -eq 'ParentCloseFailure' -and $Candidate.id -eq 1)){throw $probe.closeFailure}
}
function Invoke-QualificationTestProcess {
    param($HostPath,[string[]]$Arguments)
    $probe.launches.Add([pscustomobject]@{host=$HostPath;arguments=$Arguments})
    if($probe.launches.Count -gt 1){throw 'ColdProcess child attempted recursive launch.'}
    if($probe.mode -eq 'ExitFailure'){throw $probe.bodyFailure}
    $child=@{}
    for($i=5;$i -lt $Arguments.Count;$i++){
        switch -CaseSensitive ($Arguments[$i]){
            '-ColdProcess'{$child.ColdProcess=$true}
            '-EvidencePath'{$child.EvidencePath=$Arguments[++$i]}
            '-CandidatePath'{$child.CandidatePath=$Arguments[++$i]}
            '-PreparedManifestPath'{$child.PreparedManifestPath=$Arguments[++$i]}
            '-PreparedManifestSha256'{$child.PreparedManifestSha256=$Arguments[++$i]}
            default{throw 'Unexpected cold child argument or authority flag.'}
        }
    }
    # -ColdProcess is argument index 4 in the preserved non-STA launch.
    Assert-OpeningContext ($Arguments[4] -ceq '-ColdProcess') 'Exact cold recursion guard must be forwarded.'
    $child.ColdProcess=$true
    & $control @child|Out-Null
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$path=Join-Path $PSScriptRoot 'StatusDeskOpening.Tests.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
Assert-OpeningContext ($errors.Count -eq 0) 'Actual Opening wrapper must parse.'
$outer=@($ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.TryStatementAst] -and $null -ne $_.Finally -and $_.Finally.Extent.Text.Contains('Close-TestCandidate')})
$imports=@($ast.EndBlock.Statements|Where-Object{$_.Extent.Text -ceq ". (Join-Path `$PSScriptRoot 'TestHarness.ps1')"})
Assert-OpeningContext ($outer.Count -eq 1 -and $imports.Count -eq 1) 'Candidate finalizer and harness import must remain unique.'
$candidate=@($outer[0].Body.Statements|Where-Object{$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Extent.Text -ceq '$candidate = $candidateContext.Path'})
$cold=@($outer[0].Body.Statements|Where-Object{$_.Extent.Text.StartsWith('Assert-Equal ',[StringComparison]::Ordinal) -and ($_.Extent.Text.Contains("'this regression starts in a cold process'") -or $_.Extent.Text.Contains("'passive initialization does not compile the GUI helper'"))})
Assert-OpeningContext ($candidate.Count -eq 1 -and $cold.Count -eq 2 -and $candidate[0].Extent.EndOffset -lt $cold[0].Extent.StartOffset) 'Candidate admission must precede both exact cold checks.'
$sessionCalls=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Save-OpeningFixture'},$true)|ForEach-Object{$_.CommandElements[1].Value})
Assert-OpeningContext (($sessionCalls -join ',') -ceq 'ColdCompilerFailure,ColdRealDelayedOpeningDecline,RealOpeningFault,RealOpeningCancellation') 'Original four session cases must retain exact order.'
$text=$ast.Extent.Text
Assert-OpeningContext ($text.Contains("@('Worker','Runspace','Pending','OpeningTask','DefinitionInitializer','ParameterJson')") -and $text.Contains("(`$EvidencePath + '.cleanup.json')") -and $text.Contains('Complete-QualificationHarness -BodyError $bodyError -Cleanup $cleanup -RetainEvidence')) 'Original six-reference cleanup and evidence finalizer must remain present.'
$coldReplay=($cold|ForEach-Object{$_.Extent.Text.Replace("('WinPCInfoOwnedRunspaceOpening' -as [type])",'$null')}) -join "`n"
$workload="`n"+$coldReplay+@'

    $probe.work.Add([pscustomobject]@{candidate=$candidate;context=$candidateContext;evidence=$EvidencePath;cleanupEvidence=($EvidencePath+'.cleanup.json');cold=[bool]$ColdProcess})
    if($probe.mode -in @('WorkFailure','Unsafe')){throw $probe.bodyFailure}

'@
$start=$candidate[0].Extent.EndOffset;$end=$outer[0].Body.Extent.EndOffset-1
$source=$text.Remove($start,$end-$start).Insert($start,$workload).Replace($imports[0].Extent.Text,'# Pure APIs inherited from fixture.')
$replayTokens=$null;$replayErrors=$null
$replayAst=[Management.Automation.Language.Parser]::ParseInput($source,$path,[ref]$replayTokens,[ref]$replayErrors)
Assert-OpeningContext ($replayErrors.Count -eq 0) 'Actual cold guard/context replay must parse.'
$control=$replayAst.GetScriptBlock()
$ownedParent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
$controlRoot=Join-Path $ownedParent ('opening-candidate-context-'+[guid]::NewGuid().ToString('N'))
Assert-OpeningContext ([IO.Path]::GetFullPath($controlRoot).StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase)) 'Pure fixture root must stay within owned parent.'
$null=[IO.Directory]::CreateDirectory($controlRoot)
$controls=0
try{
foreach($prepared in @($true,$false)){
foreach($retainEvidence in @($true,$false)){
foreach($mode in @('Success','ParentRefuse','ChildRefuse','WorkFailure','Unsafe','ChildCloseFailure','ParentCloseFailure','ExitFailure')){
    $probe=[pscustomobject]@{mode=$mode;manifests=0;opens=[Collections.Generic.List[object]]::new();closes=[Collections.Generic.List[object]]::new();
        launches=[Collections.Generic.List[object]]::new();work=[Collections.Generic.List[object]]::new();coldAssertions=[Collections.Generic.List[string]]::new();
        bodyFailure=[InvalidOperationException]::new('Disclosed pure Opening body refusal.');closeFailure=[InvalidOperationException]::new('Disclosed pure Opening close refusal.')}
    if($mode -eq 'Unsafe'){$probe.bodyFailure.Data['OwnedCleanupUnverified']=$true}
    $parameters=if($prepared){@{CandidatePath=(Join-Path $controlRoot 'explicit-candidate.ps1');PreparedManifestPath=(Join-Path $controlRoot 'explicit-manifest.json');PreparedManifestSha256=('a'*64)}}else{@{}}
    $evidence=if($retainEvidence){Join-Path $controlRoot 'unchanged private evidence.json'}else{''}
    if($retainEvidence){$parameters.EvidencePath=$evidence}
    $failure=$null
    try{& $control @parameters|Out-Null}catch{$failure=$_}
    $controls++
    if($mode -eq 'ParentRefuse'){
        Assert-OpeningContext ($probe.opens.Count -eq 1 -and $probe.launches.Count -eq 0 -and $probe.closes.Count -eq 0 -and $null -ne $failure) 'Refused parent must reach no child or unowned close.'
        continue
    }
    $parent=$probe.opens[0].context
    $manifest=if($prepared){$parameters.PreparedManifestPath}else{Join-Path $parent.OwnedDirectory 'prepared-test-candidate.json'}
    $manifestHash=if($prepared){$parameters.PreparedManifestSha256}else{(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()}
    $expected=@('-NoLogo','-NoProfile','-File',$path,'-ColdProcess')
    if($retainEvidence){$expected+=@('-EvidencePath',$evidence)}
    $expected+=@('-CandidatePath',$parent.Path,'-PreparedManifestPath',$manifest,'-PreparedManifestSha256',$manifestHash)
    Assert-OpeningContext ($probe.launches.Count -eq 1 -and ($probe.launches[0].arguments|ConvertTo-Json -Compress) -ceq ($expected|ConvertTo-Json -Compress) -and $probe.launches[0].host -ceq (Join-Path $PSHOME 'pwsh.exe')) 'One fresh cold launch must preserve exact evidence and pins without authority flags.'
    Assert-OpeningContext ($probe.manifests -eq $(if($prepared){0}else{1})) 'Standalone parent must create one pinned manifest.'
    $count=if($mode -eq 'ExitFailure'){1}else{2}
    $closes=if($mode -eq 'ChildRefuse'){1}else{$count}
    Assert-OpeningContext ($probe.opens.Count -eq $count -and $probe.closes.Count -eq $closes) 'Every admitted read context must close; refused child remains unowned.'
    foreach($open in $probe.opens){Assert-OpeningContext ($open.root -ceq $repositoryRoot) 'Every context retains repository ownership.'}
    if($count -eq 2){Assert-OpeningContext ($probe.opens[1].candidate -ceq $parent.Path -and $probe.opens[1].manifest -ceq $manifest -and $probe.opens[1].sha256 -ceq $manifestHash) 'Cold child must admit same immutable inputs.'}
    if($mode -notin @('ChildRefuse','ExitFailure')){
        Assert-OpeningContext ($probe.work.Count -eq 1 -and $probe.work[0].cold -and $probe.work[0].candidate -ceq $parent.Path -and $probe.work[0].evidence -ceq $evidence -and $probe.work[0].cleanupEvidence -ceq ($evidence+'.cleanup.json') -and $probe.coldAssertions.Count -eq 2) 'Cold guard prevents recursion and preserves both cold checks and evidence destinations.'
    }
    if($mode -eq 'Success'){Assert-OpeningContext ($null -eq $failure -and $null -eq $probe.closes[-1].error) 'Successful cold child must close before returning.'}
    else{
        Assert-OpeningContext ($null -ne $failure) 'Admission, body and close failures cannot normalize to success.'
        if($mode -ne 'ParentCloseFailure'){Assert-OpeningContext ($null -ne $probe.closes[-1].error -and [object]::ReferenceEquals($probe.closes[-1].error.Exception,$failure.Exception)) 'Parent finalizer preserves original propagated body failure.'}
        if($mode -eq 'Unsafe'){Assert-OpeningContext ($failure.Exception.Data['OwnedCleanupUnverified'] -eq $true) 'Unsafe session ownership survives both candidate finalizers.'}
    }
}
}
}
}
finally{
    $resolved=[IO.Path]::GetFullPath($controlRoot)
    if(-not $resolved.StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -cnotmatch '\Aopening-candidate-context-[a-f0-9]{32}\z'){throw 'Pure fixture cleanup escaped exact owned parent.'}
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
    if([IO.Directory]::Exists($resolved)){throw 'Pure fixture cleanup remains incomplete.'}
}
Write-Output ('PASS: {0} pure Opening admission/cold-forwarding controls; original evidence paths, recursion guard and failure finalization.' -f $controls)
