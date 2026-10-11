[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Actual Entry/Choices parent launch and candidate-finalizer statements are
# replayed. GUI bodies and TestHarness APIs alone are substituted. This fixture
# starts no child, generated application, native adapter, role lease or GUI.
function Assert-EntryContext {
    param([bool]$Condition,[string]$Message)
    if(-not $Condition){throw $Message}
}
function Open-TestCandidate {
    param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $entry=[pscustomobject]@{root=$RepositoryRoot;candidate=$CandidatePath;manifest=$PreparedManifestPath;sha256=$PreparedManifestSha256;context=$null}
    $probe.opens.Add($entry)
    if($probe.mode -eq 'ChildRefuse' -and $probe.opens.Count -eq $probe.depth){throw $probe.bodyFailure}
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
    Assert-EntryContext ($RepositoryRoot -ceq $repositoryRoot -and $CandidatePath -ceq $probe.opens[0].context.Path) 'Manifest must bind original admitted root and candidate.'
    [ordered]@{contract='disclosed-pure-entry-chain';candidate=$CandidatePath}
}
function Close-TestCandidate {
    param($Candidate,$BodyError)
    $probe.closes.Add([pscustomobject]@{context=$Candidate;error=$BodyError})
    if($BodyError){throw $BodyError.Exception}
    if($probe.mode -eq 'ChildCloseFailure' -and $Candidate.id -eq $probe.depth){throw $probe.closeFailure}
}
function Invoke-QualificationTestProcess {
    param($HostPath,[string[]]$Arguments)
    $probe.launches.Add([pscustomobject]@{host=$HostPath;arguments=$Arguments})
    if($probe.mode -eq 'ExitFailure'){$global:LASTEXITCODE=1;return}
    $fileIndex=[array]::IndexOf($Arguments,'-File')
    $path=$Arguments[$fileIndex+1];$child=@{}
    for($i=$fileIndex+2;$i -lt $Arguments.Count;$i++){
        switch -CaseSensitive ($Arguments[$i]){
            '-StaChild'{$child.StaChild=$true}
            '-Choices'{$child.Choices=$true}
            '-Choices:True'{$child.Choices=$true}
            '-Choices:False'{$child.Choices=$false}
            '-CandidatePath'{$child.CandidatePath=$Arguments[++$i]}
            '-PreparedManifestPath'{$child.PreparedManifestPath=$Arguments[++$i]}
            '-PreparedManifestSha256'{$child.PreparedManifestSha256=$Arguments[++$i]}
            default{throw 'Unexpected child authority or argument in pure Entry chain.'}
        }
    }
    & $replays[$path] @child|Out-Null
    $global:LASTEXITCODE=0
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$ownedParent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
$controlRoot=Join-Path $ownedParent ('entry-candidate-context-'+[guid]::NewGuid().ToString('N'))
Assert-EntryContext ([IO.Path]::GetFullPath($controlRoot).StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase)) 'Pure fixture root must stay within its owned parent.'
$null=[IO.Directory]::CreateDirectory($controlRoot)
$replays=@{};$controls=0;$launches=0
try{
foreach($name in @('StatusDeskEntry.Tests.ps1','StatusDeskChoices.Tests.ps1')){
    $path=Join-Path $PSScriptRoot $name
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Assert-EntryContext ($errors.Count -eq 0) 'Actual Entry/Choices wrapper must parse.'
    $outer=@($ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.TryStatementAst] -and $null -ne $_.Finally -and $_.Finally.Extent.Text.Contains('Close-TestCandidate')})
    $imports=@($ast.EndBlock.Statements|Where-Object{$_.Extent.Text -ceq ". (Join-Path `$PSScriptRoot 'TestHarness.ps1')"})
    Assert-EntryContext ($outer.Count -eq 1 -and $imports.Count -eq 1) 'Candidate lifecycle and harness import must be unique.'
    $candidate=@($outer[0].Body.Statements|Where-Object{$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Extent.Text -ceq '$candidate=$candidateContext.Path'})
    Assert-EntryContext ($candidate.Count -eq 1) 'GUI must consume admitted candidate path.'
    $start=$candidate[0].Extent.EndOffset
    $end=$outer[0].Body.Extent.EndOffset-1
    if($name -eq 'StatusDeskChoices.Tests.ps1'){
        $calls=@($outer[0].Body.Statements|Where-Object{$_ -is [Management.Automation.Language.PipelineAst] -and $_.Extent.Text.StartsWith('Invoke-QualificationTestProcess ',[StringComparison]::Ordinal)})
        Assert-EntryContext ($calls.Count -eq 1) 'Choices must retain one coupled Entry launch.'
        $end=$calls[0].Extent.StartOffset
    }
    $workload=@'

    $probe.work.Add([pscustomobject]@{candidate=$candidate;context=$candidateContext;source='__SOURCE__';choices=$(if('__SOURCE__' -eq 'Entry'){[bool]$Choices}else{$false})})
    if($candidateContext.id -eq $probe.depth -and $probe.mode -in @('WorkFailure','Unsafe')){throw $probe.bodyFailure}

'@
    $source=$ast.Extent.Text.Remove($start,$end-$start).Insert($start,$workload.Replace('__SOURCE__',$(if($name -eq 'StatusDeskEntry.Tests.ps1'){'Entry'}else{'Choices'}))).
        Replace($imports[0].Extent.Text,'# Pure TestHarness APIs inherited from this fixture.')
    $replayTokens=$null;$replayErrors=$null
    $replayAst=[Management.Automation.Language.Parser]::ParseInput($source,$path,[ref]$replayTokens,[ref]$replayErrors)
    Assert-EntryContext ($replayErrors.Count -eq 0) 'Pure actual Entry chain must parse.'
    $replays[$path]=$replayAst.GetScriptBlock()
}
$entryPath=Join-Path $PSScriptRoot 'StatusDeskEntry.Tests.ps1'
$choicesPath=Join-Path $PSScriptRoot 'StatusDeskChoices.Tests.ps1'
foreach($route in @('Entry','EntryChoices','Choices')){
foreach($prepared in @($true,$false)){
foreach($mode in @('Success','ChildRefuse','WorkFailure','Unsafe','ChildCloseFailure','ExitFailure')){
    $depth=if($route -eq 'Choices'){4}else{2}
    $probe=[pscustomobject]@{mode=$mode;depth=$depth;manifests=0;opens=[Collections.Generic.List[object]]::new();
        closes=[Collections.Generic.List[object]]::new();launches=[Collections.Generic.List[object]]::new();work=[Collections.Generic.List[object]]::new();
        bodyFailure=[InvalidOperationException]::new('Disclosed pure Entry body refusal.');
        closeFailure=[InvalidOperationException]::new('Disclosed pure Entry close refusal.')}
    if($mode -eq 'Unsafe'){$probe.bodyFailure.Data['OwnedCleanupUnverified']=$true}
    $parameters=if($prepared){@{CandidatePath=(Join-Path $controlRoot 'explicit-candidate.ps1');PreparedManifestPath=(Join-Path $controlRoot 'explicit-manifest.json');PreparedManifestSha256=('a'*64)}}else{@{}}
    if($route -eq 'EntryChoices'){$parameters.Choices=$true}
    $path=if($route -eq 'Choices'){$choicesPath}else{$entryPath}
    $failure=$null
    try{& $replays[$path] @parameters|Out-Null}catch{$failure=$_}
    $controls++;$launches+=$probe.launches.Count
    $parent=$probe.opens[0].context
    $manifest=if($prepared){$parameters.PreparedManifestPath}else{Join-Path $parent.OwnedDirectory 'prepared-test-candidate.json'}
    $manifestHash=if($prepared){$parameters.PreparedManifestSha256}else{(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()}
    $pins=@('-CandidatePath',$parent.Path,'-PreparedManifestPath',$manifest,'-PreparedManifestSha256',$manifestHash)
    $expected=[Collections.Generic.List[object]]::new()
    if($route -eq 'Choices'){
        $expected.Add((@('-NoLogo','-NoProfile','-STA','-File',$choicesPath,'-StaChild')+$pins))
        $expected.Add((@('-NoLogo','-NoProfile','-File',$entryPath,'-Choices')+$pins))
        $expected.Add((@('-NoLogo','-NoProfile','-STA','-File',$entryPath,'-StaChild','-Choices:True')+$pins))
    }
    else{$expected.Add((@('-NoLogo','-NoProfile','-STA','-File',$entryPath,'-StaChild',$(if($route -eq 'EntryChoices'){'-Choices:True'}else{'-Choices:False'}))+$pins))}
    $expectedLaunchCount=if($mode -eq 'ExitFailure'){1}else{$expected.Count}
    Assert-EntryContext ($probe.launches.Count -eq $expectedLaunchCount -and $probe.manifests -eq $(if($prepared){0}else{1})) 'Original chain order and one standalone manifest must be preserved.'
    for($i=0;$i -lt $probe.launches.Count;$i++){
        Assert-EntryContext (($probe.launches[$i].arguments|ConvertTo-Json -Compress) -ceq ($expected[$i]|ConvertTo-Json -Compress) -and $probe.launches[$i].host -ceq (Join-Path $PSHOME 'pwsh.exe')) 'Every exact STA/Choices tuple and prepared binding must remain unchanged without authority flags.'
    }
    $expectedOpens=if($mode -eq 'ExitFailure'){1}else{$depth}
    $expectedCloses=if($mode -eq 'ChildRefuse'){$depth-1}else{$expectedOpens}
    Assert-EntryContext ($probe.opens.Count -eq $expectedOpens -and $probe.closes.Count -eq $expectedCloses) 'Every admitted read context must close once; refused child must not close an unowned context.'
    foreach($open in $probe.opens){
        Assert-EntryContext ($open.root -ceq $repositoryRoot) 'Every chain member retains repository ownership.'
        if(-not [object]::ReferenceEquals($open,$probe.opens[0])){Assert-EntryContext ($open.candidate -ceq $parent.Path -and $open.manifest -ceq $manifest -and $open.sha256 -ceq $manifestHash) 'Every child must independently admit the same immutable bindings.'}
    }
    for($i=0;$i -lt $probe.closes.Count;$i++){
        Assert-EntryContext ([object]::ReferenceEquals($probe.closes[$i].context,$probe.opens[$expectedCloses-1-$i].context)) 'Read contexts must close in reverse ownership order.'
    }
    foreach($work in $probe.work){Assert-EntryContext ($work.candidate -ceq $parent.Path) 'Every substituted GUI workload consumes admitted candidate.'}
    if($mode -eq 'Success'){
        Assert-EntryContext ($null -eq $failure -and $probe.work.Count -eq $(if($route -eq 'Choices'){2}else{1}) -and $probe.work[-1].choices -eq ($route -ne 'Entry')) 'Original Entry/Choices route must complete after verified closes.'
    }
    else{
        Assert-EntryContext ($null -ne $failure -and $null -ne $probe.closes[-1].error -and [object]::ReferenceEquals($probe.closes[-1].error.Exception,$failure.Exception)) 'Body, exit and close failures must propagate through all parent finalizers.'
        if($mode -eq 'Unsafe'){Assert-EntryContext ($failure.Exception.Data['OwnedCleanupUnverified'] -eq $true) 'Unsafe ownership must survive the entire coupled chain.'}
    }
}
}
}
}
finally{
    $resolved=[IO.Path]::GetFullPath($controlRoot)
    if(-not $resolved.StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -cnotmatch '\Aentry-candidate-context-[a-f0-9]{32}\z'){throw 'Pure fixture cleanup escaped exact owned parent.'}
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
    if([IO.Directory]::Exists($resolved)){throw 'Pure fixture cleanup remains incomplete.'}
}
Write-Output ('PASS: {0} pure actual Entry/Choices chain controls; {1} recorded launches; exact binding/STA forwarding and failure finalization.' -f $controls,$launches)
