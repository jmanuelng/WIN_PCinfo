[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Pure replay retains actual STA campaign branches and candidate finalizers.
# TestHarness APIs and complete GUI/runspace bodies are disclosed substitutes.
# No build, process child, file lock, GUI, native adapter or role lease runs.
function Assert-RecoveryContext {
    param([bool]$Condition,[string]$Message)
    if(-not $Condition){throw $Message}
}
function Open-TestCandidate {
    param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $entry=[pscustomobject]@{root=$RepositoryRoot;candidate=$CandidatePath;manifest=$PreparedManifestPath;sha256=$PreparedManifestSha256;context=$null}
    $probe.opens.Add($entry)
    if(($probe.mode -eq 'ParentRefuse' -and $probe.opens.Count -eq 1) -or
        ($probe.mode -eq 'ChildRefuse' -and $probe.opens.Count -eq $probe.failureAt+1)){throw $probe.bodyFailure}
    $prepared=-not [string]::IsNullOrEmpty($CandidatePath)
    $owned=if($prepared){$null}else{Join-Path $controlRoot ('candidate-'+[guid]::NewGuid().ToString('N'))}
    if($owned){$null=[IO.Directory]::CreateDirectory($owned)}
    $entry.context=[pscustomobject]@{id=$probe.opens.Count;Prepared=$prepared;OwnedDirectory=$owned;Path=$(if($prepared){$CandidatePath}else{Join-Path $owned 'WIN-PCInfo.ps1'})}
    $entry.context
}
function New-PreparedTestCandidateManifest {
    param($RepositoryRoot,$CandidatePath)
    $probe.manifests++
    Assert-RecoveryContext ($RepositoryRoot -ceq $repositoryRoot -and $CandidatePath -ceq $probe.opens[0].context.Path) 'Manifest must bind original admitted root and candidate.'
    [ordered]@{contract='disclosed-pure-recovery-context';candidate=$CandidatePath}
}
function Close-TestCandidate {
    param($Candidate,$BodyError)
    $probe.closes.Add([pscustomobject]@{context=$Candidate;error=$BodyError})
    if($BodyError){throw $BodyError.Exception}
    if(($probe.mode -eq 'ChildCloseFailure' -and $Candidate.id -eq $probe.failureAt+1) -or
        ($probe.mode -eq 'ParentCloseFailure' -and $Candidate.id -eq 1)){throw $probe.closeFailure}
}
function Invoke-QualificationTestProcess {
    param($HostPath,[string[]]$Arguments)
    $probe.launches.Add([pscustomobject]@{host=$HostPath;arguments=$Arguments})
    if($probe.mode -eq 'ExitFailure' -and $probe.launches.Count -eq $probe.failureAt){$global:LASTEXITCODE=1;return}
    $child=@{StaChild=$true}
    for($i=6;$i -lt $Arguments.Count;$i++){
        switch -CaseSensitive ($Arguments[$i]){
            '-Scenario'{$child.Scenario=$Arguments[++$i]}
            '-CandidatePath'{$child.CandidatePath=$Arguments[++$i]}
            '-PreparedManifestPath'{$child.PreparedManifestPath=$Arguments[++$i]}
            '-PreparedManifestSha256'{$child.PreparedManifestSha256=$Arguments[++$i]}
            default{throw 'Unexpected child authority or argument in pure recovery context.'}
        }
    }
    & $control @child|Out-Null
    $global:LASTEXITCODE=0
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$ownedParent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
$controlRoot=Join-Path $ownedParent ('recovery-candidate-context-'+[guid]::NewGuid().ToString('N'))
Assert-RecoveryContext ([IO.Path]::GetFullPath($controlRoot).StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase)) 'Pure fixture root must stay within its owned parent.'
$null=[IO.Directory]::CreateDirectory($controlRoot)
$controls=0;$launches=0
try{
foreach($name in @('StatusDeskCleanupGate.Tests.ps1','StatusDeskRecoveryCorrection.Tests.ps1','StatusDesk.Tests.ps1')){
    $path=Join-Path $PSScriptRoot $name
    $passive=$name -eq 'StatusDesk.Tests.ps1';$gate=$name -eq 'StatusDeskCleanupGate.Tests.ps1'
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Assert-RecoveryContext ($errors.Count -eq 0) 'Actual recovery/passive wrapper must parse.'
    $outer=@($ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.TryStatementAst] -and $null -ne $_.Finally -and $_.Finally.Extent.Text.Contains('Close-TestCandidate')})
    $imports=@($ast.EndBlock.Statements|Where-Object{$_.Extent.Text -ceq ". (Join-Path `$PSScriptRoot 'TestHarness.ps1')"})
    Assert-RecoveryContext ($outer.Count -eq 1 -and $imports.Count -eq 1) 'Candidate lifecycle and harness import must be unique.'
    $start=$outer[0].Body.Extent.StartOffset+1
    if(-not $passive){
        $candidate=@($outer[0].Body.Statements|Where-Object{$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Extent.Text -ceq '$candidate=$candidateContext.Path'})
        Assert-RecoveryContext ($candidate.Count -eq 1) 'GUI must consume admitted candidate path.'
        $start=$candidate[0].Extent.EndOffset
    }
    $end=$outer[0].Body.Extent.EndOffset-1
    $workload=@'

    $probe.work.Add([pscustomobject]@{candidate=$candidate;context=$candidateContext;scenario=$(if($probe.gate){$Scenario}else{''})})
    if($probe.work.Count -eq $probe.failureAt -and $probe.mode -in @('WorkFailure','Unsafe')){throw $probe.bodyFailure}

'@
    $source=$ast.Extent.Text.Remove($start,$end-$start).Insert($start,$workload).Replace($imports[0].Extent.Text,'# Pure API stubs inherited from fixture.')
    $replayTokens=$null;$replayErrors=$null
    $replayAst=[Management.Automation.Language.Parser]::ParseInput($source,$path,[ref]$replayTokens,[ref]$replayErrors)
    Assert-RecoveryContext ($replayErrors.Count -eq 0) 'Actual context/campaign replay must parse.'
    $control=$replayAst.GetScriptBlock()
    $modes=if($passive){@('Success','ParentRefuse','WorkFailure','Unsafe','ParentCloseFailure')}else{@('Success','ParentRefuse','ChildRefuse','WorkFailure','Unsafe','ExitFailure','ChildCloseFailure','ParentCloseFailure')}
    foreach($prepared in @($true,$false)){
    foreach($mode in $modes){
        $probe=[pscustomobject]@{mode=$mode;gate=$gate;manifests=0;failureAt=$(if($gate){2}else{1});
            opens=[Collections.Generic.List[object]]::new();closes=[Collections.Generic.List[object]]::new();launches=[Collections.Generic.List[object]]::new();work=[Collections.Generic.List[object]]::new();
            bodyFailure=[InvalidOperationException]::new('Disclosed pure recovery/passive body refusal.');closeFailure=[InvalidOperationException]::new('Disclosed pure recovery/passive close refusal.')}
        if($mode -eq 'Unsafe'){$probe.bodyFailure.Data['OwnedCleanupUnverified']=$true}
        $parameters=if($prepared){@{CandidatePath=(Join-Path $controlRoot 'explicit-candidate.ps1');PreparedManifestPath=(Join-Path $controlRoot 'explicit-manifest.json');PreparedManifestSha256=('a'*64)}}else{@{}}
        $failure=$null
        try{& $control @parameters|Out-Null}catch{$failure=$_}
        $controls++;$launches+=$probe.launches.Count
        if($mode -eq 'ParentRefuse'){
            Assert-RecoveryContext ($probe.opens.Count -eq 1 -and $probe.closes.Count -eq 0 -and $probe.launches.Count -eq 0 -and $probe.work.Count -eq 0 -and $null -ne $failure) 'Refused parent must reach no child, work or unowned close.'
            continue
        }
        $parent=$probe.opens[0].context
        $expectedLeaves=if($passive){0}elseif($mode -in @('Success','ParentCloseFailure')){if($gate){4}else{1}}else{$probe.failureAt}
        Assert-RecoveryContext ($probe.launches.Count -eq $expectedLeaves -and $probe.manifests -eq $(if(-not $prepared -and -not $passive){1}else{0})) 'Original campaign order, stop and standalone manifest count must remain unchanged.'
        if(-not $passive){
            $manifest=if($prepared){$parameters.PreparedManifestPath}else{Join-Path $parent.OwnedDirectory 'prepared-test-candidate.json'}
            $manifestHash=if($prepared){$parameters.PreparedManifestSha256}else{(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()}
            $scenarios=@('RecoveryEarly','RecoveryReady','Viewing','Export')
            for($i=0;$i -lt $probe.launches.Count;$i++){
                $expected=@('-NoLogo','-NoProfile','-STA','-File',$path,'-StaChild')
                if($gate){$expected+=@('-Scenario',$scenarios[$i])}
                $expected+=@('-CandidatePath',$parent.Path,'-PreparedManifestPath',$manifest,'-PreparedManifestSha256',$manifestHash)
                Assert-RecoveryContext (($probe.launches[$i].arguments|ConvertTo-Json -Compress) -ceq ($expected|ConvertTo-Json -Compress) -and $probe.launches[$i].host -ceq (Join-Path $PSHOME 'pwsh.exe')) 'Every original STA/scenario tuple and exact binding must remain unchanged without authority flags.'
            }
            foreach($child in @($probe.opens|Select-Object -Skip 1)){Assert-RecoveryContext ($child.candidate -ceq $parent.Path -and $child.manifest -ceq $manifest -and $child.sha256 -ceq $manifestHash) 'Each child must independently admit same immutable inputs.'}
        }
        foreach($open in $probe.opens){Assert-RecoveryContext ($open.root -ceq $repositoryRoot) 'Every read context retains repository ownership.'}
        foreach($work in $probe.work){Assert-RecoveryContext ($work.candidate -ceq $parent.Path) 'Every workload must consume admitted candidate.'}
        $admitted=@($probe.opens|Where-Object{$null -ne $_.context})
        Assert-RecoveryContext ($probe.closes.Count -eq $admitted.Count -and [object]::ReferenceEquals($probe.closes[-1].context,$parent)) 'Every admitted context closes exactly once, parent last.'
        for($i=0;$i -lt $probe.closes.Count-1;$i++){Assert-RecoveryContext ([object]::ReferenceEquals($probe.closes[$i].context,$admitted[$i+1].context)) 'Sequential child read contexts close in original campaign order.'}
        if($mode -eq 'Success'){Assert-RecoveryContext ($null -eq $failure -and $probe.work.Count -eq $(if($gate){4}else{1}) -and $null -eq $probe.closes[-1].error) 'Successful original campaign must close before returning.'}
        else{
            Assert-RecoveryContext ($null -ne $failure) 'Body, exit or close failure cannot normalize into success.'
            if($mode -ne 'ParentCloseFailure'){Assert-RecoveryContext ($null -ne $probe.closes[-1].error -and [object]::ReferenceEquals($probe.closes[-1].error.Exception,$failure.Exception)) 'Exact body failure must survive caller finalization.'}
            if($mode -eq 'Unsafe'){Assert-RecoveryContext ($failure.Exception.Data['OwnedCleanupUnverified'] -eq $true) 'Unsafe ownership remains visible through all finalizers.'}
        }
    }
    }
}
}
finally{
    $resolved=[IO.Path]::GetFullPath($controlRoot)
    if(-not $resolved.StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -cnotmatch '\Arecovery-candidate-context-[a-f0-9]{32}\z'){throw 'Pure fixture cleanup escaped exact owned parent.'}
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
    if([IO.Directory]::Exists($resolved)){throw 'Pure fixture cleanup remains incomplete.'}
}
Write-Output ('PASS: {0} pure recovery/passive candidate controls; {1} recorded STA launches; exact bindings, campaign order and failure finalization.' -f $controls,$launches)
