[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Replay the actual two wrappers with recording candidate/process APIs only.
# No Engine child, build, mutex, process observer, desktop or native lease runs.
function Assert-StopContext {
    param([bool]$Condition,[string]$Message)
    if(-not $Condition){throw $Message}
}
function Assert-QualificationCleanupReady {}
function Open-TestCandidate {
    param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $probe.opens++
    $probe.admission=@($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    if($probe.mode -eq 'AdmissionRefuse'){throw $probe.bodyFailure}
    $supplied=@($CandidatePath,$PreparedManifestPath,$PreparedManifestSha256 | Where-Object { -not [string]::IsNullOrEmpty($_) }).Count
    if($supplied -ne 0 -and ($supplied -ne 3 -or $PreparedManifestSha256 -cnotmatch '^[a-f0-9]{64}$')){throw $probe.bodyFailure}
    $prepared=$supplied -eq 3
    $owned=if($prepared){$null}else{Join-Path $controlRoot ('candidate-'+[guid]::NewGuid().ToString('N'))}
    if($owned){$null=[IO.Directory]::CreateDirectory($owned)}
    $probe.context=[pscustomobject]@{Prepared=$prepared;OwnedDirectory=$owned;
        Path=$(if($prepared){$CandidatePath}else{Join-Path $owned 'WIN-PCInfo.ps1'})}
    $probe.context
}
function New-PreparedTestCandidateManifest {
    param($RepositoryRoot,$CandidatePath)
    Assert-StopContext ($RepositoryRoot -ceq $repositoryRoot -and $CandidatePath -ceq $probe.context.Path) 'Standalone manifest must bind this exact context and repository.'
    $probe.manifests++
    if($probe.mode -eq 'StandaloneManifestFailure'){throw $probe.bodyFailure}
    [ordered]@{contract='DisclosedPureStopContextOnly';candidate=$CandidatePath}
}
function Invoke-QualificationTestProcess {
    param($HostPath,$Arguments)
    $probe.calls.Add([pscustomobject]@{host=$HostPath;arguments=@($Arguments)})
    if($probe.failureKind -in @('Body','Unsafe','BodyAndClose') -and $probe.calls.Count -eq $probe.failureAt){throw $probe.bodyFailure}
    $global:LASTEXITCODE=if($probe.failureKind -eq 'Exit' -and $probe.calls.Count -eq $probe.failureAt){1}else{0}
}
function Close-TestCandidate {
    param($Candidate,$BodyError)
    $probe.closes++;$probe.closedContext=$Candidate;$probe.closedBodyError=$BodyError
    if($probe.failureKind -eq 'BodyAndClose'){
        $exception=[AggregateException]::new('Disclosed pure body and cleanup failure.',[Exception[]]@($BodyError.Exception,$probe.closeFailure))
        $exception.Data['OwnedCleanupUnverified']=$true
        throw $exception
    }
    if($BodyError){throw $BodyError.Exception}
    if($probe.mode -like '*CloseFailure'){throw $probe.closeFailure}
}
function Normalize-StopBody {
    param([string]$Text)
    $Text.Replace("`r`n","`n").Trim()
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$ownedParent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
$controlRoot=Join-Path $ownedParent ('stop-candidate-context-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($controlRoot)
$bindingTail=',''-CandidatePath'',$candidateContext.Path,''-PreparedManifestPath'',$PreparedManifestPath,''-PreparedManifestSha256'',$PreparedManifestSha256'
$originalCancellation=@'
foreach ($stage in @('Identity','Resource')) {
    Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),('-CancelAfter'+$stage))
    if ($LASTEXITCODE -ne 0) { throw "The controlled cancellation after $stage failed." }
}
Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-CancelDuringPrivilege')
if ($LASTEXITCODE -ne 0) { throw 'Controlled cancellation inside the active privileged worker lost its partial package.' }
'@
$originalLock=@'
Invoke-QualificationTestProcess -HostPath (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-HoldRunLock')
if ($LASTEXITCODE -ne 0) { throw 'The ordinary generated assessment scheduler did not enforce the Active Run Lock.' }
'@
$controls=0;$recordedLeaves=0
try {
foreach($name in @('StatusDeskCancellation.Tests.ps1','StatusDeskLock.Tests.ps1')){
    $path=Join-Path $PSScriptRoot $name;$tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Assert-StopContext ($errors.Count -eq 0) 'Actual wrapper must parse.'
    Assert-StopContext (($ast.ParamBlock.Parameters.Name.VariablePath.UserPath -join '|') -ceq 'CandidatePath|PreparedManifestPath|PreparedManifestSha256') 'Wrapper must expose only the shared three-pin interface.'
    $tryStatements=@($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })
    Assert-StopContext ($tryStatements.Count -eq 1) 'One original campaign must have one candidate finalizer.'
    $body=(@($tryStatements[0].Body.Statements | Select-Object -Skip 1).Extent.Text -join "`n").Replace($bindingTail,'')
    $expectedBody=if($name -eq 'StatusDeskCancellation.Tests.ps1'){$originalCancellation}else{$originalLock}
    Assert-StopContext ((Normalize-StopBody $body) -ceq (Normalize-StopBody $expectedBody)) 'Removing only the explicit three-pin tails must restore every original case, command, assertion and order.'
    Assert-StopContext ($tryStatements[0].Finally.Extent.Text -ceq '{ Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }') 'Exact candidate/body error must reach the shared finalizer.'
    $imports=@($ast.EndBlock.Statements | Where-Object { $_.Extent.Text -ceq ". (Join-Path `$PSScriptRoot 'TestHarness.ps1')" })
    Assert-StopContext ($imports.Count -eq 1) 'Actual wrapper harness import must be unique.'
    $source=$ast.Extent.Text.Replace($imports[0].Extent.Text,'# Pure recording APIs inherited from this control.')
    $replayTokens=$null;$replayErrors=$null
    $replayAst=[Management.Automation.Language.Parser]::ParseInput($source,$path,[ref]$replayTokens,[ref]$replayErrors)
    Assert-StopContext ($replayErrors.Count -eq 0) 'Actual wrapper replay must parse.'
    $control=$replayAst.GetScriptBlock()
    $originalFlags=@(if($name -eq 'StatusDeskCancellation.Tests.ps1'){'-CancelAfterIdentity';'-CancelAfterResource';'-CancelDuringPrivilege'}else{'-HoldRunLock'})
    $cases=[Collections.Generic.List[object]]::new()
    foreach($prefix in @('Prepared','Standalone')){
        $cases.Add(@{mode=($prefix+'Success');kind='';at=0})
        $cases.Add(@{mode=($prefix+'CloseFailure');kind='';at=0})
        foreach($kind in @('Body','Unsafe','Exit','BodyAndClose')){
            for($at=1;$at -le $originalFlags.Count;$at++){$cases.Add(@{mode=($prefix+$kind);kind=$kind;at=$at})}
        }
    }
    foreach($mode in @('AdmissionRefuse','PartialCandidate','PartialManifest','BadDigest','StandaloneManifestFailure')){$cases.Add(@{mode=$mode;kind='';at=0})}
    foreach($case in $cases){
        $probe=[pscustomobject]@{mode=$case.mode;failureKind=$case.kind;failureAt=$case.at;opens=0;closes=0;manifests=0;
            admission=$null;context=$null;closedContext=$null;closedBodyError=$null;calls=[Collections.Generic.List[object]]::new();
            bodyFailure=[InvalidOperationException]::new('Disclosed pure stop-wrapper body failure.');closeFailure=[InvalidOperationException]::new('Disclosed pure stop-wrapper close failure.')}
        if($case.kind -eq 'Unsafe'){$probe.bodyFailure.Data['OwnedCleanupUnverified']=$true}
        $parameters=if($case.mode -like 'Standalone*'){@{}}else{@{CandidatePath=(Join-Path $controlRoot 'explicit.ps1');PreparedManifestPath=(Join-Path $controlRoot 'explicit.json');PreparedManifestSha256=('a'*64)}}
        switch($case.mode){
            'PartialCandidate' {$parameters.Remove('PreparedManifestPath');$parameters.Remove('PreparedManifestSha256')}
            'PartialManifest' {$parameters.Remove('CandidatePath');$parameters.Remove('PreparedManifestSha256')}
            'BadDigest' {$parameters.PreparedManifestSha256='invalid'}
        }
        $failure=$null;$output=@()
        try{$output=@(& $control @parameters)}catch{$failure=$_}
        $controls++;$recordedLeaves+=$probe.calls.Count
        Assert-StopContext ($probe.opens -eq 1 -and $probe.admission[0] -ceq $repositoryRoot) 'Actual wrapper must open once with its repository ownership.'
        if($case.mode -in @('AdmissionRefuse','PartialCandidate','PartialManifest','BadDigest')){
            Assert-StopContext ($probe.calls.Count -eq 0 -and $probe.closes -eq 0 -and $null -ne $failure) 'Refused admission cannot reach a child or unowned finalizer.'
            continue
        }
        Assert-StopContext ($probe.closes -eq 1 -and [object]::ReferenceEquals($probe.context,$probe.closedContext)) 'Actual wrapper must close its one exact candidate context.'
        $bodyFails=$case.kind -ne '' -or $case.mode -eq 'StandaloneManifestFailure'
        $expectedCount=if($case.mode -eq 'StandaloneManifestFailure'){0}elseif($bodyFails){$case.at}else{$originalFlags.Count}
        Assert-StopContext ($probe.calls.Count -eq $expectedCount) 'Original ordered campaign stops at the first failure only.'
        if($case.mode -like 'Standalone*'){
            Assert-StopContext ($probe.manifests -eq 1) 'Standalone wrapper creates exactly one pinned manifest.'
            $manifest=Join-Path $probe.context.OwnedDirectory 'prepared-test-candidate.json'
            $manifestHash=if($case.mode -eq 'StandaloneManifestFailure'){$null}else{(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()}
        }else{
            Assert-StopContext ($probe.manifests -eq 0 -and $probe.admission[1] -ceq $parameters.CandidatePath -and $probe.admission[2] -ceq $parameters.PreparedManifestPath -and $probe.admission[3] -ceq $parameters.PreparedManifestSha256) 'Prepared wrapper consumes exact operands without recreating the manifest.'
            $manifest=$parameters.PreparedManifestPath;$manifestHash=$parameters.PreparedManifestSha256
        }
        for($index=0;$index -lt $probe.calls.Count;$index++){
            $expected=@('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),$originalFlags[$index],'-CandidatePath',$probe.context.Path,'-PreparedManifestPath',$manifest,'-PreparedManifestSha256',$manifestHash)
            Assert-StopContext ($probe.calls[$index].host -ceq (Join-Path $PSHOME 'pwsh.exe') -and ($probe.calls[$index].arguments -join '|') -ceq ($expected -join '|')) 'Every original tuple/host forwards the one exact three-pin binding; no STA or lock-namespace change.'
        }
        if($bodyFails){
            Assert-StopContext ($null -ne $failure -and $null -ne $probe.closedBodyError) 'Body failure cannot fall through to success.'
            if($case.kind -eq 'BodyAndClose'){
                Assert-StopContext ($failure.Exception -is [AggregateException] -and [object]::ReferenceEquals($failure.Exception.InnerExceptions[0],$probe.bodyFailure) -and [object]::ReferenceEquals($failure.Exception.InnerExceptions[1],$probe.closeFailure) -and $failure.Exception.Data['OwnedCleanupUnverified']) 'Combined cleanup/body failure preserves both original causes and unsafe disposition.'
            }else{
                Assert-StopContext ([object]::ReferenceEquals($failure.Exception,$probe.closedBodyError.Exception)) 'Original body error survives the shared close boundary.'
                if($case.kind -ne 'Exit'){Assert-StopContext ([object]::ReferenceEquals($failure.Exception,$probe.bodyFailure)) 'Original thrown body exception survives.'}
                if($case.kind -eq 'Unsafe'){Assert-StopContext ($failure.Exception.Data['OwnedCleanupUnverified'] -eq $true) 'Unsafe ownership marker survives finalization.'}
            }
        }elseif($case.mode -like '*CloseFailure'){
            Assert-StopContext ($null -ne $failure -and [object]::ReferenceEquals($failure.Exception,$probe.closeFailure)) 'Close failure cannot fall through to success.'
        }else{Assert-StopContext ($null -eq $failure -and $null -eq $probe.closedBodyError) 'Successful wrapper closes without an invented body failure.'}
        if($name -eq 'StatusDeskLock.Tests.ps1'){
            Assert-StopContext ($output.Count -eq $(if($null -eq $failure){1}else{0})) 'Lock success message is emitted only after successful finalization.'
        }
    }
}
}
finally {
    $resolved=[IO.Path]::GetFullPath($controlRoot)
    if(-not $resolved.StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -cnotmatch '^stop-candidate-context-[a-f0-9]{32}$'){throw 'Pure fixture cleanup escaped its exact owned parent.'}
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
    if([IO.Directory]::Exists($resolved)){throw 'Pure fixture cleanup remains incomplete.'}
}
Write-Output ('PASS: {0} pure actual stop-wrapper controls; {1} recorded leaves; exact original bodies/cases/three-pin forwarding and unsafe finalizers.' -f $controls,$recordedLeaves)
