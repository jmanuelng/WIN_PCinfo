[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Actual caller replay with recording candidate/runtime/process APIs only.
# No build, runtime discovery, Engine child, GUI, native role or process query.
function Assert-ReportContext {
    param([bool]$Condition,[string]$Message)
    if(-not $Condition){throw $Message}
}
function Assert-QualificationCleanupReady {}
function Open-TestCandidate {
    param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $probe.opens++;$probe.admission=@($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $supplied=@(@($CandidatePath,$PreparedManifestPath,$PreparedManifestSha256) | Where-Object { -not [string]::IsNullOrEmpty($_) }).Count
    if($probe.mode -eq 'AdmissionRefuse' -or ($supplied -ne 0 -and ($supplied -ne 3 -or $PreparedManifestSha256 -cnotmatch '^[a-f0-9]{64}$'))){throw $probe.bodyFailure}
    $prepared=$supplied -eq 3
    $owned=if($prepared){$null}else{Join-Path $controlRoot ('candidate-'+[guid]::NewGuid().ToString('N'))}
    if($owned){$null=[IO.Directory]::CreateDirectory($owned)}
    $probe.context=[pscustomobject]@{Prepared=$prepared;OwnedDirectory=$owned;Path=$(if($prepared){$CandidatePath}else{Join-Path $owned 'WIN-PCInfo.ps1'})}
    $probe.context
}
function New-PreparedTestCandidateManifest {
    param($RepositoryRoot,$CandidatePath)
    $probe.manifests++
    Assert-ReportContext ($RepositoryRoot -ceq $repositoryRoot -and $CandidatePath -ceq $probe.context.Path) 'Manifest must bind the original exact admitted candidate.'
    if($probe.mode -eq 'StandaloneManifestFailure'){throw $probe.bodyFailure}
    [ordered]@{contract='DisclosedPureFullReportContextOnly';candidate=$CandidatePath}
}
function Resolve-WinPCInfoRuntime {
    param($ApplicationPath)
    $probe.runtimePaths.Add($ApplicationPath)
    if($probe.kind -in @('Runtime','RuntimeAndClose')){throw $probe.bodyFailure}
    $resolvedRuntime
}
function Invoke-QualificationTestProcess {
    param($HostPath,$Arguments)
    $probe.calls.Add([pscustomobject]@{host=$HostPath;arguments=@($Arguments)})
    if($probe.kind -in @('Body','Unsafe','BodyAndClose') -and $probe.calls.Count -eq $probe.at){throw $probe.bodyFailure}
    $global:LASTEXITCODE=if($probe.kind -eq 'Exit' -and $probe.calls.Count -eq $probe.at){1}else{0}
}
function Close-TestCandidate {
    param($Candidate,$BodyError)
    $probe.closes++;$probe.closedContext=$Candidate;$probe.closedBodyError=$BodyError
    if($probe.kind -in @('BodyAndClose','RuntimeAndClose')){
        $exception=[AggregateException]::new('Disclosed pure report body and close failure.',[Exception[]]@($BodyError.Exception,$probe.closeFailure))
        $exception.Data['OwnedCleanupUnverified']=$true;throw $exception
    }
    if($BodyError){throw $BodyError.Exception}
    if($probe.mode -like '*CloseFailure'){throw $probe.closeFailure}
}
function Normalize-ReportBody {
    param([string]$Text)
    $Text.Replace("`r`n","`n").Trim()
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$ownedParent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
$controlRoot=Join-Path $ownedParent ('full-report-context-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($controlRoot)
$resolvedRuntime=Join-Path $controlRoot 'disclosed-recording-runtime.exe'
$controls=0;$recordedLeaves=0
try {
    $path=Join-Path $PSScriptRoot 'FullReportApplication.Tests.ps1';$tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Assert-ReportContext ($errors.Count -eq 0 -and ($ast.ParamBlock.Parameters.Name.VariablePath.UserPath -join '|') -ceq 'CandidatePath|PreparedManifestPath|PreparedManifestSha256') 'Actual caller must parse and expose only the shared prepared three-pin interface.'
    $tryStatements=@($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })
    Assert-ReportContext ($tryStatements.Count -eq 1 -and $tryStatements[0].Finally.Extent.Text -ceq '{ Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }') 'One exact candidate context/body error must reach one shared finalizer.'
    $body=Normalize-ReportBody (@($tryStatements[0].Body.Statements | Select-Object -Skip 1).Extent.Text -join "`n")
    $pinLine='    $arguments += @(''-CandidatePath'',$candidateContext.Path,''-PreparedManifestPath'',$PreparedManifestPath,''-PreparedManifestSha256'',$PreparedManifestSha256)'
    $body=$body.Replace($pinLine+"`n",'').Replace('$runtime = Resolve-WinPCInfoRuntime -ApplicationPath $candidateContext.Path','$runtime = Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path (Split-Path $PSScriptRoot) ''artifacts/WIN-PCInfo.ps1'')')
    $original=@'
$runtime = Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path (Split-Path $PSScriptRoot) 'artifacts/WIN-PCInfo.ps1')
foreach ($outcome in @('AcceptedElevation','ElevationDenied')) {
    $arguments = @('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-ReportContract','-PrivilegeOutcome',$outcome)
    if ($outcome -eq 'AcceptedElevation') { $arguments += @('-SoftwareReportScenario','Maximum') }
    Invoke-QualificationTestProcess -HostPath $runtime -Arguments $arguments
    if ($LASTEXITCODE -ne 0) { throw "Comprehensive report contract failed for $outcome." }
}
'@
    Assert-ReportContext ($body -ceq (Normalize-ReportBody $original)) 'Removing only candidate admission path/tail changes must restore every original tuple, maximum condition, runtime host and exit assertion exactly.'
    $imports=@($ast.EndBlock.Statements | Where-Object { $_.Extent.Text -ceq ". (Join-Path `$PSScriptRoot 'TestHarness.ps1')" })
    Assert-ReportContext ($imports.Count -eq 1) 'Actual caller harness import must be unique.'
    $source=$ast.Extent.Text.Replace($imports[0].Extent.Text,'# Pure recording APIs inherited from this control.')
    $replayTokens=$null;$replayErrors=$null
    $replayAst=[Management.Automation.Language.Parser]::ParseInput($source,$path,[ref]$replayTokens,[ref]$replayErrors)
    Assert-ReportContext ($replayErrors.Count -eq 0) 'Actual caller replay must parse.'
    $control=$replayAst.GetScriptBlock()
    $cases=[Collections.Generic.List[object]]::new()
    foreach($prefix in @('Prepared','Standalone')){
        $cases.Add(@{mode=($prefix+'Success');kind='';at=0})
        $cases.Add(@{mode=($prefix+'CloseFailure');kind='';at=0})
        foreach($kind in @('Runtime','RuntimeAndClose')){$cases.Add(@{mode=($prefix+$kind);kind=$kind;at=0})}
        foreach($kind in @('Body','Unsafe','Exit','BodyAndClose')){
            foreach($at in @(1,2)){$cases.Add(@{mode=($prefix+$kind);kind=$kind;at=$at})}
        }
    }
    foreach($mode in @('AdmissionRefuse','PartialCandidate','PartialManifest','BadDigest','StandaloneManifestFailure')){$cases.Add(@{mode=$mode;kind='';at=0})}
    foreach($case in $cases){
        $probe=[pscustomobject]@{mode=$case.mode;kind=$case.kind;at=$case.at;opens=0;closes=0;manifests=0;
            admission=$null;context=$null;closedContext=$null;closedBodyError=$null;calls=[Collections.Generic.List[object]]::new();runtimePaths=[Collections.Generic.List[string]]::new();
            bodyFailure=[InvalidOperationException]::new('Disclosed pure full-report body failure.');closeFailure=[InvalidOperationException]::new('Disclosed pure full-report close failure.')}
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
        Assert-ReportContext ($probe.opens -eq 1 -and $probe.admission[0] -ceq $repositoryRoot) 'Actual caller opens once with repository ownership before resolving the runtime or leaf.'
        if($case.mode -in @('AdmissionRefuse','PartialCandidate','PartialManifest','BadDigest')){
            Assert-ReportContext ($probe.closes -eq 0 -and $probe.runtimePaths.Count -eq 0 -and $probe.calls.Count -eq 0 -and $null -ne $failure) 'Refused candidate cannot discover a runtime, invoke a leaf or close unowned state.'
            continue
        }
        Assert-ReportContext ($probe.closes -eq 1 -and [object]::ReferenceEquals($probe.context,$probe.closedContext)) 'Exact original candidate context closes once.'
        if($case.mode -like 'Standalone*'){
            Assert-ReportContext ($probe.manifests -eq 1) 'Standalone caller creates one shared pinned manifest.'
            $manifest=Join-Path $probe.context.OwnedDirectory 'prepared-test-candidate.json'
            $digest=if($case.mode -eq 'StandaloneManifestFailure'){$null}else{(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()}
        }else{
            Assert-ReportContext ($probe.manifests -eq 0 -and $probe.admission[1] -ceq $parameters.CandidatePath -and $probe.admission[2] -ceq $parameters.PreparedManifestPath -and $probe.admission[3] -ceq $parameters.PreparedManifestSha256) 'Prepared caller consumes the exact operands and never recreates a manifest.'
            $manifest=$parameters.PreparedManifestPath;$digest=$parameters.PreparedManifestSha256
        }
        $beforeRuntime=$case.mode -eq 'StandaloneManifestFailure'
        Assert-ReportContext ($probe.runtimePaths.Count -eq $(if($beforeRuntime){0}else{1})) 'Runtime resolution follows successful candidate/manifest admission exactly once.'
        if(-not $beforeRuntime){Assert-ReportContext ($probe.runtimePaths[0] -ceq $probe.context.Path) 'Runtime selection uses the admitted candidate rather than fixed/shared artifacts.'}
        $bodyFails=$case.kind -ne '' -or $beforeRuntime
        $expectedCount=if($beforeRuntime -or $case.kind -like 'Runtime*'){0}elseif($bodyFails){$case.at}else{2}
        Assert-ReportContext ($probe.calls.Count -eq $expectedCount) 'Original accepted→denied campaign stops at the exact failing boundary.'
        for($index=0;$index -lt $probe.calls.Count;$index++){
            $expected=@('-NoLogo','-NoProfile','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-ReportContract','-PrivilegeOutcome',@('AcceptedElevation','ElevationDenied')[$index])
            if($index -eq 0){$expected+=@('-SoftwareReportScenario','Maximum')}
            $expected+=@('-CandidatePath',$probe.context.Path,'-PreparedManifestPath',$manifest,'-PreparedManifestSha256',$digest)
            Assert-ReportContext ($probe.calls[$index].host -ceq $resolvedRuntime -and ($probe.calls[$index].arguments -join '|') -ceq ($expected -join '|')) 'Original host/flags/maximum tuple and exact three-pin forwarding remain unchanged.'
        }
        if($bodyFails){
            Assert-ReportContext ($null -ne $failure -and $null -ne $probe.closedBodyError) 'Body/runtime/manifest failure must reach the owner finalizer and cannot fall through.'
            if($case.kind -in @('BodyAndClose','RuntimeAndClose')){
                Assert-ReportContext ($failure.Exception -is [AggregateException] -and [object]::ReferenceEquals($failure.Exception.InnerExceptions[0],$probe.bodyFailure) -and [object]::ReferenceEquals($failure.Exception.InnerExceptions[1],$probe.closeFailure) -and $failure.Exception.Data['OwnedCleanupUnverified']) 'Combined body/close failure preserves both causes and unsafe cleanup.'
            }else{
                Assert-ReportContext ([object]::ReferenceEquals($failure.Exception,$probe.closedBodyError.Exception)) 'Original body failure survives close.'
                if($case.kind -ne 'Exit'){Assert-ReportContext ([object]::ReferenceEquals($failure.Exception,$probe.bodyFailure)) 'Original thrown exception is preserved.'}
                if($case.kind -eq 'Unsafe'){Assert-ReportContext ($failure.Exception.Data['OwnedCleanupUnverified'] -eq $true) 'Original unsafe marker is retained.'}
            }
        }elseif($case.mode -like '*CloseFailure'){
            Assert-ReportContext ($null -ne $failure -and [object]::ReferenceEquals($failure.Exception,$probe.closeFailure)) 'Close failure cannot fall through to success.'
        }else{Assert-ReportContext ($null -eq $failure -and $null -eq $probe.closedBodyError) 'Success finalizes without invented failure.'}
        Assert-ReportContext ($output.Count -eq $(if($null -eq $failure){1}else{0})) 'Caller PASS is emitted only after successful owner finalization.'
    }
}
finally {
    $resolved=[IO.Path]::GetFullPath($controlRoot)
    if(-not $resolved.StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -cnotmatch '^full-report-context-[a-f0-9]{32}$'){throw 'Pure fixture cleanup escaped its exact owned parent.'}
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
    if([IO.Directory]::Exists($resolved)){throw 'Pure fixture cleanup remains incomplete.'}
}
Write-Output ('PASS: {0} pure actual full-report caller controls; {1} recorded leaves; original accepted maximum/denied tuples, three-pin ownership and unsafe finalizers.' -f $controls,$recordedLeaves)
