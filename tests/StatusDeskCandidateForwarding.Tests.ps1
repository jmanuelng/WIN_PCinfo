[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Replay the actual campaign wrappers with only TestHarness APIs substituted.
# Engine leaves are argument recordings: no build, child or GUI is invoked.
function Assert-CampaignControl {
    param([bool]$Condition,[string]$Message)
    if(-not $Condition){throw $Message}
}
function Assert-QualificationCleanupReady {}
function Open-TestCandidate {
    param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $probe.opens++
    $probe.admission=@($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    if($probe.mode -eq 'AdmissionRefuse'){throw $probe.bodyFailure}
    $prepared=-not [string]::IsNullOrEmpty($CandidatePath)
    $owned=if($prepared){$null}else{Join-Path $controlRoot ('candidate-'+[guid]::NewGuid().ToString('N'))}
    if($owned){$null=[IO.Directory]::CreateDirectory($owned)}
    $probe.context=[pscustomobject]@{Prepared=$prepared;OwnedDirectory=$owned;
        Path=$(if($prepared){$CandidatePath}else{Join-Path $owned 'WIN-PCInfo.ps1'})}
    $probe.context
}
function New-PreparedTestCandidateManifest {
    param($RepositoryRoot,$CandidatePath)
    $probe.manifests++
    Assert-CampaignControl ($RepositoryRoot -ceq $repositoryRoot -and $CandidatePath -ceq $probe.context.Path) 'Standalone manifest must bind the admitted root and candidate.'
    [ordered]@{contract='disclosed-pure-campaign-fixture';candidate=$CandidatePath}
}
function Invoke-QualificationTestProcess {
    param($HostPath,[string[]]$Arguments)
    $probe.calls.Add([pscustomobject]@{host=$HostPath;arguments=$Arguments})
    if($probe.calls.Count -eq $probe.failureAt){
        if($probe.mode -like '*ExitFailure'){$global:LASTEXITCODE=1;return}
        if($probe.mode -like '*BodyFail' -or $probe.mode -like '*Unsafe'){throw $probe.bodyFailure}
    }
    $global:LASTEXITCODE=0
}
function Close-TestCandidate {
    param($Candidate,$BodyError)
    $probe.closes++;$probe.closedContext=$Candidate;$probe.closedBodyError=$BodyError
    if($BodyError){throw $BodyError.Exception}
    if($probe.mode -like '*CloseFailure'){throw $probe.closeFailure}
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$ownedParent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
$controlRoot=Join-Path $ownedParent ('wpf-campaign-forwarding-'+[guid]::NewGuid().ToString('N'))
Assert-CampaignControl ([IO.Path]::GetFullPath($controlRoot).StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase)) 'Pure fixture root must remain within its owned parent.'
$null=[IO.Directory]::CreateDirectory($controlRoot)
$controls=0;$recordedLeaves=0
try{
foreach($name in @('StatusDeskWpf.Tests.ps1','StatusDeskActiveActions.Tests.ps1')){
    $path=Join-Path $PSScriptRoot $name
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Assert-CampaignControl ($errors.Count -eq 0) 'Actual WPF campaign must parse.'
    $imports=@($ast.EndBlock.Statements|Where-Object{$_.Extent.Text -ceq ". (Join-Path `$PSScriptRoot 'TestHarness.ps1')"})
    Assert-CampaignControl ($imports.Count -eq 1) 'Actual WPF campaign harness import must be unique.'
    $source=$ast.Extent.Text.Replace($imports[0].Extent.Text,'# Pure API stubs inherited from this control.')
    $controlTokens=$null;$controlErrors=$null
    $controlAst=[Management.Automation.Language.Parser]::ParseInput($source,$path,[ref]$controlTokens,[ref]$controlErrors)
    Assert-CampaignControl ($controlErrors.Count -eq 0) 'Pure actual campaign replay must parse.'
    $control=$controlAst.GetScriptBlock()
    $base=@('-NoLogo','-NoProfile','-STA','-File',(Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1'),'-Wpf')
    $expected=[Collections.Generic.List[object]]::new()
    if($name -eq 'StatusDeskWpf.Tests.ps1'){$expected.Add($base)}
    else{
        foreach($pair in @(
            @{action='Cancel';worker='Privilege'},@{action='Close';worker='Privilege'},
            @{action='Cancel';worker='System'},@{action='Close';worker='System'},
            @{action='Cancel';worker='NativeCooperative'},@{action='Close';worker='NativeHard'})){
            $expected.Add(($base+@('-ActiveAction',$pair.action,'-ActiveWorker',$pair.worker,'-RequireRecoveryJournal')))
        }
        foreach($fault in @('PreStartIntegrity','Integrity','Cleanup')){$expected.Add(($base+@('-FailureKind',$fault)))}
    }
    foreach($mode in @('PreparedSuccess','StandaloneSuccess','PreparedBodyFail','StandaloneBodyFail',
        'PreparedUnsafe','StandaloneUnsafe','PreparedExitFailure','StandaloneExitFailure',
        'PreparedCloseFailure','StandaloneCloseFailure','AdmissionRefuse')){
        $probe=[pscustomobject]@{mode=$mode;opens=0;closes=0;manifests=0;admission=$null;context=$null;
            calls=[Collections.Generic.List[object]]::new();closedContext=$null;closedBodyError=$null;
            failureAt=$(if($name -eq 'StatusDeskWpf.Tests.ps1'){1}else{2});
            bodyFailure=[InvalidOperationException]::new('Disclosed pure WPF campaign body failure.');
            closeFailure=[InvalidOperationException]::new('Disclosed pure WPF candidate close failure.')}
        if($mode -like '*Unsafe'){$probe.bodyFailure.Data['OwnedCleanupUnverified']=$true}
        $parameters=@{}
        if($mode -notlike 'Standalone*'){
            $parameters=@{CandidatePath=(Join-Path $controlRoot 'explicit-candidate.ps1');
                PreparedManifestPath=(Join-Path $controlRoot 'explicit-manifest.json');PreparedManifestSha256=('a'*64)}
        }
        $failure=$null
        try{& $control @parameters|Out-Null}catch{$failure=$_}
        Assert-CampaignControl ($probe.opens -eq 1 -and $probe.admission[0] -ceq $repositoryRoot) 'Each actual campaign must open once with its repository ownership.'
        $controls++;$recordedLeaves+=$probe.calls.Count
        if($mode -eq 'AdmissionRefuse'){
            Assert-CampaignControl ($probe.calls.Count -eq 0 -and $probe.closes -eq 0 -and $null -ne $failure) 'Refused admission must reach neither leaf nor unowned close.'
            continue
        }
        Assert-CampaignControl ($probe.closes -eq 1 -and [object]::ReferenceEquals($probe.context,$probe.closedContext)) 'Campaign must close its one exact context.'
        $bodyFails=$mode -like '*BodyFail' -or $mode -like '*Unsafe' -or $mode -like '*ExitFailure'
        $expectedCount=if($bodyFails){$probe.failureAt}else{$expected.Count}
        Assert-CampaignControl ($probe.calls.Count -eq $expectedCount) 'Original campaign order and failure stop must remain unchanged.'
        if($mode -like 'Standalone*'){
            $manifest=Join-Path $probe.context.OwnedDirectory 'prepared-test-candidate.json'
            $manifestHash=(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()
            Assert-CampaignControl ($probe.manifests -eq 1) 'Standalone campaign must create exactly one shared pinned manifest.'
            Assert-CampaignControl (-not $probe.admission[1] -and -not $probe.admission[2] -and -not $probe.admission[3]) 'Standalone admission must not borrow shared artifact inputs.'
        }
        else{
            $manifest=$parameters.PreparedManifestPath;$manifestHash=$parameters.PreparedManifestSha256
            Assert-CampaignControl ($probe.manifests -eq 0) 'Prepared campaigns must not recreate their pinned manifest.'
            Assert-CampaignControl ($probe.admission[1] -ceq $parameters.CandidatePath -and $probe.admission[2] -ceq $manifest -and $probe.admission[3] -ceq $manifestHash) 'Prepared admission operands must remain exact.'
        }
        for($i=0;$i -lt $probe.calls.Count;$i++){
            $expectedArguments=@($expected[$i])+@('-CandidatePath',$probe.context.Path,'-PreparedManifestPath',$manifest,'-PreparedManifestSha256',$manifestHash)
            Assert-CampaignControl ($probe.calls[$i].host -ceq (Join-Path $PSHOME 'pwsh.exe')) 'Original child host must remain unchanged.'
            Assert-CampaignControl (($probe.calls[$i].arguments|ConvertTo-Json -Compress) -ceq ($expectedArguments|ConvertTo-Json -Compress)) 'Every original child tuple, STA flag and exact prepared binding must remain unchanged.'
        }
        if($bodyFails){
            Assert-CampaignControl ($null -ne $failure -and $null -ne $probe.closedBodyError -and [object]::ReferenceEquals($failure.Exception,$probe.closedBodyError.Exception)) 'Body failure must be forwarded and rethrown at close.'
            if($mode -notlike '*ExitFailure'){Assert-CampaignControl ([object]::ReferenceEquals($failure.Exception,$probe.bodyFailure)) 'Original thrown body exception must survive.'}
            if($mode -like '*Unsafe'){Assert-CampaignControl ($failure.Exception.Data['OwnedCleanupUnverified'] -eq $true) 'Unsafe ownership must survive failure cleanup.'}
        }
        elseif($mode -like '*CloseFailure'){
            Assert-CampaignControl ($null -ne $failure -and [object]::ReferenceEquals($failure.Exception,$probe.closeFailure)) 'Candidate close failure must not fall through to success.'
        }
        else{Assert-CampaignControl ($null -eq $failure -and $null -eq $probe.closedBodyError) 'Successful campaign must close without inventing failure.'}
    }
}
}
finally{
    $resolved=[IO.Path]::GetFullPath($controlRoot)
    if(-not $resolved.StartsWith($ownedParent,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -cnotmatch '\Awpf-campaign-forwarding-[a-f0-9]{32}\z'){
        throw 'Pure fixture cleanup escaped its exact owned parent.'
    }
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
    if([IO.Directory]::Exists($resolved)){throw 'Pure fixture cleanup remains incomplete.'}
}
Write-Output ('PASS: {0} pure actual-campaign controls; {1} recorded leaves; exact tuple/binding forwarding and failure cleanup.' -f $controls,$recordedLeaves)
