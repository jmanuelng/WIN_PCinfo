[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$root=Join-Path $repositoryRoot ('.test-output/source-campaign-candidate-'+[guid]::NewGuid().ToString('N'))
$fixtureTests=Join-Path $root 'tests'
$null=[IO.Directory]::CreateDirectory($fixtureTests)
$previousSpy=Get-Variable -Name SourceCampaignCandidateSpy -Scope Global -ErrorAction SilentlyContinue
$previousExit=Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
try {
    $tokens=$null;$errors=$null
    $ownerAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'TestHarness.ps1'),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Candidate owner does not parse.' }
    $owners=@($ownerAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Close-TestCandidate'},$true))
    if ($owners.Count -ne 1) { throw 'Candidate owner is not unique.' }
    $bodyParameter=@($owners[0].Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -ceq 'BodyError' })
    if ($bodyParameter.Count -ne 1 -or $bodyParameter[0].StaticType -ne [Management.Automation.ErrorRecord]) { throw 'Caller regression must match the actual finalizer ErrorRecord contract.' }
    # Only the actual caller is copied. The candidate owner, runtime and native
    # leaf below are disclosed substitutes; this regression creates no child.
    $stub=@'
function Open-TestCandidate {
    param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $expected=if ($global:SourceCampaignCandidateSpy.ContainsKey('expectedCandidate')) {$global:SourceCampaignCandidateSpy.expectedCandidate} else {'prepared-candidate.ps1'}
    if ($CandidatePath -cne $expected -or $PreparedManifestPath -cne 'prepared-manifest.json' -or $PreparedManifestSha256 -cne ('1'*64)) { throw 'Explicit prepared inputs were not forwarded to the owner.' }
    $global:SourceCampaignCandidateSpy.opens++
    [pscustomobject]@{Path=$CandidatePath;Prepared=$true;OwnedDirectory=$null}
}
function Get-TestAdmittedRuntimeHost {
    if ($global:SourceCampaignCandidateSpy.opens -ne 1) { throw 'Transport host selection must follow original candidate admission.' }
    'synthetic-pwsh'
}
function Invoke-QualificationTestProcess {
    param($HostPath,$Arguments)
    if ($HostPath -cne 'synthetic-pwsh') { throw 'Caller ignored the admitted runtime.' }
    $argumentsByName=@{}
    for ($index=0;$index-lt$Arguments.Count-1;$index++) {
        if ($Arguments[$index] -in @('-CandidatePath','-PreparedManifestPath','-PreparedManifestSha256','-RemoteSourceScenario','-IdentitySourceScenario','-SecuritySourceScenario','-PolicySourceScenario')) { $argumentsByName[$Arguments[$index]]=$Arguments[$index+1] }
    }
    if ($argumentsByName['-CandidatePath'] -cne 'prepared-candidate.ps1' -or $argumentsByName['-PreparedManifestPath'] -cne 'prepared-manifest.json' -or $argumentsByName['-PreparedManifestSha256'] -cne ('1'*64)) { throw 'Leaf would rebuild or consume different prepared input.' }
    $scenario=@($argumentsByName.Keys | Where-Object { $_.EndsWith('SourceScenario') })
    if ($scenario.Count -ne 1) { throw 'Original source scenario selection changed.' }
    $global:SourceCampaignCandidateSpy.calls.Add($argumentsByName[$scenario[0]])
    $global:LASTEXITCODE=0
    if ($global:SourceCampaignCandidateSpy.fail -and $global:SourceCampaignCandidateSpy.calls.Count -eq 2) { throw 'Synthetic original source failure' }
}
function Close-TestCandidate {
    param($Candidate,[AllowNull()] [Management.Automation.ErrorRecord] $BodyError)
    $global:SourceCampaignCandidateSpy.closes++
    if ($global:SourceCampaignCandidateSpy.ContainsKey('kind')) {
        $global:SourceCampaignCandidateSpy.closedBodyError=$BodyError
        if ($null -ne $BodyError -and $global:SourceCampaignCandidateSpy.kind -eq 'BodyAndClose') {
            $failure=[AggregateException]::new('Disclosed body and candidate close failure.',[Exception[]]@($BodyError.Exception,$global:SourceCampaignCandidateSpy.closeFailure))
            $failure.Data['OwnedCleanupUnverified']=$true
            throw $failure
        }
    }
    if ($null -ne $BodyError) { throw $BodyError }
}
function Invoke-GeneratedApplication {
    param($CandidatePath,$Arguments)
    if ($CandidatePath -cne $global:SourceCampaignCandidateSpy.expectedCandidate) { throw 'Ordinary application caller ignored its immutable input.' }
    $global:SourceCampaignCandidateSpy.calls.Add($CandidatePath)
    if ($global:SourceCampaignCandidateSpy.ContainsKey('bodyFailure')) { throw $global:SourceCampaignCandidateSpy.bodyFailure }
    throw 'Synthetic original application failure'
}
function Test-Json {
    param($Json,$SchemaFile)
    # Schema semantics are outside this caller control. Reach the first leaf
    # using the original fixture read, with schema validation substituted.
    $true
}
'@
    [IO.File]::WriteAllText((Join-Path $fixtureTests 'TestHarness.ps1'),$stub,[Text.UTF8Encoding]::new($false))
    $fixtureInputs=Join-Path $fixtureTests 'fixtures'
    $null=[IO.Directory]::CreateDirectory($fixtureInputs)
    foreach ($inputName in @('automation-request.json','automation-request-connectivity.json')) {
        [IO.File]::Copy((Join-Path $PSScriptRoot ('fixtures/'+$inputName)),(Join-Path $fixtureInputs $inputName))
    }
    foreach ($name in @('RemoteSourceApplication.Tests.ps1','IdentitySourceApplication.Tests.ps1','SecuritySourceApplication.Tests.ps1','PolicySourceApplication.Tests.ps1')) {
        $copy=Join-Path $fixtureTests $name
        [IO.File]::Copy((Join-Path $PSScriptRoot $name),$copy)
        foreach ($fail in @($false,$true)) {
            $global:SourceCampaignCandidateSpy=@{opens=0;closes=0;calls=[Collections.Generic.List[string]]::new();fail=$fail}
            $errorRecord=$null
            try { & $copy -Scenario First,Second -CandidatePath 'prepared-candidate.ps1' -PreparedManifestPath 'prepared-manifest.json' -PreparedManifestSha256 ('1'*64) | Out-Null }
            catch { $errorRecord=$_ }
            $spy=$global:SourceCampaignCandidateSpy
            if ($spy.opens -ne 1 -or $spy.closes -ne 1 -or ($spy.calls -join ',') -cne 'First,Second') { throw 'Campaign did not reuse and close one candidate through the original case order.' }
            if ($fail) {
                if ($null -eq $errorRecord -or $errorRecord.Exception.Message -cne 'Synthetic original source failure') { throw 'Original leaf failure was hidden or replaced.' }
            }
            elseif ($null -ne $errorRecord) { throw $errorRecord }
        }
    }
    foreach ($name in @('DeviceReadinessApplication.Tests.ps1','DeviceReadinessScenarios.Tests.ps1',
        'FirmwareReadinessApplication.Tests.ps1','CrossDomainGuidanceApplication.Tests.ps1',
        'AdministratorExposureApplication.Tests.ps1','MicrosoftConnectivityApplication.Tests.ps1',
        'NetworkTopologyApplication.Tests.ps1','IdentityEnrollmentApplication.Tests.ps1',
        'SoftwareInventoryApplication.Tests.ps1','ComprehensiveReportApplication.Tests.ps1',
        'RequestValidation.Tests.ps1','ResourceDependenciesApplication.Tests.ps1','SchemaContracts.Tests.ps1',
        'CertificateTrustApplication.Tests.ps1','PrivilegedCollectionPlanApplication.Tests.ps1',
        'ProductHelpApplication.Tests.ps1','EvidenceWorkspaceApplication.Tests.ps1','RunApplication.Tests.ps1')) {
        $copy=Join-Path $fixtureTests $name
        [IO.File]::Copy((Join-Path $PSScriptRoot $name),$copy)
        foreach ($manifest in @('prepared-manifest.json','')) {
        foreach ($kind in @('Ordinary','Unsafe','BodyAndClose')) {
            $expectedCandidate=Join-Path $root 'prepared-candidate.ps1'
            $bodyFailure=[InvalidOperationException]::new('Synthetic original application failure')
            if ($kind -eq 'Unsafe') { $bodyFailure.Data['OwnedCleanupUnverified']=$true }
            $closeFailure=[InvalidOperationException]::new('Synthetic candidate close failure')
            $global:SourceCampaignCandidateSpy=@{opens=0;closes=0;calls=[Collections.Generic.List[string]]::new();fail=$false;expectedCandidate=$expectedCandidate;kind=$kind;bodyFailure=$bodyFailure;closeFailure=$closeFailure;closedBodyError=$null}
            $errorRecord=$null
            $output=[Collections.Generic.List[object]]::new()
            try { & $copy -CandidatePath $expectedCandidate -PreparedManifestPath $manifest -PreparedManifestSha256 ('1'*64) | ForEach-Object { $output.Add($_) } }
            catch { $errorRecord=$_ }
            $spy=$global:SourceCampaignCandidateSpy
            if ($manifest) {
                if ($spy.opens -ne 1 -or $spy.closes -ne 1 -or $spy.calls.Count -ne 1 -or
                    $null -eq $errorRecord -or $spy.closedBodyError -isnot [Management.Automation.ErrorRecord] -or
                    -not [object]::ReferenceEquals($spy.closedBodyError.Exception,$bodyFailure)) {
                    throw 'Ordinary consumer changed prepared input or hid its original failure/finalization.'
                }
                if ($kind -eq 'BodyAndClose') {
                    if ($errorRecord.Exception -isnot [AggregateException] -or $errorRecord.Exception.InnerExceptions.Count -ne 2 -or
                        -not [object]::ReferenceEquals($errorRecord.Exception.InnerExceptions[0],$bodyFailure) -or
                        -not [object]::ReferenceEquals($errorRecord.Exception.InnerExceptions[1],$closeFailure) -or
                        $errorRecord.Exception.Data['OwnedCleanupUnverified'] -ne $true) { throw 'Combined body and close failure lost an original cause or unsafe cleanup.' }
                }
                elseif (-not [object]::ReferenceEquals($errorRecord.Exception,$bodyFailure) -or
                    ($kind -eq 'Unsafe' -and $errorRecord.Exception.Data['OwnedCleanupUnverified'] -ne $true)) {
                    throw 'Original ordinary or unsafe body failure changed at candidate finalization.'
                }
            }
            elseif ($spy.opens -ne 0 -or $spy.closes -ne 0 -or $spy.calls.Count -ne 0 -or
                $null -eq $errorRecord -or $errorRecord.Exception.Message -cne 'Explicit prepared inputs were not forwarded to the owner.') {
                throw 'Ordinary consumer rebuilt or launched after explicit incomplete input.'
            }
            if (@($output | Where-Object { $_ -is [string] -and $_ -like 'PASS:*' }).Count) { throw 'Failure escaped to a caller PASS before finalization.' }
        }
        }
    }
    Write-Output 'PASS: four source campaigns and eighteen ordinary consumers retain explicit prepared input, typed ErrorRecord causes, unsafe and combined finalizer failures without PASS fallthrough; native leaves and schema validation are substituted.'
}
finally {
    if ($null -ne $previousSpy) { Set-Variable -Name SourceCampaignCandidateSpy -Scope Global -Value $previousSpy.Value }
    else { Remove-Variable -Name SourceCampaignCandidateSpy -Scope Global -ErrorAction SilentlyContinue }
    if ($null -ne $previousExit) { Set-Variable -Name LASTEXITCODE -Scope Global -Value $previousExit.Value }
    else { Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
    $resolved=[IO.Path]::GetFullPath($root)
    if ([IO.Path]::GetDirectoryName($resolved) -ne [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))) { throw 'Source campaign fixture cleanup escaped its owner.' }
    [IO.Directory]::Delete($resolved,$true)
}
