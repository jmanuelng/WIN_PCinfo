[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Replay the actual wrapper with recording candidate/application/setup APIs.
# TEMP and repository ownership are redirected to this private pure fixture.
# No build, child, certificate/key provider, trust modification or process query.
. (Join-Path $PSScriptRoot 'QualificationCleanup.ps1')
$realComplete=(Get-Item Function:\Complete-QualificationHarness).ScriptBlock
function Assert-SharingControl {
    param([bool]$Condition,[string]$Message)
    if(-not $Condition){throw $Message}
}
function Assert-Equal {
    param($Expected,$Actual,[string]$Because)
    if($Expected -ne $Actual){throw "Expected '$Expected' but received '$Actual': $Because"}
}
function Assert-QualificationCleanupReady {}
function Get-QualificationCleanupBlockerPath { Join-Path $probe.repository '.test-output/pure-cleanup-blocked.json' }
function Complete-QualificationHarness {
    param($BodyError,[scriptblock]$RetainEvidence,[scriptblock[]]$Cleanup=@(),[scriptblock]$RetainCleanupEvidence)
    $probe.events.Add('FixtureFinalize');$probe.finalizers++
    & $realComplete @PSBoundParameters
    $probe.events.Add('FixtureFinalized')
}
function Open-TestCandidate {
    param($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $probe.opens++;$probe.admission=@($RepositoryRoot,$CandidatePath,$PreparedManifestPath,$PreparedManifestSha256)
    $supplied=@(@($CandidatePath,$PreparedManifestPath,$PreparedManifestSha256) | Where-Object { -not [string]::IsNullOrEmpty($_) }).Count
    if($probe.mode -eq 'AdmissionRefuse' -or ($supplied -ne 0 -and ($supplied -ne 3 -or $PreparedManifestSha256 -cnotmatch '^[a-f0-9]{64}$'))){throw $probe.bodyFailure}
    $prepared=$supplied -eq 3
    $owned=if($prepared){$null}else{Join-Path $probe.repository ('.test-output/candidate-'+[guid]::NewGuid().ToString('N'))}
    if($owned){$null=[IO.Directory]::CreateDirectory($owned)}
    $probe.context=[pscustomobject]@{Prepared=$prepared;OwnedDirectory=$owned;Path=$(if($prepared){$CandidatePath}else{Join-Path $owned 'WIN-PCInfo.ps1'})}
    $probe.context
}
function New-PreparedTestCandidateManifest {
    param($RepositoryRoot,$CandidatePath)
    $probe.manifests++
    Assert-SharingControl ($RepositoryRoot -ceq $probe.repository -and $CandidatePath -ceq $probe.context.Path) 'Manifest binds the admitted candidate and owning repository.'
    if($probe.mode -eq 'ManifestFailure'){throw $probe.bodyFailure}
    [ordered]@{contract='DisclosedPureRecipientSharingContextOnly';candidate=$CandidatePath}
}
function Close-TestCandidate {
    param($Candidate,[AllowNull()] [Management.Automation.ErrorRecord] $BodyError)
    $probe.events.Add('CandidateClose');$probe.closes++;$probe.closedContext=$Candidate;$probe.closedBodyError=$BodyError
    if($probe.kind -in @('CloseFailure','BodyAndClose')){
        $probe.closeFailure.Data['OwnedCleanupUnverified']=$true
        if($BodyError){
            $combined=[AggregateException]::new('Disclosed pure body and close failure.',[Exception[]]@($BodyError.Exception,$probe.closeFailure))
            $combined.Data['OwnedCleanupUnverified']=$true;throw $combined
        }
        throw $probe.closeFailure
    }
    if($BodyError){throw $BodyError.Exception}
    $probe.events.Add('CandidateClosed')
}
function New-Item {
    param($ItemType,$Path,$ErrorAction,[switch]$Force)
    Assert-SharingControl ($ItemType -ceq 'Directory' -and $ErrorAction -ceq 'Stop' -and -not $Force) 'Actual caller creates an exclusive directory without Force.'
    Assert-SharingControl (-not [IO.Directory]::Exists($Path) -and -not [IO.File]::Exists($Path)) 'Caller never acquires an existing fixture parent.'
    $null=[IO.Directory]::CreateDirectory($Path);$probe.fixture=$Path
}
function New-RecipientProfileSetup {
    param($Label,$OutputPath,[switch]$ConfirmSetup,$SyntheticProtectionLevel)
    $probe.setups++
    Assert-SharingControl ($ConfirmSetup -and $Label -ceq 'Synthetic generated-app recipient' -and $SyntheticProtectionLevel -ceq 'WindowsUserBound' -and [IO.Path]::GetDirectoryName($OutputPath) -ceq $probe.fixture) 'Original selected-profile setup flags and owned output are preserved.'
    # Static bytes only; the real synthetic certificate/key creation is replaced.
    [IO.File]::WriteAllText($OutputPath,'Disclosed pure selected profile; no key or certificate.')
    if($probe.kind -eq 'SetupFailure'){throw $probe.bodyFailure}
    [pscustomobject]@{profilePath=$OutputPath;fingerprint='DisclosedPureFingerprint'}
}
function Invoke-GeneratedApplication {
    param($CandidatePath,$Arguments)
    $probe.calls.Add([pscustomobject]@{candidate=$CandidatePath;arguments=@($Arguments)})
    Assert-SharingControl ($CandidatePath -ceq $probe.context.Path) 'Every original application invocation consumes the admitted candidate.'
    if($probe.kind -in @('BodyFailure','UnsafeFailure','BodyAndClose') -and $probe.calls.Count -eq $probe.at){throw $probe.bodyFailure}
    if($probe.kind -eq 'FixtureCleanupFailure' -and $probe.calls.Count -eq 15){
        # Substitute only the caller's cleanup reference with an unowned path
        # inside this pure fixture; its real ownership guard must refuse it.
        Set-Variable -Name selectionRoot -Value (Join-Path $probe.repository '.test-output') -Scope 1
    }
    if($Arguments[0] -ceq '-Workflow'){
        return [pscustomobject]@{ExitCode=20;Records=@([pscustomobject]@{reasonCode='PREPARATION.INTEGRITY_FAILED'});StandardError=''}
    }
    $fixtureIndex=[array]::IndexOf($Arguments,'-RecipientSharingFixturePath')
    $scenario=$expectedScenarios[$probe.calls.Count-4]
    Assert-SharingControl ([IO.Path]::GetFileName($Arguments[$fixtureIndex+1]) -ceq ('recipient-'+$scenario.ToLowerInvariant()+'.json')) 'Original fixture order is retained.'
    $package=$scenario -in @('HistoricalOpening','MissingKey','ZeroRecipient','OneRecipient','InterruptedExport','WarningDeclined','RestrictedExport')
    $access=if($scenario -in @('HistoricalOpening','MissingKey','OneRecipient')){'Unavailable'}else{'None'}
    $state=if($probe.kind -eq 'AssertionFailure' -and $probe.calls.Count -eq $probe.at){'Invalid'}else{'Validated'}
    [pscustomobject]@{ExitCode=20;StandardError='';Records=@(
        [pscustomobject]@{recordType='win-pcinfo.recipient-sharing-validation';state=$state;validationCleanupVerified=$true;completionGuidanceVerified=$true},
        [pscustomobject]@{recordType='win-pcinfo.completion-summary';packageVerified=$package;packageAvailability='VerifiedAbsent';resultSharingGuidance=[pscustomobject]@{
            recipientAccess=$access;privateTransfer=[pscustomobject]@{allowed=$false};deletionResponsibility='None';restrictedExport=[pscustomobject]@{completed=($scenario -eq 'RestrictedExport')}}},
        [pscustomobject]@{recordType='win-pcinfo.terminal';validationFixture=$true}
    )}
}
function Test-SharingContainsException {
    param([Exception]$Outer,[Exception]$Original)
    if([object]::ReferenceEquals($Outer,$Original)){return $true}
    if($Outer -is [AggregateException]){foreach($inner in $Outer.InnerExceptions){if(Test-SharingContainsException $inner $Original){return $true}}}
    if($Outer.InnerException){return (Test-SharingContainsException $Outer.InnerException $Original)}
    $false
}
function Normalize-SharingBody { param([string]$Text) $Text.Replace("`r`n","`n").Trim() }
function Assert-SharingPassOrder {
    param([object[]]$Output,[string[]]$Events,[bool]$Success,[AllowNull()]$Failure)
    $passes=@($Output | Where-Object { $_ -like 'PASS:*' })
    if($passes.Count -gt 0 -and (-not $Success -or ($Events -join '|') -cne 'CandidateClose|CandidateClosed|FixtureFinalize|FixtureFinalized|PASS')){
        $exception=[InvalidOperationException]::new('Early PASS was observed before both successful finalizers.')
        $exception.Data['EarlyPassDetected']=$true
        throw $exception
    }
    Assert-SharingControl ($passes.Count -eq $(if($Success){1}else{0}) -and ($null -eq $Failure) -eq $Success) 'PASS requires the entire original campaign and both finalizers to succeed.'
}
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$ownedParent=[IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output'))
$controlRoot=Join-Path $ownedParent ('recipient-sharing-context-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($controlRoot)
$expectedScenarios=@('TpmBackedSetup','SoftwareFallbackSetup','ProfileValidation','WrongFingerprint','ExpiredAdmission','HistoricalOpening','MissingKey','ZeroRecipient','OneRecipient','InterruptedExport','WarningDeclined','RestrictedExport')
$controls=0;$recordedLeaves=0;$mutantsRejected=0
$mutantOutcomes=[Collections.Generic.List[object]]::new()
try {
    $path=Join-Path $PSScriptRoot 'RecipientSharingApplication.Tests.ps1';$tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Assert-SharingControl ($errors.Count -eq 0 -and ($ast.ParamBlock.Parameters.Name.VariablePath.UserPath -join '|') -ceq 'CandidatePath|PreparedManifestPath|PreparedManifestSha256') 'Actual caller exposes exactly the shared prepared triple.'
    $harnessTokens=$null;$harnessErrors=$null
    $harnessAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'TestHarness.ps1'),[ref]$harnessTokens,[ref]$harnessErrors)
    $controlTokens=$null;$controlErrors=$null
    $controlAst=[Management.Automation.Language.Parser]::ParseFile($PSCommandPath,[ref]$controlTokens,[ref]$controlErrors)
    $actualClose=@($harnessAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Close-TestCandidate'},$true))
    $recordingClose=@($controlAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Close-TestCandidate'},$true))
    Assert-SharingControl ($harnessErrors.Count -eq 0 -and $controlErrors.Count -eq 0 -and $actualClose.Count -eq 1 -and $recordingClose.Count -eq 1) 'The actual harness and recording Close APIs parse and are unique.'
    foreach($definition in @($actualClose[0],$recordingClose[0])){
        $bodyParameter=@($definition.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -ceq 'BodyError' })
        $bodyTypes=@($bodyParameter.Attributes | Where-Object { $_ -is [Management.Automation.Language.TypeConstraintAst] })
        Assert-SharingControl ($bodyParameter.Count -eq 1 -and $bodyTypes.Count -eq 1 -and $bodyTypes[0].TypeName.GetReflectionType() -eq [Management.Automation.ErrorRecord]) 'Recording Close BodyError binds the exact actual TestHarness ErrorRecord type.'
    }
    $outer=@($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })
    Assert-SharingControl ($outer.Count -eq 1 -and $outer[0].CatchClauses.Count -eq 1 -and $outer[0].Finally.Extent.Text.Contains('Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError')) 'All setup and cases share one candidate owner and body-error finalizer.'
    $loop=@($outer[0].Body.Statements | Where-Object { $_ -is [Management.Automation.Language.ForEachStatementAst] -and $_.Variable.VariablePath.UserPath -ceq 'scenario' })
    Assert-SharingControl ($loop.Count -eq 1) 'One original twelve-scenario loop remains.'
    $caseAssignment=@($outer[0].Body.Statements | Where-Object { $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$cases' })
    $actualCases=@(& ([scriptblock]::Create($caseAssignment[0].Right.Extent.Text)))
    Assert-SharingControl (($actualCases -join '|') -ceq ($expectedScenarios -join '|')) 'Every original case and its order are unchanged.'
    # The exact original loop is embedded below; only the candidate operand changes.
    $originalLoop=@'
foreach ($scenario in $cases) {
    $before = @(Get-RecipientValidationResidue)
    $result = Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode', 'Automation', '-RequestPath', $(if ($scenario -eq 'OneRecipient') {
            $selectedRequestPath
        }
        else { $requestPath }), '-AcceptPreparation',
        '-PreparationFixturePath', $preparationPath,
        '-RecipientSharingFixturePath', (
            Join-Path $PSScriptRoot "fixtures/recipient-$($scenario.ToLowerInvariant()).json"
        )
    )
    $after = @(Get-RecipientValidationResidue)
    $records = @($result.Records | Where-Object `
        recordType -eq 'win-pcinfo.recipient-sharing-validation')
    $summaries = @($result.Records | Where-Object `
        recordType -eq 'win-pcinfo.completion-summary')
    $terminals = @($result.Records | Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $records.Count "$scenario emits one sanitized sharing result"
    Assert-Equal 1 $summaries.Count "$scenario emits one actual Completion Summary"
    Assert-Equal 1 $terminals.Count "$scenario emits one terminal result"
    Assert-Equal 20 $result.ExitCode "$scenario validates with the stable fixture exit"
    Assert-Equal 'Validated' $records[0].state "$scenario proves its expected safety behavior"
    Assert-Equal $true $records[0].validationCleanupVerified `
        "$scenario removes every synthetic profile, package, export, and key handle"
    Assert-Equal $true $records[0].completionGuidanceVerified `
        "$scenario retains all six Result-sharing Guidance topics"
    $expectedPackageVerified = $scenario -in @(
        'HistoricalOpening', 'MissingKey', 'ZeroRecipient', 'OneRecipient',
        'InterruptedExport', 'WarningDeclined', 'RestrictedExport'
    )
    Assert-Equal $expectedPackageVerified $summaries[0].packageVerified `
        "$scenario guidance reflects whether a package was actually verified"
    Assert-Equal 'VerifiedAbsent' $summaries[0].packageAvailability `
        "$scenario does not claim its removed validation package remains available"
    $expectedRecipientAccess = if ($scenario -in @(
        'HistoricalOpening', 'MissingKey', 'OneRecipient'
    )) {
        'Unavailable'
    }
    else { 'None' }
    Assert-Equal $expectedRecipientAccess $summaries[0].resultSharingGuidance.recipientAccess `
        "$scenario guidance reflects actual recipient access"
    Assert-Equal $false $summaries[0].resultSharingGuidance.privateTransfer.allowed `
        "$scenario does not permit transfer after validation cleanup"
    Assert-Equal 'None' $summaries[0].resultSharingGuidance.deletionResponsibility `
        "$scenario assigns no deletion duty for artifacts already removed"
    Assert-Equal ($scenario -eq 'RestrictedExport') `
        $summaries[0].resultSharingGuidance.restrictedExport.completed `
        "$scenario guidance reflects actual restricted export completion"
    Assert-Equal $true $terminals[0].validationFixture `
        "$scenario cannot create a Product Capability claim"
    Assert-Equal ($before -join '|') ($after -join '|') `
        "$scenario leaves no generated-application validation residue"
    $serialized = $records[0] | ConvertTo-Json -Compress -Depth 10
    if ($serialized -match '(?i)"(?:profilePath|packagePath|reportPath|fingerprint|certificate|privateKey|pfx|password|credential|subject|issuer)"\s*:') {
        throw "$scenario exposed private paths, recipient identity, or key material."
    }
    if ($result.StandardError) { throw "$scenario wrote stderr: $($result.StandardError)" }
}
'@
    Assert-SharingControl ((Normalize-SharingBody $loop[0].Extent.Text.Replace('$candidateContext.Path','$candidatePath')) -ceq (Normalize-SharingBody $originalLoop)) 'All original twelve-case arguments, assertions, timing and sanitized-output checks are byte-for-byte preserved after candidate substitution.'
    $originalAssertions=@'
Assert-Equal 20 $untrustedSetup.ExitCode 'an unsigned development artifact cannot create a recipient identity'
Assert-Equal 'PREPARATION.INTEGRITY_FAILED' $untrustedSetup.Records[-1].reasonCode `
    'persistent setup is gated by external artifact trust'
Assert-Equal $false ([System.IO.File]::Exists($untrustedSetupPath)) `
    'the trust failure occurs before profile or certificate creation'
Assert-Equal 20 $blocked.ExitCode "$workflow retains generated-artifact trust admission"
Assert-Equal 'PREPARATION.INTEGRITY_FAILED' $blocked.Records[-1].reasonCode "$workflow cannot use an unsigned artifact to open private evidence"
Assert-Equal 1 $records.Count "$scenario emits one sanitized sharing result"
Assert-Equal 1 $summaries.Count "$scenario emits one actual Completion Summary"
Assert-Equal 1 $terminals.Count "$scenario emits one terminal result"
Assert-Equal 20 $result.ExitCode "$scenario validates with the stable fixture exit"
Assert-Equal 'Validated' $records[0].state "$scenario proves its expected safety behavior"
Assert-Equal $true $records[0].validationCleanupVerified `
        "$scenario removes every synthetic profile, package, export, and key handle"
Assert-Equal $true $records[0].completionGuidanceVerified `
        "$scenario retains all six Result-sharing Guidance topics"
Assert-Equal $expectedPackageVerified $summaries[0].packageVerified `
        "$scenario guidance reflects whether a package was actually verified"
Assert-Equal 'VerifiedAbsent' $summaries[0].packageAvailability `
        "$scenario does not claim its removed validation package remains available"
Assert-Equal $expectedRecipientAccess $summaries[0].resultSharingGuidance.recipientAccess `
        "$scenario guidance reflects actual recipient access"
Assert-Equal $false $summaries[0].resultSharingGuidance.privateTransfer.allowed `
        "$scenario does not permit transfer after validation cleanup"
Assert-Equal 'None' $summaries[0].resultSharingGuidance.deletionResponsibility `
        "$scenario assigns no deletion duty for artifacts already removed"
Assert-Equal ($scenario -eq 'RestrictedExport') `
        $summaries[0].resultSharingGuidance.restrictedExport.completed `
        "$scenario guidance reflects actual restricted export completion"
Assert-Equal $true $terminals[0].validationFixture `
        "$scenario cannot create a Product Capability claim"
Assert-Equal ($before -join '|') ($after -join '|') `
        "$scenario leaves no generated-application validation residue"
Assert-Equal $false ([System.IO.Directory]::Exists($recipientValidationRoot)) `
    'the generated application removes its validation root after the final case'
'@
    $actualAssertions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Assert-Equal'},$true))
    Assert-SharingControl ($actualAssertions.Count -eq 21 -and (Normalize-SharingBody ($actualAssertions.Extent.Text -join "`n")) -ceq (Normalize-SharingBody $originalAssertions)) 'All 21 original assertion forms, including unsigned setup and report trust refusal, are preserved exactly.'
    $imports=@($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.PipelineAst] -and $_.PipelineElements[0] -is [Management.Automation.Language.CommandAst] -and $_.PipelineElements[0].InvocationOperator -eq [Management.Automation.Language.TokenKind]::Dot })
    Assert-SharingControl ($imports.Count -eq 5) 'Only the original five harness/product imports are replaced in the replay.'
    $source=$ast.Extent.Text
    foreach($import in $imports){$source=$source.Replace($import.Extent.Text,'# Disclosed pure APIs; no product import.')}
    $source=$source.Replace('$repositoryRoot = Split-Path -Parent $PSScriptRoot','$repositoryRoot = $probe.repository')
    $tempExpression="Join-Path ([IO.Path]::GetTempPath()) 'WIN-PCInfo-recipient-sharing-validation'"
    Assert-SharingControl ([regex]::Matches($source,[regex]::Escape($tempExpression)).Count -eq 2) 'Exactly the fixed-root admission and residue reader TEMP expressions are redirected.'
    $source=$source.Replace($tempExpression,'$probe.fixedRoot')
    $replayTokens=$null;$replayErrors=$null
    $replayAst=[Management.Automation.Language.Parser]::ParseInput($source,$path,[ref]$replayTokens,[ref]$replayErrors)
    Assert-SharingControl ($replayErrors.Count -eq 0) 'Actual caller replay parses.'
    $control=$replayAst.GetScriptBlock()
    $cases=[Collections.Generic.List[object]]::new()
    foreach($prefix in @('Prepared','Standalone')){
        foreach($mode in @('Success','ForeignEmpty','ForeignResidue','ForeignFile')){$cases.Add(@{mode=$mode;prefix=$prefix;kind='';at=0})}
        foreach($kind in @('SetupFailure','CloseFailure','FixtureCleanupFailure')){$cases.Add(@{mode='Success';prefix=$prefix;kind=$kind;at=0})}
        $cases.Add(@{mode='Success';prefix=$prefix;kind='BodyAndClose';at=15})
        foreach($at in 1..15){$cases.Add(@{mode='Success';prefix=$prefix;kind='BodyFailure';at=$at})}
        foreach($at in @(1,4,15)){$cases.Add(@{mode='Success';prefix=$prefix;kind='UnsafeFailure';at=$at})}
        foreach($at in @(4,15)){$cases.Add(@{mode='Success';prefix=$prefix;kind='AssertionFailure';at=$at})}
    }
    foreach($mode in @('AdmissionRefuse','PartialCandidate','PartialManifest','BadDigest','ManifestFailure')){$cases.Add(@{mode=$mode;prefix=$(if($mode -eq 'ManifestFailure'){'Standalone'}else{'Prepared'});kind='';at=0})}
    foreach($prefix in @('Prepared','Standalone')){
        $cases.Add(@{mode='Success';prefix=$prefix;kind='CloseFailure';at=0;mutant=$true;mutantTarget='CandidateClose'})
        $cases.Add(@{mode='Success';prefix=$prefix;kind='FixtureCleanupFailure';at=0;mutant=$true;mutantTarget='FixtureFinalize'})
    }
    foreach($case in $cases){
        $caseRoot=Join-Path $controlRoot ('case-'+($controls+1));$repo=Join-Path $caseRoot 'repository'
        $null=[IO.Directory]::CreateDirectory((Join-Path $repo '.test-output'))
        $probe=[pscustomobject]@{repository=$repo;fixedRoot=(Join-Path $caseRoot 'fixed-validation');fixture=$null;mode=$case.mode;kind=$case.kind;at=$case.at;
            opens=0;closes=0;finalizers=0;setups=0;manifests=0;admission=$null;context=$null;closedContext=$null;closedBodyError=$null;
            calls=[Collections.Generic.List[object]]::new();events=[Collections.Generic.List[string]]::new();bodyFailure=[InvalidOperationException]::new('Disclosed pure sharing body failure.');closeFailure=[InvalidOperationException]::new('Disclosed pure sharing close failure.')}
        if($case.kind -eq 'UnsafeFailure'){$probe.bodyFailure.Data['OwnedCleanupUnverified']=$true}
        $foreign=Join-Path $repo '.test-output/untrusted-recipient-profile.json';$foreignBytes=[Text.Encoding]::UTF8.GetBytes('Foreign profile must remain untouched.')
        [IO.File]::WriteAllBytes($foreign,$foreignBytes)
        switch($case.mode){
            'ForeignEmpty' {$null=[IO.Directory]::CreateDirectory($probe.fixedRoot)}
            'ForeignResidue' {$null=[IO.Directory]::CreateDirectory($probe.fixedRoot);[IO.File]::WriteAllText((Join-Path $probe.fixedRoot 'foreign.txt'),'Foreign fixed-root residue.')}
            'ForeignFile' {[IO.File]::WriteAllText($probe.fixedRoot,'Foreign fixed-root file.')}
        }
        $parameters=if($case.prefix -eq 'Standalone'){@{}}else{@{CandidatePath=(Join-Path $caseRoot 'explicit.ps1');PreparedManifestPath=(Join-Path $caseRoot 'explicit.json');PreparedManifestSha256=('a'*64)}}
        switch($case.mode){
            'PartialCandidate' {$parameters.Remove('PreparedManifestPath');$parameters.Remove('PreparedManifestSha256')}
            'PartialManifest' {$parameters.Remove('CandidatePath');$parameters.Remove('PreparedManifestSha256')}
            'BadDigest' {$parameters.PreparedManifestSha256='invalid'}
        }
        $caseControl=$control
        $isMutant=$case.ContainsKey('mutant') -and $case.mutant
        if($isMutant){
            $finalizerLine=if($case.mutantTarget -eq 'CandidateClose'){'    try { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }'}else{'    Complete-QualificationHarness -BodyError $candidateUseError -Cleanup @({'}
            Assert-SharingControl ($source.Contains($finalizerLine)) 'Early-PASS mutant insertion binds the actual assigned finalizer seam.'
            $mutantSource=$source.Replace($finalizerLine,"    Write-Output 'PASS: Disclosed early success before failing finalizers.'"+[Environment]::NewLine+$finalizerLine)
            $mutantTokens=$null;$mutantErrors=$null
            $mutantAst=[Management.Automation.Language.Parser]::ParseInput($mutantSource,$path,[ref]$mutantTokens,[ref]$mutantErrors)
            Assert-SharingControl ($mutantErrors.Count -eq 0) 'Replay-only early-PASS mutant parses.'
            $caseControl=$mutantAst.GetScriptBlock()
        }
        $failure=$null;$output=[Collections.Generic.List[object]]::new()
        # An array assignment loses success records when a later command throws.
        # Record each success item as it arrives, including premature PASS text.
        try{
            & $caseControl @parameters | ForEach-Object {
                $output.Add($_)
                if($_ -like 'PASS:*'){$probe.events.Add('PASS')}
            }
        }catch{$failure=$_}
        $controls++;$recordedLeaves+=$probe.calls.Count
        Assert-SharingControl ([Convert]::ToBase64String([IO.File]::ReadAllBytes($foreign)) -ceq [Convert]::ToBase64String($foreignBytes)) 'Every replay preserves the preexisting foreign untrusted profile exactly.'
        Assert-SharingControl ($probe.opens -eq 1 -and $probe.admission[0] -ceq $repo) 'Candidate ownership opens once against the owning repository.'
        $refused=$case.mode -in @('AdmissionRefuse','PartialCandidate','PartialManifest','BadDigest')
        if($refused){Assert-SharingControl ($null -ne $failure -and $probe.closes -eq 0 -and $probe.finalizers -eq 0 -and $probe.calls.Count -eq 0 -and $null -eq $probe.fixture) 'Refused candidate never starts setup, application work or an unowned finalizer.';continue}
        Assert-SharingControl ($probe.closes -eq 1 -and $probe.finalizers -eq 1 -and [object]::ReferenceEquals($probe.closedContext,$probe.context) -and $probe.events.IndexOf('CandidateClose') -ge 0 -and $probe.events.IndexOf('FixtureFinalize') -gt $probe.events.IndexOf('CandidateClose')) 'Exact candidate closes before the single fixture finalizer.'
        Assert-SharingControl ($probe.manifests -eq $(if($case.prefix -eq 'Standalone'){1}else{0})) 'Standalone creates one manifest; prepared admission creates none.'
        if($case.prefix -eq 'Prepared'){Assert-SharingControl (($probe.admission[1..3] -join '|') -ceq (@($parameters.CandidatePath,$parameters.PreparedManifestPath,$parameters.PreparedManifestSha256) -join '|')) 'Prepared operands reach admission exactly.'}
        if($case.mode -like 'Foreign*'){
            Assert-SharingControl ($null -ne $failure -and $probe.calls.Count -eq 0 -and $probe.setups -eq 0 -and $null -eq $probe.fixture) 'A foreign fixed root refuses all fixture/setup/application work.'
            Assert-SharingControl ([IO.Directory]::Exists($probe.fixedRoot) -or [IO.File]::Exists($probe.fixedRoot)) 'Even an empty foreign fixed root is never removed.'
            if($case.mode -eq 'ForeignResidue'){Assert-SharingControl ([IO.File]::ReadAllText((Join-Path $probe.fixedRoot 'foreign.txt')) -ceq 'Foreign fixed-root residue.') 'Foreign fixed-root residue bytes are preserved.'}
            if($case.mode -eq 'ForeignFile'){Assert-SharingControl ([IO.File]::ReadAllText($probe.fixedRoot) -ceq 'Foreign fixed-root file.') 'Foreign fixed-root file bytes are preserved.'}
        }
        $expectedCalls=if($case.mode -eq 'ManifestFailure' -or $case.mode -like 'Foreign*'){0}elseif($case.kind -eq 'SetupFailure'){3}elseif($case.kind -in @('BodyFailure','UnsafeFailure','AssertionFailure','BodyAndClose')){$case.at}else{15}
        Assert-SharingControl ($probe.calls.Count -eq $expectedCalls) 'Original setup→two trust workflows→twelve scenarios stop at the exact failed boundary.'
        for($index=0;$index -lt $probe.calls.Count;$index++){
            $arguments=$probe.calls[$index].arguments
            if($index -eq 0){$expected=@('-Workflow','RecipientProfileSetup','-RecipientProfileOutputPath',(Join-Path $probe.fixture 'untrusted-recipient-profile.json'),'-RecipientLabel','Synthetic blocked setup','-ConfirmRecipientSetup')}
            elseif($index -lt 3){$expected=@('-Workflow',@('OpenReport','RestrictedReportExport')[$index-1],'-Mode','Gui','-PackageProtectionRoute','Recipient','-ProtectedPackagePath',(Join-Path $probe.fixture 'does-not-exist.winpcinfo'))}
            else{
                $scenario=$expectedScenarios[$index-3];$request=if($scenario -eq 'OneRecipient'){Join-Path $probe.fixture 'selected-request.json'}else{Join-Path $PSScriptRoot 'fixtures/automation-request.json'}
                $expected=@('-Mode','Automation','-RequestPath',$request,'-AcceptPreparation','-PreparationFixturePath',(Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'),'-RecipientSharingFixturePath',(Join-Path $PSScriptRoot ('fixtures/recipient-'+$scenario.ToLowerInvariant()+'.json')))
            }
            Assert-SharingControl (($arguments -join '|') -ceq ($expected -join '|')) 'Original application argv is preserved except explicit owned fixture path substitutions.'
        }
        $unsafe=$case.kind -in @('UnsafeFailure','CloseFailure','BodyAndClose','FixtureCleanupFailure')
        if($probe.fixture){Assert-SharingControl ([IO.Directory]::Exists($probe.fixture) -eq $unsafe) 'Unsafe body/close retains owned fixture evidence; safe success/body/setup failure removes it.'}
        if($unsafe){Assert-SharingControl ($null -ne $failure -and (Test-QualificationCleanupUnverified $failure.Exception) -and [IO.File]::Exists((Get-QualificationCleanupBlockerPath))) 'Unsafe fixture finalization retains the durable stop signal and unsafe exception.'}
        if($case.kind -in @('SetupFailure','BodyFailure','UnsafeFailure','BodyAndClose') -or $case.mode -eq 'ManifestFailure'){Assert-SharingControl ($null -ne $failure -and (Test-SharingContainsException $failure.Exception $probe.bodyFailure)) 'Original setup/manifest/body failure survives both finalizers.'}
        if($case.kind -in @('CloseFailure','BodyAndClose')){Assert-SharingControl (Test-SharingContainsException $failure.Exception $probe.closeFailure) 'Original close failure survives fixture finalization.'}
        $success=$case.mode -eq 'Success' -and $case.kind -eq ''
        $passFailure=$null
        try{Assert-SharingPassOrder -Output @($output.ToArray()) -Events @($probe.events.ToArray()) -Success $success -Failure $failure}catch{$passFailure=$_}
        if($isMutant){
            Assert-SharingControl ($null -ne $passFailure -and $passFailure.Exception.Data['EarlyPassDetected'] -eq $true -and @($output | Where-Object { $_ -like 'PASS:*' }).Count -eq 1 -and $probe.events.IndexOf('PASS') -ge 0 -and $probe.events.IndexOf('PASS') -lt $probe.events.IndexOf($case.mutantTarget)) 'Actual early PASS survives its assigned terminating finalizer failure and is rejected by the same normal-caller order guard.'
            if($case.mutantTarget -eq 'FixtureFinalize'){Assert-SharingControl ($probe.events.IndexOf('CandidateClosed') -lt $probe.events.IndexOf('PASS')) 'Fixture-finalizer mutant is independently observed after successful candidate close.'}
            $mutantOutcomes.Add([pscustomobject]@{admission=$case.prefix;target=$case.mutantTarget;events=@($probe.events.ToArray());passItems=@($output | Where-Object { $_ -like 'PASS:*' }).Count;terminatingFailureObserved=($null -ne $failure);rejected=$passFailure.Exception.Data['EarlyPassDetected']})
            $mutantsRejected++
        }elseif($null -ne $passFailure){throw $passFailure}
    }
    Assert-SharingControl ($mutantsRejected -eq 4) 'Prepared and standalone early-PASS mutants before each finalizer are rejected.'
}
finally {
    $resolved=[IO.Path]::GetFullPath($controlRoot)
    if(-not [IO.Path]::GetDirectoryName($resolved).Equals($ownedParent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -cnotmatch '^recipient-sharing-context-[a-f0-9]{32}$'){throw 'Pure fixture cleanup escaped its exact owned parent.'}
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
    if([IO.Directory]::Exists($resolved)){throw 'Pure fixture cleanup remains incomplete.'}
}
Write-Output ('PASS: {0} pure actual recipient-sharing caller controls; {1} recorded leaves; {2} early-PASS mutants rejected; foreign preservation, original twelve scenarios, typed candidate ownership and ordered unsafe finalizers; no partition/native acceptance.' -f $controls,$recordedLeaves,$mutantsRejected)
