[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$candidatePath=Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath=Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath=Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath|Out-Null
$cases=@(
    @{scenario='LocalPrincipal';exit=0;outcome='Completed';coverage='Complete';complete=$true;count=2;groups=0;unresolved=0;duplicates=0;finding='Informational';relationship='SelectedAdministrator'},
    @{scenario='DomainPrincipal';exit=0;outcome='Completed';coverage='Complete';complete=$true;count=2;groups=1;unresolved=0;duplicates=0;finding='Informational';relationship='SelectedAdministrator'},
    @{scenario='NestedGroup';exit=0;outcome='Completed';coverage='Complete';complete=$true;count=2;groups=1;unresolved=0;duplicates=0;finding='Informational';relationship='SelectedAdministrator'},
    @{scenario='UnresolvedSid';exit=0;outcome='Completed';coverage='Complete';complete=$true;count=2;groups=0;unresolved=1;duplicates=0;finding='Informational';relationship='SelectedAdministrator'},
    @{scenario='DuplicateMembership';exit=0;outcome='Completed';coverage='Complete';complete=$true;count=2;groups=0;unresolved=0;duplicates=1;finding='Informational';relationship='SelectedAdministrator'},
    @{scenario='AlternateAdministrator';exit=0;outcome='Completed';coverage='Complete';complete=$true;count=2;groups=0;unresolved=0;duplicates=0;finding='Informational';relationship='AlternateAdministrator'},
    @{scenario='Denied';exit=10;outcome='CompletedWithGaps';coverage='Denied';complete=$false;count=0;groups=0;unresolved=0;duplicates=0;finding='Indeterminate';relationship='SelectedAdministrator'},
    @{scenario='Partial';exit=10;outcome='CompletedWithGaps';coverage='Partial';complete=$false;count=2;groups=1;unresolved=0;duplicates=0;finding='Indeterminate';relationship='SelectedAdministrator'},
    @{scenario='NonEnglish';exit=0;outcome='Completed';coverage='Complete';complete=$true;count=2;groups=1;unresolved=0;duplicates=0;finding='Informational';relationship='SelectedAdministrator'},
    @{scenario='ElevationDenied';exit=10;outcome='CompletedWithGaps';coverage='Denied';complete=$false;count=0;groups=0;unresolved=0;duplicates=0;finding='Indeterminate';relationship='NotStarted'}
)

foreach($case in $cases){
    $fixture=Join-Path $PSScriptRoot "fixtures/administrator-$($case.scenario.ToLowerInvariant()).json"
    $result=Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
        '-PreparationFixturePath',$preparationPath,'-AdministratorExposureFixturePath',$fixture
    )
    $validation=@($result.Records|Where-Object recordType -eq 'win-pcinfo.local-privilege-validation')
    $terminal=@($result.Records|Where-Object recordType -eq 'win-pcinfo.terminal')
    $progress=@($result.Records|Where-Object {
        $_.recordType -eq 'win-pcinfo.progress' -and
        $_.messageId -eq 'administrator-exposure.collection.started'
    })
    Assert-Equal 1 $validation.Count "$($case.scenario) emits one sanitized administrator projection"
    Assert-Equal 1 $terminal.Count "$($case.scenario) emits exactly one terminal"
    Assert-Equal 1 $progress.Count "$($case.scenario) exposes one identifier-free collection progress event"
    Assert-Equal 'AdministratorExposure' $progress[0].completion.unit `
        "$($case.scenario) keeps progress on the bounded slice rather than a principal"
    Assert-Equal $case.exit $result.ExitCode "$($case.scenario) returns its stable exit code"
    Assert-Equal $case.outcome $terminal[0].outcome "$($case.scenario) retains honest run coverage"
    Assert-Equal $case.scenario $validation[0].scenario "$($case.scenario) retains the closed scenario"
    Assert-Equal $case.coverage $validation[0].coverageState "$($case.scenario) keeps membership coverage explicit"
    Assert-Equal $case.complete $validation[0].enumerationComplete "$($case.scenario) cannot confuse gaps with an empty group"
    Assert-Equal $case.count $validation[0].directMemberCount "$($case.scenario) reports only a safe aggregate count"
    Assert-Equal $case.groups $validation[0].directGroupCount "$($case.scenario) preserves nested groups without expanding them"
    Assert-Equal $case.unresolved $validation[0].unresolvedPrincipalCount "$($case.scenario) keeps unresolved identities explicit"
    Assert-Equal $case.duplicates $validation[0].duplicateEntriesRemoved "$($case.scenario) de-duplicates direct SID membership"
    Assert-Equal $case.finding $validation[0].findingOutcome "$($case.scenario) derives one bounded advisory finding"
    Assert-Equal $case.relationship $validation[0].processRelationship "$($case.scenario) separates worker and Assessment User contexts"
    Assert-Equal $false $validation[0].nestedExpansionAttempted "$($case.scenario) never guesses nested effective access"
    Assert-Equal $true $validation[0].assessmentUserContextPreserved "$($case.scenario) preserves the Assessment User Context"
    Assert-Equal $true $validation[0].localPackageProtectorPreserved "$($case.scenario) preserves user-scoped package ownership"
    Assert-Equal $true $validation[0].assessmentRecordValidated "$($case.scenario) creates one canonical record"
    Assert-Equal $true $validation[0].beginnerReportVerified "$($case.scenario) creates beginner evidence-limit guidance"
    Assert-Equal $true $validation[0].protectedPackageVerified "$($case.scenario) reopens the protected package"
    Assert-Equal $true $validation[0].validationCleanupVerified "$($case.scenario) proves run-owned residue absent"
    Assert-Equal $false $validation[0].identityStateChanged "$($case.scenario) never modifies group membership"
    if($result.StandardOutput -match '(?i)S-1-5-|SYNTHETIC\\(?:local-admin|built-in-admin)|SYNTHETIC-DOMAIN\\|DOMAINE-ÉQUIPE\\|ÉQUIPE\\administrateur'){
        throw "$($case.scenario) leaked Restricted principal evidence into public output."
    }
    if($result.StandardError){throw "$($case.scenario) wrote stderr: $($result.StandardError)"}
}

Write-Output 'PASS: the generated application exercises direct administrator membership, context separation, privacy, packaging, and cleanup.'
