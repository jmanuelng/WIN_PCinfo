[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$candidatePath = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
$requestPath = Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath = Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidatePath | Out-Null

$cases = @(
    @{name='identity-workgroup';scenario='Workgroup';exit=0;outcome='Completed';user='Complete';registration='Complete';workSchool='Complete';userFinding='ExpectedCondition';tasks=0;relation='SameUser'},
    @{name='identity-domainjoined';scenario='DomainJoined';exit=0;outcome='Completed';user='Complete';registration='Complete';workSchool='Complete';userFinding='ExpectedCondition';tasks=0;relation='SameUser'},
    @{name='identity-entrajoined';scenario='EntraJoined';exit=0;outcome='Completed';user='Complete';registration='Complete';workSchool='Complete';userFinding='ExpectedCondition';tasks=4;relation='SameUser'},
    @{name='identity-registered';scenario='Registered';exit=0;outcome='Completed';user='Complete';registration='Complete';workSchool='Complete';userFinding='ExpectedCondition';tasks=4;relation='SameUser'},
    @{name='identity-mixed';scenario='Mixed';exit=0;outcome='Completed';user='Complete';registration='Complete';workSchool='Complete';userFinding='ExpectedCondition';tasks=4;relation='SameUser'},
    @{name='identity-unenrolled';scenario='Unenrolled';exit=0;outcome='Completed';user='Complete';registration='Complete';workSchool='Complete';userFinding='ExpectedCondition';tasks=0;relation='SameUser'},
    @{name='identity-userunavailable';scenario='UserContextUnavailable';exit=10;outcome='CompletedWithGaps';user='Unavailable';registration='Complete';workSchool='Complete';userFinding='Indeterminate';tasks=0;relation='Unavailable'},
    @{name='identity-standarduser';scenario='StandardUser';exit=0;outcome='Completed';user='Complete';registration='Complete';workSchool='Complete';userFinding='ExpectedCondition';tasks=0;relation='SameUser'},
    @{name='identity-administrator';scenario='Administrator';exit=0;outcome='Completed';user='Complete';registration='Complete';workSchool='Complete';userFinding='ExpectedCondition';tasks=0;relation='AlternateAdministrator'},
    @{name='identity-localsystem';scenario='LocalSystem';exit=10;outcome='CompletedWithGaps';user='Denied';registration='Denied';workSchool='Denied';userFinding='Indeterminate';tasks=0;relation='ProhibitedProcessContext'},
    @{name='identity-nonenglish';scenario='NonEnglish';exit=0;outcome='Completed';user='Complete';registration='Complete';workSchool='Complete';userFinding='ExpectedCondition';tasks=4;relation='SameUser'},
    @{name='identity-malformed';scenario='Malformed';exit=10;outcome='CompletedWithGaps';user='Malformed';registration='Malformed';workSchool='Malformed';userFinding='Indeterminate';tasks=0;relation='Unavailable'},
    @{name='identity-denied';scenario='Denied';exit=10;outcome='CompletedWithGaps';user='Denied';registration='Denied';workSchool='Denied';userFinding='Indeterminate';tasks=0;relation='Unavailable'}
)

foreach($case in $cases){
    $result=Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
        '-PreparationFixturePath',$preparationPath,
        '-IdentityEnrollmentFixturePath',(Join-Path $PSScriptRoot "fixtures/$($case.name).json")
    )
    $validation=@($result.Records|Where-Object recordType -eq 'win-pcinfo.identity-enrollment-validation')
    $terminal=@($result.Records|Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $validation.Count "$($case.name) emits one sanitized identity projection"
    Assert-Equal 1 $terminal.Count "$($case.name) emits exactly one terminal result"
    Assert-Equal $case.exit $result.ExitCode "$($case.name) uses its stable exit code"
    Assert-Equal $case.outcome $terminal[0].outcome "$($case.name) preserves coverage in the run outcome"
    Assert-Equal $case.scenario $validation[0].scenario "$($case.name) preserves the closed scenario"
    Assert-Equal $case.relation $validation[0].processRelationship "$($case.name) separates process and Assessment User Context"
    Assert-Equal $case.user $validation[0].assessmentUserCoverageState "$($case.name) retains user-context coverage"
    Assert-Equal $case.registration $validation[0].registrationCoverageState "$($case.name) retains registration coverage"
    Assert-Equal $case.workSchool $validation[0].workSchoolCoverageState "$($case.name) retains work-school coverage"
    Assert-Equal 'Complete' $validation[0].systemEnrollmentCoverageState "$($case.name) uses only the predefined SYSTEM source"
    Assert-Equal $case.userFinding $validation[0].assessmentUserFindingOutcome "$($case.name) derives the bounded user-context finding"
    Assert-Equal $case.tasks $validation[0].tenantDiscoveryTaskCount "$($case.name) creates only tenant questions justified by local Entra context"
    Assert-Equal $true $validation[0].assessmentRecordValidated "$($case.name) produces one canonical record"
    Assert-Equal $true $validation[0].beginnerReportVerified "$($case.name) produces beginner identity guidance"
    Assert-Equal $true $validation[0].protectedPackageVerified "$($case.name) reopens the protected package"
    Assert-Equal $true $validation[0].validationCleanupVerified "$($case.name) proves run-owned residue absent"
    $stdout=$result.StandardOutput
    if($stdout -match '(?i)SYNTHETIC-DOMAIN|00000000-0000-4000-8000-00000000005|SYNTHETIC\\+assessment-user|assessment\.user@example\.invalid|DOMAINE-ÉQUIPE|utilisateur@exemple\.invalid'){
        throw "$($case.name) leaked a Restricted identifier into public output."
    }
    if($result.StandardError){throw "$($case.name) wrote stderr: $($result.StandardError)"}
}

Write-Output 'PASS: the generated application exercises all registration, enrollment, locale, source, and identity contexts.'
