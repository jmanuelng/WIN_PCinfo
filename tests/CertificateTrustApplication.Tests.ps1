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
    @{file='valid-trusted';scenario='ValidTrusted';coverage='Complete';count=1;validity='ExpectedCondition';trust='ExpectedCondition'},
    @{file='expired';scenario='Expired';coverage='Complete';count=1;validity='NeedsAttention';trust='ExpectedCondition'},
    @{file='not-yet-valid';scenario='NotYetValid';coverage='Complete';count=1;validity='NeedsAttention';trust='ExpectedCondition'},
    @{file='untrusted';scenario='Untrusted';coverage='Complete';count=1;validity='ExpectedCondition';trust='NeedsAttention'},
    @{file='incomplete-chain';scenario='IncompleteChain';coverage='Complete';count=1;validity='ExpectedCondition';trust='Indeterminate'},
    @{file='multiple-candidates';scenario='MultipleCandidates';coverage='Complete';count=2;validity='NeedsAttention';trust='NeedsAttention'},
    @{file='inaccessible-store';scenario='InaccessibleStore';coverage='Denied';count=0;validity='Indeterminate';trust='Indeterminate'},
    @{file='absent-purpose';scenario='AbsentPurpose';coverage='Complete';count=0;validity='NotApplicable';trust='NotApplicable'},
    @{file='non-exportable-key';scenario='NonExportableKey';coverage='Complete';count=1;validity='ExpectedCondition';trust='ExpectedCondition'},
    @{file='alternate-administrator';scenario='AlternateAdministrator';coverage='Denied';count=0;validity='Indeterminate';trust='Indeterminate'},
    @{file='virtual-device';scenario='VirtualDevice';coverage='Complete';count=1;validity='ExpectedCondition';trust='ExpectedCondition'},
    @{file='malformed-certificate';scenario='MalformedCertificate';coverage='Malformed';count=0;validity='Indeterminate';trust='Indeterminate'}
)
foreach($case in $cases){
    $result=Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
        '-PreparationFixturePath',$preparationPath,
        '-CertificateTrustFixturePath',(Join-Path $PSScriptRoot "fixtures/certificate-trust/$($case.file).json")
    )
    $validation=@($result.Records|Where-Object recordType -eq 'win-pcinfo.certificate-trust-validation')
    $deviceValidation=@($result.Records|Where-Object recordType -eq 'win-pcinfo.device-readiness-validation')
    $terminal=@($result.Records|Where-Object recordType -eq 'win-pcinfo.terminal')
    Assert-Equal 1 $validation.Count "$($case.scenario) emits one sanitized certificate projection"
    Assert-Equal 1 $terminal.Count "$($case.scenario) retains one terminal path"
    Assert-Equal 10 $result.ExitCode "$($case.scenario) preserves unrelated explicit Local Only gaps"
    Assert-Equal 'CompletedWithGaps' $terminal[0].outcome "$($case.scenario) does not hide coverage gaps"
    Assert-Equal $case.scenario $validation[0].scenario "$($case.scenario) crosses only the release-owned validation seam"
    Assert-Equal $case.coverage $validation[0].purposeCoverage "$($case.scenario) preserves purpose coverage"
    Assert-Equal $case.validity $validation[0].validityFinding "$($case.scenario) interprets validity separately"
    Assert-Equal $case.trust $validation[0].trustFinding "$($case.scenario) interprets chain and trust separately"
    Assert-Equal $case.count $validation[0].certificateCandidateCount "$($case.scenario) publishes only a candidate count"
    Assert-Equal $false $validation[0].certificateIdentifiersPublished "$($case.scenario) keeps values and fingerprints Restricted"
    Assert-Equal $false $validation[0].privateMaterialAccessed "$($case.scenario) never reads private material"
    Assert-Equal $false $validation[0].privateMaterialPublished "$($case.scenario) publishes no private material"
    Assert-Equal $false $validation[0].certificateStoreChanged "$($case.scenario) is read-only"
    if($case.scenario -eq 'VirtualDevice'){
        Assert-Equal 'Virtual' $validation[0].deviceContext `
            'the virtual prerequisite remains observable without changing certificate semantics'
        Assert-Equal 'Detected' $deviceValidation[0].virtualizationContext `
            'the validated canonical device evidence agrees that the certificate fixture is virtual'
    }
    Assert-Equal $true $validation[0].assessmentRecordValidated "$($case.scenario) enters the canonical Assessment Record"
    Assert-Equal $true $validation[0].beginnerReportVerified "$($case.scenario) derives the beginner report"
    Assert-Equal $true $validation[0].protectedPackageVerified "$($case.scenario) reopens the protected package"
    Assert-Equal $true $validation[0].validationCleanupVerified "$($case.scenario) leaves no validation artifact"
    if($result.StandardOutput -match '(?i)synthetic-(?:management|authentication|deviceidentity|codetrust|serviceconnectivity)-certificate-|A0[1-9]A0[1-9]A0[1-9]'){
        throw "$($case.scenario) leaked Restricted certificate evidence into public output."
    }
    if($result.StandardError){throw "$($case.scenario) wrote stderr: $($result.StandardError)"}
}

Write-Output 'PASS: the generated application proves purpose-bound certificate evidence and privacy.'
