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
    @{scenario='Workgroup';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='Domain';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='UserAndComputerRsop';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=3;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='MissingRsop';exit=10;outcome='CompletedWithGaps';applied='Unsupported';configured='Complete';control='Complete';count=0;appliedFinding='Indeterminate';localFinding='Informational';orderFinding='Indeterminate';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='StaleRegistry';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Partial';control='Complete';count=2;appliedFinding='Informational';localFinding='Indeterminate';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='DeniedAdministrator';exit=10;outcome='CompletedWithGaps';applied='Denied';configured='Denied';control='Denied';count=0;appliedFinding='Indeterminate';localFinding='Indeterminate';orderFinding='Indeterminate';securityFinding='Indeterminate';constraintFinding='Indeterminate';providers=0;firewalls=3;asr=0},
    @{scenario='DeniedSystem';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='NonEnglish';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='AppliedOrderConflict';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='NeedsAttention';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='AccountLockout';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='AuditPolicy';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='UserRights';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='SecurityOptions';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='PartialChannel';exit=10;outcome='CompletedWithGaps';applied='Partial';configured='Partial';control='Partial';count=8;appliedFinding='Indeterminate';localFinding='Indeterminate';orderFinding='Indeterminate';securityFinding='Indeterminate';constraintFinding='Indeterminate';providers=1;firewalls=3;asr=0;mdmFinding='Informational';channelFinding='ExpectedCondition';tasks=0},
    @{scenario='NonMdm';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0;mdmFinding='Indeterminate';channelFinding='Indeterminate';tasks=2},
    @{scenario='UnsupportedMdmBuild';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0;mdmFinding='Indeterminate';channelFinding='Indeterminate';tasks=2},
    @{scenario='MissingMdmClass';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0;mdmFinding='Indeterminate';channelFinding='Indeterminate';tasks=2},
    @{scenario='MissingMdmProperty';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0;mdmFinding='Indeterminate';channelFinding='Indeterminate';tasks=2},
    @{scenario='MdmPolicyConflict';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0;mdmFinding='Informational';channelFinding='NeedsAttention';tasks=2},
    @{scenario='MdmWinsOverGpScoped';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0;mdmFinding='Informational';channelFinding='ExpectedCondition';tasks=0},
    @{scenario='ThirdPartyRegistration';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='ExpectedCondition';providers=1;firewalls=3;asr=0},
    @{scenario='DefenderDisabled';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=0;firewalls=3;asr=0},
    @{scenario='DefenderUnavailable';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Partial';control='Partial';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Indeterminate';constraintFinding='Indeterminate';providers=1;firewalls=3;asr=0},
    @{scenario='AmbiguousSecurityCenter';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Complete';control='Partial';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Indeterminate';constraintFinding='Indeterminate';providers=2;firewalls=3;asr=0},
    @{scenario='TamperProtected';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='ExpectedCondition';providers=1;firewalls=3;asr=0},
    @{scenario='MissingDefenderProperty';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Complete';control='Partial';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Indeterminate';constraintFinding='Indeterminate';providers=1;firewalls=3;asr=0},
    @{scenario='FirewallProfiles';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='AsrRulePairs';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=2}
)

foreach($case in $cases){
    if(-not $case.ContainsKey('mdmFinding')){
        $case.mdmFinding='Informational';$case.channelFinding='ExpectedCondition';$case.tasks=0
    }
    if($case.scenario -in @('StaleRegistry','DeniedAdministrator','PartialChannel')){
        $case.channelFinding='Indeterminate';$case.tasks=2
    }
    if($case.scenario -eq 'SecurityOptions'){
        $case.channelFinding='NeedsAttention';$case.tasks=2
    }
    if($case.scenario -eq 'DeniedSystem'){
        $case.mdmFinding='Indeterminate';$case.channelFinding='Indeterminate';$case.tasks=2
    }
}

foreach($case in $cases){
    $fixtureName=($case.scenario.ToLowerInvariant())
    $fixture=Join-Path $PSScriptRoot "fixtures/effective-policy-$fixtureName.json"
    $result=Invoke-GeneratedApplication -CandidatePath $candidatePath -Arguments @(
        '-Mode','Automation','-RequestPath',$requestPath,'-AcceptPreparation',
        '-PreparationFixturePath',$preparationPath,'-EffectivePolicyFixturePath',$fixture
    )
    $validation=@($result.Records|Where-Object recordType -eq 'win-pcinfo.effective-policy-validation')
    $terminal=@($result.Records|Where-Object recordType -eq 'win-pcinfo.terminal')
    $progress=@($result.Records|Where-Object {
        $_.recordType -eq 'win-pcinfo.progress' -and $_.messageId -eq 'effective-policy.collection.started'
    })
    Assert-Equal 1 $validation.Count "$($case.scenario) emits one sanitized policy projection"
    Assert-Equal 1 $terminal.Count "$($case.scenario) emits exactly one terminal"
    Assert-Equal 1 $progress.Count "$($case.scenario) emits identifier-free progress"
    Assert-Equal 'EffectivePolicy' $progress[0].completion.unit "$($case.scenario) progress names only the slice"
    Assert-Equal $case.exit $result.ExitCode "$($case.scenario) uses its stable exit code"
    Assert-Equal $case.outcome $terminal[0].outcome "$($case.scenario) preserves coverage in the terminal"
    Assert-Equal $case.applied $validation[0].appliedPolicyCoverage "$($case.scenario) keeps Applied Policy Evidence distinct"
    Assert-Equal $case.configured $validation[0].configuredSignalCoverage "$($case.scenario) keeps configured signals distinct"
    Assert-Equal $case.control $validation[0].currentControlCoverage "$($case.scenario) keeps Current Control State distinct"
    Assert-Equal $case.count $validation[0].appliedPolicyCount "$($case.scenario) publishes only a safe policy count"
    Assert-Equal $case.appliedFinding $validation[0].appliedPolicyFinding "$($case.scenario) derives the applied-evidence finding"
    Assert-Equal $case.localFinding $validation[0].localSecurityFinding "$($case.scenario) derives the local-policy finding"
    Assert-Equal $case.orderFinding $validation[0].appliedOrderFinding "$($case.scenario) derives the precedence finding"
    Assert-Equal $case.securityFinding $validation[0].securityControlFinding "$($case.scenario) derives the security-control coverage finding"
    Assert-Equal $case.constraintFinding $validation[0].securityControlConstraintFinding "$($case.scenario) reports constraints separately from generic failure"
    Assert-Equal $case.providers $validation[0].antivirusProviderCount "$($case.scenario) publishes only a safe antivirus-provider count"
    Assert-Equal $case.firewalls $validation[0].firewallProfileCount "$($case.scenario) publishes only the bounded firewall profile count"
    Assert-Equal $case.asr $validation[0].asrRuleCount "$($case.scenario) publishes only a safe ASR rule count"
    Assert-Equal $case.mdmFinding $validation[0].mdmPolicyCspFinding "$($case.scenario) derives the MDM coverage finding"
    Assert-Equal $case.channelFinding $validation[0].policyCspGpoConflictFinding "$($case.scenario) does not guess a winning channel"
    Assert-Equal $case.tasks $validation[0].policyDiscoveryTaskCount "$($case.scenario) emits only frozen discovery tasks"
    Assert-Equal $true $validation[0].directRightsOnly "$($case.scenario) does not expand assigned groups"
    Assert-Equal $true $validation[0].localSamOnly "$($case.scenario) does not call local SAM state domain policy"
    Assert-Equal $false $validation[0].policyIdentifiersPublished "$($case.scenario) keeps policy identifiers restricted"
    Assert-Equal $false $validation[0].policyValuesPublished "$($case.scenario) keeps configured values restricted"
    Assert-Equal $false $validation[0].policyStateChanged "$($case.scenario) performs no policy mutation"
    Assert-Equal $false $validation[0].policyRefreshAttempted "$($case.scenario) never refreshes policy"
    Assert-Equal $false $validation[0].toolInstalled "$($case.scenario) installs no policy tool"
    Assert-Equal $true $validation[0].assessmentRecordValidated "$($case.scenario) validates the combined canonical record"
    Assert-Equal $true $validation[0].beginnerReportVerified "$($case.scenario) creates three-layer beginner guidance"
    Assert-Equal $true $validation[0].protectedPackageVerified "$($case.scenario) reopens the protected package"
    Assert-Equal $true $validation[0].validationCleanupVerified "$($case.scenario) proves validation residue absent"
    if($result.StandardOutput -match '(?i)6ac1786c|7f7d1f60|LocalGPO|synthetic-(?:domain|user|computer)-link|local-machine|bounded-link-[0-9]+|registry:(?:[0-9a-f-]{36}|bounded-setting-[0-9]+)|S-1-5-(?:18|19|20|21-[0-9-]+|32-54[46])'){
        throw "$($case.scenario) leaked Restricted policy evidence into public output."
    }
    if($result.StandardError){throw "$($case.scenario) wrote stderr: $($result.StandardError)"}
}

Write-Output 'PASS: the generated application exercises three-layer policy evidence, findings, privacy, packaging, and cleanup.'
