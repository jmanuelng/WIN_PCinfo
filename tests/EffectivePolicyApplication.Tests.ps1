[CmdletBinding()]
param(
    [string[]] $Scenario = @(),
    [string] $CandidatePath,
    [string] $PreparedManifestPath,
    [string] $PreparedManifestSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$requestPath=Join-Path $PSScriptRoot 'fixtures/automation-request.json'
$preparationPath=Join-Path $PSScriptRoot 'fixtures/preparation-ready.json'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

function Get-EffectivePolicyPrivacyDiagnostic {
    param([string] $Scenario, [string] $StandardOutput, [string] $Pattern)
    $records=[Collections.Generic.List[object]]::new()
    $recordOrdinal=0
    foreach ($line in [regex]::Matches($StandardOutput, '(?m)^[^\r\n]+')) {
        $lineMatches=@([regex]::Matches($line.Value, $Pattern))
        if ($lineMatches.Count) {
            $record=$line.Value | ConvertFrom-Json -Depth 20
            $paths=[Collections.Generic.List[object]]::new()
            function Add-PrivacyPropertyPaths($Value, [string] $Path) {
                if ($Value -is [pscustomobject]) {
                    foreach ($property in $Value.PSObject.Properties) {
                        $propertyPath=$Path+'['+($property.Name | ConvertTo-Json -Compress)+']'
                        $nameMatches=@([regex]::Matches(($property.Name | ConvertTo-Json -Compress), $Pattern))
                        if ($nameMatches.Count) {
                            $paths.Add([ordered]@{path=$propertyPath;kind='PropertyName';matches=@($nameMatches | ForEach-Object Value)})
                        }
                        Add-PrivacyPropertyPaths -Value $property.Value -Path $propertyPath
                    }
                }
                elseif ($Value -is [array]) {
                    for ($index=0; $index -lt $Value.Count; $index++) {
                        Add-PrivacyPropertyPaths -Value $Value[$index] -Path ($Path+'['+$index+']')
                    }
                }
                else {
                    $encoded=ConvertTo-Json -InputObject $Value -Compress -Depth 20
                    $valueMatches=@([regex]::Matches($encoded, $Pattern))
                    if ($valueMatches.Count) {
                        $paths.Add([ordered]@{path=$Path;kind='Value';matches=@($valueMatches | ForEach-Object Value)})
                    }
                }
            }
            Add-PrivacyPropertyPaths -Value $record -Path '$'
            $typeProperty=$record.PSObject.Properties['recordType']
            $records.Add([ordered]@{
                recordOrdinal=$recordOrdinal
                recordType=$(if ($null -ne $typeProperty) { $typeProperty.Value } else { $null })
                rawPublicRecord=$line.Value
                exactMatches=@($lineMatches | ForEach-Object {
                    [ordered]@{value=$_.Value;recordOffset=$_.Index;stdoutOffset=$line.Index+$_.Index;length=$_.Length}
                })
                propertyPaths=$paths.ToArray()
            })
        }
        $recordOrdinal++
    }
    [pscustomobject][ordered]@{
        kind='PrivateEffectivePolicyPublicOutputPrivacyDiagnostic'
        scenario=$Scenario
        stdoutSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($StandardOutput))).ToLowerInvariant()
        matchingPublicRecords=$records.ToArray()
        diagnosticOnly=$true
    }
}

function Test-EffectivePolicyPublicOutputPrivacy {
    param([string] $StandardOutput, [string] $Pattern)
    # All original non-port alternatives retain their raw-output scope. Port
    # digits may occur in public metadata, so only exact owner/path/type/shape
    # exceptions apply; unknown fields and property names stay fail-closed.
    $portAlternatives='|5985|5986|'
    if ([regex]::Matches($Pattern,[regex]::Escape($portAlternatives)).Count -ne 1) {
        throw 'Policy privacy port alternatives changed.'
    }
    if ($StandardOutput -match $Pattern.Replace($portAlternatives,'|')) { return $true }
    $policyCountNames=@('appliedPolicyCount','auditCatalogCount','userRightCatalogCount',
        'securityOptionCatalogCount','antivirusProviderCount','firewallProfileCount',
        'asrRuleCount','bitLockerProtectorTypeCount','wdacPolicyCount',
        'appLockerGpCollectionCount','appLockerCspCollectionCount')
    foreach ($line in [regex]::Matches($StandardOutput,'(?m)^[^\r\n]+')) {
        if ($line.Value -notmatch '5985|5986') { continue }
        try { $record=ConvertFrom-Json -InputObject $line.Value -Depth 20 -DateKind String }
        catch { return $true }
        $typeProperty=$record.PSObject.Properties['recordType']
        $versionProperty=$record.PSObject.Properties['contractVersion']
        $type=$(if ($null -ne $typeProperty) { [string]$typeProperty.Value } else { '' })
        $knownVersion=$null -ne $versionProperty -and $versionProperty.Value -ceq '1.0.0'
        $counterPaths=@()
        $digestPaths=@()
        if ($knownVersion -and $type -ceq 'win-pcinfo.progress') {
            $counterPaths=@('$["sequence"]','$["completion"]["completedUnits"]','$["completion"]["totalUnits"]')
        }
        elseif ($knownVersion -and $type -ceq 'win-pcinfo.effective-policy-validation') {
            $counterPaths=@($policyCountNames | ForEach-Object { '$["'+$_+'"]' })
        }
        elseif ($knownVersion -and $type -ceq 'win-pcinfo.terminal') {
            $digestPaths=@('$["requestDigest"]','$["planDigest"]')
        }
        elseif ($knownVersion -and $type -ceq 'win-pcinfo.preparation-summary') {
            $digestPaths=@('$["requestDigest"]','$["planDigest"]','$["plan"]["requestDigest"]',
                '$["plan"]["network"]["context"]["snapshotDigest"]',
                '$["plan"]["integrity"]["embeddedDefinitionSha256"]',
                '$["plan"]["integrity"]["applicationManifestSha256"]')
        }
        $state=[pscustomobject]@{rejected=$false}
        function Test-PrivacyPortProperty($Value, [string] $Path) {
            if ($Value -is [pscustomobject]) {
                foreach ($property in $Value.PSObject.Properties) {
                    if ($property.Name -match '5985|5986') { $state.rejected=$true }
                    Test-PrivacyPortProperty -Value $property.Value -Path ($Path+'['+($property.Name | ConvertTo-Json -Compress)+']')
                }
            }
            elseif ($Value -is [array]) {
                for ($index=0; $index -lt $Value.Count; $index++) {
                    Test-PrivacyPortProperty -Value $Value[$index] -Path ($Path+'['+$index+']')
                }
            }
            elseif ((ConvertTo-Json -InputObject $Value -Compress -Depth 20) -match '5985|5986') {
                $allowed=$false
                if ($counterPaths -ccontains $Path -and ($Value -is [int] -or $Value -is [long]) -and $Value -ge 0) {
                    $allowed=$true
                }
                elseif (($digestPaths -ccontains $Path -or ($knownVersion -and $type -ceq 'win-pcinfo.preparation-summary' -and
                    $Path -cmatch '^\$\["plan"\]\[(?:"governingResources"|"integrity"\]\["applicationResources")\]\[[0-9]+\]\["sha256"\]$')) -and
                    $Value -is [string] -and $Value -cmatch '^[0-9a-f]{64}$') {
                    $allowed=$true
                }
                elseif ($knownVersion -and $type -ceq 'win-pcinfo.progress' -and $Path -ceq '$["time"]' -and
                    $Value -is [string] -and $Value -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}[+-]\d{2}:\d{2}$') {
                    $parsedTime=[DateTimeOffset]::MinValue
                    $allowed=[DateTimeOffset]::TryParseExact($Value,'o',[Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::None,[ref]$parsedTime)
                }
                if (-not $allowed) { $state.rejected=$true }
            }
        }
        Test-PrivacyPortProperty -Value $record -Path '$'
        if ($state.rejected) { return $true }
    }
    return $false
}

$candidateContext=Open-TestCandidate -RepositoryRoot $repositoryRoot -CandidatePath $CandidatePath `
    -PreparedManifestPath $PreparedManifestPath -PreparedManifestSha256 $PreparedManifestSha256
$candidatePath=$candidateContext.Path
$candidateUseError=$null
try {
$cases=@(
    @{scenario='Workgroup';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='Domain';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='UserAndComputerRsop';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=3;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='MissingRsop';exit=10;outcome='CompletedWithGaps';applied='Unsupported';configured='Complete';control='Complete';count=0;appliedFinding='Indeterminate';localFinding='Informational';orderFinding='Indeterminate';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='StaleRegistry';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Partial';control='Complete';count=2;appliedFinding='Informational';localFinding='Indeterminate';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='DeniedAdministrator';exit=10;outcome='CompletedWithGaps';applied='Denied';configured='Denied';control='Denied';count=0;appliedFinding='Indeterminate';localFinding='Indeterminate';orderFinding='Indeterminate';securityFinding='Indeterminate';constraintFinding='Indeterminate';providers=0;firewalls=3;asr=0},
    @{scenario='DeniedSystem';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Indeterminate';constraintFinding='Informational';providers=1;firewalls=3;asr=0;appLockerCsp=0},
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
    @{scenario='WindowsUpdatePolicy';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='RemoteManagementCombinations';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='SmbPosture';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='LegacyAuthMasks';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=2;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='ThirdPartyRegistration';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='ExpectedCondition';providers=1;firewalls=3;asr=0},
    @{scenario='DefenderDisabled';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=0;firewalls=3;asr=0},
    @{scenario='DefenderUnavailable';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Partial';control='Partial';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Indeterminate';constraintFinding='Indeterminate';providers=1;firewalls=3;asr=0},
    @{scenario='AmbiguousSecurityCenter';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Complete';control='Partial';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Indeterminate';constraintFinding='Indeterminate';providers=2;firewalls=3;asr=0},
    @{scenario='TamperProtected';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='ExpectedCondition';providers=1;firewalls=3;asr=0},
    @{scenario='MissingDefenderProperty';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Complete';control='Partial';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Indeterminate';constraintFinding='Indeterminate';providers=1;firewalls=3;asr=0},
    @{scenario='FirewallProfiles';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='AsrRulePairs';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=2},
    @{scenario='BitLockerEncrypted';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='ExpectedCondition';providers=1;firewalls=3;asr=0;bitlockerProtectors=2},
    @{scenario='BitLockerUnencrypted';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0;bitlockerProtectors=0},
    @{scenario='BitLockerUnknown';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Complete';control='Partial';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Indeterminate';constraintFinding='Indeterminate';providers=1;firewalls=3;asr=0;bitlockerProtectors=0},
    @{scenario='VbsCredentialGuardRunning';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='VbsConfiguredNotRunning';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0},
    @{scenario='WdacWindows11Policies';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0;wdacPolicies=2},
    @{scenario='WdacWindows10Unsupported';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Partial';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Indeterminate';constraintFinding='Informational';providers=1;firewalls=3;asr=0;wdacPolicies=0},
    @{scenario='AppLockerGpOnly';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0;appLockerGp=1;appLockerCsp=0},
    @{scenario='AppLockerCspOnly';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0;appLockerGp=0;appLockerCsp=1},
    @{scenario='AppLockerGpCspConflict';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='Informational';providers=1;firewalls=3;asr=0;channelFinding='NeedsAttention';tasks=2;appLockerGp=1;appLockerCsp=1},
    @{scenario='AppLockerChannelIncomplete';exit=10;outcome='CompletedWithGaps';applied='Complete';configured='Partial';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Indeterminate';constraintFinding='Informational';providers=1;firewalls=3;asr=0;channelFinding='Indeterminate';tasks=2;appLockerGp=1;appLockerCsp=0},
    @{scenario='VirtualMachineSecurity';exit=0;outcome='Completed';applied='Complete';configured='Complete';control='Complete';count=1;appliedFinding='Informational';localFinding='Informational';orderFinding='ExpectedCondition';securityFinding='Informational';constraintFinding='ExpectedCondition';providers=1;firewalls=3;asr=0;bitlockerProtectors=1}
)

if ($Scenario.Count -gt 0) {
    foreach ($name in $Scenario) {
        if ($name -notin $cases.scenario) { throw "Unknown policy application scenario: $name" }
    }
    $cases=@($cases | Where-Object scenario -in $Scenario)
}

foreach($case in $cases){
    if(-not $case.ContainsKey('mdmFinding')){$case.mdmFinding='Informational'}
    if(-not $case.ContainsKey('channelFinding')){$case.channelFinding='ExpectedCondition'}
    if(-not $case.ContainsKey('tasks')){$case.tasks=0}
    if($case.scenario -in @('StaleRegistry','DeniedAdministrator','PartialChannel')){
        $case.channelFinding='Indeterminate';$case.tasks=2
    }
    if($case.scenario -eq 'SecurityOptions'){
        $case.channelFinding='NeedsAttention';$case.tasks=2
    }
    if($case.scenario -in @('DeniedAdministrator','DeniedSystem')){
        $case.mdmFinding='Indeterminate';$case.channelFinding='Indeterminate';$case.tasks=2
    }
}

$applicationEvidence=[Collections.Generic.List[object]]::new()
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
    Assert-Equal $true $validation[0].PSObject.Properties.Name.Contains('bitLockerProtectorTypeCount') "$($case.scenario) projects a safe BitLocker protector count"
    Assert-Equal $true $validation[0].PSObject.Properties.Name.Contains('wdacPolicyCount') "$($case.scenario) projects a safe WDAC policy count"
    Assert-Equal $true $validation[0].PSObject.Properties.Name.Contains('appLockerGpCollectionCount') "$($case.scenario) projects a safe AppLocker GP count"
    Assert-Equal $true $validation[0].PSObject.Properties.Name.Contains('appLockerCspCollectionCount') "$($case.scenario) projects a safe AppLocker CSP count"
    Assert-Equal $true $validation[0].PSObject.Properties.Name.Contains('windowsUpdateSignalCoverage') "$($case.scenario) projects Windows Update signal coverage without values"
    Assert-Equal $true $validation[0].PSObject.Properties.Name.Contains('remoteManagementCoverage') "$($case.scenario) projects remote-management coverage without listener details"
    Assert-Equal $true $validation[0].PSObject.Properties.Name.Contains('smbCoverage') "$($case.scenario) projects SMB coverage without share or session detail"
    Assert-Equal $true $validation[0].PSObject.Properties.Name.Contains('legacyAuthenticationCoverage') "$($case.scenario) projects legacy-auth coverage without masks"
    Assert-Equal $case.mdmFinding $validation[0].mdmPolicyCspFinding "$($case.scenario) derives the MDM coverage finding"
    Assert-Equal $case.channelFinding $validation[0].policyCspGpoConflictFinding "$($case.scenario) does not guess a winning channel"
    Assert-Equal $case.tasks $validation[0].policyDiscoveryTaskCount "$($case.scenario) emits only frozen discovery tasks"
    if($case.ContainsKey('bitlockerProtectors')){
        Assert-Equal $case.bitlockerProtectors $validation[0].bitLockerProtectorTypeCount "$($case.scenario) publishes only the safe BitLocker protector-type count"
    }
    if($case.ContainsKey('wdacPolicies')){
        Assert-Equal $case.wdacPolicies $validation[0].wdacPolicyCount "$($case.scenario) publishes only the safe WDAC policy count"
    }
    if($case.ContainsKey('appLockerGp')){
        Assert-Equal $case.appLockerGp $validation[0].appLockerGpCollectionCount "$($case.scenario) publishes only the safe AppLocker GP collection count"
    }
    if($case.ContainsKey('appLockerCsp')){
        Assert-Equal $case.appLockerCsp $validation[0].appLockerCspCollectionCount "$($case.scenario) publishes only the safe AppLocker CSP collection count"
    }
    Assert-Equal $true $validation[0].directRightsOnly "$($case.scenario) does not expand assigned groups"
    Assert-Equal $true $validation[0].localSamOnly "$($case.scenario) does not call local SAM state domain policy"
    Assert-Equal $false $validation[0].policyIdentifiersPublished "$($case.scenario) keeps policy identifiers restricted"
    Assert-Equal $false $validation[0].policyValuesPublished "$($case.scenario) keeps configured values restricted"
    Assert-Equal $false $validation[0].bitLockerSecretsPublished "$($case.scenario) keeps BitLocker recovery material restricted"
    Assert-Equal $false $validation[0].applicationControlPoliciesPublished "$($case.scenario) keeps App Control policy payloads restricted"
    Assert-Equal $false $validation[0].updateScanAttempted "$($case.scenario) never initiates an update scan"
    Assert-Equal $false $validation[0].remoteReachabilityTested "$($case.scenario) never turns configuration into a reachability probe"
    Assert-Equal $false $validation[0].smbSharesEnumerated "$($case.scenario) never enumerates SMB shares in this slice"
    Assert-Equal $false $validation[0].smbSessionsEnumerated "$($case.scenario) never enumerates SMB sessions in this slice"
    Assert-Equal $false $validation[0].legacyProtocolUseInferred "$($case.scenario) never infers legacy protocol use from configuration alone"
    Assert-Equal $false $validation[0].policyStateChanged "$($case.scenario) performs no policy mutation"
    Assert-Equal $false $validation[0].policyRefreshAttempted "$($case.scenario) never refreshes policy"
    Assert-Equal $false $validation[0].toolInstalled "$($case.scenario) installs no policy tool"
    Assert-Equal $true $validation[0].assessmentRecordValidated "$($case.scenario) validates the combined canonical record"
    Assert-Equal $true $validation[0].beginnerReportVerified "$($case.scenario) creates three-layer beginner guidance"
    Assert-Equal $true $validation[0].protectedPackageVerified "$($case.scenario) reopens the protected package"
    Assert-Equal $true $validation[0].validationCleanupVerified "$($case.scenario) proves validation residue absent"
    $policyPrivacyPattern='(?i)6ac1786c|7f7d1f60|LocalGPO|synthetic-(?:domain|user|computer)-link|local-machine|bounded-link-[0-9]+|registry:(?:[0-9a-f-]{36}|bounded-setting-[0-9]+)|S-1-5-(?:18|19|20|21-[0-9-]+|32-54[46])|RecoveryPassword|NumericalPassword|TpmPin|XtsAes(?:128|256)?|PolicyXml|RuleCollectionXml|5985|5986|DisableDualScan|NtlmMin(?:Client|Server)Sec'
    if(Test-EffectivePolicyPublicOutputPrivacy -StandardOutput $result.StandardOutput -Pattern $policyPrivacyPattern){
        $privacyFailure=[InvalidOperationException]::new("$($case.scenario) leaked Restricted policy evidence into public output.")
        if ($env:WINPCINFO_TEST_EVIDENCE) {
            try {
                $diagnostic=Get-EffectivePolicyPrivacyDiagnostic -Scenario $case.scenario -StandardOutput $result.StandardOutput -Pattern $policyPrivacyPattern
                $diagnosticPath=Join-Path $env:WINPCINFO_TEST_EVIDENCE ('effective-policy-private-privacy-'+[guid]::NewGuid().ToString('N')+'.json')
                [IO.File]::WriteAllText($diagnosticPath,($diagnostic | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
            }
            catch {
                # Never echo a failing serializer's input or a private path.
                throw [AggregateException]::new('Policy privacy assertion and private diagnostic retention failed.',
                    [Exception[]]@($privacyFailure,[InvalidOperationException]::new('Private diagnostic capture could not be retained.')))
            }
        }
        throw $privacyFailure
    }
    if($result.StandardError){throw "$($case.scenario) wrote stderr: $($result.StandardError)"}
    $applicationEvidence.Add([pscustomobject][ordered]@{
        scenario=$case.scenario
        status='Pass'
        expectedSecurityControlFinding=$case.securityFinding
        observedSecurityControlFinding=$validation[0].securityControlFinding
        terminal=$terminal[0].outcome
        exitCode=$result.ExitCode
        appliedPolicyCoverage=$validation[0].appliedPolicyCoverage
        configuredSignalCoverage=$validation[0].configuredSignalCoverage
        currentControlCoverage=$validation[0].currentControlCoverage
        mdmPolicyCspFinding=$validation[0].mdmPolicyCspFinding
        policyCspGpoConflictFinding=$validation[0].policyCspGpoConflictFinding
        appLockerCspCollectionCount=$validation[0].appLockerCspCollectionCount
        assessmentRecordValidated=$validation[0].assessmentRecordValidated
        beginnerReportVerified=$validation[0].beginnerReportVerified
        protectedPackageVerified=$validation[0].protectedPackageVerified
        validationCleanupVerified=$validation[0].validationCleanupVerified
    })
    if ($env:WINPCINFO_TEST_EVIDENCE) {
        $applicationEvidence | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 -LiteralPath (
            Join-Path $env:WINPCINFO_TEST_EVIDENCE 'effective-policy-application-results.json')
    }
    Write-Output "PASS: EffectivePolicy $($case.scenario), $($terminal[0].outcome), verified package and cleanup."
}

Write-Output 'PASS: the generated application exercises three-layer policy evidence, findings, privacy, packaging, and cleanup.'
}
catch { $candidateUseError=$_ }
finally { Close-TestCandidate -Candidate $candidateContext -BodyError $candidateUseError }
