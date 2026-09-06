$script:AdministratorExposurePolicyBase64 = '__ADMINISTRATOR_EXPOSURE_POLICY_BASE64__'
$script:AdministratorExposurePolicyDigest = '__ADMINISTRATOR_EXPOSURE_POLICY_SHA256__'

function Get-AdministratorExposureSha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Get-AdministratorExposurePolicy {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    if ($script:AdministratorExposurePolicyBase64 -eq ('__ADMINISTRATOR_EXPOSURE_' + 'POLICY_BASE64__')) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-administrator-exposure.json'
        $bytes = [IO.File]::ReadAllBytes($path)
        $expectedDigest = Get-AdministratorExposureSha256 -Bytes $bytes
    }
    else {
        $bytes = [Convert]::FromBase64String($script:AdministratorExposurePolicyBase64)
        $expectedDigest = $script:AdministratorExposurePolicyDigest
    }
    if ((Get-AdministratorExposureSha256 -Bytes $bytes) -ne $expectedDigest) {
        throw 'The Administrator Exposure policy failed integrity validation.'
    }
    $policy = & $ConvertFromJsonCommand -InputObject (
        [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    ) -Depth 20 -ErrorAction Stop
    if ($policy.kind -ne 'win-pcinfo.administrator-exposure-policy' -or
        $policy.policyId -ne 'win-pcinfo.administrator-exposure/1.0.0' -or
        $policy.administratorsGroup.identity -ne 'BuiltinAdministratorsAlias' -or
        @($policy.collectors).Count -ne 1 -or @($policy.scopes).Count -ne 1 -or
        @($policy.rules).Count -ne 1 -or @($policy.validationScenarios).Count -ne 10) {
        throw 'The Administrator Exposure policy is not the closed release policy.'
    }
    $policy
}

function Read-AdministratorExposureFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $Policy
    )
    try {
        [byte[]]$bytes = [IO.File]::ReadAllBytes([IO.Path]::GetFullPath($LiteralPath))
        if ($bytes.Length -lt 1 -or $bytes.Length -gt 512) { throw 'Fixture size is invalid.' }
        $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $document = [Text.Json.JsonDocument]::Parse($json)
        try {
            $names = @($document.RootElement.EnumerateObject() | ForEach-Object Name)
            if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object -or
                (@($names | Sort-Object) -join '|') -ne 'contractVersion|scenario') {
                throw 'Fixture shape is invalid.'
            }
        }
        finally { $document.Dispose() }
        $fixture = & $ConvertFromJsonCommand -InputObject $json -Depth 5 -ErrorAction Stop
        if ($fixture.contractVersion -ne '1.0.0' -or
            [string]$fixture.scenario -notin @($Policy.validationScenarios)) {
            throw 'Fixture scenario is not release-owned.'
        }
        [string]$fixture.scenario
    }
    catch {
        $exception = [ArgumentException]::new('The Administrator Exposure fixture is invalid.')
        $exception.Data['ReasonCode'] = 'ADMINISTRATOR_EXPOSURE.FIXTURE_INVALID'
        throw $exception
    }
}

function New-AdministratorExposureSyntheticMember {
    param(
        [Parameter(Mandatory)] [string] $Sid,
        [Parameter()] [AllowNull()] $AccountName,
        [Parameter(Mandatory)] [ValidateSet('User','Group','Computer','Unknown')] [string] $Kind,
        [Parameter(Mandatory)] [ValidateSet('Local','Domain','Builtin','Unresolved')] [string] $Origin
    )
    [pscustomobject][ordered]@{
        sid=$Sid;accountName=$AccountName;principalKind=$Kind;origin=$Origin
    }
}

function New-AdministratorExposureSyntheticPayload {
    param([Parameter(Mandatory)] [string] $Scenario)

    $localUser = New-AdministratorExposureSyntheticMember `
        -Sid 'S-1-5-21-111111111-222222222-333333333-1001' `
        -AccountName 'SYNTHETIC\local-admin' -Kind User -Origin Local
    $builtinUser = New-AdministratorExposureSyntheticMember -Sid 'S-1-5-21-111111111-222222222-333333333-500' `
        -AccountName 'SYNTHETIC\built-in-admin' -Kind User -Origin Local
    $domainUser = New-AdministratorExposureSyntheticMember `
        -Sid 'S-1-5-21-444444444-555555555-666666666-1101' `
        -AccountName 'SYNTHETIC-DOMAIN\domain-admin' -Kind User -Origin Domain
    $domainGroup = New-AdministratorExposureSyntheticMember `
        -Sid 'S-1-5-21-444444444-555555555-666666666-2101' `
        -AccountName 'SYNTHETIC-DOMAIN\endpoint-admins' -Kind Group -Origin Domain
    $members = @($builtinUser, $localUser)
    $state = 'Complete'; $complete = $true; $locale = 'en-US'; $sourceCount = 2
    $relationship = 'SelectedAdministrator'
    switch ($Scenario) {
        'LocalPrincipal' { }
        'DomainPrincipal' { $members=@($domainGroup,$domainUser) }
        'NestedGroup' { $members=@($domainGroup,$localUser) }
        'UnresolvedSid' {
            $unresolved=New-AdministratorExposureSyntheticMember `
                -Sid 'S-1-5-21-777777777-888888888-999999999-4040' `
                -AccountName $null -Kind Unknown -Origin Unresolved
            $members=@($unresolved,$localUser)
        }
        'DuplicateMembership' { $members=@($domainUser,$localUser);$sourceCount=3 }
        'AlternateAdministrator' { $relationship='AlternateAdministrator' }
        'Denied' { $state='Denied';$complete=$false;$members=@();$sourceCount=0 }
        'Partial' { $state='Partial';$complete=$false;$members=@($domainGroup,$localUser) }
        'NonEnglish' {
            $locale='fr-FR'
            $frenchGroup=New-AdministratorExposureSyntheticMember `
                -Sid $domainGroup.sid -AccountName 'DOMAINE-ÉQUIPE\administrateurs-poste' `
                -Kind Group -Origin Domain
            $frenchUser=New-AdministratorExposureSyntheticMember `
                -Sid $localUser.sid -AccountName 'ÉQUIPE\administrateur-local' `
                -Kind User -Origin Local
            $members=@($frenchGroup,$frenchUser)
        }
        'ElevationDenied' {
            $state='Denied';$complete=$false;$members=@();$sourceCount=0
            $relationship='NotStarted'
        }
        default { throw 'The Administrator Exposure scenario is not release-defined.' }
    }
    [pscustomobject][ordered]@{
        payload=[pscustomobject][ordered]@{
            sourceLocale=$locale;groupSid='S-1-5-32-544';enumerationState=$state
            enumerationComplete=$complete;directMembers=@($members)
            sourceReturnedEntries=$sourceCount
            duplicateEntriesRemoved=[int]($sourceCount-@($members).Count)
            limitation='DirectMembersOnly'
        }
        relationship=$relationship
    }
}

function Test-AdministratorExposureCollectorPayload {
    param([Parameter(Mandatory)] $Payload, [Parameter(Mandatory)] $Policy)

    $allowed = @('sourceLocale','groupSid','enumerationState','enumerationComplete',
        'directMembers','sourceReturnedEntries','duplicateEntriesRemoved','limitation')
    $names = @($Payload.PSObject.Properties.Name)
    if ($names.Count -ne $allowed.Count -or
        (@($names|Sort-Object)-join '|') -ne (@($allowed|Sort-Object)-join '|') -or
        [string]$Payload.groupSid -ne 'S-1-5-32-544' -or
        [string]$Payload.enumerationState -notin @('Complete','Partial','Denied','Malformed','Failed','Cancelled') -or
        $Payload.enumerationComplete -isnot [bool] -or
        [string]$Payload.limitation -ne 'DirectMembersOnly' -or
        [string]$Payload.sourceLocale -notmatch '^(?:und|[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*)$' -or
        @($Payload.directMembers).Count -gt [int]$Policy.collectors[0].maximumDirectMembers -or
        ($Payload.sourceReturnedEntries -isnot [int] -and $Payload.sourceReturnedEntries -isnot [long]) -or
        $Payload.sourceReturnedEntries -lt 0 -or
        ($Payload.duplicateEntriesRemoved -isnot [int] -and $Payload.duplicateEntriesRemoved -isnot [long]) -or
        $Payload.duplicateEntriesRemoved -lt 0) {
        return $false
    }
    # Completion is a security-relevant claim: a denied source with an empty
    # array is not an empty Administrators group. Only the Complete state may
    # set this bit; source-wide failure states must carry no identity at all.
    if (($Payload.enumerationState -eq 'Complete') -ne [bool]$Payload.enumerationComplete -or
        ($Payload.enumerationState -in @('Denied','Malformed','Failed','Cancelled') -and (
            @($Payload.directMembers).Count -ne 0 -or
            [int]$Payload.sourceReturnedEntries -ne 0 -or
            [int]$Payload.duplicateEntriesRemoved -ne 0
        ))) {
        return $false
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($member in @($Payload.directMembers)) {
        $memberNames = @($member.PSObject.Properties.Name)
        if ((@($memberNames|Sort-Object)-join '|') -ne 'accountName|origin|principalKind|sid' -or
            [string]$member.sid -notmatch '^S-1-(?:[0-9]+-){1,14}[0-9]+$' -or
            -not $seen.Add([string]$member.sid) -or
            [string]$member.principalKind -notin @('User','Group','Computer','Unknown') -or
            [string]$member.origin -notin @('Local','Domain','Builtin','Unresolved') -or
            ($null -ne $member.accountName -and (
                [string]::IsNullOrWhiteSpace([string]$member.accountName) -or
                [Text.Encoding]::UTF8.GetByteCount([string]$member.accountName) -gt 256
            ))) {
            return $false
        }
    }
    @($Payload.directMembers).Count + [int]$Payload.duplicateEntriesRemoved -le
        [int]$Payload.sourceReturnedEntries
}

function Invoke-AdministratorExposureCollection {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string] $ValidationScenario
    )
    $synthetic = New-AdministratorExposureSyntheticPayload -Scenario $ValidationScenario
    if (-not (Test-AdministratorExposureCollectorPayload -Payload $synthetic.payload -Policy $Policy)) {
        throw 'The synthetic Administrator Exposure payload is invalid.'
    }
    $now=[DateTimeOffset]::UtcNow
    [pscustomobject][ordered]@{
        state=if($synthetic.payload.enumerationState -eq 'Complete'){'Completed'}else{'CompletedWithGaps'}
        reasonCode="ADMINISTRATOR_EXPOSURE.$($synthetic.payload.enumerationState.ToUpperInvariant())"
        validationScenario=$ValidationScenario;validationFixture=$true
        processRelationship=[string]$synthetic.relationship
        assessmentUserContext='subject:assessment-user:primary'
        localPackageProtector='protector:initiating-windows-user'
        membershipSemantics='DirectMembersOnly'
        envelope=[pscustomobject][ordered]@{
            startedAt=$now.AddMilliseconds(-1).ToString('o')
            completedAt=$now.ToString('o');attempts=1;executionContext='Synthetic'
        }
        payload=$synthetic.payload
    }
}

function New-AdministratorExposurePublicProjection {
    param([Parameter(Mandatory)] $CollectorResult)
    [pscustomobject][ordered]@{
        recordType='win-pcinfo.local-privilege-validation';contractVersion='1.0.0'
        scenario=[string]$CollectorResult.validationScenario
        coverageState=[string]$CollectorResult.payload.enumerationState
        enumerationComplete=[bool]$CollectorResult.payload.enumerationComplete
        directMemberCount=@($CollectorResult.payload.directMembers).Count
        nestedExpansionAttempted=$false;identifiersPublished=$false
        credentialMaterialCollected=$false;identityStateChanged=$false
    }
}

function New-AdministratorExposurePrivilegeGapResult {
    param(
        [Parameter(Mandatory)] $PrivilegeResult,
        [Parameter(Mandatory)] [bool] $ValidationFixture
    )

    # A refused UAC prompt prevents the Administrator attempt, but it does not
    # erase the coordinator-owned user/protector roles. This typed gap lets the
    # already-approved standard-user work finish while admitting no member SID
    # or false empty-group observation.
    $now=[DateTimeOffset]::UtcNow.ToString('o')
    [pscustomobject][ordered]@{
        state='CompletedWithGaps';reasonCode=[string]$PrivilegeResult.reasonCode
        validationScenario=if($ValidationFixture){'ElevationDenied'}else{'Denied'}
        validationFixture=$ValidationFixture;processRelationship='NotStarted'
        assessmentUserContext=[string]$PrivilegeResult.identity.assessmentUserContext
        localPackageProtector=[string]$PrivilegeResult.identity.localPackageProtector
        membershipSemantics='DirectMembersOnly'
        envelope=[pscustomobject][ordered]@{
            startedAt=$now;completedAt=$now;attempts=1
            executionContext=if($ValidationFixture){'Synthetic'}else{'Administrator'}
        }
        payload=[pscustomobject][ordered]@{
            sourceLocale='und';groupSid='S-1-5-32-544';enumerationState=$(if($PrivilegeResult.state -eq 'Cancelled'){'Cancelled'}else{'Denied'})
            enumerationComplete=$false;directMembers=@();sourceReturnedEntries=0
            duplicateEntriesRemoved=0;limitation='DirectMembersOnly'
        }
    }
}

function Get-AdministratorExposureCoverageReason {
    param([Parameter(Mandatory)] [string] $State)
    switch ($State) {
        'Partial' { 'COLLECTION.LOCAL_ADMINISTRATORS_PARTIAL' }
          'Denied' { 'COLLECTION.LOCAL_ADMINISTRATORS_DENIED' }
          'Cancelled' { 'COLLECTION.LOCAL_ADMINISTRATORS_CANCELLED' }
        'Malformed' { 'COLLECTION.LOCAL_ADMINISTRATORS_MALFORMED' }
        default { 'COLLECTION.LOCAL_ADMINISTRATORS_FAILED' }
    }
}

function New-AdministratorExposureObservation {
    param(
        [Parameter(Mandatory)] [string] $RunId,
        [Parameter(Mandatory)] [string] $Suffix,
        [Parameter(Mandatory)] [string] $FieldId,
        [Parameter(Mandatory)] [string] $SubjectId,
        [Parameter(Mandatory)] [string] $CollectorId,
        [Parameter(Mandatory)] [string] $CollectorVersion,
        [Parameter(Mandatory)] [string] $ObservedExecutionContext,
        [Parameter(Mandatory)] [string] $CollectedAt,
        [Parameter(Mandatory)] [string] $SourceLocale,
        [Parameter()] $Value,
        [Parameter()] [switch] $SourceReportedUnknown
    )
    $observationId="observation:administrator-$Suffix`:$RunId"
    $provenanceId="provenance:administrator-$Suffix`:$RunId"
    $observation=[ordered]@{
        observationId=$observationId;fieldId=$FieldId;subjectId=$SubjectId
        provenanceId=$provenanceId
        valueState=if($SourceReportedUnknown){'SourceReportedUnknown'}else{'ObservedValue'}
    }
    if(-not $SourceReportedUnknown){$observation.value=$Value}
    [pscustomobject][ordered]@{
        observation=[pscustomobject]$observation
        provenance=[pscustomobject][ordered]@{
            provenanceId=$provenanceId;fieldId=$FieldId;subjectId=$SubjectId
            sourceId='source:windows.native.local-administrators'
            collectorId=$CollectorId;collectorVersion=$CollectorVersion
            executionContext=$ObservedExecutionContext;collectedAt=$CollectedAt
            sourceLocale=$SourceLocale
        }
    }
}

function Add-AdministratorExposureEvidenceRecord {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $CollectorResult,
        [Parameter(Mandatory)] $Policy
    )
    if([string]$Record.run.evidenceProfileId -ne 'profile:device-firmware-and-identity-readiness'){
        throw 'Administrator evidence requires the accepted Device, Firmware, and Identity evidence profile.'
    }
    if(@($Record.findings|Where-Object {
        $_.ruleId -eq [string]$Policy.rules[0].ruleId
    }).Count -ne 0){
        throw 'Administrator evidence cannot be added after its Rule Evaluation.'
    }
    if(-not (Test-AdministratorExposureCollectorPayload -Payload $CollectorResult.payload -Policy $Policy)){
        throw 'Administrator evidence requires a closed collector result.'
    }
    # Principal values are Restricted even when they are synthetic. The short
    # digest below is only a package-local graph key, not anonymization and not
    # a value that may enter a public projection. The original SID remains in
    # the protected observation so evidence references stay exact.
    $runId=[string]$Record.run.runId;$deviceSubject='subject:device:primary'
    $collector=$Policy.collectors[0];$payload=$CollectorResult.payload
    $collectedAt=[string]$CollectorResult.envelope.completedAt
    $observedExecutionContext=[string]$CollectorResult.envelope.executionContext
    $observations=[Collections.Generic.List[object]]::new()
    $provenance=[Collections.Generic.List[object]]::new()
    $subjects=[Collections.Generic.List[object]]::new()
    $subjectIds=[Collections.Generic.List[string]]::new();$subjectIds.Add($deviceSubject)
    if([string]$payload.enumerationState -in @('Complete','Partial')){
        $deviceFields=@(
            @{suffix='group-sid';id='field:device.local-administrators.group-sid';value=[string]$payload.groupSid},
            @{suffix='complete';id='field:device.local-administrators.enumeration-complete';value=[bool]$payload.enumerationComplete},
            @{suffix='count';id='field:device.local-administrators.direct-member-count';value=[int]@($payload.directMembers).Count}
        )
        foreach($field in $deviceFields){
            $pair=New-AdministratorExposureObservation -RunId $runId -Suffix $field.suffix `
                -FieldId $field.id -SubjectId $deviceSubject -CollectorId $collector.collectorId `
                -CollectorVersion $collector.collectorVersion -ObservedExecutionContext $observedExecutionContext `
                -CollectedAt $collectedAt -SourceLocale $payload.sourceLocale -Value $field.value
            $observations.Add($pair.observation);$provenance.Add($pair.provenance)
        }
        $index=0
        foreach($member in @($payload.directMembers)){
            # The graph key is deliberately run-local. Hashing the SID alone
            # would create a stable product-generated tracking identifier
            # across packages, even though the raw SID stayed Restricted.
            $subjectId="subject:security-principal:$index"
            $subjects.Add([pscustomobject][ordered]@{subjectId=$subjectId;kind='SecurityPrincipal'})
            $subjectIds.Add($subjectId)
            $fields=@(
                @{suffix="member-$index-sid";id='field:principal.windows.sid';value=[string]$member.sid},
                @{suffix="member-$index-name";id='field:principal.windows.account-name';value=$member.accountName;absent=$null -eq $member.accountName},
                @{suffix="member-$index-kind";id='field:principal.windows.kind';value=[string]$member.principalKind},
                @{suffix="member-$index-origin";id='field:principal.windows.origin';value=[string]$member.origin},
                @{suffix="member-$index-direct";id='field:principal.local-administrator.direct-member';value=$true}
            )
            foreach($field in $fields){
                $parameters=@{
                    RunId=$runId;Suffix=$field.suffix;FieldId=$field.id;SubjectId=$subjectId
                    CollectorId=[string]$collector.collectorId
                    CollectorVersion=[string]$collector.collectorVersion
                    ObservedExecutionContext=$observedExecutionContext;CollectedAt=$collectedAt
                    SourceLocale=[string]$payload.sourceLocale;Value=$field.value
                }
                if($field.ContainsKey('absent') -and $field.absent){$parameters.SourceReportedUnknown=$true}
                $pair=New-AdministratorExposureObservation @parameters
                $observations.Add($pair.observation);$provenance.Add($pair.provenance)
            }
            $index++
        }
    }
    $coverageId="coverage:device-local-administrators:$runId"
    $diagnostics=@();$coverage=[ordered]@{
        coverageId=$coverageId;scopeId='scope:device.local-administrators.direct-membership'
        state=[string]$payload.enumerationState
        observationIds=@($observations|ForEach-Object observationId);diagnosticIds=@()
    }
    if($payload.enumerationState -ne 'Complete'){
        $diagnosticId="diagnostic:device-local-administrators:$runId"
        $coverage.reasonCode=Get-AdministratorExposureCoverageReason -State $payload.enumerationState
        $coverage.diagnosticIds=@($diagnosticId)
        $diagnostics=@([pscustomobject][ordered]@{
            diagnosticId=$diagnosticId;scopeId=$coverage.scopeId;phase='Collection'
            reasonCode=$coverage.reasonCode;operatorMessageId='administrator-exposure.collection.incomplete'
        })
    }
    $Record.subjects=@($Record.subjects)+@($subjects)
    $Record.observations=@($Record.observations)+@($observations)
    $Record.provenance=@($Record.provenance)+@($provenance)
    $Record.coverage=@($Record.coverage)+[pscustomobject]$coverage
    $Record.diagnostics=@($Record.diagnostics)+$diagnostics
    $Record.collectorResults=@($Record.collectorResults)+[pscustomobject][ordered]@{
        envelopeId="envelope:administrator-exposure:$runId"
        collectorId=[string]$collector.collectorId;collectorVersion=[string]$collector.collectorVersion
        operationId=[string]$collector.operationId
        intendedScopeIds=@('scope:device.local-administrators.direct-membership')
        subjectIds=@($subjectIds);startedAt=[string]$CollectorResult.envelope.startedAt
        completedAt=$collectedAt;executionContext=$observedExecutionContext;attempts=1
        observationIds=@($observations|ForEach-Object observationId);coverageIds=@($coverageId)
        diagnosticIds=@($diagnostics|ForEach-Object diagnosticId)
    }
    $Record.run.evidenceProfileId=[string]$Policy.evidenceProfileId
    $Record.run.outcome=if(@($Record.coverage|Where-Object state -ne Complete).Count -eq 0){
        'Completed'
    }else{'CompletedWithGaps'}
    $Record
}

function Complete-ValidatedAdministratorExposureAssessmentRecord {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $ContractValidation
    )
    if(-not [bool]$ContractValidation.accepted -or
        $ContractValidation.reasonCode -ne 'CONTRACT.ACCEPTED' -or
        @($Record.findings|Where-Object {
            $_.ruleId -eq [string]$Policy.rules[0].ruleId
        }).Count -ne 0 -or
        [string]$Record.run.evidenceProfileId -ne [string]$Policy.evidenceProfileId){
        throw 'The administrator rule requires an accepted source-only combined record.'
    }
    # The local source cannot know the organization's intended administrator
    # assignments. The rule therefore reports evidence completeness only: it
    # never labels an identity compromised and never recommends removal.
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $scope='scope:device.local-administrators.direct-membership'
    $coverage=@($Record.coverage|Where-Object scopeId -eq $scope)[0]
    $references=@($Record.observations|Where-Object {
        $_.fieldId -in @(
            'field:device.local-administrators.group-sid',
            'field:device.local-administrators.enumeration-complete',
            'field:device.local-administrators.direct-member-count',
            'field:principal.windows.sid',
            'field:principal.local-administrator.direct-member'
        )
    }|Select-Object -First ([int]$Policy.rules[0].maximumInputObservations)|ForEach-Object {
        [pscustomobject][ordered]@{
            observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId
        }
    })
    $finding=[ordered]@{
        findingId="finding:local-administrator-exposure:$($Record.run.runId)"
        ruleId=[string]$Policy.rules[0].ruleId;targetSubjectId='subject:device:primary'
        outcome=if($coverage.state -eq 'Complete'){'Informational'}else{'Indeterminate'}
        evidenceReferences=$references
    }
    if($coverage.state -ne 'Complete'){
        $finding.reasonCode='FINDING.LOCAL_ADMINISTRATORS_INCOMPLETE'
    }
    $watch.Stop()
    if($watch.ElapsedMilliseconds -gt [int]$Policy.rules[0].deadlineMilliseconds){
        throw 'The administrator Rule Evaluation exceeded its release deadline.'
    }
    $Record.findings=@($Record.findings)+[pscustomobject]$finding
    foreach ($task in @($Record.recommendations | Where-Object definitionId -eq 'task:confirm-approved-administrator-context/1.0.0')) {
        $task.findingIds=@($task.findingIds)+[string]$finding.findingId
    }
    $Record.run.outcome=if(@($Record.coverage|Where-Object state -ne Complete).Count -eq 0){
        'Completed'
    }else{'CompletedWithGaps'}
    $Record
}
