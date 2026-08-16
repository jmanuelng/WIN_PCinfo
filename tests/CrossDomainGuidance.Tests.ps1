[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1')
. (Join-Path $repositoryRoot 'src/CrossDomainGuidance.ps1')

$convertFromJson = $ExecutionContext.InvokeCommand.GetCommand(
    'ConvertFrom-Json',
    [System.Management.Automation.CommandTypes]::Cmdlet
)

function New-SyntheticCrossDomainRecord {
    param(
        [Parameter(Mandatory)] [string] $RunId,
        [Parameter(Mandatory)] [hashtable] $Outcomes,
        [Parameter()] [bool] $LocalOnly = $false
    )

    $record = [pscustomobject][ordered]@{
        run = [pscustomobject][ordered]@{
            runId = $RunId
            evidenceProfileId = 'profile:device-firmware-identity-administrator-policy-software-resource-network-certificate-and-microsoft-connectivity-readiness'
        }
        subjects = @([pscustomobject][ordered]@{
            subjectId = 'subject:device:primary'
            kind = 'Device'
        })
        observations = @()
        findings = @()
        recommendations = @()
        recommendationRelationships = @()
    }

    $findingDefinitions = @(
        @{ name = 'assessmentUser'; ruleId = 'rule:identity.assessment-user-context/1.0.0'; prefix = 'assessment-user'; reason = 'FINDING.IDENTITY_EVIDENCE_INCOMPLETE' }
        @{ name = 'deviceRegistration'; ruleId = 'rule:identity.device-registration-context/1.0.0'; prefix = 'device-registration'; reason = 'FINDING.IDENTITY_EVIDENCE_INCOMPLETE' }
        @{ name = 'workSchool'; ruleId = 'rule:identity.work-school-enrollment-context/1.0.0'; prefix = 'work-school'; reason = 'FINDING.IDENTITY_EVIDENCE_INCOMPLETE' }
        @{ name = 'administrator'; ruleId = 'rule:identity.local-administrator-exposure/1.0.0'; prefix = 'administrator'; reason = 'FINDING.ADMINISTRATOR_EVIDENCE_INCOMPLETE' }
        @{ name = 'policyApplied'; ruleId = 'rule:policy.applied-policy-coverage/1.0.0'; prefix = 'policy-applied'; reason = 'FINDING.POLICY_EVIDENCE_INCOMPLETE' }
        @{ name = 'policyLocal'; ruleId = 'rule:policy.local-security-policy-coverage/1.0.0'; prefix = 'policy-local'; reason = 'FINDING.POLICY_EVIDENCE_INCOMPLETE' }
        @{ name = 'policyOrder'; ruleId = 'rule:policy.applied-order-conflict/1.0.0'; prefix = 'policy-order'; reason = 'FINDING.POLICY_EVIDENCE_INCOMPLETE' }
        @{ name = 'policySecurity'; ruleId = 'rule:policy.security-control-coverage/1.0.0'; prefix = 'policy-security'; reason = 'FINDING.POLICY_EVIDENCE_INCOMPLETE' }
        @{ name = 'policyConstraint'; ruleId = 'rule:policy.security-control-constraint/1.0.0'; prefix = 'policy-constraint'; reason = 'FINDING.POLICY_EVIDENCE_INCOMPLETE' }
        @{ name = 'policyMdm'; ruleId = 'rule:policy.mdm-policy-csp-coverage/1.0.0'; prefix = 'policy-mdm'; reason = 'FINDING.POLICY_EVIDENCE_INCOMPLETE' }
        @{ name = 'policyConflict'; ruleId = 'rule:policy.policy-csp-gpo-conflict/1.0.0'; prefix = 'policy-conflict'; reason = 'FINDING.POLICY_EVIDENCE_INCOMPLETE' }
        @{ name = 'resourceUser'; ruleId = 'rule:resource.user-migration-dependencies/1.0.0'; prefix = 'resource-user'; reason = 'FINDING.RESOURCE_EVIDENCE_INCOMPLETE' }
        @{ name = 'resourcePeripheral'; ruleId = 'rule:resource.peripheral-migration-dependencies/1.0.0'; prefix = 'resource-peripheral'; reason = 'FINDING.RESOURCE_EVIDENCE_INCOMPLETE' }
        @{ name = 'softwareMachine'; ruleId = 'rule:software.machine-inventory/1.0.0'; prefix = 'software-machine'; reason = 'FINDING.SOFTWARE_EVIDENCE_INCOMPLETE' }
        @{ name = 'softwareUser'; ruleId = 'rule:software.assessment-user-inventory/1.0.0'; prefix = 'software-user'; reason = 'FINDING.SOFTWARE_EVIDENCE_INCOMPLETE' }
        @{ name = 'certificatePresence'; ruleId = 'rule:certificate.presence/1.0.0'; prefix = 'certificate-presence'; reason = 'FINDING.CERTIFICATE_EVIDENCE_INCOMPLETE' }
        @{ name = 'certificateTrust'; ruleId = 'rule:certificate.trust/1.0.0'; prefix = 'certificate-trust'; reason = 'FINDING.CERTIFICATE_EVIDENCE_INCOMPLETE' }
        @{ name = 'connectivity'; ruleId = 'rule:microsoft-connectivity.reachability/1.0.0'; prefix = 'connectivity'; reason = 'FINDING.CONNECTIVITY_EVIDENCE_INCOMPLETE' }
        @{ name = 'tlsInspection'; ruleId = 'rule:microsoft-connectivity.tls-inspection/1.0.0'; prefix = 'tls-inspection'; reason = 'FINDING.CONNECTIVITY_EVIDENCE_INCOMPLETE' }
        @{ name = 'networkLocalOnly'; ruleId = 'rule:network.local-only-coverage/1.0.0'; prefix = 'network-local-only'; reason = 'FINDING.NETWORK_REQUESTS_NOT_ATTEMPTED' }
    )

    $observationIndex = 0
    foreach ($definition in $findingDefinitions) {
        $outcome = if ($Outcomes.ContainsKey($definition.name)) {
            [string] $Outcomes[$definition.name]
        }
        elseif ($definition.name -eq 'networkLocalOnly') {
            if ($LocalOnly) { 'NeedsAttention' } else { 'Informational' }
        }
        else { 'Informational' }

        $fieldId = "field:synthetic.$($definition.prefix)"
        $observationId = "observation:$($definition.prefix):$observationIndex"
        $observationIndex++
        $record.observations += [pscustomobject][ordered]@{
            observationId = $observationId
            fieldId = $fieldId
            subjectId = 'subject:device:primary'
            provenanceId = "provenance:$($definition.prefix):$observationIndex"
            valueState = 'ObservedValue'
            value = $definition.prefix
        }
        $finding = [ordered]@{
            findingId = "finding:$($definition.prefix):$RunId"
            ruleId = $definition.ruleId
            targetSubjectId = 'subject:device:primary'
            outcome = $outcome
            evidenceReferences = @([pscustomobject][ordered]@{
                observationId = $observationId
                fieldId = $fieldId
                subjectId = 'subject:device:primary'
            })
        }
        if ($outcome -in @('Indeterminate', 'NotApplicable')) {
            $finding.reasonCode = $definition.reason
        }
        $record.findings += [pscustomobject] $finding
    }

    $record
}

$policy = Get-CrossDomainGuidancePolicy -ConvertFromJsonCommand $convertFromJson

$cases = @(
    @{
        scenario = 'Complete'
        localOnly = $false
        outcomes = @{
            assessmentUser = 'ExpectedCondition'
            deviceRegistration = 'ExpectedCondition'
            workSchool = 'Informational'
            administrator = 'Informational'
            policyApplied = 'Informational'
            policyLocal = 'Informational'
            policyOrder = 'Informational'
            policySecurity = 'Informational'
            policyConstraint = 'Informational'
            policyMdm = 'Informational'
            policyConflict = 'Informational'
            resourceUser = 'Informational'
            resourcePeripheral = 'Informational'
            softwareMachine = 'Informational'
            softwareUser = 'Informational'
            certificatePresence = 'ExpectedCondition'
            certificateTrust = 'ExpectedCondition'
            connectivity = 'ExpectedCondition'
            tlsInspection = 'Informational'
        }
        identity = 'ExpectedCondition'
        management = 'ExpectedCondition'
        dependency = 'Informational'
        policyModernization = 'Informational'
        overall = 'ExpectedCondition'
        discoveryTasks = 2
    }
    @{
        scenario = 'Partial'
        localOnly = $false
        outcomes = @{
            assessmentUser = 'ExpectedCondition'
            deviceRegistration = 'ExpectedCondition'
            workSchool = 'Informational'
            administrator = 'Informational'
            policyApplied = 'Indeterminate'
            policyLocal = 'Indeterminate'
            policyOrder = 'Informational'
            policySecurity = 'Indeterminate'
            policyConstraint = 'Informational'
            policyMdm = 'Informational'
            policyConflict = 'Informational'
            resourceUser = 'Informational'
            resourcePeripheral = 'Informational'
            softwareMachine = 'Informational'
            softwareUser = 'Informational'
            certificatePresence = 'ExpectedCondition'
            certificateTrust = 'ExpectedCondition'
            connectivity = 'ExpectedCondition'
            tlsInspection = 'Informational'
        }
        identity = 'ExpectedCondition'
        management = 'ExpectedCondition'
        dependency = 'Informational'
        policyModernization = 'Indeterminate'
        overall = 'Indeterminate'
        discoveryTasks = 3
    }
    @{
        scenario = 'Absent'
        localOnly = $false
        outcomes = @{
            assessmentUser = 'ExpectedCondition'
            deviceRegistration = 'NeedsAttention'
            workSchool = 'NeedsAttention'
            administrator = 'Informational'
            policyApplied = 'Informational'
            policyLocal = 'Informational'
            policyOrder = 'Informational'
            policySecurity = 'Informational'
            policyConstraint = 'Informational'
            policyMdm = 'Informational'
            policyConflict = 'Informational'
            resourceUser = 'Informational'
            resourcePeripheral = 'Informational'
            softwareMachine = 'Informational'
            softwareUser = 'Informational'
            certificatePresence = 'ExpectedCondition'
            certificateTrust = 'ExpectedCondition'
            connectivity = 'ExpectedCondition'
            tlsInspection = 'Informational'
        }
        identity = 'NeedsAttention'
        management = 'ExpectedCondition'
        dependency = 'Informational'
        policyModernization = 'Informational'
        overall = 'NeedsAttention'
        discoveryTasks = 2
    }
    @{
        scenario = 'Denied'
        localOnly = $false
        outcomes = @{
            assessmentUser = 'ExpectedCondition'
            deviceRegistration = 'ExpectedCondition'
            workSchool = 'Informational'
            administrator = 'Indeterminate'
            policyApplied = 'Indeterminate'
            policyLocal = 'Indeterminate'
            policyOrder = 'Indeterminate'
            policySecurity = 'Indeterminate'
            policyConstraint = 'Indeterminate'
            policyMdm = 'Indeterminate'
            policyConflict = 'Indeterminate'
            resourceUser = 'Informational'
            resourcePeripheral = 'Informational'
            softwareMachine = 'Informational'
            softwareUser = 'Informational'
            certificatePresence = 'ExpectedCondition'
            certificateTrust = 'ExpectedCondition'
            connectivity = 'ExpectedCondition'
            tlsInspection = 'Informational'
        }
        identity = 'ExpectedCondition'
        management = 'ExpectedCondition'
        dependency = 'Indeterminate'
        policyModernization = 'Indeterminate'
        overall = 'Indeterminate'
        discoveryTasks = 3
    }
    @{
        scenario = 'Unsupported'
        localOnly = $false
        outcomes = @{
            assessmentUser = 'ExpectedCondition'
            deviceRegistration = 'ExpectedCondition'
            workSchool = 'Informational'
            administrator = 'Informational'
            policyApplied = 'Informational'
            policyLocal = 'Informational'
            policyOrder = 'Informational'
            policySecurity = 'Indeterminate'
            policyConstraint = 'Indeterminate'
            policyMdm = 'Indeterminate'
            policyConflict = 'Informational'
            resourceUser = 'Informational'
            resourcePeripheral = 'Informational'
            softwareMachine = 'Informational'
            softwareUser = 'Informational'
            certificatePresence = 'ExpectedCondition'
            certificateTrust = 'ExpectedCondition'
            connectivity = 'ExpectedCondition'
            tlsInspection = 'Informational'
        }
        identity = 'ExpectedCondition'
        management = 'ExpectedCondition'
        dependency = 'Informational'
        policyModernization = 'Indeterminate'
        overall = 'Indeterminate'
        discoveryTasks = 3
    }
    @{
        scenario = 'Stale'
        localOnly = $true
        outcomes = @{
            assessmentUser = 'ExpectedCondition'
            deviceRegistration = 'ExpectedCondition'
            workSchool = 'Informational'
            administrator = 'Informational'
            policyApplied = 'Informational'
            policyLocal = 'Informational'
            policyOrder = 'Informational'
            policySecurity = 'Informational'
            policyConstraint = 'Informational'
            policyMdm = 'Informational'
            policyConflict = 'Informational'
            resourceUser = 'Informational'
            resourcePeripheral = 'Informational'
            softwareMachine = 'Informational'
            softwareUser = 'Informational'
            certificatePresence = 'ExpectedCondition'
            certificateTrust = 'Indeterminate'
            connectivity = 'Indeterminate'
            tlsInspection = 'Indeterminate'
        }
        identity = 'ExpectedCondition'
        management = 'Indeterminate'
        dependency = 'Informational'
        policyModernization = 'Informational'
        overall = 'Indeterminate'
        discoveryTasks = 3
    }
    @{
        scenario = 'Contradictory'
        localOnly = $false
        outcomes = @{
            assessmentUser = 'ExpectedCondition'
            deviceRegistration = 'ExpectedCondition'
            workSchool = 'NeedsAttention'
            administrator = 'Informational'
            policyApplied = 'Informational'
            policyLocal = 'Informational'
            policyOrder = 'NeedsAttention'
            policySecurity = 'Informational'
            policyConstraint = 'Informational'
            policyMdm = 'Informational'
            policyConflict = 'NeedsAttention'
            resourceUser = 'Informational'
            resourcePeripheral = 'Informational'
            softwareMachine = 'NeedsAttention'
            softwareUser = 'Informational'
            certificatePresence = 'ExpectedCondition'
            certificateTrust = 'ExpectedCondition'
            connectivity = 'ExpectedCondition'
            tlsInspection = 'Informational'
        }
        identity = 'NeedsAttention'
        management = 'ExpectedCondition'
        dependency = 'NeedsAttention'
        policyModernization = 'NeedsAttention'
        overall = 'NeedsAttention'
        discoveryTasks = 2
    }
    @{
        scenario = 'CrossDomain'
        localOnly = $false
        outcomes = @{
            assessmentUser = 'ExpectedCondition'
            deviceRegistration = 'NeedsAttention'
            workSchool = 'NeedsAttention'
            administrator = 'NeedsAttention'
            policyApplied = 'NeedsAttention'
            policyLocal = 'NeedsAttention'
            policyOrder = 'NeedsAttention'
            policySecurity = 'NeedsAttention'
            policyConstraint = 'NeedsAttention'
            policyMdm = 'NeedsAttention'
            policyConflict = 'NeedsAttention'
            resourceUser = 'NeedsAttention'
            resourcePeripheral = 'NeedsAttention'
            softwareMachine = 'NeedsAttention'
            softwareUser = 'NeedsAttention'
            certificatePresence = 'NeedsAttention'
            certificateTrust = 'NeedsAttention'
            connectivity = 'NeedsAttention'
            tlsInspection = 'NeedsAttention'
        }
        identity = 'NeedsAttention'
        management = 'NeedsAttention'
        dependency = 'NeedsAttention'
        policyModernization = 'NeedsAttention'
        overall = 'NeedsAttention'
        discoveryTasks = 2
    }
)

foreach ($case in $cases) {
    $record = New-SyntheticCrossDomainRecord -RunId "run:$($case.scenario.ToLowerInvariant())" `
        -Outcomes $case.outcomes -LocalOnly:$case.localOnly
    $derived = Add-CrossDomainGuidanceToAssessmentRecord -Record $record -Policy $policy

    $identityFinding = @($derived.findings | Where-Object ruleId -eq 'rule:cross-domain.identity-foundation/1.0.0')[0]
    $managementFinding = @($derived.findings | Where-Object ruleId -eq 'rule:cross-domain.management-plane/1.0.0')[0]
    $dependencyFinding = @($derived.findings | Where-Object ruleId -eq 'rule:cross-domain.dependency-transition/1.0.0')[0]
    $policyFinding = @($derived.findings | Where-Object ruleId -eq 'rule:cross-domain.policy-modernization/1.0.0')[0]
    $overallFinding = @($derived.findings | Where-Object ruleId -eq 'rule:cross-domain.zero-trust-path/1.0.0')[0]
    $crossDomainRecommendations = @($derived.recommendations | Where-Object recommendationId -like 'recommendation:cross-domain:*')
    $crossDomainRelationships = @($derived.recommendationRelationships | Where-Object relationshipId -like 'relationship:cross-domain:*')
    $crossDomainTasks = @($derived.recommendations | Where-Object {
        $_.kind -eq 'TenantSideDiscoveryTask' -and $_.recommendationId -like 'recommendation:cross-domain-task:*'
    })

    Assert-Equal $case.identity $identityFinding.outcome "$($case.scenario) derives the identity foundation outcome"
    Assert-Equal $case.management $managementFinding.outcome "$($case.scenario) derives the management-plane outcome"
    Assert-Equal $case.dependency $dependencyFinding.outcome "$($case.scenario) derives the dependency-transition outcome"
    Assert-Equal $case.policyModernization $policyFinding.outcome "$($case.scenario) derives the policy-modernization outcome"
    Assert-Equal $case.overall $overallFinding.outcome "$($case.scenario) derives the cautious migration-path outcome"
    Assert-Equal 5 $crossDomainRecommendations.Count "$($case.scenario) keeps the ordered migration path stable"
    Assert-Equal 4 $crossDomainRelationships.Count "$($case.scenario) keeps the relationship graph stable"
    Assert-Equal $case.discoveryTasks $crossDomainTasks.Count "$($case.scenario) materializes only supported tenant-side tasks"
}

$missingPrerequisiteRecord = New-SyntheticCrossDomainRecord -RunId 'run:missing-prerequisite' `
    -Outcomes @{ assessmentUser = 'ExpectedCondition' }
$missingPrerequisiteRecord.findings = @($missingPrerequisiteRecord.findings | Where-Object {
    $_.ruleId -ne 'rule:certificate.trust/1.0.0'
})
$missingPrerequisiteDerived = Add-CrossDomainGuidanceToAssessmentRecord `
    -Record $missingPrerequisiteRecord -Policy $policy
$missingPrerequisiteManagementFinding = @($missingPrerequisiteDerived.findings | Where-Object {
    $_.ruleId -eq 'rule:cross-domain.management-plane/1.0.0'
})[0]
Assert-Equal 'Indeterminate' $missingPrerequisiteManagementFinding.outcome `
    'Cross-domain guidance degrades missing prerequisite findings to Indeterminate'

Write-Output 'PASS: Cross-domain guidance derives stable findings, recommendations, discovery tasks, and relationships from synthetic combined records.'
