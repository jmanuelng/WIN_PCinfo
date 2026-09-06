Set-StrictMode -Version Latest

$script:CrossDomainGuidancePolicyBase64 = '__CROSS_DOMAIN_GUIDANCE_POLICY_BASE64__'
$script:CrossDomainGuidancePolicyDigest = '__CROSS_DOMAIN_GUIDANCE_POLICY_SHA256__'

function Get-CrossDomainGuidancePolicy {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    # The generated application carries the frozen release policy inline. Hash
    # the exact UTF-8 bytes before parsing so a truncated build artifact or a
    # local text edit cannot silently change the privacy bounds or migration
    # advice. Safe failure here is to stop before any guidance is derived.
    if ($script:CrossDomainGuidancePolicyBase64 -eq ('__CROSS_DOMAIN_' + 'GUIDANCE_POLICY_BASE64__')) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-cross-domain-guidance.json'
        $bytes = Get-CanonicalSupervisorTextBytes -LiteralPath $path
        $expectedDigest = Get-Sha256ForSupervisorBytes -Bytes $bytes
    }
    else {
        $bytes = [System.Convert]::FromBase64String($script:CrossDomainGuidancePolicyBase64)
        $expectedDigest = $script:CrossDomainGuidancePolicyDigest
    }
    if ((Get-Sha256ForSupervisorBytes -Bytes $bytes) -ne $expectedDigest) {
        throw 'The Cross-domain Guidance policy failed integrity validation.'
    }

    $policy = & $ConvertFromJsonCommand -InputObject (
        [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    ) -Depth 20 -ErrorAction Stop
    if ($policy.kind -ne 'win-pcinfo.cross-domain-guidance-policy' -or
        $policy.release -ne '2.0.0-preview.1' -or
        @($policy.authoritativeSources).Count -ne 4 -or
        @($policy.rules).Count -ne 5 -or
        @($policy.recommendations).Count -ne 5 -or
        @($policy.discoveryTasks).Count -ne 3 -or
        @($policy.relationships).Count -ne 4 -or
        (@($policy.migrationPath) -join '|') -ne (
            'recommendation:cross-domain.review-identity-foundation/1.0.0|' +
            'recommendation:cross-domain.review-connectivity-and-trust/1.0.0|' +
            'recommendation:cross-domain.plan-dependency-transition/1.0.0|' +
            'recommendation:cross-domain.plan-policy-modernization/1.0.0|' +
            'recommendation:cross-domain.stage-compliant-device-access/1.0.0'
        )) {
        throw 'The Cross-domain Guidance policy is not the closed release policy.'
    }
    $policy
}

function Get-CrossDomainRuleDefinition {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string] $FindingKind
    )

    $Policy.rules | Where-Object findingKind -eq $FindingKind | Select-Object -First 1
}

function Get-CrossDomainFirstOrNull {
    param([Parameter()] $InputObject)

    @($InputObject | Select-Object -First 1 | ForEach-Object { $_ }) | Select-Object -First 1
}

function Get-CrossDomainDefinitionSuffix {
    param([Parameter(Mandatory)] [string] $DefinitionId)

    $parts = $DefinitionId.Split(':', 2)
    if ($parts.Count -ne 2) {
        throw 'A cross-domain definition identifier is malformed.'
    }
    ([string] $parts[1]).Split('/', 2)[0]
}

function Get-CrossDomainInstanceName {
    param([Parameter(Mandatory)] [string] $DefinitionId)

    $suffix = Get-CrossDomainDefinitionSuffix -DefinitionId $DefinitionId
    $parts = $suffix.Split('.', 2)
    if ($parts.Count -ne 2) {
        throw 'A cross-domain instance identifier could not be derived.'
    }
    [string] $parts[1]
}

function Get-CrossDomainFindingByRuleId {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] [string] $RuleId
    )

    # Focused fixture seams can omit earlier slice findings entirely. Preserve
    # that absence as an explicit sentinel so the rollup can degrade to
    # Indeterminate instead of silently treating a missing prerequisite as if
    # the rule had never existed.
    $findings = @($Record.findings | Where-Object ruleId -eq $RuleId)
    if ($findings.Count -lt 1) {
        return ,([pscustomobject][ordered]@{
                missingSourceRuleId = $RuleId
            })
    }
    @($findings)
}

function Get-CrossDomainEvidenceReferences {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings
    )

    # Cross-domain findings must remain traceable to the admitted observations,
    # not to prose or to a transient in-memory summary. Reusing the exact
    # evidence references keeps the derived report auditable without reopening
    # collector payloads or copying sensitive values into public output.
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    $references = [System.Collections.Generic.List[object]]::new()
    foreach ($finding in $Findings) {
        if ($null -eq $finding -or $null -ne $finding.PSObject.Properties['missingSourceRuleId']) {
            continue
        }
        foreach ($reference in @($finding.evidenceReferences)) {
            $key = ([string] $reference.observationId) + '|' +
                ([string] $reference.fieldId) + '|' +
                ([string] $reference.subjectId)
            if ($seen.Add($key)) {
                if ($references.Count -ge 16) { break }
                $references.Add([pscustomobject][ordered]@{
                    observationId = [string] $reference.observationId
                    fieldId = [string] $reference.fieldId
                    subjectId = [string] $reference.subjectId
                })
            }
        }
        if ($references.Count -ge 16) { break }
    }
    @($references)
}

function Get-CrossDomainDerivedOutcome {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $SourceFindings,
        [Parameter(Mandatory)] $Rule,
        [Parameter()] [switch] $Overall
    )

    if ($SourceFindings.Count -lt 1 -or
        @($SourceFindings | Where-Object {
            $null -eq $_ -or $null -ne $_.PSObject.Properties['missingSourceRuleId']
        }).Count -gt 0) {
        return [pscustomobject]@{
            outcome = 'Indeterminate'
            reasonCode = [string] $Rule.indeterminateReasonCode
        }
    }

    $outcomes = @($SourceFindings | ForEach-Object { [string] $_.outcome })
    if ($Overall) {
        if (@($outcomes | Where-Object { $_ -eq 'Indeterminate' }).Count -gt 0) {
            return [pscustomobject]@{
                outcome = 'Indeterminate'
                reasonCode = [string] $Rule.indeterminateReasonCode
            }
        }
        if (@($outcomes | Where-Object { $_ -eq 'NeedsAttention' }).Count -gt 0) {
            return [pscustomobject]@{ outcome = 'NeedsAttention' }
        }
        return [pscustomobject]@{ outcome = 'ExpectedCondition' }
    }

    if (@($outcomes | Where-Object { $_ -eq 'Indeterminate' }).Count -gt 0) {
        return [pscustomobject]@{
            outcome = 'Indeterminate'
            reasonCode = [string] $Rule.indeterminateReasonCode
        }
    }
    # Certificate and enrollment prerequisites can be purpose-specific. A
    # generic HTTPS success does not prove that the enrollment certificate path
    # or purpose-specific trust chain is acceptable for the tenant's design. If
    # one prerequisite is NotApplicable, fail toward operator review instead of
    # overstating cloud-readiness from the partial success.
    if ([string] $Rule.findingKind -eq 'management-plane' -and
        @($outcomes | Where-Object { $_ -eq 'NotApplicable' }).Count -gt 0) {
        return [pscustomobject]@{ outcome = 'NeedsAttention' }
    }
    if (@($outcomes | Where-Object { $_ -eq 'NeedsAttention' }).Count -gt 0) {
        return [pscustomobject]@{ outcome = 'NeedsAttention' }
    }
    if (@($outcomes | Where-Object { $_ -eq 'ExpectedCondition' }).Count -gt 0) {
        if (@($outcomes | Where-Object { $_ -eq 'Informational' }).Count -gt 0) {
            return [pscustomobject]@{ outcome = 'ExpectedCondition' }
        }
        return [pscustomobject]@{ outcome = 'ExpectedCondition' }
    }
    [pscustomobject]@{ outcome = 'Informational' }
}

function New-CrossDomainFinding {
    param(
        [Parameter(Mandatory)] $Rule,
        [Parameter(Mandatory)] [string] $RunId,
        [Parameter(Mandatory)] [string] $TargetSubjectId,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $SourceFindings,
        [Parameter(Mandatory)] $OutcomeResult
    )

    $finding = [ordered]@{
        findingId = "finding:cross-domain.$([string] $Rule.findingKind):$RunId"
        ruleId = [string] $Rule.ruleId
        targetSubjectId = $TargetSubjectId
        outcome = [string] $OutcomeResult.outcome
        evidenceReferences = @(Get-CrossDomainEvidenceReferences -Findings $SourceFindings)
    }
    if ([string] $OutcomeResult.outcome -in @('Indeterminate', 'NotApplicable')) {
        $finding.reasonCode = [string] $OutcomeResult.reasonCode
    }
    [pscustomobject] $finding
}

function Get-CrossDomainTaskDefinitionIds {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $SourceFindings
    )

    $overallFinding = Get-CrossDomainFirstOrNull ($Findings | Where-Object ruleId -eq 'rule:cross-domain.zero-trust-path/1.0.0')
    $managementFinding = Get-CrossDomainFirstOrNull ($Findings | Where-Object ruleId -eq 'rule:cross-domain.management-plane/1.0.0')
    $policyFinding = Get-CrossDomainFirstOrNull ($Findings | Where-Object ruleId -eq 'rule:cross-domain.policy-modernization/1.0.0')
    $networkLocalOnly = Get-CrossDomainFirstOrNull ($SourceFindings | Where-Object {
        $_.ruleId -eq 'rule:network.local-only-coverage/1.0.0'
    })

    $taskIds = [System.Collections.Generic.List[string]]::new()
    $taskIds.Add('task:cross-domain.confirm-conditional-access-target/1.0.0')
    $taskIds.Add('task:cross-domain.confirm-advanced-security-target/1.0.0')
    if ([string] $managementFinding.outcome -eq 'Indeterminate' -or
        ($null -ne $networkLocalOnly -and [string] $networkLocalOnly.outcome -eq 'NeedsAttention') -or
        [string] $overallFinding.outcome -eq 'Indeterminate' -or
        [string] $policyFinding.outcome -eq 'Indeterminate') {
        $taskIds.Add('task:cross-domain.confirm-tenant-enrollment-path/1.0.0')
    }
    @($taskIds)
}

function Add-CrossDomainGuidanceToAssessmentRecord {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $Policy
    )

    if (@($Record.findings | Where-Object ruleId -like 'rule:cross-domain.*').Count -gt 0) {
        throw 'Cross-domain guidance is already present in the Assessment Record.'
    }

    $targetSubjectId = 'subject:device:primary'
    $runId = [string] $Record.run.runId
    $record = [pscustomobject] $Record.PSObject.Copy()
    $record.findings = @($Record.findings)
    $record.recommendations = @($Record.recommendations)
    $record.recommendationRelationships = @($Record.recommendationRelationships)

    $newFindings = [System.Collections.Generic.List[object]]::new()
    foreach ($findingKind in @(
            'identity-foundation',
            'management-plane',
            'dependency-transition',
            'policy-modernization')) {
        $rule = Get-CrossDomainRuleDefinition -Policy $Policy -FindingKind $findingKind
        $sourceFindings = @($rule.sourceRuleIds | ForEach-Object {
            Get-CrossDomainFindingByRuleId -Record $record -RuleId ([string] $_)
        })
        $outcome = Get-CrossDomainDerivedOutcome -SourceFindings @($sourceFindings) -Rule $rule
        $newFindings.Add((New-CrossDomainFinding -Rule $rule -RunId $runId `
                -TargetSubjectId $targetSubjectId -SourceFindings @($sourceFindings) `
                -OutcomeResult $outcome))
    }

    $overallRule = Get-CrossDomainRuleDefinition -Policy $Policy -FindingKind 'zero-trust-path'
    $overallOutcome = Get-CrossDomainDerivedOutcome -SourceFindings @($newFindings) `
        -Rule $overallRule -Overall
    $newFindings.Add((New-CrossDomainFinding -Rule $overallRule -RunId $runId `
            -TargetSubjectId $targetSubjectId -SourceFindings @($newFindings) `
            -OutcomeResult $overallOutcome))

    $record.findings = @($record.findings) + @($newFindings)

    $recommendationIdByDefinition = @{}
    foreach ($definitionId in @($Policy.migrationPath)) {
        $definition = Get-CrossDomainFirstOrNull ($Policy.recommendations | Where-Object definitionId -eq $definitionId)
        $ruleDefinition = Get-CrossDomainRuleDefinition -Policy $Policy `
            -FindingKind ([string] $definition.findingKind)
        $finding = Get-CrossDomainFirstOrNull ($newFindings | Where-Object {
            $_.ruleId -eq [string] $ruleDefinition.ruleId
        })
        if ($null -eq $definition -or $null -eq $finding) {
            throw 'A cross-domain recommendation did not resolve to its frozen finding.'
        }
        $suffix = Get-CrossDomainInstanceName -DefinitionId ([string] $definition.definitionId)
        $recommendationId = 'recommendation:cross-domain:{0}:{1}' -f $suffix, $runId
        $recommendationIdByDefinition[[string] $definition.definitionId] = $recommendationId
        $record.recommendations = @($record.recommendations) + [pscustomobject][ordered]@{
            recommendationId = $recommendationId
            definitionId = [string] $definition.definitionId
            kind = 'AssessmentRecommendation'
            findingIds = @([string] $finding.findingId)
        }
    }

    $taskDefinitionIds = Get-CrossDomainTaskDefinitionIds -Policy $Policy `
        -Findings @($newFindings) -SourceFindings @($Record.findings)
    foreach ($definitionId in $taskDefinitionIds) {
        $definition = Get-CrossDomainFirstOrNull ($Policy.discoveryTasks | Where-Object definitionId -eq $definitionId)
        $ruleDefinition = Get-CrossDomainRuleDefinition -Policy $Policy `
            -FindingKind ([string] $definition.findingKind)
        $finding = Get-CrossDomainFirstOrNull ($newFindings | Where-Object {
            $_.ruleId -eq [string] $ruleDefinition.ruleId
        })
        if ($null -eq $definition -or $null -eq $finding) {
            throw 'A cross-domain discovery task did not resolve to its frozen finding.'
        }
        $suffix = Get-CrossDomainInstanceName -DefinitionId ([string] $definition.definitionId)
        $record.recommendations = @($record.recommendations) + [pscustomobject][ordered]@{
            recommendationId = 'recommendation:cross-domain-task:{0}:{1}' -f $suffix, $runId
            definitionId = [string] $definition.definitionId
            kind = 'TenantSideDiscoveryTask'
            findingIds = @([string] $finding.findingId)
        }
    }

    foreach ($relationship in @($Policy.relationships)) {
        $fromId = [string] $recommendationIdByDefinition[[string] $relationship.fromDefinitionId]
        $toId = [string] $recommendationIdByDefinition[[string] $relationship.toDefinitionId]
        if ([string]::IsNullOrWhiteSpace($fromId) -or [string]::IsNullOrWhiteSpace($toId)) {
            throw 'A cross-domain relationship did not resolve to its frozen recommendations.'
        }
        $record.recommendationRelationships = @($record.recommendationRelationships) + `
            [pscustomobject][ordered]@{
                relationshipId = 'relationship:cross-domain:{0}:{1}' -f (
                    Get-CrossDomainInstanceName -DefinitionId ([string] $relationship.relationshipId)
                ), $runId
                fromRecommendationId = $fromId
                toRecommendationId = $toId
                kind = [string] $relationship.kind
            }
    }

    $record
}

function Get-CrossDomainGuidanceModel {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $Policy
    )

    $ruleById = @{}
    foreach ($rule in @($Policy.rules)) {
        $ruleById[[string] $rule.ruleId] = $rule
    }
    $recommendationById = @{}
    foreach ($definition in @($Policy.recommendations)) {
        $recommendationById[[string] $definition.definitionId] = $definition
    }
    $taskById = @{}
    foreach ($definition in @($Policy.discoveryTasks)) {
        $taskById[[string] $definition.definitionId] = $definition
    }
    $relationshipByDefinitionId = @{}
    foreach ($relationship in @($Policy.relationships)) {
        $relationshipByDefinitionId[[string] $relationship.relationshipId] = $relationship
    }

    $findings = @($Record.findings | Where-Object ruleId -like 'rule:cross-domain.*')
    $recommendations = @($Record.recommendations | Where-Object {
        $recommendationById.ContainsKey([string] $_.definitionId) -or
        $taskById.ContainsKey([string] $_.definitionId)
    })
    if ($findings.Count -eq 0) {
        return [pscustomobject][ordered]@{
            findings = @()
            pathRecommendations = @()
            tasks = @()
            relationships = @()
        }
    }
    $pathRecommendations = @(
        foreach ($definitionId in @($Policy.migrationPath)) {
            $recordRecommendation = Get-CrossDomainFirstOrNull ($recommendations | Where-Object definitionId -eq $definitionId)
            if ($null -eq $recordRecommendation) { continue }
            $definition = $recommendationById[[string] $definitionId]
            $findingId = if (@($recordRecommendation.findingIds).Count -gt 0) {
                [string] @($recordRecommendation.findingIds)[0]
            }
            else { '' }
            $finding = Get-CrossDomainFirstOrNull ($findings | Where-Object findingId -eq $findingId)
            $confidence = if ($null -ne $finding -and [string] $finding.outcome -ne 'Indeterminate') {
                'High'
            }
            else { $null }
            $severity = if ($null -ne $finding -and [string] $finding.outcome -eq 'NeedsAttention') {
                [string] (Get-CrossDomainRuleDefinition -Policy $Policy `
                    -FindingKind ([string] $definition.findingKind)).severityWhenNeedsAttention
            }
            else { $null }
            [pscustomobject][ordered]@{
                recommendationId = [string] $recordRecommendation.recommendationId
                findingId = $findingId
                definitionId = [string] $definition.definitionId
                title = [string] $definition.title
                purpose = [string] $definition.purpose
                priority = [string] $definition.priority
                priorityExplanation = [string] $definition.priorityExplanation
                prerequisites = @($definition.prerequisites)
                caution = [string] $definition.caution
                responsibleRole = [string] $definition.responsibleRole
                verification = [string] $definition.verification
                authoritativeReferences = @($definition.authoritativeReferences)
                findingOutcome = if ($null -eq $finding) { 'Indeterminate' } else { [string] $finding.outcome }
                confidence = $confidence
                severity = $severity
            }
        }
    )
    $tasks = @(
        foreach ($recordRecommendation in @($recommendations | Where-Object kind -eq 'TenantSideDiscoveryTask')) {
            $definition = $taskById[[string] $recordRecommendation.definitionId]
            if ($null -eq $definition) { continue }
            [pscustomobject][ordered]@{
                recommendationId = [string] $recordRecommendation.recommendationId
                definitionId = [string] $definition.definitionId
                purpose = [string] $definition.purpose
                requiredRole = [string] $definition.requiredRole
                approvedDestination = [string] $definition.approvedDestination
                expectedSafeResult = [string] $definition.expectedSafeResult
                authoritativeReferences = @($definition.authoritativeReferences)
            }
        }
    )
    $relationships = @(
        foreach ($recordRelationship in @($Record.recommendationRelationships | Where-Object relationshipId -like 'relationship:cross-domain:*')) {
            $definition = Get-CrossDomainFirstOrNull ($Policy.relationships | Where-Object {
                [string] $recordRelationship.relationshipId -like ("relationship:cross-domain:{0}:*" -f (
                    Get-CrossDomainInstanceName -DefinitionId ([string] $_.relationshipId)
                ))
            })
            if ($null -eq $definition) { continue }
            [pscustomobject][ordered]@{
                relationshipId = [string] $recordRelationship.relationshipId
                fromRecommendationId = [string] $recordRelationship.fromRecommendationId
                toRecommendationId = [string] $recordRelationship.toRecommendationId
                kind = [string] $recordRelationship.kind
                explanation = [string] $definition.explanation
            }
        }
    )

    [pscustomobject][ordered]@{
        findings = @($findings | ForEach-Object {
            $rule = $ruleById[[string] $_.ruleId]
            [pscustomobject][ordered]@{
                findingId = [string] $_.findingId
                ruleId = [string] $_.ruleId
                findingKind = [string] $rule.findingKind
                title = [string] $rule.title
                outcome = [string] $_.outcome
                severity = if ([string] $_.outcome -eq 'NeedsAttention') {
                    [string] $rule.severityWhenNeedsAttention
                } else { $null }
                confidence = if ([string] $_.outcome -eq 'Indeterminate') { $null } else { 'High' }
            }
        })
        pathRecommendations = $pathRecommendations
        tasks = $tasks
        relationships = $relationships
    }
}

function Get-AssessmentReportFindingAnchors {
    param([Parameter(Mandatory)]$Record)
    $anchors = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($finding in $Record.findings) { $anchors.Add([string]$finding.findingId, 'f' + $anchors.Count) }
    $anchors
}

function New-CrossDomainGuidanceHtml {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $Policy,
        [Parameter()] $ReferenceLookup
    )

    $model = Get-CrossDomainGuidanceModel -Record $Record -Policy $Policy
    if (@($model.findings).Count -eq 0) { return '' }
    # Record-order aliases are stable for identical canonical rendering inputs.
    $anchors = Get-AssessmentReportFindingAnchors -Record $Record

    $findingRows = @($model.findings | ForEach-Object {
        $findingId = [string]$_.findingId
        $ruleId = [string]$_.ruleId
        $rule = @($Policy.rules | Where-Object ruleId -eq $ruleId)[0]
        $sources = @($Record.findings | Where-Object ruleId -in @($rule.sourceRuleIds) | ForEach-Object {
            $key = [string]$_.findingId
            $suffix = ':' + [string]$Record.run.runId
            if ($key.EndsWith($suffix, [StringComparison]::Ordinal)) { $key = $key.Substring(0, $key.Length - $suffix.Length) }
            '<a href="#' + [Net.WebUtility]::HtmlEncode([string]$anchors[[string]$_.findingId]) + '">' +
                [Net.WebUtility]::HtmlEncode($key.Replace('finding:', '')) + '</a>: ' +
                [Net.WebUtility]::HtmlEncode([string]$_.outcome)
        }) -join ', '
        $severity = if ($null -eq $_.severity) { '' } else {
            '<br><strong>Severity:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.severity)
        }
        $confidence = if ($null -eq $_.confidence) { '' } else {
            '<br><strong>Confidence:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.confidence)
        }
        '<li id="' + [Net.WebUtility]::HtmlEncode([string]$anchors[$findingId]) + '"><strong>' + [Net.WebUtility]::HtmlEncode([string] $_.title) + ':</strong> ' +
        [Net.WebUtility]::HtmlEncode([string] $_.outcome) + $severity + $confidence +
        '<br>Source findings: ' + $sources + '</li>'
    })
    $stepRows = @($model.pathRecommendations | ForEach-Object {
        $prerequisites = @($_.prerequisites | ForEach-Object {
            [Net.WebUtility]::HtmlEncode([string] $_)
        }) -join '; '
        $references = if ($null -ne $ReferenceLookup) {
            New-AssessmentReportReferenceLinks -References @($_.authoritativeReferences) -Lookup $ReferenceLookup
        } else { @($_.authoritativeReferences | ForEach-Object {
            [Net.WebUtility]::HtmlEncode([string] $_)
        }) -join '; ' }
        '<li id="'+[Net.WebUtility]::HtmlEncode([string]$_.recommendationId)+'"><strong>' + [Net.WebUtility]::HtmlEncode([string] $_.priority) + ':</strong> ' +
        [Net.WebUtility]::HtmlEncode([string] $_.title) +
        '<br><a href="#' + $anchors[[string]$_.findingId] + '">Finding and evidence</a>' +
        '<br><strong>Current finding:</strong> ' + [Net.WebUtility]::HtmlEncode([string] $_.findingOutcome) +
        '<br><b>Purpose:</b> ' + [Net.WebUtility]::HtmlEncode([string] $_.purpose) +
        '<br><b>Why now:</b> ' + [Net.WebUtility]::HtmlEncode([string] $_.priorityExplanation) +
        '<br><b>Prerequisites:</b> ' + $prerequisites +
        '<br><b>Owner:</b> ' + [Net.WebUtility]::HtmlEncode([string] $_.responsibleRole) +
        '<br><b>Verification:</b> ' + [Net.WebUtility]::HtmlEncode([string] $_.verification) +
        '<br><b>Caution:</b> ' + [Net.WebUtility]::HtmlEncode([string] $_.caution) +
        '<br><b>Authoritative references:</b> ' + $references + '</li>'
    })
    $relationshipRows = @($model.relationships | ForEach-Object {
        '<li><strong>' + [Net.WebUtility]::HtmlEncode([string] $_.kind) + ':</strong> ' +
        '<a href="#' + [Net.WebUtility]::HtmlEncode([string]$_.fromRecommendationId) + '">From recommendation</a> → ' +
        '<a href="#' + [Net.WebUtility]::HtmlEncode([string]$_.toRecommendationId) + '">To recommendation</a>. ' +
        [Net.WebUtility]::HtmlEncode([string] $_.explanation) + '</li>'
    })
    $taskRows = @($model.tasks | ForEach-Object {
        $references = if ($null -ne $ReferenceLookup) {
            New-AssessmentReportReferenceLinks -References @($_.authoritativeReferences) -Lookup $ReferenceLookup
        } else { [Net.WebUtility]::HtmlEncode((@($_.authoritativeReferences) -join '; ')) }
        '<li id="'+[Net.WebUtility]::HtmlEncode([string]$_.recommendationId)+'"><b>Purpose:</b> ' + [Net.WebUtility]::HtmlEncode([string] $_.purpose) +
        '<br><b>Owner:</b> ' + [Net.WebUtility]::HtmlEncode([string] $_.requiredRole) +
        '<br><b>Approved destination:</b> ' + [Net.WebUtility]::HtmlEncode([string] $_.approvedDestination) +
        '<br><b>Expected safe result:</b> ' + [Net.WebUtility]::HtmlEncode([string] $_.expectedSafeResult) +
        '<br>Authoritative references: ' + $references + '</li>'
    })

@"
<h2>Cross-domain findings and cautious migration path</h2>
<p>This section uses only the validated local Assessment Record plus release-versioned Microsoft guidance. It is advisory only: WIN-PCInfo does not produce a score, compliance verdict, fixed schedule, or automatic remediation plan.</p>
<h3>Cross-domain findings</h3><ul>$($findingRows -join '')</ul>
<p>Finding keys omit the canonical run suffix :$([Net.WebUtility]::HtmlEncode([string]$Record.run.runId)).</p>
<h3>Ordered Microsoft Zero Trust migration path</h3><ol>$($stepRows -join '')</ol>
<h3>Relationship notes</h3><ul>$($relationshipRows -join '')</ul>
<h3>Tenant-side Discovery Tasks</h3><ul>$($taskRows -join '')</ul>
"@
}
