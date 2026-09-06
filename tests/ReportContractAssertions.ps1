Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'SoftwareReportAssertions.ps1')

function Assert-FindingEvidenceDestinations {
    param($Record, [string]$Html)
    $Html = Expand-SoftwareReportText -Html $Html
    $index = 0
    foreach ($finding in $Record.findings) {
        $pattern = if ($finding.ruleId -like 'rule:cross-domain.*') {
            '(?s)<li id="f' + $index + '">(.*?)(?=<li|</ul>)'
        } else { '(?s)<details id="f' + $index + '">(.*?)</details>' }
        $destination = [regex]::Match($Html, $pattern)
        Assert-Equal $true $destination.Success 'finding navigation opens its own evidence detail, including without cross-domain findings'
        $text = [Net.WebUtility]::HtmlDecode($destination.Groups[1].Value)
        Assert-Equal $true $text.Contains([string]$finding.findingId) 'finding destination visibly identifies the actual canonical finding'
        Assert-Equal $true $text.Contains([string]$finding.ruleId) 'finding destination identifies its exact versioned rule'
        $actual = @([regex]::Matches($text, 'href="#o(\d+)"') | ForEach-Object {
            $number = [int]$_.Groups[1].Value
            $observation = $Record.observations[$number]
            $target = [regex]::Match($Html, '(?s)<(?:td|span) id="o' + $number + '">(.*?)(?=<td|<tr|</tr>|</tbody>|</table>|</span>)')
            Assert-Equal $true $target.Success 'evidence link resolves directly to a specific rendered observation'
            Assert-Equal 1 ([regex]::Matches($Html, 'id="o' + $number + '"')).Count 'observation destination is unique'
            $value = if ($observation.valueState -eq 'ObservedValue') { [string]$observation.value } else { [string]$observation.valueState }
            $actualValue = [Net.WebUtility]::HtmlDecode($target.Groups[1].Value)
            if ($observation.valueState -eq 'ObservedAbsent' -and $actualValue -eq 'Observed absent in this source scope') { $value = 'Observed absent in this source scope' }
            if ($observation.valueState -eq 'SourceReportedUnknown' -and $actualValue -eq 'Source reported unknown') { $value = $actualValue }
            Assert-Equal $true $actualValue.Contains($value) ("linked observation $number $($observation.fieldId) retains value [$value], got [$actualValue]")
            [string]$observation.observationId
        })
        $expected = @($finding.evidenceReferences | ForEach-Object observationId)
        Assert-Equal ($expected -join '|') ($actual -join '|') 'finding destination preserves only its exact ordered observation references'
        $index++
    }
}

function Assert-ComprehensiveReportContract {
    param([Parameter(Mandatory)]$OpenedPackage)
    $record = [Text.Encoding]::UTF8.GetString($OpenedPackage.artifacts['assessment-record.json']) | ConvertFrom-Json -DateKind String
    $html = [Text.Encoding]::UTF8.GetString($OpenedPackage.artifacts['assessment-report.html'])
    foreach ($scope in $record.coverage) {
        Assert-Equal $true $html.Contains([Net.WebUtility]::HtmlEncode([string]$scope.scopeId)) 'every admitted scope is named explicitly'
    }
    $convert = $ExecutionContext.InvokeCommand.GetCommand('ConvertFrom-Json', [Management.Automation.CommandTypes]::Cmdlet)
    $inputs = @{
        Record = $record
        FirmwarePolicy = Get-FirmwareReadinessPolicy -ConvertFromJsonCommand $convert
        IdentityEnrollmentPolicy = Get-IdentityEnrollmentPolicy -ConvertFromJsonCommand $convert
        AdministratorExposurePolicy = Get-AdministratorExposurePolicy -ConvertFromJsonCommand $convert
        EffectivePolicyPolicy = Get-EffectivePolicyPolicy -ConvertFromJsonCommand $convert
        ResourceDependenciesPolicy = Get-ResourceDependenciesPolicy -ConvertFromJsonCommand $convert
        NetworkTopologyPolicy = Get-NetworkTopologyPolicy -ConvertFromJsonCommand $convert
        SoftwareInventoryPolicy = Get-SoftwareInventoryPolicy -ConvertFromJsonCommand $convert
        CertificateTrustPolicy = Get-CertificateTrustPolicy -ConvertFromJsonCommand $convert
        MicrosoftConnectivityPolicy = Get-MicrosoftConnectivityPolicy -ConvertFromJsonCommand $convert
    }
    $definitions = @{}
    foreach ($policy in @($inputs.Values) + @(Get-CrossDomainGuidancePolicy -ConvertFromJsonCommand $convert)) {
        foreach ($collection in @('recommendations','discoveryTasks')) {
            if ($policy.PSObject.Properties[$collection]) {
                foreach ($definition in $policy.$collection) { $definitions[[string]$definition.definitionId] = $definition }
            }
        }
    }
    foreach ($recommendation in $record.recommendations) {
        $definition = $definitions[[string]$recommendation.definitionId]
        foreach ($field in @('purpose','prerequisites','caution','responsibleRole','verification','authoritativeReferences','requiredRole','approvedDestination','expectedSafeResult')) {
            if (-not $definition.PSObject.Properties[$field]) { continue }
            foreach ($value in @($definition.$field)) {
                Assert-Equal $true $html.Contains([Net.WebUtility]::HtmlEncode([string]$value)) "protected report preserves recommendation $field"
            }
        }
    }
    $index = 0
    foreach ($finding in $record.findings) {
        Assert-Equal $true $html.Contains('id="f' + $index + '"') 'every canonical finding has an internal evidence destination'
        $index++
    }
    Assert-FindingEvidenceDestinations -Record $record -Html $html
    $policySets = @($record.findings | Where-Object ruleId -like 'rule:policy.*' | ForEach-Object {
        @($_.evidenceReferences | ForEach-Object observationId) -join '|'
    } | Select-Object -Unique)
    if (@($record.observations | Where-Object fieldId -like 'field:policy.*').Count -gt 0) {
        Assert-Equal $true ($policySets.Count -gt 1) 'controlled findings within policy have distinct exact evidence subsets'
    }
    # The generated, protected record is the source; removing cross-domain
    # interpretations must not remove navigation for remaining local findings.
    $incomplete = $record | ConvertTo-Json -Depth 100 | ConvertFrom-Json -DateKind String
    $incomplete.findings = @($incomplete.findings | Where-Object ruleId -notlike 'rule:cross-domain.*')
    $incomplete.recommendations = @($incomplete.recommendations | Where-Object {
        @($_.findingIds | Where-Object { $_ -notin @($incomplete.findings.findingId) }).Count -eq 0
    })
    $incomplete.coverage[0].state = 'Partial'
    $incomplete.run.outcome = 'CompletedWithGaps'
    if ($incomplete.PSObject.Properties['recommendationRelationships']) {
        $incomplete.recommendationRelationships = @($incomplete.recommendationRelationships | Where-Object {
            $_.fromRecommendationId -in @($incomplete.recommendations.recommendationId) -and
            $_.toRecommendationId -in @($incomplete.recommendations.recommendationId)
        })
    }
    $incomplete.coverage[0] | Add-Member -NotePropertyName reasonCode -NotePropertyValue 'TEST.INCOMPLETE' -Force
    $incompleteInputs = $inputs.Clone()
    $incompleteInputs.Record = $incomplete
    Assert-FindingEvidenceDestinations -Record $incomplete -Html ([Text.Encoding]::UTF8.GetString((New-DeviceReadinessReportBytes @incompleteInputs)))
    $culture = [Globalization.CultureInfo]::CurrentCulture
    $uiCulture = [Globalization.CultureInfo]::CurrentUICulture
    $baseline = $null
    $suffixRecord = $record | ConvertTo-Json -Depth 100 | ConvertFrom-Json -DateKind String
    $longNames = @($suffixRecord.observations | Where-Object {
        $_.fieldId -like 'field:software.*.display-name' -and $_.subjectId -like 'subject:software:*'
    } | Select-Object -First 2)
    if (@($record.subjects | Where-Object kind -eq Application).Count -gt 0) {
        Assert-Equal 2 $longNames.Count 'controlled maximum record supplies two separate software names'
    }
    $tail = '<' + (' & ' * 84) + ' >'
    for ($index = 0; $index -lt $longNames.Count; $index++) {
        $longNames[$index].valueState = 'ObservedValue'
        $longNames[$index] | Add-Member -NotePropertyName value -NotePropertyValue (
            [string][char](65 + $index) + ('X' * 252) + [char]::ConvertFromUtf32(0x1F600) + $tail
        ) -Force
    }
    $suffixInputs = $inputs.Clone()
    $suffixInputs.Record = $suffixRecord
    $suffixBaseline = $null
    try {
        foreach ($name in @('en-US','es-MX','tr-TR','ja-JP','ar-SA')) {
            [Globalization.CultureInfo]::CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo($name)
            [Globalization.CultureInfo]::CurrentUICulture = [Globalization.CultureInfo]::GetCultureInfo($name)
            [byte[]]$rendered = New-DeviceReadinessReportBytes @inputs
            if ($null -eq $baseline) { $baseline = $rendered }
            Assert-Equal $true ([Linq.Enumerable]::SequenceEqual[byte]($baseline, $rendered)) "$name renders identical reopened canonical inputs"
            $contract = Test-AssessmentReportContract -ReportBytes $rendered -Record $record -ExpectUnicode $false
            Assert-Equal $true $contract.verified "$name retains the offline, print and keyboard structure"
            if ($longNames.Count -ne 2) { continue }
            [byte[]]$suffixBytes = New-DeviceReadinessReportBytes @suffixInputs
            if ($null -eq $suffixBaseline) { $suffixBaseline = $suffixBytes }
            Assert-Equal $true ([Linq.Enumerable]::SequenceEqual[byte]($suffixBaseline, $suffixBytes)) "$name preserves deterministic shared Unicode suffixes"
            $suffixHtml = [Text.Encoding]::UTF8.GetString($suffixBytes)
            Assert-Equal $true $suffixHtml.Contains('[suffix 0]') 'long repeated text uses the visible exact-suffix mapping'
            $expanded = [Net.WebUtility]::HtmlDecode((Expand-SoftwareReportText -Html $suffixHtml))
            foreach ($observation in $longNames) {
                Assert-Equal $true $expanded.Contains([string]$observation.value) 'distinct prefixes, boundary emoji, escaped suffix and spaces survive exact reconstruction'
            }
        }
    } finally {
        [Globalization.CultureInfo]::CurrentCulture = $culture
        [Globalization.CultureInfo]::CurrentUICulture = $uiCulture
    }
    $sourceHash = Get-ProtectedPackageSha256 -Bytes $OpenedPackage.artifacts['assessment-report.html']
    $derived = New-DeviceReadinessReportBytes @inputs -DerivationKind ReRendered -SourceReportSha256 $sourceHash
    Assert-Equal $true ([Text.Encoding]::UTF8.GetString($derived)).Contains($sourceHash) 'derived report retains the protected original report digest'
    Write-Output 'PASS: reopened Comprehensive recommendation metadata, evidence destinations, five actual cultures and derived provenance.'
}
