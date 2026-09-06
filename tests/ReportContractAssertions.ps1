Set-StrictMode -Version Latest

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
    $culture = [Globalization.CultureInfo]::CurrentCulture
    $uiCulture = [Globalization.CultureInfo]::CurrentUICulture
    $baseline = $null
    try {
        foreach ($name in @('en-US','es-MX','tr-TR','ja-JP','ar-SA')) {
            [Globalization.CultureInfo]::CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo($name)
            [Globalization.CultureInfo]::CurrentUICulture = [Globalization.CultureInfo]::GetCultureInfo($name)
            [byte[]]$rendered = New-DeviceReadinessReportBytes @inputs
            if ($null -eq $baseline) { $baseline = $rendered }
            Assert-Equal $true ([Linq.Enumerable]::SequenceEqual[byte]($baseline, $rendered)) "$name renders identical reopened canonical inputs"
            $contract = Test-AssessmentReportContract -ReportBytes $rendered -Record $record -ExpectUnicode $false
            Assert-Equal $true $contract.verified "$name retains the offline, print and keyboard structure"
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
