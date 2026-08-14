[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/SoftwareRecognition.ps1')
$matrix = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot `
    'fixtures/software-recognition/matcher-matrix.json') | ConvertFrom-Json -Depth 10

$catalog = [pscustomobject][ordered]@{
    kind = 'win-pcinfo.software-recognition-catalog'
    schemaVersion = 1
    catalogRevision = 1
    release = '2.0.0-preview.1'
    sourceRevision = 'synthetic-test-revision'
    operation = [pscustomobject][ordered]@{
        operationId = 'annotate-software-recognition'
        executionContext = 'InProcessValidatedAssessmentRecord'
        privilege = 'StandardUser'
        networkBehavior = 'OfflineOnly'
        executableOrDependency = 'GeneratedWIN-PCInfoPowerShell'
        deadlineMilliseconds = 1000
        maximumInputEntries = 128
        maximumOutputAnnotations = 128
        maximumEvidenceUtf8Bytes = 262144
        cleanup = 'InMemoryOnly'
        mayPrompt = $false
        mayInstall = $false
        mayDownload = $false
        maySelfElevate = $false
        mayWidenScope = $false
        mayRequestAuthority = $false
        writesAllowed = $false
    }
    roles = @('DeviceManagement')
    families = @(
        [pscustomobject][ordered]@{
            familyId = 'family:synthetic.company-portal'
            label = 'Synthetic Company Portal'
            roles = @('DeviceManagement')
            lifecycle = [pscustomobject][ordered]@{
                state = 'active'; addedInRelease = '2.0.0-preview.1'
                reviewedInRelease = '2.0.0-preview.1'; reason = $null
                replacementFamilyId = $null
            }
            matchers = @([pscustomobject][ordered]@{
                matcherId = 'matcher:synthetic.company-portal.pfn'
                type = 'ExactPackageFamilyName'
                value = [string]$matrix.exactPackageFamilyName
            })
            sources = @([pscustomobject][ordered]@{
                sourceType = 'PrimaryPublisherDocumentation'
                owner = 'Synthetic Publisher'
                url = 'https://example.invalid/company-portal'
                verifiedOn = '2026-08-14'
                reviewer = 'WIN-PCInfo maintainer'
                pinnedCommit = $null
                manifestPath = $null
            })
        }
    )
}

$inventory = [pscustomobject][ordered]@{
    scopeId = 'scope:software.msix.assessment-user'
    sourceKind = 'Msix'
    registrationId = 'msix:AssessmentUser:synthetic-full-name'
    productCode = $null
    upgradeCode = $null
    packageFamilyName = [string]$matrix.exactPackageFamilyName
    packageFullName = 'Microsoft.CompanyPortal_1.0.0.0_x64__8wekyb3d8bbwe'
    displayName = 'Localized name that is not used for recognition'
    version = '1.0.0.0'
    publisher = $null
    publisherId = '8wekyb3d8bbwe'
    systemComponent = $null
    registrationContext = 'AssessmentUser'
    registryView = 'None'
    installerState = 'StatusOk'
    packageType = 'Main'
    architecture = 'x64'
}
$before = $inventory | ConvertTo-Json -Compress -Depth 10
$result = Invoke-SoftwareRecognition -Entries @($inventory) -Catalog $catalog `
    -CatalogDigest ('a' * 64)

Assert-Equal 1 @($result.annotations).Count 'one authoritative inventory entry receives one annotation'
Assert-Equal 'RecognizedExact' $result.annotations[0].outcome `
    'an exact PFN produces the strongest recognition outcome'
Assert-Equal 'family:synthetic.company-portal' $result.annotations[0].familyId `
    'the exact match resolves the reviewed family identity'
Assert-Equal 'Exact package family name' $result.annotations[0].matchStrengthExplanation `
    'the annotation explains its match strength in plain language'
Assert-Equal $before ($inventory | ConvertTo-Json -Compress -Depth 10) `
    'recognition annotates but never replaces or mutates ordinary inventory'

$nearPackage = $inventory | Select-Object *
$nearPackage.packageFamilyName = [string]$matrix.nearPackageFamilyName
$nearPackageResult = Invoke-SoftwareRecognition -Entries @($nearPackage) -Catalog $catalog `
    -CatalogDigest ('a' * 64)
Assert-Equal 'Unrecognized' $nearPackageResult.annotations[0].outcome `
    'a package-family prefix or near match is not an exact Windows identity'

$msiFamily = $catalog.families[0] | Select-Object *
$msiFamily.familyId = 'family:synthetic.msi-agent'
$msiFamily.label = 'Synthetic MSI Agent'
$msiFamily.matchers = @([pscustomobject][ordered]@{
    matcherId = 'matcher:synthetic.msi-agent.product-code'
    type = 'ExactMsiProductCode'
    value = [string]$matrix.exactMsiProductCode
})
$msiEntry = $inventory | Select-Object *
$msiEntry.sourceKind = 'Msi'
$msiEntry.packageFamilyName = $null
$msiEntry.productCode = [string]$matrix.exactMsiProductCode
$msiCatalog = $catalog | Select-Object *
$msiCatalog.families = @($msiFamily)
$msiResult = Invoke-SoftwareRecognition -Entries @($msiEntry) -Catalog $msiCatalog `
    -CatalogDigest ('b' * 64)
Assert-Equal 'RecognizedExact' $msiResult.annotations[0].outcome `
    'an exact MSI ProductCode is a strong identity match'
Assert-Equal 'Exact MSI ProductCode' $msiResult.annotations[0].matchStrengthExplanation `
    'the MSI identity strength is explained without a compatibility claim'

$upgradeFamily = $catalog.families[0] | Select-Object *
$upgradeFamily.familyId = 'family:synthetic.msi-upgrade-family'
$upgradeFamily.label = 'Synthetic MSI Upgrade Family'
$upgradeFamily.matchers = @([pscustomobject][ordered]@{
    matcherId = 'matcher:synthetic.msi-upgrade-family.upgrade-code'
    type = 'ExactMsiUpgradeCode'
    value = [string]$matrix.exactMsiUpgradeCode
})
$upgradeCatalog = $catalog | Select-Object *
$upgradeCatalog.families = @($upgradeFamily)
$upgradeEntry = $msiEntry | Select-Object *
$upgradeEntry.productCode = $null
$upgradeEntry.upgradeCode = [string]$matrix.exactMsiUpgradeCode
$upgradeResult = Invoke-SoftwareRecognition -Entries @($upgradeEntry) `
    -Catalog $upgradeCatalog -CatalogDigest ('b' * 64)
Assert-Equal 'RecognizedExact' $upgradeResult.annotations[0].outcome `
    'an exact MSI UpgradeCode is a strong identity match'
Assert-Equal 'Exact MSI UpgradeCode' $upgradeResult.annotations[0].matchStrengthExplanation `
    'the UpgradeCode identity strength is explicit in the annotation'
$entryWithoutUpgradeCode = $inventory | Select-Object * -ExcludeProperty upgradeCode
$missingUpgradeResult = Invoke-SoftwareRecognition -Entries @($entryWithoutUpgradeCode) `
    -Catalog $upgradeCatalog -CatalogDigest ('b' * 64)
Assert-Equal 'Unrecognized' $missingUpgradeResult.annotations[0].outcome `
    'an unavailable optional MSI identity cannot turn catalog evaluation into a logical failure'

$compositeFamily = $catalog.families[0] | Select-Object *
$compositeFamily.familyId = 'family:synthetic.unicode-vpn'
$compositeFamily.label = 'Synthetic Unicode VPN'
$compositeFamily.matchers = @([pscustomobject][ordered]@{
    matcherId = 'matcher:synthetic.unicode-vpn.registration'
    type = 'CompositeRegistration'
    registrationContext = [string]$matrix.composite.registrationContext
    registryView = [string]$matrix.composite.registryView
    fields = [pscustomobject][ordered]@{
        registrationId = [string]$matrix.composite.registrationId
        displayName = [string]$matrix.composite.displayName
        publisher = [string]$matrix.composite.publisher
    }
})
$compositeCatalog = $catalog | Select-Object *
$compositeCatalog.families = @($compositeFamily)
$compositeEntry = $inventory | Select-Object *
$compositeEntry.sourceKind = 'Registry'
$compositeEntry.packageFamilyName = $null
$compositeEntry.registrationId = [string]$matrix.composite.registrationId
$compositeEntry.displayName = [string]$matrix.composite.displayName
$compositeEntry.publisher = [string]$matrix.composite.publisher
$compositeEntry.registrationContext = [string]$matrix.composite.registrationContext
$compositeEntry.registryView = [string]$matrix.composite.registryView
$compositeResult = Invoke-SoftwareRecognition -Entries @($compositeEntry) `
    -Catalog $compositeCatalog -CatalogDigest ('c' * 64)
Assert-Equal 'RecognizedComposite' $compositeResult.annotations[0].outcome `
    'a fully satisfied contextual Unicode registration composite is recognized'
Assert-Equal 'Exact registration-field composite in Machine Registry64 context' `
    $compositeResult.annotations[0].matchStrengthExplanation `
    'the composite explanation names its explicit context'

$nearMatch = $compositeEntry | Select-Object *
$nearMatch.registrationContext = [string]$matrix.nearCompositeContext
$nearResult = Invoke-SoftwareRecognition -Entries @($nearMatch) `
    -Catalog $compositeCatalog -CatalogDigest ('c' * 64)
Assert-Equal 'Unrecognized' $nearResult.annotations[0].outcome `
    'matching display name, publisher, and registration key cannot bypass an explicit context mismatch'

$conflictingFamily = $catalog.families[0] | Select-Object *
$conflictingFamily.familyId = 'family:synthetic.conflict'
$conflictingFamily.label = 'Synthetic Conflicting Family'
$conflictingFamily.matchers = @([pscustomobject][ordered]@{
    matcherId = 'matcher:synthetic.conflict.pfn'
    type = 'ExactPackageFamilyName'
    value = [string]$matrix.exactPackageFamilyName
})
$orderedCatalog = $catalog | Select-Object *
$orderedCatalog.families = @($catalog.families[0], $conflictingFamily)
$reversedCatalog = $catalog | Select-Object *
$reversedCatalog.families = @($conflictingFamily, $catalog.families[0])
foreach ($candidateCatalog in @($orderedCatalog, $reversedCatalog)) {
    $ambiguous = Invoke-SoftwareRecognition -Entries @($inventory) `
        -Catalog $candidateCatalog -CatalogDigest ('d' * 64)
    Assert-Equal 'Ambiguous' $ambiguous.annotations[0].outcome `
        'cross-family identity conflicts are ambiguous in every catalog order'
    Assert-Equal 0 @($ambiguous.annotations[0].roles).Count `
        'ambiguity cannot inherit roles from whichever family appeared first'
}

$logicalFailure = Invoke-SoftwareRecognitionSafely -Entries @($inventory, $msiEntry) `
    -Catalog ([pscustomobject]@{ kind = 'malformed-logical-catalog' }) `
    -CatalogDigest ('e' * 64)
Assert-Equal 'NotEvaluated' $logicalFailure.state `
    'a logical catalog-load or evaluation failure is confined to recognition'
Assert-Equal 2 @($logicalFailure.annotations).Count `
    'every authoritative inventory entry remains accounted for when recognition fails'
foreach ($annotation in @($logicalFailure.annotations)) {
    Assert-Equal 'NotEvaluated' $annotation.outcome `
        'logical catalog failure never changes an application into unknown or removes it'
    Assert-Equal 'SOFTWARE_RECOGNITION.CATALOG_LOGICAL_FAILURE' $annotation.reasonCode `
        'safe failure gives a stable non-warning explanation'
}

Write-Output 'PASS: exact package identity is a non-destructive Software Recognition annotation.'
