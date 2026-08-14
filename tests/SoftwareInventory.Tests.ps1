[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/SoftwareInventory.ps1')
$json = Get-Command ConvertFrom-Json -CommandType Cmdlet
$policy = Get-SoftwareInventoryPolicy -ConvertFromJsonCommand $json

$cases = @(
    @{scenario='RegistryViews';count=4},
    @{scenario='UserAndMachine';count=6},
    @{scenario='MsiStates';count=2},
    @{scenario='PackageTypes';count=5},
    @{scenario='Duplicates';count=3},
    @{scenario='ArbitraryVersions';count=2},
    @{scenario='Unicode';count=3},
    @{scenario='Empty';count=0},
    @{scenario='AggregateMaximum';count=128}
)
foreach ($case in $cases) {
    $result = Invoke-SoftwareInventoryCollection -Policy $policy `
        -ValidationScenario $case.scenario
    Assert-Equal $true (Test-SoftwareInventoryCollectorPayload `
        -Payload $result.payload -Policy $policy) `
        "$($case.scenario) satisfies the closed payload contract"
    Assert-Equal $case.count @($result.payload.entries).Count `
        "$($case.scenario) preserves the expected source registrations"
    Assert-Equal $true $result.cleanupVerified `
        "$($case.scenario) owns no surviving process or artifact"
}

$duplicates = (Invoke-SoftwareInventoryCollection -Policy $policy `
    -ValidationScenario Duplicates).payload
Assert-Equal 3 @($duplicates.entries).Count `
    'matching display names and publishers do not collapse distinct registrations'
Assert-Equal 3 @($duplicates.entries.registrationId | Sort-Object -Unique).Count `
    'source registration identities, not presentation text, preserve ambiguity'

$versions = (Invoke-SoftwareInventoryCollection -Policy $policy `
    -ValidationScenario ArbitraryVersions).payload
Assert-Equal 'release-2026.08+hotfix|vNext-preview_α' `
    (@($versions.entries.version) -join '|') `
    'desktop version evidence remains bounded text rather than assumed semantic versions'

$types = (Invoke-SoftwareInventoryCollection -Policy $policy `
    -ValidationScenario PackageTypes).payload
Assert-Equal 'Bundle|Framework|Main|Optional|Resource' `
    ((@($types.entries.packageType) | Sort-Object) -join '|') `
    'the five release-owned packaged application types remain distinct'

$allUsersDenied = (Invoke-SoftwareInventoryCollection -Policy $policy `
    -ValidationScenario DeniedAllUsers).payload
$allUsersState = @($allUsersDenied.scopeStates | Where-Object `
    scopeId -eq 'scope:software.msix.machine')[0]
Assert-Equal 'Denied' $allUsersState.state `
    'all-user package access denial stays in its declared scope'
Assert-Equal 7 @($allUsersDenied.scopeStates | Where-Object state -eq 'Complete').Count `
    'all-user denial cannot erase independently completed sources'

$userDenied = (Invoke-SoftwareInventoryCollection -Policy $policy `
    -ValidationScenario DeniedUser).payload
Assert-Equal 4 @($userDenied.scopeStates | Where-Object state -eq 'Denied').Count `
    'verified-user source denial marks only the four user scopes'
Assert-Equal 4 @($userDenied.scopeStates | Where-Object state -eq 'Complete').Count `
    'verified-user denial preserves four machine scopes'

$oversize = (Invoke-SoftwareInventoryCollection -Policy $policy `
    -ValidationScenario Oversize).payload
Assert-Equal 64 @($oversize.entries | Where-Object `
    scopeId -eq 'scope:software.registry.machine.64').Count `
    'the sixty-fifth entry is excluded only after the explicit evidence ceiling'
Assert-Equal 'Partial' @($oversize.scopeStates | Where-Object `
    scopeId -eq 'scope:software.registry.machine.64')[0].state `
    'bounded overflow is explicit rather than silent truncation'

$malformed = New-SoftwareInventorySyntheticPayload -Scenario RegistryViews -Policy $policy
$malformed.entries[0].displayName = 'x' * 600
$isolated = ConvertTo-SoftwareInventoryAttemptPayload -Payload $malformed -Policy $policy
Assert-Equal 3 @($isolated.entries).Count `
    'one malformed registration fabricates no evidence for that item'
Assert-Equal 'Malformed' @($isolated.scopeStates | Where-Object `
    scopeId -eq 'scope:software.registry.machine.32')[0].state `
    'malformation remains source-scope coverage rather than run-integrity failure'
Assert-Equal 7 @($isolated.scopeStates | Where-Object state -eq 'Complete').Count `
    'one malformed registration preserves independent source scopes'

foreach ($contradiction in @(
    @{verified=$false;relationship='SameUser';context='StandardUser'},
    @{verified=$true;relationship='DifferentStandardUser';context='StandardUser'},
    @{verified=$true;relationship='SameUser';context='Administrator'}
)) {
    $payload = New-SoftwareInventorySyntheticPayload -Scenario Empty -Policy $policy
    $payload.assessmentUserContextVerified = $contradiction.verified
    $payload.processRelationship = $contradiction.relationship
    $payload.observedExecutionContext = $contradiction.context
    Assert-Equal $false (Test-SoftwareInventoryCollectorPayload `
        -Payload $payload -Policy $policy) `
        'contradictory Assessment User tuples cannot authorize completed absence'
}

foreach ($mutation in @(
    @{property='registrationContext';value='AssessmentUser'},
    @{property='registryView';value='Registry64'},
    @{property='sourceKind';value='Msix'}
)) {
    $payload = New-SoftwareInventorySyntheticPayload -Scenario RegistryViews -Policy $policy
    $payload.entries[0].$($mutation.property) = $mutation.value
    Assert-Equal $false (Test-SoftwareInventoryCollectorPayload -Payload $payload -Policy $policy) `
        'source kind, scope, registration context, registry view, state, type, and identity must form one closed tuple'
}

$tooMany = New-SoftwareInventorySyntheticPayload -Scenario Empty -Policy $policy
$tooMany.entries = @(foreach($index in 1..([int]$policy.collector.maximumTotalEntries + 1)){
    New-SoftwareInventoryEntry -ScopeId 'scope:software.registry.machine.64' `
        -SourceKind Registry -RegistrationId "reg:total:$index" `
        -RegistrationContext Machine -RegistryView Registry64 `
        -InstallerState Registered -PackageType DesktopRegistration `
        -Architecture None
})
Assert-Equal $false (Test-SoftwareInventoryCollectorPayload -Payload $tooMany -Policy $policy) `
    'the frozen aggregate entry ceiling keeps every admitted payload composable into the Assessment Contract'

$projection = New-SoftwareInventoryPublicProjection -CollectorResult (
    Invoke-SoftwareInventoryCollection -Policy $policy -ValidationScenario Unicode
)
Assert-Equal 'win-pcinfo.software-inventory-validation' $projection.recordType `
    'public evidence has an explicit sanitized shape'
Assert-Equal $false $projection.softwareIdentitiesPublished `
    'public evidence excludes every exact software identity'
Assert-Equal $false $projection.pathsOrHashesCollected `
    'the contract excludes arbitrary filesystem and binary material'
Assert-Equal $false $projection.licenseMaterialCollected `
    'license and product-key material cannot enter the payload'

Write-Output 'PASS: Software Inventory payloads preserve identity, context, bounds, and privacy.'
