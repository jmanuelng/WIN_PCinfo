[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1')
. (Join-Path $repositoryRoot 'src/SoftwareInventory.ps1')
$policy = Get-SoftwareInventoryPolicy -ConvertFromJsonCommand (
    Get-Command ConvertFrom-Json -CommandType Cmdlet
)

$allowed = Get-SoftwareInventoryProcessDisposition `
    -ProcessSid 'S-1-5-21-1-2-3-1001' `
    -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -IsAdministrator $false
Assert-Equal $true ($null -eq $allowed) `
    'the exact non-elevated Assessment User may cross the source boundary'
$alternate = Get-SoftwareInventoryProcessDisposition `
    -ProcessSid 'S-1-5-21-1-2-3-1002' `
    -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -IsAdministrator $false
Assert-Equal 'DifferentStandardUser' $alternate.relationship `
    'another standard user cannot substitute its registrations'
$admin = Get-SoftwareInventoryProcessDisposition `
    -ProcessSid 'S-1-5-21-1-2-3-1001' `
    -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -IsAdministrator $true
Assert-Equal 'ElevatedAssessmentUser' $admin.relationship `
    'an elevated Assessment User token cannot substitute its view'
$system = Get-SoftwareInventoryProcessDisposition -ProcessSid 'S-1-5-18' `
    -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -IsAdministrator $true
Assert-Equal 'ProhibitedSystemContext' $system.relationship 'SYSTEM is prohibited'

$source = Get-SoftwareInventoryLiveSource
foreach ($required in @(
    '[Microsoft.Win32.RegistryKey]::OpenBaseKey', 'Registry32', 'Registry64',
    "GetValue('UpgradeCode'",
    'LocalMachine', 'CurrentUser', 'MsiEnumProductsExW', 'MsiGetProductInfoExW',
    'Windows.Management.Deployment.PackageManager', 'FindPackagesForUser',
    'FindPackages()'
)) {
    if ($source -notmatch [regex]::Escape($required)) {
        throw "The live Software Inventory source omitted $required."
    }
}
foreach ($prohibited in @(
    'Get-CimInstance', 'Get-WmiObject', 'Win32_Product', 'RegLoadKey',
    'RegistryUsers', 'OpenRemoteBaseKey', 'Get-ChildItem', 'FileInfo',
    'InstallLocation', 'UninstallString', 'QuietUninstallString',
    'AddPackage', 'RemovePackage', 'RegisterPackage', 'StagePackage',
    'ProvisionPackage', 'DeprovisionPackage', 'Package.Current',
    'Get-AppxPackage', 'Get-AppxProvisionedPackage'
)) {
    if ($source -match [regex]::Escape($prohibited)) {
        throw "The live Software Inventory source admits prohibited access: $prohibited"
    }
}

$adapterExpectations=@(
    @{file='adapter-registry.json';kind='Registry';context='Machine';state='Registered';type='DesktopRegistration'},
    @{file='adapter-registry-upgrade-code.json';kind='Registry';context='Machine';state='Registered';type='MsiRegistration'},
    @{file='adapter-msi.json';kind='Msi';context='AssessmentUserUnmanaged';state='Advertised';type='MsiProduct'},
    @{file='adapter-msix.json';kind='Msix';context='AssessmentUser';state='StatusOk';type='Framework'}
)
foreach($expectation in $adapterExpectations){
    $row=Get-Content -Raw (Join-Path $PSScriptRoot "fixtures/software-inventory/$($expectation.file)")|ConvertFrom-Json
    $entry=ConvertFrom-SoftwareInventoryAdapterRow -Row $row
    Assert-Equal $expectation.kind $entry.sourceKind "$($expectation.file) preserves its source adapter"
    Assert-Equal $expectation.context $entry.registrationContext "$($expectation.file) maps the provider context exactly"
    Assert-Equal $expectation.state $entry.installerState "$($expectation.file) maps provider state without activating the product"
    Assert-Equal $expectation.type $entry.packageType "$($expectation.file) maps the release-owned package type"
    Assert-Equal $true (Test-SoftwareInventoryEntry -Entry $entry -Policy $policy) "$($expectation.file) crosses the same closed tuple boundary as live child output"
    if($expectation.file -eq 'adapter-registry-upgrade-code.json'){
        Assert-Equal '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}' $entry.upgradeCode `
            'the live-shaped uninstall-registration fixture retains its exact UpgradeCode'
    }
}
$registryMaximum=Get-Content -Raw (Join-Path $PSScriptRoot 'fixtures/software-inventory/adapter-registry.json')|ConvertFrom-Json
$registryMaximum.registrationKeyName=('r'*256 -join '')
$registryMaximumEntry=ConvertFrom-SoftwareInventoryAdapterRow $registryMaximum
Assert-Equal 256 ([Text.Encoding]::UTF8.GetByteCount($registryMaximumEntry.registrationId)) `
    'a maximum legal registry key identity is preserved without an artificial prefix'
Assert-Equal $true (Test-SoftwareInventoryEntry $registryMaximumEntry $policy) `
    'the maximum registry adapter identity composes with the normalized entry boundary'
$msixMaximum=Get-Content -Raw (Join-Path $PSScriptRoot 'fixtures/software-inventory/adapter-msix.json')|ConvertFrom-Json
$msixMaximum.packageFamilyName=('f'*256 -join '');$msixMaximum.packageFullName=('q'*512 -join '')
$msixMaximumEntry=ConvertFrom-SoftwareInventoryAdapterRow $msixMaximum
Assert-Equal 512 ([Text.Encoding]::UTF8.GetByteCount($msixMaximumEntry.registrationId)) `
    'a maximum package full-name identity is preserved without an artificial prefix'
Assert-Equal $true (Test-SoftwareInventoryEntry $msixMaximumEntry $policy) `
    'the maximum package adapter identity composes with the normalized entry boundary'

function New-RawAdapterPayloadForTest($Row){
    $empty=New-SoftwareInventorySyntheticPayload -Scenario Empty -Policy $policy
    [pscustomobject][ordered]@{
        assessmentUserContextVerified=$empty.assessmentUserContextVerified
        processRelationship=$empty.processRelationship
        observedExecutionContext=$empty.observedExecutionContext
        sourceLocale=$empty.sourceLocale
        scopeStates=@($empty.scopeStates|ForEach-Object {[pscustomobject][ordered]@{scopeId=$_.scopeId;state=$_.state;reasonCode=$_.reasonCode}})
        adapterRows=@($Row)
    }
}
$registryRow=Get-Content -Raw (Join-Path $PSScriptRoot 'fixtures/software-inventory/adapter-registry.json')|ConvertFrom-Json
$registryRow.scopeId='scope:software.unknown'
$unknownResult=ConvertFrom-SoftwareInventoryAdapterPayload -Payload (New-RawAdapterPayloadForTest $registryRow) -Policy $policy
Assert-Equal 0 @($unknownResult.scopeStates|Where-Object state -eq Complete).Count `
    'an unknown raw source scope cannot fabricate completed absence'
Assert-Equal 0 @($unknownResult.entries).Count `
    'an unknown raw source scope admits no registration evidence'
$registryRow=Get-Content -Raw (Join-Path $PSScriptRoot 'fixtures/software-inventory/adapter-registry.json')|ConvertFrom-Json
$registryRow.registryView='Registry64'
$mismatchResult=ConvertFrom-SoftwareInventoryAdapterPayload -Payload (New-RawAdapterPayloadForTest $registryRow) -Policy $policy
Assert-Equal 0 @($mismatchResult.scopeStates|Where-Object state -eq Complete).Count `
    'a contradictory raw source identity cannot choose which scope is absent'
Assert-Equal 0 @($mismatchResult.entries).Count `
    'a contradictory raw source identity admits no registration evidence'

$gap = Invoke-SoftwareInventoryCollection -Policy $policy -Live `
    -AssessmentUserSid 'S-1-5-21-1-2-3-1001' `
    -ProcessContextOverride LocalSystem
Assert-Equal 8 @($gap.payload.scopeStates | Where-Object state -eq 'Denied').Count `
    'a prohibited process stops before every source access'
Assert-Equal 0 @($gap.payload.entries).Count `
    'a prohibited process fabricates no registrations'
Assert-Equal $true $gap.cleanupVerified `
    'a pre-source context denial owns no worker cleanup'

$live = Invoke-SoftwareInventoryCollection -Policy $policy -Live `
    -AssessmentUserSid ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
Assert-Equal $true (Test-SoftwareInventoryCollectorPayload `
    -Payload $live.payload -Policy $policy) `
    'live Windows sources cross the same closed coordinator boundary'
Assert-Equal $true $live.cleanupVerified `
    'the supervised live attempt proves its worker and compiler boundary absent'
Assert-Equal 0 @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) `
    -Directory -Filter 'WINPCInfo-SoftwareInventory-*').Count `
    'the transient compiler boundary leaves no process artifact'

Write-Output 'PASS: the live Software Inventory source is bounded, context-bound, and read-only.'
