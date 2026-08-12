[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1')
. (Join-Path $repositoryRoot 'src/IdentityEnrollment.ps1')

function Assert-NullableEqual {
    param($Expected, $Actual, [Parameter(Mandatory)] [string] $Because)
    if ($null -eq $Expected -and $null -eq $Actual) { return }
    if ($null -eq $Expected -or $null -eq $Actual -or $Expected -ne $Actual) {
        throw "Expected '$Expected' but received '$Actual': $Because"
    }
}

$convertFromJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
    'ConvertFrom-Json', [System.Management.Automation.CommandTypes]::Cmdlet
)
$policy = Get-IdentityEnrollmentPolicy -ConvertFromJsonCommand $convertFromJsonCommand

$expected = @{
    Workgroup = @{domain='Workgroup';entra='None';user=$true;relation='SameUser'}
    DomainJoined = @{domain='DomainJoined';entra='None';user=$true;relation='SameUser'}
    EntraJoined = @{domain='Workgroup';entra='EntraJoined';user=$true;relation='SameUser'}
    Registered = @{domain='Workgroup';entra='EntraRegistered';user=$true;relation='SameUser'}
    Mixed = @{domain='DomainJoined';entra='EntraJoined';user=$true;relation='SameUser'}
    Unenrolled = @{domain='Workgroup';entra='None';user=$true;relation='SameUser'}
    UserContextUnavailable = @{domain='Workgroup';entra='None';user=$null;relation='Unavailable'}
    StandardUser = @{domain='Workgroup';entra='None';user=$true;relation='SameUser'}
    Administrator = @{domain='Workgroup';entra='None';user=$true;relation='AlternateAdministrator'}
    LocalSystem = @{domain=$null;entra=$null;user=$null;relation='ProhibitedProcessContext'}
    NonEnglish = @{domain='DomainJoined';entra='EntraRegistered';user=$true;relation='SameUser'}
    Malformed = @{domain=$null;entra=$null;user=$null;relation='Unavailable'}
    Denied = @{domain=$null;entra=$null;user=$null;relation='Unavailable'}
}

foreach ($scenario in @($policy.validationScenarios)) {
    $result = Invoke-IdentityEnrollmentCollection -Policy $policy `
        -ValidationScenario ([string]$scenario)
    Assert-Equal ([string]$scenario) ([string]$result.validationScenario) `
        'the closed fixture identity remains observable'
    Assert-NullableEqual $expected[[string]$scenario].domain $result.payload.domainJoinState `
        'domain state comes from its structured source only'
    Assert-NullableEqual $expected[[string]$scenario].entra $result.payload.entraRegistrationType `
        'Entra registration remains distinct from domain join'
    Assert-NullableEqual $expected[[string]$scenario].user $result.payload.assessmentUserVerified `
        'Assessment User Context is never substituted from process identity'
    Assert-Equal $expected[[string]$scenario].relation ([string]$result.processRelationship) `
        'the process-to-assessment-user relationship is explicit'
    Assert-Equal $true (Test-IdentityEnrollmentCollectorPayload -Payload $result.payload) `
        'every admitted fixture satisfies the same closed source contract'
}

$standard = Invoke-IdentityEnrollmentCollection -Policy $policy -ValidationScenario 'StandardUser'
$administrator = Invoke-IdentityEnrollmentCollection -Policy $policy -ValidationScenario 'Administrator'
Assert-Equal $standard.payload.assessmentUserAccountName `
    $administrator.payload.assessmentUserAccountName `
    'alternate administration cannot replace the Assessment User Context'
Assert-Equal $standard.payload.assessmentUserSessionId `
    $administrator.payload.assessmentUserSessionId `
    'the verified interactive logon session is stable across process identities'

$nonEnglish = Invoke-IdentityEnrollmentCollection -Policy $policy -ValidationScenario 'NonEnglish'
Assert-Equal 'fr-FR' $nonEnglish.payload.sourceLocale `
    'source locale is provenance rather than a parser switch'
Assert-Equal 'DOMAINE-ÉQUIPE' $nonEnglish.payload.domainName `
    'valid Unicode identifiers survive as Restricted evidence'
Assert-Equal 'équipe\utilisateur' $nonEnglish.payload.assessmentUserAccountName `
    'localized account text is carried, never interpreted as a label'

foreach ($scenario in @('Malformed','Denied','LocalSystem')) {
    $failed = Invoke-IdentityEnrollmentCollection -Policy $policy -ValidationScenario $scenario
    Assert-Equal 0 @($failed.observations).Count `
        'source-wide failure creates no fabricated observations'
    Assert-Equal 0 @($failed.provenance).Count `
        'source-wide failure cannot claim field provenance'
    if (@($failed.coverage | Where-Object state -eq 'Complete').Count -ne 0) {
        throw "$scenario cannot report complete coverage after source rejection."
    }
}

$localSystem = Invoke-IdentityEnrollmentCollection -Policy $policy -ValidationScenario 'LocalSystem'
foreach ($envelope in @($localSystem.collectorResults)) {
    Assert-Equal 'Synthetic' ([string]$envelope.executionContext) `
        'the fixture is honest about its synthetic context while proving SYSTEM rejection'
}

$publicProjection = Invoke-IdentityEnrollmentCollection -Policy $policy `
    -ValidationScenario 'Mixed' | Select-Object validationScenario, processRelationship,
        @{n='coverageStates';e={@($_.coverage.state)}}
$publicJson = $publicProjection | ConvertTo-Json -Compress -Depth 5
if ($publicJson -match 'synthetic-device|synthetic-tenant|example|accountName|domainName') {
    throw 'The sanitized validation projection leaked a Restricted synthetic identifier.'
}

Write-Output 'PASS: Identity source states, user-context separation, Unicode, and failure coverage are honest.'
