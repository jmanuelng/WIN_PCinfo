[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/Contracts.ps1')
. (Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1')
. (Join-Path $repositoryRoot 'src/FirmwareReadiness.ps1')
. (Join-Path $repositoryRoot 'src/PrivilegedCollectionPlan.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')

$convertToJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
    'ConvertTo-Json', [Management.Automation.CommandTypes]::Cmdlet
)
$plan = [pscustomobject][ordered]@{
    recordType='win-pcinfo.preparation-plan';contractVersion='1.0.0'
    release='2.0.0-preview.1'
    privilege=[pscustomobject][ordered]@{
        maximumUacInteractions=1;privilegedOperationsFrozen=$true
        privilegedOperations=@(
            [pscustomobject][ordered]@{operationId='observe-firmware-tpm';context='Administrator';parameters=[pscustomobject]@{}},
            [pscustomobject][ordered]@{operationId='observe-local-administrators';context='Administrator';parameters=[pscustomobject]@{}},
            [pscustomobject][ordered]@{operationId='observe-effective-policy';context='Administrator';parameters=[pscustomobject]@{}}
        )
    }
}
$digest = Get-ObjectDigest -Value $plan -ConvertToJsonCommand $convertToJsonCommand

$supported = Invoke-PrivilegedCollectionPlan -PreparationPlan $plan `
    -PlanDigest $digest -AssessmentUserContext 'subject:assessment-user:primary' `
    -LocalPackageProtector 'protector:initiating-windows-user' `
    -ValidationScenario AcceptedElevation -FirmwareScenario Supported
Assert-Equal 'Completed' $supported.state `
    'the frozen privileged plan returns after the bounded firmware attempt'
Assert-Equal $true $supported.cleanup.verified `
    'the worker tree and one-use channel are absent before evidence is admitted'
Assert-Equal $true $supported.channel.assessmentEvidenceCrossed `
    'the channel declares its one permitted private firmware projection'
if (-not $supported.PSObject.Properties['PrivateFirmwareCollectorResult']) {
    throw 'The firmware operation did not return its private collector result.'
}
$private = $supported.PrivateFirmwareCollectorResult
Assert-Equal 'Complete' $private.payload.firmwareState `
    'the supported fixture distinguishes successful firmware collection'
Assert-Equal 'Uefi' $private.payload.firmwareType `
    'the supported fixture carries a normalized firmware interface'
Assert-Equal $true $private.payload.secureBootEnabled `
    'the supported fixture preserves true Secure Boot evidence'
Assert-Equal $true $private.payload.tpmPresent `
    'the supported fixture preserves TPM presence'
Assert-Equal '2.0' $private.payload.tpmSpecification `
    'the supported fixture carries only the bounded TPM specification'
Assert-Equal $true (Test-FirmwareReadinessCollectorPayload -Payload $private.payload) `
    'the coordinator reprojects one exact release-shaped payload'
$unknownProviderValues = $private.payload.PSObject.Copy()
$unknownProviderValues.biosVersion = $null
$unknownProviderValues.smbiosVersion = $null
$unknownProviderValues.tpmSpecification = $null
Assert-Equal $true (Test-FirmwareReadinessCollectorPayload -Payload $unknownProviderValues) `
    'a successfully examined provider may retain explicit unknown field values'
$missingTpmBoolean = $private.payload.PSObject.Copy()
$missingTpmBoolean.tpmEnabled = $null
Assert-Equal $false (Test-FirmwareReadinessCollectorPayload -Payload $missingTpmBoolean) `
    'a present TPM cannot turn a missing readiness boolean into false evidence'
$blankProviderValues = $private.payload.PSObject.Copy()
$blankProviderValues.biosVersion = ''
$blankProviderValues.smbiosVersion = ' '
$blankProviderValues.tpmSpecification = ''
Assert-Equal $false (Test-FirmwareReadinessCollectorPayload -Payload $blankProviderValues) `
    'blank provider values cannot become affirmative observations'
if (($private | ConvertTo-Json -Compress -Depth 10) -match
    '(?i)ownerAuthorization|endorsementSecret|privateKey|recoveryData|serialNumber') {
    throw 'The private collector result contains prohibited TPM material.'
}

$legacy = Invoke-PrivilegedCollectionPlan -PreparationPlan $plan `
    -PlanDigest $digest -AssessmentUserContext 'subject:assessment-user:primary' `
    -LocalPackageProtector 'protector:initiating-windows-user' `
    -ValidationScenario AcceptedElevation
Assert-Equal $false $legacy.channel.assessmentEvidenceCrossed `
    'the original privilege tracer remains evidence-free by default'
if ($legacy.PSObject.Properties['PrivateFirmwareCollectorResult']) {
    throw 'An unrequested firmware result crossed the original privilege seam.'
}

Write-Output 'PASS: the privileged worker admits only the closed private firmware collector result.'
