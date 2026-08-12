[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1')
. (Join-Path $repositoryRoot 'src/IdentityEnrollment.ps1')

$convertFromJsonCommand = $ExecutionContext.InvokeCommand.GetCommand(
    'ConvertFrom-Json', [System.Management.Automation.CommandTypes]::Cmdlet
)
$policy = Get-IdentityEnrollmentPolicy -ConvertFromJsonCommand $convertFromJsonCommand
$result = Invoke-IdentityEnrollmentCollection -Policy $policy -Live

Assert-Equal 'Live' ([string]$result.validationScenario) `
    'the native path is distinguishable from synthetic validation'
Assert-Equal $true (Test-IdentityEnrollmentCollectorPayload -Payload $result.payload) `
    'the native APIs must produce the same closed payload contract as fixtures'
if ([string]$result.processRelationship -notin @(
        'SameUser','AlternateAdministrator','Unavailable','ProhibitedProcessContext'
    )) {
    throw 'The live process-to-user relationship is outside the closed vocabulary.'
}
foreach ($provenance in @($result.provenance)) {
    if ([string]$provenance.executionContext -notin @('StandardUser','Administrator')) {
        throw 'Standard identity evidence cannot be relabeled as SYSTEM or Synthetic.'
    }
    Assert-Equal 'und' ([string]$provenance.sourceLocale) `
        'native typed APIs have no display-text locale dependency'
}

$sourceText = Get-Content -LiteralPath (Join-Path $repositoryRoot 'src/IdentityEnrollment.ps1') -Raw
foreach ($requiredApi in @('NetGetJoinInformation','NetGetAadJoinInformation','WTSEnumerateSessions')) {
    if ($sourceText -notmatch [regex]::Escape($requiredApi)) {
        throw "The native collector does not bind the required structured API $requiredApi."
    }
}
if ($sourceText -match '(?i)dsregcmd|cmd\.exe|powershell\.exe\s+-Command') {
    throw 'The native identity collector must not parse localized commands or launch a shell.'
}

$sanitized = [pscustomobject][ordered]@{
    recordType='win-pcinfo.identity-native-source-validation';contractVersion='1.0.0'
    state=[string]$result.state;processRelationship=[string]$result.processRelationship
    coverageStates=@($result.coverage.state)
}
$json = $sanitized | ConvertTo-Json -Compress -Depth 5
if ($json -match '(?i)tenantId|deviceId|domainName|accountName|@|\\') {
    throw 'The public-safe native validation projection contains a Restricted identifier.'
}

Write-Output 'PASS: Native registration and Assessment User Context sources are structured, bounded, and sanitized.'
