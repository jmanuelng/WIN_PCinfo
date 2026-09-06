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
        'SameUser','SeparateProcessIdentity','AlternateAdministrator','Unavailable','ProhibitedProcessContext'
    )) {
    throw 'The live process-to-user relationship is outside the closed vocabulary.'
}
foreach ($provenance in @($result.provenance)) {
    Assert-Equal 'StandardUser' ([string]$provenance.executionContext) `
        'only the frozen standard-user boundary may emit identity observations'
    Assert-Equal 'und' ([string]$provenance.sourceLocale) `
        'native typed APIs have no display-text locale dependency'
}
foreach ($envelope in @($result.collectorResults)) {
    if ([string]$envelope.executionContext -eq 'Administrator' -and
        @($envelope.observationIds).Count -ne 0) {
        throw 'An elevated coordinator cannot execute or emit standard-user observations.'
    }
}
Assert-Equal 2 @($result.collectorResults).Count `
    'the two standard collector contracts correspond to two supervised attempts'
if([bool]$result.payload.assessmentUserVerified){
    if([string]$result.privateAssessmentUserSid -notmatch '^S-1-(?:[0-9]+-){1,14}[0-9]+$'){
        throw 'A verified live Assessment User must retain its private SID for downstream context binding.'
    }
}
$registrationEnvelope=$result.collectorResults[0]
$workSchoolEnvelope=$result.collectorResults[1]
foreach($envelope in @($registrationEnvelope,$workSchoolEnvelope)){
    if([DateTimeOffset]::Parse($envelope.startedAt) -gt
        [DateTimeOffset]::Parse($envelope.completedAt)){
        throw 'A supervised identity attempt has impossible timestamps.'
    }
}
Assert-Equal 'observe-device-registration' ([string]$registrationEnvelope.operationId) `
    'the registration/user snapshot has its own Collector Result Envelope'
Assert-Equal 'observe-enrollment-context' ([string]$workSchoolEnvelope.operationId) `
    'the work-school snapshot has its own Collector Result Envelope'

$sourceText = Get-Content -LiteralPath (Join-Path $repositoryRoot 'src/IdentityEnrollment.ps1') -Raw
foreach ($requiredApi in @('NetGetJoinInformation','NetGetAadJoinInformation','WTSEnumerateSessions')) {
    if ($sourceText -notmatch [regex]::Escape($requiredApi)) {
        throw "The native collector does not bind the required structured API $requiredApi."
    }
}
foreach ($requiredOfflineApi in @('LsaEnumerateLogonSessions','LsaGetLogonSessionData')) {
    if ($sourceText -notmatch [regex]::Escape($requiredOfflineApi)) {
        throw "Assessment User SID binding is missing local structured source $requiredOfflineApi."
    }
}
if ($sourceText -match 'NTAccount.*Translate|LookupAccountName') {
    throw 'Offline identity collection cannot translate an account through a domain-capable lookup.'
}
Initialize-IdentityEnrollmentNativeSource
Assert-Equal $false ([WinPCInfo.IdentityEnrollment.NativeSources]::CanVerifyUserContext(2,1,5)) `
    'one denied active-session query prevents substitution of the remaining session'
Assert-Equal $true ([WinPCInfo.IdentityEnrollment.NativeSources]::CanVerifyUserContext(1,1,0)) `
    'only one fully inspected active session can reach SID verification'
if ($sourceText -match '(?i)dsregcmd|cmd\.exe|powershell\.exe\s+-Command') {
    throw 'The native identity collector must not parse localized commands or launch a shell.'
}
if ($sourceText -notmatch 'NativeRunner\]::Run' -or
    $sourceText -notmatch 'deadlineMilliseconds') {
    throw 'Live native identity APIs must execute in the bounded owned-process boundary.'
}
Assert-Equal $true (Test-IdentityNativeAccessDeniedCode -Code ([int]0x80070005)) `
    'HRESULT E_ACCESSDENIED is classified as denied rather than unavailable'
Assert-Equal $true (Test-IdentityAadSuccessCode -Code 1) `
    'S_FALSE is complete locale-neutral evidence that no default Entra join exists'
Assert-Equal 'Complete' (Get-IdentityAadSourceState -Code 1 -InfoPresent $false) `
    'S_FALSE alone authoritatively represents absent default join information'
Assert-Equal 'Complete' (Get-IdentityAadSourceState -Code 0 -InfoPresent $false) `
    'the documented S_OK with NULL join information also establishes no default join'
Assert-Equal 'Malformed' (Get-IdentityAadSourceState -Code 1 -InfoPresent $true) `
    'S_FALSE cannot contradict its absent join information'
Assert-Equal 'Complete' (Get-IdentityAadSourceState -Code 0 -InfoPresent $true) `
    'S_OK is admitted only with the returned structured join information'

$gateStarted=[DateTimeOffset]::UtcNow
$administratorGate=Get-IdentityProcessContextDisposition `
    -ProcessSid 'S-1-5-21-1-2-3-1001' -IsAdministrator $true -StartedAt $gateStarted
Assert-Equal 'Administrator' ([string]$administratorGate.executionContext) `
    'an elevated coordinator is rejected before the StandardUser source'
Assert-Equal 'Denied' ([string]$administratorGate.payload.userContextState) `
    'administrator context creates an explicit user-context gap'
$systemGate=Get-IdentityProcessContextDisposition `
    -ProcessSid 'S-1-5-18' -IsAdministrator $true -StartedAt $gateStarted
Assert-Equal 'LocalSystem' ([string]$systemGate.executionContext) `
    'SYSTEM is preserved as its actual prohibited source context'
Assert-Equal 'ProhibitedProcessContext' ([string]$systemGate.relationship) `
    'SYSTEM cannot substitute the Assessment User Context'
$standardGate=Get-IdentityProcessContextDisposition `
    -ProcessSid 'S-1-5-21-1-2-3-1001' -IsAdministrator $false -StartedAt $gateStarted
if($null -ne $standardGate){
    throw 'A standard-user token alone must proceed to the independently verified session source.'
}

$deadlinePolicy = $policy | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
$deadlinePolicy.collectors[0].deadlineMilliseconds = 800
$originalInitializer = ${function:Initialize-IdentityEnrollmentNativeSource}
$deadlineWatch = [Diagnostics.Stopwatch]::StartNew()
try {
    Set-Item -LiteralPath Function:\Initialize-IdentityEnrollmentNativeSource -Value {
        [Threading.Thread]::Sleep(30000)
    }
    $deadlineResult = Invoke-BoundedIdentityNativeSnapshot -Policy $deadlinePolicy `
        -CollectorIndex 0 -Mode RegistrationUser
}
finally {
    Set-Item -LiteralPath Function:\Initialize-IdentityEnrollmentNativeSource `
        -Value $originalInitializer
    $deadlineWatch.Stop()
}
Assert-Equal $false ([bool]$deadlineResult.succeeded) `
    'an uncooperative native source cannot outlive its collector deadline'
Assert-Equal 'PROCESS.DEADLINE_EXCEEDED' ([string]$deadlineResult.reasonCode) `
    'deadline exhaustion remains a stable typed source failure'
Assert-Equal $true ([bool]$deadlineResult.native.CompleteOwnedTreeAbsent) `
    'the supervisor proves the uncooperative native source tree absent'
if ($deadlineWatch.ElapsedMilliseconds -ge 3000) {
    throw 'The bounded native source did not return within its termination allowance.'
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
