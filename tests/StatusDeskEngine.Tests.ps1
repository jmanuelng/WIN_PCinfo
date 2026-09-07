[CmdletBinding()]
param([switch] $CancelAfterIdentity, [switch] $CancelAfterResource, [switch] $CancelDuringPrivilege,
    [ValidateSet('','Identity','Resource','Network','Software','Certificate','Connectivity')]
    [string] $QualificationCancelAfter = '',
    [string] $QualificationPath = '',
    [string] $QualificationSourceCase = '',
    [ValidateSet('','PrivilegeTimeout','PrivilegeLoss','PrivilegePostStartLoss','SystemCancel','SystemTimeout','SystemLoss')] [string] $QualificationPlanFault = '',
    [ValidateSet('','en-US','es-MX','tr-TR','ja-JP','ar-SA')] [string] $QualificationCulture = '',
    [ValidateSet('','Identity','Resource','Network','Software','Certificate','Connectivity','Firmware','Administrator','Policy','System')]
    [string] $QualificationProhibited = '',
    [ValidateSet('','Software','Resource','Network','Certificate','IdentityRegistration','IdentityWorkSchool')] [string] $QualificationWorkerFamily = '',
    [ValidateSet('Cancel','Timeout','Loss')] [string] $QualificationWorkerFault = 'Cancel',
    [switch] $DeclinePreparation,
    [switch] $Wpf, [switch] $HoldRunLock, [switch] $ReportContract,
    [ValidateSet('None','Cancel','Close')] [string] $ActiveAction = 'None',
    [ValidateSet('Privilege','System','NativeCooperative','NativeHard')] [string] $ActiveWorker = 'Privilege',
    [switch] $RequireRecoveryJournal, [switch] $RequireFrontLoadedPrivilege,
    [string] $ReadinessSourceScenario = '',
    [string] $IdentitySourceScenario = '',
    [string] $PolicySourceScenario = '',
    [string] $SecuritySourceScenario = '',
    [string] $PlatformSourceScenario = '',
    [string] $RemoteSourceScenario = '',
    [string] $SoftwareSourceScenario = '',
    [string] $ResourceSourceScenario = '',
    [ValidateSet('','Maximum','Distinct','EscapedOverflow')] [string] $SoftwareReportScenario = '',
    [string] $NetworkSourceScenario = '',
    [string] $CertificateSourceScenario = '',
    [string] $ConnectivitySourceScenario = '',
    [ValidateSet('AcceptedElevation','AlreadyElevated','AlternateAdministrator','ElevationDenied')]
    [string] $PrivilegeOutcome = 'AcceptedElevation',
    [string] $RecoveryDestination = '', [string] $RecoveryExpectedReason = '',
    [switch] $RecoveryAuthorized, [string] $InterruptHandoffPath = '',
    [ValidateSet('None','Integrity','Cleanup')] [string] $FailureKind = 'None')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if (-not $QualificationPath -and $env:WINPCINFO_TEST_EVIDENCE) {
    $QualificationPath = Join-Path $env:WINPCINFO_TEST_EVIDENCE ('case-' + [guid]::NewGuid().ToString('N') + '.json')
}
$qualificationArguments = [ordered]@{}
foreach ($entry in $PSBoundParameters.GetEnumerator()) {
    if ($entry.Key -notin @('QualificationPath','RecoveryDestination','InterruptHandoffPath')) {
        $qualificationArguments[$entry.Key] = if ($entry.Value -is [Management.Automation.SwitchParameter]) { [bool]$entry.Value } else { $entry.Value }
    }
}
$qualificationFailed = $false
$projection = $null
$qualityWatch = [Diagnostics.Stopwatch]::StartNew()
$quality = [ordered]@{ sampledPrivateBytes=0L; sampledWorkingSetBytes=0L; sampledWorkspaceBytes=0L; packageBytes=0L; htmlBytes=0L }
function Measure-QualificationWorkload {
    $process = [Diagnostics.Process]::GetCurrentProcess()
    try {
        $quality.sampledPrivateBytes = [Math]::Max($quality.sampledPrivateBytes, $process.PrivateMemorySize64)
        $quality.sampledWorkingSetBytes = [Math]::Max($quality.sampledWorkingSetBytes, $process.WorkingSet64)
    }
    finally { $process.Dispose() }
    if ([IO.Directory]::Exists($testRoot)) {
        $bytes = 0L
        foreach ($file in @(Get-ChildItem -LiteralPath $testRoot -File -Recurse)) { $bytes += $file.Length }
        $quality.sampledWorkspaceBytes = [Math]::Max($quality.sampledWorkspaceBytes, $bytes)
    }
}
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null
$regions = [regex]::Matches([IO.File]::ReadAllText($candidate),
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach ($region in $regions) { . ([scriptblock]::Create($region.Groups[2].Value)) }
$moduleText = ($regions | ForEach-Object { $_.Groups[2].Value }) -join "`n"
# Controlled adapters substitute every OS collector boundary, never the engine,
# canonical validation, rules, report, encryption or reopening. This test invokes
# the ordinary non-fixture scheduler; no fixture or adapter CLI is shipped.
$names = @('IdentityEnrollmentCollection','ResourceDependenciesCollection','NetworkTopologyCollection',
    'SoftwareInventoryCollection','CertificateTrustCollection','MicrosoftConnectivityCollection',
    'PrivilegedCollectionPlan','SystemCollectionPlan','ApprovedCollectorProcess')
foreach ($name in $names) {
    $moduleText = $moduleText.Replace("function Invoke-$name {", "function Invoke-Controlled$name {")
}
$moduleText += @'

function Invoke-IdentityEnrollmentCollection { param($Policy, [switch]$Live)
    Invoke-ControlledIdentityEnrollmentCollection -Policy $Policy -ValidationScenario StandardUser }
function Invoke-ResourceDependenciesCollection { param($Policy, [switch]$Live, $AssessmentUserSid)
    Invoke-ControlledResourceDependenciesCollection -Policy $Policy -ValidationScenario Empty }
function Invoke-NetworkTopologyCollection { param($Policy, [switch]$Live, $AssessmentUserSid, $NetworkBehavior)
    if ($NetworkBehavior -ne 'LocalOnly') { throw 'Unexpected assessment network authority.' }
    Invoke-ControlledNetworkTopologyCollection -Policy $Policy -ValidationScenario Empty -NetworkBehavior $NetworkBehavior }
function Invoke-SoftwareInventoryCollection { param($Policy, [switch]$Live, $AssessmentUserSid)
    Invoke-ControlledSoftwareInventoryCollection -Policy $Policy -ValidationScenario Empty }
function Invoke-CertificateTrustCollection { param($Policy, [switch]$Live, $AssessmentUserSid)
    Invoke-ControlledCertificateTrustCollection -Policy $Policy -ValidationScenario ValidTrusted }
function Invoke-MicrosoftConnectivityCollection { param($Policy, [switch]$Live, $NetworkBehavior, $AssessmentUserSid)
    if ($NetworkBehavior -ne 'LocalOnly') { throw 'Unexpected assessment network authority.' }
    Invoke-ControlledMicrosoftConnectivityCollection -Policy $Policy -ValidationScenario LocalOnly -NetworkBehavior LocalOnly }
function Invoke-PrivilegedCollectionPlan { param($PreparationPlan, $PlanDigest, $AssessmentUserContext,
    $AssessmentUserSid, $LocalPackageProtector, $ValidationScenario, $FirmwareScenario,
    $AdministratorScenario, $EffectivePolicyScenario, $CancellationToken, $SystemPlanResult, $SystemValidationScenario)
    $result=Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan $PreparationPlan -PlanDigest $PlanDigest `
        -AssessmentUserContext $AssessmentUserContext -AssessmentUserSid 'S-1-5-21-100-200-300-1001' `
        -LocalPackageProtector $LocalPackageProtector -ValidationScenario AcceptedElevation `
        -FirmwareScenario Supported -AdministratorScenario LocalPrincipal -EffectivePolicyScenario Workgroup -CancellationToken $CancellationToken `
        -SystemPlanResult $SystemPlanResult -SystemValidationScenario SyntheticSuccess
    $script:StatusDeskTransport.State.PrivilegeCompleted=$true; $result }
function Invoke-SystemCollectionPlan { param($Plan, $PlanDigest, $ValidationScenario, $CancellationToken, $PrivilegeChannel)
    $script:StatusDeskTransport.State.SystemInvoked=$true
    Invoke-ControlledSystemCollectionPlan -Plan $Plan -PlanDigest $PlanDigest -ValidationScenario SyntheticSuccess -CancellationToken $CancellationToken -PrivilegeChannel $PrivilegeChannel }
function Invoke-ApprovedCollectorProcess { param($OperationId, $DeviceReadinessScenario, $CancellationToken)
    Invoke-ControlledApprovedCollectorProcess -OperationId $OperationId -DeviceReadinessScenario Complete -CancellationToken $CancellationToken }
'@
if ($PrivilegeOutcome -ne 'AcceptedElevation') {
    $moduleText=$moduleText.Replace('-ValidationScenario AcceptedElevation', '-ValidationScenario ' + $PrivilegeOutcome)
}
if ($SoftwareReportScenario) {
    . (Join-Path $PSScriptRoot 'SoftwareReportAssertions.ps1')
    $moduleText += [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'SoftwareReportAssertions.ps1'))
    $moduleText += "`n" + @'
function Invoke-SoftwareInventoryCollection { param($Policy, [switch]$Live, $AssessmentUserSid)
    $result=Invoke-ControlledSoftwareInventoryCollection -Policy $Policy -ValidationScenario AggregateMaximum
    Set-SoftwareReportTestValues -Entries $result.payload.entries -Scenario '__REPORT_CASE__'
    $result
}
'@.Replace('__REPORT_CASE__',$SoftwareReportScenario)
}
if ($RequireFrontLoadedPrivilege) {
    $moduleText=$moduleText.Replace('Invoke-ControlledIdentityEnrollmentCollection -Policy',
        'if (-not $script:StatusDeskTransport.State.ContainsKey("PrivilegeCompleted")) { throw "Collection preceded privilege authorization." }; Invoke-ControlledIdentityEnrollmentCollection -Policy')
}
if ($CancelAfterIdentity) {
    $moduleText = $moduleText.Replace('Invoke-ControlledIdentityEnrollmentCollection -Policy $Policy -ValidationScenario StandardUser }',
        'Invoke-ControlledIdentityEnrollmentCollection -Policy $Policy -ValidationScenario StandardUser; $script:StatusDeskTransport.Cancellation.Cancel() }')
}
if ($CancelAfterResource) {
    $moduleText = $moduleText.Replace('Invoke-ControlledResourceDependenciesCollection -Policy $Policy -ValidationScenario Empty }',
        'Invoke-ControlledResourceDependenciesCollection -Policy $Policy -ValidationScenario Empty; $script:StatusDeskTransport.Cancellation.Cancel() }')
}
if ($CancelDuringPrivilege) {
    $moduleText = $moduleText.Replace('Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan',
        '$script:StatusDeskTransport.Cancellation.CancelAfter(1500); Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan')
    $moduleText = $moduleText.Replace('-LocalPackageProtector $LocalPackageProtector -ValidationScenario AcceptedElevation',
        '-LocalPackageProtector $LocalPackageProtector -ValidationScenario Cancellation')
}
if ($QualificationPlanFault) {
    if ($QualificationPlanFault.StartsWith('Privilege')) {
        $scenario=if($QualificationPlanFault -eq 'PrivilegeTimeout'){'Timeout'}else{'LostWorker'}
        $moduleText=$moduleText.Replace('-LocalPackageProtector $LocalPackageProtector -ValidationScenario AcceptedElevation',
            '-LocalPackageProtector $LocalPackageProtector -ValidationScenario '+$scenario)
        $moduleText=$moduleText.Replace('$script:StatusDeskTransport.State.PrivilegeCompleted=$true; $result }',
            '$script:StatusDeskTransport.State.QualificationPrivilegeState=$result.state; $script:StatusDeskTransport.State.QualificationPrivilegeReason=$result.reasonCode; $script:StatusDeskTransport.State.QualificationPrivilegeOperationCount=@($result.operations).Count; $script:StatusDeskTransport.State.PrivilegeCompleted=$true; $result }')
        if ($QualificationPlanFault -eq 'PrivilegePostStartLoss') {
            . (Join-Path $PSScriptRoot 'AssessmentQualificationSupport.ps1')
            $moduleText=Rename-QualificationFunction -Source $moduleText -Name Get-PrivilegedCollectionWorkerSource -Replacement Get-LossOriginalPrivilegeWorkerSource
            $moduleText=Rename-QualificationFunction -Source $moduleText -Name Get-PrivilegedCollectionPlanPolicy -Replacement Get-LossOriginalPrivilegePolicy
            $moduleText+=@'

function Get-PrivilegedCollectionWorkerSource {
    $source=Get-LossOriginalPrivilegeWorkerSource
    $early='if ($configuration.workerFault -eq ''ExitAfterHello'') { exit 71 }'
    $collected='New-SyntheticFirmwareResult -Scenario ([string]$configuration.firmwareScenario)'
    foreach($anchor in @($early,$collected)) {
        if(([regex]::Matches($source,[regex]::Escape($anchor))).Count -ne 1){throw 'Controlled post-start loss source changed.'}
    }
    # Execute the real synthetic firmware reducer inside the owned worker,
    # retain only a fixed witness outside the product channel, then die before
    # its operation envelopes. No live source or arbitrary protocol work.
    $source=$source.Replace($early,'')
    $source.Replace($collected, '$null = ' + $collected + '; [IO.File]::WriteAllText(''__POST_START_WITNESS__'',''SyntheticFirmwareReturned''); exit 71')
}
function Get-PrivilegedCollectionPlanPolicy {
    $policy=Get-LossOriginalPrivilegePolicy
    $source=(Get-PrivilegedCollectionWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $policy.worker.payloadSha256=Get-PrivilegedCollectionPlanSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($source))
    $policy
}
'@
        }
        if ($QualificationPlanFault -eq 'PrivilegeTimeout') {
            # The combined privilege/SYSTEM budget exceeds the original
            # 10-second standalone fault. Keep both owned processes waiting
            # beyond that budget so this case actually reaches timeout.
            . (Join-Path $PSScriptRoot 'AssessmentQualificationSupport.ps1')
            $moduleText=Rename-QualificationFunction -Source $moduleText -Name Get-PrivilegedCollectionWorkerSource -Replacement Get-TimeoutOriginalPrivilegeWorkerSource
            $moduleText=Rename-QualificationFunction -Source $moduleText -Name Get-PrivilegedCollectionPlanPolicy -Replacement Get-TimeoutOriginalPrivilegePolicy
            $moduleText+=@'

function Get-PrivilegedCollectionWorkerSource {
    $source=Get-TimeoutOriginalPrivilegeWorkerSource
    $wait='[System.Threading.Thread]::Sleep(10000)'
    if(([regex]::Matches($source,[regex]::Escape($wait))).Count -ne 2){throw 'Controlled privilege timeout boundary changed.'}
    $source.Replace($wait,'[System.Threading.Thread]::Sleep(30000)')
}
function Get-PrivilegedCollectionPlanPolicy {
    $policy=Get-TimeoutOriginalPrivilegePolicy
    $source=(Get-PrivilegedCollectionWorkerSource).Replace("`r`n","`n").Replace("`r","`n")
    $policy.worker.payloadSha256=Get-PrivilegedCollectionPlanSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($source))
    $policy
}
'@
        }
    }
    else {
        $scenario=@{SystemCancel='Cancellation';SystemTimeout='Timeout';SystemLoss='WorkerLost'}[$QualificationPlanFault]
        $before='Invoke-ControlledSystemCollectionPlan -Plan $Plan -PlanDigest $PlanDigest -ValidationScenario SyntheticSuccess -CancellationToken $CancellationToken -PrivilegeChannel $PrivilegeChannel }'
        $after=if($QualificationPlanFault -eq 'SystemCancel'){'$script:StatusDeskTransport.Cancellation.CancelAfter(1500); '}else{''}
        $after+='$result=Invoke-ControlledSystemCollectionPlan -Plan $Plan -PlanDigest $PlanDigest -ValidationScenario '+$scenario+' -CancellationToken $CancellationToken -PrivilegeChannel $PrivilegeChannel; $script:StatusDeskTransport.State.QualificationSystemState=$result.state; $script:StatusDeskTransport.State.QualificationSystemCoverage=@($result.collectorResult.Coverage | Select-Object scopeId,state,reasonCode)+@($result.PrivatePolicyCspResults.fields | Select-Object scopeId,state,reasonCode)+@([pscustomobject]@{scopeId="scope:policy.applocker.csp-channel";state=$result.PrivatePolicyCspResults.appLockerCsp.state;reasonCode=$result.PrivatePolicyCspResults.appLockerCsp.reasonCode}); $result }'
        $moduleText=$moduleText.Replace($before,$after)
    }
}
if ($ActiveAction -ne 'None') {
    $moduleText = $moduleText.Replace('Invoke-ControlledResourceDependenciesCollection -Policy',
        '[Threading.Thread]::Sleep(11500); Invoke-ControlledResourceDependenciesCollection -Policy')
    if ($ActiveWorker -eq 'Privilege') {
        $moduleText = $moduleText.Replace('$result=Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan',
            '$script:StatusDeskTransport.State.ControlledWorkerStarted=[Diagnostics.Stopwatch]::GetTimestamp(); $result=Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan')
        $moduleText = $moduleText.Replace('$script:StatusDeskTransport.State.PrivilegeCompleted=$true; $result }',
            '$script:StatusDeskTransport.State.PrivilegeCompleted=$true; $script:StatusDeskTransport.State.ControlledWorkerCleanup=$result.cleanup.verified; $result }')
        $moduleText = $moduleText.Replace('-LocalPackageProtector $LocalPackageProtector -ValidationScenario AcceptedElevation',
            '-LocalPackageProtector $LocalPackageProtector -ValidationScenario Cancellation')
    }
    elseif ($ActiveWorker -eq 'System') {
        $moduleText = $moduleText.Replace('Invoke-ControlledSystemCollectionPlan -Plan $Plan -PlanDigest $PlanDigest -ValidationScenario SyntheticSuccess -CancellationToken $CancellationToken -PrivilegeChannel $PrivilegeChannel }',
            '$script:StatusDeskTransport.State.ControlledWorkerStarted=[Diagnostics.Stopwatch]::GetTimestamp(); $result=Invoke-ControlledSystemCollectionPlan -Plan $Plan -PlanDigest $PlanDigest -ValidationScenario Cancellation -CancellationToken $CancellationToken -PrivilegeChannel $PrivilegeChannel; $script:StatusDeskTransport.State.ControlledWorkerCleanup=$result.cleanup.verified -and $result.cleanup.taskAbsent -and $result.cleanup.workerTreeAbsent -and $result.cleanup.pipeAbsent; $result }')
    }
    else {
        $fixture = if ($ActiveWorker -eq 'NativeCooperative') { 'cooperative-cancel' } else { 'hard-cancel' }
        $moduleText = $moduleText.Replace('Invoke-ControlledApprovedCollectorProcess -OperationId $OperationId -DeviceReadinessScenario Complete -CancellationToken $CancellationToken }',
            ('$script:StatusDeskTransport.State.ControlledWorkerStarted=[Diagnostics.Stopwatch]::GetTimestamp(); $result=Invoke-ControlledApprovedCollectorProcess -OperationId fixture:synthetic.' + $fixture + ' -CancellationToken $CancellationToken; $script:StatusDeskTransport.State.ControlledWorkerCleanup=$result.Supervision.completeOwnedTreeAbsent -and $result.Supervision.temporaryArtifactsAbsent; $script:StatusDeskTransport.State.TerminationMode=$result.Supervision.terminationMode; $result }'))
    }
}
if ($RequireRecoveryJournal) {
    $moduleText = $moduleText.Replace('$result=Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan',
        '$script:StatusDeskTransport.State.JournalObserved=(Test-Path -LiteralPath $Parameters.Request.outputDestination) -and @(Get-ChildItem -LiteralPath $Parameters.Request.outputDestination -Filter WINPCInfo-Recovery-v1-* -Directory).Count -eq 1; $result=Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan')
}
if ($InterruptHandoffPath) {
    $handoffLiteral = "'" + $InterruptHandoffPath.Replace("'", "''") + "'"
    $moduleText = $moduleText.Replace('Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan',
        "[IO.File]::WriteAllText($handoffLiteral, 'registered-before-supervised-worker'); Invoke-ControlledPrivilegedCollectionPlan -PreparationPlan")
    $moduleText = $moduleText.Replace('-LocalPackageProtector $LocalPackageProtector -ValidationScenario AcceptedElevation',
        '-LocalPackageProtector $LocalPackageProtector -ValidationScenario Cancellation')
}
if ($FailureKind -eq 'Integrity') {
    $moduleText = $moduleText.Replace('-LocalPackageProtector $LocalPackageProtector -ValidationScenario AcceptedElevation',
        '-LocalPackageProtector $LocalPackageProtector -ValidationScenario AlteredPlan')
}
elseif ($FailureKind -eq 'Cleanup') {
    $moduleText = $moduleText.Replace('Invoke-ControlledResourceDependenciesCollection -Policy $Policy -ValidationScenario Empty }',
        '$result=Invoke-ControlledResourceDependenciesCollection -Policy $Policy -ValidationScenario Empty; $temporary=Add-TemporaryEvidence -JournalPath $script:AssessmentRunJournalPath -Content ([Text.Encoding]::UTF8.GetBytes("synthetic locked residue")); $script:StatusDeskTransport.State.SyntheticLock=[IO.File]::Open($temporary.literalPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None); $result }')
}
if ($ReadinessSourceScenario) {
    . (Join-Path $PSScriptRoot 'ReadinessSourceAdapters.ps1')
    $moduleText = Add-ControlledReadinessSources -ModuleText $moduleText -Scenario $ReadinessSourceScenario
}
if ($IdentitySourceScenario) {
    . (Join-Path $PSScriptRoot 'IdentitySourceAdapters.ps1')
    $moduleText = Add-ControlledIdentitySources -ModuleText $moduleText -Scenario $IdentitySourceScenario
}
if ($PolicySourceScenario) {
    $sessionSource=(Get-Command Start-StatusDeskSession).Definition.Replace(
        '# Never copy an exception (potentially Restricted) into GUI activity.',
        '$Transport.State.PolicySourceFailure=$_.Exception.Message + '' '' + $_.ScriptStackTrace')
    . ([scriptblock]::Create('function Start-StatusDeskSession {' + $sessionSource + '}'))
    . (Join-Path $PSScriptRoot 'PolicySourceAdapters.ps1')
    $moduleText = Add-ControlledPolicySources -ModuleText $moduleText -Scenario $PolicySourceScenario
}
if ($SecuritySourceScenario) {
    . (Join-Path $PSScriptRoot 'SecuritySourceAdapters.ps1')
    $moduleText=Add-ControlledSecuritySources -ModuleText $moduleText -Scenario $SecuritySourceScenario
}
if ($PlatformSourceScenario) {
    . (Join-Path $PSScriptRoot 'PlatformSourceAdapters.ps1')
    $moduleText=Add-ControlledPlatformSources -ModuleText $moduleText -Scenario $PlatformSourceScenario
}
if ($RemoteSourceScenario) {
    . (Join-Path $PSScriptRoot 'RemoteSourceAdapters.ps1')
    $moduleText=Add-ControlledRemoteSources -ModuleText $moduleText -Scenario $RemoteSourceScenario
}
if ($SoftwareSourceScenario) {
    . (Join-Path $PSScriptRoot 'SoftwareSourceAdapters.ps1')
    $moduleText=Add-ControlledSoftwareSources -ModuleText $moduleText -Scenario $SoftwareSourceScenario
}
if ($ResourceSourceScenario) {
    . (Join-Path $PSScriptRoot 'ResourceSourceAdapters.ps1')
    $moduleText=Add-ControlledResourceSources -ModuleText $moduleText -Scenario $ResourceSourceScenario
}
if ($NetworkSourceScenario) {
    . (Join-Path $PSScriptRoot 'NetworkSourceAdapters.ps1')
    $moduleText=Add-ControlledNetworkSources -ModuleText $moduleText -Scenario $NetworkSourceScenario
}
if ($ConnectivitySourceScenario) {
    . (Join-Path $PSScriptRoot 'ConnectivitySourceAdapters.ps1')
    $moduleText=Add-ControlledConnectivitySources -ModuleText $moduleText -Scenario $ConnectivitySourceScenario
}
if ($CertificateSourceScenario) {
    . (Join-Path $PSScriptRoot 'CertificateSourceAdapters.ps1')
    $moduleText=Add-ControlledCertificateSources -ModuleText $moduleText -Scenario $CertificateSourceScenario
}
if ($QualificationCancelAfter) {
    $collectionName = @{
        Identity='IdentityEnrollment'; Resource='ResourceDependencies'; Network='NetworkTopology'
        Software='SoftwareInventory'; Certificate='CertificateTrust'; Connectivity='MicrosoftConnectivity'
    }[$QualificationCancelAfter]
    $moduleText = $moduleText.Replace("function Invoke-$($collectionName)Collection {", "function Invoke-QualificationOriginalCollection {")
    $moduleText += @'

function Invoke-__COLLECTION__Collection {
    param($Policy, [switch]$Live, $AssessmentUserSid, $NetworkBehavior, $ConnectivityContext, $ContextDigest)
    $script:StatusDeskTransport.State.QualificationBoundaryReached = $true
    $result = Invoke-QualificationOriginalCollection @PSBoundParameters
    $script:StatusDeskTransport.Cancellation.Cancel()
    $result
}
'@.Replace('__COLLECTION__', $collectionName)
}
if ($QualificationPath -or $QualificationCulture -or $QualificationProhibited -or $QualificationWorkerFamily -or $QualificationSourceCase) { . (Join-Path $PSScriptRoot 'AssessmentQualificationSupport.ps1') }
if ($QualificationProhibited) { $moduleText = Add-QualificationProhibitedPayload -ModuleText $moduleText -Boundary $QualificationProhibited }
if ($QualificationWorkerFamily) { $moduleText = Add-QualificationWorkerFault -ModuleText $moduleText -Family $QualificationWorkerFamily -Fault $QualificationWorkerFault }
if ($QualificationCulture) { $moduleText = Add-QualificationCulture -ModuleText $moduleText -Culture $QualificationCulture }
if ($QualificationSourceCase) {
    . (Join-Path $PSScriptRoot 'AdditionalScopeSourceAdapters.ps1')
    $sourceCases=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/assessment-additional-sources.json') -Raw | ConvertFrom-Json
    $sourceCase=@($sourceCases | Where-Object id -eq $QualificationSourceCase)
    if ($sourceCase.Count -ne 1) { throw 'Additional source qualification case is not uniquely selected.' }
    $sourceCase=$sourceCase[0]
    $moduleText=Add-AdditionalScopeSource -ModuleText $moduleText -Case $sourceCase
}
if ($QualificationPath -or $QualificationProhibited -or $QualificationCulture) {
    $moduleText = $moduleText.Replace('switch ([string] $Record.recordType) {',
        'if (-not $Transport.State.ContainsKey("QualificationOutput")) { $Transport.State.QualificationOutput = [Collections.Generic.List[string]]::new() }; $Transport.State.QualificationOutput.Add($json); switch ([string] $Record.recordType) {')
}
$testRoot = Join-Path $repositoryRoot ('.test-output/status-desk-' + [guid]::NewGuid().ToString('N'))
if ($RecoveryDestination) { $testRoot = [IO.Path]::GetFullPath($RecoveryDestination) }
$postStartWitness=Join-Path $testRoot 'synthetic-post-start.txt'
$moduleText=$moduleText.Replace('__POST_START_WITNESS__',$postStartWitness.Replace("'","''"))
$ownedParent = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
if (-not [IO.Path]::GetFullPath($testRoot).StartsWith($ownedParent, [StringComparison]::OrdinalIgnoreCase)) { throw 'Test output must remain in its owned test boundary.' }
$request = Get-AutomationRequest -LiteralPath (Join-Path $PSScriptRoot 'fixtures/automation-request.json') `
    -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)
$request.outputDestination = $testRoot
if ($ConnectivitySourceScenario -and $ConnectivitySourceScenario -ne 'LocalOnly') { $request.networkBehavior='MicrosoftConnectivityEnabled' }
$request.automationChoices.allowStaleRecovery = [bool]$RecoveryAuthorized
$context = @{ IsFixture = $false }
foreach ($name in @('Preparation','Contract','Run','PrivilegedCollection','SystemCollection',
    'EvidenceWorkspace','ProtectedPackage','RecipientSharing','DeviceReadiness','IdentityEnrollment',
    'AdministratorExposure','EffectivePolicy','ResourceDependencies','NetworkTopology',
    'SoftwareInventory','CertificateTrust','MicrosoftConnectivity')) { $context[$name + 'FixturePath'] = '' }
$session = $null
$runLock = $null
$runLockOwned = $false
try {
    if ($HoldRunLock) {
        $runLock = [Threading.Mutex]::new($false, [string](Get-AssessmentRunLifecyclePolicy).activeRunLock.name)
        $runLockOwned = $runLock.WaitOne(0)
        if (-not $runLockOwned) { throw 'Synthetic lock ownership could not be established.' }
    }
    $launch = @{
        Request=$request; RuntimeFacts=(Get-ActiveRuntimeFacts -ModuleFacts (Get-BuiltInModuleCompatibilityFacts))
        ArtifactTrustValid=$true; ValidationContext=[pscustomobject]$context
    }
    if ($Wpf) {
        Add-Type -AssemblyName PresentationFramework
        $null = [System.Windows.Window]
        $uiState = @{ Session=$null; Window=$null; Clicked=$false; ReportClicked=$false; ReportObserved=$false; Failure=''; ActionSent=$false; ResponsiveTicks=0; Acknowledged=$false; AcknowledgmentMilliseconds=-1; PeakPrivateBytes=0L; PeakWorkingSetBytes=0L }
        $driver = [System.Windows.Threading.DispatcherTimer]::new()
        $driver.Interval = [TimeSpan]::FromMilliseconds(100)
        $reportCloser = [System.Windows.Threading.DispatcherTimer]::new()
        $reportCloser.Interval = [TimeSpan]::FromMilliseconds(200)
        $uiWatch = [Diagnostics.Stopwatch]::StartNew()
        $reportCloser.Add_Tick({
            if ($null -ne $uiState.Window -and $uiState.Window.OwnedWindows.Count -gt 0) {
                $reportWindow=$uiState.Window.OwnedWindows[0]
                $document=$reportWindow.FindName('ReportBrowser').Document
                if ($null -ne $document -and $null -ne $document.body -and
                    [string]$document.body.innerText -like '*WIN-PCInfo Comprehensive Local Assessment*') {
                    $uiState.ReportObserved=$true
                    $reportWindow.FindName('CloseViewing').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                }
            }
            if ($uiWatch.Elapsed.TotalSeconds -gt 90 -and $null -ne $uiState.Window) {
                $uiState.Failure='WPF test exceeded its deadline.'
                $uiState.Window.Close()
            }
        }.GetNewClosure())
        $driver.Add_Tick({
            $window=$uiState.Window
            if ($null -eq $window) { return }
            $ownProcess=[Diagnostics.Process]::GetCurrentProcess()
            try {
                $uiState.PeakPrivateBytes=[Math]::Max($uiState.PeakPrivateBytes,$ownProcess.PrivateMemorySize64)
                $uiState.PeakWorkingSetBytes=[Math]::Max($uiState.PeakWorkingSetBytes,$ownProcess.WorkingSet64)
            } finally { $ownProcess.Dispose() }
            if ($window.FindName('Approve').IsEnabled -and -not $uiState.Clicked) {
                $uiState.Clicked=$true
                $window.FindName('Approve').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
            }
            if ($ActiveAction -ne 'None' -and -not $uiState.ActionSent -and
                $uiState.Session.Transport.State.ContainsKey('ControlledWorkerStarted') -and
                [Diagnostics.Stopwatch]::GetElapsedTime($uiState.Session.Transport.State.ControlledWorkerStarted).TotalMilliseconds -ge 1500) {
                $uiState.ActionSent=$true
                $actionWatch=[Diagnostics.Stopwatch]::StartNew()
                if ($ActiveAction -eq 'Close') { $window.Close() }
                else { $window.FindName('Cancel').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)) }
                $uiState.Acknowledged=$actionWatch.ElapsedMilliseconds -le 2000 -and $window.FindName('Status').Text -match 'Cancelling|Closing'
                $uiState.AcknowledgmentMilliseconds=$actionWatch.ElapsedMilliseconds
            }
            if ($uiState.ActionSent -and -not $uiState.Session.Completed) { $uiState.ResponsiveTicks++ }
            if ($ActiveAction -eq 'Close' -and -not $uiState.Session.Completed) { return }
            if ($window.FindName('OpenReport').IsEnabled -and -not $uiState.ReportClicked) {
                $uiState.ReportClicked=$true
                $window.FindName('OpenReport').RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
            }
            elseif ($uiState.ReportObserved) { $window.Close() }
            elseif ($uiState.Session.Completed -and -not $window.FindName('OpenReport').IsEnabled) {
                $uiState.Failure=$window.FindName('Details').Text
                $window.Close()
            }
        }.GetNewClosure())
        try {
            $null = Invoke-StatusDesk -ModuleText $moduleText -LaunchParameters $launch -ViewReady {
                param($window, $workerSession)
                $window.Opacity=0; $window.ShowInTaskbar=$false
                $uiState.Window=$window; $uiState.Session=$workerSession
                $reportCloser.Start(); $driver.Start()
            }.GetNewClosure()
        }
        finally { $driver.Stop(); $reportCloser.Stop() }
        $session=$uiState.Session
        Assert-Equal $true $uiState.Clicked 'actual STA WPF approval control starts the same worker'
        if ($FailureKind -ne 'None') {
            Assert-Equal $false $uiState.ReportClicked 'failure disables the actual report control'
            Assert-Equal $(if($FailureKind -eq 'Integrity'){'IntegrityFailed'}else{'CleanupIncomplete'}) $uiState.Window.FindName('Status').Text 'GUI displays the authoritative failure precedence'
        }
        elseif ($ActiveAction -eq 'None') { Assert-Equal $true $uiState.ReportObserved ('actual Open report opens the protected HTML window: ' + $uiState.Failure) }
        else {
            Assert-Equal $true $uiState.ActionSent 'active action reaches the actual waiting privileged worker'
            Assert-Equal $true $uiState.Acknowledged 'actual control acknowledges cancellation within two seconds'
            Assert-Equal $true ($uiState.ResponsiveTicks -ge 3) 'dispatcher remains responsive throughout supervised finalization'
            Assert-Equal $true $session.Transport.State.ControlledWorkerCleanup 'active action verifies owned privileged process tree and channel absence'
            Assert-Equal $true ($session.Transport.State.FirstProgressMilliseconds -le 5000) 'first generated application progress arrives within five seconds'
            Assert-Equal $true ($session.Transport.State.MaximumProgressGapMilliseconds -le 10000) 'sustained generated application progress gaps stay within ten seconds'
            if ($ActiveWorker -like 'Native*') { Assert-Equal $(if ($ActiveWorker -eq 'NativeCooperative') {'Cooperative'}else{'Hard'}) $session.Transport.State.TerminationMode 'native worker uses the expected cooperative or bounded hard stop' }
            Write-Output ('TIMING: action={0}; worker={1}; first={2}ms; maximumGap={3}ms; acknowledgment={4}ms; cancellationToTerminal={5}ms; sampledPrivateMiB={6}; sampledWorkingSetMiB={7}' -f $ActiveAction,$ActiveWorker,$session.Transport.State.FirstProgressMilliseconds,$session.Transport.State.MaximumProgressGapMilliseconds,$uiState.AcknowledgmentMilliseconds,($session.Transport.State.TerminalMilliseconds-$session.Transport.State.CancellationRequestedMilliseconds),[Math]::Round($uiState.PeakPrivateBytes/1MB),[Math]::Round($uiState.PeakWorkingSetBytes/1MB))
        }
    }
    else { $session = Start-StatusDeskSession -ModuleText $moduleText -LaunchParameters $launch }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while (-not $session.Transport.State.Preparation -and -not $session.Pending.IsCompleted -and $watch.Elapsed.TotalSeconds -lt 30) { Start-Sleep -Milliseconds 25 }
    Assert-Equal $true ([bool]$session.Transport.State.Preparation) 'actual preparation runs inside the generated worker'
    $preparation = $session.Transport.State.Preparation | ConvertFrom-Json
    Assert-Equal $true $preparation.readyForApproval 'synthetic controlled run has ready local protection'
    if ($ConnectivitySourceScenario -and $ConnectivitySourceScenario -ne 'LocalOnly') {
        Assert-Equal 'ActiveWindowsResolver' $preparation.plan.network.context.resolver 'enabled approval freezes resolver context'
        Assert-Equal $false $session.Transport.State.ContainsKey('ConnectivityRequests') 'preparation invokes no protocol request'
    } else { Assert-Equal 0 @($preparation.plan.network.plannedRequests).Count 'Local Only freezes no requests' }
    if($CertificateSourceScenario){Assert-Equal $false $session.Transport.State.ContainsKey('CertificateSourceExecuted') 'preparation never examines certificate stores'}
    if ($NetworkSourceScenario) {
        Assert-Equal $false $session.Transport.State.ContainsKey('NetworkSourceExecuted') 'preparation executes no topology source before approval'
        Assert-Equal $false $session.Transport.State.ContainsKey('NetworkRequestAttempted') 'preparation invokes no network request adapter'
    }
    if (-not $Wpf) { Set-StatusDeskDecision -Session $session -Approve (-not $DeclinePreparation) -PlanDigest $preparation.planDigest }
    while (-not (Complete-StatusDeskSession $session) -and $watch.Elapsed.TotalSeconds -lt 120) {
        if ($QualificationPath) { Measure-QualificationWorkload }
        Start-Sleep -Milliseconds 25
    }
    Assert-Equal $true $session.Completed 'ordinary collector chain reaches bounded completion'
    if ($IdentitySourceScenario -and $session.Transport.State.ContainsKey('IdentitySourceFailure')) { throw ($session.Transport.State.IdentitySourceFailure + ' ' + $session.Transport.State.IdentityPrivilegeReason) }
    if ($SecuritySourceScenario -and $session.Transport.State.ContainsKey('SecuritySourceFailure')) { throw $session.Transport.State.SecuritySourceFailure }
    if ($PlatformSourceScenario -and $session.Transport.State.ContainsKey('PlatformSourceFailure')) { throw $session.Transport.State.PlatformSourceFailure }
    if ($RemoteSourceScenario -and $session.Transport.State.ContainsKey('RemoteSourceFailure')) { throw $session.Transport.State.RemoteSourceFailure }
    if ($PolicySourceScenario -and $session.Transport.State.ContainsKey('PolicySourceFailure')) { throw ($session.Transport.State.PolicySourceFailure + ' ' + $session.Transport.State.PolicyPrivilegeReason) }
    $terminal = $session.Transport.State.Terminal | ConvertFrom-Json
    if ($QualificationPath) {
        $projection = [ordered]@{
            candidateSha256 = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
            outcome = $terminal.outcome; exitCode = $session.ExitCode
            cleanupVerified = $terminal.cleanup.verified; coverage = @(); culture = $QualificationCulture
            attemptCoverage = if($session.Transport.State.ContainsKey('QualificationSystemCoverage')){$session.Transport.State.QualificationSystemCoverage}else{@()}
        }
        [IO.File]::WriteAllText([IO.Path]::GetFullPath($QualificationPath), ($projection | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    }
    if ($QualificationPath -or $QualificationProhibited -or $QualificationCulture) {
        $publicText = $session.Transport.State.QualificationOutput -join "`n"
        Assert-Equal $false $publicText.Contains([string][char]27) 'public JSON never includes an ANSI escape'
        Assert-QualificationMarkerAbsent -Text $publicText
    }
    if ($QualificationProhibited) {
        if ($QualificationProhibited -eq 'System') {
            Assert-Equal $true $session.Transport.State.SystemInvoked 'the prohibited SYSTEM frame comes from an invoked controlled worker'
            Assert-Equal 'IDENTITY.SYSTEM_INTEGRITY_FAILED' $terminal.reasonCode 'the closed SYSTEM wire rejects the prohibited property before record creation'
            $session.Transport.State.ProhibitedBoundaryReached=$true
        }
        Assert-Equal $true $session.Transport.State.ProhibitedBoundaryReached 'the controlled prohibited input actually reached the collector-result boundary'
        Assert-Equal 'IntegrityFailed' $terminal.outcome 'prohibited collector payload cannot produce a successful report'
        Assert-Equal '' $session.Transport.State.PackagePath 'rejected input cannot reach package naming or viewing'
        Assert-Equal $true $terminal.cleanup.verified 'prohibited input failure verifies owned cleanup'
        foreach ($file in @(Get-ChildItem -LiteralPath $testRoot -Recurse -File)) {
            $bytes = [IO.File]::ReadAllBytes($file.FullName)
            Assert-QualificationMarkerAbsent -Text ([Text.Encoding]::UTF8.GetString($bytes))
            Assert-QualificationMarkerAbsent -Text ([Text.Encoding]::Unicode.GetString($bytes))
        }
        Assert-Equal 0 @(Get-ChildItem -LiteralPath $testRoot -Recurse -File).Count 'rejected collector input leaves no retained file, package, report or diagnostic dump'
        Write-Output "PASS: prohibited $QualificationProhibited payload and declared transforms are absent from public output and retained artifacts."
        return
    }
    if ($QualificationSourceCase -and $sourceCase.PSObject.Properties['terminal']) {
        Assert-Equal $sourceCase.terminal $terminal.outcome 'the source failure reaches its required terminal'
        Assert-Equal $sourceCase.terminalReason $terminal.reasonCode 'the actual failed collector supplies the terminal reason'
        Assert-Equal 50 $session.ExitCode 'an untrusted device result preserves the integrity-failure code'
        Assert-Equal '' $session.Transport.State.PackagePath 'untrusted source output cannot reach final package naming'
        Assert-Equal $true $terminal.cleanup.verified 'the failed source leaves verified owned cleanup'
        if($QualificationSourceCase -eq 'Device-ProhibitedSignal') {
            Assert-Equal 'PROCESS.PROHIBITED_MATERIAL_BLOCKED' $session.Transport.State.DeviceProhibitedReason 'the actual native collector identifies prohibited input'
            Assert-Equal $false $session.Transport.State.DeviceProhibitedPayloadReturned 'prohibited input has no admitted private payload'
            foreach($file in @(Get-ChildItem -LiteralPath $testRoot -Recurse -File)) {
                $bytes=[IO.File]::ReadAllBytes($file.FullName)
                Assert-QualificationMarkerAbsent -Text ([Text.Encoding]::UTF8.GetString($bytes))
                Assert-QualificationMarkerAbsent -Text ([Text.Encoding]::Unicode.GetString($bytes))
            }
        }
        return
    }
    if ($QualificationPlanFault.StartsWith('System')) {
        $expected=@{SystemCancel='Cancelled';SystemTimeout='TimedOut';SystemLoss='Failed'}[$QualificationPlanFault]
        Assert-Equal $expected $session.Transport.State.QualificationSystemState 'the real SYSTEM worker reaches its requested interruption'
        $attemptCoverage=$session.Transport.State.QualificationSystemCoverage
        Assert-Equal 9 @($attemptCoverage).Count 'the interrupted SYSTEM attempt covers all nine owned selected scopes'
        foreach($scope in $attemptCoverage){Assert-Equal $expected $scope.state 'every SYSTEM field retains the actual interrupted attempt state'}
    }
    if ($QualificationPlanFault.StartsWith('Privilege')) {
        $isTimeout=$QualificationPlanFault -eq 'PrivilegeTimeout'
        $postStartLoss=$QualificationPlanFault -eq 'PrivilegePostStartLoss'
        if($postStartLoss) {
            Assert-Equal 'SyntheticFirmwareReturned' ([IO.File]::ReadAllText($postStartWitness)) 'the actual owned worker completed controlled source execution before dying'
        }
        Assert-Equal $(if($isTimeout){'TimedOut'}else{'IntegrityFailed'}) $session.Transport.State.QualificationPrivilegeState 'the actual privileged protocol reaches the requested fault'
        Assert-Equal $(if($isTimeout){'PRIVILEGE.DEADLINE_EXCEEDED'}else{'PRIVILEGE.WORKER_LOST'}) $session.Transport.State.QualificationPrivilegeReason 'the worker supplies the specific fault reason'
        Assert-Equal 0 $session.Transport.State.QualificationPrivilegeOperationCount 'the interrupted protocol admits no operation envelopes'
        # LostWorker exits after hello, before receiving its collection plan.
        # Preserve the distinction between protocol failure and a started run.
        $expected=if($isTimeout){'TimedOut'}elseif($postStartLoss){'IntegrityFailed'}else{'NotStarted'}
        Assert-Equal $expected $terminal.outcome 'lost or timed-out privileged protocol cannot produce a completed assessment'
        Assert-Equal ($isTimeout -or $postStartLoss) $terminal.collectionStarted 'only authenticated execution preserves the collection-started lifecycle fact'
        Assert-Equal $(if($isTimeout){40}elseif($postStartLoss){50}else{20}) $session.ExitCode 'privileged interruption retains its truthful terminal code'
        Assert-Equal $false $session.Transport.State.ContainsKey('SystemInvoked') 'a failed privileged worker cannot schedule SYSTEM'
        Assert-Equal '' $session.Transport.State.PackagePath 'no authenticated operation payload means no final package'
        Assert-Equal $true $terminal.cleanup.verified 'privileged worker failure verifies owned cleanup'
        Write-Output "PASS: $QualificationPlanFault reaches $expected with zero envelopes, no SYSTEM/package and verified cleanup."
        return
    }
    if ($SoftwareReportScenario -eq 'EscapedOverflow') {
        Assert-Equal 'IntegrityFailed' $terminal.outcome 'escaped report overflow refuses without false success'
        Assert-Equal 50 $session.ExitCode 'escaped report overflow retains the integrity-failure exit code'
        Assert-Equal $true $terminal.collectionStarted 'escaped overflow reaches the real assessment flow'
        Assert-Equal 'DEVICE_READINESS.REPORT_FAILED' $terminal.reasonCode 'rendered output bound remains enforced'
        Assert-Equal $true $terminal.cleanup.verified 'overflow verifies owned cleanup'
        Assert-Equal '' $session.Transport.State.PackagePath 'overflow exposes no unverified package'
        return
    }
    if ($DeclinePreparation) {
        Assert-Equal 'NotStarted' $terminal.outcome 'declined preparation starts no assessment'
        Assert-Equal $false $terminal.collectionStarted 'declined preparation executes no local collector'
        Assert-Equal $false $session.Transport.State.ContainsKey('NetworkSourceExecuted') 'declined preparation reaches no nested topology source'
        Assert-Equal $false $session.Transport.State.ContainsKey('NetworkRequestAttempted') 'declined preparation reaches no network adapter'
        Assert-Equal $false $session.Transport.State.ContainsKey('ConnectivityRequests') 'declined enabled preparation reaches no protocol adapter'
        Assert-Equal '' $session.Transport.State.PackagePath 'declined preparation invents no protected report'
        return
    }
    if ($ConnectivitySourceScenario -and $session.Transport.State.ContainsKey('ConnectivityFailure')) { throw $session.Transport.State.ConnectivityFailure }
    if ($FailureKind -ne 'None') {
        $expectedOutcome=if($FailureKind -eq 'Integrity'){'IntegrityFailed'}else{'CleanupIncomplete'}
        Assert-Equal $expectedOutcome $terminal.outcome 'structured terminal preserves integrity/cleanup precedence'
        Assert-Equal $(if($FailureKind -eq 'Integrity'){50}else{60}) $session.ExitCode 'exit status preserves integrity/cleanup precedence'
        $completion=$session.Transport.State.Completion | ConvertFrom-Json
        Assert-Equal $expectedOutcome $completion.assessment.outcome 'completion record agrees with GUI and exit'
        Assert-Equal '' $session.Transport.State.PackagePath 'failure exposes no unverified report action'
        if ($FailureKind -eq 'Cleanup') {
            Assert-Equal $false $terminal.cleanup.verified 'surviving locked residue is not cleanup success'
            Assert-Equal 1 @(Get-ChildItem -LiteralPath $testRoot -Filter WINPCInfo-Recovery-v1-* -Directory).Count 'cleanup uncertainty preserves durable recovery state'
        }
        return
    }
    if ($RecoveryExpectedReason) {
        Assert-Equal $RecoveryExpectedReason $terminal.reasonCode 'ordinary generated recovery has the expected truthful terminal'
        Assert-Equal $false $terminal.collectionStarted 'recovery never starts or resumes collection'
        Assert-Equal '' $session.Transport.State.PackagePath 'recovery exposes no newly collected report'
        return
    }
    if ($HoldRunLock) {
        Assert-Equal 'NotStarted' $terminal.outcome 'the actual scheduler refuses a concurrent run'
        Assert-Equal 'RUN.ACTIVE_LOCK_HELD' $terminal.reasonCode 'lock contention has an honest terminal reason'
        Assert-Equal $false $terminal.collectionStarted 'lock contention starts no collector'
        return
    }
    Assert-Equal $(if(($QualificationWorkerFamily -and $QualificationWorkerFault -eq 'Cancel') -or $QualificationCancelAfter -or $CancelAfterIdentity -or $CancelAfterResource -or $CancelDuringPrivilege -or $QualificationPlanFault -eq 'SystemCancel' -or $ActiveAction -ne 'None' -or $ReadinessSourceScenario -eq 'Cancelled'){'Cancelled'}else{'CompletedWithGaps'}) $terminal.outcome ('controlled ordinary engine: ' + $terminal.reasonCode)
    Assert-Equal $true $terminal.collectionStarted 'ordinary collection actually executed'
    if ($RequireRecoveryJournal) {
        Assert-Equal $true $session.Transport.State.JournalObserved 'ordinary assessment registers durable ownership before the first source executes'
        Assert-Equal 0 @(Get-ChildItem -LiteralPath $testRoot -Filter WINPCInfo-Recovery-v1-* -Directory).Count 'successful finalization removes the journal after owned transient absence'
    }
    Assert-Equal $preparation.planDigest $terminal.planDigest 'approval and terminal bind the same frozen plan'
    $summary = $session.Transport.State.Completion | ConvertFrom-Json
    if (($CancelDuringPrivilege -or $QualificationPlanFault -eq 'SystemCancel' -or ($ActiveAction -ne 'None' -and $ActiveWorker -in @('Privilege','System'))) -and
        $summary.packageAvailability -eq 'VerifiedAbsent') {
        Assert-Equal '' $session.Transport.State.PackagePath 'cancellation before useful evidence does not invent a report'
        Assert-Equal $true $terminal.cleanup.verified 'early cancellation verifies both privilege and SYSTEM cleanup'
        if ($CancelDuringPrivilege -or ($ActiveAction -ne 'None' -and $ActiveWorker -eq 'Privilege')) {
            Assert-Equal $false $session.Transport.State.ContainsKey('SystemInvoked') 'cancelled administrator work cannot launch SYSTEM'
        }
        return
    }
    Assert-Equal 'Available' $summary.packageAvailability 'a usable protected result survives completion'
    Assert-Equal $true ([bool]$session.Transport.State.PackagePath) 'Open report receives the exact verified package'
    $opened = Read-ProtectedEvidencePackage -LiteralPath $session.Transport.State.PackagePath
    Assert-Equal $true $opened.verified 'actual encryption boundary reopens the generated result'
    $record = [Text.Encoding]::UTF8.GetString($opened.artifacts['assessment-record.json']) | ConvertFrom-Json
    if($QualificationCulture) {
        if($IdentitySourceScenario) {
            $observedCultures=@($session.Transport.State.ObservedIdentityCultures)
            Assert-Equal 2 $observedCultures.Count 'both bounded identity children report their executing cultures'
            foreach($observedCulture in $observedCultures) {
                Assert-Equal $QualificationCulture $observedCulture.culture 'identity native child uses requested culture'
                Assert-Equal $QualificationCulture $observedCulture.uiCulture 'identity native child uses requested UI culture'
            }
        }
        $sourcePrefix=if($SoftwareSourceScenario){'field:software.*'}elseif($ResourceSourceScenario){'field:resource.*'}elseif($NetworkSourceScenario){'field:network.*'}elseif($CertificateSourceScenario){'field:certificate.*'}else{''}
        if($sourcePrefix) {
            $sourceProvenance=@($record.provenance | Where-Object fieldId -Like $sourcePrefix)
            Assert-Equal $true ($sourceProvenance.Count -gt 0) 'the executing source emits locale-bearing evidence'
            foreach($entry in $sourceProvenance) { Assert-Equal $QualificationCulture $entry.sourceLocale 'child/source culture survives canonical packaging' }
        }
    }
    if ($QualificationPath) {
        $definition = (Get-EmbeddedAssessmentContractSet -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)).Definition
        $fullProfile = 'profile:device-firmware-identity-administrator-policy-software-resource-network-certificate-and-microsoft-connectivity-readiness'
        $selected = @($definition.scopeDefinitions | Where-Object { $fullProfile -in $_.profileIds } | ForEach-Object scopeId | Sort-Object)
        Assert-Equal 99 $selected.Count 'the selected comprehensive profile has exactly 99 declared scopes'
        Assert-Equal ($selected -join '|') (@($record.coverage.scopeId | Sort-Object) -join '|') 'every selected scope remains represented, including stopped scheduling'
        foreach ($coverage in $record.coverage) {
            if ($coverage.state -ne 'Complete') {
                Assert-Equal $true (-not [string]::IsNullOrWhiteSpace($coverage.reasonCode)) 'every incomplete scope retains its stable reason'
            }
        }
        if ($QualificationCancelAfter) {
            Assert-Equal $true $session.Transport.State.QualificationBoundaryReached 'cancellation is sent only after the selected collector actually executes'
            Assert-Equal 30 $session.ExitCode 'collector cancellation reaches the process terminal'
            Assert-QualificationScopeScheduling -Record $record -CancelledAfter $QualificationCancelAfter
        }
        $projection = [ordered]@{
            candidateSha256 = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
            profileId = $record.run.evidenceProfileId; outcome = $terminal.outcome
            culture = $QualificationCulture
            observedIdentityCultures = if($session.Transport.State.ContainsKey('ObservedIdentityCultures')){@($session.Transport.State.ObservedIdentityCultures)}else{@()}
            exitCode = $session.ExitCode; cleanupVerified = $terminal.cleanup.verified
            coverage = @($record.coverage | Select-Object scopeId,state,reasonCode)
            attemptCoverage = if($session.Transport.State.ContainsKey('QualificationSystemCoverage')){$session.Transport.State.QualificationSystemCoverage}else{@()}
        }
        [IO.File]::WriteAllText([IO.Path]::GetFullPath($QualificationPath), ($projection | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    }
    Assert-Equal $true (@($record.observations).Count -gt 0) 'real engine carries controlled source observations'
    Assert-Equal $true (@($record.findings).Count -gt 0) 'rules derive evidence-linked advisory interpretation'
    Assert-Equal $true (@($record.recommendations).Count -gt 0) 'report retains useful follow-up'
    if ($PrivilegeOutcome -eq 'ElevationDenied') {
        Assert-Equal $false $session.Transport.State.ContainsKey('SystemInvoked') 'denied UAC cannot activate SYSTEM'
        Assert-Equal $true (@($record.coverage | Where-Object state -eq Complete).Count -gt 0) 'unrelated standard-user coverage survives denial'
        Assert-Equal $true (@($record.coverage | Where-Object state -in @('Denied','Unavailable')).Count -gt 0) 'denied privilege remains an explicit coverage gap'
    }
    if ($CancelDuringPrivilege) {
        Assert-Equal $false $session.Transport.State.ContainsKey('SystemInvoked') 'privileged cancellation schedules no later SYSTEM worker'
        Assert-Equal $true (@($record.coverage | Where-Object state -eq Cancelled).Count -ge 4) 'stopped prerequisites stay explicitly Cancelled'
        $policyFinding=@($record.findings | Where-Object ruleId -eq 'rule:cross-domain.policy-modernization/1.0.0')[0]
        Assert-Equal 'Indeterminate' $policyFinding.outcome 'uncollected policy evidence never becomes a successful negative'
        Assert-Equal 0 @($policyFinding.evidenceReferences).Count 'absent policy references remain a valid empty list'
    }
    $html = [Text.Encoding]::UTF8.GetString($opened.artifacts['assessment-report.html'])
    if ($QualificationPath) {
        foreach ($artifactBytes in $opened.artifacts.Values) {
            Assert-QualificationMarkerAbsent -Text ([Text.Encoding]::UTF8.GetString($artifactBytes))
        }
    }
    if ($QualificationPlanFault.StartsWith('System')) {
        $expected=@{SystemCancel='Cancelled';SystemTimeout='TimedOut';SystemLoss='Failed'}[$QualificationPlanFault]
        Assert-Equal $expected $session.Transport.State.QualificationSystemState 'the controlled SYSTEM worker reaches its real interruption disposition'
        $scopes=@($record.coverage | Where-Object { $_.scopeId -eq 'scope:device.mdm-policy.system' -or $_.scopeId -like 'scope:policy.mdm.*' -or $_.scopeId -eq 'scope:policy.applocker.csp-channel' })
        Assert-Equal 9 $scopes.Count 'all nine selected SYSTEM scopes remain represented'
        foreach ($scope in $scopes) {
            Assert-Equal $expected $scope.state 'SYSTEM interruption propagates to every owned selected scope'
            Assert-Equal 0 @($scope.observationIds).Count 'the interrupted SYSTEM worker cannot establish an absent policy'
        }
    }
    if ($QualificationWorkerFamily) {
        $expected = @{ Cancel='Cancelled'; Timeout='TimedOut'; Loss='Failed' }[$QualificationWorkerFault]
        $expectedReason = @{ Cancel='PROCESS.CANCELLED_HARD'; Timeout='PROCESS.DEADLINE_EXCEEDED'; Loss="$($QualificationWorkerFamily.ToUpperInvariant()).SOURCE_FAILED" }[$QualificationWorkerFault]
        if($QualificationWorkerFamily -like 'Identity*') {
            $expectedReason=if($QualificationWorkerFault -eq 'Loss'){'COLLECTION.IDENTITY_SOURCE_FAILED'}else{$expectedReason}
        }
        Assert-Equal $expectedReason $session.Transport.State.QualificationWorkerReason 'the real owned process reaches its requested interruption boundary'
        $prefix = "scope:$($QualificationWorkerFamily.ToLowerInvariant())."
        $ownedScopes=if($QualificationWorkerFamily -eq 'IdentityRegistration'){@('scope:identity.assessment-user-context','scope:device.registration-context')}
            elseif($QualificationWorkerFamily -eq 'IdentityWorkSchool'){@('scope:device.work-school-registration-context')}else{@()}

        foreach ($scope in @($record.coverage | Where-Object { $_.scopeId.StartsWith($prefix) -or $_.scopeId -in $ownedScopes })) {
            Assert-Equal $expected $scope.state 'native interruption propagates to every scope owned by this collector'
            Assert-Equal 0 @($scope.observationIds).Count 'a stopped worker cannot invent an empty successful observation'
        }
        if($QualificationWorkerFamily -like 'Identity*') {
            $expectedModes=if($QualificationWorkerFamily -eq 'IdentityRegistration'){'RegistrationUser'}else{'RegistrationUser|WorkSchool'}
            Assert-Equal $expectedModes ($session.Transport.State.QualificationIdentityModes -join '|') 'identity native calls follow the verified prerequisite and cancellation state'
        }
        if($QualificationWorkerFamily -eq 'IdentityRegistration' -and $QualificationWorkerFault -eq 'Cancel') {
            Assert-Equal 'NotAttempted' @($record.coverage | Where-Object scopeId -eq 'scope:device.work-school-registration-context')[0].state 'registration cancellation never schedules the dependent work-account read'
        }
        if ($QualificationWorkerFault -eq 'Cancel') { Assert-QualificationScopeScheduling -Record $record -CancelledAfter $(if($QualificationWorkerFamily -like 'Identity*'){'Identity'}else{$QualificationWorkerFamily}) }
    }
    if ($ReportContract) {
        . (Join-Path $PSScriptRoot 'ReportContractAssertions.ps1')
        Assert-ComprehensiveReportContract -OpenedPackage $opened
    }
    foreach ($link in [regex]::Matches($html, 'href="#([^"]+)"')) {
        Assert-Equal $true $html.Contains('id="' + $link.Groups[1].Value + '"') ('every protected report reference resolves offline: ' + $link.Groups[1].Value)
    }
    $recommendationIndex = 0
    foreach ($recommendation in $record.recommendations) {
        Assert-Equal $true $html.Contains('id="r' + $recommendationIndex + '"') `
            'each recommendation and tenant task has a stable report destination'
        $recommendationIndex++
    }
    if ($SoftwareReportScenario) {
        Assert-SoftwareReportEvidence -Record $record -Html $html
        $exportBoundary=New-EvidenceWorkspaceValidationBoundary -ValidationRootPath (
            Join-Path ([IO.Path]::GetTempPath()) ('winpcinfo-software-export-'+[guid]::NewGuid().ToString('N')))
        try {
            $exportPath=Join-Path $exportBoundary.CaseRoot 'software-report.html'
            $export=Export-RestrictedAssessmentReport -PackagePath $session.Transport.State.PackagePath `
                -OutputPath $exportPath -WarningAcknowledgment 'I UNDERSTAND THIS IS RESTRICTED DIAGNOSTIC EVIDENCE'
            Assert-Equal 'Exported' $export.state 'maximum software report deliberately exports after verified reopening'
            Assert-SoftwareReportEvidence -Record $record -Html ([IO.File]::ReadAllText($exportPath))
        }
        finally { if(-not (Remove-EvidenceWorkspaceValidationBoundary $exportBoundary)){throw 'Software export test cleanup failed.'} }
        Write-Output "Software report $SoftwareReportScenario bytes: $($opened.artifacts['assessment-report.html'].Length)"
    }
    if ($SoftwareSourceScenario -and -not ($QualificationWorkerFamily -or $QualificationSourceCase)) { Assert-SoftwareSourceReport -Record $record -Html $html -Scenario $SoftwareSourceScenario }
    if ($ResourceSourceScenario -and -not ($QualificationWorkerFamily -or $QualificationSourceCase)) { Assert-ResourceSourceReport -Record $record -Html $html -Scenario $ResourceSourceScenario }
    if ($ConnectivitySourceScenario) {
        Assert-ConnectivitySourceReport -Record $record -Html $html -Scenario $ConnectivitySourceScenario -State $session.Transport.State
    }
    if ($CertificateSourceScenario -and -not ($QualificationWorkerFamily -or $QualificationSourceCase)) {
        Assert-Equal ($CertificateSourceScenario -ne 'AlternateAdministrator') $session.Transport.State.ContainsKey('CertificateSourceExecuted') 'certificate stores require the Assessment User context'
        Assert-CertificateSourceReport -Record $record -Html $html -Scenario $CertificateSourceScenario
    }
    if ($NetworkSourceScenario -and -not ($QualificationWorkerFamily -or $QualificationSourceCase)) {
        Assert-Equal $true $session.Transport.State.NetworkSourceExecuted 'actual generated local reducer executed'
        Assert-Equal $false $session.Transport.State.ContainsKey('NetworkRequestAttempted') 'Local Only never enters the nested network request adapter'
        Assert-NetworkSourceReport -Record $record -Html $html -Scenario $NetworkSourceScenario
    }
    if ($ReadinessSourceScenario -and -not $QualificationSourceCase) {
        Assert-ReadinessSourceReport -Record $record -Html $html -Scenario $ReadinessSourceScenario -Culture $QualificationCulture
    }
    if ($IdentitySourceScenario -and -not ($QualificationSourceCase -or $QualificationWorkerFamily)) {
        Assert-IdentitySourceReport -Record $record -Html $html -Scenario $IdentitySourceScenario
    }
    if ($PolicySourceScenario -and -not $QualificationSourceCase) {
        Assert-PolicySourceReport -Record $record -Html $html -Scenario $PolicySourceScenario
    }
    if ($SecuritySourceScenario -and -not $QualificationSourceCase) {
        Assert-SecuritySourceReport -Record $record -Html $html -Scenario $SecuritySourceScenario -Culture $QualificationCulture
    }
    if ($PlatformSourceScenario -and -not $QualificationSourceCase) { Assert-PlatformSourceReport -Record $record -Html $html -Scenario $PlatformSourceScenario }
    if ($RemoteSourceScenario -and -not $QualificationSourceCase) { Assert-RemoteSourceReport -Record $record -Html $html -Scenario $RemoteSourceScenario }
    if ($QualificationSourceCase) { Assert-AdditionalScopeSource -Record $record -Html $html -Case $sourceCase -State $session.Transport.State }
    if (-not ($CancelAfterIdentity -or $CancelAfterResource -or $QualificationCancelAfter -in @('Identity','Resource') -or (($QualificationWorkerFamily -like 'Identity*' -or $QualificationWorkerFamily -eq 'Resource') -and $QualificationWorkerFault -eq 'Cancel'))) { Assert-Equal $true $html.Contains('Local Only') 'offline report preserves network choice' }
    $viewing = Open-EvidenceViewingSession -PackagePath $session.Transport.State.PackagePath `
        -RequestedArtifact assessment-report.html -ViewingBasePath $testRoot
    Assert-Equal 'Opened' $viewing.state 'Open report uses a registered protected viewing boundary'
    Assert-Equal $true (Close-EvidenceViewingSession $viewing).verified 'closing report verifies owned plaintext cleanup'
    foreach ($bytes in $opened.artifacts.Values) { [Security.Cryptography.CryptographicOperations]::ZeroMemory([byte[]]$bytes) }
}
catch { $qualificationFailed = $true; throw }
finally {
    if ($QualificationPath) {
        Measure-QualificationWorkload
        if ($Wpf -and $null -ne $session) {
            $quality.sampledPrivateBytes = [Math]::Max($quality.sampledPrivateBytes, $uiState.PeakPrivateBytes)
            $quality.sampledWorkingSetBytes = [Math]::Max($quality.sampledWorkingSetBytes, $uiState.PeakWorkingSetBytes)
        }
        if ($null -ne $session -and $session.Transport.State.ContainsKey('PackagePath') -and [IO.File]::Exists($session.Transport.State.PackagePath)) {
            $quality.packageBytes = (Get-Item -LiteralPath $session.Transport.State.PackagePath).Length
        }
        if (Get-Variable -Name html -Scope Local -ErrorAction SilentlyContinue) { $quality.htmlBytes = [Text.Encoding]::UTF8.GetByteCount($html) }
        if ($null -eq $projection) { $projection = [ordered]@{ candidateSha256=(Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant(); coverage=@() } }
        $projection['arguments'] = $qualificationArguments
        $projection['bodyAssertions'] = if ($qualificationFailed) { 'Fail' } else { 'Pass' }
        $projection['testCleanup'] = 'Pending'
        $projection['elapsedMilliseconds'] = $qualityWatch.ElapsedMilliseconds
        $projection['quality'] = $quality
        if ($null -ne $session) {
            $timing = [ordered]@{}
            foreach ($name in @('FirstProgressMilliseconds','MaximumProgressGapMilliseconds','TerminalMilliseconds','CancellationRequestedMilliseconds')) {
                if ($session.Transport.State.ContainsKey($name)) { $timing[$name] = $session.Transport.State[$name] }
            }
            if ($Wpf) { $timing['acknowledgmentMilliseconds'] = $uiState.AcknowledgmentMilliseconds }
            $projection['timing'] = $timing
        }
        [IO.File]::WriteAllText([IO.Path]::GetFullPath($QualificationPath), ($projection | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    }
    if ($null -ne $session -and $session.Transport.State.ContainsKey('SyntheticLock')) { $session.Transport.State.SyntheticLock.Dispose() }
    if ($null -ne $runLock) { if ($runLockOwned) { $runLock.ReleaseMutex() }; $runLock.Dispose() }
    if ($null -ne $session -and -not $session.Completed) {
        $session.Transport.Cancellation.Cancel()
        Set-StatusDeskDecision -Session $session -Approve $false -PlanDigest 'test-cleanup'
        $cleanupWatch=[Diagnostics.Stopwatch]::StartNew()
        while (-not (Complete-StatusDeskSession $session) -and $cleanupWatch.Elapsed.TotalSeconds -lt 120) { Start-Sleep -Milliseconds 50 }
        if (-not $session.Completed) { throw 'Owned test worker is still active; preserve its evidence and recovery directory.' }
    }
    if (-not $Wpf -and $null -ne $session -and $session.Completed) {
        $session.Transport.Cancellation.Dispose(); $session.Transport.DecisionReady.Dispose(); $session.Transport.Events.Dispose()
    }
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $ownedParent = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.test-output')) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($ownedParent, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected synthetic cleanup target.' }
    if (-not $RecoveryDestination -and (Test-Path -LiteralPath $resolved)) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    if ($QualificationPath) {
        $projection['testCleanup'] = if ($RecoveryDestination) { 'RetainedForRecoveryTest' } else { 'VerifiedAbsent' }
        [IO.File]::WriteAllText([IO.Path]::GetFullPath($QualificationPath), ($projection | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    }
}
Write-Output 'PASS: generated Status desk worker executes controlled comprehensive collectors, protects a useful offline report, and cleans viewing.'
