[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/CertificateTrust.ps1')
$policy = Get-CertificateTrustPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet)

Assert-Equal 'StandardUser' $policy.collector.executionContext `
    'purpose-bound certificate observation does not require elevation'
Assert-Equal 'NoElevation' $policy.collector.privilege 'the collector cannot self-elevate'
Assert-Equal 'OfflineOnly' $policy.collector.networkBehavior `
    'local trust evaluation cannot download intermediates or check remote revocation'
foreach ($flag in @('mayPrompt','mayInstall','mayDownload','maySelfElevate','writesAllowed')) {
    Assert-Equal $false $policy.collector.$flag "collector authority flag $flag remains frozen false"
}
Assert-Equal 1 $policy.collector.maximumAttempts 'the collector has one finite attempt'
Assert-Equal 30000 $policy.collector.deadlineMilliseconds 'the collector has a finite thirty-second deadline'
Assert-Equal 8 $policy.collector.maximumCertificatesPerPurpose `
    'each purpose has a finite candidate ceiling'
Assert-Equal 'CoordinatorOwnedJobObjectWorkerAndStoresClosedVerifiedAbsent' $policy.collector.cleanup `
    'the live worker tree and read-only stores have an explicit cleanup proof'
Assert-Equal 6 @($policy.purposes).Count 'six recipient-relevant purposes are modeled independently'
Assert-Equal 'Authentication|CodeTrust|DeviceIdentity|Management|ServiceConnectivity|TlsInspection' `
    ((@($policy.purposes.purposeId) | Sort-Object) -join '|') `
    'the purpose catalog is exact and release-owned'
Assert-Equal 0 @($policy.purposes | Where-Object purposeId -eq TlsInspection)[0].stores.Count `
    'TLS inspection is not guessed from an unattributed root certificate'
Assert-Equal 0 @($policy.purposes | Where-Object purposeId -eq ServiceConnectivity)[0].stores.Count `
    'service connectivity is not guessed without an approved target'

foreach ($rule in @($policy.rules)) {
    Assert-Equal 'InProcessValidatedAssessmentRecord' $rule.executionContext `
        'rules consume only validated source observations'
    Assert-Equal 'NoElevation' $rule.privilege 'rules cannot gain privilege'
    Assert-Equal 'OfflineOnly' $rule.networkBehavior 'rules remain offline'
    foreach ($flag in @('mayPrompt','mayInstall','mayDownload','maySelfElevate','writesAllowed')) {
        Assert-Equal $false $rule.$flag "rule authority flag $flag remains frozen false"
    }
    Assert-Equal 6 $rule.maximumOutputFindings 'each bounded rule emits at most one finding per purpose'
}

Assert-Equal 12 @($policy.validationScenarios).Count `
    'the release owns the complete certificate and trust validation matrix'
Write-Output 'PASS: Certificate Trust policy freezes standard-user, offline, read-only authority.'
