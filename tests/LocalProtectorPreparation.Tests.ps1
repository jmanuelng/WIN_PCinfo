[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$candidate = Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1'
& (Join-Path $repositoryRoot 'build/Build.ps1') -OutputPath $candidate | Out-Null

# Execute the generated preparation contract with only the initiating-user
# crypto provider replaced. No production command-line trust override exists.
# Loading generated module regions avoids executing ApplicationMain/collectors.
$generated = [IO.File]::ReadAllText($candidate)
$regions = [regex]::Matches($generated,
    '(?ms)^#region Generated from src/(?!ApplicationHeader|ApplicationMain)([^\r\n]+)\r?\n(.*?)^#endregion Generated from src/\1')
foreach ($region in $regions) { . ([scriptblock]::Create($region.Groups[2].Value)) }
$requestValues = Get-Content (Join-Path $PSScriptRoot 'fixtures/automation-request.json') -Raw |
    ConvertFrom-Json -AsHashtable
$requestValues.outputDestination = Join-Path $repositoryRoot '.test-output/readiness-no-output'
$request = New-NormalizedRequest @requestValues
$context = @{ IsFixture = $true }
foreach ($name in @('Preparation', 'Contract', 'Run', 'PrivilegedCollection', 'SystemCollection',
    'EvidenceWorkspace', 'ProtectedPackage', 'RecipientSharing', 'DeviceReadiness',
    'IdentityEnrollment', 'AdministratorExposure', 'EffectivePolicy', 'ResourceDependencies',
    'NetworkTopology', 'SoftwareInventory', 'CertificateTrust', 'MicrosoftConnectivity')) {
    $context[$name + 'FixturePath'] = ''
}
$runtime = [pscustomobject]@{ Eligible = $true; ReasonCode = 'RUNTIME.ELIGIBLE'; PolicyId = 'synthetic' }
$script:probeBuffers = [Collections.Generic.List[byte[]]]::new()
$script:providerCase = 'Ready'
function Protect-ProtectedPackageContentKey {
    param([byte[]] $ContentKey)
    $script:probeBuffers.Add($ContentKey)
    Assert-Equal 32 $ContentKey.Length 'readiness uses a bounded synthetic 256-bit probe'
    if ($script:providerCase -eq 'ProtectDenied') { throw 'Synthetic initiating-user protection denied.' }
    if ($script:providerCase -eq 'EmptyWrap') { return ,([byte[]]::new(0)) }
    [byte[]] $wrapped = $ContentKey.Clone()
    if ($script:providerCase -eq 'OversizedWrap') { $wrapped = [byte[]]::new(4097) }
    $script:probeBuffers.Add($wrapped)
    return ,$wrapped
}
function Unprotect-ProtectedPackageContentKey {
    param([byte[]] $ProtectedContentKey)
    if ($script:providerCase -eq 'UnprotectDenied') { throw 'Synthetic wrong user/device or inaccessible profile.' }
    if ($script:providerCase -eq 'MissingRecovery') { return $null }
    [byte[]] $opened = $ProtectedContentKey.Clone()
    if ($script:providerCase -eq 'ChangedRecovery') { $opened[0] = $opened[0] -bxor 1 }
    if ($script:providerCase -eq 'ShortRecovery') { $opened = [byte[]]::new(31) }
    $script:probeBuffers.Add($opened)
    return ,$opened
}
function Invoke-ReadinessPreparation {
param([bool] $Accept = $false)
$capture = [IO.StringWriter]::new()
$previousOutput = [Console]::Out
try {
    [Console]::SetOut($capture)
    $exitCode = Invoke-PreparationGate -Request $request -RuntimeResult $runtime -ArtifactTrustValid $true `
    -Mode Automation -AcceptPreparation $Accept -ValidationContext ([pscustomobject]$context) `
    -ConvertFromJsonCommand (Get-Command ConvertFrom-Json -CommandType Cmdlet) `
    -ConvertToJsonCommand (Get-Command ConvertTo-Json -CommandType Cmdlet) `
    -TestJsonCommand (Get-Command Test-Json -CommandType Cmdlet)
}
finally { [Console]::SetOut($previousOutput) }
$records = @($capture.ToString() -split '\r?\n' | Where-Object { $_ } | ConvertFrom-Json -Depth 40)
$capture.Dispose()
Assert-Equal 20 $exitCode 'readiness cannot report a completed assessment'
$records
}
$records = @(Invoke-ReadinessPreparation)
$summary = @($records | Where-Object recordType -eq 'win-pcinfo.preparation-summary')[0]
Assert-Equal $true $summary.readyForApproval 'successful initiating-user protection makes preparation ready'
Assert-Equal 'PREPARATION.DECLINED' $records[-1].reasonCode 'readiness never implies assessment consent'
Assert-Equal $false $records[-1].collectionStarted 'declined preparation performs no collection'
Assert-Equal $false ([IO.Directory]::Exists($request.outputDestination)) 'the probe creates no evidence destination'
Assert-Equal 3 $script:probeBuffers.Count 'the provider receives only one bounded round trip'
foreach ($buffer in $script:probeBuffers) {
    Assert-Equal 0 @($buffer | Where-Object { $_ -ne 0 }).Count 'all controllable probe buffers are cleared'
}
foreach ($case in @('ProtectDenied', 'EmptyWrap', 'OversizedWrap', 'UnprotectDenied',
    'MissingRecovery', 'ChangedRecovery', 'ShortRecovery')) {
    $script:providerCase = $case
    $script:probeBuffers.Clear()
    $records = @(Invoke-ReadinessPreparation -Accept $true)
    $summary = @($records | Where-Object recordType -eq 'win-pcinfo.preparation-summary')[0]
    Assert-Equal $false $summary.readyForApproval "$case leaves protection unresolved"
    Assert-Equal 'PREPARATION.PREREQUISITE_UNRESOLVED' $records[-1].reasonCode "$case fails closed"
    Assert-Equal $false $records[-1].collectionStarted "$case never begins collection despite approval"
    foreach ($buffer in $script:probeBuffers) {
        Assert-Equal 0 @($buffer | Where-Object { $_ -ne 0 }).Count "$case clears controllable buffers"
    }
}
Write-Output 'PASS: generated preparation verifies and clears its initiating-user probe without collection.'
