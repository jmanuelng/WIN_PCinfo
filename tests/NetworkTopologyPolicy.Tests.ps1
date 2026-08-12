[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/NetworkTopology.ps1')

$policy=Get-NetworkTopologyPolicy -ConvertFromJsonCommand (
    Get-Command ConvertFrom-Json -CommandType Cmdlet
)
Assert-Equal 'win-pcinfo.network-topology-policy' $policy.kind `
    'the release freezes one Network Topology policy'
Assert-Equal 'OfflineOnly' $policy.collector.networkBehavior `
    'the local collector cannot initiate assessment network requests'
Assert-Equal 9 @($policy.localScopes).Count `
    'all local typed source scopes are closed before approval'
Assert-Equal 3 @($policy.networkDependentScopes).Count `
    'Local Only explicitly accounts for every deferred network-dependent scope'
foreach($operation in @($policy.collector)+@($policy.networkDependentScopes)+@($policy.rules)){
    Assert-Equal $false $operation.mayPrompt 'operations cannot prompt'
    Assert-Equal $false $operation.mayInstall 'operations cannot install'
    Assert-Equal $false $operation.mayDownload 'operations cannot download'
    Assert-Equal $false $operation.maySelfElevate 'operations cannot self-elevate'
    Assert-Equal $false $operation.writesAllowed 'operations cannot change network or security state'
    Assert-Equal 1 $operation.maximumAttempts 'operations have one bounded attempt'
    if([int]$operation.deadlineMilliseconds -le 0){throw 'Every operation needs a finite deadline.'}
}

Write-Output 'PASS: the Network Topology policy freezes offline sources, bounds, and side-effect prohibitions.'
