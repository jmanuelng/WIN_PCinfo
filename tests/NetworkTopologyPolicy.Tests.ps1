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
Assert-Equal 30000 $policy.collector.deadlineMilliseconds `
    'the local collector has an evidence-based finite cold-provider deadline'
Assert-Equal 'Utf8Json' $policy.collector.resultSerialization `
    'the release freezes the compact worker transport before collection'
Assert-Equal 262144 $policy.collector.resultMaximumUtf8Bytes `
    'the compact transport ceiling covers the closed worst-case payload and framing'
$derivation=$policy.collector.resultBoundDerivation
$computed=[int]$derivation.maximumAdmittedStringUtf8Bytes*[int]$derivation.maximumJsonEscapeExpansionFactor+
    [int]$derivation.maximumStructuralUtf8Bytes
Assert-Equal $derivation.computedWorstCaseUtf8Bytes $computed `
    'the release publishes the arithmetic behind the compact transport bound'
if($computed -gt [int]$policy.collector.resultMaximumUtf8Bytes){
    throw 'The frozen transport ceiling does not cover the computed worst case.'
}
Assert-Equal 3 @($policy.networkDependentScopes |
    Where-Object deadlineMilliseconds -eq 5000).Count `
    'future network probes retain their separately frozen five-second bounds'
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
