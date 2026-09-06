[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/CertificateTrust.ps1')
. (Join-Path $PSScriptRoot 'CertificateSourceAdapters.ps1')
$policy=Get-CertificateTrustPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)
$source=Get-ControlledCertificateSource -Source (Get-CertificateTrustLiveSource -Policy $policy) -Scenario BoundedMalformed
$payload=(& ([scriptblock]::Create($source)))|ConvertFrom-Json
Assert-Equal 4 @($payload.scopeStates|Where-Object state -eq Constrained).Count 'malformed matching candidates also consume the processing budget'
Assert-Equal 28 @($payload.candidates).Count 'a malformed first candidate preserves the other seven bounded observations per purpose'
Assert-Equal 48 $script:CertificateDisposed 'all snapshot certificate objects are disposed even after early termination'
Assert-Equal 4 $script:CertificateStoresClosed 'all opened stores close after bounded selection'
Assert-Equal 4 $script:CertificateStoresDisposed 'all opened store objects are disposed'
Assert-Equal 32 $script:CertificateChainsDisposed 'all bounded chain objects dispose including malformed builds'
$source=Get-ControlledCertificateSource -Source (Get-CertificateTrustLiveSource -Policy $policy) -Scenario NativeDenied
$payload=(& ([scriptblock]::Create($source)))|ConvertFrom-Json
Assert-Equal 4 @($payload.scopeStates|Where-Object state -eq Denied).Count 'native cryptographic access denial retains denied coverage'
Write-Output 'PASS: controlled certificate processing remains bounded after malformed candidates.'
