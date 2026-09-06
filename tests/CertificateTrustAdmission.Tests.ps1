[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/CertificateTrust.ps1')
$policy=Get-CertificateTrustPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)
$payload=New-CertificateTrustSyntheticPayload -Scenario IncompleteChain -Policy $policy
$payload.candidates[0].trustState='Trusted'
Assert-Equal $false (Test-CertificateTrustPayload -Payload $payload -Policy $policy) 'incomplete chains cannot enter evidence as trusted'
$payload=New-CertificateTrustSyntheticPayload -Scenario ValidTrusted -Policy $policy
$payload.processRelationship='AlternateAdministrator';$payload.observedExecutionContext='Administrator'
Assert-Equal $false (Test-CertificateTrustPayload -Payload $payload -Policy $policy) 'another administrator cannot supply Assessment User certificate observations'
$payload=New-CertificateTrustSyntheticPayload -Scenario ValidTrusted -Policy $policy
$payload.scopeStates[0].state='Denied';$payload.scopeStates[0].reasonCode='CERTIFICATE.STORE_ACCESS_DENIED'
Assert-Equal $false (Test-CertificateTrustPayload -Payload $payload -Policy $policy) 'denied scopes cannot carry successful certificate observations'
$payload=New-CertificateTrustSyntheticPayload -Scenario ValidTrusted -Policy $policy
$payload.candidates[0].notAfter='2000-01-01T00:00:00+00:00'
Assert-Equal $false (Test-CertificateTrustPayload -Payload $payload -Policy $policy) 'reversed certificate date intervals cannot become valid source evidence'
Write-Output 'PASS: certificate admission rejects contradictory source facts.'
