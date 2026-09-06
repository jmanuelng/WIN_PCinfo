[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'src/SystemCollectionPlan.ps1')
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$valid='{"state":"Complete","reasonCode":"","collections":[{"ruleCollection":"Exe","enforcementMode":"AuditOnly"}]}'
Assert-Equal $true (Test-SystemAppLockerCspResult ($valid|ConvertFrom-Json)) 'the SYSTEM boundary admits the exact minimized channel contract'
foreach($json in @(
    '{"state":"Complete","reasonCode":"","collections":[],"Policy":"synthetic-excluded-policy-marker"}',
    '{"state":"Complete","reasonCode":"","collections":[{"ruleCollection":"Exe","enforcementMode":"Enabled","Policy":"synthetic-excluded-policy-marker"}]}',
    '{"state":"Complete","reasonCode":"","collections":[{"ruleCollection":"Other","enforcementMode":"Enabled"}]}',
    '{"state":"Complete","reasonCode":"","collections":[{"ruleCollection":"Exe","enforcementMode":"Enforced"}]}',
    '{"state":"Complete","reasonCode":"","collections":[{"ruleCollection":"Exe","enforcementMode":"Enabled"},{"ruleCollection":"Exe","enforcementMode":"AuditOnly"}]}',
    '{"state":"Denied","reasonCode":"POLICY.APPLOCKER_CSP_DENIED","collections":[{"ruleCollection":"Exe","enforcementMode":"Enabled"}]}',
    '{"state":"Denied","reasonCode":"arbitrary-diagnostic-text","collections":[]}',
    '{"state":"Complete","reasonCode":"","collections":null}'
)){
    Assert-Equal $false (Test-SystemAppLockerCspResult ($json|ConvertFrom-Json)) 'unknown, ambiguous, malformed, or secret-adjacent SYSTEM payloads fail closed'
}
foreach($state in @('Partial','Denied','Unsupported','Unavailable','Malformed')){
    $result=[pscustomobject]@{state=$state;reasonCode="POLICY.APPLOCKER_CSP_$($state.ToUpperInvariant())";collections=@()}
    Assert-Equal $true (Test-SystemAppLockerCspResult $result) 'legitimate channel gaps remain explicit without observations'
}
Write-Output 'PASS: closed SYSTEM AppLocker admission rejects policy bodies, duplicate collections, invalid modes and contradictory coverage.'
