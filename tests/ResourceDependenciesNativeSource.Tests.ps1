[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repositoryRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path $repositoryRoot 'src/ProcessSupervisor.ps1')
. (Join-Path $repositoryRoot 'src/ResourceDependencies.ps1')
$policy=Get-ResourceDependenciesPolicy -ConvertFromJsonCommand (
    Get-Command ConvertFrom-Json -CommandType Cmdlet
)

$allowed=Get-ResourceDependencyProcessDisposition -ProcessSid 'S-1-5-21-1-2-3-1001' `
    -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -IsAdministrator $false
Assert-Equal $true ($null -eq $allowed) 'the exact standard-user SID may cross the source boundary'
$alternate=Get-ResourceDependencyProcessDisposition -ProcessSid 'S-1-5-21-1-2-3-1002' `
    -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -IsAdministrator $false
Assert-Equal 'AlternateAdministrator' $alternate.relationship 'a different process identity cannot substitute for the Assessment User'
$admin=Get-ResourceDependencyProcessDisposition -ProcessSid 'S-1-5-21-1-2-3-1001' `
    -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -IsAdministrator $true
Assert-Equal 'AlternateAdministrator' $admin.relationship 'an elevated token is not relabeled StandardUser'
$system=Get-ResourceDependencyProcessDisposition -ProcessSid 'S-1-5-18' `
    -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -IsAdministrator $true
Assert-Equal 'ProhibitedSystemContext' $system.relationship 'SYSTEM is always prohibited'

$source=Get-ResourceDependenciesLiveSource
foreach($required in @('[Microsoft.Win32.Registry]::CurrentUser','Win32_NetworkConnection','Win32_Printer','Win32_PrinterDriver','Win32_PnPSignedDriver','Select-Object -First')){
    if($source -notmatch [regex]::Escape($required)){throw "The live source omitted $required."}
}
foreach($prohibited in @('Get-PrintJob','Get-Credential','cmdkey','WlanGetProfile','PNPDeviceID','SerialNumber','Win32_PrintJob','Get-ChildItem')){
    if($source -match [regex]::Escape($prohibited)){throw "The live source admits prohibited access: $prohibited"}
}

$gap=Invoke-ResourceDependenciesCollection -Policy $policy -Live `
    -AssessmentUserSid 'S-1-5-21-1-2-3-1001' -ProcessContextOverride LocalSystem
Assert-Equal 'Denied' (Get-ResourceDependencyLayerState -ScopeStates $gap.payload.scopeStates -ScopeIds @($policy.layers[0].scopeIds)) 'a prohibited process stops before source access'
Assert-Equal 0 @($gap.payload.mappedDrives).Count 'a prohibited process fabricates no user resources'
Assert-Equal $true $gap.cleanupVerified 'a pre-source context denial owns no child cleanup'

Write-Output 'PASS: the live Resource Dependency source is bounded, context-bound, and excludes prohibited material.'
