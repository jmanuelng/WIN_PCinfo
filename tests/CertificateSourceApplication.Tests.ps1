[CmdletBinding()]
param([ValidateSet('Bounded','BoundedMalformed','MissingEku','ValidTrusted','Expired','NotYetValid','Untrusted','IncompleteChain','MultipleCandidates','Denied','NativeDenied','Partial','AbsentPurpose','AlternateAdministrator')]
    [string[]]$Scenario=@('Bounded','BoundedMalformed','MissingEku','ValidTrusted','Expired','NotYetValid','Untrusted','IncompleteChain','MultipleCandidates','Denied','NativeDenied','Partial','AbsentPurpose','AlternateAdministrator'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$repositoryRoot=Split-Path -Parent $PSScriptRoot
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path $repositoryRoot 'artifacts/WIN-PCInfo.ps1')
foreach($case in $Scenario){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    & $hostPath -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -CertificateSourceScenario $case
    if($LASTEXITCODE -ne 0){throw "Generated certificate source scenario $case failed."}
    Write-Output ('PASS: certificate source {0}; elapsed seconds {1:N1}.' -f $case,$watch.Elapsed.TotalSeconds)
}
