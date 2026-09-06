[CmdletBinding()]
param([string[]]$Scenario=@('Complete','DriverRegistrations','ProviderMismatch','ProviderUnavailable','RegistryDenied','ConnectionDenied','PrinterDenied','DefaultDenied','PrinterMetadataDenied','PeripheralUnavailable','Maximum','Oversize','AlternateAdministrator','LocalSystem'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
$hostPath=Resolve-WinPCInfoRuntime -ApplicationPath (Join-Path (Split-Path $PSScriptRoot) 'artifacts/WIN-PCInfo.ps1')
foreach($case in $Scenario){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    & $hostPath -NoLogo -NoProfile -File (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -ResourceSourceScenario $case
    if($LASTEXITCODE -ne 0){throw "Generated resource source scenario $case failed."}
    Write-Output ('PASS: resource source {0}; elapsed seconds {1:N1}.' -f $case,$watch.Elapsed.TotalSeconds)
}
