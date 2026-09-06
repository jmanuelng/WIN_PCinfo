[CmdletBinding()]
param([ValidateSet('Complete','DefaultDenied','PrinterMetadataDenied')][string]$Scenario='Complete')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path (Split-Path $PSScriptRoot) 'src/ResourceDependencies.ps1')
$original=(Get-Command Get-ResourceDependenciesLiveSource).Definition
. ([scriptblock]::Create('function Get-OriginalResourceDependenciesLiveSource {'+$original+'}'))
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ResourceSourceBoundary.ps1')).Replace('__RESOURCE_CASE__',$Scenario)))
$policy=Get-ResourceDependenciesPolicy -ConvertFromJsonCommand (Get-Command ConvertFrom-Json)
$source=Get-ResourceDependenciesLiveSource
$source=$source.Replace('[Console]::Out.Write([Convert]::ToBase64String($utf8.GetBytes($xml)))','Write-Output $payload')
$source=$source.Replace('[string]$env:WINPCINFO_RESOURCE_ASSESSMENT_SID', "'S-1-5-21-100-200-300-1001'")
foreach($name in @('MAPPED','UNC','PRINTERS','DRIVERS','PERIPHERALS')){
    $source=$source.Replace('[int]$env:WINPCINFO_RESOURCE_MAX_'+$name, '8')
}
$source=$source.Replace("@([string]`$env:WINPCINFO_RESOURCE_CLASSES -split '\|')", "@('USB')")
$payload=& ([scriptblock]::Create($source))
Assert-Equal 5 @($payload.scopeStates).Count 'the actual source constructs each selected scope independently'
Assert-Equal $true (Test-ResourceDependenciesCollectorPayload $payload $policy) 'actual source output enters the typed payload contract'
Assert-Equal 2 @($payload.mappedDrives).Count 'remembered and disconnected resources survive source correlation'
Assert-Equal 1 @($payload.uncConnections).Count 'duplicate UNC resources have one subject'
Assert-Equal 2 @($payload.printers).Count 'local cache retains local and unavailable network printers'
$remote=@($payload.printers|Where-Object network)[0]
Assert-Equal $true ($null -eq $remote.portName -and $null -eq $remote.driverName -and $null -eq $remote.offline) 'uncached remote details are unknown without server contact'
if($Scenario -ne 'PrinterMetadataDenied'){
    Assert-Equal 'Driver-東京' (@($payload.printers|Where-Object name -eq 'Printer-東京')[0].driverName) 'locally registered printer driver metadata is retained'
}
if((Get-OriginalResourceDependenciesLiveSource) -match 'ClassName Win32_Printer\b|ClassName Win32_PrinterDriver\b') {throw 'Printer CIM provider can contact remote servers.'}
Write-Output 'PASS: controlled resource source execution.'
