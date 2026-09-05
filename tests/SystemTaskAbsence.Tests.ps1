[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestHarness.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/SystemCollectionPlan.ps1')
$folder = [pscustomobject]@{}
$folder | Add-Member ScriptMethod DeleteTask { param($Name,$Flags) }
$folder | Add-Member ScriptMethod GetTask { param($Name); throw [Runtime.InteropServices.COMException]::new('Synthetic access denied.', -2147024891) }
$activation = [pscustomobject]@{ Folder=$folder; RunningTask=$null; InstanceGuid='' }
$result = Remove-SystemCollectionTransientTask -Activation $activation `
    -TaskName ('WINPCInfo-SystemCollection-v1-' + [guid]::NewGuid().ToString('N')) -MaximumMilliseconds 100
Assert-Equal $false $result.Absent 'access denied while probing a task is uncertainty, never proof of absence'
Write-Output 'PASS: a failed Task Scheduler observation cannot erase cleanup uncertainty.'
